//! The engine spends a Pignus version 2 loan on a local chain, under the
//! five-point rule, with the wallet's own coins and a foreign coin beside the
//! contract coin: the take of an offer (which opens a vault), a top-up, a
//! partial repayment, a liquidation that spends and recreates the oracle's
//! beacon coin, and the full repayment that closes the vault. Every spend is
//! signed only through the approval, then confirmed.
//!
//! The refusals it asserts: a digest that was not shown; a foreign coin
//! changed after the summary; a wallet input in another asset than shown (as
//! a request that lies, and as an approval of another coin signed with the
//! shown digest); a foreign coin the chain's record does not back; a path
//! whose witness selects another path; a chain of two contract inputs. Then
//! what the wallet's signature means: the signed liquidation with its beacon
//! input moved to the other beacon coin is forced into a block, and the block
//! refuses it for the wallet input's signature, which commits to every
//! input's outpoint; the node runs with `-par=1` so the error names it.
//!
//!     SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test vault_regtest -- --nocapture
//!
//! Without `SEQUENTIA_BIN` the test does nothing. The chain's data directory
//! is a fresh temporary directory, removed when the test ends.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;

use lwk_contracts::approval::{Approval, AssetLabel, WalletView};
use lwk_contracts::hex::{hex, unhex_any};
use lwk_contracts::spend::{
    script_from_hex, script_hash_hex, Chain, ChainFacts, CoinRequest, InputRequest, OutputRequest,
    Prevout, Spend, SpendRequest, WalletCoin,
};
use lwk_contracts::{known, Contract, Instance};
use lwk_signer::SwSigner;
use sequentia_contracts::attestation::{self as att, Attestation};
use sequentia_contracts::vault;
use serde_json::{json, Value};
use simplicityhl::elements::bitcoin::bip32::DerivationPath;
use simplicityhl::elements::encode::{deserialize, serialize_hex};
use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::elements::{Address, AddressParams, BlockHash, Script, Transaction, WPubkeyHash};

// A public test mnemonic, never funded anywhere but a local chain.
const BORROWER: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";

const COIN: u64 = 100_000_000;
const FEE: u64 = 5_000;
const PRECISION: u8 = 8;
const LIQ_BP: u32 = 12_000;
const TARGET_BP: u32 = 15_000;
const BONUS_BP: u32 = 10_500;
const LOT: u64 = 10 * COIN;
const DEBT: u64 = 1_050_000_000;
const COLLATERAL: u64 = 10 * COIN;

struct Node {
    child: Child,
    dir: PathBuf,
    bin: PathBuf,
}

impl Node {
    fn cli(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(self.bin.join("sequentia-cli"))
            .arg(format!("-datadir={}", self.dir.display()))
            .args(args)
            .output()
            .unwrap();
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }
    fn ok(&self, args: &[&str]) -> String {
        self.cli(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }
    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.ok(args)).unwrap()
    }
    fn mine(&self, n: u32) {
        let a = self.ok(&["getnewaddress"]);
        self.ok(&["generatetoaddress", &n.to_string(), &a]);
    }
    fn tip(&self) -> Value {
        self.json(&["getblockheader", &self.ok(&["getbestblockhash"])])
    }
    fn mtp(&self) -> u64 {
        self.tip()["mediantime"].as_u64().unwrap()
    }
    /// Moves the median time past forward by at least `secs`.
    fn advance(&self, secs: u64) {
        let t = self.tip()["time"].as_u64().unwrap();
        self.ok(&["setmocktime", &(t + secs + 60).to_string()]);
        self.mine(12);
    }
    fn facts(&self, records: &[(&str, u32)]) -> ChainFacts {
        let tip = self.tip();
        let mut prevouts = BTreeMap::new();
        for (txid, vout) in records {
            let o = self.json(&["gettxout", txid, &vout.to_string(), "true"]);
            prevouts.insert(
                format!("{txid}:{vout}"),
                Prevout {
                    script_pubkey: o["scriptPubKey"]["hex"].as_str().unwrap().into(),
                    asset: o["asset"].as_str().unwrap().into(),
                    amount: atoms(&o["value"]),
                },
            );
        }
        ChainFacts {
            tip_height: tip["height"].as_u64().unwrap(),
            tip_median_time: tip["mediantime"].as_u64().unwrap(),
            coin_height: None,
            coin_start_median_time: None,
            prevouts,
        }
    }
    fn mempool(&self, hex: &str) -> String {
        let v = self.json(&["testmempoolaccept", &json!([hex]).to_string()]);
        if v[0]["allowed"] == json!(true) {
            "allowed".into()
        } else {
            v[0]["reject-reason"].as_str().unwrap().to_string()
        }
    }
    fn force(&self, hex: &str) -> String {
        let a = self.ok(&["getnewaddress"]);
        match self.cli(&["generateblock", &a, &json!([hex]).to_string()]) {
            Ok(_) => "mined".into(),
            Err(e) => e,
        }
    }
    /// Broadcasts and mines; returns the confirmed transaction.
    fn confirm(&self, tx: &Transaction) -> Value {
        let txid = self.ok(&["sendrawtransaction", &serialize_hex(tx)]);
        self.mine(1);
        let t = self.json(&["getrawtransaction", &txid, "true"]);
        assert!(
            t["confirmations"].as_u64().unwrap() >= 1,
            "{txid} unconfirmed"
        );
        t
    }
    /// The output of `txid` paying `spk`.
    fn vout_to(&self, txid: &str, spk: &str) -> (u32, String, u64) {
        let t = self.json(&["getrawtransaction", txid, "true"]);
        let o = t["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"] == json!(spk))
            .unwrap_or_else(|| panic!("{txid} pays nothing to {spk}"));
        (
            u32::try_from(o["n"].as_u64().unwrap()).unwrap(),
            o["asset"].as_str().unwrap().into(),
            atoms(&o["value"]),
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn atoms(v: &Value) -> u64 {
    (v.as_f64().unwrap() * COIN as f64).round() as u64
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(bin: &Path) -> Node {
    let dir = std::env::temp_dir().join(format!("lwk-contracts-vault-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let conf = [
        "chain=elementsregtest".to_string(),
        "[elementsregtest]".into(),
        "server=1".into(),
        "listen=0".into(),
        format!("port={}", free_port()),
        format!("rpcport={}", free_port()),
        "rpcbind=127.0.0.1".into(),
        "rpcallowip=127.0.0.1".into(),
        "initialfreecoins=2100000000000000".into(),
        "anyonecanspendaremine=1".into(),
        "blindedaddresses=0".into(),
        "con_default_blinded_addresses=0".into(),
        "validatepegin=0".into(),
        "con_parent_chain_signblockscript=51".into(),
        "con_any_asset_fees=1".into(),
        "evbparams=simplicity:-1:::".into(),
        "par=1".into(),
        "txindex=1".into(),
        "fallbackfee=0.0001".into(),
        "maxtxfee=100".into(),
        String::new(),
    ]
    .join("\n");
    std::fs::write(dir.join("elements.conf"), conf).unwrap();
    let child = Command::new(bin.join("sequentiad"))
        .arg(format!("-datadir={}", dir.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let node = Node {
        child,
        dir,
        bin: bin.to_path_buf(),
    };
    for i in 0.. {
        if node.cli(&["getblockchaininfo"]).is_ok() {
            break;
        }
        assert!(i < 240, "the node did not start");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    node
}

fn rec(log: &mut Vec<Value>, label: &str, v: Value) {
    println!("{label}: {v}");
    log.push(json!({"step": label, "result": v}));
}

fn internal(display: &str) -> String {
    let b = unhex_any(display).unwrap();
    hex(&b.iter().rev().copied().collect::<Vec<_>>())
}

/// The borrower wallet's P2WPKH script at `m/84h/1h/0h/0/i`.
fn wallet_key(signer: &SwSigner, i: u32) -> (String, Script) {
    let path = format!("m/84h/1h/0h/0/{i}");
    let xprv = signer
        .derive_xprv(&DerivationPath::from_str(&path).unwrap())
        .unwrap();
    let pk = simplicityhl::elements::bitcoin::PublicKey::new(
        xprv.private_key.public_key(&Secp256k1::new()),
    );
    (
        path,
        Script::new_v0_wpkh(&WPubkeyHash::hash(&pk.to_bytes())),
    )
}

fn out(to: &str, script: &str, asset: &str, amount: u64) -> OutputRequest {
    OutputRequest {
        to: to.into(),
        address: None,
        script: if to == "fee" {
            None
        } else {
            Some(script.into())
        },
        asset: asset.into(),
        amount,
        open: None,
        input: None,
    }
}

fn wallet_in(c: &WalletCoin) -> InputRequest {
    InputRequest::Wallet {
        txid: c.txid.clone(),
        vout: c.vout,
        asset: c.asset.clone(),
        amount: c.amount,
    }
}

#[test]
fn a_pignus_loan_under_the_five_point_rule() {
    let Some(bin) = std::env::var_os("SEQUENTIA_BIN").map(PathBuf::from) else {
        println!("skipped: set SEQUENTIA_BIN to a directory holding sequentiad and sequentia-cli");
        return;
    };
    let node = start(&bin);
    let mut log = Vec::new();
    rec(
        &mut log,
        "node",
        json!(node.ok(&["-version"]).lines().next().unwrap_or_default()),
    );
    node.ok(&["createwallet", "lender"]);
    node.mine(101);
    node.ok(&["rescanblockchain"]);
    let genesis_hex = node.ok(&["getblockhash", "0"]);
    let genesis = BlockHash::from_str(&genesis_hex).unwrap();
    let chain = Chain {
        genesis,
        mainnet: false,
    };

    // Two assets of equal standing, and the oracle's beacon asset: 2 atoms, no token.
    let issue = |n: &str| -> String {
        let a = node.json(&[
            "-named",
            "issueasset",
            &format!("assetamount={n}"),
            "tokenamount=0",
            "blind=false",
            "fee_asset=bitcoin",
        ])["asset"]
            .as_str()
            .unwrap()
            .to_string();
        node.mine(1);
        a
    };
    let x = issue("1000"); // the collateral, "X"
    let y = issue("1000"); // the debt asset, "Y"
    let beacon_asset = issue("0.00000002");
    let mut rates = node.json(&["getfeeexchangerates"]);
    rates[&x] = json!(COIN);
    rates[&y] = json!(COIN);
    node.ok(&["setfeeexchangerates", &rates.to_string()]);
    let t = node.tip()["time"].as_u64().unwrap();
    node.ok(&["setmocktime", &(t + 60).to_string()]);
    node.mine(12);

    // The oracle and its beacon: a coin anyone spends if output 2k recreates it.
    let oracle_sk = [7u8; 32];
    let oracle = att::xonly_of(&oracle_sk).unwrap();
    let nonce = [9u8; 32];
    let (beacon, _root, parity) = att::beacon_output(&oracle, &nonce).unwrap();
    let beacon_spk = format!("5120{}", hex(&beacon));
    let recreate = att::beacon_recreate_leaf();
    let rotate = att::beacon_rotate_leaf(&oracle, &nonce);
    let rotate_hash = {
        let mut m = vec![att::TAPSCRIPT_LEAF, u8::try_from(rotate.len()).unwrap()];
        m.extend_from_slice(&rotate);
        att::tagged_hash("TapLeaf/elements", &m)
    };
    let mut beacon_cb = vec![att::TAPSCRIPT_LEAF | parity];
    beacon_cb.extend_from_slice(&att::NUMS);
    beacon_cb.extend_from_slice(&rotate_hash);
    let beacon_addr = Address::from_script(
        &script_from_hex(&beacon_spk).unwrap(),
        None,
        &AddressParams::ELEMENTS,
    )
    .unwrap()
    .to_string();
    let mut beacon_coins = Vec::new();
    for _ in 0..2 {
        let txid = node.ok(&[
            "-named",
            "sendtoaddress",
            &format!("address={beacon_addr}"),
            "amount=0.00000001",
            &format!("assetlabel={beacon_asset}"),
            "fee_asset_label=bitcoin",
        ]);
        node.mine(1);
        let (vout, _, amount) = node.vout_to(&txid, &beacon_spk);
        assert_eq!(amount, 1);
        beacon_coins.push((txid, vout));
    }
    rec(
        &mut log,
        "beacon",
        json!({"program": hex(&beacon), "coins": beacon_coins, "asset": beacon_asset}),
    );

    // The borrower: this wallet (the kit's signer), funded at its own P2WPKH keys.
    let me = SwSigner::new(BORROWER, false).unwrap();
    let keys: Vec<(String, Script)> = (0..8).map(|i| wallet_key(&me, i)).collect();
    let scripts: Vec<Script> = keys.iter().map(|(_, s)| s.clone()).collect();
    let spk = |i: usize| hex(keys[i].1.as_bytes());
    let mut coins: Vec<WalletCoin> = Vec::new();
    let fund = |i: usize, asset: &str, amount: &str, coins: &mut Vec<WalletCoin>| -> WalletCoin {
        let a = Address::from_script(&keys[i].1, None, &AddressParams::ELEMENTS)
            .unwrap()
            .to_string();
        let txid = node.ok(&[
            "-named",
            "sendtoaddress",
            &format!("address={a}"),
            &format!("amount={amount}"),
            &format!("assetlabel={asset}"),
            "fee_asset_label=bitcoin",
        ]);
        node.mine(1);
        let (vout, asset, amount) = node.vout_to(&txid, &spk(i));
        let c = WalletCoin {
            txid,
            vout,
            script_pubkey: spk(i),
            asset,
            amount,
            key_path: keys[i].0.clone(),
            confidential: false,
        };
        coins.push(c.clone());
        c
    };
    // What the wallet records of a coin it received in a spend.
    let received = |txid: &str, vout: u32, i: usize, coins: &mut Vec<WalletCoin>| -> WalletCoin {
        let o = node.json(&["gettxout", txid, &vout.to_string(), "true"]);
        assert_eq!(o["scriptPubKey"]["hex"], json!(spk(i)));
        let c = WalletCoin {
            txid: txid.into(),
            vout,
            script_pubkey: spk(i),
            asset: o["asset"].as_str().unwrap().into(),
            amount: atoms(&o["value"]),
            key_path: keys[i].0.clone(),
            confidential: false,
        };
        coins.push(c.clone());
        c
    };
    let coll_coin = fund(0, &x, "11", &mut coins);
    let topup_coin = fund(1, &x, "2", &mut coins);
    let y_spare = fund(5, &y, "20", &mut coins);

    let lender_spk = node.json(&["getaddressinfo", &node.ok(&["getnewaddress", "", "bech32"])])
        ["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let borrower_spk = spk(0);
    let now = node.mtp();
    let (maturity, recover_after, expiry) = (now + 4 * 3600, now + 8 * 3600, now + 2 * 3600);
    let terms = |borrower: bool| -> BTreeMap<String, String> {
        let mut p = BTreeMap::from([
            ("COLL".to_string(), internal(&x)),
            ("DEBT_ASSET".into(), internal(&y)),
            ("ORACLE".into(), hex(&oracle)),
            ("BEACON_ASSET".into(), internal(&beacon_asset)),
            ("PRECISION".into(), format!("{PRECISION:02x}")),
            ("LIQ_BP".into(), format!("{LIQ_BP:08x}")),
            ("TARGET_BP".into(), format!("{TARGET_BP:08x}")),
            ("BONUS_BP".into(), format!("{BONUS_BP:08x}")),
            ("MATURITY".into(), format!("{maturity:08x}")),
            ("RECOVER_AFTER".into(), format!("{recover_after:08x}")),
            (
                "LENDER".into(),
                script_hash_hex(&script_from_hex(&lender_spk).unwrap()),
            ),
        ]);
        if borrower {
            p.insert(
                "BORROWER".into(),
                script_hash_hex(&script_from_hex(&borrower_spk).unwrap()),
            );
        }
        p
    };
    let mut offer_params = terms(false);
    offer_params.insert("LOT".into(), format!("{LOT:016x}"));
    offer_params.insert("DEBT".into(), format!("{DEBT:016x}"));
    offer_params.insert("COLLATERAL".into(), format!("{COLLATERAL:016x}"));
    offer_params.insert("EXPIRY".into(), format!("{expiry:08x}"));
    let offer_t = Arc::new(known(known::PIGNUS_OFFER).unwrap().template().unwrap());
    let vault_t = Arc::new(known(known::PIGNUS_VAULT).unwrap().template().unwrap());
    let offer = Arc::new(
        Contract::new(
            offer_t,
            Instance {
                instance: 2,
                template_hash: known::PIGNUS_OFFER.into(),
                params: offer_params,
                slots: BTreeMap::new(),
                genesis: Some(genesis_hex.clone()),
            },
        )
        .unwrap(),
    );
    let vault_instance = |debt: u64, last: u64| -> Instance {
        Instance {
            instance: 2,
            template_hash: known::PIGNUS_VAULT.into(),
            params: terms(true),
            slots: BTreeMap::from([
                ("DEBT_OUT".to_string(), format!("{debt:016x}")),
                ("LAST_TIME".into(), format!("{last:08x}")),
            ]),
            genesis: Some(genesis_hex.clone()),
        }
    };
    let vault_at = |debt: u64, last: u64| -> Arc<Contract> {
        Arc::new(Contract::new(vault_t.clone(), vault_instance(debt, last)).unwrap())
    };
    let slots = |debt: u64, last: u64| -> BTreeMap<String, String> {
        BTreeMap::from([
            ("DEBT_OUT".to_string(), format!("{debt:016x}")),
            ("LAST_TIME".into(), format!("{last:08x}")),
        ])
    };

    // The lender funds the offer with two lots.
    let offer_addr = offer.address("ert").unwrap();
    let otx = node.ok(&[
        "-named",
        "sendtoaddress",
        &format!("address={offer_addr}"),
        &format!("amount={}", 2 * LOT / COIN),
        &format!("assetlabel={y}"),
        "fee_asset_label=bitcoin",
    ]);
    node.mine(1);
    let (ovout, _, oamount) = node.vout_to(&otx, &offer.derived.script_pubkey);
    let label = |t: &str| AssetLabel {
        ticker: t.into(),
        precision: 8,
    };
    let view = WalletView {
        known: vec![known::PIGNUS_OFFER.into(), known::PIGNUS_VAULT.into()],
        registry: None,
        assets: BTreeMap::from([
            (x.clone(), label("XCOL")),
            (y.clone(), label("YDEBT")),
            (
                beacon_asset.clone(),
                AssetLabel {
                    ticker: "BEACON".into(),
                    precision: 0,
                },
            ),
        ]),
        key_path: None,
    };
    let build = |c: &Arc<Contract>, req: &SpendRequest, facts: ChainFacts, coins: &[WalletCoin]| {
        Spend::build_with_coins(c.clone(), chain, req, &scripts, coins, Some(facts))
    };

    // ---- 1. The take: the offer at input 0, the wallet's collateral after it.
    let last0 = node.mtp() - 1;
    let vault0 = vault_at(DEBT, last0);
    let take = SpendRequest {
        path: "take".into(),
        coin: CoinRequest {
            txid: otx.clone(),
            vout: ovout,
            script_pubkey: offer.derived.script_pubkey.clone(),
            asset: y.clone(),
            amount: oamount,
        },
        inputs: Some(vec![InputRequest::Contract, wallet_in(&coll_coin)]),
        sequence: None,
        lock_time: Some(u32::try_from(last0).unwrap()),
        outputs: vec![
            OutputRequest {
                open: Some(serde_json::to_value(vault_instance(DEBT, last0)).unwrap()),
                ..out("open", &vault0.derived.script_pubkey, &x, COLLATERAL)
            },
            out("contract", &offer.derived.script_pubkey, &y, oamount - LOT),
            out("wallet", &spk(2), &y, LOT - FEE),
            out("wallet", &spk(0), &x, coll_coin.amount - COLLATERAL),
            out("fee", "", &y, FEE),
        ],
        spender: BTreeMap::from([(
            "PATH".to_string(),
            format!("Left(0x{})", script_hash_hex(&keys[0].1)),
        )]),
        next_slots: None,
    };
    let facts = node.facts(&[(&otx, ovout)]);
    let a = Approval::prepare(
        build(&offer, &take, facts.clone(), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(s["path"]["name"], json!("take"));
    assert_eq!(s["inputs"][0]["is"], json!("contract"));
    assert_eq!(s["inputs"][1]["is"], json!("wallet"));
    assert_eq!(s["opens"][0]["template_hash"], json!(known::PIGNUS_VAULT));
    let borrower_shown = s["opens"][0]["params"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == json!("BORROWER"))
        .unwrap()["shown"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        borrower_shown.contains("this wallet's script"),
        "{borrower_shown}"
    );
    let changes: BTreeMap<String, String> = s["wallet_change"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["asset"].as_str().unwrap().to_string(),
                c["change"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(changes[&x], format!("-{COLLATERAL}"));
    assert_eq!(changes[&y], (LOT - FEE).to_string());
    assert!(s["checks"]["5_contract_key"]
        .as_str()
        .unwrap()
        .contains("takes no signature"));
    rec(
        &mut log,
        "take: approval",
        json!({"wallet_change": s["wallet_change"], "opens": s["opens"][0]["shown"], "checks": s["checks"], "vsize": s["vsize"], "digest": s["digest"]}),
    );

    // A digest that was not shown signs nothing.
    let e = a.sign(&"00".repeat(32), &me).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    rec(&mut log, "refused: a digest not shown", json!(e));

    let tx = a.sign(a.digest(), &me).unwrap();
    let t = node.confirm(&tx);
    rec(
        &mut log,
        "take confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let take_txid = t["txid"].as_str().unwrap().to_string();
    let vcoin = |txid: &str, c: &Arc<Contract>| -> CoinRequest {
        let (vout, asset, amount) = node.vout_to(txid, &c.derived.script_pubkey);
        CoinRequest {
            txid: txid.into(),
            vout,
            script_pubkey: c.derived.script_pubkey.clone(),
            asset,
            amount,
        }
    };
    let v0 = vcoin(&take_txid, &vault0);
    let lot_coin = received(&take_txid, 2, 2, &mut coins);

    // ---- 2. A top-up: the vault and a collateral coin of the wallet's.
    const ADD: u64 = COIN;
    let top = SpendRequest {
        path: "top_up".into(),
        coin: v0.clone(),
        inputs: Some(vec![InputRequest::Contract, wallet_in(&topup_coin)]),
        sequence: None,
        lock_time: None,
        outputs: vec![
            out(
                "contract",
                &vault0.derived.script_pubkey,
                &x,
                v0.amount + ADD,
            ),
            out("fee", "", &x, FEE),
            out("wallet", &spk(1), &x, topup_coin.amount - ADD - FEE),
        ],
        spender: BTreeMap::from([("PATH".to_string(), "Left(Right(()))".to_string())]),
        next_slots: None,
    };
    let a = Approval::prepare(
        build(&vault0, &top, node.facts(&[(&v0.txid, v0.vout)]), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(
        s["wallet_change"][0]["change"],
        json!(format!("-{}", ADD + FEE))
    );
    assert_eq!(s["contract"]["change"][0]["change"], json!(ADD.to_string()));
    rec(
        &mut log,
        "top_up: approval",
        json!({"wallet_change": s["wallet_change"], "contract": s["contract"]["change"], "program": s["checks"]["3_program_run"], "vsize": s["vsize"]}),
    );
    let t = node.confirm(&a.sign(a.digest(), &me).unwrap());
    rec(
        &mut log,
        "top_up confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let v1 = vcoin(t["txid"].as_str().unwrap(), &vault0);

    // A path whose witness selects another path is refused.
    let mut wrong = top.clone();
    wrong.spender.insert("PATH".into(), "Left(Left(()))".into());
    let e = build(&vault0, &wrong, node.facts(&[]), &coins)
        .unwrap_err()
        .to_string();
    assert!(e.contains("which is another path"), "{e}");
    rec(
        &mut log,
        "refused: a witness that selects another path",
        json!(e),
    );

    // ---- 3. A partial repayment: the vault and the debt coin the take paid.
    const PAID: u64 = 2 * COIN;
    let debt1 = DEBT - PAID;
    let vault1 = vault_at(debt1, last0);
    let repay = SpendRequest {
        path: "repay".into(),
        coin: v1.clone(),
        inputs: Some(vec![InputRequest::Contract, wallet_in(&lot_coin)]),
        sequence: None,
        lock_time: None,
        outputs: vec![
            out("contract", &vault1.derived.script_pubkey, &x, v1.amount),
            out("pay", &lender_spk, &y, PAID),
            out("fee", "", &y, FEE),
            out("wallet", &spk(3), &y, lot_coin.amount - PAID - FEE),
        ],
        spender: BTreeMap::from([("PATH".to_string(), "Left(Left(()))".to_string())]),
        next_slots: Some(slots(debt1, last0)),
    };
    let a = Approval::prepare(
        build(&vault0, &repay, node.facts(&[(&v1.txid, v1.vout)]), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(
        s["wallet_change"][0]["change"],
        json!(format!("-{}", PAID + FEE))
    );
    assert_eq!(s["payments"][0]["amount"], json!(PAID));
    rec(
        &mut log,
        "repay (partial): approval",
        json!({"wallet_change": s["wallet_change"], "payments": s["payments"], "vsize": s["vsize"]}),
    );

    // A wallet input in another asset than shown: a request that says the
    // debt coin holds collateral is refused before anything is built...
    let mut lie = repay.clone();
    lie.inputs = Some(vec![
        InputRequest::Contract,
        InputRequest::Wallet {
            txid: lot_coin.txid.clone(),
            vout: lot_coin.vout,
            asset: x.clone(),
            amount: lot_coin.amount,
        },
    ]);
    let e = build(&vault0, &lie, node.facts(&[]), &coins)
        .unwrap_err()
        .to_string();
    assert!(e.contains("so it is not spent as shown"), "{e}");
    rec(
        &mut log,
        "refused: a wallet input said to be in another asset",
        json!(e),
    );
    // ...and an approval of the wallet's other coin, in another asset, signed
    // with the digest of the one shown, signs nothing.
    let mut other = repay.clone();
    other.inputs = Some(vec![InputRequest::Contract, wallet_in(&y_spare)]);
    other.outputs[3] = out("wallet", &spk(3), &y, y_spare.amount - PAID - FEE);
    let b = Approval::prepare(
        build(&vault0, &other, node.facts(&[(&v1.txid, v1.vout)]), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let e = b.sign(a.digest(), &me).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    rec(
        &mut log,
        "refused: another wallet coin signed with the shown digest",
        json!(e),
    );
    // Two contract inputs: a chain of contract spends is refused.
    let mut chained = repay.clone();
    chained.inputs = Some(vec![
        InputRequest::Contract,
        InputRequest::Contract,
        wallet_in(&lot_coin),
    ]);
    let e = build(&vault0, &chained, node.facts(&[]), &coins)
        .unwrap_err()
        .to_string();
    assert!(e.contains("exactly one contract input"), "{e}");
    rec(&mut log, "refused: two contract inputs", json!(e));

    let t = node.confirm(&a.sign(a.digest(), &me).unwrap());
    rec(
        &mut log,
        "repay (partial) confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let rtx = t["txid"].as_str().unwrap().to_string();
    let v2 = vcoin(&rtx, &vault1);
    let change_y = received(&rtx, 3, 3, &mut coins);

    // ---- 4. A liquidation under a fresh price: the vault, the beacon coin, the wallet's debt coin.
    node.advance(600);
    let time = node.mtp() - 1;
    let price: u64 = 90_000_000; // 0.9 YDEBT per XCOL
    let c = v2.amount;
    let ratios = vault::Ratios {
        precision: PRECISION,
        liq_bp: LIQ_BP,
        target_bp: TARGET_BP,
        bonus_bp: BONUS_BP,
    };
    assert!(!vault::healthy(c, debt1, price, PRECISION, LIQ_BP).unwrap());
    let r = vault::max_repay(c, debt1, price, PRECISION, TARGET_BP, BONUS_BP).unwrap();
    let seized = c.min(vault::max_seizure(r, price, PRECISION, BONUS_BP).unwrap());
    let kept = c - seized;
    let ruled = vault::liquidation(
        c,
        debt1,
        u32::try_from(last0).unwrap(),
        u32::try_from(time).unwrap(),
        price,
        ratios,
        r,
        kept,
        false,
    )
    .unwrap();
    assert!(!ruled.closes);
    let debt2 = ruled.debt_after;
    let vault2 = vault_at(debt2, time);
    let a_t = Attestation {
        key: oracle,
        base: <[u8; 32]>::try_from(unhex_any(&internal(&x)).unwrap()).unwrap(),
        quote: <[u8; 32]>::try_from(unhex_any(&internal(&y)).unwrap()).unwrap(),
        price,
        precision: PRECISION,
        time: u32::try_from(time).unwrap(),
        beacon,
    };
    let sig = a_t.sign(&oracle_sk, &[1u8; 32]).unwrap();
    let foreign = |(txid, vout): &(String, u32)| InputRequest::Foreign {
        txid: txid.clone(),
        vout: *vout,
        script_pubkey: beacon_spk.clone(),
        asset: beacon_asset.clone(),
        amount: 1,
        witness: vec![hex(&recreate), hex(&beacon_cb)],
        sequence: None,
        label: Some("the oracle's beacon coin".into()),
    };
    let liq = |b: &(String, u32)| SpendRequest {
        path: "liquidate".into(),
        coin: v2.clone(),
        inputs: Some(vec![
            InputRequest::Contract,
            foreign(b),
            wallet_in(&change_y),
        ]),
        sequence: None,
        lock_time: Some(u32::try_from(time).unwrap()),
        outputs: vec![
            out("contract", &vault2.derived.script_pubkey, &x, kept),
            out("pay", &lender_spk, &y, r),
            OutputRequest {
                input: Some(1),
                ..out("foreign", &beacon_spk, &beacon_asset, 1)
            },
            out("wallet", &spk(4), &x, seized),
            out("wallet", &spk(3), &y, change_y.amount - r - FEE),
            out("fee", "", &y, FEE),
        ],
        spender: BTreeMap::from([(
            "PATH".to_string(),
            format!(
                "Right(Left(({price}, {time}, 0x{}, 0x{}, 1, false)))",
                hex(&beacon),
                hex(&sig)
            ),
        )]),
        next_slots: Some(slots(debt2, time)),
    };
    let b0 = &beacon_coins[0];
    let b1 = &beacon_coins[1];
    let lfacts = |b: &(String, u32)| node.facts(&[(&v2.txid, v2.vout), (&b.0, b.1)]);
    let req0 = liq(b0);
    let a = Approval::prepare(
        build(&vault1, &req0, lfacts(b0), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(s["inputs"][1]["is"], json!("foreign"));
    let what = s["inputs"][1]["shown"].as_str().unwrap();
    assert!(
        what.contains("BEACON_ASSET") && what.contains("recreated at output 2"),
        "{what}"
    );
    assert_eq!(s["inputs"][1]["checked_against_chain"], json!(true));
    rec(
        &mut log,
        "liquidate: approval",
        json!({"inputs": s["inputs"], "wallet_change": s["wallet_change"], "checks": s["checks"], "vsize": s["vsize"], "repaid": r, "seized": seized}),
    );

    // A foreign coin the chain's record does not back is refused.
    let e = build(&vault1, &req0, node.facts(&[(&v2.txid, v2.vout)]), &coins)
        .unwrap_err()
        .to_string();
    assert!(e.contains("the chain's record of it was not given"), "{e}");
    rec(
        &mut log,
        "refused: a foreign coin with no chain record",
        json!(e),
    );
    let mut said = req0.clone();
    if let Some(InputRequest::Foreign { amount, .. }) = said.inputs.as_mut().unwrap().get_mut(1) {
        *amount = 2;
    }
    let e = build(&vault1, &said, lfacts(b0), &coins)
        .unwrap_err()
        .to_string();
    assert!(e.contains("the chain's record is 1 atoms"), "{e}");
    rec(
        &mut log,
        "refused: a foreign coin said to hold what the chain does not",
        json!(e),
    );
    // The foreign coin changed after the summary: the other beacon coin, signed
    // with the digest shown for the first.
    let b_other = Approval::prepare(
        build(&vault1, &liq(b1), lfacts(b1), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let e = b_other.sign(a.digest(), &me).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    rec(
        &mut log,
        "refused: a foreign input changed after the summary",
        json!(e),
    );

    let signed = a.sign(a.digest(), &me).unwrap();
    // What the wallet's signature means: it commits to every input's outpoint,
    // so the signed spend moved onto the other beacon coin is refused in a block.
    let mut moved = signed.clone();
    moved.input[1].previous_output = simplicityhl::elements::OutPoint::new(
        simplicityhl::elements::Txid::from_str(&b1.0).unwrap(),
        b1.1,
    );
    let hm = serialize_hex(&moved);
    let (m, blk) = (node.mempool(&hm), node.force(&hm));
    assert!(
        blk.contains("TestBlockValidity") && blk.contains("mempool-script-verify-flag-failed"),
        "{blk}"
    );
    rec(
        &mut log,
        "chain refuses the signed liquidation moved to another beacon coin",
        json!({"mempool": m, "block": blk}),
    );

    let t = node.confirm(&signed);
    rec(
        &mut log,
        "liquidate confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let ltx = t["txid"].as_str().unwrap().to_string();
    let (bv, _, ba) = node.vout_to(&ltx, &beacon_spk);
    assert_eq!((bv, ba), (2, 1), "the beacon coin is recreated at output 2");
    let v3 = vcoin(&ltx, &vault2);
    let change_y2 = received(&ltx, 4, 3, &mut coins);

    // ---- 5. The full repayment: the collateral back to the borrower, this wallet.
    let full = SpendRequest {
        path: "repay".into(),
        coin: v3.clone(),
        inputs: Some(vec![
            InputRequest::Contract,
            wallet_in(&change_y2),
            wallet_in(&y_spare),
        ]),
        sequence: None,
        lock_time: None,
        outputs: vec![
            out("wallet", &borrower_spk, &x, v3.amount),
            out("pay", &lender_spk, &y, debt2),
            out("fee", "", &y, FEE),
            out(
                "wallet",
                &spk(6),
                &y,
                change_y2.amount + y_spare.amount - debt2 - FEE,
            ),
        ],
        spender: BTreeMap::from([("PATH".to_string(), "Left(Left(()))".to_string())]),
        next_slots: None,
    };
    let a = Approval::prepare(
        build(&vault2, &full, node.facts(&[(&v3.txid, v3.vout)]), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    rec(
        &mut log,
        "repay (full): approval",
        json!({"wallet_change": s["wallet_change"], "contract": s["contract"]["change"], "payments": s["payments"], "vsize": s["vsize"]}),
    );
    let t = node.confirm(&a.sign(a.digest(), &me).unwrap());
    rec(
        &mut log,
        "repay (full) confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let closed = t["txid"].as_str().unwrap();
    let (_, asset, back) = node.vout_to(closed, &borrower_spk);
    assert_eq!((asset, back), (x.clone(), v3.amount));
    let _: Transaction = deserialize(&unhex_any(&serialize_hex(&signed)).unwrap()).unwrap();

    if let Some(out) = std::env::var_os("VAULT_REGTEST_LOG") {
        std::fs::write(out, serde_json::to_string_pretty(&log).unwrap()).unwrap();
    }
}
