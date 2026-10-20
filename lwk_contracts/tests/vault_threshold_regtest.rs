//! The engine spends a Pignus loan of several oracles on a local chain, under
//! the five-point rule: the take of a 2-of-3 offer (`pignus/offer-threshold`),
//! which opens a `pignus/vault-threshold`, and its liquidation under a price
//! record two of the three oracles signed alike, each signer's beacon coin
//! spent beside the vault and recreated at its output 2j.
//!
//! The refusals it asserts: the liquidation with one signature, which the
//! engine refuses because the program it runs refuses it; a beacon coin
//! switched after the summary (the digest differs); and, forced into a block,
//! the signed liquidation with its second beacon input moved to another coin
//! of that beacon, which the block refuses for the wallet input's signature.
//! The node runs with `-par=1` so the error names it.
//!
//!     SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test vault_threshold_regtest -- --nocapture
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
const THRESHOLD: u8 = 2;
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
    let dir = std::env::temp_dir().join(format!(
        "lwk-contracts-vault-threshold-{}",
        std::process::id()
    ));
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
fn a_two_of_three_pignus_loan_under_the_five_point_rule() {
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
    let x = issue("1000"); // the collateral
    let y = issue("1000"); // the debt asset
    let mut rates = node.json(&["getfeeexchangerates"]);
    rates[&x] = json!(COIN);
    rates[&y] = json!(COIN);
    node.ok(&["setfeeexchangerates", &rates.to_string()]);

    // Three oracles, each with its own beacon asset and two beacon coins.
    struct Oracle {
        sk: [u8; 32],
        key: [u8; 32],
        beacon: [u8; 32],
        spk: String,
        asset: String,
        cb: Vec<u8>,
        coins: Vec<(String, u32)>,
    }
    let recreate = att::beacon_recreate_leaf();
    let mut oracles: Vec<Oracle> = Vec::new();
    for i in 0..3u8 {
        let sk = [7 + i; 32];
        let key = att::xonly_of(&sk).unwrap();
        let nonce = [20 + i; 32];
        let (beacon, _root, parity) = att::beacon_output(&key, &nonce).unwrap();
        let spk = format!("5120{}", hex(&beacon));
        let rotate = att::beacon_rotate_leaf(&key, &nonce);
        let rotate_hash = {
            let mut m = vec![att::TAPSCRIPT_LEAF, u8::try_from(rotate.len()).unwrap()];
            m.extend_from_slice(&rotate);
            att::tagged_hash("TapLeaf/elements", &m)
        };
        let mut cb = vec![att::TAPSCRIPT_LEAF | parity];
        cb.extend_from_slice(&att::NUMS);
        cb.extend_from_slice(&rotate_hash);
        let asset = issue("0.00000002");
        let addr = Address::from_script(
            &script_from_hex(&spk).unwrap(),
            None,
            &AddressParams::ELEMENTS,
        )
        .unwrap()
        .to_string();
        let mut coins = Vec::new();
        for _ in 0..2 {
            let txid = node.ok(&[
                "-named",
                "sendtoaddress",
                &format!("address={addr}"),
                "amount=0.00000001",
                &format!("assetlabel={asset}"),
                "fee_asset_label=bitcoin",
            ]);
            node.mine(1);
            let (vout, _, amount) = node.vout_to(&txid, &spk);
            assert_eq!(amount, 1);
            coins.push((txid, vout));
        }
        oracles.push(Oracle {
            sk,
            key,
            beacon,
            spk,
            asset,
            cb,
            coins,
        });
    }
    let t = node.tip()["time"].as_u64().unwrap();
    node.ok(&["setmocktime", &(t + 60).to_string()]);
    node.mine(12);
    rec(
        &mut log,
        "oracles",
        json!(oracles
            .iter()
            .map(|o| json!({"key": hex(&o.key), "beacon": hex(&o.beacon), "asset": o.asset}))
            .collect::<Vec<_>>()),
    );

    // The borrower: this wallet, funded at its own P2WPKH keys.
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
    let coll_coin = fund(0, &x, "11", &mut coins);
    let y_coin = fund(5, &y, "20", &mut coins);

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
            ("THRESHOLD".into(), format!("{THRESHOLD:02x}")),
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
        for (i, o) in oracles.iter().enumerate() {
            p.insert(format!("ORACLE_{}", i + 1), hex(&o.key));
            p.insert(format!("BEACON_ASSET_{}", i + 1), internal(&o.asset));
        }
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
    let offer_t = Arc::new(
        known(known::PIGNUS_OFFER_THRESHOLD)
            .unwrap()
            .template()
            .unwrap(),
    );
    let vault_t = Arc::new(
        known(known::PIGNUS_VAULT_THRESHOLD)
            .unwrap()
            .template()
            .unwrap(),
    );
    let offer = Arc::new(
        Contract::new(
            offer_t,
            Instance {
                instance: 2,
                template_hash: known::PIGNUS_OFFER_THRESHOLD.into(),
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
            template_hash: known::PIGNUS_VAULT_THRESHOLD.into(),
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

    let offer_addr = offer.address("ert").unwrap();
    let otx = node.ok(&[
        "-named",
        "sendtoaddress",
        &format!("address={offer_addr}"),
        &format!("amount={}", LOT / COIN),
        &format!("assetlabel={y}"),
        "fee_asset_label=bitcoin",
    ]);
    node.mine(1);
    let (ovout, _, oamount) = node.vout_to(&otx, &offer.derived.script_pubkey);
    let label = |t: &str, p: u8| AssetLabel {
        ticker: t.into(),
        precision: p,
    };
    let mut assets = BTreeMap::from([
        (x.clone(), label("XCOL", 8)),
        (y.clone(), label("YDEBT", 8)),
    ]);
    for (i, o) in oracles.iter().enumerate() {
        assets.insert(o.asset.clone(), label(&format!("BEACON{}", i + 1), 0));
    }
    let view = WalletView {
        known: vec![
            known::PIGNUS_OFFER_THRESHOLD.into(),
            known::PIGNUS_VAULT_THRESHOLD.into(),
        ],
        registry: None,
        assets,
        key_path: None,
    };
    let build = |c: &Arc<Contract>, req: &SpendRequest, facts: ChainFacts, coins: &[WalletCoin]| {
        Spend::build_with_coins(c.clone(), chain, req, &scripts, coins, Some(facts))
    };

    // ---- 1. The take of the 2-of-3 offer: one lot, the offer closes.
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
    let a = Approval::prepare(
        build(&offer, &take, node.facts(&[(&otx, ovout)]), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(s["template"]["hash"], json!(known::PIGNUS_OFFER_THRESHOLD));
    assert_eq!(s["path"]["name"], json!("take"));
    assert_eq!(
        s["opens"][0]["template_hash"],
        json!(known::PIGNUS_VAULT_THRESHOLD)
    );
    rec(
        &mut log,
        "take: approval",
        json!({"template": s["template"], "opens": s["opens"][0]["shown"], "wallet_change": s["wallet_change"], "checks": s["checks"], "vsize": s["vsize"]}),
    );
    let t = node.confirm(&a.sign(a.digest(), &me).unwrap());
    rec(
        &mut log,
        "take confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let take_txid = t["txid"].as_str().unwrap().to_string();
    let (vv, va, vamt) = node.vout_to(&take_txid, &vault0.derived.script_pubkey);
    let v0 = CoinRequest {
        txid: take_txid.clone(),
        vout: vv,
        script_pubkey: vault0.derived.script_pubkey.clone(),
        asset: va,
        amount: vamt,
    };

    // ---- 2. The price falls; oracles 1 and 3 sign the record, oracle 2 abstains.
    node.advance(600);
    let time = node.mtp() - 1;
    let price: u64 = 115_000_000; // 109.5 %: under LIQ_BP, a partial liquidation back to TARGET_BP
    let c = v0.amount;
    let ratios = vault::Ratios {
        precision: PRECISION,
        liq_bp: LIQ_BP,
        target_bp: TARGET_BP,
        bonus_bp: BONUS_BP,
    };
    assert!(!vault::healthy(c, DEBT, price, PRECISION, LIQ_BP).unwrap());
    let r = vault::max_repay(c, DEBT, price, PRECISION, TARGET_BP, BONUS_BP).unwrap();
    let seized = c.min(vault::max_seizure(r, price, PRECISION, BONUS_BP).unwrap());
    let kept = c - seized;
    let ruled = vault::liquidation(
        c,
        DEBT,
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
    let debt1 = ruled.debt_after;
    let vault1 = vault_at(debt1, time);
    let sig_of = |o: &Oracle| -> [u8; 64] {
        Attestation {
            key: o.key,
            base: <[u8; 32]>::try_from(unhex_any(&internal(&x)).unwrap()).unwrap(),
            quote: <[u8; 32]>::try_from(unhex_any(&internal(&y)).unwrap()).unwrap(),
            price,
            precision: PRECISION,
            time: u32::try_from(time).unwrap(),
            beacon: o.beacon,
        }
        .sign(&o.sk, &[1u8; 32])
        .unwrap()
    };
    let foreign = |o: &Oracle, b: &(String, u32)| InputRequest::Foreign {
        txid: b.0.clone(),
        vout: b.1,
        script_pubkey: o.spk.clone(),
        asset: o.asset.clone(),
        amount: 1,
        witness: vec![hex(&recreate), hex(&o.cb)],
        sequence: None,
        label: Some("an oracle's beacon coin".into()),
    };
    // `signers`: (oracle index, its beacon coin), in key order; the j-th is input j+1.
    let liq = |signers: &[(usize, usize)]| -> SpendRequest {
        let mut inputs = vec![InputRequest::Contract];
        let mut slots = vec!["None".to_string(); 3];
        for (j, (i, b)) in signers.iter().enumerate() {
            let o = &oracles[*i];
            inputs.push(foreign(o, &o.coins[*b]));
            slots[*i] = format!(
                "Some((0x{}, 0x{}, {}))",
                hex(&sig_of(o)),
                hex(&o.beacon),
                j + 1
            );
        }
        inputs.push(wallet_in(&y_coin));
        // Beacon j at output 2j; the seizure at 3, the change after the last beacon.
        let beacon_out = |j: usize| {
            let o = &oracles[signers[j - 1].0];
            OutputRequest {
                input: Some(j),
                ..out("foreign", &o.spk, &o.asset, 1)
            }
        };
        let mut outputs = vec![
            out("contract", &vault1.derived.script_pubkey, &x, kept),
            out("pay", &lender_spk, &y, r),
            beacon_out(1),
            out("wallet", &spk(4), &x, seized),
        ];
        if signers.len() == 2 {
            outputs.push(beacon_out(2));
        }
        outputs.push(out("wallet", &spk(3), &y, y_coin.amount - r - FEE));
        outputs.push(out("fee", "", &y, FEE));
        SpendRequest {
            path: "liquidate".into(),
            coin: v0.clone(),
            inputs: Some(inputs),
            sequence: None,
            lock_time: Some(u32::try_from(time).unwrap()),
            outputs,
            spender: BTreeMap::from([(
                "PATH".to_string(),
                format!(
                    "Right(Left(({price}, {time}, [{}], false)))",
                    slots.join(", ")
                ),
            )]),
            next_slots: Some(BTreeMap::from([
                ("DEBT_OUT".to_string(), format!("{debt1:016x}")),
                ("LAST_TIME".into(), format!("{time:08x}")),
            ])),
        }
    };
    let facts_for = |signers: &[(usize, usize)]| {
        let mut rs: Vec<(&str, u32)> = vec![(&v0.txid, v0.vout)];
        for (i, b) in signers {
            let (t, v) = &oracles[*i].coins[*b];
            rs.push((t, *v));
        }
        node.facts(&rs)
    };

    // One signature of a 2-of-3: the engine runs the program, which refuses.
    let one = [(0usize, 0usize)];
    let e = match build(&vault0, &liq(&one), facts_for(&one), &coins) {
        Ok(sp) => Approval::prepare(sp, view.clone(), &me)
            .map(|_| "prepared".to_string())
            .unwrap_or_else(|e| e.to_string()),
        Err(e) => e.to_string(),
    };
    assert_ne!(
        e, "prepared",
        "a 2-of-3 liquidation with one signature was prepared"
    );
    rec(&mut log, "refused: one signature of a 2-of-3", json!(e));

    let two = [(0usize, 0usize), (2, 0)];
    let req = liq(&two);
    let a = Approval::prepare(
        build(&vault0, &req, facts_for(&two), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(s["template"]["hash"], json!(known::PIGNUS_VAULT_THRESHOLD));
    assert_eq!(s["path"]["name"], json!("liquidate"));
    for (k, (p, at)) in [("BEACON_ASSET_1", 2), ("BEACON_ASSET_3", 4)]
        .iter()
        .enumerate()
    {
        let inp = &s["inputs"][k + 1];
        assert_eq!(inp["is"], json!("foreign"));
        assert_eq!(inp["checked_against_chain"], json!(true));
        let what = inp["shown"].as_str().unwrap();
        assert!(
            what.contains(p) && what.contains(&format!("recreated at output {at}")),
            "{what}"
        );
    }
    rec(
        &mut log,
        "liquidate 2-of-3: approval",
        json!({"inputs": s["inputs"], "wallet_change": s["wallet_change"], "checks": s["checks"], "vsize": s["vsize"], "repaid": r, "seized": seized}),
    );

    // A beacon coin switched after the summary: oracle 3's other coin.
    let switched = [(0usize, 0usize), (2, 1)];
    let other = Approval::prepare(
        build(&vault0, &liq(&switched), facts_for(&switched), &coins).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let e = other.sign(a.digest(), &me).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    rec(
        &mut log,
        "refused: a beacon coin switched after the summary",
        json!(e),
    );

    let signed = a.sign(a.digest(), &me).unwrap();
    let mut moved = signed.clone();
    let (b_txid, b_vout) = &oracles[2].coins[1];
    moved.input[2].previous_output = simplicityhl::elements::OutPoint::new(
        simplicityhl::elements::Txid::from_str(b_txid).unwrap(),
        *b_vout,
    );
    let hm = serialize_hex(&moved);
    let (m, blk) = (node.mempool(&hm), node.force(&hm));
    assert!(
        blk.contains("TestBlockValidity") && blk.contains("mempool-script-verify-flag-failed"),
        "{blk}"
    );
    rec(
        &mut log,
        "chain refuses the signed liquidation with its second beacon moved",
        json!({"mempool": m, "block": blk}),
    );

    let t = node.confirm(&signed);
    rec(
        &mut log,
        "liquidate 2-of-3 confirmed",
        json!({"txid": t["txid"], "vsize": t["vsize"]}),
    );
    let ltx = t["txid"].as_str().unwrap().to_string();
    assert_eq!(node.vout_to(&ltx, &oracles[0].spk).0, 2);
    assert_eq!(node.vout_to(&ltx, &oracles[2].spk).0, 4);
    let (_, _, left) = node.vout_to(&ltx, &vault1.derived.script_pubkey);
    assert_eq!(left, kept);
    let _: Transaction = deserialize(&unhex_any(&serialize_hex(&signed)).unwrap()).unwrap();

    if let Some(out) = std::env::var_os("VAULT_THRESHOLD_REGTEST_LOG") {
        std::fs::write(out, serde_json::to_string_pretty(&log).unwrap()).unwrap();
    }
}
