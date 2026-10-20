//! The engine spends a Pignus version 2 loan on a local chain, under the
//! The engine signs the two spends a wallet makes for Levo and SeqPal, on a
//! local chain, under the five-point rule:
//!
//! - a capped sale's purchase (`sequentia/capped-sale`, path `purchase`),
//!   signed by this wallet's contract key as the buyer's key on the
//!   allocation list, paid from this wallet's own coins, fee in the asset
//!   paid; then a second purchase that fills the cap exactly;
//! - a subscription escrow's release (`sequentia/subscription-escrow`, path
//!   `release`) of three subscription coins in one transaction, each its own
//!   instance, all signed by this wallet's contract key as the issuer's.
//!
//! The refusals it asserts: a purchase past the cap (refused before anything
//! is built); a key that is not this wallet's; a request that gives the
//! signature itself; the program run against an over-cap purchase; a release
//! before the close; a release coin whose instance names another issuer key;
//! a release coin the chain's record does not back. Forced into blocks with
//! `generateblock` (the node runs `-par=1`, so the block error names the
//! script failure): the over-cap purchase, forged from the cap-filling
//! purchase's own pruned program with the amount raised one atom and the
//! buyer's signature made again; the cap-filling purchase with its treasury
//! payment changed under the buyer's signature; and the release with one
//! coin taken out under the issuer's signatures.
//!
//!     SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test sale_escrow_regtest -- --nocapture
//!
//! Without `SEQUENTIA_BIN` the test does nothing. `SALE_ESCROW_RECORD` names a
//! file the run's record is written to.

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
use sequentia_contracts::sale::{self, Entry};
use serde_json::{json, Value};
use simplicityhl::elements::bitcoin::bip32::DerivationPath;
use simplicityhl::elements::confidential::Value as ConfValue;
use simplicityhl::elements::encode::serialize_hex;
use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::{Message, Secp256k1};
use simplicityhl::elements::sighash::SighashCache;
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::elements::{
    Address, AddressParams, BlockHash, EcdsaSighashType, PubkeyHash, Script, Transaction,
    TxInWitness, WPubkeyHash,
};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::Cmr;

// A public test mnemonic, never funded anywhere but a local chain.
const WALLET: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";
const CONTRACT_KEY: &str = "m/8383h/1h/0h/0/0";

const COIN: u64 = 100_000_000;
const FEE: u64 = 20_000;
const PRICE_NUM: u64 = 2;
const PRICE_DEN: u64 = 1;
const MIN_LOT: u64 = 10_000_000;
const CAP: u64 = 300_000_000;
const SALE: u64 = 1_000_000_000;
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
    let dir =
        std::env::temp_dir().join(format!("lwk-contracts-sale-escrow-{}", std::process::id()));
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

/// This wallet's P2WPKH script at `m/84h/1h/0h/0/i`.
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

fn u64h(n: u64) -> String {
    format!("{n:016x}")
}

fn proof_literal(entries: &[Entry], i: usize) -> String {
    let p = sale::proof(entries, i).unwrap();
    format!(
        "[{}]",
        p.iter()
            .map(|(s, left)| format!("(0x{}, {left})", hex(s)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The hash a Simplicity input signs, for any transaction: what an adversary
/// computes to sign again a pruned program it reuses.
fn sig_all_hash(
    tx: &Transaction,
    prevouts: &[simplicityhl::elements::TxOut],
    k: usize,
    cmr: Cmr,
    cb: &ControlBlock,
    annex: Option<&[u8]>,
    genesis: BlockHash,
) -> [u8; 32] {
    let mut tx = tx.clone();
    tx.input[k].witness.script_witness = match annex {
        Some(a) => vec![Vec::new(), a.to_vec()],
        None => Vec::new(),
    };
    let utxos = prevouts
        .iter()
        .map(|p| ElementsUtxo {
            script_pubkey: p.script_pubkey.clone(),
            asset: p.asset,
            value: p.value,
        })
        .collect();
    let env = ElementsEnv::new(
        Arc::new(tx),
        utxos,
        u32::try_from(k).unwrap(),
        cmr,
        cb.clone(),
        annex.map(|a| a[1..].to_vec()),
        genesis,
    );
    env.c_tx_env().sighash_all().to_byte_array()
}

fn bits(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        s.push_str(&format!("{x:08b}"));
        s
    })
}

/// Replaces the bit pattern of `old` by `new` inside `blob`; it must occur once.
fn bit_replace(blob: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let (b, o, n) = (bits(blob), bits(old), bits(new));
    assert_eq!(
        b.matches(&o).count(),
        1,
        "the pattern occurs once in the witness"
    );
    let r = b.replacen(&o, &n, 1);
    let mut out: Vec<u8> = (0..r.len() / 8 * 8)
        .step_by(8)
        .map(|i| u8::from_str_radix(&r[i..i + 8], 2).unwrap())
        .collect();
    if r.len() % 8 != 0 {
        let tail = &r[r.len() / 8 * 8..];
        out.push(u8::from_str_radix(&format!("{tail:0<8}"), 2).unwrap());
    }
    out
}

/// Signs each P2WPKH input of `tx` whose key path is given, `SIGHASH_ALL`.
fn sign_p2wpkh(signer: &SwSigner, tx: &mut Transaction, inputs: &[(usize, String, u64)]) {
    let secp = Secp256k1::new();
    let unsigned = tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    for (i, path, amount) in inputs {
        let sk = signer
            .derive_xprv(&DerivationPath::from_str(path).unwrap())
            .unwrap()
            .private_key;
        let pk = simplicityhl::elements::bitcoin::PublicKey::new(sk.public_key(&secp));
        let code = Script::new_p2pkh(&PubkeyHash::hash(&pk.to_bytes()));
        let h = cache.segwitv0_sighash(
            *i,
            &code,
            ConfValue::Explicit(*amount),
            EcdsaSighashType::All,
        );
        let sig = secp.sign_ecdsa_low_r(&Message::from_digest(h.to_byte_array()), &sk);
        let mut der = sig.serialize_der().to_vec();
        der.push(EcdsaSighashType::All as u8);
        tx.input[*i].witness = TxInWitness {
            script_witness: vec![der, pk.to_bytes()],
            ..Default::default()
        };
    }
}

fn set_amount(tx: &mut Transaction, i: usize, amount: u64) {
    tx.output[i].value = ConfValue::Explicit(amount);
}

fn amount_of(tx: &Transaction, i: usize) -> u64 {
    tx.output[i].value.explicit().unwrap()
}

#[test]
fn a_capped_purchase_and_an_escrow_release_under_the_five_point_rule() {
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
    node.ok(&["createwallet", "chain"]);
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
    // The token sold and the asset paid, of equal standing; the fee is paid in
    // the asset the buyer moves, which the node accepts.
    let token = issue("100");
    let pay = issue("1000");
    let mut rates = node.json(&["getfeeexchangerates"]);
    rates[&pay] = json!(COIN);
    node.ok(&["setfeeexchangerates", &rates.to_string()]);
    rec(
        &mut log,
        "assets",
        json!({"token": token, "pay": pay, "fee_asset": pay}),
    );

    // This wallet: the kit's signer, its funding keys and its contract key.
    let me = SwSigner::new(WALLET, false).unwrap();
    let my_key = hex(&Spend::key_at(&me, CONTRACT_KEY).unwrap().serialize());
    let keys: Vec<(String, Script)> = (0..6).map(|i| wallet_key(&me, i)).collect();
    let scripts: Vec<Script> = keys.iter().map(|(_, s)| s.clone()).collect();
    let spk = |i: usize| hex(keys[i].1.as_bytes());
    let fund = |i: usize, asset: &str, amount: &str| -> WalletCoin {
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
        WalletCoin {
            txid,
            vout,
            script_pubkey: spk(i),
            asset,
            amount,
            key_path: keys[i].0.clone(),
            confidential: false,
        }
    };
    let pay_a = fund(0, &pay, "10");
    let pay_b = fund(1, &pay, "10");
    let coins = vec![pay_a.clone(), pay_b.clone()];
    let mut view = WalletView {
        known: lwk_contracts::KNOWN
            .iter()
            .map(|k| k.hash.to_string())
            .collect(),
        registry: None,
        assets: BTreeMap::new(),
        key_path: None,
    };
    view.assets.insert(
        token.clone(),
        AssetLabel {
            ticker: "TOKEN".into(),
            precision: 8,
        },
    );
    view.assets.insert(
        pay.clone(),
        AssetLabel {
            ticker: "PAY".into(),
            precision: 8,
        },
    );

    // ---- the capped sale ------------------------------------------------
    let other = [0x42u8; 32];
    let other_key = hex(&Keypair::from_seckey_slice(&Secp256k1::new(), &other)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize());
    let mut list = vec![
        Entry {
            key: <[u8; 32]>::try_from(unhex_any(&other_key).unwrap()).unwrap(),
            cap: 500_000_000,
            bought: 0,
        },
        Entry {
            key: <[u8; 32]>::try_from(unhex_any(&my_key).unwrap()).unwrap(),
            cap: CAP,
            bought: 0,
        },
    ];
    let me_at = 1;
    let treasury = node.json(&["getaddressinfo", &node.ok(&["getnewaddress", "", "bech32"])])
        ["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let close = node.tip()["height"].as_u64().unwrap() + 500;
    let sale_t = Arc::new(known(known::CAPPED_SALE).unwrap().template().unwrap());
    let params = BTreeMap::from([
        ("TOKEN".to_string(), internal(&token)),
        ("PAY_ASSET".into(), internal(&pay)),
        ("PRICE_NUM".into(), u64h(PRICE_NUM)),
        ("PRICE_DEN".into(), u64h(PRICE_DEN)),
        (
            "TREASURY".into(),
            script_hash_hex(&script_from_hex(&treasury).unwrap()),
        ),
        ("MIN_LOT".into(), u64h(MIN_LOT)),
        ("CLOSE".into(), format!("{close:08x}")),
        ("PROJECT_KEY".into(), other_key.clone()),
    ]);
    let instance_at = |entries: &[Entry]| -> Contract {
        Contract::new(
            sale_t.clone(),
            Instance {
                instance: 2,
                template_hash: known::CAPPED_SALE.into(),
                params: params.clone(),
                slots: BTreeMap::from([(
                    "ALLOCATIONS".to_string(),
                    hex(&sale::root(entries).unwrap()),
                )]),
                genesis: Some(genesis_hex.clone()),
            },
        )
        .unwrap()
    };
    let sale0 = Arc::new(instance_at(&list));
    let sale_addr = sale0.address("ert").unwrap();
    let txid = node.ok(&[
        "-named",
        "sendtoaddress",
        &format!("address={sale_addr}"),
        &format!("amount={}", SALE as f64 / COIN as f64),
        &format!("assetlabel={token}"),
        "fee_asset_label=bitcoin",
    ]);
    node.mine(1);
    let sale_spk = hex(sale0.script_pubkey().as_bytes());
    let (vout, _, amt) = node.vout_to(&txid, &sale_spk);
    rec(
        &mut log,
        "sale",
        json!({"address": sale_addr, "coin": format!("{txid}:{vout}"), "amount": amt,
        "list": [{"key": other_key, "cap": 500_000_000u64}, {"key": my_key, "cap": CAP}]}),
    );

    // A purchase of `amount` by this wallet's key from the sale coin `coin`,
    // in the state `list`, paid from `pay_coin`.
    let purchase = |list: &[Entry],
                    coin: &CoinRequest,
                    amount: u64,
                    pay_coin: &WalletCoin,
                    key_at: usize|
     -> (SpendRequest, Vec<Entry>) {
        let mut next = list.to_vec();
        next[key_at].bought += amount;
        let price = sale::payment(amount, PRICE_NUM, PRICE_DEN).unwrap() as u64;
        let rest = coin.amount - amount;
        // A list past a cap has no tree (no leaf may hold more than its cap):
        // such a request is refused before its next state matters.
        let state = if sale::root(&next).is_ok() {
            next.clone()
        } else {
            list.to_vec()
        };
        let next_c = instance_at(&state);
        let mut outputs = vec![out("pay", &treasury, &pay, price)];
        if rest > 0 {
            outputs.push(out(
                "contract",
                &hex(next_c.script_pubkey().as_bytes()),
                &token,
                rest,
            ));
        }
        outputs.push(out("wallet", &spk(2), &token, amount));
        outputs.push(out("wallet", &spk(3), &pay, pay_coin.amount - price - FEE));
        outputs.push(out("fee", "", &pay, FEE));
        let e = list[key_at];
        let req = SpendRequest {
            path: "purchase".into(),
            coin: coin.clone(),
            inputs: Some(vec![InputRequest::Contract, wallet_in(pay_coin)]),
            sequence: None,
            lock_time: None,
            outputs,
            spender: BTreeMap::from([
                ("BUYER_KEY".to_string(), hex(&e.key)),
                ("CAP".into(), u64h(e.cap)),
                ("BOUGHT".into(), u64h(e.bought)),
                ("AMOUNT".into(), u64h(amount)),
                ("PROOF".into(), proof_literal(list, key_at)),
            ]),
            next_slots: if rest > 0 {
                Some(BTreeMap::from([(
                    "ALLOCATIONS".to_string(),
                    hex(&sale::root(&state).unwrap()),
                )]))
            } else {
                None
            },
        };
        (req, next)
    };
    let contract_of = |list: &[Entry]| Arc::new(instance_at(list));
    let build = |c: &Arc<Contract>, req: &SpendRequest| {
        let facts = node.facts(&[(&req.coin.txid, req.coin.vout)]);
        Spend::build_with_coins(c.clone(), chain, req, &scripts, &coins, Some(facts))
    };

    // 1. A purchase of 1.23456789 tokens, signed through the approval.
    let coin1 = CoinRequest {
        txid: txid.clone(),
        vout,
        script_pubkey: sale_spk.clone(),
        asset: token.clone(),
        amount: amt,
    };
    let (req1, list1) = purchase(&list, &coin1, 123_456_789, &pay_a, me_at);
    let spend1 = build(&sale0, &req1).unwrap();
    let a1 = Approval::prepare(spend1, view.clone(), &me).unwrap();
    let s1 = a1.summary();
    rec(
        &mut log,
        "purchase 1 approval",
        json!({"reading": s1["reading"], "checks": s1["checks"],
        "inputs": s1["inputs"], "wallet_change": s1["wallet_change"], "vsize": s1["vsize"]}),
    );
    assert_eq!(s1["reading"]["buyer_key_is_this_wallets"], json!(true));
    assert!(s1["checks"]["5_contract_key"]
        .as_str()
        .unwrap()
        .contains("BUYER_KEY is this wallet's contract key"));
    assert!(s1["checks"]["5_contract_key"]
        .as_str()
        .unwrap()
        .contains("over this purchase and no other"));
    // A digest not shown signs nothing.
    let e = a1.sign(&"00".repeat(32), &me).unwrap_err().to_string();
    rec(&mut log, "refused: digest not shown", json!(e));
    let tx1 = a1.sign(s1["digest"].as_str().unwrap(), &me).unwrap();
    assert_eq!(node.mempool(&serialize_hex(&tx1)), "allowed");
    let t = node.confirm(&tx1);
    rec(
        &mut log,
        "purchase 1 mined",
        json!({"txid": t["txid"], "vsize": t["vsize"], "weight": t["weight"]}),
    );
    list = list1;
    let txid1 = t["txid"].as_str().unwrap().to_string();
    let sale1 = contract_of(&list);
    let spk1 = hex(sale1.script_pubkey().as_bytes());
    let (v1, _, rest1) = node.vout_to(&txid1, &spk1);
    let coin2 = CoinRequest {
        txid: txid1.clone(),
        vout: v1,
        script_pubkey: spk1,
        asset: token.clone(),
        amount: rest1,
    };
    let change1 = WalletCoin {
        txid: txid1.clone(),
        vout: 3,
        script_pubkey: spk(3),
        asset: pay.clone(),
        amount: amount_of(&tx1, 3),
        key_path: keys[3].0.clone(),
        confidential: false,
    };
    assert_eq!(hex(tx1.output[3].script_pubkey.as_bytes()), spk(3));
    let coins = vec![change1.clone(), pay_b.clone()];
    let build = |c: &Arc<Contract>, req: &SpendRequest| {
        let facts = node.facts(&[(&req.coin.txid, req.coin.vout)]);
        Spend::build_with_coins(c.clone(), chain, req, &scripts, &coins, Some(facts))
    };

    // 2. Past the cap: one atom more than what is left of it.
    let (over, _) = {
        let mut l = list.clone();
        l[me_at].cap = CAP; // the list as it is; only the amount is past it
        purchase(&l, &coin2, CAP - list[me_at].bought + 1, &pay_b, me_at)
    };
    let e = build(&sale1, &over).map(|_| ()).unwrap_err().to_string();
    assert!(e.contains("past its cap"), "{e}");
    rec(&mut log, "refused: past the cap", json!(e));

    // 3. Another key on the list: the request names the other buyer's key.
    let (theirs, _) = purchase(&list, &coin2, 100_000_000, &pay_b, 0);
    let e = Approval::prepare(build(&sale1, &theirs).unwrap(), view.clone(), &me)
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(e.contains("this wallet's contract key at"), "{e}");
    rec(&mut log, "refused: the key is not this wallet's", json!(e));

    // 4. A request that gives the signature itself.
    let mut given = purchase(&list, &coin2, 100_000_000, &pay_b, me_at).0;
    given.spender.insert("BUYER_SIG".into(), "00".repeat(64));
    let e = build(&sale1, &given).map(|_| ()).unwrap_err().to_string();
    rec(&mut log, "refused: a request gives the signature", json!(e));

    // 5. The purchase that fills the cap exactly (1 token): signed, kept as the
    //    control for the forgeries, mined after them.
    let (fill, list2) = purchase(&list, &coin2, CAP - list[me_at].bought, &pay_b, me_at);
    let spend2 = build(&sale1, &fill).unwrap();
    let prevouts2 = spend2.prevouts.clone();
    let a2 = Approval::prepare(spend2.clone(), view.clone(), &me).unwrap();
    let s2 = a2.summary();
    rec(
        &mut log,
        "purchase 2 approval",
        json!({"reading": s2["reading"], "vsize": s2["vsize"]}),
    );
    let tx2 = a2.sign(s2["digest"].as_str().unwrap(), &me).unwrap();

    // 5a. The program run, with the engine's cap check stepped around: the
    //     same spend with AMOUNT one atom more is refused by the program.
    let mut bent = spend2.clone();
    bent.spender
        .insert("AMOUNT".into(), u64h(CAP - list[me_at].bought + 1));
    let e = Approval::prepare(bent, view.clone(), &me)
        .map(|_| ())
        .unwrap_err()
        .to_string();
    rec(
        &mut log,
        "refused by the program run: one atom past the cap",
        json!(e),
    );

    // 5b. Forced: the over-cap purchase, made from the control's own pruned
    //     program, its amount raised one atom (and every output to match:
    //     2 atoms more to the treasury, 1 token atom less resting, 1 more to the
    //     buyer, 2 fewer back as change) and the buyer's signature made again.
    let w = &tx2.input[0].witness.script_witness;
    let cb = ControlBlock::from_slice(&w[3]).unwrap();
    let cmr = Cmr::from_byte_array(<[u8; 32]>::try_from(w[2].as_slice()).unwrap());
    let annex = w.get(4).cloned();
    let old_sig = {
        let msg = sig_all_hash(&tx2, &prevouts2, 0, cmr, &cb, annex.as_deref(), genesis);
        let kp = me
            .derive_xprv(&DerivationPath::from_str(CONTRACT_KEY).unwrap())
            .unwrap();
        let kp = Keypair::from_secret_key(&Secp256k1::new(), &kp.private_key);
        (
            Secp256k1::new()
                .sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp)
                .serialize(),
            kp,
        )
    };
    let (control_sig, kp) = old_sig;
    let amt2 = CAP - list[me_at].bought;
    // The method's control: the same reuse with nothing changed but the
    // signature made again is accepted, so a refusal below is the change's.
    {
        let mut same = tx2.clone();
        let msg = sig_all_hash(&same, &prevouts2, 0, cmr, &cb, annex.as_deref(), genesis);
        let sig = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp)
            .serialize();
        let mut stack = vec![
            bit_replace(&w[0], &control_sig, &sig),
            w[1].clone(),
            w[2].clone(),
            w[3].clone(),
        ];
        if let Some(a) = &annex {
            stack.push(a.clone());
        }
        same.input[0].witness.script_witness = stack;
        rec(
            &mut log,
            "control: the reused program, signed again, nothing changed",
            json!(node.mempool(&serialize_hex(&same))),
        );
    }
    let mut forged = tx2.clone();
    set_amount(&mut forged, 0, amount_of(&tx2, 0) + 2);
    set_amount(&mut forged, 1, amount_of(&tx2, 1) - 1);
    set_amount(&mut forged, 2, amount_of(&tx2, 2) + 1);
    set_amount(&mut forged, 3, amount_of(&tx2, 3) - 2);
    let msg = sig_all_hash(&forged, &prevouts2, 0, cmr, &cb, annex.as_deref(), genesis);
    let sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp)
        .serialize();
    let wit = bit_replace(&w[0], &amt2.to_be_bytes(), &(amt2 + 1).to_be_bytes());
    let wit = bit_replace(&wit, &control_sig, &sig);
    let mut stack = vec![wit, w[1].clone(), w[2].clone(), w[3].clone()];
    if let Some(a) = &annex {
        stack.push(a.clone());
    }
    forged.input[0].witness.script_witness = stack;
    sign_p2wpkh(
        &me,
        &mut forged,
        &[(1, pay_b.key_path.clone(), pay_b.amount)],
    );
    rec(
        &mut log,
        "forced: one atom past the cap",
        json!({
        "mempool": node.mempool(&serialize_hex(&forged)), "block": node.force(&serialize_hex(&forged))}),
    );

    // 5c. Forced: the control with its treasury payment raised by one atom
    //     and the change lowered by one, under the buyer's signature as made.
    let mut moved = tx2.clone();
    set_amount(&mut moved, 0, amount_of(&tx2, 0) + 1);
    set_amount(&mut moved, 3, amount_of(&tx2, 3) - 1);
    sign_p2wpkh(
        &me,
        &mut moved,
        &[(1, pay_b.key_path.clone(), pay_b.amount)],
    );
    // Its control: the same change with the buyer's signature made for it.
    {
        let mut fresh = moved.clone();
        let msg = sig_all_hash(&fresh, &prevouts2, 0, cmr, &cb, annex.as_deref(), genesis);
        let sig = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp)
            .serialize();
        fresh.input[0].witness.script_witness[0] = bit_replace(&w[0], &control_sig, &sig);
        rec(
            &mut log,
            "control: the same change, signed for it",
            json!(node.mempool(&serialize_hex(&fresh))),
        );
    }
    rec(
        &mut log,
        "forced: the buyer's signature on another transaction",
        json!({
        "mempool": node.mempool(&serialize_hex(&moved)), "block": node.force(&serialize_hex(&moved))}),
    );

    // 5d. The control itself, mined: the cap is filled.
    let t = node.confirm(&tx2);
    rec(
        &mut log,
        "purchase 2 mined (the cap is filled)",
        json!({"txid": t["txid"], "vsize": t["vsize"], "bought": list2[me_at].bought, "cap": CAP}),
    );

    // ---- the subscription escrow ---------------------------------------
    let esc_t = Arc::new(
        known(known::SUBSCRIPTION_ESCROW)
            .unwrap()
            .template()
            .unwrap(),
    );
    let issuer_spk = node.json(&["getaddressinfo", &node.ok(&["getnewaddress", "", "bech32"])])
        ["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let refund_spk = node.json(&["getaddressinfo", &node.ok(&["getnewaddress", "", "bech32"])])
        ["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let close = node.tip()["height"].as_u64().unwrap() + 6;
    let esc_instance = |sub: u8, issuer: &str| -> Contract {
        Contract::new(
            esc_t.clone(),
            Instance {
                instance: 2,
                template_hash: known::SUBSCRIPTION_ESCROW.into(),
                params: BTreeMap::from([
                    ("PAY_ASSET".to_string(), internal(&pay)),
                    ("ISSUER_KEY".into(), issuer.to_string()),
                    (
                        "ISSUER_SCRIPT".into(),
                        script_hash_hex(&script_from_hex(&issuer_spk).unwrap()),
                    ),
                    ("MINIMUM".into(), u64h(150_000_000)),
                    ("CLOSE".into(), format!("{close:08x}")),
                    (
                        "REFUND_SCRIPT".into(),
                        script_hash_hex(&script_from_hex(&refund_spk).unwrap()),
                    ),
                    ("DEADLINE".into(), format!("{:08x}", close + 1000)),
                    ("FEE_CAP".into(), u64h(100_000)),
                    ("SUBSCRIPTION".into(), hex(&[sub; 32])),
                ]),
                slots: BTreeMap::new(),
                genesis: Some(genesis_hex.clone()),
            },
        )
        .unwrap()
    };
    let mut esc = Vec::new();
    for (sub, issuer) in [
        (1u8, my_key.clone()),
        (2, my_key.clone()),
        (3, my_key.clone()),
        (4, other_key.clone()),
    ] {
        let c = esc_instance(sub, &issuer);
        let a = c.address("ert").unwrap();
        let txid = node.ok(&[
            "-named",
            "sendtoaddress",
            &format!("address={a}"),
            "amount=1",
            &format!("assetlabel={pay}"),
            "fee_asset_label=bitcoin",
        ]);
        node.mine(1);
        let s = hex(c.script_pubkey().as_bytes());
        let (vout, asset, amount) = node.vout_to(&txid, &s);
        esc.push((
            c,
            CoinRequest {
                txid,
                vout,
                script_pubkey: s,
                asset,
                amount,
            },
        ));
    }
    rec(
        &mut log,
        "escrow coins",
        json!(esc
            .iter()
            .map(|(c, k)| json!({"coin": format!("{}:{}", k.txid, k.vout),
        "address": c.address("ert").unwrap(), "issuer_key": c.instance.params["ISSUER_KEY"]}))
            .collect::<Vec<_>>()),
    );
    let release = |ids: &[usize]| -> SpendRequest {
        let total: u64 = ids.iter().map(|i| esc[*i].1.amount).sum();
        let mut inputs = vec![InputRequest::Contract];
        for i in &ids[1..] {
            inputs.push(InputRequest::Sibling {
                coin: esc[*i].1.clone(),
                instance: serde_json::to_value(&esc[*i].0.instance).unwrap(),
            });
        }
        SpendRequest {
            path: "release".into(),
            coin: esc[ids[0]].1.clone(),
            inputs: Some(inputs),
            sequence: None,
            lock_time: None,
            outputs: vec![
                out("pay", &issuer_spk, &pay, total - FEE),
                out("fee", "", &pay, FEE),
            ],
            spender: BTreeMap::new(),
            next_slots: None,
        }
    };
    let build_release = |req: &SpendRequest, records: &[usize]| {
        let r: Vec<(&str, u32)> = records
            .iter()
            .map(|i| (esc[*i].1.txid.as_str(), esc[*i].1.vout))
            .collect();
        Spend::build_with_coins(
            Arc::new(esc[0].0.clone()),
            chain,
            req,
            &scripts,
            &[],
            Some(node.facts(&r)),
        )
    };
    // Before the close the engine refuses.
    let early = Approval::prepare(
        build_release(&release(&[0, 1, 2]), &[0, 1, 2]).unwrap(),
        view.clone(),
        &me,
    )
    .map(|_| ())
    .unwrap_err()
    .to_string();
    rec(&mut log, "refused: release before the close", json!(early));
    while node.tip()["height"].as_u64().unwrap() < close {
        node.mine(1);
    }
    // A coin whose instance names another issuer key.
    let e = build_release(&release(&[0, 1, 3]), &[0, 1, 3])
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(e.contains("ISSUER_KEY"), "{e}");
    rec(&mut log, "refused: a coin of another issuer key", json!(e));
    // A coin the chain's record was not given for.
    let e = build_release(&release(&[0, 1, 2]), &[0, 1])
        .map(|_| ())
        .unwrap_err()
        .to_string();
    rec(
        &mut log,
        "refused: a coin the chain's record does not back",
        json!(e),
    );
    // The release of three coins.
    let a3 = Approval::prepare(
        build_release(&release(&[0, 1, 2]), &[0, 1, 2]).unwrap(),
        view.clone(),
        &me,
    )
    .unwrap();
    let s3 = a3.summary();
    assert!(s3["checks"]["5_contract_key"]
        .as_str()
        .unwrap()
        .contains("it signs inputs [0, 1, 2]"));
    rec(
        &mut log,
        "release approval",
        json!({"inputs": s3["inputs"], "checks": s3["checks"], "payments": s3["payments"],
        "fee": s3["fee"], "vsize": s3["vsize"]}),
    );
    let tx3 = a3.sign(s3["digest"].as_str().unwrap(), &me).unwrap();
    // Control: the release of the first two coins alone, signed for itself,
    // pays more than the minimum and is accepted.
    {
        let a = Approval::prepare(
            build_release(&release(&[0, 1]), &[0, 1]).unwrap(),
            view.clone(),
            &me,
        )
        .unwrap();
        let t = a
            .sign(a.summary()["digest"].as_str().unwrap(), &me)
            .unwrap();
        rec(
            &mut log,
            "control: a release of two coins, signed for itself",
            json!(node.mempool(&serialize_hex(&t))),
        );
    }
    // Forced: the release with its third coin taken out and the raise lowered
    // to match, under the issuer's signatures as made.
    let mut fewer = tx3.clone();
    fewer.input.pop();
    set_amount(&mut fewer, 0, amount_of(&tx3, 0) - esc[2].1.amount);
    rec(
        &mut log,
        "forced: a release with one coin taken out",
        json!({
        "mempool": node.mempool(&serialize_hex(&fewer)), "block": node.force(&serialize_hex(&fewer))}),
    );
    let t = node.confirm(&tx3);
    rec(
        &mut log,
        "release mined",
        json!({"txid": t["txid"], "vsize": t["vsize"], "inputs": 3,
        "to_issuer": amount_of(&tx3, 0)}),
    );

    if let Some(p) = std::env::var_os("SALE_ESCROW_RECORD") {
        std::fs::write(p, serde_json::to_string_pretty(&log).unwrap()).unwrap();
    }
}
