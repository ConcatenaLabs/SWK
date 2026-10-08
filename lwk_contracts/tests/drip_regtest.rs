//! The engine drips from a faucet drip covenant on a local chain, under the
//! five-point rule, and refuses three bad drips before signing: one before the
//! interval, one above the tier, one whose successor is not the covenant. Each
//! bad drip is then forced on the chain as an adversary would build it (the
//! control's pruned program, re-signed for the bad transaction, as the
//! contracts harness does) and refused by the mempool and in a block made with
//! `generateblock`, for its reason; the node runs with `-par=1` so the block's
//! error names it.
//!
//!     SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test drip_regtest -- --nocapture
//!
//! Without `SEQUENTIA_BIN` the test does nothing. The chain's data directory
//! is a fresh temporary directory, removed when the test ends.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;

use lwk_contracts::approval::{Approval, AssetLabel, WalletView};
use lwk_contracts::spend::{default_contract_key_path, Chain, ChainFacts, CoinRequest, Spend};
use lwk_contracts::{drip, known, Contract, Instance};
use lwk_signer::SwSigner;
use serde_json::{json, Value};
use simplicityhl::elements::encode::{deserialize, serialize_hex};
use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::{Message, Secp256k1};
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::elements::{BlockHash, Transaction};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::Cmr;

// Public test mnemonics, never funded anywhere but a local chain.
const FAUCET: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";
const TREASURY: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const COIN: u64 = 100_000_000;
const RESERVE: u64 = 2_000_000 * COIN;
const FEE_CAP: u64 = 100_000;
const INTERVAL: u64 = 1;
const TIME: u32 = 1 << 22;

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
    /// Moves the median time past forward by at least `secs`.
    fn advance(&self, secs: u64) {
        let t = self.tip()["time"].as_u64().unwrap();
        self.ok(&["setmocktime", &(t + secs + 60).to_string()]);
        self.mine(12);
    }
    fn mtp_at(&self, height: u64) -> u64 {
        let h = self.ok(&["getblockhash", &height.to_string()]);
        self.json(&["getblockheader", &h])["mediantime"]
            .as_u64()
            .unwrap()
    }
    /// What the chain says about a confirmed coin, as a wallet reads it.
    fn facts(&self, txid: &str) -> ChainFacts {
        let tx = self.json(&["getrawtransaction", txid, "true"]);
        let height = self.json(&["getblockheader", tx["blockhash"].as_str().unwrap()])["height"]
            .as_u64()
            .unwrap();
        let tip = self.tip();
        ChainFacts {
            tip_height: tip["height"].as_u64().unwrap(),
            tip_median_time: tip["mediantime"].as_u64().unwrap(),
            coin_height: Some(height),
            coin_start_median_time: Some(self.mtp_at(height - 1)),
        }
    }
    /// The mempool's verdict on a transaction.
    fn mempool(&self, hex: &str) -> String {
        let v = self.json(&["testmempoolaccept", &json!([hex]).to_string()]);
        if v[0]["allowed"] == json!(true) {
            "allowed".into()
        } else {
            v[0]["reject-reason"].as_str().unwrap().to_string()
        }
    }
    /// Forces a transaction into a block; the node's error, or `mined`.
    fn force(&self, hex: &str) -> String {
        let a = self.ok(&["getnewaddress"]);
        match self.cli(&["generateblock", &a, &json!([hex]).to_string()]) {
            Ok(_) => "mined".into(),
            Err(e) => e,
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(bin: &Path) -> Node {
    let dir = std::env::temp_dir().join(format!("lwk-contracts-drip-{}", std::process::id()));
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

/// The signature hash a Simplicity leaf signs, for any transaction: what an
/// adversary computes to re-sign a pruned program for a transaction the
/// engine refuses to build.
fn sig_all_hash(
    tx: &Transaction,
    coin: &simplicityhl::elements::TxOut,
    cmr: &str,
    cb: &ControlBlock,
    genesis: BlockHash,
) -> [u8; 32] {
    let mut tx = tx.clone();
    tx.input[0].witness.script_witness.clear();
    let cmr = Cmr::from_byte_array(
        <[u8; 32]>::try_from(lwk_contracts::hex::unhex(cmr, 32).unwrap()).unwrap(),
    );
    let env = ElementsEnv::new(
        Arc::new(tx),
        vec![ElementsUtxo {
            script_pubkey: coin.script_pubkey.clone(),
            asset: coin.asset,
            value: coin.value,
        }],
        0,
        cmr,
        cb.clone(),
        None,
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

/// Replaces the bit pattern of `old` by `new` inside `blob`, at any offset.
fn bit_replace(blob: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let (b, o, n) = (bits(blob), bits(old), bits(new));
    assert_eq!(
        b.matches(&o).count(),
        1,
        "the signature occurs once in the witness"
    );
    let r = b.replacen(&o, &n, 1);
    (0..r.len())
        .step_by(8)
        .map(|i| u8::from_str_radix(&r[i..i + 8], 2).unwrap())
        .collect()
}

/// `bad` with the control's pruned program and witness, its signature made
/// again for `bad` by the faucet key.
fn forge(
    control: &Transaction,
    control_sig: &[u8; 64],
    bad: &Transaction,
    keypair: &Keypair,
    coin: &simplicityhl::elements::TxOut,
    cmr: &str,
    genesis: BlockHash,
) -> Transaction {
    let stack = &control.input[0].witness.script_witness;
    let cb = ControlBlock::from_slice(&stack[3]).unwrap();
    let msg = Message::from_digest(sig_all_hash(bad, coin, cmr, &cb, genesis));
    let sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&msg, keypair)
        .serialize();
    let mut tx = bad.clone();
    tx.input[0].witness.script_witness = vec![
        bit_replace(&stack[0], control_sig, &sig),
        stack[1].clone(),
        stack[2].clone(),
        stack[3].clone(),
    ];
    tx
}

fn rec(log: &mut Vec<Value>, label: &str, v: Value) {
    println!("{label}: {v}");
    log.push(json!({"step": label, "result": v}));
}

#[test]
fn a_drip_under_the_five_point_rule() {
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

    node.ok(&["createwallet", "treasury"]);
    node.mine(101);
    node.ok(&["rescanblockchain"]);
    let me = node.ok(&["getnewaddress"]);
    node.ok(&[
        "-named",
        "sendtoaddress",
        &format!("address={me}"),
        "amount=1000000",
        "fee_asset_label=bitcoin",
    ]);
    node.mine(1);
    let policy = node.json(&["getsidechaininfo"])["pegged_asset"]
        .as_str()
        .unwrap()
        .to_string();
    let genesis_hex = node.ok(&["getblockhash", "0"]);
    let genesis = BlockHash::from_str(&genesis_hex).unwrap();
    let chain = Chain {
        genesis,
        mainnet: false,
    };

    // The wallet: the faucet key is its contract key at m/8383h/1h/0h/0/0.
    let faucet = SwSigner::new(FAUCET, false).unwrap();
    let treasury = SwSigner::new(TREASURY, false).unwrap();
    let key_path = default_contract_key_path(false);
    let faucet_key = Spend::key_at(&faucet, &key_path).unwrap();
    let treasury_key = Spend::key_at(&treasury, &key_path).unwrap();
    let asset_internal: String = {
        let b = lwk_contracts::hex::unhex(&policy, 32).unwrap();
        lwk_contracts::hex::hex(&b.iter().rev().copied().collect::<Vec<_>>())
    };
    let tiers = [
        1_000_000 * COIN,
        500 * COIN,
        100_000 * COIN,
        200 * COIN,
        10_000 * COIN,
        20 * COIN,
        2 * COIN,
    ];
    let names = [
        "TIER1_FLOOR",
        "TIER1_MAX",
        "TIER2_FLOOR",
        "TIER2_MAX",
        "TIER3_FLOOR",
        "TIER3_MAX",
        "TIER4_MAX",
    ];
    let mut params: BTreeMap<String, String> = names
        .iter()
        .zip(tiers)
        .map(|(n, v)| ((*n).to_string(), format!("{v:016x}")))
        .collect();
    params.insert("ASSET".into(), asset_internal);
    params.insert("FAUCET_KEY".into(), faucet_key.to_string());
    params.insert("TREASURY_KEY".into(), treasury_key.to_string());
    params.insert("INTERVAL".into(), format!("{INTERVAL:04x}"));
    params.insert("FEE_CAP".into(), format!("{FEE_CAP:016x}"));
    params.insert("RECOVERY_DELAY".into(), format!("{:08x}", TIME | 2));
    let instance = Instance {
        instance: 2,
        template_hash: known::FAUCET_DRIP.into(),
        params,
        slots: BTreeMap::new(),
        genesis: Some(genesis_hex.clone()),
    };
    let template = Arc::new(known(known::FAUCET_DRIP).unwrap().template().unwrap());
    let contract = Arc::new(Contract::new(template, instance).unwrap());
    let covenant = contract.address("ert").unwrap();
    // The node decodes the engine's address to the engine's script.
    assert_eq!(
        node.json(&["getaddressinfo", &covenant])["scriptPubKey"],
        json!(contract.derived.script_pubkey)
    );
    rec(
        &mut log,
        "covenant",
        json!({"address": covenant, "script_pubkey": contract.derived.script_pubkey}),
    );

    // The treasury funds the reserve.
    let fund = node.ok(&[
        "-named",
        "sendtoaddress",
        &format!("address={covenant}"),
        &format!("amount={}", RESERVE / COIN),
        "fee_asset_label=bitcoin",
    ]);
    node.mine(1);
    let coin_of = |txid: &str| -> CoinRequest {
        let tx = node.json(&["getrawtransaction", txid, "true"]);
        let o = tx["vout"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["scriptPubKey"]["hex"] == json!(contract.derived.script_pubkey))
            .unwrap();
        CoinRequest {
            txid: txid.into(),
            vout: u32::try_from(o["n"].as_u64().unwrap()).unwrap(),
            script_pubkey: contract.derived.script_pubkey.clone(),
            asset: o["asset"].as_str().unwrap().into(),
            amount: (o["value"].as_f64().unwrap() * COIN as f64).round() as u64,
        }
    };
    let dest = node.ok(&["getnewaddress", "", "bech32"]);
    let view = WalletView {
        known: vec![known::FAUCET_DRIP.into()],
        registry: None,
        assets: BTreeMap::from([(
            policy.clone(),
            AssetLabel {
                ticker: "tSEQ".into(),
                precision: 8,
            },
        )]),
        key_path: None,
    };
    let rate = 1000; // atoms per 1,000 vB, in the dripped asset
                     // A drip as the wallet makes it: planned, measured, planned again at its real size.
    let prepare = |coin: &CoinRequest,
                   amount: u64,
                   facts: ChainFacts|
     -> Result<Approval, lwk_contracts::Error> {
        let mut fee = drip::fee_for(581, rate);
        for _ in 0..2 {
            let req = drip::plan(&contract, coin, &dest, amount, fee)?;
            let spend = Spend::build(contract.clone(), chain, &req, &[], Some(facts.clone()))?;
            let a = Approval::prepare(spend, view.clone(), &faucet)?;
            let need = drip::fee_for(a.summary()["vsize"].as_u64().unwrap(), rate);
            if need == fee {
                return Ok(a);
            }
            fee = need;
        }
        unreachable!("the size does not depend on the fee")
    };
    let mut coin = coin_of(&fund);

    // Before the interval: refused by the engine before signing.
    let e = prepare(&coin, 500 * COIN, node.facts(&coin.txid))
        .unwrap_err()
        .to_string();
    assert!(e.contains("non-BIP68-final"), "{e}");
    rec(
        &mut log,
        "engine refuses the first drip before the interval",
        json!(e),
    );

    // The first drip.
    node.advance(INTERVAL * 512);
    let a = prepare(&coin, 500 * COIN, node.facts(&coin.txid)).unwrap();
    let summary = a.summary();
    rec(&mut log, "approval shown for drip 1", summary.clone());
    assert_eq!(summary["template"]["shown"], json!("an unregistered template, root 5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a"));
    assert_eq!(summary["path"]["name"], json!("drip"));
    // A signature over any other digest is refused.
    let e = a.sign(&"00".repeat(32), &faucet).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    rec(&mut log, "a digest other than the one shown", json!(e));
    let tx1 = a
        .sign(summary["digest"].as_str().unwrap(), &faucet)
        .unwrap();
    let hex1 = serialize_hex(&tx1);
    let txid1 = node.ok(&["sendrawtransaction", &hex1]);
    node.mine(1);
    let conf = node.json(&["getrawtransaction", &txid1, "true"]);
    assert!(conf["confirmations"].as_u64().unwrap() >= 1);
    rec(
        &mut log,
        "drip 1 confirmed",
        json!({"txid": txid1, "vsize": conf["vsize"], "weight": conf["weight"], "fee_atoms": summary["fee"][0]["amount"]}),
    );

    // The second drip, too early: refused by the engine before signing...
    coin = coin_of(&txid1);
    let e = prepare(&coin, 500 * COIN, node.facts(&coin.txid))
        .unwrap_err()
        .to_string();
    assert!(e.contains("non-BIP68-final"), "{e}");
    rec(
        &mut log,
        "engine refuses drip 2 before the interval",
        json!(e),
    );
    // ...and by the chain when an engine is told the interval has passed.
    let mut lie = node.facts(&coin.txid);
    lie.tip_median_time += 10_000;
    let a = prepare(&coin, 500 * COIN, lie).unwrap();
    let early = a
        .sign(a.summary()["digest"].as_str().unwrap(), &faucet)
        .unwrap();
    let early_hex = serialize_hex(&early);
    let (m, b) = (node.mempool(&early_hex), node.force(&early_hex));
    assert_eq!(m, "non-BIP68-final");
    assert!(b.contains("bad-txns-nonfinal"), "{b}");
    rec(
        &mut log,
        "chain refuses drip 2 before the interval",
        json!({"mempool": m, "block": b}),
    );

    node.advance(INTERVAL * 512);
    let facts = node.facts(&coin.txid);
    // The control: a good drip for this coin, which the node accepts.
    let control_a = prepare(&coin, 500 * COIN, facts.clone()).unwrap();
    let control = control_a
        .sign(control_a.summary()["digest"].as_str().unwrap(), &faucet)
        .unwrap();
    assert_eq!(node.mempool(&serialize_hex(&control)), "allowed");
    let (keypair, _) = control_a
        .spend()
        .contract_keypair(&faucet, &key_path)
        .unwrap();
    let control_sig: [u8; 64] = {
        let cb = ControlBlock::from_slice(&control.input[0].witness.script_witness[3]).unwrap();
        let msg = Message::from_digest(sig_all_hash(
            &control,
            &control_a.spend().coin,
            "5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a",
            &cb,
            genesis,
        ));
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&msg, &keypair)
            .serialize()
    };
    let cmr = "5251ec00d9799dbcdb31da4534f25ef9960321f195e2e24ef7125c46f24b972a";
    let tier = drip::tier_for(&contract, coin.amount).unwrap();
    let fee = control.output[2].value.explicit().unwrap();

    // A wrong amount, one atom above the tier.
    let e = prepare(&coin, tier + 1, facts.clone())
        .unwrap_err()
        .to_string();
    assert!(e.contains("is above the"), "{e}");
    rec(
        &mut log,
        "engine refuses a drip above the tier (planner)",
        json!(e),
    );
    // The same drip asked for directly: the program refuses it.
    let mut req = drip::plan(&contract, &coin, &dest, tier, fee).unwrap();
    req.outputs[1].amount = tier + 1;
    req.outputs[0].amount -= 1;
    let spend = Spend::build(contract.clone(), chain, &req, &[], Some(facts.clone())).unwrap();
    let e = Approval::prepare(spend, view.clone(), &faucet)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("the contract's program refuses this transaction"),
        "{e}"
    );
    rec(
        &mut log,
        "engine refuses a drip above the tier (program run)",
        json!(e),
    );
    let mut bad: Transaction = control.clone();
    bad.output[1].value = simplicityhl::elements::confidential::Value::Explicit(tier + 1);
    bad.output[0].value = simplicityhl::elements::confidential::Value::Explicit(
        control.output[0].value.explicit().unwrap() - 1,
    );
    let bad = forge(
        &control,
        &control_sig,
        &bad,
        &keypair,
        &control_a.spend().coin,
        cmr,
        genesis,
    );
    let hexb = serialize_hex(&bad);
    let (m, b) = (node.mempool(&hexb), node.force(&hexb));
    assert!(m.contains("Assertion failed inside jet"), "{m}");
    assert!(
        b.contains("Assertion failed inside jet") && b.contains("TestBlockValidity"),
        "{b}"
    );
    rec(
        &mut log,
        "chain refuses a drip above the tier",
        json!({"mempool": m, "block": b}),
    );

    // A wrong successor: the rest paid to the wallet's own address, not the covenant.
    let mut req = drip::plan(&contract, &coin, &dest, 500 * COIN, fee).unwrap();
    req.outputs[0].script = None;
    req.outputs[0].address = Some(me.clone());
    let e = Spend::build(contract.clone(), chain, &req, &[], Some(facts.clone()))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("is said to return to the contract, but pays the script"),
        "{e}"
    );
    rec(
        &mut log,
        "engine refuses a successor that is not the covenant (accounting)",
        json!(e),
    );
    req.outputs[0].to = "pay".into();
    let spend = Spend::build(contract.clone(), chain, &req, &[], Some(facts.clone())).unwrap();
    let e = Approval::prepare(spend, view.clone(), &faucet)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("the contract's program refuses this transaction"),
        "{e}"
    );
    rec(
        &mut log,
        "engine refuses a successor that is not the covenant (program run)",
        json!(e),
    );
    let me_script = node.json(&["getaddressinfo", &me])["scriptPubKey"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bad = control.clone();
    bad.output[0].script_pubkey = lwk_contracts::spend::script_from_hex(&me_script).unwrap();
    let bad = forge(
        &control,
        &control_sig,
        &bad,
        &keypair,
        &control_a.spend().coin,
        cmr,
        genesis,
    );
    let hexb = serialize_hex(&bad);
    let (m, b) = (node.mempool(&hexb), node.force(&hexb));
    assert!(m.contains("Assertion failed inside jet"), "{m}");
    assert!(
        b.contains("Assertion failed inside jet") && b.contains("TestBlockValidity"),
        "{b}"
    );
    rec(
        &mut log,
        "chain refuses a successor that is not the covenant",
        json!({"mempool": m, "block": b}),
    );

    // The control itself confirms: the second drip.
    let txid2 = node.ok(&["sendrawtransaction", &serialize_hex(&control)]);
    node.mine(1);
    let c2 = node.json(&["getrawtransaction", &txid2, "true"]);
    assert!(c2["confirmations"].as_u64().unwrap() >= 1);
    rec(
        &mut log,
        "drip 2 (the control) confirmed",
        json!({"txid": txid2, "vsize": c2["vsize"]}),
    );
    let _: Transaction = deserialize(&lwk_contracts::hex::unhex_any(&hex1).unwrap()).unwrap();

    if let Some(out) = std::env::var_os("DRIP_REGTEST_LOG") {
        std::fs::write(out, serde_json::to_string_pretty(&log).unwrap()).unwrap();
    }
}
