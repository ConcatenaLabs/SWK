//! Arca leaves built by the Arca tree builder on a regtest chain, verified by
//! the kit, natively and through its wasm bindings, against each round as the
//! node returns it.
//!
//! The test starts a `sequentiad` on a fresh `elementsregtest` chain, issues an
//! asset, and mines six rounds, each a batch of five leaves (three of a wallet
//! whose mnemonic is generated here, two of a stranger's). One round is honest.
//! The other five are attacks consensus accepts, each mined into a block:
//!
//! - two atoms of the sweep token, the second paid straight to `R` (check 1);
//! - the token issued with a reissuance token (check 3);
//! - the only atom paid straight to `R` (check 4);
//! - the atom paid to a clock with an earlier expiry than the one published
//!   (check 5);
//! - a published clock chain whose second step expires before its first
//!   (check 5).
//!
//! `lwk_wasm/tests/node/ark_regtest.js` then restores the wallet from the
//! mnemonic in the wasm bindings, finds its leaf keys from the records' owner
//! nonces, fetches each round from the node, and must accept every leaf of
//! the honest round and refuse every leaf of each attack with its check
//! named. The same verdicts are reached natively.
//!
//! Needs `SEQUENTIAD_EXEC` (a `sequentiad` binary), `node`, and the wasm
//! package built for node.js and linked as `lwk_node` in
//! `lwk_wasm/tests/node/node_modules` (`lwk_wasm/README.md`):
//!
//! ```text
//! SEQUENTIAD_EXEC=/path/to/sequentiad \
//!   cargo test -p lwk_wollet --no-default-features --features ark --test ark_regtest -- --nocapture
//! ```
//!
//! Without `SEQUENTIAD_EXEC` the test prints that it did not run and passes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::{sha256, Hash};
use elements::hex::{FromHex, ToHex};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{
    AssetId, AssetIssuance, BlockHash, ContractHash, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxOut, TxOutWitness,
};
use lwk_signer::SwSigner;
use lwk_wollet::ark::covenant::{LeafSpec, ReserveRule, Tree, TreeParams};
use lwk_wollet::ark::keys::{fresh_leaf_key, LeafKey};
use lwk_wollet::ark::verify::{verify_leaf, verify_round};
use lwk_wollet::ark::{Chain, ClockSchedule, MedianTime, RelativeTime, Template, WalletPolicy};
use serde_json::{json, Value as Json};

const H: u32 = 3600;
const DAY: u32 = 24 * H;
const LEAF: u64 = 1_000_000;

/// One `sequentiad` on a fresh `elementsregtest` chain, stopped and its data
/// deleted on drop.
struct Node {
    child: Child,
    port: u16,
    dir: PathBuf,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Node {
    fn start(exe: &Path, dir: PathBuf) -> Node {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let child = Command::new(exe)
            .args([
                "-chain=elementsregtest".to_string(),
                format!("-datadir={}", dir.display()),
                format!("-rpcport={port}"),
                format!("-port={}", free_port()),
                "-listen=0".into(),
                "-server".into(),
                "-printtoconsole=0".into(),
                "-rpcuser=ark".into(),
                "-rpcpassword=ark".into(),
                "-disablewallet".into(),
                "-txindex=1".into(),
                "-par=1".into(),
                "-initialfreecoins=2100000000000000".into(),
                "-con_default_blinded_addresses=0".into(),
                "-validatepegin=0".into(),
                "-con_parent_chain_signblockscript=51".into(),
                "-con_any_asset_fees=1".into(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let node = Node { child, port, dir };
        let t0 = Instant::now();
        while node.try_rpc("getblockcount", json!([])).is_err() {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "sequentiad did not answer"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        node
    }

    fn try_rpc(&self, method: &str, params: Json) -> Result<Json, String> {
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).map_err(|e| e.to_string())?;
        // "ark:ark", the test node's own credentials.
        let req = format!(
            "POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nAuthorization: Basic YXJrOmFyaw==\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
        let body = resp.split("\r\n\r\n").nth(1).ok_or("no body")?;
        let v: Json = serde_json::from_str(body).map_err(|e| format!("{e}: {resp}"))?;
        if !v["error"].is_null() {
            return Err(v["error"].to_string());
        }
        Ok(v["result"].clone())
    }

    fn rpc(&self, method: &str, params: Json) -> Json {
        self.try_rpc(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e}"))
    }

    fn mine(&self, txs: &[&Transaction]) -> BlockHash {
        let hexes: Vec<String> = txs.iter().map(|t| serialize(*t).to_hex()).collect();
        let r = self.rpc("generateblock", json!(["raw(51)", hexes]));
        BlockHash::from_str(r["hash"].as_str().unwrap()).unwrap()
    }

    fn mtp(&self) -> u32 {
        let h = self.rpc("getbestblockhash", json!([]));
        self.rpc("getblockheader", json!([h]))["mediantime"]
            .as_u64()
            .unwrap() as u32
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.try_rpc("stop", json!([]));
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn op_true() -> Script {
    Script::from(vec![0x51])
}

fn explicit(asset: AssetId, value: u64, spk: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

fn tx(inputs: Vec<OutPoint>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|o| TxIn {
                previous_output: o,
                sequence: Sequence(0xffff_ffff),
                ..Default::default()
            })
            .collect(),
        output: outputs,
    }
}

fn issuance(contract: [u8; 32], amount: u64, tokens: u64, denomination: u8) -> AssetIssuance {
    AssetIssuance {
        asset_blinding_nonce: ZERO_TWEAK,
        asset_entropy: contract,
        amount: Value::Explicit(amount),
        inflation_keys: if tokens == 0 {
            Value::Null
        } else {
            Value::Explicit(tokens)
        },
        denomination,
    }
}

fn random32() -> [u8; 32] {
    lwk_wollet::ark::keys::new_owner_nonce()
}

/// What a scenario does to an honest round.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Attack {
    None,
    TwoAtomsOneAtR,
    ReissuanceToken,
    AtomAtR,
    HiddenEarlierClock,
    BackwardClock,
}

impl Attack {
    fn name(self) -> &'static str {
        match self {
            Attack::None => "honest round",
            Attack::TwoAtomsOneAtR => "two atoms of the token, the second straight to R",
            Attack::ReissuanceToken => "the token issued with a reissuance token",
            Attack::AtomAtR => "the only atom straight to R",
            Attack::HiddenEarlierClock => {
                "the atom at a clock with an earlier expiry than published"
            }
            Attack::BackwardClock => "a published clock that runs backwards",
        }
    }

    fn check(self) -> Option<u8> {
        match self {
            Attack::None => None,
            Attack::TwoAtomsOneAtR => Some(1),
            Attack::ReissuanceToken => Some(3),
            Attack::AtomAtR => Some(4),
            Attack::HiddenEarlierClock | Attack::BackwardClock => Some(5),
        }
    }
}

#[test]
fn leaves_on_regtest_verify_in_wasm() {
    let Some(exe) = std::env::var_os("SEQUENTIAD_EXEC") else {
        println!("ark_regtest did not run: set SEQUENTIAD_EXEC to a sequentiad binary");
        return;
    };
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ark-regtest-{}", std::process::id()));
    let node = Node::start(Path::new(&exe), work.join("node"));
    let genesis =
        BlockHash::from_str(node.rpc("getblockhash", json!([0])).as_str().unwrap()).unwrap();
    let policy_asset = AssetId::from_str(
        node.rpc("getsidechaininfo", json!([]))["pegged_asset"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let tip_time = node.rpc(
        "getblockheader",
        json!([node.rpc("getbestblockhash", json!([]))]),
    )["time"]
        .as_u64()
        .unwrap();
    node.rpc("setmocktime", json!([tip_time + 1]));
    node.rpc("generatetodescriptor", json!([1, "raw(51)"]));

    // The free coins, at a bare OP_TRUE of the genesis block.
    let block = node.rpc("getblock", json!([genesis.to_string(), 2]));
    let mut free = None;
    for t in block["tx"].as_array().unwrap() {
        let t: Transaction =
            deserialize(&Vec::<u8>::from_hex(t["hex"].as_str().unwrap()).unwrap()).unwrap();
        for (i, o) in t.output.iter().enumerate() {
            if o.script_pubkey == op_true() && o.asset.explicit() == Some(policy_asset) {
                free = Some((
                    OutPoint::new(t.txid(), i as u32),
                    o.value.explicit().unwrap(),
                ));
            }
        }
    }
    let (free, total) = free.expect("the genesis block pays the free coins to OP_TRUE");

    // Issue X, an asset that is not the policy asset, and split it into one
    // issuing coin per round.
    let split = tx(
        vec![free],
        vec![
            explicit(policy_asset, 1_000_000_000, op_true()),
            explicit(policy_asset, total - 1_000_000_000 - 10_000, op_true()),
            TxOut::new_fee(10_000, policy_asset),
        ],
    );
    node.mine(&[&split]);
    let contract = random32();
    let issuer = OutPoint::new(split.txid(), 0);
    let x = AssetId::new_issuance(issuer, ContractHash::from_byte_array(contract));
    let mut issue = tx(
        vec![issuer],
        vec![
            explicit(x, 100_000_000_000, op_true()),
            explicit(policy_asset, 1_000_000_000 - 5_000, op_true()),
            TxOut::new_fee(5_000, policy_asset),
        ],
    );
    issue.input[0].asset_issuance = issuance(contract, 100_000_000_000, 0, 8);
    node.mine(&[&issue]);
    let attacks = [
        Attack::None,
        Attack::TwoAtomsOneAtR,
        Attack::ReissuanceToken,
        Attack::AtomAtR,
        Attack::HiddenEarlierClock,
        Attack::BackwardClock,
    ];
    let coin = 2_000_000_000u64;
    let mut outs: Vec<TxOut> = attacks
        .iter()
        .map(|_| explicit(x, coin, op_true()))
        .collect();
    outs.push(explicit(
        x,
        100_000_000_000 - coin * attacks.len() as u64 - 2_000,
        op_true(),
    ));
    outs.push(TxOut::new_fee(2_000, x));
    let issuers = tx(vec![OutPoint::new(issue.txid(), 0)], outs);
    node.mine(&[&issuers]);
    println!("elementsregtest on genesis {genesis}; batch asset X {x}");

    // The wallet, the stranger and the operator: mnemonics made here, for this
    // test alone.
    let words = |_: ()| {
        lwk_signer::bip39::Mnemonic::generate(12)
            .unwrap()
            .to_string()
    };
    let wallet_words = words(());
    let wallet = SwSigner::new(&wallet_words, false).unwrap();
    let stranger = SwSigner::new(&words(()), false).unwrap();
    let operator = SwSigner::new(&words(()), false).unwrap();
    let s_key = fresh_leaf_key(&operator, 0).unwrap().key;

    let now = node.mtp();
    let delay = RelativeTime::from_seconds_ceil(36 * H as u64).unwrap();
    let floor_per_kvb = (node.rpc("getmempoolinfo", json!([]))["minrelaytxfee"]
        .as_f64()
        .unwrap()
        * 1e8)
        .round() as u64;
    let policy = WalletPolicy::new(
        Chain::new(genesis),
        s_key,
        MedianTime::from_consensus(now).unwrap(),
    );
    let mut batches = vec![];
    for (i, attack) in attacks.iter().enumerate() {
        let issuer = OutPoint::new(issuers.txid(), i as u32);
        let token = AssetId::new_issuance(issuer, ContractHash::from_byte_array([0; 32]));
        let e = |d: u32| MedianTime::from_consensus(now + d * DAY).unwrap();
        let published = ClockSchedule::new(token, s_key, delay, vec![e(28), e(56), e(84)]).unwrap();
        let keys: Vec<(LeafKey, bool)> = (0..5)
            .map(|j| {
                if j < 3 {
                    (fresh_leaf_key(&wallet, 0).unwrap(), true)
                } else {
                    (fresh_leaf_key(&stranger, 0).unwrap(), false)
                }
            })
            .collect();
        let preimages: Vec<[u8; 32]> = (0..5).map(|_| random32()).collect();
        let leaves: Vec<LeafSpec> = keys
            .iter()
            .enumerate()
            .map(|(j, (k, _))| LeafSpec {
                template: Template::Vtxo1,
                owner: k.key,
                value: LEAF + j as u64,
                owner_nonce: k.owner_nonce,
                operator_nonce: random32(),
                exit_delay: delay,
                unlock_hash: sha256::Hash::hash(&preimages[j]).to_byte_array(),
            })
            .collect();
        let tree = Tree::build(
            TreeParams {
                asset: x,
                chain: Chain::new(genesis),
                schedule: published.clone(),
                burn: false,
                radix: 4,
                reserve: ReserveRule::FeeRate {
                    floor_per_kvb,
                    multiple: 4,
                },
                min_leaf: 1_000,
            },
            &leaves,
        )
        .unwrap();
        let mut records = tree.records();
        let batch = tree.batch_output();
        let r_spk = published.r().script_pubkey();

        // The round: the batch output at 0, the token's atom at 1, change, fee.
        let mut clock = published.clock0_script_pubkey();
        let mut atoms = 1;
        let mut extra = vec![];
        let mut tokens = 0;
        match attack {
            Attack::None => {}
            Attack::TwoAtomsOneAtR => {
                atoms = 2;
                extra.push(explicit(token, 1, r_spk.clone()));
            }
            Attack::ReissuanceToken => {
                tokens = 1;
                let entropy =
                    AssetId::generate_asset_entropy(issuer, ContractHash::from_byte_array([0; 32]));
                extra.push(explicit(
                    AssetId::reissuance_token_from_entropy(entropy, false),
                    1,
                    op_true(),
                ));
            }
            Attack::AtomAtR => clock = r_spk.clone(),
            Attack::HiddenEarlierClock => {
                let hidden =
                    ClockSchedule::new(token, s_key, delay, vec![e(1), e(56), e(84)]).unwrap();
                clock = hidden.clock0_script_pubkey();
            }
            Attack::BackwardClock => {
                let backwards =
                    ClockSchedule::new_unchecked(token, s_key, delay, vec![e(56), e(28), e(84)])
                        .unwrap();
                clock = backwards.clock0_script_pubkey();
                // The schedule the operator publishes with each record.
                for r in records.iter_mut() {
                    r.schedule = backwards.clone();
                }
            }
        }
        let mut outputs = vec![batch.txout(), explicit(token, 1, clock)];
        outputs.extend(extra);
        outputs.push(explicit(x, coin - batch.value - 2_000, op_true()));
        outputs.push(TxOut::new_fee(2_000, x));
        let mut round = tx(vec![issuer], outputs);
        round.input[0].asset_issuance = issuance([0; 32], atoms, tokens, 0);
        // Consensus accepts every one of these rounds.
        node.mine(&[&round]);
        let confirmations = node.rpc("getrawtransaction", json!([round.txid().to_string(), true]))
            ["confirmations"]
            .as_u64()
            .unwrap();
        assert!(confirmations >= 1, "{}: not mined", attack.name());

        // The native verdicts, which the wasm bindings must reach too.
        let fetched: Transaction = deserialize(
            &Vec::<u8>::from_hex(
                node.rpc("getrawtransaction", json!([round.txid().to_string()]))
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(fetched.txid(), round.txid());
        let mut leaves_json = vec![];
        for (j, (k, ours)) in keys.iter().enumerate() {
            let rec = &records[j];
            assert_eq!(rec.owner, k.key);
            let native = if *ours {
                verify_leaf(rec, &fetched, &policy, &k.key, &k.owner_nonce)
            } else {
                verify_round(rec, &fetched, &policy)
            };
            match (attack.check(), &native) {
                (None, Ok(v)) => assert_eq!(v.round_txid, round.txid()),
                (Some(c), Err(e)) => assert_eq!(e.check(), Some(c), "{}: {e}", attack.name()),
                (c, n) => panic!("{}: expected check {c:?}, got {n:?}", attack.name()),
            }
            leaves_json.push(json!({
                "record": rec.to_json_string().unwrap(),
                "record_hex": rec.to_bytes().unwrap().to_hex(),
                "leaf_id": rec.leaf_id().unwrap().to_string(),
                "owner": k.key.serialize().to_hex(),
                "owner_nonce": k.owner_nonce.to_hex(),
                "ours": ours,
                "preimage": preimages[j].to_hex(),
            }));
        }
        println!("mined round {} for {}", round.txid(), attack.name());
        batches.push(json!({
            "name": attack.name(),
            "round_txid": round.txid().to_string(),
            "check": attack.check(),
            "leaves": leaves_json,
        }));
    }

    // The wasm half.
    let fixture = json!({
        "rpc": {"url": node.url(), "user": "ark", "password": "ark"},
        "genesis_hash": genesis.to_string(),
        "policy_asset": policy_asset.to_string(),
        "operator": s_key.serialize().to_hex(),
        "now": now,
        "mnemonic": wallet_words,
        "batches": batches,
    });
    std::fs::create_dir_all(&work).unwrap();
    let path = work.join("fixture.json");
    std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../lwk_wasm/tests/node/ark_regtest.js");
    let out = Command::new("node")
        .arg(&script)
        .arg(&path)
        .current_dir(script.parent().unwrap())
        .output()
        .expect("node runs");
    let _ = std::fs::remove_file(&path);
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "ark_regtest.js failed");
    drop(node);
    let _ = std::fs::remove_dir_all(&work);
}
