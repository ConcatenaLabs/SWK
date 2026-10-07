//! Stake record transactions built and signed by the kit, confirmed in blocks
//! a real `sequentiad` produces.
//!
//! Each test starts a proof-of-stake `sequentiad` on a fresh `elementsregtest`
//! chain, funds a kit wallet from the genesis output, then restarts the node on
//! its default relay policy, under which every kit transaction must relay.
//!
//! `records_from_block_one`, on a chain with the second generation of stake
//! records and the record hardening in force from block 1 (every new chain):
//!
//! - a bond (the wallet's PSET path), its script equal to the node's
//!   `getstakescript`;
//! - a delegation created with a coin of its controller: the wallet pays the
//!   staking key's `P2WPKH`, and the record's transaction spends it, both mined
//!   in one block; the record funded by wallet coins alone is refused
//!   (`bad-delegation-unauthorized`);
//! - a re-point and a reclaim of that record;
//! - a payout announcement by the staking key, created the same way, and its
//!   withdrawal while still inside its notice;
//! - an unbond in two steps: the stake into its unbonding output, and, once the
//!   unbonding depth has passed, the unbonding output to the wallet (refused
//!   before it with `bad-unbond-premature`).
//!
//! Every record spend is signed for the next block, which on this chain is the
//! second generation. Each wrong case (the record from wallet coins alone, the
//! same spend signed the legacy way, the claim before the depth) is refused by
//! the node's mempool and by a block, with the reason it names: the block the
//! node produces next, taken back, with the transaction added, judged by
//! `testproposedblock`; the right transaction is valid in that same block.
//!
//! `records_across_the_fork_height`, on a chain switching at height 12: below
//! it a record created from wallet coins alone is valid and a re-point is
//! signed the legacy way (the second-generation signature refused); at it the
//! reclaim is signed the second-generation way (the legacy one refused).
//!
//! Each test then runs `lwk_wasm/tests/node/stake_records.js`, which builds
//! every confirmed transaction again through the wasm bindings, from the recipe
//! a browser wallet would pass, and must get it byte for byte. That half needs
//! `node` and the wasm package built for node.js, linked as `lwk_node` in
//! `lwk_wasm/tests/node/node_modules` (`lwk_wasm/README.md`); without the
//! package it is skipped with a line saying so.
//!
//! Needs `SEQUENTIAD_EXEC` (or `ELEMENTSD_EXEC`) pointing at a `sequentiad`:
//!
//! ```text
//! SEQUENTIAD_EXEC=/path/to/sequentiad \
//!   cargo test -p lwk_wollet --features sequentia --test sequentia_stake_records -- --nocapture
//! ```
//!
//! Without it the tests fail and say what they need: a test that cannot run
//! must not pass.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use elements::bitcoin::bip32::{ChildNumber, DerivationPath};
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::{sha256d, Hash as _};
use elements::hex::{FromHex, ToHex};
use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use elements::{
    AssetId, BlockExtData, BlockHash, BlockHeader, LockTime, OutPoint, Script, Sequence,
    Transaction, TxIn, TxInWitness, TxMerkleNode, TxOut, TxOutWitness, Txid,
};
use lwk_common::{DescriptorBlindingKey, ElementsParamsBuilder, Network, Signer as _, Singlesig};
use lwk_signer::SwSigner;
use lwk_wollet::clients::LastUnused;
use lwk_wollet::sequentia_stake_records::find_key_coins;
use lwk_wollet::{
    build_delegation_create_tx, build_delegation_spend_tx, build_record_create_tx,
    build_unbond_claim_tx, build_unbond_tx, pos_records_v2_height, sequentia_stake_script,
    sign_stake_record_input, Chain, DelegationCreatePlan, DelegationSpendPlan, DownloadTxResult,
    RecordCreatePlan, StakeOutput, StakeRecordSigning, TxBuilder, UnbondClaimPlan, UnbondPlan,
    UnbondingOutput, Update, Wollet, WolletBuilder, WolletDescriptor,
};
use serde_json::{json, Value as Json};

const COIN: u64 = 100_000_000;
/// Network fee of every raw record transaction, in atoms: over 5 atoms a vbyte.
const FEE: u64 = 2_000;
/// A record's own value.
const RECORD: u64 = 100_000;
/// The wallet's PSET fee rate, atoms per 1000 vbytes.
const FEE_RATE: f32 = 2_000.0;
/// The chain's unbonding period (blocks), hence the bond's relative lock.
const UNBONDING: u32 = 5;
/// Blocks an unbonding output waits before it may be claimed.
const UNBOND_DEPTH: u32 = 3;
/// Blocks between a payout announcement and its activation, at least.
const NOTICE: u32 = 3;
/// A published test mnemonic: the wallet holds nothing outside these tests.
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// One `sequentiad` on a fresh proof-of-stake `elementsregtest` chain,
/// stopped and its data deleted on drop.
struct Node {
    exe: PathBuf,
    child: Child,
    port: u16,
    dir: PathBuf,
    chain_args: Vec<String>,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn(exe: &Path, dir: &Path, port: u16, args: &[String]) -> Child {
    Command::new(exe)
        .args([
            "-chain=elementsregtest".to_string(),
            format!("-datadir={}", dir.display()),
            format!("-rpcport={port}"),
            format!("-port={}", free_port()),
            "-listen=0".into(),
            "-server".into(),
            "-printtoconsole=0".into(),
            "-rpcuser=u".into(),
            "-rpcpassword=p".into(),
            "-disablewallet".into(),
            "-txindex=1".into(),
            // Scripts checked one by one, so a refusal names its script error.
            "-par=1".into(),
            "-persistmempool=0".into(),
        ])
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

impl Node {
    /// Start on a fresh chain whose consensus options are `chain_args`, with
    /// non-standard transactions accepted so the genesis output can be spent.
    fn start(name: &str, chain_args: Vec<String>) -> Node {
        let exe = std::env::var("SEQUENTIAD_EXEC")
            .or_else(|_| std::env::var("ELEMENTSD_EXEC"))
            .expect("sequentia_stake_records needs SEQUENTIAD_EXEC set to a sequentiad binary");
        let exe = PathBuf::from(exe);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let port = free_port();
        let mut args = chain_args.clone();
        args.push("-acceptnonstdtxn=1".into());
        let child = spawn(&exe, &dir, port, &args);
        let node = Node {
            exe,
            child,
            port,
            dir,
            chain_args,
        };
        node.wait_ready();
        node
    }

    /// Restart on the same chain under the default relay policy.
    fn restart_with_default_policy(&mut self) {
        self.stop();
        self.port = free_port();
        self.child = spawn(&self.exe, &self.dir, self.port, &self.chain_args);
        self.wait_ready();
    }

    fn wait_ready(&self) {
        let t0 = Instant::now();
        while self.try_rpc("getblockcount", json!([])).is_err() {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "sequentiad did not answer"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn stop(&mut self) {
        let _ = self.try_rpc("stop", json!([]));
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(60) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn try_rpc(&self, method: &str, params: Json) -> Result<Json, String> {
        let body =
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).map_err(|e| e.to_string())?;
        // "u:p", the test node's own credentials.
        let req = format!(
            "POST / HTTP/1.0\r\nHost: 127.0.0.1\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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

    fn tip(&self) -> u32 {
        self.rpc("getblockcount", json!([])).as_u64().unwrap() as u32
    }

    /// Produce one block as the chain's staker, from the mempool. Returns the
    /// ids of the transactions it carries.
    fn produce(&self, staker_wif: &str) -> Vec<Txid> {
        let r = self.rpc("generateposblock", json!([staker_wif]));
        let hash = BlockHash::from_str(r["hash"].as_str().unwrap()).unwrap();
        self.rpc("getblock", json!([hash.to_string(), 1]))["tx"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| Txid::from_str(t.as_str().unwrap()).unwrap())
            .collect()
    }

    fn send(&self, tx_hex: &str) -> Txid {
        Txid::from_str(
            self.rpc("sendrawtransaction", json!([tx_hex]))
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    /// The reason the mempool refuses `tx_hex`; panics if it would accept it.
    fn refusal(&self, tx_hex: &str) -> String {
        let r = &self.rpc("testmempoolaccept", json!([[tx_hex]]))[0];
        assert_eq!(
            r["allowed"],
            json!(false),
            "the node accepts what it should refuse: {r}"
        );
        r["reject-reason"].as_str().unwrap().to_string()
    }

    /// What a block makes of each variant: the block this node produces next,
    /// taken back (`invalidateblock`), with the variant's transactions added
    /// and its merkle root recomputed, judged by `testproposedblock`. That runs
    /// every check a block must pass except the leader's signature over its
    /// hash, the one thing adding a transaction breaks. Every variant is judged
    /// at the same height; the node then returns to its block, so the chain
    /// advances by one.
    ///
    /// The relay policy's verdict can hide a consensus flaw; this one cannot.
    fn block_verdicts(
        &self,
        staker_wif: &str,
        variants: &[Vec<Transaction>],
    ) -> Vec<Result<(), String>> {
        let r = self.rpc("generateposblock", json!([staker_wif]));
        let hash = r["hash"].as_str().unwrap().to_string();
        let block =
            Vec::<u8>::from_hex(self.rpc("getblock", json!([hash, 0])).as_str().unwrap()).unwrap();
        // The header as the node serialises it: this chain has no Bitcoin
        // anchor, so it is spliced as bytes rather than decoded.
        let header = Vec::<u8>::from_hex(
            self.rpc("getblockheader", json!([hash, false]))
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(&block[..header.len()], header.as_slice());
        let txs: Vec<Transaction> = deserialize(&block[header.len()..]).unwrap();
        assert_eq!(txs.len(), 1, "the block carries only its coinbase");
        // The merkle root follows the version and the previous block's hash.
        assert_eq!(
            &header[36..68],
            merkle_root(&txs).to_byte_array().as_slice()
        );
        self.rpc("invalidateblock", json!([hash]));
        let verdicts = variants
            .iter()
            .map(|extra| {
                let mut all = txs.clone();
                all.extend(extra.iter().cloned());
                commit_witnesses(&mut all);
                let mut proposal = header.clone();
                proposal[36..68].copy_from_slice(&merkle_root(&all).to_byte_array());
                proposal.extend(serialize(&all));
                self.try_rpc("testproposedblock", json!([proposal.to_hex()]))
                    .map(|_| ())
            })
            .collect();
        self.rpc("reconsiderblock", json!([hash]));
        assert_eq!(self.rpc("getbestblockhash", json!([])), json!(hash));
        verdicts
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The script error of a record spend signed the legacy way where the second
/// generation is in force: the record is checked against the segwit-v0 hash,
/// a mismatching signature must be empty (NULLFAIL), and the record rules
/// enforce that in a block as well as in the mempool.
const WRONG_HASH: &str = "(Signature must be zero for failed CHECK(MULTI)SIG operation)";
/// The script error of a record spend signed the second-generation way below
/// the fork height: the legacy check fails, and a block (which does not
/// enforce NULLFAIL on legacy scripts) sees a false result.
const FALSE_RESULT: &str =
    "(Script evaluated without error but finished with a false/empty top stack element)";

/// `bad` is refused by the node's relay policy and by a block, for the reasons
/// given, and `good` (the same thing done right, possibly several
/// transactions) is valid in that same block. Prints the reasons.
fn refused_everywhere(
    node: &Node,
    producer: &str,
    bad: &Transaction,
    good: &[&Transaction],
    what: &str,
    policy: &str,
    block: &str,
) {
    let by_policy = node.refusal(&hex_of(bad));
    let mut variants = vec![vec![bad.clone()]];
    if !good.is_empty() {
        variants.push(good.iter().map(|t| (*t).clone()).collect());
    }
    let verdicts = node.block_verdicts(producer, &variants);
    let by_block = verdicts[0]
        .clone()
        .expect_err("a block carrying it must be invalid");
    println!("{what}: mempool \"{by_policy}\"; block {by_block}");
    assert!(
        by_policy.contains(policy),
        "{what}: mempool said {by_policy}"
    );
    assert!(by_block.contains(block), "{what}: block said {by_block}");
    if let Some(v) = verdicts.get(1) {
        v.clone()
            .expect("the same block carrying the right transaction is valid");
    }
}

/// A record spend signed for the wrong generation is refused by the mempool
/// and by a block, which accepts the same spend signed for the right one.
/// `in_block` is the script error the block reports.
///
/// The node labels every script failure `mempool-script-verify-flag-failed`
/// when the flags include any standard-only bit, which block flags do (CLTV,
/// CSV, witness), so the label is the same in both places; the verdict on
/// the block is what makes the refusal a consensus one.
fn wrong_signature_refused(
    node: &Node,
    producer: &str,
    bad_hex: &str,
    good_hex: &str,
    what: &str,
    in_block: &str,
) {
    refused_everywhere(
        node,
        producer,
        &decode(bad_hex),
        &[&decode(good_hex)],
        what,
        &format!("script-verify-flag-failed {WRONG_HASH}"),
        &format!("script-verify-flag-failed {in_block}"),
    );
}

/// Rewrite the coinbase's witness commitment for the block's transactions, as
/// the node computes it in Elements mode: a fast merkle root over each
/// transaction's witness-only hash, hashed with the coinbase's witness nonce.
fn commit_witnesses(txs: &mut [Transaction]) {
    fn hash<T: elements::encode::Encodable>(v: &T) -> [u8; 32] {
        sha256d::Hash::hash(&serialize(v)).to_byte_array()
    }
    fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0; 32];
        }
        elements::fast_merkle_root(leaves).to_byte_array()
    }
    let witness_only = |tx: &Transaction| {
        let ins: Vec<[u8; 32]> = tx
            .input
            .iter()
            .map(|i| {
                let w = if i.is_coinbase() {
                    TxInWitness::default()
                } else {
                    i.witness.clone()
                };
                root(&[
                    hash(&w.amount_rangeproof),
                    hash(&w.inflation_keys_rangeproof),
                    hash(&w.script_witness),
                    hash(&w.pegin_witness),
                ])
            })
            .collect();
        let outs: Vec<[u8; 32]> = tx
            .output
            .iter()
            .map(|o| {
                root(&[
                    hash(&o.witness.surjection_proof),
                    hash(&o.witness.rangeproof),
                ])
            })
            .collect();
        root(&[root(&ins), root(&outs)])
    };
    let leaves: Vec<[u8; 32]> = txs.iter().map(witness_only).collect();
    let mut committed = root(&leaves).to_vec();
    committed.extend_from_slice(&txs[0].input[0].witness.script_witness[0]);
    let commitment = sha256d::Hash::hash(&committed).to_byte_array();
    let index = txs[0]
        .output
        .iter()
        .rposition(|o| {
            let b = o.script_pubkey.as_bytes();
            b.len() >= 38 && b[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        })
        .expect("the coinbase commits to the witnesses");
    let mut script = txs[0].output[index].script_pubkey.to_bytes();
    script[6..38].copy_from_slice(&commitment);
    txs[0].output[index].script_pubkey = Script::from(script);
}

/// A block's merkle root: the Bitcoin tree over its transaction ids.
fn merkle_root(txs: &[Transaction]) -> TxMerkleNode {
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| t.txid().to_byte_array()).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut both = pair[0].to_vec();
                both.extend_from_slice(&pair[1]);
                sha256d::Hash::hash(&both).to_byte_array()
            })
            .collect();
    }
    TxMerkleNode::from_byte_array(level[0])
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

fn hex_of(tx: &Transaction) -> String {
    serialize(tx).to_hex()
}

fn decode(raw: &str) -> Transaction {
    deserialize(&Vec::<u8>::from_hex(raw).unwrap()).unwrap()
}

fn random_key() -> (SecretKey, Vec<u8>) {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let sk = SecretKey::from_slice(&bytes).unwrap();
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    (sk, pk.serialize().to_vec())
}

fn wif(sk: &SecretKey) -> String {
    let inner = elements::bitcoin::secp256k1::SecretKey::from_slice(&sk.secret_bytes()).unwrap();
    elements::bitcoin::PrivateKey::new(inner, elements::bitcoin::NetworkKind::Test).to_wif()
}

/// The chain's consensus options: one staker, short periods, and whatever
/// `extra` sets (the fork heights).
fn chain_args(producer_pub: &[u8], extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-con_pos=1",
        "-posvrf=1",
        "-posslotinterval=1",
        "-signblockscript=51",
        "-initialfreecoins=2100000000000000",
        "-anyonecanspendaremine=0",
        "-con_blocksubsidy=0",
        "-con_connect_genesis_outputs=1",
        "-validatepegin=0",
        "-con_default_blinded_addresses=0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.push(format!("-posunbonding={UNBONDING}"));
    args.push(format!("-posunbonddepth={UNBOND_DEPTH}"));
    args.push(format!("-pospayoutnotice={NOTICE}"));
    args.push(format!("-staker={}:{}", producer_pub.to_hex(), COIN));
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

/// A kit wallet and its staking key, on the node's chain.
struct Kit {
    network: Network,
    signer: SwSigner,
    wollet: Wollet,
    staker_secret: SecretKey,
    staker: Vec<u8>,
}

impl Kit {
    fn new(node: &Node) -> Kit {
        let asset = AssetId::from_str(
            node.rpc("getsidechaininfo", json!([]))["pegged_asset"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let genesis =
            BlockHash::from_str(node.rpc("getblockhash", json!([0])).as_str().unwrap()).unwrap();
        let network = Network::CustomElements(
            ElementsParamsBuilder::new()
                .with_policy_asset(asset)
                .with_genesis_hash(genesis)
                .build()
                .unwrap(),
        );
        let signer = SwSigner::new(MNEMONIC, false).unwrap();
        let desc =
            lwk_common::singlesig_desc(&signer, Singlesig::Wpkh, DescriptorBlindingKey::Slip77)
                .unwrap();
        let mut wollet = WolletBuilder::new(network, WolletDescriptor::from_str(&desc).unwrap())
            .build()
            .unwrap();
        register_scripts(&mut wollet);
        // The staking key, m/2/0, as every wallet on the kit derives it.
        let xprv = signer
            .derive_xprv(&DerivationPath::from_str("m/2/0").unwrap())
            .unwrap();
        let staker_secret = SecretKey::from_slice(&xprv.private_key.secret_bytes()).unwrap();
        let staker = PublicKey::from_secret_key(&Secp256k1::new(), &staker_secret)
            .serialize()
            .to_vec();
        Kit {
            network,
            signer,
            wollet,
            staker_secret,
            staker,
        }
    }

    fn asset(&self) -> AssetId {
        *self.network.policy_asset()
    }

    fn address_spk(&self, index: u32) -> Script {
        self.wollet
            .address(Some(index))
            .unwrap()
            .address()
            .script_pubkey()
    }

    /// Build, sign and finalize a wallet transaction on the PSET path.
    fn pset_tx(&self, builder: TxBuilder) -> Transaction {
        let mut pset = builder
            .fee_rate(Some(FEE_RATE))
            .finish(&self.wollet)
            .unwrap();
        self.signer.sign(&mut pset).unwrap();
        self.wollet.finalize(&mut pset).unwrap()
    }

    fn applied(&mut self, tx: &Transaction) {
        self.wollet.apply_transaction(tx.clone()).unwrap();
    }

    /// The signature the node wants for a spend entering its next block.
    fn signing(&self, node: &Node, records_v2_height: u32) -> StakeRecordSigning {
        StakeRecordSigning::for_next_block(node.tip(), records_v2_height)
    }
}

/// Teach the wallet its first scripts, which a scan of a blockchain backend
/// would; the test then hands it each transaction it makes or receives
/// (`Wollet::apply_transaction`), which recognises only scripts it knows.
fn register_scripts(wollet: &mut Wollet) {
    let mut scripts = vec![];
    for i in 0..20u32 {
        let n = ChildNumber::from_normal_idx(i).unwrap();
        let external = wollet.address(Some(i)).unwrap().address().script_pubkey();
        let internal = wollet.change(Some(i)).unwrap().address().script_pubkey();
        scripts.push((Chain::External, n, external, None));
        scripts.push((Chain::Internal, n, internal, None));
    }
    let update = Update {
        version: 4,
        wollet_status: wollet.status(),
        new_txs: DownloadTxResult::default(),
        txid_height_new: vec![],
        txid_height_delete: vec![],
        timestamps: vec![],
        scripts_with_blinding_pubkey: scripts,
        // The wallet's own placeholder, which leaves its tip alone.
        tip: BlockHeader {
            version: 0,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            height: 0,
            ext: BlockExtData::default(),
            bitcoin_anchor: Some((0, BlockHash::all_zeros())),
        },
        unspent: vec![],
        last_unused: LastUnused::default(),
    };
    wollet.apply_update(update).unwrap();
}

/// Fund the kit wallet from the genesis output, then put the node on its
/// default relay policy. Returns the funding transaction.
fn fund(node: &mut Node, kit: &mut Kit, producer_wif: &str) -> Transaction {
    node.produce(producer_wif);
    let genesis = node.rpc("getblock", json!([node.rpc("getblockhash", json!([0])), 2]));
    let (txid, vout, value) = genesis["tx"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|tx| {
            tx["vout"].as_array().unwrap().iter().map(move |o| {
                (
                    tx["txid"].as_str().unwrap().to_string(),
                    o["n"].as_u64().unwrap() as u32,
                    o["scriptPubKey"]["hex"].as_str().unwrap().to_string(),
                    (o["value"].as_f64().unwrap_or(0.0) * COIN as f64).round() as u64,
                )
            })
        })
        .find(|(_, _, spk, v)| spk == "51" && *v > 0)
        .map(|(t, n, _, v)| (Txid::from_str(&t).unwrap(), n, v))
        .expect("an OP_TRUE genesis output");
    let asset = kit.asset();
    let fee = 100_000;
    let to_wallet = 2 * 200 * COIN;
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_fffe),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![
            explicit(asset, 200 * COIN, kit.address_spk(0)),
            explicit(asset, 200 * COIN, kit.address_spk(1)),
            explicit(asset, value - to_wallet - fee, Script::from(vec![0x51])),
            TxOut::new_fee(fee, asset),
        ],
    };
    let id = node.send(&hex_of(&tx));
    assert!(node.produce(producer_wif).contains(&id));
    kit.applied(&tx);

    node.restart_with_default_policy();
    // The remainder at OP_TRUE is now unspendable under relay policy: from here
    // on, what the node accepts is what the testnet would relay.
    let spend_rest = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(id, 2),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_fffe),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![
            explicit(asset, COIN, kit.address_spk(2)),
            explicit(
                asset,
                value - to_wallet - 2 * fee - COIN,
                kit.address_spk(3),
            ),
            TxOut::new_fee(fee, asset),
        ],
    };
    assert_eq!(
        node.refusal(&hex_of(&spend_rest)),
        "bad-txns-nonstandard-inputs"
    );
    tx
}

/// One transaction for the wasm half: what a wallet hands the binding `fun`
/// (`recipe`, the mnemonic added there) and the transaction the node confirmed.
fn wasm_case(what: &str, fun: &str, mut recipe: Json, raw: &str, signing: Option<&str>) -> Json {
    recipe["locktime"] = json!(decode(raw).lock_time.to_consensus_u32());
    let mut case = json!({
        "what": what,
        "fn": fun,
        "recipe": recipe,
        "raw_hex": raw,
        "txid": decode(raw).txid().to_string(),
    });
    if let Some(signing) = signing {
        case["signing"] = json!(signing);
    }
    case
}

/// The wasm half: `lwk_wasm/tests/node/stake_records.js` builds every case
/// through the bindings and must get the transaction the node confirmed. It
/// needs `node` and the wasm package built for node.js, linked as `lwk_node`
/// in `lwk_wasm/tests/node/node_modules` (`lwk_wasm/README.md`); without them
/// this half does not run, and says so.
fn wasm_half(name: &str, node: &Node, kit: &Kit, cases: Vec<Json>, signing: Vec<Json>) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lwk_wasm/tests/node");
    if !dir.join("node_modules/lwk_node").exists() {
        println!(
            "WASM HALF NOT RUN: no lwk_node package in {}/node_modules",
            dir.display()
        );
        return;
    }
    let fixture = json!({
        "policy_asset": kit.asset().to_string(),
        "genesis_hash": node.rpc("getblockhash", json!([0])),
        "mnemonic": MNEMONIC,
        "staker": kit.staker.to_hex(),
        "unbond_script": lwk_wollet::sequentia_unbond_script(&kit.staker).as_bytes().to_hex(),
        "signing": signing,
        "cases": cases,
    });
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    let out = Command::new("node")
        .arg(dir.join("stake_records.js"))
        .arg(&path)
        .current_dir(&dir)
        .output()
        .expect("node runs");
    let _ = std::fs::remove_file(&path);
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "stake_records.js failed");
}

/// The unblinded address string of the wallet's receive address `index`.
fn address_string(kit: &Kit, index: u32) -> String {
    kit.wollet
        .address(Some(index))
        .unwrap()
        .address()
        .to_unconfidential()
        .to_string()
}

#[test]
fn records_from_block_one() {
    let (producer_sk, producer_pub) = random_key();
    let producer = wif(&producer_sk);
    // The fork heights are left at the custom chain's default: block 1.
    let mut node = Node::start("stake_records_block_one", chain_args(&producer_pub, &[]));
    let mut kit = Kit::new(&node);
    let v2_height = pos_records_v2_height(&kit.network);
    assert_eq!(v2_height, 1);
    fund(&mut node, &mut kit, &producer);
    let asset = kit.asset();
    let staker = kit.staker.clone();
    let staker_hex = staker.to_hex();
    let mut wasm = vec![];

    // --- Bond -------------------------------------------------------------
    let stake_script = sequentia_stake_script(&staker, UNBONDING);
    assert_eq!(
        stake_script.as_bytes().to_hex(),
        node.rpc("getstakescript", json!([staker_hex, UNBONDING]))["script"]
            .as_str()
            .unwrap(),
        "the kit's staking script is the node's"
    );
    let bond =
        kit.pset_tx(TxBuilder::new(kit.network).add_stake_output(&staker, UNBONDING, 50 * COIN));
    let bond_id = node.send(&hex_of(&bond));
    assert!(node.produce(&producer).contains(&bond_id));
    let bond_height = node.tip();
    kit.applied(&bond);
    let bond_vout = bond
        .output
        .iter()
        .position(|o| o.script_pubkey == stake_script)
        .unwrap() as u32;
    assert_eq!(
        node.rpc("getstakerinfo", json!([false, true]))[&staker_hex],
        json!(50 * COIN)
    );
    println!("bond {bond_id} at {bond_height}");

    // --- Delegation, created with a coin of the controller -----------------
    let (_, pool_p) = random_key();
    let (_, pool_q) = random_key();

    // The wallet's coins alone no longer authorise a record.
    let unauthorised =
        kit.pset_tx(TxBuilder::new(kit.network).add_delegation_output(&staker, &pool_p, RECORD));

    let pay =
        kit.pset_tx(TxBuilder::new(kit.network).add_record_authorization(&staker, RECORD + FEE));
    let coins = find_key_coins(&pay, &staker, asset);
    assert_eq!(coins.len(), 1);
    let (coin_vout, coin_value) = coins[0];
    let (create_raw, create_id) = build_delegation_create_tx(&DelegationCreatePlan {
        coin_txid: pay.txid(),
        coin_vout,
        coin_value,
        asset,
        controller_secret: kit.staker_secret,
        signer: pool_p.clone(),
        record_value: RECORD,
        change_spk: kit.address_spk(4),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
    })
    .unwrap();
    refused_everywhere(
        &node,
        &producer,
        &unauthorised,
        &[&pay, &decode(&create_raw)],
        "record funded by wallet coins alone",
        "bad-delegation-unauthorized",
        "bad-delegation-unauthorized",
    );
    let pay_id = node.send(&hex_of(&pay));
    assert_eq!(node.send(&create_raw), create_id);
    wasm.push(wasm_case(
        "delegation created with the controller's coin",
        "buildDelegationCreateTx",
        json!({
            "coinTxHex": hex_of(&pay),
            "signer": pool_p.to_hex(),
            "recordValue": RECORD.to_string(),
            "feeAtoms": FEE.to_string(),
        }),
        &create_raw,
        None,
    ));
    let block = node.produce(&producer);
    assert!(
        block.contains(&pay_id) && block.contains(&create_id),
        "mined together"
    );
    kit.applied(&pay);
    assert_eq!(
        node.rpc("getdelegationinfo", json!([]))[&staker_hex],
        json!(pool_p.to_hex())
    );
    println!(
        "authorising payment {pay_id} and delegation {create_id} in block {}",
        node.tip()
    );

    // --- Re-point ---------------------------------------------------------
    let signing = kit.signing(&node, v2_height);
    assert_eq!(signing, StakeRecordSigning::SegwitV0);
    let repoint = |signing| DelegationSpendPlan {
        record_txid: create_id,
        record_vout: 0,
        record_value: RECORD,
        asset,
        current_signer: pool_p.clone(),
        controller_secret: kit.staker_secret,
        rotate_to: Some(pool_q.clone()),
        reclaim_spk: Script::new(),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
        signing,
    };
    let (legacy_raw, _) = build_delegation_spend_tx(&repoint(StakeRecordSigning::Legacy)).unwrap();
    let (repoint_raw, repoint_id) = build_delegation_spend_tx(&repoint(signing)).unwrap();
    wrong_signature_refused(
        &node,
        &producer,
        &legacy_raw,
        &repoint_raw,
        "re-point signed the legacy way",
        WRONG_HASH,
    );
    node.send(&repoint_raw);
    assert!(node.produce(&producer).contains(&repoint_id));
    wasm.push(wasm_case(
        "re-point",
        "buildDelegationSpendTx",
        json!({
            "recordTxid": create_id.to_string(),
            "recordVout": 0,
            "recordValue": RECORD.to_string(),
            "currentSigner": pool_p.to_hex(),
            "rotateTo": pool_q.to_hex(),
            "feeAtoms": FEE.to_string(),
        }),
        &repoint_raw,
        Some("segwitV0"),
    ));
    assert_eq!(
        node.rpc("getdelegationinfo", json!([]))[&staker_hex],
        json!(pool_q.to_hex())
    );
    println!("re-point {repoint_id} in block {}", node.tip());

    // --- Reclaim ----------------------------------------------------------
    let reclaim = |signing| DelegationSpendPlan {
        record_txid: repoint_id,
        record_vout: 0,
        record_value: RECORD - FEE,
        asset,
        current_signer: pool_q.clone(),
        controller_secret: kit.staker_secret,
        rotate_to: None,
        reclaim_spk: kit.address_spk(5),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
        signing,
    };
    let (legacy_raw, _) = build_delegation_spend_tx(&reclaim(StakeRecordSigning::Legacy)).unwrap();
    let (reclaim_raw, reclaim_id) =
        build_delegation_spend_tx(&reclaim(kit.signing(&node, v2_height))).unwrap();
    wrong_signature_refused(
        &node,
        &producer,
        &legacy_raw,
        &reclaim_raw,
        "reclaim signed the legacy way",
        WRONG_HASH,
    );
    node.send(&reclaim_raw);
    assert!(node.produce(&producer).contains(&reclaim_id));
    wasm.push(wasm_case(
        "reclaim",
        "buildDelegationSpendTx",
        json!({
            "recordTxid": repoint_id.to_string(),
            "recordVout": 0,
            "recordValue": (RECORD - FEE).to_string(),
            "currentSigner": pool_q.to_hex(),
            "reclaimAddress": address_string(&kit, 5),
            "feeAtoms": FEE.to_string(),
        }),
        &reclaim_raw,
        Some("segwitV0"),
    ));
    assert!(node
        .rpc("getdelegationinfo", json!([]))
        .get(&staker_hex)
        .is_none());
    kit.applied(&decode(&reclaim_raw));
    println!("reclaim {reclaim_id} in block {}", node.tip());

    // --- Payout announcement, and its withdrawal inside the notice ---------
    let activation = node.tip() + NOTICE + 10;
    let payout_script = Script::from(
        Vec::<u8>::from_hex(
            node.rpc(
                "getpayoutscript",
                json!([
                    staker_hex,
                    activation,
                    "direct",
                    kit.address_spk(6).as_bytes().to_hex()
                ]),
            )["script"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    let pay =
        kit.pset_tx(TxBuilder::new(kit.network).add_record_authorization(&staker, RECORD + FEE));
    let (coin_vout, coin_value) = find_key_coins(&pay, &staker, asset)[0];
    let (announce_raw, announce_id) = build_record_create_tx(&RecordCreatePlan {
        coin_txid: pay.txid(),
        coin_vout,
        coin_value,
        asset,
        key_secret: kit.staker_secret,
        record_script: payout_script.clone(),
        record_value: RECORD,
        change_spk: kit.address_spk(7),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
    })
    .unwrap();
    let pay_id = node.send(&hex_of(&pay));
    node.send(&announce_raw);
    let block = node.produce(&producer);
    assert!(
        block.contains(&pay_id) && block.contains(&announce_id),
        "mined together"
    );
    kit.applied(&pay);
    let policies = node.rpc("getpayoutinfo", json!([staker_hex]));
    assert_eq!(policies[&staker_hex][0]["activation"], json!(activation));
    assert_eq!(policies[&staker_hex][0]["in_force"], json!(false));
    println!(
        "authorising payment {pay_id} and payout announcement {announce_id} in block {}",
        node.tip()
    );

    let withdraw = |signing| {
        let mut tx = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(node.tip()),
            input: vec![TxIn {
                previous_output: OutPoint::new(announce_id, 0),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_fffd),
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                explicit(asset, RECORD - FEE, kit.address_spk(8)),
                TxOut::new_fee(FEE, asset),
            ],
        };
        sign_stake_record_input(
            &mut tx,
            0,
            &payout_script,
            Value::Explicit(RECORD),
            &kit.staker_secret,
            signing,
        )
        .unwrap();
        tx
    };
    let withdrawal = withdraw(kit.signing(&node, v2_height));
    wrong_signature_refused(
        &node,
        &producer,
        &hex_of(&withdraw(StakeRecordSigning::Legacy)),
        &hex_of(&withdrawal),
        "payout withdrawal signed the legacy way",
        WRONG_HASH,
    );
    let withdrawal_id = node.send(&hex_of(&withdrawal));
    assert!(node.produce(&producer).contains(&withdrawal_id));
    assert!(node
        .rpc("getpayoutinfo", json!([staker_hex]))
        .get(&staker_hex)
        .is_none());
    kit.applied(&withdrawal);
    println!(
        "payout record withdrawn by {withdrawal_id} in block {}",
        node.tip()
    );

    // --- Unbond, step 1 ---------------------------------------------------
    // The bond's relative lock: spendable in the block UNBONDING after it.
    while node.tip() + 1 < bond_height + UNBONDING {
        node.produce(&producer);
    }
    let unbond = |signing| UnbondPlan {
        stakes: vec![StakeOutput {
            txid: bond_id,
            vout: bond_vout,
            value: 50 * COIN,
            script_pubkey: stake_script.clone(),
        }],
        asset,
        staker_secret: kit.staker_secret,
        fee_atoms: FEE,
        locktime: node.tip(),
        signing,
    };
    let (legacy_raw, _) = build_unbond_tx(&unbond(StakeRecordSigning::Legacy)).unwrap();
    let (unbond_raw, unbond_id) = build_unbond_tx(&unbond(kit.signing(&node, v2_height))).unwrap();
    wrong_signature_refused(
        &node,
        &producer,
        &legacy_raw,
        &unbond_raw,
        "unbond signed the legacy way",
        WRONG_HASH,
    );
    node.send(&unbond_raw);
    assert!(node.produce(&producer).contains(&unbond_id));
    wasm.push(wasm_case(
        "unbond, step 1",
        "buildUnbondTx",
        json!({
            "stakes": [{
                "txid": bond_id.to_string(),
                "vout": bond_vout,
                "value": (50 * COIN).to_string(),
                "script": stake_script.as_bytes().to_hex(),
            }],
            "feeAtoms": FEE.to_string(),
        }),
        &unbond_raw,
        Some("segwitV0"),
    ));
    let unbond_height = node.tip();
    assert!(node
        .rpc("getstakerinfo", json!([false, true]))
        .get(&staker_hex)
        .is_none());
    println!("unbond {unbond_id} in block {unbond_height}");

    // --- Unbond, step 2 ---------------------------------------------------
    let claim = |signing| UnbondClaimPlan {
        unbonding: vec![UnbondingOutput {
            txid: unbond_id,
            vout: 0,
            value: 50 * COIN - FEE,
        }],
        asset,
        staker_secret: kit.staker_secret,
        destination: kit.address_spk(9),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
        signing,
    };
    let (early_raw, _) = build_unbond_claim_tx(&claim(kit.signing(&node, v2_height))).unwrap();
    refused_everywhere(
        &node,
        &producer,
        &decode(&early_raw),
        &[],
        "claim before the unbonding depth",
        "bad-unbond-premature",
        "bad-unbond-premature",
    );
    while node.tip() + 1 < unbond_height + UNBOND_DEPTH {
        node.produce(&producer);
    }
    let (legacy_raw, _) = build_unbond_claim_tx(&claim(StakeRecordSigning::Legacy)).unwrap();
    let (claim_raw, claim_id) =
        build_unbond_claim_tx(&claim(kit.signing(&node, v2_height))).unwrap();
    wrong_signature_refused(
        &node,
        &producer,
        &legacy_raw,
        &claim_raw,
        "claim signed the legacy way",
        WRONG_HASH,
    );
    node.send(&claim_raw);
    assert!(node.produce(&producer).contains(&claim_id));
    wasm.push(wasm_case(
        "unbond, step 2",
        "buildUnbondClaimTx",
        json!({
            "unbonding": [{
                "txid": unbond_id.to_string(),
                "vout": 0,
                "value": (50 * COIN - FEE).to_string(),
            }],
            "address": address_string(&kit, 9),
            "feeAtoms": FEE.to_string(),
        }),
        &claim_raw,
        Some("segwitV0"),
    ));
    kit.applied(&decode(&claim_raw));
    println!("claim {claim_id} in block {}", node.tip());

    // The claimed coins are the wallet's.
    let claimed = kit.wollet.utxos().unwrap().into_iter().any(|u| {
        u.outpoint == OutPoint::new(claim_id, 0) && u.unblinded.value == 50 * COIN - 2 * FEE
    });
    assert!(claimed, "the wallet holds the claimed coins");

    let signing = vec![
        json!({"tip": 0, "v2_height": null, "expect": "segwitV0"}),
        json!({"tip": 162_998, "v2_height": 163_000, "expect": "legacy"}),
        json!({"tip": 162_999, "v2_height": 163_000, "expect": "segwitV0"}),
    ];
    wasm_half("stake_records_block_one", &node, &kit, wasm, signing);
}

#[test]
fn records_across_the_fork_height() {
    const FORK: u32 = 12;
    let (producer_sk, producer_pub) = random_key();
    let producer = wif(&producer_sk);
    let heights = [
        format!("-posrecordsv2height={FORK}"),
        format!("-poshardeningheight={FORK}"),
    ];
    let extra: Vec<&str> = heights.iter().map(String::as_str).collect();
    let mut node = Node::start("stake_records_fork", chain_args(&producer_pub, &extra));
    let mut kit = Kit::new(&node);
    fund(&mut node, &mut kit, &producer);
    let asset = kit.asset();
    let staker = kit.staker.clone();
    let staker_hex = staker.to_hex();
    let (_, pool_p) = random_key();
    let (_, pool_q) = random_key();
    let mut wasm = vec![];

    // Below the height a record from wallet coins alone is still valid.
    let create =
        kit.pset_tx(TxBuilder::new(kit.network).add_delegation_output(&staker, &pool_p, RECORD));
    let create_id = node.send(&hex_of(&create));
    assert!(node.produce(&producer).contains(&create_id));
    kit.applied(&create);
    let record_vout = create
        .output
        .iter()
        .position(|o| lwk_wollet::parse_delegation_script(&o.script_pubkey).is_some())
        .unwrap() as u32;
    assert!(node.tip() + 1 < FORK);

    // ...and its re-point is signed the legacy way.
    let signing = StakeRecordSigning::for_next_block(node.tip(), FORK);
    assert_eq!(signing, StakeRecordSigning::Legacy);
    let repoint = |signing| DelegationSpendPlan {
        record_txid: create_id,
        record_vout,
        record_value: RECORD,
        asset,
        current_signer: pool_p.clone(),
        controller_secret: kit.staker_secret,
        rotate_to: Some(pool_q.clone()),
        reclaim_spk: Script::new(),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
        signing,
    };
    let (v2_raw, _) = build_delegation_spend_tx(&repoint(StakeRecordSigning::SegwitV0)).unwrap();
    let (repoint_raw, repoint_id) = build_delegation_spend_tx(&repoint(signing)).unwrap();
    wrong_signature_refused(
        &node,
        &producer,
        &v2_raw,
        &repoint_raw,
        "re-point below the height, signed the second-generation way",
        FALSE_RESULT,
    );
    node.send(&repoint_raw);
    assert!(node.produce(&producer).contains(&repoint_id));
    wasm.push(wasm_case(
        "re-point below the fork height",
        "buildDelegationSpendTx",
        json!({
            "recordTxid": create_id.to_string(),
            "recordVout": record_vout,
            "recordValue": RECORD.to_string(),
            "currentSigner": pool_p.to_hex(),
            "rotateTo": pool_q.to_hex(),
            "feeAtoms": FEE.to_string(),
            "recordsV2Height": FORK,
        }),
        &repoint_raw,
        Some("legacy"),
    ));
    println!(
        "legacy-signed re-point {repoint_id} in block {}",
        node.tip()
    );
    assert_eq!(
        node.rpc("getdelegationinfo", json!([]))[&staker_hex],
        json!(pool_q.to_hex())
    );

    // At the height the reclaim is signed the second-generation way.
    while node.tip() + 1 < FORK {
        node.produce(&producer);
    }
    let signing = StakeRecordSigning::for_next_block(node.tip(), FORK);
    assert_eq!(signing, StakeRecordSigning::SegwitV0);
    let reclaim = |signing| DelegationSpendPlan {
        record_txid: repoint_id,
        record_vout: 0,
        record_value: RECORD - FEE,
        asset,
        current_signer: pool_q.clone(),
        controller_secret: kit.staker_secret,
        rotate_to: None,
        reclaim_spk: kit.address_spk(5),
        fee_atoms: FEE,
        dust_floor: 1_000,
        locktime: node.tip(),
        signing,
    };
    let (legacy_raw, _) = build_delegation_spend_tx(&reclaim(StakeRecordSigning::Legacy)).unwrap();
    let (reclaim_raw, reclaim_id) = build_delegation_spend_tx(&reclaim(signing)).unwrap();
    // Judged in the block at the fork height itself.
    assert_eq!(node.tip() + 1, FORK);
    wrong_signature_refused(
        &node,
        &producer,
        &legacy_raw,
        &reclaim_raw,
        "reclaim at the height, signed the legacy way",
        WRONG_HASH,
    );
    node.send(&reclaim_raw);
    assert!(node.produce(&producer).contains(&reclaim_id));
    wasm.push(wasm_case(
        "reclaim at the fork height",
        "buildDelegationSpendTx",
        json!({
            "recordTxid": repoint_id.to_string(),
            "recordVout": 0,
            "recordValue": (RECORD - FEE).to_string(),
            "currentSigner": pool_q.to_hex(),
            "reclaimAddress": address_string(&kit, 5),
            "feeAtoms": FEE.to_string(),
            "recordsV2Height": FORK,
        }),
        &reclaim_raw,
        Some("segwitV0"),
    ));
    assert!(node
        .rpc("getdelegationinfo", json!([]))
        .get(&staker_hex)
        .is_none());
    println!(
        "second-generation reclaim {reclaim_id} in block {}",
        node.tip()
    );
    let signing = vec![
        json!({"tip": FORK - 2, "v2_height": FORK, "expect": "legacy"}),
        json!({"tip": FORK - 1, "v2_height": FORK, "expect": "segwitV0"}),
    ];
    wasm_half("stake_records_fork", &node, &kit, wasm, signing);
}
