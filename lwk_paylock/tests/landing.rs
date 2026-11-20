//! The completion service choosing the payment whose claim lands, against a fake Bitcoin
//! daemon serving real blocks (headers linked, merkle roots computed) and a fake
//! Sequentia node that anchors to them and refuses a claim whose fee does not cover its
//! weight, as `min relay fee not met`.
//!
//! - a heavy payment to the seller mined before the buyer's never stands in for it;
//! - a candidate whose claim the node refuses at every tier is passed over, and the next
//!   one is tried in the same round; one the top tier carries is claimed at the top tier;
//! - the service's Bitcoin daemon switching branches between its scan and the proof's
//!   header reads leaves the payment waiting, never passed over, and it is claimed once the
//!   two chains agree.
//!
//! Only the service's public interface is used (`tick`, `Job`), so the same file judges an
//! earlier revision of the library.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lwk_paylock::service::{self, Job, Limits, Store};
use lwk_paylock::{BtcChain, Rpc, SeqChain};
use lwk_wollet::bitcoin;
use lwk_wollet::bitcoin::hashes::Hash as _;
use lwk_wollet::btc::paylock::{self, hex_decode, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use lwk_wollet::elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Transaction};
use serde_json::{json, Value};

type Answer = Box<dyn Fn(&str, &Value) -> Result<Value, (i32, String)> + Send + Sync>;

fn fake_node(answer: Answer) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let answer = Arc::new(answer);
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let answer = answer.clone();
            std::thread::spawn(move || {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let method = v["method"].as_str().unwrap_or_default().to_string();
                let out = match answer(&method, &v["params"]) {
                    Ok(r) => json!({"jsonrpc": "2.0", "result": r, "error": null, "id": v["id"]}),
                    Err((code, message)) => json!({"jsonrpc": "2.0", "result": null,
                        "error": {"code": code, "message": message}, "id": v["id"]}),
                };
                let _ = req.respond(
                    tiny_http::Response::from_string(out.to_string())
                        .with_chunked_threshold(usize::MAX),
                );
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn rpc(u: &str) -> Rpc {
    Rpc::with_timeout(u, "u", "p", Duration::from_secs(10)).unwrap()
}

fn key(b: u8) -> SecretKey {
    SecretKey::from_slice(&[b; 32]).unwrap()
}

/// The first Bitcoin height of the fake chain; the lock's floor.
const BASE: u32 = 1_000;

fn terms() -> PayLockTerms {
    terms_at(BASE, BASE + 6, 3)
}

/// Terms from `floor` to `deadline`, paying the seller's receiving key made from byte `r`.
fn terms_at(floor: u32, deadline: u32, r: u8) -> PayLockTerms {
    let secp = Secp256k1::new();
    let x = |b| {
        Keypair::from_secret_key(&secp, &key(b))
            .x_only_public_key()
            .0
    };
    let rk = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&[r; 32]).unwrap(),
    ));
    PayLockTerms::new(
        AssetId::from_slice(&[5; 32]).unwrap(),
        1_000_000,
        50_000,
        x(1),
        x(2),
        rk,
        floor,
        deadline,
    )
    .unwrap()
}

/// A payment of the price to the terms' receiving script from the coin named by `n`, with
/// `pad` bytes of OP_RETURN data beside it (0 for none).
fn payment(t: &PayLockTerms, n: u8, pad: usize) -> bitcoin::Transaction {
    let mut out = vec![bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(t.price_sat),
        script_pubkey: t.receive_script_pubkey(),
    }];
    if pad > 0 {
        let mut data = vec![0x6a, 0x4e];
        data.extend((pad as u32).to_le_bytes());
        data.extend(std::iter::repeat(0xab).take(pad));
        out.push(bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from(data),
        });
    }
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            sequence: bitcoin::Sequence(0xffff_fffd),
            ..Default::default()
        }],
        output: out,
    }
}

/// A block on `prev` carrying a coinbase (tagged `tag`, so sibling blocks differ) and `txs`.
fn block(prev: bitcoin::BlockHash, tag: u8, txs: &[bitcoin::Transaction]) -> bitcoin::Block {
    let coinbase = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            script_sig: bitcoin::ScriptBuf::from(vec![1, tag]),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let mut b = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: u32::from(tag),
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: std::iter::once(coinbase)
            .chain(txs.iter().cloned())
            .collect(),
    };
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    b
}

/// A chain of blocks from `BASE`, each holding the transactions given for its height.
fn chain(
    prev: bitcoin::BlockHash,
    tag: u8,
    heights: &[Vec<bitcoin::Transaction>],
) -> Vec<bitcoin::Block> {
    let mut out: Vec<bitcoin::Block> = vec![];
    for (i, txs) in heights.iter().enumerate() {
        let p = out.last().map(|b| b.block_hash()).unwrap_or(prev);
        out.push(block(p, tag.wrapping_add(i as u8), txs));
    }
    out
}

/// Bitcoin as the fake daemon serves it: branches of blocks from `BASE`, the one its best
/// chain follows, the one the Sequentia node anchors to, and a switch of the daemon's best
/// chain the first time a proof reads the block named (`getblock <hash> 1`).
#[derive(Default)]
struct Btc {
    branches: Vec<Vec<bitcoin::Block>>,
    best: usize,
    node: usize,
    switch_on_proof: Option<(String, usize)>,
    fetched: u64,
    /// Transactions sent to it.
    sent: Vec<String>,
}

impl Btc {
    fn all(&self) -> HashMap<String, bitcoin::Block> {
        self.branches
            .iter()
            .flatten()
            .map(|b| (b.block_hash().to_string(), b.clone()))
            .collect()
    }
}

fn fake_btc(state: Arc<Mutex<Btc>>) -> String {
    fake_node(Box::new(move |m, p| {
        let mut s = state.lock().unwrap();
        let best = s.branches[s.best].clone();
        let all = s.all();
        let by = |h: &Value| all.get(h.as_str().unwrap_or_default()).cloned();
        match m {
            "getblockcount" => Ok(json!(BASE - 1 + best.len() as u32)),
            "getbestblockhash" => Ok(json!(best.last().unwrap().block_hash().to_string())),
            "getblockhash" => {
                let h = p[0].as_u64().unwrap() as u32;
                best.get((h - BASE) as usize)
                    .map(|b| json!(b.block_hash().to_string()))
                    .ok_or((-8, "Block height out of range".into()))
            }
            "getblock" => {
                let b = by(&p[0]).ok_or((-5, "Block not found".to_string()))?;
                if p[1].as_u64() == Some(0) {
                    s.fetched += 1;
                    return Ok(json!(hex_encode(&bitcoin::consensus::encode::serialize(
                        &b
                    ))));
                }
                if let Some((h, to)) = s.switch_on_proof.clone() {
                    if p[0].as_str() == Some(h.as_str()) {
                        s.best = to;
                        s.switch_on_proof = None;
                    }
                }
                Ok(
                    json!({"tx": b.txdata.iter().map(|t| t.compute_txid().to_string()).collect::<Vec<_>>()}),
                )
            }
            "getblockheader" => {
                let b = by(&p[0]).ok_or((-5, "Block not found".to_string()))?;
                Ok(json!(hex_encode(&bitcoin::consensus::encode::serialize(
                    &b.header
                ))))
            }
            "getrawtransaction" => {
                let b = by(&p[2]).ok_or((-5, "No such transaction".to_string()))?;
                b.txdata
                    .iter()
                    .find(|t| Some(t.compute_txid().to_string().as_str()) == p[0].as_str())
                    .map(|t| json!(hex_encode(&bitcoin::consensus::encode::serialize(t))))
                    .ok_or((-5, "No such transaction".into()))
            }
            "testmempoolaccept" => {
                Ok(json!([{"allowed": false, "reject-reason": "missing-inputs"}]))
            }
            "getmempoolentry" => Err((-5, "Transaction not in mempool".into())),
            "sendrawtransaction" => {
                let hex = p[0].as_str().unwrap_or_default().to_string();
                let t: bitcoin::Transaction =
                    bitcoin::consensus::encode::deserialize(&hex_decode(&hex).unwrap()).unwrap();
                s.sent.push(hex);
                Ok(json!(t.compute_txid().to_string()))
            }
            _ => Err((-32601, "Method not found".into())),
        }
    }))
}

/// The Sequentia node: blocks 0 to 5 anchored at these Bitcoin heights (of the branch it
/// follows), the locks mined in block 1; claims it pools; and its relay floor: a claim is
/// refused unless its fee, valued at the fee asset's `rate` as a node values it (`atoms ×
/// rate / 10^8`, rounded down), covers `floor` reference atoms per 1,000 bytes of its
/// proof's record, which `getmempoolinfo` reports as its relay floor. `generation` names
/// the blocks: raised, the same heights are other blocks (rebuilt on another branch).
struct Seq {
    anchors: Vec<u32>,
    lock: Transaction,
    locks: HashMap<String, Transaction>,
    pooled: HashMap<String, Transaction>,
    floor: usize,
    /// The fee asset's rate (10^8: one atom is worth one reference atom).
    rate: u64,
    /// Refuses every claim as `mempool full`, a refusal without figures.
    full: bool,
    /// How long it takes to answer a claim sent.
    send_delay: Duration,
    /// The claims pooled, in the order they were.
    order: Vec<String>,
    fee_asset: AssetId,
    generation: u64,
    refused: Vec<String>,
    first_pooled: Option<Instant>,
    /// How many claims it had refused when it first pooled one.
    refused_before_pooled: Option<usize>,
}

fn fake_seq(state: Arc<Mutex<Seq>>, btc: Arc<Mutex<Btc>>) -> String {
    let hash = |h: u64, g: u64| format!("{:064x}", 0x5e9_0000 + h + (g << 32));
    fake_node(Box::new(move |m, p| {
        let mut s = state.lock().unwrap();
        let lock_id = s.lock.txid().to_string();
        match m {
            "getblockcount" => Ok(json!(s.anchors.len() - 1)),
            "getbestblockhash" => Ok(json!(hash(s.anchors.len() as u64 - 1, s.generation))),
            "getblockhash" => Ok(json!(hash(p[0].as_u64().unwrap(), s.generation))),
            "getblockheader" => {
                let h = ((u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap() - 0x5e9_0000)
                    & 0xffff_ffff) as usize;
                let a = s.anchors[h];
                let b = btc.lock().unwrap();
                let anchor = b.branches[b.node][(a - BASE) as usize]
                    .block_hash()
                    .to_string();
                Ok(
                    json!({"height": h, "confirmations": 1, "anchorheight": a, "anchorhash": anchor}),
                )
            }
            "getrawtransaction" if p[0].as_str() == Some(&lock_id) => Ok(
                json!({"hex": hex_encode(&serialize(&s.lock)), "blockhash": hash(1, s.generation)}),
            ),
            "getrawtransaction" if s.locks.contains_key(p[0].as_str().unwrap_or_default()) => {
                let l = &s.locks[p[0].as_str().unwrap_or_default()];
                Ok(json!({"hex": hex_encode(&serialize(l)), "blockhash": hash(1, s.generation)}))
            }
            "getrawmempool" => Ok(json!(s.pooled.keys().collect::<Vec<_>>())),
            "getmempoolinfo" => Ok(json!({"mempoolminfee": s.floor as f64 / 1e8,
                "minrelaytxfee": s.floor as f64 / 1e8})),
            "getrawtransaction" => match s.pooled.get(p[0].as_str().unwrap_or_default()) {
                Some(tx) => Ok(json!({"hex": hex_encode(&serialize(tx))})),
                None => Err((-5, "No such mempool or blockchain transaction".into())),
            },
            "getposfinality" => Ok(json!({"finalized_height": 0})),
            "gettxout" => Ok(json!({"value": 1})),
            "getfeeassetinfo" => {
                let mut m = serde_json::Map::new();
                let asset = p[0]
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| s.fee_asset.to_string());
                m.insert(asset, json!({"accepted": true, "rate": s.rate}));
                Ok(Value::Object(m))
            }
            "sendrawtransaction" => {
                if !s.send_delay.is_zero() {
                    let d = s.send_delay;
                    drop(s);
                    std::thread::sleep(d);
                    s = state.lock().unwrap();
                }
                let tx: Transaction =
                    deserialize(&hex_decode(p[0].as_str().unwrap()).unwrap()).unwrap();
                if s.full {
                    s.refused.push("mempool full".into());
                    return Err((-26, "mempool full".into()));
                }
                let record = tx.input[0]
                    .witness
                    .pegin_witness
                    .first()
                    .map(Vec::len)
                    .unwrap_or(0);
                let atoms = paylock::fee_of(&tx).map(|f| f.1).unwrap_or(0);
                let fee = (atoms as u128 * s.rate as u128 / 100_000_000) as usize;
                let need = record * s.floor / 1_000;
                if fee < need {
                    let m = format!("min relay fee not met, {fee} < {need}");
                    s.refused.push(m.clone());
                    return Err((-26, m));
                }
                s.pooled.insert(tx.txid().to_string(), tx.clone());
                s.order.push(tx.txid().to_string());
                s.first_pooled.get_or_insert_with(Instant::now);
                let n = s.refused.len();
                s.refused_before_pooled.get_or_insert(n);
                Ok(json!(tx.txid().to_string()))
            }
            _ => Err((-32601, "Method not found".into())),
        }
    }))
}

/// The lock transaction paying the terms' lock script at output 0.
fn lock_tx(t: &PayLockTerms) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![paylock::lock_txout(t).unwrap()],
    }
}

/// The job a buyer's wallet hands over: claims at a going tier of 1,000 atoms and a top
/// tier of `top`, and the payment `held` if given.
fn job_with(
    t: &PayLockTerms,
    lock: &Transaction,
    held: Option<&bitcoin::Transaction>,
    top: u64,
) -> Job {
    let lock = OutPoint::new(lock.txid(), 0);
    let claims: Vec<String> = [1_000u64, top]
        .iter()
        .map(|f| {
            let to = Script::from(vec![0x51]);
            let c = paylock::sign_claim(t, lock, to, *f, BlockHash::all_zeros(), &key(1)).unwrap();
            hex_encode(&serialize(&c))
        })
        .collect();
    let mut v = json!({
        "terms": t.to_json(),
        "lock": format!("{}:{}", lock.txid, lock.vout),
        "claims": claims,
    });
    if let Some(p) = held {
        v["payment_hex"] = json!(hex_encode(&bitcoin::consensus::encode::serialize(p)));
    }
    Job::from_request(&v).unwrap()
}

fn job(t: &PayLockTerms, lock: &Transaction, held: Option<&bitcoin::Transaction>) -> Job {
    job_with(t, lock, held, 50_000)
}

/// The payment the pooled claim proves: the transaction id of the record's payment.
fn proven(seq: &Arc<Mutex<Seq>>) -> Option<String> {
    let s = seq.lock().unwrap();
    let tx = s.pooled.values().next()?;
    let r = tx.input[0].witness.pegin_witness.first()?;
    let depth = r[121] as usize;
    let at = 126 + 64 * depth;
    let links = u16::from_le_bytes([r[at], r[at + 1]]) as usize;
    let pay: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(&r[at + 2 + 80 * links..]).ok()?;
    Some(pay.compute_txid().to_string())
}

struct World {
    seq: Arc<Mutex<Seq>>,
    btc: Arc<Mutex<Btc>>,
    seq_chain: SeqChain,
    btc_chain: BtcChain,
    seq_url: String,
    btc_url: String,
}

/// The fake chains: Bitcoin's branches, Sequentia's anchors, and its floor of one atom per
/// `per_atom` bytes of proof.
fn world(
    t: &PayLockTerms,
    branches: Vec<Vec<bitcoin::Block>>,
    anchors: Vec<u32>,
    per_atom: usize,
) -> World {
    let lock = lock_tx(t);
    let probe = paylock::sign_claim(
        t,
        OutPoint::new(lock.txid(), 0),
        Script::from(vec![0x51]),
        1,
        BlockHash::all_zeros(),
        &key(1),
    )
    .unwrap();
    let btc = Arc::new(Mutex::new(Btc {
        branches,
        ..Default::default()
    }));
    let seq = Arc::new(Mutex::new(Seq {
        anchors,
        lock,
        locks: HashMap::new(),
        pooled: HashMap::new(),
        floor: 1_000 / per_atom,
        rate: 100_000_000,
        full: false,
        send_delay: Duration::ZERO,
        order: vec![],
        fee_asset: paylock::fee_of(&probe).unwrap().0,
        generation: 0,
        refused: vec![],
        first_pooled: None,
        refused_before_pooled: None,
    }));
    let (su, bu) = (fake_seq(seq.clone(), btc.clone()), fake_btc(btc.clone()));
    World {
        seq,
        btc,
        seq_chain: SeqChain { rpc: rpc(&su) },
        btc_chain: BtcChain { rpc: rpc(&bu) },
        seq_url: su,
        btc_url: bu,
    }
}

fn tick(w: &World, j: &mut Job) -> Result<(), String> {
    let until = Instant::now() + Duration::from_secs(20);
    service::tick(&w.seq_chain, &w.btc_chain, j, &Limits::default(), until).map_err(|e| e.0)
}

fn id(t: &bitcoin::Transaction) -> String {
    t.compute_txid().to_string()
}

#[test]
fn a_heavy_payment_mined_first_never_stands_in_for_the_buyers() {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let heavy = payment(&t, 77, 90_000);
    assert!(lwk_paylock::provable(&heavy));
    // F 1000; the heavy payment at 1001, the buyer's at 1002; Sequentia anchored up to 1003.
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        10,
        &[vec![], vec![heavy.clone()], vec![buyer.clone()], vec![]],
    );
    // The relay floor: one atom per byte of proof. The going tier (1,000 atoms) carries a
    // plain payment's proof; neither tier carries the heavy one's (about 90 KB).
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
    let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    let mut outcome = vec![];
    for _ in 0..3 {
        outcome.push(tick(&w, &mut j));
        if proven(&w.seq).is_some() {
            break;
        }
    }
    let v = j.public_json();
    eprintln!(
        "heavy first: {outcome:?}; {} ; refused {:?}",
        v["note"],
        w.seq.lock().unwrap().refused
    );
    assert_eq!(
        proven(&w.seq),
        Some(id(&buyer)),
        "the claim proves the buyer's payment: {}",
        v["note"]
    );
    assert_eq!(v["state"], "pooled");
    assert_eq!(v["payment_height"], 1002);
}

#[test]
fn a_refused_claim_passes_its_payment_over_and_the_next_is_tried_at_once() {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let heavy = payment(&t, 77, 90_000);
    // A heavy payment is handed over (held: at most 32 KiB), so it is tried first; the
    // buyer's comes in the next block. One round: refused at both tiers (1,000 and 20,000
    // atoms, against about 30,000 needed), passed over, and the buyer's claimed.
    let held = payment(&t, 76, 30_000);
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        20,
        &[vec![], vec![held.clone()], vec![buyer.clone()], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
    let mut j = job_with(&t, &w.seq.lock().unwrap().lock.clone(), Some(&held), 20_000);
    let r = tick(&w, &mut j);
    let v = j.public_json();
    let refused = w.seq.lock().unwrap().refused.clone();
    eprintln!("held heavy: {r:?}; {} ; refused {refused:?}", v["note"]);
    assert_eq!(
        refused.len(),
        2,
        "both tiers of the heavy one were tried: {refused:?}"
    );
    assert!(refused
        .iter()
        .all(|m| m.starts_with("min relay fee not met")));
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert_eq!(v["state"], "pooled");

    // Alone in the window, the heavy payment's claim is carried by the top tier.
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        30,
        &[vec![], vec![heavy.clone()], vec![], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 4);
    let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    let mut outcome = vec![];
    for _ in 0..3 {
        outcome.push(tick(&w, &mut j));
        if proven(&w.seq).is_some() {
            break;
        }
    }
    let v = j.public_json();
    eprintln!("heavy alone: {outcome:?}; {}", v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&heavy)), "{}", v["note"]);
    assert_eq!(
        (v["state"].clone(), v["tier"].clone()),
        (json!("pooled"), json!(1))
    );

    // Alone and carried by no tier: passed over, the job waits for another payment.
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        40,
        &[vec![], vec![heavy.clone()], vec![], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
    let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    let r = tick(&w, &mut j);
    let v = j.public_json();
    eprintln!("heavy, no tier: {r:?}; {}", v["note"]);
    assert!(proven(&w.seq).is_none());
    assert_eq!(v["state"], "waiting");
    assert!(
        v["note"].as_str().unwrap().contains("refuses every claim"),
        "{}",
        v["note"]
    );
    // Bitcoin moves on with the buyer's payment: claimed.
    {
        let mut b = w.btc.lock().unwrap();
        let p = b.branches[0][2].block_hash();
        let nb = block(p, 99, &[buyer.clone()]);
        b.branches[0][3] = nb;
        let p = b.branches[0][3].block_hash();
        b.branches[0].push(block(p, 98, &[]));
    }
    w.seq.lock().unwrap().anchors.push(1004);
    let mut outcome = vec![];
    for _ in 0..3 {
        outcome.push(tick(&w, &mut j));
        if proven(&w.seq).is_some() {
            break;
        }
    }
    let v = j.public_json();
    eprintln!("then the buyer's: {outcome:?}; {}", v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
}

#[test]
fn a_branch_switch_inside_one_round_passes_nothing_over() {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let other = payment(&t, 9, 0);
    let mut other_tx = other.clone();
    other_tx.output.truncate(0);
    other_tx.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(5),
        script_pubkey: bitcoin::ScriptBuf::new(),
    });
    // Two branches from 1001: A has the buyer's payment at 1002; B, which the Sequentia
    // node follows, has it at 1003. Sequentia's anchors jump from 1001 to 1003.
    let common = chain(bitcoin::BlockHash::all_zeros(), 50, &[vec![], vec![]]);
    let tip = common.last().unwrap().block_hash();
    let a = chain(tip, 60, &[vec![buyer.clone()], vec![], vec![]]);
    let b = chain(tip, 70, &[vec![other_tx], vec![buyer.clone()], vec![]]);
    let branch = |x: &[bitcoin::Block]| common.iter().chain(x).cloned().collect::<Vec<_>>();
    let w = world(
        &t,
        vec![branch(&a), branch(&b)],
        vec![1000, 1000, 1001, 1003, 1004],
        2,
    );
    {
        // The service's daemon follows A while it scans, and switches to B the moment the
        // proof reads A's block 1002: the headers the proof then reads by height are B's.
        let mut s = w.btc.lock().unwrap();
        s.best = 0;
        s.node = 1;
        s.switch_on_proof = Some((a[0].block_hash().to_string(), 1));
    }
    let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    let first = tick(&w, &mut j);
    let v = j.public_json();
    eprintln!(
        "the round the daemon switched in: {first:?}; {} {}",
        v["state"], v["note"]
    );
    assert_eq!(
        w.btc.lock().unwrap().best,
        1,
        "the daemon switched during the round"
    );
    assert!(proven(&w.seq).is_none());
    assert_ne!(v["state"], "never");
    let mut outcome = vec![];
    for _ in 0..3 {
        outcome.push(tick(&w, &mut j));
        if proven(&w.seq).is_some() {
            break;
        }
    }
    let v = j.public_json();
    eprintln!("then: {outcome:?}; {} {}", v["state"], v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert_eq!(
        (v["state"].clone(), v["payment_height"].clone()),
        (json!("pooled"), json!(1003))
    );
}

/// A flood of `jobs` jobs on the attacker's own terms (its floor 1,000 Bitcoin blocks back,
/// its deadline a block before the buyer's), posted from `clients` addresses, beside the
/// buyer's job. Every job is worked once; then the buyer's payment is mined and anchored.
/// Returns how long the next round took to pool the buyer's claim, and how many blocks the
/// daemon served.
fn flood(jobs: usize, clients: usize) -> (Option<Duration>, u64) {
    let tip = BASE + 1_000;
    let buyer_terms = terms_at(tip - 1, tip + 6, 3);
    let att = terms_at(BASE, tip + 5, 4);
    let blocks = chain(bitcoin::BlockHash::all_zeros(), 1, &vec![vec![]; 1_001]);
    let mut anchors = vec![BASE, BASE];
    anchors.extend(BASE + 1..=tip);
    let w = world(&buyer_terms, vec![blocks], anchors, 1);
    let dir = std::env::temp_dir().join(format!("paylock-flood-{jobs}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let limits = Limits {
        max_jobs: 1_000_000,
        jobs_per_client: 0,
        round_time: Duration::from_secs(10),
        ..Limits::default()
    };
    let store = Mutex::new(Store::open(&dir).unwrap());
    let att_lock = lock_tx(&att);
    let att_claim = |i: u32| {
        let lock = OutPoint::new(att_lock.txid(), i);
        let c = paylock::sign_claim(
            &att,
            lock,
            Script::from(vec![0x51]),
            1_000,
            BlockHash::all_zeros(),
            &key(1),
        )
        .unwrap();
        json!({"terms": att.to_json(), "lock": format!("{}:{}", lock.txid, lock.vout),
               "claims": [hex_encode(&serialize(&c))]})
    };
    {
        let mut st = store.lock().unwrap();
        for i in 0..jobs {
            let mut j = Job::from_request(&att_claim(i as u32)).unwrap();
            j.client = format!("100.64.{}.{}", (i % clients) / 250, (i % clients) % 250);
            st.add(j, &limits).unwrap();
        }
        let mut j = job(&buyer_terms, &w.seq.lock().unwrap().lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    // Every job worked once, nothing paid yet.
    for _ in 0..30 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        let pending = store
            .lock()
            .unwrap()
            .jobs
            .values()
            .filter(|j| j.note.is_empty())
            .count();
        if pending == 0 {
            break;
        }
    }
    // The buyer pays: its payment mined at the next block and anchored.
    let buyer = payment(&buyer_terms, 42, 0);
    {
        let mut b = w.btc.lock().unwrap();
        let p = b.branches[0].last().unwrap().block_hash();
        b.branches[0].push(block(p, 200, &[buyer]));
    }
    w.seq.lock().unwrap().anchors.push(tip + 1);
    let t0 = Instant::now();
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let took = w.seq.lock().unwrap().first_pooled.map(|t| t - t0);
    let fetched = w.btc.lock().unwrap().fetched;
    let _ = std::fs::remove_dir_all(&dir);
    (took, fetched)
}

#[test]
fn a_flood_of_jobs_and_clients_does_not_delay_a_buyers_claim() {
    let mut seen = vec![];
    for (jobs, clients) in [(100, 8), (1_000, 8), (1_000, 500)] {
        let (took, fetched) = flood(jobs, clients);
        eprintln!("{jobs} attacker jobs from {clients} addresses: the buyer's claim pooled {took:?} into the round after its payment; {fetched} blocks served");
        seen.push((jobs, clients, took, fetched));
    }
    for (jobs, clients, took, fetched) in seen {
        let took = took.unwrap_or_else(|| {
            panic!("{jobs} jobs from {clients}: the buyer's claim was not pooled in the round")
        });
        assert!(
            took < Duration::from_secs(2),
            "{jobs} jobs from {clients}: {took:?}"
        );
        // Each of the 1,002 blocks read about once, whatever the number of jobs.
        assert!(
            fetched < 1_100,
            "{jobs} jobs from {clients}: {fetched} blocks served"
        );
    }
}

/// Terms from `floor` to `deadline` whose seller receives at a key of its own, made from
/// `n`: one more job, one more receiving script.
fn terms_n(floor: u32, deadline: u32, n: u32) -> PayLockTerms {
    let secp = Secp256k1::new();
    let x = |b| {
        Keypair::from_secret_key(&secp, &key(b))
            .x_only_public_key()
            .0
    };
    let mut seed = [7u8; 32];
    seed[28..].copy_from_slice(&(n + 1).to_be_bytes());
    let rk = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
    ));
    PayLockTerms::new(
        AssetId::from_slice(&[5; 32]).unwrap(),
        1_000_000,
        50_000,
        x(1),
        x(2),
        rk,
        floor,
        deadline,
    )
    .unwrap()
}

/// A store in a directory of its own, carrying any number of jobs.
fn store(name: &str) -> (Mutex<Store>, std::path::PathBuf, Limits) {
    let dir = std::env::temp_dir().join(format!("paylock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let limits = Limits {
        max_jobs: 1_000_000,
        jobs_per_client: 0,
        ..Limits::default()
    };
    (Mutex::new(Store::open(&dir).unwrap()), dir, limits)
}

/// Mines one more Bitcoin block holding `txs` on the daemon's best branch, and a Sequentia
/// block anchoring it.
fn mine(w: &World, tag: u8, txs: &[bitcoin::Transaction]) {
    let h = {
        let mut b = w.btc.lock().unwrap();
        let best = b.best;
        let p = b.branches[best].last().unwrap().block_hash();
        b.branches[best].push(block(p, tag, txs));
        BASE - 1 + b.branches[best].len() as u32
    };
    w.seq.lock().unwrap().anchors.push(h);
}

/// F10. An attacker gives each of its jobs a receiving script of its own, pays every one
/// with one transaction, and prices every claim under the node's floor: its jobs never
/// land. Each is tried once and passed over; after that none is tried again as Bitcoin
/// blocks arrive, so a real buyer's claim is pooled in the first turns of the round after
/// its payment is anchored, with no attacker claim sent before it. Once the node's floor
/// falls below what the attacker's claims pay, they are tried again, and land.
#[test]
fn jobs_whose_claims_cannot_land_cost_a_buyer_nothing() {
    const N: u32 = 300;
    let tip = BASE + 4;
    let buyer_terms = terms_at(tip, tip + 8, 3);
    let att: Vec<PayLockTerms> = (0..N).map(|n| terms_n(BASE, tip + 7, n)).collect();
    // One transaction pays every attacker script the price, at BASE + 1.
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        1,
        &[vec![], vec![pay], vec![], vec![], vec![]],
    );
    let w = world(
        &buyer_terms,
        vec![blocks],
        vec![BASE, BASE, BASE + 2, BASE + 3, tip],
        1,
    );
    let (store, dir, limits) = store("cannot-land");
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for (n, t) in att.iter().enumerate() {
            let lock = lock_tx(t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let op = OutPoint::new(lock.txid(), 0);
            // One tier, at one atom: far under the floor.
            let c = paylock::sign_claim(
                t,
                op,
                Script::from(vec![0x51]),
                1,
                BlockHash::all_zeros(),
                &key(1),
            )
            .unwrap();
            let mut j = Job::from_request(&json!({"terms": t.to_json(),
                "lock": format!("{}:0", op.txid), "claims": [hex_encode(&serialize(&c))]}))
            .unwrap();
            j.client = format!("100.64.{}.{}", n / 250, n % 250);
            st.add(j, &limits).unwrap();
        }
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    let refused = |w: &World| w.seq.lock().unwrap().refused.len();
    // Every attacker job tried once, and passed over.
    for _ in 0..20 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        if refused(&w) >= N as usize {
            break;
        }
    }
    let first_pass = refused(&w);
    assert_eq!(first_pass, N as usize, "each attacker job is tried once");
    // Bitcoin blocks arrive, anchored: nothing is tried again.
    for tag in 0..3u8 {
        mine(&w, 100 + tag, &[]);
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let after_blocks = refused(&w) - first_pass;
    // The buyer pays: its payment is mined and anchored.
    mine(&w, 120, &[payment(&buyer_terms, 42, 0)]);
    let t0 = Instant::now();
    let before = refused(&w);
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let took = w.seq.lock().unwrap().first_pooled.map(|t| t - t0);
    let sent_before_buyer = refused(&w) - before;
    eprintln!(
        "{N} attacker jobs: first pass {first_pass} refused; then {after_blocks} tried again over 3 blocks; the buyer pooled {took:?} into its round, {sent_before_buyer} attacker claims sent in that round"
    );
    assert_eq!(
        after_blocks, 0,
        "a block arriving brings no attacker job back"
    );
    assert_eq!(
        sent_before_buyer, 0,
        "no attacker claim is sent in the buyer's round"
    );
    assert!(
        took.is_some(),
        "the buyer's claim is pooled in the round after its payment"
    );
    assert!(took.unwrap() < Duration::from_secs(2), "{took:?}");
    // The floor falls a millionfold: one atom now covers the attacker's claims, which are
    // tried again and land.
    w.seq.lock().unwrap().floor = 0;
    let pooled_before = w.seq.lock().unwrap().pooled.len();
    for _ in 0..20 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        if w.seq.lock().unwrap().pooled.len() >= pooled_before + N as usize {
            break;
        }
    }
    let landed = w.seq.lock().unwrap().pooled.len() - pooled_before;
    eprintln!("the floor fell: {landed} attacker claims landed");
    assert_eq!(landed, N as usize);
    let _ = std::fs::remove_dir_all(&dir);
}

/// F8. The service works a job in the moment Bitcoin has switched branches and Sequentia
/// has not yet rebuilt its tip on the new one: the chains disagree and the claim waits.
/// Sequentia then replaces its tip with a block of the same height, anchored on the new
/// branch at the same Bitcoin height. The tips' heights are unchanged, their blocks are
/// not: the job is worked again at once, and the claim pooled.
#[test]
fn a_tip_rebuilt_at_the_same_heights_wakes_the_job() {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let common = chain(bitcoin::BlockHash::all_zeros(), 50, &[vec![], vec![]]);
    let tip = common.last().unwrap().block_hash();
    let a = chain(tip, 60, &[vec![], vec![], vec![]]);
    let b = chain(tip, 70, &[vec![], vec![buyer.clone()], vec![]]);
    let branch = |x: &[bitcoin::Block]| common.iter().chain(x).cloned().collect::<Vec<_>>();
    let w = world(
        &t,
        vec![branch(&a), branch(&b)],
        vec![1000, 1000, 1001, 1003, 1004],
        1,
    );
    {
        // The daemon follows B; Sequentia's blocks still anchor to A.
        let mut s = w.btc.lock().unwrap();
        s.best = 1;
        s.node = 0;
    }
    let (store, dir, limits) = store("rebuilt");
    {
        let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
        j.client = "203.0.113.91".into();
        store.lock().unwrap().add(j, &limits).unwrap();
    }
    for _ in 0..2 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let note = |s: &Mutex<Store>| s.lock().unwrap().jobs.values().next().unwrap().note.clone();
    eprintln!("chains disagreeing: {}", note(&store));
    assert!(proven(&w.seq).is_none());
    // Sequentia rebuilds its blocks on B: the same heights, other blocks.
    w.btc.lock().unwrap().node = 1;
    w.seq.lock().unwrap().generation += 1;
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    eprintln!("after the rebuild: {}", note(&store));
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", note(&store));
    let _ = std::fs::remove_dir_all(&dir);
}

/// F9. A claim proving the seller's own payment is pooled, so the buyer's cancel is
/// withheld (the buyer has the asset). The claim then leaves the node's mempool, and the
/// node refuses every tier: no claim proving a payment is pooled or mined any more, so
/// the buyer's cancel is sent two blocks before the deadline.
#[test]
fn a_claim_gone_and_refused_releases_the_cancel() {
    let t = terms();
    let own = payment(&t, 9, 0);
    let buyer = payment(&t, 42, 0);
    let cancel = bitcoin::Transaction {
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat - 500),
            script_pubkey: bitcoin::ScriptBuf::from(vec![0x51]),
        }],
        ..buyer.clone()
    };
    let hex = |x: &bitcoin::Transaction| hex_encode(&bitcoin::consensus::encode::serialize(x));
    // The seller's own payment at 1001; Sequentia anchors it.
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        80,
        &[vec![], vec![own.clone()], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002], 1);
    let (store, dir, limits) = store("gone");
    {
        let j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
        let mut v = j.to_json();
        v["payments"] = json!([{"hex": hex(&buyer), "vouched": true, "by": "203.0.113.91",
            "cancels": [{"hex": hex(&cancel), "fee": 500, "vouched": true}]}]);
        let mut j = Job::from_stored(&v).unwrap();
        j.client = "203.0.113.91".into();
        store.lock().unwrap().add(j, &limits).unwrap();
    }
    for _ in 0..3 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        if proven(&w.seq).is_some() {
            break;
        }
    }
    assert_eq!(
        proven(&w.seq),
        Some(id(&own)),
        "the claim lands on the seller's own payment"
    );
    // Two blocks before the deadline (1006): the claim pooled withholds the cancel.
    mine(&w, 81, &[]);
    mine(&w, 82, &[]);
    assert_eq!(w.btc_chain.tip().unwrap(), 1004);
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    service::send_due_cancels(&store, &w.btc_chain, &w.seq_chain, &limits).unwrap();
    let cancel_sent = |w: &World| w.btc.lock().unwrap().sent.contains(&hex(&cancel));
    assert!(!cancel_sent(&w), "withheld while the claim is pooled");
    // The claim leaves the mempool, and the floor rises above every tier.
    {
        let mut s = w.seq.lock().unwrap();
        s.pooled.clear();
        s.floor = 1_000_000;
    }
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let j = store
        .lock()
        .unwrap()
        .jobs
        .values()
        .next()
        .unwrap()
        .public_json();
    eprintln!("the claim gone and refused: {} {}", j["state"], j["note"]);
    service::send_due_cancels(&store, &w.btc_chain, &w.seq_chain, &limits).unwrap();
    assert!(cancel_sent(&w), "the cancel is sent: {j}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// F10, first attempts. The attacker's jobs are posted and never tried yet when its payment
/// and the buyer's are mined in the same block. The buyer's job, which the service has
/// worked before, has something new on the chains and goes first; the attacker's jobs are
/// worked after it, and those the block cache shows priced under the floor for the proof
/// their payment makes after the rest. So the buyer's claim is sent before any attacker's.
#[test]
fn jobs_never_tried_go_after_the_buyer_when_their_claims_are_under_the_floor() {
    const N: u32 = 300;
    let tip = BASE + 4;
    // The buyer's floor as low as the attacker's: the blocks between are read already, so
    // every attacker job reaches its payment's block by the cache, as on a running service.
    let buyer_terms = terms_at(BASE, tip + 8, 3);
    let att: Vec<PayLockTerms> = (0..N).map(|n| terms_n(BASE, tip + 7, n)).collect();
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
    let blocks = chain(bitcoin::BlockHash::all_zeros(), 1, &vec![vec![]; 5]);
    let w = world(
        &buyer_terms,
        vec![blocks],
        vec![BASE, BASE, BASE + 2, BASE + 3, tip],
        1,
    );
    let (store, dir, limits) = store("first-attempts");
    {
        let mut st = store.lock().unwrap();
        let s = w.seq.lock().unwrap();
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    // The service has been running: the buyer's job is worked and the blocks are read.
    for _ in 0..2 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    // The attacker's jobs are posted, and not tried yet when both payments are mined.
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for (n, t) in att.iter().enumerate() {
            let lock = lock_tx(t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let op = OutPoint::new(lock.txid(), 0);
            let c = paylock::sign_claim(
                t,
                op,
                Script::from(vec![0x51]),
                1,
                BlockHash::all_zeros(),
                &key(1),
            )
            .unwrap();
            let mut j = Job::from_request(&json!({"terms": t.to_json(),
                "lock": format!("{}:0", op.txid), "claims": [hex_encode(&serialize(&c))]}))
            .unwrap();
            j.client = format!("100.64.{}.{}", n / 250, n % 250);
            st.add(j, &limits).unwrap();
        }
    }
    mine(&w, 130, &[pay, payment(&buyer_terms, 42, 0)]);
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let s = w.seq.lock().unwrap();
    eprintln!(
        "{N} attacker jobs never tried, paid in the buyer's block: the buyer pooled after {:?} attacker refusals; {} refused in the round",
        s.refused_before_pooled,
        s.refused.len()
    );
    assert!(
        s.first_pooled.is_some(),
        "the buyer's claim is pooled in the round"
    );
    assert_eq!(
        s.refused_before_pooled,
        Some(0),
        "the buyer's claim is sent first"
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refusal valued at zero. The fee asset's rate falls (or, at the normal rate, the
/// node's floor rises a thousandfold), so the node refuses every tier of the buyer's
/// claim; at a rate of 1 its message values the 1,000- and 50,000-atom fees at `0`. Once
/// the rate and the floor are back, the claim lands, whatever figure the refusal gave:
/// the service judges by the claim's own signed fee, never by the node's rounded worth.
#[test]
fn a_claim_refused_at_any_rate_lands_once_the_floor_allows_it() {
    for low in [1u64, 100_000, 100_000_000] {
        let t = terms();
        let buyer = payment(&t, 42, 0);
        let blocks = chain(
            bitcoin::BlockHash::all_zeros(),
            10,
            &[vec![], vec![buyer.clone()], vec![], vec![]],
        );
        let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
        {
            let mut s = w.seq.lock().unwrap();
            if low < 100_000_000 {
                s.rate = low;
            } else {
                s.floor *= 1_000;
            }
        }
        let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
        let r = tick(&w, &mut j);
        let v = j.public_json();
        let refused = w.seq.lock().unwrap().refused.clone();
        eprintln!("rate {low}: {r:?}; {}; refused {refused:?}", v["note"]);
        assert!(proven(&w.seq).is_none());
        assert!(
            v["note"].as_str().unwrap().contains("refuses every claim"),
            "{}",
            v["note"]
        );
        {
            let mut s = w.seq.lock().unwrap();
            s.rate = 100_000_000;
            s.floor = 1_000;
        }
        let mut outcome = vec![];
        for _ in 0..3 {
            outcome.push(tick(&w, &mut j));
            if proven(&w.seq).is_some() {
                break;
            }
        }
        let v = j.public_json();
        eprintln!("rate {low}, then back: {outcome:?}; {}", v["note"]);
        assert_eq!(
            proven(&w.seq),
            Some(id(&buyer)),
            "refused at rate {low}, the claim never came back: {}",
            v["note"]
        );
        assert_eq!(v["state"], "pooled");
    }
}

/// A refusal that gives no figures (`mempool full`) says nothing of the floor the claim
/// needs. Once the floors change at all (here the relay floor rises a little as the
/// mempool clears), the claim is tried again, and lands.
#[test]
fn a_refusal_without_figures_is_tried_again_when_the_floors_change() {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        11,
        &[vec![], vec![buyer.clone()], vec![], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
    w.seq.lock().unwrap().full = true;
    let mut j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    let r = tick(&w, &mut j);
    eprintln!("mempool full: {r:?}; {}", j.public_json()["note"]);
    assert!(proven(&w.seq).is_none());
    // The same floors: not tried again.
    let n = w.seq.lock().unwrap().refused.len();
    let _ = tick(&w, &mut j);
    assert_eq!(
        w.seq.lock().unwrap().refused.len(),
        n,
        "tried again at the same floors"
    );
    {
        let mut s = w.seq.lock().unwrap();
        s.full = false;
        s.floor = 1_001;
    }
    let mut outcome = vec![];
    for _ in 0..3 {
        outcome.push(tick(&w, &mut j));
        if proven(&w.seq).is_some() {
            break;
        }
    }
    let v = j.public_json();
    eprintln!("then the floors moved: {outcome:?}; {}", v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
}

/// Jobs on `n` receiving scripts of their own, each paid by one output of one transaction
/// mined at `BASE + 1`, each with claims of 1,000 and `top` atoms; and the buyer's job,
/// whose payment is mined at `BASE + 2`. The store holds them all.
fn retry_world(
    n: u32,
    top: u64,
    name: &str,
) -> (
    World,
    Mutex<Store>,
    std::path::PathBuf,
    Limits,
    PayLockTerms,
) {
    let tip = BASE + 3;
    let buyer_terms = terms_at(BASE, tip + 8, 3);
    let att: Vec<PayLockTerms> = (0..n).map(|i| terms_n(BASE, tip + 7, i)).collect();
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        1,
        &[
            vec![],
            vec![pay],
            vec![payment(&buyer_terms, 42, 0)],
            vec![],
        ],
    );
    let w = world(
        &buyer_terms,
        vec![blocks],
        vec![BASE, BASE, BASE + 2, tip],
        1,
    );
    let (store, dir, limits) = store(name);
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for (i, t) in att.iter().enumerate() {
            let lock = lock_tx(t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let mut j = job_with(t, &lock, None, top);
            j.client = format!("100.64.{}.{}", i / 250, i % 250);
            st.add(j, &limits).unwrap();
        }
    }
    (w, store, dir, limits, buyer_terms)
}

/// An oscillating floor, the order. The fee asset's rate falls a thousandfold, and
/// every claim is refused: the attacker's many, then the buyer's, worked last. When the
/// rate is back, every one of them may land, and the claims that clear the node's ask by
/// the most go first: the buyer's, whose fee covers its small proof a hundred times, before
/// the attacker's, whose fees barely cover the big proof their shared payment makes. To go
/// first, an attacker must pay more, and then its claims land and leave.
#[test]
fn claims_that_may_land_again_go_by_how_far_they_clear() {
    const N: u32 = 100;
    let (w, store, dir, limits, buyer_terms) = retry_world(N, 20_000, "clears-first");
    w.seq.lock().unwrap().rate = 100_000;
    for _ in 0..5 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let refused = w.seq.lock().unwrap().refused.len();
    assert!(refused >= 2 * N as usize, "{refused}");
    // The buyer's job comes now, and is refused alone: it was worked last.
    {
        let mut st = store.lock().unwrap();
        let s = w.seq.lock().unwrap();
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    assert!(w.seq.lock().unwrap().pooled.is_empty());
    w.seq.lock().unwrap().rate = 100_000_000;
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let s = w.seq.lock().unwrap();
    let buyer_ids: Vec<String> = store
        .lock()
        .unwrap()
        .jobs
        .values()
        .filter(|j| j.terms.receive_script_pubkey() == buyer_terms.receive_script_pubkey())
        .flat_map(|j| {
            j.claims
                .iter()
                .map(|c| c.txid().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    let at = s.order.iter().position(|t| buyer_ids.contains(t));
    eprintln!(
        "the rate back: {} claims pooled; the buyer's at place {at:?}",
        s.order.len()
    );
    assert_eq!(
        at,
        Some(0),
        "the buyer's claim waited behind {:?} others",
        at
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An oscillating floor, the delay. A round is busy retrying the attacker's claims
/// (each answer takes the node 30 ms) when the buyer's payment is mined and anchored. The
/// round ends its background work at the next look at the chains, and the next round
/// pools the buyer's claim: well under the three seconds the retries take.
#[test]
fn a_buyer_mined_during_background_retries_is_not_kept_behind_them() {
    const N: u32 = 100;
    let tip = BASE + 3;
    let buyer_terms = terms_at(BASE, tip + 8, 3);
    let att: Vec<PayLockTerms> = (0..N).map(|i| terms_n(BASE, tip + 7, i)).collect();
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        1,
        &[vec![], vec![pay], vec![], vec![]],
    );
    let w = world(
        &buyer_terms,
        vec![blocks],
        vec![BASE, BASE, BASE + 2, tip],
        1,
    );
    let (store, dir, mut limits) = store("background-moves");
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for (i, t) in att.iter().enumerate() {
            let lock = lock_tx(t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let mut j = job_with(t, &lock, None, 20_000);
            j.client = format!("100.64.{}.{}", i / 250, i % 250);
            st.add(j, &limits).unwrap();
        }
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
        s.rate = 100_000;
    }
    for _ in 0..5 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    assert!(w.seq.lock().unwrap().pooled.is_empty());
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 100_000_000;
        s.send_delay = Duration::from_millis(30);
    }
    limits.round_time = Duration::from_secs(20);
    limits.job_time = Duration::from_secs(5);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = {
        let (store, stop) = (Arc::new(store), stop.clone());
        let (seq, btc) = (
            SeqChain {
                rpc: rpc(&w.seq_url),
            },
            BtcChain {
                rpc: rpc(&w.btc_url),
            },
        );
        let limits = limits.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                service::work_round(&store, &seq, &btc, &limits);
            }
        })
    };
    // Retries under way; then the buyer's payment is mined and anchored.
    std::thread::sleep(Duration::from_millis(400));
    let busy = w.seq.lock().unwrap().order.len();
    mine(&w, 120, &[payment(&buyer_terms, 42, 0)]);
    let t0 = Instant::now();
    let buyer_script = buyer_terms.receive_script_pubkey();
    let mut took = None;
    while t0.elapsed() < Duration::from_secs(15) {
        let s = w.seq.lock().unwrap();
        if proven_by(&s, &buyer_script) {
            took = Some(t0.elapsed());
            break;
        }
        drop(s);
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    worker.join().unwrap();
    let retried = w.seq.lock().unwrap().order.len();
    eprintln!(
        "{busy} attacker claims retried before the buyer's block; the buyer pooled {took:?} after it was anchored; {retried} claims pooled in all"
    );
    assert!(
        busy < N as usize,
        "the retries were over before the buyer's block"
    );
    let took = took.expect("the buyer's claim was pooled");
    assert!(
        took < Duration::from_millis(1_500),
        "the buyer waited {took:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Whether a claim pooled proves a payment to `script`.
fn proven_by(s: &Seq, script: &bitcoin::ScriptBuf) -> bool {
    s.pooled.values().any(|tx| {
        let Some(r) = tx.input[0].witness.pegin_witness.first() else {
            return false;
        };
        let depth = r[121] as usize;
        let at = 126 + 64 * depth;
        let links = u16::from_le_bytes([r[at], r[at + 1]]) as usize;
        bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&r[at + 2 + 80 * links..])
            .map(|p| p.output.iter().any(|o| &o.script_pubkey == script))
            .unwrap_or(false)
    })
}

/// F11. 1,500 attacker jobs, each on a receiving script of its own and passed over
/// once (claims at one atom against a shared payment's heavy proof). Then one block holds
/// 1,500 small transactions, each paying one attacker script dust, and the buyer's
/// payment: every attacker job is hit by it. Each hit job reads only the transactions
/// that touch it, from the block's index, so working them all is linear in the block,
/// not a pass over the whole block for each job.
#[test]
fn jobs_hit_by_one_block_read_only_their_own_transactions() {
    const N: u32 = 1_500;
    let tip = BASE + 3;
    let buyer_terms = terms_at(BASE, tip + 8, 3);
    let att: Vec<PayLockTerms> = (0..N).map(|i| terms_n(BASE, tip + 7, i)).collect();
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        1,
        &[vec![], vec![pay], vec![], vec![]],
    );
    let w = world(
        &buyer_terms,
        vec![blocks],
        vec![BASE, BASE, BASE + 2, tip],
        1,
    );
    let (store, dir, mut limits) = store("hit-block");
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for (i, t) in att.iter().enumerate() {
            let lock = lock_tx(t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let op = OutPoint::new(lock.txid(), 0);
            let c = paylock::sign_claim(
                t,
                op,
                Script::from(vec![0x51]),
                1,
                BlockHash::all_zeros(),
                &key(1),
            )
            .unwrap();
            let mut j = Job::from_request(&json!({"terms": t.to_json(),
                "lock": format!("{}:0", op.txid), "claims": [hex_encode(&serialize(&c))]}))
            .unwrap();
            j.client = format!("100.64.{}.{}", i / 250, i % 250);
            st.add(j, &limits).unwrap();
        }
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    limits.round_time = Duration::from_secs(120);
    for _ in 0..20 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        if w.seq.lock().unwrap().refused.len() >= N as usize {
            break;
        }
    }
    assert!(w.seq.lock().unwrap().refused.len() >= N as usize);
    // One block: dust to every attacker script, each from a coin of its own, then the
    // buyer's payment.
    let mut txs: Vec<bitcoin::Transaction> = att
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut d = payment(t, 0, 0);
            d.input[0].previous_output.txid = bitcoin::Txid::from_byte_array({
                let mut b = [0x77u8; 32];
                b[..4].copy_from_slice(&(i as u32).to_le_bytes());
                b
            });
            d.output[0].value = bitcoin::Amount::from_sat(330);
            d
        })
        .collect();
    txs.push(payment(&buyer_terms, 42, 0));
    mine(&w, 130, &txs);
    let t0 = Instant::now();
    let mut worked = 0;
    let buyer_script = buyer_terms.receive_script_pubkey();
    let mut buyer = None;
    while t0.elapsed() < Duration::from_secs(300) && worked < N as usize + 1 {
        worked += service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        if buyer.is_none() && proven_by(&w.seq.lock().unwrap(), &buyer_script) {
            buyer = Some(t0.elapsed());
        }
    }
    let took = t0.elapsed();
    eprintln!(
        "{N} attacker jobs hit by one block of {} transactions: {worked} jobs worked in {took:?}; the buyer pooled after {buyer:?}",
        N + 2
    );
    assert!(buyer.is_some(), "the buyer's claim was pooled");
    assert!(
        took < Duration::from_secs(20),
        "working the hit jobs took {took:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An oscillating floor, as a regtest run traced it: the attacker's claims landed in a
/// dip of the floor and are pooled, so every new block asks the service to look at each
/// of them again (to raise a claim a block left out). The buyer's payment is mined and
/// anchored in such a block: a claim must be made for it, and that goes before the upkeep
/// of claims already pooled, however many there are.
#[test]
fn a_buyer_goes_before_the_upkeep_of_claims_already_pooled() {
    const N: u32 = 100;
    let (w, store, dir, limits, buyer_terms) = retry_world(N, 20_000, "upkeep-after");
    // The buyer's payment is not mined yet: the world's block at BASE + 2 is replaced by
    // an empty one, and its payment comes later.
    {
        let mut b = w.btc.lock().unwrap();
        let p = b.branches[0][1].block_hash();
        b.branches[0][2] = block(p, 77, &[]);
        let p = b.branches[0][2].block_hash();
        b.branches[0][3] = block(p, 78, &[]);
    }
    // A floor low enough for the going tier (1,000 atoms) to carry the attacker's proofs:
    // its claims are pooled at the going tier, and a block that leaves them out raises them.
    w.seq.lock().unwrap().floor = 200;
    for _ in 0..5 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let landed = w.seq.lock().unwrap().order.len();
    assert!(
        landed >= N as usize,
        "the attacker's claims are pooled: {landed}"
    );
    {
        let mut st = store.lock().unwrap();
        let s = w.seq.lock().unwrap();
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    mine(&w, 140, &[payment(&buyer_terms, 42, 0)]);
    let before = w.seq.lock().unwrap().order.len();
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let s = w.seq.lock().unwrap();
    let buyer_script = buyer_terms.receive_script_pubkey();
    let after: Vec<&String> = s.order[before..].iter().collect();
    let at = after.iter().position(|t| {
        s.pooled
            .get(*t)
            .map(|tx| {
                let one = Seq {
                    pooled: [((*t).clone(), tx.clone())].into(),
                    ..seq_like(&s)
                };
                proven_by(&one, &buyer_script)
            })
            .unwrap_or(false)
    });
    eprintln!(
        "{landed} attacker claims pooled; in the buyer's round {} claims were sent, the buyer's at {at:?}",
        after.len()
    );
    assert!(
        after.len() > N as usize / 2,
        "the attacker's claims were raised in that round"
    );
    assert_eq!(
        at,
        Some(0),
        "the buyer waited behind the upkeep of {:?} claims",
        at
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty node state shaped like `s`, to ask [`proven_by`] about one claim.
fn seq_like(s: &Seq) -> Seq {
    Seq {
        anchors: vec![],
        lock: s.lock.clone(),
        locks: HashMap::new(),
        pooled: HashMap::new(),
        floor: s.floor,
        rate: s.rate,
        full: false,
        send_delay: Duration::ZERO,
        order: vec![],
        fee_asset: s.fee_asset,
        generation: 0,
        refused: vec![],
        first_pooled: None,
        refused_before_pooled: None,
    }
}
