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
            _ => Err((-32601, "Method not found".into())),
        }
    }))
}

/// The Sequentia node: blocks 0 to 5 anchored at these Bitcoin heights (of the branch it
/// follows), the lock mined in block 1; claims it pools; and its relay floor: a claim is
/// refused unless its fee covers its proof's bytes divided by `per_atom`.
struct Seq {
    anchors: Vec<u32>,
    lock: Transaction,
    pooled: HashMap<String, Transaction>,
    per_atom: usize,
    refused: Vec<String>,
    first_pooled: Option<Instant>,
}

fn fake_seq(state: Arc<Mutex<Seq>>, btc: Arc<Mutex<Btc>>) -> String {
    let hash = |h: u64| format!("{:064x}", 0x5e9_0000 + h);
    fake_node(Box::new(move |m, p| {
        let mut s = state.lock().unwrap();
        let lock_id = s.lock.txid().to_string();
        match m {
            "getblockcount" => Ok(json!(s.anchors.len() - 1)),
            "getblockhash" => Ok(json!(hash(p[0].as_u64().unwrap()))),
            "getblockheader" => {
                let h = (u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap() - 0x5e9_0000)
                    as usize;
                let a = s.anchors[h];
                let b = btc.lock().unwrap();
                let anchor = b.branches[b.node][(a - BASE) as usize]
                    .block_hash()
                    .to_string();
                Ok(
                    json!({"height": h, "confirmations": 1, "anchorheight": a, "anchorhash": anchor}),
                )
            }
            "getrawtransaction" if p[0].as_str() == Some(&lock_id) => {
                Ok(json!({"hex": hex_encode(&serialize(&s.lock)), "blockhash": hash(1)}))
            }
            "getrawtransaction" => match s.pooled.get(p[0].as_str().unwrap_or_default()) {
                Some(tx) => Ok(json!({"hex": hex_encode(&serialize(tx))})),
                None => Err((-5, "No such mempool or blockchain transaction".into())),
            },
            "getposfinality" => Ok(json!({"finalized_height": 0})),
            "gettxout" => Ok(json!({"value": 1})),
            "getfeeassetinfo" => {
                let mut m = serde_json::Map::new();
                m.insert(
                    p[0].as_str().unwrap().to_string(),
                    json!({"accepted": true, "rate": 100_000_000}),
                );
                Ok(Value::Object(m))
            }
            "sendrawtransaction" => {
                let tx: Transaction =
                    deserialize(&hex_decode(p[0].as_str().unwrap()).unwrap()).unwrap();
                let record = tx.input[0]
                    .witness
                    .pegin_witness
                    .first()
                    .map(Vec::len)
                    .unwrap_or(0);
                let fee = paylock::fee_of(&tx).map(|f| f.1).unwrap_or(0) as usize;
                let need = record / s.per_atom;
                if fee < need {
                    let m = format!("min relay fee not met, {fee} < {need}");
                    s.refused.push(m.clone());
                    return Err((-26, m));
                }
                s.pooled.insert(tx.txid().to_string(), tx.clone());
                s.first_pooled.get_or_insert_with(Instant::now);
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
}

fn world(
    t: &PayLockTerms,
    branches: Vec<Vec<bitcoin::Block>>,
    anchors: Vec<u32>,
    per_atom: usize,
) -> World {
    let btc = Arc::new(Mutex::new(Btc {
        branches,
        ..Default::default()
    }));
    let seq = Arc::new(Mutex::new(Seq {
        anchors,
        lock: lock_tx(t),
        pooled: HashMap::new(),
        per_atom,
        refused: vec![],
        first_pooled: None,
    }));
    let (su, bu) = (fake_seq(seq.clone(), btc.clone()), fake_btc(btc.clone()));
    World {
        seq,
        btc,
        seq_chain: SeqChain { rpc: rpc(&su) },
        btc_chain: BtcChain { rpc: rpc(&bu) },
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
