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
/// chain the first time a proof reads the block named (its ids, or its second whole read:
/// the scan reads it whole first).
#[derive(Default)]
struct Btc {
    branches: Vec<Vec<bitcoin::Block>>,
    best: usize,
    node: usize,
    switch_on_proof: Option<(String, usize)>,
    fetched: u64,
    /// Calls that read a block whole (`getblock`, at any verbosity, and
    /// `getrawtransaction`, which reads the block it is given).
    block_reads: u64,
    /// Reads of the block `switch_on_proof` names, so far.
    switch_reads: u32,
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
                s.block_reads += 1;
                let b = by(&p[0]).ok_or((-5, "Block not found".to_string()))?;
                let raw = p[1].as_u64() == Some(0);
                // The proof's read of the block: the scan reads it whole first, so the
                // proof's is its second whole read, or a read of its ids.
                if let Some((h, to)) = s.switch_on_proof.clone() {
                    if p[0].as_str() == Some(h.as_str()) {
                        s.switch_reads += 1;
                        if !raw || s.switch_reads >= 2 {
                            s.best = to;
                            s.switch_on_proof = None;
                        }
                    }
                }
                if raw {
                    s.fetched += 1;
                    return Ok(json!(hex_encode(&bitcoin::consensus::encode::serialize(
                        &b
                    ))));
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
                s.block_reads += 1;
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
    /// Once this many claims are refused in all, the fee asset's rate becomes the second
    /// figure: a rate that moves between a refusal and the read after it.
    rate_after: Option<(usize, u64)>,
    /// More such changes, in order: once that many claims are refused in all, the rate.
    rates_after: Vec<(usize, u64)>,
    /// Refuses as `mempool full` every claim paying at least this many atoms (0: none).
    full_from: u64,
    /// Another accepted fee asset's rate, reported beside the fee asset's (0: none).
    other_rate: u64,
    /// How long it takes to answer `getposfinality`, which every job's work asks first.
    tick_delay: Duration,
    /// How many claims it had refused when it first pooled one.
    refused_before_pooled: Option<usize>,
    /// `sendrawtransaction`'s fee ceiling, in what a fee is worth (0: none): a claim the
    /// node would take, worth more, is refused unless sent with `maxfeerate` 0.
    max_fee: usize,
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
                let n = u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap() - 0x5e9_0000;
                let h = (n & 0xffff_ffff) as usize;
                // A block of another generation, or above the tip, is not on the best chain.
                let confirmations = if n >> 32 == s.generation && h < s.anchors.len() {
                    (s.anchors.len() - h) as i64
                } else {
                    -1
                };
                if h >= s.anchors.len() {
                    return Err((-5, "Block not found".into()));
                }
                let a = s.anchors[h];
                let b = btc.lock().unwrap();
                let anchor = b.branches[b.node][(a - BASE) as usize]
                    .block_hash()
                    .to_string();
                Ok(
                    json!({"height": h, "confirmations": confirmations, "anchorheight": a, "anchorhash": anchor}),
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
            "getposfinality" => {
                if !s.tick_delay.is_zero() {
                    let d = s.tick_delay;
                    drop(s);
                    std::thread::sleep(d);
                }
                Ok(json!({"finalized_height": 0}))
            }
            "gettxout" => Ok(json!({"value": 1})),
            "getfeeassetinfo" => {
                let mut m = serde_json::Map::new();
                let asset = p[0]
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| s.fee_asset.to_string());
                m.insert(asset, json!({"accepted": true, "rate": s.rate}));
                if s.other_rate > 0 {
                    m.insert(
                        AssetId::from_slice(&[7; 32]).unwrap().to_string(),
                        json!({"accepted": true, "rate": s.other_rate}),
                    );
                }
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
                let refusal = if s.full_from > 0 && atoms >= s.full_from {
                    Some("mempool full".to_string())
                } else {
                    (fee < need).then(|| format!("min relay fee not met, {fee} < {need}"))
                };
                let capped = s.max_fee > 0 && p.get(1).and_then(Value::as_f64) != Some(0.0);
                if refusal.is_none() && capped && fee > s.max_fee {
                    let m = "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)";
                    s.refused.push(m.into());
                    return Err((-25, m.into()));
                }
                if let Some(m) = refusal {
                    s.refused.push(m.clone());
                    if let Some((n, r)) = s.rate_after {
                        if s.refused.len() >= n {
                            s.rate = r;
                            s.rate_after = None;
                        }
                    }
                    while let Some(&(n, r)) = s.rates_after.first() {
                        if s.refused.len() < n {
                            break;
                        }
                        s.rate = r;
                        s.rates_after.remove(0);
                    }
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
        rate_after: None,
        rates_after: vec![],
        full_from: 0,
        other_rate: 0,
        tick_delay: Duration::ZERO,
        refused_before_pooled: None,
        max_fee: 0,
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
        rate_after: None,
        rates_after: vec![],
        full_from: 0,
        other_rate: 0,
        tick_delay: Duration::ZERO,
        refused_before_pooled: None,
        max_fee: 0,
    }
}

/// K jobs on receiving scripts of their own, each paid in one block by a transaction of its
/// own, with claims at one atom: each is tried once, and each try builds a proof of a
/// payment in that block. The block is read once for all of them, never once a proof: the
/// reads stay flat as K grows.
#[test]
fn proofs_of_payments_in_one_block_read_it_once() {
    let mut reads = vec![];
    for k in [40u32, 160] {
        let tip = BASE + 3;
        let att: Vec<PayLockTerms> = (0..k).map(|i| terms_n(BASE, tip + 7, 10_000 + i)).collect();
        let pays: Vec<bitcoin::Transaction> = att
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let mut p = payment(t, 0, 0);
                p.input[0].previous_output.txid = bitcoin::Txid::from_byte_array({
                    let mut b = [0x55u8; 32];
                    b[..4].copy_from_slice(&(i as u32).to_le_bytes());
                    b
                });
                p
            })
            .collect();
        let blocks = chain(
            bitcoin::BlockHash::all_zeros(),
            1,
            &[vec![], vec![], vec![], vec![]],
        );
        let w = world(&att[0], vec![blocks], vec![BASE, BASE, BASE + 2, tip], 1);
        let (store, dir, mut limits) = store(&format!("proof-reads-{k}"));
        limits.round_time = Duration::from_secs(120);
        {
            let mut st = store.lock().unwrap();
            let mut s = w.seq.lock().unwrap();
            for t in &att {
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
                let j = Job::from_request(&json!({"terms": t.to_json(),
                    "lock": format!("{}:0", op.txid), "claims": [hex_encode(&serialize(&c))]}))
                .unwrap();
                st.add(j, &limits).unwrap();
            }
        }
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
        mine(&w, 150, &pays);
        let before = w.btc.lock().unwrap().block_reads;
        for _ in 0..10 {
            service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
            if w.seq.lock().unwrap().refused.len() >= k as usize {
                break;
            }
        }
        let tried = w.seq.lock().unwrap().refused.len();
        let n = w.btc.lock().unwrap().block_reads - before;
        eprintln!("{k} claims proving payments in one block: {tried} tried, {n} block reads");
        assert_eq!(tried, k as usize);
        reads.push(n);
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        reads[1] <= reads[0] + 2 && reads[1] <= 6,
        "block reads grow with the claims: {reads:?}"
    );
}

/// The upkeep of claims already pooled is background too: a round raising the attacker's
/// many pooled claims (each answer takes the node 30 ms) when the buyer's payment is mined
/// and anchored ends at the next look at the chains, and the next round pools the buyer's
/// claim, well under the three seconds the raises take.
#[test]
fn a_buyer_mined_during_the_upkeep_of_pooled_claims_is_not_kept_behind_it() {
    const N: u32 = 100;
    let (w, store, dir, mut limits, buyer_terms) = retry_world(N, 20_000, "upkeep-moves");
    {
        let mut b = w.btc.lock().unwrap();
        let p = b.branches[0][1].block_hash();
        b.branches[0][2] = block(p, 77, &[]);
        let p = b.branches[0][2].block_hash();
        b.branches[0][3] = block(p, 78, &[]);
    }
    w.seq.lock().unwrap().floor = 200;
    for _ in 0..5 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    assert!(w.seq.lock().unwrap().order.len() >= N as usize);
    {
        let mut st = store.lock().unwrap();
        let s = w.seq.lock().unwrap();
        let mut j = job(&buyer_terms, &s.lock.clone(), None);
        j.client = "203.0.113.91".into();
        st.add(j, &limits).unwrap();
    }
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    // A block that leaves every pooled claim out: each is raised, slowly.
    w.seq.lock().unwrap().send_delay = Duration::from_millis(30);
    mine(&w, 141, &[]);
    limits.round_time = Duration::from_secs(20);
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
    std::thread::sleep(Duration::from_millis(400));
    let busy = w.seq.lock().unwrap().order.len();
    mine(&w, 142, &[payment(&buyer_terms, 42, 0)]);
    let t0 = Instant::now();
    let script = buyer_terms.receive_script_pubkey();
    let mut took = None;
    while t0.elapsed() < Duration::from_secs(15) {
        if proven_by(&w.seq.lock().unwrap(), &script) {
            took = Some(t0.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    worker.join().unwrap();
    let all = w.seq.lock().unwrap().order.len();
    eprintln!(
        "{} raises sent before the buyer's block; the buyer pooled {took:?} after it was anchored; {all} claims pooled in all",
        busy.saturating_sub(N as usize)
    );
    let took = took.expect("the buyer's claim was pooled");
    assert!(
        took < Duration::from_millis(1_500),
        "the buyer waited {took:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A buyer's world: its payment mined at `BASE + 1` and anchored, the node at the usual
/// floors; and its job.
fn buyer_world() -> (World, Job, bitcoin::Transaction) {
    let t = terms();
    let buyer = payment(&t, 42, 0);
    let blocks = chain(
        bitcoin::BlockHash::all_zeros(),
        11,
        &[vec![], vec![buyer.clone()], vec![], vec![]],
    );
    let w = world(&t, vec![blocks], vec![1000, 1000, 1001, 1002, 1003], 1);
    let j = job(&t, &w.seq.lock().unwrap().lock.clone(), None);
    (w, j, buyer)
}

/// Ticks `j` until its claim is pooled, at most `n` times; the claims refused meanwhile.
fn until_pooled(w: &World, j: &mut Job, n: usize) -> usize {
    let before = w.seq.lock().unwrap().refused.len();
    for _ in 0..n {
        let _ = tick(w, j);
        if proven(&w.seq).is_some() {
            break;
        }
    }
    w.seq.lock().unwrap().refused.len() - before
}

/// The before/after race. The fee asset's rate is 1 when the claims are sent (each refused, its
/// fee read as worth 0), and back to 1:1 a moment later, when the service reads the floors
/// again. The reading that refused the claims is not known, so they are tried again at the
/// next reading, which is the later one, and land. A record that took the later read as
/// the one that refused it would wait for another change that never comes.
#[test]
fn a_rate_that_moves_while_the_claims_are_refused_brings_them_back() {
    let (w, mut j, buyer) = buyer_world();
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 1;
        s.rate_after = Some((2, 100_000_000));
    }
    let r = tick(&w, &mut j);
    let refused = w.seq.lock().unwrap().refused.clone();
    eprintln!(
        "race: {r:?}; refused {refused:?}; {}",
        j.public_json()["note"]
    );
    assert_eq!(refused.len(), 2, "both tiers refused at rate 1");
    assert!(proven(&w.seq).is_none());
    assert_eq!(w.seq.lock().unwrap().rate, 100_000_000);
    // Nothing else changes from here on.
    until_pooled(&w, &mut j, 3);
    assert_eq!(
        proven(&w.seq),
        Some(id(&buyer)),
        "refused while the rate moved, the claim never came back: {}",
        j.public_json()["note"]
    );
}

/// Every way the floors can change brings a refused claim back, and it lands once its fee
/// clears: the fee asset's rate rising, the relay floor falling, a partial change (the top
/// tier clears, the going tier does not), a change elsewhere in the reading only (another
/// asset's rate: tried once, refused, and not again), and an oscillation between refusing
/// rates, back to readings seen before, that ends where the claim clears. Each change is
/// one try; at an unchanged reading nothing is sent.
#[test]
fn a_refused_claim_comes_back_at_any_change_of_the_floors() {
    type Step = fn(&mut Seq);
    let cases: Vec<(&str, Step, Vec<Step>)> = vec![
        ("rise", |s| s.rate = 100_000, vec![|s| s.rate = 100_000_000]),
        ("fall", |s| s.floor *= 1_000, vec![|s| s.floor = 1_000]),
        (
            "partial",
            |s| s.rate = 100_000,
            vec![|s| s.rate = 1_000_000],
        ),
        (
            "elsewhere, then the rate",
            |s| s.rate = 100_000,
            vec![|s| s.other_rate = 5, |s| s.rate = 100_000_000],
        ),
        (
            "oscillation",
            |s| s.rate = 1,
            vec![
                |s| s.rate = 100_000,
                |s| s.rate = 1,
                |s| s.rate = 100_000,
                |s| s.rate = 1,
                |s| s.rate = 100_000_000,
            ],
        ),
    ];
    for (name, refuse, steps) in cases {
        let (w, mut j, buyer) = buyer_world();
        refuse(&mut w.seq.lock().unwrap());
        let _ = tick(&w, &mut j);
        assert!(proven(&w.seq).is_none(), "{name}");
        // The same reading: nothing sent.
        assert_eq!(
            until_pooled(&w, &mut j, 2),
            0,
            "{name}: tried again unchanged"
        );
        let mut sent = vec![];
        for (i, step) in steps.iter().enumerate() {
            step(&mut w.seq.lock().unwrap());
            sent.push(until_pooled(&w, &mut j, 1));
            if proven(&w.seq).is_some() {
                break;
            }
            // Refused again at the new reading: not tried again while it holds.
            assert_eq!(until_pooled(&w, &mut j, 2), 0, "{name}: step {i} looped");
        }
        let v = j.public_json();
        eprintln!("{name}: refusals per change {sent:?}; {}", v["note"]);
        assert_eq!(proven(&w.seq), Some(id(&buyer)), "{name}: {}", v["note"]);
        assert_eq!(v["state"], "pooled", "{name}");
    }
}

/// A tier refused without figures. The going tier is refused with figures, the top tier
/// `mempool full`, without. Each tier keeps its own record, so when the mempool clears
/// and the rate rises enough for the top tier but not the going one, the claim is tried
/// again and lands at the top tier. Judged by the going tier's record alone it would wait
/// for a rise that clears the going tier.
#[test]
fn a_tier_refused_without_figures_keeps_its_own_record() {
    let (w, mut j, buyer) = buyer_world();
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 100_000;
        s.full_from = 50_000;
    }
    let _ = tick(&w, &mut j);
    let refused = w.seq.lock().unwrap().refused.clone();
    eprintln!("refused {refused:?}");
    assert!(refused.iter().any(|m| m == "mempool full"));
    assert!(refused
        .iter()
        .any(|m| m.starts_with("min relay fee not met")));
    {
        let mut s = w.seq.lock().unwrap();
        s.full_from = 0;
        s.rate = 1_000_000;
    }
    until_pooled(&w, &mut j, 3);
    let v = j.public_json();
    eprintln!("then: {}", v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert!(
        v["note"].as_str().unwrap().contains("top tier"),
        "{}",
        v["note"]
    );
}

/// A reorganization of Sequentia (its blocks rebuilt at the same heights) brings a
/// refused claim back, as one of Bitcoin does, even at an unchanged reading of the floors.
#[test]
fn a_sequentia_reorganization_brings_a_refused_claim_back() {
    let (w, j, _) = buyer_world();
    let (store, dir, limits) = store("seq-reorg");
    store.lock().unwrap().add(j, &limits).unwrap();
    w.seq.lock().unwrap().rate = 1;
    for _ in 0..3 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let n = w.seq.lock().unwrap().refused.len();
    assert!(n >= 2, "{n}");
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    assert_eq!(
        w.seq.lock().unwrap().refused.len(),
        n,
        "tried again unchanged"
    );
    w.seq.lock().unwrap().generation += 1;
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let m = w.seq.lock().unwrap().refused.len();
    eprintln!("refusals: {n} before the reorganization, {m} after");
    assert!(m > n, "not tried again after Sequentia reorganized");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retries starved by intake. 300 jobs are changed by intake
/// all through the round (new cancels posted to each, as a flood does), and each takes the
/// node 40 ms to work, 12 s in all, past the round's 10 s. The fee asset's rate is back
/// after refusing the buyer's claim. Retries and intake take turns, a retry first, so the
/// buyer's claim is pooled in that very round, in its first turns.
#[test]
fn a_refused_buyer_is_retried_within_a_round_of_an_intake_flood() {
    const N: u32 = 300;
    let (w, j, buyer) = buyer_world();
    let tip = 1_003;
    let (store, dir, limits) = store("intake-flood");
    store.lock().unwrap().add(j, &limits).unwrap();
    {
        let mut st = store.lock().unwrap();
        let mut s = w.seq.lock().unwrap();
        for i in 0..N {
            let t = terms_n(1_000, tip + 7, i);
            let lock = lock_tx(&t);
            s.locks.insert(lock.txid().to_string(), lock.clone());
            let mut j = job_with(&t, &lock, None, 50_000);
            j.client = format!("100.64.{}.{}", i / 250, i % 250);
            st.add(j, &limits).unwrap();
        }
    }
    w.seq.lock().unwrap().rate = 1;
    for _ in 0..4 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    assert!(proven(&w.seq).is_none());
    assert!(!w.seq.lock().unwrap().refused.is_empty());
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 100_000_000;
        s.tick_delay = Duration::from_millis(40);
    }
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood = {
        let (stop, store) = (stop.clone(), &store);
        let buyer_script = terms().receive_script_pubkey();
        std::thread::scope(|sc| {
            let flag = stop.clone();
            let h = sc.spawn(move || {
                let mut posts = 0u64;
                while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                    for j in store.lock().unwrap().jobs.values_mut() {
                        if j.terms.receive_script_pubkey() != buyer_script {
                            j.changed += 1;
                            posts += 1;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                posts
            });
            let start = Instant::now();
            service::work_round(store, &w.seq_chain, &w.btc_chain, &limits);
            let took = start.elapsed();
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            (h.join().unwrap(), took)
        })
    };
    let s = w.seq.lock().unwrap();
    let at = s.first_pooled;
    eprintln!(
        "{} intake changes during the round ({:?}); the buyer pooled: {}",
        flood.0,
        flood.1,
        at.is_some()
    );
    drop(s);
    assert_eq!(
        proven(&w.seq),
        Some(id(&buyer)),
        "the refused buyer was not retried in the round after the floors changed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Sequentia block on top of the tip, anchoring the same Bitcoin block.
fn seq_block(w: &World) {
    let mut s = w.seq.lock().unwrap();
    let a = *s.anchors.last().unwrap();
    s.anchors.push(a);
}

/// A refusal for want of room. Both tiers are refused `mempool full`, a refusal for want of room,
/// which depends on what else the mempool holds and not on the floors. While the mempool
/// stays full, the claim is tried again at the next Sequentia block, then after 2 blocks,
/// then every 4 ([`lwk_paylock::CAPACITY_BACKOFF_MAX`]), never at the same block. Once the
/// mempool has room, with the floors read exactly as before, a block brings the claim back
/// within that backoff, and it lands. Judged by the floors alone it would never come back.
#[test]
fn a_claim_refused_for_want_of_room_is_tried_again_as_blocks_are_mined() {
    let (w, mut j, buyer) = buyer_world();
    let refused = |w: &World| w.seq.lock().unwrap().refused.len();
    w.seq.lock().unwrap().full = true;
    let _ = tick(&w, &mut j);
    assert_eq!(refused(&w), 2, "both tiers refused");
    // No block: not tried again, however often the job is worked.
    for _ in 0..3 {
        let _ = tick(&w, &mut j);
    }
    assert_eq!(refused(&w), 2, "tried again with no block mined");
    // Blocks while the mempool stays full: tried at the 1st, then the 3rd, then every 4th.
    let mut tried_at = vec![];
    for b in 1..=11u32 {
        let before = refused(&w);
        seq_block(&w);
        let _ = tick(&w, &mut j);
        let _ = tick(&w, &mut j);
        if refused(&w) > before {
            tried_at.push(b);
        }
    }
    eprintln!("mempool full: tried again at blocks {tried_at:?}");
    assert_eq!(tried_at, vec![1, 3, 7, 11]);
    // The mempool clears, the floors read as before.
    w.seq.lock().unwrap().full = false;
    let mut blocks = 0;
    while proven(&w.seq).is_none() && blocks < 8 {
        seq_block(&w);
        blocks += 1;
        let _ = tick(&w, &mut j);
    }
    let v = j.public_json();
    eprintln!(
        "room again at unchanged floors: pooled after {blocks} block(s); {}",
        v["note"]
    );
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert!(
        blocks <= lwk_paylock::CAPACITY_BACKOFF_MAX as usize,
        "{blocks}"
    );
}

/// A reorganization while stopped. The service is stopped with a claim passed over, and while it is
/// down Sequentia reorganizes (its tip rebuilt at the same height), the floors read as
/// before and no block added. No round saw the reorganization, so the first round after
/// the start checks the Sequentia block each candidate was passed over at against the
/// node's best chain: gone, the candidate is tried again, and the buyer lands. Started
/// again without a reorganization, nothing is tried again.
#[test]
fn a_sequentia_reorganization_while_the_service_is_stopped_brings_a_refused_claim_back() {
    let (w, j, buyer) = buyer_world();
    let (store, dir, limits) = store("offline-reorg");
    store.lock().unwrap().add(j, &limits).unwrap();
    let refused = |w: &World| w.seq.lock().unwrap().refused.len();
    let passed = |st: &Mutex<Store>| {
        st.lock()
            .unwrap()
            .jobs
            .values()
            .map(|j| j.scan.passed.len())
            .sum::<usize>()
    };
    w.seq.lock().unwrap().full = true;
    for _ in 0..3 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    let n = refused(&w);
    assert_eq!(n, 2, "both tiers refused once");
    assert_eq!(passed(&store), 1);
    // Stopped. The mempool has room again; the floors and the tip are as they were.
    drop(store);
    w.seq.lock().unwrap().full = false;
    let store = Mutex::new(Store::open(&dir).unwrap());
    for _ in 0..2 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    assert_eq!(refused(&w), n, "tried again with nothing changed");
    assert_eq!(passed(&store), 1);
    assert!(proven(&w.seq).is_none());
    // Stopped again; Sequentia reorganizes meanwhile.
    drop(store);
    w.seq.lock().unwrap().generation += 1;
    let store = Mutex::new(Store::open(&dir).unwrap());
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    eprintln!(
        "offline Sequentia reorganization: refusals {n} -> {}, passed {}",
        refused(&w),
        passed(&store)
    );
    assert_eq!(
        proven(&w.seq),
        Some(id(&buyer)),
        "not tried again after a reorganization while stopped"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// First tries under the floor. An attacker posts 300 jobs on scripts of their own, pays them all in
/// one transaction and prices every claim under the floor: once that payment is mined and
/// anchored, each is a claim to make, and each takes the node 40 ms to work, 12 s in all,
/// past the round's 10 s. A buyer refused before is due again in that same round (the
/// fee asset's rate is back). The attacker's first tries take turns with retries, a retry
/// first, so the buyer's claim is pooled in that round, in its first turns.
#[test]
fn a_refused_buyer_is_retried_within_a_round_of_first_tries_under_the_floor() {
    const N: u32 = 300;
    let (w, j, buyer) = buyer_world();
    let tip = 1_003;
    let (store, dir, limits) = store("first-try-flood");
    store.lock().unwrap().add(j, &limits).unwrap();
    w.seq.lock().unwrap().rate = 1;
    for _ in 0..4 {
        service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    }
    assert!(proven(&w.seq).is_none());
    let refused_buyer = w.seq.lock().unwrap().refused.len();
    assert!(refused_buyer >= 2);
    let att: Vec<PayLockTerms> = (0..N).map(|n| terms_n(BASE, tip + 7, n)).collect();
    let mut pay = payment(&att[0], 200, 0);
    pay.output = att
        .iter()
        .map(|t| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        })
        .collect();
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
    mine(&w, 140, &[pay]);
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 100_000_000;
        s.tick_delay = Duration::from_millis(40);
    }
    let start = Instant::now();
    service::work_round(&store, &w.seq_chain, &w.btc_chain, &limits);
    let took = start.elapsed();
    let s = w.seq.lock().unwrap();
    let attacker_refused = s.refused.len() - refused_buyer;
    eprintln!(
        "{N} first tries under the floor: round {took:?}, {attacker_refused} attacker claims refused, buyer pooled after {:?}",
        s.first_pooled.map(|t| t - start)
    );
    drop(s);
    assert_eq!(
        proven(&w.seq),
        Some(id(&buyer)),
        "the refused buyer was not retried in the round of the attacker's first tries"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each tier's own floor reads. The fee asset's rate is 1,000,000: the going
/// tier (1,000 atoms) is refused and the top tier (50,000) would land. The rate drops to 1
/// as the going tier is refused, so the top tier is sent at 1 and refused, and is back at
/// 1,000,000 as the top tier is refused. Read once before the first tier and once after
/// the last, the floors agree, and both tiers would wait for a change that never comes.
/// Each tier keeps the reads around its own send, which disagree, so the claim is tried
/// again at the next reading and the top tier lands.
#[test]
fn each_tier_keeps_the_floors_read_around_its_own_send() {
    let (w, mut j, buyer) = buyer_world();
    {
        let mut s = w.seq.lock().unwrap();
        s.rate = 1_000_000;
        s.rates_after = vec![(1, 1), (2, 1_000_000)];
    }
    let _ = tick(&w, &mut j);
    let refused = w.seq.lock().unwrap().refused.clone();
    eprintln!("refused {refused:?}");
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(w.seq.lock().unwrap().rate, 1_000_000);
    until_pooled(&w, &mut j, 3);
    let v = j.public_json();
    eprintln!("then: {}", v["note"]);
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert!(
        v["note"].as_str().unwrap().contains("top tier"),
        "{}",
        v["note"]
    );
}

/// A swap worth more than the RPC's default fee ceiling allows its top tier. The going tier
/// is refused for its fee rate; the top tier pays far more than `sendrawtransaction`'s
/// default `maxfeerate` lets through, a fee the buyer signed and nothing can lower. The
/// service sends with no ceiling, so the top tier lands; sent with the default, the node
/// would refuse it for ever and the buyer would have no tier that lands.
#[test]
fn a_top_tier_above_the_default_fee_ceiling_lands() {
    let (w, mut j, buyer) = buyer_world();
    {
        let mut s = w.seq.lock().unwrap();
        // The going tier (1,000 atoms) is under the floor, the top tier (50,000) over it.
        s.floor = 10_000;
        s.max_fee = 10_000;
    }
    until_pooled(&w, &mut j, 3);
    let refused = w.seq.lock().unwrap().refused.clone();
    let v = j.public_json();
    eprintln!("refused {refused:?}; then: {}", v["note"]);
    assert!(
        !refused.iter().any(|m| m.contains("Fee exceeds maximum")),
        "{refused:?}"
    );
    assert_eq!(proven(&w.seq), Some(id(&buyer)), "{}", v["note"]);
    assert!(
        v["note"].as_str().unwrap().contains("top tier"),
        "{}",
        v["note"]
    );
}

/// The Bitcoin daemon is asked about and sent payments and cancels with no fee ceiling
/// either: a fee the signer chose never makes the service refuse or hold back one the
/// daemon would take.
#[test]
fn bitcoin_sends_and_checks_carry_no_fee_ceiling() {
    let u = fake_node(Box::new(|m, p| {
        let uncapped = p.get(1).and_then(Value::as_f64) == Some(0.0);
        match (m, uncapped) {
            ("testmempoolaccept", true) => {
                Ok(json!([{"txid": "00", "allowed": true, "fees": {"base": 0.5}}]))
            }
            ("testmempoolaccept", false) => {
                Ok(json!([{"txid": "00", "allowed": false, "reject-reason": "max-fee-exceeded"}]))
            }
            ("sendrawtransaction", true) => Ok(json!("00")),
            ("sendrawtransaction", false) => Err((
                -25,
                "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".into(),
            )),
            _ => Err((-32601, "Method not found".into())),
        }
    }));
    let btc = BtcChain { rpc: rpc(&u) };
    assert_eq!(
        btc.test_accept("00").unwrap(),
        lwk_paylock::Accept::Allowed { fee: 50_000_000 }
    );
    assert_eq!(btc.send_raw("00").unwrap(), "00");
}
