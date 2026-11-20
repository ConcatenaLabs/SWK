//! The completion service against fake nodes: a Sequentia node whose every answer takes
//! two seconds (a stalled round of work), a Bitcoin daemon that records what it is sent,
//! one that is slow to refuse stale cancels, and one whose blocks carry a bumped payment.
//!
//! The cases that run the `paylock` binary run `PAYLOCK_TEST_BIN` when it is set, so the
//! same case judges another revision of the service.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lwk_paylock::service::{self, Added, Intake, Job, Limits, State, Store};
use lwk_paylock::{BtcChain, Rpc, SeqChain};
use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{self, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::serialize;
use lwk_wollet::elements::hashes::Hash;
use lwk_wollet::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use lwk_wollet::elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

type Answer = Box<dyn Fn(&str, &Value) -> Result<Value, (i32, String)> + Send + Sync>;

/// A JSON-RPC server on a free loopback port; every request is answered on a thread of
/// its own, so one slow answer holds back no other.
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

fn key(b: u8) -> SecretKey {
    SecretKey::from_slice(&[b; 32]).unwrap()
}

fn terms(floor: u32, deadline: u32) -> PayLockTerms {
    let secp = Secp256k1::new();
    let x = |b| {
        Keypair::from_secret_key(&secp, &key(b))
            .x_only_public_key()
            .0
    };
    let rk = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
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

/// A lock transaction paying the terms' lock script at output 0.
fn lock_tx(t: &PayLockTerms) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![paylock::lock_txout(t).unwrap()],
    }
}

/// A Bitcoin transaction spending the coin named by `n`: a cancel, as far as its form goes.
fn btc_spend(n: u32, value: u64) -> bitcoin::Transaction {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_le_bytes());
    id[31] = 0xbc;
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(id),
                vout: 0,
            },
            sequence: bitcoin::Sequence(0xffff_fffd),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

fn btc_hex(tx: &bitcoin::Transaction) -> String {
    hex_encode(&bitcoin::consensus::encode::serialize(tx))
}

/// A Bitcoin block carrying a coinbase and `txs`, raw, as `getblock <hash> 0` answers.
fn raw_block(txs: &[bitcoin::Transaction]) -> String {
    let coinbase = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: std::iter::once(coinbase)
            .chain(txs.iter().cloned())
            .collect(),
    };
    hex_encode(&bitcoin::consensus::encode::serialize(&block))
}

/// A payment of the terms' price to their receiving script from the coin named by `n`,
/// with `fee` taken from a 100,000-sat coin; and a cancel of it.
fn payment_for(t: &PayLockTerms, n: u32, fee: u64) -> (bitcoin::Transaction, bitcoin::Transaction) {
    let mut pay = btc_spend(n, 100_000 - t.price_sat - fee);
    pay.output.insert(
        0,
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(t.price_sat),
            script_pubkey: t.receive_script_pubkey(),
        },
    );
    (pay, btc_spend(n, 90_000))
}

/// The `paylock` binary under test.
fn bin() -> String {
    std::env::var("PAYLOCK_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_paylock").to_string())
}

/// A job as a buyer's wallet hands it over, for the lock `lock`.
fn request_for(t: &PayLockTerms, lock: OutPoint, payment: &str, cancel: Option<String>) -> Value {
    request_tiers(t, lock, payment, cancel, &[1000])
}

/// A job whose claims pay these fees, as a buyer's wallet hands it over.
fn request_tiers(
    t: &PayLockTerms,
    lock: OutPoint,
    payment: &str,
    cancel: Option<String>,
    fees: &[u64],
) -> Value {
    let claims: Vec<String> = fees
        .iter()
        .map(|f| {
            let c =
                paylock::sign_claim(t, lock, Script::new(), *f, BlockHash::all_zeros(), &key(1))
                    .unwrap();
            hex_encode(&serialize(&c))
        })
        .collect();
    let mut v = json!({
        "terms": t.to_json(),
        "lock": format!("{}:{}", lock.txid, lock.vout),
        "claims": claims,
        "payment": payment,
    });
    if let Some(c) = cancel {
        v["cancel"] = json!(c);
    }
    v
}

/// A job whose lock is named by `n` (a lock no node knows).
fn request(n: u32, floor: u32, deadline: u32, cancel: Option<String>) -> Value {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_le_bytes());
    let lock = OutPoint::new(Txid::from_byte_array(id), 0);
    request_for(&terms(floor, deadline), lock, &format!("{n:064x}"), cancel)
}

/// The job a request names, as the service holds it once intake has placed its cancel:
/// with a payment of the terms spending the cancel's coins, vouched for, the cancel kept.
/// For the cases that fill a store directly.
fn holding(v: &Value) -> Job {
    let j = Job::from_request(v).unwrap();
    let mut s = j.to_json();
    if let Some(c) = v["cancel"].as_str() {
        let cancel: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&paylock::hex_decode(c).unwrap()).unwrap();
        let mut pay = cancel.clone();
        pay.output = vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(j.terms.price_sat),
            script_pubkey: j.terms.receive_script_pubkey(),
        }];
        pay.input
            .iter_mut()
            .for_each(|i| i.witness = bitcoin::Witness::new());
        s["payments"] = json!([{"hex": btc_hex(&pay), "vouched": true,
            "cancels": [{"hex": c, "fee": 1_000, "vouched": true}]}]);
    }
    Job::from_stored(&s).unwrap()
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("paylock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn rpc(u: &str, secs: u64) -> Rpc {
    Rpc::with_timeout(u, "u", "p", Duration::from_secs(secs)).unwrap()
}

#[test]
fn a_stalled_round_does_not_hold_back_a_due_cancel() {
    let tip = Arc::new(AtomicU32::new(1_000));
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let (t2, s2) = (tip.clone(), sent.clone());
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(t2.load(Ordering::SeqCst))),
        "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
        "getblock" => {
            std::thread::sleep(Duration::from_millis(50));
            Ok(json!(raw_block(&[])))
        }
        "sendrawtransaction" => {
            s2.lock().unwrap().push(p[0].as_str().unwrap().to_string());
            Ok(json!("00".repeat(32)))
        }
        "getmempoolentry" | "getrawtransaction" => Err((-5, "not in mempool".into())),
        _ => Err((-32601, "no such method".into())),
    }));
    // Every answer of the Sequentia node takes two seconds. It knows the live job's lock.
    let live_terms = terms(1_000, 1_003);
    let live_lock_tx = lock_tx(&live_terms);
    let live_lock = OutPoint::new(live_lock_tx.txid(), 0);
    let (lock_id, lock_hex) = (
        live_lock.txid.to_string(),
        hex_encode(&serialize(&live_lock_tx)),
    );
    let seq_url = fake_node(Box::new(move |m, p| {
        std::thread::sleep(Duration::from_secs(2));
        match m {
            "getposfinality" => Ok(json!({"finalized_height": 0})),
            "getrawtransaction" if p[0].as_str() == Some(&lock_id) => Ok(json!({"hex": lock_hex})),
            "getrawtransaction" => Err((-5, "No such mempool or blockchain transaction".into())),
            "getblockcount" => Ok(json!(10)),
            "gettxout" => Ok(json!({"value": 1})),
            _ => Err((-32601, "no such method".into())),
        }
    }));
    let live_cancel = btc_hex(&btc_spend(999, 40_000));

    let dir = tmpdir("stalled");
    {
        let mut st = Store::open(&dir).unwrap();
        // One client starts them all here; its quota is not what this case is about.
        let limits = Limits {
            jobs_per_client: 0,
            ..Limits::default()
        };
        // Thirty ended and buried jobs, as a long-running service accumulates them.
        for n in 0..30 {
            let mut j = Job::from_request(&request(n, 990, 996, None)).unwrap();
            st.add(j.clone(), &limits).unwrap();
            j.state = [State::Final, State::Cancelled, State::Never][n as usize % 3];
            j.buried = true;
            st.save(&j).unwrap();
        }
        // Forty stale ones whose payment never comes, each reaching 800 blocks back.
        for n in 100..140 {
            st.add(
                holding(&request(n, 300, 1_100 + n, Some(btc_hex(&btc_spend(n, 1))))),
                &limits,
            )
            .unwrap();
        }
        // The live one, due two blocks before its deadline at 1,003.
        st.add(
            holding(&request_for(
                &live_terms,
                live_lock,
                &"ab".repeat(32),
                Some(live_cancel.clone()),
            )),
            &limits,
        )
        .unwrap();
    }
    // Reopened, the ended and buried jobs are archived: never worked on again.
    let store = Arc::new(Mutex::new(Store::open(&dir).unwrap()));
    assert_eq!(store.lock().unwrap().jobs.len(), 41);
    assert_eq!(std::fs::read_dir(dir.join("archive")).unwrap().count(), 30);

    let limits = Limits {
        round_time: Duration::from_secs(3),
        job_time: Duration::from_secs(1),
        ..Limits::default()
    };
    let (st2, l2, su, bu) = (
        store.clone(),
        limits.clone(),
        seq_url.clone(),
        btc_url.clone(),
    );
    let work = std::thread::spawn(move || {
        let t = Instant::now();
        let n = service::work_round(
            &st2,
            &SeqChain { rpc: rpc(&su, 15) },
            &BtcChain { rpc: rpc(&bu, 15) },
            &l2,
        );
        (n, t.elapsed())
    });

    // Bitcoin reaches D - 2 while the round is stuck on the Sequentia node.
    std::thread::sleep(Duration::from_millis(500));
    tip.store(1_001, Ordering::SeqCst);
    let t = Instant::now();
    let n = service::send_due_cancels(
        &store,
        &BtcChain {
            rpc: rpc(&btc_url, 3),
        },
        &SeqChain {
            rpc: rpc(&seq_url, 3),
        },
        &limits,
    )
    .unwrap();
    let took = t.elapsed();
    eprintln!("the due cancel went out in {took:?} (one lock lookup at the slow node) while the round was stalled");
    assert_eq!(n, 1);
    assert_eq!(*sent.lock().unwrap(), vec![live_cancel]);
    assert!(took < Duration::from_secs(3), "the cancel took {took:?}");
    assert!(
        !work.is_finished(),
        "the round was not stalled when the cancel went out"
    );

    // The round keeps to its budget: it stops after the job it is in when its time is up.
    let (worked, elapsed) = work.join().unwrap();
    eprintln!(
        "the stalled round worked {worked} of 41 jobs in {elapsed:?} (budget 3 s, one answer 2 s)"
    );
    assert!(worked < 41, "a stalled round worked every job ({worked})");
    assert!(
        elapsed < Duration::from_secs(9),
        "the round took {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Posts JSON to the service; returns the status code and the body.
fn post(port: u16, path: &str, body: &Value) -> (u16, Value) {
    post_as(port, path, body, None)
}

/// Posts JSON to the service as the client `client` (a reverse proxy's `X-Forwarded-For`).
fn post_as(port: u16, path: &str, body: &Value, client: Option<&str>) -> (u16, Value) {
    let b = body.to_string();
    let fwd = client
        .map(|c| format!("X-Forwarded-For: {c}\r\n"))
        .unwrap_or_default();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{fwd}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let code = out.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    let json = out.split("\r\n\r\n").nth(1).unwrap_or("null");
    (code, serde_json::from_str(json).unwrap_or(Value::Null))
}

/// The service as it runs (`paylock serve`), its process stopped when the test ends.
struct Serve(std::process::Child);

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve(dir: &std::path::Path, seq_url: &str, btc_url: &str) -> (Serve, u16) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = std::process::Command::new(bin())
        .args(["serve", "--data", dir.to_str().unwrap(), "--listen"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["--interval", "0.5"])
        .env("PAYLOCK_SEQ_URL", seq_url)
        .env("PAYLOCK_SEQ_USER", "u")
        .env("PAYLOCK_SEQ_PASS", "p")
        .env("PAYLOCK_BTC_URL", btc_url)
        .env("PAYLOCK_BTC_USER", "u")
        .env("PAYLOCK_BTC_PASS", "p")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let serve = Serve(child);
    let t = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "the service did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    (serve, port)
}

/// Gets a path from the service; returns the status code and the body.
fn get(port: u16, path: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let code = out.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    let json = out.split("\r\n\r\n").nth(1).unwrap_or("null");
    (code, serde_json::from_str(json).unwrap_or(Value::Null))
}

/// A fake Bitcoin daemon's answer to `testmempoolaccept`: every transaction allowed.
fn allow_all(p: &Value) -> Result<Value, (i32, String)> {
    Ok(json!([{"txid": "00", "allowed": true, "fees": {"base": 0.0001}, "params": p}]))
}

/// A fake Sequentia node's genesis: the one the test claims are signed for.
fn genesis_answer(p: &Value) -> Option<Value> {
    (p[0].as_u64() == Some(0)).then(|| json!("00".repeat(32)))
}

type Locks = Arc<Mutex<std::collections::HashMap<String, Transaction>>>;

/// A fake Sequentia node that holds the locks in `locks` (each lock's id, as a job names
/// it, and a transaction whose output at the lock's index pays the lock) unspent while
/// `knows` is set, and answers what the service asks of a node.
fn fake_seq(locks: Locks, knows: Arc<std::sync::atomic::AtomicBool>) -> String {
    fake_node(Box::new(move |m, p| {
        let id = p[0].as_str().unwrap_or_default().to_string();
        let held = knows
            .load(Ordering::SeqCst)
            .then(|| locks.lock().unwrap().get(&id).cloned())
            .flatten();
        match m {
            "getposfinality" => Ok(json!({"finalized_height": 0})),
            "getrawtransaction" => match held {
                Some(tx) => Ok(json!({"hex": hex_encode(&serialize(&tx))})),
                None => Err((-5, "No such mempool or blockchain transaction".into())),
            },
            "gettxout" => Ok(if held.is_some() {
                json!({"value": 1})
            } else {
                Value::Null
            }),
            "getblockhash" => genesis_answer(p).ok_or((-8, "out of range".into())),
            "getblockcount" => Ok(json!(10)),
            "getfeeassetinfo" => Ok(json!({})),
            _ => Err((-32601, "no such method".into())),
        }
    }))
}

/// A made-up lock outpoint named by `n`, which a [`fake_seq`] holds when it is in its locks.
fn lock_named(n: u32) -> OutPoint {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_le_bytes());
    id[31] = 0x10;
    OutPoint::new(Txid::from_byte_array(id), 0)
}

/// The review's flood: 150 jobs from three other clients whose deadlines come first and
/// whose cancels the Bitcoin daemon takes 50 ms each to refuse, beside one live job of a
/// fourth client. Each has a real lock; the clients take turns, so the live cancel goes
/// out at once. Run against the `paylock` binary, so the same case judges any revision of
/// the service.
#[test]
fn a_flood_of_slow_stale_cancels_does_not_hold_back_a_live_one() {
    const T: u32 = 1_000;
    const STALE: u32 = 150;
    let tip = Arc::new(AtomicU32::new(T));
    let live_terms = terms(T - 1, T + 5);
    let (live_pay, live_cancel) = payment_for(&live_terms, 999_999, 1_000);
    let live_cancel = btc_hex(&live_cancel);
    let got_live = Arc::new(Mutex::new(None::<Instant>));
    let stale_tried = Arc::new(AtomicU32::new(0));
    let (t2, lc, gl, st2) = (
        tip.clone(),
        live_cancel.clone(),
        got_live.clone(),
        stale_tried.clone(),
    );
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(t2.load(Ordering::SeqCst))),
        "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
        "getblock" => Ok(json!(raw_block(&[]))),
        "testmempoolaccept" => allow_all(p),
        "sendrawtransaction" if p[0].as_str() == Some(&lc) => {
            gl.lock().unwrap().get_or_insert(Instant::now());
            Ok(json!("00".repeat(32)))
        }
        "sendrawtransaction" => {
            st2.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            Err((-25, "bad-txns-inputs-missingorspent".into()))
        }
        "getmempoolentry" | "getrawtransaction" => Err((-5, "not in mempool".into())),
        _ => Err((-32601, "no such method".into())),
    }));
    let locks: Locks = Default::default();
    let live_lock_tx = lock_tx(&live_terms);
    let live_lock = OutPoint::new(live_lock_tx.txid(), 0);
    locks
        .lock()
        .unwrap()
        .insert(live_lock.txid.to_string(), live_lock_tx);
    let stale_terms = terms(T - 1, T + 3);
    for n in 0..STALE {
        locks
            .lock()
            .unwrap()
            .insert(lock_named(n).txid.to_string(), lock_tx(&stale_terms));
    }
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("flood");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    for n in 0..STALE {
        let (pay, cancel) = payment_for(&stale_terms, n, 1_000);
        let mut r = request_for(
            &stale_terms,
            lock_named(n),
            &pay.compute_txid().to_string(),
            Some(btc_hex(&cancel)),
        );
        r["payment_hex"] = json!(btc_hex(&pay));
        let client = format!("10.0.0.{}", n % 3);
        let (code, r) = post_as(port, "/jobs", &r, Some(&client));
        assert_eq!(code, 200, "{r}");
    }
    let mut live = request_for(
        &live_terms,
        live_lock,
        &live_pay.compute_txid().to_string(),
        Some(live_cancel),
    );
    live["payment_hex"] = json!(btc_hex(&live_pay));
    let (code, r) = post(port, "/jobs", &live);
    assert_eq!(code, 200, "{r}");
    // Let the service settle, then Bitcoin reaches the live job's D - 2 (and every stale
    // job is due too, its deadline first).
    std::thread::sleep(Duration::from_secs(3));
    let t = Instant::now();
    tip.store(T + 3, Ordering::SeqCst);
    while got_live.lock().unwrap().is_none() && t.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = got_live.lock().unwrap().map(|g| g.duration_since(t));
    let tried = stale_tried.load(Ordering::SeqCst);
    eprintln!("the live cancel went out {took:?} after D - 2; stale cancels tried before it and since: {tried}");
    let took = took.expect("the live cancel never went out");
    assert!(
        took < Duration::from_secs(3),
        "the live cancel waited {took:?} behind {tried} stale ones"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Sequentia node that says it does not know the lock any more (one restarted and
/// still syncing, say) holds back no cancel: the cancel concerns Bitcoin alone. Through
/// the binary.
#[test]
fn a_due_cancel_goes_out_whatever_the_node_says_of_the_lock() {
    const T: u32 = 1_000;
    let tip = Arc::new(AtomicU32::new(T));
    let t = terms(T - 1, T + 5);
    let (pay, cancel) = payment_for(&t, 77, 1_000);
    let cancel = btc_hex(&cancel);
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let (t2, s2) = (tip.clone(), sent.clone());
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(t2.load(Ordering::SeqCst))),
        "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
        "getblock" => Ok(json!(raw_block(&[]))),
        "testmempoolaccept" => allow_all(p),
        "sendrawtransaction" => {
            s2.lock().unwrap().push(p[0].as_str().unwrap().to_string());
            Ok(json!("00".repeat(32)))
        }
        "getmempoolentry" | "getrawtransaction" => Err((-5, "not in mempool".into())),
        _ => Err((-32601, "no such method".into())),
    }));
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let knows = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let seq_url = fake_seq(locks, knows.clone());
    let dir = tmpdir("unknownlock");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let mut r = request_for(
        &t,
        lock,
        &pay.compute_txid().to_string(),
        Some(cancel.clone()),
    );
    r["payment_hex"] = json!(btc_hex(&pay));
    let (code, r) = post(port, "/jobs", &r);
    assert_eq!(code, 200, "{r}");
    // From now on the node knows no transaction at all: not the lock, not anything.
    knows.store(false, Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(2));
    tip.store(T + 3, Ordering::SeqCst);
    let w = Instant::now();
    while !sent.lock().unwrap().contains(&cancel) && w.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        sent.lock().unwrap().contains(&cancel),
        "the due cancel was never sent: the node's word on the lock held it back"
    );
    eprintln!(
        "the due cancel went out {:?} after D - 2 though the node knows no lock",
        w.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake Bitcoin daemon for the intake cases: its tip, what it was sent, and its answer
/// to `testmempoolaccept` from `judge(hex)`.
fn judged_daemon(
    tip: Arc<AtomicU32>,
    sent: Arc<Mutex<Vec<String>>>,
    judge: Box<dyn Fn(&str) -> Value + Send + Sync>,
    send_ok: Arc<std::sync::atomic::AtomicBool>,
) -> String {
    fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(tip.load(Ordering::SeqCst))),
        "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
        "getblock" => Ok(json!(raw_block(&[]))),
        "testmempoolaccept" => Ok(json!([judge(p[0][0].as_str().unwrap_or_default())])),
        "sendrawtransaction" => {
            sent.lock()
                .unwrap()
                .push(p[0].as_str().unwrap().to_string());
            if send_ok.load(Ordering::SeqCst) {
                Ok(json!("00".repeat(32)))
            } else {
                Err((-25, "bad-txns-inputs-missingorspent".into()))
            }
        }
        "getmempoolentry" => Ok(json!({"fees": {"base": 0.0002}})),
        "getrawtransaction" => Err((-5, "No such mempool transaction".into())),
        _ => Err((-32601, "no such method".into())),
    }))
}

/// The payment's parent is signed but not broadcast, so the service's Bitcoin
/// daemon knows neither it nor the payment, and answers `missing-inputs` for the cancel.
/// The cancel is kept unchecked (never read as a spend in a block), sent at D - 2, and
/// checked again once the parent and the payment are broadcast.
#[test]
fn a_cancel_whose_coins_are_not_known_yet_is_kept_and_sent() {
    const T: u32 = 1_000;
    let tip = Arc::new(AtomicU32::new(T));
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let parent_known = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pk = parent_known.clone();
    let btc_url = judged_daemon(
        tip.clone(),
        sent.clone(),
        Box::new(move |_| {
            if pk.load(Ordering::SeqCst) {
                json!({"allowed": true, "fees": {"base": 0.0001}})
            } else {
                json!({"allowed": false, "reject-reason": "missing-inputs"})
            }
        }),
        parent_known.clone(),
    );
    let t = terms(T - 1, T + 5);
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("unknownparent");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let (pay, cancel) = payment_for(&t, 31, 1_000);
    let cancel = btc_hex(&cancel);
    let mut r = request_for(
        &t,
        lock,
        &pay.compute_txid().to_string(),
        Some(cancel.clone()),
    );
    r["payment_hex"] = json!(btc_hex(&pay));
    let (code, r) = post(port, "/jobs", &r);
    assert_eq!(code, 200, "{r}");
    let id = r["id"].as_str().unwrap().to_string();
    let notes = r["notes"].to_string();
    assert!(notes.contains("kept unchecked"), "{r}");
    assert!(!notes.contains("spent in a block"), "{r}");
    let (_, j) = get(port, &format!("/jobs/{id}"));
    assert_eq!(
        (j["cancels"].as_u64(), j["pending_cancels"].as_u64()),
        (Some(0), Some(1)),
        "{j}"
    );
    // D - 2 with the parent still unbroadcast: the cancel is tried all the same.
    tip.store(T + 3, Ordering::SeqCst);
    let w = Instant::now();
    while !sent.lock().unwrap().contains(&cancel) && w.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        sent.lock().unwrap().contains(&cancel),
        "the unchecked cancel was not tried at D - 2"
    );
    // The buyer broadcasts the parent and the payment: the cancel is checked, kept, and
    // accepted by the daemon.
    parent_known.store(true, Ordering::SeqCst);
    let w = Instant::now();
    loop {
        let (_, j) = get(port, &format!("/jobs/{id}"));
        if j["cancels"].as_u64() == Some(1) && j["cancel_sent"].as_bool() == Some(true) {
            assert_eq!(j["pending_cancels"].as_u64(), Some(0), "{j}");
            eprintln!(
                "checked and sent {:?} after its coins became known: {}",
                w.elapsed(),
                j["note"]
            );
            break;
        }
        assert!(
            w.elapsed() < Duration::from_secs(20),
            "the cancel was never checked and sent: {j}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cancel the buyer already broadcast (or that is already mined) is valid:
/// kept, with a note; never a refusal that would lose the post's claims.
#[test]
fn a_cancel_already_broadcast_is_kept_with_the_claims() {
    const T: u32 = 1_000;
    let tip = Arc::new(AtomicU32::new(T));
    let t = terms(T - 1, T + 5);
    let (pay, cancel) = payment_for(&t, 41, 1_000);
    let (pay2, cancel2) = payment_for(&t, 42, 1_000);
    let (c1, c2) = (btc_hex(&cancel), btc_hex(&cancel2));
    let (k1, k2) = (c1.clone(), c2.clone());
    let btc_url = judged_daemon(
        tip,
        Default::default(),
        Box::new(move |hex| {
            if hex == k1 {
                json!({"allowed": false, "reject-reason": "txn-already-in-mempool"})
            } else if hex == k2 {
                json!({"allowed": false, "reject-reason": "txn-already-known"})
            } else {
                // The payment the broadcast cancel replaced.
                json!({"allowed": false, "reject-reason": "insufficient fee, rejecting replacement"})
            }
        }),
        Arc::new(true.into()),
    );
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("broadcastcancel");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    for (pay, c, says) in [
        (&pay, &c1, "already broadcast"),
        (&pay2, &c2, "already mined"),
    ] {
        let mut r = request_tiers(
            &t,
            lock,
            &pay.compute_txid().to_string(),
            Some(c.clone()),
            &[1_000, 9_000],
        );
        r["payment_hex"] = json!(btc_hex(pay));
        let (code, r) = post(port, "/jobs", &r);
        assert_eq!(code, 200, "{r}");
        assert!(r["notes"].to_string().contains(says), "{r}");
        // One job for the lock: each payment with its cancel.
        let (_, j) = get(port, &format!("/jobs/{}", r["id"].as_str().unwrap()));
        let n = if says == "already broadcast" { 1 } else { 2 };
        assert_eq!(
            (j["tiers"].as_u64(), j["cancels"].as_u64()),
            (Some(2), Some(n)),
            "{j}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A thousand jobs on made-up locks are refused, and do not lock a real buyer
/// out; and one client starts at most its quota of live jobs, while another client, and a
/// post that merges into a job held, are taken.
#[test]
fn made_up_locks_and_one_client_cannot_fill_the_service() {
    const T: u32 = 1_000;
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(T)),
        Default::default(),
        Box::new(|_| json!({"allowed": true, "fees": {"base": 0.0001}})),
        Arc::new(true.into()),
    );
    let t = terms(T - 1, T + 5);
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    // Locks 5000.. are real (the node holds them); 0..1000 are made up.
    for n in 5_000..5_060 {
        locks
            .lock()
            .unwrap()
            .insert(lock_named(n).txid.to_string(), lock_tx(&t));
    }
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("fakelocks");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let started = Instant::now();
    for n in 0..1_000 {
        let r = request_for(&t, lock_named(n), &format!("{n:064x}"), None);
        let (code, r) = post(port, "/jobs", &r);
        assert_eq!(code, 400, "{r}");
        if n == 0 {
            assert!(
                r["error"]
                    .as_str()
                    .unwrap()
                    .contains("not an unspent output"),
                "{r}"
            );
        }
    }
    eprintln!(
        "1,000 jobs on made-up locks refused in {:?}",
        started.elapsed()
    );
    let (code, r) = post(
        port,
        "/jobs",
        &request_for(&t, lock, &"ab".repeat(32), None),
    );
    assert_eq!(code, 200, "the buyer was locked out: {r}");
    // One client's quota (50 by default) of jobs on real locks; then 429.
    for n in 5_000..5_050 {
        let (code, r) = post_as(
            port,
            "/jobs",
            &request_for(&t, lock_named(n), &"cd".repeat(32), None),
            Some("10.9.9.9"),
        );
        assert_eq!(code, 200, "{r}");
    }
    let (code, r) = post_as(
        port,
        "/jobs",
        &request_for(&t, lock_named(5_050), &"cd".repeat(32), None),
        Some("10.9.9.9"),
    );
    assert_eq!(code, 429, "{r}");
    // Another client is taken; and the full client's post into a job held merges.
    let (code, r) = post_as(
        port,
        "/jobs",
        &request_for(&t, lock_named(5_051), &"cd".repeat(32), None),
        Some("10.9.9.8"),
    );
    assert_eq!(code, 200, "{r}");
    let more = request_tiers(&t, lock, &"ab".repeat(32), None, &[1_000, 9_000]);
    let (code, r) = post_as(port, "/jobs", &more, Some("10.9.9.9"));
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["merged"], json!(["claims"]), "{r}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A client that sends its body slowly holds only its own connection, and only
/// until the request's deadline; reads and other posts are answered meanwhile.
#[test]
fn a_slow_body_stalls_nothing() {
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(1_000)),
        Default::default(),
        Box::new(|_| json!({"allowed": true, "fees": {"base": 0.0001}})),
        Arc::new(true.into()),
    );
    let seq_url = fake_seq(Default::default(), Arc::new(true.into()));
    let dir = tmpdir("slowbody");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let mut slow = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        slow,
        "POST /jobs HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n{{\"terms\":"
    )
    .unwrap();
    let opened = Instant::now();
    std::thread::sleep(Duration::from_millis(300));
    for i in 0..3 {
        let t = Instant::now();
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(
            s,
            "GET /jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(
            out.starts_with("HTTP/1.1 200"),
            "a read waited on a slow body: {out:?}"
        );
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(
            s,
            "POST /jobs HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        )
        .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(
            out.starts_with("HTTP/1.1 400"),
            "a post waited on a slow body: {out:?}"
        );
        eprintln!(
            "read and post {i} answered in {:?} beside a slow body",
            t.elapsed()
        );
    }
    // A client that asks to continue (curl, for a body over 1 KiB) is told to.
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(s, "POST /jobs HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\nConnection: close\r\n\r\n").unwrap();
    let mut first = [0u8; 25];
    s.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"HTTP/1.1 100 Continue\r\n\r\n");
    write!(s, "{{}}").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 400"), "{out:?}");
    slow.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut out = String::new();
    let _ = slow.read_to_string(&mut out);
    eprintln!(
        "the slow body was answered {:?} after it began: {:?}",
        opened.elapsed(),
        out.lines().next()
    );
    assert!(out.starts_with("HTTP/1.1 408"), "{out:?}");
    assert!(opened.elapsed() < Duration::from_secs(15));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every answer `testmempoolaccept` gives intake is judged: for a cancel and for a
/// signed payment.
#[test]
fn every_answer_of_the_daemon_is_judged() {
    use lwk_paylock::Accept;
    use service::{judge_cancel, judge_payment, CancelCheck, PaymentCheck};
    let refused = |r: &str| Accept::Refused(r.to_string());
    let cases: Vec<(Accept, &str, &str)> = vec![
        (Accept::Allowed { fee: 1_761 }, "valid", "vouched"),
        (refused("txn-already-in-mempool"), "valid", "vouched"),
        (refused("txn-already-known"), "valid", "vouched"),
        (refused("txn-same-nonwitness-data-in-mempool"), "copy", "copy"),
        (refused("mandatory-script-verify-flag-failed (Witness program hash mismatch)"), "invalid", "invalid"),
        (refused("mandatory-script-verify-flag-failed (Witness program was passed an empty witness)"), "invalid", "invalid"),
        (refused("non-mandatory-script-verify-flag (Invalid Schnorr signature)"), "invalid", "invalid"),
        (refused("bad-witness-nonstandard"), "invalid", "invalid"),
        (refused("missing-inputs"), "unknown", "kept"),
        (refused("bad-txns-inputs-missingorspent"), "unknown", "kept"),
        (refused("insufficient fee, rejecting replacement 1a2b, less fees than conflicting txs; 0.00001 < 0.00002"), "invalid", "kept"),
        (refused("txn-mempool-conflict"), "invalid", "kept"),
        (refused("replacement-adds-unconfirmed"), "invalid", "kept"),
        (refused("min relay fee not met, 100 < 141"), "invalid", "kept"),
        (refused("mempool min fee not met"), "invalid", "kept"),
        (refused("dust"), "invalid", "kept"),
        (refused("non-final"), "invalid", "kept"),
    ];
    for (a, c, p) in cases {
        let got_c = match judge_cancel(&a) {
            CancelCheck::Valid { .. } => "valid",
            CancelCheck::PooledCopy => "copy",
            CancelCheck::Unknown(_) => "unknown",
            CancelCheck::Invalid(_) => "invalid",
        };
        let got_p = match judge_payment(&a) {
            PaymentCheck::Vouched => "vouched",
            PaymentCheck::PooledCopy => "copy",
            PaymentCheck::Kept => "kept",
            PaymentCheck::Invalid(_) => "invalid",
        };
        assert_eq!((got_c, got_p), (c, p), "{a:?}");
    }
    // A cancel accepted now carries its fee; one already pooled or mined, a note.
    assert_eq!(
        judge_cancel(&Accept::Allowed { fee: 1_761 }),
        CancelCheck::Valid {
            fee: Some(1_761),
            vouched: true,
            note: None
        }
    );
    // Pooled under this very witness: vouched for. Mined: only its id is, not this copy.
    assert!(matches!(
        judge_cancel(&refused("txn-already-in-mempool")),
        CancelCheck::Valid {
            fee: None,
            vouched: true,
            note: Some(_)
        }
    ));
    assert!(matches!(
        judge_cancel(&refused("txn-already-known")),
        CancelCheck::Valid {
            fee: None,
            vouched: false,
            note: Some(_)
        }
    ));
    // A missing coin is never read as spent in a block.
    match judge_cancel(&refused("missing-inputs")) {
        CancelCheck::Unknown(r) => assert_eq!(r, "missing-inputs"),
        x => panic!("{x:?}"),
    }
}

#[test]
fn a_payment_search_keeps_its_place() {
    let reads = Arc::new(AtomicU32::new(0));
    let r2 = reads.clone();
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(1_500)),
        "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
        "getblock" => {
            r2.fetch_add(1, Ordering::SeqCst);
            Ok(json!(raw_block(&[])))
        }
        _ => Err((-32601, "no such method".into())),
    }));
    let btc = BtcChain {
        rpc: Rpc::new(&btc_url, "u", "p").unwrap(),
    };
    // The old search read every block from the tip down to F on every round.
    let t = terms(1_000, 1_006);
    let mut scan = lwk_paylock::PaymentScan::default();
    let far = Instant::now() + Duration::from_secs(60);
    let done = btc
        .scan_payment(&"ab".repeat(32), &t, &mut scan, 5, far)
        .unwrap();
    assert!(!done);
    assert_eq!(reads.load(Ordering::SeqCst), 5);
    let done = btc
        .scan_payment(&"ab".repeat(32), &t, &mut scan, 100, far)
        .unwrap();
    assert!(done);
    // F to D + 6: thirteen blocks, each read once, however far the tip is.
    assert_eq!(reads.load(Ordering::SeqCst), 13);
    btc.scan_payment(&"ab".repeat(32), &t, &mut scan, 100, far)
        .unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 13);
    assert!(matches!(
        lwk_paylock::payment_position(&t, &scan, true, 1_500),
        lwk_paylock::Position::Never(_)
    ));
}

#[test]
fn intake_is_bounded_and_needs_a_token_beyond_loopback() {
    let dir = tmpdir("intake");
    let mut st = Store::open(&dir).unwrap();
    let limits = Limits {
        max_jobs: 2,
        ..Limits::default()
    };
    st.add(
        Job::from_request(&request(1, 1_000, 1_006, None)).unwrap(),
        &limits,
    )
    .unwrap();
    st.add(
        Job::from_request(&request(2, 1_000, 1_006, None)).unwrap(),
        &limits,
    )
    .unwrap();
    let e = st
        .add(
            Job::from_request(&request(3, 1_000, 1_006, None)).unwrap(),
            &limits,
        )
        .unwrap_err();
    assert!(e.message().contains("its limit"), "{e:?}");
    assert_eq!(e.status(), 429);
    // A job whose outcome is decided, still watched, no longer counts toward the cap.
    let first = st.jobs.keys().next().unwrap().clone();
    st.jobs.get_mut(&first).unwrap().state = State::Cancelled;
    st.add(
        Job::from_request(&request(3, 1_000, 1_006, None)).unwrap(),
        &limits,
    )
    .unwrap();
    assert_eq!(st.jobs.len(), 3);
    let wide = Limits::default();
    let e = st
        .add(
            Job::from_request(&request(4, 1, 2_000, None)).unwrap(),
            &wide,
        )
        .unwrap_err();
    assert!(e.message().contains("spans"), "{e:?}");
    // A job id is a hash, never a path.
    assert!(st.archived("../../etc/passwd").is_none());
    assert!(service::loopback_only("127.0.0.1:1234"));
    assert!(service::loopback_only("[::1]:1234"));
    assert!(!service::loopback_only("0.0.0.0:1234"));
    let dead = || Rpc::new("http://127.0.0.1:1", "u", "p").unwrap();
    let e = service::serve(
        service::Clients {
            seq: SeqChain { rpc: dead() },
            btc: BtcChain { rpc: dead() },
            seq_cancels: SeqChain { rpc: dead() },
            btc_cancels: BtcChain { rpc: dead() },
            seq_intake: SeqChain { rpc: dead() },
            btc_intake: BtcChain { rpc: dead() },
        },
        &dir,
        "0.0.0.0:0",
        Duration::from_secs(1),
        Limits::default(),
        service::Access::default(),
    )
    .unwrap_err();
    assert!(e.0.contains("token"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fake Bitcoin daemon that judges a cancel as Bitcoin Core would for the test's
/// purposes: one whose last output pays 90,000 sat is the buyer's, signed; any other
/// fails its scripts. Its mempool holds the payments in `pooled`.
fn judging_daemon(pooled: Vec<bitcoin::Transaction>) -> String {
    fake_node(Box::new(move |m, p| match m {
        "testmempoolaccept" => {
            let hex = p[0][0].as_str().unwrap_or_default();
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(
                &lwk_wollet::btc::paylock::hex_decode(hex).unwrap(),
            )
            .unwrap();
            let id = tx.compute_txid();
            if pooled.iter().any(|t| t.compute_txid() == id) {
                return Ok(json!([{"allowed": false, "reject-reason": "txn-already-in-mempool"}]));
            }
            let v = tx.output.last().map(|o| o.value.to_sat()).unwrap_or(0);
            if v == 90_000 || v == 89_000 {
                Ok(json!([{"allowed": true, "fees": {"base": (100_000 - v) as f64 / 1e8}}]))
            } else if v == 99_999 {
                Ok(json!([{"allowed": false, "reject-reason": "insufficient fee"}]))
            } else {
                Ok(json!([{"allowed": false, "reject-reason":
                    "mandatory-script-verify-flag-failed (Witness program was passed an empty witness)"}]))
            }
        }
        "getrawtransaction" => {
            let id = p[0].as_str().unwrap_or_default();
            match pooled.iter().find(|t| t.compute_txid().to_string() == id) {
                Some(t) => Ok(json!(btc_hex(t))),
                None => Err((-5, "No such mempool transaction".into())),
            }
        }
        _ => Err((-32601, "no such method".into())),
    }))
}

fn intake_with(btc_url: &str, locks: Locks) -> Intake {
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    Intake::new(
        SeqChain {
            rpc: rpc(&seq_url, 3),
        },
        BtcChain {
            rpc: rpc(btc_url, 3),
        },
    )
}

/// What a client posts, checked and added, as the service does.
fn post_job(st: &mut Store, intake: &Intake, v: &Value) -> Result<(String, Added), String> {
    let mut j = Job::from_request(v).map_err(|e| e.0)?;
    let held = st.jobs.get(&j.id).cloned();
    service::check_intake(intake, &mut j, held.as_ref()).map_err(|e| e.message().to_string())?;
    st.add(j, &Limits::default())
        .map_err(|e| e.message().to_string())
}

/// The reviews' blocks of a buyer's job, by a client posting first: with no payment and a
/// dummy cancel of another coin; with the payment and an unsigned cancel of its coins;
/// with a subset of the claims. None of them is refused for coming second, none keeps the
/// buyer's cancel out, and what fails a check is refused whoever posts it.
#[test]
fn no_client_can_block_a_buyers_job() {
    let dir = tmpdir("noblock");
    let mut st = Store::open(&dir).unwrap();
    let t = terms(1_000, 1_006);
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    let locks: Locks = Default::default();
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let (pay, cancel) = payment_for(&t, 42, 1_000);
    let pay_id = pay.compute_txid().to_string();
    let cancel = btc_hex(&cancel);
    let intake = intake_with(&judging_daemon(vec![pay.clone()]), locks);
    // A lock the node does not hold: refused before anything else.
    let other = request_for(
        &t,
        OutPoint::new(Txid::from_byte_array([7; 32]), 0),
        &pay_id,
        None,
    );
    let e = post_job(&mut st, &intake, &other).unwrap_err();
    assert!(e.contains("not an unspent output"), "{e}");

    // No payment_hex, and a dummy cancel spending a coin the payment does not.
    let dummy = request_for(&t, lock, &pay_id, Some(btc_hex(&btc_spend(43, 90_000))));
    let e = post_job(&mut st, &intake, &dummy).unwrap_err();
    assert!(e.contains("exactly the payment's coins"), "{e}");
    // The payment itself and an unsigned spend of its coins.
    let mut unsigned = request_for(&t, lock, &pay_id, Some(btc_hex(&btc_spend(42, 1_000))));
    unsigned["payment_hex"] = json!(btc_hex(&pay));
    let e = post_job(&mut st, &intake, &unsigned).unwrap_err();
    assert!(e.contains("signatures do not verify"), "{e}");
    // One too cheap to replace the pooled payment.
    let mut cheap = request_for(&t, lock, &pay_id, Some(btc_hex(&btc_spend(42, 99_999))));
    cheap["payment_hex"] = json!(btc_hex(&pay));
    let e = post_job(&mut st, &intake, &cheap).unwrap_err();
    assert!(e.contains("replace the payment"), "{e}");
    // A first poster with only the top tier and no payment at all: held.
    let top = request_tiers(&t, lock, &pay_id, None, &[9_000]);
    let (id, added) = post_job(&mut st, &intake, &top).unwrap();
    assert_eq!(added, Added::New);
    // The mempool held the payment the post named: the service took it from there, as a
    // payment Bitcoin vouches for.
    assert!(st.jobs[&id].payments[0].vouched);
    // A claim the buyer did not sign, under the same name: refused.
    let mut forged = request_tiers(&t, lock, &pay_id, None, &[7_000]);
    let mut c: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(
        &lwk_wollet::btc::paylock::hex_decode(forged["claims"][0].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    c.input[0].witness.script_witness[1] = vec![0x11; 64];
    forged["claims"] = json!([hex_encode(&serialize(&c))]);
    let e = post_job(&mut st, &intake, &forged).unwrap_err();
    assert!(e.contains("not signed by the terms' buyer"), "{e}");
    // The buyer's whole handover: merged into the same job, nothing refused.
    let mut buyer = request_tiers(&t, lock, &pay_id, Some(cancel.clone()), &[1_000, 9_000]);
    buyer["payment_hex"] = json!(btc_hex(&pay));
    let (id2, added) = post_job(&mut st, &intake, &buyer).unwrap();
    assert_eq!(id2, id);
    assert_eq!(added, Added::Merged(vec!["claims", "cancels"]));
    assert_eq!(st.jobs[&id].claims.len(), 2);
    let p = &st.jobs[&id].payments[0];
    assert_eq!(p.cancels.len(), 1);
    assert_eq!(&*p.cancels[0].hex, cancel.as_str());
    assert_eq!(p.cancels[0].fee, 10_000);
    // A second valid cancel of the same coins is kept beside it, highest fee first.
    let mut second = buyer.clone();
    second["cancel"] = json!(btc_hex(&btc_spend(42, 89_000)));
    let (_, added) = post_job(&mut st, &intake, &second).unwrap();
    assert_eq!(added, Added::Merged(vec!["cancels"]));
    assert_eq!(st.jobs[&id].payments[0].cancels.len(), 2);
    assert_eq!(st.jobs[&id].payments[0].cancels[0].fee, 11_000);
    // The same again: held.
    let (_, again) = post_job(&mut st, &intake, &buyer).unwrap();
    assert_eq!(again, Added::Same);
    // The payment id a post names is only a hint: the buyer's cancel under another id is
    // placed by its coins with the payment held; a cancel of coins no payment held spends
    // is refused.
    let other_pay = "cd".repeat(32);
    let (_, again) = post_job(
        &mut st,
        &intake,
        &request_for(&t, lock, &other_pay, Some(cancel.clone())),
    )
    .unwrap();
    assert_eq!(again, Added::Same);
    let e = post_job(
        &mut st,
        &intake,
        &request_for(&t, lock, &other_pay, Some(btc_hex(&btc_spend(44, 90_000)))),
    )
    .unwrap_err();
    assert!(e.contains("exactly the payment's coins"), "{e}");
    assert_eq!(st.jobs.len(), 1);
    // What anyone reads holds no signed claim, cancel or payment.
    let public = st.jobs[&id].public_json().to_string();
    assert!(!public.contains(&cancel));
    assert!(!public.contains(&hex_encode(&serialize(&st.jobs[&id].claims[0]))));
    assert!(!public.contains(&btc_hex(&pay)));
    assert!(!public.contains(&pay_id));
    // Stored and read back, it is the same job.
    let st = Store::open(&dir).unwrap();
    assert_eq!(st.jobs[&id].payments[0].cancels.len(), 2);
    assert_eq!(st.jobs[&id].claims.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The payment is known by the coins it spends: a replacement that pays the seller is the
/// payment, whatever its id; a spend that does not pay is the cancel; the named payment
/// is the payment whatever it pays; and a coin that is merely missing decides nothing.
#[test]
fn a_payment_is_known_by_its_coins() {
    let t = terms(1_000, 1_006);
    let (pay, cancel) = payment_for(&t, 42, 1_000);
    let (bump, _) = payment_for(&t, 42, 3_000);
    assert_ne!(pay.compute_txid(), bump.compute_txid());
    let coins: Vec<bitcoin::OutPoint> = pay.input.iter().map(|i| i.previous_output).collect();
    let blocks: Arc<Mutex<Vec<Vec<bitcoin::Transaction>>>> = Arc::new(Mutex::new(vec![]));
    let b2 = blocks.clone();
    let btc_url = fake_node(Box::new(move |m, p| {
        let b = b2.lock().unwrap();
        match m {
            "getblockcount" => Ok(json!(1_000 + b.len() as u32)),
            "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
            "getblock" => {
                let h: u32 = u32::from_str_radix(p[0].as_str().unwrap(), 16).unwrap();
                match h.checked_sub(1_001) {
                    Some(i) => Ok(json!(raw_block(&b[i as usize]))),
                    None => Ok(json!(raw_block(&[]))),
                }
            }
            _ => Err((-32601, "no such method".into())),
        }
    }));
    let btc = BtcChain {
        rpc: rpc(&btc_url, 3),
    };
    let far = Instant::now() + Duration::from_secs(60);
    let pay_id = pay.compute_txid().to_string();
    let mut unrelated = btc_spend(5, 1);
    unrelated.output[0].script_pubkey = t.receive_script_pubkey();
    unrelated.output[0].value = bitcoin::Amount::from_sat(t.price_sat);

    // The bump, mined at 1,002 inside the window: it is the payment.
    *blocks.lock().unwrap() = vec![vec![unrelated.clone()], vec![bump.clone()]];
    let mut scan = lwk_paylock::PaymentScan::default();
    btc.scan_for(&pay_id, &coins, &t, &mut scan, 100, far)
        .unwrap();
    let f = scan.found.clone().expect("the bump is the payment");
    assert_eq!(
        (f.height, f.txid.clone()),
        (1_002, bump.compute_txid().to_string())
    );
    assert!(scan.cancel.is_none());
    // Without its coins, only the named id is the payment: the bump is not found.
    let mut scan = lwk_paylock::PaymentScan::default();
    btc.scan_for(&pay_id, &[], &t, &mut scan, 100, far).unwrap();
    assert!(scan.found.is_none());

    // The cancel mined at 1,001: a spend of the coins that does not pay. Read on: the
    // payment could still come from coins the cancel left (here it does not).
    *blocks.lock().unwrap() = vec![vec![cancel.clone()], vec![], vec![]];
    let mut scan = lwk_paylock::PaymentScan::default();
    btc.scan_for(&pay_id, &coins, &t, &mut scan, 100, far)
        .unwrap();
    assert!(scan.found.is_none());
    let c = scan.cancel.clone().expect("the cancel");
    assert_eq!(
        (c.height, c.txid),
        (1_001, cancel.compute_txid().to_string())
    );

    // The bump mined at D + 1: the payment, late; never mistaken for a cancel.
    let mut late = vec![vec![]; 6];
    late.push(vec![bump.clone()]);
    *blocks.lock().unwrap() = late;
    let mut scan = lwk_paylock::PaymentScan::default();
    btc.scan_for(&pay_id, &coins, &t, &mut scan, 100, far)
        .unwrap();
    assert_eq!(scan.found.as_ref().map(|f| f.height), Some(1_007));
    assert!(scan.cancel.is_none());
    assert!(matches!(
        lwk_paylock::payment_position(&t, &scan, true, 1_007),
        lwk_paylock::Position::Never(_)
    ));

    // Nothing mined: with its coins known, the search reads on past D + 6 to the tip, a
    // block at a time, and finds nothing; no coin's absence is read as a cancel.
    *blocks.lock().unwrap() = vec![vec![]; 20];
    let mut scan = lwk_paylock::PaymentScan::default();
    assert!(btc
        .scan_for(&pay_id, &coins, &t, &mut scan, 100, far)
        .unwrap());
    assert_eq!(scan.scanned.as_ref().map(|s| s.0), Some(1_020));
    assert!(scan.found.is_none() && scan.cancel.is_none());
}

/// A node without a transaction index cannot say whether it knows a lock: its answer
/// drops no cancel.
#[test]
fn a_node_without_a_transaction_index_drops_no_cancel() {
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let s2 = sent.clone();
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(1_001)),
        "sendrawtransaction" => {
            s2.lock().unwrap().push(p[0].as_str().unwrap().to_string());
            Ok(json!("00".repeat(32)))
        }
        _ => Err((-32601, "no such method".into())),
    }));
    let seq_url = fake_node(Box::new(|m, _| {
        match m {
        "getrawtransaction" => Err((
            -5,
            "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.".into(),
        )),
        _ => Err((-32601, "no such method".into())),
    }
    }));
    let dir = tmpdir("notxindex");
    let mut st = Store::open(&dir).unwrap();
    let cancel = btc_hex(&btc_spend(5, 1_000));
    st.add(
        holding(&request(5, 1_000, 1_003, Some(cancel.clone()))),
        &Limits::default(),
    )
    .unwrap();
    let store = Mutex::new(st);
    let n = service::send_due_cancels(
        &store,
        &BtcChain {
            rpc: rpc(&btc_url, 3),
        },
        &SeqChain {
            rpc: rpc(&seq_url, 3),
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(n, 1);
    assert_eq!(*sent.lock().unwrap(), vec![cancel]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cancel with a P2WPKH-shaped witness, spending the coin named by `n`; and a copy of it
/// with one byte of its signature changed: the same `txid`, another `wtxid`.
fn witnessed_cancel(n: u32) -> (bitcoin::Transaction, bitcoin::Transaction) {
    let mut good = btc_spend(n, 90_000);
    good.input[0].witness = bitcoin::Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]);
    let mut bad = good.clone();
    let mut sig = vec![0x30; 71];
    sig[10] ^= 1;
    bad.input[0].witness = bitcoin::Witness::from_slice(&[sig, vec![0x02; 33]]);
    assert_eq!(good.compute_txid(), bad.compute_txid());
    assert_ne!(good.compute_wtxid(), bad.compute_wtxid());
    (good, bad)
}

/// The payment's parent is not broadcast, so the
/// daemon can check no cancel. Another client posts first the buyer's own cancel with one
/// byte of its signature changed (same txid), then the buyer posts its valid one. Each
/// copy is held on its own; both are tried at D - 2 while neither can be checked; once
/// the parent is broadcast the bad one is dropped, the buyer's is checked, kept and sent.
/// In the other order too. Through the binary.
#[test]
fn a_bad_witness_copy_never_stands_in_for_the_buyers_cancel() {
    const T: u32 = 1_000;
    for bad_first in [true, false] {
        let tip = Arc::new(AtomicU32::new(T));
        let sent = Arc::new(Mutex::new(Vec::<String>::new()));
        let parent_known = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let t = terms(T - 1, T + 5);
        let (pay, _) = payment_for(&t, 61, 1_000);
        let (good, bad) = witnessed_cancel(61);
        let (good, bad) = (btc_hex(&good), btc_hex(&bad));
        let (pk, g) = (parent_known.clone(), good.clone());
        let btc_url = judged_daemon(
            tip.clone(),
            sent.clone(),
            Box::new(move |hex| {
                if !pk.load(Ordering::SeqCst) {
                    json!({"allowed": false, "reject-reason": "missing-inputs"})
                } else if hex == g {
                    json!({"allowed": true, "fees": {"base": 0.0001}})
                } else if hex.len() == g.len() {
                    json!({"allowed": false, "reject-reason":
                        "mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"})
                } else {
                    // The payment: its parent known, it is valid.
                    json!({"allowed": true, "fees": {"base": 0.00001}})
                }
            }),
            Arc::new(true.into()),
        );
        let locks: Locks = Default::default();
        let ltx = lock_tx(&t);
        let lock = OutPoint::new(ltx.txid(), 0);
        locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
        let seq_url = fake_seq(locks, Arc::new(true.into()));
        let dir = tmpdir(&format!("samewit-{bad_first}"));
        let (_serve, port) = serve(&dir, &seq_url, &btc_url);
        let pay_id = pay.compute_txid().to_string();
        let post_cancel = |c: &str, client: &str| {
            let mut r = request_for(&t, lock, &pay_id, Some(c.to_string()));
            r["payment_hex"] = json!(btc_hex(&pay));
            post_as(port, "/jobs", &r, Some(client))
        };
        let order = if bad_first {
            [(&bad, "198.51.100.7"), (&good, "203.0.113.9")]
        } else {
            [(&good, "203.0.113.9"), (&bad, "198.51.100.7")]
        };
        let mut id = String::new();
        for (c, who) in order {
            let (code, r) = post_cancel(c, who);
            assert_eq!(code, 200, "{r}");
            id = r["id"].as_str().unwrap().to_string();
        }
        let (_, j) = get(port, &format!("/jobs/{id}"));
        assert_eq!(
            (j["cancels"].as_u64(), j["pending_cancels"].as_u64()),
            (Some(0), Some(2)),
            "each copy is held on its own: {j}"
        );
        // D - 2, the parent still unbroadcast: both are tried.
        tip.store(T + 3, Ordering::SeqCst);
        let w = Instant::now();
        while !(sent.lock().unwrap().contains(&good) && sent.lock().unwrap().contains(&bad))
            && w.elapsed() < Duration::from_secs(10)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            sent.lock().unwrap().contains(&good),
            "the buyer's cancel was not tried"
        );
        // The parent and payment are broadcast: the bad copy is dropped, the buyer's kept.
        parent_known.store(true, Ordering::SeqCst);
        let w = Instant::now();
        loop {
            let (_, j) = get(port, &format!("/jobs/{id}"));
            if j["cancels"].as_u64() == Some(1) && j["pending_cancels"].as_u64() == Some(0) {
                eprintln!(
                    "bad first {bad_first}: the buyer's cancel checked and kept after {:?}: {}",
                    w.elapsed(),
                    j["note"]
                );
                break;
            }
            assert!(
                w.elapsed() < Duration::from_secs(20),
                "the buyer's cancel was never kept: {j}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        // The one kept is the buyer's: stored, and sent again.
        let stored: Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("{id}.json"))).unwrap())
                .unwrap();
        let held = &stored["payments"][0]["cancels"][0];
        assert_eq!(held["hex"], json!(good), "{stored}");
        assert_eq!(held["vouched"], json!(true));
        let n = sent.lock().unwrap().len();
        let w = Instant::now();
        while sent.lock().unwrap()[n..].iter().all(|h| *h != good)
            && w.elapsed() < Duration::from_secs(15)
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(sent.lock().unwrap()[n..].contains(&good));
        // The bad copy posted now is refused outright: its signatures can be checked.
        let (code, r) = post_cancel(&bad, "198.51.100.8");
        assert_eq!(code, 400, "{r}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The same rules at the library's level: copies are told apart by `wtxid`; a vouched
/// copy makes the unchecked copies of its transaction redundant and is never displaced.
#[test]
fn cancels_are_held_by_witness_id() {
    let dir = tmpdir("wtxid");
    let mut st = Store::open(&dir).unwrap();
    let t = terms(1_000, 1_006);
    let lock = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let (pay, _) = payment_for(&t, 71, 1_000);
    let (good, bad) = witnessed_cancel(71);
    let base = Job::from_request(&request_for(&t, lock, &"ab".repeat(32), None))
        .unwrap()
        .to_json();
    let with = |cancels: Value, pending: Value| {
        let mut v = base.clone();
        v["payments"] = json!([{"hex": btc_hex(&pay), "vouched": true, "by": "x",
            "cancels": cancels, "pending": pending}]);
        Job::from_stored(&v).unwrap()
    };
    let l = Limits::default();
    let (id, a) = st
        .add(
            with(json!([]), json!([{"hex": btc_hex(&bad), "by": "x"}])),
            &l,
        )
        .unwrap();
    assert_eq!(a, Added::New);
    // The buyer's copy, same txid: held beside the bad one.
    let (_, a) = st
        .add(
            with(json!([]), json!([{"hex": btc_hex(&good), "by": "y"}])),
            &l,
        )
        .unwrap();
    assert_eq!(a, Added::Merged(vec!["pending_cancels"]));
    assert_eq!(st.jobs[&id].payments[0].pending.len(), 2);
    // Checked and vouched for: it is kept, and the unchecked copies give way.
    let (_, a) = st
        .add(
            with(
                json!([{"hex": btc_hex(&good), "fee": 1_000, "vouched": true}]),
                json!([]),
            ),
            &l,
        )
        .unwrap();
    assert_eq!(a, Added::Merged(vec!["cancels"]));
    let p = &st.jobs[&id].payments[0];
    assert_eq!((p.cancels.len(), p.pending.len()), (1, 0));
    // No copy of it, unchecked or unvouched, is taken beside it, nor displaces it.
    for j in [
        with(json!([]), json!([{"hex": btc_hex(&bad), "by": "z"}])),
        with(
            json!([{"hex": btc_hex(&bad), "fee": 5_000, "vouched": false}]),
            json!([]),
        ),
    ] {
        assert_eq!(st.add(j, &l).unwrap().1, Added::Same);
    }
    assert_eq!(
        &*st.jobs[&id].payments[0].cancels[0].hex,
        btc_hex(&good).as_str()
    );
    // Stored and read back, the same.
    let st = Store::open(&dir).unwrap();
    assert_eq!(
        &*st.jobs[&id].payments[0].cancels[0].hex,
        btc_hex(&good).as_str()
    );
    assert!(st.jobs[&id].payments[0].cancels[0].vouched);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A request never names what the service
/// keeps of its own. Unchecked cancels (`pending`), a cancel's fee or standing, and the
/// client are not read from it; a post carrying 17 made-up `pending` entries holds none.
#[test]
fn a_request_names_nothing_the_service_keeps_of_its_own() {
    let t = terms(1_000, 1_006);
    let lock = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let mut v = request_for(&t, lock, &"ab".repeat(32), None);
    v["pending"] = json!((0..17)
        .map(|i| json!({"hex": btc_hex(&btc_spend(500 + i, 1_000)), "by": "someone"}))
        .collect::<Vec<_>>());
    v["client"] = json!("10.1.1.1");
    v["state"] = json!("final");
    v["cancel_sent"] = json!(true);
    let j = Job::from_request(&v).unwrap();
    assert!(j.payments.is_empty() && j.loose.is_empty());
    assert_eq!(j.client, "");
    assert_eq!(j.state, State::Waiting);
    assert!(!j.cancel_sent);
    // A cancel is a raw transaction: the stored form, with its fee, is refused.
    let mut w = request_for(&t, lock, &"ab".repeat(32), None);
    w["cancels"] = json!([{"hex": btc_hex(&btc_spend(42, 90_000)), "fee": 99_999}]);
    let e = Job::from_request(&w).unwrap_err();
    assert!(e.0.contains("raw Bitcoin transaction"), "{e}");
    let mut w = request_for(&t, lock, &"ab".repeat(32), None);
    w["cancels"] = json!([btc_hex(&btc_spend(42, 90_000))]);
    let j = Job::from_request(&w).unwrap();
    assert_eq!(
        (j.loose.len(), j.loose[0].fee, j.loose[0].vouched),
        (1, 0, false)
    );
    // Nor is the stored form of a payment: `payments` is not read from a request.
    let mut w = request_for(&t, lock, &"ab".repeat(32), None);
    w["payments"] = json!([{"hex": btc_hex(&payment_for(&t, 9, 1_000).0), "vouched": true}]);
    assert!(Job::from_request(&w).unwrap().payments.is_empty());

    // Through the binary: the post is a job with no unchecked cancel at all.
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(1_000)),
        Default::default(),
        Box::new(|_| json!({"allowed": true, "fees": {"base": 0.0001}})),
        Arc::new(true.into()),
    );
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let real = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(real.txid.to_string(), ltx);
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("wirepending");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let mut v = request_for(&t, real, &"ab".repeat(32), None);
    v["pending"] = json!((0..17)
        .map(|i| json!({"hex": btc_hex(&btc_spend(500 + i, 1_000)), "by": "someone"}))
        .collect::<Vec<_>>());
    let (code, r) = post_as(port, "/jobs", &v, Some("198.51.100.20"));
    assert_eq!(code, 200, "{r}");
    let (_, j) = get(port, &format!("/jobs/{}", r["id"].as_str().unwrap()));
    assert_eq!(
        (j["cancels"].as_u64(), j["pending_cancels"].as_u64()),
        (Some(0), Some(0)),
        "{j}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The seller holds the buyer's signed claims, which verify whatever payment id they are
/// posted with. Posting them first on the buyer's lock with made-up payment ids, from
/// many addresses, takes nothing: every post for a lock merges into its one job, and a
/// payment id is only a hint. Payments nobody can check yet (their parents unknown to the
/// daemon) are held within a bound and refused beyond it; the buyer's payment, which the
/// daemon accepts (and the service broadcasts), is taken whatever is held, with its
/// cancel. Through the binary.
#[test]
fn nothing_unverified_holds_a_buyers_lock() {
    const T: u32 = 1_000;
    let t = terms(T - 1, T + 5);
    let (pay, cancel) = payment_for(&t, 81, 1_000);
    let (pay_hex, cancel_hex) = (btc_hex(&pay), btc_hex(&cancel));
    let (ph, ch) = (pay_hex.clone(), cancel_hex.clone());
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(T)),
        sent.clone(),
        Box::new(move |hex| {
            if hex == ph || hex == ch {
                json!({"allowed": true, "fees": {"base": 0.0001}})
            } else {
                json!({"allowed": false, "reject-reason": "missing-inputs"})
            }
        }),
        Arc::new(true.into()),
    );
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("lockheld");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    // The seller's posts: the buyer's claims, made-up payment ids, many addresses.
    let mut ids = std::collections::BTreeSet::new();
    for i in 0..60u32 {
        let (code, r) = post_as(
            port,
            "/jobs",
            &request_for(
                &t,
                lock,
                &format!("{:064x}", 0xfeed_0000u64 + u64::from(i)),
                None,
            ),
            Some(&format!("198.51.100.{}", i % 30)),
        );
        assert_eq!(code, 200, "{r}");
        ids.insert(r["id"].as_str().unwrap().to_string());
    }
    assert_eq!(ids.len(), 1, "one job per lock");
    let id = ids.into_iter().next().unwrap();
    // Payments nobody can check yet: eight held (two per address), then refused.
    let mut codes = vec![];
    for i in 0..12u32 {
        let (junk, _) = payment_for(&t, 900 + i, 1_000);
        let mut r = request_for(&t, lock, &junk.compute_txid().to_string(), None);
        r["payment_hex"] = json!(btc_hex(&junk));
        codes.push(post_as(port, "/jobs", &r, Some(&format!("192.0.2.{}", i / 2))).0);
    }
    assert_eq!(&codes[..8], &[200; 8]);
    assert!(codes[8..].iter().all(|c| *c == 429), "{codes:?}");
    let (_, j) = get(port, &format!("/jobs/{id}"));
    assert_eq!(j["unvouched_payments"], json!(8), "{j}");
    // The buyer's payment and cancel, after all that: taken, the payment broadcast.
    let mut buyer = request_for(
        &t,
        lock,
        &pay.compute_txid().to_string(),
        Some(cancel_hex.clone()),
    );
    buyer["payment_hex"] = json!(pay_hex);
    let (code, r) = post_as(port, "/jobs", &buyer, Some("203.0.113.50"));
    assert_eq!(code, 200, "{r}");
    assert_eq!(r["id"], json!(id));
    let (_, j) = get(port, &format!("/jobs/{id}"));
    assert_eq!(
        (
            j["payments"].as_u64(),
            j["unvouched_payments"].as_u64(),
            j["cancels"].as_u64()
        ),
        (Some(9), Some(8), Some(1)),
        "{j}"
    );
    assert!(
        sent.lock().unwrap().contains(&pay_hex),
        "the payment was not broadcast"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The limits on live jobs never refuse a post whose payment Bitcoin vouches for: such a
/// job is taken past them. A job with nothing verified is refused at them.
#[test]
fn a_paying_post_is_never_refused_for_a_limit() {
    let dir = tmpdir("paying");
    let mut st = Store::open(&dir).unwrap();
    let limits = Limits {
        max_jobs: 1,
        jobs_per_client: 1,
        ..Limits::default()
    };
    let t = terms(1_000, 1_006);
    let job = |n: u32, vouched: bool| {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&n.to_le_bytes());
        let lock = OutPoint::new(Txid::from_byte_array(id), 0);
        let mut v = Job::from_request(&request_for(&t, lock, &"ab".repeat(32), None))
            .unwrap()
            .to_json();
        if vouched {
            v["payments"] =
                json!([{"hex": btc_hex(&payment_for(&t, n, 1_000).0), "vouched": true}]);
        }
        Job::from_stored(&v).unwrap()
    };
    st.add(job(1, false), &limits).unwrap();
    let e = st.add(job(2, false), &limits).unwrap_err();
    assert_eq!(e.status(), 429);
    let (_, a) = st.add(job(3, true), &limits).unwrap();
    assert_eq!(a, Added::New);
    assert_eq!(st.jobs.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The payment is whatever Bitcoin mines in the lock's heights paying the terms'
/// receiving script at least the price: whoever made it, whatever coins it spends, held
/// or not. A paying transaction at or below the floor, or after the deadline, opens
/// nothing and hides nothing. A held payment's coins spent by a transaction that does
/// not pay settle it as cancelled.
#[test]
fn the_payment_is_whatever_bitcoin_mines_paying_the_terms() {
    let t = terms(1_000, 1_006);
    let (held, cancel) = payment_for(&t, 42, 1_000);
    let (stranger, _) = payment_for(&t, 77, 1_000);
    let (early, _) = payment_for(&t, 78, 1_000);
    let blocks: Arc<Mutex<Vec<Vec<bitcoin::Transaction>>>> = Arc::new(Mutex::new(vec![]));
    let b2 = blocks.clone();
    let btc_url = fake_node(Box::new(move |m, p| {
        let b = b2.lock().unwrap();
        match m {
            "getblockcount" => Ok(json!(999 + b.len() as u64)),
            "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
            "getblock" => {
                let h = u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap();
                Ok(json!(raw_block(&b[(h - 1000) as usize])))
            }
            _ => Err((-32601, "no such method".into())),
        }
    }));
    let btc = BtcChain {
        rpc: rpc(&btc_url, 3),
    };
    let coins = vec![held
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect::<Vec<_>>()];
    let far = Instant::now() + Duration::from_secs(30);
    // Block 1000 (= F): a paying transaction at the floor; 1001: the held payment's
    // cancel; 1002: a stranger's payment.
    *blocks.lock().unwrap() = vec![vec![early], vec![cancel.clone()], vec![stranger.clone()]];
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    // The scan takes nothing: the stranger's payment is a candidate, not yet the payment.
    assert!(scan.found.is_none());
    let f = scan
        .ordered()
        .first()
        .cloned()
        .expect("the stranger's payment may open the lock");
    assert_eq!(
        (f.at.height, f.at.txid, f.held),
        (1002, stranger.compute_txid().to_string(), false)
    );
    let s = settled[0].clone().expect("the held payment is settled");
    assert_eq!((s.at.height, s.paid), (1001, false));
    // Mined after the deadline only: noted late, nothing found.
    *blocks.lock().unwrap() = (0..8)
        .map(|h| if h == 7 { vec![held.clone()] } else { vec![] })
        .collect();
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        false,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    assert!(scan.found.is_none() && scan.candidates.is_empty());
    assert_eq!(scan.late.map(|f| f.height), Some(1007));
    assert_eq!(settled[0].clone().map(|s| s.paid), Some(true));
}

/// `t`'s payment from coin `n` padded with an OP_RETURN of `pad` bytes: past 100,000 bytes
/// without its witness, no proof can carry it.
fn padded_payment(t: &PayLockTerms, n: u32, pad: usize) -> bitcoin::Transaction {
    let (mut pay, _) = payment_for(t, n, 1_000);
    let mut data = vec![0x6a, 0x4e];
    data.extend((pad as u32).to_le_bytes());
    data.extend(std::iter::repeat(0xab).take(pad));
    pay.output.push(bitcoin::TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from(data),
    });
    pay
}

#[test]
fn a_payment_no_proof_can_carry_opens_nothing() {
    let t = terms(1_000, 1_006);
    let (held, _) = payment_for(&t, 42, 1_000);
    let (stranger, _) = payment_for(&t, 77, 1_000);
    let (other, _) = payment_for(&t, 79, 1_000);
    let big = padded_payment(&t, 78, 100_500);
    assert!(big.base_size() > 100_000);
    assert!(!lwk_paylock::provable(&big));
    assert!(lwk_paylock::provable(&held));
    // 64 bytes without witness: an inner node of the merkle tree, never a payment.
    let mut tiny = btc_spend(5, 1);
    tiny.output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0x51; 4]);
    assert_eq!(tiny.base_size(), 64);
    assert!(!lwk_paylock::provable(&tiny));
    tiny.output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0x51; 5]);
    assert!(lwk_paylock::provable(&tiny));

    let blocks: Arc<Mutex<Vec<Vec<bitcoin::Transaction>>>> = Arc::new(Mutex::new(vec![]));
    let b2 = blocks.clone();
    let btc_url = fake_node(Box::new(move |m, p| {
        let b = b2.lock().unwrap();
        match m {
            "getblockcount" => Ok(json!(999 + b.len() as u64)),
            "getblockhash" => Ok(json!(format!("{:064x}", p[0].as_u64().unwrap()))),
            "getblock" => {
                let h = u64::from_str_radix(p[0].as_str().unwrap(), 16).unwrap();
                Ok(json!(raw_block(&b[(h - 1000) as usize])))
            }
            _ => Err((-32601, "no such method".into())),
        }
    }));
    let btc = BtcChain {
        rpc: rpc(&btc_url, 3),
    };
    let coins = vec![held
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect::<Vec<_>>()];
    let far = Instant::now() + Duration::from_secs(30);
    let id = |t: &bitcoin::Transaction| t.compute_txid().to_string();

    // 1001: the unprovable payment; 1002: the buyer's. The first is no candidate.
    *blocks.lock().unwrap() = vec![vec![], vec![big.clone()], vec![held.clone()]];
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    let ids = |s: &lwk_paylock::PaymentScan| {
        s.ordered()
            .into_iter()
            .map(|c| (c.at.height, c.at.txid))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&scan), vec![(1002, id(&held))]);
    let u = scan
        .unprovable
        .clone()
        .expect("the unprovable one is shown");
    assert_eq!((u.height, u.txid), (1001, id(&big)));
    assert_eq!(
        settled[0].clone().map(|s| (s.at.height, s.paid)),
        Some((1002, true))
    );

    // Only the unprovable payment in the window: no candidate, so nothing is paid in it.
    *blocks.lock().unwrap() = (0..8)
        .map(|h| if h == 1 { vec![big.clone()] } else { vec![] })
        .collect();
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    assert!(btc
        .scan_lock(
            &mut lwk_paylock::BlockCache::default(),
            &t,
            &coins,
            &mut settled,
            false,
            &mut scan,
            100,
            far
        )
        .unwrap());
    assert!(scan.found.is_none() && scan.late.is_none() && scan.candidates.is_empty());
    assert_eq!(scan.unprovable.as_ref().map(|f| f.height), Some(1001));
    assert_eq!(
        lwk_paylock::payment_position(&t, &scan, true, 1_007),
        lwk_paylock::Position::Never(
            "no payment was mined by the deadline (Bitcoin block 1006)".into()
        )
    );

    // Its coins spent by an unprovable payment, a payment held is settled as unpaid.
    let mut held_big = padded_payment(&t, 42, 100_500);
    held_big.input = held.input.clone();
    *blocks.lock().unwrap() = vec![vec![], vec![held_big]];
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    assert!(scan.candidates.is_empty());
    assert_eq!(
        settled[0].clone().map(|s| (s.at.height, s.paid)),
        Some((1001, false))
    );

    // Across the whole window, a payment held comes first, then the rest by the lightest
    // proof they make: here a stranger's padded but provable payment in an earlier block
    // and a plain one in a later block.
    let heavy = padded_payment(&t, 80, 90_000);
    assert!(lwk_paylock::provable(&heavy));
    *blocks.lock().unwrap() = vec![
        vec![],
        vec![heavy.clone()],
        vec![stranger.clone()],
        vec![held.clone(), other.clone()],
    ];
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    assert_eq!(
        ids(&scan),
        vec![
            (1003, id(&held)),
            (1002, id(&stranger)),
            (1003, id(&other)),
            (1001, id(&heavy)),
        ]
    );
    let order = scan.ordered();
    assert!(order[0].held && !order[1].held);
    assert!(order[3].min_proof > 90_000);

    // A candidate passed over (the node refused every claim on it for its weight) passes
    // over every candidate whose lightest proof is as heavy, until what refused it can have
    // changed: the node's floor in the fee asset falls below the rate it refused, or an
    // asset no tier could pay in is accepted. A block arriving changes neither.
    let tip = 1_003;
    let asset = lwk_wollet::elements::AssetId::from_slice(&[5; 32]).unwrap();
    let other_asset = lwk_wollet::elements::AssetId::from_slice(&[6; 32]).unwrap();
    let (paid, need) = lwk_paylock::refusal_figures(
        "the node refused: min relay fee not met, 5000 < 8356 (code 66)",
    )
    .unwrap();
    assert_eq!((paid, need), (5_000, 8_356));
    let floors = |rate: u64, rates: &[(lwk_wollet::elements::AssetId, u64)]| lwk_paylock::Floors {
        known: true,
        rate,
        rates: rates.iter().cloned().collect(),
    };
    let at = floors(1_000, &[(asset, 100_000_000)]);
    scan.passed.push(lwk_paylock::Passed {
        at: order[3].at.clone(),
        proof: order[3].min_proof,
        why: "min relay fee not met, 5000 < 8356".into(),
        tip,
        retry: lwk_paylock::Retry::Floor {
            refused: vec![lwk_paylock::Refusal::new(
                asset,
                5_000,
                "min relay fee not met, 5000 < 8356",
                &at,
                None,
            )],
            untried: vec![other_asset],
        },
    });
    assert!(scan.is_passed(&order[3]).is_some());
    assert!(scan.is_passed(&order[0]).is_none());
    scan.passed[0].proof = order[1].min_proof;
    assert!(scan.is_passed(&order[1]).is_some() && scan.is_passed(&order[2]).is_some());
    let p = &scan.passed[0];
    // The same floor, however many blocks later: not tried again.
    assert!(!p.retry_due(&at));
    // The floor down, but not below the rate refused (5,000 / 8,356 of it): not yet.
    assert!(!p.retry_due(&floors(700, &[(asset, 100_000_000)])));
    // Below it: tried again. So too when the asset's rate rises as much.
    assert!(p.retry_due(&floors(598, &[(asset, 100_000_000)])));
    assert!(p.retry_due(&floors(1_000, &[(asset, 168_000_000)])));
    // The asset no tier could pay in is accepted: tried again.
    assert!(p.retry_due(&floors(1_000, &[(asset, 100_000_000), (other_asset, 1)])));
    // Unread floors bring nothing back; a record that says nothing is tried again.
    assert!(!p.retry_due(&lwk_paylock::Floors::default()));
    let mut q = p.clone();
    q.retry = lwk_paylock::Retry::Unknown;
    assert!(q.retry_due(&at));
    q.retry = lwk_paylock::Retry::Never;
    assert!(!q.retry_due(&floors(0, &[(asset, u64::MAX)])));

    // The claim's own signed fee decides, never the node's figure for its worth, which is
    // rounded down: at a rate of 1 a fee of 5,000 atoms reads `0 < 304`. Whatever the rate
    // the refusal came at, the claim is tried again once its fee covers the ask, and not
    // before.
    let normal = floors(1_000, &[(asset, 100_000_000)]);
    for low in [1u64, 100_000, 100_000_000] {
        let (relay, worth) = if low == 100_000_000 {
            (100_000, 5_000)
        } else {
            (1_000, lwk_paylock::fee_worth(5_000, low))
        };
        let need = 304 * relay / 1_000;
        let then = floors(relay, &[(asset, low)]);
        let r = lwk_paylock::Refusal::new(
            asset,
            5_000,
            &format!("min relay fee not met, {worth} < {need} (code -26)"),
            &then,
            Some(&then),
        );
        assert!(r.trusted, "{r:?}");
        assert!(!r.may_clear(&then), "{r:?}");
        assert!(r.may_clear(&normal), "rate {low}: {r:?}");
        assert!(r.margin(&normal) > 10.0, "{r:?}");
        // Halfway back is not enough for a floor 100 times too high.
        let half = floors(
            relay / 2,
            &[(asset, low.saturating_mul(2).min(100_000_000))],
        );
        assert!(!r.may_clear(&half), "{r:?}");
    }
    // A refusal without figures (`mempool full`) or whose figures are not the signed fee's
    // worth at the rate read (the rate moved under it) says nothing of when the claim
    // lands: tried again at any floors other than those it was refused at, a higher floor
    // included, once.
    for m in ["mempool full", "min relay fee not met, 77 < 8356"] {
        let r = lwk_paylock::Refusal::new(asset, 5_000, m, &at, None);
        assert!(!r.trusted, "{m}");
        assert!(!r.may_clear(&at), "{m}");
        assert!(r.may_clear(&floors(1_001, &[(asset, 100_000_000)])), "{m}");
        assert!(r.may_clear(&floors(1_000, &[(asset, 99_000_000)])), "{m}");
        // Not while the node does not take the asset, nor with the floors unread.
        assert!(!r.may_clear(&floors(10, &[(other_asset, 1)])), "{m}");
        assert!(!r.may_clear(&lwk_paylock::Floors::default()), "{m}");
    }

    // A reorganization below the scan's place drops every candidate and everything passed
    // over: the scan reads again from the floor, on the new branch.
    let mut reorged = blocks.lock().unwrap().clone();
    reorged[2] = vec![];
    *blocks.lock().unwrap() = reorged;
    scan.scanned = Some((1003, format!("{:064x}", 0xdead)));
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    assert!(scan.passed.is_empty());
    assert_eq!(
        ids(&scan),
        vec![(1003, id(&held)), (1003, id(&other)), (1001, id(&heavy))]
    );

    // Only the lightest non-held candidates are kept.
    let many: Vec<bitcoin::Transaction> = (0..40)
        .map(|n| padded_payment(&t, 200 + n, 100 + 10 * n as usize))
        .collect();
    *blocks.lock().unwrap() = vec![vec![], many.clone(), vec![held.clone()]];
    let mut scan = lwk_paylock::PaymentScan::default();
    let mut settled = vec![None];
    btc.scan_lock(
        &mut lwk_paylock::BlockCache::default(),
        &t,
        &coins,
        &mut settled,
        true,
        &mut scan,
        100,
        far,
    )
    .unwrap();
    assert_eq!(scan.candidates.len(), lwk_paylock::MAX_CANDIDATES + 1);
    let kept = ids(&scan);
    assert_eq!(kept[0], (1002, id(&held)));
    assert_eq!(kept[1], (1001, id(&many[0])));
    assert!(!kept.contains(&(1001, id(&many[39]))));
}

/// A connection from `source` (a loopback address of its own) to the service.
fn connect_from(source: &str, port: u16) -> std::io::Result<TcpStream> {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    s.bind(
        &format!("{source}:0")
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )?;
    s.connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        Duration::from_secs(2),
    )?;
    Ok(s.into())
}

/// A raw request to the service; its status line and JSON body, or what went wrong.
fn try_request(port: u16, req: &str) -> Result<(u16, Value), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let code = out
        .get(9..12)
        .and_then(|c| c.parse().ok())
        .ok_or(out.clone())?;
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("null");
    Ok((
        code,
        serde_json::from_str(body).map_err(|e| format!("{e}: {out}"))?,
    ))
}

/// One client keeps 300 connections open that send nothing,
/// opening a new one for each the service closes. A buyer's posts and reads beside it
/// are answered at once, whether the flood comes from another address or from the
/// buyer's own (its idle connections give way to the buyer's). Through the binary.
#[test]
fn idle_connections_take_no_one_elses_slot() {
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(1_000)),
        Default::default(),
        Box::new(|_| json!({"allowed": true, "fees": {"base": 0.0001}})),
        Arc::new(true.into()),
    );
    let t = terms(999, 1_005);
    let locks: Locks = Default::default();
    let ltx = lock_tx(&t);
    let lock = OutPoint::new(ltx.txid(), 0);
    locks.lock().unwrap().insert(lock.txid.to_string(), ltx);
    let seq_url = fake_seq(locks, Arc::new(true.into()));
    let dir = tmpdir("idleconns");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    for source in ["127.0.0.2", "127.0.0.1"] {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let opened = Arc::new(AtomicU32::new(0));
        let (st, op, src) = (stop.clone(), opened.clone(), source.to_string());
        let flood = std::thread::spawn(move || {
            let mut held: Vec<TcpStream> = vec![];
            while !st.load(Ordering::SeqCst) {
                // Drop those the service closed, and open new ones in their place.
                held.retain(|k| {
                    k.set_nonblocking(true).unwrap();
                    let mut b = [0u8; 1];
                    matches!({ let mut r: &TcpStream = k; r.read(&mut b) }, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
                });
                while held.len() < 300 && !st.load(Ordering::SeqCst) {
                    match connect_from(&src, port) {
                        Ok(k) => {
                            held.push(k);
                            op.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => break,
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        std::thread::sleep(Duration::from_secs(3));
        let mut posts = vec![];
        let mut reads = vec![];
        for i in 0..10 {
            let mut r = request_for(&t, lock, &format!("{:064x}", 0xee00 + i % 3), None);
            r["payment_hex"] = Value::Null;
            let b = r.to_string();
            let started = Instant::now();
            let p = try_request(
                port,
                &format!(
                    "POST /jobs HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                ),
            );
            posts.push((
                p.as_ref().map(|x| x.0).map_err(|e| e.clone()),
                started.elapsed(),
            ));
            let started = Instant::now();
            let g = try_request(
                port,
                "GET /jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            );
            reads.push((
                g.as_ref().map(|x| x.0).map_err(|e| e.clone()),
                started.elapsed(),
            ));
            assert_eq!(
                p.as_ref().map(|x| x.0),
                Ok(200),
                "the buyer's post {i}: {p:?}"
            );
            assert_eq!(g.as_ref().map(|x| x.0), Ok(200), "read {i}: {g:?}");
            std::thread::sleep(Duration::from_millis(300));
        }
        stop.store(true, Ordering::SeqCst);
        flood.join().unwrap();
        eprintln!(
            "flood from {source} ({} connections opened): posts {posts:?}; reads {reads:?}",
            opened.load(Ordering::SeqCst)
        );
        assert!(opened.load(Ordering::SeqCst) >= 300);
        // The flood gone, the buyer is served at once.
        let (code, r) = post(
            port,
            "/jobs",
            &request_for(&t, lock, &format!("{:064x}", 0xee00), None),
        );
        assert_eq!(code, 200, "{r}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A connection refused because every slot is taken reads its JSON
/// answer, never a reset. Every slot is held by a body being sent slowly, each from an
/// address of its own; the next connection sends its request and reads `503` with a JSON
/// body, to its end. Through the binary.
#[test]
fn a_refused_connection_reads_its_answer() {
    let btc_url = judged_daemon(
        Arc::new(AtomicU32::new(1_000)),
        Default::default(),
        Box::new(|_| json!({"allowed": true, "fees": {"base": 0.0001}})),
        Arc::new(true.into()),
    );
    let seq_url = fake_seq(Default::default(), Arc::new(true.into()));
    let dir = tmpdir("refused");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let mut slow = vec![];
    let started = Instant::now();
    for i in 0..256 {
        // Each from an address of its own, so none waits on its own address's share.
        let mut s = connect_from(&format!("127.0.1.{i}"), port).unwrap();
        write!(
            s,
            "POST /jobs HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{{"
        )
        .unwrap();
        slow.push(s);
    }
    std::thread::sleep(Duration::from_millis(300));
    // Every slow body holds its slot, unanswered.
    let answered: Vec<(usize, String)> = slow
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            s.set_nonblocking(true).unwrap();
            let mut b = [0u8; 200];
            let mut r: &TcpStream = s;
            let r = r.read(&mut b);
            s.set_nonblocking(false).unwrap();
            match r {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                Ok(n) => Some((i, String::from_utf8_lossy(&b[..n]).to_string())),
                Err(e) => Some((i, e.to_string())),
            }
        })
        .collect();
    assert!(
        answered.is_empty(),
        "slow bodies answered before the deadline: {answered:?}"
    );
    let mut answers = vec![];
    for _ in 0..3 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = write!(
            s,
            "GET /jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let mut out = String::new();
        let r = s.read_to_string(&mut out);
        let reset = r.is_err();
        answers.push(format!(
            "{:?} {}",
            r.err().map(|e| e.kind()),
            out.lines().next().unwrap_or("")
        ));
        assert!(out.starts_with("HTTP/1.1 503"), "{answers:?}");
        // Read to its end: closed, not reset.
        assert!(!reset, "{answers:?}");
        let body = out.split("\r\n\r\n").nth(1).unwrap_or_default();
        let v: Value = serde_json::from_str(body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("busy"), "{v}");
    }
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the slow bodies timed out first"
    );
    eprintln!("past every slot: {answers:?}");
    drop(slow);
    // The slots come back.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(get(port, "/jobs").0, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

/// What a client hands over is kept no larger than the buyer's own: a claim's unsigned
/// witness parts (which completing it writes) are cleared, so a copy padded there is the
/// buyer's claim byte for byte; a cancel or a payment over the size cap is refused.
#[test]
fn intake_keeps_nothing_larger_than_the_buyers_own() {
    let t = terms(1_000, 1_006);
    let lock = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let plain = request_for(&t, lock, &"ab".repeat(32), None);
    let mut padded = plain.clone();
    let mut c: Transaction = lwk_wollet::elements::encode::deserialize(
        &paylock::hex_decode(plain["claims"][0].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    c.input[0].witness.script_witness[0] = vec![0x77; 100_000];
    c.input[0].witness.pegin_witness = vec![vec![0x66; 100_000]];
    padded["claims"] = json!([hex_encode(&serialize(&c))]);
    let a = Job::from_request(&plain).unwrap();
    let b = Job::from_request(&padded).unwrap();
    assert_eq!(serialize(&a.claims[0]), serialize(&b.claims[0]));
    assert!(serialize(&b.claims[0]).len() < 2_000);
    // A cancel over the cap.
    let mut big = btc_spend(42, 90_000);
    big.input[0].witness = bitcoin::Witness::from_slice(&[vec![0x30; service::MAX_TX_BYTES]]);
    let e = Job::from_request(&request_for(
        &t,
        lock,
        &"ab".repeat(32),
        Some(btc_hex(&big)),
    ))
    .unwrap_err();
    assert!(e.0.contains("at most"), "{e}");
}

/// Cancel contention: 2,000 jobs whose cancels fall due at the same tip as a
/// buyer's, from as many addresses, all holding one payment (the same coins) and its one
/// cancel. They are one payment to the cancel thread: one send between them, so the
/// buyer's cancel goes out in the first two sends, and every one of the jobs is marked
/// sent by that one send.
#[test]
fn jobs_sharing_a_payment_cost_one_cancel_send() {
    const D: u32 = 1_006;
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let c2 = calls.clone();
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "getblockcount" => Ok(json!(D - 2)),
        "sendrawtransaction" => {
            std::thread::sleep(Duration::from_millis(1));
            let hex = p[0].as_str().unwrap_or_default().to_string();
            let mut c = c2.lock().unwrap();
            let again = c.contains(&hex);
            c.push(hex);
            if again {
                Err((-27, "txn-already-in-mempool".into()))
            } else {
                Ok(json!("00".repeat(32)))
            }
        }
        _ => Err((-32601, "no such method".into())),
    }));
    let seq_url = fake_seq(Default::default(), Arc::new(true.into()));
    let dir = tmpdir("sharedcancel");
    let store = Mutex::new(Store::open(&dir).unwrap());
    let limits = Limits {
        jobs_per_client: 0,
        max_jobs: 100_000,
        ..Limits::default()
    };
    let shared_cancel = btc_hex(&btc_spend(7, 90_000));
    let buyer_cancel = btc_hex(&btc_spend(999, 90_000));
    {
        let mut st = store.lock().unwrap();
        for n in 0..2_000u32 {
            let mut j = holding(&request(n, 1_000, D, Some(shared_cancel.clone())));
            j.lock_known = Some(true);
            j.client = format!("100.64.{}.{}", n / 250, n % 250);
            st.add(j, &limits).unwrap();
        }
        let mut j = holding(&request(5_000, 1_000, D, Some(buyer_cancel.clone())));
        j.lock_known = Some(true);
        j.client = "203.0.113.92".into();
        st.add(j, &limits).unwrap();
    }
    let t = Instant::now();
    let n = service::send_due_cancels(
        &store,
        &BtcChain {
            rpc: rpc(&btc_url, 3),
        },
        &SeqChain {
            rpc: rpc(&seq_url, 3),
        },
        &limits,
    )
    .unwrap();
    let took = t.elapsed();
    let c = calls.lock().unwrap().clone();
    let at = c.iter().position(|h| *h == buyer_cancel);
    let st = store.lock().unwrap();
    let marked = st.jobs.values().filter(|j| j.cancel_sent).count();
    eprintln!(
        "2,000 jobs on one payment and a buyer's: {} sends, the buyer's at {at:?}, {n} accepted, {marked} jobs marked sent, in {took:?}",
        c.len()
    );
    assert!(
        at.is_some_and(|i| i < 2),
        "the buyer's cancel was send {at:?}"
    );
    assert_eq!(
        c.len(),
        2,
        "one send for the shared payment, one for the buyer's"
    );
    assert_eq!(marked, 2_001);
    drop(st);
    let _ = std::fs::remove_dir_all(&dir);
}

/// One transaction id, many witnesses: one payment mined (the daemon says `txn-already-known` of any copy
/// of it, whatever the witness) is handed over with 50 jobs, each copy with a witness of
/// its own. The service holds one copy of it in memory and one file on disk.
#[test]
fn a_mined_payment_is_held_once_whatever_its_witness() {
    let t = terms(1_000, 1_006);
    // A coin of its own: the copies held are the process's, shared by every test in it.
    let (pay, _) = payment_for(&t, 4_242, 1_000);
    let txid = pay.compute_txid();
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "testmempoolaccept" => {
            let hex = p[0][0].as_str().unwrap_or_default();
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(
                &lwk_wollet::btc::paylock::hex_decode(hex).unwrap(),
            )
            .unwrap();
            if tx.compute_txid() == txid {
                Ok(json!([{"allowed": false, "reject-reason": "txn-already-known"}]))
            } else {
                Ok(json!([{"allowed": false, "reject-reason": "missing-inputs"}]))
            }
        }
        _ => Err((-32601, "no such method".into())),
    }));
    let locks: Locks = Default::default();
    let intake = intake_with(&btc_url, locks.clone());
    let dir = tmpdir("onecopy");
    let mut st = Store::open(&dir).unwrap();
    for n in 0..50u32 {
        let lock = lock_named(n);
        locks
            .lock()
            .unwrap()
            .insert(lock.txid.to_string(), lock_tx(&t));
        let mut copy = pay.clone();
        copy.input[0].witness = bitcoin::Witness::from_slice(&[vec![n as u8; 72], vec![2; 33]]);
        assert_eq!(copy.compute_txid(), txid);
        let mut v = request_for(&t, lock, &txid.to_string(), None);
        v["payment_hex"] = json!(btc_hex(&copy));
        post_job(&mut st, &intake, &v).unwrap();
    }
    let copies: Vec<Arc<str>> = st
        .jobs
        .values()
        .flat_map(|j| j.payments.iter().map(|p| p.hex.clone()))
        .collect();
    let files = std::fs::read_dir(dir.join("payments")).unwrap().count();
    let distinct = copies
        .iter()
        .filter(|h| !Arc::ptr_eq(h, &copies[0]))
        .count();
    eprintln!(
        "50 witness copies of one mined payment: {} jobs hold it, {} copies other than the first in memory, {files} files",
        copies.len(),
        distinct
    );
    assert_eq!(copies.len(), 50);
    assert!(st
        .jobs
        .values()
        .all(|j| j.payments.iter().all(|p| p.vouched)));
    assert_eq!(distinct, 0, "each copy is held");
    assert_eq!(files, 1, "each copy is stored");
    // Reopened, every job holds the one copy again.
    drop(st);
    let st = Store::open(&dir).unwrap();
    assert!(st
        .jobs
        .values()
        .all(|j| j.payments.len() == 1 && !j.payments[0].hex.is_empty()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// F13: one real payment of 300 inputs vouches for 200 jobs. Its coins are held
/// once, like its transaction, and no job's file names them: a job's file is the same
/// size whatever the payment weighs.
#[test]
fn a_payment_of_many_coins_costs_each_job_no_more() {
    let t = terms(1_000, 1_006);
    let mut pay = payment_for(&t, 4_343, 1_000).0;
    let first = pay.input[0].clone();
    pay.input = (0..300u32)
        .map(|i| {
            let mut x = first.clone();
            x.previous_output.vout = i;
            x
        })
        .collect();
    let txid = pay.compute_txid();
    let btc_url = fake_node(Box::new(move |m, p| match m {
        "testmempoolaccept" => {
            let hex = p[0][0].as_str().unwrap_or_default();
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(
                &lwk_wollet::btc::paylock::hex_decode(hex).unwrap(),
            )
            .unwrap();
            if tx.compute_txid() == txid {
                Ok(json!([{"allowed": false, "reject-reason": "txn-already-known"}]))
            } else {
                Ok(json!([{"allowed": false, "reject-reason": "missing-inputs"}]))
            }
        }
        _ => Err((-32601, "no such method".into())),
    }));
    let locks: Locks = Default::default();
    let intake = intake_with(&btc_url, locks.clone());
    let dir = tmpdir("manycoins");
    let mut st = Store::open(&dir).unwrap();
    for n in 0..200u32 {
        let lock = lock_named(10_000 + n);
        locks
            .lock()
            .unwrap()
            .insert(lock.txid.to_string(), lock_tx(&t));
        let mut v = request_for(&t, lock, &txid.to_string(), None);
        v["payment_hex"] = json!(btc_hex(&pay));
        post_job(&mut st, &intake, &v).unwrap();
    }
    let coins: Vec<_> = st
        .jobs
        .values()
        .flat_map(|j| j.payments.iter().map(|p| p.coins.clone()))
        .collect();
    assert_eq!(coins.len(), 200);
    assert_eq!(coins[0].len(), 300);
    let apart = coins
        .iter()
        .filter(|c| c.as_ptr() != coins[0].as_ptr())
        .count();
    let sizes: Vec<u64> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .map(|e| e.metadata().unwrap().len())
        .collect();
    let biggest = sizes.iter().max().copied().unwrap_or(0);
    let payment_file = std::fs::metadata(dir.join("payments").join(format!("tx-{txid}.hex")))
        .map(|m| m.len())
        .unwrap_or(0);
    eprintln!(
        "200 jobs on one payment of 300 coins: {apart} coin lists held apart from the first; job files up to {biggest} bytes; the payment's file {payment_file} bytes"
    );
    assert_eq!(apart, 0, "the coins are held once");
    assert!(
        biggest < 8_000,
        "a job's file names the coins: {biggest} bytes"
    );
    // Reopened, each job knows the payment's coins from its one file.
    drop(st);
    let st = Store::open(&dir).unwrap();
    assert!(st
        .jobs
        .values()
        .all(|j| j.payments.len() == 1 && j.payments[0].coins.len() == 300));
    let _ = std::fs::remove_dir_all(&dir);
}
