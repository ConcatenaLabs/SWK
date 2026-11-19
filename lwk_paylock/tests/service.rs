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

use lwk_paylock::service::{self, Added, Intake, Job, Limits, Refused, State, Store};
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
                let _ = req.respond(tiny_http::Response::from_string(out.to_string()));
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
        let limits = Limits::default();
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
                Job::from_request(&request(n, 300, 1_100 + n, Some(btc_hex(&btc_spend(n, 1)))))
                    .unwrap(),
                &limits,
            )
            .unwrap();
        }
        // The live one, due two blocks before its deadline at 1,003.
        st.add(
            Job::from_request(&request_for(
                &live_terms,
                live_lock,
                &"ab".repeat(32),
                Some(live_cancel.clone()),
            ))
            .unwrap(),
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
    let b = body.to_string();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
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

/// A fake Bitcoin daemon's answer to `testmempoolaccept`: every transaction allowed.
fn allow_all(p: &Value) -> Result<Value, (i32, String)> {
    Ok(json!([{"txid": "00", "allowed": true, "fees": {"base": 0.0001}, "params": p}]))
}

/// A fake Sequentia node's genesis: the one the test claims are signed for.
fn genesis_answer(p: &Value) -> Option<Value> {
    (p[0].as_u64() == Some(0)).then(|| json!("00".repeat(32)))
}

/// The review's flood: stale jobs (locks no node knows) whose deadlines come first and
/// whose cancels the Bitcoin daemon takes 50 ms each to refuse, beside one live job. Run
/// against the `paylock` binary, so the same case judges any revision of the service.
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
        "gettxout" => Ok(Value::Null),
        _ => Err((-32601, "no such method".into())),
    }));
    let live_lock_tx = lock_tx(&live_terms);
    let live_lock = OutPoint::new(live_lock_tx.txid(), 0);
    let (lock_id, lock_hex) = (
        live_lock.txid.to_string(),
        hex_encode(&serialize(&live_lock_tx)),
    );
    let seq_url = fake_node(Box::new(move |m, p| match m {
        "getposfinality" => Ok(json!({"finalized_height": 0})),
        "getrawtransaction" if p[0].as_str() == Some(&lock_id) => Ok(json!({"hex": lock_hex})),
        "getrawtransaction" => Err((-5, "No such mempool or blockchain transaction".into())),
        "getblockhash" => genesis_answer(p).ok_or((-8, "out of range".into())),
        "getblockcount" => Ok(json!(10)),
        "gettxout" => Ok(json!({"value": 1})),
        "getfeeassetinfo" => Ok(json!({})),
        _ => Err((-32601, "no such method".into())),
    }));
    let dir = tmpdir("flood");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    for n in 0..STALE {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&n.to_le_bytes());
        let lock = OutPoint::new(Txid::from_byte_array(id), 0);
        let t = terms(T - 1, T + 3);
        let (pay, cancel) = payment_for(&t, n, 1_000);
        let mut r = request_for(
            &t,
            lock,
            &pay.compute_txid().to_string(),
            Some(btc_hex(&cancel)),
        );
        r["payment_hex"] = json!(btc_hex(&pay));
        let (code, r) = post(port, "/jobs", &r);
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

/// A Sequentia node that says it does not know the lock (one still syncing, say) holds
/// back no cancel: the cancel concerns Bitcoin alone. Through the binary.
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
    // The node knows no transaction at all: not the lock, not anything.
    let seq_url = fake_node(Box::new(move |m, p| match m {
        "getposfinality" => Ok(json!({"finalized_height": 0})),
        "getrawtransaction" => Err((-5, "No such mempool or blockchain transaction".into())),
        "getblockhash" => genesis_answer(p).ok_or((-8, "out of range".into())),
        "getblockcount" => Ok(json!(10)),
        "gettxout" => Ok(Value::Null),
        "getfeeassetinfo" => Ok(json!({})),
        _ => Err((-32601, "no such method".into())),
    }));
    let dir = tmpdir("unknownlock");
    let (_serve, port) = serve(&dir, &seq_url, &btc_url);
    let lock = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let mut r = request_for(
        &t,
        lock,
        &pay.compute_txid().to_string(),
        Some(cancel.clone()),
    );
    r["payment_hex"] = json!(btc_hex(&pay));
    let (code, r) = post(port, "/jobs", &r);
    assert_eq!(code, 200, "{r}");
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
    assert!(e.0.contains("its limit"), "{e}");
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
    assert!(e.0.contains("spans"), "{e}");
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

fn intake_with(btc_url: &str) -> Intake {
    let seq_url = fake_node(Box::new(|m, p| match m {
        "getblockhash" => genesis_answer(p).ok_or((-8, "out of range".into())),
        "getrawtransaction" => Err((-5, "No such mempool or blockchain transaction".into())),
        _ => Err((-32601, "no such method".into())),
    }));
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
    match service::check_intake(intake, &mut j) {
        Ok(_) => {}
        Err(Refused::Bad(e)) | Err(Refused::Unavailable(e)) => return Err(e.0),
    }
    st.add(j, &Limits::default()).map_err(|e| e.0)
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
    let lock = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
    let (pay, cancel) = payment_for(&t, 42, 1_000);
    let pay_id = pay.compute_txid().to_string();
    let cancel = btc_hex(&cancel);
    let intake = intake_with(&judging_daemon(vec![pay.clone()]));

    // Kimi's: no payment_hex, a dummy cancel spending a coin the payment does not.
    let dummy = request_for(&t, lock, &pay_id, Some(btc_hex(&btc_spend(43, 90_000))));
    let e = post_job(&mut st, &intake, &dummy).unwrap_err();
    assert!(e.contains("exactly the payment's coins"), "{e}");
    // Opus's: the payment itself and an unsigned spend of its coins.
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
    // The mempool held the payment: the service took it from there.
    assert!(st.jobs[&id].payment_hex.is_some());
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
    assert_eq!(st.jobs[&id].cancels.len(), 1);
    assert_eq!(st.jobs[&id].cancels[0].hex, cancel);
    assert_eq!(st.jobs[&id].cancels[0].fee, 10_000);
    // A second valid cancel of the same coins is kept beside it, highest fee first.
    let mut second = buyer.clone();
    second["cancel"] = json!(btc_hex(&btc_spend(42, 89_000)));
    let (_, added) = post_job(&mut st, &intake, &second).unwrap();
    assert_eq!(added, Added::Merged(vec!["cancels"]));
    assert_eq!(st.jobs[&id].cancels.len(), 2);
    assert_eq!(st.jobs[&id].cancels[0].fee, 11_000);
    // The same again: held.
    let (_, again) = post_job(&mut st, &intake, &buyer).unwrap();
    assert_eq!(again, Added::Same);
    // A cancel with no payment known anywhere: refused, its coins cannot be compared.
    let other_pay = "cd".repeat(32);
    let e = post_job(
        &mut st,
        &intake,
        &request_for(&t, lock, &other_pay, Some(cancel.clone())),
    )
    .unwrap_err();
    assert!(e.contains("beside the payment"), "{e}");
    // What anyone reads holds no signed claim, cancel or payment.
    let public = st.jobs[&id].public_json().to_string();
    assert!(!public.contains(&cancel));
    assert!(!public.contains(&hex_encode(&serialize(&st.jobs[&id].claims[0]))));
    assert!(!public.contains(&btc_hex(&pay)));
    assert!(!public.contains(&pay_id));
    // Stored and read back, it is the same job.
    let st = Store::open(&dir).unwrap();
    assert_eq!(st.jobs[&id].cancels.len(), 2);
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
        Job::from_request(&request(5, 1_000, 1_003, Some(cancel.clone()))).unwrap(),
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
