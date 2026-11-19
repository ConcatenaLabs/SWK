//! The completion service's bounds, against fake nodes: a Sequentia node whose every
//! answer takes two seconds (a stalled round of work) and a Bitcoin daemon that records
//! what it is sent.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lwk_paylock::service::{self, Job, Limits, State, Store};
use lwk_paylock::{BtcChain, Rpc, SeqChain};
use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{self, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::serialize;
use lwk_wollet::elements::hashes::Hash;
use lwk_wollet::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use lwk_wollet::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
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
                let _ = std::io::Read::read_to_string(req.as_reader(), &mut body);
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

/// A job as a buyer's wallet hands it over, its lock named by `n`.
fn request(n: u32, floor: u32, deadline: u32, cancel: &str) -> Value {
    let t = terms(floor, deadline);
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_le_bytes());
    let lock = OutPoint::new(Txid::from_byte_array(id), 0);
    let claim = paylock::sign_claim(
        &t,
        lock,
        Script::new(),
        1000,
        BlockHash::all_zeros(),
        &key(1),
    )
    .unwrap();
    json!({
        "terms": t.to_json(),
        "lock": format!("{}:0", lock.txid),
        "claims": [hex_encode(&serialize(&claim))],
        "cancel": cancel,
        "payment": format!("{n:064x}"),
    })
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("paylock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
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
            Ok(json!({"tx": []}))
        }
        "sendrawtransaction" => {
            s2.lock().unwrap().push(p[0].as_str().unwrap().to_string());
            Ok(json!("00".repeat(32)))
        }
        "getmempoolentry" => Err((-5, "not in mempool".into())),
        _ => Err((-32601, "no such method".into())),
    }));
    // Every answer of the Sequentia node takes two seconds.
    let seq_url = fake_node(Box::new(|m, _| {
        std::thread::sleep(Duration::from_secs(2));
        match m {
            "getposfinality" => Ok(json!({"finalized_height": 0})),
            "getrawtransaction" => Err((-5, "No such mempool or blockchain transaction".into())),
            "getblockcount" => Ok(json!(10)),
            "gettxout" => Ok(json!({"value": 1})),
            _ => Err((-32601, "no such method".into())),
        }
    }));
    let rpc = |u: &str| Rpc::with_timeout(u, "u", "p", Duration::from_secs(15)).unwrap();

    let dir = tmpdir("stalled");
    {
        let mut st = Store::open(&dir).unwrap();
        let limits = Limits::default();
        // Thirty ended jobs, as a long-running service accumulates them.
        for n in 0..30 {
            let mut j = Job::from_request(&request(n, 990, 996, "dead")).unwrap();
            st.add(j.clone(), &limits).unwrap();
            j.state = [State::Final, State::Cancelled, State::Never][n as usize % 3];
            st.save(&j).unwrap();
        }
        // Forty stale ones whose payment never comes, each reaching 800 blocks back.
        for n in 100..140 {
            st.add(
                Job::from_request(&request(n, 300, 1_100 + n, "beef")).unwrap(),
                &limits,
            )
            .unwrap();
        }
        // The live one, due two blocks before its deadline at 1,003.
        st.add(
            Job::from_request(&request(999, 1_000, 1_003, "cafe")).unwrap(),
            &limits,
        )
        .unwrap();
    }
    // Reopened, the ended jobs are archived: never worked on again, still readable.
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
            &SeqChain { rpc: rpc(&su) },
            &BtcChain { rpc: rpc(&bu) },
            &l2,
        );
        (n, t.elapsed())
    });

    // Bitcoin reaches D - 2 while the round is stuck on the Sequentia node.
    std::thread::sleep(Duration::from_millis(500));
    tip.store(1_001, Ordering::SeqCst);
    let t = Instant::now();
    let n = service::send_due_cancels(&store, &BtcChain { rpc: rpc(&btc_url) }).unwrap();
    let took = t.elapsed();
    eprintln!("the due cancel went out in {took:?} while the round was stalled");
    assert_eq!(n, 1);
    assert_eq!(*sent.lock().unwrap(), vec!["cafe".to_string()]);
    assert!(took < Duration::from_secs(1), "the cancel took {took:?}");
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
    // The job worked first is the one nearest its deadline.
    let live = store
        .lock()
        .unwrap()
        .jobs
        .values()
        .find(|j| j.terms.deadline == 1_003)
        .unwrap()
        .clone();
    assert!(live.cancel_sent);
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
            Ok(json!({"tx": []}))
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
        Job::from_request(&request(1, 1_000, 1_006, "")).unwrap(),
        &limits,
    )
    .unwrap();
    st.add(
        Job::from_request(&request(2, 1_000, 1_006, "")).unwrap(),
        &limits,
    )
    .unwrap();
    let e = st
        .add(
            Job::from_request(&request(3, 1_000, 1_006, "")).unwrap(),
            &limits,
        )
        .unwrap_err();
    assert!(e.0.contains("its limit"), "{e}");
    // The same job again is no new job.
    st.add(
        Job::from_request(&request(1, 1_000, 1_006, "")).unwrap(),
        &limits,
    )
    .unwrap();
    let wide = Limits::default();
    let e = st
        .add(Job::from_request(&request(4, 1, 2_000, "")).unwrap(), &wide)
        .unwrap_err();
    assert!(e.0.contains("spans"), "{e}");
    // A job id is a transaction id, never a path.
    assert!(st.archived("../../etc/passwd").is_none());
    assert!(service::loopback_only("127.0.0.1:1234"));
    assert!(service::loopback_only("[::1]:1234"));
    assert!(!service::loopback_only("0.0.0.0:1234"));
    let dead = || BtcChain {
        rpc: Rpc::new("http://127.0.0.1:1", "u", "p").unwrap(),
    };
    let e = service::serve(
        SeqChain {
            rpc: Rpc::new("http://127.0.0.1:1", "u", "p").unwrap(),
        },
        dead(),
        dead(),
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
