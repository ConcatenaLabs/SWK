//! The completion service: it holds a buyer's signed claims, its signed cancel and
//! its payment's transaction id, and holds no key. It
//!
//! - completes the claim as soon as a Sequentia block anchors at the payment's
//!   Bitcoin block or above, with a proof of the buyer's own payment;
//! - after every reorganization that disconnects the claim, proves it again,
//!   linked to the lowest anchor the active chain recorded at or above the payment;
//! - raises the claim to its top fee tier as soon as a block is made after the
//!   claim was pooled and does not include it;
//! - broadcasts the cancel if the payment is still unconfirmed two blocks before `D`;
//! - watches the claim until its block is final, and only then calls the swap done.
//!
//! (The node's `doc/sequentia/bitcoin-payment-proof.md`, section 8.5.) Jobs are
//! kept as one JSON file each, so a restart carries on where it stopped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lwk_wollet::btc::paylock::{self, hex_decode, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::{OutPoint, Transaction};
use serde_json::{json, Value};

use crate::{complete_claim, outpoint, BtcChain, Completion, Error, SeqChain, TxStatus};

/// Where a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for the payment, or for a Sequentia block anchored at it.
    Waiting,
    /// The completed claim is in the node's mempool.
    Pooled,
    /// The claim is mined, not yet final.
    Mined,
    /// The claim's block is final: the swap is done.
    Final,
    /// The payment did not confirm in time and the cancel was broadcast.
    Cancelled,
    /// The payment can never open the lock (mined after `D`, or at or below `F`).
    Never,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Waiting => "waiting",
            State::Pooled => "pooled",
            State::Mined => "mined",
            State::Final => "final",
            State::Cancelled => "cancelled",
            State::Never => "never",
        }
    }

    fn parse(s: &str) -> State {
        match s {
            "pooled" => State::Pooled,
            "mined" => State::Mined,
            "final" => State::Final,
            "cancelled" => State::Cancelled,
            "never" => State::Never,
            _ => State::Waiting,
        }
    }
}

/// One swap the service carries.
#[derive(Debug, Clone)]
pub struct Job {
    /// The going tier's transaction id, which names the job.
    pub id: String,
    /// The swap's terms.
    pub terms: PayLockTerms,
    /// The lock.
    pub lock: OutPoint,
    /// The signed claims, lowest fee first; the last is the top tier.
    pub claims: Vec<Transaction>,
    /// The buyer's signed cancel of its payment (a raw Bitcoin transaction).
    pub cancel: Option<String>,
    /// The payment's Bitcoin transaction id.
    pub payment: String,
    /// The signed payment itself, when the buyer hands it over: the service sends it
    /// again if a Bitcoin reorganization evicts it before `D`.
    pub payment_hex: Option<String>,
    /// Where it stands.
    pub state: State,
    /// The tier in use.
    pub tier: usize,
    /// The Sequentia height at which the current tier was pooled.
    pub pooled_at: Option<u32>,
    /// The height the claim was mined at, while it is mined.
    pub mined_at: Option<u32>,
    /// What the service last saw, in words.
    pub note: String,
}

impl Job {
    /// A job from what a buyer's wallet hands over:
    /// `{terms, lock: "txid:vout", claims: [hex...], cancel?: hex, payment: txid}`.
    pub fn from_request(v: &Value) -> Result<Job, Error> {
        let terms = PayLockTerms::from_json(
            v.get("terms")
                .ok_or_else(|| Error("a job needs terms".into()))?,
        )?;
        let lock = outpoint(
            v.get("lock")
                .and_then(Value::as_str)
                .ok_or_else(|| Error("a job needs the lock".into()))?,
        )?;
        let claims = v
            .get("claims")
            .and_then(Value::as_array)
            .ok_or_else(|| Error("a job needs its signed claims".into()))?
            .iter()
            .map(|c| -> Result<Transaction, Error> {
                let tx: Transaction = deserialize(&hex_decode(c.as_str().unwrap_or_default())?)
                    .map_err(|e| Error(format!("a claim does not parse: {e}")))?;
                Ok(tx)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if claims.is_empty() {
            return Err(Error("a job needs at least one signed claim".into()));
        }
        let leaf = terms.claim_leaf().to_bytes();
        for c in &claims {
            if c.input.len() != 1 || c.input[0].previous_output != lock {
                return Err(Error("a claim does not spend the lock alone".into()));
            }
            if c.input[0].witness.script_witness.get(2) != Some(&leaf) {
                return Err(Error("a claim does not spend the terms' claim leaf".into()));
            }
        }
        let payment = v
            .get("payment")
            .and_then(Value::as_str)
            .filter(|p| p.len() == 64 && hex_decode(p).is_ok())
            .ok_or_else(|| Error("a job needs the payment's Bitcoin transaction id".into()))?
            .to_string();
        Ok(Job {
            id: claims[0].txid().to_string(),
            terms,
            lock,
            claims,
            cancel: v.get("cancel").and_then(Value::as_str).map(String::from),
            payment,
            payment_hex: v
                .get("payment_hex")
                .and_then(Value::as_str)
                .map(String::from),
            state: State::Waiting,
            tier: 0,
            pooled_at: None,
            mined_at: None,
            note: String::new(),
        })
    }

    /// The job as stored and as reported.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "terms": self.terms.to_json(),
            "lock": format!("{}:{}", self.lock.txid, self.lock.vout),
            "claims": self.claims.iter().map(|c| hex_encode(&serialize(c))).collect::<Vec<_>>(),
            "cancel": self.cancel,
            "payment": self.payment,
            "payment_hex": self.payment_hex,
            "state": self.state.name(),
            "tier": self.tier,
            "pooled_at": self.pooled_at,
            "mined_at": self.mined_at,
            "note": self.note,
        })
    }

    /// A stored job.
    pub fn from_stored(v: &Value) -> Result<Job, Error> {
        let mut j = Job::from_request(v)?;
        j.state = State::parse(v.get("state").and_then(Value::as_str).unwrap_or_default());
        j.tier = v.get("tier").and_then(Value::as_u64).unwrap_or(0) as usize;
        j.tier = j.tier.min(j.claims.len() - 1);
        j.pooled_at = v.get("pooled_at").and_then(Value::as_u64).map(|n| n as u32);
        j.mined_at = v.get("mined_at").and_then(Value::as_u64).map(|n| n as u32);
        j.note = v
            .get("note")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(j)
    }
}

/// Moves one job on, once. Every step reads the chains as they are now, so a
/// reorganization of either chain is followed at the next tick.
pub fn tick(seq: &SeqChain, btc: &BtcChain, job: &mut Job) -> Result<(), Error> {
    // Mined, and final? Any tier may be the one mined.
    let finalized = seq.finalized_height()?;
    for c in &job.claims {
        if let TxStatus::Mined(h) = seq.status(&c.txid())? {
            job.mined_at = Some(h);
            if h <= finalized {
                job.state = State::Final;
                job.note = format!("the claim {} is final at Sequentia height {h}", c.txid());
            } else {
                job.state = State::Mined;
                job.note = format!("the claim {} is mined at {h}, not final yet", c.txid());
            }
            return Ok(());
        }
    }
    job.mined_at = None;
    let seq_tip = seq.height()?;

    // A block made after the claim was pooled left it out: the top tier, at once.
    let pooled = job
        .claims
        .iter()
        .any(|c| matches!(seq.status(&c.txid()), Ok(TxStatus::Pooled)));
    if pooled {
        if let Some(at) = job.pooled_at {
            if seq_tip > at && job.tier + 1 < job.claims.len() {
                job.tier = job.claims.len() - 1;
                job.pooled_at = None;
                job.note =
                    format!("a block at {seq_tip} left the claim out: raised to the top tier");
            }
        }
    } else if job.state == State::Pooled || job.state == State::Mined {
        // It left the mempool or a disconnected block: prove it again.
        job.pooled_at = None;
    }

    let btc_tip = btc.tip()?;
    match complete_claim(
        seq,
        btc,
        &job.terms,
        &job.lock,
        &job.claims[job.tier],
        &job.payment,
    )? {
        Completion::Ready { tx, height, .. } => match seq.send(&tx) {
            Ok(_) => {
                if job.state != State::Pooled || job.pooled_at.is_none() {
                    job.pooled_at = Some(seq_tip);
                }
                job.state = State::Pooled;
                job.note = format!(
                    "the claim (tier {}) is pooled with a proof of the payment in Bitcoin block {height}",
                    job.tier
                );
            }
            Err(e) => {
                job.note = format!("the node refused the completed claim: {e}");
            }
        },
        Completion::Waiting(why) => {
            let mined = btc
                .find(&job.payment, job.terms.floor.max(1), btc_tip)?
                .is_some();
            if paylock::cancel_due(&job.terms, btc_tip, mined) {
                if let Some(cancel) = &job.cancel {
                    match btc.send_raw(cancel) {
                        Ok(_) => {
                            job.state = State::Cancelled;
                            job.note =
                                "the payment did not confirm in time: the cancel is broadcast"
                                    .into();
                        }
                        Err(e) => job.note = format!("the cancel was refused: {e}"),
                    }
                    return Ok(());
                }
            }
            if job.state != State::Cancelled {
                job.state = State::Waiting;
                // Unmined and not in the daemon's mempool (a reorganization evicted it, say):
                // send the buyer's payment again while it can still open the lock.
                if let Some(p) = &job.payment_hex {
                    if !mined && !btc.pooled(&job.payment)? {
                        let _ = btc.send_raw(p);
                    }
                }
            }
            job.note = why;
        }
        Completion::Never(why) => {
            job.state = State::Never;
            job.note = why;
        }
    }
    Ok(())
}

/// The jobs, kept one file each under a directory.
pub struct Store {
    dir: PathBuf,
    /// The jobs by id.
    pub jobs: BTreeMap<String, Job>,
}

impl Store {
    /// Opens (or creates) the store and reads every job in it.
    pub fn open(dir: &Path) -> Result<Store, Error> {
        std::fs::create_dir_all(dir).map_err(|e| Error(format!("{}: {e}", dir.display())))?;
        let mut jobs = BTreeMap::new();
        for e in std::fs::read_dir(dir).map_err(|e| Error(e.to_string()))? {
            let p = e.map_err(|e| Error(e.to_string()))?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let v: Value =
                serde_json::from_slice(&std::fs::read(&p).map_err(|e| Error(e.to_string()))?)
                    .map_err(|e| Error(format!("{}: {e}", p.display())))?;
            let j = Job::from_stored(&v)?;
            jobs.insert(j.id.clone(), j);
        }
        Ok(Store {
            dir: dir.to_path_buf(),
            jobs,
        })
    }

    /// Adds a job, or keeps the one already held under its id.
    pub fn add(&mut self, job: Job) -> Result<String, Error> {
        let id = job.id.clone();
        if !self.jobs.contains_key(&id) {
            self.save(&job)?;
            self.jobs.insert(id.clone(), job);
        }
        Ok(id)
    }

    /// Writes a job's file.
    pub fn save(&self, job: &Job) -> Result<(), Error> {
        let p = self.dir.join(format!("{}.json", job.id));
        let tmp = self.dir.join(format!("{}.json.tmp", job.id));
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&job.to_json()).map_err(|e| Error(e.to_string()))?,
        )
        .map_err(|e| Error(e.to_string()))?;
        std::fs::rename(&tmp, &p).map_err(|e| Error(e.to_string()))
    }

    /// Ticks every job that is not done, and saves the ones that changed.
    pub fn tick_all(&mut self, seq: &SeqChain, btc: &BtcChain) {
        let ids: Vec<String> = self.jobs.keys().cloned().collect();
        for id in ids {
            let Some(job) = self.jobs.get_mut(&id) else {
                continue;
            };
            if job.state == State::Final {
                continue;
            }
            let before = job.to_json();
            if let Err(e) = tick(seq, btc, job) {
                job.note = format!("could not read the chains: {e}");
            }
            if job.to_json() != before {
                let j = job.clone();
                let _ = self.save(&j);
            }
        }
    }
}

fn respond(req: tiny_http::Request, code: u16, body: &Value) {
    let h = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header");
    let _ = req.respond(
        tiny_http::Response::from_string(body.to_string())
            .with_status_code(code)
            .with_header(h),
    );
}

fn handle(store: &Arc<Mutex<Store>>, mut req: tiny_http::Request) {
    let url = req.url().to_string();
    let method = req.method().clone();
    let mut body = String::new();
    if method == tiny_http::Method::Post {
        use std::io::Read;
        if req
            .as_reader()
            .take(4 << 20)
            .read_to_string(&mut body)
            .is_err()
        {
            return respond(req, 400, &json!({"error": "unreadable body"}));
        }
    }
    let Ok(mut st) = store.lock() else {
        return respond(req, 500, &json!({"error": "store unavailable"}));
    };
    match (method, url.trim_end_matches('/')) {
        (tiny_http::Method::Post, "/jobs") => {
            let v: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => return respond(req, 400, &json!({"error": e.to_string()})),
            };
            match Job::from_request(&v).and_then(|j| st.add(j)) {
                Ok(id) => respond(req, 200, &json!({"id": id})),
                Err(e) => respond(req, 400, &json!({"error": e.0})),
            }
        }
        (tiny_http::Method::Get, "/jobs") => {
            let list: Vec<Value> = st
                .jobs
                .values()
                .map(|j| json!({"id": j.id, "state": j.state.name(), "note": j.note}))
                .collect();
            respond(req, 200, &json!(list))
        }
        (tiny_http::Method::Get, p) if p.starts_with("/jobs/") => match st.jobs.get(&p[6..]) {
            Some(j) => respond(req, 200, &j.to_json()),
            None => respond(req, 404, &json!({"error": "no such job"})),
        },
        _ => respond(req, 404, &json!({"error": "not found"})),
    }
}

/// Runs the service: an HTTP intake on `listen` (`POST /jobs`, `GET /jobs`,
/// `GET /jobs/<id>`) and a tick of every job each `interval`. Never returns.
pub fn serve(
    seq: SeqChain,
    btc: BtcChain,
    dir: &Path,
    listen: &str,
    interval: Duration,
) -> Result<(), Error> {
    let store = Arc::new(Mutex::new(Store::open(dir)?));
    let server =
        tiny_http::Server::http(listen).map_err(|e| Error(format!("listen {listen}: {e}")))?;
    let s2 = store.clone();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(&s2, req);
        }
    });
    loop {
        if let Ok(mut st) = store.lock() {
            st.tick_all(&seq, &btc);
        }
        std::thread::sleep(interval);
    }
}
