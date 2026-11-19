//! The completion service: it holds a buyer's signed claims, its signed cancel and
//! its payment's transaction id, and holds no key. It
//!
//! - completes the claim as soon as a Sequentia block anchors at the payment's
//!   Bitcoin block or above, with a proof of the buyer's own payment;
//! - after every reorganization that disconnects the claim, proves it again,
//!   linked to the lowest anchor the active chain recorded at or above the payment;
//! - raises the claim to its top fee tier as soon as a block is made after the
//!   claim was pooled and does not include it;
//! - pays the fee in whichever asset the node still accepts, when the buyer signed
//!   tiers in two;
//! - broadcasts the cancel if the payment is still unconfirmed two blocks before `D`;
//! - watches the claim until its block is final, and only then calls the swap done.
//!
//! (The node's `doc/sequentia/bitcoin-payment-proof.md`, section 8.5.)
//!
//! **Bounded.** Cancels have a thread of their own, which reads Bitcoin's tip and
//! broadcasts every cancel that is due, nearest deadline first, and never waits on
//! the work of completing claims. That work runs jobs nearest deadline first, each
//! within a time and block budget, and the whole round within a budget of its own;
//! a job it does not reach waits for the next round. The search for a payment keeps
//! its place between rounds, so each Bitcoin block is read once per job. A job that
//! fails retries with a backoff. A job that has ended (final, cancelled, never
//! payable, or its lock spent by the seller's refund) is archived and not worked on
//! again. Intake caps the request's size, the claims per job, a lock's span of heights
//! and the number of jobs, and needs a token whenever it listens beyond loopback.
//!
//! Jobs are kept as one JSON file each, so a restart carries on where it stopped;
//! ended jobs move to `archive/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lwk_wollet::btc::paylock::{self, fee_of, hex_decode, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use crate::{
    outpoint, payment_position, prove_claim, BtcChain, Completion, Error, Found, PaymentScan,
    Position, SeqChain, TxStatus,
};

/// Where a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for the payment, or for a Sequentia block anchored at it.
    Waiting,
    /// The completed claim is in the node's mempool.
    Pooled,
    /// The claim is mined, not yet final.
    Mined,
    /// The claim's block is final: the swap is done. Ended.
    Final,
    /// The cancel was broadcast and the deadline passed with no payment in the lock's
    /// heights: the buyer keeps its bitcoin. Ended.
    Cancelled,
    /// The payment can never open the lock (mined after `D`, at or below `F`, or not
    /// mined by `D`). Ended.
    Never,
    /// The lock was spent in the chain by something other than these claims: the
    /// seller's refund. Ended.
    Refunded,
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
            State::Refunded => "refunded",
        }
    }

    fn parse(s: &str) -> State {
        match s {
            "pooled" => State::Pooled,
            "mined" => State::Mined,
            "final" => State::Final,
            "cancelled" => State::Cancelled,
            "never" => State::Never,
            "refunded" => State::Refunded,
            _ => State::Waiting,
        }
    }

    /// Whether the job has ended and is archived.
    pub fn ended(self) -> bool {
        matches!(
            self,
            State::Final | State::Cancelled | State::Never | State::Refunded
        )
    }
}

/// What the service accepts and how much work it does. The defaults suit a service
/// carrying up to a thousand swaps at once beside one node and one Bitcoin daemon.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Jobs carried at once; intake refuses more.
    pub max_jobs: usize,
    /// A request's body, in bytes.
    pub max_body: usize,
    /// Signed claims in one job (every tier in every fee asset).
    pub max_claims: usize,
    /// The most Bitcoin blocks a lock may span, `D - F`.
    pub max_window: u32,
    /// Bitcoin blocks one job may read in one round.
    pub blocks_per_job: u32,
    /// Time one job may take in one round (checked between reads).
    pub job_time: Duration,
    /// Time one round of work may take.
    pub round_time: Duration,
    /// The longest a failing job waits before it is tried again.
    pub backoff_max: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_jobs: 1000,
            max_body: 512 << 10,
            max_claims: 8,
            max_window: 1008,
            blocks_per_job: 24,
            job_time: Duration::from_secs(5),
            round_time: Duration::from_secs(10),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// One swap the service carries.
#[derive(Debug, Clone)]
pub struct Job {
    /// The first claim's transaction id, which names the job.
    pub id: String,
    /// The swap's terms.
    pub terms: PayLockTerms,
    /// The lock.
    pub lock: OutPoint,
    /// The signed claims: every tier, in every fee asset the buyer signed.
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
    /// The claim in use (an index into `claims`).
    pub tier: usize,
    /// Whether a block left the claim out, so the top tier is in use.
    pub raised: bool,
    /// The Sequentia height at which the claim in use was pooled.
    pub pooled_at: Option<u32>,
    /// The height the claim was mined at, while it is mined.
    pub mined_at: Option<u32>,
    /// How far the search for the payment has read Bitcoin.
    pub scan: PaymentScan,
    /// Whether the cancel has been broadcast.
    pub cancel_sent: bool,
    /// When the cancel was last sent (seconds since 1970).
    pub cancel_at: u64,
    /// Rounds in a row that failed.
    pub failures: u32,
    /// Not worked on again before this time (seconds since 1970).
    pub retry_at: u64,
    /// What the service last saw, in words.
    pub note: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Job {
    /// A job from what a buyer's wallet hands over:
    /// `{terms, lock: "txid:vout", claims: [hex...], cancel?: hex, payment: txid, payment_hex?: hex}`.
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
            if c.input.first().map(|i| i.previous_output) != Some(lock) {
                return Err(Error(
                    "a claim does not spend the lock as its first input".into(),
                ));
            }
            for (i, input) in c.input.iter().enumerate() {
                let w = &input.witness.script_witness;
                let claim_leaf = w.len() == 4 && w[2] == leaf;
                if i == 0 && !claim_leaf {
                    return Err(Error("a claim does not spend the terms' claim leaf".into()));
                }
                if claim_leaf && input.previous_output.txid != lock.txid {
                    return Err(Error(
                        "a claim spends the claim leaf of an output that is not the lock's".into(),
                    ));
                }
                if !claim_leaf && w.is_empty() {
                    return Err(Error(format!(
                        "a claim's input {i} (its fee coin) is not signed"
                    )));
                }
            }
            if fee_of(c).is_none() {
                return Err(Error("a claim pays no fee in the clear".into()));
            }
        }
        let payment = v
            .get("payment")
            .and_then(Value::as_str)
            .filter(|p| is_txid(p))
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
            raised: false,
            pooled_at: None,
            mined_at: None,
            scan: PaymentScan::default(),
            cancel_sent: false,
            cancel_at: 0,
            failures: 0,
            retry_at: 0,
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
            "raised": self.raised,
            "fee": fee_of(&self.claims[self.tier]).map(|(a, f)| json!({"asset": a.to_string(), "atoms": f})),
            "pooled_at": self.pooled_at,
            "mined_at": self.mined_at,
            "scanned": self.scan.scanned.as_ref().map(|(h, b)| json!({"height": h, "block": b})),
            "found": self.scan.found.as_ref().map(|f| json!({"height": f.height, "block": f.block})),
            "cancel_sent": self.cancel_sent,
            "cancel_at": self.cancel_at,
            "failures": self.failures,
            "retry_at": self.retry_at,
            "note": self.note,
        })
    }

    /// A stored job.
    pub fn from_stored(v: &Value) -> Result<Job, Error> {
        let mut j = Job::from_request(v)?;
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        j.state = State::parse(v.get("state").and_then(Value::as_str).unwrap_or_default());
        j.tier = (n("tier").unwrap_or(0) as usize).min(j.claims.len() - 1);
        j.raised = v.get("raised").and_then(Value::as_bool).unwrap_or(false);
        j.pooled_at = n("pooled_at").map(|n| n as u32);
        j.mined_at = n("mined_at").map(|n| n as u32);
        j.scan = PaymentScan {
            scanned: v.get("scanned").and_then(|s| {
                Some((
                    s.get("height")?.as_u64()? as u32,
                    s.get("block")?.as_str()?.to_string(),
                ))
            }),
            found: v.get("found").and_then(|s| {
                Some(Found {
                    height: s.get("height")?.as_u64()? as u32,
                    block: s.get("block")?.as_str()?.to_string(),
                })
            }),
        };
        j.cancel_sent = v
            .get("cancel_sent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        j.cancel_at = n("cancel_at").unwrap_or(0);
        j.failures = n("failures").unwrap_or(0) as u32;
        j.retry_at = n("retry_at").unwrap_or(0);
        j.note = v
            .get("note")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(j)
    }

    /// Whether the payment is known to be mined at a height the claim accepts.
    fn paid_in_window(&self) -> bool {
        self.scan
            .found
            .as_ref()
            .map(|f| f.height > self.terms.floor && f.height <= self.terms.deadline)
            .unwrap_or(false)
    }

    /// The claims grouped by fee asset, in the order the buyer gave them, each group
    /// lowest fee first: the going tier, then the top.
    fn fee_sets(&self) -> Vec<(AssetId, Vec<usize>)> {
        let mut sets: Vec<(AssetId, Vec<usize>)> = vec![];
        for (i, c) in self.claims.iter().enumerate() {
            let Some((asset, _)) = fee_of(c) else {
                continue;
            };
            match sets.iter_mut().find(|(a, _)| *a == asset) {
                Some((_, v)) => v.push(i),
                None => sets.push((asset, vec![i])),
            }
        }
        for (_, v) in sets.iter_mut() {
            v.sort_by_key(|&i| fee_of(&self.claims[i]).map(|f| f.1).unwrap_or(0));
        }
        sets
    }
}

/// The claim to submit now: the going tier, or the top once a block left the claim out,
/// in the first fee asset the node accepts whose fee coin (if any) is still unspent.
fn choose(seq: &SeqChain, job: &Job) -> Result<Option<usize>, Error> {
    let leaf = job.terms.claim_leaf().to_bytes();
    for (asset, tiers) in job.fee_sets() {
        if !seq.fee_asset_accepted(&asset)? {
            continue;
        }
        let i = if job.raised {
            *tiers.last().expect("non-empty")
        } else {
            tiers[0]
        };
        let mut coins_unspent = true;
        for input in &job.claims[i].input {
            let w = &input.witness.script_witness;
            let spends_lock = w.len() == 4 && w[2] == leaf;
            if !spends_lock && !seq.unspent_in_chain(&input.previous_output)? {
                coins_unspent = false;
            }
        }
        if coins_unspent {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Moves one job on, once, within `limits` and before `until`. Every step reads the
/// chains as they are now, so a reorganization of either chain is followed at the next
/// round. The cancel is not sent here: [`send_due_cancels`] sends it.
pub fn tick(
    seq: &SeqChain,
    btc: &BtcChain,
    job: &mut Job,
    limits: &Limits,
    until: Instant,
) -> Result<(), Error> {
    // Mined, and final? Any tier may be the one mined.
    let finalized = seq.finalized_height()?;
    let mut pooled = None;
    for (i, c) in job.claims.iter().enumerate() {
        match seq.status(&c.txid())? {
            TxStatus::Mined(h) => {
                job.mined_at = Some(h);
                job.tier = i;
                if h <= finalized {
                    job.state = State::Final;
                    job.note = format!("the claim {} is final at Sequentia height {h}", c.txid());
                } else {
                    job.state = State::Mined;
                    job.note = format!("the claim {} is mined at {h}, not final yet", c.txid());
                }
                return Ok(());
            }
            TxStatus::Pooled => pooled = Some(i),
            TxStatus::Unknown => {}
        }
    }
    job.mined_at = None;
    // Out of time: the job carries on from here next round, its state unchanged.
    if Instant::now() >= until {
        return Ok(());
    }
    let seq_tip = seq.height()?;

    // A block made after the claim was pooled left it out: the top tier, at once.
    match pooled {
        Some(_) => {
            if let Some(at) = job.pooled_at {
                if seq_tip > at && !job.raised {
                    job.raised = true;
                    job.pooled_at = None;
                    job.note =
                        format!("a block at {seq_tip} left the claim out: raised to the top tier");
                }
            }
        }
        None => {
            job.pooled_at = None;
            // Spent in the chain by none of these claims: the seller refunded.
            if !seq.unspent_in_chain(&job.lock)? && seq.coin_anchor(&job.lock.txid)?.is_some() {
                job.state = State::Refunded;
                job.note = "the lock is spent by another transaction: the seller's refund".into();
                return Ok(());
            }
        }
    }

    if Instant::now() >= until {
        return Ok(());
    }
    let complete = btc.scan_payment(
        &job.payment,
        &job.terms,
        &mut job.scan,
        limits.blocks_per_job,
        until,
    )?;
    let btc_tip = btc.tip()?;
    match payment_position(&job.terms, &job.scan, complete, btc_tip) {
        Position::Never(why) => {
            job.state = if job.cancel_sent && job.scan.found.is_none() {
                State::Cancelled
            } else {
                State::Never
            };
            job.note = if job.state == State::Cancelled {
                format!("{why}; the cancel was broadcast and the buyer keeps its bitcoin")
            } else {
                why
            };
        }
        Position::Waiting(why) => {
            job.state = State::Waiting;
            job.note = why;
            // Unmined and not in the daemon's mempool (a reorganization evicted it, say):
            // send the buyer's payment again while it can still open the lock.
            if complete && !job.cancel_sent && btc_tip < job.terms.deadline {
                if let Some(p) = &job.payment_hex {
                    if !btc.pooled(&job.payment)? && btc.send_raw(p).is_ok() {
                        job.note = "the payment was not in the Bitcoin mempool: sent again".into();
                    }
                }
            }
        }
        Position::InWindow => {
            let Some(want) = choose(seq, job)? else {
                job.state = State::Waiting;
                job.note = "no signed tier pays its fee in an asset the node accepts, from a coin still unspent".into();
                return Err(Error(job.note.clone()));
            };
            if pooled == Some(want) {
                job.state = State::Pooled;
                return Ok(());
            }
            if Instant::now() >= until {
                return Ok(());
            }
            let found = job.scan.found.clone().expect("in window");
            match prove_claim(
                seq,
                btc,
                &job.terms,
                &job.lock,
                &job.claims[want],
                &job.payment,
                &found,
            )? {
                Completion::Ready { tx, height, .. } => match seq.send(&tx) {
                    Ok(_) => {
                        job.tier = want;
                        job.pooled_at = Some(seq_tip);
                        job.state = State::Pooled;
                        job.note = format!(
                            "the claim ({}tier, fee {}) is pooled with a proof of the payment in Bitcoin block {height}",
                            if job.raised { "top " } else { "going " },
                            fee_of(&tx).map(|(a, f)| format!("{f} atoms of {a}")).unwrap_or_default()
                        );
                    }
                    Err(e) => {
                        job.note = format!("the node refused the completed claim: {e}");
                        return Err(Error(job.note.clone()));
                    }
                },
                Completion::Waiting(why) => {
                    job.state = State::Waiting;
                    job.note = why;
                }
                Completion::Never(why) => {
                    job.state = State::Never;
                    job.note = why;
                }
            }
        }
    }
    Ok(())
}

/// Broadcasts every cancel that is due, nearest deadline first: a job not ended, with a
/// cancel, whose payment is not known to be mined in the lock's heights, once Bitcoin's
/// tip is two blocks before `D` or later. A cancel already sent is sent again every ten
/// seconds, in case a node dropped it; one whose payment is mined is simply refused by
/// the daemon. Reads nothing but Bitcoin's tip.
pub fn send_due_cancels(store: &Mutex<Store>, btc: &BtcChain) -> Result<usize, Error> {
    let tip = btc.tip()?;
    let now = now_secs();
    let mut due: Vec<(u32, String, String)> = lock(store)
        .jobs
        .values()
        .filter(|j| {
            !j.state.ended()
                && !j.paid_in_window()
                && paylock::cancel_due(&j.terms, tip, false)
                && (!j.cancel_sent || now >= j.cancel_at + 10)
        })
        .filter_map(|j| Some((j.terms.deadline, j.id.clone(), j.cancel.clone()?)))
        .collect();
    due.sort();
    let mut sent = 0;
    for (_, id, hex) in due {
        let r = btc.send_raw(&hex);
        let mut st = lock(store);
        let Some(j) = st.jobs.get_mut(&id) else {
            continue;
        };
        j.cancel_at = now;
        match r {
            Ok(_) => {
                sent += 1;
                if !j.cancel_sent {
                    j.note = format!(
                        "the payment did not confirm by Bitcoin block {tip} (two before the deadline): the cancel is broadcast"
                    );
                }
                j.cancel_sent = true;
            }
            Err(e) => {
                let m = e.to_string();
                if m.contains("already") {
                    j.cancel_sent = true;
                } else if !j.cancel_sent {
                    j.note = format!("the cancel was refused: {m}");
                }
            }
        }
        let j = j.clone();
        let _ = st.save(&j);
    }
    Ok(sent)
}

fn lock(store: &Mutex<Store>) -> MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|e| e.into_inner())
}

/// The jobs, kept one file each under a directory; ended jobs under `archive/`.
pub struct Store {
    dir: PathBuf,
    /// The jobs being carried, by id.
    pub jobs: BTreeMap<String, Job>,
}

impl Store {
    /// Opens (or creates) the store and reads every job in it; any ended job found
    /// among them is archived.
    pub fn open(dir: &Path) -> Result<Store, Error> {
        std::fs::create_dir_all(dir.join("archive"))
            .map_err(|e| Error(format!("{}: {e}", dir.display())))?;
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
        let mut st = Store {
            dir: dir.to_path_buf(),
            jobs,
        };
        let ended: Vec<String> = st
            .jobs
            .values()
            .filter(|j| j.state.ended())
            .map(|j| j.id.clone())
            .collect();
        for id in ended {
            st.archive(&id)?;
        }
        Ok(st)
    }

    /// Adds a job, or keeps the one already held under its id.
    pub fn add(&mut self, job: Job, limits: &Limits) -> Result<String, Error> {
        let id = job.id.clone();
        if self.jobs.contains_key(&id) || self.archived(&id).is_some() {
            return Ok(id);
        }
        if self.jobs.len() >= limits.max_jobs {
            return Err(Error(format!(
                "the service carries {} jobs, its limit; try another service or later",
                self.jobs.len()
            )));
        }
        if job.claims.len() > limits.max_claims {
            return Err(Error(format!(
                "a job carries at most {} signed claims",
                limits.max_claims
            )));
        }
        if job.terms.deadline - job.terms.floor > limits.max_window {
            return Err(Error(format!(
                "the lock spans {} Bitcoin blocks from its floor to its deadline; this service takes at most {}",
                job.terms.deadline - job.terms.floor,
                limits.max_window
            )));
        }
        self.save(&job)?;
        self.jobs.insert(id.clone(), job);
        Ok(id)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn archive_path(&self, id: &str) -> PathBuf {
        self.dir.join("archive").join(format!("{id}.json"))
    }

    /// Writes a job's file.
    pub fn save(&self, job: &Job) -> Result<(), Error> {
        let p = self.path(&job.id);
        let tmp = self.dir.join(format!("{}.json.tmp", job.id));
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&job.to_json()).map_err(|e| Error(e.to_string()))?,
        )
        .map_err(|e| Error(e.to_string()))?;
        std::fs::rename(&tmp, &p).map_err(|e| Error(e.to_string()))
    }

    /// Moves an ended job to the archive.
    pub fn archive(&mut self, id: &str) -> Result<(), Error> {
        if let Some(j) = self.jobs.remove(id) {
            self.save(&j)?;
            std::fs::rename(self.path(id), self.archive_path(id))
                .map_err(|e| Error(e.to_string()))?;
        }
        Ok(())
    }

    /// An archived job, as stored.
    pub fn archived(&self, id: &str) -> Option<Value> {
        if !is_txid(id) {
            return None;
        }
        serde_json::from_slice(&std::fs::read(self.archive_path(id)).ok()?).ok()
    }
}

/// One round of work: the jobs not ended and not backing off, nearest deadline first,
/// each within its budget, the whole within the round's. The store's lock is held only
/// to copy a job out and to put it back, so intake and cancels never wait on the
/// chains. Returns how many jobs it worked on.
pub fn work_round(store: &Mutex<Store>, seq: &SeqChain, btc: &BtcChain, limits: &Limits) -> usize {
    let start = Instant::now();
    let round_end = start + limits.round_time;
    let now = now_secs();
    let mut order: Vec<(u32, String)> = lock(store)
        .jobs
        .values()
        .filter(|j| !j.state.ended() && j.retry_at <= now)
        .map(|j| (j.terms.deadline, j.id.clone()))
        .collect();
    order.sort();
    let mut worked = 0;
    for (_, id) in order {
        let t = Instant::now();
        if t >= round_end {
            break;
        }
        let Some(mut job) = lock(store).jobs.get(&id).cloned() else {
            continue;
        };
        let until = (t + limits.job_time).min(round_end);
        let before = job.to_json();
        match tick(seq, btc, &mut job, limits, until) {
            Ok(()) => {
                job.failures = 0;
                job.retry_at = 0;
            }
            Err(e) => {
                job.failures = job.failures.saturating_add(1);
                let wait = limits
                    .backoff_max
                    .as_secs()
                    .min(1u64 << job.failures.min(16));
                job.retry_at = now_secs() + wait;
                if !job.note.contains(&e.0) {
                    job.note = format!("{} (retrying in {wait} s)", e.0);
                }
            }
        }
        worked += 1;
        let mut st = lock(store);
        // The cancel thread owns the cancel's fields.
        if let Some(cur) = st.jobs.get(&id) {
            job.cancel_sent |= cur.cancel_sent;
            job.cancel_at = job.cancel_at.max(cur.cancel_at);
            if cur.cancel_sent && !before["cancel_sent"].as_bool().unwrap_or(false) {
                job.note = format!("{}; {}", cur.note, job.note);
            }
        }
        if job.to_json() != before {
            let _ = st.save(&job);
        }
        let ended = job.state.ended();
        st.jobs.insert(id.clone(), job);
        if ended {
            let _ = st.archive(&id);
        }
    }
    worked
}

/// How the service listens.
#[derive(Debug, Clone, Default)]
pub struct Access {
    /// The token every request must carry (`Authorization: Bearer <token>`). Required
    /// when the listener is not loopback.
    pub token: Option<String>,
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

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

fn authorized(req: &tiny_http::Request, access: &Access) -> bool {
    let Some(token) = &access.token else {
        return true;
    };
    req.headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .map(|t| same(t.trim().as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

fn handle(store: &Mutex<Store>, limits: &Limits, access: &Access, mut req: tiny_http::Request) {
    if !authorized(&req, access) {
        return respond(req, 401, &json!({"error": "a valid token is required"}));
    }
    let url = req.url().to_string();
    let method = req.method().clone();
    let mut body = String::new();
    if method == tiny_http::Method::Post {
        if req.body_length().unwrap_or(0) > limits.max_body {
            return respond(req, 413, &json!({"error": "the request is too large"}));
        }
        use std::io::Read;
        if req
            .as_reader()
            .take(limits.max_body as u64 + 1)
            .read_to_string(&mut body)
            .is_err()
        {
            return respond(req, 400, &json!({"error": "unreadable body"}));
        }
        if body.len() > limits.max_body {
            return respond(req, 413, &json!({"error": "the request is too large"}));
        }
    }
    match (method, url.trim_end_matches('/')) {
        (tiny_http::Method::Post, "/jobs") => {
            let v: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => return respond(req, 400, &json!({"error": e.to_string()})),
            };
            let job = match Job::from_request(&v) {
                Ok(j) => j,
                Err(e) => return respond(req, 400, &json!({"error": e.0})),
            };
            let r = lock(store).add(job, limits);
            match r {
                Ok(id) => respond(req, 200, &json!({"id": id})),
                Err(e) => respond(req, 400, &json!({"error": e.0})),
            }
        }
        (tiny_http::Method::Get, "/jobs") => {
            let list: Vec<Value> = lock(store)
                .jobs
                .values()
                .map(|j| json!({"id": j.id, "state": j.state.name(), "note": j.note}))
                .collect();
            respond(req, 200, &json!(list))
        }
        (tiny_http::Method::Get, p) if p.starts_with("/jobs/") => {
            let id = p[6..].to_string();
            let found = {
                let st = lock(store);
                st.jobs
                    .get(&id)
                    .map(Job::to_json)
                    .or_else(|| st.archived(&id))
            };
            match found {
                Some(j) => respond(req, 200, &j),
                None => respond(req, 404, &json!({"error": "no such job"})),
            }
        }
        _ => respond(req, 404, &json!({"error": "not found"})),
    }
}

/// Whether every address `listen` names is a loopback address.
pub fn loopback_only(listen: &str) -> bool {
    use std::net::ToSocketAddrs;
    match listen.to_socket_addrs() {
        Ok(addrs) => {
            let a: Vec<_> = addrs.collect();
            !a.is_empty() && a.iter().all(|s| s.ip().is_loopback())
        }
        Err(_) => false,
    }
}

/// Runs the service: an HTTP intake on `listen` (`POST /jobs`, `GET /jobs`,
/// `GET /jobs/<id>`), a thread that sends due cancels every `interval` (at most every
/// second), and a round of work every `interval`. `btc_cancels` is a Bitcoin client of
/// the cancel thread's own. Refuses to listen beyond loopback without a token. Never
/// returns.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    seq: SeqChain,
    btc: BtcChain,
    btc_cancels: BtcChain,
    dir: &Path,
    listen: &str,
    interval: Duration,
    limits: Limits,
    access: Access,
) -> Result<(), Error> {
    if access.token.is_none() && !loopback_only(listen) {
        return Err(Error(format!(
            "{listen} is not a loopback address: give the service a token (--token-file) so that only the wallets it serves can hand it jobs"
        )));
    }
    let store = Arc::new(Mutex::new(Store::open(dir)?));
    let server =
        tiny_http::Server::http(listen).map_err(|e| Error(format!("listen {listen}: {e}")))?;
    let (s2, l2) = (store.clone(), limits.clone());
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(&s2, &l2, &access, req);
        }
    });
    let s3 = store.clone();
    std::thread::spawn(move || loop {
        let _ = send_due_cancels(&s3, &btc_cancels);
        std::thread::sleep(interval.min(Duration::from_secs(1)));
    });
    loop {
        work_round(&store, &seq, &btc, &limits);
        std::thread::sleep(interval);
    }
}
