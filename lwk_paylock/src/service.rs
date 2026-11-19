//! The completion service: it holds a buyer's signed claims, its signed cancels and
//! its payment, and holds no key. It
//!
//! - knows the payment by the coins it spends: a transaction mined on Bitcoin that
//!   spends them and pays the seller's receiving script at least the price is the
//!   payment, whatever its id (a fee bump counts); one that spends them and does not
//!   pay so is the cancel. Nothing is inferred from a coin that is merely missing;
//! - completes the claim as soon as a Sequentia block anchors at the payment's
//!   Bitcoin block or above, with a proof of the buyer's own payment;
//! - after every reorganization that disconnects the claim, proves it again,
//!   linked to the lowest anchor the active chain recorded at or above the payment;
//! - raises the claim to its top fee tier as soon as a block is made after the
//!   claim was pooled (by anyone) and does not include it;
//! - pays the fee in whichever asset the node still accepts, when the buyer signed
//!   tiers in two;
//! - broadcasts the cancels if the payment is still unconfirmed two blocks before `D`,
//!   whatever its Sequentia node says of the lock (the cancel concerns Bitcoin alone),
//!   and sends them again until a spend of the payment's coins is confirmed;
//! - shows the claim complete once its block is final, and goes on watching in the
//!   background until the Bitcoin blocks that decided the swap are buried
//!   ([`Limits::watch_depth`]): a later Bitcoin reorganization is followed by proving
//!   the claim again, not left to what the nodes kept.
//!
//! (The node's `doc/sequentia/bitcoin-payment-proof.md`, section 8.5.)
//!
//! **Bounded.** Cancels have a thread of their own, which reads Bitcoin's tip and
//! sends every due cancel within a time budget per pass: jobs whose lock the node knows
//! go first, then those it has not answered for, then those it says it does not know;
//! within each, cancels never sent go first, nearest deadline first, then those sent
//! before, the longest ago first, so a cancel skipped in one pass is reached in the
//! next. The node's answer orders the sends and never withholds one. The work of
//! completing claims runs jobs nearest deadline first, each within a time and block
//! budget, and the whole round within a budget of its own; ended jobs that are still
//! watched come after the live ones. The search for a payment keeps its place between
//! rounds, so each Bitcoin block is read once per job. A job that fails retries with a
//! backoff. Intake caps the request's size, the claims and cancels per job, a lock's
//! span of heights and the number of live jobs, and needs a token whenever it listens
//! beyond loopback.
//!
//! **No client can block a buyer's job.** A job is named by its terms, its lock and its
//! payment's id, and whatever is posted under that name is merged into it, never refused
//! for having come second: the claims are checked against the buyer's key and pooled;
//! each cancel is kept if the Bitcoin daemon accepts it as a spend of exactly the
//! payment's coins (its signatures included), up to a few, and every one is sent; a
//! signed payment is kept once it hashes to the payment's id. What fails a check is
//! refused, whoever posted first. A read returns where a job stands, never its signed
//! claims, its cancels or its payment.
//!
//! Jobs are kept as one JSON file each, so a restart carries on where it stopped;
//! ended jobs move to `archive/` once buried, and leave it after
//! [`Limits::archive_days`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{self, fee_of, hex_decode, hex_encode, PayLockTerms};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::hashes::{sha256, Hash};
use lwk_wollet::elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

pub use crate::CANCEL_KEEP_BLOCKS;
use crate::{
    outpoint, payment_position, prove_claim, Accept, BtcChain, Completion, Error, Found,
    PaymentScan, Position, SeqChain, TxStatus,
};

/// How often a lock the node did not know is looked up again, in seconds.
const LOCK_RECHECK_SECS: u64 = 60;

/// How often a cancel already sent is sent again, in seconds.
const CANCEL_RESEND_SECS: u64 = 10;

/// The most cancels one job keeps: each a valid spend of exactly the payment's coins,
/// so only the buyer can make one. A further one takes the place of the cheapest.
pub const MAX_CANCELS: usize = 4;

/// A cancel the job keeps: a spend of exactly the payment's coins back to the buyer,
/// which the Bitcoin daemon accepted (signatures and replacement rules) when it was
/// handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    /// The raw transaction.
    pub hex: String,
    /// Its id.
    pub txid: String,
    /// Its fee in satoshis, as the daemon reported it.
    pub fee: u64,
}

/// Where a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for the payment, or for a Sequentia block anchored at it; or, past the
    /// deadline, for the cancel to confirm.
    Waiting,
    /// The completed claim is in the node's mempool.
    Pooled,
    /// The claim is mined, not yet final.
    Mined,
    /// The claim's block is final: the swap is done.
    Final,
    /// A spend of the payment's coins other than the payment is confirmed (the cancel):
    /// the buyer keeps its bitcoin.
    Cancelled,
    /// The payment can never open the lock (mined after `D` or at or below `F`, or not
    /// mined by `D`), or the lock is unknown to the node.
    Never,
    /// The lock was spent in the chain by something other than these claims: the
    /// seller's refund.
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

    /// Whether the swap has an outcome. An ended job is still watched until the Bitcoin
    /// blocks that decided it are buried, and only then archived.
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
    /// Live jobs (not yet decided) carried at once; intake refuses more. A decided job
    /// still watched does not count.
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
    /// Time one pass of the cancel thread may take; what it does not reach waits for
    /// the next pass.
    pub cancel_pass_time: Duration,
    /// The longest a failing job waits before it is tried again.
    pub backoff_max: Duration,
    /// How deep the Bitcoin block that decided an ended swap must be buried before the
    /// service stops watching it. What a person is shown does not wait for it.
    pub watch_depth: u32,
    /// How often an ended job still watched is looked at.
    pub watch_every: Duration,
    /// Days an archived job is kept.
    pub archive_days: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_jobs: 1000,
            max_body: 512 << 10,
            max_claims: 8,
            max_window: paylock::MAX_DEADLINE_AHEAD,
            blocks_per_job: 24,
            job_time: Duration::from_secs(5),
            round_time: Duration::from_secs(10),
            cancel_pass_time: Duration::from_secs(2),
            backoff_max: Duration::from_secs(60),
            watch_depth: 6,
            watch_every: Duration::from_secs(30),
            archive_days: 30,
        }
    }
}

/// One swap the service carries.
#[derive(Debug, Clone)]
pub struct Job {
    /// The job's name: a hash of its terms, its lock and its payment's id.
    pub id: String,
    /// The swap's terms.
    pub terms: PayLockTerms,
    /// The lock.
    pub lock: OutPoint,
    /// The signed claims: every tier, in every fee asset the buyer signed.
    pub claims: Vec<Transaction>,
    /// The buyer's signed cancels of its payment, cheapest last; at most [`MAX_CANCELS`].
    pub cancels: Vec<Cancel>,
    /// The payment's Bitcoin transaction id, as the buyer named it.
    pub payment: String,
    /// The signed payment itself, when the buyer hands it over or the Bitcoin daemon's
    /// mempool holds it: it names the payment's coins, and the service sends it again if
    /// a Bitcoin reorganization evicts it before `D`.
    pub payment_hex: Option<String>,
    /// Whether the daemon has vouched for `payment_hex` (accepted it, or pooled it):
    /// its witness, which its id does not cover, is then the one that relays.
    pub payment_checked: bool,
    /// Where it stands.
    pub state: State,
    /// The claim in use (an index into `claims`).
    pub tier: usize,
    /// Whether a block left the claim out, so the top tier is in use.
    pub raised: bool,
    /// The Sequentia height at which the claim in use was first seen pooled.
    pub pooled_at: Option<u32>,
    /// The height the claim was mined at, while it is mined.
    pub mined_at: Option<u32>,
    /// How far the search for the payment (and the cancel) has read Bitcoin.
    pub scan: PaymentScan,
    /// Whether a Bitcoin daemon has accepted the cancel.
    pub cancel_sent: bool,
    /// Whether the cancel has been tried at all.
    pub cancel_tried: bool,
    /// When the cancel was last tried (seconds since 1970).
    pub cancel_at: u64,
    /// Whether the node knows the lock and it pays the terms' script; `None` until looked up.
    pub lock_known: Option<bool>,
    /// When the lock was last looked up (seconds since 1970).
    pub lock_checked_at: u64,
    /// The Bitcoin height that decided an ended swap.
    pub decided_at: Option<u32>,
    /// Whether that height is buried by [`Limits::watch_depth`]: the job is then archived.
    pub buried: bool,
    /// When an ended job is next looked at (seconds since 1970).
    pub watch_at: u64,
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

/// A job's name: its terms, its lock and its payment's id, hashed. Whatever else is
/// posted under it (claims, cancels, the signed payment) is merged into the one job.
pub fn job_id(terms: &PayLockTerms, lock: &OutPoint, payment_txid: &str) -> String {
    sha256::Hash::hash(
        format!(
            "{}|{}:{}|{payment_txid}",
            terms.to_json(),
            lock.txid,
            lock.vout
        )
        .as_bytes(),
    )
    .to_string()
}

fn btc_tx(hex: &str, what: &str) -> Result<bitcoin::Transaction, Error> {
    bitcoin::consensus::encode::deserialize(&hex_decode(hex)?)
        .map_err(|e| Error(format!("the {what} is not a Bitcoin transaction: {e}")))
}

fn inputs_of(tx: &bitcoin::Transaction) -> Vec<bitcoin::OutPoint> {
    let mut v: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();
    v.sort();
    v
}

fn parse_claim(c: &Value) -> Result<Transaction, Error> {
    deserialize(&hex_decode(c.as_str().unwrap_or_default())?)
        .map_err(|e| Error(format!("a claim does not parse: {e}")))
}

/// The cancels a request or a stored job carries: `cancel` (one, as a wallet hands it
/// over) and `cancels` (as stored, each `{hex, fee}`).
fn cancels_of(v: &Value) -> Result<Vec<Cancel>, Error> {
    let mut out = vec![];
    let mut add = |hex: &str, fee: u64| -> Result<(), Error> {
        let t = btc_tx(hex, "cancel")?;
        out.push(Cancel {
            hex: hex.to_string(),
            txid: t.compute_txid().to_string(),
            fee,
        });
        Ok(())
    };
    if let Some(h) = v.get("cancel").and_then(Value::as_str) {
        add(h, 0)?;
    }
    for c in v
        .get("cancels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match c {
            Value::String(h) => add(h, 0)?,
            o => add(
                o.get("hex").and_then(Value::as_str).unwrap_or_default(),
                o.get("fee").and_then(Value::as_u64).unwrap_or(0),
            )?,
        }
    }
    Ok(out)
}

impl Job {
    /// A job from what a buyer's wallet hands over:
    /// `{terms, lock: "txid:vout", claims: [hex...], cancel?: hex, payment: txid, payment_hex?: hex}`.
    /// This checks the form only: every claim spends the lock through the claim leaf, the
    /// signed payment hashes to the payment's id, and each cancel is a Bitcoin transaction
    /// that is not the payment and spends exactly its coins when they are known.
    /// [`check_intake`] checks the signatures against the chains.
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
            .map(parse_claim)
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
            .to_lowercase();
        let payment_hex = v
            .get("payment_hex")
            .and_then(Value::as_str)
            .map(String::from);
        let cancels = cancels_of(v)?;
        if cancels.len() > MAX_CANCELS {
            return Err(Error(format!(
                "a job carries at most {MAX_CANCELS} cancels"
            )));
        }
        let mut job = Job {
            id: job_id(&terms, &lock, &payment),
            terms,
            lock,
            claims: vec![],
            cancels,
            payment,
            payment_hex,
            payment_checked: false,
            state: State::Waiting,
            tier: 0,
            raised: false,
            pooled_at: None,
            mined_at: None,
            scan: PaymentScan::default(),
            cancel_sent: false,
            cancel_tried: false,
            cancel_at: 0,
            lock_known: None,
            lock_checked_at: 0,
            decided_at: None,
            buried: false,
            watch_at: 0,
            failures: 0,
            retry_at: 0,
            note: String::new(),
        };
        for c in claims {
            job.add_claim(c);
        }
        job.check_form()?;
        Ok(job)
    }

    /// Adds a claim the job does not hold yet (by transaction id); says whether it did.
    fn add_claim(&mut self, c: Transaction) -> bool {
        let id = c.txid();
        if self.claims.iter().any(|h| h.txid() == id) {
            return false;
        }
        self.claims.push(c);
        true
    }

    /// The signed payment hashes to the payment's id, and every cancel is not the payment
    /// and spends exactly its coins when the signed payment is known.
    fn check_form(&self) -> Result<(), Error> {
        let pay = match &self.payment_hex {
            Some(h) => {
                let t = btc_tx(h, "signed payment")?;
                if t.compute_txid().to_string() != self.payment {
                    return Err(Error(
                        "the signed payment is not the payment the job names".into(),
                    ));
                }
                Some(t)
            }
            None => None,
        };
        for c in &self.cancels {
            if c.txid == self.payment {
                return Err(Error("the cancel is the payment itself".into()));
            }
            if let Some(p) = &pay {
                if inputs_of(p) != inputs_of(&btc_tx(&c.hex, "cancel")?) {
                    return Err(Error(
                        "the cancel does not spend exactly the payment's coins".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The job as stored: everything, its signed transactions included.
    pub fn to_json(&self) -> Value {
        let mut v = self.public_json();
        v["terms"] = self.terms.to_json();
        v["claims"] = json!(self
            .claims
            .iter()
            .map(|c| hex_encode(&serialize(c)))
            .collect::<Vec<_>>());
        v["cancels"] = json!(self
            .cancels
            .iter()
            .map(|c| json!({"hex": c.hex, "fee": c.fee}))
            .collect::<Vec<_>>());
        v["payment"] = json!(self.payment);
        v["payment_hex"] = json!(self.payment_hex);
        v["payment_checked"] = json!(self.payment_checked);
        v["scanned"] = json!(self
            .scan
            .scanned
            .as_ref()
            .map(|(h, b)| json!({"height": h, "block": b})));
        let f = |f: &Option<Found>| {
            json!(f
                .as_ref()
                .map(|f| json!({"height": f.height, "block": f.block, "txid": f.txid})))
        };
        v["found"] = f(&self.scan.found);
        v["cancel_found"] = f(&self.scan.cancel);
        v["lock_known"] = json!(self.lock_known);
        v["lock_checked_at"] = json!(self.lock_checked_at);
        v["cancel_at"] = json!(self.cancel_at);
        v["cancel_tried"] = json!(self.cancel_tried);
        v["retry_at"] = json!(self.retry_at);
        v["watch_at"] = json!(self.watch_at);
        v
    }

    /// Where the job stands, as the service answers anyone who reads it: no signed
    /// claim, no cancel, no payment, no terms.
    pub fn public_json(&self) -> Value {
        json!({
            "id": self.id,
            "lock": format!("{}:{}", self.lock.txid, self.lock.vout),
            "state": self.state.name(),
            "watching": self.state.ended() && !self.buried,
            "tiers": self.claims.len(),
            "tier": self.tier,
            "raised": self.raised,
            "fee": self.claims.get(self.tier).and_then(fee_of).map(|(a, f)| json!({"asset": a.to_string(), "atoms": f})),
            "pooled_at": self.pooled_at,
            "mined_at": self.mined_at,
            "payment_height": self.scan.found.as_ref().map(|f| f.height),
            "payment_bumped": self.scan.found.as_ref().map(|f| f.txid != self.payment),
            "has_cancel": !self.cancels.is_empty(),
            "cancels": self.cancels.len(),
            "cancel_sent": self.cancel_sent,
            "cancel_height": self.scan.cancel.as_ref().map(|f| f.height),
            "decided_at": self.decided_at,
            "buried": self.buried,
            "failures": self.failures,
            "note": self.note,
        })
    }

    /// A stored job.
    pub fn from_stored(v: &Value) -> Result<Job, Error> {
        let mut j = Job::from_request(v)?;
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let payment = j.payment.clone();
        let found = |k: &str| {
            v.get(k).and_then(|s| {
                Some(Found {
                    height: s.get("height")?.as_u64()? as u32,
                    block: s.get("block")?.as_str()?.to_string(),
                    txid: s
                        .get("txid")
                        .and_then(Value::as_str)
                        .unwrap_or(&payment)
                        .to_string(),
                })
            })
        };
        j.payment_checked = b("payment_checked");
        j.state = State::parse(v.get("state").and_then(Value::as_str).unwrap_or_default());
        j.tier = (n("tier").unwrap_or(0) as usize).min(j.claims.len() - 1);
        j.raised = b("raised");
        j.pooled_at = n("pooled_at").map(|n| n as u32);
        j.mined_at = n("mined_at").map(|n| n as u32);
        j.scan = PaymentScan {
            scanned: v.get("scanned").and_then(|s| {
                Some((
                    s.get("height")?.as_u64()? as u32,
                    s.get("block")?.as_str()?.to_string(),
                ))
            }),
            found: found("found"),
            cancel: found("cancel_found"),
        };
        j.cancel_sent = b("cancel_sent");
        j.cancel_tried = b("cancel_tried");
        j.cancel_at = n("cancel_at").unwrap_or(0);
        j.lock_known = v.get("lock_known").and_then(Value::as_bool);
        j.lock_checked_at = n("lock_checked_at").unwrap_or(0);
        j.decided_at = n("decided_at").map(|n| n as u32);
        j.buried = b("buried");
        j.watch_at = n("watch_at").unwrap_or(0);
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

    /// The coins the payment spends, read from the signed payment, else from a cancel
    /// (which spends exactly them); none while neither is known.
    fn payment_coins(&self) -> Vec<bitcoin::OutPoint> {
        self.payment_hex
            .as_deref()
            .or(self.cancels.first().map(|c| c.hex.as_str()))
            .and_then(|h| btc_tx(h, "payment").ok())
            .map(|t| inputs_of(&t))
            .unwrap_or_default()
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

    /// Whether the lock should be looked up now: never looked up, or not known and not
    /// looked up for a while.
    fn lock_check_due(&self, now: u64) -> bool {
        match self.lock_known {
            None => true,
            Some(true) => false,
            Some(false) => now >= self.lock_checked_at + LOCK_RECHECK_SECS,
        }
    }

    /// Keeps a checked cancel: a new one is added, up to [`MAX_CANCELS`], beyond which it
    /// takes the place of the cheapest when it pays more. Says whether it kept it.
    fn keep_cancel(&mut self, c: Cancel) -> bool {
        if self.cancels.iter().any(|h| h.txid == c.txid) {
            return false;
        }
        if self.cancels.len() >= MAX_CANCELS {
            let (i, low) = self
                .cancels
                .iter()
                .enumerate()
                .min_by_key(|(_, h)| h.fee)
                .map(|(i, h)| (i, h.fee))
                .expect("full");
            if c.fee <= low {
                return false;
            }
            self.cancels.remove(i);
        }
        self.cancels.push(c);
        self.cancels.sort_by(|a, b| b.fee.cmp(&a.fee));
        true
    }
}

/// The chains intake reads to check what it is handed: the Sequentia node for a claim's
/// fee coin and the chain's genesis, the Bitcoin daemon for the cancels and the payment.
/// Its clients give up quickly, so one slow answer holds intake back for seconds only.
pub struct Intake {
    /// The Sequentia node.
    pub seq: SeqChain,
    /// The Bitcoin daemon.
    pub btc: BtcChain,
    genesis: Mutex<Option<lwk_wollet::elements::BlockHash>>,
}

impl Intake {
    /// Intake over these clients.
    pub fn new(seq: SeqChain, btc: BtcChain) -> Self {
        Intake {
            seq,
            btc,
            genesis: Mutex::new(None),
        }
    }

    fn genesis(&self) -> Result<lwk_wollet::elements::BlockHash, Error> {
        let mut g = self.genesis.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = *g {
            return Ok(h);
        }
        let h = self.seq.genesis()?;
        *g = Some(h);
        Ok(h)
    }
}

/// Why intake refused what it was handed: the request itself (400), or a chain that did
/// not answer (503, try again).
#[derive(Debug)]
pub enum Refused {
    /// The request fails a check.
    Bad(Error),
    /// A chain did not answer.
    Unavailable(Error),
}

/// Checks a job against the chains before the service holds anything of it, and returns
/// what it did not keep, in words:
///
/// - every claim is signed by the terms' buyer for this very transaction (and its fee
///   coin, if any, by the coin's key): a claim that fails is refused;
/// - the signed payment, when given, is vouched for by the Bitcoin daemon (a payment whose
///   signatures fail is refused); when not given, the daemon's mempool is asked for it;
/// - each cancel spends exactly the payment's coins and the daemon accepts it now, its
///   signatures and the replacement of a pooled payment included. One the daemon cannot
///   check because the payment's coins are already spent in a block is not kept (it can
///   never be needed); any other refusal refuses the request. A cancel with no known
///   payment is refused: its coins cannot be compared.
pub fn check_intake(intake: &Intake, job: &mut Job) -> Result<Vec<String>, Refused> {
    let down = |e: Error| Refused::Unavailable(e);
    let genesis = intake.genesis().map_err(down)?;
    // The outputs the claims' fee coins spend, read first: a node that does not answer
    // refuses nothing for good.
    let mut coins: BTreeMap<OutPoint, Option<lwk_wollet::elements::TxOut>> = BTreeMap::new();
    for c in &job.claims {
        for i in &c.input {
            let op = i.previous_output;
            if op.txid != job.lock.txid && !coins.contains_key(&op) {
                let out = intake
                    .seq
                    .tx(&op.txid)
                    .map_err(down)?
                    .and_then(|(tx, _)| tx.output.get(op.vout as usize).cloned());
                coins.insert(op, out);
            }
        }
    }
    let mut coin =
        |op: &OutPoint| -> Result<Option<lwk_wollet::elements::TxOut>, lwk_wollet::Error> {
            Ok(coins.get(op).cloned().flatten())
        };
    for (i, c) in job.claims.iter().enumerate() {
        paylock::verify_claim(&job.terms, job.lock, c, genesis, &mut coin)
            .map_err(|e| Refused::Bad(Error(format!("claim {i}: {e}"))))?;
    }
    let mut notes = vec![];
    match job.payment_hex.clone() {
        Some(h) => match intake.btc.test_accept(&h).map_err(down)? {
            Accept::Allowed { .. } => job.payment_checked = true,
            Accept::Refused(r)
                if r.contains("already-in-mempool") || r.contains("txn-already-known") =>
            {
                job.payment_checked = true
            }
            Accept::Refused(r) if r.contains("same-nonwitness-data-in-mempool") => {
                // The daemon pools the same payment with another witness: keep its copy.
                if let Some(p) = intake.btc.mempool_tx(&job.payment).map_err(down)? {
                    job.payment_hex = Some(p);
                    job.payment_checked = true;
                }
            }
            Accept::Refused(r) if Accept::scripts_fail(&r) => {
                return Err(Refused::Bad(Error(format!(
                    "the signed payment's signatures do not verify: {r}"
                ))))
            }
            // Mined already, or its parent unseen, or outbid: kept as handed over.
            Accept::Refused(_) => {}
        },
        None => {
            if let Some(p) = intake.btc.mempool_tx(&job.payment).map_err(down)? {
                job.payment_hex = Some(p);
                job.payment_checked = true;
            }
        }
    }
    if !job.cancels.is_empty() && job.payment_hex.is_none() {
        return Err(Refused::Bad(Error(
            "a cancel is kept only beside the payment it cancels: give payment_hex, or post it once the payment is broadcast".into(),
        )));
    }
    job.check_form().map_err(Refused::Bad)?;
    let mut kept = vec![];
    for mut c in std::mem::take(&mut job.cancels) {
        match intake.btc.test_accept(&c.hex).map_err(down)? {
            Accept::Allowed { fee } => {
                c.fee = fee;
                kept.push(c);
            }
            Accept::Refused(r) if Accept::scripts_fail(&r) => {
                return Err(Refused::Bad(Error(format!(
                    "the cancel's signatures do not verify: {r}"
                ))))
            }
            Accept::Refused(r) if Accept::coins_missing(&r) => notes.push(format!(
                "the cancel {} was not kept: the payment's coins are spent in a block already ({r})",
                c.txid
            )),
            Accept::Refused(r) => {
                return Err(Refused::Bad(Error(format!(
                    "the Bitcoin daemon does not accept the cancel: {r}; a cancel must pay enough to replace the payment"
                ))))
            }
        }
    }
    job.cancels = vec![];
    for c in kept {
        job.keep_cancel(c);
    }
    Ok(notes)
}

/// Whether the node knows the lock and its output pays the terms' lock script. A job
/// whose lock is not so is stale: no cancel or claim of it is worth any work.
fn lock_on_chain(seq: &SeqChain, job: &Job) -> Result<bool, Error> {
    let spk = job.terms.tree()?.script_pubkey;
    match seq.rpc.call(
        "getrawtransaction",
        json!([job.lock.txid.to_string(), true]),
    ) {
        Ok(v) => {
            let tx: Transaction = deserialize(&hex_decode(
                v.get("hex").and_then(Value::as_str).unwrap_or_default(),
            )?)
            .map_err(|e| Error(format!("the lock does not parse: {e}")))?;
            Ok(tx
                .output
                .get(job.lock.vout as usize)
                .map(|o| o.script_pubkey == spk)
                .unwrap_or(false))
        }
        // A node without a transaction index cannot say: that is no answer, never "unknown".
        Err(crate::RpcError::Rpc { code: -5, message }) if message.contains("-txindex") => Err(
            Error("the node keeps no transaction index (-txindex=1)".into()),
        ),
        Err(crate::RpcError::Rpc { code: -5, .. }) => Ok(false),
        Err(e) => Err(e.into()),
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

/// Ends a job with `state`, decided by Bitcoin height `at`; buried once the tip is
/// `watch_depth` blocks deep on it.
fn end(job: &mut Job, state: State, at: u32, btc_tip: u32, limits: &Limits, note: String) {
    job.state = state;
    job.decided_at = Some(at);
    job.buried = btc_tip.saturating_add(1) >= at.saturating_add(limits.watch_depth);
    job.note = note;
}

/// Moves one job on, once, within `limits` and before `until`. Every step reads the
/// chains as they are now, so a reorganization of either chain is followed at the next
/// round, an ended job's included. The cancel is not sent here: [`send_due_cancels`]
/// sends it.
pub fn tick(
    seq: &SeqChain,
    btc: &BtcChain,
    job: &mut Job,
    limits: &Limits,
    until: Instant,
) -> Result<(), Error> {
    let now = now_secs();
    // Mined, and final? Any tier may be the one mined.
    let finalized = seq.finalized_height()?;
    let mut pooled = None;
    for (i, c) in job.claims.iter().enumerate() {
        match seq.status(&c.txid())? {
            TxStatus::Mined(h) => {
                job.mined_at = Some(h);
                job.tier = i;
                if h <= finalized {
                    // Final: shown at once. Watched until the payment's block and the
                    // claim's anchor are buried.
                    let anchor = seq.at(h)?.anchor_height;
                    let at = anchor.max(job.scan.found.as_ref().map(|f| f.height).unwrap_or(0));
                    end(
                        job,
                        State::Final,
                        at,
                        btc.tip()?,
                        limits,
                        format!("the claim {} is final at Sequentia height {h}", c.txid()),
                    );
                } else {
                    job.state = State::Mined;
                    job.decided_at = None;
                    job.buried = false;
                    job.note = format!("the claim {} is mined at {h}, not final yet", c.txid());
                }
                return Ok(());
            }
            TxStatus::Pooled => pooled = Some(i),
            TxStatus::Unknown => {}
        }
    }
    job.mined_at = None;
    if job.state == State::Final || job.state == State::Mined {
        job.note = "the claim's block left the chain: proving it again".into();
    }
    // Out of time: the job carries on from here next round.
    if Instant::now() >= until {
        return Ok(());
    }
    // The lock, looked up once (again a minute later while the node does not know it).
    if job.lock_check_due(now) {
        job.lock_known = Some(lock_on_chain(seq, job)?);
        job.lock_checked_at = now;
    }
    let seq_tip = seq.height()?;

    // A block made after the claim was first seen pooled, by whoever pooled it, left it
    // out: the top tier, at once.
    match pooled {
        Some(i) => match job.pooled_at {
            None => {
                job.pooled_at = Some(seq_tip);
                job.tier = i;
                job.note = format!(
                    "the claim (tier {i}) is pooled at Sequentia height {seq_tip}; a block that leaves it out raises it to the top tier"
                );
            }
            Some(at) if seq_tip > at && !job.raised => {
                job.raised = true;
                job.pooled_at = None;
                job.note =
                    format!("a block at {seq_tip} left the claim out: raised to the top tier");
            }
            Some(_) => {}
        },
        None => {
            job.pooled_at = None;
            // Spent in the chain by none of these claims: the seller refunded.
            if !seq.unspent_in_chain(&job.lock)? && seq.coin_anchor(&job.lock.txid)?.is_some() {
                let at = match (job.state, job.decided_at) {
                    (State::Refunded, Some(a)) => a,
                    _ => seq.at(seq_tip)?.anchor_height,
                };
                end(
                    job,
                    State::Refunded,
                    at,
                    btc.tip()?,
                    limits,
                    "the lock is spent by another transaction: the seller's refund".into(),
                );
                return Ok(());
            }
        }
    }

    if Instant::now() >= until {
        return Ok(());
    }
    // The payment's coins name it on Bitcoin. Not handed over: the daemon's mempool may
    // hold it (only its own id, which covers its inputs, is trusted).
    if job.payment_hex.is_none() && job.scan.found.is_none() {
        if let Some(p) = btc.mempool_tx(&job.payment)? {
            if btc_tx(&p, "payment")?.compute_txid().to_string() == job.payment {
                job.payment_hex = Some(p);
                job.payment_checked = true;
            }
        }
    }
    let coins = job.payment_coins();
    let complete = btc.scan_for(
        &job.payment,
        &coins,
        &job.terms,
        &mut job.scan,
        limits.blocks_per_job,
        until,
    )?;
    let btc_tip = btc.tip()?;
    // A confirmed spend of the payment's coins that does not pay the seller settles it:
    // the payment can no longer be mined. Decided at that block.
    if job.scan.found.is_none() {
        if let Some(c) = job.scan.cancel.clone() {
            let ours = job.cancels.iter().any(|x| x.txid == c.txid);
            end(
                job,
                State::Cancelled,
                c.height,
                btc_tip,
                limits,
                if ours {
                    format!(
                        "the cancel {} is confirmed in Bitcoin block {}: the buyer keeps its bitcoin",
                        c.txid, c.height
                    )
                } else {
                    format!(
                        "the payment's coins are spent in Bitcoin block {} by {}, which does not pay the seller the price: the payment can no longer be mined",
                        c.height, c.txid
                    )
                },
            );
            return Ok(());
        }
    }
    match payment_position(&job.terms, &job.scan, complete, btc_tip) {
        Position::Never(why) => {
            match &job.scan.found {
                Some(f) => {
                    let h = f.height;
                    end(job, State::Never, h, btc_tip, limits, why);
                }
                None if !job.cancels.is_empty() => {
                    // Not mined by D, and cancels to send. The swap has an outcome only once
                    // a spend of the payment's coins is confirmed (found above), whatever
                    // the Sequentia node says of the lock: the cancel concerns Bitcoin alone.
                    if btc_tip > job.terms.deadline.saturating_add(CANCEL_KEEP_BLOCKS) {
                        let d = job.terms.deadline;
                        end(
                            job,
                            State::Never,
                            d,
                            btc_tip,
                            limits,
                            format!("{why}; no spend of the payment's coins confirmed in {CANCEL_KEEP_BLOCKS} blocks"),
                        );
                    } else {
                        job.state = State::Waiting;
                        job.decided_at = None;
                        job.buried = false;
                        job.note = if job.cancel_sent {
                            format!("{why}; the cancel is broadcast and not confirmed yet: it is sent again until a spend of the payment's coins is")
                        } else {
                            format!("{why}; the cancel is not accepted yet: it is sent again")
                        };
                    }
                }
                None => {
                    let d = job.terms.deadline;
                    end(job, State::Never, d, btc_tip, limits, why);
                }
            }
        }
        Position::Waiting(why) => {
            job.state = State::Waiting;
            job.decided_at = None;
            job.buried = false;
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
            job.decided_at = None;
            job.buried = false;
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
            match prove_claim(seq, btc, &job.terms, &job.lock, &job.claims[want], &found)? {
                Completion::Ready { tx, height, .. } => match seq.send(&tx) {
                    Ok(_) => {
                        job.tier = want;
                        job.pooled_at = Some(seq_tip);
                        job.state = State::Pooled;
                        job.note = format!(
                            "the claim ({}tier, fee {}) is pooled with a proof of the payment {}{} in Bitcoin block {height}",
                            if job.raised { "top " } else { "going " },
                            fee_of(&tx).map(|(a, f)| format!("{f} atoms of {a}")).unwrap_or_default(),
                            found.txid,
                            if found.txid != job.payment { " (a replacement of the one named, spending its coins)" } else { "" },
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
                    end(job, State::Never, found.height, btc_tip, limits, why);
                }
            }
        }
    }
    Ok(())
}

/// One pass of the cancel thread. It reads Bitcoin's tip and sends the cancels that are
/// due (a job not ended, with cancels, its payment not known to be mined in the lock's
/// heights and no spend of its coins confirmed, the tip two blocks before `D` or later,
/// and not more than [`CANCEL_KEEP_BLOCKS`] past `D`), within
/// [`Limits::cancel_pass_time`] (and half as long again for looking up locks the node has
/// not answered for). Every due cancel is sent, whatever the Sequentia node
/// says of the lock: the cancel concerns Bitcoin alone, and a node still syncing must not
/// cost a buyer its bitcoin. The node's answer only orders the sends: jobs whose lock it
/// knows first, then those it has not answered for, then those it says it does not know.
/// Within each, cancels never tried go first, nearest deadline first; then those tried
/// before, the longest ago first (each at most every ten seconds), so what one pass does
/// not reach the next one does. A job's cancels go out highest fee first. Returns how many
/// cancels a daemon accepted.
pub fn send_due_cancels(
    store: &Mutex<Store>,
    btc: &BtcChain,
    seq: &SeqChain,
    limits: &Limits,
) -> Result<usize, Error> {
    let start = Instant::now();
    let tip = btc.tip()?;
    let now = now_secs();
    let due = |j: &Job| {
        !j.cancels.is_empty()
            && !j.state.ended()
            && !j.paid_in_window()
            && j.scan.cancel.is_none()
            && paylock::cancel_due(&j.terms, tip, false)
            && tip <= j.terms.deadline.saturating_add(CANCEL_KEEP_BLOCKS)
            && (!j.cancel_tried || now >= j.cancel_at + CANCEL_RESEND_SECS)
    };
    // Locks never looked up, looked up within half the pass: an unanswered node only
    // leaves them where they are in the order.
    let unknown: Vec<Job> = lock(store)
        .jobs
        .values()
        .filter(|j| due(j) && j.lock_known.is_none())
        .cloned()
        .collect();
    let lookups_end = start + limits.cancel_pass_time / 2;
    for job in unknown {
        if Instant::now() >= lookups_end {
            break;
        }
        let Ok(known) = lock_on_chain(seq, &job) else {
            break;
        };
        let mut st = lock(store);
        if let Some(j) = st.jobs.get_mut(&job.id) {
            j.lock_known = Some(known);
            j.lock_checked_at = now;
            let j = j.clone();
            let _ = st.save(&j);
        }
    }
    // The sends have the pass's budget of their own, so a lookup never costs a send.
    let end_at = Instant::now() + limits.cancel_pass_time;
    let mut order: Vec<(u8, bool, u64, String)> = lock(store)
        .jobs
        .values()
        .filter(|j| due(j))
        .map(|j| {
            let rank = match j.lock_known {
                Some(true) => 0,
                None => 1,
                Some(false) => 2,
            };
            let key = if j.cancel_tried {
                j.cancel_at
            } else {
                u64::from(j.terms.deadline)
            };
            (rank, j.cancel_tried, key, j.id.clone())
        })
        .collect();
    order.sort();
    let mut sent = 0;
    for (_, _, _, id) in order {
        let Some(job) = lock(store).jobs.get(&id).cloned() else {
            continue;
        };
        let mut accepted = false;
        let mut refused = None;
        let mut tried = false;
        for c in &job.cancels {
            if Instant::now() >= end_at {
                break;
            }
            tried = true;
            match btc.send_raw(&c.hex) {
                Ok(_) => {
                    sent += 1;
                    accepted = true;
                }
                Err(e) => {
                    let m = e.to_string();
                    if m.contains("already") {
                        accepted = true;
                    } else {
                        refused.get_or_insert(m);
                    }
                }
            }
        }
        if !tried {
            break;
        }
        let mut st = lock(store);
        let Some(j) = st.jobs.get_mut(&id) else {
            continue;
        };
        j.cancel_tried = true;
        j.cancel_at = now;
        if accepted {
            if !j.cancel_sent {
                j.note = format!(
                    "the payment did not confirm by Bitcoin block {tip} (two before the deadline): the cancel is broadcast"
                );
            }
            j.cancel_sent = true;
        } else if let Some(m) = refused {
            if !j.cancel_sent {
                j.note = format!("the cancel was refused: {m}");
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

/// What [`Store::add`] did with a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Added {
    /// A new job.
    New,
    /// The same job was already held.
    Same,
    /// The held job lacked what this one adds (named).
    Merged(Vec<&'static str>),
}

/// The jobs, kept one file each under a directory; ended and buried jobs under `archive/`.
pub struct Store {
    dir: PathBuf,
    /// The jobs being carried (watched ones included), by id.
    pub jobs: BTreeMap<String, Job>,
}

impl Store {
    /// Opens (or creates) the store and reads every job in it; any ended and buried job
    /// found among them is archived.
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
            let mut j = Job::from_stored(&v)?;
            // A file written under another name (an older naming of jobs) takes the job's;
            // two that now share a name are one job.
            let named = dir.join(format!("{}.json", j.id));
            if p != named {
                if let Some(h) = jobs.remove(&j.id) {
                    j = merge(h, j, &Limits::default())?.0;
                }
                std::fs::write(
                    &named,
                    serde_json::to_vec_pretty(&j.to_json()).map_err(|e| Error(e.to_string()))?,
                )
                .map_err(|e| Error(e.to_string()))?;
                std::fs::remove_file(&p).map_err(|e| Error(e.to_string()))?;
            }
            jobs.insert(j.id.clone(), j);
        }
        let mut st = Store {
            dir: dir.to_path_buf(),
            jobs,
        };
        let done: Vec<String> = st
            .jobs
            .values()
            .filter(|j| j.state.ended() && j.buried)
            .map(|j| j.id.clone())
            .collect();
        for id in done {
            st.archive(&id)?;
        }
        Ok(st)
    }

    /// Adds a job, checked by [`check_intake`]. A job already held under the same name
    /// (terms, lock, payment) takes in what this one adds and keeps all it held: claims
    /// it lacks, cancels it lacks (up to [`MAX_CANCELS`], the cheapest giving way), and a
    /// signed payment it lacks or held unvouched. Nothing is refused for having come
    /// second. A job that has ended and is archived is answered with its id.
    pub fn add(&mut self, job: Job, limits: &Limits) -> Result<(String, Added), Error> {
        let id = job.id.clone();
        if job.claims.len() > limits.max_claims {
            return Err(Error(format!(
                "a job carries at most {} signed claims",
                limits.max_claims
            )));
        }
        if let Some(held) = self.jobs.get(&id).cloned() {
            let (m, what) = merge(held, job, limits)?;
            if what.is_empty() {
                return Ok((id, Added::Same));
            }
            self.save(&m)?;
            self.jobs.insert(id.clone(), m);
            return Ok((id, Added::Merged(what)));
        }
        if self.archived(&id).is_some() {
            return Ok((id, Added::Same));
        }
        let live = self.jobs.values().filter(|j| !j.state.ended()).count();
        if live >= limits.max_jobs {
            return Err(Error(format!(
                "the service carries {live} live jobs, its limit; try another service or later"
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
        Ok((id, Added::New))
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

    /// Moves a job to the archive.
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

    /// Removes archived jobs older than `days`. Returns how many it removed.
    pub fn prune_archive(&self, days: u64) -> usize {
        let Ok(rd) = std::fs::read_dir(self.dir.join("archive")) else {
            return 0;
        };
        let max_age = Duration::from_secs(days * 86_400);
        let mut n = 0;
        for e in rd.flatten() {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|a| a > max_age)
                .unwrap_or(false);
            if old && std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
        n
    }
}

/// `held` with what `new`, posted under the same name, adds: its claims, its cancels and
/// its signed payment. Returns the merged job and what it took in.
fn merge(mut held: Job, new: Job, limits: &Limits) -> Result<(Job, Vec<&'static str>), Error> {
    let mut what = vec![];
    let mut claims = held.claims.clone();
    for c in new.claims {
        let id = c.txid();
        if !claims.iter().any(|h| h.txid() == id) {
            claims.push(c);
        }
    }
    if claims.len() > limits.max_claims {
        return Err(Error(format!(
            "a job carries at most {} signed claims",
            limits.max_claims
        )));
    }
    if claims.len() > held.claims.len() {
        held.claims = claims;
        what.push("claims");
    }
    let vouched = new.payment_checked && !held.payment_checked;
    if new.payment_hex.is_some() && (held.payment_hex.is_none() || vouched) {
        held.payment_hex = new.payment_hex;
        held.payment_checked = new.payment_checked;
        what.push("payment_hex");
    }
    let mut took = false;
    for c in new.cancels {
        took |= held.keep_cancel(c);
    }
    if took {
        what.push("cancels");
    }
    // The cancels held are spends of exactly the payment's coins, now that it is known.
    held.check_form()?;
    Ok((held, what))
}

/// One round of work: the live jobs (not ended, not backing off), nearest deadline
/// first, then the ended ones still watched whose turn has come, each within its budget,
/// the whole within the round's. The store's lock is held only to copy a job out and to
/// put it back, so intake and cancels never wait on the chains. An ended job is archived
/// once the Bitcoin block that decided it is buried. Returns how many jobs it worked on.
pub fn work_round(store: &Mutex<Store>, seq: &SeqChain, btc: &BtcChain, limits: &Limits) -> usize {
    let start = Instant::now();
    let round_end = start + limits.round_time;
    let now = now_secs();
    let mut order: Vec<(bool, u32, String)> = lock(store)
        .jobs
        .values()
        .filter(|j| j.retry_at <= now && (!j.state.ended() || j.watch_at <= now))
        .map(|j| (j.state.ended(), j.terms.deadline, j.id.clone()))
        .collect();
    order.sort();
    let mut worked = 0;
    for (_, _, id) in order {
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
        job.watch_at = if job.state.ended() {
            now_secs() + limits.watch_every.as_secs()
        } else {
            0
        };
        worked += 1;
        let mut st = lock(store);
        // The cancel thread owns the cancel's fields and may have looked the lock up.
        if let Some(cur) = st.jobs.get(&id) {
            job.cancel_sent |= cur.cancel_sent;
            job.cancel_tried |= cur.cancel_tried;
            job.cancel_at = job.cancel_at.max(cur.cancel_at);
            if cur.lock_checked_at > job.lock_checked_at {
                job.lock_known = cur.lock_known;
                job.lock_checked_at = cur.lock_checked_at;
            }
            // Intake may have merged claims, cancels or a signed payment meanwhile.
            for c in &cur.claims {
                job.add_claim(c.clone());
            }
            for c in &cur.cancels {
                job.keep_cancel(c.clone());
            }
            if cur.payment_hex.is_some()
                && (job.payment_hex.is_none() || (cur.payment_checked && !job.payment_checked))
            {
                job.payment_hex = cur.payment_hex.clone();
                job.payment_checked = cur.payment_checked;
            }
            if cur.cancel_sent && !before["cancel_sent"].as_bool().unwrap_or(false) {
                job.note = format!("{}; {}", cur.note, job.note);
            }
        }
        if job.to_json() != before {
            let _ = st.save(&job);
        }
        let done = job.state.ended() && job.buried;
        st.jobs.insert(id.clone(), job);
        if done {
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

fn handle(
    store: &Mutex<Store>,
    limits: &Limits,
    access: &Access,
    intake: &Intake,
    mut req: tiny_http::Request,
) {
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
            let mut job = match Job::from_request(&v) {
                Ok(j) => j,
                Err(e) => return respond(req, 400, &json!({"error": e.0})),
            };
            let notes = match check_intake(intake, &mut job) {
                Ok(n) => n,
                Err(Refused::Bad(e)) => return respond(req, 400, &json!({"error": e.0})),
                Err(Refused::Unavailable(e)) => {
                    return respond(
                        req,
                        503,
                        &json!({"error": format!("a chain did not answer, try again: {}", e.0)}),
                    )
                }
            };
            let r = lock(store).add(job, limits);
            match r {
                Ok((id, Added::New)) => respond(req, 200, &json!({"id": id, "notes": notes})),
                Ok((id, Added::Same)) => {
                    respond(req, 200, &json!({"id": id, "held": true, "notes": notes}))
                }
                Ok((id, Added::Merged(what))) => {
                    respond(req, 200, &json!({"id": id, "merged": what, "notes": notes}))
                }
                Err(e) => respond(req, 400, &json!({"error": e.0})),
            }
        }
        (tiny_http::Method::Get, "/jobs") => {
            let list: Vec<Value> = lock(store)
                .jobs
                .values()
                .map(|j| json!({"id": j.id, "state": j.state.name(), "watching": j.state.ended() && !j.buried}))
                .collect();
            respond(req, 200, &json!(list))
        }
        (tiny_http::Method::Get, p) if p.starts_with("/jobs/") => {
            let id = p[6..].to_string();
            let found = {
                let st = lock(store);
                st.jobs.get(&id).map(Job::public_json).or_else(|| {
                    st.archived(&id)
                        .and_then(|v| Job::from_stored(&v).ok())
                        .map(|j| j.public_json())
                })
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

/// The chain clients the service uses: one pair for the work of completing claims, one
/// for the cancel thread and one for intake, so none waits on another's calls.
pub struct Clients {
    /// The Sequentia node, for the work.
    pub seq: SeqChain,
    /// The Bitcoin daemon, for the work.
    pub btc: BtcChain,
    /// The Sequentia node, for the cancel thread's lock lookups.
    pub seq_cancels: SeqChain,
    /// The Bitcoin daemon, for the cancel thread's sends.
    pub btc_cancels: BtcChain,
    /// The Sequentia node, for intake's checks of the claims.
    pub seq_intake: SeqChain,
    /// The Bitcoin daemon, for intake's checks of the cancels and the payment.
    pub btc_intake: BtcChain,
}

/// Runs the service: an HTTP intake on `listen` (`POST /jobs`, `GET /jobs`,
/// `GET /jobs/<id>`), a thread that sends due cancels every `interval` (at most every
/// second), and a round of work every `interval`. Refuses to listen beyond loopback
/// without a token. Never returns.
pub fn serve(
    clients: Clients,
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
    let (s3, l3) = (store.clone(), limits.clone());
    let Clients {
        seq,
        btc,
        seq_cancels,
        btc_cancels,
        seq_intake,
        btc_intake,
    } = clients;
    let (s2, l2) = (store.clone(), limits.clone());
    let intake = Intake::new(seq_intake, btc_intake);
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            handle(&s2, &l2, &access, &intake, req);
        }
    });
    std::thread::spawn(move || loop {
        let _ = send_due_cancels(&s3, &btc_cancels, &seq_cancels, &l3);
        std::thread::sleep(interval.min(Duration::from_secs(1)));
    });
    let mut pruned = Instant::now();
    lock(&store).prune_archive(limits.archive_days);
    loop {
        work_round(&store, &seq, &btc, &limits);
        if pruned.elapsed() > Duration::from_secs(3600) {
            lock(&store).prune_archive(limits.archive_days);
            pruned = Instant::now();
        }
        std::thread::sleep(interval);
    }
}
