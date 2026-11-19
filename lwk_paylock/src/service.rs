//! The completion service: it holds a buyer's signed claims, its signed cancels and
//! its payment, and holds no key. It
//!
//! - knows the payment from Bitcoin alone: a transaction mined above `F` and at or
//!   below `D` that pays the seller's receiving script at least the price is the
//!   payment, whoever made it and whatever its id or coins, since that is what the
//!   claim's script accepts. No payment handed over is needed to complete the claim;
//! - knows each payment it holds by the coins it spends: a confirmed spend of them that
//!   does not pay is its cancel. Nothing is inferred from a coin that is merely missing;
//! - completes the claim as soon as a Sequentia block anchors at the payment's
//!   Bitcoin block or above, with a proof of that payment;
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
//! backoff. Intake caps the request's size, the size of each transaction it keeps, the
//! claims, payments and cancels per job, a lock's span of heights, the number of live
//! jobs and those each client starts, and needs a token whenever it listens
//! beyond loopback. Each request is served on a thread of its own under deadlines, and
//! no address takes every connection ([`http`]), so a slow or crowding client stalls
//! nobody else.
//!
//! **No client can block a buyer's job.** There is one job per lock, named by the lock
//! alone, and whatever is posted for that lock is merged into it, never refused for
//! having come second and never given a place of its own: a payment id a client names
//! is only a hint. The claims are checked against the buyer's key. Each payment handed
//! over must pay the terms; the daemon judges it, and one it accepts is broadcast, so a
//! payment held as vouched for is one Bitcoin pools or has mined: real coins paying the
//! seller, which open the lock if they are mined in time. Such a post is never refused
//! for a limit. A payment the daemon cannot check yet (its parent unseen) is unverified
//! and held only within a bound, beyond which the answer is to post it again once its
//! parent is broadcast. Each cancel spends exactly the coins of a payment held and is
//! kept with it if the daemon accepts it (its signatures included) or already holds it,
//! up to a few per payment, and every one is sent; one whose coins the daemon does not
//! know yet is kept unchecked and checked again until it does. So nothing unverified
//! takes what a real buyer needs: completing the claim needs nothing posted, and a paying
//! payment and its valid cancels are never crowded out, since only the payment's signer
//! can make them.
//! A cancel is known by its witness id, never its transaction id alone (which does not
//! cover the witness): a copy of the buyer's cancel with a bad witness is a copy of its
//! own, held beside the buyer's, dropped once its signatures can be checked, and never
//! stands in for the buyer's. What fails a check is refused, whoever posted first. A
//! request names only what a wallet hands over; nothing the service keeps of its own
//! (payments held, unchecked cancels, a cancel's fee, the client) is read from it. A new
//! job needs a real lock, an unspent output paying the terms, so nobody fills the service
//! with made-up ones. A read returns where a job stands, never its signed claims, its
//! cancels or its payments.
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
    http, outpoint, payment_position, prove_claim, Accept, BtcChain, Completion, Error, Found,
    PaymentScan, Position, SeqChain, Settled, TxStatus,
};

/// How often a lock the node did not know is looked up again, in seconds.
const LOCK_RECHECK_SECS: u64 = 60;

/// How often a cancel already sent is sent again, in seconds.
const CANCEL_RESEND_SECS: u64 = 10;

/// The most cancels one job keeps: each a valid spend of exactly the payment's coins,
/// so only the buyer can make one. A further one takes the place of the cheapest.
pub const MAX_CANCELS: usize = 4;

/// The most cancels one job keeps that the Bitcoin daemon could not check yet, because it
/// does not know the coins they spend (the payment's parent is not broadcast yet). Each
/// is checked again until it can be: kept if valid, dropped if its signatures fail.
pub const MAX_PENDING_CANCELS: usize = 16;

/// The most of those one client may hand over for one job.
pub const PENDING_PER_CLIENT: usize = 2;

/// The most fee coins the claims of one post may spend (each is looked up on the node).
const MAX_FEE_COINS: usize = 16;

/// The largest Bitcoin transaction intake keeps, a cancel or a signed payment, in bytes.
/// A cancel spends exactly the payment's coins back to the buyer, so it is about the
/// payment's size; this is some two hundred inputs.
pub const MAX_TX_BYTES: usize = 32 << 10;

/// The most payments one job holds that the Bitcoin daemon cannot vouch for yet (their
/// coins are unknown to it: a parent not broadcast), and the most of those one client may
/// hand over. A payment the daemon pools or has mined is never refused nor given up.
pub const MAX_UNVOUCHED_PAYMENTS: usize = 8;
/// See [`MAX_UNVOUCHED_PAYMENTS`].
pub const UNVOUCHED_PER_CLIENT: usize = 2;

/// A cancel the job keeps: a spend of exactly the payment's coins back to the buyer.
///
/// A cancel is known by its witness transaction id (`wtxid`), never by its `txid` alone:
/// a Bitcoin transaction id does not cover the witness, so two copies of one transaction,
/// one validly signed and one not, share a `txid`. Each copy is held on its own, and one
/// the daemon vouched for is never displaced by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    /// The raw transaction.
    pub hex: String,
    /// Its id (which does not cover its witness).
    pub txid: String,
    /// Its witness transaction id: what tells one copy of it from another.
    pub wtxid: String,
    /// Its fee in satoshis, as the daemon reported it (0 while it cannot be checked).
    pub fee: u64,
    /// Whether the daemon vouched for this very copy, witness included: it accepted it,
    /// or holds it in its mempool. A cancel already mined is kept unvouched: the daemon
    /// answers for its id, not its witness.
    pub vouched: bool,
    /// For a cancel not checked yet, the client that handed it over.
    pub by: String,
}

impl Cancel {
    /// A cancel from its raw transaction, not vouched for, not by anyone.
    fn new(hex: &str) -> Result<Cancel, Error> {
        let t = btc_tx(hex, "cancel")?;
        Ok(Cancel {
            hex: hex.to_string(),
            txid: t.compute_txid().to_string(),
            wtxid: t.compute_wtxid().to_string(),
            fee: 0,
            vouched: false,
            by: String::new(),
        })
    }
}

/// A payment the job holds: a signed Bitcoin transaction that pays the terms' receiving
/// script at least the price, known by the coins it spends, with the buyer's cancels of
/// it. Several may be held (the buyer's, a replacement of it, anyone's); none is the
/// job's name, and none is needed to complete the claim, which the service does for any
/// payment Bitcoin mines in the lock's heights. A payment is held so that its cancels are:
/// a cancel spends exactly the coins of a payment held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// The coins it spends, sorted: what it is known by.
    pub coins: Vec<bitcoin::OutPoint>,
    /// The signed transaction held: the copy the daemon vouched for, when there is one.
    pub hex: String,
    /// Its id.
    pub txid: String,
    /// Whether the Bitcoin daemon pools it or has mined it: real coins, validly signed,
    /// paying the seller. Until then (its parent unknown to the daemon) it is unverified,
    /// and held within [`MAX_UNVOUCHED_PAYMENTS`].
    pub vouched: bool,
    /// The client that handed it over.
    pub by: String,
    /// The cancels of it the daemon judged valid, highest fee first; at most
    /// [`MAX_CANCELS`], each copy known by its witness id.
    pub cancels: Vec<Cancel>,
    /// The cancels of it the daemon could not check yet; at most [`MAX_PENDING_CANCELS`],
    /// [`PENDING_PER_CLIENT`] from one client.
    pub pending: Vec<Cancel>,
    /// The first confirmed spend of its coins, once Bitcoin has one.
    pub settled: Option<Settled>,
}

impl Payment {
    /// A payment from its signed transaction, if it pays the terms' receiving script at
    /// least the price; not vouched for, handed over by `by`.
    fn new(hex: &str, terms: &PayLockTerms, by: &str) -> Result<Payment, Error> {
        let t = btc_tx(hex, "signed payment")?;
        let spk = terms.receive_script_pubkey();
        if !t
            .output
            .iter()
            .any(|o| o.script_pubkey == spk && o.value.to_sat() >= terms.price_sat)
        {
            return Err(Error(
                "the signed payment does not pay the terms' receiving script the price".into(),
            ));
        }
        Ok(Payment {
            coins: inputs_of(&t),
            hex: hex.to_string(),
            txid: t.compute_txid().to_string(),
            vouched: false,
            by: by.to_string(),
            cancels: vec![],
            pending: vec![],
            settled: None,
        })
    }

    /// Whether Bitcoin has shown its coins real: the daemon vouched for the payment, or for
    /// a cancel of it (a valid spend of exactly these coins, signed by their owner).
    fn real(&self) -> bool {
        self.vouched || self.cancels.iter().any(|c| c.vouched)
    }

    /// Whether it holds a cancel, checked or not.
    fn has_cancel(&self) -> bool {
        !self.cancels.is_empty() || !self.pending.is_empty()
    }

    /// Keeps a checked cancel, by its `wtxid`: a new one is added, up to [`MAX_CANCELS`],
    /// beyond which it takes the place of the cheapest when it pays more. A copy vouched
    /// for takes the place of an unvouched copy of the same transaction, and makes the
    /// unchecked copies of it redundant; a copy of a transaction held vouched for adds
    /// nothing. Only the payment's signer can make a valid cancel of it, so nobody else
    /// can crowd these out. Says whether it kept it.
    fn keep_cancel(&mut self, c: Cancel) -> bool {
        if self.cancels.iter().any(|h| h.wtxid == c.wtxid) {
            return false;
        }
        // The same transaction held vouched for: this copy adds nothing. (Unvouched copies
        // of one transaction are each kept, and each judged by the daemon when sent.)
        if self.cancels.iter().any(|h| h.txid == c.txid && h.vouched) {
            return false;
        }
        // An unvouched copy of the same transaction gives way to a vouched one.
        let gives_way = |h: &Cancel| c.vouched && h.txid == c.txid && !h.vouched;
        let staying = self.cancels.iter().filter(|h| !gives_way(h)).count();
        if staying >= MAX_CANCELS {
            let (i, low) = self
                .cancels
                .iter()
                .enumerate()
                .filter(|(_, h)| !gives_way(h))
                .min_by_key(|(_, h)| (h.fee, h.vouched))
                .map(|(i, h)| (i, h.fee))
                .expect("full");
            if c.fee <= low {
                return false;
            }
            self.cancels.remove(i);
        }
        if c.vouched {
            // Kept: the unvouched and unchecked copies of it are redundant.
            self.cancels.retain(|h| !gives_way(h));
            self.pending.retain(|p| p.txid != c.txid);
        }
        self.pending.retain(|p| p.wtxid != c.wtxid);
        self.cancels.push(Cancel {
            by: String::new(),
            ..c
        });
        self.cancels.sort_by(|a, b| b.fee.cmp(&a.fee));
        true
    }

    /// Keeps a cancel the daemon could not check yet, by its `wtxid`, up to
    /// [`MAX_PENDING_CANCELS`] and [`PENDING_PER_CLIENT`] from its client; says whether it
    /// is new. A copy that differs from one held only in its witness is a copy of its own:
    /// one with a bad witness never stands in for the buyer's. A copy of a transaction held
    /// vouched for adds nothing. Beyond those limits it is refused, and the answer says to
    /// post it again once the payment's parent is broadcast, when it can be checked and
    /// kept with the checked ones.
    fn keep_pending(&mut self, c: Cancel) -> Result<bool, Refused> {
        if self
            .cancels
            .iter()
            .chain(&self.pending)
            .any(|h| h.wtxid == c.wtxid)
            || self.cancels.iter().any(|h| h.txid == c.txid && h.vouched)
        {
            return Ok(false);
        }
        let mine = self.pending.iter().filter(|p| p.by == c.by).count();
        if self.pending.len() >= MAX_PENDING_CANCELS || mine >= PENDING_PER_CLIENT {
            return Err(Refused::Limit(Error(
                "the job holds as many cancels of this payment as it keeps before their coins can be checked: post this one again once the payment's parent is broadcast".into(),
            )));
        }
        self.pending.push(c);
        Ok(true)
    }

    /// Takes in what another copy of the same payment (the same coins) adds: a vouched
    /// copy in place of an unvouched one, its cancels and its unchecked cancels. Returns
    /// what it took in.
    fn take_in(&mut self, new: Payment) -> Result<Vec<&'static str>, Refused> {
        let mut what = vec![];
        if (new.vouched && !self.vouched) || (self.hex.is_empty() && !new.hex.is_empty()) {
            self.hex = new.hex;
            self.txid = new.txid;
            self.vouched = new.vouched;
            what.push("payment");
        }
        let mut took = false;
        for c in new.cancels {
            took |= self.keep_cancel(c);
        }
        if took {
            what.push("cancels");
        }
        let mut took = false;
        for c in new.pending {
            took |= self.keep_pending(c)?;
        }
        if took {
            what.push("pending_cancels");
        }
        Ok(what)
    }

    fn to_json(&self) -> Value {
        json!({
            "coins": self.coins.iter().map(|c| format!("{}:{}", c.txid, c.vout)).collect::<Vec<_>>(),
            "txid": self.txid,
            "hex": self.hex,
            "vouched": self.vouched,
            "by": self.by,
            "cancels": self.cancels.iter().map(|c| json!({"hex": c.hex, "fee": c.fee, "vouched": c.vouched})).collect::<Vec<_>>(),
            "pending": self.pending.iter().map(|c| json!({"hex": c.hex, "by": c.by})).collect::<Vec<_>>(),
            "settled": self.settled.as_ref().map(|s| json!({"height": s.at.height, "block": s.at.block, "txid": s.at.txid, "paid": s.paid})),
        })
    }

    fn from_stored(v: &Value, terms: &PayLockTerms) -> Result<Payment, Error> {
        let by = v.get("by").and_then(Value::as_str).unwrap_or_default();
        let mut p = match v.get("hex").and_then(Value::as_str).unwrap_or_default() {
            "" => Payment {
                coins: v
                    .get("coins")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c.as_str()?.parse().ok())
                    .collect(),
                hex: String::new(),
                txid: v
                    .get("txid")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                vouched: false,
                by: by.to_string(),
                cancels: vec![],
                pending: vec![],
                settled: None,
            },
            h => Payment::new(h, terms, by)?,
        };
        p.vouched = v.get("vouched").and_then(Value::as_bool).unwrap_or(false);
        for c in v
            .get("cancels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut k = Cancel::new(c.get("hex").and_then(Value::as_str).unwrap_or_default())?;
            k.fee = c.get("fee").and_then(Value::as_u64).unwrap_or(0);
            k.vouched = c.get("vouched").and_then(Value::as_bool).unwrap_or(false);
            p.cancels.push(k);
        }
        for c in v
            .get("pending")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut k = Cancel::new(c.get("hex").and_then(Value::as_str).unwrap_or_default())?;
            k.by = c
                .get("by")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            p.pending.push(k);
        }
        p.settled = v.get("settled").and_then(|s| {
            Some(Settled {
                at: Found {
                    height: s.get("height")?.as_u64()? as u32,
                    block: s.get("block")?.as_str()?.to_string(),
                    txid: s.get("txid")?.as_str()?.to_string(),
                },
                paid: s.get("paid")?.as_bool()?,
            })
        });
        Ok(p)
    }
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
    /// Live jobs (not yet decided) carried at once; intake refuses more, but never a job
    /// whose payment the Bitcoin daemon vouches for. A decided job still watched does not
    /// count.
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
    /// Live jobs one client may have started (a post that merges into a job held starts
    /// none); intake refuses it more, but never a job whose payment the Bitcoin daemon
    /// vouches for. 0: no limit.
    pub jobs_per_client: usize,
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
            jobs_per_client: 50,
        }
    }
}

/// One swap the service carries: one per lock.
#[derive(Debug, Clone)]
pub struct Job {
    /// The job's name: a hash of its lock. Nothing a client chooses (a payment's id, say)
    /// names a job, so every post for a lock merges into the one job, and none takes a
    /// place of its own.
    pub id: String,
    /// The swap's terms.
    pub terms: PayLockTerms,
    /// The lock.
    pub lock: OutPoint,
    /// The signed claims: every tier, in every fee asset the buyer signed.
    pub claims: Vec<Transaction>,
    /// The payments held, each with its cancels. None is needed to complete the claim.
    pub payments: Vec<Payment>,
    /// The client that started the job (its address), for [`Limits::jobs_per_client`].
    /// Set by the service from the connection, never read from a request.
    pub client: String,
    /// A request's payment id: only a hint, to take the payment from the daemon's
    /// mempool. Never stored, never a name.
    pub hint: Option<String>,
    /// A request's cancels, until intake places each with the payment whose coins it
    /// spends exactly. Never stored.
    pub loose: Vec<Cancel>,
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

/// A job's name: its lock, hashed. Whatever is posted for that lock (claims, payments,
/// cancels) is merged into the one job.
pub fn job_id(lock: &OutPoint) -> String {
    sha256::Hash::hash(format!("paylock|{}:{}", lock.txid, lock.vout).as_bytes()).to_string()
}

fn btc_tx(hex: &str, what: &str) -> Result<bitcoin::Transaction, Error> {
    let raw = hex_decode(hex)?;
    if raw.len() > MAX_TX_BYTES {
        return Err(Error(format!(
            "the {what} is {} bytes; this service keeps transactions of at most {MAX_TX_BYTES}",
            raw.len()
        )));
    }
    bitcoin::consensus::encode::deserialize(&raw)
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

/// The cancels a request carries, as a wallet hands them over: `cancel` (one raw
/// transaction) and `cancels` (raw transactions). Nothing else of a cancel is read from a
/// request: its fee, whether it is vouched for and who handed it over are the service's.
fn request_cancels(v: &Value) -> Result<Vec<Cancel>, Error> {
    let mut out = vec![];
    if let Some(c) = v.get("cancel") {
        out.push(Cancel::new(c.as_str().ok_or_else(|| {
            Error("a cancel is a raw Bitcoin transaction, in hex".into())
        })?)?);
    }
    for c in v
        .get("cancels")
        .map(|c| {
            c.as_array()
                .ok_or_else(|| Error("cancels is a list of raw Bitcoin transactions".into()))
        })
        .transpose()?
        .into_iter()
        .flatten()
    {
        out.push(Cancel::new(c.as_str().ok_or_else(|| {
            Error("a cancel is a raw Bitcoin transaction, in hex".into())
        })?)?);
    }
    Ok(out)
}

impl Job {
    /// A job from what a buyer's wallet hands over:
    /// `{terms, lock: "txid:vout", claims: [hex...], payment?: txid, payment_hex?: hex,
    /// cancel?: hex, cancels?: [hex...]}`. Nothing else is read: what the service keeps of
    /// its own (unchecked cancels, a cancel's fee, the client, the job's progress) never
    /// comes from a request, and the payment's id is only a hint. This checks the form
    /// only: every claim spends the lock through the claim leaf, and the signed payment
    /// pays the terms' receiving script at least the price. [`check_intake`] checks the
    /// signatures against the chains and places each cancel with its payment.
    pub fn from_request(v: &Value) -> Result<Job, Error> {
        Job::parse(v, false)
    }

    fn parse(v: &Value, stored: bool) -> Result<Job, Error> {
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
        let mut claims = claims;
        for c in claims.iter_mut() {
            // What the buyer's signature does not cover, and completing the claim writes
            // (the payment's output index, the proof), is cleared: a copy of a claim
            // differs from the buyer's in nothing the service keeps.
            for input in c.input.iter_mut() {
                let w = &mut input.witness;
                if w.script_witness.len() == 4 && w.script_witness[2] == leaf {
                    w.script_witness[0] = vec![];
                    w.pegin_witness = vec![];
                }
            }
        }
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
        let id = job_id(&lock);
        let mut payments = vec![];
        let (mut hint, mut loose, mut client) = (None, vec![], String::new());
        if stored {
            for p in v
                .get("payments")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                payments.push(Payment::from_stored(p, &terms)?);
            }
            client = v
                .get("client")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
        } else {
            hint = match v.get("payment") {
                None | Some(Value::Null) => None,
                Some(p) => Some(
                    p.as_str()
                        .filter(|p| is_txid(p))
                        .ok_or_else(|| Error("payment is a Bitcoin transaction id".into()))?
                        .to_lowercase(),
                ),
            };
            if let Some(h) = v.get("payment_hex").and_then(Value::as_str) {
                payments.push(Payment::new(h, &terms, "")?);
            }
            loose = request_cancels(v)?;
            if loose.len() > MAX_CANCELS {
                return Err(Error(format!(
                    "a post carries at most {MAX_CANCELS} cancels"
                )));
            }
        }
        let mut job = Job {
            id,
            terms,
            lock,
            claims: vec![],
            payments,
            client,
            hint,
            loose,
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

    /// Every payment held pays the terms; every cancel held spends exactly its payment's
    /// coins and is not the payment.
    fn check_form(&self) -> Result<(), Error> {
        for p in &self.payments {
            for c in p.cancels.iter().chain(&p.pending) {
                let t = btc_tx(&c.hex, "cancel")?;
                if c.txid == p.txid {
                    return Err(Error("the cancel is the payment itself".into()));
                }
                if inputs_of(&t) != p.coins {
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
        v["payments"] = json!(self
            .payments
            .iter()
            .map(Payment::to_json)
            .collect::<Vec<_>>());
        v["client"] = json!(self.client);
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
        v["late"] = f(&self.scan.late);
        v["unprovable"] = f(&self.scan.unprovable);
        v["unusable"] = json!(self.scan.unusable);
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
        let held = |f: fn(&Payment) -> usize| self.payments.iter().map(f).sum::<usize>();
        let cancelled = self
            .payments
            .iter()
            .filter_map(|p| p.settled.as_ref().filter(|s| !s.paid))
            .map(|s| s.at.height)
            .max();
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
            // Where a payment was mined: in the lock's heights, or else after `D`.
            "payment_height": self.scan.found.as_ref().or(self.scan.late.as_ref()).map(|f| f.height),
            "payment_bumped": self.scan.found.as_ref().or(self.scan.late.as_ref()).map(|f| !self.payments.iter().any(|p| p.txid == f.txid)),
            // A transaction paying the seller in the lock's heights that no proof can carry:
            // passed over, it opens nothing and withholds no cancel.
            "unprovable_payment_height": self.scan.unprovable.as_ref().map(|f| f.height),
            "payments": self.payments.len(),
            "unvouched_payments": self.payments.iter().filter(|p| !p.vouched).count(),
            "has_cancel": self.payments.iter().any(Payment::has_cancel),
            "cancels": held(|p| p.cancels.len()),
            "pending_cancels": held(|p| p.pending.len()),
            "cancel_sent": self.cancel_sent,
            "cancel_height": cancelled,
            "decided_at": self.decided_at,
            "buried": self.buried,
            "failures": self.failures,
            "note": self.note,
        })
    }

    /// A stored job.
    pub fn from_stored(v: &Value) -> Result<Job, Error> {
        let mut j = Job::parse(v, true)?;
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        let found = |k: &str| {
            v.get(k).and_then(|s| {
                Some(Found {
                    height: s.get("height")?.as_u64()? as u32,
                    block: s.get("block")?.as_str()?.to_string(),
                    txid: s.get("txid")?.as_str()?.to_string(),
                })
            })
        };
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
            cancel: None,
            late: found("late"),
            unprovable: found("unprovable"),
            unusable: v
                .get("unusable")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str().map(String::from))
                .collect(),
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

    /// Whether a payment is known to be mined at a height the claim accepts.
    fn paid_in_window(&self) -> bool {
        self.scan
            .found
            .as_ref()
            .map(|f| f.height > self.terms.floor && f.height <= self.terms.deadline)
            .unwrap_or(false)
    }

    /// The payment held that spends exactly `coins`.
    fn payment_for(&mut self, coins: &[bitcoin::OutPoint]) -> Option<&mut Payment> {
        self.payments.iter_mut().find(|p| p.coins == coins)
    }

    /// Takes in a payment (with its cancels): into the payment held with the same coins,
    /// or as a new one. One the daemon vouches for is always taken; an unvouched one only
    /// within [`MAX_UNVOUCHED_PAYMENTS`] and [`UNVOUCHED_PER_CLIENT`], beyond which the
    /// answer is to post it again once its parent is broadcast. Returns what it took in.
    fn take_payment(&mut self, p: Payment) -> Result<Vec<&'static str>, Refused> {
        let coins = p.coins.clone();
        if let Some(held) = self.payment_for(&coins) {
            return held.take_in(p);
        }
        if !p.vouched {
            let unvouched = self.payments.iter().filter(|h| !h.vouched);
            let mine = unvouched.clone().filter(|h| h.by == p.by).count();
            if unvouched.count() >= MAX_UNVOUCHED_PAYMENTS || mine >= UNVOUCHED_PER_CLIENT {
                return Err(Refused::Limit(Error(
                    "the job holds as many payments as it keeps before the Bitcoin daemon can check them: post this one again once its parent is broadcast".into(),
                )));
            }
        }
        let mut what = vec!["payment"];
        if !p.cancels.is_empty() {
            what.push("cancels");
        }
        if !p.pending.is_empty() {
            what.push("pending_cancels");
        }
        self.payments.push(p);
        Ok(what)
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

/// Why intake refused what it was handed: the request itself (400), a limit (429), or a
/// chain that did not answer (503, try again).
#[derive(Debug)]
pub enum Refused {
    /// The request fails a check.
    Bad(Error),
    /// A limit is reached: the client's jobs, the service's, or a job's unchecked cancels.
    Limit(Error),
    /// A chain did not answer.
    Unavailable(Error),
}

impl Refused {
    /// The message.
    pub fn message(&self) -> &str {
        match self {
            Refused::Bad(e) | Refused::Limit(e) | Refused::Unavailable(e) => &e.0,
        }
    }

    /// The HTTP status it is answered with.
    pub fn status(&self) -> u16 {
        match self {
            Refused::Bad(_) => 400,
            Refused::Limit(_) => 429,
            Refused::Unavailable(_) => 503,
        }
    }
}

/// What the Bitcoin daemon's answer on a cancel (`testmempoolaccept`) makes of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelCheck {
    /// Valid: kept. Its fee is known when the daemon accepted it now; one it already pools
    /// or has mined is valid too, and kept.
    Valid {
        /// The fee, when the daemon gave it.
        fee: Option<u64>,
        /// Whether the daemon vouched for this very copy, witness included: accepted now,
        /// or pooled under this witness id. A mined one is vouched for by its id only.
        vouched: bool,
        /// What to tell the client.
        note: Option<String>,
    },
    /// The daemon pools the same transaction with another witness: keep the daemon's copy.
    PooledCopy,
    /// The daemon does not know the coins it spends (the payment's parent is not
    /// broadcast yet, say): it cannot say. Kept, and checked again until it can. A
    /// missing coin is never read as a confirmed spend.
    Unknown(String),
    /// Refused: its signatures fail, or the daemon will not take it as it stands.
    Invalid(String),
}

/// [`CancelCheck`] from the daemon's answer.
pub fn judge_cancel(a: &Accept) -> CancelCheck {
    match a {
        Accept::Allowed { fee } => CancelCheck::Valid {
            fee: Some(*fee),
            vouched: true,
            note: None,
        },
        // The daemon says so only of the copy it pools, by witness id.
        Accept::Refused(r) if r.contains("txn-already-in-mempool") => CancelCheck::Valid {
            fee: None,
            vouched: true,
            note: Some("is already broadcast: kept".into()),
        },
        // Said of the transaction's id: the witness of this copy is not checked.
        Accept::Refused(r) if r.contains("txn-already-known") => CancelCheck::Valid {
            fee: None,
            vouched: false,
            note: Some("is already mined: kept".into()),
        },
        Accept::Refused(r) if r.contains("same-nonwitness-data-in-mempool") => {
            CancelCheck::PooledCopy
        }
        Accept::Refused(r) if Accept::scripts_fail(r) => {
            CancelCheck::Invalid(format!("the cancel's signatures do not verify: {r}"))
        }
        Accept::Refused(r) if Accept::coins_missing(r) => CancelCheck::Unknown(r.clone()),
        Accept::Refused(r) => CancelCheck::Invalid(format!(
            "the Bitcoin daemon does not accept the cancel: {r}; a cancel must be valid as it stands and pay enough to replace the payment"
        )),
    }
}

/// What the Bitcoin daemon's answer on a signed payment (`testmempoolaccept`) makes of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentCheck {
    /// Valid now, pooled or mined: its witness is one that relays.
    Vouched,
    /// The daemon pools it with another witness: keep the daemon's copy.
    PooledCopy,
    /// The daemon cannot vouch for it now (its parent unseen, outbid, mined and its
    /// coins gone): kept as handed over. Its id fixes its coins whatever its witness.
    Kept,
    /// Its signatures fail: refused.
    Invalid(String),
}

/// [`PaymentCheck`] from the daemon's answer.
pub fn judge_payment(a: &Accept) -> PaymentCheck {
    match a {
        Accept::Allowed { .. } => PaymentCheck::Vouched,
        Accept::Refused(r)
            if r.contains("txn-already-in-mempool") || r.contains("txn-already-known") =>
        {
            PaymentCheck::Vouched
        }
        Accept::Refused(r) if r.contains("same-nonwitness-data-in-mempool") => {
            PaymentCheck::PooledCopy
        }
        Accept::Refused(r) if Accept::scripts_fail(r) => PaymentCheck::Invalid(format!(
            "the signed payment's signatures do not verify: {r}"
        )),
        Accept::Refused(_) => PaymentCheck::Kept,
    }
}

/// A new job's lock must be an unspent output of the Sequentia chain paying the terms'
/// lock script, asset and atoms (what `check-lock` asks before a buyer pays), or already
/// spent by one of the job's own claims. So a job costs a real lock: nobody fills the
/// service with jobs for locks that do not exist.
fn check_lock_for_intake(seq: &SeqChain, job: &Job) -> Result<(), Refused> {
    let down = Refused::Unavailable;
    if seq.unspent_in_chain(&job.lock).map_err(down)? {
        let out = seq
            .tx(&job.lock.txid)
            .map_err(down)?
            .and_then(|(tx, _)| tx.output.get(job.lock.vout as usize).cloned());
        let want = paylock::lock_txout(&job.terms).map_err(|e| Refused::Bad(e.into()))?;
        return match out {
            Some(o)
                if o.script_pubkey == want.script_pubkey
                    && o.asset == want.asset
                    && o.value == want.value =>
            {
                Ok(())
            }
            _ => Err(Refused::Bad(Error(
                "the lock does not pay the terms' lock script, asset and atoms".into(),
            ))),
        };
    }
    for c in &job.claims {
        if seq.status(&c.txid()).map_err(down)? != TxStatus::Unknown {
            return Ok(());
        }
    }
    Err(Refused::Bad(Error(
        "the lock is not an unspent output of the Sequentia chain: post the job once the lock is mined".into(),
    )))
}

/// Has the Bitcoin daemon judge a payment handed over, and vouch for it if it can: one
/// it accepts now is broadcast (as the buyer is about to), so a payment the service holds
/// as vouched for is one Bitcoin pools or has mined. One whose coins the daemon does not
/// know yet stays unvouched; one whose signatures fail is refused.
fn vouch(btc: &BtcChain, p: &mut Payment, notes: &mut Vec<String>) -> Result<(), Refused> {
    let down = Refused::Unavailable;
    let a = btc.test_accept(&p.hex).map_err(down)?;
    let now = matches!(a, Accept::Allowed { .. });
    match judge_payment(&a) {
        // Pooled under this witness, or mined.
        PaymentCheck::Vouched if !now => p.vouched = true,
        PaymentCheck::Vouched => match btc.send_raw(&p.hex) {
            Ok(_) => {
                p.vouched = true;
                notes.push(format!("the payment {} is broadcast", p.txid));
            }
            Err(e) if e.to_string().contains("already") => p.vouched = true,
            Err(e) => notes.push(format!(
                "the payment {} is kept unvouched: the Bitcoin daemon does not take it now ({e})",
                p.txid
            )),
        },
        PaymentCheck::PooledCopy => {
            if let Some(h) = btc.mempool_tx(&p.txid).map_err(down)? {
                p.hex = h;
                p.vouched = true;
            }
        }
        PaymentCheck::Kept => notes.push(format!(
            "the payment {} is kept unvouched: the Bitcoin daemon does not vouch for it now ({}); it is checked again every round",
            p.txid,
            match &a {
                Accept::Refused(r) => r.as_str(),
                Accept::Allowed { .. } => "",
            }
        )),
        PaymentCheck::Invalid(m) => return Err(Refused::Bad(Error(m))),
    }
    Ok(())
}

/// Checks a post against the chains before the service holds anything of it, and returns
/// what it kept in a way worth saying, in words. `held` is the job the service already
/// holds for this lock, which the post merges into.
///
/// - a new job's lock is an unspent output paying the terms' script, asset and atoms; a
///   post for a held job must name terms that make the same lock;
/// - every claim is signed by the terms' buyer for this very transaction (and its fee
///   coin, if any, by the coin's key): a claim that fails is refused;
/// - the signed payment, when given, pays the terms' receiving script at least the price,
///   and is judged by the Bitcoin daemon ([`vouch`]); when not given, the payment id, if
///   any, is only a hint to take a paying transaction from the daemon's mempool;
/// - each cancel spends exactly the coins of the post's payment or of one the job holds,
///   and is judged by the daemon ([`judge_cancel`]): valid, already pooled or mined, it is
///   kept; one whose coins the daemon does not know yet is kept unchecked
///   ([`Payment::pending`]) and checked again until it can be; one that fails is refused.
pub fn check_intake(
    intake: &Intake,
    job: &mut Job,
    held: Option<&Job>,
) -> Result<Vec<String>, Refused> {
    let down = Refused::Unavailable;
    match held {
        None => check_lock_for_intake(&intake.seq, job)?,
        Some(h) => {
            let bad = |e: lwk_wollet::Error| Refused::Bad(e.into());
            if paylock::lock_txout(&h.terms).map_err(bad)?
                != paylock::lock_txout(&job.terms).map_err(bad)?
            {
                return Err(Refused::Bad(Error(
                    "these terms do not make the lock the service holds a job for".into(),
                )));
            }
        }
    }
    let genesis = intake.genesis().map_err(down)?;
    // The outputs the claims' fee coins spend, read first: a node that does not answer
    // refuses nothing for good.
    let mut coins: BTreeMap<OutPoint, Option<lwk_wollet::elements::TxOut>> = BTreeMap::new();
    for c in &job.claims {
        for i in &c.input {
            let op = i.previous_output;
            if op.txid != job.lock.txid && !coins.contains_key(&op) {
                if coins.len() >= MAX_FEE_COINS {
                    return Err(Refused::Bad(Error(format!(
                        "the claims spend more than {MAX_FEE_COINS} fee coins"
                    ))));
                }
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
    let client = job.client.clone();
    for p in job.payments.iter_mut() {
        p.by = client.clone();
        vouch(&intake.btc, p, &mut notes)?;
    }
    if job.payments.is_empty() {
        if let Some(h) = job.hint.clone() {
            if let Some(hex) = intake.btc.mempool_tx(&h).map_err(down)? {
                match Payment::new(&hex, &job.terms, &client) {
                    Ok(mut p) if p.txid == h => {
                        p.vouched = true;
                        job.payments.push(p);
                    }
                    Ok(_) => {}
                    Err(e) => notes.push(format!("the transaction {h} is not held: {}", e.0)),
                }
            }
        }
    }
    // Each cancel goes with the payment whose coins it spends exactly: the post's, or one
    // the job holds.
    for mut c in std::mem::take(&mut job.loose) {
        let spent = inputs_of(&btc_tx(&c.hex, "cancel").map_err(Refused::Bad)?);
        if job.payment_for(&spent).is_none() {
            match held.and_then(|h| h.payments.iter().find(|p| p.coins == spent)) {
                Some(p) => job.payments.push(Payment {
                    cancels: vec![],
                    pending: vec![],
                    by: client.clone(),
                    ..p.clone()
                }),
                None => {
                    let known = !job.payments.is_empty()
                        || held.map(|h| !h.payments.is_empty()).unwrap_or(false);
                    return Err(Refused::Bad(Error(if known {
                        "the cancel does not spend exactly the payment's coins".into()
                    } else {
                        "a cancel is kept only beside the payment it cancels: give payment_hex, or post it once the payment is broadcast".into()
                    })));
                }
            }
        }
        if job.payment_for(&spent).map(|p| p.txid == c.txid) == Some(true) {
            return Err(Refused::Bad(Error(
                "the cancel is the payment itself".into(),
            )));
        }
        match judge_cancel(&intake.btc.test_accept(&c.hex).map_err(down)?) {
            CancelCheck::Valid { fee, vouched, note } => {
                c.vouched = vouched;
                c.fee = match fee {
                    Some(f) => f,
                    None => intake.btc.mempool_fee(&c.txid).map_err(down)?.unwrap_or(0),
                };
                if let Some(n) = note {
                    notes.push(format!("the cancel {} {n}", c.txid));
                }
                job.payment_for(&spent).expect("placed").keep_cancel(c);
            }
            CancelCheck::PooledCopy => {
                match intake.btc.mempool_tx(&c.txid).map_err(down)? {
                    Some(h) => {
                        c = Cancel::new(&h).map_err(Refused::Bad)?;
                        c.vouched = true;
                    }
                    // Mined or replaced meanwhile: this copy stays unvouched.
                    None => c.vouched = false,
                }
                c.fee = intake.btc.mempool_fee(&c.txid).map_err(down)?.unwrap_or(0);
                notes.push(format!(
                    "the cancel {} is already broadcast with another witness: the broadcast one is kept",
                    c.txid
                ));
                job.payment_for(&spent).expect("placed").keep_cancel(c);
            }
            CancelCheck::Unknown(r) => {
                notes.push(format!(
                    "the cancel {} is kept unchecked: the Bitcoin daemon does not know the coins it spends yet ({r}); it is checked again until it does, and sent two blocks before the deadline",
                    c.txid
                ));
                c.by = client.clone();
                job.payment_for(&spent).expect("placed").keep_pending(c)?;
            }
            CancelCheck::Invalid(m) => return Err(Refused::Bad(Error(m))),
        }
    }
    job.check_form().map_err(Refused::Bad)?;
    Ok(notes)
}

/// Checks the payments a job holds again, each round:
///
/// - a payment the daemon could not vouch for is vouched for once Bitcoin's mempool holds
///   a transaction spending its coins that pays the terms (the buyer broadcast it, or a
///   replacement), or once the daemon accepts the copy held (which is then broadcast). A
///   copy whose signatures fail never takes its payment's cancels with it: the payment is
///   given up only when it holds no cancel;
/// - a paying transaction in the mempool that spends a held payment's coins with other
///   coins (a replacement that added an input) is held as a payment of its own;
/// - a cancel not checked yet joins the checked ones once the daemon accepts it (or pools
///   it, or has mined it), and is dropped if its signatures fail.
fn recheck_payments(btc: &BtcChain, job: &mut Job) -> Result<(), Error> {
    let terms = job.terms.clone();
    let mut found = vec![];
    let mut note = None;
    for p in job.payments.iter_mut() {
        if p.vouched || p.settled.is_some() {
            continue;
        }
        if let Some(t) = p.coins.first() {
            if let Some(id) = btc.mempool_spender(t)? {
                if let Some(hex) = btc.mempool_tx(&id)? {
                    if let Ok(mut q) = Payment::new(&hex, &terms, &p.by) {
                        q.vouched = true;
                        if q.coins == p.coins {
                            p.hex = q.hex;
                            p.txid = q.txid;
                            p.vouched = true;
                        } else {
                            found.push(q);
                        }
                    }
                }
            }
        }
        if p.vouched {
            continue;
        }
        let a = btc.test_accept(&p.hex)?;
        match judge_payment(&a) {
            PaymentCheck::Vouched => {
                if !matches!(a, Accept::Allowed { .. })
                    || btc.send_raw(&p.hex).is_ok()
                    || btc.pooled(&p.txid)?
                {
                    p.vouched = true;
                }
            }
            PaymentCheck::Invalid(m) => {
                note = Some(format!("a signed payment held was dropped: {m}"));
                p.hex.clear();
            }
            PaymentCheck::PooledCopy | PaymentCheck::Kept => {}
        }
    }
    for q in found {
        let _ = job.take_payment(q);
    }
    // A copy whose signatures failed is given up with its payment only if that holds no
    // cancel; otherwise the payment is kept (its coins name its cancels), without a copy.
    job.payments.retain(|p| !p.hex.is_empty() || p.has_cancel());
    for p in job.payments.iter_mut() {
        if p.pending.is_empty() {
            continue;
        }
        for c in p.pending.clone() {
            let a = btc.test_accept(&c.hex)?;
            match judge_cancel(&a) {
                CancelCheck::Valid { fee, vouched, .. } => {
                    let fee = match fee {
                        Some(f) => f,
                        None => btc.mempool_fee(&c.txid)?.unwrap_or(0),
                    };
                    p.pending.retain(|x| x.wtxid != c.wtxid);
                    p.keep_cancel(Cancel { fee, vouched, ..c });
                }
                CancelCheck::PooledCopy => {
                    let fee = btc.mempool_fee(&c.txid)?.unwrap_or(0);
                    p.pending.retain(|x| x.wtxid != c.wtxid);
                    // The daemon's copy is the one that relays; this one adds nothing beside it.
                    if let Some(h) = btc.mempool_tx(&c.txid)? {
                        let mut k = Cancel::new(&h)?;
                        k.fee = fee;
                        k.vouched = true;
                        p.keep_cancel(k);
                    }
                }
                CancelCheck::Invalid(m) if matches!(&a, Accept::Refused(r) if Accept::scripts_fail(r)) =>
                {
                    p.pending.retain(|x| x.wtxid != c.wtxid);
                    note = Some(format!("an unchecked cancel was dropped: {m}"));
                }
                _ => {}
            }
        }
    }
    if let Some(n) = note {
        job.note = n;
    }
    Ok(())
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
    // The payments held, checked again: vouched for once Bitcoin holds them, their
    // cancels checked once their coins are known. Ended jobs still watched too, so a
    // payment that becomes known after a decision reopens it.
    recheck_payments(btc, job)?;
    let coins: Vec<Vec<bitcoin::OutPoint>> = job.payments.iter().map(|p| p.coins.clone()).collect();
    let mut settled: Vec<Option<Settled>> =
        job.payments.iter().map(|p| p.settled.clone()).collect();
    let open = job
        .payments
        .iter()
        .any(|p| p.real() && p.settled.is_none() && p.has_cancel());
    let complete = btc.scan_lock(
        &job.terms,
        &coins,
        &mut settled,
        open,
        &mut job.scan,
        limits.blocks_per_job,
        until,
    )?;
    for (p, s) in job.payments.iter_mut().zip(settled) {
        p.settled = s;
    }
    let btc_tip = btc.tip()?;
    let d = job.terms.deadline;
    if job.scan.found.is_none() {
        // The payments Bitcoin has shown real, or has settled. Unverified ones (coins the
        // daemon has never seen) decide nothing.
        let vouched: Vec<&Payment> = job
            .payments
            .iter()
            .filter(|p| p.real() || p.settled.is_some())
            .collect();
        // Every one of them is settled: the swap's payment can no longer be mined, unless
        // another comes (it is then found, and the job reopens), or a payment held becomes
        // known (the job reopens with it).
        if !vouched.is_empty() && vouched.iter().all(|p| p.settled.is_some()) {
            let cancel = vouched
                .iter()
                .filter_map(|p| Some((p, p.settled.as_ref().filter(|s| !s.paid)?)))
                .max_by_key(|(_, s)| s.at.height);
            match cancel {
                Some((p, s)) => {
                    let ours = p
                        .cancels
                        .iter()
                        .chain(&p.pending)
                        .any(|c| c.txid == s.at.txid);
                    let (txid, h) = (s.at.txid.clone(), s.at.height);
                    end(
                        job,
                        State::Cancelled,
                        h.max(d),
                        btc_tip,
                        limits,
                        if ours {
                            format!("the cancel {txid} is confirmed in Bitcoin block {h}: the buyer keeps its bitcoin")
                        } else {
                            format!("the payment's coins are spent in Bitcoin block {h} by {txid}, which does not pay the seller the price in a form a proof can carry: the payment can no longer be mined")
                        },
                    );
                }
                None => {
                    let late = job.scan.late.clone();
                    let h = late.as_ref().map(|f| f.height).unwrap_or(d);
                    end(
                        job,
                        State::Never,
                        h.max(d),
                        btc_tip,
                        limits,
                        format!(
                            "the payment is mined at Bitcoin block {h}, after the deadline {d}"
                        ),
                    );
                }
            }
            return Ok(());
        }
    }
    match payment_position(&job.terms, &job.scan, complete, btc_tip) {
        Position::Never(why) => {
            let why = match &job.scan.unprovable {
                Some(u) => format!(
                    "{why} (the transaction {} in Bitcoin block {} pays the seller, but no proof can carry it: it opens nothing)",
                    u.txid, u.height
                ),
                None => why,
            };
            let open = job
                .payments
                .iter()
                .any(|p| p.real() && p.settled.is_none() && p.has_cancel());
            if open && btc_tip <= d.saturating_add(CANCEL_KEEP_BLOCKS) {
                // Not mined by D, and cancels to send. The swap has an outcome only once a
                // spend of the payment's coins is confirmed, whatever the Sequentia node
                // says of the lock: the cancel concerns Bitcoin alone.
                job.state = State::Waiting;
                job.decided_at = None;
                job.buried = false;
                job.note = if job.cancel_sent {
                    format!("{why}; the cancel is broadcast and not confirmed yet: it is sent again until a spend of the payment's coins is")
                } else {
                    format!("{why}; the cancel is not accepted yet: it is sent again")
                };
            } else {
                let why = match &job.scan.late {
                    Some(f) => format!(
                        "the payment is mined at Bitcoin block {}, after the deadline {d}",
                        f.height
                    ),
                    None if open => format!("{why}; no spend of the payment's coins confirmed in {CANCEL_KEEP_BLOCKS} blocks"),
                    None => why,
                };
                end(job, State::Never, d, btc_tip, limits, why);
            }
        }
        Position::Waiting(why) => {
            job.state = State::Waiting;
            job.decided_at = None;
            job.buried = false;
            job.note = why;
            // A payment Bitcoin vouched for, unmined and not in the daemon's mempool (a
            // reorganization evicted it, say): sent again while it can still open the lock.
            if complete && !job.cancel_sent && btc_tip < d {
                for p in job
                    .payments
                    .iter()
                    .filter(|p| p.vouched && p.settled.is_none() && !p.hex.is_empty())
                {
                    if !btc.pooled(&p.txid)? && btc.send_raw(&p.hex).is_ok() {
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
                            "the claim ({}tier, fee {}) is pooled with a proof of the payment {} in Bitcoin block {height}",
                            if job.raised { "top " } else { "going " },
                            fee_of(&tx).map(|(a, f)| format!("{f} atoms of {a}")).unwrap_or_default(),
                            found.txid,
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
                    // This payment opens nothing; another one may. Never settled by it: it
                    // is passed over, and the scan reads on from its block. Until another
                    // is found the job is waiting, its cancels due as if none were mined.
                    btc.pass_over(&mut job.scan)?;
                    job.state = State::Waiting;
                    job.note = format!("{why}: passed over, looking for another payment");
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
        j.payments
            .iter()
            .any(|p| p.settled.is_none() && p.has_cancel())
            && !j.state.ended()
            && !j.paid_in_window()
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
    // One entry per payment with cancels to send, keyed by the client that handed it over:
    // whoever started the job, each payment's sender takes its own turns.
    let mut due_jobs: Vec<Turn> = vec![];
    for j in lock(store).jobs.values().filter(|j| due(j)) {
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
        for (i, p) in j.payments.iter().enumerate() {
            if p.settled.is_none() && p.has_cancel() {
                due_jobs.push((rank, j.cancel_tried, key, (j.id.clone(), i), p.by.clone()));
            }
        }
    }
    due_jobs.sort();
    let mut sent = 0;
    for (id, i) in take_turns(due_jobs) {
        let Some(p) = lock(store)
            .jobs
            .get(&id)
            .and_then(|j| j.payments.get(i).cloned())
        else {
            continue;
        };
        let mut accepted = false;
        let mut refused = None;
        let mut tried = false;
        // The checked ones, highest fee first; then those not checkable yet, which a
        // daemon refuses if they are not valid.
        for c in p.cancels.iter().chain(&p.pending) {
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

/// The order cancels are sent in: by lock rank, and within a rank the clients that
/// started the jobs take turns, each in its own order (never tried first, nearest
/// deadline first). So a client with many jobs gets one send per turn, like any other,
/// and cannot push another client's cancel back. `due` is sorted by rank first.
/// A payment's cancels due: lock rank, tried before, its order key, (job, payment), and
/// the client that handed the payment over.
type Turn = (u8, bool, u64, (String, usize), String);

fn take_turns<K: Clone>(due: Vec<(u8, bool, u64, K, String)>) -> Vec<K> {
    let mut out = vec![];
    let mut i = 0;
    while i < due.len() {
        let rank = due[i].0;
        let mut queues: Vec<(String, std::collections::VecDeque<K>)> = vec![];
        while i < due.len() && due[i].0 == rank {
            let (_, _, _, id, client) = &due[i];
            match queues.iter_mut().find(|(c, _)| c == client) {
                Some((_, q)) => q.push_back(id.clone()),
                None => queues.push((client.clone(), [id.clone()].into())),
            }
            i += 1;
        }
        while queues.iter().any(|(_, q)| !q.is_empty()) {
            for (_, q) in queues.iter_mut() {
                if let Some(id) = q.pop_front() {
                    out.push(id);
                }
            }
        }
    }
    out
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
                    j = merge(h, j, &Limits::default())
                        .map_err(|e| Error(e.message().to_string()))?
                        .0;
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

    /// Adds a post, checked by [`check_intake`]. The job held for its lock takes in what
    /// the post adds and keeps all it held: claims it lacks, payments it lacks (an
    /// unverified one within [`MAX_UNVOUCHED_PAYMENTS`]) and cancels it lacks. Nothing is
    /// refused for having come second, and a post for a lock held never takes a place of
    /// its own. A job that has ended and is archived is answered with its id. A new job
    /// counts toward the service's live jobs and its client's
    /// ([`Limits::jobs_per_client`]), except one whose payment the Bitcoin daemon vouches
    /// for: a buyer whose payment pays the terms is never refused for a limit.
    pub fn add(&mut self, mut job: Job, limits: &Limits) -> Result<(String, Added), Refused> {
        let id = job.id.clone();
        let io = |e: Error| Refused::Unavailable(e);
        if job.claims.len() > limits.max_claims {
            return Err(Refused::Bad(Error(format!(
                "a job carries at most {} signed claims",
                limits.max_claims
            ))));
        }
        if let Some(held) = self.jobs.get(&id).cloned() {
            let (m, what) = merge(held, job, limits)?;
            if what.is_empty() {
                return Ok((id, Added::Same));
            }
            self.save(&m).map_err(io)?;
            self.jobs.insert(id.clone(), m);
            return Ok((id, Added::Merged(what)));
        }
        if self.archived(&id).is_some() {
            return Ok((id, Added::Same));
        }
        if job.terms.deadline - job.terms.floor > limits.max_window {
            return Err(Refused::Bad(Error(format!(
                "the lock spans {} Bitcoin blocks from its floor to its deadline; this service takes at most {}",
                job.terms.deadline - job.terms.floor,
                limits.max_window
            ))));
        }
        let pays = job.payments.iter().any(|p| p.vouched);
        if !pays {
            let live = self.jobs.values().filter(|j| !j.state.ended()).count();
            if live >= limits.max_jobs {
                return Err(Refused::Limit(Error(format!(
                    "the service carries {live} live jobs, its limit; try another service, or post again with a payment the Bitcoin daemon holds"
                ))));
            }
            if limits.jobs_per_client > 0 {
                let mine = self
                    .jobs
                    .values()
                    .filter(|j| !j.state.ended() && j.client == job.client)
                    .count();
                if mine >= limits.jobs_per_client {
                    return Err(Refused::Limit(Error(format!(
                        "this client has started {mine} live jobs, the most one client may; try again once some have ended"
                    ))));
                }
            }
        }
        // A new job holds its payments within the same bounds as a merge.
        let payments = std::mem::take(&mut job.payments);
        for p in payments {
            job.take_payment(p)?;
        }
        self.save(&job).map_err(io)?;
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

/// `held` with what `new`, posted for the same lock, adds: its claims, its payments and
/// their cancels (checked and not yet checkable). Returns the merged job and what it took
/// in.
fn merge(mut held: Job, new: Job, limits: &Limits) -> Result<(Job, Vec<&'static str>), Refused> {
    let mut what = vec![];
    let mut claims = held.claims.clone();
    for c in new.claims {
        let id = c.txid();
        if !claims.iter().any(|h| h.txid() == id) {
            claims.push(c);
        }
    }
    if claims.len() > limits.max_claims {
        return Err(Refused::Bad(Error(format!(
            "a job carries at most {} signed claims",
            limits.max_claims
        ))));
    }
    if claims.len() > held.claims.len() {
        held.claims = claims;
        what.push("claims");
    }
    for p in new.payments {
        for w in held.take_payment(p)? {
            if !what.contains(&w) {
                what.push(w);
            }
        }
    }
    held.check_form().map_err(Refused::Bad)?;
    Ok((held, what))
}

/// Takes into `job` (just worked on) what intake added to `cur` (the job as held now)
/// since `before` (the job as the round began): payments, cancels and unchecked cancels
/// it did not hold then. What the round itself dropped stays dropped.
fn fold_in(job: &mut Job, cur: &Job, before: &Value) {
    let had = |key: &str| -> Vec<String> {
        before["payments"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| {
                let k = key.to_string();
                p[k.as_str()]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|c| c["hex"].as_str().map(String::from))
            })
            .collect()
    };
    let (had_cancels, had_pending) = (had("cancels"), had("pending"));
    let had_coins: Vec<Value> = before["payments"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| p["coins"].clone())
        .collect();
    for p in &cur.payments {
        let key = json!(p
            .coins
            .iter()
            .map(|c| format!("{}:{}", c.txid, c.vout))
            .collect::<Vec<_>>());
        let new = Payment {
            cancels: p
                .cancels
                .iter()
                .filter(|c| !had_cancels.contains(&c.hex))
                .cloned()
                .collect(),
            pending: p
                .pending
                .iter()
                .filter(|c| !had_pending.contains(&c.hex))
                .cloned()
                .collect(),
            ..p.clone()
        };
        if job.payment_for(&p.coins).is_some() || !had_coins.contains(&key) {
            let _ = job.take_payment(new);
        }
    }
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
            // Intake may have merged claims, payments or cancels meanwhile; not what this
            // round dropped.
            for c in &cur.claims {
                job.add_claim(c.clone());
            }
            fold_in(&mut job, cur, &before);
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

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

fn authorized(req: &http::Request, access: &Access) -> bool {
    let Some(token) = &access.token else {
        return true;
    };
    req.header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| same(t.trim().as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

/// Answers one request, read whole by [`http::serve`] (which bounds its size and time).
/// A post's checks against the chains run outside the store's lock, so no read waits
/// on them.
fn handle(
    store: &Mutex<Store>,
    limits: &Limits,
    access: &Access,
    intake: &Intake,
    req: &http::Request,
) -> http::Answer {
    if !authorized(req, access) {
        return (401, json!({"error": "a valid token is required"}));
    }
    match (req.method.as_str(), req.path.trim_end_matches('/')) {
        ("POST", "/jobs") => {
            let v: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => return (400, json!({"error": e.to_string()})),
            };
            let mut job = match Job::from_request(&v) {
                Ok(j) => j,
                Err(e) => return (400, json!({"error": e.0})),
            };
            job.client = req.client.clone();
            // Bounded before any chain is asked about it.
            if job.claims.len() > limits.max_claims {
                return (
                    400,
                    json!({"error": format!("a job carries at most {} signed claims", limits.max_claims)}),
                );
            }
            let (held, archived) = {
                let st = lock(store);
                (
                    st.jobs.get(&job.id).cloned(),
                    st.archived(&job.id).is_some(),
                )
            };
            // A swap that has ended and is buried: nothing left to take.
            if archived && held.is_none() {
                return (200, json!({"id": job.id, "held": true, "notes": []}));
            }
            let refused = |e: Refused| {
                let m = match &e {
                    Refused::Unavailable(x) => {
                        format!("a chain did not answer, try again: {}", x.0)
                    }
                    _ => e.message().to_string(),
                };
                (e.status(), json!({"error": m}))
            };
            let notes = match check_intake(intake, &mut job, held.as_ref()) {
                Ok(n) => n,
                Err(e) => return refused(e),
            };
            let r = lock(store).add(job, limits);
            match r {
                Ok((id, Added::New)) => (200, json!({"id": id, "notes": notes})),
                Ok((id, Added::Same)) => (200, json!({"id": id, "held": true, "notes": notes})),
                Ok((id, Added::Merged(what))) => {
                    (200, json!({"id": id, "merged": what, "notes": notes}))
                }
                Err(e) => refused(e),
            }
        }
        ("GET", "/jobs") => {
            let list: Vec<Value> = lock(store)
                .jobs
                .values()
                .map(|j| json!({"id": j.id, "state": j.state.name(), "watching": j.state.ended() && !j.buried}))
                .collect();
            (200, json!(list))
        }
        ("GET", p) if p.starts_with("/jobs/") => {
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
                Some(j) => (200, j),
                None => (404, json!({"error": "no such job"})),
            }
        }
        _ => (404, json!({"error": "not found"})),
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
/// `GET /jobs/<id>`; each request on a thread of its own under a deadline, see
/// [`http`]), a thread that sends due cancels every `interval` (at most every second),
/// and a round of work every `interval`. Refuses to listen beyond loopback
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
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| Error(format!("listen {listen}: {e}")))?;
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
    let http_limits = http::HttpLimits {
        max_body: limits.max_body,
        ..http::HttpLimits::default()
    };
    let handler: http::Handler =
        Arc::new(move |req: &http::Request| handle(&s2, &l2, &access, &intake, req));
    std::thread::spawn(move || http::serve(listener, http_limits, handler));
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
