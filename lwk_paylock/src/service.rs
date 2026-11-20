//! The completion service: it holds a buyer's signed claims, its signed cancels and
//! its payment, and holds no key. It
//!
//! - knows the payment from Bitcoin alone: any transaction mined above `F` and at or
//!   below `D` that pays the seller's receiving script at least the price, in a form a
//!   proof can carry, may be the payment, whoever made it and whatever its id or coins,
//!   since that is what the claim's script accepts. It is the payment once the node
//!   accepts a claim proving it: the candidates are tried in turn (one handed over first,
//!   then the rest by the lightest proof they make), and one whose completed claim the
//!   node refuses for the claim's weight, at every tier, is passed over for the next.
//!   No payment handed over is needed to complete the claim;
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
//! - broadcasts the cancels if the payment is still unconfirmed two blocks before `D`
//!   and no claim proving another payment is pooled or mined, whatever its Sequentia node
//!   says of the lock (the cancel concerns Bitcoin alone), and sends them again until a
//!   spend of the payment's coins is confirmed;
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
//! next. The turns are per payment, by its coins: jobs holding the same coins share one
//! turn and one send. The node's answer orders the sends and never withholds one. The work of
//! completing claims follows what happens on the chains, never the number of jobs or
//! clients ([`work_round`]): each Bitcoin block is read once for every job
//! ([`BlockCache`]), a job's search passes blocks that hold nothing for it by a lookup,
//! and a job is worked only when something it waits on can have changed, those that
//! something new on the chains concerns first, taking turns by receiving script; a
//! candidate passed over comes back only when the node's floors have moved so that a
//! refused tier's own signed fee covers the node's ask (or at all, when the refusal gave
//! no figures to judge by), or its accepted assets have, never because a block arrived
//! and never at the floors that refused it; background work ends at once when a chain
//! moves; each job works within a time and block budget, the whole round within a
//! budget of its own. A job that fails retries with a backoff.
//! Each signed payment and cancel is held once however many jobs hold it (a payment the
//! daemon vouched for, once per transaction id whatever its witness; its coins with it,
//! named in a job's file by a digest), and a job's
//! own bytes are bounded ([`MAX_CLAIM_BYTES`], [`MAX_UNCHECKED_BYTES`],
//! [`MAX_CANCEL_BYTES`]). Intake caps the request's size, the size of each transaction
//! it keeps, the claims, payments and cancels per job, a lock's span of heights, the
//! number of live jobs and those each client starts, and needs a token whenever it
//! listens beyond loopback. Each request is served on a thread of its own under deadlines, and
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
//! Jobs are kept as one JSON file each, their payments one file each under `payments/`
//! however many jobs hold them (one per transaction id once vouched for), so a restart carries on where it stopped;
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
    http, outpoint, prove_claim, proven_payment, refusal_figures, refused_for_weight, script_key,
    Accept, Advance, BlockCache, BtcChain, Candidate, Completion, Error, Floors, Found, Passed,
    PaymentScan, Refusal, Retry, SeqChain, Settled, TxStatus,
};

/// How often a lock the node did not know is looked up again, in seconds.
const LOCK_RECHECK_SECS: u64 = 60;

/// How often a job holding a payment or cancel the Bitcoin daemon could not check yet is
/// checked again while neither chain moves, in seconds: its parent may be broadcast at any
/// time.
const UNCHECKED_RECHECK_SECS: u64 = 10;

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

/// The largest signed claim a job keeps, in bytes, without its proof (which the service
/// writes): a claim spends the lock and a few fee coins to a few outputs, a few hundred
/// bytes in the clear, and a few kilobytes with confidential outputs.
pub const MAX_CLAIM_BYTES: usize = 16 << 10;

/// The most bytes of signed transactions the Bitcoin daemon cannot check yet that one job
/// keeps: payments it cannot vouch for and cancels of them. Beyond it, the answer is to
/// post them again once the payment's parent is broadcast.
pub const MAX_UNCHECKED_BYTES: usize = 64 << 10;

/// The most bytes of checked cancels one job keeps for one payment. Only the payment's
/// signer can make one, so they crowd out nobody else's; beyond it the cheapest goes.
pub const MAX_CANCEL_BYTES: usize = MAX_TX_BYTES;

/// A cancel the job keeps: a spend of exactly the payment's coins back to the buyer.
///
/// A cancel is known by its witness transaction id (`wtxid`), never by its `txid` alone:
/// a Bitcoin transaction id does not cover the witness, so two copies of one transaction,
/// one validly signed and one not, share a `txid`. Each copy is held on its own, and one
/// the daemon vouched for is never displaced by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    /// The raw transaction, held once for every job that keeps the same one ([`shared`]).
    pub hex: Arc<str>,
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
            hex: shared(hex),
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
    /// The coins it spends, sorted: what it is known by. Held once however many jobs
    /// hold the same coins ([`shared_coins`]).
    pub coins: Arc<[bitcoin::OutPoint]>,
    /// The signed transaction held: the copy the daemon vouched for, when there is one.
    /// Held once for every job that holds it ([`shared`]), and stored once on disk.
    pub hex: Arc<str>,
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
            coins: shared_coins(inputs_of(&t)),
            hex: shared(hex),
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

    /// Holds the one copy kept of it once it is vouched for ([`one_copy`]); `witnessed`
    /// when the daemon vouched for this very copy, witness included.
    fn one_copy(&mut self, witnessed: bool) {
        if self.vouched && !self.hex.is_empty() {
            self.hex = one_copy(&self.txid, &self.hex, witnessed);
        }
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
        let wtxid = c.wtxid.clone();
        self.cancels.push(Cancel {
            by: String::new(),
            ..c
        });
        self.cancels.sort_by(|a, b| b.fee.cmp(&a.fee));
        // Within the bytes kept for one payment's cancels: the cheapest goes first.
        while self.cancels.len() > 1
            && self.cancels.iter().map(|c| c.hex.len() / 2).sum::<usize>() > MAX_CANCEL_BYTES
        {
            let i = self
                .cancels
                .iter()
                .enumerate()
                .min_by_key(|(_, h)| (h.fee, h.vouched))
                .map(|(i, _)| i)
                .expect("non-empty");
            self.cancels.remove(i);
        }
        self.cancels.iter().any(|h| h.wtxid == wtxid)
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

    /// As stored; with `inline` false, the signed transaction is named by its key
    /// ([`payment_key`]) and kept in a file of its own, once for every job.
    ///
    /// Its coins follow from the transaction, so a job's file names them only when it
    /// holds no copy of the transaction; otherwise it carries a digest of them
    /// ([`coins_digest`]), and a payment of many coins costs each job's file no more than
    /// one of few.
    fn to_json(&self, inline: bool) -> Value {
        let (k, hex) = if inline || self.hex.is_empty() {
            ("hex", self.hex.to_string())
        } else {
            ("hex_ref", payment_key(self))
        };
        let mut v = json!({
            "coins_key": coins_digest(&self.coins),
            "txid": self.txid,
            k: hex,
            "vouched": self.vouched,
            "by": self.by,
            "cancels": self.cancels.iter().map(|c| json!({"hex": &*c.hex, "fee": c.fee, "vouched": c.vouched})).collect::<Vec<_>>(),
            "pending": self.pending.iter().map(|c| json!({"hex": &*c.hex, "by": c.by})).collect::<Vec<_>>(),
            "settled": self.settled.as_ref().map(|s| json!({"height": s.at.height, "block": s.at.block, "txid": s.at.txid, "paid": s.paid})),
        });
        if k == "hex" {
            v["coins"] = json!(self
                .coins
                .iter()
                .map(|c| format!("{}:{}", c.txid, c.vout))
                .collect::<Vec<_>>());
        }
        v
    }

    fn from_stored(v: &Value, terms: &PayLockTerms) -> Result<Payment, Error> {
        let by = v.get("by").and_then(Value::as_str).unwrap_or_default();
        let mut p = match v.get("hex").and_then(Value::as_str).unwrap_or_default() {
            "" => Payment {
                coins: shared_coins(
                    v.get("coins")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c.as_str()?.parse().ok())
                        .collect(),
                ),
                hex: shared(""),
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
        p.one_copy(false);
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
        // A payment whose file is gone (removed by hand) and whose coins were not named:
        // its cancels spend exactly its coins.
        if p.coins.is_empty() {
            if let Some(c) = p.cancels.iter().chain(&p.pending).next() {
                if let Ok(t) = btc_tx(&c.hex, "cancel") {
                    p.coins = shared_coins(inputs_of(&t));
                }
            }
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
    /// When the work thread last worked the job (an order, not a time); 0 never, since the
    /// service started. Not stored.
    pub worked: u64,
    /// When the work thread last worked it (seconds since 1970); 0 never. Not stored.
    pub worked_at: u64,
    /// The tips of both chains when it was last worked, by their blocks' hashes (keys of
    /// them): a block replaced at the same height moves it. Not stored.
    pub epoch: (u64, u64),
    /// How many times intake merged something new in, and how many of those the work
    /// thread had seen when it last worked the job. Not stored.
    pub changed: u64,
    /// See `changed`.
    pub seen: u64,
}

/// What brings a candidate passed over back, as stored.
fn retry_json(r: &Retry) -> Value {
    match r {
        Retry::Never => json!({"kind": "never"}),
        Retry::Unknown => json!({"kind": "unknown"}),
        Retry::Floor { refused, untried } => json!({
            "kind": "floor",
            "refused": refused.iter().map(|r| json!({"asset": r.asset.to_string(), "atoms": r.atoms,
                "paid": r.paid, "need": r.need, "relay": r.relay, "rate": r.rate,
                "trusted": r.trusted})).collect::<Vec<_>>(),
            "untried": untried.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        }),
    }
}

/// [`retry_json`] read back; anything else (a record stored without it) is tried again.
fn retry_from(v: Option<&Value>) -> Retry {
    let Some(v) = v else {
        return Retry::Unknown;
    };
    match v.get("kind").and_then(Value::as_str) {
        Some("never") => Retry::Never,
        Some("floor") => Retry::Floor {
            refused: v
                .get("refused")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|r| {
                    let n = |k: &str| r.get(k).and_then(Value::as_u64).unwrap_or(0);
                    // A record without the claim's own fee (written before it was kept)
                    // tells nothing: tried again at the first floors read.
                    Some(Refusal {
                        asset: r.get("asset")?.as_str()?.parse().ok()?,
                        atoms: n("atoms"),
                        paid: n("paid"),
                        need: n("need"),
                        relay: n("relay"),
                        rate: n("rate"),
                        trusted: r.get("atoms").is_some()
                            && r.get("trusted").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect(),
            untried: v
                .get("untried")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|a| a.as_str()?.parse().ok())
                .collect(),
        },
        _ => Retry::Unknown,
    }
}

/// Signed transactions held, each once however many jobs hold it: a payment that vouches
/// for many jobs, or a cancel handed over for each, costs one copy.
static SHARED: std::sync::OnceLock<Mutex<std::collections::HashSet<Arc<str>>>> =
    std::sync::OnceLock::new();

/// The one copy of `hex` held ([`SHARED`]).
fn shared(hex: &str) -> Arc<str> {
    let mut set = SHARED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(h) = set.get(hex) {
        return h.clone();
    }
    let h: Arc<str> = Arc::from(hex);
    set.insert(h.clone());
    h
}

/// Payments vouched for, one copy per transaction id, whatever the witness of the copies
/// handed over: a mined transaction is vouched for by its id alone (`txn-already-known`),
/// so its copies may carry any witness, and each would otherwise cost memory and a file.
/// The copy kept is the first one held, unless the daemon later vouches for another by
/// its witness too (it pools or accepts that very copy), which then takes its place.
static BY_TXID: std::sync::OnceLock<Mutex<ByTxid>> = std::sync::OnceLock::new();

/// [`BY_TXID`]'s map: a transaction id, its copy held, and whether the daemon vouched for
/// that copy by its witness too.
type ByTxid = std::collections::HashMap<String, (Arc<str>, bool)>;

/// The one copy held of the vouched payment `txid` ([`BY_TXID`]): `hex` if none is, or if
/// `hex` is vouched for by its witness (`witnessed`) and the one held is not.
fn one_copy(txid: &str, hex: &Arc<str>, witnessed: bool) -> Arc<str> {
    let mut m = BY_TXID
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match m.get(txid) {
        Some((h, w)) if *w || !witnessed => h.clone(),
        _ => {
            m.insert(txid.to_string(), (hex.clone(), witnessed));
            hex.clone()
        }
    }
}

/// The coins of payments held, each list once however many jobs hold it.
static COINS: std::sync::OnceLock<Mutex<std::collections::HashSet<Arc<[bitcoin::OutPoint]>>>> =
    std::sync::OnceLock::new();

/// The one copy held of the coin list `coins` ([`COINS`]).
fn shared_coins(coins: Vec<bitcoin::OutPoint>) -> Arc<[bitcoin::OutPoint]> {
    let mut set = COINS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(c) = set.get(&coins[..]) {
        return c.clone();
    }
    let c: Arc<[bitcoin::OutPoint]> = Arc::from(coins);
    set.insert(c.clone());
    c
}

/// A short name for a payment's coins, as a job's file records them while the payment's
/// own file holds the transaction.
fn coins_digest(coins: &[bitcoin::OutPoint]) -> String {
    let mut e = sha256::Hash::engine();
    for c in coins {
        lwk_wollet::elements::hashes::HashEngine::input(
            &mut e,
            format!("{}:{};", c.txid, c.vout).as_bytes(),
        );
    }
    sha256::Hash::from_engine(e).to_string()
}

/// Lets go of the copies no job holds any more.
fn drop_unshared() {
    if let Some(m) = SHARED.get() {
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|h| Arc::strong_count(h) > 1);
    }
    if let Some(m) = BY_TXID.get() {
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (h, _)| Arc::strong_count(h) > 1);
    }
    if let Some(m) = COINS.get() {
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|c| Arc::strong_count(c) > 1);
    }
}

/// The name of a signed payment's file: its transaction id once the daemon vouched for it
/// (one file per transaction, whatever the witness of the copies handed over); until then
/// a hash of the copy, witness included, since an unchecked witness may be bad and must not
/// stand in for another's.
fn payment_key(p: &Payment) -> String {
    if p.vouched {
        format!("tx-{}", p.txid)
    } else {
        sha256::Hash::hash(p.hex.as_bytes()).to_string()
    }
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
            if serialize(c).len() > MAX_CLAIM_BYTES {
                return Err(Error(format!(
                    "a signed claim is at most {MAX_CLAIM_BYTES} bytes"
                )));
            }
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
            worked: 0,
            worked_at: 0,
            epoch: (0, 0),
            changed: 0,
            seen: 0,
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
                if inputs_of(&t)[..] != p.coins[..] {
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
        self.json(true)
    }

    /// The job as its file holds it: its payments named by key, each kept once for every
    /// job in a file of its own ([`Store::save`]).
    fn stored_json(&self) -> Value {
        self.json(false)
    }

    fn json(&self, inline: bool) -> Value {
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
            .map(|p| p.to_json(inline))
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
        v["candidates"] = json!(self
            .scan
            .candidates
            .iter()
            .map(
                |c| json!({"height": c.at.height, "block": c.at.block, "txid": c.at.txid,
                "held": c.held, "min_proof": c.min_proof})
            )
            .collect::<Vec<_>>());
        v["passed"] = json!(self
            .scan
            .passed
            .iter()
            .map(
                |p| json!({"height": p.at.height, "block": p.at.block, "txid": p.at.txid,
                "proof": p.proof, "why": p.why, "tip": p.tip, "retry": retry_json(&p.retry)})
            )
            .collect::<Vec<_>>());
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
        // The payment the claim proves, else the candidate tried first, else a late one.
        let first = self.scan.ordered().into_iter().next().map(|c| c.at);
        let payment = self.scan.found.clone().or(first).or(self.scan.late.clone());
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
            "payment_height": payment.as_ref().map(|f| f.height),
            "payment_bumped": payment.as_ref().map(|f| !self.payments.iter().any(|p| p.txid == f.txid)),
            // Whether the node accepted a claim proving that payment.
            "payment_claimed": self.scan.found.is_some(),
            // A transaction paying the seller in the lock's heights that no proof can carry:
            // it opens nothing and withholds no cancel.
            "unprovable_payment_height": self.scan.unprovable.as_ref().map(|f| f.height),
            // Payments in the lock's heights a proof can carry, and those passed over: the
            // node refused every claim on them for the claim's weight.
            "candidates": self.scan.candidates.len(),
            "passed_over": self.scan.passed.iter().map(|p| json!({"height": p.at.height, "txid": p.at.txid, "why": p.why})).collect::<Vec<_>>(),
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
            candidates: v
                .get("candidates")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|c| {
                    Some(Candidate {
                        at: Found {
                            height: c.get("height")?.as_u64()? as u32,
                            block: c.get("block")?.as_str()?.to_string(),
                            txid: c.get("txid")?.as_str()?.to_string(),
                        },
                        held: c.get("held")?.as_bool()?,
                        min_proof: c.get("min_proof")?.as_u64()? as usize,
                    })
                })
                .collect(),
            passed: v
                .get("passed")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|p| {
                    Some(Passed {
                        at: Found {
                            height: p.get("height")?.as_u64()? as u32,
                            block: p.get("block")?.as_str()?.to_string(),
                            txid: p.get("txid")?.as_str()?.to_string(),
                        },
                        proof: p.get("proof")?.as_u64()? as usize,
                        why: p.get("why")?.as_str()?.to_string(),
                        tip: p.get("tip")?.as_u64()? as u32,
                        retry: retry_from(p.get("retry")),
                    })
                })
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

    /// Whether the payment is known: mined at a height the claim accepts, and proven by a
    /// claim that is pooled or mined now. A payment only mined, whose claim may never land,
    /// withholds no cancel, and neither does one whose claim the node once accepted but
    /// holds no longer (it left the mempool, and every tier is refused now).
    fn paid_in_window(&self) -> bool {
        matches!(self.state, State::Pooled | State::Mined | State::Final)
            && self
                .scan
                .found
                .as_ref()
                .map(|f| f.height > self.terms.floor && f.height <= self.terms.deadline)
                .unwrap_or(false)
    }

    /// The bytes of signed transactions held that the Bitcoin daemon could not check yet:
    /// payments it has not vouched for, and cancels not checked yet.
    fn unchecked_bytes(&self) -> usize {
        self.payments
            .iter()
            .map(|p| {
                (if p.vouched { 0 } else { p.hex.len() / 2 })
                    + p.pending.iter().map(|c| c.hex.len() / 2).sum::<usize>()
            })
            .sum()
    }

    /// The payment held that spends exactly `coins`.
    fn payment_for(&mut self, coins: &[bitcoin::OutPoint]) -> Option<&mut Payment> {
        self.payments.iter_mut().find(|p| *p.coins == *coins)
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

    /// Holds the one copy kept of each payment vouched for ([`one_copy`]).
    fn one_copy_each(&mut self) {
        for p in self.payments.iter_mut() {
            p.one_copy(false);
        }
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
                p.hex = shared(&h);
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
    // Vouched for by its id alone when mined: any witness passes, so the copy held is the
    // one already held for that id, if any.
    let by_id_only = matches!(&a, Accept::Refused(r) if r.contains("txn-already-known"));
    p.one_copy(!by_id_only);
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
                        p.one_copy(true);
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
            match held.and_then(|h| h.payments.iter().find(|p| *p.coins == spent[..])) {
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
                p.hex = shared("");
            }
            PaymentCheck::PooledCopy | PaymentCheck::Kept => {}
        }
    }
    for q in found {
        let _ = job.take_payment(q);
    }
    job.one_copy_each();
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

/// The tiers to try a claim at now ([`Tiers`]), cheapest first within each fee asset, in
/// the order the buyer signed the assets: every tier of each asset the node accepts whose
/// fee coin (if any) is still unspent; only the top tiers once a block left the claim out.
fn tiers(seq: &SeqChain, job: &Job) -> Result<Tiers, Error> {
    let leaf = job.terms.claim_leaf().to_bytes();
    let mut out = Tiers::default();
    for (asset, tiers) in job.fee_sets() {
        if !seq.fee_asset_accepted(&asset)? {
            out.unaccepted.push(asset);
            continue;
        }
        let take = if job.raised {
            vec![*tiers.last().expect("non-empty")]
        } else {
            tiers
        };
        for i in take {
            let mut coins_unspent = true;
            for input in &job.claims[i].input {
                let w = &input.witness.script_witness;
                let spends_lock = w.len() == 4 && w[2] == leaf;
                if !spends_lock && !seq.unspent_in_chain(&input.previous_output)? {
                    coins_unspent = false;
                }
            }
            if coins_unspent {
                out.usable.push(i);
            } else {
                out.coin_spent = true;
            }
        }
    }
    Ok(out)
}

/// [`tiers`]' answer.
#[derive(Default)]
struct Tiers {
    /// The tiers to try.
    usable: Vec<usize>,
    /// The claims' fee assets the node does not accept.
    unaccepted: Vec<AssetId>,
    /// Whether a tier was left out because its fee coin is not unspent in the chain (spent,
    /// or not confirmed yet).
    coin_spent: bool,
}

/// Whether claim `i` is the top tier of its fee asset.
fn is_top(job: &Job, i: usize) -> bool {
    job.fee_sets().iter().any(|(_, v)| v.last() == Some(&i))
}

/// Takes the payment a claim on the chain proves as the swap's payment, when Bitcoin's
/// best chain holds it: the node accepted a claim on it.
fn note_proven(btc: &BtcChain, job: &mut Job, claim: &Transaction) -> Result<(), Error> {
    if let Some(f) = proven_payment(claim) {
        if job.scan.found.as_ref() != Some(&f) && btc.holds(f.height, &f.block)? {
            job.scan.found = Some(f);
        }
    }
    Ok(())
}

/// What trying the candidates came to.
enum Landing {
    /// A claim is pooled, or the round's time ran out: nothing more this round.
    Done,
    /// No claim yet, and why: the chain's state, which a later round may find changed.
    Waiting(String),
    /// Every candidate is passed over.
    Nothing,
}

/// Completes and submits a claim on the first candidate whose claim the node accepts: the
/// candidates in [`PaymentScan::ordered`]'s order, each at every tier in [`tiers`]'
/// order. A refusal for the claim's weight ([`refused_for_weight`]) moves to the next
/// tier, and at the last passes the candidate over, with every heavier one, recording what
/// refused it ([`Retry`]) so that it is tried again only once that can have changed; the
/// next candidate is tried at once. When no tier pays in an asset the node accepts, every
/// candidate is passed over until one of those assets is accepted. A candidate whose proof
/// waits on the chain (no anchor at its height yet, the two chains not agreeing, too many
/// links) is left for a later round and the next one is tried. Any other refusal does not
/// depend on the payment: it ends the round in error, to be retried.
fn land(
    seq: &SeqChain,
    btc: &BtcChain,
    job: &mut Job,
    seq_tip: u32,
    btc_tip: u32,
    floors: &Floors,
    until: Instant,
) -> Result<Landing, Error> {
    if !job.scan.live() {
        return Ok(Landing::Nothing);
    }
    let tiers = tiers(seq, job)?;
    if tiers.usable.is_empty() {
        job.state = State::Waiting;
        if tiers.coin_spent || tiers.unaccepted.is_empty() {
            job.note =
                "no signed tier pays its fee in an asset the node accepts, from a coin still unspent"
                    .into();
            return Err(Error(job.note.clone()));
        }
        // Nothing to try until an asset the buyer signed in is accepted: every candidate
        // waits for that, and costs nothing meanwhile.
        let why = format!(
            "no signed tier pays its fee in an asset the node accepts ({})",
            tiers
                .unaccepted
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        for c in job.scan.candidates.clone() {
            if job.scan.is_passed(&c).is_none() {
                pass_over(
                    job,
                    &c,
                    usize::MAX,
                    why.clone(),
                    btc_tip,
                    Retry::Floor {
                        refused: vec![],
                        untried: tiers.unaccepted.clone(),
                    },
                );
            }
        }
        return Ok(Landing::Nothing);
    }
    let mut waiting: Option<String> = None;
    for c in job.scan.ordered() {
        if job.scan.is_passed(&c).is_some() {
            continue;
        }
        if Instant::now() >= until {
            return Ok(Landing::Done);
        }
        let mut heavy: Option<(String, usize)> = None;
        let mut every_tier = true;
        // The best refusal for the claim's fee rate in each asset (the claim's signed fee
        // and the node's message), and whether a tier was refused for its size, which no
        // floor changes.
        let mut refused: Vec<(AssetId, u64, String)> = vec![];
        for &t in &tiers.usable {
            match prove_claim(seq, btc, &job.terms, &job.lock, &job.claims[t], &c.at)? {
                Completion::Ready {
                    tx,
                    height,
                    proof_bytes,
                    ..
                } => match seq.send(&tx) {
                    Ok(_) => {
                        job.tier = t;
                        job.pooled_at = Some(seq_tip);
                        job.state = State::Pooled;
                        job.decided_at = None;
                        job.buried = false;
                        job.scan.found = Some(c.at.clone());
                        let passed = match job.scan.passed.len() {
                            0 => String::new(),
                            n => format!(
                                "; {n} heavier payment(s) passed over, the node refusing every claim on them"
                            ),
                        };
                        job.note = format!(
                            "the claim ({} tier, fee {}) is pooled with a proof of the payment {} in Bitcoin block {height}{passed}",
                            if is_top(job, t) { "top" } else { "going" },
                            fee_of(&tx)
                                .map(|(a, f)| format!("{f} atoms of {a}"))
                                .unwrap_or_default(),
                            c.at.txid,
                        );
                        return Ok(Landing::Done);
                    }
                    Err(e) if refused_for_weight(&e.0) => {
                        if let (Some((asset, atoms)), false) =
                            (fee_of(&tx), e.0.contains("tx-size"))
                        {
                            // Keep the one nearest to landing: the highest signed fee over
                            // what the node asked (one that gave no figures, the least).
                            let near = |atoms: u64, m: &str| {
                                refusal_figures(m)
                                    .filter(|(_, need)| *need > 0)
                                    .map(|(_, need)| atoms as f64 / need as f64)
                                    .unwrap_or(-1.0)
                            };
                            match refused.iter_mut().find(|x| x.0 == asset) {
                                Some(x) if near(atoms, &e.0) > near(x.1, &x.2) => {
                                    *x = (asset, atoms, e.0.clone())
                                }
                                Some(_) => {}
                                None => refused.push((asset, atoms, e.0.clone())),
                            }
                        }
                        heavy = Some((e.0, proof_bytes));
                    }
                    Err(e) => {
                        job.state = State::Waiting;
                        job.note = format!("the node refused the completed claim: {e}");
                        return Err(Error(job.note.clone()));
                    }
                },
                Completion::Waiting(why) => {
                    waiting.get_or_insert(why);
                    every_tier = false;
                    break;
                }
                Completion::Never(why) => {
                    // No proof can carry it: this candidate alone, never a heavier one, and
                    // for good (short of a reorganization).
                    every_tier = false;
                    pass_over(job, &c, usize::MAX, why, btc_tip, Retry::Never);
                    break;
                }
            }
        }
        if let Some((why, proof)) = heavy.filter(|_| every_tier) {
            // The floors the node judged by, read again now: the record holds both reads,
            // so a floor that moved meanwhile is seen (and the record is not trusted when
            // the asset's rate moved under the refusal).
            let after = if refused.is_empty() {
                None
            } else {
                seq.floors().ok()
            };
            let refused: Vec<Refusal> = refused
                .iter()
                .map(|(asset, atoms, m)| Refusal::new(*asset, *atoms, m, floors, after.as_ref()))
                .collect();
            let retry = if refused.is_empty() && tiers.unaccepted.is_empty() {
                // Refused for its size at every tier: no floor brings it back.
                Retry::Never
            } else {
                Retry::Floor {
                    refused,
                    untried: tiers.unaccepted.clone(),
                }
            };
            pass_over(job, &c, proof, why, btc_tip, retry);
        }
    }
    Ok(match waiting {
        Some(w) => Landing::Waiting(w),
        None => Landing::Nothing,
    })
}

/// Passes candidate `c` over (see [`Passed`]). The payment a claim was accepted on is no
/// longer known once its claim is refused at every tier: it withholds no cancel.
fn pass_over(job: &mut Job, c: &Candidate, proof: usize, why: String, tip: u32, retry: Retry) {
    if job.scan.found.as_ref() == Some(&c.at) {
        job.scan.found = None;
    }
    job.scan.passed.push(Passed {
        at: c.at.clone(),
        proof,
        why,
        tip,
        retry,
    });
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
    let floors = seq.floors().unwrap_or_default();
    tick_with(
        seq,
        btc,
        &mut BlockCache::default(),
        &floors,
        job,
        limits,
        until,
    )
}

/// [`tick`], reading Bitcoin's blocks through `blocks` and the node's fee floors from
/// `floors`, which the work thread reads once a round for every job: each block is read
/// once, whatever the number of jobs.
pub fn tick_with(
    seq: &SeqChain,
    btc: &BtcChain,
    blocks: &mut BlockCache,
    floors: &Floors,
    job: &mut Job,
    limits: &Limits,
    until: Instant,
) -> Result<(), Error> {
    let now = now_secs();
    // Mined, and final? Any tier may be the one mined.
    let finalized = seq.finalized_height()?;
    let mut pooled = None;
    for (i, c) in job.claims.iter().enumerate() {
        let Some((tx, status)) = seq.tx(&c.txid())? else {
            continue;
        };
        match status {
            TxStatus::Mined(h) => {
                job.mined_at = Some(h);
                job.tier = i;
                note_proven(btc, job, &tx)?;
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
                        format!("the claim {} is final at Sequentia height {h}", tx.txid()),
                    );
                } else {
                    job.state = State::Mined;
                    job.decided_at = None;
                    job.buried = false;
                    job.note = format!("the claim {} is mined at {h}, not final yet", tx.txid());
                }
                return Ok(());
            }
            TxStatus::Pooled => pooled = Some((i, tx)),
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
    match pooled.as_ref().map(|(i, _)| *i) {
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
    let coins: Vec<Arc<[bitcoin::OutPoint]>> =
        job.payments.iter().map(|p| p.coins.clone()).collect();
    let mut settled: Vec<Option<Settled>> =
        job.payments.iter().map(|p| p.settled.clone()).collect();
    let open = job
        .payments
        .iter()
        .any(|p| p.real() && p.settled.is_none() && p.has_cancel());
    let complete = btc.scan_lock(
        blocks,
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
    // What is passed over is tried again once what refused it can have changed: the node's
    // floor in the fee asset fell below the rate it refused, or an asset no tier could pay
    // in is accepted. Never merely because a block arrived.
    job.scan.passed.retain(|p| !p.retry_due(floors));

    // A claim pooled at the tier wanted: the node accepted it, so the payment it proves
    // is the swap's. Raised, a lower tier pooled is replaced by a top one below.
    if let Some((i, tx)) = &pooled {
        if !job.raised || is_top(job, *i) {
            note_proven(btc, job, tx)?;
            job.state = State::Pooled;
            job.decided_at = None;
            job.buried = false;
            return Ok(());
        }
    }
    // The payment is the candidate whose completed claim the node accepts.
    if !job.scan.candidates.is_empty() {
        match land(seq, btc, job, seq_tip, btc_tip, floors, until)? {
            Landing::Done => return Ok(()),
            Landing::Waiting(why) => {
                job.state = State::Waiting;
                job.decided_at = None;
                job.buried = false;
                job.note = why;
                return Ok(());
            }
            Landing::Nothing => {}
        }
    }

    // No candidate takes a claim now: none is mined in the lock's heights, or the node
    // refuses every claim on those that are.
    let passed = job.scan.passed.first().map(|p| {
        format!(
            "the payment {} in Bitcoin block {} pays the seller, but the node refuses every claim on it ({})",
            p.at.txid, p.at.height, p.why
        )
    });
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
        if let Some((p, s)) = cancel {
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
            return Ok(());
        }
        // Each payment held is mined, paying the seller: the latest names the outcome.
        if let Some(s) = vouched
            .iter()
            .filter_map(|p| p.settled.as_ref())
            .max_by_key(|s| s.at.height)
        {
            let (txid, h) = (s.at.txid.clone(), s.at.height);
            let why = if h > d {
                format!("the payment {txid} is mined at Bitcoin block {h}, after the deadline {d}")
            } else if h <= job.terms.floor {
                format!(
                    "the payment {txid} is mined at Bitcoin block {h}, not above the lock's floor {}",
                    job.terms.floor
                )
            } else {
                passed.clone().unwrap_or_else(|| {
                    format!("the payment {txid} in Bitcoin block {h} pays the seller, but no claim on it is accepted")
                })
            };
            if h > job.terms.floor && h <= d && !(complete && btc_tip > d) {
                // Another payment may still come before the deadline.
                job.state = State::Waiting;
                job.decided_at = None;
                job.buried = false;
                job.note = format!("{why}: passed over, looking for another payment");
            } else {
                end(job, State::Never, h.max(d), btc_tip, limits, why);
            }
            return Ok(());
        }
    }
    if complete && btc_tip > d {
        let why = match (&passed, &job.scan.unprovable) {
            (Some(p), _) => format!("{p}; no other payment was mined by the deadline (Bitcoin block {d})"),
            (None, Some(u)) => format!(
                "no payment was mined by the deadline (Bitcoin block {d}) (the transaction {} in Bitcoin block {} pays the seller, but no proof can carry it: it opens nothing)",
                u.txid, u.height
            ),
            (None, None) => format!("no payment was mined by the deadline (Bitcoin block {d})"),
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
                    "the payment {} is mined at Bitcoin block {}, after the deadline {d}",
                    f.txid, f.height
                ),
                None if open => format!("{why}; no spend of the payment's coins confirmed in {CANCEL_KEEP_BLOCKS} blocks"),
                None => why,
            };
            end(job, State::Never, d, btc_tip, limits, why);
        }
        return Ok(());
    }
    job.state = State::Waiting;
    job.decided_at = None;
    job.buried = false;
    job.note = match passed {
        Some(p) => format!("{p}: passed over, looking for another payment"),
        None => "the payment is not mined on Bitcoin yet".into(),
    };
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
    Ok(())
}

/// One pass of the cancel thread. It reads Bitcoin's tip and sends the cancels that are
/// due (a job not ended, with cancels, its payment not known to be mined in the lock's
/// heights and no spend of its coins confirmed, the tip two blocks before `D` or later,
/// and not more than [`CANCEL_KEEP_BLOCKS`] past `D`), within
/// [`Limits::cancel_pass_time`]; then, for half as long again, it looks up the locks the
/// node has not answered for, which orders the next pass (never before a send). Every due cancel is sent, whatever the Sequentia node
/// says of the lock: the cancel concerns Bitcoin alone, and a node still syncing must not
/// cost a buyer its bitcoin. The node's answer only orders the sends: jobs whose lock it
/// knows first, then those it has not answered for, then those it says it does not know.
/// Within each, cancels never tried go first, nearest deadline first; then those tried
/// before, the longest ago first (each at most every ten seconds), so what one pass does
/// not reach the next one does. The turns are per payment, known by its coins: every job
/// holding the same coins shares one turn and one send, so a payment shared by many jobs
/// costs one send. A payment's cancels go out highest fee first until the daemon takes
/// one. What the sends tell the jobs is written once every send is done. Returns how many
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
    let end_at = start + limits.cancel_pass_time;
    // One entry per payment with cancels to send, keyed by the client that handed it over:
    // whoever started the job, each payment's sender takes its own turns. Payments are
    // known by their coins: every job holding the same coins (one payment vouching for
    // many jobs, or copies of it) is one entry, sent once, so jobs that share a payment
    // cost one send between them, however many there are.
    let mut groups: Vec<CancelGroup> = vec![];
    let mut group_of: std::collections::HashMap<Arc<[bitcoin::OutPoint]>, usize> =
        Default::default();
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
                // A payment known by no coins (its copy lost) is a turn of its own.
                let g = if p.coins.is_empty() {
                    groups.push((p.coins.clone(), vec![]));
                    groups.len() - 1
                } else {
                    *group_of.entry(p.coins.clone()).or_insert_with(|| {
                        groups.push((p.coins.clone(), vec![]));
                        groups.len() - 1
                    })
                };
                groups[g].1.push((j.id.clone(), i));
                due_jobs.push((rank, j.cancel_tried, key, g, p.by.clone()));
            }
        }
    }
    due_jobs.sort();
    // A group takes its place at its first entry: its best rank, its client's turn.
    let mut seen = std::collections::HashSet::new();
    due_jobs.retain(|t| seen.insert(t.3));
    let mut sent = 0;
    // The sends first, then what they tell each job: so a group's many jobs are written
    // once every cancel due has gone out, and never before another payment's send.
    let mut results: Vec<(usize, bool, Option<String>)> = vec![];
    for g in take_turns(due_jobs) {
        let members = &groups[g].1;
        // The cancels of every job holding these coins, each copy once: the checked ones,
        // highest fee first; then those not checkable yet, which a daemon refuses if they
        // are not valid. All spend the same coins, so the first one taken ends the turn.
        let mut checked: Vec<Cancel> = vec![];
        let mut pending: Vec<Cancel> = vec![];
        {
            let st = lock(store);
            for (id, i) in members {
                let Some(p) = st.jobs.get(id).and_then(|j| j.payments.get(*i)) else {
                    continue;
                };
                for c in &p.cancels {
                    if !checked.iter().any(|k| k.hex == c.hex) {
                        checked.push(c.clone());
                    }
                }
                for c in &p.pending {
                    if !pending.iter().any(|k| k.hex == c.hex) {
                        pending.push(c.clone());
                    }
                }
            }
        }
        checked.sort_by(|a, b| b.fee.cmp(&a.fee));
        // The unchecked ones take turns by the client that handed them over, so no
        // client's copies come all before another's: none can be checked, and a bad
        // copy must not keep the good one from being tried.
        let pending = take_turns(
            pending
                .into_iter()
                .map(|c| (0, false, 0, c.clone(), c.by.clone()))
                .collect(),
        );
        let mut accepted = false;
        let mut refused = None;
        let mut tried = false;
        let send = |c: &Cancel, accepted: &mut bool, refused: &mut Option<String>| match btc
            .send_raw(&c.hex)
        {
            Ok(_) => {
                *accepted = true;
                1
            }
            Err(e) => {
                let m = e.to_string();
                if m.contains("already") {
                    *accepted = true;
                } else {
                    refused.get_or_insert(m);
                }
                0
            }
        };
        // The checked ones until the daemon takes one: each spends the same coins, so
        // the rest could only conflict with it.
        for c in &checked {
            if Instant::now() >= end_at || accepted {
                break;
            }
            tried = true;
            sent += send(c, &mut accepted, &mut refused);
        }
        // Then, while none was taken, every unchecked copy: the daemon refuses those that
        // are not valid.
        if !accepted {
            for c in &pending {
                if Instant::now() >= end_at {
                    break;
                }
                tried = true;
                sent += send(c, &mut accepted, &mut refused);
            }
        }
        if !tried {
            break;
        }
        results.push((g, accepted, refused));
    }
    for (g, accepted, refused) in results {
        let mut ids: Vec<&String> = groups[g].1.iter().map(|(id, _)| id).collect();
        ids.dedup();
        for id in ids {
            let mut st = lock(store);
            let Some(j) = st.jobs.get_mut(id) else {
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
            } else if let Some(m) = &refused {
                if !j.cancel_sent {
                    j.note = format!("the cancel was refused: {m}");
                }
            }
            let j = j.clone();
            let _ = st.save(&j);
        }
    }
    // Then the locks never looked up, for half the pass again: the answer orders the next
    // pass's sends (an unanswered node leaves them where they are). Looked up after the
    // sends, so no lookup ever delays one.
    let ids: Vec<String> = lock(store)
        .jobs
        .values()
        .filter(|j| due(j) && j.lock_known.is_none())
        .map(|j| j.id.clone())
        .collect();
    let lookups_end = Instant::now() + limits.cancel_pass_time / 2;
    for id in ids {
        if Instant::now() >= lookups_end {
            break;
        }
        let Some(job) = lock(store).jobs.get(&id).cloned() else {
            continue;
        };
        let Ok(known) = lock_on_chain(seq, &job) else {
            break;
        };
        let mut st = lock(store);
        if let Some(j) = st.jobs.get_mut(&id) {
            j.lock_known = Some(known);
            j.lock_checked_at = now;
            let j = j.clone();
            let _ = st.save(&j);
        }
    }
    Ok(sent)
}

/// The order cancels are sent in: by lock rank, and within a rank the clients that
/// started the jobs take turns, each in its own order (never tried first, nearest
/// deadline first). So a client with many jobs gets one send per turn, like any other,
/// and cannot push another client's cancel back. `due` is sorted by rank first.
/// The coins of a payment with cancels due, and every (job, payment) holding them.
type CancelGroup = (Arc<[bitcoin::OutPoint]>, Vec<(String, usize)>);

/// A payment's cancels due: lock rank, tried before, its order key, the group of jobs
/// holding its coins, and the client that handed the payment over.
type Turn = (u8, bool, u64, usize, String);

fn take_turns<K: Clone>(due: Vec<(u8, bool, u64, K, String)>) -> Vec<K> {
    let mut out = vec![];
    let mut i = 0;
    while i < due.len() {
        let rank = due[i].0;
        // The clients' queues in the order each first appears, found by a map: linear in
        // the cancels, however many clients there are.
        let mut queues: Vec<std::collections::VecDeque<K>> = vec![];
        let mut of: std::collections::HashMap<&str, usize> = Default::default();
        while i < due.len() && due[i].0 == rank {
            let (_, _, _, id, client) = &due[i];
            let q = *of.entry(client.as_str()).or_insert_with(|| {
                queues.push(Default::default());
                queues.len() - 1
            });
            queues[q].push_back(id.clone());
            i += 1;
        }
        // Turn by turn: one from each client still holding some, in that order.
        let mut live: Vec<usize> = (0..queues.len()).collect();
        while !live.is_empty() {
            live.retain(|&q| match queues[q].pop_front() {
                Some(id) => {
                    out.push(id);
                    true
                }
                None => false,
            });
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
    /// Bitcoin's blocks as the work thread reads them, shared by every job.
    pub blocks: Arc<Mutex<BlockCache>>,
}

impl Store {
    /// Opens (or creates) the store and reads every job in it; any ended and buried job
    /// found among them is archived.
    pub fn open(dir: &Path) -> Result<Store, Error> {
        for d in ["archive", "payments"] {
            std::fs::create_dir_all(dir.join(d))
                .map_err(|e| Error(format!("{}: {e}", dir.display())))?;
        }
        let mut jobs = BTreeMap::new();
        for e in std::fs::read_dir(dir).map_err(|e| Error(e.to_string()))? {
            let p = e.map_err(|e| Error(e.to_string()))?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let mut v: Value =
                serde_json::from_slice(&std::fs::read(&p).map_err(|e| Error(e.to_string()))?)
                    .map_err(|e| Error(format!("{}: {e}", p.display())))?;
            // Each payment from its own file. One gone (removed by hand) leaves the payment
            // known by its id, without the transaction, and by its coins as its cancels
            // spend them.
            for q in v
                .get_mut("payments")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                if let Some(k) = q.get("hex_ref").and_then(Value::as_str).map(String::from) {
                    let f = dir.join("payments").join(format!("{k}.hex"));
                    if let Ok(h) = std::fs::read_to_string(&f) {
                        q["hex"] = json!(h);
                    }
                }
            }
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
            blocks: Arc::new(Mutex::new(BlockCache::default())),
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
        st.prune_payments();
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
            let had = held.unchecked_bytes();
            let (mut m, what) = merge(held, job, limits)?;
            if what.is_empty() {
                return Ok((id, Added::Same));
            }
            if m.unchecked_bytes() > MAX_UNCHECKED_BYTES && m.unchecked_bytes() > had {
                return Err(unchecked_limit());
            }
            // Something new to work on: the job's turn comes early.
            m.changed += 1;
            m.one_copy_each();
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
        if job.unchecked_bytes() > MAX_UNCHECKED_BYTES {
            return Err(unchecked_limit());
        }
        job.one_copy_each();
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

    /// Writes a job's file, and the file of each payment it holds that is not written yet:
    /// one per signed payment, however many jobs hold it.
    pub fn save(&self, job: &Job) -> Result<(), Error> {
        let io = |e: std::io::Error| Error(e.to_string());
        for p in job.payments.iter().filter(|p| !p.hex.is_empty()) {
            let key = payment_key(p);
            let f = self.dir.join("payments").join(format!("{key}.hex"));
            if !f.exists() {
                let tmp = self.dir.join("payments").join(format!("{key}.tmp"));
                std::fs::write(&tmp, p.hex.as_bytes()).map_err(io)?;
                std::fs::rename(&tmp, &f).map_err(io)?;
            }
        }
        let p = self.path(&job.id);
        let tmp = self.dir.join(format!("{}.json.tmp", job.id));
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&job.stored_json()).map_err(|e| Error(e.to_string()))?,
        )
        .map_err(io)?;
        std::fs::rename(&tmp, &p).map_err(io)
    }

    /// Removes the payment files no job carried holds, and lets go of the copies in memory
    /// no job holds. Returns how many files it removed.
    pub fn prune_payments(&self) -> usize {
        drop_unshared();
        let held: std::collections::HashSet<String> = self
            .jobs
            .values()
            .flat_map(|j| j.payments.iter())
            .filter(|p| !p.hex.is_empty())
            .map(|p| format!("{}.hex", payment_key(p)))
            .collect();
        let Ok(rd) = std::fs::read_dir(self.dir.join("payments")) else {
            return 0;
        };
        let mut n = 0;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !held.contains(&name) && std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
        n
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

fn unchecked_limit() -> Refused {
    Refused::Limit(Error(format!(
        "the job holds {MAX_UNCHECKED_BYTES} bytes of payments and cancels the Bitcoin daemon cannot check yet, as many as it keeps: post these again once the payment's parent is broadcast"
    )))
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
        .map(|p| p["coins_key"].clone())
        .collect();
    for p in &cur.payments {
        let key = json!(coins_digest(&p.coins));
        let new = Payment {
            cancels: p
                .cancels
                .iter()
                .filter(|c| !had_cancels.iter().any(|h| **h == *c.hex))
                .cloned()
                .collect(),
            pending: p
                .pending
                .iter()
                .filter(|c| !had_pending.iter().any(|h| **h == *c.hex))
                .cloned()
                .collect(),
            ..p.clone()
        };
        if job.payment_for(&p.coins).is_some() || !had_coins.contains(&key) {
            let _ = job.take_payment(new);
        }
    }
}

/// Whether every claim of a job is worth less than the node's floor asks for its lightest
/// proof in play (a candidate not passed over, or `hit`, a payment in a block just reached),
/// by a margin: its worth at the fee asset's rate, a quarter again, is still under. The
/// proof counted is the lightest one possible, so a claim judged under is under. It only
/// orders the work (such jobs take their turns after the rest of their class), never skips
/// it, so a wrong guess costs time, never a claim.
fn under_floor(j: &Job, floors: &Floors, hit: Option<usize>) -> bool {
    if !floors.known {
        return false;
    }
    let Some(proof) = j
        .scan
        .candidates
        .iter()
        .filter(|c| j.scan.is_passed(c).is_none())
        .map(|c| c.min_proof)
        .chain(hit)
        .min()
    else {
        return false;
    };
    !j.claims.iter().any(|c| {
        let Some((asset, atoms)) = fee_of(c) else {
            return false;
        };
        let Some(&rate) = floors.rates.get(&asset) else {
            return false;
        };
        let worth = atoms as f64 * rate as f64 / 1e8;
        let vsize = (c.weight() + proof + 3) / 4;
        let need = floors.rate as f64 * vsize as f64 / 1000.0;
        worth * 1.25 > need
    })
}

/// The order jobs are worked in: an increasing count.
static WORK_ORDER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One round of work. The work a job costs follows what happens to it on the chains, never
/// the number of jobs or of the clients that posted them:
///
/// - Bitcoin's blocks are read once for every job ([`BlockCache`]), and the node's fee
///   floors once a round ([`Floors`]): a job's search moves through blocks that neither pay
///   its receiving script nor spend its payments' coins by a lookup, without a call to
///   either chain ([`BlockCache::advance`]);
/// - a job is worked only when something it waits on can have changed, and in this order:
///   1. something new on the chains concerns it. First those a claim must be made for: a
///      block that pays its script or spends its coins; a candidate payment not passed
///      over that a Sequentia block now anchors; its claim gone from the mempool. Those
///      whose claims are worth at least the node's floor go first, the rest after. Then
///      those whose claim is made: pooled by someone, left out of a block (to raise it),
///      or mined;
///   2. intake changed it since it was last worked, or its search reached a block not read
///      yet;
///   3. a candidate it passed over may now land: a refused tier's signed fee covers what
///      the node would ask for it at the floors now ([`lwk_paylock::Refusal::may_clear`]),
///      or an asset no tier could pay in is accepted, the claims clearing the ask by the
///      most first; then a job whose last round failed, once its backoff is over, fewest
///      failures first;
///   4. the rest, once per Bitcoin block (for the deadline and the state they show), and
///      those holding a payment or cancel Bitcoin cannot check yet, whenever a chain moves
///      and at least every ten seconds.
///
///   A candidate passed over is never tried again merely because a block arrived, so a
///   job whose claims cannot land (priced under the floor, in an asset the node does not
///   accept) costs a lookup a round once it has been tried, however many there are;
/// - within each of those, the jobs take turns by receiving script, each script's least
///   recently worked first (in the third, the one clearing the node's ask by the most). So a
///   buyer whose payment is mined is worked in the first turns of the next round, behind
///   only the jobs that a claim must be made for in that round, each of which cost
///   whoever made it an output in a new Bitcoin block or a claim the node takes (and pays
///   for: a claim pooled pays its fee once mined, and its job leaves); the upkeep of
///   claims already pooled or mined comes after it;
/// - all but the claims to make are background (the upkeep of claims made too): while they run, the chains' tips are looked at every
///   [`MOVE_CHECK`], and a move ends the round, the next starting at once. So background
///   work keeps a buyer whose payment was just mined or anchored waiting one job's work
///   at most, however long it is.
///
/// A job backing off, and an ended one still watched whose turn has not come, waits.
/// Each job works within its budget, the whole round within the round's; a job cut short
/// by its budget is worked again next round. The store's lock is held only to sort the
/// jobs, copy one out and put it back, so intake and cancels never wait on the chains. An
/// ended job is archived once the Bitcoin block that decided it is buried. Returns how
/// many jobs it worked on.
pub fn work_round(store: &Mutex<Store>, seq: &SeqChain, btc: &BtcChain, limits: &Limits) -> usize {
    round(store, seq, btc, limits).0
}

/// How often a round doing background work looks at the chains' tips ([`work_round`]).
pub const MOVE_CHECK: Duration = Duration::from_millis(200);

/// [`work_round`], and whether it ended its background work early because a chain moved
/// (the next round is then started at once).
fn round(store: &Mutex<Store>, seq: &SeqChain, btc: &BtcChain, limits: &Limits) -> (usize, bool) {
    let start = Instant::now();
    let round_end = start + limits.round_time;
    let now = now_secs();
    let cache = lock(store).blocks.clone();
    let mut blocks = cache.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(btc_tip) = blocks.sync(btc, start + limits.round_time / 2) else {
        return (0, false);
    };
    let Ok(seq_tip) = seq.height() else {
        return (0, false);
    };
    // The tips by their blocks' hashes, so a block replaced at the same height (a
    // Sequentia block rebuilt on Bitcoin's new branch) moves them; and the anchor of
    // Sequentia's tip, below which a candidate's proof can link.
    // These reads are skipped once half the round's time is gone (a node answering
    // slowly): a hash not read leaves the height alone to tell the tips apart, unread
    // floors bring nothing passed over back this round, and an unread anchor holds no
    // candidate back.
    let spare = || Instant::now() < start + limits.round_time / 2;
    let key = |h: &str| script_key(h.as_bytes());
    let seq_hash = spare()
        .then(|| seq.rpc.call("getblockhash", json!([seq_tip])).ok())
        .flatten()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("height {seq_tip}"));
    let btc_hash = blocks
        .hash(btc, btc_tip)
        .unwrap_or_else(|_| format!("height {btc_tip}"));
    let epoch = (key(&seq_hash), key(&btc_hash));
    let tip_anchor = spare()
        .then(|| seq.rpc.call("getblockheader", json!([seq_hash, true])).ok())
        .flatten()
        .and_then(|h| h.get("anchorheight").and_then(Value::as_u64))
        .map(|a| a as u32);
    let floors = spare()
        .then(|| seq.floors().ok())
        .flatten()
        .unwrap_or_default();
    let pooled: std::collections::HashSet<String> = seq
        .rpc
        .call("getrawmempool", json!([]))
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t.as_str().map(String::from))
        .collect();
    // (class, receiving script, rank, last worked, deadline, id). The rank is the job's
    // failures, except in class 4, where it is how far its claim clears the node's ask
    // now, the farthest first.
    let mut due: Vec<(u8, u64, u32, u64, u32, String)> = vec![];
    for j in lock(store).jobs.values_mut() {
        if j.retry_at > now || (j.state.ended() && j.watch_at > now) {
            continue;
        }
        let coins: Vec<Arc<[bitcoin::OutPoint]>> =
            j.payments.iter().map(|p| p.coins.clone()).collect();
        let open = j
            .payments
            .iter()
            .any(|p| p.real() && p.settled.is_none() && p.has_cancel());
        let moved = j.epoch != epoch;
        let btc_moved = j.epoch.1 != epoch.1;
        let claim_pooled = j
            .claims
            .iter()
            .any(|c| pooled.contains(&c.txid().to_string()));
        // A candidate not passed over that a Sequentia block anchors: a claim on it can be
        // completed now.
        let provable = !j.state.ended()
            && !matches!(j.state, State::Pooled | State::Mined)
            && j.failures == 0
            && j.scan.candidates.iter().any(|c| {
                j.scan.is_passed(c).is_none()
                    && tip_anchor.map(|a| c.at.height <= a).unwrap_or(true)
            });
        let advance = blocks.advance(&j.terms, &coins, open, &mut j.scan, btc_tip);
        let script = script_key(j.terms.receive_script_pubkey().as_bytes());
        // A block paying the job's script: the lightest proof a payment in it makes, read
        // from the cache, so a job never tried yet is ordered by what its claim can carry.
        let hit_proof = (advance == Advance::Hit)
            .then(|| {
                let h = j
                    .scan
                    .scanned
                    .as_ref()
                    .map(|(h, _)| h + 1)
                    .unwrap_or(j.terms.floor.max(1));
                blocks.lightest_proof(script, h)
            })
            .flatten();
        // Something new on the chains that a claim must be made for: a payment in a new
        // block, a candidate now anchored, the job's pooled claim gone.
        let to_claim = advance == Advance::Hit
            || (provable && moved)
            || (j.state == State::Pooled && !claim_pooled);
        // Something new for a claim already made: pooled by someone, a block that left it
        // out (to raise it), a block on top of it mined.
        let upkeep = (claim_pooled && j.state != State::Pooled)
            || (j.state == State::Pooled && !j.raised && moved)
            || (j.state == State::Mined && moved);
        let mut rank = j.failures;
        let class = if to_claim {
            if under_floor(j, &floors, hit_proof) {
                1
            } else {
                0
            }
        } else if upkeep {
            2
        } else if advance == Advance::Unread || j.worked == 0 || j.changed != j.seen {
            3
        } else if j.failures == 0 && j.scan.passed.iter().any(|p| p.retry_due(&floors)) {
            let margin = j
                .scan
                .passed
                .iter()
                .map(|p| p.margin(&floors))
                .fold(0.0, f64::max);
            rank = u32::MAX - (margin.clamp(0.0, 4_000.0) * 1_000_000.0) as u32;
            4
        } else if j.failures > 0 {
            5
        } else if btc_moved
            || ((moved || now >= j.worked_at + UNCHECKED_RECHECK_SECS)
                && j.payments
                    .iter()
                    .any(|p| !p.vouched || !p.pending.is_empty()))
        {
            6
        } else {
            continue;
        };
        due.push((
            class,
            script,
            rank,
            j.worked,
            j.terms.deadline,
            j.id.clone(),
        ));
    }
    let mut order: Vec<String> = vec![];
    for class in 0..7u8 {
        let mut groups: BTreeMap<u64, Vec<(u32, u64, u32, String)>> = BTreeMap::new();
        for (_, script, f, w, d, id) in due.iter().filter(|x| x.0 == class) {
            groups
                .entry(*script)
                .or_default()
                .push((*f, *w, *d, id.clone()));
        }
        let mut queues: Vec<std::collections::VecDeque<(u32, u64, u32, String)>> = groups
            .into_values()
            .map(|mut v| {
                v.sort();
                v.into()
            })
            .collect();
        // The script whose next job ranks first (failed least; in class 4, clears farthest),
        // then waited longest, takes the first turn.
        queues.sort_by_key(|q| q.front().map(|x| (x.0, x.1, x.2)));
        while queues.iter().any(|q| !q.is_empty()) {
            for q in queues.iter_mut() {
                if let Some((_, _, _, id)) = q.pop_front() {
                    order.push(id);
                }
            }
        }
    }
    // Classes 0 and 1 are the claims something new on the chains asks for; the rest,
    // the upkeep of claims made included, is background. While it runs, the chains' tips are looked at every
    // [`MOVE_CHECK`]: once either moves, the round ends, and the next one starts at
    // once, with whatever the move brings first. So background work (retries at new
    // floors, first tries, the per-block tick) never keeps a buyer whose payment was
    // just mined or anchored waiting longer than one job's work and one check.
    let urgent = due.iter().filter(|x| x.0 <= 1).count();
    let mut checked = Instant::now();
    let mut moved = false;
    let mut worked = 0;
    for (n, id) in order.into_iter().enumerate() {
        let t = Instant::now();
        if t >= round_end {
            break;
        }
        if n >= urgent && t >= checked + MOVE_CHECK {
            checked = t;
            let tip = |r: &crate::Rpc| {
                r.call("getbestblockhash", json!([]))
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
            };
            // A tip this round could not read by its hash is not compared: it would read
            // as moved at every look.
            let read = |h: &str| !h.starts_with("height ");
            if (read(&seq_hash) && tip(&seq.rpc).is_some_and(|h| h != seq_hash))
                || (read(&btc_hash) && tip(&btc.rpc).is_some_and(|h| h != btc_hash))
            {
                moved = true;
                break;
            }
        }
        let Some(mut job) = lock(store).jobs.get(&id).cloned() else {
            continue;
        };
        let until = (t + limits.job_time).min(round_end);
        let before = job.stored_json();
        let result = tick_with(seq, btc, &mut blocks, &floors, &mut job, limits, until);
        job.worked = WORK_ORDER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        job.worked_at = now_secs();
        // A job cut short by its budget has not seen these tips yet: it is worked again.
        if Instant::now() < until {
            job.epoch = epoch;
        }
        job.seen = job.changed;
        match result {
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
            // What intake merged in while it was worked is still to be seen.
            job.changed = cur.changed;
        }
        job.one_copy_each();
        if job.stored_json() != before {
            let _ = st.save(&job);
        }
        let done = job.state.ended() && job.buried;
        st.jobs.insert(id.clone(), job);
        if done {
            let _ = st.archive(&id);
        }
    }
    (worked, moved)
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
        let (_, moved) = round(&store, &seq, &btc, &limits);
        if pruned.elapsed() > Duration::from_secs(600) {
            let st = lock(&store);
            st.prune_archive(limits.archive_days);
            st.prune_payments();
            pruned = Instant::now();
        }
        if !moved {
            std::thread::sleep(interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::take_turns;
    use std::time::{Duration, Instant};

    /// F12: the cancel pass's turns are linear in the cancels, however many clients
    /// hand them over. 160,000 cancels from as many clients took 21.8 s with a queue found
    /// by a linear search; the order is unchanged: one from each client in the order it
    /// first appears, then the next round.
    #[test]
    fn turns_are_linear_in_the_clients() {
        let order = take_turns(vec![
            (0, false, 1, "a1", "a".to_string()),
            (0, false, 2, "a2", "a".to_string()),
            (0, false, 3, "b1", "b".to_string()),
            (0, false, 4, "c1", "c".to_string()),
            (0, false, 5, "a3", "a".to_string()),
            (1, false, 1, "d1", "d".to_string()),
            (1, false, 2, "a4", "a".to_string()),
        ]);
        assert_eq!(order, vec!["a1", "b1", "c1", "a2", "a3", "d1", "a4"]);
        let mut times = vec![];
        for n in [10_000u32, 40_000, 160_000] {
            let due: Vec<_> = (0..n)
                .map(|i| (0u8, false, u64::from(i), i, format!("client-{i}")))
                .collect();
            let t = Instant::now();
            let out = take_turns(due);
            let took = t.elapsed();
            assert_eq!(out.len(), n as usize);
            times.push((n, took));
        }
        eprintln!("take_turns, one cancel per client: {times:?}");
        assert!(
            times.iter().all(|(_, t)| *t < Duration::from_secs(2)),
            "{times:?}"
        );
    }
}
