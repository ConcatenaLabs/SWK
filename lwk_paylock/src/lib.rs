//! The swap of a Sequentia asset for an ordinary on-chain bitcoin payment, over
//! the chains: what [`lwk_wollet::btc::paylock`] cannot do without I/O.
//!
//! - [`Rpc`]: a JSON-RPC client for a Sequentia node and a Bitcoin daemon.
//! - [`SeqChain`] and [`BtcChain`]: the reads a swap needs from each chain.
//! - [`complete_claim`]: a signed claim completed with a proof of the buyer's
//!   payment, linked to the lowest anchor the Sequentia chain recorded at or
//!   above the payment.
//! - [`refused_for_weight`]: which of the node's refusals of a completed claim depend
//!   on the payment it proves, and which wait on the chain.
//! - [`activation`]: whether the node's next block is under both rules the lock needs.
//! - [`service`]: the completion service, which holds a buyer's signed claims and
//!   cancel and carries the swap to its end with nobody online.
//!
//! A node used here must watch Bitcoin (`-validateanchor=1`) and keep a
//! transaction index (`-txindex=1`): a node that takes anchors on trust can be
//! shown a claim on a payment that is in no Bitcoin block, and must not be used
//! to decide that a swap is complete.

pub mod http;
pub mod service;

use std::time::Duration;

use std::time::Instant;

use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{
    self, attach_proof, fee_pot_vout, hex_decode, hex_encode, payment_state, FeeSource,
    PayLockTerms, PaymentProof, PaymentState, ProofSource,
};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::{confidential, AssetId, OutPoint, Transaction, TxOut, Txid};
use serde_json::{json, Value};

/// An error of this crate: a message a product can show or log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<lwk_wollet::Error> for Error {
    fn from(e: lwk_wollet::Error) -> Self {
        Error(e.to_string())
    }
}

fn err(m: impl std::fmt::Display) -> Error {
    Error(m.to_string())
}

/// What a JSON-RPC call returned when it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The server answered with an error.
    Rpc {
        /// Its code.
        code: i32,
        /// Its message.
        message: String,
    },
    /// The server could not be reached or answered something unreadable.
    Transport(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Rpc { code, message } => write!(f, "{message} (code {code})"),
            RpcError::Transport(m) => write!(f, "{m}"),
        }
    }
}

impl From<RpcError> for Error {
    fn from(e: RpcError) -> Self {
        Error(e.to_string())
    }
}

/// A JSON-RPC client.
pub struct Rpc {
    client: jsonrpc::Client,
}

impl Rpc {
    /// A client of `url` (`http://host:port`, optionally with a `/wallet/<name>` path).
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, Error> {
        Self::with_timeout(url, user, pass, Duration::from_secs(60))
    }

    /// A client whose every call gives up after `timeout`.
    pub fn with_timeout(
        url: &str,
        user: &str,
        pass: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let t = jsonrpc::simple_http::SimpleHttpTransport::builder()
            .url(url)
            .map_err(|e| err(format!("RPC url: {e}")))?
            .auth(user, Some(pass))
            .timeout(timeout)
            .build();
        Ok(Rpc {
            client: jsonrpc::Client::with_transport(t),
        })
    }

    /// Calls `method` with positional `params`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let raw = serde_json::value::to_raw_value(&params)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        match self.client.call::<Value>(method, Some(&raw)) {
            Ok(v) => Ok(v),
            Err(jsonrpc::Error::Rpc(e)) => Err(RpcError::Rpc {
                code: e.code,
                message: e.message,
            }),
            Err(e) => Err(RpcError::Transport(e.to_string())),
        }
    }
}

fn rev32(h: &str) -> Result<[u8; 32], Error> {
    let mut b: [u8; 32] = hex_decode(h)?
        .try_into()
        .map_err(|_| err("a 32-byte hash was expected"))?;
    b.reverse();
    Ok(b)
}

fn header80(h: &str) -> Result<[u8; 80], Error> {
    hex_decode(h)?
        .try_into()
        .map_err(|_| err("an 80-byte header was expected"))
}

fn u32_of(v: &Value, k: &str) -> Result<u32, Error> {
    v.get(k)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| err(format!("the node's answer has no {k}")))
}

// ----------------------------------------------------------------- Sequentia

/// A Sequentia block's height and anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchored {
    /// The Sequentia height.
    pub height: u32,
    /// Its Bitcoin anchor height.
    pub anchor_height: u32,
    /// Its Bitcoin anchor hash, in internal byte order.
    pub anchor_hash: [u8; 32],
}

/// Where a Sequentia transaction stands on a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    /// Unknown to the node, neither pooled nor in the active chain.
    Unknown,
    /// In the mempool.
    Pooled,
    /// In a block of the active chain, at this height.
    Mined(u32),
}

/// The reads a swap needs from a Sequentia node.
pub struct SeqChain {
    /// The node's RPC.
    pub rpc: Rpc,
}

impl SeqChain {
    /// The active chain's height.
    pub fn height(&self) -> Result<u32, Error> {
        let v = self.rpc.call("getblockcount", json!([]))?;
        v.as_u64()
            .map(|n| n as u32)
            .ok_or_else(|| err("getblockcount"))
    }

    /// The block at `height` of the active chain, with its anchor.
    pub fn at(&self, height: u32) -> Result<Anchored, Error> {
        let hash = self.rpc.call("getblockhash", json!([height]))?;
        let h = self.rpc.call("getblockheader", json!([hash, true]))?;
        Ok(Anchored {
            height,
            anchor_height: u32_of(&h, "anchorheight")?,
            anchor_hash: rev32(
                h.get("anchorhash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("anchorhash"))?,
            )?,
        })
    }

    /// The tip's anchor height: the floor `F` of a lock built now.
    pub fn tip_anchor(&self) -> Result<u32, Error> {
        Ok(self.at(self.height()?)?.anchor_height)
    }

    /// The first block of the active chain anchored at Bitcoin height `h` or above:
    /// the block that records the lowest anchor a proof of a payment at `h` links to.
    /// Anchor heights never fall along a chain, so a binary search finds it.
    pub fn first_anchored_at(&self, h: u32) -> Result<Option<Anchored>, Error> {
        let tip = self.height()?;
        if self.at(tip)?.anchor_height < h {
            return Ok(None);
        }
        let (mut lo, mut hi) = (0u32, tip);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.at(mid)?.anchor_height >= h {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Ok(Some(self.at(lo)?))
    }

    /// The chain's genesis hash, which every signature commits to.
    pub fn genesis(&self) -> Result<lwk_wollet::elements::BlockHash, Error> {
        let v = self.rpc.call("getblockhash", json!([0]))?;
        v.as_str()
            .ok_or_else(|| err("getblockhash"))?
            .parse()
            .map_err(err)
    }

    /// A transaction as the node knows it, and where it stands.
    pub fn tx(&self, txid: &Txid) -> Result<Option<(Transaction, TxStatus)>, Error> {
        match self
            .rpc
            .call("getrawtransaction", json!([txid.to_string(), true]))
        {
            Ok(v) => {
                let hex = v
                    .get("hex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("hex"))?;
                let tx: Transaction = deserialize(&hex_decode(hex)?).map_err(err)?;
                let status = match v.get("blockhash").and_then(Value::as_str) {
                    None => TxStatus::Pooled,
                    Some(bh) => {
                        let h = self.rpc.call("getblockheader", json!([bh, true]))?;
                        let conf = h.get("confirmations").and_then(Value::as_i64).unwrap_or(-1);
                        if conf < 1 {
                            TxStatus::Unknown
                        } else {
                            TxStatus::Mined(u32_of(&h, "height")?)
                        }
                    }
                };
                Ok(Some((tx, status)))
            }
            Err(RpcError::Rpc { code: -5, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Where a transaction stands.
    pub fn status(&self, txid: &Txid) -> Result<TxStatus, Error> {
        Ok(self.tx(txid)?.map(|(_, s)| s).unwrap_or(TxStatus::Unknown))
    }

    /// `C`: the anchor height of the block that created a coin; `None` while unconfirmed.
    pub fn coin_anchor(&self, txid: &Txid) -> Result<Option<u32>, Error> {
        match self.status(txid)? {
            TxStatus::Mined(h) => Ok(Some(self.at(h)?.anchor_height)),
            _ => Ok(None),
        }
    }

    /// Whether an output is unspent on the active chain or by the mempool.
    pub fn unspent(&self, op: &OutPoint) -> Result<bool, Error> {
        let v = self
            .rpc
            .call("gettxout", json!([op.txid.to_string(), op.vout, true]))?;
        Ok(!v.is_null())
    }

    /// Whether an output is unspent in the active chain, whatever the mempool holds.
    pub fn unspent_in_chain(&self, op: &OutPoint) -> Result<bool, Error> {
        let v = self
            .rpc
            .call("gettxout", json!([op.txid.to_string(), op.vout, false]))?;
        Ok(!v.is_null())
    }

    /// An output exactly as its transaction carries it, while it is unspent (in the
    /// active chain and by the mempool).
    pub fn txout(&self, op: &OutPoint) -> Result<Option<TxOut>, Error> {
        if !self.unspent(op)? {
            return Ok(None);
        }
        Ok(self
            .tx(&op.txid)?
            .and_then(|(tx, _)| tx.output.get(op.vout as usize).cloned()))
    }

    /// Whether this node values a fee paid in `asset` (`getfeeassetinfo`'s `accepted`:
    /// listed and priced above zero). A node mirrors the price server block producers
    /// follow, so this is the buyer's best reading of what producers accept. Anything the
    /// node does not answer counts as not accepted.
    pub fn fee_asset_accepted(&self, asset: &AssetId) -> Result<bool, Error> {
        let hex = asset.to_string();
        let v = self.rpc.call("getfeeassetinfo", json!([hex]))?;
        Ok(v.get(&hex)
            .and_then(|e| e.get("accepted"))
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    /// The rate a node values `asset` at (`getfeeassetinfo`'s `rate`), when it accepts it.
    pub fn fee_asset_rate(&self, asset: &AssetId) -> Result<Option<u64>, Error> {
        let hex = asset.to_string();
        let v = self.rpc.call("getfeeassetinfo", json!([hex]))?;
        let e = v.get(&hex);
        if !e
            .and_then(|e| e.get("accepted"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(None);
        }
        Ok(e.and_then(|e| e.get("rate")).and_then(Value::as_u64))
    }

    /// The node's fee floors ([`Floors`]): its mempool's floor (`getmempoolinfo`) and the
    /// rate of every fee asset it accepts (`getfeeassetinfo`). Two calls, whatever the
    /// number of jobs.
    pub fn floors(&self) -> Result<Floors, Error> {
        let m = self.rpc.call("getmempoolinfo", json!([]))?;
        let per_k = |k: &str| {
            m.get(k)
                .and_then(Value::as_f64)
                .map(|b| (b * 1e8).round() as u64)
                .unwrap_or(0)
        };
        let rate = per_k("mempoolminfee").max(per_k("minrelaytxfee"));
        let v = self.rpc.call("getfeeassetinfo", json!([]))?;
        let mut rates = std::collections::HashMap::new();
        for (k, e) in v.as_object().into_iter().flatten() {
            if e.get("accepted").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            if let (Ok(a), Some(r)) = (k.parse::<AssetId>(), e.get("rate").and_then(Value::as_u64))
            {
                rates.insert(a, r);
            }
        }
        Ok(Floors {
            known: true,
            rate,
            rates,
        })
    }

    /// The highest height the node holds final (`getposfinality`).
    pub fn finalized_height(&self) -> Result<u32, Error> {
        let v = self.rpc.call("getposfinality", json!([]))?;
        Ok(v.get("finalized_height")
            .and_then(Value::as_i64)
            .unwrap_or(-1)
            .max(0) as u32)
    }

    /// Submits a transaction. A transaction the node already pools under the same id
    /// counts as submitted.
    pub fn send(&self, tx: &Transaction) -> Result<Txid, Error> {
        match self
            .rpc
            .call("sendrawtransaction", json!([hex_encode(&serialize(tx))]))
        {
            Ok(v) => v
                .as_str()
                .ok_or_else(|| err("sendrawtransaction"))?
                .parse()
                .map_err(err),
            Err(RpcError::Rpc { message, .. })
                if message.contains("txn-already-in-mempool")
                    || message.contains("txn-same-nonwitness-data-in-mempool")
                    || message.contains("txn-already-known") =>
            {
                Ok(tx.txid())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The node's `checklock`: the lock's block certified and final, Bitcoin's tip
    /// uncontested, and the lock's unburied ancestry free of anything a Bitcoin
    /// reorganization can make fail.
    pub fn checklock(&self, lock: &Txid) -> Result<(bool, Vec<String>), Error> {
        let v = self.rpc.call("checklock", json!([lock.to_string()]))?;
        let payable = v.get("payable").and_then(Value::as_bool).unwrap_or(false);
        let reasons = v
            .get("reasons")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok((payable, reasons))
    }
}

// ------------------------------------------------------------------- Bitcoin

/// The reads a swap needs from a Bitcoin daemon. They follow the daemon's best chain.
pub struct BtcChain {
    /// The daemon's RPC.
    pub rpc: Rpc,
}

/// A transaction found in a block of Bitcoin's best chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The block's height.
    pub height: u32,
    /// The block's hash, in display order.
    pub block: String,
    /// The transaction's id.
    pub txid: String,
}

/// How far a search for a payment has read Bitcoin's best chain, kept between ticks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PaymentScan {
    /// The last block read: its height and hash.
    pub scanned: Option<(u32, String)>,
    /// The payment's block, once found: the transaction the buyer named, or any
    /// transaction that spends the payment's coins and pays the receiving script at
    /// least the price (a fee bump of the payment, whatever its id).
    pub found: Option<Found>,
    /// The first confirmed spend of the payment's coins that does not pay the receiving
    /// script the price (the buyer's cancel, or any other): the payment can no longer be
    /// mined.
    pub cancel: Option<Found>,
    /// For [`BtcChain::scan_lock`]: the first transaction paying the receiving script at
    /// least the price mined after `D`, which opens nothing.
    pub late: Option<Found>,
    /// For [`BtcChain::scan_lock`]: the first transaction mined in the lock's heights that
    /// pays the receiving script at least the price but that no proof can carry (see
    /// [`provable`]). It opens nothing, so it is passed over: shown, never a candidate.
    pub unprovable: Option<Found>,
    /// For [`BtcChain::scan_lock`]: every transaction mined in the lock's heights that pays
    /// the receiving script at least the price in a form a proof can carry. Each may be the
    /// swap's payment; none is until the node accepts a claim proving it (`found`).
    pub candidates: Vec<Candidate>,
    /// Candidates whose completed claim the node refused at every tier for the claim's
    /// own weight, keyed by transaction and block. A reorganization clears them, and each
    /// is tried again once what refused it can have changed (see [`Passed`]).
    pub passed: Vec<Passed>,
}

/// A transaction that pays the receiving script at least the price, mined in the lock's
/// heights, in a form a proof can carry: a candidate for the swap's payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Where it is.
    pub at: Found,
    /// Whether it spends the coins of a payment the service holds: one handed over.
    pub held: bool,
    /// The lightest proof of it, in bytes: its block's merkle depth and no linking header.
    pub min_proof: usize,
}

/// A candidate passed over: the node refused the claim proving it, at every tier the
/// buyer signed, for the claim's weight (its fee rate below the node's floor, or its size
/// above the standard limit), or no tier pays its fee in an asset the node accepts. A claim
/// proving a payment that needs as heavy a proof or heavier is refused alike, so every
/// candidate whose lightest proof is at least `proof` bytes is passed over with it.
///
/// It is tried again only once what refused it can have changed ([`Passed::retry_due`]):
/// the node's floor for a fee asset fell below the rate it refused, or an asset no tier
/// could pay in became accepted. A block arriving changes neither, so it never brings a
/// candidate back; a reorganization of Bitcoin below the scan's place clears every one.
#[derive(Debug, Clone, PartialEq)]
pub struct Passed {
    /// The candidate.
    pub at: Found,
    /// The size of the proof the node refused, in bytes.
    pub proof: usize,
    /// The node's refusal.
    pub why: String,
    /// Bitcoin's tip when it was passed over.
    pub tip: u32,
    /// What brings it back.
    pub retry: Retry,
}

/// What brings a candidate passed over back ([`Passed`]).
#[derive(Debug, Clone, PartialEq)]
pub enum Retry {
    /// Refused for the claim's fee rate in the assets of `refused`, and not tried in the
    /// assets of `untried` (the node did not accept them): tried again once the node's
    /// floor in one of the first falls below the rate it refused, or one of the second is
    /// accepted.
    Floor {
        /// The best refusal in each asset tried.
        refused: Vec<Refusal>,
        /// The claims' fee assets the node did not accept.
        untried: Vec<AssetId>,
    },
    /// Nothing but a reorganization changes it: the claim is above the standard size at
    /// every tier, or no proof can carry the payment.
    Never,
    /// Recorded without saying what refused it: tried again at the next round.
    Unknown,
}

/// The node's refusal of a claim for its fee rate, in one fee asset: the claim's fee was
/// worth `paid` and the node asked `need` (`min relay fee not met, paid < need`, in the
/// reference unit), when the node's floor in that asset was `floor` ([`Floors::floor`]).
/// The fee's worth follows the asset's rate and the need follows the floor, so the claim
/// is accepted once the floor in the asset is at most `floor × paid / need`.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    /// The fee asset.
    pub asset: AssetId,
    /// What the fee was worth to the node (0 when the refusal gave no figures).
    pub paid: u64,
    /// What the node asked (0 when the refusal gave no figures).
    pub need: u64,
    /// The node's floor in the asset when it refused; `None` when it could not be read.
    pub floor: Option<f64>,
}

impl Refusal {
    /// Whether the claim this refusal was for may be accepted at `floors`.
    pub fn may_clear(&self, floors: &Floors) -> bool {
        let (Some(then), Some(now)) = (self.floor, floors.floor(&self.asset)) else {
            // The floor unread then or now: what changed cannot be told, so it is tried.
            return floors.known;
        };
        if self.need == 0 {
            // A refusal without figures (`mempool full`): back once the floor falls.
            return now < then;
        }
        now * self.need as f64 <= then * self.paid as f64
    }
}

impl Passed {
    /// Whether it is tried again at `floors`: what refused it can have changed.
    pub fn retry_due(&self, floors: &Floors) -> bool {
        match &self.retry {
            Retry::Never => false,
            Retry::Unknown => true,
            Retry::Floor { refused, untried } => {
                refused.iter().any(|r| r.may_clear(floors))
                    || untried.iter().any(|a| floors.accepts(a))
            }
        }
    }
}

/// The node's fee floors as one read of its mempool and fee whitelist gives them: the
/// rate a claim's fee must reach, in the reference unit, and the rate each accepted fee
/// asset is valued at. Read once per round of work and shared by every job, so whether a
/// claim passed over may now land costs a lookup, not a call to the node.
#[derive(Debug, Clone, Default)]
pub struct Floors {
    /// Whether the node answered.
    pub known: bool,
    /// The fee rate the node's mempool takes, in reference atoms per 1,000 vbytes: the
    /// higher of its relay floor and its mempool's minimum.
    pub rate: u64,
    /// The rate of each fee asset the node accepts (`getfeeassetinfo`'s `rate`).
    pub rates: std::collections::HashMap<AssetId, u64>,
}

impl Floors {
    /// The node's floor in `asset`: its fee rate floor over the asset's rate, which grows
    /// with the atoms of `asset` a claim must pay per vbyte. `None` when the node does not
    /// accept the asset or was not read.
    pub fn floor(&self, asset: &AssetId) -> Option<f64> {
        if !self.known {
            return None;
        }
        let r = *self.rates.get(asset)?;
        (r > 0).then(|| self.rate as f64 / r as f64)
    }

    /// Whether the node accepts fees in `asset`.
    pub fn accepts(&self, asset: &AssetId) -> bool {
        self.rates.get(asset).map(|r| *r > 0).unwrap_or(false)
    }
}

/// Non-held candidates a scan keeps, the lightest: more are heavier than all of these,
/// and a claim proving one would be refused wherever all of these are.
pub const MAX_CANDIDATES: usize = 32;

impl PaymentScan {
    /// Whether a candidate is passed over: itself, or by a lighter proof the node refused.
    pub fn is_passed(&self, c: &Candidate) -> Option<&Passed> {
        self.passed.iter().find(|p| {
            (p.at.txid == c.at.txid && p.at.block == c.at.block) || c.min_proof >= p.proof
        })
    }

    /// Whether a candidate is not passed over: a claim on it may land.
    pub fn live(&self) -> bool {
        self.candidates.iter().any(|c| self.is_passed(c).is_none())
    }

    /// The candidates in the order they are tried: the payment a claim already proves;
    /// then those the service holds (handed over), then the rest, each by the lightest
    /// proof they make, then by height.
    pub fn ordered(&self) -> Vec<Candidate> {
        let mut v = self.candidates.clone();
        let proven = |c: &Candidate| {
            self.found
                .as_ref()
                .map(|f| f.txid == c.at.txid && f.block == c.at.block)
        };
        v.sort_by_key(|c| (proven(c) != Some(true), !c.held, c.min_proof, c.at.height));
        v
    }

    /// Takes a candidate in, keeping every held one and the [`MAX_CANDIDATES`] lightest
    /// others.
    fn add_candidate(&mut self, c: Candidate) {
        if self
            .candidates
            .iter()
            .any(|k| k.at.txid == c.at.txid && k.at.block == c.at.block)
        {
            return;
        }
        self.candidates.push(c);
        let others = self.candidates.iter().filter(|c| !c.held).count();
        if others > MAX_CANDIDATES {
            if let Some(i) = self
                .candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| !c.held)
                .max_by_key(|(_, c)| (c.min_proof, c.at.height))
                .map(|(i, _)| i)
            {
                self.candidates.remove(i);
            }
        }
    }
}

/// How a payment the completion service holds was settled on Bitcoin: the first confirmed
/// spend of its coins, and whether that spend pays the terms (the payment itself, or a
/// replacement of it) or not (its cancel, or any other spend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    /// Where the spend is.
    pub at: Found,
    /// Whether it pays the receiving script at least the price.
    pub paid: bool,
}

/// How many blocks above `D` a search reads, to tell a late payment from none.
pub const LATE_SCAN: u32 = 6;

/// How many Bitcoin blocks past `D` a search goes on reading for a spend of the payment's
/// coins while none is found (and a cancel is still sent): a day. Past it, a payment still
/// unmined is taken to be gone.
pub const CANCEL_KEEP_BLOCKS: u32 = 144;

/// Whether a proof can carry `tx` as a payment (specification section 4.1, check 4, and
/// the record's limit in section 3): it is not a coinbase, and without its witness it is
/// neither 64 bytes long nor above [`paylock::MAX_PAYMENT_BYTES`]. Only such a transaction
/// opens a lock, so only such a transaction is ever taken as a swap's payment: a miner can
/// mine one that is not, and it must neither stand in for the buyer's payment nor withhold
/// the buyer's cancel.
pub fn provable(tx: &bitcoin::Transaction) -> bool {
    let n = tx.base_size();
    !tx.is_coinbase() && n != 64 && n <= paylock::MAX_PAYMENT_BYTES
}

/// Whether `tx` pays `spk` at least `price_sat` in a form a proof can carry: what a claim
/// accepts.
fn pays_provably(tx: &bitcoin::Transaction, spk: &bitcoin::ScriptBuf, price_sat: u64) -> bool {
    tx.output
        .iter()
        .any(|o| o.script_pubkey == *spk && o.value.to_sat() >= price_sat)
        && provable(tx)
}

/// What a transaction is to a swap whose payment is `payment` and spends `coins`.
fn classify(
    tx: &bitcoin::Transaction,
    txid: &str,
    payment: &str,
    coins: &[bitcoin::OutPoint],
    terms: &PayLockTerms,
    spk: &bitcoin::ScriptBuf,
) -> Option<bool> {
    let named = txid == payment;
    let spends = tx.input.iter().any(|i| coins.contains(&i.previous_output));
    if !named && !spends {
        return None;
    }
    let pays = pays_provably(tx, spk, terms.price_sat);
    // The named payment is the payment, whatever it pays: a claim on it is then refused
    // for paying too little (or for no proof carrying it), never mistaken for a cancel.
    Some(named || pays)
}

/// A key for a receiving script in a [`BlockCache`].
pub fn script_key(spk: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    spk.hash(&mut h);
    h.finish()
}

/// A key for a coin in a [`BlockCache`].
pub fn coin_key(c: &bitcoin::OutPoint) -> u64 {
    use bitcoin::hashes::Hash as _;
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    c.txid.to_byte_array().hash(&mut h);
    c.vout.hash(&mut h);
    h.finish()
}

/// What a [`BlockCache`] keeps of a block: its hash, its number of transactions, and keys
/// of every script its transactions pay (each with the size without witness of the
/// smallest transaction paying it) and every coin they spend (the coinbase's left out).
#[derive(Debug, Clone)]
struct Summary {
    hash: String,
    txs: usize,
    pays: std::collections::HashMap<u64, usize>,
    spends: std::collections::HashSet<u64>,
}

/// Bitcoin's best chain as the completion service reads it: each block is read from the
/// daemon once and kept as keys of the scripts it pays and the coins it spends, so the
/// work of looking for a lock's payment is a lookup per block, whatever the number of
/// locks looked for. A block is read whole again only when it holds a key a lock looks
/// for, and the few last read whole are kept. [`BlockCache::sync`] drops what a
/// reorganization replaced.
#[derive(Debug, Default)]
pub struct BlockCache {
    blocks: std::collections::BTreeMap<u32, Summary>,
    whole: std::collections::VecDeque<(String, std::sync::Arc<bitcoin::Block>)>,
    /// Blocks fetched from the daemon, in all.
    pub fetched: u64,
}

/// Bitcoin blocks below the tip a [`BlockCache`] keeps: two weeks, more than a lock's
/// heights and the watch after them span.
pub const CACHE_BLOCKS: u32 = 2 * paylock::MAX_DEADLINE_AHEAD + CANCEL_KEEP_BLOCKS;

/// Where [`BlockCache::advance`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advance {
    /// As far as the scan reads: nothing in the blocks passed concerns the lock.
    Done,
    /// At a block that pays the lock's script or spends one of its coins, or a block the
    /// scan read is no longer the one the cache holds: the job has work.
    Hit,
    /// At a block the cache has not read.
    Unread,
}

impl BlockCache {
    /// Brings the cache in line with the daemon's best chain: what is above its tip, or
    /// replaced by a reorganization, is dropped, and so is what is too deep to matter.
    /// Then reads every block above what it holds, up to the tip. Returns the tip.
    pub fn sync(&mut self, btc: &BtcChain, until: Instant) -> Result<u32, Error> {
        let tip = btc.tip()?;
        self.blocks
            .retain(|h, _| *h <= tip && *h + CACHE_BLOCKS >= tip);
        while let Some((&h, s)) = self.blocks.iter().next_back() {
            if btc.block_hash(h)? == s.hash {
                break;
            }
            self.blocks.remove(&h);
        }
        if let Some(&top) = self.blocks.keys().next_back() {
            for h in top + 1..=tip {
                if Instant::now() >= until {
                    break;
                }
                self.summary(btc, h)?;
            }
        }
        Ok(tip)
    }

    // The entry API would hold the map while the block is read and kept whole.
    #[allow(clippy::map_entry)]
    fn summary(&mut self, btc: &BtcChain, h: u32) -> Result<&Summary, Error> {
        if !self.blocks.contains_key(&h) {
            let hash = btc.block_hash(h)?;
            let block = btc.block(&hash)?;
            self.fetched += 1;
            let mut pays = std::collections::HashMap::new();
            let mut spends = std::collections::HashSet::new();
            for tx in block.txdata.iter().skip(1) {
                let n = tx.base_size();
                for o in &tx.output {
                    let m = pays
                        .entry(script_key(o.script_pubkey.as_bytes()))
                        .or_insert(n);
                    *m = (*m).min(n);
                }
                for i in &tx.input {
                    spends.insert(coin_key(&i.previous_output));
                }
            }
            let txs = block.txdata.len();
            self.keep_whole(hash.clone(), std::sync::Arc::new(block));
            self.blocks.insert(
                h,
                Summary {
                    hash,
                    txs,
                    pays,
                    spends,
                },
            );
        }
        Ok(self.blocks.get(&h).expect("inserted"))
    }

    fn keep_whole(&mut self, hash: String, b: std::sync::Arc<bitcoin::Block>) {
        self.whole.retain(|(k, _)| *k != hash);
        self.whole.push_back((hash, b));
        while self.whole.len() > 8 {
            self.whole.pop_front();
        }
    }

    /// The lightest proof a payment to `script` in the block at `h` would make, in bytes,
    /// as far as the cache can tell without reading the block: its smallest transaction
    /// paying the script (any amount), at the block's merkle depth, with no linking header.
    /// `None` when the cache does not hold the block or nothing in it pays the script.
    pub fn lightest_proof(&self, script: u64, h: u32) -> Option<usize> {
        let s = self.blocks.get(&h)?;
        let n = *s.pays.get(&script)?;
        Some(paylock::proof_bytes(n, paylock::merkle_depth(s.txs), 0))
    }

    /// The hash of the best chain's block at `h`, as the cache holds it.
    pub fn hash(&mut self, btc: &BtcChain, h: u32) -> Result<String, Error> {
        match self.blocks.get(&h) {
            Some(s) => Ok(s.hash.clone()),
            None => btc.block_hash(h),
        }
    }

    /// The block at `h`, its hash, and whether it pays `script` or spends any of `coins`.
    fn hits(
        &mut self,
        btc: &BtcChain,
        h: u32,
        script: u64,
        coins: &[u64],
    ) -> Result<(String, bool), Error> {
        let s = self.summary(btc, h)?;
        let hit = s.pays.contains_key(&script) || coins.iter().any(|c| s.spends.contains(c));
        Ok((s.hash.clone(), hit))
    }

    fn block(
        &mut self,
        btc: &BtcChain,
        hash: &str,
    ) -> Result<std::sync::Arc<bitcoin::Block>, Error> {
        if let Some((_, b)) = self.whole.iter().find(|(k, _)| k == hash) {
            return Ok(b.clone());
        }
        let b = std::sync::Arc::new(btc.block(hash)?);
        self.fetched += 1;
        self.keep_whole(hash.to_string(), b.clone());
        Ok(b)
    }

    /// Moves a scan on through the blocks the cache holds, reading nothing from the
    /// daemon, while none concerns the lock: none pays `terms`' receiving script and none
    /// spends a coin of `coins`. What [`BtcChain::scan_lock`] would do over those blocks is
    /// only to move on, so a lock nothing happens to costs a lookup per block. It stops
    /// where the scan has work to do.
    pub fn advance(
        &self,
        terms: &PayLockTerms,
        coins: &[Vec<bitcoin::OutPoint>],
        open: bool,
        scan: &mut PaymentScan,
        tip: u32,
    ) -> Advance {
        if let Some((h, hash)) = &scan.scanned {
            match self.blocks.get(h) {
                Some(s) if s.hash == *hash => {}
                Some(_) => return Advance::Hit,
                None if *h > tip => return Advance::Hit,
                None => return Advance::Unread,
            }
        }
        let script = script_key(terms.receive_script_pubkey().as_bytes());
        let keys: Vec<u64> = coins.iter().flatten().map(coin_key).collect();
        let last = scan_last(terms, open, tip);
        let mut h = scan
            .scanned
            .as_ref()
            .map(|(h, _)| h + 1)
            .unwrap_or(terms.floor.max(1));
        while h <= last {
            let Some(s) = self.blocks.get(&h) else {
                return Advance::Unread;
            };
            if s.pays.contains_key(&script) || keys.iter().any(|c| s.spends.contains(c)) {
                return Advance::Hit;
            }
            scan.scanned = Some((h, s.hash.clone()));
            h += 1;
        }
        Advance::Done
    }
}

/// The last block a lock's scan reads: [`LATE_SCAN`] past `D`, or [`CANCEL_KEEP_BLOCKS`]
/// while `open`, and not above the tip.
fn scan_last(terms: &PayLockTerms, open: bool, tip: u32) -> u32 {
    tip.min(
        terms
            .deadline
            .saturating_add(if open { CANCEL_KEEP_BLOCKS } else { LATE_SCAN }),
    )
}

impl BtcChain {
    /// Bitcoin's tip height.
    pub fn tip(&self) -> Result<u32, Error> {
        let v = self.rpc.call("getblockcount", json!([]))?;
        v.as_u64()
            .map(|n| n as u32)
            .ok_or_else(|| err("getblockcount"))
    }

    fn block_hash(&self, h: u32) -> Result<String, Error> {
        let v = self.rpc.call("getblockhash", json!([h]))?;
        Ok(v.as_str().ok_or_else(|| err("getblockhash"))?.to_string())
    }

    /// A block of the best chain, whole.
    fn block(&self, hash: &str) -> Result<bitcoin::Block, Error> {
        let v = self.rpc.call("getblock", json!([hash, 0]))?;
        bitcoin::consensus::encode::deserialize(&hex_decode(
            v.as_str().ok_or_else(|| err("getblock"))?,
        )?)
        .map_err(|e| err(format!("Bitcoin block {hash} does not parse: {e}")))
    }

    /// Moves `scan` on through the best chain's blocks the payment `txid` can be in, at
    /// most `max_blocks` blocks and until `until`, looking for that transaction alone
    /// (see [`BtcChain::scan_for`]).
    pub fn scan_payment(
        &self,
        txid: &str,
        terms: &PayLockTerms,
        scan: &mut PaymentScan,
        max_blocks: u32,
        until: Instant,
    ) -> Result<bool, Error> {
        self.scan_for(txid, &[], terms, scan, max_blocks, until)
    }

    /// Moves `scan` on through Bitcoin's best chain, at most `max_blocks` blocks and until
    /// `until`, and says whether it reached as far as it reads. The payment is the
    /// transaction named `payment`, or any that spends one of `coins` (the payment's
    /// inputs) and pays the receiving script at least the price: a fee bump of the
    /// payment counts, whatever its id. A spend of `coins` that does not pay so is the
    /// cancel. Nothing is inferred from a coin that is merely missing.
    ///
    /// It reads from `F` to a few blocks past `D`; while `coins` are known and neither
    /// is found, on to Bitcoin's tip, up to [`CANCEL_KEEP_BLOCKS`] past `D`, since only a
    /// confirmed spend settles that the payment can no longer be mined. A scan keeps its
    /// place, so each block is read once; a reorganization below its place (the block it
    /// stopped at, or a found block, is no longer in the best chain) starts it again from
    /// the floor.
    pub fn scan_for(
        &self,
        payment: &str,
        coins: &[bitcoin::OutPoint],
        terms: &PayLockTerms,
        scan: &mut PaymentScan,
        max_blocks: u32,
        until: Instant,
    ) -> Result<bool, Error> {
        let tip = self.tip()?;
        if let Some(f) = &scan.found {
            if f.height <= tip && self.block_hash(f.height)? == f.block {
                return Ok(true);
            }
            scan.found = None;
            scan.scanned = None;
        }
        if let Some(c) = &scan.cancel {
            if c.height > tip || self.block_hash(c.height)? != c.block {
                scan.cancel = None;
                scan.scanned = None;
            }
        }
        if let Some((h, hash)) = &scan.scanned {
            if *h > tip || self.block_hash(*h)? != *hash {
                scan.scanned = None;
                scan.cancel = None;
            }
        }
        let first = terms.floor.max(1);
        let mut last = tip.min(terms.deadline.saturating_add(LATE_SCAN));
        if !coins.is_empty() && scan.cancel.is_none() {
            last = tip.min(terms.deadline.saturating_add(CANCEL_KEEP_BLOCKS));
        }
        let spk = terms.receive_script_pubkey();
        let mut h = scan.scanned.as_ref().map(|(h, _)| h + 1).unwrap_or(first);
        let mut read = 0;
        while h <= last {
            if read >= max_blocks || Instant::now() >= until {
                return Ok(false);
            }
            let hash = self.block_hash(h)?;
            let block = self.block(&hash)?;
            read += 1;
            scan.scanned = Some((h, hash.clone()));
            for tx in block.txdata.iter().skip(1) {
                let txid = tx.compute_txid().to_string();
                match classify(tx, &txid, payment, coins, terms, &spk) {
                    Some(true) => {
                        scan.found = Some(Found {
                            height: h,
                            block: hash,
                            txid,
                        });
                        return Ok(true);
                    }
                    Some(false) if scan.cancel.is_none() => {
                        scan.cancel = Some(Found {
                            height: h,
                            block: hash.clone(),
                            txid,
                        });
                    }
                    _ => {}
                }
            }
            h += 1;
        }
        Ok(true)
    }

    /// Moves `scan` on through Bitcoin's best chain for a lock, at most `max_blocks`
    /// blocks and until `until`, and says whether it reached as far as it reads.
    ///
    /// The payment is known by Bitcoin alone: any transaction mined above `F` and at or
    /// below `D` that pays the terms' receiving script at least the price in a form a
    /// proof can carry, whoever made it and whatever coins it spends, since that is what
    /// the claim accepts. The scan gathers every one as a candidate (`scan.candidates`,
    /// noting those that spend coins of `coins`, the payments held); it takes none. Which
    /// one is the payment is the one whose completed claim the node accepts
    /// (`scan.found`, which the completion service sets). A paying transaction no proof
    /// can carry ([`provable`]) opens nothing and is no candidate (`scan.unprovable` shows
    /// the first). A provable paying transaction mined after `D` is noted (`scan.late`).
    /// For each entry of `coins` (the coins of a payment held, to which its cancels
    /// belong), `settled` records the first confirmed spend of any of them, and whether it
    /// pays so. Nothing is inferred from a coin that is merely missing.
    ///
    /// It reads from `F` to [`LATE_SCAN`] blocks past `D`, and on, up to
    /// [`CANCEL_KEEP_BLOCKS`] past `D`, while `open` (a payment held with cancels is not
    /// settled yet). A scan keeps its place, so each block is read once; a reorganization
    /// below its place, or of a block it found something in, starts it again from the
    /// floor and drops every candidate and everything passed over.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_lock(
        &self,
        blocks: &mut BlockCache,
        terms: &PayLockTerms,
        coins: &[Vec<bitcoin::OutPoint>],
        settled: &mut [Option<Settled>],
        open: bool,
        scan: &mut PaymentScan,
        max_blocks: u32,
        until: Instant,
    ) -> Result<bool, Error> {
        let tip = self.tip()?;
        let mut gone = false;
        let mut kept = |f: &Option<Found>| -> Result<bool, Error> {
            Ok(match f {
                Some(f) => f.height <= tip && blocks.hash(self, f.height)? == f.block,
                None => true,
            })
        };
        if !kept(&scan.found)? {
            scan.found = None;
            gone = true;
        }
        if !kept(&scan.late)? {
            scan.late = None;
            gone = true;
        }
        if !kept(&scan.unprovable)? {
            scan.unprovable = None;
            gone = true;
        }
        for s in settled.iter_mut() {
            if !kept(&s.as_ref().map(|s| s.at.clone()))? {
                *s = None;
                gone = true;
            }
        }
        if let Some((h, hash)) = &scan.scanned {
            if *h > tip || blocks.hash(self, *h)? != *hash {
                gone = true;
            }
        }
        if gone {
            // Read again from the floor: what was found below the change is found again,
            // and nothing passed over on the old branch stays passed over.
            scan.scanned = None;
            scan.found = None;
            scan.late = None;
            scan.unprovable = None;
            scan.candidates.clear();
            scan.passed.clear();
            settled.iter_mut().for_each(|s| *s = None);
        }
        let first = terms.floor.max(1);
        let last = scan_last(terms, open, tip);
        let spk = terms.receive_script_pubkey();
        let script = script_key(spk.as_bytes());
        let keys: Vec<u64> = coins.iter().flatten().map(coin_key).collect();
        let mut h = scan.scanned.as_ref().map(|(h, _)| h + 1).unwrap_or(first);
        let mut read = 0;
        while h <= last {
            if Instant::now() >= until {
                return Ok(false);
            }
            // Each block is read once for every lock (the cache); one that neither pays
            // this lock's script nor spends its coins holds nothing for it.
            let (hash, hit) = blocks.hits(self, h, script, &keys)?;
            if !hit {
                scan.scanned = Some((h, hash));
                h += 1;
                continue;
            }
            if read >= max_blocks {
                return Ok(false);
            }
            let block = blocks.block(self, &hash)?;
            read += 1;
            scan.scanned = Some((h, hash.clone()));
            let depth = paylock::merkle_depth(block.txdata.len());
            for tx in block.txdata.iter().skip(1) {
                let pays_price = tx
                    .output
                    .iter()
                    .any(|o| o.script_pubkey == spk && o.value.to_sat() >= terms.price_sat);
                let txid = tx.compute_txid().to_string();
                let usable = pays_price && provable(tx);
                let here = || Found {
                    height: h,
                    block: hash.clone(),
                    txid: txid.clone(),
                };
                let mut held = false;
                for (c, s) in coins.iter().zip(settled.iter_mut()) {
                    if tx.input.iter().any(|i| c.contains(&i.previous_output)) {
                        held = true;
                        if s.is_none() {
                            *s = Some(Settled {
                                at: here(),
                                paid: usable,
                            });
                        }
                    }
                }
                if !pays_price || h <= terms.floor {
                    continue;
                }
                if !usable {
                    if h <= terms.deadline && scan.unprovable.is_none() {
                        scan.unprovable = Some(here());
                    }
                    continue;
                }
                if h > terms.deadline {
                    if scan.late.is_none() {
                        scan.late = Some(here());
                    }
                } else {
                    scan.add_candidate(Candidate {
                        at: here(),
                        held,
                        min_proof: paylock::proof_bytes(tx.base_size(), depth, 0),
                    });
                }
            }
            h += 1;
        }
        Ok(true)
    }

    /// Whether the best chain holds block `block` (display order) at `height`.
    pub fn holds(&self, height: u32, block: &str) -> Result<bool, Error> {
        Ok(height <= self.tip()? && self.block_hash(height)? == block)
    }

    /// The first transaction of the best chain's blocks from `lo` to `hi` with an output
    /// paying `script_pubkey` at least `min_sat`, in a form a proof can carry (not a
    /// coinbase, and without its witness neither 64 bytes nor above
    /// [`paylock::MAX_PAYMENT_BYTES`]; see [`provable`]): what a seller looks for before it
    /// refunds, since such a payment in the lock's heights belongs to a buyer whose claim
    /// may still come. One no proof can carry opens nothing, so it is passed over.
    pub fn paid_to(
        &self,
        script_pubkey: &[u8],
        min_sat: u64,
        lo: u32,
        hi: u32,
    ) -> Result<Option<(String, u32)>, Error> {
        let want = hex_encode(script_pubkey);
        for h in lo.max(1)..=hi {
            let b = self.rpc.call("getblock", json!([self.block_hash(h)?, 2]))?;
            for tx in b
                .get("tx")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .skip(1)
            {
                // Without its witness: weight = 3 × that size + the whole size.
                let n = |k: &str| tx.get(k).and_then(Value::as_u64).unwrap_or(0);
                let base = n("weight").saturating_sub(n("size")) / 3;
                if base == 64 || base as usize > paylock::MAX_PAYMENT_BYTES {
                    continue;
                }
                let pays = tx
                    .get("vout")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|o| {
                        o.pointer("/scriptPubKey/hex").and_then(Value::as_str)
                            == Some(want.as_str())
                            && o.get("value")
                                .and_then(Value::as_f64)
                                .map(|v| (v * 1e8).round() as u64 >= min_sat)
                                .unwrap_or(false)
                    });
                if pays {
                    let id = tx
                        .get("txid")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    return Ok(Some((id, h)));
                }
            }
        }
        Ok(None)
    }

    /// The transaction in the daemon's mempool that spends `coin`, if any
    /// (`gettxspendingprevout`). A daemon without the call answers none.
    pub fn mempool_spender(&self, coin: &bitcoin::OutPoint) -> Result<Option<String>, Error> {
        match self.rpc.call(
            "gettxspendingprevout",
            json!([[{"txid": coin.txid.to_string(), "vout": coin.vout}]]),
        ) {
            Ok(v) => Ok(v
                .get(0)
                .and_then(|e| e.get("spendingtxid"))
                .and_then(Value::as_str)
                .map(String::from)),
            Err(RpcError::Rpc { code: -32601, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether the daemon's mempool holds the transaction (unconfirmed).
    pub fn pooled(&self, txid: &str) -> Result<bool, Error> {
        match self.rpc.call("getmempoolentry", json!([txid])) {
            Ok(_) => Ok(true),
            Err(RpcError::Rpc { code: -5, .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// A raw transaction of the block `block`.
    pub fn raw_tx(&self, txid: &str, block: &str) -> Result<Vec<u8>, Error> {
        let v = self
            .rpc
            .call("getrawtransaction", json!([txid, false, block]))?;
        hex_decode(v.as_str().ok_or_else(|| err("getrawtransaction"))?).map_err(Into::into)
    }

    /// Everything a proof of `txid` in `found` is built from, with the headers that
    /// link its block to the recorded anchor `to`. Refuses when the daemon's best
    /// chain does not reach that anchor: the proof would not link.
    pub fn proof_source(
        &self,
        txid: &str,
        found: &Found,
        to: &Anchored,
    ) -> Result<ProofSource, Error> {
        if to.anchor_height < found.height {
            return Err(err(
                "the anchor Sequentia recorded is below the payment's block; waiting for the two chains to agree",
            ));
        }
        let links = (to.anchor_height - found.height) as usize;
        if links > paylock::MAX_LINKS {
            return Err(err(format!(
                "the lowest anchor Sequentia recorded at or above the payment is {links} Bitcoin blocks above it, more than a proof links ({}): no proof of it links on this chain unless Bitcoin reorganizes",
                paylock::MAX_LINKS
            )));
        }
        let b = self.rpc.call("getblock", json!([found.block, 1]))?;
        let ids = b
            .get("tx")
            .and_then(Value::as_array)
            .ok_or_else(|| err("getblock"))?;
        let txids = ids
            .iter()
            .map(|t| rev32(t.as_str().unwrap_or_default()))
            .collect::<Result<Vec<_>, _>>()?;
        let cb = ids
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| err("an empty block"))?;
        let hdr = |hash: &str| -> Result<[u8; 80], Error> {
            let v = self.rpc.call("getblockheader", json!([hash, false]))?;
            header80(v.as_str().ok_or_else(|| err("getblockheader"))?)
        };
        let header = hdr(&found.block)?;
        let mut links = vec![];
        for x in found.height + 1..=to.anchor_height {
            links.push(hdr(&self.block_hash(x)?)?);
        }
        let end = links
            .last()
            .map(paylock::header_hash)
            .unwrap_or_else(|| paylock::header_hash(&header));
        if to.anchor_height < found.height || end != to.anchor_hash {
            return Err(err(
                "the Bitcoin daemon's best chain does not lead to the anchor Sequentia recorded; waiting for the two to agree",
            ));
        }
        Ok(ProofSource {
            height: found.height,
            header,
            txids,
            coinbase: self.raw_tx(cb, &found.block)?,
            payment: self.raw_tx(txid, &found.block)?,
            links,
        })
    }

    /// Submits a raw transaction.
    pub fn send_raw(&self, hex: &str) -> Result<String, RpcError> {
        self.rpc
            .call("sendrawtransaction", json!([hex]))
            .map(|v| v.as_str().unwrap_or_default().to_string())
    }

    /// A transaction of the daemon's mempool, raw; `None` when the mempool does not hold it.
    pub fn mempool_tx(&self, txid: &str) -> Result<Option<String>, Error> {
        match self.rpc.call("getrawtransaction", json!([txid, false])) {
            Ok(v) => Ok(v.as_str().map(String::from)),
            Err(RpcError::Rpc { code: -5, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The fee in satoshis of a transaction the daemon's mempool holds; `None` when it
    /// does not hold it.
    pub fn mempool_fee(&self, txid: &str) -> Result<Option<u64>, Error> {
        match self.rpc.call("getmempoolentry", json!([txid])) {
            Ok(v) => Ok(v
                .pointer("/fees/base")
                .and_then(Value::as_f64)
                .map(|b| (b * 1e8).round() as u64)),
            Err(RpcError::Rpc { code: -5, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// What the daemon would do with a transaction now, without relaying it
    /// (`testmempoolaccept`): it checks every signature and, against a transaction it
    /// pools that spends the same coins, the replacement rules.
    pub fn test_accept(&self, hex: &str) -> Result<Accept, Error> {
        let v = self.rpc.call("testmempoolaccept", json!([[hex]]))?;
        let r = v.get(0).ok_or_else(|| err("testmempoolaccept"))?;
        if r.get("allowed").and_then(Value::as_bool) == Some(true) {
            let fee = r
                .pointer("/fees/base")
                .and_then(Value::as_f64)
                .map(|b| (b * 1e8).round() as u64)
                .unwrap_or(0);
            return Ok(Accept::Allowed { fee });
        }
        let reason = r
            .get("reject-reason")
            .and_then(Value::as_str)
            .unwrap_or("refused")
            .to_string();
        Ok(Accept::Refused(reason))
    }
}

/// [`BtcChain::test_accept`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accept {
    /// The daemon would take it, at this fee in satoshis.
    Allowed {
        /// The fee.
        fee: u64,
    },
    /// The daemon would refuse it, for this reason.
    Refused(String),
}

impl Accept {
    /// Whether a refusal is the transaction's own signatures or scripts failing: no later
    /// state of the chain makes it valid.
    pub fn scripts_fail(reason: &str) -> bool {
        reason.contains("script-verify-flag")
            || reason.contains("bad-witness")
            || reason.contains("scriptsig")
            || reason.contains("witness-program")
    }

    /// Whether a refusal says the daemon does not have the coins it spends: never seen
    /// (a parent not broadcast yet), or already spent. Which of the two it cannot say, so
    /// it never settles anything.
    pub fn coins_missing(reason: &str) -> bool {
        reason.contains("missing-inputs") || reason.contains("missingorspent")
    }
}

// ------------------------------------------------------ completing a claim

/// What [`complete_claim`] found.
#[derive(Debug, Clone)]
pub enum Completion {
    /// The claim with a proof linked to a recorded anchor, ready to submit.
    Ready {
        /// The completed claim (same transaction id as the signed one).
        tx: Transaction,
        /// The payment's Bitcoin height.
        height: u32,
        /// The payment's output that pays the seller.
        vout: u32,
        /// The proof's size in bytes.
        proof_bytes: usize,
    },
    /// Nothing to submit yet, and why.
    Waiting(String),
    /// The payment can never open this lock: no proof can carry it (another payment still
    /// may).
    Never(String),
}

/// Where a payment stands for a claim, from a scan of Bitcoin's best chain.
pub fn payment_position(
    terms: &PayLockTerms,
    scan: &PaymentScan,
    complete: bool,
    btc_tip: u32,
) -> Position {
    match payment_state(terms, scan.found.as_ref().map(|f| f.height)) {
        PaymentState::NotMined if complete && btc_tip > terms.deadline => Position::Never(format!(
            "no payment was mined by the deadline (Bitcoin block {})",
            terms.deadline
        )),
        PaymentState::NotMined => {
            Position::Waiting("the payment is not mined on Bitcoin yet".into())
        }
        PaymentState::BelowFloor(h) => Position::Never(format!(
            "the payment is mined at {h}, not above the lock's floor {}",
            terms.floor
        )),
        PaymentState::Late(h) => Position::Never(format!(
            "the payment is mined at Bitcoin block {h}, after the deadline {}",
            terms.deadline
        )),
        PaymentState::InWindow(_) => Position::InWindow,
    }
}

/// [`payment_position`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    /// Mined at a height the claim accepts.
    InWindow,
    /// Not mined yet, or not read that far yet.
    Waiting(String),
    /// It can never open the lock.
    Never(String),
}

/// Completes a signed claim with a proof of the payment `payment_txid`, when it is
/// mined in Bitcoin's best chain within the lock's heights and a Sequentia block
/// has anchored at its height or above. Asks no key. It reads every block the payment
/// can be in, from the floor to a few blocks past the deadline; the completion service
/// keeps its place instead ([`BtcChain::scan_payment`]).
pub fn complete_claim(
    seq: &SeqChain,
    btc: &BtcChain,
    terms: &PayLockTerms,
    lock: &OutPoint,
    claim: &Transaction,
    payment_txid: &str,
) -> Result<Completion, Error> {
    let mut scan = PaymentScan::default();
    let window = terms.deadline - terms.floor + LATE_SCAN + 1;
    let far = Instant::now() + Duration::from_secs(3600);
    let complete = btc.scan_payment(payment_txid, terms, &mut scan, window, far)?;
    match payment_position(terms, &scan, complete, btc.tip()?) {
        Position::Waiting(w) => Ok(Completion::Waiting(w)),
        Position::Never(w) => Ok(Completion::Never(w)),
        Position::InWindow => prove_claim(
            seq,
            btc,
            terms,
            lock,
            claim,
            scan.found.as_ref().expect("in window"),
        ),
    }
}

/// Completes a signed claim with a proof of the payment found in `found` (the transaction
/// it names), linked to the lowest anchor the Sequentia chain recorded at or above it.
pub fn prove_claim(
    seq: &SeqChain,
    btc: &BtcChain,
    terms: &PayLockTerms,
    lock: &OutPoint,
    claim: &Transaction,
    found: &Found,
) -> Result<Completion, Error> {
    let payment_txid = found.txid.as_str();
    let Some(anchor) = seq.first_anchored_at(found.height)? else {
        return Ok(Completion::Waiting(format!(
            "no Sequentia block has anchored at Bitcoin block {} yet",
            found.height
        )));
    };
    let Some(coin_anchor) = seq.coin_anchor(&lock.txid)? else {
        return Ok(Completion::Waiting(
            "the lock is not in the active chain".into(),
        ));
    };
    let src = match btc.proof_source(payment_txid, found, &anchor) {
        Ok(s) => s,
        Err(e) => return Ok(Completion::Waiting(e.0)),
    };
    let vout = *paylock::paying_outputs(terms, &src.payment)?
        .first()
        .ok_or_else(|| err("the payment pays the seller's receiving script less than the price"))?;
    let payment: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&src.payment)
        .map_err(|e| err(format!("the payment does not parse: {e}")))?;
    let proof = match PaymentProof::build(&src, coin_anchor) {
        Ok(p) => p,
        // Only what the payment is decides that no proof carries it (`provable`). Any
        // other failure is the chain's: the headers read did not hold together (the
        // daemon switched branches while they were read, say), which the next read may
        // mend. It never passes the payment over.
        Err(e) if !provable(&payment) => {
            return Ok(Completion::Never(format!(
                "no proof can carry the payment {payment_txid}: {e}"
            )))
        }
        Err(e) => {
            return Ok(Completion::Waiting(format!(
                "the proof of the payment {payment_txid} did not hold together ({e}): the Bitcoin daemon's chain moved while it was read; reading it again"
            )))
        }
    };
    let proof_bytes = proof.encode().len();
    Ok(Completion::Ready {
        tx: attach_proof(claim, &proof, vout)?,
        height: found.height,
        vout,
        proof_bytes,
    })
}

/// Whether the node's refusal of a completed claim is for the claim's weight, the one
/// thing about the claim that depends on which payment it proves (everything else is
/// signed). A claim whose proof is heavier pays a lower fee rate for the same fee, and may
/// pass the standard size: `min relay fee not met`, `mempool min fee not met` and
/// `mempool full` (its rate below what the node keeps), and `tx-size` (its weight above the
/// standard limit). A lighter proof (another payment) or a higher tier may still be
/// accepted, so the payment is passed over, not the swap.
///
/// Every other refusal does not depend on the payment, and a claim proving any other
/// payment meets it too, so it is waited on, never passed over: the lock spent or not
/// confirmed yet (`bad-txns-inputs-missingorspent`, `bad-btcpay-coin-missing`,
/// `btcpay-coin-unconfirmed`, `txn-lost-conflict`), the proof's anchor not on the node's
/// branch (`btcpay-not-in-anchor-chain`) or its coin anchor moved (`bad-btcpay-coin-anchor`)
/// by a reorganization, the mempool holding a conflicting spend or tier
/// (`txn-mempool-conflict`, `insufficient fee`, `bip125-replacement-disallowed`,
/// `btcpay-replacement-conflicts`, `btcpay-floor-replaces-proof`, `too many potential
/// replacements`, `replacement-adds-unconfirmed`, `too-long-mempool-chain`), a lock time
/// (`non-final`, `non-BIP68-final`), the fee's asset (`bad-txns-no-fee`,
/// `fee-value-out-of-range`), and what the claim's signed parts carry (scripts,
/// outputs, sigops, a record no opcode reads). The proof's own checks (`bad-btcpay-encoding`,
/// `-tx-64-bytes`, `-tx-coinbase`, `-index`, `-merkle`, `-links`, `-tx-encoding`,
/// `-duplicate`) cannot fail for a candidate: [`provable`] and the proof's own check
/// before sending rule them out.
pub fn refused_for_weight(message: &str) -> bool {
    [
        "min relay fee not met",
        "mempool min fee not met",
        "mempool full",
        "tx-size",
    ]
    .iter()
    .any(|m| message.contains(m))
        && !message.contains("tx-size-small")
}

/// The figures of a refusal for the claim's fee rate: what the fee was worth and what the
/// node asked (`min relay fee not met, 5000 < 8356`), and whether it was the mempool's
/// floor (`mempool min fee not met`) rather than the relay floor. `None` for any other
/// refusal, `mempool full` included (it gives no figures).
pub fn refusal_figures(message: &str) -> Option<(u64, u64)> {
    let i = ["min relay fee not met", "mempool min fee not met"]
        .iter()
        .find_map(|m| message.find(m).map(|i| i + m.len()))?;
    let rest = message[i..].trim_start_matches([',', ' ', ':']);
    let mut it = rest.split(" < ");
    let paid = it.next()?.trim().parse().ok()?;
    let need = it
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((paid, need))
}

/// The payment a completed claim proves, from the record on its first input: its Bitcoin
/// height, its block's hash and its transaction id (both in display order). `None` for a
/// claim without a payment proof.
pub fn proven_payment(claim: &Transaction) -> Option<Found> {
    let r = claim.input.first()?.witness.pegin_witness.first()?;
    if r.len() < 128 || r[0] != paylock::RECORD_PAYMENT {
        return None;
    }
    let height = u32::from_le_bytes(r[1..5].try_into().ok()?);
    let header: [u8; 80] = r[9..89].try_into().ok()?;
    let depth = r[121] as usize;
    let at = 126 + 64 * depth;
    let links = u16::from_le_bytes(r.get(at..at + 2)?.try_into().ok()?) as usize;
    let payment = r.get(at + 2 + 80 * links..)?;
    let display = |mut h: [u8; 32]| {
        h.reverse();
        hex_encode(&h)
    };
    use bitcoin::hashes::{sha256d, Hash};
    let txid = sha256d::Hash::hash(payment).to_byte_array();
    Some(Found {
        height,
        block: display(paylock::header_hash(&header)),
        txid: display(txid),
    })
}

// ---------------------------------------------------------------- the claim's fee

/// One way a claim (or a refund) can pay its fee, and whether the node accepts its asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeRoute {
    /// Where the fee would come from.
    pub source: FeeSource,
    /// The fee's asset, when the source is there to read.
    pub asset: Option<AssetId>,
    /// Usable: the source is there and the node accepts its asset.
    pub usable: bool,
    /// Why not, in words, when it is not.
    pub why_not: Option<String>,
}

impl FeeRoute {
    /// The route as JSON.
    pub fn to_json(&self) -> Value {
        let source = match &self.source {
            FeeSource::Locked => "locked asset".to_string(),
            FeeSource::Pot(v) => format!("fee pot (output {v})"),
            FeeSource::Coin { outpoint, .. } => {
                format!("coin {}:{}", outpoint.txid, outpoint.vout)
            }
        };
        json!({
            "source": source,
            "asset": self.asset.map(|a| a.to_string()),
            "usable": self.usable,
            "why_not": self.why_not,
        })
    }
}

/// Every way the claim on `lock_tx`'s output `lock_vout` can pay its fee: the locked
/// asset, the terms' fee pot, and each coin in `coins` (the buyer's own). A route is
/// usable only when its source is there, unspent and in the clear, and the node accepts
/// its asset; anything it cannot read counts against the route. A buyer pays only when
/// one route is usable (section 8.2).
pub fn fee_routes(
    seq: &SeqChain,
    terms: &PayLockTerms,
    lock_tx: &Transaction,
    lock_vout: u32,
    coins: &[OutPoint],
) -> Vec<FeeRoute> {
    let mut out = vec![];
    let accepted = |a: &AssetId| -> (bool, Option<String>) {
        match seq.fee_asset_accepted(a) {
            Ok(true) => (true, None),
            Ok(false) => (
                false,
                Some(format!("block producers do not accept a fee in asset {a}")),
            ),
            Err(e) => (
                false,
                Some(format!(
                    "the node did not say whether it accepts a fee in asset {a}: {e}"
                )),
            ),
        }
    };
    let (ok, why) = accepted(&terms.asset);
    out.push(FeeRoute {
        source: FeeSource::Locked,
        asset: Some(terms.asset),
        usable: ok,
        why_not: why,
    });
    if let Some(pot) = terms.fee_pot {
        match fee_pot_vout(terms, lock_tx, lock_vout) {
            Some(v) => {
                let (ok, why) = accepted(&pot.asset);
                out.push(FeeRoute {
                    source: FeeSource::Pot(v),
                    asset: Some(pot.asset),
                    usable: ok,
                    why_not: why,
                });
            }
            None => out.push(FeeRoute {
                source: FeeSource::Pot(u32::MAX),
                asset: Some(pot.asset),
                usable: false,
                why_not: Some("the lock transaction carries no fee pot".into()),
            }),
        }
    }
    for op in coins {
        let txout = match seq.txout(op) {
            Ok(Some(o)) => o,
            Ok(None) => {
                out.push(FeeRoute {
                    source: FeeSource::Coin {
                        outpoint: *op,
                        txout: TxOut::default(),
                    },
                    asset: None,
                    usable: false,
                    why_not: Some(format!(
                        "the fee coin {}:{} is spent or unknown",
                        op.txid, op.vout
                    )),
                });
                continue;
            }
            Err(e) => {
                out.push(FeeRoute {
                    source: FeeSource::Coin {
                        outpoint: *op,
                        txout: TxOut::default(),
                    },
                    asset: None,
                    usable: false,
                    why_not: Some(format!("the fee coin could not be read: {e}")),
                });
                continue;
            }
        };
        let route = match (txout.asset, txout.value) {
            (confidential::Asset::Explicit(a), confidential::Value::Explicit(_)) => {
                let (ok, why) = accepted(&a);
                FeeRoute {
                    source: FeeSource::Coin {
                        outpoint: *op,
                        txout,
                    },
                    asset: Some(a),
                    usable: ok,
                    why_not: why,
                }
            }
            _ => FeeRoute {
                source: FeeSource::Coin {
                    outpoint: *op,
                    txout,
                },
                asset: None,
                usable: false,
                why_not: Some(
                    "the fee coin is confidential; a fee coin must be in the clear".into(),
                ),
            },
        };
        out.push(route);
    }
    out
}

// -------------------------------------------------------------- activation

/// Whether the node puts its next block under the rules the payment lock needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// `btc_payment`: the payment-proof opcodes and records.
    pub btc_payment: bool,
    /// `lost_blocks`: the rule that carries a lost block's transactions first.
    pub lost_blocks: bool,
    /// The lost-block window `W` the node reports, when it reports one.
    pub window: Option<u32>,
}

impl Activation {
    /// Build the payment lock only when both rules apply to the next block;
    /// otherwise the product keeps the swap it had.
    pub fn payment_lock(&self) -> bool {
        self.btc_payment && self.lost_blocks
    }
}

/// Reads from the node's `getdeploymentinfo` whether `btc_payment` and
/// `lost_blocks` are active for its next block. An entry the node does not
/// report is not active: a node that predates the report, or a chain that has
/// no height for the rule, keeps today's swap. Nothing is guessed.
pub fn activation(seq: &SeqChain) -> Result<Activation, Error> {
    let v = seq.rpc.call("getdeploymentinfo", json!([]))?;
    Ok(activation_from(&v))
}

/// [`activation`] over a `getdeploymentinfo` answer.
pub fn activation_from(v: &Value) -> Activation {
    let d = v.get("deployments");
    let active = |k: &str| {
        d.and_then(|d| d.get(k))
            .and_then(|e| e.get("active"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    Activation {
        btc_payment: active("btc_payment"),
        lost_blocks: active("lost_blocks"),
        window: d
            .and_then(|d| d.get("lost_blocks"))
            .and_then(|e| e.get("window"))
            .and_then(Value::as_u64)
            .map(|w| w as u32),
    }
}

/// The node's `checklock` verdict as reasons a lock is not payable: its own reasons, and
/// one more when it answers not payable without saying why. Its `payable` decides, not
/// only the reasons it gives.
pub fn checklock_reasons(payable: bool, reasons: Vec<String>) -> Vec<String> {
    if !payable && reasons.is_empty() {
        return vec!["the node's checklock does not call the lock payable".into()];
    }
    reasons
}

/// Parses `txid:vout`.
pub fn outpoint(s: &str) -> Result<OutPoint, Error> {
    let (t, v) = s
        .split_once(':')
        .ok_or_else(|| err("an outpoint is txid:vout"))?;
    Ok(OutPoint::new(
        t.parse().map_err(err)?,
        v.parse().map_err(err)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_reads_the_report_and_guesses_nothing() {
        let a = activation_from(&json!({"deployments": {
            "btc_payment": {"type": "buried", "active": true, "height": 0},
            "lost_blocks": {"type": "buried", "active": true, "height": 0, "window": 6}}}));
        assert!(a.payment_lock());
        assert_eq!(a.window, Some(6));
        // A node that reports neither, or only one, keeps today's swap.
        assert!(
            !activation_from(&json!({"deployments": {"taproot": {"active": true}}})).payment_lock()
        );
        assert!(!activation_from(&json!({"deployments": {
            "btc_payment": {"active": true}}}))
        .payment_lock());
        assert!(!activation_from(&json!({"deployments": {
            "btc_payment": {"active": false}, "lost_blocks": {"active": true}}}))
        .payment_lock());
        assert!(!activation_from(&json!({})).payment_lock());
    }

    #[test]
    fn checklock_payable_decides() {
        assert!(checklock_reasons(true, vec![]).is_empty());
        assert_eq!(checklock_reasons(false, vec![]).len(), 1);
        let r = vec!["the lock's block is not final yet".to_string()];
        assert_eq!(checklock_reasons(false, r.clone()), r);
    }

    #[test]
    fn outpoints_parse() {
        assert!(outpoint("00").is_err());
        let o = outpoint(&format!("{}:3", "11".repeat(32))).unwrap();
        assert_eq!(o.vout, 3);
    }
}
