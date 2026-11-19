//! The swap of a Sequentia asset for an ordinary on-chain bitcoin payment, over
//! the chains: what [`lwk_wollet::btc::paylock`] cannot do without I/O.
//!
//! - [`Rpc`]: a JSON-RPC client for a Sequentia node and a Bitcoin daemon.
//! - [`SeqChain`] and [`BtcChain`]: the reads a swap needs from each chain.
//! - [`complete_claim`]: a signed claim completed with a proof of the buyer's
//!   payment, linked to the lowest anchor the Sequentia chain recorded at or
//!   above the payment.
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    let pays = tx
        .output
        .iter()
        .any(|o| o.script_pubkey == *spk && o.value.to_sat() >= terms.price_sat);
    // The named payment is the payment, whatever it pays: a claim on it is then refused
    // for paying too little, never mistaken for a cancel.
    Some(named || pays)
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
    /// The payment is known by Bitcoin alone: the first transaction mined above `F` and at
    /// or below `D` that pays the terms' receiving script at least the price
    /// (`scan.found`), whoever made it and whatever coins it spends, since that is what the
    /// claim's script accepts. A paying transaction mined after `D` is noted
    /// (`scan.late`). For each entry of `coins` (the coins of a payment held, to which its
    /// cancels belong), `settled` records the first confirmed spend of any of them, and
    /// whether it pays. Nothing is inferred from a coin that is merely missing.
    ///
    /// It reads from `F` to [`LATE_SCAN`] blocks past `D`, and on, up to
    /// [`CANCEL_KEEP_BLOCKS`] past `D`, while `open` (a payment held with cancels is not
    /// settled yet) and no payment is found. A scan keeps its place, so each block is read
    /// once; a reorganization below its place, or of a block it found something in,
    /// starts it again from the floor.
    #[allow(clippy::too_many_arguments)]
    pub fn scan_lock(
        &self,
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
        let kept = |f: &Option<Found>| -> Result<bool, Error> {
            Ok(match f {
                Some(f) => f.height <= tip && self.block_hash(f.height)? == f.block,
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
        for s in settled.iter_mut() {
            if !kept(&s.as_ref().map(|s| s.at.clone()))? {
                *s = None;
                gone = true;
            }
        }
        if let Some((h, hash)) = &scan.scanned {
            if *h > tip || self.block_hash(*h)? != *hash {
                gone = true;
            }
        }
        if gone {
            // Read again from the floor: what was found below the change is found again.
            scan.scanned = None;
            scan.found = None;
            scan.late = None;
            settled.iter_mut().for_each(|s| *s = None);
        }
        if scan.found.is_some() {
            return Ok(true);
        }
        let first = terms.floor.max(1);
        let last = tip.min(terms.deadline.saturating_add(if open {
            CANCEL_KEEP_BLOCKS
        } else {
            LATE_SCAN
        }));
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
                let pays = tx
                    .output
                    .iter()
                    .any(|o| o.script_pubkey == spk && o.value.to_sat() >= terms.price_sat);
                let here = || Found {
                    height: h,
                    block: hash.clone(),
                    txid: tx.compute_txid().to_string(),
                };
                for (c, s) in coins.iter().zip(settled.iter_mut()) {
                    if s.is_none() && tx.input.iter().any(|i| c.contains(&i.previous_output)) {
                        *s = Some(Settled {
                            at: here(),
                            paid: pays,
                        });
                    }
                }
                if pays && h > terms.floor {
                    if h <= terms.deadline {
                        scan.found = Some(here());
                        return Ok(true);
                    }
                    if scan.late.is_none() {
                        scan.late = Some(here());
                    }
                }
            }
            h += 1;
        }
        Ok(true)
    }

    /// The first transaction of the best chain's blocks from `lo` to `hi` with an output
    /// paying `script_pubkey` at least `min_sat`: what a seller looks for before it
    /// refunds, since a payment in the lock's heights belongs to a buyer whose claim
    /// may still come.
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
            for tx in b.get("tx").and_then(Value::as_array).into_iter().flatten() {
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
    /// The payment can never open this lock.
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
    let proof = PaymentProof::build(&src, coin_anchor)?;
    let proof_bytes = proof.encode().len();
    Ok(Completion::Ready {
        tx: attach_proof(claim, &proof, vout)?,
        height: found.height,
        vout,
        proof_bytes,
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
