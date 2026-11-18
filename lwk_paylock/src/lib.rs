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

pub mod service;

use std::time::Duration;

use lwk_wollet::btc::paylock::{
    self, attach_proof, hex_decode, hex_encode, payment_state, PayLockTerms, PaymentProof,
    PaymentState, ProofSource,
};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::{OutPoint, Transaction, Txid};
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
        let t = jsonrpc::simple_http::SimpleHttpTransport::builder()
            .url(url)
            .map_err(|e| err(format!("RPC url: {e}")))?
            .auth(user, Some(pass))
            .timeout(Duration::from_secs(60))
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

    /// Looks for a transaction in the best chain's blocks from `hi` down to `lo`.
    pub fn find(&self, txid: &str, lo: u32, hi: u32) -> Result<Option<Found>, Error> {
        let mut h = hi;
        while h >= lo && h > 0 {
            let hash = self.block_hash(h)?;
            let b = self.rpc.call("getblock", json!([hash, 1]))?;
            if b.get("tx")
                .and_then(Value::as_array)
                .map(|a| a.iter().any(|t| t.as_str() == Some(txid)))
                .unwrap_or(false)
            {
                return Ok(Some(Found {
                    height: h,
                    block: hash,
                }));
            }
            h -= 1;
        }
        Ok(None)
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

/// Completes a signed claim with a proof of the payment `payment_txid`, when it is
/// mined in Bitcoin's best chain within the lock's heights and a Sequentia block
/// has anchored at its height or above. Asks no key.
pub fn complete_claim(
    seq: &SeqChain,
    btc: &BtcChain,
    terms: &PayLockTerms,
    lock: &OutPoint,
    claim: &Transaction,
    payment_txid: &str,
) -> Result<Completion, Error> {
    let tip = btc.tip()?;
    let found = btc.find(payment_txid, terms.floor.max(1), tip)?;
    match payment_state(terms, found.as_ref().map(|f| f.height)) {
        PaymentState::NotMined => {
            return Ok(Completion::Waiting(
                "the payment is not mined on Bitcoin yet".into(),
            ))
        }
        PaymentState::BelowFloor(h) => {
            return Ok(Completion::Never(format!(
                "the payment is mined at {h}, not above the lock's floor {}",
                terms.floor
            )))
        }
        PaymentState::Late(h) => {
            return Ok(Completion::Never(format!(
                "the payment is mined at Bitcoin block {h}, after the deadline {}",
                terms.deadline
            )))
        }
        PaymentState::InWindow(_) => {}
    }
    let found = found.expect("in window");
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
    let src = match btc.proof_source(payment_txid, &found, &anchor) {
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
    fn outpoints_parse() {
        assert!(outpoint("00").is_err());
        let o = outpoint(&format!("{}:3", "11".repeat(32))).unwrap();
        assert_eq!(o.vout, 3);
    }
}
