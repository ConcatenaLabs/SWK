//! The payment lock: a Sequentia asset sold for an ordinary on-chain bitcoin
//! payment, with no hash lock and no Bitcoin script.
//!
//! The seller locks the asset in a taproot output with an unspendable internal
//! key and two leaves (the node's `doc/sequentia/bitcoin-payment-proof.md`,
//! section 8.1):
//!
//! ```text
//! claim:   <buyer> OP_CHECKSIGVERIFY            # witness: <i> <signature>
//!          OP_INSPECTBTCPAYMENT OP_DROP         # i h
//!          OP_DUP <F> OP_GREATERTHAN OP_VERIFY
//!          <D> OP_LESSTHANOREQUAL OP_VERIFY     # i
//!          OP_0 OP_INSPECTBTCTX                 # value program version
//!          <version> OP_EQUALVERIFY <program> OP_EQUALVERIFY
//!          <price, 8 bytes LE> OP_GREATERTHANOREQUAL64
//! refund:  <R> OP_CHECKANCHORHEIGHTVERIFY OP_DROP <seller> OP_CHECKSIG
//! ```
//!
//! The buyer pays the seller's receiving script `wsh(and_v(v:pk(K),older(1)))`
//! at least the price, mined at a Bitcoin height above `F` and at most `D`. The
//! claim, signed by the buyer before it pays, is completed by anyone once a
//! Sequentia block anchors at or above the payment: the proof of the payment
//! goes in the input's peg-in witness slot, which no signature covers, so
//! completing a claim, or proving it again after a Bitcoin reorganization,
//! never changes its transaction id and needs no key.
//!
//! This module holds no I/O: the scripts, the checks a buyer runs on a lock,
//! the claim, the refund, the proof record and the buyer's cancel of its own
//! payment. The `lwk_paylock` crate reads the chains and runs the completion
//! service over it.

use crate::bitcoin;
use crate::bitcoin::consensus::encode::{
    deserialize as btc_deserialize, serialize as btc_serialize,
};
use crate::bitcoin::hashes::{sha256d, Hash as _};
use crate::elements::hashes::sha256;
use crate::elements::opcodes::all::*;
use crate::elements::opcodes::All as Op;
use crate::elements::script::Builder;
use crate::elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use crate::elements::sighash::{Prevouts, SchnorrSighashType, ScriptPath, SighashCache};
use crate::elements::taproot::{LeafVersion, TaprootBuilder};
use crate::elements::{
    confidential, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness,
};
use crate::error::Error;

/// `OP_INSPECTBTCPAYMENT`: pushes the proven payment's Bitcoin height, then the coin anchor.
pub const OP_INSPECTBTCPAYMENT: u8 = 0xe5;
/// `OP_INSPECTBTCTX`: reads a field of the proven payment.
pub const OP_INSPECTBTCTX: u8 = 0xe6;
/// `OP_CHECKANCHORHEIGHTVERIFY`: fails unless the input carries this anchor floor.
pub const OP_CHECKANCHORHEIGHTVERIFY: u8 = 0xe7;
/// `OP_INSPECTBTCTX` selector for an output of the payment.
pub const FIELD_OUTPUT: i64 = 0;
/// The depth at which an anchor floor is judged: the block this many below the spending block.
pub const FLOOR_DEPTH: u32 = 60;
/// The most linking headers a proof may carry.
pub const MAX_LINKS: usize = 2016;
/// The deepest merkle branch a proof may carry.
pub const MAX_DEPTH: usize = 24;
/// The largest payment a proof may carry (Bitcoin's standardness ceiling).
pub const MAX_PAYMENT_BYTES: usize = 100_000;
/// Record type of a payment proof.
pub const RECORD_PAYMENT: u8 = 0x01;
/// Record type of an anchor floor.
pub const RECORD_FLOOR: u8 = 0x02;
/// A claim signals replacement, so a higher fee tier of the same claim replaces a lower one.
pub const CLAIM_SEQUENCE: u32 = 0xffff_fffd;
/// Bitcoin blocks the default deadline leaves for the payment to confirm.
pub const DEFAULT_DEADLINE_MARGIN: u32 = 6;
/// The buyer cancels a still-unconfirmed payment once Bitcoin's tip is this many blocks below `D`.
pub const CANCEL_BEFORE_DEADLINE: u32 = 2;
/// The highest height a script number holds: a height in the leaves above it is a
/// five-byte number, which the comparison opcodes refuse, so no claim or refund opens.
pub const MAX_HEIGHT: u32 = 0x7fff_ffff;
/// How far above Bitcoin's tip a deadline may be, and how many Bitcoin blocks a lock may
/// span from its floor to its deadline: a week. A buyer calls nothing payable beyond it,
/// and a completion service carries nothing beyond it.
pub const MAX_DEADLINE_AHEAD: u32 = 1008;
/// The fee rate a replacement pays for its own size above the fee it replaces (Bitcoin
/// Core's incremental relay fee, BIP125 rule 4), in satoshis per virtual byte.
pub const INCREMENTAL_RELAY_SAT_VB: u64 = 1;
/// The chain's block limit in virtual bytes, which the top fee tier is sized against.
pub const BLOCK_VSIZE: u64 = 89_999;
/// Sequentia blocks the top tier must hold the claim for (section 8.5: the 59 after the
/// first block anchored at the payment, less the one the going rate is tried in).
pub const TOP_TIER_BLOCKS: u64 = 58;

/// The unspendable internal key of the lock (the BIP341 "H" point).
pub const NUMS_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

fn gen(m: impl std::fmt::Display) -> Error {
    Error::Generic(m.to_string())
}

fn nums() -> Result<XOnlyPublicKey, Error> {
    let b = hex_decode(NUMS_HEX)?;
    XOnlyPublicKey::from_slice(&b).map_err(gen)
}

/// Lower-case hex of bytes.
pub fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Bytes of a hex string.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(gen("odd-length hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| gen("invalid hex")))
        .collect()
}

/// The minimal script-number encoding of `n`, as a witness item.
pub fn script_num(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = vec![];
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        out.push(if neg { 0x80 } else { 0 });
    } else if neg {
        *out.last_mut().expect("non-empty") |= 0x80;
    }
    out
}

// ------------------------------------------------------------------ terms

/// Everything both sides agree before the seller locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayLockTerms {
    /// The asset sold.
    pub asset: AssetId,
    /// Its atoms in the lock.
    pub atoms: u64,
    /// The price, in satoshis, that the payment must pay at least.
    pub price_sat: u64,
    /// The buyer's key, which signs the claim.
    pub buyer: XOnlyPublicKey,
    /// The seller's key, which signs the refund.
    pub seller: XOnlyPublicKey,
    /// The seller's Bitcoin receiving key (compressed), fresh for every lock.
    pub receive_key: bitcoin::PublicKey,
    /// `F`: the anchor height of the Sequentia tip when the lock is built. The payment is above it.
    pub floor: u32,
    /// `D`: the last Bitcoin height at which the payment may be mined.
    pub deadline: u32,
    /// `R`: the anchor floor of the refund; the swap sets `R = D`.
    pub refund_at: u32,
    /// A fee pot: a second output of the lock transaction, under the same two leaves,
    /// holding an asset block producers accept, from which the claim (or the refund)
    /// pays its fee when producers do not accept the locked asset (section 8.1).
    pub fee_pot: Option<FeePot>,
}

/// A fee pot: `atoms` of `asset` in an output of the lock transaction that pays the
/// lock's own script. The seller prices it into the offer; the claim spends it beside
/// the lock, with the same proof, and the buyer keeps what its fee leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePot {
    /// The pot's asset, one producers accept as a fee.
    pub asset: AssetId,
    /// Its atoms.
    pub atoms: u64,
}

impl PayLockTerms {
    /// Terms with `R = D`, after checking the heights and amounts make a swap.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset: AssetId,
        atoms: u64,
        price_sat: u64,
        buyer: XOnlyPublicKey,
        seller: XOnlyPublicKey,
        receive_key: bitcoin::PublicKey,
        floor: u32,
        deadline: u32,
    ) -> Result<Self, Error> {
        let t = PayLockTerms {
            asset,
            atoms,
            price_sat,
            buyer,
            seller,
            receive_key,
            floor,
            deadline,
            refund_at: deadline,
            fee_pot: None,
        };
        t.sane()?;
        Ok(t)
    }

    /// The same terms with a fee pot in another asset (section 8.1).
    pub fn with_fee_pot(mut self, pot: FeePot) -> Result<Self, Error> {
        self.fee_pot = Some(pot);
        self.sane()?;
        Ok(self)
    }

    /// The checks every party runs on terms, whoever wrote them.
    pub fn sane(&self) -> Result<(), Error> {
        if self.atoms == 0 {
            return Err(gen("a lock of zero atoms"));
        }
        if self.price_sat == 0 || self.price_sat > 21_000_000 * 100_000_000 {
            return Err(gen(
                "the price must be between 1 satoshi and 21 million bitcoin",
            ));
        }
        for (name, h) in [
            ("floor F", self.floor),
            ("deadline D", self.deadline),
            ("refund height R", self.refund_at),
        ] {
            if h > MAX_HEIGHT {
                return Err(gen(format!(
                    "the {name} ({h}) is above {MAX_HEIGHT}, the highest height a script compares"
                )));
            }
        }
        if self.deadline <= self.floor {
            return Err(gen("the deadline D must be above the floor F"));
        }
        if self.refund_at != self.deadline {
            return Err(gen("the refund must open at the deadline (R = D)"));
        }
        if !self.receive_key.compressed {
            return Err(gen("the receiving key must be compressed"));
        }
        if let Some(pot) = &self.fee_pot {
            if pot.atoms == 0 {
                return Err(gen("a fee pot of zero atoms"));
            }
            if pot.asset == self.asset {
                return Err(gen(
                    "a fee pot in the locked asset adds nothing: the claim pays from the lock itself",
                ));
            }
        }
        Ok(())
    }

    /// The terms as JSON: what two parties exchange and what a completion service is given.
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "asset": self.asset.to_string(),
            "atoms": self.atoms,
            "price_sat": self.price_sat,
            "buyer": hex_encode(&self.buyer.serialize()),
            "seller": hex_encode(&self.seller.serialize()),
            "receive_key": hex_encode(&self.receive_key.to_bytes()),
            "floor": self.floor,
            "deadline": self.deadline,
            "refund_at": self.refund_at,
        });
        if let Some(pot) = &self.fee_pot {
            v["fee_pot"] = serde_json::json!({"asset": pot.asset.to_string(), "atoms": pot.atoms});
        }
        v
    }

    /// Terms read from [`PayLockTerms::to_json`]'s form, checked with [`PayLockTerms::sane`].
    pub fn from_json(v: &serde_json::Value) -> Result<Self, Error> {
        let s = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .ok_or_else(|| gen(format!("terms: missing {k}")))
        };
        let n = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| gen(format!("terms: missing {k}")))
        };
        let h32 = |k: &str| -> Result<u32, Error> {
            u32::try_from(n(k)?).map_err(|_| gen(format!("terms: {k} is not a height")))
        };
        let x = |k: &str| -> Result<XOnlyPublicKey, Error> {
            XOnlyPublicKey::from_slice(&hex_decode(s(k)?)?).map_err(gen)
        };
        let t = PayLockTerms {
            asset: s("asset")?.parse().map_err(gen)?,
            atoms: n("atoms")?,
            price_sat: n("price_sat")?,
            buyer: x("buyer")?,
            seller: x("seller")?,
            receive_key: bitcoin::PublicKey::from_slice(&hex_decode(s("receive_key")?)?)
                .map_err(gen)?,
            floor: h32("floor")?,
            deadline: h32("deadline")?,
            refund_at: h32("refund_at")?,
            fee_pot: match v.get("fee_pot") {
                None | Some(serde_json::Value::Null) => None,
                Some(p) => Some(FeePot {
                    asset: p
                        .get("asset")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| gen("terms: the fee pot has no asset"))?
                        .parse()
                        .map_err(gen)?,
                    atoms: p
                        .get("atoms")
                        .and_then(|x| x.as_u64())
                        .ok_or_else(|| gen("terms: the fee pot has no atoms"))?,
                }),
            },
        };
        t.sane()?;
        Ok(t)
    }

    /// The seller's receiving witness script, `<K> OP_CHECKSIGVERIFY OP_1 OP_CHECKSEQUENCEVERIFY`:
    /// the seller cannot spend the payment before it confirms, so it cannot pin it (section 8.3).
    pub fn receive_witness_script(&self) -> bitcoin::ScriptBuf {
        use crate::bitcoin::opcodes::all as b;
        bitcoin::script::Builder::new()
            .push_key(&self.receive_key)
            .push_opcode(b::OP_CHECKSIGVERIFY)
            .push_int(1)
            .push_opcode(b::OP_CSV)
            .into_script()
    }

    /// The receiving script's scriptPubKey (P2WSH).
    pub fn receive_script_pubkey(&self) -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::new_p2wsh(&self.receive_witness_script().wscript_hash())
    }

    /// The receiving address on the given Bitcoin network.
    pub fn receive_address(&self, network: bitcoin::Network) -> bitcoin::Address {
        bitcoin::Address::p2wsh(&self.receive_witness_script(), network)
    }

    /// The claim leaf.
    pub fn claim_leaf(&self) -> Script {
        let program = self.receive_witness_script().wscript_hash().to_byte_array();
        Builder::new()
            .push_slice(&self.buyer.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(Op::from(OP_INSPECTBTCPAYMENT))
            .push_opcode(OP_DROP)
            .push_opcode(OP_DUP)
            .push_int(i64::from(self.floor))
            .push_opcode(OP_GREATERTHAN)
            .push_opcode(OP_VERIFY)
            .push_int(i64::from(self.deadline))
            .push_opcode(OP_LESSTHANOREQUAL)
            .push_opcode(OP_VERIFY)
            .push_int(FIELD_OUTPUT)
            .push_opcode(Op::from(OP_INSPECTBTCTX))
            .push_int(0) // witness version of the receiving script
            .push_opcode(OP_EQUALVERIFY)
            .push_slice(&program)
            .push_opcode(OP_EQUALVERIFY)
            .push_slice(&self.price_sat.to_le_bytes())
            .push_opcode(OP_GREATERTHANOREQUAL64)
            .into_script()
    }

    /// The refund leaf.
    pub fn refund_leaf(&self) -> Script {
        Builder::new()
            .push_int(i64::from(self.refund_at))
            .push_opcode(Op::from(OP_CHECKANCHORHEIGHTVERIFY))
            .push_opcode(OP_DROP)
            .push_slice(&self.seller.serialize())
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// The lock's scriptPubKey and each leaf's control block.
    pub fn tree(&self) -> Result<LockTree, Error> {
        let claim = self.claim_leaf();
        let refund = self.refund_leaf();
        let secp = Secp256k1::verification_only();
        let info = TaprootBuilder::new()
            .add_leaf(1, claim.clone())
            .map_err(|e| gen(format!("taproot builder: {e:?}")))?
            .add_leaf(1, refund.clone())
            .map_err(|e| gen(format!("taproot builder: {e:?}")))?
            .finalize(&secp, nums()?)
            .map_err(|e| gen(format!("taproot finalize: {e:?}")))?;
        let cb = |s: &Script| {
            info.control_block(&(s.clone(), LeafVersion::default()))
                .map(|c| c.serialize())
                .ok_or_else(|| gen("no control block"))
        };
        Ok(LockTree {
            script_pubkey: Script::new_v1_p2tr_tweaked(info.output_key()),
            claim_control: cb(&claim)?,
            refund_control: cb(&refund)?,
            claim,
            refund,
        })
    }
}

/// The lock's output script and its two leaves.
#[derive(Debug, Clone)]
pub struct LockTree {
    /// The P2TR scriptPubKey the seller pays the asset to.
    pub script_pubkey: Script,
    /// The claim leaf.
    pub claim: Script,
    /// Its control block.
    pub claim_control: Vec<u8>,
    /// The refund leaf.
    pub refund: Script,
    /// Its control block.
    pub refund_control: Vec<u8>,
}

/// `D` for terms written now: the Bitcoin tip plus a margin to confirm a payment.
/// There is no wait before paying, so nothing else is added.
pub fn deadline_for(btc_tip: u32, margin: u32) -> u32 {
    btc_tip.saturating_add(margin)
}

// ----------------------------------------------------- the buyer's checks

/// What a buyer's wallet checks a lock against before it pays, besides the
/// node's `checklock` (finality, an uncontested Bitcoin tip, the lock's ancestry).
#[derive(Debug, Clone)]
pub struct LockFacts<'a> {
    /// The lock transaction as mined.
    pub lock_tx: &'a Transaction,
    /// The lock's output index.
    pub vout: u32,
    /// `L`: the anchor height of the block the lock is mined in.
    pub lock_anchor: u32,
    /// Bitcoin's tip in the buyer's view.
    pub btc_tip: u32,
}

/// The buyer's own checks on a mined lock, leaf for leaf against the terms it
/// agreed. Returns every reason the lock is not payable, in words a wallet can
/// show; an empty list means these checks pass.
pub fn check_lock(terms: &PayLockTerms, facts: &LockFacts<'_>) -> Vec<String> {
    let mut why = vec![];
    if let Err(e) = terms.sane() {
        why.push(format!("the terms do not make a swap: {e}"));
        return why;
    }
    let tree = match terms.tree() {
        Ok(t) => t,
        Err(e) => {
            why.push(format!(
                "the lock's script cannot be built from the terms: {e}"
            ));
            return why;
        }
    };
    match facts.lock_tx.output.get(facts.vout as usize) {
        None => why.push("the lock transaction has no such output".into()),
        Some(o) => {
            if o.script_pubkey != tree.script_pubkey {
                why.push("the lock does not pay the agreed claim and refund leaves".into());
            }
            if o.asset != confidential::Asset::Explicit(terms.asset) {
                why.push("the lock does not hold the agreed asset in the clear".into());
            }
            if o.value != confidential::Value::Explicit(terms.atoms) {
                why.push("the lock does not hold the agreed amount in the clear".into());
            }
        }
    }
    if terms.fee_pot.is_some() && fee_pot_vout(terms, facts.lock_tx, facts.vout).is_none() {
        why.push(
            "the lock transaction carries no fee pot of the agreed asset and amount under the lock's leaves"
                .into(),
        );
    }
    if facts
        .lock_tx
        .input
        .iter()
        .any(|i| i.sequence.0 < 0xffff_fffe)
    {
        why.push("the lock signals replacement, so its seller could replace it".into());
    }
    if terms.floor > facts.lock_anchor {
        why.push(format!(
            "the lock's floor F ({}) is above the anchor of its own block ({})",
            terms.floor, facts.lock_anchor
        ));
    }
    if terms.deadline > facts.btc_tip.saturating_add(MAX_DEADLINE_AHEAD) {
        why.push(format!(
            "the deadline (Bitcoin block {}) is more than {MAX_DEADLINE_AHEAD} blocks above Bitcoin's tip {}",
            terms.deadline, facts.btc_tip
        ));
    }
    if terms.deadline - terms.floor > MAX_DEADLINE_AHEAD {
        why.push(format!(
            "the lock spans {} Bitcoin blocks from its floor to its deadline, more than {MAX_DEADLINE_AHEAD}",
            terms.deadline - terms.floor
        ));
    }
    if facts.btc_tip.saturating_add(CANCEL_BEFORE_DEADLINE) >= terms.deadline {
        why.push(format!(
            "the deadline (Bitcoin block {}) leaves no time to confirm a payment from tip {}",
            terms.deadline, facts.btc_tip
        ));
    }
    why
}

/// The output of the lock transaction that holds the terms' fee pot: it pays the lock's
/// own script, in the clear, exactly the pot's asset and atoms, at an index other than the
/// lock's. `None` when the terms have no pot or the transaction does not carry it.
pub fn fee_pot_vout(terms: &PayLockTerms, lock_tx: &Transaction, lock_vout: u32) -> Option<u32> {
    let pot = terms.fee_pot?;
    let spk = terms.tree().ok()?.script_pubkey;
    lock_tx
        .output
        .iter()
        .enumerate()
        .find(|(i, o)| {
            *i as u32 != lock_vout
                && o.script_pubkey == spk
                && o.asset == confidential::Asset::Explicit(pot.asset)
                && o.value == confidential::Value::Explicit(pot.atoms)
        })
        .map(|(i, _)| i as u32)
}

// --------------------------------------------------------- the proof record

/// A payment proof (record type `0x01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentProof {
    /// The payment's Bitcoin height `h`.
    pub height: u32,
    /// The coin anchor `C`: the anchor height of the block that created the lock.
    pub coin_anchor: u32,
    /// The payment block's 80-byte header.
    pub header: [u8; 80],
    /// `SHA256(coinbase)`, single.
    pub coinbase_sha: [u8; 32],
    /// The payment's position in its block.
    pub index: u32,
    /// The payment's merkle branch.
    pub payment_branch: Vec<[u8; 32]>,
    /// The coinbase's merkle branch, of the same length.
    pub coinbase_branch: Vec<[u8; 32]>,
    /// Headers from the payment's block's child up to a recorded anchor.
    pub links: Vec<[u8; 80]>,
    /// The payment without its witness.
    pub payment: Vec<u8>,
}

fn dsha(b: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(b).to_byte_array()
}

fn merkle_branch(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut branch = vec![];
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        branch.push(level[index ^ 1]);
        level = level
            .chunks(2)
            .map(|p| {
                let mut c = [0u8; 64];
                c[..32].copy_from_slice(&p[0]);
                c[32..].copy_from_slice(&p[1]);
                dsha(&c)
            })
            .collect();
        index >>= 1;
    }
    branch
}

fn fold_branch(leaf: [u8; 32], branch: &[[u8; 32]], mut index: u32) -> [u8; 32] {
    let mut h = leaf;
    for s in branch {
        let mut c = [0u8; 64];
        if index & 1 == 1 {
            c[..32].copy_from_slice(s);
            c[32..].copy_from_slice(&h);
        } else {
            c[..32].copy_from_slice(&h);
            c[32..].copy_from_slice(s);
        }
        h = dsha(&c);
        index >>= 1;
    }
    h
}

/// A Bitcoin transaction's bytes without its witness: what its transaction id hashes.
pub fn strip_witness(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut tx: bitcoin::Transaction = btc_deserialize(raw).map_err(gen)?;
    for i in tx.input.iter_mut() {
        i.witness = bitcoin::Witness::new();
    }
    Ok(btc_serialize(&tx))
}

/// A Bitcoin block header's hash, in internal byte order.
pub fn header_hash(h: &[u8; 80]) -> [u8; 32] {
    dsha(h)
}

/// Everything a proof is built from, as a Bitcoin daemon or an Esplora server gives it.
#[derive(Debug, Clone)]
pub struct ProofSource {
    /// The payment block's height.
    pub height: u32,
    /// Its 80-byte header.
    pub header: [u8; 80],
    /// Every transaction id of the block, in order, in internal byte order.
    pub txids: Vec<[u8; 32]>,
    /// The raw coinbase (with or without witness).
    pub coinbase: Vec<u8>,
    /// The raw payment (with or without witness).
    pub payment: Vec<u8>,
    /// Headers from `height + 1` up to the recorded anchor the proof links to.
    pub links: Vec<[u8; 80]>,
}

impl PaymentProof {
    /// Builds a proof from what a Bitcoin source returned, and checks it as the node will.
    pub fn build(src: &ProofSource, coin_anchor: u32) -> Result<Self, Error> {
        let payment = strip_witness(&src.payment)?;
        let coinbase = strip_witness(&src.coinbase)?;
        let txid = dsha(&payment);
        let index = src
            .txids
            .iter()
            .position(|t| *t == txid)
            .ok_or_else(|| gen("the payment is not in the block given"))?;
        if src.txids.first() != Some(&dsha(&coinbase)) {
            return Err(gen(
                "the coinbase given is not the block's first transaction",
            ));
        }
        let p = PaymentProof {
            height: src.height,
            coin_anchor,
            header: src.header,
            coinbase_sha: sha256::Hash::hash(&coinbase).to_byte_array(),
            index: index as u32,
            payment_branch: merkle_branch(&src.txids, index),
            coinbase_branch: merkle_branch(&src.txids, 0),
            links: src.links.clone(),
            payment,
        };
        p.check()?;
        Ok(p)
    }

    /// Checks 1 to 5 of the specification (section 4.1, and the links of 4.2), which
    /// depend only on the record: a proof that fails them would only be refused.
    pub fn check(&self) -> Result<(), Error> {
        let d = self.payment_branch.len();
        if d == 0 || d > MAX_DEPTH || self.coinbase_branch.len() != d {
            return Err(gen(
                "the merkle branches must have the same length, 1 to 24",
            ));
        }
        if self.index == 0 || u64::from(self.index) >= (1u64 << d) {
            return Err(gen("the payment's index must be above 0 and below 2^depth"));
        }
        if self.links.len() > MAX_LINKS {
            return Err(gen("a proof links at most 2,016 headers"));
        }
        if self.payment.len() > MAX_PAYMENT_BYTES || self.payment.len() == 64 {
            return Err(gen(
                "the payment's size is refused (64 bytes, or above 100,000)",
            ));
        }
        let tx: bitcoin::Transaction = btc_deserialize(&self.payment).map_err(gen)?;
        if tx.is_coinbase() {
            return Err(gen("the payment is a coinbase"));
        }
        let root = &self.header[36..68];
        if fold_branch(dsha(&self.payment), &self.payment_branch, self.index) != root {
            return Err(gen(
                "the payment's branch does not reach the header's merkle root",
            ));
        }
        let cb_leaf = dsha_single(&self.coinbase_sha);
        if fold_branch(cb_leaf, &self.coinbase_branch, 0) != root {
            return Err(gen(
                "the coinbase's branch does not reach the header's merkle root",
            ));
        }
        // One encoding of the index: where a node's sibling is itself, the bit is 0.
        let mut h = dsha(&self.payment);
        let mut idx = self.index;
        for s in &self.payment_branch {
            if *s == h && idx & 1 == 1 {
                return Err(gen("the payment's index is not canonical"));
            }
            let mut c = [0u8; 64];
            if idx & 1 == 1 {
                c[..32].copy_from_slice(s);
                c[32..].copy_from_slice(&h);
            } else {
                c[..32].copy_from_slice(&h);
                c[32..].copy_from_slice(s);
            }
            h = dsha(&c);
            idx >>= 1;
        }
        let mut prev = header_hash(&self.header);
        for l in &self.links {
            if l[4..36] != prev {
                return Err(gen("a linking header does not follow the one before it"));
            }
            prev = header_hash(l);
        }
        Ok(())
    }

    /// The anchor the proof links to: the last linking header's hash, or the block's own.
    pub fn linked_anchor(&self) -> (u32, [u8; 32]) {
        let h = self.height + self.links.len() as u32;
        let hash = self
            .links
            .last()
            .map(header_hash)
            .unwrap_or_else(|| header_hash(&self.header));
        (h, hash)
    }

    /// The payment's transaction id, in internal byte order.
    pub fn payment_txid(&self) -> [u8; 32] {
        dsha(&self.payment)
    }

    /// The record's one valid encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            128 + 64 * self.payment_branch.len() + 80 * self.links.len() + self.payment.len(),
        );
        v.push(RECORD_PAYMENT);
        v.extend(self.height.to_le_bytes());
        v.extend(self.coin_anchor.to_le_bytes());
        v.extend(self.header);
        v.extend(self.coinbase_sha);
        v.push(self.payment_branch.len() as u8);
        v.extend(self.index.to_le_bytes());
        for b in &self.payment_branch {
            v.extend(b);
        }
        for b in &self.coinbase_branch {
            v.extend(b);
        }
        v.extend((self.links.len() as u16).to_le_bytes());
        for l in &self.links {
            v.extend(l);
        }
        v.extend(&self.payment);
        v
    }
}

fn dsha_single(sha: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::hash(sha).to_byte_array()
}

/// An anchor floor record (type `0x02`).
pub fn floor_record(height: u32) -> Vec<u8> {
    let mut v = vec![RECORD_FLOOR];
    v.extend(height.to_le_bytes());
    v
}

/// The outputs of a Bitcoin payment that pay the receiving script at least the price.
pub fn paying_outputs(terms: &PayLockTerms, payment_raw: &[u8]) -> Result<Vec<u32>, Error> {
    let tx: bitcoin::Transaction = btc_deserialize(payment_raw).map_err(gen)?;
    let spk = terms.receive_script_pubkey();
    Ok(tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == spk && o.value.to_sat() >= terms.price_sat)
        .map(|(i, _)| i as u32)
        .collect())
}

// --------------------------------------------------- the claim and the refund

fn explicit_out(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

/// The lock's output, as the claim and the refund spend it.
pub fn lock_txout(terms: &PayLockTerms) -> Result<TxOut, Error> {
    Ok(explicit_out(
        terms.asset,
        terms.atoms,
        terms.tree()?.script_pubkey,
    ))
}

/// Where a claim's or a refund's fee comes from (section 8.1). No asset is a fallback: a
/// wallet picks a source whose asset block producers accept, and declines the trade when
/// it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one per claim; boxing buys nothing
pub enum FeeSource {
    /// The locked asset itself: the default, when producers accept it.
    Locked,
    /// The terms' fee pot, at this output of the lock transaction, spent beside the lock
    /// through the same leaf.
    Pot(u32),
    /// A coin of the signer's own, in an asset producers accept. Its wallet signs that
    /// input. The claim's (or the refund's) signature commits to the coin's outpoint and
    /// output, so it authorises nothing but this one transaction.
    Coin {
        /// The coin.
        outpoint: OutPoint,
        /// Its output, in the clear.
        txout: TxOut,
    },
}

/// A fee: its source, its atoms, and where what the source leaves goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeePlan {
    /// Where the fee comes from.
    pub source: FeeSource,
    /// The fee, in atoms of the source's asset.
    pub fee: u64,
    /// Where what a pot or a coin leaves after the fee goes; `None` sends it with the asset.
    pub change: Option<Script>,
}

impl FeePlan {
    /// A fee of `fee` atoms of the locked asset.
    pub fn locked(fee: u64) -> Self {
        FeePlan {
            source: FeeSource::Locked,
            fee,
            change: None,
        }
    }

    /// The asset the fee is paid in.
    pub fn asset(&self, terms: &PayLockTerms) -> Result<AssetId, Error> {
        match &self.source {
            FeeSource::Locked => Ok(terms.asset),
            FeeSource::Pot(_) => terms
                .fee_pot
                .map(|p| p.asset)
                .ok_or_else(|| gen("the terms have no fee pot")),
            FeeSource::Coin { txout, .. } => match txout.asset {
                confidential::Asset::Explicit(a) => Ok(a),
                _ => Err(gen("a fee coin must hold its asset in the clear")),
            },
        }
    }
}

/// A spend of the lock (a claim or a refund), before its signatures, with the outputs its
/// inputs spend.
#[derive(Debug, Clone)]
pub struct LockSpend {
    /// The transaction.
    pub tx: Transaction,
    /// The output each input spends, in input order.
    pub prevouts: Vec<TxOut>,
    /// The inputs that spend the lock's script: the lock, and the fee pot when it pays.
    pub lock_inputs: Vec<usize>,
}

fn txin(previous_output: OutPoint, sequence: u32) -> TxIn {
    TxIn {
        previous_output,
        sequence: Sequence(sequence),
        ..Default::default()
    }
}

/// The lock spent to `to`, its fee paid as `plan` says. Input 0 is the lock; a pot or a
/// coin is input 1. Output 0 pays the asset to `to` (less the fee when the locked asset
/// pays it), then what the pot or coin leaves, then the fee.
pub fn lock_spend(
    terms: &PayLockTerms,
    lock: OutPoint,
    to: Script,
    plan: &FeePlan,
    sequence: u32,
) -> Result<LockSpend, Error> {
    let fee = plan.fee;
    let mut input = vec![txin(lock, sequence)];
    let mut prevouts = vec![lock_txout(terms)?];
    let mut lock_inputs = vec![0];
    let (fee_asset, left, left_to) = match &plan.source {
        FeeSource::Locked => {
            if fee == 0 || fee >= terms.atoms {
                return Err(gen(format!(
                    "the fee must be between 1 and {} atoms of the locked asset",
                    terms.atoms.saturating_sub(1)
                )));
            }
            let tx = Transaction {
                version: 2,
                lock_time: LockTime::ZERO,
                input,
                output: vec![
                    explicit_out(terms.asset, terms.atoms - fee, to),
                    explicit_out(terms.asset, fee, Script::new()),
                ],
            };
            return Ok(LockSpend {
                tx,
                prevouts,
                lock_inputs,
            });
        }
        FeeSource::Pot(vout) => {
            let pot = terms
                .fee_pot
                .ok_or_else(|| gen("the terms have no fee pot"))?;
            if *vout == lock.vout {
                return Err(gen("the fee pot is the lock's own output"));
            }
            if fee == 0 || fee > pot.atoms {
                return Err(gen(format!(
                    "the fee must be between 1 and {} atoms of the fee pot",
                    pot.atoms
                )));
            }
            input.push(txin(OutPoint::new(lock.txid, *vout), sequence));
            prevouts.push(explicit_out(
                pot.asset,
                pot.atoms,
                terms.tree()?.script_pubkey,
            ));
            lock_inputs.push(1);
            (pot.asset, pot.atoms - fee, plan.change.clone())
        }
        FeeSource::Coin { outpoint, txout } => {
            let (asset, value) = match (txout.asset, txout.value) {
                (confidential::Asset::Explicit(a), confidential::Value::Explicit(v)) => (a, v),
                _ => {
                    return Err(gen(
                        "a fee coin must hold its asset and amount in the clear",
                    ))
                }
            };
            if outpoint.txid == lock.txid {
                return Err(gen(
                    "a fee coin cannot be an output of the lock transaction",
                ));
            }
            if fee == 0 || fee > value {
                return Err(gen(format!(
                    "the fee must be between 1 and {value} atoms of the fee coin"
                )));
            }
            input.push(txin(*outpoint, sequence));
            prevouts.push(txout.clone());
            (asset, value - fee, plan.change.clone())
        }
    };
    let mut output = vec![explicit_out(terms.asset, terms.atoms, to.clone())];
    if left > 0 {
        output.push(explicit_out(fee_asset, left, left_to.unwrap_or(to)));
    }
    output.push(explicit_out(fee_asset, fee, Script::new()));
    Ok(LockSpend {
        tx: Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input,
            output,
        },
        prevouts,
        lock_inputs,
    })
}

fn sign_leaf(
    spend: &LockSpend,
    input: usize,
    leaf: &Script,
    genesis: BlockHash,
    sk: &SecretKey,
) -> Result<Vec<u8>, Error> {
    let sighash = SighashCache::new(&spend.tx)
        .taproot_script_spend_signature_hash(
            input,
            &Prevouts::All(&spend.prevouts),
            ScriptPath::with_defaults(leaf),
            SchnorrSighashType::Default,
            genesis,
        )
        .map_err(gen)?;
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, sk);
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &kp);
    Ok(sig.serialize().to_vec())
}

/// Takes the witnesses of the inputs this key does not sign (a fee coin) from a copy of
/// the same transaction its wallet signed. The two must be the same transaction.
fn take_wallet_witnesses(
    spend: &mut LockSpend,
    wallet_signed: Option<&Transaction>,
) -> Result<(), Error> {
    let Some(w) = wallet_signed else {
        return Ok(());
    };
    if w.txid() != spend.tx.txid() {
        return Err(gen(
            "the wallet-signed transaction is not this claim or refund: it spends or pays something else",
        ));
    }
    for i in 0..spend.tx.input.len() {
        if !spend.lock_inputs.contains(&i) {
            spend.tx.input[i].witness = w.input[i].witness.clone();
        }
    }
    Ok(())
}

fn check_key(sk: &SecretKey, want: &XOnlyPublicKey, who: &str) -> Result<(), Error> {
    let secp = Secp256k1::new();
    if Keypair::from_secret_key(&secp, sk).x_only_public_key().0 != *want {
        return Err(gen(format!("the key given is not the terms' {who} key")));
    }
    Ok(())
}

/// The buyer's claim, signed and ready for a proof: input 0 spends the lock through
/// the claim leaf, output 0 pays the asset less the fee to `to`, output 1 is the fee,
/// paid in the asset being moved. Its witness waits for the payment's output index
/// and its proof ([`attach_proof`]), neither of which the signature covers.
pub fn sign_claim(
    terms: &PayLockTerms,
    lock: OutPoint,
    to: Script,
    fee: u64,
    genesis: BlockHash,
    buyer_sk: &SecretKey,
) -> Result<Transaction, Error> {
    sign_claim_with(
        terms,
        lock,
        to,
        &FeePlan::locked(fee),
        genesis,
        buyer_sk,
        None,
    )
}

/// The buyer's claim with its fee paid as `plan` says. Every input that spends the lock's
/// script (the lock, and the fee pot) is signed through the claim leaf. A fee coin's input
/// is the buyer's wallet's to sign: pass the copy the wallet signed as `wallet_signed`, a
/// copy of [`lock_spend`]'s transaction (the template); without it that input is left
/// unsigned.
pub fn sign_claim_with(
    terms: &PayLockTerms,
    lock: OutPoint,
    to: Script,
    plan: &FeePlan,
    genesis: BlockHash,
    buyer_sk: &SecretKey,
    wallet_signed: Option<&Transaction>,
) -> Result<Transaction, Error> {
    check_key(buyer_sk, &terms.buyer, "buyer")?;
    let tree = terms.tree()?;
    let mut spend = lock_spend(terms, lock, to, plan, CLAIM_SEQUENCE)?;
    take_wallet_witnesses(&mut spend, wallet_signed)?;
    for &i in &spend.lock_inputs.clone() {
        let sig = sign_leaf(&spend, i, &tree.claim, genesis, buyer_sk)?;
        spend.tx.input[i].witness = TxInWitness {
            script_witness: vec![
                script_num(0),
                sig,
                tree.claim.to_bytes(),
                tree.claim_control.clone(),
            ],
            ..Default::default()
        };
    }
    Ok(spend.tx)
}

/// Completes a signed claim with a proof and the index of the payment's output that
/// pays the seller. Every input that spends the claim leaf (the lock, and a fee pot)
/// carries the proof. The transaction id is unchanged; only its witness id moves.
pub fn attach_proof(
    claim: &Transaction,
    proof: &PaymentProof,
    payment_vout: u32,
) -> Result<Transaction, Error> {
    let mut tx = claim.clone();
    let leaf = match tx.input.first().map(|i| &i.witness.script_witness) {
        Some(w) if w.len() == 4 => w[2].clone(),
        Some(_) => return Err(gen("the claim's witness is not <i> <sig> <leaf> <control>")),
        None => return Err(gen("a claim with no input")),
    };
    let record = proof.encode();
    for i in tx.input.iter_mut() {
        let w = &mut i.witness;
        if w.script_witness.len() == 4 && w.script_witness[2] == leaf {
            w.script_witness[0] = script_num(i64::from(payment_vout));
            w.pegin_witness = vec![record.clone()];
        }
    }
    Ok(tx)
}

/// The seller's refund: valid once the block 60 below it is anchored at `R` or above.
pub fn sign_refund(
    terms: &PayLockTerms,
    lock: OutPoint,
    to: Script,
    fee: u64,
    genesis: BlockHash,
    seller_sk: &SecretKey,
) -> Result<Transaction, Error> {
    sign_refund_with(
        terms,
        lock,
        to,
        &FeePlan::locked(fee),
        genesis,
        seller_sk,
        None,
    )
}

/// The seller's refund with its fee paid as `plan` says: from the fee pot, which it takes
/// back with the lock, or from a coin of the seller's own (`wallet_signed` as for
/// [`sign_claim_with`]). Each input that spends the lock's script carries the refund's
/// anchor floor record.
pub fn sign_refund_with(
    terms: &PayLockTerms,
    lock: OutPoint,
    to: Script,
    plan: &FeePlan,
    genesis: BlockHash,
    seller_sk: &SecretKey,
    wallet_signed: Option<&Transaction>,
) -> Result<Transaction, Error> {
    check_key(seller_sk, &terms.seller, "seller")?;
    let tree = terms.tree()?;
    let mut spend = lock_spend(terms, lock, to, plan, CLAIM_SEQUENCE)?;
    take_wallet_witnesses(&mut spend, wallet_signed)?;
    for &i in &spend.lock_inputs.clone() {
        let sig = sign_leaf(&spend, i, &tree.refund, genesis, seller_sk)?;
        spend.tx.input[i].witness = TxInWitness {
            script_witness: vec![sig, tree.refund.to_bytes(), tree.refund_control.clone()],
            pegin_witness: vec![floor_record(terms.refund_at)],
            ..Default::default()
        };
    }
    Ok(spend.tx)
}

/// The fee a claim or a refund pays: the asset and atoms of its fee output.
pub fn fee_of(tx: &Transaction) -> Option<(AssetId, u64)> {
    tx.output
        .iter()
        .find(|o| o.script_pubkey.is_empty())
        .and_then(|o| match (o.asset, o.value) {
            (confidential::Asset::Explicit(a), confidential::Value::Explicit(v)) => Some((a, v)),
            _ => None,
        })
}

/// The witness bytes a fee coin's wallet adds to an input it has not signed yet: a P2WPKH
/// spend, the usual wallet coin. Pricing only.
const UNSIGNED_INPUT_WITNESS: u64 = 108;

/// A claim's virtual size with a proof of `proof_bytes` on every input that spends the
/// claim leaf, for pricing its fee tiers.
pub fn claim_vsize(claim: &Transaction, proof_bytes: usize) -> u64 {
    let base = crate::elements::encode::serialize(&Transaction {
        input: claim
            .input
            .iter()
            .map(|i| TxIn {
                witness: TxInWitness::default(),
                ..i.clone()
            })
            .collect(),
        ..claim.clone()
    })
    .len() as u64;
    let proofs = claim
        .input
        .iter()
        .filter(|i| i.witness.script_witness.len() == 4)
        .count() as u64;
    let unsigned = claim
        .input
        .iter()
        .filter(|i| i.witness.script_witness.is_empty())
        .count() as u64;
    let total = crate::elements::encode::serialize(claim).len() as u64
        + proofs * (proof_bytes as u64 + 3)
        + unsigned * UNSIGNED_INPUT_WITNESS;
    let weight = base * 3 + total;
    weight.div_ceil(4)
}

/// The top fee tier (section 8.5): what a seller must outbid on every block the claim
/// can be mined in before the refund is valid, so that keeping the claim out costs more
/// than the asset is worth. `atoms` is `V`, the value locked, expressed in atoms of the
/// asset the tier pays its fee in (the locked asset's own atoms when it pays). `stale_ratio`
/// is `m`, the most a fee asset's published rate may exceed its market price; the seller's
/// share of the blocks is taken as one half.
pub fn top_tier_fee(
    atoms: u64,
    claim_vsize: u64,
    block_vsize: u64,
    blocks: u64,
    stale_ratio: u64,
) -> u64 {
    // V * v * m * 4 / (B * N * (1 - s) * 3), with s = 1/2.
    let num = u128::from(atoms) * u128::from(claim_vsize) * u128::from(stale_ratio.max(1)) * 8;
    let den = u128::from(block_vsize.max(1)) * u128::from(blocks.max(1)) * 3;
    num.div_ceil(den).min(u128::from(atoms.saturating_sub(1))) as u64
}

// ---------------------------------------------------------------- the cancel

/// The buyer's cancel of its own payment, unsigned: it spends every input of the
/// payment back to the buyer, so it replaces the payment if the payment has not
/// confirmed. `prevout_values` are the amounts the payment's inputs spend, in order.
/// The buyer's Bitcoin wallet signs it before the payment is broadcast and hands it
/// to the completion service, which broadcasts it two blocks before `D`.
pub fn cancel_template(
    payment_raw: &[u8],
    prevout_values: &[u64],
    to: bitcoin::ScriptBuf,
    fee_sat: u64,
) -> Result<bitcoin::Transaction, Error> {
    let pay: bitcoin::Transaction = btc_deserialize(payment_raw).map_err(gen)?;
    let pay_fee = payment_fee(&pay, prevout_values)?;
    let floor = cancel_fee_floor(payment_raw, prevout_values, to.clone())?;
    if fee_sat < floor {
        return Err(gen(format!(
            "the cancel must pay at least {floor} sat: the payment's own fee ({pay_fee} sat) and \
             {INCREMENTAL_RELAY_SAT_VB} sat per virtual byte of its own size, or Bitcoin nodes do not let it replace the payment"
        )));
    }
    let total: u64 = prevout_values.iter().sum();
    let value = total
        .checked_sub(fee_sat)
        .filter(|v| *v > 330)
        .ok_or_else(|| gen("the cancel's fee leaves nothing to return"))?;
    Ok(cancel_tx(&pay, value, to))
}

fn payment_fee(pay: &bitcoin::Transaction, prevout_values: &[u64]) -> Result<u64, Error> {
    if prevout_values.len() != pay.input.len() {
        return Err(gen("one amount per payment input is needed"));
    }
    let total: u64 = prevout_values.iter().sum();
    let pay_out: u64 = pay.output.iter().map(|o| o.value.to_sat()).sum();
    total
        .checked_sub(pay_out)
        .ok_or_else(|| gen("the payment spends less than it pays"))
}

fn cancel_tx(pay: &bitcoin::Transaction, value: u64, to: bitcoin::ScriptBuf) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: pay
            .input
            .iter()
            .map(|i| bitcoin::TxIn {
                previous_output: i.previous_output,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0xffff_fffd),
                witness: bitcoin::Witness::new(),
            })
            .collect(),
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: to,
        }],
    }
}

/// The least fee a cancel of this payment pays and still replaces it under BIP125: the
/// payment's own fee, and the incremental relay fee for the cancel's own virtual size.
/// The cancel spends the payment's own coins, so its signatures are sized from the
/// payment's (an unsigned input is taken as a P2WPKH spend), with a byte to spare per
/// input for a signature's varying length.
pub fn cancel_fee_floor(
    payment_raw: &[u8],
    prevout_values: &[u64],
    to: bitcoin::ScriptBuf,
) -> Result<u64, Error> {
    let pay: bitcoin::Transaction = btc_deserialize(payment_raw).map_err(gen)?;
    let pay_fee = payment_fee(&pay, prevout_values)?;
    let mut sized = cancel_tx(&pay, 0, to);
    for (c, p) in sized.input.iter_mut().zip(&pay.input) {
        c.script_sig = p.script_sig.clone();
        c.witness = if p.witness.is_empty() && p.script_sig.is_empty() {
            bitcoin::Witness::from_slice(&[vec![0u8; 72], vec![0u8; 33]])
        } else {
            p.witness.clone()
        };
    }
    let vsize = sized.vsize() as u64 + sized.input.len() as u64;
    let mut floor = pay_fee + INCREMENTAL_RELAY_SAT_VB * vsize;
    // And a higher rate than the payment's, should the cancel be the larger of the two.
    let pay_vsize = pay.vsize() as u64;
    if pay_vsize > 0 && floor * pay_vsize <= pay_fee * vsize {
        floor = (pay_fee * vsize).div_ceil(pay_vsize) + 1;
    }
    Ok(floor)
}

// ------------------------------------------------------------ the timeline

/// Where a swap stands, from the chains alone. Every product shows these states in
/// its own words; none of them names a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentState {
    /// No payment to the receiving script is mined on Bitcoin's best chain.
    NotMined,
    /// The payment is mined at a height the claim accepts (`F < h <= D`).
    InWindow(u32),
    /// The payment is mined at or below `F`: it predates the lock and opens nothing.
    BelowFloor(u32),
    /// The payment is mined above `D`: it came too late, and the seller refunds.
    Late(u32),
}

/// Classifies a mined payment's height against the terms.
pub fn payment_state(terms: &PayLockTerms, mined_at: Option<u32>) -> PaymentState {
    match mined_at {
        None => PaymentState::NotMined,
        Some(h) if h <= terms.floor => PaymentState::BelowFloor(h),
        Some(h) if h > terms.deadline => PaymentState::Late(h),
        Some(h) => PaymentState::InWindow(h),
    }
}

/// Whether the buyer's cancel is due: the payment is still unconfirmed and Bitcoin's
/// tip has reached two blocks before `D`.
pub fn cancel_due(terms: &PayLockTerms, btc_tip: u32, payment_mined: bool) -> bool {
    !payment_mined && btc_tip.saturating_add(CANCEL_BEFORE_DEADLINE) >= terms.deadline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements::Txid;
    use std::str::FromStr;

    fn key(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }

    fn terms() -> PayLockTerms {
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
            AssetId::from_str("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
                .unwrap(),
            1_000_000_000,
            1_230_000,
            x(1),
            x(2),
            rk,
            900_000,
            900_006,
        )
        .unwrap()
    }

    #[test]
    fn script_numbers_are_minimal() {
        assert_eq!(script_num(0), Vec::<u8>::new());
        assert_eq!(script_num(1), vec![1]);
        assert_eq!(script_num(127), vec![0x7f]);
        assert_eq!(script_num(128), vec![0x80, 0]);
        assert_eq!(script_num(900_006), vec![0xa6, 0xbb, 0x0d]);
        assert_eq!(script_num(-1), vec![0x81]);
    }

    #[test]
    fn terms_refuse_what_is_not_a_swap() {
        let t = terms();
        let mut bad = t.clone();
        bad.refund_at = t.deadline + 1;
        assert!(bad.sane().is_err());
        let mut bad = t.clone();
        bad.deadline = t.floor;
        assert!(bad.sane().is_err());
        let mut bad = t.clone();
        bad.atoms = 0;
        assert!(bad.sane().is_err());
        assert_eq!(PayLockTerms::from_json(&t.to_json()).unwrap(), t);
        let mut j = t.to_json();
        j["refund_at"] = serde_json::json!(t.deadline + 1);
        assert!(PayLockTerms::from_json(&j).is_err());
    }

    #[test]
    fn leaves_have_the_specified_shape() {
        let t = terms();
        let c = t.claim_leaf().to_bytes();
        assert_eq!(c[0], 32);
        assert_eq!(c[33], 0xad); // OP_CHECKSIGVERIFY
        assert_eq!(c[34], OP_INSPECTBTCPAYMENT);
        assert_eq!(*c.last().unwrap(), 0xdf); // OP_GREATERTHANOREQUAL64
        let r = t.refund_leaf().to_bytes();
        assert_eq!(r[4], OP_CHECKANCHORHEIGHTVERIFY);
        assert_eq!(*r.last().unwrap(), 0xac);
        let tree = t.tree().unwrap();
        assert!(tree.script_pubkey.is_v1_p2tr());
        assert_eq!(tree.claim_control.len(), 65);
    }

    #[test]
    fn a_claim_keeps_its_txid_whatever_proof_completes_it() {
        let t = terms();
        let lock = OutPoint::default();
        let genesis = BlockHash::all_zeros();
        let c = sign_claim(&t, lock, Script::new(), 1000, genesis, &key(1)).unwrap();
        assert!(sign_claim(&t, lock, Script::new(), 1000, genesis, &key(2)).is_err());
        let p = PaymentProof {
            height: 900_001,
            coin_anchor: 900_000,
            header: [0; 80],
            coinbase_sha: [0; 32],
            index: 1,
            payment_branch: vec![[1; 32]],
            coinbase_branch: vec![[2; 32]],
            links: vec![],
            payment: vec![9; 100],
        };
        let a = attach_proof(&c, &p, 1).unwrap();
        assert_eq!(a.txid(), c.txid());
        assert_ne!(a.wtxid(), c.wtxid());
        assert_eq!(a.input[0].witness.script_witness[0], vec![1]);
        assert_eq!(a.input[0].witness.pegin_witness[0][0], RECORD_PAYMENT);
        let r = sign_refund(&t, lock, Script::new(), 1000, genesis, &key(2)).unwrap();
        assert_eq!(r.input[0].witness.pegin_witness[0], floor_record(900_006));
    }

    fn other_asset() -> AssetId {
        AssetId::from_str("b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23")
            .unwrap()
    }

    fn proof() -> PaymentProof {
        PaymentProof {
            height: 900_001,
            coin_anchor: 900_000,
            header: [0; 80],
            coinbase_sha: [0; 32],
            index: 1,
            payment_branch: vec![[1; 32]],
            coinbase_branch: vec![[2; 32]],
            links: vec![],
            payment: vec![9; 100],
        }
    }

    #[test]
    fn a_fee_pot_is_part_of_the_terms() {
        let pot = FeePot {
            asset: other_asset(),
            atoms: 20_000,
        };
        let t = terms().with_fee_pot(pot).unwrap();
        assert_eq!(PayLockTerms::from_json(&t.to_json()).unwrap(), t);
        // Terms without a pot read and write as before.
        assert!(terms().to_json().get("fee_pot").is_none());
        assert!(terms()
            .with_fee_pot(FeePot {
                asset: terms().asset,
                atoms: 1
            })
            .is_err());
        assert!(terms()
            .with_fee_pot(FeePot {
                asset: other_asset(),
                atoms: 0
            })
            .is_err());

        // check_lock finds the pot only at the lock's script, in the clear, exact.
        let spk = t.tree().unwrap().script_pubkey;
        let lock_tx = |pot_value: u64| Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                explicit_out(t.asset, t.atoms, spk.clone()),
                explicit_out(other_asset(), pot_value, spk.clone()),
            ],
        };
        let good = lock_tx(20_000);
        assert_eq!(fee_pot_vout(&t, &good, 0), Some(1));
        let facts = LockFacts {
            lock_tx: &good,
            vout: 0,
            lock_anchor: 900_000,
            btc_tip: 900_000,
        };
        assert!(
            check_lock(&t, &facts).is_empty(),
            "{:?}",
            check_lock(&t, &facts)
        );
        let short = lock_tx(19_999);
        assert_eq!(fee_pot_vout(&t, &short, 0), None);
        let facts = LockFacts {
            lock_tx: &short,
            ..facts
        };
        assert!(check_lock(&t, &facts)
            .iter()
            .any(|r| r.contains("no fee pot")));
    }

    #[test]
    fn a_claim_pays_its_fee_from_the_pot_with_a_proof_on_both_inputs() {
        let t = terms()
            .with_fee_pot(FeePot {
                asset: other_asset(),
                atoms: 20_000,
            })
            .unwrap();
        let lock = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
        let plan = FeePlan {
            source: FeeSource::Pot(1),
            fee: 5_000,
            change: None,
        };
        let to = Script::from(vec![0x51]);
        let c = sign_claim_with(
            &t,
            lock,
            to.clone(),
            &plan,
            BlockHash::all_zeros(),
            &key(1),
            None,
        )
        .unwrap();
        assert_eq!(c.input.len(), 2);
        assert_eq!(c.input[1].previous_output, OutPoint::new(lock.txid, 1));
        // The whole locked amount reaches the buyer; the pot pays the fee and the rest.
        assert_eq!(c.output[0].value, confidential::Value::Explicit(t.atoms));
        assert_eq!(c.output[1].value, confidential::Value::Explicit(15_000));
        assert_eq!(c.output[1].script_pubkey, to);
        assert_eq!(fee_of(&c), Some((other_asset(), 5_000)));
        // Two signatures, each for its own input.
        let w0 = &c.input[0].witness.script_witness;
        let w1 = &c.input[1].witness.script_witness;
        assert_eq!(w0.len(), 4);
        assert_eq!(w1.len(), 4);
        assert_eq!(w0[2], w1[2]);
        assert_ne!(w0[1], w1[1]);
        let a = attach_proof(&c, &proof(), 2).unwrap();
        assert_eq!(a.txid(), c.txid());
        for i in &a.input {
            assert_eq!(i.witness.script_witness[0], vec![2]);
            assert_eq!(i.witness.pegin_witness[0][0], RECORD_PAYMENT);
        }
        assert!(
            claim_vsize(&c, 400)
                > claim_vsize(
                    &sign_claim(&t, lock, to.clone(), 5000, BlockHash::all_zeros(), &key(1))
                        .unwrap(),
                    400
                ) + 100
        );
        // A pot the terms do not have, or the lock's own output, is refused.
        assert!(lock_spend(&terms(), lock, to.clone(), &plan, CLAIM_SEQUENCE).is_err());
        let own = FeePlan {
            source: FeeSource::Pot(0),
            ..plan.clone()
        };
        assert!(lock_spend(&t, lock, to.clone(), &own, CLAIM_SEQUENCE).is_err());
        // The refund takes the pot back too, each input with its floor record.
        let r =
            sign_refund_with(&t, lock, to, &plan, BlockHash::all_zeros(), &key(2), None).unwrap();
        assert_eq!(r.input.len(), 2);
        for i in &r.input {
            assert_eq!(i.witness.pegin_witness[0], floor_record(900_006));
        }
    }

    #[test]
    fn a_claim_pays_its_fee_from_a_coin_the_wallet_signs() {
        let t = terms();
        let lock = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
        let coin = OutPoint::new(Txid::from_byte_array([8; 32]), 3);
        let coin_out = explicit_out(other_asset(), 9_000, Script::from(vec![0x00, 0x14]));
        let change = Script::from(vec![0x52]);
        let plan = FeePlan {
            source: FeeSource::Coin {
                outpoint: coin,
                txout: coin_out.clone(),
            },
            fee: 1_000,
            change: Some(change.clone()),
        };
        let to = Script::from(vec![0x51]);
        let template = lock_spend(&t, lock, to.clone(), &plan, CLAIM_SEQUENCE).unwrap();
        assert_eq!(template.lock_inputs, vec![0]);
        assert_eq!(template.prevouts[1], coin_out);
        // The wallet signs input 1 of the template; the buyer's key signs input 0 after.
        let mut wallet = template.tx.clone();
        wallet.input[1].witness.script_witness = vec![vec![0xaa; 71], vec![0x02; 33]];
        let c = sign_claim_with(
            &t,
            lock,
            to.clone(),
            &plan,
            BlockHash::all_zeros(),
            &key(1),
            Some(&wallet),
        )
        .unwrap();
        assert_eq!(
            c.input[1].witness.script_witness,
            wallet.input[1].witness.script_witness
        );
        assert_eq!(c.input[0].witness.script_witness.len(), 4);
        assert_eq!(c.output[0].value, confidential::Value::Explicit(t.atoms));
        assert_eq!(c.output[1].script_pubkey, change);
        assert_eq!(fee_of(&c), Some((other_asset(), 1_000)));
        // The proof goes on the lock's input only.
        let a = attach_proof(&c, &proof(), 0).unwrap();
        assert!(a.input[1].witness.pegin_witness.is_empty());
        // A wallet copy of some other transaction is refused.
        let mut other = wallet.clone();
        other.output[0].script_pubkey = Script::from(vec![0x53]);
        assert!(sign_claim_with(
            &t,
            lock,
            to.clone(),
            &plan,
            BlockHash::all_zeros(),
            &key(1),
            Some(&other)
        )
        .is_err());
        // A fee as large as the coin is allowed (no change); a larger one is not.
        let all = FeePlan {
            fee: 9_000,
            ..plan.clone()
        };
        assert_eq!(
            lock_spend(&t, lock, to.clone(), &all, CLAIM_SEQUENCE)
                .unwrap()
                .tx
                .output
                .len(),
            2
        );
        let over = FeePlan { fee: 9_001, ..plan };
        assert!(lock_spend(&t, lock, to, &over, CLAIM_SEQUENCE).is_err());
    }

    #[test]
    fn heights_a_script_cannot_compare_are_refused() {
        let t = terms();
        for k in ["floor", "deadline", "refund_at"] {
            let mut j = t.to_json();
            j[k] = serde_json::json!(u64::from(MAX_HEIGHT) + 1);
            if k != "floor" {
                j["deadline"] = serde_json::json!(u64::from(MAX_HEIGHT) + 1);
                j["refund_at"] = serde_json::json!(u64::from(MAX_HEIGHT) + 1);
            }
            let e = PayLockTerms::from_json(&j).unwrap_err().to_string();
            assert!(e.contains("highest height"), "{k}: {e}");
        }
        // The review's terms: D = 2^31.
        let mut bad = t.clone();
        bad.deadline = 1 << 31;
        bad.refund_at = 1 << 31;
        assert!(bad.sane().is_err());
        // The highest height that compares is allowed.
        let mut top = t.clone();
        top.deadline = MAX_HEIGHT;
        top.refund_at = MAX_HEIGHT;
        top.floor = MAX_HEIGHT - 6;
        assert!(top.sane().is_ok());
    }

    #[test]
    fn a_lock_whose_deadline_is_too_far_is_not_payable() {
        let t = terms();
        let spk = t.tree().unwrap().script_pubkey;
        let lock_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![explicit_out(t.asset, t.atoms, spk)],
        };
        let facts = |tip| LockFacts {
            lock_tx: &lock_tx,
            vout: 0,
            lock_anchor: 900_000,
            btc_tip: tip,
        };
        assert!(check_lock(&t, &facts(900_000)).is_empty());
        // D more than a week above Bitcoin's tip, or a lock spanning more than a week.
        let mut far = t.clone();
        far.deadline = 900_000 + MAX_DEADLINE_AHEAD + 1;
        far.refund_at = far.deadline;
        let far_tx = Transaction {
            output: vec![explicit_out(far.asset, far.atoms, far.tree().unwrap().script_pubkey)],
            ..lock_tx.clone()
        };
        let why = check_lock(
            &far,
            &LockFacts {
                lock_tx: &far_tx,
                ..facts(900_000)
            },
        );
        assert!(why.iter().any(|w| w.contains("above Bitcoin's tip")), "{why:?}");
        assert!(why.iter().any(|w| w.contains("spans")), "{why:?}");
    }

    #[test]
    fn a_cancel_pays_what_replacing_the_payment_costs() {
        // A payment of one P2WPKH-signed input, to the seller and back to the buyer.
        let pay = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([4; 32]),
                    vout: 1,
                },
                sequence: bitcoin::Sequence(0xffff_fffd),
                witness: bitcoin::Witness::from_slice(&[vec![0x30; 72], vec![0x02; 33]]),
                ..Default::default()
            }],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(50_000_000),
                    script_pubkey: bitcoin::ScriptBuf::from(vec![0x00; 34]),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(49_990_000),
                    script_pubkey: bitcoin::ScriptBuf::from(vec![0x00; 22]),
                },
            ],
        };
        let raw = btc_serialize(&pay);
        let values = [100_000_000u64];
        let pay_fee = 10_000;
        let to = bitcoin::ScriptBuf::from(vec![0x00; 22]);
        let floor = cancel_fee_floor(&raw, &values, to.clone()).unwrap();
        let cancel = cancel_template(&raw, &values, to.clone(), floor).unwrap();
        // The floor: the payment's fee and 1 sat for each virtual byte of the signed cancel.
        let mut signed = cancel.clone();
        signed.input[0].witness = pay.input[0].witness.clone();
        assert!(floor >= pay_fee + signed.vsize() as u64, "{floor}");
        assert!(floor <= pay_fee + signed.vsize() as u64 + 2, "{floor}");
        // The review's cancel, at the payment's fee and one satoshi: refused.
        let e = cancel_template(&raw, &values, to.clone(), pay_fee + 1).unwrap_err();
        assert!(e.to_string().contains("at least"), "{e}");
        assert!(cancel_template(&raw, &values, to, floor - 1).is_err());
    }

    #[test]
    fn a_proof_is_checked_as_the_node_checks_it() {
        // Three transactions; the payment is the last, a duplicated node on its level.
        let mk = |n: u8| {
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([n; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1000 + u64::from(n)),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            };
            btc_serialize(&tx)
        };
        let coinbase = {
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: bitcoin::ScriptBuf::from(vec![1, 2, 3]),
                    ..Default::default()
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(5_000_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            };
            btc_serialize(&tx)
        };
        let txs = [coinbase.clone(), mk(1), mk(2)];
        let txids: Vec<[u8; 32]> = txs.iter().map(|t| dsha(t)).collect();
        let mut level = txids.clone();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level
                .chunks(2)
                .map(|p| dsha(&[p[0], p[1]].concat()))
                .collect();
        }
        let mut header = [0u8; 80];
        header[36..68].copy_from_slice(&level[0]);
        let mut link = [0u8; 80];
        link[4..36].copy_from_slice(&header_hash(&header));
        let src = ProofSource {
            height: 100,
            header,
            txids,
            coinbase,
            payment: txs[2].clone(),
            links: vec![link],
        };
        let p = PaymentProof::build(&src, 99).unwrap();
        assert_eq!(p.index, 2);
        assert_eq!(p.linked_anchor(), (101, header_hash(&link)));
        let e = p.encode();
        assert_eq!(
            e.len(),
            1 + 4 + 4 + 80 + 32 + 1 + 4 + 64 * 2 + 2 + 80 + p.payment.len()
        );
        let mut bad = p.clone();
        bad.index = 3;
        assert!(bad.check().is_err());
        let mut bad = p.clone();
        bad.links[0][4] ^= 1;
        assert!(bad.check().is_err());
        let mut src2 = src.clone();
        src2.payment = mk(7);
        assert!(PaymentProof::build(&src2, 99).is_err());
    }

    #[test]
    fn the_top_tier_follows_the_specification() {
        // V / 3,262 for a 300-vbyte claim with m = 2 (section 8.5).
        let f = top_tier_fee(3_262_000_000, 300, BLOCK_VSIZE, TOP_TIER_BLOCKS, 2);
        assert!((999_000..=1_001_000).contains(&f), "{f}");
    }

    #[test]
    fn the_timeline() {
        let t = terms();
        assert_eq!(
            payment_state(&t, Some(900_000)),
            PaymentState::BelowFloor(900_000)
        );
        assert_eq!(
            payment_state(&t, Some(900_006)),
            PaymentState::InWindow(900_006)
        );
        assert_eq!(
            payment_state(&t, Some(900_007)),
            PaymentState::Late(900_007)
        );
        assert!(!cancel_due(&t, 900_003, false));
        assert!(cancel_due(&t, 900_004, false));
        assert!(!cancel_due(&t, 900_004, true));
        assert_eq!(deadline_for(900_000, DEFAULT_DEADLINE_MARGIN), 900_006);
    }
}
