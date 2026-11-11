//! Swap escrows: the Sequentia side of a restricted (OpenAMP) asset traded for
//! on-chain BTC.
//!
//! The BTC payer (the buyer) holds a secret `s` with `H = SHA256(s)` and locks
//! its bitcoin first. The seller then locks the asset in an escrow for that
//! buyer, and a small fee pot of an accepted fee asset beside it. The buyer
//! claims both together with `s`; the pot's witness carries `s` in plain
//! tapscript, and the seller reads it there to take the bitcoin. After `T_seq`
//! anyone can send each coin home with no key at all, so no refusal and no
//! absence can keep a coin from its owner.
//!
//! The scripts are openampd's (`openampd/internal/elements/escrow.go` in the
//! `openamp` repository), checked byte for byte against the same golden
//! vectors, which the node's test framework produced.
//!
//! Escrow, `P2TR(NUMS, [claim, [refund, claw]])` (no `claw` without clawback):
//!
//! ```text
//! claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
//!         <K_buyer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//! refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <pin: the seller's enclave>
//! claw  : <K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//! ```
//!
//! Fee pot, `P2TR(NUMS, [claim, refund])`:
//!
//! ```text
//! claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <K_buyer> OP_CHECKSIG
//! refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <pin: the seller's address>
//! ```
//!
//! A pin requires the output at the spending input's own index to carry exactly
//! the given witness program, explicit asset and explicit value.

use crate::elements::encode::serialize;
use crate::elements::hashes::{sha256, Hash};
use crate::elements::hex::FromHex;
use crate::elements::opcodes::all::*;
use crate::elements::script::Builder;
use crate::elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use crate::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use crate::elements::{
    confidential, AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut,
    TxOutWitness,
};
use crate::error::Error;
use crate::openamp::ENCLAVE_NUMS_HEX;

/// The smallest lock time read as a Unix time. Every swap lock is a time: a
/// Sequentia height can stall while Bitcoin's clock runs.
pub const MIN_TIME_LOCK: u32 = 500_000_000;

/// The claim cut-off before `T_seq`, in seconds: a buyer's wallet never
/// broadcasts a claim (and so never reveals the secret) later than this, and
/// openampd co-signs none. The refund is keyless, so a claim revealed at the
/// last moment could be beaten by it.
pub const CLAIM_CUTOFF_SECS: u32 = 3600;

/// Everything a swap escrow's scripts commit to.
#[derive(Debug, Clone)]
pub struct SwapEscrowTerms {
    /// `H = SHA256(s)`.
    pub hash: [u8; 32],
    /// The buyer's enclave key.
    pub buyer: XOnlyPublicKey,
    /// The asset's policy key.
    pub policy: XOnlyPublicKey,
    /// The clawback key, only where the asset elected clawback.
    pub issuer: Option<XOnlyPublicKey>,
    /// The refund opens at this median time past (at least [`MIN_TIME_LOCK`]).
    pub t_seq: u32,
    /// The seller's enclave: its v1 witness program.
    pub seller_program: [u8; 32],
    /// The restricted asset.
    pub asset: AssetId,
    /// The escrowed atoms, all of which go home on a refund.
    pub value: u64,
}

/// Everything a fee pot's scripts commit to.
#[derive(Debug, Clone)]
pub struct FeePotTerms {
    /// `H = SHA256(s)`, the escrow's.
    pub hash: [u8; 32],
    /// The buyer's key.
    pub buyer: XOnlyPublicKey,
    /// The escrow's `T_seq`.
    pub t_seq: u32,
    /// The seller's payout address: witness version 0 or 1 ...
    pub seller_version: u8,
    /// ... and program (20 or 32 bytes for v0, 32 for v1).
    pub seller_program: Vec<u8>,
    /// The fee asset the pot holds.
    pub fee_asset: AssetId,
    /// The pot's atoms.
    pub value: u64,
}

/// A built escrow or pot: its scriptPubKey and each leaf with its control block.
#[derive(Debug, Clone)]
pub struct SwapTree {
    /// The P2TR scriptPubKey.
    pub script_pubkey: Script,
    /// `(name, leaf script, control block)` for every leaf.
    pub leaves: Vec<(String, Script, Vec<u8>)>,
}

impl SwapTree {
    /// The leaf script and control block of the named leaf.
    pub fn leaf(&self, name: &str) -> Result<(&Script, &[u8]), Error> {
        self.leaves
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, s, c)| (s, c.as_slice()))
            .ok_or_else(|| Error::Generic(format!("no leaf {name}")))
    }
}

fn nums() -> Result<XOnlyPublicKey, Error> {
    let b = Vec::<u8>::from_hex(ENCLAVE_NUMS_HEX)
        .map_err(|e| Error::Generic(format!("NUMS hex: {e}")))?;
    XOnlyPublicKey::from_slice(&b).map_err(|e| Error::Generic(format!("NUMS point: {e}")))
}

fn asset_bytes(asset: &AssetId) -> Vec<u8> {
    serialize(asset)
}

fn hash_lock(b: Builder, hash: &[u8; 32]) -> Builder {
    b.push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
}

fn pin(b: Builder, version: u8, program: &[u8], asset: &AssetId, value: u64) -> Builder {
    b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
        .push_opcode(OP_DUP)
        .push_opcode(OP_DUP)
        .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY)
        .push_int(i64::from(version))
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(program)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_INSPECTOUTPUTASSET)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&asset_bytes(asset))
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_INSPECTOUTPUTVALUE)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&value.to_le_bytes())
        .push_opcode(OP_EQUAL)
}

fn time_lock(b: Builder, t: u32) -> Builder {
    b.push_int(i64::from(t))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
}

fn check_sig_pair(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> Builder {
    Builder::new()
        .push_slice(&a.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(&b.serialize())
        .push_opcode(OP_CHECKSIG)
}

fn concat(a: Builder, b: Builder) -> Script {
    let mut v = a.into_script().into_bytes();
    v.extend(b.into_script().into_bytes());
    Script::from(v)
}

/// Builds a tree of named leaves in the shape of the test framework's
/// `taproot_construct` over a flat list: one or two leaves at depth 1, three as
/// `[a, [b, c]]`.
fn build(leaves: Vec<(&str, Script)>) -> Result<SwapTree, Error> {
    let depths: &[usize] = match leaves.len() {
        2 => &[1, 1],
        3 => &[1, 2, 2],
        n => {
            return Err(Error::Generic(format!(
                "a swap tree has 2 or 3 leaves, not {n}"
            )))
        }
    };
    let secp = Secp256k1::verification_only();
    let mut builder = TaprootBuilder::new();
    for ((_, script), depth) in leaves.iter().zip(depths) {
        builder = builder
            .add_leaf(*depth, script.clone())
            .map_err(|e| Error::Generic(format!("taproot builder: {e:?}")))?;
    }
    let info: TaprootSpendInfo = builder
        .finalize(&secp, nums()?)
        .map_err(|e| Error::Generic(format!("taproot finalize: {e:?}")))?;
    let script_pubkey = Script::new_v1_p2tr_tweaked(info.output_key());
    let mut out = Vec::with_capacity(leaves.len());
    for (name, script) in leaves {
        let cb = info
            .control_block(&(script.clone(), LeafVersion::default()))
            .ok_or_else(|| Error::Generic(format!("no control block for {name}")))?;
        out.push((name.to_string(), script, cb.serialize()));
    }
    Ok(SwapTree {
        script_pubkey,
        leaves: out,
    })
}

/// The swap escrow: leaves `claim`, `refund` and, with clawback, `claw`.
pub fn swap_escrow_tree(t: &SwapEscrowTerms) -> Result<SwapTree, Error> {
    if t.t_seq < MIN_TIME_LOCK {
        return Err(Error::Generic(format!(
            "T_seq {} is a height: every swap lock is a time (>= {MIN_TIME_LOCK})",
            t.t_seq
        )));
    }
    if t.value == 0 {
        return Err(Error::Generic("an escrow of zero atoms".into()));
    }
    let claim = concat(
        hash_lock(Builder::new(), &t.hash),
        check_sig_pair(&t.buyer, &t.policy),
    );
    let refund = pin(
        time_lock(Builder::new(), t.t_seq),
        1,
        &t.seller_program,
        &t.asset,
        t.value,
    )
    .into_script();
    let mut leaves = vec![("claim", claim), ("refund", refund)];
    if let Some(issuer) = &t.issuer {
        leaves.push(("claw", check_sig_pair(issuer, &t.policy).into_script()));
    }
    build(leaves)
}

/// The fee pot: leaves `claim` and `refund`.
pub fn fee_pot_tree(t: &FeePotTerms) -> Result<SwapTree, Error> {
    if t.t_seq < MIN_TIME_LOCK {
        return Err(Error::Generic(format!(
            "T_seq {} is a height: every swap lock is a time (>= {MIN_TIME_LOCK})",
            t.t_seq
        )));
    }
    let ok = match t.seller_version {
        0 => t.seller_program.len() == 20 || t.seller_program.len() == 32,
        1 => t.seller_program.len() == 32,
        _ => false,
    };
    if !ok {
        return Err(Error::Generic(
            "the pot's payout must be a v0 or v1 witness program".into(),
        ));
    }
    if t.value == 0 {
        return Err(Error::Generic("a fee pot of zero atoms".into()));
    }
    let claim = hash_lock(Builder::new(), &t.hash)
        .push_slice(&t.buyer.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let refund = pin(
        time_lock(Builder::new(), t.t_seq),
        t.seller_version,
        &t.seller_program,
        &t.fee_asset,
        t.value,
    )
    .into_script();
    build(vec![("claim", claim), ("refund", refund)])
}

/// `H = SHA256(s)` for a 32-byte secret.
pub fn secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    sha256::Hash::hash(secret).to_byte_array()
}

fn explicit_out(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

/// The buyer's claim, unsigned: the escrow at input 0 and its pot at input 1;
/// output 0 pays the escrow's whole amount to the buyer's enclave, output 1 the
/// pot less the fee to the buyer's own address, output 2 the fee in the pot's
/// asset. Every input is final, so the claim is valid at once.
#[allow(clippy::too_many_arguments)]
pub fn claim_tx(
    escrow: OutPoint,
    escrow_terms: &SwapEscrowTerms,
    buyer_enclave: Script,
    pot: OutPoint,
    pot_terms: &FeePotTerms,
    buyer_change: Script,
    fee: u64,
) -> Result<Transaction, Error> {
    if fee == 0 || fee >= pot_terms.value {
        return Err(Error::Generic(format!(
            "the fee must be between 1 and {} atoms, the pot less one",
            pot_terms.value.saturating_sub(1)
        )));
    }
    let input = |previous_output| TxIn {
        previous_output,
        sequence: Sequence::MAX,
        ..Default::default()
    };
    Ok(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(escrow), input(pot)],
        output: vec![
            explicit_out(escrow_terms.asset, escrow_terms.value, buyer_enclave),
            explicit_out(pot_terms.fee_asset, pot_terms.value - fee, buyer_change),
            explicit_out(pot_terms.fee_asset, fee, Script::new()),
        ],
    })
}

/// Completes a claim built by [`claim_tx`]: the escrow input's witness is
/// `<policy sig> <buyer sig> <s> <claim leaf> <control>`, the pot's
/// `<buyer sig> <s> <claim leaf> <control>`. Refuses a secret that does not
/// hash to the escrow's `H`.
#[allow(clippy::too_many_arguments)]
pub fn finish_claim(
    mut tx: Transaction,
    escrow: &SwapTree,
    pot: &SwapTree,
    secret: &[u8; 32],
    hash: &[u8; 32],
    policy_sig: &[u8],
    buyer_sig_escrow: &[u8],
    buyer_sig_pot: &[u8],
) -> Result<Transaction, Error> {
    if &secret_hash(secret) != hash {
        return Err(Error::Generic(
            "the secret does not hash to the escrow's H".into(),
        ));
    }
    if tx.input.len() != 2 {
        return Err(Error::Generic(
            "a claim has the escrow and its pot as inputs".into(),
        ));
    }
    let (claim, cb) = escrow.leaf("claim")?;
    tx.input[0].witness.script_witness = vec![
        policy_sig.to_vec(),
        buyer_sig_escrow.to_vec(),
        secret.to_vec(),
        claim.to_bytes(),
        cb.to_vec(),
    ];
    let (pclaim, pcb) = pot.leaf("claim")?;
    tx.input[1].witness.script_witness = vec![
        buyer_sig_pot.to_vec(),
        secret.to_vec(),
        pclaim.to_bytes(),
        pcb.to_vec(),
    ];
    Ok(tx)
}

/// Reads the secret out of a claim of `hash`: any input whose witness carries
/// a 32-byte item hashing to it (the escrow's and the pot's claims both do).
pub fn extract_secret(tx: &Transaction, hash: &[u8; 32]) -> Option<[u8; 32]> {
    tx.input.iter().find_map(|i| {
        i.witness.script_witness.iter().find_map(|item| {
            let s: [u8; 32] = item.as_slice().try_into().ok()?;
            (&secret_hash(&s) == hash).then_some(s)
        })
    })
}

/// The keyless refund's witness for a coin of `tree`: `<refund leaf> <control>`.
/// The transaction must pay each refunded coin home at the output with that
/// coin's own input index, carry `T_seq` (or later) as its lock time, and have
/// a non-final sequence on every input.
pub fn refund_witness(tree: &SwapTree) -> Result<Vec<Vec<u8>>, Error> {
    let (refund, cb) = tree.leaf("refund")?;
    Ok(vec![refund.to_bytes(), cb.to_vec()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements::hex::ToHex;
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    // Pinned from the openamp repository (openampd/internal/elements/testdata/
    // escrow_vectors.json), produced by its tools/gen_escrow_vectors.py with the
    // node's functional test framework. Copy it again when the scripts change.
    const VECTORS: &str = include_str!("../tests/data/escrow_vectors.json");

    #[derive(Deserialize)]
    struct Vector {
        hash: String,
        buyer_x: String,
        #[serde(default)]
        policy_x: String,
        #[serde(default)]
        issuer_x: String,
        t_seq: u32,
        #[serde(default)]
        seller_version: u8,
        seller_program: String,
        #[serde(default)]
        asset: String,
        #[serde(default)]
        fee_asset: String,
        value: u64,
        spk: String,
        claim_script: String,
        claim_control: String,
        refund_script: String,
        refund_control: String,
        #[serde(default)]
        claw_script: String,
        #[serde(default)]
        claw_control: String,
    }

    fn h32(s: &str) -> [u8; 32] {
        Vec::<u8>::from_hex(s).unwrap().try_into().unwrap()
    }
    fn x(s: &str) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&h32(s)).unwrap()
    }
    // The vectors carry asset ids in internal byte order.
    fn asset(s: &str) -> AssetId {
        AssetId::from_slice(&h32(s)).unwrap()
    }

    fn check(name: &str, tree: &SwapTree, v: &Vector) {
        assert_eq!(tree.script_pubkey.to_hex(), v.spk, "{name} spk");
        let mut want = vec![
            ("claim", &v.claim_script, &v.claim_control),
            ("refund", &v.refund_script, &v.refund_control),
        ];
        if !v.claw_script.is_empty() {
            want.push(("claw", &v.claw_script, &v.claw_control));
        }
        assert_eq!(tree.leaves.len(), want.len(), "{name} leaves");
        for (leaf, script, control) in want {
            let (s, c) = tree.leaf(leaf).unwrap();
            assert_eq!(&s.to_hex(), script, "{name} {leaf} script");
            assert_eq!(&c.to_hex(), control, "{name} {leaf} control");
        }
    }

    #[test]
    fn escrow_and_pot_match_the_test_framework() {
        let vs: BTreeMap<String, Vector> = serde_json::from_str(VECTORS).unwrap();
        for name in ["escrow_claw", "escrow_noclaw"] {
            let v = &vs[name];
            let t = SwapEscrowTerms {
                hash: h32(&v.hash),
                buyer: x(&v.buyer_x),
                policy: x(&v.policy_x),
                issuer: (!v.issuer_x.is_empty()).then(|| x(&v.issuer_x)),
                t_seq: v.t_seq,
                seller_program: h32(&v.seller_program),
                asset: asset(&v.asset),
                value: v.value,
            };
            check(name, &swap_escrow_tree(&t).unwrap(), v);
        }
        for name in ["pot_v0", "pot_v1"] {
            let v = &vs[name];
            let t = FeePotTerms {
                hash: h32(&v.hash),
                buyer: x(&v.buyer_x),
                t_seq: v.t_seq,
                seller_version: v.seller_version,
                seller_program: Vec::<u8>::from_hex(&v.seller_program).unwrap(),
                fee_asset: asset(&v.fee_asset),
                value: v.value,
            };
            check(name, &fee_pot_tree(&t).unwrap(), v);
        }
    }

    fn terms() -> SwapEscrowTerms {
        let vs: BTreeMap<String, Vector> = serde_json::from_str(VECTORS).unwrap();
        let v = &vs["escrow_noclaw"];
        SwapEscrowTerms {
            hash: secret_hash(&[9u8; 32]),
            buyer: x(&v.buyer_x),
            policy: x(&v.policy_x),
            issuer: None,
            t_seq: v.t_seq,
            seller_program: h32(&v.seller_program),
            asset: asset(&v.asset),
            value: 300,
        }
    }

    fn pot_terms() -> FeePotTerms {
        let t = terms();
        FeePotTerms {
            hash: t.hash,
            buyer: t.buyer,
            t_seq: t.t_seq,
            seller_version: 0,
            seller_program: vec![6u8; 20],
            fee_asset: AssetId::from_slice(&[0x22; 32]).unwrap(),
            value: 20_000,
        }
    }

    #[test]
    fn every_lock_is_a_time_and_nothing_is_empty() {
        let mut t = terms();
        t.t_seq = MIN_TIME_LOCK - 1;
        assert!(swap_escrow_tree(&t).is_err());
        let mut t = terms();
        t.value = 0;
        assert!(swap_escrow_tree(&t).is_err());
        let mut p = pot_terms();
        p.seller_version = 1;
        p.seller_program = vec![0; 20];
        assert!(fee_pot_tree(&p).is_err());
        let mut p = pot_terms();
        p.t_seq = 1;
        assert!(fee_pot_tree(&p).is_err());
    }

    #[test]
    fn a_claim_carries_the_secret_and_refuses_a_wrong_one() {
        let t = terms();
        let p = pot_terms();
        let escrow = swap_escrow_tree(&t).unwrap();
        let pot = fee_pot_tree(&p).unwrap();
        let op = |n| {
            OutPoint::new(
                crate::elements::Txid::from_str(&"11".repeat(32)).unwrap(),
                n,
            )
        };
        let tx = claim_tx(
            op(0),
            &t,
            Script::from(vec![0x51, 0x20, 0, 0]),
            op(1),
            &p,
            Script::new(),
            5000,
        )
        .unwrap();
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(300));
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(15_000));
        assert!(tx.output[2].script_pubkey.is_empty(), "the fee output");
        assert!(claim_tx(op(0), &t, Script::new(), op(1), &p, Script::new(), 20_000).is_err());
        assert!(finish_claim(
            tx.clone(),
            &escrow,
            &pot,
            &[8u8; 32],
            &t.hash,
            &[1],
            &[2],
            &[3]
        )
        .is_err());
        let done = finish_claim(tx, &escrow, &pot, &[9u8; 32], &t.hash, &[1], &[2], &[3]).unwrap();
        assert_eq!(done.input[0].witness.script_witness.len(), 5);
        assert_eq!(
            done.input[1].witness.script_witness[1],
            vec![9u8; 32],
            "s in the pot's witness"
        );
        assert_eq!(extract_secret(&done, &t.hash), Some([9u8; 32]));
        assert_eq!(extract_secret(&done, &[0u8; 32]), None);
    }
}
