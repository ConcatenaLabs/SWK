//! Swap HTLCs: the Sequentia side of a restricted (OpenAMP) asset traded for
//! on-chain BTC.
//!
//! The BTC payer (the buyer) holds a secret `s` with `H = SHA256(s)` and locks
//! its bitcoin first. The seller then locks the asset in an HTLC for that
//! buyer, and a small fee pot of an accepted fee asset beside it. The buyer
//! claims both together with `s`; the pot's witness carries `s` in plain
//! tapscript, and the seller reads it there to take the bitcoin. After `T_seq`
//! anyone can send each coin home with no key at all, so no refusal and no
//! absence can keep a coin from its owner.
//!
//! The scripts are openampd's (`openampd/internal/elements/htlc.go` in the
//! `openamp` repository), checked byte for byte against the same golden
//! vectors, which the node's test framework produced.
//!
//! HTLC, `P2TR(NUMS, [claim, [refund, claw]])` (no `claw` without clawback):
//!
//! ```text
//! claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
//!         <K_buyer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//! refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <home: the seller's enclave>
//! claw  : <K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//! ```
//!
//! Fee pot, `P2TR(NUMS, [claim, refund])`:
//!
//! ```text
//! claim : OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <K_buyer> OP_CHECKSIG
//! refund: <T_seq> OP_CHECKLOCKTIMEVERIFY OP_DROP <home: the seller's address>
//! ```
//!
//! A way home requires the coin to be spent as input 0, and output 0 to carry
//! exactly the given witness program, explicit asset and explicit value:
//!
//! ```text
//! OP_PUSHCURRENTINPUTINDEX OP_0 OP_EQUALVERIFY
//! OP_PUSHCURRENTINPUTINDEX OP_DUP OP_DUP
//! OP_INSPECTOUTPUTSCRIPTPUBKEY <version> OP_EQUALVERIFY <program> OP_EQUALVERIFY
//! OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//! OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <value, 8 bytes LE> OP_EQUAL
//! ```
//!
//! Input 0 and output 0, because a keyless path must never accept an output
//! that another covenant in the same transaction also counts as its own: a
//! refund to "the output at my own input index" would share output `2k` with a
//! SeqDEX order at input `k`, which pays its maker there. With the refund at
//! input 0 only one refund fits in a transaction, and every covenant that pays
//! relative to its own index pays outputs 2 and above from any later input.
//! Each refund is a transaction of its own.

use crate::elements::encode::serialize;
use crate::elements::hashes::{sha256, Hash};
use crate::elements::hex::FromHex;
use crate::elements::opcodes::all::*;
use crate::elements::script::Builder;
use crate::elements::secp256k1_zkp::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use crate::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use crate::elements::{
    confidential, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxOut, TxOutWitness,
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

/// Everything a swap HTLC's scripts commit to.
#[derive(Debug, Clone)]
pub struct SwapHtlcTerms {
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
    /// The locked atoms, all of which go home on a refund.
    pub value: u64,
}

/// Everything a fee pot's scripts commit to.
#[derive(Debug, Clone)]
pub struct FeePotTerms {
    /// `H = SHA256(s)`, the HTLC's.
    pub hash: [u8; 32],
    /// The buyer's key.
    pub buyer: XOnlyPublicKey,
    /// The HTLC's `T_seq`.
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

/// A built HTLC or pot: its scriptPubKey and each leaf with its control block.
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

fn home(b: Builder, version: u8, program: &[u8], asset: &AssetId, value: u64) -> Builder {
    b.push_opcode(OP_PUSHCURRENTINPUTINDEX)
        .push_int(0)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_PUSHCURRENTINPUTINDEX)
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

/// The swap HTLC: leaves `claim`, `refund` and, with clawback, `claw`.
pub fn swap_htlc_tree(t: &SwapHtlcTerms) -> Result<SwapTree, Error> {
    if t.t_seq < MIN_TIME_LOCK {
        return Err(Error::Generic(format!(
            "T_seq {} is a height: every swap lock is a time (>= {MIN_TIME_LOCK})",
            t.t_seq
        )));
    }
    if t.value == 0 {
        return Err(Error::Generic("an HTLC of zero atoms".into()));
    }
    let claim = concat(
        hash_lock(Builder::new(), &t.hash),
        check_sig_pair(&t.buyer, &t.policy),
    );
    let refund = home(
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
    let refund = home(
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

/// The buyer's claim, unsigned: the HTLC at input 0 and its pot at input 1;
/// output 0 pays the HTLC's whole amount to the buyer's enclave, output 1 the
/// pot less the fee to the buyer's own address, output 2 the fee in the pot's
/// asset. Every input is final, so the claim is valid at once.
#[allow(clippy::too_many_arguments)]
pub fn claim_tx(
    htlc: OutPoint,
    htlc_terms: &SwapHtlcTerms,
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
        input: vec![input(htlc), input(pot)],
        output: vec![
            explicit_out(htlc_terms.asset, htlc_terms.value, buyer_enclave),
            explicit_out(pot_terms.fee_asset, pot_terms.value - fee, buyer_change),
            explicit_out(pot_terms.fee_asset, fee, Script::new()),
        ],
    })
}

/// Everything [`finish_claim`] checks a claim against before it places the
/// secret: the terms both sides agreed, the coins as they are on the chain,
/// and where the asset must go.
#[derive(Debug, Clone)]
pub struct ClaimCheck<'a> {
    /// The HTLC's terms.
    pub htlc: &'a SwapHtlcTerms,
    /// Its fee pot's terms.
    pub pot: &'a FeePotTerms,
    /// The HTLC's output and the pot's output, as read from the chain, in the
    /// claim's input order: `[HTLC, pot]`.
    pub spent: &'a [TxOut],
    /// The buyer's enclave, where output 0 must pay the HTLC's whole amount.
    pub buyer_enclave: &'a Script,
    /// The chain's genesis hash, which every sighash commits to.
    pub genesis_hash: BlockHash,
    /// Now, as the later of the wallet's clock and the chain's median time
    /// past (Unix seconds). No claim is finished at or after the cut-off.
    pub now: u32,
}

/// Completes a claim built by [`claim_tx`]: the HTLC input's witness is
/// `<policy sig> <buyer sig> <s> <claim leaf> <control>`, the pot's
/// `<buyer sig> <s> <claim leaf> <control>`.
///
/// The secret is placed only into a claim that will be valid, because once a
/// claim is broadcast anyone can read the secret, and the secret unlocks the
/// buyer's bitcoin for the seller. So, before placing it, this refuses:
/// - a claim at or after the cut-off, `T_seq` less [`CLAIM_CUTOFF_SECS`]: the
///   keyless refund could then beat it;
/// - a secret that does not hash to the HTLC's `H`, or a pot of other terms;
/// - spent coins that are not the HTLC and the pot those terms build, with
///   exactly their explicit asset and amount;
/// - a transaction that does not pay the HTLC's whole amount to the buyer's
///   enclave at output 0, or that moves the asset anywhere else;
/// - any of the three signatures that does not verify over the claim's own
///   sighash: the policy key's and the buyer's on the HTLC, the buyer's on the pot.
pub fn finish_claim(
    mut tx: Transaction,
    check: &ClaimCheck<'_>,
    secret: &[u8; 32],
    policy_sig: &[u8],
    buyer_sig_htlc: &[u8],
    buyer_sig_pot: &[u8],
) -> Result<Transaction, Error> {
    let (t, p) = (check.htlc, check.pot);
    let refuse = |m: String| Err(Error::Generic(m));
    let cutoff = t.t_seq.saturating_sub(CLAIM_CUTOFF_SECS);
    if check.now >= cutoff {
        return refuse(format!(
            "the claim cut-off has passed ({cutoff}): the secret stays unrevealed, and the HTLC goes home to its seller at {}",
            t.t_seq
        ));
    }
    if secret_hash(secret) != t.hash {
        return refuse("the secret does not hash to the HTLC's H".into());
    }
    if p.hash != t.hash || p.buyer != t.buyer || p.t_seq != t.t_seq {
        return refuse("the pot's terms are not the HTLC's (hash, buyer, T_seq)".into());
    }
    if tx.input.len() != 2 || check.spent.len() != 2 {
        return refuse("a claim has the HTLC and its pot as inputs, and nothing else".into());
    }
    let htlc = swap_htlc_tree(t)?;
    let pot = fee_pot_tree(p)?;
    let explicit = |o: &TxOut| match (o.asset, o.value) {
        (confidential::Asset::Explicit(a), confidential::Value::Explicit(v)) => Some((a, v)),
        _ => None,
    };
    if check.spent[0].script_pubkey != htlc.script_pubkey
        || explicit(&check.spent[0]) != Some((t.asset, t.value))
    {
        return refuse(
            "input 0 is not the HTLC these terms build, with exactly its asset and amount".into(),
        );
    }
    if check.spent[1].script_pubkey != pot.script_pubkey
        || explicit(&check.spent[1]) != Some((p.fee_asset, p.value))
    {
        return refuse(
            "input 1 is not the pot these terms build, with exactly its asset and amount".into(),
        );
    }
    match tx.output.first() {
        Some(o)
            if &o.script_pubkey == check.buyer_enclave
                && explicit(o) == Some((t.asset, t.value)) => {}
        _ => {
            return refuse(
                "output 0 must pay the HTLC's whole amount to the buyer's enclave".into(),
            )
        }
    }
    if tx.output.iter().skip(1).any(|o| match o.asset {
        confidential::Asset::Explicit(a) => a == t.asset,
        _ => true,
    }) {
        return refuse(
            "the claim moves the asset somewhere other than output 0, or hides an asset".into(),
        );
    }
    let (claim, cb) = htlc.leaf("claim")?;
    let (pclaim, pcb) = pot.leaf("claim")?;
    let sh_htlc =
        crate::openamp::enclave_sighash(&tx, 0, check.spent, claim, cb, check.genesis_hash)?;
    let sh_pot =
        crate::openamp::enclave_sighash(&tx, 1, check.spent, pclaim, pcb, check.genesis_hash)?;
    let secp = Secp256k1::verification_only();
    let verify = |sig: &[u8], digest: &[u8; 32], key: &XOnlyPublicKey, what: &str| {
        let sig = schnorr::Signature::from_slice(sig)
            .map_err(|_| Error::Generic(format!("{what} is not a 64-byte signature")))?;
        let msg = Message::from_digest_slice(digest)
            .map_err(|e| Error::Generic(format!("sighash: {e}")))?;
        secp.verify_schnorr(&sig, &msg, key)
            .map_err(|_| Error::Generic(format!("{what} does not verify over this claim")))
    };
    verify(policy_sig, &sh_htlc, &t.policy, "the policy signature")?;
    verify(
        buyer_sig_htlc,
        &sh_htlc,
        &t.buyer,
        "the buyer's signature on the HTLC",
    )?;
    verify(
        buyer_sig_pot,
        &sh_pot,
        &t.buyer,
        "the buyer's signature on the pot",
    )?;
    tx.input[0].witness.script_witness = vec![
        policy_sig.to_vec(),
        buyer_sig_htlc.to_vec(),
        secret.to_vec(),
        claim.to_bytes(),
        cb.to_vec(),
    ];
    tx.input[1].witness.script_witness = vec![
        buyer_sig_pot.to_vec(),
        secret.to_vec(),
        pclaim.to_bytes(),
        pcb.to_vec(),
    ];
    Ok(tx)
}

/// Reads the secret out of a claim of `hash`: any input whose witness carries
/// a 32-byte item hashing to it (the HTLC's and the pot's claims both do).
pub fn extract_secret(tx: &Transaction, hash: &[u8; 32]) -> Option<[u8; 32]> {
    tx.input.iter().find_map(|i| {
        i.witness.script_witness.iter().find_map(|item| {
            let s: [u8; 32] = item.as_slice().try_into().ok()?;
            (&secret_hash(&s) == hash).then_some(s)
        })
    })
}

/// The keyless refund's witness for a coin of `tree`: `<refund leaf> <control>`.
/// The coin must be input 0 and output 0 must pay it home; the transaction
/// carries `T_seq` (or later) as its lock time and a non-final sequence on
/// every input. One refund per transaction; anyone adds fee inputs after it.
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
    // htlc_vectors.json), produced by its tools/gen_htlc_vectors.py with the
    // node's functional test framework. Copy it again when the scripts change.
    const VECTORS: &str = include_str!("../tests/data/htlc_vectors.json");

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
    fn htlc_and_pot_match_the_test_framework() {
        let vs: BTreeMap<String, Vector> = serde_json::from_str(VECTORS).unwrap();
        for name in ["htlc_claw", "htlc_noclaw"] {
            let v = &vs[name];
            let t = SwapHtlcTerms {
                hash: h32(&v.hash),
                buyer: x(&v.buyer_x),
                policy: x(&v.policy_x),
                issuer: (!v.issuer_x.is_empty()).then(|| x(&v.issuer_x)),
                t_seq: v.t_seq,
                seller_program: h32(&v.seller_program),
                asset: asset(&v.asset),
                value: v.value,
            };
            check(name, &swap_htlc_tree(&t).unwrap(), v);
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

    fn terms() -> SwapHtlcTerms {
        let vs: BTreeMap<String, Vector> = serde_json::from_str(VECTORS).unwrap();
        let v = &vs["htlc_noclaw"];
        SwapHtlcTerms {
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
        assert!(swap_htlc_tree(&t).is_err());
        let mut t = terms();
        t.value = 0;
        assert!(swap_htlc_tree(&t).is_err());
        let mut p = pot_terms();
        p.seller_version = 1;
        p.seller_program = vec![0; 20];
        assert!(fee_pot_tree(&p).is_err());
        let mut p = pot_terms();
        p.t_seq = 1;
        assert!(fee_pot_tree(&p).is_err());
    }

    // The vectors' buyer and policy keys are the x-only keys of these secrets
    // (tools/gen_htlc_vectors.py: det(4) and det(2)).
    fn keypair(b: u8) -> crate::elements::secp256k1_zkp::Keypair {
        crate::elements::secp256k1_zkp::Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32])
            .unwrap()
    }

    struct Claim {
        t: SwapHtlcTerms,
        p: FeePotTerms,
        tx: Transaction,
        spent: Vec<TxOut>,
        enclave: Script,
        genesis: BlockHash,
    }

    fn claim() -> Claim {
        let t = terms();
        let p = pot_terms();
        let op = |n| {
            OutPoint::new(
                crate::elements::Txid::from_str(&"11".repeat(32)).unwrap(),
                n,
            )
        };
        let enclave = Script::from(vec![0x51, 0x20, 7, 7]);
        let tx = claim_tx(op(0), &t, enclave.clone(), op(1), &p, Script::new(), 5000).unwrap();
        let spent = vec![
            explicit_out(t.asset, t.value, swap_htlc_tree(&t).unwrap().script_pubkey),
            explicit_out(
                p.fee_asset,
                p.value,
                fee_pot_tree(&p).unwrap().script_pubkey,
            ),
        ];
        let genesis = BlockHash::from_str(&"ab".repeat(32)).unwrap();
        Claim {
            t,
            p,
            tx,
            spent,
            enclave,
            genesis,
        }
    }

    impl Claim {
        fn check(&self, now: u32) -> ClaimCheck<'_> {
            ClaimCheck {
                htlc: &self.t,
                pot: &self.p,
                spent: &self.spent,
                buyer_enclave: &self.enclave,
                genesis_hash: self.genesis,
                now,
            }
        }
        // (policy sig, buyer sig on the HTLC, buyer sig on the pot), each over
        // this claim's own sighash.
        fn sigs(&self, tx: &Transaction) -> [Vec<u8>; 3] {
            let secp = Secp256k1::new();
            let h = swap_htlc_tree(&self.t).unwrap();
            let p = fee_pot_tree(&self.p).unwrap();
            let (l, c) = h.leaf("claim").unwrap();
            let (pl, pc) = p.leaf("claim").unwrap();
            let sh =
                crate::openamp::enclave_sighash(tx, 0, &self.spent, l, c, self.genesis).unwrap();
            let psh =
                crate::openamp::enclave_sighash(tx, 1, &self.spent, pl, pc, self.genesis).unwrap();
            let sign = |d: [u8; 32], k: u8| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(d), &keypair(k))
                    .as_ref()
                    .to_vec()
            };
            [sign(sh, 2), sign(sh, 4), sign(psh, 4)]
        }
        fn early(&self) -> u32 {
            self.t.t_seq - CLAIM_CUTOFF_SECS - 1
        }
    }

    #[test]
    fn a_claim_carries_the_secret_once_everything_verifies() {
        let c = claim();
        assert_eq!(c.tx.output[0].value, confidential::Value::Explicit(300));
        assert_eq!(c.tx.output[1].value, confidential::Value::Explicit(15_000));
        assert!(c.tx.output[2].script_pubkey.is_empty(), "the fee output");
        let [ps, bs, bps] = c.sigs(&c.tx);
        let done = finish_claim(
            c.tx.clone(),
            &c.check(c.early()),
            &[9u8; 32],
            &ps,
            &bs,
            &bps,
        )
        .unwrap();
        assert_eq!(done.input[0].witness.script_witness.len(), 5);
        assert_eq!(
            done.input[1].witness.script_witness[1],
            vec![9u8; 32],
            "s in the pot's witness"
        );
        assert_eq!(extract_secret(&done, &c.t.hash), Some([9u8; 32]));
        assert_eq!(extract_secret(&done, &[0u8; 32]), None);
    }

    // Proof review PV4 S1 and S2: the secret is never placed into a claim
    // that would fail, nor after the cut-off.
    #[test]
    fn the_secret_goes_into_no_claim_that_would_fail() {
        let c = claim();
        let [ps, bs, bps] = c.sigs(&c.tx);
        let s = [9u8; 32];
        // Each case must be refused for its own reason, not another one.
        let refused = |tx: Transaction,
                       chk: &ClaimCheck<'_>,
                       sigs: [&[u8]; 3],
                       secret: &[u8; 32],
                       want: &str| {
            let err = finish_claim(tx, chk, secret, sigs[0], sigs[1], sigs[2])
                .expect_err(want)
                .to_string();
            assert!(err.contains(want), "want {want:?}, got {err:?}");
        };
        let good = [ps.as_slice(), bs.as_slice(), bps.as_slice()];
        // The signatures the old kit accepted: arbitrary bytes.
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            [&[1], &[2], &[3]],
            &s,
            "not a 64-byte signature",
        );
        // Each signature swapped for a valid one by the wrong key or over the wrong input.
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            [&bs, &bs, &bps],
            &s,
            "the policy signature does not verify",
        );
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            [&ps, &ps, &bps],
            &s,
            "the buyer's signature on the HTLC does not verify",
        );
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            [&ps, &bs, &bs],
            &s,
            "the buyer's signature on the pot does not verify",
        );
        // Signatures over another transaction (a different fee).
        let mut other = c.tx.clone();
        other.output[1].value = confidential::Value::Explicit(14_000);
        other.output[2].value = confidential::Value::Explicit(6_000);
        let [ops, obs, obps] = c.sigs(&other);
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            [&ops, &obs, &obps],
            &s,
            "the policy signature does not verify",
        );
        // A wrong secret.
        refused(
            c.tx.clone(),
            &c.check(c.early()),
            good,
            &[8u8; 32],
            "does not hash to the HTLC's H",
        );
        // The cut-off: one second before passes, at it is refused.
        assert!(finish_claim(
            c.tx.clone(),
            &c.check(c.t.t_seq - CLAIM_CUTOFF_SECS - 1),
            &s,
            &ps,
            &bs,
            &bps
        )
        .is_ok());
        refused(
            c.tx.clone(),
            &c.check(c.t.t_seq - CLAIM_CUTOFF_SECS),
            good,
            &s,
            "cut-off has passed",
        );
        refused(
            c.tx.clone(),
            &c.check(c.t.t_seq + 1),
            good,
            &s,
            "cut-off has passed",
        );
        // Spent coins that are not the HTLC and pot the terms build.
        let mut c2 = claim();
        c2.spent[0].script_pubkey = Script::from(vec![0x51, 0x20, 1]);
        refused(
            c2.tx.clone(),
            &c2.check(c2.early()),
            good,
            &s,
            "input 0 is not the HTLC",
        );
        let mut c2 = claim();
        c2.spent[0].value = confidential::Value::Explicit(299);
        refused(
            c2.tx.clone(),
            &c2.check(c2.early()),
            good,
            &s,
            "input 0 is not the HTLC",
        );
        let mut c2 = claim();
        c2.spent[1].script_pubkey = Script::from(vec![0x51, 0x20, 1]);
        refused(
            c2.tx.clone(),
            &c2.check(c2.early()),
            good,
            &s,
            "input 1 is not the pot",
        );
        // A destination other than the buyer's enclave, or the asset elsewhere.
        let c3 = claim();
        let other_enclave = Script::from(vec![0x51, 0x20, 8, 8]);
        let chk = ClaimCheck {
            buyer_enclave: &other_enclave,
            ..c3.check(c3.early())
        };
        refused(c3.tx.clone(), &chk, good, &s, "output 0 must pay");
        let mut tx = c3.tx.clone();
        tx.output.push(explicit_out(c3.t.asset, 1, Script::new()));
        refused(
            tx,
            &c3.check(c3.early()),
            good,
            &s,
            "somewhere other than output 0",
        );
        // A pot of other terms, and a third input.
        let mut c4 = claim();
        c4.p.hash = [0u8; 32];
        refused(
            c4.tx.clone(),
            &c4.check(c4.early()),
            good,
            &s,
            "the pot's terms are not the HTLC's",
        );
        let mut tx = c.tx.clone();
        tx.input.push(tx.input[0].clone());
        refused(
            tx,
            &c.check(c.early()),
            good,
            &s,
            "the HTLC and its pot as inputs",
        );
    }
}
