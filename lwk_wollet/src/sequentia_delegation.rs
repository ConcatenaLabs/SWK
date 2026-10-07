//! SEQUENTIA staking pools: delegation records, from a light wallet.
//!
//! A staker (the **controller**) lends its stake weight to a **signer** (a pool
//! operator) by funding one small bare output, the delegation record:
//!
//! ```text
//! <"SEQDEL"> OP_DROP <signer> OP_DROP <controller> OP_CHECKSIG
//! ```
//!
//! While that record is unspent the controller's whole stake weight counts for
//! the signer, who must produce and sign the blocks. The staked coins are not
//! touched by any of this, and the signer never appears in the staking output's
//! spending condition, so a pool can never spend a delegator's stake.
//!
//! A bare script matches no descriptor, so the wallet's PSET signer will neither
//! spend a record nor spend the coin of the staking key that authorises one.
//! This module builds and signs both. Without it a light wallet could not
//! leave a pool, which would turn the one property that makes delegation safe
//! (exit is unilateral and immediate) into a promise the wallet could not keep.
//!
//! # Creating a record
//!
//! A delegation record must be created by a transaction that spends a coin of
//! its controller, so that nobody can lend weight in another key's name. A
//! record naming the controller as its own signer is refused, and so is a
//! record spent and re-created identically in one block. The wallet's own coins
//! belong to its descriptor keys, not to the staking key, so creating a first
//! record takes two transactions, mined together:
//!
//! 1. an ordinary payment from the wallet to the controller's `P2WPKH`
//!    ([`crate::TxBuilder::add_record_authorization`]);
//! 2. the record, funded by that coin and nothing else
//!    ([`build_delegation_create_tx`]), which may spend it unconfirmed.
//!
//! A wallet that already holds a coin of the controller (a split pool pays its
//! delegators to that key's `P2WPKH`) passes that coin to the second step and
//! skips the first.
//!
//! # Spending a record
//!
//! Two spends, one shape ([`build_delegation_spend_tx`]):
//!
//! * **reclaim** - spend the record back to the wallet. The delegation ends at
//!   that confirmation.
//! * **re-point** - spend it and create a new record for a different signer in
//!   the SAME transaction. This is not an optimisation. Consensus permits at
//!   most one unspent record per controller, so a reclaim and a fresh
//!   delegation broadcast as two loose transactions could be mined in the order
//!   that leaves two live records, which invalidates the block carrying the
//!   second. One transaction cannot be mis-ordered against itself. The record
//!   it spends is the controller's, which is what authorises the new one.
//!
//! The record pays its own fee out of its own value, so neither spend needs to
//! select a wallet coin, which is what keeps this independent of the PSET path.
//! Its signature is the one the chain wants at the next block
//! ([`crate::sequentia_stake_records`]).

use elements::encode::serialize_hex;
use elements::hex::FromHex;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};
use elements::{
    confidential, opcodes, AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness, Txid,
};
use std::str::FromStr;

use crate::error::Error;
use crate::sequentia_stake_records::{
    key_coin_script, sign_stake_record_input, RecordCreatePlan, StakeRecordSigning,
};

/// The record's marker, byte for byte the node's `DELEGATION_MARKER`.
const DELEGATION_MARKER: &[u8; 6] = b"SEQDEL";

/// The canonical Sequentia delegation-record script, a byte-for-byte mirror of
/// the node's `BuildDelegationScript`:
/// `<"SEQDEL"> OP_DROP <signer> OP_DROP <controller> OP_CHECKSIG`.
///
/// Note the order: the SIGNER is pushed first and the CONTROLLER last, because
/// the controller is the key the final `OP_CHECKSIG` tests. Only the controller
/// can spend the record; the signer is inert data.
pub fn sequentia_delegation_script(controller_pubkey: &[u8], signer_pubkey: &[u8]) -> Script {
    elements::script::Builder::new()
        .push_slice(DELEGATION_MARKER)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(signer_pubkey)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(controller_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// Everything needed to spend one delegation record: reclaiming it, or
/// re-pointing it at another signer.
#[derive(Debug, Clone)]
pub struct DelegationSpendPlan {
    /// The record output being spent.
    pub record_txid: Txid,
    /// Its index in that transaction.
    pub record_vout: u32,
    /// Its explicit value. A record is always unblinded (it is a bare script),
    /// so this is readable from the chain.
    pub record_value: u64,
    /// The policy asset (SEQ); a record only ever holds that.
    pub asset: AssetId,
    /// The signer named in the record being spent. Needed to rebuild the exact
    /// script, which is both the sighash subscript and the thing being satisfied.
    pub current_signer: Vec<u8>,
    /// The controller's secret key. It alone can spend the record.
    pub controller_secret: SecretKey,
    /// `Some(new signer)` re-points the delegation, `None` reclaims it.
    pub rotate_to: Option<Vec<u8>>,
    /// Where reclaimed coins go. Ignored when re-pointing, since the value goes
    /// straight back into the new record.
    pub reclaim_spk: Script,
    /// Network fee, taken out of the record's own value.
    pub fee_atoms: u64,
    /// The dust floor the resulting output must clear to relay. A record funded
    /// with barely more than the floor has nothing left after one fee, so this
    /// is a reachable refusal rather than a theoretical one. 0 disables it.
    pub dust_floor: u64,
    /// nLockTime, normally the current tip (anti-fee-sniping).
    pub locktime: u32,
    /// The signature the next block wants
    /// ([`StakeRecordSigning::for_next_block`]).
    pub signing: StakeRecordSigning,
}

/// Build and sign the spend of a delegation record. Returns `(raw_hex, txid)`.
///
/// The transaction is self-contained: one input (the record), one output (the
/// new record when re-pointing, otherwise the reclaimed coins), and the explicit
/// fee output Elements requires.
pub fn build_delegation_spend_tx(plan: &DelegationSpendPlan) -> Result<(String, Txid), Error> {
    let secp = Secp256k1::new();

    if plan.fee_atoms >= plan.record_value {
        return Err(Error::Generic(format!(
            "the delegation record holds {} atoms, which does not cover the {} atom fee to spend it",
            plan.record_value, plan.fee_atoms
        )));
    }
    let out_value = plan.record_value - plan.fee_atoms;
    if out_value < plan.dust_floor {
        return Err(Error::Generic(format!(
            "this would leave {} atoms, below the {} the network will relay; the record cannot pay its own fee \
             and still leave a usable output. The delegation is unaffected, and the stake was never at risk",
            out_value, plan.dust_floor
        )));
    }

    // The controller key must be the one the record actually commits to,
    // otherwise the signature cannot satisfy it. Catch a wrong derivation here,
    // with a message that says so, rather than broadcasting an unspendable
    // transaction and watching it be rejected.
    let controller_pk =
        elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &plan.controller_secret);
    let controller_bytes = controller_pk.serialize().to_vec();
    let record_script = sequentia_delegation_script(&controller_bytes, &plan.current_signer);

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(plan.locktime),
        input: vec![TxIn {
            previous_output: OutPoint::new(plan.record_txid, plan.record_vout),
            is_pegin: false,
            script_sig: Script::new(),
            // A record carries no relative lock, so nothing forces a sequence.
            // Stay replaceable, so a fee that turns out too low can be bumped.
            sequence: Sequence::from_consensus(0xffff_fffd),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output: vec![],
    };

    let destination = match &plan.rotate_to {
        Some(new_signer) => {
            if new_signer.as_slice() == plan.current_signer.as_slice() {
                return Err(Error::Generic(
                    "re-pointing to the signer the record already names would change nothing"
                        .into(),
                ));
            }
            if new_signer.as_slice() == controller_bytes.as_slice() {
                return Err(Error::Generic(
                    "delegating to the controller itself is what already happens with no record at all; reclaim instead"
                        .into(),
                ));
            }
            sequentia_delegation_script(&controller_bytes, new_signer)
        }
        None => plan.reclaim_spk.clone(),
    };
    tx.output.push(TxOut {
        asset: confidential::Asset::Explicit(plan.asset),
        value: confidential::Value::Explicit(out_value),
        nonce: confidential::Nonce::Null,
        script_pubkey: destination,
        witness: TxOutWitness::default(),
    });
    tx.output.push(TxOut::new_fee(plan.fee_atoms, plan.asset));

    // The scriptSig is nothing but the signature push, over the hash the next
    // block wants - the same shape the node's own reclaim builds.
    sign_stake_record_input(
        &mut tx,
        0,
        &record_script,
        confidential::Value::Explicit(plan.record_value),
        &plan.controller_secret,
        plan.signing,
    )?;

    let txid = tx.txid();
    Ok((serialize_hex(&tx), txid))
}

/// Everything needed to create a delegation record from a coin of its
/// controller.
#[derive(Debug, Clone)]
pub struct DelegationCreatePlan {
    /// The controller's coin: an explicit Sequence token output paying the
    /// controller's `P2WPKH` ([`crate::sequentia_stake_records::key_coin_script`]).
    pub coin_txid: Txid,
    /// Its index in that transaction.
    pub coin_vout: u32,
    /// Its explicit value.
    pub coin_value: u64,
    /// The Sequence token's asset id; the coin and the record hold it.
    pub asset: AssetId,
    /// The controller's secret key, which alone can spend the coin and,
    /// later, the record.
    pub controller_secret: SecretKey,
    /// The signer (pool) the record lends the controller's weight to.
    pub signer: Vec<u8>,
    /// The record's own value, recoverable when it is reclaimed.
    pub record_value: u64,
    /// Where whatever the coin holds beyond the record and the fee goes. Unused
    /// when nothing is left over.
    pub change_spk: Script,
    /// Network fee, taken out of the coin.
    pub fee_atoms: u64,
    /// The dust floor the record and any change must clear to relay. 0
    /// disables it.
    pub dust_floor: u64,
    /// nLockTime, normally the current tip.
    pub locktime: u32,
}

/// Build and sign the transaction that creates a delegation record, funded by
/// a coin of its controller and nothing else. Returns `(raw_hex, txid)`.
///
/// Spending the controller's coin is what authorises the record
/// ([`crate::sequentia_stake_records::build_record_create_tx`]); the
/// transaction may spend it unconfirmed.
pub fn build_delegation_create_tx(plan: &DelegationCreatePlan) -> Result<(String, Txid), Error> {
    let secp = Secp256k1::new();
    let controller =
        elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &plan.controller_secret)
            .serialize()
            .to_vec();
    if plan.signer.as_slice() == controller.as_slice() {
        return Err(Error::Generic(
            "delegating to the controller itself is what already happens with no record at all; the network refuses it"
                .into(),
        ));
    }
    crate::sequentia_stake_records::build_record_create_tx(&RecordCreatePlan {
        coin_txid: plan.coin_txid,
        coin_vout: plan.coin_vout,
        coin_value: plan.coin_value,
        asset: plan.asset,
        key_secret: plan.controller_secret,
        record_script: sequentia_delegation_script(&controller, &plan.signer),
        record_value: plan.record_value,
        change_spk: plan.change_spk.clone(),
        fee_atoms: plan.fee_atoms,
        dust_floor: plan.dust_floor,
        locktime: plan.locktime,
    })
}

/// Parse a 33-byte compressed secp256k1 public key from hex, rejecting anything
/// that is not one. Every pubkey crossing this boundary comes from a pool
/// listing or a user paste, so it is checked rather than trusted.
pub fn delegation_pubkey_from_hex(hex: &str, what: &str) -> Result<Vec<u8>, Error> {
    let bytes = Vec::<u8>::from_hex(hex.trim())
        .map_err(|e| Error::Generic(format!("invalid {what} public key hex: {e}")))?;
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(Error::Generic(format!(
            "{what} must be a 33-byte compressed public key (66 hex characters starting 02 or 03)"
        )));
    }
    elements::secp256k1_zkp::PublicKey::from_slice(&bytes)
        .map_err(|e| Error::Generic(format!("invalid {what} public key: {e}")))?;
    Ok(bytes)
}

/// Parse a delegation-record script back into `(controller, signer)`, the exact
/// inverse of [`sequentia_delegation_script`]. Used to recognise a record found
/// on-chain, so a restored wallet can discover a delegation it no longer has any
/// local note of.
pub fn parse_delegation_script(script: &Script) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut instructions = script.instructions();
    let marker = instructions.next()?.ok()?.push_bytes()?.to_vec();
    if marker.as_slice() != DELEGATION_MARKER {
        return None;
    }
    if instructions.next()?.ok()?.push_bytes().is_some() {
        return None; // expected OP_DROP
    }
    let signer = instructions.next()?.ok()?.push_bytes()?.to_vec();
    if instructions.next()?.ok()?.push_bytes().is_some() {
        return None; // expected OP_DROP
    }
    let controller = instructions.next()?.ok()?.push_bytes()?.to_vec();
    // Trailing OP_CHECKSIG, and nothing after it.
    instructions.next()?.ok()?;
    if instructions.next().is_some() {
        return None;
    }
    if signer.len() != 33 || controller.len() != 33 {
        return None;
    }
    Some((controller, signer))
}

/// The `P2WPKH` script of a compressed public key: the reclaim destination a
/// light wallet may use when it takes its delegation back, and the kind of
/// coin of the controller a record's creation spends.
pub fn p2wpkh_script_pubkey(compressed_pubkey: &[u8]) -> Script {
    key_coin_script(compressed_pubkey)
}

/// Parse a txid from hex.
pub fn delegation_txid_from_hex(hex: &str) -> Result<Txid, Error> {
    Txid::from_str(hex.trim()).map_err(|e| Error::Generic(format!("invalid txid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::bitcoin::hashes::Hash as _;
    use elements::hashes::hash160;
    use elements::secp256k1_zkp::Message;
    use elements::sighash::SighashCache;
    use elements::EcdsaSighashType;

    fn key(byte: u8) -> (SecretKey, Vec<u8>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &sk);
        (sk, pk.serialize().to_vec())
    }

    #[test]
    fn script_matches_the_nodes_layout() {
        let (_, controller) = key(1);
        let (_, signer) = key(2);
        let script = sequentia_delegation_script(&controller, &signer);
        let bytes = script.as_bytes();
        // <6-byte push> SEQDEL OP_DROP <33-push> signer OP_DROP <33-push> controller OP_CHECKSIG
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[1..7], DELEGATION_MARKER);
        assert_eq!(bytes[7], opcodes::all::OP_DROP.into_u8());
        assert_eq!(bytes[8], 33);
        assert_eq!(
            &bytes[9..42],
            signer.as_slice(),
            "the signer is pushed FIRST"
        );
        assert_eq!(bytes[42], opcodes::all::OP_DROP.into_u8());
        assert_eq!(bytes[43], 33);
        assert_eq!(
            &bytes[44..77],
            controller.as_slice(),
            "the controller is what OP_CHECKSIG tests"
        );
        assert_eq!(bytes[77], opcodes::all::OP_CHECKSIG.into_u8());
        assert_eq!(bytes.len(), 78);
    }

    #[test]
    fn matches_the_nodes_pinned_vector() {
        // A cross-implementation vector, asserted identically by the node in
        // test/functional/feature_pos_pools.py. Two independent implementations
        // of one consensus script is exactly where a silent divergence hides: a
        // swapped push order still looks like a valid script, still relays, and
        // simply credits the stake weight to the wrong key. Neither side can
        // drift alone while both assert this.
        let (_, controller) = key(7);
        let (_, signer) = key(8);
        assert_eq!(
            elements::hex::ToHex::to_hex(controller.as_slice()),
            "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
        );
        assert_eq!(
            elements::hex::ToHex::to_hex(signer.as_slice()),
            "03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b"
        );
        let script = sequentia_delegation_script(&controller, &signer);
        let expected = format!(
            "06{}75 21{}75 21{}ac",
            elements::hex::ToHex::to_hex(DELEGATION_MARKER.as_slice()),
            elements::hex::ToHex::to_hex(signer.as_slice()),
            elements::hex::ToHex::to_hex(controller.as_slice()),
        )
        .replace(' ', "");
        assert_eq!(elements::hex::ToHex::to_hex(script.as_bytes()), expected);
        assert_eq!(
            expected,
            "0653455144454c752103f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b752102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac"
        );
    }

    #[test]
    fn parse_is_the_inverse_of_build() {
        let (_, controller) = key(3);
        let (_, signer) = key(4);
        let script = sequentia_delegation_script(&controller, &signer);
        let (c, s) = parse_delegation_script(&script).expect("should parse");
        assert_eq!(c, controller);
        assert_eq!(s, signer);
    }

    #[test]
    fn parse_rejects_other_scripts() {
        assert!(parse_delegation_script(&Script::new()).is_none());
        let (_, pk) = key(5);
        // A staking script, which is the other bare script in play.
        let stake = elements::script::Builder::new()
            .push_int(1000)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_slice(&pk)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(parse_delegation_script(&stake).is_none());
    }

    fn plan(rotate_to: Option<Vec<u8>>) -> (DelegationSpendPlan, Vec<u8>) {
        let (controller_sk, controller) = key(7);
        let (_, signer) = key(8);
        (
            DelegationSpendPlan {
                record_txid: Txid::from_slice(&[9u8; 32]).unwrap(),
                record_vout: 1,
                record_value: 100_000,
                asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
                current_signer: signer,
                controller_secret: controller_sk,
                rotate_to,
                reclaim_spk: p2wpkh_script_pubkey(&controller),
                fee_atoms: 1_000,
                dust_floor: 1_000,
                locktime: 500,
                signing: StakeRecordSigning::SegwitV0,
            },
            controller,
        )
    }

    #[test]
    fn reclaim_spends_the_record_to_the_wallet() {
        let (p, controller) = plan(None);
        let (raw, _txid) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2, "destination + the explicit fee output");
        assert_eq!(
            tx.output[0].script_pubkey,
            p2wpkh_script_pubkey(&controller)
        );
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(99_000));
        assert!(tx.output[1].is_fee());
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(1_000));
        assert!(
            !tx.input[0].script_sig.is_empty(),
            "the record must be signed"
        );
    }

    #[test]
    fn repoint_spends_and_recreates_in_one_transaction() {
        let (_, new_signer) = key(11);
        let (p, controller) = plan(Some(new_signer.clone()));
        let (raw, _) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        // The whole point: the old record is consumed and the new one created by
        // the SAME transaction, so no block can ever hold two for one controller.
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 1);
        let (c, s) =
            parse_delegation_script(&tx.output[0].script_pubkey).expect("output 0 is a record");
        assert_eq!(c, controller);
        assert_eq!(s, new_signer);
    }

    #[test]
    fn refuses_a_fee_the_record_cannot_pay() {
        let (mut p, _) = plan(None);
        p.fee_atoms = p.record_value;
        assert!(build_delegation_spend_tx(&p).is_err());
    }

    #[test]
    fn refuses_an_output_below_the_relay_floor() {
        // Reachable, not theoretical: a record funded with barely more than the
        // dust floor has nothing left once it has paid one fee, and the
        // resulting transaction would be rejected by every relay.
        let (mut p, _) = plan(None);
        p.record_value = 1_500;
        p.fee_atoms = 1_000;
        p.dust_floor = 1_000; // leaves 500
        let e = build_delegation_spend_tx(&p).unwrap_err().to_string();
        assert!(e.contains("relay"), "unexpected error: {e}");
        // The stake is never involved in any of this, and the message says so.
        assert!(
            e.contains("stake was never at risk"),
            "unexpected error: {e}"
        );
    }

    #[test]
    fn refuses_a_pointless_or_self_repoint() {
        let (p, _) = plan(None);
        let same = DelegationSpendPlan {
            rotate_to: Some(p.current_signer.clone()),
            ..p.clone()
        };
        assert!(
            build_delegation_spend_tx(&same).is_err(),
            "re-pointing to the same signer"
        );

        let secp = Secp256k1::new();
        let controller =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &p.controller_secret)
                .serialize()
                .to_vec();
        let to_self = DelegationSpendPlan {
            rotate_to: Some(controller),
            ..p.clone()
        };
        assert!(
            build_delegation_spend_tx(&to_self).is_err(),
            "re-pointing at yourself"
        );
    }

    #[test]
    fn signature_satisfies_the_record_script() {
        // The signature must verify against the exact script the record commits
        // to, under the hash the chain wants. This is the check that catches a
        // wrong sighash or a mixed-up controller/signer order, which would
        // otherwise only show up as a rejected broadcast.
        for signing in [StakeRecordSigning::Legacy, StakeRecordSigning::SegwitV0] {
            let (mut p, controller) = plan(None);
            p.signing = signing;
            let (raw, _) = build_delegation_spend_tx(&p).unwrap();
            let tx: Transaction =
                elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
            let script = sequentia_delegation_script(&controller, &p.current_signer);
            let sighash = crate::sequentia_stake_records::stake_record_sighash(
                &tx,
                0,
                &script,
                confidential::Value::Explicit(p.record_value),
                signing,
            )
            .unwrap();
            crate::sequentia_stake_records::tests::verify_single_push(
                &tx,
                0,
                &sighash,
                &controller,
            );
        }
    }

    #[test]
    fn the_two_signatures_differ_and_only_the_second_commits_to_the_amount() {
        let (p, controller) = plan(None);
        let (raw, _) = build_delegation_spend_tx(&p).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        let script = sequentia_delegation_script(&controller, &p.current_signer);
        let hash = |value: u64, signing| {
            crate::sequentia_stake_records::stake_record_sighash(
                &tx,
                0,
                &script,
                confidential::Value::Explicit(value),
                signing,
            )
            .unwrap()
        };
        let v2 = StakeRecordSigning::SegwitV0;
        let legacy = StakeRecordSigning::Legacy;
        assert_ne!(hash(p.record_value, v2), hash(p.record_value, legacy));
        assert_ne!(
            hash(p.record_value, v2),
            hash(p.record_value + 1, v2),
            "the amount is committed"
        );
        assert_eq!(
            hash(p.record_value, legacy),
            hash(p.record_value + 1, legacy),
            "the legacy hash ignores it"
        );
    }

    #[test]
    fn matches_the_nodes_signed_vectors() {
        // The reclaim of `plan(None)`, built and signed by the node's own test
        // framework (test/functional/test_framework/script.py,
        // `PosRecordSignatureHash`, with RFC 6979 low-S signing) for each
        // generation of stake records. The kit must produce the same hash and
        // the same transaction byte for byte: a hash that differs in one
        // committed field still yields a well-formed signature, which the
        // chain refuses only at broadcast.
        let vectors = [
            (
                StakeRecordSigning::Legacy,
                "4dac157ced649ca73c2363270ac2c66c2ecbb542e7f7bcdde404d5af31c9c2f0",
                "02000000000109090909090909090909090909090909090909090909090909090909090909090100000049483045022100a954f962ea9741d1d5fbae4ba639aed176b83226f0238307e749be77377125b402204b54732a976c4382effed5b928254e720346828a2b0af315825e92ee7307dbad01fdffffff020103030303030303030303030303030303030303030303030303030303030303030100000000000182b800160014a3c6b1ee4a49d9f2af3b3802974744fba924164a0103030303030303030303030303030303030303030303030303030303030303030100000000000003e80000f4010000",
            ),
            (
                StakeRecordSigning::SegwitV0,
                "0c3d13a49395473dfc335bbae3cb4d429c3f2d6addbe6b5a4fd9cd7844b36b75",
                "020000000001090909090909090909090909090909090909090909090909090909090909090901000000484730440220723cb39f64b3a4192cacbf0d77dfd79686675458c2dbfcda5646525e9a63c4b102205e41a12d8e7d5a71fe1d69b16da0a7d7e43376c49636d8ce745cdc9f952004c701fdffffff020103030303030303030303030303030303030303030303030303030303030303030100000000000182b800160014a3c6b1ee4a49d9f2af3b3802974744fba924164a0103030303030303030303030303030303030303030303030303030303030303030100000000000003e80000f4010000",
            ),
        ];
        for (signing, sighash_hex, raw_hex) in vectors {
            let (mut p, controller) = plan(None);
            p.signing = signing;
            let (raw, _) = build_delegation_spend_tx(&p).unwrap();
            let tx: Transaction =
                elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
            let sighash = crate::sequentia_stake_records::stake_record_sighash(
                &tx,
                0,
                &sequentia_delegation_script(&controller, &p.current_signer),
                confidential::Value::Explicit(p.record_value),
                signing,
            )
            .unwrap();
            assert_eq!(
                elements::hex::ToHex::to_hex(sighash.as_slice()),
                sighash_hex,
                "{signing:?}"
            );
            assert_eq!(raw, raw_hex, "{signing:?}");
        }
    }

    fn create_plan() -> (DelegationCreatePlan, Vec<u8>) {
        let (controller_sk, controller) = key(7);
        let (_, signer) = key(8);
        (
            DelegationCreatePlan {
                coin_txid: Txid::from_slice(&[10u8; 32]).unwrap(),
                coin_vout: 2,
                coin_value: 101_000,
                asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
                controller_secret: controller_sk,
                signer,
                record_value: 100_000,
                change_spk: p2wpkh_script_pubkey(&controller),
                fee_atoms: 1_000,
                dust_floor: 1_000,
                locktime: 7,
            },
            controller,
        )
    }

    #[test]
    fn create_spends_the_controllers_coin_into_the_record() {
        let (p, controller) = create_plan();
        let (raw, _) = build_delegation_create_tx(&p).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.input.len(), 1, "the controller's coin and nothing else");
        assert_eq!(tx.input[0].previous_output, OutPoint::new(p.coin_txid, 2));
        assert_eq!(
            tx.output.len(),
            2,
            "the record and the fee: nothing left over"
        );
        let (c, s) = parse_delegation_script(&tx.output[0].script_pubkey).unwrap();
        assert_eq!(c, controller);
        assert_eq!(s, p.signer);
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(100_000));
        assert!(tx.output[1].is_fee());

        // The witness is a P2WPKH spend of the controller's key.
        let wit = &tx.input[0].witness.script_witness;
        assert_eq!(wit.len(), 2);
        assert_eq!(wit[1], controller);
        assert!(tx.input[0].script_sig.is_empty());
        let pkh = hash160::Hash::hash(&controller).to_byte_array();
        let code = elements::script::Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&pkh)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        let sighash = SighashCache::new(&tx).segwitv0_sighash(
            0,
            &code,
            confidential::Value::Explicit(p.coin_value),
            EcdsaSighashType::All,
        );
        let sig = elements::secp256k1_zkp::ecdsa::Signature::from_der(&wit[0][..wit[0].len() - 1])
            .unwrap();
        Secp256k1::new()
            .verify_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &sig,
                &elements::secp256k1_zkp::PublicKey::from_slice(&controller).unwrap(),
            )
            .expect("the controller's coin is signed by the controller");
    }

    #[test]
    fn create_returns_change_and_refuses_what_the_network_would() {
        let (mut p, controller) = create_plan();
        p.coin_value = 150_000;
        let (raw, _) = build_delegation_create_tx(&p).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.output.len(), 3);
        assert_eq!(
            tx.output[1].script_pubkey,
            p2wpkh_script_pubkey(&controller)
        );
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(49_000));

        p.coin_value = 101_500; // 500 atoms of change, below the floor
        assert!(build_delegation_create_tx(&p)
            .unwrap_err()
            .to_string()
            .contains("change"));
        p.coin_value = 100_500; // short of record + fee
        assert!(build_delegation_create_tx(&p)
            .unwrap_err()
            .to_string()
            .contains("does not cover"));
        let (mut p, controller) = create_plan();
        p.signer = controller; // bad-delegation-self
        assert!(build_delegation_create_tx(&p)
            .unwrap_err()
            .to_string()
            .contains("controller itself"));
    }

    #[test]
    fn pubkey_hex_is_validated() {
        let (_, pk) = key(12);
        let hex = elements::hex::ToHex::to_hex(pk.as_slice());
        assert!(delegation_pubkey_from_hex(&hex, "signer").is_ok());
        assert!(delegation_pubkey_from_hex("not hex", "signer").is_err());
        assert!(
            delegation_pubkey_from_hex("02ab", "signer").is_err(),
            "too short"
        );
        // Right length, wrong prefix: an uncompressed-style lead byte.
        assert!(delegation_pubkey_from_hex(&format!("04{}", &hex[2..]), "signer").is_err());
    }
}
