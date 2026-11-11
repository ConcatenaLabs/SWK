//! Bitcoin parent-chain (testnet4) HTLC leg for cross-chain SeqDEX swaps.
//!
//! The wallet is Alice (the secret holder): she funds the BTC HTLC, the maker
//! (Bob) claims it by revealing the preimage, and Alice refunds via the CLTV
//! branch if Bob never claims.
//!
//!   OP_IF  OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <claimPub> OP_CHECKSIG
//!   OP_ELSE  <locktime> OP_CLTV OP_DROP <refundPub> OP_CHECKSIG
//!   OP_ENDIF                                            (paid to a bare P2SH)
//!
//! The redeemScript is NOT rebuilt here: it delegates to the kit's single
//! chain-agnostic source [`crate::build_htlc_redeem_script`] (the
//! daemon-parity-proven SEQ builder), so the BTC and SEQ legs are byte-identical
//! by construction. The refund spend uses a legacy SIGHASH_ALL over the
//! redeemScript and a hand-built scriptSig `<sig> OP_0 <redeemScript>` to select
//! the ELSE branch (a generic signer won't template the OP_0 selector). The BTC
//! claim is Bob's path and is not built here.

use std::str::FromStr;

use crate::bitcoin::absolute::LockTime;
use crate::bitcoin::consensus::encode::serialize_hex;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::script::{Builder, PushBytes};
use crate::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use crate::bitcoin::sighash::SighashCache;
use crate::bitcoin::transaction::Version;
use crate::bitcoin::{
    opcodes, Address, Amount, EcdsaSighashType, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};

use crate::error::Error;

fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

fn push_bytes(b: &[u8]) -> Result<&PushBytes, Error> {
    <&PushBytes>::try_from(b).map_err(map)
}

/// Build the BTC-leg HTLC redeemScript as a bitcoin [`ScriptBuf`].
///
/// Delegates to the kit's single source [`crate::build_htlc_redeem_script`] and
/// wraps its bytes, so the BTC leg is byte-identical to the SEQ leg (and the
/// daemon) by construction — not by a coincidentally-matching second builder.
pub fn build_htlc_redeem_script(
    hash: &[u8],
    claim_pub: &[u8],
    refund_pub: &[u8],
    locktime: u32,
) -> Result<ScriptBuf, Error> {
    let seq = crate::build_htlc_redeem_script(hash, claim_pub, refund_pub, locktime)?;
    Ok(ScriptBuf::from_bytes(seq.as_bytes().to_vec()))
}

/// The bare-P2SH address + scriptPubKey for an HTLC redeemScript, on testnet
/// (testnet `2…` base58 P2SH; the version byte is shared with testnet4). The
/// wallet funds this address and locates the funding output by matching this spk.
pub fn htlc_p2sh(redeem: &ScriptBuf) -> Result<(Address, ScriptBuf), Error> {
    let address = Address::p2sh(redeem, Network::Testnet).map_err(map)?;
    Ok((address, redeem.to_p2sh()))
}

/// A spend of an HTLC P2SH output: the funding outpoint, its value, where the
/// refund pays, and the fee to subtract.
pub struct BtcHtlcSpend {
    /// Funding txid (the HTLC outpoint).
    pub txid: String,
    /// Funding vout of the HTLC P2SH output.
    pub vout: u32,
    /// Value of the HTLC output, in sats.
    pub amount_sats: u64,
    /// scriptPubKey the refund pays to.
    pub dest_spk: ScriptBuf,
    /// Fee to subtract from the HTLC amount, in sats.
    pub fee_sats: u64,
}

/// Build + sign the BTC refund: a legacy P2SH spend of the HTLC via the ELSE/CLTV
/// branch, paying `amount - fee` to `dest_spk`. Only valid once the chain tip
/// reaches `locktime` (CLTV). Returns the raw tx hex to broadcast.
///
/// The scriptSig is `<sig> OP_0 <redeemScript>`: the empty (false) item selects
/// the OP_ELSE branch, and the redeemScript push is what P2SH executes. The
/// sighash is a LEGACY SIGHASH_ALL over the redeemScript (not the P2SH spk).
pub fn build_refund_tx(
    redeem: &ScriptBuf,
    spend: &BtcHtlcSpend,
    locktime: u32,
    refund_sk: &SecretKey,
) -> Result<String, Error> {
    let out_value = spend
        .amount_sats
        .checked_sub(spend.fee_sats)
        .ok_or_else(|| Error::Generic("fee exceeds the HTLC amount".into()))?;
    if out_value == 0 {
        return Err(Error::Generic("refund output is zero after fee".into()));
    }
    let txid = Txid::from_str(&spend.txid).map_err(map)?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: spend.vout },
            script_sig: ScriptBuf::new(),
            // 0xfffffffd: non-final (bit 31 set -> BIP68 disabled, so absolute
            // CLTV still applies) AND BIP125-replaceable, so a time-sensitive
            // refund can be fee-bumped before its deadline. It must NOT be raised
            // to a final value (0xffffffff): that makes OP_CLTV FAIL and the refund
            // tx invalid/un-minable (it does not make it spendable before locktime).
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: spend.dest_spk.clone() }],
    };
    // Legacy SIGHASH_ALL over the redeemScript (the subscript), computed while the
    // cache borrows &tx; then drop it before mutating the input's scriptSig.
    let sighash = SighashCache::new(&tx)
        .legacy_signature_hash(0, redeem, EcdsaSighashType::All.to_u32())
        .map_err(map)?;
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), refund_sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8); // 0x01

    tx.input[0].script_sig = Builder::new()
        .push_slice(push_bytes(&sig_bytes)?)
        .push_opcode(opcodes::all::OP_PUSHBYTES_0) // OP_0 / false -> selects the ELSE/CLTV branch
        .push_slice(push_bytes(redeem.as_bytes())?)
        .into_script();
    Ok(serialize_hex(&tx))
}

/// Build + sign the BTC CLAIM: a legacy P2SH spend of the HTLC via the IF/preimage
/// branch, paying `amount - fee` to `dest_spk`. Valid immediately (no CLTV). This is
/// the exact MIRROR of [`build_refund_tx`] — same legacy SIGHASH_ALL over the
/// redeemScript, same low-S DER + `0x01` sig — differing only in:
///   - scriptSig `<sig> <preimage> OP_1 <redeemScript>`: the truthy `OP_1` selects the
///     OP_IF/preimage branch, and the preimage satisfies `OP_SHA256 <H> OP_EQUALVERIFY`.
///   - `nSequence = 0xffffffff` (final) and `nLockTime = 0`: the claim has no timelock
///     (only the refund's ELSE branch is CLTV-gated).
/// The `[sig, preimage, OP_1]` item order matches the daemon's proven
/// `HashLock::RedeemUnlockItems` (`[sig, P, {0x01}]`), so the spend is byte-compatible
/// with `xdriver_subasset_sell.go` / `xsubas-claim-btc`.
pub fn build_claim_tx(
    redeem: &ScriptBuf,
    spend: &BtcHtlcSpend,
    preimage: &[u8],
    claim_sk: &SecretKey,
) -> Result<String, Error> {
    let out_value = spend
        .amount_sats
        .checked_sub(spend.fee_sats)
        .ok_or_else(|| Error::Generic("fee exceeds the HTLC amount".into()))?;
    if out_value == 0 {
        return Err(Error::Generic("claim output is zero after fee".into()));
    }
    let txid = Txid::from_str(&spend.txid).map_err(map)?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(0), // claim has no CLTV constraint
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: spend.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_ffff), // final: the claim branch has no timelock
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: spend.dest_spk.clone() }],
    };
    // Legacy SIGHASH_ALL over the redeemScript (the subscript) — identical to refund.
    let sighash = SighashCache::new(&tx)
        .legacy_signature_hash(0, redeem, EcdsaSighashType::All.to_u32())
        .map_err(map)?;
    let secp = Secp256k1::new();
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), claim_sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8); // 0x01

    tx.input[0].script_sig = Builder::new()
        .push_slice(push_bytes(&sig_bytes)?)
        .push_slice(push_bytes(preimage)?)
        .push_opcode(opcodes::all::OP_PUSHNUM_1) // OP_1 / true -> selects the IF/preimage branch
        .push_slice(push_bytes(redeem.as_bytes())?)
        .into_script();
    Ok(serialize_hex(&tx))
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::consensus::encode::deserialize;
    use crate::bitcoin::hex::FromHex;
    use crate::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::bitcoin::Transaction;

    fn pubkey(byte: u8) -> [u8; 33] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        sk.public_key(&secp).serialize()
    }

    // The fund-safety chain rests on the BTC redeemScript being byte-identical to
    // the daemon's. The kit's `build_htlc_redeem_script` is the single proven
    // source; confirm the BTC wrapper reproduces its bytes exactly.
    #[test]
    fn btc_redeem_matches_seq_builder() {
        let hash = [0x11u8; 32];
        let claim = pubkey(2);
        let refund = pubkey(3);
        let locktime = 1_234_567u32;

        let btc = super::build_htlc_redeem_script(&hash, &claim, &refund, locktime).unwrap();
        let seq = crate::build_htlc_redeem_script(&hash, &claim, &refund, locktime).unwrap();
        assert_eq!(btc.as_bytes(), seq.as_bytes(), "BTC HTLC script must byte-match the SEQ/daemon script");

        let (addr, spk) = super::htlc_p2sh(&btc).unwrap();
        assert!(addr.to_string().starts_with('2'), "testnet P2SH base58 starts with 2, got {addr}");
        assert_eq!(spk.as_bytes()[0], 0xa9, "P2SH spk starts with OP_HASH160");
    }

    #[test]
    fn refund_tx_shape() {
        let secp = Secp256k1::new();
        let refund_sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let refund_pub = refund_sk.public_key(&secp).serialize();
        let redeem = super::build_htlc_redeem_script(&[0x22u8; 32], &pubkey(2), &refund_pub, 800_000).unwrap();
        let dest_spk = super::htlc_p2sh(&redeem).unwrap().1; // any spk for the structural check
        let spend = super::BtcHtlcSpend {
            txid: "a".repeat(64),
            vout: 1,
            amount_sats: 50_000,
            dest_spk,
            fee_sats: 2_000,
        };
        let hex = super::build_refund_tx(&redeem, &spend, 800_000, &refund_sk).unwrap();
        let raw = Vec::<u8>::from_hex(&hex).unwrap();
        let tx: Transaction = deserialize(&raw).unwrap();
        assert_eq!(tx.version, super::Version::TWO);
        assert_eq!(tx.lock_time.to_consensus_u32(), 800_000); // CLTV enforced
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].sequence.0, 0xffff_fffd); // non-final (CLTV applies) + BIP125-replaceable
        assert!(tx.input[0].witness.is_empty()); // legacy P2SH, no witness
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 48_000); // amount - fee
        assert!(!tx.input[0].script_sig.is_empty());
    }

    #[test]
    fn refund_rejects_fee_over_amount() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let redeem =
            super::build_htlc_redeem_script(&[0x22u8; 32], &pubkey(2), &sk.public_key(&secp).serialize(), 1).unwrap();
        let spend = super::BtcHtlcSpend {
            txid: "a".repeat(64),
            vout: 0,
            amount_sats: 1_000,
            dest_spk: super::htlc_p2sh(&redeem).unwrap().1,
            fee_sats: 2_000,
        };
        assert!(super::build_refund_tx(&redeem, &spend, 1, &sk).is_err());
    }

    // Round-trip: build an HTLC on H=SHA256(P), build the CLAIM tx via the IF branch,
    // and prove it would be ACCEPTED — the preimage satisfies OP_SHA256<H>EQUALVERIFY
    // and the signature satisfies CHECKSIG for the exact claim pubkey (over the legacy
    // sighash). This is the money-safety check the wallet relies on (no bitcoinconsensus
    // dep, so we verify the two spend conditions directly rather than run the interpreter).
    #[test]
    fn claim_tx_roundtrip_spends_htlc() {
        use crate::bitcoin::hashes::{sha256, Hash as _};
        use crate::bitcoin::script::Instruction;
        use crate::bitcoin::secp256k1::{ecdsa, Message, PublicKey};
        use crate::bitcoin::sighash::{EcdsaSighashType, SighashCache};

        let secp = Secp256k1::new();
        let preimage = [0x42u8; 32];
        let hash = sha256::Hash::hash(&preimage).to_byte_array();
        let claim_sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let claim_pub = claim_sk.public_key(&secp).serialize();
        let refund_pub = pubkey(3);
        let redeem = super::build_htlc_redeem_script(&hash, &claim_pub, &refund_pub, 800_000).unwrap();
        let spend = super::BtcHtlcSpend {
            txid: "b".repeat(64),
            vout: 2,
            amount_sats: 50_000,
            dest_spk: super::htlc_p2sh(&redeem).unwrap().1,
            fee_sats: 1_000,
        };
        let hex = super::build_claim_tx(&redeem, &spend, &preimage, &claim_sk).unwrap();
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();

        // shape: the mirror of refund — final sequence + zero locktime, single output.
        assert_eq!(tx.version, super::Version::TWO);
        assert_eq!(tx.lock_time.to_consensus_u32(), 0); // claim has no CLTV
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].sequence.0, 0xffff_ffff); // final
        assert!(tx.input[0].witness.is_empty()); // legacy P2SH, no witness
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 49_000); // amount - fee

        // scriptSig = <sig> <preimage> OP_1 <redeemScript>
        let items: Vec<_> = tx.input[0].script_sig.instructions().collect::<Result<_, _>>().unwrap();
        assert_eq!(items.len(), 4, "scriptSig items = [sig, preimage, OP_1, redeemScript]");
        let sig_der = match items[0] {
            Instruction::PushBytes(b) => b.as_bytes(),
            _ => panic!("item 0 must push the sig"),
        };
        match items[1] {
            Instruction::PushBytes(b) => assert_eq!(b.as_bytes(), &preimage, "preimage pushed verbatim"),
            _ => panic!("item 1 must push the preimage"),
        }
        assert!(matches!(items[2], Instruction::Op(op) if op.to_u8() == 0x51), "item 2 = OP_1 (IF selector)");
        match items[3] {
            Instruction::PushBytes(b) => assert_eq!(b.as_bytes(), redeem.as_bytes(), "redeemScript pushed last"),
            _ => panic!("item 3 must push the redeemScript"),
        }

        // spend condition 1: SHA256(preimage) == H committed in the script.
        assert_eq!(sha256::Hash::hash(&preimage).to_byte_array(), hash);
        // spend condition 2: the sig (DER || 0x01) verifies against the legacy SIGHASH_ALL
        // over the redeemScript for the EXACT claim pubkey -> OP_CHECKSIG would pass.
        assert_eq!(*sig_der.last().unwrap(), EcdsaSighashType::All.to_u32() as u8);
        let sighash = SighashCache::new(&tx)
            .legacy_signature_hash(0, &redeem, EcdsaSighashType::All.to_u32())
            .unwrap();
        let sig = ecdsa::Signature::from_der(&sig_der[..sig_der.len() - 1]).unwrap();
        let pk = PublicKey::from_slice(&claim_pub).unwrap();
        secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sig, &pk)
            .expect("claim sig must satisfy CHECKSIG for the claim pubkey");
    }

    // Claim and refund keys MUST differ (distinct derivation paths) so one leaked key
    // can never unlock both HTLC branches.
    #[test]
    fn claim_key_distinct_from_refund_key() {
        use crate::btc::addr::ChainAddressParams;
        use crate::btc::xchain::{btc_claim_keypair, btc_refund_keypair, PathMode};
        let p = ChainAddressParams::testnet();
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (_, claim) = btc_claim_keypair(&p, m, PathMode::Canonical).unwrap();
        let (_, refund) = btc_refund_keypair(&p, m, PathMode::Canonical).unwrap();
        assert_ne!(claim, refund, "m/84h/1h/0h/4/0 (claim) and …/2/0 (refund) must derive different keys");
    }
}
