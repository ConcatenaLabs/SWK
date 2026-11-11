//! BIP340 Schnorr adaptor signatures (SWK, `openamp/spec/btc-atomic-swap-followup.md`
//! sections 1, 2, 8).
//!
//! This is the SWK-side, security-critical primitive that couples the two legs of
//! an atomic BTC ↔ restricted-asset swap. A restricted asset can never sit in a
//! hash-locked output (spec §1), so the hashlock is replaced by an adaptor lock on
//! the BIP340 *user* signature only: the completed user signature is an ORDINARY
//! BIP340 signature that `<K_user> CHECKSIGVERIFY` accepts, so neither consensus nor
//! openampd can tell an adaptor-derived signature from a plain one (spec §1, §8).
//!
//! The vendored `secp256k1-zkp` (0.11.0) exposes only an ECDSA adaptor module, which
//! cannot serve the BIP340 enclave leg, so this is built IN-HOUSE on the same
//! `secp256k1` 0.29 point/scalar operations the OpenAMP/covenant signers already use
//! (`crate::bitcoin::secp256k1`, resolved through `elements_miniscript`). It is
//! feature-gated (`adaptor`) and MUST be independently audited before any
//! fund-bearing use (spec §8).
//!
//! # The four functions (spec §8)
//!
//! - [`adaptor_sign`]`(d, m, T) -> â` : a 65-byte pre-signature.
//! - [`adaptor_complete`]`(â, t) -> σ` : a 64-byte BIP340 signature.
//! - [`adaptor_extract`]`(σ, â) -> t` : recovers the coupling secret.
//! - [`adaptor_verify`]`(P, m, T, â) -> bool` : the seller's normative release gate.
//!
//! # Parity, the whole security surface
//!
//! A BIP340 signature commits to an x-only nonce point with EVEN Y. The completed
//! adaptor signature's effective nonce point is `R + T` (signer nonce `R = k·G` plus
//! the adaptor point `T`), so the parity that matters is `has_even_y(R + T)`, NOT the
//! parity of the signer's own nonce `R` (which is left alone). Two independent facts
//! flow from `has_even_y(R + T)`:
//!
//! - The challenge `e` is hashed over `x(R + T)` (not `x(R)`), so the completed
//!   `x(R + T) || s` verifies byte-identically under stock BIP340.
//! - When `R + T` has ODD Y the effective nonce is `lift_x(x(R+T)) = -(R+T)`, so the
//!   signer folds the sign flip into `ŝ`, the completer SUBTRACTS `t`, and the
//!   extractor flips its subtraction. This negation is exactly what makes
//!   [`adaptor_extract`] recover `t` in the odd case.
//!
//! The 65-byte pre-signature stores `R + T` as a 33-byte COMPRESSED point so the
//! parity bit survives to the completer/extractor; storing it x-only would silently
//! break completion.
//!
//! # Determinism (spec 0.4(4))
//!
//! The base nonce mirrors the OpenAMP/covenant `sign_schnorr_no_aux_rand` style
//! (`aux_rand = 32 zero bytes`), but binds `compressed(T)` into the nonce hash so an
//! adaptor nonce is domain-separated from a plain BIP340 nonce for the same
//! `(key, msg)` — without that, a key that both plain-signs and adaptor-signs one
//! message would reuse `k` and leak `d`.

use crate::bitcoin::secp256k1::{
    All, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use crate::elements::hashes::{sha256, Hash, HashEngine};
use crate::error::Error;

/// Length of a pre-signature: `compressed(R+T)` (33) `|| ŝ` (32).
pub const PRESIG_LEN: usize = 65;
/// Length of a completed BIP340 signature: `x(R+T)` (32) `|| s` (32).
pub const SIG_LEN: usize = 64;

/// The secp256k1 group order `n`, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

fn err(msg: impl Into<String>) -> Error {
    Error::Generic(msg.into())
}

// ---------------------------------------------------------------------------
// scalar helpers
// ---------------------------------------------------------------------------

/// BIP340 tagged hash `sha256(sha256(tag) || sha256(tag) || m)` (identical to
/// `openamp::tagged_hash`, re-implemented here so the module carries no
/// feature dependency on `openamp`).
fn tagged_hash(tag: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    for c in chunks {
        engine.input(c);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Reduce a 256-bit big-endian integer modulo `n`. Because `n > 2^255` and every
/// 32-byte value is `< 2^256 < 2n`, a single conditional subtraction of `n`
/// suffices. Used only to fold hash outputs (the challenge `e` and nonce `k`) into
/// the scalar field; all other arithmetic wraps mod `n` natively via `SecretKey`.
fn reduce_mod_n(mut bytes: [u8; 32]) -> [u8; 32] {
    // bytes >= n ?
    let mut ge = true; // assume equal until a byte proves otherwise
    for i in 0..32 {
        if bytes[i] < CURVE_ORDER[i] {
            ge = false;
            break;
        } else if bytes[i] > CURVE_ORDER[i] {
            ge = true;
            break;
        }
    }
    if !ge {
        return bytes;
    }
    // bytes = bytes - n  (big-endian subtraction with borrow)
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = bytes[i] as i16 - CURVE_ORDER[i] as i16 - borrow;
        if diff < 0 {
            bytes[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            bytes[i] = diff as u8;
            borrow = 0;
        }
    }
    bytes
}

/// A reduced hash output as a `Scalar` (may be zero; callers that need nonzero use
/// [`scalar_secret`]).
fn scalar_reduced(bytes: [u8; 32]) -> Scalar {
    // reduce_mod_n guarantees < n, so from_be_bytes never fails.
    Scalar::from_be_bytes(reduce_mod_n(bytes)).expect("reduced value < n")
}

/// A reduced hash output as a nonzero `SecretKey`; errors on the negligible zero.
fn scalar_secret(bytes: [u8; 32]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(&reduce_mod_n(bytes))
        .map_err(|_| err("scalar reduced to zero (negligible); retry with different inputs"))
}

fn has_even_y(pk: &PublicKey) -> bool {
    matches!(pk.x_only_public_key().1, Parity::Even)
}

/// The BIP340 challenge `e = int(H("BIP0340/challenge", x(R+T) || Px || m)) mod n`,
/// as a `Scalar`. Bound to `x(R+T)`, so it is identical for `R+T` and `-(R+T)`.
fn challenge(r_comb: &PublicKey, px: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    let (rx, _) = r_comb.x_only_public_key();
    let rx = rx.serialize();
    scalar_reduced(tagged_hash("BIP0340/challenge", &[&rx, px, msg]))
}

// ---------------------------------------------------------------------------
// the four functions
// ---------------------------------------------------------------------------

/// `adaptorSign(d, m, T) -> â` (spec §8).
///
/// `d` is the signer secret (BIP340-normalized here so `P = d·G` has even Y); `m` is
/// the 32-byte sighash the pre-signature commits to; `t_point = T = t·G` is the
/// adaptor point. Returns the 65-byte pre-signature `compressed(R+T) || ŝ`.
///
/// The signer never forces its own nonce `R = k·G` even; it computes `R + T` and
/// branches on `has_even_y(R + T)`:
/// - even: `ŝ = k + e·d`
/// - odd: `ŝ = e·d − k`  (the nonce term flips sign; `e·d` does not)
pub fn adaptor_sign(
    secp: &Secp256k1<All>,
    d: &SecretKey,
    msg: &[u8; 32],
    t_point: &PublicKey,
) -> Result<[u8; PRESIG_LEN], Error> {
    // Normalize d to the even-Y pubkey P (BIP340), so P_x = x(d·G) and d' matches.
    let (xonly, parity) = d.x_only_public_key(secp);
    let d = if matches!(parity, Parity::Odd) {
        d.negate()
    } else {
        *d
    };
    let px = xonly.serialize();
    let t_compressed = t_point.serialize();

    // Deterministic nonce (aux_rand = zeros), binding compressed(T) for domain
    // separation from a plain BIP340 nonce over the same (key, msg).
    let aux = tagged_hash("BIP0340/aux", &[&[0u8; 32]]);
    let mut t_aux = d.secret_bytes();
    for i in 0..32 {
        t_aux[i] ^= aux[i];
    }
    let k = scalar_secret(tagged_hash(
        "BIP0340/nonce",
        &[&t_aux, &px, &t_compressed, msg],
    ))?;

    let r = PublicKey::from_secret_key(secp, &k);
    let r_comb = r
        .combine(t_point)
        .map_err(|_| err("R + T is the point at infinity (R == -T)"))?;

    let e = challenge(&r_comb, &px, msg);
    let ed = d
        .mul_tweak(&e)
        .map_err(|_| err("e·d is zero (negligible)"))?;

    let s_hat = if has_even_y(&r_comb) {
        // ŝ = k + e·d
        k.add_tweak(&Scalar::from(ed))
    } else {
        // ŝ = e·d − k = e·d + (n − k)
        ed.add_tweak(&Scalar::from(k.negate()))
    }
    .map_err(|_| err("ŝ is zero (negligible)"))?;

    let mut out = [0u8; PRESIG_LEN];
    out[..33].copy_from_slice(&r_comb.serialize());
    out[33..].copy_from_slice(&s_hat.secret_bytes());
    Ok(out)
}

/// `adaptorVerify(P, m, T, â) -> bool` (spec §8) — the seller's normative gate before
/// releasing its own pre-signature (spec §2.3, §8).
///
/// Accepts a valid pre-signature; rejects a tampered `ŝ`, `T`, or `m`, and any
/// malformed input (`ŝ ≥ n`, off-curve/infinity `R+T` or `T`, or `R+T == T` which
/// makes `R = ∞`). Never panics.
///
/// Checks `ŝ·G == U + e·P` where `R0 = (R+T) − T`, `U = R0` if `R+T` is even else
/// `U = −R0`, and `P = lift_x(Px)`.
pub fn adaptor_verify(
    secp: &Secp256k1<All>,
    p_xonly: &XOnlyPublicKey,
    msg: &[u8; 32],
    t_point: &PublicKey,
    presig: &[u8; PRESIG_LEN],
) -> bool {
    let r_comb = match PublicKey::from_slice(&presig[..33]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // ŝ must be a canonical nonzero scalar in [1, n).
    let s_hat = match SecretKey::from_slice(&presig[33..]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let px = p_xonly.serialize();
    let p = p_xonly.public_key(Parity::Even); // lift_x
    let e = challenge(&r_comb, &px, msg);

    // R0 = R_comb - T
    let neg_t = t_point.negate(secp);
    let r0 = match r_comb.combine(&neg_t) {
        Ok(p) => p, // Err => R_comb == T, R0 = infinity => reject
        Err(_) => return false,
    };
    let u = if has_even_y(&r_comb) {
        r0
    } else {
        r0.negate(secp)
    };

    let ep = match p.mul_tweak(secp, &e) {
        Ok(p) => p,
        Err(_) => return false, // e == 0, negligible
    };
    let rhs = match u.combine(&ep) {
        Ok(p) => p,
        Err(_) => return false, // U == -e·P, negligible
    };
    let lhs = PublicKey::from_secret_key(secp, &s_hat); // ŝ·G

    lhs == rhs
}

/// `adaptorComplete(â, t) -> σ` (spec §8). Adds the coupling secret `t` into `ŝ`,
/// with the sign governed by `has_even_y(R+T)`:
/// - even: `s = ŝ + t`
/// - odd: `s = ŝ − t`
///
/// Returns the 64-byte BIP340 signature `x(R+T) || s`, which verifies byte-identically
/// under stock `secp256k1` schnorr verification (spec §8, acceptance criterion 4).
pub fn adaptor_complete(presig: &[u8; PRESIG_LEN], t: &SecretKey) -> Result<[u8; SIG_LEN], Error> {
    let r_comb =
        PublicKey::from_slice(&presig[..33]).map_err(|e| err(format!("bad R+T in â: {e}")))?;
    let s_hat = SecretKey::from_slice(&presig[33..]).map_err(|e| err(format!("bad ŝ in â: {e}")))?;

    let s = if has_even_y(&r_comb) {
        s_hat.add_tweak(&Scalar::from(*t)) // s = ŝ + t
    } else {
        s_hat.add_tweak(&Scalar::from(t.negate())) // s = ŝ − t
    }
    .map_err(|_| err("completed s is zero (negligible)"))?;

    let (rx, _) = r_comb.x_only_public_key();
    let mut out = [0u8; SIG_LEN];
    out[..32].copy_from_slice(&rx.serialize());
    out[32..].copy_from_slice(&s.secret_bytes());
    Ok(out)
}

/// `adaptorExtract(σ, â) -> t` (spec §8). Given the completed signature and the
/// pre-signature it was completed from, recovers the coupling secret:
/// - even: `t = s − ŝ`
/// - odd: `t = ŝ − s`
///
/// The parity comes from `R+T` stored in `â`; the `σ` nonce `x(R+T)` must match `â`.
pub fn adaptor_extract(
    full_sig: &[u8; SIG_LEN],
    presig: &[u8; PRESIG_LEN],
) -> Result<[u8; 32], Error> {
    let r_comb =
        PublicKey::from_slice(&presig[..33]).map_err(|e| err(format!("bad R+T in â: {e}")))?;
    let s_hat = SecretKey::from_slice(&presig[33..]).map_err(|e| err(format!("bad ŝ in â: {e}")))?;
    let s = SecretKey::from_slice(&full_sig[32..]).map_err(|e| err(format!("bad s in σ: {e}")))?;

    // The σ nonce x(R+T) must equal â's R+T, else the pair does not match.
    let (rx, _) = r_comb.x_only_public_key();
    if rx.serialize() != full_sig[..32] {
        return Err(err("σ nonce x(R+T) does not match â"));
    }

    let t = if has_even_y(&r_comb) {
        s.add_tweak(&Scalar::from(s_hat.negate())) // t = s − ŝ
    } else {
        s_hat.add_tweak(&Scalar::from(s.negate())) // t = ŝ − s
    }
    .map_err(|_| err("extracted t is zero (negligible)"))?;

    Ok(t.secret_bytes())
}

// ===========================================================================
// conformance vectors (spec §8)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::secp256k1::{Keypair, Message};

    // Search for a secret t whose adaptor point T makes R+T have the requested
    // parity for a fixed (d, msg). This exercises BOTH parity branches (vector 4).
    fn find_t_with_parity(
        secp: &Secp256k1<All>,
        d: &SecretKey,
        msg: &[u8; 32],
        want_even: bool,
    ) -> (SecretKey, PublicKey, [u8; PRESIG_LEN]) {
        for i in 1u32..100_000 {
            let mut tb = [0u8; 32];
            tb[28..].copy_from_slice(&i.to_be_bytes());
            let t = match SecretKey::from_slice(&tb) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let t_point = PublicKey::from_secret_key(secp, &t);
            let presig = adaptor_sign(secp, d, msg, &t_point).unwrap();
            let r_comb = PublicKey::from_slice(&presig[..33]).unwrap();
            if has_even_y(&r_comb) == want_even {
                return (t, t_point, presig);
            }
        }
        panic!("no t found producing requested R+T parity");
    }

    fn fixed_key(secp: &Secp256k1<All>) -> (SecretKey, XOnlyPublicKey) {
        let d = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let (xonly, _) = d.x_only_public_key(secp);
        (d, xonly)
    }

    // ---- Vector 1: sign / complete / extract ROUND-TRIP recovers t ----------
    #[test]
    fn vector1_round_trip_recovers_t() {
        let secp = Secp256k1::new();
        let (d, _px) = fixed_key(&secp);
        let msg = [0x22u8; 32];
        // Fixed t.
        let mut tb = [0u8; 32];
        tb[31] = 0x07;
        let t = SecretKey::from_slice(&tb).unwrap();
        let t_point = PublicKey::from_secret_key(&secp, &t);

        let presig = adaptor_sign(&secp, &d, &msg, &t_point).unwrap();
        let sig = adaptor_complete(&presig, &t).unwrap();
        let recovered = adaptor_extract(&sig, &presig).unwrap();

        assert_eq!(recovered, t.secret_bytes(), "extract must recover t");
        // And t·G == T (recovered scalar reproduces the adaptor point).
        let rec_sk = SecretKey::from_slice(&recovered).unwrap();
        assert_eq!(PublicKey::from_secret_key(&secp, &rec_sk), t_point);
    }

    // ---- Vector 2: verify ACCEPTS valid, REJECTS tampered s / T / msg --------
    #[test]
    fn vector2_verify_accept_and_reject_tampered() {
        let secp = Secp256k1::new();
        let (d, px) = fixed_key(&secp);
        let msg = [0x33u8; 32];
        let mut tb = [0u8; 32];
        tb[31] = 0x09;
        let t = SecretKey::from_slice(&tb).unwrap();
        let t_point = PublicKey::from_secret_key(&secp, &t);

        let presig = adaptor_sign(&secp, &d, &msg, &t_point).unwrap();
        assert!(
            adaptor_verify(&secp, &px, &msg, &t_point, &presig),
            "valid â must verify"
        );

        // Tampered ŝ: flip a byte (keep it a valid scalar).
        let mut bad_s = presig;
        bad_s[40] ^= 0x01;
        assert!(
            !adaptor_verify(&secp, &px, &msg, &t_point, &bad_s),
            "tampered ŝ must be rejected"
        );

        // Wrong T (different adaptor point).
        let t2 = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
        let t2_point = PublicKey::from_secret_key(&secp, &t2);
        assert!(
            !adaptor_verify(&secp, &px, &msg, &t2_point, &presig),
            "wrong T must be rejected"
        );

        // Wrong msg.
        let msg2 = [0x44u8; 32];
        assert!(
            !adaptor_verify(&secp, &px, &msg2, &t_point, &presig),
            "wrong msg must be rejected"
        );

        // Wrong pubkey.
        let (_d2, px2) = {
            let d2 = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
            let (x, _) = d2.x_only_public_key(&secp);
            (d2, x)
        };
        assert!(
            !adaptor_verify(&secp, &px2, &msg, &t_point, &presig),
            "wrong pubkey must be rejected"
        );
    }

    // ---- Vector 3: completed sig verifies byte-identically via BIP340 --------
    #[test]
    fn vector3_completed_sig_is_valid_bip340() {
        let secp = Secp256k1::new();
        let (d, px) = fixed_key(&secp);
        let msg = [0x22u8; 32];
        let mut tb = [0u8; 32];
        tb[31] = 0x07;
        let t = SecretKey::from_slice(&tb).unwrap();
        let t_point = PublicKey::from_secret_key(&secp, &t);

        let presig = adaptor_sign(&secp, &d, &msg, &t_point).unwrap();
        let sig = adaptor_complete(&presig, &t).unwrap();

        // Stock BIP340 verification is the ground truth (spec §8, criterion 4).
        let signature =
            crate::bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap();
        let message = Message::from_digest(msg);
        secp.verify_schnorr(&signature, &message, &px)
            .expect("completed adaptor signature must verify as an ordinary BIP340 signature");
    }

    // ---- Vector 4: BOTH R+T even-Y and odd-Y (negation path) -----------------
    #[test]
    fn vector4_parity_edges_both_recover_t() {
        let secp = Secp256k1::new();
        let (d, px) = fixed_key(&secp);
        let msg = [0x5au8; 32];

        for want_even in [true, false] {
            let (t, t_point, presig) = find_t_with_parity(&secp, &d, &msg, want_even);
            let r_comb = PublicKey::from_slice(&presig[..33]).unwrap();
            assert_eq!(
                has_even_y(&r_comb),
                want_even,
                "test setup must hit the requested parity"
            );

            // verify accepts
            assert!(
                adaptor_verify(&secp, &px, &msg, &t_point, &presig),
                "â must verify for parity even={want_even}"
            );
            // complete -> extract recovers t
            let sig = adaptor_complete(&presig, &t).unwrap();
            let recovered = adaptor_extract(&sig, &presig).unwrap();
            assert_eq!(
                recovered,
                t.secret_bytes(),
                "extract must recover t (parity even={want_even})"
            );
            // and the completed sig is a valid BIP340 sig in BOTH parity cases
            let signature =
                crate::bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap();
            secp.verify_schnorr(&signature, &Message::from_digest(msg), &px)
                .unwrap_or_else(|_| {
                    panic!("completed sig must verify (parity even={want_even})")
                });
        }
    }

    // ---- reduce_mod_n sanity --------------------------------------------------
    #[test]
    fn reduce_mod_n_boundaries() {
        // Below n: unchanged.
        let small = [0u8; 32];
        assert_eq!(reduce_mod_n(small), small);
        // Exactly n: reduces to 0.
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0u8; 32]);
        // n + 1 (0x...4142): reduces to 1.
        let mut np1 = CURVE_ORDER;
        np1[31] = 0x42;
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(reduce_mod_n(np1), one);
    }

    // Determinism: identical inputs give an identical pre-signature (spec 0.4(4)).
    #[test]
    fn deterministic_presignature() {
        let secp = Secp256k1::new();
        let (d, _px) = fixed_key(&secp);
        let msg = [0x22u8; 32];
        let t = SecretKey::from_slice(&[0x03u8; 32]).unwrap();
        let t_point = PublicKey::from_secret_key(&secp, &t);
        let a = adaptor_sign(&secp, &d, &msg, &t_point).unwrap();
        let b = adaptor_sign(&secp, &d, &msg, &t_point).unwrap();
        assert_eq!(a, b, "adaptor_sign must be deterministic");
    }

    // Keypair path parity: normalization matches secp's own x-only derivation.
    #[test]
    fn normalization_matches_keypair_xonly() {
        let secp = Secp256k1::new();
        // Pick a key whose raw pubkey has ODD Y so normalization actually flips it.
        let mut i = 1u8;
        let (d, xonly) = loop {
            let d = SecretKey::from_slice(&[i; 32]).unwrap();
            let (x, parity) = d.x_only_public_key(&secp);
            if matches!(parity, Parity::Odd) {
                break (d, x);
            }
            i += 1;
        };
        let kp = Keypair::from_secret_key(&secp, &d);
        assert_eq!(kp.x_only_public_key().0, xonly);
    }
}
