//! A statement signed with a contract key.
//!
//! A platform that names this wallet's contract key in a contract (an escrow's
//! release key, say) may ask the wallet to prove it holds that key by signing
//! a statement: BIP340 over the tagged hash
//! `sha256(sha256(tag) || sha256(tag) || message)`. What else such a signature
//! could authorise is the whole question, because the same key signs spends:
//!
//! - a tapscript spend signs a tagged hash under `TapSighash`, so every tag
//!   beginning `tap` (and `bip0340`, `bip340`, `bip322`, `elements`,
//!   `sequentia/`, and any tag containing `sighash`) is refused here;
//! - a Simplicity spend signs `sig_all_hash`, which is
//!   `sha256(genesis || genesis || ...)`: the genesis hash stands where
//!   `sha256(tag)` would, so a statement could only collide with it under a
//!   tag whose SHA-256 is the chain's genesis hash, a preimage.
//!
//! So a statement's signature authorises no spend. The wallet still shows the
//! statement before signing; this module only refuses what must never be
//! signed at all.

use std::str::FromStr;

use lwk_signer::SwSigner;
use simplicityhl::elements::bitcoin::bip32::DerivationPath;
use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::{Message, Secp256k1};

use crate::error::Error;
use crate::hex::hex;

const RESERVED_PREFIXES: &[&str] = &[
    "tap",
    "bip0340",
    "bip340",
    "bip322",
    "elements",
    "sequentia/",
];
const MAX_TAG: usize = 64;

/// Refuses a tag a contract key must never sign a statement under.
pub fn check_tag(tag: &str) -> Result<(), Error> {
    if tag.is_empty() || tag.len() > MAX_TAG || !tag.bytes().all(|c| (0x21..=0x7e).contains(&c)) {
        return Err(Error::Signing(
            "a statement's tag must be 1-64 printable characters with no spaces".into(),
        ));
    }
    let lower = tag.to_ascii_lowercase();
    if RESERVED_PREFIXES.iter().any(|p| lower.starts_with(p)) || lower.contains("sighash") {
        return Err(Error::Signing(format!(
            "a contract key never signs a statement under the reserved tag {tag:?}: a signature under it could stand for a spend"
        )));
    }
    Ok(())
}

/// The tagged hash a statement's signature signs.
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    e.input(message);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// Signs `message` under `tag` with the contract key at `key_path`, which must
/// be under the contract account. Returns the signature and the x-only key, hex.
pub fn sign(
    signer: &SwSigner,
    mainnet: bool,
    key_path: &str,
    tag: &str,
    message: &[u8],
) -> Result<(String, String), Error> {
    check_tag(tag)?;
    let account = crate::spend::contract_account(mainnet);
    let canon = key_path.replace('\'', "h");
    if !canon.starts_with(&format!("{account}/")) {
        return Err(Error::Signing(format!(
            "{key_path} is not a contract key: contract keys are under {account}"
        )));
    }
    let path =
        DerivationPath::from_str(&canon).map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
    let xprv = signer
        .derive_xprv(&path)
        .map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &xprv.private_key);
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(tagged_hash(tag, message)), &kp);
    Ok((
        hex(&sig.serialize()),
        hex(&kp.x_only_public_key().0.serialize()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_tags_are_refused() {
        for t in [
            "TapSighash",
            "TapSighash/elements",
            "tapleaf",
            "BIP0340/challenge",
            "bip340",
            "BIP322-signed-message",
            "Elements/foo",
            "sequentia/SupervisionRecord",
            "my-sighash",
            "",
            "has space",
        ] {
            assert!(check_tag(t).is_err(), "{t}");
        }
        for t in ["seqpal-escrow-terms-v1", "openamp-challenge-v1"] {
            assert!(check_tag(t).is_ok(), "{t}");
        }
    }

    #[test]
    fn signs_with_the_contract_key_only() {
        let s = SwSigner::new(
            "exist carry drive collect lend cereal occur much tiger just involve mean",
            false,
        )
        .unwrap();
        let (sig, key) = sign(
            &s,
            false,
            "m/8383h/1h/0h/0/0",
            "seqpal-escrow-terms-v1",
            b"terms",
        )
        .unwrap();
        let secp = Secp256k1::verification_only();
        let pk = simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey::from_str(&key).unwrap();
        let sig =
            simplicityhl::elements::secp256k1_zkp::schnorr::Signature::from_str(&sig).unwrap();
        secp.verify_schnorr(
            &sig,
            &Message::from_digest(tagged_hash("seqpal-escrow-terms-v1", b"terms")),
            &pk,
        )
        .unwrap();
        assert!(sign(
            &s,
            false,
            "m/84h/1h/0h/0/0",
            "seqpal-escrow-terms-v1",
            b"terms"
        )
        .is_err());
    }
}
