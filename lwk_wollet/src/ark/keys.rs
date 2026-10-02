//! Leaf keys: one key for every leaf instance.
//!
//! When one owner key holds two leaves, the operator can take one of them: a
//! salt the owner has signed under, built into a new leaf, lets an old signature
//! pair spend it; one release fills two slots of a reclaim; two forfeits merge
//! into one output. So a leaf key signs for one leaf only, and is never derived
//! from a counter, which a restore would repeat and a server could steer.
//!
//! For every leaf it asks for, or publishes in a receive request, the wallet
//! draws a random 32-byte owner nonce ([`new_owner_nonce`]). The nonce goes
//! into the leaf's salt and into its record, and the leaf key follows from it:
//!
//! ```text
//! m / 6' / account' / c1' / c2' / c3' / c4'
//! ```
//!
//! where `c1` to `c4` are the first four 31-bit chunks, most significant bit
//! first, of `SHA256("Arca/key" ‖ owner_nonce)`. Purpose `6'` is the kit's own
//! ([`ARK_PURPOSE`]), apart from every on-chain address purpose and from the
//! kit's other keys (`m/2/0` staking, `m/3/0` swaps, `m/5/0` OpenAMP, where the
//! kit signs raw digests); `SEQUENTIA.md` lists them.
//!
//! A restore needs no index scan and no gap limit: for each record the server
//! returns, the wallet derives the key from the record's owner nonce and checks
//! that it is the record's owner key ([`restore_key`]).

use elements::bitcoin::bip32::{ChildNumber, DerivationPath};
use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::XOnlyPublicKey;
use rand::RngCore;

use super::{ArkError, LeafRecord};

/// The kit's BIP32 purpose for Arca leaf keys, hardened.
pub const ARK_PURPOSE: u32 = 6;

/// The tag that begins the hash a leaf key's path is read from.
pub const KEY_TAG: &[u8] = b"Arca/key";

/// A leaf's owner nonce: 32 random bytes, drawn once for that leaf alone.
pub type OwnerNonce = [u8; 32];

/// A fresh owner nonce, from the system's random source.
pub fn new_owner_nonce() -> OwnerNonce {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// The four 31-bit chunks of `SHA256("Arca/key" ‖ owner_nonce)` that name a
/// leaf key's path, most significant bit first.
pub fn path_chunks(owner_nonce: &OwnerNonce) -> [u32; 4] {
    let mut data = KEY_TAG.to_vec();
    data.extend_from_slice(owner_nonce);
    let hash = sha256::Hash::hash(&data).to_byte_array();
    let mut first = [0u8; 16];
    first.copy_from_slice(&hash[..16]);
    let x = u128::from_be_bytes(first);
    let chunk = |shift: u32| ((x >> shift) & 0x7fff_ffff) as u32;
    [chunk(97), chunk(66), chunk(35), chunk(4)]
}

/// `m/6'/account'/c1'/c2'/c3'/c4'`, the path of the key for the leaf whose
/// owner nonce is `owner_nonce`.
pub fn leaf_key_path(account: u32, owner_nonce: &OwnerNonce) -> Result<DerivationPath, ArkError> {
    let hardened = |i: u32| ChildNumber::from_hardened_idx(i).map_err(|_| ArkError::Account(i));
    let mut path = vec![hardened(ARK_PURPOSE)?, hardened(account)?];
    for c in path_chunks(owner_nonce) {
        path.push(hardened(c)?);
    }
    Ok(DerivationPath::from(path))
}

/// A leaf's key: its owner nonce, the path the nonce gives, and the x-only key
/// at that path, as the leaf's scripts name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafKey {
    /// The leaf's owner nonce.
    pub owner_nonce: OwnerNonce,
    /// The account the key is under.
    pub account: u32,
    /// `m/6'/account'/c1'/c2'/c3'/c4'`.
    pub path: DerivationPath,
    /// The owner key `A`.
    pub key: XOnlyPublicKey,
}

/// The key for the leaf whose owner nonce is `owner_nonce`, from a signer
/// holding the wallet's master key. The derivation is hardened all the way, so
/// it needs the private key; the signer gives only the public key.
pub fn leaf_key<S: lwk_common::Signer>(
    signer: &S,
    account: u32,
    owner_nonce: &OwnerNonce,
) -> Result<LeafKey, ArkError> {
    let path = leaf_key_path(account, owner_nonce)?;
    let xpub = signer
        .derive_xpub(&path)
        .map_err(|e| ArkError::Derivation(format!("{e:?}")))?;
    let key = xpub.public_key.x_only_public_key().0;
    Ok(LeafKey {
        owner_nonce: *owner_nonce,
        account,
        path,
        key,
    })
}

/// A key for a new leaf: a fresh owner nonce and the key it gives. The wallet
/// keeps the nonce with the request until the leaf's record arrives.
pub fn fresh_leaf_key<S: lwk_common::Signer>(
    signer: &S,
    account: u32,
) -> Result<LeafKey, ArkError> {
    leaf_key(signer, account, &new_owner_nonce())
}

/// The key for `record`, rebuilt from its owner nonce, checked to be the
/// record's owner key. This is how a wallet restored from its mnemonic finds
/// its leaves among the records a server or a mirror returns.
pub fn restore_key<S: lwk_common::Signer>(
    signer: &S,
    account: u32,
    record: &LeafRecord,
) -> Result<LeafKey, ArkError> {
    let key = leaf_key(signer, account, &record.owner_nonce)?;
    if key.key != record.owner {
        return Err(ArkError::NotOurs {
            derived: key.key.to_string(),
            owner: record.owner.to_string(),
        });
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::ark::covenant::{
        Chain, ClockSchedule, LeafSpec, MedianTime, RelativeTime, ReserveRule, Template, Tree,
        TreeParams,
    };
    use elements::{AssetId, BlockHash};
    use lwk_signer::SwSigner;

    // A public test mnemonic; it holds nothing.
    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn the_path_follows_the_nonce() {
        // Computed independently (Python hashlib, the hash read as a bit string).
        let nonce: OwnerNonce = core::array::from_fn(|i| i as u8);
        assert_eq!(
            path_chunks(&nonce),
            [330116911, 809309685, 1623618847, 382661522]
        );
        assert_eq!(
            leaf_key_path(0, &nonce).unwrap().to_string(),
            "6'/0'/330116911'/809309685'/1623618847'/382661522'"
        );
        assert_eq!(
            path_chunks(&[0xff; 32]),
            [420927215, 1717579787, 356525174, 1629183434]
        );
        assert_eq!(
            leaf_key_path(7, &[0xff; 32]).unwrap().to_string(),
            "6'/7'/420927215'/1717579787'/356525174'/1629183434'"
        );
        assert!(matches!(
            leaf_key_path(1 << 31, &nonce),
            Err(ArkError::Account(_))
        ));
        // Every step is hardened, starting at the kit's own purpose.
        let path = leaf_key_path(3, &new_owner_nonce()).unwrap();
        assert_eq!(path.len(), 6);
        assert!(path.into_iter().all(|c| c.is_hardened()));
        assert_eq!(
            path[0],
            ChildNumber::from_hardened_idx(ARK_PURPOSE).unwrap()
        );
    }

    #[test]
    fn one_key_per_nonce() {
        let signer = SwSigner::new(MNEMONIC, false).unwrap();
        let a = fresh_leaf_key(&signer, 0).unwrap();
        let b = fresh_leaf_key(&signer, 0).unwrap();
        assert_ne!(a.owner_nonce, b.owner_nonce);
        assert_ne!(a.key, b.key);
        // The same nonce gives the same key, from the signer's own derivation.
        let again = leaf_key(&signer, 0, &a.owner_nonce).unwrap();
        assert_eq!(again, a);
        assert_eq!(signer.xonly_public_key(&a.path).unwrap(), a.key);
        // Another account gives another key.
        assert_ne!(leaf_key(&signer, 1, &a.owner_nonce).unwrap().key, a.key);
    }

    #[test]
    fn a_restore_finds_its_leaves_by_their_nonces() {
        let signer = SwSigner::new(MNEMONIC, false).unwrap();
        let keys: Vec<LeafKey> = (0..5)
            .map(|_| fresh_leaf_key(&signer, 0).unwrap())
            .collect();
        let stranger = SwSigner::new(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            false,
        )
        .unwrap();
        let theirs = fresh_leaf_key(&stranger, 0).unwrap();
        let genesis =
            BlockHash::from_str("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c")
                .unwrap();
        let asset = AssetId::from_slice(&[0x28; 32]).unwrap();
        let operator = SwSigner::new(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            false,
        )
        .unwrap();
        let s_key = leaf_key(&operator, 0, &[9; 32]).unwrap().key;
        let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
        let t0 = 1_800_000_000u32;
        let schedule = ClockSchedule::new(
            AssetId::from_slice(&[0x77; 32]).unwrap(),
            s_key,
            delay,
            (1..=3)
                .map(|k| MedianTime::from_consensus(t0 + 28 * 86_400 * k).unwrap())
                .collect(),
        )
        .unwrap();
        let leaves: Vec<LeafSpec> = keys
            .iter()
            .chain([&theirs])
            .enumerate()
            .map(|(i, k)| LeafSpec {
                template: Template::Vtxo1,
                owner: k.key,
                value: 1_000_000 + i as u64,
                owner_nonce: k.owner_nonce,
                operator_nonce: [i as u8 + 1; 32],
                exit_delay: delay,
                unlock_hash: [i as u8 + 0x40; 32],
            })
            .collect();
        let tree = Tree::build(
            TreeParams {
                asset,
                chain: Chain::new(genesis),
                schedule,
                burn: false,
                radix: 4,
                reserve: ReserveRule::Fixed {
                    node: 3_000,
                    entry: 1_000,
                },
                min_leaf: 1_000,
            },
            &leaves,
        )
        .unwrap();

        // A wallet restored from the same mnemonic: a new signer, no state.
        let restored = SwSigner::new(MNEMONIC, false).unwrap();
        let records = tree.records();
        for (i, rec) in records.iter().enumerate() {
            let rec = LeafRecord::from_bytes(&rec.to_bytes().unwrap()).unwrap();
            match restore_key(&restored, 0, &rec) {
                Ok(k) => {
                    assert!(i < 5);
                    assert_eq!(k, keys[i]);
                }
                Err(e) => {
                    assert_eq!(i, 5, "{e}");
                    assert!(matches!(e, ArkError::NotOurs { .. }), "{e}");
                }
            }
        }
        // A record whose nonce is not the one its key came from is not ours.
        let mut forged = records[0].clone();
        forged.owner_nonce = keys[1].owner_nonce;
        assert!(matches!(
            restore_key(&restored, 0, &forged),
            Err(ArkError::NotOurs { .. })
        ));
    }
}
