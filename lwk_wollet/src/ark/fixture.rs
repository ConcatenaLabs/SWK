//! Test fixtures for the Arca module: test keys, and batches with the round
//! transactions that create them.

use std::str::FromStr;

use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, Secp256k1, XOnlyPublicKey, ZERO_TWEAK};
use elements::{
    AssetId, AssetIssuance, BlockHash, ContractHash, LockTime, OutPoint, Script, Transaction, TxIn,
    TxOut, Txid,
};

use super::covenant::{LeafSpec, ReserveRule, Tree, TreeParams};
use super::{Chain, ClockSchedule, MedianTime, RelativeTime, Template, WalletPolicy};

pub const DAY: u32 = 86_400;

/// A test key from a fixed secret; it holds nothing.
pub fn test_key(b: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
}

pub fn xonly(k: &Keypair) -> XOnlyPublicKey {
    k.x_only_public_key().0
}

pub fn chain() -> Chain {
    Chain::new(
        BlockHash::from_str("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c")
            .unwrap(),
    )
}

/// The batch asset.
pub fn asset() -> AssetId {
    AssetId::from_slice(&[0x28; 32]).unwrap()
}

/// The operator's test key.
pub fn operator() -> Keypair {
    test_key(0x51)
}

/// The specification's exit delay and notice, 36 hours.
pub fn delay() -> RelativeTime {
    RelativeTime::from_seconds_ceil(36 * 3600).unwrap()
}

/// An explicit output.
pub fn explicit(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: Default::default(),
    }
}

/// A batch and the round that creates it.
pub struct Batch {
    pub tree: Tree,
    pub round: Transaction,
    /// The first expiry.
    pub e0: u32,
    /// The round's creation, 28 days before the first expiry.
    pub created: MedianTime,
    /// The preimage of every entry's unlock hash.
    pub preimage: [u8; 32],
}

impl Batch {
    /// Five leaves of 1,000,000 atoms and up, leaf 0 owned by `owner` with
    /// `owner_nonce`, the others by bystanders; created at `created`, with
    /// the sweep token issued from an outpoint named by `issuer`. The round
    /// pays the batch output at 0, the token's one atom at clock 0 at 1, then
    /// `extra`, then a fee.
    pub fn new(
        owner: XOnlyPublicKey,
        owner_nonce: [u8; 32],
        created: u32,
        issuer: u8,
        preimage: [u8; 32],
        extra: Vec<TxOut>,
    ) -> Batch {
        let s = operator();
        let e0 = created + 28 * DAY;
        let issuer = OutPoint::new(Txid::from_byte_array([issuer; 32]), 0);
        let token = AssetId::new_issuance(issuer, ContractHash::from_byte_array([0; 32]));
        let schedule = ClockSchedule::new(
            token,
            xonly(&s),
            delay(),
            vec![
                MedianTime::from_consensus(e0).unwrap(),
                MedianTime::from_consensus(e0 + 28 * DAY).unwrap(),
            ],
        )
        .unwrap();
        let leaves: Vec<LeafSpec> = (0..5u8)
            .map(|i| LeafSpec {
                template: Template::Vtxo1,
                owner: if i == 0 {
                    owner
                } else {
                    xonly(&test_key(0xc0 + i))
                },
                value: 1_000_000 + i as u64,
                owner_nonce: if i == 0 {
                    owner_nonce
                } else {
                    [owner_nonce[0] ^ i; 32]
                },
                operator_nonce: [0x60 + i; 32],
                exit_delay: delay(),
                unlock_hash: sha256::Hash::hash(&preimage).to_byte_array(),
            })
            .collect();
        let tree = Tree::build(
            TreeParams {
                asset: asset(),
                chain: chain(),
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
        let mut output = vec![
            tree.batch_output().txout(),
            explicit(token, 1, tree.clock0_script_pubkey()),
        ];
        output.extend(extra);
        output.push(TxOut::new_fee(2_000, asset()));
        let mut round = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: issuer,
                ..Default::default()
            }],
            output,
        };
        round.input[0].asset_issuance = AssetIssuance {
            asset_blinding_nonce: ZERO_TWEAK,
            asset_entropy: [0; 32],
            amount: Value::Explicit(1),
            inflation_keys: Value::Null,
            denomination: 0,
        };
        Batch {
            tree,
            round,
            e0,
            created: MedianTime::from_consensus(created).unwrap(),
            preimage,
        }
    }

    /// The policy of a wallet at the round's creation.
    pub fn policy(&self) -> WalletPolicy {
        WalletPolicy::new(chain(), xonly(&operator()), self.created)
    }
}
