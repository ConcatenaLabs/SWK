//! Paying out of round: the reassignment a wallet builds as its sender.
//!
//! A coin moves between rounds by a checkpoint and a reassignment, which its
//! owner and the operator sign in advance (the Arca library's `transfer`
//! module). The sender's wallet chooses the reassignment's outputs: a leaf for
//! each receiver, from the receive request the receiver published
//! ([`ReceiveRequest`]: its owner key, owner nonce and exit delay), and a leaf
//! of its own for the change.
//!
//! Every leaf a reassignment creates has a salt of two nonces,
//! `SHA256("Arca/salt" ‖ owner_nonce ‖ creator_nonce)`. The owner's comes from
//! the request; the second is the creator's, and in a reassignment the
//! creator is the sender. The wallet draws it fresh and at random for every
//! leaf it creates, change included ([`new_creator_nonce`]). Two
//! reassignments that pay one receive request then still create two different
//! leaves, and never commit to outputs one transaction could satisfy at once.
//! Were they mergeable, the operator could put both senders' coins into one
//! transaction and the second coin would go to whoever broadcasts it; the
//! operator refuses to co-sign such a pair (kind `merge`), and a sender that
//! draws its nonces this way is never refused for it.
//!
//! A reassignment pays each receive request once. A request names one owner
//! key, and a key holds one leaf: two leaves under it would let a signature
//! made for one spend the other.

use std::collections::{BTreeMap, BTreeSet};

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;
use rand::RngCore;

use super::covenant::leaf::MAX_OUTPUTS;
use super::covenant::TransferPlan;
use super::keys::OwnerNonce;
use super::{
    Chain, CoinRecord, ExplicitOutput, NewLeaf, RelativeTime, Transfer, TransferError,
    TransferInput, ValidCoin,
};

/// The second nonce of a leaf's salt, drawn by the leaf's creator.
pub type CreatorNonce = [u8; 32];

/// A fresh creator nonce, from the system's random source: one for every leaf
/// a reassignment creates.
pub fn new_creator_nonce() -> CreatorNonce {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// What a receiver publishes to be paid out of round: the key of the leaf it
/// asks for, the owner nonce that key follows from, and the exit delay it
/// accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveRequest {
    /// The new leaf's owner key.
    pub owner: XOnlyPublicKey,
    /// The receiver's owner nonce for the leaf.
    pub owner_nonce: OwnerNonce,
    /// The new leaf's exit delay.
    pub exit_delay: RelativeTime,
}

/// One leaf a reassignment creates: `value` atoms of `asset` to `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payment {
    /// The receive request the leaf is for; the wallet's own for its change.
    pub to: ReceiveRequest,
    /// The leaf's asset.
    pub asset: AssetId,
    /// The leaf's value, in atoms.
    pub value: u64,
}

/// Why a reassignment was not built.
#[derive(thiserror::Error, Debug)]
pub enum PayError {
    /// One receive request is paid twice: two leaves under one key.
    #[error("receive request {0} is paid twice: its key would hold two leaves")]
    RequestTwice(String),

    /// The Arca library refuses the reassignment.
    #[error(transparent)]
    Transfer(#[from] TransferError),
}

/// A reassignment the wallet sends: the plan its owners and the operator
/// sign, and the new leaf behind each output.
#[derive(Debug, Clone)]
pub struct Reassignment {
    /// The coins spent, each with its checkpoint's value, and the outputs.
    pub plan: TransferPlan,
    /// The leaf at each output of `plan`, in order, each with its own fresh
    /// creator nonce.
    pub leaves: Vec<NewLeaf>,
}

impl Reassignment {
    /// The reassignment of `inputs` (each coin with its checkpoint's value)
    /// into one leaf per payment, under `operator` on `chain`. Draws a fresh
    /// creator nonce for every leaf. Refuses what a receiver's validation
    /// would refuse, before anything is signed: a receive request paid twice,
    /// an output count outside 1 to 4 ([`TransferError::Outputs`]), a
    /// checkpoint worth more than its coin ([`TransferError::CheckpointValue`])
    /// and outputs taking more of an asset than the checkpoints hold
    /// ([`TransferError::Overspend`]).
    pub fn new(
        inputs: Vec<(ValidCoin, u64)>,
        payments: &[Payment],
        operator: XOnlyPublicKey,
        chain: Chain,
    ) -> Result<Reassignment, PayError> {
        let mut requests = BTreeSet::new();
        for p in payments {
            if !requests.insert(p.to.owner_nonce) || !requests.insert(p.to.owner.serialize()) {
                return Err(PayError::RequestTwice(p.to.owner.to_string()));
            }
        }
        let leaves: Vec<NewLeaf> = payments
            .iter()
            .map(|p| NewLeaf {
                owner: p.to.owner,
                owner_nonce: p.to.owner_nonce,
                creator_nonce: new_creator_nonce(),
                exit_delay: p.to.exit_delay,
            })
            .collect();
        let outputs = payments
            .iter()
            .zip(&leaves)
            .map(|(p, l)| {
                ExplicitOutput::new(p.asset, p.value, l.policy(operator, chain).script_pubkey())
            })
            .collect();
        let plan = TransferPlan { inputs, outputs };
        let m = plan.outputs.len();
        if m == 0 || m > MAX_OUTPUTS as usize {
            return Err(TransferError::Outputs(m).into());
        }
        let mut held: BTreeMap<AssetId, u128> = BTreeMap::new();
        for (coin, checkpoint) in &plan.inputs {
            if *checkpoint == 0 || *checkpoint > coin.value {
                return Err(TransferError::CheckpointValue {
                    value: *checkpoint,
                    coin: coin.value,
                }
                .into());
            }
            *held.entry(coin.asset).or_default() += *checkpoint as u128;
        }
        let mut taken: BTreeMap<AssetId, u128> = BTreeMap::new();
        for o in &plan.outputs {
            *taken.entry(o.asset).or_default() += o.value as u128;
        }
        for (asset, t) in taken {
            if t > held.get(&asset).copied().unwrap_or(0) {
                return Err(TransferError::Overspend(asset).into());
            }
        }
        Ok(Reassignment { plan, leaves })
    }

    /// The record the receiver of output `index` is given: the coins spent,
    /// each with its signed checkpoint and reassignment pairs, in the plan's
    /// input order.
    pub fn record(&self, index: usize, inputs: Vec<TransferInput>) -> Result<CoinRecord, PayError> {
        let leaf = *self.leaves.get(index).ok_or(TransferError::Index {
            index,
            count: self.leaves.len(),
        })?;
        Ok(CoinRecord::Transfer(Box::new(Transfer {
            inputs,
            outputs: self.plan.outputs.clone(),
            index: index as u8,
            leaf,
        })))
    }
}

#[cfg(test)]
mod tests {
    use elements::secp256k1_zkp::Keypair;

    use super::*;
    use crate::ark::covenant::sign::sign_digest;
    use crate::ark::covenant::spend::Pair;
    use crate::ark::covenant::transfer::mergeable;
    use crate::ark::covenant::SeenReassignments;
    use crate::ark::fixture::{self, test_key, xonly, Batch};
    use crate::ark::verify::verify_coin;
    use crate::ark::WalletPolicy;

    const MARGIN: u64 = 2_000;

    /// A sender holding leaf 0 of a batch, and its policy.
    struct Sender {
        batch: Batch,
        policy: WalletPolicy,
        key: Keypair,
        coin: CoinRecord,
    }

    /// Leaf 0 of the batch, owned by the sender's key.
    fn sender() -> Sender {
        let key = test_key(0xa1);
        let batch = Batch::new(
            xonly(&key),
            [0x40; 32],
            1_800_000_000,
            0x1e,
            [0x33; 32],
            vec![],
        );
        sender_at(batch, 0, key)
    }

    /// Leaf `leaf` of `batch`, owned by `key`: the fixture gives leaf 0 to
    /// the key it is built with and leaf `i` to `test_key(0xc0 + i)`.
    fn sender_at(batch: Batch, leaf: usize, key: Keypair) -> Sender {
        let policy = batch.policy();
        let record = batch.tree.records()[leaf].clone();
        let auths = record
            .branch()
            .unwrap()
            .nodes
            .iter()
            .map(|n| {
                (
                    sign_digest(
                        &key,
                        &n.unroll_authorisation(batch.created).digest,
                        &[0; 32],
                    ),
                    batch.created,
                )
            })
            .collect();
        let coin = CoinRecord::Leaf {
            record,
            preimage: batch.preimage,
            auths,
        };
        Sender {
            batch,
            policy,
            key,
            coin,
        }
    }

    fn request(b: u8) -> ReceiveRequest {
        ReceiveRequest {
            owner: xonly(&test_key(b)),
            owner_nonce: [b; 32],
            exit_delay: fixture::delay(),
        }
    }

    impl Sender {
        /// A second sender: leaf 1 of the same batch, its bystander's.
        fn second(&self) -> Sender {
            let batch = Batch::new(
                xonly(&self.key),
                [0x40; 32],
                1_800_000_000,
                0x1e,
                [0x33; 32],
                vec![],
            );
            sender_at(batch, 1, test_key(0xc1))
        }

        fn valid(&self) -> ValidCoin {
            self.coin
                .resolve(&[self.batch.round.clone()], &self.policy)
                .unwrap()
        }

        /// The sender's coin, paid to `to` less two margins, with the
        /// rest of the checkpoint to `change`.
        fn pay(
            &self,
            to: &ReceiveRequest,
            value: u64,
            change: Option<&ReceiveRequest>,
        ) -> Reassignment {
            let coin = self.valid();
            let checkpoint = coin.value - MARGIN;
            let mut payments = vec![Payment {
                to: *to,
                asset: coin.asset,
                value,
            }];
            if let Some(c) = change {
                payments.push(Payment {
                    to: *c,
                    asset: coin.asset,
                    value: checkpoint - MARGIN - value,
                });
            }
            Reassignment::new(
                vec![(coin, checkpoint)],
                &payments,
                xonly(&fixture::operator()),
                self.policy.chain,
            )
            .unwrap()
        }
    }

    #[test]
    fn every_leaf_gets_its_own_creator_nonce() {
        let f = sender();
        let r = request(0xb1);
        let change = request(0xa9);
        let value = f.valid().value / 2;
        let one = f.pay(&r, value, Some(&change));
        let two = f.pay(&r, value, Some(&change));
        // Change included: four leaves, four creator nonces.
        let nonces: BTreeSet<_> = one
            .leaves
            .iter()
            .chain(&two.leaves)
            .map(|l| l.creator_nonce)
            .collect();
        assert_eq!(nonces.len(), 4);
        // Two payments of one value to one request, from one coin, never
        // commit to outputs one transaction could satisfy at once.
        assert_ne!(one.plan.outputs, two.plan.outputs);
        assert!(!mergeable(&one.plan.outputs, &two.plan.outputs));
        let mut seen = SeenReassignments::new();
        one.plan.admit(&mut seen).unwrap();
        two.plan.admit(&mut seen).unwrap();

        // Two senders paying one request the same value, with no change
        // (D33): fresh nonces, two leaves, and the operator admits both.
        let g = f.second();
        let a = f.pay(&r, 900_000, None);
        let b = g.pay(&r, 900_000, None);
        assert!(!mergeable(&a.plan.outputs, &b.plan.outputs));
        let mut seen = SeenReassignments::new();
        a.plan.admit(&mut seen).unwrap();
        b.plan.admit(&mut seen).unwrap();
        // What the fresh nonce prevents: the second sender repeating the
        // first's creator nonce builds the same leaf, which one transaction
        // could pay once for both coins. The operator refuses to co-sign it,
        // kind `merge`.
        let mut repeated = b.clone();
        repeated.leaves[0].creator_nonce = a.leaves[0].creator_nonce;
        repeated.plan.outputs = a.plan.outputs.clone();
        let err = repeated.plan.admit(&mut seen).unwrap_err();
        assert_eq!(err.kind(), "merge", "{err}");
        println!("a repeated creator nonce: {err} (kind {})", err.kind());
    }

    #[test]
    fn the_receiver_verifies_the_coin_with_the_sender_s_nonce() {
        let f = sender();
        let b = test_key(0xb1);
        let r = request(0xb1);
        let coin = f.valid();
        let re = f.pay(&r, coin.value - 2 * MARGIN, None);
        let s = fixture::operator();
        let pair = |d: &[u8; 32]| Pair {
            operator: sign_digest(&s, d, &[0; 32]),
            owner: sign_digest(&f.key, d, &[0; 32]),
        };
        let input = TransferInput {
            coin: f.coin.clone(),
            checkpoint_value: re.plan.inputs[0].1,
            checkpoint: pair(&re.plan.checkpoint_message(0).unwrap().digest),
            reassignment: pair(&re.plan.reassignment_message(0).unwrap().digest),
        };
        let record = re.record(0, vec![input]).unwrap();
        let ok = verify_coin(
            &record,
            &[f.batch.round.clone()],
            &f.policy,
            &xonly(&b),
            &r.owner_nonce,
            None,
        )
        .unwrap();
        assert_eq!(ok.coin.value, coin.value - 2 * MARGIN);
        match &record {
            CoinRecord::Transfer(t) => assert_eq!(t.leaf.creator_nonce, re.leaves[0].creator_nonce),
            _ => unreachable!(),
        }
        assert!(re.record(1, vec![]).is_err());
    }

    #[test]
    fn a_request_is_paid_once() {
        let f = sender();
        let coin = f.valid();
        let r = request(0xb1);
        let p = Payment {
            to: r,
            asset: coin.asset,
            value: 1_000,
        };
        let err = Reassignment::new(
            vec![(coin.clone(), coin.value - MARGIN)],
            &[p, p],
            xonly(&fixture::operator()),
            f.policy.chain,
        )
        .unwrap_err();
        assert!(matches!(err, PayError::RequestTwice(_)), "{err}");
        // What a receiver would refuse is refused before anything is signed.
        let op = xonly(&fixture::operator());
        let over = Payment {
            value: coin.value - MARGIN + 1,
            ..p
        };
        let err = Reassignment::new(
            vec![(coin.clone(), coin.value - MARGIN)],
            &[over],
            op,
            f.policy.chain,
        )
        .unwrap_err();
        assert!(
            matches!(err, PayError::Transfer(TransferError::Overspend(_))),
            "{err}"
        );
        let err = Reassignment::new(
            vec![(coin.clone(), coin.value + 1)],
            &[p],
            op,
            f.policy.chain,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PayError::Transfer(TransferError::CheckpointValue { .. })
            ),
            "{err}"
        );
        let five: Vec<Payment> = (0..5u8)
            .map(|i| Payment {
                to: request(0xc0 + i),
                ..p
            })
            .collect();
        let err = Reassignment::new(
            vec![(coin.clone(), coin.value - MARGIN)],
            &five,
            op,
            f.policy.chain,
        )
        .unwrap_err();
        assert!(
            matches!(err, PayError::Transfer(TransferError::Outputs(5))),
            "{err}"
        );
        Reassignment::new(
            vec![(coin.clone(), coin.value - MARGIN)],
            &five[..4],
            op,
            f.policy.chain,
        )
        .unwrap();
    }
}
