//! The forfeit a wallet signs to give a leaf up in a round.
//!
//! In a refresh or an offboard the owner gives its old leaf up through the
//! leaf's collaborative path into a forfeit output ([`Forfeit`]). The operator
//! can claim that output only by publishing the preimage that unlocks the
//! owner's new entry (or offboard output), and only while the round carrying
//! the new leaf is in the chain: the claim needs one atom of the round's
//! connector asset `M`, which only a spend of the round's connector output
//! `c` issues. If the operator withholds the preimage, the owner takes the
//! old coin back after the refund delay.
//!
//! The wallet never takes `h` or `M` from the operator's word. [`refresh`]
//! verifies the new leaf against the round itself, as a leaf taken from a
//! round, takes `h` from that leaf's entry and `M` from the round, and refuses
//! unless output `c` of the round carries the connector script
//! ([`ConnectorPolicy`]); [`offboard`] does the same for an offboard output
//! the round pays. What the wallet then signs is [`Forfeit::message`]: the old
//! leaf's rebindable message over the forfeit output alone, which
//! `lwk_signer`'s `sign_csfs` takes as a rebind of the old leaf into that one
//! output with no other input.
//!
//! Once the wallet holds the new leaf's preimage and its round is final, it
//! also signs the release of the lowest node above the old leaf, which lets
//! the operator reclaim that node before the batch expires ([`release`],
//! [`release_for_offboard`]). The release names the same round's connector
//! asset `M`, so like the forfeit it is void if that round is lost; the
//! wallet takes `H` from the old leaf it holds and `M` from the round it
//! validated. `lwk_signer`'s `ReleaseMessage::release` makes it a message for
//! `sign_csfs`, with the node's children for the wallet to show.
//!
//! After a rollback the operator broadcasts the identical round again, and
//! every forfeit of it can still be claimed. A transaction with another txid
//! paying the same batch is a new round: a forfeit signed for the old one can
//! never be claimed, and the old leaf stays its owner's
//! ([`super::verify::Recheck::Replaced`]).

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

pub use arca_covenant::spend::SpendError;
pub use arca_covenant::{
    connector_asset, ConnectorPolicy, Forfeit, ForfeitPolicy, OffboardPolicy, Release,
};

use super::keys::OwnerNonce;
use super::verify::{VerifyError, EXIT_DEADLINE_MARGIN};
use super::{
    ExplicitOutput, LeafId, LeafPolicy, LeafRecord, RecordError, RelativeTime, ValidCoin,
    ValidLeaf, WalletPolicy,
};

/// A leaf the wallet gives up: its policy, the coin it holds and its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenUp {
    /// The leaf's scripts: owner, operator, salt, chain and exit delay.
    pub leaf: LeafPolicy,
    /// The coin's asset.
    pub asset: AssetId,
    /// The coin's value, in atoms.
    pub value: u64,
    /// The leaf's id, which the forfeit output names.
    pub id: LeafId,
}

impl GivenUp {
    /// A leaf of a batch, from its record.
    pub fn leaf(record: &LeafRecord) -> Result<GivenUp, RecordError> {
        Ok(GivenUp {
            leaf: record.leaf(),
            asset: record.asset,
            value: record.value,
            id: record.leaf_id()?,
        })
    }

    /// A coin the wallet received out of round
    /// ([`super::verify::verify_coin`]).
    pub fn coin(coin: &ValidCoin) -> GivenUp {
        GivenUp {
            leaf: coin.leaf,
            asset: coin.asset,
            value: coin.value,
            id: coin.id,
        }
    }
}

/// Why a forfeit was not built.
#[derive(thiserror::Error, Debug)]
pub enum ForfeitError {
    /// The new leaf does not verify against the round.
    #[error("the new leaf: {0}")]
    NewLeaf(#[from] VerifyError),

    /// The round, its connector output or the offboard is not what the
    /// forfeit needs.
    #[error(transparent)]
    Spend(#[from] SpendError),

    /// Even a forfeit published now could not be refunded before the new
    /// batch's exit deadline.
    #[error("a refund delay of {delay} seconds from now ends at {ends}, after the new batch's exit deadline {deadline}")]
    RefundAfterDeadline {
        /// The refund delay, in seconds.
        delay: u64,
        /// When a refund of a forfeit published now becomes possible.
        ends: u64,
        /// The new leaf's exit deadline, three days before its first expiry.
        deadline: u64,
    },
}

/// The forfeit the wallet signs to refresh `old` into the new leaf `new`.
///
/// `new` is verified against `round` as the wallet's own leaf taken from a
/// round: under `policy` with its acceptance horizon, for the wallet's key
/// `owner` and the `owner_nonce` it picked. The forfeit's unlock hash is that
/// leaf's entry's and its connector asset is the one spending output `c` of
/// `round` issues; `c` must carry the operator's connector script. The old
/// leaf must be under the same operator.
///
/// The specification has the refund delay end before the new batch's exit
/// deadline. The operator chooses when the forfeit is published, so no check
/// at signing time proves that; this refuses a `refund_delay` that fails it
/// even for a forfeit published at `policy.now`. A wallet whose preimage does
/// not arrive starts its exit of the old leaf at once.
#[allow(clippy::too_many_arguments)]
pub fn refresh(
    old: &GivenUp,
    new: &LeafRecord,
    round: &Transaction,
    c: u32,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
    refund_delay: RelativeTime,
    margin: u64,
) -> Result<Forfeit, ForfeitError> {
    let valid = new
        .validate(round, policy, owner, owner_nonce)
        .map_err(VerifyError)?;
    let deadline = new.schedule.expiries()[0]
        .to_consensus_u32()
        .saturating_sub(EXIT_DEADLINE_MARGIN) as u64;
    let ends = policy.now.to_consensus_u32() as u64 + refund_delay.seconds();
    if ends >= deadline {
        return Err(ForfeitError::RefundAfterDeadline {
            delay: refund_delay.seconds(),
            ends,
            deadline,
        });
    }
    Ok(Forfeit::for_refresh(
        old.leaf,
        (old.asset, old.value),
        old.id,
        &valid,
        round,
        c,
        refund_delay,
        margin,
    )?)
}

/// The forfeit the wallet signs to give `old` up for the offboard output
/// `offboard`, which `round` must pay, whose connector output `c` must carry
/// the operator's connector script.
///
/// The offboard's reclaim delay must outlast the unroll of the old leaf, its
/// exit delay, the forfeit's refund delay and a margin to broadcast the
/// unlock (the Arca library's `offboard` module). That depends on the old
/// leaf's depth and on how fast transactions confirm, so it is the caller's
/// to check before signing; this does not.
pub fn offboard(
    old: &GivenUp,
    offboard: &OffboardPolicy,
    round: &Transaction,
    c: u32,
    refund_delay: RelativeTime,
    margin: u64,
) -> Result<Forfeit, ForfeitError> {
    Ok(Forfeit::for_offboard(
        old.leaf,
        (old.asset, old.value),
        old.id,
        offboard,
        round,
        c,
        refund_delay,
        margin,
    )?)
}

/// A release to sign: the Arca library's [`Release`] and the lowest node's
/// children, in output order, for the wallet to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRelease {
    /// The release: chain, the node's children hash `H`, the old leaf's
    /// owner key and the round's connector asset `M`.
    pub release: Release,
    /// The lowest node's children, whose records hash to `H`.
    pub children: Vec<ExplicitOutput>,
}

/// The old leaf, checked against its own round. Only its structure matters
/// here, not how long it has left: a leaf being given up may be close to its
/// exit deadline.
fn old_leaf(
    old: &LeafRecord,
    old_round: &Transaction,
    policy: &WalletPolicy,
) -> Result<ValidLeaf, ForfeitError> {
    let any_time = WalletPolicy {
        horizon: 0,
        ..*policy
    };
    Ok(old
        .validate_round(old_round, &any_time)
        .map_err(VerifyError)?)
}

fn node_release(old: &ValidLeaf, release: Release) -> NodeRelease {
    let children = old
        .branch
        .nodes
        .last()
        .map(|n| n.children.iter().map(|c| c.output()).collect())
        .unwrap_or_default();
    NodeRelease { release, children }
}

/// The release of the lowest node above `old` (checked against `old_round`),
/// given up in a refresh for the new leaf `new`, which is verified against
/// `round` as the wallet's own leaf it holds: under the receipt form of
/// `policy`, for the wallet's key `owner` and the `owner_nonce` it picked.
/// `M` is the connector asset spending output `c` of `round` issues; `c` must
/// carry the operator's connector script. Sign it only once the preimage of
/// the new leaf is held and `round` is final.
#[allow(clippy::too_many_arguments)]
pub fn release(
    old: &LeafRecord,
    old_round: &Transaction,
    new: &LeafRecord,
    round: &Transaction,
    c: u32,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<NodeRelease, ForfeitError> {
    let old = old_leaf(old, old_round, policy)?;
    let new = new
        .validate(round, &policy.receipt(), owner, owner_nonce)
        .map_err(VerifyError)?;
    let r = Release::for_refresh(&old, &new, round, c)?;
    Ok(node_release(&old, r))
}

/// The release of the lowest node above `old` (checked against `old_round`),
/// given up for the offboard output `offboard`, which `round` must pay, whose
/// connector output `c` must carry the operator's connector script.
pub fn release_for_offboard(
    old: &LeafRecord,
    old_round: &Transaction,
    offboard: &OffboardPolicy,
    round: &Transaction,
    c: u32,
    policy: &WalletPolicy,
) -> Result<NodeRelease, ForfeitError> {
    let old = old_leaf(old, old_round, policy)?;
    let r = Release::for_offboard(&old, offboard, round, c)?;
    Ok(node_release(&old, r))
}

#[cfg(test)]
mod tests {
    use elements::hashes::{sha256, Hash};
    use elements::Script;
    use lwk_signer::csfs::{
        ArcaMessage, CommittedOutput, CsfsError, CsfsPolicy, RebindMessage, RebindSource,
        ReleaseMessage,
    };
    use lwk_signer::SwSigner;

    use super::*;
    use crate::ark::covenant::ExplicitOutput;
    use crate::ark::fixture::{self, asset, operator, test_key, xonly, Batch, DAY};
    use crate::ark::keys::{fresh_leaf_key, LeafKey};
    use crate::ark::MedianTime;

    // A public test mnemonic; it holds nothing.
    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const C: u32 = 2;
    const MARGIN: u64 = 2_000;

    /// A's old leaf in a first batch, and a second round, five days later,
    /// carrying A's new leaf at leaf 0, the connector at output 2 and
    /// `extra` after it.
    struct Refresh {
        signer: SwSigner,
        old_key: LeafKey,
        old: LeafRecord,
        old_round: Transaction,
        new_key: LeafKey,
        new: Batch,
        policy: WalletPolicy,
    }

    fn refresh_fixture(connector: Option<XOnlyPublicKey>, extra: Vec<elements::TxOut>) -> Refresh {
        let signer = SwSigner::new(MNEMONIC, false).unwrap();
        let old_key = fresh_leaf_key(&signer, 0).unwrap();
        let new_key = fresh_leaf_key(&signer, 0).unwrap();
        let created = 1_800_000_000;
        let old_batch = Batch::new(
            old_key.key,
            old_key.owner_nonce,
            created,
            0x1e,
            [0x33; 32],
            vec![],
        );
        let mut outputs = vec![];
        if let Some(op) = connector {
            outputs.push(
                ConnectorPolicy { operator: op }
                    .output(asset(), 5_000)
                    .txout(),
            );
        }
        outputs.extend(extra);
        let new = Batch::new(
            new_key.key,
            new_key.owner_nonce,
            created + 5 * DAY,
            0x2e,
            [0x44; 32],
            outputs,
        );
        let policy = new.policy();
        Refresh {
            signer,
            old: old_batch.tree.records()[0].clone(),
            old_round: old_batch.round.clone(),
            old_key,
            new_key,
            new,
            policy,
        }
    }

    impl Refresh {
        fn build(&self, c: u32, round: &Transaction) -> Result<Forfeit, ForfeitError> {
            refresh(
                &GivenUp::leaf(&self.old).unwrap(),
                &self.new.tree.records()[0],
                round,
                c,
                &self.policy,
                &self.new_key.key,
                &self.new_key.owner_nonce,
                fixture::delay(),
                MARGIN,
            )
        }
    }

    #[test]
    fn a_refresh_forfeit_binds_the_validated_leaf_and_round() {
        // Review R4, F7; decision D30: h and M come from the new leaf the
        // wallet validated and from that round, and output c must be the
        // operator's connector.
        let f = refresh_fixture(Some(xonly(&operator())), vec![]);
        let forfeit = f.build(C, &f.new.round).unwrap();
        let new = &f.new.tree.records()[0];
        assert_eq!(forfeit.policy.unlock_hash, new.unlock_hash);
        assert_eq!(
            forfeit.policy.unlock_hash,
            sha256::Hash::hash(&f.new.preimage).to_byte_array()
        );
        assert_eq!(
            forfeit.policy.connector,
            connector_asset(f.new.round.txid(), C)
        );
        assert_eq!(forfeit.policy.leaf_id, f.old.leaf_id().unwrap());
        assert_eq!(forfeit.value - forfeit.margin, forfeit.output().value);

        // The kit's signer signs it as a rebind of the old leaf into the
        // forfeit output, spent alone: the same digest.
        let out = forfeit.output();
        let msg = ArcaMessage::Rebind(RebindMessage {
            source: RebindSource::leaf(&f.old).unwrap(),
            asset_in: forfeit.asset,
            value_in: forfeit.value,
            outputs: vec![CommittedOutput {
                asset: out.asset,
                value: out.value,
                script_pubkey: out.script_pubkey.clone(),
            }],
            other_inputs: Some(vec![]),
        });
        let digest = msg.digest().unwrap();
        assert_eq!(digest, forfeit.message().digest);
        let genesis = f.policy.chain.genesis_hash();
        let sig = f
            .signer
            .sign_csfs(
                &f.old_key.path,
                &msg,
                &digest,
                &CsfsPolicy::with_ceiling(genesis, MARGIN),
            )
            .unwrap();
        msg.verify(
            &elements::secp256k1_zkp::Secp256k1::verification_only(),
            &f.old.owner,
            &sig.serialize(),
        )
        .unwrap();
        // The margin is what the forfeit leaves to whoever broadcasts it.
        let err = f
            .signer
            .sign_csfs(
                &f.old_key.path,
                &msg,
                &digest,
                &CsfsPolicy::with_ceiling(genesis, MARGIN - 1),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                CsfsError::AboveCeiling {
                    uncommitted: MARGIN,
                    ..
                }
            ),
            "{err}"
        );

        // Another transaction paying the same batch is another round: the
        // forfeit for it names its connector, not this one's.
        let mut replaced = f.new.round.clone();
        replaced.input[0].sequence = elements::Sequence(0xffff_fffe);
        let other = f.build(C, &replaced).unwrap();
        assert_ne!(other.policy.connector, forfeit.policy.connector);
        assert_eq!(other.policy.connector, connector_asset(replaced.txid(), C));
    }

    #[test]
    fn a_refresh_forfeit_is_refused_when_its_round_does_not_bind_it() {
        let f = refresh_fixture(Some(xonly(&operator())), vec![]);
        // Output c is the batch output, the token, the fee: not the connector.
        for c in [0, 1, 3, 9] {
            let err = f.build(c, &f.new.round).unwrap_err();
            assert!(
                matches!(err, ForfeitError::Spend(SpendError::Connector(n)) if n == c),
                "{c}: {err}"
            );
        }
        // A round with no connector, or one of another operator.
        let none = refresh_fixture(None, vec![]);
        assert!(matches!(
            none.build(C, &none.new.round),
            Err(ForfeitError::Spend(SpendError::Connector(C)))
        ));
        let theirs = refresh_fixture(Some(xonly(&test_key(0x99))), vec![]);
        assert!(matches!(
            theirs.build(C, &theirs.new.round),
            Err(ForfeitError::Spend(SpendError::Connector(C)))
        ));
        // A round paying an output named like a connector, but bare OP_TRUE.
        let mut bare = f.new.round.clone();
        bare.output[C as usize].script_pubkey = Script::from(vec![0x51]);
        // The batch output and token are unchanged, so the leaf still
        // verifies against it; output c does not carry the connector.
        assert!(matches!(
            f.build(C, &bare),
            Err(ForfeitError::Spend(SpendError::Connector(C)))
        ));

        // The new leaf must verify as the wallet's own, from a round.
        let wrong_nonce = refresh(
            &GivenUp::leaf(&f.old).unwrap(),
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &f.policy,
            &f.new_key.key,
            &[0x42; 32],
            fixture::delay(),
            MARGIN,
        )
        .unwrap_err();
        assert!(
            matches!(&wrong_nonce, ForfeitError::NewLeaf(e) if e.failed() == "owner"),
            "{wrong_nonce}"
        );
        let mut late = f.policy;
        late.now = MedianTime::from_consensus(f.policy.now.to_consensus_u32() + 2 * DAY).unwrap();
        let err = refresh(
            &GivenUp::leaf(&f.old).unwrap(),
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &late,
            &f.new_key.key,
            &f.new_key.owner_nonce,
            fixture::delay(),
            MARGIN,
        )
        .unwrap_err();
        assert!(
            matches!(&err, ForfeitError::NewLeaf(e) if e.failed() == "wallet policy"),
            "{err}"
        );

        // The old leaf under another operator.
        let mut stranger = GivenUp::leaf(&f.old).unwrap();
        stranger.leaf.operator = xonly(&test_key(0x99));
        let err = refresh(
            &stranger,
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &f.policy,
            &f.new_key.key,
            &f.new_key.owner_nonce,
            fixture::delay(),
            MARGIN,
        )
        .unwrap_err();
        assert!(
            matches!(err, ForfeitError::Spend(SpendError::OtherOperator)),
            "{err}"
        );

        // A refund delay that cannot end before the new exit deadline.
        let long = RelativeTime::from_seconds_ceil(25 * DAY as u64).unwrap();
        let err = refresh(
            &GivenUp::leaf(&f.old).unwrap(),
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &f.policy,
            &f.new_key.key,
            &f.new_key.owner_nonce,
            long,
            MARGIN,
        )
        .unwrap_err();
        assert!(
            matches!(err, ForfeitError::RefundAfterDeadline { .. }),
            "{err}"
        );
    }

    impl Refresh {
        fn release(&self, c: u32, round: &Transaction) -> Result<NodeRelease, ForfeitError> {
            release(
                &self.old,
                &self.old_round,
                &self.new.tree.records()[0],
                round,
                c,
                &self.policy,
                &self.new_key.key,
                &self.new_key.owner_nonce,
            )
        }
    }

    fn committed(o: &ExplicitOutput) -> CommittedOutput {
        CommittedOutput {
            asset: o.asset,
            value: o.value,
            script_pubkey: o.script_pubkey.clone(),
        }
    }

    #[test]
    fn a_release_is_bound_to_the_round_of_the_new_leaf() {
        // D34: the release names the connector asset M of the round that
        // made the new leaf, read from that round, and H from the old leaf.
        let f = refresh_fixture(Some(xonly(&operator())), vec![]);
        let r = f.release(C, &f.new.round).unwrap();
        assert_eq!(r.release.connector, connector_asset(f.new.round.txid(), C));
        assert_eq!(r.release.owner, f.old.owner);
        let lowest = f.old.branch().unwrap().nodes.last().unwrap().clone();
        assert_eq!(r.release.node_hash, lowest.children_hash());
        let chain = f.policy.chain;
        assert_eq!(
            r.release.message().digest,
            chain
                .release_message(&lowest.children_hash(), r.release.connector)
                .digest
        );

        // The kit's signer rebuilds the same digest from the node's children
        // and M, signs it with the old leaf's key, and the release verifies.
        let msg = ArcaMessage::Release(
            ReleaseMessage::release(&r.release, r.children.iter().map(committed).collect())
                .unwrap(),
        );
        let digest = msg.digest().unwrap();
        assert_eq!(digest, r.release.message().digest);
        let genesis = f.policy.chain.genesis_hash();
        let policy = CsfsPolicy::with_ceiling(genesis, 0);
        let sig = f
            .signer
            .sign_csfs(&f.old_key.path, &msg, &digest, &policy)
            .unwrap();
        r.release.verify(&sig).unwrap();
        assert!(msg
            .describe()
            .join("\n")
            .contains(&r.release.connector.to_string()));

        // Signed for this round, it is no release for another: a
        // replacement round has another M, and the signature fails there.
        let mut replaced = f.new.round.clone();
        replaced.input[0].sequence = elements::Sequence(0xffff_fffe);
        let other = f.release(C, &replaced).unwrap();
        assert_ne!(other.release.connector, r.release.connector);
        assert!(other.release.verify(&sig).is_err());
        // The message of the earlier form, without M, which RECLAIM no
        // longer accepts, is not what the wallet signs.
        let old_form = chain.release_prefix(&lowest.children_hash());
        assert_eq!(old_form.len(), 76);
        assert_eq!(msg.preimage().unwrap()[..76], old_form[..]);
        assert_ne!(sha256::Hash::hash(&old_form).to_byte_array(), digest);

        // Children that are not the node's are refused by the signer.
        let mut wrong: Vec<CommittedOutput> = r.children.iter().map(committed).collect();
        wrong[0].value += 1;
        assert!(matches!(
            ReleaseMessage::release(&r.release, wrong),
            Err(CsfsError::OtherNode)
        ));
    }

    #[test]
    fn a_release_is_refused_when_its_round_does_not_bind_it() {
        let f = refresh_fixture(Some(xonly(&operator())), vec![]);
        for c in [0, 1, 3, 9] {
            let err = f.release(c, &f.new.round).unwrap_err();
            assert!(
                matches!(err, ForfeitError::Spend(SpendError::Connector(n)) if n == c),
                "{c}: {err}"
            );
        }
        let none = refresh_fixture(None, vec![]);
        assert!(matches!(
            none.release(C, &none.new.round),
            Err(ForfeitError::Spend(SpendError::Connector(C)))
        ));
        // The new leaf must verify against the round, as the wallet's own.
        let err = f.release(C, &f.old_round).unwrap_err();
        assert!(matches!(&err, ForfeitError::NewLeaf(_)), "{err}");
        let err = release(
            &f.old,
            &f.old_round,
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &f.policy,
            &f.new_key.key,
            &[0x42; 32],
        )
        .unwrap_err();
        assert!(
            matches!(&err, ForfeitError::NewLeaf(e) if e.failed() == "owner"),
            "{err}"
        );
        // The old leaf must verify against its own round.
        let err = release(
            &f.old,
            &f.new.round,
            &f.new.tree.records()[0],
            &f.new.round,
            C,
            &f.policy,
            &f.new_key.key,
            &f.new_key.owner_nonce,
        )
        .unwrap_err();
        assert!(matches!(&err, ForfeitError::NewLeaf(_)), "{err}");
    }

    #[test]
    fn an_offboard_release_needs_the_offboard_and_the_connector() {
        let s = xonly(&operator());
        let off = OffboardPolicy {
            unlock_hash: [0x55; 32],
            destination: ExplicitOutput::new(asset(), 500_000, Script::from(vec![0x51])),
            operator: s,
            reclaim_delay: RelativeTime::from_seconds_ceil(10 * DAY as u64).unwrap(),
        };
        let f = refresh_fixture(Some(s), vec![off.output(1_000).txout()]);
        let r =
            release_for_offboard(&f.old, &f.old_round, &off, &f.new.round, C, &f.policy).unwrap();
        assert_eq!(r.release.connector, connector_asset(f.new.round.txid(), C));
        let without = refresh_fixture(Some(s), vec![]);
        assert!(matches!(
            release_for_offboard(&f.old, &f.old_round, &off, &without.new.round, C, &f.policy),
            Err(ForfeitError::Spend(SpendError::Offboard(_)))
        ));
        assert!(matches!(
            release_for_offboard(&f.old, &f.old_round, &off, &f.new.round, 3, &f.policy),
            Err(ForfeitError::Spend(SpendError::Connector(3)))
        ));
    }

    #[test]
    fn an_offboard_forfeit_needs_the_offboard_and_the_connector() {
        let s = xonly(&operator());
        let off = OffboardPolicy {
            unlock_hash: [0x55; 32],
            destination: ExplicitOutput::new(asset(), 500_000, Script::from(vec![0x51])),
            operator: s,
            reclaim_delay: RelativeTime::from_seconds_ceil(10 * DAY as u64).unwrap(),
        };
        let f = refresh_fixture(Some(s), vec![off.output(1_000).txout()]);
        let old = GivenUp::leaf(&f.old).unwrap();
        let forfeit = offboard(&old, &off, &f.new.round, C, fixture::delay(), MARGIN).unwrap();
        assert_eq!(forfeit.policy.unlock_hash, off.unlock_hash);
        assert_eq!(
            forfeit.policy.connector,
            connector_asset(f.new.round.txid(), C)
        );
        // A round that does not pay the offboard, or whose output c is not
        // the connector.
        let without = refresh_fixture(Some(s), vec![]);
        assert!(matches!(
            offboard(&old, &off, &without.new.round, C, fixture::delay(), MARGIN),
            Err(ForfeitError::Spend(SpendError::Offboard(_)))
        ));
        assert!(matches!(
            offboard(&old, &off, &f.new.round, 3, fixture::delay(), MARGIN),
            Err(ForfeitError::Spend(SpendError::Connector(3)))
        ));
    }
}
