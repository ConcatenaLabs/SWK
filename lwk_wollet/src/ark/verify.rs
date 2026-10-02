//! Verifying a leaf against the round transaction that created its batch.
//!
//! A wallet accepts a leaf only after checking, from first principles and with
//! no server trusted, that the round pays the batch output its record
//! rebuilds and that the round's sweep token and clock are honest. Consensus
//! does not stop an operator from building a dishonest clock, so the five
//! client checks are what keep an owner's leaf from being swept early:
//!
//! 1. the token `T` is issued as exactly one atom;
//! 2. the issuance is explicit;
//! 3. it creates no reissuance token, and nothing reissues `T`;
//! 4. the atom is paid to one output, not at `R`, and no output hides it;
//! 5. that output is clock 0 rebuilt from the published schedule, every sweep
//!    path above the leaf names that `T`, `S`, `R` and notice, and the
//!    schedule never runs backwards.
//!
//! [`verify_leaf`] rebuilds every script on the leaf's path from its record,
//! requires the round to pay the batch output exactly once, runs the five
//! checks, applies the wallet's policy ([`WalletPolicy`]: its chain, the
//! operator key it was told, the shortest notice, how far after `now` the
//! first expiry must lie and the bounds of the exit delay), and checks that
//! the record is for the wallet's key and the owner nonce it picked for this
//! leaf. A failure names what failed ([`VerifyError::check`] for the five
//! checks).
//!
//! # How far ahead the first expiry must lie
//!
//! Two rules bound the first expiry `E_0`, both counted from `now`, the median
//! time the caller's chain source gives at the time of the call:
//!
//! - a leaf the wallet takes from a round it joins (a board, a refresh, a
//!   payment made in a round) must leave the policy's acceptance horizon,
//!   by default 27 days ([`verify_leaf`]);
//! - a leaf or a coin the wallet is given out of round ([`verify_round`],
//!   [`verify_coin`]), and a leaf it already holds, when it checks it again
//!   ([`recheck`]) or finds it in a restore ([`verify_held_leaf`]), need only
//!   leave the exit deadline:
//!   `E_0 ≥ now + EXIT_DEADLINE_MARGIN`. These build that policy from the
//!   caller's ([`exit_deadline_policy`]) and ignore its horizon, so a leaf
//!   is not refused, and unrolled, merely for being days old.
//!
//! Finality is not this module's claim. A verified leaf names the round it was
//! checked against ([`VerifiedLeaf::round_txid`]); whether that round is
//! certified and its Bitcoin anchor buried is for the caller's chain source to
//! say. After a rollback the operator broadcasts the identical round again, so
//! the same transaction returns. Another transaction can still pay the same
//! batch output from the same issuing coin: after any rollback that
//! disconnects the round, the wallet checks whichever transaction now pays the
//! batch output ([`recheck`]) and, if that fails, unrolls at once.

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction, Txid};

use super::keys::OwnerNonce;
use super::{
    CoinRecord, LeafId, LeafRecord, MedianTime, RecordError, RelativeTime, TransferError,
    ValidCoin, ValidLeaf, WalletPolicy,
};

/// The time before the expiry by which an exit must start: the
/// specification's exit deadline, three days, for the unroll, the exit delay
/// and a margin for an anchor rollback.
pub const EXIT_DEADLINE_MARGIN: u32 = 3 * 86_400;

/// The policy a re-check or a receipt applies: the wallet's own, except that
/// the first expiry need only leave the exit deadline,
/// `E_0 ≥ now + EXIT_DEADLINE_MARGIN`, rather than the acceptance horizon a
/// leaf taken from a round must leave.
pub fn exit_deadline_policy(policy: &WalletPolicy) -> WalletPolicy {
    WalletPolicy {
        horizon: EXIT_DEADLINE_MARGIN,
        ..*policy
    }
}

/// What a verification established about a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLeaf {
    /// The leaf's id, from its batch output, position and script.
    pub leaf_id: LeafId,
    /// The round the leaf was checked against. Not a claim that the round is
    /// final.
    pub round_txid: Txid,
    /// The index of the batch output in the round.
    pub batch_vout: u32,
    /// The batch's asset.
    pub asset: AssetId,
    /// What the leaf holds, in atoms of `asset`.
    pub value: u64,
    /// The published expiry schedule `E_0 … E_K`; the current expiry is the
    /// `E` of whichever clock holds the token, `E_0` while the round's clock 0
    /// does.
    pub expiries: Vec<MedianTime>,
    /// The notice `W` every sweep waits after the release.
    pub notice: RelativeTime,
    /// The leaf's exit delay.
    pub exit_delay: RelativeTime,
    /// True when checked as the wallet's own leaf: its key and owner nonce.
    pub owned: bool,
}

impl VerifiedLeaf {
    fn new(record: &LeafRecord, valid: ValidLeaf, owned: bool) -> Self {
        VerifiedLeaf {
            leaf_id: valid.leaf_id,
            round_txid: valid.round_txid,
            batch_vout: valid.batch_vout,
            asset: record.asset,
            value: record.value,
            expiries: record.schedule.expiries().to_vec(),
            notice: record.schedule.notice,
            exit_delay: record.exit_delay,
            owned,
        }
    }

    /// The first expiry `E_0`.
    pub fn expiry(&self) -> MedianTime {
        self.expiries[0]
    }

    /// The median time by which an exit must start while the token is in
    /// clock 0: `E_0` less [`EXIT_DEADLINE_MARGIN`].
    pub fn exit_deadline(&self) -> u32 {
        self.expiry()
            .to_consensus_u32()
            .saturating_sub(EXIT_DEADLINE_MARGIN)
    }
}

/// Why a leaf was refused, and which check refused it.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("{}", describe(.0))]
pub struct VerifyError(pub RecordError);

fn describe(e: &RecordError) -> String {
    match e {
        // The five checks name themselves ("check 3: ...").
        RecordError::Round(_) => e.to_string(),
        _ => format!("{}: {e}", what_failed(e)),
    }
}

fn what_failed(e: &RecordError) -> &'static str {
    match e.kind() {
        "batch_output" => "batch output",
        "policy" => "wallet policy",
        "owner" => "owner",
        _ => "record",
    }
}

impl VerifyError {
    /// The client check, 1 to 5, the round failed; `None` when the refusal is
    /// not one of the five.
    pub fn check(&self) -> Option<u8> {
        match &self.0 {
            RecordError::Round(f) => Some(f.check()),
            _ => None,
        }
    }

    /// What failed, in a few words: `check 1` to `check 5`, `batch output`
    /// (the round does not pay the batch output the record rebuilds),
    /// `wallet policy`, `owner` (not the wallet's key or nonce) or `record`.
    pub fn failed(&self) -> String {
        match self.check() {
            Some(n) => format!("check {n}"),
            None => what_failed(&self.0).to_string(),
        }
    }
}

/// Verify the wallet's own leaf, taken from a round it joins: `record`
/// against `round`, under `policy` with its acceptance horizon, for the
/// wallet's key `owner` and the `owner_nonce` it picked for the leaf.
pub fn verify_leaf(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<VerifiedLeaf, VerifyError> {
    let valid = record
        .validate(round, policy, owner, owner_nonce)
        .map_err(VerifyError)?;
    Ok(VerifiedLeaf::new(record, valid, true))
}

/// Verify the wallet's own leaf that it already holds, such as one found in a
/// restore: as [`verify_leaf`], with the exit deadline in place of the
/// acceptance horizon ([`exit_deadline_policy`]).
pub fn verify_held_leaf(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<VerifiedLeaf, VerifyError> {
    verify_leaf(
        record,
        round,
        &exit_deadline_policy(policy),
        owner,
        owner_nonce,
    )
}

/// Verify a leaf the wallet does not own, such as the coin a sender is about
/// to give it: the same checks as [`verify_leaf`] without the owner's key and
/// nonce, and with the exit deadline in place of the acceptance horizon
/// ([`exit_deadline_policy`]). A wallet never accepts a leaf of its own with
/// this alone.
pub fn verify_round(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
) -> Result<VerifiedLeaf, VerifyError> {
    let valid = record
        .validate_round(round, &exit_deadline_policy(policy))
        .map_err(VerifyError)?;
    Ok(VerifiedLeaf::new(record, valid, false))
}

/// Verify a coin the wallet receives out of round, for its key `owner` and the
/// `owner_nonce` it published: the Arca library's [`CoinRecord::validate`]
/// against `rounds` (every round transaction the coin's lineage came from),
/// under `policy` with the exit deadline in place of the acceptance horizon
/// ([`exit_deadline_policy`]). Every batch leaf in the lineage meets that
/// bound, so the coin's earliest expiry ([`ValidCoin::expiry`]) does too.
///
/// This does not look at the chain. A leaf of the lineage already on-chain
/// past its exit delay can be exited by its holder at once, so the receiver
/// relies on the operator's rule that no leaf on-chain is spent off-chain;
/// and the sender and the operator together could still sign another spend
/// of an input.
pub fn verify_coin(
    coin: &CoinRecord,
    rounds: &[Transaction],
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<ValidCoin, TransferError> {
    coin.validate(rounds, &exit_deadline_policy(policy), owner, owner_nonce)
}

/// The outcome of checking a leaf again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// The same round pays the batch output, and still passes.
    Same(VerifiedLeaf),
    /// Another transaction pays the batch output now, and passes. The wallet
    /// keeps the new round's txid. The operator never does this on purpose:
    /// after a rollback it broadcasts the identical round again. While this
    /// transaction stands, no forfeit bound to the previous round's connector
    /// can be claimed.
    Replaced {
        /// The round the leaf was first checked against.
        previous: Txid,
        /// The leaf as checked against the transaction that replaced it.
        now: VerifiedLeaf,
    },
}

/// Check the wallet's own leaf again, after a rollback, against whichever
/// transaction now pays its batch output; `previous_round` is the round it
/// was last verified against. The policy is the caller's with the exit
/// deadline in place of the acceptance horizon ([`exit_deadline_policy`]):
/// a leaf the wallet already holds is not refused for being days old, only
/// once its exit must start. An error is an order to unroll at once: the
/// notice `W`, counted from the replacement's release, is the time the wallet
/// has.
pub fn recheck(
    previous_round: &Txid,
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<Recheck, VerifyError> {
    let now = verify_held_leaf(record, round, policy, owner, owner_nonce)?;
    if now.round_txid == *previous_round {
        Ok(Recheck::Same(now))
    } else {
        Ok(Recheck::Replaced {
            previous: *previous_round,
            now,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::confidential::{Asset, Value};
    use elements::encode::deserialize;
    use elements::hashes::Hash;
    use elements::hex::FromHex;
    use elements::{BlockHash, ContractHash, OutPoint, Script, TxIn, TxOut};
    use serde_json::Value as Json;

    use super::*;
    use crate::ark::{Chain, ClockSchedule};

    fn vectors() -> Json {
        serde_json::from_str(include_str!("../../tests/data/arca_records.json")).unwrap()
    }

    fn hex(s: &Json) -> Vec<u8> {
        Vec::<u8>::from_hex(s.as_str().unwrap()).unwrap()
    }

    fn key(s: &Json) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(s.as_str().unwrap()).unwrap()
    }

    fn nonce(s: &Json) -> OwnerNonce {
        hex(s).try_into().unwrap()
    }

    /// The policy of a wallet on the vectors' chain, told the vectors'
    /// operator key, at the batch's creation: 28 days before its first expiry.
    fn policy(v: &Json, batch: &Json) -> WalletPolicy {
        let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"].as_str().unwrap()).unwrap();
        let e0 = batch["inputs"]["expiries"][0].as_u64().unwrap() as u32;
        WalletPolicy::new(
            Chain::new(genesis),
            key(&v["inputs"]["operator"]),
            MedianTime::from_consensus(e0 - 28 * 86_400).unwrap(),
        )
    }

    struct Case {
        record: LeafRecord,
        round: Transaction,
        policy: WalletPolicy,
        owner: XOnlyPublicKey,
        nonce: OwnerNonce,
    }

    fn case(v: &Json, b: usize, r: usize) -> Case {
        let batch = &v["batches"][b];
        let rec = &batch["records"][r];
        let leaf = &batch["inputs"]["leaves"][rec["leaf"].as_u64().unwrap() as usize];
        Case {
            record: LeafRecord::from_bytes(&hex(&rec["binary"])).unwrap(),
            round: deserialize(&hex(&batch["round"]["tx"])).unwrap(),
            policy: policy(v, batch),
            owner: key(&leaf["owner"]),
            nonce: nonce(&leaf["owner_nonce"]),
        }
    }

    impl Case {
        fn verify(&self) -> Result<VerifiedLeaf, VerifyError> {
            verify_leaf(
                &self.record,
                &self.round,
                &self.policy,
                &self.owner,
                &self.nonce,
            )
        }
    }

    #[test]
    fn every_record_verifies_against_its_round() {
        let v = vectors();
        let (mut n, mut longer) = (0, 0);
        for batch in v["batches"].as_array().unwrap() {
            let round: Transaction = deserialize(&hex(&batch["round"]["tx"])).unwrap();
            let p = policy(&v, batch);
            for rec in batch["records"].as_array().unwrap() {
                let name = format!("{} / leaf {}", batch["name"], rec["leaf"]);
                let binary = hex(&rec["binary"]);
                let from_binary = LeafRecord::from_bytes(&binary).unwrap();
                let from_json = LeafRecord::from_json_str(rec["json"].as_str().unwrap()).unwrap();
                assert_eq!(from_binary, from_json, "{name}");
                assert_eq!(from_binary.to_bytes().unwrap(), binary, "{name}");
                assert_eq!(
                    from_binary.to_json_string().unwrap(),
                    rec["json"].as_str().unwrap(),
                    "{name}"
                );
                let leaf = &batch["inputs"]["leaves"][rec["leaf"].as_u64().unwrap() as usize];
                let (owner, owner_nonce) = (key(&leaf["owner"]), nonce(&leaf["owner_nonce"]));
                // Some vectors give a leaf a longer exit delay than the
                // default policy's 48 hours, which refuses it; a wallet that
                // accepts that delay verifies the leaf.
                let mut p = p;
                if from_binary.exit_delay.units() > p.max_exit_delay.units() {
                    let err =
                        verify_leaf(&from_binary, &round, &p, &owner, &owner_nonce).unwrap_err();
                    assert_eq!(err.failed(), "wallet policy", "{name}: {err}");
                    assert!(err.to_string().contains("exit delay"), "{err}");
                    p.max_exit_delay = from_binary.exit_delay;
                    longer += 1;
                }
                let ok = verify_leaf(&from_binary, &round, &p, &owner, &owner_nonce)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    ok.leaf_id.to_string(),
                    rec["leaf_id"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(ok.round_txid, round.txid());
                assert_eq!(
                    ok.batch_vout as u64,
                    batch["round"]["batch_vout"].as_u64().unwrap()
                );
                assert_eq!(ok.value, leaf["value"].as_u64().unwrap());
                assert!(ok.owned);
                assert_eq!(
                    ok.exit_deadline() as u64,
                    batch["inputs"]["expiries"][0].as_u64().unwrap() - 3 * 86_400
                );
                // Without the owner's key and nonce, the same checks pass, but
                // the leaf is not marked the wallet's own.
                assert!(!verify_round(&from_binary, &round, &p).unwrap().owned);
                n += 1;
            }
        }
        // Seven batches: 1, 5, 16, 17, 10 and 7 leaves with every record, and 5
        // records of a 64-leaf batch.
        assert_eq!(n, 61);
        assert!(longer > 0);
        println!("{n} records verified, {longer} of them only under a longer exit delay");
    }

    #[test]
    fn refusal_vectors_are_refused_by_kind() {
        let v = vectors();
        let mut n = 0;
        for bad in v["invalid_binary"].as_array().unwrap() {
            let err = LeafRecord::from_bytes(&hex(&bad["binary"])).unwrap_err();
            assert_eq!(
                err.kind(),
                bad["kind"].as_str().unwrap(),
                "{}: {err}",
                bad["name"]
            );
            n += 1;
        }
        for bad in v["invalid_json"].as_array().unwrap() {
            let err = LeafRecord::from_json_str(bad["json"].as_str().unwrap()).unwrap_err();
            assert_eq!(
                err.kind(),
                bad["kind"].as_str().unwrap(),
                "{}: {err}",
                bad["name"]
            );
            n += 1;
        }
        assert_eq!(n, 30);
    }

    /// The round's token issuance, on its first input.
    fn token_issuer(c: &Case) -> OutPoint {
        c.round.input[0].previous_output
    }

    #[test]
    fn the_token_attacks_and_a_backward_clock_are_refused_by_their_check() {
        let v = vectors();
        let base = case(&v, 2, 5);
        base.verify().unwrap();
        let token = base.record.schedule.token;
        let r_spk = base.record.schedule.r().script_pubkey();
        let mut refused = vec![];
        let mut expect = |name: &str, c: &Case, check: u8| {
            let err = c.verify().unwrap_err();
            assert_eq!(err.check(), Some(check), "{name}: {err}");
            assert!(
                err.to_string().starts_with(&format!("check {check}: ")),
                "{err}"
            );
            assert_eq!(err.failed(), format!("check {check}"));
            refused.push(format!("{name}: {err}"));
        };

        // Check 1: a second atom issued, straight to R.
        let mut c = case(&v, 2, 5);
        c.round.input[0].asset_issuance.amount = Value::Explicit(2);
        c.round.output.insert(
            2,
            TxOut {
                asset: Asset::Explicit(token),
                value: Value::Explicit(1),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: r_spk.clone(),
                witness: Default::default(),
            },
        );
        expect("two atoms, one at R", &c, 1);

        // Check 2: the issued amount is confidential.
        let mut c = case(&v, 2, 5);
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let generator = elements::secp256k1_zkp::Generator::new_unblinded(&secp, token.into_tag());
        let vbf = elements::confidential::ValueBlindingFactor::from_slice(&[3; 32]).unwrap();
        let commitment = Value::new_confidential(&secp, 1, generator, vbf);
        c.round.input[0].asset_issuance.amount = commitment;
        expect("a confidential issuance", &c, 2);

        // Check 3: the issuance creates a reissuance token.
        let mut c = case(&v, 2, 5);
        c.round.input[0].asset_issuance.inflation_keys = Value::Explicit(1);
        expect("a reissuance token", &c, 3);

        // Check 3: another input reissues T.
        let mut c = case(&v, 2, 5);
        let entropy = AssetId::generate_asset_entropy(
            token_issuer(&c),
            ContractHash::from_byte_array([0; 32]),
        );
        let mut reissue = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            ..Default::default()
        };
        reissue.asset_issuance.asset_blinding_nonce =
            elements::secp256k1_zkp::Tweak::from_slice(&[1; 32]).unwrap();
        reissue.asset_issuance.asset_entropy = entropy.to_byte_array();
        reissue.asset_issuance.amount = Value::Explicit(1);
        c.round.input.push(reissue);
        expect("an input reissuing the token", &c, 3);

        // Check 4: the only atom issued straight to R.
        let mut c = case(&v, 2, 5);
        let at = c
            .round
            .output
            .iter()
            .position(|o| o.asset == Asset::Explicit(token))
            .unwrap();
        c.round.output[at].script_pubkey = r_spk.clone();
        expect("the atom at R", &c, 4);

        // Check 4: the atom in two outputs.
        let mut c = case(&v, 2, 5);
        let copy = c.round.output[at].clone();
        c.round.output.push(copy);
        expect("the token in two outputs", &c, 4);

        // Check 5: a clock chain whose second step expires before its first,
        // paid as clock 0 and published as the schedule.
        let mut c = case(&v, 2, 5);
        let s = &c.record.schedule;
        let mut e = s.expiries().to_vec();
        e.swap(0, 1);
        let backwards = ClockSchedule::new_unchecked(s.token, s.operator, s.notice, e).unwrap();
        c.round.output[at].script_pubkey = backwards.clock0_script_pubkey();
        c.record.schedule = backwards;
        expect("a clock that runs backwards", &c, 5);

        // Check 5: the atom paid to a clock not rebuilt from the schedule.
        let mut c = case(&v, 2, 5);
        c.round.output[at].script_pubkey = Script::from(vec![0x51]);
        expect("the atom at another script", &c, 5);

        assert_eq!(refused.len(), 8);
        for r in refused {
            println!("refused: {r}");
        }
    }

    #[test]
    fn the_wallets_policy_and_keys_are_enforced() {
        let v = vectors();
        let base = case(&v, 1, 2);
        base.verify().unwrap();
        let expect = |c: &Case, failed: &str| {
            let err = c.verify().unwrap_err();
            assert_eq!(err.failed(), failed, "{err}");
            assert_eq!(err.check(), None);
            err.to_string()
        };

        let mut c = case(&v, 1, 2);
        let mut reversed = c.policy.chain.genesis_hash().to_byte_array();
        reversed.reverse();
        c.policy.chain = Chain::new(BlockHash::from_byte_array(reversed));
        assert!(expect(&c, "wallet policy").contains("another chain"));

        let mut c = case(&v, 1, 2);
        c.policy.operator = c.owner;
        assert!(expect(&c, "wallet policy").contains("operator key"));

        let mut c = case(&v, 1, 2);
        c.policy.min_notice = RelativeTime::from_seconds_ceil(48 * 3600).unwrap();
        assert!(expect(&c, "wallet policy").contains("notice"));

        let mut c = case(&v, 1, 2);
        c.policy.now =
            MedianTime::from_consensus(c.record.schedule.expiries()[0].to_consensus_u32() - 86_400)
                .unwrap();
        assert!(expect(&c, "wallet policy").contains("first expiry"));

        let mut c = case(&v, 1, 2);
        c.policy.max_exit_delay = RelativeTime::from_seconds_ceil(24 * 3600).unwrap();
        assert!(expect(&c, "wallet policy").contains("exit delay"));

        let mut c = case(&v, 1, 2);
        c.nonce = [0x42; 32];
        assert!(expect(&c, "owner").contains("owner nonce"));

        let mut c = case(&v, 1, 3);
        c.owner = case(&v, 1, 2).owner;
        assert!(expect(&c, "owner").contains("another owner"));

        // The round pays no such batch output: one atom less in the record.
        let mut c = case(&v, 1, 2);
        c.record.value -= 1;
        assert_eq!(c.verify().unwrap_err().failed(), "batch output");
    }

    #[test]
    fn a_replaced_round_is_checked_again() {
        // After a rollback, another transaction can pay the same batch output
        // from the same issuing coin (review R1, probe D).
        let v = vectors();
        let c = case(&v, 2, 0);
        let first = c.verify().unwrap();
        let again = recheck(
            &first.round_txid,
            &c.record,
            &c.round,
            &c.policy,
            &c.owner,
            &c.nonce,
        )
        .unwrap();
        assert_eq!(again, Recheck::Same(first.clone()));

        // An honest replacement: the same coins and outputs, another sequence,
        // so another txid.
        let mut replaced = c.round.clone();
        replaced.input[0].sequence = elements::Sequence(0xffff_fffe);
        match recheck(
            &first.round_txid,
            &c.record,
            &replaced,
            &c.policy,
            &c.owner,
            &c.nonce,
        )
        .unwrap()
        {
            Recheck::Replaced { previous, now } => {
                assert_eq!(previous, first.round_txid);
                assert_eq!(now.round_txid, replaced.txid());
                assert_ne!(now.round_txid, first.round_txid);
                assert_eq!(now.leaf_id, first.leaf_id);
            }
            other => panic!("{other:?}"),
        }

        // A dishonest replacement: the same batch output, a second atom at R.
        let mut bad = c.round.clone();
        bad.input[0].asset_issuance.amount = Value::Explicit(2);
        let token = c.record.schedule.token;
        bad.output.push(TxOut {
            asset: Asset::Explicit(token),
            value: Value::Explicit(1),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: c.record.schedule.r().script_pubkey(),
            witness: Default::default(),
        });
        let err = recheck(
            &first.round_txid,
            &c.record,
            &bad,
            &c.policy,
            &c.owner,
            &c.nonce,
        )
        .unwrap_err();
        assert_eq!(err.check(), Some(1), "{err}");
    }

    const DAY: u32 = 86_400;

    fn at(policy: &WalletPolicy, now: u32) -> WalletPolicy {
        WalletPolicy {
            now: MedianTime::from_consensus(now).unwrap(),
            ..*policy
        }
    }

    #[test]
    fn a_held_leaf_is_checked_again_against_the_exit_deadline() {
        // Review R4, F4: the re-check applied the acceptance horizon, 27
        // days, and so refused every leaf from the second day of its batch,
        // the same round or an honest replacement, which the module calls an
        // order to unroll.
        let v = vectors();
        let c = case(&v, 2, 0);
        let e0 = c.record.schedule.expiries()[0].to_consensus_u32();
        let created = c.policy.now.to_consensus_u32();
        assert_eq!(created, e0 - 28 * DAY);
        let first = c.verify().unwrap();
        let mut replaced = c.round.clone();
        replaced.input[0].sequence = elements::Sequence(0xffff_fffe);
        let deadline = e0 - EXIT_DEADLINE_MARGIN;
        let recheck_at = |round: &Transaction, policy: &WalletPolicy| {
            recheck(
                &first.round_txid,
                &c.record,
                round,
                policy,
                &c.owner,
                &c.nonce,
            )
        };
        for now in [
            created + DAY,
            created + 2 * DAY,
            created + 10 * DAY,
            deadline,
        ] {
            let p = at(&c.policy, now);
            assert!(matches!(recheck_at(&c.round, &p), Ok(Recheck::Same(_))));
            assert!(matches!(
                recheck_at(&replaced, &p),
                Ok(Recheck::Replaced { .. })
            ));
            // The caller's horizon plays no part.
            let mut none = p;
            none.horizon = 0;
            assert!(recheck_at(&c.round, &none).is_ok());
            // A leaf received out of round, or found in a restore, needs the
            // same and no more.
            assert!(!verify_round(&c.record, &c.round, &p).unwrap().owned);
            assert!(
                verify_held_leaf(&c.record, &c.round, &none, &c.owner, &c.nonce)
                    .unwrap()
                    .owned
            );
        }
        // From one second past the exit deadline, the exit must have started:
        // the re-check refuses, whatever horizon the caller passes.
        for horizon in [0, EXIT_DEADLINE_MARGIN, 27 * DAY] {
            let mut p = at(&c.policy, deadline + 1);
            p.horizon = horizon;
            for round in [&c.round, &replaced] {
                let err = recheck_at(round, &p).unwrap_err();
                assert_eq!(err.failed(), "wallet policy", "{err}");
                assert!(err.to_string().contains("first expiry"), "{err}");
            }
            let err = verify_round(&c.record, &c.round, &p).unwrap_err();
            assert_eq!(err.failed(), "wallet policy", "{err}");
            let err = verify_held_leaf(&c.record, &c.round, &p, &c.owner, &c.nonce).unwrap_err();
            assert_eq!(err.failed(), "wallet policy", "{err}");
        }
        // A new leaf taken from a round still needs the acceptance horizon:
        // the same record, offered as a new leaf on the second day, is refused.
        verify_leaf(
            &c.record,
            &c.round,
            &at(&c.policy, created + DAY),
            &c.owner,
            &c.nonce,
        )
        .unwrap();
        let err = verify_leaf(
            &c.record,
            &c.round,
            &at(&c.policy, created + 2 * DAY),
            &c.owner,
            &c.nonce,
        )
        .unwrap_err();
        assert_eq!(err.failed(), "wallet policy", "{err}");
        assert_eq!(
            exit_deadline_policy(&c.policy),
            WalletPolicy {
                horizon: 3 * DAY,
                ..c.policy
            }
        );
    }

    /// A batch of five leaves with test keys, its round, the base record of
    /// leaf 0 as its owner hands it on, and a coin record for a receiver one
    /// reassignment later.
    struct Coins {
        policy: WalletPolicy,
        rounds: Vec<Transaction>,
        e0: u32,
        base: CoinRecord,
        base_owner: (XOnlyPublicKey, OwnerNonce),
        transferred: CoinRecord,
        receiver: (XOnlyPublicKey, OwnerNonce),
    }

    fn coins() -> Coins {
        use crate::ark::covenant::spend::Pair;
        use crate::ark::covenant::{sign::sign_digest, LeafSpec, ReserveRule, Tree, TreeParams};
        use crate::ark::{ExplicitOutput, NewLeaf, Template, Transfer, TransferInput};
        use elements::secp256k1_zkp::{Keypair, Secp256k1};
        use elements::{AssetIssuance, ContractHash};

        let secp = Secp256k1::new();
        // Test keys, from fixed secrets; they hold nothing.
        let key = |b: u8| Keypair::from_seckey_slice(&secp, &[b; 32]).unwrap();
        let xonly = |k: &Keypair| k.x_only_public_key().0;
        let (s, a, b) = (key(0x51), key(0xa1), key(0xb1));
        let genesis =
            BlockHash::from_str("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c")
                .unwrap();
        let chain = Chain::new(genesis);
        let x = AssetId::from_slice(&[0x28; 32]).unwrap();
        let created = 1_800_000_000u32;
        let e0 = created + 28 * DAY;
        let issuer = OutPoint::new(Txid::from_byte_array([0x1e; 32]), 0);
        let token = AssetId::new_issuance(issuer, ContractHash::from_byte_array([0; 32]));
        let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
        let schedule = ClockSchedule::new(
            token,
            xonly(&s),
            delay,
            vec![
                MedianTime::from_consensus(e0).unwrap(),
                MedianTime::from_consensus(e0 + 28 * DAY).unwrap(),
            ],
        )
        .unwrap();
        let preimage = [0x33; 32];
        let leaves: Vec<LeafSpec> = (0..5u8)
            .map(|i| LeafSpec {
                template: Template::Vtxo1,
                owner: if i == 0 {
                    xonly(&a)
                } else {
                    xonly(&key(0xc0 + i))
                },
                value: 1_000_000 + i as u64,
                owner_nonce: [0x40 + i; 32],
                operator_nonce: [0x60 + i; 32],
                exit_delay: delay,
                unlock_hash: elements::hashes::sha256::Hash::hash(&preimage).to_byte_array(),
            })
            .collect();
        let tree = Tree::build(
            TreeParams {
                asset: x,
                chain,
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
        // The round: the batch output, the token's one atom at clock 0, a fee.
        let explicit = |asset: AssetId, value: u64, spk: Script| TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: spk,
            witness: Default::default(),
        };
        let mut round = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: issuer,
                ..Default::default()
            }],
            output: vec![
                tree.batch_output().txout(),
                explicit(token, 1, tree.clock0_script_pubkey()),
                TxOut::new_fee(2_000, x),
            ],
        };
        round.input[0].asset_issuance = AssetIssuance {
            asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK,
            asset_entropy: [0; 32],
            amount: Value::Explicit(1),
            inflation_keys: Value::Null,
            denomination: 0,
        };
        let rounds = vec![round];
        let now = MedianTime::from_consensus(created).unwrap();
        let policy = WalletPolicy::new(chain, xonly(&s), now);

        // Leaf 0's base record: its preimage and its owner's unroll
        // authorisations, usable from the round's creation.
        let record = tree.records()[0].clone();
        let auths = record
            .branch()
            .unwrap()
            .nodes
            .iter()
            .map(|n| {
                (
                    sign_digest(&a, &n.unroll_authorisation(now).digest, &[0; 32]),
                    now,
                )
            })
            .collect();
        let base = CoinRecord::Leaf {
            record: record.clone(),
            preimage,
            auths,
        };

        // A reassignment of it to B, the operator and A signing both steps.
        let coin = base.resolve(&rounds, &policy).unwrap();
        let margin = 2_000;
        let new_leaf = NewLeaf {
            owner: xonly(&b),
            owner_nonce: [0xb2; 32],
            operator_nonce: [0xb3; 32],
            exit_delay: delay,
        };
        let out = ExplicitOutput::new(
            x,
            coin.value - 2 * margin,
            new_leaf.policy(xonly(&s), chain).script_pubkey(),
        );
        let plan = crate::ark::covenant::TransferPlan {
            inputs: vec![(coin.clone(), coin.value - margin)],
            outputs: vec![out],
        };
        let cp = plan.checkpoint_message(0).unwrap().digest;
        let re = plan.reassignment_message(0).unwrap().digest;
        let pair = |d: &[u8; 32]| Pair {
            operator: sign_digest(&s, d, &[0; 32]),
            owner: sign_digest(&a, d, &[0; 32]),
        };
        let transferred = CoinRecord::Transfer(Box::new(Transfer {
            inputs: vec![TransferInput {
                coin: base.clone(),
                checkpoint_value: coin.value - margin,
                checkpoint: pair(&cp),
                reassignment: pair(&re),
            }],
            outputs: plan.outputs.clone(),
            index: 0,
            leaf: new_leaf,
        }));
        Coins {
            policy,
            rounds,
            e0,
            base,
            base_owner: (record.owner, record.owner_nonce),
            transferred,
            receiver: (xonly(&b), [0xb2; 32]),
        }
    }

    #[test]
    fn a_received_coin_needs_only_the_exit_deadline() {
        // Review R4, F4 and e3: under the acceptance horizon a coin received
        // out of round is refused from the second day of the batch it comes
        // from; a receipt needs only E_0 ≥ now + the exit deadline.
        let f = coins();
        let created = f.policy.now.to_consensus_u32();
        let deadline = f.e0 - EXIT_DEADLINE_MARGIN;
        let both = [(&f.base, f.base_owner), (&f.transferred, f.receiver)];
        for (coin, (owner, nonce)) in both {
            verify_coin(coin, &f.rounds, &f.policy, &owner, &nonce).unwrap();
            for now in [created + 2 * DAY, created + 10 * DAY, deadline] {
                let p = at(&f.policy, now);
                // The library's validation under the acceptance horizon
                // refuses it; the kit's receipt accepts it.
                let err = coin.validate(&f.rounds, &p, &owner, &nonce).unwrap_err();
                assert_eq!(err.kind(), "policy", "{err}");
                let ok = verify_coin(coin, &f.rounds, &p, &owner, &nonce).unwrap();
                assert_eq!(ok.expiry.to_consensus_u32(), f.e0);
            }
            let err = verify_coin(
                coin,
                &f.rounds,
                &at(&f.policy, deadline + 1),
                &owner,
                &nonce,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "policy", "{err}");
            assert!(err.to_string().contains("first expiry"), "{err}");
        }
        let hops = |c: &CoinRecord, k: &(XOnlyPublicKey, OwnerNonce)| {
            verify_coin(c, &f.rounds, &f.policy, &k.0, &k.1)
                .unwrap()
                .hops
        };
        assert_eq!(
            (
                hops(&f.base, &f.base_owner),
                hops(&f.transferred, &f.receiver)
            ),
            (0, 1)
        );
        // Everything else the library checks still holds: another key is
        // refused.
        let err = verify_coin(
            &f.transferred,
            &f.rounds,
            &f.policy,
            &f.base_owner.0,
            &f.receiver.1,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "owner", "{err}");
    }
}
