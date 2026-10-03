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
//!   `E_0 ≥ now + EXIT_DEADLINE_MARGIN`. These apply the receipt form of the
//!   caller's policy ([`WalletPolicy::receipt`]) whatever its horizon, so a
//!   leaf is not refused, and unrolled, merely for being days old.
//!
//! Every leaf in a received coin's lineage, whoever owns it, meets the same
//! policy: chain, operator, exit delay, depth and reserves. The record cannot
//! show what is on-chain, and an Arca leaf that is on-chain is never spent
//! off-chain, since past its exit delay its owner can exit it at once:
//! [`verify_coin`] refuses a coin when an index of the chain reports any leaf
//! or checkpoint of its lineage on-chain, and says when no index was asked
//! ([`LineageCheck`]).
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
use elements::{AssetId, Script, Transaction, Txid};

use super::keys::OwnerNonce;
use super::{
    CoinRecord, LeafId, LeafRecord, MedianTime, RecordError, RelativeTime, TransferError,
    ValidCoin, ValidLeaf, WalletPolicy,
};

/// The time before the expiry by which an exit must start: the
/// specification's exit deadline, three days, for the unroll, the exit delay
/// and a margin for an anchor rollback. The Arca library's
/// [`WalletPolicy::EXIT_DEADLINE`].
pub const EXIT_DEADLINE_MARGIN: u32 = WalletPolicy::EXIT_DEADLINE;

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
/// acceptance horizon ([`WalletPolicy::receipt`]).
pub fn verify_held_leaf(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<VerifiedLeaf, VerifyError> {
    verify_leaf(record, round, &policy.receipt(), owner, owner_nonce)
}

/// Verify a leaf the wallet does not own, such as the coin a sender is about
/// to give it: the same checks as [`verify_leaf`] without the owner's key and
/// nonce, and with the exit deadline in place of the acceptance horizon
/// ([`WalletPolicy::receipt`]). A wallet never accepts a leaf of its own with
/// this alone.
pub fn verify_round(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
) -> Result<VerifiedLeaf, VerifyError> {
    let valid = record
        .validate_round(round, &policy.receipt())
        .map_err(VerifyError)?;
    Ok(VerifiedLeaf::new(record, valid, false))
}

/// How a received coin's lineage was checked against the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageCheck {
    /// An index of the chain reported no leaf or checkpoint of the lineage
    /// on-chain.
    Indexed,
    /// No index was asked. The wallet relies on the operator's rule that no
    /// Arca leaf on-chain is spent off-chain, and says so to its user.
    OperatorRule,
}

/// A coin received out of round, as [`verify_coin`] accepted it.
#[derive(Debug, Clone)]
pub struct ReceivedCoin {
    /// The coin, with everything needed to bring it on-chain.
    pub coin: ValidCoin,
    /// How its lineage was checked against the chain.
    pub lineage: LineageCheck,
}

/// Verify a coin the wallet receives out of round, for its key `owner` and the
/// `owner_nonce` it published: the Arca library's [`CoinRecord::validate`]
/// against `rounds` (every round transaction the coin's lineage came from),
/// under the receipt form of `policy` ([`WalletPolicy::receipt`]). Every leaf
/// of the lineage meets the policy, and every batch leaf's first expiry lies
/// past the exit deadline, so the coin's earliest expiry
/// ([`ValidCoin::expiry`]) does too.
///
/// `on_chain` is an index of the chain: whether any transaction has paid a
/// scriptPubKey. With it, the coin is refused ([`TransferError::OnChain`])
/// when any leaf or checkpoint of its lineage ([`ValidCoin::lineage`]) is
/// on-chain, since its owner could exit it under the receiver. A wallet that
/// cannot reach its index passes `None` rather than guessing, and the result
/// says the coin rests on the operator's rule ([`LineageCheck::OperatorRule`]).
/// Either way the sender and the operator together could still sign another
/// spend of an input: a coin received out of round is refreshed into a round
/// before it is trusted further.
pub fn verify_coin(
    coin: &CoinRecord,
    rounds: &[Transaction],
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
    on_chain: Option<&mut dyn FnMut(&Script) -> bool>,
) -> Result<ReceivedCoin, TransferError> {
    let coin = coin.validate(rounds, &policy.receipt(), owner, owner_nonce)?;
    let lineage = match on_chain {
        Some(index) => {
            coin.check_lineage(index)?;
            LineageCheck::Indexed
        }
        None => LineageCheck::OperatorRule,
    };
    Ok(ReceivedCoin { coin, lineage })
}

/// The outcome of checking a leaf again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// The same round pays the batch output, and still passes.
    Same(VerifiedLeaf),
    /// Another transaction pays the batch output now, and passes: a new round
    /// (the Arca library's `Recheck::NewRound`). The wallet keeps the new
    /// round's txid. The operator never does this on purpose: after a rollback
    /// it broadcasts the identical round again. Nothing signed for the old
    /// round carries over: a forfeit bound to its connector can never be
    /// claimed, so a leaf the wallet gave up for it is still its own.
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
/// deadline in place of the acceptance horizon ([`WalletPolicy::receipt`]):
/// a leaf the wallet already holds is not refused for being days old, only
/// once its exit must start. With `round` on-chain, an error is an order to
/// unroll at once: the notice `W`, counted from the replacement's release, is
/// the time the wallet has.
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
    use crate::ark::{Chain, ClockSchedule, ReserveFloor};

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
        let (mut n, mut longer, mut unreserved) = (0, 0, 0);
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
                // Some batches hold no reserve on a node or the entry, which
                // the default floor of one atom refuses; a wallet that sets
                // no floor verifies the leaf.
                if let Err(err) = verify_leaf(&from_binary, &round, &p, &owner, &owner_nonce) {
                    assert!(
                        matches!(
                            err.0,
                            RecordError::NodeReserve { reserve: 0, .. }
                                | RecordError::EntryReserve { reserve: 0, .. }
                        ),
                        "{name}: {err}"
                    );
                    assert_eq!(err.failed(), "wallet policy", "{name}: {err}");
                    p.min_reserve = ReserveFloor::Atoms(0);
                    unreserved += 1;
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
        assert!(unreserved > 0);
        println!(
            "{n} records verified, {longer} of them only under a longer exit delay, {unreserved} only with no reserve floor"
        );
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
            c.policy.receipt(),
            WalletPolicy {
                horizon: 3 * DAY,
                ..c.policy
            }
        );
    }

    use crate::ark::covenant::sign::sign_digest;
    use crate::ark::covenant::spend::Pair;
    use crate::ark::covenant::TransferPlan;
    use crate::ark::fixture::{self, test_key, xonly, Batch};
    use crate::ark::{ExplicitOutput, NewLeaf, Transfer, TransferInput};
    use elements::secp256k1_zkp::Keypair;

    /// A batch of five leaves with test keys, its round and the base record of
    /// leaf 0 as its owner A hands it on; `reassign` moves a coin one hop on.
    struct Coins {
        policy: WalletPolicy,
        rounds: Vec<Transaction>,
        e0: u32,
        s: Keypair,
        a: Keypair,
        base: CoinRecord,
        delay: RelativeTime,
    }

    const MARGIN: u64 = 2_000;

    impl Coins {
        fn new() -> Coins {
            let a = test_key(0xa1);
            let batch = Batch::new(
                xonly(&a),
                [0x40; 32],
                1_800_000_000,
                0x1e,
                [0x33; 32],
                vec![],
            );
            let now = batch.created;
            // Leaf 0's base record: its preimage and its owner's unroll
            // authorisations, usable from the round's creation.
            let record = batch.tree.records()[0].clone();
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
            Coins {
                policy: batch.policy(),
                rounds: vec![batch.round.clone()],
                e0: batch.e0,
                s: fixture::operator(),
                a,
                base: CoinRecord::Leaf {
                    record,
                    preimage: batch.preimage,
                    auths,
                },
                delay: fixture::delay(),
            }
        }

        /// `record`, whose owner is `owner`, reassigned whole (less two
        /// margins) to the new leaf of `to`, whose nonce is `nonce`, with exit
        /// delay `delay`; the operator and the owner sign both steps. The
        /// coin is resolved under `policy`.
        fn reassign(
            &self,
            record: &CoinRecord,
            owner: &Keypair,
            to: &Keypair,
            nonce: OwnerNonce,
            delay: RelativeTime,
            policy: &WalletPolicy,
        ) -> CoinRecord {
            let coin = record.resolve(&self.rounds, policy).unwrap();
            let leaf = NewLeaf {
                owner: xonly(to),
                owner_nonce: nonce,
                operator_nonce: [nonce[0] ^ 0xff; 32],
                exit_delay: delay,
            };
            let out = ExplicitOutput::new(
                coin.asset,
                coin.value - 2 * MARGIN,
                leaf.policy(xonly(&self.s), self.policy.chain)
                    .script_pubkey(),
            );
            let plan = TransferPlan {
                inputs: vec![(coin.clone(), coin.value - MARGIN)],
                outputs: vec![out],
            };
            let pair = |d: &[u8; 32]| Pair {
                operator: sign_digest(&self.s, d, &[0; 32]),
                owner: sign_digest(owner, d, &[0; 32]),
            };
            CoinRecord::Transfer(Box::new(Transfer {
                inputs: vec![TransferInput {
                    coin: record.clone(),
                    checkpoint_value: coin.value - MARGIN,
                    checkpoint: pair(&plan.checkpoint_message(0).unwrap().digest),
                    reassignment: pair(&plan.reassignment_message(0).unwrap().digest),
                }],
                outputs: plan.outputs.clone(),
                index: 0,
                leaf,
            }))
        }

        fn base_owner(&self) -> (XOnlyPublicKey, OwnerNonce) {
            match &self.base {
                CoinRecord::Leaf { record, .. } => (record.owner, record.owner_nonce),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn a_received_coin_needs_only_the_exit_deadline() {
        // Review R4, F4 and e3: under the acceptance horizon a coin received
        // out of round is refused from the second day of the batch it comes
        // from; a receipt needs only E_0 ≥ now + the exit deadline.
        let f = Coins::new();
        let b = test_key(0xb1);
        let transferred = f.reassign(&f.base, &f.a, &b, [0xb2; 32], f.delay, &f.policy);
        let created = f.policy.now.to_consensus_u32();
        let deadline = f.e0 - EXIT_DEADLINE_MARGIN;
        let both = [
            (&f.base, f.base_owner()),
            (&transferred, (xonly(&b), [0xb2; 32])),
        ];
        for (coin, (owner, nonce)) in both {
            verify_coin(coin, &f.rounds, &f.policy, &owner, &nonce, None).unwrap();
            for now in [created + 2 * DAY, created + 10 * DAY, deadline] {
                let p = at(&f.policy, now);
                // The library's validation under the acceptance horizon
                // refuses it; the kit's receipt accepts it.
                let err = coin.validate(&f.rounds, &p, &owner, &nonce).unwrap_err();
                assert_eq!(err.kind(), "policy", "{err}");
                let ok = verify_coin(coin, &f.rounds, &p, &owner, &nonce, None).unwrap();
                assert_eq!(ok.coin.expiry.to_consensus_u32(), f.e0);
            }
            let err = verify_coin(
                coin,
                &f.rounds,
                &at(&f.policy, deadline + 1),
                &owner,
                &nonce,
                None,
            )
            .unwrap_err();
            assert_eq!(err.kind(), "policy", "{err}");
            assert!(err.to_string().contains("first expiry"), "{err}");
        }
        let hops = |c: &CoinRecord, k: (XOnlyPublicKey, OwnerNonce)| {
            verify_coin(c, &f.rounds, &f.policy, &k.0, &k.1, None)
                .unwrap()
                .coin
                .hops
        };
        assert_eq!(
            (
                hops(&f.base, f.base_owner()),
                hops(&transferred, (xonly(&b), [0xb2; 32]))
            ),
            (0, 1)
        );
        // Everything else the library checks still holds: another key is
        // refused.
        let err = verify_coin(
            &transferred,
            &f.rounds,
            &f.policy,
            &f.base_owner().0,
            &[0xb2; 32],
            None,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "owner", "{err}");
    }

    #[test]
    fn a_coin_is_refused_when_its_lineage_is_on_chain() {
        // Review R4, F2 and e3; decision D31: an Arca leaf on-chain is never
        // spent off-chain, since past its exit delay its owner can exit it
        // under the receiver. With an index, a receiver refuses the coin when
        // any leaf or checkpoint of its lineage is on-chain; without one, it
        // says it relies on the operator.
        let f = Coins::new();
        let b = test_key(0xb1);
        let coin = f.reassign(&f.base, &f.a, &b, [0xb2; 32], f.delay, &f.policy);
        let (owner, nonce) = (xonly(&b), [0xb2; 32]);
        let received = verify_coin(&coin, &f.rounds, &f.policy, &owner, &nonce, None).unwrap();
        assert_eq!(received.lineage, LineageCheck::OperatorRule);
        let lineage = received.coin.lineage();
        // A's leaf, then its checkpoint; B's own leaf is not among them.
        assert_eq!(lineage.len(), 2);
        let mut nothing = |_: &Script| false;
        let indexed = verify_coin(
            &coin,
            &f.rounds,
            &f.policy,
            &owner,
            &nonce,
            Some(&mut nothing),
        )
        .unwrap();
        assert_eq!(indexed.lineage, LineageCheck::Indexed);
        for on in &lineage {
            let spk = on.output.script_pubkey.clone();
            let mut index = |s: &Script| *s == spk;
            let err = verify_coin(
                &coin,
                &f.rounds,
                &f.policy,
                &owner,
                &nonce,
                Some(&mut index),
            )
            .unwrap_err();
            assert_eq!(err.kind(), "on_chain", "{err}");
            assert!(err.to_string().contains(&on.kind.to_string()), "{err}");
        }
    }

    #[test]
    fn every_leaf_of_a_lineage_meets_the_policy() {
        // Review R4, F1 and e2: B's leaf with an exit delay of one unit (512
        // seconds), passed on to D. D accepted the coin, and B, exiting its
        // leaf in nine blocks, took it back from under D.
        let f = Coins::new();
        let (b, d) = (test_key(0xb1), test_key(0xd1));
        let short = RelativeTime::from_units(1).unwrap();
        let mut loose = f.policy;
        loose.min_exit_delay = short;
        let to_b = f.reassign(&f.base, &f.a, &b, [0xb2; 32], short, &loose);
        let to_d = f.reassign(&to_b, &b, &d, [0xd2; 32], f.delay, &loose);
        // A policy that accepts the short delay takes the coin; the wallet's
        // own refuses it for the leaf one hop up.
        verify_coin(&to_d, &f.rounds, &loose, &xonly(&d), &[0xd2; 32], None).unwrap();
        let err =
            verify_coin(&to_d, &f.rounds, &f.policy, &xonly(&d), &[0xd2; 32], None).unwrap_err();
        assert_eq!(err.kind(), "policy", "{err}");
        assert!(matches!(
            err,
            TransferError::LineageExitDelay { delay: 1, .. }
        ));
    }
}
