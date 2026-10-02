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
//! operator key it was told, the shortest notice, the horizon of the first
//! expiry and the bounds of the exit delay), and checks that the record is for
//! the wallet's key and the owner nonce it picked for this leaf. A failure
//! names what failed ([`VerifyError::check`] for the five checks).
//!
//! Finality is not this module's claim. A verified leaf names the round it was
//! checked against ([`VerifiedLeaf::round_txid`]); whether that round is
//! certified and its Bitcoin anchor buried is for the caller's chain source to
//! say. A rollback can put another transaction in the round's place, paying
//! the same batch output from the same issuing coin: after any rollback that
//! disconnects the round, the wallet checks whichever transaction now pays the
//! batch output ([`recheck`]) and, if that fails, unrolls at once.

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction, Txid};

use super::keys::OwnerNonce;
use super::{LeafId, LeafRecord, MedianTime, RecordError, RelativeTime, ValidLeaf, WalletPolicy};

/// The time before the expiry by which an exit must start: the
/// specification's exit deadline, three days, for the unroll, the exit delay
/// and a margin for an anchor rollback.
pub const EXIT_DEADLINE_MARGIN: u32 = 3 * 86_400;

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

/// Verify the wallet's own leaf: `record` against `round`, under `policy`,
/// for the wallet's key `owner` and the `owner_nonce` it picked for the leaf.
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

/// Verify a leaf the wallet does not own, such as the coin a sender is about
/// to give it: the same checks as [`verify_leaf`] without the owner's key and
/// nonce. A wallet never accepts a leaf of its own with this alone.
pub fn verify_round(
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
) -> Result<VerifiedLeaf, VerifyError> {
    let valid = record.validate_round(round, policy).map_err(VerifyError)?;
    Ok(VerifiedLeaf::new(record, valid, false))
}

/// The outcome of checking a leaf again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// The same round pays the batch output, and still passes.
    Same(VerifiedLeaf),
    /// Another transaction pays the batch output now, and passes. The wallet
    /// keeps the new round's txid.
    Replaced {
        /// The round the leaf was first checked against.
        previous: Txid,
        /// The leaf as checked against the transaction that replaced it.
        now: VerifiedLeaf,
    },
}

/// Check the wallet's own leaf again, after a rollback, against whichever
/// transaction now pays its batch output. An error is an order to unroll at
/// once: the notice `W`, counted from the replacement's release, is the time
/// the wallet has.
pub fn recheck(
    previous: &VerifiedLeaf,
    record: &LeafRecord,
    round: &Transaction,
    policy: &WalletPolicy,
    owner: &XOnlyPublicKey,
    owner_nonce: &OwnerNonce,
) -> Result<Recheck, VerifyError> {
    let now = verify_leaf(record, round, policy, owner, owner_nonce)?;
    if now.round_txid == previous.round_txid {
        Ok(Recheck::Same(now))
    } else {
        Ok(Recheck::Replaced {
            previous: previous.round_txid,
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
        let again = recheck(&first, &c.record, &c.round, &c.policy, &c.owner, &c.nonce).unwrap();
        assert_eq!(again, Recheck::Same(first.clone()));

        // An honest replacement: the same coins and outputs, another sequence,
        // so another txid.
        let mut replaced = c.round.clone();
        replaced.input[0].sequence = elements::Sequence(0xffff_fffe);
        match recheck(&first, &c.record, &replaced, &c.policy, &c.owner, &c.nonce).unwrap() {
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
        let err = recheck(&first, &c.record, &bad, &c.policy, &c.owner, &c.nonce).unwrap_err();
        assert_eq!(err.check(), Some(1), "{err}");
    }
}
