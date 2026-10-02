//! Arca: holding a leaf of an Arca covenant tree on Sequentia.
//!
//! Arca is an Ark protocol for Sequentia. An operator commits many owners'
//! balances to one on-chain output, a batch, whose tree of introspection
//! scripts pins every child output down to each owner's leaf. A wallet holds a
//! leaf as its record ([`LeafRecord`]): everything needed to check the leaf
//! against the chain and to take it on-chain alone, and nothing secret.
//!
//! This module is what a wallet needs to hold a leaf safely:
//!
//! - [`keys`]: one key for every leaf instance, derived from the leaf's random
//!   owner nonce, so a restore needs no index scan;
//! - [`verify`]: a leaf checked against its round, a coin received out of
//!   round checked back to its rounds, and a leaf checked again after a
//!   rollback;
//! - [`store`]: the wallet's leaves over the kit's store;
//! - the scripts, the leaf and coin records and the client's checks,
//!   re-exported from the Arca library (`arca-covenant`, [`covenant`]), never
//!   written a second time.
//!
//! The signers are in `lwk_signer`: `SwSigner::sign_tapscript` for the exit
//! and the other ordinary script-path signatures, `SwSigner::sign_csfs` for
//! the rebindable paths, unroll authorisations and releases.
//!
//! # Byte order
//!
//! Asset ids, the sweep token and the genesis hash are in internal byte order
//! wherever a script or a hash takes them, and in display hex (as the node's
//! RPCs print them) wherever they cross into text: the record's JSON form,
//! error messages, descriptions and the wasm bindings. Leaf ids, salts, nonces,
//! keys and witness programs have one order only and are written as their
//! bytes.

pub mod keys;
pub mod store;
pub mod verify;

/// The Arca library: every script, the leaf record, its validation and the
/// client's checks on a round.
pub use arca_covenant as covenant;
pub use arca_covenant::{
    check_round, Branch, Chain, ClockSchedule, CoinRecord, ExplicitOutput, LeafId, LeafPolicy,
    LeafRecord, MedianTime, NewLeaf, RecordError, RelativeTime, RoundCheckFailure, Template,
    Transfer, TransferError, TransferInput, ValidCoin, ValidLeaf, ValidOrigin, WalletPolicy,
};

/// Errors from the Arca module.
#[derive(thiserror::Error, Debug)]
pub enum ArkError {
    /// The record does not decode, is malformed, or does not match the chain.
    #[error(transparent)]
    Record(#[from] RecordError),

    /// An account number is not a hardened BIP32 index.
    #[error("account {0} is not below 2^31")]
    Account(u32),

    /// The signer could not derive a key.
    #[error("key derivation: {0}")]
    Derivation(String),

    /// The key derived from a record's owner nonce is not the record's owner key.
    #[error("the record's owner nonce gives the key {derived}, not the record's owner key {owner}: the leaf is not this wallet's")]
    NotOurs {
        /// The key the wallet derives from the record's nonce.
        derived: String,
        /// The record's owner key.
        owner: String,
    },
}

#[cfg(test)]
mod tests {
    // The byte-order vector (tests/data/ark_byte_order.json, written by
    // ark_byte_order.py from the Arca record vectors with hashlib alone).

    use std::str::FromStr;

    use elements::encode::serialize;
    use elements::hex::{FromHex, ToHex};
    use elements::{AssetId, Script};
    use serde_json::Value;

    use super::*;

    #[test]
    fn byte_order_follows_the_vector() {
        let v: Value =
            serde_json::from_str(include_str!("../../tests/data/ark_byte_order.json")).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let binary = Vec::<u8>::from_hex(&s("record_hex")).unwrap();
        let record = LeafRecord::from_bytes(&binary).unwrap();
        assert_eq!(
            record,
            LeafRecord::from_json_str(&s("record_json")).unwrap()
        );
        assert_eq!(record.leaf_id().unwrap().to_string(), s("leaf_id"));

        let at = |field: &str| {
            let f = &v[field];
            let off = f["binary_offset"].as_u64().unwrap() as usize;
            let internal = f["internal"].as_str().unwrap();
            assert_eq!(binary[off..off + 32].to_hex(), internal, "{field}");
            (
                f["display"].as_str().unwrap().to_string(),
                internal.to_string(),
            )
        };
        let (display, internal) = at("asset");
        assert_eq!(record.asset.to_string(), display);
        assert_eq!(serialize(&record.asset).to_hex(), internal);
        let (display, internal) = at("token");
        assert_eq!(record.schedule.token.to_string(), display);
        assert_eq!(serialize(&record.schedule.token).to_hex(), internal);
        let (display, internal) = at("genesis_hash");
        assert_eq!(record.chain.genesis_hash().to_string(), display);
        assert_eq!(record.chain.genesis_bytes().to_hex(), internal);

        assert_eq!(record.salt().to_hex(), s("salt"));
        assert_eq!(record.chain.tag().to_hex(), s("chain_tag"));
        assert_eq!(record.leaf().leaf_constant().to_hex(), s("leaf_constant"));

        // The rebindable message of the leaf's coin into one output.
        let r = &v["rebind"];
        let out = &r["output"];
        let asset = AssetId::from_str(out["asset_display"].as_str().unwrap()).unwrap();
        let output = ExplicitOutput::new(
            asset,
            out["value"].as_str().unwrap().parse().unwrap(),
            Script::from(Vec::<u8>::from_hex(out["script_pubkey"].as_str().unwrap()).unwrap()),
        );
        assert_eq!(output.record().to_hex(), out["record"].as_str().unwrap());
        let msg = record
            .leaf()
            .collab_message(
                record.asset,
                r["value_in"].as_str().unwrap().parse().unwrap(),
                &[output.clone()],
            )
            .unwrap();
        assert_eq!(msg.preimage.to_hex(), r["message"].as_str().unwrap());
        assert_eq!(msg.digest.to_hex(), r["digest"].as_str().unwrap());

        // The kit's own message signer, given the record, builds the same digest.
        use lwk_signer::csfs::{ArcaMessage, CommittedOutput, RebindMessage, RebindSource};
        let signer_msg = ArcaMessage::Rebind(RebindMessage {
            source: RebindSource::leaf(&record).unwrap(),
            asset_in: record.asset,
            value_in: record.value,
            outputs: vec![CommittedOutput {
                asset: output.asset,
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            }],
            other_inputs: Some(vec![]),
        });
        assert_eq!(
            signer_msg.digest().unwrap().to_hex(),
            r["digest"].as_str().unwrap()
        );
    }
}
