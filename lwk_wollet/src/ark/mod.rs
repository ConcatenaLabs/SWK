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
//! - the scripts, the record and the client's checks, re-exported from the
//!   Arca library (`arca-covenant`, [`covenant`]), never written a second time.
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
    check_round, Branch, Chain, ClockSchedule, ExplicitOutput, LeafId, LeafPolicy, LeafRecord,
    MedianTime, RecordError, RelativeTime, RoundCheckFailure, Template, ValidLeaf, WalletPolicy,
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
