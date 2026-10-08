//! The contract engine of the Sequentia Wallet Kit.
//!
//! A contract is a template (a descriptor of `sequentia-contracts`, read with
//! that repository's own reader and checked with its pinned compiler) and an
//! instance (the template's parameter and slot values, and a chain). The
//! engine recomputes an instance's output, lists its spending paths and what
//! each needs, builds the spend of a chosen path, runs the path's program
//! against the final transaction, pads it under the budget rule, and signs it
//! with a key reserved for contracts.
//!
//! `templates/` holds the templates the kit carries, copied from
//! `sequentia-contracts` at the revision `templates/PIN.json` names.

pub mod budget;
pub mod drip;
pub mod error;
pub mod hex;
pub mod known;
pub mod spend;
pub mod template;

pub use error::Error;
pub use known::{known, KnownTemplate, KNOWN};
pub use spend::{ChainFacts, CoinRequest, OutputRequest, Spend, SpendRequest};
pub use template::{Contract, Instance, PathInfo, Template};

/// The `sequentia-contracts` revision the reader and the known templates come from.
pub const CONTRACTS_REVISION: &str = "ad8ed18";
