//! Bitcoin parent-chain (testnet4) support for the dual-chain Sequentia kit.
//!
//! Every standard Sequentia wallet is Bitcoin + Sequentia from one seed, sharing
//! the unconfidential address (the SEQ testnet HRP `tb` == Bitcoin testnet `tb`,
//! same BIP84 keychain). This module brings the parent-chain wallet + HTLC leg
//! into the kit so consuming wallets don't each reimplement them.
//!
//! - [`addr`] — the shared `(coin_type, HRP, Bitcoin network)` address model.
//! - [`htlc`] — the BTC-leg HTLC, whose redeemScript delegates to the kit's single
//!   source [`crate::build_htlc_redeem_script`] (byte-identical to the SEQ leg).
//! - `core` — the I/O-free wallet logic (derivation, gap-scan, coin selection,
//!   P2WPKH build+sign), shared by both transports so they are byte-identical.
//! - [`esplora`] — testnet4 esplora wire types + the blocking and async clients.
//! - [`wallet`] / [`wallet_async`] — the blocking (Ambra) and async (wasm/web)
//!   wallet drivers over `core`.

// `btc-blocking` must never be unified into a wasm build: `reqwest::blocking` is
// absent on wasm32, and additive feature unification could otherwise pull it in.
// Fail loudly rather than emit a broken wasm artifact.
#[cfg(all(feature = "btc-blocking", target_arch = "wasm32"))]
compile_error!(
    "feature `btc-blocking` cannot target wasm32 (reqwest::blocking is unavailable); use `btc-async`"
);

pub mod addr;
pub mod htlc;
// The payment lock: an asset released on a node-checked proof of an ordinary
// bitcoin payment (no hash lock). I/O-free; `lwk_paylock` reads the chains.
pub mod paylock;

#[cfg(any(feature = "btc-blocking", feature = "btc-async"))]
mod core;
#[cfg(any(feature = "btc-blocking", feature = "btc-async"))]
mod esplora;
#[cfg(any(feature = "btc-blocking", feature = "btc-async"))]
pub use core::{address, BtcPrepared, BtcScan, HtlcFunding, DEFAULT_FEERATE};

// Cross-chain (BTC <-> Sequentia-asset) HTLC swap glue: the reveal/anchor gate,
// SEQ-claim key derivation + claim, transport-split like esplora.
#[cfg(any(feature = "btc-blocking", feature = "btc-async"))]
pub mod xchain;

#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub mod wallet;
#[cfg(feature = "btc-async")]
pub mod wallet_async;
