//! Per-network address parameters shared by both chains.
//!
//! Sequentia mirrors Bitcoin's address space per network, so a single
//! unconfidential address holds on both: both chains derive
//! `m/84'/{coin_type}'/0'` and reuse Bitcoin's bech32 HRP. The Bitcoin network is
//! HARDCODED here (not derived from the Elements `Network`, which maps Sequentia
//! to `Regtest` and would yield the wrong parent-chain params).

use crate::bitcoin::address::KnownHrp;
use crate::bitcoin::Network;

/// The `(coin_type, HRP, Bitcoin network)` triple that makes the shared address
/// work. Testnet: coin_type 1, HRP `tb` -> `tb1...` (Bitcoin testnet4 and
/// Sequentia testnet derive the identical address). Mainnet: coin_type 0, HRP
/// `bc` -> `bc1...`. The Sequentia side takes its coin type from
/// `lwk_common::bip44_coin_type`, which gives the same values.
#[derive(Debug, Clone, Copy)]
pub struct ChainAddressParams {
    /// BIP84 coin_type: `1` on testnet, `0` on mainnet (Bitcoin's, shared by design).
    pub coin_type: u32,
    /// bech32 HRP for the shared address: `tb` on testnet, `bc` on mainnet.
    pub hrp: KnownHrp,
    /// Bitcoin network for the parent-chain side (hardcoded, never derived from
    /// the Elements network).
    pub network: Network,
}

impl ChainAddressParams {
    /// Bitcoin testnet4 + Sequentia testnet — the shared `tb1...` address space.
    pub fn testnet() -> Self {
        Self {
            coin_type: 1,
            hrp: KnownHrp::Testnets,
            network: Network::Testnet4,
        }
    }

    /// Bitcoin mainnet + Sequentia mainnet — the shared `bc1...` address space.
    pub fn mainnet() -> Self {
        Self {
            coin_type: 0,
            hrp: KnownHrp::Mainnet,
            network: Network::Bitcoin,
        }
    }
}
