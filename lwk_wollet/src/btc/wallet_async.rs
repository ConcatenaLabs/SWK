//! Async btc wallet driver (wasm / web).
//!
//! Thin transport layer: esplora I/O via `futures` `.buffered(8)`, all derivation
//! / coin-selection / build+sign logic in the shared [`super::core`] — the SAME
//! core the blocking driver [`super::wallet`] uses, so the two paths produce
//! byte-identical transactions (Phase 1's parity gate).

use crate::bitcoin::secp256k1::Secp256k1;

use super::addr::ChainAddressParams;
use super::core::{self, BtcPrepared, BtcScan, HtlcFunding, ScanState};
use super::esplora::asyncr as tx;
use crate::error::Error;

/// BIP44-style gap scan (async). See [`super::wallet::scan`].
pub async fn scan(params: &ChainAddressParams, mnemonic: &str, t4_api: &str) -> Result<BtcScan, Error> {
    let secp = Secp256k1::new();
    let master = core::master_xprv(mnemonic, params)?;
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');

    let mut state = ScanState::new();
    let mut start = 0u32;
    for _ in 0..core::MAX_BATCHES {
        let (slots, addrs) = ScanState::batch_addresses(&secp, &master, params, start)?;
        let infos = tx::fetch_infos(&client, base, &addrs).await;
        let active = state.absorb(start, &slots, infos);
        start += core::GAP;
        if !active {
            break;
        }
    }
    Ok(state.finish())
}

/// Build + sign a P2WPKH transaction (async). See [`super::wallet::prepare`].
pub async fn prepare(
    params: &ChainAddressParams,
    mnemonic: &str,
    t4_api: &str,
    dest_addr: &str,
    amount_sats: u64,
    fee_rate: f64,
) -> Result<BtcPrepared, Error> {
    let secp = Secp256k1::new();
    let master = core::master_xprv(mnemonic, params)?;
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');

    let scan = scan(params, mnemonic, base).await?;
    let keys = core::window_keys(&secp, &master, params, scan.scan_limit, scan.change_next)?;
    let addrs: Vec<String> = keys.iter().map(|k| k.address.to_string()).collect();
    let lists = tx::fetch_utxos(&client, base, &addrs).await;
    let utxos = core::utxos_from_lists(keys, lists)?;
    core::build_signed_tx(&secp, &master, params, dest_addr, amount_sats, fee_rate, scan.change_next, utxos)
}

/// Live BTC fee rate (sat/vB) for confirming within `target_blocks` (async); for
/// sizing a time-sensitive send/refund. `None` if unavailable.
pub async fn fee_estimate(t4_api: &str, target_blocks: u16) -> Option<f64> {
    let Ok(client) = tx::client() else { return None };
    tx::fee_estimate(&client, t4_api.trim_end_matches('/'), target_blocks).await
}

/// Broadcast a raw transaction hex to testnet4 (async); returns the txid.
pub async fn broadcast(t4_api: &str, tx_hex: &str) -> Result<String, Error> {
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');
    let (ok, body) = tx::post_tx(&client, base, tx_hex).await?;
    core::parse_broadcast(ok, &body)
}

/// Find the HTLC funding output in `txid` by matching `p2sh_spk_hex` (async).
//
// INTENTIONALLY RETAINED, NOT DEAD CODE, on the same grounds as
// `btc::xchain::asyncr`: this locates the BTC HTLC output a cross-chain taker must
// confirm before it commits the asset leg, and it is reached from wasm as
// `xchainFindBtcFunding`. It was swept once already, as collateral damage from
// deleting the retired RFQ rail by container rather than by reachability.
pub async fn find_htlc_funding(t4_api: &str, txid: &str, p2sh_spk_hex: &str) -> Result<HtlcFunding, Error> {
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');
    let tx_json = tx::get_tx_json(&client, base, txid).await?;
    let tip = tx::tip_height(&client, base).await;
    core::parse_htlc_funding(&tx_json, p2sh_spk_hex, tip)
}
