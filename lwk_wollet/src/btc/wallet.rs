//! Blocking btc wallet driver (Ambra / native).
//!
//! Thin transport layer: esplora I/O via `std::thread::scope`, all derivation /
//! coin-selection / build+sign logic in the shared [`super::core`]. The async
//! driver [`super::wallet_async`] mirrors this over the same core, so the two
//! produce byte-identical transactions.

use crate::bitcoin::secp256k1::Secp256k1;

use super::addr::ChainAddressParams;
use super::core::{self, BtcPrepared, BtcScan, HtlcFunding, ScanState};
use super::esplora::blocking as tx;
use crate::error::Error;

/// BIP44-style gap scan: keep scanning GAP-wide batches (external + internal)
/// until a whole batch shows no activity. Balance = funded − spent across chain +
/// mempool stats.
pub fn scan(params: &ChainAddressParams, mnemonic: &str, t4_api: &str) -> Result<BtcScan, Error> {
    let secp = Secp256k1::new();
    let master = core::master_xprv(mnemonic, params)?;
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');

    let mut state = ScanState::new();
    let mut start = 0u32;
    for _ in 0..core::MAX_BATCHES {
        let (slots, addrs) = ScanState::batch_addresses(&secp, &master, params, start)?;
        let infos = tx::fetch_infos(&client, base, &addrs);
        let active = state.absorb(start, &slots, infos);
        start += core::GAP;
        if !active {
            break;
        }
    }
    Ok(state.finish())
}

/// Build + sign a P2WPKH transaction paying `amount_sats` to `dest_addr`, with
/// largest-first coin selection and change to the next change address. Does a
/// fresh scan so the UTXO set and change index are current. Not broadcast.
pub fn prepare(
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

    let scan = scan(params, mnemonic, base)?;
    let keys = core::window_keys(&secp, &master, params, scan.scan_limit, scan.change_next)?;
    let addrs: Vec<String> = keys.iter().map(|k| k.address.to_string()).collect();
    let lists = tx::fetch_utxos(&client, base, &addrs);
    let utxos = core::utxos_from_lists(keys, lists)?;
    core::build_signed_tx(&secp, &master, params, dest_addr, amount_sats, fee_rate, scan.change_next, utxos)
}

/// Live BTC fee rate (sat/vB) for confirming within `target_blocks`, from the
/// testnet4 esplora `/fee-estimates` — for sizing a time-sensitive send/refund.
/// `None` if unavailable (the caller falls back to a default). Pass this as
/// `prepare`'s `fee_rate` instead of the flat default.
pub fn fee_estimate(t4_api: &str, target_blocks: u16) -> Option<f64> {
    let client = tx::client().ok()?;
    tx::fee_estimate(&client, t4_api.trim_end_matches('/'), target_blocks)
}

/// Broadcast a raw transaction hex to testnet4; returns the txid on success.
pub fn broadcast(t4_api: &str, tx_hex: &str) -> Result<String, Error> {
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');
    let (ok, body) = tx::post_tx(&client, base, tx_hex)?;
    core::parse_broadcast(ok, &body)
}

/// Find the HTLC funding output in `txid` by matching `p2sh_spk_hex`, reporting
/// its value + confirmation depth on the caller's own testnet4 view. HARD-FAILS
/// if no output matches (never defaults to vout 0).
pub fn find_htlc_funding(t4_api: &str, txid: &str, p2sh_spk_hex: &str) -> Result<HtlcFunding, Error> {
    let client = tx::client()?;
    let base = t4_api.trim_end_matches('/');
    let tx_json = tx::get_tx_json(&client, base, txid)?;
    let tip = tx::tip_height(&client, base);
    core::parse_htlc_funding(&tx_json, p2sh_spk_hex, tip)
}
