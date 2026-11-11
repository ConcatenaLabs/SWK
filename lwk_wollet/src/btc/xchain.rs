//! Cross-chain (BTC <-> Sequentia-asset) HTLC swap glue — the taker's (Alice's) side.
//!
//! Alice holds BTC and wants the SEQ asset: she funds the BTC HTLC, the maker funds
//! the SEQ HTLC, Alice verifies the SEQ leg is anchor-safe (the reveal gate), then
//! claims it, revealing the preimage. SEQ-leg crypto reuses the kit's `seqdex_htlc`
//! primitives; the BTC leg is [`super::htlc`]. This is the glue: HTLC spend-key
//! derivation, the swap secret, the reveal + claim-deadline gates, and the SEQ
//! claim + broadcast.
//!
//! THE REVEAL GATE (anchoring's whole point — no cross-chain buffer): Alice may
//! reveal the preimage only when, read from her OWN nodes (never the maker), the
//! SEQ funding's Bitcoin anchor height A satisfies A >= H_btc, `anchorstatus` is
//! "ok", and A is at least D Bitcoin-confirmations deep (D default 1, a TAKER dial
//! — the same security as accepting that much BTC at 1 conf). There is NO
//! value-scaled depth and NO reorg-protection timelock; the SEQ tx's finality IS
//! its anchor Bitcoin block's finality (the chain follows Bitcoin reorgs in real
//! time). The CLTV refund timelocks are LIVENESS only.
//!
//! Ported verbatim (logic-wise) from ambra_core's xchain.rs, swapping SwSigner for
//! the kit's [`super::core`] derivation and reqwest::blocking for the blocking +
//! async transport split (like [`super::esplora`]).

use std::str::FromStr;

use crate::bitcoin::bip32::DerivationPath;
use crate::bitcoin::hex::{DisplayHex, FromHex};
use crate::bitcoin::secp256k1::{Secp256k1, SecretKey};

use super::addr::ChainAddressParams;
use crate::error::Error;

fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

fn hexdec(s: &str) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_hex(s).map_err(map)
}

/// Which HD path the SEQ-claim / BTC-refund keys derive from.
///
/// `Canonical` is the kit's one true derivation: absolute paths under the BIP84
/// account, deliberately OUTSIDE the receive(0)/change(1) branches so the wallet
/// never sweeps the HTLC keys as ordinary funds. `LegacyRelative` reproduces the
/// web wallet's older relative `m/3/0` SEQ-claim key, so a swap that wallet funded
/// before the port can still be claimed/recovered. The chosen mode MUST be
/// recorded in the persisted swap state so recovery derives the SAME key that
/// funded the leg. The daemon does not enforce the path (it rebuilds scripts from
/// the pubkeys the taker sends); the only constraint is claim==funding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PathMode {
    /// Absolute `m/84'/1'/0'/{3,2}/0` (new swaps).
    Canonical,
    /// The web wallet's legacy relative `m/3/0` SEQ-claim key (recovery only).
    LegacyRelative,
}

impl PathMode {
    fn seq_claim_path(self) -> &'static str {
        match self {
            PathMode::Canonical => "m/84h/1h/0h/3/0",
            PathMode::LegacyRelative => "m/3/0",
        }
    }
    fn btc_refund_path(self) -> &'static str {
        // The legacy web wallet never built a BTC refund, so canonical for both.
        "m/84h/1h/0h/2/0"
    }
    fn btc_claim_path(self) -> &'static str {
        // DISTINCT from btc_refund (…/2/0) and seq_claim (…/3/0): the CLAIM key
        // spends the HTLC's IF/preimage branch and MUST differ from the refund
        // key, so a single leaked key can never unlock both branches. Index 4 is
        // still outside the receive(0)/change(1) branches (never swept as funds).
        "m/84h/1h/0h/4/0"
    }
}

/// Derive `(secret, 33-byte compressed pubkey hex)` at `path`. Byte-identical to
/// ambra's SwSigner derivation: the kit's `master_xprv` is the same BIP39 seed("")
/// -> `Xpriv::new_master` -> `derive_priv` chain SwSigner uses.
fn derive_keypair(params: &ChainAddressParams, mnemonic: &str, path: &str) -> Result<(SecretKey, String), Error> {
    let secp = Secp256k1::new();
    let master = super::core::master_xprv(mnemonic, params)?;
    let xprv = master.derive_priv(&secp, &DerivationPath::from_str(path).map_err(map)?).map_err(map)?;
    let sk = xprv.private_key;
    let pubkey = sk.public_key(&secp).serialize().to_lower_hex_string();
    Ok((sk, pubkey))
}

/// The taker's SEQ-claim keypair (spends the IF/redeem branch, revealing the preimage).
pub fn seq_claim_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.seq_claim_path())
}

/// The taker's BTC-refund keypair (spends the BTC HTLC's ELSE/CLTV branch).
pub fn btc_refund_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.btc_refund_path())
}

/// The taker's BTC-CLAIM keypair (spends the BTC HTLC's IF/preimage branch). This
/// is the money key for a sub-asset SELL: the pubkey is the `btc_claim_pub` sent to
/// the LSP `/swap`, and the secret signs the on-chain claim once the preimage is
/// learned. Its path is distinct from the refund key's (see `btc_claim_path`).
pub fn btc_claim_keypair(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
) -> Result<(SecretKey, String), Error> {
    derive_keypair(params, mnemonic, mode.btc_claim_path())
}

/// A fresh swap preimage + its SHA256 hashlock, as `(secret_hex, hash_hex)`. The
/// secret is NOT HD-derivable; the caller MUST persist it (sealed) before any
/// money moves — it is unrecoverable if lost and it gates the BTC claim.
pub fn new_secret() -> (String, String) {
    let s = crate::generate_swap_secret();
    (s.secret_hex, s.hash_hex)
}

/// Evidence + verdict of the reveal gate.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorEvidence {
    /// SEQ funding block's Bitcoin anchor height, or `-1` if the block carries none.
    pub seq_anchor_height: i64,
    /// `H_btc` — the BTC funding confirmation height.
    pub btc_leg_height: i64,
    /// The taker's OWN testnet4 tip height.
    pub btc_tip: i64,
    /// `getanchorstatus` from the taker's own SEQ node.
    pub anchor_status: String,
    /// `btc_tip - seq_anchor_height + 1`, or `-1` when there is no anchor.
    pub depth: i64,
    /// Whether it is safe to reveal (all conditions met).
    pub ok: bool,
}

/// The pure reveal-gate arithmetic (the I/O-free heart of `verify_seq_leg_safe`),
/// shared by both transports so they share one truth table.
///
/// `ok` iff the SEQ funding is anchored (`seq_anchor_height >= 0`), its anchor is at
/// or above the BTC funding (`>= btc_leg_height`), the chain's anchor status is
/// "ok", and the anchor is at least `min_depth` (D, default 1) Bitcoin-confs deep.
pub fn evaluate_gate(
    seq_anchor_height: i64,
    anchor_status: &str,
    btc_tip: i64,
    btc_leg_height: i64,
    min_depth: i64,
) -> AnchorEvidence {
    let depth = if seq_anchor_height >= 0 { btc_tip - seq_anchor_height + 1 } else { -1 };
    let ok = seq_anchor_height >= 0
        && seq_anchor_height >= btc_leg_height
        && anchor_status == "ok"
        && depth >= min_depth;
    AnchorEvidence {
        seq_anchor_height,
        btc_leg_height,
        btc_tip,
        anchor_status: anchor_status.to_string(),
        depth,
        ok,
    }
}

/// Pure claim-deadline check: there must be `margin` SEQ blocks of headroom before
/// the SEQ-leg CLTV refund height. `seq_locktime` is a SEQUENTIA block height, so
/// it is compared to the SEQ chain tip (NOT the Bitcoin tip). If this fails the
/// taker must NOT reveal: a claim that can't confirm before `seq_locktime` lets the
/// maker refund the SEQ leg via CLTV and then claim the BTC with the now-public
/// preimage.
pub fn deadline_ok(seq_tip: i64, seq_locktime: u32, margin: i64) -> bool {
    seq_tip >= 0 && seq_tip + margin < seq_locktime as i64
}

/// A sane default SEQ-chain native feerate (atoms per vByte) for the claim, well
/// above the node's ~0.1-atom/vByte min-relay floor so a rate-derived claim fee
/// always clears relay. This is a SEQUENTIA feerate, NOT a Bitcoin sat/vB.
pub const DEFAULT_SEQ_CLAIM_FEERATE: u64 = 1;

/// Conservative vbyte estimate for the single-input SEQ HTLC claim tx: 1 P2SH
/// HTLC input (72B max DER sig + 32B preimage + 1B OP_1 selector + ~114B
/// OP_PUSHDATA1 redeemScript) + 2 explicit Elements outputs (recipient + fee).
/// Deliberately OVER-estimates so the rate-derived fee never undershoots the
/// node's own vsize-based relay floor. (Refine against an actual built claim.)
pub fn claim_tx_vsize() -> u64 {
    400
}

/// The SEQ-leg claim fee, in atoms of the CLAIMED asset: the native-equivalent of
/// `seq_feerate_native * claim_tx_vsize()`, converted at the claimed asset's
/// published acceptance rate. Replaces the old flat 100000-atom fee.
///
/// `rate` is the CLAIMED asset's acceptance rate (atoms per 1e8 native). It MUST
/// be non-zero: a `rate == 0` asset is NOT fee-accepted by producers, so any claim
/// in it is unrelayable — this returns `Err` rather than emitting a stuck claim
/// (the rate==0 ⇒ 1:1 fallback of `convert_value_to_amount` is wrong here and is
/// deliberately NOT used). `seq_feerate_native` is a SEQUENTIA native feerate
/// (atoms/vByte), never a Bitcoin sat/vB. The result is still bounded by the
/// `fee < seq_amount` guard in [`seq_claim`].
pub fn seq_claim_fee_atoms(rate: u64, seq_feerate_native: u64) -> Result<u64, Error> {
    if rate == 0 {
        return Err(Error::Generic(
            "claimed asset is not currently fee-accepted by producers; cannot build a relayable Sequentia-leg claim".into(),
        ));
    }
    let native_value = seq_feerate_native.saturating_mul(claim_tx_vsize());
    Ok(crate::seqdex_swap::convert_value_to_amount(native_value, rate))
}

/// The SEQ-leg redeemScript the taker rebuilds (claim = her SEQ-claim key, refund =
/// the maker's SEQ-refund pubkey), as hex, so the caller can byte-compare it to the
/// daemon-reported `seqLeg.redeemScript` (value-binding) before trusting the leg.
pub fn seq_redeem_script_hex(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
    hash_hex: &str,
    maker_seq_refund_pub_hex: &str,
    seq_locktime: u32,
) -> Result<String, Error> {
    let (_sk, claim_pub_hex) = seq_claim_keypair(params, mnemonic, mode)?;
    let script = crate::build_htlc_redeem_script(
        &hexdec(hash_hex)?,
        &hexdec(&claim_pub_hex)?,
        &hexdec(maker_seq_refund_pub_hex)?,
        seq_locktime,
    )?;
    Ok(script.as_bytes().to_lower_hex_string())
}

/// Build the Sequentia-leg claim tx (reveals the preimage). Rebuilds the redeemScript from its
/// components (so it is exactly the verified script) and pays `amount - fee` to the
/// taker's own SEQ `dest_address` plus an explicit Elements fee output in the
/// claimed asset. `fee` must be `< seq_amount`. Returns the raw Elements tx hex.
#[allow(clippy::too_many_arguments)]
pub fn seq_claim(
    params: &ChainAddressParams,
    mnemonic: &str,
    mode: PathMode,
    seq_txid: &str,
    seq_vout: u32,
    seq_amount: u64,
    seq_asset_id: &str,
    dest_address: &str,
    hash_hex: &str,
    maker_seq_refund_pub_hex: &str,
    seq_locktime: u32,
    fee: u64,
    preimage_hex: &str,
) -> Result<String, Error> {
    let (sk, claim_pub_hex) = seq_claim_keypair(params, mnemonic, mode)?;
    let redeem = crate::build_htlc_redeem_script(
        &hexdec(hash_hex)?,
        &hexdec(&claim_pub_hex)?,
        &hexdec(maker_seq_refund_pub_hex)?,
        seq_locktime,
    )?;
    let dest = crate::elements::Address::parse_with_params(
        dest_address,
        lwk_common::Network::sequentia_testnet().address_params(),
    )
    .map_err(map)?;
    if fee >= seq_amount {
        return Err(Error::Generic("Sequentia-leg claim fee exceeds the leg amount".into()));
    }
    let spend = crate::SeqHtlcSpend {
        txid: seq_txid.to_string(),
        vout: seq_vout,
        amount: seq_amount,
        asset_id: seq_asset_id.to_string(),
        dest_spk: dest.script_pubkey().as_bytes().to_vec(),
        fee,
    };
    crate::build_claim_tx(&spend, &redeem, &sk, &hexdec(preimage_hex)?)
}

// --- transport: the reveal gate + broadcast over the taker's OWN nodes ---------
//
// Each submodule mirrors `super::esplora`'s split and reuses its esplora clients.

/// Blocking transport (Ambra / native): the 3 reveal-gate GETs, the Sequentia-leg
/// broadcast, and the Sequentia tip for the claim-deadline gate.
//
// INTENTIONALLY RETAINED, NOT DEAD CODE — and unlike the `asyncr` twins below,
// these are not even orphaned: they have a LIVE caller that simply lives in
// another repository. Ambra reaches them through a path dependency, at
// `ambra_core/src/api/mod.rs` (xchain_verify_seq_leg_safe -> verify_seq_leg_safe,
// xchain_seq_broadcast -> seq_broadcast, and the claim-deadline guard around
// them). A dead-code sweep run inside THIS repo alone cannot see those calls and
// will report the whole module as unused. It is not. `verify_seq_leg_safe` is the
// anchor reveal gate that must pass before Ambra reveals a preimage; deleting any
// of this removes a fund-safety check from a shipped mobile wallet.
#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub mod blocking {
    use super::*;

    fn client() -> Result<reqwest::blocking::Client, Error> {
        super::super::esplora::blocking::client()
    }

    /// Evaluate the reveal gate from the taker's OWN SEQ esplora + testnet4 view,
    /// NEVER the maker. `min_depth` = D (default 1).
    pub fn verify_seq_leg_safe(
        seq_esplora: &str,
        seq_block_hash: &str,
        btc_leg_height: i64,
        t4_api: &str,
        min_depth: i64,
    ) -> Result<AnchorEvidence, Error> {
        let client = client()?;
        let seq = seq_esplora.trim_end_matches('/');
        let t4 = t4_api.trim_end_matches('/');

        let block: serde_json::Value =
            client.get(format!("{seq}/block/{seq_block_hash}")).send().map_err(map)?.json().map_err(map)?;
        let seq_anchor_height = block
            .get("bitcoin_anchor")
            .and_then(|a| a.get("height"))
            .and_then(|h| h.as_i64())
            .unwrap_or(-1);

        let status_v: serde_json::Value =
            client.get(format!("{seq}/sequentia/anchorstatus")).send().map_err(map)?.json().map_err(map)?;
        let anchor_status = status_v.get("anchorstatus").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();

        let btc_tip = client
            .get(format!("{t4}/blocks/tip/height"))
            .send()
            .map_err(map)?
            .text()
            .map_err(map)?
            .trim()
            .parse::<i64>()
            .map_err(map)?;

        Ok(evaluate_gate(seq_anchor_height, &anchor_status, btc_tip, btc_leg_height, min_depth))
    }

    /// The taker's own SEQ chain tip height (for the claim-deadline gate), or `-1`.
    pub fn seq_tip_height(seq_esplora: &str) -> i64 {
        let Ok(client) = client() else { return -1 };
        let base = seq_esplora.trim_end_matches('/');
        client
            .get(format!("{base}/blocks/tip/height"))
            .send()
            .ok()
            .and_then(|r| r.text().ok())
            .and_then(|t| t.trim().parse::<i64>().ok())
            .unwrap_or(-1)
    }

    /// Whether there is safe margin before the SEQ-leg CLTV refund height, read
    /// from the taker's own Sequentia tip. Refuse to reveal when this is false.
    pub fn claim_deadline_ok(seq_esplora: &str, seq_locktime: u32, margin: i64) -> bool {
        deadline_ok(seq_tip_height(seq_esplora), seq_locktime, margin)
    }

    /// Broadcast a raw Elements tx hex to the Sequentia esplora; returns the txid.
    pub fn seq_broadcast(seq_esplora: &str, tx_hex: &str) -> Result<String, Error> {
        let client = client()?;
        let base = seq_esplora.trim_end_matches('/');
        let resp = client.post(format!("{base}/tx")).body(tx_hex.to_string()).send().map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().map_err(map)?;
        super::super::core::parse_broadcast(ok, &body)
    }

    /// Read the maker's revealed preimage from its on-chain spend of the taker's
    /// funded SEQ asset leg — the REVERSE-swap reveal (asset -> BTC). Finds the tx
    /// that spent `(seq_leg_txid, vout)` on the Sequentia esplora, then returns the
    /// scriptSig/witness data push whose `sha256` equals `hash_hex` (the agreed
    /// hashlock `H`), or `None` if the leg is not yet spent / no matching push is
    /// visible yet. TRUST-MINIMISING: the taker learns the secret from the CHAIN
    /// and validates it here (`sha256(push) == H`) — never on a counterparty's word
    /// — so a withheld or bogus off-chain "secret" message can never mislead it.
    //
    // INTENTIONALLY RETAINED, NOT DEAD CODE, on the same grounds as the `asyncr`
    // block above: no in-repo caller yet, but this is the reverse-swap (asset -> BTC)
    // half of the same fund-safety surface for the live order-book cross rail. A
    // dead-code sweep must not take it.
    pub fn read_seq_preimage(
        seq_esplora: &str,
        seq_leg_txid: &str,
        vout: u32,
        hash_hex: &str,
    ) -> Result<Option<String>, Error> {
        use crate::bitcoin::hashes::{sha256, Hash as _};

        let client = client()?;
        let base = seq_esplora.trim_end_matches('/');
        let want = hash_hex.to_lowercase();

        // 1. Is the funded outpoint spent, and by which tx? A not-yet-spent (or
        //    transiently unreadable) outpoint is "no preimage yet", not an error.
        let os: serde_json::Value = match client
            .get(format!("{base}/tx/{seq_leg_txid}/outspend/{vout}"))
            .send()
            .map_err(map)?
            .json()
        {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if !os.get("spent").and_then(|s| s.as_bool()).unwrap_or(false) {
            return Ok(None);
        }
        let Some(spend_txid) = os.get("txid").and_then(|t| t.as_str()) else { return Ok(None) };

        // 2. Fetch the spending tx and scan every input's scriptSig (and witness,
        //    defensively) for the 32-byte push that hashes to H.
        let stx: serde_json::Value =
            client.get(format!("{base}/tx/{spend_txid}")).send().map_err(map)?.json().map_err(map)?;
        let is_hex = |s: &str| s.len() >= 2 && s.chars().all(|c| c.is_ascii_hexdigit());
        if let Some(vins) = stx.get("vin").and_then(|v| v.as_array()) {
            for vin in vins {
                let mut pushes: Vec<String> = vec![];
                if let Some(asm) = vin.get("scriptsig_asm").and_then(|a| a.as_str()) {
                    // asm interleaves opcode names (OP_PUSHBYTES_32, …) with hex data
                    // pushes; the opcode names contain non-hex letters and are skipped.
                    for tok in asm.split_whitespace() {
                        if is_hex(tok) {
                            pushes.push(tok.to_lowercase());
                        }
                    }
                }
                if let Some(wit) = vin.get("witness").and_then(|w| w.as_array()) {
                    for w in wit.iter().filter_map(|w| w.as_str()) {
                        if is_hex(w) {
                            pushes.push(w.to_lowercase());
                        }
                    }
                }
                for p in pushes {
                    if p.len() == 64 {
                        if let Ok(bytes) = Vec::<u8>::from_hex(&p) {
                            let h = sha256::Hash::hash(&bytes).to_byte_array().to_lower_hex_string();
                            if h == want {
                                return Ok(Some(p));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Async transport (wasm / web): the same reveal gate + broadcast + Sequentia tip.
//
// INTENTIONALLY RETAINED, NOT DEAD CODE. `verify_seq_leg_safe`, `seq_tip_height`,
// `claim_deadline_ok` and `seq_broadcast` below (and `wallet_async::find_htlc_funding`)
// briefly had no in-repo caller, when the wasm client of the retired RFQ rail was
// deleted by CONTAINER and took the non-RFQ bindings with it. They are reachable
// again from `lwk_wasm::xchain`'s free functions (xchainVerifySeqLeg,
// xchainClaimDeadlineOk, xchainSeqBroadcast, xchainFindBtcFunding), which are free
// functions precisely so this cannot recur. Either way they are kept
// deliberately: they are the fund-safety surface of the
// order-book cross rail, which is LIVE. `verify_seq_leg_safe` IS the anchor reveal
// gate a taker must pass before a preimage is ever revealed, `claim_deadline_ok` /
// `seq_tip_height` are the refund-deadline guard around it, and `seq_broadcast` puts
// the claim on chain over the taker's OWN node rather than a counterparty's. Removing
// any of them removes a safety check, not dead weight. Decide by whether the cross
// rail still needs the guarantee, never by "nothing in this repo calls it".
#[cfg(feature = "btc-async")]
pub mod asyncr {
    use super::*;

    fn client() -> Result<reqwest::Client, Error> {
        super::super::esplora::asyncr::client()
    }

    /// Evaluate the reveal gate from the taker's OWN nodes (async). See the
    /// blocking analogue.
    pub async fn verify_seq_leg_safe(
        seq_esplora: &str,
        seq_block_hash: &str,
        btc_leg_height: i64,
        t4_api: &str,
        min_depth: i64,
    ) -> Result<AnchorEvidence, Error> {
        let client = client()?;
        let seq = seq_esplora.trim_end_matches('/');
        let t4 = t4_api.trim_end_matches('/');

        let block: serde_json::Value = client
            .get(format!("{seq}/block/{seq_block_hash}"))
            .send()
            .await
            .map_err(map)?
            .json()
            .await
            .map_err(map)?;
        let seq_anchor_height = block
            .get("bitcoin_anchor")
            .and_then(|a| a.get("height"))
            .and_then(|h| h.as_i64())
            .unwrap_or(-1);

        let status_v: serde_json::Value = client
            .get(format!("{seq}/sequentia/anchorstatus"))
            .send()
            .await
            .map_err(map)?
            .json()
            .await
            .map_err(map)?;
        let anchor_status = status_v.get("anchorstatus").and_then(|s| s.as_str()).unwrap_or("unknown").to_string();

        let btc_tip = client
            .get(format!("{t4}/blocks/tip/height"))
            .send()
            .await
            .map_err(map)?
            .text()
            .await
            .map_err(map)?
            .trim()
            .parse::<i64>()
            .map_err(map)?;

        Ok(evaluate_gate(seq_anchor_height, &anchor_status, btc_tip, btc_leg_height, min_depth))
    }

    /// The taker's own SEQ chain tip height (async), or `-1`.
    pub async fn seq_tip_height(seq_esplora: &str) -> i64 {
        let Ok(client) = client() else { return -1 };
        let base = seq_esplora.trim_end_matches('/');
        match client.get(format!("{base}/blocks/tip/height")).send().await {
            Ok(r) => r.text().await.ok().and_then(|t| t.trim().parse::<i64>().ok()).unwrap_or(-1),
            Err(_) => -1,
        }
    }

    /// Whether there is safe margin before the SEQ-leg CLTV refund height (async).
    pub async fn claim_deadline_ok(seq_esplora: &str, seq_locktime: u32, margin: i64) -> bool {
        deadline_ok(seq_tip_height(seq_esplora).await, seq_locktime, margin)
    }

    /// Broadcast a raw Elements tx hex to the Sequentia esplora (async); returns the txid.
    pub async fn seq_broadcast(seq_esplora: &str, tx_hex: &str) -> Result<String, Error> {
        let client = client()?;
        let base = seq_esplora.trim_end_matches('/');
        let resp = client.post(format!("{base}/tx")).body(tx_hex.to_string()).send().await.map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().await.map_err(map)?;
        super::super::core::parse_broadcast(ok, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The reveal gate's truth table — the load-bearing safety predicate.
    #[test]
    fn gate_predicate() {
        // anchored, A >= H_btc, status ok, depth >= 1 -> safe.
        let e = evaluate_gate(100, "ok", 100, 100, 1);
        assert!(e.ok && e.depth == 1);
        // anchor below the BTC funding -> NOT safe (can't bind the legs).
        assert!(!evaluate_gate(99, "ok", 200, 100, 1).ok);
        // not anchored -> NOT safe.
        assert!(!evaluate_gate(-1, "ok", 200, 100, 1).ok);
        // status not ok -> NOT safe.
        assert!(!evaluate_gate(100, "stalled", 200, 100, 1).ok);
        // depth below the taker's dial -> NOT safe (anchor not buried enough).
        assert!(!evaluate_gate(200, "ok", 200, 100, 3).ok); // depth 1 < 3
        assert!(evaluate_gate(198, "ok", 200, 100, 3).ok); // depth 3 >= 3
    }

    #[test]
    fn deadline_predicate() {
        assert!(deadline_ok(100, 200, 10)); // 100 + 10 < 200
        assert!(!deadline_ok(195, 200, 10)); // 195 + 10 >= 200 -> too close
        assert!(!deadline_ok(-1, 200, 10)); // no tip -> refuse
    }

    #[test]
    fn claim_fee_sizing() {
        // rate 0 (asset not fee-accepted) -> refuse, never emit an unrelayable claim.
        assert!(seq_claim_fee_atoms(0, DEFAULT_SEQ_CLAIM_FEERATE).is_err());
        // native (rate 1e8) -> fee == native_value == feerate * vsize.
        let native = seq_claim_fee_atoms(100_000_000, 1).unwrap();
        assert_eq!(native, claim_tx_vsize()); // 1 atom/vB * 400 vB
        // a high-unit-value asset pays FEWER atoms (granularity), per first-principle 4.
        let gold = seq_claim_fee_atoms(4_377_615_194_112, 1).unwrap();
        assert!(gold >= 1 && gold < native, "a valuable asset pays fewer atoms (not a bug)");
    }

    // Legacy and canonical SEQ-claim keys differ (the web shim must record which).
    #[test]
    fn pathmode_keys_differ() {
        let p = ChainAddressParams::testnet();
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (_, canon) = seq_claim_keypair(&p, m, PathMode::Canonical).unwrap();
        let (_, legacy) = seq_claim_keypair(&p, m, PathMode::LegacyRelative).unwrap();
        assert_ne!(canon, legacy, "m/84'/1'/0'/3/0 and m/3/0 must derive different keys");
        assert_eq!(canon.len(), 66); // 33-byte compressed pubkey hex
    }

    // Live read-only acceptance run for the ANCHOR REVEAL GATE against the real
    // infrastructure. Ignored by default (it needs network); run with:
    //   cargo test -p lwk_wollet --features btc-blocking --lib \
    //     btc::xchain::tests::live_anchor_gate -- --ignored --nocapture
    //
    // This is the surviving half of a test that also exercised the retired RFQ
    // rail's REST client. Deleting the rail took the whole test with it, and with
    // it the only I/O coverage of the gate — but the gate is not RFQ code, it is
    // the fund-safety predicate of the LIVE order-book cross rail. Restored here
    // touching ONLY the taker's own Sequentia and testnet4 esplora, which is all
    // the gate is ever allowed to consult: it must never read the counterparty.
    #[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
    #[test]
    #[ignore = "hits the live Sequentia testnet infra"]
    fn live_anchor_gate() {
        let seq = "http://159.195.15.140/api";
        let t4 = "http://159.195.15.140/testnet4/api";

        // Evaluate the gate against the real Sequentia tip block and the live
        // testnet4 view. btc_leg_height = 0 so only the anchored + depth
        // conditions decide; this exercises the three live GETs, the parsing and
        // the predicate together, which no unit test can.
        let client = reqwest::blocking::Client::new();
        let tip_hash = client
            .get(format!("{seq}/blocks/tip/hash"))
            .send()
            .unwrap()
            .text()
            .unwrap();
        let tip_hash = tip_hash.trim();
        let ev = blocking::verify_seq_leg_safe(seq, tip_hash, 0, t4, 1).expect("gate");
        eprintln!(
            "LIVE gate: seq_anchor_height={} btc_tip={} status={} depth={} ok={}",
            ev.seq_anchor_height, ev.btc_tip, ev.anchor_status, ev.depth, ev.ok
        );
        // The tip block must carry a real Bitcoin anchor and the chain's anchor
        // status must be healthy — the safety-critical live behaviour.
        assert!(
            ev.seq_anchor_height >= 0,
            "the Sequentia tip must carry a Bitcoin anchor"
        );
        assert!(ev.btc_tip > 0, "must read the taker's own testnet4 tip");
        assert_eq!(ev.anchor_status, "ok", "anchor status must be ok");
    }
}
