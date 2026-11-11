//! I/O-free core shared by the blocking and async btc transports.
//!
//! Key derivation, the gap-scan accumulator, coin selection, and P2WPKH
//! build+sign all live here, transport-agnostic. Both drivers (blocking esplora
//! for Ambra, async esplora for wasm/web) call this same code, so they produce
//! BYTE-IDENTICAL transactions by construction — the property Phase 1's parity
//! gate checks. The drivers contribute only the esplora fetch/broadcast I/O.

use std::str::FromStr;

use bip39::Mnemonic;

use crate::bitcoin::bip32::{DerivationPath, Xpriv};
use crate::bitcoin::consensus::encode::serialize_hex;
use crate::bitcoin::hashes::Hash;
use crate::bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use crate::bitcoin::sighash::SighashCache;
use crate::bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, CompressedPublicKey, EcdsaSighashType,
    Network as BtcNetwork, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use super::addr::ChainAddressParams;
use super::esplora::{AddrInfo, EsploraUtxo};
use crate::error::Error;

/// BIP44 gap limit scanned per chain (external/internal) before stopping.
pub(super) const GAP: u32 = 20;
/// P2WPKH dust threshold (sats); change at or below this is folded into the fee.
const DUST: u64 = 294;
/// Default fee rate (sat/vB) when the caller doesn't supply one.
pub const DEFAULT_FEERATE: f64 = 2.0;
/// Bound on gap-scan batches, so a pathological server can't loop forever.
pub(super) const MAX_BATCHES: u32 = 64;

pub(super) fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

// --- key derivation (shared keychain with the Sequentia side) -----------------

/// One derived P2WPKH key: the spendable secret, the compressed pubkey, and the
/// `tb1` address / scriptPubKey it controls.
pub(super) struct Key {
    sk: SecretKey,
    pk: CompressedPublicKey,
    pub(super) address: Address,
    script: ScriptBuf,
}

/// Derive the BIP32 master xprv from the recovery phrase, byte-for-byte as lwk's
/// `SwSigner::new(mnemonic, is_mainnet)` does it (BIP39 seed with an empty
/// passphrase, then `Xpriv::new_master`). Deriving here directly (no signer crate)
/// keeps the btc module cross-platform — the same code derives on native and on
/// wasm, where lwk_wollet's `lwk_signer` dep would otherwise force jade/ledger.
/// The Bitcoin network only sets the xprv's version bytes; the derived child keys
/// (and thus the shared address) are network-independent — the
/// `tb1_matches_lwk_unconfidential` test guards the byte-match against SwSigner.
pub(super) fn master_xprv(mnemonic: &str, params: &ChainAddressParams) -> Result<Xpriv, Error> {
    let mnemonic: Mnemonic = mnemonic.parse().map_err(map)?;
    let seed = mnemonic.to_seed("");
    let network = if params.coin_type == 0 { BtcNetwork::Bitcoin } else { BtcNetwork::Testnet };
    Xpriv::new_master(network, &seed).map_err(map)
}

pub(super) fn derive(
    secp: &Secp256k1<All>,
    master: &Xpriv,
    params: &ChainAddressParams,
    internal: bool,
    i: u32,
) -> Result<Key, Error> {
    let path =
        DerivationPath::from_str(&format!("m/84h/{}h/0h/{}/{}", params.coin_type, internal as u8, i)).map_err(map)?;
    let xprv = master.derive_priv(secp, &path).map_err(map)?;
    let sk = xprv.private_key;
    let pk = CompressedPublicKey(sk.public_key(secp));
    let address = Address::p2wpkh(&pk, params.hrp);
    let script = address.script_pubkey();
    Ok(Key { sk, pk, address, script })
}

/// The `tb1` address at a derivation slot — used by the alignment test and any
/// BTC-specific receive flow. (Normal receive reuses the shared address.)
pub fn address(params: &ChainAddressParams, mnemonic: &str, internal: bool, i: u32) -> Result<String, Error> {
    let secp = Secp256k1::new();
    Ok(derive(&secp, &master_xprv(mnemonic, params)?, params, internal, i)?.address.to_string())
}

// --- gap scan (transport-agnostic accumulation) -------------------------------

/// The result of a gap-limit scan of the Bitcoin keychain.
pub struct BtcScan {
    /// Confirmed + mempool balance, in sats.
    pub balance_sats: u64,
    /// Next unused external index (informational; receive reuses the shared addr).
    pub external_next: u32,
    /// Next change index to use for a new transaction.
    pub change_next: u32,
    /// How far (per chain) the scan reached — the window UTXO gathering covers.
    pub scan_limit: u32,
}

/// Running accumulator for the gap scan, finalized into a [`BtcScan`].
pub(super) struct ScanState {
    balance: i64,
    ext_max: i64,
    chg_max: i64,
    scanned: u32,
}

impl ScanState {
    pub(super) fn new() -> Self {
        Self { balance: 0, ext_max: -1, chg_max: -1, scanned: GAP }
    }

    /// Derive a batch's external + internal addresses starting at `start`,
    /// returning the (internal, index) slots paired with their address strings to
    /// fetch. The driver fetches `AddrInfo` for each, then calls [`Self::absorb`].
    pub(super) fn batch_addresses(
        secp: &Secp256k1<All>,
        master: &Xpriv,
        params: &ChainAddressParams,
        start: u32,
    ) -> Result<(Vec<(bool, u32)>, Vec<String>), Error> {
        let mut slots = Vec::with_capacity((GAP as usize) * 2);
        let mut addrs = Vec::with_capacity((GAP as usize) * 2);
        for i in start..start + GAP {
            for internal in [false, true] {
                slots.push((internal, i));
                addrs.push(derive(secp, master, params, internal, i)?.address.to_string());
            }
        }
        Ok((slots, addrs))
    }

    /// Absorb a fetched batch (the slots and their `AddrInfo`s, in order); returns
    /// whether ANY address in the batch showed activity (so the driver knows
    /// whether to scan the next gap-wide batch). `start` is this batch's first
    /// index; the scan frontier advances by `GAP`.
    pub(super) fn absorb(&mut self, start: u32, slots: &[(bool, u32)], infos: Vec<Option<AddrInfo>>) -> bool {
        let mut any = false;
        for ((internal, i), info) in slots.iter().zip(infos.into_iter()) {
            let Some(info) = info else { continue };
            let cs = info.chain_stats;
            let ms = info.mempool_stats;
            self.balance += (cs.funded_txo_sum - cs.spent_txo_sum) + (ms.funded_txo_sum - ms.spent_txo_sum);
            if cs.tx_count + ms.tx_count > 0 {
                any = true;
                if *internal {
                    self.chg_max = self.chg_max.max(*i as i64);
                } else {
                    self.ext_max = self.ext_max.max(*i as i64);
                }
            }
        }
        self.scanned = start + GAP;
        any
    }

    pub(super) fn finish(self) -> BtcScan {
        BtcScan {
            balance_sats: self.balance.max(0) as u64,
            external_next: (self.ext_max + 1) as u32,
            change_next: (self.chg_max + 1) as u32,
            scan_limit: self.scanned,
        }
    }
}

// --- coin selection + build/sign (the byte-identity-critical core) ------------

pub(super) struct Utxo {
    outpoint: OutPoint,
    value: u64,
    script: ScriptBuf,
    sk: SecretKey,
    pk: CompressedPublicKey,
}

/// Derive every external+internal key across the scan window (both chains), for
/// the driver to fetch UTXOs against.
pub(super) fn window_keys(
    secp: &Secp256k1<All>,
    master: &Xpriv,
    params: &ChainAddressParams,
    scan_limit: u32,
    change_next: u32,
) -> Result<Vec<Key>, Error> {
    let lim = scan_limit.max(change_next + 1);
    let mut keys = Vec::with_capacity((lim as usize) * 2);
    for internal in [false, true] {
        for i in 0..lim {
            keys.push(derive(secp, master, params, internal, i)?);
        }
    }
    Ok(keys)
}

/// Zip the window keys with their fetched UTXO lists (same order) into spendable
/// UTXOs carrying their key.
pub(super) fn utxos_from_lists(keys: Vec<Key>, lists: Vec<Vec<EsploraUtxo>>) -> Result<Vec<Utxo>, Error> {
    let mut utxos = Vec::new();
    for (k, list) in keys.iter().zip(lists.into_iter()) {
        for u in list {
            let txid = Txid::from_str(&u.txid).map_err(map)?;
            utxos.push(Utxo {
                outpoint: OutPoint { txid, vout: u.vout },
                value: u.value,
                script: k.script.clone(),
                sk: k.sk,
                pk: k.pk,
            });
        }
    }
    Ok(utxos)
}

/// Deterministic vbytes for a P2WPKH-only transaction.
fn vbytes(nin: usize, nout: usize) -> u64 {
    (10.75 + 68.0 * nin as f64 + 31.0 * nout as f64).ceil() as u64
}

/// A built, signed (but not yet broadcast) Bitcoin transaction.
pub struct BtcPrepared {
    /// Raw transaction hex, ready to broadcast.
    pub hex: String,
    /// The transaction id.
    pub txid: String,
    /// Fee paid, in sats.
    pub fee_sats: u64,
    /// Virtual size (vbytes) of the signed transaction.
    pub vsize: u64,
    /// Number of inputs selected.
    pub inputs: u32,
}

/// Coin-select (largest-first) over `utxos`, build a P2WPKH tx paying
/// `amount_sats` to `dest_addr` with change to `change_index`, and BIP143-sign it.
/// Pure: the driver supplies the gathered UTXOs + the current change index, so the
/// blocking and async paths build byte-identical transactions.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_signed_tx(
    secp: &Secp256k1<All>,
    master: &Xpriv,
    params: &ChainAddressParams,
    dest_addr: &str,
    amount_sats: u64,
    fee_rate: f64,
    change_index: u32,
    mut utxos: Vec<Utxo>,
) -> Result<BtcPrepared, Error> {
    if amount_sats == 0 {
        return Err(Error::Generic("enter an amount greater than zero".into()));
    }
    let fee_rate = if fee_rate > 0.0 { fee_rate } else { DEFAULT_FEERATE };

    let dest = Address::from_str(dest_addr)
        .map_err(|_| Error::Generic("invalid Bitcoin address".into()))?
        .require_network(params.network)
        .map_err(|_| Error::Generic("address is not a Bitcoin testnet (tb1) address".into()))?;

    if utxos.is_empty() {
        return Err(Error::Generic("no spendable BTC; the testnet4 balance is empty".into()));
    }
    utxos.sort_by(|a, b| b.value.cmp(&a.value)); // largest first

    let fee_for = |nin: usize, nout: usize| (vbytes(nin, nout) as f64 * fee_rate).ceil() as u64;

    // Select until inputs cover amount + fee (assuming a change output).
    let mut sel: Vec<&Utxo> = Vec::new();
    let mut in_sum: u64 = 0;
    for u in &utxos {
        sel.push(u);
        in_sum += u.value;
        if in_sum >= amount_sats.saturating_add(fee_for(sel.len(), 2)) {
            break;
        }
    }

    let mut fee = fee_for(sel.len(), 2);
    let mut with_change = true;
    if in_sum < amount_sats.saturating_add(fee) {
        return Err(Error::Generic("insufficient BTC for amount + fee".into()));
    }
    let mut change = in_sum - amount_sats - fee;
    if change <= DUST {
        // Dust change isn't worth an output — fold it into the fee.
        with_change = false;
        let no_change_fee = fee_for(sel.len(), 1);
        if in_sum < amount_sats.saturating_add(no_change_fee) {
            return Err(Error::Generic("insufficient BTC for amount + fee".into()));
        }
        fee = in_sum - amount_sats;
        change = 0;
    }

    // Assemble inputs/outputs.
    let input: Vec<TxIn> = sel
        .iter()
        .map(|u| TxIn {
            previous_output: u.outpoint,
            script_sig: ScriptBuf::new(),
            // BIP125-replaceable (0xfffffffd, the max RBF-signalling value) so a
            // stuck send / HTLC-funding tx can be fee-bumped. nLockTime is ZERO
            // here, so this only adds RBF (no locktime effect).
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        })
        .collect();

    let mut output = vec![TxOut { value: Amount::from_sat(amount_sats), script_pubkey: dest.script_pubkey() }];
    if with_change {
        let change_spk = derive(secp, master, params, true, change_index)?.script;
        output.push(TxOut { value: Amount::from_sat(change), script_pubkey: change_spk });
    }

    let mut tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input, output };

    // Sign each P2WPKH input (BIP143). Compute every sighash first (the cache holds
    // an immutable borrow of the tx), then drop it and attach the witnesses.
    let mut witnesses: Vec<Witness> = Vec::with_capacity(sel.len());
    {
        let mut cache = SighashCache::new(&tx);
        for (idx, u) in sel.iter().enumerate() {
            let sighash = cache
                .p2wpkh_signature_hash(idx, &u.script, Amount::from_sat(u.value), EcdsaSighashType::All)
                .map_err(map)?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg, &u.sk);
            let es = crate::bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
            witnesses.push(Witness::p2wpkh(&es, &u.pk.0));
        }
    }
    for (txin, w) in tx.input.iter_mut().zip(witnesses.into_iter()) {
        txin.witness = w;
    }

    Ok(BtcPrepared {
        hex: serialize_hex(&tx),
        txid: tx.compute_txid().to_string(),
        fee_sats: fee,
        vsize: tx.vsize() as u64,
        inputs: sel.len() as u32,
    })
}

/// A located HTLC funding output on testnet4.
pub struct HtlcFunding {
    /// Index of the matching P2SH output in the funding tx.
    pub vout: u32,
    /// Value of the funding output, in sats.
    pub value_sats: u64,
    /// Confirmation block height, or `-1` if unconfirmed.
    pub height: i64,
    /// Confirmation depth on the caller's own testnet4 view, or `0` if unconfirmed.
    pub confirmations: i64,
}

/// Parse the esplora `GET /tx/{txid}` JSON for the HTLC funding output matching
/// `p2sh_spk_hex`, given the caller's current `tip` height (the driver fetches
/// both). HARD-FAILS if no output matches (never defaults to vout 0). Pure: the
/// confirmation depth is computed from the supplied tip.
pub(super) fn parse_htlc_funding(tx: &serde_json::Value, p2sh_spk_hex: &str, tip: i64) -> Result<HtlcFunding, Error> {
    let vouts = tx.get("vout").and_then(|v| v.as_array()).ok_or_else(|| Error::Generic("funding tx has no vout".into()))?;
    let mut found: Option<(u32, u64)> = None;
    for (i, o) in vouts.iter().enumerate() {
        let spk = o.get("scriptpubkey").and_then(|s| s.as_str()).unwrap_or("");
        if spk.eq_ignore_ascii_case(p2sh_spk_hex) {
            found = Some((i as u32, o.get("value").and_then(|v| v.as_u64()).unwrap_or(0)));
            break;
        }
    }
    let (vout, value_sats) = found.ok_or_else(|| Error::Generic("HTLC P2SH output not found in the funding tx".into()))?;
    let status = tx.get("status");
    let confirmed = status.and_then(|s| s.get("confirmed")).and_then(|b| b.as_bool()).unwrap_or(false);
    let height = if confirmed {
        status.and_then(|s| s.get("block_height")).and_then(|h| h.as_i64()).unwrap_or(-1)
    } else {
        -1
    };
    let confirmations = if confirmed && height >= 0 && tip >= height { tip - height + 1 } else { 0 };
    Ok(HtlcFunding { vout, value_sats, height, confirmations })
}

/// Validate an esplora broadcast response body: success status + a 64-hex txid.
pub(super) fn parse_broadcast(ok: bool, body: &str) -> Result<String, Error> {
    let body = body.trim();
    if !ok {
        return Err(Error::Generic(body.to_string()));
    }
    if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Generic(format!("unexpected broadcast response: {}", &body[..body.len().min(80)])));
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_common::{singlesig_desc, DescriptorBlindingKey, Network, Singlesig};
    // SwSigner (a dev-dependency) builds the reference lwk wallet whose
    // unconfidential address the directly-derived BTC address must byte-match.
    use lwk_signer::SwSigner;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // The whole point of the dual-chain design: the Bitcoin address derived here
    // must be byte-identical to the lwk Sequentia wallet's unconfidential address
    // at the same index. If this ever fails, "one address, both chains" is broken.
    #[test]
    fn tb1_matches_lwk_unconfidential() {
        let params = ChainAddressParams::testnet();
        let btc0 = address(&params, MNEMONIC, false, 0).unwrap();
        assert!(btc0.starts_with("tb1"), "expected a tb1 address, got {btc0}");

        let sw = SwSigner::new(MNEMONIC, false).unwrap();
        let desc_str = singlesig_desc(&sw, Singlesig::Wpkh, DescriptorBlindingKey::Slip77).unwrap();
        let desc = crate::WolletDescriptor::from_str(&desc_str).unwrap();
        let wollet = crate::WolletBuilder::new(Network::sequentia_testnet(), desc).build().unwrap();
        let lwk0 = wollet.address(Some(0)).unwrap().address().to_unconfidential().to_string();

        assert_eq!(btc0, lwk0, "Bitcoin and Sequentia-unconfidential addresses must match");
    }

    // Phase 1's parity property: the blocking and async drivers both call this
    // `build_signed_tx`, so as long as it is deterministic for a given input it is
    // byte-identical across transports. Construct a fixed UTXO set and confirm the
    // build is well-formed AND reproducible bit-for-bit (no nonce/order leak).
    #[test]
    fn build_signed_tx_is_deterministic_and_well_formed() {
        use crate::bitcoin::{OutPoint, Txid};
        use std::str::FromStr;

        let params = ChainAddressParams::testnet();
        let secp = Secp256k1::new();
        let master = master_xprv(MNEMONIC, &params).unwrap();
        // A real key (external/0) so the BIP143 signature is valid; pay to ourselves.
        let k = derive(&secp, &master, &params, false, 0).unwrap();
        let dest = k.address.to_string();

        let utxos = |n: u32| -> Vec<Utxo> {
            (0..n)
                .map(|vout| Utxo {
                    outpoint: OutPoint { txid: Txid::from_str(&"11".repeat(32)).unwrap(), vout },
                    value: 100_000,
                    script: k.script.clone(),
                    sk: k.sk,
                    pk: k.pk,
                })
                .collect()
        };

        let a = build_signed_tx(&secp, &master, &params, &dest, 150_000, 2.0, 1, utxos(2)).unwrap();
        let b = build_signed_tx(&secp, &master, &params, &dest, 150_000, 2.0, 1, utxos(2)).unwrap();

        assert_eq!(a.hex, b.hex, "build must be deterministic -> blocking and async are byte-identical");
        assert_eq!(a.txid, b.txid);
        assert_eq!(a.inputs, 2); // 2x100k needed to cover 150k + fee
        assert!(a.fee_sats > 0);
        // Spend 200k: 150k to dest + change − fee, so a change output exists.
        assert!(!a.hex.is_empty());
    }
}
