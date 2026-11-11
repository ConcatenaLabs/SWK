//! Sequentia SeqOB passive-CLOB covenant — wasm bindings for the web wallet.
//!
//! This is the terminal piece the browser wallet could not build from JS: the raw
//! Elements FILL transaction that carries the covenant's taproot **script-path**
//! witness (no signature) at input 0, the taker's own **key-path** funding inputs
//! signed from the seed, and the explicit maker-credit / remainder / receipt /
//! change / fee outputs in the consensus-fixed order. Everything the wallet feeds
//! in — the FILL leaf, control block, maker credit, remainder — is already derived
//! and byte-verified by `covenant.js` / `covenant-order.js` (pinned to the Go
//! module and the regtest-proven Python builders). This binding just assembles and
//! signs, mirroring [`crate::seqdex_htlc::build_seq_htlc_claim_tx`].
//!
//! It also exposes [`covenant_maker_address`], the BIP86 taproot receive address +
//! its 32-byte `maker_prog` a maker needs to place an order and later be paid.

use std::str::FromStr;

use lwk_wollet::bitcoin::bip32;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::{
    build_covenant_fill_tx, build_covenant_refund_tx, covenant_secret_from_hex,
    maker_payout_program, CovenantFillPlan, CovenantInput, CovenantRefundInput, CovenantRefundPlan,
    FillCredit, FillRemainder, TakerFundingInput,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Error, Network, Signer};

/// One taker-owned funding UTXO, as reported by the wollet's UTXO list.
///
/// `chain` is 0 (external) or 1 (internal/change) and `index` is the wildcard
/// index — together the wallet derivation coordinates `m/84'/coin'/0'/chain/index`
/// used to re-derive the signing key. Amounts are decimal strings (u64-safe).
#[derive(Deserialize)]
struct TakerUtxoJson {
    txid: String,
    vout: u32,
    value: String,
    asset: String,
    #[serde(alias = "spkHex", alias = "spk")]
    spk_hex: String,
    chain: u32,
    index: u32,
}

/// The FILL recipe JS assembles (`planFillFromMatched`) merged with the wallet's
/// funding selection. Byte-exact fields (`fillLeafHex`, `controlBlockHex`,
/// `creditProg`, `remainderSpkHex`) come straight from `covenant.js`. Amount fields
/// are decimal strings to survive JS' 2^53 number limit.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CovenantFillRecipeJson {
    covenant_txid: String,
    covenant_vout: u32,
    covenant_asset: String,
    covenant_locked: String,
    fill_leaf_hex: String,
    control_block_hex: String,

    credit_asset: String,
    credit_prog: String,
    #[serde(default = "default_credit_ver")]
    credit_prog_ver: u8,
    credit_value: String,

    #[serde(default)]
    partial: bool,
    #[serde(default)]
    remainder_asset: Option<String>,
    #[serde(default)]
    remainder_value: Option<String>,
    #[serde(default)]
    remainder_spk_hex: Option<String>,

    taker_funding_utxos: Vec<TakerUtxoJson>,
    taker_receipt_addr: String,
    taker_change_addr: String,
    fee_atoms: String,
    fee_asset: String,
    mnemonic: String,
}

fn default_credit_ver() -> u8 {
    1
}

/// The built FILL tx: raw Elements hex ready for `sendrawtransaction`, plus its txid.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltFillTx {
    raw_hex: String,
    txid: String,
}

fn parse_u64(s: &str, what: &str) -> Result<u64, Error> {
    s.parse::<u64>()
        .map_err(|e| Error::Generic(format!("invalid {what} '{s}': {e}")))
}

fn parse_asset(s: &str, what: &str) -> Result<lwk_wollet::elements::AssetId, Error> {
    use std::str::FromStr;
    lwk_wollet::elements::AssetId::from_str(s)
        .map_err(|e| Error::Generic(format!("invalid {what} asset '{s}': {e}")))
}

fn parse_addr(s: &str, what: &str) -> Result<lwk_wollet::elements::Address, Error> {
    use std::str::FromStr;
    lwk_wollet::elements::Address::from_str(s)
        .map_err(|e| Error::Generic(format!("invalid {what} address '{s}': {e}")))
}

fn hexbytes(s: &str, what: &str) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid {what} hex: {e}")))
}

/// Assemble, sign, and serialize the covenant FILL transaction in-browser.
///
/// Takes the JS FILL recipe (see [`CovenantFillRecipeJson`]) merged with the
/// wallet's funding selection and recovery phrase. The covenant input at index 0
/// carries the introspection-only `[leaf, control_block]` witness (NO signature);
/// each taker funding UTXO is re-derived at `m/84'/coin'/0'/chain/index` and signed
/// key-path (p2wpkh, segwit-v0 SIGHASH_ALL). Outputs are explicit and placed in the
/// covenant's fixed order (credit at 0, remainder/gap at 1). Returns
/// `{ rawHex, txid }`.
#[wasm_bindgen(js_name = buildCovenantFillTx)]
pub fn build_covenant_fill_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: CovenantFillRecipeJson = serde_wasm_bindgen::from_value(recipe)?;

    // Re-derive the taker signing keys from the seed, at the BIP84 account's
    // coin type as in lwk_common::singlesig_desc.
    let signer = crate::Signer::new(&crate::Mnemonic::new(&r.mnemonic)?, network)?;
    let coin: u32 = lwk_common::bip44_coin_type(network.is_mainnet());

    let mut taker_inputs = Vec::with_capacity(r.taker_funding_utxos.len());
    for u in &r.taker_funding_utxos {
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Hardened { index: 84 },
            bip32::ChildNumber::Hardened { index: coin },
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Normal { index: u.chain },
            bip32::ChildNumber::Normal { index: u.index },
        ]);
        let xprv = signer
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(format!("derive taker key: {e}")))?;
        let secret_hex = xprv.private_key.secret_bytes().to_hex();
        let secret_key = covenant_secret_from_hex(&secret_hex)?;
        taker_inputs.push(TakerFundingInput {
            txid: u.txid.clone(),
            vout: u.vout,
            value: parse_u64(&u.value, "taker utxo value")?,
            asset: parse_asset(&u.asset, "taker utxo")?,
            spk: hexbytes(&u.spk_hex, "taker utxo spk")?,
            secret_key,
        });
    }

    let remainder = if r.partial {
        Some(FillRemainder {
            asset: parse_asset(
                r.remainder_asset
                    .as_deref()
                    .ok_or_else(|| Error::Generic("partial fill missing remainderAsset".into()))?,
                "remainder",
            )?,
            value: parse_u64(
                r.remainder_value
                    .as_deref()
                    .ok_or_else(|| Error::Generic("partial fill missing remainderValue".into()))?,
                "remainderValue",
            )?,
            spk: hexbytes(
                r.remainder_spk_hex
                    .as_deref()
                    .ok_or_else(|| Error::Generic("partial fill missing remainderSpkHex".into()))?,
                "remainderSpk",
            )?,
        })
    } else {
        None
    };

    let plan = CovenantFillPlan {
        covenant: CovenantInput {
            txid: r.covenant_txid,
            vout: r.covenant_vout,
            asset: parse_asset(&r.covenant_asset, "covenant")?,
            locked: parse_u64(&r.covenant_locked, "covenantLocked")?,
            fill_leaf: hexbytes(&r.fill_leaf_hex, "fillLeaf")?,
            control_block: hexbytes(&r.control_block_hex, "controlBlock")?,
        },
        credit: FillCredit {
            asset: parse_asset(&r.credit_asset, "credit")?,
            program: hexbytes(&r.credit_prog, "creditProg")?,
            version: r.credit_prog_ver,
            value: parse_u64(&r.credit_value, "creditValue")?,
        },
        remainder,
        taker_inputs,
        receipt_addr: parse_addr(&r.taker_receipt_addr, "taker receipt")?,
        change_addr: parse_addr(&r.taker_change_addr, "taker change")?,
        fee_atoms: parse_u64(&r.fee_atoms, "feeAtoms")?,
        fee_asset: parse_asset(&r.fee_asset, "fee")?,
    };

    let (raw_hex, txid) = build_covenant_fill_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltFillTx {
        raw_hex,
        txid: txid.to_string(),
    })?)
}

/// The REFUND recipe JS assembles to reclaim an EXPIRED resting covenant order.
///
/// Byte-exact fields (`refundLeafHex`, `controlBlockHex`, `covenantSpkHex`) come
/// straight from `covenant.js` `deriveTaptree`. `makerKeyPath` is the BIP32 path
/// of the key the REFUND leaf commits to (the same `m/86'/coin'/0'/0/index`
/// `covenantMakerAddress` returned as `internalKey`); the helper derives that key
/// and signs the tapscript-path Schnorr signature with it. `genesisHex` is the
/// network genesis block hash (the Elements taproot sighash domain separator),
/// which JS fetches from the node (`/block-height/0`). Amounts are decimal strings.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CovenantRefundRecipeJson {
    covenant_txid: String,
    covenant_vout: u32,
    covenant_asset: String,
    covenant_locked: String,
    covenant_spk_hex: String,
    refund_leaf_hex: String,
    control_block_hex: String,
    expiry_locktime: u32,
    genesis_hex: String,

    maker_reclaim_addr: String,
    maker_key_path: String,

    fee_atoms: String,
    fee_asset: String,
    #[serde(default)]
    extra_fee_utxos: Vec<TakerUtxoJson>,
    change_addr: String,
    mnemonic: String,
}

/// Assemble, sign, and serialize the covenant REFUND transaction in-browser.
///
/// Takes the JS REFUND recipe (see [`CovenantRefundRecipeJson`]) plus the wallet's
/// recovery phrase. Input 0 is the covenant UTXO spent **script-path** via the
/// CLTV REFUND leaf: the tx `nLockTime` is set to `expiryLocktime`, the input's
/// `nSequence` enables locktime, the maker key derived at `makerKeyPath` signs the
/// BIP-341 tapscript sighash, and the witness is
/// `[maker_sig, refund_leaf, control_block]`. When the fee asset differs from the
/// covenant asset, `extraFeeUtxos` (the maker's own p2wpkh coins) fund the fee and
/// are signed key-path. Returns `{ rawHex, txid }`.
#[wasm_bindgen(js_name = buildCovenantRefundTx)]
pub fn build_covenant_refund_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    use lwk_wollet::elements::BlockHash;

    let r: CovenantRefundRecipeJson = serde_wasm_bindgen::from_value(recipe)?;

    let signer = crate::Signer::new(&crate::Mnemonic::new(&r.mnemonic)?, network)?;
    let coin: u32 = lwk_common::bip44_coin_type(network.is_mainnet());

    // The maker key the REFUND leaf commits to. `makerKeyPath` is the full BIP32
    // path (e.g. `m/86'/1'/0'/0/0`); its x-only pubkey must equal the leaf's
    // `maker_x`. The core builder re-checks the sig verifies against the leaf.
    let maker_path = bip32::DerivationPath::from_str(r.maker_key_path.trim_start_matches("m/"))
        .or_else(|_| bip32::DerivationPath::from_str(&r.maker_key_path))
        .map_err(|e| Error::Generic(format!("invalid makerKeyPath '{}': {e}", r.maker_key_path)))?;
    let maker_xprv = signer
        .inner
        .derive_xprv(&maker_path)
        .map_err(|e| Error::Generic(format!("derive maker key: {e}")))?;
    let maker_secret = covenant_secret_from_hex(&maker_xprv.private_key.secret_bytes().to_hex())?;

    // The maker's own p2wpkh fee-funding coins (only when the fee asset differs
    // from the covenant asset), re-derived at m/84'/coin'/0'/chain/index.
    let mut fee_inputs = Vec::with_capacity(r.extra_fee_utxos.len());
    for u in &r.extra_fee_utxos {
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Hardened { index: 84 },
            bip32::ChildNumber::Hardened { index: coin },
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Normal { index: u.chain },
            bip32::ChildNumber::Normal { index: u.index },
        ]);
        let xprv = signer
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(format!("derive fee key: {e}")))?;
        let secret_key = covenant_secret_from_hex(&xprv.private_key.secret_bytes().to_hex())?;
        fee_inputs.push(TakerFundingInput {
            txid: u.txid.clone(),
            vout: u.vout,
            value: parse_u64(&u.value, "fee utxo value")?,
            asset: parse_asset(&u.asset, "fee utxo")?,
            spk: hexbytes(&u.spk_hex, "fee utxo spk")?,
            secret_key,
        });
    }

    let genesis_hash = BlockHash::from_str(&r.genesis_hex)
        .map_err(|e| Error::Generic(format!("invalid genesisHex '{}': {e}", r.genesis_hex)))?;

    let plan = CovenantRefundPlan {
        covenant: CovenantRefundInput {
            txid: r.covenant_txid,
            vout: r.covenant_vout,
            asset: parse_asset(&r.covenant_asset, "covenant")?,
            locked: parse_u64(&r.covenant_locked, "covenantLocked")?,
            spk: hexbytes(&r.covenant_spk_hex, "covenantSpk")?,
            refund_leaf: hexbytes(&r.refund_leaf_hex, "refundLeaf")?,
            control_block: hexbytes(&r.control_block_hex, "controlBlock")?,
            maker_secret,
        },
        expiry_locktime: r.expiry_locktime,
        reclaim_addr: parse_addr(&r.maker_reclaim_addr, "maker reclaim")?,
        fee_atoms: parse_u64(&r.fee_atoms, "feeAtoms")?,
        fee_asset: parse_asset(&r.fee_asset, "fee")?,
        fee_inputs,
        change_addr: parse_addr(&r.change_addr, "change")?,
        genesis_hash,
    };

    let (raw_hex, txid) = build_covenant_refund_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltFillTx {
        raw_hex,
        txid: txid.to_string(),
    })?)
}

/// A maker taproot payout address + its covenant `maker_prog`.
///
/// JS shape: `{ program (32-byte x-only hex), spkHex, address, internalKey, path }`.
/// `program` is what goes into the offer's `maker_prog`; `spkHex` is the exact
/// `OP_1 <program>` scriptPubKey the FILL credit pays; `address` is the unblinded
/// (transparent, Sequentia-default) BIP86 taproot receive address.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MakerAddressJson {
    program: String,
    spk_hex: String,
    address: String,
    internal_key: String,
    path: String,
}

#[wasm_bindgen]
impl Signer {
    /// Derive a BIP86 taproot maker-payout address + its 32-byte `maker_prog`.
    ///
    /// The covenant FILL leaf pins a v1-taproot maker payout, so a maker placing an
    /// order needs a taproot (witness v1) receive address it CONTROLS, and that
    /// output key's 32 bytes are the `maker_prog` baked into the order. This derives
    /// `m/86'/coin'/0'/0/index` and returns `{ program, spkHex, address, internalKey,
    /// path }`. The program uses the ELEMENTS TapTweak, so it matches an `eltr`
    /// (BIP86) LWK descriptor: a companion `Wollet` built from that descriptor
    /// watches and key-path-spends the credit (see `covenantMakerDescriptor`).
    #[wasm_bindgen(js_name = covenantMakerAddress)]
    pub fn covenant_maker_address(
        &self,
        network: &Network,
        index: u32,
    ) -> Result<JsValue, Error> {
        use lwk_wollet::bitcoin::secp256k1::Secp256k1;
        let coin: u32 = lwk_common::bip44_coin_type(network.is_mainnet());
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Hardened { index: 86 },
            bip32::ChildNumber::Hardened { index: coin },
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Normal { index: 0 },
            bip32::ChildNumber::Normal { index },
        ]);
        let xprv = self
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(format!("derive maker key: {e}")))?;
        let secp = Secp256k1::signing_only();
        let (internal, _parity) = xprv.private_key.public_key(&secp).x_only_public_key();

        let (program, spk) = maker_payout_program(internal)?;

        // Build the (unblinded) taproot address from the output-key witness program.
        let script = lwk_wollet::elements::Script::from(spk.clone());
        let params = address_params(network);
        let address = lwk_wollet::elements::Address::from_script(&script, None, params)
            .ok_or_else(|| Error::Generic("cannot form taproot address from program".into()))?;

        Ok(serde_wasm_bindgen::to_value(&MakerAddressJson {
            program: program.to_hex(),
            spk_hex: spk.to_hex(),
            address: address.to_string(),
            internal_key: internal.serialize().to_hex(),
            path: format!("m/86'/{coin}'/0'/0/{index}"),
        })?)
    }

    /// The `eltr` (BIP86) taproot descriptor a companion `Wollet` uses to WATCH and
    /// key-path-SPEND covenant maker-credit payouts. The wallet's primary descriptor
    /// is `wpkh` (BIP84) and does not track taproot receives, so the maker runs this
    /// second wollet to see the credits and sweep them. Confidential-blinded (the
    /// scriptPubKey is identical to the unblinded payout, so it still matches the
    /// explicit credit the covenant pays).
    #[wasm_bindgen(js_name = covenantMakerDescriptor)]
    pub fn covenant_maker_descriptor(&self) -> Result<crate::WolletDescriptor, Error> {
        let desc = lwk_common::singlesig_desc(
            &self.inner,
            lwk_common::Singlesig::Tr,
            lwk_common::DescriptorBlindingKey::Slip77,
        )
        .map_err(Error::Generic)?;
        crate::WolletDescriptor::new(&desc)
    }
}

/// Convert a scriptPubKey (hex) to an Elements address for the given network.
///
/// The maker order flow funds the covenant by paying an address; the covenant spk
/// is derived in JS (`covenant.js`), and this turns it into the address the wallet
/// sends to (`hooks.spkToAddress`). Returns the unblinded (transparent) address.
#[wasm_bindgen(js_name = scriptToAddress)]
pub fn script_to_address(spk_hex: &str, network: &Network) -> Result<String, Error> {
    let spk = lwk_wollet::elements::Script::from(hexbytes(spk_hex, "scriptPubKey")?);
    let params = address_params(network);
    let address = lwk_wollet::elements::Address::from_script(&spk, None, params)
        .ok_or_else(|| Error::Generic("scriptPubKey is not a standard address".into()))?;
    Ok(address.to_string())
}

fn address_params(network: &Network) -> &'static lwk_wollet::elements::AddressParams {
    use lwk_wollet::elements::AddressParams;
    if network.is_mainnet() {
        &AddressParams::LIQUID
    } else {
        // Sequentia testnet/regtest share Elements' bech32 HRP for the transparent
        // (default) address family used across the dual-chain wallet.
        &AddressParams::ELEMENTS
    }
}
