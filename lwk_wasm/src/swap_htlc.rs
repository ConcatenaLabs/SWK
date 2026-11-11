//! Swap-htlc wasm bindings: the Sequentia side of a restricted (OpenAMP) asset
//! traded for on-chain BTC (`lwk_wollet::swap_htlc`).
//!
//! The wallet derives every HTLC and pot script itself from the terms, never
//! from a server's word, and compares them with the outputs it is about to
//! claim. Signing stays on [`crate::Signer`]: the buyer recomputes each claim
//! input's sighash with `enclaveSighash` and signs it with `openampSignSighash`;
//! the secret comes from `swapSecret`, derived from the seed so a restored
//! wallet can still claim.

use lwk_wollet::elements;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::swap_htlc as se;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::Error;

fn hex32(s: &str, what: &str) -> Result<[u8; 32], Error> {
    Vec::<u8>::from_hex(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Error::Generic(format!("{what} must be 32 bytes of hex")))
}

fn xonly(s: &str, what: &str) -> Result<XOnlyPublicKey, Error> {
    XOnlyPublicKey::from_slice(&hex32(s, what)?).map_err(|e| Error::Generic(format!("{what}: {e}")))
}

fn asset(s: &str, what: &str) -> Result<elements::AssetId, Error> {
    use std::str::FromStr;
    elements::AssetId::from_str(s).map_err(|e| Error::Generic(format!("{what} asset id: {e}")))
}

/// The HTLC's terms, as the web wallet holds them. Asset ids are display hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HtlcTermsJson {
    hash: String,
    buyer_x: String,
    policy_x: String,
    #[serde(default)]
    issuer_x: Option<String>,
    t_seq: u32,
    seller_program: String,
    asset: String,
    value: u64,
}

impl HtlcTermsJson {
    fn terms(&self) -> Result<se::SwapHtlcTerms, Error> {
        Ok(se::SwapHtlcTerms {
            hash: hex32(&self.hash, "hash")?,
            buyer: xonly(&self.buyer_x, "buyerX")?,
            policy: xonly(&self.policy_x, "policyX")?,
            issuer: match &self.issuer_x {
                Some(s) if !s.is_empty() => Some(xonly(s, "issuerX")?),
                _ => None,
            },
            t_seq: self.t_seq,
            seller_program: hex32(&self.seller_program, "sellerProgram")?,
            asset: asset(&self.asset, "the HTLC's")?,
            value: self.value,
        })
    }
}

/// The fee pot's terms. The asset id is display hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PotTermsJson {
    hash: String,
    buyer_x: String,
    t_seq: u32,
    seller_version: u8,
    seller_program: String,
    fee_asset: String,
    value: u64,
}

impl PotTermsJson {
    fn terms(&self) -> Result<se::FeePotTerms, Error> {
        Ok(se::FeePotTerms {
            hash: hex32(&self.hash, "hash")?,
            buyer: xonly(&self.buyer_x, "buyerX")?,
            t_seq: self.t_seq,
            seller_version: self.seller_version,
            seller_program: Vec::<u8>::from_hex(&self.seller_program)
                .map_err(|e| Error::Generic(format!("sellerProgram: {e}")))?,
            fee_asset: asset(&self.fee_asset, "the pot's")?,
            value: self.value,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LeafJson {
    name: String,
    script: String,
    control: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TreeJson {
    script_pubkey: String,
    leaves: Vec<LeafJson>,
}

fn tree_json(t: &se::SwapTree) -> TreeJson {
    TreeJson {
        script_pubkey: t.script_pubkey.to_hex(),
        leaves: t
            .leaves
            .iter()
            .map(|(n, s, c)| LeafJson {
                name: n.clone(),
                script: s.to_hex(),
                control: c.to_hex(),
            })
            .collect(),
    }
}

/// The swap HTLC for these terms: `{scriptPubkey, leaves: [{name, script,
/// control}]}`. A wallet compares `scriptPubkey` with the output it claims.
#[wasm_bindgen(js_name = swapHtlcTree)]
pub fn swap_htlc_tree(terms: JsValue) -> Result<JsValue, Error> {
    let t: HtlcTermsJson = serde_wasm_bindgen::from_value(terms)?;
    let tree = se::swap_htlc_tree(&t.terms()?)?;
    Ok(serde_wasm_bindgen::to_value(&tree_json(&tree))?)
}

/// The fee pot for these terms, in the same shape as [`swap_htlc_tree`].
#[wasm_bindgen(js_name = swapFeePotTree)]
pub fn swap_fee_pot_tree(terms: JsValue) -> Result<JsValue, Error> {
    let t: PotTermsJson = serde_wasm_bindgen::from_value(terms)?;
    let tree = se::fee_pot_tree(&t.terms()?)?;
    Ok(serde_wasm_bindgen::to_value(&tree_json(&tree))?)
}

/// `SHA256(secret)`, hex.
#[wasm_bindgen(js_name = swapSecretHash)]
pub fn swap_secret_hash(secret_hex: &str) -> Result<String, Error> {
    Ok(se::secret_hash(&hex32(secret_hex, "secret")?).to_hex())
}

/// The claim cut-off before `T_seq`, in seconds. A wallet never broadcasts a
/// claim at or after `T_seq` minus this.
#[wasm_bindgen(js_name = swapClaimCutoffSeconds)]
pub fn swap_claim_cutoff_seconds() -> u32 {
    se::CLAIM_CUTOFF_SECS
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimRecipe {
    htlc_txid: String,
    htlc_vout: u32,
    htlc: HtlcTermsJson,
    buyer_enclave_spk: String,
    pot_txid: String,
    pot_vout: u32,
    pot: PotTermsJson,
    buyer_change_spk: String,
    fee: u64,
}

fn outpoint(txid: &str, vout: u32) -> Result<elements::OutPoint, Error> {
    use std::str::FromStr;
    Ok(elements::OutPoint::new(
        elements::Txid::from_str(txid).map_err(|e| Error::Generic(format!("txid: {e}")))?,
        vout,
    ))
}

fn spk(s: &str, what: &str) -> Result<elements::Script, Error> {
    Ok(elements::Script::from(
        Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("{what}: {e}")))?,
    ))
}

/// The buyer's claim, unsigned, as transaction hex: the HTLC and its pot in,
/// the HTLC's whole amount to the buyer's enclave, the pot less the fee to
/// the buyer's own address, and the fee out.
#[wasm_bindgen(js_name = swapBuildClaim)]
pub fn swap_build_claim(recipe: JsValue) -> Result<String, Error> {
    let r: ClaimRecipe = serde_wasm_bindgen::from_value(recipe)?;
    let tx = se::claim_tx(
        outpoint(&r.htlc_txid, r.htlc_vout)?,
        &r.htlc.terms()?,
        spk(&r.buyer_enclave_spk, "buyerEnclaveSpk")?,
        outpoint(&r.pot_txid, r.pot_vout)?,
        &r.pot.terms()?,
        spk(&r.buyer_change_spk, "buyerChangeSpk")?,
        r.fee,
    )?;
    Ok(elements::encode::serialize_hex(&tx))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpentJson {
    script_pubkey: String,
    asset: String,
    value: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinishRecipe {
    tx: String,
    htlc: HtlcTermsJson,
    pot: PotTermsJson,
    /// The HTLC's output and the pot's output as read from the chain, in that order.
    spent: Vec<SpentJson>,
    buyer_enclave_spk: String,
    /// The chain's genesis block hash (display hex).
    genesis_hash: String,
    /// The later of the wallet's clock and the chain's median time past.
    now: u32,
    secret: String,
    policy_sig: String,
    buyer_sig_htlc: String,
    buyer_sig_pot: String,
}

/// Completes a claim from [`swap_build_claim`] with the policy signature, the
/// buyer's two signatures and the secret. Before it places the secret it
/// refuses a claim at or after the cut-off, a secret of another hash, spent
/// coins that are not the HTLC and pot the terms build, a claim that does not
/// pay the HTLC's whole amount to the buyer's enclave, and any signature that
/// does not verify over the claim.
#[wasm_bindgen(js_name = swapFinishClaim)]
pub fn swap_finish_claim(recipe: JsValue) -> Result<String, Error> {
    use std::str::FromStr;
    let r: FinishRecipe = serde_wasm_bindgen::from_value(recipe)?;
    let tx: elements::Transaction = elements::encode::deserialize(
        &Vec::<u8>::from_hex(&r.tx).map_err(|e| Error::Generic(format!("tx hex: {e}")))?,
    )
    .map_err(|e| Error::Generic(format!("tx decode: {e}")))?;
    let sig = |s: &str, what: &str| {
        Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("{what}: {e}")))
    };
    let spent = r
        .spent
        .iter()
        .map(|o| {
            Ok(elements::TxOut {
                asset: elements::confidential::Asset::Explicit(asset(&o.asset, "spent asset")?),
                value: elements::confidential::Value::Explicit(o.value),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: spk(&o.script_pubkey, "spent scriptPubkey")?,
                witness: elements::TxOutWitness::default(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let (ht, pt) = (r.htlc.terms()?, r.pot.terms()?);
    let enclave = spk(&r.buyer_enclave_spk, "buyerEnclaveSpk")?;
    let check = se::ClaimCheck {
        htlc: &ht,
        pot: &pt,
        spent: &spent,
        buyer_enclave: &enclave,
        genesis_hash: elements::BlockHash::from_str(&r.genesis_hash)
            .map_err(|e| Error::Generic(format!("genesisHash: {e}")))?,
        now: r.now,
    };
    let done = se::finish_claim(
        tx,
        &check,
        &hex32(&r.secret, "secret")?,
        &sig(&r.policy_sig, "policySig")?,
        &sig(&r.buyer_sig_htlc, "buyerSigHtlc")?,
        &sig(&r.buyer_sig_pot, "buyerSigPot")?,
    )?;
    Ok(elements::encode::serialize_hex(&done))
}

/// The secret a claim of `hash` revealed, hex, or `undefined` if the
/// transaction carries none.
#[wasm_bindgen(js_name = swapExtractSecret)]
pub fn swap_extract_secret(tx_hex: &str, hash_hex: &str) -> Result<Option<String>, Error> {
    let tx: elements::Transaction = elements::encode::deserialize(
        &Vec::<u8>::from_hex(tx_hex).map_err(|e| Error::Generic(format!("tx hex: {e}")))?,
    )
    .map_err(|e| Error::Generic(format!("tx decode: {e}")))?;
    Ok(se::extract_secret(&tx, &hex32(hash_hex, "hash")?).map(|s| s.to_hex()))
}

/// A gated order's terms, as the web wallet holds them. The asset id is
/// display hex; `fill` is the SeqDEX fill covenant (hex) the order wraps.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatedTermsJson {
    policy_x: String,
    fill: String,
    #[serde(default)]
    issuer_x: Option<String>,
    expiry: u32,
    maker_program: String,
    asset: String,
}

/// A gated order (a resting offer to sell a restricted asset) for these
/// terms: `{scriptPubkey, leaves: [{name, script, control}]}`, the same shape
/// as [`swap_htlc_tree`]. A taker fills it as an ordinary SeqDEX order with
/// the `fill` leaf and its control block (`buildCovenantFillTx`), paying the
/// asset to its own enclave, and hands the transaction to the policy server
/// with `order_inputs` and `"broadcast": true`; the server completes the order
/// input's witness and broadcasts.
#[wasm_bindgen(js_name = gatedOrderTree)]
pub fn gated_order_tree(terms: JsValue) -> Result<JsValue, Error> {
    let t: GatedTermsJson = serde_wasm_bindgen::from_value(terms)?;
    let terms = lwk_wollet::gated_order::GatedOrderTerms {
        policy: xonly(&t.policy_x, "policyX")?,
        fill: Vec::<u8>::from_hex(&t.fill).map_err(|e| Error::Generic(format!("fill: {e}")))?,
        issuer: match &t.issuer_x {
            Some(s) if !s.is_empty() => Some(xonly(s, "issuerX")?),
            _ => None,
        },
        expiry: t.expiry,
        maker_program: hex32(&t.maker_program, "makerProgram")?,
        asset: asset(&t.asset, "the order's")?,
    };
    let tree = lwk_wollet::gated_order::gated_order_tree(&terms)?;
    Ok(serde_wasm_bindgen::to_value(&tree_json(&tree))?)
}
