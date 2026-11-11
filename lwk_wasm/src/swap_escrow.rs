//! Swap-escrow wasm bindings: the Sequentia side of a restricted (OpenAMP) asset
//! traded for on-chain BTC (`lwk_wollet::swap_escrow`).
//!
//! The wallet derives every escrow and pot script itself from the terms, never
//! from a server's word, and compares them with the outputs it is about to
//! claim. Signing stays on [`crate::Signer`]: the buyer recomputes each claim
//! input's sighash with `enclaveSighash` and signs it with `openampSignSighash`;
//! the secret comes from `swapSecret`, derived from the seed so a restored
//! wallet can still claim.

use lwk_wollet::elements;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::swap_escrow as se;
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

/// The escrow's terms, as the web wallet holds them. Asset ids are display hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EscrowTermsJson {
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

impl EscrowTermsJson {
    fn terms(&self) -> Result<se::SwapEscrowTerms, Error> {
        Ok(se::SwapEscrowTerms {
            hash: hex32(&self.hash, "hash")?,
            buyer: xonly(&self.buyer_x, "buyerX")?,
            policy: xonly(&self.policy_x, "policyX")?,
            issuer: match &self.issuer_x {
                Some(s) if !s.is_empty() => Some(xonly(s, "issuerX")?),
                _ => None,
            },
            t_seq: self.t_seq,
            seller_program: hex32(&self.seller_program, "sellerProgram")?,
            asset: asset(&self.asset, "the escrow's")?,
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

/// The swap escrow for these terms: `{scriptPubkey, leaves: [{name, script,
/// control}]}`. A wallet compares `scriptPubkey` with the output it claims.
#[wasm_bindgen(js_name = swapEscrowTree)]
pub fn swap_escrow_tree(terms: JsValue) -> Result<JsValue, Error> {
    let t: EscrowTermsJson = serde_wasm_bindgen::from_value(terms)?;
    let tree = se::swap_escrow_tree(&t.terms()?)?;
    Ok(serde_wasm_bindgen::to_value(&tree_json(&tree))?)
}

/// The fee pot for these terms, in the same shape as [`swap_escrow_tree`].
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
    escrow_txid: String,
    escrow_vout: u32,
    escrow: EscrowTermsJson,
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

/// The buyer's claim, unsigned, as transaction hex: the escrow and its pot in,
/// the escrow's whole amount to the buyer's enclave, the pot less the fee to
/// the buyer's own address, and the fee out.
#[wasm_bindgen(js_name = swapBuildClaim)]
pub fn swap_build_claim(recipe: JsValue) -> Result<String, Error> {
    let r: ClaimRecipe = serde_wasm_bindgen::from_value(recipe)?;
    let tx = se::claim_tx(
        outpoint(&r.escrow_txid, r.escrow_vout)?,
        &r.escrow.terms()?,
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
struct FinishRecipe {
    tx: String,
    escrow: EscrowTermsJson,
    pot: PotTermsJson,
    secret: String,
    policy_sig: String,
    buyer_sig_escrow: String,
    buyer_sig_pot: String,
}

/// Completes a claim from [`swap_build_claim`] with the policy signature, the
/// buyer's two signatures and the secret. Refuses a secret that does not hash
/// to the escrow's `H`.
#[wasm_bindgen(js_name = swapFinishClaim)]
pub fn swap_finish_claim(recipe: JsValue) -> Result<String, Error> {
    let r: FinishRecipe = serde_wasm_bindgen::from_value(recipe)?;
    let tx: elements::Transaction = elements::encode::deserialize(
        &Vec::<u8>::from_hex(&r.tx).map_err(|e| Error::Generic(format!("tx hex: {e}")))?,
    )
    .map_err(|e| Error::Generic(format!("tx decode: {e}")))?;
    let et = r.escrow.terms()?;
    let sig = |s: &str, what: &str| {
        Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("{what}: {e}")))
    };
    let done = se::finish_claim(
        tx,
        &se::swap_escrow_tree(&et)?,
        &se::fee_pot_tree(&r.pot.terms()?)?,
        &hex32(&r.secret, "secret")?,
        &et.hash,
        &sig(&r.policy_sig, "policySig")?,
        &sig(&r.buyer_sig_escrow, "buyerSigEscrow")?,
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
