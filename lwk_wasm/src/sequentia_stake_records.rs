//! SEQUENTIA unbonding, for the browser and mobile wallets: a stake bonded to
//! the wallet's staking key (m/2/0, `Signer.stakerPublicKey()`) leaves in two
//! steps.
//!
//! 1. `buildUnbondTx` spends the staking outputs into one unbonding output of
//!    the same key, paying a fee of at most 1% of the stake out of it. The
//!    stake stops counting when this confirms. Each staking output can be
//!    spent once its own relative lock (the `csv` it was bonded with) has
//!    passed since it confirmed.
//! 2. `buildUnbondClaimTx` sends the unbonding output to an address once the
//!    parent chain (Bitcoin) has advanced the unbonding depth (2,016 blocks on
//!    the testnet) past the anchor of the block that confirmed step 1. The node
//!    refuses an earlier claim with `bad-unbond-premature`.
//!
//! Both are bare-script spends the wallet's PSET signer will not touch, signed
//! here with the staking key for the next block (`tipHeight`).

use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::sequentia_delegation::{delegation_pubkey_from_hex, delegation_txid_from_hex};
use lwk_wollet::sequentia_stake_records::{
    build_unbond_claim_tx, build_unbond_tx, sequentia_unbond_script, unbond_fee_cap, StakeOutput,
    UnbondClaimPlan, UnbondPlan, UnbondingOutput,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::sequentia_delegation::{
    address_script, atoms, record_signing, signing_name, staker_secret,
};
use crate::{Error, Network};

/// The canonical unbonding output script for a 33-byte hex staker key, as hex.
/// Cross-checked byte-for-byte against the node's `BuildUnbondScript`.
#[wasm_bindgen(js_name = sequentiaUnbondScript)]
pub fn sequentia_unbond_script_js(staker_pubkey: &str) -> Result<String, Error> {
    let pk = delegation_pubkey_from_hex(staker_pubkey, "staker")?;
    Ok(sequentia_unbond_script(&pk).as_bytes().to_hex())
}

/// The most unbonding may pay in fees out of a stake of `staked_atoms` (a
/// decimal string): 1%, rounded as the node rounds it. Returns a string.
#[wasm_bindgen(js_name = unbondFeeCap)]
pub fn unbond_fee_cap_js(staked_atoms: &str) -> Result<String, Error> {
    Ok(unbond_fee_cap(atoms(staked_atoms, "stakedAtoms")?).to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StakeJson {
    txid: String,
    vout: u32,
    /// Atoms, as a string.
    value: String,
    /// The staking output's script, hex, as found on chain.
    script: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnbondRecipeJson {
    mnemonic: String,
    /// The staking outputs to unbond, all bonded to the wallet's staking key.
    stakes: Vec<StakeJson>,
    /// Network fee in atoms, taken out of the stake (at most `unbondFeeCap`).
    fee_atoms: String,
    /// nLockTime, normally the current tip.
    locktime: u32,
    /// The chain tip the spend is built against; defaults to `locktime`.
    #[serde(default)]
    tip_height: Option<u32>,
    /// Overrides the network's fork height for a custom chain.
    #[serde(default)]
    records_v2_height: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltUnbondTx {
    raw_hex: String,
    txid: String,
    /// What the unbonding output (vout 0) holds, atoms, as a string.
    unbonding_value: String,
    /// The signature it carries: `"legacy"` or `"segwitV0"`.
    signing: &'static str,
}

/// Unbonding, step 1: spend the staking outputs into an unbonding output of
/// the same key (vout 0). Returns `{ rawHex, txid, unbondingValue, signing }`.
#[wasm_bindgen(js_name = buildUnbondTx)]
pub fn build_unbond_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: UnbondRecipeJson = serde_wasm_bindgen::from_value(recipe)?;
    let signing = record_signing(network, r.tip_height, r.locktime, r.records_v2_height)?;
    let mut stakes = Vec::with_capacity(r.stakes.len());
    for s in &r.stakes {
        stakes.push(StakeOutput {
            txid: delegation_txid_from_hex(&s.txid)?,
            vout: s.vout,
            value: atoms(&s.value, "stake value")?,
            script_pubkey: lwk_wollet::elements::Script::from(
                Vec::<u8>::from_hex(s.script.trim())
                    .map_err(|e| Error::Generic(format!("invalid staking script hex: {e}")))?,
            ),
        });
    }
    let total: u64 = stakes.iter().map(|s| s.value).sum();
    let plan = UnbondPlan {
        stakes,
        asset: network.policy_asset().into(),
        staker_secret: staker_secret(&r.mnemonic, network)?,
        fee_atoms: atoms(&r.fee_atoms, "feeAtoms")?,
        locktime: r.locktime,
        signing,
    };
    let (raw_hex, txid) = build_unbond_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltUnbondTx {
        raw_hex,
        txid: txid.to_string(),
        unbonding_value: total.saturating_sub(plan.fee_atoms).to_string(),
        signing: signing_name(signing),
    })?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnbondingJson {
    txid: String,
    vout: u32,
    /// Atoms, as a string.
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnbondClaimRecipeJson {
    mnemonic: String,
    /// The unbonding outputs to claim, all of the wallet's staking key.
    unbonding: Vec<UnbondingJson>,
    /// Where the coins go: an unblinded address of the wallet.
    address: String,
    /// Network fee in atoms, taken out of the coins claimed.
    fee_atoms: String,
    /// nLockTime, normally the current tip.
    locktime: u32,
    /// The chain tip the spend is built against; defaults to `locktime`.
    #[serde(default)]
    tip_height: Option<u32>,
    /// Overrides the network's fork height for a custom chain.
    #[serde(default)]
    records_v2_height: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltClaimTx {
    raw_hex: String,
    txid: String,
    /// What arrives at the address, atoms, as a string.
    out_value: String,
    /// The signature it carries: `"legacy"` or `"segwitV0"`.
    signing: &'static str,
}

/// Unbonding, step 2: send the unbonding outputs to `address`. Returns
/// `{ rawHex, txid, outValue, signing }`.
#[wasm_bindgen(js_name = buildUnbondClaimTx)]
pub fn build_unbond_claim_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: UnbondClaimRecipeJson = serde_wasm_bindgen::from_value(recipe)?;
    let signing = record_signing(network, r.tip_height, r.locktime, r.records_v2_height)?;
    let mut unbonding = Vec::with_capacity(r.unbonding.len());
    for u in &r.unbonding {
        unbonding.push(UnbondingOutput {
            txid: delegation_txid_from_hex(&u.txid)?,
            vout: u.vout,
            value: atoms(&u.value, "unbonding value")?,
        });
    }
    let total: u64 = unbonding.iter().map(|u| u.value).sum();
    let plan = UnbondClaimPlan {
        unbonding,
        asset: network.policy_asset().into(),
        staker_secret: staker_secret(&r.mnemonic, network)?,
        destination: address_script(&r.address, "destination")?,
        fee_atoms: atoms(&r.fee_atoms, "feeAtoms")?,
        dust_floor: 1_000,
        locktime: r.locktime,
        signing,
    };
    let (raw_hex, txid) = build_unbond_claim_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltClaimTx {
        raw_hex,
        txid: txid.to_string(),
        out_value: total.saturating_sub(plan.fee_atoms).to_string(),
        signing: signing_name(signing),
    })?)
}
