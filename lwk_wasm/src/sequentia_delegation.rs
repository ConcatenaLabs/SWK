//! SEQUENTIA staking pools, for the browser and mobile wallets: join a pool,
//! move between pools, and leave one.
//!
//! Joining takes two transactions, mined together, because the network accepts
//! a delegation record only from a transaction that spends a coin of its
//! controller (the wallet's staking key, m/2/0), and the wallet's descriptor
//! coins are not that key's:
//!
//! 1. `TxBuilder.addRecordAuthorization(stakerPublicKey, recordAtoms + feeAtoms)`,
//!    an ordinary wallet payment to the staking key's `P2WPKH`, signed and
//!    broadcast the usual way;
//! 2. `buildDelegationCreateTx`, the record, funded by that coin and nothing
//!    else; broadcast it straight after, unconfirmed parent and all.
//!
//! Spending a record (`buildDelegationSpendTx`) moves to another pool or
//! leaves. A bare script matches no descriptor, so the wallet's own signer will
//! not touch either the record or the staking key's coin; this module signs
//! both. Its signature is the one the chain wants at the next block, chosen
//! from the chain tip (`tipHeight`): stake record spends commit to the amount
//! from `pos_records_v2_height`, 163,000 on the testnet.
//!
//! Note what is deliberately NOT here: announcing a payout policy, which is what
//! turns a staker into a pool anyone should join. That binds every block a key
//! ever produces and requires being online with the signing key on the machine
//! producing them, so it belongs to the node wallet and is offered only there.

use lwk_wollet::bitcoin::bip32;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::sequentia_delegation::{
    build_delegation_create_tx, build_delegation_spend_tx, delegation_pubkey_from_hex,
    delegation_txid_from_hex, sequentia_delegation_script, DelegationCreatePlan,
    DelegationSpendPlan,
};
use lwk_wollet::sequentia_stake_records::{find_key_coins, StakeRecordSigning};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Error, Network};

/// Build the canonical Sequentia delegation-record script for a 33-byte hex
/// controller and signer; returns the scriptPubKey as hex. Cross-checked
/// byte-for-byte against the node's `getdelegationscript`, and pinned by a
/// shared test vector on both sides.
#[wasm_bindgen(js_name = sequentiaDelegationScript)]
pub fn sequentia_delegation_script_js(controller: &str, signer: &str) -> Result<String, Error> {
    let c = delegation_pubkey_from_hex(controller, "controller")?;
    let s = delegation_pubkey_from_hex(signer, "signer")?;
    Ok(sequentia_delegation_script(&c, &s).as_bytes().to_hex())
}

/// Read a delegation record back out of a scriptPubKey hex, returning
/// `{ controller, signer }`, or `null` if the script is not one.
///
/// This is how a wallet finds a delegation it has no local note of, which is the
/// case that matters: restore a seed on a new device and the record is still
/// out there lending your weight to a pool. Scanning the wallet's own history
/// for a script this recognises needs no index, no extra service and no pool
/// list, because the transaction that funded the record spent this wallet's
/// coins and is therefore in its history.
#[wasm_bindgen(js_name = parseDelegationScript)]
pub fn parse_delegation_script_js(script_hex: &str) -> Result<JsValue, Error> {
    let bytes = Vec::<u8>::from_hex(script_hex.trim())
        .map_err(|e| Error::Generic(format!("invalid script hex: {e}")))?;
    let script = lwk_wollet::elements::Script::from(bytes);
    match lwk_wollet::sequentia_delegation::parse_delegation_script(&script) {
        None => Ok(JsValue::NULL),
        Some((controller, signer)) => Ok(serde_wasm_bindgen::to_value(&ParsedDelegation {
            controller: controller.to_hex(),
            signer: signer.to_hex(),
        })?),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParsedDelegation {
    controller: String,
    signer: String,
}

/// Every delegation record in `tx_hex` naming `controller` as its controller,
/// as `[{ vout, signer, value }]`.
///
/// This is how a wallet finds a delegation it has no local note of, which is
/// the case that matters: restore a seed on another device and the record is
/// still out there lending your weight to a pool. The wallet does not hold the
/// record as one of its own coins (a bare script matches no descriptor), but
/// the transaction that FUNDED it spent this wallet's coins and is therefore in
/// its history, so scanning that history finds it with no index, no pool list
/// and no stored state. Whether it is still unspent is a separate question only
/// the explorer can answer, because a transaction spending a bare script need
/// not touch this wallet at all.
#[wasm_bindgen(js_name = findDelegationRecords)]
pub fn find_delegation_records_js(tx_hex: &str, controller: &str) -> Result<JsValue, Error> {
    let want = delegation_pubkey_from_hex(controller, "controller")?;
    let bytes = Vec::<u8>::from_hex(tx_hex.trim())
        .map_err(|e| Error::Generic(format!("invalid transaction hex: {e}")))?;
    let tx: lwk_wollet::elements::Transaction =
        lwk_wollet::elements::encode::deserialize(&bytes)
            .map_err(|e| Error::Generic(format!("could not decode the transaction: {e}")))?;

    let mut found = Vec::new();
    for (vout, out) in tx.output.iter().enumerate() {
        let parsed = lwk_wollet::sequentia_delegation::parse_delegation_script(&out.script_pubkey);
        let (controller_bytes, signer_bytes) = match parsed {
            Some(p) => p,
            None => continue,
        };
        if controller_bytes != want {
            continue;
        }
        // A record is always explicit; a blinded one would carry no readable
        // value and could not be spent by this path anyway.
        let value = match out.value {
            lwk_wollet::elements::confidential::Value::Explicit(v) => v,
            _ => continue,
        };
        found.push(FoundDelegationRecord {
            vout: vout as u32,
            signer: signer_bytes.to_hex(),
            // A string: a JS number cannot hold 64 bits without silently rounding.
            value: value.to_string(),
        });
    }
    Ok(serde_wasm_bindgen::to_value(&found)?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundDelegationRecord {
    vout: u32,
    signer: String,
    value: String,
}

/// Everything needed to spend a delegation record, as JSON from the wallet.
///
/// `rotateTo` decides which of the two spends this is: present re-points the
/// delegation at a new signer, absent reclaims it to `reclaimAddress`. Both are
/// one self-contained transaction paying its fee out of the record's own value,
/// so neither needs the wallet to select a coin.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegationSpendRecipeJson {
    mnemonic: String,
    /// The record output being spent.
    record_txid: String,
    record_vout: u32,
    /// Its explicit value in atoms, as a string (JS numbers cannot hold 64 bits).
    record_value: String,
    /// The signer the record currently names. Needed to rebuild the exact script
    /// being satisfied.
    current_signer: String,
    /// Present: re-point at this signer. Absent: reclaim.
    #[serde(default)]
    rotate_to: Option<String>,
    /// Where the reclaimed coins go. Required unless re-pointing.
    #[serde(default)]
    reclaim_address: Option<String>,
    /// Network fee in atoms, taken out of the record.
    fee_atoms: String,
    /// nLockTime, normally the current tip.
    locktime: u32,
    /// The chain tip the spend is built against, which decides its signature.
    /// Defaults to `locktime`, which wallets set to the tip.
    #[serde(default)]
    tip_height: Option<u32>,
    /// The height the chain signs record spends the second-generation way
    /// from. Defaults to the network's (163,000 on the testnet, 1 elsewhere);
    /// set it only for a custom chain started with `-posrecordsv2height`.
    #[serde(default)]
    records_v2_height: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltDelegationTx {
    raw_hex: String,
    txid: String,
    /// What the record will hold afterwards (re-point), or what comes back to
    /// the wallet (reclaim). Atoms, as a string.
    out_value: String,
    /// True when this re-points rather than reclaims, so the caller can say the
    /// right thing without re-deriving it.
    repointed: bool,
    /// The signature it carries: `"legacy"` or `"segwitV0"`.
    signing: &'static str,
}

/// The staking key's secret, m/2/0: the key `Signer.stakerPublicKey()` hands
/// out, the controller of the wallet's delegation and the key its stake is
/// bonded to.
pub(crate) fn staker_secret(
    mnemonic: &str,
    network: &Network,
) -> Result<lwk_wollet::elements::secp256k1_zkp::SecretKey, Error> {
    let signer = crate::Signer::new(&crate::Mnemonic::new(mnemonic)?, network)?;
    let path = bip32::DerivationPath::from(vec![
        bip32::ChildNumber::Normal { index: 2 },
        bip32::ChildNumber::Normal { index: 0 },
    ]);
    let xprv = signer
        .inner
        .derive_xprv(&path)
        .map_err(|e| Error::Generic(format!("derive staking key: {e}")))?;
    lwk_wollet::elements::secp256k1_zkp::SecretKey::from_slice(&xprv.private_key.secret_bytes())
        .map_err(|e| Error::Generic(format!("invalid staking key: {e}")))
}

/// The signature a record spend built against `tip_height` (or, without one,
/// `locktime`, which wallets set to the tip) needs in the next block.
pub(crate) fn record_signing(
    network: &Network,
    tip_height: Option<u32>,
    locktime: u32,
    records_v2_height: Option<u32>,
) -> Result<StakeRecordSigning, Error> {
    let tip = match tip_height {
        Some(t) => t,
        None if locktime > 0 => locktime,
        None => {
            return Err(Error::Generic(
                "the chain tip is needed to choose the signature (tipHeight); it changes at the network's fork height"
                    .into(),
            ))
        }
    };
    let v2 =
        records_v2_height.unwrap_or_else(|| lwk_wollet::pos_records_v2_height(&network.into()));
    Ok(StakeRecordSigning::for_next_block(tip, v2))
}

pub(crate) fn signing_name(signing: StakeRecordSigning) -> &'static str {
    match signing {
        StakeRecordSigning::Legacy => "legacy",
        StakeRecordSigning::SegwitV0 => "segwitV0",
    }
}

pub(crate) fn atoms(value: &str, what: &str) -> Result<u64, Error> {
    value
        .trim()
        .parse()
        .map_err(|_| Error::Generic(format!("{what} must be an integer number of atoms")))
}

/// Build and sign the spend of a delegation record. Returns
/// `{ rawHex, txid, outValue, repointed, signing }`.
#[wasm_bindgen(js_name = buildDelegationSpendTx)]
pub fn build_delegation_spend_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: DelegationSpendRecipeJson = serde_wasm_bindgen::from_value(recipe)?;
    let controller_secret = staker_secret(&r.mnemonic, network)?;
    let signing = record_signing(network, r.tip_height, r.locktime, r.records_v2_height)?;

    let current_signer = delegation_pubkey_from_hex(&r.current_signer, "current signer")?;
    let rotate_to = match r.rotate_to.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(delegation_pubkey_from_hex(s, "new signer")?),
        _ => None,
    };

    // A reclaim with nowhere to go would burn the record's value to fees, so
    // require the destination rather than inventing one.
    let reclaim_spk = match (&rotate_to, r.reclaim_address.as_deref()) {
        (Some(_), _) => lwk_wollet::elements::Script::new(),
        (None, Some(a)) if !a.trim().is_empty() => address_script(a, "reclaim")?,
        (None, _) => {
            return Err(Error::Generic(
                "reclaiming a delegation needs a reclaimAddress to send its coins to".into(),
            ))
        }
    };

    let plan = DelegationSpendPlan {
        record_txid: delegation_txid_from_hex(&r.record_txid)?,
        record_vout: r.record_vout,
        record_value: atoms(&r.record_value, "recordValue")?,
        asset: network.policy_asset().into(),
        current_signer,
        controller_secret,
        rotate_to: rotate_to.clone(),
        reclaim_spk,
        fee_atoms: atoms(&r.fee_atoms, "feeAtoms")?,
        // Elements' default dust relay fee over the ~200-byte spend-and-output
        // pair a record produces. Refusing here beats a broadcast rejection the
        // wallet would have to explain after the fact.
        dust_floor: 1_000,
        locktime: r.locktime,
        signing,
    };
    let out_value = plan.record_value.saturating_sub(plan.fee_atoms);
    let (raw_hex, txid) = build_delegation_spend_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltDelegationTx {
        raw_hex,
        txid: txid.to_string(),
        out_value: out_value.to_string(),
        repointed: rotate_to.is_some(),
        signing: signing_name(signing),
    })?)
}

pub(crate) fn address_script(
    address: &str,
    what: &str,
) -> Result<lwk_wollet::elements::Script, Error> {
    let addr: lwk_wollet::elements::Address = address
        .trim()
        .parse()
        .map_err(|e| Error::Generic(format!("invalid {what} address: {e}")))?;
    Ok(addr.script_pubkey())
}

/// Everything needed to create a delegation record from a coin of the
/// wallet's staking key, as JSON from the wallet.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegationCreateRecipeJson {
    mnemonic: String,
    /// The transaction holding the staking key's coin: normally the payment
    /// `TxBuilder.addRecordAuthorization` built, signed and finalized.
    coin_tx_hex: String,
    /// Which output of it; by default the first explicit Sequence token
    /// output paying the staking key's `P2WPKH`.
    #[serde(default)]
    coin_vout: Option<u32>,
    /// The pool's signer key, 33-byte hex.
    signer: String,
    /// The record's own value in atoms, as a string.
    record_value: String,
    /// Where anything the coin holds beyond the record and the fee goes.
    /// Required only when something is left over.
    #[serde(default)]
    change_address: Option<String>,
    /// Network fee in atoms, taken out of the coin.
    fee_atoms: String,
    /// nLockTime, normally the current tip.
    locktime: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltDelegationCreateTx {
    raw_hex: String,
    txid: String,
    /// The record's value, atoms, as a string.
    record_value: String,
    /// What went back to `changeAddress`, atoms, as a string ("0" for none).
    change_value: String,
}

/// Build and sign the transaction that creates a delegation record, funded by
/// a coin of the wallet's staking key and nothing else. Returns
/// `{ rawHex, txid, recordValue, changeValue }`.
///
/// Broadcast it right after the transaction holding the coin; it may spend
/// that coin unconfirmed, and the two are mined together.
#[wasm_bindgen(js_name = buildDelegationCreateTx)]
pub fn build_delegation_create_tx_js(recipe: JsValue, network: &Network) -> Result<JsValue, Error> {
    let r: DelegationCreateRecipeJson = serde_wasm_bindgen::from_value(recipe)?;
    let controller_secret = staker_secret(&r.mnemonic, network)?;
    let controller = lwk_wollet::elements::secp256k1_zkp::PublicKey::from_secret_key(
        &lwk_wollet::elements::secp256k1_zkp::Secp256k1::new(),
        &controller_secret,
    )
    .serialize()
    .to_vec();
    let asset: lwk_wollet::elements::AssetId = network.policy_asset().into();
    let bytes = Vec::<u8>::from_hex(r.coin_tx_hex.trim())
        .map_err(|e| Error::Generic(format!("invalid transaction hex: {e}")))?;
    let coin_tx: lwk_wollet::elements::Transaction =
        lwk_wollet::elements::encode::deserialize(&bytes)
            .map_err(|e| Error::Generic(format!("could not decode the transaction: {e}")))?;
    let coins = find_key_coins(&coin_tx, &controller, asset);
    let (coin_vout, coin_value) = match r.coin_vout {
        Some(v) => *coins.iter().find(|(n, _)| *n == v).ok_or_else(|| {
            Error::Generic(format!(
                "output {v} of that transaction is not an explicit Sequence token coin of the staking key"
            ))
        })?,
        None => *coins.first().ok_or_else(|| {
            Error::Generic(
                "that transaction pays the staking key nothing; build it with TxBuilder.addRecordAuthorization"
                    .into(),
            )
        })?,
    };
    let record_value = atoms(&r.record_value, "recordValue")?;
    let fee_atoms = atoms(&r.fee_atoms, "feeAtoms")?;
    let change = coin_value.saturating_sub(record_value.saturating_add(fee_atoms));
    let change_spk = match r.change_address.as_deref() {
        Some(a) if !a.trim().is_empty() => address_script(a, "change")?,
        _ if change > 0 => {
            return Err(Error::Generic(format!(
                "the coin holds {change} atoms more than the record and its fee; give a changeAddress for them"
            )))
        }
        _ => lwk_wollet::elements::Script::new(),
    };
    let plan = DelegationCreatePlan {
        coin_txid: coin_tx.txid(),
        coin_vout,
        coin_value,
        asset,
        controller_secret,
        signer: delegation_pubkey_from_hex(&r.signer, "signer")?,
        record_value,
        change_spk,
        fee_atoms,
        dust_floor: 1_000,
        locktime: r.locktime,
    };
    let (raw_hex, txid) = build_delegation_create_tx(&plan)?;
    Ok(serde_wasm_bindgen::to_value(&BuiltDelegationCreateTx {
        raw_hex,
        txid: txid.to_string(),
        record_value: record_value.to_string(),
        change_value: change.to_string(),
    })?)
}

/// The signature a stake record spend built against `tipHeight` needs in the
/// next block: `"legacy"` or `"segwitV0"`. `recordsV2Height` overrides the
/// network's fork height (163,000 on the testnet, 1 elsewhere) for a custom
/// chain started with `-posrecordsv2height`.
#[wasm_bindgen(js_name = stakeRecordSigning)]
pub fn stake_record_signing_js(
    network: &Network,
    tip_height: u32,
    records_v2_height: Option<u32>,
) -> String {
    let v2 =
        records_v2_height.unwrap_or_else(|| lwk_wollet::pos_records_v2_height(&network.into()));
    signing_name(StakeRecordSigning::for_next_block(tip_height, v2)).to_string()
}
