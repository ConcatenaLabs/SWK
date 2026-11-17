//! CoinJoin wasm bindings.
//!
//! One export: sign the coordinator's round transaction for the wallet's own inputs
//! ([`lwk_wollet::sign_coinjoin_inputs`]). Everything else a participant does — choosing a round,
//! blinding credentials, registering outputs, and above all VERIFYING that the round pays what it
//! promised — is JavaScript, in the wallet's `coinjoin.js`. Only the Elements segwit-v0 sighash has
//! to be here, for the same reason the covenant FILL does: it commits to the spent coin's
//! confidential value and to every output commitment in the transaction.
//!
//! The verification order matters and is enforced by the caller, not by this module: `coinjoin.js`
//! unblinds its own outputs with the wallet's blinding key and refuses to call this at all unless
//! the amounts are the ones the round owed it. A signature is the irreversible step; the check
//! cannot live inside it.

use lwk_wollet::bitcoin::bip32;
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::Txid;
use lwk_wollet::secp256k1::Secp256k1;
use lwk_wollet::{sign_coinjoin_inputs, CoinjoinInput};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::Error;

/// One output of the round transaction that belongs to this wallet, unblinded.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MyOutputJson {
    vout: u32,
    script_pubkey: String,
    asset: String,
    /// Atoms as a decimal string: a value above 2^53 would be silently rounded as a JS number, and
    /// this figure is the thing the participant checks the round against.
    value: String,
}

/// Unblind the outputs of a CoinJoin round transaction that belong to this wallet.
///
/// This is the participant's ONLY way to answer the question that decides whether to sign: does this
/// transaction actually pay me what the round owed me? The coordinator built and blinded it, so its
/// word for the amounts is worth nothing; the wallet's own SLIP-77 blinding key is what settles it.
///
/// An output is "mine" exactly when it unblinds under the blinding key this descriptor derives for
/// that scriptPubKey — which is true precisely for the addresses this wallet handed out. Outputs
/// belonging to other participants stay opaque here, as they must.
#[wasm_bindgen(js_name = coinjoinUnblindOutputs)]
pub fn coinjoin_unblind_outputs(
    tx_hex: &str,
    descriptor: &crate::WolletDescriptor,
) -> Result<JsValue, Error> {
    let bytes = Vec::<u8>::from_hex(tx_hex)
        .map_err(|e| Error::Generic(format!("invalid coinjoin tx hex: {e}")))?;
    let tx: lwk_wollet::elements::Transaction = lwk_wollet::elements::encode::deserialize(&bytes)
        .map_err(|e| Error::Generic(format!("coinjoin tx decode: {e}")))?;
    let desc: lwk_wollet::WolletDescriptor = descriptor.into();
    let ct = desc.ct_descriptor()?;
    let secp = Secp256k1::new();

    let mut mine = Vec::new();
    for (vout, out) in tx.output.iter().enumerate() {
        if out.is_fee() {
            continue;
        }
        let Some(key) = lwk_common::derive_blinding_key(ct, &out.script_pubkey) else {
            continue;
        };
        // A failure here is the normal case: it means the output is somebody else's.
        if let Ok(secrets) = out.unblind(&secp, key) {
            mine.push(MyOutputJson {
                vout: vout as u32,
                script_pubkey: out.script_pubkey.to_hex(),
                asset: secrets.asset.to_string(),
                value: secrets.value.to_string(),
            });
        }
    }
    Ok(serde_wasm_bindgen::to_value(&mine)?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoinjoinSignRequest {
    /// The round transaction, blinded, exactly as the coordinator published it.
    tx_hex: String,
    /// The wallet's recovery phrase. Used only to re-derive the signing keys, in memory, here.
    mnemonic: String,
    inputs: Vec<CoinjoinInputJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoinjoinInputJson {
    txid: String,
    vout: u32,
    /// The coin's explicit value in atoms, as a decimal string (JS numbers lose atoms above 2^53).
    value: String,
    /// Its scriptPubKey hex, checked against the derived key.
    spk_hex: String,
    /// Wallet derivation coordinates of the address holding the coin: external/internal chain and
    /// address index, under `m/84'/coin'/0'`.
    chain: u32,
    index: u32,
}

/// Sign the participant's own inputs of a CoinJoin round transaction.
///
/// `request`:
/// ```js
/// { txHex, mnemonic, inputs: [{ txid, vout, value: "1000000000", spkHex, chain, index }] }
/// ```
/// Returns the transaction hex with witnesses attached for those inputs only. Inputs are matched by
/// outpoint, so the coordinator's shuffling of the round cannot make the wallet sign a coin it did
/// not mean to.
#[wasm_bindgen(js_name = coinjoinSignInputs)]
pub fn coinjoin_sign_inputs(request: JsValue, network: &crate::Network) -> Result<String, Error> {
    let r: CoinjoinSignRequest = serde_wasm_bindgen::from_value(request)?;
    let signer = crate::Signer::new(&crate::Mnemonic::new(&r.mnemonic)?, network)?;
    // The BIP84 account's coin type, as in lwk_common::singlesig_desc.
    let coin: u32 = lwk_common::bip44_coin_type(network.is_mainnet());

    let mut inputs = Vec::with_capacity(r.inputs.len());
    for i in &r.inputs {
        let path = bip32::DerivationPath::from(vec![
            bip32::ChildNumber::Hardened { index: 84 },
            bip32::ChildNumber::Hardened { index: coin },
            bip32::ChildNumber::Hardened { index: 0 },
            bip32::ChildNumber::Normal { index: i.chain },
            bip32::ChildNumber::Normal { index: i.index },
        ]);
        let xprv = signer
            .inner
            .derive_xprv(&path)
            .map_err(|e| Error::Generic(format!("derive coinjoin input key: {e}")))?;
        inputs.push(CoinjoinInput {
            txid: Txid::from_str(&i.txid)
                .map_err(|e| Error::Generic(format!("invalid coinjoin input txid: {e}")))?,
            vout: i.vout,
            value: i
                .value
                .parse::<u64>()
                .map_err(|e| Error::Generic(format!("invalid coinjoin input value: {e}")))?,
            spk: Vec::<u8>::from_hex(&i.spk_hex)
                .map_err(|e| Error::Generic(format!("invalid coinjoin input spk: {e}")))?,
            secret_key: xprv.private_key,
        });
    }

    Ok(sign_coinjoin_inputs(&r.tx_hex, &inputs)?)
}
