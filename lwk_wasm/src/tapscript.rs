//! Taproot script-path signature hashes for the wasm bindings.
//!
//! The signing itself is [`crate::Signer::sign_tapscript`]; this module holds
//! the parsing it shares with [`tapscript_sighash`], which lets a page or a
//! watcher compute the hash a signature must cover without holding a key, and
//! [`tapscript_describe`], which says what a signature would authorise.
//!
//! Byte order at this edge: the genesis hash is display hex (as
//! `getblockhash` prints it); transactions and prevouts are consensus
//! serialisations, so they carry their bytes in internal order.

use lwk_signer::tapscript::{sighash_type_from_u8, ScriptPathSpend};
use lwk_wollet::elements::{
    self,
    hex::{FromHex, ToHex},
    taproot::ControlBlock,
    BlockHash, Script, Transaction, TxOut,
};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::Error;

/// Decode hex, naming the field in the error.
pub(crate) fn unhex(s: &str, what: &str) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_hex(s).map_err(|e| Error::Generic(format!("invalid {what} hex: {e}")))
}

/// The decoded parts of one script-path spend, owned.
pub(crate) struct SpendParts {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub leaf: Script,
    pub control_block: ControlBlock,
    pub input_index: usize,
    pub sighash_type: elements::SchnorrSighashType,
    pub genesis: BlockHash,
}

impl SpendParts {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse(
        tx_hex: &str,
        input_index: u32,
        prevouts_hex: &[String],
        leaf_script_hex: &str,
        control_block_hex: &str,
        sighash_type: u8,
        genesis_hex: &str,
    ) -> Result<Self, Error> {
        let tx: Transaction = elements::encode::deserialize(&unhex(tx_hex, "transaction")?)?;
        let prevouts = prevouts_hex
            .iter()
            .map(|p| Ok(elements::encode::deserialize(&unhex(p, "prevout")?)?))
            .collect::<Result<Vec<TxOut>, Error>>()?;
        let leaf = Script::from(unhex(leaf_script_hex, "leaf script")?);
        let control_block = ControlBlock::from_slice(&unhex(control_block_hex, "control block")?)?;
        let sighash_type = sighash_type_from_u8(sighash_type)?;
        let genesis = BlockHash::from_str(genesis_hex)?;
        Ok(Self {
            tx,
            prevouts,
            leaf,
            control_block,
            input_index: input_index as usize,
            sighash_type,
            genesis,
        })
    }

    pub(crate) fn spend(&self) -> ScriptPathSpend<'_> {
        ScriptPathSpend {
            tx: &self.tx,
            input_index: self.input_index,
            prevouts: &self.prevouts,
            leaf_script: &self.leaf,
            control_block: &self.control_block,
            sighash_type: self.sighash_type,
            genesis_hash: self.genesis,
        }
    }
}

/// The BIP341 script-path signature hash of input `inputIndex` of `txHex`,
/// spent through `leafScriptHex` at the leaf version its control block
/// carries, with the Elements tagged hashes and the genesis hash.
///
/// - `prevoutsHex`: every input's spent output, consensus-serialised hex, in
///   input order.
/// - `sighashType`: the BIP341 type byte; 0 is `SIGHASH_DEFAULT`.
/// - `genesisHex`: the chain's genesis hash, display hex.
///
/// Refuses when the control block does not commit the leaf to the output the
/// input spends. Returns 32 bytes as hex.
#[wasm_bindgen(js_name = tapscriptSighash)]
#[allow(clippy::too_many_arguments)]
pub fn tapscript_sighash(
    tx_hex: &str,
    input_index: u32,
    prevouts_hex: Vec<String>,
    leaf_script_hex: &str,
    control_block_hex: &str,
    sighash_type: u8,
    genesis_hex: &str,
) -> Result<String, Error> {
    let parts = SpendParts::parse(
        tx_hex,
        input_index,
        &prevouts_hex,
        leaf_script_hex,
        control_block_hex,
        sighash_type,
        genesis_hex,
    )?;
    let spend = parts.spend();
    spend.check_commitment(&elements::secp256k1_zkp::Secp256k1::verification_only())?;
    Ok(spend.sighash()?.to_hex())
}

/// What a signature over this spend would authorise, as plain lines for the
/// wallet to show before it asks for approval: the coin and the leaf, what the
/// sighash type covers (under `SIGHASH_NONE`, no output at all), the outputs,
/// the fee and the locks. Takes the same arguments as `tapscriptSighash` and
/// refuses the same spends.
#[wasm_bindgen(js_name = tapscriptDescribe)]
#[allow(clippy::too_many_arguments)]
pub fn tapscript_describe(
    tx_hex: &str,
    input_index: u32,
    prevouts_hex: Vec<String>,
    leaf_script_hex: &str,
    control_block_hex: &str,
    sighash_type: u8,
    genesis_hex: &str,
) -> Result<Vec<String>, Error> {
    let parts = SpendParts::parse(
        tx_hex,
        input_index,
        &prevouts_hex,
        leaf_script_hex,
        control_block_hex,
        sighash_type,
        genesis_hex,
    )?;
    let spend = parts.spend();
    spend.check_commitment(&elements::secp256k1_zkp::Secp256k1::verification_only())?;
    Ok(spend.describe()?)
}
