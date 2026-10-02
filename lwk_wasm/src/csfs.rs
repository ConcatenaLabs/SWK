//! Arca message signing for the wasm bindings.
//!
//! A message crosses this edge as a plain object naming its fields, never as a
//! bare hash. Byte order: asset ids and the genesis hash are display hex (as
//! the node and the explorer print them); the leaf salt and scriptPubKeys are
//! raw bytes as hex. Amounts are atoms, as a number or a decimal string.
//!
//! ```js
//! { kind: "rebind", genesisHash, leafSalt, assetIn, valueIn,
//!   outputs: [{ asset, value, scriptPubkey }, ...] }   // 1 to 4 outputs
//! { kind: "unroll", children: [{ asset, value, scriptPubkey }, ...], time }
//! { kind: "release", genesisHash, children: [{ asset, value, scriptPubkey }, ...] }
//! ```

use std::str::FromStr;

use lwk_signer::csfs::{
    ArcaMessage, CommittedOutput, RebindMessage, ReleaseMessage, UnrollAuthorisation,
};
use lwk_wollet::elements::{hex::ToHex, AssetId, BlockHash, Script};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::tapscript::unhex;
use crate::Error;

#[derive(Deserialize)]
#[serde(untagged)]
enum Atoms {
    Number(u64),
    Decimal(String),
}

impl Atoms {
    fn get(&self) -> Result<u64, Error> {
        match self {
            Atoms::Number(n) => Ok(*n),
            Atoms::Decimal(s) => s
                .parse()
                .map_err(|e| Error::Generic(format!("invalid amount {s:?}: {e}"))),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutputDto {
    asset: String,
    value: Atoms,
    script_pubkey: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum MessageDto {
    #[serde(rename_all = "camelCase")]
    Rebind {
        genesis_hash: String,
        leaf_salt: String,
        asset_in: String,
        value_in: Atoms,
        outputs: Vec<OutputDto>,
    },
    #[serde(rename_all = "camelCase")]
    Unroll { children: Vec<OutputDto>, time: u32 },
    #[serde(rename_all = "camelCase")]
    Release {
        genesis_hash: String,
        children: Vec<OutputDto>,
    },
}

fn asset(s: &str) -> Result<AssetId, Error> {
    AssetId::from_str(s).map_err(|e| Error::Generic(format!("invalid asset id {s:?}: {e}")))
}

fn genesis(s: &str) -> Result<BlockHash, Error> {
    BlockHash::from_str(s).map_err(|e| Error::Generic(format!("invalid genesis hash {s:?}: {e}")))
}

fn outputs(list: &[OutputDto]) -> Result<Vec<CommittedOutput>, Error> {
    list.iter()
        .map(|o| {
            Ok(CommittedOutput {
                asset: asset(&o.asset)?,
                value: o.value.get()?,
                script_pubkey: Script::from(unhex(&o.script_pubkey, "scriptPubkey")?),
            })
        })
        .collect()
}

/// Parse a message object into the signer's typed message.
pub(crate) fn parse_message(message: JsValue) -> Result<ArcaMessage, Error> {
    let dto: MessageDto = serde_wasm_bindgen::from_value(message)?;
    Ok(match dto {
        MessageDto::Rebind {
            genesis_hash,
            leaf_salt,
            asset_in,
            value_in,
            outputs: outs,
        } => ArcaMessage::Rebind(RebindMessage {
            genesis_hash: genesis(&genesis_hash)?,
            leaf_salt: unhex(&leaf_salt, "leafSalt")?
                .try_into()
                .map_err(|_| Error::Generic("leafSalt must be 32 bytes".into()))?,
            asset_in: asset(&asset_in)?,
            value_in: value_in.get()?,
            outputs: outputs(&outs)?,
        }),
        MessageDto::Unroll { children, time } => ArcaMessage::Unroll(UnrollAuthorisation {
            children: outputs(&children)?,
            time,
        }),
        MessageDto::Release {
            genesis_hash,
            children,
        } => ArcaMessage::Release(ReleaseMessage {
            genesis_hash: genesis(&genesis_hash)?,
            children: outputs(&children)?,
        }),
    })
}

/// The 32-byte digest (hex) an Arca script verifies for `message`, rebuilt
/// from its fields. Refuses fields a script cannot produce.
#[wasm_bindgen(js_name = csfsDigest)]
pub fn csfs_digest(message: JsValue) -> Result<String, Error> {
    Ok(parse_message(message)?.digest()?.to_hex())
}

#[derive(Serialize)]
struct Description {
    kind: &'static str,
    digest: String,
    lines: Vec<String>,
}

/// What signing `message` authorises, for the wallet to show before it asks
/// for approval: `{ kind, digest, lines }`, one plain sentence per line.
#[wasm_bindgen(js_name = csfsDescribe)]
pub fn csfs_describe(message: JsValue) -> Result<JsValue, Error> {
    let m = parse_message(message)?;
    let d = Description {
        kind: m.kind(),
        digest: m.digest()?.to_hex(),
        lines: m.describe(),
    };
    Ok(serde_wasm_bindgen::to_value(&d)?)
}
