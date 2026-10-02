//! Arca message signing for the wasm bindings.
//!
//! A message crosses this edge as a plain object naming its fields, never as a
//! bare hash. Byte order: asset ids and the genesis hash are display hex (as
//! the node and the explorer print them); the leaf id, the salt and
//! scriptPubKeys are raw bytes as hex. Amounts are atoms, as a number or a
//! decimal string.
//!
//! ```js
//! { kind: "rebind", source, assetIn, valueIn,
//!   outputs: [{ asset, value, scriptPubkey }, ...] }   // 1 to 4 outputs
//! { kind: "unroll", children: [{ asset, value, scriptPubkey }, ...], time }
//! { kind: "release", genesisHash, children: [{ asset, value, scriptPubkey }, ...] }
//! ```
//!
//! A rebind's `source` names the output it spends. For a leaf's
//! collaborative path it is the leaf's record, `{ record }` (the record's
//! binary form as hex), from which the leaf id, the salt and the chain are
//! taken. Otherwise it is `{ path, leafId, genesisHash, salt }`, where `path`
//! is `leaf`, `checkpoint`, `htlc-claim`, `htlc-claim-both` or
//! `htlc-refund-both` and `leafId` is the id of the leaf the output is, or
//! was made from.

use std::str::FromStr;

use lwk_signer::csfs::{
    ArcaMessage, CommittedOutput, CsfsPolicy, RebindMessage, RebindPath, RebindSource,
    ReleaseMessage, UnrollAuthorisation,
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
#[serde(deny_unknown_fields)]
struct RecordSourceDto {
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NamedSourceDto {
    path: String,
    leaf_id: String,
    genesis_hash: String,
    salt: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SourceDto {
    Record(RecordSourceDto),
    Named(NamedSourceDto),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum MessageDto {
    #[serde(rename_all = "camelCase")]
    Rebind {
        source: SourceDto,
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

fn bytes32(s: &str, what: &str) -> Result<[u8; 32], Error> {
    unhex(s, what)?
        .try_into()
        .map_err(|_| Error::Generic(format!("{what} must be 32 bytes")))
}

fn source(dto: SourceDto) -> Result<RebindSource, Error> {
    Ok(match dto {
        SourceDto::Record(RecordSourceDto { record }) => {
            let record = arca_covenant::LeafRecord::from_bytes(&unhex(&record, "record")?)
                .map_err(|e| Error::Generic(format!("the leaf's record: {e}")))?;
            RebindSource::leaf(&record)?
        }
        SourceDto::Named(NamedSourceDto {
            path,
            leaf_id,
            genesis_hash,
            salt,
        }) => RebindSource::new(
            RebindPath::from_name(&path)?,
            bytes32(&leaf_id, "leafId")?,
            genesis(&genesis_hash)?,
            bytes32(&salt, "salt")?,
        ),
    })
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LimitsDto {
    fee_floor_per_kvb: Option<Atoms>,
    max_uncommitted: Option<Atoms>,
}

/// The signer's policy from the `limits` object of `signCsfs`, for the
/// network whose genesis hash is `genesis_hash`.
pub(crate) fn parse_limits(limits: JsValue, genesis_hash: BlockHash) -> Result<CsfsPolicy, Error> {
    let dto: LimitsDto = if limits.is_undefined() || limits.is_null() {
        LimitsDto::default()
    } else {
        serde_wasm_bindgen::from_value(limits)?
    };
    Ok(match (dto.fee_floor_per_kvb, dto.max_uncommitted) {
        (Some(_), Some(_)) => {
            return Err(Error::Generic(
                "limits: give feeFloorPerKvb or maxUncommitted, not both".into(),
            ))
        }
        (Some(floor), None) => CsfsPolicy::new(genesis_hash, floor.get()?),
        (None, Some(max)) => CsfsPolicy::with_ceiling(genesis_hash, max.get()?),
        (None, None) => CsfsPolicy::with_ceiling(genesis_hash, 0),
    })
}

/// Parse a message object into the signer's typed message.
pub(crate) fn parse_message(message: JsValue) -> Result<ArcaMessage, Error> {
    let dto: MessageDto = serde_wasm_bindgen::from_value(message)?;
    Ok(match dto {
        MessageDto::Rebind {
            source: src,
            asset_in,
            value_in,
            outputs: outs,
        } => ArcaMessage::Rebind(RebindMessage {
            source: source(src)?,
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
