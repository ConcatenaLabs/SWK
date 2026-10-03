//! Arca coins, forfeits and releases for the wasm bindings.
//!
//! A page can check a coin it is given out of round, ask which outputs its
//! lineage rests on so it can look them up in its own chain source, and build
//! the two things it signs when it gives a leaf up in a round: the forfeit and
//! the release of the lowest node above the old leaf. Each builder returns the
//! message as the object `Signer.signCsfs` takes, with its digest, so what is
//! signed is rebuilt from fields and never handed over as a bare hash.
//!
//! Byte order, as in the rest of the Arca bindings: asset ids and the genesis
//! hash are display hex; leaf ids, nonces, keys, salts, scripts and
//! transactions are hex of their bytes. Amounts are decimal strings. A coin
//! record is its binary form as hex.
//!
//! ```js
//! const lineage = verifier.coinLineage(coinHex, roundsHex, now);
//! // look each lineage script and board up in the chain source, then:
//! const coin = verifier.verifyCoin(coinHex, roundsHex, ownerKey, ownerNonce, now,
//!     { paid: scriptsFoundPaid, spent: boardsFoundSpent });
//! if (!coin.accepted) console.log(coin.kind, coin.reason);   // "salt", "on_chain", ...
//! ```

use lwk_wollet::ark::covenant::transfer::{LineageKind, ValidCoin};
use lwk_wollet::ark::forfeit::{self, ForfeitError, GivenUp, NodeRelease, OffboardPolicy};
use lwk_wollet::ark::verify::{self, ChainIndex, LineageCheck, EXIT_DEADLINE_MARGIN};
use lwk_wollet::ark::{CoinRecord, ExplicitOutput, RelativeTime, TransferError};
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::{OutPoint, Script, Transaction, Txid};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::ark::{from_js, generic, nonce, parse_record, transaction, xonly, ArkVerifier};
use crate::csfs::{asset, Atoms};
use crate::Error;

fn coin_record(hex: &str) -> Result<CoinRecord, TransferError> {
    let bytes = Vec::<u8>::from_hex(hex.trim()).map_err(|_| {
        TransferError::Record(lwk_wollet::ark::RecordError::Hex("coin record".into()))
    })?;
    CoinRecord::from_bytes(&bytes)
}

fn rounds(list: &[String]) -> Result<Vec<Transaction>, Error> {
    list.iter().map(|r| transaction(r)).collect()
}

fn lineage_kind(k: LineageKind) -> String {
    k.to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputDto {
    asset: String,
    value: String,
    script_pubkey: String,
}

impl From<&ExplicitOutput> for OutputDto {
    fn from(o: &ExplicitOutput) -> Self {
        OutputDto {
            asset: o.asset.to_string(),
            value: o.value.to_string(),
            script_pubkey: o.script_pubkey.as_bytes().to_hex(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LineageOutputDto {
    kind: String,
    asset: String,
    value: String,
    script_pubkey: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutPointDto {
    txid: String,
    vout: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoinVerdictDto {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coin_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hops: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_deadline: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lineage_check: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lineage: Option<Vec<LineageOutputDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boards: Option<Vec<OutPointDto>>,
}

impl CoinVerdictDto {
    fn refused(e: &TransferError) -> Self {
        CoinVerdictDto {
            accepted: false,
            kind: Some(e.kind().to_string()),
            reason: Some(e.to_string()),
            coin_id: None,
            asset: None,
            value: None,
            hops: None,
            expiry: None,
            exit_deadline: None,
            lineage_check: None,
            lineage: None,
            boards: None,
        }
    }

    fn accepted(coin: &ValidCoin) -> Self {
        let expiry = coin.expiry.to_consensus_u32();
        CoinVerdictDto {
            accepted: true,
            coin_id: Some(coin.id.to_string()),
            asset: Some(coin.asset.to_string()),
            value: Some(coin.value.to_string()),
            hops: Some(coin.hops),
            expiry: Some(expiry),
            exit_deadline: Some(expiry.saturating_sub(EXIT_DEADLINE_MARGIN)),
            lineage: Some(
                coin.lineage()
                    .iter()
                    .map(|l| LineageOutputDto {
                        kind: lineage_kind(l.kind),
                        asset: l.output.asset.to_string(),
                        value: l.output.value.to_string(),
                        script_pubkey: l.output.script_pubkey.as_bytes().to_hex(),
                    })
                    .collect(),
            ),
            boards: Some(
                coin.boards()
                    .iter()
                    .map(|o| OutPointDto {
                        txid: o.txid.to_string(),
                        vout: o.vout,
                    })
                    .collect(),
            ),
            ..CoinVerdictDto::empty()
        }
    }

    fn empty() -> Self {
        CoinVerdictDto {
            accepted: true,
            kind: None,
            reason: None,
            coin_id: None,
            asset: None,
            value: None,
            hops: None,
            expiry: None,
            exit_deadline: None,
            lineage_check: None,
            lineage: None,
            boards: None,
        }
    }
}

/// What the wallet's chain source found for a coin's lineage: the lineage
/// scripts it found paid, and the boards it found spent.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChainDto {
    #[serde(default)]
    paid: Vec<String>,
    #[serde(default)]
    spent: Vec<OutPointInDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutPointInDto {
    txid: String,
    vout: u32,
}

/// The leaf a forfeit gives up: a leaf record the wallet holds, or a coin it
/// received out of round with the rounds its lineage came from.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldLeafDto {
    record: Option<String>,
    coin: Option<String>,
    rounds: Option<Vec<String>>,
}

/// An offboard output, as the round pays it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OffboardDto {
    unlock_hash: String,
    destination: DestinationDto,
    operator: String,
    reclaim_delay_seconds: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DestinationDto {
    asset: String,
    value: Atoms,
    script_pubkey: String,
}

fn offboard_policy(v: JsValue) -> Result<OffboardPolicy, Error> {
    let d: OffboardDto = from_js(v)?;
    let unlock_hash: [u8; 32] = Vec::<u8>::from_hex(&d.unlock_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| generic("unlockHash is 32 bytes of hex"))?;
    let script = Vec::<u8>::from_hex(&d.destination.script_pubkey)
        .map_err(|e| generic(format!("invalid destination scriptPubkey: {e}")))?;
    Ok(OffboardPolicy {
        unlock_hash,
        destination: ExplicitOutput::new(
            asset(&d.destination.asset)?,
            d.destination.value.get()?,
            Script::from(script),
        ),
        operator: xonly(&d.operator, "offboard operator key")?,
        reclaim_delay: relative(d.reclaim_delay_seconds as u64, "reclaimDelaySeconds")?,
    })
}

fn relative(seconds: u64, what: &str) -> Result<RelativeTime, Error> {
    RelativeTime::from_seconds_ceil(seconds).map_err(|e| generic(format!("{what}: {e}")))
}

fn atoms(v: JsValue, what: &str) -> Result<u64, Error> {
    let a: Atoms =
        serde_wasm_bindgen::from_value(v).map_err(|e| generic(format!("{what}: {e}")))?;
    a.get()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordSourceOut {
    record: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NamedSourceOut {
    path: &'static str,
    leaf_id: String,
    genesis_hash: String,
    salt: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SourceOut {
    Record(RecordSourceOut),
    Named(NamedSourceOut),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InputOut {
    asset: String,
    value: String,
}

/// A rebind message as `Signer.signCsfs` and `csfsDigest` take it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RebindOut {
    kind: &'static str,
    source: SourceOut,
    asset_in: String,
    value_in: String,
    outputs: Vec<OutputDto>,
    other_inputs: Vec<InputOut>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ForfeitDto {
    message: RebindOut,
    digest: String,
    leaf_id: String,
    unlock_hash: String,
    connector: String,
    refund_delay_seconds: u64,
    margin: String,
    output: OutputDto,
}

/// A release message as `Signer.signCsfs` and `csfsDigest` take it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseOut {
    kind: &'static str,
    genesis_hash: String,
    children: Vec<OutputDto>,
    connector: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseDto {
    message: ReleaseOut,
    digest: String,
    node_hash: String,
    owner: String,
    connector: String,
}

fn release_dto(r: &NodeRelease) -> ReleaseDto {
    let rel = &r.release;
    ReleaseDto {
        message: ReleaseOut {
            kind: "release",
            genesis_hash: rel.chain.genesis_hash().to_string(),
            children: r.children.iter().map(OutputDto::from).collect(),
            connector: rel.connector.to_string(),
        },
        digest: rel.message().digest.to_hex(),
        node_hash: rel.node_hash.to_hex(),
        owner: rel.owner.serialize().to_hex(),
        connector: rel.connector.to_string(),
    }
}

fn forfeit_refused(e: ForfeitError) -> Error {
    generic(format!("forfeit refused: {e}"))
}

fn release_refused(e: ForfeitError) -> Error {
    generic(format!("release refused: {e}"))
}

impl ArkVerifier {
    /// The leaf a forfeit gives up, and the source a rebind of it names.
    fn old_leaf(&self, old: JsValue, now: u32) -> Result<(GivenUp, SourceOut), Error> {
        let d: OldLeafDto = from_js(old)?;
        match (d.record, d.coin, d.rounds) {
            (Some(record), None, None) => {
                let r = parse_record(&record).map_err(|e| crate::ark::refused(&e))?;
                let given = GivenUp::leaf(&r).map_err(|e| crate::ark::refused(&e))?;
                let hex = r.to_bytes().map_err(|e| crate::ark::refused(&e))?.to_hex();
                Ok((given, SourceOut::Record(RecordSourceOut { record: hex })))
            }
            (None, Some(coin), Some(list)) => {
                let policy = self.at(now)?.receipt();
                let rounds = rounds(&list)?;
                let valid = coin_record(&coin).and_then(|c| c.resolve(&rounds, &policy))?;
                let source = SourceOut::Named(NamedSourceOut {
                    path: "leaf",
                    leaf_id: valid.id.to_string(),
                    genesis_hash: valid.leaf.chain.genesis_hash().to_string(),
                    salt: valid.leaf.salt.to_hex(),
                });
                Ok((GivenUp::coin(&valid), source))
            }
            _ => Err(generic(
                "the old leaf is { record } or { coin, rounds }, nothing else",
            )),
        }
    }
}

fn forfeit_dto(f: &lwk_wollet::ark::forfeit::Forfeit, source: SourceOut) -> ForfeitDto {
    let out = f.output();
    ForfeitDto {
        message: RebindOut {
            kind: "rebind",
            source,
            asset_in: f.asset.to_string(),
            value_in: f.value.to_string(),
            outputs: vec![OutputDto::from(&out)],
            other_inputs: vec![],
        },
        digest: f.message().digest.to_hex(),
        leaf_id: f.policy.leaf_id.to_string(),
        unlock_hash: f.policy.unlock_hash.to_hex(),
        connector: f.policy.connector.to_string(),
        refund_delay_seconds: f.policy.refund_delay.seconds(),
        margin: f.margin.to_string(),
        output: OutputDto::from(&out),
    }
}

impl From<TransferError> for Error {
    fn from(e: TransferError) -> Self {
        generic(format!("coin refused (kind {}): {e}", e.kind()))
    }
}

#[wasm_bindgen]
impl ArkVerifier {
    /// Verify a coin the wallet receives out of round, at median time `now`:
    /// the coin record `coinHex` against `roundsHex` (every round and board
    /// transaction its lineage came from), for the wallet's key `ownerKeyHex`
    /// and the owner nonce `ownerNonceHex` it published, with the exit
    /// deadline in place of the horizon.
    ///
    /// `chain`, when given, is what the wallet's chain source found for the
    /// coin's lineage ([`ArkVerifier::coin_lineage`]): `{ paid: [scriptPubkey],
    /// spent: [{ txid, vout }] }`, the lineage scripts it found paid and the
    /// boards it found spent. A coin with a lineage script paid or a board
    /// spent is refused (kind `on_chain`): its owner could take it back. Without
    /// `chain` the verdict's `lineageCheck` is `operator-rule`: the coin rests
    /// on the operator's rule that no Arca leaf on-chain is spent off-chain.
    ///
    /// The verdict is `{ accepted: true, coinId, asset, value, hops, expiry,
    /// exitDeadline, lineageCheck, lineage, boards }` or `{ accepted: false,
    /// kind, reason }`, `kind` naming the refusal as the Arca library does
    /// (`salt` for a record promising one leaf twice, `owner`, `policy`,
    /// `on_chain`, ...).
    #[wasm_bindgen(js_name = verifyCoin)]
    pub fn verify_coin(
        &self,
        coin_hex: &str,
        rounds_hex: Vec<String>,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
        chain: JsValue,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?;
        let rounds = rounds(&rounds_hex)?;
        let owner = xonly(owner_key_hex, "owner key")?;
        let owner_nonce = nonce(owner_nonce_hex)?;
        let chain: Option<ChainDto> = if chain.is_undefined() || chain.is_null() {
            None
        } else {
            Some(from_js(chain)?)
        };
        let coin = match coin_record(coin_hex) {
            Ok(c) => c,
            Err(e) => return Ok(serde_wasm_bindgen::to_value(&CoinVerdictDto::refused(&e))?),
        };
        let verdict = match chain {
            None => verify::verify_coin(&coin, &rounds, &policy, &owner, &owner_nonce, None),
            Some(c) => {
                let paid: Vec<Vec<u8>> = c
                    .paid
                    .iter()
                    .map(|s| {
                        Vec::<u8>::from_hex(s)
                            .map_err(|e| generic(format!("invalid paid scriptPubkey: {e}")))
                    })
                    .collect::<Result<_, _>>()?;
                let spent: Vec<OutPoint> = c
                    .spent
                    .iter()
                    .map(|o| {
                        Ok(OutPoint::new(
                            o.txid
                                .parse::<Txid>()
                                .map_err(|e| generic(format!("invalid spent txid: {e}")))?,
                            o.vout,
                        ))
                    })
                    .collect::<Result<_, Error>>()?;
                let mut is_paid = |s: &Script| paid.iter().any(|p| p.as_slice() == s.as_bytes());
                let mut is_unspent = |o: &OutPoint| !spent.contains(o);
                verify::verify_coin(
                    &coin,
                    &rounds,
                    &policy,
                    &owner,
                    &owner_nonce,
                    Some(ChainIndex {
                        paid: &mut is_paid,
                        unspent: &mut is_unspent,
                    }),
                )
            }
        };
        let dto = match verdict {
            Ok(r) => CoinVerdictDto {
                lineage_check: Some(match r.lineage {
                    LineageCheck::Indexed => "indexed",
                    LineageCheck::OperatorRule => "operator-rule",
                }),
                ..CoinVerdictDto::accepted(&r.coin)
            },
            Err(e) => CoinVerdictDto::refused(&e),
        };
        Ok(serde_wasm_bindgen::to_value(&dto)?)
    }

    /// What a coin's lineage rests on, for the wallet to look up in its own
    /// chain source before [`ArkVerifier::verify_coin`]: the coin `coinHex`
    /// resolved against `roundsHex` at median time `now`, with `lineage`, every
    /// leaf and checkpoint output it descends from (`{ kind, asset, value,
    /// scriptPubkey }`, kind `leaf` or `checkpoint`), and `boards`, every board
    /// output it rests on (`{ txid, vout }`). This does not say whose coin it
    /// is; `verifyCoin` does.
    #[wasm_bindgen(js_name = coinLineage)]
    pub fn coin_lineage(
        &self,
        coin_hex: &str,
        rounds_hex: Vec<String>,
        now: u32,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?.receipt();
        let rounds = rounds(&rounds_hex)?;
        let dto = match coin_record(coin_hex).and_then(|c| c.resolve(&rounds, &policy)) {
            Ok(coin) => CoinVerdictDto::accepted(&coin),
            Err(e) => CoinVerdictDto::refused(&e),
        };
        Ok(serde_wasm_bindgen::to_value(&dto)?)
    }

    /// The forfeit the wallet signs to refresh `old` into its new leaf
    /// `newRecord`, which is verified against `roundHex` as the wallet's own
    /// leaf taken from a round, for its key `ownerKeyHex` and owner nonce
    /// `ownerNonceHex`, at median time `now`. `old` is `{ record }`, a leaf
    /// the wallet holds, or `{ coin, rounds }`, a coin it received. Output `c`
    /// of the round must be the operator's connector, whose asset `M` the
    /// forfeit names; the unlock hash is the new leaf's.
    ///
    /// Returns `{ message, digest, leafId, unlockHash, connector,
    /// refundDelaySeconds, margin, output }`: `message` is the rebind of the
    /// old leaf into the forfeit output, as `signCsfs` takes it, signed with
    /// the old leaf's key and the limit `{ maxUncommitted: margin }`.
    #[wasm_bindgen(js_name = forfeitRefresh)]
    #[allow(clippy::too_many_arguments)]
    pub fn forfeit_refresh(
        &self,
        old: JsValue,
        new_record: &str,
        round_hex: &str,
        c: u32,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        refund_delay_seconds: u32,
        margin: JsValue,
        now: u32,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?;
        let (given, source) = self.old_leaf(old, now)?;
        let new = parse_record(new_record).map_err(|e| crate::ark::refused(&e))?;
        let round = transaction(round_hex)?;
        let f = forfeit::refresh(
            &given,
            &new,
            &round,
            c,
            &policy,
            &xonly(owner_key_hex, "owner key")?,
            &nonce(owner_nonce_hex)?,
            relative(refund_delay_seconds as u64, "refundDelaySeconds")?,
            atoms(margin, "margin")?,
        )
        .map_err(forfeit_refused)?;
        Ok(serde_wasm_bindgen::to_value(&forfeit_dto(&f, source))?)
    }

    /// The forfeit the wallet signs to give `old` up for the offboard output
    /// `offboard` (`{ unlockHash, destination: { asset, value, scriptPubkey },
    /// operator, reclaimDelaySeconds }`), which `roundHex` must pay, whose
    /// connector output `c` must carry the operator's connector script.
    /// Returns what `forfeitRefresh` returns. The offboard's reclaim delay
    /// must outlast the old leaf's unroll, its exit delay, the refund delay
    /// and a margin; that is the caller's to check.
    #[wasm_bindgen(js_name = forfeitOffboard)]
    #[allow(clippy::too_many_arguments)]
    pub fn forfeit_offboard(
        &self,
        old: JsValue,
        offboard: JsValue,
        round_hex: &str,
        c: u32,
        refund_delay_seconds: u32,
        margin: JsValue,
        now: u32,
    ) -> Result<JsValue, Error> {
        let (given, source) = self.old_leaf(old, now)?;
        let off = offboard_policy(offboard)?;
        let round = transaction(round_hex)?;
        let f = forfeit::offboard(
            &given,
            &off,
            &round,
            c,
            relative(refund_delay_seconds as u64, "refundDelaySeconds")?,
            atoms(margin, "margin")?,
        )
        .map_err(forfeit_refused)?;
        Ok(serde_wasm_bindgen::to_value(&forfeit_dto(&f, source))?)
    }

    /// The release of the lowest node above the old leaf `oldRecord` (checked
    /// against its round `oldRoundHex`), given up in a refresh for the new
    /// leaf `newRecord`, verified against `roundHex` as the wallet's own leaf
    /// it holds, for its key `ownerKeyHex` and owner nonce `ownerNonceHex`, at
    /// median time `now`. The release names `M`, the connector asset of
    /// output `c` of that round, so it is void if that round is lost. Sign it
    /// only once the new leaf's preimage is held and its round is final.
    ///
    /// Returns `{ message, digest, nodeHash, owner, connector }`: `message` is
    /// the release as `signCsfs` takes it, signed with the old leaf's key.
    #[wasm_bindgen(js_name = releaseRefresh)]
    #[allow(clippy::too_many_arguments)]
    pub fn release_refresh(
        &self,
        old_record: &str,
        old_round_hex: &str,
        new_record: &str,
        round_hex: &str,
        c: u32,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?;
        let old = parse_record(old_record).map_err(|e| crate::ark::refused(&e))?;
        let new = parse_record(new_record).map_err(|e| crate::ark::refused(&e))?;
        let r = forfeit::release(
            &old,
            &transaction(old_round_hex)?,
            &new,
            &transaction(round_hex)?,
            c,
            &policy,
            &xonly(owner_key_hex, "owner key")?,
            &nonce(owner_nonce_hex)?,
        )
        .map_err(release_refused)?;
        Ok(serde_wasm_bindgen::to_value(&release_dto(&r))?)
    }

    /// The release of the lowest node above the old leaf `oldRecord` (checked
    /// against `oldRoundHex`), given up for the offboard output `offboard`,
    /// which `roundHex` must pay, whose connector output `c` must carry the
    /// operator's connector script. Returns what `releaseRefresh` returns.
    #[wasm_bindgen(js_name = releaseOffboard)]
    pub fn release_offboard(
        &self,
        old_record: &str,
        old_round_hex: &str,
        offboard: JsValue,
        round_hex: &str,
        c: u32,
        now: u32,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?;
        let old = parse_record(old_record).map_err(|e| crate::ark::refused(&e))?;
        let r = forfeit::release_for_offboard(
            &old,
            &transaction(old_round_hex)?,
            &offboard_policy(offboard)?,
            &transaction(round_hex)?,
            c,
            &policy,
        )
        .map_err(release_refused)?;
        Ok(serde_wasm_bindgen::to_value(&release_dto(&r))?)
    }
}
