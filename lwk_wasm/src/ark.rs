//! Arca leaves for the wasm bindings: keys, records, verification and a store.
//!
//! A page can be handed a leaf's record and the round transaction, and say
//! with no server trusted whether the leaf is real and what it holds.
//!
//! Byte order at this edge: asset ids, the sweep token and the genesis hash
//! are display hex, as the node's RPCs print them; they enter scripts and
//! hashes in internal order, the reverse. Leaf ids, owner nonces, keys and
//! transactions have one order only and are hex of their bytes. A record is
//! its JSON text (which begins `{`) or its binary form as hex.
//!
//! ```js
//! const verifier = new ArkVerifier(network, { operator });
//! const now = tip.mediantime;   // the chain source's median time, at each call
//! const leaf = verifier.verifyLeaf(record, roundTxHex, ownerKeyHex, ownerNonceHex, now);
//! if (!leaf.accepted) console.log(leaf.failed, leaf.reason);   // "check 3", "check 3: ..."
//! ```

use std::str::FromStr;
use std::sync::Arc;

use lwk_wollet::ark::keys::{self, OwnerNonce};
use lwk_wollet::ark::store::ArkStore as Store;
use lwk_wollet::ark::verify::{self, Recheck, VerifiedLeaf, VerifyError};
use lwk_wollet::ark::{Chain, LeafRecord, MedianTime, RecordError, RelativeTime, WalletPolicy};
use lwk_wollet::elements::hex::{FromHex, ToHex};
use lwk_wollet::elements::secp256k1_zkp::XOnlyPublicKey;
use lwk_wollet::elements::{encode, Transaction};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Error, JsStorage, JsStoreLink, Network, Signer};

fn generic(e: impl std::fmt::Display) -> Error {
    Error::Generic(e.to_string())
}

fn refused(e: &RecordError) -> Error {
    Error::Generic(format!("record refused (kind {}): {e}", e.kind()))
}

/// A record from its JSON text or its binary form as hex.
pub(crate) fn parse_record(text: &str) -> Result<LeafRecord, RecordError> {
    let t = text.trim();
    if t.starts_with('{') {
        LeafRecord::from_json_str(t)
    } else {
        let bytes = Vec::<u8>::from_hex(t).map_err(|_| RecordError::Hex("record".into()))?;
        LeafRecord::from_bytes(&bytes)
    }
}

fn nonce(hex: &str) -> Result<OwnerNonce, Error> {
    Vec::<u8>::from_hex(hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| generic("an owner nonce is 32 bytes of hex"))
}

fn xonly(hex: &str, what: &str) -> Result<XOnlyPublicKey, Error> {
    XOnlyPublicKey::from_str(hex).map_err(|e| generic(format!("invalid {what}: {e}")))
}

fn transaction(hex: &str) -> Result<Transaction, Error> {
    let bytes = Vec::<u8>::from_hex(hex).map_err(|e| generic(format!("invalid round hex: {e}")))?;
    Ok(encode::deserialize(&bytes)?)
}

/// A fresh random owner nonce, 32 bytes as hex, for a leaf the wallet asks
/// for or publishes in a receive request. Each leaf gets its own, and with it
/// its own key.
#[wasm_bindgen(js_name = arkNewOwnerNonce)]
pub fn ark_new_owner_nonce() -> String {
    keys::new_owner_nonce().to_hex()
}

/// The path of the key for the leaf whose owner nonce is `ownerNonceHex`:
/// `m/6'/account'/c1'/c2'/c3'/c4'`, from `SHA256("Arca/key" ‖ owner_nonce)`.
#[wasm_bindgen(js_name = arkLeafKeyPath)]
pub fn ark_leaf_key_path(account: u32, owner_nonce_hex: &str) -> Result<String, Error> {
    let path = keys::leaf_key_path(account, &nonce(owner_nonce_hex)?).map_err(generic)?;
    Ok(format!("m/{path}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LeafKeyDto {
    owner_nonce: String,
    account: u32,
    path: String,
    key: String,
}

impl From<keys::LeafKey> for LeafKeyDto {
    fn from(k: keys::LeafKey) -> Self {
        LeafKeyDto {
            owner_nonce: k.owner_nonce.to_hex(),
            account: k.account,
            path: format!("m/{}", k.path),
            key: k.key.serialize().to_hex(),
        }
    }
}

#[wasm_bindgen]
impl Signer {
    /// The key for the leaf whose owner nonce is `ownerNonceHex`:
    /// `{ ownerNonce, account, path, key }`, the key x-only hex as the leaf's
    /// scripts name it.
    #[wasm_bindgen(js_name = arkLeafKey)]
    pub fn ark_leaf_key(&self, account: u32, owner_nonce_hex: &str) -> Result<JsValue, Error> {
        let k = keys::leaf_key(&self.inner, account, &nonce(owner_nonce_hex)?).map_err(generic)?;
        Ok(serde_wasm_bindgen::to_value(&LeafKeyDto::from(k))?)
    }

    /// The key for `record`, rebuilt from the owner nonce in it and refused
    /// unless it is the record's owner key: how a wallet restored from its
    /// mnemonic finds its leaves among the records a server returns.
    #[wasm_bindgen(js_name = arkRestoreKey)]
    pub fn ark_restore_key(&self, account: u32, record: &str) -> Result<JsValue, Error> {
        let record = parse_record(record).map_err(|e| refused(&e))?;
        let k = keys::restore_key(&self.inner, account, &record).map_err(generic)?;
        Ok(serde_wasm_bindgen::to_value(&LeafKeyDto::from(k))?)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDto {
    leaf_id: String,
    template: String,
    hex: String,
    json: String,
    owner: String,
    owner_nonce: String,
    operator_nonce: String,
    asset: String,
    value: String,
    entry_reserve: String,
    unlock_hash: String,
    genesis_hash: String,
    operator: String,
    token: String,
    notice_seconds: u64,
    expiries: Vec<u32>,
    exit_delay_seconds: u64,
    burn: bool,
    position: Vec<u8>,
}

/// Read a leaf's record, given as JSON text or as its binary form in hex,
/// and give its fields: `{ leafId, template, hex, json, owner, ownerNonce,
/// operatorNonce, asset, value, entryReserve, unlockHash, genesisHash,
/// operator, token, noticeSeconds, expiries, exitDelaySeconds, burn,
/// position }`. Asset ids, the token and the genesis hash are display hex,
/// amounts decimal strings. Refuses a record that does not decode, naming the
/// kind of error as the Arca vectors do.
#[wasm_bindgen(js_name = arkParseRecord)]
pub fn ark_parse_record(record: &str) -> Result<JsValue, Error> {
    let r = parse_record(record).map_err(|e| refused(&e))?;
    let leaf_id = r.leaf_id().map_err(|e| refused(&e))?;
    let dto = RecordDto {
        leaf_id: leaf_id.to_string(),
        template: r.template.to_string(),
        hex: r.to_bytes().map_err(|e| refused(&e))?.to_hex(),
        json: r.to_json_string().map_err(|e| refused(&e))?,
        owner: r.owner.serialize().to_hex(),
        owner_nonce: r.owner_nonce.to_hex(),
        operator_nonce: r.operator_nonce.to_hex(),
        asset: r.asset.to_string(),
        value: r.value.to_string(),
        entry_reserve: r.entry_reserve.to_string(),
        unlock_hash: r.unlock_hash.to_hex(),
        genesis_hash: r.chain.genesis_hash().to_string(),
        operator: r.operator().serialize().to_hex(),
        token: r.schedule.token.to_string(),
        notice_seconds: r.schedule.notice.seconds(),
        expiries: r
            .schedule
            .expiries()
            .iter()
            .map(|e| e.to_consensus_u32())
            .collect(),
        exit_delay_seconds: r.exit_delay.seconds(),
        burn: r.burn,
        position: r.position(),
    };
    Ok(serde_wasm_bindgen::to_value(&dto)?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyDto {
    operator: String,
    /// Refused when present: `now` is given to each call. Named here because
    /// an object read from JavaScript ignores fields the struct does not name.
    now: Option<serde::de::IgnoredAny>,
    min_notice_seconds: Option<u64>,
    horizon_seconds: Option<u32>,
    min_exit_delay_seconds: Option<u64>,
    max_exit_delay_seconds: Option<u64>,
}

fn relative(seconds: u64, what: &str) -> Result<RelativeTime, Error> {
    RelativeTime::from_seconds_ceil(seconds).map_err(|e| generic(format!("{what}: {e}")))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerdictDto {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    round_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaced: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_round_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_vout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiries: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notice_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_delay_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_deadline: Option<u32>,
}

impl VerdictDto {
    fn empty(accepted: bool) -> Self {
        VerdictDto {
            accepted,
            failed: None,
            check: None,
            kind: None,
            reason: None,
            owned: None,
            leaf_id: None,
            round_txid: None,
            replaced: None,
            previous_round_txid: None,
            batch_vout: None,
            asset: None,
            value: None,
            expiries: None,
            notice_seconds: None,
            exit_delay_seconds: None,
            exit_deadline: None,
        }
    }

    fn accepted(v: &VerifiedLeaf) -> Self {
        VerdictDto {
            owned: Some(v.owned),
            leaf_id: Some(v.leaf_id.to_string()),
            round_txid: Some(v.round_txid.to_string()),
            batch_vout: Some(v.batch_vout),
            asset: Some(v.asset.to_string()),
            value: Some(v.value.to_string()),
            expiries: Some(v.expiries.iter().map(|e| e.to_consensus_u32()).collect()),
            notice_seconds: Some(v.notice.seconds()),
            exit_delay_seconds: Some(v.exit_delay.seconds()),
            exit_deadline: Some(v.exit_deadline()),
            ..VerdictDto::empty(true)
        }
    }

    fn refused(e: &VerifyError) -> Self {
        VerdictDto {
            failed: Some(e.failed()),
            check: e.check(),
            kind: Some(e.0.kind().to_string()),
            reason: Some(e.to_string()),
            ..VerdictDto::empty(false)
        }
    }

    fn unreadable(e: &RecordError) -> Self {
        VerdictDto {
            failed: Some("record".into()),
            kind: Some(e.kind().to_string()),
            reason: Some(format!("record: {e}")),
            ..VerdictDto::empty(false)
        }
    }
}

/// Verifies Arca leaves for a wallet: its network (whose genesis hash binds
/// every leaf to its chain) and its policy.
///
/// The policy object is `{ operator, minNoticeSeconds?, horizonSeconds?,
/// minExitDelaySeconds?, maxExitDelaySeconds? }`: the operator key the wallet
/// was told (x-only hex) and the bounds, which default to the specification's
/// (a notice of at least 36 hours, a first expiry at least 27 days after now
/// for a leaf taken from a round, an exit delay of 36 to 48 hours). Every
/// method takes `now`, the median time the wallet's chain source gives at
/// the time of the call, so a verifier kept for a long time never applies a
/// stale time.
///
/// `verifyLeaf` is for a leaf the wallet takes from a round it joins, and
/// applies the horizon. `verifyRound` (a leaf the wallet is given) and
/// `recheck` (a leaf it holds) need only the exit deadline: a first expiry
/// at least three days after now.
///
/// A verdict is `{ accepted: true, owned, leafId, roundTxid, batchVout,
/// asset, value, expiries, noticeSeconds, exitDelaySeconds, exitDeadline }`
/// or `{ accepted: false, failed, check, kind, reason }`, where `failed` is
/// `check 1` to `check 5`, `batch output`, `wallet policy`, `owner` or
/// `record`. An accepted leaf is not a final one: whether its round is
/// certified and its Bitcoin anchor buried is for the wallet's chain source
/// to say. After any rollback that disconnects the round, check again with
/// `recheck`.
#[wasm_bindgen]
pub struct ArkVerifier {
    /// The wallet's policy. Its `now` is replaced on every call ([`Self::at`]).
    policy: WalletPolicy,
}

/// The parsed inputs for the wallet's own leaf, or the verdict refusing a
/// record that does not decode.
type Own = Result<(LeafRecord, Transaction, XOnlyPublicKey, OwnerNonce), VerdictDto>;

#[wasm_bindgen]
impl ArkVerifier {
    /// A verifier for `network` with the `policy` object described above.
    #[wasm_bindgen(constructor)]
    pub fn new(network: &Network, policy: JsValue) -> Result<ArkVerifier, Error> {
        let dto: PolicyDto = serde_wasm_bindgen::from_value(policy)?;
        if dto.now.is_some() {
            return Err(generic(
                "the policy takes no `now`: give the chain's median time to each call",
            ));
        }
        let net: lwk_common::Network = network.into();
        // A placeholder: every use goes through `at`, which sets the caller's.
        let unset = MedianTime::from_consensus(500_000_000).map_err(generic)?;
        let mut policy = WalletPolicy::new(
            Chain::new(net.genesis_hash()),
            xonly(&dto.operator, "operator key")?,
            unset,
        );
        if let Some(s) = dto.min_notice_seconds {
            policy.min_notice = relative(s, "minNoticeSeconds")?;
        }
        if let Some(s) = dto.horizon_seconds {
            policy.horizon = s;
        }
        if let Some(s) = dto.min_exit_delay_seconds {
            policy.min_exit_delay = relative(s, "minExitDelaySeconds")?;
        }
        if let Some(s) = dto.max_exit_delay_seconds {
            policy.max_exit_delay = relative(s, "maxExitDelaySeconds")?;
        }
        Ok(ArkVerifier { policy })
    }

    /// The policy at median time `now`.
    fn at(&self, now: u32) -> Result<WalletPolicy, Error> {
        Ok(WalletPolicy {
            now: MedianTime::from_consensus(now).map_err(|e| generic(format!("now: {e}")))?,
            ..self.policy
        })
    }

    fn parse_own(
        record: &str,
        round_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
    ) -> Result<Own, Error> {
        let round = transaction(round_hex)?;
        let owner = xonly(owner_key_hex, "owner key")?;
        let owner_nonce = nonce(owner_nonce_hex)?;
        Ok(match parse_record(record) {
            Ok(r) => Ok((r, round, owner, owner_nonce)),
            Err(e) => Err(VerdictDto::unreadable(&e)),
        })
    }

    /// The wallet's own leaf taken from a round, verified at `now`.
    fn own(
        &self,
        record: &str,
        round_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<Result<(LeafRecord, VerifiedLeaf), VerdictDto>, Error> {
        let policy = self.at(now)?;
        Ok(
            match Self::parse_own(record, round_hex, owner_key_hex, owner_nonce_hex)? {
                Err(refusal) => Err(refusal),
                Ok((record, round, owner, owner_nonce)) => {
                    match verify::verify_leaf(&record, &round, &policy, &owner, &owner_nonce) {
                        Ok(v) => Ok((record, v)),
                        Err(e) => Err(VerdictDto::refused(&e)),
                    }
                }
            },
        )
    }

    /// The wallet's own leaf checked again at `now`, against the round it
    /// was last verified against, `previous`.
    fn own_again(
        &self,
        previous: &lwk_wollet::elements::Txid,
        record: &str,
        round_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<Result<Recheck, VerdictDto>, Error> {
        let policy = self.at(now)?;
        Ok(
            match Self::parse_own(record, round_hex, owner_key_hex, owner_nonce_hex)? {
                Err(refusal) => Err(refusal),
                Ok((record, round, owner, owner_nonce)) => {
                    verify::recheck(previous, &record, &round, &policy, &owner, &owner_nonce)
                        .map_err(|e| VerdictDto::refused(&e))
                }
            },
        )
    }

    /// Verify the wallet's own leaf, taken from a round it joins: `record`
    /// against the round transaction `roundTxHex`, for the wallet's key
    /// `ownerKeyHex` and the owner nonce `ownerNonceHex` it picked for the
    /// leaf, at median time `now`.
    #[wasm_bindgen(js_name = verifyLeaf)]
    pub fn verify_leaf(
        &self,
        record: &str,
        round_tx_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<JsValue, Error> {
        let verdict = match self.own(record, round_tx_hex, owner_key_hex, owner_nonce_hex, now)? {
            Ok((_, v)) => VerdictDto::accepted(&v),
            Err(refusal) => refusal,
        };
        Ok(serde_wasm_bindgen::to_value(&verdict)?)
    }

    /// Verify a leaf the wallet does not own, such as the coin a sender is
    /// about to give it, at median time `now`: the same checks without the
    /// owner's key and nonce, and the exit deadline in place of the horizon.
    #[wasm_bindgen(js_name = verifyRound)]
    pub fn verify_round(
        &self,
        record: &str,
        round_tx_hex: &str,
        now: u32,
    ) -> Result<JsValue, Error> {
        let policy = self.at(now)?;
        let round = transaction(round_tx_hex)?;
        let verdict = match parse_record(record) {
            Err(e) => VerdictDto::unreadable(&e),
            Ok(r) => match verify::verify_round(&r, &round, &policy) {
                Ok(v) => VerdictDto::accepted(&v),
                Err(e) => VerdictDto::refused(&e),
            },
        };
        Ok(serde_wasm_bindgen::to_value(&verdict)?)
    }

    /// Check the wallet's own leaf again after a rollback, at median time
    /// `now`, against whichever transaction now pays its batch output, with
    /// the exit deadline in place of the horizon. The verdict adds `replaced`
    /// (and `previousRoundTxid`) when that is another transaction than
    /// `previousRoundTxid`. A refusal is an order to unroll at once.
    pub fn recheck(
        &self,
        previous_round_txid: &str,
        record: &str,
        round_tx_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<JsValue, Error> {
        let previous: lwk_wollet::elements::Txid = previous_round_txid
            .parse()
            .map_err(|e| generic(format!("previousRoundTxid: {e}")))?;
        let verdict = match self.own_again(
            &previous,
            record,
            round_tx_hex,
            owner_key_hex,
            owner_nonce_hex,
            now,
        )? {
            Err(refusal) => refusal,
            Ok(Recheck::Same(v)) => VerdictDto {
                replaced: Some(false),
                ..VerdictDto::accepted(&v)
            },
            Ok(Recheck::Replaced { previous, now: v }) => VerdictDto {
                replaced: Some(true),
                previous_round_txid: Some(previous.to_string()),
                ..VerdictDto::accepted(&v)
            },
        };
        Ok(serde_wasm_bindgen::to_value(&verdict)?)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredDto {
    leaf_id: String,
    record: String,
    round_txid: String,
    batch_vout: u32,
    preimage: Option<String>,
    unroll: Vec<lwk_wollet::ark::store::UnrollAuthorisation>,
}

/// The wallet's Arca leaves over a JavaScript storage object (see
/// `JsStorage`): each leaf's record and the round it was verified against,
/// the entry's unlock preimage, unroll authorisations, and the owner nonces
/// of leaves asked for whose records have not arrived. Every key it writes
/// begins `ark/`; no key is ever stored.
#[wasm_bindgen]
pub struct ArkStore {
    inner: Store,
}

#[wasm_bindgen]
impl ArkStore {
    /// An Arca store over `storage`.
    #[wasm_bindgen(constructor)]
    pub fn new(storage: JsStorage) -> ArkStore {
        ArkStore {
            inner: Store::new(Arc::new(JsStoreLink::new(storage))),
        }
    }

    /// Verify the wallet's own leaf, taken from a round it joins, with
    /// `verifier` at median time `now`, and keep it. Refuses a leaf that
    /// does not verify, naming what failed, and a second leaf under an owner
    /// nonce or key the store already holds. Returns the leaf id.
    #[wasm_bindgen(js_name = putLeaf)]
    pub fn put_leaf(
        &self,
        verifier: &ArkVerifier,
        record: &str,
        round_tx_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<String, Error> {
        match verifier.own(record, round_tx_hex, owner_key_hex, owner_nonce_hex, now)? {
            Err(refusal) => Err(generic(format!(
                "leaf refused: {}",
                refusal.reason.unwrap_or_default()
            ))),
            Ok((record, verified)) => {
                self.inner.put_leaf(&record, &verified).map_err(generic)?;
                Ok(verified.leaf_id.to_string())
            }
        }
    }

    /// Take a new round for a stored leaf after `recheck` accepted the
    /// transaction that replaced it: checks the leaf again at median time
    /// `now` against that transaction, as `recheck` does, then keeps the new
    /// round's txid.
    #[wasm_bindgen(js_name = setRound)]
    pub fn set_round(
        &self,
        verifier: &ArkVerifier,
        record: &str,
        round_tx_hex: &str,
        owner_key_hex: &str,
        owner_nonce_hex: &str,
        now: u32,
    ) -> Result<(), Error> {
        let parsed = parse_record(record).map_err(|e| refused(&e))?;
        let id = parsed.leaf_id().map_err(|e| refused(&e))?;
        let stored = self
            .inner
            .leaf(&id)
            .map_err(generic)?
            .ok_or_else(|| generic(format!("no leaf {id} in the store")))?;
        match verifier.own_again(
            &stored.round_txid,
            record,
            round_tx_hex,
            owner_key_hex,
            owner_nonce_hex,
            now,
        )? {
            Err(refusal) => Err(generic(format!(
                "leaf refused: {}",
                refusal.reason.unwrap_or_default()
            ))),
            Ok(Recheck::Same(v) | Recheck::Replaced { now: v, .. }) => {
                self.inner.set_round(&v).map_err(generic)
            }
        }
    }

    /// The ids of every stored leaf.
    #[wasm_bindgen(js_name = leafIds)]
    pub fn leaf_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self
            .inner
            .leaf_ids()
            .map_err(generic)?
            .iter()
            .map(|i| i.to_string())
            .collect())
    }

    /// A stored leaf: `{ leafId, record (JSON), roundTxid, batchVout,
    /// preimage, unroll }`, or `undefined`.
    pub fn leaf(&self, leaf_id: &str) -> Result<JsValue, Error> {
        let id = leaf_id.parse().map_err(|e: RecordError| generic(e))?;
        match self.inner.leaf(&id).map_err(generic)? {
            None => Ok(JsValue::UNDEFINED),
            Some(l) => Ok(serde_wasm_bindgen::to_value(&StoredDto {
                leaf_id: l.leaf_id.to_string(),
                record: l.record.to_json_string().map_err(generic)?,
                round_txid: l.round_txid.to_string(),
                batch_vout: l.batch_vout,
                preimage: l.preimage.map(|p| p.to_hex()),
                unroll: l.unroll,
            })?),
        }
    }

    /// Keep the entry's unlock preimage (32 bytes, hex). Refuses one that
    /// does not hash to the leaf's unlock hash.
    #[wasm_bindgen(js_name = putPreimage)]
    pub fn put_preimage(&self, leaf_id: &str, preimage_hex: &str) -> Result<(), Error> {
        let id = leaf_id.parse().map_err(|e: RecordError| generic(e))?;
        let p: [u8; 32] = Vec::<u8>::from_hex(preimage_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| generic("a preimage is 32 bytes of hex"))?;
        self.inner.put_preimage(&id, &p).map_err(generic)
    }

    /// Keep an unroll authorisation for the node at `level` on the leaf's
    /// path (0 is the batch output), usable from median time `time`, with the
    /// owner's 64-byte signature. Refuses one the record's owner key did not
    /// sign for that node and time.
    #[wasm_bindgen(js_name = putUnrollAuthorisation)]
    pub fn put_unroll_authorisation(
        &self,
        leaf_id: &str,
        level: u32,
        time: u32,
        signature_hex: &str,
    ) -> Result<(), Error> {
        let id = leaf_id.parse().map_err(|e: RecordError| generic(e))?;
        let t = MedianTime::from_consensus(time).map_err(generic)?;
        let sig = Vec::<u8>::from_hex(signature_hex).map_err(generic)?;
        self.inner
            .put_unroll_authorisation(&id, level as usize, t, &sig)
            .map_err(generic)
    }

    /// Forget a leaf.
    #[wasm_bindgen(js_name = removeLeaf)]
    pub fn remove_leaf(&self, leaf_id: &str) -> Result<(), Error> {
        let id = leaf_id.parse().map_err(|e: RecordError| generic(e))?;
        self.inner.remove_leaf(&id).map_err(generic)
    }

    /// Remember the owner nonce of a leaf asked for until its record arrives.
    #[wasm_bindgen(js_name = putPending)]
    pub fn put_pending(&self, owner_nonce_hex: &str, note: &str) -> Result<(), Error> {
        self.inner
            .put_pending(&nonce(owner_nonce_hex)?, note)
            .map_err(generic)
    }

    /// The owner nonces waited on: `[{ ownerNonce, note }]`.
    pub fn pending(&self) -> Result<JsValue, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct P {
            owner_nonce: String,
            note: String,
        }
        let p: Vec<P> = self
            .inner
            .pending()
            .map_err(generic)?
            .into_iter()
            .map(|(n, note)| P {
                owner_nonce: n.to_hex(),
                note,
            })
            .collect();
        Ok(serde_wasm_bindgen::to_value(&p)?)
    }
}
