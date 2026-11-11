//! OpenAMP restricted-asset client + enclave signing helpers.
//!
//! This is the SWK backing for the OpenAMP wallet integration
//! (`openamp/spec/venue-wallet-integration.md`). It is deliberately NOT a retrofit
//! of [`crate::amp2`]: AMP2 is descriptor-registered P2WSH multisig with
//! PSET-level cosign, architecturally unrelated. Only the async+blocking
//! `reqwest` client shape is reused.
//!
//! Two independent halves live here:
//!
//! 1. **Crypto helpers** (no network): the AID derivation (spec 0.2), the tagged
//!    hash used by every non-spending signature (spec 0.4(2)), and the MANDATORY
//!    client-side enclave-sighash recomputation + transaction decode (spec 0.4(3),
//!    work item SWK-6). These are the safety mechanism: a conforming wallet NEVER
//!    blind-signs a server-supplied enclave digest; it recomputes the Elements
//!    taproot sighash itself and shows the decoded effects before signing.
//!
//! 2. **A typed HTTP client** (`OpenampClient`) for the 0.3 endpoints and the 1.6
//!    hosted-transfer state machine (create -> to_sign -> sign locally -> complete).
//!
//! The enclave-spend signing itself is done from the wallet seed inside the wasm
//! `Signer` (SWK-1, deterministic BIP340, m/5/0); this module supplies the digest
//! that signer signs and never touches the secret.

use std::collections::BTreeMap;

use crate::elements::hashes::{sha256, Hash, HashEngine};
use crate::elements::hex::{FromHex, ToHex};
use crate::elements::sighash::{Prevouts, SchnorrSighashType, ScriptPath, SighashCache};
use crate::elements::{confidential, AssetId, BlockHash, Script, Transaction, TxOut};
use crate::error::Error;

use serde::{Deserialize, Serialize};

/// Tag prepended to the sorted pubkey set before hashing to the AID (spec 0.2).
const AID_TAG: &str = "openamp-aid-v1";

/// Tagged-hash tag for wallet-link and login challenges (spec 0.4(2)).
pub const TAG_CHALLENGE: &str = "openamp-challenge-v1";

/// Tagged-hash tag for document e-signatures (spec 0.4(2)).
pub const TAG_DOCUMENT: &str = "openamp-document-v1";

/// Whether a generic tagged-message signer may sign under `tag` for a site.
/// Every `openamp-` tag but the challenge and the document tags is refused:
/// those name statements openampd itself acts on (`openamp-cosign-v1`, a
/// sender's request for a co-sign; `openamp-dvp-v1`, a trade's expiry; and any
/// later one), and a wallet makes them only in its own flows, never because a
/// site asked (proof review PV5, T1).
pub fn check_site_tag(tag: &str) -> Result<(), Error> {
    let lower = tag.to_ascii_lowercase();
    if lower.starts_with("openamp-") && tag != TAG_CHALLENGE && tag != TAG_DOCUMENT {
        return Err(Error::Generic(format!(
            "refusing to sign under the OpenAMP protocol tag \"{tag}\": only {TAG_CHALLENGE} and {TAG_DOCUMENT} are signed for a site"
        )));
    }
    Ok(())
}

/// The BIP341 NUMS internal key of every enclave output (contract-v1 §4).
pub const ENCLAVE_NUMS_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// The Elements leaf version of enclave leaves (contract-v1 §4).
pub const ENCLAVE_LEAF_VERSION: u8 = 0xc4;

// ===========================================================================
// 0.2  AID
// ===========================================================================

/// Compute an OpenAMP AID from a set of x-only pubkeys, exactly matching Go
/// `store.AID` (`openampd/internal/store/store.go:258-268`):
///
/// `AID = hex(first 20 bytes of sha256("openamp-aid-v1" || pubkey-hex-strings
/// sorted lexicographically, concatenated as UTF-8))`.
///
/// Pubkeys are 64-hex BIP340 x-only keys; they are lowercased and sorted before
/// hashing. Registering a different key, or a second key, yields a different AID.
/// Clients MUST compute this locally and assert equality with the server's answer
/// (spec 1.3).
pub fn compute_aid(pubkeys: &[String]) -> String {
    let mut sorted: Vec<String> = pubkeys.iter().map(|p| p.trim().to_lowercase()).collect();
    sorted.sort();
    let mut engine = sha256::Hash::engine();
    engine.input(AID_TAG.as_bytes());
    for p in &sorted {
        engine.input(p.as_bytes());
    }
    let digest = sha256::Hash::from_engine(engine).to_byte_array();
    digest[..20].to_hex()
}

// ===========================================================================
// 0.4(2)  tagged hash
// ===========================================================================

/// The OpenAMP tagged hash (spec 0.4(2)):
/// `tagged_hash(tag, m) = sha256(sha256(tag) || sha256(tag) || m)`.
///
/// Note this is domain-separated from an enclave-spend sighash: producing a
/// signature valid as a transfer sighash from a tagged-hash-signing surface would
/// require a preimage of this hash. Used for challenges (`TAG_CHALLENGE`) and
/// document hashes (`TAG_DOCUMENT`).
pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

// ===========================================================================
// SWK-6  enclave sighash recomputation + decode (spec 0.4(3) — MANDATORY)
// ===========================================================================

/// A transaction prevout as the wallet knows it: explicit asset id, explicit
/// value (atoms), and the scriptPubKey. Every restricted-asset transaction is
/// transparent (spec 0.6), so these are always explicit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclavePrevout {
    /// The prevout's asset id, display hex.
    pub asset: String,
    /// The prevout's explicit value, atoms.
    pub value: u64,
    /// The prevout's scriptPubKey, hex.
    pub script: String,
}

impl EnclavePrevout {
    fn to_txout(&self) -> Result<TxOut, Error> {
        let asset = AssetId::from_str_checked(&self.asset)?;
        let spk = Script::from(Vec::<u8>::from_hex(&self.script)?);
        Ok(TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(self.value),
            nonce: confidential::Nonce::Null,
            script_pubkey: spk,
            witness: Default::default(),
        })
    }
}

// Small helper: AssetId from display hex, mapping the error into ours.
trait AssetIdExt {
    fn from_str_checked(s: &str) -> Result<AssetId, Error>;
}
impl AssetIdExt for AssetId {
    fn from_str_checked(s: &str) -> Result<AssetId, Error> {
        use std::str::FromStr;
        AssetId::from_str(s).map_err(|e| Error::Generic(format!("invalid asset id {s}: {e}")))
    }
}

/// Recompute the Elements taproot script-path sighash (SIGHASH_DEFAULT,
/// genesis-committed) for a foreign NUMS enclave input, exactly as openampd does
/// (`transfer.go:485-493`). This is the digest the wallet signs, and the wallet
/// MUST use its OWN recomputed value, refusing to sign if it differs from the
/// server's `to_sign` (spec 0.4(3)).
///
/// The leaf version is recovered from the control block's first byte with the
/// parity bit cleared (identical to the covenant precedent,
/// `seqob_covenant.rs:621`), which for an enclave leaf is `0xc4`.
#[allow(clippy::too_many_arguments)]
pub fn enclave_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_script: &Script,
    control_block: &[u8],
    genesis_hash: BlockHash,
) -> Result<[u8; 32], Error> {
    if control_block.is_empty() {
        return Err(Error::Generic("enclave control block is empty".into()));
    }
    if input_index >= tx.input.len() {
        return Err(Error::Generic(format!(
            "input index {input_index} out of range ({} inputs)",
            tx.input.len()
        )));
    }
    if prevouts.len() != tx.input.len() {
        return Err(Error::Generic(format!(
            "prevouts ({}) must align with inputs ({})",
            prevouts.len(),
            tx.input.len()
        )));
    }
    let leaf_version = control_block[0] & 0xfe;
    let script_path = ScriptPath::new(leaf_script, 0xFFFF_FFFF, leaf_version);
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            script_path,
            SchnorrSighashType::Default,
            genesis_hash,
        )
        .map_err(|e| Error::Generic(format!("enclave tapscript sighash: {e}")))?;
    Ok(sighash.to_byte_array())
}

/// One decoded input of a candidate enclave spend.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedInput {
    /// Input index in the transaction.
    pub index: u32,
    /// Prevout txid, display hex.
    pub txid: String,
    /// Prevout vout.
    pub vout: u32,
    /// Prevout asset id (display hex) if the prevout was supplied.
    pub asset: Option<String>,
    /// Prevout value (atoms) if the prevout was supplied.
    pub value: Option<u64>,
    /// True when the prevout scriptPubKey is one of MY enclave scripts.
    pub mine: bool,
}

/// One decoded output of a candidate enclave spend.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedOutput {
    /// Output index in the transaction.
    pub index: u32,
    /// Explicit asset id (display hex), or `None` if the output is confidential.
    pub asset: Option<String>,
    /// Explicit value (atoms), or `None` if the output is confidential.
    pub value: Option<u64>,
    /// The output scriptPubKey, hex (empty for the Elements fee output).
    pub script: String,
    /// True for the explicit Elements fee output (empty scriptPubKey).
    pub is_fee: bool,
    /// True when this output pays one of MY enclave scripts (a receipt to me).
    pub mine: bool,
}

/// The human-readable effects of a candidate enclave spend, shown to the user
/// BEFORE signing (spec 0.4(3)): which of my UTXOs are spent, what each output
/// pays and to whom, and which outputs are receipts back to me.
#[derive(Debug, Clone, Serialize)]
pub struct EnclaveSpendEffects {
    /// The transaction id.
    pub txid: String,
    /// Every input, with `mine` set for my enclave prevouts.
    pub inputs: Vec<DecodedInput>,
    /// Every output, with `mine` set for receipts to my enclave scripts.
    pub outputs: Vec<DecodedOutput>,
    /// Indices of the inputs that spend MY enclave UTXOs.
    pub my_inputs_spent: Vec<u32>,
    /// True if ANY output anywhere is confidential (a red flag: restricted-asset
    /// spends must be fully transparent, spec 2.4/0.6).
    pub any_confidential: bool,
}

/// Decode a candidate enclave-spend transaction into the effects a wallet must
/// display before signing (spec 0.4(3), work item SWK-6). `my_scripts` is the set
/// of MY enclave scriptPubKeys (hex) across the assets I hold; a prevout or output
/// matching one is flagged `mine`. `prevouts` aligns with the transaction inputs.
pub fn decode_enclave_spend(
    tx: &Transaction,
    prevouts: &[TxOut],
    my_scripts: &[String],
) -> Result<EnclaveSpendEffects, Error> {
    let mine: std::collections::BTreeSet<String> =
        my_scripts.iter().map(|s| s.trim().to_lowercase()).collect();

    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut my_inputs_spent = Vec::new();
    for (i, txin) in tx.input.iter().enumerate() {
        let prevout = prevouts.get(i);
        let (asset, value, is_mine) = match prevout {
            Some(o) => {
                let asset = match o.asset {
                    confidential::Asset::Explicit(a) => Some(a.to_string()),
                    _ => None,
                };
                let value = match o.value {
                    confidential::Value::Explicit(v) => Some(v),
                    _ => None,
                };
                let spk = o.script_pubkey.as_bytes().to_hex();
                (asset, value, mine.contains(&spk))
            }
            None => (None, None, false),
        };
        if is_mine {
            my_inputs_spent.push(i as u32);
        }
        inputs.push(DecodedInput {
            index: i as u32,
            txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
            asset,
            value,
            mine: is_mine,
        });
    }

    let mut outputs = Vec::with_capacity(tx.output.len());
    let mut any_confidential = false;
    for (i, o) in tx.output.iter().enumerate() {
        let asset = match o.asset {
            confidential::Asset::Explicit(a) => Some(a.to_string()),
            _ => {
                any_confidential = true;
                None
            }
        };
        let value = match o.value {
            confidential::Value::Explicit(v) => Some(v),
            _ => {
                any_confidential = true;
                None
            }
        };
        let spk = o.script_pubkey.as_bytes().to_hex();
        outputs.push(DecodedOutput {
            index: i as u32,
            asset,
            value,
            script: spk.clone(),
            is_fee: o.is_fee(),
            mine: mine.contains(&spk),
        });
    }

    Ok(EnclaveSpendEffects {
        txid: tx.txid().to_string(),
        inputs,
        outputs,
        my_inputs_spent,
        any_confidential,
    })
}

/// Convenience: parse `EnclavePrevout` records into `TxOut`s (input order).
pub fn prevouts_to_txouts(prevouts: &[EnclavePrevout]) -> Result<Vec<TxOut>, Error> {
    prevouts.iter().map(EnclavePrevout::to_txout).collect()
}

// ===========================================================================
// SWK-2  typed HTTP client + hosted-transfer state machine
// ===========================================================================

/// A registered user's record (spec 0.3 `GET /v1/users/{aid}`). `categories` and
/// `frozen` are `omitempty` server-side, so they are defaulted (no categories,
/// not frozen) when absent — never treated as an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenampUser {
    /// The AID.
    pub aid: String,
    /// The registered x-only pubkeys (64-hex).
    #[serde(default)]
    pub pubkeys: Vec<String>,
    /// The holder's granted categories (empty when omitted).
    #[serde(default)]
    pub categories: Vec<String>,
    /// Global freeze flag (false when omitted).
    #[serde(default)]
    pub frozen: bool,
}

/// A per-asset enclave deposit address (spec 0.3 `GET /v1/users/{aid}/address`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveAddress {
    /// The tb1 P2TR (or blech32 confidential) enclave address.
    pub address: String,
    /// The enclave scriptPubKey, hex.
    pub script_pubkey: String,
    /// The holder's x-only pubkey committed in the transfer leaf, 64-hex.
    pub user_pubkey: String,
    /// The transfer leaf script, hex (`<K_user> CHECKSIGVERIFY <K_policy> CHECKSIG`).
    pub transfer_leaf: String,
    /// The transfer-leaf control block, hex.
    pub transfer_control: String,
    /// The clawback leaf script, hex (present iff the asset has clawback).
    #[serde(default)]
    pub claw_leaf: Option<String>,
    /// The clawback-leaf control block, hex.
    #[serde(default)]
    pub claw_control: Option<String>,
    /// Whether the address is a confidential (blech32) address.
    #[serde(default)]
    pub confidential: bool,
}

/// A confirmed enclave balance (spec 0.3 `GET /v1/users/{aid}/balance`). `atoms`
/// is confirmed-only; `utxos` is a COUNT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveBalance {
    /// The AID.
    pub aid: String,
    /// The asset id, display hex.
    pub asset: String,
    /// Confirmed atoms.
    pub atoms: u64,
    /// UTXO count (not a value).
    #[serde(default)]
    pub utxos: u64,
}

/// One enclave input the wallet is asked to sign in a hosted transfer draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToSign {
    /// Transaction input index.
    pub input: u32,
    /// The server's computed sighash, 32-byte hex — a CROSS-CHECK, never the thing
    /// the wallet signs (spec 0.4(1),(3)).
    pub sighash: String,
    /// The x-only pubkey the signature must verify under, 64-hex.
    pub pubkey: String,
}

/// A hosted-transfer draft (spec 1.6 `POST /v1/transfers`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDraft {
    /// The volatile draft id (15-minute TTL; 404 => rebuild).
    pub id: String,
    /// The full unsigned transaction, hex — supplied so the client can recompute
    /// every sighash locally (spec 0.5(7)).
    pub tx: String,
    /// The enclave inputs the sender must sign.
    #[serde(default)]
    pub to_sign: Vec<ToSign>,
    /// The atoms of the fee taken in the transacted asset under `fee_mode:convert`.
    #[serde(default)]
    pub convert_atoms: u64,
    /// The equivalent network fee in sats.
    #[serde(default)]
    pub fee_sats: u64,
}

/// The result of completing a hosted transfer (spec 1.6 `/complete`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResult {
    /// The broadcast transaction id.
    pub txid: String,
}

#[derive(Serialize)]
struct RegisterUsersRequest {
    pubkeys: Vec<String>,
}

#[derive(Deserialize)]
struct RegisterUsersResponse {
    aid: String,
}

#[derive(Serialize)]
struct CreateTransferRequest {
    asset: String,
    sender_aid: String,
    recipient_aid: String,
    // atoms is a JSON NUMBER (uint64); openampd rejects strings (spec 0.4(5),
    // transfer.go:291). Serialized as a bare u64 here, never a string.
    atoms: u64,
    fee_mode: String,
}

#[derive(Serialize)]
struct CompleteTransferRequest {
    // keyed by input index as a DECIMAL STRING (spec 0.4(5), transfer.go:515-580).
    sigs: BTreeMap<String, String>,
}

/// A typed OpenAMP HTTP client for the 0.3 endpoints and the 1.6 hosted-transfer
/// state machine. Mirrors the async+blocking `reqwest` shape of [`crate::amp2`]
/// (nothing else). All endpoints are public except the platform-only issuer path,
/// which wallets never touch.
#[derive(Debug, Clone)]
pub struct OpenampClient {
    base_url: String,
}

impl OpenampClient {
    /// Create a client for a base URL (for example `https://sequentiatestnet.com/openamp`).
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.base_url, path.trim_start_matches('/'))
    }
}

// The async client compiles on every target (wasm uses it). The blocking mirror
// is native-only, matching amp2.rs.
impl OpenampClient {
    /// Register (idempotent) a set of pubkeys and return the server AID. The
    /// caller MUST assert this equals [`compute_aid`] of the same pubkeys.
    pub async fn register_user(&self, pubkeys: Vec<String>) -> Result<String, Error> {
        let body = RegisterUsersRequest { pubkeys };
        let r: RegisterUsersResponse = reqwest::Client::new()
            .post(self.url("users"))
            .json(&body)
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?;
        Ok(r.aid)
    }

    /// Fetch a user record; `categories`/`frozen` default when omitted.
    pub async fn get_user(&self, aid: &str) -> Result<OpenampUser, Error> {
        Ok(reqwest::Client::new()
            .get(self.url(&format!("users/{aid}")))
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }

    /// Fetch the per-asset enclave deposit address.
    pub async fn get_address(&self, aid: &str, asset: &str) -> Result<EnclaveAddress, Error> {
        Ok(reqwest::Client::new()
            .get(self.url(&format!("users/{aid}/address")))
            .query(&[("asset", asset)])
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }

    /// Fetch the confirmed enclave balance for one asset.
    pub async fn get_balance(&self, aid: &str, asset: &str) -> Result<EnclaveBalance, Error> {
        Ok(reqwest::Client::new()
            .get(self.url(&format!("users/{aid}/balance")))
            .query(&[("asset", asset)])
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }

    /// Fetch the full asset record (rules + contract with the openamp block).
    pub async fn get_asset(&self, asset: &str) -> Result<serde_json::Value, Error> {
        Ok(reqwest::Client::new()
            .get(self.url(&format!("assets/{asset}")))
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }

    /// Fetch all asset records.
    pub async fn get_assets(&self) -> Result<serde_json::Value, Error> {
        Ok(reqwest::Client::new()
            .get(self.url("assets"))
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }

    /// Create a hosted transfer draft. `atoms` is sent as a JSON NUMBER.
    pub async fn create_transfer(
        &self,
        asset: &str,
        sender_aid: &str,
        recipient_aid: &str,
        atoms: u64,
        fee_mode: &str,
    ) -> Result<TransferDraft, Error> {
        let body = CreateTransferRequest {
            asset: asset.to_string(),
            sender_aid: sender_aid.to_string(),
            recipient_aid: recipient_aid.to_string(),
            atoms,
            fee_mode: fee_mode.to_string(),
        };
        let resp = reqwest::Client::new()
            .post(self.url("transfers"))
            .json(&body)
            .send()
            .await
            .map_err(reqwest_err)?;
        let status = resp.status();
        let text = resp.text().await.map_err(reqwest_err)?;
        if !status.is_success() {
            return Err(Error::Generic(format!(
                "create_transfer {}: {}",
                status.as_u16(),
                text
            )));
        }
        serde_json::from_str(&text).map_err(Error::from)
    }

    /// Complete a hosted transfer with signatures keyed by decimal input index.
    /// Surfaces a 403 refusal reason verbatim; a 404 means the draft expired.
    pub async fn complete_transfer(
        &self,
        id: &str,
        sigs: BTreeMap<String, String>,
    ) -> Result<TransferResult, Error> {
        let body = CompleteTransferRequest { sigs };
        let resp = reqwest::Client::new()
            .post(self.url(&format!("transfers/{id}/complete")))
            .json(&body)
            .send()
            .await
            .map_err(reqwest_err)?;
        let status = resp.status();
        let text = resp.text().await.map_err(reqwest_err)?;
        if !status.is_success() {
            return Err(Error::Generic(format!(
                "complete_transfer {}: {}",
                status.as_u16(),
                text
            )));
        }
        serde_json::from_str(&text).map_err(Error::from)
    }

    /// Fetch the hash-chained transparency log.
    pub async fn get_log(&self) -> Result<serde_json::Value, Error> {
        Ok(reqwest::Client::new()
            .get(self.url("log"))
            .send()
            .await
            .map_err(reqwest_err)?
            .json()
            .await
            .map_err(reqwest_err)?)
    }
}

fn reqwest_err(e: reqwest::Error) -> Error {
    Error::Generic(format!("openamp http error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SWK-T (a): AID vector, identical to Go store.AID --------------------
    #[test]
    fn aid_matches_go_store_aid_single_key() {
        // Fixed x-only pubkey; the AID is sha256("openamp-aid-v1" || hex) first 20.
        let pk = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let aid = compute_aid(&[pk.to_string()]);
        // Independently computed reference (see openamp/spec 0.2; single-key set).
        let mut engine = sha256::Hash::engine();
        engine.input(AID_TAG.as_bytes());
        engine.input(pk.as_bytes());
        let digest = sha256::Hash::from_engine(engine).to_byte_array();
        let expected = digest[..20].to_hex();
        assert_eq!(aid, expected);
        assert_eq!(aid.len(), 40);
    }

    #[test]
    fn aid_is_sorted_set_and_case_insensitive() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        // Order and case must not matter (sorted, lowercased).
        let aid1 = compute_aid(&[a.clone(), b.clone()]);
        let aid2 = compute_aid(&[b.clone(), a.to_uppercase()]);
        assert_eq!(aid1, aid2);
        // A different set (single vs two keys) differs.
        assert_ne!(aid1, compute_aid(&[a]));
    }

    #[test]
    #[ignore = "prints goldens for SWK-T (b)/(d); run with --nocapture to regenerate"]
    fn print_goldens() {
        use crate::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        use crate::elements::{
            confidential, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction,
            TxIn, TxInWitness, TxOut, Txid,
        };
        use std::str::FromStr;

        // (b) deterministic BIP340 signature over a fixed digest with a fixed key.
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let digest = [0x22u8; 32];
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp);
        println!("SIG_XONLY={}", xonly.serialize().to_hex());
        println!("SIG_128HEX={}", sig.serialize().to_hex());

        // (d) enclave sighash over a fixed tx + prevout + enclave transfer leaf.
        let nums = ENCLAVE_NUMS_HEX; // internal key (unused by sighash directly)
        let _ = nums;
        let asset = AssetId::from_slice(&[0x01u8; 32]).unwrap();
        let value = 100_000u64;
        // Fixed enclave scriptPubKey (a 32-byte v1 program) as the prevout spk.
        let spk = Script::from(
            Vec::<u8>::from_hex(
                "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        );
        // Fixed transfer leaf: <K_user> CHECKSIGVERIFY <K_policy> CHECKSIG, 0xc4.
        // transfer leaf: <32B K_user> CHECKSIGVERIFY <32B K_policy> CHECKSIG
        let mut leaf_bytes = vec![0x20u8];
        leaf_bytes.extend_from_slice(&[0xbbu8; 32]);
        leaf_bytes.push(0xad); // OP_CHECKSIGVERIFY
        leaf_bytes.push(0x20);
        leaf_bytes.extend_from_slice(&[0xccu8; 32]);
        leaf_bytes.push(0xac); // OP_CHECKSIG
        let leaf = Script::from(leaf_bytes);
        // Control block: 0xc4 (leaf version, even parity) || NUMS internal key.
        let mut cb = vec![ENCLAVE_LEAF_VERSION];
        cb.extend_from_slice(&Vec::<u8>::from_hex(ENCLAVE_NUMS_HEX).unwrap());
        let genesis =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000042")
                .unwrap();
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"11".repeat(32)).unwrap(), 0),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(value - 1000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: spk.clone(),
                    witness: Default::default(),
                },
                TxOut::new_fee(1000, asset),
            ],
        };
        let prevout = TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey: spk,
            witness: Default::default(),
        };
        let sighash = enclave_sighash(&tx, 0, &[prevout], &leaf, &cb, genesis).unwrap();
        println!("ENCLAVE_SIGHASH={}", sighash.to_hex());
    }

    // ---- SWK-T (b): deterministic BIP340 signature vector --------------------
    // Fixed key (secret = 0x11*32) over fixed digest (0x22*32), aux_rand = zeros.
    // This is the byte form Ambra's `openamp_sign_sighash` must reproduce, and the
    // form `Signer.openampSignSighash` produces. Regenerate via `print_goldens`.
    #[test]
    fn deterministic_bip340_signature_vector() {
        use crate::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let digest = [0x22u8; 32];
        let sig = secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
            .serialize()
            .to_hex();
        assert_eq!(
            sig,
            "2600b9fff18847ba6486b575d70623f929cabecd7050c050da42f8e9a72f02ef8a73403ed1f92f1868e0077fc15a8e2528c09f5a2e9579a4859123ee3ad497e8",
            "deterministic BIP340 signature drifted"
        );
    }

    // ---- SWK-T (d): enclave-sighash recomputation vector ---------------------
    // A fixed tx + prevout + enclave transfer leaf (0xc4, NUMS) whose recomputed
    // Elements taproot sighash is pinned; this is what makes 0.4(3) enforceable
    // (the wallet refuses to sign anything whose digest it cannot reproduce). The
    // pinned value must equal the digest openampd returns in `to_sign` for the same
    // tx. Regenerate via `print_goldens`.
    #[test]
    fn enclave_sighash_vector() {
        use crate::elements::{
            confidential, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction,
            TxIn, TxInWitness, TxOut, Txid,
        };
        use std::str::FromStr;
        let asset = AssetId::from_slice(&[0x01u8; 32]).unwrap();
        let value = 100_000u64;
        let spk = Script::from(
            Vec::<u8>::from_hex(
                "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        );
        // transfer leaf: <32B K_user> CHECKSIGVERIFY <32B K_policy> CHECKSIG
        let mut leaf_bytes = vec![0x20u8];
        leaf_bytes.extend_from_slice(&[0xbbu8; 32]);
        leaf_bytes.push(0xad); // OP_CHECKSIGVERIFY
        leaf_bytes.push(0x20);
        leaf_bytes.extend_from_slice(&[0xccu8; 32]);
        leaf_bytes.push(0xac); // OP_CHECKSIG
        let leaf = Script::from(leaf_bytes);
        let mut cb = vec![ENCLAVE_LEAF_VERSION];
        cb.extend_from_slice(&Vec::<u8>::from_hex(ENCLAVE_NUMS_HEX).unwrap());
        let genesis =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000042")
                .unwrap();
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str(&"11".repeat(32)).unwrap(), 0),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(value - 1000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: spk.clone(),
                    witness: Default::default(),
                },
                TxOut::new_fee(1000, asset),
            ],
        };
        let prevout = TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey: spk,
            witness: Default::default(),
        };
        let sighash = enclave_sighash(&tx, 0, &[prevout], &leaf, &cb, genesis).unwrap();
        assert_eq!(
            sighash.to_hex(),
            "1bff568af1b88b0518ea7b82374b047e5d8383b9bd230bb20df68452001db43c",
            "enclave sighash drifted"
        );
    }

    // ---- SWK-T (c): tagged-hash vectors for both tags ------------------------
    #[test]
    fn a_site_cannot_get_an_openampd_authorisation() {
        for tag in [
            "openamp-cosign-v1",
            "openamp-dvp-v1",
            "OpenAMP-Cosign-v1",
            "openamp-rotation-v1",
            "openamp-next-v2",
        ] {
            assert!(check_site_tag(tag).is_err(), "{tag}");
        }
        for tag in [TAG_CHALLENGE, TAG_DOCUMENT, "example-app-v1"] {
            assert!(check_site_tag(tag).is_ok(), "{tag}");
        }
    }

    #[test]
    fn tagged_hash_challenge_and_document_vectors() {
        // Challenge over a fixed UTF-8 string.
        let ch = tagged_hash(TAG_CHALLENGE, b"hello-openamp");
        let mut th = sha256::Hash::hash(TAG_CHALLENGE.as_bytes())
            .to_byte_array()
            .to_vec();
        th.extend_from_slice(&sha256::Hash::hash(TAG_CHALLENGE.as_bytes()).to_byte_array());
        th.extend_from_slice(b"hello-openamp");
        let expect = sha256::Hash::hash(&th).to_byte_array();
        assert_eq!(ch.to_hex(), expect.to_hex());

        // Document tag over a fixed 32-byte doc hash differs from the challenge tag
        // over the same bytes (domain separation).
        let doc_hash = [0x11u8; 32];
        let d = tagged_hash(TAG_DOCUMENT, &doc_hash);
        let c = tagged_hash(TAG_CHALLENGE, &doc_hash);
        assert_ne!(d.to_hex(), c.to_hex());
    }
}
