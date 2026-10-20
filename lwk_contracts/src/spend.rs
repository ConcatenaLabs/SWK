//! The spend of one path of a contract: built from a request, run against its
//! final transaction, padded under the budget rule, and finalized.
//!
//! A spend has exactly one contract input, the coin of the contract whose
//! path is taken. Beside it a request may name:
//!
//! - the wallet's own coins (`{"is": "wallet"}`), for a top-up, a payment or a
//!   fee in another asset. Each is checked against the wallet's own record of
//!   it ([`WalletCoin`]), never taken on the request's word, and the wallet
//!   signs it with its funding key (P2WPKH, `SIGHASH_ALL`);
//! - foreign coins (`{"is": "foreign"}`), spent through a script leaf with a
//!   witness the request gives, such as an oracle's beacon coin that anyone
//!   spends and recreates. The engine checks the coin against the chain's
//!   record, checks the leaf is committed in the coin's output key, and runs
//!   the program of a Simplicity leaf; it signs nothing for them.
//!
//! The key path, a path of several signatures, and a second contract input
//! (a chain of contract spends) are refused, each with its reason.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use lwk_signer::tapscript::ScriptPathSpend;
use lwk_signer::SwSigner;
use serde::{Deserialize, Serialize};
use simplicityhl::elements::bitcoin::bip32::DerivationPath;
use simplicityhl::elements::confidential::{Asset, Nonce, Value as ConfValue};
use simplicityhl::elements::hashes::{sha256, Hash};
use simplicityhl::elements::schnorr::{Keypair, TweakedPublicKey};
use simplicityhl::elements::secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey};
use simplicityhl::elements::sighash::{SchnorrSighashType, SighashCache};
use simplicityhl::elements::taproot::{ControlBlock, LeafVersion};
use simplicityhl::elements::{
    AssetId, BlockHash, EcdsaSighashType, LockTime, OutPoint, PubkeyHash, Script, Sequence,
    Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Txid, WPubkeyHash,
};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::BitMachine;
use simplicityhl::str::WitnessName;
use simplicityhl::{Value as HlValue, WitnessValues};

use crate::budget::{self, ANNEX_TAG};
use crate::error::Error;
use crate::hex::{hex, unhex_any};
use crate::template::{Contract, Instance, PathInfo, SEQUENCE_DISABLE_FLAG, SEQUENCE_TIME_FLAG};

/// The purpose number of contract keys: the account `m/8383h/{coin}h/0h`,
/// apart from the wallet's funding keys, so a contract key never answers for
/// a wallet coin nor a wallet key for a contract. The Simplex fork settled it
/// (`CONTRACT_KEY_PURPOSE`); the kit uses the same.
pub const CONTRACT_KEY_PURPOSE: u32 = 8383;

/// The sequence a wallet or foreign input carries unless told otherwise: it
/// lets the lock time count, and no relative lock.
pub const DEFAULT_SEQUENCE: u32 = 0xffff_fffd;

/// The Simplicity leaf version in a control block.
pub const SIMPLICITY_LEAF: u8 = 0xbe;

/// The contract account's path on a chain: `m/8383h/1776h/0h` on mainnet,
/// `m/8383h/1h/0h` elsewhere.
pub fn contract_account(mainnet: bool) -> String {
    format!(
        "m/{CONTRACT_KEY_PURPOSE}h/{}h/0h",
        if mainnet { 1776 } else { 1 }
    )
}

/// The default contract key's path: `0/0` under the contract account.
pub fn default_contract_key_path(mainnet: bool) -> String {
    format!("{}/0/0", contract_account(mainnet))
}

/// The contract coin being spent, as the chain holds it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoinRequest {
    pub txid: String,
    pub vout: u32,
    /// The output's script, hex.
    pub script_pubkey: String,
    /// The asset id, display hex (as an RPC prints it).
    pub asset: String,
    pub amount: u64,
}

/// One input of the spend, in the order the transaction carries them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "is", rename_all = "lowercase", deny_unknown_fields)]
pub enum InputRequest {
    /// The contract coin, `coin` of the request.
    Contract,
    /// One of the wallet's own coins, as the request claims it. The engine
    /// spends it only when the wallet's own record of the coin says the same.
    Wallet {
        txid: String,
        vout: u32,
        /// The asset id, display hex.
        asset: String,
        amount: u64,
    },
    /// A coin that is neither the contract's nor the wallet's, spent through
    /// a script leaf with the witness given here (hex items, the leaf script
    /// and the control block last, an annex after them if any).
    Foreign {
        txid: String,
        vout: u32,
        script_pubkey: String,
        /// The asset id, display hex.
        asset: String,
        amount: u64,
        witness: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sequence: Option<u32>,
        /// What the request says the coin is. Shown as the request's claim only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

/// One output of the spend, and what the request says it does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    /// `contract` (back to this contract, or to its next state), `wallet`
    /// (one of the wallet's own scripts), `pay` (anyone, named here), `fee`,
    /// `open` (a new contract, the instance `open` names) or `foreign`
    /// (foreign input `input` recreated: its script, asset and amount).
    pub to: String,
    /// The recipient's unblinded address, for `pay` and `wallet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Or the recipient's script, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// The asset id, display hex.
    pub asset: String,
    pub amount: u64,
    /// For `open`: the instance record of the contract the output opens, of
    /// a template this kit carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<serde_json::Value>,
    /// For `foreign`: the index of the input it recreates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<usize>,
}

/// What a wallet or a site asks the engine to build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpendRequest {
    pub path: String,
    pub coin: CoinRequest,
    /// Every input in order, `{"is": "contract"}` among them exactly once.
    /// Without it the contract coin is the only input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<InputRequest>>,
    /// The contract input's sequence. Defaults to the value of the path's
    /// relative-lock parameter when the leaf has one, else to no relative lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_time: Option<u32>,
    pub outputs: Vec<OutputRequest>,
    /// Values of `spender` witness entries, by name: hex of their width, or,
    /// for a value of a composite type (`Either`, `Option`, a tuple), its
    /// SimplicityHL literal such as `Left(Left(()))`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spender: BTreeMap<String, String>,
    /// The slots of the contract's next state, when an output returns to it in another state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_slots: Option<BTreeMap<String, String>>,
}

impl SpendRequest {
    pub fn parse(text: &str) -> Result<Self, Error> {
        serde_json::from_str(text).map_err(|e| Error::Spend(format!("request: {e}")))
    }
}

/// One of the wallet's own coins, as the wallet itself records it (from its
/// own sync, never from a site).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletCoin {
    pub txid: String,
    pub vout: u32,
    /// The output's script, hex.
    pub script_pubkey: String,
    /// The asset id, display hex.
    pub asset: String,
    pub amount: u64,
    /// The funding key's full path, such as `m/84h/1h/0h/0/3`.
    pub key_path: String,
    /// Whether the coin is blinded on the chain. A contract spend takes
    /// explicit coins only.
    #[serde(default)]
    pub confidential: bool,
}

/// An output as the chain holds it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Prevout {
    pub script_pubkey: String,
    /// The asset id, display hex.
    pub asset: String,
    pub amount: u64,
}

/// What the chain says about the coin and the tip, for its locks, and about
/// the coins the wallet does not hold.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainFacts {
    pub tip_height: u64,
    /// The tip's median time past.
    pub tip_median_time: u64,
    /// The height of the block holding the coin; `None` while unconfirmed.
    #[serde(default)]
    pub coin_height: Option<u64>,
    /// The median time past of the block before the coin's, from which BIP68
    /// counts a time lock.
    #[serde(default)]
    pub coin_start_median_time: Option<u64>,
    /// The chain's record of coins, by `txid:vout`: the contract coin's and
    /// every foreign input's, read by the wallet from its own node or
    /// indexer. A foreign input is spent only when its record is here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prevouts: BTreeMap<String, Prevout>,
}

/// The chain a spend is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub genesis: BlockHash,
    pub mainnet: bool,
}

/// One output, classified.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OutputRole {
    pub index: usize,
    /// `contract`, `contract next state`, `wallet`, `pay`, `fee`, `opens`
    /// or `foreign returned`.
    pub role: String,
    pub script_pubkey: String,
    pub asset: String,
    pub amount: u64,
    /// For `foreign returned`: the input it recreates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<usize>,
}

/// One input, classified.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InputRole {
    pub index: usize,
    /// `contract`, `wallet` or `foreign`.
    pub role: String,
    /// `txid:vout`.
    pub coin: String,
    pub script_pubkey: String,
    pub asset: String,
    pub amount: u64,
    pub sequence: u32,
    /// A wallet input's funding key path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    /// A foreign input's witness, hex items, exactly as it goes on the chain.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<String>,
    /// A foreign input's leaf: `tapscript` or `simplicity`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_kind: Option<String>,
    /// A foreign tapscript leaf's script, or a Simplicity leaf's root, hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<String>,
    /// What the request says a foreign input is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A contract an output opens, recomputed by the engine.
#[derive(Debug, Clone)]
pub struct Opened {
    pub output: usize,
    pub contract: Arc<Contract>,
}

/// A built spend: the transaction, the leaf, and what each input and output does.
#[derive(Debug, Clone)]
pub struct Spend {
    pub contract: Arc<Contract>,
    pub path: PathInfo,
    pub chain: Chain,
    /// The contract coin.
    pub coin: TxOut,
    pub outpoint: OutPoint,
    /// The contract coin's input index.
    pub k: usize,
    /// The transaction with the foreign inputs' witnesses in place and every
    /// other witness empty.
    pub tx: Transaction,
    /// Every input's coin, in order.
    pub prevouts: Vec<TxOut>,
    pub inputs: Vec<InputRole>,
    pub outputs: Vec<OutputRole>,
    pub opened: Vec<Opened>,
    pub spender: BTreeMap<String, String>,
    pub facts: Option<ChainFacts>,
    /// The wallet's own scripts, to tell its outputs apart.
    pub wallet_scripts: Vec<Script>,
    /// Whether each foreign input and the contract coin were checked against
    /// the chain's record.
    pub chain_checked: Vec<usize>,
}

/// A finalized spend.
#[derive(Debug, Clone)]
pub struct Finalized {
    pub tx: Transaction,
    /// Program cost bound, in milli weight units; 0 for a tapscript leaf.
    pub cost_mwu: u64,
    /// What the witness earns, in weight units; 0 for a tapscript leaf.
    pub budget_wu: u64,
    /// The annex, tag included, when padding was needed.
    pub annex_bytes: usize,
    /// Each foreign Simplicity input's run: (input, cost milli-WU, budget WU).
    pub foreign_runs: Vec<(usize, u64, u64)>,
}

fn display_asset(asset: &str) -> Result<AssetId, Error> {
    AssetId::from_str(asset).map_err(|e| Error::Spend(format!("asset {asset}: {e}")))
}

fn explicit(script: Script, asset: AssetId, amount: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: ConfValue::Explicit(amount),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: TxOutWitness::default(),
    }
}

fn outpoint_of(txid: &str, vout: u32) -> Result<OutPoint, Error> {
    Ok(OutPoint::new(
        Txid::from_str(txid).map_err(|e| Error::Spend(format!("txid {txid}: {e}")))?,
        vout,
    ))
}

/// A witness type whose spender value is a SimplicityHL literal, not hex.
pub fn is_composite(ty: &str) -> bool {
    let t = ty.trim();
    t.starts_with("Either") || t.starts_with("Option") || t.starts_with('(') || t.starts_with('[')
}

/// A foreign input's witness, read: the leaf and its control block, checked
/// against the coin's output key.
struct ForeignLeaf {
    kind: &'static str,
    leaf: Vec<u8>,
    cb: ControlBlock,
    annex: Option<Vec<u8>>,
}

fn read_foreign(index: usize, script: &Script, witness: &[Vec<u8>]) -> Result<ForeignLeaf, Error> {
    if !script.is_v1_p2tr() {
        return Err(Error::Unaccounted(format!(
            "input {index} is a foreign coin of script {}, which is not a taproot output; the engine spends a foreign coin only through a script leaf",
            hex(script.as_bytes())
        )));
    }
    let mut stack = witness.to_vec();
    let annex = if stack.len() >= 2 && stack.last().and_then(|a| a.first()) == Some(&ANNEX_TAG) {
        stack.pop()
    } else {
        None
    };
    if stack.len() < 2 {
        return Err(Error::Unaccounted(format!(
            "input {index} is a foreign coin whose witness is a key-path spend; the engine takes a foreign coin only through a script leaf, with its leaf and control block given"
        )));
    }
    let cb_bytes = stack.pop().expect("two items");
    let leaf = stack.pop().expect("one item");
    let cb = ControlBlock::from_slice(&cb_bytes)
        .map_err(|e| Error::Unaccounted(format!("input {index}: control block: {e}")))?;
    let output_key = XOnlyPublicKey::from_slice(&script.as_bytes()[2..])
        .map_err(|e| Error::Unaccounted(format!("input {index}: output key: {e}")))?;
    let secp = Secp256k1::verification_only();
    let kind = if cb.leaf_version.as_u8() == SIMPLICITY_LEAF {
        "simplicity"
    } else if cb.leaf_version == LeafVersion::default() {
        "tapscript"
    } else {
        return Err(Error::Unaccounted(format!(
            "input {index}: leaf version {:#04x} is neither tapscript nor Simplicity",
            cb.leaf_version.as_u8()
        )));
    };
    if !cb.verify_taproot_commitment(
        &secp,
        &TweakedPublicKey::new(output_key),
        &Script::from(leaf.clone()),
    ) {
        return Err(Error::Unaccounted(format!(
            "input {index}: the witness's {kind} leaf is not committed in the coin's output key {output_key}"
        )));
    }
    if kind == "simplicity" && (stack.len() != 2 || leaf.len() != 32) {
        return Err(Error::Unaccounted(format!(
            "input {index}: a Simplicity leaf's witness is the witness data, the program, the root and the control block"
        )));
    }
    Ok(ForeignLeaf {
        kind,
        leaf,
        cb,
        annex,
    })
}

impl Spend {
    /// Builds the transaction a request describes with the contract coin as
    /// its only input from the wallet's side (no wallet coins).
    pub fn build(
        contract: Arc<Contract>,
        chain: Chain,
        request: &SpendRequest,
        wallet_scripts: &[Script],
        facts: Option<ChainFacts>,
    ) -> Result<Self, Error> {
        Self::build_with_coins(contract, chain, request, wallet_scripts, &[], facts)
    }

    /// Builds the transaction a request describes, refusing anything the
    /// engine cannot account for. `wallet_coins` is the wallet's own record of
    /// its coins: a wallet input the request names is spent only as that
    /// record says.
    pub fn build_with_coins(
        contract: Arc<Contract>,
        chain: Chain,
        request: &SpendRequest,
        wallet_scripts: &[Script],
        wallet_coins: &[WalletCoin],
        facts: Option<ChainFacts>,
    ) -> Result<Self, Error> {
        let template = &contract.template;
        let path = template
            .paths()
            .into_iter()
            .find(|p| p.name == request.path)
            .ok_or_else(|| {
                Error::Spend(format!(
                    "the template has no path {:?}; its paths are {:?}",
                    request.path,
                    template
                        .paths()
                        .iter()
                        .map(|p| p.name.clone())
                        .collect::<Vec<_>>()
                ))
            })?;
        if path.kind == "key" {
            return Err(Error::Spend(format!(
                "path {} spends by the internal key; the engine spends leaves only",
                path.name
            )));
        }
        let signers = path
            .witness
            .iter()
            .filter(|w| w.source.starts_with("signature:"))
            .count();
        if signers > 1 {
            return Err(Error::Spend(format!(
                "path {} takes {signers} signatures; the engine signs paths of one key, so a multisignature path is not spent here",
                path.name
            )));
        }
        if let Some(g) = &contract.instance.genesis {
            if *g != chain.genesis.to_string() {
                return Err(Error::Spend(format!(
                    "the instance is for the chain with genesis {g}; this wallet is on {}",
                    chain.genesis
                )));
            }
        } else {
            return Err(Error::Spend(
                "the instance names no chain (genesis null), so a signature for it could be replayed on any chain that holds the same output".into(),
            ));
        }

        // The coin: the contract's script, recomputed here, and explicit.
        let script = contract.script_pubkey();
        let coin_script = Script::from(
            unhex_any(&request.coin.script_pubkey)
                .map_err(|e| Error::Spend(format!("coin script: {e}")))?,
        );
        if coin_script != script {
            return Err(Error::Spend(format!(
                "the coin's script {} is not the contract's, which the engine recomputes as {}",
                request.coin.script_pubkey,
                hex(script.as_bytes())
            )));
        }
        let coin_asset = display_asset(&request.coin.asset)?;
        let coin = explicit(coin_script, coin_asset, request.coin.amount);
        let outpoint = outpoint_of(&request.coin.txid, request.coin.vout)?;
        let next = match &request.next_slots {
            Some(s) => Some(contract.with_slots(s.clone())?),
            None => None,
        };

        // The sequence the leaf needs, when it says so.
        let sequence = match (&path.sequence_param, request.sequence) {
            (Some(p), None) => {
                u32::try_from(contract.value_u64(p)?).map_err(|e| Error::Spend(e.to_string()))?
            }
            (Some(p), Some(s)) => {
                let need = u32::try_from(contract.value_u64(p)?)
                    .map_err(|e| Error::Spend(e.to_string()))?;
                if s != need {
                    return Err(Error::Spend(format!(
                        "path {} checks the relative lock {p} = {need:#x}; the request sets {s:#x}",
                        path.name
                    )));
                }
                s
            }
            (None, Some(s)) => s,
            (None, None) => DEFAULT_SEQUENCE,
        };
        let lock_time = match (&path.lock_time_param, request.lock_time) {
            (Some(p), _) => {
                u32::try_from(contract.value_u64(p)?).map_err(|e| Error::Spend(e.to_string()))?
            }
            (None, l) => l.unwrap_or(0),
        };

        // The inputs, each with what it is.
        let wanted = request
            .inputs
            .clone()
            .unwrap_or_else(|| vec![InputRequest::Contract]);
        let contracts = wanted
            .iter()
            .filter(|i| matches!(i, InputRequest::Contract))
            .count();
        if contracts != 1 {
            return Err(Error::Spend(format!(
                "a spend has exactly one contract input; this request names {contracts}. A chain of several contract inputs is not spent by the engine"
            )));
        }
        let facts_ref = facts.as_ref();
        let mut chain_checked = Vec::new();
        let mut txins = Vec::new();
        let mut prevouts = Vec::new();
        let mut roles = Vec::new();
        let mut k = 0;
        let mut seen: Vec<OutPoint> = Vec::new();
        for (index, i) in wanted.iter().enumerate() {
            let (op, prev, role) = match i {
                InputRequest::Contract => {
                    k = index;
                    if let Some(p) = facts_ref.and_then(|f| {
                        f.prevouts
                            .get(&format!("{}:{}", request.coin.txid, request.coin.vout))
                    }) {
                        if p.script_pubkey != request.coin.script_pubkey
                            || p.asset != request.coin.asset
                            || p.amount != request.coin.amount
                        {
                            return Err(Error::Unaccounted(format!(
                                "the contract coin {}:{} is said to hold {} atoms of {} at {}; the chain's record is {} atoms of {} at {}",
                                request.coin.txid, request.coin.vout, request.coin.amount, request.coin.asset,
                                request.coin.script_pubkey, p.amount, p.asset, p.script_pubkey
                            )));
                        }
                        chain_checked.push(index);
                    }
                    (
                        outpoint,
                        coin.clone(),
                        InputRole {
                            index,
                            role: "contract".into(),
                            coin: format!("{}:{}", request.coin.txid, request.coin.vout),
                            script_pubkey: request.coin.script_pubkey.clone(),
                            asset: request.coin.asset.clone(),
                            amount: request.coin.amount,
                            sequence,
                            key_path: None,
                            witness: Vec::new(),
                            leaf_kind: None,
                            leaf: None,
                            label: None,
                        },
                    )
                }
                InputRequest::Wallet {
                    txid,
                    vout,
                    asset,
                    amount,
                } => {
                    let rec = wallet_coins
                        .iter()
                        .find(|c| c.txid == *txid && c.vout == *vout)
                        .ok_or_else(|| {
                            Error::Unaccounted(format!(
                                "input {index} is said to be this wallet's coin {txid}:{vout}, which is not among this wallet's coins"
                            ))
                        })?;
                    if rec.asset != *asset || rec.amount != *amount {
                        return Err(Error::Unaccounted(format!(
                            "input {index} is said to hold {amount} atoms of {asset}; this wallet's own record of {txid}:{vout} is {} atoms of {}, so it is not spent as shown",
                            rec.amount, rec.asset
                        )));
                    }
                    if rec.confidential {
                        return Err(Error::Unaccounted(format!(
                            "input {index}, this wallet's coin {txid}:{vout}, is confidential; a contract spend's outputs are explicit, so it takes explicit coins only"
                        )));
                    }
                    let canon = rec.key_path.replace('\'', "h");
                    if canon.starts_with(&format!("{}/", contract_account(chain.mainnet))) {
                        return Err(Error::Signing(format!(
                            "input {index}'s key {} is a contract key; a contract key never answers for a wallet coin",
                            rec.key_path
                        )));
                    }
                    let s = Script::from(
                        unhex_any(&rec.script_pubkey)
                            .map_err(|e| Error::Spend(format!("wallet coin script: {e}")))?,
                    );
                    if s == script || next.as_ref().is_some_and(|n| n.script_pubkey() == s) {
                        return Err(Error::Spend(format!(
                            "input {index} is a coin of this same contract; a chain of several contract inputs is not spent by the engine"
                        )));
                    }
                    if !s.is_v0_p2wpkh() {
                        return Err(Error::Unaccounted(format!(
                            "input {index}, this wallet's coin {txid}:{vout}, pays {}, which is not a P2WPKH script; the engine signs P2WPKH wallet coins only",
                            rec.script_pubkey
                        )));
                    }
                    (
                        outpoint_of(txid, *vout)?,
                        explicit(s, display_asset(asset)?, *amount),
                        InputRole {
                            index,
                            role: "wallet".into(),
                            coin: format!("{txid}:{vout}"),
                            script_pubkey: rec.script_pubkey.clone(),
                            asset: asset.clone(),
                            amount: *amount,
                            sequence: DEFAULT_SEQUENCE,
                            key_path: Some(rec.key_path.clone()),
                            witness: Vec::new(),
                            leaf_kind: None,
                            leaf: None,
                            label: None,
                        },
                    )
                }
                InputRequest::Foreign {
                    txid,
                    vout,
                    script_pubkey,
                    asset,
                    amount,
                    witness,
                    sequence: seq,
                    label,
                } => {
                    let key = format!("{txid}:{vout}");
                    let p = facts_ref.and_then(|f| f.prevouts.get(&key)).ok_or_else(|| {
                        Error::Unaccounted(format!(
                            "input {index} is a foreign coin {key}, and the chain's record of it was not given; the engine does not take a foreign coin on the request's word"
                        ))
                    })?;
                    if p.script_pubkey != *script_pubkey || p.asset != *asset || p.amount != *amount
                    {
                        return Err(Error::Unaccounted(format!(
                            "input {index}, the foreign coin {key}, is said to hold {amount} atoms of {asset} at {script_pubkey}; the chain's record is {} atoms of {} at {}",
                            p.amount, p.asset, p.script_pubkey
                        )));
                    }
                    chain_checked.push(index);
                    if wallet_coins
                        .iter()
                        .any(|c| c.txid == *txid && c.vout == *vout)
                    {
                        return Err(Error::Unaccounted(format!(
                            "input {index} is named as a foreign coin, but {key} is this wallet's own; name it as a wallet input"
                        )));
                    }
                    let s = Script::from(
                        unhex_any(script_pubkey)
                            .map_err(|e| Error::Spend(format!("input {index} script: {e}")))?,
                    );
                    if s == script || next.as_ref().is_some_and(|n| n.script_pubkey() == s) {
                        return Err(Error::Spend(format!(
                            "input {index} is a coin of this same contract; a chain of several contract inputs is not spent by the engine"
                        )));
                    }
                    let stack = witness
                        .iter()
                        .map(|w| {
                            unhex_any(w)
                                .map_err(|e| Error::Spend(format!("input {index} witness: {e}")))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let leaf = read_foreign(index, &s, &stack)?;
                    (
                        outpoint_of(txid, *vout)?,
                        explicit(s, display_asset(asset)?, *amount),
                        InputRole {
                            index,
                            role: "foreign".into(),
                            coin: key,
                            script_pubkey: script_pubkey.clone(),
                            asset: asset.clone(),
                            amount: *amount,
                            sequence: seq.unwrap_or(DEFAULT_SEQUENCE),
                            key_path: None,
                            witness: witness.clone(),
                            leaf_kind: Some(leaf.kind.into()),
                            leaf: Some(hex(&leaf.leaf)),
                            label: label.clone(),
                        },
                    )
                }
            };
            if seen.contains(&op) {
                return Err(Error::Spend(format!(
                    "input {index} spends {op} a second time"
                )));
            }
            seen.push(op);
            let mut txin = TxIn {
                previous_output: op,
                sequence: Sequence::from_consensus(role.sequence),
                ..Default::default()
            };
            if role.role == "foreign" {
                txin.witness.script_witness = role
                    .witness
                    .iter()
                    .map(|w| unhex_any(w).expect("checked"))
                    .collect();
            }
            txins.push(txin);
            prevouts.push(prev);
            roles.push(role);
        }

        // The outputs, each with what it does.
        let mut outputs = Vec::new();
        let mut out_roles = Vec::new();
        let mut opened = Vec::new();
        for (index, o) in request.outputs.iter().enumerate() {
            let asset = display_asset(&o.asset)?;
            if o.to != "open" && o.open.is_some() {
                return Err(Error::Unaccounted(format!(
                    "output {index} names a contract to open but says it goes to {}",
                    o.to
                )));
            }
            if o.to != "foreign" && o.input.is_some() {
                return Err(Error::Unaccounted(format!(
                    "output {index} names an input to recreate but says it goes to {}",
                    o.to
                )));
            }
            let (out_script, role) = match o.to.as_str() {
                "fee" => {
                    if o.address.is_some() || o.script.is_some() {
                        return Err(Error::Unaccounted(format!(
                            "output {index} is a fee, which pays no script"
                        )));
                    }
                    (Script::new(), "fee".to_string())
                }
                "open" => {
                    let record = o.open.as_ref().ok_or_else(|| {
                        Error::Unaccounted(format!(
                            "output {index} opens a contract and names no instance (open)"
                        ))
                    })?;
                    let inst = Instance::parse(&record.to_string())?;
                    let known = crate::known(&inst.template_hash).ok_or_else(|| {
                        Error::Unaccounted(format!(
                            "output {index} opens a contract of template {}, which this kit does not carry, so the engine cannot recompute it",
                            inst.template_hash
                        ))
                    })?;
                    let c = Contract::new(Arc::new(known.template()?), inst)?;
                    if c.instance.genesis.as_deref() != Some(&chain.genesis.to_string()) {
                        return Err(Error::Unaccounted(format!(
                            "output {index} opens a contract for another chain than this one ({})",
                            chain.genesis
                        )));
                    }
                    let s = c.script_pubkey();
                    if o.address.is_some() || o.script.is_some() {
                        let said = output_script(index, o)?;
                        if said != s {
                            return Err(Error::Unaccounted(format!(
                                "output {index} is said to open the contract {}, but pays the script {}",
                                hex(s.as_bytes()),
                                hex(said.as_bytes())
                            )));
                        }
                    }
                    opened.push(Opened {
                        output: index,
                        contract: Arc::new(c),
                    });
                    (s, "opens".to_string())
                }
                "foreign" => {
                    let j = o.input.ok_or_else(|| {
                        Error::Unaccounted(format!(
                            "output {index} recreates a foreign coin and names no input"
                        ))
                    })?;
                    let r = roles.get(j).filter(|r| r.role == "foreign").ok_or_else(|| {
                        Error::Unaccounted(format!(
                            "output {index} is said to recreate input {j}, which is not a foreign input"
                        ))
                    })?;
                    let s = Script::from(unhex_any(&r.script_pubkey).expect("checked"));
                    if o.address.is_some() || o.script.is_some() {
                        let said = output_script(index, o)?;
                        if said != s {
                            return Err(Error::Unaccounted(format!(
                                "output {index} is said to recreate input {j}, but pays the script {} rather than its {}",
                                hex(said.as_bytes()),
                                r.script_pubkey
                            )));
                        }
                    }
                    if o.asset != r.asset || o.amount != r.amount {
                        return Err(Error::Unaccounted(format!(
                            "output {index} is said to recreate input {j}, but pays {} atoms of {} where the coin holds {} atoms of {}",
                            o.amount, o.asset, r.amount, r.asset
                        )));
                    }
                    (s, "foreign returned".to_string())
                }
                _ => {
                    let s = output_script(index, o)?;
                    let role = classify(index, o, &s, &script, next.as_ref(), wallet_scripts)?;
                    (s, role)
                }
            };
            if o.amount == 0 && role != "fee" {
                return Err(Error::Unaccounted(format!("output {index} pays nothing")));
            }
            if role != "foreign returned"
                && roles
                    .iter()
                    .any(|r| r.role == "foreign" && r.script_pubkey == hex(out_script.as_bytes()))
            {
                return Err(Error::Unaccounted(format!(
                    "output {index} pays a foreign input's script; say it recreates that input (to: foreign)"
                )));
            }
            outputs.push(explicit(out_script.clone(), asset, o.amount));
            out_roles.push(OutputRole {
                index,
                role,
                script_pubkey: hex(out_script.as_bytes()),
                asset: o.asset.clone(),
                amount: o.amount,
                input: o.input,
            });
        }
        if out_roles.iter().filter(|r| r.role == "fee").count() != 1 {
            return Err(Error::Unaccounted(
                "a spend has exactly one fee output, in one asset".into(),
            ));
        }
        // Every asset balances: what the inputs hold is what the outputs pay.
        let mut balance: BTreeMap<String, i128> = BTreeMap::new();
        for r in &roles {
            *balance.entry(r.asset.clone()).or_default() += i128::from(r.amount);
        }
        for r in &out_roles {
            *balance.entry(r.asset.clone()).or_default() -= i128::from(r.amount);
        }
        for (asset, left) in balance {
            if left != 0 {
                return Err(Error::Unaccounted(if left > 0 {
                    format!("{left} atoms of {asset} are in the inputs and in no output")
                } else {
                    format!(
                        "the outputs pay {} atoms of {asset} that the inputs do not hold",
                        -left
                    )
                }));
            }
        }

        let tx = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(lock_time),
            input: txins,
            output: outputs,
        };
        for (name, value) in &request.spender {
            let w = path
                .witness
                .iter()
                .find(|w| w.name == *name && w.source == "spender")
                .ok_or_else(|| {
                    Error::Spend(format!(
                        "{name} is not a value the spender chooses on path {}",
                        path.name
                    ))
                })?;
            if !is_composite(&w.ty) {
                unhex_any(value).map_err(|e| Error::Spend(format!("{name}: {e}")))?;
            }
        }
        if let Some((name, prefix)) = crate::known::path_selector(template.hash(), &path.name) {
            let v: String = request
                .spender
                .get(name)
                .map(|v| v.chars().filter(|c| !c.is_whitespace()).collect())
                .unwrap_or_default();
            if !v.starts_with(prefix) {
                return Err(Error::Spend(format!(
                    "path {} is chosen by {name} = {prefix}…; the request gives {name} = {}, which is another path",
                    path.name,
                    if v.is_empty() { "nothing".into() } else { v }
                )));
            }
        }
        Ok(Spend {
            contract,
            path,
            chain,
            coin,
            outpoint,
            k,
            tx,
            prevouts,
            inputs: roles,
            outputs: out_roles,
            opened,
            spender: request.spender.clone(),
            facts,
            wallet_scripts: wallet_scripts.to_vec(),
            chain_checked,
        })
    }

    /// The contract input's sequence.
    pub fn sequence(&self) -> u32 {
        self.tx.input[self.k].sequence.to_consensus_u32()
    }

    /// Refuses a spend the chain would refuse now for its locks: a relative
    /// lock (BIP68) on the contract input that has not matured since the coin
    /// confirmed, or a lock time not yet reached.
    pub fn check_locks(&self) -> Result<Option<String>, Error> {
        let seq = self.sequence();
        let relative =
            self.tx.version >= 2 && seq & SEQUENCE_DISABLE_FLAG == 0 && seq & 0xffff != 0;
        let absolute = self.tx.lock_time.to_consensus_u32() != 0
            && self
                .tx
                .input
                .iter()
                .any(|i| i.sequence.to_consensus_u32() != 0xffff_ffff);
        if !relative && !absolute {
            return Ok(None);
        }
        let facts = self.facts.as_ref().ok_or_else(|| {
            Error::Chain("the spend carries a lock, and the chain's height and times were not given to check it".into())
        })?;
        let mut said = Vec::new();
        if relative {
            let n = u64::from(seq & 0xffff);
            let height = facts.coin_height.ok_or_else(|| {
                Error::Chain(
                    "the coin is not confirmed, so its relative lock has not started".into(),
                )
            })?;
            if seq & SEQUENCE_TIME_FLAG != 0 {
                let start = facts.coin_start_median_time.ok_or_else(|| {
                    Error::Chain("the median time before the coin's block was not given".into())
                })?;
                let due = start + n * 512;
                if facts.tip_median_time < due {
                    return Err(Error::Chain(format!(
                        "the coin's relative lock of {n} × 512 s ends at median time {due}; the chain's median time is {}, so a block would refuse this spend for another {} (non-BIP68-final)",
                        facts.tip_median_time,
                        crate::template::show_duration(due - facts.tip_median_time)
                    )));
                }
                said.push(format!(
                    "relative lock of {n} × 512 s passed at median time {due}"
                ));
            } else {
                let due = height + n;
                if facts.tip_height + 1 < due {
                    return Err(Error::Chain(format!(
                        "the coin's relative lock of {n} blocks ends at height {due}; the next block is {} (non-BIP68-final)",
                        facts.tip_height + 1
                    )));
                }
                said.push(format!(
                    "relative lock of {n} blocks passed at height {due}"
                ));
            }
        }
        if absolute {
            let l = self.tx.lock_time.to_consensus_u32();
            let ok = if l < 500_000_000 {
                u64::from(l) < facts.tip_height + 1
            } else {
                u64::from(l) < facts.tip_median_time
            };
            if !ok {
                return Err(Error::Chain(format!(
                    "the lock time {l} is not yet reached (non-final)"
                )));
            }
            said.push(format!("lock time {l} reached"));
        }
        Ok(Some(said.join("; ")))
    }

    /// The contract key at `path`, refused unless it is under the contract
    /// account and is the key the leaf names; `None` for a path that takes
    /// no signature.
    pub fn contract_keypair(
        &self,
        signer: &SwSigner,
        key_path: &str,
    ) -> Result<Option<(Keypair, String)>, Error> {
        let Some(named) = self.signing_param()? else {
            return Ok(None);
        };
        let account = contract_account(self.chain.mainnet);
        let canon = key_path.replace('\'', "h");
        if !canon.starts_with(&format!("{account}/")) {
            return Err(Error::Signing(format!(
                "{key_path} is not a contract key: contract keys are under {account}, apart from the wallet's funding keys"
            )));
        }
        let path = DerivationPath::from_str(&canon)
            .map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
        let xprv = signer
            .derive_xprv(&path)
            .map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &xprv.private_key);
        let xonly = hex(&keypair.x_only_public_key().0.serialize());
        let want = hex(&self.contract.value_bytes(&named)?);
        if xonly != want {
            return Err(Error::Signing(format!(
                "path {} is signed by {named} = {want}; this wallet's contract key at {key_path} is {xonly}",
                self.path.name
            )));
        }
        Ok(Some((keypair, named)))
    }

    /// The parameter naming the key that signs this path; `None` when the
    /// path takes no signature.
    pub fn signing_param(&self) -> Result<Option<String>, Error> {
        let keys: Vec<String> = self
            .path
            .witness
            .iter()
            .filter_map(|w| w.source.strip_prefix("signature:").map(str::to_string))
            .collect();
        match keys.as_slice() {
            [one] => Ok(Some(one.clone())),
            [] => Ok(None),
            _ => Err(Error::Signing(format!(
                "path {} takes {} signatures; the engine signs paths of one key",
                self.path.name,
                keys.len()
            ))),
        }
    }

    fn witness_values(&self, sig: &[u8; 64]) -> Result<WitnessValues, Error> {
        let leaf = self.path.leaf.as_deref().unwrap_or_default();
        let program = self
            .contract
            .template
            .program(leaf)
            .ok_or_else(|| Error::Spend(format!("{leaf} is not a Simplicity leaf")))?;
        let types = program.witness_types();
        let mut map = std::collections::HashMap::new();
        for w in &self.path.witness {
            let ty = types
                .iter()
                .find(|(n, _)| AsRef::<str>::as_ref(*n) == w.name)
                .map(|(_, t)| t)
                .ok_or_else(|| {
                    Error::Spend(format!("the program declares no witness {}", w.name))
                })?;
            let literal = if w.source == "spender" && is_composite(&w.ty) {
                self.spender
                    .get(&w.name)
                    .ok_or_else(|| {
                        Error::Spend(format!("the spender's value {} is not given", w.name))
                    })?
                    .clone()
            } else {
                let bytes = if w.source.starts_with("signature:") {
                    sig.to_vec()
                } else if let Some(p) = w
                    .source
                    .strip_prefix("param:")
                    .or_else(|| w.source.strip_prefix("slot:"))
                {
                    self.contract.value_bytes(p)?
                } else {
                    let v = self.spender.get(&w.name).ok_or_else(|| {
                        Error::Spend(format!("the spender's value {} is not given", w.name))
                    })?;
                    unhex_any(v).map_err(|e| Error::Spend(e.to_string()))?
                };
                match w.ty.as_str() {
                    "u1" | "u2" | "u4" | "u8" | "u16" | "u32" | "u64" | "u128" => {
                        let n = bytes
                            .iter()
                            .fold(0u128, |acc, x| (acc << 8) | u128::from(*x));
                        n.to_string()
                    }
                    _ => format!("0x{}", hex(&bytes)),
                }
            };
            let value = HlValue::parse_from_str(&literal, ty)
                .map_err(|e| Error::Spend(format!("witness {}: {e}", w.name)))?;
            map.insert(WitnessName::from_str_unchecked(&w.name), value);
        }
        Ok(WitnessValues::from(map))
    }

    fn control_block(&self) -> Result<ControlBlock, Error> {
        self.contract
            .control_block(self.path.leaf.as_deref().unwrap_or_default())
    }

    fn utxos(&self) -> Vec<ElementsUtxo> {
        self.prevouts
            .iter()
            .map(|p| ElementsUtxo {
                script_pubkey: p.script_pubkey.clone(),
                asset: p.asset,
                value: p.value,
            })
            .collect()
    }

    /// The environment input `index` runs in, for `tx` as it stands, with the
    /// annex, if any, read the way the node reads it. For the contract input,
    /// `stack_annex` replaces its witness; every other input keeps the
    /// witness `tx` gives it.
    fn env_at(
        &self,
        tx: &Transaction,
        index: usize,
        cmr: simplicityhl::simplicity::Cmr,
        cb: ControlBlock,
        annex: Option<&[u8]>,
        replace: bool,
    ) -> ElementsEnv<Arc<Transaction>> {
        let mut tx = tx.clone();
        if replace {
            // The signature hash commits to every input's annex: a lone
            // placeholder annex is read after an empty item, as the node would
            // read the final stack.
            tx.input[index].witness.script_witness = match annex {
                Some(a) => vec![Vec::new(), a.to_vec()],
                None => Vec::new(),
            };
        }
        ElementsEnv::new(
            Arc::new(tx),
            self.utxos(),
            u32::try_from(index).expect("few inputs"),
            cmr,
            cb,
            annex.map(|a| a[1..].to_vec()),
            self.chain.genesis,
        )
    }

    /// The environment of the contract input.
    fn env(
        &self,
        tx: &Transaction,
        annex: Option<&[u8]>,
    ) -> Result<ElementsEnv<Arc<Transaction>>, Error> {
        let leaf = self.path.leaf.as_deref().unwrap_or_default();
        let program = self
            .contract
            .template
            .program(leaf)
            .expect("a Simplicity leaf");
        Ok(self.env_at(
            tx,
            self.k,
            program.commit().cmr(),
            self.control_block()?,
            annex,
            true,
        ))
    }

    /// The hash a Simplicity leaf's signature signs: `sig_all_hash`.
    pub fn sig_all_hash(&self, annex: Option<&[u8]>) -> Result<[u8; 32], Error> {
        Ok(self
            .env(&self.tx, annex)?
            .c_tx_env()
            .sighash_all()
            .to_byte_array())
    }

    /// Runs the program against `tx` with this signature and annex; returns
    /// the witness stack (witness, program, root, control block) and the
    /// pruned program's cost bound in milli weight units.
    fn run(&self, sig: &[u8; 64], annex: Option<&[u8]>) -> Result<(Vec<Vec<u8>>, u64), Error> {
        let leaf = self.path.leaf.as_deref().unwrap_or_default();
        let program = self
            .contract
            .template
            .program(leaf)
            .expect("a Simplicity leaf");
        let satisfied = program
            .satisfy(self.witness_values(sig)?)
            .map_err(Error::Program)?;
        let env = self.env(&self.tx, annex)?;
        let pruned = match satisfied.redeem().prune(&env) {
            Ok(p) => p,
            Err(e) => {
                return Err(Error::Program(match self.diagnose(sig, annex) {
                    Some(check) => format!("{e}: the check that fails is `{check}`"),
                    None => e.to_string(),
                }))
            }
        };
        let mut mac =
            BitMachine::for_program(&pruned).map_err(|e| Error::Program(e.to_string()))?;
        mac.exec(&pruned, &env)
            .map_err(|e| Error::Program(e.to_string()))?;
        let (program_bytes, witness_bytes) = pruned.to_vec_with_witness();
        let stack = vec![
            witness_bytes,
            program_bytes,
            pruned.cmr().as_ref().to_vec(),
            self.control_block()?.serialize(),
        ];
        Ok((stack, budget::cost_milliweight(pruned.bounds().cost)))
    }

    /// The source text of the check a refused run fails at: the program is
    /// compiled again with debug symbols (which change its root, so the
    /// environment keeps the committed root and the signature stays valid)
    /// and run with a tracker that notes each assertion it enters.
    fn diagnose(&self, sig: &[u8; 64], annex: Option<&[u8]>) -> Option<String> {
        use simplicityhl::debug::TrackedCallName;
        use simplicityhl::simplicity::bit_machine::{ExecTracker, FrameIter, NodeOutput};
        use simplicityhl::simplicity::node::Inner;
        use simplicityhl::simplicity::RedeemNode;

        struct Last<'a> {
            symbols: &'a simplicityhl::debug::DebugSymbols,
            last: Option<String>,
            failed: Option<String>,
        }
        impl ExecTracker for Last<'_> {
            fn visit_node(&mut self, node: &RedeemNode, _: FrameIter, output: NodeOutput) {
                if let Inner::AssertL(_, cmr) = node.inner() {
                    if let Some(call) = self.symbols.get(cmr) {
                        if matches!(
                            call.name(),
                            TrackedCallName::Assert
                                | TrackedCallName::Unwrap
                                | TrackedCallName::Panic
                        ) {
                            self.last = Some(call.text().to_string());
                        }
                    }
                }
                if matches!(output, NodeOutput::JetFailed) && self.failed.is_none() {
                    self.failed = self.last.clone();
                }
            }
        }

        let leaf = self.path.leaf.as_deref()?;
        let source = self.contract.template.source_text(leaf)?;
        let debug = simplicityhl::TemplateProgram::new(
            source,
            Box::new(simplicityhl::ast::ElementsJetHinter::new()),
        )
        .ok()?
        .instantiate(simplicityhl::Arguments::default(), true)
        .ok()?;
        let satisfied = debug.satisfy(self.witness_values(sig).ok()?).ok()?;
        let env = self.env(&self.tx, annex).ok()?;
        let mut tracker = Last {
            symbols: satisfied.debug_symbols(),
            last: None,
            failed: None,
        };
        let mut mac = BitMachine::for_program(satisfied.redeem()).ok()?;
        let _ = mac.exec_with_tracker(satisfied.redeem(), &env, &mut tracker);
        tracker.failed.or(tracker.last)
    }

    /// Runs foreign input `j`'s Simplicity program, as its witness gives it,
    /// against the final transaction: (cost milli-WU, budget WU).
    fn run_foreign(&self, tx: &Transaction, j: usize) -> Result<(u64, u64), Error> {
        use simplicityhl::simplicity::jet::Elements;
        use simplicityhl::simplicity::{BitIter, RedeemNode};
        let stack = &tx.input[j].witness.script_witness;
        let read = read_foreign(j, &self.prevouts[j].script_pubkey, stack)?;
        let program = RedeemNode::decode::<_, _, Elements>(
            BitIter::from(stack[1].as_slice()),
            BitIter::from(stack[0].as_slice()),
        )
        .map_err(|e| Error::Program(format!("input {j}'s program does not decode: {e}")))?;
        if program.cmr().as_ref() != read.leaf.as_slice() {
            return Err(Error::Program(format!(
                "input {j}'s program has root {}, not the {} its leaf commits to",
                program.cmr(),
                hex(&read.leaf)
            )));
        }
        let env = self.env_at(
            tx,
            j,
            program.cmr(),
            read.cb.clone(),
            read.annex.as_deref(),
            false,
        );
        let mut mac = BitMachine::for_program(&program)
            .map_err(|e| Error::Program(format!("input {j}: {e}")))?;
        mac.exec(&program, &env).map_err(|e| {
            Error::Program(format!("input {j}'s program refuses this transaction: {e}"))
        })?;
        let cost = budget::cost_milliweight(program.bounds().cost);
        let rule = sequentia_contracts::descriptor::Budget {
            per_witness_byte: 4,
            offset: 50,
            max: 4_000_050,
        };
        let earned = budget::earned(&rule, stack);
        if cost > earned * 1000 {
            return Err(Error::Program(format!(
                "input {j}'s program costs {cost} milli-WU and its witness earns {earned} WU"
            )));
        }
        Ok((cost, earned))
    }

    /// Signs each wallet input with its funding key: P2WPKH, `SIGHASH_ALL`,
    /// so the signature commits to every input's outpoint and sequence, every
    /// output, the lock time and this coin's own amount. The key is refused
    /// unless it pays the coin's script.
    fn sign_wallet_inputs(&self, signer: &SwSigner, tx: &mut Transaction) -> Result<(), Error> {
        let secp = Secp256k1::new();
        let unsigned = tx.clone();
        let mut cache = SighashCache::new(&unsigned);
        for r in self.inputs.iter().filter(|r| r.role == "wallet") {
            let key_path = r.key_path.as_deref().expect("a wallet input has a key");
            let path = DerivationPath::from_str(&key_path.replace('\'', "h"))
                .map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
            let xprv = signer
                .derive_xprv(&path)
                .map_err(|e| Error::Signing(format!("{key_path}: {e}")))?;
            let sk = xprv.private_key;
            let pk = simplicityhl::elements::bitcoin::PublicKey::new(sk.public_key(&secp));
            let wpkh = WPubkeyHash::hash(&pk.to_bytes());
            let spk = Script::new_v0_wpkh(&wpkh);
            if hex(spk.as_bytes()) != r.script_pubkey {
                return Err(Error::Signing(format!(
                    "input {}: this wallet's key at {key_path} pays {}, not the coin's script {}",
                    r.index,
                    hex(spk.as_bytes()),
                    r.script_pubkey
                )));
            }
            let code = Script::new_p2pkh(&PubkeyHash::hash(&pk.to_bytes()));
            let hash = cache.segwitv0_sighash(
                r.index,
                &code,
                ConfValue::Explicit(r.amount),
                EcdsaSighashType::All,
            );
            let msg = Message::from_digest(hash.to_byte_array());
            let sig = secp.sign_ecdsa_low_r(&msg, &sk);
            let mut der = sig.serialize_der().to_vec();
            der.push(EcdsaSighashType::All as u8);
            tx.input[r.index].witness = TxInWitness {
                script_witness: vec![der, pk.to_bytes()],
                ..Default::default()
            };
        }
        Ok(())
    }

    /// Signs the contract input with the contract key at `key_path` when its
    /// path takes a signature, runs the program against the final
    /// transaction, pads it under the budget rule, signs the wallet's own
    /// inputs, and runs every foreign Simplicity input's program. The key is
    /// checked first: under the contract account, and the one the path names.
    /// A wallet reaches it only through the five-point gate,
    /// [`crate::approval::Approval`], which signs only what it showed.
    pub(crate) fn finalize(&self, signer: &SwSigner, key_path: &str) -> Result<Finalized, Error> {
        let keypair = self.contract_keypair(signer, key_path)?.map(|(k, _)| k);
        let secp = Secp256k1::new();
        let mut tx = self.tx.clone();
        let (cost_mwu, budget_wu, annex_bytes) = match self.path.kind.as_str() {
            "simplicity" => {
                let rule = self.contract.template.model().budget;
                let sign = |annex: Option<&[u8]>| -> Result<[u8; 64], Error> {
                    match &keypair {
                        Some(kp) => {
                            let msg = Message::from_digest(self.sig_all_hash(annex)?);
                            Ok(secp.sign_schnorr_no_aux_rand(&msg, kp).serialize())
                        }
                        None => Ok([0; 64]),
                    }
                };
                let sig = sign(None)?;
                let (stack, cost) = self.run(&sig, None)?;
                let (stack, annex) =
                    match budget::padding(&rule, cost, &stack).map_err(Error::Program)? {
                        None => (stack, None),
                        Some(annex) => {
                            let sig = sign(Some(&annex))?;
                            let (mut stack, cost2) = self.run(&sig, Some(&annex))?;
                            debug_assert_eq!(cost, cost2);
                            stack.push(annex.clone());
                            (stack, Some(annex))
                        }
                    };
                let earned = budget::earned(&rule, &stack);
                if cost > earned * 1000 {
                    return Err(Error::Program(format!(
                        "the program costs {cost} milli-WU and its witness earns {earned} WU"
                    )));
                }
                debug_assert!(annex.as_ref().is_none_or(|a| a[0] == ANNEX_TAG));
                tx.input[self.k].witness = TxInWitness {
                    script_witness: stack,
                    ..Default::default()
                };
                (cost, earned, annex.map_or(0, |a| a.len()))
            }
            "tapscript" => {
                let leaf = self.path.leaf.as_deref().unwrap_or_default();
                let script = self.contract.leaf_script(leaf)?;
                let cb = self.control_block()?;
                let mut stack = Vec::new();
                if keypair.is_some() {
                    let spend = ScriptPathSpend {
                        tx: &self.tx,
                        input_index: self.k,
                        prevouts: &self.prevouts,
                        leaf_script: &script,
                        control_block: &cb,
                        sighash_type: SchnorrSighashType::Default,
                        genesis_hash: self.chain.genesis,
                    };
                    let path = DerivationPath::from_str(&key_path.replace('\'', "h"))
                        .map_err(|e| Error::Signing(e.to_string()))?;
                    let sig = signer
                        .sign_tapscript(&path, &spend)
                        .map_err(|e| Error::Signing(e.to_string()))?;
                    stack.push(sig.to_vec());
                } else if !self.path.witness.is_empty() {
                    return Err(Error::Spend(format!(
                        "path {} is a tapscript leaf whose witness the engine cannot supply",
                        self.path.name
                    )));
                }
                stack.push(script.to_bytes());
                stack.push(cb.serialize());
                tx.input[self.k].witness = TxInWitness {
                    script_witness: stack,
                    ..Default::default()
                };
                (0, 0, 0)
            }
            k => {
                return Err(Error::Spend(format!(
                    "a {k} path is not spent by the engine"
                )))
            }
        };
        self.sign_wallet_inputs(signer, &mut tx)?;
        let mut foreign_runs = Vec::new();
        for r in self.inputs.iter().filter(|r| r.role == "foreign") {
            if r.leaf_kind.as_deref() == Some("simplicity") {
                let (c, b) = self.run_foreign(&tx, r.index)?;
                foreign_runs.push((r.index, c, b));
            }
        }
        Ok(Finalized {
            tx,
            cost_mwu,
            budget_wu,
            annex_bytes,
            foreign_runs,
        })
    }

    /// The x-only key a signer holds at `key_path`, for display and checks.
    pub fn key_at(signer: &SwSigner, key_path: &str) -> Result<XOnlyPublicKey, Error> {
        let path = DerivationPath::from_str(&key_path.replace('\'', "h"))
            .map_err(|e| Error::Signing(e.to_string()))?;
        signer
            .xonly_public_key(&path)
            .map_err(|e| Error::Signing(e.to_string()))
    }
}

fn output_script(index: usize, o: &OutputRequest) -> Result<Script, Error> {
    match (&o.address, &o.script) {
        (Some(a), None) => {
            let addr = simplicityhl::elements::Address::from_str(a).map_err(|e| {
                Error::Unaccounted(format!("output {index}: {a} is not an address: {e}"))
            })?;
            if addr.is_blinded() {
                return Err(Error::Unaccounted(format!(
                    "output {index} pays the confidential address {a}; the engine accounts for explicit outputs only, so give the recipient's transparent address"
                )));
            }
            Ok(addr.script_pubkey())
        }
        (None, Some(s)) => {
            Ok(Script::from(unhex_any(s).map_err(|e| {
                Error::Unaccounted(format!("output {index}: {e}"))
            })?))
        }
        _ => Err(Error::Unaccounted(format!(
            "output {index} names neither an address nor a script (exactly one)"
        ))),
    }
}

/// What an output does, checked against what the request says it does.
fn classify(
    index: usize,
    o: &OutputRequest,
    out_script: &Script,
    contract_script: &Script,
    next: Option<&Contract>,
    wallet_scripts: &[Script],
) -> Result<String, Error> {
    let is_contract = out_script == contract_script;
    let is_next = next.is_some_and(|n| *out_script == n.script_pubkey());
    let is_wallet = wallet_scripts.contains(out_script);
    match o.to.as_str() {
        "contract" if is_contract => Ok("contract".into()),
        "contract" if is_next => Ok("contract next state".into()),
        "contract" => Err(Error::Unaccounted(format!(
            "output {index} is said to return to the contract, but pays the script {}, which is neither the contract's ({}){}",
            hex(out_script.as_bytes()),
            hex(contract_script.as_bytes()),
            match next {
                Some(n) => format!(" nor its next state's ({})", hex(n.script_pubkey().as_bytes())),
                None => String::new(),
            }
        ))),
        "wallet" if is_wallet => Ok("wallet".into()),
        "wallet" => Err(Error::Unaccounted(format!(
            "output {index} is said to pay this wallet, but its script {} is none of the wallet's",
            hex(out_script.as_bytes())
        ))),
        "pay" if is_contract || is_next => Err(Error::Unaccounted(format!(
            "output {index} is said to pay someone, but pays the contract itself"
        ))),
        "pay" if is_wallet => Ok("wallet".into()),
        "pay" => Ok("pay".into()),
        other => Err(Error::Unaccounted(format!(
            "output {index}: {other:?} is not something an output can do (contract, wallet, pay, fee, open or foreign)"
        ))),
    }
}

/// Lowercase hex of a script.
pub fn script_hex(s: &Script) -> String {
    hex(s.as_bytes())
}

/// A script from hex.
pub fn script_from_hex(s: &str) -> Result<Script, Error> {
    Ok(Script::from(unhex_any(s).map_err(Error::Spend)?))
}

/// SHA-256 of a script, hex: what a `script_hash` parameter holds.
pub fn script_hash_hex(s: &Script) -> String {
    hex(sha256::Hash::hash(s.as_bytes()).as_ref())
}
