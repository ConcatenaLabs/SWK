//! The spend of one path of a contract: built from a request, run against its
//! final transaction, padded under the budget rule, and finalized.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use lwk_signer::tapscript::ScriptPathSpend;
use lwk_signer::SwSigner;
use serde::{Deserialize, Serialize};
use simplicityhl::elements::bitcoin::bip32::DerivationPath;
use simplicityhl::elements::confidential::{Asset, Nonce, Value as ConfValue};
use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey};
use simplicityhl::elements::sighash::SchnorrSighashType;
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::elements::{
    AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness,
    TxOut, TxOutWitness, Txid,
};
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::BitMachine;
use simplicityhl::str::WitnessName;
use simplicityhl::{Value as HlValue, WitnessValues};

use crate::budget::{self, ANNEX_TAG};
use crate::error::Error;
use crate::hex::{hex, unhex_any};
use crate::template::{Contract, PathInfo, SEQUENCE_DISABLE_FLAG, SEQUENCE_TIME_FLAG};

/// The purpose number of contract keys: the account `m/8383h/{coin}h/0h`,
/// apart from the wallet's funding keys, so a contract key never answers for
/// a wallet coin nor a wallet key for a contract. The Simplex fork settled it
/// (`CONTRACT_KEY_PURPOSE`); the kit uses the same.
pub const CONTRACT_KEY_PURPOSE: u32 = 8383;

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

/// One output of the spend, and what the request says it does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    /// `contract` (back to this contract, or to its next state), `wallet`
    /// (one of the wallet's own scripts), `pay` (anyone, named here) or `fee`.
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
}

/// What a wallet or a site asks the engine to build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpendRequest {
    pub path: String,
    pub coin: CoinRequest,
    /// The input's sequence. Defaults to the value of the path's relative-lock
    /// parameter when the leaf has one, else to no relative lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_time: Option<u32>,
    pub outputs: Vec<OutputRequest>,
    /// Values of `spender` witness entries, by name, hex of their width.
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

/// What the chain says about the coin and the tip, for its locks.
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
    /// `contract`, `contract next state`, `wallet`, `pay` or `fee`.
    pub role: String,
    pub script_pubkey: String,
    pub asset: String,
    pub amount: u64,
}

/// A built spend: the transaction, the leaf, and what each output does.
#[derive(Debug, Clone)]
pub struct Spend {
    pub contract: Arc<Contract>,
    pub path: PathInfo,
    pub chain: Chain,
    pub coin: TxOut,
    pub outpoint: OutPoint,
    /// The transaction with an empty witness.
    pub tx: Transaction,
    pub outputs: Vec<OutputRole>,
    pub spender: BTreeMap<String, String>,
    pub facts: Option<ChainFacts>,
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
}

fn display_asset(asset: &str) -> Result<AssetId, Error> {
    AssetId::from_str(asset).map_err(|e| Error::Spend(format!("asset {asset}: {e}")))
}

impl Spend {
    /// Builds the transaction a request describes, refusing anything the
    /// engine cannot account for.
    pub fn build(
        contract: Arc<Contract>,
        chain: Chain,
        request: &SpendRequest,
        wallet_scripts: &[Script],
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
        let coin = TxOut {
            asset: Asset::Explicit(coin_asset),
            value: ConfValue::Explicit(request.coin.amount),
            nonce: Nonce::Null,
            script_pubkey: coin_script,
            witness: TxOutWitness::default(),
        };
        let outpoint = OutPoint::new(
            Txid::from_str(&request.coin.txid).map_err(|e| Error::Spend(format!("txid: {e}")))?,
            request.coin.vout,
        );

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
            (None, None) => 0xffff_fffd,
        };
        let lock_time = match (&path.lock_time_param, request.lock_time) {
            (Some(p), _) => {
                u32::try_from(contract.value_u64(p)?).map_err(|e| Error::Spend(e.to_string()))?
            }
            (None, l) => l.unwrap_or(0),
        };

        // The outputs, each with what it does.
        let next = match &request.next_slots {
            Some(s) => Some(contract.with_slots(s.clone())?),
            None => None,
        };
        let mut outputs = Vec::new();
        let mut roles = Vec::new();
        for (index, o) in request.outputs.iter().enumerate() {
            let asset = display_asset(&o.asset)?;
            let out_script = if o.to == "fee" {
                if o.address.is_some() || o.script.is_some() {
                    return Err(Error::Unaccounted(format!(
                        "output {index} is a fee, which pays no script"
                    )));
                }
                Script::new()
            } else {
                output_script(index, o)?
            };
            let role = classify(
                index,
                o,
                &out_script,
                &script,
                next.as_ref(),
                wallet_scripts,
            )?;
            if o.amount == 0 && role != "fee" {
                return Err(Error::Unaccounted(format!("output {index} pays nothing")));
            }
            outputs.push(TxOut {
                asset: Asset::Explicit(asset),
                value: ConfValue::Explicit(o.amount),
                nonce: Nonce::Null,
                script_pubkey: out_script.clone(),
                witness: TxOutWitness::default(),
            });
            roles.push(OutputRole {
                index,
                role,
                script_pubkey: hex(out_script.as_bytes()),
                asset: o.asset.clone(),
                amount: o.amount,
            });
        }
        if roles.iter().filter(|r| r.role == "fee").count() != 1 {
            return Err(Error::Unaccounted(
                "a spend has exactly one fee output, in one asset".into(),
            ));
        }
        // Every asset balances: what the coin holds is what the outputs pay.
        let mut balance: BTreeMap<String, i128> = BTreeMap::new();
        *balance.entry(request.coin.asset.clone()).or_default() += i128::from(request.coin.amount);
        for r in &roles {
            *balance.entry(r.asset.clone()).or_default() -= i128::from(r.amount);
        }
        for (asset, left) in balance {
            if left != 0 {
                return Err(Error::Unaccounted(if left > 0 {
                    format!("{left} atoms of {asset} are in the coin and in no output")
                } else {
                    format!(
                        "the outputs pay {} atoms of {asset} that the coin does not hold",
                        -left
                    )
                }));
            }
        }

        let tx = Transaction {
            version: 2,
            lock_time: LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: outpoint,
                sequence: Sequence::from_consensus(sequence),
                ..Default::default()
            }],
            output: outputs,
        };
        for (name, value) in &request.spender {
            if !path
                .witness
                .iter()
                .any(|w| w.name == *name && w.source == "spender")
            {
                return Err(Error::Spend(format!(
                    "{name} is not a value the spender chooses on path {}",
                    path.name
                )));
            }
            unhex_any(value).map_err(|e| Error::Spend(format!("{name}: {e}")))?;
        }
        Ok(Spend {
            contract,
            path,
            chain,
            coin,
            outpoint,
            tx,
            outputs: roles,
            spender: request.spender.clone(),
            facts,
        })
    }

    /// The input's sequence.
    pub fn sequence(&self) -> u32 {
        self.tx.input[0].sequence.to_consensus_u32()
    }

    /// Refuses a spend the chain would refuse now for its locks: a relative
    /// lock (BIP68) that has not matured since the coin confirmed, or a lock
    /// time not yet reached.
    pub fn check_locks(&self) -> Result<Option<String>, Error> {
        let seq = self.sequence();
        let relative =
            self.tx.version >= 2 && seq & SEQUENCE_DISABLE_FLAG == 0 && seq & 0xffff != 0;
        let absolute = self.tx.lock_time.to_consensus_u32() != 0 && seq != 0xffff_ffff;
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
    /// account and is the key the leaf names.
    pub fn contract_keypair(
        &self,
        signer: &SwSigner,
        key_path: &str,
    ) -> Result<(Keypair, String), Error> {
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
        let named = self.signing_param()?;
        let want = hex(&self.contract.value_bytes(&named)?);
        if xonly != want {
            return Err(Error::Signing(format!(
                "path {} is signed by {named} = {want}; this wallet's contract key at {key_path} is {xonly}",
                self.path.name
            )));
        }
        Ok((keypair, named))
    }

    /// The parameter naming the key that signs this path.
    pub fn signing_param(&self) -> Result<String, Error> {
        let keys: Vec<String> = self
            .path
            .witness
            .iter()
            .filter_map(|w| w.source.strip_prefix("signature:").map(str::to_string))
            .collect();
        match keys.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(Error::Signing(format!(
                "path {} takes no signature",
                self.path.name
            ))),
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
            let literal = match w.ty.as_str() {
                "u1" | "u2" | "u4" | "u8" | "u16" | "u32" | "u64" | "u128" => {
                    let n = bytes
                        .iter()
                        .fold(0u128, |acc, x| (acc << 8) | u128::from(*x));
                    n.to_string()
                }
                _ => format!("0x{}", hex(&bytes)),
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

    /// The environment a Simplicity leaf runs in, for `tx` as it stands, with
    /// the annex, if any, read the way the node reads it.
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
        let mut tx = tx.clone();
        // The signature hash commits to every input's annex: a lone placeholder
        // annex is read after an empty item, as the node would read the final stack.
        tx.input[0].witness.script_witness = match annex {
            Some(a) => vec![Vec::new(), a.to_vec()],
            None => Vec::new(),
        };
        Ok(ElementsEnv::new(
            Arc::new(tx),
            vec![ElementsUtxo {
                script_pubkey: self.coin.script_pubkey.clone(),
                asset: self.coin.asset,
                value: self.coin.value,
            }],
            0,
            program.commit().cmr(),
            self.control_block()?,
            annex.map(|a| a[1..].to_vec()),
            self.chain.genesis,
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

    /// Signs with the contract key at `key_path`, runs the program against the
    /// final transaction, pads it under the budget rule, and returns it. The
    /// key is checked first: under the contract account, and the one the path
    /// names.
    pub fn finalize(&self, signer: &SwSigner, key_path: &str) -> Result<Finalized, Error> {
        let (keypair, _) = self.contract_keypair(signer, key_path)?;
        let secp = Secp256k1::new();
        match self.path.kind.as_str() {
            "simplicity" => {
                let rule = self.contract.template.model().budget;
                let sign = |annex: Option<&[u8]>| -> Result<[u8; 64], Error> {
                    let msg = Message::from_digest(self.sig_all_hash(annex)?);
                    Ok(secp.sign_schnorr_no_aux_rand(&msg, &keypair).serialize())
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
                let mut tx = self.tx.clone();
                tx.input[0].witness = TxInWitness {
                    script_witness: stack,
                    ..Default::default()
                };
                Ok(Finalized {
                    tx,
                    cost_mwu: cost,
                    budget_wu: earned,
                    annex_bytes: annex.map_or(0, |a| a.len()),
                })
            }
            "tapscript" => {
                let leaf = self.path.leaf.as_deref().unwrap_or_default();
                let script = self.contract.leaf_script(leaf)?;
                let cb = self.control_block()?;
                let prevouts = [self.coin.clone()];
                let spend = ScriptPathSpend {
                    tx: &self.tx,
                    input_index: 0,
                    prevouts: &prevouts,
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
                let mut tx = self.tx.clone();
                tx.input[0].witness = TxInWitness {
                    script_witness: vec![sig.to_vec(), script.to_bytes(), cb.serialize()],
                    ..Default::default()
                };
                Ok(Finalized {
                    tx,
                    cost_mwu: 0,
                    budget_wu: 0,
                    annex_bytes: 0,
                })
            }
            k => Err(Error::Spend(format!(
                "a {k} path is not spent by the engine"
            ))),
        }
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
        "fee" => Ok("fee".into()),
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
            "output {index}: {other:?} is not something an output can do (contract, wallet, pay or fee)"
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
