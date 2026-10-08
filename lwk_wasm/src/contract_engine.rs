//! The contract engine (`lwk_contracts`) for a browser wallet.
//!
//! A template is a descriptor of `sequentia-contracts` and the resolved text
//! of each of its programs; the engine checks it with that repository's own
//! reader and pinned compiler. An instance is the template's values on one
//! chain. Values cross the boundary as JSON text, with hex as the descriptor
//! writes it.

use std::collections::BTreeMap;
use std::sync::Arc;

use lwk_contracts::spend::{script_from_hex, Chain};
use lwk_contracts::template::Node;
use lwk_contracts::{
    drip, ChainFacts, CoinRequest, Contract, Instance, Spend, SpendRequest, Template,
};
use wasm_bindgen::prelude::*;

use crate::{Error, Network};

fn err(e: lwk_contracts::Error) -> Error {
    Error::Generic(e.to_string())
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, Error> {
    Ok(serde_json::to_string(v)?)
}

/// The chain a network is: its genesis hash and whether it is mainnet.
pub(crate) fn chain_of(network: &Network) -> Chain {
    let n: lwk_common::Network = network.into();
    Chain {
        genesis: n.genesis_hash(),
        mainnet: n.is_mainnet(),
    }
}

/// A contract template, checked: the descriptor's every rule, and each
/// program compiled with the pinned compiler to the root the descriptor gives.
#[wasm_bindgen]
pub struct ContractTemplate {
    pub(crate) inner: Arc<Template>,
}

#[wasm_bindgen]
impl ContractTemplate {
    /// Reads `descriptorJson` with the resolved source of each program,
    /// `sourcesJson` = `{"<source name>": "<text>"}` (what `seqc expand`
    /// prints, the text `source_sha256` hashes). Throws the reason a
    /// descriptor or a source is refused.
    #[wasm_bindgen(constructor)]
    pub fn new(descriptor_json: &str, sources_json: &str) -> Result<ContractTemplate, Error> {
        let sources: BTreeMap<String, String> = serde_json::from_str(sources_json)?;
        Ok(ContractTemplate {
            inner: Arc::new(Template::new(descriptor_json, &sources).map_err(err)?),
        })
    }

    /// The templates this kit carries: `[{hash, name, version, summary}]` as JSON.
    #[wasm_bindgen(js_name = knownList)]
    pub fn known_list() -> Result<String, Error> {
        let mut out = Vec::new();
        for k in lwk_contracts::KNOWN {
            let t = k.template().map_err(err)?;
            out.push(serde_json::json!({
                "hash": k.hash,
                "name": t.self_name(),
                "version": t.version(),
                "summary": t.summary(),
            }));
        }
        json(&out)
    }

    /// A template this kit carries, by hash.
    pub fn known(hash: &str) -> Result<ContractTemplate, Error> {
        let k = lwk_contracts::known(hash)
            .ok_or_else(|| Error::Generic(format!("the kit carries no template {hash}")))?;
        Ok(ContractTemplate {
            inner: Arc::new(k.template().map_err(err)?),
        })
    }

    /// A carried template's descriptor text, for a registry or a page to show.
    #[wasm_bindgen(js_name = knownDescriptor)]
    pub fn known_descriptor(hash: &str) -> Result<String, Error> {
        lwk_contracts::known(hash)
            .map(|k| k.descriptor.to_string())
            .ok_or_else(|| Error::Generic(format!("the kit carries no template {hash}")))
    }

    /// The template hash: the template's identity.
    pub fn hash(&self) -> String {
        self.inner.hash().to_string()
    }

    /// The name the template gives itself. Only a registry vouches for a name.
    #[wasm_bindgen(js_name = selfName)]
    pub fn self_name(&self) -> String {
        self.inner.self_name()
    }

    /// The template's version.
    pub fn version(&self) -> u64 {
        self.inner.version()
    }

    /// One sentence a wallet can show.
    pub fn summary(&self) -> String {
        self.inner.summary()
    }

    /// Parameters, slots, paths (with what each needs) and leaves, as JSON.
    pub fn describe(&self) -> Result<String, Error> {
        let t = &self.inner;
        let leaves: Vec<_> = t
            .model()
            .tree
            .leaves()
            .into_iter()
            .map(|(n, depth)| {
                let kind = match n {
                    Node::Simplicity { .. } => "simplicity",
                    Node::Tapscript { .. } => "tapscript",
                    Node::Data { .. } => "data",
                    Node::Branch(..) => "branch",
                };
                let cmr = match n {
                    Node::Simplicity { program, .. } => Some(program.cmr.clone()),
                    _ => None,
                };
                serde_json::json!({"name": n.name(), "kind": kind, "depth": depth, "cmr": cmr})
            })
            .collect();
        json(&serde_json::json!({
            "hash": t.hash(),
            "name": t.self_name(),
            "version": t.version(),
            "summary": t.summary(),
            "descriptor": t.descriptor().descriptor,
            "internal_key": t.model().internal_key,
            "params": t.params(),
            "slots": t.slots(),
            "paths": t.paths(),
            "leaves": leaves,
        }))
    }
}

/// An instance of a template: its output, recomputed by the engine.
#[wasm_bindgen]
pub struct ContractInstance {
    pub(crate) inner: Arc<Contract>,
}

#[wasm_bindgen]
impl ContractInstance {
    /// Reads an instance record (`{"instance": 1|2, "template_hash", "params",
    /// "slots", "genesis"}`) of `template` and recomputes its output.
    #[wasm_bindgen(constructor)]
    pub fn new(
        template: &ContractTemplate,
        instance_json: &str,
    ) -> Result<ContractInstance, Error> {
        let instance = Instance::parse(instance_json).map_err(err)?;
        Ok(ContractInstance {
            inner: Arc::new(Contract::new(template.inner.clone(), instance).map_err(err)?),
        })
    }

    /// The output script, hex.
    #[wasm_bindgen(js_name = scriptPubkey)]
    pub fn script_pubkey(&self) -> String {
        self.inner.derived.script_pubkey.clone()
    }

    /// The unblinded address on `network`.
    pub fn address(&self, network: &Network) -> Result<String, Error> {
        let n: lwk_common::Network = network.into();
        self.inner
            .address(n.address_params().bech_hrp.as_str())
            .map_err(err)
    }

    /// The address under a bech32 prefix, as the golden vectors give one per chain.
    #[wasm_bindgen(js_name = addressWithPrefix)]
    pub fn address_with_prefix(&self, hrp: &str) -> Result<String, Error> {
        self.inner.address(hrp).map_err(err)
    }

    /// Everything the output is made of, as the golden vectors write it:
    /// `{leaves, merkle_root, tweak, output_key, output_key_parity, script_pubkey}`.
    pub fn derived(&self) -> Result<String, Error> {
        json(&self.inner.derived_json())
    }

    /// Each spending path and what its spend needs, as JSON.
    pub fn paths(&self) -> Result<String, Error> {
        json(&self.inner.template.paths())
    }

    /// The instance record, as JSON.
    pub fn instance(&self) -> Result<String, Error> {
        json(&self.inner.instance)
    }

    /// The template hash of this instance.
    #[wasm_bindgen(js_name = templateHash)]
    pub fn template_hash(&self) -> String {
        self.inner.template.hash().to_string()
    }

    /// For a faucet drip covenant: the request for a drip of `amount` from
    /// the reserve `coinJson` (`{txid, vout, script_pubkey, asset, amount}`,
    /// asset in display hex) to `toAddress`, paying `fee` in the reserve's
    /// asset. Refuses an amount above the reserve's tier and a fee above the
    /// covenant's cap, as its program would.
    #[wasm_bindgen(js_name = planDrip)]
    pub fn plan_drip(
        &self,
        coin_json: &str,
        to_address: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String, Error> {
        let coin: CoinRequest = serde_json::from_str(coin_json)?;
        json(&drip::plan(&self.inner, &coin, to_address, amount, fee).map_err(err)?)
    }

    /// For a faucet drip covenant: the most a drip may pay from a reserve of `reserve`.
    #[wasm_bindgen(js_name = dripTier)]
    pub fn drip_tier(&self, reserve: u64) -> Result<u64, Error> {
        drip::tier_for(&self.inner, reserve).map_err(err)
    }
}

/// The spend of one path of a contract, built from a request and not yet signed.
#[wasm_bindgen]
pub struct ContractSpend {
    pub(crate) inner: Spend,
}

#[wasm_bindgen]
impl ContractSpend {
    /// Builds the spend `requestJson` describes (see `SpendRequest`) on
    /// `network`. `walletScriptsJson` lists the wallet's own scripts (hex), so
    /// an output to the wallet is told apart from a payment; `chainJson`
    /// (`{tip_height, tip_median_time, coin_height, coin_start_median_time}`)
    /// lets the engine check the spend's locks. Refuses an output the request
    /// mislabels, a confidential output, a missing or second fee, and outputs
    /// that do not balance the coin, each with the reason.
    pub fn build(
        instance: &ContractInstance,
        network: &Network,
        request_json: &str,
        wallet_scripts_json: &str,
        chain_json: Option<String>,
    ) -> Result<ContractSpend, Error> {
        let request = SpendRequest::parse(request_json).map_err(err)?;
        let scripts: Vec<String> = serde_json::from_str(wallet_scripts_json)?;
        let scripts = scripts
            .iter()
            .map(|s| script_from_hex(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        let facts: Option<ChainFacts> = match chain_json {
            Some(c) => Some(serde_json::from_str(&c)?),
            None => None,
        };
        Ok(ContractSpend {
            inner: Spend::build(
                instance.inner.clone(),
                chain_of(network),
                &request,
                &scripts,
                facts,
            )
            .map_err(err)?,
        })
    }

    /// The unsigned transaction, hex.
    #[wasm_bindgen(js_name = unsignedTx)]
    pub fn unsigned_tx(&self) -> String {
        lwk_wollet::elements::encode::serialize_hex(&self.inner.tx)
    }

    /// What each output does: `[{index, role, script_pubkey, asset, amount}]`.
    pub fn outputs(&self) -> Result<String, Error> {
        json(&self.inner.outputs)
    }

    /// The path being spent and what it needs, as JSON.
    pub fn path(&self) -> Result<String, Error> {
        json(&self.inner.path)
    }

    /// Refuses, with the reason, a spend whose locks the chain would refuse
    /// now; otherwise says which locks have passed.
    #[wasm_bindgen(js_name = checkLocks)]
    pub fn check_locks(&self) -> Result<String, Error> {
        Ok(self.inner.check_locks().map_err(err)?.unwrap_or_default())
    }
}

/// A contract spend checked under the five-point rule, with the summary the
/// wallet shows before it signs.
#[wasm_bindgen]
pub struct ContractApproval {
    pub(crate) inner: lwk_contracts::Approval,
}

#[wasm_bindgen]
impl ContractApproval {
    /// Checks `spend` for `signer`: the template is on the wallet's list
    /// (`viewJson.known`), the output was recomputed and is the coin's, the
    /// chain's locks have passed, the key is the wallet's contract key the
    /// path names (`viewJson.key_path`, by default `0/0` under
    /// `m/8383h/{coin}h/0h`), and the program accepts the final transaction.
    /// `viewJson` may also carry the registry's name for the template
    /// (`registry: {name, version}`) and asset labels
    /// (`assets: {"<id>": {ticker, precision}}`). Throws the first rule that fails.
    pub fn prepare(
        spend: &ContractSpend,
        signer: &crate::Signer,
        view_json: &str,
    ) -> Result<ContractApproval, Error> {
        let view: lwk_contracts::WalletView = serde_json::from_str(view_json)?;
        if crate::contract_engine::chain_of_signer(signer) != spend.inner.chain {
            return Err(Error::Generic(
                "the signer is for another chain than the spend".into(),
            ));
        }
        Ok(ContractApproval {
            inner: lwk_contracts::Approval::prepare(spend.inner.clone(), view, &signer.inner)
                .map_err(err)?,
        })
    }

    /// What the wallet shows, as JSON: the template (by registry name, else
    /// its root), the path, the parameters by role, the wallet's balance
    /// change in every asset, the contract's, payments, the fee, the checks,
    /// and the `digest` that `Signer.signContractSpend` takes back.
    pub fn summary(&self) -> Result<String, Error> {
        json(&self.inner.summary())
    }

    /// The digest of the summary.
    pub fn digest(&self) -> String {
        self.inner.digest().to_string()
    }
}

/// The chain a signer was made for.
pub(crate) fn chain_of_signer(signer: &crate::Signer) -> Chain {
    Chain {
        genesis: signer.network.genesis_hash(),
        mainnet: signer.network.is_mainnet(),
    }
}
