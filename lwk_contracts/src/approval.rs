//! Signing for a contract under the five-point rule.
//!
//! A wallet signs a contract spend only when all of these hold:
//!
//! 1. the template hash is on its list of known templates;
//! 2. it recomputed the output script from the template and the instance,
//!    and it equals the coin being spent;
//! 3. it ran the program against the final transaction itself;
//! 4. the approval shows the template (by registry name where registered,
//!    else its root), the path, the parameters by role, and the wallet's own
//!    balance change in every asset;
//! 5. the signing key is one reserved for contracts.
//!
//! [`Approval::prepare`] checks 1, 2, 3 and 5, and the chain's locks, and
//! writes the summary of 4 with a digest over it. [`Approval::sign`] signs only
//! when it is handed that digest back, so a wallet signs only what it showed;
//! it prepares the spend again from the same inputs, refuses if anything
//! differs, and runs the program once more against the transaction it returns.
//!
//! To run a program before the approval, the engine signs inside itself
//! (the program checks the signature) and drops that signature: the only one
//! that leaves the engine is made by [`Approval::sign`].

use std::collections::BTreeMap;

use lwk_signer::SwSigner;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use simplicityhl::elements::hashes::{sha256, Hash, HashEngine};
use simplicityhl::elements::{encode, Transaction};

use crate::error::Error;
use crate::hex::hex;
use crate::spend::{Finalized, Spend};
use crate::template::{show_sequence, show_value};

/// The name and version a registry gives a template hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryName {
    pub name: String,
    pub version: u64,
}

/// How a wallet labels an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssetLabel {
    pub ticker: String,
    pub precision: u8,
}

/// What the wallet brings to an approval.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletView {
    /// The template hashes on the wallet's list.
    pub known: Vec<String>,
    /// The registry's name for this template, when it has one.
    #[serde(default)]
    pub registry: Option<RegistryName>,
    /// Labels of assets, by display hex.
    #[serde(default)]
    pub assets: BTreeMap<String, AssetLabel>,
    /// The contract key's path. Defaults to `0/0` under the contract account.
    #[serde(default)]
    pub key_path: Option<String>,
}

/// A spend checked under the five-point rule, with what the wallet must show.
#[derive(Debug, Clone)]
pub struct Approval {
    spend: Spend,
    view: WalletView,
    key_path: String,
    summary: Value,
    digest: String,
}

fn amount(view: &WalletView, asset: &str, atoms: i128) -> String {
    match view.assets.get(asset) {
        Some(l) => {
            let p = u32::from(l.precision);
            let sign = if atoms < 0 { "-" } else { "" };
            let a = atoms.unsigned_abs();
            let unit = 10u128.pow(p);
            if p == 0 {
                format!("{sign}{a} {}", l.ticker)
            } else {
                format!(
                    "{sign}{}.{:0width$} {}",
                    a / unit,
                    a % unit,
                    l.ticker,
                    width = p as usize
                )
            }
        }
        None => format!("{atoms} atoms of {asset}"),
    }
}

impl Approval {
    /// Checks a spend under points 1, 2, 3 and 5 and the chain's locks, and
    /// writes the summary point 4 asks the wallet to show.
    pub fn prepare(spend: Spend, view: WalletView, signer: &SwSigner) -> Result<Self, Error> {
        let key_path = view
            .key_path
            .clone()
            .unwrap_or_else(|| crate::spend::default_contract_key_path(spend.chain.mainnet));
        let (summary, _) = summarize(&spend, &view, &key_path, signer)?;
        let digest = digest(&summary);
        Ok(Approval {
            spend,
            view,
            key_path,
            summary,
            digest,
        })
    }

    /// What the wallet shows, as JSON; its `digest` is what [`Self::sign`] takes back.
    pub fn summary(&self) -> Value {
        let mut s = self.summary.clone();
        s["digest"] = self.digest.clone().into();
        s
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn spend(&self) -> &Spend {
        &self.spend
    }

    /// Signs the spend the wallet showed: `shown_digest` must be the digest of
    /// the summary it showed. Everything is checked again, and the program is
    /// run once more against the transaction returned.
    pub fn sign(&self, shown_digest: &str, signer: &SwSigner) -> Result<Transaction, Error> {
        if shown_digest != self.digest {
            return Err(Error::Signing(format!(
                "the approval shown has digest {shown_digest}; this spend's is {}, so it is not what was shown",
                self.digest
            )));
        }
        let (summary, finalized) = summarize(&self.spend, &self.view, &self.key_path, signer)?;
        let again = digest(&summary);
        if again != self.digest {
            return Err(Error::Signing(format!(
                "the spend prepared again has digest {again}, not the {} shown",
                self.digest
            )));
        }
        Ok(finalized.tx)
    }
}

fn digest(summary: &Value) -> String {
    let mut e = sha256::Hash::engine();
    e.input(b"lwk_contracts/approval/1\0");
    e.input(summary.to_string().as_bytes());
    hex(sha256::Hash::from_engine(e).as_ref())
}

/// The checks, the run, and the summary. Returns the finalized transaction
/// as well, which only [`Approval::sign`] lets out.
fn summarize(
    spend: &Spend,
    view: &WalletView,
    key_path: &str,
    signer: &SwSigner,
) -> Result<(Value, Finalized), Error> {
    let contract = &spend.contract;
    let template = &contract.template;

    // 1. The template is on the wallet's list.
    if !view.known.iter().any(|h| h == template.hash()) {
        return Err(Error::Signing(format!(
            "template {} ({}) is not on this wallet's list of known templates",
            template.hash(),
            template.self_name()
        )));
    }
    // 2. The output was recomputed by `Spend::build`, which refuses a coin whose
    //    script is not the contract's; checked again here.
    if spend.coin.script_pubkey != contract.script_pubkey() {
        return Err(Error::Signing(
            "the coin is not the contract's output".into(),
        ));
    }
    // The chain's locks.
    let locks = spend.check_locks()?;
    // 5. A contract key, and the one the path names.
    let (keypair, key_param) = spend.contract_keypair(signer, key_path)?;
    // 3. The program, run against the final transaction.
    let finalized = spend.finalize(signer, key_path)?;
    let weight = finalized.tx.weight();
    let vsize = weight.div_ceil(4);

    // 4. The summary.
    let leaf = spend.path.leaf.clone().unwrap_or_default();
    let roots: Vec<String> = template
        .model()
        .tree
        .leaves()
        .into_iter()
        .filter_map(|(n, _)| match n {
            crate::template::Node::Simplicity { program, .. } => Some(program.cmr.clone()),
            _ => None,
        })
        .collect();
    let shown_template = match &view.registry {
        Some(r) => format!("{} v{} (registered)", r.name, r.version),
        None => format!(
            "an unregistered template, root {}",
            roots
                .first()
                .cloned()
                .unwrap_or_else(|| template.hash().to_string())
        ),
    };
    let our_key = hex(&keypair.x_only_public_key().0.serialize());
    let params: Vec<Value> = template
        .params()
        .iter()
        .map(|p| {
            let v = &contract.instance.params[&p.name];
            let mut shown = show_value(&p.role, v);
            if p.role == "asset" {
                if let Some(l) = view.assets.get(&shown) {
                    shown = format!("{} ({shown})", l.ticker);
                }
            }
            if p.role == "amount" {
                if let Some(asset) = template_asset(spend) {
                    let atoms = i128::from(u64::from_str_radix(v, 16).unwrap_or(0));
                    shown = amount(view, &asset, atoms);
                }
            }
            if p.role == "pubkey" && *v == our_key {
                shown = format!("{v} (this wallet's contract key, {key_path})");
            }
            json!({"name": p.name, "label": p.label, "role": p.role, "type": p.ty, "value": v, "shown": shown})
        })
        .collect();
    let slots: Vec<Value> = template
        .slots()
        .iter()
        .map(|p| {
            let v = &contract.instance.slots[&p.name];
            json!({"name": p.name, "label": p.label, "role": p.role, "value": v, "shown": show_value(&p.role, v)})
        })
        .collect();

    // Balance changes, per asset: the wallet's, the contract's, payments, the fee.
    let coin_asset = spend
        .outputs
        .first()
        .map(|_| contract_asset(spend).unwrap_or_default())
        .unwrap_or_default();
    let coin_amount = i128::from(spend.coin.value.explicit().unwrap_or(0));
    let mut wallet: BTreeMap<String, i128> = BTreeMap::new();
    let mut contract_change: BTreeMap<String, i128> = BTreeMap::new();
    *contract_change.entry(coin_asset.clone()).or_default() -= coin_amount;
    let mut payments = Vec::new();
    let mut fee = Vec::new();
    for o in &spend.outputs {
        let a = i128::from(o.amount);
        match o.role.as_str() {
            "wallet" => *wallet.entry(o.asset.clone()).or_default() += a,
            "contract" | "contract next state" => {
                *contract_change.entry(o.asset.clone()).or_default() += a
            }
            "pay" => payments.push(json!({
                "index": o.index, "script_pubkey": o.script_pubkey, "asset": o.asset,
                "amount": o.amount, "shown": amount(view, &o.asset, a)})),
            _ => fee.push(
                json!({"asset": o.asset, "amount": o.amount, "shown": amount(view, &o.asset, a)}),
            ),
        }
    }
    let show_map = |m: &BTreeMap<String, i128>| -> Vec<Value> {
        m.iter()
            .map(|(asset, d)| json!({"asset": asset, "change": d.to_string(), "shown": amount(view, asset, *d)}))
            .collect()
    };
    let wallet_change = if wallet.is_empty() {
        vec![
            json!({"asset": null, "change": "0", "shown": "no change in any asset: this spend moves the contract's coin, not the wallet's"}),
        ]
    } else {
        show_map(&wallet)
    };

    let summary = json!({
        "template": {
            "shown": shown_template,
            "hash": template.hash(),
            "registered": view.registry.is_some(),
            "names_itself": template.self_name(),
            "version": template.version(),
            "summary": template.summary(),
            "roots": roots,
        },
        "path": {
            "name": spend.path.name,
            "who": spend.path.who,
            "effect": spend.path.effect,
            "leaf": leaf,
            "kind": spend.path.kind,
        },
        "params": params,
        "slots": slots,
        "contract": {
            "script_pubkey": contract.derived.script_pubkey,
            "coin": format!("{}:{}", spend.outpoint.txid, spend.outpoint.vout),
            "change": show_map(&contract_change),
        },
        "wallet_change": wallet_change,
        "payments": payments,
        "fee": fee,
        "outputs": spend.outputs,
        "sequence": format!("{:#010x} ({})", spend.sequence(), show_sequence(spend.sequence())),
        "locks": locks,
        "checks": {
            "1_known_template": format!("{} is on this wallet's list", template.hash()),
            "2_output_recomputed": format!("the engine derived {} from the template and the instance; the coin pays it", contract.derived.script_pubkey),
            "3_program_run": if spend.path.kind == "simplicity" {
                format!("the program ran against the final transaction: cost {} milli-WU of a {} WU budget{}",
                    finalized.cost_mwu, finalized.budget_wu,
                    if finalized.annex_bytes > 0 { format!(", padded with a {}-byte annex", finalized.annex_bytes) } else { String::new() })
            } else {
                "a tapscript leaf: no program to run; its script is recomputed from the template".into()
            },
            "4_shown": "this summary",
            "5_contract_key": format!("{key_param} is this wallet's contract key at {key_path}"),
        },
        "unsigned_txid": spend.tx.txid().to_string(),
        "unsigned_tx": encode::serialize_hex(&spend.tx),
        "weight": weight,
        "vsize": vsize,
    });
    Ok((summary, finalized))
}

/// The asset the template's amounts are in: its one `asset` parameter, when
/// it has exactly one. Otherwise an amount is shown in atoms.
fn template_asset(spend: &Spend) -> Option<String> {
    let assets: Vec<_> = spend
        .contract
        .template
        .params()
        .iter()
        .filter(|p| p.role == "asset")
        .collect();
    match assets.as_slice() {
        [one] => Some(show_value(
            "asset",
            &spend.contract.instance.params[&one.name],
        )),
        _ => None,
    }
}

/// The asset of the coin, display hex.
fn contract_asset(spend: &Spend) -> Option<String> {
    spend.coin.asset.explicit().map(|a| a.to_string())
}
