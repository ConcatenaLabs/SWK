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
use simplicityhl::elements::{encode, Script, Transaction};

use crate::error::Error;
use crate::hex::hex;
use crate::spend::{script_hash_hex, Finalized, Spend};
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
    e.input(b"lwk_contracts/approval/2\0");
    e.input(summary.to_string().as_bytes());
    hex(sha256::Hash::from_engine(e).as_ref())
}

/// The template line a wallet shows: the registry's name where it has one,
/// else the template's first program root.
fn shown_template(
    template: &crate::template::Template,
    registry: Option<&RegistryName>,
) -> (String, Vec<String>) {
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
    let shown = match registry {
        Some(r) => format!("{} v{} (registered)", r.name, r.version),
        None => format!(
            "an unregistered template, root {}",
            roots
                .first()
                .cloned()
                .unwrap_or_else(|| template.hash().to_string())
        ),
    };
    (shown, roots)
}

/// Each parameter of a contract by its role, as the wallet shows it.
fn shown_params(
    contract: &crate::template::Contract,
    view: &WalletView,
    our_key: Option<(&str, &str)>,
    wallet_scripts: &[Script],
) -> (Vec<Value>, Vec<Value>) {
    let template = &contract.template;
    let one_asset = template_asset_of(contract);
    let show = |p: &sequentia_contracts::descriptor::Param, v: &String| -> String {
        let mut shown = show_value(&p.role, v);
        if p.role == "asset" {
            if let Some(l) = view.assets.get(&shown) {
                shown = format!("{} ({shown})", l.ticker);
            }
        }
        if p.role == "amount" {
            if let Some(asset) = &one_asset {
                let atoms = i128::from(u64::from_str_radix(v, 16).unwrap_or(0));
                shown = amount(view, asset, atoms);
            }
        }
        if p.role == "pubkey" {
            if let Some((key, path)) = our_key {
                if v == key {
                    shown = format!("{v} (this wallet's contract key, {path})");
                }
            }
        }
        if p.role == "script_hash" {
            if let Some(s) = wallet_scripts.iter().find(|s| script_hash_hex(s) == *v) {
                shown = format!(
                    "{v} (SHA-256 of this wallet's script {})",
                    hex(s.as_bytes())
                );
            } else {
                shown = format!("{v} (SHA-256 of a script that is not this wallet's)");
            }
        }
        shown
    };
    let params = template
        .params()
        .iter()
        .map(|p| {
            let v = &contract.instance.params[&p.name];
            json!({"name": p.name, "label": p.label, "role": p.role, "type": p.ty, "value": v, "shown": show(p, v)})
        })
        .collect();
    let slots = template
        .slots()
        .iter()
        .map(|p| {
            let v = &contract.instance.slots[&p.name];
            json!({"name": p.name, "label": p.label, "role": p.role, "value": v, "shown": show(p, v)})
        })
        .collect();
    (params, slots)
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

    // 1. The template is on the wallet's list, and so is every template an
    //    output opens.
    if !view.known.iter().any(|h| h == template.hash()) {
        return Err(Error::Signing(format!(
            "template {} ({}) is not on this wallet's list of known templates",
            template.hash(),
            template.self_name()
        )));
    }
    for o in &spend.opened {
        let h = o.contract.template.hash();
        if !view.known.iter().any(|k| k == h) {
            return Err(Error::Signing(format!(
                "output {} opens a contract of template {h} ({}), which is not on this wallet's list of known templates",
                o.output,
                o.contract.template.self_name()
            )));
        }
    }
    // 2. The output was recomputed by `Spend::build`, which refuses a coin whose
    //    script is not the contract's; checked again here, with every opened one.
    if spend.coin.script_pubkey != contract.script_pubkey() {
        return Err(Error::Signing(
            "the coin is not the contract's output".into(),
        ));
    }
    for o in &spend.opened {
        if spend.tx.output[o.output].script_pubkey != o.contract.script_pubkey() {
            return Err(Error::Signing(format!(
                "output {} does not pay the contract it opens",
                o.output
            )));
        }
    }
    // The chain's locks.
    let locks = spend.check_locks()?;
    // 5. A contract key, and the one the path names, when the path takes one.
    let key = spend.contract_keypair(signer, key_path)?;
    // 3. Every program, run against the final transaction.
    let finalized = spend.finalize(signer, key_path)?;
    let weight = finalized.tx.weight();
    let vsize = weight.div_ceil(4);

    // 4. The summary.
    let leaf = spend.path.leaf.clone().unwrap_or_default();
    let (shown, roots) = shown_template(template, view.registry.as_ref());
    let our_key = key
        .as_ref()
        .map(|(kp, _)| hex(&kp.x_only_public_key().0.serialize()));
    let (params, slots) = shown_params(
        contract,
        view,
        our_key.as_deref().map(|k| (k, key_path)),
        &spend.wallet_scripts,
    );

    // Balance changes, per asset: the wallet's, the contract's, payments, the fee.
    let mut wallet: BTreeMap<String, i128> = BTreeMap::new();
    let mut contract_change: BTreeMap<String, i128> = BTreeMap::new();
    let mut inputs = Vec::new();
    for r in &spend.inputs {
        let a = i128::from(r.amount);
        let held = amount(view, &r.asset, a);
        match r.role.as_str() {
            "contract" => {
                *contract_change.entry(r.asset.clone()).or_default() -= a;
                inputs.push(json!({"index": r.index, "is": "contract", "coin": r.coin, "asset": r.asset, "amount": r.amount,
                    "shown": format!("the contract's coin, {held}"), "sequence": format!("{:#010x}", r.sequence),
                    "checked_against_chain": spend.chain_checked.contains(&r.index)}));
            }
            "wallet" => {
                *wallet.entry(r.asset.clone()).or_default() -= a;
                inputs.push(json!({"index": r.index, "is": "wallet", "coin": r.coin, "asset": r.asset, "amount": r.amount,
                    "script_pubkey": r.script_pubkey, "key_path": r.key_path,
                    "shown": format!("this wallet's coin, {held}, signed with its funding key {}", r.key_path.as_deref().unwrap_or_default())}));
            }
            _ => {
                // What the coin is, from what the engine itself knows.
                let named: Vec<String> = template
                    .params()
                    .iter()
                    .filter(|p| {
                        p.role == "asset"
                            && show_value("asset", &contract.instance.params[&p.name]) == r.asset
                    })
                    .map(|p| format!("{} ({})", p.name, p.label))
                    .collect();
                let returned: Vec<usize> = spend
                    .outputs
                    .iter()
                    .filter(|o| o.role == "foreign returned" && o.input == Some(r.index))
                    .map(|o| o.index)
                    .collect();
                let what = format!(
                    "a coin that is neither the contract's nor this wallet's: {held}{}, at script {}, spent through its {} leaf {} with the witness the request gives; {}",
                    if named.is_empty() { String::new() } else { format!(", the asset of this contract's parameter {}", named.join(", ")) },
                    r.script_pubkey,
                    r.leaf_kind.as_deref().unwrap_or_default(),
                    r.leaf.as_deref().unwrap_or_default(),
                    match returned.as_slice() {
                        [] => "it is not recreated".to_string(),
                        [o] => format!("recreated at output {o} with the same script, asset and amount"),
                        many => format!("recreated at outputs {many:?}"),
                    }
                );
                inputs.push(json!({"index": r.index, "is": "foreign", "coin": r.coin, "asset": r.asset, "amount": r.amount,
                    "script_pubkey": r.script_pubkey, "leaf_kind": r.leaf_kind, "leaf": r.leaf, "witness": r.witness,
                    "sequence": format!("{:#010x}", r.sequence), "recreated_at": returned,
                    "checked_against_chain": spend.chain_checked.contains(&r.index),
                    "request_says": r.label, "shown": what}));
            }
        }
    }
    let mut payments = Vec::new();
    let mut fee = Vec::new();
    let mut opens = Vec::new();
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
            "opens" => {
                let c = &spend
                    .opened
                    .iter()
                    .find(|x| x.output == o.index)
                    .expect("an opened output")
                    .contract;
                let (t_shown, _) = shown_template(&c.template, None);
                let (p, s) = shown_params(c, view, None, &spend.wallet_scripts);
                opens.push(json!({
                    "index": o.index, "asset": o.asset, "amount": o.amount,
                    "shown": format!("opens {} v{} ({}), holding {}", c.template.self_name(), c.template.version(), t_shown, amount(view, &o.asset, a)),
                    "template_hash": c.template.hash(), "script_pubkey": c.derived.script_pubkey,
                    "summary": c.template.summary(), "params": p, "slots": s}));
            }
            "foreign returned" => {}
            _ => fee.push(
                json!({"asset": o.asset, "amount": o.amount, "shown": amount(view, &o.asset, a)}),
            ),
        }
    }
    let show_map = |m: &BTreeMap<String, i128>| -> Vec<Value> {
        m.iter()
            .filter(|(_, d)| **d != 0)
            .map(|(asset, d)| json!({"asset": asset, "change": d.to_string(), "shown": amount(view, asset, *d)}))
            .collect()
    };
    let mut wallet_change = show_map(&wallet);
    if wallet_change.is_empty() {
        wallet_change.push(
            json!({"asset": null, "change": "0", "shown": "no change in any asset: this spend moves the contract's coin, not the wallet's"}),
        );
    }
    let mut contract_shown = show_map(&contract_change);
    if contract_shown.is_empty() {
        contract_shown.push(json!({"asset": null, "change": "0", "shown": "no change: the contract holds what it held"}));
    }

    let wallet_inputs: Vec<String> = spend
        .inputs
        .iter()
        .filter(|r| r.role == "wallet")
        .map(|r| {
            format!(
                "input {} ({})",
                r.index,
                r.key_path.as_deref().unwrap_or_default()
            )
        })
        .collect();
    let five = match &key {
        Some((_, param)) => format!(
            "{param} is this wallet's contract key at {key_path}{}",
            if wallet_inputs.is_empty() {
                String::new()
            } else {
                format!(
                    "; this wallet's funding keys sign only its own {}",
                    wallet_inputs.join(", ")
                )
            }
        ),
        None => format!(
            "path {} takes no signature, so no contract key signs; {}",
            spend.path.name,
            if wallet_inputs.is_empty() {
                "this wallet signs nothing else".to_string()
            } else {
                format!("this wallet's funding keys sign only its own {}, each key checked against its coin's script", wallet_inputs.join(", "))
            }
        ),
    };
    let mut ran = vec![if spend.path.kind == "simplicity" {
        format!("the contract's program (input {}) ran against the final transaction: cost {} milli-WU of a {} WU budget{}",
            spend.k, finalized.cost_mwu, finalized.budget_wu,
            if finalized.annex_bytes > 0 { format!(", padded with a {}-byte annex", finalized.annex_bytes) } else { String::new() })
    } else {
        format!("the contract's input {} is a tapscript leaf: no program to run; its script is recomputed from the template", spend.k)
    }];
    for (j, c, b) in &finalized.foreign_runs {
        ran.push(format!("input {j}'s program, as its witness gives it, ran against the final transaction: cost {c} milli-WU of a {b} WU budget"));
    }
    for r in spend
        .inputs
        .iter()
        .filter(|r| r.role == "foreign" && r.leaf_kind.as_deref() == Some("tapscript"))
    {
        ran.push(format!("input {} is a tapscript leaf, committed in its coin's output key (checked); the engine runs no tapscript, the node does", r.index));
    }
    let selected_by = match crate::known::path_selector(template.hash(), &spend.path.name) {
        Some((w, prefix)) => Value::from(format!("{w} = {prefix}… (checked against the kit's table for this template)")),
        None if template.paths().iter().filter(|p| p.leaf == spend.path.leaf).count() > 1 => Value::from(
            "the descriptor does not say which witness value selects this path among its leaf's; the program runs whichever the spender values choose",
        ),
        None => Value::Null,
    };
    let spender: Vec<Value> = spend
        .spender
        .iter()
        .map(|(k, v)| json!({"name": k, "value": v}))
        .collect();

    let summary = json!({
        "template": {
            "shown": shown,
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
            "selected_by": selected_by,
        },
        "params": params,
        "slots": slots,
        "spender": spender,
        "contract": {
            "script_pubkey": contract.derived.script_pubkey,
            "coin": format!("{}:{}", spend.outpoint.txid, spend.outpoint.vout),
            "input": spend.k,
            "change": contract_shown,
        },
        "inputs": inputs,
        "wallet_change": wallet_change,
        "payments": payments,
        "opens": opens,
        "fee": fee,
        "outputs": spend.outputs,
        "sequence": format!("{:#010x} ({})", spend.sequence(), show_sequence(spend.sequence())),
        "lock_time": spend.tx.lock_time.to_consensus_u32(),
        "locks": locks,
        "checks": {
            "1_known_template": if spend.opened.is_empty() {
                format!("{} is on this wallet's list", template.hash())
            } else {
                format!("{} is on this wallet's list, and so is every template an output opens ({})", template.hash(),
                    spend.opened.iter().map(|o| o.contract.template.hash().to_string()).collect::<Vec<_>>().join(", "))
            },
            "2_output_recomputed": format!("the engine derived {} from the template and the instance; the coin pays it{}", contract.derived.script_pubkey,
                spend.opened.iter().map(|o| format!("; output {} pays {}, derived from the instance it opens", o.output, o.contract.derived.script_pubkey)).collect::<Vec<_>>().join("")),
            "3_program_run": ran.join("; "),
            "4_shown": "this summary",
            "5_contract_key": five,
        },
        "unsigned_txid": spend.tx.txid().to_string(),
        "unsigned_tx": encode::serialize_hex(&spend.tx),
        "weight": weight,
        "vsize": vsize,
    });
    Ok((summary, finalized))
}

/// The asset a contract's amounts are in: its one `asset` parameter, when
/// it has exactly one. Otherwise an amount is shown in atoms.
fn template_asset_of(contract: &crate::template::Contract) -> Option<String> {
    let assets: Vec<_> = contract
        .template
        .params()
        .iter()
        .filter(|p| p.role == "asset")
        .collect();
    match assets.as_slice() {
        [one] => Some(show_value("asset", &contract.instance.params[&one.name])),
        _ => None,
    }
}
