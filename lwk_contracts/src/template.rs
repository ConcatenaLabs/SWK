//! Templates, instances and the outputs they derive.
//!
//! A template is read with `sequentia-contracts`' own reader (the reference
//! implementation of the descriptor specification), checked with the pinned
//! compiler from the source texts it was handed, and its Simplicity leaves are
//! kept compiled so a spend can be run against its final transaction.

use std::collections::BTreeMap;
use std::sync::Arc;

pub use sequentia_contracts::descriptor::Node;
use sequentia_contracts::descriptor::{
    parse_json, Descriptor, Model, Param, Path2, ScriptItem, SimplicityLeaf, TreeDerived,
    WitnessValue, NUMS_KEY,
};
use serde::Serialize;
use serde_json::Value;
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::elements::Script;
use simplicityhl::CompiledProgram;

use crate::error::Error;
use crate::hex::{hex, unhex};

/// BIP68's type flag: a relative lock counted in units of 512 seconds.
pub const SEQUENCE_TIME_FLAG: u32 = 1 << 22;
/// BIP68's disable flag.
pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;

/// A checked template: its descriptor, its model, and each Simplicity leaf
/// compiled from the text it was handed.
#[derive(Clone)]
pub struct Template {
    descriptor: Descriptor,
    model: Model,
    programs: BTreeMap<String, Arc<CompiledProgram>>,
    sources: BTreeMap<String, String>,
}

impl std::fmt::Debug for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Template")
            .field("hash", &self.descriptor.template_hash)
            .finish()
    }
}

/// What a spending path needs, as a wallet shows and supplies it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PathInfo {
    pub name: String,
    pub who: String,
    pub effect: String,
    /// `simplicity`, `tapscript` or `key`.
    pub kind: String,
    /// The leaf it spends; `None` for the key path.
    pub leaf: Option<String>,
    /// Each value the spend's witness carries, in order.
    pub witness: Vec<WitnessNeed>,
    /// The parameter whose value is the BIP68 sequence the input must carry,
    /// when the leaf checks one with `OP_CHECKSEQUENCEVERIFY`.
    pub sequence_param: Option<String>,
    /// The parameter whose value is the lock time the transaction must carry,
    /// when the leaf checks one with `OP_CHECKLOCKTIMEVERIFY`.
    pub lock_time_param: Option<String>,
}

/// One witness value of a path.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WitnessNeed {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    /// `param:<NAME>`, `slot:<NAME>`, `signature:<KEY PARAM>` or `spender`.
    pub source: String,
}

impl Template {
    /// Reads and checks a descriptor. `sources` maps each Simplicity leaf's
    /// `source` name to its text with the helper includes resolved (what
    /// `seqc expand` prints): every check `seqc descriptor check` makes,
    /// including compiling each source with the pinned compiler and comparing
    /// its root, witness and cost bound with the descriptor's.
    pub fn new(descriptor_json: &str, sources: &BTreeMap<String, String>) -> Result<Self, Error> {
        let descriptor = Descriptor::parse(descriptor_json).map_err(Error::Descriptor)?;
        descriptor
            .validate_sources(sources)
            .map_err(Error::Descriptor)?;
        let model = descriptor.model().map_err(Error::Descriptor)?;
        let mut programs = BTreeMap::new();
        let mut leaf_sources = BTreeMap::new();
        for (leaf, _) in model.tree.leaves() {
            if let Node::Simplicity { name, program } = leaf {
                let text = &sources[&program.source];
                leaf_sources.insert(name.clone(), text.clone());
                let compiled =
                    sequentia_contracts::compile_expanded(text, simplicityhl::Arguments::default())
                        .map_err(Error::Descriptor)?;
                programs.insert(name.clone(), Arc::new(compiled));
            }
        }
        Ok(Template {
            descriptor,
            model,
            programs,
            sources: leaf_sources,
        })
    }

    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    /// The template hash: its identity.
    pub fn hash(&self) -> &str {
        &self.descriptor.template_hash
    }

    fn field(&self, key: &str) -> Option<&Value> {
        self.descriptor.template.get(key)
    }

    /// The name the template gives itself. Only a registry vouches for a name.
    pub fn self_name(&self) -> String {
        self.field("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn version(&self) -> u64 {
        self.field("version").and_then(Value::as_u64).unwrap_or(0)
    }

    pub fn summary(&self) -> String {
        self.field("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn params(&self) -> &[Param] {
        &self.model.params
    }

    pub fn slots(&self) -> &[Param] {
        &self.model.slots
    }

    /// The parameter or slot of this name, and whether it is a slot.
    pub fn field_param(&self, name: &str) -> Option<(&Param, bool)> {
        self.model
            .params
            .iter()
            .find(|p| p.name == name)
            .map(|p| (p, false))
            .or_else(|| {
                self.model
                    .slots
                    .iter()
                    .find(|p| p.name == name)
                    .map(|p| (p, true))
            })
    }

    /// A leaf of the tree, by name.
    pub fn leaf(&self, name: &str) -> Option<&Node> {
        self.model
            .tree
            .leaves()
            .into_iter()
            .map(|(n, _)| n)
            .find(|n| n.name() == Some(name))
    }

    /// The compiled program of a Simplicity leaf.
    pub fn program(&self, leaf: &str) -> Option<&Arc<CompiledProgram>> {
        self.programs.get(leaf)
    }

    /// The resolved source text of a Simplicity leaf.
    pub fn source_text(&self, leaf: &str) -> Option<&str> {
        self.sources.get(leaf).map(String::as_str)
    }

    /// The Simplicity leaf's descriptor entry.
    pub fn simplicity_leaf(&self, leaf: &str) -> Option<&SimplicityLeaf> {
        match self.leaf(leaf) {
            Some(Node::Simplicity { program, .. }) => Some(program),
            _ => None,
        }
    }

    pub fn path(&self, name: &str) -> Option<&Path2> {
        self.model.paths.iter().find(|p| p.name == name)
    }

    /// Every way to spend, with what each needs.
    pub fn paths(&self) -> Vec<PathInfo> {
        self.model.paths.iter().map(|p| self.path_info(p)).collect()
    }

    fn path_info(&self, p: &Path2) -> PathInfo {
        let (kind, witness, seq, lock) = match p.leaf.as_deref().and_then(|l| self.leaf(l)) {
            Some(Node::Simplicity { program, .. }) => (
                "simplicity",
                program.witness.iter().map(need).collect(),
                None,
                None,
            ),
            Some(Node::Tapscript { items, .. }) => {
                let keys = tapscript_keys(items);
                let witness = keys
                    .iter()
                    .rev()
                    .map(|k| WitnessNeed {
                        name: format!("signature of {k}"),
                        ty: "Signature".into(),
                        source: format!("signature:{k}"),
                    })
                    .collect();
                let (s, l) = tapscript_locks(items);
                ("tapscript", witness, s, l)
            }
            _ => ("key", Vec::new(), None, None),
        };
        PathInfo {
            name: p.name.clone(),
            who: p.who.clone(),
            effect: p.effect.clone(),
            kind: kind.into(),
            leaf: p.leaf.clone(),
            witness,
            sequence_param: seq,
            lock_time_param: lock,
        }
    }

    /// Whether the template has a key path (an internal key other than NUMS).
    pub fn has_key_path(&self) -> bool {
        self.model.internal_key != NUMS_KEY
    }
}

fn need(w: &WitnessValue) -> WitnessNeed {
    let source = match w.source.strip_prefix("signature:sig_all_hash:") {
        Some(k) => format!("signature:{k}"),
        None => w.source.clone(),
    };
    WitnessNeed {
        name: w.name.clone(),
        ty: w.ty.clone(),
        source,
    }
}

/// The parameters a tapscript pushes as keys checked by a signature opcode:
/// each `push` immediately followed by `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`
/// or `OP_CHECKSIGADD`.
pub fn tapscript_keys(items: &[ScriptItem]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if let ScriptItem::Push(p) = item {
            if let Some(ScriptItem::Bytes(next)) = items.get(i + 1) {
                if matches!(next.first(), Some(0xac | 0xad | 0xba)) {
                    out.push(p.clone());
                }
            }
        }
    }
    out
}

/// The parameters a tapscript checks as a relative lock (`num` then
/// `OP_CHECKSEQUENCEVERIFY`) and as a lock time (`num` then
/// `OP_CHECKLOCKTIMEVERIFY`).
pub fn tapscript_locks(items: &[ScriptItem]) -> (Option<String>, Option<String>) {
    let (mut seq, mut lock) = (None, None);
    for (i, item) in items.iter().enumerate() {
        if let ScriptItem::Num(p) = item {
            match items.get(i + 1) {
                Some(ScriptItem::Bytes(b)) if b.first() == Some(&0xb2) => seq = Some(p.clone()),
                Some(ScriptItem::Bytes(b)) if b.first() == Some(&0xb1) => lock = Some(p.clone()),
                _ => {}
            }
        }
    }
    (seq, lock)
}

/// An instance: a template hash, its values and its chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instance {
    pub instance: u64,
    pub template_hash: String,
    pub params: BTreeMap<String, String>,
    pub slots: BTreeMap<String, String>,
    /// The chain's genesis hash, display hex; `None` names no chain.
    pub genesis: Option<String>,
}

impl Instance {
    /// Reads an instance record. Unknown fields are refused, as the
    /// descriptor's readers refuse them.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let v = parse_json(text).map_err(Error::Instance)?;
        let obj = v
            .as_object()
            .ok_or_else(|| Error::Instance("an instance is a JSON object".into()))?;
        for k in obj.keys() {
            if !["instance", "template_hash", "params", "slots", "genesis"].contains(&k.as_str()) {
                return Err(Error::Instance(format!("unknown field {k}")));
            }
        }
        let version = v["instance"]
            .as_u64()
            .filter(|n| *n == 1 || *n == 2)
            .ok_or_else(|| Error::Instance("instance is not 1 or 2".into()))?;
        let template_hash = v["template_hash"]
            .as_str()
            .ok_or_else(|| Error::Instance("no template_hash".into()))?
            .to_string();
        let strings = |key: &str| -> Result<BTreeMap<String, String>, Error> {
            match v.get(key) {
                None if key == "slots" => Ok(BTreeMap::new()),
                None => Err(Error::Instance(format!("no {key}"))),
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, x)| {
                        x.as_str()
                            .map(|s| (k.clone(), s.to_string()))
                            .ok_or_else(|| Error::Instance(format!("{key}.{k} is not a string")))
                    })
                    .collect(),
                Some(_) => Err(Error::Instance(format!("{key} is not an object"))),
            }
        };
        if version == 1 && v.get("slots").is_some() {
            return Err(Error::Instance("a version 1 instance has no slots".into()));
        }
        let genesis = match v.get("genesis") {
            Some(Value::String(s)) => {
                unhex(s, 32).map_err(|e| Error::Instance(format!("genesis: {e}")))?;
                Some(s.clone())
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err(Error::Instance("genesis is a hash or null".into())),
        };
        Ok(Instance {
            instance: version,
            template_hash,
            params: strings("params")?,
            slots: strings("slots")?,
            genesis,
        })
    }
}

/// A template and an instance of it: an output recomputed from both.
#[derive(Debug, Clone)]
pub struct Contract {
    pub template: Arc<Template>,
    pub instance: Instance,
    pub derived: TreeDerived,
}

impl Contract {
    /// Recomputes the instance's output from the template. Refuses an
    /// instance of another template, or one of the template's other version.
    pub fn new(template: Arc<Template>, instance: Instance) -> Result<Self, Error> {
        if instance.template_hash != template.hash() {
            return Err(Error::Instance(format!(
                "the instance is of template {}, not {}",
                instance.template_hash,
                template.hash()
            )));
        }
        if instance.instance != template.descriptor.descriptor {
            return Err(Error::Instance(format!(
                "a version {} instance of a version {} descriptor",
                instance.instance, template.descriptor.descriptor
            )));
        }
        let derived = template
            .model
            .derive(&instance.params, &instance.slots)
            .map_err(Error::Instance)?;
        Ok(Contract {
            template,
            instance,
            derived,
        })
    }

    /// The same instance with other slot values: its next state.
    pub fn with_slots(&self, slots: BTreeMap<String, String>) -> Result<Self, Error> {
        let mut instance = self.instance.clone();
        instance.slots = slots;
        Contract::new(self.template.clone(), instance)
    }

    pub fn script_pubkey(&self) -> Script {
        Script::from(unhex(&self.derived.script_pubkey, 34).expect("derived"))
    }

    /// The unblinded address on a chain with this bech32 prefix.
    pub fn address(&self, hrp: &str) -> Result<String, Error> {
        sequentia_contracts::descriptor::address(&self.derived.output_key, hrp)
            .ok_or_else(|| Error::Instance(format!("{hrp} is not a bech32 prefix")))
    }

    /// The control block that reveals a leaf.
    pub fn control_block(&self, leaf: &str) -> Result<ControlBlock, Error> {
        let cb = self
            .derived
            .leaves
            .get(leaf)
            .and_then(|l| l.control_block.as_ref())
            .ok_or_else(|| Error::Spend(format!("{leaf} is not a spendable leaf")))?;
        ControlBlock::from_slice(&unhex(cb, cb.len() / 2).expect("derived"))
            .map_err(|e| Error::Spend(format!("control block: {e}")))
    }

    /// A tapscript leaf's script, its parameters in place.
    pub fn leaf_script(&self, leaf: &str) -> Result<Script, Error> {
        let s = self
            .derived
            .leaves
            .get(leaf)
            .and_then(|l| l.script.as_ref())
            .ok_or_else(|| Error::Spend(format!("{leaf} is not a tapscript leaf")))?;
        Ok(Script::from(unhex(s, s.len() / 2).expect("derived")))
    }

    /// A parameter or slot value, as its bytes.
    pub fn value_bytes(&self, name: &str) -> Result<Vec<u8>, Error> {
        let v = self
            .instance
            .params
            .get(name)
            .or_else(|| self.instance.slots.get(name))
            .ok_or_else(|| Error::Spend(format!("no value {name}")))?;
        unhex(v, v.len() / 2).map_err(|e| Error::Spend(format!("{name}: {e}")))
    }

    /// A parameter or slot value of at most 8 bytes, as a number.
    pub fn value_u64(&self, name: &str) -> Result<u64, Error> {
        let b = self.value_bytes(name)?;
        if b.len() > 8 {
            return Err(Error::Spend(format!("{name} is wider than 8 bytes")));
        }
        Ok(b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)))
    }

    /// The derivation as the golden vectors write it (version 2 form).
    pub fn derived_json(&self) -> Value {
        let leaves: serde_json::Map<String, Value> = self
            .derived
            .leaves
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::to_value(v).expect("plain")))
            .collect();
        serde_json::json!({
            "leaves": leaves,
            "merkle_root": self.derived.merkle_root,
            "tweak": self.derived.tweak,
            "output_key": self.derived.output_key,
            "output_key_parity": self.derived.output_key_parity,
            "script_pubkey": self.derived.script_pubkey,
        })
    }
}

/// Shows a value by its role: what a wallet prints beside the label.
pub fn show_value(role: &str, hex_value: &str) -> String {
    match role {
        "asset" => {
            // Internal byte order in the template; the RPC and the explorer print the reverse.
            let b = unhex(hex_value, 32).unwrap_or_default();
            let rev: Vec<u8> = b.iter().rev().copied().collect();
            hex(&rev)
        }
        "amount" | "number" | "height" => u128::from_str_radix(hex_value, 16)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| hex_value.into()),
        "time" => u64::from_str_radix(hex_value, 16)
            .map(|v| format!("{v} (unix time)"))
            .unwrap_or_else(|_| hex_value.into()),
        "sequence" => u32::from_str_radix(hex_value, 16)
            .map(show_sequence)
            .unwrap_or_else(|_| hex_value.into()),
        _ => hex_value.into(),
    }
}

/// A BIP68 sequence in words.
pub fn show_sequence(seq: u32) -> String {
    if seq & SEQUENCE_DISABLE_FLAG != 0 {
        return format!("{seq:#010x}: no relative lock");
    }
    let n = seq & 0xffff;
    if seq & SEQUENCE_TIME_FLAG != 0 {
        let secs = u64::from(n) * 512;
        format!("{n} × 512 s = {secs} s ({})", show_duration(secs))
    } else {
        format!("{n} blocks")
    }
}

/// A number of seconds in days, hours and minutes.
pub fn show_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    let s = secs % 60;
    match (d, h, m) {
        (0, 0, 0) => format!("{s} s"),
        (0, 0, _) => format!("{m} min {s} s"),
        (0, _, _) => format!("{h} h {m} min"),
        _ => format!("{d} d {h} h {m} min"),
    }
}
