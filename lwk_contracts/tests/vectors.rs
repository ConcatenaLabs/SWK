//! The engine reproduces every golden vector of the templates it carries and
//! of the version 2 fixture, and refuses every case of the shared refusal
//! corpus for its reason: the same files `sequentia-contracts`' Rust reader and
//! its Python, JavaScript and Go mirrors check.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lwk_contracts::{Contract, Instance, Template};
use serde_json::{json, Value};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("templates")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The resolved source of each Simplicity leaf in a template directory.
fn sources(d: &Path) -> BTreeMap<String, String> {
    std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "simf"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                read(&p),
            )
        })
        .collect()
}

fn strings(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                .collect()
        })
        .unwrap_or_default()
}

/// Every vector of one template directory; returns how many.
fn check_vectors(d: &Path) -> usize {
    let t = Arc::new(Template::new(&read(&d.join("descriptor.json")), &sources(d)).unwrap());
    let vectors: Value = serde_json::from_str(&read(&d.join("vectors.json"))).unwrap();
    assert_eq!(vectors["template_hash"], json!(t.hash()), "{}", d.display());
    let v1 = vectors["vectors"] == json!(1);
    let mut n = 0;
    for a in vectors["addresses"].as_array().unwrap() {
        let name = a["name"].as_str().unwrap();
        let instance = Instance {
            instance: if v1 { 1 } else { 2 },
            template_hash: t.hash().into(),
            params: strings(&a["params"]),
            slots: strings(&a["slots"]),
            genesis: None,
        };
        let c = Contract::new(t.clone(), instance).unwrap_or_else(|e| panic!("{name}: {e}"));
        let got = c.derived_json();
        for k in [
            "merkle_root",
            "tweak",
            "output_key",
            "output_key_parity",
            "script_pubkey",
        ] {
            assert_eq!(got[k], a[k], "{}: {name}: {k}", d.display());
        }
        if v1 {
            assert_eq!(
                vectors["cmr"].as_str().unwrap(),
                t.simplicity_leaf("program").unwrap().cmr
            );
            assert_eq!(got["leaves"]["params"]["hash"], a["data_leaf"], "{name}");
            assert_eq!(got["leaves"]["params"]["data"], a["param_bytes"], "{name}");
            assert_eq!(
                got["leaves"]["program"]["hash"], a["program_leaf"],
                "{name}"
            );
        } else {
            assert_eq!(
                got["leaves"],
                a["leaves"],
                "{}: {name}: leaves",
                d.display()
            );
        }
        let chains = &t.descriptor().chains;
        for (chain, addr) in a["address"].as_object().unwrap() {
            let hrp = &chains.iter().find(|c| &c.name == chain).unwrap().bech32_hrp;
            assert_eq!(&json!(c.address(hrp).unwrap()), addr, "{name}: {chain}");
        }
        n += 1;
    }
    n
}

#[test]
fn every_vector_is_reproduced() {
    let mut counts = BTreeMap::new();
    for t in [
        "one_key",
        "one_key_exit",
        "faucet_drip",
        "fixtures/one_key_as_v2",
    ] {
        counts.insert(t, check_vectors(&dir().join(t)));
    }
    println!("vectors reproduced: {counts:?}");
    assert_eq!(
        counts,
        BTreeMap::from([
            ("faucet_drip", 8),
            ("fixtures/one_key_as_v2", 6),
            ("one_key", 6),
            ("one_key_exit", 10)
        ])
    );
}

#[test]
fn every_known_template_is_the_copy_in_templates() {
    for k in lwk_contracts::KNOWN {
        let t = k.template().unwrap();
        assert_eq!(t.hash(), k.hash);
        assert_eq!(
            k.descriptor,
            read(&dir().join(k.dir).join("descriptor.json"))
        );
    }
}

fn edit(doc: &mut Value, op: &Value) {
    let at = op["at"].as_array().unwrap();
    let mut target = doc;
    for k in &at[..at.len() - 1] {
        target = match k {
            Value::String(s) => target.get_mut(s.as_str()).unwrap(),
            Value::Number(n) => target.get_mut(n.as_u64().unwrap() as usize).unwrap(),
            _ => panic!("bad path"),
        };
    }
    let last = &at[at.len() - 1];
    let o = op.as_object().unwrap();
    if let Some(v) = o.get("set") {
        match last {
            Value::String(s) => target[s.as_str()] = v.clone(),
            Value::Number(n) => target[n.as_u64().unwrap() as usize] = v.clone(),
            _ => panic!("bad path"),
        }
    } else if o.contains_key("delete") {
        match last {
            Value::String(s) => {
                target.as_object_mut().unwrap().remove(s.as_str());
            }
            Value::Number(n) => {
                target
                    .as_array_mut()
                    .unwrap()
                    .remove(n.as_u64().unwrap() as usize);
            }
            _ => panic!("bad path"),
        }
    } else if let Some(v) = o.get("append") {
        target[last.as_str().unwrap()]
            .as_array_mut()
            .unwrap()
            .push(v.clone());
    } else if let Some(v) = o.get("suffix") {
        let k = last.as_str().unwrap();
        let s = format!("{}{}", target[k].as_str().unwrap(), v.as_str().unwrap());
        target[k] = s.into();
    } else {
        panic!("unknown edit {op}");
    }
}

fn base_dir(base: &str) -> PathBuf {
    match base {
        "mirrors/fixtures/one_key_as_v2" => dir().join("fixtures/one_key_as_v2"),
        b => dir().join(b.strip_prefix("templates/").unwrap()),
    }
}

#[test]
fn every_refusal_is_made_for_its_reason() {
    let text = read(&dir().join("fixtures/refusals.json"));
    let doc = sequentia_contracts::descriptor::parse_json(&text).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    let (mut refused, mut accepted) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let base = base_dir(case["base"].as_str().unwrap());
        let mut text = read(&base.join("descriptor.json"));
        if let Some(replacements) = case.get("text") {
            for r in replacements.as_array().unwrap() {
                text = text.replacen(r[0].as_str().unwrap(), r[1].as_str().unwrap(), 1);
            }
        } else {
            let mut d = sequentia_contracts::descriptor::parse_json(&text).unwrap();
            for op in case["edit"].as_array().unwrap() {
                edit(&mut d, op);
            }
            if case.get("reseal").and_then(Value::as_bool) != Some(false) {
                d["template_hash"] =
                    sequentia_contracts::descriptor::template_hash(&d["template"]).into();
            }
            text = serde_json::to_string_pretty(&d).unwrap();
        }
        let read = Template::new(&text, &sources(&base)).map(Arc::new);
        if case.get("accept").and_then(Value::as_bool) == Some(true) {
            read.unwrap_or_else(|e| panic!("{name}: refused: {e}"));
            accepted += 1;
            continue;
        }
        let err = match (read, case.get("derive")) {
            (Ok(t), Some(v)) => {
                let instance = Instance {
                    instance: t.descriptor().descriptor,
                    template_hash: t.hash().into(),
                    params: strings(&v["params"]),
                    slots: strings(&v["slots"]),
                    genesis: None,
                };
                Contract::new(t, instance)
                    .map(|_| ())
                    .expect_err(name)
                    .to_string()
            }
            (Ok(_), None) => panic!("{name}: ACCEPTED"),
            (Err(e), Some(_)) => panic!("{name}: the descriptor is refused: {e}"),
            (Err(e), None) => e.to_string(),
        };
        let expect = case["expect"].as_str().unwrap();
        assert!(
            err.contains(expect),
            "{name}: refused, but not for {expect:?}: {err}"
        );
        refused += 1;
    }
    println!("refusals made for their reason: {refused}; accepted as they must be: {accepted}");
    assert_eq!((refused, accepted), (75, 1));
}
