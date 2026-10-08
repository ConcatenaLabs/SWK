//! The templates this kit knows: copies of `sequentia-contracts`' published
//! templates at the revision `templates/PIN.json` names, each source with its
//! helper includes resolved (`seqc expand`), so the engine checks them with
//! no file system. A wallet's list of known templates starts here.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::template::Template;

/// A template the kit carries.
pub struct KnownTemplate {
    /// Its directory under `templates/`.
    pub dir: &'static str,
    pub hash: &'static str,
    pub descriptor: &'static str,
    /// Source name and resolved text of each Simplicity leaf.
    pub sources: &'static [(&'static str, &'static str)],
    pub vectors: &'static str,
}

/// `sequentia/one-key`, version 1.
pub const ONE_KEY: &str = "ad33258c1eb94ba8a748cde489498fda5b80a1026839c25bca20b3d3e77367a7";
/// `sequentia/one-key-exit`, version 1.
pub const ONE_KEY_EXIT: &str = "c8c53a337fd5f6af1c0ae6ccb30690adf3850265a3c135384082b63133d83c42";
/// `sequentia/faucet-drip`, version 1.
pub const FAUCET_DRIP: &str = "12986f202fbfb850f7699c5d5188f261f276de6c7038142f0a28bbb672b5af34";

pub const KNOWN: &[KnownTemplate] = &[
    KnownTemplate {
        dir: "one_key",
        hash: ONE_KEY,
        descriptor: include_str!("../templates/one_key/descriptor.json"),
        sources: &[(
            "one_key.simf",
            include_str!("../templates/one_key/one_key.simf"),
        )],
        vectors: include_str!("../templates/one_key/vectors.json"),
    },
    KnownTemplate {
        dir: "one_key_exit",
        hash: ONE_KEY_EXIT,
        descriptor: include_str!("../templates/one_key_exit/descriptor.json"),
        sources: &[(
            "one_key_exit.simf",
            include_str!("../templates/one_key_exit/one_key_exit.simf"),
        )],
        vectors: include_str!("../templates/one_key_exit/vectors.json"),
    },
    KnownTemplate {
        dir: "faucet_drip",
        hash: FAUCET_DRIP,
        descriptor: include_str!("../templates/faucet_drip/descriptor.json"),
        sources: &[(
            "faucet_drip.simf",
            include_str!("../templates/faucet_drip/faucet_drip.simf"),
        )],
        vectors: include_str!("../templates/faucet_drip/vectors.json"),
    },
];

impl KnownTemplate {
    pub fn sources(&self) -> BTreeMap<String, String> {
        self.sources
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// The template, checked as any other.
    pub fn template(&self) -> Result<Template, Error> {
        Template::new(self.descriptor, &self.sources())
    }
}

/// A known template, by hash.
pub fn known(hash: &str) -> Option<&'static KnownTemplate> {
    KNOWN.iter().find(|k| k.hash == hash)
}
