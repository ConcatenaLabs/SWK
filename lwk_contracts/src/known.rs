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

/// `pignus/vault`, version 2.
pub const PIGNUS_VAULT: &str = "6b17869c4e2abe782fe3d8a3ece4865b8f0aa483028b1d0a815e6bcb4e8939ac";
/// `pignus/offer`, version 2.
pub const PIGNUS_OFFER: &str = "4e999cdc9efa1186c0876ce9ebcc8e6dac60c10885bfb2cb5dce9489840084e7";

/// `sequentia/capped-sale`, version 1.
pub const CAPPED_SALE: &str = "9406d4247e602c013533c273316c0ab319ed41019aac59d39b102e8710556692";
/// `sequentia/subscription-escrow`, version 1.
pub const SUBSCRIPTION_ESCROW: &str =
    "e602bafffda0dd1f2c19b3725fb4a84aa3106ceee88ada4ff6865b249ca254b4";

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
    KnownTemplate {
        dir: "pignus_vault",
        hash: PIGNUS_VAULT,
        descriptor: include_str!("../templates/pignus_vault/descriptor.json"),
        sources: &[(
            "pignus_vault.simf",
            include_str!("../templates/pignus_vault/pignus_vault.simf"),
        )],
        vectors: include_str!("../templates/pignus_vault/vectors.json"),
    },
    KnownTemplate {
        dir: "pignus_offer",
        hash: PIGNUS_OFFER,
        descriptor: include_str!("../templates/pignus_offer/descriptor.json"),
        sources: &[(
            "pignus_offer.simf",
            include_str!("../templates/pignus_offer/pignus_offer.simf"),
        )],
        vectors: include_str!("../templates/pignus_offer/vectors.json"),
    },
    KnownTemplate {
        dir: "capped_sale",
        hash: CAPPED_SALE,
        descriptor: include_str!("../templates/capped_sale/descriptor.json"),
        sources: &[(
            "capped_sale.simf",
            include_str!("../templates/capped_sale/capped_sale.simf"),
        )],
        vectors: include_str!("../templates/capped_sale/vectors.json"),
    },
    KnownTemplate {
        dir: "subscription_escrow",
        hash: SUBSCRIPTION_ESCROW,
        descriptor: include_str!("../templates/subscription_escrow/descriptor.json"),
        sources: &[],
        vectors: include_str!("../templates/subscription_escrow/vectors.json"),
    },
];

/// Paths whose signature is made with a key the spender names rather than
/// a parameter: `(template, path, signature witness, key witness)`. The
/// capped sale's purchase is signed by the buyer's key on the allocation
/// list, which the purchase shows as a spender value (`BUYER_KEY`) and
/// proves against the sale's state; the descriptor gives both as `spender`
/// values, so the kit keeps which one is the signature and which the key.
/// The engine signs such a path only with this wallet's contract key, and
/// only when the request's key value is that key.
pub const SPENDER_KEYS: &[(&str, &str, &str, &str)] =
    &[(CAPPED_SALE, "purchase", "BUYER_SIG", "BUYER_KEY")];

/// The signature witness and the key witness of a path signed by a key the
/// spender names.
pub fn spender_key(template: &str, path: &str) -> Option<(&'static str, &'static str)> {
    SPENDER_KEYS
        .iter()
        .find(|(t, p, _, _)| *t == template && *p == path)
        .map(|(_, _, s, k)| (*s, *k))
}

/// Which value of which spender witness chooses each path of a template
/// whose paths share one Simplicity leaf: `(template, path, witness, the
/// literal's prefix)`. A descriptor names a path's leaf but not the value
/// that selects it among the leaf's branches, so the kit keeps this for the
/// templates it carries, and the engine refuses a request whose value
/// selects another path than the one it names (and the approval shows).
pub const PATH_SELECTORS: &[(&str, &str, &str, &str)] = &[
    (PIGNUS_VAULT, "repay", "PATH", "Left(Left("),
    (PIGNUS_VAULT, "top_up", "PATH", "Left(Right("),
    (PIGNUS_VAULT, "liquidate", "PATH", "Right(Left("),
    (PIGNUS_VAULT, "recover", "PATH", "Right(Right("),
    (PIGNUS_OFFER, "take", "PATH", "Left("),
    (PIGNUS_OFFER, "refund", "PATH", "Right("),
];

/// The witness and the literal prefix that choose `path` of `template`.
pub fn path_selector(template: &str, path: &str) -> Option<(&'static str, &'static str)> {
    PATH_SELECTORS
        .iter()
        .find(|(t, p, _, _)| *t == template && *p == path)
        .map(|(_, _, w, v)| (*w, *v))
}

/// Whether the kit knows which value selects each path of `template`.
pub fn has_selectors(template: &str) -> bool {
    PATH_SELECTORS.iter().any(|(t, ..)| *t == template)
}

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

/// A spender value of type `u64`, given as hex of its width.
fn spender_u64(spender: &BTreeMap<String, String>, name: &str) -> Result<u64, Error> {
    let v = spender
        .get(name)
        .ok_or_else(|| Error::Spend(format!("the spender's value {name} is not given")))?;
    let h = v.trim_start_matches("0x");
    if h.len() != 16 {
        return Err(Error::Spend(format!(
            "{name} is a u64, given as 16 hex digits; the request gives {v:?}"
        )));
    }
    u64::from_str_radix(h, 16).map_err(|e| Error::Spend(format!("{name}: {e}")))
}

/// The capped sale's purchase, read from the spender's values: the amount
/// bought before, the amount of this purchase and the cap of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CappedPurchase {
    pub cap: u64,
    pub bought: u64,
    pub amount: u64,
}

impl CappedPurchase {
    pub fn read(spender: &BTreeMap<String, String>) -> Result<Self, Error> {
        Ok(CappedPurchase {
            cap: spender_u64(spender, "CAP")?,
            bought: spender_u64(spender, "BOUGHT")?,
            amount: spender_u64(spender, "AMOUNT")?,
        })
    }
}

/// Refuses, before anything is signed or run, a capped-sale purchase that
/// would take the buyer's running total past the cap the allocation list
/// gives the key, or buy more than the coin holds. The program refuses both
/// as well; this says so in the purchase's own terms.
pub fn check_capped_purchase(
    spender: &BTreeMap<String, String>,
    coin: &crate::spend::CoinRequest,
) -> Result<CappedPurchase, Error> {
    let p = CappedPurchase::read(spender)?;
    let after = p
        .bought
        .checked_add(p.amount)
        .ok_or_else(|| Error::Spend("BOUGHT + AMOUNT overflows a 64-bit amount".to_string()))?;
    if after > p.cap {
        return Err(Error::Spend(format!(
            "a purchase of {} atoms would bring this key's total to {after}, past its cap of {} on the allocation list ({} bought so far, {} left); the sale refuses it, so nothing is signed",
            p.amount,
            p.cap,
            p.bought,
            p.cap.saturating_sub(p.bought)
        )));
    }
    if p.amount > coin.amount {
        return Err(Error::Spend(format!(
            "a purchase of {} atoms is more than the {} the sale's coin holds",
            p.amount, coin.amount
        )));
    }
    Ok(p)
}
