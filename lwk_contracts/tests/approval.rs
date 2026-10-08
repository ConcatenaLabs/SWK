//! The five-point gate, with no chain: a one-key contract's spend is shown and
//! signed only as the rule allows. `drip_regtest.rs` makes the same checks on a
//! chain, with a covenant, and puts the transactions in blocks.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use lwk_contracts::approval::{Approval, RegistryName, WalletView};
use lwk_contracts::spend::{
    default_contract_key_path, Chain, CoinRequest, OutputRequest, Spend, SpendRequest,
};
use lwk_contracts::{known, Contract, Instance};
use lwk_signer::SwSigner;
use serde_json::json;
use simplicityhl::elements::BlockHash;

// Public test mnemonics.
const OWNER: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";
const OTHER: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const GENESIS: &str = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";
const ASSET: &str = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23";

fn setup() -> (Spend, SwSigner) {
    let owner = SwSigner::new(OWNER, false).unwrap();
    let pk = Spend::key_at(&owner, &default_contract_key_path(false)).unwrap();
    let template = Arc::new(known(known::ONE_KEY).unwrap().template().unwrap());
    let instance = Instance {
        instance: 1,
        template_hash: known::ONE_KEY.into(),
        params: BTreeMap::from([("PK".into(), pk.to_string())]),
        slots: BTreeMap::new(),
        genesis: Some(GENESIS.into()),
    };
    let contract = Arc::new(Contract::new(template, instance).unwrap());
    let request = SpendRequest {
        path: "spend".into(),
        coin: CoinRequest {
            txid: "11".repeat(32),
            vout: 1,
            script_pubkey: contract.derived.script_pubkey.clone(),
            asset: ASSET.into(),
            amount: 100_000,
        },
        sequence: None,
        lock_time: None,
        outputs: vec![
            OutputRequest {
                to: "pay".into(),
                address: None,
                script: Some(format!("0014{}", "22".repeat(20))),
                asset: ASSET.into(),
                amount: 99_000,
            },
            OutputRequest {
                to: "fee".into(),
                address: None,
                script: None,
                asset: ASSET.into(),
                amount: 1_000,
            },
        ],
        spender: BTreeMap::new(),
        next_slots: None,
    };
    let chain = Chain {
        genesis: BlockHash::from_str(GENESIS).unwrap(),
        mainnet: false,
    };
    (
        Spend::build(contract, chain, &request, &[], None).unwrap(),
        owner,
    )
}

fn view() -> WalletView {
    WalletView {
        known: vec![known::ONE_KEY.into()],
        ..Default::default()
    }
}

#[test]
fn the_approval_shows_what_is_signed_and_only_that_is_signed() {
    let (spend, owner) = setup();
    let a = Approval::prepare(spend.clone(), view(), &owner).unwrap();
    let s = a.summary();
    assert_eq!(
        s["template"]["shown"],
        json!("an unregistered template, root c1a71ea2b1ccb88c315419a16ab142eab3864976863ee3c23ccb6bcaeee546fa")
    );
    assert_eq!(s["path"]["name"], json!("spend"));
    assert_eq!(s["params"][0]["role"], json!("pubkey"));
    assert!(s["params"][0]["shown"]
        .as_str()
        .unwrap()
        .contains("this wallet's contract key"));
    assert_eq!(s["wallet_change"][0]["change"], json!("0"));
    assert_eq!(s["payments"][0]["amount"], json!(99_000));
    assert_eq!(s["fee"][0]["amount"], json!(1_000));
    assert!(s["checks"]["3_program_run"]
        .as_str()
        .unwrap()
        .starts_with("the program ran against the final transaction"));

    // Only the digest shown signs.
    let e = a.sign(&"00".repeat(32), &owner).unwrap_err().to_string();
    assert!(e.contains("is not what was shown"), "{e}");
    let tx = a.sign(a.digest(), &owner).unwrap();
    assert_eq!(tx.input[0].witness.script_witness.len(), 4);
    // Another wallet cannot sign what this one prepared.
    let other = SwSigner::new(OTHER, false).unwrap();
    let e = a.sign(a.digest(), &other).unwrap_err().to_string();
    assert!(e.contains("is signed by PK"), "{e}");

    // The registry's name, where it has one.
    let mut v = view();
    v.registry = Some(RegistryName {
        name: "sequentia/one-key".into(),
        version: 1,
    });
    let b = Approval::prepare(spend, v, &owner).unwrap();
    assert_eq!(
        b.summary()["template"]["shown"],
        json!("sequentia/one-key v1 (registered)")
    );
    assert_ne!(
        a.digest(),
        b.digest(),
        "a different screen is a different digest"
    );
}

#[test]
fn the_rule_refuses_what_it_must() {
    let (spend, owner) = setup();
    // 1. A template not on the wallet's list.
    let e = Approval::prepare(spend.clone(), WalletView::default(), &owner)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("is not on this wallet's list of known templates"),
        "{e}"
    );
    // 5. A key outside the contract account, and a contract key the path does not name.
    let mut v = view();
    v.key_path = Some("m/84h/1h/0h/0/0".into());
    let e = Approval::prepare(spend.clone(), v, &owner)
        .unwrap_err()
        .to_string();
    assert!(e.contains("is not a contract key"), "{e}");
    let mut v = view();
    v.key_path = Some("m/8383h/1h/0h/0/1".into());
    let e = Approval::prepare(spend.clone(), v, &owner)
        .unwrap_err()
        .to_string();
    assert!(e.contains("is signed by PK"), "{e}");
    let other = SwSigner::new(OTHER, false).unwrap();
    let e = Approval::prepare(spend, view(), &other)
        .unwrap_err()
        .to_string();
    assert!(e.contains("is signed by PK"), "{e}");
}
