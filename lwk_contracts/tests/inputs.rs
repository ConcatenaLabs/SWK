//! Spends with more than the contract coin, with no chain: what the engine
//! refuses about the wallet's own inputs and foreign inputs before anything is
//! signed, each for its reason. `vault_regtest.rs` spends such inputs on a
//! chain.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use lwk_contracts::approval::{Approval, WalletView};
use lwk_contracts::spend::{
    default_contract_key_path, Chain, ChainFacts, CoinRequest, InputRequest, OutputRequest,
    Prevout, Spend, SpendRequest, WalletCoin,
};
use lwk_contracts::{known, Contract, Error, Instance};
use lwk_signer::SwSigner;
use simplicityhl::elements::BlockHash;

const OWNER: &str = "exist carry drive collect lend cereal occur much tiger just involve mean";
const GENESIS: &str = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";
const ASSET: &str = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23";
const OTHER_ASSET: &str = "1945f03695fc4bf67e0533af10993793be6a928b927bcc6fcf5d650c3c430a48";
// The P2WPKH script of OWNER's key at m/84h/1h/0h/0/0.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const WALLET_KEY: &str = "m/84h/1h/0h/0/0";

fn chain() -> Chain {
    Chain {
        genesis: BlockHash::from_str(GENESIS).unwrap(),
        mainnet: false,
    }
}

fn wallet_script(owner: &SwSigner) -> String {
    use simplicityhl::elements::bitcoin::bip32::DerivationPath;
    use simplicityhl::elements::hashes::Hash;
    let x = owner
        .derive_xprv(&DerivationPath::from_str(WALLET_KEY).unwrap())
        .unwrap();
    let pk = simplicityhl::elements::bitcoin::PublicKey::new(
        x.private_key
            .public_key(&simplicityhl::elements::secp256k1_zkp::Secp256k1::new()),
    );
    format!(
        "0014{}",
        lwk_contracts::hex::hex(
            simplicityhl::elements::WPubkeyHash::hash(&pk.to_bytes()).as_byte_array()
        )
    )
}

fn out(to: &str, script: Option<String>, asset: &str, amount: u64) -> OutputRequest {
    OutputRequest {
        to: to.into(),
        address: None,
        script,
        asset: asset.into(),
        amount,
        open: None,
        input: None,
    }
}

struct Case {
    contract: Arc<Contract>,
    owner: SwSigner,
    request: SpendRequest,
    coins: Vec<WalletCoin>,
    facts: ChainFacts,
}

/// A one-key contract coin and a wallet coin, paid to someone.
fn case() -> Case {
    let owner = SwSigner::new(OWNER, false).unwrap();
    let pk = Spend::key_at(&owner, &default_contract_key_path(false)).unwrap();
    let template = Arc::new(known(known::ONE_KEY).unwrap().template().unwrap());
    let contract = Arc::new(
        Contract::new(
            template,
            Instance {
                instance: 1,
                template_hash: known::ONE_KEY.into(),
                params: BTreeMap::from([("PK".into(), pk.to_string())]),
                slots: BTreeMap::new(),
                genesis: Some(GENESIS.into()),
            },
        )
        .unwrap(),
    );
    let ws = wallet_script(&owner);
    let coin = WalletCoin {
        txid: "33".repeat(32),
        vout: 0,
        script_pubkey: ws.clone(),
        asset: OTHER_ASSET.into(),
        amount: 50_000,
        key_path: WALLET_KEY.into(),
        confidential: false,
    };
    let request = SpendRequest {
        path: "spend".into(),
        coin: CoinRequest {
            txid: "11".repeat(32),
            vout: 1,
            script_pubkey: contract.derived.script_pubkey.clone(),
            asset: ASSET.into(),
            amount: 100_000,
        },
        inputs: Some(vec![
            InputRequest::Contract,
            InputRequest::Wallet {
                txid: coin.txid.clone(),
                vout: 0,
                asset: OTHER_ASSET.into(),
                amount: 50_000,
            },
        ]),
        sequence: None,
        lock_time: None,
        outputs: vec![
            out(
                "pay",
                Some(format!("0014{}", "22".repeat(20))),
                ASSET,
                100_000,
            ),
            out("wallet", Some(ws), OTHER_ASSET, 49_000),
            out("fee", None, OTHER_ASSET, 1_000),
        ],
        spender: BTreeMap::new(),
        next_slots: None,
    };
    Case {
        contract,
        owner,
        request,
        coins: vec![coin],
        facts: ChainFacts::default(),
    }
}

fn build(c: &Case) -> Result<Spend, Error> {
    let scripts = vec![lwk_contracts::spend::script_from_hex(&wallet_script(&c.owner)).unwrap()];
    Spend::build_with_coins(
        c.contract.clone(),
        chain(),
        &c.request,
        &scripts,
        &c.coins,
        Some(c.facts.clone()),
    )
}

fn refused(c: &Case) -> String {
    build(c).unwrap_err().to_string()
}

#[test]
fn a_fee_from_a_wallet_coin_in_another_asset_is_shown_and_signed() {
    let c = case();
    let a = Approval::prepare(
        build(&c).unwrap(),
        WalletView {
            known: vec![known::ONE_KEY.into()],
            ..Default::default()
        },
        &c.owner,
    )
    .unwrap();
    let s = a.summary();
    assert_eq!(s["inputs"][1]["is"], "wallet");
    assert_eq!(s["wallet_change"][0]["asset"], OTHER_ASSET);
    assert_eq!(s["wallet_change"][0]["change"], "-1000");
    let tx = a.sign(a.digest(), &c.owner).unwrap();
    // The contract input carries the program; the wallet input its signature and key.
    assert_eq!(tx.input[0].witness.script_witness.len(), 4);
    assert_eq!(tx.input[1].witness.script_witness.len(), 2);
    assert_eq!(tx.input[1].witness.script_witness[1].len(), 33);
}

#[test]
fn the_wallets_inputs_are_spent_only_as_its_own_record_says() {
    // Not among the wallet's coins.
    let mut c = case();
    c.coins.clear();
    assert!(refused(&c).contains("which is not among this wallet's coins"));
    // Another asset than the record.
    let mut c = case();
    if let Some(InputRequest::Wallet { asset, .. }) = c.request.inputs.as_mut().unwrap().get_mut(1)
    {
        *asset = ASSET.into();
    }
    assert!(refused(&c).contains("so it is not spent as shown"));
    // A confidential coin.
    let mut c = case();
    c.coins[0].confidential = true;
    assert!(refused(&c).contains("is confidential"));
    // A contract key answering for a wallet coin.
    let mut c = case();
    c.coins[0].key_path = default_contract_key_path(false);
    assert!(refused(&c).contains("a contract key never answers for a wallet coin"));
    // A script the engine does not sign for.
    let mut c = case();
    c.coins[0].script_pubkey = format!("5120{}", "44".repeat(32));
    assert!(refused(&c).contains("not a P2WPKH script"));
    // The same coin twice.
    let mut c = case();
    let again = c.request.inputs.as_ref().unwrap()[1].clone();
    c.request.inputs.as_mut().unwrap().push(again);
    assert!(refused(&c).contains("a second time"));
    // A key that does not pay the coin's script is refused at signing.
    let mut c = case();
    c.coins[0].key_path = "m/84h/1h/0h/0/1".into();
    let e = Approval::prepare(
        build(&c).unwrap(),
        WalletView {
            known: vec![known::ONE_KEY.into()],
            ..Default::default()
        },
        &c.owner,
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("not the coin's script"), "{e}");
}

#[test]
fn a_foreign_input_is_taken_only_through_a_committed_leaf_the_chain_backs() {
    let foreign = |witness: Vec<String>| InputRequest::Foreign {
        txid: "55".repeat(32),
        vout: 0,
        script_pubkey: format!("5120{NUMS}"),
        asset: ASSET.into(),
        amount: 1,
        witness,
        sequence: None,
        label: None,
    };
    let with = |w: Vec<String>, record: bool| {
        let mut c = case();
        c.request.inputs.as_mut().unwrap().push(foreign(w));
        c.request.outputs.push(OutputRequest {
            input: Some(2),
            ..out("foreign", None, ASSET, 1)
        });
        if record {
            c.facts.prevouts.insert(
                format!("{}:0", "55".repeat(32)),
                Prevout {
                    script_pubkey: format!("5120{NUMS}"),
                    asset: ASSET.into(),
                    amount: 1,
                },
            );
        }
        c
    };
    let e = refused(&with(
        vec![
            "51".into(),
            format!(
                "c4{}",
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            ),
        ],
        false,
    ));
    assert!(e.contains("the chain's record of it was not given"), "{e}");
    let e = refused(&with(vec!["00".repeat(64)], true));
    assert!(e.contains("is a key-path spend"), "{e}");
    let e = refused(&with(
        vec![
            "51".into(),
            format!(
                "c4{}",
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            ),
        ],
        true,
    ));
    assert!(
        e.contains("is not committed in the coin's output key"),
        "{e}"
    );
    // A foreign coin of this same contract: a chain of contract inputs.
    let mut c = case();
    let script = c.contract.derived.script_pubkey.clone();
    c.request
        .inputs
        .as_mut()
        .unwrap()
        .push(InputRequest::Foreign {
            txid: "77".repeat(32),
            vout: 0,
            script_pubkey: script.clone(),
            asset: ASSET.into(),
            amount: 5,
            witness: vec![],
            sequence: None,
            label: None,
        });
    c.facts.prevouts.insert(
        format!("{}:0", "77".repeat(32)),
        Prevout {
            script_pubkey: script,
            asset: ASSET.into(),
            amount: 5,
        },
    );
    assert!(refused(&c).contains("a chain of several contract inputs"));
}

#[test]
fn an_output_that_opens_a_contract_is_recomputed() {
    let mut c = case();
    c.request.outputs[0] = OutputRequest {
        open: Some(
            serde_json::json!({"instance": 1, "template_hash": "ab".repeat(32), "params": {}, "genesis": GENESIS}),
        ),
        ..out("open", None, ASSET, 100_000)
    };
    assert!(refused(&c).contains("which this kit does not carry"));
}

#[test]
fn the_key_path_and_a_path_of_two_signatures_are_refused() {
    let template = Arc::new(
        lwk_contracts::Template::new(
            include_str!("fixtures/two_keys/descriptor.json"),
            &BTreeMap::new(),
        )
        .unwrap(),
    );
    let contract = Arc::new(
        Contract::new(
            template,
            Instance {
                instance: 2,
                template_hash: "a0feb0b347a437488f19f9efd9d8f56f358c4e6f8b2e26f78feb3959fec6d499"
                    .into(),
                params: BTreeMap::from([
                    (
                        "A".into(),
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
                    ),
                    (
                        "B".into(),
                        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".into(),
                    ),
                ]),
                slots: BTreeMap::new(),
                genesis: Some(GENESIS.into()),
            },
        )
        .unwrap(),
    );
    let mut c = case();
    c.request.coin.script_pubkey = contract.derived.script_pubkey.clone();
    c.contract = contract;
    c.request.path = "key".into();
    let e = refused(&c);
    assert!(
        e.contains("spends by the internal key; the engine spends leaves only"),
        "{e}"
    );
    c.request.path = "both".into();
    let e = refused(&c);
    assert!(
        e.contains("takes 2 signatures") && e.contains("multisignature path is not spent here"),
        "{e}"
    );
}
