//! `paylock`: every step of the swap of a Sequentia asset for an on-chain bitcoin
//! payment, as one command, for products that drive it from another language and
//! for the operator of a completion service.
//!
//! Each command prints one JSON object. The nodes are named by environment:
//! `PAYLOCK_SEQ_URL` with `PAYLOCK_SEQ_USER` and `PAYLOCK_SEQ_PASS` (or
//! `PAYLOCK_SEQ_COOKIE`, a cookie file) for the Sequentia node, and the same with
//! `PAYLOCK_BTC_` for the Bitcoin daemon. Secret keys are read from files
//! (`--key-file`), never from the command line.
//!
//! ```text
//! paylock activation
//! paylock terms      --asset A --atoms N --price SAT --buyer X --seller X --receive-key K [--floor F] [--deadline D] [--margin 6]
//!                    [--fee-pot-asset A --fee-pot-atoms N]
//! paylock check-lock --terms T --lock TXID:VOUT [--fee-coin TXID:VOUT,...]
//! paylock sign-claim --terms T --lock TXID:VOUT --key-file F --to SPK --fee N [--top-fee N|auto|none] [--value N]
//!                    [--fee-pot | --fee-coin TXID:VOUT [--change SPK] [--wallet-signed HEX,...]]
//! paylock complete   --terms T --lock TXID:VOUT --claim HEX --payment TXID [--send]
//! paylock cancel     --payment-hex HEX --values V,V --to SPK [--fee SAT]
//! paylock sign-refund --terms T --lock TXID:VOUT --key-file F --to SPK --fee N [--send] [--despite-payment]
//!                    [--fee-pot | --fee-coin TXID:VOUT [--change SPK] [--wallet-signed HEX]]
//! paylock serve      --data DIR --listen HOST:PORT [--interval SECS] [--token-file F] [--max-jobs N]
//!                    [--jobs-per-client 50] [--watch-depth 6] [--watch-every 30]
//! ```
//!
//! `T` is a terms file, or the terms' JSON itself.
//!
//! `terms` builds a payment lock only when the node reports both rules it needs active
//! for its next block; otherwise it answers `"payment_lock": false` and no lock, and the
//! product keeps today's swap. A claim pays its fee in an asset block producers accept:
//! the locked asset, the terms' fee pot, or a coin of the buyer's own (`--fee-coin`).
//! `check-lock` is payable only when one of these is accepted, and `sign-claim` refuses a
//! fee in an asset the node does not accept. With `--fee-coin`, `sign-claim` first answers
//! the unsigned `templates`; the buyer's wallet signs the coin's input of each, and the
//! same command with `--wallet-signed` adds the claim's own signature.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use lwk_paylock::{
    activation, checklock_reasons, complete_claim, fee_routes, outpoint, service, BtcChain,
    Completion, Error, Rpc, SeqChain, TxStatus,
};
use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{
    self, check_lock, fee_of, fee_pot_vout, hex_decode, hex_encode, FeePlan, FeePot, FeeSource,
    LockFacts, PayLockTerms,
};
use lwk_wollet::elements::encode::{deserialize, serialize};
use lwk_wollet::elements::secp256k1_zkp::{SecretKey, XOnlyPublicKey};
use lwk_wollet::elements::{Script, Transaction};
use serde_json::{json, Value};

type Args = HashMap<String, String>;

fn parse(args: &[String]) -> Result<Args, Error> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let k = args[i]
            .strip_prefix("--")
            .ok_or_else(|| Error(format!("unexpected argument {}", args[i])))?;
        if k == "send" || k == "despite-payment" || k == "fee-pot" {
            m.insert(k.to_string(), "1".to_string());
            i += 1;
            continue;
        }
        let v = args
            .get(i + 1)
            .ok_or_else(|| Error(format!("--{k} needs a value")))?;
        m.insert(k.to_string(), v.clone());
        i += 2;
    }
    Ok(m)
}

fn arg<'a>(a: &'a Args, k: &str) -> Result<&'a str, Error> {
    a.get(k)
        .map(String::as_str)
        .ok_or_else(|| Error(format!("--{k} is required")))
}

fn num(a: &Args, k: &str) -> Result<u64, Error> {
    arg(a, k)?
        .parse()
        .map_err(|_| Error(format!("--{k} must be a number")))
}

fn rpc(prefix: &str) -> Result<Rpc, Error> {
    rpc_with(prefix, Duration::from_secs(60))
}

fn rpc_with(prefix: &str, timeout: Duration) -> Result<Rpc, Error> {
    let env = |k: &str| std::env::var(format!("PAYLOCK_{prefix}_{k}")).ok();
    let url = env("URL").ok_or_else(|| Error(format!("PAYLOCK_{prefix}_URL is not set")))?;
    let (user, pass) = match env("COOKIE") {
        Some(path) => {
            let c =
                std::fs::read_to_string(&path).map_err(|e| Error(format!("cookie {path}: {e}")))?;
            let (u, p) = c
                .trim()
                .split_once(':')
                .ok_or_else(|| Error("a cookie is user:password".into()))?;
            (u.to_string(), p.to_string())
        }
        None => (
            env("USER").unwrap_or_default(),
            env("PASS").unwrap_or_default(),
        ),
    };
    Rpc::with_timeout(&url, &user, &pass, timeout)
}

fn seq() -> Result<SeqChain, Error> {
    Ok(SeqChain { rpc: rpc("SEQ")? })
}

fn btc() -> Result<BtcChain, Error> {
    Ok(BtcChain { rpc: rpc("BTC")? })
}

fn terms_of(a: &Args) -> Result<PayLockTerms, Error> {
    let t = arg(a, "terms")?;
    let text = if t.trim_start().starts_with('{') {
        t.to_string()
    } else {
        std::fs::read_to_string(t).map_err(|e| Error(format!("{t}: {e}")))?
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| Error(format!("terms: {e}")))?;
    Ok(PayLockTerms::from_json(&v)?)
}

fn key_of(a: &Args) -> Result<SecretKey, Error> {
    let p = arg(a, "key-file")?;
    let s = std::fs::read_to_string(p).map_err(|e| Error(format!("{p}: {e}")))?;
    SecretKey::from_slice(&hex_decode(s.trim())?).map_err(|e| Error(format!("key: {e}")))
}

fn xonly(a: &Args, k: &str) -> Result<XOnlyPublicKey, Error> {
    XOnlyPublicKey::from_slice(&hex_decode(arg(a, k)?)?).map_err(|e| Error(format!("--{k}: {e}")))
}

fn script(a: &Args, k: &str) -> Result<Script, Error> {
    Ok(Script::from(hex_decode(arg(a, k)?)?))
}

fn tx_hex(tx: &Transaction) -> String {
    hex_encode(&serialize(tx))
}

fn a_fee(a: &Args) -> Result<u64, Error> {
    num(a, "fee")
}

fn coins_of(a: &Args) -> Result<Vec<lwk_wollet::elements::OutPoint>, Error> {
    match a.get("fee-coin") {
        None => Ok(vec![]),
        Some(s) => s.split(',').map(|c| outpoint(c.trim())).collect(),
    }
}

/// The fee source the arguments name: the fee pot (`--fee-pot`), a coin (`--fee-coin`),
/// or the locked asset.
fn fee_source(
    a: &Args,
    seq: &SeqChain,
    t: &PayLockTerms,
    lock: &lwk_wollet::elements::OutPoint,
) -> Result<FeeSource, Error> {
    if a.contains_key("fee-pot") {
        let (tx, _) = seq
            .tx(&lock.txid)?
            .ok_or_else(|| Error("the node does not know the lock transaction".into()))?;
        let v = fee_pot_vout(t, &tx, lock.vout)
            .ok_or_else(|| Error("the lock transaction carries no fee pot of the terms".into()))?;
        return Ok(FeeSource::Pot(v));
    }
    if let Some(c) = a.get("fee-coin") {
        let op = outpoint(c)?;
        let txout = seq
            .txout(&op)?
            .ok_or_else(|| Error(format!("the fee coin {c} is spent or unknown")))?;
        return Ok(FeeSource::Coin {
            outpoint: op,
            txout,
        });
    }
    Ok(FeeSource::Locked)
}

/// A template with the claim leaf's witness on its lock inputs, for sizing only.
fn with_claim_witness(t: &PayLockTerms, s: &paylock::LockSpend) -> Transaction {
    let mut tx = s.tx.clone();
    let tree = t.tree().expect("terms build");
    for &i in &s.lock_inputs {
        tx.input[i].witness.script_witness = vec![
            vec![],
            vec![0; 64],
            tree.claim.to_bytes(),
            tree.claim_control.clone(),
        ];
    }
    tx
}

fn claims_json(claims: &[Transaction]) -> Value {
    json!({
        "claims": claims.iter().map(tx_hex).collect::<Vec<_>>(),
        "txids": claims.iter().map(|c| c.txid().to_string()).collect::<Vec<_>>(),
        "fees": claims.iter().map(|c| fee_of(c).map(|f| f.1)).collect::<Vec<_>>(),
        "fee_asset": claims.first().and_then(fee_of).map(|f| f.0.to_string()),
    })
}

fn btc_network(btc: &BtcChain) -> bitcoin::Network {
    match btc
        .rpc
        .call("getblockchaininfo", json!([]))
        .ok()
        .and_then(|v| v["chain"].as_str().map(String::from))
        .as_deref()
    {
        Some("main") => bitcoin::Network::Bitcoin,
        Some("regtest") => bitcoin::Network::Regtest,
        Some("signet") => bitcoin::Network::Signet,
        _ => bitcoin::Network::Testnet,
    }
}

fn run(cmd: &str, a: &Args) -> Result<Value, Error> {
    match cmd {
        "activation" => {
            let act = activation(&seq()?)?;
            Ok(json!({
                "payment_lock": act.payment_lock(),
                "btc_payment": act.btc_payment,
                "lost_blocks": act.lost_blocks,
                "window": act.window,
            }))
        }
        "terms" => {
            // Activation first: before these rules apply to the next block, the opcodes are
            // OP_SUCCESS and the lock would be anyone's. No lock and no receiving address
            // is built then; the product keeps today's swap.
            let seq = seq()?;
            let act = activation(&seq)?;
            if !act.payment_lock() {
                return Ok(json!({
                    "payment_lock": false,
                    "use": "today's swap",
                    "reason": "this node does not put its next block under both rules the payment lock needs",
                    "activation": {"btc_payment": act.btc_payment, "lost_blocks": act.lost_blocks, "window": act.window},
                }));
            }
            let btc = btc()?;
            let floor = match a.get("floor") {
                Some(f) => f.parse().map_err(|_| Error("--floor".into()))?,
                None => seq.tip_anchor()?,
            };
            let deadline = match a.get("deadline") {
                Some(d) => d.parse().map_err(|_| Error("--deadline".into()))?,
                None => {
                    let margin = a
                        .get("margin")
                        .map(|m| m.parse().unwrap_or(paylock::DEFAULT_DEADLINE_MARGIN));
                    paylock::deadline_for(
                        btc.tip()?,
                        margin.unwrap_or(paylock::DEFAULT_DEADLINE_MARGIN),
                    )
                }
            };
            let mut t = PayLockTerms::new(
                arg(a, "asset")?
                    .parse()
                    .map_err(|e| Error(format!("--asset: {e}")))?,
                num(a, "atoms")?,
                num(a, "price")?,
                xonly(a, "buyer")?,
                xonly(a, "seller")?,
                bitcoin::PublicKey::from_slice(&hex_decode(arg(a, "receive-key")?)?)
                    .map_err(|e| Error(format!("--receive-key: {e}")))?,
                floor,
                deadline,
            )?;
            if let Some(pa) = a.get("fee-pot-asset") {
                t = t.with_fee_pot(FeePot {
                    asset: pa
                        .parse()
                        .map_err(|e| Error(format!("--fee-pot-asset: {e}")))?,
                    atoms: num(a, "fee-pot-atoms")?,
                })?;
            }
            let tree = t.tree()?;
            let locked_ok = seq.fee_asset_accepted(&t.asset)?;
            let pot_ok = match &t.fee_pot {
                Some(p) => Some(seq.fee_asset_accepted(&p.asset)?),
                None => None,
            };
            let claim_fee = if locked_ok {
                "the locked asset"
            } else if pot_ok == Some(true) {
                "the fee pot"
            } else {
                "none the node accepts: the buyer must pay the claim's fee from a coin of its own, and the seller its refund's"
            };
            let mut out = json!({
                "payment_lock": true,
                "terms": t.to_json(),
                "lock_script_pubkey": hex_encode(tree.script_pubkey.as_bytes()),
                "receive_address": t.receive_address(btc_network(&btc)).to_string(),
                "fee": {"locked_asset_accepted": locked_ok, "fee_pot_accepted": pot_ok, "claim_pays_from": claim_fee},
            });
            if let Some(p) = &t.fee_pot {
                out["fee_pot"] = json!({"asset": p.asset.to_string(), "atoms": p.atoms,
                    "note": "the lock transaction pays the pot to lock_script_pubkey too, as a second output"});
            }
            Ok(out)
        }
        "check-lock" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let (seq, btc) = (seq()?, btc()?);
            let mut reasons = vec![];
            let mut routes: Vec<Value> = vec![];
            if !activation(&seq)?.payment_lock() {
                reasons.push(
                    "this node does not put its next block under the payment lock's rules"
                        .to_string(),
                );
            }
            match seq.tx(&lock.txid)? {
                Some((tx, TxStatus::Mined(h))) => {
                    let facts = LockFacts {
                        lock_tx: &tx,
                        vout: lock.vout,
                        lock_anchor: seq.at(h)?.anchor_height,
                        btc_tip: btc.tip()?,
                    };
                    reasons.extend(check_lock(&t, &facts));
                    let (node_payable, node) = seq.checklock(&lock.txid)?;
                    reasons.extend(checklock_reasons(node_payable, node));
                    // The claim must be able to pay its fee in an asset producers accept,
                    // or it is never mined and the seller refunds (section 8.1).
                    let coins = coins_of(a)?;
                    let r = fee_routes(&seq, &t, &tx, lock.vout, &coins);
                    if !r.iter().any(|r| r.usable) {
                        reasons.push(format!(
                            "the claim cannot pay its fee in an asset block producers accept ({}); \
                             it would never be mined and the seller would refund. Pay only with a fee \
                             pot in the lock or a coin of your own in an accepted asset (--fee-coin)",
                            r.iter()
                                .filter_map(|r| r.why_not.clone())
                                .collect::<Vec<_>>()
                                .join("; ")
                        ));
                    }
                    routes = r.iter().map(|r| r.to_json()).collect();
                }
                _ => reasons.push(
                    "the lock is not in a block of the active chain: wait until it is mined".into(),
                ),
            }
            Ok(json!({"payable": reasons.is_empty(), "reasons": reasons, "fee_routes": routes}))
        }
        "sign-claim" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let seq = seq()?;
            let genesis = seq.genesis()?;
            let sk = key_of(a)?;
            let to = script(a, "to")?;
            let source = fee_source(a, &seq, &t, &lock)?;
            let change = a.get("change").map(|_| script(a, "change")).transpose()?;
            let plan_with = |fee: u64| FeePlan {
                source: source.clone(),
                fee,
                change: change.clone(),
            };
            let fee_asset = plan_with(1).asset(&t)?;
            // Fail closed: a claim whose fee the node does not accept is never mined.
            if !seq.fee_asset_accepted(&fee_asset)? {
                return Err(Error(format!(
                    "block producers do not accept a fee in asset {fee_asset}: a claim paying it would never be mined. \
                     Pay the fee from the lock's fee pot (--fee-pot) or a coin of your own in an accepted asset (--fee-coin)"
                )));
            }
            // The second step of a fee coin: the wallet signed the coin's input of each template.
            if let Some(signed) = a.get("wallet-signed") {
                let mut claims = vec![];
                for h in signed.split(',') {
                    let w: Transaction = deserialize(&hex_decode(h.trim())?)
                        .map_err(|e| Error(format!("--wallet-signed: {e}")))?;
                    let (_, fee) =
                        fee_of(&w).ok_or_else(|| Error("--wallet-signed: no fee output".into()))?;
                    claims.push(paylock::sign_claim_with(
                        &t,
                        lock,
                        to.clone(),
                        &plan_with(fee),
                        genesis,
                        &sk,
                        Some(&w),
                    )?);
                }
                return Ok(claims_json(&claims));
            }
            let going = paylock::lock_spend(
                &t,
                lock,
                to.clone(),
                &plan_with(a_fee(a)?),
                paylock::CLAIM_SEQUENCE,
            )?;
            let mut fees = vec![a_fee(a)?];
            let top = match a.get("top-fee").map(String::as_str) {
                None | Some("auto") => {
                    // V in the fee asset's atoms: the locked atoms, or their worth at the node's
                    // rates, or what the wallet states (--value).
                    let value = if fee_asset == t.asset {
                        t.atoms
                    } else if let Some(v) = a.get("value") {
                        v.parse()
                            .map_err(|_| Error("--value must be a number".into()))?
                    } else {
                        match (seq.fee_asset_rate(&t.asset)?, seq.fee_asset_rate(&fee_asset)?) {
                            (Some(rl), Some(rf)) if rf > 0 => {
                                (u128::from(t.atoms) * u128::from(rl) / u128::from(rf)) as u64
                            }
                            _ => {
                                return Err(Error(
                                    "the top tier is priced at the locked value in the fee asset, and the node prices only one of the two: \
                                     give --value (the locked value in atoms of the fee asset) or --top-fee"
                                        .into(),
                                ))
                            }
                        }
                    };
                    // Sized for a proof of about 1.2 kilobytes, the usual completed claim.
                    let v = paylock::claim_vsize(&with_claim_witness(&t, &going), 1_200);
                    Some(paylock::top_tier_fee(
                        value,
                        v,
                        paylock::BLOCK_VSIZE,
                        paylock::TOP_TIER_BLOCKS,
                        2,
                    ))
                }
                Some("none") => None,
                Some(n) => Some(n.parse().map_err(|_| Error("--top-fee".into()))?),
            };
            if let Some(top) = top.filter(|f| *f > fees[0]) {
                paylock::lock_spend(
                    &t,
                    lock,
                    to.clone(),
                    &plan_with(top),
                    paylock::CLAIM_SEQUENCE,
                )
                .map_err(|e| {
                    Error(format!(
                        "the top tier's fee is {top} atoms, and its source cannot pay it ({e}): \
                             use a larger fee coin, or name the tier with --top-fee"
                    ))
                })?;
                fees.push(top);
            }
            if matches!(source, FeeSource::Coin { .. }) {
                let templates = fees
                    .iter()
                    .map(|f| {
                        paylock::lock_spend(
                            &t,
                            lock,
                            to.clone(),
                            &plan_with(*f),
                            paylock::CLAIM_SEQUENCE,
                        )
                        .map(|s| tx_hex(&s.tx))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(json!({
                    "templates": templates,
                    "fees": fees,
                    "fee_asset": fee_asset.to_string(),
                    "sign_input": 1,
                    "next": "sign input 1 of each template with the coin's wallet, then run sign-claim again with --wallet-signed",
                }));
            }
            let claims = fees
                .iter()
                .map(|f| {
                    paylock::sign_claim_with(
                        &t,
                        lock,
                        to.clone(),
                        &plan_with(*f),
                        genesis,
                        &sk,
                        None,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(claims_json(&claims))
        }
        "complete" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let claim: Transaction =
                deserialize(&hex_decode(arg(a, "claim")?)?).map_err(|e| Error(e.to_string()))?;
            let (seq, btc) = (seq()?, btc()?);
            match complete_claim(&seq, &btc, &t, &lock, &claim, arg(a, "payment")?)? {
                Completion::Ready {
                    tx,
                    height,
                    vout,
                    proof_bytes,
                } => {
                    let sent = if a.contains_key("send") {
                        Some(seq.send(&tx).map(|t| t.to_string()))
                    } else {
                        None
                    };
                    Ok(json!({
                        "state": "ready", "hex": tx_hex(&tx), "txid": tx.txid().to_string(),
                        "payment_height": height, "payment_vout": vout, "proof_bytes": proof_bytes,
                        "sent": sent.as_ref().map(|r| r.as_ref().ok().cloned()),
                        "send_error": sent.and_then(|r| r.err().map(|e| e.0)),
                    }))
                }
                Completion::Waiting(w) => Ok(json!({"state": "waiting", "reason": w})),
                Completion::Never(w) => Ok(json!({"state": "never", "reason": w})),
            }
        }
        "cancel" => {
            let values = arg(a, "values")?
                .split(',')
                .map(|v| {
                    v.trim()
                        .parse::<u64>()
                        .map_err(|_| Error("--values".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let pay = hex_decode(arg(a, "payment-hex")?)?;
            let to = bitcoin::ScriptBuf::from(hex_decode(arg(a, "to")?)?);
            // The least fee that still replaces the payment (BIP125), unless more is asked.
            let floor = paylock::cancel_fee_floor(&pay, &values, to.clone())?;
            let fee = match a.get("fee") {
                Some(_) => num(a, "fee")?,
                None => floor,
            };
            let tx = paylock::cancel_template(&pay, &values, to, fee)?;
            Ok(json!({
                "hex": hex_encode(&bitcoin::consensus::encode::serialize(&tx)),
                "txid": tx.compute_txid().to_string(),
                "fee": fee,
                "fee_floor": floor,
            }))
        }
        "sign-refund" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let seq = seq()?;
            // The seller refunds only when no payment to its receiving script is mined in
            // the lock's heights (section 8.2, step 7): such a payment is a buyer's, and
            // its claim can still be mined. `--despite-payment` signs anyway.
            if !a.contains_key("despite-payment") {
                let btc = btc()?;
                let hi = t.deadline.min(btc.tip()?);
                let spk = t.receive_script_pubkey();
                if let Some((txid, h)) =
                    btc.paid_to(spk.as_bytes(), t.price_sat, t.floor + 1, hi)?
                {
                    return Err(Error(format!(
                        "a payment to the receiving address ({txid}, Bitcoin block {h}) is in the lock's heights: \
                         the buyer's claim can still be mined, so this wallet does not refund"
                    )));
                }
            }
            let source = fee_source(a, &seq, &t, &lock)?;
            let plan = FeePlan {
                source: source.clone(),
                fee: a_fee(a)?,
                change: a.get("change").map(|_| script(a, "change")).transpose()?,
            };
            let fee_asset = plan.asset(&t)?;
            if !seq.fee_asset_accepted(&fee_asset)? {
                return Err(Error(format!(
                    "block producers do not accept a fee in asset {fee_asset}: a refund paying it would never be mined. \
                     Pay the fee from the lock's fee pot (--fee-pot) or a coin of your own in an accepted asset (--fee-coin)"
                )));
            }
            let wallet_signed: Option<Transaction> = match a.get("wallet-signed") {
                Some(h) => Some(
                    deserialize(&hex_decode(h)?)
                        .map_err(|e| Error(format!("--wallet-signed: {e}")))?,
                ),
                None => None,
            };
            if matches!(source, FeeSource::Coin { .. }) && wallet_signed.is_none() {
                let s = paylock::lock_spend(
                    &t,
                    lock,
                    script(a, "to")?,
                    &plan,
                    paylock::CLAIM_SEQUENCE,
                )?;
                return Ok(json!({"template": tx_hex(&s.tx), "sign_input": 1,
                    "next": "sign input 1 with the coin's wallet, then run sign-refund again with --wallet-signed"}));
            }
            let tx = paylock::sign_refund_with(
                &t,
                lock,
                script(a, "to")?,
                &plan,
                seq.genesis()?,
                &key_of(a)?,
                wallet_signed.as_ref(),
            )?;
            let sent = if a.contains_key("send") {
                Some(seq.send(&tx).map(|t| t.to_string()))
            } else {
                None
            };
            Ok(json!({
                "hex": tx_hex(&tx), "txid": tx.txid().to_string(),
                "sent": sent.as_ref().map(|r| r.as_ref().ok().cloned()),
                "send_error": sent.and_then(|r| r.err().map(|e| e.0)),
            }))
        }
        "serve" => {
            let interval = a
                .get("interval")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(2.0);
            let token = match a.get("token-file") {
                Some(p) => {
                    let t = std::fs::read_to_string(p)
                        .map_err(|e| Error(format!("{p}: {e}")))?
                        .trim()
                        .to_string();
                    if t.len() < 16 {
                        return Err(Error("the token must be at least 16 characters".into()));
                    }
                    Some(t)
                }
                None => None,
            };
            let mut limits = service::Limits::default();
            if let Some(n) = a.get("max-jobs") {
                limits.max_jobs = n.parse().map_err(|_| Error("--max-jobs".into()))?;
            }
            if let Some(n) = a.get("jobs-per-client") {
                limits.jobs_per_client =
                    n.parse().map_err(|_| Error("--jobs-per-client".into()))?;
            }
            if let Some(n) = a.get("watch-depth") {
                limits.watch_depth = n.parse().map_err(|_| Error("--watch-depth".into()))?;
            }
            if let Some(n) = a.get("watch-every") {
                limits.watch_every =
                    Duration::from_secs_f64(n.parse().map_err(|_| Error("--watch-every".into()))?);
            }
            // A slow node is given up on after 15 s, so one job's call cannot hold the
            // round; the cancel thread and intake give up after 3 s, so no send holds a
            // cancel back and no check holds intake for long.
            let (t, tc) = (Duration::from_secs(15), Duration::from_secs(3));
            service::serve(
                service::Clients {
                    seq: SeqChain {
                        rpc: rpc_with("SEQ", t)?,
                    },
                    btc: BtcChain {
                        rpc: rpc_with("BTC", t)?,
                    },
                    seq_cancels: SeqChain {
                        rpc: rpc_with("SEQ", tc)?,
                    },
                    btc_cancels: BtcChain {
                        rpc: rpc_with("BTC", tc)?,
                    },
                    seq_intake: SeqChain {
                        rpc: rpc_with("SEQ", tc)?,
                    },
                    btc_intake: BtcChain {
                        rpc: rpc_with("BTC", tc)?,
                    },
                },
                std::path::Path::new(arg(a, "data")?),
                arg(a, "listen")?,
                Duration::from_secs_f64(interval),
                limits,
                service::Access { token },
            )?;
            Ok(json!({}))
        }
        _ => Err(Error(format!(
            "unknown command {cmd}; see the crate documentation"
        ))),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprintln!("usage: paylock <activation|terms|check-lock|sign-claim|complete|cancel|sign-refund|serve> [--arg value ...]");
        return ExitCode::from(2);
    };
    match parse(&argv[1..]).and_then(|a| run(cmd, &a)) {
        Ok(v) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", json!({"error": e.0}));
            ExitCode::from(1)
        }
    }
}
