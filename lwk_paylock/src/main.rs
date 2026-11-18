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
//! paylock check-lock --terms T --lock TXID:VOUT
//! paylock sign-claim --terms T --lock TXID:VOUT --key-file F --to SPK --fee N [--top-fee N|auto]
//! paylock complete   --terms T --lock TXID:VOUT --claim HEX --payment TXID [--send]
//! paylock cancel     --payment-hex HEX --values V,V --to SPK --fee SAT
//! paylock sign-refund --terms T --lock TXID:VOUT --key-file F --to SPK --fee N [--send]
//! paylock serve      --data DIR --listen HOST:PORT [--interval SECS]
//! ```
//!
//! `T` is a terms file, or the terms' JSON itself.

use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;

use lwk_paylock::{
    activation, complete_claim, outpoint, service, BtcChain, Completion, Error, Rpc, SeqChain,
    TxStatus,
};
use lwk_wollet::bitcoin;
use lwk_wollet::btc::paylock::{self, check_lock, hex_decode, hex_encode, LockFacts, PayLockTerms};
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
        if k == "send" {
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
    Rpc::new(&url, &user, &pass)
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
            let btc = btc()?;
            let floor = match a.get("floor") {
                Some(f) => f.parse().map_err(|_| Error("--floor".into()))?,
                None => seq()?.tip_anchor()?,
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
            let t = PayLockTerms::new(
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
            let tree = t.tree()?;
            Ok(json!({
                "terms": t.to_json(),
                "lock_script_pubkey": hex_encode(tree.script_pubkey.as_bytes()),
                "receive_address": t.receive_address(btc_network(&btc)).to_string(),
            }))
        }
        "check-lock" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let (seq, btc) = (seq()?, btc()?);
            let mut reasons = vec![];
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
                    let (_, node) = seq.checklock(&lock.txid)?;
                    reasons.extend(node);
                }
                _ => reasons.push(
                    "the lock is not in a block of the active chain: wait until it is mined".into(),
                ),
            }
            Ok(json!({"payable": reasons.is_empty(), "reasons": reasons}))
        }
        "sign-claim" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let genesis = seq()?.genesis()?;
            let sk = key_of(a)?;
            let to = script(a, "to")?;
            let fee = num(a, "fee")?;
            let going = paylock::sign_claim(&t, lock, to.clone(), fee, genesis, &sk)?;
            let mut claims = vec![going.clone()];
            let top = match a.get("top-fee").map(String::as_str) {
                None | Some("auto") => {
                    // Sized for a proof of about 1.2 kilobytes, the usual completed claim.
                    let v = paylock::claim_vsize(&going, 1_200);
                    Some(paylock::top_tier_fee(
                        t.atoms,
                        v,
                        paylock::BLOCK_VSIZE,
                        paylock::TOP_TIER_BLOCKS,
                        2,
                    ))
                }
                Some("none") => None,
                Some(n) => Some(n.parse().map_err(|_| Error("--top-fee".into()))?),
            };
            if let Some(top) = top.filter(|f| *f > fee) {
                claims.push(paylock::sign_claim(&t, lock, to, top, genesis, &sk)?);
            }
            Ok(json!({
                "claims": claims.iter().map(tx_hex).collect::<Vec<_>>(),
                "txids": claims.iter().map(|c| c.txid().to_string()).collect::<Vec<_>>(),
                "fees": claims.iter().map(|c| c.output[1].value.explicit()).collect::<Vec<_>>(),
            }))
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
            let tx = paylock::cancel_template(
                &hex_decode(arg(a, "payment-hex")?)?,
                &values,
                bitcoin::ScriptBuf::from(hex_decode(arg(a, "to")?)?),
                num(a, "fee")?,
            )?;
            Ok(
                json!({"hex": hex_encode(&bitcoin::consensus::encode::serialize(&tx)), "txid": tx.compute_txid().to_string()}),
            )
        }
        "sign-refund" => {
            let t = terms_of(a)?;
            let lock = outpoint(arg(a, "lock")?)?;
            let seq = seq()?;
            let tx = paylock::sign_refund(
                &t,
                lock,
                script(a, "to")?,
                num(a, "fee")?,
                seq.genesis()?,
                &key_of(a)?,
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
            service::serve(
                seq()?,
                btc()?,
                std::path::Path::new(arg(a, "data")?),
                arg(a, "listen")?,
                Duration::from_secs_f64(interval),
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
