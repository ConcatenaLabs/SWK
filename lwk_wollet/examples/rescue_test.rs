//! SEQUENTIA: live functional test of the RBF (bump / replace) and CPFP rescues.
//!
//! Drives a real wallet against the live Sequentia testnet explorer and proves, end to end, that
//! the [`Wollet::bump_fee_of`] / [`Wollet::replace_tx_of`] / [`Wollet::cpfp_of`] primitives — the
//! exact code the wasm web-wallet wraps — build replacements/children the node accepts. Each
//! mechanism is tested in the regime it actually applies to (rather than the old harness's mistake
//! of grabbing "any priced asset" and assuming the result is stuck — serving-node-priced says
//! nothing about whether producers mine it):
//!
//!   • BUMP    — on an asset-fee self-send (reliably unconfirmed): re-pay the SAME payment at a
//!               higher fee in native tSEQ. Asserts the node accepts the replacement.
//!   • REPLACE — on a second asset-fee self-send: re-pin its inputs but send NEW outputs (a
//!               different amount) and pay the fee in tSEQ. Asserts the node accepts it.
//!   • CPFP    — on a low-fee *tSEQ* self-send (mineable, just under-priced): attach a child that
//!               spends the parent's unconfirmed change and pays a high tSEQ fee. Asserts the node
//!               accepts the child of an unconfirmed parent (the package mechanism).
//!
//!   cargo run -p lwk_wollet --example rescue_test --features sequentia
//!
//! Mnemonic comes from $SEQ_TEST_MNEMONIC (else a fixed throwaway testnet phrase). Funds have no
//! value.
use std::process::Command;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use lwk_common::{singlesig_desc, DescriptorBlindingKey, Signer, Singlesig};
use lwk_signer::SwSigner;
use lwk_wollet::blocking::{BlockchainBackend, EsploraClient};
use lwk_wollet::elements::{Address, AssetId, Txid};
use lwk_wollet::{Network, TxBuilder, Wollet, WolletBuilder, WolletDescriptor};

const BASE: &str = "http://159.195.15.140";
const ESPLORA: &str = "http://159.195.15.140/api";
const DEFAULT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn curl(args: &[&str]) -> String {
    let out = Command::new("curl")
        .args(["-s", "-m", "25"])
        .args(args)
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Parse `"<hex>": <number>` out of the /feerates JSON object (no serde needed).
fn rate_for(feerates: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let i = feerates.find(&needle)? + needle.len();
    let rest = &feerates[i..];
    let colon = rest.find(':')? + 1;
    rest[colon..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

/// full_scan with retry — the reverse-tunnel link drops connections (IncompleteMessage) often.
fn sync(wollet: &mut Wollet, client: &mut EsploraClient) -> R<()> {
    let mut last = None;
    for _ in 0..6 {
        match client.full_scan(wollet) {
            Ok(Some(update)) => match wollet.apply_update(update) {
                Ok(()) => return Ok(()),
                // The lagging esplora (behind the flaky tunnel) sometimes returns an older tip than
                // we've already cached; the cache is ahead, so just skip this stale update.
                Err(lwk_wollet::Error::UpdateHeightTooOld { .. }) => return Ok(()),
                Err(e) => return Err(e.into()),
            },
            Ok(None) => return Ok(()),
            Err(e) => {
                last = Some(e);
                sleep(Duration::from_secs(3));
            }
        }
    }
    Err(format!("scan failed after retries: {last:?}").into())
}

/// Sync until the wallet has no unconfirmed transactions, so each scenario starts from clean,
/// fully-confirmed state (blocks here are ~30-90s, so this settles quickly). Without this, a prior
/// scenario's still-unconfirmed tx gets re-selected and the next tx self-conflicts.
fn settle(wollet: &mut Wollet, client: &mut EsploraClient) -> R<()> {
    for _ in 0..25 {
        sync(wollet, client)?;
        if !wollet.transactions()?.iter().any(|t| t.height.is_none()) {
            return Ok(());
        }
        sleep(Duration::from_secs(8));
    }
    Ok(()) // best effort
}

/// (known, confirmed) for a txid, via the explorer.
fn tx_status(txid: &Txid) -> (bool, bool) {
    let s = curl(&[&format!("{ESPLORA}/tx/{txid}/status")]);
    (s.contains("confirmed"), s.contains("\"confirmed\":true") || s.contains("\"confirmed\": true"))
}

fn sign_finalize_broadcast(
    label: &str,
    mut pset: lwk_wollet::elements::pset::PartiallySignedTransaction,
    signer: &SwSigner,
    wollet: &Wollet,
    client: &EsploraClient,
) -> R<Option<Txid>> {
    signer.sign(&mut pset)?;
    let tx = wollet.finalize(&mut pset)?;
    match client.broadcast(&tx) {
        Ok(txid) => {
            println!("    ✅ {label}: node ACCEPTED → {txid}");
            Ok(Some(txid))
        }
        Err(e) => {
            println!("    ❌ {label}: node REJECTED → {e}");
            Ok(None)
        }
    }
}

/// Broadcast a built pset, then apply it to the wallet LOCALLY (no network scan) so a rescue can
/// re-pin its inputs / spend its change immediately — before the next block (~30-90s here) confirms
/// it, which would make RBF impossible. Returns the txid, or None if the node rejected it.
fn broadcast_and_apply(
    label: &str,
    mut pset: lwk_wollet::elements::pset::PartiallySignedTransaction,
    signer: &SwSigner,
    wollet: &mut Wollet,
    client: &EsploraClient,
) -> R<Option<Txid>> {
    signer.sign(&mut pset)?;
    let tx = wollet.finalize(&mut pset)?;
    let txid = match client.broadcast(&tx) {
        Ok(t) => {
            println!("    ✅ {label}: node ACCEPTED → {t}");
            t
        }
        Err(e) => {
            println!("    ❌ {label}: node REJECTED → {e}");
            return Ok(None);
        }
    };
    wollet.apply_transaction(tx)?; // local cache update — no round-trip
    Ok(Some(txid))
}

fn main() -> R<()> {
    let network = Network::sequentia_testnet();
    let policy = *network.policy_asset();
    let mnemonic = std::env::var("SEQ_TEST_MNEMONIC").unwrap_or_else(|_| DEFAULT_MNEMONIC.into());

    let signer = SwSigner::new(&mnemonic, false)?;
    let desc = WolletDescriptor::from_str(&singlesig_desc(
        &signer,
        Singlesig::Wpkh,
        DescriptorBlindingKey::Slip77,
    )?)?;
    let mut wollet = WolletBuilder::new(network, desc).build()?;
    let mut client = EsploraClient::new(ESPLORA, network)?;

    println!("== Sequentia RBF (bump/replace) + CPFP rescue test ==");
    let addr: Address = wollet.address(None)?.address().clone();
    let unconf = addr.to_unconfidential();
    println!("wallet: {unconf}");

    let feerates = curl(&[&format!("{BASE}/feerates")]);
    sync(&mut wollet, &mut client)?;
    let mut bal = wollet.balance()?;

    // A non-policy asset we hold that the serving node prices (so it accepts the asset-fee tx into
    // its mempool). We use it ONLY for bump/replace, which re-pin inputs and so work regardless of
    // whether producers would mine it.
    let priced_asset = |bal: &std::collections::BTreeMap<AssetId, u64>| {
        bal.iter()
            .filter(|(a, v)| **a != policy && **v > 1000 && rate_for(&feerates, &a.to_string()).is_some())
            .map(|(a, v)| (*a, *v))
            .max_by_key(|(_, v)| *v)
    };

    // Fund if needed.
    if bal.get(&policy).copied().unwrap_or(0) < 1_000_000 {
        println!("faucet tSEQ: {}", curl(&["-X","POST","-H","Content-Type: application/json","-d",&format!("{{\"address\":\"{unconf}\"}}"),&format!("{BASE}/faucet")]));
    }
    if priced_asset(&bal).is_none() {
        for a in ["USDX", "EURX", "GOLD", "WBTC"] {
            println!("faucet {a}: {}", curl(&["-X","POST","-H","Content-Type: application/json","-d",&format!("{{\"address\":\"{unconf}\",\"asset\":\"{a}\"}}"),&format!("{BASE}/faucet")]));
        }
    }
    for i in 0..30 {
        sync(&mut wollet, &mut client)?;
        bal = wollet.balance()?;
        if bal.get(&policy).copied().unwrap_or(0) >= 1_000_000 && priced_asset(&bal).is_some() {
            break;
        }
        if i % 3 == 0 {
            println!("  …waiting for funds (tSEQ={}, asset={:?})", bal.get(&policy).copied().unwrap_or(0), priced_asset(&bal));
        }
        sleep(Duration::from_secs(10));
    }
    bal = wollet.balance()?;
    let (asset, asset_bal) = priced_asset(&bal).ok_or("no node-priced asset funded")?;
    let arate = rate_for(&feerates, &asset.to_string()).unwrap();
    println!("tSEQ={} | asset {asset} bal={asset_bal} rate={arate}", bal.get(&policy).copied().unwrap_or(0));

    // An asset-fee self-send: reliably unconfirmed (producers won't mine a non-native fee), so a
    // dependable parent for the RBF tests.
    let asset_amt = (asset_bal / 16).max(1);
    // Send to the *unconfidential* address: Sequentia's default form, and the only one bump_fee_of
    // can recreate (it re-adds explicit recipient outputs; confidential ones are opt-in and can't be
    // bumped — bump errors clearly on them).
    let asset_stuck = |w: &Wollet| -> R<_> {
        Ok(TxBuilder::new(network)
            .add_explicit_recipient(&unconf, asset_amt, asset)?
            .fee_asset(asset, arate)
            .fee_rate(Some(2000.0)) // ~2 sat/vB-equiv — clears min relay for any asset rate
            .finish(w)?)
    };

    settle(&mut wollet, &mut client)?;
    // ---- 1) RBF BUMP: asset-fee parent → re-pay the same payment at a higher fee in tSEQ --------
    println!("\n[1/3] RBF bump (asset-fee parent → tSEQ)");
    if let Some(orig) = broadcast_and_apply("stuck (fee in asset)", asset_stuck(&wollet)?, &signer, &mut wollet, &client)? {
        let pset = wollet.bump_fee_of(orig)?.fee_rate(Some(8000.0)).finish(&wollet)?;
        if let Some(b) = sign_finalize_broadcast("bump → tSEQ", pset, &signer, &wollet, &client)? {
            sleep(Duration::from_secs(6));
            let orig_gone = !curl(&[&format!("{ESPLORA}/tx/{orig}")]).contains("\"txid\"");
            let (_, b_conf) = tx_status(&b);
            println!("  BUMP: PASS — replacement {b} accepted (orig replaced={orig_gone}, confirmed={b_conf})");
        } else {
            println!("  BUMP: FAIL");
        }
    }

    // ---- 2) RBF REPLACE: asset-fee parent → re-pin inputs, send NEW outputs, fee in tSEQ --------
    println!("\n[2/3] RBF replace (new outputs)");
    settle(&mut wollet, &mut client)?;
    if let Some(orig) = broadcast_and_apply("stuck #2 (fee in asset)", asset_stuck(&wollet)?, &signer, &mut wollet, &client)? {
        // New output: a different amount of the same asset back to ourselves, fee in tSEQ.
        let pset = wollet
            .replace_tx_of(orig)?
            .add_explicit_recipient(&unconf, (asset_amt / 2).max(1), asset)?
            .fee_rate(Some(8000.0))
            .finish(&wollet)?;
        if let Some(rep) = sign_finalize_broadcast("replace (new outputs)", pset, &signer, &wollet, &client)? {
            sleep(Duration::from_secs(6));
            let orig_gone = !curl(&[&format!("{ESPLORA}/tx/{orig}")]).contains("\"txid\"");
            println!("  REPLACE: PASS — {rep} accepted (orig replaced={orig_gone})");
        } else {
            println!("  REPLACE: FAIL");
        }
    }

    // ---- 3) CPFP: low-fee tSEQ parent (mineable, under-priced) → child spends its change --------
    println!("\n[3/3] CPFP (low-fee tSEQ parent → child)");
    settle(&mut wollet, &mut client)?;
    let tseq_stuck = TxBuilder::new(network)
        .add_explicit_recipient(&unconf, 100_000, policy)?
        .fee_rate(Some(1000.0)) // 1 sat/vB — clears min relay, still low priority
        .finish(&wollet)?;
    if let Some(parent) = broadcast_and_apply("low-fee tSEQ parent", tseq_stuck, &signer, &mut wollet, &client)? {
        let (_, p_conf) = tx_status(&parent);
        if p_conf {
            println!("  CPFP: inconclusive — parent confirmed before the child could attach (quiet testnet, no mempool backlog)");
        } else {
            let rate = wollet.cpfp_suggested_feerate(parent, 10_000.0)?; // target 10 sat/vB package
            // fee paid in tSEQ (default — producer-accepted); not the change's asset.
            let pset = wollet.cpfp_of(parent)?.fee_rate(Some(rate)).finish(&wollet)?;
            if let Some(child) = sign_finalize_broadcast("CPFP child (fee in tSEQ)", pset, &signer, &wollet, &client)? {
                println!("  CPFP: PASS — node accepted child {child} of unconfirmed parent {parent} (suggested child feerate {:.0} sat/kvb)", rate);
            } else {
                println!("  CPFP: FAIL");
            }
        }
    }

    println!("\n== done ==");
    Ok(())
}
