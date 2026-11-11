//! Testnet4 esplora transport — wire types + the blocking and async clients.
//!
//! Endpoints: GET `/address/{a}`, `/address/{a}/utxo`, `/tx/{txid}`,
//! `/blocks/tip/height`; POST `/tx`. The blocking client (Ambra) fans out with
//! `std::thread::scope`; the async client (wasm/web) fans out with an ordered
//! `futures` `.buffered(8)`. Both feed the I/O-free [`super::core`].

#[allow(unused_imports)]
use crate::error::Error;

#[allow(dead_code)]
fn map<E: std::fmt::Debug>(e: E) -> Error {
    Error::Generic(format!("{e:?}"))
}

// --- wire types (shared by both transports) -----------------------------------

/// esplora address stats (chain + mempool): funded/spent sums + tx count.
#[derive(serde::Deserialize, Default)]
pub(crate) struct Stats {
    #[serde(default)]
    pub funded_txo_sum: i64,
    #[serde(default)]
    pub spent_txo_sum: i64,
    #[serde(default)]
    pub tx_count: i64,
}

#[derive(serde::Deserialize)]
pub(crate) struct AddrInfo {
    #[serde(default)]
    pub chain_stats: Stats,
    #[serde(default)]
    pub mempool_stats: Stats,
}

#[derive(serde::Deserialize)]
pub(crate) struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

/// Concurrent esplora requests in flight at once (bounded so a mobile client
/// doesn't spawn dozens of threads / sockets).
const CONCURRENCY: usize = 8;

/// Pick a sat/vB estimate for confirming within `target_blocks` from esplora's
/// `/fee-estimates` map (`{ "<target>": sat_per_vB }`): the largest available
/// target key `<= target_blocks` (its rate confirms at least that fast), falling
/// back to the fastest (smallest-key) estimate. `None` if the map is empty.
pub(crate) fn pick_fee(map: &std::collections::HashMap<String, f64>, target_blocks: u16) -> Option<f64> {
    let mut best: Option<(u16, f64)> = None;
    let mut fastest: Option<(u16, f64)> = None;
    for (k, v) in map {
        let Ok(t) = k.parse::<u16>() else { continue };
        if fastest.map_or(true, |(ft, _)| t < ft) {
            fastest = Some((t, *v));
        }
        if t <= target_blocks && best.map_or(true, |(bt, _)| t > bt) {
            best = Some((t, *v));
        }
    }
    best.or(fastest).map(|(_, v)| v)
}

// --- blocking transport (Ambra) -----------------------------------------------

#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]
pub(super) mod blocking {
    use super::*;
    use std::time::Duration;

    pub(in crate::btc) fn client() -> Result<reqwest::blocking::Client, Error> {
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().map_err(map)
    }

    /// Map `f` over `items` with at most [`CONCURRENCY`] in-flight, preserving
    /// order. Scoped threads borrow the client + base URL (no clones, no 'static).
    fn par_fetch<I: Sync, R: Send>(
        client: &reqwest::blocking::Client,
        base: &str,
        items: &[I],
        f: impl Fn(&reqwest::blocking::Client, &str, &I) -> R + Sync,
    ) -> Vec<R> {
        let mut out = Vec::with_capacity(items.len());
        for chunk in items.chunks(CONCURRENCY) {
            let part = std::thread::scope(|s| {
                let handles: Vec<_> = chunk.iter().map(|it| s.spawn(|| f(client, base, it))).collect();
                handles.into_iter().map(|h| h.join().expect("esplora worker panicked")).collect::<Vec<_>>()
            });
            out.extend(part);
        }
        out
    }

    pub(in crate::btc) fn fetch_infos(
        client: &reqwest::blocking::Client,
        base: &str,
        addrs: &[String],
    ) -> Vec<Option<AddrInfo>> {
        par_fetch(client, base, addrs, |c, base, addr: &String| {
            c.get(format!("{base}/address/{addr}")).send().ok()?.json::<AddrInfo>().ok()
        })
    }

    pub(in crate::btc) fn fetch_utxos(
        client: &reqwest::blocking::Client,
        base: &str,
        addrs: &[String],
    ) -> Vec<Vec<EsploraUtxo>> {
        par_fetch(client, base, addrs, |c, base, addr: &String| {
            c.get(format!("{base}/address/{addr}/utxo"))
                .send()
                .ok()
                .and_then(|r| r.json::<Vec<EsploraUtxo>>().ok())
                .unwrap_or_default()
        })
    }

    pub(in crate::btc) fn post_tx(client: &reqwest::blocking::Client, base: &str, hex: &str) -> Result<(bool, String), Error> {
        let resp = client.post(format!("{base}/tx")).body(hex.to_string()).send().map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().map_err(map)?;
        Ok((ok, body))
    }

    pub(in crate::btc) fn get_tx_json(client: &reqwest::blocking::Client, base: &str, txid: &str) -> Result<serde_json::Value, Error> {
        client.get(format!("{base}/tx/{txid}")).send().map_err(map)?.json().map_err(map)
    }

    pub(in crate::btc) fn tip_height(client: &reqwest::blocking::Client, base: &str) -> i64 {
        client
            .get(format!("{base}/blocks/tip/height"))
            .send()
            .ok()
            .and_then(|r| r.text().ok())
            .and_then(|t| t.trim().parse::<i64>().ok())
            .unwrap_or(-1)
    }

    /// Live BTC fee rate (sat/vB) for confirming within `target_blocks`, from the
    /// esplora `/fee-estimates`. `None` if unavailable. BITCOIN sat/vB only — never
    /// feed this into a Sequentia-asset fee (whose units are the asset's own).
    pub(in crate::btc) fn fee_estimate(client: &reqwest::blocking::Client, base: &str, target_blocks: u16) -> Option<f64> {
        let map: std::collections::HashMap<String, f64> =
            client.get(format!("{base}/fee-estimates")).send().ok()?.json().ok()?;
        super::pick_fee(&map, target_blocks)
    }
}

// --- async transport (wasm / web) ---------------------------------------------

#[cfg(feature = "btc-async")]
pub(super) mod asyncr {
    use super::*;
    use futures::stream::{self, StreamExt};

    pub(in crate::btc) fn client() -> Result<reqwest::Client, Error> {
        // No builder timeout: it is unsupported on the wasm fetch backend.
        Ok(reqwest::Client::new())
    }

    /// Ordered, bounded-concurrency (`.buffered(CONCURRENCY)`) fan-out — the async
    /// analogue of the blocking `par_fetch`, preserving input order.
    pub(in crate::btc) async fn fetch_infos(client: &reqwest::Client, base: &str, addrs: &[String]) -> Vec<Option<AddrInfo>> {
        stream::iter(addrs.iter())
            .map(|addr| async move {
                client.get(format!("{base}/address/{addr}")).send().await.ok()?.json::<AddrInfo>().await.ok()
            })
            .buffered(CONCURRENCY)
            .collect()
            .await
    }

    pub(in crate::btc) async fn fetch_utxos(client: &reqwest::Client, base: &str, addrs: &[String]) -> Vec<Vec<EsploraUtxo>> {
        stream::iter(addrs.iter())
            .map(|addr| async move {
                match client.get(format!("{base}/address/{addr}/utxo")).send().await {
                    Ok(r) => r.json::<Vec<EsploraUtxo>>().await.unwrap_or_default(),
                    Err(_) => Vec::new(),
                }
            })
            .buffered(CONCURRENCY)
            .collect()
            .await
    }

    pub(in crate::btc) async fn post_tx(client: &reqwest::Client, base: &str, hex: &str) -> Result<(bool, String), Error> {
        let resp = client.post(format!("{base}/tx")).body(hex.to_string()).send().await.map_err(map)?;
        let ok = resp.status().is_success();
        let body = resp.text().await.map_err(map)?;
        Ok((ok, body))
    }

    pub(in crate::btc) async fn get_tx_json(client: &reqwest::Client, base: &str, txid: &str) -> Result<serde_json::Value, Error> {
        client.get(format!("{base}/tx/{txid}")).send().await.map_err(map)?.json().await.map_err(map)
    }

    pub(in crate::btc) async fn tip_height(client: &reqwest::Client, base: &str) -> i64 {
        match client.get(format!("{base}/blocks/tip/height")).send().await {
            Ok(r) => r.text().await.ok().and_then(|t| t.trim().parse::<i64>().ok()).unwrap_or(-1),
            Err(_) => -1,
        }
    }

    /// Live BTC fee rate (sat/vB) for confirming within `target_blocks` (async).
    /// BITCOIN sat/vB only — never feed this into a Sequentia-asset fee.
    pub(in crate::btc) async fn fee_estimate(client: &reqwest::Client, base: &str, target_blocks: u16) -> Option<f64> {
        let map: std::collections::HashMap<String, f64> =
            client.get(format!("{base}/fee-estimates")).send().await.ok()?.json().await.ok()?;
        super::pick_fee(&map, target_blocks)
    }
}
