# SWK dual-chain plan: bring the Bitcoin parent-chain into the kit

> **STATUS (2026-07-08, refreshed 2026-07-25): HISTORICAL PLAN. The dual-chain
> work is implemented.**
> This document is kept as design history; the plan text below is the plan as
> approved, not a description of the current code. Where the plan named a type
> that no longer exists (the RFQ-era `XchainSwap` / `XchainSwapState`), the
> wording describes the role instead of the deleted name, so no reader mistakes
> it for present-day API. What actually happened, verified against the
> `sequentia` branch:
>
> **Built as planned**
> - The `btc` / `btc-async` / `btc-blocking` feature-gated module in
>   `lwk_wollet/src/btc/` (no new crate), with the blocking+async transports
>   over one I/O-free core, the wasm32 `compile_error!` guard, and
>   `bitcoin = "=0.32.8"` pinned in the workspace (Phases 0-1).
> - `ChainAddressParams` in `lwk_wollet/src/btc/addr.rs` with the hardcoded
>   Bitcoin network and shared `(coin_type, HRP)` per network; `isSequentia()`
>   on the wasm `Network`.
> - The single chain-agnostic redeemScript source (the Sequentia-leg builder in
>   `lwk_wollet/src/seqdex_htlc.rs`, which the BTC leg wraps), plus
>   blocking-vs-async build determinism locked by a parity test.
> - Phase 4 cross-chain glue in `lwk_wollet/src/btc/xchain.rs` and
>   `lwk_wasm/src/xchain.rs`: the self-verifying anchor gate (safety
>   requirement 1), persist-before-fund over an age-encrypted swap-state type
>   (requirements 4 and 9; that type was later removed together with the RFQ
>   client, so persistence is now the caller's contract and the kit's `btc`
>   features no longer pull `age`), the rate-derived any-asset Sequentia-claim fee
>   (closed decision kept), BIP125 RBF + `/fee-estimates` fees, crash-recovery
>   path modes (canonical deep HTLC paths with a recorded legacy `m/3/0` mode),
>   and a claim-deadline gate (requirement 8). Live-validated read-only against
>   the running testnet infrastructure (ignored integration test).
> - Ambra consumes the kit's `btc-blocking` feature (Phase 2 cutover happened
>   in the ambra repository).
>
> **Deviations from the plan**
> - Safety requirements 2 and 3 (value-scaled BTC reorg buffer, wall-clock
>   timelock comparison) were deliberately superseded: Sequentia follows
>   Bitcoin reorgs in real time, so the Sequentia leg's finality IS its anchor
>   block's Bitcoin finality. The shipped reveal gate requires anchor height at
>   or above the BTC funding height, `anchorstatus` ok, and a taker-chosen
>   anchor confirmation depth (default 1); the CLTV timelocks are liveness
>   only. See `lwk_wollet/src/btc/xchain.rs`.
> - No `SwSigner::sign_btc_psbt`: the btc module derives its BIP84 keychain
>   directly (bip39 + bip32, byte-identical results) and does not depend on
>   `lwk_signer`, keeping the wasm build free of the jade/ledger deps.
> - No `DualChainWallet` wasm type: the wasm surface is `BtcWallet` plus the
>   free cross-chain functions in `lwk_wasm/src/xchain.rs` alongside the existing
>   `Wollet`, and consumers compose them. (An `XchainSwap` wasm type did ship
>   here; it was removed with the RFQ client.)
>
> **Not built (still open)**
> - Phase 5 entirely: hardware-signer BTC routing, CPFP rescue for the BTC
>   side, mainnet wiring (there is no Sequentia mainnet; the inherited Liquid
>   coin_type `1776` in `lwk_common` (`signer.rs`, `descriptor.rs`) is still
>   unfixed, though `ChainAddressParams::mainnet()` already uses coin_type 0).
> - The full claim/refund golden-vector suite regenerated from a running
>   daemon (requirement 6) beyond the redeemScript and determinism parity
>   tests that do exist.
>
> For the current architecture, read [SEQUENTIA.md](SEQUENTIA.md) and the
> module docs in `lwk_wollet/src/btc/`.

Original plan text follows.

Status: approved plan, ready to implement. This consolidates the Bitcoin parent-chain
side into SWK so the kit builds standard dual-chain wallets directly, replacing the two
current per-wallet reimplementations (Ambra's `ambra_core` Rust, and the web wallet's
`btc.js` plus `xswap.js`).

## Goal and principles

A standard Sequentia wallet is always Bitcoin plus Sequentia, with no exception. One seed,
one default receiving address valid on both chains, two balances, cross-chain swaps. The
kit must provide all of this so consuming wallets do not reimplement it.

First principles this plan must honor:
- The Sequence token (ticker SEQ; tSEQ on testnet) is just another issued asset; it is never
  privileged in the UI/UX. The only special case is staking for block production. Any asset
  can be proposed as a transaction fee.
- Bitcoin anchoring is supreme and is verified by the wallet's OWN node, never trusted from a
  counterparty.
- Fee estimation in a wallet relies only on the rates at which the chosen fee asset has been
  accepted by block producers in the past.

## What makes this cheap (verified)

- `bitcoin` 0.32.8 is already in the dependency graph (transitive via `elements-miniscript`),
  re-exported at `lwk_wollet/src/lib.rs` as `pub use ...bitcoin`. It already models
  `Network::Testnet4`. No new crate dependency is needed; pin `bitcoin = "=0.32.8"` in the
  workspace so it cannot drift from the `elements-miniscript` transitive version (a drift
  would silently break HTLC redeemScript byte-identity).
- `SwSigner::derive_xprv(path)` already yields a `bitcoin::Xpriv` at any BIP84 path and works
  on wasm32 (used today by `seqdex_htlc.rs`).
- The Sequentia esplora server already serves Bitcoin testnet4 at `/testnet4/api` with
  identical esplora JSON shapes.
- `ambra_core` already contains a working, tested Rust BTC wallet and BTC-leg HTLC
  (`btc.rs`, `btc_htlc.rs`, `xchain.rs`). The task is largely relocate plus async-port, not
  greenfield. BDK is rejected (it adds 10 to 15 crates and duplicates descriptor machinery
  the kit already has).

## Address model (the load-bearing invariant)

Sequentia mirrors Bitcoin's address space per network, so the single shared address holds on
both testnet and mainnet:

- Testnet: BIP84 `m/84'/1'/0'`, bech32 HRP `tb` -> shared `tb1...` (Bitcoin testnet4 and
  Sequentia testnet derive the identical address).
- Mainnet: BIP84 `m/84'/0'/0'`, bech32 HRP `bc` -> shared `bc1...`.

Consequences for the implementation:
- `coin_type` selects which account xprv is derived (`m/84'/{coin_type}'/0'`); on each network
  both chains use Bitcoin's coin_type, so there is ONE account and ONE address.
- The inherited Liquid coin_type `1776` in `lwk_common` (`keyorigin_xpub` mainnet branch) is
  L-BTC's SLIP-44 value, not Sequentia's. It MUST be set to `0` for Sequentia mainnet so the
  mainnet address stays shared with Bitcoin. Do not introduce a "two namespaces on mainnet"
  branch; there is one namespace by design.
- The default address is unconfidential and cross-network. It cycles whenever a transaction is
  received on either chain (to discourage reuse), but all prior addresses stay valid and are
  always scanned.
- Confidential/blinded addresses are opt-in and Sequentia-only (Bitcoin has none).
- Fix the existing `CustomElements -> bitcoin::Network::Regtest` mapping for the BTC side by
  hardcoding the Bitcoin network (`Network::Testnet4` on testnet) and `KnownHrp` rather than
  deriving the Bitcoin network from the Elements `Network`; add an `isSequentia()` accessor so
  consumers stop relying on `isRegtest()` (which returns true for Sequentia today).

## Module layout (no new crate)

Changes land in three existing crates. The `bitcoin` crate stays transitive.

`lwk_wollet` (new module behind feature `btc`):
- `src/btc/wallet.rs` -- `BtcWollet`: BIP84 wpkh watch-only; gap scan (GAP=20); UTXO gather;
  largest-first coin selection (dust 294 sats folded into fee); P2WPKH build; BIP143 sign;
  broadcast; persisted scan state. The I/O-free core is shared; only the scan/gather/broadcast
  driver is transport-split. Port from `ambra_core/src/btc.rs`.
- `src/btc/esplora.rs` -- testnet4 esplora client (`/testnet4/api`): GET `/address/{a}`,
  `/address/{a}/utxo`, `/tx/{txid}`, `/fee-estimates`; POST `/tx`. Two transports behind
  features: `btc-async` (reqwest async, ordered `.buffered(8)`) and `btc-blocking`
  (reqwest::blocking, std::thread::scope). Base URL is a constructor parameter; same-origin
  `/testnet4/api`, no public fallback.
- `src/btc/addr.rs` -- `ChainAddressParams { coin_type, hrp, network }` with constructors that
  mirror Bitcoin per network; hardcodes the Bitcoin network for the BTC side.
- `src/btc/htlc.rs` -- BTC-leg HTLC: P2SH address from redeemScript, fund tx, refund tx (the
  CLTV/ELSE branch with `nSequence=0xfffffffe`, `nLockTime`, legacy SIGHASH_ALL, manual
  scriptSig with the `OP_FALSE` branch selector). Port from `ambra_core/src/btc_htlc.rs`.
- `src/btc/xchain.rs` -- HTLC spend-key derivation and the swap secret; the self-verifying
  anchor gate; the Sequentia-leg claim and broadcast. Port from `ambra_core/src/xchain.rs`.
- `src/seqdex_htlc.rs` (modify) -- build the redeemScript ONCE chain-agnostically with
  `bitcoin::script::Builder` returning bytes; the Sequentia leg wraps the bytes for Elements.

`lwk_signer` (extend):
- `SwSigner::sign_btc_psbt(&self, psbt)` -- derive the BIP84 child xprv, BIP143 p2wpkh sighash,
  low-S ECDSA; a raw-sign fast path preserves byte-identity with the current implementations.
  Hardware-signer BTC routing is deferred (Phase 5).

`lwk_wasm` (new bindings plus wrapper):
- `src/btc_wallet.rs`, `src/btc_htlc.rs` -- wasm-bindgen async wrappers.
- `src/dual_chain.rs` -- `DualChainWallet` over `Wollet` plus `BtcWollet`: `sharedAddress(i)`,
  `btcAddress`/`seqAddress`, `btc/seq/unifiedBalance`, `dualChainNextUnused`,
  `sendBtc`/`sendSequentia`, `btcTipHeight` (for the anchor gate).
- `src/seqdex_htlc.rs` (modify) -- `htlcKeypair()` canonical at `m/84'/1'/0'/3/0`,
  `htlcKeypairLegacy()` at `m/3/0` for in-flight swaps; add `isSequentia()`.

Cargo features in `lwk_wollet`: `btc`, `btc-async = ["btc"]`, `btc-blocking = ["btc"]`.
Default wasm build uses `btc-async`; Ambra uses `btc-blocking`. Gate the blocking impl with
`#[cfg(all(feature = "btc-blocking", not(target_arch = "wasm32")))]` and add a `compile_error!`
guard so additive feature unification cannot pull blocking code into the wasm build.

## Canonical HD paths

- Wallet: `m/84'/{coin_type}'/0'/{0,1}/i` (external/internal).
- BTC-HTLC-refund key: `m/84'/1'/0'/2/0` (web and Ambra already agree).
- Sequentia-HTLC-claim key: canonical `m/84'/1'/0'/3/0` (Ambra's deep path). The wasm/web
  top-level `m/3/0` is the sole outlier; move `htlcKeypair()` to the deep path and keep
  `htlcKeypairLegacy()` at `m/3/0` for in-flight swaps. Safe to flip because that key holds no
  resting funds and the web wallet persists and reuses `seq_claim_secret` rather than
  re-deriving it (no path may rebuild the redeemScript from a re-derived claim key). Tag
  persisted swap state with a path version so the legacy selection is data-driven.
- Staking stays at top-level `m/2/0`; do not move it (live on-chain stakes are locked to it; it
  does not collide with deep `m/84'/1'/0'/2/0`).

## Cross-chain safety requirements (must-fix before any cross-chain code ships)

1. Self-verify the anchor. The reveal gate re-derives `anchor_height` from the taker's OWN
   Sequentia esplora (`block/{block_hash}`) plus `anchorstatus`, never the maker's propose
   response. Ambra already does this; the web wallet does not. Trusting the maker lets it report
   a fake anchor so the taker reveals the preimage and loses the BTC. This is anchoring
   supremacy: anchoring is verified by your own node.
2. Real reorg buffer. Require the BTC funding to be buried `D` blocks deep, with `D` sized to
   the swap value, not `D=1`. A reorg at `H_btc < R <= A` reverts the Sequentia leg while the
   BTC funding survives, so a thin buffer is a loss path for the secret-revealing taker.
3. Time-based timelocks. Do not compare `T_btc > T_seq` as raw integers; they are heights on two
   different chains. Convert both to estimated wall-clock and require
   `time(T_btc) >= time(T_seq) + margin`.
4. Persist before fund. Persist the secret, both pubkeys, both locktimes, and the redeemScript
   before broadcasting the BTC funding; otherwise a crash makes the BTC permanently unrefundable.
5. Real refund path. The CLTV refund is currently unexercised and the web implementation is
   structurally wrong (its JS finalizer cannot emit the `OP_FALSE` branch selector). Use Ambra's
   manual-scriptSig refund and gate it with a live testnet4 fund-then-refund test before
   enabling any cross-chain path, including fallback.
6. Spend-tx parity. RedeemScript byte-identity is already tested, but the claim/refund
   scriptSig plus sighash have three independent finalizers (daemon, Ambra, web) that are not
   parity-tested against each other. Add full claim and refund tx-hex (or sighash plus scriptSig)
   golden vectors against `seqdexd`, regenerated by running the daemon rather than hand-pasted.
7. Crash recovery around propose. Persist a "proposing" record (quote_id, hash, btc_leg) before
   the propose call; make the daemon propose idempotent keyed by hash; expose swap-lookup-by-hash
   so the Sequentia leg is recoverable without the response.
8. Claim deadline gate. Refuse to reveal the preimage once within a safety margin of `T_seq`
   (measured against the taker's own Sequentia tip), and steer to refund instead.
9. Encrypt swap secrets at rest. The serializable swap state defines a cipher boundary (or an
   explicit "secrets are caller-encrypted" contract); Ambra routes it through the platform
   keystore.

## Phased plan

Phase 0 prerequisites (list explicitly, none are implicit): a funded testnet4 BTC wallet and a
testnet4 faucet source; a running `seqdexd` with the test asset whitelisted; `clang`/`cc` for the
wasm-pack secp256k1 build. Each "real on-chain" exit below is split into a deterministic CI
fixture gate (always runnable) plus a separately-tracked live-testnet acceptance step.

- Phase 0 -- Parity baseline. Pin `bitcoin=0.32.8`; add the `btc`/`btc-async`/`btc-blocking`
  feature scaffold; import `ambra_core` `btc.rs` and `btc_htlc.rs` as the blocking impl; collapse
  the redeemScript to one chain-agnostic source; lift the tb1-identity test and the
  BTC-vs-Sequentia-vs-daemon redeemScript test into SWK; ADD claim and refund spend-tx parity
  vectors vs the daemon. Exit: SWK compiles with `btc` plus `btc-blocking`; all parity tests
  green (no placeholders); the default upstream build is unaffected with `btc` off.
- Phase 1 -- Async BTC wallet plus wasm bindings. Async esplora using ordered `.buffered(8)`;
  `BtcWollet` scan/gather/build/sign/broadcast/tip; `DualChainWallet`; `sign_btc_psbt` with the
  raw-sign fast path; `ChainAddressParams`; `isSequentia()`; BTC network hardcoded. Keep all
  fee/vbytes math in f64 to preserve byte-identity. Exit: for a fixed seed and UTXO set the async
  path is byte-identical to recorded `btc.js` fixtures and to the blocking path; wasm-pack release
  builds and bundle size is within budget; CORS verified against `/testnet4/api`.
- Phase 2 -- Ambra cutover. Delete Ambra's `btc.rs` and `btc_htlc.rs`; depend on
  `btc-blocking`. Exit: CI reproduces pre-migration Ambra txids and redeemScripts exactly; a real
  testnet4 send and an existing-format cross-chain swap both succeed from Ambra.
- Phase 3 -- Web wallet cutover. Replace `btc.js` scan/send with the wasm bindings behind a
  runtime flag; keep `btc.js` as fallback. Exit: a real testnet4 send via wasm confirms;
  address and balance parity with `btc.js` over fixtures; flag flipped; `btc.js` removed only
  after a clean window.
- Phase 4 -- Cross-chain into the kit. BTC-leg HTLC fund/refund plus bindings; canonical
  Sequentia-claim path with the legacy shim; a serializable swap state with at-rest
  encryption; the self-verifying anchor gate; the SEQ-leg claim fee wired to the any-asset fee
  market (estimate from the fee asset's past acceptance rates; replaces the hardcoded 100000
  atoms, which can make a claim un-buildable for a high-value asset); dynamic BTC fee estimation
  from `/fee-estimates` plus RBF (BIP125 sequence on fund/refund) moved here, not Phase 5, since
  time-sensitive HTLCs must be fee-bumpable; couple each chain's scan frontier to
  `max(seq_used, btc_used) + GAP` so a shared address used only on one chain does not blind the
  other chain's recovery. Exit: a full Bitcoin-to-Sequentia-asset swap completes on testnet4 via
  the kit on both web and Ambra; the CLTV refund branch is exercised end-to-end on testnet4;
  spend-tx parity vs the live daemon is green; the old `xswap.js` path is removed only after this
  passes.
- Phase 5 -- Hardening and mainnet. Hardware-signer (Jade/Ledger) BTC signing via `AnySigner`
  routing; CPFP rescue; mainnet support (coin_type 0, HRP `bc`, shared `bc1...`); fix the
  inherited `1776` so it is never used. Exit: a hardware-signed BTC send works; mainnet
  derivation produces the shared `bc1...` address; stuck-send rescue demonstrated on testnet4.

## Migration safety

Both consumers cut over incrementally with legacy code kept live until the new path completes
real testnet4 sends and swaps; nothing is deleted before its golden vectors pass.

Coexistence rests on byte-identity of the redeemScript AND the spend transactions across the
Sequentia leg, the BTC leg, and the daemon (Phase 0 promotes these to first-class gates).
Therefore an HTLC funded by old code is claimable and refundable by new code, so the two
implementations coexist during the transition.

Ambra (Phase 2) is the safest cutover because it adopts the same blocking Rust it already runs.
The web wallet (Phase 3) flips behind a runtime flag with `btc.js` as fallback. The
`m/3/0 -> m/84'/1'/0'/3/0` Sequentia-claim flip touches only the web wallet (Ambra already uses
the deep path), holds no resting funds, and is covered by the legacy shim plus a pre-cutover
check that no `m/3/0`-proposed swaps are in flight.

## Closed decisions (recorded)

- Single shared address across both networks: mandatory; Sequentia mirrors Bitcoin's
  `(coin_type, HRP)` per network. The inherited Liquid `1776` is a bug to fix.
- SEQ-leg claim fee: estimated from the any-asset fee market, not hardcoded.
- BTC esplora: same-origin `/testnet4/api`, no fallback.
- Confidential addresses: opt-in, Sequentia-only; default is the shared unconfidential address.
- Crate layout: feature-gated module, no new crate. Async strategy: dual transport behind
  features. PSBT-shaped BTC API with a raw-sign fast path.
