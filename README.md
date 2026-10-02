# SWK: Sequentia Wallet Kit

SWK is the toolkit for building **Sequentia** wallets: a Rust wallet library with
WASM bindings, a CLI, and multi-language (UniFFI) bindings, forked from
[Blockstream LWK](https://github.com/Blockstream/lwk) (Liquid Wallet Kit, fork
point v0.18.1). Sequentia is a Bitcoin sidechain for asset tokenization and
disintermediated exchanges, built as a fork of Blockstream Elements; the protocol
documentation lives in the node repository,
[Sequentia](https://github.com/ConcatenaLabs/Sequentia), under
`doc/sequentia/`.

Everything here targets the **public Sequentia testnet** (parent chain: Bitcoin
testnet4). There is no mainnet.

The development branch is **`sequentia`** (this branch). Crate names stay `lwk_*`
so upstream LWK changes can be merged; all Sequentia changes are additive commits
on top of the upstream history, listed precisely in [SEQUENTIA.md](SEQUENTIA.md).

## What SWK adds on top of LWK

- **Sequentia network support**: `Network::sequentia_testnet()` with Sequentia's
  policy asset (the Sequence token, ticker SEQ, tSEQ on testnet), address
  parameters (bech32 `tb`, blech32 `tsqb`), and a vendored `rust-elements` that
  can (de)serialize Sequentia's Bitcoin-anchored block headers and issuance
  transactions (upstream `elements` cannot even decode a Sequentia tip header).
- **Transparent-by-default handling**: Sequentia flips the Elements/Liquid
  default, so unblinded (explicit) outputs are ordinary wallet funds. Behind the
  `sequentia` cargo feature, explicit outputs participate in balance, coin
  selection, and history, and change is sent unblinded unless the wallet holds
  a confidential UTXO (Elements requires a blinded output to balance a blinded
  input, and coin selection may pick one). Confidential transactions remain
  available, opt-in.
- **The dual-chain kit**: every standard Sequentia wallet is also a Bitcoin
  (testnet4) wallet, from one seed. Behind the `btc` cargo features, SWK ships a
  Bitcoin parent-chain wallet (BIP84 P2WPKH: scan, balance, send, fee estimates)
  plus the Bitcoin leg of cross-chain HTLC swaps. See "The dual-chain principle"
  below.
- **Open-fee-market support**: fees can be paid in any accepted asset.
  `TxBuilder::fee_asset(asset, rate)` selects the fee asset, and RBF/CPFP rescue
  primitives (`bump_fee_of`, `replace_tx_of`, `cpfp_of`) work with any-asset fees.
- **Staking**: `sequentia_stake_script` / `TxBuilder::add_stake_output` build the
  CSV-locked bonding output used to stake Sequence tokens for block production
  (the only place the Sequence token is special).
- **SeqDEX primitives**: the same-chain atomic-swap `SeqdexSwapRequest` builder
  and the Sequentia-leg HTLC (redeem script, claim, refund) for cross-chain
  BTC-to-asset swaps, byte-compatible with the SeqDEX daemon.
- **SeqOB covenant orders**: `seqob_covenant` assembles the raw FILL and REFUND
  transactions for a resting passive-CLOB covenant order (a taproot script-path
  input with no signature, plus the taker's own key-path funding inputs).
- **Staking-pool delegation**: `TxBuilder::add_delegation_output` creates a
  delegation record and `sequentia_delegation` spends one (leave a pool, or
  re-point to another signer in the same transaction).
- **CoinJoin**: `coinjoin::sign_coinjoin_inputs` signs the wallet's own P2WPKH
  inputs of a coordinator-built seqcj round transaction.
- **OpenAMP restricted assets** (feature `openamp`): AID derivation, the tagged
  hash for non-spending signatures, client-side enclave-sighash recomputation
  and spend decoding, and a typed HTTP client for the OpenAMP service.
- **Adaptor signatures** (feature `adaptor`): BIP340 Schnorr adaptor signatures
  (`adaptor_sign` / `adaptor_verify` / `adaptor_complete` / `adaptor_extract`)
  coupling the two legs of a BTC-to-restricted-asset swap. Not yet audited.

## The dual-chain principle

Sequentia's default (unblinded) addresses use Bitcoin's own bech32 format, and
Sequentia mirrors Bitcoin's BIP84 derivation per network. On testnet both chains
derive `m/84'/1'/0'` and use the HRP `tb`, so **one seed yields one `tb1...`
address that is valid on Bitcoin testnet4 and Sequentia testnet alike**, and BTC
is a first-class asset next to every issued asset.

In code (`lwk_wollet/src/btc/`, cargo features `btc`, `btc-async`,
`btc-blocking`):

- `btc::addr::ChainAddressParams` pins the shared `(coin_type, HRP, Bitcoin
  network)` triple: testnet is `(1, tb, Testnet4)`.
- `btc::wallet` / `btc::wallet_async` are blocking and async drivers over one
  I/O-free core (derivation, gap scan, coin selection, P2WPKH build and sign),
  so the two transports produce byte-identical transactions. The async driver is
  what the WASM build uses; the blocking driver is what Ambra uses.
- `btc::esplora` talks to a Bitcoin testnet4 esplora endpoint (the public
  deployment serves it at `https://sequentiatestnet.com/testnet4/api`).
- `btc::htlc` builds the Bitcoin leg of a cross-chain HTLC whose redeemScript is
  byte-identical to the Sequentia leg (single script source in `seqdex_htlc`).
- `btc::xchain` is the cross-chain swap glue: HTLC key derivation, the swap
  secret, the anchor-verifying reveal gate (the taker checks the Sequentia leg's
  Bitcoin anchor against its OWN nodes, never the counterparty's), the claim
  deadline gate, and the Sequentia-leg claim + broadcast.

## Where SWK fits in the Sequentia ecosystem

| Repo | One-liner |
|---|---|
| [`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) | The Sequentia node, Sequentia Core (`sequentiad`, a fork of Elements 23.3.3): consensus, anchoring, proof of stake, open fee market, plus the canonical protocol documentation in `doc/sequentia/`. |
| [`SWK`](https://github.com/ConcatenaLabs/SWK) | Sequentia Wallet Kit: a fork of Blockstream LWK, with Rust wallet library, CLI, and WASM bindings for building Sequentia (and Bitcoin testnet4) wallets. |
| [`sequentia-web-wallet`](https://github.com/ConcatenaLabs/sequentia-web-wallet) | Proof-of-concept browser wallet built on SWK, live at https://sequentiatestnet.com/wallet/. |
| [`ambra`](https://github.com/ConcatenaLabs/ambra) | Ambra: non-custodial dual-chain (Bitcoin testnet4 + Sequentia) mobile wallet: Flutter UI over a Rust core built on SWK. |
| [`seqdex`](https://github.com/ConcatenaLabs/seqdex) | SeqDEX: non-custodial atomic-swap DEX: P2P order book (seqob), same-chain swaps, and cross-chain BTC↔asset swaps made safe by Bitcoin anchoring. |
| [`sequentia-electrs`](https://github.com/ConcatenaLabs/sequentia-electrs) | The electrs fork: Rust indexer + Esplora REST API for Sequentia and its Bitcoin testnet4 parent chain. |

Consumers of SWK:

- **sequentia-web-wallet** (live at https://sequentiatestnet.com/wallet/) uses the
  `lwk_wasm` bindings compiled to WebAssembly, all client-side.
- **Ambra** (mobile) uses a Rust core (`ambra_core`) that depends on
  `lwk_wollet` with features `sequentia`, `esplora`, `btc-blocking`, plus
  `lwk_signer` and `lwk_common`.

## Workspace crates

Sequentia changes are concentrated in `lwk_common`, `lwk_wollet`, `lwk_signer`,
`lwk_wasm`, and the vendored `rust-elements`; the other crates are upstream LWK, apart from
a `Contract::from_parts` call site in `lwk_app` and `lwk_bindings` and one
Sequentia example in `lwk_simplicity`.

| Crate | What it is |
|---|---|
| `lwk_wollet` | The watch-only wallet core (CT descriptors, scanning, balances, PSET create/finalize). Sequentia additions: explicit-output handling, any-asset fees + RBF/CPFP rescue, staking output, SeqDEX swap/HTLC builders, SeqOB covenant fill/refund, staking-pool delegation, CoinJoin input signing, the OpenAMP client (feature `openamp`), adaptor signatures (feature `adaptor`), and the whole Bitcoin parent-chain module (`src/btc/`). |
| `lwk_common` | Shared types. Sequentia addition: `Network::sequentia_testnet()` and Sequentia address parameters. |
| `lwk_signer` | Software signer (BIP39 mnemonic to PSET signatures); signs Sequentia PSETs as-is. Sequentia addition: `sign_tapscript`, a script-path signature at any leaf version over the Elements signature hash, for covenant leaves that name the wallet's key. |
| `lwk_wasm` | WebAssembly bindings (wasm-bindgen). Sequentia additions: `Network.sequentiaTestnet()`, `BtcWallet`, the `xchain*` HTLC helpers, SeqDEX bindings, `buildCovenantFillTx` / `buildCovenantRefundTx`, delegation (`buildDelegationSpendTx`, `findDelegationRecords`), `coinjoinSignInputs` / `coinjoinUnblindOutputs`, the `Openamp` client and enclave helpers, `adaptor*`, `Signer.signTapscript` / `tapscriptSighash`, staking and any-asset-fee bindings. |
| `lwk_bindings` | UniFFI bindings (Python, Kotlin, Swift, C#, Go, C++). Upstream API surface (no Sequentia network exposed yet); only the `Contract::from_parts` call changed. |
| `lwk_cli` / `lwk_app` / `lwk_rpc_model` / `lwk_tiny_jrpc` | JSON-RPC wallet server and CLI client. Upstream apart from `lwk_app`'s `Contract::from_parts` call: no `sequentia` network selector yet (networks: liquid, liquid-testnet, regtest). |
| `lwk_jade`, `lwk_ledger`, `lwk_hwi` | Hardware-signer support (upstream; not wired to Sequentia flows). |
| `lwk_simplicity` | Upstream Simplicity utilities plus one Sequentia example, `examples/live_covenant.rs`, which derives and spends a Simplicity leaf on the live testnet. |
| `lwk_boltz`, `lwk_payment_instructions`, `amp2_mock`, `lwk_containers`, `lwk_test_util` | Upstream LWK crates (Boltz swaps, payment-URI parsing, test infrastructure). Unmodified on this branch. |
| `rust-elements` (vendored, not a workspace member) | Fork of the `elements` crate wired in via `[patch.crates-io]`, with a `sequentia` cargo feature for anchored headers, issuance denomination, and `tb`/`tsqb` address parsing. |

## Quick start (Rust)

Watch-only sync of a Sequentia wallet against the live testnet explorer:

```rust
use std::str::FromStr;
use lwk_wollet::blocking::{BlockchainBackend, EsploraClient};
use lwk_wollet::{Network, WolletBuilder, WolletDescriptor};

let network = Network::sequentia_testnet();
let desc = WolletDescriptor::from_str("ct(slip77(<blinding>),elwpkh(<xpub>/<0;1>/*))#...")?;
let mut wollet = WolletBuilder::new(network, desc).build()?;
let mut client = EsploraClient::new("https://sequentiatestnet.com/api", network)?;
if let Some(update) = client.full_scan(&wollet)? {
    wollet.apply_update(update)?;
}
println!("{:?}", wollet.balance()?);
```

A runnable end-to-end version of this (it syncs against the live explorer):

```sh
cargo run -p lwk_wollet --example sequentia_sync
```

Enable the Sequentia-specific wallet behavior and the Bitcoin side with cargo
features on `lwk_wollet`:

```toml
# transparent-by-default handling only
lwk_wollet = { features = ["sequentia"] }
# dual-chain: + Bitcoin testnet4 wallet and cross-chain HTLC (pick one transport)
lwk_wollet = { features = ["btc-blocking"] }   # native apps (Ambra)
lwk_wollet = { features = ["btc-async"] }      # wasm / async apps
```

`btc-blocking` cannot target wasm32; a `compile_error!` guard in
`lwk_wollet/src/btc/mod.rs` enforces that at build time.

## WASM (browser wallets)

`lwk_wasm` builds the kit to WebAssembly with the Sequentia features on
(`sequentia`, `openamp`, `adaptor`, `btc-async`), exposing among others
`Network.sequentiaTestnet()`, `Network.isSequentia()`, the dual-chain
`BtcWallet`, the `xchain*` helpers for cross-chain swaps,
`TxBuilder.feeAsset()` / `addStakeOutput()` / `addExplicitRecipient()` /
`addDelegationOutput()`, `Signer.stakerPublicKey()`, `buildCovenantFillTx()`,
`buildDelegationSpendTx()`, `coinjoinSignInputs()`, the `Openamp` client, and
the `adaptor*` functions.

```sh
cd lwk_wasm
wasm-pack build --target web --release    # needs clang for the secp256k1 build
```

The fork is not published to npm; the `lwk_wasm` npm package is upstream LWK.
Consume the fork by building `pkg/` yourself (this is what
[sequentia-web-wallet](https://github.com/ConcatenaLabs/sequentia-web-wallet)
does).

## Building and testing

Standard Rust workspace (toolchain pinned in `rust-toolchain.toml`):

```sh
cargo build                                                             # whole workspace
cargo test -p lwk_wollet --lib --features btc-blocking,btc-async btc   # dual-chain tests
cargo test -p lwk_wollet --lib --features sequentia seqdex             # SeqDEX builders
```

Notes:

- Unit tests run without any node or network access.
- Known issue: a plain `cargo test -p lwk_wollet --lib` reports a number of
  failing upstream fixture tests. The workspace enables the vendored `elements`
  crate's `sequentia` feature globally, which changes the transaction and
  header wire format, so upstream Liquid test vectors no longer deserialize.
  The Sequentia-specific test modules (`btc`, `seqdex_htlc`, `seqdex_swap`) all
  pass; use the filtered commands above.
- Upstream integration tests (`lwk_wollet/tests/e2e.rs` and friends) need a
  local Elements/Liquid test environment (see `lwk_test_util` and
  `lwk_containers`); they exercise upstream Liquid behavior, not Sequentia.
- Two examples act as live functional tests against the public Sequentia
  testnet: `sequentia_sync` (watch-only sync) and `rescue_test` (RBF/CPFP
  rescue; needs a funded wallet).
- Multi-language bindings and other build recipes: see the `justfile` and the
  crate READMEs.

Contributions target the `sequentia` branch. Keep Sequentia changes additive and
minimal so upstream LWK can still be merged; document any new fork delta in
[SEQUENTIA.md](SEQUENTIA.md).

## Documentation

- [SEQUENTIA.md](SEQUENTIA.md): the precise list of fork changes vs upstream LWK.
- [SEQUENTIA-DUALCHAIN-PLAN.md](SEQUENTIA-DUALCHAIN-PLAN.md): historical design
  plan for the dual-chain work, kept with a status header stating what was built.
- Upstream LWK documentation (generic LWK concepts, descriptors, PSET flows,
  hardware signers, bindings): https://blockstream.github.io/lwk/book and the
  `docs/` mdbook sources in this repo. Liquid-specific statements there (for
  example confidential-by-default addresses) do not apply to Sequentia networks;
  see [SEQUENTIA.md](SEQUENTIA.md).

## License

[MIT](LICENSE)
