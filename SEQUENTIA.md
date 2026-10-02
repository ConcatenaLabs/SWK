# Sequentia changes vs upstream LWK

This document is the precise list of what the `sequentia` branch changes
relative to upstream [Blockstream LWK](https://github.com/Blockstream/lwk).
The fork point is upstream v0.18.1 (commit `1095b825`, "bump 0.18.0 -> 0.18.1");
all Sequentia work is additive commits on top of the upstream history so
upstream can still be merged. Crate names and versions stay `lwk_*` / 0.18.x for
the same reason.

Everything targets the public Sequentia testnet (parent chain: Bitcoin
testnet4). Protocol background lives in the node repo,
https://github.com/ConcatenaLabs/Sequentia, under `doc/sequentia/`.

Crates NOT touched by the fork (still pure upstream): `lwk_cli`,
`lwk_jade`, `lwk_ledger`, `lwk_hwi`, `lwk_boltz`, `lwk_payment_instructions`,
`lwk_rpc_model`, `lwk_tiny_jrpc`, `lwk_containers`, `lwk_test_util`,
`amp2_mock`. The CLI/UniFFI surfaces have no Sequentia network selector yet.

Crates touched only mechanically:

- `lwk_app/src/lib.rs` and `lwk_bindings/src/contract.rs`: the `Contract`
  struct literal became a `Contract::from_parts(...)` call, because the fork's
  `Contract` (`lwk_wollet/src/contract.rs`) keeps the original registry JSON
  beside its typed fields and is no longer built field by field.
- `lwk_simplicity/examples/live_covenant.rs`: a Sequentia-specific example that
  derives the address of a real Simplicity leaf (taproot leaf version 0xbe)
  and finalizes a spend of it on the live testnet. `lwk_simplicity` itself is
  an upstream LWK crate that predates the fork, not a Sequentia addition.

## Workspace (`Cargo.toml`)

- `[patch.crates-io] elements = { path = "rust-elements" }`: the whole workspace
  uses the vendored `rust-elements` (see below).
- `elements` workspace dependency enables features
  `["base64", "serde", "sequentia"]`. The `sequentia` serialization is therefore
  ON for every crate in the workspace. Consequence: upstream Liquid test
  fixtures that hard-code the Liquid wire format fail to deserialize, so a plain
  `cargo test -p lwk_wollet --lib` has known failures in upstream fixture tests;
  the Sequentia-specific test modules all pass.
- `bitcoin = "=0.32.7"` pinned exactly to the version `elements-miniscript`
  pulls transitively, so the parent-chain crate can never drift and silently
  change HTLC redeemScript bytes.

## Vendored `rust-elements` (`./rust-elements`, cargo feature `sequentia`)

A vendored fork of the `elements` crate. All Sequentia deltas are gated behind
its `sequentia` cargo feature:

- `src/block.rs`: `BlockHeader::bitcoin_anchor: Option<(u32, BlockHash)>`.
  Sequentia headers commit a 36-byte Bitcoin anchor (parent-chain height + block
  hash) right after the height, matching the node's `src/primitives/block.h`.
  It is (de)serialized on the wire and committed in the block hash. Without
  this, upstream `elements` cannot even decode a Sequentia tip header. Verified
  by re-hashing a real header to the chain's block hash.
- `src/transaction.rs` (+ `src/issuance.rs`, `src/pset/map/input.rs`,
  `src/sighash.rs`, `src/blind.rs` touch points): Sequentia issuance
  transactions carry an extra `nDenomination` byte; the feature adds it to
  issuance (de)serialization, PSET input mapping, and sighash computation.
- `src/address.rs`: `AddressParams::SEQUENTIA_TESTNET` (base58 p2pkh 111 /
  p2sh 196 / blinded 70; bech32 HRP `tb`; blech32 HRP `tsqb`) and address-string
  parsing for those prefixes. Sequentia is transparent by default: the default
  unblinded address is Bitcoin's own bech32 format (`tb1...`), which is exactly
  why one address works on both chains; confidential (blinded) addresses are
  opt-in and use the distinct `tsqb` blech32 HRP.

## `lwk_common`

- `src/network.rs`:
  - `SEQUENTIA_TESTNET_ADDRESS_PARAMS` const (same parameters as above).
  - `ElementsParamsBuilder::with_address_params()` / `with_name()`: custom
    Elements networks can carry their own address params and short name
    (upstream hard-codes `AddressParams::ELEMENTS` and "liquid-regtest").
  - `Network::sequentia_testnet()`: Sequentia testnet as a custom Elements
    network with the policy asset (the Sequence token, tSEQ:
    `c8eccacf0953e1931cd31e434d8319101cc36e6c38b0e2104d8687552fae3e40`), the
    Sequentia address params, and the name `sequentia-testnet`.
  - The genesis-hash constant in `sequentia_testnet()` is the current
    2026-07-05 re-genesis hash (`ddd11d54...`). The policy-asset id was
    preserved across the re-genesis. Inside LWK the network genesis hash is
    used for BIP341 (taproot) sighash computation (e.g. the SeqOB covenant
    flows), so it must track the live chain.

## `lwk_signer`

The PSET signing path (`Signer::sign`) is upstream and unchanged. The fork adds
script-path signing for covenant protocols whose leaves name the wallet's key.

- `src/tapscript.rs`: `SwSigner::sign_tapscript(path, &ScriptPathSpend)`, a
  BIP341 script-path signature for one input, at any leaf version (`0xc4`, the
  Elements tapscript version, included), over the Elements signature hash: the
  `TapSighash/elements`, `TapLeaf/elements` and `TapBranch/elements` tagged
  hashes with the chain's genesis hash committed in the message.
  `ScriptPathSpend` names the transaction, the input, every prevout, the leaf
  script, its control block (which carries the leaf version), the sighash type
  and the genesis hash. Before signing, the signer checks that the control
  block commits the leaf to the taproot output the input spends, and that the
  key at `path` is pushed in the leaf; it refuses otherwise. Signatures use no
  auxiliary randomness, so the same request always gives the same bytes.
  `ScriptPathSpend::sighash` and `verify` serve a party that holds no key, and
  `SwSigner::xonly_public_key(path)` gives the key as a leaf names it.
- `test_data/arca_vectors.json`: the Arca golden vectors, copied unchanged from
  `regtest/vectors/arca.json` in the
  [`arca`](https://github.com/ConcatenaLabs/arca) repository (test keys only).
  The unit tests recompute every ordinary script-path signature hash in it and
  re-sign each with its test key; both match byte for byte.

A hardware signer gives the same guarantee only if its firmware does the same
work on the device: compute the Elements script-path signature hash itself from
the transaction, all prevouts, the leaf script and the leaf version (with the
genesis hash of a chain the device knows), check the control block against the
spent output, check that the leaf names the device's key, and show the outputs
before signing. The Jade and Ledger integrations refuse every taproot input
(`UnsupportedScriptPubkeyType`, `UnsupportedTaprootInput`), so neither signs
these spends.

## `lwk_wollet`

New cargo features:

- `sequentia = ["elements/sequentia"]`: transparent-by-default wallet behavior.
- `btc = ["bitcoin", "sequentia"]`: the I/O-free Bitcoin parent-chain core.
- `btc-async` / `btc-blocking`: the two esplora transports over that core
  (wasm/async apps vs native blocking apps). `btc-blocking` on wasm32 is a
  compile error by design.
- `openamp = ["reqwest"]`: the OpenAMP restricted-asset client and enclave
  signing helpers.
- `adaptor = []`: BIP340 Schnorr adaptor signatures.

Changes by file:

- `src/wollet.rs`, `src/pset_create.rs`, `src/update.rs` (feature `sequentia`):
  explicit (non-confidential) outputs are first-class wallet funds: they count
  in balance, coin selection, and history; wallet inputs may be explicit;
  change is sent unblinded unless the wallet holds any confidential UTXO
  (Elements requires at least one blinded output to balance a blinded input,
  and coin selection may pick one). Also
  `Wollet::explicit_utxos()` and a valid zero anchor in the placeholder header.
- `src/tx_builder.rs`:
  - Any-asset fees: `TxBuilder::fee_asset(asset, rate)` pays the fee in any
    accepted asset at a given rate, per Sequentia's open fee market (no
    privileged fee asset). Fee-rate units are the chosen asset's own units per
    vByte.
  - RBF/CPFP rescue: `Wollet::bump_fee_of()`, `replace_tx_of()`, `cpfp_of()`,
    `cpfp_suggested_feerate()` build fee-bump/replacement/child transactions,
    any-asset-fee aware. Exercised live by `examples/rescue_test.rs`.
  - Staking (the one place the Sequence token is special):
    `sequentia_stake_script()` and `TxBuilder::add_stake_output(staker_pubkey,
    csv, satoshi)` build the CSV-locked bonding output used to stake for block
    production.
  - Staking pools: `TxBuilder::add_delegation_output()` pays the bare
    delegation-record script (`"SEQDEL" OP_DROP <signer> OP_DROP <controller>
    OP_CHECKSIG`) that lends the wallet's stake weight to a pool signer.
- `src/sequentia_delegation.rs` (feature `sequentia`): spends a delegation
  record, which no descriptor matches. `build_delegation_spend_tx()` either
  reclaims the record (leave the pool) or re-points it to another signer in
  the same transaction (consensus allows one live record per controller, so
  the two steps must not be separate transactions). Also
  `sequentia_delegation_script()` and `parse_delegation_script()`.
- `src/seqob_covenant.rs` (feature `sequentia`): the raw-Elements FILL and
  REFUND transaction assemblers for a resting SeqOB passive-CLOB covenant
  order (`build_covenant_fill_tx()`, `build_covenant_refund_tx()`). The
  covenant leaf, witness and fill recipe are produced and byte-verified by the
  web wallet's JS; what JS cannot do is assemble a taproot script-path input
  with no key signature next to the taker's own key-path funding inputs in the
  consensus-fixed output order, which is what this module builds.
- `src/coinjoin.rs` (feature `sequentia`): `sign_coinjoin_inputs()` signs the
  wallet's own key-path P2WPKH inputs of a seqcj coordinator-built round
  transaction (the Elements segwit-v0 sighash commits to confidential values,
  which JS cannot compute). It refuses coins the derived key does not control
  and never judges whether the round is worth signing; that check lives in the
  wallet before the call.
- `src/openamp.rs` (feature `openamp`): the OpenAMP restricted-asset client.
  Crypto helpers (AID derivation `compute_aid()`, `tagged_hash()` for
  non-spending signatures, `enclave_sighash()` + `decode_enclave_spend()` so a
  wallet recomputes the enclave sighash itself and never blind-signs) and the
  typed `OpenampClient` for the user / address / balance / transfer endpoints.
- `src/adaptor.rs` (feature `adaptor`): BIP340 Schnorr adaptor signatures
  (`adaptor_sign`, `adaptor_verify`, `adaptor_complete`, `adaptor_extract`),
  built in-house on `secp256k1` point arithmetic because the vendored
  `secp256k1-zkp` only ships an ECDSA adaptor module. Couples the two legs of a
  BTC-to-restricted-asset swap. Must be independently audited before any
  fund-bearing use.
- `src/seqdex_swap.rs` (feature `sequentia`): `SeqdexSwapRequest`, the taker
  half of a SeqDEX same-chain atomic swap (unsigned unblinded PSETv2 plus
  revealed input blinders), wire-compatible with the SeqDEX daemon's
  `/v1/trade/propose`.
- `src/seqdex_htlc.rs` (feature `sequentia`): the cross-chain HTLC's Sequentia
  leg: `build_htlc_redeem_script()` (the single redeemScript source for BOTH
  legs, byte-identical to the daemon's), `build_claim_tx()`,
  `build_refund_tx()`, `SwapSecret` handling.
- `src/btc/` (features `btc*`): the Bitcoin parent-chain side of the dual-chain
  kit:
  - `addr.rs`: `ChainAddressParams`, the shared `(coin_type, HRP, Bitcoin
    network)` triple. Testnet `(1, tb, Testnet4)`: Bitcoin testnet4 and
    Sequentia testnet derive the identical `tb1...` address from one BIP84
    seed. A `mainnet()` constructor exists for the future shared `bc1...`
    space; there is no Sequentia mainnet.
  - `core.rs`: I/O-free wallet logic (BIP39+BIP32 derivation done directly, no
    `lwk_signer` dependency; gap-limit scan; largest-first coin selection;
    P2WPKH build and BIP143 sign). Shared by both transports so blocking and
    async builds are byte-identical (locked by a parity test).
  - `esplora.rs`: Bitcoin testnet4 esplora client, blocking + async (the public
    deployment serves `/testnet4/api` same-origin with the Sequentia esplora).
  - `wallet.rs` / `wallet_async.rs`: the blocking (Ambra) and async (wasm)
    wallet drivers: scan, balance, prepare/sign/broadcast, tip height,
    fee estimates.
  - `htlc.rs`: the BTC-leg HTLC (P2SH from the shared redeemScript, funding,
    and the manual-scriptSig CLTV refund with BIP125 RBF).
  - `xchain.rs`: cross-chain (BTC to Sequentia-asset) swap glue for the taker:
    HTLC key derivation (canonical absolute paths outside the receive/change
    branches, plus a legacy relative mode recorded in persisted state), the
    swap secret, the reveal gate, claim-deadline gate, rate-derived
    Sequentia-leg claim fee, and the Sequentia-leg claim + broadcast (plus the
    on-chain preimage read). The reveal gate is anchoring supremacy in
    code: the taker reveals the preimage only after ITS OWN nodes confirm the
    Sequentia funding's Bitcoin anchor height is at or above the BTC funding
    height, `anchorstatus` is ok, and the anchor is D confirmations deep
    (D is a taker dial, default 1); the Sequentia transaction's finality IS its
    anchor's Bitcoin finality, so no extra reorg timelocks are needed and the
    CLTV timelocks are liveness only.
- `examples/sequentia_sync.rs`: end-to-end watch-only sync against the live
  explorer (`cargo run -p lwk_wollet --example sequentia_sync`).
- `examples/rescue_test.rs`: live functional test of bump/replace/CPFP against
  the testnet (needs a funded wallet).

## `lwk_wasm`

Built with `lwk_wollet` features `sequentia`, `openamp`, `adaptor` and
`btc-async` (plus upstream defaults), so the npm-style `pkg/` output of this
fork is Sequentia-enabled.
The fork is not published to npm; consumers build `pkg/` with `wasm-pack`.

- `src/network.rs`: `Network.sequentiaTestnet()`; `Network.isSequentia()`
  (Sequentia is modelled as a custom Elements network, so upstream's
  `isRegtest()` returns true for it; use `isSequentia()`).
- `src/btc_wallet.rs`: `BtcWallet` (address, scan, prepare, sign+broadcast) with
  `BtcScan` / `BtcPrepared` result types: the Bitcoin testnet4 half of a
  dual-chain browser wallet.
- `src/xchain.rs`: the `xchain*` helper functions (secret and key derivation,
  BTC HTLC, Sequentia redeem script, Sequentia claim, BTC claim and refund)
  wrapping `lwk_wollet::btc::xchain` for the web wallet.
- `src/seqdex_swap.rs`: `SwapRequest` (same-chain SeqDEX swap proposal).
- `src/seqdex_htlc.rs`: `generateSwapSecret`, `htlcKeypair`,
  `buildSeqHtlcRedeemScript`, `buildSeqHtlcClaimTx`, `buildSeqHtlcRefundTx`.
- `src/tx_builder.rs`: `feeAsset()` (any-asset fees), `addExplicitRecipient()`,
  `addStakeOutput()`, `sequentiaStakeScript()`, `addDelegationOutput()`.
- `src/wollet.rs`: explicit-UTXO and rescue (bump/replace/CPFP) bindings.
- `src/signer.rs`: `Signer.stakerPublicKey()` (staking key at `m/2/0`); the
  OpenAMP enclave key and its signing at `m/5/0`; `Signer.xonlyPublicKeyAt(path)`
  and `Signer.signTapscript(path, txHex, inputIndex, prevoutsHex, leafScriptHex,
  controlBlockHex, sighashType, genesisHex)` over `SwSigner::sign_tapscript`.
- `src/tapscript.rs`: `tapscriptSighash(...)`, the same signature hash without a
  key. Prevouts are consensus-serialised hex in input order; the genesis hash is
  display hex.
- `src/seqob_covenant.rs`: `buildCovenantFillTx`, `buildCovenantRefundTx`,
  `covenantMakerAddress`, `covenantMakerDescriptor`, `scriptToAddress`.
- `src/sequentia_delegation.rs`: `sequentiaDelegationScript`,
  `parseDelegationScript`, `findDelegationRecords`, `buildDelegationSpendTx`.
- `src/coinjoin.rs`: `coinjoinSignInputs`, `coinjoinUnblindOutputs`.
- `src/openamp.rs`: the `Openamp` client class (`registerUser`, `getUser`,
  `enclaveAddress`, `assetInfo`, `createTransfer`, `completeTransfer`) and
  the free functions `openampComputeAid`, `openampTaggedHash`,
  `enclaveSighash`, `decodeEnclaveSpend`.
- `src/adaptor.rs`: `adaptorSign`, `adaptorVerify`, `adaptorComplete`,
  `adaptorExtract`.

The browser-wallet demo that used to live in `lwk_wasm/www/` was extracted to
its own repository,
[sequentia-web-wallet](https://github.com/ConcatenaLabs/sequentia-web-wallet),
live at https://sequentiatestnet.com/wallet/.

## Design invariants the fork keeps

- Sequentia is transparent by default; confidentiality is opt-in. Docs and code
  never assume blinded-by-default (that is the Liquid model).
- The Sequence token (SEQ; tSEQ on testnet) is the policy asset but has no
  privilege anywhere in the kit except the staking output builder; fees are
  payable in any accepted asset and fee rates are denominated in the chosen
  asset's own units per vByte.
- One redeemScript source for cross-chain HTLCs: the Bitcoin leg wraps the same
  builder the Sequentia leg uses, so the legs cannot drift (this is why the
  `btc` feature implies `sequentia`).
- Anchor verification is always done against the wallet's own backends, never
  data supplied by a swap counterparty.
