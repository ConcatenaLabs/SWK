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
- `arca-covenant`, Arca's covenant scripts, leaf record and client checks
  (`covenant/` in the [`arca`](https://github.com/ConcatenaLabs/arca)
  repository), is a git dependency pinned to one revision in this file's
  `[workspace.dependencies]`; moving the pin is a change to that line alone.
  `[patch."https://github.com/ConcatenaLabs/SWK"]` points the `elements` that
  `arca-covenant` names by this repository's URL at the vendored
  `rust-elements`, so the kit and Arca share one `elements` crate.

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
  The PSET format has no field for it, so a PSET input keeps it in a
  proprietary key (prefix `sequentia`, subtype `0x00`, one byte;
  `Input::issuance_denomination`, `set_issuance_denomination`), written only
  when it is not the node's default, 8. `Input::from_txin` carries it from the
  transaction, and the transaction a PSET extracts has it, so a PSET made from
  a transaction is signed over that transaction.
- `src/pset/map/input.rs`, `src/pset/mod.rs`: an input's issuance is not
  flagged in its output index (`Input::from_txin`), as Elements Core's PSET
  does not flag it, and `Input::previous_outpoint()` masks off any flag a PSET
  carries there. The extracted transaction and the issued asset's id use that
  outpoint, so an issuance input is signed over the outpoint it spends.
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
  block commits the leaf to the taproot output the input spends, that the key
  at `path` is pushed in the leaf and checked there by `OP_CHECKSIG`,
  `OP_CHECKSIGVERIFY` or `OP_CHECKSIGADD` (a key that only
  `OP_CHECKSIGFROMSTACK` checks is refused), and that the sighash type is
  `SIGHASH_DEFAULT` or `SIGHASH_ALL`, which cover every input and output. Any
  other type leaves outputs or inputs free (under `SIGHASH_NONE` an exit
  signature lets whoever holds it send the coin anywhere);
  `sign_tapscript_allowing(path, spend, type)` signs one such type, which the
  caller names. `ScriptPathSpend::describe` gives the plain lines a wallet
  shows before approval: the coin, the leaf, what the sighash type covers,
  the outputs, the fee and the locks. Signatures use no auxiliary randomness,
  so the same request always gives the same bytes. `ScriptPathSpend::sighash`
  and `verify` serve a party that holds no key, and
  `SwSigner::xonly_public_key(path)` gives the key as a leaf names it.
- `src/csfs.rs`: `SwSigner::sign_csfs(path, &ArcaMessage, &digest, &CsfsPolicy)`,
  a BIP340 signature over a 32-byte digest for `OP_CHECKSIGFROMSTACK`, for the
  three messages Arca's scripts verify: `RebindMessage` (a rebindable path: the
  output it spends, the spent coin's asset and value, the 1 to 4 committed
  outputs, and the transaction's other inputs, which the digest does not name),
  `UnrollAuthorisation` (a node's children and the median time `t`)
  and `ReleaseMessage` (genesis hash, a lowest node's children and `M`, the
  connector asset of the round that made the owner's new leaf, so that a
  release is void if that round is lost; with the feature `ark`,
  `ReleaseMessage::release` builds it from the Arca library's `Release`).
  The caller presents the digest together with the fields it was built from;
  the signer rebuilds the digest and refuses when the two differ, so it never
  signs a bare hash. It also refuses fields no script can produce: an output
  count outside 1 to 4, a time below 500,000,000 (a height), no children, or
  children whose records exceed the 520 bytes a script can concatenate.
  - A rebind names the output it spends with a `RebindSource`: the path
    (`leaf`, `checkpoint`, `htlc-claim`, `htlc-claim-both` or
    `htlc-refund-both`), the id of the leaf, and the salt and chain that make
    the script's constant `K`. With the feature `ark`,
    `RebindSource::leaf(&LeafRecord)` takes all of these from the leaf's
    record, and the signer then also refuses a key that is not the record's
    owner key and a coin that is not the record's asset and value.
  - `CsfsPolicy` names the wallet's chain: a rebind or a release for any
    other genesis hash is refused. It also caps what a rebind leaves
    uncommitted, which goes to whoever broadcasts. The default,
    `CsfsPolicy::new(genesis, floor_per_kvb)`, is the specification's fee
    margin: four times the relay floor (atoms of the coin's asset per 1,000
    vbytes) for the spend's measured size, once for each input of the coin's
    asset; `with_ceiling` sets the ceiling in atoms.
  - What a rebind leaves is reckoned over the whole transaction
    (`RebindMessage::uncommitted`): its inputs of the coin's asset, the coin
    and `other_inputs`, less what the committed outputs take, since a
    signature names no other input and every owner in a reassignment signs
    the same outputs. `other_inputs` is `Some(vec![])` for a coin spent
    alone. When it is `None`, the signer refuses, under any ceiling, a
    reassignment (the checkpoint path) and any rebind whose outputs take more
    of the coin's asset than the coin holds; it refuses named inputs that
    hold less of an asset than the outputs take.
  - `ArcaMessage::describe` gives the plain-language lines a wallet shows
    before asking for approval: the path and the leaf id, the outputs, and the
    amount in each asset the committed outputs leave to whoever broadcasts.
  Records follow the node's introspection rule exactly: a witness output
  contributes its program and version, any other script its SHA256 and
  version −1. The genesis hash and asset ids enter the messages in internal
  byte order; `BlockHash` and `AssetId` parse display hex into it.
- Feature `ark` adds the dependency on `arca-covenant` for
  `RebindSource::leaf` and `ReleaseMessage::release`.
- `test_data/arca_vectors.json`: the Arca golden vectors, copied unchanged from
  `regtest/vectors/arca.json` in the
  [`arca`](https://github.com/ConcatenaLabs/arca) repository at the revision
  the workspace pins (test keys only); moving the pin copies it again.
  The unit tests recompute every ordinary script-path signature hash, every
  record and every collaborative, unroll and release message in it (a
  board's collaborative path is its leaf's own), and re-sign each with its
  test key; all match byte for byte.

A hardware signer gives the same guarantee only if its firmware does the same
work on the device: compute the Elements script-path signature hash itself from
the transaction, all prevouts, the leaf script and the leaf version (with the
genesis hash of a chain the device knows), check the control block against the
spent output, check that the leaf names the device's key, and show the outputs
before signing. For a message signature the device must likewise take the
fields, rebuild the digest and show what it authorises; a device API that signs
a presented hash cannot give that guarantee. The Jade and Ledger integrations refuse every taproot input
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
- `ark = ["sequentia", "dep:arca-covenant"]`: holding a leaf of an Arca
  covenant tree (`src/ark/`).

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
  - Staking pools: `TxBuilder::add_record_authorization(pubkey, satoshi)`
    pays the staking key's `P2WPKH`, the coin that authorises a delegation
    record (below). `TxBuilder::add_delegation_output()` pays the bare
    delegation-record script (`"SEQDEL" OP_DROP <signer> OP_DROP <controller>
    OP_CHECKSIG`) straight from wallet coins, which the network accepts only
    below `pos_hardening_height` (on the testnet the same height as its
    `pos_records_v2_height`; block 1 on every other chain).
- `src/sequentia_delegation.rs` (feature `sequentia`): creates and spends
  delegation records, which no descriptor matches. A record must be created
  by a transaction spending a coin of its controller, so
  `build_delegation_create_tx()` funds it from such a coin and nothing else:
  the wallet pays the staking key's `P2WPKH` first
  (`add_record_authorization`), and the two transactions are mined together.
  `build_delegation_spend_tx()` either reclaims the record (leave the pool) or
  re-points it to another signer in the same transaction (consensus allows one
  live record per controller, so the two steps must not be separate
  transactions; the spent record authorises the new one). Also
  `sequentia_delegation_script()` and `parse_delegation_script()`.
- `src/sequentia_stake_records.rs` (feature `sequentia`): stake record spends
  (staking, unbonding, delegation and payout outputs) and two-step unbonding.
  `StakeRecordSigning` names the signature a spend needs in the block after
  the wallet's tip: the legacy hash below the chain's `pos_records_v2_height`,
  and from it the segwit-v0 hash over the record script, committing to the
  amount, in a scriptSig of one minimal low-S push. `pos_records_v2_height()`
  is `SEQUENTIA_TESTNET_POS_RECORDS_V2_HEIGHT` for
  `Network::sequentia_testnet()` (matched on its whole definition, genesis
  hash included) and 1 on every other chain; no node RPC reports it.
  `sign_stake_record_input()` signs any record spend that way.
  `build_unbond_tx()` moves staking outputs into an unbonding output of the
  same key (`sequentia_unbond_script()`, `"SEQUNBOND" OP_DROP <key>
  OP_CHECKSIG`), its fee capped at 1% of the stake (`unbond_fee_cap()`);
  `build_unbond_claim_tx()` sends unbonding outputs to an address once the
  unbonding depth has passed. `build_record_create_tx()` creates any record
  from a `P2WPKH` coin of its key; the kit announces no payout policy of its
  own (that belongs to the node wallet), but its tests create and withdraw one
  this way. Also `parse_stake_script()`, `key_coin_script()` and
  `find_key_coins()`.
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
- `src/ark/` (feature `ark`): what a wallet needs to hold a leaf of an Arca
  covenant tree. The scripts, the leaf record, its validation and the client's
  checks on a round are the Arca library's (`arca-covenant`), re-exported as
  `ark::covenant` and never written a second time; signing is `lwk_signer`'s.
  Asset ids, the token and the genesis hash are in internal byte order in
  scripts and hashes and in display hex in every text form.
  - `keys.rs`: one key for every leaf instance. The wallet draws a random
    32-byte owner nonce for every leaf it asks for or publishes in a receive
    request (`new_owner_nonce`); the leaf key is at
    `m/6'/<account>'/c1'/c2'/c3'/c4'`, where `c1` to `c4` are the first four
    31-bit chunks, most significant bit first, of
    `SHA256("Arca/key" ‖ owner_nonce)` (`leaf_key`, `leaf_key_path`). The
    nonce is in the leaf's record, so a restore derives each record's key from
    its nonce and checks it equals the record's owner key (`restore_key`): no
    index scan and no gap limit. A key is never derived from a counter and
    never reused, because one key on two leaves lets the operator take one.
  - `verify.rs`: `verify_leaf(record, round, policy, owner, owner_nonce)`
    rebuilds every script on the leaf's path from its record, requires the
    round transaction to pay the batch output exactly once, runs the five
    client checks on the sweep token and its clock, applies the wallet's
    `WalletPolicy` (its chain, the operator key it was told, the shortest
    notice, how far after `now` the first expiry lies, the bounds of the exit
    delay, the deepest path, no node of one child outside a batch of one
    leaf, and a floor on every reserve), and checks the record is for the
    wallet's key and owner nonce. A refusal names what failed
    (`VerifyError::check` gives 1 to 5 for the client checks). `verify_round`
    runs the same checks on a leaf the wallet does not own, and `verify_coin`
    runs the Arca library's `CoinRecord::validate` on a coin received out of
    round, back to every round its lineage came from, every leaf of the
    lineage under the same policy. Given an index of the chain
    (`ChainIndex`: whether a scriptPubKey was ever paid, whether an outpoint
    is unspent), `verify_coin` also refuses the coin when any leaf or
    checkpoint of its lineage is on-chain, since an Arca leaf on-chain is
    never spent off-chain, and when a board it rests on (`board-1`) is spent,
    since its owner may have converted it into its leaf; without one, its
    `ReceivedCoin` says the coin rests on the operator's rule
    (`LineageCheck::OperatorRule`). A record that promises one leaf twice is
    refused with kind `salt`. A `VerifiedLeaf` names the round it was
    checked against and makes no claim of finality, which the caller's chain
    source decides; after any rollback that disconnects that round,
    `recheck(previous_round, …)` checks whichever transaction now pays the
    batch output, and a failure is an order to unroll at once. A leaf taken
    from a round (`verify_leaf`) must leave the policy's acceptance horizon,
    27 days by default; a leaf or coin received (`verify_round`,
    `verify_coin`) and a leaf held (`recheck`) need only leave the exit
    deadline, `E_0 ≥ now + 3 days` (the library's `WalletPolicy::receipt`),
    whatever horizon the caller's policy names. `now` is the chain source's median time at the
    call. `tests/data/arca_records.json` is the Arca
    repository's `regtest/vectors/records.json`, copied unchanged; every
    record in it verifies against its round, and every refusal vector is
    refused by its kind. `tests/data/arca_transactions.json` is its
    `regtest/vectors/transactions.json`, copied unchanged: every received
    coin in it verifies, one of them resting on a board, and its refused
    record is refused by its kind. `tests/data/ark_byte_order.json` pins the byte
    order: ids in display hex in the JSON form, internal bytes in the binary
    form and in the rebindable message; a release's `M` in display hex at the
    edge and internal in its message; a received coin's asset in display hex
    as the kit gives it and internal in its record.
  - `forfeit.rs`: the forfeit a wallet signs to give a leaf up in a round,
    from the Arca library's `Forfeit::for_refresh` and `for_offboard`.
    `forfeit::refresh` verifies the new leaf against the round itself as the
    wallet's own leaf taken from a round, takes the unlock hash from that
    leaf and the connector asset `M` from that round, and refuses unless
    output `c` carries the operator's connector script, so nothing the
    wallet signs over comes from the operator's word; it also refuses a
    refund delay that could not end before the new batch's exit deadline even
    for a forfeit published now. `forfeit::offboard` does the same for an
    offboard output the round pays; the offboard's reclaim-delay rule is the
    caller's to check. `GivenUp` names the leaf given up, from its record or
    from a received coin. The wallet signs `Forfeit::message` with
    `sign_csfs` as a rebind of the old leaf into the forfeit output with no
    other input. Once it holds the new leaf's preimage and the round is
    final, `forfeit::release` (or `release_for_offboard`) gives the release
    of the lowest node above the old leaf, from the Arca library's
    `Release::for_refresh` and `for_offboard`: `H` from the old leaf, checked
    against its own round, and `M` from the round the new leaf or offboard
    was validated against, with the node's children for the wallet to show.
  - `transfer.rs`: paying out of round. `Reassignment::new` builds the
    reassignment a sender signs: one leaf per `Payment` to a
    `ReceiveRequest` (the receiver's owner key, owner nonce and exit delay),
    the sender's change among them, each with a fresh random creator nonce
    (`new_creator_nonce`), the second half of the leaf's salt. Two
    reassignments that pay one request therefore never commit to outputs one
    transaction could satisfy for both, which the operator refuses to
    co-sign (kind `merge`). It refuses a request paid twice and whatever a
    receiver would refuse (an output count outside 1 to 4, a checkpoint worth
    more than its coin, outputs taking more than the checkpoints hold);
    `Reassignment::record` gives each receiver its coin record.
  - `store.rs`: `ArkStore`, the wallet's leaves over any of the kit's stores
    (`Arc<dyn DynStore>`), every key under `ark/`: each leaf's record by leaf
    id with the round txid and batch output index it was verified against,
    the entry's unlock preimage, unroll authorisations by node level, the
    owner nonces of leaves asked for whose records have not arrived, and
    every owner nonce and key a leaf was ever kept under, marked rather than
    forgotten when the leaf is removed. No private key is kept. `put_leaf`
    keeps a leaf only for a nonce the wallet waits on (`put_pending`);
    `put_restored_leaf` is for a restore, where nothing is pending (verify
    such a leaf with `verify_held_leaf`). Both refuse a leaf under an owner
    nonce or key the store has kept another leaf under, now or before, and a
    leaf it has removed, since an old signature under the leaf's salt would
    fit it; `put_pending` refuses a nonce already used. It also refuses a
    preimage that does not open the record's unlock hash and an unroll
    authorisation that is not the record owner's signature over that node's
    message. The marks are state the mnemonic cannot rebuild: back the store
    up.
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
- `tests/sequentia_stake_records.rs`: every stake record transaction the kit
  builds, confirmed in a block a proof-of-stake `sequentiad` produces on an
  `elementsregtest` chain, under the node's default relay policy: a bond, a
  delegation created with the controller's coin, a re-point, a reclaim, a
  payout announcement and its withdrawal, and an unbond in two steps; then a
  chain crossing `pos_records_v2_height` at block 12, signed the legacy way
  below it and the second-generation way at it. Each wrong case (a record from
  wallet coins alone, a spend signed for the other generation, a claim before
  the unbonding depth) is refused by the mempool and by a block
  (`testproposedblock` on the node's own next block with the transaction
  added), which accepts the right one. It needs `SEQUENTIAD_EXEC`, and runs
  `lwk_wasm/tests/node/stake_records.js` when the node package is linked.
- `examples/rescue_test.rs`: live functional test of bump/replace/CPFP against
  the testnet (needs a funded wallet).

## `lwk_contracts`

A crate of this fork: the contract engine for templates written with
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts)
(descriptor versions 1 and 2). It depends on that repository's reader and its
pinned compiler, `simplicityhl` 0.7.2 (with `simplicity-lang` 0.8.0, whose C
library carries its own symbol prefix, so it links beside the 0.7.0 that
`lwk_simplicity` uses). `lwk_contracts/README.md` describes what it does;
`templates/PIN.json` names the revision of the templates it carries.

Taking these libraries moved three entries of `Cargo.lock`: `bitcoin_hashes`
0.14.0 to 0.14.1 and `semver` 1.0.27 to 1.0.28, which they require, and `psm`
held at 0.1.26, the last release that builds with the pinned Rust 1.85. The
Simplex SDK itself needs Rust 1.87, so the engine uses its libraries directly
and ports its budget rule.

## `lwk_wasm`

Built with `lwk_wollet` features `sequentia`, `openamp`, `adaptor`,
`btc-async` and `ark` (plus upstream defaults), so the npm-style `pkg/` output
of this fork is Sequentia-enabled.
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
- `src/contract_engine.rs`: the contract engine (`lwk_contracts`):
  `ContractTemplate` (a descriptor and its resolved sources, checked; the
  carried templates by hash, `knownList`), `ContractInstance` (the output,
  address, derivation and paths of an instance; `planDrip` for the faucet
  drip covenant), `ContractSpend` (the spend of a path, its outputs'
  roles, its locks) and `ContractApproval` (the spend checked under the
  five-point signing rule, with the summary a wallet shows and its digest).
  `Signer.signContractSpend(approval, shownDigest)` signs only that digest's
  spend. Values cross as JSON text.
- `build-web.sh`: the browser build (`wasm-pack build --target web
  --release`) with every build-machine path remapped, failing if one remains.
- `src/seqdex_swap.rs`: `SwapRequest` (same-chain SeqDEX swap proposal).
- `src/seqdex_htlc.rs`: `generateSwapSecret`, `htlcKeypair`,
  `buildSeqHtlcRedeemScript`, `buildSeqHtlcClaimTx`, `buildSeqHtlcRefundTx`.
- `src/tx_builder.rs`: `feeAsset()` (any-asset fees), `addExplicitRecipient()`,
  `addStakeOutput()`, `sequentiaStakeScript()`, `addRecordAuthorization()`,
  `addDelegationOutput()`.
- `src/wollet.rs`: explicit-UTXO and rescue (bump/replace/CPFP) bindings.
- `src/network.rs`: `Network.regtestWithGenesis(policyAsset, genesisHash)`, a
  regtest network for a chain started with its own parameters, whose genesis
  hash a signer must know.
- `src/signer.rs`: `Signer.stakerPublicKey()` (staking key at `m/2/0`); the
  OpenAMP enclave key and its signing at `m/5/0`; `Signer.xonlyPublicKeyAt(path)`
  and `Signer.signTapscript(path, txHex, inputIndex, prevoutsHex, leafScriptHex,
  controlBlockHex, sighashType, genesisHex, allowSighash?)` over
  `SwSigner::sign_tapscript`. A `Signer` keeps the network it was made with
  (`Signer.genesisHash()`) and refuses a script-path spend or an Arca message
  for any other chain. `allowSighash` names the one sighash type other than
  `SIGHASH_DEFAULT` and `SIGHASH_ALL` the caller accepts (`"none"`,
  `"single"`, `"all|anyonecanpay"`, `"none|anyonecanpay"`,
  `"single|anyonecanpay"`).
- `src/tapscript.rs`: `tapscriptSighash(...)`, the same signature hash without a
  key, and `tapscriptDescribe(...)`, the plain lines of what a signature over
  the spend authorises. Prevouts are consensus-serialised hex in input order;
  the genesis hash is display hex.
- `src/csfs.rs` and `src/signer.rs`: `Signer.signCsfs(path, message,
  digestHex, limits)` over `SwSigner::sign_csfs`, and the free functions
  `csfsDigest(message)` and `csfsDescribe(message)` (`{ kind, digest, lines }`).
  A message is a plain object: `{ kind: "rebind", source, assetIn, valueIn,
  outputs }`, `{ kind: "unroll", children, time }` or
  `{ kind: "release", genesisHash, children, connector }`, each output or child
  `{ asset, value, scriptPubkey }`; asset ids and the genesis hash in display
  hex, amounts in atoms as a number or a decimal string. A rebind's `source`
  is the leaf's record, `{ record }` (its JSON text or its binary form as hex), or
  `{ path, leafId, genesisHash, salt }`; its `otherInputs`, `[{ asset, value }]`,
  are the transaction's other inputs, `[]` for a coin spent alone. `limits` is
  `{ feeFloorPerKvb }` for the specification's fee margin or
  `{ maxUncommitted }` for a ceiling in atoms; without it a rebind must commit
  the whole coin. A message, a source, an output or input, or `limits` with a
  field it does not name is refused (`unknown field ...`), so a misspelt field
  never quietly takes a default.
- `src/ark.rs`: Arca leaves. `arkNewOwnerNonce()`, `arkLeafKeyPath(account,
  ownerNonce)`, `Signer.arkLeafKey(account, ownerNonce)` and
  `Signer.arkRestoreKey(account, record)` for the leaf keys;
  `arkParseRecord(record)` for a record's fields; `ArkVerifier(network,
  policy)`, whose policy object also takes the tree bounds (`maxLevels`, and
  `minReserveAtoms` or `minReserveFeeRate`), with `verifyLeaf`, `verifyRound`
  and `recheck`, each taking the
  chain's median time `now` as its last argument (the policy names none, and
  refuses one), whose verdict is
  `{ accepted: true, leafId, roundTxid, asset, value, expiries, ... }` or
  `{ accepted: false, failed, check, kind, reason }`; a policy with a field
  it does not name is refused, as a misspelt bound would otherwise take its
  default; and `ArkStore(storage)`
  over a `JsStorage` object, with `putPending`, `putLeaf`, `putRestoredLeaf`
  and `removeLeaf` keeping the same rules as the native store. A record is its JSON text or its binary form as
  hex. Asset ids, the token and the genesis hash are display hex at this
  edge; leaf ids, nonces, keys and transactions are hex of their bytes. The
  verifier takes the wallet's chain from its `Network` and makes no claim of
  finality.
- `src/ark_spend.rs`: coins, forfeits and releases, on `ArkVerifier`, each
  taking `now`. `verifyCoin(coin, rounds, ownerKey, ownerNonce, now, chain?)`
  verifies a coin received out of round (its record as hex, every round and
  board transaction its lineage came from); `chain` is what the wallet's chain
  source found, `{ paid: [scriptPubkey], spent: [{ txid, vout }] }`, and a coin
  with a lineage script paid or a board spent is refused (kind `on_chain`);
  without it the verdict's `lineageCheck` is `operator-rule`. The verdict is
  `{ accepted: true, coinId, asset, value, hops, expiry, exitDeadline,
  lineageCheck, lineage, boards }` or `{ accepted: false, kind, reason }`.
  `coinLineage(coin, rounds, now)` gives the lineage scripts and boards to look
  up first. `forfeitRefresh(old, newRecord, round, c, ownerKey, ownerNonce,
  refundDelaySeconds, margin, now)` and `forfeitOffboard(old, offboard, round,
  c, refundDelaySeconds, margin, now)`, `old` being `{ record }` or
  `{ coin, rounds }`, and `releaseRefresh(oldRecord, oldRound, newRecord,
  round, c, ownerKey, ownerNonce, now)` and `releaseOffboard(oldRecord,
  oldRound, offboard, round, c, now)` wrap the native builders and return
  `{ message, digest, ... }`, `message` being the object `signCsfs` takes;
  `connector` is `M` in display hex.
- `tests/node/arca_signers.js`: the bindings against the Arca vectors.
  `tests/node/scripts/arca_regtest.py` spends the Arca reference scripts on a
  regtest node with signatures from these bindings (see `lwk_wasm/README.md`).
- `tests/node/ark_records.js`: the Arca record vectors and the byte-order
  vector (`lwk_wollet/tests/data/ark_byte_order.json`, written by
  `ark_byte_order.py` with hashlib alone) through the bindings: every record
  verifies, every refusal vector is refused by its kind, and the keys, the
  policy and the store hold. Every received coin in the transfer vectors
  verifies through `verifyCoin`, one of them resting on a board; a coin
  whose lineage script is paid, or whose board is spent, is refused, and so
  is the record promising one leaf twice (kind `salt`).
- `lwk_wollet/tests/ark_regtest.rs` with `tests/node/ark_regtest.js`: leaves
  built by the Arca tree builder in an honest round and in five rounds that
  consensus accepts but a wallet must refuse, mined on an `elementsregtest`
  node; the bindings restore the wallet from its mnemonic, find its leaf keys
  from the records' nonces, fetch each round from the node, accept the honest
  leaves and refuse each attack by the check that catches it. The honest
  round is then rolled back with `invalidateblock` and replaced by a round
  paying the same batch output from the same issuing coin: `recheck`, at the
  node's median time, accepts an honest replacement as such, still accepts it
  with the chain ten days on, refuses it one second past its exit deadline,
  and refuses a replacement carrying a second token atom at `R`, by check 1.
  Before the rollback a round paying the wallet a new leaf, an offboard
  output and the operator's connector is mined, and the bindings build the
  forfeit and the release for two of the wallet's old leaves
  (`forfeitRefresh`, `releaseRefresh`, `forfeitOffboard`, `releaseOffboard`):
  each digest equals the native one, `M` is that round's connector asset in
  display hex, and the signatures `signCsfs` makes with the old leaves' keys
  verify natively. It needs `SEQUENTIAD_EXEC` and fails without it. CI
  builds it and runs the native Arca tests (`lwk_signer` and `lwk_wollet`'s
  `ark` module) in a job of their own.
- `src/seqob_covenant.rs`: `buildCovenantFillTx`, `buildCovenantRefundTx`,
  `covenantMakerAddress`, `covenantMakerDescriptor`, `scriptToAddress`.
- `src/sequentia_delegation.rs`: `sequentiaDelegationScript`,
  `parseDelegationScript`, `findDelegationRecords`, `buildDelegationCreateTx`,
  `buildDelegationSpendTx`, `stakeRecordSigning`. The builders take the chain
  tip (`tipHeight`, defaulting to `locktime`) and sign for the block after it.
- `src/sequentia_stake_records.rs`: `buildUnbondTx` and `buildUnbondClaimTx`
  (the two steps of unbonding), `sequentiaUnbondScript`, `unbondFeeCap`.
- `tests/node/stake_records.js`: the wasm half of
  `lwk_wollet/tests/sequentia_stake_records.rs`: every recipe the test's
  confirmed transactions came from, through the bindings, must give the same
  transaction byte for byte.
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

## Key paths

Every key the kit derives for a role of its own, beside the on-chain address
purposes (BIP44 `44'`, BIP49 `49'`, BIP84 `84'`, BIP86 `86'`, AMP2 `87'`):

| Path | Key |
|---|---|
| `m/2/0` | The staking key: stake bonding and unbonding, staking-pool delegation (with the `P2WPKH` coin that authorises a record), and messages signed as the staker |
| `m/3/0` | The SeqDEX HTLC key (`htlcKeypair`), and the cross-chain swap's Sequentia claim key in its legacy relative mode; the cross-chain swap's own keys are at `m/84'/1'/0'/2/0` (BTC refund), `/3/0` (Sequentia claim) and `/4/0` (BTC claim) |
| `m/5/0` | The OpenAMP enclave key, which signs raw 32-byte digests (`openampSignSighash`) |
| `m/6'/<account>'/c1'/c2'/c3'/c4'` | Arca leaf keys, one per leaf, from the leaf's owner nonce (`ark::keys`) |
| `m/8383'/<coin>'/0'/...` | Contract keys (`lwk_contracts`): the keys a contract template names, `0/0` by default; `<coin>` is 1776 on mainnet and 1 elsewhere. The account and its default are the Simplex fork's, so a key made there signs here |

The SeqLN device keys of the web wallet and Ambra are under `m/1017'`. A new
role takes the next free number here; a key that signs raw digests never
shares a path with one that signs anything else.

## Design invariants the fork keeps

- Sequentia is transparent by default; confidentiality is opt-in. Docs and code
  never assume blinded-by-default (that is the Liquid model).
- The Sequence token (SEQ; tSEQ on testnet) is the policy asset but has no
  privilege anywhere in the kit except staking (bonding, unbonding and
  delegation records); fees are payable in any accepted asset and fee rates
  are denominated in the chosen asset's own units per vByte.
- One redeemScript source for cross-chain HTLCs: the Bitcoin leg wraps the same
  builder the Sequentia leg uses, so the legs cannot drift (this is why the
  `btc` feature implies `sequentia`).
- Anchor verification is always done against the wallet's own backends, never
  data supplied by a swap counterparty.
