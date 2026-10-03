
# Liquid Wallet Kit for WASM

> **Sequentia note (SWK fork).** On this branch the crate builds with the
> Sequentia features enabled (`lwk_wollet` with `sequentia`, `openamp`,
> `adaptor`, `btc-async`) and additionally exposes: `Network.sequentiaTestnet()`
> and `Network.isSequentia()`, the Bitcoin testnet4 `BtcWallet` (dual-chain
> wallets), the `xchain*` helpers (cross-chain BTC-to-asset HTLC swaps), SeqDEX
> bindings (`SwapRequest`, `buildSeqHtlc*`), `TxBuilder.feeAsset()` (any-asset
> fees), `addStakeOutput()` and `Signer.stakerPublicKey()` (staking),
> `addDelegationOutput()` / `buildDelegationSpendTx()` (staking pools),
> `buildCovenantFillTx()` / `buildCovenantRefundTx()` (SeqOB covenant orders),
> `coinjoinSignInputs()` / `coinjoinUnblindOutputs()` (CoinJoin), the `Openamp`
> client and `adaptor*` functions. See
> [SEQUENTIA.md](../SEQUENTIA.md). This fork is NOT published to npm (the
> `lwk_wasm` npm package is upstream LWK): build `pkg/` yourself with
> `wasm-pack build --target web --release` (needs clang). The main consumer is
> [sequentia-web-wallet](https://github.com/ConcatenaLabs/sequentia-web-wallet),
> live at https://sequentiatestnet.com/wallet/; the demo formerly in
> `lwk_wasm/www/` moved to that repository.
>
> The upstream README follows.

This is only a proof of concept at the moment but we want to show our commitment to have the 
Liquid Wallet Kit working in the WASM environment.

[Available](https://www.npmjs.com/package/lwk_wasm) as npm package.

For an example usage see the [Liquid Web Wallet](https://liquidwebwallet.org/) ([source](https://github.com/RCasatta/liquid-web-wallet)). Works as CT descriptor watch-only wallet or connected to a Jade.


## For LWK Library developers

To build the WASM library you need [rust](https://www.rust-lang.org/learn/get-started) and
[wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) installed

```shell
$ wasm-pack build --dev
```

To enable web-serial:

```shell
$ RUSTFLAGS="--cfg=web_sys_unstable_apis" wasm-pack build --dev --features serial
```

## For LWK library consumers (front-end developers)

Download the Liquid Web Wallet source

```shell
$ git clone https://github.com/RCasatta/liquid-web-wallet
$ npm install
$ npm run start
```

Open the browser at `http://localhost:8080`

### Test

```shell
$ cd lwk_wasm
$ wasm-pack test --firefox # or --chrome
```

Then open the browser at http://127.0.0.1:8000, open also the dev tools to see console messages and
network requests.

To avoid requiring opening the browser the headless mode is possible.

Note the increased timeout specified via the env var, the 20s default one could be too low.

```shell
$ cd lwk_wasm
$ WASM_BINDGEN_TEST_TIMEOUT=60 wasm-pack test --firefox --headless
```

run specific test (note the double `--`)

```shell
$ wasm-pack test --firefox --headless -- -- balance_test_testnet
```

### Build NPM Package for release

Build rust crates in release mode, optimizing for space.

```shell
$ cd lwk_wasm/
$ RUSTFLAGS="--cfg=web_sys_unstable_apis" CARGO_PROFILE_RELEASE_OPT_LEVEL=z wasm-pack build --features serial
```

```shell
$ cd pkg
$ npm publish
```

### Build wasm lib for profiling

To analyze the generated wasm file to optimize for size, we want to follow the same optimization
as release but we want to keep debug info to analyze the produced lib with function names.

```shell
$ cd lwk_wasm/
$ RUSTFLAGS="--cfg=web_sys_unstable_apis" CARGO_PROFILE_RELEASE_OPT_LEVEL=z CARGO_PROFILE_RELEASE_DEBUG=2 wasm-pack build --profiling --features serial
```

With [twiggy](https://github.com/rustwasm/twiggy) is then possible to analyze the library:

```shell
twiggy top -n 10 pkg/lwk_wasm_bg.wasm
```

### Build for nodejs

```shell
$ cd lwk_wasm
$ RUSTFLAGS="--cfg=web_sys_unstable_apis" CARGO_PROFILE_RELEASE_OPT_LEVEL=z wasm-pack build --target nodejs --out-dir pkg_node -- --features serial
```

Rename the package to `lwk_node` so that we can publish it to npm.

```shell
sed -i 's/"lwk_wasm"/"lwk_node"/g' pkg_node/package.json
```

### Test node js examples

Requirement:

* having built node pkg like shown in previous paragraph
* having node and npm installed

```shell
cd lwk_wasm/tests/node
npm install
node network.js
```

### Arca leaves

`tests/node/ark_records.js` runs the Arca record vectors through the bindings.
`lwk_wollet/tests/ark_regtest.rs` mines Arca rounds on an `elementsregtest`
node, among them attacks a wallet must refuse and replacements after a
rollback, and runs `tests/node/ark_regtest.js`, which verifies them through
the bindings against each round as the node returns it. Both need the node
package above, linked or installed as `lwk_node` in `tests/node/node_modules`;
the second also needs a `sequentiad` binary, and fails without one:

```shell
cd lwk_wasm/tests/node && node ark_records.js
SEQUENTIAD_EXEC=/path/to/sequentiad cargo test -p lwk_wollet \
  --no-default-features --features ark --test ark_regtest -- --nocapture
```

### Arca signers on regtest

`tests/node/scripts/arca_regtest.py` spends the Arca reference scripts on a
regtest node, with every signature made by the wasm bindings
(`Signer.signTapscript` and `Signer.signCsfs`) through
`tests/node/scripts/arca_regtest_driver.js`: a node unrolled with an
authorisation the kit signed, a leaf's collaborative path at one and two
outputs, an exit claim, and a reclaim whose releases each name the connector
asset `M` of a round, issued from a connector output the kit's operator key
signs for. Each negative case is forced into a
block with `generateblock` on a node started with `-par=1`, and must fail in
the mempool and in the block for its own named reason. The kit's own
refusals are recorded too: a message or spend for another chain than the
signer's network, a rebind above the fee margin, and an exit under
`SIGHASH_NONE`. The signers' keys come from mnemonics generated inside the
driver, each signer made for the regtest chain's genesis hash.

It needs the node package above, linked or installed as `lwk_node` in
`tests/node/node_modules`, a `sequentiad` binary, a Sequentia source tree (for
the node's functional test framework), and the `regtest/` directory of the
[`arca`](https://github.com/ConcatenaLabs/arca) repository (for the reference
scripts). Write a framework `config.ini` as `arca/regtest/run` does, then:

```shell
cd lwk_wasm/tests/node/scripts
ARCA_REGTEST=/path/to/arca/regtest SEQUENTIA_DIR=/path/to/Sequentia \
BITCOIND=/path/to/sequentiad ARCA_RESULTS=/tmp/arca-results \
python3 arca_regtest.py --configfile=/path/to/config.ini --tmpdir=/tmp/arca-signers
```

## Javascript code conventions

For new additions and improvements, follow our [guidelines](GUIDE.md).
