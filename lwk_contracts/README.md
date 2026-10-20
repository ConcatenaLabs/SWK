# lwk_contracts: the contract engine

The kit's engine for Sequentia contracts written with
[`sequentia-contracts`](https://github.com/ConcatenaLabs/sequentia-contracts).
A **template** is a descriptor (version 1 or 2) and the source of each of its
Simplicity programs; an **instance** is the template's parameter and slot
values on one chain. The engine:

- reads a descriptor with `sequentia-contracts`' own reader and checks it with
  that repository's pinned compiler, from source texts it is handed (each
  with its helper includes resolved, as `seqc expand` prints it), so it runs
  in a browser with no file system;
- recomputes an instance's output, its address on a chain and each leaf's
  control block, exactly as the golden vectors and the Rust, Python,
  JavaScript and Go readers do;
- lists the template's spending paths and what each needs: the witness values
  and their sources, the key that signs, and the relative lock or lock time a
  tapscript leaf checks;
- builds the spend of a chosen path from a request, and refuses an output the
  request mislabels (a "return to the contract" that pays another script, a
  "payment to this wallet" that is not the wallet's), a confidential output, a
  missing or second fee, and inputs and outputs that do not balance;
- spends, beside the one contract coin, the wallet's own coins (a top-up, a
  purchase, a fee in another asset) and foreign coins spent through a script
  leaf with a given witness (an oracle's beacon coin, spent and recreated),
  as described below;
- recomputes a contract an output opens (a vault a take creates) from its
  instance, for a template the kit carries;
- refuses a spend whose relative lock (BIP68) or lock time the chain would
  refuse now, from the chain facts it is given;
- signs, through the five-point gate below, with a contract key (under
  `m/8383h/{coin}h/0h`, `0/0` by default), only the one the path names; runs
  the program against the final
  transaction, naming the source check that fails when it refuses; and pads
  the witness with an annex when the program costs more than it earns under
  the budget rule (`min(4 × witness bytes + 50, 4000050)` weight units).

## Inputs beside the contract coin

A request lists its inputs in order (`inputs`), `{"is": "contract"}` among
them exactly once; without the list the contract coin is the only input.

- `{"is": "wallet", "txid", "vout", "asset", "amount"}` is one of the
  wallet's own coins. The wallet hands the engine its own record of its coins
  (`WalletCoin`: script, asset, amount, the funding key's path), from its own
  sync (`wallet::wallet_coins` reads it from a Wollet, under the `wollet`
  feature), and a wallet input is spent only when that record says what the
  request says: a coin the wallet does not hold, a coin said to be in another
  asset or of another amount, a confidential coin, a coin under a contract
  key, and a script other than P2WPKH are refused. The wallet signs it with
  its funding key, `SIGHASH_ALL`, after checking the key pays the coin's
  script; that signature commits to every input's outpoint and sequence and
  to every output.
- `{"is": "foreign", "txid", "vout", "script_pubkey", "asset", "amount",
  "witness", "sequence"?, "label"?}` is a coin that is neither the
  contract's nor the wallet's, spent through a script leaf with the witness
  given (hex items, the leaf and its control block last). The engine spends
  it only when the chain facts carry the chain's record of that coin
  (`ChainFacts.prevouts`) and it agrees; only through a script leaf (a
  key-path witness is refused); only when the control block commits the leaf
  to the coin's output key; and it runs the program of a Simplicity leaf
  against the final transaction. An output `{"to": "foreign", "input": j}`
  recreates foreign input `j`, with its script, asset and amount. The
  approval shows the coin as what the engine knows it to be (for instance a
  coin in the asset of the contract's `BEACON_ASSET` parameter, recreated at
  output 2), and the request's `label` only as the request's claim.

A second contract input (a chain of contract spends), the key path and a
path of several signatures are refused, each with its reason.

A path that takes no signature (the Pignus vault's and offer's) is signed by
no contract key; the wallet's keys sign only its own inputs. Where several
paths share one Simplicity leaf, the kit keeps, for the templates it carries,
which spender value selects each (`known::PATH_SELECTORS`), and refuses a
request whose value selects another path than the one it names. For any
other template the approval says that the descriptor does not tell.

## Signing under the five-point rule

A wallet signs a contract spend only through `approval::Approval`, which holds
the five points of the signing rule in the contracts' specification:

1. the template hash is on the wallet's list of known templates, and so is
   that of every contract an output opens;
2. the engine recomputed the output from the template and the instance, and
   the coin pays it, and recomputed every contract an output opens or returns
   to;
3. the engine ran the program of every Simplicity input against the final
   transaction;
4. the approval shows the template (by the registry's name where the wallet
   has one, else its commitment root), the path, every parameter by its role
   (assets by ticker, amounts in the asset's precision, keys and script
   hashes marked when they are the wallet's, relative locks as a delay), every
   input by what it is, and the wallet's own balance change in every asset,
   counting what its own inputs pay, beside the contract's, the payments, the
   contracts opened and the fee;
5. the key is a contract key, the one the path names, or none when the path
   takes no signature; the wallet's funding keys sign only its own inputs.

`Approval::prepare` checks 1, 2, 3 and 5 and the chain's locks, and writes the
summary of 4 with a digest over it. `Approval::sign` signs only when handed that
digest back: it prepares the spend again from the same inputs, refuses if the
digest differs, and runs the program once more against the transaction it
returns. To run a program before the approval, the engine signs inside itself
(the program checks the signature) and drops that signature; the only one that
leaves the engine is made by `sign`.

The digest is over the whole summary, which holds the unsigned transaction
and every foreign input's witness: a foreign input or a wallet input changed
after the summary was shown is a different digest, and nothing is signed.

The faucet drip covenant (`sequentia/faucet-drip`) has a planner, `drip::plan`,
which computes a drip's sequence, successor and tier as its program checks
them.

## The templates the kit carries

`templates/` holds `sequentia/one-key`, `sequentia/one-key-exit`,
`sequentia/faucet-drip`, `pignus/vault` and `pignus/offer` with their vectors, the version 2 fixture and the
shared refusal corpus, copied from `sequentia-contracts` at the revision
`templates/PIN.json` names (with each file's SHA-256). The `.simf` files there
are the resolved texts. To move the pin, copy the files again from that
repository at the new revision (`seqc expand` for each source), rewrite
`PIN.json`, change the `rev` in `Cargo.toml` and `CONTRACTS_REVISION`, and
run the tests.

## Tests

```sh
cargo test -p lwk_contracts                       # vectors, refusals, budget, the gate
SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test drip_regtest -- --nocapture
SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test vault_regtest -- --nocapture
```

`tests/vectors.rs` reproduces every golden vector and makes every refusal of
the corpus for its reason. `tests/approval.rs` holds the gate to its rule with
no chain, and `tests/inputs.rs` the refusals about wallet and foreign inputs,
the key path and a path of two signatures. `tests/drip_regtest.rs` starts a local
`elementsregtest` chain with Simplicity active and `-par=1`, drips from a
covenant through the gate, and forces three bad drips into blocks (before the interval, above
the tier, a successor that is not the covenant), asserting each refusal's
reason in the mempool and in the block. `tests/vault_regtest.rs` runs a Pignus
version 2 loan through the gate on such a chain: a take that opens a vault, a
top-up, a partial repayment, a liquidation that spends and recreates the
oracle's beacon coin, and the full repayment, each confirmed; it asserts the
refusals for a digest not shown, a foreign input changed after the summary
and a wallet input in another asset than shown, and forces the signed
liquidation moved onto another beacon coin into a block, which refuses it for
the wallet input's signature.
