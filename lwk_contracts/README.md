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
  missing or second fee, and outputs that do not balance the coin;
- refuses a spend whose relative lock (BIP68) or lock time the chain would
  refuse now, from the chain facts it is given;
- signs, through the five-point gate below, with a contract key (under
  `m/8383h/{coin}h/0h`, `0/0` by default), only the one the path names; runs
  the program against the final
  transaction, naming the source check that fails when it refuses; and pads
  the witness with an annex when the program costs more than it earns under
  the budget rule (`min(4 × witness bytes + 50, 4000050)` weight units).

## Signing under the five-point rule

A wallet signs a contract spend only through `approval::Approval`, which holds
the five points of the signing rule in the contracts' specification:

1. the template hash is on the wallet's list of known templates;
2. the engine recomputed the output from the template and the instance, and
   the coin pays it;
3. the engine ran the program against the final transaction;
4. the approval shows the template (by the registry's name where the wallet
   has one, else its commitment root), the path, every parameter by its role
   (assets by ticker, amounts in the asset's precision, keys marked when they
   are the wallet's, relative locks as a delay), and the wallet's own balance
   change in every asset, beside the contract's, the payments and the fee;
5. the key is a contract key, the one the path names.

`Approval::prepare` checks 1, 2, 3 and 5 and the chain's locks, and writes the
summary of 4 with a digest over it. `Approval::sign` signs only when handed that
digest back: it prepares the spend again from the same inputs, refuses if the
digest differs, and runs the program once more against the transaction it
returns. To run a program before the approval, the engine signs inside itself
(the program checks the signature) and drops that signature; the only one that
leaves the engine is made by `sign`.

The faucet drip covenant (`sequentia/faucet-drip`) has a planner, `drip::plan`,
which computes a drip's sequence, successor and tier as its program checks
them.

## The templates the kit carries

`templates/` holds `sequentia/one-key`, `sequentia/one-key-exit` and
`sequentia/faucet-drip` with their vectors, the version 2 fixture and the
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
```

`tests/vectors.rs` reproduces every golden vector and makes every refusal of
the corpus for its reason. `tests/approval.rs` holds the gate to its rule with
no chain. `tests/drip_regtest.rs` starts a local
`elementsregtest` chain with Simplicity active and `-par=1`, drips from a
covenant through the gate, and forces three bad drips into blocks (before the interval, above
the tier, a successor that is not the covenant), asserting each refusal's
reason in the mempool and in the block.
