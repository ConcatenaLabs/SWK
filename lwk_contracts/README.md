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
- signs with a contract key (under `m/8383h/{coin}h/0h`, `0/0` by default),
  only the one the path names; runs the program against the final
  transaction, naming the source check that fails when it refuses; and pads
  the witness with an annex when the program costs more than it earns under
  the budget rule (`min(4 × witness bytes + 50, 4000050)` weight units).

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
cargo test -p lwk_contracts                       # vectors, refusals, budget
SEQUENTIA_BIN=/path/to/Sequentia/src cargo test -p lwk_contracts --test drip_regtest -- --nocapture
```

`tests/vectors.rs` reproduces every golden vector and makes every refusal of
the corpus for its reason. `tests/drip_regtest.rs` starts a local
`elementsregtest` chain with Simplicity active and `-par=1`, drips from a
covenant, and forces three bad drips into blocks (before the interval, above
the tier, a successor that is not the covenant), asserting each refusal's
reason in the mempool and in the block.
