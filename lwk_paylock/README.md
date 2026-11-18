# lwk_paylock

The swap of a Sequentia asset for an ordinary on-chain bitcoin payment, over the
chains. The seller locks the asset so that it opens for the buyer on a proof that
the buyer paid the seller's Bitcoin address; there is no hash lock and no Bitcoin
script. The rule is specified in the node's
[`doc/sequentia/bitcoin-payment-proof.md`](https://github.com/ConcatenaLabs/Sequentia/blob/feature/btc-swap-release/doc/sequentia/bitcoin-payment-proof.md),
section 8; the scripts, the proof record and the transactions are built by
`lwk_wollet::btc::paylock`, which has no I/O and also builds for wasm.

This crate adds what needs the chains:

- `SeqChain` and `BtcChain`: the reads a swap needs from a Sequentia node and a
  Bitcoin daemon, over JSON-RPC.
- `complete_claim`: a claim the buyer signed before paying, completed with a
  proof of its payment linked to the lowest anchor the Sequentia chain recorded
  at or above the payment. No key is needed, and the claim's transaction id does
  not change.
- `activation`: whether the node's next block is under both rules the swap
  needs, read from `getdeploymentinfo` (`btc_payment` and `lost_blocks`). An
  entry the node does not report is not active, and a product then keeps the
  swap it had.
- `service`: the completion service.
- `paylock`: one command for every step, for products written in another
  language and for the operator of a completion service.

The Sequentia node must watch Bitcoin (`-validateanchor=1`) and keep a
transaction index (`-txindex=1`).

## The swap

1. **Terms.** Both sides agree the asset, its amount, the price in satoshis, the
   buyer's key, the seller's key and a fresh receiving key of the seller's.
   `paylock terms` sets the floor `F` from the Sequentia tip's anchor and the
   deadline `D` to Bitcoin's tip plus 6, with `R = D`. There is no wait.
2. **The lock.** The seller's wallet pays the asset to the lock's script, from
   its own coins, without signalling replacement.
3. **The buyer's check.** `paylock check-lock` runs the buyer's own checks (the
   lock's script leaf for leaf, the asset and amount in the clear, `F` not above
   the lock's anchor, `D` far enough ahead) and the node's `checklock`. The
   buyer pays only when it answers `payable: true`.
4. **The claim and the cancel.** `paylock sign-claim` signs the claim at the
   going fee and at the top tier (section 8.5), paying the fee in the asset
   being moved. The buyer's Bitcoin wallet makes the payment without sending it,
   and signs the cancel that `paylock cancel` builds. All of them go to the
   completion service.
5. **The payment**, an ordinary Bitcoin transaction to the receiving address.
6. **Completion.** Once a Sequentia block anchors at the payment's height or
   above, the service attaches the proof and submits the claim. The swap is
   done when the claim's block is final.
7. **Or the refund.** If no claim is mined, the seller's `paylock sign-refund`
   is valid 60 blocks after the first block anchored at `D`.

## The completion service

```sh
PAYLOCK_SEQ_URL=http://127.0.0.1:<port> PAYLOCK_SEQ_COOKIE=<datadir>/<chain>/.cookie \
PAYLOCK_BTC_URL=http://127.0.0.1:<port> PAYLOCK_BTC_COOKIE=<datadir>/.cookie \
  paylock serve --data <dir> --listen 127.0.0.1:<port>
```

It holds no key. A buyer's wallet posts one job:

```json
{"terms": {...}, "lock": "<txid>:<vout>", "claims": ["<going tier>", "<top tier>"],
 "cancel": "<signed Bitcoin transaction>", "payment": "<Bitcoin txid>",
 "payment_hex": "<signed payment>"}
```

to `POST /jobs`, and reads its state at `GET /jobs/<id>` (`waiting`, `pooled`,
`mined`, `final`, `cancelled`, `never`). On every tick the service reads both
chains as they are now:

- it completes the claim and submits it once the payment is anchored, and proves
  it again after every reorganization that disconnects it;
- it raises the claim to the top tier as soon as a block made after the claim
  was pooled leaves it out;
- it sends the buyer's payment again if a reorganization evicted it before `D`;
- it broadcasts the cancel if the payment is still unconfirmed two blocks before
  `D`;
- it calls the swap done only when the claim's block is final.

Jobs are one JSON file each under `--data`, so a restart carries on.

## The regtest proof

`tests/regtest/paylock_regtest.py` runs the swap end to end on a
proof-of-stake chain of six stakers anchored to a Bitcoin regtest daemon, every
step through `paylock`, and forces each negative into a block. It needs a node
built from a branch that carries both rules and reports them
(`feature/btc-swap-release`), and Bitcoin Core at `PARENT_BITCOIND` (default
`/usr/local/bin/bitcoind`):

```sh
cargo build -p lwk_paylock
PAYLOCK_NODE_FUNCTIONAL=<node>/test/functional PAYLOCK_BIN=target/debug/paylock \
  python3 lwk_paylock/tests/regtest/paylock_regtest.py \
  --configfile <node>/test/config.ini --tmpdir <empty dir>
```

`PAYLOCK_CASES` picks cases (`path,unpaid,late,gone,remined,anchor`), and
`PAYLOCK_RESULTS` names a file for the observed outcomes and refusal reasons.
