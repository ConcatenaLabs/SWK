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
   It first reads activation: unless the node reports both rules active for its
   next block, it answers `"payment_lock": false` with no lock and no receiving
   address, and the product keeps today's swap.
2. **The lock.** The seller's wallet pays the asset to the lock's script, from
   its own coins, without signalling replacement. When block producers do not
   accept a fee in the asset sold, the seller can add a fee pot
   (`--fee-pot-asset`, `--fee-pot-atoms`): a second output of the lock
   transaction, to the same script, in an accepted asset, priced into the
   offer.
3. **The buyer's check.** `paylock check-lock` runs the buyer's own checks (the
   lock's script leaf for leaf, the asset and amount in the clear, `F` not above
   the lock's anchor, `D` far enough ahead), the node's `checklock`, and that
   the claim can pay its fee in an asset the node accepts (`getfeeassetinfo`):
   the locked asset, the fee pot, or a coin of the buyer's own named with
   `--fee-coin`. The buyer pays only when it answers `payable: true`.
4. **The claim and the cancel.** `paylock sign-claim` signs the claim at the
   going fee and at the top tier (section 8.5). The fee is paid in the asset
   being moved, or from the fee pot (`--fee-pot`, spent beside the lock with the
   same proof), or from a coin of the buyer's own (`--fee-coin`): then the
   command first answers unsigned `templates`, the buyer's wallet signs the
   coin's input of each, and the same command with `--wallet-signed` adds the
   claim's signature. It refuses a fee in an asset the node does not accept.
   Run it once per fee asset to sign tiers in two, so that an asset dropped
   from the producers' lists before the claim is mined leaves a tier that is
   still accepted; the buyer's wallet keeps a fee coin unspent until the claim
   is mined or the refund is valid. The buyer's Bitcoin wallet makes the
   payment without sending it, and signs the cancel that `paylock cancel`
   builds. All of them go to the completion service.
5. **The payment**, an ordinary Bitcoin transaction to the receiving address.
6. **Completion.** Once a Sequentia block anchors at the payment's height or
   above, the service attaches the proof and submits the claim. The swap is
   done when the claim's block is final.
7. **Or the refund.** If no claim is mined, the seller's `paylock sign-refund`
   is valid 60 blocks after the first block anchored at `D`. It refuses to sign
   while a payment to the receiving address is mined above `F` and at most `D`:
   that payment is a buyer's, and its claim can still be mined. Its fee, too,
   comes from the locked asset, the fee pot or a coin of the seller's own.

## The completion service

```sh
PAYLOCK_SEQ_URL=http://127.0.0.1:<port> PAYLOCK_SEQ_COOKIE=<datadir>/<chain>/.cookie \
PAYLOCK_BTC_URL=http://127.0.0.1:<port> PAYLOCK_BTC_COOKIE=<datadir>/.cookie \
  paylock serve --data <dir> --listen 127.0.0.1:<port> [--token-file <file>] [--max-jobs 1000]
```

Beyond loopback it refuses to start without `--token-file`; every request then
carries `Authorization: Bearer <token>`.

It holds no key. A buyer's wallet posts one job:

```json
{"terms": {...}, "lock": "<txid>:<vout>", "claims": ["<going tier>", "<top tier>"],
 "cancel": "<signed Bitcoin transaction>", "payment": "<Bitcoin txid>",
 "payment_hex": "<signed payment>"}
```

to `POST /jobs`, and reads its state at `GET /jobs/<id>` (`waiting`, `pooled`,
`mined`, `final`, `cancelled`, `never`, `refunded`). The claims may be tiers in
two fee assets. On every round the service reads both chains as they are now:

- it completes the claim and submits it once the payment is anchored, and proves
  it again after every reorganization that disconnects it;
- it raises the claim to the top tier as soon as a block made after the claim
  was pooled leaves it out;
- it submits the tiers of the first fee asset the node still accepts whose fee
  coin is unspent;
- it sends the buyer's payment again if a reorganization evicted it before `D`;
- it broadcasts the cancel if the payment is still unconfirmed two blocks before
  `D`;
- it calls the swap done only when the claim's block is final.

Its work is bounded. Cancels have a thread of their own that reads only
Bitcoin's tip, so no slow or stale job delays a cancel. The rest runs jobs
nearest deadline first, each within a time and block budget and the round
within its own; the search for a payment keeps its place between rounds and
reads each Bitcoin block once, from `F` to six blocks past `D`. A failing job
backs off, up to a minute. Intake caps a request at 512 KiB, a job at eight
claims and a lock at 1,008 Bitcoin blocks from `F` to `D`.

Jobs are one JSON file each under `--data`, so a restart carries on. A job that
has ended (final, cancelled, never payable, or refunded) moves to
`--data/archive/` and is still answered at `GET /jobs/<id>`.

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

`PAYLOCK_CASES` picks cases (`path,unpaid,late,gone,remined,anchor,wrongamount,
wrongaddress,unaccepted,feecoin,feepot,twoasset,raise,resend,crowd`; the
script's docstring says what each shows), and
`PAYLOCK_RESULTS` names a file for the observed outcomes and refusal reasons.

`tests/regtest/paylock_activation.py` shows that `paylock terms` builds no lock
unless both rules are reported active: against a node with the payment rule's
height far ahead, a node on a chain without proof-of-stake, and stub reports
of every other combination:

```sh
PAYLOCK_SEQUENTIAD=<node>/src/sequentiad PAYLOCK_BIN=target/debug/paylock \
  python3 lwk_paylock/tests/regtest/paylock_activation.py <empty dir>
```

`cargo test -p lwk_paylock` includes the service's bounds, run against fake
nodes that stall.
