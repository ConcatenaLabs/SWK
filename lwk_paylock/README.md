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
   the lock's anchor, `D` far enough ahead and at most 1,008 blocks above
   Bitcoin's tip, the lock spanning at most 1,008 blocks), the node's `checklock`, and that
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

   **The payment is at most 400 bytes without its witness**: seven ordinary
   (P2WPKH) inputs and two outputs fit, eight do not. The fee tiers are priced
   for the claim that proves such a payment: a proof of 1,584 bytes (the payment,
   a merkle branch of 14 levels, for a Bitcoin block of up to 16,384
   transactions, and two linking headers; `PRICED_PROOF_BYTES`). A heavier
   payment makes a heavier claim, whose fee rate is lower than its tiers were
   priced for: it may not relay at the going tier, and the top tier no longer
   costs a seller more than the swap is worth to keep out. `paylock cancel`
   (and the library's `cancel_template` and `check_own_payment`) refuse a
   heavier payment; a wallet pays from fewer inputs instead. A wallet sizes the
   going fee for the same claim: `claim_vsize(claim, PRICED_PROOF_BYTES)`
   virtual bytes at the going rate, with headroom.
5. **The payment**, an ordinary Bitcoin transaction to the receiving address.
6. **Completion.** Once a Sequentia block anchors at the payment's height or
   above, the service attaches the proof and submits the claim. The swap is
   done when the claim's block is final.
7. **Or the refund.** If no claim is mined, the seller's `paylock sign-refund`
   is valid 60 blocks after the first block anchored at `D`. It refuses to sign
   while a payment to the receiving address that a proof can carry is mined
   above `F` and at most `D`: that payment is a buyer's, and its claim can still
   be mined. One no proof can carry opens nothing and does not hold it back. Its fee, too,
   comes from the locked asset, the fee pot or a coin of the seller's own.

## The completion service

```sh
PAYLOCK_SEQ_URL=http://127.0.0.1:<port> PAYLOCK_SEQ_COOKIE=<datadir>/<chain>/.cookie \
PAYLOCK_BTC_URL=http://127.0.0.1:<port> PAYLOCK_BTC_COOKIE=<datadir>/.cookie \
  paylock serve --data <dir> --listen 127.0.0.1:<port> [--token-file <file>] [--max-jobs 1000] \
    [--jobs-per-client 50] [--watch-depth 6] [--watch-every 30]
```

Beyond loopback it refuses to start without `--token-file`; every request then
carries `Authorization: Bearer <token>`. A request's client is the peer's
address (an IPv6 address by its /64); behind a reverse proxy on the same host
(the peer is loopback) it is the last address in `X-Forwarded-For`, the one that
proxy wrote.

Each connection is served on a thread of its own, one request per connection,
under deadlines: the request line and headers within 5 seconds, the whole
request within 10 (`408` beyond). A body needs `Content-Length` (`411`) of at
most 512 KiB (`413`). The service serves 256 connections at once. One address
holds at most 16 of them (`429` beyond; behind the proxy, the client its
headers name), and the last 32 go only to an address holding none. A
connection that has sent no headers is idle: a new one from its own address
takes its place when that address holds its share, and when every slot is
taken a new one takes the place of the oldest idle one (idle for a second) of
the address holding the most; with none idle it is answered `503`. A client
may be sending four bodies at a time (`429` beyond). Every refusal is a JSON
answer the client reads: what it sent is read before the connection closes.
So a slow or crowding client holds only its own connections, and reads and
other posts are answered meanwhile.

It holds no key. A buyer's wallet hands its job over before it broadcasts its
payment:

```json
{"terms": {...}, "lock": "<txid>:<vout>", "claims": ["<going tier>", "<top tier>"],
 "payment_hex": "<signed payment>", "cancel": "<signed Bitcoin transaction>"}
```

to `POST /jobs`, and reads its state at `GET /jobs/<id>` (`waiting`, `pooled`,
`mined`, `final`, `cancelled`, `never`, `refunded`). The claims may be tiers in
two fee assets. `cancels` may carry several cancels. `payment` (a Bitcoin
transaction id) may stand in for `payment_hex` once the payment is broadcast:
it is only a hint, to take the payment from the daemon's mempool.

There is one job per lock, named by the lock. Every post for a lock merges into
its job and never takes a place of its own: claims it lacks are added, and so
are payments and cancels. So a client that posts the buyer's claims first, with
a made-up payment id, no payment, a subset of the claims or no cancel, holds
nothing of the buyer's out.

The claim needs nothing a client posts besides the claims. The payment is a
transaction mined above `F` and at or below `D` that pays the terms' receiving
script at least the price, whoever made it and whatever coins it spends, since
that is what the claim accepts, **and whose completed claim the node accepts**.
Any such transaction a proof can carry is a candidate: one that is not a
coinbase and is, without its witness, neither 64 bytes long nor above 100,000
bytes (the specification's section 4.1). A paying transaction outside those
bounds (a miner can mine one Bitcoin would not relay) opens nothing and is no
candidate; a read shows its height as `unprovable_payment_height`.

The candidates are tried in turn, across the whole window: a payment handed
over first, then the rest by the lightest proof they make. Each is tried at
every tier the buyer signed, cheapest first. A refusal for the claim's weight
(`min relay fee not met`, `mempool min fee not met`, `mempool full`, `tx-size`:
the only refusals that depend on which payment the claim proves) moves to the
next tier; refused at every tier, the candidate is passed over, with every one
whose proof would be as heavy, and the next is tried in the same round. A
candidate is passed over only for that, and comes back only once what refused
it can have changed. The node's floors (its relay floor and each fee asset's
rate, read once a round) have moved so that a refused tier's own signed fee is
worth what the node would now ask for that claim: the refusal states the ask,
which fixes the claim's size, and the service values the fee itself, never by
the worth the refusal states, which the node rounds down (at a low rate a fee of
thousands of atoms reads `0`). A refusal that gives no figures (`mempool full`),
or whose figures are not the signed fee at the rate read, brings the candidate
back once the floors change at all. Either way it is never tried again at the
very floors that refused it, so it costs at most one try for each change of the
floors. It also comes back once an asset the node did not accept, in which a
tier is signed, is accepted. A claim refused for its size at every tier never
comes back. A block arriving
changes none of this, so it brings nothing back. When no tier is in an asset
the node accepts, every candidate is passed over until one is. A reorganization
below the scan's place drops everything passed over. Anything else that keeps a
claim from being made waits on the chain and never passes a payment over: no
Sequentia block anchored at the payment yet, the Bitcoin daemon and the node's
anchors not agreeing (or the daemon switching branches between reading a block
and its headers), the lowest recorded anchor more than 2,016 blocks above the
payment. A refusal that does not depend on the payment (the lock spent, a
conflicting spend pooled, the fee's asset) would meet every candidate alike,
and is retried. A read shows `candidates`, `passed_over` (each with the node's
reason), and `payment_claimed`: whether the node accepted a claim proving
`payment_height`'s payment. A payment handed over is held so that its cancels
are: a cancel spends exactly the coins of a payment held.

Intake checks what it is handed against the chains before holding any of it,
and refuses what fails, whoever posts it:

- a new job's lock must be an unspent output of the Sequentia chain paying the
  terms' lock script, asset and atoms (or already spent by one of the job's own
  claims): a job costs a real lock. A post for a held lock must name terms that
  make the same lock;
- every claim must spend the lock through the terms' claim leaf and carry the
  buyer's signature over that very transaction; a fee coin's input must be a
  signed P2WPKH spend;
- a signed payment must pay the terms' receiving script at least the price.
  The Bitcoin daemon judges it: one whose signatures fail is refused; one it
  accepts is broadcast at once (the buyer is about to), and is then held as
  vouched for, as is one the daemon already pools or has mined. Such a payment
  is real coins paying the seller, and a post carrying one is never refused for
  a limit. One the daemon cannot check yet (its parent is not broadcast) is held
  unvouched, up to eight in a job and two from one client; beyond that the
  answer is `429`, and the wallet posts it again once the parent is broadcast,
  when it is checked and held whatever else the job holds. Every round checks
  an unvouched payment again: once the daemon's mempool holds a paying
  transaction spending its coins, or accepts the copy held, it is vouched for;
  a copy whose signatures fail never takes its payment's cancels with it;
- a cancel must spend exactly the coins of the post's payment, or of a payment
  the job holds, and the daemon judges it (`testmempoolaccept`). Valid now, or
  already broadcast or mined, it is kept with that payment (up to four; a
  further one takes the place of the cheapest when it pays more). If the daemon
  does not know the coins it spends yet, such a cancel is kept unchecked (up to
  16 for a payment, two from one client), checked again on every round until
  the daemon knows its coins, and sent with the others when they are due; it is
  dropped only if its signatures then fail. A cancel whose signatures fail, or
  that the daemon will not take as it stands (too low a fee to replace the
  payment, say), is refused, and so is one of coins no payment held spends. The
  answer's `notes` say what was kept and how;
- a cancel is known by its witness id, not its transaction id alone, which does
  not cover the witness. A copy of the buyer's cancel with another witness is
  held as a copy of its own beside the buyer's, never in its place: while
  neither can be checked both are kept and sent, and once the daemon knows the
  coins the bad one is dropped and the buyer's kept. A copy the daemon vouched
  for (accepted, or pools) is never displaced by another;
- a cancel or a signed payment is at most 32 KiB, and a claim is kept without
  the witness parts its signature does not cover (the payment's output index
  and the proof, which completing it writes). A post carries at most eight
  claims, spending at most 16 fee coins between them, and four cancels.

Only the payment's signer can make a payment of its coins or a valid cancel of
it, so nobody crowds out the buyer's; what anyone can make up (a payment id, a
payment of coins the daemon has never seen) is bounded, and the buyer's own
gets in as soon as Bitcoin can check it.

A request names only what a wallet hands over (`terms`, `lock`, `claims`,
`payment`, `payment_hex`, `cancel` or `cancels` as raw transactions). Nothing
the service keeps of its own (the payments held, the unchecked cancels, a
cancel's fee, the client, the job's progress) is read from it.

The answer is `200` with the job's `id` (and `merged` or `held`), `400` for a
request that fails a check, `429` when a limit is reached (the client's live
jobs or the service's, for a job with no payment the daemon vouches for; a
job's unvouched payments or unchecked cancels), `503` when a chain does not
answer (try again). A wallet that gets `429` posts again later, at the latest
once its payment's parent is broadcast. A read returns where a job stands and
never its signed claims, cancels, payments or terms.

On every round the service reads both chains as they are now:

- it completes the claim and submits it once the payment is anchored, and proves
  it again after every reorganization that disconnects it;
- it raises the claim to the top tier as soon as a block made after the claim
  was first seen pooled, by whoever pooled it, leaves it out;
- it submits the tiers of the first fee asset the node still accepts whose fee
  coin is unspent;
- it completes the claim with a paying transaction in the lock's heights whose
  claim the node accepts (above), so the buyer's fee bump completes it too; a
  paying transaction mined only after `D` ends the job `never`, and so does a
  window whose every payment is passed over once Bitcoin is past `D`;
- it knows each payment it holds by the coins it spends: a confirmed spend of
  them that does not pay is its cancel. Once every payment Bitcoin has shown
  real is spent so, the job is `cancelled` at the latest of those blocks; a
  payment held that later becomes known reopens it. A coin that is merely
  missing from the UTXO set decides nothing;
- it sends a payment it holds vouched for again if a reorganization evicted it
  before `D`;
- it broadcasts every cancel of every payment held that is not settled, the
  checked ones highest fee first and then those not checkable yet, if two
  blocks before `D` no claim proving a payment mined in the lock's heights is
  pooled or mined, whatever its Sequentia node says of the lock, and sends them
  again until a spend of that payment's coins is confirmed. A claim the node
  once accepted withholds nothing once it has left the mempool and the node
  refuses every tier;
- it shows the swap done (`final`) as soon as the claim's block is final, and
  goes on watching in the background (`watching: true`) until the Bitcoin block
  that decided it is `--watch-depth` blocks deep: a Bitcoin reorganization
  before then is followed by proving the claim again. No one waits for that
  depth; it only sets how long the service keeps a finished swap in view.

Its work is bounded. Cancels have a thread of their own, with clients of their
own that give up on a call after 3 seconds. Each pass sends for at most 2
seconds, then spends at most 1 second looking up locks the node has not answered
for, which orders the next pass: no lookup comes before a send. The node's answer
orders the sends and never withholds one: jobs whose lock
it knows go first, then those it has not answered for, then those it says it does
not know. The turns are per payment, known by its coins: every job holding the
same coins shares one turn and one send, so one payment handed over with many
jobs costs one send, and once the daemon takes a cancel of it the rest of its
checked cancels are not sent. Within each, the clients that handed the payments
over take turns, so one client's many payments get one send per turn like any
other's; and each client's cancels never tried go first, nearest deadline first,
then those tried before, the longest ago first, so what one pass does not reach
the next one does. The turns are found by a map, so a pass is linear in its
cancels however many clients hand them over. What the sends tell the jobs is written after the pass's
sends, so writing many jobs never delays another payment's send. A cancel is
sent until 144 blocks past `D`.

The rest of the work follows what happens on the chains, never the number of
jobs or of the clients that posted them. Each Bitcoin block is read from the
daemon once for every job, and kept (two weeks of blocks) as the scripts it pays
and the coins it spends: a job's search for its payment, from `F` to six blocks
past `D` (on to Bitcoin's tip, up to 144 blocks past `D`, while a payment held
with cancels is not settled), passes a block that neither pays its receiving
script nor spends its payments' coins by a lookup, and reads a block whole only
when it does. A block read whole is kept indexed by the scripts it pays and the
coins it spends, so a job it concerns reads only the transactions that touch it:
one block that concerns many jobs costs a lookup for each, not a pass over the
block for each. A proof is built from its payment's block read once for every
claim proving a payment in it (the last eight such blocks are kept, by hash), so
claims on many payments in one block cost one read of it, not one each. The node's fee floors are read once a round for every job.

A job is worked only when something it waits on can have changed, in this
order:

1. something new on the chains concerns it. First the jobs a claim must be made
   for: a Bitcoin block pays its receiving script or spends its payments' coins;
   a Sequentia block anchors a candidate not passed over; its claim is gone from
   the mempool. Jobs whose claims are worth less than the node's floor asks for
   the lightest proof their payment can make (read from the blocks already held,
   so before they are first tried) take their turns after the others here. Then
   the jobs whose claim is made: pooled by someone, left out of a block (to raise
   it), or mined. The tips are told apart by their blocks' hashes, so a block
   rebuilt at the same height counts;
2. intake changed it since it was last worked;
3. a candidate it passed over may now land (a refused tier's signed fee covers
   the node's ask at the floors now, or an asset became accepted), the claims
   that clear the ask by the most first; then a job whose last round failed,
   once its backoff is over, fewest failures first;
4. the rest, once per Bitcoin block, for the deadline and the state a read
   shows, and a job holding a payment or cancel the daemon cannot check yet,
   whenever a chain moves and at least every ten seconds.

Within each, the jobs take turns by receiving script, least recently worked
first (in the third, the claims that clear by the most first: to go ahead of
another, a claim must pay more, and then it lands and its job leaves). The first
is the work something new on the chains asks for; the rest is background,
and while it runs the service looks at both chains' tips every 200 ms: once
either moves, the round ends and the next one starts at once, so retries after
a change of floors, first tries and the per-block tick keep a buyer whose payment
was just mined or anchored waiting for one job's work at most. A candidate
passed over is never tried again merely because a block arrived, so a job whose claims cannot land (priced under the floor, in assets the
node does not accept) is tried once and then costs a lookup a round, however many
there are and on however many scripts. A buyer whose payment is mined is worked
in the first turns of the round after a Sequentia block anchors it, behind only
the jobs that a claim must be made for in that round, each of which cost whoever
made it an output in a new Bitcoin block or a claim the node takes (a claim
pooled pays its fee once mined, and its job leaves); the upkeep of claims already
pooled or mined comes after it.
Measured on regtest with a release build, against 750 to 40,000 attacker jobs,
each on a receiving script of its own, paid by shared transactions and with
claims priced under the floor: once each had been tried, a buyer's claim was
pooled within 2 seconds of a Sequentia block anchoring its payment, the buyer's
cancel went out within a second of `D - 2`, and the service's memory grew by
about 8 KB a job (326 MB at 40,000).
Each job works within a time and block budget, the round within its own; a job
cut short is worked again next round. A job keeps every payment handed over and
the 32 lightest others as candidates, by the proof each makes linking no header (a
later candidate links fewer headers, 80 bytes each, so one dropped can prove lighter
than one kept by that much, a block or two on a live chain). A failing job backs off, up to a minute.

Memory and disk follow the jobs by a bound per job, never by what a payment
weighs: each signed payment is held once, in memory and in one file under
`--data/payments/`, however many jobs it vouches for, and so is each cancel in
memory. So are a payment's coins: they are held once with it, and a job's file
names them only by a digest while the payment's own file holds the transaction,
so a payment of many coins costs each job no more than one of few. Once the daemon vouches for a payment it is held by its transaction id,
whatever the witness of the copies handed over: a mined payment is vouched for
by its id alone, so copies of it with other witnesses cost nothing more. Until
then each copy is its own, since an unchecked witness may be bad and must never
stand in for another's. A job keeps at most eight claims of 16 KiB each, 64 KiB of payments and
cancels the daemon cannot check yet, and, per payment held, 32 KiB of checked
cancels (only that payment's signer can make one).

Intake caps a request at 512 KiB, a job at eight claims, eight unvouched payments
and, per payment, four cancels (and 16 not yet checkable), a lock at 1,008
Bitcoin blocks from `F` to `D`, the service at `--max-jobs` live jobs and each
client at `--jobs-per-client` live jobs it started (`0` for no limit), never for
a job whose payment the daemon vouches for; a job whose outcome is decided no
longer counts, and a post that merges into a job held starts none.

Jobs are one JSON file each under `--data`, with their payments in
`--data/payments/`, so a restart carries on. A job that
has ended and is buried (the block that decided it, and for a job that did not
complete `D` as well, `--watch-depth` deep) moves to `--data/archive/`, where it
is still answered at `GET /jobs/<id>`, and is removed after 30 days.

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
wrongaddress,unaccepted,feecoin,feepot,twoasset,raise,resend,crowd,overflow,
noraise,preempt,cancelstate,afterfinal,unconf,bumplate,bumpin,block,nopayment,
unknownparent,afterbroadcast,fakelock,samewit,wirepending,onelock,idleconns`;
the script's docstring says what each shows), and
`PAYLOCK_RESULTS` names a file for the observed outcomes and refusal reasons.

`tests/regtest/paylock_activation.py` shows that `paylock terms` builds no lock
unless both rules are reported active: against a node with the payment rule's
height far ahead, a node on a chain without proof-of-stake, and stub reports
of every other combination:

```sh
PAYLOCK_SEQUENTIAD=<node>/src/sequentiad PAYLOCK_BIN=target/debug/paylock \
  python3 lwk_paylock/tests/regtest/paylock_activation.py <empty dir>
```

`cargo test -p lwk_paylock` includes the service's bounds, its intake and its
search by coins, run against fake nodes. The cases that start the `paylock`
binary start `PAYLOCK_TEST_BIN` instead when it is set.
