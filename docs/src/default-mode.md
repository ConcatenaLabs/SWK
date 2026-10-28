# Default mode

Every Sequentia wallet built on this kit (the web wallet, the browser extension, Ambra, the
desktop wallet) has two modes, kept for each wallet. This page describes what **default mode**
shows and says. The words are the same in every wallet. A wallet that needs a new sentence adds it
here first.

## The principle

> Developer mode is where people can really mess around and use different rails than those we have
> deemed most efficient, but default mode must provide a consistent experience where all
> complexity is abstracted away from the end user so that they don't need to worry or think about
> rails at all.

In practice:

- Default mode never shows or offers a rail. The wallet chooses the most efficient route for each
  payment or trade: the operator's tree first, then Lightning or the chain. When that route
  cannot be used, the wallet falls back to the next one without asking. Only when no route works
  does it refuse, in one plain sentence, and nothing moves.
- Developer mode shows every rail by name, with its own balance and its manual controls.
- A capability reaches default mode only once the wallet can use it without asking anything, and
  its figure stays one number.

## Names

- The network is **Sequentia**. Its token is **the Sequence token (SEQ)**, tSEQ on the testnet.
- Sequence is one asset among equals. It gets no "native" label and no balance of its own at the
  top of the screen. It is set apart only where staking needs it.
- **BTC** is native bitcoin, never pegged, and is always the first row. A fresh wallet shows
  exactly one row: BTC at 0.
- Assets are named by their ticker and use their own decimals. Default mode never shows an amount
  in atoms or sats.

## Balance

- Each asset has **one figure**: everything the wallet holds of it, wherever it is held. At the
  top is **one total** in the reference currency, across every asset.
- What has been received and cannot be spent yet appears under the figure as
  **"<amount> <TICKER> arriving"**. Once it can be spent, it is simply part of the figure.
- The row's details show only what a person may act on: **Staked**, **Arriving**, and a freeze,
  as "<amount> <TICKER> is frozen by its issuer: it can't be sent until the issuer lifts the
  freeze."
- The split by rail (on-chain, instant, Lightning) and every move between rails are in developer
  mode only.

## Receive

- The card's label is **Receive code**. Under it: "Any asset, any amount. A payment from another
  Sequentia wallet arrives in seconds. Each code is paid once; a new one shows when it is."
- Buttons: **Copy receive code** (confirmation: "Receive code copied"), **New code**, and **Show
  address**.
- Show address gives the wallet's address, the same tb1 address on both chains, with the line:
  "For BTC, and for senders that ask for an address." Its button back is **Show receive code**.
- If the wallet cannot hold coins with the operator (the operator is unreachable, or its server
  shows another key than the one pinned), the address is shown instead and nothing is said about
  why. The wallet tries again on its own.
- **Faucet** (testnet): the faucet pays the receive code. When it has paid: "Received <amount>
  <TICKER>." If the faucet refuses the code, the wallet asks it to pay the address instead, in the
  same click.

## Send

- The field is **Recipient**, with the hint "a receive code, an address or an invoice". Next to
  the asset is its one figure, "balance <amount>".
- A receive code for the wallet's own operator and chain is paid instantly. Anything else goes the
  way it always has. The wallet chooses; nothing asks the person.
- The review is titled **Send <amount> <TICKER>?** with the line "It arrives in seconds." and the
  buttons **Cancel** and **Send**.
- When it is done: **"Sent <amount> <TICKER> (<seconds> s)."** The seconds stay in, so the speed
  can be seen.
- Refusals: one sentence each, and nothing is signed.
  - "Part of this <TICKER> is still arriving: try again in a moment."
  - "A receive code takes Sequentia assets. For BTC, use an address or an invoice." This applies
    until BTC is held with an operator too. From then on, a receive code takes BTC as well.
  - "This amount is kept for instant payments and can't be sent to an address yet. Send it to a
    receive code, or pay an invoice." This applies until the wallet can pay an address from the
    operator's tree. From then on, the payment goes out of the tree and no sentence is shown.
  - "This payment was declined; nothing was sent."

## Trade

- Three inputs and one button: **You pay**, **You get**, **Amount**, then **Review** and
  **Trade**. While pricing: "Finding the best price…". If the price moves: "The price moved. Here
  is the new one."
- Fees are one line, each fee in the asset it is paid in: "Fees <amount> <TICKER>, included
  above", or "No fees". What the wallet pays to be able to receive (for BTC, the room it needs to
  take a payment) is counted as one of these fees and has no row of its own.
- Statuses: **Sent**, then **Settled**. If a trade is undone: "Returned: nothing traded." or
  "Returned: nothing traded. Fees of <fees> were paid."
- Refusals: "This trade could not be made. Nothing moved."; "The other side declined. Nothing was
  traded."; "Not offered right now: nobody offers <get> for <pay> in one step."; "<get> for <pay>
  is not offered."; "Up to <amount> can be traded now."; "Enter how much you pay."; "That amount
  is too small to trade."; "You have no <pay> to trade."
- When a trade cannot be paid or received the way the wallet chose, the wallet takes the next
  route by itself. The person is never offered a button to pick one.

## History

- **One row per payment or trade.** A trade is one row, however many legs it has.
- A trade's row is "Swapped <pay amount> <TICKER> for <get amount> <TICKER>", then a small line
  with the time and, while the trade is not settled, its status. On the right are
  "-<pay> <TICKER>" and "+<get> <TICKER>", then "fee <amount> <TICKER>" when there was one.
- A payment's row has its description (or "Received" / "Sent"), its time and its amount as +/-.
- Which rails a trade used ("BTC on-chain · GOLD over Lightning", "over Lightning") is shown in
  developer mode only.

## Never in default mode

None of these words appear on any screen in default mode, in the wallet's own text: rail,
round, leaf, operator, tree, board, covenant, expiry, atom, sat, forfeit, checkpoint,
reassignment, exit, unroll, anchor, channel, node, room, relay, maker, hash, preimage, HTLC,
submarine, LSP, bridge, gateway, on-chain, Lightning. Nor do these controls: a choice of rail, a
move between rails, a receive request form, an exit drill, contract internals, a fee-rate field,
or a "native asset" label. A refusal the wallet passes on from another service is said in
these words too, never in the service's own.

The web wallet holds its list in `USER_MODE_FORBIDDEN_WORDS` (`user-trade.js`), and each wallet
tests its default-mode strings against the list.
