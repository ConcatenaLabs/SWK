# SWK — Sequentia Wallet Kit

A fork of Blockstream's LWK (Liquid Wallet Kit), taken at v0.18.1, adapted for Sequentia and for
dual-chain Bitcoin. The crates keep their upstream `lwk_*` names; `upstream` points at
`Blockstream/lwk`, and telling fork code from upstream code is the first question in most changes
here.

`README.md` is the front door and `SEQUENTIA.md` is the precise fork-delta list. `AGENTS.md` in
this directory is the inherited upstream LWK style guide — its Rust conventions (error handling
with `thiserror`, no `unwrap` outside tests, import grouping, naming, commit-message format,
`cargo fmt`/`clippy`/`audit` invocations, the `just` recipes) still apply. It says nothing about
Sequentia; this file covers that gap rather than repeating it.

Node and consensus conventions live in the
[`Sequentia`](https://github.com/ConcatenaLabs/Sequentia) repo.

## Branch

**The default and development branch is `sequentia`.** There is no `origin/master`; the local
`master` is a frozen pointer at the upstream fork point.

The GitHub workflows trigger on pushes to `master` and on pull requests. Since `master` is frozen,
**a direct push to `sequentia` runs no CI at all — only a PR does.** That is a concrete reason to
route every change through a PR, beyond the recorded-reasoning one.

## Build and test

Toolchain is pinned in `rust-toolchain.toml` (1.85.0, with `wasm32-unknown-unknown`).

```sh
cargo build
cargo test -p lwk_wollet --lib --features btc-blocking,btc-async btc
cargo test -p lwk_wollet --lib --features sequentia seqdex
cargo run -p lwk_wollet --example sequentia_sync
```

The `elements` dependency is patched workspace-wide to the vendored `rust-elements/` fork with its
`sequentia` feature on. `README.md` records that this makes a number of upstream fixture tests
fail; treat those as expected fork behaviour rather than as something you broke.

## The WASM build, and who consumes it

```sh
cd lwk_wasm
wasm-pack build --target web --release      # needs clang for the secp256k1 build
```

`--target web` is not optional. The output lands in `lwk_wasm/pkg/` (gitignored, never committed)
and is consumed by
[`sequentia-web-wallet`](https://github.com/ConcatenaLabs/sequentia-web-wallet),
whose `index.html` imports a **default-exported `init`** from `./pkg/lwk_wasm.js` — a shape only
the `web` target produces. The wallet symlinks or copies `lwk_wasm/pkg` into its own `pkg/`.

There is no `just` recipe and no npm script for the wasm build. The Sequentia features
(`sequentia`, `openamp`, `adaptor`, `btc-async`) are compiled into `lwk_wasm` unconditionally, so
no extra flags are needed.

`ambra` also consumes this repo, but as a Rust path dependency on sibling crates rather than
through wasm.

## What the fork actually changes

- **Sequentia is modelled as a custom Elements network.** A direct consequence: upstream's
  `isRegtest()` returns **true** for Sequentia. Use `is_sequentia` instead. This is annotated in
  the code and it is easy to get wrong.
- **Explicit (unblinded) outputs are first-class.** Upstream skips them; under the `sequentia`
  feature they count toward balance, coin selection and history. Change is emitted
  **unconfidential** unless the wallet already holds a confidential UTXO. This mirrors Sequentia
  being transparent by default with confidentiality opt-in — the opposite of Liquid, and the
  opposite of what upstream LWK's own documentation assumes.
- **Address parameters** use bech32 HRP `tb` (identical to Bitcoin testnet, which is what lets one
  address serve both chains) and blech32 HRP `tsqb` for confidential addresses.
- **The genesis hash is hardcoded** in the network constructor, and it feeds the BIP341 taproot
  sighash. The testnet was re-genesised on 2026-07-05 and this value had to be updated. A stale
  genesis hash silently breaks covenant signing rather than failing loudly.
- **The vendored `rust-elements/` fork** adds the Bitcoin anchor to the block header and includes
  it in the block hash. It is patched in via `[patch.crates-io]` and is not a workspace member.
- **`bitcoin` is pinned to an exact version** (`=0.32.7`) specifically to stop HTLC redeemScript
  bytes drifting. Do not loosen that pin.
- **`btc-blocking` cannot target wasm32** and says so with a `compile_error!`. Use `btc-async` for
  anything that must run in a browser.
- Sequentia-specific modules exported from `lwk_wollet`: `btc`, `adaptor`, `openamp`,
  `seqdex_htlc`, `seqdex_swap`, `seqob_covenant`, `sequentia_delegation`, `coinjoin`, plus
  `sequentia_stake_script` and the any-asset fee builder. `SEQUENTIA.md` documents each. `pos` is
  upstream's point-of-sale module (feature `prices`), not proof of stake.

## Cross-language contracts

Several pieces here must stay byte-identical to counterparts outside this repo:

- Swap wire format against the go-elements side in `seqdex` — explicit value and asset are dropped
  on unconfidential swap inputs for exactly that reason.
- HTLC redeem scripts, hence the exact `bitcoin` pin.
- A test locks `build_signed_tx` output to be byte-identical between the `btc-blocking` and
  `btc-async` drivers. Changes to the Bitcoin core path must keep both identical.
- Build a `Contract` through `from_parts`, not a struct literal.

## Retired API

The RFQ client and the `XchainSwap` / `XchainSwapState` types were **deleted**. Commits and design
documents from before that retirement describe an API that no longer exists; do not follow them as
current.

## Naming

The network is **Sequentia**. The token is named **Sequence**, ticker SEQ (tSEQ on testnet). Never
abbreviate the network as "SEQ".

## Working in this repo

- **Repository is public.** Never commit keys, seeds, wallet files, RPC credentials, `.env` files
  or tokens.
- **Commit author:**
  `GracedEternalKingCabbageMan <151803062+GracedEternalKingCabbageMan@users.noreply.github.com>`
- **Always open a pull request, then merge it yourself immediately.** The PR exists so the change
  and its reasoning are recorded — and, here, so CI runs at all — not because anyone is waiting to
  review it. There is no review process. If you are ever told to leave one specific PR open, that
  applies to that PR only and never becomes the default.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->
