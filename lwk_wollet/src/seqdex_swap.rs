//! Sequentia (SeqDEX / TDEX-fork) same-chain SwapRequest builder.
//!
//! This builds the *taker* (proposer) half of a same-chain atomic swap that the
//! SeqDEX daemon's `ProposeTrade` (seqdex.v1, `/v1/trade/propose`) consumes: an
//! unsigned, unblinded PSETv2 plus the list of `UnblindedInput`s revealing the
//! taker's input blinders so the maker (responder) can balance the confidential
//! transaction with `BlindLast`.
//!
//! This is a faithful Rust port of the Go daemon's taker SDK:
//! `daemon/pkg/trade/buy.go::marketOrderRequest` + `daemon/pkg/trade/wallet.go::NewSwapTx`,
//! and the wire shape in `daemon/pkg/swap/request.go`.
//!
//! ## Blinder byte order — the critical correctness detail
//!
//! The daemon hit `bad-txns-in-ne-out` from a blinder byte-order flip (fixed in
//! commit b9f63c8). The net effect of the daemon's code is that the wire
//! `asset_blinder` / `amount_blinder` of each `UnblindedInput` are the Elements
//! node's `listunspent` `assetblinder` / `amountblinder` hex **verbatim** —
//! i.e. transaction-id-style *display* order, which is **byte-reversed** relative
//! to the secp256k1 internal little-endian representation. In go-elements the
//! explorer reverses node-hex → internal-LE and then `utxosToUnblindedIns`
//! reverses internal-LE → display-hex via `elementsutil.TxIDFromBytes`, so the
//! two reversals cancel and the wire carries display-order hex.
//!
//! In the Rust `elements` crate the blinding factor's `Display`/`to_string()`
//! (and serde human-readable form) is exactly this **display / big-endian** hex
//! (`hex::format_hex_reverse` over the internal bytes), while `.into_inner().
//! serialize()` / `to_bytes()` is the internal little-endian order. So the wire
//! hex is produced with `to_string()`, NOT the raw bytes. Using the raw bytes
//! would reproduce the b9f63c8 bug.
//!
//! ## Transparent or blinded receive: the taker's choice for each swap
//!
//! Sequentia is transparent by default, and confidentiality is the holder's choice
//! for each transfer. The taker makes that choice with the receive address it
//! passes:
//!
//! - **An unconfidential address** (the plain `tb1…` form) builds an explicit half:
//!   the receive output and every change output carry their asset and amount in the
//!   clear, and only explicit coins are spent, since a blinded input's blinding
//!   factors can only be absorbed by a blinded output. A wallet whose coins of the
//!   asset sit only at blinded addresses is refused before anything is sent to the
//!   maker. The maker completes such a half explicitly; its own outputs follow its
//!   own coins and choice.
//! - **A confidential address** builds the blinded half: the maker blinds the
//!   receive output to the address's blinding key and the change outputs with the
//!   taker's revealed input blinders.
//!
//! ## Checking the maker's answer before signing
//!
//! [`Wollet::seqdex_verify_accept`] compares the maker's co-signed transaction with
//! the request this wallet built, and refuses it unless every input the wallet put
//! in is there and unchanged, no other coin of the wallet is spent, the wallet's
//! inputs are signed over the whole transaction, and every output the wallet put in
//! pays the same script the same asset and amount, explicit where the wallet asked
//! for explicit and blinded to the wallet's own key where it asked for blinded. The
//! signature then authorises exactly the swap the wallet proposed, and nothing the
//! maker added can take from it.

use std::collections::{HashMap, HashSet};

use crate::bitcoin::PublicKey as BitcoinPublicKey;
use crate::elements::pset::{Output, PartiallySignedTransaction};
use crate::elements::{Address, AssetId, OutPoint, Script, TxOutSecrets};
use crate::error::Error;
use crate::util::EC;
use crate::wollet::Wollet;
use lwk_common::set_genesis_hash;

/// One revealed taker input of a [`SeqdexSwapRequest`].
///
/// Mirrors `daemon/pkg/swap` `UnblindedInput` and the `seqdex.v1.UnblindedInput`
/// proto. `asset` is display-hex asset id; `asset_blinder` / `amount_blinder`
/// are display-order (txid-style) hex — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqdexUnblindedInput {
    /// Index of the input in the PSET.
    pub index: u32,
    /// Unblinded asset id, display hex.
    pub asset: String,
    /// Unblinded amount in satoshi.
    pub amount: u64,
    /// Asset blinder, display-order hex (byte-reversed vs internal LE).
    pub asset_blinder: String,
    /// Amount (value) blinder, display-order hex (byte-reversed vs internal LE).
    pub amount_blinder: String,
}

/// The taker half of a SeqDEX same-chain swap, ready to be sent to the daemon's
/// `ProposeTrade` as a `SwapRequest`.
#[derive(Debug, Clone)]
pub struct SeqdexSwapRequest {
    /// Random swap id (8 bytes hex = 16 hex chars), matching `randstr.Hex(8)`.
    pub id: String,
    /// Proposer's amount (the amount of `asset_p` the taker sends, fee-exclusive).
    pub amount_p: u64,
    /// Proposer's asset (display hex) — what the taker sends.
    pub asset_p: String,
    /// Responder's amount (the amount of `asset_r` the taker receives).
    pub amount_r: u64,
    /// Responder's asset (display hex) — what the taker receives.
    pub asset_r: String,
    /// The unsigned, unblinded PSETv2, base64.
    pub transaction: String,
    /// The taker's revealed input blinders.
    pub unblinded_inputs: Vec<SeqdexUnblindedInput>,
}

/// Options for [`Wollet::seqdex_swap_request`].
#[derive(Debug, Clone)]
pub struct SeqdexSwapRequestOpts {
    /// Asset the taker sends (display hex).
    pub asset_p: AssetId,
    /// Amount of `asset_p` the taker sends (fee-exclusive, the `amount_p` on the wire).
    pub amount_p: u64,
    /// Asset the taker receives (display hex).
    pub asset_r: AssetId,
    /// Amount of `asset_r` the taker receives (the `amount_r` on the wire).
    pub amount_r: u64,
    /// The taker's own address that receives `asset_r` and the change. Its form is
    /// the taker's choice for this swap: an unconfidential address receives
    /// explicitly (the transparent default), a confidential one receives blinded.
    pub receive_address: Address,
    /// Fee asset (display hex) — the asset the taker funds the on-chain network
    /// fee in (open fee market). May be `asset_p` or any other held, fee-eligible
    /// asset, but NOT `asset_r` (a fee output in the received asset would inflate
    /// the `amount_r` the maker validates). When `fee_amount == 0` the taker funds
    /// nothing and the maker funds the fee in `asset_r` (the legacy default path).
    pub fee_asset: AssetId,
    /// Fee amount, in atoms of `fee_asset`. `0` ⇒ maker-funded (default); `> 0` ⇒
    /// the taker funds the fee itself, adding a `fee_asset` input + an explicit
    /// fee output (+ blinded `fee_asset` change) to the swap.
    pub fee_amount: u64,
    /// `fee_asset`'s open-fee-market rate: atoms of `fee_asset` per
    /// `exchange_rate_scale` (1e8) native atoms, as published by the node. Used
    /// only to compute the `fee_asset` dust threshold so a sub-dust change is
    /// folded into the fee output rather than emitted (and rejected by node
    /// policy). `0` is treated as native (1:1). Ignored when `fee_amount == 0`.
    pub fee_rate: u64,
}

impl Wollet {
    /// Build a SeqDEX same-chain SwapRequest (taker half).
    ///
    /// Selects the wallet's `asset_p` UTXOs to fund `amount_p`, builds an
    /// unsigned/unblinded PSETv2 with a receive output of `amount_r` `asset_r` to
    /// `receive_address` and an `asset_p` change output, and reveals the selected
    /// inputs' blinders.
    ///
    /// With an unconfidential `receive_address` both outputs are explicit and only
    /// explicit coins are selected; a shortfall that the wallet's blinded coins of
    /// the asset would cover is refused with that reason. With a confidential
    /// `receive_address` the maker blinds the receive output to its key and the
    /// change outputs with the revealed blinders, as below.
    ///
    /// Open fee market — the taker may fund the on-chain network fee in ANY held,
    /// fee-eligible asset (the user picks; default = the asset being sent), not
    /// just a swap leg. When `opts.fee_amount > 0`:
    ///   * if `fee_asset == asset_p`, the single `asset_p` selection funds both
    ///     the send leg and the fee, and an explicit `asset_p` fee output is added;
    ///   * otherwise (`fee_asset` is a third asset) a SECOND coin-selection over
    ///     `fee_asset` UTXOs is added BEFORE the receive output (so the receive
    ///     output's blinder index still equals the total taker input count and
    ///     thus points at the maker's first input), plus a blinded `fee_asset`
    ///     change and an explicit `fee_asset` fee output.
    /// A fee in `asset_r` is rejected (it would inflate the `amount_r` the maker
    /// validates). When `fee_amount == 0`, the function emits NO fee output and
    /// the maker funds the fee in `asset_r` (the legacy default), byte-for-byte
    /// as before.
    ///
    /// The explicit fee output is empty-script + unblinded (an Elements `IsFee`
    /// output) so the maker's last-blinder skips it; the maker (CompleteSwap)
    /// detects this taker-supplied fee output, validates its native-equivalent
    /// value, and does not add its own.
    ///
    /// Faithful to `daemon/pkg/trade/buy.go::marketOrderRequest` +
    /// `wallet.go::NewSwapTx`.
    pub fn seqdex_swap_request(
        &self,
        opts: &SeqdexSwapRequestOpts,
    ) -> Result<SeqdexSwapRequest, Error> {
        // A fee in the RECEIVED asset is not representable here: the explicit fee
        // output would add to the asset_r sum the maker/validator compares to
        // amount_r. "Fee in the received asset" is exactly the maker-funded
        // default, reached with fee_amount == 0.
        if opts.fee_amount > 0 && opts.fee_asset == opts.asset_r {
            return Err(Error::Generic(
                "swap fee cannot be paid in the received asset; \
                 use the maker-funded default (fee_amount = 0) or pick another asset"
                    .into(),
            ));
        }
        let taker_funds_fee = opts.fee_amount > 0;
        let fee_in_asset_p = taker_funds_fee && opts.fee_asset == opts.asset_p;

        // asset_p the taker must fund: amount_p, plus the fee when (and only when)
        // the fee is denominated in asset_p (one selection covers both).
        let fund_amount = if fee_in_asset_p {
            opts.amount_p
                .checked_add(opts.fee_amount)
                .ok_or_else(|| Error::Generic("amount_p + fee_amount overflow".into()))?
        } else {
            opts.amount_p
        };

        // The receive address's form is the taker's choice: a confidential one has
        // the maker blind the receive output to its key (and the change goes there
        // too); an unconfidential one builds an explicit half that spends explicit
        // coins only.
        let blinding_pubkey = opts.receive_address.blinding_pubkey;
        let explicit = blinding_pubkey.is_none();
        let out_script = opts.receive_address.script_pubkey();

        // Init the PSETv2 with the network genesis hash, like TxBuilder::finish.
        let mut pset = PartiallySignedTransaction::new_v2();
        set_genesis_hash(&mut pset, &self.network());

        let mut inp_txout_sec = HashMap::new();
        let mut inp_weight = 0usize;
        let mut n_inputs: u32 = 0;
        let mut unblinded_inputs = Vec::new();

        let utxos = self.utxos_map()?;

        // Greedy largest-first coin-selection of `asset`'s UTXOs covering
        // `target`. Adds each as an input (with the real confidential prevout +
        // input rangeproof the maker's stateless blinder consumes), reveals its
        // blinders in DISPLAY-order hex (see module docs; raw bytes would
        // reproduce the b9f63c8 bad-txns-in-ne-out bug), and bumps `n_inputs`.
        // Returns the total selected; the caller checks it covers `target`.
        let select = |pset: &mut PartiallySignedTransaction,
                      inp_txout_sec: &mut HashMap<usize, crate::elements::TxOutSecrets>,
                      inp_weight: &mut usize,
                      n_inputs: &mut u32,
                      unblinded_inputs: &mut Vec<SeqdexUnblindedInput>,
                      asset: AssetId,
                      target: u64|
         -> Result<u64, Error> {
            // An explicit half spends explicit coins only: a blinded input's blinding
            // factors can only be absorbed by a blinded output.
            let mut candidates: Vec<_> = utxos
                .values()
                .filter(|u| u.unblinded.asset == asset)
                .filter(|u| !explicit || is_explicit_coin(&u.unblinded))
                .cloned()
                .collect();
            candidates.sort_by(|a, b| b.unblinded.value.cmp(&a.unblinded.value));

            let mut selected: u64 = 0;
            for utxo in &candidates {
                if selected >= target {
                    break;
                }
                let idx = self.add_input(pset, inp_txout_sec, inp_weight, utxo, true)?;
                // An explicit (unconfidential) input carries its asset+value in the
                // witness_utxo; lwk also sets the PSET explicit-asset/value fields, but
                // go-elements (the maker's parser) REQUIRES a matching asset/value proof
                // whenever those are present — which an unconfidential input has no
                // commitment to prove. Drop them on explicit inputs (no proof) so the swap
                // PSET parses; the maker reads the input from the witness_utxo + the
                // revealed unblinded_inputs. Confidential inputs keep their fields+proofs.
                if let Some(inp) = pset.inputs_mut().get_mut(idx) {
                    if inp.blind_value_proof.is_none() {
                        inp.amount = None;
                    }
                    if inp.blind_asset_proof.is_none() {
                        inp.asset = None;
                    }
                }
                let secrets = &utxo.unblinded;
                unblinded_inputs.push(SeqdexUnblindedInput {
                    index: idx as u32,
                    asset: secrets.asset.to_string(),
                    amount: secrets.value,
                    asset_blinder: secrets.asset_bf.to_string(),
                    amount_blinder: secrets.value_bf.to_string(),
                });
                selected = selected
                    .checked_add(secrets.value)
                    .ok_or_else(|| Error::Generic("selected total overflow".into()))?;
                *n_inputs += 1;
            }
            Ok(selected)
        };

        // Fund the send leg (asset_p), plus the fee when it's in asset_p.
        let selected_p = select(
            &mut pset,
            &mut inp_txout_sec,
            &mut inp_weight,
            &mut n_inputs,
            &mut unblinded_inputs,
            opts.asset_p,
            fund_amount,
        )?;
        if selected_p < fund_amount {
            return Err(shortfall(
                &utxos,
                explicit,
                opts.asset_p,
                fund_amount,
                selected_p,
            ));
        }
        let asset_p_change = selected_p - fund_amount;

        // Fund the fee in a THIRD asset, if any. Done BEFORE the receive output so
        // the receive output's blinder index counts all taker inputs.
        let mut fee_selected: u64 = 0;
        if taker_funds_fee && !fee_in_asset_p {
            fee_selected = select(
                &mut pset,
                &mut inp_txout_sec,
                &mut inp_weight,
                &mut n_inputs,
                &mut unblinded_inputs,
                opts.fee_asset,
                opts.fee_amount,
            )?;
            if fee_selected < opts.fee_amount {
                return Err(shortfall(
                    &utxos,
                    explicit,
                    opts.fee_asset,
                    opts.fee_amount,
                    fee_selected,
                ));
            }
        }

        // Receive output: amount_r of asset_r to the taker's address. Blinded, the
        // maker is responsible for blinding it (its input comes after every taker
        // input), so BlinderIndex = total taker input count. Explicit, it carries
        // no blinding key and nobody blinds it.
        let receive_output = Output {
            script_pubkey: out_script.clone(),
            amount: Some(opts.amount_r),
            asset: Some(opts.asset_r),
            blinding_key: blinding_pubkey.map(BitcoinPublicKey::new),
            blinder_index: blinding_pubkey.map(|_| n_inputs),
            ..Default::default()
        };
        pset.add_output(receive_output);

        // A change output back to the taker, in the same form as the receive
        // output. Blinded: BlinderIndex 0 (the taker's first, always-revealed
        // input); the maker blinds it via the revealed unblinded_inputs.
        let add_change = |pset: &mut PartiallySignedTransaction, amount: u64, asset: AssetId| {
            pset.add_output(Output {
                script_pubkey: out_script.clone(),
                amount: Some(amount),
                asset: Some(asset),
                blinding_key: blinding_pubkey.map(BitcoinPublicKey::new),
                blinder_index: blinding_pubkey.map(|_| 0),
                ..Default::default()
            });
        };

        // The explicit (unblinded, empty-script) Elements fee output value. A
        // sub-dust fee-asset change is folded in (overpay) below rather than
        // emitted as a change the node would reject by dust policy.
        let mut fee_out_amount = opts.fee_amount;

        if fee_in_asset_p {
            // One asset: the asset_p selection covers amount_p + fee. Both the
            // change and the fee output are asset_p.
            let dust = dust_threshold(opts.fee_rate);
            if asset_p_change as u128 > dust as u128 {
                add_change(&mut pset, asset_p_change, opts.asset_p);
            } else {
                fee_out_amount += asset_p_change;
            }
            pset.add_output(Output::new_explicit(
                Script::default(),
                fee_out_amount,
                opts.fee_asset,
                None,
            ));
        } else {
            // asset_p change, in the receive output's form.
            if asset_p_change > 0 {
                add_change(&mut pset, asset_p_change, opts.asset_p);
            }
            if taker_funds_fee {
                // Third-asset fee: a fee_asset change + explicit fee out.
                let fee_change = fee_selected - opts.fee_amount;
                let dust = dust_threshold(opts.fee_rate);
                if fee_change as u128 > dust as u128 {
                    add_change(&mut pset, fee_change, opts.fee_asset);
                } else {
                    fee_out_amount += fee_change;
                }
                pset.add_output(Output::new_explicit(
                    Script::default(),
                    fee_out_amount,
                    opts.fee_asset,
                    None,
                ));
            }
        }

        // When taker_funds_fee is false there is NO fee output: the maker's
        // CompleteSwap selects its own asset_r inputs, adds the native-equivalent
        // fee output in asset_r, blinds (BlindLast) and signs its inputs.
        //
        // NB: we deliberately do NOT add bip32 derivations / key origins to the
        // request PSET. The Go daemon parses it with go-elements' psetv2, which
        // rejects the extra elements-rs global-xpub / input-bip32 fields with
        // "invalid swap request transaction". Instead the taker, on receiving the
        // SwapAccept, injects those derivations locally (`Wollet::add_details` on
        // the accept PSET) just before signing, then strips them again before
        // returning the signed PSET to the daemon — they never go on the wire.
        // This matches the Go taker, whose NewSwapTx likewise emits a bare PSET
        // and whose Wallet.Sign signs by matching the witness script directly.

        let transaction = pset.to_string();

        let id = random_swap_id();

        Ok(SeqdexSwapRequest {
            id,
            amount_p: opts.amount_p,
            asset_p: opts.asset_p.to_string(),
            amount_r: opts.amount_r,
            asset_r: opts.asset_r.to_string(),
            transaction,
            unblinded_inputs,
        })
    }
}

impl Wollet {
    /// Check the maker's co-signed SwapAccept PSET against the `request` this wallet
    /// built, before the wallet signs it.
    ///
    /// The taker's signature covers the whole transaction, so the check is on what
    /// that transaction does to this wallet, recomputed from the wallet's own
    /// request rather than from anything the maker says:
    ///
    /// - every input of the request is in the accept, with the same previous
    ///   output, no issuance added, and no sighash type other than ALL (or the
    ///   taproot default), so the signature cannot be reused for other outputs;
    /// - no other coin of this wallet is spent;
    /// - the lock time is the request's;
    /// - every output of the request is at the same position with the same script,
    ///   asset and amount: explicit where the request had no blinding key, and
    ///   blinded to this wallet's own key where it had one. An output the taker
    ///   asked to receive explicitly that comes back blinded is refused, and so is
    ///   one asked blinded that comes back explicit: the form is the taker's choice.
    ///
    /// Outputs the maker appends after the request's own are the maker's business.
    pub fn seqdex_verify_accept(
        &self,
        request: &SeqdexSwapRequest,
        accept: &PartiallySignedTransaction,
    ) -> Result<(), Error> {
        let refuse = |why: String| Error::Generic(format!("refusing the maker's swap: {why}"));
        let ours: PartiallySignedTransaction = request
            .transaction
            .parse()
            .map_err(|e| Error::Generic(format!("the swap request does not parse: {e}")))?;

        if ours.locktime()? != accept.locktime()? {
            return Err(refuse("its lock time differs from the request's".into()));
        }

        // Inputs.
        let mut our_inputs = HashMap::new();
        for inp in ours.inputs() {
            our_inputs.insert(inp.previous_outpoint(), inp);
        }
        let mut seen: HashSet<OutPoint> = HashSet::new();
        let txos = self.txos_map()?;
        for inp in accept.inputs() {
            let op = inp.previous_outpoint();
            match our_inputs.get(&op) {
                Some(mine) => {
                    if !seen.insert(op) {
                        return Err(refuse(format!("it spends this wallet's {op} twice")));
                    }
                    if inp.witness_utxo != mine.witness_utxo {
                        return Err(refuse(format!(
                            "it changes the coin {op} this wallet funded the swap with"
                        )));
                    }
                    if inp.has_issuance() != mine.has_issuance() {
                        return Err(refuse(format!("it adds an issuance to the input {op}")));
                    }
                    if let Some(h) = inp.sighash_type {
                        let h = h.to_u32();
                        // 0 = the taproot default, 1 = ALL: both sign every output.
                        if h != 0 && h != 1 {
                            return Err(refuse(format!(
                                "it asks this wallet to sign {op} with sighash type {h:#x}, \
                                 which would leave outputs unsigned"
                            )));
                        }
                    }
                }
                None => {
                    let owned = txos.contains_key(&op)
                        || inp
                            .witness_utxo
                            .as_ref()
                            .is_some_and(|o| self.cache.paths.contains_key(&o.script_pubkey));
                    if owned {
                        return Err(refuse(format!(
                            "it spends {op}, another coin of this wallet"
                        )));
                    }
                }
            }
        }
        if let Some(op) = our_inputs.keys().find(|op| !seen.contains(op)) {
            return Err(refuse(format!(
                "it leaves out {op}, which this wallet funded the swap with"
            )));
        }

        // Outputs.
        if accept.outputs().len() < ours.outputs().len() {
            return Err(refuse("it drops outputs this wallet put in".into()));
        }
        let tx = accept.extract_tx()?;
        for (i, mine) in ours.outputs().iter().enumerate() {
            let theirs = &accept.outputs()[i];
            let txout = &tx.output[i];
            if theirs.script_pubkey != mine.script_pubkey
                || txout.script_pubkey != mine.script_pubkey
            {
                return Err(refuse(format!(
                    "output {i} no longer pays the script this wallet asked for"
                )));
            }
            let want_asset = mine
                .asset
                .ok_or_else(|| Error::Generic(format!("request output {i} has no asset")))?;
            let want_amount = mine
                .amount
                .ok_or_else(|| Error::Generic(format!("request output {i} has no amount")))?;
            let explicit = txout.asset.is_explicit() && txout.value.is_explicit();
            let got: (AssetId, u64) = match mine.blinding_key {
                None => {
                    if !explicit {
                        return Err(refuse(format!(
                            "the maker blinded output {i}, which this wallet asked to \
                             receive explicitly"
                        )));
                    }
                    (
                        txout.asset.explicit().expect("explicit"),
                        txout.value.explicit().expect("explicit"),
                    )
                }
                Some(_) => {
                    if txout.asset.is_explicit() || txout.value.is_explicit() {
                        return Err(refuse(format!(
                            "the maker left output {i} explicit, which this wallet asked \
                             to receive blinded"
                        )));
                    }
                    let sk = self
                        .descriptor
                        .blinding_key_for_script(&mine.script_pubkey)
                        .ok_or_else(|| {
                            refuse(format!(
                                "output {i} pays a script this wallet cannot unblind"
                            ))
                        })?;
                    let secrets = txout.unblind(&EC, sk).map_err(|_| {
                        refuse(format!(
                            "output {i} is not blinded to this wallet's key, so the wallet \
                             could not see or spend what it holds"
                        ))
                    })?;
                    (secrets.asset, secrets.value)
                }
            };
            if got != (want_asset, want_amount) {
                return Err(refuse(format!(
                    "output {i} pays {} of {} where this wallet asked for {want_amount} of \
                     {want_asset}",
                    got.1, got.0
                )));
            }
        }
        Ok(())
    }
}

/// Whether a coin is explicit: both its blinding factors are zero.
fn is_explicit_coin(secrets: &TxOutSecrets) -> bool {
    use crate::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    secrets.asset_bf == AssetBlindingFactor::zero()
        && secrets.value_bf == ValueBlindingFactor::zero()
}

/// The error for a coin selection that fell short of `target`. For an explicit half,
/// a shortfall the wallet's blinded coins of the asset would cover is not a lack of
/// funds: it says so, and what to do about it.
fn shortfall(
    utxos: &HashMap<OutPoint, crate::WalletTxOut>,
    explicit: bool,
    asset: AssetId,
    target: u64,
    selected: u64,
) -> Error {
    if explicit {
        let blinded: u64 = utxos
            .values()
            .filter(|u| u.unblinded.asset == asset && !is_explicit_coin(&u.unblinded))
            .map(|u| u.unblinded.value)
            .fold(0u64, |a, v| a.saturating_add(v));
        if selected.saturating_add(blinded) >= target {
            return Error::Generic(format!(
                "a transparent receive spends only explicit coins, and this wallet's {asset} \
                 that would pay for the swap is held at a blinded address: {selected} explicit \
                 of the {target} needed. Send those coins to this wallet's usual address, or \
                 receive this swap at a blinded address"
            ));
        }
    }
    Error::InsufficientFunds {
        missing_sats: target - selected,
        asset_id: asset,
        is_token: false,
    }
}

/// The `fee_asset` dust threshold, mirroring the node's
/// `ConvertValueToAmount(294, asset)` = `ceil(294 * exchange_rate_scale / rate)`.
/// A confidential change at/below this is rejected by node dust policy, so the
/// builder folds it into the (explicit) fee output instead. `rate == 0` is the
/// native asset (1:1), giving the native 294-atom dust.
fn dust_threshold(rate: u64) -> u64 {
    convert_value_to_amount(294, rate)
}

/// The node's fee-market conversion `ExchangeRateMap::ConvertValueToAmount`:
/// atoms of an asset whose published rate is `rate` (atoms per 1e8 native) that
/// carry `value` native atoms of fee value — `ceil(value * 1e8 / rate)`.
///
/// `rate == 0` is treated as the native asset (1:1), which is correct for the
/// dust threshold (the native asset legitimately values 1:1). CAUTION: for a
/// NON-native asset, `rate == 0` means "not fee-accepted by producers" — callers
/// that must distinguish that (e.g. the cross-chain SEQ-claim fee) MUST check
/// `rate != 0` themselves rather than relying on the 1:1 fallback here.
pub(crate) fn convert_value_to_amount(value: u64, rate: u64) -> u64 {
    const SCALE: u128 = 100_000_000;
    if rate == 0 {
        return value; // native 1:1
    }
    ((value as u128 * SCALE + rate as u128 - 1) / rate as u128) as u64
}

/// 8 random bytes as hex (16 chars), matching the daemon's `randstr.Hex(8)`.
fn random_swap_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use elements::bitcoin::bip32::ChildNumber;
    use elements::confidential::{self, AssetBlindingFactor, ValueBlindingFactor};
    use elements::hashes::Hash;
    use elements::pset::{Input, Output, PartiallySignedTransaction};
    use elements::{AssetId, OutPoint, Script, Transaction, TxIn, TxOut, TxOutSecrets, Txid};

    use super::{SeqdexSwapRequest, SeqdexSwapRequestOpts};
    use crate::clients::LastUnused;
    use crate::descriptor::Chain;
    use crate::update::{default_blockheader, DownloadTxResult, Update};
    use crate::{Wollet, WolletBuilder, WolletDescriptor, EC};

    // A slip77 descriptor, so blinded outputs to it can be unblinded.
    const DESC: &str = "ct(slip77(ac53739ddde9fdf6bba3dbc51e989b09aa8c9cdce7b7d7eddd49cec86ddf71f7),elwpkh([93970d14/84'/1'/0']tpubDC3BrFCCjXq4jAceV8k6UACxDDJCFb1eb7R7BiKYUGZdNagEhNfJoYtUrRdci9JFs1meiGGModvmNm8PrqkrEjJ6mpt6gA1DRNU8vu7GqXH/<0;1>/*))#u0y4axgs";

    fn asset(b: u8) -> AssetId {
        AssetId::from_slice(&[b; 32]).unwrap()
    }
    const P: u8 = 0x11; // what the taker pays
    const R: u8 = 0x22; // what the taker receives

    /// A wallet that knows its first two receive and change scripts.
    fn wollet() -> Wollet {
        let desc: WolletDescriptor = DESC.parse().unwrap();
        let mut w = WolletBuilder::new(crate::Network::default_regtest(), desc)
            .with_stores(Arc::new(lwk_common::MemoryStore::default()))
            .unwrap()
            .build()
            .unwrap();
        let mut scripts = vec![];
        for i in 0..2 {
            let child = ChildNumber::from_normal_idx(i).unwrap();
            let r = w.address(Some(i)).unwrap().address().script_pubkey();
            let c = w.change(Some(i)).unwrap().address().script_pubkey();
            scripts.push((Chain::External, child, r, None));
            scripts.push((Chain::Internal, child, c, None));
        }
        let update = Update {
            version: 4,
            wollet_status: w.status(),
            new_txs: DownloadTxResult::default(),
            txid_height_new: vec![],
            txid_height_delete: vec![],
            timestamps: vec![],
            scripts_with_blinding_pubkey: scripts,
            tip: default_blockheader(),
            unspent: vec![],
            last_unused: LastUnused::default(),
        };
        w.apply_update(update).unwrap();
        w
    }

    fn explicit_txout(script: Script, a: AssetId, value: u64) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(a),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey: script,
            witness: Default::default(),
        }
    }

    /// Fund the wallet's address `i` with `value` of `a`, explicit or blinded to
    /// the wallet's own key, in a transaction of its own.
    fn fund(w: &mut Wollet, i: u32, a: AssetId, value: u64, blinded: bool, salt: u8) -> OutPoint {
        let addr = w.address(Some(i)).unwrap().address().clone();
        let out = if blinded {
            let spent = [TxOutSecrets::new(
                a,
                AssetBlindingFactor::zero(),
                value,
                ValueBlindingFactor::zero(),
            )];
            TxOut::new_not_last_confidential(&mut rand::thread_rng(), &EC, value, addr, a, &spent)
                .unwrap()
                .0
        } else {
            explicit_txout(addr.script_pubkey(), a, value)
        };
        let tx = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([salt; 32]), 0),
                ..Default::default()
            }],
            output: vec![out],
        };
        let op = OutPoint::new(tx.txid(), 0);
        w.apply_transaction(tx).unwrap();
        op
    }

    fn opts(w: &Wollet, blinded: bool, amount_p: u64, amount_r: u64) -> SeqdexSwapRequestOpts {
        let a = w.address(Some(0)).unwrap().address().clone();
        SeqdexSwapRequestOpts {
            asset_p: asset(P),
            amount_p,
            asset_r: asset(R),
            amount_r,
            receive_address: if blinded { a } else { a.to_unconfidential() },
            fee_asset: asset(P),
            fee_amount: 0,
            fee_rate: 0,
        }
    }

    fn maker_script() -> Script {
        Script::from(vec![
            0x00, 0x14, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        ])
    }

    /// What an honest maker does with the request: adds its own coin of `R`,
    /// takes `amount_p` of `P`, pays the fee in `R`, keeps its change, and
    /// blinds when the request asks for it. Returns the accept PSET.
    fn complete(w: &Wollet, req: &SeqdexSwapRequest) -> PartiallySignedTransaction {
        complete_with(w, req, |_| {})
    }

    /// `complete`, with `tamper` applied to the maker's PSET before it blinds.
    fn complete_with(
        w: &Wollet,
        req: &SeqdexSwapRequest,
        tamper: impl Fn(&mut PartiallySignedTransaction),
    ) -> PartiallySignedTransaction {
        let mut pset: PartiallySignedTransaction = req.transaction.parse().unwrap();
        let maker_in = 10_000u64;
        let fee = 100u64;
        let mut inp = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x99; 32]), 1));
        inp.witness_utxo = Some(explicit_txout(maker_script(), asset(R), maker_in));
        pset.add_input(inp);
        pset.add_output(Output::new_explicit(
            maker_script(),
            req.amount_p,
            asset(P),
            None,
        ));
        pset.add_output(Output::new_explicit(
            maker_script(),
            maker_in - req.amount_r - fee,
            asset(R),
            None,
        ));
        pset.add_output(Output::new_explicit(Script::default(), fee, asset(R), None));
        tamper(&mut pset);
        let blinded = pset.outputs().iter().any(|o| o.blinding_key.is_some());
        if blinded {
            blind(w, req, &mut pset);
        }
        pset
    }

    /// Blind every output carrying a blinding key, as the maker's last blinder does,
    /// from the taker's revealed input secrets and the maker's explicit input.
    fn blind(w: &Wollet, req: &SeqdexSwapRequest, pset: &mut PartiallySignedTransaction) {
        let utxos = w.utxos_map().unwrap();
        let mut secrets: HashMap<usize, TxOutSecrets> = HashMap::new();
        for (i, inp) in pset.inputs().iter().enumerate() {
            let s = match utxos.get(&inp.previous_outpoint()) {
                Some(u) => u.unblinded,
                None => {
                    let o = inp.witness_utxo.as_ref().unwrap();
                    TxOutSecrets::new(
                        o.asset.explicit().unwrap(),
                        AssetBlindingFactor::zero(),
                        o.value.explicit().unwrap(),
                        ValueBlindingFactor::zero(),
                    )
                }
            };
            secrets.insert(i, s);
        }
        let _ = req;
        pset.blind_last(&mut rand::thread_rng(), &EC, &secrets)
            .unwrap();
    }

    fn refused(r: Result<(), crate::Error>, want: &str) {
        let e = r.expect_err("the accept must be refused").to_string();
        assert!(e.contains(want), "refusal {e:?} does not name {want:?}");
    }

    #[test]
    fn honest_blinded_accept_passes() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, true, 1);
        let req = w.seqdex_swap_request(&opts(&w, true, 1_000, 700)).unwrap();
        let acc = complete(&w, &req);
        let tx = acc.extract_tx().unwrap();
        assert!(!tx.output[0].value.is_explicit() && !tx.output[1].value.is_explicit());
        w.seqdex_verify_accept(&req, &acc).unwrap();
    }

    #[test]
    fn maker_leaving_a_blinded_receive_explicit_is_refused() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, false, 1);
        let req = w.seqdex_swap_request(&opts(&w, true, 1_000, 700)).unwrap();
        let mut acc: PartiallySignedTransaction = req.transaction.parse().unwrap();
        // Complete it without blinding anything.
        let mut inp = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x99; 32]), 1));
        inp.witness_utxo = Some(explicit_txout(maker_script(), asset(R), 10_000));
        acc.add_input(inp);
        acc.add_output(Output::new_explicit(maker_script(), 1_000, asset(P), None));
        acc.add_output(Output::new_explicit(maker_script(), 9_200, asset(R), None));
        acc.add_output(Output::new_explicit(Script::default(), 100, asset(R), None));
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "the maker left output 0 explicit, which this wallet asked to receive blinded",
        );
    }

    #[test]
    fn maker_blinding_to_a_foreign_key_is_refused() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, true, 1);
        let req = w.seqdex_swap_request(&opts(&w, true, 1_000, 700)).unwrap();
        let mut acc: PartiallySignedTransaction = req.transaction.parse().unwrap();
        let foreign = elements::secp256k1_zkp::SecretKey::from_slice(&[7u8; 32]).unwrap();
        acc.outputs_mut()[0].blinding_key =
            Some(elements::bitcoin::PublicKey::new(foreign.public_key(&EC)));
        let mut inp = Input::from_prevout(OutPoint::new(Txid::from_byte_array([0x99; 32]), 1));
        inp.witness_utxo = Some(explicit_txout(maker_script(), asset(R), 10_000));
        acc.add_input(inp);
        acc.add_output(Output::new_explicit(maker_script(), 1_000, asset(P), None));
        acc.add_output(Output::new_explicit(maker_script(), 9_200, asset(R), None));
        acc.add_output(Output::new_explicit(Script::default(), 100, asset(R), None));
        blind(&w, &req, &mut acc);
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "output 0 is not blinded to this wallet's key",
        );
    }

    #[test]
    fn maker_short_paying_is_refused() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, true, 1);
        let req = w.seqdex_swap_request(&opts(&w, true, 1_000, 700)).unwrap();
        // One atom less to the taker, one more to the maker's change: a valid
        // transaction that a wallet signing unchecked would broadcast.
        let acc = complete_with(&w, &req, |p| {
            p.outputs_mut()[0].amount = Some(699);
            let maker_change = p.outputs().len() - 2;
            let v = p.outputs()[maker_change].amount.unwrap();
            p.outputs_mut()[maker_change].amount = Some(v + 1);
        });
        refused(
            w.seqdex_verify_accept(&req, &acc),
            &format!(
                "output 0 pays 699 of {} where this wallet asked for 700",
                asset(R)
            ),
        );
        // Or pays the change somewhere else.
        let acc = complete_with(&w, &req, |p| {
            p.outputs_mut()[1].script_pubkey = maker_script()
        });
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "output 1 no longer pays the script this wallet asked for",
        );
        // Or drops the change.
        let mut acc: PartiallySignedTransaction = req.transaction.parse().unwrap();
        acc.remove_output(1);
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "it drops outputs this wallet put in",
        );
    }

    #[test]
    fn maker_touching_the_takers_inputs_is_refused() {
        let mut w = wollet();
        let coin = fund(&mut w, 0, asset(P), 1_500, true, 1);
        let other = fund(&mut w, 1, asset(P), 3_000, true, 2);
        let mut o = opts(&w, true, 1_000, 700);
        o.amount_p = 2_500; // selects the 3,000 coin only
        let req = w.seqdex_swap_request(&o).unwrap();
        let pset: PartiallySignedTransaction = req.transaction.parse().unwrap();
        assert_eq!(pset.inputs()[0].previous_outpoint(), other);

        // Another coin of the wallet added.
        let coin_txout = w.txos_map().unwrap()[&coin].clone();
        let mut acc = complete(&w, &req);
        let mut extra = Input::from_prevout(coin);
        extra.witness_utxo = Some(explicit_txout(coin_txout.script_pubkey, asset(P), 1_500));
        acc.add_input(extra);
        refused(
            w.seqdex_verify_accept(&req, &acc),
            &format!("it spends {coin}, another coin of this wallet"),
        );

        // The wallet's own input signed for less than the whole transaction.
        let mut acc = complete(&w, &req);
        acc.inputs_mut()[0].sighash_type = Some(elements::pset::PsbtSighashType::from_u32(0x83));
        refused(w.seqdex_verify_accept(&req, &acc), "with sighash type 0x83");

        // The wallet's input dropped (replaced by a maker coin).
        let mut acc = complete(&w, &req);
        acc.remove_input(0);
        refused(
            w.seqdex_verify_accept(&req, &acc),
            &format!("it leaves out {other}, which this wallet funded the swap with"),
        );

        // A different lock time.
        let mut acc = complete(&w, &req);
        acc.global.tx_data.fallback_locktime =
            Some(elements::LockTime::from_height(500_000).unwrap());
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "its lock time differs from the request's",
        );
    }

    #[test]
    fn transparent_request_is_explicit_and_spends_explicit_coins() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 2_000, true, 1);
        let explicit_coin = fund(&mut w, 1, asset(P), 1_500, false, 2);
        let req = w.seqdex_swap_request(&opts(&w, false, 1_000, 700)).unwrap();
        let pset: PartiallySignedTransaction = req.transaction.parse().unwrap();
        // Only the explicit coin, though the blinded one is larger.
        assert_eq!(pset.inputs().len(), 1);
        assert_eq!(pset.inputs()[0].previous_outpoint(), explicit_coin);
        assert_eq!(
            req.unblinded_inputs[0].asset_blinder,
            AssetBlindingFactor::zero().to_string()
        );
        // Receive 700 R and change 500 P, both explicit.
        assert_eq!(pset.outputs().len(), 2);
        for o in pset.outputs() {
            assert!(o.blinding_key.is_none() && o.blinder_index.is_none());
        }
        assert_eq!(
            (pset.outputs()[0].asset, pset.outputs()[0].amount),
            (Some(asset(R)), Some(700))
        );
        assert_eq!(
            (pset.outputs()[1].asset, pset.outputs()[1].amount),
            (Some(asset(P)), Some(500))
        );
    }

    #[test]
    fn transparent_request_refuses_blinded_coins() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 5_000, true, 1);
        let e = w
            .seqdex_swap_request(&opts(&w, false, 1_000, 700))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("a transparent receive spends only explicit coins"),
            "{e}"
        );
        assert!(e.contains("0 explicit of the 1000 needed"), "{e}");
        // Not a lack of funds blinded either: the blinded request takes the coin.
        let req = w.seqdex_swap_request(&opts(&w, true, 1_000, 700)).unwrap();
        let pset: PartiallySignedTransaction = req.transaction.parse().unwrap();
        assert!(pset.outputs().iter().all(|o| o.blinding_key.is_some()));
        // And a shortfall that no coin covers stays a plain lack of funds.
        let e = w
            .seqdex_swap_request(&opts(&w, false, 9_000, 700))
            .unwrap_err();
        assert!(matches!(e, crate::Error::InsufficientFunds { .. }), "{e}");
    }

    #[test]
    fn honest_explicit_accept_passes() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, false, 1);
        let req = w.seqdex_swap_request(&opts(&w, false, 1_000, 700)).unwrap();
        let acc = complete(&w, &req);
        w.seqdex_verify_accept(&req, &acc).unwrap();
        let tx = acc.extract_tx().unwrap();
        assert!(tx
            .output
            .iter()
            .all(|o| o.asset.is_explicit() && o.value.is_explicit()));
    }

    #[test]
    fn maker_blinding_an_explicit_receive_is_refused() {
        let mut w = wollet();
        fund(&mut w, 0, asset(P), 1_500, false, 1);
        let req = w.seqdex_swap_request(&opts(&w, false, 1_000, 700)).unwrap();
        let mut acc = complete(&w, &req);
        // The maker blinds the taker's receive output to a key of its own.
        let foreign = elements::secp256k1_zkp::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = elements::bitcoin::PublicKey::new(foreign.public_key(&EC));
        let n = acc.inputs().len() as u32;
        acc.outputs_mut()[0].blinding_key = Some(pk);
        acc.outputs_mut()[0].blinder_index = Some(n - 1);
        blind(&w, &req, &mut acc);
        refused(
            w.seqdex_verify_accept(&req, &acc),
            "the maker blinded output 0, which this wallet asked to receive explicitly",
        );
    }
}
