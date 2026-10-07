//! SEQUENTIA stake records, from a light wallet: which signature a spend of one
//! carries, how it is signed, and the two steps that take a stake out.
//!
//! Four bare scripts hold a staker's standing on chain, and each ends in
//! `<key> OP_CHECKSIG`, so only that key can spend it:
//!
//! * the staking output, [`crate::sequentia_stake_script`];
//! * the unbonding output, [`sequentia_unbond_script`];
//! * the delegation record, [`crate::sequentia_delegation_script`];
//! * the payout record, which the node wallet announces (`announcepayout`).
//!
//! A bare script matches no descriptor, so the wallet's PSET signer never signs
//! a spend of one. The builders here and in [`crate::sequentia_delegation`] do.
//!
//! # Which signature a record spend carries
//!
//! The chain's `pos_records_v2_height` decides, block by block:
//!
//! * below it, the legacy signature hash over the record script, which commits
//!   to no amount;
//! * from it, the segwit-v0 signature hash with the record script as the script
//!   code and the amount spent committed, and a scriptSig with exactly one valid
//!   encoding: one minimal push of a low-S signature.
//!
//! A spend signed for one side is invalid on the other. The wallet therefore
//! signs for the block it expects the spend to enter, the one after its tip
//! ([`StakeRecordSigning::for_next_block`]). A spend signed just below the
//! height and still unconfirmed when the chain reaches it is evicted from the
//! mempool and has to be built again.
//!
//! The height is fixed per chain and no node RPC reports it, so the kit carries
//! it ([`pos_records_v2_height`]): 163,000 on the testnet, block 1 on every
//! other chain. A custom chain started with `-posrecordsv2height` set to
//! something else needs that value passed to
//! [`StakeRecordSigning::for_next_block`] directly.
//!
//! # Unbonding, in two steps
//!
//! A staking output may only be spent into another staking output or into an
//! unbonding output of the same key, losing at most a capped fee on the way
//! ([`build_unbond_tx`]). The unbonding output carries no stake weight. Its
//! coins can be sent to an address ([`build_unbond_claim_tx`]) once the parent
//! chain (Bitcoin) has advanced the unbonding depth past the anchor of the block
//! that created it: 2,016 Bitcoin blocks on the testnet, counted in Sequentia
//! blocks on a chain without anchoring. A claim sent earlier is refused with
//! `bad-unbond-premature`.

use elements::bitcoin::hashes::Hash as _;
use elements::encode::serialize_hex;
use elements::hashes::hash160;
use elements::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSHNUM_1,
    OP_PUSHNUM_16,
};
use elements::script::{Builder, Instruction};
use elements::secp256k1_zkp::{Message, PublicKey, Secp256k1, SecretKey};
use elements::sighash::SighashCache;
use elements::{
    confidential, AssetId, EcdsaSighashType, LockTime, OutPoint, Script, Sequence, Transaction,
    TxIn, TxInWitness, TxOut, TxOutWitness, Txid,
};

use crate::error::Error;

/// The height from which the Sequentia testnet enforces the second generation
/// of stake records (`pos_records_v2_height` in the node's chain parameters).
pub const SEQUENTIA_TESTNET_POS_RECORDS_V2_HEIGHT: u32 = 163_000;

/// The share of a stake, in thousandths, that unbonding may spend on its fee
/// (the node's `POS_UNBOND_MAX_FEE_PERMILLE`).
pub const UNBOND_MAX_FEE_PERMILLE: u64 = 10;

/// The unbonding output's marker, byte for byte the node's `UNBOND_MARKER`.
const UNBOND_MARKER: &[u8; 9] = b"SEQUNBOND";

/// SIGHASH_ALL, as the byte appended to a DER signature.
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// BIP68: the relative lock counts 512-second units rather than blocks.
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// BIP68: the bits of a relative lock that hold its value.
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// The first block height at which `network` signs stake record spends the
/// second-generation way: 163,000 on the Sequentia testnet, 1 on every other
/// chain.
///
/// The testnet is recognised by its whole definition, genesis hash included,
/// so a chain started afresh under the same name falls to the rule every new
/// chain has from its first block.
pub fn pos_records_v2_height(network: &lwk_common::Network) -> u32 {
    if *network == lwk_common::Network::sequentia_testnet() {
        SEQUENTIA_TESTNET_POS_RECORDS_V2_HEIGHT
    } else {
        1
    }
}

/// The signature a spend of a stake record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeRecordSigning {
    /// Below `pos_records_v2_height`: the legacy signature hash over the
    /// record script, which commits to no amount.
    Legacy,
    /// From `pos_records_v2_height`: the segwit-v0 signature hash with the
    /// record script as the script code and the amount spent committed, in a
    /// canonical scriptSig.
    SegwitV0,
}

impl StakeRecordSigning {
    /// The signature a spend needs to be valid in the block at `block_height`.
    /// A `records_v2_height` of 0 means the chain never switches.
    pub fn at_height(block_height: u32, records_v2_height: u32) -> Self {
        if records_v2_height > 0 && block_height >= records_v2_height {
            StakeRecordSigning::SegwitV0
        } else {
            StakeRecordSigning::Legacy
        }
    }

    /// The signature a spend needs to enter the block after `tip_height`, which
    /// is the block a spend built now is meant for.
    pub fn for_next_block(tip_height: u32, records_v2_height: u32) -> Self {
        Self::at_height(tip_height.saturating_add(1), records_v2_height)
    }

    /// [`Self::for_next_block`] with the height `network` switches at.
    pub fn for_network(network: &lwk_common::Network, tip_height: u32) -> Self {
        Self::for_next_block(tip_height, pos_records_v2_height(network))
    }
}

/// The hash a spend of `record_script` at `input_index` signs, under `signing`.
/// `value` is the spent output's value, which only the second generation
/// commits to.
pub fn stake_record_sighash(
    tx: &Transaction,
    input_index: usize,
    record_script: &Script,
    value: confidential::Value,
    signing: StakeRecordSigning,
) -> Result<[u8; 32], Error> {
    if input_index >= tx.input.len() {
        return Err(Error::Generic(format!(
            "input {input_index} is not in a transaction of {} inputs",
            tx.input.len()
        )));
    }
    let mut cache = SighashCache::new(tx);
    let sighash = match signing {
        StakeRecordSigning::Legacy => {
            cache.legacy_sighash(input_index, record_script, EcdsaSighashType::All)
        }
        StakeRecordSigning::SegwitV0 => {
            cache.segwitv0_sighash(input_index, record_script, value, EcdsaSighashType::All)
        }
    };
    Ok(sighash.to_byte_array())
}

/// Sign the spend of a stake record at `input_index` with `secret`, setting
/// the input's scriptSig to the one push the record takes.
///
/// The signature is deterministic (RFC 6979) and low-S, and the push is
/// minimal, which is the one encoding the second generation accepts and is
/// equally valid under the legacy rule. Sign after every input and output is in
/// place: the signature commits to all of them.
pub fn sign_stake_record_input(
    tx: &mut Transaction,
    input_index: usize,
    record_script: &Script,
    value: confidential::Value,
    secret: &SecretKey,
    signing: StakeRecordSigning,
) -> Result<(), Error> {
    let sighash = stake_record_sighash(tx, input_index, record_script, value, signing)?;
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&Message::from_digest(sighash), secret);
    let mut der = signature.serialize_der().to_vec();
    der.push(SIGHASH_ALL_BYTE);
    let input = &mut tx.input[input_index];
    input.script_sig = Builder::new().push_slice(&der).into_script();
    // A record is spent with no witness at all.
    input.witness.script_witness.clear();
    Ok(())
}

/// The canonical unbonding output for `staker_pubkey`, a byte-for-byte mirror
/// of the node's `BuildUnbondScript`:
/// `<"SEQUNBOND"> OP_DROP <staker_pubkey> OP_CHECKSIG`.
pub fn sequentia_unbond_script(staker_pubkey: &[u8]) -> Script {
    Builder::new()
        .push_slice(UNBOND_MARKER)
        .push_opcode(OP_DROP)
        .push_slice(staker_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// The staker key of an unbonding output, or `None` if `script` is not one.
pub fn parse_unbond_script(script: &Script) -> Option<Vec<u8>> {
    let mut ins = script.instructions();
    if ins.next()?.ok()?.push_bytes()? != UNBOND_MARKER.as_slice() {
        return None;
    }
    if ins.next()?.ok()?.op()? != OP_DROP {
        return None;
    }
    let pubkey = ins.next()?.ok()?.push_bytes()?.to_vec();
    if ins.next()?.ok()?.op()? != OP_CHECKSIG || ins.next().is_some() {
        return None;
    }
    if pubkey.len() != 33 || PublicKey::from_slice(&pubkey).is_err() {
        return None;
    }
    Some(pubkey)
}

/// A staking output's script, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStakeScript {
    /// The BIP68 relative lock a spend's input must carry as its sequence.
    pub csv: u32,
    /// The staker key, 33 bytes compressed.
    pub staker_pubkey: Vec<u8>,
    /// Whether the output registers a committee BLS key (data only; it does
    /// not change how the output is spent).
    pub registers_bls_key: bool,
    /// The absolute vesting lock, when the stake has one.
    pub vesting_locktime: Option<u32>,
}

/// Read a staking output's script: `<csv> OP_CHECKSEQUENCEVERIFY OP_DROP`,
/// optionally `<bls key> OP_DROP <proof> OP_DROP`, optionally
/// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP`, then `<pubkey> OP_CHECKSIG`.
///
/// Only the node's canonical encoding is recognised (minimal numbers, a
/// non-zero relative lock with no stray bits, a compressed key), which is what
/// the node counts as stake.
pub fn parse_stake_script(script: &Script) -> Option<ParsedStakeScript> {
    let mut ins = script.instructions().peekable();
    let csv = script_number(&ins.next()?.ok()?)?;
    if csv < 1 || csv > u32::MAX as i64 {
        return None;
    }
    let csv = csv as u32;
    if csv & !(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK) != 0
        || csv & SEQUENCE_LOCKTIME_MASK == 0
    {
        return None;
    }
    if ins.next()?.ok()?.op()? != OP_CSV || ins.next()?.ok()?.op()? != OP_DROP {
        return None;
    }
    let mut push = ins.next()?.ok()?.push_bytes()?.to_vec();
    let mut bls = None;
    if push.len() == 48 {
        if ins.next()?.ok()?.op()? != OP_DROP {
            return None;
        }
        let pop = ins.next()?.ok()?.push_bytes()?.to_vec();
        if pop.len() != 96 || ins.next()?.ok()?.op()? != OP_DROP {
            return None;
        }
        bls = Some((push, pop));
        push = ins.next()?.ok()?.push_bytes()?.to_vec();
    }
    // A vesting lock is told from the key by what follows it, as in the node.
    let mut vesting = None;
    if let Some(Ok(Instruction::Op(op))) = ins.peek() {
        if *op == OP_CLTV {
            ins.next();
            let value = script_number(&Instruction::PushBytes(&push))?;
            if value <= 0 || value > u32::MAX as i64 {
                return None;
            }
            vesting = Some(value as u32);
            if ins.next()?.ok()?.op()? != OP_DROP {
                return None;
            }
            push = ins.next()?.ok()?.push_bytes()?.to_vec();
        }
    }
    if ins.next()?.ok()?.op()? != OP_CHECKSIG || ins.next().is_some() {
        return None;
    }
    if push.len() != 33 || PublicKey::from_slice(&push).is_err() {
        return None;
    }
    // Rebuild it canonically: anything the builder would not have written, a
    // non-minimal number above all, is not a stake the node counts.
    let mut b = Builder::new()
        .push_int(csv as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP);
    if let Some((key, pop)) = &bls {
        b = b
            .push_slice(key)
            .push_opcode(OP_DROP)
            .push_slice(pop)
            .push_opcode(OP_DROP);
    }
    if let Some(lock) = vesting {
        b = b
            .push_int(lock as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP);
    }
    let canonical = b.push_slice(&push).push_opcode(OP_CHECKSIG).into_script();
    if canonical != *script {
        return None;
    }
    Some(ParsedStakeScript {
        csv,
        staker_pubkey: push,
        registers_bls_key: bls.is_some(),
        vesting_locktime: vesting,
    })
}

/// A script number: `OP_1`..`OP_16` or a push of up to five bytes. Minimality
/// is checked by the caller's canonical rebuild.
fn script_number(ins: &Instruction<'_>) -> Option<i64> {
    match ins {
        Instruction::Op(op)
            if op.into_u8() >= OP_PUSHNUM_1.into_u8()
                && op.into_u8() <= OP_PUSHNUM_16.into_u8() =>
        {
            Some((op.into_u8() - OP_PUSHNUM_1.into_u8() + 1) as i64)
        }
        Instruction::PushBytes(data) if !data.is_empty() && data.len() <= 5 => {
            let mut value: i64 = 0;
            for (i, byte) in data.iter().enumerate() {
                value |= (*byte as i64) << (8 * i);
            }
            if data[data.len() - 1] & 0x80 != 0 {
                return None; // negative: never a lock
            }
            Some(value)
        }
        _ => None,
    }
}

/// The most a stake may pay in fees out of itself on its way to unbonding: 1%
/// of the staked total, rounded the way the node rounds it.
pub fn unbond_fee_cap(staked_total: u64) -> u64 {
    staked_total / 1000 * UNBOND_MAX_FEE_PERMILLE
}

/// One staking output of the wallet's staker key.
#[derive(Debug, Clone)]
pub struct StakeOutput {
    /// The transaction that created it.
    pub txid: Txid,
    /// Its index there.
    pub vout: u32,
    /// Its explicit value, in atoms of the Sequence token.
    pub value: u64,
    /// Its script, as found on chain. It names the relative lock the spend's
    /// sequence must carry.
    pub script_pubkey: Script,
}

/// Everything needed to move stake into an unbonding output.
#[derive(Debug, Clone)]
pub struct UnbondPlan {
    /// The staking outputs to unbond, all of the staker key below, each past
    /// its relative lock.
    pub stakes: Vec<StakeOutput>,
    /// The Sequence token's asset id.
    pub asset: AssetId,
    /// The staker key's secret.
    pub staker_secret: SecretKey,
    /// The network fee, taken out of the stake; at most
    /// [`unbond_fee_cap`] of the staked total.
    pub fee_atoms: u64,
    /// nLockTime, normally the current tip.
    pub locktime: u32,
    /// The signature the next block wants ([`StakeRecordSigning::for_next_block`]).
    pub signing: StakeRecordSigning,
}

/// Build and sign the first step of unbonding: every staking output in `plan`
/// spent into one unbonding output of the same key, less the fee. Returns
/// `(raw_hex, txid)`.
///
/// The stake stops counting when this confirms; the coins wait in the
/// unbonding output until [`build_unbond_claim_tx`] can send them on.
pub fn build_unbond_tx(plan: &UnbondPlan) -> Result<(String, Txid), Error> {
    if plan.stakes.is_empty() {
        return Err(Error::Generic("no staking outputs to unbond".into()));
    }
    let secp = Secp256k1::signing_only();
    let staker = PublicKey::from_secret_key(&secp, &plan.staker_secret)
        .serialize()
        .to_vec();

    let mut total: u64 = 0;
    let mut inputs = Vec::with_capacity(plan.stakes.len());
    for stake in &plan.stakes {
        let parsed = parse_stake_script(&stake.script_pubkey).ok_or_else(|| {
            Error::Generic(format!(
                "{}:{} is not a staking output",
                stake.txid, stake.vout
            ))
        })?;
        if parsed.staker_pubkey != staker {
            return Err(Error::Generic(format!(
                "{}:{} is staked to another key; this wallet's staker key cannot unbond it",
                stake.txid, stake.vout
            )));
        }
        if parsed.vesting_locktime.is_some() {
            return Err(Error::Generic(format!(
                "{}:{} carries a vesting lock; unbond it from the node wallet (withdrawstake)",
                stake.txid, stake.vout
            )));
        }
        total = total
            .checked_add(stake.value)
            .ok_or_else(|| Error::Generic("staked total overflows".into()))?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(stake.txid, stake.vout),
            is_pegin: false,
            script_sig: Script::new(),
            // BIP68: the input must carry the script's own relative lock.
            sequence: Sequence::from_consensus(parsed.csv),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        });
    }

    let cap = unbond_fee_cap(total);
    if plan.fee_atoms > cap {
        return Err(Error::Generic(format!(
            "a {} atom fee is more than unbonding may take out of the stake: {} atoms, 1% of the {} staked",
            plan.fee_atoms, cap, total
        )));
    }
    if plan.fee_atoms >= total {
        return Err(Error::Generic(format!(
            "the stake ({total} atoms) does not cover the {} atom fee",
            plan.fee_atoms
        )));
    }

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(plan.locktime),
        input: inputs,
        output: vec![
            explicit_output(
                plan.asset,
                total - plan.fee_atoms,
                sequentia_unbond_script(&staker),
            ),
            TxOut::new_fee(plan.fee_atoms, plan.asset),
        ],
    };
    for (i, stake) in plan.stakes.iter().enumerate() {
        sign_stake_record_input(
            &mut tx,
            i,
            &stake.script_pubkey,
            confidential::Value::Explicit(stake.value),
            &plan.staker_secret,
            plan.signing,
        )?;
    }
    let txid = tx.txid();
    Ok((serialize_hex(&tx), txid))
}

/// One unbonding output of the wallet's staker key.
#[derive(Debug, Clone)]
pub struct UnbondingOutput {
    /// The transaction that created it (the first step of unbonding).
    pub txid: Txid,
    /// Its index there.
    pub vout: u32,
    /// Its explicit value, in atoms of the Sequence token.
    pub value: u64,
}

/// Everything needed to send unbonded coins to an address.
#[derive(Debug, Clone)]
pub struct UnbondClaimPlan {
    /// The unbonding outputs to claim, all of the staker key below, each past
    /// the unbonding depth.
    pub unbonding: Vec<UnbondingOutput>,
    /// The Sequence token's asset id.
    pub asset: AssetId,
    /// The staker key's secret.
    pub staker_secret: SecretKey,
    /// Where the coins go.
    pub destination: Script,
    /// The network fee, taken out of the coins claimed.
    pub fee_atoms: u64,
    /// The dust floor the claimed output must clear to relay. 0 disables it.
    pub dust_floor: u64,
    /// nLockTime, normally the current tip.
    pub locktime: u32,
    /// The signature the next block wants ([`StakeRecordSigning::for_next_block`]).
    pub signing: StakeRecordSigning,
}

/// Build and sign the second step of unbonding: every unbonding output in
/// `plan` sent to `destination`, less the fee. Returns `(raw_hex, txid)`.
///
/// Valid only once the parent chain has advanced the unbonding depth past the
/// anchor of the block that created each output; the node refuses an earlier
/// claim with `bad-unbond-premature`.
pub fn build_unbond_claim_tx(plan: &UnbondClaimPlan) -> Result<(String, Txid), Error> {
    if plan.unbonding.is_empty() {
        return Err(Error::Generic("no unbonding outputs to claim".into()));
    }
    let secp = Secp256k1::signing_only();
    let staker = PublicKey::from_secret_key(&secp, &plan.staker_secret)
        .serialize()
        .to_vec();
    let script = sequentia_unbond_script(&staker);

    let mut total: u64 = 0;
    for u in &plan.unbonding {
        total = total
            .checked_add(u.value)
            .ok_or_else(|| Error::Generic("unbonded total overflows".into()))?;
    }
    if plan.fee_atoms >= total {
        return Err(Error::Generic(format!(
            "the unbonded coins ({total} atoms) do not cover the {} atom fee",
            plan.fee_atoms
        )));
    }
    let out_value = total - plan.fee_atoms;
    if out_value < plan.dust_floor {
        return Err(Error::Generic(format!(
            "this would leave {out_value} atoms, below the {} the network will relay",
            plan.dust_floor
        )));
    }

    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(plan.locktime),
        input: plan
            .unbonding
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint::new(u.txid, u.vout),
                is_pegin: false,
                script_sig: Script::new(),
                // No relative lock: the depth is judged from the anchors.
                // Replaceable, so a fee that turns out too low can be bumped.
                sequence: Sequence::from_consensus(0xffff_fffd),
                asset_issuance: Default::default(),
                witness: TxInWitness::default(),
            })
            .collect(),
        output: vec![
            explicit_output(plan.asset, out_value, plan.destination.clone()),
            TxOut::new_fee(plan.fee_atoms, plan.asset),
        ],
    };
    for (i, u) in plan.unbonding.iter().enumerate() {
        sign_stake_record_input(
            &mut tx,
            i,
            &script,
            confidential::Value::Explicit(u.value),
            &plan.staker_secret,
            plan.signing,
        )?;
    }
    let txid = tx.txid();
    Ok((serialize_hex(&tx), txid))
}

/// Everything needed to create a delegation or payout record from a coin of
/// its key.
#[derive(Debug, Clone)]
pub struct RecordCreatePlan {
    /// The key's coin: an explicit Sequence token output paying the key's
    /// `P2WPKH` ([`key_coin_script`]).
    pub coin_txid: Txid,
    /// Its index in that transaction.
    pub coin_vout: u32,
    /// Its explicit value.
    pub coin_value: u64,
    /// The Sequence token's asset id; the coin and the record hold it.
    pub asset: AssetId,
    /// The key's secret: a delegation record's controller, a payout record's
    /// signer.
    pub key_secret: SecretKey,
    /// The record to create. It must name the key; the node refuses one that
    /// does not (`bad-delegation-unauthorized`, `bad-payout-unauthorized`).
    pub record_script: Script,
    /// The record's own value, recoverable when it is spent.
    pub record_value: u64,
    /// Where whatever the coin holds beyond the record and the fee goes.
    /// Unused when nothing is left over.
    pub change_spk: Script,
    /// Network fee, taken out of the coin.
    pub fee_atoms: u64,
    /// The dust floor the record and any change must clear to relay. 0
    /// disables it.
    pub dust_floor: u64,
    /// nLockTime, normally the current tip.
    pub locktime: u32,
}

/// Build and sign the transaction that creates a record, funded by a coin of
/// its key and nothing else. Returns `(raw_hex, txid)`.
///
/// Spending a coin only the key can spend is what authorises the record. The
/// coin is a key-path `P2WPKH` spend, signed the same way in either generation
/// of stake records; the transaction may spend it unconfirmed, so the payment
/// that created it ([`crate::TxBuilder::add_record_authorization`]) and the
/// record are mined together.
pub fn build_record_create_tx(plan: &RecordCreatePlan) -> Result<(String, Txid), Error> {
    let secp = Secp256k1::signing_only();
    let key = PublicKey::from_secret_key(&secp, &plan.key_secret)
        .serialize()
        .to_vec();
    let spent = plan
        .record_value
        .checked_add(plan.fee_atoms)
        .ok_or_else(|| Error::Generic("record value and fee overflow".into()))?;
    if spent > plan.coin_value {
        return Err(Error::Generic(format!(
            "the key's coin holds {} atoms, which does not cover a {} atom record and its {} atom fee",
            plan.coin_value, plan.record_value, plan.fee_atoms
        )));
    }
    if plan.record_value < plan.dust_floor {
        return Err(Error::Generic(format!(
            "a {} atom record is below the {} the network will relay",
            plan.record_value, plan.dust_floor
        )));
    }
    let change = plan.coin_value - spent;
    if change > 0 && change < plan.dust_floor {
        return Err(Error::Generic(format!(
            "this would leave {change} atoms of change, below the {} the network will relay; put them into the record or the fee",
            plan.dust_floor
        )));
    }

    let mut output = vec![explicit_output(
        plan.asset,
        plan.record_value,
        plan.record_script.clone(),
    )];
    if change > 0 {
        output.push(explicit_output(plan.asset, change, plan.change_spk.clone()));
    }
    output.push(TxOut::new_fee(plan.fee_atoms, plan.asset));
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(plan.locktime),
        input: vec![TxIn {
            previous_output: OutPoint::new(plan.coin_txid, plan.coin_vout),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_fffd),
            asset_issuance: Default::default(),
            witness: TxInWitness::default(),
        }],
        output,
    };

    // P2WPKH: the segwit-v0 hash over the P2PKH script code of the key hash,
    // committing to the coin's value; witness <signature> <pubkey>.
    let pkh = hash160::Hash::hash(&key).to_byte_array();
    let script_code = Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(&pkh)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let sighash = SighashCache::new(&tx).segwitv0_sighash(
        0,
        &script_code,
        confidential::Value::Explicit(plan.coin_value),
        EcdsaSighashType::All,
    );
    let signature = secp.sign_ecdsa(
        &Message::from_digest(sighash.to_byte_array()),
        &plan.key_secret,
    );
    let mut der = signature.serialize_der().to_vec();
    der.push(SIGHASH_ALL_BYTE);
    tx.input[0].witness.script_witness = vec![der, key];

    let txid = tx.txid();
    Ok((serialize_hex(&tx), txid))
}

/// The `P2WPKH` script of a compressed key: the kind of coin of the key a
/// delegation record's transaction spends to show the key authorised it.
pub fn key_coin_script(compressed_pubkey: &[u8]) -> Script {
    let pkh = hash160::Hash::hash(compressed_pubkey).to_byte_array();
    Builder::new().push_int(0).push_slice(&pkh).into_script()
}

/// The explicit `asset` outputs of `tx` paying [`key_coin_script`] of
/// `compressed_pubkey`, as `(vout, value)`.
pub fn find_key_coins(
    tx: &Transaction,
    compressed_pubkey: &[u8],
    asset: AssetId,
) -> Vec<(u32, u64)> {
    let script = key_coin_script(compressed_pubkey);
    tx.output
        .iter()
        .enumerate()
        .filter(|(_, out)| out.script_pubkey == script)
        .filter_map(|(vout, out)| match (out.asset, out.value) {
            (confidential::Asset::Explicit(a), confidential::Value::Explicit(v)) if a == asset => {
                Some((vout as u32, v))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use elements::hex::{FromHex, ToHex};

    fn key(byte: u8) -> (SecretKey, Vec<u8>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk.serialize().to_vec())
    }

    #[test]
    fn signing_follows_the_height_of_the_next_block() {
        let fork = SEQUENTIA_TESTNET_POS_RECORDS_V2_HEIGHT;
        // The tip below the fork's parent signs legacy; the fork's parent is the
        // tip from which the next block is the first second-generation one.
        assert_eq!(
            StakeRecordSigning::for_next_block(fork - 2, fork),
            StakeRecordSigning::Legacy
        );
        assert_eq!(
            StakeRecordSigning::for_next_block(fork - 1, fork),
            StakeRecordSigning::SegwitV0
        );
        assert_eq!(
            StakeRecordSigning::for_next_block(fork, fork),
            StakeRecordSigning::SegwitV0
        );
        // 0 is "never", as in the node.
        assert_eq!(
            StakeRecordSigning::for_next_block(u32::MAX, 0),
            StakeRecordSigning::Legacy
        );
        // A fresh chain has it from block 1, so from its genesis tip.
        assert_eq!(
            StakeRecordSigning::for_next_block(0, 1),
            StakeRecordSigning::SegwitV0
        );
    }

    #[test]
    fn the_fork_height_is_per_chain() {
        let testnet = lwk_common::Network::sequentia_testnet();
        assert_eq!(pos_records_v2_height(&testnet), 163_000);
        assert_eq!(
            StakeRecordSigning::for_network(&testnet, 162_998),
            StakeRecordSigning::Legacy
        );
        assert_eq!(
            StakeRecordSigning::for_network(&testnet, 162_999),
            StakeRecordSigning::SegwitV0
        );
        let regtest = lwk_common::Network::default_regtest();
        assert_eq!(pos_records_v2_height(&regtest), 1);
        assert_eq!(
            StakeRecordSigning::for_network(&regtest, 0),
            StakeRecordSigning::SegwitV0
        );
    }

    #[test]
    fn unbond_script_matches_the_nodes_layout() {
        let (_, pk) = key(1);
        let script = sequentia_unbond_script(&pk);
        let expected =
            format!("09{}75 21{}ac", UNBOND_MARKER.to_hex(), pk.to_hex()).replace(' ', "");
        assert_eq!(script.as_bytes().to_hex(), expected);
        assert_eq!(parse_unbond_script(&script), Some(pk.clone()));
        assert!(parse_unbond_script(&crate::sequentia_stake_script(&pk, 5)).is_none());
    }

    #[test]
    fn stake_scripts_parse_back() {
        let (_, pk) = key(2);
        for csv in [
            1u32,
            5,
            16,
            17,
            127,
            128,
            255,
            43_200,
            65_535,
            SEQUENCE_LOCKTIME_TYPE_FLAG | 7,
        ] {
            let parsed = parse_stake_script(&crate::sequentia_stake_script(&pk, csv))
                .unwrap_or_else(|| panic!("csv {csv} parses"));
            assert_eq!(parsed.csv, csv);
            assert_eq!(parsed.staker_pubkey, pk);
            assert!(!parsed.registers_bls_key);
            assert_eq!(parsed.vesting_locktime, None);
        }
        // With a committee registration and a vesting lock, as the node builds it.
        let full = Builder::new()
            .push_int(10)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_slice(&[7u8; 48])
            .push_opcode(OP_DROP)
            .push_slice(&[8u8; 96])
            .push_opcode(OP_DROP)
            .push_int(200_000)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_slice(&pk)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let parsed = parse_stake_script(&full).unwrap();
        assert_eq!(parsed.csv, 10);
        assert!(parsed.registers_bls_key);
        assert_eq!(parsed.vesting_locktime, Some(200_000));
    }

    #[test]
    fn non_canonical_stake_scripts_are_not_stake() {
        let (_, pk) = key(3);
        // csv 5 pushed as a one-byte push instead of OP_5.
        let non_minimal =
            Script::from(Vec::<u8>::from_hex(&format!("0105b27521{}ac", pk.to_hex())).unwrap());
        assert!(parse_stake_script(&non_minimal).is_none());
        // The disable flag is a stray bit.
        assert!(parse_stake_script(&crate::sequentia_stake_script(&pk, (1 << 31) | 5)).is_none());
        // A zero relative lock.
        assert!(parse_stake_script(&crate::sequentia_stake_script(
            &pk,
            SEQUENCE_LOCKTIME_TYPE_FLAG
        ))
        .is_none());
        assert!(parse_stake_script(&sequentia_unbond_script(&pk)).is_none());
    }

    fn stake(value: u64, csv: u32, pk: &[u8]) -> StakeOutput {
        StakeOutput {
            txid: Txid::from_slice(&[4u8; 32]).unwrap(),
            vout: 0,
            value,
            script_pubkey: crate::sequentia_stake_script(pk, csv),
        }
    }

    #[test]
    fn unbond_moves_the_stake_to_its_own_unbonding_output() {
        let (sk, pk) = key(5);
        let plan = UnbondPlan {
            stakes: vec![stake(4_000_000_000_000, 43_200, &pk)],
            asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
            staker_secret: sk,
            fee_atoms: 1_000,
            locktime: 160_000,
            signing: StakeRecordSigning::SegwitV0,
        };
        let (raw, _) = build_unbond_tx(&plan).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.version, 2);
        assert_eq!(
            tx.input[0].sequence.to_consensus_u32(),
            43_200,
            "the input carries the script's lock"
        );
        assert_eq!(tx.output[0].script_pubkey, sequentia_unbond_script(&pk));
        assert_eq!(
            tx.output[0].value,
            confidential::Value::Explicit(4_000_000_000_000 - 1_000)
        );
        assert!(tx.output[1].is_fee());
        // The signature is one push and satisfies the second-generation hash.
        let sighash = stake_record_sighash(
            &tx,
            0,
            &plan.stakes[0].script_pubkey,
            confidential::Value::Explicit(plan.stakes[0].value),
            StakeRecordSigning::SegwitV0,
        )
        .unwrap();
        verify_single_push(&tx, 0, &sighash, &pk);
    }

    #[test]
    fn unbond_matches_the_nodes_signed_vector() {
        // Built and signed by the node's own test framework
        // (`PosRecordSignatureHash`, second generation, RFC 6979 low-S): the
        // kit must produce the same stake script, hash and transaction.
        let (sk, pk) = key(5);
        let script = crate::sequentia_stake_script(&pk, 43_200);
        assert_eq!(
            script.as_bytes().to_hex(),
            "03c0a800b275210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7ac"
        );
        let plan = UnbondPlan {
            stakes: vec![stake(4_000_000_000_000, 43_200, &pk)],
            asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
            staker_secret: sk,
            fee_atoms: 1_000,
            locktime: 160_000,
            signing: StakeRecordSigning::SegwitV0,
        };
        let (raw, _) = build_unbond_tx(&plan).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        let sighash = stake_record_sighash(
            &tx,
            0,
            &script,
            confidential::Value::Explicit(4_000_000_000_000),
            StakeRecordSigning::SegwitV0,
        )
        .unwrap();
        assert_eq!(
            sighash.to_hex(),
            "881d9a78e3a5631bf22c2593359a6dfb5807e3468cc1f517054cbcccb7f4667a"
        );
        assert_eq!(
            raw,
            "0200000000010404040404040404040404040404040404040404040404040404040404040404000000004847304402207e24ad7a9754c17e3d3384ed67f803352595d7268918c08d7eaca3b9a41cd38b022061e52ba1a3aac59d8700f8c87940dae5bc950a0af40b4a5cfcfc348d3ed056a401c0a800000201030303030303030303030303030303030303030303030303030303030303030301000003a352943c18002e09534551554e424f4e4475210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7ac0103030303030303030303030303030303030303030303030303030303030303030100000000000003e8000000710200"
        );
    }

    #[test]
    fn unbond_refuses_a_fee_above_the_cap_and_another_key() {
        let (sk, pk) = key(6);
        let (_, other) = key(7);
        let mut plan = UnbondPlan {
            stakes: vec![stake(100_000, 5, &pk)],
            asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
            staker_secret: sk,
            fee_atoms: 1_001,
            locktime: 0,
            signing: StakeRecordSigning::SegwitV0,
        };
        assert_eq!(unbond_fee_cap(100_000), 1_000);
        let e = build_unbond_tx(&plan).unwrap_err().to_string();
        assert!(e.contains("1%"), "unexpected error: {e}");
        plan.fee_atoms = 1_000;
        assert!(build_unbond_tx(&plan).is_ok());
        plan.stakes = vec![stake(100_000, 5, &other)];
        assert!(build_unbond_tx(&plan)
            .unwrap_err()
            .to_string()
            .contains("another key"));
    }

    #[test]
    fn claim_spends_the_unbonding_outputs_to_the_destination() {
        let (sk, pk) = key(8);
        let dest = key_coin_script(&pk);
        let plan = UnbondClaimPlan {
            unbonding: vec![
                UnbondingOutput {
                    txid: Txid::from_slice(&[5u8; 32]).unwrap(),
                    vout: 0,
                    value: 70_000,
                },
                UnbondingOutput {
                    txid: Txid::from_slice(&[6u8; 32]).unwrap(),
                    vout: 0,
                    value: 30_000,
                },
            ],
            asset: AssetId::from_slice(&[3u8; 32]).unwrap(),
            staker_secret: sk,
            destination: dest.clone(),
            fee_atoms: 500,
            dust_floor: 1_000,
            locktime: 9,
            signing: StakeRecordSigning::Legacy,
        };
        let (raw, _) = build_unbond_claim_tx(&plan).unwrap();
        let tx: Transaction =
            elements::encode::deserialize(&Vec::<u8>::from_hex(&raw).unwrap()).unwrap();
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output[0].script_pubkey, dest);
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(99_500));
        for i in 0..2 {
            let sighash = stake_record_sighash(
                &tx,
                i,
                &sequentia_unbond_script(&pk),
                confidential::Value::Explicit(plan.unbonding[i].value),
                StakeRecordSigning::Legacy,
            )
            .unwrap();
            verify_single_push(&tx, i, &sighash, &pk);
        }
    }

    #[test]
    fn find_key_coins_reads_explicit_payments_to_the_key() {
        let (_, pk) = key(9);
        let asset = AssetId::from_slice(&[3u8; 32]).unwrap();
        let other = AssetId::from_slice(&[4u8; 32]).unwrap();
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                explicit_output(asset, 5, Script::new()),
                explicit_output(asset, 2_000, key_coin_script(&pk)),
                explicit_output(other, 3_000, key_coin_script(&pk)),
            ],
        };
        assert_eq!(find_key_coins(&tx, &pk, asset), vec![(1, 2_000)]);
    }

    /// The scriptSig is exactly one minimal push of a low-S DER signature with
    /// SIGHASH_ALL, verifying against `sighash` under `pk`.
    pub(crate) fn verify_single_push(tx: &Transaction, i: usize, sighash: &[u8; 32], pk: &[u8]) {
        let mut ins = tx.input[i].script_sig.instructions_minimal();
        let push = ins.next().unwrap().unwrap().push_bytes().unwrap().to_vec();
        assert!(ins.next().is_none(), "one push and nothing else");
        assert_eq!(
            tx.input[i].script_sig.len(),
            push.len() + 1,
            "a direct push"
        );
        assert_eq!(*push.last().unwrap(), SIGHASH_ALL_BYTE);
        let mut sig =
            elements::secp256k1_zkp::ecdsa::Signature::from_der(&push[..push.len() - 1]).unwrap();
        let normalized = {
            let mut s = sig;
            s.normalize_s();
            s
        };
        assert_eq!(sig, normalized, "low-S");
        sig.normalize_s();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(*sighash),
                &sig,
                &PublicKey::from_slice(pk).unwrap(),
            )
            .expect("the signature satisfies the record");
        assert!(tx.input[i].witness.script_witness.is_empty());
    }
}
