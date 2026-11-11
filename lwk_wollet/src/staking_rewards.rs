//! SEQUENTIA staking rewards: which coins a staker was PAID, and which of them
//! to convert.
//!
//! Layers 1 and 2 of reward auto-conversion, as specified in the node repo's
//! `doc/sequentia/reward-autoconvert-design.md`. Both are **pure**: attribution
//! is a function of the wallet's own transactions, and policy is a function of
//! attribution plus a quote from the book. Nothing here touches the network, so
//! the web wallet, the browser extension and Ambra share one implementation of
//! the two decisions that must not differ between them - which coins are
//! rewards, and which of them to sell.
//!
//! # Why attribution is not obvious
//!
//! Sequentia has no block subsidy: a staker earns the transaction fees of the
//! blocks it produces, and under the open fee market those arrive in whichever
//! assets the payers chose - one coinbase output per asset. There are exactly
//! two shapes a reward can take, because there are exactly two ways the
//! consensus rules pay a staker:
//!
//! * a **coinbase output the wallet owns**, which is the leader's own reward
//!   (`solo`), a pool paying the address it committed to (`direct`), or a
//!   pool's per-block draw landing on this wallet (`lottery`);
//! * an output the wallet owns in a **pot claim**, paid to `P2WPKH(controller)`
//!   by `claimpoolrewards` under a `split` policy.
//!
//! The second is recognised by the payee being a *staking* key and the
//! transaction not being one the wallet sent - which is what excludes a
//! delegator's own withdrawal or re-pointing, since those pay back to the same
//! key. This mirrors the node's `liststakingrewards` rule for rule; the two are
//! pinned by the shared fixtures in the tests below.

use std::collections::{BTreeMap, HashMap, HashSet};

use elements::{AssetId, OutPoint, Script};

/// Sequentia's coinbase maturity, in blocks.
///
/// NOT Bitcoin's 100. COINBASE_MATURITY is a number of BLOCKS, so what it
/// protects drifts with the cadence: 100 blocks at Bitcoin's 600 seconds is
/// 16h40m, while the same 100 on a 60-second chain is 100 minutes -- a tenth of
/// the protection. Sequentia holds the WALL-CLOCK figure equal to Bitcoin's
/// instead of the block count, which at 60s means 1,000 blocks. It matters more
/// here than on Bitcoin, because Sequentia has no block subsidy and the coinbase
/// carries the producer's fee income rather than new issuance.
///
/// A wallet that used 100 here would call a reward spendable 900 blocks early
/// and then build a transaction the chain rejects. That is exactly what every
/// light wallet did until a node running against the live testnet reported 941
/// blocks to maturity on a reward with 60 confirmations.
pub const SEQUENTIA_COINBASE_MATURITY: u32 = 1000;

/// Which of the four ways a staker gets paid produced this coin.
///
/// Informational only: nothing in policy or execution branches on it. A staker
/// wants to see it, and telling `solo` from `lottery` is the difference between
/// "I produced a block" and "my pool's draw came up".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RewardSource {
    /// This wallet's own key was the elected leader and the coinbase paid it.
    Solo,
    /// A pool paid the address it committed to under a `direct` payout policy.
    Direct,
    /// A pool's per-block lottery draw landed on this wallet's stake.
    Lottery,
    /// A share of a pool's pot, distributed by a claim under a `split` policy.
    Split,
}

impl RewardSource {
    /// The one string every RPC, wallet and board prints for this source.
    pub fn as_str(&self) -> &'static str {
        match self {
            RewardSource::Solo => "solo",
            RewardSource::Direct => "direct",
            RewardSource::Lottery => "lottery",
            RewardSource::Split => "split",
        }
    }
}

/// One coin this wallet was paid for staking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingReward {
    /// The coin itself.
    pub outpoint: OutPoint,
    /// The asset it was paid in - whichever the block's fee payers chose.
    pub asset: AssetId,
    /// How much, in that asset's atoms.
    pub value: u64,
    /// Which of the four ways of being paid produced it.
    pub source: RewardSource,
    /// `None` while unconfirmed.
    pub height: Option<u32>,
    /// Blocks left before the coin is spendable; 0 when it already is. Only a
    /// coinbase has one - a pot claim is an ordinary output and matures at once.
    pub blocks_to_maturity: u32,
    /// Whether this wallet has already spent it.
    pub spent: bool,
}

impl StakingReward {
    /// Whether the coin is spendable yet.
    pub fn mature(&self) -> bool {
        self.blocks_to_maturity == 0
    }

    /// Eligible to be converted: matured, still ours, still unspent.
    pub fn convertible(&self) -> bool {
        self.mature() && !self.spent
    }
}

/// One output of one wallet transaction, as attribution needs to see it.
///
/// `asset` and `value` are the UNBLINDED values. An output the wallet cannot
/// unblind is not attributable and the caller passes `None` - consensus only
/// ever creates explicit coinbase and pot-claim outputs, so this discards
/// nothing real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedOutput {
    /// Index of the output in its transaction.
    pub vout: u32,
    /// The script it pays. This is what tells a reward from an ordinary receive.
    pub script_pubkey: Script,
    /// The unblinded asset.
    pub asset: AssetId,
    /// The unblinded amount, in atoms.
    pub value: u64,
    /// Whether this wallet has already spent it.
    pub spent: bool,
}

/// A wallet transaction, reduced to the facts attribution depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFacts {
    /// The transaction's id.
    pub txid: elements::Txid,
    /// Height it confirmed at; `None` while it is still in the mempool.
    pub height: Option<u32>,
    /// Whether it is a coinbase, which is where every non-pool reward arrives.
    pub is_coinbase: bool,
    /// Whether this wallet sent it. A coinbase is never anyone's to send.
    pub from_me: bool,
    /// Only the outputs this wallet owns AND can unblind.
    pub owned_outputs: Vec<OwnedOutput>,
}

/// The keys a reward can be paid on, keyed by the `P2WPKH` script that pays
/// them: every key the stake registry knows as a staker whose script this
/// wallet can spend, every key it holds a stake output for, and every
/// controller it holds a delegation record for.
///
/// The registry route is the one that matters in practice - a node configured
/// with `-staker=` holds weight without the wallet holding a stake output at
/// all, which is how the committee runs.
pub type StakingScripts = HashMap<Script, elements::secp256k1_zkp::PublicKey>;

/// Whether a delegation to this signer is (or was) in force, used only to tell
/// `lottery` from `solo`. Both are coinbase payments to a staking key; the
/// difference is whether that key was signing for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerRelation {
    /// The key signs for itself: a coinbase paying it is its own block's reward.
    SelfSigning,
    /// The key's weight is lent to a pool: a coinbase paying it is a draw.
    Delegated,
}

/// Every staking reward in `txs`, newest first.
///
/// Pure. `coinbase_maturity` is the chain's `COINBASE_MATURITY` (100), and
/// `tip_height` the height maturity is judged against.
///
/// ```text
/// coinbase && owned(out)                    -> solo | direct | lottery
/// !coinbase && !from_me && owned(out)
///     && out pays P2WPKH(a staking key)     -> split
/// ```
pub fn attribute_rewards(
    txs: &[TxFacts],
    staking_scripts: &StakingScripts,
    signer_relation: &HashMap<elements::secp256k1_zkp::PublicKey, SignerRelation>,
    tip_height: u32,
    coinbase_maturity: u32,
) -> Vec<StakingReward> {
    let mut out = Vec::new();

    for tx in txs {
        // Our own spending is never a reward. A coinbase is never ours to send,
        // so the test is only meaningful off the coinbase path.
        if !tx.is_coinbase && tx.from_me {
            continue;
        }

        for o in &tx.owned_outputs {
            if o.value == 0 {
                continue; // an empty block's coinbase pays nothing
            }
            let staking_key = staking_scripts.get(&o.script_pubkey);
            if !tx.is_coinbase && staking_key.is_none() {
                continue;
            }

            let source = match (tx.is_coinbase, staking_key) {
                (false, Some(_)) => RewardSource::Split,
                (true, Some(k)) => match signer_relation.get(k) {
                    Some(SignerRelation::Delegated) => RewardSource::Lottery,
                    _ => RewardSource::Solo,
                },
                // A coinbase paying some other script of ours is a pool paying
                // the address it committed to under a direct policy.
                (true, None) => RewardSource::Direct,
                // Excluded above: a non-coinbase output not on a staking key is
                // an ordinary receive, not a reward.
                (false, None) => continue,
            };

            let blocks_to_maturity = if tx.is_coinbase {
                blocks_to_maturity(tx.height, tip_height, coinbase_maturity)
            } else {
                0
            };

            out.push(StakingReward {
                outpoint: OutPoint::new(tx.txid, o.vout),
                asset: o.asset,
                value: o.value,
                source,
                height: tx.height,
                blocks_to_maturity,
                spent: o.spent,
            });
        }
    }

    // Newest first, with a total order so the listing is stable across calls.
    out.sort_by(|a, b| {
        b.height
            .unwrap_or(u32::MAX)
            .cmp(&a.height.unwrap_or(u32::MAX))
            .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
            .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
    });
    out
}

/// Blocks left before a coinbase confirmed at `height` is spendable. An
/// unconfirmed coinbase is the whole wait, not zero.
///
/// `maturity + 1 - depth`, matching the node exactly (`GetTxBlocksToMaturity`):
/// a coinbase becomes spendable when its depth EXCEEDS the maturity, not when
/// it equals it. One block out here is a wallet that offers a reward for
/// conversion one block before the chain will accept the spend, so it is worth
/// the +1 being deliberate rather than inherited.
fn blocks_to_maturity(height: Option<u32>, tip_height: u32, coinbase_maturity: u32) -> u32 {
    match height {
        None => coinbase_maturity.saturating_add(1),
        Some(h) => {
            let depth = tip_height.saturating_sub(h).saturating_add(1);
            coinbase_maturity.saturating_add(1).saturating_sub(depth)
        }
    }
}

// ---------------------------------------------------------------------------
// Layer 2: policy
// ---------------------------------------------------------------------------

/// What rewards are converted into. Native Bitcoin is the default and the top
/// entry of every picker, but it is not the only choice: outside staking no
/// asset is privileged, and a staker who wants USDX, or GOLD, or more SEQ to
/// grow a stake with is doing the same thing for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertTarget {
    /// Native parent-chain BTC. Never SBTC: a staker who asks for Bitcoin gets
    /// Bitcoin, and one who genuinely wants the peg picks it as an asset.
    NativeBtc,
    /// Any Sequentia asset, converted same-chain.
    Asset(AssetId),
}

impl ConvertTarget {
    /// Whether `asset` IS the target, and so has nothing to convert into.
    pub fn is_target_asset(&self, asset: &AssetId) -> bool {
        matches!(self, ConvertTarget::Asset(a) if a == asset)
    }

    /// Native BTC settles cross-chain (an HTLC on the cross book, or
    /// Lightning); a Sequentia asset settles same-chain. Auto-conversion adds
    /// no settlement primitive of its own - which one runs follows from the
    /// target alone.
    pub fn is_cross_chain(&self) -> bool {
        matches!(self, ConvertTarget::NativeBtc)
    }
}

/// The staker's standing instruction. Off by default, always: converting
/// someone's rewards is irreversible and they may have chosen those assets
/// deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoConvertSettings {
    /// Off by default. Nobody's rewards are converted because they upgraded.
    pub enabled: bool,
    /// What to convert into. Native BTC by default, and first in every picker.
    pub target: ConvertTarget,
    /// Assets to keep as they are, on top of the target itself.
    pub exclude: HashSet<AssetId>,
    /// The floor a batch must clear, in the TARGET asset's atoms.
    pub min_receive: u64,
    /// How far from the reference price a fill may land, in basis points.
    pub max_slippage_bp: u32,
}

impl Default for AutoConvertSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            target: ConvertTarget::NativeBtc,
            exclude: HashSet::new(),
            // 0.0001 BTC. In the target's atoms, so a non-BTC target's caller
            // sets its own equivalent.
            min_receive: 10_000,
            max_slippage_bp: 200,
        }
    }
}

/// Reward coins of one asset, gathered until they are worth converting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardBatch {
    /// The asset being sold.
    pub asset: AssetId,
    /// Exactly the coins this batch would spend. Nothing else is ever spent:
    /// not the staker's principal, not a stake output, not a delegation record.
    pub inputs: Vec<OutPoint>,
    /// What they add up to, in the asset's atoms.
    pub value: u64,
}

/// What the book says a batch would fetch right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    /// Target atoms the book would actually deliver for the whole batch,
    /// having walked the levels, net of the swap's own costs.
    pub receives: u64,
    /// Target atoms the batch is worth at the reference price, ignoring depth.
    /// The gap between the two is the slippage the fill would suffer.
    pub reference: u64,
}

impl Quote {
    /// How far below the reference price this fill lands, in basis points.
    /// Saturates at 10000; a fill BETTER than reference is zero, not negative.
    pub fn slippage_bp(&self) -> u32 {
        if self.reference == 0 || self.receives >= self.reference {
            return 0;
        }
        let shortfall = (self.reference - self.receives) as u128;
        ((shortfall * 10_000) / self.reference as u128).min(10_000) as u32
    }
}

/// Whether a batch converts now, and if not, why not.
///
/// Every "not now" is a WAIT, never an error. A batch that cannot convert keeps
/// its coins exactly where they are and is reconsidered when the next reward in
/// the same asset lands, or the book changes - indefinitely, if that is how
/// long it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Sell the batch. Market, never Limit: a resting order the staker forgot
    /// is worse than a reward that did not convert.
    Convert {
        /// Target atoms the fill is expected to deliver.
        receives: u64,
    },
    /// Auto-conversion is switched off.
    Disabled,
    /// The asset IS the target, or the staker excluded it.
    NotConverted,
    /// No market for this pair at all. This is the user's own "as long as there
    /// is a market for that trading pair", checked against the live book rather
    /// than a static list of pairs.
    NoMarket,
    /// A market EXISTS, but this batch is worth less than one atom of the
    /// target. Saying "no market" here would send a staker looking for
    /// liquidity that is already there, so the two are kept apart.
    TooSmallToPrice,
    /// The proceeds would not clear the floor. Wait for more rewards.
    BelowFloor {
        /// What the batch would fetch.
        receives: u64,
        /// The configured minimum it has to clear.
        floor: u64,
    },
    /// A market that exists but is quoted far from the reference price is not a
    /// market the staker meant to sell into.
    SlippageTooHigh {
        /// How far below the reference price the fill would land.
        slippage_bp: u32,
        /// The configured cap it exceeded.
        cap_bp: u32,
    },
}

impl Decision {
    /// Whether this decision is to go ahead and sell.
    pub fn converts(&self) -> bool {
        matches!(self, Decision::Convert { .. })
    }
}

/// Group convertible rewards into one batch per asset, skipping the target
/// itself and anything excluded.
///
/// Immature and already-spent rewards are left out by [`StakingReward::convertible`],
/// and `already_converted` excludes coins a conversion has already consumed -
/// the idempotence that stops a restart, or a second window, selling the same
/// reward twice.
pub fn batches(
    rewards: &[StakingReward],
    settings: &AutoConvertSettings,
    already_converted: &HashSet<OutPoint>,
) -> Vec<RewardBatch> {
    let mut by_asset: BTreeMap<AssetId, RewardBatch> = BTreeMap::new();

    for r in rewards {
        if !r.convertible() || already_converted.contains(&r.outpoint) {
            continue;
        }
        if settings.target.is_target_asset(&r.asset) || settings.exclude.contains(&r.asset) {
            continue;
        }
        let e = by_asset.entry(r.asset).or_insert_with(|| RewardBatch {
            asset: r.asset,
            inputs: Vec::new(),
            value: 0,
        });
        e.inputs.push(r.outpoint);
        e.value = e.value.saturating_add(r.value);
    }

    // Biggest first: if only some batches can be worked through in a pass, the
    // ones that matter most go first.
    let mut out: Vec<_> = by_asset.into_values().collect();
    out.sort_by(|a, b| b.value.cmp(&a.value).then_with(|| a.asset.cmp(&b.asset)));
    out
}

/// Whether one batch converts, given what the book is offering for it.
///
/// `quote` is `None` when there is no market for `ASSET/TARGET`, or none deep
/// enough to fill the batch.
pub fn decide(
    batch: &RewardBatch,
    quote: Option<Quote>,
    settings: &AutoConvertSettings,
) -> Decision {
    if !settings.enabled {
        return Decision::Disabled;
    }
    if settings.target.is_target_asset(&batch.asset) || settings.exclude.contains(&batch.asset) {
        return Decision::NotConverted;
    }
    let quote = match quote {
        None => return Decision::NoMarket,
        Some(q) => q,
    };
    if quote.receives == 0 {
        // The reference price is what tells an empty book from a batch too
        // small to price: it is only set when there were offers.
        return if quote.reference > 0 {
            Decision::TooSmallToPrice
        } else {
            Decision::NoMarket
        };
    }
    // Slippage before the floor: a batch quoted 40% away should say so, rather
    // than blame a floor it only misses because the price is wrong.
    let slippage_bp = quote.slippage_bp();
    if slippage_bp > settings.max_slippage_bp {
        return Decision::SlippageTooHigh {
            slippage_bp,
            cap_bp: settings.max_slippage_bp,
        };
    }
    if quote.receives < settings.min_receive {
        return Decision::BelowFloor {
            receives: quote.receives,
            floor: settings.min_receive,
        };
    }
    Decision::Convert {
        receives: quote.receives,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::hashes::Hash as _;
    use std::str::FromStr;

    fn asset(n: u8) -> AssetId {
        AssetId::from_slice(&[n; 32]).unwrap()
    }

    fn txid(n: u8) -> elements::Txid {
        elements::Txid::from_slice(&[n; 32]).unwrap()
    }

    /// The secp256k1 generator, which is as good a staker key as any.
    fn pubkey() -> elements::secp256k1_zkp::PublicKey {
        elements::secp256k1_zkp::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    /// `P2WPKH(pubkey())`, byte for byte the script the node's
    /// `PosLeaderFeeScript` builds and every reward on a staking key pays.
    fn staking_script() -> Script {
        let h = elements::hashes::hash160::Hash::hash(&pubkey().serialize());
        let mut v = vec![0x00, 0x14];
        v.extend_from_slice(&h[..]);
        Script::from(v)
    }

    /// Some other P2WPKH of ours: an ordinary receive address.
    fn other_script() -> Script {
        let mut v = vec![0x00, 0x14];
        v.extend_from_slice(&[0x22u8; 20]);
        Script::from(v)
    }

    fn owned(vout: u32, script: Script, a: AssetId, value: u64) -> OwnedOutput {
        OwnedOutput {
            vout,
            script_pubkey: script,
            asset: a,
            value,
            spent: false,
        }
    }

    fn scripts() -> StakingScripts {
        let mut m = HashMap::new();
        m.insert(staking_script(), pubkey());
        m
    }

    fn no_relations() -> HashMap<elements::secp256k1_zkp::PublicKey, SignerRelation> {
        HashMap::new()
    }

    #[test]
    fn the_coinbase_maturity_is_sequentias_not_bitcoins() {
        // 1,000 blocks, because the chain runs at 60 seconds and the protection
        // is a wall-clock one. A wallet that used 100 would call a reward
        // spendable 900 blocks early and then build a transaction the chain
        // rejects -- which is what every light wallet did until a node on the
        // live testnet reported 941 blocks to maturity at 60 confirmations.
        assert_eq!(SEQUENTIA_COINBASE_MATURITY, 1000);

        let txs = vec![TxFacts {
            txid: txid(1),
            height: Some(1000),
            is_coinbase: true,
            from_me: false,
            owned_outputs: vec![owned(0, staking_script(), asset(9), 500)],
        }];
        // 60 deep: still 941 to go, exactly as the node reports.
        let r = attribute_rewards(&txs, &scripts(), &no_relations(), 1059,
                                  SEQUENTIA_COINBASE_MATURITY);
        assert_eq!(r[0].blocks_to_maturity, 941);
        assert!(!r[0].mature());
        assert!(!r[0].convertible());
    }

    #[test]
    fn coinbase_to_our_staking_key_is_solo() {
        let txs = vec![TxFacts {
            txid: txid(1),
            height: Some(100),
            is_coinbase: true,
            from_me: false,
            owned_outputs: vec![owned(0, staking_script(), asset(9), 500)],
        }];
        let r = attribute_rewards(&txs, &scripts(), &no_relations(), 100, 100);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, RewardSource::Solo);
        assert_eq!(r[0].value, 500);
        // Freshly mined, one deep: the full maturity still to wait, because a
        // coinbase is spendable only once its depth EXCEEDS the maturity.
        assert_eq!(r[0].blocks_to_maturity, 100);
        assert!(!r[0].mature());
        assert!(!r[0].convertible());
    }

    #[test]
    fn coinbase_to_a_delegated_key_is_a_lottery_draw() {
        let mut rel = HashMap::new();
        rel.insert(pubkey(), SignerRelation::Delegated);
        let txs = vec![TxFacts {
            txid: txid(1),
            height: Some(1),
            is_coinbase: true,
            from_me: false,
            owned_outputs: vec![owned(0, staking_script(), asset(9), 500)],
        }];
        let r = attribute_rewards(&txs, &scripts(), &rel, 200, 100);
        assert_eq!(r[0].source, RewardSource::Lottery);
        assert!(r[0].mature());
    }

    #[test]
    fn coinbase_to_any_other_script_of_ours_is_a_direct_payout() {
        let txs = vec![TxFacts {
            txid: txid(1),
            height: Some(1),
            is_coinbase: true,
            from_me: false,
            owned_outputs: vec![owned(0, other_script(), asset(9), 500)],
        }];
        let r = attribute_rewards(&txs, &scripts(), &no_relations(), 200, 100);
        assert_eq!(r[0].source, RewardSource::Direct);
    }

    #[test]
    fn a_payment_to_our_staking_key_is_a_split_claim_and_matures_at_once() {
        let txs = vec![TxFacts {
            txid: txid(2),
            height: Some(150),
            is_coinbase: false,
            from_me: false,
            owned_outputs: vec![owned(1, staking_script(), asset(9), 700)],
        }];
        let r = attribute_rewards(&txs, &scripts(), &no_relations(), 150, 100);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].source, RewardSource::Split);
        // A pot claim is an ordinary transaction output.
        assert_eq!(r[0].blocks_to_maturity, 0);
        assert!(r[0].convertible());
    }

    #[test]
    fn an_ordinary_receive_is_not_a_reward() {
        let txs = vec![TxFacts {
            txid: txid(3),
            height: Some(150),
            is_coinbase: false,
            from_me: false,
            owned_outputs: vec![owned(0, other_script(), asset(9), 700)],
        }];
        assert!(attribute_rewards(&txs, &scripts(), &no_relations(), 150, 100).is_empty());
    }

    #[test]
    fn our_own_payment_to_our_own_staking_key_is_not_a_reward() {
        // The shape of a delegator's withdrawal or re-pointing: it pays back to
        // the staking key, and must never be mistaken for a pool paying out.
        let txs = vec![TxFacts {
            txid: txid(4),
            height: Some(150),
            is_coinbase: false,
            from_me: true,
            owned_outputs: vec![owned(0, staking_script(), asset(9), 700)],
        }];
        assert!(attribute_rewards(&txs, &scripts(), &no_relations(), 150, 100).is_empty());
    }

    #[test]
    fn an_empty_blocks_coinbase_pays_nothing_and_is_not_a_reward() {
        let txs = vec![TxFacts {
            txid: txid(5),
            height: Some(150),
            is_coinbase: true,
            from_me: false,
            owned_outputs: vec![owned(0, staking_script(), asset(9), 0)],
        }];
        assert!(attribute_rewards(&txs, &scripts(), &no_relations(), 150, 100).is_empty());
    }

    #[test]
    fn rewards_come_back_newest_first() {
        let txs = vec![
            TxFacts {
                txid: txid(1),
                height: Some(10),
                is_coinbase: true,
                from_me: false,
                owned_outputs: vec![owned(0, staking_script(), asset(9), 1)],
            },
            TxFacts {
                txid: txid(2),
                height: Some(30),
                is_coinbase: true,
                from_me: false,
                owned_outputs: vec![owned(0, staking_script(), asset(9), 2)],
            },
            TxFacts {
                txid: txid(3),
                height: Some(20),
                is_coinbase: true,
                from_me: false,
                owned_outputs: vec![owned(0, staking_script(), asset(9), 3)],
            },
        ];
        let r = attribute_rewards(&txs, &scripts(), &no_relations(), 500, 100);
        let heights: Vec<_> = r.iter().map(|x| x.height.unwrap()).collect();
        assert_eq!(heights, vec![30, 20, 10]);
    }

    // ---- policy ----------------------------------------------------------

    fn mature_reward(t: u8, v: u32, a: AssetId, value: u64) -> StakingReward {
        StakingReward {
            outpoint: OutPoint::new(txid(t), v),
            asset: a,
            value,
            source: RewardSource::Solo,
            height: Some(1),
            blocks_to_maturity: 0,
            spent: false,
        }
    }

    fn on(target: ConvertTarget) -> AutoConvertSettings {
        AutoConvertSettings {
            enabled: true,
            target,
            ..Default::default()
        }
    }

    #[test]
    fn batches_group_by_asset_and_sum() {
        let rewards = vec![
            mature_reward(1, 0, asset(1), 100),
            mature_reward(2, 0, asset(1), 250),
            mature_reward(3, 0, asset(2), 900),
        ];
        let b = batches(&rewards, &on(ConvertTarget::NativeBtc), &HashSet::new());
        assert_eq!(b.len(), 2);
        // Biggest first.
        assert_eq!(b[0].asset, asset(2));
        assert_eq!(b[0].value, 900);
        assert_eq!(b[1].value, 350);
        assert_eq!(b[1].inputs.len(), 2);
    }

    #[test]
    fn immature_spent_and_already_converted_rewards_are_never_batched() {
        let mut immature = mature_reward(1, 0, asset(1), 100);
        immature.blocks_to_maturity = 5;
        let mut spent = mature_reward(2, 0, asset(1), 100);
        spent.spent = true;
        let done = mature_reward(3, 0, asset(1), 100);
        let mut already = HashSet::new();
        already.insert(done.outpoint);

        let rewards = vec![immature, spent, done];
        assert!(batches(&rewards, &on(ConvertTarget::NativeBtc), &already).is_empty());
    }

    #[test]
    fn the_target_asset_and_excluded_assets_are_left_alone() {
        let mut s = on(ConvertTarget::Asset(asset(1)));
        s.exclude.insert(asset(2));
        let rewards = vec![
            mature_reward(1, 0, asset(1), 100), // the target itself
            mature_reward(2, 0, asset(2), 100), // excluded
            mature_reward(3, 0, asset(3), 100),
        ];
        let b = batches(&rewards, &s, &HashSet::new());
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].asset, asset(3));
    }

    #[test]
    fn a_batch_converts_when_the_book_clears_the_floor() {
        let s = on(ConvertTarget::NativeBtc);
        let batch = RewardBatch {
            asset: asset(3),
            inputs: vec![OutPoint::new(txid(1), 0)],
            value: 100,
        };
        let q = Quote {
            receives: 20_000,
            reference: 20_000,
        };
        assert_eq!(decide(&batch, Some(q), &s), Decision::Convert { receives: 20_000 });
    }

    #[test]
    fn no_market_is_a_wait_not_an_error() {
        let s = on(ConvertTarget::NativeBtc);
        let batch = RewardBatch {
            asset: asset(3),
            inputs: vec![],
            value: 100,
        };
        assert_eq!(decide(&batch, None, &s), Decision::NoMarket);
        // A book with nothing in it at all says the same.
        let empty = Quote {
            receives: 0,
            reference: 0,
        };
        assert_eq!(decide(&batch, Some(empty), &s), Decision::NoMarket);

        // But a market that EXISTS and a batch too small to price are different
        // situations, and reporting the second as the first sends a staker
        // hunting for liquidity that is already resting on the book.
        let dust = Quote {
            receives: 0,
            reference: 20_000,
        };
        assert_eq!(decide(&batch, Some(dust), &s), Decision::TooSmallToPrice);
    }

    #[test]
    fn a_batch_below_the_floor_waits_for_more_rewards() {
        let s = on(ConvertTarget::NativeBtc);
        let batch = RewardBatch {
            asset: asset(3),
            inputs: vec![],
            value: 100,
        };
        let q = Quote {
            receives: 9_999,
            reference: 9_999,
        };
        assert_eq!(
            decide(&batch, Some(q), &s),
            Decision::BelowFloor {
                receives: 9_999,
                floor: 10_000
            }
        );
    }

    #[test]
    fn a_badly_quoted_market_is_refused_before_the_floor_is_considered() {
        let s = on(ConvertTarget::NativeBtc);
        let batch = RewardBatch {
            asset: asset(3),
            inputs: vec![],
            value: 100,
        };
        // Would clear the floor, but 40% below the reference price.
        let q = Quote {
            receives: 60_000,
            reference: 100_000,
        };
        assert_eq!(
            decide(&batch, Some(q), &s),
            Decision::SlippageTooHigh {
                slippage_bp: 4_000,
                cap_bp: 200
            }
        );
    }

    #[test]
    fn a_fill_better_than_reference_is_zero_slippage_not_negative() {
        let q = Quote {
            receives: 120_000,
            reference: 100_000,
        };
        assert_eq!(q.slippage_bp(), 0);
    }

    #[test]
    fn nothing_converts_while_the_setting_is_off() {
        let s = AutoConvertSettings::default();
        assert!(!s.enabled);
        let batch = RewardBatch {
            asset: asset(3),
            inputs: vec![],
            value: 100,
        };
        let q = Quote {
            receives: 1_000_000,
            reference: 1_000_000,
        };
        assert_eq!(decide(&batch, Some(q), &s), Decision::Disabled);
    }

    #[test]
    fn native_btc_settles_cross_chain_and_an_asset_target_does_not() {
        assert!(ConvertTarget::NativeBtc.is_cross_chain());
        assert!(!ConvertTarget::Asset(asset(1)).is_cross_chain());
    }
}
