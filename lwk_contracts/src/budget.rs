//! The execution budget of a Simplicity spend, and the annex that raises it.
//!
//! The rule is the node's and the descriptor's `budget`: a spend may cost
//! `min(per_witness_byte × w + offset, max)` weight units, `w` the serialized
//! size of its input's witness stack. A program whose cost bound is above
//! what its witness earns is padded with an annex, the last witness item,
//! tagged `0x50`; a full signature hash commits to it, so the padding is
//! fixed before anything is signed. Ported from the Simplex fork's
//! `BudgetRule` (ConcatenaLabs/smplx, `crates/sdk/src/program/budget.rs`).

use sequentia_contracts::descriptor::Budget;
use simplicityhl::simplicity::Cost;

/// The first byte of a taproot annex (BIP 341).
pub const ANNEX_TAG: u8 = 0x50;

/// The largest annex, tag included, a Sequentia node relays on a Simplicity spend.
pub const MAX_STANDARD_ANNEX: usize = 100_000;

/// A cost bound in milli weight units.
pub fn cost_milliweight(cost: Cost) -> u64 {
    cost.to_string()
        .parse()
        .expect("a cost prints as its milli weight units")
}

/// The size of a witness stack as consensus serializes it.
pub fn serialized_size(stack: &[Vec<u8>]) -> usize {
    compact_size_len(stack.len())
        + stack
            .iter()
            .map(|item| compact_size_len(item.len()) + item.len())
            .sum::<usize>()
}

fn compact_size_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// The budget a witness stack earns, in weight units.
pub fn earned(rule: &Budget, stack: &[Vec<u8>]) -> u64 {
    rule.earned(u64::try_from(serialized_size(stack)).unwrap_or(u64::MAX))
}

/// The smallest annex that lets a program of this cost run once appended to
/// `stack` (which carries none); `None` when the stack earns enough already.
pub fn padding(rule: &Budget, cost_mwu: u64, stack: &[Vec<u8>]) -> Result<Option<Vec<u8>>, String> {
    if cost_mwu > rule.max * 1000 {
        return Err(format!(
            "the program costs {cost_mwu} milli-WU, above the {} WU any spend can be given",
            rule.max
        ));
    }
    if cost_mwu <= earned(rule, stack) * 1000 {
        return Ok(None);
    }
    let target = cost_mwu.div_ceil(1000).saturating_sub(rule.offset);
    let needed = usize::try_from(target.div_ceil(rule.per_witness_byte)).unwrap_or(usize::MAX);
    let without = serialized_size(stack) - compact_size_len(stack.len());
    let fixed = without + compact_size_len(stack.len() + 1);
    let size_with = |len: usize| fixed + compact_size_len(len) + len;
    let mut len = needed.saturating_sub(fixed + 9).max(1);
    while size_with(len) < needed {
        len += 1;
    }
    if len > MAX_STANDARD_ANNEX {
        return Err(format!(
            "the program costs {cost_mwu} milli-WU and needs a {len}-byte annex; a node relays at most {MAX_STANDARD_ANNEX}"
        ));
    }
    let mut annex = vec![0; len];
    annex[0] = ANNEX_TAG;
    Ok(Some(annex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequentia_contracts::descriptor::SEQUENTIA_BUDGET;

    #[test]
    fn padding_reaches_exactly_the_budget_needed() {
        // S1.2's measured case: a witness of 1,369 bytes earns 5,526 WU; a
        // program of 8,503,470 milli-WU needs the 742-byte annex, and 741 is short.
        let stack = vec![vec![0u8; 1365]];
        assert_eq!(serialized_size(&stack), 1369);
        assert_eq!(earned(&SEQUENTIA_BUDGET, &stack), 5526);
        let annex = padding(&SEQUENTIA_BUDGET, 8_503_470, &stack)
            .unwrap()
            .unwrap();
        assert_eq!(annex.len(), 742);
        assert_eq!(annex[0], ANNEX_TAG);
        let mut padded = stack.clone();
        padded.push(annex.clone());
        assert!(earned(&SEQUENTIA_BUDGET, &padded) * 1000 >= 8_503_470);
        let mut short = stack.clone();
        short.push(annex[..annex.len() - 1].to_vec());
        assert!(earned(&SEQUENTIA_BUDGET, &short) * 1000 < 8_503_470);
        assert_eq!(padding(&SEQUENTIA_BUDGET, 1000, &stack).unwrap(), None);
        assert!(padding(&SEQUENTIA_BUDGET, 4_000_051_000, &stack).is_err());
    }
}
