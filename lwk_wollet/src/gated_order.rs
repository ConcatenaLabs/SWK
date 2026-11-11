//! Gated orders: a holder's resting offer to sell a restricted (OpenAMP) asset
//! on the chain, filled while its maker is offline.
//!
//! The scripts are openampd's (`openampd/internal/elements/gated.go` in the
//! `openamp` repository), checked byte for byte against the same golden
//! vectors, which the node's test framework produced.
//!
//! `P2TR(NUMS, [fill, [refund, claw]])` (no `claw` without clawback):
//!
//! ```text
//! fill  : <K_policy> OP_CHECKSIGVERIFY <a SeqDEX fill covenant>
//! refund: <expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!         OP_PUSHCURRENTINPUTINDEX OP_0 OP_EQUALVERIFY
//!         OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <maker's enclave program> OP_EQUALVERIFY
//!         OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!         OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY
//!         OP_0 OP_INSPECTINPUTVALUE OP_1 OP_EQUALVERIFY OP_EQUAL
//! claw  : <K_issuer> OP_CHECKSIGVERIFY <K_policy> OP_CHECKSIG
//! ```
//!
//! The fill is SeqDEX's tapscript fill covenant behind the policy key: every
//! fill needs the policy server's signature, which it gives only together with
//! the broadcast (`POST /v1/cosign` with `order_inputs` and `"broadcast":
//! true`). A taker therefore builds the fill exactly as for an ordinary SeqDEX
//! order, with this tree's `fill` leaf and control block, signs its own inputs,
//! and hands the transaction to the policy server, which completes the order
//! input's witness (`<policy sig> <fill leaf> <control>`) and broadcasts. The
//! taker's receipt of the asset must pay its own enclave.
//!
//! The refund needs no key: after the expiry the order must be input 0 and
//! output 0 must carry its whole value, read from the input, home to the
//! maker's enclave. One refund per transaction, so no refund output can also
//! count for another covenant in the same transaction.

use crate::elements::opcodes::all::*;
use crate::elements::script::Builder;
use crate::elements::secp256k1_zkp::XOnlyPublicKey;
use crate::elements::{AssetId, Script};
use crate::error::Error;
use crate::swap_htlc::{asset_bytes, build, check_sig_pair, time_lock, SwapTree, MIN_TIME_LOCK};

/// The largest fill covenant a gated order wraps (openampd's bound).
pub const GATED_FILL_MAX: usize = 1000;

/// Everything a gated order's scripts commit to.
#[derive(Debug, Clone)]
pub struct GatedOrderTerms {
    /// The asset's policy key.
    pub policy: XOnlyPublicKey,
    /// The SeqDEX fill covenant the order wraps, without the gate.
    pub fill: Vec<u8>,
    /// The clawback key, only where the asset elected clawback.
    pub issuer: Option<XOnlyPublicKey>,
    /// The refund opens at this median time past (at least [`MIN_TIME_LOCK`]).
    pub expiry: u32,
    /// The maker's enclave: its v1 witness program.
    pub maker_program: [u8; 32],
    /// The restricted asset.
    pub asset: AssetId,
}

/// The policy gate followed by the fill covenant.
pub fn gated_fill_leaf(policy: &XOnlyPublicKey, fill: &[u8]) -> Script {
    let mut v = Builder::new()
        .push_slice(&policy.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script()
        .into_bytes();
    v.extend_from_slice(fill);
    Script::from(v)
}

/// The gated order: leaves `fill`, `refund` and, with clawback, `claw`.
pub fn gated_order_tree(t: &GatedOrderTerms) -> Result<SwapTree, Error> {
    if t.expiry < MIN_TIME_LOCK {
        return Err(Error::Generic(format!(
            "expiry {} is a height: an order's expiry is a time (>= {MIN_TIME_LOCK})",
            t.expiry
        )));
    }
    if t.fill.is_empty() || t.fill.len() > GATED_FILL_MAX {
        return Err(Error::Generic(format!(
            "the fill covenant must be 1 to {GATED_FILL_MAX} bytes"
        )));
    }
    let refund = time_lock(Builder::new(), t.expiry)
        .push_opcode(OP_PUSHCURRENTINPUTINDEX)
        .push_int(0)
        .push_opcode(OP_EQUALVERIFY)
        .push_int(0)
        .push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&t.maker_program)
        .push_opcode(OP_EQUALVERIFY)
        .push_int(0)
        .push_opcode(OP_INSPECTOUTPUTASSET)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&asset_bytes(&t.asset))
        .push_opcode(OP_EQUALVERIFY)
        .push_int(0)
        .push_opcode(OP_INSPECTOUTPUTVALUE)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_int(0)
        .push_opcode(OP_INSPECTINPUTVALUE)
        .push_int(1)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_EQUAL)
        .into_script();
    let mut leaves = vec![
        ("fill", gated_fill_leaf(&t.policy, &t.fill)),
        ("refund", refund),
    ];
    if let Some(issuer) = &t.issuer {
        leaves.push(("claw", check_sig_pair(issuer, &t.policy).into_script()));
    }
    build(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements::hex::{FromHex, ToHex};
    use std::collections::BTreeMap;

    const VECTORS: &str = include_str!("../tests/data/htlc_vectors.json");

    fn h32(s: &str) -> [u8; 32] {
        Vec::<u8>::from_hex(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn gated_orders_match_the_test_framework() {
        let vs: BTreeMap<String, serde_json::Value> = serde_json::from_str(VECTORS).unwrap();
        for name in ["gated_claw", "gated_noclaw"] {
            let v = &vs[name];
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            let x = |k: &str| XOnlyPublicKey::from_slice(&h32(&s(k))).unwrap();
            let t = GatedOrderTerms {
                policy: x("policy_x"),
                fill: Vec::<u8>::from_hex(&s("fill")).unwrap(),
                issuer: (!s("issuer_x").is_empty()).then(|| x("issuer_x")),
                expiry: v["expiry"].as_u64().unwrap() as u32,
                maker_program: h32(&s("maker_program")),
                asset: AssetId::from_slice(&h32(&s("asset"))).unwrap(),
            };
            let tree = gated_order_tree(&t).unwrap();
            assert_eq!(tree.script_pubkey.to_hex(), s("spk"), "{name} spk");
            let mut leaves = vec!["fill", "refund"];
            if t.issuer.is_some() {
                leaves.push("claw");
            }
            assert_eq!(tree.leaves.len(), leaves.len(), "{name} leaves");
            for l in leaves {
                let (script, control) = tree.leaf(l).unwrap();
                assert_eq!(
                    script.to_hex(),
                    s(&format!("{l}_script")),
                    "{name} {l} script"
                );
                assert_eq!(
                    control.to_hex(),
                    s(&format!("{l}_control")),
                    "{name} {l} control"
                );
            }
        }
    }

    #[test]
    fn an_expiry_is_a_time_and_the_fill_has_a_size() {
        let vs: BTreeMap<String, serde_json::Value> = serde_json::from_str(VECTORS).unwrap();
        let p = XOnlyPublicKey::from_slice(&h32(vs["gated_noclaw"]["policy_x"].as_str().unwrap()))
            .unwrap();
        let t = GatedOrderTerms {
            policy: p,
            fill: vec![0x51],
            issuer: None,
            expiry: MIN_TIME_LOCK,
            maker_program: [7; 32],
            asset: AssetId::from_slice(&[1; 32]).unwrap(),
        };
        assert!(gated_order_tree(&t).is_ok());
        assert!(gated_order_tree(&GatedOrderTerms {
            expiry: MIN_TIME_LOCK - 1,
            ..t.clone()
        })
        .is_err());
        assert!(gated_order_tree(&GatedOrderTerms {
            fill: vec![],
            ..t.clone()
        })
        .is_err());
        assert!(gated_order_tree(&GatedOrderTerms {
            fill: vec![0; GATED_FILL_MAX + 1],
            ..t
        })
        .is_err());
    }
}
