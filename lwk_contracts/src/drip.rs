//! The faucet drip covenant's spends (`sequentia/faucet-drip`), planned from
//! its parameters the way its program checks them. The program run against
//! the final transaction remains the authority; these checks only name the
//! rule a request breaks before the program is asked.

use crate::error::Error;
use crate::spend::{CoinRequest, OutputRequest, SpendRequest};
use crate::template::{Contract, SEQUENCE_TIME_FLAG};

/// The drip's path and the recovery's, as the template names them.
pub const DRIP_PATH: &str = "drip";
pub const RECOVER_PATH: &str = "recover";

/// The most a drip may pay from a reserve of `reserve`, as the program computes it.
pub fn tier_for(contract: &Contract, reserve: u64) -> Result<u64, Error> {
    let tiers = [
        (
            contract.value_u64("TIER1_FLOOR")?,
            contract.value_u64("TIER1_MAX")?,
        ),
        (
            contract.value_u64("TIER2_FLOOR")?,
            contract.value_u64("TIER2_MAX")?,
        ),
        (
            contract.value_u64("TIER3_FLOOR")?,
            contract.value_u64("TIER3_MAX")?,
        ),
        (0, contract.value_u64("TIER4_MAX")?),
    ];
    Ok(tiers
        .into_iter()
        .find(|(floor, _)| reserve >= *floor)
        .map_or(0, |(_, max)| max))
}

/// The input sequence a drip carries: the interval, in units of 512 seconds.
pub fn drip_sequence(contract: &Contract) -> Result<u32, Error> {
    Ok(SEQUENCE_TIME_FLAG
        | u32::try_from(contract.value_u64("INTERVAL")?)
            .map_err(|e| Error::Spend(e.to_string()))?)
}

/// A drip of `amount` from the reserve `coin` to `to` (an address), paying
/// `fee` in the reserve's asset; the rest returns to the covenant as output 0.
pub fn plan(
    contract: &Contract,
    coin: &CoinRequest,
    to_address: &str,
    amount: u64,
    fee: u64,
) -> Result<SpendRequest, Error> {
    if contract.template.hash() != crate::known::FAUCET_DRIP {
        return Err(Error::Spend("not a faucet drip covenant".into()));
    }
    let asset_internal = contract.value_bytes("ASSET")?;
    let asset: String = crate::hex::hex(&asset_internal.iter().rev().copied().collect::<Vec<_>>());
    if coin.asset != asset {
        return Err(Error::Spend(format!(
            "the reserve holds {}, the covenant drips {asset}",
            coin.asset
        )));
    }
    let max = tier_for(contract, coin.amount)?;
    if amount > max {
        return Err(Error::Spend(format!(
            "a drip of {amount} is above the {max} a reserve of {} may pay",
            coin.amount
        )));
    }
    let cap = contract.value_u64("FEE_CAP")?;
    if fee > cap {
        return Err(Error::Spend(format!(
            "a fee of {fee} is above the covenant's cap of {cap}"
        )));
    }
    let rest = coin
        .amount
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(fee))
        .ok_or_else(|| Error::Spend("the reserve holds less than the drip and its fee".into()))?;
    Ok(SpendRequest {
        path: DRIP_PATH.into(),
        coin: coin.clone(),
        sequence: Some(drip_sequence(contract)?),
        lock_time: None,
        outputs: vec![
            OutputRequest {
                to: "contract".into(),
                address: None,
                script: Some(contract.derived.script_pubkey.clone()),
                asset: asset.clone(),
                amount: rest,
            },
            OutputRequest {
                to: "pay".into(),
                address: Some(to_address.into()),
                script: None,
                asset: asset.clone(),
                amount,
            },
            OutputRequest {
                to: "fee".into(),
                address: None,
                script: None,
                asset,
                amount: fee,
            },
        ],
        spender: Default::default(),
        next_slots: None,
    })
}

/// The fee for `vsize` virtual bytes at `rate_per_kvb` atoms of the fee
/// asset per 1,000 virtual bytes, rounded up.
pub fn fee_for(vsize: u64, rate_per_kvb: u64) -> u64 {
    (vsize * rate_per_kvb).div_ceil(1000)
}
