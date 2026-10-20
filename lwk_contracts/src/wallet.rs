//! The wallet's own coins, as the engine takes them, read from a Wollet.
//!
//! A wallet input of a contract spend is spent only as the wallet's own
//! record of it says ([`crate::spend::WalletCoin`]): its script, asset,
//! amount and the funding key that signs it. This module writes that record
//! from what the Wollet synced, never from what a site says.

use lwk_wollet::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use lwk_wollet::elements_miniscript::descriptor::DescriptorType;
use lwk_wollet::elements_miniscript::ForEachKey;
use lwk_wollet::Wollet;

use crate::error::Error;
use crate::hex::hex;
use crate::spend::WalletCoin;

/// Every unspent coin of `wollet`, with the full path of the key that signs
/// it (`m/84h/1h/0h/0/3`). A coin of a descriptor whose key carries no
/// origin, or of several keys, is left out: the engine cannot name its key.
pub fn wallet_coins(wollet: &Wollet) -> Result<Vec<WalletCoin>, Error> {
    let desc = wollet.wollet_descriptor();
    let mut out = Vec::new();
    let utxos = wollet
        .utxos()
        .map_err(|e| Error::Spend(format!("the wallet's coins: {e}")))?;
    for u in utxos {
        let Ok(d) = desc.definite_descriptor(u.ext_int, u.wildcard_index) else {
            continue;
        };
        if d.desc_type() != DescriptorType::Wpkh {
            continue;
        }
        let mut paths = Vec::new();
        d.for_each_key(|k| {
            if let Some(p) = k.full_derivation_path() {
                paths.push(p);
            }
            true
        });
        let [path] = paths.as_slice() else {
            continue;
        };
        let text = path.to_string().replace('\'', "h");
        let key_path = if text.starts_with('m') {
            text
        } else {
            format!("m/{text}")
        };
        out.push(WalletCoin {
            txid: u.outpoint.txid.to_string(),
            vout: u.outpoint.vout,
            script_pubkey: hex(u.script_pubkey.as_bytes()),
            asset: u.unblinded.asset.to_string(),
            amount: u.unblinded.value,
            key_path,
            confidential: !(u.unblinded.asset_bf == AssetBlindingFactor::zero()
                && u.unblinded.value_bf == ValueBlindingFactor::zero()),
        });
    }
    Ok(out)
}
