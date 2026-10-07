// The wasm half of lwk_wollet/tests/sequentia_stake_records.rs. That test
// builds each stake record transaction natively, has a sequentiad node confirm
// it in a block, and writes a fixture holding, for each, the recipe a wallet
// hands the bindings and the transaction the node confirmed. Here every recipe
// goes through the bindings and must give that transaction byte for byte, so
// what the node accepted is what the browser wallets build.
//
// Run by that test as `node stake_records.js <fixture.json>`.

const assert = require('assert');
const fs = require('fs');
const lwk = require('lwk_node');

const fx = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(fx.policy_asset), fx.genesis_hash);

// The staking key the bindings derive is the one the native wallet used.
const signer = new lwk.Signer(new lwk.Mnemonic(fx.mnemonic), network);
assert.strictEqual(signer.stakerPublicKey(), fx.staker);
assert.strictEqual(lwk.sequentiaUnbondScript(fx.staker), fx.unbond_script);

// The signature follows the fork height: legacy below it, segwit-v0 from it.
for (const c of fx.signing) {
    assert.strictEqual(lwk.stakeRecordSigning(network, c.tip, c.v2_height), c.expect, JSON.stringify(c));
}
// The testnet's own height, with no override: a spend built on a tip of
// 162,998 enters block 162,999 and signs the legacy way; from a tip of
// 162,999 it enters block 163,000 and signs the second-generation way.
const testnet = lwk.Network.sequentiaTestnet();
assert.strictEqual(lwk.stakeRecordSigning(testnet, 162998), 'legacy');
assert.strictEqual(lwk.stakeRecordSigning(testnet, 162999), 'segwitV0');

const build = {
    buildDelegationCreateTx: lwk.buildDelegationCreateTx,
    buildDelegationSpendTx: lwk.buildDelegationSpendTx,
    buildUnbondTx: lwk.buildUnbondTx,
    buildUnbondClaimTx: lwk.buildUnbondClaimTx,
};

let n = 0;
for (const c of fx.cases) {
    const built = build[c.fn]({ mnemonic: fx.mnemonic, ...c.recipe }, network);
    assert.strictEqual(built.rawHex, c.raw_hex, `${c.what}: the bindings built another transaction`);
    assert.strictEqual(built.txid, c.txid, c.what);
    if (c.signing !== undefined) assert.strictEqual(built.signing, c.signing, c.what);
    console.log(`stake_records: ${c.fn} (${c.what}) gives ${built.txid}`);
    n++;
}

// What the bindings refuse rather than build.
assert.throws(() => lwk.buildDelegationSpendTx({
    mnemonic: fx.mnemonic, ...fx.cases.find(c => c.fn === 'buildDelegationSpendTx').recipe, locktime: 0,
}, network), /chain tip is needed/);
console.log(`stake_records: ${n} transactions built by the bindings, each the one the node confirmed`);
