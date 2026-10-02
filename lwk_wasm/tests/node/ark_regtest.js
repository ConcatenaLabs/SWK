// The wasm half of lwk_wollet/tests/ark_regtest.rs, which starts an
// elementsregtest node, mines one honest round and five attacks that
// consensus accepts, and writes a fixture naming them. Run by that test as
// `node ark_regtest.js <fixture.json>`.
//
// Here, with nothing but the bindings and the node:
// - the wallet is restored from its mnemonic, and its leaf keys are found from
//   the owner nonces in the records the operator handed out, with no index
//   scan; the stranger's records are not the wallet's;
// - each round is fetched from the node, and every leaf of the honest round is
//   accepted, the wallet's as its own, while every leaf of each attack is
//   refused with the check that catches it named;
// - the honest leaves go into the store with their unlock preimages.

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const lwk = require('lwk_node');

const fx = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

function rpc(method, params) {
    const body = JSON.stringify({ jsonrpc: '1.0', id: 1, method, params });
    const url = new URL(fx.rpc.url);
    const auth = Buffer.from(`${fx.rpc.user}:${fx.rpc.password}`).toString('base64');
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: url.hostname, port: url.port, path: '/', method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}`, 'Content-Length': Buffer.byteLength(body) },
        }, (res) => {
            let data = '';
            res.on('data', (c) => { data += c; });
            res.on('end', () => {
                const v = JSON.parse(data);
                if (v.error) reject(new Error(`${method}: ${JSON.stringify(v.error)}`)); else resolve(v.result);
            });
        });
        req.on('error', reject);
        req.end(body);
    });
}

async function main() {
    const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(fx.policy_asset), fx.genesis_hash);
    // The wallet restored from its mnemonic: no state but the words.
    const signer = new lwk.Signer(new lwk.Mnemonic(fx.mnemonic), network);
    const verifier = new lwk.ArkVerifier(network, { operator: fx.operator, now: fx.now });
    const map = new Map();
    const store = new lwk.ArkStore({
        get: (k) => map.get(k) || null,
        put: (k, val) => { map.set(k, new Uint8Array(val)); },
        remove: (k) => { map.delete(k); },
        isPersisted: () => false,
    });

    let restored = 0;
    let accepted = 0;
    let refused = 0;
    for (const b of fx.batches) {
        const roundHex = await rpc('getrawtransaction', [b.round_txid]);
        const info = await rpc('getrawtransaction', [b.round_txid, true]);
        assert.ok(info.confirmations >= 1, `${b.name}: the round is not in a block`);
        for (const l of b.leaves) {
            let verdict;
            if (l.ours) {
                // The key comes back from the record's own nonce.
                const key = signer.arkRestoreKey(0, l.record);
                assert.strictEqual(key.key, l.owner, b.name);
                assert.strictEqual(key.ownerNonce, l.owner_nonce, b.name);
                assert.strictEqual(key.path, lwk.arkLeafKeyPath(0, l.owner_nonce));
                restored++;
                verdict = verifier.verifyLeaf(l.record, roundHex, key.key, key.ownerNonce);
            } else {
                assert.throws(() => signer.arkRestoreKey(0, l.record), /the leaf is not this wallet's/);
                verdict = verifier.verifyRound(l.record_hex, roundHex);
            }
            if (b.check === null) {
                assert.ok(verdict.accepted, `${b.name}: ${verdict.reason}`);
                assert.strictEqual(verdict.leafId, l.leaf_id);
                assert.strictEqual(verdict.roundTxid, b.round_txid);
                assert.strictEqual(verdict.owned, l.ours);
                accepted++;
                if (l.ours) {
                    store.putLeaf(verifier, l.record, roundHex, l.owner, l.owner_nonce);
                    store.putPreimage(l.leaf_id, l.preimage);
                    const again = verifier.recheck(b.round_txid, l.record, roundHex, l.owner, l.owner_nonce);
                    assert.strictEqual(again.replaced, false);
                }
            } else {
                assert.strictEqual(verdict.accepted, false, `${b.name}: accepted`);
                assert.strictEqual(verdict.check, b.check, `${b.name}: ${verdict.reason}`);
                assert.strictEqual(verdict.failed, `check ${b.check}`);
                if (l.ours) {
                    assert.throws(() => store.putLeaf(verifier, l.record, roundHex, l.owner, l.owner_nonce),
                        new RegExp(`leaf refused: check ${b.check}: `));
                }
                refused++;
            }
        }
        const first = b.leaves[0];
        const v0 = first.ours
            ? verifier.verifyLeaf(first.record, roundHex, first.owner, first.owner_nonce)
            : verifier.verifyRound(first.record, roundHex);
        console.log(`${b.round_txid} ${b.name}: ${v0.accepted ? `accepted; leaf 0 holds ${v0.value} atoms of ${v0.asset}, first expiry ${v0.expiries[0]}` : v0.reason}`);
    }
    const kept = store.leafIds();
    assert.strictEqual(kept.length, 3);
    for (const id of kept) assert.ok(store.leaf(id).preimage);
    assert.ok([...map.keys()].every((k) => k.startsWith('ark/')));
    console.log(`ark_regtest: ${restored} wallet leaf keys restored from the mnemonic; ${accepted} leaves accepted, ${refused} refused by the check named; ${kept.length} kept in the store with their preimages`);
}

main().catch((e) => { console.error(e); process.exit(1); });
