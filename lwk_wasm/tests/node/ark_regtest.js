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
//
// With a fixture of mode "refresh", written after the test mines a round that
// pays the wallet a new leaf, an offboard output and the operator's connector,
// it builds the forfeit and the release for each of two old leaves with the
// bindings (forfeitRefresh, releaseRefresh, forfeitOffboard, releaseOffboard),
// requires the digests the test computed natively and the round's connector
// asset in display order, signs each with the old leaf's key through
// signCsfs, and prints the signatures for the test to verify.
//
// With a fixture of mode "recheck", written after the test rolls the honest
// round back and mines a replacement, it checks the wallet's leaf again
// against the replacement as the node returns it, at the median time of the
// node's tip, and requires the verdict the fixture names.

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

// After a rollback: the wallet's leaf, checked again against the
// transaction that now pays its batch output, at the tip's median time.
async function recheck() {
    const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(fx.policy_asset), fx.genesis_hash);
    const verifier = new lwk.ArkVerifier(network, { operator: fx.operator });
    const tip = await rpc('getblockheader', [await rpc('getbestblockhash', [])]);
    const now = tip.mediantime;
    const roundHex = await rpc('getrawtransaction', [fx.round_txid]);
    const l = fx.leaf;
    const v = verifier.recheck(fx.previous_round_txid, l.record, roundHex, l.owner, l.owner_nonce, now);
    const when = `median time ${now}, ${((now - fx.now) / 86400).toFixed(2)} days after the round`;
    if (fx.expect.accepted) {
        assert.ok(v.accepted, `${fx.name}: ${v.reason}`);
        assert.strictEqual(v.replaced, true);
        assert.strictEqual(v.previousRoundTxid, fx.previous_round_txid);
        assert.strictEqual(v.roundTxid, fx.round_txid);
        assert.strictEqual(v.leafId, l.leaf_id);
        console.log(`recheck, ${fx.name}, at ${when}: accepted as a replacement of ${v.previousRoundTxid} by ${v.roundTxid}`);
    } else {
        assert.strictEqual(v.accepted, false, `${fx.name}: accepted`);
        assert.strictEqual(v.failed, fx.expect.failed, v.reason);
        assert.strictEqual(v.check, fx.expect.check === null ? undefined : fx.expect.check, v.reason);
        console.log(`recheck, ${fx.name}, at ${when}: refused, ${v.reason}`);
    }
}

// A refresh and an offboard, built and signed in the bindings.
async function refresh() {
    const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(fx.policy_asset), fx.genesis_hash);
    const signer = new lwk.Signer(new lwk.Mnemonic(fx.mnemonic), network);
    const verifier = new lwk.ArkVerifier(network, { operator: fx.operator });
    const now = fx.now;
    const oldRound = await rpc('getrawtransaction', [fx.old_round_txid]);
    const round = await rpc('getrawtransaction', [fx.round_txid]);
    const [o0, o1] = fx.old_leaves;
    const n = fx.new_leaf;
    const x = fx.expect;
    // M in display order is its internal bytes reversed.
    assert.strictEqual(Buffer.from(x.connector_internal, 'hex').reverse().toString('hex'), x.connector);
    const keyPath = (l) => signer.arkLeafKey(0, l.owner_nonce).path;
    const sign = (l, built, limits) => {
        assert.strictEqual(lwk.csfsDigest(built.message), built.digest);
        return signer.signCsfs(keyPath(l), built.message, built.digest, limits);
    };
    const margin = { maxUncommitted: fx.margin };

    const f = verifier.forfeitRefresh({ record: o0.record }, n.record, round, fx.c, n.owner, n.owner_nonce,
        fx.refund_delay_seconds, fx.margin, now);
    assert.strictEqual(f.digest, x.forfeit_digest);
    assert.strictEqual(f.connector, x.connector);
    assert.strictEqual(f.leafId, o0.leaf_id);
    assert.strictEqual(f.margin, String(fx.margin));
    assert.strictEqual(f.message.outputs[0].asset, f.output.asset);
    const r = verifier.releaseRefresh(o0.record, oldRound, n.record, round, fx.c, n.owner, n.owner_nonce, now);
    assert.strictEqual(r.digest, x.release_digest);
    assert.strictEqual(r.connector, x.connector);
    assert.strictEqual(r.message.connector, x.connector);
    assert.strictEqual(r.owner, o0.owner);
    const fo = verifier.forfeitOffboard({ record: o1.record }, fx.offboard, round, fx.c, fx.refund_delay_seconds,
        String(fx.margin), now);
    assert.strictEqual(fo.digest, x.offboard_forfeit_digest);
    assert.strictEqual(fo.unlockHash, fx.offboard.unlockHash);
    const ro = verifier.releaseOffboard(o1.record, oldRound, fx.offboard, round, fx.c, now);
    assert.strictEqual(ro.digest, x.offboard_release_digest);

    // Refused: output c not the connector; the new leaf against another round;
    // the old leaf against another round; another wallet's nonce; an unknown
    // field in the old leaf or the offboard.
    assert.throws(() => verifier.forfeitRefresh({ record: o0.record }, n.record, round, 0, n.owner, n.owner_nonce,
        fx.refund_delay_seconds, fx.margin, now), /forfeit refused: .*connector/);
    assert.throws(() => verifier.releaseRefresh(o0.record, oldRound, n.record, oldRound, fx.c, n.owner, n.owner_nonce, now),
        /release refused: the new leaf/);
    assert.throws(() => verifier.releaseRefresh(o0.record, round, n.record, round, fx.c, n.owner, n.owner_nonce, now),
        /release refused: the new leaf/);
    assert.throws(() => verifier.forfeitRefresh({ record: o0.record }, n.record, round, fx.c, n.owner, 'ab'.repeat(32),
        fx.refund_delay_seconds, fx.margin, now), /forfeit refused: the new leaf: owner/);
    assert.throws(() => verifier.forfeitRefresh({ record: o0.record, rounds: [] }, n.record, round, fx.c, n.owner,
        n.owner_nonce, fx.refund_delay_seconds, fx.margin, now), /\{ record \} or \{ coin, rounds \}/);
    assert.throws(() => verifier.forfeitOffboard({ record: o1.record }, { ...fx.offboard, reclaimDelay: 1 }, round, fx.c,
        fx.refund_delay_seconds, fx.margin, now), /unknown field `reclaimDelay`/);
    // The forfeit leaves the margin to whoever broadcasts: under a lower
    // ceiling the signer refuses it.
    assert.throws(() => sign(o0, f, { maxUncommitted: fx.margin - 1 }), /the ceiling is/);

    const sigs = {
        forfeit: sign(o0, f, margin),
        release: sign(o0, r),
        offboard_forfeit: sign(o1, fo, margin),
        offboard_release: sign(o1, ro),
    };
    console.log(`refresh: forfeit ${f.digest}, release ${r.digest}, offboard forfeit ${fo.digest}, offboard release ${ro.digest}, M ${r.connector}`);
    console.log(`SIGNATURES ${JSON.stringify(sigs)}`);
}

async function main() {
    const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(fx.policy_asset), fx.genesis_hash);
    // The wallet restored from its mnemonic: no state but the words.
    const signer = new lwk.Signer(new lwk.Mnemonic(fx.mnemonic), network);
    const verifier = new lwk.ArkVerifier(network, { operator: fx.operator });
    const now = fx.now;
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
                verdict = verifier.verifyLeaf(l.record, roundHex, key.key, key.ownerNonce, now);
            } else {
                assert.throws(() => signer.arkRestoreKey(0, l.record), /the leaf is not this wallet's/);
                verdict = verifier.verifyRound(l.record_hex, roundHex, now);
            }
            if (b.check === null) {
                assert.ok(verdict.accepted, `${b.name}: ${verdict.reason}`);
                assert.strictEqual(verdict.leafId, l.leaf_id);
                assert.strictEqual(verdict.roundTxid, b.round_txid);
                assert.strictEqual(verdict.owned, l.ours);
                accepted++;
                if (l.ours) {
                    store.putPending(l.owner_nonce, 'receive');
                    store.putLeaf(verifier, l.record, roundHex, l.owner, l.owner_nonce, now);
                    store.putPreimage(l.leaf_id, l.preimage);
                    const again = verifier.recheck(b.round_txid, l.record, roundHex, l.owner, l.owner_nonce, now);
                    assert.strictEqual(again.replaced, false);
                }
            } else {
                assert.strictEqual(verdict.accepted, false, `${b.name}: accepted`);
                assert.strictEqual(verdict.check, b.check, `${b.name}: ${verdict.reason}`);
                assert.strictEqual(verdict.failed, `check ${b.check}`);
                if (l.ours) {
                    assert.throws(() => store.putLeaf(verifier, l.record, roundHex, l.owner, l.owner_nonce, now),
                        new RegExp(`leaf refused: check ${b.check}: `));
                }
                refused++;
            }
        }
        const first = b.leaves[0];
        const v0 = first.ours
            ? verifier.verifyLeaf(first.record, roundHex, first.owner, first.owner_nonce, now)
            : verifier.verifyRound(first.record, roundHex, now);
        console.log(`${b.round_txid} ${b.name}: ${v0.accepted ? `accepted; leaf 0 holds ${v0.value} atoms of ${v0.asset}, first expiry ${v0.expiries[0]}` : v0.reason}`);
    }
    const kept = store.leafIds();
    assert.strictEqual(kept.length, 3);
    for (const id of kept) assert.ok(store.leaf(id).preimage);
    assert.ok([...map.keys()].every((k) => k.startsWith('ark/')));
    console.log(`ark_regtest: ${restored} wallet leaf keys restored from the mnemonic; ${accepted} leaves accepted, ${refused} refused by the check named; ${kept.length} kept in the store with their preimages`);
}

const modes = { recheck, refresh };
(modes[fx.mode] || main)().catch((e) => { console.error(e); process.exit(1); });
