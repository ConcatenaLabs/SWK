// Arca leaves through the wasm bindings, against the Arca record vectors
// (lwk_wollet/tests/data/arca_records.json, copied from the arca repository)
// and the byte-order vector (ark_byte_order.json, written by
// ark_byte_order.py with hashlib alone). Test keys only.
//
// Every record decodes from both forms, re-encodes byte for byte, has the
// vector's leaf id and verifies against its round; every refusal vector is
// refused with its kind; ids are display hex at this edge and internal bytes
// in the record and in the rebindable message; leaf keys follow the owner
// nonce; the wallet's policy and its key are enforced, a leaf taken from a
// round against the acceptance horizon and a leaf held or given against the
// exit deadline, at the time each call names; the store keeps what verifies
// for a nonce the wallet waits on, refuses a second leaf under one nonce, and
// never keeps a removed leaf or its nonce again. Every coin received out of
// round in the transfer vectors (arca_transactions.json) verifies, one of
// them resting on a board; its lineage names what to look up on-chain; a coin
// whose lineage is paid on-chain, or whose board is spent, and a record
// promising one leaf twice are refused with their kind.

const assert = require('assert');
const fs = require('fs');
const lwk = require('lwk_node');

const data = `${__dirname}/../../../lwk_wollet/tests/data`;
const v = JSON.parse(fs.readFileSync(`${data}/arca_records.json`, 'utf8'));
const bo = JSON.parse(fs.readFileSync(`${data}/ark_byte_order.json`, 'utf8'));
const genesis = v.inputs.genesis_hash;
const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(v.inputs.asset), genesis);

// A wallet on the vectors' chain, told the vectors' operator key. It checks
// a batch's leaves at its creation: 28 days before its first expiry.
const DAY = 86400;
function verifier(extra = {}) {
    return new lwk.ArkVerifier(network, { operator: v.inputs.operator, ...extra });
}
const created = (batch) => batch.inputs.expiries[0] - 28 * DAY;

// 1. Every record.
let n = 0;
let longer = 0;
let unreserved = 0;
for (const b of v.batches) {
    const ver = verifier();
    const now = created(b);
    for (const r of b.records) {
        const name = `${b.name} / leaf ${r.leaf}`;
        const leaf = b.inputs.leaves[r.leaf];
        const fromHex = lwk.arkParseRecord(r.binary);
        const fromJson = lwk.arkParseRecord(r.json);
        assert.strictEqual(fromHex.leafId, r.leaf_id, name);
        assert.strictEqual(fromJson.leafId, r.leaf_id, name);
        assert.strictEqual(fromJson.hex, r.binary, name);
        assert.strictEqual(fromHex.json, r.json, name);
        assert.strictEqual(fromHex.owner, leaf.owner, name);
        assert.strictEqual(fromHex.ownerNonce, leaf.owner_nonce, name);
        let res = ver.verifyLeaf(r.binary, b.round.tx, leaf.owner, leaf.owner_nonce, now);
        if (!res.accepted && res.failed === 'wallet policy' && /exit delay/.test(res.reason)) {
            // A longer exit delay than the default 48 hours: refused, until the
            // wallet accepts that delay.
            longer++;
            res = verifier({ maxExitDelaySeconds: fromHex.exitDelaySeconds })
                .verifyLeaf(r.json, b.round.tx, leaf.owner, leaf.owner_nonce, now);
        }
        if (!res.accepted && res.failed === 'wallet policy' && /holds a reserve of 0/.test(res.reason)) {
            // No reserve on a node or the entry: refused by the default floor
            // of one atom, until the wallet sets none.
            unreserved++;
            res = verifier({ minReserveAtoms: 0 })
                .verifyLeaf(r.json, b.round.tx, leaf.owner, leaf.owner_nonce, now);
        }
        assert.ok(res.accepted, `${name}: ${res.reason}`);
        assert.strictEqual(res.leafId, r.leaf_id, name);
        assert.strictEqual(res.batchVout, b.round.batch_vout, name);
        assert.strictEqual(res.value, String(leaf.value), name);
        assert.strictEqual(res.asset, v.inputs.asset, name);
        assert.strictEqual(res.owned, true);
        assert.strictEqual(res.exitDeadline, b.inputs.expiries[0] - 3 * 86400);
        n++;
    }
}
assert.strictEqual(n, 61);
assert.strictEqual(longer, 1);
assert.strictEqual(unreserved, 7);
// The tree bounds: a path deeper than the wallet allows, and both reserve
// floors at once.
const deep = v.batches.find((b) => b.records.length < b.inputs.leaves.length);
const dr = deep.records[0];
const dl = deep.inputs.leaves[dr.leaf];
const shallow = verifier({ maxLevels: 1 }).verifyLeaf(dr.json, deep.round.tx, dl.owner, dl.owner_nonce, created(deep));
assert.strictEqual(shallow.accepted, false);
assert.ok(/a path of \d+ levels; the wallet accepts 1 at most/.test(shallow.reason), shallow.reason);
assert.throws(() => verifier({ minReserveAtoms: 0, minReserveFeeRate: { floorPerKvb: 1, multiple: 1 } }), /not both/);
// A field the policy does not name is refused, not ignored: a misspelt bound
// would otherwise take its default without a word.
assert.throws(() => verifier({ maxExitDelaySecond: 172800 }), /unknown field `maxExitDelaySecond`/);
assert.throws(() => verifier({ minReserveFeeRate: { floorPerKvb: 1, multiple: 1, mutliple: 4 } }), /unknown field `mutliple`/);

// 2. The refusal vectors, by kind, from both the reader and the verifier.
const any = v.batches[1];
const anyLeaf = any.inputs.leaves[0];
let refusals = 0;
for (const bad of [...v.invalid_binary.map((b) => [b.name, b.binary, b.kind]),
                   ...v.invalid_json.map((b) => [b.name, b.json, b.kind])]) {
    const [name, text, kind] = bad;
    assert.throws(() => lwk.arkParseRecord(text), new RegExp(`record refused \\(kind ${kind}\\)`), name);
    const res = verifier().verifyLeaf(text, any.round.tx, anyLeaf.owner, anyLeaf.owner_nonce, created(any));
    assert.strictEqual(res.accepted, false, name);
    assert.strictEqual(res.failed, 'record', name);
    assert.strictEqual(res.kind, kind, name);
    refusals++;
}
assert.strictEqual(refusals, 30);

// 3. Byte order: display hex at this edge, internal bytes in the record and
// in the rebindable message.
const p = lwk.arkParseRecord(bo.record_hex);
const raw = Buffer.from(bo.record_hex, 'hex');
for (const [field, got] of [['asset', p.asset], ['genesis_hash', p.genesisHash], ['token', p.token]]) {
    const f = bo[field];
    assert.strictEqual(got, f.display, field);
    assert.strictEqual(raw.subarray(f.binary_offset, f.binary_offset + 32).toString('hex'), f.internal, field);
    assert.strictEqual(Buffer.from(f.display, 'hex').reverse().toString('hex'), f.internal, field);
}
assert.strictEqual(p.leafId, bo.leaf_id);
const out = bo.rebind.output;
const outputs = [{ asset: out.asset_display, value: out.value, scriptPubkey: out.script_pubkey }];
const fromRecord = { kind: 'rebind', source: { record: bo.record_hex }, assetIn: p.asset, valueIn: bo.rebind.value_in, outputs };
const named = {
    kind: 'rebind', source: { path: 'leaf', leafId: bo.leaf_id, genesisHash: bo.genesis_hash.display, salt: bo.salt },
    assetIn: p.asset, valueIn: bo.rebind.value_in, outputs,
};
assert.strictEqual(lwk.csfsDigest(fromRecord), bo.rebind.digest);
assert.strictEqual(lwk.csfsDigest({ ...fromRecord, source: { record: bo.record_json } }), bo.rebind.digest);
assert.strictEqual(lwk.csfsDigest(named), bo.rebind.digest);
assert.ok(lwk.csfsDescribe(fromRecord).lines[0].includes(bo.leaf_id));
// A release: M in display hex here, in internal order in the message.
const rel = bo.release;
assert.strictEqual(Buffer.from(rel.connector.display, 'hex').reverse().toString('hex'), rel.connector.internal);
const relMsg = {
    kind: 'release', genesisHash: rel.genesis_display, connector: rel.connector.display,
    children: rel.children.map((c) => ({ asset: c.asset_display, value: c.value, scriptPubkey: c.script_pubkey })),
};
assert.strictEqual(lwk.csfsDigest(relMsg), rel.digest);
assert.notStrictEqual(lwk.csfsDigest({ ...relMsg, connector: rel.connector.internal }), rel.digest);

// 4. Keys follow the owner nonce.
const nonce0 = Buffer.from([...Array(32).keys()]).toString('hex');
const path0 = "m/6'/0'/330116911'/809309685'/1623618847'/382661522'";
assert.strictEqual(lwk.arkLeafKeyPath(0, nonce0), path0);
const signer = new lwk.Signer(lwk.Mnemonic.fromRandom(12), network);
const k0 = signer.arkLeafKey(0, nonce0);
assert.strictEqual(k0.path, path0);
assert.strictEqual(k0.key, signer.xonlyPublicKeyAt(path0));
const fresh = [lwk.arkNewOwnerNonce(), lwk.arkNewOwnerNonce()];
assert.ok(/^[0-9a-f]{64}$/.test(fresh[0]) && fresh[0] !== fresh[1]);
assert.notStrictEqual(signer.arkLeafKey(0, fresh[0]).key, signer.arkLeafKey(0, fresh[1]).key);
assert.throws(() => signer.arkRestoreKey(0, bo.record_hex), /not this wallet's/);

// 5. The wallet's policy and its key.
const b1 = v.batches[1];
const r1 = b1.records[2];
const l1 = b1.inputs.leaves[r1.leaf];
const check = (ver, owner, nonce, failed, why, now = created(b1)) => {
    const res = ver.verifyLeaf(r1.binary, b1.round.tx, owner, nonce, now);
    assert.strictEqual(res.accepted, false);
    assert.strictEqual(res.failed, failed, res.reason);
    assert.ok(why.test(res.reason), res.reason);
    return res.reason;
};
const reasons = [
    check(verifier({ operator: l1.owner }), l1.owner, l1.owner_nonce, 'wallet policy', /operator key/),
    check(verifier(), l1.owner, l1.owner_nonce, 'wallet policy', /first expiry/, b1.inputs.expiries[0] - DAY),
    check(verifier({ minNoticeSeconds: 48 * 3600 }), l1.owner, l1.owner_nonce, 'wallet policy', /notice/),
    check(verifier(), l1.owner, 'ab'.repeat(32), 'owner', /owner nonce/),
    check(verifier(), b1.inputs.leaves[0].owner, l1.owner_nonce, 'owner', /another owner/),
];
const elsewhere = new lwk.ArkVerifier(lwk.Network.regtestDefault(), { operator: v.inputs.operator });
reasons.push(check(elsewhere, l1.owner, l1.owner_nonce, 'wallet policy', /another chain/));
assert.strictEqual(verifier().verifyRound(r1.json, b1.round.tx, created(b1)).owned, false);
const round1 = lwk.Transaction.fromString(b1.round.tx).txid().toString();
const again = verifier().recheck(round1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, created(b1));
assert.strictEqual(again.accepted, true);
assert.strictEqual(again.replaced, false);
// `now` belongs to each call, never to the verifier.
assert.throws(() => new lwk.ArkVerifier(network, { operator: v.inputs.operator, now: created(b1) }), /the policy takes no `now`/);
// A call without it is refused, not run at time zero: by the bindings' own
// argument check in a debug build, by the policy (time 0 is not a median
// time) in a release build.
assert.throws(() => verifier().verifyLeaf(r1.json, b1.round.tx, l1.owner, l1.owner_nonce),
    /expected a number argument|now: /);
assert.throws(() => verifier().verifyLeaf(r1.json, b1.round.tx, l1.owner, l1.owner_nonce, 0), /now: /);

// A leaf taken from a round must leave the acceptance horizon, 27 days; a
// leaf held (recheck) or given (verifyRound) need only leave the exit
// deadline, three days before the first expiry. Review R4, F4: the re-check
// applied the horizon and refused every leaf from its batch's second day.
const deadline = b1.inputs.expiries[0] - 3 * DAY;
const later = [created(b1) + 2 * DAY, created(b1) + 10 * DAY, deadline];
for (const now of later) {
    const ver = verifier();
    const taken = ver.verifyLeaf(r1.json, b1.round.tx, l1.owner, l1.owner_nonce, now);
    assert.strictEqual(taken.accepted, false, `taken at ${now}`);
    assert.ok(/first expiry/.test(taken.reason), taken.reason);
    const held = ver.recheck(round1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, now);
    assert.ok(held.accepted, `held at ${now}: ${held.reason}`);
    assert.strictEqual(held.replaced, false);
    assert.ok(ver.verifyRound(r1.json, b1.round.tx, now).accepted, `given at ${now}`);
    // The caller's horizon plays no part in a re-check.
    assert.ok(verifier({ horizonSeconds: 27 * DAY }).recheck(round1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, now).accepted);
}
for (const ver of [verifier(), verifier({ horizonSeconds: 0 })]) {
    const past = ver.recheck(round1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, deadline + 1);
    assert.strictEqual(past.accepted, false);
    assert.strictEqual(past.failed, 'wallet policy');
    assert.ok(/first expiry/.test(past.reason), past.reason);
    assert.strictEqual(ver.verifyRound(r1.json, b1.round.tx, deadline + 1).accepted, false);
}
reasons.push(verifier().recheck(round1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, deadline + 1).reason);

// 6. The store, over a JavaScript Map.
const map = new Map();
const storage = {
    get: (k) => map.get(k) || null,
    put: (k, val) => { map.set(k, new Uint8Array(val)); },
    remove: (k) => { map.delete(k); },
    isPersisted: () => false,
};
const store = new lwk.ArkStore(storage);
const ver1 = verifier();
const t1 = created(b1);
// A record nobody asked for is not kept.
assert.throws(() => store.putLeaf(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, t1), /is not one this wallet is waiting on/);
store.putPending(l1.owner_nonce, 'receive');
assert.strictEqual(store.pending().length, 1);
const id = store.putLeaf(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, t1);
assert.strictEqual(id, r1.leaf_id);
assert.strictEqual(store.pending().length, 0);
const other = b1.records[3];
const lo = b1.inputs.leaves[other.leaf];
store.putPending(lo.owner_nonce, 'receive');
store.putLeaf(ver1, other.binary, b1.round.tx, lo.owner, lo.owner_nonce, t1);
assert.deepStrictEqual(store.leafIds(), [r1.leaf_id, other.leaf_id].sort());
const kept = store.leaf(id);
assert.strictEqual(kept.record, r1.json);
assert.strictEqual(kept.batchVout, b1.round.batch_vout);
assert.throws(() => store.putPreimage(id, '00'.repeat(32)), /does not hash to the leaf's unlock hash/);
assert.throws(() => store.putLeaf(ver1, r1.json, b1.round.tx, l1.owner, 'ab'.repeat(32), t1), /leaf refused: owner/);
// Ten days on, the round checked again is kept; past the exit deadline it
// is refused.
store.setRound(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, t1 + 10 * DAY);
assert.throws(() => store.setRound(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, deadline + 1), /leaf refused: wallet policy/);
assert.throws(() => store.putUnrollAuthorisation(id, 0, 1800000000, '00'.repeat(64)), /not the owner's unroll authorisation/);
store.removeLeaf(other.leaf_id);
assert.deepStrictEqual(store.leafIds(), [r1.leaf_id]);
assert.strictEqual(store.leaf(other.leaf_id), undefined);
// Review R4, F8: a removed leaf, and its nonce, are never kept again, nor
// in a restore.
assert.throws(() => store.putLeaf(ver1, other.binary, b1.round.tx, lo.owner, lo.owner_nonce, t1), /was removed from the store/);
assert.throws(() => store.putRestoredLeaf(ver1, other.binary, b1.round.tx, lo.owner, lo.owner_nonce, t1), /was removed from the store/);
assert.throws(() => store.putPending(lo.owner_nonce, 'again'), /already has owner nonce/);
// A restore, into an empty store, keeps a leaf the wallet holds without its
// nonce pending, checked against the exit deadline: ten days on it is kept
// (as a new leaf it would be refused), past the deadline it is refused.
const map2 = new Map();
const fresh2 = new lwk.ArkStore({
    get: (k) => map2.get(k) || null,
    put: (k, val) => { map2.set(k, new Uint8Array(val)); },
    remove: (k) => { map2.delete(k); },
    isPersisted: () => false,
});
fresh2.putPending(l1.owner_nonce, 'receive');
assert.throws(() => fresh2.putLeaf(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, t1 + 10 * DAY), /leaf refused: wallet policy/);
assert.strictEqual(fresh2.putRestoredLeaf(ver1, r1.json, b1.round.tx, l1.owner, l1.owner_nonce, t1 + 10 * DAY), r1.leaf_id);
assert.throws(() => fresh2.putRestoredLeaf(ver1, other.binary, b1.round.tx, lo.owner, lo.owner_nonce, deadline + 1), /leaf refused: wallet policy/);
assert.ok([...map.keys()].every((k) => k.startsWith('ark/')), [...map.keys()]);

// 7. Coins received out of round (the transfer vectors).
const t = JSON.parse(fs.readFileSync(`${data}/arca_transactions.json`, 'utf8'));
const tnet = lwk.Network.regtestWithGenesis(new lwk.AssetId(t.inputs.asset), t.inputs.genesis_hash);
const tver = new lwk.ArkVerifier(tnet, { operator: t.inputs.operator });
const trounds = [...t.transfer.inputs.rounds, ...t.transfer.inputs.boards];
const tnow = Number(t.transfer.inputs.now);
let coins = 0;
let onBoards = 0;
for (const [name, c] of Object.entries(t.transfer.records)) {
    const ok = tver.verifyCoin(c.binary, trounds, c.owner, c.owner_nonce, tnow);
    assert.ok(ok.accepted, `${name}: ${ok.reason}`);
    assert.strictEqual(ok.coinId, c.id, name);
    assert.strictEqual(ok.lineageCheck, 'operator-rule');
    // What to look up: the lineage's scripts and the boards it rests on.
    const lin = tver.coinLineage(c.binary, trounds, tnow);
    assert.deepStrictEqual(lin.lineage, ok.lineage);
    assert.ok(lin.lineage.length > 0 && lin.lineage.every((l) => ['leaf', 'checkpoint'].includes(l.kind)), name);
    const none = tver.verifyCoin(c.binary, trounds, c.owner, c.owner_nonce, tnow, { paid: [], spent: [] });
    assert.strictEqual(none.lineageCheck, 'indexed', name);
    for (const l of lin.lineage) {
        const paid = tver.verifyCoin(c.binary, trounds, c.owner, c.owner_nonce, tnow, { paid: [l.scriptPubkey] });
        assert.strictEqual(paid.accepted, false, name);
        assert.strictEqual(paid.kind, 'on_chain', paid.reason);
        assert.ok(paid.reason.includes(l.kind), paid.reason);
    }
    for (const b of lin.boards) {
        const spent = tver.verifyCoin(c.binary, trounds, c.owner, c.owner_nonce, tnow, { spent: [b] });
        assert.strictEqual(spent.kind, 'on_chain', spent.reason);
        assert.ok(spent.reason.includes('board'), spent.reason);
        onBoards++;
    }
    // Another key, another nonce.
    assert.strictEqual(tver.verifyCoin(c.binary, trounds, t.inputs.operator, c.owner_nonce, tnow).kind, 'owner');
    assert.strictEqual(tver.verifyCoin(c.binary, trounds, c.owner, 'ab'.repeat(32), tnow).kind, 'owner');
    coins++;
}
assert.strictEqual(coins, 7);
assert.strictEqual(onBoards, 2);
for (const x of t.transfer.refused_records) {
    const r = tver.verifyCoin(x.binary, trounds, x.owner, x.owner_nonce, tnow);
    assert.strictEqual(r.accepted, false, x.name);
    assert.strictEqual(r.kind, x.kind, r.reason);
    reasons.push(`${x.name}: ${r.reason} (kind ${r.kind})`);
}
// Without the board's transaction there is nothing to rest on.
const e = t.transfer.records.E;
assert.strictEqual(tver.verifyCoin(e.binary, t.transfer.inputs.rounds, e.owner, e.owner_nonce, tnow).kind, 'round');
assert.throws(() => tver.verifyCoin(e.binary, trounds, e.owner, e.owner_nonce, tnow, { payd: [] }), /unknown field `payd`/);
// Byte order: the coin's asset is display hex here, internal in its record.
const bc = bo.coin;
const vc = tver.verifyCoin(bc.binary, trounds, bc.owner, bc.owner_nonce, tnow);
assert.strictEqual(vc.coinId, bc.id);
assert.strictEqual(vc.asset, bc.asset.display);
assert.strictEqual(Buffer.from(bc.binary, 'hex').subarray(bc.asset.binary_offset, bc.asset.binary_offset + 32).toString('hex'), bc.asset.internal);

console.log(`ark_records: ${coins} received coins verified (${onBoards} resting on a board), lineage checks and refusals by kind hold`);
console.log(`ark_records: ${n} records verified (${longer} under a longer exit delay, ${unreserved} with no reserve floor), ${refusals} refusal vectors refused by kind; byte order, keys, policy and store hold`);
for (const r of reasons) console.log(`  refused: ${r}`);
