// The script-path and message signers through the wasm bindings, against the
// Arca golden vectors (lwk_signer/test_data/arca_vectors.json, test keys only).
//
// tapscriptSighash must give every ordinary script-path signature hash in the
// vectors, and csfsDigest every collaborative, unroll and release digest,
// rebuilt from the message's fields. The signers refuse a digest that is not
// the digest of the fields given, a request without fields, a leaf that does
// not name their key, a chain that is not their network's, a sighash type
// that leaves outputs free unless it is named, and a rebind that leaves more
// to whoever broadcasts than the ceiling.

const assert = require('assert');
const fs = require('fs');
const lwk = require('lwk_node');

const v = JSON.parse(fs.readFileSync(`${__dirname}/../../../lwk_signer/test_data/arca_vectors.json`, 'utf8'));
const genesis = v.inputs.genesis_hash.display;
const display = (internalHex) => Buffer.from(internalHex, 'hex').reverse().toString('hex');

// A reader for the parts of the Elements serialisation the vectors use: no
// issuance inputs, and outputs with an explicit asset and value.
function reader(hex) {
    const b = Buffer.from(hex, 'hex');
    let p = 0;
    const r = {
        skip: (n) => { p += n; },
        u32: () => { const x = b.readUInt32LE(p); p += 4; return x; },
        varint: () => {
            const x = b[p++];
            if (x < 0xfd) return x;
            if (x === 0xfd) { const n = b.readUInt16LE(p); p += 2; return n; }
            return r.u32();
        },
        output: () => {
            assert.strictEqual(b[p], 0x01, 'explicit asset');
            const asset = display(b.subarray(p + 1, p + 33).toString('hex')); p += 33;
            assert.strictEqual(b[p], 0x01, 'explicit value');
            const value = b.readBigUInt64BE(p + 1); p += 9;
            p += b[p] === 0 ? 1 : 33; // nonce
            const len = r.varint();
            const scriptPubkey = b.subarray(p, p + len).toString('hex'); p += len;
            return { asset, value: value.toString(), scriptPubkey };
        },
    };
    return r;
}

function explicitOutputs(txHex) {
    const r = reader(txHex);
    r.skip(4 + 1); // version, witness flag
    const nin = r.varint();
    for (let i = 0; i < nin; i++) {
        r.skip(32);
        assert.strictEqual(r.u32() & 0x80000000, 0, 'issuance inputs are not expected here');
        r.skip(r.varint() + 4); // scriptSig, sequence
    }
    const nout = r.varint();
    return Array.from({ length: nout }, () => r.output());
}

function vectorPath(s) {
    const paths = {
        'leaf/collab': 'leaf', 'checkpoint/collab': 'checkpoint', 'htlc/claim': 'htlc-claim',
        'htlc/claim_both': 'htlc-claim-both', 'htlc/refund_both': 'htlc-refund-both',
    };
    const p = paths[`${s.output}/${s.leaf}`];
    assert(p, `no rebindable path for ${s.name}`);
    return p;
}

function children(params) {
    return params.children.map((c) => ({ asset: display(c.asset), value: c.value, scriptPubkey: '5120' + c.program }));
}

let sighashes = 0;
let digests = 0;
for (const s of v.spends) {
    const w = s.witness;
    if (s.sighash) {
        const got = lwk.tapscriptSighash(s.tx, s.input_index, s.prevouts, w[w.length - 2], w[w.length - 1], 0, genesis);
        assert.strictEqual(got, s.sighash, s.name);
        sighashes++;
    }
    const params = v.outputs[s.output].params;
    let msg = null;
    let digest = null;
    if (s.K) {
        const salt = params.salt || params.salts[s.leaf];
        const coin = reader(s.prevouts[s.input_index]).output();
        // The vectors' outputs are in no batch, so each is named by its own
        // witness program.
        const source = { path: vectorPath(s), leafId: coin.scriptPubkey.slice(4), genesisHash: genesis, salt };
        msg = {
            kind: 'rebind', source, assetIn: coin.asset, valueIn: coin.value,
            outputs: explicitOutputs(s.tx).slice(0, s.m),
        };
        digest = s.digest;
    } else if (s.t !== undefined) {
        msg = { kind: 'unroll', children: children(params), time: s.t };
        digest = s.digest;
    } else if (s.release_digest) {
        msg = { kind: 'release', genesisHash: genesis, children: children(params) };
        digest = s.release_digest;
    }
    if (msg) {
        assert.strictEqual(lwk.csfsDigest(msg), digest, s.name);
        const d = lwk.csfsDescribe(msg);
        assert.strictEqual(d.digest, digest);
        assert.strictEqual(d.kind, msg.kind);
        digests++;
    }
}
assert.strictEqual(sighashes, 16);
assert.strictEqual(digests, 11);

// Refusals. The signer is made for the vectors' chain.
const X = display(v.inputs.assets.X);
const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(X), genesis);
const signer = new lwk.Signer(lwk.Mnemonic.fromRandom(12), network);
assert.strictEqual(signer.genesisHash(), genesis);
const reversed = Buffer.from(genesis, 'hex').reverse().toString('hex');
const node = v.outputs.lowest_node.params;
const unroll = { kind: 'unroll', children: children(node), time: 1791000000 };
const release = { kind: 'release', genesisHash: genesis, children: children(node) };
const sig = signer.signCsfs('m/6/0', unroll, lwk.csfsDigest(unroll));
assert.strictEqual(sig.length, 128);
assert.strictEqual(signer.signCsfs('m/6/0', release, lwk.csfsDigest(release)).length, 128);
assert.throws(() => signer.signCsfs('m/6/0', unroll, lwk.csfsDigest(release)), /does not match the message/);
assert.throws(() => signer.signCsfs('m/6/0', undefined, lwk.csfsDigest(unroll)), /MessageDto/);
assert.throws(() => signer.signCsfs('m/6/0', { kind: 'unroll', children: [], time: 1791000000 }, sig.slice(0, 64)), /at least one child/);
const releaseElsewhere = { ...release, genesisHash: reversed };
assert.throws(() => signer.signCsfs('m/6/0', releaseElsewhere, lwk.csfsDigest(releaseElsewhere)), /not this wallet's/);

// A rebind names its leaf and path, states what it leaves to whoever
// broadcasts, and is refused above the ceiling.
const rebind = {
    kind: 'rebind',
    source: { path: 'leaf', leafId: 'a1'.repeat(32), genesisHash: genesis, salt: '07'.repeat(32) },
    assetIn: X, valueIn: '10000000',
    outputs: [{ asset: X, value: 1000, scriptPubkey: v.inputs.operator_script_pubkey }],
};
const described = lwk.csfsDescribe(rebind);
assert.ok(described.lines[0].includes('a1'.repeat(32)) && described.lines[0].includes('(path leaf)'), described.lines[0]);
assert.ok(described.lines.some((l) => l.includes('leave 9999000 atoms uncommitted: whoever broadcasts')), described.lines);
const d = lwk.csfsDigest(rebind);
assert.throws(() => signer.signCsfs('m/6/0', rebind, d, { feeFloorPerKvb: 1000 }),
    /leave 9999000 atoms .* uncommitted, for whoever broadcasts; the ceiling is 1120/);
assert.throws(() => signer.signCsfs('m/6/0', rebind, d), /the ceiling is 0/);
assert.strictEqual(signer.signCsfs('m/6/0', rebind, d, { maxUncommitted: '9999000' }).length, 128);
assert.throws(() => signer.signCsfs('m/6/0', rebind, d, { feeFloorPerKvb: 1, maxUncommitted: 1 }), /not both/);
const fair = { ...rebind, outputs: [{ ...rebind.outputs[0], value: 10000000 - 1120 }] };
assert.strictEqual(signer.signCsfs('m/6/0', fair, lwk.csfsDigest(fair), { feeFloorPerKvb: 1000 }).length, 128);
const rebindElsewhere = { ...rebind, source: { ...rebind.source, genesisHash: reversed } };
assert.throws(() => signer.signCsfs('m/6/0', rebindElsewhere, lwk.csfsDigest(rebindElsewhere), { maxUncommitted: '9999000' }),
    /not this wallet's/);
assert.throws(() => lwk.csfsDigest({ ...rebind, source: { ...rebind.source, path: 'exit' } }), /unknown rebindable path/);

const exit = v.spends.find((s) => s.name === 'leaf/exit');
const tap = (type, g, allow) => signer.signTapscript('m/6/0', exit.tx, 0, exit.prevouts, exit.witness[1], exit.witness[2], type, g, allow);
assert.throws(() => tap(0, genesis), /is not pushed in the leaf script/);
assert.throws(() => tap(0, reversed), /not this signer's network/);
// SIGHASH_NONE is refused unless named; named, the signer goes on to its key check.
assert.throws(() => tap(2, genesis), /sighash type none leaves every output free/);
assert.throws(() => tap(2, genesis, 'single'), /sighash type none leaves every output free/);
assert.throws(() => tap(2, genesis, 'NONE'), /is not a name the signer knows/);
assert.throws(() => tap(2, genesis, 'none'), /is not pushed in the leaf script/);
const lines = lwk.tapscriptDescribe(exit.tx, 0, exit.prevouts, exit.witness[1], exit.witness[2], 0, genesis);
assert.ok(lines.some((l) => l.includes('covers every output')), lines);
const noneLines = lwk.tapscriptDescribe(exit.tx, 0, exit.prevouts, exit.witness[1], exit.witness[2], 2, genesis);
assert.ok(noneLines.some((l) => l.includes('covers no output, so whoever holds it can send this coin anywhere')), noneLines);
const collabCb = v.outputs.leaf.leaves.collab.control_block;
assert.throws(() => lwk.tapscriptSighash(exit.tx, 0, exit.prevouts, exit.witness[1], collabCb, 0, genesis),
    /does not commit the leaf/);

console.log(`arca_signers: ${sighashes} sighashes and ${digests} message digests match the vectors; refusals hold`);
