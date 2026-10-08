// The contract engine in the wasm build reproduces every golden vector of the
// templates the kit carries and of the version 2 fixture, and refuses every
// case of the shared refusal corpus for its reason: the files
// sequentia-contracts' Rust reader and its Python, JavaScript and Go mirrors
// check (lwk_contracts/templates/PIN.json names the revision).
//
//   wasm-pack build --dev --target nodejs --out-dir pkg_node; cd tests/node; npm install; node contract_vectors.js
const fs = require('fs')
const path = require('path')
const assert = require('assert')
const lwk = require(process.env.LWK_WASM_PKG || 'lwk_node')

const DIR = path.join(__dirname, '../../../lwk_contracts/templates')
const read = p => fs.readFileSync(p, 'utf8')
const sources = d => Object.fromEntries(fs.readdirSync(d).filter(f => f.endsWith('.simf')).map(f => [f, read(path.join(d, f))]))
const errText = e => (e && (e.message || (typeof e.toString === 'function' && e.toString()))) || String(e)

function vectors (dir) {
  const d = path.join(DIR, dir)
  const t = new lwk.ContractTemplate(read(path.join(d, 'descriptor.json')), JSON.stringify(sources(d)))
  const v = JSON.parse(read(path.join(d, 'vectors.json')))
  assert.strictEqual(v.template_hash, t.hash())
  const chains = JSON.parse(read(path.join(d, 'descriptor.json'))).chains
  let n = 0
  for (const a of v.addresses) {
    const inst = new lwk.ContractInstance(t, JSON.stringify({ instance: v.vectors, template_hash: t.hash(), params: a.params, ...(v.vectors === 2 ? { slots: a.slots } : {}), genesis: null }))
    const got = JSON.parse(inst.derived())
    for (const k of ['merkle_root', 'tweak', 'output_key', 'output_key_parity', 'script_pubkey']) assert.deepStrictEqual(got[k], a[k], `${dir}: ${a.name}: ${k}`)
    if (v.vectors === 1) {
      assert.strictEqual(got.leaves.params.hash, a.data_leaf)
      assert.strictEqual(got.leaves.params.data, a.param_bytes)
      assert.strictEqual(got.leaves.program.hash, a.program_leaf)
    } else {
      assert.deepStrictEqual(got.leaves, a.leaves, `${dir}: ${a.name}: leaves`)
    }
    for (const [chain, addr] of Object.entries(a.address)) {
      assert.strictEqual(inst.addressWithPrefix(chains.find(c => c.name === chain).bech32_hrp), addr, `${a.name}: ${chain}`)
    }
    n++
  }
  return n
}

function edit (doc, op) {
  let t = doc
  for (const k of op.at.slice(0, -1)) t = t[k]
  const last = op.at[op.at.length - 1]
  // A field named like Object's own (`__proto__`) is set as a field, not a prototype.
  if ('set' in op) Object.defineProperty(t, last, { value: op.set, enumerable: true, writable: true, configurable: true })
  else if ('delete' in op) { if (Array.isArray(t)) t.splice(last, 1); else delete t[last] }
  else if ('append' in op) t[last].push(op.append)
  else if ('suffix' in op) t[last] = t[last] + op.suffix
  else throw new Error('unknown edit ' + JSON.stringify(op))
}

// The template hash a reseal writes: SHA-256 of the canonical JSON. The
// engine's own reader checks it; this only reseals an edited file.
const crypto = require('crypto')
const canonical = v => Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']'
  : (v && typeof v === 'object') ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}'
    : JSON.stringify(v)

function refusals () {
  const corpus = JSON.parse(read(path.join(DIR, 'fixtures/refusals.json')))
  let refused = 0; let accepted = 0
  for (const c of corpus.cases) {
    const base = c.base === 'mirrors/fixtures/one_key_as_v2' ? path.join(DIR, 'fixtures/one_key_as_v2') : path.join(DIR, c.base.replace('templates/', ''))
    let text = read(path.join(base, 'descriptor.json'))
    if (c.text) {
      for (const [from, to] of c.text) text = text.replace(from, to)
    } else {
      const d = JSON.parse(text)
      for (const op of c.edit) edit(d, op)
      if (c.reseal !== false) d.template_hash = crypto.createHash('sha256').update(canonical(d.template)).digest('hex')
      text = JSON.stringify(d, null, 2)
    }
    let t; let err
    try { t = new lwk.ContractTemplate(text, JSON.stringify(sources(base))) } catch (e) { err = errText(e) }
    if (c.accept) { assert.ok(t, `${c.name}: refused: ${err}`); accepted++; continue }
    if (c.derive) {
      assert.ok(t, `${c.name}: the descriptor is refused: ${err}`)
      const d = JSON.parse(text)
      try {
        // eslint-disable-next-line no-new
        new lwk.ContractInstance(t, JSON.stringify({ instance: d.descriptor, template_hash: t.hash(), params: c.derive.params, ...(d.descriptor === 2 ? { slots: c.derive.slots || {} } : {}), genesis: null }))
        assert.fail(`${c.name}: ACCEPTED`)
      } catch (e) { err = errText(e) }
    } else {
      assert.ok(!t, `${c.name}: ACCEPTED`)
    }
    assert.ok(err.includes(c.expect), `${c.name}: refused, but not for ${JSON.stringify(c.expect)}: ${err}`)
    refused++
  }
  return [refused, accepted]
}

const counts = {}
for (const d of ['one_key', 'one_key_exit', 'faucet_drip', 'fixtures/one_key_as_v2']) counts[d] = vectors(d)
assert.deepStrictEqual(counts, { one_key: 6, one_key_exit: 10, faucet_drip: 8, 'fixtures/one_key_as_v2': 6 })
const [refused, accepted] = refusals()
assert.deepStrictEqual([refused, accepted], [75, 1])
const known = JSON.parse(lwk.ContractTemplate.knownList())
assert.deepStrictEqual(known.map(k => k.name), ['sequentia/one-key', 'sequentia/one-key-exit', 'sequentia/faucet-drip'])
console.log(`vectors reproduced: ${JSON.stringify(counts)}; refusals made for their reason: ${refused}; accepted: ${accepted}; known templates: ${known.length}`)
