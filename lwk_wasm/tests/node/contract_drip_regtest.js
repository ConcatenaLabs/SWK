// A wallet built on the kit's wasm drips from a faucet drip covenant on a
// local chain, under the five-point rule: it recomputes the covenant's
// address, prepares the drip (the program runs against the final
// transaction), shows the approval (template, path, parameters by role, its
// own balance change in every asset), and signs only that digest. The drip
// confirms. A second drip before the interval, a drip above the tier and a
// drip whose successor is not the covenant are refused by the engine before
// anything is signed; the early drip, signed by an engine that is told the
// interval has passed, is refused by the mempool and in a forced block.
// (The other two are forced into blocks by lwk_contracts/tests/drip_regtest.rs,
// which can build what this kit's wasm will not.)
//
//   SEQUENTIA_BIN=/path/to/Sequentia/src node tests/node/contract_drip_regtest.js [log.json]
//
// The chain's data directory is a fresh temporary directory, removed at the end.
const fs = require('fs')
const os = require('os')
const path = require('path')
const net = require('net')
const assert = require('assert')
const { execFileSync, spawn } = require('child_process')
const lwk = require(process.env.LWK_WASM_PKG || 'lwk_node')

const BIN = process.env.SEQUENTIA_BIN
if (!BIN) { console.log('skipped: set SEQUENTIA_BIN'); process.exit(0) }
const LOG = process.argv[2]

// Public test mnemonics, never funded anywhere but a local chain.
const FAUCET = 'exist carry drive collect lend cereal occur much tiger just involve mean'
const TREASURY = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const COIN = 100000000n
const RESERVE = 2000000n * COIN
const FEE_CAP = 100000n
const INTERVAL = 1
const TIME = 1 << 22
const RATE = 1000n // atoms of the dripped asset per 1,000 vB
const KEY_PATH = "m/8383h/1h/0h/0/0"
const DRIP_HASH = '12986f202fbfb850f7699c5d5188f261f276de6c7038142f0a28bbb672b5af34'

const errText = e => (e && (e.message || (typeof e.toString === 'function' && e.toString()))) || String(e)
const hex16 = (n, w) => BigInt(n).toString(16).padStart(w, '0')
const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer(); s.once('error', reject)
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)) })
})
const log = []
const rec = (step, result) => { console.log(`${step}: ${typeof result === 'string' ? result : JSON.stringify(result)}`); log.push({ step, result }) }

async function main () {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'swk-contract-drip-'))
  const [port, rpcport] = [await freePort(), await freePort()]
  fs.writeFileSync(path.join(dir, 'elements.conf'), [
    'chain=elementsregtest', '[elementsregtest]', 'server=1', 'listen=0', `port=${port}`, `rpcport=${rpcport}`,
    'rpcbind=127.0.0.1', 'rpcallowip=127.0.0.1', 'initialfreecoins=2100000000000000', 'anyonecanspendaremine=1',
    'blindedaddresses=0', 'con_default_blinded_addresses=0', 'validatepegin=0', 'con_parent_chain_signblockscript=51',
    'con_any_asset_fees=1', 'evbparams=simplicity:-1:::', 'par=1', 'txindex=1', 'fallbackfee=0.0001', 'maxtxfee=100', ''
  ].join('\n'))
  const node = spawn(path.join(BIN, 'sequentiad'), [`-datadir=${dir}`], { stdio: 'ignore' })
  const cli = (...a) => execFileSync(path.join(BIN, 'sequentia-cli'), [`-datadir=${dir}`, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  const tryCli = (...a) => { try { return { ok: cli(...a) } } catch (e) { return { err: String(e.stderr || e.message).trim() } } }
  const json = (...a) => JSON.parse(cli(...a))
  const stop = () => new Promise(resolve => {
    const done = () => { fs.rmSync(dir, { recursive: true, force: true }); resolve() }
    try { cli('stop') } catch (e) { node.kill() }
    if (node.exitCode !== null) done(); else node.once('exit', done)
  })
  try {
    for (let i = 0; ; i++) {
      try { cli('getblockchaininfo'); break } catch (e) {
        if (i > 240) throw new Error('the node did not start')
        await new Promise(resolve => setTimeout(resolve, 500))
      }
    }
    rec('node', cli('-version').split('\n')[0])
    cli('createwallet', 'treasury')
    const mine = n => cli('generatetoaddress', String(n), cli('getnewaddress'))
    mine(101); cli('rescanblockchain')
    cli('-named', 'sendtoaddress', `address=${cli('getnewaddress')}`, 'amount=1000000', 'fee_asset_label=bitcoin')
    mine(1)
    const policy = json('getsidechaininfo').pegged_asset
    const genesis = cli('getblockhash', '0')
    const tip = () => json('getblockheader', cli('getbestblockhash'))
    const advance = secs => { cli('setmocktime', String(tip().time + secs + 60)); mine(12) }
    const facts = txid => {
      const height = json('getblockheader', json('getrawtransaction', txid, 'true').blockhash).height
      const t = tip()
      return { tip_height: t.height, tip_median_time: t.mediantime, coin_height: height, coin_start_median_time: json('getblockheader', cli('getblockhash', String(height - 1))).mediantime }
    }

    // The wallet: the kit's signer on this chain. Its contract key is the faucet key.
    const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(policy), genesis)
    const wallet = new lwk.Signer(new lwk.Mnemonic(FAUCET), network)
    const treasury = new lwk.Signer(new lwk.Mnemonic(TREASURY), network)
    const faucetKey = wallet.xonlyPublicKeyAt(KEY_PATH)
    const params = {
      ASSET: Buffer.from(policy, 'hex').reverse().toString('hex'),
      FAUCET_KEY: faucetKey,
      TREASURY_KEY: treasury.xonlyPublicKeyAt(KEY_PATH),
      INTERVAL: hex16(INTERVAL, 4),
      FEE_CAP: hex16(FEE_CAP, 16),
      RECOVERY_DELAY: hex16(TIME | 2, 8)
    }
    const tiers = [1000000n, 500n, 100000n, 200n, 10000n, 20n, 2n].map(n => n * COIN)
    ;['TIER1_FLOOR', 'TIER1_MAX', 'TIER2_FLOOR', 'TIER2_MAX', 'TIER3_FLOOR', 'TIER3_MAX', 'TIER4_MAX'].forEach((k, i) => { params[k] = hex16(tiers[i], 16) })
    const template = lwk.ContractTemplate.known(DRIP_HASH)
    const instance = new lwk.ContractInstance(template, JSON.stringify({ instance: 2, template_hash: DRIP_HASH, params, slots: {}, genesis }))
    const covenant = instance.address(network)
    // Point 2: the node decodes the engine's address to the engine's own script.
    assert.strictEqual(json('getaddressinfo', covenant).scriptPubKey, instance.scriptPubkey())
    rec('covenant', { address: covenant, script_pubkey: instance.scriptPubkey(), paths: JSON.parse(instance.paths()).map(p => `${p.name} (${p.kind})`) })

    const fund = cli('-named', 'sendtoaddress', `address=${covenant}`, `amount=${(RESERVE / COIN).toString()}`, 'fee_asset_label=bitcoin')
    mine(1)
    const coinOf = txid => {
      const o = json('getrawtransaction', txid, 'true').vout.find(o => o.scriptPubKey.hex === instance.scriptPubkey())
      return { txid, vout: o.n, script_pubkey: instance.scriptPubkey(), asset: o.asset, amount: Number(BigInt(Math.round(o.value * 1e8))) }
    }
    // The drip pays this wallet's own address on the chain.
    const dest = cli('getnewaddress', '', 'bech32')
    const destScript = json('getaddressinfo', dest).scriptPubKey
    const view = { known: lwk.ContractTemplate.knownList() && JSON.parse(lwk.ContractTemplate.knownList()).map(k => k.hash), registry: { name: 'sequentia/faucet-drip', version: 1 }, assets: { [policy]: { ticker: 'tSEQ', precision: 8 } } }
    const prepare = (coin, amount, chain) => {
      let fee = (581n * RATE + 999n) / 1000n
      for (let i = 0; i < 2; i++) {
        const req = instance.planDrip(JSON.stringify(coin), dest, BigInt(amount), fee)
        const spend = lwk.ContractSpend.build(instance, network, req, JSON.stringify([destScript]), JSON.stringify(chain))
        const approval = lwk.ContractApproval.prepare(spend, wallet, JSON.stringify(view))
        const need = (BigInt(JSON.parse(approval.summary()).vsize) * RATE + 999n) / 1000n
        if (need === fee) return approval
        fee = need
      }
      throw new Error('the size does not depend on the fee')
    }
    const refusedBy = (label, f, want) => {
      let e
      try { f(); assert.fail(`${label}: not refused`) } catch (x) { e = errText(x) }
      assert.ok(e.includes(want), `${label}: refused, but not for ${want}: ${e}`)
      rec(label, e)
    }

    let coin = coinOf(fund)
    refusedBy('engine refuses the first drip before the interval', () => prepare(coin, 500n * COIN, facts(coin.txid)), 'non-BIP68-final')

    advance(INTERVAL * 512)
    const a = prepare(coin, 500n * COIN, facts(coin.txid))
    const shown = JSON.parse(a.summary())
    // What the wallet shows before it signs.
    const screen = {
      template: shown.template.shown,
      path: `${shown.path.name}: ${shown.path.effect}`,
      who: shown.path.who,
      params: shown.params.map(p => `${p.label} [${p.role}]: ${p.shown}`),
      wallet_change: shown.wallet_change.map(c => c.shown),
      contract_change: shown.contract.change.map(c => c.shown),
      payments: shown.payments.map(p => p.shown),
      fee: shown.fee.map(f => f.shown),
      checks: shown.checks,
      digest: shown.digest
    }
    rec('approval shown for drip 1', screen)
    assert.strictEqual(shown.template.shown, 'sequentia/faucet-drip v1 (registered)')
    assert.strictEqual(shown.path.name, 'drip')
    assert.deepStrictEqual(shown.wallet_change.map(c => c.shown), ['500.00000000 tSEQ'])
    refusedBy('a digest other than the one shown', () => wallet.signContractSpend(a, '00'.repeat(32)), 'is not what was shown')
    refusedBy('another wallet signing the approval', () => treasury.signContractSpend(a, shown.digest), 'is signed by FAUCET_KEY')
    const tx1 = wallet.signContractSpend(a, shown.digest)
    const txid1 = cli('sendrawtransaction', tx1)
    mine(1)
    const c1 = json('getrawtransaction', txid1, 'true')
    assert.ok(c1.confirmations >= 1)
    assert.strictEqual(c1.vsize, shown.vsize)
    rec('drip 1 confirmed', { txid: txid1, vsize: c1.vsize, weight: c1.weight, fee: shown.fee[0].shown })

    coin = coinOf(txid1)
    refusedBy('engine refuses drip 2 before the interval', () => prepare(coin, 500n * COIN, facts(coin.txid)), 'non-BIP68-final')
    const lie = facts(coin.txid); lie.tip_median_time += 10000
    const early = prepare(coin, 500n * COIN, lie)
    const earlyHex = wallet.signContractSpend(early, JSON.parse(early.summary()).digest)
    const m = json('testmempoolaccept', JSON.stringify([earlyHex]))[0]['reject-reason']
    const b = tryCli('generateblock', cli('getnewaddress'), JSON.stringify([earlyHex])).err
    assert.strictEqual(m, 'non-BIP68-final')
    assert.ok(b.includes('bad-txns-nonfinal'), b)
    rec('chain refuses drip 2 before the interval (signed by an engine told the interval had passed)', { mempool: m, block: b })

    advance(INTERVAL * 512)
    const f2 = facts(coin.txid)
    const tier = instance.dripTier(BigInt(coin.amount))
    refusedBy('engine refuses a drip above the tier', () => prepare(coin, tier + 1n, f2), 'is above the')
    // The same, asked for directly: the program run refuses it.
    const req = JSON.parse(instance.planDrip(JSON.stringify(coin), dest, tier, 581n))
    req.outputs[1].amount = Number(tier) + 1; req.outputs[0].amount -= 1
    refusedBy('engine refuses a drip above the tier, asked for directly (program run)', () => lwk.ContractApproval.prepare(lwk.ContractSpend.build(instance, network, JSON.stringify(req), '[]', JSON.stringify(f2)), wallet, JSON.stringify(view)), 'the check that fails is `assert!(jet::le_64(drip, tier(reserve, floors, maxes)))`')
    const bad = JSON.parse(instance.planDrip(JSON.stringify(coin), dest, 500n * COIN, 581n))
    bad.outputs[0].script = undefined; bad.outputs[0].address = dest
    refusedBy('engine refuses a successor that is not the covenant', () => lwk.ContractSpend.build(instance, network, JSON.stringify(bad), '[]', JSON.stringify(f2)), 'is said to return to the contract, but pays the script')
    bad.outputs[0].to = 'pay'
    refusedBy('engine refuses a successor that is not the covenant, named as a payment (program run)', () => lwk.ContractApproval.prepare(lwk.ContractSpend.build(instance, network, JSON.stringify(bad), '[]', JSON.stringify(f2)), wallet, JSON.stringify(view)), 'the check that fails is')
    // A template the wallet does not know is not signed.
    refusedBy('a template not on the wallet\'s list', () => lwk.ContractApproval.prepare(lwk.ContractSpend.build(instance, network, instance.planDrip(JSON.stringify(coin), dest, 500n * COIN, 581n), '[]', JSON.stringify(f2)), wallet, JSON.stringify({ known: [] })), 'is not on this wallet\'s list of known templates')
    // A key outside the contract account is not used.
    refusedBy('a key that is not a contract key', () => lwk.ContractApproval.prepare(lwk.ContractSpend.build(instance, network, instance.planDrip(JSON.stringify(coin), dest, 500n * COIN, 581n), '[]', JSON.stringify(f2)), wallet, JSON.stringify({ known: [DRIP_HASH], key_path: "m/84h/1h/0h/0/0" })), 'is not a contract key')

    const a2 = prepare(coin, 500n * COIN, f2)
    const txid2 = cli('sendrawtransaction', wallet.signContractSpend(a2, JSON.parse(a2.summary()).digest))
    mine(1)
    assert.ok(json('getrawtransaction', txid2, 'true').confirmations >= 1)
    rec('drip 2 confirmed', { txid: txid2 })
    if (LOG) fs.writeFileSync(LOG, JSON.stringify(log, null, 2))
    console.log('all passed')
  } finally {
    await stop()
  }
}

main().catch(e => { console.error(e); process.exit(1) })
