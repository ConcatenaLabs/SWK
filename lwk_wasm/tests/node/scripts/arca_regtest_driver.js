// The wasm side of arca_regtest.py: SWK's signers behind a pipe, one JSON
// request per line on stdin and one JSON reply per line on stdout.
const lwk = require('lwk_node');
const readline = require('readline');
// Each signer's mnemonic is generated here and never leaves this process.
const signers = [];
function signer(id) { return signers[id]; }
function handle(r) {
  switch (r.op) {
    case 'new': {
      // A signer for the regtest chain: its network carries the chain's genesis hash.
      const network = lwk.Network.regtestWithGenesis(new lwk.AssetId(r.policyAsset), r.genesis);
      signers.push(new lwk.Signer(lwk.Mnemonic.fromRandom(12), network));
      return signers.length - 1;
    }
    case 'xonly': return signer(r.signer).xonlyPublicKeyAt(r.path);
    case 'tapscript': return signer(r.signer).signTapscript(r.path, r.tx, r.inputIndex, r.prevouts, r.leaf, r.controlBlock, r.sighashType, r.genesis, r.allowSighash);
    case 'sighash': return lwk.tapscriptSighash(r.tx, r.inputIndex, r.prevouts, r.leaf, r.controlBlock, r.sighashType, r.genesis);
    case 'tapdescribe': return lwk.tapscriptDescribe(r.tx, r.inputIndex, r.prevouts, r.leaf, r.controlBlock, r.sighashType, r.genesis);
    case 'csfs': return signer(r.signer).signCsfs(r.path, r.message, r.digest, r.limits);
    case 'digest': return lwk.csfsDigest(r.message);
    case 'describe': return lwk.csfsDescribe(r.message);
    default: throw new Error('unknown op ' + r.op);
  }
}
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let out;
  try { out = { ok: handle(JSON.parse(line)) }; }
  catch (e) { out = { error: String(e && e.message ? e.message : e), name: e && e.name } ; }
  process.stdout.write(JSON.stringify(out) + '\n');
});
