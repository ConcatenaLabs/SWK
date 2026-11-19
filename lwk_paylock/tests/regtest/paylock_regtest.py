#!/usr/bin/env python3
"""The payment lock end to end on a private chain, every step through `paylock`.

A Proof-of-Stake chain of six stakers (the node's lost-block suite,
`feature_pos_lost_blocks.py`) is anchored to a real Bitcoin regtest daemon. The
seller's terms, the buyer's checks (`check-lock`, which reads the node's
`checklock` and its deployment report), the buyer's signed claims and cancel,
the completion service, and the seller's refund are all this crate's code; the
node test framework only runs the network, the Bitcoin wallets and the blocks.

Cases (PAYLOCK_CASES):
  path     the normal path (spec section 5.1): terms, lock, check, claim and cancel
           handed to the service, payment, the claim completed and final;
  unpaid   the buyer never pays: the refund, forced early, is refused; then valid;
  late     the payment does not confirm by D: the service broadcasts the cancel two
           blocks before D; and a payment mined after D, whose claim is refused;
  gone     the payment's block is replaced and the payment double-spent: the claim
           leaves with it, its old proof is refused, and the job ends cancelled at the
           double-spend's block;
  remined  the payment's block is replaced and the payment mined again: the service
           proves the same claim again and it completes;
  anchor   the lock's anchor is replaced: the lock comes back first, the seller's
           respend is refused, the claim completes;
  wrongamount  a payment one satoshi short: no completion, and the claim forced into
           a block is refused;
  wrongaddress the full price paid to another address: likewise;
  unaccepted   a newly issued asset no producer accepts as a fee: check-lock is not
           payable and sign-claim refuses, before any payment;
  feecoin  the same asset, the claim's fee paid from a coin of the buyer's own;
  feepot   the same asset with a fee pot in the lock: the claim spends both with the
           proof on each; an unpaid one is refunded with its fee from the pot;
  twoasset tiers in the locked asset and in another; the locked asset is dropped from
           every node's list before the payment, and the other tier completes;
  raise    a block leaves the pooled claim out: the service raises it to the top tier;
  resend   the payment reaches only the service, which sends it to Bitcoin;
  crowd    stale jobs reaching back to Bitcoin height 1 beside a live one: the live
           one's cancel still goes out at D - 2, and the stale ones end and are archived;
  overflow terms with D = 2^31 are refused; a lock whose D is more than a week above
           Bitcoin's tip is never payable;
  noraise  the counterparty pools the going tier itself and a block leaves it out: the
           service still raises it to the top tier;
  preempt  a job naming the buyer's claims with another payment, posted first, keeps
           nothing of the buyer's out; a cancel of no known payment is refused; reads hold
           no signed transaction;
  cancelstate  a cancel below the BIP125 floor is refused; a broadcast cancel left
           unconfirmed past D keeps the job open until it confirms;
  afterfinal   Bitcoin replaces the payment's block after the claim is final: the service,
           still watching, proves it again; it archives the job once the payment is buried;
  unconf   the payment spends an unconfirmed coin and the cancel stays unmined past D: the
           job waits for a confirmed spend of the payment's coins, then ends cancelled at
           its block;
  bumplate the buyer bumps its payment above its cancel's fee and the bump is mined at
           D + 1: it is the payment, late (never), not a cancel;
  bumpin   the buyer's bump is mined inside the window: the service proves the bump and
           the claim is final;
  block    another client posts the buyer's claims and payment with an unsigned spend of
           the payment's coins first: refused; the buyer's post is taken and its cancel
           goes out at D - 2;
  nopayment    another client posts the buyer's claims and payment id with a cancel of a
           coin the payment does not spend (refused, before and after the payment is
           broadcast), and only the top tier and no cancel (taken): the buyer's post merges
           into that job, and its cancel goes out at D - 2.

Each negative is forced into a block: a block node 1 produced is rewritten to
carry the transaction, certified again (`recertifyposblock`) and submitted, and
the node's reason (it runs -par=1) is asserted.

Run from anywhere:
  PAYLOCK_NODE_FUNCTIONAL=<node>/test/functional PAYLOCK_BIN=<target>/debug/paylock \\
    python3 paylock_regtest.py --configfile <node>/test/config.ini --tmpdir <dir>
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from decimal import Decimal

sys.path.insert(0, os.environ["PAYLOCK_NODE_FUNCTIONAL"])
PAYLOCK = os.environ["PAYLOCK_BIN"]

import feature_btc_payment_proof as bp  # noqa: E402
from feature_pos_lost_blocks import ALL_KEYS, CHAIN, HONEST, LATE, N, SELLER  # noqa: E402
from feature_pos_lost_swap import LostSwapTest  # noqa: E402
from pos_lost_attack_util import block_from_hex  # noqa: E402
from test_framework.address import program_to_witness  # noqa: E402
from test_framework.authproxy import JSONRPCException  # noqa: E402
import test_framework.util  # noqa: E402
from test_framework.key import ECKey, compute_xonly_pubkey, generate_privkey  # noqa: E402
from test_framework.messages import hash256, tx_from_hex  # noqa: E402
from test_framework.script import CScript  # noqa: E402
from test_framework.util import assert_equal, get_auth_cookie, p2p_port, rpc_port  # noqa: E402

CASES = os.environ.get("PAYLOCK_CASES", "path,unpaid,late,gone,remined,anchor,wrongamount,wrongaddress,"
                       "unaccepted,feecoin,feepot,twoasset,raise,resend,crowd,overflow,noraise,preempt,"
                       "cancelstate,afterfinal,unconf,bumplate,bumpin,block,nopayment").split(",")
RESULTS = os.environ.get("PAYLOCK_RESULTS", "")
BUYER = 1  # the buyer's node, which the completion service also reads
COIN = Decimal(100_000_000)
COMMITMENT = bytes.fromhex("6a24aa21a9ed")  # OP_RETURN, push 36, the witness commitment header


def dummy_cancel(i):
    """A Bitcoin transaction in form (a cancel spending a coin nobody has)."""
    txid = (0xca5e0000 + i).to_bytes(32, "little")
    return ("02000000" + "01" + txid.hex() + "00000000" + "00" + "fdffffff" + "01" +
            (1000).to_bytes(8, "little").hex() + "01" + "51" + "00000000")


class PayLockRegtest(LostSwapTest):
    def set_test_params(self):
        super().set_test_params()

    # ------------------------------------------------------------ plumbing
    def pl_env(self):
        u, p = get_auth_cookie(self.nodes[BUYER].datadir, CHAIN)
        e = dict(os.environ)
        e.update(PAYLOCK_SEQ_URL="http://127.0.0.1:%d" % rpc_port(BUYER), PAYLOCK_SEQ_USER=u, PAYLOCK_SEQ_PASS=p,
                 PAYLOCK_BTC_URL="http://127.0.0.1:%d" % self.btc_port, PAYLOCK_BTC_USER=self.btc_user,
                 PAYLOCK_BTC_PASS=self.btc_pass)
        return e

    def pl(self, *args, ok=True):
        r = subprocess.run([PAYLOCK] + [str(a) for a in args], capture_output=True, text=True, env=self.pl_env(),
                           timeout=300)
        v = json.loads(r.stdout.strip().splitlines()[-1])
        if ok and "error" in v:
            raise AssertionError("paylock %s: %s" % (args[0], v["error"]))
        return v

    def keyfile(self, sk, name):
        d = os.path.join(self.options.tmpdir, "keys")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(sk.hex())
        os.chmod(p, 0o600)
        return p

    def start_service(self):
        self.svc_port = p2p_port(N + 6)
        data = os.path.join(self.options.tmpdir, "service")
        self.svc_log = open(os.path.join(self.options.tmpdir, "service.log"), "w")
        self.svc = subprocess.Popen([PAYLOCK, "serve", "--data", data, "--listen", "127.0.0.1:%d" % self.svc_port,
                                     "--interval", "0.5", "--watch-every", "1"], env=self.pl_env(),
                                    stdout=self.svc_log, stderr=self.svc_log)
        self.log.info("completion service pid %d on port %d", self.svc.pid, self.svc_port)
        self.wait_until(lambda: self.http("GET", "/jobs") is not None, timeout=30)

    def stop_service(self):
        if getattr(self, "svc", None) and self.svc.poll() is None:
            self.svc.terminate()
            self.svc.wait(timeout=30)

    def http(self, method, path, body=None):
        try:
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.svc_port, path), method=method,
                                         data=json.dumps(body).encode() if body is not None else None)
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())
        except OSError:
            return None

    def http_code(self, method, path, body=None):
        """(status, body) of a request to the service."""
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.svc_port, path), method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def listed(self, s):
        """Whether the service still carries (or watches) the job, rather than archived it."""
        return any(x["id"] == s["job"] for x in self.http("GET", "/jobs"))

    # ------------------------------------------------------------ forcing
    def produce_by(self, node_i, txs_must=()):
        """A block on node_i from its mempool, certified by every staker; returns it and its leader."""
        node = self.nodes[node_i]
        if txs_must:
            self.wait_until(lambda: all(t in node.getrawmempool() for t in txs_must), timeout=30)
        last = None
        for _ in range(80):
            for k in ALL_KEYS:
                try:
                    r = node.generateposblock(self.stakers[k][0], [self.stakers[j][0] for j in ALL_KEYS if j != k])
                    return r, k
                except JSONRPCException as e:
                    last = e.error["message"]
            time.sleep(0.25)
        raise AssertionError("no block: %s" % last)

    def force(self, case, what, txs, expect):
        """Rewrite a block node 1 produced to carry `txs` (dropping what conflicts with them), certify it
        again and submit it; assert the node refuses it for `expect`."""
        n1 = self.nodes[1]
        r, leader = self.produce_by(1)
        raw = n1.getblock(r["hash"], 0)
        n1.invalidateblock(r["hash"])
        blk = block_from_hex(raw)
        cb = blk.vtx[0]
        # Elements' witness root covers every transaction's witness hash, the coinbase's
        # included; the node computes the fast merkle root (test_framework.util).
        test_framework.util.node_fastmerkle = n1
        k = [i for i, o in enumerate(cb.vout) if bytes(o.scriptPubKey).startswith(COMMITMENT)][-1]
        nonce = cb.wit.vtxinwit[0].scriptWitness.stack[0]

        def commitment(txs):
            wroot = bytes.fromhex(test_framework.util.calcfastmerkleroot([t.calc_witness_hash() for t in txs]))[::-1]
            return COMMITMENT + hash256(wroot + nonce)
        assert_equal(commitment(blk.vtx), bytes(cb.vout[k].scriptPubKey))
        forced = [tx_from_hex(h) for h in txs]
        spent = {(i.prevout.hash, i.prevout.n) for t in forced for i in t.vin}
        keep = [t for t in blk.vtx[1:] if not any((i.prevout.hash, i.prevout.n) in spent for i in t.vin)]
        blk.vtx = [cb] + keep + forced
        cb.vout[k].scriptPubKey = commitment(blk.vtx)
        for t in blk.vtx:
            t.sha256 = None
            t.rehash()
        blk.hashMerkleRoot = blk.calc_merkle_root()
        rc = n1.recertifyposblock(blk.serialize().hex(), self.stakers[leader][0],
                                  [self.stakers[j][0] for j in ALL_KEYS if j != leader])
        reason = n1.submitblock(rc["hex"])
        n1.reconsiderblock(r["hash"])
        self.wait_until(lambda: n1.getbestblockhash() == r["hash"] or n1.getblockcount() > r["height"], timeout=30)
        assert reason and expect in reason, "expected %r, got %r" % (expect, reason)
        self.record(case, "forced: " + what, reason)
        return reason

    def mined(self, txid, node_i=1):
        """Whether txid is in a block of node_i's active chain (a transaction index keeps the block
        hash of a disconnected block, so the block's own confirmations decide)."""
        node = self.nodes[node_i]
        try:
            bh = node.getrawtransaction(txid, True).get("blockhash")
        except JSONRPCException:
            return False
        return bool(bh) and node.getblockheader(bh)["confirmations"] > 0

    def first_anchored_at(self, h, node):
        lo, hi = 0, node.getblockcount()
        assert node.getblockheader(node.getblockhash(hi))["anchorheight"] >= h
        while lo < hi:
            mid = (lo + hi) // 2
            if node.getblockheader(node.getblockhash(mid))["anchorheight"] >= h:
                hi = mid
            else:
                lo = mid + 1
        return lo

    # ------------------------------------------------------------ the swap
    def new_swap(self, case, price=50_000_000, atoms=1_000_000_000, margin=None, asset=None, pot=None):
        """Terms and the seller's signed lock (not yet sent). `asset` is the asset sold (the policy
        asset by default); `pot` adds a fee pot of that many atoms of the policy asset."""
        bsk, ssk = generate_privkey(), generate_privkey()
        rk = ECKey()
        rk.generate(compressed=True)
        asset = asset or self.asset
        args = ["terms", "--asset", asset, "--atoms", atoms, "--price", price,
                "--buyer", compute_xonly_pubkey(bsk)[0].hex(), "--seller", compute_xonly_pubkey(ssk)[0].hex(),
                "--receive-key", rk.get_pubkey().get_bytes().hex()]
        if margin:
            args += ["--margin", margin]
        if pot:
            args += ["--fee-pot-asset", self.asset, "--fee-pot-atoms", pot]
        t = self.pl(*args)
        assert t["payment_lock"], t
        tfile = os.path.join(self.options.tmpdir, "terms-%s-%d.json" % (case, time.time_ns()))
        with open(tfile, "w") as f:
            json.dump(t["terms"], f)
        spk = bytes.fromhex(t["lock_script_pubkey"])
        a = self.nodes[SELLER]
        lock_addr = program_to_witness(1, spk[2:])
        outs = [{lock_addr: Decimal(atoms) / COIN, "asset": asset}]
        if pot:
            # The pot pays the lock's own script too; a second output to one address is written
            # by hand, since the RPC takes each address once.
            spare = a.getnewaddress()
            outs.append({spare: Decimal(pot) / COIN})
        raw = a.createrawtransaction([], outs)
        if pot:
            tx = tx_from_hex(raw)
            spare_spk = bytes.fromhex(a.getaddressinfo(spare)["scriptPubKey"])
            for o in tx.vout:
                if bytes(o.scriptPubKey) == spare_spk:
                    o.scriptPubKey = CScript(spk)
            raw = tx.serialize().hex()
        funded = a.fundrawtransaction(raw, {"fee_asset": "bitcoin", "replaceable": False, "change_type": "bech32"})["hex"]
        lock_hex = a.signrawtransactionwithwallet(funded)["hex"]
        lt = tx_from_hex(lock_hex)
        txid = lt.rehash()
        mine = [i for i, o in enumerate(lt.vout) if o.scriptPubKey == spk]
        vout = [i for i in mine if lt.vout[i].nAsset.vchCommitment[1:][::-1].hex() == asset][0]
        s = dict(case=case, terms=t["terms"], tfile=tfile, lock_hex=lock_hex, txid=txid, vout=vout,
                 lock="%s:%d" % (txid, vout), bkey=self.keyfile(bsk, case + "-buyer"),
                 skey=self.keyfile(ssk, case + "-seller"), recv=t["receive_address"], price=price, atoms=atoms,
                 asset=asset, pot_vout=[i for i in mine if i != vout][0] if pot else None)
        self.record(case, "terms", "F %d, D %d, R %d (Bitcoin tip %d); %d atoms for %d sat to %s%s" %
                    (t["terms"]["floor"], t["terms"]["deadline"], t["terms"]["refund_at"], self.btc().getblockcount(),
                     atoms, price, s["recv"], "; fee pot %d atoms" % pot if pot else ""))
        return s

    def lock_and_confirm(self, s):
        self.nodes[1].sendrawtransaction(s["lock_hex"])
        L = self.produce(1, ALL_KEYS, txs_must=[s["txid"]])
        self.produce(1, ALL_KEYS)
        self.sync_tips(range(N))
        s["L"] = L
        self.record(s["case"], "lock", "%s certified at height %d, anchored at %d" %
                    (s["txid"][:16], L["height"], L["block"]["anchorheight"]))
        return L

    def check_payable(self, s, timeout=30):
        first = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        t0 = time.time()
        v = first
        while not v["payable"]:
            assert time.time() - t0 < timeout, "the lock never became payable: %s" % v["reasons"]
            time.sleep(0.5)
            v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        self.record(s["case"], "check-lock", "payable after %.1f s%s" % (
            time.time() - t0, "" if first["payable"] else " (first: %s)" % "; ".join(first["reasons"])))

    def buyer_sign(self, s, *fee_args, extend=False):
        """The buyer's signed claims (going and top tier). `fee_args` name the fee's source
        (`--fee-pot`, `--fee-coin X`); with a fee coin the buyer's wallet signs the coin's input
        of each template first. `extend` adds the tiers to those already signed (a second asset)."""
        n1 = self.nodes[1]
        if not s.get("to"):
            s["to"] = n1.getaddressinfo(n1.getnewaddress())["scriptPubKey"]
        base = ["sign-claim", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["bkey"], "--to", s["to"],
                "--fee", 5000] + list(fee_args)
        c = self.pl(*base)
        if "templates" in c:
            signed = []
            for t in c["templates"]:
                r = n1.signrawtransactionwithwallet(t)
                # The wallet signs the coin's input and cannot sign the lock's: incomplete, by design.
                assert not r["complete"]
                signed.append(r["hex"])
            c = self.pl(*(base + ["--wallet-signed", ",".join(signed)]))
        if extend:
            s["claims"] += c["claims"]
            s["claim_ids"] += c["txids"]
        else:
            s["claims"], s["claim_ids"] = c["claims"], c["txids"]
        self.record(s["case"], "claims" + (" (more)" if extend else ""), "signed before paying: tiers %s, fees %s atoms of %s" %
                    ([t[:12] for t in c["txids"]], c["fees"], c["fee_asset"][:12]))
        return c

    def make_payment(self, s, cancel=True, sat=None, to_addr=None):
        b = self.bbuyer
        raw = b.createrawtransaction([], [{to_addr or s["recv"]: Decimal(sat or s["price"]) / COIN}])
        f = b.fundrawtransaction(raw, {"replaceable": True})
        s["pay_hex"] = b.signrawtransactionwithwallet(f["hex"])["hex"]
        d = b.decoderawtransaction(s["pay_hex"])
        s["pay"] = d["txid"]
        if cancel:
            values = []
            for vin in d["vin"]:
                prev = b.decoderawtransaction(b.gettransaction(vin["txid"])["hex"])
                values.append(int(Decimal(str(prev["vout"][vin["vout"]]["value"])) * COIN))
            fee = int(f["fee"] * COIN) * 3 + 1000
            to = b.getaddressinfo(b.getnewaddress())["scriptPubKey"]
            c = self.pl("cancel", "--payment-hex", s["pay_hex"], "--values", ",".join(map(str, values)),
                        "--to", to, "--fee", fee)
            s["cancel_hex"] = b.signrawtransactionwithwallet(c["hex"])["hex"]
            s["cancel_id"] = c["txid"]

    def send_pay(self, s):
        """The buyer broadcasts its payment; the service may have sent it already."""
        try:
            self.btc().sendrawtransaction(s["pay_hex"])
        except JSONRPCException as e:
            assert "already" in e.error["message"], e.error

    def hand_over(self, s):
        job = {"terms": s["terms"], "lock": s["lock"], "claims": s["claims"], "payment": s["pay"],
               "payment_hex": s["pay_hex"]}
        if s.get("cancel_hex"):
            job["cancel"] = s["cancel_hex"]
        r = self.http("POST", "/jobs", job)
        assert "id" in r, r
        s["job"] = r["id"]

    def job(self, s):
        return self.http("GET", "/jobs/" + s["job"])

    def wait_job(self, s, states, produce=True, timeout=120):
        t0 = time.time()
        while True:
            j = self.job(s)
            if j and j["state"] in states:
                return j
            assert time.time() - t0 < timeout, "job stuck: %s" % j
            if produce:
                # A payment the service sent again after a reorganization waits for Bitcoin's next block.
                if s.get("pay") and s["pay"] in self.btc().getrawmempool() and s["case"] != "late":
                    self.btc_mine(1)
                self.produce(1, ALL_KEYS)
            time.sleep(0.6)

    def claim_with_python_proof(self, s, pay_txid, blockhash=None, to_addr=None):
        """The buyer's signed claim (the crate's) completed with the node suite's own proof builder,
        naming the payment's output to `to_addr` (the seller's receiving address by default)."""
        n1 = self.nodes[1]
        bh = n1.getrawtransaction(s["txid"], True)["blockhash"]
        pr = self.proof_for(pay_txid, n1.getblockheader(bh)["anchorheight"], blockhash=blockhash)
        t = self.btc().getrawtransaction(pay_txid, True, pr["blockhash"])
        vout = [o["n"] for o in t["vout"] if o["scriptPubKey"].get("address") == (to_addr or s["recv"])][0]
        tx = tx_from_hex(s["claims"][0])
        tx.wit.vtxinwit[0].scriptWitness.stack[0] = bp.scriptnum(vout)
        tx.wit.vtxinwit[0].peginWitness.stack = [pr["record"]]
        tx.rehash()
        return tx.serialize().hex(), pr

    def assert_buyer_paid(self, s, j):
        """The mined claim pays every locked atom to the buyer, less the fee only when the locked
        asset pays it; returns its txid and decoded transaction."""
        n1 = self.nodes[1]
        txid = [t for t in s["claim_ids"] if self.mined(t)][0]
        d = n1.getrawtransaction(txid, True)
        o = d["vout"][0]
        assert_equal(o["scriptPubKey"]["hex"], s["to"])
        fee_out = [x for x in d["vout"] if x["scriptPubKey"]["type"] == "fee"][0]
        fee = int(Decimal(str(fee_out["value"])) * COIN)
        fee_asset = fee_out["asset"]
        expect = s["atoms"] - (fee if fee_asset == s["asset"] else 0)
        assert_equal(o["asset"], s["asset"])
        assert_equal(int(Decimal(str(o["value"])) * COIN), expect)
        proofs = [len(bytes.fromhex(i["pegin_witness"][0])) for i in d["vin"] if i.get("pegin_witness")]
        self.record(s["case"], "outcome", "claim %s (tier %d) final at height %s: %d atoms to the buyer, fee %d atoms of %s, "
                    "%d inputs, vsize %d, proofs %s bytes" % (txid[:16], s["claim_ids"].index(txid), j["mined_at"], expect, fee,
                                                       "the locked asset" if fee_asset == s["asset"] else fee_asset[:12],
                                                       len(d["vin"]), d["vsize"], proofs))
        return txid, d

    # ------------------------------------------------------------ cases
    def case_path(self):
        self.log.info("(path) the normal path, spec section 5.1")
        a = self.pl("activation")
        assert a["payment_lock"], a
        self.record("path", "activation", json.dumps(a))
        s = self.new_swap("path")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        t0 = time.time()
        self.btc_mine(1)
        self.record("path", "payment", "%s mined in Bitcoin block %d" % (s["pay"][:16], self.btc().getblockcount()))
        j = self.wait_job(s, ["final"])
        self.record("path", "service", "final %.1f s after the payment's block: %s" % (time.time() - t0, j["note"]))
        self.assert_buyer_paid(s, j)
        # The seller's wallet sees the buyer's payment in the lock's heights and does not refund.
        to = self.nodes[SELLER].getaddressinfo(self.nodes[SELLER].getnewaddress())["scriptPubKey"]
        r = self.pl("sign-refund", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["skey"],
                    "--to", to, "--fee", 5000, ok=False)
        assert "does not refund" in r.get("error", ""), r
        self.record("path", "seller's refund after a payment", r["error"])
        self.sync_tips(range(N))

    def case_unpaid(self):
        self.log.info("(unpaid) the buyer never pays: the refund opens 60 blocks after the first block anchored at D")
        s = self.new_swap("unpaid")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        n1 = self.nodes[1]
        to = self.nodes[SELLER].getaddressinfo(self.nodes[SELLER].getnewaddress())["scriptPubKey"]
        early = self.pl("sign-refund", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["skey"],
                        "--to", to, "--fee", 5000, "--send")
        self.record("unpaid", "early refund, mempool", early["send_error"])
        assert "anchorlock-not-reached" in early["send_error"]
        self.force("unpaid", "the refund before its floor", [early["hex"]], "bad-anchorlock-not-reached")
        D = s["terms"]["deadline"]
        self.btc_mine(max(0, D - self.btc().getblockcount()))
        self.anchored_block(D)
        first = self.first_anchored_at(D, n1)
        while n1.getblockcount() < first + bp.FLOOR_DEPTH - 2:
            self.produce(1, ALL_KEYS)
        # One block short of the floor: still refused, in a block too. Forcing leaves the
        # block it rewrote at the tip, so the next block is the 60th.
        self.force("unpaid", "the refund one block before its floor", [early["hex"]], "bad-anchorlock-not-reached")
        assert_equal(n1.getblockcount(), first + bp.FLOOR_DEPTH - 1)
        r = self.pl("sign-refund", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["skey"],
                    "--to", to, "--fee", 5000, "--send")
        assert r["sent"], r
        h = self.produce(1, ALL_KEYS, txs_must=[r["txid"]])
        self.record("unpaid", "refund", "mined at height %d, the 60th block after %d (the first anchored at D = %d)" %
                    (h["height"], first, D))
        assert_equal(h["height"], first + bp.FLOOR_DEPTH)
        self.sync_tips(range(N))

    def empty_btc_blocks(self, n):
        b = self.btc()
        addr = self.btc("miner").getnewaddress()
        for _ in range(n):
            b.generateblock(addr, [])

    def case_late(self):
        self.log.info("(late) the payment does not confirm by D: the cancel; and a payment mined after D")
        b = self.btc()
        s = self.new_swap("late")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        D = s["terms"]["deadline"]
        # Blocks without the payment, up to three before D: no cancel yet.
        self.empty_btc_blocks(D - 3 - b.getblockcount())
        time.sleep(2)
        assert self.job(s)["state"] == "waiting", self.job(s)
        assert s["pay"] in b.getrawmempool()
        self.empty_btc_blocks(1)
        self.wait_until(lambda: self.job(s)["cancel_sent"], timeout=30)
        j = self.job(s)
        self.record("late", "service at tip %d (D - 2)" % b.getblockcount(), j["note"])
        mp = b.getrawmempool()
        assert s["cancel_id"] in mp and s["pay"] not in mp, mp
        self.btc_mine(1)
        assert self.bbuyer.gettransaction(s["cancel_id"])["confirmations"] == 1
        self.record("late", "cancel", "%s replaced the payment and is mined; the buyer keeps its bitcoin" % s["cancel_id"][:16])
        # The confirmed cancel ends the job; it is watched until the cancel's block is buried.
        j = self.wait_job(s, ["cancelled"], produce=False, timeout=30)
        assert j["watching"] and self.listed(s), j
        self.empty_btc_blocks(6)
        self.wait_until(lambda: not self.listed(s), timeout=30)
        self.record("late", "ended", "%s at the cancel's block %s, archived once it was 6 deep: %s" %
                    (j["state"], j["cancel_height"], j["note"]))

        # A payment with no cancel, mined one block after D.
        s2 = self.new_swap("late")
        self.lock_and_confirm(s2)
        self.check_payable(s2)
        self.buyer_sign(s2)
        self.make_payment(s2, cancel=False)
        self.hand_over(s2)
        self.send_pay(s2)
        D2 = s2["terms"]["deadline"]
        self.empty_btc_blocks(D2 - b.getblockcount())
        self.btc_mine(1)
        assert_equal(b.getblockcount(), D2 + 1)
        self.anchored_block(D2 + 1)
        j = self.wait_job(s2, ["never"], timeout=60)
        self.record("late", "service, payment at D + 1", j["note"])
        late_claim, pr = self.claim_with_python_proof(s2, s2["pay"])
        assert_equal(pr["height"], D2 + 1)
        self.force("late", "a claim on a payment mined at D + 1", [late_claim], "Script failed an OP_VERIFY operation")
        self.sync_tips(range(N))

    def paid_and_claimed(self, case):
        s = self.new_swap(case)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        s["p_hash"] = self.btc_mine(1)[0]
        s["p"] = self.btc().getblockcount()
        j = self.wait_job(s, ["mined", "final"])
        s["claim_txid"] = [t for t in s["claim_ids"] if self.mined(t)][0]
        s["LC"] = self.nodes[1].getrawtransaction(s["claim_txid"], True)["blockhash"]
        s["old_claim"] = self.nodes[1].getrawtransaction(s["claim_txid"])
        self.produce(1, ALL_KEYS)
        self.sync_tips(range(N))
        self.record(case, "claim", "%s mined at %d with a proof of Bitcoin block %d" % (s["claim_txid"][:16], j["mined_at"], s["p"]))
        return s

    def case_gone(self):
        self.log.info("(gone) the payment's block is replaced and the payment double-spent")
        b = self.btc()
        s = self.paid_and_claimed("gone")
        vin = b.getrawtransaction(s["pay"], True, s["p_hash"])["vin"]
        b.invalidateblock(s["p_hash"])
        ins = [{"txid": i["txid"], "vout": i["vout"]} for i in vin]
        total = sum(Decimal(str(self.bbuyer.gettransaction(i["txid"], True, True)["decoded"]["vout"][i["vout"]]["value"]))
                    for i in ins)
        raw = self.bbuyer.createrawtransaction(ins, [{self.bbuyer.getnewaddress(): total - Decimal("0.001")}])
        dbl = self.bbuyer.signrawtransactionwithwallet(raw)["hex"]
        b.sendrawtransaction(dbl, 0)
        self.btc_mine(2)
        self.wait_lost(s["LC"], HONEST)
        self.record("gone", "reorg", "Bitcoin block %d replaced, the payment double-spent; the claim's block is lost" % s["p"])
        assert self.bbuyer.gettransaction(s["pay"])["confirmations"] <= 0
        # The double-spend is a confirmed spend of the payment's coins that does not pay the
        # seller: the payment can never be mined, and the buyer keeps its bitcoin.
        j = self.wait_job(s, ["cancelled"], timeout=60)
        assert_equal(j["cancel_height"], s["p"])
        assert "does not pay the seller" in j["note"], j
        self.record("gone", "service", "%s: %s" % (j["state"], j["note"]))
        self.force("gone", "the claim with its old proof", [s["old_claim"]], "bad-btcpay-not-in-anchor-chain")
        assert not any(self.mined(t) for t in s["claim_ids"])
        self.realign()

    def case_remined(self):
        self.log.info("(remined) the payment's block is replaced and the payment mined again")
        b = self.btc()
        s = self.paid_and_claimed("remined")
        # Keep the service from re-proving before the negative is forced.
        self.stop_service()
        b.invalidateblock(s["p_hash"])
        if s["pay"] not in b.getrawmempool():
            self.send_pay(s)
        self.btc_mine(2)
        self.wait_lost(s["LC"], HONEST)
        on = self.bbuyer.gettransaction(s["pay"])
        self.record("remined", "reorg", "Bitcoin block %d replaced; the payment mined again in %s" % (s["p"], on["blockhash"][:16]))
        self.anchored_block(b.getblockcount())
        self.force("remined", "the claim with the proof of the replaced block", [s["old_claim"]],
                   "bad-btcpay-not-in-anchor-chain")
        self.start_service()
        j = self.wait_job(s, ["final"])
        txid, _ = self.assert_buyer_paid(s, j)
        assert_equal(txid, s["claim_txid"])
        self.record("remined", "same id", "the claim came back as %s, proven again by the service" % txid[:16])
        self.realign()

    def case_anchor(self):
        self.log.info("(anchor) the lock's anchor is replaced: the lock comes back first")
        b = self.btc()
        a = self.nodes[SELLER]
        n1 = self.nodes[1]
        s = self.new_swap("anchor")
        b.generatetoaddress(1, self.bbuyer.getnewaddress())
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        self.btc_mine(1)
        self.bitcoin_reorg(2)
        self.wait_lost(s["L"]["hash"], HONEST)
        self.record("anchor", "reorg", "Bitcoin 2 deep: the lock's block %s (anchor %d) lost on %s" %
                    (s["L"]["hash"][:16], s["L"]["block"]["anchorheight"], HONEST))
        # The seller respends the lock's inputs. Its own node pools the lock again (it is back
        # in every mempool), so the respend is forced into a block a holder judges.
        t = tx_from_hex(s["lock_hex"])
        ins = [{"txid": "%064x" % i.prevout.hash, "vout": i.prevout.n} for i in t.vin]
        # The lock left the chain with its block, so its inputs are unspent there.
        total = sum(Decimal(str(a.gettxout(i["txid"], i["vout"], False)["value"])) for i in ins)
        raw = a.createrawtransaction(ins, [{a.getnewaddress(): total - Decimal("0.001")}, {"fee": Decimal("0.001")}])
        respend = a.signrawtransactionwithwallet(raw)["hex"]
        try:
            a.sendrawtransaction(respend)
        except JSONRPCException as e:
            self.record("anchor", "the respend in the seller's own mempool", e.error["message"])
        self.force("anchor", "the seller's respend of the lock's inputs", [respend], "bad-txns-lost-respend")
        # The block node 1 made, now its tip: the lock comes back first.
        tip = n1.getblock(n1.getbestblockhash())
        assert_equal(tip["tx"][1], s["txid"])
        self.record("anchor", "replay", "block %s at height %d carries the lock first (tx[1])" % (tip["hash"][:16], tip["height"]))
        j = self.wait_job(s, ["final"], timeout=180)
        self.assert_buyer_paid(s, j)
        self.realign()

    # ------------------------------------------------------------ the claim's fee
    def issue(self, case):
        """A newly issued asset on the seller's node, in the clear. No node accepts a fee in it."""
        a = self.nodes[SELLER]
        r = a.issueasset(assetamount=Decimal(100), tokenamount=0, blind=False, fee_asset="bitcoin")
        self.produce(1, ALL_KEYS, txs_must=[r["txid"]])
        self.sync_tips(range(N))
        info = self.nodes[1].getfeeassetinfo(r["asset"])[r["asset"]]
        self.record(case, "issued", "%s; the buyer's node: accepted %s, listed %s" % (r["asset"][:16], info["accepted"], info["listed"]))
        return r["asset"]

    def fee_coin(self, case, atoms=200_000):
        """A coin of the buyer's own in the policy asset, in the clear, confirmed."""
        n1 = self.nodes[1]
        addr = n1.getnewaddress()
        # Funded from the seller's node, which holds the chain's initial coins; the key is node 1's.
        txid = self.nodes[SELLER].sendtoaddress(address=addr, amount=Decimal(atoms) / COIN, assetlabel="bitcoin",
                                                fee_asset_label="bitcoin")
        self.produce(1, ALL_KEYS, txs_must=[txid])
        self.sync_tips(range(N))
        d = n1.getrawtransaction(txid, True)
        vout = [o["n"] for o in d["vout"] if o["scriptPubKey"].get("address") == addr][0]
        return "%s:%d" % (txid, vout)

    def set_fee_list(self, rates):
        for n in self.nodes:
            n.setfeeexchangerates(rates, False)

    def case_unaccepted(self):
        self.log.info("(unaccepted) a newly issued asset no producer accepts: refused before payment")
        x = self.issue("unaccepted")
        s = self.new_swap("unaccepted", asset=x)
        self.lock_and_confirm(s)
        time.sleep(4)
        v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        assert not v["payable"], v
        assert any("cannot pay its fee" in r for r in v["reasons"]), v
        self.record("unaccepted", "check-lock", "payable %s: %s" % (v["payable"], [r for r in v["reasons"] if "fee" in r][0]))
        n1 = self.nodes[1]
        to = n1.getaddressinfo(n1.getnewaddress())["scriptPubKey"]
        e = self.pl("sign-claim", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["bkey"], "--to", to,
                    "--fee", 5000, ok=False)
        assert "do not accept a fee" in e.get("error", ""), e
        self.record("unaccepted", "sign-claim", e["error"])
        self.unaccepted_asset = x

    def case_feecoin(self):
        self.log.info("(feecoin) the same asset, its claim's fee paid from a coin of the buyer's own")
        x = getattr(self, "unaccepted_asset", None) or self.issue("feecoin")
        s = self.new_swap("feecoin", asset=x)
        self.lock_and_confirm(s)
        coin = self.fee_coin("feecoin")
        time.sleep(4)
        v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        assert not v["payable"]
        v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"], "--fee-coin", coin)
        assert v["payable"], v
        self.record("feecoin", "check-lock with the coin", "payable; routes %s" % [(r["source"], r["usable"]) for r in v["fee_routes"]])
        self.buyer_sign(s, "--fee-coin", coin, "--value", 50_000_000)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        self.btc_mine(1)
        j = self.wait_job(s, ["final"])
        txid, d = self.assert_buyer_paid(s, j)
        ct, cv = coin.split(":")
        assert any(i["txid"] == ct and i["vout"] == int(cv) for i in d["vin"]), d["vin"]
        assert_equal([x for x in d["vout"] if x["scriptPubKey"]["type"] == "fee"][0]["asset"], self.asset)
        self.record("feecoin", "fee coin", "spent by the claim as input 1; the fee is in the policy asset")
        self.sync_tips(range(N))

    def case_feepot(self):
        self.log.info("(feepot) the same asset with a fee pot in the lock: claimed, and an unpaid one refunded")
        x = getattr(self, "unaccepted_asset", None) or self.issue("feepot")
        s = self.new_swap("feepot", asset=x, pot=200_000)
        self.lock_and_confirm(s)
        self.check_payable(s)
        v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        self.record("feepot", "routes", [(r["source"], r["usable"]) for r in v["fee_routes"]])
        self.buyer_sign(s, "--fee-pot", "--value", 50_000_000)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        self.btc_mine(1)
        j = self.wait_job(s, ["final"])
        txid, d = self.assert_buyer_paid(s, j)
        assert_equal(len(d["vin"]), 2)
        assert all(i.get("pegin_witness") for i in d["vin"]), "both inputs carry the proof"
        assert_equal(d["vin"][1]["vout"], s["pot_vout"])
        self.sync_tips(range(N))

        # Unpaid: the seller's refund takes the lock and the pot back, its fee from the pot.
        s2 = self.new_swap("feepot", asset=x, pot=200_000)
        self.lock_and_confirm(s2)
        n1 = self.nodes[1]
        a = self.nodes[SELLER]
        to = a.getaddressinfo(a.getnewaddress())["scriptPubKey"]
        e = self.pl("sign-refund", "--terms", s2["tfile"], "--lock", s2["lock"], "--key-file", s2["skey"],
                    "--to", to, "--fee", 5000, ok=False)
        assert "do not accept a fee" in e.get("error", ""), e
        self.record("feepot", "refund paying in the locked asset", e["error"])
        D = s2["terms"]["deadline"]
        self.btc_mine(max(0, D - self.btc().getblockcount()))
        self.anchored_block(D)
        first = self.first_anchored_at(D, n1)
        while n1.getblockcount() < first + bp.FLOOR_DEPTH - 1:
            self.produce(1, ALL_KEYS)
        r = self.pl("sign-refund", "--terms", s2["tfile"], "--lock", s2["lock"], "--key-file", s2["skey"],
                    "--to", to, "--fee", 5000, "--fee-pot", "--send")
        assert r["sent"], r
        h = self.produce(1, ALL_KEYS, txs_must=[r["txid"]])
        d = n1.getrawtransaction(r["txid"], True)
        assert_equal(len(d["vin"]), 2)
        back = sum(int(Decimal(str(o["value"])) * COIN) for o in d["vout"] if o["asset"] == x)
        assert_equal(back, s2["atoms"])
        self.record("feepot", "refund", "mined at %d (60th after %d): %d atoms back to the seller, fee 5000 from the pot, %d vB" %
                    (h["height"], first, back, d["vsize"]))
        self.sync_tips(range(N))

    def case_twoasset(self):
        self.log.info("(twoasset) tiers in two fee assets: the locked one is dropped before the payment")
        before = self.nodes[1].getfeeexchangerates()
        y = self.issue("twoasset")
        rates = dict(before)
        rates[y] = 100_000_000
        self.set_fee_list(rates)
        assert self.nodes[1].getfeeassetinfo(y)[y]["accepted"]
        s = self.new_swap("twoasset", asset=y)
        self.lock_and_confirm(s)
        # The top tier is priced at the locked value (10 coins at the node's 1:1 rates): about 600,000 atoms.
        coin = self.fee_coin("twoasset", atoms=2_000_000)
        self.check_payable(s)
        self.buyer_sign(s)
        self.buyer_sign(s, "--fee-coin", coin, extend=True)
        self.make_payment(s)
        self.hand_over(s)
        self.set_fee_list(before)
        assert not self.nodes[1].getfeeassetinfo(y)[y]["accepted"]
        self.record("twoasset", "fee list", "the locked asset %s dropped from every node's list after the claims were signed" % y[:12])
        self.send_pay(s)
        self.btc_mine(1)
        j = self.wait_job(s, ["final"])
        txid, d = self.assert_buyer_paid(s, j)
        assert_equal([x for x in d["vout"] if x["scriptPubKey"]["type"] == "fee"][0]["asset"], self.asset)
        assert s["claim_ids"].index(txid) >= 2, "a tier in the second asset was mined"
        self.sync_tips(range(N))

    # ------------------------------------------------------------ the service
    def case_raise(self):
        self.log.info("(raise) a block leaves the pooled claim out: the top tier at once")
        n1 = self.nodes[1]
        s = self.new_swap("raise")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        assert len(s["claim_ids"]) == 2
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        self.btc_mine(1)
        going = s["claim_ids"][0]
        # Wait for the service to pool the going tier, with no block made meanwhile.
        self.anchored_block(self.btc().getblockcount())
        self.wait_until(lambda: going in n1.getrawmempool(), timeout=60)
        # The producer prices the going tier out of its template: the block leaves it out.
        n1.prioritisetransaction(going, 0, -10_000_000)
        b = self.produce(1, ALL_KEYS)
        assert going not in b["block"]["tx"]
        self.record("raise", "left out", "block %d made without the pooled going tier %s" % (b["height"], going[:16]))
        j = self.wait_job(s, ["final"])
        txid, _ = self.assert_buyer_paid(s, j)
        assert_equal(txid, s["claim_ids"][1])
        assert j["raised"], j
        self.record("raise", "service", "raised to the top tier and mined: %s" % txid[:16])
        self.sync_tips(range(N))

    def case_resend(self):
        self.log.info("(resend) the payment reaches only the service: it sends it")
        s = self.new_swap("resend")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.wait_until(lambda: s["pay"] in self.btc().getrawmempool(), timeout=30)
        self.record("resend", "service", "the payment, never broadcast by the buyer, is in the Bitcoin mempool: %s" % self.job(s)["note"])
        self.btc_mine(1)
        j = self.wait_job(s, ["final"])
        self.assert_buyer_paid(s, j)
        self.sync_tips(range(N))

    def case_wrongamount(self):
        self.log.info("(wrongamount) a payment one satoshi short")
        s = self.new_swap("wrongamount")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s, cancel=False, sat=s["price"] - 1)
        self.send_pay(s)
        self.btc_mine(1)
        self.anchored_block(self.btc().getblockcount())
        r = self.pl("complete", "--terms", s["tfile"], "--lock", s["lock"], "--claim", s["claims"][0],
                    "--payment", s["pay"], ok=False)
        assert "less than the price" in r.get("error", ""), r
        self.record("wrongamount", "complete", r["error"])
        claim, _ = self.claim_with_python_proof(s, s["pay"])
        self.force("wrongamount", "a claim on a payment one satoshi short", [claim],
                   "Script evaluated without error but finished with a false/empty top stack element")
        self.sync_tips(range(N))

    def case_wrongaddress(self):
        self.log.info("(wrongaddress) the full price paid to another address")
        s = self.new_swap("wrongaddress")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        other = self.bseller.getnewaddress("", "bech32")
        self.make_payment(s, cancel=False, to_addr=other)
        self.send_pay(s)
        self.btc_mine(1)
        self.anchored_block(self.btc().getblockcount())
        r = self.pl("complete", "--terms", s["tfile"], "--lock", s["lock"], "--claim", s["claims"][0],
                    "--payment", s["pay"], ok=False)
        assert "less than the price" in r.get("error", ""), r
        self.record("wrongaddress", "complete", r["error"])
        claim, _ = self.claim_with_python_proof(s, s["pay"], to_addr=other)
        self.force("wrongaddress", "a claim on a payment to another address", [claim],
                   "Script failed an OP_EQUALVERIFY operation")
        self.sync_tips(range(N))

    def case_crowd(self):
        self.log.info("(crowd) stale and stalled jobs beside a live one: its cancel still goes out at D - 2")
        b = self.btc()
        tip = b.getblockcount()
        # Stale jobs: locks that do not exist, payments that never come, each reaching from
        # Bitcoin height 1 (the old search walked from the tip down to F on every round), and
        # every deadline before the live job's, so that the work round reaches them first.
        tmpl = self.new_swap("crowd")
        n_stale = int(os.environ.get("PAYLOCK_CROWD", "150"))
        terms = dict(tmpl["terms"], floor=max(1, tip + 4 - 1000))
        # Every stale job's payment and cancel spend one coin of the buyer's: each is valid
        # alone (intake takes nothing else), and once one of them is pooled the rest are
        # refused, as a flood of real cancels would be.
        w = self.bbuyer
        xa = w.getnewaddress("", "bech32")
        xt = w.sendtoaddress(xa, Decimal("0.01"))
        self.btc_mine(1)
        xv = [o["n"] for o in w.gettransaction(xt, True, True)["decoded"]["vout"]
              if o["scriptPubKey"].get("address") == xa][0]
        w.lockunspent(False, [{"txid": xt, "vout": xv}])
        back = w.getnewaddress("", "bech32")
        x_in = [{"txid": xt, "vout": xv, "sequence": 0xfffffffd}]
        stale = []
        t0 = time.time()
        for i in range(n_stale):
            t = dict(terms, deadline=tip + 4, refund_at=tip + 4)
            tf = os.path.join(self.options.tmpdir, "crowd-terms.json")
            with open(tf, "w") as f:
                json.dump(t, f)
            lock = "%064x:0" % (0xc0de0000 + i)
            c = self.pl("sign-claim", "--terms", tf, "--lock", lock, "--key-file", tmpl["bkey"], "--to", "51",
                        "--fee", 5000, "--top-fee", "none")
            pay = w.signrawtransactionwithwallet(w.createrawtransaction(x_in, [{back: Decimal(999_000 - i) / COIN}]))["hex"]
            can = w.signrawtransactionwithwallet(w.createrawtransaction(x_in, [{back: Decimal(995_000 - i) / COIN}]))["hex"]
            r = self.http("POST", "/jobs", {"terms": t, "lock": lock, "claims": c["claims"],
                                            "payment": w.decoderawtransaction(pay)["txid"], "payment_hex": pay,
                                            "cancel": can})
            assert "id" in r, r
            stale.append(r["id"])
        assert all(self.http("GET", "/jobs/" + i)["cancels"] == 1 for i in stale)
        self.record("crowd", "stale jobs", "%d handed over in %.1f s, each from F = %d to D = %d" %
                    (n_stale, time.time() - t0, terms["floor"], tip + 4))
        # The live job: paid, never mined, with its cancel.
        s = self.new_swap("crowd")
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        D = s["terms"]["deadline"]
        assert D > tip + 4
        self.empty_btc_blocks(D - 3 - b.getblockcount())
        time.sleep(3)
        assert self.job(s)["state"] == "waiting", self.job(s)
        self.empty_btc_blocks(1)
        t1 = time.time()
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=60)
        took = time.time() - t1
        j = self.job(s)
        self.record("crowd", "cancel", "in the Bitcoin mempool %.1f s after tip %d (D - 2), beside %d stale jobs: %s" %
                    (took, b.getblockcount(), n_stale, j["note"]))
        assert took < 5, took
        self.btc_mine(1)
        # The stale jobs end at the block that spends their coin, and are archived once it is buried.
        self.empty_btc_blocks(6)
        self.wait_until(lambda: len(self.http("GET", "/jobs")) <= 1, timeout=180)
        self.record("crowd", "archive", "every stale job ended and left the active list; the live one: %s" % self.job(s)["state"])
        self.sync_tips(range(N))

    # ------------------------------------------------------------ the second review
    def case_overflow(self):
        self.log.info("(overflow) heights no script compares, and deadlines too far ahead")
        c = "overflow"
        bsk, ssk = generate_privkey(), generate_privkey()
        rk = ECKey()
        rk.generate(compressed=True)
        args = ["terms", "--asset", self.asset, "--atoms", 1_000_000_000, "--price", 50_000_000,
                "--buyer", compute_xonly_pubkey(bsk)[0].hex(), "--seller", compute_xonly_pubkey(ssk)[0].hex(),
                "--receive-key", rk.get_pubkey().get_bytes().hex()]
        r = self.pl(*(args + ["--deadline", 2 ** 31]), ok=False)
        assert "highest height" in r.get("error", ""), r
        self.record(c, "terms with D = 2^31", r["error"])
        # D in range but more than the service's week above Bitcoin's tip: built, never payable.
        tip = self.btc().getblockcount()
        s = self.new_swap(c, margin=1009)
        assert_equal(s["terms"]["deadline"], tip + 1009)
        self.lock_and_confirm(s)
        time.sleep(4)
        v = self.pl("check-lock", "--terms", s["tfile"], "--lock", s["lock"])
        assert not v["payable"], v
        assert any("above Bitcoin's tip" in x for x in v["reasons"]), v
        self.record(c, "check-lock with D = tip + 1009", [x for x in v["reasons"] if "above" in x or "spans" in x])

    def case_noraise(self):
        self.log.info("(noraise) the counterparty pools the going tier first; a block leaves it out")
        c = "noraise"
        n1 = self.nodes[1]
        s = self.new_swap(c)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        going, top = s["claim_ids"]
        self.make_payment(s)
        self.send_pay(s)
        self.btc_mine(1)
        self.anchored_block(self.btc().getblockcount())
        # The seller holds the signed claims (spec 8.2 step 4) and completes the going tier itself.
        r = self.pl("complete", "--terms", s["tfile"], "--lock", s["lock"], "--claim", s["claims"][0],
                    "--payment", s["pay"], "--send")
        assert_equal(r["sent"], going)
        n1.prioritisetransaction(going, 0, -10_000_000)
        self.hand_over(s)
        self.wait_until(lambda: self.job(s)["pooled_at"] is not None, timeout=30)
        self.record(c, "service", "sees the going tier pooled by another: %s" % self.job(s)["note"])
        b = self.produce(1, ALL_KEYS)
        assert going not in b["block"]["tx"]
        j = self.wait_job(s, ["final"])
        txid, _ = self.assert_buyer_paid(s, j)
        assert_equal(txid, top)
        assert j["raised"], j
        self.record(c, "outcome", "a block left the going tier out; the service raised it and the top tier is final")

    def case_preempt(self):
        self.log.info("(preempt) a job with the buyer's claims and another payment, posted first")
        c = "preempt"
        b = self.btc()
        s = self.new_swap(c)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        bogus = {"terms": s["terms"], "lock": s["lock"], "claims": s["claims"], "payment": "00" * 32}
        code, r1 = self.http_code("POST", "/jobs", bogus)
        assert_equal(code, 200)
        self.hand_over(s)
        assert s["job"] != r1["id"], "the buyer's job was taken for the earlier one"
        j = self.job(s)
        assert j["has_cancel"], j
        # The same claim and payment with a cancel of no payment the service knows: refused,
        # and the buyer's cancel stays.
        other = {"terms": s["terms"], "lock": s["lock"], "claims": s["claims"], "payment": s["pay"],
                 "cancel": dummy_cancel(7)}
        code, r = self.http_code("POST", "/jobs", other)
        assert_equal(code, 400)
        self.record(c, "a cancel of no known payment", "%d: %s" % (code, r["error"]))
        assert_equal(self.job(s)["cancels"], 1)
        # What any client reads holds no signed transaction.
        assert not ({"claims", "cancel", "payment_hex", "terms"} & set(j)), sorted(j)
        assert s["cancel_hex"] not in json.dumps(self.http("GET", "/jobs/" + s["job"]))
        self.send_pay(s)
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 2 - b.getblockcount())
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=30)
        self.record(c, "at tip D - 2", "the buyer's cancel is broadcast: %s" % self.job(s)["note"])
        self.btc_mine(1)
        self.wait_job(s, ["cancelled"], produce=False, timeout=30)

    def case_cancelstate(self):
        self.log.info("(cancelstate) the cancel broadcast but not mined by D; a cancel below the BIP125 floor")
        c = "cancelstate"
        b = self.btc()
        s = self.new_swap(c)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        # A cancel at the payment's own fee + 1 sat is refused.
        d = self.bbuyer.decoderawtransaction(s["pay_hex"])
        values = []
        for vin in d["vin"]:
            prev = self.bbuyer.decoderawtransaction(self.bbuyer.gettransaction(vin["txid"])["hex"])
            values.append(int(Decimal(str(prev["vout"][vin["vout"]]["value"])) * COIN))
        pay_fee = sum(values) - sum(int(Decimal(str(o["value"])) * COIN) for o in d["vout"])
        to = self.bbuyer.getaddressinfo(self.bbuyer.getnewaddress())["scriptPubKey"]
        r = self.pl("cancel", "--payment-hex", s["pay_hex"], "--values", ",".join(map(str, values)), "--to", to,
                    "--fee", pay_fee + 1, ok=False)
        assert "at least" in r.get("error", ""), r
        self.record(c, "cancel at the payment's fee + 1 (%d sat)" % (pay_fee + 1), r["error"])
        # At the floor it replaces the payment.
        f = self.pl("cancel", "--payment-hex", s["pay_hex"], "--values", ",".join(map(str, values)), "--to", to)
        self.send_pay(s)
        t = b.testmempoolaccept([self.bbuyer.signrawtransactionwithwallet(f["hex"])["hex"]])[0]
        assert t["allowed"], t
        self.record(c, "cancel at the floor (%d sat)" % f["fee_floor"], "replaces the pooled payment: allowed")
        self.hand_over(s)
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 2 - b.getblockcount())
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=30)
        # Bitcoin's miners leave the cancel out past D.
        b.prioritisetransaction(s["cancel_id"], 0, -100_000_000)
        self.empty_btc_blocks(D + 1 - b.getblockcount())
        time.sleep(3)
        j = self.job(s)
        assert j["state"] == "waiting" and j["cancel_sent"] and self.listed(s), j
        self.record(c, "at tip D + 1, the cancel unconfirmed", "%s: %s" % (j["state"], j["note"]))
        b.prioritisetransaction(s["cancel_id"], 0, 100_000_000)
        self.btc_mine(1)
        j = self.wait_job(s, ["cancelled"], produce=False, timeout=30)
        assert_equal(self.bbuyer.gettransaction(s["cancel_id"])["confirmations"], 1)
        self.record(c, "the cancel confirmed", "%s: %s" % (j["state"], j["note"]))

    def case_afterfinal(self):
        self.log.info("(afterfinal) Bitcoin replaces the payment's block after the claim is final")
        c = "afterfinal"
        b = self.btc()
        n1 = self.nodes[1]
        s = self.new_swap(c)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        p_hash = self.btc_mine(1)[0]
        j = self.wait_job(s, ["final"])
        claim = [t for t in s["claim_ids"] if self.mined(t)][0]
        lc = n1.getrawtransaction(claim, True)["blockhash"]
        # Final is shown at once; the service watches on until the payment is buried.
        assert self.listed(s) and j.get("watching"), j
        self.record(c, "final", "claim %s at %s, shown final; watched until Bitcoin block %s is 6 deep" %
                    (claim[:16], j["mined_at"], j["decided_at"]))
        self.produce(1, ALL_KEYS)
        self.sync_tips(range(N))
        b.invalidateblock(p_hash)
        if s["pay"] not in b.getrawmempool():
            self.send_pay(s)
        self.btc_mine(2)
        self.wait_lost(lc, HONEST)
        # The service follows: the claim left the chain, and it is proven and pooled again.
        self.wait_until(lambda: self.job(s)["state"] in ("pooled", "waiting"), timeout=30)
        self.record(c, "after the reorganization", self.job(s)["note"])
        j = self.wait_job(s, ["final"])
        assert self.mined(claim)
        self.record(c, "final again", "the same claim %s at %s" % (claim[:16], j["mined_at"]))
        self.empty_btc_blocks(6)
        self.wait_until(lambda: not self.listed(s), timeout=60)
        self.record(c, "archived", "once the payment's block was 6 deep")
        self.realign()

    # ------------------------------------------------------------ the third review
    def ready(self, case):
        s = self.new_swap(case)
        self.lock_and_confirm(s)
        self.check_payable(s)
        self.buyer_sign(s)
        return s

    def floor_cancel(self, s):
        """The buyer's cancel of s's payment at the BIP125 floor, signed by its wallet."""
        w = self.bbuyer
        d = w.decoderawtransaction(s["pay_hex"])
        values = []
        for vin in d["vin"]:
            prev = w.decoderawtransaction(w.gettransaction(vin["txid"])["hex"])
            values.append(int(Decimal(str(prev["vout"][vin["vout"]]["value"])) * COIN))
        to = w.getaddressinfo(w.getnewaddress())["scriptPubKey"]
        c = self.pl("cancel", "--payment-hex", s["pay_hex"], "--values", ",".join(map(str, values)), "--to", to)
        signed = w.signrawtransactionwithwallet(c["hex"])
        assert signed["complete"], signed
        s["cancel_hex"], s["cancel_id"], s["cancel_fee"] = signed["hex"], c["txid"], c["fee"]

    def post(self, s, cancel=None, payment_hex=None, claims=None):
        job = {"terms": s["terms"], "lock": s["lock"], "claims": claims or s["claims"], "payment": s["pay"]}
        if cancel:
            job["cancel"] = cancel
        if payment_hex:
            job["payment_hex"] = payment_hex
        return self.http_code("POST", "/jobs", job)

    def cancelled_and_archived(self, s, c):
        b = self.btc()
        j = self.wait_job(s, ["cancelled"], produce=False, timeout=30)
        assert_equal(j["cancel_height"], b.getblockcount())
        assert_equal(self.bbuyer.gettransaction(s["cancel_id"])["confirmations"], 1)
        assert j["watching"] and self.listed(s), j
        self.record(c, "ended", "%s at the cancel's block %d: %s" % (j["state"], j["cancel_height"], j["note"]))
        self.empty_btc_blocks(6)
        self.wait_until(lambda: not self.listed(s), timeout=30)
        self.record(c, "archived", "once the cancel's block was 6 deep")

    def case_unconf(self):
        self.log.info("(unconf) the payment spends an unconfirmed coin; the cancel unmined past D")
        c = "unconf"
        b, w = self.btc(), self.bbuyer
        s = self.ready(c)
        a = w.getnewaddress("", "bech32")
        parent = w.sendtoaddress(a, Decimal("0.7"))
        pd = w.gettransaction(parent, True, True)["decoded"]
        vout = [o["n"] for o in pd["vout"] if o["scriptPubKey"].get("address") == a][0]
        change = w.getnewaddress("", "bech32")
        raw = w.createrawtransaction([{"txid": parent, "vout": vout, "sequence": 0xfffffffd}],
                                     [{s["recv"]: Decimal(s["price"]) / COIN},
                                      {change: Decimal("0.7") - Decimal(s["price"]) / COIN - Decimal("0.00002")}])
        s["pay_hex"] = w.signrawtransactionwithwallet(raw)["hex"]
        s["pay"] = w.decoderawtransaction(s["pay_hex"])["txid"]
        self.floor_cancel(s)
        self.hand_over(s)
        self.send_pay(s)
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 2 - b.getblockcount())
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=30)
        # Bitcoin's blocks leave the parent and the cancel out past D.
        self.empty_btc_blocks(D + 1 - b.getblockcount())
        time.sleep(3)
        j = self.job(s)
        conf = w.gettransaction(s["cancel_id"])["confirmations"]
        self.record(c, "at tip D + 1, the cancel and its parent unconfirmed",
                    "%s (cancel confirmations %d, parent %d): %s" % (
                        j["state"], conf, w.gettransaction(parent)["confirmations"], j["note"]))
        assert_equal(conf, 0)
        assert j["state"] == "waiting" and j["cancel_sent"] and not j["watching"], j
        self.btc_mine(1)
        self.cancelled_and_archived(s, c)

    def case_bumplate(self):
        self.log.info("(bumplate) the buyer's bump, above its cancel's fee, mined at D + 1")
        c = "bumplate"
        b, w = self.btc(), self.bbuyer
        s = self.ready(c)
        self.make_payment(s, cancel=False)
        self.floor_cancel(s)
        self.hand_over(s)
        self.send_pay(s)
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 3 - b.getblockcount())
        bump = w.bumpfee(s["pay"], {"fee_rate": 50})
        self.record(c, "bump", "payment %s bumped to %s at %s BTC fee; the cancel pays %d sat" % (
            s["pay"][:16], bump["txid"][:16], bump["fee"], s["cancel_fee"]))
        self.empty_btc_blocks(1)
        time.sleep(3)
        mp = b.getrawmempool()
        assert bump["txid"] in mp and s["cancel_id"] not in mp, mp
        self.record(c, "at tip D - 2", "the cancel cannot replace the bump: %s" % self.job(s)["note"])
        self.empty_btc_blocks(D - b.getblockcount())
        blk = b.generateblock(self.btc("miner").getnewaddress(), [bump["txid"]])["hash"]
        assert_equal(b.getblockheader(blk)["height"], D + 1)
        j = self.wait_job(s, ["never"], produce=False, timeout=30)
        assert_equal(j["payment_height"], D + 1)
        assert j["payment_bumped"], j
        assert "after the deadline" in j["note"], j
        self.record(c, "the bump mined at D + 1", "%s: %s" % (j["state"], j["note"]))
        self.empty_btc_blocks(6)
        self.wait_until(lambda: not self.listed(s), timeout=30)
        self.record(c, "archived", "once the bump's block was 6 deep")

    def case_bumpin(self):
        self.log.info("(bumpin) the buyer's bump mined inside the window")
        c = "bumpin"
        b, w = self.btc(), self.bbuyer
        s = self.ready(c)
        self.make_payment(s)
        self.hand_over(s)
        self.send_pay(s)
        bump = w.bumpfee(s["pay"], {"fee_rate": 50})
        blk = b.generateblock(self.btc("miner").getnewaddress(), [bump["txid"]])["hash"]
        h = b.getblockheader(blk)["height"]
        assert s["terms"]["floor"] < h <= s["terms"]["deadline"]
        self.record(c, "bump", "%s mined at Bitcoin %d (D = %d), paying the seller" % (bump["txid"][:16], h, s["terms"]["deadline"]))
        t0 = time.time()
        j = self.wait_job(s, ["final"], timeout=90)
        assert_equal(j["payment_height"], h)
        assert j["payment_bumped"], j
        self.record(c, "service", "final %.1f s after the bump's block: %s" % (time.time() - t0, j["note"]))
        txid, d = self.assert_buyer_paid(s, j)
        # The proof carries the bump itself: its change output, smaller than the payment's.
        def change_out(t):
            o = [o for o in t["vout"] if o["scriptPubKey"].get("address") != s["recv"]][0]
            sat = int(Decimal(str(o["value"])) * COIN)
            spk = o["scriptPubKey"]["hex"]
            return sat.to_bytes(8, "little").hex() + "%02x" % (len(spk) // 2) + spk
        record = d["vin"][0]["pegin_witness"][0]
        assert change_out(b.getrawtransaction(bump["txid"], True, blk)) in record
        assert change_out(b.decoderawtransaction(s["pay_hex"])) not in record
        self.record(c, "proof", "the claim %s carries a proof of the bump %s" % (txid[:16], bump["txid"][:16]))
        self.sync_tips(range(N))

    def case_block(self):
        self.log.info("(block) an unsigned spend of the payment's coins, posted first")
        c = "block"
        b = self.btc()
        s = self.ready(c)
        self.make_payment(s)
        self.send_pay(s)
        p = b.getrawtransaction(s["pay"], True)
        fake = b.createrawtransaction([{"txid": i["txid"], "vout": i["vout"]} for i in p["vin"]],
                                      [{self.bseller.getnewaddress(): Decimal("0.0001")}])
        code, r = self.post(s, fake, b.getrawtransaction(s["pay"]))
        self.record(c, "another client's post, an unsigned spend of the payment's coins", "%d: %s" % (code, r.get("error", r)))
        assert_equal(code, 400)
        assert "signatures do not verify" in r["error"], r
        code, r = self.post(s, s["cancel_hex"], s["pay_hex"])
        assert_equal(code, 200)
        s["job"] = r["id"]
        assert_equal(self.job(s)["cancels"], 1)
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 2 - b.getblockcount())
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=30)
        assert s["pay"] not in b.getrawmempool()
        self.record(c, "at tip D - 2", "the buyer's cancel replaced the payment: %s" % self.job(s)["note"])
        self.btc_mine(1)
        self.cancelled_and_archived(s, c)

    def case_nopayment(self):
        self.log.info("(nopayment) a dummy cancel with no signed payment, and a first post with the top tier only")
        c = "nopayment"
        b = self.btc()
        s = self.ready(c)
        self.make_payment(s)
        bad = {"terms": s["terms"], "lock": s["lock"], "claims": s["claims"], "payment": s["pay"],
               "cancel": dummy_cancel(11)}
        code, r = self.http_code("POST", "/jobs", bad)
        assert_equal(code, 400)
        self.record(c, "a dummy cancel before the payment is broadcast", "%d: %s" % (code, r["error"]))
        code, r = self.post(s, claims=s["claims"][1:])
        assert_equal(code, 200)
        first = r["id"]
        self.send_pay(s)
        code, r = self.http_code("POST", "/jobs", bad)
        assert_equal(code, 400)
        assert "exactly the payment's coins" in r["error"], r
        self.record(c, "the dummy cancel after it is broadcast", "%d: %s" % (code, r["error"]))
        code, r = self.post(s, s["cancel_hex"], s["pay_hex"])
        assert_equal(code, 200)
        s["job"] = r["id"]
        assert_equal(s["job"], first)
        j = self.job(s)
        assert_equal((j["tiers"], j["cancels"]), (len(s["claims"]), 1))
        self.record(c, "the buyer's post", "merged into the first job (%s): %d claims, %d cancel" % (
            ", ".join(r.get("merged", [])), j["tiers"], j["cancels"]))
        D = s["terms"]["deadline"]
        self.empty_btc_blocks(D - 2 - b.getblockcount())
        self.wait_until(lambda: s["cancel_id"] in b.getrawmempool(), timeout=30)
        self.record(c, "at tip D - 2", self.job(s)["note"])
        self.btc_mine(1)
        self.cancelled_and_archived(s, c)

    def run_test(self):
        try:
            self.wallets()
            self.start_service()
            for c in CASES:
                getattr(self, "case_" + c)()
        finally:
            self.stop_service()
            if RESULTS:
                with open(RESULTS, "w") as f:
                    json.dump(self.results, f, indent=1)
            self.stop_bitcoind()


if __name__ == '__main__':
    if not any(a.startswith("--configfile") for a in sys.argv):
        sys.argv.append("--configfile=" + os.path.join(os.environ["PAYLOCK_NODE_FUNCTIONAL"], "..", "config.ini"))
    PayLockRegtest().main()
