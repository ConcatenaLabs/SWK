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
           leaves with it, and its old proof is refused;
  remined  the payment's block is replaced and the payment mined again: the service
           proves the same claim again and it completes;
  anchor   the lock's anchor is replaced: the lock comes back first, the seller's
           respend is refused, the claim completes.

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
from test_framework.util import assert_equal, get_auth_cookie, p2p_port, rpc_port  # noqa: E402

CASES = os.environ.get("PAYLOCK_CASES", "path,unpaid,late,gone,remined,anchor").split(",")
RESULTS = os.environ.get("PAYLOCK_RESULTS", "")
BUYER = 1  # the buyer's node, which the completion service also reads
COIN = Decimal(100_000_000)
COMMITMENT = bytes.fromhex("6a24aa21a9ed")  # OP_RETURN, push 36, the witness commitment header


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
                                     "--interval", "0.5"], env=self.pl_env(), stdout=self.svc_log, stderr=self.svc_log)
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
    def new_swap(self, case, price=50_000_000, atoms=1_000_000_000, margin=None):
        bsk, ssk = generate_privkey(), generate_privkey()
        rk = ECKey()
        rk.generate(compressed=True)
        args = ["terms", "--asset", self.asset, "--atoms", atoms, "--price", price,
                "--buyer", compute_xonly_pubkey(bsk)[0].hex(), "--seller", compute_xonly_pubkey(ssk)[0].hex(),
                "--receive-key", rk.get_pubkey().get_bytes().hex()]
        if margin:
            args += ["--margin", margin]
        t = self.pl(*args)
        tfile = os.path.join(self.options.tmpdir, "terms-%s-%d.json" % (case, time.time_ns()))
        with open(tfile, "w") as f:
            json.dump(t["terms"], f)
        spk = bytes.fromhex(t["lock_script_pubkey"])
        a = self.nodes[SELLER]
        raw = a.createrawtransaction([], [{program_to_witness(1, spk[2:]): Decimal(atoms) / COIN}])
        funded = a.fundrawtransaction(raw, {"fee_asset": "bitcoin", "replaceable": False, "change_type": "bech32"})["hex"]
        lock_hex = a.signrawtransactionwithwallet(funded)["hex"]
        lt = tx_from_hex(lock_hex)
        txid = lt.rehash()
        vout = [i for i, o in enumerate(lt.vout) if o.scriptPubKey == spk][0]
        s = dict(case=case, terms=t["terms"], tfile=tfile, lock_hex=lock_hex, txid=txid, vout=vout,
                 lock="%s:%d" % (txid, vout), bkey=self.keyfile(bsk, case + "-buyer"),
                 skey=self.keyfile(ssk, case + "-seller"), recv=t["receive_address"], price=price, atoms=atoms)
        self.record(case, "terms", "F %d, D %d, R %d (Bitcoin tip %d); %d atoms for %d sat to %s" %
                    (t["terms"]["floor"], t["terms"]["deadline"], t["terms"]["refund_at"], self.btc().getblockcount(),
                     atoms, price, s["recv"]))
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

    def buyer_sign(self, s):
        n1 = self.nodes[1]
        s["to"] = n1.getaddressinfo(n1.getnewaddress())["scriptPubKey"]
        c = self.pl("sign-claim", "--terms", s["tfile"], "--lock", s["lock"], "--key-file", s["bkey"],
                    "--to", s["to"], "--fee", 5000)
        s["claims"], s["claim_ids"] = c["claims"], c["txids"]
        self.record(s["case"], "claims", "signed before paying: tiers %s, fees %s atoms" %
                    ([t[:12] for t in c["txids"]], c["fees"]))

    def make_payment(self, s, cancel=True):
        b = self.bbuyer
        raw = b.createrawtransaction([], [{s["recv"]: Decimal(s["price"]) / COIN}])
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

    def claim_with_python_proof(self, s, pay_txid, blockhash=None):
        """The buyer's signed claim (the crate's) completed with the node suite's own proof builder."""
        n1 = self.nodes[1]
        bh = n1.getrawtransaction(s["txid"], True)["blockhash"]
        pr = self.proof_for(pay_txid, n1.getblockheader(bh)["anchorheight"], blockhash=blockhash)
        t = self.btc().getrawtransaction(pay_txid, True, pr["blockhash"])
        vout = [o["n"] for o in t["vout"] if o["scriptPubKey"].get("address") == s["recv"]][0]
        tx = tx_from_hex(s["claims"][0])
        tx.wit.vtxinwit[0].scriptWitness.stack[0] = bp.scriptnum(vout)
        tx.wit.vtxinwit[0].peginWitness.stack = [pr["record"]]
        tx.rehash()
        return tx.serialize().hex(), pr

    def assert_buyer_paid(self, s, j):
        n1 = self.nodes[1]
        txid = [t for t in s["claim_ids"] if self.mined(t)][0]
        d = n1.getrawtransaction(txid, True)
        o = d["vout"][0]
        assert_equal(o["scriptPubKey"]["hex"], s["to"])
        fee = int(Decimal(str(d["vout"][1]["value"])) * COIN)
        assert_equal(int(Decimal(str(o["value"])) * COIN), s["atoms"] - fee)
        proof = len(bytes.fromhex(d["vin"][0]["pegin_witness"][0])) if d["vin"][0].get("pegin_witness") else 0
        self.record(s["case"], "outcome", "claim %s (tier %d) final at height %s: %d atoms to the buyer, fee %d, "
                    "vsize %d, proof %d bytes" % (txid[:16], s["claim_ids"].index(txid), j["mined_at"],
                                                  s["atoms"] - fee, fee, d["vsize"], proof))
        return txid

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
        self.btc().sendrawtransaction(s["pay_hex"])
        t0 = time.time()
        self.btc_mine(1)
        self.record("path", "payment", "%s mined in Bitcoin block %d" % (s["pay"][:16], self.btc().getblockcount()))
        j = self.wait_job(s, ["final"])
        self.record("path", "service", "final %.1f s after the payment's block: %s" % (time.time() - t0, j["note"]))
        self.assert_buyer_paid(s, j)
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
        b.sendrawtransaction(s["pay_hex"])
        D = s["terms"]["deadline"]
        # Blocks without the payment, up to three before D: no cancel yet.
        self.empty_btc_blocks(D - 3 - b.getblockcount())
        time.sleep(2)
        assert self.job(s)["state"] == "waiting", self.job(s)
        assert s["pay"] in b.getrawmempool()
        self.empty_btc_blocks(1)
        j = self.wait_job(s, ["cancelled"], produce=False, timeout=30)
        self.record("late", "service at tip %d (D - 2)" % b.getblockcount(), j["note"])
        mp = b.getrawmempool()
        assert s["cancel_id"] in mp and s["pay"] not in mp, mp
        self.btc_mine(1)
        assert self.bbuyer.gettransaction(s["cancel_id"])["confirmations"] == 1
        self.record("late", "cancel", "%s replaced the payment and is mined; the buyer keeps its bitcoin" % s["cancel_id"][:16])

        # A payment with no cancel, mined one block after D.
        s2 = self.new_swap("late")
        self.lock_and_confirm(s2)
        self.check_payable(s2)
        self.buyer_sign(s2)
        self.make_payment(s2, cancel=False)
        self.hand_over(s2)
        b.sendrawtransaction(s2["pay_hex"])
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
        self.btc().sendrawtransaction(s["pay_hex"])
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
        j = self.wait_job(s, ["waiting"], timeout=60)
        self.record("gone", "service", j["note"])
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
            b.sendrawtransaction(s["pay_hex"])
        self.btc_mine(2)
        self.wait_lost(s["LC"], HONEST)
        on = self.bbuyer.gettransaction(s["pay"])
        self.record("remined", "reorg", "Bitcoin block %d replaced; the payment mined again in %s" % (s["p"], on["blockhash"][:16]))
        self.anchored_block(b.getblockcount())
        self.force("remined", "the claim with the proof of the replaced block", [s["old_claim"]],
                   "bad-btcpay-not-in-anchor-chain")
        self.start_service()
        j = self.wait_job(s, ["final"])
        txid = self.assert_buyer_paid(s, j)
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
        b.sendrawtransaction(s["pay_hex"])
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
