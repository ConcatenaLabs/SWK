#!/usr/bin/env python3
"""SWK's script-path and message signers, driven through the wasm bindings,
spend the Arca reference scripts on a regtest node.

Every key here is SWK's: the operator and the owners are two SWK software
signers whose mnemonics are generated inside the wasm driver (arca_regtest_driver.js) and
never leave it. The scripts, trees and transactions are built by the Arca
reference library (arklib3, the frozen constructions); every signature comes
from SWK: `signCsfs` for the unroll authorisation, the collaborative path and
the release, `signTapscript` for the exit claim and the reclaim's operator
signature. Each message and signature hash SWK computes is also compared with
the reference's own.

  node A  [gated timed UNROLL, RECLAIM]   unrolled with an authorisation SWK signed
  leaf 0  exit claim                        signTapscript
  leaf 1  collaborative, m = 2              signCsfs by owner and operator
  leaf 2  collaborative, m = 1              signCsfs by owner and operator
  node B  [gated timed UNROLL, RECLAIM]   reclaimed: four SWK releases + signTapscript

Negative cases are forced into a block with generateblock, on a node started
with -par=1 so that the block's error names the script failure, and each is
asserted to fail for its own reason in the mempool and in the block. SWK's
refusals are recorded with their error strings: a signature for another chain
than the signer's network, a rebind that leaves more than its ceiling to
whoever broadcasts, and a sighash type that leaves outputs free.
"""
import json
import os as _os
import subprocess
import sys

# The Arca reference library: regtest/ of the arca repository.
sys.path.insert(0, _os.environ["ARCA_REGTEST"])
from arklib3 import *  # noqa: E402,F401,F403

LEAF = 1000_0000
RESERVE = 1000
FEE = 1500
H = 3600
DELAY = rel_time(36 * H)
DRIVER = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "arca_regtest_driver.js")


class Swk:
    """One wasm process; requests and replies are JSON lines."""

    def __init__(self):
        self.p = subprocess.Popen(["node", DRIVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def call(self, **req):
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def ok(self, **req):
        r = self.call(**req)
        assert "ok" in r, (req.get("op"), r)
        return r["ok"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=30)


SIG = "Invalid Schnorr signature"


class ArcaSigners(Ark3, ArkBase, BitcoinTestFramework):
    NAME = "swk_signers"
    # Scripts checked one at a time: a block refused for a script failure then
    # names it, instead of the generic block-validation-failed.
    EXTRA = ["-par=1"]

    def set_test_params(self):
        self.ark_params()

    def run_test(self):
        self.swk = Swk()
        try:
            self.flow()
        finally:
            self.swk.close()

    # -- helpers -------------------------------------------------------------
    def key(self, signer, path):
        return bytes.fromhex(self.swk.ok(op="xonly", signer=signer, path=path))

    def outputs_json(self, outs3):
        return [{"asset": self.X, "value": v, "scriptPubkey": bytes(spk).hex()} for (_, v, spk) in outs3]

    def children_json(self, kids):
        return [{"asset": self.X, "value": v, "scriptPubkey": (bytes([0x51, 0x20]) + p).hex()} for (_, v, p) in kids]

    def csfs(self, signer, path, message, expect_digest, limits=None):
        """SWK rebuilds the digest from the fields; it must equal the
        reference's, and SWK signs only that digest. A rebind may leave the
        fee, FEE atoms, to whoever broadcasts."""
        d = self.swk.ok(op="digest", message=message)
        assert d == expect_digest.hex(), (message["kind"], d, expect_digest.hex())
        limits = limits or {"maxUncommitted": FEE}
        return bytes.fromhex(self.swk.ok(op="csfs", signer=signer, path=path, message=message, digest=d,
                                         limits=limits))

    def refuse(self, tx, label, why):
        """Refused by the mempool and when forced into a block, each time for
        `why`."""
        self.reject(tx, label, expect=why)
        block = self.R[label]["block-error"]
        assert why in block, (label, block)

    def tapscript(self, signer, path, tx, idx, tap, name, genesis=None, check=True):
        self.pad(tx)
        leaf = tap.leaves[name].script
        req = dict(tx=tx.serialize().hex(), inputIndex=idx, prevouts=[u.txout.serialize().hex() for u in tx.prev],
                   leaf=bytes(leaf).hex(), controlBlock=control_block(tap, name).hex(), sighashType=0,
                   genesis=genesis or self.genesis_display)
        if check:
            sh = self.swk.ok(op="sighash", **req)
            assert sh == self.sighash(tx, idx, leaf).hex(), "SWK's tapscript sighash differs from the reference"
        return bytes.fromhex(self.swk.ok(op="tapscript", signer=signer, path=path, **req))

    def refusal(self, label, **req):
        r = self.swk.call(**req)
        assert "error" in r, "%s: SWK signed (%s)" % (label, r)
        self.log.info("SWK REFUSED %-40s %s", label, r["error"])
        self.rec(label, {"swk_refused": True, "error": r["error"]})

    def make_node(self, salts):
        leaves = [leaf3_taptree(self.ox[i], self.s_x, salts[i], self.ctag, DELAY, fold=True) for i in range(4)]
        kids = [(self.X_ID, LEAF, bytes(t.scriptPubKey)[2:]) for t, _ in leaves]
        keys = [self.s_x] + self.ox
        levels, padded = hmerkle(keys, self.s_x)
        unroll = hgate_unroll(levels[-1][0], len(levels) - 1, kids, timed=True)
        reclaim = reclaim_leaf(release_msg(self.gen, kids), self.ox, self.s_x)
        tap = taproot_construct(NUMS, [("unroll", unroll), ("reclaim", reclaim)])
        return {"tap": tap, "kids": kids, "leaves": leaves, "levels": levels, "keys": padded, "salts": salts,
                "value": 4 * LEAF + RESERVE}

    # -- the flow ------------------------------------------------------------
    def flow(self):
        self.boot(issue=("X",))
        self.whitelist(self.X)
        self.clock_start()
        self.gen = self.genesis_internal()
        self.genesis_display = self.node.getblockhash(0)
        self.genesis_reversed = self.gen.hex()          # the internal bytes read as display hex: the wrong order
        self.ctag = chain_tag(self.gen)
        net = dict(genesis=self.genesis_display, policyAsset=self.X)
        op, own = self.swk.ok(op="new", **net), self.swk.ok(op="new", **net)
        self.s_x = self.key(op, "m/6/0")
        self.ox = [self.key(own, "m/6/%d" % i) for i in range(4)]
        self.rec("keys", {"operator": self.s_x.hex(), "owners": [x.hex() for x in self.ox],
                          "paths": "operator m/6/0 of one SWK signer; owners m/6/0..3 of another"})

        A = self.make_node([_os.urandom(32) for _ in range(4)])
        B = self.make_node([_os.urandom(32) for _ in range(4)])
        self.rec_script("scripts/node_unroll", A["tap"].leaves["unroll"].script, A["tap"], "unroll")
        self.rec_script("scripts/node_reclaim", A["tap"].leaves["reclaim"].script, A["tap"], "reclaim")
        self.rec_script("scripts/leaf_collab", A["leaves"][0][1]["collab"], A["leaves"][0][0], "collab")
        self.rec_script("scripts/leaf_exit", A["leaves"][0][1]["exit"], A["leaves"][0][0], "exit")
        uA = self.fund(A["tap"].scriptPubKey, A["value"], self.X)
        uB = self.fund(B["tap"].scriptPubKey, B["value"], self.X)

        # ---- unroll node A with an authorisation SWK signed (owner 0, member 1)
        t = self.mtp() - 60
        auth = {"kind": "unroll", "children": self.children_json(A["kids"]), "time": t}
        self.rec("describe/unroll", self.swk.ok(op="describe", message=auth))
        sig = self.csfs(own, "m/6/0", auth, unroll_auth3(A["kids"], t))

        def unroll_tx(sig_, t_=t):
            outs = [self.out(LEAF, bytes([0x51, 0x20]) + p, self.X_OUT) for (_, _, p) in A["kids"]]
            tx = self.mktx([(uA, 0xfffffffe)], outs + [self.fee(RESERVE, self.X_OUT)], t_)
            wit = hgate_witness(sig_, mpath(A["levels"], 1), A["keys"][1], t_)
            self.setwit(tx, 0, wit + [bytes(A["tap"].leaves["unroll"].script), control_block(A["tap"], "unroll")])
            return tx
        later = dict(auth, time=t + 1)
        self.refuse(unroll_tx(self.csfs(own, "m/6/0", later, unroll_auth3(A["kids"], t + 1))),
                    "neg/unroll_auth_signed_for_another_time", SIG)
        other = dict(auth, children=self.children_json(B["kids"]))
        self.refuse(unroll_tx(self.csfs(own, "m/6/0", other, unroll_auth3(B["kids"], t))),
                    "neg/unroll_auth_signed_for_another_node", SIG)
        self.refuse(unroll_tx(self.csfs(own, "m/6/1", auth, unroll_auth3(A["kids"], t))),
                    "neg/unroll_auth_by_another_members_key", SIG)
        txid = self.send(unroll_tx(sig), "pos/unroll_with_swk_authorisation")
        ls = [Utxo(txid, i, self.utxo_at(txid, i).txout) for i in range(4)]

        # ---- SWK's refusals: a digest whose preimage does not match, or is not given
        d_other = self.swk.ok(op="digest", message=other)
        self.refusal("swk/refuses_digest_of_another_node", op="csfs", signer=own, path="m/6/0",
                     message=auth, digest=d_other)
        d_auth = self.swk.ok(op="digest", message=auth)
        self.refusal("swk/refuses_digest_without_preimage", op="csfs", signer=own, path="m/6/0", digest=d_auth)
        self.refusal("swk/refuses_height_as_authorisation_time", op="csfs", signer=own, path="m/6/0",
                     message=dict(auth, time=1000), digest=d_auth)

        # ---- leaf 1: collaborative path, m = 2, both signatures from SWK
        tap1, lv1 = A["leaves"][1]
        rx = compute_xonly_pubkey(generate_privkey())[0]
        recv = leaf3_taptree(rx, self.s_x, _os.urandom(32), self.ctag, DELAY, fold=True)[0]
        chg = leaf3_taptree(self.ox[1], self.s_x, _os.urandom(32), self.ctag, DELAY, fold=True)[0]
        outs3 = [(self.X_ID, 6000_000, bytes(recv.scriptPubKey)),
                 (self.X_ID, LEAF - 6000_000 - FEE, bytes(chg.scriptPubKey))]
        # The leaves are in no batch here, so each is named by its own witness program.
        def source(leaf_tap, salt):
            return {"path": "leaf", "leafId": bytes(leaf_tap.scriptPubKey)[2:].hex(),
                    "genesisHash": self.genesis_display, "salt": salt.hex()}
        rb = {"kind": "rebind", "source": source(tap1, A["salts"][1]),
              "assetIn": self.X, "valueIn": LEAF, "outputs": self.outputs_json(outs3)}
        self.rec("describe/rebind", self.swk.ok(op="describe", message=rb))
        ref = rebind_msg3(self.ctag, A["salts"][1], self.X_ID, LEAF, outs3, fold=True)
        sA, sS = self.csfs(own, "m/6/1", rb, ref), self.csfs(op, "m/6/0", rb, ref)
        # The fee margin at the relay floor the node gives X (listed 1:1) is
        # four times the floor for a 359 vB spend, less than the FEE this
        # transfer leaves; and a rebind for the chain's genesis in display
        # order is for another chain.
        floor = int(self.node.getmempoolinfo()["minrelaytxfee"] * 100_000_000)
        d_rb = self.swk.ok(op="digest", message=rb)
        self.refusal("swk/refuses_rebind_above_the_fee_margin", op="csfs", signer=own, path="m/6/1", message=rb,
                     digest=d_rb, limits={"feeFloorPerKvb": floor})
        wrong = dict(rb, source=dict(rb["source"], genesisHash=self.genesis_reversed))
        self.refusal("swk/refuses_rebind_for_display_order_genesis", op="csfs", signer=own, path="m/6/1",
                     message=wrong, digest=self.swk.ok(op="digest", message=wrong))

        def collab_tx(u, tap, lv, outs3_, sig_s, sig_a, m=None, shave=0):
            outs = [self.out(v - (shave if j == 0 else 0), spk, self.X_OUT) for j, (_, v, spk) in enumerate(outs3_)]
            left = u.amount - sum(v for (_, v, _) in outs3_) + shave
            tx = self.mktx([u], outs + [self.fee(left, self.X_OUT)])
            self.setwit(tx, 0, [sig_s, sig_a, bytes([m or len(outs3_)]), bytes(lv["collab"]),
                                control_block(tap, "collab")])
            return tx
        self.refuse(collab_tx(ls[1], tap1, lv1, outs3, sS, sA, shave=1), "neg/collab_output_one_atom_less", SIG)
        self.refuse(collab_tx(ls[1], tap1, lv1, outs3, sA, sS), "neg/collab_signatures_swapped", SIG)
        self.refuse(collab_tx(ls[1], tap1, lv1, outs3, sS, sA, m=1), "neg/collab_wrong_m", SIG)
        coin = dict(rb, valueIn=LEAF + 1)
        cref = rebind_msg3(self.ctag, A["salts"][1], self.X_ID, LEAF + 1, outs3, fold=True)
        more = {"maxUncommitted": FEE + 1}
        self.refuse(collab_tx(ls[1], tap1, lv1, outs3, self.csfs(op, "m/6/0", coin, cref, more),
                              self.csfs(own, "m/6/1", coin, cref, more)), "neg/collab_signed_for_another_coin_value",
                    SIG)
        self.send(collab_tx(ls[1], tap1, lv1, outs3, sS, sA), "pos/collab_m2_swk_owner_and_operator")

        # ---- leaf 2: collaborative path, m = 1
        tap2, lv2 = A["leaves"][2]
        outs3 = [(self.X_ID, LEAF - FEE, bytes(recv.scriptPubKey))]
        rb2 = dict(rb, source=source(tap2, A["salts"][2]), outputs=self.outputs_json(outs3))
        ref2 = rebind_msg3(self.ctag, A["salts"][2], self.X_ID, LEAF, outs3, fold=True)
        self.send(collab_tx(ls[2], tap2, lv2, outs3, self.csfs(op, "m/6/0", rb2, ref2),
                            self.csfs(own, "m/6/2", rb2, ref2)), "pos/collab_m1_swk_owner_and_operator")

        # ---- leaf 0: exit claim signed by signTapscript after the exit delay
        tap0, lv0 = A["leaves"][0]
        self.mtp_past(self.csv_ready_at(ls[0].txid, 36 * H))
        tx = self.mktx([(ls[0], DELAY)], [self.out(LEAF - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.refusal("swk/refuses_exit_with_a_key_not_in_the_leaf", op="tapscript", signer=op, path="m/6/0",
                     tx=tx.serialize().hex(), inputIndex=0, prevouts=[ls[0].txout.serialize().hex()],
                     leaf=bytes(lv0["exit"]).hex(), controlBlock=control_block(tap0, "exit").hex(), sighashType=0,
                     genesis=self.genesis_display)
        self.refusal("swk/refuses_exit_with_the_collab_control_block", op="tapscript", signer=own, path="m/6/0",
                     tx=tx.serialize().hex(), inputIndex=0, prevouts=[ls[0].txout.serialize().hex()],
                     leaf=bytes(lv0["exit"]).hex(), controlBlock=control_block(tap0, "collab").hex(), sighashType=0,
                     genesis=self.genesis_display)
        exit_req = dict(tx=tx.serialize().hex(), inputIndex=0, prevouts=[ls[0].txout.serialize().hex()],
                        leaf=bytes(lv0["exit"]).hex(), controlBlock=control_block(tap0, "exit").hex())
        self.refusal("swk/refuses_exit_for_display_order_genesis", op="tapscript", signer=own, path="m/6/0",
                     sighashType=0, genesis=self.genesis_reversed, **exit_req)
        self.refusal("swk/refuses_exit_under_sighash_none", op="tapscript", signer=own, path="m/6/0",
                     sighashType=2, genesis=self.genesis_display, **exit_req)
        self.rec("describe/exit_under_sighash_none",
                 self.swk.ok(op="tapdescribe", sighashType=2, genesis=self.genesis_display, **exit_req))
        sig = self.tapscript(own, "m/6/0", tx, 0, tap0, "exit")
        self.setwit(tx, 0, [sig, bytes(lv0["exit"]), control_block(tap0, "exit")])
        self.send(tx, "pos/exit_claim_signed_by_sign_tapscript")

        # ---- node B: reclaim with four SWK releases and the operator's tapscript signature
        rel = {"kind": "release", "genesisHash": self.genesis_display, "children": self.children_json(B["kids"])}
        self.rec("describe/release", self.swk.ok(op="describe", message=rel))
        rref = release_msg(self.gen, B["kids"])
        rsigs = [self.csfs(own, "m/6/%d" % i, rel, rref) for i in range(4)]
        relw = dict(rel, genesisHash=self.genesis_reversed)
        self.refusal("swk/refuses_release_for_display_order_genesis", op="csfs", signer=own, path="m/6/0",
                     message=relw, digest=self.swk.ok(op="digest", message=relw))

        def reclaim_tx(owner_sigs):
            tx = self.mktx([uB], [self.out(uB.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
            s = self.tapscript(op, "m/6/0", tx, 0, B["tap"], "reclaim")
            leaf = B["tap"].leaves["reclaim"].script
            self.setwit(tx, 0, [s] + list(reversed(owner_sigs)) + [bytes(leaf), control_block(B["tap"], "reclaim")])
            return tx
        self.refuse(reclaim_tx(rsigs[:3] + [b""]), "neg/three_releases_of_four",
                    "Script failed an OP_CHECKSIGVERIFY operation")
        self.refuse(reclaim_tx(rsigs[1:] + rsigs[:1]), "neg/releases_in_the_wrong_slots", SIG)
        rtx = self.mktx([uB], [self.out(uB.amount - FEE, self.wallet_spk(), self.X_OUT), self.fee(FEE, self.X_OUT)])
        self.pad(rtx)
        self.refusal("swk/refuses_reclaim_for_display_order_genesis", op="tapscript", signer=op, path="m/6/0",
                     tx=rtx.serialize().hex(), inputIndex=0, prevouts=[uB.txout.serialize().hex()],
                     leaf=bytes(B["tap"].leaves["reclaim"].script).hex(),
                     controlBlock=control_block(B["tap"], "reclaim").hex(), sighashType=0,
                     genesis=self.genesis_reversed)
        self.send(reclaim_tx(rsigs), "pos/reclaim_swk_releases_and_sign_tapscript")


if __name__ == "__main__":
    ArcaSigners().main()
