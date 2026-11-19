#!/usr/bin/env python3
"""`paylock terms` reads activation before it builds anything.

Against real nodes and against a stub that answers `getdeploymentinfo` only:

  inactive   a node with `-con_btc_payment_height` far ahead: neither rule active;
  partial    a node on a chain without proof-of-stake: `btc_payment` active and
             `lost_blocks` not reported;
  stubs      the reports `btc_payment` off with `lost_blocks` on (the review's
             reproduction), the reverse, and both on.

Gated, `terms` answers `"payment_lock": false` with no lock and no receiving address,
before it reads Bitcoin at all (the Bitcoin URL given is closed). With both on, it goes
past the gate to read the chains (the stub then has nothing to say). The active case on a
real proof-of-stake chain is `paylock_regtest.py`'s `path`.

Run from anywhere:
  PAYLOCK_SEQUENTIAD=<node>/src/sequentiad PAYLOCK_BIN=<target>/debug/paylock \\
    python3 paylock_activation.py <empty work dir>
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

SEQUENTIAD = os.environ["PAYLOCK_SEQUENTIAD"]
PAYLOCK = os.environ["PAYLOCK_BIN"]
WORK = sys.argv[1]
KEY = "02" + "11" * 32
X1, X2 = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", \
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ASSET = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23"
RECEIVE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def terms(url, user="u", pw="p"):
    env = dict(os.environ, PAYLOCK_SEQ_URL=url, PAYLOCK_SEQ_USER=user, PAYLOCK_SEQ_PASS=pw,
               PAYLOCK_BTC_URL="http://127.0.0.1:1", PAYLOCK_BTC_USER="u", PAYLOCK_BTC_PASS="p")
    r = subprocess.run([PAYLOCK, "terms", "--asset", ASSET, "--atoms", "1000", "--price", "5000",
                        "--buyer", X1, "--seller", X2, "--receive-key", RECEIVE],
                       capture_output=True, text=True, env=env, timeout=60)
    return json.loads(r.stdout.strip().splitlines()[-1])


def activation(url, user="u", pw="p"):
    env = dict(os.environ, PAYLOCK_SEQ_URL=url, PAYLOCK_SEQ_USER=user, PAYLOCK_SEQ_PASS=pw)
    r = subprocess.run([PAYLOCK, "activation"], capture_output=True, text=True, env=env, timeout=60)
    return json.loads(r.stdout.strip().splitlines()[-1])


def gated(v):
    assert v.get("payment_lock") is False, v
    assert v.get("use") == "today's swap", v
    assert "lock_script_pubkey" not in v and "receive_address" not in v and "terms" not in v, v


def stub(report):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if req["method"] == "getdeploymentinfo":
                out = {"result": report, "error": None, "id": req["id"]}
            else:
                out = {"result": None, "error": {"code": -32601, "message": "stub: no " + req["method"]}, "id": req["id"]}
            b = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def node(name, extra):
    d = os.path.join(WORK, name)
    os.makedirs(d)
    port = free_port()
    p = subprocess.Popen([SEQUENTIAD, "-chain=elementsregtest", "-datadir=" + d, "-listen=0", "-server=1",
                          "-rpcport=%d" % port, "-rpcuser=u", "-rpcpassword=p", "-validatepegin=0",
                          "-disablewallet=1", "-printtoconsole=0"] + extra,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = "http://127.0.0.1:%d" % port
    for _ in range(120):
        try:
            if "deployments" in str(activation(url)) or "payment_lock" in activation(url):
                return p, url
        except Exception:
            pass
        time.sleep(0.5)
    p.terminate()
    raise AssertionError("node %s did not start" % name)


def stop(p):
    p.terminate()
    p.wait(timeout=60)


results = {}
procs = []
try:
    # Real nodes.
    p, url = node("inactive", ["-con_btc_payment_height=100000000"])
    procs.append(p)
    a, t = activation(url), terms(url)
    assert not a["btc_payment"] and not a["lost_blocks"], a
    gated(t)
    results["inactive (real node)"] = {"activation": a, "terms": t}
    stop(p)

    p, url = node("partial", [])
    procs.append(p)
    a, t = activation(url), terms(url)
    assert a["btc_payment"] and not a["lost_blocks"], a
    gated(t)
    results["partial (real node)"] = {"activation": a, "terms": t}
    stop(p)

    # Stubs.
    for name, rep in [("btc off, lost on (stub)", {"btc_payment": {"type": "buried", "active": False},
                                                   "lost_blocks": {"type": "buried", "active": True, "window": 6}}),
                      ("btc on, lost off (stub)", {"btc_payment": {"type": "buried", "active": True, "height": 0},
                                                   "lost_blocks": {"type": "buried", "active": False, "window": 6}}),
                      ("neither reported (stub)", {"taproot": {"type": "buried", "active": True}})]:
        srv, url = stub({"deployments": rep})
        t = terms(url)
        gated(t)
        results[name] = t
        srv.shutdown()
    srv, url = stub({"deployments": {"btc_payment": {"type": "buried", "active": True, "height": 0},
                                     "lost_blocks": {"type": "buried", "active": True, "window": 6}}})
    t = terms(url)
    # Past the gate: it now reads the chain, which the stub cannot answer.
    assert "error" in t and "stub: no" in t["error"], t
    results["both on (stub)"] = t
    srv.shutdown()
finally:
    for p in procs:
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=60)

print(json.dumps(results, indent=1))
print("activation: all cases passed")
