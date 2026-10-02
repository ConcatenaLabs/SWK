#!/usr/bin/env python3
"""Writes ark_byte_order.json, the byte-order vector for Arca records in the
kit, from arca_records.json (the Arca repository's record vectors).

Asset ids, the sweep token and the genesis hash are in internal byte order in
scripts, hashes and the record's binary form, and in display hex (the reverse,
as the node's RPCs print them) in the record's JSON form and at every API edge.
This script works that out with nothing but hashlib, so the Rust tests
(lwk_wollet's ark module, lwk_signer) and the wasm test
(lwk_wasm/tests/node/ark_records.js) each check their own code against it.

    python3 ark_byte_order.py      # rewrites ark_byte_order.json
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def sha(b):
    return hashlib.sha256(b).digest()


def rev(h):
    return bytes.fromhex(h)[::-1].hex()


v = json.load(open(os.path.join(HERE, "arca_records.json")))
batch = v["batches"][1]          # five leaves
rec = batch["records"][0]
j = json.loads(rec["json"])
binary = bytes.fromhex(rec["binary"])

# The binary form, version 2: version, template id and version, owner key,
# owner nonce, operator nonce, exit delay (u16), then the asset, value (u64),
# unlock hash, entry reserve (u64), genesis hash, operator key, token.
off = {"asset": 1 + 2 + 32 * 3 + 2}
off["genesis_hash"] = off["asset"] + 32 + 8 + 32 + 8
off["operator"] = off["genesis_hash"] + 32
off["token"] = off["operator"] + 32

fields = {}
for name in ("asset", "genesis_hash", "token"):
    internal = binary[off[name]:off[name] + 32].hex()
    assert internal == rev(j[name]), name
    fields[name] = {"display": j[name], "internal": internal, "binary_offset": off[name]}
assert binary[off["operator"]:off["operator"] + 32].hex() == j["operator"]

genesis_internal = bytes.fromhex(fields["genesis_hash"]["internal"])
salt = sha(b"Arca/salt" + bytes.fromhex(j["owner_nonce"]) + bytes.fromhex(j["operator_nonce"]))
assert salt.hex() == rec["salt"]
chain_tag = sha(b"ArcaRbd1" + genesis_internal)
k = sha(chain_tag + salt)

# The leaf's coin spent through its collaborative path into one output of the
# same asset, 1,000 atoms less: the rebindable message, as the script builds it.
asset_internal = bytes.fromhex(fields["asset"]["internal"])
value = int(j["value"])
out_value = value - 1000
out_spk = bytes.fromhex("5120" + "11" * 32)
out_record = asset_internal + b"\x01\x01" + out_value.to_bytes(8, "little") + bytes.fromhex("11" * 32) + bytes([1 + 2])
message = k + asset_internal + b"\x01\x01" + value.to_bytes(8, "little") + bytes([1]) + sha(out_record)

out = {
    "about": "Byte-order vector for Arca records in the kit. Written by ark_byte_order.py from arca_records.json; "
             "the display form of an id is its internal bytes reversed.",
    "record_hex": rec["binary"],
    "record_json": rec["json"],
    "leaf_id": rec["leaf_id"],
    "owner": j["owner"],
    "owner_nonce": j["owner_nonce"],
    "asset": fields["asset"],
    "genesis_hash": fields["genesis_hash"],
    "token": fields["token"],
    "salt": salt.hex(),
    "chain_tag": chain_tag.hex(),
    "leaf_constant": k.hex(),
    "rebind": {
        "value_in": str(value),
        "output": {"asset_display": fields["asset"]["display"], "value": str(out_value),
                   "script_pubkey": out_spk.hex(), "record": out_record.hex()},
        "message": message.hex(),
        "digest": sha(message).hex(),
    },
}
with open(os.path.join(HERE, "ark_byte_order.json"), "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print("wrote ark_byte_order.json")
