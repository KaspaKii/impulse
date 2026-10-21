#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Independent check of the proof fixtures' deterministic data, written from spec/V3-ZK.md
sections 5.1 and 5.2 alone with Python's hashlib (not the Rust list-core): the empty-tree root,
both fixture lists' roots, each fixture's leaf and path, J and journal_hash.
Usage: check-fixtures.py <tests/engine/fixtures/v3/proofs>"""
import hashlib, json, os, struct, sys

DEPTH = 20
H = lambda b: hashlib.sha256(b).digest()
node = lambda l, r: H(b"\x01" + l + r)
leaf = lambda salt, spk: H(b"Impulse/zk/leaf/v1" + salt + spk)
p2pk = lambda x: b"\x00\x00\x20" + x + b"\xac"
p2sh = lambda h: b"\x00\x00\xaa\x20" + h + b"\x87"
G = {"A": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "B": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
     "D": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}

def owner(n):
    return p2sh(H(b"Impulse/zk/fixture/owner/C")) if n == "C" else p2pk(bytes.fromhex(G[n]))

def entries(name):
    salt = lambda i: H(b"Impulse/zk/fixture/salt/v1/" + name.encode() + b"/" + struct.pack(">I", i))
    if name == "list1":
        return [(salt(0), owner("A"))]
    spk = lambda i: {0: owner("B"), 500: owner("C"), 999: owner("A")}.get(i) or p2sh(H(f"Impulse/zk/fixture/filler/{i}".encode()))
    return [(salt(i), spk(i)) for i in range(1000)]

def root(es):
    zeros = [bytes(32)]
    for _ in range(DEPTH):
        zeros.append(node(zeros[-1], zeros[-1]))
    level = [leaf(s, o) for s, o in es]
    for k in range(DEPTH):
        if len(level) % 2:
            level.append(zeros[k])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], zeros[DEPTH]

def fail(m):
    sys.exit("check-fixtures: FAIL: " + m)

d = sys.argv[1]
lists = json.load(open(os.path.join(d, "lists.json")))
for name in ("list1", "list1000"):
    r, empty = root(entries(name))
    if lists[name]["root"] != r.hex() or lists[name]["size"] != len(entries(name)):
        fail(f"{name} root or size")
if empty.hex() != "51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503":
    fail("empty-tree root differs from spec/V3-ZK.md 5.1")
n = 0
for f in sorted(os.listdir(d)):
    if not f.endswith(".inputs.json"):
        continue
    x = json.load(open(os.path.join(d, f)))
    o = owner(x["owner"])
    if x["owner_spk"] != o.hex():
        fail(f + ": owner")
    p = x["path"]
    h = leaf(bytes.fromhex(p["salt"]), o)
    if len(p["siblings"]) != DEPTH:
        fail(f + ": depth")
    for k, s in enumerate(p["siblings"]):
        s = bytes.fromhex(s)
        h = node(h, s) if (p["index"] >> k) & 1 == 0 else node(s, h)
    if h.hex() != x["root"] or x["root"] != lists[x["list"]]["root"]:
        fail(f + ": path does not lead to the list root")
    vault = bytes.fromhex(x["vault_spk"])
    if len(vault) != 37 or vault[:4] != b"\x00\x00\xaa\x20" or vault[36] != 0x87:
        fail(f + ": vault form")
    if x["vault_spk_is_standin"] and vault != p2sh(H(f"Impulse/zk/fixture/standin-vault/{x['vault']}".encode())):
        fail(f + ": stand-in vault")
    j = b"Impulse/zk/wl/v1" + bytes.fromhex(x["root"]) + vault + o
    if x["journal"] != j.hex() or x["journal_hash"] != H(j).hex():
        fail(f + ": J or journal_hash")
    pf = json.load(open(os.path.join(d, f.replace(".inputs.", ".proof."))))
    if pf["journal"] != j.hex() or pf["journal_hash"] != H(j).hex() or len(bytes.fromhex(pf["proof"])) != 128:
        fail(f + ": proof file J, hash or proof length")
    n += 1
print(f"check-fixtures: {n} fixtures, 2 lists and the empty-tree root recomputed independently")
