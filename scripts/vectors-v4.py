#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Independent check of tests/vectors/terms_v4 and tests/vectors/vaults_v4 from spec/V3-ZK.md
section 22.2 alone, with hashlib and the committed template artifact, no Rust code. Checks per
file: the canonical terms start with version 4 and the blind is the last 64 bytes' first half;
terms_hash = BLAKE2b-256(key "Impulse/terms/v4", canonical); commit(leg) = BLAKE2b-256(key
"Impulse/commit/v4", terms_hash || leg); each redeem script is the template prefix, the state
(commitment, authority key) and the template suffix of contracts/compiled/impulse_vault.v4.json,
with the commitment of its leg and the authority of the terms; script_hash = BLAKE2b-256(redeem).
Addresses are not decoded here (the v1 and v3 vector checks cover the address encoding).

usage: vectors-v4.py <tests/vectors>
"""
import hashlib
import json
import pathlib
import sys


def b2(data, key=b""):
    return hashlib.blake2b(data, digest_size=32, key=key).digest()


def main(root):
    root = pathlib.Path(root)
    art = json.load(open("contracts/compiled/impulse_vault.v4.json"))
    c = art["contracts"]["ImpulseVaultV4"]["compiled"]
    code = bytes(c["bytecode"]) if isinstance(c["bytecode"], list) else bytes.fromhex(c["bytecode"])
    off, ln = c["state_span"]["offset"], c["state_span"]["len"]
    prefix, suffix = code[:off], code[off + ln:]
    names = sorted(p.name for p in (root / "terms_v4").glob("*.json"))
    if len(names) < 3 or names != sorted(p.name for p in (root / "vaults_v4").glob("*.json")):
        sys.exit("vectors-v4: terms_v4 and vaults_v4 must hold the same non-trivial set")
    for n in names:
        t = json.load(open(root / "terms_v4" / n))
        v = json.load(open(root / "vaults_v4" / n))
        canon = bytes.fromhex(t["canonical"])
        if canon[0] != 4:
            sys.exit(f"{n}: canonical terms are not version 4")
        th = b2(canon, b"Impulse/terms/v4")
        if th.hex() != t["terms_hash"] or th.hex() != v["terms_hash"]:
            sys.exit(f"{n}: terms_hash")
        if canon[-64:-32] == bytes(32):
            sys.exit(f"{n}: blind is zero")
        for leg in (0, 1):
            commit = b2(th + bytes([leg]), b"Impulse/commit/v4")
            if commit.hex() != t[f"commit_leg{leg}"]:
                sys.exit(f"{n}: commit_leg{leg}")
            vault = v["asset_vault" if leg == 0 else "cash_vault"]
            if vault is None:
                if leg == 0:
                    sys.exit(f"{n}: asset vault missing")
                continue
            redeem = bytes.fromhex(vault["redeem_script"])
            if not (redeem.startswith(prefix) and redeem.endswith(suffix)):
                sys.exit(f"{n}: leg {leg} redeem script is not the template")
            state = redeem[len(prefix):len(redeem) - len(suffix)]
            if commit not in state or bytes.fromhex(v["authority"]) not in state:
                sys.exit(f"{n}: leg {leg} state lacks the commitment or the authority")
            if b2(redeem).hex() != vault["script_hash"]:
                sys.exit(f"{n}: leg {leg} script_hash")
            if vault["commit"] != commit.hex():
                sys.exit(f"{n}: leg {leg} commit")
        if bytes.fromhex(v["authority"]) not in canon:
            sys.exit(f"{n}: authority is not in the canonical terms")
    print(f"vectors-v4: ok ({len(names)} fixtures)")
    journals(root)
    ipsts(root)


def journals(root):
    """tests/vectors/journal_v4: J rebuilt from spec/V3-ZK.md 22.3 alone. Per file: the bytes are
    tag | mode | vault spk | commit | authority | leg | input index | lock time (8, little-endian) |
    signer | cov_a | cov_c | count_a | count_c | n_in | n_out | items (value 8 little-endian, sha256
    of the scriptPubKey 32, covenant ID 32); the hash is SHA-256 of the bytes; the commitment is
    BLAKE2b-256(key "Impulse/commit/v4", terms hash || leg) of the canonical terms in the file; the
    authority is the terms' authority key; the vault scriptPubKey is version 0 and
    OP_BLAKE2B <32> OP_EQUAL."""
    names = sorted(p.name for p in (root / "journal_v4").glob("*.json"))
    if len(names) < 8:
        sys.exit("vectors-v4: journal_v4 must hold the eight fixture journals")
    for n in names:
        v = json.load(open(root / "journal_v4" / n))
        h = lambda k: bytes.fromhex(v[k])
        le = lambda x, w: int(x).to_bytes(w, "little")
        items = lambda xs: b"".join(le(x["value"], 8) + bytes.fromhex(x["spk_hash"]) + bytes.fromhex(x["cov"]) for x in xs)
        j = (b"Impulse/zk/ht/v1" + bytes([v["mode"]]) + h("vault_spk") + h("commit") + h("authority")
             + bytes([v["journal_leg"], v["input_index"]]) + le(v["lock_time"], 8) + h("signer") + h("cov_a")
             + h("cov_c") + bytes([v["count_a"], v["count_c"], len(v["inputs"]), len(v["outputs"])])
             + items(v["inputs"]) + items(v["outputs"]))
        if j != h("journal"):
            sys.exit(f"{n}: journal bytes")
        if hashlib.sha256(j).hexdigest() != v["journal_hash"]:
            sys.exit(f"{n}: journal_hash")
        if len(v["inputs"]) > 4 or len(v["outputs"]) > 4:
            sys.exit(f"{n}: view larger than four")
        canon = h("canonical_terms")
        if canon[0] != 4 or canon[75] != 1:
            sys.exit(f"{n}: terms are not version 4 with an authority")
        if canon[76:108] != h("authority"):
            sys.exit(f"{n}: authority is not the terms' authority")
        th = b2(canon, b"Impulse/terms/v4")
        if b2(th + bytes([v["leg"]]), b"Impulse/commit/v4") != h("commit"):
            sys.exit(f"{n}: commit is not the commitment of the terms for the leg")
        spk = h("vault_spk")
        if len(spk) != 37 or spk[:2] != b"\x00\x00" or spk[2:4] != b"\xaa\x20" or spk[-1:] != b"\x87":
            sys.exit(f"{n}: vault scriptPubKey is not a P2SH")
        if v["mode"] == 1 and v["journal_leg"] != v["input_index"]:
            sys.exit(f"{n}: a settle's leg is its input index")
        if v["mode"] == 2 and (v["input_index"] != 0 or v["cov_c"] != "00" * 32):
            sys.exit(f"{n}: a refund spends input 0 and has no cash covenant")
    print(f"vectors-v4: journal_v4 ok ({len(names)} journals)")


def ipsts(root):
    """tests/vectors/ipst_v5: each plan is an IPST version 5 whose terms are canonical terms v4."""
    names = sorted(p.name for p in (root / "ipst_v5").glob("*.json"))
    if len(names) < 6:
        sys.exit("vectors-v4: ipst_v5 must hold the six fixture plans")
    for n in names:
        d = json.load(open(root / "ipst_v5" / n))
        if d["ipst"] != 5:
            sys.exit(f"{n}: ipst is not 5")
        t = bytes.fromhex(d["terms"])
        if t[0] != 4 or t[-64:-32] == bytes(32):
            sys.exit(f"{n}: terms are not terms v4 with a blind")
        if "zk_proof" in d:
            sys.exit(f"{n}: a version 5 document has no zk_proof key")
    print(f"vectors-v4: ipst_v5 ok ({len(names)} plans)")


main(sys.argv[1])
