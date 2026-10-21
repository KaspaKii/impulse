#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Independent check of tests/vectors/zk and tests/vectors/terms_v3 from spec/V3-ZK.md alone
(sections 5.1, 5.2, 5.6, 7.1, 7.2), with hashlib and no Rust code. Called by scripts/vectors.sh.

usage: vectors-zk.py <tests/vectors>
"""
import hashlib
import json
import pathlib
import struct
import sys

DEPTH = 20
LEAF_TAG = b"Impulse/zk/leaf/v1"
JOURNAL_TAG = b"Impulse/zk/wl/v1"


def sha(b):
    return hashlib.sha256(b).digest()


def leaf(salt, spk):
    return sha(LEAF_TAG + salt + spk)


def node(l, r):
    return sha(b"\x01" + l + r)


def spk_of(owner_type, ident):
    if owner_type == "pubkey":
        return bytes([0, 0, 0x20]) + ident + bytes([0xAC])
    if owner_type == "script_hash":
        return bytes([0, 0, 0xAA, 0x20]) + ident + bytes([0x87])
    sys.exit(f"no scriptPubKey for owner type {owner_type}")


def zeros():
    z = [bytes(32)]
    for _ in range(DEPTH):
        z.append(node(z[-1], z[-1]))
    return z


def tree(leaves):
    z = zeros()
    levels = [list(leaves)]
    for k in range(DEPTH):
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            r = cur[i + 1] if i + 1 < len(cur) else z[k]
            nxt.append(node(cur[i], r))
        levels.append(nxt)
    return levels, z


def path_of(levels, z, i):
    sibs = []
    for k in range(DEPTH):
        s = i ^ 1
        sibs.append(levels[k][s] if s < len(levels[k]) else z[k])
        i >>= 1
    return sibs


def root_from(lf, index, sibs):
    h = lf
    for k, s in enumerate(sibs):
        h = node(h, s) if (index >> k) & 1 == 0 else node(s, h)
    return h


def load(path):
    return json.loads(path.read_text())


def hx(s):
    return bytes.fromhex(s)


def check_leaf(v, f):
    spk = spk_of(v["owner_type"], hx(v["owner_id"]))
    if spk.hex() != v["owner_spk"]:
        sys.exit(f"{f}: owner_spk")
    if v["leaf_tag"].encode() != LEAF_TAG:
        sys.exit(f"{f}: leaf_tag")
    if leaf(hx(v["salt"]), spk).hex() != v["leaf"]:
        sys.exit(f"{f}: leaf")


def check_empty(v, f):
    z = zeros()
    if [x.hex() for x in z] != v["levels"] or z[DEPTH].hex() != v["root"]:
        sys.exit(f"{f}: empty tree")
    if v["root"] != "51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503":
        sys.exit(f"{f}: root is not the value of spec section 5.1")


def list_entries(v, f):
    """(spk, salt) of every entry, from the explicit list or the generating rule."""
    if "entries" in v:
        out = []
        for e in v["entries"]:
            spk = spk_of(e["owner_type"], hx(e["owner_id"]))
            if spk.hex() != e["owner_spk"]:
                sys.exit(f"{f}: entry owner_spk")
            if leaf(hx(e["salt"]), spk).hex() != e["leaf"]:
                sys.exit(f"{f}: entry leaf")
            out.append((spk, hx(e["salt"])))
        return out
    rule = v["entries_rule"]
    special = {s["index"]: s for s in rule["special"]}
    out = []
    for i in range(v["entry_count"]):
        if i in special:
            s = special[i]
            spk = spk_of(s["owner_type"], hx(s["owner_id"]))
            if spk.hex() != s["owner_spk"]:
                sys.exit(f"{f}: special owner_spk")
        else:
            spk = spk_of("script_hash", sha(rule["filler_label"].encode() + str(i).encode()))
        salt = sha(rule["salt_label"].encode() + struct.pack(">I", i))
        out.append((spk, salt))
    return out


def check_list(v, f):
    entries = list_entries(v, f)
    if len(entries) != v["entry_count"] or v["depth"] != DEPTH:
        sys.exit(f"{f}: entry count or depth")
    leaves = [leaf(salt, spk) for spk, salt in entries]
    levels, z = tree(leaves)
    if levels[DEPTH][0].hex() != v["root"]:
        sys.exit(f"{f}: root")
    for p in v["paths"]:
        i = p["index"]
        spk, salt = entries[i]
        if spk.hex() != p["owner_spk"] or salt.hex() != p["salt"]:
            sys.exit(f"{f}: path {i} owner or salt")
        sibs = path_of(levels, z, i)
        if [s.hex() for s in sibs] != p["siblings"]:
            sys.exit(f"{f}: path {i} siblings")
        if root_from(leaf(salt, spk), i, sibs).hex() != v["root"]:
            sys.exit(f"{f}: path {i} does not reach the root")


def check_manifest(v, f):
    lid = v["list_id"].encode()
    if not 1 <= len(lid) <= 64:
        sys.exit(f"{f}: list_id length")
    m = (
        b"\x01"
        + bytes([0 if v["network"] == "mainnet" else 1])
        + bytes([len(lid)])
        + lid
        + struct.pack(">I", v["list_version"])
        + struct.pack(">Q", v["issued_at"])
        + hx(v["list_root"])
    )
    if m.hex() != v["manifest"]:
        sys.exit(f"{f}: manifest bytes")
    d = hashlib.blake2b(m, digest_size=32, key=v["digest_key"].encode()).hexdigest()
    if d != v["manifest_digest"] or v["digest_key"] != "Impulse/zk/manifest/v1":
        sys.exit(f"{f}: manifest digest")


def check_journal(v, f):
    spk = spk_of(v["owner_type"], hx(v["owner_id"]))
    vault = bytes([0, 0, 0xAA, 0x20]) + hx(v["vault_script_hash"]) + bytes([0x87])
    if spk.hex() != v["owner_spk"] or vault.hex() != v["vault_spk"]:
        sys.exit(f"{f}: spk")
    j = JOURNAL_TAG + hx(v["list_root"]) + vault + spk
    if len(j) not in (121, 122) or j.hex() != v["journal"]:
        sys.exit(f"{f}: journal")
    if sha(j).hex() != v["journal_hash"]:
        sys.exit(f"{f}: journal_hash")


def check_receipt(v, f):
    j = hx(v["journal"])
    if not j.startswith(JOURNAL_TAG) or len(j) not in (121, 122):
        sys.exit(f"{f}: journal shape")
    if sha(j).hex() != v["journal_hash"]:
        sys.exit(f"{f}: the receipt's journal digest is not SHA-256 of J")


# Terms v3 (section 7.2): the v1 layout, version byte 3, the issuer key and the root inserted
# before trade_ref.
class R:
    def __init__(s, b):
        s.b, s.p = b, 0

    def take(s, n):
        if len(s.b) - s.p < n:
            raise ValueError("truncated")
        s.p += n
        return s.b[s.p - n : s.p]

    def u8(s):
        return s.take(1)[0]

    def u16(s):
        return struct.unpack("<H", s.take(2))[0]

    def u32(s):
        return struct.unpack("<I", s.take(4))[0]

    def u64(s):
        return str(struct.unpack("<Q", s.take(8))[0])

    def hx(s):
        return s.take(32).hex()

    def opt(s, f):
        p = s.u8()
        if p not in (0, 1):
            raise ValueError("presence")
        return f() if p else None


def leg(r):
    k = ["kas", "kcc20", "external"][r.u8()]
    o = {"kind": k}
    if k == "kcc20":
        o.update(covenant_id=r.hx(), template_hash=r.hx(), template_prefix_len=r.u32(), template_suffix_len=r.u32())
    o["amount"] = r.u64()
    return o


def dest(r):
    k = ["kas", "kcc20", "off_chain"][r.u8()]
    if k == "kas":
        v = r.u16()
        n = r.u32()
        if n > 10000:
            raise ValueError("too long")
        return {"kind": k, "version": v, "script": r.take(n).hex()}
    if k == "kcc20":
        t = ["pubkey", "script_hash", "covenant_id"][r.u8()]
        return {"kind": k, "identifier_type": t, "identifier": r.hx()}
    return {"kind": k}


def decode_v3(b):
    r = R(b)
    t = {}
    t["version"] = r.u8()
    if t["version"] != 3:
        raise ValueError("version")
    t["network"] = ["mainnet", "testnet"][r.u8()]
    t["settlement_mode"] = ["direct", "vault"][r.u8()]
    t["nonce"] = r.u64()
    t["seller_key"] = r.hx()
    t["buyer_key"] = r.hx()
    t["authority_key"] = r.opt(r.hx)
    t["asset_leg"] = leg(r)
    t["cash_leg"] = leg(r)
    for name in ("buyer_delivery", "seller_proceeds", "seller_refund", "buyer_refund"):
        t[name] = dest(r)
    t["earliest_daa"] = r.opt(r.u64)
    t["expiry_daa"] = r.u64()
    t["funding_mode"] = ["revocable", "earmarked"][r.u8()]
    t["list_issuer_key"] = r.hx()
    t["list_root"] = r.hx()
    t["trade_ref"] = r.hx()
    if r.p != len(b):
        raise ValueError("trailing bytes")
    return t


def check_terms(v, f):
    canonical = hx(v["canonical"])
    t = decode_v3(canonical)
    if json.dumps(t) != json.dumps(v["terms"]):
        sys.exit(f"{f}: canonical bytes do not decode to the terms object")
    h = hashlib.blake2b(canonical, digest_size=32, key=b"Impulse/terms/v3").hexdigest()
    if h != v["terms_hash"]:
        sys.exit(f"{f}: terms_hash does not match its canonical bytes")
    # The two known answers of section 7.1 pin the key.
    if hashlib.blake2b(b"", digest_size=32, key=b"Impulse/terms/v3").hexdigest() != (
        "175c483831717b966ff22e32bf1821b41ecb33c235c30b5c97ef3071a4c3a078"
    ):
        sys.exit("terms v3 hash key: known answer")
    if t["settlement_mode"] != "vault" or t["buyer_delivery"].get("identifier_type") not in ("pubkey", "script_hash"):
        sys.exit(f"{f}: terms v3 are Vault with a pubkey or script hash delivery owner")


# Template v3 vaults (section 6): the v1 state with version 3 and listIssuerKey, listRoot after
# fundingMode. The redeem script is decoded from the template bytes of the artifact alone.
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)


def polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i, g in enumerate(GEN):
            if c0 & (1 << i):
                c ^= g
    return c ^ 1


def to5(data):
    acc = bits = 0
    out = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def address(prefix, version, payload):
    data = to5(bytes([version]) + payload)
    chk = polymod([ord(c) & 31 for c in prefix] + [0] + data + [0] * 8)
    return prefix + ":" + "".join(CHARSET[d] for d in data + to5(chk.to_bytes(5, "big")))


for _p, _payload, _want in [("a", b"", "a:pq99546ray"), ("b", b"abc", "b:ppskycc8txxxn2w")]:
    if address(_p, 8, _payload) != _want:
        sys.exit("address encoder self-check failed")


def pushes(b):
    out, i = [], 0
    while i < len(b):
        op = b[i]
        i += 1
        if op == 0:
            n = 0
        elif op <= 75:
            n = op
        elif op == 0x4C:
            n = b[i]
            i += 1
        else:
            raise ValueError("opcode %#x in state" % op)
        if n == 0 and op != 0 or 0 < n <= 75 and op != n or n > 75 and op != 0x4C:
            raise ValueError("non-canonical push")
        if i + n > len(b):
            raise ValueError("truncated push")
        out.append(b[i : i + n])
        i += n
    return out


def num(b):
    if len(b) != 8:
        raise ValueError("int is not 8 bytes")
    mag = int.from_bytes(b[:7] + bytes([b[7] & 0x7F]), "little")
    if b[7] & 0x80:
        if mag == 0:
            raise ValueError("negative zero")
        return -mag
    return mag


LAYOUT_V3 = [
    ("version", 1), ("network", 1), ("nonce", 8), ("sellerKey", 32), ("buyerKey", 32),
    ("hasAuthority", 1), ("authorityKey", 32), ("assetCovenantId", 32), ("assetTemplateHash", 32),
    ("assetPrefixLen", 8), ("assetSuffixLen", 8), ("amountA", 8), ("cashKind", 1),
    ("cashCovenantId", 32), ("cashTemplateHash", 32), ("cashPrefixLen", 8), ("cashSuffixLen", 8),
    ("amountB", 8), ("buyerDeliveryType", 1), ("buyerDeliveryId", 32), ("sellerProceedsType", 1),
    ("sellerProceedsId", 32), ("sellerProceedsSpk", None), ("sellerRefundType", 1),
    ("sellerRefundId", 32), ("buyerRefundType", 1), ("buyerRefundId", 32), ("buyerRefundSpk", None),
    ("hasEarliest", 1), ("earliestDaa", 8), ("expiryDaa", 8), ("fundingMode", 1),
    ("listIssuerKey", 32), ("listRoot", 32), ("tradeRef", 32), ("legIndex", 8),
]
IDS = ["pubkey", "script_hash", "covenant_id"]


def decode_vault(script, prefix, suffix):
    if not (script.startswith(prefix) and script.endswith(suffix)) or len(script) < len(prefix) + len(suffix):
        raise ValueError("not the ImpulseVaultV3 template")
    ps = pushes(script[len(prefix) : len(script) - len(suffix)])
    if len(ps) != len(LAYOUT_V3):
        raise ValueError("state has %d pushes" % len(ps))
    f = {}
    for (name, size), data in zip(LAYOUT_V3, ps):
        if size is not None and len(data) != size:
            raise ValueError(name + " size")
        f[name] = data
    flag = lambda n: {b"\x00": False, b"\x01": True}[f[n]]
    zero = lambda n: f[n] == bytes(len(f[n]))

    def token(side):
        return {
            "covenant_id": f[side + "CovenantId"].hex(),
            "template_hash": f[side + "TemplateHash"].hex(),
            "template_prefix_len": num(f[side + "PrefixLen"]),
            "template_suffix_len": num(f[side + "SuffixLen"]),
        }

    def owner(t, i):
        return {"kind": "kcc20", "identifier_type": IDS[f[t][0]], "identifier": f[i].hex()}

    cash = f["cashKind"][0]

    def cash_dest(t, i, sp):
        if cash == 0:
            if not (zero(t) and zero(i)):
                raise ValueError(t + " used under KAS cash")
            spk = f[sp]
            return {"kind": "kas", "version": int.from_bytes(spk[:2], "big"), "script": spk[2:].hex()}
        if f[sp] != b"":
            raise ValueError(sp + " used without KAS cash")
        if cash == 1:
            return owner(t, i)
        if not (zero(t) and zero(i)):
            raise ValueError(t + " used under external cash")
        return {"kind": "off_chain"}

    t = {
        "version": f["version"][0],
        "network": ["mainnet", "testnet"][f["network"][0]],
        "settlement_mode": "vault",
        "nonce": str(int.from_bytes(f["nonce"], "little")),
        "seller_key": f["sellerKey"].hex(),
        "buyer_key": f["buyerKey"].hex(),
    }
    if flag("hasAuthority"):
        t["authority_key"] = f["authorityKey"].hex()
    elif zero("authorityKey"):
        t["authority_key"] = None
    else:
        raise ValueError("authority key under an absent authority")
    t["asset_leg"] = dict(kind="kcc20", **token("asset"), amount=str(num(f["amountA"])))
    if cash == 1:
        t["cash_leg"] = dict(kind="kcc20", **token("cash"), amount=str(num(f["amountB"])))
    else:
        if not all(zero(n) for n in ("cashCovenantId", "cashTemplateHash", "cashPrefixLen", "cashSuffixLen")):
            raise ValueError("cash token fields used without KCC-20 cash")
        t["cash_leg"] = {"kind": ["kas", None, "external"][cash], "amount": str(num(f["amountB"]))}
    t["buyer_delivery"] = owner("buyerDeliveryType", "buyerDeliveryId")
    t["seller_proceeds"] = cash_dest("sellerProceedsType", "sellerProceedsId", "sellerProceedsSpk")
    t["seller_refund"] = owner("sellerRefundType", "sellerRefundId")
    t["buyer_refund"] = cash_dest("buyerRefundType", "buyerRefundId", "buyerRefundSpk")
    if flag("hasEarliest"):
        t["earliest_daa"] = str(num(f["earliestDaa"]))
    elif zero("earliestDaa"):
        t["earliest_daa"] = None
    else:
        raise ValueError("earliest_daa under an absent bound")
    t["expiry_daa"] = str(num(f["expiryDaa"]))
    t["funding_mode"] = ["revocable", "earmarked"][f["fundingMode"][0]]
    t["list_issuer_key"] = f["listIssuerKey"].hex()
    t["list_root"] = f["listRoot"].hex()
    t["trade_ref"] = f["tradeRef"].hex()
    return t, num(f["legIndex"])


def check_vaults(root, repo):
    art = json.load(open(repo / "contracts/compiled/impulse_vault.v3.json"))["contracts"]["ImpulseVaultV3"]["compiled"]
    code = bytes(art["bytecode"])
    span = art["state_span"]
    prefix, suffix = code[: span["offset"]], code[span["offset"] + span["len"] :]
    pinned = (repo / "contracts/TEMPLATE_HASH_V3").read_text().strip()
    if bytes(art["template_hash"]).hex() != pinned:
        sys.exit("artifact template_hash is not TEMPLATE_HASH_V3")
    image = (repo / "circuits/IMAGE_ID").read_text().strip()
    if (prefix + suffix).count(bytes.fromhex(image)) != 1:
        sys.exit("circuits/IMAGE_ID does not occur exactly once in template v3")
    terms_dir, vault_dir = root / "terms_v3", root / "vaults_v3"
    files = sorted(vault_dir.glob("*.json"))
    if [f.name for f in files] != sorted(f.name for f in terms_dir.glob("*.json")):
        sys.exit("vault vectors do not match the terms v3 vectors one to one")
    count = 0
    for f in files:
        v = load(f)
        tv = load(terms_dir / f.name)
        if v["name"] != tv["name"] or v["terms_hash"] != tv["terms_hash"] or v["template_hash"] != pinned:
            sys.exit(f"{f}: name, terms_hash or template_hash")
        terms = tv["terms"]
        for key, leg in (("asset_vault", 0), ("cash_vault", 1)):
            j = v[key]
            if j["leg_index"] != leg:
                sys.exit(f"{f} {key}: leg_index")
            if leg == 1 and terms["cash_leg"]["kind"] == "external":
                if j != {"leg_index": leg, "refused": "TEMPLATE_NO_VAULT"}:
                    sys.exit(f"{f} {key}: expected TEMPLATE_NO_VAULT")
                continue
            if sorted(j) != ["address", "leg_index", "redeem_script", "script_hash"]:
                sys.exit(f"{f} {key}: fields")
            script = bytes.fromhex(j["redeem_script"])
            try:
                decoded, decoded_leg = decode_vault(script, prefix, suffix)
            except (ValueError, IndexError, KeyError) as e:
                sys.exit(f"{f} {key}: {e}")
            if json.dumps(decoded) != json.dumps(terms) or decoded_leg != leg:
                sys.exit(f"{f} {key}: the redeem script does not decode to the terms vector")
            h = hashlib.blake2b(script, digest_size=32).digest()
            if j["script_hash"] != h.hex():
                sys.exit(f"{f} {key}: script_hash")
            hrp = {"mainnet": "kaspa", "testnet": "kaspatest"}[terms["network"]]
            if j["address"] != address(hrp, 8, h):
                sys.exit(f"{f} {key}: address")
            count += 1
    return count


def main():
    root = pathlib.Path(sys.argv[1])
    repo = root.parent.parent
    counts = {}
    for f in sorted((root / "zk").glob("*.json")):
        v = load(f)
        name = v["name"]
        if name.startswith(("01-leaf", "02-leaf")):
            check_leaf(v, f)
        elif name == "03-empty-root":
            check_empty(v, f)
        elif "-list-" in name:
            check_list(v, f)
        elif "-manifest-" in name:
            check_manifest(v, f)
        elif "-journal-p2" in name:
            check_journal(v, f)
        elif name.endswith("receipt-journal-digest"):
            check_receipt(v, f)
        else:
            sys.exit(f"{f}: no checker for this vector")
        counts["zk"] = counts.get("zk", 0) + 1
    terms = sorted((root / "terms_v3").glob("*.json"))
    for f in terms:
        check_terms(load(f), f)
    if not counts or not terms:
        sys.exit("no zk or terms_v3 vectors")
    print(f"vectors: {counts['zk']} zk vectors and {len(terms)} terms v3 vectors checked independently")
    if (root / "vaults_v3").is_dir():
        n = check_vaults(root, repo)
        print(f"vectors: {n} template v3 vault scripts decoded, hashed and addressed independently")


if __name__ == "__main__":
    main()
