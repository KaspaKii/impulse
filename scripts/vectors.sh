#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Regenerate golden vectors and diff against tests/vectors/ (diff must be empty).
#   1. Frozen: no vector file that exists on main may change or disappear.
#   2. Every file under tests/vectors/ belongs to a generated set (terms/, vaults/).
#   3. Regenerate every set from the code and diff against the committed files.
#   4. Independent hash check: each terms_hash is recomputed from its canonical bytes with
#      Python's hashlib, an implementation separate from the Rust one.
#   5. Independent vault check (I4): each redeem script is decoded in Python from
#      spec/TEMPLATE.md alone and compared with its terms vector; its template bytes, script
#      hash and address are recomputed without the Rust code.
#   6. Independent IPST check (I5): every sighash in each IPST vector is recomputed in Python
#      from spec/IPST.md and the rusty-kaspa a41a333 sighash definition alone.
#   7. Independent v2 check (I16): each terms v2 vector is decoded in Python from spec/V2.md 5.2
#      alone and hashed with hashlib (key "Impulse/terms/v2"); each v2 vault script is decoded
#      from spec/V2.md 4.2 and the v2 artifact's prefix and suffix, hashed and addressed again;
#      every sighash of each IPST of version 2 is recomputed as in step 6.
#   8. Independent linked-sheet check (I22): each linked vector's sheet is decoded in Python from
#      spec/V2.md 17.2 alone, hashed with hashlib (key "Impulse/terms/v2/linked"), and both
#      trades are derived from the table of 17.3 alone, encoded by 5.2 and hashed again.
#   7. Independent hashlock check (I18): each hashlock terms vector is decoded in Python from
#      spec/V2.md section 10.2 alone, both hashes are recomputed with hashlib, and the vault's
#      redeem script is decoded against the hashlock artifact, hashed and addressed again.
# The base for step 1 is main, else origin/main (fetched in CI if the clone lacks it).
# $IMPULSE_VECTORS_BASE overrides it for local checks only; it is refused when CI is set.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "vectors: FAIL: $1" >&2; exit 1; }

if [ -n "${CI:-}" ] && [ -n "${IMPULSE_VECTORS_BASE:-}" ]; then
  fail "IMPULSE_VECTORS_BASE is set while CI is set; CI always checks against main"
fi
find_main() {
  for ref in main origin/main; do
    if git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then echo "$ref"; return 0; fi
  done
  return 1
}
base_ref="${IMPULSE_VECTORS_BASE:-}"
if [ -z "$base_ref" ]; then
  base_ref=$(find_main) || true
  if [ -z "$base_ref" ] && [ -n "${CI:-}" ]; then
    # A CI clone fetches only the pipeline's branch; fetch main for the freeze check.
    git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main' \
      || fail "cannot fetch origin main for the freeze check"
    base_ref=$(find_main) || true
  fi
fi
[ -n "$base_ref" ] || fail "no base ref (main, origin/main) to check frozen vectors against"
base=$(git merge-base HEAD "$base_ref") || fail "no merge base with $base_ref"
# Working tree against the base: any modified, deleted or retyped vector fails.
changed=$(git diff --name-status --no-renames --diff-filter=MDT "$base" -- tests/vectors)
[ -z "$changed" ] || fail "frozen vectors changed since $base_ref ($base):
$changed"

stray=$(git ls-files -co --exclude-standard -- tests/vectors | grep -Ev '^tests/vectors/(htlc|linked|terms|vaults|ipst|terms_v2|vaults_v2|ipst_v2|zk|terms_v3|vaults_v3|terms_v4|vaults_v4|journal_v4|ipst_v5)/[^/]+\.json$' || true)
[ -z "$stray" ] || fail "files under tests/vectors/ that no generator owns:
$stray"

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
for set in htlc terms template tx v2 linked; do
  IMPULSE_VECTORS_OUT="$out" cargo test --locked -q -p impulse-core --lib \
    "$set::golden::emit_vectors" -- --ignored --exact >/dev/null
done
diff -r "$out/linked" tests/vectors/linked || fail "regenerated linked-sheet vectors differ from tests/vectors/linked"
diff -r "$out/htlc" tests/vectors/htlc || fail "regenerated hashlock vectors differ from tests/vectors/htlc"
diff -r "$out/terms" tests/vectors/terms || fail "regenerated terms vectors differ from tests/vectors/terms"
diff -r "$out/vaults" tests/vectors/vaults || fail "regenerated vault vectors differ from tests/vectors/vaults"
diff -r "$out/ipst" tests/vectors/ipst || fail "regenerated IPST vectors differ from tests/vectors/ipst"
diff -r "$out/terms_v2" tests/vectors/terms_v2 || fail "regenerated terms v2 vectors differ from tests/vectors/terms_v2"
diff -r "$out/vaults_v2" tests/vectors/vaults_v2 || fail "regenerated v2 vault vectors differ from tests/vectors/vaults_v2"
diff -r "$out/ipst_v2" tests/vectors/ipst_v2 || fail "regenerated IPST v2 vectors differ from tests/vectors/ipst_v2"

python3 - tests/vectors/htlc <<'EOF' || fail "independent hashlock decode, hash, vault and address check"
# Decodes each hashlock terms encoding by spec/V2.md section 10.2 alone and compares it with the
# vector's terms object; recomputes the counterpart record hash and the terms hash with hashlib
# (keys "Impulse/htlc/counterpart/v1" and "Impulse/htlc/v1", as they are); decodes the vault's
# redeem script against the hashlock artifact's prefix and suffix and the state layout of
# section 10.2, and recomputes its script hash and address.
import hashlib, json, pathlib, struct, sys

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        if len(s.b) - s.p < n: raise ValueError("truncated")
        s.p += n
        return s.b[s.p - n:s.p]
    def u8(s): return s.take(1)[0]
    def u32(s): return struct.unpack("<I", s.take(4))[0]
    def u64(s): return str(struct.unpack("<Q", s.take(8))[0])
    def hx(s): return s.take(32).hex()

IDS = ["pubkey", "script_hash", "covenant_id"]
def owner(r): return {"identifier_type": IDS[r.u8()], "identifier": r.hx()}

def decode(b):
    r = R(b); t = {}
    t["version"] = r.u8()
    if t["version"] != 1: raise ValueError("version")
    t["network"] = ["mainnet", "testnet"][r.u8()]
    t["nonce"] = r.u64()
    t["seller_key"] = r.hx(); t["buyer_key"] = r.hx()
    if r.u8() != 1: raise ValueError("the asset leg is not KCC-20")
    t["asset_leg"] = {"kind": "kcc20", "covenant_id": r.hx(), "template_hash": r.hx(),
                      "template_prefix_len": r.u32(), "template_suffix_len": r.u32(), "amount": r.u64()}
    t["buyer_delivery"] = owner(r); t["seller_refund"] = owner(r)
    t["hash_lock"] = r.hx(); t["expiry_daa"] = r.u64()
    start = r.p
    chain = {1: "solana", 2: "other_sha256"}[r.u8()]
    t["counterpart"] = {"chain": chain, "chain_id": r.hx(), "htlc_program": r.hx(), "asset": r.hx(),
                        "amount": r.u64(), "recipient": r.hx(), "refund": r.hx(), "timeout": r.u64()}
    record = b[start:r.p]
    if len(record) != 177: raise ValueError("counterpart record length")
    t["trade_ref"] = r.hx()
    if r.p != len(b): raise ValueError("trailing bytes")
    return t, record

art = json.load(open("contracts/compiled/impulse_hashlock.v1.json"))["contracts"]["ImpulseHashlock"]["compiled"]
code = bytes(art["bytecode"])
span = art["state_span"]
prefix, suffix = code[:span["offset"]], code[span["offset"] + span["len"]:]
pinned = open("contracts/TEMPLATE_HASH_HASHLOCK").read().strip()
if bytes(art["template_hash"]).hex() != pinned:
    sys.exit("artifact template_hash is not TEMPLATE_HASH_HASHLOCK")

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)
def polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i, g in enumerate(GEN):
            if c0 & (1 << i): c ^= g
    return c ^ 1
def to5(data):
    acc = bits = 0; out = []
    for x in data:
        acc = (acc << 8) | x; bits += 8
        while bits >= 5:
            bits -= 5; out.append((acc >> bits) & 31)
    if bits: out.append((acc << (5 - bits)) & 31)
    return out
def address(hrp, version, payload):
    data = to5(bytes([version]) + payload)
    chk = polymod([ord(c) & 31 for c in hrp] + [0] + data + [0] * 8)
    return hrp + ":" + "".join(CHARSET[d] for d in data + to5(chk.to_bytes(5, "big")))
# rusty-kaspa a41a333 crypto/addresses tests, ScriptHash version: the encoder must reproduce them.
for p, payload, want in [("a", b"", "a:pq99546ray"), ("b", b"abc", "b:ppskycc8txxxn2w"),
                         ("b", b"1234598760", "b:pqcnyve5x5unsdekxqeusxeyu2")]:
    if address(p, 8, payload) != want:
        sys.exit("address encoder self-check failed")

def pushes(b):
    # The hashlock state holds fixed-width fields only, each one canonical OpData push.
    out, i = [], 0
    while i < len(b):
        op = b[i]; i += 1
        if not 1 <= op <= 75: raise ValueError("opcode %#x in state" % op)
        if i + op > len(b): raise ValueError("truncated push")
        out.append(b[i:i + op]); i += op
    return out
def num(b):
    if len(b) != 8 or b[7] & 0x80: raise ValueError("not a non-negative 8-byte int")
    return int.from_bytes(b, "little")

LAYOUT = [("version", 1), ("network", 1), ("nonce", 8), ("sellerKey", 32), ("buyerKey", 32),
    ("assetCovenantId", 32), ("assetTemplateHash", 32), ("assetPrefixLen", 8), ("assetSuffixLen", 8),
    ("amount", 8), ("buyerDeliveryType", 1), ("buyerDeliveryId", 32), ("sellerRefundType", 1),
    ("sellerRefundId", 32), ("hashLock", 32), ("expiryDaa", 8), ("counterpartHash", 32), ("tradeRef", 32)]

def vault_state(script):
    if len(script) < len(prefix) + len(suffix) or not (script.startswith(prefix) and script.endswith(suffix)):
        raise ValueError("not the ImpulseHashlock template")
    ps = pushes(script[len(prefix):len(script) - len(suffix)])
    if len(ps) != len(LAYOUT): raise ValueError("state has %d pushes" % len(ps))
    f = {}
    for (name, size), data in zip(LAYOUT, ps):
        if len(data) != size: raise ValueError(name + " size")
        f[name] = data
    return f

files = sorted(pathlib.Path(sys.argv[1]).glob("*.json"))
if not files:
    sys.exit("no hashlock vectors")
for f in files:
    v = json.loads(f.read_text())
    if v["name"] != f.stem: sys.exit(f"{f}: name")
    canonical = bytes.fromhex(v["canonical"])
    try:
        t, record = decode(canonical)
    except (ValueError, IndexError, KeyError) as e:
        sys.exit(f"{f}: {e}")
    if json.dumps(t) != json.dumps(v["terms"]):
        sys.exit(f"{f}: canonical bytes do not decode to the terms object")
    if record.hex() != v["counterpart_record"]: sys.exit(f"{f}: counterpart_record")
    ch = hashlib.blake2b(record, digest_size=32, key=b"Impulse/htlc/counterpart/v1").hexdigest()
    if ch != v["counterpart_hash"]: sys.exit(f"{f}: counterpart_hash")
    if hashlib.blake2b(canonical, digest_size=32, key=b"Impulse/htlc/v1").hexdigest() != v["htlc_terms_hash"]:
        sys.exit(f"{f}: htlc_terms_hash")
    if v["template_hash"] != pinned: sys.exit(f"{f}: template_hash")
    script = bytes.fromhex(v["vault"]["redeem_script"])
    try:
        s = vault_state(script)
        a = t["asset_leg"]
        expected = [
            ("version", bytes([t["version"]])), ("network", bytes([["mainnet", "testnet"].index(t["network"])])),
            ("nonce", int(t["nonce"]).to_bytes(8, "little")), ("sellerKey", bytes.fromhex(t["seller_key"])),
            ("buyerKey", bytes.fromhex(t["buyer_key"])), ("assetCovenantId", bytes.fromhex(a["covenant_id"])),
            ("assetTemplateHash", bytes.fromhex(a["template_hash"])),
            ("buyerDeliveryType", bytes([IDS.index(t["buyer_delivery"]["identifier_type"])])),
            ("buyerDeliveryId", bytes.fromhex(t["buyer_delivery"]["identifier"])),
            ("sellerRefundType", bytes([IDS.index(t["seller_refund"]["identifier_type"])])),
            ("sellerRefundId", bytes.fromhex(t["seller_refund"]["identifier"])),
            ("hashLock", bytes.fromhex(t["hash_lock"])), ("counterpartHash", bytes.fromhex(ch)),
            ("tradeRef", bytes.fromhex(t["trade_ref"]))]
        for name, want in expected:
            if s[name] != want: raise ValueError(name)
        for name, want in [("assetPrefixLen", a["template_prefix_len"]), ("assetSuffixLen", a["template_suffix_len"]),
                           ("amount", int(a["amount"])), ("expiryDaa", int(t["expiry_daa"]))]:
            if num(s[name]) != want: raise ValueError(name)
    except (ValueError, IndexError, KeyError) as e:
        sys.exit(f"{f} vault: {e}")
    h = hashlib.blake2b(script, digest_size=32).digest()
    if v["vault"]["script_hash"] != h.hex(): sys.exit(f"{f}: script_hash")
    hrp = {"mainnet": "kaspa", "testnet": "kaspatest"}[t["network"]]
    if v["vault"]["address"] != address(hrp, 8, h): sys.exit(f"{f}: address")
print(f"vectors: {len(files)} hashlock vectors decoded, hashed, instantiated and addressed independently")
EOF

# I20 (spec/V3-ZK.md sections 7.4, 13.4): the issuer list, manifest, journal and terms v3 vectors.
# Their generator is behind the non-default `zk` feature of impulse-core.
IMPULSE_VECTORS_OUT="$out" cargo test --locked -q -p impulse-core --features zk --lib \
  "zk::golden::emit_vectors" -- --ignored --exact >/dev/null
diff -r "$out/zk" tests/vectors/zk || fail "regenerated zk vectors differ from tests/vectors/zk"
diff -r "$out/terms_v3" tests/vectors/terms_v3 || fail "regenerated terms v3 vectors differ from tests/vectors/terms_v3"
diff -r "$out/vaults_v3" tests/vectors/vaults_v3 || fail "regenerated template v3 vault vectors differ from tests/vectors/vaults_v3"
python3 -I scripts/vectors-zk.py tests/vectors || fail "independent zk and terms v3 check"

# I21 (spec/V3-ZK.md 22.9): the terms v4, template v4 vault, journal v4 and IPST version 5 vectors, generator behind the
# non-default `zk-hashed` feature of impulse-core.
IMPULSE_VECTORS_OUT="$out" cargo test --locked -q -p impulse-core --features zk-hashed --lib \
  "zkh::tests::emit_vectors" -- --ignored --exact >/dev/null
diff -r "$out/terms_v4" tests/vectors/terms_v4 || fail "regenerated terms v4 vectors differ from tests/vectors/terms_v4"
diff -r "$out/vaults_v4" tests/vectors/vaults_v4 || fail "regenerated template v4 vault vectors differ from tests/vectors/vaults_v4"
diff -r "$out/journal_v4" tests/vectors/journal_v4 || fail "regenerated journal v4 vectors differ from tests/vectors/journal_v4"
diff -r "$out/ipst_v5" tests/vectors/ipst_v5 || fail "regenerated IPST version 5 vectors differ from tests/vectors/ipst_v5"
python3 -I scripts/vectors-v4.py tests/vectors || fail "independent terms v4 and template v4 vault check"

python3 - tests/vectors/terms <<'EOF' || fail "independent decode and terms_hash check"
# Decodes each canonical encoding by spec/ENCODING.md alone and compares it, field by field and
# in order, with the vector's terms object; then recomputes the hash with hashlib.
import hashlib, json, pathlib, struct, sys

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        if len(s.b) - s.p < n: raise ValueError("truncated")
        s.p += n
        return s.b[s.p - n:s.p]
    def u8(s): return s.take(1)[0]
    def u16(s): return struct.unpack("<H", s.take(2))[0]
    def u32(s): return struct.unpack("<I", s.take(4))[0]
    def u64(s): return str(struct.unpack("<Q", s.take(8))[0])
    def hx(s): return s.take(32).hex()
    def opt(s, f):
        p = s.u8()
        if p not in (0, 1): raise ValueError("presence")
        return f() if p else None

def leg(r):
    k = ["kas", "kcc20", "external"][r.u8()]
    o = {"kind": k}
    if k == "kcc20":
        o.update(covenant_id=r.hx(), template_hash=r.hx(),
                 template_prefix_len=r.u32(), template_suffix_len=r.u32())
    o["amount"] = r.u64()
    return o

def dest(r):
    k = ["kas", "kcc20", "off_chain"][r.u8()]
    if k == "kas":
        v = r.u16(); n = r.u32()
        if n > 10000: raise ValueError("too long")
        return {"kind": k, "version": v, "script": r.take(n).hex()}
    if k == "kcc20":
        t = ["pubkey", "script_hash", "covenant_id"][r.u8()]
        return {"kind": k, "identifier_type": t, "identifier": r.hx()}
    return {"kind": k}

def decode(b):
    r = R(b); t = {}
    t["version"] = r.u8()
    if t["version"] != 1: raise ValueError("version")
    t["network"] = ["mainnet", "testnet"][r.u8()]
    t["settlement_mode"] = ["direct", "vault"][r.u8()]
    t["nonce"] = r.u64()
    t["seller_key"] = r.hx(); t["buyer_key"] = r.hx()
    t["authority_key"] = r.opt(r.hx)
    t["asset_leg"] = leg(r); t["cash_leg"] = leg(r)
    for f in ("buyer_delivery", "seller_proceeds", "seller_refund", "buyer_refund"):
        t[f] = dest(r)
    t["earliest_daa"] = r.opt(r.u64)
    t["expiry_daa"] = r.u64()
    t["funding_mode"] = ["revocable", "earmarked"][r.u8()]
    t["trade_ref"] = r.hx()
    if r.p != len(b): raise ValueError("trailing bytes")
    return t

files = sorted(pathlib.Path(sys.argv[1]).glob("*.json"))
if not files:
    sys.exit("no terms vectors")
for f in files:
    v = json.loads(f.read_text())
    canonical = bytes.fromhex(v["canonical"])
    t = decode(canonical)
    if json.dumps(t) != json.dumps(v["terms"]):
        sys.exit(f"{f}: canonical bytes do not decode to the terms object")
    h = hashlib.blake2b(canonical, digest_size=32, key=b"Impulse/terms/v1")
    if h.hexdigest() != v["terms_hash"]:
        sys.exit(f"{f}: terms_hash does not match its canonical bytes")
print(f"vectors: {len(files)} terms vectors decoded and hashed independently")
EOF

python3 - tests/vectors/terms tests/vectors/vaults <<'EOF' || fail "independent vault decode, script hash and address check"
# Decodes each vault's redeem script by spec/TEMPLATE.md alone, compares the state with the terms
# vector's terms object and the leg index, and recomputes the script hash (hashlib) and the
# address (an encoder written from the rusty-kaspa address format, below).
import hashlib, json, pathlib, sys

art = json.load(open("contracts/compiled/impulse_vault.v1.json"))["contracts"]["ImpulseVault"]["compiled"]
code = bytes(art["bytecode"])
span = art["state_span"]
prefix, suffix = code[:span["offset"]], code[span["offset"] + span["len"]:]
pinned = open("contracts/TEMPLATE_HASH").read().strip()
if bytes(art["template_hash"]).hex() != pinned:
    sys.exit("artifact template_hash is not TEMPLATE_HASH")

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)
def polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i, g in enumerate(GEN):
            if c0 & (1 << i): c ^= g
    return c ^ 1
def to5(data):
    acc = bits = 0; out = []
    for b in data:
        acc = (acc << 8) | b; bits += 8
        while bits >= 5:
            bits -= 5; out.append((acc >> bits) & 31)
    if bits: out.append((acc << (5 - bits)) & 31)
    return out
def address(prefix, version, payload):
    data = to5(bytes([version]) + payload)
    chk = polymod([ord(c) & 31 for c in prefix] + [0] + data + [0] * 8)
    return prefix + ":" + "".join(CHARSET[d] for d in data + to5(chk.to_bytes(5, "big")))
# rusty-kaspa a41a333 crypto/addresses tests, ScriptHash version: the encoder must reproduce them.
for p, payload, want in [("a", b"", "a:pq99546ray"), ("b", b"abc", "b:ppskycc8txxxn2w"),
                         ("b", b"1234598760", "b:pqcnyve5x5unsdekxqeusxeyu2")]:
    if address(p, 8, payload) != want:
        sys.exit("address encoder self-check failed")

def pushes(b):
    out, i = [], 0
    while i < len(b):
        op = b[i]; i += 1
        if op == 0: n = 0
        elif op <= 75: n = op
        elif op == 0x4c: n = b[i]; i += 1
        else: raise ValueError("opcode %#x in state" % op)
        if n == 0 and op != 0 or 0 < n <= 75 and op != n or n > 75 and op != 0x4c:
            raise ValueError("non-canonical push")
        if i + n > len(b): raise ValueError("truncated push")
        out.append(b[i:i + n]); i += n
    return out
def num(b):
    if len(b) != 8: raise ValueError("int is not 8 bytes")
    mag = int.from_bytes(b[:7] + bytes([b[7] & 0x7f]), "little")
    if b[7] & 0x80:
        if mag == 0: raise ValueError("negative zero")
        return -mag
    return mag

LAYOUT = [("version", 1), ("network", 1), ("nonce", 8), ("sellerKey", 32), ("buyerKey", 32),
    ("hasAuthority", 1), ("authorityKey", 32), ("assetCovenantId", 32), ("assetTemplateHash", 32),
    ("assetPrefixLen", 8), ("assetSuffixLen", 8), ("amountA", 8), ("cashKind", 1),
    ("cashCovenantId", 32), ("cashTemplateHash", 32), ("cashPrefixLen", 8), ("cashSuffixLen", 8),
    ("amountB", 8), ("buyerDeliveryType", 1), ("buyerDeliveryId", 32), ("sellerProceedsType", 1),
    ("sellerProceedsId", 32), ("sellerProceedsSpk", None), ("sellerRefundType", 1),
    ("sellerRefundId", 32), ("buyerRefundType", 1), ("buyerRefundId", 32), ("buyerRefundSpk", None),
    ("hasEarliest", 1), ("earliestDaa", 8), ("expiryDaa", 8), ("fundingMode", 1), ("tradeRef", 32),
    ("legIndex", 8)]
IDS = ["pubkey", "script_hash", "covenant_id"]

def decode(script):
    if not (script.startswith(prefix) and script.endswith(suffix)) or len(script) < len(prefix) + len(suffix):
        raise ValueError("not the ImpulseVault template")
    ps = pushes(script[len(prefix):len(script) - len(suffix)])
    if len(ps) != len(LAYOUT): raise ValueError("state has %d pushes" % len(ps))
    f = {}
    for (name, size), data in zip(LAYOUT, ps):
        if size is not None and len(data) != size: raise ValueError(name + " size")
        f[name] = data
    flag = lambda n: {b"\x00": False, b"\x01": True}[f[n]]
    zero = lambda n: f[n] in (bytes(len(f[n])),)
    def token(side):
        return {"covenant_id": f[side + "CovenantId"].hex(), "template_hash": f[side + "TemplateHash"].hex(),
                "template_prefix_len": num(f[side + "PrefixLen"]), "template_suffix_len": num(f[side + "SuffixLen"])}
    def owner(t, i):
        return {"kind": "kcc20", "identifier_type": IDS[f[t][0]], "identifier": f[i].hex()}
    cash = f["cashKind"][0]
    def cash_dest(t, i, s):
        if cash == 0:
            if not (zero(t) and zero(i)): raise ValueError(t + " used under KAS cash")
            spk = f[s]
            return {"kind": "kas", "version": int.from_bytes(spk[:2], "big"), "script": spk[2:].hex()}
        if f[s] != b"": raise ValueError(s + " used without KAS cash")
        if cash == 1: return owner(t, i)
        if not (zero(t) and zero(i)): raise ValueError(t + " used under external cash")
        return {"kind": "off_chain"}
    t = {"version": f["version"][0], "network": ["mainnet", "testnet"][f["network"][0]], "settlement_mode": "vault",
         "nonce": str(int.from_bytes(f["nonce"], "little")), "seller_key": f["sellerKey"].hex(),
         "buyer_key": f["buyerKey"].hex()}
    if flag("hasAuthority"): t["authority_key"] = f["authorityKey"].hex()
    elif zero("authorityKey"): t["authority_key"] = None
    else: raise ValueError("authority key under an absent authority")
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
    if flag("hasEarliest"): t["earliest_daa"] = str(num(f["earliestDaa"]))
    elif zero("earliestDaa"): t["earliest_daa"] = None
    else: raise ValueError("earliest_daa under an absent bound")
    t["expiry_daa"] = str(num(f["expiryDaa"]))
    t["funding_mode"] = ["revocable", "earmarked"][f["fundingMode"][0]]
    t["trade_ref"] = f["tradeRef"].hex()
    return t, num(f["legIndex"])

terms_dir, vault_dir = map(pathlib.Path, sys.argv[1:3])
files = sorted(vault_dir.glob("*.json"))
if [f.name for f in files] != sorted(f.name for f in terms_dir.glob("*.json")):
    sys.exit("vault vectors do not match the terms vectors one to one")
count = 0
for f in files:
    v = json.loads(f.read_text())
    tv = json.loads((terms_dir / f.name).read_text())
    if v["name"] != tv["name"] or v["terms_hash"] != tv["terms_hash"] or v["template_hash"] != pinned:
        sys.exit(f"{f}: name, terms_hash or template_hash")
    terms = tv["terms"]
    for key, leg in (("asset_vault", 0), ("cash_vault", 1)):
        j = v[key]
        if j["leg_index"] != leg: sys.exit(f"{f} {key}: leg_index")
        has_vault = terms["settlement_mode"] == "vault" and not (leg == 1 and terms["cash_leg"]["kind"] == "external")
        if not has_vault:
            if j != {"leg_index": leg, "refused": "TEMPLATE_NO_VAULT"}: sys.exit(f"{f} {key}: expected TEMPLATE_NO_VAULT")
            continue
        if sorted(j) != ["address", "leg_index", "redeem_script", "script_hash"]:
            sys.exit(f"{f} {key}: expected leg_index, redeem_script, script_hash and address")
        script = bytes.fromhex(j["redeem_script"])
        try:
            decoded, decoded_leg = decode(script)
        except (ValueError, IndexError, KeyError) as e:
            sys.exit(f"{f} {key}: {e}")
        if json.dumps(decoded) != json.dumps(terms) or decoded_leg != leg:
            sys.exit(f"{f} {key}: the redeem script does not decode to the terms vector")
        h = hashlib.blake2b(script, digest_size=32).digest()
        if j["script_hash"] != h.hex(): sys.exit(f"{f} {key}: script_hash")
        hrp = {"mainnet": "kaspa", "testnet": "kaspatest"}[terms["network"]]
        if j["address"] != address(hrp, 8, h): sys.exit(f"{f} {key}: address")
        count += 1
print(f"vectors: {count} vault redeem scripts decoded, hashed and addressed independently")
EOF

python3 - tests/vectors/ipst <<'EOF' || fail "independent IPST sighash check"
# Recomputes each slot's SIG_HASH_ALL Schnorr sighash from the IPST alone, as rusty-kaspa a41a333
# consensus/core/src/hashing/sighash.rs defines it for a version-1 transaction on the native
# subnetwork with gas 0 and an empty payload (spec/IPST.md, "Fixed transaction fields").
import hashlib, json, pathlib, struct, sys

def H(data): return hashlib.blake2b(data, digest_size=32, key=b"TransactionSigningHash").digest()
def u8(n): return struct.pack("<B", n)
def u16(n): return struct.pack("<H", n)
def u32(n): return struct.pack("<I", n)
def u64(n): return struct.pack("<Q", int(n))
def spk(j):
    script = bytes.fromhex(j["script"])
    return u16(j["version"]) + u64(len(script)) + script

files = sorted(pathlib.Path(sys.argv[1]).glob("*.json"))
if not files:
    sys.exit("no IPST vectors")
count = 0
for f in files:
    v = json.loads(f.read_text())
    if v["name"] != f.stem: sys.exit(f"{f}: name")
    d = v["ipst"]
    if d["ipst"] != 1: sys.exit(f"{f}: version")
    ins, outs = d["inputs"], d["outputs"]
    prev = H(b"".join(bytes.fromhex(i["transaction_id"]) + u32(i["index"]) for i in ins))
    seqs = H(b"".join(u64(i["sequence"]) for i in ins))
    def output(o):
        c = o["covenant"]
        tail = u8(0) if c is None else u8(1) + u16(c["authorizing_input"]) + bytes.fromhex(c["covenant_id"])
        return u64(o["value"]) + spk(o["script_public_key"]) + tail
    outh = H(b"".join(output(o) for o in outs))
    fixed = u64(d["lock_time"]) + bytes(20) + u64(0) + bytes(32) + u8(1)
    for n, i in enumerate(ins):
        if i["signature"] is not None: sys.exit(f"{f} input {n}: the vectors are unsigned")
        if i["signer"] is None:
            if i["sighash"] is not None or i["script_after"] != "":
                sys.exit(f"{f} input {n}: a slot without a signer has no sighash and no script_after")
            continue
        u = i["utxo"]
        msg = (u16(1) + prev + seqs + bytes.fromhex(i["transaction_id"]) + u32(i["index"])
               + spk(u["script_public_key"]) + u64(u["amount"]) + u64(i["sequence"]) + outh + fixed)
        if H(msg).hex() != i["sighash"]: sys.exit(f"{f} input {n}: sighash")
        count += 1
    held = sum(int(i["utxo"]["amount"]) for i in ins)
    paid = sum(int(o["value"]) for o in outs)
    if held <= paid: sys.exit(f"{f}: no fee")
print(f"vectors: {len(files)} IPST vectors, {count} sighashes recomputed independently")
EOF

python3 - tests/vectors/terms_v2 tests/vectors/vaults_v2 <<'EOF' || fail "independent terms v2 and v2 vault check"
# Decodes each terms v2 encoding by spec/V2.md 5.2 alone and compares it, field by field and in
# order, with the vector's terms object; recomputes the hash with hashlib (key "Impulse/terms/v2",
# as it is). Then decodes each v2 vault's redeem script by spec/V2.md 4.2 against the v2
# artifact's prefix and suffix, compares it with the terms vector and the leg index, and
# recomputes the script hash and the address.
import hashlib, json, pathlib, struct, sys

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        if len(s.b) - s.p < n: raise ValueError("truncated")
        s.p += n
        return s.b[s.p - n:s.p]
    def u8(s): return s.take(1)[0]
    def u32(s): return struct.unpack("<I", s.take(4))[0]
    def u64(s): return str(struct.unpack("<Q", s.take(8))[0])
    def hx(s): return s.take(32).hex()
    def opt(s, f):
        p = s.u8()
        if p not in (0, 1): raise ValueError("presence")
        return f() if p else None

IDS = ["pubkey", "script_hash", "covenant_id"]
def dest(r): return {"identifier_type": IDS[r.u8()], "identifier": r.hx()}

def decode_terms(b):
    r = R(b); t = {}
    t["version"] = r.u8()
    if t["version"] != 2: raise ValueError("version")
    t["network"] = ["mainnet", "testnet"][r.u8()]
    t["nonce"] = r.u64()
    t["authority_key"] = r.opt(r.hx)
    legs = []
    for _ in range(r.u8()):
        leg = {"depositor_key": r.hx()}
        k = ["kas", "kcc20", "external"][r.u8()]
        a = {"kind": k}
        if k == "kcc20":
            a.update(covenant_id=r.hx(), template_hash=r.hx(),
                     template_prefix_len=r.u32(), template_suffix_len=r.u32())
        a["amount"] = r.u64()
        leg["asset"] = a
        leg["delivery"] = dest(r); leg["refund"] = dest(r)
        legs.append(leg)
    t["legs"] = legs
    t["earliest_daa"] = r.opt(r.u64)
    t["expiry_daa"] = r.u64()
    t["funding_mode"] = ["revocable", "earmarked"][r.u8()]
    t["partial"] = r.opt(lambda: {"lot_count": r.u64(), "min_lot": r.u64()})
    t["trade_ref"] = r.hx()
    if r.p != len(b): raise ValueError("trailing bytes")
    return t

terms_dir, vault_dir = map(pathlib.Path, sys.argv[1:3])
files = sorted(terms_dir.glob("*.json"))
if not files:
    sys.exit("no terms v2 vectors")
for f in files:
    v = json.loads(f.read_text())
    canonical = bytes.fromhex(v["canonical"])
    if json.dumps(decode_terms(canonical)) != json.dumps(v["terms"]):
        sys.exit(f"{f}: canonical bytes do not decode to the terms object")
    if hashlib.blake2b(canonical, digest_size=32, key=b"Impulse/terms/v2").hexdigest() != v["terms_hash"]:
        sys.exit(f"{f}: terms_hash does not match its canonical bytes")

art = json.load(open("contracts/compiled/impulse_vault.v2.json"))["contracts"]["ImpulseVaultV2"]["compiled"]
code = bytes(art["bytecode"])
span = art["state_span"]
prefix, suffix = code[:span["offset"]], code[span["offset"] + span["len"]:]
pinned = open("contracts/TEMPLATE_HASH_V2").read().strip()
if bytes(art["template_hash"]).hex() != pinned:
    sys.exit("v2 artifact template_hash is not TEMPLATE_HASH_V2")

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = (0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)
def polymod(values):
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i, g in enumerate(GEN):
            if c0 & (1 << i): c ^= g
    return c ^ 1
def to5(data):
    acc = bits = 0; out = []
    for b in data:
        acc = (acc << 8) | b; bits += 8
        while bits >= 5:
            bits -= 5; out.append((acc >> bits) & 31)
    if bits: out.append((acc << (5 - bits)) & 31)
    return out
def address(hrp, version, payload):
    data = to5(bytes([version]) + payload)
    chk = polymod([ord(c) & 31 for c in hrp] + [0] + data + [0] * 8)
    return hrp + ":" + "".join(CHARSET[d] for d in data + to5(chk.to_bytes(5, "big")))
for p, payload, want in [("a", b"", "a:pq99546ray"), ("b", b"abc", "b:ppskycc8txxxn2w"),
                         ("b", b"1234598760", "b:pqcnyve5x5unsdekxqeusxeyu2")]:
    if address(p, 8, payload) != want:
        sys.exit("address encoder self-check failed")

def pushes(b):
    out, i = [], 0
    while i < len(b):
        op = b[i]; i += 1
        if op == 0: n = 0
        elif op <= 75: n = op
        elif op == 0x4c: n = b[i]; i += 1
        elif op == 0x4d: n = b[i] | b[i + 1] << 8; i += 2
        else: raise ValueError("opcode %#x in state" % op)
        canonical = (n == 0 and op == 0) or (0 < n <= 75 and op == n) or \
                    (75 < n <= 255 and op == 0x4c) or (255 < n <= 65535 and op == 0x4d)
        if not canonical: raise ValueError("non-canonical push")
        if i + n > len(b): raise ValueError("truncated push")
        out.append(b[i:i + n]); i += n
    return out
def num(b):
    if len(b) != 8: raise ValueError("int is not 8 bytes")
    if b[7] & 0x80: raise ValueError("negative")
    return int.from_bytes(b, "little")

LAYOUT = [("version", 1), ("network", 1), ("nonce", 8), ("hasAuthority", 1), ("authorityKey", 32),
    ("legCount", 8), ("legs", None), ("hasEarliest", 1), ("earliestDaa", 8), ("expiryDaa", 8),
    ("fundingMode", 1), ("tradeRef", 32), ("lotCount", 8), ("minLot", 8), ("legIndex", 8)]

def decode_vault(script):
    if len(script) < len(prefix) + len(suffix) or not script.startswith(prefix) or not script.endswith(suffix):
        raise ValueError("not the ImpulseVault v2 template")
    ps = pushes(script[len(prefix):len(script) - len(suffix)])
    if len(ps) != len(LAYOUT): raise ValueError("state has %d pushes" % len(ps))
    f = {}
    for (name, size), data in zip(LAYOUT, ps):
        if size is not None and len(data) != size: raise ValueError(name + " size")
        f[name] = data
    flag = lambda n: {b"\x00": False, b"\x01": True}[f[n]]
    count = num(f["legCount"])
    if len(f["legs"]) != 187 * count: raise ValueError("leg list length")
    legs = []
    for j in range(count):
        rec = f["legs"][187 * j:187 * (j + 1)]
        leg = {"depositor_key": rec[0:32].hex()}
        kind = rec[32]
        if kind == 1:
            a = {"kind": "kcc20", "covenant_id": rec[33:65].hex(), "template_hash": rec[65:97].hex(),
                 "template_prefix_len": num(rec[97:105]), "template_suffix_len": num(rec[105:113])}
        elif kind == 0:
            if rec[33:113] != bytes(80): raise ValueError("token fields on a KAS leg")
            a = {"kind": "kas"}
        else:
            raise ValueError("kind byte")
        a["amount"] = str(num(rec[113:121]))
        leg["asset"] = a
        leg["delivery"] = {"identifier_type": IDS[rec[121]], "identifier": rec[122:154].hex()}
        leg["refund"] = {"identifier_type": IDS[rec[154]], "identifier": rec[155:187].hex()}
        legs.append(leg)
    t = {"version": f["version"][0], "network": ["mainnet", "testnet"][f["network"][0]],
         "nonce": str(int.from_bytes(f["nonce"], "little"))}
    if flag("hasAuthority"): t["authority_key"] = f["authorityKey"].hex()
    elif f["authorityKey"] == bytes(32): t["authority_key"] = None
    else: raise ValueError("authority key under an absent authority")
    t["legs"] = legs
    if flag("hasEarliest"): t["earliest_daa"] = str(num(f["earliestDaa"]))
    elif num(f["earliestDaa"]) == 0: t["earliest_daa"] = None
    else: raise ValueError("earliest_daa under an absent bound")
    t["expiry_daa"] = str(num(f["expiryDaa"]))
    t["funding_mode"] = ["revocable", "earmarked"][f["fundingMode"][0]]
    lots, minimum = num(f["lotCount"]), num(f["minLot"])
    t["partial"] = None if (lots, minimum) == (1, 1) else {"lot_count": str(lots), "min_lot": str(minimum)}
    t["trade_ref"] = f["tradeRef"].hex()
    return t, num(f["legIndex"])

vfiles = sorted(vault_dir.glob("*.json"))
if [f.name for f in vfiles] != [f.name for f in files]:
    sys.exit("v2 vault vectors do not match the terms v2 vectors one to one")
count = 0
for f in vfiles:
    v = json.loads(f.read_text())
    tv = json.loads((terms_dir / f.name).read_text())
    if v["name"] != tv["name"] or v["terms_hash"] != tv["terms_hash"] or v["template_hash"] != pinned:
        sys.exit(f"{f}: name, terms_hash or template_hash")
    if len(v["vaults"]) != len(tv["terms"]["legs"]):
        sys.exit(f"{f}: one vault per leg")
    for i, j in enumerate(v["vaults"]):
        if sorted(j) != ["address", "leg_index", "redeem_script", "script_hash"] or j["leg_index"] != i:
            sys.exit(f"{f} vault {i}: keys or leg_index")
        script = bytes.fromhex(j["redeem_script"])
        try:
            decoded, leg = decode_vault(script)
        except (ValueError, IndexError, KeyError) as e:
            sys.exit(f"{f} vault {i}: {e}")
        if json.dumps(decoded) != json.dumps(tv["terms"]) or leg != i:
            sys.exit(f"{f} vault {i}: the redeem script does not decode to the terms vector")
        h = hashlib.blake2b(script, digest_size=32).digest()
        if j["script_hash"] != h.hex(): sys.exit(f"{f} vault {i}: script_hash")
        hrp = {"mainnet": "kaspa", "testnet": "kaspatest"}[tv["terms"]["network"]]
        if j["address"] != address(hrp, 8, h): sys.exit(f"{f} vault {i}: address")
        count += 1
print(f"vectors: {len(files)} terms v2 vectors decoded and hashed, {count} v2 vault scripts decoded, hashed and addressed independently")
EOF

python3 - tests/vectors/ipst_v2 <<'EOF' || fail "independent IPST v2 sighash check"
# Step 6 for documents of version 2: the same sighash, recomputed from each document alone.
import hashlib, json, pathlib, struct, sys

def H(data): return hashlib.blake2b(data, digest_size=32, key=b"TransactionSigningHash").digest()
def u8(n): return struct.pack("<B", n)
def u16(n): return struct.pack("<H", n)
def u32(n): return struct.pack("<I", n)
def u64(n): return struct.pack("<Q", int(n))
def spk(j):
    script = bytes.fromhex(j["script"])
    return u16(j["version"]) + u64(len(script)) + script

files = sorted(pathlib.Path(sys.argv[1]).glob("*.json"))
if not files:
    sys.exit("no IPST v2 vectors")
count = 0
for f in files:
    v = json.loads(f.read_text())
    if v["name"] != f.stem: sys.exit(f"{f}: name")
    d = v["ipst"]
    if d["ipst"] != 2: sys.exit(f"{f}: version")
    if bytes.fromhex(d["terms"])[0] != 2: sys.exit(f"{f}: terms are not version 2")
    ins, outs = d["inputs"], d["outputs"]
    prev = H(b"".join(bytes.fromhex(i["transaction_id"]) + u32(i["index"]) for i in ins))
    seqs = H(b"".join(u64(i["sequence"]) for i in ins))
    def output(o):
        c = o["covenant"]
        tail = u8(0) if c is None else u8(1) + u16(c["authorizing_input"]) + bytes.fromhex(c["covenant_id"])
        return u64(o["value"]) + spk(o["script_public_key"]) + tail
    outh = H(b"".join(output(o) for o in outs))
    fixed = u64(d["lock_time"]) + bytes(20) + u64(0) + bytes(32) + u8(1)
    for n, i in enumerate(ins):
        if i["signature"] is not None: sys.exit(f"{f} input {n}: the vectors are unsigned")
        if i["signer"] is None:
            if i["sighash"] is not None or i["script_after"] != "":
                sys.exit(f"{f} input {n}: a slot without a signer has no sighash and no script_after")
            continue
        u = i["utxo"]
        msg = (u16(1) + prev + seqs + bytes.fromhex(i["transaction_id"]) + u32(i["index"])
               + spk(u["script_public_key"]) + u64(u["amount"]) + u64(i["sequence"]) + outh + fixed)
        if H(msg).hex() != i["sighash"]: sys.exit(f"{f} input {n}: sighash")
        count += 1
    held = sum(int(i["utxo"]["amount"]) for i in ins)
    paid = sum(int(o["value"]) for o in outs)
    if held <= paid: sys.exit(f"{f}: no fee")
print(f"vectors: {len(files)} IPST v2 vectors, {count} sighashes recomputed independently")
EOF

python3 - tests/vectors/linked <<'EOF' || fail "independent linked sheet decode, hash and derivation check"
# Decodes each linked sheet by spec/V2.md 17.2 alone, hashes it with hashlib (key
# "Impulse/terms/v2/linked", as it is), derives the opening and the return by the table of 17.3
# alone, encodes both by spec/V2.md 5.2 alone, and compares bytes, hashes and the JSON views.
import hashlib, json, pathlib, struct, sys

class R:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        if len(s.b) - s.p < n: raise ValueError("truncated")
        s.p += n
        return s.b[s.p - n:s.p]
    def u8(s): return s.take(1)[0]
    def u16(s): return struct.unpack("<H", s.take(2))[0]
    def u32(s): return struct.unpack("<I", s.take(4))[0]
    def u64(s): return struct.unpack("<Q", s.take(8))[0]
    def d64(s): return str(s.u64())
    def hx(s): return s.take(32).hex()
    def opt(s, f):
        p = s.u8()
        if p not in (0, 1): raise ValueError("presence")
        return f() if p else None

IDS = ["pubkey", "script_hash", "covenant_id"]
KINDS = ["kas", "kcc20", "external"]
def dest(r): return {"identifier_type": IDS[r.u8()], "identifier": r.hx()}

def decode_terms(b):
    r = R(b); t = {}
    t["version"] = r.u8()
    if t["version"] != 2: raise ValueError("version")
    t["network"] = ["mainnet", "testnet"][r.u8()]
    t["nonce"] = r.d64()
    t["authority_key"] = r.opt(r.hx)
    legs = []
    for _ in range(r.u8()):
        leg = {"depositor_key": r.hx()}
        k = KINDS[r.u8()]
        a = {"kind": k}
        if k == "kcc20":
            a.update(covenant_id=r.hx(), template_hash=r.hx(),
                     template_prefix_len=r.u32(), template_suffix_len=r.u32())
        a["amount"] = r.d64()
        leg["asset"] = a
        leg["delivery"] = dest(r); leg["refund"] = dest(r)
        legs.append(leg)
    t["legs"] = legs
    t["earliest_daa"] = r.opt(r.d64)
    t["expiry_daa"] = r.d64()
    t["funding_mode"] = ["revocable", "earmarked"][r.u8()]
    t["partial"] = r.opt(lambda: {"lot_count": r.d64(), "min_lot": r.d64()})
    t["trade_ref"] = r.hx()
    if r.p != len(b): raise ValueError("trailing bytes")
    return t

def encode_terms(t):
    o = bytes([t["version"], ["mainnet", "testnet"].index(t["network"])]) + struct.pack("<Q", int(t["nonce"]))
    o += b"\x00" if t["authority_key"] is None else b"\x01" + bytes.fromhex(t["authority_key"])
    o += bytes([len(t["legs"])])
    for l in t["legs"]:
        a = l["asset"]
        o += bytes.fromhex(l["depositor_key"]) + bytes([KINDS.index(a["kind"])])
        if a["kind"] == "kcc20":
            o += bytes.fromhex(a["covenant_id"]) + bytes.fromhex(a["template_hash"])
            o += struct.pack("<II", a["template_prefix_len"], a["template_suffix_len"])
        o += struct.pack("<Q", int(a["amount"]))
        for d in (l["delivery"], l["refund"]):
            o += bytes([IDS.index(d["identifier_type"])]) + bytes.fromhex(d["identifier"])
    o += b"\x00" if t["earliest_daa"] is None else b"\x01" + struct.pack("<Q", int(t["earliest_daa"]))
    o += struct.pack("<Q", int(t["expiry_daa"]))
    o += bytes([["revocable", "earmarked"].index(t["funding_mode"])])
    if t["partial"] is None: o += b"\x00"
    else: o += b"\x01" + struct.pack("<QQ", int(t["partial"]["lot_count"]), int(t["partial"]["min_lot"]))
    return o + bytes.fromhex(t["trade_ref"])

def H(key, msg): return hashlib.blake2b(msg, digest_size=32, key=key).hexdigest()

files = sorted(pathlib.Path(sys.argv[1]).glob("*.json"))
if not files:
    sys.exit("no linked vectors")
for f in files:
    v = json.loads(f.read_text())
    b = bytes.fromhex(v["canonical"])
    r = R(b)
    if r.u8() != 1: sys.exit(f"{f}: link_version")
    n = r.u16()
    opening_bytes = r.take(n)
    opening = decode_terms(opening_bytes)
    amounts = [r.d64(), r.d64()]
    earliest, expiry = r.d64(), r.d64()
    if r.p != len(b): sys.exit(f"{f}: trailing bytes")
    sheet = {"link_version": 1, "opening": opening, "return_amounts": amounts,
             "return_earliest_daa": earliest, "return_expiry_daa": expiry}
    if json.dumps(sheet) != json.dumps(v["sheet"]):
        sys.exit(f"{f}: canonical bytes do not decode to the sheet object")
    linked = H(b"Impulse/terms/v2/linked", b)
    if linked != v["linked_hash"]: sys.exit(f"{f}: linked_hash")
    # 17.4 checks the vectors must satisfy.
    if len(opening["legs"]) != 2 or opening["partial"] is not None: sys.exit(f"{f}: not a bilateral, non-partial opening")
    if opening["trade_ref"] != "00" * 32: sys.exit(f"{f}: the sheet's opening trade_ref is not zero")
    if int(earliest) <= int(opening["expiry_daa"]): sys.exit(f"{f}: return earliest not above the opening expiry")
    # 17.3: the opening, with the hash written into trade_ref.
    derived_open = dict(opening, trade_ref=linked)
    # 17.3: the return, leg by leg.
    legs = []
    for i in (0, 1):
        o, j = opening["legs"][i], opening["legs"][1 - i]
        legs.append({"depositor_key": j["depositor_key"],
                     "asset": dict(o["asset"], amount=amounts[i]),
                     "delivery": o["refund"], "refund": o["delivery"]})
    derived_ret = {"version": 2, "network": opening["network"], "nonce": opening["nonce"],
                   "authority_key": opening["authority_key"], "legs": legs,
                   "earliest_daa": earliest, "expiry_daa": expiry,
                   "funding_mode": opening["funding_mode"], "partial": None, "trade_ref": linked}
    for key, d in (("opening_trade", derived_open), ("return_trade", derived_ret)):
        c = encode_terms(d)
        if c.hex() != v[key]["canonical"]: sys.exit(f"{f}: {key} canonical bytes differ from the derivation")
        if json.dumps(decode_terms(c)) != json.dumps(v[key]["terms"]): sys.exit(f"{f}: {key} terms object")
        if H(b"Impulse/terms/v2", c) != v[key]["terms_hash"]: sys.exit(f"{f}: {key} terms_hash")
    if v["opening_trade"]["terms_hash"] == v["return_trade"]["terms_hash"]: sys.exit(f"{f}: the two trades share a hash")
print(f"vectors: {len(files)} linked vectors, sheets, derivations and hashes recomputed independently")
EOF

echo "vectors: frozen against $base_ref, regenerated, empty diff"
