#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# scripts/check-zk-text.sh: the wording rules of spec/V3-ZK.md section 9.5 and the figures rule of
# section 10, enforced on the user-facing text of v3 (I20).
#
#   scripts/check-zk-text.sh              check the repository
#   scripts/check-zk-text.sh --self-test  feed the checker one sample of each banned phrase and one
#                                         missing fixed text and expect a failure for each
#   [--impulse <binary>]                  use this CLI (built with the `zk` feature) instead of
#                                         building one
#
# In scope: the README's v3 section (between <!-- impulse-v3 --> and <!-- /impulse-v3 -->), the
# output of `impulse zk --help` and of --help for every `impulse zk` subcommand, the output of the
# `impulse zk` commands that run offline on the golden vectors and on a list made for the check,
# and docs/ZK-*.md. spec/ is not in scope: a specification must be able to name what it rules out.
#
# It fails on: a banned phrase outside the fixed texts; a missing fixed text; a number of four or
# more characters (digits, commas, points) that is none of: in docs/measurements/v3-zk-units.txt
# or docs/evidence/i20-proving-*/results.txt, a design constant (1048576, the entry bound), an
# echo of a value the check itself gave a command (an amount, a DAA score or a count in its
# inputs), or on a line the CLI prints about the transaction it just built (the per-transaction
# facts named in TX_LINES below: inputs, outputs, fee, change, lock time).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"
mode=check impulse=
while [ $# -gt 0 ]; do
  case "$1" in
    --self-test) mode=self-test; shift ;;
    --impulse) impulse=$2; shift 2 ;;
    *) echo "usage: $0 [--self-test] [--impulse <binary>]" >&2; exit 2 ;;
  esac
done

checker() { python3 -I - "$@" <<'PY'
import re, sys, pathlib

DISCLAIMER = "Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain."
SETUP = "The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified."
CAPLINE = "Template v3 and the list prover are for values at or below the 10 KAS cap. Above it the tools refuse unless --i-accept-the-risk is passed."
GATE = "Only the asset vault checks the proof. The cash vault settles only beside the asset vault of the same terms, so verify both vault addresses before funding cash."
FIXED = {DISCLAIMER, SETUP, CAPLINE, GATE}
# Banned, case-insensitive, outside the fixed texts (spec 9.5). "private" is allowed in "private key".
BANNED = [
    r"private(?! key)", r"anonymous", r"anonymity", r"hidden member", r"hides the member",
    r"confidential", r"compliant", r"compliance", r"\bKYC\b", r"\bAML\b", r"sanction",
    r"whitelist", r"trustless", r"cryptographically enforced", r"verified identity",
]
# Numbers that are design constants: the entry bound of the list tree (spec section 5.1) and the
# per-trade value cap of the contract, 10 KAS in sompi (decision D4).
DESIGN = {"1048576", "1,048,576", "1000000000"}
# Lines the CLI prints about the transaction it just built, from the inputs it was given and the
# pinned mass calculator: a fact of that transaction, not a figure of the design.
TX_LINES = re.compile(r"^(input \d+:|output \d+:|fee:|change:|payer cost|lock_time:|txid:|you commit:|"
                      r"token change:|wrote:|from_block:|submitted:|signed_tx:)")
NUMBER = re.compile(r"(?<![0-9A-Za-z_.:/\-])[0-9][0-9,.]{3,}(?![0-9A-Za-z_]|-[0-9])")
KAS = re.compile(r"^([0-9]+)\.([0-9]{8})$")

def figures_allowed(root):
    allowed = set(DESIGN)
    files = [root / "docs/measurements/v3-zk-units.txt"] + sorted((root / "docs/evidence").glob("i20-proving-*/results.txt"))
    for f in files:
        if f.is_file():
            allowed.update(m.group(0) for m in NUMBER.finditer(f.read_text()))
    return allowed

def scan(name, text, allowed, echoed):
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip() in FIXED:
            continue
        for pat in BANNED:
            if re.search(pat, line, re.I):
                problems.append(f"{name}:{n}: banned phrase /{pat}/: {line.strip()[:100]}")
        if TX_LINES.match(line.strip()):
            continue
        for m in NUMBER.finditer(line):
            tok = m.group(0).rstrip(".,")
            kas = KAS.match(tok)
            if kas and str(int(kas.group(1)) * 10**8 + int(kas.group(2))) in echoed | allowed:
                continue  # a KAS amount with eight places, the rendering of an echoed sompi amount
            if len(tok) >= 4 and tok not in allowed and tok not in echoed:
                problems.append(f"{name}:{n}: unsourced figure {tok}: {line.strip()[:100]}")
    return problems

def require(name, text, needed):
    lines = {l.strip() for l in text.splitlines()}
    return [f"{name}: missing fixed text: {t[:60]}..." for t in needed if t not in lines]

def run(root, texts, echoed_file):
    """texts: name -> (text, fixed texts it must carry)."""
    allowed = figures_allowed(root)
    echoed = set()
    if echoed_file and pathlib.Path(echoed_file).is_file():
        echoed = {m.group(0).rstrip(".,") for m in NUMBER.finditer(pathlib.Path(echoed_file).read_text())}
    problems = []
    for name, (text, needed) in sorted(texts.items()):
        problems += require(name, text, needed)
        problems += scan(name, text, allowed, echoed)
    return problems

def load(dirpath):
    d = pathlib.Path(dirpath)
    texts = {}
    needs = {  # a file name prefix -> the fixed texts it must carry
        "readme": [DISCLAIMER, SETUP, CAPLINE, GATE],
        "help-zk.txt": [DISCLAIMER, SETUP, GATE],
        "out-verify": [DISCLAIMER, SETUP, GATE],
    }
    for f in sorted(d.glob("*")):
        if f.name == "echoed.txt":
            continue
        need = []
        for prefix, t in needs.items():
            if f.name.startswith(prefix):
                need = t
        texts[f.name] = (f.read_text(), need)
    return texts

mode = sys.argv[1]
if mode == "check":
    root = pathlib.Path(sys.argv[2])
    problems = run(root, load(sys.argv[3]), pathlib.Path(sys.argv[3]) / "echoed.txt")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"check-zk-text: {len(load(sys.argv[3]))} texts clean")
elif mode == "self-test":
    root = pathlib.Path(sys.argv[2])
    clean = {"readme.md": (f"{DISCLAIMER}\n{SETUP}\n{CAPLINE}\n{GATE}\nA list-gated settle.\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}
    assert run(root, clean, None) == [], "the clean sample must pass"
    samples = ["this is private", "anonymous", "anonymity", "a hidden member", "it hides the member", "confidential",
               "compliant", "compliance", "KYC", "AML", "a sanction", "the whitelist", "trustless", "cryptographically enforced",
               "verified identity", "PRIVATE data"]
    failed = 0
    for s in samples:
        texts = {"readme.md": (f"{DISCLAIMER}\n{SETUP}\n{CAPLINE}\n{GATE}\n{s}\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}
        if not run(root, texts, None):
            print(f"self-test: banned sample not caught: {s}", file=sys.stderr); failed += 1
    # "private key" is allowed, and the fixed texts may hold the words the rules ban.
    ok = {"readme.md": (f"{DISCLAIMER}\n{SETUP}\n{CAPLINE}\n{GATE}\nA private key never leaves the signer.\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}
    if run(root, ok, None):
        print("self-test: 'private key' was refused", file=sys.stderr); failed += 1
    # A missing fixed text, one of each.
    for drop in (DISCLAIMER, SETUP, CAPLINE, GATE):
        body = "\n".join(t for t in (DISCLAIMER, SETUP, CAPLINE, GATE) if t != drop)
        if not run(root, {"readme.md": (body + "\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}, None):
            print(f"self-test: a missing fixed text was not caught: {drop[:40]}", file=sys.stderr); failed += 1
    # An unsourced figure, a sourced one and a design constant.
    base = f"{DISCLAIMER}\n{SETUP}\n{CAPLINE}\n{GATE}\n"
    if not run(root, {"readme.md": (base + "Proving takes 187 seconds and costs 15500000 units.\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}, None):
        print("self-test: an unsourced figure was not caught", file=sys.stderr); failed += 1
    if run(root, {"readme.md": (base + "A list holds up to 1048576 entries.\n", [DISCLAIMER, SETUP, CAPLINE, GATE])}, None):
        print("self-test: a design constant was refused", file=sys.stderr); failed += 1
    if failed:
        sys.exit(1)
    print(f"check-zk-text: self-test passed ({len(samples) + 9} cases)")
PY
}

if [ "$mode" = self-test ]; then
  checker self-test "$repo"
  exit $?
fi

# ---- collect the in-scope text ------------------------------------------------------------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
mkdir "$work/texts"
t="$work/texts"
if [ -z "$impulse" ]; then
  cargo build --locked -q -p impulse-cli --features zk --manifest-path "$repo/Cargo.toml" --target-dir "$repo/target/zk-text"
  impulse="$repo/target/zk-text/debug/impulse"
fi

# The README section.
if ! grep -q '<!-- impulse-v3 -->' README.md; then
  echo "check-zk-text: README.md has no v3 section (<!-- impulse-v3 --> ... <!-- /impulse-v3 -->)" >&2
  exit 1
fi
sed -n '/<!-- impulse-v3 -->/,/<!-- \/impulse-v3 -->/p' README.md > "$t/readme-v3.md"
for f in docs/ZK-*.md; do [ -e "$f" ] && cp "$f" "$t/doc-$(basename "$f")"; done

# Help of every `impulse zk` command, found from the help itself.
helps() { # words...
  local text
  text=$("$impulse" "$@" --help 2>&1) || true
  printf '%s\n' "$text"
  printf '%s\n' "$text" | awk '/^Commands:/{f=1;next} /^$/{f=0} f && $1 != "help" {print $1}' | while read -r sub; do
    [ -n "$sub" ] && helps "$@" "$sub"
  done
}
helps zk > "$t/help-zk.txt"

# The commands that run offline, on the golden vectors and on a list made for the check.
echoed="$t/echoed.txt"
: > "$echoed"
in="$work/in"
mkdir "$in"
# The trade the check runs the commands on: the pinned-template trade impulse-core commits its
# end-to-end proof for, decoded from its canonical bytes and moved to testnet (the text, not the
# trade, is under test).
python3 -I - "$in" <<'PY'
import importlib.util, json, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("vz", "scripts/vectors-zk.py")
vz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vz)
raw = open("crates/impulse-core/src/zk/testdata/e2e-selfsettle.terms.hex").read().strip()
t = vz.decode_v3(bytes.fromhex(raw))
issuer, root = t.pop("list_issuer_key"), t.pop("list_root")
t["network"] = "testnet"
json.dump(t, open(sys.argv[1] + "/draft.json", "w"))
open(sys.argv[1] + "/issuer", "w").write(issuer)
open(sys.argv[1] + "/root", "w").write(root)
open(sys.argv[1] + "/seller", "w").write(t["seller_key"])
PY
cat "$in/draft.json" >> "$echoed"
issuer=$(cat "$in/issuer") root=$(cat "$in/root") seller=$(cat "$in/seller")
party=(--role seller --my-key "$seller" --kas-equivalent 100000000)
DAA=1500000
echo "$DAA 100000000" >> "$echoed"  # the values the commands below are given

cat > "$in/list.txt" <<EOL
pubkey:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
pubkey:$seller
EOL
cat "$in/list.txt" >> "$echoed"
run() { local name=$1; shift; "$impulse" --network testnet zk "$@" > "$t/out-$name.txt" 2>&1 || { echo "check-zk-text: impulse zk $* failed:" >&2; cat "$t/out-$name.txt" >&2; exit 1; }; }
run list-build list build --list "$in/list.txt" --out-dir "$in/paths"
root_made=$(sed -n 's/^list root: //p' "$t/out-list-build.txt")
run list-manifest list manifest --root "$root_made" --list-id check --list-version 1 --issued-at 1760000000
run terms-new terms new --draft "$in/draft.json" --list-issuer-key "$issuer" --list-root "$root" --daa $DAA \
  --no-authority --out "$in/terms.json" "${party[@]}"
run address address --terms "$in/terms.json" --daa $DAA "${party[@]}"
asset=$(sed -n 's/^asset vault: //p' "$t/out-address.txt" | head -n 1)
cash=$(sed -n 's/^cash vault: //p' "$t/out-address.txt" | head -n 1)
run verify verify --terms "$in/terms.json" --asset-address "$asset" --cash-address "$cash" --daa $DAA "${party[@]}"
run prove-args prove-args --terms "$in/terms.json"
cat "$in/terms.json" >> "$echoed"

checker check "$repo" "$t"
