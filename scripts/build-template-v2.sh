#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Compile contracts/impulse_vault_v2.sil with silverc built from the pinned silverscript v1.0.0,
# then check the committed artifact and contracts/TEMPLATE_HASH_V2. Fails closed on any mismatch.
# The v1 template is checked by scripts/build-template.sh, which this script does not touch.
#
#   scripts/build-template-v2.sh            check (CI)
#   scripts/build-template-v2.sh --update   rewrite the v2 artifact and TEMPLATE_HASH_V2; only in an
#                                           change whose purpose is to change the v2 contract
#
# The terms are the contract state, so the template (the bytecode outside the state span) and
# its hash do not depend on the constructor values, the leg count included. The committed
# artifact is compiled from the placeholder values in contracts/compiled/impulse_vault.v2.ctor.json.
# The source carries its own template layout ([S10] rebuilds a sibling's redeem script from it):
# PREFIX_LEN, STATE_FIXED and SUFFIX_LEN must equal the compiled layout, or every settle fails.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "build-template-v2: FAIL: $1" >&2; exit 1; }

SS_GIT=https://github.com/kaspanet/silverscript
SS_TAG=v1.0.0
SS_REV=3ed973335b59269293564805cc2c58a14595ec03
SRC=contracts/impulse_vault_v2.sil
CTOR=contracts/compiled/impulse_vault.v2.ctor.json
ARTIFACT=contracts/compiled/impulse_vault.v2.json
HASH_FILE=contracts/TEMPLATE_HASH_V2

update=0
case "${1:-}" in
  "") ;;
  --update) update=1 ;;
  *) fail "unknown argument: $1" ;;
esac

# silverc from the pinned tag (the same install root as scripts/build-template.sh).
root=target/silverc-$SS_TAG
cargo install --quiet --locked --git "$SS_GIT" --tag "$SS_TAG" silverscript-lang --bin silverc --root "$root"
silverc=$root/bin/silverc
[ -x "$silverc" ] || fail "silverc was not built"
grep -qF "\"silverscript-lang 1.0.0 (git+$SS_GIT?tag=$SS_TAG#$SS_REV)\"" "$root/.crates2.json" \
  || fail "silverc in $root is not silverscript-lang 1.0.0 at $SS_REV"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
"$silverc" "$SRC" --constructor-args "$CTOR" -o "$tmp/artifact.json"

hash=$(python3 - "$tmp/artifact.json" "$SRC" "$CTOR" <<'PY'
import json, re, sys
artifact = json.load(open(sys.argv[1]))
source = open(sys.argv[2]).read()
ctor = json.load(open(sys.argv[3]))
contracts = artifact["contracts"]
if list(contracts) != ["ImpulseVaultV2"]:
    sys.exit("expected exactly one contract, ImpulseVaultV2, got %s" % list(contracts))
compiled = contracts["ImpulseVaultV2"]["compiled"]
code, span = compiled["bytecode"], compiled["state_span"]
prefix, suffix = span["offset"], len(code) - span["offset"] - span["len"]
def const(name):
    m = re.search(r"^\s*int constant %s = (\d+);" % name, source, re.M)
    if not m:
        sys.exit("constant %s missing from the source" % name)
    return int(m.group(1))
legs = len(ctor[6]["value"])
for name, actual in (("PREFIX_LEN", prefix), ("STATE_FIXED", span["len"] - legs), ("SUFFIX_LEN", suffix)):
    if const(name) != actual:
        sys.exit("%s is %d in the source, the compiled template has %d" % (name, const(name), actual))
print(bytes(compiled["template_hash"]).hex())
print("ImpulseVaultV2: %d bytes, template prefix %d, state %d (%d of legs), suffix %d" % (len(code), prefix, span["len"], legs, suffix), file=sys.stderr)
PY
)
[ ${#hash} -eq 64 ] || fail "could not read the template hash"

if [ "$update" -eq 1 ]; then
  cp "$tmp/artifact.json" "$ARTIFACT"
  echo "$hash" > "$HASH_FILE"
  echo "build-template-v2: updated $ARTIFACT and $HASH_FILE ($hash)"
  exit 0
fi

[ -f "$ARTIFACT" ] || fail "$ARTIFACT missing"
[ -f "$HASH_FILE" ] || fail "$HASH_FILE missing"
cmp -s "$tmp/artifact.json" "$ARTIFACT" || fail "$ARTIFACT differs from the pinned silverc output"
[ "$(cat "$HASH_FILE")" = "$hash" ] || fail "TEMPLATE_HASH_V2 $(cat "$HASH_FILE") does not match the compiled template $hash"
echo "build-template-v2: ok, TEMPLATE_HASH_V2 $hash"
