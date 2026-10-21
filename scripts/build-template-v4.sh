#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Compile contracts/impulse_vault_v4.sil with silverc built from the pinned silverscript v1.0.0,
# then check the committed artifact and contracts/TEMPLATE_HASH_V4. Fails closed on any mismatch.
#
#   scripts/build-template-v4.sh            check (CI)
#   scripts/build-template-v4.sh --update   rewrite the artifact and TEMPLATE_HASH_V4; only in an
#                                        change whose purpose is to change the contract
#
# The v1 and v3 templates are checked by their own scripts, which this script does not touch.
# The terms are the contract state, so the template (the bytecode outside the state span) and
# its hash do not depend on the constructor values. The committed artifact is compiled from the
# placeholder values in contracts/compiled/impulse_vault.v4.ctor.json.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "build-template-v4: FAIL: $1" >&2; exit 1; }

SS_GIT=https://github.com/kaspanet/silverscript
SS_TAG=v1.0.0
SS_REV=3ed973335b59269293564805cc2c58a14595ec03
SRC=contracts/impulse_vault_v4.sil
CTOR=contracts/compiled/impulse_vault.v4.ctor.json
ARTIFACT=contracts/compiled/impulse_vault.v4.json
HASH_FILE=contracts/TEMPLATE_HASH_V4
IMAGE_FILE=circuits/IMAGE_ID_V4

update=0
case "${1:-}" in
  "") ;;
  --update) update=1 ;;
  *) fail "unknown argument: $1" ;;
esac

# silverc from the pinned tag, built with silverscript's own lock file. cargo reuses an
# existing install of the same source. Set CARGO_NET_OFFLINE=true to build from the git cache.
root=target/silverc-$SS_TAG
cargo install --quiet --locked --git "$SS_GIT" --tag "$SS_TAG" silverscript-lang --bin silverc --root "$root"
silverc=$root/bin/silverc
[ -x "$silverc" ] || fail "silverc was not built"
# Provenance: the installed binary must come from the pinned commit.
grep -qF "\"silverscript-lang 1.0.0 (git+$SS_GIT?tag=$SS_TAG#$SS_REV)\"" "$root/.crates2.json" \
  || fail "silverc in $root is not silverscript-lang 1.0.0 at $SS_REV"

# IMAGE_ID in the source must equal circuits/IMAGE_ID_V4 (spec/V4-ZK.md 6.1).
[ -f "$IMAGE_FILE" ] || fail "$IMAGE_FILE missing"
img=$(tr -d '[:space:]' < "$IMAGE_FILE")
grep -qF "IMAGE_ID = byte[32](0x$img);" "$SRC" || fail "IMAGE_ID in $SRC differs from $IMAGE_FILE"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$silverc" "$SRC" --constructor-args "$CTOR" -o "$tmp/artifact.json"

hash=$(python3 - "$tmp/artifact.json" <<'PY'
import json, sys
artifact = json.load(open(sys.argv[1]))
contracts = artifact["contracts"]
if list(contracts) != ["ImpulseVaultV4"]:
    sys.exit("expected exactly one contract, ImpulseVaultV4, got %s" % list(contracts))
compiled = contracts["ImpulseVaultV4"]["compiled"]
code, span = compiled["bytecode"], compiled["state_span"]
prefix, suffix = span["offset"], len(code) - span["offset"] - span["len"]
print(bytes(compiled["template_hash"]).hex(), file=sys.stdout)
print("ImpulseVaultV4: %d bytes, template prefix %d, state %d, suffix %d" % (len(code), prefix, span["len"], suffix), file=sys.stderr)
PY
)
[ ${#hash} -eq 64 ] || fail "could not read the template hash"

if [ "$update" -eq 1 ]; then
  cp "$tmp/artifact.json" "$ARTIFACT"
  echo "$hash" > "$HASH_FILE"
  echo "build-template-v4: updated $ARTIFACT and $HASH_FILE ($hash)"
  exit 0
fi

[ -f "$ARTIFACT" ] || fail "$ARTIFACT missing"
[ -f "$HASH_FILE" ] || fail "$HASH_FILE missing"
cmp -s "$tmp/artifact.json" "$ARTIFACT" || fail "$ARTIFACT differs from the pinned silverc output"
[ "$(cat "$HASH_FILE")" = "$hash" ] || fail "TEMPLATE_HASH $(cat "$HASH_FILE") does not match the compiled template $hash"
echo "build-template-v4: ok, TEMPLATE_HASH $hash"
