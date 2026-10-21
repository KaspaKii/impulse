#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# usage: template-check.sh <silverc binary> <repo dir>
# Same compile and checks as scripts/build-template.sh (check mode), for a given silverc.
set -euo pipefail
silverc=$1; repo=$2
cd "$repo"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
"$silverc" contracts/impulse_vault.sil --constructor-args contracts/compiled/impulse_vault.v1.ctor.json -o "$tmp/artifact.json"
hash=$(python3 -I - "$tmp/artifact.json" <<'PY'
import json, sys
artifact = json.load(open(sys.argv[1]))
compiled = artifact["contracts"]["ImpulseVault"]["compiled"]
code, span = compiled["bytecode"], compiled["state_span"]
print(bytes(compiled["template_hash"]).hex())
print("ImpulseVault: %d bytes, template prefix %d, state %d, suffix %d" % (len(code), span["offset"], span["len"], len(code) - span["offset"] - span["len"]), file=sys.stderr)
PY
)
echo "silverc sha256 $(shasum -a 256 "$silverc" | cut -d' ' -f1)"
echo "artifact sha256 $(shasum -a 256 "$tmp/artifact.json" | cut -d' ' -f1)"
echo "committed artifact sha256 $(shasum -a 256 contracts/compiled/impulse_vault.v1.json | cut -d' ' -f1)"
cmp "$tmp/artifact.json" contracts/compiled/impulse_vault.v1.json && echo "artifact byte-identical to the committed artifact"
echo "TEMPLATE_HASH compiled   $hash"
echo "TEMPLATE_HASH committed  $(cat contracts/TEMPLATE_HASH)"
[ "$hash" = "$(cat contracts/TEMPLATE_HASH)" ] && echo "TEMPLATE_HASH matches"
