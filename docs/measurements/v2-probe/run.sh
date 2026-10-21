#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Feasibility probes for spec/V2.md. Compiles each probe with the pinned silverc (silverscript
# v1.0.0, 3ed9733, installed by scripts/build-template.sh under target/silverc-v1.0.0) and prints
# bytecode, state and template suffix sizes. The probes are not templates and are never deployed.
#   docs/measurements/v2-probe/run.sh > docs/measurements/v2-probe/results.txt
# SILVERC_ROOT names another install root of the same pinned silverc (checked by provenance).
set -euo pipefail
cd "$(dirname "$0")"
root=${SILVERC_ROOT:-../../../target/silverc-v1.0.0}
silverc=$root/bin/silverc
[ -x "$silverc" ] || { echo "run scripts/build-template.sh first, or set SILVERC_ROOT" >&2; exit 1; }
grep -qF "silverscript-lang 1.0.0 (git+https://github.com/kaspanet/silverscript?tag=v1.0.0#3ed973335b59269293564805cc2c58a14595ec03)" "$root/.crates2.json" \
  || { echo "silverc in $root is not silverscript-lang 1.0.0 at 3ed9733" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sizes() {
  python3 - "$1" "$2" <<'PY'
import json, sys
a = json.load(open(sys.argv[2]))
c = list(a["contracts"].values())[0]["compiled"]
s = c["state_span"]; b = len(c["bytecode"])
print("%s: bytecode %d, prefix %d, state %d, suffix %d" % (sys.argv[1], b, s["offset"], s["len"], b - s["offset"] - s["len"]))
PY
}
echo "silverc: silverscript-lang 1.0.0 at 3ed9733"
for m in 2 4 10 16; do
  sed "s/@MAX@/$m/" vault_v2_probe.sil.in > "$tmp/v.sil"
  "$silverc" "$tmp/v.sil" --constructor-args vault_v2_probe.ctor.json -o "$tmp/v.json"
  sizes "vault_v2_probe MAX_LEGS=$m (state for N=3)" "$tmp/v.json"
done
"$silverc" hashlock_probe.sil --constructor-args hashlock_probe.ctor.json -o "$tmp/h.json"
sizes "hashlock_probe" "$tmp/h.json"
"$silverc" int_cast_probe.sil --constructor-args int_cast_probe.ctor.json -o "$tmp/i.json"
python3 - "$tmp/i.json" <<'PY'
import json, sys
c = list(json.load(open(sys.argv[1]))["contracts"].values())[0]["compiled"]
print("int_cast_probe bytecode: " + bytes(c["bytecode"]).hex())
PY
echo "continuation_state_probe (expected to fail):"
"$silverc" continuation_state_probe.sil --constructor-args continuation_state_probe.ctor.json -o "$tmp/c.json" 2>&1 || true
