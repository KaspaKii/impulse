#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Measures template v4 in the pinned engine (spec/V3-ZK.md 22.10) and writes
# docs/measurements/v4-zk-units.txt with the date, commit and commands. Needs Docker and the
# built prover: it makes the real receipts of tests/engine/v4_live.rs (minutes each). Script sizes
# come from the pinned silverc's artifacts; units and masses from the engine runs of the receipts.
# Figures are quoted only from the file this writes.
set -euo pipefail
cd "$(dirname "$0")/.."
out=docs/measurements/v4-zk-units.txt
mkdir -p docs/measurements
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
: > "$tmp"
cmd="IMPULSE_V4_UNITS_OUT=<file> cargo test -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1 --nocapture"
# Without Docker (the Groth16 prover needs it) and without a ready file, the real-receipt part is
# marked pending and the file holds the sizes and the probe units only (nothing is estimated).
probe=$(mktemp); trap 'rm -f "$tmp" "$probe"' EXIT
IMPULSE_V4_PROBE_OUT="$probe" cargo test --locked -q -p impulse-engine-tests --test v4_script v4_probe_units >/dev/null 2>&1 \
  || { echo "measure-v4-units: the probe measurement failed" >&2; exit 1; }
massf=$(mktemp); trap 'rm -f "$tmp" "$probe" "$massf"' EXIT
IMPULSE_V4_MASS_OUT="$massf" cargo test --locked -q -p impulse-core --features zk-hashed --lib builder_plan_masses >/dev/null 2>&1 \
  || { echo "measure-v4-units: the builder mass measurement failed" >&2; exit 1; }
live=real
if [ -z "${IMPULSE_V4_UNITS_FROM:-}" ] && { [ -n "${IMPULSE_V4_PROBE_ONLY:-}" ] || ! command -v docker >/dev/null 2>&1; }; then
  live=pending
  echo "REAL-RECEIPT MEASUREMENT PENDING: Docker is not available on this machine, so the units of an input with a real receipt, the transaction masses and the proving times are not measured. Run scripts/ci-zk.sh (or this script) on a machine with Docker." > "$tmp"
elif [ -n "${IMPULSE_V4_UNITS_FROM:-}" ]; then
  # scripts/ci-zk.sh runs the real-receipt tests once with IMPULSE_V4_UNITS_OUT set and hands the
  # file here, so the receipts are not proved twice.
  cp "$IMPULSE_V4_UNITS_FROM" "$tmp"
else
  (cd circuits && source scripts/env.sh && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)
  IMPULSE_V4_UNITS_OUT="$tmp" cargo test --locked -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1 --nocapture >/dev/null 2>&1 \
    || { IMPULSE_V4_UNITS_OUT="$tmp" cargo test --locked -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1 --nocapture; exit 1; }
fi
sizes=$(python3 -I - <<'PY'
import json
def size(p, name):
    c = json.load(open(p))["contracts"][name]["compiled"]
    return len(c["bytecode"])
v1 = size("contracts/compiled/impulse_vault.v1.json", "ImpulseVault")
v3 = size("contracts/compiled/impulse_vault.v3.json", "ImpulseVaultV3")
v4 = size("contracts/compiled/impulse_vault.v4.json", "ImpulseVaultV4")
print("Template sizes (bytes, compiled artifacts with the placeholder state):")
print("  template v1 %d, template v3 %d, template v4 %d" % (v1, v3, v4))
print("  v4 against v1: %+d bytes, ratio %.3f; v4 against v3: %+d bytes, ratio %.3f" % (v4 - v1, v4 / v1, v4 - v3, v4 / v3))
PY
)
{
  echo "Template v4 measurements in the pinned engine (kaspa-txscript at rusty-kaspa a41a333, covenants enabled, mainnet parameters)"
  echo "date: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "commit: $(git rev-parse --short HEAD) (working tree $(git status --porcelain -- contracts tests/engine circuits | wc -l | tr -d ' ') changed paths under contracts, tests/engine and circuits)"
  echo "template v4 hash: $(cat contracts/TEMPLATE_HASH_V4)"
  echo "image ID (terms guest): $(cat circuits/IMAGE_ID_V4)"
  echo "silverc: silverscript-lang 1.0.0, tag v1.0.0 (commit 3ed973335b59269293564805cc2c58a14595ec03), command: silverc contracts/impulse_vault_v4.sil --constructor-args contracts/compiled/impulse_vault.v4.ctor.json -o <artifact> (scripts/build-template-v4.sh)"
  echo "machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
  echo "command: $cmd (scripts/measure-v4-units.sh); real-receipt part: $live"
  echo "method: the probe table is tests/engine/v4_script.rs v4_probe_units (used_script_units() of an unbounded run of each accepted input); the rest is tests/engine/v4_live.rs; units are used_script_units() of an unbounded run of each accepted input with a real receipt; v1 is the same trade shape on template v1 with random throwaway keys; budgets are the smallest covering the units; masses are MassCalculator under mainnet parameters at exact covering budgets"
  echo
  echo "$sizes"
  echo
  echo "Script units per vault input, probe build (the verify call replaced by a comparison of sha256(J) with the proof), against template v1 on the same shape. The probe holds everything except the gate; the gate adds the precompile's fixed cost on top (below)."
  cat "$probe"
  echo
  echo "Masses and relay fee of the plans the v4 builders make (impulse-core builder_plan_masses: the fixture world of the builders' tests, the vault input budgets the builders commit, mainnet parameters, the fee at the relay minimum of 100 sompi per gram of fee mass). Storage mass depends on the values of the UTXOs; these are the minimum values the builders accept, so a larger value only lowers it:"
  cat "$massf"
  echo
  cat "$tmp"
  echo
  echo "MASS lines above: the engine harness's world, whose UTXO values are artificially small, so its storage mass is not representative; the compute and transient masses there are those of the shape at exact covering budgets. The plans of the v4 builders (table above) are the representative masses, asserted against all three caps."
  echo "Proof gate: the precompile costs 14,000,000 units fixed and 250,000 for each of the six elements of the verifying key, 15,500,000 in all (V3-ZK.md 3.4); the same fragment and key as v3; each vault input of a settle carries its own verification. The PROVE lines are the prover's own timings for that receipt on this machine while other work was running (a checkpoint run on an idle machine is docs/evidence/i21-proving-<date>/)."
} > "$out"
echo "wrote $out"
