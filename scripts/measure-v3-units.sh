#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Measures template v3 in the pinned engine (spec/V3-ZK.md 13.3) and writes
# docs/measurements/v3-zk-units.txt with the date, commit and command. Run on the committed
# proof fixtures; figures are quoted only from the file this writes.
set -euo pipefail
cd "$(dirname "$0")/.."
out=docs/measurements/v3-zk-units.txt
mkdir -p docs/measurements
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
cmd="IMPULSE_V3_UNITS_OUT=<file> cargo test -p impulse-engine-tests --test v3_measure -- --nocapture"
IMPULSE_V3_UNITS_OUT="$tmp" cargo test -p impulse-engine-tests --test v3_measure -- --nocapture >/dev/null 2>&1 \
  || { IMPULSE_V3_UNITS_OUT="$tmp" cargo test -p impulse-engine-tests --test v3_measure -- --nocapture; exit 1; }
{
  echo "Template v3 measurements in the pinned engine (kaspa-txscript at rusty-kaspa a41a333, covenants enabled, mainnet parameters)"
  echo "date: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "commit: $(git rev-parse --short HEAD) (working tree $(git status --porcelain -- contracts tests/engine | wc -l | tr -d ' ') changed paths under contracts and tests/engine)"
  echo "template v3 hash: $(cat contracts/TEMPLATE_HASH_V3)"
  echo "image ID: $(cat circuits/IMAGE_ID)"
  echo "machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
  echo "command: $cmd (scripts/measure-v3-units.sh)"
  echo "method: tests/engine/v3_measure.rs, header comment"
  echo
  cat "$tmp"
} > "$out"
echo "wrote $out"
