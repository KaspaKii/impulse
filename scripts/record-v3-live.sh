#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Writes tests/engine/v3-live-run.txt after the two real-proof authority settle tests passed
# (scripts/ci-zk.sh runs them and then this). Records the sha256 of everything the tests depend
# on, so scripts/check-v3-live-record.sh can tell a stale record from a current one.
set -euo pipefail
cd "$(dirname "$0")/.."
out=tests/engine/v3-live-run.txt
{
  echo "Real-proof authority settles on the shipped template v3 (tests/engine/v3_live.rs)"
  echo "run by scripts/ci-zk.sh: cargo test -p impulse-engine-tests --test v3_live -- --ignored --test-threads=1"
  for f in contracts/impulse_vault_v3.sil circuits/IMAGE_ID tests/engine/v3_live.rs tests/engine/harness.rs tests/engine/v3_common.rs circuits/GROTH16_PROVER_IMAGE; do
    echo "sha256 $f $(shasum -a 256 "$f" | cut -d' ' -f1)"
  done
  echo "tests passed: 2"
  echo "date $(date -u +%Y-%m-%d)"
} > "$out"
echo "wrote $out"
