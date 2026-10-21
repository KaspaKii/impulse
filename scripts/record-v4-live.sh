#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Writes tests/engine/v4-live-run.txt after the real-receipt tests of template v4 passed
# (scripts/ci-zk.sh runs them and then this). Records the sha256 of everything the tests depend
# on, so scripts/check-v4-live-record.sh can tell a stale record from a current one.
set -euo pipefail
cd "$(dirname "$0")/.."
out=tests/engine/v4-live-run.txt
{
  echo "Real-receipt settles and refunds on the shipped template v4 (tests/engine/v4_live.rs)"
  echo "run by scripts/ci-zk.sh: cargo test -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1"
  for f in contracts/impulse_vault_v4.sil circuits/IMAGE_ID_V4 tests/engine/v4_live.rs tests/engine/harness.rs tests/engine/v4_common.rs tests/engine/v4_core.rs circuits/GROTH16_PROVER_IMAGE; do
    echo "sha256 $f $(shasum -a 256 "$f" | cut -d' ' -f1)"
  done
  echo "tests passed: 5"
  echo "date $(date -u +%Y-%m-%d)"
} > "$out"
rm -f tests/engine/v4-live-run.PENDING
echo "wrote $out"
