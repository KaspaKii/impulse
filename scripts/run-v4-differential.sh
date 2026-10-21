#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# The differential of spec/V3-ZK.md 22.9 (`v4_differential_agrees_with_v1`): every valid and invalid
# vector of the v1 settle, refund, lock-time and escrow-release suites is run again as the test
# binaries v4d_* (the same files, tests/engine/Cargo.toml), and each run of a v1 vault input is also
# put through the statement of terms-core (tests/engine/v4_core.rs, `shadow_check`). The statement
# must accept exactly when v1's script accepts, up to the checks the v4 script keeps ([S6], [R2]
# and the lock-time finality of the spending input); a divergence panics the test. Writes the count
# of comparisons to tests/engine/v4-differential-run.txt. The same binaries also run in
# `cargo test --workspace`, where the check is on without the log.
set -euo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp); trap 'rm -f "$log"' EXIT
IMPULSE_V4_SHADOW_LOG="$log" cargo test --locked --no-fail-fast -p impulse-engine-tests \
  --test v4d_settle --test v4d_refund --test v4d_locktime --test v4d_escrow_release
both_accept=$(grep -c '^compared both accept$' "$log" || true)
both_refuse=$(grep -c '^compared both refuse$' "$log" || true)
sig_only=$(grep -c '^compared v1 refuses a signature or finality only' "$log" || true)
skipped=$(grep -c '^skipped ' "$log" || true)
[ "$both_accept" -ge 100 ] && [ "$both_refuse" -ge 50 ] || { echo "run-v4-differential: too few comparisons" >&2; exit 1; }
{
  echo "v4 differential (scripts/run-v4-differential.sh): terms-core against the v1 script on every v1 vector"
  echo "date $(date -u +%Y-%m-%d)"
  echo "compared, both accept: $both_accept"
  echo "compared, both refuse: $both_refuse"
  echo "compared, v1 refuses a signature or finality only, statement accepts: $sig_only"
  echo "skipped, outside the v4 domain (no authority, or terms that do not decode as terms v4): $skipped"
  echo "divergences: 0 (a divergence fails the run)"
} > tests/engine/v4-differential-run.txt
echo "wrote tests/engine/v4-differential-run.txt"
