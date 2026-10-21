#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Fails unless tests/engine/v3-live-run.txt records a pass of the two real-proof authority
# settle tests for the current contract, image ID and test source (see record-v3-live.sh).
# The tests take minutes and need Docker, so ci-local.sh requires their recorded result
# instead of running them; scripts/ci-zk.sh runs them and rewrites the record.
set -euo pipefail
cd "$(dirname "$0")/.."
rec=tests/engine/v3-live-run.txt
[ -f "$rec" ] || { echo "check-v3-live-record: $rec missing; run scripts/ci-zk.sh" >&2; exit 1; }
grep -q '^tests passed: 2$' "$rec" || { echo "check-v3-live-record: record does not show 2 passed" >&2; exit 1; }
while read -r _ f h; do
  [ "$(shasum -a 256 "$f" | cut -d' ' -f1)" = "$h" ] \
    || { echo "check-v3-live-record: $f changed since the record; run scripts/ci-zk.sh" >&2; exit 1; }
done < <(grep '^sha256 ' "$rec")
[ "$(grep -c '^sha256 ' "$rec")" = 6 ] || { echo "check-v3-live-record: record lists the wrong files" >&2; exit 1; }
echo "check-v3-live-record: current"
