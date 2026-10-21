#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Fails unless tests/engine/v4-live-run.txt records a pass of the five real-receipt tests of
# template v4 for the current contract, image ID and test source (see record-v4-live.sh).
# The tests take an hour or more and need Docker, so ci-local.sh requires their recorded result
# instead of running them; scripts/ci-zk.sh runs them and rewrites the record.
set -euo pipefail
cd "$(dirname "$0")/.."
rec=tests/engine/v4-live-run.txt
if [ ! -f "$rec" ]; then
  # Docker-only check pending (D108): allowed only while the marker names it, and never once a
  # record exists. scripts/record-v4-live.sh removes the marker when it writes the record.
  if [ -f tests/engine/v4-live-run.PENDING ]; then
    echo "check-v4-live-record: PENDING (no Docker on the machine that made this commit): the five real-receipt tests of v4_live.rs have not run; run scripts/ci-zk.sh" >&2
    exit 0
  fi
  echo "check-v4-live-record: $rec missing; run scripts/ci-zk.sh" >&2; exit 1
fi
grep -q '^tests passed: 5$' "$rec" || { echo "check-v4-live-record: record does not show 5 passed" >&2; exit 1; }
while read -r _ f h; do
  [ "$(shasum -a 256 "$f" | cut -d' ' -f1)" = "$h" ] \
    || { echo "check-v4-live-record: $f changed since the record; run scripts/ci-zk.sh" >&2; exit 1; }
done < <(grep '^sha256 ' "$rec")
[ "$(grep -c '^sha256 ' "$rec")" = 7 ] || { echo "check-v4-live-record: record lists the wrong files" >&2; exit 1; }
echo "check-v4-live-record: current"
