#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Regenerates the committed real receipts of template v4 in tests/engine/fixtures/v4/ (spec/V3-ZK.md
# 22.9). One receipt per fixture plan of crates/impulse-core/src/zkh/build_tests.rs
# (`fixture_plans`): the builders' own settle and refund plans for a fixed world of label-derived
# public keys, so no key of any kind is involved. Proving is local: the succinct receipt on this
# machine, the Groth16 step in the image pinned by digest, no network. Each receipt takes several
# minutes of CPU time and a few GiB of memory.
#   regen-fixtures-v4.sh            prove every fixture (missing ones only with --missing)
#   regen-fixtures-v4.sh --missing  prove only the fixtures that have no proof file yet
#   regen-fixtures-v4.sh --check    check every committed receipt in the pinned engine, prove nothing
# The proof bytes are not deterministic (the prover's blinding); the journals are, and
# `committed_receipts_are_the_journals_the_builders_make` (impulse-core) compares them.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
dir="$repo/tests/engine/fixtures/v4"
source "$repo/circuits/scripts/env.sh"
(cd "$repo/circuits" && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)
bin="$repo/circuits/target/release/impulse-zk-prove-terms"
mkdir -p "$dir"
if [ "${1:-}" = "--check" ]; then
  n=0
  for f in "$dir"/*.proof.json; do
    "$bin" --verify "$f" >/dev/null || { echo "regen-fixtures-v4: FAIL: $f" >&2; exit 1; }
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || { echo "regen-fixtures-v4: FAIL: no receipt in $dir" >&2; exit 1; }
  echo "regen-fixtures-v4: $n receipts accepted by the pinned engine"
  exit 0
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
(cd "$repo" && IMPULSE_V4_FIXTURE_WITNESS="$tmp" cargo test --locked -p impulse-core --features zk-hashed --lib -- --ignored emit_fixture_witnesses >/dev/null)
for w in "$tmp"/*.witness.bin; do
  name=$(basename "$w" .witness.bin)
  if [ "${1:-}" = "--missing" ] && [ -f "$dir/$name.proof.json" ]; then continue; fi
  echo "proving $name"
  "$bin" --witness "$w" --out "$tmp/$name.proof.json" --timings "$tmp/$name.timings.json"
  "$bin" --verify "$tmp/$name.proof.json"
  cp "$tmp/$name.proof.json" "$dir/$name.proof.json"
done
echo "regen-fixtures-v4: done; run scripts/regen-fixtures-v4.sh --check"
