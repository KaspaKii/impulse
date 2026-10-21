#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Regenerates the committed proof fixtures in tests/engine/fixtures/v3/proofs/ (spec/V3-ZK.md
# section 13.1), then checks them in the pinned engine.
#   regen-fixtures.sh                    prove every fixture (stand-in vaults unless --vaults)
#   regen-fixtures.sh --vaults <file>    bind the fixtures to real template v3 vault scriptPubKeys
#   regen-fixtures.sh --only <names>     prove only the named fixtures (others keep their proofs)
#   regen-fixtures.sh --inputs-only      write the deterministic files only, prove nothing
#   regen-fixtures.sh --check            recompute and check the committed files, prove nothing
# Deterministic: lists, salts, roots, paths, journals, cases. Not deterministic: the Groth16 proof
# bytes (the prover's random blinding), so a regenerated proof is checked by verification.
# Proving is local (succinct on this machine, Groth16 in the pinned image with no network).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
dir="$repo/tests/engine/fixtures/v3/proofs"
source "$here/env.sh"
cd "$repo/circuits"
cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-fixtures
bin="$repo/circuits/target/release/impulse-zk-fixtures"
case "${1:-}" in
  --check) exec "$bin" --check "$dir" ;;
  --inputs-only) shift; "$bin" --out "$dir" --only "" "$@"; exit 0 ;;
esac
args=("$@")
if [ -f "$dir/vaults.json" ] && ! printf '%s\n' "${args[@]+"${args[@]}"}" | grep -qx -- '--vaults'; then
  # Keep the committed vault map unless a new one is given.
  if [ "$(tr -d '[:space:]' < "$dir/vaults.json")" != "{}" ]; then args+=(--vaults "$dir/vaults.json"); fi
fi
"$bin" --out "$dir" "${args[@]+"${args[@]}"}"
"$bin" --check "$dir"
