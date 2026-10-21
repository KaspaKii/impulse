#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# End-to-end test of scripts/sample-daa.sh (I18) against the offline fake node: the CLI built with
# the test-only `offline-fake-node` feature and a fake node state file. Offline: no network, no
# key. It proves the script and the CLI work together; it says nothing about any live network.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
checks=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { checks=$((checks + 1)); }
check() { if eval "$2"; then pass; else fail "$1"; fi; }

echo "building impulse with the offline-fake-node feature"
cargo build --locked -q -p impulse-cli --features offline-fake-node \
  --manifest-path "$repo/Cargo.toml" --target-dir "$repo/target/fake-node" || exit 1
B="$repo/target/fake-node/debug/impulse"
state="$work/tn.state"
node="fake://$state"
"$B" fake-node init --state "$state" --daa 1000000 --tick 0 > /dev/null || exit 1

out=$("$here/sample-daa.sh" --network testnet --node "$node" --file "$work/sample" --interval 1 --count 2 \
  --impulse "$B" 2>&1); rc=$?
check "sample-daa takes two points (got $rc): $out" \
  '[ $rc -eq 0 ] && [ "$(wc -l < "$work/sample" | tr -d " ")" -eq 3 ] && head -n 1 "$work/sample" | grep -qx "impulse-daa-sample 1 testnet bps 10"'
out=$("$here/sample-daa.sh" --network mainnet --node "$node" --file "$work/sample2" --interval 1 --count 1 \
  --impulse "$B" 2>&1); rc=$?
check "sample-daa reports a refused point as skipped and exits non-zero (testnet node, --network mainnet)" \
  '[ $rc -ne 0 ] && printf "%s\n" "$out" | grep -q "^skipped: impulse: CLI_NODE_" && [ ! -e "$work/sample2" ]'
out=$("$here/sample-daa.sh" --node "$node" --file "$work/sample3" --count 1 --impulse "$B" 2>&1); rc=$?
check "sample-daa needs the network named" '[ $rc -eq 2 ]'
out=$("$here/sample-daa.sh" --network testnet --node "$node" --file "$work/sample3" --interval 600 --count 1 --impulse "$B" 2>&1); rc=$?
check "sample-daa refuses an interval that could leave a 10-minute gap" '[ $rc -eq 2 ]'

echo "test-sample-daa: $checks checks passed, $fails failed"
[ "$fails" -eq 0 ]
