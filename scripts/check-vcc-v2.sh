#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Pre-run check of a node for the I8 watcher: get_virtual_chain_from_block_v2 at Full verbosity,
# its per-input spent UTXO entries, the transaction IDs that must rebuild, and its added-block
# batch limit (check against the rusty-kaspa revision mainnet
# nodes run, kaspad 2.1.0 on 2026-10-06, before any live run).
#
# The key holder runs this against their own node. Nobody else runs it against mainnet.
#
#   scripts/check-vcc-v2.sh --network mainnet --node ws://127.0.0.1:17110 [--expect-version 2.1.0]
#
# Read-only: it makes get_server_info, get_block_dag_info, get_block and
# get_virtual_chain_from_block_v2 calls and submits nothing. It holds no key. Nothing is
# defaulted but the expected server version (2.1.0, the version mainnet nodes run): the network and the
# node URL are required, and mainnet is never implied. On mainnet the link must be wss://, or
# ws:// to this machine (an SSH tunnel reaches a remote node).
#
# Environment: IMPULSE_WATCH_BIN uses an existing impulse-watch binary instead of building one.
# The node URL is shown without its user information, path and query (scheme, host and port only).
#
# Exit 0: every check passed. Exit 1: a check failed, or the node was refused. Exit 2: usage.
# On success, keep the output with the date and the node version.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 --network mainnet|testnet --node <ws:// or wss:// URL> [--expect-version <version>]" >&2
  exit 2
}

network=""
node=""
expect="2.1.0"
while [ $# -gt 0 ]; do
  case "$1" in
    --network) [ $# -ge 2 ] || usage; network="$2"; shift 2 ;;
    --node) [ $# -ge 2 ] || usage; node="$2"; shift 2 ;;
    --expect-version) [ $# -ge 2 ] || usage; expect="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$network" in
  mainnet | testnet) ;;
  *) usage ;;
esac
[ -n "$node" ] || usage

bin="${IMPULSE_WATCH_BIN:-}"
if [ -z "$bin" ]; then
  # Where cargo put the binary is cargo's to say (CARGO_TARGET_DIR and build.target-dir move it).
  bin=$(cargo build --locked --release -p impulse-watch --message-format=json | python3 -c '
import json, sys
exe = None
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    t = m.get("target", {})
    if (m.get("reason") == "compiler-artifact" and "bin" in t.get("kind", [])
            and t.get("name") == "impulse-watch" and m.get("executable")):
        exe = m["executable"]
if exe:
    print(exe)
')
  [ -n "$bin" ] || { echo "check-vcc-v2: cargo did not report the impulse-watch binary" >&2; exit 1; }
fi

# The URL as shown: scheme and host with port only. Credentials, a path or a query may carry a
# key, and this output is meant to be pasted into the run record.
case "$node" in
  *://*) shown=$(printf '%s' "$node" | sed -E -e 's|^([A-Za-z]+://)[^/?#]*@|\1***@|' -e 's|^([A-Za-z]+://[^/?#]*)[/?#].*$|\1/...|') ;;
  *) shown="(not a URL)" ;;
esac

echo "check-vcc-v2: network $network, node $shown, expecting server version $expect"
if "$bin" probe --network "$network" --node "$node" --expect-version "$expect"; then
  echo "check-vcc-v2: all checks passed"
  echo "check-vcc-v2: keep this output with the date and the node version"
else
  echo "check-vcc-v2: FAILED" >&2
  exit 1
fi
