#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# scripts/sample-daa.sh: the DAA rate sample of the hashlock margin rule (I18; spec/V2.md
# section 10.5; decision D45).
#
# Read only: every interval it runs `impulse xchain daa-sample`, which checks the node's network,
# sync and blocks-per-second and appends one line, the system clock in unix seconds and the
# node's virtual DAA score, to the sample file. No key, no signature, no transaction. A point the
# node does not give is reported as `skipped:` and the run goes on; two points more than 10
# minutes apart make the sample unusable (HTLC_DAA_SAMPLE), so the interval is at most 240
# seconds and a run with many skips should be restarted into a new file. The rate is read over
# fixed 10-minute windows, linearly between points, so a burst shorter than the interval is spread
# over it: keep the default of 60 s (spec/V2.md section 10.8, sampling resolution; D67).
#
# Usage:
#   scripts/sample-daa.sh --network mainnet|testnet --node <ws:// or wss:// URL> --file <sample file>
#     [--interval <seconds, 1 to 240, default 60>] [--count <points, default 0: until stopped>]
#     [--impulse <binary>]
#
# The network is named explicitly; there is no default. On mainnet the node URL must be wss:// or
# ws:// to this machine (the CLI's transport rule). Leave it running for at least 7 days; the
# sample is usable for 30 days after its last point.
set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^# The network is named/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

network= node= file= interval=60 count=0 impulse=impulse
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --network) network=$2 ;;
    --node) node=$2 ;;
    --file) file=$2 ;;
    --interval) interval=$2 ;;
    --count) count=$2 ;;
    --impulse) impulse=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$node" ] && [ -n "$file" ] || usage
case "$network" in mainnet|testnet) ;; *) usage ;; esac
case "$interval" in ''|*[!0-9]*) usage ;; esac
case "$count" in ''|*[!0-9]*) usage ;; esac
[ "$interval" -ge 1 ] && [ "$interval" -le 240 ] || usage

echo "sampling: network $network, every $interval s, into $file (read only; no key, no transaction)"
taken=0 skipped=0
while :; do
  if out=$("$impulse" --network "$network" xchain daa-sample --node "$node" --file "$file" 2>&1); then
    taken=$((taken + 1))
    printf '%s\n' "$out"
  else
    skipped=$((skipped + 1))
    printf 'skipped: %s\n' "$(printf '%s' "$out" | head -n 1)"
  fi
  if [ "$count" -gt 0 ] && [ $((taken + skipped)) -ge "$count" ]; then
    break
  fi
  sleep "$interval"
done
echo "sampled: $taken points, $skipped skipped, in $file"
[ "$skipped" -eq 0 ]
