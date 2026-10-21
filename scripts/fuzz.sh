#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Fuzzes the untrusted-input parsers of impulse-core and impulse-cli with cargo-fuzz (I14).
#
#   scripts/fuzz.sh [SECONDS] [TARGET...]   fuzz each target for SECONDS (default 600)
#   scripts/fuzz.sh --list                  list the targets
#   scripts/fuzz.sh --replay [TARGET...]    run each target once over its committed corpus
#
# Needs the nightly toolchain and cargo-fuzz (`cargo install cargo-fuzz`). fuzz/ is its own
# workspace, excluded from the stable one, so scripts/ci-local.sh never builds it. Seeds are
# regenerated into fuzz/corpus/<target>/seed-* first; inputs the fuzzer finds go into the same
# directory, and a crash is written to fuzz/artifacts/<target>/. Each run's libFuzzer log goes
# to $FUZZ_LOG_DIR (default: a fresh temporary directory, printed).
#
# Key material (rule 1, docs/ENGINEERING-RULES.md): the threshold_secret target decodes FROST share encodings, so
# every input it keeps is shaped like a share. Its corpus and artifacts live only in a temporary
# directory removed when this script exits, are never under fuzz/, and are never committed.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"

targets=(terms_decode template_decode tx_decode ipst_parse kcc20_template threshold_public
  threshold_secret cli_json cli_terms_file cli_args cli_receipt cli_rpc_walk cli_rpc_wire)

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "${targets[@]}"
  exit 0
fi
replay=0
if [ "${1:-}" = "--replay" ]; then
  replay=1
  shift
fi
secs=600
if [ $replay -eq 0 ] && [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  secs=$1
  shift
fi
[ $# -gt 0 ] && targets=("$@")

command -v cargo-fuzz >/dev/null || { echo "fuzz.sh: cargo-fuzz not installed" >&2; exit 1; }
# On macOS the linker rejects an unresolved risc0 platform symbol that nothing calls at run time
# (pulled in by the kaspa zk crate); let it resolve lazily. Not needed on Linux.
if [ "$(uname -s)" = Darwin ]; then
  export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-undefined,dynamic_lookup"
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
logs=${FUZZ_LOG_DIR:-$scratch/logs}
mkdir -p "$logs"

cargo +nightly run --quiet --release --bin seeds -- "$PWD/corpus"
cargo +nightly fuzz build -O

status=0
for t in "${targets[@]}"; do
  if [ "$t" = threshold_secret ]; then
    corpus=("$scratch/corpus-$t")
    art=$scratch/artifacts-$t/
  else
    corpus=("corpus/$t")
    art=artifacts/$t/
  fi
  mkdir -p "${corpus[0]}" "$art"
  if [ $replay -eq 1 ]; then
    flags=(-runs=0)
  else
    flags=(-max_total_time="$secs" -print_final_stats=1 -rss_limit_mb=4096 -timeout=10)
  fi
  echo "==> $t"
  if cargo +nightly fuzz run -O "$t" "${corpus[@]}" -- -artifact_prefix="$art" "${flags[@]}" \
    >"$logs/$t.log" 2>&1; then
    grep -E '^(Done|stat::|#[0-9]+ *DONE)' "$logs/$t.log" | tail -12 || true
  else
    status=1
    echo "fuzz.sh: $t FAILED, log $logs/$t.log, artifacts $art" >&2
    tail -40 "$logs/$t.log" >&2
  fi
done
[ -z "${FUZZ_LOG_DIR:-}" ] && echo "logs (removed on exit): $logs"
exit $status
