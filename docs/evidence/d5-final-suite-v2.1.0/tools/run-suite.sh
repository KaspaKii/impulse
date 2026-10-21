#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# As run for the D5 final evidence (SP is the scratch directory of that run). usage: run-suite.sh base|v210 all|ci
# all: cargo test --workspace --all-features --no-fail-fast; ci: cargo test --workspace --no-fail-fast.
# Every script-engine execution is appended to $out.runs.log by the instrumentation diff.
set -uo pipefail
SP=/private/tmp/scratch/d5final
label=$1; fs=$2
dir=$SP/$label; tgt=$SP/tgt-$label
out=$SP/out/$label-$fs
rm -f $out.runs.log $out.test.log
cd $dir
case $fs in
  all) flags="--workspace --all-features" ;;
  ci)  flags="--workspace" ;;
esac
lock=""; [ "$label" = base ] && lock="--locked"
start=$(date +%s)
impulse_d5_log=$out.runs.log CARGO_TARGET_DIR=$tgt CARGO_NET_OFFLINE=true cargo test $lock $flags --no-fail-fast > $out.test.log 2>&1
echo "cargo exit $?" >> $out.test.log
echo "seconds $(( $(date +%s) - start ))" >> $out.test.log
