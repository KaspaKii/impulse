#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Rebuilds the I20 list guest and the I21 terms guest from scratch in RISC Zero's guest-builder Docker image (pinned by
# digest in circuits/methods/build.rs) and fails unless its image ID is circuits/IMAGE_ID
# (spec/V3-ZK.md section 5.5, red team finding 5) and the terms guest unless its image ID is
# circuits/IMAGE_ID_V4 (spec/V3-ZK.md 22.2). Both guests come from one Docker build. Needs a running Docker daemon.
# Limits: this shows the build reproduces on this machine from a clean guest target directory;
# reproduction on another machine is asserted by RISC Zero's documentation, not checked here.
set -euo pipefail
cd "$(dirname "$0")/../circuits"
source scripts/env.sh
docker info >/dev/null 2>&1 || { echo "build-guest: FAIL: Docker daemon not running" >&2; exit 1; }
want=$(tr -d '[:space:]' < IMAGE_ID)
want_v4=$(tr -d '[:space:]' < IMAGE_ID_V4)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# risc0-build writes Docker-built ELFs under circuits/target/riscv-guest whatever CARGO_TARGET_DIR is.
rm -rf target/riscv-guest
got=$(CARGO_TARGET_DIR="$tmp" cargo run --locked --quiet -p impulse-zk-methods --example image-id)
got_v4=$(CARGO_TARGET_DIR="$tmp" cargo run --locked --quiet -p impulse-zk-methods --example image-id-v4)
echo "built list guest image ID:  $got"
echo "circuits/IMAGE_ID:          $want"
echo "built terms guest image ID: $got_v4"
echo "circuits/IMAGE_ID_V4:       $want_v4"
[ "$got" = "$want" ] || { echo "build-guest: FAIL: ZK_IMAGE_ID_MISMATCH (list guest)" >&2; exit 1; }
[ "$got_v4" = "$want_v4" ] || { echo "build-guest: FAIL: ZK_IMAGE_ID_MISMATCH (terms guest)" >&2; exit 1; }
echo "build-guest: image IDs reproduced"
