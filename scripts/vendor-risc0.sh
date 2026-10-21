#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Builds circuits/vendor/risc0-zkvm-3.0.4: the crates.io 3.0.4 source plus a two-line fix
# (circuits/patches/risc0-zkvm-3.0.4-prove.patch). Why: zkvm 3.0.4's `prove` feature calls
# ReadIOP::read_field_elem_slice and read_u32s as infallible, but risc0-zkp 3.0.4 (which the pinned
# kaspa-txscript requires with "=3.0.4") returns Result, so the unpatched crate does not compile
# (measured: E0599 at src/host/recursion/prove/mod.rs:640). risc0-zkvm 3.0.5 has the same fix but
# is not the version the pinned rusty-kaspa pins, so we patch 3.0.4 instead. circuits/vendor is
# generated and not committed. Idempotent.
set -euo pipefail
cd "$(dirname "$0")/../circuits"
dest=vendor/risc0-zkvm-3.0.4
[ -f "$dest/.patched" ] && exit 0
src=$(ls -d "$HOME"/.cargo/registry/src/*/risc0-zkvm-3.0.4 2>/dev/null | head -1 || true)
[ -n "$src" ] || { echo "vendor-risc0: risc0-zkvm-3.0.4 not in the cargo registry; run cargo fetch in circuits/ first" >&2; exit 1; }
rm -rf "$dest"; mkdir -p vendor; cp -R "$src" "$dest"; rm -f "$dest/.cargo-ok"
patch -s -p1 -d "$dest" < patches/risc0-zkvm-3.0.4-prove.patch
touch "$dest/.patched"
