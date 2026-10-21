#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Builds the static site into demo/dist: the pages, the SDK bundled locally (no CDN, no network
# at run time beyond the node URL a user types), the licence, and the golden terms vectors as
# loadable examples (with their tokens pinned: see pin-examples.mjs). Needs the SDK built first:
# crates/impulse-wasm/ci.sh.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "demo: FAIL: $1" >&2; exit 1; }

sdk=../crates/impulse-wasm/npm
for f in index.js pkg/impulse_wasm.js pkg/impulse_wasm_bg.wasm; do
  [ -f "$sdk/$f" ] || fail "$sdk/$f is missing (build the SDK first: crates/impulse-wasm/ci.sh)"
done

rm -rf dist
mkdir -p dist/sdk/pkg dist/examples
cp index.html decoder.html style.css favicon.svg impulse-wordmark.svg main.js app.js dom.js node.js wallets.js actions.js decoder.js config.js dist/
cp ../LICENSE ../NOTICE dist/
cp "$sdk/index.js" dist/sdk/
cp "$sdk/pkg/impulse_wasm.js" "$sdk/pkg/impulse_wasm_bg.wasm" dist/sdk/pkg/
# The examples are the golden vectors with the token of each KCC-20 leg pinned, written by the SDK
# just copied to dist: the vectors themselves name a synthetic token that no funding accepts.
node pin-examples.mjs || fail "the examples could not be written from the golden vectors"
echo "demo: built demo/dist"
