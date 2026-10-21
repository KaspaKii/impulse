#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Demo gate (I11), a step of scripts/ci-local.sh after the SDK step. Every step is blocking.
#   1. Build demo/dist from the pages and the SDK that crates/impulse-wasm/ci.sh built.
#   2. npm ci from the lockfile without install scripts, tsc type check.
#   3. The browser tests, in headless Chrome or Chromium ($IMPULSE_BROWSER, else a usual path; a
#      machine with none fails here, it does not skip): exactly BROWSER_TESTS tests, all passing,
#      none skipped.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "demo: FAIL: $1" >&2; exit 1; }

# How many tests the runner must report. A runner that finds no tests still exits 0, so the
# count is checked here. Change it with the tests.
BROWSER_TESTS=126 # test/*.test.ts, run by node --test

command -v node >/dev/null || fail "node not installed"
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 18) ? 0 : 1)' \
  || fail "node $(node --version), need 22.18 or later"
command -v npm >/dev/null || fail "npm not installed"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "demo: build"
./build.sh

echo "demo: mutation record matches the sources"
# demo/mutation-run.txt names the page files, the tests and demo/mutation.mjs by hash, and every
# mutant caught: it is stale the moment one changes. Rerun by hand: node demo/mutation.mjs --record
node mutation.mjs --verify-record \
  || fail "demo/mutation-run.txt does not match the sources, or records a survivor (rerun: node demo/mutation.mjs --record)"

echo "demo: npm ci, type check"
npm ci --ignore-scripts --no-audit --no-fund
./node_modules/.bin/tsc -p tsconfig.json

echo "demo: browser tests"
# At most 4 test files (each with its own headless browser) run at once, to bound memory.
node --test --test-concurrency=4 --test-reporter=tap "test/*.test.ts" | tee "$tmp/browser-test.log"
for line in "# tests $BROWSER_TESTS" "# pass $BROWSER_TESTS" "# fail 0" "# cancelled 0" "# skipped 0" "# todo 0"; do
  grep -qxF "$line" "$tmp/browser-test.log" || fail "the browser tests did not report '$line'"
done

echo "demo: green"
