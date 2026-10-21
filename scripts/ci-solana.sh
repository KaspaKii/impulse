#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Solana CI gate (I19, I18 Solana half). Every step is blocking. The Solana code is its own cargo
# workspace under solana/ with its own rust-toolchain.toml (1.91.0) and Cargo.lock; the Kaspa
# workspace and scripts/ci-local.sh never build it (owner decision D28). This script is the only
# gate for the Solana tests: run it beside scripts/ci-local.sh before any merge that touches solana/.
#
# Needs: the Solana CLI tools on PATH (solana-cli 3.1.x with cargo-build-sbf), platform-tools
# v1.52, pnpm 9 and Node 22.18 or later. For example:
#   export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
# No key is read, written or printed here. cargo-build-sbf writes a random throwaway program
# keypair under solana/target/deploy/ (gitignored); it is never used to deploy (rule 6, docs/ENGINEERING-RULES.md:
# devnet and mainnet deploys are run by the key holder).
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

step() { printf '\n==> %s\n' "$1"; }
fail() { echo "ci-solana: FAIL: $1" >&2; exit 1; }

# Pinned like upstream solana-foundation/dvp df9919e: v1.57 overflows the SBF stack frame.
SBF_TOOLS_VERSION=v1.52
# The two on-chain programs, each a crate under solana/programs/. Both must exist.
PROGRAMS="impulse-solana impulse-htlc"
# Test-only SBF programs the impulse-solana LiteSVM tests load (upstream's transfer-hook and
# smart-wallet fixtures, renamed). Never deployed.
SBF_FIXTURES="impulse-solana-hook-fixture impulse-solana-wallet-fixture"
# The TypeScript cross-check (one term sheet derives the Kaspa vault addresses through the
# impulse-wasm SDK and the Solana escrow PDA).
CROSSCHECK=solana/ts

step "tools"
command -v cargo-build-sbf >/dev/null || fail "cargo-build-sbf not on PATH (see the header of this script)"
command -v pnpm >/dev/null || fail "pnpm not installed"
command -v node >/dev/null || fail "node not installed"
echo "ci-solana: $(cargo-build-sbf --version | head -n 1), pnpm $(pnpm --version), node $(node --version)"
[ "$(cd solana && rustc --version | cut -d' ' -f2)" = "1.91.0" ] \
  || fail "solana/ does not resolve to Rust 1.91.0 (solana/rust-toolchain.toml)"
[ -f solana/LICENSE-MIT ] && grep -qF "Copyright (c) 2026 Solana Foundation" solana/LICENSE-MIT \
  || fail "solana/LICENSE-MIT (upstream MIT notice of solana-foundation/dvp) missing"

step "workspace sources (rule 2, docs/ENGINEERING-RULES.md)"
# Every package comes from crates.io or a path inside solana/; no git source, no WarpCore crate.
for p in $PROGRAMS; do
  [ -f "solana/programs/$p/Cargo.toml" ] || fail "program solana/programs/$p is missing"
done
(cd solana && cargo metadata --locked --format-version 1) | ROOT="$root/solana" python3 -c '
import json, os, sys
m = json.load(sys.stdin)
root = os.path.realpath(os.environ["ROOT"]) + os.sep
bad = []
for p in m["packages"]:
    src = p.get("source")
    if "warpcore" in p["name"].lower():
        bad.append(p["name"] + " (WarpCore crate)")
    elif src is None:
        if not os.path.realpath(p["manifest_path"]).startswith(root):
            bad.append(p["name"] + " (path outside solana/)")
    elif src != "registry+https://github.com/rust-lang/crates.io-index":
        bad.append(p["name"] + " (" + src + ")")
if bad:
    sys.exit("disallowed packages: " + ", ".join(bad))
' || fail "solana workspace has a disallowed package source"

step "cargo audit (solana/Cargo.lock)"
# Known advisories are triaged and ignored one by one in solana/.cargo/audit.toml; a new one fails.
command -v cargo-audit >/dev/null || fail "cargo-audit not installed"
(cd solana && cargo audit --deny warnings) || fail "cargo audit failed for solana/Cargo.lock"

step "fmt"
(cd solana && cargo fmt --all --check) || fail "cargo fmt --check failed in solana/"

step "build programs (cargo-build-sbf --tools-version $SBF_TOOLS_VERSION)"
# Built from each program directory, as upstream does, so only the on-chain crate is compiled for
# the SBF target. The .so files land in solana/target/deploy/, where the tests load them.
for p in $PROGRAMS $SBF_FIXTURES; do
  (cd "solana/programs/$p" && cargo-build-sbf --tools-version "$SBF_TOOLS_VERSION" -- --locked) \
    || fail "cargo-build-sbf failed for $p"
done

step "clippy (every solana/ crate, -D warnings)"
# --workspace, so impulse-htlc and any crate added under solana/programs/ are linted too.
(cd solana && cargo clippy --locked --workspace --all-targets -- -D warnings) \
  || fail "clippy failed in solana/"

step "program tests"
(cd solana && cargo test --workspace --locked) || fail "solana workspace tests failed"

step "impulse-solana IDL and generated client match the program"
# The program's build script rewrote idl/impulse_solana.json during the builds above; the
# committed IDL must be what the program says. The Rust client is then regenerated from it with
# the pinned Codama (solana/codegen) and must match the committed one byte for byte.
git diff --exit-code -- solana/programs/impulse-solana/idl \
  || fail "solana/programs/impulse-solana/idl is stale: commit the IDL the build wrote"
pnpm --dir solana/codegen install --frozen-lockfile --ignore-scripts
pnpm --dir solana/codegen generate
git diff --exit-code -- solana/programs/impulse-solana-client/src/generated \
  || fail "the generated impulse-solana client is stale: run pnpm --dir solana/codegen generate"

step "TypeScript cross-check (one term sheet, Kaspa vault addresses and Solana PDA)"
[ -f "$CROSSCHECK/package.json" ] || fail "$CROSSCHECK/package.json missing"
[ -f "$CROSSCHECK/pnpm-lock.yaml" ] || fail "$CROSSCHECK/pnpm-lock.yaml missing"
# Always rebuild the SDK from the current impulse-core and impulse-wasm sources (review round 2):
# npm/pkg is gitignored, so a package left over from an older build would otherwise be what the
# cross-check tests. crates/impulse-wasm/ci.sh removes npm/pkg before it builds it again.
echo "ci-solana: rebuilding the SDK package; running crates/impulse-wasm/ci.sh"
crates/impulse-wasm/ci.sh || fail "crates/impulse-wasm/ci.sh failed (SDK build for the cross-check)"
[ -f crates/impulse-wasm/npm/pkg/impulse_wasm_bg.wasm ] || fail "the SDK build left no impulse_wasm_bg.wasm"
pnpm --dir "$CROSSCHECK" install --frozen-lockfile --ignore-scripts
pnpm --dir "$CROSSCHECK" test || fail "TypeScript cross-check failed"

echo
echo "ci-solana: green"
