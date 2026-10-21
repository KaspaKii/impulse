#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# SDK gate (I9), a step of scripts/ci-local.sh. Every step is blocking.
#   1. Tool pins: the wasm-bindgen CLI and its test runner equal the wasm-bindgen crate in
#      Cargo.lock; wasm-pack 0.14.0; Node 22.18 or later (it runs the TypeScript tests by type
#      stripping); an LLVM archiver, since secp256k1-sys builds libsecp256k1 in C and an archive
#      without a wasm symbol index links to a module that imports its symbols from nowhere.
#   2. clippy -D warnings on wasm32 (the native pass does not see the wasm-only test module).
#   3. wasm-pack test --node: the Rust tests run inside the JavaScript engine, exactly
#      WASM_TESTS of them.
#   4. wasm-pack build --target web into npm/pkg; the module imports exactly the functions of
#      wasm-imports.txt, all from its own glue, and holds no path of the machine that built it.
#   5. npm ci from the lockfile without install scripts, npm audit (high or worse fails; the
#      dev dependencies are exact pins, so this is what keeps "no known vulnerability" true),
#      tsc type check, then the TypeScript suite (golden vectors byte for byte, a Direct and a
#      Vault trade end to end against the native build, every refusal code beside an accepted
#      control), exactly TS_TESTS tests, with the module's randomness imports counted (only a
#      wallet's key may draw, and each draw is a key a test asked for).
#   6. The packed package holds exactly its files, among them the repository's LICENSE and
#      NOTICE, names the workspace's repository, and a consumer that installs the tarball loads
#      it by name, hashes a golden vector, and cannot import the generated module directly.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "sdk: FAIL: $1" >&2; exit 1; }

# How many tests each runner must report, all passing. A runner that finds no tests, or fewer,
# still exits 0, so the counts are checked here, in this one place. Change them with the tests.
WASM_TESTS=6 # src/wasm_tests.rs, run by wasm-pack test --node
TS_TESTS=452 # npm/test/*.test.ts, run by node --test

WASM_PACK_VERSION=0.14.0
bindgen=$(awk '/^name = "wasm-bindgen"$/ { getline; print }' ../../Cargo.lock | sed -E 's/^version = "(.*)"$/\1/')
[ -n "$bindgen" ] || fail "no wasm-bindgen in Cargo.lock"
for tool in wasm-bindgen wasm-bindgen-test-runner; do
  command -v "$tool" >/dev/null \
    || fail "$tool not installed (cargo install wasm-bindgen-cli --version $bindgen --locked)"
  [ "$($tool --version)" = "$tool $bindgen" ] \
    || fail "$($tool --version), but Cargo.lock pins wasm-bindgen $bindgen"
done
command -v wasm-pack >/dev/null \
  || fail "wasm-pack not installed (cargo install wasm-pack --version $WASM_PACK_VERSION --locked)"
[ "$(wasm-pack --version)" = "wasm-pack $WASM_PACK_VERSION" ] \
  || fail "$(wasm-pack --version), expected wasm-pack $WASM_PACK_VERSION"
command -v node >/dev/null || fail "node not installed"
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 18) ? 0 : 1)' \
  || fail "node $(node --version), need 22.18 or later"
command -v npm >/dev/null || fail "npm not installed"

if [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
  llvm=""
  if command -v brew >/dev/null && [ -x "$(brew --prefix llvm 2>/dev/null)/bin/llvm-ar" ]; then
    llvm="$(brew --prefix llvm)/bin/"
  fi
  command -v "${llvm}llvm-ar" >/dev/null || fail "llvm-ar not found (Debian: apt install llvm clang; macOS: brew install llvm)"
  export AR_wasm32_unknown_unknown="${llvm}llvm-ar"
  export CC_wasm32_unknown_unknown="${llvm}clang"
fi
command -v "$CC_wasm32_unknown_unknown" >/dev/null || fail "no C compiler for wasm32: $CC_wasm32_unknown_unknown"

echo "sdk: wasm-bindgen $bindgen, wasm-pack $WASM_PACK_VERSION, node $(node --version), $AR_wasm32_unknown_unknown"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# rustc writes the source paths of dependencies (cargo registry and git checkouts) into panic
# locations. Remap them, and the repository, so the module does not depend on, or name, the
# machine that built it. This variable replaces the target rustflags of .cargo/config.toml, so
# it repeats that cfg. rustc applies the last remap that matches, so the cargo home, which CI
# keeps inside the repository, comes last. Paths with spaces are refused: the variable is split
# on spaces.
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
repo=$(cd ../.. && pwd -P)
case "$cargo_home$repo" in *" "*) fail "a space in $cargo_home or $repo";; esac
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\" --remap-path-prefix=$repo=/impulse --remap-path-prefix=$cargo_home=/cargo"

echo "sdk: clippy on wasm32"
cargo clippy --locked -p impulse-wasm --target wasm32-unknown-unknown --all-targets -- -D warnings

echo "sdk: wasm-pack test --node"
wasm-pack test --node --mode no-install . --locked 2>&1 | tee "$tmp/wasm-test.log"
grep -qE "^test result: ok\. $WASM_TESTS passed; 0 failed; 0 ignored; 0 filtered out;" "$tmp/wasm-test.log" \
  || fail "wasm-pack test did not run exactly $WASM_TESTS tests, all passing"

echo "sdk: wasm-pack build --target web"
rm -rf npm/pkg
wasm-pack build --target web --out-dir npm/pkg --mode no-install --release . -- --locked
node -e '
const fs = require("fs");
const m = new WebAssembly.Module(fs.readFileSync("npm/pkg/impulse_wasm_bg.wasm"));
const got = WebAssembly.Module.imports(m).map((i) => `${i.module} ${i.name}${i.kind === "function" ? "" : " " + i.kind}`);
const want = fs.readFileSync("wasm-imports.txt", "utf8").split("\n").filter((l) => l !== "" && !l.startsWith("#"));
const extra = got.filter((x) => !want.includes(x));
const missing = want.filter((x) => !got.includes(x));
if (extra.length + missing.length > 0 || new Set(got).size !== want.length) {
  for (const x of extra) console.error("sdk: imported, not in wasm-imports.txt: " + x);
  for (const x of missing) console.error("sdk: in wasm-imports.txt, not imported: " + x);
  if (got.some((x) => !x.startsWith("wbg "))) {
    console.error("sdk: an import from outside wbg is a symbol the link left unresolved (is AR_wasm32_unknown_unknown an LLVM archiver?)");
  }
  process.exit(1);
}' || fail "the built module's imports differ from wasm-imports.txt"
node -e '
const bytes = require("fs").readFileSync("npm/pkg/impulse_wasm_bg.wasm");
const found = process.argv.slice(1).filter((path) => bytes.includes(path));
if (found.length > 0) { console.error("sdk: the module holds " + found.join(", ")); process.exit(1); }
' /Use""rs/ /ho""me/ "$HOME/" "$cargo_home" "$repo" || fail "the built module holds a build machine path"

echo "sdk: native oracle build"
# The TypeScript trade tests run the same calls natively (ops_tests::oracle) and compare the
# answers; build that test binary here so a compile error is reported as one, and not as a
# failed TypeScript test.
cargo test --locked -p impulse-wasm --lib --no-run

echo "sdk: TypeScript type check and tests"
cd npm
npm ci --ignore-scripts --no-audit --no-fund
npm audit --audit-level=high || fail "npm audit found a vulnerability of high severity or worse in the dev dependencies"
./node_modules/.bin/tsc -p tsconfig.json
# The suite runs with rng-count.mjs preloaded in every test process: the module draws randomness
# for one thing, the key of Wallet.generate, and the tests count the keys they ask for; a process
# whose count of draws differs from its count of keys fails here.
NODE_OPTIONS="--import $(cd .. && pwd -P)/rng-count.mjs" RNG_COUNT_FILE="$tmp/rng-calls.txt" \
  node --test --test-reporter=tap "test/*.test.ts" | tee "$tmp/ts-test.log"
for line in "# tests $TS_TESTS" "# pass $TS_TESTS" "# fail 0" "# cancelled 0" "# skipped 0" "# todo 0"; do
  grep -qxF "$line" "$tmp/ts-test.log" || fail "the TypeScript suite did not report '$line'"
done
test_files=$(ls test/*.test.ts | wc -l | tr -d ' ')
[ "$(wc -l <"$tmp/rng-calls.txt" | tr -d ' ')" = "$test_files" ] \
  || fail "rng-count.mjs reported for $(wc -l <"$tmp/rng-calls.txt" | tr -d ' ') processes, not the $test_files test files"
awk '{
  if ($2 != "control=1" || $3 !~ /getRandomValues/ || $3 !~ /randomFillSync/) bad = 1
  split($4, e, "="); if ($1 != e[2]) bad = 1
  if ($1 > 0) drew = 1
} END { exit (bad || !drew) }' "$tmp/rng-calls.txt" \
  || fail "a test process drew randomness it did not ask for (or none drew, so the count proves nothing): $(sort "$tmp/rng-calls.txt" | uniq -c)"

echo "sdk: package contents and a consumer install"
# The package ships the repository's licence and notice; the copies are git-ignored.
cp ../../../LICENSE ../../../NOTICE .
repository=$(sed -nE 's/^repository = "(.*)"$/\1/p' ../../../Cargo.toml)
node -e '
const p = JSON.parse(require("fs").readFileSync("package.json", "utf8"));
const r = process.argv[1];
if (!r || p.repository.url !== r || p.homepage !== r || p.bugs.url !== r + "/issues") process.exit(1);
' "$repository" || fail "package.json repository, homepage and bugs must name the workspace repository $repository"
npm pack --pack-destination "$tmp" --json >"$tmp/pack.json"
node -e '
const [pack] = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
const files = pack.files.map((f) => f.path).sort().join(" ");
const want = ["LICENSE", "NOTICE", "README.md", "index.d.ts", "index.js", "package.json", "pkg/impulse_wasm.d.ts",
  "pkg/impulse_wasm.js", "pkg/impulse_wasm_bg.wasm", "pkg/impulse_wasm_bg.wasm.d.ts"].join(" ");
if (files !== want) { console.error("packed: " + files); process.exit(1); }
' "$tmp/pack.json" || fail "the packed package does not hold exactly its files"
vector="$(cd ../../.. && pwd)/tests/vectors/terms/01-vault-authority-earmarked-kcc20-kcc20.json"
(
  cd "$tmp"
  echo '{"name": "consumer", "private": true, "type": "module"}' >package.json
  npm install --ignore-scripts --no-audit --no-fund ./*.tgz >/dev/null
  node --input-type=module -e '
import { readFileSync } from "node:fs";
import { initSync, ipstVersion, Terms } from "@warpcore/impulse";
initSync({ module: readFileSync(new URL(import.meta.resolve("@warpcore/impulse/impulse_wasm_bg.wasm"))) });
const v = JSON.parse(readFileSync(process.argv[1], "utf8"));
if (Buffer.from(Terms.fromJson(v.terms).termsHash()).toString("hex") !== v.terms_hash) process.exit(1);
if (ipstVersion() !== 1) process.exit(3);
try {
  await import("@warpcore/impulse/pkg/impulse_wasm.js");
  process.exit(2);
} catch (e) {
  if (e.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw e;
}
' "$vector"
) || fail "a consumer could not install and use the packed package"

echo "sdk: green"
