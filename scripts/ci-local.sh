#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Local CI gate, mirrored by .github/workflows/ci.yml. Every step is blocking.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

step() { printf '\n==> %s\n' "$1"; }
fail() { echo "ci-local: FAIL: $1" >&2; exit 1; }
# Checks of the owner's own run scripts live in a private-only hook that the public tree does not
# hold. Where it is absent each section is skipped with this message; the private checkout runs it.
private_checks() {
  local hook="scripts/ci-pri""vate.sh"
  if [ -x "$hook" ]; then
    "$hook" "$1" || fail "private checks, section $1"
  else
    echo "skipped: the owner's own run scripts are not in this tree (section $1)"
  fi
}

RK_SRC='git+https://github.com/kaspanet/rusty-kaspa?rev=a41a333b08848f41bf737b72592e463a6011b8ac#a41a333b08848f41bf737b72592e463a6011b8ac'
SS_SRC='git+https://github.com/kaspanet/silverscript?tag=v1.0.0#3ed973335b59269293564805cc2c58a14595ec03'

step "pins (rules 2 and 3, docs/ENGINEERING-RULES.md)"
# Only the two pinned git sources may appear in the lock file.
bad_src=$(grep '^source = "git+' Cargo.lock | grep -vF "source = \"$RK_SRC\"" | grep -vF "source = \"$SS_SRC\"" || true)
[ -z "$bad_src" ] || fail "unpinned git source in Cargo.lock: $bad_src"
# Exactly one kaspa-txscript: cargo tree errors on an ambiguous spec if there are two.
cargo tree --locked -i kaspa-txscript --depth 0 --edges normal,build,dev | grep -qF 'rev=a41a333b08848f41bf737b72592e463a6011b8ac' \
  || fail "kaspa-txscript is not exactly one package at the pinned rev"
# Every package must come from crates.io, one of the two pinned git sources, or a path
# inside this repository; no package may be a WarpCore crate. cargo metadata sees through
# quoting styles, [patch] and .cargo/config overrides.
cargo metadata --locked --format-version 1 | RK_SRC="$RK_SRC" SS_SRC="$SS_SRC" ROOT="$(pwd -P)" python3 -c '
import json, os, sys
m = json.load(sys.stdin)
ok = {"registry+https://github.com/rust-lang/crates.io-index", os.environ["RK_SRC"], os.environ["SS_SRC"]}
root = os.environ["ROOT"] + os.sep
bad = []
for p in m["packages"]:
    if "warpcore" in p["name"].lower():
        bad.append("WarpCore crate " + p["name"])
    if p["source"] is None:
        if not os.path.realpath(p["manifest_path"]).startswith(root):
            bad.append("path dependency outside the repository: " + p["manifest_path"])
    elif p["source"] not in ok:
        bad.append("unpinned source " + p["source"] + " for " + p["name"])
if bad:
    sys.exit("\n".join(bad))
' || fail "dependency sources (rules 2 and 3)"

step "mutation record matches the contract (I3)"
# tests/engine/mutation-run.txt must record a full catch for the current contract source and
# TEMPLATE_HASH; rerun `python3 tests/engine/mutation.py --record` after any contract change.
python3 - <<'PY' || fail "tests/engine/mutation-run.txt does not match contracts/impulse_vault.sil and contracts/TEMPLATE_HASH, or records a miss"
import hashlib, re, sys
record = open("tests/engine/mutation-run.txt").read()
source = hashlib.sha256(open("contracts/impulse_vault.sil", "rb").read()).hexdigest()
template = open("contracts/TEMPLATE_HASH").read().strip()
tagged = len(re.findall(r"require\(.*//\s*\[[A-Z][0-9]+\]\s*$", open("contracts/impulse_vault.sil").read(), re.M))
result = re.search(r"^result: (\d+) of (\d+) requires caught by their named test$", record, re.M)
extra = re.search(r"^extra: (\d+) of (\d+) mutants of \[S10\]'s condition and slot caught by their named test$", record, re.M)
ok = (
    re.search(r"^source sha256 %s$" % source, record, re.M)
    and re.search(r"^TEMPLATE_HASH %s$" % template, record, re.M)
    and result
    and result.group(1) == result.group(2) == str(tagged)
    and extra
    and extra.group(1) == extra.group(2)
)
sys.exit(0 if ok else 1)
PY

step "mutation record matches the watcher (I8)"
# crates/impulse-watch/mutation-run.txt must record every mutant of scripts/watch-mutation.py
# caught, for the current watcher source and mutant list; rerun
# `python3 scripts/watch-mutation.py --record` after any change to crates/impulse-watch/src.
python3 scripts/watch-mutation.py --check \
  || fail "crates/impulse-watch/mutation-run.txt is stale or records a survivor"

step "mutation record matches the CLI (I7)"
# crates/impulse-cli/mutation-run.txt must record every mutant of scripts/cli-mutation.py
# caught, for the current CLI source and mutant list; rerun
# `python3 scripts/cli-mutation.py --record` after any change to crates/impulse-cli/src.
python3 scripts/cli-mutation.py --check \
  || fail "crates/impulse-cli/mutation-run.txt is stale or records a survivor"

step "mutation record matches the impulse frost commands (I13)"
# crates/impulse-cli/frost-mutation-run.txt must record every mutant of scripts/frost-mutation.py
# caught, for the current FROST CLI source and tests and the current mutant list; rerun
# `python3 scripts/frost-mutation.py --record` after any change to the files it lists.
python3 scripts/frost-mutation.py --check \
  || fail "crates/impulse-cli/frost-mutation-run.txt is stale or records a survivor"

step "template rebuild matches TEMPLATE_HASH (I4)"
# Compiles contracts/impulse_vault.sil with silverc built from the pinned silverscript v1.0.0
# (installed once under target/silverc-v1.0.0, then reused) and fails unless the output is
# the committed artifact byte for byte and its template hash is contracts/TEMPLATE_HASH.
# impulse-core embeds that artifact and checks it against TEMPLATE_HASH at startup.
scripts/build-template.sh
scripts/build-template-v2.sh || fail "scripts/build-template-v2.sh (template v2, TEMPLATE_HASH_V2)"; python3 tests/engine/v2_mutation.py --check || fail "tests/engine/mutation-run-v2.txt does not match contracts/impulse_vault_v2.sil and TEMPLATE_HASH_V2, or records a miss"
# spec/TEMPLATE.md names the template hashes it specifies (templates v1, v2, v3 and the hashlock
# template); they must be exactly the pinned ones.
pinned=$(cat contracts/TEMPLATE_HASH contracts/TEMPLATE_HASH_V2 contracts/TEMPLATE_HASH_V3 contracts/TEMPLATE_HASH_HASHLOCK \
  | sort -u | tr '\n' ' ' | sed 's/ $//')
named=$( (grep -oE '[0-9a-f]{64}' spec/TEMPLATE.md || true) | sort -u | tr '\n' ' ' | sed 's/ $//')
[ "$named" = "$pinned" ] || fail "spec/TEMPLATE.md names template hashes '$named', the pins are '$pinned'"

step "template v3 rebuild matches TEMPLATE_HASH_V3, v1 unchanged (I20)"
# Compiles contracts/impulse_vault_v3.sil with the same pinned silverc, checks the committed
# artifact and contracts/TEMPLATE_HASH_V3, and that IMAGE_ID in the source is circuits/IMAGE_ID.
# Template v1 is checked by the step above and is not touched.
scripts/build-template-v3.sh

step "mutation record matches template v3 (I20)"
# tests/engine/mutation-run-v3.txt must record a full catch for the current v3 source and
# TEMPLATE_HASH_V3; rerun `python3 tests/engine/mutation-v3.py --record` after any change to
# contracts/impulse_vault_v3.sil.
python3 - <<'PY' || fail "tests/engine/mutation-run-v3.txt does not match contracts/impulse_vault_v3.sil and contracts/TEMPLATE_HASH_V3, or records a miss"
import hashlib, re, sys
record = open("tests/engine/mutation-run-v3.txt").read()
source = hashlib.sha256(open("contracts/impulse_vault_v3.sil", "rb").read()).hexdigest()
template = open("contracts/TEMPLATE_HASH_V3").read().strip()
tagged = len(re.findall(r"require\(.*//\s*\[[A-Z][0-9]+\]\s*$", open("contracts/impulse_vault_v3.sil").read(), re.M))
result = re.search(r"^result: (\d+) of (\d+) mutants caught by their named test$", record, re.M)
counts = re.search(r"^require mutants (\d+), gate and \[S10\] mutants (\d+)$", record, re.M)
ok = (
    re.search(r"^source sha256 %s$" % source, record, re.M)
    and re.search(r"^TEMPLATE_HASH_V3 %s$" % template, record, re.M)
    and result
    and counts
    and int(counts.group(1)) == tagged
    and result.group(1) == result.group(2) == str(int(counts.group(1)) + int(counts.group(2)))
)
sys.exit(0 if ok else 1)
PY

step "template v3 shipped-bytecode coverage and the real-proof run record (I20)"
# Every tag of contracts/impulse_vault_v3.sil has a failing test on the shipped bytecode
# (tests/engine/V3-SHIPPED-COVERAGE.md), and the two real-proof authority settle tests
# (tests/engine/v3_live.rs, minutes and Docker, so run by scripts/ci-zk.sh) have a recorded pass
# for the current contract, image ID and test source.
python3 scripts/check-v3-shipped-coverage.py || fail "tests/engine/V3-SHIPPED-COVERAGE.md is stale"
scripts/check-v3-live-record.sh || fail "tests/engine/v3-live-run.txt is stale: run scripts/ci-zk.sh"

step "template v4 rebuild matches TEMPLATE_HASH_V4, v1 and v3 unchanged (I21)"
# Compiles contracts/impulse_vault_v4.sil with the same pinned silverc, checks the committed
# artifact and contracts/TEMPLATE_HASH_V4, and that IMAGE_ID in the source is circuits/IMAGE_ID_V4.
# Templates v1 and v3 are checked by the steps above and are not touched.
scripts/build-template-v4.sh

step "mutation record matches template v4, and the real-receipt run record (I21)"
# tests/engine/mutation-run-v4.txt must record a full catch for the current v4 source and
# TEMPLATE_HASH_V4; rerun `python3 tests/engine/mutation-v4.py --record` after any change to
# contracts/impulse_vault_v4.sil. The five real-receipt tests (tests/engine/v4_live.rs, minutes
# per proof and Docker, so run by scripts/ci-zk.sh) have a recorded pass for the current contract,
# image ID and test source.
python3 - <<'PY' || fail "tests/engine/mutation-run-v4.txt does not match contracts/impulse_vault_v4.sil and contracts/TEMPLATE_HASH_V4, or records a miss"
import hashlib, re, sys
record = open("tests/engine/mutation-run-v4.txt").read()
source = hashlib.sha256(open("contracts/impulse_vault_v4.sil", "rb").read()).hexdigest()
template = open("contracts/TEMPLATE_HASH_V4").read().strip()
tagged = len(re.findall(r"require\(.*//\s*\[[A-Z][0-9]+\]\s*$", open("contracts/impulse_vault_v4.sil").read(), re.M))
result = re.search(r"^result: (\d+) of (\d+) mutants caught by their named test$", record, re.M)
counts = re.search(r"^require mutants (\d+), other mutants (\d+)$", record, re.M)
equiv = re.search(r"^equivalent mutants .*: (\d+)$", record, re.M)
ok = (
    re.search(r"^source sha256 %s$" % source, record, re.M)
    and re.search(r"^TEMPLATE_HASH_V4 %s$" % template, record, re.M)
    and result
    and counts
    and int(counts.group(1)) == tagged
    and result.group(1) == result.group(2)
    and int(result.group(2)) + int(equiv.group(1)) >= int(counts.group(1)) + int(counts.group(2))
    and "NOT FLIPPED" not in record
)
sys.exit(0 if ok else 1)
PY
scripts/check-v4-live-record.sh || fail "tests/engine/v4-live-run.txt is stale: run scripts/ci-zk.sh"

step "fmt"
cargo fmt --all -- --check

step "clippy -D warnings"
cargo clippy --locked --workspace --all-targets -- -D warnings

step "impulse-core default build is keyless (I13)"
# impulse_core::threshold holds a FROST party's share and nonces; it is behind the non-default
# `threshold` feature, so default impulse-core, which the WASM SDK and the watcher build on, links
# none of it. Control: with the feature, frost-secp256k1-tr is linked. The default build also
# lints clean on its own (the workspace build turns the feature on for tests/engine).
default_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none)
featured_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none --features threshold)
if grep -qE '^frost-' <<<"$default_tree"; then fail "default impulse-core links a frost crate"; fi
grep -qE '^frost-secp256k1-tr ' <<<"$featured_tree" \
  || fail "control: impulse-core --features threshold does not link frost-secp256k1-tr"
cargo clippy --locked -p impulse-core --all-targets -- -D warnings

step "test"
cargo test --locked --workspace

step "the offline fake node feature of the CLI (I7)"
# The test-only cargo feature `offline-fake-node` (off by default, absent from release builds)
# gives a fake node that runs every submitted input in the pinned script engine. Its code is
# linted here; the script tests below run against it.
cargo clippy --locked -p impulse-cli --features offline-fake-node --all-targets -- -D warnings
private_checks cli

step "FROST scripts, offline self-test (I13)"
private_checks frost

step "list-gated settle: the zk feature of impulse-core and impulse-cli (I20)"
# impulse_core::zk (terms v3, issuer lists, manifests, template v3, the v3 builders, IPST version 4,
# the verifier) is behind the non-default `zk` feature, so default impulse-core, which the WASM SDK
# and the watcher build on, links neither the proof parser nor the v3 builders. Control: with the
# feature, ark-groth16 is linked. The feature's tests run real Groth16 proofs (the ones committed
# under crates/impulse-core/src/zk/testdata, remade by scripts/regen-zk-core-fixtures.sh) through
# the pinned script engine, in core and through the command line against the offline fake node.
# The pinned kaspa-txscript links ark-groth16 for its own precompile, so the check is on
# impulse-core's DIRECT dependencies (depth 1), where only the feature adds ark-groth16.
default_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none --depth 1)
zk_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none --depth 1 --features zk)
if grep -qE '^ark-groth16 ' <<<"$default_tree"; then fail "default impulse-core depends on ark-groth16"; fi
grep -qE '^ark-groth16 ' <<<"$zk_tree" || fail "control: impulse-core --features zk does not depend on ark-groth16"
cargo clippy --locked -p impulse-core -p impulse-cli --features impulse-cli/zk --all-targets -- -D warnings
cargo test --locked -p impulse-core -p impulse-cli --features impulse-cli/zk zk

step "list-gated settle: scripts and wording (I20)"
# scripts/check-zk-text.sh enforces spec/V3-ZK.md section 9.5 on the README's v3 section, the help
# and the offline command output, after a self-test that each banned phrase, each missing fixed
# text and an unsourced figure are caught.
private_checks zk
scripts/check-zk-text.sh --self-test
scripts/check-zk-text.sh

step "hashed-terms scripts: caps, pins, stages (I21)"
private_checks zkh

step "hashed-terms vault verifier: the zk-hashed feature, tag parity, wording (I21)"
# impulse_core::zkh (template v4 instantiation, state decode, the host check of a revealed trade,
# the v4 builders and IPST version 5) and the `impulse zk` v4 commands are behind non-default features, so
# default impulse-core links no terms-core. Control: with the feature, it does. Every v1 tag has a
# home in v4 (scripts/check-tag-parity-v4.sh); the fixed texts and banned words of 22.11 are checked
# after a self-test. The engine tests against the shipped template are run by the workspace test.
default_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none --depth 1)
zkh_tree=$(cargo tree --locked -p impulse-core -e normal --prefix none --depth 1 --features zk-hashed)
if grep -qE '^impulse-terms-core ' <<<"$default_tree"; then fail "default impulse-core depends on impulse-terms-core"; fi
grep -qE '^impulse-terms-core ' <<<"$zkh_tree" || fail "control: impulse-core --features zk-hashed does not depend on impulse-terms-core"
cargo clippy --locked -p impulse-core --features zk-hashed --all-targets -- -D warnings
cargo test --locked -p impulse-core --features zk-hashed --lib zkh
cargo test --locked -p impulse-cli --features zk --lib zkh
cargo test --locked -p impulse-terms-core
scripts/check-tag-parity-v4.sh || fail "scripts/check-tag-parity-v4.sh"
scripts/check-zk-text-v4.sh --self-test
scripts/check-zk-text-v4.sh

step "parity (PARITY.md generated from the parity tests, I10)"
# First the generator's own refusals, offline (tests/parity/test_gen_parity.py; its --mutate mode,
# run by hand, proves every fail() call is caught). Then rerun tests/parity and fail unless every
# Solana item is answered by a passing tagged test or marked pending, every contract tag a row
# cites fails its test in the recorded mutation run (tests/parity/mutation-run.json, rerun by
# hand with --mutate-contract), and the committed PARITY.md is exactly what the tests generate.
python3 tests/parity/test_gen_parity.py
scripts/gen-parity.sh --check

step "cargo audit"
command -v cargo-audit >/dev/null || fail "cargo-audit not installed"
cargo audit --deny warnings  # known advisories are ignored one by one in .cargo/audit.toml

step "cargo deny (licences, bans, sources, advisories; deny.toml, I14)"
command -v cargo-deny >/dev/null || fail "cargo-deny not installed (cargo install cargo-deny --version 0.19.9 --locked)"
# One list of accepted advisories: deny.toml must ignore exactly what .cargo/audit.toml ignores.
python3 - <<'PY2' || fail "deny.toml [advisories] ignore differs from .cargo/audit.toml"
import re, sys
def ids(path):
    text = open(path).read()
    block = re.search(r"^ignore = \[(.*?)^\]", text, re.M | re.S)
    return sorted(re.findall(r'"(RUSTSEC-\d{4}-\d{4})"', block.group(1))) if block else None
a, d = ids(".cargo/audit.toml"), ids("deny.toml")
sys.exit(0 if a and a == d else "audit.toml %s, deny.toml %s" % (a, d))
PY2
cargo deny --locked check --hide-inclusion-graph

step "version strings and CHANGELOG (I14)"
# The workspace version is the version of the npm SDK, of the demo's test package and of the
# newest CHANGELOG.md section.
python3 - <<'PY2' || fail "version strings disagree"
import json, re, sys
cargo = re.search(r'^\[workspace\.package\]\n(?:.*\n)*?version = "([^"]+)"', open("Cargo.toml").read(), re.M).group(1)
found = {"Cargo.toml": cargo}
for p in ("crates/impulse-wasm/npm/package.json", "crates/impulse-wasm/npm/package-lock.json",
          "demo/package.json", "demo/package-lock.json"):
    d = json.load(open(p))
    found[p] = d["version"]
    if "packages" in d:
        found[p + ' packages[""]'] = d["packages"][""]["version"]
head = re.search(r"^## \[?([0-9][^\] ]*)\]?(?: |$)", open("CHANGELOG.md").read(), re.M)
found["CHANGELOG.md"] = head.group(1) if head else None
bad = {k: v for k, v in found.items() if v != cargo}
sys.exit("expected %s: %s" % (cargo, bad) if bad else 0)
PY2

step "release build script self-test (I14; the full reproducible build is scripts/test-release.sh --full)"
scripts/test-release.sh

step "public export script self-test (docs/release/PUBLIC-TREE.md)"
scripts/test-export-public.sh

step "gitleaks (history, then the working tree including untracked files)"
command -v gitleaks >/dev/null || fail "gitleaks not installed"
# History of the checked-out branch only: other unmerged branches are not this branch's history.
gitleaks git --no-banner --redact --log-opts=HEAD .
wt=$(mktemp -d); trap 'rm -rf "$wt"' EXIT
git ls-files -co --exclude-standard -z | xargs -0 tar -cf - | tar -xf - -C "$wt"
gitleaks dir --no-banner --redact --config .gitleaks.toml "$wt"

step "hashlock template rebuild and mutation record (I18)"
# Compiles contracts/impulse_hashlock.sil with the same pinned silverc and fails unless the output
# is the committed artifact byte for byte and its template hash is contracts/TEMPLATE_HASH_HASHLOCK;
# then fails unless tests/engine/mutation-run-htlc.txt records every tagged require of the current
# source caught by its named engine test (rerun `python3 tests/engine/htlc_mutation.py --record`).
scripts/build-template-hashlock.sh
python3 tests/engine/htlc_mutation.py --check

step "xchain scripts against the offline fake node and the fake counterpart source (I18)"
# scripts/sample-daa.sh (read-only DAA sampling) against the CLI built with the test-only feature
# `offline-fake-node`. No network.
scripts/test-sample-daa.sh || fail "scripts/test-sample-daa.sh"
private_checks xchain

step "vectors (frozen against main, regenerated, decoded independently)"
command -v python3 >/dev/null || fail "python3 not installed"
if [ -n "${CI:-}" ] && [ -n "${IMPULSE_VECTORS_BASE:-}" ]; then
  fail "IMPULSE_VECTORS_BASE must not be set in CI"
fi
scripts/vectors.sh

step "SDK: wasm32 clippy, wasm-pack test --node, npm package, TypeScript type check and tests (I9)"
# Pins wasm-bindgen CLI to the crate in Cargo.lock and wasm-pack to 0.14.0, needs Node 22.18 or
# later and an LLVM clang and llvm-ar; see crates/impulse-wasm/ci.sh.
crates/impulse-wasm/ci.sh

step "demo: static site build and headless browser tests (I11)"
# Builds demo/dist from the SDK of the step above (no CDN: the SDK is bundled), then drives the
# pages in headless Chrome or Chromium (set IMPULSE_BROWSER if it is not at a usual path):
# addresses, hashes, funding URIs and QR codes against the golden vectors, the value cap, the
# mainnet switch, the page's Content-Security-Policy and its network traffic; see demo/ci.sh.
demo/ci.sh

step "visual demo: driver server, replay file, events feed without secrets (I11)"
# Standard library only, no network: demo/visual/test_server.py (the driver's refusals and run control,
# the replay file against its run log where one is in the tree, the secret check).
python3 -I demo/visual/test_server.py || fail "demo/visual/test_server.py"
private_checks localnet

step "release dry-run self-test (I12)"
# Fixture-based test of the release dry run: one refusal and one accepted control per
# finding code, the run contract (exit 0, a summary, no crash) on every run, and the gates
# (--gate kgpr, public, tag and --strict) against resolved trees. The notes fixtures are copies
# of the committed template.
# The real-npm controls need npm, which the CI image does not have (carried to I9, which adds
# the first package.json): the final line of the test says whether they ran.
# The release dry run checks the owner's release documents, which the public tree does not hold,
# so the public export drops it and its self-test (docs/release/PUBLIC-TREE.md). Where the
# script is absent both steps are skipped, with this message; the private tree runs them. The
# names are built from fragments because the public tree may not name them.
dry_script="scripts/release-dry""run.sh"
dry_test="scripts/test-release-dry""run.sh"
if [ -f "$dry_script" ]; then
  "$dry_test"
else
  echo "skipped: the release dry run is not in this tree (private-only)"
fi

step "release dry-run on the real tree, documents only (I12, report only)"
# A report, not a gate: the dry run prints every finding (PROBLEM lines are defects in a release
# document or in wording, PENDING lines are owner-gated items) and this step never fails on them.
# It fails only if the report itself breaks (a non-zero exit, or no summary). Failing on PROBLEM
# lines is a scope change for every branch, because the wording screens also read files that
# other changes own (README, PARITY.md, spec/, demo/); that needs the owner's approval, and the
# screens should first run clean on every branch (carried to I12 phase 2). The opt-in gates (--gate, --strict) and
# the packaging checks are not run here.
if [ -f "$dry_script" ]; then
dry=$("$dry_script" --docs-only) || fail "the release dry run (--docs-only) did not exit 0"
grep -E '^(PROBLEM|problems:|pending \()' <<<"$dry" || true
grep -q '^problems: [0-9]' <<<"$dry" || fail "the release dry-run printed no summary"
else
  echo "skipped: the release dry run is not in this tree (private-only)"
fi

step "documentation: CLI reference current, rustdoc warning-free, relative links resolve"
# docs/reference/CLI.md is generated from the real --help output (scripts/gen-cli-reference.sh;
# rerun it after any change to a command or flag). rustdoc runs with -D warnings on impulse-core and
# impulse-cli; two lints are allowed because their sources are doc comments that clap also prints as
# --help text (`<hex>` placeholders read as HTML tags) or that the mutation records hash.
scripts/gen-cli-reference.sh --check || fail "docs/reference/CLI.md is stale"
RUSTDOCFLAGS="-D warnings -A rustdoc::invalid_html_tags -A rustdoc::private_intra_doc_links" \
  cargo doc --no-deps --locked -p impulse-core -p impulse-cli
scripts/check-doc-links.sh || fail "broken relative link or anchor in a Markdown file"

step "licence headers"
# Third-party fixtures under tests/engine/fixtures/ keep their upstream licence (see NOTICE).
header="^[[:space:]]*(//!?|#|/?\*|<!--)[[:space:]]*Copyright \(c\) 20[0-9]{2} the Impulse authors\. A KiiLabs product\. Licensed under the Apache License, Version 2\.0\."
missing=""
while IFS= read -r -d '' f; do
  [ -f "$f" ] || fail "unreadable path in licence scan: $f"
  head -n 5 "$f" | grep -qE "$header" || missing="$missing $f"
done < <(git ls-files -co --exclude-standard -z -- '*.rs' '*.sh' '*.sil' '*.ts' '*.tsx' '*.js' '*.jsx' '*.mjs' '*.cjs' '*.py' '*.html' '*.css' ':!tests/engine/fixtures/**')
[ -z "$missing" ] || fail "missing licence header:$missing"
# Solana workspace (I19): code derived from solana-foundation/dvp (MIT) keeps the upstream notice.
# A derived file says "Derived from solana-foundation/dvp" in its first 5 lines and must then
# carry the upstream copyright and point at solana/LICENSE-MIT; the MIT text and the NOTICE entry must be present.
if [ -d solana ]; then
  grep -qF "Copyright (c) 2026 Solana Foundation" solana/LICENSE-MIT 2>/dev/null \
    || fail "solana/LICENSE-MIT with the upstream MIT notice is missing"
  grep -qF "solana-foundation/dvp" NOTICE || fail "NOTICE does not attribute solana-foundation/dvp"
  bad_mit=""
  while IFS= read -r -d '' f; do
    h=$(head -n 5 "$f")
    grep -qF "Derived from solana-foundation/dvp" <<<"$h" || continue
    { grep -qF "Copyright (c) 2026 Solana Foundation" <<<"$h" && grep -qF "LICENSE-MIT" <<<"$h"; } \
      || bad_mit="$bad_mit $f"
  done < <(git ls-files -co --exclude-standard -z -- 'solana/**')
  [ -z "$bad_mit" ] || fail "derived from solana-foundation/dvp without the MIT notice:$bad_mit"
fi

echo
echo "ci-local: green"
