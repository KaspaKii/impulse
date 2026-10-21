#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# CI gate for the I20 circuits workspace (circuits/, its own cargo workspace, D60). Every step is
# blocking. Needs a running Docker daemon: the guests build in RISC Zero's guest-builder image and
# the Groth16 step runs in RISC Zero's prover image, both pinned by digest.
#   scripts/ci-zk.sh           everything, including one real proof end to end (a few minutes)
#   scripts/ci-zk.sh --quick   everything except the real proof
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)
quick=0; [ "${1:-}" = "--quick" ] && quick=1

step() { printf '\n==> %s\n' "$1"; }
fail() { echo "ci-zk: FAIL: $1" >&2; exit 1; }

source circuits/scripts/env.sh
RK_SRC='git+https://github.com/kaspanet/rusty-kaspa?rev=a41a333b08848f41bf737b72592e463a6011b8ac#a41a333b08848f41bf737b72592e463a6011b8ac'

step "Docker and the pinned Groth16 prover image"
docker info >/dev/null 2>&1 || fail "Docker daemon not running"
case "$(uname -m)" in arm64|aarch64) plat=linux/arm64 ;; x86_64) plat=linux/amd64 ;; *) fail "unsupported host" ;; esac
digest=$(grep "^$plat=" circuits/GROTH16_PROVER_IMAGE | cut -d= -f2)
image=$(grep '^image=' circuits/GROTH16_PROVER_IMAGE | cut -d= -f2)
[ -n "$digest" ] || fail "circuits/GROTH16_PROVER_IMAGE has no digest for $plat"
# Pulling by digest is content-addressed: Docker refuses content that does not match.
docker image inspect "$image@$digest" >/dev/null 2>&1 || docker pull "$image@$digest" >/dev/null \
  || fail "cannot pull $image@$digest"

step "pins (rule 3, docs/ENGINEERING-RULES.md; spec/V3-ZK.md 3.4, 3.6)"
cd circuits
bad_src=$(grep '^source = "git+' Cargo.lock | grep -vF "source = \"$RK_SRC\"" || true)
[ -z "$bad_src" ] || fail "unpinned git source in circuits/Cargo.lock: $bad_src"
for lock in Cargo.lock list-guest/Cargo.lock terms-guest/Cargo.lock test-guests/forge-guest/Cargo.lock; do
  v=$(grep -A1 '^name = "risc0-zkvm"$' "$lock" | sed -n 's/^version = "\(.*\)"/\1/p' | sort -u | tr '\n' ' ')
  [ "$v" = "3.0.4 " ] || fail "$lock resolves risc0-zkvm '$v', not exactly 3.0.4"
done
for c in risc0-groth16 risc0-binfmt; do
  v=$(grep -A1 "^name = \"$c\"\$" Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p' | sort -u | tr '\n' ' ')
  [ "$v" = "3.0.4 " ] || fail "circuits/Cargo.lock resolves $c '$v', not exactly 3.0.4"
done
# risc0-zkvm 3.0.4 asks for risc0-circuit-rv32im ^4.0.3, but 4.0.4 changed the SyscallContext API
# and 3.0.4's executor no longer compiles against it (measured, run: cargo build, E0038 and E0049
# in risc0-zkvm-3.0.4/src/host/server/exec/executor.rs). The lock holds 4.0.3.
v=$(grep -A1 '^name = "risc0-circuit-rv32im"$' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p' | sort -u | tr '\n' ' ')
[ "$v" = "4.0.3 " ] || fail "circuits/Cargo.lock resolves risc0-circuit-rv32im '$v', not exactly 4.0.3"
cargo tree --locked -i kaspa-txscript --depth 0 | grep -qF 'rev=a41a333b08848f41bf737b72592e463a6011b8ac' \
  || fail "kaspa-txscript is not exactly one package at the pinned rev"
if grep -qi warpcore Cargo.lock; then fail "WarpCore crate in circuits/Cargo.lock"; fi

step "fmt"
cargo fmt --all -- --check
for g in list-guest terms-guest test-guests/forge-guest; do cargo fmt --manifest-path "$g/Cargo.toml" -- --check; done

step "clippy -D warnings"
cargo clippy --locked --workspace --all-targets --features impulse-zk-prover/fixtures -- -D warnings
cargo clippy --locked -p impulse-list-core --all-targets --features std,test-hook -- -D warnings
cargo clippy --locked -p impulse-list-core -- -D warnings  # no_std build, as the guest uses it

step "list-core unit tests (std, test hook)"
cargo test --locked -p impulse-list-core --features std,test-hook

step "guest host tests and committed fixtures in the pinned engine"
cargo test --locked --workspace

step "guest image ID reproduces (scripts/build-guest.sh)"
cd "$root"
scripts/build-guest.sh

step "vendored risc0-zkvm is the registry source plus the recorded patch and nothing else"
(
  cd circuits/patches
  shasum -a 256 -c risc0-zkvm-3.0.4-prove.patch.sha256 >/dev/null || fail "the patch differs from its recorded SHA-256"
)
reg_src=$(ls -d "$HOME"/.cargo/registry/src/*/risc0-zkvm-3.0.4 2>/dev/null | head -1 || true)
[ -n "$reg_src" ] || fail "risc0-zkvm-3.0.4 not in the cargo registry"
chk=$(mktemp -d)
cp -R "$reg_src" "$chk/expected"; rm -f "$chk/expected/.cargo-ok"
patch -s -p1 -d "$chk/expected" < circuits/patches/risc0-zkvm-3.0.4-prove.patch
diff -r -x .patched -x .cargo-ok "$chk/expected" circuits/vendor/risc0-zkvm-3.0.4 >/dev/null \
  || { rm -rf "$chk"; fail "circuits/vendor/risc0-zkvm-3.0.4 differs from the registry source plus the recorded patch"; }
rm -rf "$chk"

step "committed proof fixtures recompute and verify (regen-fixtures.sh --check)"
circuits/scripts/regen-fixtures.sh --check

step "committed v4 receipts are accepted by the pinned engine (regen-fixtures-v4.sh --check)"
scripts/regen-fixtures-v4.sh --check

if [ "$quick" = 0 ]; then
  step "one real proof end to end (impulse-zk-prove, list of one entry)"
  (cd circuits && cargo build --release --locked -p impulse-zk-prover --bin impulse-zk-prove)
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  fx=tests/engine/fixtures/v3/proofs/a_list1.inputs.json
  read -r r v o < <(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); json.dump(d["path"], open(sys.argv[2],"w")); print(d["root"], d["vault_spk"], d["owner_spk"])' "$fx" "$tmp/path.json")
  circuits/target/release/impulse-zk-prove --path "$tmp/path.json" --root "$r" --vault-spk "$v" --owner-spk "$o" \
    --out "$tmp/proof.json" --timings "$tmp/t.json"
  python3 -I -c 'import json,sys; a=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2])); assert a["journal"]==b["journal"] and a["image_id"]==b["image_id"] and len(a["proof"])==256' \
    "$tmp/proof.json" tests/engine/fixtures/v3/proofs/a_list1.proof.json || fail "fresh proof differs in journal or image ID"
  # A non-member is refused before any proving, with its code.
  python3 -I -c 'import json,sys; p=json.load(open(sys.argv[1])); p["salt"]="00"*32; json.dump(p, open(sys.argv[1],"w"))' "$tmp/path.json"
  if out=$(circuits/target/release/impulse-zk-prove --path "$tmp/path.json" --root "$r" --vault-spk "$v" --owner-spk "$o" --out "$tmp/x.json" 2>&1); then
    fail "impulse-zk-prove proved with a wrong salt"
  fi
  grep -q 'ZK_PATH_INVALID' <<<"$out" || fail "wrong salt not refused as ZK_PATH_INVALID: $out"
fi

if [ "$quick" = 0 ]; then
  step "template v3 settle with an authority, real proofs made at test time (tests/engine/v3_live.rs)"
  (cd circuits && cargo build --release --locked -p impulse-zk-prover --bin impulse-zk-prove)
  cargo test --locked -p impulse-engine-tests --test v3_live -- --ignored --test-threads=1
  scripts/record-v3-live.sh
fi

if [ "$quick" = 0 ]; then
  step "template v4 settles and refunds with real receipts made at test time (tests/engine/v4_live.rs, I21)"
  (cd circuits && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)
  rm -f target/v4-units.txt
  IMPULSE_V4_UNITS_OUT="$root/target/v4-units.txt" cargo test --locked -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1
  scripts/record-v4-live.sh
  IMPULSE_V4_UNITS_FROM="$root/target/v4-units.txt" scripts/measure-v4-units.sh
fi

if [ "$quick" = 0 ]; then
  step "template v4 through the command line with real receipts: terms, fund, settle, refund (zkh_tests)"
  (cd circuits && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)
  cargo test --locked -p impulse-cli --features zk --lib -- --ignored --test-threads=1 a_v4_trade_end_to_end_with_real_receipts
fi

step "cargo audit (circuits/Cargo.lock)"
command -v cargo-audit >/dev/null || fail "cargo-audit not installed"
# Eight advisories ignored (four by owner decision, 2026-10-12; one by D133, 2026-10-15;
# three triaged 2026-10-17 under the owner's delegation). All arrive through the pinned
# risc0 toolchain and kaspa-txscript-zk-sdk tree and cannot move without a pin change (rule 3):
#   RUSTSEC-2023-0071 rsa timing side channel: reached only through rzup; the prover never uses RSA
#                     and holds no keys.
#   RUSTSEC-2023-0089 atomic-polyfill, RUSTSEC-2025-0141 bincode, RUSTSEC-2024-0449 unsafe-libyaml:
#                     unmaintained notices, no known vulnerability.
#   RUSTSEC-2026-0344 ruzstd decompression bomb (decision D133, 2026-10-15): reached only through
#                     object 0.36.7 inside risc0-zkvm 3.0.4, which reads the guest ELFs this
#                     repository builds and embeds; the prover decompresses nothing from a network
#                     or a user. The fix needs object and risc0-zkvm to move, a pin change (rule 3).
#   RUSTSEC-2026-0367, -0368, -0369 zip 2.4.2 extraction to disk (SUID bits, symlink targets,
#                     permissions through symlinks): reached only through risc0-circuit-recursion
#                     4.0.4, which opens its own embedded constant archive in memory
#                     (ZipArchive::new(Cursor::new(ZKR_ZIP))) and never calls extract or writes a file.
#                     The fix needs zip 3, which risc0 does not take: a pin change (rule 3).
# Any other advisory still fails this step.
cargo audit --file circuits/Cargo.lock --deny warnings \
  --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2023-0089 \
  --ignore RUSTSEC-2025-0141 --ignore RUSTSEC-2024-0449 --ignore RUSTSEC-2026-0344 \
  --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369

echo
echo "ci-zk: green"
