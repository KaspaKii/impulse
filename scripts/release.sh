#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Reproducible release build of the `impulse` CLI and the `impulse-watch` watcher (I14 supply chain).
#
#   scripts/release.sh [--ref REF] [--out DIR] [--twice] [--root DIR]
#
#   --ref REF   the commit to build (default HEAD). Only the committed tree is built: the source
#               is a `git archive` of REF, so uncommitted and untracked files never enter a release.
#   --out DIR   where the artifacts go (default <root>/target/dist). The script writes
#               DIR/impulse-<version>-<target>/ and refuses if that directory already exists.
#   --twice     build a second time from a second export at a different path and fail unless
#               every artifact is byte for byte the same (the reproducibility check).
#   --root DIR  the repository to build from (default: the one holding this script).
#
# It builds the host target only, with the toolchain pinned in rust-toolchain.toml, `--locked`,
# default features (the test-only `offline-fake-node` is never on), each binary in its own cargo
# invocation so the watcher's impulse-core keeps its default, keyless feature set. Supported
# targets: aarch64-apple-darwin and x86_64-unknown-linux-gnu. It does not cross-compile: the
# other target is recorded as not built in BUILD-INFO.txt and is built by running this script on
# a native host of that target.
#
# Output, in DIR/impulse-<version>-<target>/:
#   impulse-<version>-<target>.tar.gz   the two binaries, LICENSE, NOTICE, README.md, CHANGELOG.md,
#                                       SECURITY.md and the two SBOMs
#   impulse.cdx.json, impulse-watch.cdx.json   CycloneDX 1.5 SBOMs (cargo-cyclonedx 0.5.9)
#   BUILD-INFO.txt                      version, commit, toolchain, flags, targets not built
#   SHA256SUMS                          over every file above
# Reproducibility: SOURCE_DATE_EPOCH is the commit time of REF, build paths are remapped
# (--remap-path-prefix, -ffile-prefix-map), codegen-units 1, symbols stripped, no rustc wrapper,
# and the archive is written by scripts/release-pack.py with fixed times, owners and order.
#
# It never signs, tags, pushes, publishes or uploads, and reads no key material. Signing
# SHA256SUMS is the owner's.
# Self-test: scripts/test-release.sh (refusals, fast); scripts/test-release.sh --full (a real
# build with --twice).
set -euo pipefail

CYCLONEDX_VERSION="0.5.9"
SUPPORTED_TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu"
USAGE="usage: release.sh [--ref REF] [--out DIR] [--twice] [--root DIR]"

die() { echo "release: REFUSED: $*" >&2; exit 1; }
usage() { echo "$USAGE" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
pack="$here/release-pack.py"
root=$(cd "$here/.." && pwd)
ref=HEAD
out=""
twice=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) [ $# -ge 2 ] || usage; ref=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
    --root) [ $# -ge 2 ] || usage; root=$(cd "$2" 2>/dev/null && pwd) || die "no such directory: $2"; shift 2 ;;
    --twice) twice=1; shift ;;
    -h|--help) echo "$USAGE"; exit 0 ;;
    *) usage ;;
  esac
done
[ -n "$out" ] || out="$root/target/dist"

for tool in git cargo rustc python3 tar; do
  command -v "$tool" >/dev/null || die "$tool not found"
done
cdx=$(command -v cargo-cyclonedx || true)
[ -n "$cdx" ] || die "cargo-cyclonedx not found (cargo install cargo-cyclonedx --version $CYCLONEDX_VERSION --locked)"
cdx_v=$("$cdx" cyclonedx --version 2>/dev/null | awk '{print $NF}')
[ "$cdx_v" = "$CYCLONEDX_VERSION" ] \
  || die "cargo-cyclonedx $cdx_v, need $CYCLONEDX_VERSION (cargo install cargo-cyclonedx --version $CYCLONEDX_VERSION --locked)"

git -C "$root" rev-parse --git-dir >/dev/null 2>&1 || die "$root is not a git repository"
commit=$(git -C "$root" rev-parse --verify --quiet "$ref^{commit}") || die "not a commit: $ref"
epoch=$(git -C "$root" log -1 --format=%ct "$commit")

cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
case "$cargo_home$rustup_home" in *[[:space:]]*) die "CARGO_HOME or RUSTUP_HOME contains white space" ;; esac

work=$(mktemp -d "${TMPDIR:-/tmp}/impulse-release.XXXXXX")
work=$(cd "$work" && pwd -P)  # resolved (macOS /var is /private/var): rustc and cc see the real path
trap 'rm -rf "$work"' EXIT
case "$work" in *[[:space:]]*) die "the temporary directory path contains white space: $work" ;; esac

# build_once DIR: export, check, build, package into DIR/stage. Prints nothing on stdout but the
# stage directory path.
build_once() {
  local w=$1 src="$1/src" stage="$1/stage" target_dir="$1/target"
  mkdir -p "$src" "$stage"
  git -C "$root" archive --format=tar "$commit" | tar -xf - -C "$src"

  # The pinned toolchain (rust-toolchain.toml), as rustup resolves it inside the export.
  local channel
  channel=$(sed -nE 's/^channel = "([^"]+)"$/\1/p' "$src/rust-toolchain.toml")
  [ -n "$channel" ] || die "no channel in rust-toolchain.toml at $commit"
  local rustc_vv cargo_v
  rustc_vv=$(cd "$src" && rustc -vV) || die "rustc -vV failed"
  case "$(head -n1 <<<"$rustc_vv")" in
    "rustc $channel "*) ;;
    *) die "rustc is '$(head -n1 <<<"$rustc_vv")', rust-toolchain.toml pins $channel" ;;
  esac
  cargo_v=$(cd "$src" && cargo -V)
  local host
  host=$(awk '/^host: /{print $2}' <<<"$rustc_vv")
  case " $SUPPORTED_TARGETS " in *" $host "*) ;; *) die "host $host is not a release target ($SUPPORTED_TARGETS)" ;; esac

  # One version for both binaries, and a v* tag on the commit must name it.
  local version
  version=$(cd "$src" && cargo metadata --locked --no-deps --format-version 1 | python3 -c '
import json, sys
v = {p["name"]: p["version"] for p in json.load(sys.stdin)["packages"]}
a, b = v.get("impulse-cli"), v.get("impulse-watch")
if not a or a != b:
    sys.exit("impulse-cli %s and impulse-watch %s differ" % (a, b))
print(a)') || die "version check failed"
  local tags
  tags=$(git -C "$root" tag --points-at "$commit" --list 'v*')
  if [ -n "$tags" ] && ! grep -qxF "v$version" <<<"$tags"; then
    die "commit $commit is tagged $(tr '\n' ' ' <<<"$tags")but the crates say $version"
  fi
  grep -qE "^## \[?$(sed 's/\./\\./g' <<<"$version")\]?( |$)" "$src/CHANGELOG.md" 2>/dev/null \
    || die "CHANGELOG.md at $commit has no section for $version"

  echo "release: building impulse $version for $host from $commit" >&2
  (
    cd "$src"
    export SOURCE_DATE_EPOCH=$epoch
    export CARGO_ENCODED_RUSTFLAGS
    CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s\037%s' "--remap-path-prefix=$src=/impulse" \
      "--remap-path-prefix=$cargo_home=/cargo" "--remap-path-prefix=$rustup_home=/rustup")
    export CFLAGS="-ffile-prefix-map=$src=/impulse -ffile-prefix-map=$cargo_home=/cargo"
    export CXXFLAGS="$CFLAGS"
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=symbols \
      CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0
    unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WRAPPER RUSTFLAGS CARGO_BUILD_RUSTFLAGS
    export CARGO_BUILD_RUSTC_WRAPPER=""
    for p in impulse-cli impulse-watch; do
      cargo build --release --locked --quiet --target "$host" --target-dir "$target_dir" -p "$p" >&2 \
        || die "cargo build -p $p failed"
    done
    "$cdx" cyclonedx --format json --spec-version 1.5 --target "$host" --describe binaries -q >&2 \
      || die "cargo cyclonedx failed"
  )
  local bin="$target_dir/$host/release"
  # The binaries name the release version, and the test-only fake node is absent.
  [ "$("$bin/impulse" --version)" = "impulse $version" ] || die "impulse --version is '$("$bin/impulse" --version)'"
  [ "$("$bin/impulse-watch" --version)" = "impulse-watch $version" ] \
    || die "impulse-watch --version is '$("$bin/impulse-watch" --version)'"
  local rc=0 err
  err=$("$bin/impulse" fake-node --help 2>&1 >/dev/null) || rc=$?
  [ "$rc" -eq 2 ] && grep -q "unrecognized subcommand" <<<"$err" \
    || die "the release impulse binary answers 'fake-node' (offline-fake-node is a test feature)"

  python3 "$pack" sbom "$src/crates/impulse-cli/impulse_bin.cdx.json" "$w/impulse.cdx.json" "$src" "$epoch"
  python3 "$pack" sbom "$src/crates/impulse-watch/impulse-watch_bin.cdx.json" "$w/impulse-watch.cdx.json" "$src" "$epoch"

  local name="impulse-$version-$host"
  python3 "$pack" tar "$stage/$name.tar.gz" "$name" "$epoch" \
    "impulse=$bin/impulse:755" "impulse-watch=$bin/impulse-watch:755" \
    "LICENSE=$src/LICENSE" "NOTICE=$src/NOTICE" "README.md=$src/README.md" \
    "CHANGELOG.md=$src/CHANGELOG.md" "SECURITY.md=$src/SECURITY.md" \
    "sbom/impulse.cdx.json=$w/impulse.cdx.json" "sbom/impulse-watch.cdx.json=$w/impulse-watch.cdx.json"
  cp "$w/impulse.cdx.json" "$w/impulse-watch.cdx.json" "$stage/"

  {
    echo "impulse $version"
    echo "commit $commit"
    echo "SOURCE_DATE_EPOCH $epoch"
    echo "target $host"
    for t in $SUPPORTED_TARGETS; do
      [ "$t" = "$host" ] || echo "not built $t: no cross build; run scripts/release.sh on a native $t host"
    done
    echo "features: default (offline-fake-node off), one cargo invocation per binary"
    echo "profile: release, codegen-units 1, strip symbols, debug 0, incremental off, no rustc wrapper"
    echo "path remapping: source -> /impulse, CARGO_HOME -> /cargo, RUSTUP_HOME -> /rustup"
    echo "sbom: cargo-cyclonedx $cdx_v, CycloneDX 1.5, serialNumber removed, timestamp = commit time, build path -> /impulse"
    echo "$cargo_v"
    echo "$rustc_vv"
    echo "cc: $(cc --version 2>&1 | head -n1)"
    echo "ld: $(ld -v 2>&1 | head -n1)"
    echo "signed: no (the owner signs SHA256SUMS)"
  } > "$stage/BUILD-INFO.txt"
  python3 "$pack" sums "$stage"
  echo "$name"
}

name=$(build_once "$work/a")
if [ "$twice" -eq 1 ]; then
  # A second export at a different path, built from nothing: the remapping and the fixed
  # times must make every byte the same.
  name_b=$(build_once "$work/second-build-at-another-path")
  [ "$name" = "$name_b" ] || die "the two builds name different releases: $name, $name_b"
  if ! cmp -s "$work/a/stage/SHA256SUMS" "$work/second-build-at-another-path/stage/SHA256SUMS"; then
    diff "$work/a/stage/SHA256SUMS" "$work/second-build-at-another-path/stage/SHA256SUMS" >&2 || true
    diff -r "$work/a/stage" "$work/second-build-at-another-path/stage" 2>&1 | head -n 40 >&2 || true
    for d in a second-build-at-another-path; do
      mkdir -p "$work/x-$d" && tar -xzf "$work/$d/stage/"impulse-*.tar.gz -C "$work/x-$d" && ( cd "$work/x-$d" && find . -type f -exec shasum -a 256 {} + | sort -k2 ) > "$work/x-$d.sums"
    done
    diff "$work/x-a.sums" "$work/x-second-build-at-another-path.sums" >&2 || true
    die "the two builds differ: not reproducible"
  fi
  echo "release: reproducible: two builds at different paths match byte for byte" >&2
fi

dest="$out/$name"
[ ! -e "$dest" ] || die "$dest already exists; remove it or pass another --out"
mkdir -p "$out"
cp -R "$work/a/stage" "$dest"
echo "release: wrote $dest" >&2
(cd "$dest" && cat SHA256SUMS)
