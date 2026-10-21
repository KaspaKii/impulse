#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Self-test of scripts/release.sh and scripts/release-pack.py (I14 supply chain).
#
#   scripts/test-release.sh          refusals and the packing helper; no cargo build (seconds)
#   scripts/test-release.sh --full   also a real release build with --twice (minutes)
#
# Each refusal is checked by its message and exit code beside an accepted control, so a crash
# cannot pass as a refusal. Hermetic apart from --full: no network, no key material, no build.
# scripts/ci-local.sh runs the fast mode.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
rel="$here/release.sh"
pack="$here/release-pack.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
checks=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { checks=$((checks + 1)); }

# expect NAME CODE PATTERN CMD...: CMD exits CODE and its stderr matches PATTERN.
expect() {
  local name=$1 code=$2 pat=$3; shift 3
  local rc=0 err
  err=$("$@" 2>&1 >/dev/null) || rc=$?
  if [ "$rc" -ne "$code" ]; then fail "$name: exit $rc, expected $code: $err"; return; fi
  if ! grep -qE -- "$pat" <<<"$err"; then fail "$name: stderr does not match '$pat': $err"; return; fi
  pass
}

# A shim directory: a cargo-cyclonedx of a chosen version, and a rustc that reports a chosen
# version, put first on PATH. Neither builds anything.
shim() {
  local d="$work/shim-$1"; mkdir -p "$d"
  printf '#!/bin/sh\necho "cargo-cyclonedx-cyclonedx %s"\n' "$2" > "$d/cargo-cyclonedx"
  chmod +x "$d/cargo-cyclonedx"
  if [ -n "${3:-}" ]; then
    printf '#!/bin/sh\nprintf "rustc %s (fixture)\\nhost: aarch64-apple-darwin\\n"\n' "$3" > "$d/rustc"
    chmod +x "$d/rustc"
  fi
  echo "$d"
}

# A clone of the repository at HEAD, so tags can be added without touching the real one.
clone="$work/clone"
git clone -q --shared --no-checkout "$repo" "$clone" && git -C "$clone" checkout -q --detach HEAD \
  || { echo "FAIL: could not clone $repo" >&2; exit 1; }
channel=$(sed -nE 's/^channel = "([^"]+)"$/\1/p' "$repo/rust-toolchain.toml")
version=$(sed -nE '/^\[workspace.package\]/,/^\[/ s/^version = "([^"]+)"$/\1/p' "$repo/Cargo.toml")
ok_shim=$(shim ok 0.5.9 "$channel")

# Usage and arguments.
expect "unknown argument" 2 '^usage: release.sh' "$rel" --bogus
expect "--ref without a value" 2 '^usage: release.sh' "$rel" --ref
expect "--root of a missing directory" 1 'REFUSED: no such directory' "$rel" --root "$work/nope"
# Tools: cargo-cyclonedx must be the pinned version (refusal, then the shim of the right version
# gets past this check to the next refusal).
expect "cargo-cyclonedx of another version" 1 'REFUSED: cargo-cyclonedx 0\.5\.8, need 0\.5\.9' \
  env PATH="$(shim old 0.5.8):$PATH" "$rel" --root "$clone" --ref no-such-ref
expect "control: right cargo-cyclonedx, then the bad ref" 1 'REFUSED: not a commit: no-such-ref' \
  env PATH="$ok_shim:$PATH" "$rel" --root "$clone" --ref no-such-ref
expect "--root that is not a git repository" 1 'REFUSED: .* is not a git repository' \
  env PATH="$ok_shim:$PATH" "$rel" --root "$work"
# The pinned toolchain: a rustc of another version is refused before anything is built.
expect "rustc of another version" 1 "REFUSED: rustc is 'rustc 1\.0\.0 \(fixture\)', rust-toolchain\.toml pins $channel" \
  env PATH="$(shim oldrustc 0.5.9 1.0.0):$PATH" "$rel" --root "$clone"
# A v* tag on the commit must name the crates' version (the shim rustc passes the toolchain check
# and stops nothing else; the refusal comes before any build).
# A clone of a tagged commit (the public export is tagged) drops its own v* tags first.
git -C "$clone" tag -l 'v*' | while read -r t; do git -C "$clone" tag -d "$t" >/dev/null; done
git -C "$clone" tag v9.9.9 HEAD
expect "tag that does not name the version" 1 "REFUSED: commit [0-9a-f]{40} is tagged v9\.9\.9 but the crates say $version" \
  env PATH="$ok_shim:$PATH" "$rel" --root "$clone"
git -C "$clone" tag -d v9.9.9 >/dev/null
# A commit whose CHANGELOG.md has no section for the version.
sed "s/^## $version/## 9.9.9/" "$repo/CHANGELOG.md" > "$clone/CHANGELOG.md"
git -C "$clone" -c user.name=t -c user.email=t@example.invalid commit -q -am "fixture: changelog without the version"
expect "CHANGELOG.md without a section for the version" 1 "REFUSED: CHANGELOG\.md at [0-9a-f]{40} has no section for $version" \
  env PATH="$ok_shim:$PATH" "$rel" --root "$clone"
# A host that is not a release target.
hshim="$work/shim-host"; mkdir -p "$hshim"; cp "$ok_shim/cargo-cyclonedx" "$hshim/"
printf '#!/bin/sh\nprintf "rustc %s (fixture)\\nhost: riscv64gc-unknown-linux-gnu\\n"\n' "$channel" > "$hshim/rustc"
chmod +x "$hshim/rustc"
expect "host that is not a release target" 1 'REFUSED: host riscv64gc-unknown-linux-gnu is not a release target' \
  env PATH="$hshim:$PATH" "$rel" --root "$clone"

# release-pack.py tar: the same bytes whatever the files' times and the directory they sit in;
# fixed owner, times, modes and order.
mkdir -p "$work/p1" "$work/p2"
for d in p1 p2; do printf 'bin\n' > "$work/$d/b"; printf 'text\n' > "$work/$d/t"; done
touch -t 202001010000 "$work/p1/b"; touch -t 202501010000 "$work/p2/t"
python3 "$pack" tar "$work/1.tar.gz" top 1700000000 "z/t=$work/p1/t" "b=$work/p1/b:755" || fail "tar p1"
python3 "$pack" tar "$work/2.tar.gz" top 1700000000 "b=$work/p2/b:755" "z/t=$work/p2/t" || fail "tar p2"
if cmp -s "$work/1.tar.gz" "$work/2.tar.gz"; then pass; else fail "tar is not deterministic"; fi
python3 - "$work/1.tar.gz" <<'PY' && pass || fail "tar entries"
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    got = [(m.name, m.mode, m.uid, m.gid, m.uname, m.gname, m.mtime) for m in t.getmembers()]
want = [("top", 0o755, 0, 0, "", "", 1700000000), ("top/b", 0o755, 0, 0, "", "", 1700000000),
        ("top/z", 0o755, 0, 0, "", "", 1700000000), ("top/z/t", 0o644, 0, 0, "", "", 1700000000)]
sys.exit(0 if got == want else "got %r" % got)
PY
python3 "$pack" tar "$work/3.tar.gz" top 1700000001 "z/t=$work/p1/t" "b=$work/p1/b:755"
if cmp -s "$work/1.tar.gz" "$work/3.tar.gz"; then fail "tar ignores the epoch"; else pass; fi
expect "tar: entry escaping the top directory" 1 'bad entry name' python3 "$pack" tar "$work/x.tar.gz" top 1 "../b=$work/p1/b"
expect "tar: entry named twice" 1 'entry named twice' python3 "$pack" tar "$work/x.tar.gz" top 1 "b=$work/p1/b" "b=$work/p1/t"
expect "tar: missing file" 1 'not a regular file' python3 "$pack" tar "$work/x.tar.gz" top 1 "b=$work/none"
expect "tar: bad epoch" 1 'EPOCH must be' python3 "$pack" tar "$work/x.tar.gz" top -1 "b=$work/p1/b"
expect "pack: misuse" 2 'usage' python3 "$pack" frobnicate

# release-pack.py sbom: the build path and the serial number are removed; anything else is kept.
src="$work/build/src"
printf '{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:x","metadata":{"timestamp":"2099-01-01T00:00:00Z","component":{"bom-ref":"path+file://%s/crates/a#0"}},"components":[{"name":"c"}]}\n' "$src" > "$work/in.json"
python3 "$pack" sbom "$work/in.json" "$work/out.json" "$src" 86400 || fail "sbom"
python3 - "$work/out.json" "$src" <<'PY' && pass || fail "sbom content"
import json, sys
text = open(sys.argv[1]).read(); d = json.loads(text)
ok = (sys.argv[2] not in text and "serialNumber" not in d
      and d["metadata"]["component"]["bom-ref"] == "path+file:///impulse/crates/a#0"
      and d["metadata"]["timestamp"] == "1970-01-02T00:00:00Z"
      and d["components"] == [{"name": "c"}])
sys.exit(0 if ok else "got " + text)
PY
printf '{"bomFormat":"SPDX","components":[]}\n' > "$work/bad.json"
expect "sbom: not CycloneDX" 1 'not a CycloneDX SBOM' python3 "$pack" sbom "$work/bad.json" "$work/o.json" "$src" 1
expect "sbom: relative build path" 1 'must be an absolute path' python3 "$pack" sbom "$work/in.json" "$work/o.json" rel/src 1

# release-pack.py sums: shasum -c accepts it, a changed file fails it, SHA256SUMS is not listed.
mkdir -p "$work/s"; printf a > "$work/s/one"; printf b > "$work/s/two.tar.gz"
python3 "$pack" sums "$work/s" || fail "sums"
python3 "$pack" sums "$work/s" || fail "sums again"
if [ "$(wc -l < "$work/s/SHA256SUMS")" -eq 2 ] && (cd "$work/s" && shasum -a 256 -c SHA256SUMS >/dev/null); then pass; else fail "sums format"; fi
printf c > "$work/s/one"
if (cd "$work/s" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then fail "sums miss a change"; else pass; fi
mkdir -p "$work/e"
expect "sums: empty directory" 1 'no files to sum' python3 "$pack" sums "$work/e"

if [ "${1:-}" = "--full" ]; then
  # A real build of HEAD, twice at different paths; then the output is checked from outside.
  out="$work/dist"
  if "$rel" --twice --out "$out" >/dev/null; then
    d=$(ls -d "$out"/impulse-* 2>/dev/null | head -n1)
    if [ -n "$d" ] && (cd "$d" && shasum -a 256 -c SHA256SUMS >/dev/null) && [ -f "$d/BUILD-INFO.txt" ] \
       && grep -q "^impulse $version$" "$d/BUILD-INFO.txt"; then pass; else fail "full: release output"; fi
    expect "full: refuses to overwrite a release" 1 'already exists' "$rel" --out "$out"
  else
    fail "full: scripts/release.sh --twice"
  fi
fi

if [ "$fails" -ne 0 ]; then
  echo "test-release: $fails failed, $checks passed" >&2
  exit 1
fi
echo "test-release: $checks checks passed${1:+ ($1)}"
