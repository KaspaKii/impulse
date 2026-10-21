#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Self-test of scripts/export-public.sh on a throwaway git repository: a clean tree exports
# and the internal paths are gone; each planted offender (home path, em dash, banned word,
# placeholder, private-key header, a named excluded path, an internal build-process or tooling
# word, the owner's personal name) makes the export fail and is listed. Hermetic: no network,
# no real key (the planted key block is a header line only).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exp="$here/export-public.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
gc() { git -C "$src" -c user.name=t -c user.email=t@example.invalid commit -q "$@"; }

src="$work/src"
# The internal paths, built from fragments so that this file does not itself hold them.
internal=(
  "CLAU""DE.md" ".clau""de/x.md" ".project""-map/state.json" "docs/presen""tation/deck.md"
  "docs/reference/INTERNAL""-STRATEGY.md" "docs/incre""ments/I00.md" "docs/WORK""PLAN.md"
  "docs/rehear""sal/RUNSHEET.md" "demo/DEMO""-SCRIPT.md" "demo/STAGE""-CHEATSHEET.md"
  "demo/REHEAR""SAL.md" "docs/reference/IDE""AS.md" "HAND""OFF.md" "docs/x/hand""off-notes.md"
  "docs/RUNBOOK""-OWNER.md" "docs/RELEASE""-CHECKLIST.md" "docs/MAINNET""-RUNBOOK.md"
  "docs/release/BOUNTY""-TERMS-DRAFT.md" "docs/reference/KGPR""-DRAFT.md"
  "docs/RELEASE-NOTES""-v0.1.0.md" "docs/release/NOTES""-v0.1.0.md"
  "docs/evidence/tn10-rehear""sal-2026-10-11/README.md" "docs/evidence/tn10-ops-smo""ke-2026-10-12/README.md"
  "docs/evidence/tn10-read""only-2026-10-11/README.md" "docs/evidence/xchain-refund-lo""cal-2026-10-17/README.md"
  "docs/evidence/solana-local""net-2026-10-11/README.md" "docs/evidence/public-no""de-2026-10-17/README.md"
  "scripts/release-dry""run.sh" "scripts/test-release-dry""run.sh"
  "docs/au""dit/AU""DIT-SCOPE.md" "docs/release/EVI""DENCE.md" "docs/evidence/tn10-fr""ost-2026-10-11/README.md"
  "docs/evidence/xchain-de""mo-2026-10-13/README.md" "docs/measurements/tn10-read""-only-2026-10-11.txt"
  "scripts/rehe""arse-tn10.sh" "scripts/rehe""arse-xchain.sh" "demo/rehe""arse-xchain-local.sh"
  "scripts/mainnet-sm""oke.sh" "scripts/mainnet-sm""oke-xchain.sh" "scripts/mainnet-tran""che.sh"
  "scripts/smo""ke-tn10-ops.sh" "scripts/lib-zkh""-trade.sh" "scripts/test-cli""-scripts.sh"
  "scripts/test-mainnet-sm""oke-xchain.sh" "scripts/ci-pri""vate.sh" "docs/OWNER""-RUNS.md"
)
mkdir -p "$src/spec" "$src/docs/reference" "$src/scripts"
git -C "$src" init -q -b main
printf '# Clean\n\nSee [guide](docs/G.md).\n' > "$src/README.md"
printf '# Guide\n' > "$src/docs/G.md"
# The security documents directory: renamed docs/security in the export, its links rewritten.
mkdir -p "$src/docs/au""dit"
printf '# Limits\n' > "$src/docs/au""dit/LIMITS.md"
printf '# Index\n\n[limits](au''dit/LIMITS.md), and docs/au''dit/LIMITS.md\n' > "$src/docs/INDEX.md"
printf '/target\n.project''-map/\n.env\n' > "$src/.gitignore"
: > "$src/spec/ERRORS.md"; : > "$src/docs/reference/ERRORS.md"
for f in "${internal[@]}"; do
  mkdir -p "$(dirname "$src/$f")"
  printf 'internal\n' > "$src/$f"
done
cp "$exp" "$here/check-doc-links.sh" "$src/scripts/"
git -C "$src" add -A
gc -m base
git -C "$src" config user.name "Test Owner"
git -C "$src" config user.email "owner@example.invalid"

out="$work/ok"
if msg=$("$src/scripts/export-public.sh" HEAD "$out" v9.9.9 2>&1); then
  for gone in "${internal[@]}"; do
    [ -e "$out/$gone" ] && fail "clean export still holds $gone"
  done
  [ -f "$out/README.md" ] || fail "clean export lost README.md"
  [ -f "$out/docs/security/LIMITS.md" ] && [ ! -e "$out/docs/au""dit" ] || fail "the security documents directory was not renamed"
  [ "$(sed -n 3p "$out/docs/INDEX.md")" = "[limits](security/LIMITS.md), and docs/security/LIMITS.md" ] || fail "links to the security documents were not rewritten"
  [ "$(cat "$out/.gitignore")" = "$(printf '/target\n.env')" ] || fail "the .gitignore still names the internal notes directory, or lost a line"
  [ "$(git -C "$out" rev-list --count HEAD)" = 1 ] || fail "export is not one commit"
  [ "$(git -C "$out" log -1 --format=%an)" = "Test Owner" ] || fail "commit not in the caller's identity"
  git -C "$out" rev-parse -q --verify refs/tags/v9.9.9 >/dev/null || fail "tag missing"
  grep -q "git push -u origin main --tags" <<<"$msg" || fail "push commands not printed"
  grep -q "git@github.com:kaspakii/impulse.git" <<<"$msg" || fail "push commands do not name github.com/kaspakii/impulse"
  [ -z "$(git -C "$out" remote)" ] || fail "export set a remote"
else
  fail "clean tree refused: $msg"
fi

"$src/scripts/export-public.sh" HEAD "$work/ok" v9.9.9 >/dev/null 2>&1 && fail "non-empty output dir accepted"
# A commit identity with an internal word is refused before anything is committed.
git -C "$src" config user.email "someone@private""relay.appleid.com"
err=$("$src/scripts/export-public.sh" HEAD "$work/ident" 2>&1 >/dev/null) && fail "a relay address as the commit identity was accepted"
grep -q "commit identity holds an internal word" <<<"$err" || fail "identity offender not named: $err"
[ ! -e "$work/ident/.git" ] || fail "a repository was made despite the identity refusal"
git -C "$src" config user.email "owner@example.invalid"

# plant NAME FILE CONTENT EXPECT: append CONTENT, commit, the export must fail and list EXPECT.
plant() {
  local name=$1 file=$2 content=$3 expect=$4 o="$work/p-$1" rc=0 err
  printf '%s\n' "$content" >> "$src/$file"
  git -C "$src" add -A
  gc -m "plant $name"
  err=$("$src/scripts/export-public.sh" HEAD "$o" 2>&1 >/dev/null) || rc=$?
  [ "$rc" -ne 0 ] || fail "$name: export succeeded"
  grep -q -- "$expect" <<<"$err" || fail "$name: offender not listed ($expect): $err"
  [ ! -e "$o/.git" ] || fail "$name: a repository was made despite the refusal"
  git -C "$src" reset -q --hard HEAD~1
}
home="/Use""rs/someone/key"
dash=$(printf '\342\200\224')
plant home-path README.md "see $home" "README.md:4: /Use"
plant em-dash README.md "a $dash b" "README.md:4: em dash"
plant placeholder README.md "at REPLACE" "README.md:4: REPLACE"
plant banned-word README.md "an unaudited tool" "README.md:4: banned word (audited)"
plant pre-release README.md "a Pre-release build" "README.md:4: banned word (pre-release)"
plant key-block README.md "-----BEGIN EC PRIV""ATE KEY-----" "README.md:4: private key block"
plant dangling-link README.md "[x](docs/missing.md)" "dangling document links"
# Each excluded path named in a shipped file is refused.
for nd in "CLAU""DE.md" "docs/incre""ments" "WORK""PLAN" "docs/rehear""sal" "DEMO""-SCRIPT" \
  "STAGE""-CHEATSHEET" "demo/REHEAR""SAL" "IDE""AS.md" "INTERNAL""-STRATEGY" "docs/presen""tation" \
  "RUNBOOK""-OWNER" "RELEASE""-CHECKLIST" "MAINNET""-RUNBOOK" "BOUNTY""-TERMS-DRAFT" "KGPR""-DRAFT" \
  "RELEASE""-NOTES""-v0.1.0" "NOTES""-v0.1.0" "tn10-rehear""sal-2026" "tn10-ops-smo""ke-2026" \
  "tn10-read""only-2026" "xchain-refund-lo""cal-2026" "solana-local""net-2026" "public-no""de-2026" \
  "release-dry""run" "mainnet-tran""che" "mainnet-3""way" "mainnet-lin""ked" "smo""ke-tn10" "lib-zk""-trade" \
  "lib-zkh""-trade" "tn10-fr""ost-2026" "xchain-de""mo-2026" "tn10-read""-only-2026" "release/EVI""DENCE" \
  "ci-pri""vate" "OWNER""-RUNS"; do
  plant "path-${nd//\//_}" README.md "see $nd here" "README.md:4: excluded path named ($nd)"
done
# Each internal build-process or tooling word is refused, in any case.
i=0
for word in "Clau""de" "ANTHRO""PIC" "Son""net" "op""us" "sub""agent" "Sub-""Agent" "Orches""trator" \
  "work""tree" "origin/la""ne/xchain" "project""-map" "Hand""off" "HAND""OFF" "Co-Authored""-By: x" \
  "github.com/kaspa""-kii/impulse" "private""relay"; do
  i=$((i + 1))
  plant "word-$i" README.md "a $word b" "README.md:4: internal word"
done
# Each out-of-scope word is refused, in any case: a review of the code by others, a test-network run
# of the owner, a mainnet run of the owner.
i=0
for word in "an au""dit" "AU""DIT" "a rehe""arsal" "Rehe""arse" "capped main""net" "capped-main""net" \
  "mainnet sm""oke" "Mainnet-Sm""oke" "I""15" "independent rev""iew"; do
  i=$((i + 1))
  plant "scope-$i" README.md "a $word b" "README.md:4: out-of-scope word"
done
# Not refused: the dependency scanners and their files, and a field of the Solana token program.
printf 'cargo-au''dit, cargo au''dit, npm au''dit --au''dit-level=high, npm ci --no-au''dit, .cargo/au''dit.toml, au''dit.toml, ext.au''ditor_elgamal_pubkey, I150\n' >> "$src/README.md"
git -C "$src" add -A
gc -m tools
"$src/scripts/export-public.sh" HEAD "$work/tools" >/dev/null 2>&1 || fail "a dependency scanner name or I150 was refused"
git -C "$src" reset -q --hard HEAD~1
# Not refused: a needle that is only part of a longer word, and the project web site.
printf 'magnum opusculum, a plane/train, kaspa-kii.org\n' >> "$src/README.md"
git -C "$src" add -A
gc -m words
"$src/scripts/export-public.sh" HEAD "$work/words" >/dev/null 2>&1 || fail "opusculum, plane/ or the kaspa-kii.org site was refused"
# A needle inside a compressed log is refused.
printf 'a log from %s\n' "/Use""rs/someone/x" | gzip -n > "$src/docs/run.log.gz"
git -C "$src" add -A
gc -m gz
err=$("$src/scripts/export-public.sh" HEAD "$work/gz" 2>&1 >/dev/null) && fail "a home path inside a .gz log was accepted"
grep -q "docs/run.log.gz:1: /Use" <<<"$err" || fail "gz offender not listed: $err"
git -C "$src" reset -q --hard HEAD~1
# The owner's personal name or local username is refused in a line, in any form and case, in a file
# name and in the commit identity (built from fragments so that this file does not itself hold them).
i=0
for word in "Ro""ry" "O'Ne""ill" "ONe""ill" "One""ill" "O\342\200\231Ne""ill" "src/ro""ry/x" "ro""ry@example.invalid" "RO""RY"; do
  i=$((i + 1))
  plant "owner-$i" README.md "a $(printf "$word") b" "README.md:[0-9]*: owner name"
done
printf 'x\n' > "$src/docs/ro""ry-notes.txt"
git -C "$src" add -A
gc -m oname
err=$("$src/scripts/export-public.sh" HEAD "$work/oname" 2>&1 >/dev/null) && fail "owner name in a file name accepted"
grep -q "owner name in the path" <<<"$err" || fail "owner file name offender not listed: $err"
git -C "$src" reset -q --hard HEAD~1
git -C "$src" config user.name "Ro""ry"
err=$("$src/scripts/export-public.sh" HEAD "$work/oident" 2>&1 >/dev/null) && fail "the owner name as the commit identity was accepted"
grep -q "commit identity holds the owner name" <<<"$err" || fail "owner identity offender not listed: $err"
[ ! -e "$work/oident/.git" ] || fail "a repository was made despite the owner identity refusal"
git -C "$src" config user.name "Test Owner"
# An internal word in a file name is refused.
printf 'x\n' > "$src/docs/clau""de-notes.txt"
git -C "$src" add -A
gc -m fname
err=$("$src/scripts/export-public.sh" HEAD "$work/fname" 2>&1 >/dev/null) && fail "internal word in a file name accepted"
grep -q "internal word in the path" <<<"$err" || fail "file name offender not listed: $err"
git -C "$src" reset -q --hard HEAD~1

if [ "$fails" -ne 0 ]; then echo "test-export-public: $fails FAILED" >&2; exit 1; fi
echo "test-export-public: ok"
