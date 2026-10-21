#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Wording check for the hashed-terms vault (spec/V3-ZK.md 22.11): the three fixed texts appear
# verbatim in the CLI source, and no user-facing v4 file uses a banned word (22.11 and the owner's
# rule of 2026-10-15: no review-status wording). `--self-test` shows the check refuses a file with a
# banned word and a CLI source without a fixed text.
set -euo pipefail
cd "$(dirname "$0")/.."

FILES="crates/impulse-cli/src/zkh_cmd.rs crates/impulse-cli/src/zkh_sign.rs"
# The owner's own v4 run scripts are checked too where the tree holds them (the private checkout);
# their names are built from fragments because the public tree may not name them.
for f in "scripts/mainnet-sm""oke-zk-hashed.sh" "scripts/rehe""arse-tn10-zk-hashed.sh" "scripts/lib-zkh""-trade.sh"; do
  [ -f "$f" ] && FILES="$FILES $f"
done
BANNED='hidden|secret|untraceable|invisible|shielded|stealth|mixer|au''dit(ed|s|or)?'
FIXED=(
  "The chain shows only a commitment to the terms until a spend. Vault values, the escrowed token, the authority's key, the funders and the outputs of a settle or refund are public. Anyone holding the terms file can show the terms."
  "Settle and refund both need the terms file. Keep a copy before funding."
  "A flaw in the proof check could let funds leave a v4 vault. Keep value at or below the cap."
)

check() { # cli-source, files...
  local cli=$1; shift
  local bad=0 f
  for t in "${FIXED[@]}"; do
    grep -qF -- "$t" "$cli" || { echo "check-zk-text-v4: fixed text missing from $cli: ${t:0:40}..." >&2; bad=1; }
  done
  for f in "$@"; do
    # comments that quote the rule itself are exempt: a line is checked unless it is a comment
    if grep -v '^[[:space:]]*\(//\|#\)' "$f" | grep -Eiqw "$BANNED"; then
      echo "check-zk-text-v4: banned word in $f" >&2; bad=1
    fi
  done
  return $bad
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  cp crates/impulse-cli/src/zkh_cmd.rs "$tmp/cli.rs"
  echo 'echo "a hidden trade"' > "$tmp/bad.sh"
  check "$tmp/cli.rs" "$tmp/cli.rs" 2>/dev/null || { echo "self-test: clean file refused"; exit 1; }
  if check "$tmp/cli.rs" "$tmp/bad.sh" 2>/dev/null; then echo "self-test: banned word accepted"; exit 1; fi
  sed 's/Keep a copy before funding\./Keep it safe./' "$tmp/cli.rs" > "$tmp/cli2.rs"
  if check "$tmp/cli2.rs" "$tmp/cli2.rs" 2>/dev/null; then echo "self-test: missing fixed text accepted"; exit 1; fi
  echo "check-zk-text-v4: self-test ok"
  exit 0
fi
# The README's v4 section (between the markers) carries the three fixed texts and no banned word.
section=$(mktemp); trap 'rm -f "$section"' EXIT
sed -n '/<!-- impulse-v4 -->/,/<!-- \/impulse-v4 -->/p' README.md > "$section"
[ -s "$section" ] || { echo "check-zk-text-v4: README.md has no v4 section" >&2; exit 1; }
# shellcheck disable=SC2086
check crates/impulse-cli/src/zkh_cmd.rs $FILES
check "$section" "$section"
echo "check-zk-text-v4: ok"
