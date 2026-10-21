#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Clean export of the public tree (docs/release/PUBLIC-TREE.md).
#
#   scripts/export-public.sh <git-ref> <empty-output-dir> [tag]     tag defaults to v0.4.0
#
# Archives the ref, removes the internal paths, refuses (non-zero, offenders listed) if what
# is left holds a home-directory path, a defence-tree name, an em dash, a banned word, the
# placeholder REPLACE, the name of an excluded path, an internal build-process or tooling word
# (in a line or a file name), the owner's personal name or username (in a line, a file name or the
# commit identity), a private-key block, a gitleaks finding or a dangling document link.
# Then it makes one fresh commit "Impulse <tag>" in the caller's git identity and tags it.
# It never pushes and never contacts a network. No key material is read or written.
set -uo pipefail

ref=${1:-}
out=${2:-}
tag=${3:-v0.4.0}
[ -n "$ref" ] && [ -n "$out" ] || { echo "usage: $0 <git-ref> <empty-output-dir> [tag]" >&2; exit 2; }
repo=$(cd "$(dirname "$0")/.." && pwd)
git -C "$repo" rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "export-public: unknown ref $ref" >&2; exit 2; }
if [ -e "$out" ]; then
  [ -d "$out" ] && [ -z "$(ls -A "$out")" ] || { echo "export-public: $out must be an empty directory" >&2; exit 2; }
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)

name=$(git -C "$repo" config user.name) || name=
email=$(git -C "$repo" config user.email) || email=
[ -n "$name" ] && [ -n "$email" ] || { echo "export-public: git user.name and user.email must be set" >&2; exit 2; }

git -C "$repo" archive "$ref" | tar -x -C "$out" || { echo "export-public: archive failed" >&2; exit 1; }

# Internal paths: never in the public tree (reasons in docs/release/PUBLIC-TREE.md). The names
# are built from fragments so that this script does not itself hold them.
excluded=(
  "CLAU""DE.md" ".clau""de" ".project""-map" "docs/presen""tation"
  "docs/reference/INTERNAL""-STRATEGY.md" "docs/incre""ments" "docs/WORK""PLAN.md"
  "docs/rehear""sal" "demo/DEMO""-SCRIPT.md" "demo/STAGE""-CHEATSHEET.md" "demo/REHEAR""SAL.md"
  "docs/reference/IDE""AS.md"
  "docs/RUNBOOK""-OWNER.md" "docs/RELEASE""-CHECKLIST.md" "docs/MAINNET""-RUNBOOK.md"
  "docs/release/BOUNTY""-TERMS-DRAFT.md" "docs/reference/KGPR""-DRAFT.md"
  "docs/RELEASE-NOTES""-v0.1.0.md" "docs/release/NOTES""-v0.1.0.md"
  "docs/evidence/tn10-rehear""sal-2026-10-11" "docs/evidence/tn10-ops-smo""ke-2026-10-12"
  "docs/evidence/tn10-read""only-2026-10-11" "docs/evidence/xchain-refund-lo""cal-2026-10-17"
  "docs/evidence/solana-local""net-2026-10-11" "docs/evidence/public-no""de-2026-10-17"
  "scripts/release-dry""run.sh" "scripts/test-release-dry""run.sh"
  "docs/au""dit/AU""DIT-SCOPE.md" "docs/release/EVI""DENCE.md"
  "docs/evidence/tn10-fr""ost-2026-10-11" "docs/evidence/xchain-de""mo-2026-10-13"
  "docs/measurements/tn10-read""-only-2026-10-11.txt"
  "scripts/rehe""arse-tn10.sh" "scripts/rehe""arse-tn10-frost.sh" "scripts/rehe""arse-tn10-zk.sh"
  "scripts/rehe""arse-tn10-zk-hashed.sh" "scripts/rehe""arse-xchain.sh" "demo/rehe""arse-xchain-local.sh"
  "scripts/mainnet-sm""oke.sh" "scripts/mainnet-sm""oke-frost.sh" "scripts/mainnet-sm""oke-zk.sh"
  "scripts/mainnet-sm""oke-zk-hashed.sh" "scripts/mainnet-sm""oke-xchain.sh"
  "scripts/mainnet-tran""che.sh" "scripts/mainnet-3""way.sh" "scripts/mainnet-lin""ked.sh"
  "scripts/smo""ke-tn10-ops.sh" "scripts/lib-zk""-trade.sh" "scripts/lib-zkh""-trade.sh"
  "scripts/test-cli""-scripts.sh" "scripts/test-frost""-scripts.sh" "scripts/test-zk""-scripts.sh"
  "scripts/test-zk-hashed""-scripts.sh" "scripts/test-xchain""-scripts.sh"
  "scripts/test-mainnet-sm""oke-xchain.sh" "scripts/test-tranche""-script.sh"
  "scripts/test-3way""-script.sh" "scripts/test-linked""-script.sh" "scripts/ci-pri""vate.sh"
  "docs/OWNER""-RUNS.md" "docs/br""and"
)
for p in "${excluded[@]}"; do rm -rf "${out:?}/$p"; done
# The review documents directory ships as docs/security; every reference to it is rewritten.
if [ -d "$out/docs/au""dit" ]; then
  mv "$out/docs/au""dit" "$out/docs/security" || { echo "export-public: rename of the review documents failed" >&2; exit 1; }
  python3 -I - "$out" <<'PY' || { echo "export-public: rewriting the review documents links failed" >&2; exit 1; }
import os, re, sys
root = sys.argv[1]
old = "au" "dit"
rx = re.compile(r"(docs/|\]\(|\[|\.\./)%s/" % old)
for d, dirs, files in os.walk(root):
    if ".git" in dirs:
        dirs.remove(".git")
    for f in files:
        p = os.path.join(d, f)
        try:
            text = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        new = rx.sub(lambda m: m.group(1) + "security/", text)
        if new != text:
            open(p, "w", encoding="utf-8").write(new)
PY
fi
# The private checkout ignores its internal notes directory; the public .gitignore does not name it.
[ -f "$out/.gitignore" ] && { grep -v '^\.project''-map/$' "$out/.gitignore" > "$out/.gitignore.tmp"; mv "$out/.gitignore.tmp" "$out/.gitignore"; }
# Internal notes files, wherever they sit.
find "$out" \( -iname 'hand''off*' -o -iname 'AGENT-NOTES*' -o -iname 'SESSION-NOTES*' \) -prune -exec rm -rf {} +

# Needles are built from fragments so that this script does not itself hold them.
# Fields are separated by a newline; the em dash is U+2014.
n_dash=$(printf '\342\200\224')
EP_NEEDLES=$(printf '%s\n' "/Use""rs/" "/ho""me/" "kii-""defense" "09_""Defence" "$n_dash" "REPLACE")
# Excluded paths: a shipped file must not name them (case-sensitive substrings).
EP_PATHS=$(printf '%s\n' "CLAU""DE.md" "docs/incre""ments" "WORK""PLAN" "docs/rehear""sal" "DEMO""-SCRIPT" \
  "STAGE""-CHEATSHEET" "demo/REHEAR""SAL" "IDE""AS.md" "INTERNAL""-STRATEGY" "docs/presen""tation" \
  "RUNBOOK""-OWNER" "RELEASE""-CHECKLIST" "MAINNET""-RUNBOOK" "BOUNTY""-TERMS-DRAFT" "KGPR""-DRAFT" \
  "RELEASE""-NOTES""-v0.1.0" "NOTES""-v0.1.0" "tn10-rehear""sal-2026" "tn10-ops-smo""ke-2026" \
  "tn10-read""only-2026" "xchain-refund-lo""cal-2026" "solana-local""net-2026" "public-no""de-2026" \
  "release-dry""run" "mainnet-tran""che" "mainnet-3""way" "mainnet-lin""ked" "smo""ke-tn10" "lib-zk""-trade" \
  "lib-zkh""-trade" "tn10-fr""ost-2026" "xchain-de""mo-2026" "tn10-read""-only-2026" "release/EVI""DENCE" "ci-pri""vate" "OWNER""-RUNS")
# Public scope (owner instruction): the public tree states what the software does. It
# names no review of the code by others, no test-network run of the owner and no mainnet run of the
# owner (case-insensitive regular expressions). The dependency scanners cargo-audit and npm audit,
# their flags and their audit.toml files, and a field of the Solana token program, are tools and
# names, not a review, and are allowed.
EP_SCOPE=$(printf '%s\n' "(?<!cargo-)(?<!cargo )(?<!cargo/)(?<!npm )(?<!no-)(?<!--)\\bau""dit(?!\\.toml|or_elgamal|-level)" \
  "rehe""ars" "capped[- ]main""net" "mainnet[- ]sm""oke" "\\bI""15\\b" "independent rev""iew")
# Internal build-process and tooling words (case-insensitive regular expressions).
EP_INTERNAL=$(printf '%s\n' "clau""de" "anthro""pic" "son""net" "\\bop""us\\b" "sub-?""agent" "orches""trat" \
  "work""tree" "\\blane/" "project""-map" "hand""off" "co-authored""-by" "kaspa-""kii(?!\\.org)" "private""relay")
# The owner's personal name and local username, in any form (owner decision 2026-10-20): the public
# tree names KiiLabs only (case-insensitive regular expressions).
EP_OWNER=$(printf '%s\n' "ro""ry" "o[\\x27\\u2019]?ne""ill")
export EP_NEEDLES EP_PATHS EP_INTERNAL EP_SCOPE EP_OWNER
export EP_WORDS_ALL='pre-release'
# The commit identity becomes public with the commit: it may not hold an internal word.
if ! EP_ID="$name <$email>" python3 -I -c '
import os, re, sys
ident = os.environ["EP_ID"]
bad = [w for w in os.environ["EP_INTERNAL"].split("\n") if re.search(w, ident, re.I)]
owner = [w for w in os.environ["EP_OWNER"].split("\n") if re.search(w, ident, re.I)]
if owner:
    sys.exit("export-public: REFUSED, the commit identity holds the owner name (%s); set a public user.name and user.email" % ", ".join(owner))
sys.exit("export-public: REFUSED, the commit identity holds an internal word (%s); set a public user.name and user.email" % ", ".join(bad) if bad else 0)
'; then
  rm -rf "${out:?}"/* "${out:?}"/.[!.]* 2>/dev/null
  exit 1
fi
export EP_WORDS_NOINC='unaudited|audited'

if ! python3 -I - "$out" <<'PY'
import gzip, os, re, sys
root = sys.argv[1]
needles = os.environ["EP_NEEDLES"].split("\n")
paths = os.environ["EP_PATHS"].split("\n")
internal = [(w, re.compile(w, re.I)) for w in os.environ["EP_INTERNAL"].split("\n")]
owner = [(w, re.compile(w, re.I)) for w in os.environ["EP_OWNER"].split("\n")]
scope = [(w, re.compile(w, re.I)) for w in os.environ["EP_SCOPE"].split("\n")]
all_words = re.compile(r"\b(?:%s)\b" % os.environ["EP_WORDS_ALL"], re.I)
noinc_words = re.compile(r"\b(?:%s)\b" % os.environ["EP_WORDS_NOINC"], re.I)
pem = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CHECKERS = {"scripts/release-dry" "run.sh", "scripts/test-release-dry" "run.sh",
            "scripts/export-public.sh", "scripts/test-export-public.sh"}
bad = []
for d, dirs, files in os.walk(root):
    if ".git" in dirs:
        dirs.remove(".git")
    for f in files:
        p = os.path.join(d, f)
        rel = os.path.relpath(p, root)
        try:
            if p.endswith(".gz"):
                # Compressed logs are read as their text, so that a needle cannot hide in them.
                text = gzip.decompress(open(p, "rb").read()).decode("utf-8")
            else:
                text = open(p, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError, EOFError, gzip.BadGzipFile):
            continue
        # The release checkers hold the banned words and the out-of-scope words as the patterns
        # they search for. They hold the path and internal-word needles only as fragments, so those
        # rules apply to them too.
        checker = rel in CHECKERS
        for w, rx in internal:
            if rx.search(rel):
                bad.append("%s: internal word in the path (%s)" % (rel, w))
        for w, rx in scope:
            if not checker and rx.search(rel):
                bad.append("%s: out-of-scope word in the path (%s)" % (rel, w))
        for w, rx in owner:
            if rx.search(rel):
                bad.append("%s: owner name in the path (%s)" % (rel, w))
        for n, line in enumerate(text.splitlines(), 1):
            for nd in needles:
                if nd in line and not (checker and nd == "REPLACE"):
                    bad.append("%s:%d: %s" % (rel, n, "em dash" if nd == chr(0x2014) else nd))
            for nd in paths:
                if nd in line:
                    bad.append("%s:%d: excluded path named (%s)" % (rel, n, nd))
            for w, rx in internal:
                if rx.search(line):
                    bad.append("%s:%d: internal word (%s)" % (rel, n, w))
            for w, rx in scope:
                if not checker and rx.search(line):
                    bad.append("%s:%d: out-of-scope word (%s)" % (rel, n, w))
            for w, rx in owner:
                if rx.search(line):
                    bad.append("%s:%d: owner name (%s)" % (rel, n, w))
            if not checker and all_words.search(line):
                bad.append("%s:%d: banned word (pre-release)" % (rel, n))
            if not checker and noinc_words.search(line):
                bad.append("%s:%d: banned word (audited)" % (rel, n))
            if pem.search(line):
                bad.append("%s:%d: private key block" % (rel, n))
if bad:
    sys.stderr.write("export-public: REFUSED, %d offending lines:\n" % len(bad))
    for b in bad[:200]:
        sys.stderr.write("  " + b + "\n")
    if len(bad) > 200:
        sys.stderr.write("  ... and %d more\n" % (len(bad) - 200))
    sys.exit(1)
PY
then
  exit 1
fi

if command -v gitleaks >/dev/null 2>&1; then
  cfg=()
  [ -f "$out/.gitleaks.toml" ] && cfg=(--config "$out/.gitleaks.toml")
  gitleaks dir --no-banner --redact ${cfg[@]+"${cfg[@]}"} "$out" >&2 \
    || { echo "export-public: REFUSED, gitleaks found key-like material" >&2; exit 1; }
else
  echo "export-public: gitleaks not installed, key-material scan skipped (the owner should run it)" >&2
fi

git -C "$out" init -q -b main || exit 1
git -C "$out" add -A || exit 1
if [ -x "$out/scripts/check-doc-links.sh" ]; then
  "$out/scripts/check-doc-links.sh" >&2 || { echo "export-public: REFUSED, dangling document links in the export" >&2; rm -rf "${out:?}/.git"; exit 1; }
fi
git -C "$out" -c user.name="$name" -c user.email="$email" commit -q -m "Impulse $tag" || exit 1
git -C "$out" -c user.name="$name" -c user.email="$email" tag -a "$tag" -m "Impulse $tag" || exit 1

echo "export-public: OK, $(git -C "$out" ls-files | wc -l | tr -d ' ') files, commit $(git -C "$out" rev-parse --short HEAD), tag $tag, in $out"
echo "Nothing was pushed. To publish, the owner runs:"
echo "  cd $out"
echo "  git remote add origin git@github.com:kaspakii/impulse.git"
echo "  git push -u origin main --tags"
