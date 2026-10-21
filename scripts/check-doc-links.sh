#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Offline link check: every relative link and #anchor in the tracked Markdown files must resolve
# to a file in the repository and, for an anchor, to a heading of the target (GitHub slug rules).
# External (scheme:) links are not fetched. Links inside code fences and inline code are skipped.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -I - "$@" <<'PY'
import os, re, subprocess, sys

files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z", "--", "*.md"],
                       capture_output=True, text=True, check=True).stdout.split("\0")
files = [f for f in files if f and os.path.isfile(f)]

def slug(h):
    h = re.sub(r"`", "", h.strip().lower())
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"[^\w\- ]", "", h, flags=re.UNICODE)
    return h.replace(" ", "-")

cache = {}
def lines_of(path):
    out, fence = [], False
    for ln in open(path, encoding="utf-8"):
        if re.match(r"\s*(```|~~~)", ln):
            fence = not fence
            continue
        if not fence:
            out.append(ln.rstrip("\n"))
    return out

def anchors(path):
    if path not in cache:
        seen, res = {}, set()
        for ln in lines_of(path):
            m = re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", ln)
            if m:
                s = slug(m.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                res.add(s if n == 0 else "%s-%d" % (s, n))
        cache[path] = res
    return cache[path]

bad = []
for f in files:
    for i, ln in enumerate(lines_of(f), 1):
        ln = re.sub(r"`[^`]*`", "", ln)
        for m in re.finditer(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", ln):
            t = m.group(1)
            if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", t) or t.startswith("//"):
                continue
            path, _, frag = t.partition("#")
            dest = f if path == "" else os.path.normpath(os.path.join(os.path.dirname(f), path))
            if not os.path.exists(dest):
                bad.append("%s:%d: missing target %s" % (f, i, t))
            elif frag and dest.endswith(".md") and os.path.isfile(dest) and frag.lower() not in anchors(dest):
                bad.append("%s:%d: no heading #%s in %s" % (f, i, frag, dest))
if bad:
    print("\n".join(bad), file=sys.stderr)
    sys.exit("check-doc-links: %d broken link(s)" % len(bad))

# docs/reference/ERRORS.md must index every code of spec/ERRORS.md (RELEASE_ findings are linked, not listed).
spec = open("spec/ERRORS.md", encoding="utf-8").read().split("## Retired and changed")[0]
codes = set(re.findall(r"^\| \d+ \| `([A-Z]+_[A-Z0-9_]+)`", spec, re.M))
raw = open("spec/ERRORS.md", encoding="utf-8").read()
codes |= set(re.findall(r"^\| `((?:TEMPLATE|DECODE)_[A-Z0-9_]+)` \| (?:Retired|Withdrawn)", raw, re.M))
idx = open("docs/reference/ERRORS.md", encoding="utf-8").read()
missing = sorted(c for c in codes if not c.startswith("RELEASE_") and "`" + c + "`" not in idx)
if missing:
    sys.exit("check-doc-links: docs/reference/ERRORS.md lacks: " + " ".join(missing))
print("check-doc-links: %d files, all relative links resolve; %d codes indexed" % (len(files), len(codes)))
PY
