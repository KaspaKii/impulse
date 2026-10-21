#!/usr/bin/env bash
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Every tag of spec/ERRORS.md "### settle" and "### refund" (template v1) has a row in
# "### Template v4: where each v1 tag lives", and every guest tag it names exists in
# circuits/terms-core/src/statement.rs (spec/V3-ZK.md 22.8). Fails closed.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -I - <<'PY'
import re, sys
text = open("spec/ERRORS.md").read()
def section(head, nxt):
    return text.split(head, 1)[1].split(nxt, 1)[0]
v1 = section("\n### settle\n", "\n## ") + section("\n### refund\n", "\n## ")
tags = sorted(set(re.findall(r"^\| `\[([A-Z]\d+)\]` \|", v1, re.M)))
home = text.split("### Template v4: where each v1 tag lives", 1)[1]
rows = dict(re.findall(r"^\| `\[([A-Z]\d+)\]` \| (.*) \|$", home, re.M))
guest = open("circuits/terms-core/src/statement.rs").read() + open("circuits/terms-core/src/structure.rs").read()
bad = []
for t in tags:
    if t not in rows:
        bad.append("no v4 row for [%s]" % t)
        continue
    m = re.search(r"guest, tag `\[(\w+)\]`", rows[t])
    if m and '"%s"' % m.group(1) not in guest:
        bad.append("guest has no tag [%s]" % m.group(1))
if len(tags) < 31:
    bad.append("read only %d v1 tags" % len(tags))
if bad:
    print("check-tag-parity-v4: FAIL: " + "; ".join(bad), file=sys.stderr)
    sys.exit(1)
print("check-tag-parity-v4: ok (%d v1 tags)" % len(tags))
PY
