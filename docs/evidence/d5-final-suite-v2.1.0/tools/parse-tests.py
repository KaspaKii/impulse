#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Parse a `cargo test` log into per-test verdicts and per-target counts.

usage: parse_tests.py LOG VERDICTS_OUT COUNTS_OUT
VERDICTS_OUT: one line per test, `target<TAB>test<TAB>verdict`, sorted.
COUNTS_OUT: one line per target, `target<TAB>passed<TAB>failed<TAB>ignored<TAB>measured<TAB>filtered_out`, in run order.
"""
import re, sys

log, vout, cout = sys.argv[1:4]
target = None
label = None
verdicts = []
counts = []
seen = {}
for line in open(log, errors="replace"):
    line = line.rstrip("\n")
    m = re.match(r"\s+Running (.+?) \((?:.*/)?deps/([A-Za-z0-9_]+)-[0-9a-f]{16}\)", line)
    if m:
        label, target = m.group(1), m.group(2)
        if target in seen:
            seen[target] += 1
            target = "%s#%d" % (target, seen[target])
        else:
            seen[target] = 1
        continue
    m = re.match(r"\s+Doc-tests (\S+)", line)
    if m:
        label, target = "doctests", "doctests:" + m.group(1)
        continue
    m = re.match(r"test (.+?) \.\.\. (ok|FAILED|ignored.*)$", line)
    if m and target:
        v = m.group(2)
        verdicts.append((target, m.group(1), "ignored" if v.startswith("ignored") else v))
        continue
    m = re.match(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", line)
    if m and target:
        counts.append((target, label, m.group(1), *[int(x) for x in m.groups()[1:]]))
verdicts.sort()
with open(vout, "w") as f:
    for t, n, v in verdicts:
        f.write("%s\t%s\t%s\n" % (t, n, v))
with open(cout, "w") as f:
    for c in counts:
        f.write("%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (c[0], c[3], c[4], c[5], c[6], c[7], c[2], c[1]))
tot = [sum(c[i] for c in counts) for i in (3, 4, 5, 6, 7)]
print("targets %d tests %d passed %d failed %d ignored %d measured %d filtered %d" % (len(counts), len(verdicts), *tot))
