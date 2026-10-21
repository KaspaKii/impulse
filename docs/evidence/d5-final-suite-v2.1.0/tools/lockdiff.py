#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Compare the package sets of two Cargo.lock files; print what changed and count what did not."""
import re, sys

def pk(path):
    d = {}
    for blk in open(path).read().split("[[package]]")[1:]:
        n = re.search(r'name = "([^"]+)"', blk).group(1)
        v = re.search(r'version = "([^"]+)"', blk).group(1)
        s = re.search(r'source = "([^"]+)"', blk)
        d.setdefault(n, []).append((v, s.group(1) if s else "path"))
    return d

def short(s):
    return "git a41a333" if "rusty-kaspa" in s and "a41a333" in s else ("git silverscript v1.0.0" if "silverscript?tag=v1.0.0" in s else s)

a, b = pk(sys.argv[1]), pk(sys.argv[2])
changed = [n for n in sorted(set(a) | set(b)) if a.get(n) != b.get(n)]
for n in changed:
    print("%s: %s -> %s" % (n, ", ".join("%s (%s)" % (v, short(s)) for v, s in a.get(n, [])) or "absent",
                            ", ".join("%s (%s)" % (v, "path" if s == "path" else short(s)) for v, s in b.get(n, [])) or "absent"))
print("packages in the first lock: %d, in the second: %d, changed: %d, unchanged: %d" % (
    len(a), len(b), len(changed), len(set(a) & set(b)) - len([n for n in changed if n in a and n in b])))
