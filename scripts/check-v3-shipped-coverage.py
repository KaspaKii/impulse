#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Checks tests/engine/V3-SHIPPED-COVERAGE.md against the shipped template v3 (I20, review 2).

Fails if a tag of contracts/impulse_vault_v3.sil has no row, if a named test function does not
exist in its source file, or if a named test binary is not a [[test]] of tests/engine/Cargo.toml
(binaries marked "(ignored..." are checked by their leading name).
"""
import os
import re
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
os.chdir(root)
sil = open("contracts/impulse_vault_v3.sil").read()
tags = set(re.findall(r"//\s*\[([A-Z][0-9]+)\]\s*$", sil, re.M))
doc = open("tests/engine/V3-SHIPPED-COVERAGE.md").read()
cargo = open("tests/engine/Cargo.toml").read()
rows = re.findall(r"^\| (`\[[^`]+\]`|gate) \| ([^|]+) \| `([^`]+)` \| `([^`]+)` \|$", doc, re.M)
problems = []
seen = set()
for tag, binary, path, name in rows:
    seen.add(tag.strip("`[]").split(" ")[0])
    if not os.path.isfile(path):
        problems.append(f"{path} does not exist")
        continue
    if not re.search(r"fn %s\(" % re.escape(name), open(path).read()):
        problems.append(f"{path} has no test fn {name}")
    b = binary.strip().split(" ")[0]
    if f'name = "{b}"' not in cargo:
        problems.append(f"{b} is not a test binary of tests/engine/Cargo.toml")
for t in sorted(tags - seen):
    problems.append(f"tag [{t}] has no row")
for t in sorted(seen - tags - {"gate"}):
    problems.append(f"row for [{t}] names a tag the contract does not have")
if problems:
    sys.exit("check-v3-shipped-coverage: " + "; ".join(problems))
print(f"check-v3-shipped-coverage: {len(tags)} tags, {len(rows)} rows, all present")
