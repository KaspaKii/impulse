#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Generates PARITY.md (I10). Run it through scripts/gen-parity.sh.

Inputs: tests/parity/solana-dvp.json (the Solana items and the claims trace), the tags on the
tests in tests/parity/{instructions,errors,edges}.rs (format in tests/parity/parity.rs), the
result of `cargo test -p impulse-parity`, the head-to-head table of spec/IMPULSE-SPEC.md, and
tests/parity/solana-onchain.json (raw JSON-RPC responses about the declared program ID, decoded
here; the generator never queries the network).

Fails closed: an item without a passing tagged test (unless pending), a test without an item, a
failed or missing test, a pending item answered by a test that is not tagged partial (or a partial
test on an item that is not pending), a pending note naming no increment, a claim row that drifted
from the spec, an equivalent row resting on an off-chain code (any family of spec/ERRORS.md) with no
contract tag behind it and no client_side mark, a cited contract tag whose removal does not fail the
row's test (per tests/parity/mutation-run.json), a sentence of the spec outside the head-to-head
table that names Solana outside every quote of the mapping's 'prose' trace, or sits in the section
describing the program and holds no part of a quote (or a prose quote that no longer occurs once in the
spec), a date in the spec text of a statement traced to the on-chain measurement that is not the date
the record gives, a
code family prefix of the generator that differs from the Families table of spec/ERRORS.md, or a
malformed mapping stops it before anything is written.

  gen_parity.py                       run the tests, write PARITY.md
  gen_parity.py --check               run the tests, fail if PARITY.md differs
  gen_parity.py --mutate-contract     replace each tagged require of the contract by require(true)
                                      in turn, run the parity tests against each mutant
                                      (IMPULSE_VAULT_SIL), write tests/parity/mutation-run.json,
                                      then PARITY.md; 33 runs of the parity crate, by hand after a
                                      change to the contract, the harness or a test citing a tag
  gen_parity.py --verify-source [DIR] check the mapping against solana-foundation/dvp at the
                                      pinned commit (DIR: a checkout; default: clone into
                                      target/parity/solana-dvp, which needs network)
"""

import base64
import datetime
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
MAPPING = "tests/parity/solana-dvp.json"
ITEM_FILES = ["instructions.rs", "errors.rs", "edges.rs"]
SPEC = "spec/IMPULSE-SPEC.md"
ERRORS = "spec/ERRORS.md"
CITED_TAG = re.compile(r"\[[A-Z]\d+\]")
# The prefixes of spec/ERRORS.md: every family of stable codes. A code is a refusal (or, for TOKEN_
# and WATCH_ flags, a report) of off-chain software; only the contract tags refuse on chain.
FAMILIES = "XCHAIN|LINKED|HTLC|TERMS|TEMPLATE|TX|IPST|VERIFY|DECODE|TOKEN|CLI|SIGN|RECEIPT|WATCH|SDK|THRESHOLD|FROST|ZK|RELEASE"
CITED_CODE = re.compile(r"(?<![/\w])(?:%s)_[A-Z0-9_]+\b" % FAMILIES)  # not a path such as contracts/TEMPLATE_HASH
LISTED_CODE = re.compile(r"^\| \d+ \| `((?:%s)_[A-Z0-9_]+)` \|" % FAMILIES, re.M)
OUTPUT = "PARITY.md"
ONCHAIN = "tests/parity/solana-onchain.json"
MUTATION = "tests/parity/mutation-run.json"
CONTRACT = "contracts/impulse_vault.sil"
# Inputs besides the contract and the tests themselves that decide what a mutant fails.
MUTATION_INPUTS = ["tests/parity/common.rs", "tests/parity/trade.rs", "tests/parity/verify_world.rs",
                   "tests/engine/harness.rs", "tests/engine/real_terms.rs",
                   "tests/engine/fixtures/kcc20/kcc20.sil"]
REQUIRE_TAG = re.compile(r"//\s*\[([A-Z][0-9]+)\]\s*$")
REQUIRE_CALL = re.compile(r"require\(.*\);")
# Inputs whose sha256 PARITY.md shows, so an edit to any of them changes PARITY.md.
DIGESTED = [MAPPING, ONCHAIN, "tests/parity/common.rs", "tests/parity/trade.rs",
            "tests/parity/verify_world.rs", "tests/engine/real_terms.rs", ERRORS, MUTATION]
# A measured or contradicted claim names the upgrade authority only through this slot, which
# render() fills from the decoded on-chain record.
AUTHORITY_SLOT = "{upgrade_authority}"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
CLAIM_KINDS = ("items", "source", "unsupported", "measured", "contradicted")
# A statement elsewhere in the spec may also say nothing about the program (a heading, a question).
PROSE_KINDS = CLAIM_KINDS + ("none",)
BASELINE = "The baseline: Solana Foundation DvP"
HEAD_TO_HEAD = "Head-to-head with Solana DvP"
KINDS = [("instruction", "Instructions"), ("error", "Error codes"), ("edge_case", "README edge cases")]
VERDICTS = {
    "equivalent": "Equivalent",
    "impossible": "Impossible by construction",
    "divergent": "Different by design",
    "uncovered": "Not covered",
    "partial": "Partial",
}
SUMMARY = {
    "equivalent": "Equivalent, test passes",
    "impossible": "Impossible by construction, test passes",
    "divergent": "Different by design, test passes",
    "uncovered": "Not covered, test pins what is checked",
    "partial": "Partial, test passes for one part, the rest pending",
}
TAG = re.compile(r"^/// parity: (\S+) (\S+)\n/// (.+)\n#\[test\]\nfn (\w+)\(\)", re.M)
# An `impossible` row must rest on a construction in Impulse's own code. These mark a rationale or
# a test that rests on a property of the test fixtures (the KCC-20 test token) instead.
FIXTURE_WORDS = re.compile(r"\bfixtures?\b|\bpinned KCC-20\b|\btest token\b", re.I)
FIXTURE_CODE = re.compile(r"\.artifact\b|\bkcc20_source\(|\bruntime_state\b")


def fail(message):
    sys.exit("gen-parity: FAIL: " + message)


def read(relative):
    with open(os.path.join(ROOT, relative), encoding="utf-8") as f:
        return f.read()


def load_mapping():
    m = json.loads(read(MAPPING))
    source = m["source"]
    if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
        fail("source commit is not a 40-digit hash")
    d = source["deployment"]
    for key in ("set_by_commit", "readme_note_commit"):
        if not re.fullmatch(r"[0-9a-f]{40}", d[key]):
            fail(f"deployment {key} is not a 40-digit hash")
    for key in ("declared_at", "readme_note"):
        if d[key].rsplit(":", 1)[0] not in source["sha256"]:
            fail(f"deployment {key} cites an unpinned file: {d[key]}")
    ids = [i["id"] for i in m["items"]]
    if len(ids) != len(set(ids)):
        fail("duplicate item ids")
    for item in m["items"]:
        if item["kind"] not in dict(KINDS):
            fail(f"{item['id']}: unknown kind {item['kind']}")
        for cite in item["cite"]:
            if cite.rsplit(":", 1)[0] not in source["sha256"]:
                fail(f"{item['id']}: cites an unpinned file: {cite}")
        for key in ("solana", "summary"):
            if not item.get(key):
                fail(f"{item['id']}: no {key}")
        if item.get("client_side") not in (None, True):
            fail(f"{item['id']}: client_side is {item['client_side']!r}; it is true or absent")
    codes = {k: [i["code"] for i in m["items"] if i["kind"] == k] for k in ("instruction", "error")}
    if codes["instruction"] != list(range(6)):
        fail("instructions are not codes 0 to 5 in order")
    if codes["error"] != list(range(24)):
        fail("error codes are not 0 to 23 in order")
    return m


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def b58encode(raw):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def load_onchain(m):
    """What the raw responses in ONCHAIN show about the declared program ID, decoded here."""
    d = m["source"]["deployment"]
    if d["onchain"] != ONCHAIN:
        fail(f"deployment onchain is {d['onchain']}, expected {ONCHAIN}")
    o = json.loads(read(ONCHAIN))
    try:
        program, data, block = (q for q in o["queries"])
        if program["request"]["method"] != "getAccountInfo" or program["request"]["params"][0] != d["declared_id"]:
            fail(f"{ONCHAIN}: query 1 is not getAccountInfo of the declared ID {d['declared_id']}")
        value = program["response"]["result"]["value"]
        program_data = value["data"]["parsed"]["info"]["programData"]
        if not value["executable"] or value["owner"] != UPGRADEABLE_LOADER:
            fail(f"{ONCHAIN}: the declared ID is not an executable account of the upgradeable loader")
        if data["request"]["method"] != "getAccountInfo" or data["request"]["params"][0] != program_data:
            fail(f"{ONCHAIN}: query 2 is not getAccountInfo of the ProgramData account {program_data}")
        dvalue = data["response"]["result"]["value"]
        raw = base64.b64decode(dvalue["data"][0], validate=True)
        if dvalue["owner"] != UPGRADEABLE_LOADER or len(raw) != 45 or int.from_bytes(raw[:4], "little") != 3:
            fail(f"{ONCHAIN}: query 2 is not the 45-byte header of an upgradeable ProgramData account")
        if raw[12] not in (0, 1):
            fail(f"{ONCHAIN}: ProgramData upgrade authority option byte is {raw[12]}")
        slot = int.from_bytes(raw[4:12], "little")
        authority = b58encode(raw[13:45]) if raw[12] == 1 else None
        if block["request"]["method"] != "getBlockTime" or block["request"]["params"] != [slot]:
            fail(f"{ONCHAIN}: query 3 is not getBlockTime of the last deploy slot {slot}")
        deployed = datetime.datetime.fromtimestamp(block["response"]["result"], datetime.timezone.utc)
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", o["measured_at"]):
            fail(f"{ONCHAIN}: measured_at is not a UTC timestamp")
    except (KeyError, TypeError, ValueError) as err:
        fail(f"{ONCHAIN} does not parse as the three recorded queries: {err!r}")
    return {
        "measured_at": o["measured_at"], "endpoint": o["endpoint"], "program_data": program_data,
        "slot": slot, "authority": authority, "deployed": deployed.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_tags():
    """Item id -> (verdict, rationale, test path, test source) from the tagged tests."""
    tags = {}
    for name in ITEM_FILES:
        text = read(f"tests/parity/{name}")
        module = name[: -len(".rs")]
        tests = len(re.findall(r"^#\[test\]$", text, re.M))
        found = TAG.findall(text)
        if len(found) != tests:
            fail(f"tests/parity/{name}: {tests} tests but {len(found)} carry a parity tag")
        for match in TAG.finditer(text):
            item_id, verdict, rationale, fn = match.groups()
            end = text.find("\n}\n", match.end())
            if end < 0:
                fail(f"{module}::{fn}: no closing brace at the start of a line")
            source = text[match.start():end + 3]
            if verdict not in VERDICTS:
                fail(f"{module}::{fn}: verdict {verdict} is not one of {sorted(VERDICTS)}")
            if item_id in tags:
                fail(f"{item_id}: tagged on two tests")
            if verdict == "impossible" and (FIXTURE_WORDS.search(rationale) or FIXTURE_CODE.search(source)):
                fail(f"{item_id}: {module}::{fn} is impossible by construction but rests on a test "
                     "fixture; a fixture's properties are not Impulse's")
            tags[item_id] = (verdict, rationale.strip(), f"{module}::{fn}", source)
    return tags


def cargo_test(env=None):
    """One run of the parity crate, with `env` added to the environment."""
    cmd = ["cargo", "test", "--locked", "-p", "impulse-parity", "--", "--color", "never"]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=dict(os.environ, **(env or {})))


def results_of(proc):
    return dict(re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)$", proc.stdout, re.M))


def tail_of(proc):
    return "\n".join((proc.stdout + proc.stderr).splitlines()[-40:])


def run_tests():
    """Test path -> result, from one run of the parity crate."""
    proc = cargo_test()
    if proc.returncode != 0:
        fail("cargo test -p impulse-parity failed:\n" + tail_of(proc))
    return results_of(proc)


def body_digest(text):
    """sha256 of a tagged test's source from `#[test]` on: its code without the tag lines."""
    return digest(text[text.index("#[test]"):])


def contract_requires(source):
    """(line index, tag) of every tagged require of the contract."""
    found = []
    for n, line in enumerate(source.split("\n")):
        if "require(" not in line.split("//")[0]:
            continue
        tag = REQUIRE_TAG.search(line)
        if not tag or not REQUIRE_CALL.search(line.split("//")[0]):
            fail(f"{CONTRACT}:{n + 1}: a require that is not one tagged line")
        found.append((n, f"[{tag.group(1)}]"))
    return found


SUFFIX_CONST = re.compile(r"^(\s*int constant SUFFIX_LEN = )(\d+);", re.M)


def at_suffix_fixed_point(text, scratch):
    """`text` with its SUFFIX_LEN constant set to the suffix length it compiles to. The contract
    carries its own template suffix length for [S10], and removing a require shortens the suffix,
    so without this every mutant would refuse every settle and the run would show nothing."""
    # The pinned compiler and the committed constructor values of the checkout this script is in
    # (its self-test runs it against a scratch tree that has neither).
    here = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    silverc = os.path.join(here, "target", "silverc-v1.0.0", "bin", "silverc")
    ctor = os.path.join(here, "contracts", "compiled", "impulse_vault.v1.ctor.json")
    if not os.access(silverc, os.X_OK):
        fail(f"missing {silverc}: run scripts/build-template.sh first")
    for _ in range(8):
        src = os.path.join(scratch, "suffix.sil")
        out = os.path.join(scratch, "suffix.json")
        with open(src, "w", encoding="utf-8") as f:
            f.write(text)
        proc = subprocess.run([silverc, src, "--constructor-args", ctor, "-o", out], capture_output=True, text=True)
        if proc.returncode != 0:
            fail("a mutant does not compile: " + proc.stderr.strip())
        compiled = json.load(open(out))["contracts"]["ImpulseVault"]["compiled"]
        span = compiled["state_span"]
        actual = len(compiled["bytecode"]) - span["offset"] - span["len"]
        current = int(SUFFIX_CONST.search(text).group(2))
        if actual == current:
            return text
        text = SUFFIX_CONST.sub(lambda m: "%s%d;" % (m.group(1), actual), text, count=1)
    fail("SUFFIX_LEN did not converge")


def mutate_contract(m, tags):
    """Runs the parity tests against each one-require mutant and writes MUTATION."""
    source = read(CONTRACT)
    lines = source.split("\n")
    tests = sorted(t[2] for t in tags.values())
    flipped = {}
    with tempfile.TemporaryDirectory() as scratch:
        def run(text, label):
            path = os.path.join(scratch, "impulse_vault.sil")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            proc = cargo_test({"IMPULSE_VAULT_SIL": path})
            if "test result:" not in proc.stdout:
                fail(f"{label}: cargo test -p impulse-parity did not run its tests:\n" + tail_of(proc))
            if re.search(r"^compile: ", proc.stdout + proc.stderr, re.M):
                fail(f"{label}: the harness could not compile it")
            results = results_of(proc)
            missing = [t for t in tests if t not in results]
            if missing:
                fail(f"{label}: no result for {missing}")
            return sorted(t for t in tests if results[t] != "ok")

        failing = run(source, "the unmutated contract")
        if failing:
            fail(f"the unmutated contract: {failing} fail")
        for n, tag in contract_requires(source):
            mutant = list(lines)
            mutant[n] = REQUIRE_CALL.sub("require(true);", mutant[n], count=1)
            flipped[tag] = run(at_suffix_fixed_point("\n".join(mutant), scratch), f"the mutant without {tag}")
            print(f"gen-parity: {tag} removed: {len(flipped[tag])} parity tests fail", flush=True)
    record = {
        "about": "Contract mutation run for the parity rows (I10): each tagged require of the contract "
                 "replaced by require(true) in turn, the parity crate run against the mutant through "
                 "IMPULSE_VAULT_SIL, and the tests that failed recorded under the tag. Written by "
                 "scripts/gen-parity.sh --mutate-contract; never edit by hand. The generator refuses a "
                 "row citing a tag whose mutant does not fail its test, and a record whose contract, "
                 "inputs or citing tests have changed since.",
        "contract": CONTRACT,
        "contract_sha256": digest(source),
        "inputs": {path: digest(read(path)) for path in MUTATION_INPUTS},
        "tests": {t[2]: body_digest(t[3]) for t in sorted(tags.values(), key=lambda t: t[2])},
        "flipped": flipped,
    }
    with open(os.path.join(ROOT, MUTATION), "w", encoding="utf-8") as f:
        f.write(json.dumps(record, indent=1) + "\n")
    print(f"gen-parity: wrote {MUTATION} ({len(flipped)} mutants)")


def spec_claims():
    """(capability, Solana column, Impulse column) of every row of the spec's head-to-head table."""
    section = read(SPEC).split("\n## Head-to-head with Solana DvP\n", 1)
    if len(section) != 2:
        fail(f"{SPEC} has no 'Head-to-head with Solana DvP' section")
    rows = [line for line in section[1].split("\n## ", 1)[0].splitlines() if line.startswith("|")]
    return [tuple(cell.strip() for cell in row.strip().strip("|").split("|")[:3]) for row in rows[2:]]


def check_families(errors):
    """FAMILIES is exactly the set of code prefixes in the Families table of spec/ERRORS.md."""
    parts = errors.split("\n## Families\n", 1)
    if len(parts) != 2:
        fail(f"{ERRORS} has no 'Families' section")
    listed = set()
    for row in parts[1].split("\n## ", 1)[0].splitlines():
        if row.startswith("| `"):
            listed.update(re.findall(r"`([A-Z]+)_`", row.split("|")[1]))
    if listed != set(FAMILIES.split("|")):
        fail(f"the code families of gen_parity.py {sorted(FAMILIES.split('|'))} differ from the "
             f"Families table of {ERRORS} {sorted(listed)}")


def check(m, tags, results):
    by_id = {i["id"]: i for i in m["items"]}
    for item_id in tags:
        if item_id not in by_id:
            fail(f"{tags[item_id][2]} is tagged {item_id}, which the mapping does not have")
    for item in m["items"]:
        tag = tags.get(item["id"])
        if "pending" in item:
            if not re.search(r"\bI\d+\b", item["pending"]):
                fail(f"{item['id']}: the pending note names no increment (I<n>)")
            if not tag:
                continue
            if tag[0] != "partial":
                fail(f"{item['id']} is pending but {tag[2]} answers it as {tag[0]}; tag it partial")
        elif not tag:
            fail(f"{item['id']} is unmapped: no tagged test and not pending")
        elif tag[0] == "partial":
            fail(f"{item['id']}: {tag[2]} is partial but the item has no pending note")
        result = results.get(tag[2])
        if result != "ok":
            fail(f"{item['id']}: {tag[2]} result is {result or 'missing'}")
    errors = read(ERRORS)
    check_families(errors)
    # The v1 contract's tags: the "## On-chain refusals" section only. Later templates list their
    # own, separately scoped tags in sections of their own (spec/V2.md 8.6).
    v1_section = re.search(r"^## On-chain refusals\n(.*?)(?=^## |\Z)", errors, re.M | re.S)
    if not v1_section:
        fail(f"{ERRORS} has no '## On-chain refusals' section")
    listed_tags = set(re.findall(r"^\| `(\[[A-Z]\d+\])` \|", v1_section.group(1), re.M))
    listed_codes = set(LISTED_CODE.findall(errors))
    for item_id, (_, rationale, test, _) in tags.items():
        text = rationale + " " + by_id[item_id].get("pending", "")
        for tag in CITED_TAG.findall(text):
            if tag not in listed_tags:
                fail(f"{item_id}: {test} cites {tag}, which {ERRORS} does not list")
        for code in CITED_CODE.findall(text):
            if code not in listed_codes:
                fail(f"{item_id}: {test} cites {code}, which {ERRORS} does not list")
    for item_id, (verdict, rationale, test, _) in tags.items():
        codes = CITED_CODE.findall(rationale)
        if verdict == "equivalent" and codes and not CITED_TAG.search(rationale) and not by_id[item_id].get("client_side"):
            fail(f"{item_id}: {test} is equivalent but rests on an off-chain refusal ({', '.join(codes)}) "
                 "that no contract tag backs; the contract does not repeat those checks: tag it "
                 "divergent and say what the contract does, cite the tag that refuses on chain, or, "
                 "where Solana's own answer is a check the client runs, mark the item client_side")
    check_mutation(tags, listed_tags)
    claims = [(c["capability"], c["solana"], c["impulse"]) for c in m["claims"]]
    spec = spec_claims()
    if claims != spec:
        missing = [c for c in spec if c not in claims]
        extra = [c for c in claims if c not in spec]
        fail(f"claims trace differs from {SPEC}: not traced {missing}, not in the spec {extra}")
    for c in m["claims"]:
        check_trace(m, c, f"claim {c['capability']}", CLAIM_KINDS)
    prose_rows(m)


def check_trace(m, c, label, kinds):
    """One traced statement (a head-to-head row or a sentence elsewhere): exactly one kind of
    trace, and each trace resolves."""
    by_id = {i["id"]: i for i in m["items"]}
    found = [k for k in kinds if k in c]
    if len(found) != 1:
        fail(f"{label}: exactly one of {', '.join(kinds)}")
    for key in ("measured", "contradicted"):
        fixed = c.get(key, "").replace(AUTHORITY_SLOT, "")
        if re.search(r"upgrade authority", fixed, re.I):
            fail(f"{label}: states the upgrade authority in fixed text; write "
                 f"{AUTHORITY_SLOT}, which is filled from {ONCHAIN}")
        if "{" in fixed or "}" in fixed:
            fail(f"{label}: a placeholder other than {AUTHORITY_SLOT}")
    for item_id in c.get("items", []) + c.get("see", []):
        if item_id not in by_id:
            fail(f"{label}: no item {item_id}")
    for cite in c.get("source", []):
        if cite.rsplit(":", 1)[0] not in m["source"]["sha256"]:
            fail(f"{label}: cites an unpinned file: {cite}")


def spec_files():
    return sorted(f"spec/{name}" for name in os.listdir(os.path.join(ROOT, "spec")) if name.endswith(".md"))


def prose_scope(lines):
    """Indexes of the lines of one spec file that hold something to trace: every line that names
    Solana and every line of the baseline section, except headings, blank lines and the rows of
    the head-to-head table (traced in 'claims'); the indexes of the baseline lines among them; and
    whether the baseline section exists."""
    need, base, section, seen = set(), set(), None, False
    for n, line in enumerate(lines):
        if line.startswith("#"):
            if line.startswith("## "):
                section = line[3:].strip()
                seen = seen or section == BASELINE
            continue
        if not line.strip() or (section == HEAD_TO_HEAD and line.startswith("|")):
            continue
        if section == BASELINE:
            base.add(n)
        if "solana" in line.lower() or section == BASELINE:
            need.add(n)
    return need, base, seen


# A sentence ends at a full stop, question mark or exclamation mark followed by white space.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def sentence_spans(line):
    """(start, end) of each sentence of one spec line that has a letter in it."""
    spans, start = [], 0
    for end in SENTENCE_END.finditer(line):
        spans.append((start, end.start()))
        start = end.end()
    spans.append((start, len(line)))
    return [(a, b) for a, b in spans if re.search(r"[A-Za-z]", line[a:b])]


def untraced(line, quotes, whole):
    """What one in-scope line says about Solana that no quote holds: each mention of Solana (any
    case) outside every quote, and, when `whole` (the line sits in the baseline section), each
    sentence that holds no part of any quote. A quote that spans two sentences covers both."""
    marks = []
    for quote in quotes:
        at = line.find(quote)
        while at >= 0:
            marks.append((at, at + len(quote)))
            at = line.find(quote, at + 1)
    found = [line[max(0, m.start() - 30):m.end() + 40].strip() for m in re.finditer("solana", line, re.I)
             if not any(s <= m.start() and m.end() <= e for s, e in marks)]
    if whole:
        found += [line[a:b].strip() for a, b in sentence_spans(line)
                  if not any(s < b and a < e for s, e in marks)]
    return found


def prose_rows(m):
    """The traced sentences of the spec outside the head-to-head table, resolved to their section
    and line. Fails on an entry that does not resolve, on a mention of Solana outside every quote,
    and on a sentence of the baseline section that holds no part of any entry's quote."""
    entries = m.get("prose")
    if not isinstance(entries, list) or not entries:
        fail("the mapping has no prose trace ('prose')")
    lines_of = {path: read(path).split("\n") for path in spec_files()}
    rows = []
    for e in entries:
        quote, path = e.get("quote"), e.get("file", SPEC)
        if not isinstance(quote, str) or not quote or "\n" in quote:
            fail(f"prose entry {quote!r}: the quote is one non-empty line of text")
        if path not in lines_of:
            fail(f"prose {quote!r}: {path} is not a spec file")
        lines = lines_of[path]
        found = sum(line.count(quote) for line in lines)
        if found != 1:
            fail(f"prose {quote!r}: occurs {found} times in {path}, expected once")
        at = next(n for n, line in enumerate(lines) if quote in line)
        section = next((lines[k][3:].strip() for k in range(at, -1, -1) if lines[k].startswith("## ")), "")
        if section == HEAD_TO_HEAD and lines[at].startswith("|"):
            fail(f"prose {quote!r}: a row of the head-to-head table, which 'claims' traces")
        check_trace(m, e, f"prose {quote!r}", PROSE_KINDS)
        if ("unsupported" in e or "contradicted" in e) and not e.get("proposal"):
            fail(f"prose {quote!r}: not supported, so it needs a proposal (a design-property rewording)")
        if "none" in e and not e["none"]:
            fail(f"prose {quote!r}: 'none' needs the reason it says nothing about the program")
        rows.append({"entry": e, "section": section, "path": path})
    for path, lines in lines_of.items():
        need, base, seen = prose_scope(lines)
        if path == SPEC and not seen:
            fail(f"{SPEC} has no '{BASELINE}' section")
        quotes = [e["quote"] for e in entries if e.get("file", SPEC) == path]
        for n in sorted(need):
            for text in untraced(lines[n], quotes, n in base):
                fail(f"{path}:{n + 1} is about Solana and no prose entry covers it: {text[:70]!r}")
    return rows


ISO_DATE = re.compile(r"\b\d{4}-\d\d-\d\d\b")


def check_measured_dates(m, onchain):
    """A date in the spec text of a statement traced to the on-chain measurement is the date of the
    measurement recorded in ONCHAIN, so a re-measurement that moves the date fails until the spec
    and the mapping follow it."""
    measured = onchain["measured_at"][:10]
    statements = [(f"claim {c['capability']}", [c["solana"], c["impulse"]], c) for c in m["claims"]]
    statements += [(f"prose {e['quote']!r}", [e["quote"]], e) for e in m.get("prose", [])]
    for label, texts, c in statements:
        if "measured" not in c:
            continue
        for date in (d for text in texts for d in ISO_DATE.findall(text)):
            if date != measured:
                fail(f"{label}: the spec text says {date}, but {ONCHAIN} records the measurement on {measured}")


def check_mutation(tags, listed_tags):
    """Every contract tag a rationale cites fails that row's test when its require is removed."""
    rerun = "; run scripts/gen-parity.sh --mutate-contract"
    if not os.path.exists(os.path.join(ROOT, MUTATION)):
        fail(f"no {MUTATION}" + rerun)
    try:
        r = json.loads(read(MUTATION))
        contract, inputs, recorded, flipped = r["contract_sha256"], r["inputs"], r["tests"], r["flipped"]
        every = set.intersection(*(set(v) for v in flipped.values()))
    except (KeyError, TypeError, ValueError) as err:
        fail(f"{MUTATION} does not parse as a mutation record: {err!r}")
    if contract != digest(read(CONTRACT)):
        fail(f"{MUTATION} records another {CONTRACT}" + rerun)
    for path in MUTATION_INPUTS:
        if inputs.get(path) != digest(read(path)):
            fail(f"{path} changed since {MUTATION}" + rerun)
    if set(flipped) != listed_tags:
        fail(f"{MUTATION} mutates {sorted(flipped)}, {ERRORS} lists {sorted(listed_tags)}" + rerun)
    for item_id, (_, rationale, test, text) in tags.items():
        cited = sorted(set(CITED_TAG.findall(rationale)))
        if not cited:
            continue
        if recorded.get(test) != body_digest(text):
            fail(f"{item_id}: {test} changed since {MUTATION}" + rerun)
        if test in every:
            fail(f"{item_id}: {test} fails under every mutant, so it cannot show which require it exercises")
        for tag in cited:
            if test not in flipped[tag]:
                fail(f"{item_id}: {test} cites {tag}, but replacing {tag} by require(true) does not fail it")


def cell(text):
    if "|" in text or "\n" in text:
        fail(f"table text contains a pipe or newline: {text!r}")
    return text


def link(m, cite):
    path, line = cite.rsplit(":", 1)
    base = f"{m['source']['repository']}/blob/{m['source']['commit']}/{path}"
    anchor = f"?plain=1#L{line}" if path.endswith(".md") else f"#L{line}"
    return f"[{path}:{line}]({base}{anchor})"


def render(m, tags, onchain):
    s = m["source"]
    short = s["commit"][:7]
    by_id = {i["id"]: i for i in m["items"]}
    out = []
    w = out.append
    w("# Parity with the Solana Foundation DvP program")
    w("")
    w("Generated by `scripts/gen-parity.sh` from `tests/parity/solana-dvp.json`, the tagged tests in "
      "`tests/parity/` and their results. Do not edit by hand: `scripts/ci-local.sh` fails when this "
      "file differs from what the tests generate.")
    w("")
    w(f"Compared with [solana-foundation/dvp]({s['repository']}) at commit "
      f"[`{short}`]({s['repository']}/tree/{s['commit']}) ({s['commit_date']}). Licence of the "
      f"compared program: {s['licence']}")
    w("")
    w("Design properties only. No row compares performance, cost, adoption or security level, and "
      "a row says nothing beyond what its test runs. Engine tests run ImpulseVault in the Kaspa "
      "script engine (rusty-kaspa a41a333, covenants enabled) through `tests/engine/harness.rs`; "
      "the other tests run impulse-core's terms and template code. Check tags such as `[S2]` are "
      "the contract refusals listed in `spec/ERRORS.md`.")
    w("")
    w("A code with any prefix of `spec/ERRORS.md` (`TERMS_`, `TEMPLATE_`, `TX_`, `VERIFY_` and the "
      "rest) is a refusal or a report of Impulse's off-chain software, made for whoever runs it: the "
      "creator, a builder, or a funder who checks the terms before funding. The contract does not "
      "repeat those checks. A row whose rationale cites such a code is tagged Equivalent only if it "
      "also cites a contract tag that refuses on chain, or if Solana's own answer to the item is a "
      "check its clients run (the item is marked client side in the mapping); otherwise its test "
      "also runs what the code refuses through the engine and the rationale says what the "
      "contract does with it. Every "
      f"contract tag a rationale cites fails that row's test when its require is replaced by "
      f"`require(true)`, as recorded in `{MUTATION}` (written by `scripts/gen-parity.sh "
      "--mutate-contract` for the contract whose sha256 it records). That record is of template v1. "
      "Template v3 has its own, `tests/engine/mutation-run-v3.txt` (43 of 43 mutants caught); it "
      "runs against the probe (template v3 with the one verify call replaced), not the shipped "
      "bytecode, because a real proof binds one vault address and a mutated contract is another "
      "address, so it is not mutation evidence for `contracts/impulse_vault_v3.sil` as shipped. The "
      "shipped bytecode is covered by the failing test per tag listed in "
      "`tests/engine/V3-SHIPPED-COVERAGE.md`.")
    w("")
    w("Each row's Digest is the first 12 hex digits of the sha256 of its test's source, from the "
      "parity tag to the closing brace, so an edited test changes this file. The inputs below are "
      "digested the same way, in full; the Solana files are pinned under Source and measurements.")
    w("")
    w("| Input | sha256 |")
    w("| --- | --- |")
    for path in DIGESTED:
        w(f"| `{path}` | `{digest(read(path))}` |")
    w("")
    w("## Summary")
    w("")
    w("| Verdict | Instructions | Error codes | README edge cases | Total |")
    w("| --- | --- | --- | --- | --- |")

    def count(kind, pred):
        return sum(1 for i in m["items"] if (kind is None or i["kind"] == kind) and pred(i))

    def row(label, pred):
        cells = [str(count(k, pred)) for k, _ in KINDS] + [str(count(None, pred))]
        w(f"| {label} | " + " | ".join(cells) + " |")

    for verdict, label in SUMMARY.items():
        row(label, lambda i, v=verdict: i["id"] in tags and tags[i["id"]][0] == v)
    row("Pending, no test, nothing claimed", lambda i: i["id"] not in tags)
    row("Unmapped", lambda i: False)
    row("**Rows**", lambda i: True)
    w("")
    w("- **Equivalent**: Impulse has a behaviour that answers the Solana item; the test demonstrates it.")
    w("- **Impossible by construction**: the Solana case cannot arise in Impulse; the test "
      "demonstrates the construction in Impulse's own code that rules it out.")
    w("- **Different by design**: Impulse answers the item differently; the test pins the Impulse "
      "behaviour and the rationale states the difference.")
    w("- **Not covered**: Impulse has no check for the risk the item guards against; the test pins "
      "what Impulse does check and the rationale names the risk left.")
    w("- **Partial**: the test passes for the part the merged code can express; the rest belongs to "
      "the named later increment and nothing is claimed for it yet.")
    w("- **Pending**: the Impulse answer belongs to the named later increment. No test, nothing claimed.")

    for kind, title in KINDS:
        w("")
        w(f"## {title}")
        w("")
        first = "Code | Solana" if kind != "edge_case" else "Solana"
        w(f"| ID | {first} | Source | Verdict | Impulse | Test | Digest | Result |")
        w("| --- | " + "--- | " * (first.count("|") + 1) + "--- | --- | --- | --- | --- | --- |")
        for i in m["items"]:
            if i["kind"] != kind:
                continue
            name = f"`{i['solana']}`" if kind != "edge_case" else i["solana"]
            solana = f"{name}: {i['summary']}"
            if i.get("client_side"):
                solana += " Solana's answer is a check its clients run."
            lead = f"{i['code']} | {cell(solana)}" if kind != "edge_case" else cell(solana)
            source = ", ".join(link(m, c) for c in i["cite"])
            if i["id"] not in tags:
                w(f"| {i['id']} | {lead} | {source} | Pending | {cell(i['pending'])} | none | none "
                  "| pending |")
            else:
                verdict, rationale, test, text = tags[i["id"]]
                if verdict == "partial":
                    rationale += " **Pending:** " + i["pending"]
                w(f"| {i['id']} | {lead} | {source} | {VERDICTS[verdict]} | {cell(rationale)} "
                  f"| `{test}` | `{digest(text)[:12]}` | pass |")

    w("")
    w("## Source and measurements")
    w("")
    w(f"Fetched {s['fetched']}. The rows cite these files at commit `{short}`, pinned by sha256; "
      "`scripts/gen-parity.sh --verify-source` checks a checkout against the pins.")
    w("")
    w("| File | sha256 |")
    w("| --- | --- |")
    for path, pin in s["sha256"].items():
        w(f"| `{path}` | `{pin}` |")
    d = s["deployment"]
    w("")
    w(f"Deployment, from the source: the README's deploying note ({link(m, d['readme_note'])}) "
      f"calls the declared program ID a placeholder that has not been deployed. At the pinned commit "
      f"{link(m, d['declared_at'])} declares `{d['declared_id']}`, set by commit "
      f"[`{d['set_by_commit'][:7]}`]({s['repository']}/commit/{d['set_by_commit']}) "
      f"({d['set_by_date']}; {d['set_by_title']}). The note was last changed in "
      f"[`{d['readme_note_commit'][:7]}`]({s['repository']}/commit/{d['readme_note_commit']}), "
      "an ancestor of that commit, so it is stale against the code. `--verify-source` checks the "
      "declared ID, the commit that set it and the commit order; it cannot judge what either text "
      "means.")
    w("")
    authority = f"upgrade authority `{onchain['authority']}`" if onchain["authority"] else "no upgrade authority"
    w(f"Deployment, measured on Solana mainnet-beta at {onchain['measured_at']} with JSON-RPC "
      f"`getAccountInfo` and `getBlockTime` against {onchain['endpoint']} (method and raw responses: "
      f"`{ONCHAIN}`): the account at `{d['declared_id']}` is executable and owned by the upgradeable "
      f"BPF loader; its ProgramData account `{onchain['program_data']}` records last deploy slot "
      f"{onchain['slot']} (block time {onchain['deployed']}) and {authority}. Not measured: whether "
      "the deployed bytecode matches the pinned source.")

    w("")
    w("## Head-to-head claims in spec/IMPULSE-SPEC.md")
    w("")
    w("Every row of the head-to-head table. The Solana column is traced to the rows above (whose "
      "Source column cites the pinned program), to a cited fact, or to the measurement above; a row "
      "marked not supported or contradicted needs rewording before it is published. The Impulse "
      "column is copied from the spec, with a note where the parity tests show less than it says.")
    w("")
    slot = "names an upgrade authority" if onchain["authority"] else "names no upgrade authority"
    w("| Capability | Solana claim in the spec | Traced to | Impulse claim in the spec |")
    w("| --- | --- | --- | --- |")
    for c in m["claims"]:
        impulse = c["impulse"] + (f" **Note:** {c['impulse_note']}" if "impulse_note" in c else "")
        w(f"| {cell(c['capability'])} | {cell(c['solana'])} | {cell(traced(m, tags, c, slot))} "
          f"| {cell(impulse)} |")
    w("")
    w("## Other statements about Solana in the spec")
    w("")
    w("Every sentence of the spec outside the head-to-head table that is about the Solana program: "
      "each sentence that names Solana and each sentence of the section that describes the program. "
      "Each is quoted in part, traced like the table rows, and where it is not supported or is "
      "contradicted a design-property rewording is proposed for the owner. `scripts/gen-parity.sh` "
      "fails when a quote no longer occurs once in the spec, when the name Solana occurs on a line "
      "outside every quote here, or when a sentence of that section holds no part of a quote. A "
      "sentence outside that section that does not name Solana is not checked. The spec is not "
      "edited by the parity suite.")
    w("")
    w("| Section | Statement | Traced to | Proposed wording |")
    w("| --- | --- | --- | --- |")
    for row in prose_rows(m):
        e = row["entry"]
        proposal = e.get("proposal", "none needed")
        where = row["section"] if row["path"] == SPEC else f"{row['path']}, {row['section'] or 'top'}"
        w(f"| {cell(where)} | {cell(e['quote'])} "
          f"| {cell(traced(m, tags, e, slot, '**Not supported.** '))} | {cell(proposal)} |")
    w("")
    return "\n".join(out)


def traced(m, tags, c, slot, unsupported="**Not supported by the pinned source.** "):
    """How a statement is traced, as the table cell says it."""
    if "items" in c:
        text = ", ".join(
            f"{item_id} ({VERDICTS[tags[item_id][0]].lower() if item_id in tags else 'pending'})"
            for item_id in c["items"]
        )
    elif "source" in c:
        text = "Source fact: " + ", ".join(link(m, x) for x in c["source"]) + ". " + c.get("note", "")
    elif "measured" in c:
        text = "Measured on chain. " + c["measured"].replace(AUTHORITY_SLOT, slot)
    elif "contradicted" in c:
        text = "**Contradicted.** " + c["contradicted"].replace(AUTHORITY_SLOT, slot)
    elif "none" in c:
        text = "Says nothing about the program: " + c["none"]
    else:
        text = unsupported + c["unsupported"]
    if "items" in c and c.get("note"):
        text += ". " + c["note"]
    if c.get("see"):
        if not text.endswith((".", "?", "!")):
            text += "."
        text += " See " + ", ".join(
            f"{item_id} ({VERDICTS[tags[item_id][0]].lower() if item_id in tags else 'pending'})"
            for item_id in c["see"]) + "."
    return text


def verify_source(m, directory):
    """Checks the mapping against a checkout of the pinned commit."""
    s = m["source"]
    if directory is None:
        directory = os.path.join(ROOT, "target", "parity", "solana-dvp")
        if not os.path.isdir(directory):
            os.makedirs(os.path.dirname(directory), exist_ok=True)
            subprocess.run(["git", "clone", "--quiet", s["repository"], directory], check=True)
        subprocess.run(["git", "-C", directory, "-c", "advice.detachedHead=false", "checkout",
                        "--quiet", s["commit"]], check=True)
    head = subprocess.run(["git", "-C", directory, "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    if head != s["commit"]:
        fail(f"{directory} is at {head}, not the pinned {s['commit']}")
    files = {}
    for path, pin in s["sha256"].items():
        with open(os.path.join(directory, path), "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != pin:
            fail(f"{path}: sha256 differs from the pin")
        files[path] = data.decode("utf-8").split("\n")

    def line(cite):
        path, n = cite.rsplit(":", 1)
        n = int(n)
        if not 1 <= n <= len(files[path]) or not files[path][n - 1].strip():
            fail(f"citation {cite} is not a non-empty line")
        return files[path][n - 1]

    for item in m["items"]:
        for cite in item["cite"]:
            line(cite)
    for c in m["claims"] + m.get("prose", []):
        for cite in c.get("source", []):
            line(cite)

    # Error codes: the error.rs variants in order, the README table rows, and the citations.
    error_rs = files["program/src/error.rs"]
    variants = [(n + 1, l.strip().rstrip(",")) for n, l in enumerate(error_rs)
                if re.fullmatch(r"    [A-Z]\w+,", l)]
    errors = [i for i in m["items"] if i["kind"] == "error"]
    if [v for _, v in variants] != [i["solana"] for i in errors]:
        fail("error variants differ from program/src/error.rs")
    readme = files["README.md"]
    table = {}
    for n, text in enumerate(readme):
        row = re.match(r"\| (\d+)\s+\| `(\w+)`", text)
        if row:
            table[int(row.group(1))] = (n + 1, row.group(2))
    for item, (variant_line, variant) in zip(errors, variants):
        want = [f"README.md:{table[item['code']][0]}", f"program/src/error.rs:{variant_line}"]
        if table[item["code"]][1] != variant or item["cite"][:2] != want:
            fail(f"{item['id']}: cite {item['cite'][:2]}, expected {want}")

    # Instructions: the discriminators, and the README instruction table.
    disc = []
    for n, text in enumerate(files["program/src/discriminator.rs"]):
        row = re.fullmatch(r"    (\w+) = (\d+),", text)
        if row:
            disc.append((n + 1, row.group(1), row.group(2)))
    instructions = [i for i in m["items"] if i["kind"] == "instruction"]
    if [(name, int(code)) for _, name, code in disc[:6]] != [(i["solana"], i["code"]) for i in instructions]:
        fail("instructions differ from program/src/discriminator.rs")
    for item, (n, name, _) in zip(instructions, disc):
        readme_row = next(k + 1 for k, l in enumerate(readme) if re.match(rf"\| {item['code']}\s+\| {name} ", l))
        want = [f"README.md:{readme_row}", f"program/src/discriminator.rs:{n}"]
        if item["cite"][:2] != want:
            fail(f"{item['id']}: cite {item['cite'][:2]}, expected {want}")

    # README edge cases: every bullet of the instruction notes and the deploying note is cited.
    start = readme.index("### Notes")
    end = readme.index("## Errors")
    bullets = [n + 1 for n in range(start, end) if re.match(r"\s*- \*\*", readme[n])]
    deploying = readme.index("### Deploying")
    bullets.append(next(n + 1 for n in range(deploying + 1, len(readme)) if readme[n].strip()))
    cited = {c for i in m["items"] for c in i["cite"]}
    uncited = [b for b in bullets if f"README.md:{b}" not in cited]
    if uncited:
        fail(f"README edge cases not cited by any item: lines {uncited}")
    # Deployment: the declared ID, the commit that set it, and that the README's deploying note
    # was last changed before it. The meaning of either text is not checked.
    d = s["deployment"]
    if f'declare_id!("{d["declared_id"]}");' != line(d["declared_at"]).strip():
        fail(f"{d['declared_at']} does not declare {d['declared_id']}")

    def git(*args):
        return subprocess.run(["git", "-C", directory, *args], capture_output=True, text=True,
                              check=True).stdout.strip()

    path = d["declared_at"].rsplit(":", 1)[0]
    setter = git("log", "-1", "--format=%H", "-S", f'declare_id!("{d["declared_id"]}")', s["commit"], "--", path)
    if setter != d["set_by_commit"]:
        fail(f"the declared ID was set by {setter or 'no commit'}, not {d['set_by_commit']}")
    readme, n = d["readme_note"].rsplit(":", 1)
    blamed = git("blame", "--porcelain", "-L", f"{n},{n}", s["commit"], "--", readme).split(" ", 1)[0]
    if blamed != d["readme_note_commit"]:
        fail(f"{d['readme_note']} was last changed in {blamed}, not {d['readme_note_commit']}: re-read EDGE-24")
    ancestor = subprocess.run(["git", "-C", directory, "merge-base", "--is-ancestor", blamed, setter])
    if blamed == setter or ancestor.returncode != 0:
        fail(f"{d['readme_note']} changed with or after the declared ID was set: re-read EDGE-24")

    edges = [i for i in m["items"] if i["kind"] == "edge_case"]
    print(f"gen-parity: source verified at {s['commit']}: {len(instructions)} instructions, "
          f"{len(errors)} error codes, {len(bullets)} README notes cited by {len(edges)} edge cases; "
          f"declared ID set by {setter[:7]}, after the README deploying note ({blamed[:7]})")


def main(argv):
    m = load_mapping()
    if argv[:1] == ["--verify-source"]:
        verify_source(m, argv[1] if len(argv) > 1 else None)
        return
    if argv == ["--mutate-contract"]:
        mutate_contract(m, load_tags())
        argv = []
    if argv not in ([], ["--check"]):
        fail(f"usage: gen-parity.sh [--check | --mutate-contract | --verify-source [DIR]], got {argv}")
    onchain = load_onchain(m)
    tags = load_tags()
    results = run_tests()
    check(m, tags, results)
    check_measured_dates(m, onchain)
    text = render(m, tags, onchain)
    path = os.path.join(ROOT, OUTPUT)
    rows = len(m["items"])
    if argv == ["--check"]:
        current = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        if current != text:
            diff = difflib.unified_diff(current.splitlines(), text.splitlines(),
                                        "PARITY.md (committed)", "PARITY.md (generated)", lineterm="")
            sys.stderr.write("\n".join(diff) + "\n")
            fail("PARITY.md differs from what the tests generate; run scripts/gen-parity.sh")
        print(f"gen-parity: PARITY.md matches the tests ({rows} rows)")
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"gen-parity: wrote PARITY.md ({rows} rows)")


if __name__ == "__main__":
    main(sys.argv[1:])
