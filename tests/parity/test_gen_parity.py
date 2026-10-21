#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Tests the refusals of tests/parity/gen_parity.py (I10), offline and without cargo.

Each case copies the generator's inputs from this repository into a temporary tree, applies one
change, and runs the generator there with the cargo run replaced by recorded results (every
tagged test passed). The unchanged tree is the accepted control: it must generate exactly the
committed PARITY.md and then pass --check. Every other case must stop with its expected
message, except the accepted variants named as such. The cargo run itself, and the cargo runs of
--mutate-contract, are tested with a stand-in `cargo` on PATH. --verify-source runs against a
synthetic Solana repository built here with git, with a mapping pinned to it, so it needs no
network.

  test_gen_parity.py            run every case (scripts/ci-local.sh runs this)
  test_gen_parity.py --mutate   also replace each fail() call of the generator by a no-op, one at
                                a time, and require some case to catch every one
"""

import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # no __pycache__ beside the generator
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.realpath(os.path.join(HERE, "..", ".."))
GENERATOR = os.path.join(HERE, "gen_parity.py")
TREE = [
    "tests/parity/solana-dvp.json",
    "tests/parity/solana-onchain.json",
    "tests/parity/instructions.rs",
    "tests/parity/errors.rs",
    "tests/parity/edges.rs",
    "tests/parity/common.rs",
    "tests/parity/trade.rs",
    "tests/parity/verify_world.rs",
    "tests/engine/real_terms.rs",
    "spec/IMPULSE-SPEC.md",
    "spec/ERRORS.md",
    "spec/V2.md",
    "PARITY.md",
    "tests/parity/mutation-run.json",
    "contracts/impulse_vault.sil",
    "tests/engine/harness.rs",
    "tests/engine/fixtures/kcc20/kcc20.sil",
]
MUTATION = "tests/parity/mutation-run.json"
GIT = ["git", "-c", "user.name=parity-test", "-c", "user.email=parity-test@invalid",
       "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]


def load(path):
    spec = importlib.util.spec_from_file_location("gen_parity_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.cargo_run_tests = module.run_tests  # the cases below replace run_tests
    return module


def ok_results(gen, root):
    """Every tagged test passed, keyed as `cargo test` names them."""
    results = {}
    for name in gen.ITEM_FILES:
        text = open(os.path.join(root, "tests/parity", name), encoding="utf-8").read()
        for match in gen.TAG.finditer(text):
            results[f"{name[:-3]}::{match.group(4)}"] = "ok"
    return results


def run(gen, root, argv, results=None):
    """Runs the generator in `root`; returns (None, output) or (failure message, output)."""
    gen.ROOT = root
    gen.run_tests = (lambda: results) if results is not None else (lambda: ok_results(gen, root))
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            gen.main(argv)
    except SystemExit as stop:
        return str(stop.code), out.getvalue()
    return None, out.getvalue()


# ----------------------------------------------------------------------------------------------
# Edits of a fixture tree
# ----------------------------------------------------------------------------------------------

def edit(root, path, old, new, count=1):
    full = os.path.join(root, path)
    text = open(full, encoding="utf-8").read()
    if text.count(old) != count:
        raise AssertionError(f"fixture edit: {old!r} occurs {text.count(old)} times in {path}")
    with open(full, "w", encoding="utf-8") as f:
        f.write(text.replace(old, new))


def mapping(root, change):
    path = os.path.join(root, "tests/parity/solana-dvp.json")
    m = json.load(open(path, encoding="utf-8"))
    change(m)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1)


def onchain(root, change):
    path = os.path.join(root, "tests/parity/solana-onchain.json")
    o = json.load(open(path, encoding="utf-8"))
    change(o)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(o, f, indent=1)


def record(root, change):
    path = os.path.join(root, MUTATION)
    r = json.load(open(path, encoding="utf-8"))
    change(r)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1)


def in_every_mutant(r, test):
    for tests in r["flipped"].values():
        if test not in tests:
            tests.append(test)


def append(root, path, text):
    with open(os.path.join(root, path), "a", encoding="utf-8") as f:
        f.write(text)


def strip_last_newline(root):
    """The last test's closing brace ends the file, with no newline after it."""
    path = os.path.join(root, "tests/parity/edges.rs")
    text = open(path, encoding="utf-8").read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip("\n"))


def item(m, item_id):
    return next(i for i in m["items"] if i["id"] == item_id)


def claim(m, capability):
    return next(c for c in m["claims"] if c["capability"] == capability)


def prose(m, quote):
    return next(e for e in m["prose"] if e["quote"] == quote)


TRACE_KEYS = ("items", "source", "note", "see", "unsupported", "measured", "contradicted", "none")


def retrace(entry, **trace):
    """Replaces the trace of a mapping entry (a claim or a prose entry) by `trace`."""
    for key in TRACE_KEYS:
        entry.pop(key, None)
    entry.update(trace)


def programdata(o, change):
    data = o["queries"][1]["response"]["result"]["value"]["data"]
    raw = bytearray(base64.b64decode(data[0]))
    data[0] = base64.b64encode(bytes(change(raw))).decode()


def set_byte(raw, at, value):
    raw[at] = value
    return raw


def regenerate_then(change):
    """Writes PARITY.md for the tree, then applies `change`; --check must then refuse."""
    def case(gen, root):
        message, _ = run(gen, root, [])
        if message is not None:
            return f"setup failed: {message}"
        change(root)
        return run(gen, root, ["--check"])[0]
    return case


def with_results(change):
    def case(gen, root):
        results = ok_results(gen, root)
        change(results)
        return run(gen, root, ["--check"], results)[0]
    return case


def tree_edit(change, argv=("--check",)):
    def case(gen, root):
        change(root)
        return run(gen, root, list(argv))[0]
    return case


SPEC_ROW = "| Atomic single-transaction settlement | Yes | Yes |"
ERR00_TAG = "/// parity: ERR-00 equivalent\n"
ERR00_FN = "fn err00_signer_not_party() {\n"
ERR00_TEST = "errors::err00_signer_not_party"
UPGRADE = "Program upgrade authority to trust"
EDGE02_TAG = "/// parity: EDGE-02 impossible\n/// KAS is native"
ERR09_BODY = "    for leg in [\"asset\", \"cash\"] {"

CHECK_CASES = [
    ("an untagged test", "tests but", tree_edit(lambda r: append(
        r, "tests/parity/edges.rs", "\n#[test]\nfn stray() {}\n"))),
    ("an unknown verdict", "verdict maybe is not one of", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", ERR00_TAG, "/// parity: ERR-00 maybe\n"))),
    ("a tag on two tests", "ERR-00: tagged on two tests", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "/// parity: ERR-02 equivalent\n", "/// parity: ERR-00 equivalent\n"))),
    ("a test with no closing brace", "no closing brace", tree_edit(strip_last_newline)),
    ("an impossible row resting on the fixture (rationale)", "rests on a test fixture", tree_edit(
        lambda r: edit(r, "tests/parity/edges.rs", EDGE02_TAG, EDGE02_TAG.replace("KAS is native", "KAS is native in the fixture")))),
    ("an impossible row resting on the fixture (test body)", "rests on a test fixture", tree_edit(
        lambda r: edit(r, "tests/parity/edges.rs", "fn edge02_native_kas_needs_no_wrapping() {\n",
                       "fn edge02_native_kas_needs_no_wrapping() {\n    let _ = kcc20_source();\n"))),
    ("a tag without a row", "which the mapping does not have", tree_edit(lambda r: edit(
        r, "tests/parity/edges.rs", "/// parity: EDGE-02 impossible\n", "/// parity: EDGE-99 impossible\n"))),
    ("a pending note naming no increment", "names no increment", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-18").update(pending="Later, when the SDK is run.")))),
    ("a pending row answered by a test that is not partial", "tag it partial", tree_edit(lambda r: edit(
        r, "tests/parity/edges.rs", "/// parity: EDGE-18 partial\n", "/// parity: EDGE-18 equivalent\n"))),
    ("a partial test on a row with no pending note", "has no pending note", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-18").pop("pending")))),
    ("an unmapped row", "EDGE-26 is unmapped", tree_edit(lambda r: mapping(
        r, lambda m: m["items"].append(dict(id="EDGE-26", kind="edge_case", solana="x", summary="x",
                                            cite=["README.md:11"]))))),
    ("a failed test", "result is FAILED", with_results(lambda res: res.update({"errors::err00_signer_not_party": "FAILED"}))),
    ("an ignored test", "result is ignored", with_results(lambda res: res.update({"errors::err00_signer_not_party": "ignored"}))),
    ("a missing test result", "result is missing", with_results(lambda res: res.pop("errors::err00_signer_not_party"))),
    ("a cited tag ERRORS.md does not list", "cites [S99]", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "a stranger's signature is refused ([R1])", "a stranger's signature is refused ([S99])"))),
    ("a cited code ERRORS.md does not list", "cites TERMS_NOT_A_CODE", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "(TERMS_AMOUNT_ZERO)", "(TERMS_NOT_A_CODE)"))),
    ("a changed Solana cell in the spec", "claims trace differs", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", SPEC_ROW, "| Atomic single-transaction settlement | Sometimes | Yes |"))),
    ("a changed Impulse cell in the spec", "claims trace differs", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", SPEC_ROW, "| Atomic single-transaction settlement | Yes | Always |"))),
    ("a spec with no head-to-head section", "has no 'Head-to-head", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", "\n## Head-to-head with Solana DvP\n", "\n## Comparison\n"))),
    ("a claim traced two ways", "exactly one of", tree_edit(lambda r: mapping(
        r, lambda m: claim(m, "Atomic single-transaction settlement").update(unsupported="x")))),
    ("a claim traced to no item", "no item IX-9", tree_edit(lambda r: mapping(
        r, lambda m: claim(m, "Atomic single-transaction settlement").update(items=["IX-9"])))),
    ("a claim citing an unpinned file", "claim Licence: cites an unpinned file", tree_edit(lambda r: mapping(
        r, lambda m: claim(m, "Licence").update(source=["NOTICE:1"])))),
    ("a pipe in table text", "contains a pipe or newline", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "a stranger's signature is refused ([R1])", "a stranger's | signature is refused ([R1])"))),
    ("a hand edit of PARITY.md", "PARITY.md differs", regenerate_then(lambda r: edit(
        r, "PARITY.md", "## Summary", "## Summary (edited)"))),
    ("a hollowed test body", "PARITY.md differs", regenerate_then(lambda r: edit(
        r, "tests/parity/errors.rs", ERR09_BODY, "    return;\n" + ERR09_BODY))),
    ("a changed sha256 pin", "PARITY.md differs", regenerate_then(lambda r: edit(
        r, "tests/parity/solana-dvp.json", '"LICENSE": "fa80', '"LICENSE": "0a80'))),
    ("a changed fetch date", "PARITY.md differs", regenerate_then(lambda r: edit(
        r, "tests/parity/solana-dvp.json", '"fetched": "2026-10-07"', '"fetched": "2026-01-01"'))),
    ("an unknown argument", "usage:", tree_edit(lambda r: None, argv=("--bogus",))),
    ("a commit that is not a hash", "source commit is not", tree_edit(lambda r: mapping(
        r, lambda m: m["source"].update(commit="main")))),
    ("a deployment commit that is not a hash", "deployment set_by_commit is not", tree_edit(lambda r: mapping(
        r, lambda m: m["source"]["deployment"].update(set_by_commit="dfd47bf")))),
    ("a deployment citing an unpinned file", "deployment declared_at cites an unpinned file", tree_edit(lambda r: mapping(
        r, lambda m: m["source"]["deployment"].update(declared_at="program/src/state.rs:1")))),
    ("duplicate item ids", "duplicate item ids", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-02").update(id="EDGE-01")))),
    ("an unknown item kind", "unknown kind", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-02").update(kind="note")))),
    ("an item citing an unpinned file", "EDGE-02: cites an unpinned file", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-02").update(cite=["NOTICE:1"])))),
    ("an item with no summary", "EDGE-02: no summary", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "EDGE-02").update(summary="")))),
    ("instructions out of order", "instructions are not codes 0 to 5", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "IX-5").update(code=6)))),
    ("error codes out of order", "error codes are not 0 to 23", tree_edit(lambda r: mapping(
        r, lambda m: item(m, "ERR-23").update(code=24)))),
    ("an on-chain record at another path", "deployment onchain is", tree_edit(lambda r: mapping(
        r, lambda m: m["source"]["deployment"].update(onchain="elsewhere.json")))),
    ("an on-chain query of another ID", "query 1 is not getAccountInfo", tree_edit(lambda r: onchain(
        r, lambda o: o["queries"][0]["request"]["params"].__setitem__(0, "11111111111111111111111111111111")))),
    ("a declared ID that is not executable", "not an executable account", tree_edit(lambda r: onchain(
        r, lambda o: o["queries"][0]["response"]["result"]["value"].update(executable=False)))),
    ("a ProgramData query of another account", "query 2 is not getAccountInfo", tree_edit(lambda r: onchain(
        r, lambda o: o["queries"][1]["request"]["params"].__setitem__(0, "11111111111111111111111111111111")))),
    ("a ProgramData header of the wrong size", "45-byte header", tree_edit(lambda r: onchain(
        r, lambda o: programdata(o, lambda raw: raw[:44])))),
    ("a ProgramData authority option byte of 2", "option byte is 2", tree_edit(lambda r: onchain(
        r, lambda o: programdata(o, lambda raw: set_byte(raw, 12, 2))))),
    ("a block time query of another slot", "query 3 is not getBlockTime", tree_edit(lambda r: onchain(
        r, lambda o: o["queries"][2]["request"].update(params=[1])))),
    ("a measurement time that is not UTC", "measured_at is not a UTC timestamp", tree_edit(lambda r: onchain(
        r, lambda o: o.update(measured_at="7 October 2026")))),
    ("an on-chain record missing a field", "does not parse as the three recorded queries", tree_edit(lambda r: onchain(
        r, lambda o: o["queries"][0]["response"].pop("result")))),
    ("an equivalent row resting on a library code alone", "rests on an off-chain refusal", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "/// parity: ERR-09 divergent\n", "/// parity: ERR-09 equivalent\n"))),
    ("an equivalent row resting on a verifier code, not marked client side", "rests on an off-chain refusal", tree_edit(
        lambda r: mapping(r, lambda m: item(m, "EDGE-19").pop("client_side")))),
    ("a client_side mark that is not true", "client_side is 'yes'", tree_edit(
        lambda r: mapping(r, lambda m: item(m, "EDGE-19").update(client_side="yes")))),
    ("a cited code of a later family that ERRORS.md does not list", "cites TX_NOT_A_CODE", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "(TERMS_AMOUNT_ZERO)", "(TX_NOT_A_CODE)"))),
    ("a claim stating the upgrade authority in fixed text", "states the upgrade authority in fixed text", tree_edit(
        lambda r: mapping(r, lambda m: claim(m, UPGRADE).update(
            measured=claim(m, UPGRADE)["measured"].replace("{upgrade_authority}", "names an upgrade authority"))))),
    ("a claim with another placeholder", "a placeholder other than", tree_edit(
        lambda r: mapping(r, lambda m: claim(m, UPGRADE).update(
            measured=claim(m, UPGRADE)["measured"].replace("{upgrade_authority}", "{authority}"))))),
    ("no mutation record", "no tests/parity/mutation-run.json", tree_edit(
        lambda r: os.remove(os.path.join(r, MUTATION)))),
    ("a mutation record that does not parse", "does not parse as a mutation record", tree_edit(
        lambda r: record(r, lambda x: x.pop("flipped")))),
    ("a mutation record of another contract", "records another contracts/impulse_vault.sil", tree_edit(
        lambda r: append(r, "contracts/impulse_vault.sil", "// changed\n"))),
    ("a mutation record of other tags", "mutates", tree_edit(
        lambda r: record(r, lambda x: x["flipped"].pop("[R14]")))),
    ("a citing test changed since the record", "changed since tests/parity/mutation-run.json", tree_edit(
        lambda r: edit(r, "tests/parity/errors.rs", ERR00_FN, ERR00_FN + "    let _unused = 0;\n"))),
    ("a cited tag whose mutant does not fail the row", "cites [S5], but replacing [S5]", tree_edit(lambda r: edit(
        r, "tests/parity/errors.rs", "a stranger's signature is refused ([R1])", "a stranger's signature is refused ([R1], [S5])"))),
    ("a citing row that every mutant fails", "fails under every mutant", tree_edit(
        lambda r: record(r, lambda x: in_every_mutant(x, ERR00_TEST)))),
    ("no prose trace", "has no prose trace", tree_edit(lambda r: mapping(r, lambda m: m.pop("prose")))),
    ("a quote the spec no longer holds", "occurs 0 times", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", "Solana only offers revocable funding", "Solana offers only revocable funding"))),
    ("a quote that occurs twice", "occurs 2 times", tree_edit(lambda r: append(
        r, "spec/IMPULSE-SPEC.md", "\nSolana only offers revocable funding.\n"))),
    ("a quote in a head-to-head row", "a row of the head-to-head table", tree_edit(lambda r: mapping(
        r, lambda m: m["prose"].append(dict(quote="Rent and account lifecycle", none="x"))))),
    ("a quote over two lines", "the quote is one non-empty line", tree_edit(lambda r: mapping(
        r, lambda m: m["prose"].append(dict(quote="a\nb", none="x"))))),
    ("an empty quote", "the quote is one non-empty line", tree_edit(lambda r: mapping(
        r, lambda m: m["prose"].append(dict(quote="", none="x"))))),
    ("a prose entry in a file that is not a spec file", "is not a spec file", tree_edit(lambda r: mapping(
        r, lambda m: prose(m, "Solana's program is published under the MIT licence").update(file="README.md")))),
    ("a prose entry traced two ways", "exactly one of", tree_edit(lambda r: mapping(
        r, lambda m: prose(m, "Solana's program is published under the MIT licence").update(none="x")))),
    ("a prose entry that is not supported and has no proposal", "needs a proposal", tree_edit(lambda r: mapping(
        r, lambda m: retrace(prose(m, "Solana only offers revocable funding"), unsupported="x")))),
    ("a prose entry that says nothing and gives no reason", "needs the reason", tree_edit(lambda r: mapping(
        r, lambda m: prose(m, "What it ships:").update(none="")))),
    ("a prose entry citing an unknown item", 'prose "Solana\'s program is published under the MIT licence": no item IX-9', tree_edit(
        lambda r: mapping(r, lambda m: prose(m, "Solana's program is published under the MIT licence").update(see=["IX-9"])))),
    ("a prose entry citing an unpinned file", "cites an unpinned file: NOTICE:1", tree_edit(lambda r: mapping(
        r, lambda m: prose(m, "Solana's program is published under the MIT licence").update(source=["NOTICE:1"])))),
    ("a new line about Solana that no entry covers", "no prose entry covers it", tree_edit(lambda r: append(
        r, "spec/IMPULSE-SPEC.md", "\nSolana settles in one transaction.\n"))),
    ("a new line in the baseline section that no entry covers", "no prose entry covers it", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", "- **Licence:** MIT.\n", "- **Licence:** MIT.\n- **Fees:** none.\n"))),
    ("a spec without the baseline section", "has no 'The baseline", tree_edit(lambda r: edit(
        r, "spec/IMPULSE-SPEC.md", "## The baseline: Solana Foundation DvP", "## The baseline"))),
    ("a pipe in a proposal", "contains a pipe or newline", tree_edit(lambda r: mapping(
        r, lambda m: prose(m, "Solana's program is published under the MIT licence").update(proposal="a | b")))),
    # A traced line is not a traced sentence: the first two are the reviewer's probes.
    ("a sentence about Solana appended to a traced line (line 24)", "no prose entry covers it", tree_edit(
        lambda r: edit(r, "spec/IMPULSE-SPEC.md", "and the builders refuse to fund them.",
                       "and the builders refuse to fund them. Solana is also slower to settle and costs more."))),
    ("a sentence about Solana appended to a traced line (line 305)", "no prose entry covers it", tree_edit(
        lambda r: edit(r, "spec/IMPULSE-SPEC.md", "Impulse goes to mainnet at v0.1, with a default per-trade value cap and a risk notice.",
                       "Impulse goes to mainnet at v0.1, with a default per-trade value cap and a risk notice. Solana is slower than Kaspa on every measure."))),
    ("a clause naming Solana added inside a quoted sentence", "no prose entry covers it", tree_edit(
        lambda r: edit(r, "spec/IMPULSE-SPEC.md", "The Solana program is a minimal settlement primitive",
                       "The Solana program is a minimal settlement primitive and Solana is slower"))),
    ("a table cell naming Solana added to a traced row", "no prose entry covers it", tree_edit(
        lambda r: edit(r, "spec/IMPULSE-SPEC.md", "Commitments or ZK are later work |",
                       "Commitments or ZK are later work | Solana is slower |"))),
    ("a new line naming Solana in lower case", "no prose entry covers it", tree_edit(lambda r: append(
        r, "spec/IMPULSE-SPEC.md", "\nthe solana program is slow.\n"))),
    ("a new sentence appended to a traced line of the baseline section", "no prose entry covers it", tree_edit(
        lambda r: edit(r, "spec/IMPULSE-SPEC.md", "- **Licence:** MIT.\n", "- **Licence:** MIT. Free to fork.\n"))),
    ("a prose entry that is contradicted and has no proposal", "needs a proposal", tree_edit(lambda r: mapping(
        r, lambda m: retrace(prose(m, "Solana only offers revocable funding"), contradicted="x")))),
    # A date in the spec text of a measured statement is the date of the recorded measurement.
    ("a measured sentence dated otherwise than the measurement", "records the measurement on 2026-11-01", tree_edit(
        lambda r: onchain(r, lambda o: o.update(measured_at="2026-11-01T00:00:00Z")))),
    ("a measured sentence of the spec dated otherwise than the measurement", "records the measurement on 2026-10-07",
     tree_edit(lambda r: (
         edit(r, "spec/IMPULSE-SPEC.md", "was measured on 2026-10-07.", "was measured on 2026-10-08."),
         mapping(r, lambda m: [e.update(quote=e["quote"].replace("2026-10-07", "2026-10-08"))
                               for e in m["prose"] if "was measured on 2026-10-07" in e["quote"]])))),
    ("a measured head-to-head cell dated otherwise than the measurement", "records the measurement on 2026-10-07",
     tree_edit(lambda r: (
         edit(r, "spec/IMPULSE-SPEC.md", "at the declared ID on 2026-10-07 |", "at the declared ID on 2026-10-08 |"),
         mapping(r, lambda m: claim(m, "On mainnet").update(
             solana=claim(m, "On mainnet")["solana"].replace("2026-10-07", "2026-10-08")))))),
    # The code families of the generator are the Families table of ERRORS.md.
    ("a family in the Families table that the generator lacks", "differ from the Families table", tree_edit(
        lambda r: edit(r, "spec/ERRORS.md", "| `THRESHOLD_` |", "| `NODE_`, `THRESHOLD_` |"))),
    ("a family of the generator that the Families table lacks", "differ from the Families table", tree_edit(
        lambda r: edit(r, "spec/ERRORS.md", "| `SDK_` |", "| `SDX_` |"))),
    ("an ERRORS.md without a Families section", "has no 'Families' section", tree_edit(
        lambda r: edit(r, "spec/ERRORS.md", "\n## Families\n", "\n## Code families\n"))),
]

# A rationale citing a code of any family that ERRORS.md does not list is refused, family by family
# (the cited-code and listed-code patterns are built from one list, so one dropped family would
# let its codes through); and an edit of any input of the mutation record makes the record stale.
for _family in ["TERMS", "TEMPLATE", "TX", "IPST", "VERIFY", "DECODE", "TOKEN", "CLI", "SIGN", "RECEIPT",
                "WATCH", "SDK", "THRESHOLD", "FROST", "ZK", "RELEASE"]:
    CHECK_CASES.append((
        f"a cited {_family}_ code that ERRORS.md does not list", f"cites {_family}_NOT_A_CODE", tree_edit(
            lambda r, f=_family: edit(r, "tests/parity/errors.rs", "a stranger's signature is refused ([R1])",
                                      f"a stranger's signature is refused ([R1], {f}_NOT_A_CODE)"))))
for _input in ["tests/parity/common.rs", "tests/parity/trade.rs", "tests/parity/verify_world.rs",
               "tests/engine/harness.rs", "tests/engine/real_terms.rs", "tests/engine/fixtures/kcc20/kcc20.sil"]:
    CHECK_CASES.append((
        f"a mutation input changed since the record ({_input})", f"{_input} changed since", tree_edit(
            lambda r, p=_input: append(r, p, "// changed\n"))))


def other_spec_file(gen, root):
    """Accepted: a statement in another spec file is traced and named by its file."""
    mapping(root, lambda m: m["prose"].append(dict(
        quote="Every stable code Impulse software returns", file="spec/ERRORS.md",
        none="the opening line of the catalogue")))
    message, _ = run(gen, root, [])
    if message is not None:
        return message
    text = open(os.path.join(root, "PARITY.md"), encoding="utf-8").read()
    if "| spec/ERRORS.md, top | Every stable code Impulse software returns |" not in text:
        return "the statement is not named by its file"
    return None


def impulse_sentence(gen, root):
    """Accepted: a sentence that does not name Solana, outside the baseline section, is not checked
    (the limit of the gate, stated in PARITY.md)."""
    edit(root, "spec/IMPULSE-SPEC.md", "and the builders refuse to fund them.",
         "and the builders refuse to fund them. See spec/TRANSACTIONS.md for the fee rules.")
    message, _ = run(gen, root, [])
    return message


def undecided(gen, root):
    """Accepted: a claim row and a sentence that the pinned source does not support render as such,
    the sentence with its proposed wording."""
    mapping(root, lambda m: (
        retrace(claim(m, "Licence"), contradicted="The LICENSE file says otherwise."),
        retrace(prose(m, "Solana only offers revocable funding"), unsupported="The README says otherwise.",
                proposal="Solana's program offers revocable funding.")))
    message, _ = run(gen, root, [])
    if message is not None:
        return message
    text = open(os.path.join(root, "PARITY.md"), encoding="utf-8").read()
    claims, others = text.split("## Head-to-head claims", 1)[1].split("## Other statements", 1)
    if "**Contradicted.** The LICENSE file says otherwise." not in claims:
        return "the contradicted claim row is not rendered as contradicted"
    if ("**Not supported.** The README says otherwise. | Solana's program offers revocable funding. |"
            not in others):
        return "the unsupported sentence is not rendered with its proposed wording"
    return None


def no_authority(gen, root):
    """Accepted: a record with no upgrade authority renders as such everywhere it is named."""
    onchain(root, lambda o: programdata(o, lambda raw: set_byte(raw, 12, 0)))
    message, _ = run(gen, root, [])
    if message is not None:
        return message
    text = open(os.path.join(root, "PARITY.md"), encoding="utf-8").read()
    claims, others = text.split("## Head-to-head claims", 1)[1].split("## Other statements", 1)
    if (claims.count("names no upgrade authority") != 2 or others.count("names no upgrade authority") != 1
            or "names an upgrade authority" in text):
        return "the claims and the other statements do not render the decoded authority"
    if "and no upgrade authority. Not measured" not in text:
        return "the deployment paragraph does not render the decoded authority"
    return None


# ----------------------------------------------------------------------------------------------
# --mutate-contract with a stand-in cargo
# ----------------------------------------------------------------------------------------------

STAND_IN = """#!/usr/bin/env python3
import json, os, re, sys
plan = json.loads({plan!r})
source = open(os.environ["IMPULSE_VAULT_SIL"], encoding="utf-8").read()
mutated = re.search(r"require\\(true\\);\\s*//\\s*(\\[[A-Z][0-9]+\\])", source)
key = mutated.group(1) if mutated else "baseline"
if plan.get("exit"):
    print("error: could not compile"); sys.exit(101)
if key in plan.get("compile_error", []):
    print("compile: mutant", file=sys.stderr)
for test in plan["tests"]:
    if test in plan.get("missing", {{}}).get(key, []):
        continue
    print("test %s ... %s" % (test, "FAILED" if test in plan["fail"].get(key, []) else "ok"))
print("test result: ok.")
"""


def mutate_cases(gen, scratch):
    """--mutate-contract against a stand-in cargo that fails the tests a plan names."""
    found = []
    bin_dir = os.path.join(scratch, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    path = os.environ["PATH"]
    committed = json.load(open(os.path.join(REPO, MUTATION), encoding="utf-8"))
    tests = sorted(committed["tests"])

    def plan_case(label, expect, plan, change=None):
        root = fresh_tree(scratch, "mutate-" + label)
        if change:
            change(root)
        with open(os.path.join(bin_dir, "cargo"), "w") as f:
            f.write(STAND_IN.format(plan=json.dumps(dict(plan, tests=tests))))
        os.chmod(os.path.join(bin_dir, "cargo"), 0o755)
        os.environ["PATH"] = bin_dir + os.pathsep + path
        try:
            message, _ = run(gen, root, ["--mutate-contract"])
            if expect is None and message is None:
                written = json.load(open(os.path.join(root, MUTATION), encoding="utf-8"))
                if written["flipped"] != committed["flipped"] or written["tests"] != committed["tests"]:
                    message = "the written record differs from the stand-in's results"
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        finally:
            os.environ["PATH"] = path
        passed = message is None if expect is None else (message is not None and expect in message)
        found.append((label, passed, message))

    replay = {"fail": committed["flipped"]}
    plan_case("--mutate-contract replaying the committed record (control)", None, replay)
    plan_case("a mutation run whose baseline fails", "the unmutated contract:",
              dict(replay, fail=dict(replay["fail"], baseline=[ERR00_TEST])))
    plan_case("a mutant the harness cannot compile", "could not compile it", dict(replay, compile_error=["[R1]"]))
    plan_case("a cargo run that runs no tests", "did not run its tests", dict(replay, exit=True))
    plan_case("a mutant run missing a result", "no result for", dict(replay, missing={"[R1]": [ERR00_TEST]}))
    plan_case("a require that is not one tagged line", "a require that is not one tagged line", replay,
              lambda r: edit(r, "contracts/impulse_vault.sil", "entry settle(sig authSig) {\n",
                             "entry settle(sig authSig) {\n        require(false);\n"))
    return found


def cargo_cases(gen, scratch):
    """The real cargo run, with a stand-in `cargo` first on PATH."""
    found = []
    bin_dir = os.path.join(scratch, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stand_in = os.path.join(bin_dir, "cargo")
    path = os.environ["PATH"]
    for name, script, check in [
        ("a cargo run that fails", "echo 'error: build failed'; exit 101",
         lambda message, value: message is not None and "cargo test -p impulse-parity failed" in message),
        ("a cargo run that passes", "echo 'test errors::err00_signer_not_party ... ok'; "
         "echo 'test edges::edge01_funding_by_plain_transfer ... FAILED'",
         lambda message, value: message is None and value == {
             "errors::err00_signer_not_party": "ok", "edges::edge01_funding_by_plain_transfer": "FAILED"}),
    ]:
        with open(stand_in, "w") as f:
            f.write("#!/bin/sh\n" + script + "\n")
        os.chmod(stand_in, 0o755)
        os.environ["PATH"] = bin_dir + os.pathsep + path
        gen.ROOT = scratch
        message, value = None, None
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                value = gen.cargo_run_tests()
        except SystemExit as stop:
            message = str(stop.code)
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        finally:
            os.environ["PATH"] = path
        found.append((name, check(message, value), message))
    return found


# ----------------------------------------------------------------------------------------------
# --verify-source against a synthetic Solana repository
# ----------------------------------------------------------------------------------------------

def git(directory, *args):
    return subprocess.run([*GIT, "-C", directory, *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def write(directory, path, text):
    full = os.path.join(directory, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(text)


def synthetic(scratch):
    """A repository shaped like the pinned program, and a mapping pinned to it."""
    real = json.load(open(os.path.join(REPO, "tests/parity/solana-dvp.json"), encoding="utf-8"))
    ix = [i for i in real["items"] if i["kind"] == "instruction"]
    errs = [i for i in real["items"] if i["kind"] == "error"]
    edges = [i for i in real["items"] if i["kind"] == "edge_case"]
    notes = len(edges) - 1  # every edge case cites one note, EDGE-24 the deploying line instead
    readme = ["# Synthetic DvP", "", "## Instructions", "", "| #   | Name | Signer | Effect |",
              "| --- | ---- | ------ | ------ |"]
    readme += [f"| {i['code']}   | {i['solana']} | any | effect |" for i in ix]
    readme += ["", "### Notes", ""] + [f"- **Note {n}.** text" for n in range(1, notes + 1)]
    readme += ["", "## Errors", "", "| Code | Variant | When |", "| ---- | ------- | ---- |"]
    readme += [f"| {e['code']}    | `{e['solana']}` | when |" for e in errs]
    readme += ["", "### Deploying", "", "The declared ID is a placeholder.", ""]
    error_rs = "pub enum E {\n" + "".join(f"    {e['solana']},\n" for e in errs) + "}\n"
    disc_rs = "pub enum D {\n" + "".join(f"    {i['solana']} = {i['code']},\n" for i in ix) + "}\n"
    declared = real["source"]["deployment"]["declared_id"]
    repo = os.path.join(scratch, "solana-dvp")
    os.makedirs(repo)
    git(repo, "init", "--quiet")
    for path, text in [("README.md", "\n".join(readme)), ("LICENSE", "MIT\n"),
                       ("program/src/error.rs", error_rs), ("program/src/discriminator.rs", disc_rs),
                       ("program/src/instructions.rs", "// instructions\n"),
                       ("program/src/lib.rs", '// lib\ndeclare_id!("Placeholder11111111111111111111111111111111");\n')]:
        write(repo, path, text)
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "program and README")
    note_commit = git(repo, "rev-parse", "HEAD")
    write(repo, "program/src/lib.rs", f'// lib\ndeclare_id!("{declared}");\n')
    git(repo, "commit", "--quiet", "-am", "set the declared ID")
    set_commit = git(repo, "rev-parse", "HEAD")
    write(repo, "LICENSE", "MIT License\n")
    git(repo, "commit", "--quiet", "-am", "licence")
    pinned = git(repo, "rev-parse", "HEAD")

    def line_of(pattern, path="README.md"):
        lines = open(os.path.join(repo, path), encoding="utf-8").read().split("\n")
        return next(n + 1 for n, text in enumerate(lines) if re.match(pattern, text))

    m = copy.deepcopy(real)
    ix, errs, edges = ([i for i in m["items"] if i["kind"] == k] for k in ("instruction", "error", "edge_case"))
    s = m["source"]
    s["repository"], s["commit"] = repo, pinned
    s["sha256"] = {p: hash_file(repo, p) for p in ["README.md", "LICENSE", "program/src/error.rs",
                                                   "program/src/discriminator.rs",
                                                   "program/src/instructions.rs", "program/src/lib.rs"]}
    deploying = line_of(r"The declared ID")
    s["deployment"].update(declared_at="program/src/lib.rs:2", set_by_commit=set_commit,
                           readme_note=f"README.md:{deploying}", readme_note_commit=note_commit)
    for i in ix:
        row = line_of(r"\| %d\s+\| %s " % (i["code"], i["solana"]))
        disc = line_of(r"    %s =" % i["solana"], "program/src/discriminator.rs")
        i["cite"] = ["README.md:%d" % row, "program/src/discriminator.rs:%d" % disc]
    for e in errs:
        row = line_of(r"\| %d\s+\| `" % e["code"])
        variant = line_of(r"    %s," % e["solana"], "program/src/error.rs")
        e["cite"] = ["README.md:%d" % row, "program/src/error.rs:%d" % variant]
    bullets = [line_of(r"- \*\*Note %d\." % n) for n in range(1, notes + 1)]
    for e in edges:
        if e["id"] == "EDGE-24":
            e["cite"] = [f"README.md:{deploying}", "program/src/lib.rs:2"]
        else:
            e["cite"] = [f"README.md:{bullets.pop(0)}"]
    for c in m["claims"] + m["prose"]:
        if "source" in c:
            c["source"] = ["README.md:1"]
    return repo, m


def hash_file(repo, path):
    return hashlib.sha256(open(os.path.join(repo, path), "rb").read()).hexdigest()


def verify_cases(gen, scratch):
    repo, base = synthetic(scratch)
    late_note = None
    found = []

    def run_verify(m, directory, label, expect):
        root = os.path.join(scratch, "root-" + re.sub(r"\W+", "-", label))
        os.makedirs(os.path.join(root, "tests/parity"), exist_ok=True)
        with open(os.path.join(root, "tests/parity/solana-dvp.json"), "w", encoding="utf-8") as f:
            json.dump(m, f)
        argv = ["--verify-source"] + ([directory] if directory else [])
        try:
            message, out = run(gen, root, argv)
        except Exception as err:  # a mutant may crash instead of failing
            message, out = f"crash: {err!r}", ""
        if expect is None:
            passed = message is None and "source verified" in out
        else:
            passed = message is not None and expect in message
        found.append((label, passed, message))

    def variant(change):
        m = copy.deepcopy(base)
        change(m)
        return m

    run_verify(base, repo, "the synthetic repository (control)", None)
    run_verify(base, None, "the synthetic repository, cloned (control)", None)
    git(repo, "checkout", "--quiet", "HEAD~1")
    run_verify(base, repo, "a checkout at another commit", "not the pinned")
    git(repo, "checkout", "--quiet", base["source"]["commit"])
    run_verify(variant(lambda m: m["source"]["sha256"].update(LICENSE="0" * 64)), repo,
               "a file that differs from its pin", "sha256 differs from the pin")
    run_verify(variant(lambda m: item(m, "EDGE-02").update(cite=["README.md:2"])), repo,
               "a citation of an empty line", "is not a non-empty line")
    run_verify(variant(lambda m: claim(m, "Licence").update(source=["LICENSE:99"])), repo,
               "a claim citing a line past the end", "is not a non-empty line")
    run_verify(variant(lambda m: prose(m, "Solana's program is published under the MIT licence").update(source=["LICENSE:99"])), repo,
               "a prose citation of a line past the end", "is not a non-empty line")
    run_verify(variant(lambda m: item(m, "ERR-05").update(solana="Renamed")), repo,
               "a renamed error variant", "error variants differ")
    run_verify(variant(lambda m: item(m, "ERR-05").update(cite=item(m, "ERR-06")["cite"])), repo,
               "an error cited at the wrong lines", "ERR-05: cite")
    run_verify(variant(lambda m: item(m, "IX-3").update(solana="Renamed")), repo,
               "a renamed instruction", "instructions differ")
    run_verify(variant(lambda m: item(m, "IX-3").update(cite=item(m, "IX-4")["cite"])), repo,
               "an instruction cited at the wrong lines", "IX-3: cite")
    run_verify(variant(lambda m: item(m, "EDGE-02").update(cite=item(m, "EDGE-03")["cite"])), repo,
               "a README note no item cites", "not cited by any item")
    run_verify(variant(lambda m: m["source"]["deployment"].update(declared_id="Other1111111111111111111111111111111111111")),
               repo, "another declared ID", "does not declare")
    run_verify(variant(lambda m: m["source"]["deployment"].update(set_by_commit=m["source"]["commit"])), repo,
               "the wrong commit for the declared ID", "the declared ID was set by")
    run_verify(variant(lambda m: m["source"]["deployment"].update(readme_note_commit=m["source"]["commit"])), repo,
               "the wrong commit for the deploying note", "was last changed in")
    # The note changed after the declared ID was set: blame now names a later commit.
    git(repo, "checkout", "--quiet", "-b", "late-note")
    readme = open(os.path.join(repo, "README.md"), encoding="utf-8").read()
    write(repo, "README.md", readme.replace("The declared ID is a placeholder.", "The declared ID is deployed."))
    git(repo, "commit", "--quiet", "-am", "update the deploying note")
    late_note = git(repo, "rev-parse", "HEAD")
    run_verify(variant(lambda m: (m["source"].update(commit=late_note),
                                  m["source"]["sha256"].update({"README.md": hash_file(repo, "README.md")}),
                                  m["source"]["deployment"].update(readme_note_commit=late_note))),
               repo, "a deploying note changed after the declared ID", "changed with or after")
    git(repo, "checkout", "--quiet", base["source"]["commit"])
    return found


# ----------------------------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------------------------

def fresh_tree(scratch, label):
    root = os.path.join(scratch, "tree-" + re.sub(r"\W+", "-", label))
    for path in TREE:
        os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
        shutil.copy(os.path.join(REPO, path), os.path.join(root, path))
    return root


def all_cases(generator_path):
    """(case, passed, message) of every case against the generator at `generator_path`."""
    gen = load(generator_path)
    found = []
    with tempfile.TemporaryDirectory() as scratch:
        root = fresh_tree(scratch, "control")
        committed = open(os.path.join(root, "PARITY.md"), encoding="utf-8").read()
        try:
            first, _ = run(gen, root, [])
            generated = open(os.path.join(root, "PARITY.md"), encoding="utf-8").read()
            second, _ = run(gen, root, ["--check"])
            control = first is None and second is None and generated == committed
            found.append(("the repository's inputs (control)", control, first or second))
        except Exception as err:
            found.append(("the repository's inputs (control)", False, f"crash: {err!r}"))
        for label, expect, case in CHECK_CASES:
            root = fresh_tree(scratch, label)
            try:
                message = case(gen, root)
            except Exception as err:  # a mutant may crash instead of failing
                message = f"crash: {err!r}"
            found.append((label, message is not None and expect in message, message))
        label = "a statement in another spec file (accepted, named by its file)"
        try:
            message = other_spec_file(gen, fresh_tree(scratch, label))
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        found.append((label, message is None, message))
        label = "a sentence about Impulse alone outside the baseline section (accepted, not checked)"
        try:
            message = impulse_sentence(gen, fresh_tree(scratch, label))
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        found.append((label, message is None, message))
        label = "a claim contradicted and a sentence not supported (accepted, rendered with the proposal)"
        try:
            message = undecided(gen, fresh_tree(scratch, label))
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        found.append((label, message is None, message))
        label = "a ProgramData with no upgrade authority (accepted, rendered from the record)"
        try:
            message = no_authority(gen, fresh_tree(scratch, label))
        except Exception as err:  # a mutant may crash instead of failing
            message = f"crash: {err!r}"
        found.append((label, message is None, message))
        found += cargo_cases(gen, os.path.join(scratch, "cargo"))
        found += mutate_cases(gen, os.path.join(scratch, "mutate"))
        found += verify_cases(gen, os.path.join(scratch, "verify"))
    return found


def mutate():
    """Each fail() call replaced by a no-op, one at a time: some case must catch every one."""
    source = open(GENERATOR, encoding="utf-8").read()
    sites = [m.start() for m in re.finditer(r"(?<!def )\bfail\(", source)]
    survivors = []
    with tempfile.TemporaryDirectory() as scratch:
        for n, at in enumerate(sites):
            mutant = os.path.join(scratch, f"mutant_{n}.py")
            with open(mutant, "w", encoding="utf-8") as f:
                f.write(source[:at] + "(lambda *a, **k: None)(" + source[at + len("fail("):])
            line = source.count("\n", 0, at) + 1
            if all(passed for _, passed, _ in all_cases(mutant)):
                survivors.append(line)
            print(f"  mutant {n + 1}/{len(sites)}: fail() at gen_parity.py:{line} "
                  f"{'SURVIVED' if line in survivors else 'caught'}")
    return sites, survivors


def main(argv):
    found = all_cases(GENERATOR)
    failed = [(label, message) for label, passed, message in found if not passed]
    for label, passed, message in found:
        print(f"  {'ok  ' if passed else 'FAIL'} {label}" + ("" if passed else f": {message}"))
    if failed:
        sys.exit(f"test-gen-parity: FAIL: {len(failed)} of {len(found)} cases")
    print(f"test-gen-parity: {len(found)} cases pass")
    if argv == ["--mutate"]:
        sites, survivors = mutate()
        if survivors:
            sys.exit(f"test-gen-parity: FAIL: fail() at lines {survivors} survives every case")
        print(f"test-gen-parity: every one of {len(sites)} fail() calls is caught by a case")
    elif argv:
        sys.exit(f"test-gen-parity: usage: test_gen_parity.py [--mutate], got {argv}")


if __name__ == "__main__":
    main(sys.argv[1:])
