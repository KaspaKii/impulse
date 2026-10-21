#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for contracts/impulse_vault.sil (I3, carried forward from the I1 review).

Every require in the contract carries an ID tag (`// [S1]` and so on). For each one, this
script writes a mutant with that require replaced by `require(true)`, checks the mutant still
compiles with the pinned silverc, runs the engine tests against it (IMPULSE_VAULT_SIL), and
asserts that the named refusal test fails, i.e. that the require is the only thing refusing
that case. It also records every other test that flips.

The contract carries its own template suffix length (SUFFIX_LEN, for [S10]), and removing a
require shortens the suffix, so each mutant's SUFFIX_LEN is re-established at its fixed point
before it runs; without this step every mutant would refuse every settle and the run would prove
nothing. Beside the require mutants, EXTRA lists mutants of [S10]'s condition and slot, each with
the test that must flip.

    python3 tests/engine/mutation.py            run and print
    python3 tests/engine/mutation.py --record   also write tests/engine/mutation-run.txt

Needs target/silverc-v1.0.0/bin/silverc (scripts/build-template.sh builds it).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCE = os.path.join(ROOT, "contracts", "impulse_vault.sil")
CTOR = os.path.join(ROOT, "contracts", "compiled", "impulse_vault.v1.ctor.json")
SILVERC = os.path.join(ROOT, "target", "silverc-v1.0.0", "bin", "silverc")
RECORD = os.path.join(ROOT, "tests", "engine", "mutation-run.txt")
TARGETS = ["escrow_release", "settle", "refund", "locktime", "foreign_covenant", "foreign_covenant_residual"]

# Require ID -> the refusal test that must flip when that require is removed.
EXPECTED = {
    "S1": "settle::s1_second_kas_cash_deposit_cannot_settle_off_its_index",
    "E1": "escrow_release::second_escrow_deposit_cannot_ride_along_a_settle",
    "E2": "settle::e2_escrow_without_covenant_binding_real_asset_elsewhere",
    "E3": "settle::e3_escrow_owner_type_pubkey",
    "E4": "settle::e4_escrow_owned_by_another_vault",
    "E5": "settle::e5_escrow_over_funded",
    "E6": "settle::e6_minter_escrow_cannot_hand_minting_to_a_stranger",
    "S2": "settle::s2_kas_cash_vault_under_funded",
    "S3": "locktime::s3_settle_one_daa_before_earliest",
    "D1": "foreign_covenant::d1_output0_without_a_covenant_real_asset_to_a_stranger",
    "D2": "settle::d2_asset_delivery_carrier_kas_short",
    "S4": "settle::s4_kas_proceeds_to_stranger",
    "S5": "settle::s5_kas_proceeds_short",
    "S6": "settle::s6_authority_signature_from_stranger",
    "S7": "settle::s7_external_cash_without_authority",
    "S8": "settle::s8_seller_authorizer_return_to_stranger",
    "S9": "settle::s9_seller_return_short",
    "R1": "refund::r1_stranger_signer",
    "R2": "refund::r2_depositor_named_stranger_signs",
    "R3": "locktime::r3_depositor_earmarked_refund_one_daa_before_expiry",
    "R4": "refund::r4_second_kas_cash_deposit_cannot_refund_off_input_0",
    "R5": "refund::r5_authorizer_kas_short",
    "R6": "refund::r6_kas_cash_to_stranger",
    "R7": "refund::r7_authorizer_kas_to_stranger",
    "R8": "escrow_release::second_escrow_deposit_cannot_ride_along_a_refund",
    "R9": "foreign_covenant::r9_covenant_less_copy_at_input_1_real_escrow_at_input_2",
    "R10": "foreign_covenant::r10_home_output_without_a_covenant_escrow_to_a_stranger",
    "R11": "refund::r11_counterparty_cannot_refund_asset_authorizer_without_token",
    "R12": "refund::r12_counterparty_cannot_substitute_a_foreign_token",
    "R13": "refund::r13_token_carrier_kas_short",
    "R14": "refund::r14_asset_decoy_amount_0",
    "F1": "foreign_covenant::f1_asset_vault_settle_refuses_a_token_of_another_covenant",
    "F2": "foreign_covenant::f2_asset_vault_refuses_a_second_token_of_the_cash_covenant",
    "F3": "foreign_covenant::f3_refund_refuses_a_token_of_another_covenant",
    "F4": "foreign_covenant::f4_a_settle_with_13_inputs_is_refused_at_the_bound",
    "F5": "foreign_covenant::f5_a_refund_with_13_inputs_is_refused_at_the_bound",
    "S10": "foreign_covenant_residual::s10_a_cash_token_at_the_asset_vault_cannot_pay_the_seller_without_the_cash_vault",
}

# [S10]'s condition and slot: (name, exact text in the source, replacement, test that must flip).
EXTRA = [
    ("S10 only for KCC-20 cash (KAS cash left unbound)",
     "if (cashKind != CASH_EXTERNAL) {\n            int vaultIdx",
     "if (cashKind == CASH_KCC20) {\n            int vaultIdx",
     "foreign_covenant_residual::s10_asset_vault_refuses_a_kas_cash_settle_without_the_cash_vault"),
    ("S10 also under external cash",
     "if (cashKind != CASH_EXTERNAL) {\n            int vaultIdx",
     "if (true) {\n            int vaultIdx",
     "foreign_covenant_residual::s10_external_cash_asset_vault_settles_with_no_cash_vault"),
    ("S10 rebuilds this vault's own script (legIndex kept)",
     "OpNum2Bin(otherLeg, 8)",
     "OpNum2Bin(legIndex, 8)",
     "settle::settle_authority_kcc20_cash"),
    ("S10 checks this vault's own slot",
     "require(tx.inputs[otherLeg].scriptPubKey",
     "require(tx.inputs[legIndex].scriptPubKey",
     "settle::settle_authority_kcc20_cash"),
]

TAG = re.compile(r"//\s*\[([A-Z][0-9]+)\]\s*$")
REQUIRE = re.compile(r"require\(.*\);")
SUFFIX = re.compile(r"^(\s*int constant SUFFIX_LEN = )(\d+);", re.M)


def requires(lines):
    """(line index, ID) of every require; every require must carry exactly one tag."""
    found = []
    for n, line in enumerate(lines):
        if "require(" not in line.split("//")[0]:
            continue
        m = TAG.search(line)
        if not m:
            sys.exit("untagged require at line %d: %s" % (n + 1, line.strip()))
        found.append((n, m.group(1)))
    ids = [i for _, i in found]
    if len(set(ids)) != len(ids):
        sys.exit("duplicate require tags: %s" % ids)
    if set(ids) != set(EXPECTED):
        sys.exit("tags %s do not match the expected map %s" % (sorted(ids), sorted(EXPECTED)))
    return found


def run_tests(source_path):
    """Names (target::test) of the tests that fail against `source_path`, and the raw output."""
    env = dict(os.environ, IMPULSE_VAULT_SIL=source_path)
    failed, texts = [], []
    for target in TARGETS:
        cmd = ["cargo", "test", "--locked", "-p", "impulse-engine-tests", "--test", target]
        out = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        text = out.stdout + out.stderr
        texts.append(text)
        if "test result:" not in text:
            sys.exit("test target %s did not run:\n%s" % (target, text[-4000:]))
        for line in out.stdout.splitlines():
            m = re.match(r"test (\S+) \.\.\. FAILED$", line)
            if m:
                failed.append("%s::%s" % (target, m.group(1)))
    return sorted(failed), "\n".join(texts)


def suffix_len(path, tmp):
    out_path = os.path.join(tmp, "artifact.json")
    out = subprocess.run([SILVERC, path, "--constructor-args", CTOR, "-o", out_path], capture_output=True, text=True)
    if out.returncode != 0:
        return None, out.stderr.strip()
    compiled = json.load(open(out_path))["contracts"]["ImpulseVault"]["compiled"]
    span = compiled["state_span"]
    return len(compiled["bytecode"]) - span["offset"] - span["len"], ""


def fix_suffix(path, tmp):
    """Rewrite SUFFIX_LEN in `path` to its fixed point. Returns (ok, error)."""
    for _ in range(8):
        text = open(path).read()
        current = int(SUFFIX.search(text).group(2))
        actual, err = suffix_len(path, tmp)
        if actual is None:
            return False, err
        if actual == current:
            return True, ""
        with open(path, "w") as f:
            f.write(SUFFIX.sub(lambda m: "%s%d;" % (m.group(1), actual), text, count=1))
    return False, "SUFFIX_LEN did not converge"


def main():
    record = "--record" in sys.argv[1:]
    if not os.access(SILVERC, os.X_OK):
        sys.exit("missing %s: run scripts/build-template.sh first" % SILVERC)
    with open(SOURCE) as f:
        original = f.read()
    lines = original.split("\n")
    found = requires(lines)
    digest = hashlib.sha256(original.encode()).hexdigest()
    with open(os.path.join(ROOT, "contracts", "TEMPLATE_HASH")) as f:
        template_hash = f.read().strip()

    report = [
        "Mutation run, contracts/impulse_vault.sil (tests/engine/mutation.py)",
        "source sha256 %s" % digest,
        "TEMPLATE_HASH %s" % template_hash,
        "requires %d, mutants %d, test targets %s" % (len(found), len(found) + len(EXTRA), ", ".join(TARGETS)),
        "",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "baseline.sil")
        with open(base, "w") as f:
            f.write(original)
        ok, err = fix_suffix(base, tmp)
        if not ok or open(base).read() != original:
            sys.exit("the committed source is not at its SUFFIX_LEN fixed point: %s" % err)
        baseline, text = run_tests(base)
        if baseline:
            sys.exit("baseline is not green:\n%s" % text[-4000:])
        report.append("baseline: all tests pass")
        report.append("")

        caught = 0
        for n, rid in found:
            mutant = list(lines)
            new_line, count = REQUIRE.subn("require(true);", mutant[n], count=1)
            if count != 1:
                sys.exit("could not mutate [%s]: %s" % (rid, mutant[n].strip()))
            mutant[n] = new_line
            path = os.path.join(tmp, "mutant_%s.sil" % rid)
            with open(path, "w") as f:
                f.write("\n".join(mutant))
            ok, err = fix_suffix(path, tmp)
            if not ok:
                sys.exit("mutant [%s] does not compile: %s" % (rid, err))
            flipped, _ = run_tests(path)
            expected = EXPECTED[rid]
            hit = expected in flipped
            caught += hit
            report.append("[%s] %s" % (rid, lines[n].strip().split("//")[0].strip()))
            report.append("  SUFFIX_LEN %s" % SUFFIX.search(open(path).read()).group(2))
            report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if hit else "NOT FLIPPED"))
            others = [t for t in flipped if t != expected]
            report.append("  also flipped (%d): %s" % (len(others), ", ".join(others) if others else "none"))
            print("[%s] %s" % (rid, "caught" if hit else "MISSED"), flush=True)

        extra_caught = 0
        for k, (name, old, new, expected) in enumerate(EXTRA):
            if original.count(old) != 1:
                sys.exit("extra mutant %r: its text is not in the source exactly once" % name)
            path = os.path.join(tmp, "extra_%d.sil" % k)
            with open(path, "w") as f:
                f.write(original.replace(old, new))
            ok, err = fix_suffix(path, tmp)
            if not ok:
                sys.exit("extra mutant %r does not compile: %s" % (name, err))
            flipped, _ = run_tests(path)
            hit = expected in flipped
            extra_caught += hit
            report.append("[extra] %s" % name)
            report.append("  SUFFIX_LEN %s" % SUFFIX.search(open(path).read()).group(2))
            report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if hit else "NOT FLIPPED"))
            others = [t for t in flipped if t != expected]
            report.append("  also flipped (%d): %s" % (len(others), ", ".join(others) if others else "none"))
            print("[extra] %s: %s" % (name, "caught" if hit else "MISSED"), flush=True)

    report.append("")
    report.append("result: %d of %d requires caught by their named test" % (caught, len(found)))
    report.append("extra: %d of %d mutants of [S10]'s condition and slot caught by their named test" % (extra_caught, len(EXTRA)))
    text = "\n".join(report) + "\n"
    print(text)
    if record:
        with open(RECORD, "w") as f:
            f.write(text)
    if caught != len(found) or extra_caught != len(EXTRA):
        sys.exit(1)


if __name__ == "__main__":
    main()
