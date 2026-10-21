#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for contracts/impulse_vault_v2.sil (I16), as tests/engine/mutation.py for v1.

Every require in the v2 contract carries an ID tag (`// [S1]` and so on; the tags are scoped to
template v2). For each one, this script writes a mutant with that require replaced by
`require(true)`, re-establishes the mutant's SUFFIX_LEN fixed point (the contract carries its
own template suffix length for [S10], and removing a require shortens the suffix, so without
this step every mutant would refuse every settle and the run would prove nothing), checks the
mutant compiles with the pinned silverc, runs the v2 engine tests against it
(IMPULSE_VAULT_V2_SIL), and asserts that the named refusal test fails, i.e. that the require is
the only thing refusing that case. It also records every other test that flips.

    python3 tests/engine/v2_mutation.py            run and print
    python3 tests/engine/v2_mutation.py --record   also write tests/engine/mutation-run-v2.txt
    python3 tests/engine/v2_mutation.py --check    only check the record matches the source,
                                                   TEMPLATE_HASH_V2 and the tags (CI)

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
SOURCE = os.path.join(ROOT, "contracts", "impulse_vault_v2.sil")
CTOR = os.path.join(ROOT, "contracts", "compiled", "impulse_vault.v2.ctor.json")
HASH = os.path.join(ROOT, "contracts", "TEMPLATE_HASH_V2")
SILVERC = os.path.join(ROOT, "target", "silverc-v1.0.0", "bin", "silverc")
RECORD = os.path.join(ROOT, "tests", "engine", "mutation-run-v2.txt")
TARGETS = ["v2_settle", "v2_refund", "v2_foreign_covenant"]

# Require ID -> the refusal test that must flip when that require is removed.
EXPECTED = {
    # settle
    "S1": "v2_settle::s1_second_kas_deposit_cannot_settle_off_its_index",
    "V1": "v2_settle::v1_leg_count_above_max_legs",
    "V2": "v2_settle::v2_leg_list_longer_than_leg_count",
    "V5": "v2_settle::v5_leg_index_equal_to_leg_count",
    "P1": "v2_settle::p1_zero_lots",
    "E1": "v2_foreign_covenant::e1_a_second_escrow_of_the_covenant_at_another_escrow_slot",
    "E2": "v2_foreign_covenant::e2_the_escrow_slots_swap_their_covenants",
    "E3": "v2_settle::e3_escrow_owner_type_pubkey",
    "E4": "v2_settle::e4_escrow_owned_by_another_vault",
    "E6": "v2_settle::e6_minter_escrow",
    "P2": "v2_settle::p2_kas_vault_over_funded",
    "P3": "v2_settle::p3_held_not_whole_lots",
    "P4": "v2_settle::p4_tranche_beyond_held_with_crafted_negative_min_lot",
    "P5": "v2_settle::p5_tranche_below_min_lot",
    "P6": "v2_settle::p6_remainder_below_min_lot",
    "S3": "v2_settle::s3_settle_one_daa_before_earliest",
    "V6": "v2_settle::v6_leg_kind_byte_2",
    "V7": "v2_settle::v7_kas_delivery_type_2",
    "S10": "v2_settle::s10_crossed_settle_of_two_trades_with_identical_deliveries",
    "S4": "v2_settle::s4_kas_delivery_to_stranger",
    "S5": "v2_settle::s5_kas_delivery_short",
    "D1": "v2_foreign_covenant::d1_delivery_without_a_covenant_escrow_to_a_stranger",
    "D2": "v2_settle::d2_delivery_carrier_kas_short",
    "C1": "v2_settle::c1_final_settle_leaves_a_continuation",
    "S8": "v2_settle::s8_authorizer_return_to_stranger",
    "S9": "v2_settle::s9_authorizer_return_short",
    "C2": "v2_settle::c2_tranche_from_a_zero_covenant_vault",
    "C3": "v2_settle::c3_two_continuations",
    "C4": "v2_settle::c4_continuation_at_another_position",
    "C5": "v2_settle::c5_continuation_with_another_script",
    "C6": "v2_settle::c6_kas_remainder_short",
    "C7": "v2_settle::c7_authorizer_continuation_short",
    "C8": "v2_foreign_covenant::c8_remainder_without_a_covenant_to_a_stranger",
    "C9": "v2_settle::c9_remainder_carrier_short",
    "S6": "v2_settle::s6_authority_signature_from_stranger",
    "F1": "v2_foreign_covenant::f1_every_vault_refuses_a_token_of_another_covenant_after_the_vaults",
    "F4": "v2_foreign_covenant::f4_a_settle_above_n_plus_18_inputs_is_refused_at_the_bound",
    # refund
    "V3": "v2_refund::v3_leg_count_above_max_legs",
    "V4": "v2_refund::v4_leg_list_longer_than_leg_count",
    "V8": "v2_refund::v8_leg_index_equal_to_leg_count",
    "V9": "v2_refund::v9_leg_kind_byte_2",
    "V10": "v2_refund::v10_kas_refund_type_2",
    "R1": "v2_refund::r1_signer_leg_beyond_the_authority",
    "R16": "v2_refund::r16_authority_signs_when_the_terms_name_none",
    "R2": "v2_refund::r2_depositor_named_stranger_signs",
    "R3": "v2_refund::r3_earmarked_depositor_one_daa_before_expiry",
    "R4": "v2_refund::r4_second_kas_deposit_cannot_refund_off_input_0",
    "R5": "v2_refund::r5_vault_kas_short",
    "R15": "v2_refund::r15_refund_leaves_a_continuation",
    "R6": "v2_refund::r6_kas_refund_to_stranger",
    "R7": "v2_refund::r7_authorizer_kas_to_stranger",
    "R11": "v2_refund::r11_another_depositor_cannot_refund_the_authorizer_alone",
    "R8": "v2_refund::r8_second_escrow_rides_along",
    "R9": "v2_foreign_covenant::r9_covenant_less_copy_at_input_1_real_escrow_at_input_2",
    "R12": "v2_refund::r12_foreign_token_not_owned_by_the_vault",
    "R14": "v2_refund::r14_decoy_below_one_lot",
    "R17": "v2_refund::r17_token_above_the_leg_amount",
    "R18": "v2_refund::r18_token_not_whole_lots",
    "R10": "v2_foreign_covenant::r10_home_output_without_a_covenant_escrow_to_a_stranger",
    "R13": "v2_refund::r13_home_carrier_short",
    "F3": "v2_foreign_covenant::f3_refund_refuses_a_token_of_another_covenant",
    "F5": "v2_foreign_covenant::f5_a_refund_with_13_inputs_is_refused_at_the_bound",
}

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


def suffix_len(path, tmp):
    out_path = os.path.join(tmp, "artifact.json")
    out = subprocess.run([SILVERC, path, "--constructor-args", CTOR, "-o", out_path], capture_output=True, text=True)
    if out.returncode != 0:
        return None, out.stderr.strip()
    compiled = json.load(open(out_path))["contracts"]["ImpulseVaultV2"]["compiled"]
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


def run_tests(source_path):
    """Names (target::test) of the tests that fail against `source_path`, and the raw output."""
    env = dict(os.environ, IMPULSE_VAULT_V2_SIL=source_path)
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


def header(original, found):
    digest = hashlib.sha256(original.encode()).hexdigest()
    with open(HASH) as f:
        template_hash = f.read().strip()
    return [
        "Mutation run, contracts/impulse_vault_v2.sil (tests/engine/v2_mutation.py)",
        "source sha256 %s" % digest,
        "TEMPLATE_HASH_V2 %s" % template_hash,
        "requires %d, mutants %d, test targets %s" % (len(found), len(found), ", ".join(TARGETS)),
    ]


def check(original, found):
    """The record matches the current source, TEMPLATE_HASH_V2 and tags, and records a full catch."""
    if not os.path.exists(RECORD):
        sys.exit("missing %s: run python3 tests/engine/v2_mutation.py --record" % RECORD)
    record = open(RECORD).read()
    for line in header(original, found):
        if line not in record.splitlines():
            sys.exit("%s is stale: no line %r; rerun python3 tests/engine/v2_mutation.py --record" % (RECORD, line))
    m = re.search(r"^result: (\d+) of (\d+) requires caught by their named test$", record, re.M)
    if not (m and m.group(1) == m.group(2) == str(len(found))):
        sys.exit("%s does not record every require caught" % RECORD)
    print("v2 mutation record: ok, %d of %d requires caught" % (len(found), len(found)))


def main():
    args = sys.argv[1:]
    with open(SOURCE) as f:
        original = f.read()
    lines = original.split("\n")
    found = requires(lines)
    if "--check" in args:
        check(original, found)
        return
    record = "--record" in args
    if not os.access(SILVERC, os.X_OK):
        sys.exit("missing %s: run scripts/build-template.sh first" % SILVERC)

    report = header(original, found) + [""]
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "baseline.sil")
        with open(base, "w") as f:
            f.write(original)
        ok, err = fix_suffix(base, tmp)
        if not ok or open(base).read() != original:
            sys.exit("the committed source is not at its SUFFIX_LEN fixed point: %s" % err)
        baseline, text = run_tests(base)
        if baseline:
            sys.exit("baseline is not green: %s\n%s" % (baseline, text[-4000:]))
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
            print("[%s] %s (%d other)" % (rid, "caught" if hit else "MISSED", len(others)), flush=True)

    report.append("")
    report.append("result: %d of %d requires caught by their named test" % (caught, len(found)))
    text = "\n".join(report) + "\n"
    print(text)
    if record:
        with open(RECORD, "w") as f:
            f.write(text)
    if caught != len(found):
        sys.exit(1)


if __name__ == "__main__":
    main()
