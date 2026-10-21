#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for contracts/impulse_hashlock.sil (I18, spec/V2.md section 11), after tests/engine/mutation.py.

Every require in the contract carries an ID tag (`// [H1]` and so on). For each one, this
script writes a mutant with that require replaced by `require(true)`, checks the mutant still
compiles with the pinned silverc, runs the engine tests against it (IMPULSE_HASHLOCK_SIL), and
asserts that the named refusal test fails, i.e. that the require is the only thing refusing
that case. It also records every other test that flips.

    python3 tests/engine/htlc_mutation.py            run and print
    python3 tests/engine/htlc_mutation.py --record   also write tests/engine/mutation-run-htlc.txt
    python3 tests/engine/htlc_mutation.py --check    only check the record against the source (CI)

Needs target/silverc-v1.0.0/bin/silverc (scripts/build-template.sh builds it).
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCE = os.path.join(ROOT, "contracts", "impulse_hashlock.sil")
CTOR = os.path.join(ROOT, "contracts", "compiled", "impulse_hashlock.v1.ctor.json")
HASH_FILE = os.path.join(ROOT, "contracts", "TEMPLATE_HASH_HASHLOCK")
SILVERC = os.path.join(ROOT, "target", "silverc-v1.0.0", "bin", "silverc")
RECORD = os.path.join(ROOT, "tests", "engine", "mutation-run-htlc.txt")
TARGETS = ["htlc_settle", "htlc_refund", "htlc_foreign_covenant"]

# Require ID -> the refusal test that must flip when that require is removed.
EXPECTED = {
    "H1": "htlc_settle::h1_second_vault_utxo_cannot_claim_off_input_0",
    "H2": "htlc_settle::h2_secret_of_33_bytes",
    "H3": "htlc_settle::h3_wrong_secret",
    "HE1": "htlc_settle::he1_second_escrow_deposit_cannot_ride_along",
    "HE2": "htlc_foreign_covenant::he2_escrow_without_a_covenant_real_asset_elsewhere",
    "HE3": "htlc_settle::he3_escrow_owner_type_pubkey",
    "HE4": "htlc_settle::he4_escrow_owned_by_another_vault",
    "HE5": "htlc_settle::he5_escrow_over_funded",
    "HE6": "htlc_settle::he6_minter_escrow_cannot_hand_minting_to_a_stranger",
    "HD1": "htlc_foreign_covenant::hd1_output0_without_a_covenant_escrow_to_a_stranger",
    "HD2": "htlc_settle::hd2_delivery_carrier_kas_short",
    "HS8": "htlc_settle::hs8_authorizer_return_to_stranger",
    "HS9": "htlc_settle::hs9_authorizer_return_short",
    "HR1": "htlc_refund::hr1_stranger_signer",
    "HR2": "htlc_refund::hr2_seller_cannot_pose_as_the_buyer_before_expiry",
    "HR3": "htlc_refund::hr3_seller_refund_one_daa_before_expiry",
    "HR4": "htlc_refund::hr4_second_vault_utxo_cannot_refund_off_input_0",
    "HR5": "htlc_refund::hr5_authorizer_kas_short",
    "HR7": "htlc_refund::hr7_authorizer_kas_to_stranger",
    "HR11": "htlc_refund::hr11_buyer_cannot_refund_the_authorizer_without_the_token",
    "HR8": "htlc_refund::hr8_second_escrow_deposit_cannot_ride_along_a_seller_refund",
    "HR9": "htlc_foreign_covenant::hr9_covenant_less_copy_at_input_1_real_escrow_at_input_2",
    "HR12": "htlc_refund::hr12_buyer_cannot_substitute_a_foreign_token",
    "HR14": "htlc_refund::hr14_decoy_amount_0",
    "HR10": "htlc_foreign_covenant::hr10_home_output_without_a_covenant_escrow_to_a_stranger",
    "HR13": "htlc_refund::hr13_token_carrier_kas_short",
    "HF1": "htlc_foreign_covenant::hf1_claim_refuses_a_token_of_another_covenant",
    "HF2": "htlc_foreign_covenant::hf2_a_claim_with_13_inputs_is_refused_at_the_bound",
    "HF3": "htlc_foreign_covenant::hf3_refund_refuses_a_token_of_another_covenant",
    "HF4": "htlc_foreign_covenant::hf4_a_refund_with_13_inputs_is_refused_at_the_bound",
}

TAG = re.compile(r"//\s*\[(H[A-Z]?[0-9]+)\]\s*$")
REQUIRE = re.compile(r"require\(.*\);")


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
    env = dict(os.environ, IMPULSE_HASHLOCK_SIL=source_path)
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


def compiles(path):
    out = subprocess.run([SILVERC, path, "--constructor-args", CTOR, "-c"], capture_output=True, text=True)
    return out.returncode == 0, out.stderr.strip()


def check():
    """The committed record is a full catch for the current source and TEMPLATE_HASH_HASHLOCK."""
    with open(SOURCE) as f:
        original = f.read()
    found = requires(original.split("\n"))
    with open(HASH_FILE) as f:
        template_hash = f.read().strip()
    with open(RECORD) as f:
        record = f.read()
    result = re.search(r"^result: (\d+) of (\d+) requires caught by their named test$", record, re.M)
    ok = (
        re.search(r"^source sha256 %s$" % hashlib.sha256(original.encode()).hexdigest(), record, re.M)
        and re.search(r"^TEMPLATE_HASH_HASHLOCK %s$" % template_hash, record, re.M)
        and result
        and result.group(1) == result.group(2) == str(len(found))
    )
    if not ok:
        sys.exit("%s does not record a full catch for the current %s and TEMPLATE_HASH_HASHLOCK; "
                 "rerun python3 tests/engine/htlc_mutation.py --record" % (RECORD, SOURCE))
    print("htlc_mutation: record matches, %d of %d requires caught" % (len(found), len(found)))


def main():
    if "--check" in sys.argv[1:]:
        check()
        return
    record = "--record" in sys.argv[1:]
    if not os.access(SILVERC, os.X_OK):
        sys.exit("missing %s: run scripts/build-template.sh first" % SILVERC)
    with open(SOURCE) as f:
        original = f.read()
    lines = original.split("\n")
    found = requires(lines)
    digest = hashlib.sha256(original.encode()).hexdigest()
    with open(HASH_FILE) as f:
        template_hash = f.read().strip()

    report = [
        "Mutation run, contracts/impulse_hashlock.sil (tests/engine/htlc_mutation.py)",
        "source sha256 %s" % digest,
        "TEMPLATE_HASH_HASHLOCK %s" % template_hash,
        "requires %d, mutants %d, test targets %s" % (len(found), len(found), ", ".join(TARGETS)),
        "",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "baseline.sil")
        with open(base, "w") as f:
            f.write(original)
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
            ok, err = compiles(path)
            if not ok:
                sys.exit("mutant [%s] does not compile: %s" % (rid, err))
            flipped, _ = run_tests(path)
            expected = EXPECTED[rid]
            hit = expected in flipped
            caught += hit
            report.append("[%s] %s" % (rid, lines[n].strip().split("//")[0].strip()))
            report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if hit else "NOT FLIPPED"))
            others = [t for t in flipped if t != expected]
            report.append("  also flipped (%d): %s" % (len(others), ", ".join(others) if others else "none"))
            print("[%s] %s" % (rid, "caught" if hit else "MISSED"), flush=True)

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
