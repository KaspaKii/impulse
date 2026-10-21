#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for contracts/impulse_vault_v3.sil (I20; the v1 run is mutation.py).

Two kinds of mutant, each compiled with the pinned silverc and run against the engine tests
through IMPULSE_VAULT_V3_SIL. The v1 settle and refund suites run on template v3 through the
probe (v3p_*, harness::v3_probe_by_default) and v3_refund; the journal tests (v3_journal) build
the expected J from the spec; v3p_gate tests [Z1] and [Z2] with a proof the gate accepts.

  1. Every tagged require, replaced by `require(true)`: the named test must flip.
  2. The gate itself: the r0.g16.verify call removed, each of the four fields removed from the
     journal, the owner scriptPubKey form forced to P2PK or to P2SH, the gate moved to the
     cash vault or off the asset vault: the named test must flip. Also [S10]'s condition and
     slot (the other leg's vault): the named test must flip.

The contract carries its own template suffix length (SUFFIX_LEN, for [S10]); every mutant's
SUFFIX_LEN is re-established at its fixed point before it runs, and the probe built by the
harness sets the probe's own (harness::v3_probe_source), so a mutant is not refused merely
because its suffix moved.

Each mutant runs only the test target of its named test (the baseline runs every target once), so
"also flipped" lists the other tests of that target.

Scope: this run mutates the PROBE (the v3 source with the verify call replaced), not the shipped
bytecode. It shows the tests are sensitive to each require and journal field; it is not mutation
evidence for contracts/impulse_vault_v3.sil as shipped, which tests/engine/V3-SHIPPED-COVERAGE.md
covers with a failing test per tag.

Real-proof tests (v3_proofs, v3_settle) are bound to the vault address, which every mutant
changes, so they flip on every mutant for that reason alone; only the verify-call mutant is
judged by one of them (a mutant with no gate accepts a bit-flipped proof, whatever its address).

    python3 tests/engine/mutation-v3.py            run and print
    python3 tests/engine/mutation-v3.py --record   also write tests/engine/mutation-run-v3.txt

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
SOURCE = os.path.join(ROOT, "contracts", "impulse_vault_v3.sil")
CTOR = os.path.join(ROOT, "contracts", "compiled", "impulse_vault.v3.ctor.json")
SILVERC = os.path.join(ROOT, "target", "silverc-v1.0.0", "bin", "silverc")
RECORD = os.path.join(ROOT, "tests", "engine", "mutation-run-v3.txt")
PROBE_TARGETS = ["v3_refund", "v3p_settle", "v3p_locktime", "v3p_escrow_release", "v3p_gate", "v3_journal", "v3p_foreign_covenant", "v3p_sibling"]
REAL_TARGETS = ["v3_proofs"]

# Require ID -> the refusal test that must flip when that require is removed.
EXPECTED = {
    "S1": "v3p_settle::suite::s1_second_kas_cash_deposit_cannot_settle_off_its_index",
    "E1": "v3p_escrow_release::suite::second_escrow_deposit_cannot_ride_along_a_settle",
    "E2": "v3p_settle::suite::e2_escrow_without_covenant_binding_real_asset_elsewhere",
    "E3": "v3p_settle::suite::e3_escrow_owner_type_pubkey",
    "E4": "v3p_settle::suite::e4_escrow_owned_by_another_vault",
    "E5": "v3p_settle::suite::e5_escrow_over_funded",
    "E6": "v3p_settle::suite::e6_minter_escrow_cannot_hand_minting_to_a_stranger",
    "S2": "v3p_settle::suite::s2_kas_cash_vault_under_funded",
    "S3": "v3p_locktime::suite::s3_settle_one_daa_before_earliest",
    "D1": "v3p_foreign_covenant::suite::d1_output0_without_a_covenant_real_asset_to_a_stranger",
    "D2": "v3p_settle::suite::d2_asset_delivery_carrier_kas_short",
    "S4": "v3p_settle::suite::s4_kas_proceeds_to_stranger",
    "S5": "v3p_settle::suite::s5_kas_proceeds_short",
    "S6": "v3p_settle::suite::s6_authority_signature_from_stranger",
    "S7": "v3p_settle::suite::s7_external_cash_without_authority",
    "S8": "v3p_settle::suite::s8_seller_authorizer_return_to_stranger",
    "S9": "v3p_settle::suite::s9_seller_return_short",
    "R1": "v3_refund::suite::r1_stranger_signer",
    "R2": "v3_refund::suite::r2_depositor_named_stranger_signs",
    "R3": "v3p_locktime::suite::r3_depositor_earmarked_refund_one_daa_before_expiry",
    "R4": "v3_refund::suite::r4_second_kas_cash_deposit_cannot_refund_off_input_0",
    "R5": "v3_refund::suite::r5_authorizer_kas_short",
    "R6": "v3_refund::suite::r6_kas_cash_to_stranger",
    "R7": "v3_refund::suite::r7_authorizer_kas_to_stranger",
    "R8": "v3p_escrow_release::suite::second_escrow_deposit_cannot_ride_along_a_refund",
    "R9": "v3p_foreign_covenant::suite::r9_covenant_less_copy_at_input_1_real_escrow_at_input_2",
    "R10": "v3p_foreign_covenant::suite::r10_home_output_without_a_covenant_escrow_to_a_stranger",
    "R11": "v3_refund::suite::r11_counterparty_cannot_refund_asset_authorizer_without_token",
    "R12": "v3_refund::suite::r12_counterparty_cannot_substitute_a_foreign_token",
    "R13": "v3_refund::suite::r13_token_carrier_kas_short",
    "R14": "v3_refund::suite::r14_asset_decoy_amount_0",
    "Z1": "v3p_gate::z1_covenant_owner_refused",
    "Z2": "v3p_gate::z2_cash_vault_nonempty_proof_refused",
    "F1": "v3p_foreign_covenant::suite::f1_asset_vault_settle_refuses_a_token_of_another_covenant",
    "F2": "v3p_foreign_covenant::suite::f2_asset_vault_refuses_a_second_token_of_the_cash_covenant",
    "F3": "v3p_foreign_covenant::suite::f3_refund_refuses_a_token_of_another_covenant",
    "F4": "v3p_foreign_covenant::suite::f4_a_settle_with_13_inputs_is_refused_at_the_bound",
    "F5": "v3p_foreign_covenant::suite::f5_a_refund_with_13_inputs_is_refused_at_the_bound",
    "S10": "v3p_sibling::suite::s10_a_cash_token_at_the_asset_vault_cannot_pay_the_seller_without_the_cash_vault",
}

# Gate mutants: name -> (old text, new text, test that must flip, targets to run)
VERIFY = "r0.g16.verify(journalHash, proof, IMAGE_ID);"
JOURNAL = "sha256(JOURNAL_TAG + listRoot + this.activeScriptPubKey + ownerSpk)"
J_TEST = "v3_journal::v3_journal_accepted_for_pubkey_and_script_hash_owners"
GATE_MUTANTS = [
    ("verify call removed", VERIFY, "// verify removed", "v3_proofs::v3_proof_bit_flip_refused", REAL_TARGETS),
    ("journal without the tag", JOURNAL, "sha256(listRoot + this.activeScriptPubKey + ownerSpk)", J_TEST, PROBE_TARGETS),
    ("journal without the list root", JOURNAL, "sha256(JOURNAL_TAG + this.activeScriptPubKey + ownerSpk)", J_TEST, PROBE_TARGETS),
    ("journal without the vault scriptPubKey", JOURNAL, "sha256(JOURNAL_TAG + listRoot + ownerSpk)", J_TEST, PROBE_TARGETS),
    ("journal without the owner scriptPubKey", JOURNAL, "sha256(JOURNAL_TAG + listRoot + this.activeScriptPubKey)", J_TEST, PROBE_TARGETS),
    ("owner scriptPubKey always P2PK form", "if (buyerDeliveryType == IDENTIFIER_PUBKEY) {", "if (true) {", J_TEST, PROBE_TARGETS),
    ("owner scriptPubKey always P2SH form", "if (buyerDeliveryType == IDENTIFIER_PUBKEY) {", "if (false) {", J_TEST, PROBE_TARGETS),
    ("P2PK script ends with another opcode", "byte[1](0xac)", "byte[1](0xad)", J_TEST, PROBE_TARGETS),
    ("gate on every leg", "        if (legIndex == ASSET_LEG) {\n            require(buyerDeliveryType == IDENTIFIER_PUBKEY", "        if (true) {\n            require(buyerDeliveryType == IDENTIFIER_PUBKEY", "v3p_gate::z2_cash_vault_empty_proof_settles", PROBE_TARGETS),
    ("gate on no leg", "        if (legIndex == ASSET_LEG) {\n            require(buyerDeliveryType == IDENTIFIER_PUBKEY", "        if (false) {\n            require(buyerDeliveryType == IDENTIFIER_PUBKEY", "v3p_gate::z1_script_hash_owner_settles", PROBE_TARGETS),
    ("[S10] only for KCC-20 cash (KAS cash left unbound)", "if (cashKind != CASH_EXTERNAL) {\n            int vaultIdx", "if (cashKind == CASH_KCC20) {\n            int vaultIdx", "v3p_sibling::suite::s10_asset_vault_refuses_a_kas_cash_settle_without_the_cash_vault", PROBE_TARGETS),
    ("[S10] also under external cash", "if (cashKind != CASH_EXTERNAL) {\n            int vaultIdx", "if (true) {\n            int vaultIdx", "v3p_sibling::suite::s10_external_cash_asset_vault_settles_with_no_cash_vault", PROBE_TARGETS),
    ("[S10] rebuilds this vault's own script (legIndex kept)", "OpNum2Bin(otherLeg, 8)", "OpNum2Bin(legIndex, 8)", "v3p_settle::suite::settle_authority_kcc20_cash", PROBE_TARGETS),
    ("[S10] checks this vault's own slot", "require(tx.inputs[otherLeg].scriptPubKey", "require(tx.inputs[legIndex].scriptPubKey", "v3p_settle::suite::settle_authority_kcc20_cash", PROBE_TARGETS),
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


def run_tests(source_path, targets):
    """Names (target::test) of the tests that fail against `source_path`, and the raw output."""
    env = dict(os.environ, IMPULSE_VAULT_V3_SIL=source_path)
    failed, texts = [], []
    for target in targets:
        cmd = ["cargo", "test", "-p", "impulse-engine-tests", "--test", target]
        out = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
        text = out.stdout + out.stderr
        texts.append(text)
        if "test result:" not in text:
            # a panic in every test (the probe cannot be built from the mutant) prints a result too;
            # no result at all means the target did not build or run
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
    compiled = json.load(open(out_path))["contracts"]["ImpulseVaultV3"]["compiled"]
    span = compiled["state_span"]
    return len(compiled["bytecode"]) - span["offset"] - span["len"], ""


def compiles(path, tmp):
    """Compiles `path` and rewrites its SUFFIX_LEN to its fixed point. Returns (ok, error)."""
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
    with open(os.path.join(ROOT, "contracts", "TEMPLATE_HASH_V3")) as f:
        template_hash = f.read().strip()

    report = [
        "Mutation run, contracts/impulse_vault_v3.sil (tests/engine/mutation-v3.py)",
        "source sha256 %s" % digest,
        "TEMPLATE_HASH_V3 %s" % template_hash,
        "require mutants %d, gate and [S10] mutants %d" % (len(found), len(GATE_MUTANTS)),
        "test targets %s; real-proof targets %s" % (", ".join(PROBE_TARGETS), ", ".join(REAL_TARGETS)),
        "scope: the mutants run against the probe (template v3 with the verify call replaced), not the shipped",
        "bytecode; a real proof binds one vault address and a mutant is another address. This is not mutation",
        "evidence for contracts/impulse_vault_v3.sil as shipped; see tests/engine/V3-SHIPPED-COVERAGE.md.",
        "",
    ]
    caught = 0
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "baseline.sil")
        with open(base, "w") as f:
            f.write(original)
        ok, err = compiles(base, tmp)
        if not ok or open(base).read() != original:
            sys.exit("the committed source is not at its SUFFIX_LEN fixed point: %s" % err)
        baseline, text = run_tests(base, PROBE_TARGETS + REAL_TARGETS)
        if baseline:
            sys.exit("baseline is not green:\n%s" % text[-4000:])
        report.append("baseline: all tests pass")
        report.append("")

        for n, rid in found:
            mutant = list(lines)
            new_line, count = REQUIRE.subn("require(true);", mutant[n], count=1)
            if count != 1:
                sys.exit("could not mutate [%s]: %s" % (rid, mutant[n].strip()))
            mutant[n] = new_line
            path = os.path.join(tmp, "mutant_%s.sil" % rid)
            with open(path, "w") as f:
                f.write("\n".join(mutant))
            ok, err = compiles(path, tmp)
            if not ok:
                sys.exit("mutant [%s] does not compile: %s" % (rid, err))
            expected = EXPECTED[rid]
            flipped, _ = run_tests(path, [expected.split("::")[0]])
            hit = expected in flipped
            total += 1
            caught += hit
            report.append("[%s] %s" % (rid, lines[n].strip().split("//")[0].strip()))
            report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if hit else "NOT FLIPPED"))
            others = [t for t in flipped if t != expected]
            report.append("  also flipped (%d): %s" % (len(others), ", ".join(others) if others else "none"))
            print("[%s] %s" % (rid, "caught" if hit else "MISSED"), flush=True)

        for k, (name, old, new, expected, targets) in enumerate(GATE_MUTANTS):
            if original.count(old) != 1:
                sys.exit("gate mutant %r: pattern found %d times" % (name, original.count(old)))
            path = os.path.join(tmp, "gate_%d.sil" % k)
            with open(path, "w") as f:
                f.write(original.replace(old, new))
            ok, err = compiles(path, tmp)
            if not ok:
                sys.exit("gate mutant %r does not compile: %s" % (name, err))
            flipped, _ = run_tests(path, [expected.split("::")[0]])
            hit = expected in flipped
            total += 1
            caught += hit
            report.append("[gate] %s" % name)
            report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if hit else "NOT FLIPPED"))
            others = [t for t in flipped if t != expected]
            report.append("  also flipped (%d): %s" % (len(others), ", ".join(others) if others else "none"))
            print("[gate] %s: %s" % (name, "caught" if hit else "MISSED"), flush=True)

    report.append("")
    report.append("result: %d of %d mutants caught by their named test" % (caught, total))
    text = "\n".join(report) + "\n"
    print(text)
    if record:
        with open(RECORD, "w") as f:
            f.write(text)
    if caught != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
