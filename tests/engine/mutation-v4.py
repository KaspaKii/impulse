#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for contracts/impulse_vault_v4.sil (I21; the v1 run is mutation.py, v3 is mutation-v3.py).

Mutants, each compiled with the pinned silverc and run against the named test through
IMPULSE_VAULT_V4_SIL. The require tests (v4_script.rs) run on the SHIPPED template v4, whose
verify call is the real precompile: with no receipt, a faulty spec must be refused BEFORE the gate
and its control (same zero proof) BY the gate, so a mutant that removes the require moves the
faulty spec to the gate and flips the test. The journal tests run on the probe (the same source with
the verify call replaced by a comparison with sha256(J)): the host-built J must equal the J the
script builds, so a mutant that drops or changes a field of J flips them.

  1. Every tagged require replaced by `require(true)`: the named test must flip.
  2. The conjuncts of the bound checks [T2], [T3], [T7], each replaced by `true`.
  3. Every field of J removed (each in the settle and the refund), the item fields and loop bounds
     of the view, the view itself, the mode bytes, the verify call removed, the image ID changed.
  4. Template v4's covenant rule (spec/V3-ZK.md 22.15): each slot's expected covenant ID, the
     slot conditions, the input bound and the range of each loop over the inputs.
  5. The guest's [H5] (spec/V3-ZK.md 22.16, circuits/terms-core/src/statement.rs): the other leg's
     vault slot, its commitment, each check of the vault's own redeem script, where it applies.
     Each mutant is written into statement.rs, run against the named terms-core test, and the
     file is restored. The guest binary is not rebuilt per mutant: a change to the guest changes
     IMAGE_ID_V4, which scripts/build-guest.sh and the template pin catch.

    python3 tests/engine/mutation-v4.py            run and print
    python3 tests/engine/mutation-v4.py --record   also write tests/engine/mutation-run-v4.txt

Needs target/silverc-v1.0.0/bin/silverc (scripts/build-template.sh builds it).
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCE = os.path.join(ROOT, "contracts", "impulse_vault_v4.sil")
CTOR = os.path.join(ROOT, "contracts", "compiled", "impulse_vault.v4.ctor.json")
SILVERC = os.path.join(ROOT, "target", "silverc-v1.0.0", "bin", "silverc")
RECORD = os.path.join(ROOT, "tests", "engine", "mutation-run-v4.txt")

# Require ID -> the refusal test that must flip when that require is removed.
EXPECTED = {
    "T1": "v4_script::v4_t1_vault_beyond_input_1_refused_shipped",
    "T2": "v4_script::v4_t2_input_count_bounds_shipped",
    "T3": "v4_script::v4_t3_output_count_bounds_shipped",
    "T4": "v4_script::v4_t4_authority_signature_shipped",
    "T8": "v4_script::v4_t8_t9_lock_time_finality_shipped",
    "T5": "v4_script::v4_t5_signer_signature_shipped",
    "T6": "v4_script::v4_t6_leg_byte_shipped",
    "T7": "v4_script::v4_t7_refund_view_bounds_shipped",
    "T9": "v4_script::v4_t8_t9_lock_time_finality_shipped",
    "T10": "v4_script::v4_t10_covenant_ids_of_every_settle_input_shipped",
    "T11": "v4_script::v4_t11_covenant_ids_of_every_refund_input_shipped",
}

SETTLE_J = "v4_script::v4_probe_settle_accepted_every_cash_kind"
REFUND_J = "v4_script::v4_probe_refund_accepted"
GATE = "v4_script::v4_t4_authority_signature_shipped"
IMAGE = "v4_template::v4_image_id_in_the_source_is_the_circuits_image_id_v4"
SETTLE_HEAD = "+ byte[](this.activeInputIndex as byte[1]) + byte[](this.activeInputIndex as byte[1]) +"

# (name, old text, new text, test that must flip). The old text must occur exactly `count` times.
CONJUNCTS = [
    ("[T2] nIn >= 2 dropped", "require(nIn >= 2 && nIn <= 4 && nIn <= tx.inputs.length);", "require(true && nIn <= 4 && nIn <= tx.inputs.length);", EXPECTED["T2"], 1),
    ("[T2] nIn <= 4 dropped", "require(nIn >= 2 && nIn <= 4 && nIn <= tx.inputs.length);", "require(nIn >= 2 && true && nIn <= tx.inputs.length);", EXPECTED["T2"], 1),
    ("[T2] nIn <= tx.inputs.length dropped", "require(nIn >= 2 && nIn <= 4 && nIn <= tx.inputs.length);", "require(nIn >= 2 && nIn <= 4 && true);", EXPECTED["T2"], 1),
    ("[T3] nOut >= 2 dropped", "require(nOut >= 2 && nOut <= 4 && nOut <= tx.outputs.length);", "require(true && nOut <= 4 && nOut <= tx.outputs.length);", EXPECTED["T3"], 1),
    ("[T3] nOut <= 4 dropped", "require(nOut >= 2 && nOut <= 4 && nOut <= tx.outputs.length);", "require(nOut >= 2 && true && nOut <= tx.outputs.length);", EXPECTED["T3"], 1),
    ("[T3] nOut <= tx.outputs.length dropped", "require(nOut >= 2 && nOut <= 4 && nOut <= tx.outputs.length);", "require(nOut >= 2 && nOut <= 4 && true);", EXPECTED["T3"], 1),
]
R7 = "nIn >= 1 && nIn <= 2 && nIn <= tx.inputs.length && nOut >= 1 && nOut <= 2 && nOut <= tx.outputs.length"
for i, part in enumerate(["nIn >= 1", "nIn <= 2", "nIn <= tx.inputs.length", "nOut >= 1", "nOut <= 2", "nOut <= tx.outputs.length"]):
    CONJUNCTS.append(("[T7] %s dropped" % part, R7, R7.replace(part, "true", 1), EXPECTED["T7"], 1))

# Conjuncts whose removal changes nothing observable, because a second mechanism refuses the same
# spec at the same place (before the gate): they are defence in depth and stay in the source. Each
# is listed with its reason and must NOT flip its test (if one flips, it is no longer equivalent and
# the run says so); any other mutant that does not flip fails the run.
EQUIVALENT = {
    "[T2] nIn <= 4 dropped": "the compiled for loop carries its own runtime check that the range is at most MAX_VIEW (silverscript v1.0.0 compiler/for.rs, 'sanity check end-start > max_iterations')",
    "[T3] nOut <= 4 dropped": "the same runtime loop-range check on the output loop",
    "[T2] nIn <= tx.inputs.length dropped": "tx.inputs[i] beyond the transaction's inputs is an engine error before the gate",
    "[T3] nOut <= tx.outputs.length dropped": "tx.outputs[k] beyond the transaction's outputs is an engine error before the gate",
    "[T7] nIn <= tx.inputs.length dropped": "tx.inputs[i] beyond the transaction's inputs is an engine error before the gate",
    "[T7] nOut <= tx.outputs.length dropped": "tx.outputs[k] beyond the transaction's outputs is an engine error before the gate",
}

JOURNAL = [
    ("J: tag removed", "JOURNAL_TAG + MODE_", "MODE_", None, 2),
    ("J: settle mode byte removed", "MODE_SETTLE + ", "", SETTLE_J, 1),
    ("J: refund mode byte removed", "MODE_REFUND + ", "", REFUND_J, 1),
    ("J: settle mode byte is the refund's", "JOURNAL_TAG + MODE_SETTLE", "JOURNAL_TAG + MODE_REFUND", SETTLE_J, 1),
    ("J: refund mode byte is the settle's", "JOURNAL_TAG + MODE_REFUND", "JOURNAL_TAG + MODE_SETTLE", REFUND_J, 1),
    ("J: vault scriptPubKey removed", " + this.activeScriptPubKey", "", None, 2),
    ("J: commitment removed", " + termsCommit", "", None, 2),
    ("J: authority removed", " + byte[](authorityKey)", "", None, 2),
    ("J: settle leg removed", SETTLE_HEAD, "+ byte[](this.activeInputIndex as byte[1]) +", SETTLE_J, 1),
    ("J: refund leg removed", " + byte[1](leg) + byte[](this.activeInputIndex", " + byte[](this.activeInputIndex", REFUND_J, 1),
    ("J: refund input index removed", "byte[1](leg) + byte[](this.activeInputIndex as byte[1])", "byte[1](leg)", REFUND_J, 1),
    ("J: lock time removed", " + byte[](lockTime as byte[8])", "", None, 2),
    ("J: settle signer removed", " + ZERO32 + covA", " + covA", SETTLE_J, 1),
    ("J: refund signer removed", " + byte[](signer)", "", REFUND_J, 1),
    ("J: settle cov_a removed", " + covA + covC", " + covC", SETTLE_J, 1),
    ("J: refund cov_a removed", " + cov + ZERO32", " + ZERO32", REFUND_J, 1),
    ("J: settle cov_c removed", " + covC + byte[](OpCovInputCount", " + byte[](OpCovInputCount", SETTLE_J, 1),
    ("J: refund cov_c removed", " + cov + ZERO32 + byte", " + cov + byte", REFUND_J, 1),
    ("J: settle count_a removed", " + byte[](OpCovInputCount(covA) as byte[1])", "", SETTLE_J, 1),
    ("J: refund count_a removed", " + byte[](OpCovInputCount(cov) as byte[1])", "", REFUND_J, 1),
    ("J: settle count_c removed", " + byte[](OpCovInputCount(covC) as byte[1])", "", SETTLE_J, 1),
    ("J: refund count_c removed", " + byte[1](0x00) + byte[](nIn", " + byte[](nIn", REFUND_J, 1),
    ("J: nIn removed", " + byte[](nIn as byte[1])", "", None, 2),
    ("J: nOut removed", " + byte[](nOut as byte[1])", "", None, 2),
    ("J: view items removed", "sha256(head + items)", "sha256(head)", None, 2),
    ("view: input value removed", "byte[](tx.inputs[i].value as byte[8]) + ", "", None, 1),
    ("view: input scriptPubKey hash removed", "sha256(tx.inputs[i].scriptPubKey) + ", "", None, 1),
    ("view: input covenant ID removed", " + OpInputCovenantId(i)", "", None, 1),
    ("view: output value removed", "byte[](tx.outputs[k].value as byte[8]) + ", "", None, 1),
    ("view: output scriptPubKey hash removed", "sha256(tx.outputs[k].scriptPubKey) + ", "", None, 1),
    ("view: output covenant ID removed", " + OpOutputCovenantId(k)", "", None, 1),
    ("view: input loop stops at two", "for(i, 0, nIn, MAX_VIEW)", "for(i, 0, 2, MAX_VIEW)", None, 1),
    ("view: output loop stops at two", "for(k, 0, nOut, MAX_VIEW)", "for(k, 0, 2, MAX_VIEW)", None, 1),
]

# Template v4's covenant rule: the expected value of each slot, the slot conditions, the bound.
SETTLE_LOOP = "for(i, 0, tx.inputs.length, MAX_INPUTS) {\n            byte[32] want = none;\n            if (i == assetSlot) {"
REFUND_LOOP = "for(i, 0, tx.inputs.length, MAX_INPUTS) {\n            byte[32] want = none;\n            if (i == 1 && nIn == 2) {"
COVENANTS = [
    ("cov: settle asset slot expects no covenant", "                want = covA;", "                want = none;", SETTLE_J, 1),
    ("cov: settle input 3 expects no covenant", "                want = covC;", "                want = none;", SETTLE_J, 1),
    ("cov: external cash asset slot is input 2", "            assetSlot = 1;", "            assetSlot = 2;", SETTLE_J, 1),
    ("cov: refund input 1 expects no covenant", "                want = cov;", "                want = none;", REFUND_J, 1),
    ("cov: refund input 1 condition drops nIn == 2", "if (i == 1 && nIn == 2) {", "if (i == 1) {", EXPECTED["T11"], 1),
    ("cov: input bound raised to nine (both entries)", "int constant MAX_INPUTS = 8;", "int constant MAX_INPUTS = 9;", EXPECTED["T10"], 1),
    ("cov: settle loop covers the view only", SETTLE_LOOP, SETTLE_LOOP.replace("tx.inputs.length", "nIn"), EXPECTED["T10"], 1),
    ("cov: refund loop covers the view only", REFUND_LOOP, REFUND_LOOP.replace("tx.inputs.length", "nIn"), EXPECTED["T11"], 1),
]

GATE_MUTANTS = [
    ("gate: verify call removed (both entries)", "r0.g16.verify(sha256(head + items), proof, IMAGE_ID);", "", GATE, 2),
    ("gate: image ID changed", "IMAGE_ID = byte[32](0xffaa95f9", "IMAGE_ID = byte[32](0xffaa95fa", IMAGE, 1),
]

# The guest's [H5]: (name, old text, new text, terms-core statement test that must flip, count).
STATEMENT = os.path.join(ROOT, "circuits", "terms-core", "src", "statement.rs")
H5_OTHER = "guest_refuses_h5_other_vault"
H5_WITNESS = "guest_refuses_h5_witness"
H5_SCOPE = "h5_does_not_apply_to_external_cash_or_refunds"
GUEST = [
    ("[H5] check removed", "        other_vault(c)?;\n", "", H5_OTHER, 1),
    ("[H5] only for KCC-20 cash", "if !external && c.vault_binding {", "if matches!(t.cash, Leg::Kcc20 { .. }) && c.vault_binding {", H5_OTHER, 1),
    ("[H5] also for external cash", "if !external && c.vault_binding {", "if c.vault_binding {", H5_SCOPE, 1),
    ("[H5] off in statement", "    run(w, opts, true)\n", "    run(w, opts, false)\n", H5_OTHER, 1),
    ("[H5] compares this vault's own slot", "c.input(1 - j.input_index as usize)", "c.input(j.input_index as usize)", H5_OTHER, 1),
    ("[H5] swaps in this leg's commitment", "hashes::commit(&th, 1 - j.leg)", "hashes::commit(&th, j.leg)", H5_OTHER, 1),
    ("[H5] the other vault's redeem script is read", "c.w.redeem(j.input_index as usize)", "c.w.redeem(1 - j.input_index as usize)", H5_OTHER, 1),
    ("[H5] own script need not open J.vault_spk", "        || hashes::p2sh_spk(&hashes::blake2b256(r)) != j.vault_spk\n", "", H5_WITNESS, 1),
    ("[H5] commitment push byte unchecked", "        || r[at] != 0x20\n", "", H5_WITNESS, 1),
    ("[H5] commitment unchecked", "        || r[at + 1..at + 33] != j.commit\n", "", H5_WITNESS, 1),
    ("[H5] authority push byte unchecked", "        || r[at + 33] != 0x20\n", "", H5_WITNESS, 1),
    ("[H5] authority unchecked", "        || r[at + 34..at + 66] != j.authority\n", "", H5_WITNESS, 1),
    ("[H5] length unchecked", "if r.len() < at + VAULT_STATE_LEN\n", "if false\n", H5_WITNESS, 1),
    ("[H5] state offset moved", "pub const VAULT_STATE_OFFSET: usize = 1;", "pub const VAULT_STATE_OFFSET: usize = 2;", H5_OTHER, 1),
]


def run_guest_test(name):
    """True when the named terms-core statement test fails against the current statement.rs."""
    cmd = ["cargo", "test", "--locked", "-p", "impulse-terms-core", "--test", "statement", name, "--", "--exact"]
    out = subprocess.run(cmd, cwd=os.path.join(ROOT, "circuits"), capture_output=True, text=True)
    text = out.stdout + out.stderr
    if "test result:" not in text and "error[" in text:
        sys.exit("terms-core tests did not build:\n%s" % text[-3000:])
    return re.search(r"^test %s \.\.\. FAILED$" % re.escape(name), out.stdout, re.M) is not None, text


TAG = re.compile(r"//\s*\[([A-Z][0-9]+)\]\s*$")
REQUIRE = re.compile(r"require\(.*\);")


def requires(lines):
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


def run_test(source_path, expected):
    """True when the named test fails against `source_path`."""
    target, name = expected.split("::")
    env = dict(os.environ, IMPULSE_VAULT_V4_SIL=source_path)
    cmd = ["cargo", "test", "--locked", "-p", "impulse-engine-tests", "--test", target, name, "--", "--exact"]
    out = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    text = out.stdout + out.stderr
    if "test result:" not in text and "error[" in text:
        sys.exit("test target %s did not build:\n%s" % (target, text[-3000:]))
    return re.search(r"^test %s \.\.\. FAILED$" % re.escape(name), out.stdout, re.M) is not None, text


def compiles(path):
    out = subprocess.run([SILVERC, path, "--constructor-args", CTOR, "-c"], capture_output=True, text=True)
    return out.returncode == 0, out.stderr.strip()


def main():
    record = "--record" in sys.argv[1:]
    if not os.access(SILVERC, os.X_OK):
        sys.exit("missing %s: run scripts/build-template.sh first" % SILVERC)
    with open(SOURCE) as f:
        original = f.read()
    lines = original.split("\n")
    found = requires(lines)
    digest = hashlib.sha256(original.encode()).hexdigest()
    with open(os.path.join(ROOT, "contracts", "TEMPLATE_HASH_V4")) as f:
        template_hash = f.read().strip()
    other = CONJUNCTS + JOURNAL + COVENANTS + GATE_MUTANTS
    with open(STATEMENT) as f:
        statement_src = f.read()
    statement_digest = hashlib.sha256(statement_src.encode()).hexdigest()
    report = [
        "Mutation run, contracts/impulse_vault_v4.sil (tests/engine/mutation-v4.py)",
        "source sha256 %s" % digest,
        "TEMPLATE_HASH_V4 %s" % template_hash,
        "circuits/terms-core/src/statement.rs sha256 %s" % statement_digest,
        "IMAGE_ID_V4 %s" % open(os.path.join(ROOT, "circuits", "IMAGE_ID_V4")).read().strip(),
        "require mutants %d, other mutants %d" % (len(found), len(other)),
        "guest [H5] mutants %d (circuits/terms-core/src/statement.rs)" % len(GUEST),
        "scope: the require tests run on the shipped template v4 (zero proof, refusal before the gate against a",
        "control refused by the gate); the journal tests run on the probe, the same source with the verify call",
        "replaced by a comparison with sha256(J). Real-receipt tests (v4_live.rs) are not mutated: a mutant is",
        "another vault address and a receipt binds one.",
        "",
    ]
    caught = 0
    total = 0
    equivalent = []

    def judge(label, path, expected, shown):
        nonlocal caught, total
        ok, err = compiles(path)
        if not ok:
            sys.exit("mutant %s does not compile: %s" % (label, err))
        flipped, _ = run_test(path, expected)
        reason = EQUIVALENT.get(shown)
        if reason is not None:
            if flipped:
                sys.exit("mutant %r is listed as equivalent but flips %s: remove it from EQUIVALENT" % (shown, expected))
            equivalent.append((shown, expected, reason))
            report.append("%s %s" % (label, shown))
            report.append("  EQUIVALENT (not counted): %s still passes; %s" % (expected, reason))
            print("%s %s: equivalent" % (label, shown), flush=True)
            return
        total += 1
        caught += flipped
        report.append("%s %s" % (label, shown))
        report.append("  expected flip: %s -> %s" % (expected, "FLIPPED" if flipped else "NOT FLIPPED"))
        print("%s %s: %s" % (label, shown, "caught" if flipped else "MISSED"), flush=True)

    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "baseline.sil")
        with open(base, "w") as f:
            f.write(original)
        for name in sorted(set(list(EXPECTED.values()) + [SETTLE_J, REFUND_J, GATE, IMAGE])):
            failed, text = run_test(base, name)
            if failed or "test result: ok" not in text:
                sys.exit("baseline is not green for %s:\n%s" % (name, text[-3000:]))
        report.append("baseline: every named test passes")
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
            judge("[%s]" % rid, path, EXPECTED[rid], lines[n].strip().split("//")[0].strip())

        for k, (name, old, new, expected, count) in enumerate(other):
            if original.count(old) != count:
                sys.exit("mutant %r: pattern found %d times, expected %d" % (name, original.count(old), count))
            path = os.path.join(tmp, "other_%d.sil" % k)
            with open(path, "w") as f:
                f.write(original.replace(old, new))
            judge("[mutant]", path, expected or (REFUND_J if "refund" in name else SETTLE_J), name)
            if expected is None:
                # a field present in both entries: also its refund half must flip the refund test
                total_before = total
                flipped_r, _ = run_test(path, REFUND_J)
                total += 1
                caught += flipped_r
                report.append("  and in the refund: %s -> %s" % (REFUND_J, "FLIPPED" if flipped_r else "NOT FLIPPED"))
                print("  refund half: %s" % ("caught" if flipped_r else "MISSED"), flush=True)
                del total_before

        # 5. the guest's [H5], in circuits/terms-core/src/statement.rs, restored after each mutant
        for name in sorted({m[3] for m in GUEST}):
            failed, text = run_guest_test(name)
            if failed or "test result: ok" not in text:
                sys.exit("guest baseline is not green for %s:\n%s" % (name, text[-3000:]))
        report.append("")
        report.append("guest baseline: every named terms-core test passes")
        try:
            for name, old, new, expected, count in GUEST:
                if statement_src.count(old) != count:
                    sys.exit("guest mutant %r: pattern found %d times, expected %d" % (name, statement_src.count(old), count))
                with open(STATEMENT, "w") as f:
                    f.write(statement_src.replace(old, new))
                flipped, _ = run_guest_test(expected)
                total += 1
                caught += flipped
                report.append("[guest] %s" % name)
                report.append("  expected flip: terms-core statement::%s -> %s" % (expected, "FLIPPED" if flipped else "NOT FLIPPED"))
                print("[guest] %s: %s" % (name, "caught" if flipped else "MISSED"), flush=True)
        finally:
            with open(STATEMENT, "w") as f:
                f.write(statement_src)

    report.append("")
    report.append("equivalent mutants (conjuncts that another mechanism refuses identically, kept as defence in depth): %d" % len(equivalent))
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
