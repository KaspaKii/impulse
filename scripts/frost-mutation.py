#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Mutation run for the `impulse frost` checks (I13 phase 2, review round 1).

Each mutant below is one hand-written fault in the CLI's FROST code: a check removed or
weakened, a wire tag or digest field changed, a prompt skipped. For each one, this script writes
the mutant into a scratch copy of the repository (the working tree is never touched), runs
`cargo test -p impulse-cli --lib --test frost` there, and records which tests fail. A mutant no
test catches is a survivor. Every pattern must occur exactly once in its file, so a mutant can
never silently stop applying.

The list covers the checks the phase 2 report and review round 1 name. It is not every possible
mutant: a check guarded twice (for example the call of `check_kind` in `frost sign`, which no
IPST that passes the vault-input rule and the terms check can reach) is left out, because no
input can reach the second guard.

    python3 scripts/frost-mutation.py            run and print
    python3 scripts/frost-mutation.py --record   also write crates/impulse-cli/frost-mutation-run.txt
    python3 scripts/frost-mutation.py --check    check the record against the current source and
                                                 this script (scripts/ci-local.sh runs this)

The record names the sha256 of the files below and of this script; --check fails unless both
match and every mutant was caught. Any change to those files needs a new run with --record.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRATE = os.path.join("crates", "impulse-cli")
SRC = os.path.join(CRATE, "src")
RECORD = os.path.join(ROOT, CRATE, "frost-mutation-run.txt")
TARGET_DIR = os.path.join(ROOT, "target", "frost-mutation")
# The FROST code and the tests that guard it; the record goes stale when any of them changes.
COVERED = [
    os.path.join(SRC, "frost.rs"),
    os.path.join(SRC, "frost_tests.rs"),
    os.path.join(SRC, "keygen.rs"),
    os.path.join(SRC, "signing.rs"),
    os.path.join(CRATE, "tests", "frost.rs"),
    os.path.join(CRATE, "tests", "support", "world.rs"),
]

# (id, file in src/, what the fault does, pattern, replacement)
MUTANTS = [
    # Authority inputs and the transaction kind (review round 1, MEDIUM 1).
    ("A1", "frost.rs", "a slot naming the authority may spend any UTXO (a fee input is signed)",
     "if slot.signer() == Some(authority) && !vaults.contains(&entry.script_public_key) {",
     "if false {"),
    ("A2", "frost.rs", "any kind the terms check finds is signed",
     "        IpstKind::Settle\n        | IpstKind::Refund {\n            signer: RefundSigner::Authority,\n            ..\n        } => Ok(()),",
     "        _ if true => Ok(()),"),
    ("A3", "frost.rs", "the outputs are not shown before signing",
     '"output {i}: {} sompi to {}{covenant}",', '"output {i}: {} sompi at {}{covenant}",'),
    ("A4", "frost.rs", "the change is not shown before signing",
     "\"change: {} sompi to {} (the fee payer's)\",", "\"change: {} sompi (the fee payer's) {}\","),
    ("A5", "frost.rs", "a wrong session typed back still signs",
     "if answer.trim() != hex(session) {", "if false {"),
    ("A6", "frost.rs", "the signer is never asked to approve",
     "            approve(console, &session, &terms.terms_hash())?;\n", ""),
    # Terms check of frost sign (review round 1, LOW 2).
    ("T1", "frost.rs", "--cash-template ignored",
     "let cash = a.cash_template.as_deref().map(read_template).transpose()?;",
     "let cash: Option<Kcc20Template> = None;"),
    ("T2", "frost.rs", "the terms check runs without the cash template",
     ".verify_against_terms(&asset, cash.as_ref(), now)", ".verify_against_terms(&asset, None, now)"),
    # Session files (review round 1, MEDIUM 3 and LOW trailing bytes).
    ("S1", "frost.rs", "a signature-share file of another set of inputs accepted",
     "if !shares.keys().eq(inputs.iter()) || shares.len() != count as usize {", "if false {"),
    ("S2", "frost.rs", "a commitment file with a repeated input accepted",
     "if !commitments.keys().eq(inputs.iter()) || commitments.len() != count as usize {",
     "if !commitments.keys().eq(inputs.iter()) {"),
    ("S3", "frost.rs", "a commitment file of another set of inputs accepted",
     "if !commitments.keys().eq(inputs.iter()) || commitments.len() != count as usize {",
     "if commitments.len() != count as usize {"),
    ("S4", "frost.rs", "trailing bytes after the last entry accepted",
     "        if self.rest.is_empty() {\n            Ok(())", "        if true {\n            Ok(())"),
    ("S5", "frost.rs", "a commitment file of another session accepted",
     "commitments.insert(input, c);\n    }\n    b.end()?;\n    if file_session != *session {",
     "commitments.insert(input, c);\n    }\n    b.end()?;\n    if false {"),
    ("S6", "frost.rs", "a signature-share file of another session accepted",
     "shares.insert(input, s);\n    }\n    b.end()?;\n    if file_session != *session {",
     "shares.insert(input, s);\n    }\n    b.end()?;\n    if false {"),
    ("S7", "frost.rs", "a signature share made against other commitments accepted",
     "        if theirs != set_digest {", "        if false {"),
    ("S8", "frost.rs", "the group file of another group accepted",
     "    if group.authority_key() != authority {", "    if false {"),
    ("S9", "frost.rs", "aggregate checks --out only when writing",
     "    check_signers(group.shape(), &signers)?;\n    must_not_exist(&a.out)?;",
     "    check_signers(group.shape(), &signers)?;"),
    ("S10", "frost.rs", "sign overwrites its own signature-share file",
     "            must_not_exist(&a.dir.join(sigshare_name(me)))?;\n", ""),
    # Wire formats (review round 1, MEDIUM 4).
    ("W1", "frost.rs", "commitment set digest without the session",
     "    state.update(session);\n    for (id, by_input) in set {", "    for (id, by_input) in set {"),
    ("W2", "frost.rs", "commitment set digest without the party numbers",
     "        state.update(&id.to_be_bytes());\n        for c in by_input.values() {",
     "        for c in by_input.values() {"),
    ("W3", "frost.rs", "round-1 tag changed", '"impulse-frost-round1-v1"', '"impulse-frost-round1-v2"'),
    ("W4", "frost.rs", "round-2 tag changed", '"impulse-frost-round2-v1"', '"impulse-frost-round2-v2"'),
    ("W5", "frost.rs", "share tag changed", '"impulse-frost-share-v1"', '"impulse-frost-share-v2"'),
    ("W6", "frost.rs", "group tag changed", '"impulse-frost-group-v1"', '"impulse-frost-group-v2"'),
    ("W7", "frost.rs", "commit tag changed", '"impulse-frost-commit-v1"', '"impulse-frost-commit-v2"'),
    ("W8", "frost.rs", "sigshare tag changed", '"impulse-frost-sigshare-v1"', '"impulse-frost-sigshare-v2"'),
    ("W9", "frost.rs", "session domain changed", 'b"Impulse/frostsession/v1"', 'b"Impulse/frostsession/v2"'),
    ("W10", "frost.rs", "commitment set domain changed",
     'b"Impulse/frostcommitments/v1"', 'b"Impulse/frostcommitments/v2"'),
    ("W11", "frost.rs", "session digest without the signers",
     "    for id in signers {\n        state.update(&id.to_be_bytes());\n    }\n    state.update(&(messages.len()",
     "    state.update(&(messages.len()"),
    # Files and arguments.
    ("F1", "frost.rs", "a FIFO is opened before it is checked (the command waits for a writer)",
     "    if !named.is_file() {", "    if false {"),
    ("F2", "frost.rs", "group or others may read a secret file", "        if mode & 0o077 != 0 {", "        if false {"),
    ("F3", "frost.rs", "a repeated signer accepted", "        if !set.insert(id) {", "        if !set.insert(id) && false {"),
    ("F4", "frost.rs", "fewer signers than the threshold accepted",
     "    if signers.len() < shape.threshold() as usize {", "    if false {"),
    ("F5", "frost.rs", "party 0 accepted as a signer",
     "        if id == 0 || id > shape.parties() {", "        if id > shape.parties() {"),
    ("F6", "frost.rs", "a typed-back digest or fingerprint not compared",
     "if answer.trim() != hex(value) {", "if false {"),
    ("F7", "frost.rs", "keygen may overwrite an existing share or group file",
     "        must_not_exist(path)?;\n        parent_exists(path)?;", "        parent_exists(path)?;"),
    ("F8", "frost.rs", "keygen starts without the share or group file's directory",
     "        must_not_exist(path)?;\n        parent_exists(path)?;", "        must_not_exist(path)?;"),
    # Key generation (keygen.rs).
    ("K1", "keygen.rs", "a secret file overwrites one that appeared while keygen ran",
     "    options.write(true).create_new(true);", "    options.write(true).create(true).truncate(true);"),
    ("K2", "keygen.rs", "a round-2 file that cannot be removed is not reported",
     "            Err(e) => not_removed.push((path, e.to_string())),", "            Err(_) => {}"),
    ("K3", "keygen.rs", "received round-2 files are never removed",
     "        match std::fs::remove_file(&path) {", "        match Ok::<(), std::io::Error>(()) {"),
    ("K4", "keygen.rs", "a round-2 file of another round-1 transcript accepted",
     "    if transcript != *digest {", "    if false {"),
    ("K5", "keygen.rs", "a round-2 file addressed to another party accepted", "    if recipient != to {", "    if false {"),
    ("K6", "keygen.rs", "a round file of another sender accepted", "    if sender != from {", "    if false {"),
    ("K7", "keygen.rs", "a round file of another group shape accepted",
     "    if (t, n) != (shape.threshold(), shape.parties()) {", "    if false {"),
    ("K8", "keygen.rs", "secret files written readable by others", "        options.mode(0o600);", "        options.mode(0o644);"),
    ("K9", "keygen.rs", "round-2 files written before the digest is confirmed",
     '    confirm(console, "round-1 digest", &digest)?;\n', ""),
    ("K10", "keygen.rs", "the share written before the fingerprint is confirmed",
     '    confirm(console, "group fingerprint", &group.fingerprint())?;\n', ""),
    ("K11", "keygen.rs", "a round-2 file readable by others accepted",
     '    permissions: Some("FROST_FILE_PERMISSIONS"),', "    permissions: None,"),
    # Signing (signing.rs, the FROST request).
    ("G1", "signing.rs", "a share of another group signs",
     "    if share.authority_key() != authority {", "    if false {"),
    ("G2", "signing.rs", "a signer outside its own signing set signs",
     "    if !req.signers.contains(&me) {", "    if false {"),
    ("G3", "signing.rs", "an incomplete commitment set signed", "    if !complete {", "    if false {"),
    ("G4", "signing.rs", "a FROST signature for mainnet without --network mainnet",
     "    check_network(req.ipst.terms().terms().network, req.mainnet_explicit)?;\n", ""),
    ("G5", "signing.rs", "a share file readable by others accepted",
     '    permissions: Some("FROST_SHARE_FILE_PERMISSIONS"),', "    permissions: None,"),
    ("G6", "signing.rs", "nonces drawn before the signing set is checked",
     "    check_signers(share.shape(), req.signers)?;\n", ""),
    # The agreed trade (hardening round 1, A1).
    ("N1", "frost.rs", "frost sign does not require the trade the signer named",
     '    check_agreed_as(\n        &a.agreed,\n        &ipst.terms().terms_hash(),\n        "FROST_TERMS_NOT_AGREED",\n    )?;',
     "    let _ = &a.agreed;"),
    ("N2", "frost.rs", "the approval prompt does not name the terms",
     "        hex(terms_hash)\n    ))?;", "        hex(session)\n    ))?;"),
]


def covered_digest():
    """sha256 over every covered file, by path, in list order."""
    h = hashlib.sha256()
    for rel in COVERED:
        with open(os.path.join(ROOT, rel), "rb") as f:
            h.update(rel.encode() + b"\0" + f.read() + b"\0")
    return h.hexdigest()


def script_digest():
    with open(os.path.realpath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check():
    try:
        with open(RECORD) as f:
            record = f.read()
    except OSError:
        sys.exit("missing %s: run scripts/frost-mutation.py --record" % RECORD)
    result = re.search(r"^result: (\d+) of (\d+) mutants caught$", record, re.M)
    problems = []
    if not re.search(r"^source sha256 %s$" % covered_digest(), record, re.M):
        problems.append("the record is for other FROST CLI source or tests")
    if not re.search(r"^script sha256 %s$" % script_digest(), record, re.M):
        problems.append("the record is for another mutant list")
    if not result or result.group(1) != result.group(2) or int(result.group(2)) != len(MUTANTS):
        problems.append("the record does not show every mutant caught")
    if problems:
        sys.exit("frost mutation record: " + "; ".join(problems) + "; rerun with --record")
    print("frost mutation record: %s of %s mutants caught, current" % (result.group(1), result.group(2)))


def copy_tree(dest):
    files = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=True,
    ).stdout.split(b"\0")
    for rel in filter(None, files):
        rel = rel.decode()
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            continue
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(src, "rb") as a, open(out, "wb") as b:
            b.write(a.read())
        os.chmod(out, os.stat(src).st_mode & 0o777)


def run_tests(tree):
    env = dict(os.environ, CARGO_TARGET_DIR=TARGET_DIR)
    env.pop("IMPULSE_MAX_VALUE", None)
    out = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "-p", "impulse-cli", "--lib", "--test", "frost"],
        cwd=tree, env=env, capture_output=True, text=True,
    )
    text = out.stdout + out.stderr
    if "error[" in text or "could not compile" in text:
        return None, text
    failed = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED$", out.stdout, re.M)))
    if out.returncode != 0 and not failed:
        return None, text
    return failed, text


def main():
    if "--check" in sys.argv[1:]:
        return check()
    record = "--record" in sys.argv[1:]
    for mid, name, _, old, _ in MUTANTS:
        with open(os.path.join(ROOT, SRC, name)) as f:
            n = f.read().count(old)
        if n != 1:
            sys.exit("[%s] pattern occurs %d times in %s; it must occur once" % (mid, n, name))
    if len({m[0] for m in MUTANTS}) != len(MUTANTS):
        sys.exit("duplicate mutant ids")

    report = [
        "Mutation run, impulse frost (scripts/frost-mutation.py)",
        "source sha256 %s" % covered_digest(),
        "script sha256 %s" % script_digest(),
        "mutants %d, test targets impulse-cli --lib --test frost" % len(MUTANTS),
        "",
    ]
    with tempfile.TemporaryDirectory() as tree:
        copy_tree(tree)
        failed, text = run_tests(tree)
        if failed is None or failed:
            sys.exit("baseline is not green:\n%s" % text[-4000:])
        report += ["baseline: all tests pass", ""]
        print("\n".join(report), flush=True)
        caught = 0
        for mid, name, what, old, new in MUTANTS:
            path = os.path.join(tree, SRC, name)
            with open(path) as f:
                original = f.read()
            with open(path, "w") as f:
                f.write(original.replace(old, new, 1))
            try:
                failed, text = run_tests(tree)
            finally:
                with open(path, "w") as f:
                    f.write(original)
            if failed is None:
                sys.exit("[%s] mutant does not compile; fix the mutant:\n%s" % (mid, text[-3000:]))
            lines = ["[%s] %s: %s" % (mid, name, what)]
            if failed:
                caught += 1
                lines.append("  caught by (%d): %s" % (len(failed), ", ".join(failed)))
            else:
                lines.append("  SURVIVED")
            report += lines
            print("\n".join(lines), flush=True)
    result = "result: %d of %d mutants caught" % (caught, len(MUTANTS))
    report += ["", result]
    print("\n" + result)
    if record:
        with open(RECORD, "w") as f:
            f.write("\n".join(report) + "\n")
        print("wrote %s" % RECORD)
    if caught != len(MUTANTS):
        sys.exit(1)


if __name__ == "__main__":
    main()
