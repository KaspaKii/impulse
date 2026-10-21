# Contributing to Impulse

Impulse is open-source infrastructure that holds value on a public chain, so changes are held to a high bar. This page says what that means in practice. Read the rules below and [docs/ENGINEERING-RULES.md](docs/ENGINEERING-RULES.md), the project's engineering rules. The design is `spec/IMPULSE-SPEC.md` and is authoritative.

## Before you start

- **Contributor licence agreement.** Contributions require a signed contributor licence agreement. The text is published at I12, the release step that publishes it. Until it is published, changes from outside the project cannot be merged. The project is licensed under Apache-2.0 (`LICENSE`).
- **Security findings do not go in public issues.** Follow `SECURITY.md`.
- **Design changes come first as a proposal.** The contract and the specification are not changed by a pull request alone. Open an issue that describes the change, the property it adds or removes and the test that would pin it. Changing the contract changes the template hash, which changes every vault address.
- **Features for later releases live on release branches.** `main` is v0.1. Baskets, partial settlement, cross-chain hashlock, ZK settle, linked trades and the hashed-terms vault are v0.2 and v0.3 work (`spec/V2.md` and `spec/V3-ZK.md` on those branches). Do not add them to `main`.

## Rules every change follows

The hard rules of the project are [docs/ENGINEERING-RULES.md](docs/ENGINEERING-RULES.md), rules 1 to 8. Code comments, scripts and documents cite them by number ("rule 1, docs/ENGINEERING-RULES.md"). They decide whether a change is accepted:

1. **No private key, seed phrase or mnemonic, anywhere.** Not in code, tests, examples, issues or logs. No component may hold, read, log or transmit a key, with the recorded exceptions of rule 1 (throwaway test keys generated at run time, one FROST party's own share, the demo page's in-browser wallet). Test keys are never real.
2. **No dependency on any WarpCore crate, path or git.** Borrowed code is copied in, stripped of WarpCore types and relicensed (`docs/reference/BORROW-MAP.md`).
3. **Pinned toolchain.** rusty-kaspa rev `a41a333b08848f41bf737b72592e463a6011b8ac`, silverscript v1.0.0 and Rust 1.94.0. A pin moves only in a change whose stated purpose is to move it.
4. **Fail closed.** Every `require` in the contract has a failing test. Every builder refuses malformed input with a stable error code from `spec/ERRORS.md`. Codes are append-only.
5. **Exact amounts.** A leg settles only from a UTXO that holds exactly the leg amount. Fees come from a separate input.
6. **Mainnet is the target; TN10 is the supported test network.** Only a key holder sends a mainnet transaction, from their own machine.
7. **No unverifiable claims.** Compare design properties only. Publish a number only when it is measured, with the method and the raw data. Mark what is measured, what is modelled and what is asserted. Do not describe the software with review-status wording.
8. **No em dashes** in code comments, documents or commit messages. Use a comma, a colon or a full stop.

Changes are also surgical: touch only what the change names, and put unrelated clean-ups in a separate change.

## Build and test

Install `rustup`; the pinned toolchain installs itself from `rust-toolchain.toml`. You also need `python3`, `cargo-audit`, `cargo-deny` and `gitleaks`, and, for the SDK and demo, Node.js and `wasm-pack`.

```
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

The full gate is one command and is what CI runs. It must pass before a change is proposed:

```
scripts/ci-local.sh
```

Other commands you may need:

```
scripts/build-template.sh        compile contracts/impulse_vault.sil with the pinned silverc; check TEMPLATE_HASH
scripts/vectors.sh               regenerate and diff the golden vectors (the diff must be empty)
python3 tests/engine/mutation.py contract mutation run (see docs/security/INVARIANTS.md)
```

## What a change must include

- **A test that fails without it.** Tests are the deliverable. A refusal gets a failing case beside an accepted control, and the test asserts the stable code. A change to the contract needs a failing engine test for the changed `require` and a fresh mutation record (`python3 tests/engine/mutation.py --record`); CI fails on a stale record.
- **Updated records where they apply.** Changing `crates/impulse-cli/src` needs `python3 scripts/cli-mutation.py --record`; `frost.rs` also needs `python3 scripts/frost-mutation.py --record`; `crates/impulse-watch/src` needs `python3 scripts/watch-mutation.py --record`. Changing a code or a contract tag needs `spec/ERRORS.md` updated; the parity tests fail until it is.
- **Spec and docs in step.** If behaviour changes, the spec section and any affected document change in the same series.
- **A CHANGELOG entry** under the unreleased section of `CHANGELOG.md` for any user-visible change.

## Commits and review

- One logical change per commit. The message starts with the increment or area and says what changed, for example `I14: watcher refuses a walk above the node's virtual DAA score` or `docs: operations guide`.
- Never commit to `main` directly. Work on a branch and open a merge request.
- A reviewer checks the change against the rules above and against the spec, and looks for the failing test. Expect a finding to be rated CRITICAL, HIGH, MEDIUM or LOW; CRITICAL and HIGH findings are fixed before merge.
- Do not run mainnet transactions from a change, a test or a CI job.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.

## Licence

By contributing you agree that your contribution is licensed under Apache-2.0, subject to the contributor licence agreement above.
