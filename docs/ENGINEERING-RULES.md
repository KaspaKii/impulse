<!-- Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0. -->
# Engineering rules

These are the hard rules of the Impulse project. Every change, by a maintainer or a contributor, follows them, and a change that breaks one is not merged. Code comments, scripts and documents cite them by number, as "rule N, docs/ENGINEERING-RULES.md". How to propose and test a change is in [CONTRIBUTING.md](../CONTRIBUTING.md). The design is [spec/IMPULSE-SPEC.md](../spec/IMPULSE-SPEC.md) and is authoritative: the design is not changed in code; a spec change is proposed first.

## Hard rules

1. **No component ever holds, reads, logs or transmits a private key.** Signing is local to the key holder. Test keys live only in `tests/` fixtures and are never real. The project's recorded exceptions, decided by the project owner:
   - Tests (decisions of 2026-10-06 and 2026-10-10) may generate random throwaway keys and FROST shares at run time to exercise signature paths. They are never real, never committed, never logged or printed, erased on drop, and may be written only into a temporary directory that is removed when the test ends.
   - The impulse-core `threshold` feature (off by default) and the `impulse frost` CLI (decision D15, 2026-10-10) hold one FROST party's own share. The CLI writes it only to a file the party names on its own machine, mode 0600, and never prints, logs or transmits it. Signing nonces stay in process memory.
   - The demo page's two in-page wallets (decision of 2026-10-11) hold a key that the user's own browser generated with `crypto.getRandomValues`, in memory only, never stored, sent or logged, and wiped on page exit or by the user. Signing stays in the user's browser.
2. **No dependency on any WarpCore crate, path or git.** Borrowed code is copied in, stripped of WarpCore types and relicensed. See [docs/reference/BORROW-MAP.md](reference/BORROW-MAP.md).
3. **Pinned toolchain.** rusty-kaspa rev `a41a333b08848f41bf737b72592e463a6011b8ac` (tag v2.0.1 plus the kaspa-txscript-zk-sdk crate; the exact rev silverscript v1.0.0 pins), silverscript v1.0.0 and Rust 1.94.0 only. A pin moves only in a change whose stated purpose is to move it.
4. **Fail closed.** Every `require` in the contract has a failing test. Every builder refuses malformed input with a stable error code from [spec/ERRORS.md](../spec/ERRORS.md).
5. **Exact amounts.** A leg settles only from a UTXO that holds exactly the leg amount. Fees always come from a separate input.
6. **Mainnet is the target.** TN10 is the supported test network. A mainnet transaction is sent only by the key holder, on the key holder's own machine, never by CI or by a maintainer on someone else's behalf.
7. **No unverifiable claims** in any document, README or comment. Compare design properties only. Publish numbers only when measured, with the method and the raw data. Mark what is measured, what is modelled and what is asserted.
8. **No em dashes** anywhere: code comments, documents, commit messages. Use a comma, a colon or a full stop.

## Coding principles

1. Think before coding: read the spec section and any borrowed source before writing.
2. Simplicity first: the smallest contract and the smallest crate that pass the test.
3. Surgical changes: touch only what the change names. Unrelated clean-ups go in a separate change.
4. Goal-driven: a change is done when its test passes in CI, not when the code looks done.
