# D5 evidence: engine suite on rusty-kaspa v2.1.0

Date: 2026-10-07. Question: does Impulse behave the same on rusty-kaspa v2.1.0 (01b532e, what mainnet nodes ran on 2026-10-06) as on the pinned rev a41a333?

## Method
- rusty-kaspa cloned at v2.1.0 (HEAD 01b532e; a41a333 is its ancestor, 13 commits back).
- Impulse main de54ac2 copied twice: baseline (pin a41a333) and v2.1.0 (a `[patch]` repointing all 12 rusty-kaspa crates in the lock to the v2.1.0 clone; no third-party version changed). silverscript v1.0.0 (3ed9733) was vendored and patched the same way because it does not compile against v2.1.0 unchanged.
- Build adaptations, renames and removals only, no value changes: `adaptation-impulse.diff`, `adaptation-silverscript.diff`, `ss_patch.toml`.
- Ran `cargo test --workspace` on both; logged every engine execution (input, limit, units, exact result); re-ran the mutation run; rebuilt silverc and the template on both.

## Results (raw data in this folder, checksums in SHA256SUMS)
| Check | a41a333 | v2.1.0 | Files |
| --- | --- | --- | --- |
| Tests | 230 passed, 2 ignored | 230 passed, 2 ignored, same per-test verdicts | baseline.verdicts, v210.verdicts (identical) |
| Engine executions | 816 runs in 135 tests | identical input, limit, units and result, including 148 error payloads | runs_a41a333.log, runs_v210.log (identical) |
| Units and compute mass | 32 spend rows, 14 transaction rows | byte-identical | baseline.measure, v210.measure (identical) |
| Mutation run | 31 of 31 requires caught | identical | mut_a41a333.txt, mut_v210.txt (identical) |
| TEMPLATE_HASH | 1877344751ca7b4491ba6d19e20139995c83321b3106e539f1c1be4384a65fcd | same; artifact byte-identical | |
| Script-unit meter source | | textually identical | meter_old.txt, meter_new.txt |

## Diffs between the revisions that touch scripts
None changes a verdict for a P2SH covenant script: the Toccata cleanup deletes pre-activation paths and keeps the post-activation code. Remaining differences: `InvalidOutputIndex` error text reports the output count; a wasm-only AnyOneCanPay sighash mapping fix (relevant to I9 only if the SDK uses rusty-kaspa wasm sighash types); the 100,000-gram standard mass cap is removed (already inactive after activation on a41a333).

## Scope and limit
This covers the suite at de54ac2 (I0 to I4). The release gate A3 still applies: re-run before any mainnet step with the suite as it stands then (I5 builders and later).
