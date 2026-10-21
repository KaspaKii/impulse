# D5 final evidence: full suite on rusty-kaspa v2.1.0

Date: 2026-10-11. This is the definition-of-done gate (release gate A3) for the suite as it stands now. The earlier evidence (`../d5-rusty-kaspa-v2.1.0/`, 2026-10-07) covered I0 to I4 only.

Question: does the whole Impulse suite at main `ac25dd1e88ed9d4c86e2cfc2c1c9fe243e66a5df` behave the same on rusty-kaspa v2.1.0 (`01b532e8b553523216471682649693af92f0fd16`, what mainnet nodes ran on 2026-10-06) as on the pinned rev `a41a333b08848f41bf737b72592e463a6011b8ac`?

Answer: yes, on every check run. Not one per-test verdict, engine execution (input, limit, script units, exact result), measurement row, mutation verdict, template byte or golden vector differs. Recommendation at the end.

Main has moved since the task was set (now `700c4ea`). The 9 commits after `ac25dd1` change only `docs/` (35 files: the owner runbook, the maintainers' plan, the release checklist, the I12 record and evidence); `git diff ac25dd1 700c4ea -- crates tests contracts scripts demo spec Cargo.toml Cargo.lock` is empty, so the code under test is the same.

## Method
Same as the earlier evidence, extended to the full suite. Everything ran in a scratch directory outside the repository; the rusty-kaspa source checkout it was cloned from was not modified.

1. `git clone` of the local rusty-kaspa checkout, then `git checkout v2.1.0` (HEAD `01b532e8`). `a41a333` is its ancestor, 13 commits back (list below).
2. `git archive ac25dd1` unpacked into the baseline copy and given the run-logging instrumentation (`instrumentation.diff`, below); the v2.1.0 copy is a copy of that instrumented tree.
3. v2.1.0 copy: a `[patch."https://github.com/kaspanet/rusty-kaspa"]` table repoints all 22 rusty-kaspa crates in the lock to the clone, and silverscript v1.0.0 (3ed9733, unpacked with `git archive`) is vendored with a `[patch]` for `silverscript-abi` and `silverscript-lang`, because it does not compile against v2.1.0 unchanged. `cargo update -p` on the 22 crates moved the lock. Lock comparison (`lock-packages-impulse.txt`): 499 packages before and after, 24 changed (the 22 rusty-kaspa crates 2.0.1 to 2.1.0 and the two silverscript crates, git to path), 475 unchanged. No third-party version moved.
4. Adaptations to make it compile and run are listed below; `adaptation-impulse.diff` and `adaptation-silverscript.diff` are the exact diffs against the baseline copy.
5. Baseline copy: `--locked`, the git sources of `Cargo.lock` unchanged, offline.
6. Both copies: `cargo test --workspace --all-features --no-fail-fast`, then `cargo test --workspace --no-fail-fast` (the feature set `scripts/ci-local.sh` uses). `tools/run-suite.sh` and `tools/parse-tests.py` are the scripts as run. Rust 1.94.0, aarch64 macOS.
7. Extras on both copies: `impulse-core` alone with default features and with `--features threshold`; the measurement test with `--nocapture`; the three golden-vector generators (`scripts/vectors.sh` step 3) diffed against `tests/vectors`; `scripts/test-cli-scripts.sh` and `scripts/test-frost-scripts.sh`; `tests/engine/mutation.py --record`; `tests/parity/gen_parity.py --mutate-contract`; `scripts/watch-mutation.py --jobs=2 --record`; `scripts/cli-mutation.py --record`; `scripts/frost-mutation.py --record`.
8. silverc: the baseline uses the installed pinned silverc (provenance in its `.crates2.json`: silverscript-lang 1.0.0 at 3ed973335b59269293564805cc2c58a14595ec03). For v2.1.0 silverc was rebuilt from the patched vendored silverscript (`cargo build --release --locked -p silverscript-lang --bin silverc` after `cargo update -p` on its 22 rusty-kaspa crates). Its lock also moved `libredox` 0.1.17 to 0.1.25 (`lock-packages-silverscript.txt`); `cargo tree -p silverscript-lang -i libredox` on the host target prints "nothing to print", so it is not in the silverc build. `tools/template-check.sh` runs the same compile and checks as `scripts/build-template.sh`.

## Adaptations (v2.1.0 copy only)
| Where | Change | Kind |
| --- | --- | --- |
| `Cargo.toml` | `[patch]` tables for the 22 rusty-kaspa crates and the 2 silverscript crates (absolute scratch paths) | build wiring |
| `crates/impulse-core/src/terms/validate.rs` | `MAX_SCRIPTS_SIZE_POST_TOCCATA` to `MAX_SCRIPTS_SIZE` (1,000,000 on both revisions) | rename |
| `covenants_enabled: true,` removed from `EngineFlags { .. }` in `crates/impulse-core/src/tx/mod.rs`, `crates/impulse-watch/src/entry.rs`, `crates/impulse-watch/src/tests.rs` (2 sites), `crates/impulse-watch/tests/e2e.rs`, `crates/impulse-cli/src/sim.rs`, `crates/impulse-cli/tests/frost.rs`, `tests/engine/harness.rs` | v2.1.0 has no such field (covenants are always on); a41a333 had it set to true everywhere Impulse runs the engine or the script builder | removal |
| `tests/engine/harness.rs` | `MAINNET_PARAMS.prior_block_mass_limits.compute` to `MAINNET_PARAMS.block_mass_limits.compute` (500,000 on both) | rename |
| `crates/impulse-core/src/tx/rules.rs` | `params.mempool_block_mass_cofactors().raw_post()` to `params.block_mass_cofactors()` | API change, not a pure rename (new since the earlier evidence) |
| `tests/engine/builders.rs` | `node_rule_ports_follow_the_pinned_source` asserted that the package source ends in `#a41a333b...`; a path-patched package has no source, so the assertion is replaced by `git rev-parse HEAD` of the clone equals `01b532e8...`. The rest of the test, which compares the load-bearing statements of the node's lock-time rules in the validator source with `crates/impulse-core/src/locktime.rs`, runs unchanged against the v2.1.0 text | test wiring |
| silverscript: `silverscript-abi/src/lib.rs`, `silverscript-lang/src/compiler/{compile.rs, compile/expression.rs, compile/stack_analysis/stack.rs, type_check.rs}` | the same rename-only edits as the earlier evidence (removed `covenants_enabled`, `max_scripts_size(true)` to `MAX_SCRIPTS_SIZE`, `max_script_element_size(true)` to `MAX_SCRIPT_ELEMENT_SIZE`, `max_ops_per_script(true)` to `MAX_OPS_PER_SCRIPT`, `new_max_signature_script_len` to `max_signature_script_len`, `deserialize_i64(.., false)` to `deserialize_i64(..)`); the diff applied to the same commit | rename |

On the `rules.rs` change. In a41a333 the accessor returns the mempool cofactors as a fork-aware value and `raw_post()` takes the value after Toccata activation, which is the cofactors of `{compute, storage} = prior_block_mass_limits` with `transient = new_transient_mass_limit`. Read from `consensus/core/src/config/params.rs` on both revisions: all four parameter sets in each file give `{compute 500,000, storage 500,000, transient 1,000,000}` after activation (a41a333: `prior_block_mass_limits: with_shared_limit(500_000)`, `new_transient_mass_limit: 1_000_000`; v2.1.0: `block_mass_limits: { compute: 500_000, storage: 500_000, transient: 1_000_000 }`). The values are equal, and the fee-mass assertions in `impulse-core` and the builders pass with the same numbers (verdicts below). Nothing else in production code is more than a deletion or a rename.

Instrumentation (`instrumentation.diff`, both copies, no effect on results): each place that calls `TxScriptEngine::execute` appends one line (module path and thread, input index, limit, script units used, exact `Result` in `Debug`) to the file named by the lower-case environment variable `impulse_d5_log`: `tests/engine/harness.rs` (also used by `tests/parity`), `crates/impulse-cli/src/sim.rs`, `crates/impulse-cli/tests/frost.rs`, `crates/impulse-watch/src/tests.rs`. A first attempt used an upper-case variable name and `env!("CARGO_CRATE_NAME")` in the sources; the parity test `catalogue::every_code_in_the_rust_sources_is_in_errors_md` read those literals as undeclared error-code families and failed on the baseline copy. The names were changed and everything re-run; the logs here are from the second attempt.

## Results
Raw data is in this folder; checksums are in `SHA256SUMS`.

### Tests, per target (`cargo test --workspace --all-features`, files `baseline.counts` and `v210.counts`)
Format of each cell: passed / failed / ignored. The two columns are identical in every row.

| Target | a41a333 | v2.1.0 |
| --- | --- | --- |
| impulse-core lib (includes the `threshold` module: 38 tests) | 261 / 0 / 3 | 261 / 0 / 3 |
| tests/engine `escrow_release` | 13 / 0 / 0 | 13 / 0 / 0 |
| tests/engine `settle` | 57 / 0 / 0 | 57 / 0 / 0 |
| tests/engine `refund` | 45 / 0 / 0 | 45 / 0 / 0 |
| tests/engine `locktime` | 13 / 0 / 0 | 13 / 0 / 0 |
| tests/engine `template` | 3 / 0 / 0 | 3 / 0 / 0 |
| tests/engine `measure` | 1 / 0 / 0 | 1 / 0 / 0 |
| tests/engine `instantiate` | 7 / 0 / 0 | 7 / 0 / 0 |
| tests/engine `builders` | 29 / 0 / 1 | 29 / 0 / 1 |
| tests/engine `threshold` | 6 / 0 / 0 | 6 / 0 / 0 |
| tests/engine `verify` | 11 / 0 / 0 | 11 / 0 / 0 |
| tests/parity | 64 / 0 / 0 | 64 / 0 / 0 |
| impulse-cli lib | 179 / 0 / 0 | 179 / 0 / 0 |
| impulse-cli `tests/binary.rs` | 6 / 0 / 0 | 6 / 0 / 0 |
| impulse-cli `tests/frost.rs` | 2 / 0 / 1 | 2 / 0 / 1 |
| impulse-cli bin | 0 / 0 / 0 | 0 / 0 / 0 |
| impulse-watch lib | 155 / 0 / 1 | 155 / 0 / 1 |
| impulse-watch `tests/e2e.rs` | 21 / 0 / 0 | 21 / 0 / 0 |
| impulse-watch bin | 0 / 0 / 0 | 0 / 0 / 0 |
| impulse-wasm lib (native build) | 73 / 0 / 1 | 73 / 0 / 1 |
| doc-tests (core 2; cli, wasm, watch 0) | 2 / 0 / 0 | 2 / 0 / 0 |
| **Total** | **948 / 0 / 7** | **948 / 0 / 7** |

- The 7 ignored tests are generators, not checks (`emit_vectors` x3, `emit_kcc20_fixtures`, `emit_settle_ipst`, `regenerate_the_golden_state_file`, `ops_tests::oracle`); the same 7 on both.
- `cargo test --workspace` (the `scripts/ci-local.sh` feature set, files `baseline-ci.*` and `v210-ci.*`): 949 passed, 0 failed, 7 ignored on both. The one extra test against the all-features run is `binary::a_release_build_has_no_fake_node`, which exists only without `offline-fake-node`. Verdicts identical.
- `cargo test -p impulse-core` alone, default features: 225 passed, 0 failed, 3 ignored on both (lib 223 plus 2 doc-tests). With `--features threshold`: 263 passed, 0 failed, 3 ignored on both (lib 261 plus 2). Files `*-core-default.counts`, `*-core-threshold.counts`. The 38 tests of the `threshold` module are the difference.
- Per-test verdicts (`baseline.verdicts`, `v210.verdicts`, `*-ci.verdicts`; `target<TAB>test<TAB>verdict`): the two files of each pair are identical (`diff` prints nothing).

### Engine executions (`runs_a41a333.log.gz`, `runs_v210.log.gz`)
Method: every call to the script engine in the suites above logs its input index, script-unit limit, units used and exact result. The log is sorted with `LC_ALL=C sort`. 2,710 executions from 236 test labels; 2,414 `Ok(())` and 296 `Err` with 30 distinct error payloads (`VerifyError` 222, `UnsatisfiedLockTime` 37, `ExceededCommittedScriptUnits` 32 with exact used and limit, `EvalFalse` 3, `InvalidPubkey` 1, `InvalidSigHashType` 1; the lock-time texts are kept whole in the log). The sorted logs of both revisions, and of the all-features and ci-feature-set runs, are byte-identical: sha256 of the uncompressed sorted log `3b594b87750e78a4dd040789a2bc7df05e2a3d2564d07768c709b2a64e8dd80f` for all four. Largest units used in one input: 277,178.

### Script units and compute mass (`baseline.measure`, `v210.measure`)
Output of `cargo test -p impulse-engine-tests --test measure -- --nocapture` (method in the header of `tests/engine/measure.rs`): 32 spend rows (redeem script bytes, signature script bytes, script units, covering compute budget, budget mass) and 14 transaction rows (budgets per input, compute mass in grams). The two files are identical (51 lines each), including `Mainnet block compute mass limit: 500000 grams. Grams per compute budget unit: 100.` Examples: settle, authority, KAS cash, input 0: 3,011 byte redeem script, 133,657 units, budget 13; whole transaction 12,415 grams.

### Mutation runs
Each file is the record the script wrote in its own copy. Verdicts are identical on both revisions; the table says where and why a listing is not byte-identical.

| Run | Files | Result on a41a333 | Result on v2.1.0 |
| --- | --- | --- | --- |
| Contract, `tests/engine/mutation.py` (31 requires replaced by `require(true)`, 4 engine targets each) | `mut_a41a333.txt`, `mut_v210.txt` | 31 of 31 caught by the named test | 31 of 31; the two files are byte-identical, and identical to the committed `tests/engine/mutation-run.txt` |
| Contract, parity, `gen_parity.py --mutate-contract` (31 mutants, `tests/parity`) | `mut-parity_a41a333.json`, `mut-parity_v210.json` | 31 mutants, 77 parity-test flips | same; the `flipped` map is identical on both and to the committed `tests/parity/mutation-run.json`. The `inputs` digest of `tests/engine/harness.rs` differs from the committed one (instrumented, and adapted on v2.1.0), so the `PARITY.md` each copy generated differs from the committed one in exactly one line, the sha256 of that json; all 55 rows are identical |
| Watcher, `scripts/watch-mutation.py` (210 mutants) | `mut-watch_*.txt` | 210 of 210 caught | 210 of 210 caught; two mutants list different catching tests, see below |
| CLI, `scripts/cli-mutation.py` (69 mutants) | `mut-cli_*.txt` | 69 of 69 | 69 of 69; identical apart from the source sha256 line, and to the committed record |
| FROST CLI, `scripts/frost-mutation.py` (54 mutants) | `mut-frost_*.txt` | 54 of 54 | 54 of 54; identical apart from the source sha256 line, and to the committed record |

The watcher listing. In the full runs, mutant C10 lists 3 catching tests on a41a333 (`a_link_made_again_to_a_node_that_never_answers_is_a_failed_call_and_is_tried_again` as the extra one) and 2 on v2.1.0, and mutant W48 lists 5 on a41a333 and 4 on v2.1.0 (`tests::review::a_run_waits_the_interval_between_polls` missing). The committed record on main lists 2 for C10 and 5 for W48. All three are caught in every run. The named tests are timing-based (a link that never answers; a wait between polls). The full runs shared the machine with other jobs; the one-minute load average read at eight points during the session ranged from 44 to 685 (the load during the reruns was not recorded). Reruns of `--only=C10,W48` on each revision, twice each (`mut-watch-rerun_a41a333.txt`, `mut-watch-rerun_v210.txt`): C10 lists the same 2 tests and W48 the same 5 tests in all four reruns, which is also the committed record. So no verdict differs, and the catcher sets of the two timing-sensitive listings are not stable between runs on either revision.

### TEMPLATE_HASH (`template_a41a333.txt`, `template_v210.txt`)
`contracts/impulse_vault.sil` compiled with the pinned silverc (sha256 `12efce4a...`) and with silverc rebuilt on v2.1.0 (sha256 `3732fd20...`; the binaries differ, as expected). The compiled artifact is byte-identical to `contracts/compiled/impulse_vault.v1.json` in both cases (sha256 `59cba93eabdf324f88a981749dbe44694ae94d5f069bd90ecdf3a0deae5944ce`), 2,938 bytes (template prefix 1, state 508, suffix 2,429). TEMPLATE_HASH on both: `1877344751ca7b4491ba6d19e20139995c83321b3106e539f1c1be4384a65fcd`, equal to `contracts/TEMPLATE_HASH`.

### Golden vectors (`vectors.sha256`)
The three generators of `scripts/vectors.sh` (`terms`, `template`, `tx`) run on both copies: `diff -r` of the regenerated `terms/`, `vaults/` and `ipst/` against the committed `tests/vectors` is empty on both (35 files). `vectors.sha256` lists them.

### CLI scripts (`scripts_a41a333.txt`, `scripts_v210.txt`)
`scripts/test-cli-scripts.sh` (CLI built with `offline-fake-node`, every submitted input run in the script engine): 85 checks passed, 0 failed, on both. `scripts/test-frost-scripts.sh`: ok on both.

## Differences
None in a verdict or a number. What differs and is not a result:
- the two watcher catcher listings above (timing-sensitive tests, stable across four clean reruns);
- the `source sha256` lines of the mutation records and one `PARITY.md` hash line (inputs changed by the copy's own instrumentation and adaptations);
- the binary of silverc.

Upstream commits between the revisions (`git log a41a333..v2.1.0`): 01b532e8 Bump version to v2.1.0; 2a47b249 Arithmetic safety and more; ecb9b1f5 report output counts in txscript errors; eb0a856d reject coinbase transactions from mempool; f2f87ff6 split headers to 20 MiB chunks during IBD; c338d495 Toccata cleanup P2P follow-ups; 593399eb, 059d61ec, 02dcf442, bbf12cd6, 887fd5f6, 34ff1e4b Toccata Cleanup parts 6, 5, 4, 3, 2, 1; 3563f06b fix(wasm) sighash type mapping. Script-relevant files changed: `crypto/txscript/src/{lib.rs, opcodes/mod.rs, data_stack.rs, runtime_resource_meter.rs, script_builder.rs}`, `consensus/core/src/config/params.rs`. The sighash mapping fix is in the rusty-kaspa wasm types; `crates/impulse-wasm` does not use them (it signs with `SIG_HASH_ALL` through `impulse-core`).

## Not covered
- The wasm32 build and `wasm-pack test`, the npm SDK tests and the demo browser tests (`crates/impulse-wasm/ci.sh`, `demo/ci.sh`) were not re-run on v2.1.0; only the native `impulse-wasm` lib tests (73) were.
- No node was contacted. The wRPC client code compiles on v2.1.0 and its tests pass against fakes; behaviour against a live v2.1.0 node is not shown here.
- Consensus rules beyond the script engine, the mass calculator and the lock-time validator text compared by `node_rule_ports_follow_the_pinned_source`.
- The logs come from instrumented copies; the instrumentation only appends to a file named by an environment variable that is unset in `scripts/ci-local.sh`.

## Recommendation
The row A3 gate (the engine suite re-run green against the revision mainnet nodes run) is met for the code at `ac25dd1` and `700c4ea`: the suite is green on v2.1.0 with results identical to the pinned revision. The pin can stay at `a41a333`. The mainnet steps themselves remain the key holder's.

Moving the pin to v2.1.0 is a separate decision (rule 3 of docs/ENGINEERING-RULES.md needs a reviewed change whose purpose is the pin). It would need: the adaptations in the table above (10 source files besides `Cargo.toml`: one API change in `rules.rs`, the rest renames, removals and test wiring); silverscript, whose v1.0.0 does not build against v2.1.0 unchanged (five files in the vendored copy), so either a silverscript release for v2.1.0 or a vendored patch; and edits to the pin checks in `scripts/ci-local.sh`, `scripts/build-template.sh` and the `Cargo.toml` comments. Nothing in this evidence requires the move.

If `crates/impulse-wasm` or the demo is to be cited for mainnet, re-run `crates/impulse-wasm/ci.sh` and `demo/ci.sh` against v2.1.0 first.
