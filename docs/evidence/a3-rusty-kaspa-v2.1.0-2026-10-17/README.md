# A3 evidence: engine suite on rusty-kaspa v2.1.0 (kaspad 2.1.0)

Date: 2026-10-17. Release gate A3. Question: do the Impulse
engine tests give the same verdicts on the rusty-kaspa revision mainnet nodes run (v2.1.0) as on
the official pin a41a333? The official pin is NOT moved: no Cargo.toml, Cargo.lock or source
file of the committed tree changes; the patches live in this folder only.

## Result
Every tested path passes on v2.1.0. No test differs in verdict. One test needed a scratch
relaxation of a provenance assertion (see "The one test that needed a scratch change"); it
passes after it and the underlying comparison is unchanged. No consensus difference affecting
mainnet was found in anything tested.

| Suite | Tree | Passed | Failed | Ignored |
| --- | --- | --- | --- | --- |
| `cargo test -p impulse-engine-tests --no-fail-fast` (v1 vault, v2, hashlock/HTLC, threshold, locktime, verify) | release/v0.2 acb690a | 393 (392 + 1 re-run) | 0 | 1 |
| `cargo test -p impulse-core` | release/v0.2 acb690a | 321 | 0 | 5 |
| Engine suite incl. v3 and v4 (no proving at test time) | the v0.3 branch at 523f4ea (scratch copy) | 541 (540 + 1 re-run) | 0 | 7 |

Template rebuild (hashes unchanged), all compiled with a silverc built against v2.1.0 and also
with the official pinned `scripts/build-template*.sh`:

| Template | TEMPLATE_HASH | Artifact vs committed |
| --- | --- | --- |
| v1 vault | 1877344751ca7b4491ba6d19e20139995c83321b3106e539f1c1be4384a65fcd | byte-identical (2938 bytes) |
| v2 vault | 1a1239083ca68bdf7ef38e74409edf10c0cdc54ae0d5a4d881593b871ff54703 | byte-identical (7582 bytes) |
| hashlock | aa9e7e2ddeccc1d94d559767d7eb89c26ff1d19c3a53be99948673c3ed1f59dc | byte-identical (1635 bytes) |
| v3 (v0.3 branch) | e68c826290f681639f5a13088bb96350c5d1a1e89c90ccdadd6dc3902fb60da1 | byte-identical (3922 bytes) |
| v4 (v0.3 branch) | aad094cd22e417872a820fb0951076c55a4c74def86558f085f49e6bbdf25655 | byte-identical (2890 bytes) |

## Method
- rusty-kaspa: tag v2.1.0, commit 01b532e8b553523216471682649693af92f0fd16 (`git -C ~/rusty-kaspa rev-parse v2.1.0^{commit}`), extracted with `git archive` into a scratch directory. a41a333 is its ancestor, 13 commits back. (The local checkout is 2 commits past the tag; those are not used.)
- silverscript v1.0.0 (3ed9733) copied to scratch and adapted to the v2.1.0 API, as in D5, because it does not compile against v2.1.0 unchanged: `adaptation-silverscript.patch`.
- Impulse: a `[patch."https://github.com/kaspanet/rusty-kaspa"]` entry for every kaspa-* crate in the lock (path = the v2.1.0 extract) and a `[patch."https://github.com/kaspanet/silverscript"]` entry for the two silverscript crates. `cargo update -p kaspa-txscript` re-pointed the lock; `Cargo.lock.patch` shows that only kaspa-* and silverscript-* entries changed, no third-party version. Patch: `adaptation-impulse-release-v0.2.patch` (Cargo.toml plus source).
- Source adaptations, all API renames or removals of pre-Toccata switches, no value changed:
  - `EngineFlags.covenants_enabled` removed (always on in v2.1.0): deleted from the flags literals.
  - `MAX_SCRIPTS_SIZE_POST_TOCCATA` to `MAX_SCRIPTS_SIZE`; `post_toccata_p2sh_sig_scanner` to `p2sh_sig_scanner` (same body, minus the "post-Toccata" wording).
  - `Params::prior_block_mass_limits` to `block_mass_limits` (a field now, no fork wrapper); `block_mass_limits().after()` to `block_mass_limits`; `mempool_block_mass_cofactors().raw_post()` to `block_mass_cofactors()`. Mainnet values are 500,000 compute, 500,000 storage, 1,000,000 transient on both revisions.
- the v0.3 branch at 523f4ea was `git archive`d into scratch (nothing in ~/impulse was touched or committed) and given the same adaptations: `adaptation-impulse-release-v0.3-523f4ea.patch`. It also exercises the kaspa-txscript-zk-sdk Groth16 verification on v2.1.0 through the committed real-receipt fixtures (v3_proofs), with no proving at test time.
- Paths in patches and logs are redacted to `~`; scratch paths show as `~/scratch/...`.

## Commands
```
cargo build --workspace --tests                      (release/v0.2 patched tree)
cargo test -p impulse-engine-tests --no-fail-fast    logs/engine.log
cargo test -p impulse-core --no-fail-fast            logs/core.log
cargo test -p impulse-engine-tests --test builders node_rule_ports   logs/builders-rerun.log
CARGO_NET_OFFLINE=true scripts/build-template.sh; ...-v2.sh; ...-hashlock.sh    logs/build-scripts.log
silverc (built against v2.1.0) on the three .sil files, cmp with the committed artifacts   logs/templates.log
(v0.3 scratch) cargo test -p impulse-engine-tests --no-fail-fast -- --test-threads=4     logs/zkengine.log
(v0.3 scratch) silverc on impulse_vault_v3.sil and _v4.sil    logs/templates-zk.log
```
Tests ran in debug builds on a loaded machine; times in the logs are not benchmarks.

## The one test that needed a scratch change
`builders::node_rule_ports_follow_the_pinned_source` (tests/engine/builders.rs, near line 1405) first asserts that `cargo metadata` reports kaspa-consensus-core's git source ending in `#a41a333...`. With a path patch the source is null, so it panicked at `builders.rs:1408:46` (`unwrap` on None). That is the provenance assertion working as designed, not a behaviour difference. The scratch patch drops only that assertion; the rest of the test then reads the `transaction_validator` source of the crate actually built (now v2.1.0) and checks the ported node rules against it, and it passes. So the ported rules also match the v2.1.0 validator source.

## What this proves
- The script engine, sighash, covenant introspection, script-unit metering, mass calculation and Groth16 precompile of rusty-kaspa v2.1.0 give the same verdict (pass or refusal) as the pinned a41a333 for every path the suites exercise: v1 vault, v2 vault, hashlock/HTLC, threshold signatures, locktime and expiry, KCC-20 interplay, the node-rule ports, and for the v0.3 branch the v3 and v4 gate paths with real receipts. Every `require` failing test in those suites still fails for the same reason it did on the pin.
- The compiler (silverc v1.0.0) rebuilt against v2.1.0 emits byte-identical artifacts, so TEMPLATE_HASH values are unchanged.
- impulse-core builders, transaction mass and fee rules (impulse-core unit tests) hold on v2.1.0.

## What this does not prove
- Not a node test: no kaspad was run, no network, no transaction, no key. Mempool policy, relay, block validation outside script execution, and wallet/RPC behaviour are not covered.
- Not a comparison run: the pinned a41a333 baseline was not re-run in this session, and per-execution (input, limit, units) logs were not re-captured as in D5. The comparison rests on the suites' own assertions, which include exact script-unit and mass expectations. The D5 folder holds the earlier line-by-line comparison for I0 to I4.
- Mutation run NOT completed: `tests/engine/mutation.py` was started, showed E1 and E2 caught, and was stopped as too slow (two mutants in roughly 15 minutes on a loaded machine, 31 or more to go) against the "if quick" instruction. Nothing was recorded or changed (`logs/mutation-partial-aborted.log`). The v2, HTLC, v3 and v4 mutation runs and the CLI/watch/wasm suites were not run.
- Not run on v2.1.0: impulse-cli, impulse-watch, impulse-wasm test suites (they compile with the patch, which shows the API adaptation is complete, but their tests were not executed), the live proving tests (`v3_live`, `v4_live`, ignored, need Docker and a prover), and impulse-core on the v0.3 tree.
- The ignored tests (1 in the release engine suite, 7 in the v0.3 one, 5 in impulse-core) stay ignored.
- The patch touches build adaptations only; if a later release moves the pin it still needs its own reviewed change (rule 3, docs/ENGINEERING-RULES.md).
