# Documentation index

Every specification and document in the repository, one line each. The specifications in `spec/` are authoritative: where a guide and a spec differ, the spec is right. v0.2 and v0.3 features are on release branches, not on `main`; their specifications are `spec/V2.md` and `spec/V3-ZK.md` on those branches.

Check that every relative link here resolves with `scripts/check-doc-links.sh`.

## Start here

| Document | What it is |
| --- | --- |
| [README.md](../README.md) | What Impulse is, status, build and quick start |
| [USER-GUIDE.md](USER-GUIDE.md) | Task-oriented instructions for the `impulse` command line |
| [GLOSSARY.md](GLOSSARY.md) | Terms as Impulse v0.1 uses them, each pointing to its defining document |
| [ARCHITECTURE.md](ARCHITECTURE.md) | A map of how the parts of v0.1 fit together |
| [OPERATIONS.md](OPERATIONS.md) | Operating `impulse-watch` and the `impulse` CLI |

## Specifications (spec/)

| Document | What it is |
| --- | --- |
| [IMPULSE-SPEC.md](../spec/IMPULSE-SPEC.md) | Product specification v0.1: the design, the contract, the settlement modes |
| [ENCODING.md](../spec/ENCODING.md) | Terms encoding version 1: fields, canonical bytes, terms hash, validation, `TERMS_*` codes |
| [TEMPLATE.md](../spec/TEMPLATE.md) | ImpulseVault v1 template: instantiation, decoding, addresses, `TEMPLATE_*` codes |
| [TRANSACTIONS.md](../spec/TRANSACTIONS.md) | The transactions the builders make: layouts, budgets, fees, `TX_*` codes |
| [IPST.md](../spec/IPST.md) | The Impulse partially signed transaction interchange format, version 1 |
| [VERIFY.md](../spec/VERIFY.md) | The verifier and decoder: checks before funding and after a spend |
| [CLI.md](../spec/CLI.md) | The `impulse` command line: commands, signing module, value cap, receipts |
| [WATCH.md](../spec/WATCH.md) | The reference watcher `impulse-watch`: events, state file, flags |
| [THRESHOLD.md](../spec/THRESHOLD.md) | FROST threshold settlement authority and the `impulse frost` commands |
| [ERRORS.md](../spec/ERRORS.md) | The single list of stable error codes and on-chain refusals |

## Reference (docs/reference/)

| Document | What it is |
| --- | --- |
| [CLI.md](reference/CLI.md) | Every command and flag, generated from the real `--help` output |
| [SDK.md](reference/SDK.md) | The TypeScript SDK surface, with examples |
| [ERRORS.md](reference/ERRORS.md) | Error codes by family with the user-facing remedy for each |
| [BORROW-MAP.md](reference/BORROW-MAP.md) | Code copied from WarpCore or the Kaspa toolchain into Impulse, and from where |
| [SDK package README](../crates/impulse-wasm/npm/README.md) | The npm package's own README: loading, the mapping from impulse-core, refusals |
| [Demo README](../demo/README.md) | The browser demo: pages, build, tests |

## Parity, security and review material

| Document | What it is |
| --- | --- |
| [PARITY.md](../PARITY.md) | Generated comparison with the Solana Foundation DvP program, row by row against tests |
| [SECURITY.md](../SECURITY.md) | Security policy and how to report a vulnerability |
| [security/THREAT-MODEL.md](security/THREAT-MODEL.md) | What is protected, who acts against it, which control answers each attack |
| [security/INVARIANTS.md](security/INVARIANTS.md) | Each property mapped to its enforcement, its test and its mutation record |
| [security/KNOWN-LIMITATIONS.md](security/KNOWN-LIMITATIONS.md) | Limits of the v0.1 design and its dependencies |

## Release and project

| Document | What it is |
| --- | --- |
| [CHANGELOG.md](../CHANGELOG.md) | Changes by version |
| [release/SOLANA-PROGRAM.md](release/SOLANA-PROGRAM.md) | Record of the impulse-htlc mainnet deploy (program ID, build hash, SOL needed) |
| [release/PUBLIC-TREE.md](release/PUBLIC-TREE.md) | What the public tree excludes and why, how to export it, the owner's publishing steps and GitHub settings |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Code of conduct |
| [ENGINEERING-RULES.md](ENGINEERING-RULES.md) | The project's engineering rules 1 to 8, cited by number across the code and documents |

## Increment numbers

Code, specs and documents name parts of the work by increment number (I0 to I23). The table says what each number covers; the design of each is in the specification that names it.

| Increment | Subject |
| --- | --- |
| I00 | Repository scaffold, CI, pins |
| I01 | Feasibility spike (gate) |
| I02 | Terms schema, canonical encoding, terms hash |
| I03 | ImpulseVault contract |
| I04 | Template instantiation, addresses, decode |
| I05 | Transaction builders |
| I06 | Verifier |
| I07 | CLI with local signing and IPST |
| I08 | Watcher |
| I09 | WASM bindings and npm SDK |
| I10 | Solana parity suite |
| I11 | Browser demo |
| I12 | Release v0.1.0 |
| I13 | Threshold settlement authority (FROST) |
| I14 | External review |
| I16 | Basket and multi-party settlement (v0.2) |
| I17 | Partial settlement (v0.2) |
| I18 | Cross-chain cash via hashlock (v0.2) |
| I19 | Impulse-compatible escrow on Solana (v0.2) |
| I20 | Proof-carrying settlement, ZK-gated settle (v0.3) |
| I21 | Hashed-terms vault (v0.3) |
| I22 | Repo and securities lending |
| I23 | Post-quantum refund paths (research) |

## Evidence (docs/evidence/)

Raw data and method for every measured claim. Each directory has a README with the method and a SHA256SUMS file.

| Directory | What it holds |
| --- | --- |
| [d5-final-suite-v2.1.0](evidence/d5-final-suite-v2.1.0/README.md) | Full suite and mutation runs on rusty-kaspa v2.1.0 beside the pinned rev |
| [d5-rusty-kaspa-v2.1.0](evidence/d5-rusty-kaspa-v2.1.0/README.md) | Engine suite on rusty-kaspa v2.1.0 |
| [fuzz-2026-10-12](evidence/fuzz-2026-10-12/README.md) | Fuzz run of I14 |

Also in `docs/`: [measurements/](measurements/v3-zk-units.txt).

## Scripts

| Script | What it does |
| --- | --- |
| `scripts/ci-local.sh` | The full local gate, every step blocking |
| `scripts/gen-cli-reference.sh` | Regenerates [reference/CLI.md](reference/CLI.md); `--check` fails if it is stale |
| `scripts/check-doc-links.sh` | Offline check of relative links and anchors in every Markdown file |
| `scripts/build-template.sh` | Compiles the contract with the pinned silverc and checks `TEMPLATE_HASH` |
| `scripts/vectors.sh` | Regenerates and diffs the golden vectors |
| `scripts/gen-parity.sh` | Regenerates and checks PARITY.md |
| `scripts/release.sh` | Reproducible release build |
