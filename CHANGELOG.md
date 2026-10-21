# Changelog

All notable changes to Impulse are recorded here. The format follows Keep a Changelog, and versions follow Semantic Versioning. The crates, the CLI, the watcher and the npm SDK carry the same version.

## 0.4.0 - supersedes v0.3.0

The workspace, the CLI, the watcher and the npm packages carry this version; the owner cuts the tag. It supersedes v0.3.0, published on 18 October 2026 at https://github.com/KaspaKii/impulse. The sections below the 0.4.0 entry record the feature lines (v0.1, v0.2, v0.3) that make it up. Design: `spec/TEMPLATE.md`, "Inputs outside the layout" and "The other leg's vault"; `spec/V2.md` 4.5a and 10.4; `spec/V3-ZK.md` 6.5, 6.6 and 22.15.

### History note

v0.3.0 shipped the earlier vault templates (v1 template hash `1877344751ca7b4491ba6d19e20139995c83321b3106e539f1c1be4384a65fcd`, v4 `aad094cd22e417872a820fb0951076c55a4c74def86558f085f49e6bbdf25655`, and the v2, v3 and hashlock templates of that tree). They carry known limitation L20 in full: a token of another covenant owned by a vault's script hash can be moved by whoever spends that vault. v0.3.0 disclosed L20 for v1, v2, v3 and hashlock; its disclosure did not name template v4, which is affected too (inputs past the proof's view). Do not fund a vault of a v0.3.0 template; use v0.4.0. v0.4.0 replaces the templates in place and carries no code to recognise the v0.3.0 ones. The fixed templates keep the plain names v1, v2, v3, hashlock and v4.

### Fixed

- Known limitation L20 (`docs/security/KNOWN-LIMITATIONS.md`): a KCC-20 token of another covenant owned by a vault's script hash moved with any settle or refund of that vault. Every template now refuses it. Templates v1, v2, v3 and hashlock: a settle or refund allows only inputs with no covenant or with the trade's own covenants ([F1], [F3]; [HF1], [HF3]), and a v1 or v3 settle refuses a second input of the other leg's covenant ([F2]). Template v4: the script pins the covenant ID of every input.
- A vault spend has at most 12 inputs, N + 18 for a template v2 settle ([F4], [F5]; [HF2], [HF4]); the builders refuse more with `TX_TOO_MANY_INPUTS`. A template v4 spend has at most 8 inputs, refused by the builders as `ZK_H_SHAPE`.
- Known limitation L20, last case (I26, owner decision of 2026-10-19): a token of a leg's own covenant sent to the other leg's vault address could stand in for that leg's escrow in a settle that omitted the other vault (templates v1, v3 and v4). Every settle now requires the other leg's vault of the same trade: templates v1 and v3 rebuild it from their own redeem script with the leg index replaced and require it at its canonical input ([S10], as template v2 already did); template v4's terms guest requires, at the other leg's slot, the other leg's template v4 vault of the same terms (`[H5]`, `spec/V3-ZK.md` 22.16; a new guest and `IMAGE_ID_V4`). L20 is closed in every template with no remaining case: a misdirected token cannot move, and is lost. The tests that pinned the old behaviour now pin its refusal (`tests/engine/foreign_covenant_residual.rs`, `v3p_sibling`, `v3_settle::v3_s10_*`, and the template v4 engine tests).
- Known limitation L8, cross-trade mixing, is closed in every template by the same check (templates v1 and v3 `[S10]`, template v4 `[H5]`; template v2 already had its own `[S10]`): the vaults of two trades no longer settle together. A template v3 cash vault no longer settles beside any asset vault but the gated v3 asset vault of its terms, so the fixed gate line now says so (`spec/V3-ZK.md` 6.5).
- `TOKEN_FOREIGN_AT_VAULT` (builders) and `WATCH_FOREIGN_TOKEN` (watcher) are retired: the case they warned about no longer exists. Their names stay reserved in their frozen lists and are never raised (`spec/ERRORS.md`, "Retired and changed codes").
- The builders' compute budget rule for a vault input allows 45,000 fixed script units (was 20,000), for `[S10]`; every committed vector keeps its budget floor.

### Template hashes

- `TEMPLATE_HASH` (v1) ec92ce9d06ff2f57a4f547b724b6fdfe9d9fa62814e687d8670ae96d331e6f02; `TEMPLATE_HASH_V2` 75d754c16299e7707787f0e66d9880d7657d09b1bea4ef3bd508cefdb6dd7548; `TEMPLATE_HASH_V3` f00009e88c562fc529d1c30e406c783eb7532e39f6426be518616eb9a7283d4c; `TEMPLATE_HASH_HASHLOCK` 1e708d70c86ace8015778ccb693573b109dcd7135cf921366525a6f4aeef43d6; `TEMPLATE_HASH_V4` 9656711aae5fad7375afa9076241765356f6f7b9a9d5816ad0f4dc48cc4cddc5; `IMAGE_ID_V4` ffaa95f97b44a9209e245579361b81baaa45bd414f11446f11d8d7a1903916a3. L20 and L8 are closed in the templates of these hashes; `scripts/build-template*.sh` and `scripts/build-guest.sh` reproduce them. The committed template v3 Groth16 receipts are regenerated, because a proof binds the vault scriptPubKey.

### Measured

- Pinned engine (rusty-kaspa a41a333, silverscript v1.0.0), raw data in `docs/evidence/template-fix-2026-10-19/v0.4-template-units.txt`: redeem scripts grow from 2,938 to 3,854 bytes (v1), 7,582 to 8,994 (v2, two legs), 3,922 to 4,839 (v3) and 1,635 to 2,371 (hashlock). With one fee input a v1 settle costs 2,535 to 3,068 more script units per vault input and a refund 2,096 to 2,295 more; each further input costs about 235 units in a settle and 168 in a refund. At the bound of 12 inputs every v1 vault input stays within the builders' existing rule (at most 157,111 units against 173,057). Template v2 costs about 107 units per input after the vaults in a settle and 168 in a refund; template v2 budgets are refitted (`spec/V2.md` 6.4 and 9.2, `docs/measurements/v2-max-n.txt`). Template v3: `docs/measurements/v3-zk-units.txt`.
- Templates v1 and v3, `[S10]` (I26), raw data in `docs/evidence/template-fix-I26/s10-units.txt`: redeem scripts grow by 92 bytes (v1 3,854 to 3,946; v3 4,839 to 4,931). A v1 settle costs 20,610 to 21,126 more script units per vault input with one fee input; at the bound of 12 inputs the most is 177,722 units against the builders' rule of 198,057; a refund costs 184 more. The largest v1 settle at exact budgets has a compute mass of 17,623 grams. Template v3, re-measured with the re-proved receipts (`docs/measurements/v3-zk-units.txt`): each settle vault input costs about 26,100 more script units (the longer v3 script is rebuilt and hashed); the asset vault's covering budget is 1,556 (was 1,554) and every settle stays within the post-Toccata caps, at a compute mass of at most 172,924 grams.
- Template v4: the cost of checking the covenant ID of every input (script size +708 bytes, script units per vault input), raw data in `docs/evidence/template-fix-2026-10-19/v4-1-covenant-check.txt`.
- Each new require has a failing engine test, and the contract mutation records catch every tagged require with its named test (`tests/engine/mutation-run*.txt`, `tests/engine/V3-SHIPPED-COVERAGE.md`).

### Asserted, not measured

- That no other path moves a token of another covenant from a vault. The engine tests cover the spends the builders make and the faults named in the spec, not every transaction.
- A token of another covenant sent to a vault address can no longer move at all: the mistake no longer gives it away, but it is lost. This follows from the design; there is no recovery path.

### Feature lines in this release

The three sections below record what each feature line added.

### v0.3 line

Builds on the v0.2 line. Designs: `spec/V3-ZK.md` (templates v3 and v4) and `spec/V2.md` section 17 (linked trades).

#### Added

- I20, list-gated settle (`impulse zk`, `impulse-core` feature `zk`, off by default): template v3 settles only with a Groth16 proof, verified by the pinned engine's precompile, that the buyer's delivery owner is in an issuer list. Terms v3, list and manifest tooling, builders, IPST version 4, receipts, 26 `ZK_` codes, golden vectors in `tests/vectors/zk/`, `terms_v3/`, `vaults_v3/`. The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified. It checks list membership only: not identity, eligibility or sanctions status.
- I21, hashed-terms vault (template v4, feature `zk-hashed`, IPST version 5, `impulse zk` v4 commands, 19 `ZK_H_` codes): the vault holds a commitment to the terms and a proof that the settling transaction satisfies them. `IMAGE_ID_V4` is reproduced by `scripts/build-guest.sh`. Cap override is never accepted for v4.
- I22, linked trades (`impulse linked`, `impulse-watch --linked`): an opening and a return as two ordinary template v2 trades described by one sheet, with a gate that keeps the return from being built before the opening settled, linked receipts and 14 `LINKED_` codes. The gate is enforced by the builders, the CLI and the watcher, not by the contract.
- Demo: the visual demo (`demo/visual`) has a dark institutional redesign; the trade app and decoder were polished.

#### Measured

- Real Groth16 receipts for a settle and a refund of every cash kind are accepted by the pinned engine (`tests/engine/v4-live-run.txt`; fixtures in `tests/engine/fixtures/v4/`). Run on one machine, CPU proving.
- Proving a list of 1,000 entries, 3 runs: 187.7 / 222.3 / 223.9 s (min / median / max), 128-byte proof, Groth16 container peak about 7.8 to 8.1 GiB (`docs/evidence/i20-proving-2026-10-12/`). The machine was under heavy load, so times are upper-biased.
- Mutation records on the merged tree: CLI 313 of 313 mutants caught (`crates/impulse-cli/mutation-run.txt`), watcher 235 of 235 (`crates/impulse-watch/mutation-run.txt`), demo record at `demo/mutation-run.txt`.

#### Asserted, not measured

- That the proof statement of template v4 is sound, and that the RISC Zero Groth16 setup holds. Both rest on third-party components that Impulse has not verified.
- That no key is exposed by any new command. This is enforced by design rules and tests, not proven.

### v0.2 line

Builds on the v0.1 line. Design: `spec/V2.md`.

#### Added

- I16, basket settlement: template v2 settles two to ten legs in one transaction (`impulse v2`, terms v2, `TEMPLATE_HASH_V2`). The engine tests cover rings of three tokens, nine tokens plus KAS, and ten tokens. All 58 tagged requires are caught by their named test (`tests/engine/mutation-run-v2.txt`).
- I17, partial settlement: the vault continues as its covenant with the remainder (tranches), version 2 receipts for each tranche (`impulse v2 status`, `v2 receipt verify`).
- I18, cross-chain cash by hashlock (`impulse xchain`, template `ImpulseHashlock`, `TEMPLATE_HASH_HASHLOCK`): a Kaspa token leg against a counterpart chain leg, including Solana USDC, with a Solana HTLC program under `solana/`. It is a conditional exchange across two chains, not atomic settlement.
- I19, an Impulse-compatible escrow on Solana whose address binds the Impulse terms hash (`solana/`). Positioning against the Solana Foundation DvP program is the owner's sign-off (D27).
- Live demo (`demo/live`, `demo/visual`): the cross-chain flow on Kaspa TN10 and Solana devnet, with a replay mode for a recorded run.

#### Changed

- The hashlock mainnet gate is lifted by the owner's decisions D39 (b) and D40. On mainnet the tools refuse a trade above 10 KAS unless --i-accept-the-risk is passed, and every `xchain` command prints the R2 notice. `HTLC_MAINNET_GATED` and `XCHAIN_MAINNET_GATED` are reserved and never returned.

#### Measured

- Race R2 is disclosed, not solved: a buyer who controls or colludes with a block producer or relay of the counterpart chain can delay the seller's claim past the counterpart timeout and take both legs. Claiming early narrows the window only.
- Hashlock script size and script units are measured in the pinned engine (`tests/engine/htlc_measure.rs`; `docs/measurements/v2-max-n.txt` for template v2). Redeem script of template v2: 7,582 bytes at two legs, 9,078 at ten.
- Solana program tests at the I19 step: 136 LiteSVM tests passed (128 upstream, 8 added), run on 2026-10-11. The CLI mutation record at the v0.2 step was 284 of 284.

#### Asserted, not measured

- That the counterpart program used on any chain behaves as its owner states. Impulse names none for mainnet; the key holder uses one they reviewed.
- Compliance with issuer terms, freezing and sanctions controls of any asset (USDC included) stays the user's responsibility.

### v0.1 line

First feature line. The owner cuts and signs the tag when the release gates are complete. The design is `spec/IMPULSE-SPEC.md`.

#### Added

- `ImpulseVault`, one SilverScript contract template (`contracts/impulse_vault.sil`) with two entries, `settle` and `refund`, compiled with silverscript v1.0.0. The template hash is pinned in `contracts/TEMPLATE_HASH` and specified in `spec/TEMPLATE.md`.
- Four settlement modes: Direct (no escrow), Vault with authority, Vault self-settling and Vault with external cash. Legs are native KAS or KCC-20 tokens. Funding is revocable or earmarked.
- `impulse-core`: terms schema, canonical encoding and terms hash (`spec/ENCODING.md`), template instantiation, vault addresses and decoding, transaction builders (`spec/TRANSACTIONS.md`) and the verifier (`spec/VERIFY.md`). Its default build holds no key material.
- `impulse` CLI (`spec/CLI.md`): terms, addresses and funding URIs with QR codes, unsigned fund, settle, refund and Direct cancellation builders, local signing from a key file the user names, the IPST exchange format (`spec/IPST.md`), submission, decoding, settlement receipts, and a per-trade value cap. Mainnet is used only when `--network mainnet` is passed.
- FROST threshold settlement authority (`spec/THRESHOLD.md`): `impulse frost` key generation, signing and aggregation for a t-of-n authority with a BIP-340 output. Each party's share stays in a file on that party's machine.
- `impulse-watch` (`spec/WATCH.md`): follows trades on a Kaspa node over wRPC and reports per-leg JSON events. It holds no key and keeps its state in memory or in a local file.
- npm SDK `@warpcore/impulse`: `impulse-core` compiled to WebAssembly, with TypeScript types.
- Static browser demo (`demo/`) with in-page wallets whose keys are generated in, and never leave, the user's browser.
- Parity suite against the Solana Foundation DvP program, generated into `PARITY.md`.
- Error catalogue with stable codes (`spec/ERRORS.md`) and golden vectors (`tests/vectors/`).
- Release engineering: `scripts/release.sh` (reproducible build of the CLI and watcher, SHA256SUMS, CycloneDX SBOMs), `deny.toml` (licences, bans, sources and advisories, checked by `cargo deny` in `scripts/ci-local.sh`), and this changelog.

#### Documentation

- `docs/security/`: threat model (`THREAT-MODEL.md`), invariants mapped to the contract tags, their engine tests and the mutation records (`INVARIANTS.md`), and accepted limitations with the decision behind each (`KNOWN-LIMITATIONS.md`).
- `CONTRIBUTING.md` rewritten, `CODE_OF_CONDUCT.md` added (Contributor Covenant 2.1 by reference), `SECURITY.md` names the maintainers as the security contact via kaspa-kii.org and links the security documents.

### Security

- Known limits of v0.1.0 are listed in `docs/security/KNOWN-LIMITATIONS.md`, including two upstream defects in the pinned rusty-kaspa readers (a hostile node can stop the CLI or the watcher; no key is involved).

#### Measured and asserted

- Measured: every `require` of the contract has a failing test, with a mutation record per template (`docs/security/INVARIANTS.md`); the parity suite is generated into `PARITY.md`; golden vectors are regenerated with an empty diff by `scripts/vectors.sh`.
- Asserted: that the pinned silverscript compiler and rusty-kaspa engine behave as their authors state; correctness of third-party dependencies is not reviewed here.

### Pinned toolchain

- Rust 1.94.0
- rusty-kaspa rev a41a333b08848f41bf737b72592e463a6011b8ac (tag v2.0.1 plus the kaspa-txscript-zk-sdk crate)
- silverscript v1.0.0
