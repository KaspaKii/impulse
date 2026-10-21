# Impulse threat model (v0.1)

Scope: Impulse v0.1.0 as on `main`. Design authority is `spec/IMPULSE-SPEC.md`. This file describes what the system protects, who can act against it, what it assumes, and which control answers each attack, with a pointer to the code and the test that pins it. Property-by-property detail is in `INVARIANTS.md`; accepted residual risk is in `KNOWN-LIMITATIONS.md`.

Evidence labels used throughout: **measured** (a test or recorded run in this repository shows it), **modelled** (argued from the design and the pinned engine, with no run that exercises it), **asserted** (stated by the design, not checked here). Nothing here is asserted without saying so.

## 1. What Impulse is

Impulse is atomic delivery-versus-payment (DvP) on Kaspa. Two parties agree terms. Each leg of the trade is escrowed at a P2SH address derived from those terms (`ImpulseVault`, one template, `contracts/impulse_vault.sil`), or, in Direct mode, no escrow is used. A settle transaction pays both legs in one transaction. A refund transaction sends a leg home whole. There is no Impulse server, no database of trades and no custody: tools build transactions, and the key holder signs locally.

Modes: Direct; Vault with authority; Vault self-settling; Vault with external cash. Funding: revocable or earmarked. Legs: KAS or KCC-20. The v1 asset leg is KCC-20 only (owner decision D13).

## 2. Assets

| # | Asset | Where it lives | Why it matters |
| --- | --- | --- | --- |
| A1 | Value escrowed in a vault UTXO (KAS, or a KCC-20 token plus its carrier KAS) | On chain, at the vault P2SH address | Direct financial loss if misdirected, locked or stolen |
| A2 | Private keys of seller, buyer and authority | The key holder's machine (CLI key file, FROST share file, or the demo page's in-memory key) | Loss of a key is loss of that role's authority. Impulse never holds a key (rule 1, docs/ENGINEERING-RULES.md) |
| A3 | Agreed terms and their hash | Terms file, IPST file, the vault address itself | The address commits to every term; a wrong term is a wrong trade |
| A4 | The compiled template and its hash | `contracts/compiled/`, `contracts/TEMPLATE_HASH` | Every vault address is derived from it; a substituted template redirects funds |
| A5 | Liveness of settlement and refund | The vault script, the authority, the node | A leg that cannot move is lost value for the lock period |
| A6 | The integrity of the release artifacts | Release archives, `SHA256SUMS`, SBOMs, npm package | A tampered binary could build a wrong transaction |
| A7 | Accuracy of public statements about Impulse | Public claims in the docs | Unverifiable claims are a legal and reputational risk (rule 7, docs/ENGINEERING-RULES.md) |

## 3. Actors

| Actor | Capability assumed |
| --- | --- |
| Seller, buyer | Hold their own keys. May be honest, or may defect after seeing the other's move |
| Settlement authority | Holds one key (single, or a FROST group key). Present only in authority modes. May be honest, offline, compromised or hostile |
| Third-party observer | Reads the chain, can broadcast any valid transaction, can deposit anything to any address |
| Token issuer | Controls a KCC-20 template and any minter branch. May be benign or hostile |
| Node operator | Serves the CLI, the watcher and the demo over RPC. May be hostile or compromised |
| Network attacker | Man in the middle on node, download and package channels |
| Malicious counterparty file | Supplies a terms file, IPST or FROST package crafted to mislead a signer |
| Supply-chain attacker | Controls a dependency, a build input or a mirror |

## 4. Trust assumptions

Impulse makes these assumptions. If one fails, the guarantees stated below fail with it.

| # | Assumption | Basis | Status |
| --- | --- | --- | --- |
| T1 | Kaspa consensus, as run by the pinned rusty-kaspa, enforces script, covenant and lock-time rules as the pinned source reads | The pin and the engine tests in `tests/engine` | Measured against the pinned rev; also run against v2.1.0 with no verdict differing (`docs/evidence/d5-final-suite-v2.1.0/README.md`) |
| T2 | silverc v1.0.0 compiles `impulse_vault.sil` to the bytes in `contracts/compiled/` | `scripts/build-template.sh` rebuilds and compares, and fails on any difference | Measured on each CI run |
| T3 | The KCC-20 template named in the terms behaves as the pinned `kcc20.sil` (covenant-ID binding, four-field state) | `verify` pins artifacts and refuses states beyond four fields (`spec/VERIFY.md`) | Checked by the tooling; KCC-20 itself is not ratified and its own security is not established by this repository |
| T4 | The owner's signing machine is not compromised | Out of Impulse's control | Asserted |
| T5 | A node the operator runs or trusts serves the CLI and watcher | `docs/OPERATIONS.md` section 2 | Asserted; a hostile node can stop the CLI (see AT-14) |
| T6 | The settlement authority, where named, will not sign a settle it should not | Operational policy, `docs/OPERATIONS.md` section 7 | Asserted. The script limits what a signed settle can do (outputs are fixed) but not when it is broadcast |
| T7 | The Rust standard library, `secp256k1`, the FROST library and other dependencies are correct | `Cargo.lock`, `cargo audit`, `cargo deny` in CI | Asserted; advisories are checked, correctness is not proven |
| T8 | The parties compare the terms hash and vault addresses through a channel the other cannot alter | Terms review in the CLI and demo | Asserted |

## 5. Trust boundaries and data flow

```
 key holder's machine                     public
 +----------------------------+          +------------------------+
 | impulse CLI / demo page    |  RPC     | Kaspa node (wRPC)      |
 |  terms -> vault addresses  | -------> |  mempool, DAG, scripts |
 |  unsigned tx builders      | <------- |                        |
 |  local signing (key file)  |          +-----------+------------+
 +--------------+-------------+                      |
                | IPST / FROST files                 | chain
                | moved by the parties               v
                v                          +------------------------+
         counterparty, authority           | ImpulseVault UTXOs     |
                                           | (consensus enforces)   |
 impulse-watch: reads the node, no key,    +------------------------+
 rebroadcasts a valid signed settle
```

Boundaries: (1) key holder to node (untrusted data comes back); (2) party to party (files are unauthenticated unless the parties arrange a channel, `spec/IPST.md`, `spec/THRESHOLD.md`); (3) build time to release (toolchain and dependencies); (4) the contract to everything: only consensus-enforced rules are guarantees, everything else is tooling.

## 6. Security objectives

1. **Atomicity.** A funded trade either settles with both legs delivered as the terms say, or each leg goes home whole. Subject to the limits in `KNOWN-LIMITATIONS.md`.
2. **No redirect.** No signer, including the authority, can send a leg to a destination not named in the terms. The contract fixes the outputs.
3. **Exact amounts.** A leg settles only from a UTXO that holds exactly the leg amount. Fees come from a separate input (rule 5, docs/ENGINEERING-RULES.md).
4. **No key exposure.** No Impulse component holds, reads, logs or transmits a private key (rule 1 of docs/ENGINEERING-RULES.md and its recorded exceptions).
5. **Fail closed.** A malformed input is refused with a stable error code (`spec/ERRORS.md`); every `require` has a failing test.
6. **Reproducibility.** The template and the release artifacts rebuild byte-for-byte from the tagged source.

## 7. Attack surfaces and mitigations

Each row names the attack, the control, where the control is in the code, and the test that fails if the control is removed. Contract tags (`[S1]` to `[R14]`) are explained in `INVARIANTS.md`. Test paths are relative to the repository root; `engine` means `tests/engine`.

### 7.1 On-chain contract

| ID | Attack | Control | Test (fails without the control) | Evidence |
| --- | --- | --- | --- | --- |
| AT-1 | Settler pays a leg to an address of its choosing | Delivery outputs are checked against the terms: `[D1]`, `[D2]`, the delivery builtin, `[S4]`, `[S5]` | `engine/settle.rs`: `d1_output0_under_decoy_covenant`, `s4_kas_proceeds_to_stranger`, `s5_kas_proceeds_short` | Measured, mutation record 31 of 31 |
| AT-2 | Underpaid or overpaid escrow settles | `[E5]`, `[S2]` require exact leg amounts | `settle::e5_escrow_over_funded`, `settle::e5_escrow_under_funded`, `settle::s2_kas_cash_vault_under_funded` | Measured |
| AT-3 | A second deposit to the same vault rides along and is routed elsewhere | `[E1]`, `[E2]`, `[R8]`: the leg's escrow is the only input of its covenant | `escrow_release::second_escrow_deposit_cannot_ride_along_a_settle`, `..._a_refund` | Measured |
| AT-4 | A minter token is escrowed, letting the settler hand minting to a stranger | `[E6]` | `settle::e6_minter_escrow_cannot_hand_minting_to_a_stranger` | Measured |
| AT-5 | Decoy token (wrong amount, wrong covenant, foreign owner) used to drain or strand a leg | `[E3]` to `[E5]`, `[R9]`, `[R12]`, `[R14]`; a non-depositor refund must carry the full leg amount, so a decoy costs the whole leg and it goes home to the depositor | `settle::e4_escrow_owned_by_another_vault`, `refund::r12_counterparty_cannot_substitute_a_foreign_token`, `refund::r14_*` (8 tests) | Measured |
| AT-6 | Authorizer KAS diverted when settling or refunding | `[S8]`, `[S9]`, `[R5]` to `[R7]`, `[R11]` | `settle::s8_*`, `settle::s9_*`, `refund::r5_*`, `r7_*`, `r11_*` | Measured |
| AT-7 | Settle before the agreed time | `[S3]` | `locktime::s3_settle_one_daa_before_earliest` and two more | Measured |
| AT-8 | Depositor withdraws an earmarked leg before expiry | `[R3]`; any funding mode other than revocable is treated as earmarked | `locktime::r3_depositor_earmarked_refund_one_daa_before_expiry`, `r3_unknown_funding_mode_is_earmarked` | Measured |
| AT-9 | Unauthorised refund signer, or signature from the wrong key | `[R1]`, `[R2]` | `refund::r1_stranger_signer`, `refund::r2_depositor_named_stranger_signs` | Measured |
| AT-10 | Settle without the authority when the terms name one; external cash without an authority | `[S6]`, `[S7]` | `settle::s6_authority_signature_from_stranger`, `settle::s7_external_cash_without_authority` | Measured |
| AT-11 | A second vault UTXO at the same address spends off its intended input index | `[S1]`, `[R4]` | `settle::s1_second_kas_cash_deposit_cannot_settle_off_its_index`, `refund::r4_second_kas_cash_deposit_cannot_refund_off_input_0` | Measured |
| AT-12 | Template substitution: a different script presented as the vault | Addresses are derived from the compiled template and terms; `impulse verify` recomputes both vault addresses and the template hash; the startup check refuses a template that does not match `TEMPLATE_HASH` | `crates/impulse-core/src/template/tests.rs`, `engine/template.rs`, `scripts/build-template.sh` | Measured |
| AT-13 | Cross-trade mixing: the asset vault of one trade and the cash vault of another settle together | Closed in templates v1 and v3 by `[S10]`: each vault requires its own trade's other vault at the other leg's canonical input (I26); template v2 by its own `[S10]` | `engine/foreign_covenant_residual.rs` (`s10_cross_trade_mixing_is_refused`) | Measured; limit L8, closed |

### 7.2 Tools, files and nodes

| ID | Attack | Control | Where | Test | Evidence |
| --- | --- | --- | --- | --- | --- |
| AT-14 | Hostile or compromised node: panics or aborts the CLI or watcher; feeds wrong DAA scores or UTXOs | The CLI and watcher bound walks, redact credentials and fail loudly. Two upstream defects (F2, F3) remain and are documented; the process stops, nothing is signed or submitted | `crates/impulse-watch/src/node.rs`, `crates/impulse-cli/src/node.rs`; cap of 5,000 added chain blocks per walk | `crates/impulse-watch/src/tests_review.rs`; fuzz targets `cli_rpc_walk`, `cli_rpc_wire` | Measured; F2 and F3 open (L4) |
| AT-15 | Malformed terms, IPST, transaction, template or token state parsed unsafely | Strict decoders with stable codes; 13 cargo-fuzz targets run 600 s each, clean apart from F1 (fixed) and F2/F3 (upstream) | `crates/impulse-core/src/{terms,tx,template,decode,threshold}`, `fuzz/fuzz_targets/` | `terms::tests::error_codes_are_frozen` and the other frozen-list tests; `docs/evidence/fuzz-2026-10-12/` | Measured |
| AT-16 | Terms tampered after agreement (swapped destination, amount or authority) | The terms hash and the vault address commit to every term; the IPST "terms check" refuses a tampered IPST; `frost sign` requires the agreed terms or terms hash | `crates/impulse-core/src/tx/ipst.rs`, `crates/impulse-cli/src/frost.rs` | `tx::tests::the_terms_check_refuses_tampered_vault_ipsts`, `frost_tests::sign_refuses_before_printing_or_writing_anything` | Measured |
| AT-17 | Builder produces a transaction that fails or is non-standard (mass, dust, fee) | Builders compute masses and minimum KAS, refuse in a fixed order | `crates/impulse-core/src/tx/rules.rs`, `build.rs` | `tx::tests::every_mass_dimension_is_capped`, `refusal_order_*`, `below_min_kas` | Measured |
| AT-18 | Token with extended state, minter branches or foreign templates presented as ordinary | `verify` refuses states beyond four fields and surfaces warnings before funding | `crates/impulse-core/src/verify/token.rs` | `crates/impulse-core/src/verify/tests.rs`; `verify::tests::token_warning_codes_are_frozen` | Measured |
| AT-19 | Funds sent to the cash-vault script of external-cash terms, which Impulse never instantiates | No Impulse tool gives its address; the watcher flags a deposit there as `stray_deposit` (`WATCH_STRAY_DEPOSIT`). There is no recovery builder (D14) | `crates/impulse-watch/src/trades.rs`; `spec/TEMPLATE.md` | Tests in `crates/impulse-watch/src/tests*.rs` | Measured; limit L6 |
| AT-20 | Value-cap bypass: a user funds more than they can lose | Per-trade cap of 10 KAS equivalent (D4), lifted only by `--i-accept-the-risk` | `crates/impulse-cli/src/value_cap.rs` | Tests in that file; CLI mutation record 188 of 188 | Measured |

### 7.3 Keys and signing

| ID | Attack | Control | Where | Test | Evidence |
| --- | --- | --- | --- | --- | --- |
| AT-21 | Key exfiltration by the tools | No component transmits a key. `impulse-core` default build has no key material. The CLI reads a key file the user names and signs locally. FROST shares are written only to a file the party names (0600), never printed or logged; nonces stay in memory; test keys are throwaway | `crates/impulse-cli/src/signing.rs`, `keygen.rs`, `frost.rs`; `crates/impulse-core/src/threshold/` (feature `threshold`, off by default) | `frost_tests`, `phase2_tests`; gitleaks in `scripts/ci-local.sh` | Measured for the tests; the recorded exceptions are in rule 1, docs/ENGINEERING-RULES.md |
| AT-22 | Browser demo leaks its in-page key | Key generated with `crypto.getRandomValues`, in memory only, never stored, sent or logged, wiped on page exit or by the user | `demo/wallets.js`, `crates/impulse-wasm/src/wallet.rs` | `demo/test/*.test.ts`; demo mutation record 159 of 160 (the survivor, M68, is recorded as an equivalent edit) | Measured |
| AT-23 | Proposer obtains FROST shares for a trade the party never agreed to | `frost sign` requires `--terms` or `--terms-hash` and refuses with `FROST_TERMS_NOT_AGREED` | `crates/impulse-cli/src/frost.rs` | `frost_tests::sign_refuses_before_printing_or_writing_anything`; FROST mutation record 56 of 56 | Measured (finding A1, fixed) |
| AT-24 | Authority-signed settle used as a bearer instrument after the circumstance changes | Not fixable in script (the template hash is fixed). Mitigation is operational: sign only when the signing party will broadcast at once, keep the fee input under the authority's control, know how to withdraw a held signature | `docs/OPERATIONS.md` section 7; `spec/THRESHOLD.md` | None (a policy control) | Modelled; limit L2 |
| AT-25 | Authority key compromise | Outputs are fixed by script, so the worst case is early settlement of the agreed trade or a stall. A threshold key reduces exposure | `contracts/impulse_vault.sil` `[S6]` with fixed outputs | `settle::s6_*` | Modelled for the worst case; measured for the output binding |
| AT-26 | Bad FROST point encoding gives several encodings of one value | Point decoders refuse SEC1 prefixes other than 2 and 3 | `crates/impulse-core/src/threshold/encoding.rs` | `threshold::tests::public_encodings_refuse_a_point_prefix_other_than_2_or_3` | Measured (finding F1, fixed) |

### 7.4 Economic and protocol-level

| ID | Attack | Control | Evidence |
| --- | --- | --- | --- |
| AT-27 | Free option: a party with revocable funding withdraws after seeing the market move | Earmarked funding blocks the depositor's own withdrawal before expiry (`[R3]`). It does not stop the counterparty or authority from sending the other leg home at any time before expiry. Disclosed in the CLI summary | Pinned by `refund::a3_earmarked_counterparty_cancels_the_other_leg_before_expiry`; limit L3 |
| AT-28 | Settle after expiry | Cannot be forbidden in script; authorities are expected to refuse and the builders refuse (`TX_EXPIRED`). A self-settling vault has no authority, so anyone can settle after expiry; the trade that settles is still the agreed one | Measured for the builder refusal (`tx::tests::expired`); the rest is policy; limit L1 |
| AT-29 | Direct mode: a party signs, then spends its input elsewhere | Disclosed; use vault mode when earmarking matters | Limit L5 |
| AT-30 | Reorg removes a settle | The signed settle stays valid unless a conflicting spend (for example a refund) is accepted first; `impulse-watch` rebroadcasts while it is valid | `crates/impulse-watch/tests/e2e.rs` (`exit_a_settle_reorged_out_is_rebroadcast_and_the_state_survives_every_restart`) |
| AT-31 | Terms revealed on chain when a vault is spent | Accepted; commitments or ZK are later work | Limit L7 |

### 7.5 Supply chain and release

| ID | Attack | Control | Evidence |
| --- | --- | --- | --- |
| AT-32 | Unpinned or foreign dependency (a WarpCore crate, an unpinned git source) | `scripts/ci-local.sh` fails on any git source other than the two pins, on a second `kaspa-txscript`, on a path dependency outside the repository and on a package named for WarpCore | Measured on each CI run |
| AT-33 | Known-vulnerable dependency | `cargo audit` and `cargo deny` (licences, bans, sources, advisories) in CI. One advisory is ignored with its reason (RUSTSEC-2024-0449, `unsafe-libyaml`, unmaintained, transitive through the pinned rusty-kaspa; D72) | `.cargo/audit.toml`, `deny.toml` |
| AT-34 | Tampered release artifact | `scripts/release.sh` writes `SHA256SUMS` and CycloneDX SBOMs; the build is reproducible from the tagged commit; `SECURITY.md` "Verifying a release" gives the check | `scripts/test-release.sh`; the owner signs `SHA256SUMS` |
| AT-35 | Template compiled from different source than published | `scripts/build-template.sh` compares byte for byte; the mutation record is bound to the source SHA-256 and the template hash, and CI fails if either is stale | Measured on each CI run |
| AT-36 | Secrets committed | gitleaks in CI; no key-shaped corpus is committed to `fuzz/corpus/` | `scripts/ci-local.sh` |

## 8. Out of scope for this model

- The security of Kaspa consensus itself, the rusty-kaspa implementation beyond what the engine tests exercise, silverc beyond the byte-identical rebuild, and KCC-20 as a standard.
- The legal status of any asset a trade moves, and regulatory obligations of whoever operates an authority. Impulse is software, not a service, and makes no compliance claims.
- Physical and operational security of the key holder's devices.
- v0.2 and v0.3 features. v0.2 adds baskets, partial settlement and cross-chain hashlock legs (`spec/V2.md` on the v0.2 release branch); v0.3 adds ZK settle, linked trades and a hashed-terms vault (`spec/V3-ZK.md` on the v0.3 release branch). They need their own model; the cross-chain and ZK work in particular changes the trust assumptions in section 4.

## 9. Review history

The threat model is maintained with the red-team tables in `spec/IMPULSE-SPEC.md` ("Red team") and the findings of the internal reviews of I3 to I14. No CRITICAL finding was open at the end of the last round, and no HIGH finding was open.
