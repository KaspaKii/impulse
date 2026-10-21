# Impulse invariants (v0.1)

Every property the contract and the builders must hold, each mapped to where it is enforced, the test that fails without it, and the mutation record that shows the test is load-bearing. Companion to `THREAT-MODEL.md`.

Evidence labels: **measured** (a test or recorded run in this repository), **modelled** (argued from design), **asserted** (stated, not checked here). A row is measured only where a named test or record is given.

## 1. How to read the contract tags

`contracts/impulse_vault.sil` marks every `require` with a tag in a trailing comment, for example `// [S1]`. The tags are fixed with template v1: the template hash pins the source, so a tag cannot change without a new template (`spec/ERRORS.md`, "Rules"). They are names, not error codes: the contract returns none, and the engine reports a failed script.

- `S` settle entry, `R` refund entry, `E` escrow check, `D` delivery check.
- The tests are in `tests/engine`; `settle::name` means `tests/engine/settle.rs`, function `name`. The four mutation targets are `escrow_release`, `settle`, `refund` and `locktime`.
- The mutation record is `tests/engine/mutation-run.txt`. `tests/engine/mutation.py` replaces each tagged `require` in turn with `require(true)`, confirms the mutant still compiles with the pinned silverc, runs the engine tests against it (`IMPULSE_VAULT_SIL`), and demands that the named test fails. CI (`scripts/ci-local.sh`, step "mutation record matches the contract") fails if the record is not bound to the current source SHA-256 and `contracts/TEMPLATE_HASH`, or records a miss.

Record header (measured): source sha256 `7ad37f06cb4e7c1b43c4fb42b6cacee313eb41074c18e5e4d9de2a595a251132`, TEMPLATE_HASH `1877344751ca7b4491ba6d19e20139995c83321b3106e539f1c1be4384a65fcd`, 31 requires, 31 mutants, result "31 of 31 requires caught by their named test".

## 2. Contract invariants

The "Line" column is the line of the tagged `require` in `contracts/impulse_vault.sil`. "Mutation record" gives the verdict of the named test in the record and the number of other tests that also failed against the same mutant (a higher number means more independent coverage of the same require).

| Tag | Line | Property (refuses unless) | Engine test that fails without it | Mutation record |
| --- | --- | --- | --- | --- |
| `[S1]` | 158 | The vault input sits at its leg's canonical index: the asset authorizer at input 0, the cash authorizer at input 1 | `settle::s1_second_kas_cash_deposit_cannot_settle_off_its_index` | flipped; 1 further test(s) also fail |
| `[S2]` | 174 | A KAS cash vault UTXO holds exactly amount_b | `settle::s2_kas_cash_vault_under_funded` | flipped; 1 further test(s) also fail |
| `[S3]` | 184 | When earliest_daa is set, the lock time is at least earliest_daa (an unsatisfied lock time) | `locktime::s3_settle_one_daa_before_earliest` | flipped; 2 further test(s) also fail |
| `[S4]` | 192 | KAS cash: output 1 pays the seller_proceeds scriptPubKey | `settle::s4_kas_proceeds_to_stranger` | flipped; 0 further test(s) also fail |
| `[S5]` | 193 | KAS cash: output 1 holds exactly amount_b | `settle::s5_kas_proceeds_short` | flipped; 0 further test(s) also fail |
| `[S6]` | 200 | When the terms name an authority, the authority's signature verifies | `settle::s6_authority_signature_from_stranger` | flipped; 2 further test(s) also fail |
| `[S7]` | 164 | External cash settles only when the terms name an authority | `settle::s7_external_cash_without_authority` | flipped; 1 further test(s) also fail |
| `[S8]` | 137 | A KCC-20 leg's authorizer KAS goes to its depositor's key: output 2 for the asset (output 1 under external cash), output 3 for KCC-20 cash | `settle::s8_seller_authorizer_return_to_stranger` | flipped; 4 further test(s) also fail |
| `[S9]` | 138 | That return holds at least the authorizer's value | `settle::s9_seller_return_short` | flipped; 2 further test(s) also fail |
| `[E1]` | 125 | The leg's escrowed token is the only input of the leg's covenant in the transaction | `escrow_release::second_escrow_deposit_cannot_ride_along_a_settle` | flipped; 2 further test(s) also fail |
| `[E2]` | 126 | That input sits at the escrow position: input 2 for the asset (input 1 under external cash), input 3 for KCC-20 cash | `settle::e2_escrow_under_another_covenant_real_asset_elsewhere` | flipped; 1 further test(s) also fail |
| `[E3]` | 128 | The escrowed token's owner type is SCRIPT_HASH | `settle::e3_escrow_owner_type_pubkey` | flipped; 0 further test(s) also fail |
| `[E4]` | 129 | The escrowed token's owner is this vault's script hash | `settle::e4_escrow_owned_by_another_vault` | flipped; 1 further test(s) also fail |
| `[E5]` | 130 | The escrowed token holds exactly the leg amount | `settle::e5_escrow_over_funded` | flipped; 3 further test(s) also fail |
| `[E6]` | 132 | The escrowed token is not a minter | `settle::e6_minter_escrow_cannot_hand_minting_to_a_stranger` | flipped; 0 further test(s) also fail |
| `[D1]` | 145 | A KCC-20 delivery output carries the leg's covenant ID | `settle::d1_output0_under_decoy_covenant` | flipped; 1 further test(s) also fail |
| `[D2]` | 146 | A KCC-20 delivery output carries at least the escrowed token's own KAS | `settle::d2_asset_delivery_carrier_kas_short` | flipped; 2 further test(s) also fail |
| `[R1]` | 210 | The named signer is the leg's depositor, its counterparty, or the authority when the terms name one | `refund::r1_stranger_signer` | flipped; 1 further test(s) also fail |
| `[R2]` | 211 | The signature verifies for the named signer | `refund::r2_depositor_named_stranger_signs` | flipped; 1 further test(s) also fail |
| `[R3]` | 216 | Earmarked funding: a refund signed by the depositor has a lock time of at least expiry_daa (an unsatisfied lock time) | `locktime::r3_depositor_earmarked_refund_one_daa_before_expiry` | flipped; 3 further test(s) also fail |
| `[R4]` | 220 | The vault UTXO being refunded is input 0 | `refund::r4_second_kas_cash_deposit_cannot_refund_off_input_0` | flipped; 0 further test(s) also fail |
| `[R5]` | 221 | Output 0 holds exactly input 0's value | `refund::r5_authorizer_kas_short` | flipped; 1 further test(s) also fail |
| `[R6]` | 224 | KAS cash leg: output 0 pays the buyer_refund scriptPubKey | `refund::r6_kas_cash_to_stranger` | flipped; 0 further test(s) also fail |
| `[R7]` | 227 | KCC-20 leg (or the cash script of external-cash terms): output 0 pays the depositor's key | `refund::r7_authorizer_kas_to_stranger` | flipped; 1 further test(s) also fail |
| `[R8]` | 241 | At most one input of the leg's covenant | `escrow_release::second_escrow_deposit_cannot_ride_along_a_refund` | flipped; 0 further test(s) also fail |
| `[R9]` | 242 | That input is input 1 | `refund::r9_decoy_token_at_input_1_real_escrow_elsewhere` | flipped; 1 further test(s) also fail |
| `[R10]` | 255 | Output 1 carries the leg's covenant ID | `refund::r10_home_output_under_decoy_covenant` | flipped; 0 further test(s) also fail |
| `[R11]` | 234 | A refund not signed by the depositor carries exactly one input of the leg's covenant | `refund::r11_counterparty_cannot_refund_asset_authorizer_without_token` | flipped; 3 further test(s) also fail |
| `[R12]` | 247 | The token at input 1 is owned by this vault's script hash | `refund::r12_counterparty_cannot_substitute_a_foreign_token` | flipped; 0 further test(s) also fail |
| `[R13]` | 256 | Output 1 carries at least the token input's KAS | `refund::r13_token_carrier_kas_short` | flipped; 0 further test(s) also fail |
| `[R14]` | 253 | A refund not signed by the depositor returns a token holding exactly the leg amount | `refund::r14_asset_decoy_amount_0` | flipped; 7 further test(s) also fail |

Two builtins refuse without a tag (`spec/ERRORS.md`, "On-chain refusals"):

| Builtin | Property | Covered by |
| --- | --- | --- |
| `readInputStateWithTemplate` | The escrowed token runs the KCC-20 template the terms name (hash, prefix length, suffix length) and holds the state it claims | `tests/engine/escrow_release.rs`, `tests/engine/settle.rs` (template-swap cases), `crates/impulse-core/src/tx/tests.rs` (`asset_template_swapped`, `cash_template_swapped`) |
| `validateOutputStateWithInputTemplate` | A delivery or home output is that template with exactly the expected owner, amount and minter flag | `tests/engine/settle.rs` (`d1_*`, `d2_*`), `tests/engine/refund.rs` (`r10_*`, `r13_*`) |

These two are not covered by the tag-by-tag mutation run, because they are not `require` statements. They are exercised by the engine tests above, and the pinned silverscript compiler owns their semantics (T2 in `THREAT-MODEL.md`). They are part of the trusted base.

### 2.1 Properties that follow from several tags

| Property | Established by | Why |
| --- | --- | --- |
| No signer can redirect a leg | `[D1]`, `[D2]`, `[S4]`, `[S5]`, `[S8]`, `[S9]`, `[R5]`, `[R6]`, `[R7]`, `[R10]`, `[R13]` | Every destination output is fixed by the terms, so the authority's signature (`[S6]`) only decides when, not where |
| Exact amounts | `[E5]`, `[S2]`, `[S5]`, `[R14]`, `[R5]` | A leg settles only from a UTXO holding exactly the leg amount; fees come from a separate input |
| One escrow per vault per transaction | `[E1]`, `[E2]`, `[R8]`, `[R9]` | A second deposit cannot ride along and be routed by the KCC-20 transfer |
| Refund returns the whole leg | `[R5]`, `[R6]`, `[R7]`, `[R10]`, `[R11]`, `[R12]`, `[R13]`, `[R14]` | The authorizer KAS and the token go to the depositor together; only the depositor may refund the authorizer alone |
| Time gates | `[S3]`, `[R3]` | Lower bounds on the transaction lock time as a DAA score. There is no upper bound in script (limit L1) |
| Roles | `[R1]`, `[R2]`, `[S6]`, `[S7]` | Refund by depositor, counterparty or named authority; settle needs the authority when the terms name one; external cash needs one |
| Earmarked is the safe default | `[R3]` with `fundingMode != FUNDING_REVOCABLE` | Any unknown funding mode is treated as earmarked (`locktime::r3_unknown_funding_mode_is_earmarked`) |

## 3. Template and terms invariants

| ID | Property | Enforced in | Test | Evidence |
| --- | --- | --- | --- | --- |
| TM1 | The compiled template matches the source and `contracts/TEMPLATE_HASH` byte for byte | `scripts/build-template.sh` | CI step "template rebuild matches TEMPLATE_HASH (I4)" in `scripts/ci-local.sh`; `tests/engine/template.rs` | Measured per CI run |
| TM2 | The vault address commits to every term, including fields the entries never read (version, network, nonce, trade reference) | State span in the contract; `crates/impulse-core/src/template/state.rs` | `crates/impulse-core/src/template/tests.rs`, `proptests.rs`; `tests/engine/instantiate.rs` | Measured |
| TM3 | Terms encode canonically and hash to one value; decode then encode round-trips | `crates/impulse-core/src/terms/codec.rs`; `spec/ENCODING.md` | `terms::tests::error_codes_are_frozen`, `terms/proptests.rs`, golden vectors in `tests/vectors/terms` (`scripts/vectors.sh`, diff must be empty) | Measured |
| TM4 | Terms are structurally valid or refused with a stable `TERMS_` code (distinct parties, KCC-20 asset leg, authority present for external cash, expiry after earliest, and so on) | `crates/impulse-core/src/terms/validate.rs` | `crates/impulse-core/src/terms/tests.rs` | Measured |
| TM5 | The template startup check refuses a template that is not the one pinned | `crates/impulse-core/src/template/mod.rs` | `crates/impulse-core/src/template/tests.rs` | Measured |
| TM6 | A script decodes back to the terms it was built from, or is refused with a `DECODE_` code | `crates/impulse-core/src/decode/mod.rs` | `crates/impulse-core/src/decode/tests.rs` | Measured |
| TM7 | The cash-vault script of external-cash terms is never instantiated by Impulse tools | `spec/TEMPLATE.md` "The cash-vault script of external-cash terms" | `external_cash_has_no_cash_vault_to_fund_or_refund` (`crates/impulse-core/src/tx/tests.rs`) | Measured |

## 4. Builder invariants

Builders are in `crates/impulse-core/src/tx/` (`build.rs`, `rules.rs`, `ipst.rs`, `kcc20.rs`). Each refuses malformed input with a stable code from `spec/ERRORS.md` (rule 4, docs/ENGINEERING-RULES.md). The order of refusal is fixed so every implementation returns the same code for the same input (`spec/TRANSACTIONS.md`, "Refusal order").

| ID | Property | Code | Test | Evidence |
| --- | --- | --- | --- | --- |
| B1 | Canonical settle layout in every mode (inputs 0 to 3 and outputs 0 to 3 as the contract expects) | `TX_WRONG_MODE`, `TX_NOT_AT_VAULT` | `settle_layout_in_every_vault_mode` | Measured |
| B2 | Refund layout for every leg and signer role; the depositor may refund the authorizer alone, others must carry the token | `TX_REFUND_SIGNER` | `refund_layout_for_every_leg_and_signer`, `depositor_may_refund_the_authorizer_alone` | Measured |
| B3 | A leg UTXO holds exactly the leg amount where required | `TX_LEG_AMOUNT` | `kas_cash_short`, `asset_escrow_wrong`, `cash_escrow_wrong` | Measured |
| B4 | The escrowed token is the vault's: covenant, owner, amount, minter flag, template | `TX_ESCROW_MISMATCH`, `TX_TOKEN_TEMPLATE` | `escrow_mismatch`, `asset_template_swapped`, `cash_template_swapped`, `kcc20_artifacts_refused_by_each_check` | Measured |
| B5 | Fees come from a separate input; no fee input is refused; no outpoint is spent twice | `TX_KAS_INPUT`, `TX_DUPLICATE_INPUT`, `TX_INSUFFICIENT_FUNDS` | `no_fee_input`, `duplicate_input`, `insufficient_funds_and_change`, `a_fee_input_of_another_script_version` | Measured |
| B6 | No builder builds a transaction that is expired, or whose lock time and sequences differ from the node's rule | `TX_EXPIRED` | `expired`, `expired_without_earliest`, `expired_when_earliest_equals_expiry`, `lock_time_and_sequences_follow_the_node_rule`; `tests/engine/locktime.rs`, `tests/engine/builders.rs` (`node_rule_ports_follow_the_pinned_source`) | Measured |
| B7 | Mass is within the standard cap in every mode; minimum KAS per output is derived from storage mass; relay fee is met | `TX_MASS`, `TX_BELOW_MIN_KAS`, `TX_FEE_TOO_LOW` | `every_mass_dimension_is_capped`, `masses_are_within_the_cap_in_every_mode`, `at_the_minimum_the_worst_case_fits_the_cap`, `minimum_kas_is_derived_from_storage_mass`, `fee_too_low` | Measured |
| B8 | Token amounts outside the script integer range, and UTXO values above the supply cap, are refused | `TX_ENCODING`, `TX_UTXO_VALUE` | `token_amounts_outside_the_script_integer_range`, `encoding`, `utxo_value` | Measured |
| B9 | Every builder output passes the node engine with real signatures | (engine) | `tests/engine/builders.rs`, `tests/engine/real_terms.rs` | Measured |
| B10 | Refusals are returned in the documented order | all `TX_` codes | `refusal_order_settle`, `refusal_order_shared_checks`, `refusal_order_fund`, `refusal_order_refund`, `refusal_order_direct` | Measured |
| B11 | The error code list is frozen and may only grow | all | `tx::tests::tx_error_codes_are_frozen`, and the parity tests that keep `spec/ERRORS.md` in step (`tests/parity/errors.rs`) | Measured |
| B12 | IPST files round-trip, are read leniently only in whitespace and key order, refuse values outside the supply, and combine only if they differ in signatures alone | `IPST_*` | `ipst_round_trips`, `ipst_reads_any_whitespace_and_key_order`, `ipst_refusals`, `ipst_reader_refuses_values_outside_the_supply`, `ipst_combine_refuses_any_difference_but_signatures` | Measured |
| B13 | An IPST's terms check refuses a tampered transaction | `IPST_*`, `TX_SIGNATURE` | `the_terms_check_refuses_a_tampered_direct_ipst`, `the_terms_check_refuses_tampered_vault_ipsts`, `the_terms_check_accepts_every_builder_ipst` | Measured |
| B14 | Signatures: 65 bytes, SIG_HASH_ALL, verify against the slot's signer and sighash | `TX_SIGNATURE`, `TX_SIGNATURE_SLOT` | `sighash_refuses_a_missing_input`, `tampered` | Measured |

Test names in B1 to B14 are in `crates/impulse-core/src/tx/tests.rs` unless a path is given.

## 5. Verifier, tooling and key-handling invariants

| ID | Property | Enforced in | Test | Evidence |
| --- | --- | --- | --- | --- |
| V1 | `verify` recomputes both vault addresses and the template hash from the terms before funding; a mismatch means there is nothing to fund | `crates/impulse-core/src/verify/mod.rs`; `spec/VERIFY.md` | `crates/impulse-core/src/verify/tests.rs` | Measured |
| V2 | A token whose state goes beyond KCC-20's four fields is refused; minter branches, issuer keys and foreign templates are surfaced as warnings | `crates/impulse-core/src/verify/token.rs` | `verify::tests::token_warning_codes_are_frozen`, `crates/impulse-core/src/verify/tests.rs` | Measured |
| V3 | Text from a counterparty is escaped outside printable ASCII before it reaches a message | `spec/ERRORS.md` "Rules" | `crates/impulse-core/src/verify/tests.rs` | Measured |
| K1 | The `impulse-core` default build holds no key material | `crates/impulse-core/Cargo.toml` (`threshold` feature off by default) | `cargo test -p impulse-core` with default features and with `--features threshold` | Measured (`docs/evidence/d5-final-suite-v2.1.0/baseline-core-default.counts`, `baseline-core-threshold.counts`) |
| K2 | A FROST share is written only to a file the party names, mode 0600, never printed or logged; nonces stay in memory | `crates/impulse-cli/src/frost.rs`, `keygen.rs` | `crates/impulse-cli/src/frost_tests.rs` | Measured; FROST mutation record 56 of 56 (`crates/impulse-cli/frost-mutation-run.txt`) |
| K3 | `frost sign` refuses before printing or writing anything unless the agreed terms or terms hash match | `crates/impulse-cli/src/frost.rs` | `frost_tests::sign_refuses_before_printing_or_writing_anything` | Measured (finding A1, fixed) |
| K4 | Test keys are throwaway, generated at runtime, never committed, logged or printed, erased on drop | rule 1 exceptions, docs/ENGINEERING-RULES.md | gitleaks in `scripts/ci-local.sh`; `fuzz/corpus/` holds no key-shaped corpus | Measured for the scans |
| K5 | The demo page's wallet key is generated in the browser, held in memory only, and wiped on exit or by the user | `demo/wallets.js`, `crates/impulse-wasm/src/wallet.rs` | `demo/test/*.test.ts` | Measured; demo mutation record 159 of 160 (`demo/mutation-run.txt`) |
| C1 | A trade above the per-trade cap (10 KAS equivalent, D4) is refused unless `--i-accept-the-risk` is passed | `crates/impulse-cli/src/value_cap.rs` | tests in `crates/impulse-cli/src/value_cap.rs` and `phase2_tests.rs` | Measured; CLI mutation record 188 of 188 (`crates/impulse-cli/mutation-run.txt`) |
| C2 | Mainnet is used only when `--network mainnet` is passed | `crates/impulse-cli/src/cli.rs` | `crates/impulse-cli/src/phase2_tests.rs` | Measured |
| W1 | The watcher holds no key, bounds a walk to 5,000 added chain blocks, refuses a walk above the node's virtual DAA score, and rebroadcasts a valid signed settle | `crates/impulse-watch/src/node.rs`, `watcher.rs` | `crates/impulse-watch/src/tests_review.rs`, `crates/impulse-watch/tests/e2e.rs` | Measured; watcher mutation record 219 of 219 (`crates/impulse-watch/mutation-run.txt`) |
| W2 | Per-leg attribution: a funded leg is never reported for a trade as a whole; stray deposits are flagged | `spec/WATCH.md` | `crates/impulse-watch/src/tests*.rs` | Measured |

## 6. Mutation records at a glance

| Component | Record | Result | Notes |
| --- | --- | --- | --- |
| Contract (`impulse_vault.sil`) | `tests/engine/mutation-run.txt`, script `tests/engine/mutation.py` | 31 of 31 requires caught by their named test | Bound to source SHA-256 and TEMPLATE_HASH; checked in CI |
| Contract, parity rows | `tests/parity/mutation-run.json`, `scripts/gen-parity.sh --mutate-contract` | Recorded per tag | A parity row citing a tag whose mutant does not fail its test is refused by the generator |
| CLI | `crates/impulse-cli/mutation-run.txt`, `scripts/cli-mutation.py` | 188 of 188 mutants caught | Checked in CI |
| `impulse frost` | `crates/impulse-cli/frost-mutation-run.txt`, `scripts/frost-mutation.py` | 56 of 56 mutants caught | Checked in CI |
| Watcher | `crates/impulse-watch/mutation-run.txt`, `scripts/watch-mutation.py` | 219 of 219 mutants caught | One slow property test is skipped in every run, named in the record |
| Demo (browser) | `demo/mutation-run.txt`, `demo/mutation.mjs` | 159 of 160 mutants caught | The survivor, M68 (`decoder.js`: the decoder trusts the ID the node states), is recorded as an equivalent edit: the caller already refuses a mismatched ID with `SDK_TXID_MISMATCH`. Not a CI step |

A mutation record shows that the tests notice the removal of a check. It does not show that the checks are sufficient.

## 7. Cross-revision evidence

The full suite was run on rusty-kaspa v2.1.0 (what mainnet nodes ran on 2026-10-06) as well as on the pinned rev `a41a333`. No per-test verdict, engine execution result, measurement row, mutation verdict, template byte or golden vector differed (`docs/evidence/d5-final-suite-v2.1.0/README.md`, with raw data and `SHA256SUMS`). The pin was not moved (rule 3, docs/ENGINEERING-RULES.md).

## 8. Properties that are not invariants

For honesty, these are things a reader might expect and the contract does not enforce:

- Settle before expiry. The script has no upper time bound (L1).
- That the trade is the one both parties want. The terms are a commitment, not a judgement.
- That the asset is what its issuer says. Impulse does not check issuer terms, sanctions or transfer restrictions.
- Liveness. A leg moves only if someone with the right to move it acts.
- v0.2 and v0.3 properties (baskets, partial settlement, cross-chain hashlock, ZK settle, linked trades, hashed-terms vault). v0.2 adds these to a separate template on the v0.2 release branch; see `spec/V2.md` there and `spec/V3-ZK.md` on the v0.3 branch. Their invariants are not on `main` and are not covered here.
