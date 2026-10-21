# Template v3: each contract tag against its failing test on the shipped bytecode

`contracts/impulse_vault_v3.sil` as compiled and shipped (`contracts/compiled/impulse_vault.v3.json`). Each test below runs on the real template, not the probe: the settle tests carry the committed Groth16 receipt of the fixture vault, the refund tests need no proof. Where a tag's cell is empty there is no such test; `scripts/check-v3-shipped-coverage.py` (run by `scripts/ci-local.sh`) fails when a tag of the contract is missing from this table or a named test does not exist.

The 53-mutant record (`tests/engine/mutation-run-v3.txt`) is NOT mutation evidence for the shipped bytecode: it runs against the probe (template v3 with the one verify call replaced), because a real proof binds one vault address and a mutated contract is another address. The shipped bytecode is covered by this table: a control that is accepted and a fault that is refused, per tag, with a valid proof so that the gate cannot mask the refusal. The shipped bytecode itself has not been mutated.

The `v3_live` row is ignored by default and takes minutes with Docker; `scripts/ci-zk.sh` runs it and records the result in `tests/engine/v3-live-run.txt`, which `scripts/ci-local.sh` requires to match the current contract and test source.

| Tag | Test binary | Source file | Test |
| --- | --- | --- | --- |
| `[S1]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s1_asset_vault_refuses_input_1` |
| `[S2]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s2_kas_cash_vault_under_funded` |
| `[S3]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s3_settle_before_earliest` |
| `[S4]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s4_kas_proceeds_to_stranger` |
| `[S5]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s5_kas_proceeds_short` |
| `[S6]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s6_authority_checked_after_the_gate` |
| `[S7]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s7_external_cash_without_authority` |
| `[S8]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s8_authorizer_return_to_stranger` |
| `[S9]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s9_authorizer_return_short` |
| `[S10]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_s10_asset_vault_refuses_a_settle_without_the_cash_vault` |
| `[E1]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e1_second_escrow_deposit_refused` |
| `[E2]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e2_escrow_under_another_covenant_real_asset_elsewhere` |
| `[E3]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e3_escrow_owner_type_pubkey` |
| `[E4]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e4_escrow_owned_by_another_vault` |
| `[E5]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e5_escrow_over_funded` |
| `[E6]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_e6_minter_escrow_cannot_hand_minting_to_a_stranger` |
| `[D1]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_d1_output0_under_decoy_covenant` |
| `[D2]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_d2_asset_delivery_carrier_kas_short` |
| `[Z1]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_z1_covenant_owner_refused` |
| `[Z2]` | v3_settle | `tests/engine/v3_settle.rs` | `v3_z2_cash_vault_nonempty_proof_refused` |
| `[R1]` | v3_refund | `tests/engine/refund.rs` | `r1_stranger_signer` |
| `[R2]` | v3_refund | `tests/engine/refund.rs` | `r2_depositor_named_stranger_signs` |
| `[R3]` | v3_refund_guards | `tests/engine/v3_refund_guards.rs` | `r3_depositor_earmarked_refund_one_daa_before_expiry` |
| `[R4]` | v3_refund | `tests/engine/refund.rs` | `r4_second_kas_cash_deposit_cannot_refund_off_input_0` |
| `[R5]` | v3_refund | `tests/engine/refund.rs` | `r5_authorizer_kas_short` |
| `[R6]` | v3_refund | `tests/engine/refund.rs` | `r6_kas_cash_to_stranger` |
| `[R7]` | v3_refund | `tests/engine/refund.rs` | `r7_authorizer_kas_to_stranger` |
| `[R8]` | v3_refund_guards | `tests/engine/v3_refund_guards.rs` | `second_escrow_deposit_cannot_ride_along_a_refund` |
| `[R9]` | v3_refund | `tests/engine/refund.rs` | `r9_decoy_token_at_input_1_real_escrow_elsewhere` |
| `[R10]` | v3_refund | `tests/engine/refund.rs` | `r10_home_output_under_decoy_covenant` |
| `[R11]` | v3_refund | `tests/engine/refund.rs` | `r11_counterparty_cannot_refund_asset_authorizer_without_token` |
| `[R12]` | v3_refund | `tests/engine/refund.rs` | `r12_counterparty_cannot_substitute_a_foreign_token` |
| `[R13]` | v3_refund | `tests/engine/refund.rs` | `r13_token_carrier_kas_short` |
| `[R14]` | v3_refund | `tests/engine/refund.rs` | `r14_asset_decoy_amount_0` |
| `[F4]` | v3_foreign_covenant | `tests/engine/v3_foreign_covenant.rs` | `v3_f4_twelve_inputs_settle_and_a_thirteenth_is_refused_before_the_gate` |
| `[F1]` | v3_foreign_covenant | `tests/engine/v3_foreign_covenant.rs` | `v3_f1_a_token_of_another_covenant_is_refused_before_the_gate` |
| `[F2]` | v3_foreign_covenant | `tests/engine/v3_foreign_covenant.rs` | `v3_f2_a_second_token_of_the_other_legs_covenant_is_refused_before_the_gate` |
| `[F5]` | v3_foreign_covenant | `tests/engine/v3_foreign_covenant.rs` | `v3_f5_a_refund_with_13_inputs_is_refused` |
| `[F3]` | v3_foreign_covenant | `tests/engine/v3_foreign_covenant.rs` | `v3_f3_refund_refuses_a_token_of_another_covenant` |
| gate | v3_proofs | `tests/engine/v3_proofs.rs` | `v3_proof_bit_flip_refused` |
| gate | v3_proofs | `tests/engine/v3_proofs.rs` | `v3_forging_guest_refused` |
| `[S6 accepted]` | v3_live (ignored; ci-zk.sh) | `tests/engine/v3_live.rs` | `v3_live_authority_settle_kas_cash` |
