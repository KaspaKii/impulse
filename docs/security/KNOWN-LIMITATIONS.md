# Known limitations (v0.1)

Each limitation below is a property of the v0.1 design or of its dependencies that a user or reviewer would otherwise have to discover. For each: what it is, why it stands, who accepted it and where, and what a user can do. Nothing here is hidden by the code: where a tool can surface the limit, it does.

"Accepted by" names the source of the acceptance. Items marked "spec red team" were accepted in the red-team table of `spec/IMPULSE-SPEC.md` ("Red team"), which the owner approved as the design. Items with a D number are owner decisions; where the number is followed by "default applied", the increment or its review applied the stated default and the owner's confirmation is tracked in the owner's decision log (not in this repository). This file does not say they are confirmed.

Ratings use the project scale: CRITICAL, HIGH, MEDIUM, LOW. No CRITICAL or HIGH limitation is open. Counts and results quoted come from the files cited.

## Summary

| ID | Limitation | Rating | Accepted by |
| --- | --- | --- | --- |
| L1 | Settle after expiry cannot be forbidden in script | MEDIUM | Spec red team |
| L2 | An authority-signed settle is a bearer instrument | MEDIUM | Spec red team (finding A2) |
| L3 | Revocable funding is a free option; earmarked funding does not stop cancellation by the other side | MEDIUM | Spec red team (finding A3) |
| L4 | A hostile node can stop the CLI or watcher | MEDIUM | D71, default applied |
| L5 | Direct mode: a party can abort after signing | MEDIUM | Spec red team |
| L6 | No recovery for a stray deposit to the cash-vault script of external-cash terms | LOW | D14 |
| L7 | Terms are revealed on chain when a vault is spent | MEDIUM | Spec red team |
| L8 | Cross-trade mixing: closed in every template (each settle requires its own trade's other vault) | Closed | `[S10]`, `[H5]`, I26 |
| L9 | KCC-20 is not a ratified standard; issuer powers can stall or move an escrowed leg | HIGH, flagged | Spec red team (flagged, `verify` mitigates) |
| L10 | External cash: the trust in the cash leg sits with the authority | MEDIUM | Design (mode definition) |
| L11 | The authority key is a single point of trust for liveness | MEDIUM | Spec red team |
| L12 | The v1 asset leg is KCC-20 only; tokens with extended state are refused | MEDIUM | D13 |
| L13 | The watcher has no historical scan after a long stop, no failover, no metrics | MEDIUM and LOW | D74 default applied; D19 |
| L14 | A reorg can remove a settle | MEDIUM | Spec red team |
| L15 | One ignored advisory in the dependency tree | MEDIUM | D72, default applied |
| L16 | Per-trade value cap and the declared value | LOW | D4 |
| L17 | Operating an authority may need regulatory authorisation | HIGH, flagged | Spec red team |
| L19 | The template is pinned to silverscript v1.0.0 and KCC-20 at that commit | MEDIUM | rule 3, docs/ENGINEERING-RULES.md |
| L20 | A token of another covenant at a vault address, the other leg's own covenant included: closed in every template, no remaining case; such a token cannot move and is lost | Closed | Owner decision 2026-10-19 (I26); engine tests |

## L1. Settle after expiry cannot be forbidden in script

The vault enforces lower time bounds only: `[S3]` (earliest) and `[R3]` (the depositor's own refund on earmarked funding). The script has no upper bound on a settle, because the engine offers a lock time as a lower bound.

- Effect: a signed settle remains valid after expiry. A self-settling vault has no authority, so anyone can settle it after expiry. The worst case is the agreed trade settling late.
- Control: the builders refuse to build a settle at or past expiry (`TX_EXPIRED`, test `tx::tests::expired`). Authorities are expected to refuse.
- Why it stands: changing it is a template change, and the template hash is fixed.
- What to do: choose the expiry as the time after which you no longer want the trade, and refund promptly.

## L2. An authority-signed settle is a bearer instrument

The authority's signature covers outpoints and outputs. The contract has only a lower time bound, so a signed settle does not expire and the authority cannot revoke it. Example, external cash: the authority signs after seeing the off-chain payment, the buyer keeps the signed transaction, the payment is then reversed. The authority can only race its own refund, which the buyer pre-empts by broadcasting first.

- Control: operational. `docs/OPERATIONS.md` section 7 gives three signing rules (sign only when the signing party will broadcast at once, keep the fee input under the authority's control, and how to withdraw a held signature). `spec/THRESHOLD.md` ("A signed settle does not expire") says the same for threshold signing.
- Why it stands: no contract change is possible without a new template hash.
- Evidence: modelled. There is no test that exercises the policy.

## L3. Revocable funding is a free option; earmarked does not stop the other side cancelling

Revocable funding lets the depositor withdraw a funded leg before settlement. Earmarked funding (`[R3]`) stops the depositor withdrawing its own leg before expiry. It does not stop the counterparty or the authority sending a funded leg home at any time (their refund needs no lock time). So either party can abandon a trade before settlement, at the cost of a fee and of its own leg staying locked until expiry. The refund races any settle already broadcast, because both spend vault input 0.

- Control: the CLI terms summary states the limit and the lock length (`crates/impulse-cli/src/summary.rs`, test `disclosure_and_mode_lines_are_exact`). The behaviour is pinned by `refund::a3_earmarked_counterparty_cancels_the_other_leg_before_expiry`.
- Rated MEDIUM, partially mitigated.

## L4. A hostile node can stop the CLI or watcher

At the pinned rusty-kaspa a41a333, two upstream defects are reachable from a node response: the Borsh readers of `kaspa-rpc-core` size `Vec::with_capacity` from an unchecked u64 length prefix (F2, a failed allocation aborts the process), and `Address::new` asserts the payload length (F3, a panic). The fuzz harness found both (`docs/evidence/fuzz-2026-10-12/README.md`).

- Effect: the process stops. No key is involved and nothing is signed or submitted by it.
- Why it stands: the fix is a pin bump or a patched client, and rule 3 of docs/ENGINEERING-RULES.md bars both without a reviewed change whose purpose is the pin. D71, default applied: accept and document for v0.1.
- What to do: run the CLI and the watcher only against a node you operate or trust (`docs/OPERATIONS.md` section 2). A node URL with a credential appears in the process list and shell history (finding O5); prefer an SSH tunnel.

## L5. Direct mode: a party can abort after signing

In Direct mode both parties sign one transaction over their own UTXOs. A party can sign and then spend its own input elsewhere, so the trade cannot settle. No value is lost, because the other party's input was never moved, but the trade fails.

- Why it stands: Direct mode has no escrow by design. Use vault mode when earmarking matters.

## L6. A stray deposit to the cash-vault script of external-cash terms has no recovery builder

With external cash, there is no cash vault: Impulse tools never instantiate one and give no address for it. A deposit sent there anyway is only recoverable by the buyer. A KCC-20 token sent to that script is not protected: it can be moved to anyone, and Impulse builds no recovery for it.

- Control: `impulse-watch` flags any output that pays that script as `stray_deposit` (`WATCH_STRAY_DEPOSIT`). `refund` returns `TEMPLATE_NO_VAULT`.
- Accepted by: D14 (no recovery builder).

## L7. Terms are revealed on chain when a vault is spent

A settlement reveals its own terms in the redeem script. The Solana program stores terms in the trade account from the start, so this is a difference in design, not a gain either way. Commitments or zero-knowledge proofs are later work; a hashed-terms vault and ZK settle are on the v0.3 release branch (`spec/V3-ZK.md` there) and are not part of v0.1.

## L8. Cross-trade mixing

Status: closed in every template: v1 (`TEMPLATE_HASH` ec92ce9d06ff2f57a4f547b724b6fdfe9d9fa62814e687d8670ae96d331e6f02), v2 (`TEMPLATE_HASH_V2` 75d754c16299e7707787f0e66d9880d7657d09b1bea4ef3bd508cefdb6dd7548), v3 (`TEMPLATE_HASH_V3` f00009e88c562fc529d1c30e406c783eb7532e39f6426be518616eb9a7283d4c) and v4 (`TEMPLATE_HASH_V4` 9656711aae5fad7375afa9076241765356f6f7b9a9d5816ad0f4dc48cc4cddc5, `IMAGE_ID_V4` ffaa95f97b44a9209e245579361b81baaa45bd414f11446f11d8d7a1903916a3). The hashlock template settles one vault alone, so mixing does not arise there.

Before I26, the asset vault of one trade and the cash vault of another settled together under templates v1 and v3 when their delivery terms (destinations, amounts, covenants) matched, for example a repeat trade between the same parties. Each vault still got exactly its own deliveries and its authorizer back. The fix of L20 closes it: in every settle each vault requires, at the other leg's canonical input, the other vault of its own trade, rebuilt from its own redeem script with only the leg index changed (`[S10]`, `spec/TEMPLATE.md`, "The other leg's vault"). The vaults of two trades differ in nonce and trade_ref, so they are refused, and so is a template v1 vault beside a template v3 vault of the same terms. Measured in the pinned engine: `foreign_covenant_residual::s10_cross_trade_mixing_is_refused`, against template v1 and, through `v3p_sibling`, the template v3 probe. Template v2 binds every vault of a trade with its own `[S10]` (`spec/V2.md`). Template v4: the terms guest requires, at the other leg's slot, the template v4 vault of the same terms for the other leg (`[H5]`, `spec/V3-ZK.md` 22.16); a vault of other terms has another commitment (the terms carry 32 random bytes of `blind`) and another address, so no receipt exists for a mixed settle (guest tests `guest_refuses_h5_other_vault`, engine tests in `tests/engine/v4_script.rs` and `tests/engine/v4_live.rs`). What remains is the precise statement: a settle of these templates spends exactly the two vaults of one trade (one under external cash), never vaults of two trades.

## L9. KCC-20 is not a ratified standard; issuer powers

KCC-20 is a published example and proposal in the silverscript v1.0.0 tree. It may change. Issuer powers on a token (minter branches, any extended-state freeze or clawback) can stall or move an escrowed leg.

- Controls: the template hash and the KCC-20 template named in the terms are pinned and checked on every leg. `impulse verify` refuses a token whose state goes beyond KCC-20's four fields, and surfaces minter branches, issuer keys and templates outside the pinned builds as warnings (`spec/VERIFY.md`, tests in `crates/impulse-core/src/verify/tests.rs`).
- The security of KCC-20, silverc and rusty-kaspa is not established by this repository.

## L10. External cash: trust in the cash leg sits with the authority

With external cash, the cash is paid off chain and the authority signs after confirming it. Impulse cannot see the payment. The authority's confirmation is the cash leg's only evidence.

## L11. The authority key is a single point of trust for liveness

The vault enforces the outputs, so a compromised authority key can stall a trade or settle the agreed trade early. It cannot redirect value (`[D1]`, `[D2]`, `[S4]`, `[S5]`, `[S8]`, `[S9]`). A threshold key (FROST, `spec/THRESHOLD.md`) reduces the exposure. A refund path (`[R1]`) exists for the depositor and the counterparty without the authority.

## L12. The v1 asset leg is KCC-20 only

A KAS asset leg is refused (`TERMS_ASSET_KIND_UNSUPPORTED`). KAS against a token is expressed by swapping buyer and seller. KAS against external cash is not supported. A token whose state extends beyond four fields cannot settle or refund through the vault and `verify` refuses it (`VERIFY_TOKEN_EXTENDED_STATE`). Accepted by D13. Lifting D13 later needs no encoding change; the extended-state case needs a template change.

## L13. Watcher limits

- No historical scan (W1, finding O2). A watcher stopped for longer than its node keeps history fails every poll, loudly, and nothing is skipped silently. Recovery is a new state plus `impulse status --from-block`. No settle or refund depends on the watcher, and it holds no key. D74, default applied: not built.
- No node failover inside the watcher (O3): one node per process. Multi-node tracking is outside the open-source watcher (D19). Use a supervisor and `--max-failed-polls`.
- No metrics endpoint or heartbeat (O5, O6): read liveness from the state file's modification time and stderr. Alerting is outside Impulse (D19).
- The 30 second call timeout applies to `decode` and `status` walks (O4). A long walk from an old `--from-block` on a busy mainnet node may not finish in 30 seconds. The time a full batch takes on mainnet is not measured.
- Walk bounds: 5,000 added chain blocks per walk, and a walk whose last chain block is above the node's virtual DAA score is refused (closed finding O1). Not covered: removed chain blocks, transactions per walk, and the decoder's own allocation (L4).

## L14. A reorg can remove a settle

The signed settle stays valid unless a conflicting spend, for example a refund, is accepted first. `impulse-watch` rebroadcasts while it is valid. Finality depth is the operator's parameter. Test: `exit_a_settle_reorged_out_is_rebroadcast_and_the_state_survives_every_restart` (`crates/impulse-watch/tests/e2e.rs`).

## L15. One ignored advisory

RUSTSEC-2024-0449 (`unsafe-libyaml`, unmaintained) is reached through the pinned rusty-kaspa. It is ignored in `.cargo/audit.toml` and `deny.toml` with its reason; any other advisory fails CI. The pin is not moved (D72, default applied: keep the ignore).

## L16. Per-trade value cap and the declared value

The CLI refuses to build or sign a trade above 10 KAS equivalent unless `--i-accept-the-risk` is passed (D4). Because the v1 asset leg is a KCC-20 token whose value the CLI cannot know, every v1 trade needs a declared `--kas-equivalent`. The declaration is the user's word; the cap is a seat belt, not a valuation.

## L17. Operating a settlement authority may need regulatory authorisation

Impulse is software, not a service. Whoever runs an authority carries their own authorisation (the spec names CSDR and the DLT Pilot Regime as examples to check). Impulse makes no compliance claims and does not check issuer terms, transfer restrictions or sanctions.

## L19. Pins

The toolchain is pinned: rusty-kaspa rev a41a333b08848f41bf737b72592e463a6011b8ac (tag v2.0.1 plus the kaspa-txscript-zk-sdk crate), silverscript v1.0.0 (3ed973335b59269293564805cc2c58a14595ec03) and Rust 1.94.0. The suite also passes on rusty-kaspa v2.1.0 with the adaptations listed in `docs/evidence/d5-final-suite-v2.1.0/README.md`, but v0.1.0 is built and shipped on the pins. A pin bump needs a reviewed change whose purpose is the pin (rule 3).

## L20. A token of another covenant at a vault address

Status: closed in every template, with no remaining case: v1 (`TEMPLATE_HASH` ec92ce9d06ff2f57a4f547b724b6fdfe9d9fa62814e687d8670ae96d331e6f02), v2 (`TEMPLATE_HASH_V2` 75d754c16299e7707787f0e66d9880d7657d09b1bea4ef3bd508cefdb6dd7548, unchanged by I26), v3 (`TEMPLATE_HASH_V3` f00009e88c562fc529d1c30e406c783eb7532e39f6426be518616eb9a7283d4c), hashlock (`TEMPLATE_HASH_HASHLOCK` 1e708d70c86ace8015778ccb693573b109dcd7135cf921366525a6f4aeef43d6, unchanged by I26) and v4 (`TEMPLATE_HASH_V4` 9656711aae5fad7375afa9076241765356f6f7b9a9d5816ad0f4dc48cc4cddc5, `IMAGE_ID_V4` ffaa95f97b44a9209e245579361b81baaa45bd414f11446f11d8d7a1903916a3). Send each leg only to its own vault address.

kcc20.sil lets a token owned by a script hash move in any transaction that also spends an input at that address. So a KCC-20 token sent to a vault's address, for example the buyer's cash token sent by mistake to the asset vault's address, would be at the mercy of whoever spends that vault unless the vault refuses it.

- A token of a covenant no leg names. Templates v1, v2, v3 and hashlock: a settle or refund allows only inputs with no covenant or with the trade's own covenants ([F1], [F3]; [HF1], [HF3] in the hashlock template), and a v1 or v3 settle refuses a second input of the other leg's covenant ([F2]). A spend has at most 12 inputs, a template v2 settle N + 18 ([F4], [F5]; [HF2], [HF4]); the builders refuse more with `TX_TOO_MANY_INPUTS`. Pay the fee from fewer, larger UTXOs. Template v4: the script pins the covenant ID of every input of a settle or refund; a spend has at most 8 inputs, which the builders enforce as `ZK_H_SHAPE` (`spec/V3-ZK.md` 22.15).
- A token of a leg's own covenant at the other leg's vault (the case left open in v0.4.0 before I26). Every settle requires the other leg's vault beside this one: templates v1 and v3 `[S10]` (`spec/TEMPLATE.md`, "The other leg's vault"), template v2 its own `[S10]`, template v4 the guest's `[H5]` (`spec/V3-ZK.md` 22.16). That vault admits only its own escrow ([E1], [E4] in v1 and v3), so the stray token cannot stand in for it, and a refund refuses it as a token of another covenant ([F3]).
- Consequence: a token of any covenant sent to a vault address cannot move at all, because every spend that could move it spends the vault, which refuses it. The mistake does not give the token away; it does lose it. This follows from the design (asserted: the engine tests cover the spends the builders make and the faults named in the spec, not every transaction).
- Evidence (measured, pinned rusty-kaspa a41a333 engine): each require has a failing engine test and is caught by its named test in the contract mutation records (`tests/engine/mutation-run*.txt`); the former residual is refused in `tests/engine/foreign_covenant_residual.rs` (`s10_a_cash_token_at_the_asset_vault_cannot_pay_the_seller_without_the_cash_vault`, `s10_an_asset_token_at_the_cash_vault_cannot_deliver_to_the_buyer_without_the_asset_vault`, each with the KCC-20 transfer itself shown valid) against template v1, against the template v3 probe (`v3p_sibling`), and on the shipped template v3 with the committed Groth16 receipts (`v3_settle::v3_s10_*`, `tests/engine/V3-SHIPPED-COVERAGE.md`); template v4 in `tests/engine/v4_script.rs` and `tests/engine/v4_live.rs`.
- Cost: `[S10]` adds about 21,000 script units to each v1 settle vault input; every settle stays within the builders' rule and the standard mass cap (`docs/evidence/template-fix-I26/s10-units.txt`; template v3 in `docs/measurements/v3-zk-units.txt`).

Controls. None is needed for the closed case. The builders' warning `TOKEN_FOREIGN_AT_VAULT` and the watcher's flag `WATCH_FOREIGN_TOKEN` are retired and never raised (`spec/ERRORS.md`, "Retired and changed codes").

Accepted by: the owner, decision of 2026-10-19 (I26): v0.4.0 ships with L20 closed in every template.

## Out of scope for v0.1

v0.2 adds baskets, partial settlement and cross-chain hashlock legs, with Solana programs for the other side (`spec/V2.md` on the v0.2 release branch). v0.3 adds ZK settle, linked trades and a hashed-terms vault (`spec/V3-ZK.md` on the v0.3 release branch). Neither is on `main`. Their limitations are documented with them.
