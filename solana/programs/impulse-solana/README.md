<!-- Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0. -->
# impulse-solana

A fork of the Solana Foundation DvP program ([solana-foundation/dvp](https://github.com/solana-foundation/dvp), commit `df9919ed02c25a93620e7f6820107c9050ce3b92`, MIT) in which the escrow address binds an Impulse term sheet. Not deployed. Part of Impulse v0.2 (increment I19).

The upstream program, its design and its README are the work of the Solana Foundation and its contributors. This fork changes only what is listed under "What changed". Everything else, including the instruction set, the account layouts of each instruction, the funding model and the unwind paths, is upstream's. For how the program works, read the upstream README at the pinned commit.

## What changed

The escrow (the `SwapDvp` PDA) is derived from one more seed, the Impulse terms hash:

```
upstream: [b"dvp", settlement_authority, user_a, user_b, mint_a, mint_b, nonce_le]
fork:     [b"dvp", settlement_authority, user_a, user_b, mint_a, mint_b, terms_hash, nonce_le]
```

`terms_hash` is the impulse-core v1 terms hash: BLAKE2b-256 keyed with `Impulse/terms/v1` over the canonical terms encoding (`spec/ENCODING.md`). It is the same 32 bytes the Kaspa side commits to in every ImpulseVault script, so one term sheet determines both the Kaspa vault addresses and the Solana escrow address.

| Item | Change |
| --- | --- |
| `CreateDvp` | New argument `terms_hash: [u8; 32]` after `nonce`. The passed `swap_dvp` must be the PDA for that hash (else `InvalidSeeds`). An all-zero hash is refused (`ZeroTermsHash`, 24). |
| `SwapDvp` account | New field `terms_hash` after `nonce`; 490 bytes (458 upstream). |
| `SettleDvp` | New argument `terms_hash: [u8; 32]` after `leg_a_extras_count`; it must equal the stored hash (`TermsHashMismatch`, 25). The settlement authority names the term sheet it settles. |
| `RecoverDvp` | New seed argument `terms_hash` (between `mint_b` and `nonce`), used to re-derive the closed PDA. |
| `CancelDvp`, `RejectDvp`, `ReclaimDvp` | Unchanged. Refunds never need the term sheet. |
| Error codes | Upstream codes 0 to 23 unchanged; 24 and 25 appended. |
| Program ID | A placeholder (base58 of SHA-256 of `impulse-solana/program-id/placeholder/v0.2`) for which nobody holds a key. See "Deploying". |
| `security.txt` | Points at the Impulse repository. |
| Rust client | Regenerated with upstream's Codama pipeline (`solana/codegen`, Rust only); `verify::find_swap_dvp_address` takes the terms hash. |

The instruction set is upstream's: the same six instructions, discriminators and account lists.

## What the binding gives, and what it does not

- Anyone holding the term sheet can derive the escrow address and its two escrow token accounts without trusting a counterparty for them, and can check that the account at that address stores the same hash.
- Two term sheets that differ in any field have different terms hashes, so the same parties, mints and nonce give different escrow addresses.
- A `SettleDvp` that names another term sheet's hash is refused, and nothing moves.
- It does not prove consent. As upstream, `CreateDvp` is permissionless and the parties do not sign it; the hash binds the address to a term sheet, not to anyone's agreement to it.
- The program does not read or check the Impulse terms themselves. It cannot recompute the hash on chain (the terms describe Kaspa assets), and it does not compare the Solana leg amounts with any amount in the terms. Clients check that the Solana parameters they fund belong to the term sheet they hold.
- How a Kaspa vault and this escrow settle together atomically is not part of this program. Cross-chain settlement is increment I18.
- Kept from upstream (owner decision D48, default): anyone can send extra tokens to an escrow, and `SettleDvp` refunds that surplus to the depositor's own token account (`user_a_ata_a` or `user_b_ata_b`). If that account is closed, frozen or needs a memo, the whole `SettleDvp` reverts, so a party can block settlement of its own trade by dusting its leg and closing its account. Nothing is taken: the counterparty reclaims its own leg with `ReclaimDvp` at once, and `RejectDvp` closes the DvP once the refund account exists (test `test_settle_blocked_by_closed_surplus_ata_still_recovers`).

## Tests

Measured on 2026-10-11 with Rust 1.91.0, solana-cli 3.1.13 and platform-tools v1.52 (`scripts/ci-solana.sh`), LiteSVM 0.7.0:

| Suite | Upstream tests | Added | Result |
| --- | --- | --- | --- |
| Program unit tests (`cargo test -p impulse-solana`) | 17 | 2 (zero hash refused; argument parsing) | 19 pass |
| Client unit tests (`-p impulse-solana-client`) | 9 | 0 | 9 pass |
| LiteSVM integration tests (`-p impulse-solana-tests`) | 128 | 9 (8 in `test_terms_binding`, 1 blocked-Settle recovery) | 137 pass |
| TypeScript cross-check (`solana/ts`) | none | 5 | 5 pass |

Upstream tests are kept as they are, except that each passes a fixed test terms hash where an instruction now takes one and the account sizes include the 32 extra bytes. One upstream client test (`strict_try_from_bytes_rejects_invalid_option_tag`) computed the option tag offset without the two mint-authority fields; it fails at the pinned upstream commit as well (run on 2026-10-11 against a fresh client generated from the upstream IDL). The fork corrects the offset.

The added LiteSVM tests: the pinned PDAs of the term-sheet fixture; a create, fund and settle under a term-sheet hash; `CreateDvp` naming one hash cannot open the address of another; an all-zero hash is refused; `SettleDvp` naming a wrong hash is refused with both escrows untouched, then the right hash settles; a client that derives the escrow from the wrong term sheet reaches an address with no escrow; `RecoverDvp` with a wrong hash is `InvalidSeeds`; each hash has its own address.

The cross-check (`solana/ts`, Node test runner) takes the term sheets in `solana/tests/fixtures/term-sheets.json`, each of which names a golden terms vector (`tests/vectors/terms/`). Through the impulse-wasm SDK it computes the terms hash and the Kaspa vault addresses and compares them with `tests/vectors/`; through `@solana/kit` it derives the SwapDvp PDA, the nonce tombstone and both escrow token accounts from the same hash and compares them with the values the Rust tests derive with `solana-pubkey`. One sheet has two Kaspa vaults; the other has a Kaspa asset vault and an external cash leg.

Program size, `cargo-build-sbf --tools-version v1.52`: 138,552 bytes.

## Building

From the repository root, with the Solana tools on `PATH`:

```
scripts/ci-solana.sh
```

It builds the program and the two test-only SBF fixtures (`impulse-solana-hook-fixture`, `impulse-solana-wallet-fixture`, upstream's transfer-hook and smart-wallet fixtures, never deployed), runs clippy and the tests, checks that the committed IDL and generated client match the program, and runs the TypeScript cross-check.

The program writes its IDL to `idl/impulse_solana.json` when it builds. After a change to the program's instructions or accounts, regenerate the client with `pnpm --dir solana/codegen install && pnpm --dir solana/codegen generate` and commit both.

## Deploying

Test run with throwaway keys: `scripts/solana-devnet.sh` builds this program and impulse-htlc,
deploys both `--final` at addresses from throwaway program keypairs (the `declare_id!`
placeholder is left as committed; neither program compares its own ID), and runs one settlement
from a term sheet plus one HTLC claim and one refund, with test SPL mints. Devnet by default,
rule 1 of `docs/ENGINEERING-RULES.md` test-key exception; it refuses mainnet. Evidence goes to
`docs/evidence/solana-<cluster>-<date>/`. On 2026-10-11 it passed on a local validator; the devnet
run is pending (faucet rate-limited).

A lasting deployment is not done here, and only ever by the key holder (rule 6, docs/ENGINEERING-RULES.md). The key holder:

1. generates the program keypair on their own machine and sets its public key in `declare_id!` in `src/lib.rs`;
2. rebuilds, regenerates the client and reruns `scripts/ci-solana.sh` (the term-sheet fixture pins PDAs under the program ID, so it is regenerated with the new ID);
3. deploys to devnet with that keypair and runs one settlement from a term sheet (the I19 exit test).

Publication waits for the owner's sign-off on positioning (I19).

## Licence

The upstream code is MIT, Copyright (c) 2026 Solana Foundation; its licence text is in `solana/LICENSE-MIT` and applies to the portions derived from it. The Impulse modifications are Apache-2.0. Every derived file says so in its header; `NOTICE` at the repository root attributes the upstream project.
