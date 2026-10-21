<!-- Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0. -->
# Solana counterpart HTLC (I18, Solana half)

Status: example program written by this repository (owner decision D33). Mainnet use follows D39: capped values only, with the residual race R2 disclosed (section 3). A deploy is the key holder's action. See the disclaimer in section 7. Source: `solana/programs/impulse-htlc/`. Tests: `solana/programs/impulse-htlc/tests/litesvm.rs`, run by `scripts/ci-solana.sh`.

## 1. Where the parameters come from

The Kaspa side is specified in `spec/V2.md` section 10 (draft of 11 October 2026, increment I16; not yet on release/v0.2 when this was written). This program is written to that draft's counterpart requirements (section 10.5) and its race table (section 10.6). If the owner changes those sections, this file and the program follow the spec, not the other way round.

| Parameter | Kaspa `ImpulseHashlock` (spec/V2.md 10) | This program |
| --- | --- | --- |
| Hash | `sha256(secret) == hash_lock` (`[H3]`) | `sha256(preimage) == hash_lock` (code 13) |
| Preimage length | exactly 32 bytes (`[H2]`) | exactly 32 bytes, other lengths refused (code 12) |
| Who holds the secret | the seller of the Kaspa asset (D32) | the same party is the `recipient` here |
| Lock order | Kaspa vault first, the longer lock | opened second, by the buyer, the shorter lock |
| Clock | DAA score, `expiry_daa` | cluster `Clock::unix_timestamp`, seconds, `timeout` (T_C) |
| Claim window | from funding, unbounded above (R4) | strictly before T_C (code 14) |
| Refund window | seller at or after `expiry_daa` | at or after T_C (code 15) |
| Payee of the claim | `buyer_delivery`, fixed in the terms | token account of the mint owned by `recipient`, fixed at open (code 17) |
| Payee of the refund | `seller_refund`, fixed in the terms | token account of the mint owned by `refund`, fixed at open (code 18) |
| Amount | exactly `amount` | exactly `amount` (open checks the escrow balance, claim pays exactly `amount`) |

## 2. Counterpart requirements of spec/V2.md 10.5, checked against this program

| Requirement | Met | How |
| --- | --- | --- |
| sha256 hashlock over a preimage of exactly 32 bytes, refusing any other length | yes | `claim` refuses data of any length but 32 (`PreimageLength`), then compares sha256 (`PreimageMismatch`). Tested: lengths 0, 31, 33, 64 and a one-bit change |
| The claim pays a recipient fixed at lock time and refuses at or after the timeout | yes | recipient stored at `open`; `claim` checks the destination's owner and mint, and `now < timeout`. Tested at T_C, T_C + 1 and T_C + 1 day |
| The refund pays a refund account fixed at lock time and opens only at or after the timeout | yes | refund owner stored at `open`; `refund` checks `now >= timeout`. Tested at open time and T_C - 1 (refused) and at T_C (pays) |
| The secret appears in the claim transaction or an event readable from a public node | yes | the preimage is the whole instruction data of `claim` after the tag byte |
| Published source, a licence compatible with Apache-2.0 | yes, once published | Apache-2.0, in this repository |

Consequence for I18: the flow can run with this program on devnet and, under D39, on mainnet within the value cap, with USDC as the counterpart asset (D47; section 3, issuer freeze).

## 3. Timing: the margin and the secret-reveal race

Notation as `spec/V2.md` 10.5: T_C is this program's `timeout` (unix seconds), Δ the safety margin, `DAA_RATE_MAX` the assumed maximum DAA rate.

Margin rule (checked off chain by `impulse xchain new` as `HTLC_TIMEOUT_MARGIN` and before the seller's claim as `XCHAIN_MARGIN_TOO_SHORT`, both I18):

```
now + (expiry_daa - current_daa) / DAA_RATE_MAX  >=  T_C + Δ
```

Defaults from D32 (not yet answered by the owner, so these are the defaults in force):

| Quantity | Value | Status |
| --- | --- | --- |
| Δ (Kaspa expiry after T_C) | one hour, and at least the wall-clock equivalent of the D18 finality depth (600 DAA since 2026-10-12; the one-hour floor binds at every rate the code accepts) | default, D32 |
| `DAA_RATE_MAX` | 11 DAA per second (10 per second target plus 10 percent) | modelled; I18 is to measure it over at least 24 hours before mainnet use |
| Δ_claim (seller claims at least this long before T_C) | at least two hours and at least ten times the counterpart chain's time to finalized commitment (`spec/V2.md` section 10.5) | D39 |
| Solana cluster time drift | about 60 seconds | asserted from the Solana Foundation DvP README, not measured here |
| Longest HTLC lifetime on Solana | 30 days from open (code 5) | program constant, bounds rent and lock-up only |

So the Solana timeout must be shorter than the Kaspa expiry by at least Δ in wall-clock terms, with the Kaspa side converted at the fastest assumed DAA rate (which makes the Kaspa expiry arrive as early as plausible). At the defaults, 36,000 DAA at 11 per second is about 54.5 minutes (modelled), so the one-hour floor governs.

What each race case of `spec/V2.md` 10.6 means for this program:

- R1, seller claims on Solana at the last moment: the claim cannot land at or after T_C (code 14), so the buyer always has at least Δ before `expiry_daa` to submit `settleWithPreimage`.
- R2, the seller's claim is seen but does not land before T_C: the secret leaks while the buyer can still refund here. Operational mitigation only: the seller claims at least Δ_claim before T_C and retries. Anyone can submit a claim with the preimage, so a seller with a stalled fee payer can use another; the payee is fixed. Residual risk, disclosed under owner decision D39: a buyer who is, or colludes with, a Solana leader or relay can see the seller's claim and keep it out of blocks until T_C, then take the Kaspa asset with the revealed secret and refund here. Claiming early narrows this window but does not close it, so mainnet runs use capped values only.
- R3, unbounded claim: does not apply; the claim is bounded by T_C.
- R6, R7: 32-byte preimage and sha256 on both sides.
- R8, secret reuse: the HTLC address is `["htlc", funder, hash_lock]`, so one funder cannot hold two live HTLCs with one hash (code 10). A new secret per trade remains the CLI's duty (I18).
- R10, Solana reorg of the seller's claim: the seller resubmits before T_C and checks its claim at finalized commitment.
- R11, clocks: drift of the cluster clock is inside Δ.
- R13, the seller must verify this HTLC before claiming: see section 4.
- Issuer freeze (not a case of 10.6; owner decision D47): with a mint that has a freeze authority, such as USDC, that authority can freeze the escrow at any time, and then neither the claim nor the refund moves it (the token program refuses with `AccountFrozen`; the HTLC stays live until the authority thaws it). Frozen after the seller's reveal, the buyer can still claim on Kaspa with the revealed secret while the seller's claim here fails: the seller loses its leg unless the authority thaws the escrow before T_C. If the authority is, or acts for, the buyer, it can do this on purpose and refund after T_C once thawed. The issuer is therefore a trusted party of every trade that uses such a mint. Tested: `frozen_escrow_blocks_claim_and_refund` (both token programs; claim before T_C and refund at T_C refused, nothing moves, the refund pays once the authority thaws).

## 4. Verifying the counterpart (`impulse xchain verify-counterpart`)

Read at finalized commitment. The counterpart record of `spec/V2.md` 10.2 maps to this program as follows:

| Counterpart record field | Solana value |
| --- | --- |
| chain | `0x01` |
| chain_id | the cluster's genesis hash |
| htlc_program | the deployed program ID |
| asset | the mint (state offset 68); the mint is confirmed by the owner from the issuer's documentation at run time. Its freeze authority is read from the mint (see below) |
| amount | state offset 228, u64 little-endian; and the escrow token account (state offset 100) holds at least this |
| recipient | the seller's wallet: the owner of the token account the claim pays (state offset 132) |
| refund | the buyer's wallet (state offset 164) |
| timeout | state offset 236, i64 little-endian unix seconds |
| hash_lock | state offset 196, equal to the Kaspa terms' hash_lock |

Also check: the state account is owned by the program ID, is 245 bytes, starts with tag `0x48` and version `1`; its address is the PDA of `["htlc", funder, hash_lock]`; the token program at offset 36 is the mint's owner. The full layout is in `solana/programs/impulse-htlc/src/state.rs`. Recipient and refund are wallet addresses, not token accounts: a claim to any token account of the right mint owned by the recipient is accepted.

Freeze authority (owner decision D47). `open` accepts a mint with a freeze authority, so the verifier reads it: the mint's `freeze_authority` is a `COption<Pubkey>` at bytes 46..82 (a 4-byte tag, 1 when set, then the 32-byte key). When it is set, verify-counterpart does not refuse; it prints a warning that names it, before the seller reveals, for example:

```
warning: mint <mint> has a freeze authority, <freeze authority>. It can freeze this HTLC's escrow so that neither claim nor refund moves it; you trust it not to.
```

The verifier also reads the escrow token account's state (byte 108: 1 initialised, 2 frozen) and refuses to report the lock as agreed while the escrow is frozen, since a claim would fail. A frozen escrow after the seller's reveal is the issuer-trust case below; the seller cannot undo it.

The source in this repository (I11 live demo, `crates/impulse-cli/src/xchain_solana.rs`) implements this section. It is read-only: it holds no key and `counterpart-claim` cannot send the claim through it (`XCHAIN_CHAIN_UNSUPPORTED`); the seller claims with `impulse-htlc-demo claim` (`solana/programs/impulse-htlc-demo`). Select it with `--counterpart "solana+<rpc url>#program=<base58 program id>[&funder=<base58>]"`. `https://` is required, `http://` only to exactly `localhost`, `127.0.0.1` or `[::1]`; the url is parsed, and a url with user information (`http://localhost:1@rpc.example/` is a request to rpc.example) is refused. A live HTLC is found by `getProgramAccounts` (size 245, the hash lock at offset 196) at finalized, then confirmed commitment, and must derive from its own funder, hash lock and bump. A claimed or refunded HTLC has no account left: with `funder=` the source rebuilds the lock from the funder's `open` transaction, so the buyer can still read the reveal. Claims are the successful transactions on the HTLC address with a claim instruction of the program on that address, at top level or as an inner instruction (the program accepts a claim through a cross-program invocation, so a reveal can sit in `meta.innerInstructions`). Anyone can send cheap transactions that name the HTLC or the funder, so both histories are paged with `before`, newest first, back to the HTLC's `open` or the start of the history; past 20 pages of 1,000 signatures the source refuses with `CLI_NODE_RPC` and says the history was not searched to its end, never a quiet `XCHAIN_REVEAL_NOT_FOUND`. A frozen escrow is refused as `XCHAIN_COUNTERPART_MISMATCH` by `verify-counterpart` and `counterpart-claim`; a freeze authority prints the warning above. Tests: `xchain_solana_tests.rs` and the `solana_source` module of `xchain_tests.rs` (against a mock cluster, including the HTTP transport). A real validator was exercised on localnet; the devnet run is the key holder's.

## 5. Error codes (`ProgramError::Custom(n)`)

Stable; a new code is appended, never renumbered, and a retired code is never reused.

| n | Name | Raised by | Meaning |
| --- | --- | --- | --- |
| 0 | AmountZero | open | amount is 0 |
| 1 | HashZero | open | hash_lock is all zero |
| 2 | PartyZero | open | recipient or refund is the zero address |
| 3 | PartiesNotDistinct | open | recipient equals refund |
| 4 | TimeoutNotInFuture | open | timeout at or before now |
| 5 | TimeoutTooFar | open | timeout more than 30 days ahead |
| 6 | UnsupportedTokenProgram | open | token program is neither SPL Token nor Token-2022 |
| 7 | MintNotSupported | open | mint not owned by the token program, not initialised, or carries Token-2022 extensions |
| 8 | HtlcAddressMismatch | open | HTLC account is not the PDA of (funder, hash_lock) |
| 9 | EscrowAddressMismatch | open, claim, refund | escrow account is not the HTLC's escrow |
| 10 | AccountNotEmpty | open | HTLC or escrow address already in use (a live HTLC with this funder and hash) |
| 11 | NotHtlc | claim, refund | account is not a live HTLC (never opened, or already claimed or refunded) |
| 12 | PreimageLength | claim | preimage is not 32 bytes |
| 13 | PreimageMismatch | claim | sha256 of the preimage is not hash_lock |
| 14 | ClaimExpired | claim | at or after the timeout |
| 15 | RefundTooEarly | refund | before the timeout |
| 16 | MintMismatch | claim, refund | mint or destination mint differs from the HTLC's |
| 17 | RecipientMismatch | claim | destination not a token account owned by the recipient |
| 18 | RefundAccountMismatch | refund | destination not a token account owned by the refund owner |
| 19 | RentReceiverMismatch | claim, refund | rent receiver is not the funder |
| 20 | EscrowShort | claim, refund | escrow holds less than amount |
| 21 | ExactAmount | open | escrow does not hold exactly amount after the transfer |
| 22 | MissingSigner | open | funder did not sign |
| 23 | (retired) | none | was RefundAccountRequired; retired in review round 1 (claim pays a donation to the recipient), never reused |
| 24 | TokenProgramMismatch | claim, refund | token program differs from the HTLC's |
| 25 | (retired) | none | was MintHasFreezeAuthority; retired by owner decision D47 (a mint with a freeze authority is accepted), never reused |

Malformed instruction data (unknown tag, wrong length for `open` or `refund`) returns `InvalidInstructionData`.

## 6. What this program does not do

- No deployment and no upgrade authority policy. A deploy is the key holder's action.
- No events beyond the transaction itself; watchers read the claim's instruction data.
- No partial claims and no extension-bearing Token-2022 mints (code 7).
- Donations: the escrow holds exactly `amount` after `open`, but anyone can send more tokens to it. `claim` pays everything the escrow holds to the recipient, so it never needs an account the recipient does not control; `refund` pays everything to the refund owner. A donation is a gift to whoever ends the HTLC.

## 7. Disclaimer

- Non-custodial. Impulse runs no service and holds no key or funds. Tokens locked by `open` sit in an escrow token account owned by the HTLC's program address, which no private key controls; only `claim` or `refund`, under the rules above, moves them. Two parties can still act on it: the program's upgrade authority, if the deploy kept one (a deploy with `--final` removes it), and the mint's freeze authority (section 3, issuer freeze).
- No advice. Nothing in this program or its documents is investment, legal, tax or financial advice.
- No issuance. Impulse issues no asset or token. The tokens this program locks, USDC included, are issued by third parties.
- Issuer terms and sanctions. A token such as USDC is held and moved under its issuer's terms, and the issuer can freeze accounts, including this escrow. Each user is responsible for complying with those terms and with the sanctions and other laws that apply to them.
