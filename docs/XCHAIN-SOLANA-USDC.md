# Hashlock exchange: a Kaspa KCC-20 asset against USDC on Solana

User guide for the I18 hashlock flow, Kaspa side (`impulse xchain`), with a counterpart HTLC on Solana. The design is `spec/V2.md` sections 10.5 (flow), 10.6 (race analysis) and 10.9 (commands); this file explains them for the two parties and does not change them. The mainnet steps are in the "Mainnet" section below and are run by the key holder.

## Read this first

- **What it is.** Two transactions on two chains, linked by one sha256 hash lock. It is conditional exchange with residual risk (`spec/V2.md` section 10.6, R2, R9, R10, R12), not atomic settlement. A hashlock trade is reported complete only when the Kaspa claim is final and the Solana claim is counterpart-final (`spec/V2.md` section 4.8).
- **Where it runs.** TN10, the counterpart's devnet and, since the owner's answers D39 (b) and D40 (2026-10-15), Kaspa mainnet under the per-trade value cap. Mainnet is capped (10 KAS by default; a larger trade needs `--i-accept-the-risk`, otherwise `CLI_VALUE_CAP_EXCEEDED`), needs a DAA rate sample from `xchain daa-sample` no older than 30 days, and every `impulse xchain` command on mainnet prints the race R2 disclosure on stderr. Race R2 is disclosed, not removed: a buyer who controls or colludes with a counterpart block producer or relay can delay the seller's counterpart claim past its timeout, so claim early. `XCHAIN_MAINNET_GATED` is reserved and no longer returned.
- **Solana source.** The CLI has a read-only Solana JSON-RPC counterpart source (`crates/impulse-cli/src/xchain_solana.rs`, `docs/xchain/SOLANA-HTLC.md` section 4): select it with `--counterpart "solana+<rpc url>#program=<base58 program id>[&funder=<base58>]"`. It holds no key and sends nothing: `counterpart-claim` cannot send the Solana claim through it (`XCHAIN_CHAIN_UNSUPPORTED`), so the seller claims with the Solana tool (`impulse-htlc-demo claim`). Before it signs, the tool reads the live HTLC and refuses unless it holds exactly `--expect-amount` base units (required on mainnet), pays the destination owner (`--dest-owner`, else the payer) and times out more than `--min-lead` seconds from the cluster time (default 7,200, the claim lead); the scripts pass the agreed amount and the seller as the owner. The commands that read the counterpart chain (`verify-counterpart`, `watch`, `claim --counterpart`, `status --counterpart`) work against it. No production Solana program is chosen; the program the source reads is the demo `impulse-htlc-demo` program (`solana/programs/impulse-htlc-demo`), and a real validator was exercised on localnet (D27). Any other `--counterpart` URL form is `XCHAIN_CHAIN_UNSUPPORTED`.
- **What is in this build.** The Solana HTLC is `solana/programs/impulse-htlc` (`docs/xchain/SOLANA-HTLC.md`); the CLI reads Solana over JSON-RPC (`--counterpart solana+<rpc url>#program=<id>&funder=<buyer>`) and sends nothing there; the Solana transactions are made by `impulse-htlc-demo` (below). Mainnet-beta use is the section "Mainnet" below.
- **Non-custodial, no advice, no issuance.** Impulse is software. It holds no funds on any chain and runs no service; the counterpart program holds the buyer's funds under its own rules. Impulse gives no financial, legal or investment advice and issues no asset. USDC, or any stablecoin named in an example, is issued by its issuer under the issuer's own terms, which may include freezing and sanctions controls that Impulse cannot see or override. Users are responsible for their own sanctions and regulatory compliance.
- **Value cap.** The per-trade value cap of `spec/CLI.md` applies.

## The two locks

| | Kaspa (first, longer) | Solana (second, shorter) |
| --- | --- | --- |
| Holds | The seller's KCC-20 asset, in the ImpulseHashlock vault | The buyer's USDC, in the counterpart HTLC program |
| Opens to the other party with | The 32-byte preimage of hash_lock (`settleWithPreimage`), until the seller refunds after expiry_daa | The same preimage, until the counterpart timeout T_C |
| Goes home | Seller after expiry_daa; buyer at any time (sends the asset back to the seller) | Buyer after T_C |
| Funded by | The seller (`xchain fund build`) | The buyer, with the counterpart program's tools |

The seller makes the secret and holds it (D32). The Kaspa vault is earmarked: the seller cannot take the asset back before expiry_daa (R5).

## What the counterpart HTLC must do (D33)

A Solana program is acceptable only if all of these hold, checked before it is used:

- sha256 hash lock over a preimage of exactly 32 bytes; any other length is refused (R6, R7);
- the claim pays a recipient fixed at lock time and is refused at or after T_C (an upper-bounded claim, R3);
- the refund pays a refund account fixed at lock time and opens only at or after T_C;
- the preimage appears in the claim transaction or an event readable from a public node;
- published source and a licence compatible with Apache-2.0; for any mainnet use, your own review of it (D40; Impulse names no program).

No program is named here: none has been checked against these requirements. The file `claim.rs` of an earlier work branch is not a candidate until its origin and licence are recorded (D25).

## The counterpart record for Solana

The hashlock terms carry the agreed Solana lock (`spec/V2.md` section 10.2). In a draft it is the `counterpart` object, every identifier as 64 lowercase hex digits (the 32 bytes the Solana base58 form encodes):

| Field | Value for Solana |
| --- | --- |
| `chain` | `"solana"` (chain kind `0x01`) |
| `chain_id` | The cluster's genesis hash, read by the owner from the cluster itself at run time |
| `htlc_program` | The HTLC program ID |
| `asset` | The USDC mint of that cluster, which the owner confirms from the issuer's own documentation at run time. No mint address is stated in this repository |
| `amount` | In the mint's base units, as the mint defines them |
| `recipient` | The seller's account that the program pays on a claim, in the form the program pays to |
| `refund` | The buyer's account that the program pays on a refund |
| `timeout` | T_C, in unix seconds as the program compares it with the cluster's clock |

The seller pins `recipient` with `--my-counterpart-account` in `xchain new`, the buyer pins `refund` in `xchain verify`; a mismatch is `CLI_DESTINATION_NOT_MINE`.

## Timing: the margins

All figures below are rules of the design; the times they produce are estimates, not guarantees.

- **expiry_daa against T_C.** `xchain new`, `verify` and `fund build` refuse terms whose expiry_daa is estimated to arrive earlier than T_C plus Δ (`HTLC_TIMEOUT_MARGIN`). The estimate is early on purpose: now plus the DAA scores to expiry divided by `DAA_RATE_MAX`. On TN10 without a sample, `DAA_RATE_MAX` is 2 times the target rate, 20 per second. On mainnet it would come from a recorded sample (`scripts/sample-daa.sh`, D45), and creation without one is refused (`HTLC_DAA_SAMPLE`). It is 1.5 times the sample's busiest 10 minutes and never below the target rate, 10 per second, and a sample whose mean rate is below half the target is refused (`HTLC_DAA_SAMPLE`), so a wrong or forged slow sample cannot make the estimate late.
- **Δ** is the D18 finality depth (D18: 600 DAA, about 60 s at 10 BPS; modelled from the target rate, not measured) at `DAA_RATE_MAX`, plus the counterpart's time to finalized commitment (`--counterpart-final-secs`), plus the retry window for the Kaspa claim (`--retry-secs`, default 1,800 seconds), and never less than one hour.
- **Δ_claim**, the seller's lead before T_C, is the larger of two hours and ten times the counterpart's time to finalized commitment. The terms summary prints the latest reveal, T_C minus Δ_claim. `xchain new` refuses a T_C closer than Δ_claim (`XCHAIN_MARGIN_TOO_SHORT`), and `xchain counterpart-claim` refuses a first reveal after the latest reveal time.
- **Keep the expiry short.** Until expiry_daa the seller's asset is locked, and the buyer holds a free option: it may never lock on Solana (R12). Choose the shortest expiry the margin rule accepts.

## The flow, step by step

| Step | Who | Kaspa side (`impulse xchain`) | Solana side (the program's tools) |
| --- | --- | --- | --- |
| 1 | Seller | `new`: draft in, fresh secret written to `--secret-out` (mode 0600, never shown), terms file and vault address out; the hash lock is recorded in `--known-hashes` | |
| 2 | Buyer | `verify`: role, own delivery, own Solana refund account, margins, hash lock not seen before (`XCHAIN_HASH_REUSED`) | |
| 3 | Seller | `fund build`, `sign`, `submit` | |
| 4 | Buyer | `verify-funding --txid <funding>`: run until it prints `ok:`. It refuses unless the funding holds exactly one escrowed token (the asset's covenant and template, owned by the vault's script hash, exactly the amount, not a minter) and an authorizer at the vault, both unspent, at final depth (600 DAA, D18). A transaction ID from the seller proves nothing by itself | |
| 5 | Buyer | | Only once step 4 printed `ok:`: lock the USDC amount with hash_lock, recipient, refund and T_C exactly as the terms summary shows them |
| 6 | Seller | `verify-counterpart`: the lock equals the record in every field, is funded and is counterpart-final (R13). With `--counterpart solana+...` the CLI reads the lock; the seller may also check the same fields with the program's tools | |
| 7 | Seller | `counterpart-claim`: reveal by claiming before the latest reveal time; reported done only at counterpart-final, resubmitted until then | The claim, with the secret from the seller's file (`impulse-htlc-demo claim`; the CLI source is read-only) |
| 8 | Buyer, or anyone | `watch` (preimage written at counterpart-final, never shown), or `claim --counterpart` (takes a reveal in any state); then `claim`, `sign` as payer, `submit` | |
| 9 | Both | `status --txid <claim> --counterpart`: `trade: complete` only when the transaction is this trade's claim (it spends this vault and delivers to buyer_delivery), final, and the Solana claim counterpart-final; a transaction that is not part of the trade is refused (`XCHAIN_TX_UNRELATED`) | |

If the seller never reveals: the buyer refunds on Solana after T_C; the seller refunds the asset after expiry_daa (`xchain refund --signer seller`), or the buyer sends it home at any time (`xchain refund --signer buyer`, with the token).

## Race analysis, for the parties

The full table is `spec/V2.md` section 10.6. What each party does about each case:

| Case | At risk | What the design does | What you do |
| --- | --- | --- | --- |
| R1, a reveal at the last moment | Buyer | The margin rule leaves the buyer at least Δ before expiry_daa, and the Solana claim cannot land after T_C (requirement above) | Buyer: run `watch` from the time you lock; claim as soon as the preimage is seen |
| R2, the seller's Solana claim seen but delayed past T_C | Seller | Open, not resolved. Δ_claim, done only at counterpart-final, and resubmission narrow the window only. A buyer who is, or works with, a block producer or relay can see the claim and delay it on purpose | Seller: reveal early, never after the latest reveal time. This case is why mainnet is gated (D39) |
| R3, a counterpart claim not bounded by T_C | Buyer | Such a program is refused (D33) | Use only a program that meets the requirements |
| R4, the Kaspa claim has no upper bound | Seller, after expiry only | After expiry_daa both the claim and the seller's refund are valid; the first accepted wins | Buyer: `claim` refuses with less than the retry window left (`XCHAIN_MARGIN_TOO_SHORT`) unless `--past-margin`, which warns |
| R5, a revocable Kaspa vault | Buyer | Hashlock vaults are always earmarked | Nothing |
| R6, R7, preimage length or hash function differ | Either | 32 bytes and sha256 on both sides | Use a program that meets the requirements |
| R8, a secret reused across trades | Seller | `new` makes a fresh secret for every trade and never takes one from outside; `new` and `verify` refuse a known hash lock (`XCHAIN_HASH_REUSED`) | Keep one `--known-hashes` file per installation. The guarantees hold only with a fresh secret per trade |
| R9, a Kaspa reorg removes the claim | Buyer | The claim stays valid and can be submitted again | Buyer: claim at least Δ before expiry_daa; resubmit if it drops |
| R10, a Solana reorg removes the seller's claim | Seller | The seller resubmits before T_C | Seller: run `counterpart-claim` until it reports counterpart-final |
| R11, clock conversion | Buyer | `DAA_RATE_MAX` and Δ absorb DAA rate variation; Solana clock drift is not measured here | Both: keep the margins, do not shorten them |
| R12, the buyer never locks | Seller | A known property: the asset stays locked until expiry_daa; the buyer can end it early by sending the asset home | Seller: shortest viable expiry; a premium, bond or early abort is not in v0.2 (D43) |
| R13, the seller reveals without checking the lock | Seller | `counterpart-claim` runs the full check first and refuses otherwise | Seller: never reveal with other tools before this check |
| R14, someone else submits the Kaspa claim | none | The outputs are fixed by the script: a copy completes the same exchange | Nothing |

## Mainnet: Kaspa mainnet against USDC on Solana mainnet-beta

Owner decision of 2026-10-17: the swap is usable on mainnet at launch, with the key holder deploying the program himself. On mainnet the tools refuse a trade above the value cap unless `--i-accept-the-risk` is passed; each party signs with their own key files. Impulse holds no funds, runs no service, issues no asset, and gives no advice. USDC is issued by Circle under its own terms, which include freezing and sanctions controls Impulse cannot see or override (D47: the issuer is trusted, not controlled). Race R2 applies in full and is not resolved: the swap is conditional exchange across two chains, not atomic settlement.

**The Solana tool.** `impulse-htlc-demo` (the name is historical; `solana/programs/impulse-htlc-demo`, built with `cd solana && cargo build --locked --release -p impulse-htlc-demo`) is the tool for devnet and mainnet. It acts on mainnet-beta only when all of these hold, each tested offline (`solana/programs/impulse-htlc-demo/tests/mainnet_guard.rs`):

| Rule | Behaviour |
| --- | --- |
| Explicit network | The cluster's genesis hash is mainnet-beta's and `--network mainnet` is passed. Either alone is refused, as is `--network devnet` on mainnet. A cluster that is not mainnet and `--network mainnet` is refused. |
| Program ID | `--program` is required on every command; there is no default. The placeholder ID in the source is refused. On mainnet the program account must exist, be executable and be an upgradeable-loader program; its upgrade authority is printed (`program_upgrade_authority:`). |
| Mint | Only USDC, `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, pinned in the tool. Confirm it against Circle's own documentation before a run. The mint must be an SPL Token mint with 6 decimals. The tool warns on stderr that the mint has a freeze authority and names it. |
| Value cap | `open` is capped at 10,000,000 base units (10 USDC), the owner's figure (2026-10-17) beside the Kaspa CLI's default cap of 10 KAS. USDC is the settled amount, so no declaration is needed (the Kaspa leg still needs `--kas-equivalent`). `IMPULSE_MAX_USDC` (base units) may lower the cap, never raise it. `--i-accept-the-risk` lifts it and the tool says so. Refusal text starts `CLI_VALUE_CAP_EXCEEDED`. `claim` and `refund` are never capped: a recovery is never stuck behind a cap. |
| Notice | Every command prints the race R2 notice on stderr on mainnet. |
| No test mint | `setup` (which makes a test mint) is refused on mainnet. |
| Priority fee | `--priority-micro-lamports <n>` (at most 1,000,000) adds a compute-unit price to every transaction the tool sends. |
| Token accounts | `ata --payer-key <file> --owner <key> --mint <usdc>` creates an owner's USDC account (idempotent). A claim and a refund pay into an existing account, so both parties need theirs before the lock. |

The tool reads keypair files only to sign, by the path the caller names; it never prints, logs or writes one. The checks above run before any key file is read.

**Deploy and record the program.** `scripts/solana-mainnet-deploy.sh` builds the program, records the sha256 of the `.so`, reads the rent from a Solana RPC (read-only), prints the exact deploy commands for the key holder's own keypairs (it never deploys, signs or reads a key), and verifies the deployed bytes against the recorded build. The program ID, build hash and deploy facts are recorded in `docs/release/SOLANA-PROGRAM.md`. Keep a dedicated upgrade authority offline. Making the program final (`solana program set-upgrade-authority --final`) is irreversible: no fix is possible after it.

**Costs (modelled from the rent the cluster reported on 2026-10-17, not measured; the deploy figures are in `docs/release/SOLANA-PROGRAM.md`).** Deploy: about 0.34 SOL stays locked with `--max-len` at twice the program size, 0.17 SOL at the exact size, plus about the same again held in the buffer until the deploy completes. Per swap, the buyer needs about 0.01 SOL: two USDC accounts about 0.003 SOL (kept), the HTLC and escrow rent about 0.0034 SOL (returned on claim or refund), and fees well under 0.0001 SOL; the seller needs about 0.001 SOL for the claim fee.

## What is still open

- The owner's positioning sign-off (I19, D27).
- The program ID is not known until the key holder deploys the program.
- R2 has no resolution in this design.
