<!-- Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0. -->
# impulse-htlc

A minimal example program written for the Solana half of increment I18 (owner decision D33). Mainnet use follows owner decision D39: capped values only, with the residual claim-inclusion race R2 disclosed in `docs/xchain/SOLANA-HTLC.md` section 3. Read the disclaimer below.

A sha256 hash time-locked escrow for one SPL Token or Token-2022 amount, the Solana counterpart of the Kaspa `ImpulseHashlock` vault. The design, parameters and the secret-reveal race are in `docs/xchain/SOLANA-HTLC.md`.

## What it does

| Instruction | Who | When | Effect |
| --- | --- | --- | --- |
| `open` (tag 0) | the funder (signer) | timeout in the future, at most 30 days ahead | Moves exactly `amount` from the funder's token account into an escrow token account owned by the HTLC PDA, and records mint, amount, hash_lock, timeout, recipient and refund |
| `claim` (tag 1) | anyone holding the 32-byte preimage | strictly before the timeout | Pays the whole escrow (exactly `amount` unless someone donated more) to a token account of the mint owned by `recipient`, closes the escrow and the HTLC; rent goes back to the funder |
| `refund` (tag 2) | anyone | at or after the timeout | Pays the whole escrow to a token account of the mint owned by `refund`, closes both accounts; rent goes back to the funder |

- Hash: `sha256(preimage) == hash_lock`, preimage exactly 32 bytes (any other length is refused).
- Clock: the cluster's `Clock::unix_timestamp`, in seconds.
- Exact amounts: `open` checks that the escrow holds exactly `amount` after the transfer. Anyone can still send more tokens to the escrow afterwards; `claim` pays everything the escrow holds to the recipient and `refund` everything to the refund owner, so neither depends on an account its payee does not control.
- Token programs: SPL Token and Token-2022. A mint with any Token-2022 extension is refused at `open` (a transfer fee would break the exact amount; a hook, a permanent delegate or a pause could take or freeze the escrow). A mint with a freeze authority is accepted (owner decision D47), so USDC and other issued stablecoins can be locked; see "The issuer is a trusted party" below. Code 25 (`MintHasFreezeAuthority`) is retired and never reused.
- PDAs: HTLC `["htlc", funder, hash_lock]`, escrow token account `["escrow", htlc]`. A funder cannot open two live HTLCs with one hash.
- The preimage is the claim's instruction data, so it is public once the claim lands.

## The issuer is a trusted party

Most issued stablecoins, USDC included, have a freeze authority, held by the issuer. That authority can freeze the HTLC's escrow token account at any time, and while it is frozen neither `claim` nor `refund` moves it: the token program refuses the transfer (`AccountFrozen`), the HTLC stays live, and only the authority can thaw it. If the freeze authority is, or acts for, the funder, it can claim the Kaspa leg with the revealed secret and keep the escrow frozen until the timeout passes, then thaw it and refund. Using a mint with a freeze authority therefore trusts its holder not to freeze this escrow. `impulse xchain verify-counterpart` warns and names the freeze authority before the seller reveals (`docs/xchain/SOLANA-HTLC.md` section 4). The tests `freeze_authority_mint_opens_and_claims`, `freeze_authority_mint_opens_and_refunds` and `frozen_escrow_blocks_claim_and_refund` show both sides.

The program ID in `src/lib.rs` is a placeholder with no known private key. A devnet deploy is run by the key holder with their own program keypair and that deploy's ID (rule 6, docs/ENGINEERING-RULES.md).

## Disclaimer

- Non-custodial. Impulse runs no service and holds no key or funds. Locked tokens sit in an escrow token account owned by the HTLC's program address, which no private key controls; only `claim` or `refund` moves them. The program's upgrade authority, if a deploy keeps one, and the mint's freeze authority can still act on it.
- No advice. Nothing here is investment, legal, tax or financial advice.
- No issuance. Impulse issues no asset or token. The tokens this program locks, USDC included, are issued by third parties.
- Issuer terms and sanctions. A token such as USDC is held and moved under its issuer's terms, and the issuer can freeze accounts, including this escrow. Each user is responsible for complying with those terms and with the sanctions and other laws that apply to them.

## Build and test

```
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd solana/programs/impulse-htlc && cargo-build-sbf --tools-version v1.52
cd ../.. && cargo test -p impulse-htlc
```

`scripts/ci-solana.sh` runs both. The LiteSVM tests (`tests/litesvm.rs`) cover the happy paths for both token programs and every refusal code except `ExactAmount` (21), a defence-in-depth check that no extension-free mint can trigger.
