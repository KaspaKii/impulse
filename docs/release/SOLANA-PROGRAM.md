<!-- Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0. -->
# Solana program record: impulse-htlc on mainnet-beta

Where the key holder records the mainnet deploy of `solana/programs/impulse-htlc` (owner decision 2026-10-17). The deploy is the key holder's action; nobody but the key holder fills in anything marked OWNER. Nothing in this file is a claim about the program's safety.

## The record (OWNER fills the empty fields)

| Field | Value |
| --- | --- |
| Program ID | (empty: set by the deploy) |
| Deploy transaction | (empty) |
| Deploy slot and date (UTC) | (empty) |
| Fee payer public key | (empty) |
| Upgrade authority public key | (empty; a dedicated key kept offline) |
| Upgrade authority final? | no (finalizing is irreversible: no fix is possible after it) |
| `scripts/solana-mainnet-deploy.sh verify` output | (empty: paste the lines, `ok: the deployed program equals the recorded build`) |
| `solana-verify verify-from-repo` output | (empty: once the repository is public) |
| Actual SOL spent and locked | (empty: measured) |

## The build this record was prepared for

| Field | Value |
| --- | --- |
| Source | `solana/programs/impulse-htlc` in this repository, `solana/Cargo.lock` as committed |
| Toolchain | solana-cli 3.1.13, platform-tools v1.52 (`cargo-build-sbf --tools-version v1.52 -- --locked`), Rust 1.91.0 |
| `impulse_htlc.so` size | 33,248 bytes (measured 2026-10-17) |
| `impulse_htlc.so` sha256 | `895dc73545db797d535f814c1793544682ad8b3ad585a754c92153e21046e8f4` (measured 2026-10-17 by `scripts/solana-mainnet-deploy.sh build`; the same hash as the devnet deployment recorded in `demo/xchain-demo.sh`) |
| Reproduce | `scripts/solana-mainnet-deploy.sh build` (with `solana-verify` and Docker it uses `solana-verify build`, the cross-machine reproducible path; without them it uses `cargo-build-sbf` as above, which reproduces on the same toolchain) |

The program ID is not part of the program logic: the `declare_id!` in the source is a placeholder, the PDAs derive from the ID the runtime passes, and the hash above does not depend on where it is deployed. `impulse-htlc-demo` refuses the placeholder on mainnet.

## SOL needed (modelled, not measured)

Rent read from the Solana mainnet-beta RPC on 2026-10-17 (`solana rent`); fees modelled at 5,000 lamports per signature plus the default priority fee of the plan (5,000 micro-lamports per unit); both change with the cluster.

| Item | `--max-len` 66,496 (2x, upgrade room; the plan default) | `--max-len` 33,248 (exact size) |
| --- | --- | --- |
| Program-data account rent (stays locked) | 0.338679 SOL | 0.169779 SOL |
| Program account rent (stays locked) | 0.000833 SOL | 0.000833 SOL |
| Buffer rent (held until the deploy completes, then returned) | 0.169738 SOL | 0.169738 SOL |
| Fees | about 0.0004 SOL | about 0.0004 SOL |
| Peak on the fee payer | about 0.510 SOL | about 0.341 SOL |
| Recommended balance (peak + 20 percent + 0.01 SOL) | about 0.62 SOL | about 0.42 SOL |

Closing a deployed program returns its program-data rent; a final program cannot be closed. A failed deploy leaves the buffer, which `solana program close --buffers` returns.
