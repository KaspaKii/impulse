# Impulse

**Atomic delivery-versus-payment for Kaspa. Impulse by WarpCore.**

Impulse is a KiiLabs product.

Impulse is a standalone, open-source delivery-versus-payment (DvP) primitive for Kaspa mainnet. Two parties agree terms, each derives the escrow addresses from those terms, each funds its own leg by plain transfer, and the trade settles in one transaction. It is designed so that either the trade settles or every leg goes home whole, within the limits listed in [Known limitations](docs/security/KNOWN-LIMITATIONS.md). There is one contract template (`ImpulseVault`), a Rust core, a command line, a TypeScript/WASM SDK and a reference watcher.

Impulse is new software that holds value on a public chain. Use small values, recompute both vault addresses from the terms with `impulse verify` before funding, and do not use value you cannot afford to lose. Nothing here is financial, legal or tax advice, and Impulse issues no asset.

Use only values you can lose. A per-trade value cap applies (10 KAS by default).

## Why

Kaspa has no settlement primitive that uses its UTXO model directly. Impulse makes the escrow address a hash of the agreed terms, so there is no trade record to forge, refunds are stateless, and no deployed program or upgrade key has to be trusted. Design properties are compared with the Solana Foundation DvP program, row by row, in [PARITY.md](PARITY.md); the design itself is [spec/IMPULSE-SPEC.md](spec/IMPULSE-SPEC.md). Impulse is software, not a service: it holds no funds and no keys.

## Quickstart (testnet, offline, about a minute)

This derives and checks the escrow addresses of a trade. It needs no node, no key and no funds. It needs Rust 1.94.0 (pinned by `rust-toolchain.toml`) and `jq`.

```
git clone https://github.com/KaspaKii/impulse impulse && cd impulse
cargo build --locked --release -p impulse-cli
export PATH="$PWD/target/release:$PATH"

# 1. A draft: golden vector 08 (a testnet vault trade with an authority), with its
#    KCC-20 asset leg moved to a pinned kcc20.sil build (see the note below).
jq '.terms | .nonce = null
    | .asset_leg.template_hash = "d7fe87e5cc7f41bf3f76ada9b8ef049fa65e53f98f96bdbf29655dca2964a0d1"
    | .asset_leg.template_prefix_len = 1 | .asset_leg.template_suffix_len = 982' \
   tests/vectors/terms/08-testnet-vault-authority-earmarked-kcc20-kas.json > draft.json

# 2. Terms file: canonical bytes and terms hash. On testnet you may type the DAA score.
#    --role and --my-key (a public key) say which side you are; the value is declared in sompi.
impulse terms new --draft draft.json --out terms.json --daa 400000000 --role buyer \
  --my-key 67b2e7c8dfe143ccdad9cdd0929b9bfff2ed9039ef21a146a2caab1c2b542de3 \
  --kas-equivalent 100000000

# 3. Vault addresses and funding instructions, as the buyer (the cash leg is native KAS). Add `--no-qr` to skip the QR code.
impulse address --terms terms.json --daa 400000000 --role buyer \
  --my-key 67b2e7c8dfe143ccdad9cdd0929b9bfff2ed9039ef21a146a2caab1c2b542de3 \
  --kas-equivalent 100000000
```

The last command prints the terms hash, a decoded summary of the trade, the role check, and the funding URI and QR code for the buyer's cash vault. Nothing is signed or sent.

Why step 1 edits the template: the golden vectors name a synthetic token that no funding is ever given for (`CLI_TEMPLATE_UNPINNED`), so the draft uses the first pinned kcc20.sil template listed in `crates/impulse-core/src/verify/pins.rs`. Flags and refusal codes are those of [spec/CLI.md](spec/CLI.md). To go further on TN10 (mint test tokens, fund, settle, refund, in every mode), follow [docs/USER-GUIDE.md](docs/USER-GUIDE.md). Mainnet is used only when you pass `--network mainnet`.

## What is in each release

| Release | Contents | Where |
| --- | --- | --- |
| v0.1 | `ImpulseVault` template with `settle` and `refund`. Four settlement modes: Direct (no escrow), Vault with authority, Vault self-settling, Vault with external cash. Legs are native KAS or KCC-20 tokens (the asset leg is always KCC-20). Revocable and earmarked funding. Terms, canonical encoding and terms hash. Rust core, `impulse` CLI, FROST threshold authority, TypeScript/WASM SDK, `impulse-watch`, static browser demo, parity suite, error catalogue, golden vectors. Per-trade value cap (default 10 KAS, decision D4). | `main` |
| v0.2 | v0.2 adds basket settlement, partial settlement and cross-chain hashlock settlement (design: [spec/V2.md](spec/V2.md)). | `main` |
| v0.3 | v0.3 adds proof-carrying (zero-knowledge, list-gated) settlement (design: [spec/V3-ZK.md](spec/V3-ZK.md)). | `main` |
| v0.4 | v0.4.0 supersedes v0.3.0 (whose templates carry L20; do not fund them). Every template refuses a token of another covenant in any settle or refund of a vault, and every settle requires the other leg's vault of the same trade, which closes known limitation L20 in every template with no remaining case, and cross-trade mixing (L8) in every template. A vault spend has at most 12 inputs (N + 18 for a basket settle; 8 for template v4). Design: [spec/TEMPLATE.md](spec/TEMPLATE.md), "Inputs outside the layout" and "The other leg's vault". | `main` |

All four lines are on `main`, shipped together as v0.4.0, which supersedes the public v0.3.0 (the owner cuts the tag; CHANGELOG.md). The authoritative statement of what each does is the specification, with [CHANGELOG.md](CHANGELOG.md).

## Documentation

| Read | For |
| --- | --- |
| [docs/USER-GUIDE.md](docs/USER-GUIDE.md) | Tasks: create terms, fund, settle, refund, Direct mode, FROST authority, value cap, verifying a counterparty, troubleshooting by error code |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, trust boundaries, how terms, template, vaults, IPST, watcher and SDK fit together |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terms used across the documentation |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running `impulse-watch` and the CLI: install, node, monitoring, incidents |
| [spec/IMPULSE-SPEC.md](spec/IMPULSE-SPEC.md) | The design; authoritative |
| [spec/ENCODING.md](spec/ENCODING.md) | Terms schema, canonical bytes, terms hash, validation |
| [spec/TEMPLATE.md](spec/TEMPLATE.md) | The vault script: layout, instantiation, decoding |
| [spec/TRANSACTIONS.md](spec/TRANSACTIONS.md) | Transaction builders, canonical settle layout, minimum KAS |
| [spec/IPST.md](spec/IPST.md) | The partially signed transaction exchange format |
| [spec/VERIFY.md](spec/VERIFY.md) | Verifier, decoder, token warnings |
| [spec/CLI.md](spec/CLI.md) | Every CLI command, flag and refusal |
| [spec/THRESHOLD.md](spec/THRESHOLD.md) | FROST t-of-n settlement authority |
| [spec/WATCH.md](spec/WATCH.md) | Watcher events, attribution, rebroadcast |
| [spec/ERRORS.md](spec/ERRORS.md) | Every stable error code |
| [PARITY.md](PARITY.md) | Instruction-by-instruction comparison with the Solana Foundation DvP program |
| [crates/impulse-wasm/npm/README.md](crates/impulse-wasm/npm/README.md) | The SDK |
| [demo/README.md](demo/README.md) | The static browser demo |
| [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) | Changes, contributing, reporting a vulnerability |
| [docs/ENGINEERING-RULES.md](docs/ENGINEERING-RULES.md), [CONTRIBUTING.md](CONTRIBUTING.md) | The project's engineering rules and conventions |

## Hashlock exchange (v0.2 draft, testnet only)

`impulse xchain` exchanges a Kaspa KCC-20 asset against a payment locked in a hash time-locked contract on another chain, such as USDC on Solana. It is two transactions on two chains linked by one hash lock: conditional exchange with residual risk, not atomic settlement. On mainnet it runs under the per-trade value cap and prints the race R2 notice (D39 b, D40). See `docs/XCHAIN-SOLANA-USDC.md`.

Impulse is non-custodial software: it holds no funds on any chain, runs no service, gives no financial, legal or investment advice and issues no asset. Any stablecoin named in an example (USDC included) is issued by its issuer under the issuer's own terms, which may include freezing and sanctions controls Impulse cannot see or override. Users are responsible for their own sanctions and regulatory compliance.

## Layout

```
contracts/   impulse_vault.sil, compiled artifact, TEMPLATE_HASH
crates/      impulse-core, impulse-cli, impulse-watch, impulse-wasm
tests/       engine, parity, vectors
spec/        IMPULSE-SPEC.md, IPST format, error catalogue
docs/        guides, security documents, evidence, release documents, reference
demo/        static browser demo
```

## Building

`scripts/ci-local.sh` runs the full gate (fmt, clippy, tests, cargo-audit, secret scan, licence scan). Toolchain pins:

- Rust 1.94.0
- rusty-kaspa rev a41a333 (tag v2.0.1 plus the kaspa-txscript-zk-sdk crate; the exact rev silverscript v1.0.0 pins)
- silverscript v1.0.0 (ships KCC-20)

## Licence

Apache-2.0. See `LICENSE`.

## Disclaimer

Impulse is non-custodial software: it holds no funds and no keys, and signing happens only on the key holder's machine. Nothing in it, or in this documentation, is financial, legal or tax advice, or an offer or solicitation to buy or sell anything. Impulse issues no asset and no token: any asset or token a trade moves is issued by someone else. Issuer terms, transfer restrictions and sanctions or other legal obligations that apply to an asset or a party stay the users' own responsibility, and Impulse does not check them.

## Operators

Impulse is software, not a service. Anyone who runs a settlement authority with it carries their own regulatory authorisation. Impulse makes no compliance claims.

## Contact

Speak to our team through the issue tracker or the security contact in `SECURITY.md`.

<!-- impulse-v3 -->
## List-gated settle (v0.3)

Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain.
The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified.
Only the asset vault checks the proof. The cash vault settles only beside the asset vault of the same terms, so verify both vault addresses before funding cash.
Template v3 and the list prover are for values at or below the 10 KAS cap. Above it the tools refuse unless --i-accept-the-risk is passed.

What it is. In a list-gated trade the asset vault releases the asset only if the settle carries a zero-knowledge proof, checked on chain by Kaspa's ZK precompile, that the buyer's delivery owner is a member of an issuer list whose Merkle root the terms commit to. The proof is bound to this vault, this root and this owner. The other entries of the list stay off chain; the member does not (the delivery owner is the token owner in the vault state and in the delivery output). `spec/V3-ZK.md` is the design, with what is and is not hidden in its section 9.

How it works, in the command line only (there is no SDK or demo page for v3):

1. The issuer builds the list: `impulse zk list build` writes the root and one path file per entry. A path file holds that entry's salt and is given to that member only, before any trade. The issuer signs a manifest digest with its own signer (`impulse zk list manifest`); no Impulse command holds the issuer's key.
2. The parties make terms v3 (`impulse zk terms new`) and check them (`impulse zk verify`, with the manifest and the buyer's path file). Terms without an authority need `--no-authority`: without one, removal from the list after the terms were made cannot stop the settle.
3. Both legs are funded as for any vault trade (`impulse zk fund build`, then `impulse zk ipst sign` and `impulse zk submit`).
4. The member proves membership on its own machine with `impulse-zk-prove` from `circuits/` (`impulse zk prove-args` prints its arguments); then `impulse zk settle build --proof` builds the settle, which is run in the pinned script engine before it is written, and it is signed and submitted like any other IPST.

What to know before using it.

- The gate is on the asset side only. A seller can fund an ungated asset vault (for example a v1 vault) with the same deliveries and settle it against a v3 cash vault with no proof; nothing on chain stops that. `impulse zk verify` checks that both vault addresses are the v3 vaults of the stated terms, and the buyer runs it before funding cash. Neither side of a trade is gated by the other.
- A list cannot be revoked inside the terms. Keep the refund expiry short, and name the issuer as authority if removals must stop a settle.
- The issuer holds every path file, so it can withhold one and stall a trade until the refund; refunds are unaffected.
- A v3 settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass.
- Listing at settle is not a transfer restriction: a member can pass the token on after delivery.
- A list holds at most 1048576 entries. Figures for proving time, memory and script units are published only from the measurement files under `docs/measurements/` and `docs/evidence/`, with their method.
<!-- /impulse-v3 -->

<!-- impulse-v4 -->
## Hashed-terms vault (v0.3, experimental)

The chain shows only a commitment to the terms until a spend. Vault values, the escrowed token, the authority's key, the funders and the outputs of a settle or refund are public. Anyone holding the terms file can show the terms.
Settle and refund both need the terms file. Keep a copy before funding.
A flaw in the proof check could let funds leave a v4 vault. Keep value at or below the cap.
The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified.
Template v4 is for values at or below the 10 KAS cap, and the tools never lift the cap for it.

What it is. In a hashed-terms trade each vault holds a commitment to the terms and the authority's key and nothing else. A settle or a refund carries a zero-knowledge proof, checked on chain by Kaspa's ZK precompile, that the spending transaction satisfies the committed terms: the amounts, the destinations, the lock time and the signer rules of a v1 vault, which the vault of this template no longer reads itself. `spec/V3-ZK.md` section 22 is the design, with what is public at each moment.

How it works, in the command line only:

1. A party writes a draft with `"version": 4` and an authority and makes the terms file with `impulse zk terms new-hashed`. The command draws the blind, writes the file and reads it back. Every party and the authority keep a copy.
2. The parties check both vault addresses with `impulse zk verify`, which needs the terms file and both addresses, then fund as for any vault trade (`impulse zk fund build`, `impulse zk ipst sign`, `impulse zk submit`).
3. To settle or refund, `impulse zk settle build` or `impulse zk refund build` writes a plan; `impulse zk witness` writes one witness file for each vault input; each is proved on a machine you control with `impulse-zk-prove-terms` from `circuits/`; the build is repeated with the proof files; the authority signs a settle and the named signer a refund. Both builders check the statement natively before they write anything, and the pinned script engine runs the signed transaction before it is broadcast.
4. Anyone holding the terms file can check an accepted trade with `impulse decode --with-terms`.

What to know before using it.

- A v4 settle carries two proofs, one for each vault input, and a refund one; a refund waits for its proof as well as for its time. A proof can be made before the refund is final.
- Losing the terms file strands the vaults until a copy is found: settle and refund both need it.
- The authority sees the terms it signs for, and a settle cannot happen without it. A refund does not need the authority.
- A v4 settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass.
- This template makes no privacy claim: amounts, the token and the funders are visible, and a settle publishes the parties' keys and the lock time. Figures for proving time, memory, script units and mass are published only from the measurement files under `docs/measurements/` and `docs/evidence/`, with their method.
<!-- /impulse-v4 -->
