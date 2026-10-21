# circuits: the I20 issuer list prover

The prover side of the list-gated settle of `spec/V3-ZK.md` (template v3). It proves that the buyer's delivery owner is in an issuer list whose root the terms commit to, and produces the 128-byte Groth16 proof that template v3 checks with the Kaspa ZK precompile (tag `0x20`, through the `kaspa-txscript-zk-sdk` fragment at rusty-kaspa `a41a333`).

Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain. The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified. Template v3 and this prover are for values at or below the 10 KAS cap; above it the tools refuse unless --i-accept-the-risk is passed.

## Layout

| Path | What |
| --- | --- |
| `list-core/` | `no_std` crate: leaf, node, root, path, journal and guest input rules (spec sections 5.1, 5.2, 5.4). Used by the guest and the host. The tree builder needs feature `std`; feature `test-hook` exposes the zero-leaf test hook and is never enabled by the guest. |
| `list-guest/` | The list guest. Its own workspace and `Cargo.lock`. Built only in Docker (below). |
| `test-guests/forge-guest/` | TEST ONLY: a guest that commits any J without checking a path. Its receipts carry another image ID and are refused (`v3_forging_guest_refused`). |
| `methods/` | Builds both guests with `risc0-build` in RISC Zero's guest-builder image and embeds the ELF binaries and image IDs. `examples/image-id.rs` prints the list guest's image ID. |
| `prover/` | Library and the binaries `impulse-zk-prove` (list guest) and `impulse-zk-prove-terms` (terms guest, `--witness`, `--out`, `--check`, `--image-id`); the test-only binary `impulse-zk-fixtures` (feature `fixtures`). |
| `terms-core/` | The statement of the hashed-terms vault (template v4, spec section 22): terms v4 and its two commitments, the journal J, and the tag functions (`statement`) that the guest, the host checker and the engine differential all call. Plain Rust, the codes of spec 22.8 it raises are `ZK_H_TERMS_VERSION`, `ZK_H_TERMS_DIRECT`, `ZK_H_AUTHORITY_REQUIRED`, `ZK_H_BLIND_INVALID`, `ZK_H_STATEMENT_FALSE` (naming the v1 tag), `ZK_H_SHAPE` and `ZK_H_WITNESS_INVALID`. |
| `terms-guest/` | The terms guest: reads the encoded witness, runs `statement`, commits exactly J. Its own workspace and `Cargo.lock`; built only in Docker. |
| `IMAGE_ID_V4` | The terms guest's image ID, in the same form as `IMAGE_ID`. Template v4 holds it as `IMAGE_ID`; `scripts/build-template-v4.sh` refuses a mismatch and `scripts/build-guest.sh` rebuilds both guests and compares both IDs. |
| `IMAGE_ID` | The list guest's image ID, 32 bytes as hex, in the byte order the template and the zk-sdk use. |
| `GROTH16_PROVER_IMAGE` | The Groth16 prover image pinned by digest, with provenance (spec section 14.1). |
| `scripts/` | `measure-proving.sh` (spec 14.2), `regen-fixtures.sh` (spec 13.1), `env.sh` and the macOS `xcrun-shim/`. |

The workspace is excluded from the root workspace (D60). The host crates build with the root's Rust 1.94.0 (`rust-toolchain.toml`); the guests build with the RISC Zero Rust toolchain 1.91.1 inside the pinned guest-builder image. `scripts/ci-zk.sh` at the repository root builds and tests everything here; `scripts/build-guest.sh` rebuilds the guest and compares its image ID with `IMAGE_ID`.

## Pins

- risc0-zkvm, risc0-groth16, risc0-build `=3.0.4`, the versions rusty-kaspa `a41a333` pins (its workspace `Cargo.toml` lines 306-312). The guests' locks also resolve risc0-zkvm 3.0.4. `ci-zk.sh` checks all three.
- risc0-circuit-rv32im `4.0.3` in `Cargo.lock`: risc0-zkvm 3.0.4 accepts `^4.0.3`, but 4.0.4 changed the `SyscallContext` trait and 3.0.4's executor does not compile against it (measured, run: `cargo build`, errors E0038 and E0049 in `risc0-zkvm-3.0.4/src/host/server/exec/executor.rs`). `ci-zk.sh` checks it.
- kaspa-txscript, kaspa-txscript-zk-sdk and the other Kaspa crates at rusty-kaspa rev `a41a333b08848f41bf737b72592e463a6011b8ac`, the only git source in `Cargo.lock`.
- Guest builder: `risczero/risc0-guest-builder:r0.1.91.1@sha256:fafb377a44e1cfca415577c48d2f7012bda99ed36f2fae27f9a663b9fe6048f0` (`methods/build.rs`), digest read from the registry with `docker buildx imagetools inspect` on 2026-10-12. It is a single-platform image; on this laptop it runs under Docker's emulation.
- Groth16 prover: `GROTH16_PROVER_IMAGE`. The tag is the one risc0-groth16 3.0.4 uses; the registry publishes a `linux/arm64` image beside `linux/amd64` for it, so on the M1 Max the Groth16 step runs natively, not under emulation as spec section 3.6 expected (measured, run: `docker buildx imagetools inspect risczero/risc0-groth16-prover:v2025-04-03.1`). `impulse-zk-prove` runs only the digest for its host's platform, refuses (`ZK_PROVER_IMAGE`) if that image is not present locally, and runs it with `--network none`. Owner confirmation of the digest is pending (D61).
- `risc0-zkvm` is built with `disable-dev-mode`, so `RISC0_DEV_MODE` cannot turn a proof into a fake receipt in these binaries.

## Trust that is asserted, not checked (I20 review round 1)

- The Groth16 ceremony behind the verifying key is asserted, not checked (D59, below). A forged receipt would pass the precompile and bypass the gate for a buyer who is not on the list, so nothing may call the gate enforced.
- The prover image digest in `GROTH16_PROVER_IMAGE` was read from the registry by the maintainers with no independent source. The owner confirms it from a second source (D61).
- `vendor/risc0-zkvm-3.0.4` is a local fork: the crates.io 3.0.4 source plus `patches/risc0-zkvm-3.0.4-prove.patch` (two added `?` in `src/host/recursion/prove/mod.rs`, lines 639 and 640, because risc0-zkp 3.0.4 returns `Result` where the crate calls it as infallible, so the unpatched `prove` feature does not compile). Patch SHA-256: `d8225f3994bc6ce5a84de30a243f406622b35fb537dd9994061479aa7b44b84c` (recorded in `patches/risc0-zkvm-3.0.4-prove.patch.sha256`). The `[patch.crates-io]` entry in `Cargo.toml` hides the fork from dependency scanners such as cargo-audit, so `scripts/ci-zk.sh` checks that the vendored tree equals the registry source plus that patch and nothing else. The patch touches the host prover only; the chain verifies the 128-byte proof with the precompile, which does not use this crate. The patch is named in `spec/V3-ZK.md` section 16.

## The RISC Zero Groth16 setup (D59, point 3)

- SHA-256 of the 424-byte compressed verifying key that the zk-sdk fragment embeds, and template v3 with it: `78886245c5d55b850f2ac26af823802cd128eb4a43d6c52c8a62af46d54306a4` (measured, run: Python `hashlib.sha256` over the bytes of `R0_SERIALIZED_COMPRESSED_VK` in `crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs` at `a41a333`, 2026-10-12). The pinned test `verify_upstream_vk_roundtrip` ties those bytes to `risc0_groth16::verifying_key()` of risc0-groth16 3.0.4.
- Ceremony transcript location: **not yet recorded.** The pinned crate sources name no transcript (measured, run: `grep -ri ceremony` over risc0-groth16 3.0.4 and risc0-zkvm 3.0.4 finds only a comment about rerunning a bootstrap after a new ceremony). The owner records the location from RISC Zero's published documentation and sees both items before the owner run (D59).

## Building on macOS

risc0-sys 1.5.0 compiles Metal kernels on macOS with the Metal compiler's default language standard, and the compiler of a laptop with Xcode rejects three assignments in `poseidon2.metal` under its default (measured, run). `scripts/xcrun-shim/xcrun` adds `-std=metal3.2` to `metal -c` compiles and passes every other call through; `source circuits/scripts/env.sh` puts it on `PATH`, and every script here does so. Without a Metal toolchain (no Xcode), the same shim writes an empty output file for `xcrun metal` and `xcrun metallib` calls and passes the rest through. risc0 4.0.4 proves on the CPU (its Metal segment and recursion provers are commented out in the sources), so the kernels are compiled or stubbed but never used for proving. Do not set `RISC0_SKIP_BUILD_KERNELS`: it also skips the C++ CPU kernels the prover links (measured, run: the link fails with undefined `risc0_circuit_*_cpu_*` symbols). The guests build in Docker (`scripts/build-guest.sh`, which needs a running daemon and reproduces `IMAGE_ID` and `IMAGE_ID_V4`).

## Guest input

`0x01 || index u32 BE || salt 32 || count u32 BE || count x 32 sibling bytes || root 32 || vault_len u8 || vault_spk || owner_len u8 || owner_spk`, nothing after, passed to the guest as one `Vec<u8>` with `ExecutorEnv::write`. The guest refuses (panics) unless `count` is 20, `index < 2^20`, `vault_spk` is 37 bytes of the P2SH form, `owner_spk` is the 36-byte Schnorr P2PK or the 37-byte P2SH form, the salted leaf is not zero and the path leads to `root`. It then commits exactly J of spec section 5.2.

## impulse-zk-prove

```
impulse-zk-prove --path <path.json> --root <hex32> --vault-spk <hex37> --owner-spk <hex36|hex37> \
                 --out <proof.json> [--timings <timings.json>] [--container <name>]
impulse-zk-prove --image-id
```

Path file: `{"index": n, "salt": "<hex32>", "siblings": ["<hex32>", ... 20 of them]}`. The salt hides the entry (spec section 9.2); the path file stays on the member's machine.

Steps: refuse unless the embedded guest's image ID is `IMAGE_ID` (`ZK_IMAGE_ID_MISMATCH`) and the pinned prover image is present (`ZK_PROVER_IMAGE`); check the statement natively (`ZK_PATH_INVALID`, nothing is proved for a non-member); execute; prove a succinct receipt locally; `identity_p254`; the Groth16 step in the pinned image; verify the Groth16 receipt with risc0; map it to the 128-byte compressed proof with the zk-sdk; verify that proof in the pinned Kaspa script engine; write the proof file. Any failure after the native check is `ZK_PROVER`. Nothing is sent to a remote proving service.

Proof file: `{"format": "impulse-zk-proof/1", "proof": "<128 bytes hex>", "journal": "<J hex>", "journal_hash": "<SHA-256 of J>", "image_id": "<hex32>", "risc0_zkvm": "3.0.4", "groth16_prover_image": "<name@digest>"}`.

## Fixtures

`scripts/regen-fixtures.sh` writes `tests/engine/fixtures/v3/proofs/`: per fixture `<name>.inputs.json` (list, root, vault and owner scriptPubKeys, path with its fixed fixture salt, J) and `<name>.proof.json`, plus `lists.json`, `vaults.json` and `cases.json` (each proof, possibly altered, against the J and image ID a vault would use, with the expected engine result and the spec 13.2 test it backs). Everything except the Groth16 proof bytes is deterministic and `--check` recomputes and compares it; a regenerated proof differs in bytes (the prover's random blinding) and is checked by verification. Owners use the x coordinates of the public points G, 2G and 3G; no private key exists anywhere in the fixtures.

The vault scriptPubKeys are stand-ins until template v3 is compiled: P2SH scripts whose hash is SHA-256 of a fixed label (`vault_spk_is_standin` in each inputs file). The proofs are real receipts of the list guest and the proof-only engine cases are meaningful now; the v3 settle tests need proofs bound to the real vault addresses, made with `regen-fixtures.sh --vaults <name to scriptPubKey map>` once the contract step has them.

## Terms guest receipts (template v4)

`impulse-zk-prove-terms --witness <file> --out <proof.json> [--timings <file>]` proves the hashed-terms statement (spec/V3-ZK.md 22.4) for one vault input. The witness is `terms_core::Witness::to_bytes` (the canonical terms, the journal J, the redeem scripts of the escrowed tokens), written by `impulse zk witness`; it holds the terms and stays on the machine that proves. `--check <witness>` runs the statement natively and prints J; `--verify <proof.json>` runs a proof file in the pinned engine's gate on its own (`ZK_H_PROOF_INVALID` if refused); `--image-id` prints the embedded guest's image ID. The proof file has the format above, with `image_id` equal to `IMAGE_ID_V4`.

Committed receipts. `tests/engine/fixtures/v4/<name>.proof.json` holds one real receipt for each fixture plan of `crates/impulse-core/src/zkh/build_tests.rs` (`fixture_plans`: a settle of each cash kind, three refunds), made by `scripts/regen-fixtures-v4.sh` for a fixed world of label-derived public keys. They hold no key of any kind. They are not spendable (a settle needs the authority's signature), so they check the proof and the journal, not a spend: `circuits/prover/tests/v4_fixtures.rs` runs each in the pinned engine's gate (accepted; refused for any changed proof byte, any changed journal byte, another image ID or another receipt's journal), and impulse-core's `committed_receipts_are_the_journals_the_builders_make` compares each journal with the one the v4 builders make today. `scripts/regen-fixtures-v4.sh --check` verifies them all with `--verify`.

Spendable receipts. `tests/engine/v4_live.rs` instead generates the harness's throwaway keys at run time (rule 1, docs/ENGINEERING-RULES.md, the owner's exceptions), builds the real vaults from them, proves each vault input (witness and proof in a temporary directory removed at the end) and runs the inputs in the pinned engine; `zkh_tests::a_v4_trade_end_to_end_with_real_receipts` does the same through the command line. `scripts/ci-zk.sh` runs both after building the prover:

```
(cd circuits && source scripts/env.sh && cargo build --release --locked -p impulse-zk-prover --features fixtures --bin impulse-zk-prove-terms)
cargo test --locked -p impulse-engine-tests --test v4_live -- --ignored --test-threads=1
cargo test --locked -p impulse-cli --features zk --lib -- --ignored a_v4_trade_end_to_end_with_real_receipts
```

Proving measurement: `circuits/scripts/measure-proving-terms.sh` (five runs on an idle machine, the method of spec 14.2) writes `docs/evidence/i21-proving-<date>/`.
