# Impulse v0.3 design: proof-carrying settlement (list-gated settle)

Draft, 11 October 2026, increment I20 (design step), revised the same day after the red team of section 21. Companion to `IMPULSE-SPEC.md` (the v0.1 design, authoritative for everything this file does not change), `ENCODING.md`, `TEMPLATE.md`, `TRANSACTIONS.md`, `VERIFY.md`, `IPST.md`, `ERRORS.md` and `V2.md`. This file is the authoritative I20 design once the owner accepts it; until then it is a draft and nothing on `release/v0.3` may contradict it without a spec change.

## 0. How to read this file

Every factual statement about the toolchain, the chain, a size or a cost carries one of three marks, as in `V2.md`:

- **(measured)**: observed in this session. "(measured, source)" means read from the pinned source code, with file and line named; it is not a run. "(measured, run)" means a command was run, and the command is named.
- **(modelled)**: computed from a formula and stated assumptions. An estimate for design choices, never a number to publish. Each one names the I20 test that replaces it with a measurement.
- **(asserted)**: taken from a document or a third party and not checked here.

Statements of the design (what the contract requires, what the builders refuse) carry no mark: they are the specification.

Paths in "(measured, source)" marks are relative to the pinned rusty-kaspa checkout `~/.cargo/git/checkouts/rusty-kaspa-410e06d1fde91a92/a41a333` unless they start with `silverscript/` (the pinned silverscript v1.0.0 tree at `~/silverscript-v1.0.0`) or `registry/` (`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f`).

Wording. This file calls the issuer's set of accepted delivery owners the **issuer list** and the feature the **list-gated settle**. User-facing text (README, CLI help and output, receipts) follows section 9.5. Earlier drafts and the I20 requirement say "whitelist"; no identifier, flag, error code or user text of v3 uses that word.

Owner decisions this design depends on are D58 to D66, D68 and D69, each with a default; this design follows the defaults (section 18). Of these, D58, D59, D61 and D68 need the owner's answer; the rest are design defaults recorded for the owner's information.

## 1. Scope

| Item | In I20 | Where |
| --- | --- | --- |
| Circuit 1: the buyer's delivery owner is a member of an issuer list committed to in the terms (Merkle membership over salted leaves), proved with a zero-knowledge receipt and verified on chain by the Kaspa ZK precompile | yes | sections 3 to 11 |
| Template v3 (`ImpulseVaultV3`): the v1 vault with three more state fields and a settle entry that verifies the proof; terms v3 | yes | sections 6, 7 |
| The list issuer's key in the terms, and a signed list manifest that `verify` checks | yes | sections 5.6, 7, 11 |
| Prover in its own cargo workspace under `circuits/`, proving on the owner's laptop, time and memory measured with method and raw data, with a go or no-go bound | yes | sections 5.5, 14 |
| Engine tests with valid and invalid proofs; the measured script units and masses | yes | section 13 |
| CI checks on user-facing v3 text: banned phrases and unmeasured figures | yes | section 9.5, 10 |
| SDK and demo page | no (D65): v3 is CLI only and needs a node whose mempool accepts its mass (section 10) | section 11 |
| Circuit 2: the trade matches a pair of signed ISO 20022 instruction hashes committed in the terms | deferred until circuit 1 is complete, reviewed, and seen by counsel (D68) | section 20 |

The I20 exit test is: invalid proof refused in the engine; proving time and script units recorded.

What I20 does not do. It does not hide the member (section 9 says exactly what an observer learns). It does not restrict what a member does with the token after delivery (section 19, finding 2). It does not check identity, eligibility or sanctions status, and it makes no statement that any list satisfies any legal or regulatory requirement. The issuer decides who is on its list; Impulse checks membership against the list's root and nothing else. Every user-facing v3 text carries the fixed disclaimer of section 9.5, and no public use of v3 on mainnet happens before counsel has reviewed that disclaimer (D68).

## 2. Versions 1 and 2 stay valid and byte-identical

- `contracts/impulse_vault.sil`, its artifacts and `contracts/TEMPLATE_HASH` do not change. Nor do template v2, the hashlock template, their hashes or any v1 or v2 vector.
- Terms v1 and v2, their codecs and their dispatcher are unchanged. Terms v3 have their own version byte (`0x03`), their own hash key (`Impulse/terms/v3`) and their own decoder (`impulse_core::zk::terms::decode`); the v1 decoder refuses them as `TERMS_UNSUPPORTED_VERSION`, which is existing behaviour for an unknown version. No existing code's meaning is widened to admit version 3: the v2 dispatcher is not taught version 3.
- A v3 vault script ends with another suffix than v1's or v2's, so the v1 decoder refuses it (`TEMPLATE_NOT_IMPULSE_VAULT`) and the v1 verifier refuses it (`VERIFY_TEMPLATE_MISMATCH`), as for any other script.
- Error codes: I20 adds one new family, `ZK_` (section 12). No existing code is renamed, reused, widened or renumbered.
- Design principles of `IMPULSE-SPEC.md` hold for v3, with one written exception to principle 2 (section 6.5). Principle 6 holds in the form `V2.md` section 15 gives it: template v3 has two entries, `settle` and `refund`.

## 3. Facts at the pinned revisions this design rests on

### 3.1 How a script invokes the precompile

- One opcode, `OpZkPrecompile`, byte `0xa6` (measured, source: `crypto/txscript/src/opcodes/mod.rs:891`). It is valid only when covenants are enabled; otherwise it is `InvalidOpcode` (lines 892 and 904 to 906).
- It pops one tag byte from the top of the stack (`parse_tag`, `crypto/txscript/src/zk_precompiles/mod.rs:20-27`: exactly one byte, else `ZkIntegrity` error), charges the tag's fixed cost in script units (`opcodes/mod.rs:897`), runs the tag's verifier (`zk_precompiles/mod.rs:33-39`) and, on success, pushes true (`opcodes/mod.rs:902`). Any verifier error is a script error, so a failed proof fails the input; there is no false result to test.
- Two tags exist (measured, source: `crypto/txscript/src/zk_precompiles/tags.rs:8-11, 13-21`): `0x20` Groth16 and `0x21` R0Succinct (RISC Zero succinct receipt). Any other byte is `UnknownTag`.
- Fixed costs (from source: `tags.rs:29-35`): Groth16 `Gram(140,000)`, R0Succinct `Gram(250,000)`, converted at `SCRIPT_UNITS_PER_GRAM = 100` (`consensus/core/src/mass/units.rs:6`; conversion at lines 146-150), that is 14,000,000 and 25,000,000 script units. The pinned tests assert that by compute mass a block holds 3 Groth16 and 2 R0Succinct verifications (`tags.rs:75-89`, against `MAINNET_PARAMS.block_mass_limits().after().compute`).
- A static upper bound, `get_zk_script_units_upper_bound`, reads the tag from the push before `OpZkPrecompile` and charges the maximum cost when it cannot (`crypto/txscript/src/lib.rs:364-405`). It feeds `estimate_script_units_upper_bound` (`lib.rs:350-362`), an estimator; consensus charges at run time (`opcodes/mod.rs:897`).
- The precompile is not a signature operation: the post-Toccata P2SH sig-op scanner counts the `OpCheckSig` and `OpCheckMultiSig` families only (measured, source: `crypto/txscript/src/lib.rs:284-290`).

### 3.2 Groth16 (tag 0x20)

- Curve BN254, verifier `ark-groth16` 0.6.0 (measured, source: `crypto/txscript/src/zk_precompiles/groth16/mod.rs:2-3`; versions pinned `=0.6.0` in the workspace `Cargo.toml:300-305`).
- Stack, top to bottom, after the tag (measured, source: `groth16/mod.rs:69-73`): verifying key (compressed bytes), proof (compressed bytes), public input count (i32), then that many public inputs, each 32 bytes.
- Each public input must be exactly 32 bytes and deserialize as a BN254 scalar (measured, source: `crypto/txscript/src/zk_precompiles/fields/mod.rs:22-31`, `deserialize_uncompressed`).
- The verifying key must have exactly count + 1 `gamma_abc` points (`groth16/mod.rs:41-44`), no trailing bytes (`56-58`); the proof must have no trailing bytes (`106-109`). A compressed G1 point is 32 bytes and a G2 point 64 bytes (`groth16/mod.rs:149-152`), so a compressed proof is 128 bytes.
- Extra cost: 250,000 script units per `gamma_abc` point, charged before the points are read (`groth16/mod.rs:18, 46-49`). With k public inputs a Groth16 verification therefore costs `14,000,000 + 250,000 * (k + 1)` script units (measured, source; the engine figure is measured by the I20 test of section 13.3).
- The verifying key is whatever the script pushes. A script that takes the key from the witness verifies nothing; the key must be a constant of the script (`crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs:197-199` says the same of its own fragment).

### 3.3 RISC Zero succinct (tag 0x21)

- Stack, top to bottom, after the tag (measured, source: `crypto/txscript/src/zk_precompiles/risc0/mod.rs:83-93`): hash function id, control id, image id, journal digest, seal, control inclusion digests, control index, claim. Only the Poseidon2 hash function is accepted (`risc0/mod.rs:100-104`). The claim is recomputed from the image id and journal digest with input, assumptions and exit code fixed to zero, `Halted(0)` and zero (`risc0/receipt_claim.rs:50-65`), so a receipt with assumptions does not verify.
- Seal size: the pinned test receipt's seal is 445,336 hex characters, 222,668 bytes (measured, run: `wc -c crypto/txscript/src/zk_precompiles/tests/data/succinct.seal.hex`). The whole succinct receipt of the zk-sdk tests is 446,340 hex characters (measured, run: `wc -c crypto/txscript/zk-sdk/tests/data/zk_builder_tests/succinct.rcpt.hex`).

### 3.4 RISC Zero receipts over Groth16 (the zk-sdk fragment)

- `kaspa-txscript-zk-sdk` at the pinned rev provides `append_r0_groth16_verifier_dynamic_image_id` (measured, source: `crypto/txscript/zk-sdk/src/zk_to_script/fragments/groth16.rs:126-204`). Given `[journal_hash, proof, image_id]` on the stack, it recomputes in script the RISC Zero `Output` digest and `ReceiptClaim` digest with `OpSHA256` and `OpCat` (lines 145-170), splits the claim digest and the RISC Zero control root into 16-byte halves zero-padded to 32 bytes (lines 172-189 and 12-20), and calls the Groth16 precompile with five public inputs, `a0, a1, c0, c1, id_bn254` (lines 192-201).
- The verifying key is RISC Zero's fixed Groth16 key, embedded as a 424-byte constant (line 56); the pinned test `verify_upstream_vk_roundtrip` ties it to `risc0_groth16::verifying_key()` (lines 240-258). The control root and `bn254_control_id` come from `Groth16ReceiptVerifierParameters::default()` of risc0-zkvm `=3.0.4` (line 127; versions at workspace `Cargo.toml:306-312`).
- Cost of one such verification: five public inputs, six `gamma_abc` points, so `14,000,000 + 6 * 250,000 = 15,500,000` script units, 155,000 grams of compute mass (measured, source: the arithmetic of section 3.2 applied to line 195; the engine figure comes from section 13.3).
- The journal enters only as its digest: the script must compute `journal_hash` itself from data it trusts. Whatever the guest commits is then bound by the claim digest, in full, because the claim digest is a public input; there is no unconstrained public input of the kind a hand-written Groth16 circuit can leave by mistake.

### 3.5 silverscript v1.0.0

- The builtin `r0.g16.verify(byte[32] journal_hash, byte[] proof, byte[32] image_id)` (measured, source: `silverscript/silverscript-lang/src/compiler/builtin_types.rs:188-192`) lowers to the zk-sdk fragment of section 3.4 followed by `OpDrop` of its true result (`silverscript/silverscript-lang/src/compiler/compile/expression/builtin.rs:304-312`). The compiler test `tests/compiler_tests.rs:10999-11029` (`r0_g16_verify_lowers_with_sdk_verifier_fragment`) pins the emitted bytes to the fragment, and the example `tests/examples/r0_g16.sil` verifies the pinned fixture receipt in the engine (`tests/examples_tests.rs:371-390`).
- It returns nothing, so it cannot sit inside `require`; it refuses by failing the script, as `readInputStateWithTemplate` does.
- `sha256(byte[])`, `+` on byte arrays, `.length` and `this.activeScriptPubKey` exist (asserted, `silverscript/docs/TUTORIAL.md` lines 741-743, 959-965, 734-738, 1094; the v3 contract step confirms each by compiling). `new ScriptPubKeyP2PK(pk)` is 36 bytes and `new ScriptPubKeyP2SH(hash)` 37 bytes, the scriptPubKey version as two bytes then the script (measured, source: `builtin_types.rs:119-120`).

### 3.6 The RISC Zero toolchain on this laptop

- `rzup show` lists cargo-risczero 3.0.5, cpp 2024.1.5, r0vm 3.0.5 and the RISC Zero Rust toolchain 1.91.1 (measured, run: `~/.risc0/bin/rzup show`). The precompile's verifier parameters come from risc0-zkvm 3.0.4 (section 3.4).
- The control IDs and control root are the same in risc0-circuit-recursion 4.0.4 and 4.0.5 (measured, run: `diff registry/risc0-circuit-recursion-4.0.4/src/control_id.rs registry/risc0-circuit-recursion-4.0.5/src/control_id.rs`, no output), and the sources of risc0-groth16 3.0.4 and 3.0.5 are identical (measured, run: `diff -r registry/risc0-groth16-3.0.4/src registry/risc0-groth16-3.0.5/src`, no output). A 3.0.5 prover is therefore expected to produce receipts the 3.0.4 parameters accept; I20 still pins the host crate to `=3.0.4` where r0vm allows it and tests acceptance in the engine (section 13.1).
- The Groth16 step ("shrink-wrap") of risc0-groth16 3.0.5 without the `cuda` feature runs the Docker image `risczero/risc0-groth16-prover:v2025-04-03.1`, referenced by tag (measured, source: `registry/risc0-groth16-3.0.5/src/prove/mod.rs:17-37`, `src/prove/docker.rs:36-57`). Docker client 29.6.1 is installed (measured, run: `docker info`, client section; whether the daemon runs and how the image performs on Apple silicon is not checked). That the image is built for x86-64 and runs on this laptop under emulation is asserted, not checked; section 14 measures it. Because the crate pulls by tag, I20 pins the digest itself (section 14.1).

## 4. Choice of proof system

**Decision (D58): Groth16, tag `0x20`, carrying a RISC Zero receipt (the zk-sdk fragment of section 3.4, through silverscript's `r0.g16.verify`).** The statement is an ordinary Rust guest program; the chain verifies a 128-byte Groth16 proof against RISC Zero's fixed verifying key and an image ID pinned by the template.

| Option | Proof bytes in the witness | Verification cost | Setup | Fits a v1 settle? |
| --- | --- | --- | --- | --- |
| R0Succinct (`0x21`), transparent | about 222,700 (section 3.3) | 25,000,000 units, 250,000 grams | none (transparent STARK) | No (below) |
| Groth16 (`0x20`), own circuit | 128 | 14,000,000 + 250,000 (k + 1) units | a circuit-specific phase-2 ceremony that I20 would have to run | Yes |
| Groth16 (`0x20`), RISC Zero receipt | 128 | 15,500,000 units, 155,000 grams | RISC Zero's Groth16 setup for its fixed STARK-to-SNARK circuit, plus the transparent STARK underneath | Yes |

Why not R0Succinct. With the seal alone at 222,668 bytes, the settle's compute mass would be at least 222,668 grams of size plus 250,000 grams of precompile cost, 472,668 grams, before the vault templates, the tokens and the other inputs (modelled, from sections 3.1 and 3.3 and the mass rule of `V2.md` section 3.1). That is above the per-transaction compute cap Impulse uses after Toccata (450,000, D37, carried to v3 by D63) and within 6 percent of the block's 500,000; transient mass would be at least 890,672 grams against a cap of 900,000. It also leaves under 28,000 bytes of the 250,000-byte signature-script limit for the vault itself. A succinct receipt does not fit a settle.

Why not an own Groth16 circuit. It would be cheaper to prove and slightly cheaper to verify, but it needs a phase-2 trusted setup for that circuit. Run by one party, that party could forge membership proofs; run as a public multi-party ceremony, it is an organisational project of its own. It also means a hand-written R1CS circuit (Merkle path, hash gadgets) to review. Kept as a fallback if RISC Zero's Groth16 step cannot run on hardware the owner controls (D61).

Trust assumption of the choice. Soundness rests on: (1) the RISC Zero zkVM and recursion circuits and their STARK, which are transparent (no setup); (2) RISC Zero's Groth16 setup for its STARK-to-SNARK circuit. RISC Zero states that this setup came from a public multi-party ceremony whose phase 1 is a public powers-of-tau and whose phase 2 is specific to its circuit, and that soundness holds if at least one participant in each phase destroyed its secret contribution (asserted, RISC Zero's published documentation; not checked here, and not reviewed by the owner). If every participant colluded, they could forge a receipt for any image ID and journal, so anyone holding the secret could settle a v3 vault for a buyer who is not on the list; the vault would then have been gated in name only. They could not redirect any output: every delivery and return require of v1 still holds (section 6.3).

What D59 accepts, exactly, and nothing more:

1. that the assumption above is unverified by Impulse and by the owner;
2. that it is accepted only for values at or below the D4 cap;
3. that `circuits/README.md` records the location of RISC Zero's ceremony transcript and the SHA-256 of the 424-byte verifying key the template embeds, and that the owner has seen both;
4. that any value above the D4 cap, and any public use, waits for the owner to revisit D59 after reviewing that transcript.

Every user-facing v3 text that mentions the proof check carries the setup line of section 9.5; no text calls the gate "cryptographically enforced", "trustless" or similar (section 9.5).

## 5. The statement (circuit 1): list membership

### 5.1 The list tree

- An issuer list is a list of Kaspa scriptPubKeys the issuer accepts as delivery owners: Schnorr P2PK (36 bytes in silverscript's form) or P2SH (37 bytes). Entries are given as addresses of the terms' network or as owner identifiers with their type; an ECDSA P2PK address, an address of another network or any other script is refused (`ZK_LIST_ENTRY`).
- Salt: `impulse zk list build` draws one 32-byte salt per entry from the operating system's random number generator. Salts are drawn afresh for every list version, so the same address in two lists, or in two versions of one list, has unrelated leaves. A salt is not a key and signs nothing; it is secret only in the sense that it hides its entry (section 9.2), and it is delivered to that entry's member in its path file.
- Leaf of entry `spk` with salt `s`: `LEAF(s, spk) = SHA-256("Impulse/zk/leaf/v1" || s || spk)`, the tag as its 18 ASCII bytes, `s` as 32 bytes, `spk` as the 36 or 37 bytes of section 3.5 (version `0x0000`, then the script). The leaf is computed in the guest only; the script never sees the salt or the leaf. (The unsalted leaf of the first draft was never implemented.)
- Empty leaf: 32 zero bytes. Node: `NODE(l, r) = SHA-256(0x01 || l || r)`. A leaf preimage starts with `I` (`0x49`) and is 86 or 87 bytes; a node preimage starts with `0x01` and is 65 bytes, so the two never collide by form.
- Depth: fixed at 20, so a tree holds up to 1,048,576 entries and every path has 20 siblings, whatever the list's size. Entry i of the list (0-based, the order the issuer chooses) is leaf i; positions from the list's length to 2^20 - 1 are empty.
- Root of the empty tree at depth 20: `51c20d66008024c04cf114564a998e49ef8f6e044e2d13a03a66521d6e200503` (measured, run: Python `hashlib` with the rules above). Terms whose root is this value or all zero are refused (`ZK_ROOT_INVALID`): nobody could settle them.
- Hash choice: SHA-256 because RISC Zero accelerates SHA-256 in the guest (asserted, RISC Zero documentation; the guest's cycle count is measured in section 14) and the script already uses it for the journal.

### 5.2 The journal

The guest commits exactly these bytes with `env::commit_slice`, 121 bytes for a P2PK owner and 122 for a P2SH owner, and the script recomputes them:

```
J = "Impulse/zk/wl/v1"        16 bytes, ASCII
  || list_root                32 bytes, from the vault state
  || vault_spk                37 bytes, the asset vault's own scriptPubKey (P2SH form)
  || owner_spk                36 or 37 bytes, the buyer delivery owner's scriptPubKey
journal_hash = SHA-256(J)
```

`owner_spk` is last and the only field of variable length, so J parses one way. That the RISC Zero journal digest is SHA-256 of the committed bytes is asserted (RISC Zero documentation); the I20 vector of section 13.4 measures it against a real receipt before the template freezes.

### 5.3 Public inputs bound to the transaction

| Bound value | How the script obtains it | Why |
| --- | --- | --- |
| list root | the vault state (`listRoot`) | the list the terms name |
| delivery owner | built in script from the state fields `buyerDeliveryType` and `buyerDeliveryId` (the owner that `validateOutputStateWithInputTemplate` already pins in output 0) | the proof speaks about the owner who receives the asset in this transaction |
| this vault | `this.activeScriptPubKey` of the asset vault, 37 bytes | binds the proof to one vault address, and through it to every terms field, the network byte, the nonce, trade_ref, the issuer key and the leg index (`TEMPLATE.md`: the address commits to the whole state) |
| the program | `IMAGE_ID`, a constant of template v3 | only the list guest's receipts verify |

The terms hash itself is not a public input: the script cannot compute it (it is keyed BLAKE2b over the canonical terms, which the vault holds as state fields, not as the canonical bytes). The vault scriptPubKey is the in-script equivalent: it is a hash of the template and the state, and the state is injective in the terms (`TEMPLATE.md`), so two vaults with different terms or legs have different scriptPubKeys unless BLAKE2b-256 collides.

The delivery output's own scriptPubKey is not hashed into the journal: output 0 is a KCC-20 token output whose P2SH hash covers the token template and its state; the v1 builtin `validateOutputStateWithInputTemplate` already fixes that state to exactly (buyer delivery owner, amount_a, not a minter), and the journal fixes the owner through `owner_spk`.

Nullifier: none. A nullifier serves one-time anonymous membership against a global spent set. Here the member is public (section 9); the settle spends the vault UTXO, so it settles once; Kaspa script has no global set to record nullifiers in; and a vault-bound journal already stops the use of one proof at another vault (section 8).

### 5.4 The guest program

Private input: `index` (u32), `salt` (32 bytes), `siblings` (exactly 20 hashes of 32 bytes). Public input, committed: `root`, `vault_spk`, `owner_spk`. The guest:

1. refuses unless `siblings` has 20 entries, `index < 2^20`, `vault_spk` is 37 bytes of the form `0x0000 0xaa 0x20 <32 bytes> 0x87`, and `owner_spk` is either 36 bytes of the form `0x0000 0x20 <32 bytes> 0xac` or 37 bytes of the P2SH form;
2. computes `leaf = LEAF(salt, owner_spk)` and refuses if it is 32 zero bytes (a guard: the empty leaf is not a member, and a guest that accepted a supplied leaf would let any empty position prove membership);
3. computes the root from `leaf` up: at level k, if bit k of `index` is 0 the current hash is the left child, else the right;
4. refuses unless the computed root equals `root`;
5. commits `J` of section 5.2 and nothing else.

A refusal is a guest panic, so no receipt exists.

### 5.5 Where it lives

`circuits/` is a cargo workspace of its own, excluded from the root workspace (D60), because the guest builds with the RISC Zero toolchain (Rust 1.91.1) and the host needs risc0-zkvm with proving, neither of which belongs in the root workspace (Rust 1.94.0, rule 3). Its parts:

- `circuits/list-core/`: `no_std` crate with the salt, leaf, node, root and path rules of section 5.1, used by the guest and the host;
- `circuits/list-guest/`: the guest of section 5.4;
- `circuits/prover/`: the host binary `impulse-zk-prove`, which reads a path file and the public values, proves locally (succinct, then Groth16 through the pinned Docker image, section 14.1), checks the receipt against the expected journal, and writes a proof file (128-byte compressed proof, journal, image ID, risc0 versions). It never contacts a remote proving service;
- `circuits/IMAGE_ID`: the guest's image ID from the reproducible build (`cargo risczero build`, which builds in Docker; that its output is reproducible across machines is asserted, RISC Zero documentation, and checked by `scripts/build-guest.sh`, which rebuilds and compares);
- `circuits/GROTH16_PROVER_IMAGE`: the pinned Docker image digest and its provenance (section 14.1).

`impulse_core::zk` (cargo feature `zk`, off by default) reimplements the section 5.1 rules for the CLI, and `tests/vectors/zk/` pins both implementations to the same bytes.

### 5.6 The list issuer and the list manifest

A root on its own says nothing about who curated the list: a seller could supply a root over its own or invented addresses. Terms v3 therefore name a **list issuer key** (`list_issuer_key`, a 32-byte BIP-340 x-only key), and the issuer publishes a **list manifest** signed with that key:

```
M = 0x01                          manifest version, 1 byte
  || network                      1 byte, as the terms' network byte
  || list_id_len || list_id       1 byte, then 1 to 64 bytes of UTF-8 chosen by the issuer
  || list_version                 u32, big-endian
  || issued_at                    u64, big-endian, Unix seconds
  || list_root                    32 bytes
manifest_digest = BLAKE2b-256(key = "Impulse/zk/manifest/v1", message = M)
signature       = BIP-340 Schnorr signature of manifest_digest by list_issuer_key
```

Known answers of the keyed hash (measured, run: Python `hashlib.blake2b(m, key=b"Impulse/zk/manifest/v1", digest_size=32)`): empty message `6783cd7f7b56d97a8ecf7289e3835aac964a7be48fc668510f50bd763fbf39e6`, `abc` `41d7a32ff0778cd5986d942dc77220548918a6ef1aa0c1d5556afa353426224c`.

- `impulse zk list manifest` writes M and its digest. The issuer signs the digest with its own signer; no Impulse component holds, reads or receives the issuer's key (rule 1). `impulse zk list manifest --signature <hex>` attaches the signature and checks it.
- The contract does not check the manifest: the issuer key is in the terms (and so in the vault address), the manifest binds the root to that key, and only a person who knows the issuer's published key out of band can decide that the key is the issuer's. On chain verification would add no assurance that `verify` lacks.
- `impulse zk verify` prints the issuer key and one of: "list manifest: signed by the list issuer key, list `<id>` version `<n>`, issued `<date>`"; "list manifest: none supplied, nothing ties this root to the issuer key" (warning); or refuses a manifest whose root, network or signature does not match (`ZK_MANIFEST_INVALID`). It warns when the issuer key equals the seller key ("the seller curates this list").
- Rotation and revocation are out of scope. A new list version is a new root and a new manifest; terms made under an old root keep it until they settle or expire. The issuer can stop a settle only as the trade's authority (section 7.3). `terms new` and `verify` print this guidance: "A list cannot be revoked inside these terms. Keep the refund expiry short, and name the list issuer as authority if removals must stop a settle."

## 6. Template v3

### 6.1 Files and hash

- Source `contracts/impulse_vault_v3.sil`, contract `ImpulseVaultV3`; artifacts `contracts/compiled/impulse_vault.v3.json` and `.v3.ctor.json`; pin `contracts/TEMPLATE_HASH_V3`; `scripts/build-template-v3.sh` compiles with the pinned silverc and checks, as `build-template.sh` does for v1.
- `IMAGE_ID` is a `byte[32]` constant of the template, equal to `circuits/IMAGE_ID`; the build script refuses a mismatch. A new guest is a new template with a new hash (D66).
- The files above add the requires of section 6.6 and `[S10]` (section 6.3). A proof is bound to the asset vault's scriptPubKey, so a proof made for a vault of another template does not verify at this vault: the committed proof fixtures are made for this template (`circuits/scripts/regen-fixtures.sh`, `scripts/regen-zk-core-fixtures.sh`).
- Freeze: template v3 is frozen when the engine suite of section 13 is green, the measurements of sections 13.3 and 14 are committed and pass the go or no-go bound of section 14.2, `scripts/build-guest.sh` reproduces `IMAGE_ID`, and the owner has accepted this file. No v3 vault is funded on mainnet before the freeze.
- Size: v1 is 2,938 bytes with the placeholder state (`V2.md` section 3.2). v3 adds the 424-byte key, about 270 bytes of fragment constants and pushes, the image ID, the two tags, two state fields and the journal code, about 3,900 bytes in all (modelled; the contract step records the measured size in the I20 Report).

### 6.2 State

The v1 state (`TEMPLATE.md`), with `version = 3` and two fields inserted after `fundingMode`:

| # | Field | Type | Value |
| --- | --- | --- | --- |
| 1 to 32 | as v1, `version` first | as v1 | as v1, `version` 3 |
| 33 | listIssuerKey | byte[32] | list_issuer_key |
| 34 | listRoot | byte[32] | list_root |
| 35 | tradeRef | byte[32] | trade_ref |
| 36 | legIndex | int | 0 asset vault, 1 cash vault |

The state stays injective in the terms, so the address commits to every term including the issuer key and the root (principle 1). `listIssuerKey` is state only; no require reads it.

### 6.3 Entry `settle(sig authSig, byte[] proof)`

Every v1 require runs unchanged and in the same order (`ERRORS.md`, `### settle`: `[F4]`, `[S1]`, `[S7]`, `[S10]`, `[F1]`, `[F2]`, `[E1]` to `[E6]`, `[S8]`, `[S9]`, `[S2]`, `[S3]`, `[D1]`, `[D2]`, the delivery builtin, `[S4]`, `[S5]`), then the proof gate, then `[S6]`. `[S10]` is v1's (`TEMPLATE.md`, "The other leg's vault"): where the other leg has a vault, the input at its canonical index runs this template with this trade's terms, rebuilt from this vault's own redeem script with `legIndex` replaced (here `STATE_FIXED` 574 and `SUFFIX_LEN` 4,356). So a template v3 cash vault settles only beside the template v3 asset vault of its own terms, which runs the gate (section 6.5):

```
if (legIndex == ASSET_LEG) {
    require(buyerDeliveryType == PUBKEY || buyerDeliveryType == SCRIPT_HASH); // [Z1]
    byte[] ownerSpk = (the 36-byte P2PK of buyerDeliveryId for PUBKEY, else the 37-byte P2SH);
    byte[32] journalHash = sha256(JOURNAL_TAG + listRoot + this.activeScriptPubKey + ownerSpk);
    r0.g16.verify(journalHash, proof, IMAGE_ID);
} else {
    require(proof.length == 0); // [Z2]
}
```

| Tag | Require | Purpose |
| --- | --- | --- |
| `[Z1]` | asset vault: the buyer delivery owner is of type PUBKEY or SCRIPT_HASH | A COVENANT_ID owner has no scriptPubKey to be a leaf; terms v3 refuse it (`ZK_DELIVERY_OWNER_TYPE`), and the script refuses it again for terms made without impulse-core |
| (builtin) | asset vault: `r0.g16.verify(SHA-256(J), proof, IMAGE_ID)` | The settle carries a valid receipt of the list guest for this root, this vault and this delivery owner |
| `[Z2]` | cash vault: `proof` is empty | The cash vault carries no proof; nothing unchecked rides in its witness |

The gate runs after the cheap checks, so a malformed settle fails before the 15.5 million units of the verification. Tags are scoped to template v3: v3's `[S1]` is not v1's `[S1]`, though its text is the same.

### 6.4 Entry `refund(sig s, pubkey signer)`

Unchanged from v1, `[R1]` to `[R14]`, and `[F5]` and `[F3]` (section 6.6). A refund needs no proof: it only sends each leg home.

### 6.6 Inputs outside the layout

The requires of template v1, unchanged (`TEMPLATE.md`, "Inputs outside the layout"): `settle` `[F4]` (at most 12 inputs), `[F1]` (every input but this vault carries no covenant, the asset covenant or, for KCC-20 cash, the cash covenant) and `[F2]` (the other leg's covenant has exactly one input); `refund` `[F5]` and `[F3]`. In `settle` they run after `[S7]` and before the escrow checks, so before the proof gate: a spend that carries a token of another covenant is refused without the verification's 15.5 million units. With `[S10]` (section 6.3) they close known limitation L20 for template v3 with no remaining case: a token of a leg's own covenant at the other leg's vault cannot stand in for that leg's escrow, because the other vault is required beside this one. Engine tests of `[S10]`: `tests/engine/foreign_covenant_residual.rs` against the probe (`v3p_sibling.rs`) and `v3_settle.rs` (`v3_s10_*`) on the shipped template with the committed proofs. Engine tests: the suite `tests/engine/foreign_covenant.rs` against the probe (`v3p_foreign_covenant.rs`), and on the shipped template with the committed proofs (`v3_foreign_covenant.rs`).

Template v4 (section 22) checks the covenant ID of every input in its own script (22.15).

### 6.5 Written exception to principle 2

Principle 2 says both vaults check both delivery outputs. In v3 they still do. The proof is checked only by the asset vault, because the gate is a condition on releasing the asset and the asset vault is the only script that can release it: the escrowed asset is owned by the asset vault's script hash (`[E4]`), so KCC-20 moves it only in a transaction where the asset vault is an input, and both of the asset vault's entries then run; `refund` only sends it home. Verifying in both vaults would double the cost (310,000 grams) and prove nothing more. Recorded as D64.

What binds the cash side (I26). Before `[S10]` a buyer's v3 cash vault settled beside any asset vault with the same deliveries, a v1 vault for one, with no proof: the gate bound only a seller who chose to use it. `[S10]` makes the cash vault require, at input 0, the template v3 asset vault of its own terms, rebuilt from the cash vault's own script; that vault's `settle` runs the gate, and its `refund` cannot run beside a settle of the cash vault (`TEMPLATE.md`, "The other leg's vault"). So a v3 cash vault settles only in a transaction that carries a valid proof for its trade. The asset vault still verifies alone; the cash vault verifies nothing itself. What the buyer must still check: that the cash vault it funds is the template v3 vault of the terms it agreed, since a cash vault of another template is bound to that template's asset vault instead. Hence the fixed gate line of section 9.5 in the README, `zk --help`, `zk` command output and the runbook; `impulse zk verify` requires BOTH vault addresses and refuses unless each is the v3 vault of the stated terms for its leg (`ZK_VERIFY_ADDRESS_MISMATCH`), and the buyer runs it before funding cash; and the engine test `v3_settle::v3_s10_v3_cash_vault_refuses_a_v1_asset_vault`, which records the refusal.

## 7. Terms v3

### 7.1 Hash

```
terms_hash_v3 = BLAKE2b-256(key = "Impulse/terms/v3", message = canonical bytes)
```

Keyed BLAKE2b exactly as v1, the key the 16 ASCII bytes of the tag. Known answers (measured, run: Python `hashlib.blake2b(m, key=b"Impulse/terms/v3", digest_size=32)`):

| Message | terms_hash_v3 |
| --- | --- |
| empty | `175c483831717b966ff22e32bf1821b41ecb33c235c30b5c97ef3071a4c3a078` |
| `abc` | `033b06c4d13408373d9ea699b075c6d0621ba1f6740446026d920571c79b3e33` |

### 7.2 Layout

The v1 layout (`ENCODING.md`, "Layout") with the version byte `0x03` and two fields inserted after `funding_mode`, so `trade_ref` stays last:

| # | Field | Encoding | Bytes |
| --- | --- | --- | --- |
| 1 | version | u8, `0x03` | 1 |
| 2 to 16 | as v1 fields 2 to 16 | as v1 | as v1 |
| 17 | list_issuer_key | 32-byte x-only Schnorr public key | 32 |
| 18 | list_root | 32 bytes, the root of section 5.1 | 32 |
| 19 | trade_ref | 32 bytes | 32 |

Decoding refuses a version byte other than `0x03` first (`ZK_TERMS_VERSION`), then applies v1's decoding refusals with their v1 codes (`TERMS_TRUNCATED`, `TERMS_INVALID_TAG`, `TERMS_INVALID_PRESENCE`, `TERMS_UNKNOWN_SETTLEMENT_MODE`, `TERMS_FIELD_TOO_LONG`, `TERMS_TRAILING_BYTES`), whose meanings apply unchanged. `decode(encode(t)) = t` and `encode(decode(b)) = b`.

### 7.3 Validation

Structure checks, first failure returned: version 3 (`ZK_TERMS_VERSION`); settlement_mode is Vault (`ZK_TERMS_DIRECT`: Direct has no contract to carry the gate); then v1's structure checks 2 to 10 in v1's order with v1's codes; then buyer_delivery's owner type is PUBKEY or SCRIPT_HASH (`ZK_DELIVERY_OWNER_TYPE`); then list_issuer_key is a valid BIP-340 x-only key (`ZK_ISSUER_KEY`); then list_root is neither all zero nor the empty-tree root (`ZK_ROOT_INVALID`). The issuer key may equal a party's or the authority's key (an issuer may sell its own token); `verify` reports it (section 5.6). Creation checks are v1's. `TermsV3::validate_structure` is the only way to obtain `ValidatedTermsV3`.

Authority by default. The codec accepts terms v3 without an authority, so vectors and other tools may make them. `impulse zk terms new` refuses to make them unless `--no-authority` is given (`ZK_AUTHORITY_ABSENT`); its help names the list issuer as the usual authority, because the authority's `[S6]` signature is the only way to stop a settle for an owner removed from the list after the terms were made. `impulse zk verify` prints a warning when the terms have no authority: "No authority: removal from the list after these terms were made cannot stop the settle."

### 7.4 Vectors

`tests/vectors/terms_v3/` (v1's JSON form plus `list_issuer_key` and `list_root`) and `tests/vectors/vaults_v3/` (each vector's two vault scripts, script hashes and addresses). At least: KAS cash, KCC-20 cash, external cash with authority, authority present and absent, both networks, both funding modes, both delivery owner types, issuer key equal to the seller key and distinct from every party. Checked by `scripts/vectors.sh` from this file alone, in Python.

## 8. Replay

- Another vault. The journal contains the asset vault's scriptPubKey. A receipt made for vault A verifies at vault B only if their scriptPubKeys are equal, that is, only if they have the same template and state (the same terms and leg) or BLAKE2b-256 collides. Different terms, another network, another nonce or trade_ref, another issuer key, or the cash vault of the same trade all change it.
- The same vault twice. The settle spends the vault UTXO; it cannot settle again. A second UTXO at the same address (a second deposit, or an authorizer refunded on its own and funded again) has the same scriptPubKey, so the same receipt is valid for it. That is accepted: the statement (this owner is on this list, for these terms) is equally true for it, and every other require still applies.
- Another statement. The image ID is a template constant, so a receipt of any other program fails, including one that commits the same J without checking a path (the "forging guest" test of section 13.2).
- Another list or owner. Root and owner scriptPubKey are in the journal, so a member's receipt does not verify for another owner or another root; a P2PK and a P2SH owner over the same 32 bytes differ in `owner_spk`.
- Proof malleability. Groth16 proofs can be re-randomised into other valid proofs of the same statement (asserted, a property of Groth16). Nothing here depends on a proof being unique.

## 9. What is and is not hidden

### 9.1 What an observer of the chain learns

From a v3 settle:

- the list root and the issuer key (the vault state is revealed in the signature script when the vault is spent; before that the P2SH address reveals nothing, as in v1);
- the buyer delivery owner, in the clear: it is in the vault state and in output 0's token state, as in v1. **The member is not hidden.** Hiding it would need a token whose owner is not public, which KCC-20 is not;
- that this owner is in the tree with that root, according to a receipt of the program with this image ID;
- that the vault uses template v3 (its suffix and hash), and the 128-byte proof.

What the observer does not learn, provided the receipt is zero knowledge with respect to the guest's private input (asserted, RISC Zero documentation for its zkVM receipts and the zero-knowledge property of Groth16; not checked here): the other entries of the list, the member's salt, its position and the sibling hashes. The receipt does not reveal the list's size beyond the bound of 1,048,576.

Linkability: every trade under one root is visibly under one list, so an observer can group an issuer's trades by root and by issuer key; a delivery owner used in several trades links them, as in v1.

### 9.2 Against address enumeration

A leaf is a hash of a public scriptPubKey. Without the salt, anyone holding a leaf or a path could hash every address seen on chain and find which ones are on the list, and leaves of the same address in two lists would match. With the per-entry salt of section 5.1:

- a leaked sibling or leaf cannot be tested against addresses without that entry's salt;
- the same address in two lists, or two versions of one list, has unrelated leaves;
- a member's path file reveals, besides its own salt and siblings, which of its sibling subtrees are empty (an empty subtree's root is a known constant), so a member learns roughly how many entries the list has, and nothing about who they are;
- the list is not secret from the issuer or from anyone the issuer gives the list file or the salts to. A leaked salt together with its entry's address confirms that entry, nothing more; a leaked path file also lets its holder prove membership for that member, which only ever delivers to that member's own owner.

### 9.3 What the issuer learns and controls

- Whoever makes the proof needs the member's path file. The issuer, or whoever holds the list, therefore can learn which owner is about to prove if it is asked for a path at trade time, and the vault address if it makes the proof itself.
- The issuer is a liveness dependency: only it holds the paths, so it can withhold one and stall a settle until the refund expiry. Refunds are unaffected. Mitigations, all required of the CLI and runbook text: the issuer delivers each member's path file at onboarding, before any trade, so that neither the trade nor the vault is disclosed by asking for it; `impulse zk verify --path <file>` checks that the path leads from the buyer delivery owner to the terms' root and warns when no path file is supplied ("No path file: the buyer cannot settle without the list issuer's path for this owner."); `terms new` advises sizing the refund expiry to the issuer's committed response time.

### 9.4 Cost of hiding the path

The same membership checked as a plain SHA-256 Merkle path in script would cost on the order of 20 hashes of 65 bytes, about 1,300 script units (modelled), against 15,500,000 units here, but it would reveal the 20 siblings and the position. The ZK gate exists to keep the list's other entries off the chain, not to hide the member.

### 9.5 User-facing wording (normative)

Scope: the README's v3 section, between the markers `<!-- impulse-v3 -->` and `<!-- /impulse-v3 -->`; the output of `impulse zk --help` and of `--help` for every `impulse zk` subcommand; the output of every `impulse zk` command, receipts included; and any `docs/ZK-*.md`. `spec/` is not in scope: a specification must be able to name what it rules out.

Permitted names: "list-gated settle", "issuer list", "allowlist", "membership in a list the issuer chose", "proof of list membership".

Fixed texts, reproduced exactly and each on its own line:

- Disclaimer, in the README v3 section, in `impulse zk --help`, at the top of `impulse zk verify` output and in every v3 receipt: "Impulse checks that the buyer's delivery owner is in a list the issuer chose. It does not check identity, eligibility, sanctions status or onward transfers. The delivery owner is public on chain."
- Setup line, wherever the proof check is described and in `impulse zk verify` output: "The proof check relies on RISC Zero's Groth16 setup, a third-party setup Impulse has not verified."
- Gate line, in the README v3 section, in `impulse zk --help`, in `impulse zk verify` output and in the other `impulse zk` commands that print the terms: "Only the asset vault checks the proof. The cash vault settles only beside the asset vault of the same terms, so verify both vault addresses before funding cash."
- Cap line, in the README v3 section: "Template v3 and the list prover are for values at or below the 10 KAS cap. Above it the tools refuse unless --i-accept-the-risk is passed."

Banned in scope, case-insensitive, outside the fixed texts: `private` (except in the phrase "private key"), `anonymous`, `anonymity`, `hidden member`, `hides the member`, `confidential`, `compliant`, `compliance`, `KYC`, `AML`, `sanction`, `whitelist`, `trustless`, `cryptographically enforced`, `verified identity`.

Enforcement: `scripts/check-zk-text.sh`, called from `scripts/ci-local.sh` after the v3 build step. It builds the CLI with the `zk` feature, collects the in-scope text (README section, help output, the output of each `impulse zk` command run on the `tests/vectors/` fixtures, `docs/ZK-*.md`), removes lines equal to a fixed text, and fails on any banned phrase, on a missing fixed text, and on an unsourced figure (section 10). Its own self-test feeds it one sample of each banned phrase and one missing fixed text and expects a failure for each. The fixed texts are drafts for counsel's review (D68); a change after that review changes them here first.

## 10. Transactions, budgets and mass

- Shapes: v1's settle and refund layouts, unchanged (`TRANSACTIONS.md`); the asset vault's signature script gains the proof (128 bytes plus its push) and the cash vault's an empty push.
- Budget: the asset vault's settle budget is v1's rule plus the verification and the hashing: `units(settle, asset vault) = units_v1 + 15,500,000 + h`, where h is the journal hash and the fragment's own SHA-256 work (a few hundred units, modelled). I20 measures it in the engine (section 13.3) and the builder budgets from the measured rule with the fixture floor plus margin, as v1. That is about 1,560 budget units against a u16 field (modelled).
- Mass, KAS-cash settle, fixture tokens (modelled from v1's measured 15,166 grams compute and 33,664 transient, `TRANSACTIONS.md`): compute about 172,000 grams (155,000 of it the verification, the rest v1's size and units plus about 2,100 bytes of extra template and proof), transient about 42,000. That is above v1's 100,000-gram standard cap. v3 uses the per-dimension caps of `V2.md` D37 (compute 450,000, storage 450,000, transient 900,000; D63), refused above as `ZK_TX_MASS`. Toccata is active on mainnet (asserted, the Kii data room `CANONICAL_MEMORY_NOTE.md`, with an activation DAA score this design does not check; the pinned mempool policy was read in source, `docs/evidence/i20-mempool-mass-2026-10-13/findings.txt`: the 100,000-gram standard cap lives in `mining/src/mempool/check_transaction_standard.rs` and is lifted from 30 minutes before the Toccata activation, leaving the block-fit limits; whether a given public node runs that policy is checked only by the owner run's two-node submission), after which the mempool's per-transaction ceiling is the block limit (`V2.md` section 3.1). A wallet or node that still applies the pre-Toccata 100,000 cap will not relay a v3 settle; the CLI says so when it builds one, in words and without figures: "This settle is heavier than older wallets and nodes accept. Submit it to a node whose mempool accepts post-Toccata mass."
- Fee: at the post-Toccata minimum relay rate of 100 sompi per gram of fee mass (`TRANSACTIONS.md`, "Fee"), about 17,200,000 sompi, 0.172 KAS (modelled).
- Capacity: the pinned tests assert that by compute mass a block holds three Groth16 verifications (measured, source: `tags.rs:82-84`). This is a bound from those tests, not a throughput figure.

Figures in user text. The modelled and asserted figures of this file (masses, fees, the activation score, units, capacity, proving times) do not appear in README, CLI output or receipts. Once `docs/measurements/v3-zk-units.txt` and a `docs/evidence/i20-proving-<date>/results.txt` exist, user text may quote figures from them, with the file named. `scripts/check-zk-text.sh` enforces it: every number of four or more characters (digits, commas and points) in the in-scope text must occur in one of those files or in the script's list of design constants (the depth 20 bound of 1,048,576 entries, the 128-byte proof, the 32-byte salt); until the files exist, the in-scope text holds no such number outside the design constants.

## 11. Off-chain components

- `impulse_core::zk` (feature `zk`): terms v3 codec and checks, template v3 instantiation and decode, the list tree (salts, build, root, path, `ZK_NOT_MEMBER`, `ZK_PATH_INVALID`), the manifest (section 5.6), the journal, and the v3 builders. The settle builder takes a proof file, checks it is 128 bytes and parses (`ZK_PROOF_MALFORMED`), then runs the asset vault's settle script with that proof in the pinned engine before returning anything (`ZK_PROOF_INVALID`), so a builder never returns a settle the chain would refuse for its proof. Masses as section 10.
- Partially signed form: IPST version 4 (`"ipst": 4`; 2 is terms v2 and 3 the hashlock document of D52), `IPST.md`'s layout with terms v3 bytes and one more key, `zk_proof`, the proof as hex. A v1 reader refuses it as `IPST_UNSUPPORTED_VERSION`; a v3 reader given another version refuses with `ZK_IPST_VERSION`.
- Verify: v3 address checks mirror `VERIFY.md` (`ZK_VERIFY_ADDRESS_MISMATCH`, `ZK_VERIFY_TEMPLATE_MISMATCH`). Output, in order: the disclaimer and the setup line (section 9.5); the root, the issuer key and the manifest status (section 5.6); the delivery owner, stated to be public on chain; the path check or its warning (section 9.3); the authority or its warning (section 7.3); the revocation guidance (section 5.6).
- CLI (`impulse zk ...`, `crates/impulse-cli/src/zk_cmd.rs`, built with the `zk` feature): `list build` (list file in; one salt per entry; root and one path file per entry out, each holding index, salt and siblings; the list and the salts never leave the issuer's machine except in each member's own path file, and are never printed), `list manifest` (section 5.6), `terms new` (v1's flags plus `--list-issuer-key`, `--list-root` and `--no-authority`), `address`, `verify` (`--manifest`, `--path`), `fund build`, `settle build --proof <file>`, `refund build`, and the v1 signing and submit commands. Proving is `impulse-zk-prove` from `circuits/`. The SDK and demo page gain nothing in I20 (D65): v3 is CLI only.
- Every receipt and message names its finality state as `V2.md` section 4.8 requires.

## 12. Error codes

A new family, appended to `ERRORS.md` by the I20 core step in the same commit as the code and its frozen list (`impulse_core::zk::ZK_ERROR_CODES`), with `tests/parity/gen_parity.py`'s `FAMILIES` and the parity tests gaining `ZK`. Families row: `ZK_` | proof-carrying settlement: terms v3, template v3, issuer lists, manifests, proofs, v3 builders and verifier (`impulse_core::zk`, cargo feature `zk`), and the `impulse zk` commands | `V3-ZK.md` | I20.

| # | Code | Raised by | Meaning |
| --- | --- | --- | --- |
| 1 | `ZK_TERMS_VERSION` | decode v3, structure v3 | The terms v3 decoder was given a version byte other than 3 |
| 2 | `ZK_TERMS_DIRECT` | structure v3 | Terms v3 name Direct settlement |
| 3 | `ZK_DELIVERY_OWNER_TYPE` | structure v3 | The buyer delivery owner is not of type PUBKEY or SCRIPT_HASH |
| 4 | `ZK_ROOT_INVALID` | structure v3 | list_root is all zero or the root of the empty tree |
| 5 | `ZK_ARTIFACT_INVALID` | v3 startup check | The embedded v3 artifact, `TEMPLATE_HASH_V3` or `IMAGE_ID` cannot be used |
| 6 | `ZK_TEMPLATE_HASH_MISMATCH` | v3 startup check | The v3 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V3` |
| 7 | `ZK_IMAGE_ID_MISMATCH` | v3 startup check, prove | The image ID in template v3 differs from `circuits/IMAGE_ID` or from the prover's guest |
| 8 | `ZK_NOT_V3_VAULT` | decode v3 | The script does not run template v3 |
| 9 | `ZK_STATE_MALFORMED` | decode v3 | The state does not parse as the v3 state |
| 10 | `ZK_STATE_INVALID` | decode v3 | A v3 state field holds a value no terms v3 value encodes to |
| 11 | `ZK_NONCANONICAL` | decode v3 | The script is not the v3 instantiation of the terms it decodes to |
| 12 | `ZK_LIST_ENTRY` | list build | An entry is not a Schnorr P2PK or P2SH address or owner of the terms' network |
| 13 | `ZK_LIST_SIZE` | list build | The list is empty or has more than 1,048,576 entries |
| 14 | `ZK_NOT_MEMBER` | list path | The delivery owner is not in the list |
| 15 | `ZK_PATH_INVALID` | prove, settle build, verify | The path file is malformed or does not lead from the owner's salted leaf to list_root |
| 16 | `ZK_PROOF_MALFORMED` | settle build, IPST read | The proof is not 128 bytes or does not parse as a compressed Groth16 proof |
| 17 | `ZK_PROOF_INVALID` | settle build | The proof does not verify for this vault's journal in the pinned engine |
| 18 | `ZK_PROVER` | prove | No receipt was produced: r0vm or the Groth16 step is missing or of another version, or the guest refused |
| 19 | `ZK_TX_MASS` | v3 builders | The compute, storage or transient mass exceeds its v3 cap (section 10) |
| 20 | `ZK_IPST_VERSION` | v3 IPST read | `ipst` is not 4 |
| 21 | `ZK_VERIFY_ADDRESS_MISMATCH` | v3 addresses | The offered address pays neither vault of these v3 terms |
| 22 | `ZK_VERIFY_TEMPLATE_MISMATCH` | v3 revealed script | The revealed script does not run the pinned template v3 |
| 23 | `ZK_ISSUER_KEY` | structure v3 | list_issuer_key is not a valid BIP-340 x-only public key |
| 24 | `ZK_AUTHORITY_ABSENT` | `impulse zk terms new` | Terms v3 without an authority were requested without `--no-authority` |
| 25 | `ZK_MANIFEST_INVALID` | list manifest, verify | The manifest is malformed, names another root or network, or its signature does not verify under list_issuer_key |
| 26 | `ZK_PROVER_IMAGE` | prove | The local Groth16 prover image's digest differs from `circuits/GROTH16_PROVER_IMAGE` |

The v3 terms also return the v1 `TERMS_` codes whose meaning applies unchanged (sections 7.2, 7.3), and the v3 builders the v1 `TX_` codes, with `ZK_TX_MASS` in place of `TX_MASS`.

On-chain refusals: `ERRORS.md` gains `## On-chain refusals, template v3` at the end of the file (after any v2 or hashlock section), with `### Template v3: settle` (v1's settle rows, then `[Z1]` and `[Z2]`) and `### Template v3: refund` (v1's refund rows), and the builtin list gains `r0.g16.verify`. The headings keep the existing parity test, which reads `### settle` and `### refund`, unaffected; a new parity test checks the v3 table against the tagged requires of `contracts/impulse_vault_v3.sil`.

## 13. Test plan (exit: invalid proof refused in the engine; script units and proving time recorded)

All engine tests use kaspa-txscript at rusty-kaspa a41a333 with covenants enabled, mainnet parameters, the fixture KCC-20 tokens, and run every input at its committed budget. Files `tests/engine/v3_*.rs`. Test names below are the names the code uses; section 19 cites them.

### 13.1 Valid proofs

Proof fixtures are real receipts of the list guest, made by `impulse-zk-prove` once and committed under `tests/engine/fixtures/v3/proofs/` with the terms, J, the proof and the risc0 versions; `circuits/scripts/regen-fixtures.sh` remakes them. They are made only after the go or no-go checkpoint of section 14.2 passes. Because the journal binds the vault scriptPubKey, the fixture terms use fixed fixture keys and fixed fixture salts (rule 1, test fixtures; a salt is not a key); fee inputs may use runtime keys. `v3_fixture_journal_matches_terms` checks that each fixture's J equals what the vault computes from its terms.

- `v3_fixture_receipt_accepted` and the settle-shape tests: KAS cash, KCC-20 cash, external cash with authority; with and without authority; delivery owner PUBKEY and SCRIPT_HASH; a list of one entry and of 1,000 entries. `v3_list_size_does_not_change_cost` asserts that the two proofs have the same size and the two settles the same script units; nothing is claimed about it before that test runs.
- Refund unchanged: every v1 refund test, run against template v3.
- Every v1 settle tag's failing test, run against template v3 with a valid proof, so the gate does not mask a v1 refusal.

### 13.2 Invalid proofs, each refused in the engine

| Test | Case | Expected |
| --- | --- | --- |
| `v3_proof_bit_flip_refused` | One bit of the proof flipped | script fails in the precompile |
| `v3_proof_length_refused` | Proof of 0, 127 and 129 bytes | script fails (proof parse, trailing bytes) |
| `v3_proof_for_other_vault_refused` | Valid proof for vault A, used at vault B (same root and owner, another nonce) | fails: J differs |
| `v3_proof_for_other_root_refused` | Valid proof for another root | fails |
| `v3_proof_for_other_owner_refused` | Valid proof of another member, settle delivering to a different owner | fails |
| `v3_proof_owner_type_swap_refused` | Valid proof for a P2PK owner, terms naming the P2SH owner with the same 32 bytes | fails: `owner_spk` differs |
| `v3_forging_guest_refused` | Proof from the forging guest: commits a correct J without checking a path, another image ID | fails: image ID |
| `v3_proof_for_cash_vault_refused` | Proof of the right guest for the cash vault's scriptPubKey | fails at the asset vault |
| `v3_z1_covenant_owner_refused` | `[Z1]`: terms with a COVENANT_ID delivery owner (made without impulse-core) | fails at `[Z1]` |
| `v3_z2_cash_vault_nonempty_proof_refused` | `[Z2]`: cash vault given a non-empty proof | fails at `[Z2]` |
| `guest_refuses_non_member` (host test in `circuits/`) | A non-member, or a member with a wrong salt | the guest refuses; no receipt exists to submit |

Mutation run `tests/engine/mutation-run-v3.txt`: removing `[Z1]`, `[Z2]`, the `r0.g16.verify` call, or any one field from J in the contract is caught by a named test.

### 13.3 Measurements in the engine

`tests/engine/v3_measure.rs`, printed with `-- --nocapture`, committed as `docs/measurements/v3-zk-units.txt` with date, commit and command: script units of each vault input for every settle shape and refund role; template v3 size; signature-script bytes per input; compute, transient and storage mass of each settle from the pinned `MassCalculator`; sig-op count per input from the pinned scanner (expected unchanged from v1, section 3.1). The fitted budget rule of section 10 is asserted within v1's tolerance. Figures are quoted, the I20 Report included, only from that file.

### 13.4 Vectors, guest and text checks

`tests/vectors/zk/`: leaves for both owner types with fixed salts, roots of lists of 1, 2, 3 and 1,000 entries, paths at the first and last positions, the empty-tree root, manifests with their digests and a signature by a fixture key, and J and journal_hash for each engine fixture, plus one real receipt's journal digest showing SHA-256 of J (section 5.2). `scripts/vectors.sh` checks them in Python; `circuits/` tests check `list-core` and the guest against the same files. Guest host tests: `guest_refuses_wrong_depth`, `guest_refuses_index_out_of_range`, `guest_refuses_zero_leaf` (through a test hook that forces the computed leaf), `guest_refuses_wrong_root`, `guest_refuses_malformed_vault_spk`, `guest_refuses_malformed_owner_spk`, `guest_refuses_non_member`. `scripts/check-zk-text.sh --self-test` (section 9.5) runs in CI.

## 14. Proving on the laptop: method

### 14.1 Prover image pin

Before the first proof, the maintainers record in `circuits/GROTH16_PROVER_IMAGE`: the image name and tag of section 3.6, its `sha256` manifest digest for the platform pulled, the source the digest was compared against (the registry's manifest, read with `docker buildx imagetools inspect`, and the digest RISC Zero publishes for that tag if it publishes one, with the URL), the date, and who compared them. The owner confirms that entry (D61). `impulse-zk-prove` checks the local image's digest against the file before it starts the Groth16 step and refuses a mismatch (`ZK_PROVER_IMAGE`). This replaces the "pin at first pull" of the first draft, which trusted whatever the first pull returned.

### 14.2 Measurement, and the go or no-go checkpoint

`circuits/scripts/measure-proving.sh` runs on the owner's M1 Max laptop, by the maintainers in I20 (it moves no value and touches no key), and writes raw data to `docs/evidence/i20-proving-<date>/` with the script itself:

- Machine: `sysctl -n machdep.cpu.brand_string hw.memsize`, `sw_vers`, `docker version`, Docker's VM memory and CPU limits, `rzup show`, the Groth16 image's digest.
- Five runs on a fixture of 1,000 entries, each recording: guest cycles and segments from the executor; wall time of (a) execution, (b) proving to a succinct receipt, (c) the Groth16 step in Docker, from the host's monotonic clock; the host process's peak resident memory from `/usr/bin/time -l`; the Docker container's memory, sampled each second with `docker stats --no-stream` into a CSV (the Groth16 step runs inside Docker's VM, so the host figure does not include it); whether the container exited normally or was killed; proof and receipt sizes.
- Idle machine: the script reads the 1-minute load average before each run and stops above `MAX_LOAD` (default 4); a result whose runs started above it is NO-GO and its figures are loaded-machine upper bounds, not a checkpoint (I20 review round 1). `results.txt` records the load at each run's start.
- `results.txt`: minimum, median and maximum per stage. Figures are quoted only from that directory, with the method, as figures for that laptop and those versions, never as a general claim.

Go or no-go, decided from `results.txt` before any real-receipt fixture is made: **go** if every one of the five runs completes all three stages, each run's Groth16 stage finishes within 60 minutes of wall time, and no container is killed or reaches the Docker VM's memory limit. Otherwise **no-go**: the maintainers record the measured result as a blocker of I20 and stop before section 13.1's fixtures. The 60-minute bound is a design choice for a step that runs once per trade, off chain; it is not a performance claim. After a no-go, D61 applies: the step runs on an x86-64 Linux machine the owner controls, if there is one; no remote proving service is used (the succinct receipt passed to the Groth16 step carries no list data in the clear, but its zero-knowledge property is asserted, section 9, and no part of the proving leaves the owner's machines). If there is none, the mainnet half of the exit test is deferred and recorded as such.

## 15. Networks

Template v3 runs on TN10, the supported test network, and on mainnet. On mainnet, as everywhere, the tools refuse a trade above 10 KAS unless --i-accept-the-risk is passed (section 9.5). A v3 settle needs a node whose mempool accepts its mass (section 10). Public use of v3 on mainnet waits for D68 (counsel).

## 16. What the gate's correctness rests on

Named so that anyone can review them, the parts of this repository that the correctness of template v3 and the list prover rests on: the vendored `risc0-zkvm` 3.0.4 patch (`circuits/patches/risc0-zkvm-3.0.4-prove.patch`, SHA-256 `d8225f3994bc6ce5a84de30a243f406622b35fb537dd9994061479aa7b44b84c`; host prover only, checked by `scripts/ci-zk.sh` against the registry source), the asset-only placement of the gate and the substitution property of section 6.5, the diff of template v3 against v1 (`[Z1]`, `[Z2]`, the journal construction, the state fields, the position of the gate); the compiled bytes of the `r0.g16.verify` lowering in the v3 artifact against the zk-sdk fragment at a41a333; the guest and `list-core` (salt handling, path rules, depth, the zero-leaf guard, the committed bytes); the reproducibility of `IMAGE_ID`; the image pin of section 14.1 and the check in `impulse-zk-prove`; `impulse_core::zk` builders, the manifest and the pre-submit proof check; the replay analysis of section 8 and the statements of section 9; and a supply-chain review of `circuits/Cargo.lock` and of the root `Cargo.lock` entries the `zk` feature adds (cargo-vet records, or a recorded per-crate review where none exists, plus cargo-audit and the licence scan with the feature on).

Outside this repository, and disclosed as third-party trust: the RISC Zero zkVM, its recursion and STARK-to-SNARK circuits, its Groth16 setup and the contents of the Docker prover image; `ark-groth16` and the Kaspa precompile itself (consensus code of rusty-kaspa). These carry the soundness of the gate; the setup line of section 9.5 says so wherever the gate is described.

## 17. Files of template v3

| Path | Rule |
| --- | --- |
| `spec/V3-ZK.md` | new |
| `contracts/impulse_vault_v3.sil`, `contracts/compiled/impulse_vault.v3.*`, `contracts/TEMPLATE_HASH_V3`, `scripts/build-template-v3.sh` | new |
| `circuits/` (own workspace, including `IMAGE_ID` and `GROTH16_PROVER_IMAGE`), `scripts/build-guest.sh` | new |
| `crates/impulse-core/src/zk/`, `crates/impulse-cli/src/zk_cmd.rs` | new |
| `tests/engine/v3_*.rs`, `tests/engine/fixtures/v3/`, `tests/engine/mutation-run-v3.txt` | new |
| `tests/vectors/terms_v3/`, `vaults_v3/`, `zk/` | new |
| `docs/measurements/v3-zk-units.txt`, `docs/evidence/i20-proving-<date>/` | new |
| `scripts/check-zk-text.sh` | new |

Shared files, append only: `spec/ERRORS.md` (a Families row at the end of the table, `## ZK_ codes` immediately before `## Retired and changed codes`, and the on-chain section at the end of the file); `Cargo.toml` (`exclude = ["circuits"]`, and the `zk` feature's dependencies on `kaspa-txscript-zk-sdk` at a41a333); `crates/impulse-core/src/lib.rs` and `crates/impulse-cli/src/lib.rs` (`pub mod zk;` and `zk_cmd` after the last module line); `tests/engine/Cargo.toml` (`[[test]]` blocks at the end); `tests/parity/gen_parity.py` (`ZK` in `FAMILIES`) and the parity tests (the `ZK_` frozen list and the v3 on-chain table test, at the end); `scripts/ci-local.sh` (the v3 template, guest and text checks after the v1 build step); `scripts/vectors.sh` (generator entries at the end); the key holder's runbook (a section at the end of the file); `README.md` (the v3 section between its markers, at the end, written only after `check-zk-text.sh` exists). `PARITY.md` is regenerated, never hand-merged. This file names the baseline program nowhere, so it needs no parity `prose` entries.

## 18. Decisions (defaults followed here)

| D | Question | Default | Owner answer needed |
| --- | --- | --- | --- |
| D58 | Proof system | Groth16 tag `0x20` carrying a RISC Zero receipt (section 4) | yes |
| D59 | Accept the RISC Zero Groth16 setup assumption, and the cap | Accepted only as the four points of section 4: unverified, values at or below the cap only, transcript location and key hash recorded and seen first, anything above the cap or public waits for transcript review | yes |
| D60 | Where the guest and prover live | `circuits/`, its own cargo workspace, excluded from the root workspace, with its own toolchain | no |
| D61 | Where the Groth16 step runs, the image pin, and whether an x86-64 machine exists | The owner's laptop through RISC Zero's Docker image pinned by a recorded digest (14.1) that the owner confirms; after a no-go (14.2), an x86-64 Linux machine the owner controls; never a remote prover; if no such machine exists, the mainnet half is deferred | yes |
| D62 | Which template v3 extends | v1 (two legs); a gated basket on template v2 is not in I20 | no |
| D63 | Mass caps for v3 | D37's per-dimension caps (compute 450,000, storage 450,000, transient 900,000); v1 keeps 100,000 | no |
| D64 | Principle 2 exception | The proof is checked by the asset vault only (section 6.5) | no |
| D65 | SDK and demo page for v3 | Not in I20; CLI and core only | no |
| D66 | Image ID: template constant or terms field | Template constant; a new guest is a new template | no |
| D68 | Legal positioning of v3 | No marketing of v3; capped values; the fixed texts of section 9.5 reviewed by counsel before any public mainnet use; circuit 2 stays deferred until counsel has seen circuit 1 | yes |
| D69 | Design answers to the red team (section 21) | Per-entry random salt in the leaf; list issuer key in the terms and a signed manifest checked by `verify`; `terms new` requires an authority unless `--no-authority`; rotation and revocation out of scope | no |

## 19. Red team of this design (first round)

Status words: "resolved in design, open until ..." names the test or record that closes a finding; a finding closes only when that is green or committed.

| # | Finding | Area | Rating | Resolution |
| --- | --- | --- | --- | --- |
| 1 | The requirement asks to prove membership "without revealing the member"; the delivery owner is public in the vault state and in output 0 | Technical, commercial | HIGH | Resolved in design (section 9, the fixed disclaimer and banned list of 9.5); open until `scripts/check-zk-text.sh` and its self-test are green in CI. Hiding the member needs a token with private owners, out of scope |
| 2 | Listing at settle is not a transfer restriction: a member can pass the token to anyone after delivery | Regulatory, commercial | HIGH | Flagged and disclosed: the fixed disclaimer says "does not check onward transfers"; a transfer restriction belongs in the token's own template, out of scope; legal positioning is D68 |
| 3 | Soundness depends on RISC Zero's Groth16 setup; collusion of all its participants forges receipts | Technical | HIGH | Flagged: assumption stated and D59's acceptance limited to four points (section 4); the setup line in user text; cannot redirect funds; verifying key pinned by the template; open until `circuits/README.md` records the transcript location and key hash |
| 4 | The Groth16 step needs RISC Zero's x86-64 Docker image; on Apple silicon it may be slow or fail | Operational | HIGH | Resolved in design (sections 14.1, 14.2, D61); open until `docs/evidence/i20-proving-<date>/results.txt` is committed with a go, or a no-go blocker is written and D61's fallback is answered |
| 5 | A non-reproducible guest build would give each machine another image ID | Technical | HIGH | Resolved in design (`circuits/IMAGE_ID`, `ZK_IMAGE_ID_MISMATCH`); open until `scripts/build-guest.sh` reproduces `IMAGE_ID` in `scripts/ci-local.sh` |
| 6 | A guest bug (no depth check, index beyond the tree, empty leaf accepted) would admit non-members | Technical | HIGH | Resolved in design (section 5.4); open until the seven `guest_refuses_*` host tests of 13.4 are green and `tests/engine/mutation-run-v3.txt` shows every J field caught |
| 7 | "Whitelist" read as a compliance claim | Legal, regulatory | HIGH | Resolved in design: the word is gone from every v3 identifier and user text (sections 0, 9.5), the fixed disclaimer, D68; open until `scripts/check-zk-text.sh` is green and counsel has reviewed the fixed texts |
| 8 | A v3 settle is above the 100,000-gram standard cap of older wallets and nodes | Technical, operational | MEDIUM | D63 caps; CLI warning without figures (section 10); v3 CLI only; a node whose mempool accepts the mass is needed (section 15) |
| 9 | Three Groth16 verifications fill a block's compute; fees of about 0.17 KAS per settle (modelled) | Commercial | MEDIUM | Disclosed in this file only; user text quotes figures only from the measurement files (section 10), enforced by `check-zk-text.sh` |
| 10 | Removal from the list after terms are made does not stop the settle | Commercial, regulatory | MEDIUM | Authority required by default in `terms new` (`ZK_AUTHORITY_ABSENT`), verify warning when absent, revocation guidance printed (sections 5.6, 7.3) |
| 11 | Prover and verifier versions drift apart | Technical | MEDIUM | Resolved in design (section 3.6, host pinned); open until `v3_fixture_receipt_accepted` is green |
| 12 | Proof reuse at another vault | Technical | MEDIUM | Resolved in design (section 8); open until `v3_proof_for_other_vault_refused` is green |
| 13 | The cash vault does not check the proof | Technical | MEDIUM | Written exception (section 6.5, D64); open until `v3_z2_cash_vault_nonempty_proof_refused` is green |
| 14 | Heavy dependencies (risc0-zkvm through the zk-sdk) enter impulse-core | Operational, legal | MEDIUM | Feature `zk`, off by default; WASM build unaffected; supply-chain review named in section 16 |
| 15 | A buyer without its path cannot settle; the trade stalls until refund | Operational | MEDIUM | Disclosed as an issuer liveness dependency (section 9.3); paths delivered at onboarding; `verify --path` and its warning |
| 16 | The issuer's list file and salts are sensitive | Operational | MEDIUM | `list build` reads the list locally and writes only the root and per-entry path files; never prints or transmits the list or the salts |
| 17 | Groth16 proofs are malleable | Technical | LOW | Accepted: nothing relies on proof uniqueness (section 8) |
| 18 | The ZK property is asserted, not checked | Technical | LOW | Marked asserted (section 9.1); the per-entry salt (9.2) limits what a leak would expose |
| 19 | BN254's security level is below 128 bits | Technical | LOW | Accepted as the precompile's only Groth16 curve (section 3.2); value capped |
| 20 | Hashing the whole terms (the terms hash) is not possible in script | Technical | LOW | Resolved: the vault scriptPubKey binds the same terms (section 5.3) |

## 20. Circuit 2 (ISO 20022 instruction pair): deferred

The I20 requirement puts circuit 2 in scope only if budget allows; the run that wrote this file puts it in scope only once circuit 1 is complete and reviewed, and D68 adds that counsel must have seen circuit 1 first, because an instruction-matching circuit strengthens a compliance reading of v3. Circuit 1 is not yet implemented, so circuit 2 is deferred and recorded as deferred in I20. When it is taken up, it reuses this design's frame (a guest under `circuits/`, a journal that binds the vault scriptPubKey, an image ID constant, a new template) and needs its own spec section, including how the two signatures over the instruction hashes are checked in the guest and which keys the terms name for them.

## 21. Red team (second round, 11 October 2026)

Findings of the second red team of this file and how this revision answers them. Each CRITICAL or HIGH is resolved in the design or flagged as an open question with a decision and a default; none is closed until the named check is green.

| # | Severity | Where | Finding | Resolution |
| --- | --- | --- | --- | --- |
| R1 | HIGH | sections 9, 19 #1 | Privacy claim exposure: the member is public, nothing enforced wording outside the spec, and unsalted leaves made the list testable against every address on chain and linkable across lists; the issuer learns member and vault; the root groups trades | Resolved in design: per-entry random salt in the leaf, computed in the guest only, `owner_spk` in the journal instead of the leaf (5.1, 5.2, 5.4, D69); section 9 rewritten as what is and is not hidden, with enumeration, linkability and the issuer's view stated (9.1 to 9.3); normative permitted wording, fixed texts and banned phrases (9.5). Open until `scripts/check-zk-text.sh` and its self-test are green in CI and the salt vectors of 13.4 pass |
| R2 | HIGH | sections 5.1, 7, 19 #10 | No binding of a root to an issuer; removal after terms does not stop a settle; authority optional; no rotation or revocation story | Resolved in design: `list_issuer_key` in terms v3 and state (6.2, 7.2), a signed list manifest that `verify` checks and reports (5.6, `ZK_MANIFEST_INVALID`), a warning when the seller is the issuer; `terms new` requires an authority unless `--no-authority` (`ZK_AUTHORITY_ABSENT`), with a verify warning when absent (7.3); rotation and revocation out of scope with printed short-expiry guidance (5.6). Open until the manifest vectors and the `verify` output tests are green |
| R3 | HIGH | sections 1, 19 #2, #7, 20 | KYC and regulatory reading (MiCA, travel rule, securities rules); onward transfer defeats the assumed use; circuit 2 strengthens the reading; no legal review before mainnet | Flagged as an open question, D68, default: no marketing, capped values, the fixed disclaimer of 9.5 in verify output, CLI help and README, reviewed by counsel before any public mainnet use; the owner's private capped smoke run is not public use (section 15); circuit 2 stays deferred until counsel has seen circuit 1 (section 20) |
| R4 | MEDIUM | section 4, D59 | Ceremony assumption asserted and accepted unreviewed; a forged receipt bypasses the gate | D59 lists the four points accepted and nothing more (section 4); setup line in verify output and README (9.5); transcript location and key SHA-256 recorded; revisit before any value above the cap; "cryptographically enforced" and "trustless" banned |
| R5 | MEDIUM | section 16, D61 | What carries soundness is third-party trust outside this repository; image pinned by trust on first use | README cap line; digest pinned in `circuits/GROTH16_PROVER_IMAGE` from a documented source with who compared it, confirmed by the owner, checked by the prover (14.1, `ZK_PROVER_IMAGE`); supply-chain review named in section 16 |
| R6 | MEDIUM | sections 14, 15, 18 | Owner workload and schedule; Groth16 under emulation unmeasured; fallback hardware unconfirmed | Measurement moved to the maintainers with a go or no-go bound before any real-receipt fixture (14.2, step 0); D61 now asks whether an x86-64 machine exists, default no remote prover and defer the mainnet half; owner-facing decisions reduced to D58, D59, D61 and D68 (section 18) |
| R7 | MEDIUM | sections 9, 19 #15 | The issuer is a liveness and censorship dependency | Disclosed beside the privacy note (9.3); paths delivered at onboarding; `verify --path` and its warning; expiry sized to issuer responsiveness |
| R8 | MEDIUM | sections 3.1, 10, 19 #8, #9 | Asserted and modelled figures likely to be copied into README | Figures stay out of user text until the measurement files exist, enforced by `check-zk-text.sh` (section 10); the activation score is no longer quoted; capacity phrased as what the pinned tests assert; the 1,000-entry cost equality is a test, not a claim (13.1) |
| R9 | LOW | section 10, D63, D65 | Mass above the standard cap; no SDK or demo; no relay test on independent nodes | v3 recorded as CLI only, needing a node whose mempool accepts its mass (section 1, 11, and I20; section 15) |
| R10 | LOW | sections 1, 19 | Closure language marked HIGH findings resolved without code; "whitelist" wording | Section 19 uses "resolved in design, open until" with each test named; "whitelist" removed from identifiers and user text, replaced by "issuer list" and "allowlist" (sections 0, 9.5) |

## 22. I21: hashed-terms vault (template v4)

Draft, 13 October 2026, increment I21 (design step). It builds on I20's frame: a guest under `circuits/`, the `r0.g16.verify` builtin and the zk-sdk fragment of sections 3.4 and 3.5, a journal that binds the vault's scriptPubKey, an image ID constant of the template, the prover pin and the measurement method of section 14. Marks are those of section 0. Status, 15 October 2026: implemented in I21 (22.14). The sizes, units, masses and proving times that were measured are in `docs/measurements/v4-zk-units.txt` and `docs/evidence/i21-proving-<date>/results.txt`; a figure in this section that those files do not repeat is modelled. Amended 18 October 2026 by 22.15: the script checks the covenant ID of every input of a settle or refund (known limitation L20). Amended 19 October 2026 by 22.16 (I26): the guest requires the other leg's vault at its input slot in a settle, which closes L20 for template v4.

### 22.1 Scope

| Item | In I21 | Where |
| --- | --- | --- |
| Template v4 (`ImpulseVaultV4`): a vault whose state is the terms commitment and the authority key, and nothing else | yes | 22.2, 22.5 |
| Terms v4 and the two commitments | yes | 22.2 |
| Guest 2 (`circuits/terms-guest`, `circuits/terms-core`), its own `IMAGE_ID_V4`: the spending transaction's checked inputs and outputs satisfy the committed terms | yes | 22.3, 22.4 |
| Settle and refund, both proof-carrying | yes | 22.5, 22.6 |
| `impulse decode ... --with-terms`, `impulse zk terms reveal`, v4 builders, IPST version 5 | yes | 22.7, 22.8 |
| Engine tests, script size against v1, measured units, mass and proving time | yes | 22.9, 22.10 |
| Hiding amounts, the token, the authority, the funders, or anyone's identity | no | 22.4 |
| Combining with the issuer list of v3 | no | not designed |
| SDK and demo page | no (D65 stands) | |

### 22.2 What the vault holds, and terms v4

State, two fields:

| # | Field | Type | Value |
| --- | --- | --- | --- |
| 1 | termsCommit | byte[32] | `commit(terms, leg)` below |
| 2 | authorityKey | pubkey | the authority's x-only key, in clear |

Constants of the template: `IMAGE_ID_V4` (byte[32], equal to `circuits/IMAGE_ID_V4`; the build script refuses a mismatch), the journal tag, the entry tags. The state holds no version, network, nonce, party, token, amount, destination, time or leg field: all of those are inside the committed terms. The address commits to the template hash and the state, so two vaults differ if their commitments or authority keys differ.

Terms v4 canonical bytes: the v1 layout (`ENCODING.md`) with `version = 0x04` and two fields appended after field 16 (`funding_mode`): `blind` (32 bytes, drawn by `impulse zk terms new` from the operating system's random number generator, never typed, never reused) and `trade_ref` (32 bytes). Structure checks: v1's in v1's order with v1's codes, plus: settlement mode is Vault (`ZK_H_TERMS_DIRECT`); an authority is present (`ZK_H_AUTHORITY_REQUIRED`: the authority key is the vault's second state field, and the authority's `[S6]` signature is required on every settle); `blind` is not all zero (`ZK_H_BLIND_INVALID`); the version byte is 4 (`ZK_H_TERMS_VERSION`, checked first).

```
terms_hash_v4 = BLAKE2b-256(key = "Impulse/terms/v4",  message = canonical terms v4)
commit(t, leg) = BLAKE2b-256(key = "Impulse/commit/v4", message = terms_hash_v4(t) || leg)    leg: 1 byte, 0 asset, 1 cash
```

Known answers (measured, run: Python `hashlib.blake2b(m, key=k, digest_size=32)`):

| Key | Message | Digest |
| --- | --- | --- |
| `Impulse/terms/v4` | empty | `51c6e19b097e437b72bcee41372f358236d44511430de2fba6ba50ac62ee9893` |
| `Impulse/terms/v4` | `abc` | `b80e077a53e2bcf5ec633915e22bbb94525fb06ec5fe97853c6d2166d8d03ad5` |
| `Impulse/commit/v4` | 32 zero bytes, `0x00` | `41aad3a9e889815bb8e7387397971eacfcbb5a59c119f5a19127e0b0e24e6cf7` |
| `Impulse/commit/v4` | 32 zero bytes, `0x01` | `4b36a373a9e9b321e72777e8902560aeca913c7b86d2768251c7a197e719376e` |

Why a commitment per leg. With one commitment for both vaults, both would have the same state and the same address. The leg byte makes the two addresses differ and binds the leg index to the terms. Why `blind`. The v1 nonce is 8 bytes, which does not stop someone who knows the parties and the likely amounts from testing guessed terms against the commitment; 32 random bytes do (finding 6).

### 22.3 The journal

The script builds these bytes; the guest commits exactly these bytes with `env::commit_slice`; the script checks them with `r0.g16.verify(sha256(J), proof, IMAGE_ID_V4)`. Every field has a fixed width, so J parses one way.

```
J = "Impulse/zk/ht/v1"     16   ASCII
 || mode                    1   0x01 settle, 0x02 refund (a constant of each entry)
 || vault_spk              37   this.activeScriptPubKey
 || commit                 32   state termsCommit
 || authority              32   state authorityKey
 || leg                     1   settle: this.activeInputIndex.  refund: the entry argument
 || input_index             1   this.activeInputIndex
 || locktime                8   OpTxLockTime(), 8 bytes little-endian (amended by D122: the transaction lock time, not tx.daa)
 || signer                 32   settle: 32 zero bytes.  refund: the signer's key
 || cov_a                  32   entry argument: the asset (settle) or the leg's (refund) token covenant ID
 || cov_c                  32   settle: entry argument, the cash token covenant ID, else zero.  refund: zero
 || count_a                 1   OpCovInputCount(cov_a)
 || count_c                 1   OpCovInputCount(cov_c), 0 on refund
 || n_in                    1   entry argument
 || n_out                   1   entry argument
 || for i in 0 .. n_in:   value(8, LE) || sha256(spk)(32) || covenant ID(32)    of tx.inputs[i]
 || for k in 0 .. n_out:  value(8, LE) || sha256(spk)(32) || covenant ID(32)    of tx.outputs[k]
```

228 bytes of header and fields, then 72 per input or output: 516 bytes for external cash (2 in, 2 out), 660 for KAS cash (3, 3), 804 for KCC-20 cash (4, 4), at most 516 for a refund (modelled: arithmetic from the layout). The scriptPubKeys enter as their SHA-256 so J has fixed width whatever the length of a KAS destination. `r0.g16.verify` receives `sha256(J)`; that the RISC Zero journal digest is SHA-256 of the committed bytes is asserted (section 5.2), and the I21 vector measures it against a real receipt, as I20's does.

Binding. The authority's `[T4]` signature and the transaction's sighash cover the whole transaction, so the authority approves exactly the view the proof speaks about. Inputs and outputs beyond `n_in` and `n_out` (fee inputs, change) are not in the view; of them the script checks only the covenant ID of each input (`[T10]`, `[T11]`, 22.15), the guest nothing; the fee is exactly the caller's and never comes from a leg because the guest enforces v1's exact-amount rules on the view. The journal contains no outpoint and no transaction ID: a receipt is valid for any transaction with the same view, and for a second UTXO at the same vault address, the accepted property of section 8.

### 22.4 What the proof shows, and what is hidden

Private input of the guest: the canonical terms `T`; for every view item the full scriptPubKey bytes (so `sha256(spk)` can be opened); in a settle, this vault's own redeem script (22.16); for each escrowed token input the redeem script (a KCC-20 template with its state), which the guest checks against that input's P2SH hash with BLAKE2b-256. Public: J. Statement, for mode settle (names are v1's tags; each is a function in `terms-core` carrying its tag, and the host checker, the guest and the `--tx` check of 22.7 call the same functions):

| Group | v1 tags | Where it runs in v4 |
| --- | --- | --- |
| Commitment | commit(T, leg) equals J.commit; T passes the structure checks; T's authority key equals J.authority; J.cov_a and J.cov_c equal T's covenant IDs; `n_in` and `n_out` equal the layout of T's cash kind (KAS cash 3 and 3, KCC-20 cash 4 and 4, external 2 and 2; refund 1 or 2 and 1 or 2); in a settle with KAS or KCC-20 cash, the input at the other leg's vault slot is the v4 vault of T for the other leg (22.16) | guest, `[H1]` to `[H5]` |
| Position | `[S1]` leg equals input_index; `[R4]` refund input_index is 0 | guest |
| External cash needs an authority | `[S7]` | vacuous in v4: an authority is always present |
| Escrow | `[E1]` and `[E2]`: count_a (and count_c) is 1 and the covenant sits at the layout's slot (read from the view's covenant IDs); `[E3]` to `[E6]`: the token redeem script opens to the input's P2SH hash, runs the template named in T (BLAKE3 of the length-prefixed prefix and suffix, as the `templateHash` builtin does: measured, source `silverscript/silverscript-lang/src/compiler/compile/expression/builtin.rs:240-248`), its owner is this vault's script hash, its amount is exactly the leg amount, it is not a minter | guest |
| Amounts and time | `[S2]` KAS cash input equals `amount_b`; `[S3]` locktime is at least `earliest_daa` when set; `[S5]` KAS cash output equals `amount_b` | guest |
| Returns | `[S8]` the authorizer's KAS returns to the depositor's P2PK; `[S9]` at least in full | guest |
| Deliveries | `[D1]`, `[D2]` covenant ID, KAS at least the escrow input's; delivery builtin: the output's scriptPubKey equals the P2SH of the template with state (owner, exact amount, not a minter) built by `terms-core`'s KCC-20 state encoder; `[S4]` the KAS proceeds scriptPubKey | guest |
| Authority | `[S6]` | script, `[T4]` |
| Refund | `[R1]` signer is the depositor, the counterparty or the authority; `[R3]` earmarked depositor refund needs locktime at least `expiry_daa`; `[R5]` to `[R14]`, using count_a for `tokenInputs` | guest; `[R2]` the signature in script, `[T5]` |

Principle 2 holds in v4 without the exception of 6.5: each vault proves the whole view, both deliveries included, against its own commitment, so neither vault relies on the other. The price is two receipts in a settle (22.10).

What an observer learns.

| Moment | Visible on chain | Not visible |
| --- | --- | --- |
| Before any spend | The vault address and state (a commitment and the authority key); each vault UTXO's KAS value; for a token leg the escrow UTXO's covenant ID and amount and that its owner is the vault; the funding transactions and their funders; timing | Both parties' keys, all four destinations, the cash kind where the UTXOs do not show it, expiry, earliest time, funding mode, nonce, `blind`, `trade_ref`; that the two vaults belong to one trade (until a settle spends both) |
| A settle | Everything in the transaction: the delivery token output (its owner sits inside the P2SH hash), the seller's KAS proceeds scriptPubKey in clear for KAS cash, the authorizers' P2PK returns, which are the seller's and buyer's keys, the lock time, the authority's signature, the proof | Expiry, funding mode, refund destinations, earliest time beyond the lock time, nonce, `blind`, `trade_ref`; the unrevealed owners behind a token output's hash |
| A refund | The signer, the refund output(s), the lock time | The other leg's destinations, expiry (beyond the lock time), nonce, `blind`, `trade_ref` |

So the requirement's "parties and conditions stay hidden until the parties reveal" holds for the period before a spend and only partly after: a spend publishes the outputs it must contain. Revealing the terms to a verifier is all or nothing: the file holds every field. Selective disclosure is out of scope.

### 22.5 Template v4: entries and requires

One template, two entries. Compiled with the pinned silverc; artifacts `contracts/compiled/impulse_vault.v4.json` and `.v4.ctor.json`, pin `contracts/TEMPLATE_HASH_V4`, source `contracts/impulse_vault_v4.sil`, build script `scripts/build-template-v4.sh`.

`settle(sig authSig, byte[] proof, int nIn, int nOut, byte[32] covA, byte[32] covC)`

| Tag | Require | Purpose |
| --- | --- | --- |
| `[T1]` | `this.activeInputIndex <= 1` | The vault sits at input 0 or 1, so `leg` in J is 0 or 1 (v1 `[S1]` is checked against the commitment in the guest) |
| `[T2]` | `nIn >= 2 && nIn <= 4 && nIn <= tx.inputs.length` | The view has a bounded size and is inside the transaction |
| `[T3]` | `nOut >= 2 && nOut <= 4 && nOut <= tx.outputs.length` | The same for outputs |
| `[T4]` | `checkSig(authSig, authorityKey)` | The authority approves this exact transaction (v1 `[S6]`, now mandatory) |
| `[T8]` | `tx.daa >= OpTxLockTime()` | The lock time is final, so the lock time in J cannot be later than the chain (D122; consensus also refuses a non-final transaction, this makes the bound a script rule) |
| `[T10]` | for every input `i` of the transaction, at most `MAX_INPUTS` (8): `OpInputCovenantId(i)` is `covA` at the asset escrow slot (input 1 when `nIn = 2`, else input 2), `covC` at input 3, and 32 zero bytes everywhere else | No token rides along in a settle except the escrows the guest checks (22.15) |
| builtin | `r0.g16.verify(sha256(J), proof, IMAGE_ID_V4)` | The view satisfies the committed terms |

`refund(sig s, pubkey signer, byte leg, byte[] proof, int nIn, int nOut, byte[32] cov)`

| Tag | Require | Purpose |
| --- | --- | --- |
| `[T5]` | `checkSig(s, signer)` | The named signer signed (v1 `[R2]`); whether the signer may refund is the guest's `[R1]` |
| `[T6]` | `leg <= 1` | The leg byte is a leg |
| `[T7]` | `nIn >= 1 && nIn <= 2 && nIn <= tx.inputs.length && nOut >= 1 && nOut <= 2 && nOut <= tx.outputs.length` | Refund shapes (v1 refund layout) |
| `[T9]` | `tx.daa >= OpTxLockTime()` | The same finality bound for a refund (D122) |
| `[T11]` | for every input `i` of the transaction, at most `MAX_INPUTS` (8): `OpInputCovenantId(i)` is `cov` at input 1 when `nIn = 2`, and 32 zero bytes everywhere else | No token rides along in a refund except the leg's escrow (22.15) |
| builtin | `r0.g16.verify(sha256(J), proof, IMAGE_ID_V4)` | The refund view satisfies the committed terms |

Lock time (D122, amends the v1 reading of `tx.daa`): J carries the transaction lock time. The guest's `[S3]` and `[R3]` require a set lock time in `[earliest_daa, 5e11)` (a DAA-score lock time, not a timestamp), where v1 compared `tx.daa`. A v4 spend therefore needs an explicit lock time and a non-final sequence on at least one input; v1 spends needed neither.

The gate runs after the cheap requires, so a malformed spend fails before the verification. The code that builds J is straight-line (conditional on `nIn` and `nOut` up to the maxima of four and four); v4 has two verifier call sites, each embedding the 424-byte key, so the artifact is larger than v3's modelled 3,900 bytes in the verifier part and smaller in the state part. Modelled total between 3,500 and 5,500 bytes against v1's 2,938 (section 6.1); I21 records the measured size and compares it to v1 in `docs/measurements/v4-zk-units.txt`.

Contract-step items, each with a stated outcome if it fails; none is solved by weakening a check:
1. Integer to fixed-width bytes in silverscript source (the compiler has it internally, `builtin.rs:240-241`). If the language exposes no spelling, I21 stops and writes a Blocker; the J layout does not change.
2. `OpInputCovenantId` on an input without a covenant (fee inputs, KAS cash). If it fails the script, the view hashes covenant IDs only at the positions the layout fixes for tokens, and a `shape` byte (which of the four layouts) becomes a J field; the guest then checks it against T.
3. Dynamic indexing in loops: if no loop construct exists, J is built by straight-line code up to the maxima.
4. Two verifications in one input's script and the budget they need: measured in the engine.

### 22.6 Refund path

A refund is also proof-carrying, because the refund destinations, the signer set, the funding mode and the expiry are inside the commitment. The guest runs the refund tags of 22.4 over the refund view (one vault input at index 0, its KAS whole at output 0; for a token leg the escrow token at input 1 returned whole at output 1). Consequences, all disclosed in the fixed texts of 22.11:

- A refund needs the terms file and a proof. Proving is done where the I20 prover runs, and the proof can be built before the expiry: the view contains the lock time, not the block, and the signed transaction is not final until the lock time passes (`TRANSACTIONS.md`, "Lock time"). A depositor who wants a refund at expiry prepares and holds the signed transaction ahead of time.
- Loss of the terms file strands the vault until a copy is found (finding 4).
- The signer set is v1's: the depositor, the counterparty, the authority. The counterparty and authority refunds take the token home with it, as in v1 (`[R11]`, `[R14]`).
- A refund does not need the authority's signature, as in v1.

### 22.7 Verifier: `decode --with-terms`, `terms reveal`

`impulse decode <txid> --node <url> --from-block <hash> [--with-terms <terms-file>]` (`spec/CLI.md`, decode). A v4 vault input decoded without terms is reported as: template v4 vault, commitment, authority key, entry (settle or refund), proof present, "terms hidden". It is not an error (no code). With `--with-terms`:

1. Decode the file as terms v4 (`ZK_H_TERMS_VERSION`, then v1's `TERMS_*` codes), run the structure checks.
2. For each v4 vault input, instantiate the vault for leg 0 and leg 1 from the terms and compare script hashes with the input's: neither matches is `ZK_H_TERMS_MISMATCH`; a script that is not template v4 is `ZK_H_NOT_V4_VAULT`.
3. Reconstruct the view of the accepted transaction from the node's data and run the `terms-core` tag functions natively on it. Print each tag with pass or fail; the first failure is `ZK_H_STATEMENT_FALSE` naming the tag. This repeats what the guest proved, without a proof, so a reader needs no prover to check a revealed trade.
4. Print the terms summary of v1's `verify` for the reconstructed trade, the fixed texts of 22.11, and that the check is bound to the scriptPubKeys the node reports.

`impulse zk terms reveal --terms <file> --leg <0|1>` prints the commitment and vault address of a leg, so a party can show a counterparty, a verifier or the authority what a file commits to before anything is funded. `impulse zk verify` for v4 requires the terms file and BOTH vault addresses and refuses unless each is the v4 vault of the terms for its leg (`ZK_H_VERIFY_ADDRESS_MISMATCH`), as v3's does.

### 22.8 Error codes appended

Appended to `ERRORS.md` under `## ZK_ codes`, after code 26, in the same commit as the code and its frozen list. Meanings of v3's `ZK_PROVER`, `ZK_PROVER_IMAGE`, `ZK_IMAGE_ID_MISMATCH` (with `IMAGE_ID_V4`) and `ZK_TX_MASS` apply unchanged to v4; v1's `TX_` and `TERMS_` codes apply where the text above says so.

| # | Code | Raised by | Meaning |
| --- | --- | --- | --- |
| 27 | `ZK_H_TERMS_VERSION` | decode terms v4 | The version byte is not 4 |
| 28 | `ZK_H_TERMS_DIRECT` | structure v4 | Terms v4 name Direct settlement |
| 29 | `ZK_H_AUTHORITY_REQUIRED` | structure v4 | Terms v4 name no authority |
| 30 | `ZK_H_BLIND_INVALID` | structure v4 | `blind` is all zero |
| 31 | `ZK_H_ARTIFACT_INVALID` | v4 startup check | The embedded v4 artifact, `TEMPLATE_HASH_V4` or `IMAGE_ID_V4` cannot be used |
| 32 | `ZK_H_TEMPLATE_HASH_MISMATCH` | v4 startup check | The v4 template hash differs from the artifact's or from `TEMPLATE_HASH_V4` |
| 33 | `ZK_H_NOT_V4_VAULT` | decode | The script does not run template v4 |
| 34 | `ZK_H_STATE_MALFORMED` | decode | The state is not (commitment, authority key) |
| 35 | `ZK_H_NONCANONICAL` | decode | The script is not the v4 instantiation of its state |
| 36 | `ZK_H_TERMS_MISMATCH` | decode, verify | The terms' commitment for neither leg equals the vault's |
| 37 | `ZK_H_STATEMENT_FALSE` | prove, decode `--with-terms`, builders | A tag of 22.4 fails on the view; the message names the tag |
| 38 | `ZK_H_WITNESS_INVALID` | prove | A scriptPubKey or redeem script given does not open to its view item |
| 39 | `ZK_H_SHAPE` | builders, prove | `n_in` or `n_out` is not the layout of the terms, or a settle or refund would have more than eight inputs |
| 40 | `ZK_H_PROOF_MALFORMED` | settle and refund build, `ipst raw`, `submit` | A proof file or an IPST holds no usable proof: not 128 bytes, all zero bytes, another form of file, or a vault input still holds the zero placeholder of a plan |
| 41 | `ZK_H_PROOF_INVALID` | settle and refund build, `ipst raw`, `submit` | A proof file's journal is not the one the vault input builds, or the pinned engine refuses the vault input because the precompile refused the proof |
| 42 | `ZK_H_IPST_VERSION` | v4 IPST read | `ipst` is not 5 |
| 43 | `ZK_H_VERIFY_ADDRESS_MISMATCH` | verify | The offered address is not the v4 vault of these terms for its leg |
| 44 | `ZK_H_TERMS_FILE` | `terms new-hashed`, every v4 command that reads a terms file | The terms file cannot be read, is not exactly the lowercase hex of the canonical terms, or did not read back to the terms written |
| 45 | `ZK_H_CAP_OVERRIDE` | every v4 command that takes the cap arguments | The value-cap override flag was given; v4 never accepts it |

On-chain refusals: `ERRORS.md` gains `### Template v4: settle` (`[T1]` to `[T4]` and `[T8]`, the gate) and `### Template v4: refund` (`[T5]` to `[T7]` and `[T9]`, the gate), plus a table that gives each v1 tag its v4 home (script, or guest function of the same tag). `scripts/check-tag-parity-v4.sh` fails if any v1 tag of `### settle` or `### refund` has no row.

### 22.9 Test plan (exit: engine tests green; script size against v1 recorded)

All engine tests use kaspa-txscript at rusty-kaspa a41a333 with covenants enabled, mainnet parameters, the fixture KCC-20 tokens, and every input at its committed budget; files `tests/engine/v4_*.rs`. Receipts are real, made by the I20 prover pipeline on fixtures committed under `tests/engine/fixtures/v4/`.

Valid. Settle for KAS cash, KCC-20 cash and external cash (a receipt per vault input, each accepted); refund by the depositor of a revocable leg, by the depositor of an earmarked leg after expiry, by the counterparty, by the authority, for a KAS and a token leg. The v4 guest's receipt for each fixture also verifies in the engine against the value of `IMAGE_ID_V4`.

Invalid, each refused in the engine (the failing test of every script require):
- `[T1]` a vault at input 2; `[T2]` and `[T3]` each bound: one below, one above, one beyond the transaction's length; `[T4]` a wrong signature, a signature by another key; `[T5]` a wrong signature, a signer that did not sign; `[T6]` leg 2; `[T7]` each bound; `[T10]` and `[T11]` the cases of 22.15; `[H5]`, a guest tag, the cases of 22.16.
- The gate: one proof bit flipped; a proof of another vault; a receipt of another image ID (a forging guest that commits the same J without checking, and one that checks fewer tags); a proof for a transaction that differs from the one spent in exactly one J field, one test per field (value, scriptPubKey and covenant ID of an input and of an output, lock time, `n_in`, `n_out`, `cov_a`, `cov_c`, both counts, signer, leg, mode, authority, commit, vault scriptPubKey). The mutation run is recorded in `tests/engine/mutation-run-v4.txt`, and every J field must be caught.
- A settle given a refund's proof and the reverse (the mode byte).

Guest (host tests, `circuits/`): `guest_refuses_<tag>` for every tag of 22.4, each a witness that breaks that tag and only that tag, expecting `ZK_H_STATEMENT_FALSE` naming it; the exactness cases (token output one unit over or under, KAS cash output one sompi off, fee taken from a leg, a second input of the asset covenant, a minter escrow, an escrow owned by another vault, a delivery to another owner, a lock time one below `earliest_daa`, a refund by a stranger, an earmarked refund one score early); `guest_refuses_wrong_layout` for each shape.

Differential: every valid and invalid v1 settle and refund vector of `tests/engine/` is translated to terms v4 and run through the `terms-core` checker; the checker must accept exactly when v1's script accepts (`v4_differential_agrees_with_v1`). A divergence is a bug in the guest, never a documented difference (finding 2).

Vectors, in Python from this file alone via `scripts/vectors.sh`: `tests/vectors/terms_v4/` (the known answers of 22.2 and canonical bytes of fixtures for KAS, KCC-20 and external cash), `vaults_v4/` (both legs' addresses), `journal_v4/` (J bytes of each fixture).

Verifier: `decode --with-terms` accepts each fixture, refuses a terms file differing in one byte of `blind` with `ZK_H_TERMS_MISMATCH`, refuses a v1 vault with `ZK_H_NOT_V4_VAULT`, and names the failing tag on a mutated transaction; `fund build` refuses without a saved terms file; the wording check of 22.11 runs in `scripts/check-zk-text.sh`'s style with its own self-test.

### 22.10 Measured-cost method

Nothing below is quoted in user text before the files exist (section 10).

- Script size: `scripts/build-template-v4.sh` writes the compiled byte length of the v4 artifact, of v1 (2,938 with the placeholder state, `V2.md` section 3.2) and of v3 to `docs/measurements/v4-zk-units.txt`, with the silverc version and command line. Compared as bytes and as a ratio.
- Script units: the engine run reports the units each input consumed; recorded for settle (asset vault input, cash vault input) and refund, per cash kind, against the formula `units_v1 + 15,500,000 + h` per verification (section 10; modelled; the engine value replaces it).
- Mass: compute, storage and transient mass of each fixture transaction from the node's mass calculator at the pinned revision, against D63's caps. A settle carries two verifications, modelled at 310,000 grams of compute before the rest (section 10 arithmetic: 155,000 per verification, measured in source), so the caps are the test: a fixture shape whose compute exceeds 450,000 is refused as `ZK_TX_MASS` and the shape is not shipped.
- Fee: at 100 sompi per gram of fee mass (`TRANSACTIONS.md`), reported from the measured mass.
- Proving: `circuits/scripts/measure-proving.sh` of 14.2 with the terms guest added: guest cycles and segments, wall time of execution, STARK proving and the Groth16 step, peak memory of host and container, five runs on an idle machine, raw data under `docs/evidence/i21-proving-<date>/`. Go or no-go as 14.2, per receipt; a settle needs two receipts and the report states the sum. A no-go is written under Blockers and no v4 vault is funded.
- The raw data and the method are published with any figure; figures are for that laptop and those versions.

### 22.11 User-facing wording (normative for v4)

Scope as section 9.5, with `<!-- impulse-v4 -->` markers in the README. The setup line and the value-cap line of 9.5 apply to v4 as they stand. Fixed texts of v4, on their own lines:

- Disclosure line: "The chain shows only a commitment to the terms until a spend. Vault values, the escrowed token, the authority's key, the funders and the outputs of a settle or refund are public. Anyone holding the terms file can show the terms."
- Loss line: "Settle and refund both need the terms file. Keep a copy before funding."
- Soundness line: "A flaw in the proof check could let funds leave a v4 vault. Keep value at or below the cap."

Banned in scope, in addition to 9.5's list: `hidden`, `secret`, `untraceable`, `invisible`, `shielded`, `stealth`, `mixer`. Permitted names: "hashed-terms vault", "commitment to the terms", "terms revealed by the parties".

### 22.12 Self red team of I21 (13 October 2026)

| # | Finding | Area | Rating | Resolution |
| --- | --- | --- | --- | --- |
| 1 | In v3 a forged receipt only bypasses a gate. In v4 the proof carries the whole of settle and refund, so a break of the proving system's setup or of the guest lets someone claim terms with their own destinations and take the funds. A settle also needs the authority's signature; a refund does not | Technical | HIGH | Flagged, decision D100: the assumption is disclosed (soundness line, setup line); the authority signature is mandatory on settle, so a forger alone cannot settle; values are held at the D4 cap and the builders refuse the override flag (`ZK_H_CAP_OVERRIDE`); no use above the cap. Open until the owner accepts D100 |
| 2 | About thirty v1 requires move from script into a guest. One missed or divergent check is a silent weakening against v1 | Technical | HIGH | Resolved in design: tag-for-tag table with a CI check (`check-tag-parity-v4.sh`), `guest_refuses_<tag>` for each, and the differential test against every v1 engine vector (22.9). Open until those are green |
| 3 | Proving is slow and a settle needs two receipts; a refund waits on a prover | Operational | HIGH | Resolved in design: measured with the 14.2 method and its bound before any funding; refund proofs can be built before expiry (22.6); a no-go is a Blocker, not a weaker design. Open until `docs/evidence/i21-proving-<date>/results.txt` shows a go |
| 4 | Loss of the terms file strands both vaults, since settle and refund both need the terms | Operational | HIGH | Resolved in design: `fund build` writes the file, reads it back, and refuses to fund otherwise (`ZK_H_TERMS_FILE`); `verify` and `address` need the file, so each party and the authority hold a copy before funding; the loss line is fixed text. Open until the funding test is green. The residual risk (all copies lost) is disclosed, not removable |
| 5 | Two Groth16 verifications plus token transfers may exceed D63's compute cap or be relayed by few nodes | Technical | HIGH | Resolved in design: measured per shape (22.10); a shape over the cap is refused with `ZK_TX_MASS` and not shipped; the CLI states that the settle is heavier than older nodes accept (section 10 wording). Open until the measurements are committed |
| 6 | Guessing attack on the commitment: with the parties, token and likely amounts known, the 8-byte nonce is too short to stop testing guesses | Technical | MEDIUM | Resolved in design: 32 random bytes of `blind`, drawn by the tool, no flag to set it; vectors use fixed values only in fixtures |
| 7 | "Hidden terms" read as concealment, including from regulators or sanctions screening; privacy claims in copy | Legal, commercial | HIGH | Flagged, decision D101: v4 carries no privacy claim (22.11 banned words and fixed texts); a mandatory authority always sees the terms it signs for; `decode --with-terms` lets any holder of the file verify a trade; no marketing; values capped; follows 9.5 and D68 as they stand. Open until the owner accepts D101 |
| 8 | The requirement says "parties stay hidden until the parties reveal"; a settle publishes the authorizers' keys (`[S8]` returns), the KAS proceeds scriptPubKey and the lock time, and the funders are visible at funding | Commercial | HIGH | Resolved in design: 22.4 states exactly what is public at each moment; the disclosure line says it; the I21 record states that the requirement's sentence holds for the period before a spend only |
| 9 | The authority is a trust and liveness dependency: it sees the terms, can refuse to sign a settle, and a settle cannot happen without it | Commercial | MEDIUM | Disclosed in 22.2 and 22.11; refund does not need it, so funds are not held by it |
| 10 | A receipt is valid for a second UTXO at the same address | Technical | MEDIUM | Accepted as in section 8: the statement is equally true for it and every other check still applies |
| 11 | Two proofs per settle double fee and proving time, which limits the trades v4 suits | Commercial | MEDIUM | Disclosed with measured figures once they exist (22.10); v4 is positioned as experimental and capped |
| 12 | Trust base is I20's: RISC Zero setup, Docker prover image, patched host crate | Technical | MEDIUM | Same records and checks as I20 (sections 4, 14.1, 16), the second guest added to the image-ID reproduction in `scripts/build-guest.sh` |
| 13 | Language items of 22.5 (integer encoding, covenant ID of a plain input, loops) may not compile as designed | Technical | LOW | Stop-and-Blocker rule stated in 22.5; the journal layout does not bend to the compiler |

### 22.13 Decisions

| D | Question | Default | Owner answer needed |
| --- | --- | --- | --- |
| D99 | Shape of template v4 | Per-leg commitment, mandatory authority, a 32-byte `blind` in terms v4, both vaults prove, refund proof-carrying, guest 2 with its own image ID (22.2 to 22.6) | no |
| D100 | Exposure when the proof system's soundness fails | Accepted under the D4 cap only, the soundness line and the setup line, no override flag | yes |
| D101 | Positioning of v4 | No privacy claim, no marketing, fixed texts of 22.11, the rules of 9.5 and D68 as they stand | yes |

### 22.14 As built (I21, 15 October 2026)

What the implementation does where the text above left a choice, each point decided and none a weaker check.

1. **Builders.** `impulse_core::zkh` (feature `zk-hashed`) holds `fund_kas`, `fund_kcc20`, `settle` and `refund` over `ValidatedTermsV4`, the v3 builders' layouts and exact-amount checks over the v4 vaults, and `IpstV4` (IPST version 5). A settle has a vault input at 0 and, for KAS and KCC-20 cash, at 1, each with its own proof; a refund has one. The fee inputs and the change come after the view and are not in it, so the journal of a vault input does not depend on the fee or on the proofs.
2. **IPST version 5.** `IPST.md`'s document with `"ipst": 5` and the canonical terms v4 in `terms`. There is no separate proof key: each vault input's 128-byte proof is in its signature script, where the engine reads it, so a document cannot disagree with itself about it. A proof of 128 zero bytes is the placeholder of a plan for the prover. A plan can be read, signed and merged; `finalize` refuses it (`ZK_H_PROOF_MALFORMED`). A v1 reader refuses version 5 as `IPST_UNSUPPORTED_VERSION`; this reader refuses another version as `ZK_H_IPST_VERSION`. Vectors: `tests/vectors/ipst_v5/`.
3. **Order of work.** `settle build` and `refund build` without proof files write a plan; `zk witness` writes the witness file of each vault input (`terms_core::Witness`, the file `impulse-zk-prove-terms --witness` reads); each is proved on the party's machine; the build is repeated with `--proof` and `--proof-cash`. Each proof file is checked at the build: its journal must equal the journal the vault input builds (`ZK_H_PROOF_INVALID`) and its image ID must be `IMAGE_ID_V4` (`ZK_IMAGE_ID_MISMATCH`). `impulse-zk-prove-terms --verify` runs a proof file in the pinned engine's gate on its own.
4. **When the engine runs.** The vault checks the signature before the proof (`[T4]`, `[T5]` precede the gate, 22.5), so a run without the signatures cannot reach the gate. The builders therefore run the statement of `terms-core` natively on the view of every vault input they made (`ZK_H_STATEMENT_FALSE`), and the pinned engine runs every input of the signed transaction at `IpstV4::finalize`, which `ipst raw` and `submit` call: a vault input the precompile refuses is `ZK_H_PROOF_INVALID`. The table of 22.8 names these places.
5. **Budgets.** A vault input's compute budget covers the precompile's cost for the key's five public inputs (15,500,000 script units, 3.4) and 200,000 units for the rest (measured at 109,216 to 121,219 units in the probe build, 22.10, 22.15). The builders refuse a transaction over the caps of D63 (`ZK_TX_MASS`). Measured masses and fees: `docs/measurements/v4-zk-units.txt`.
6. **No override.** Every v4 command that takes the cap arguments refuses the override flag (`ZK_H_CAP_OVERRIDE`). The cap applies to funding, where new value enters (`CLI_VALUE_CAP_EXCEEDED`). Settle and refund of an already funded vault are never blocked by it: `settle build`, `refund build` and `ipst sign` of a settle or refund print a `warning:` line on the notes stream (stderr) and go on, because anyone can fund a vault address above the cap, and `IMPULSE_MAX_VALUE` can be lowered after funding, and with no override a refusal would lock the funds.
7. **CLI.** `spec/CLI.md`, "zk, template v4". The commands route on the terms file (hex for v4, JSON for v3) and on the IPST version, so one command name serves both templates and no v3 behaviour changes. `zk status`, `zk receipt` and `zk prove-args` have no v4 form.
8. **Wording.** The fixed texts of 22.11 are printed by every v4 command that shows terms; the README v4 section carries them between `<!-- impulse-v4 -->` markers; `scripts/check-zk-text-v4.sh` checks the CLI source and that section. User text states the cap condition as: values above the 10 KAS cap are refused unless `--i-accept-the-risk` is passed (never for v4).

### 22.15 The covenant ID of every input (known limitation L20)

Owner decision (18 October 2026): the vaults refuse a token of another covenant. Owner decision (19 October 2026): the fixed templates replace the earlier ones in place.

Finding. kcc20.sil (silverscript v1.0.0) lets a token whose owner is a script hash move in any transaction that also spends an input at that script hash's address (`docs/security/KNOWN-LIMITATIONS.md`, L20). A template that constrained covenant IDs only where the layout names a token would leave the rest open: the guest reads the covenant IDs at the escrow slots of the view (`[E1]`, `[E2]`, `[R8]`, `[R9]`) and nothing of the view's other inputs, and the script would read none of the inputs after the view. A KCC-20 token of another covenant owned by a v4 vault's script hash (for example the buyer's cash token sent to the asset vault's address) could then ride along in any settle or refund of that vault, at a fee position or at a vault slot of the view, and go to any output the builder of the spend chooses.

Rule. In a settle or refund of a template v4 vault, every input outside the layout's escrow slots carries no covenant ID, and each escrow slot carries the covenant ID the layout names for it, so no input carries a covenant the layout does not name. Vault and authorizer slots carry none, which the builders already require (a vault UTXO with a covenant ID is `TX_NOT_AT_VAULT`, a fee input with one `TX_KAS_INPUT`).

| Entry | Input `i` | `OpInputCovenantId(i)` must be |
| --- | --- | --- |
| settle | the asset escrow slot: 1 when `nIn = 2` (external cash), else 2 | `covA` |
| settle | 3 | `covC`: the cash escrow for KCC-20 cash; for KAS and external cash the guest requires `covC` to be zero (`[H4]`, for both legs), so input 3, a fee input there, carries none |
| settle | every other input | 32 zero bytes |
| refund | 1, when `nIn = 2` | `cov` |
| refund | every other input | 32 zero bytes |

An input without a covenant reads as 32 zero bytes (measured, source: `crypto/txscript/src/opcodes/mod.rs:1500-1514`, `utxo.covenant_id.unwrap_or(ZERO_HASH)`).

Where it runs: in the script, not in J. Reasons:

1. The script can read the covenant ID of any input of the transaction, view or not (`OpInputCovenantId(i)`, same source). J holds only the view. Checking the inputs after the view in the guest would put every fee input into J (72 bytes each, hashed by the script), change the journal layout, the guest and `IMAGE_ID_V4`, and make J depend on the fee inputs.
2. The script already holds `nIn`, `covA`, `covC` and `cov`, and the guest binds each of them to the committed terms (`[H4]` and the shape check), so the script knows the slots without the terms.
3. J and the guest do not change, so `IMAGE_ID_V4` and every receipt of the terms guest stay as they were.

Rejected: the view part in the guest and the fee part in the script (two places and a new image ID); a count of covenant inputs instead of a loop (the engine counts only the inputs of one named covenant, `OpCovInputCount`, measured, source: same file, 1517-1531, so a covenant nobody names cannot be counted).

Bound. silverscript v1.0.0 has bounded loops only, and the compiled loop refuses a range longer than its bound before its body runs (measured, source: `silverscript/silverscript-lang/src/compiler/for.rs`, the require the lowering inserts, `end - start <= max_iterations`). Template v4 sets `MAX_INPUTS = 8`: a settle or refund has at most eight inputs, so at most four fee inputs in a settle with KCC-20 cash, five with KAS cash, six with external cash or in a refund. The builders refuse more as `ZK_H_SHAPE` before anything is signed. The bound of eight is what the silverscript v1.0.0 loop lowering emits (`for.rs`) and is pinned by the template hash; any silverscript bump must re-run the nine-input refusal tests (`v4_t10`, `v4_t11`). Both checks run before the gate. Size, units and masses: measured, `docs/measurements/v4-zk-units.txt`; the comparison with the template before this check is `docs/evidence/template-fix-2026-10-19/v4-1-covenant-check.txt`.

Files: `contracts/impulse_vault_v4.sil`, `contracts/compiled/impulse_vault.v4.json`, `contracts/TEMPLATE_HASH_V4`; `scripts/build-template-v4.sh` rebuilds and checks them.

What remained after this section (a token of a leg's own covenant at the other leg's vault address standing in for that leg's escrow in a settle that omits the other vault) is closed by 22.16 (I26): no case of L20 remains in template v4.

Tests (engine, kaspa-txscript at rusty-kaspa a41a333, covenants enabled). On the probe and on the shipped template, each against an accepted control that differs only in the fault: `[T10]` a token of another covenant at a fee position, a second input of the asset covenant at a fee position, a covenant ID on a vault slot, the asset covenant at input 3 of a KAS cash settle, nine inputs; `[T11]` the L20 case (the cash token owned by the asset vault, moved by the asset leg's refund), a covenant ID on the fee input, the leg's covenant at input 1 of a one-input view, nine inputs; and fee inputs without a covenant accepted up to eight inputs. With a real receipt (`tests/engine/v4_live.rs`): the L20 refund carries a receipt the terms guest made (its view is the plain refund's, so the statement holds and the guest proves it) and the script refuses it before the gate. Mutation run: `tests/engine/mutation-run-v4.txt`. Vectors: `tests/vectors/vaults_v4/`, `journal_v4/` and `ipst_v5/`.

Red team (18 October 2026):

| # | Finding | Area | Rating | Resolution |
| --- | --- | --- | --- | --- |
| 1 | The input-3 rule of `[T10]` takes `covC` from the entry argument; for KAS and external cash it is safe only because the guest refuses a non-zero `covC` | Technical | MEDIUM | Resolved: `[H4]` runs before the leg branch in both legs' statements, so no receipt exists for a non-zero `covC` there; `guest_refuses_h4_covenant_ids_and_layout` covers KAS cash for both legs and external cash, and the J field `cov_c` is bound by the gate |
| 2 | A spend that needs more than eight inputs (many small fee UTXOs) is refused | Operational | LOW | The builders refuse it before signing (`ZK_H_SHAPE`); consolidate the fee UTXOs first |
| 3 | A token of a leg's own covenant at the other leg's vault can stand in for that leg's escrow in a settle that omits the other vault | Security | MEDIUM | Resolved by 22.16 (I26): a settle with KAS or KCC-20 cash must spend both vaults of the terms, each of which admits only its own escrow |
| 4 | A UTXO at a v4 vault address that carries a covenant ID (only a covenant transaction makes one) cannot be spent by settle or refund | Operational | LOW | The builders never fund one (`TX_NOT_AT_VAULT`); what a covenant sends to a vault address is the sender's own error, it stays put rather than moving with a vault spend |

### 22.16 The other leg's vault in a settle (I26, known limitation L20 closed)

Owner decision (19 October 2026, I26): v0.4.0 ships with no known open template defect; the residual of L20 is closed in every template, and the fixed templates replace the earlier ones in place. This section changes the terms guest, `IMAGE_ID_V4` and, through that constant only, template v4 and `TEMPLATE_HASH_V4`. The journal layout and the script's requires do not change.

Finding (the residual of 22.15). A v4 vault's settle statement checks its own escrow and both deliveries, not that the other leg's vault is spent. A token of a leg's own covenant owned by the other vault's script hash (misdirected funding) could therefore stand in for that leg's escrow in a settle that spends one vault and omits the other: KCC-20 lets the token move because an input at its owner's address is spent, `[T10]` admits the covenant at that leg's escrow slot, and the statement of the vault that is spent does not look at the other leg's escrow. Pinned before I26 by two engine tests of `tests/engine/v4_script.rs`, now refusal tests.

Rule `[H5]` (guest, settle, KAS cash and KCC-20 cash). The view's input `1 - leg` is the template v4 vault of the same terms for the other leg: its `sha256(spk)` equals that of the P2SH of the redeem script of template v4 with state (`commit(T, 1 - leg)`, T's authority key). `[S1]` puts this vault at input `leg`, so the two vaults are inputs 0 and 1, each at its canonical slot. External cash has no cash vault (`n_in = 2`, input 1 is the asset escrow): `[H5]` does not apply and the asset vault's settle is unchanged. Refunds do not change (red team below).

How the guest knows template v4. The guest cannot embed template v4's bytes: the template embeds `IMAGE_ID_V4`, which is a hash of the guest, so each would have to contain the other's hash. The witness therefore carries this vault's own redeem script `R`, keyed by this vault's input index (`R` is public: every spend of the vault reveals it in its signature script). The guest requires:

1. `P2SH(BLAKE2b-256(R))` equals `J.vault_spk` byte for byte, and `R[1..67]` is the state as silverc v1.0.0 lays it out for template v4: `0x20 || J.commit || 0x20 || J.authority` (state span offset 1, length 66, read from `contracts/compiled/impulse_vault.v4.json`, `state_span`; measured). Otherwise `ZK_H_WITNESS_INVALID` naming `[H5]`.
2. `R'` is `R` with bytes 2 to 33 replaced by `commit(T, 1 - leg)`. `sha256(P2SH(BLAKE2b-256(R')))` equals the spk hash of view input `1 - leg`. Otherwise `ZK_H_STATEMENT_FALSE` naming `[H5]`.

Why this is the other leg's vault. `J.vault_spk` is `this.activeScriptPubKey`, so `R` is the script that runs, an instance of template v4; another `R` with the same P2SH would be a second preimage of BLAKE2b-256. `[H1]` binds `J.commit` to `commit(T, leg)` and `[H3]` binds `J.authority` to T's authority, so `R'` is exactly `VaultV4::of_terms(T, 1 - leg)`, the vault `impulse zk terms reveal --leg` prints. A template whose state span moved would fail step 1 on every settle (fail closed); the offset is pinned by `v4_template_state_span_is_the_guests` in `tests/engine/v4_template.rs`. Why not in the script: the script holds only the commitment of its own leg and cannot compute the other leg's without the terms; the guest has them.

Where it runs: in `settle` of `circuits/terms-core/src/statement.rs`, after `[S1]` and before the escrow checks, for both legs.

Red team (19 October 2026), each case under the fix:

| # | Case | Outcome | Rating after |
| --- | --- | --- | --- |
| 1 | Misdirected token: a token of leg L's covenant owned by the other vault V' | A settle must spend V' at its slot (`[H5]`); V''s statement admits only an escrow of its own covenant owned by itself (`[E1]` to `[E4]`), and this vault's `[E4]` refuses an escrow owned by V'; `[T10]` admits the covenant at no other slot. A refund of either vault admits only the leg's own covenant (`[T11]` with `[H4]`) owned by that vault (`[R12]`). So no v4 spend moves the token: it stays at V''s address. It cannot be taken; it is also not recoverable through Impulse | Closed (security). Operational LOW: a misdirected token is stranded; send each leg only to its own vault address |
| 2 | Missing vault: a settle that spends one vault and puts another input at the other slot | `ZK_H_STATEMENT_FALSE` `[H5]`: no receipt | Closed |
| 3 | Duplicate vault: a second UTXO of this vault at the other slot | Its scriptPubKey is this vault's, not `R'`'s (the two legs' commitments differ): `[H5]` refuses. A UTXO of either vault at any input other than 0 or 1 fails `[T1]` in its own script | Closed |
| 4 | Another trade's vault at the other slot (L8, cross-trade mixing) | `R'` is built from this vault's own terms, which include the 32 random bytes of `blind`: a vault of other terms has another commitment and another address, so `[H5]` refuses. Two v4 vaults settle together only if they are the two vaults of one terms file | L8 closed for template v4 |
| 5 | External cash | No cash vault; `n_in = 2`; `[H5]` does not apply; nothing changes | Unchanged |
| 6 | Refunds | The residual does not exist in a refund: `[T11]` admits a covenant only at input 1 of a two-input view, `[H4]` makes it the leg's own, `[R12]` makes its owner this vault. No change | Unchanged |
| 7 | Tranches and linked trades | Built on templates v1 and v2 only (`impulse_core::linked`); no v4 form exists | Not affected |
| 8 | A prover that omits `R` or gives another script | `ZK_H_WITNESS_INVALID` `[H5]`, no receipt; `R` is public, so an honest prover always has it (the builders put it in the witness) | Closed |
| 9 | Receipts and vectors made before I26 | They carry the old `IMAGE_ID_V4`; the new template refuses them at the gate. Nothing has shipped with the old hashes (owner decision, I26); fixtures, vectors and records are regenerated | Accepted |
| 10 | Cost | The script is unchanged but for the `IMAGE_ID_V4` constant, so size, units and mass do not change; the guest reads the 3,598-byte redeem script from the witness and, in a settle with a cash vault, computes two more BLAKE2b-256 over it. Measured (`docs/measurements/v4-zk-units.txt`, PROVE lines, user cycles of the receipts `tests/engine/v4_live.rs` makes, before and after I26): settle KAS cash 2,233,589 to 3,544,796 (asset vault) and 2,091,513 to 3,402,715 (cash vault); KCC-20 cash 2,713,850 to 4,025,401 and 2,733,198 to 4,044,756; external cash 1,945,067 to 2,356,213; refunds about 410,000 more each (the builders' witness carries the vault's redeem script there too). Script sizes, units and masses are unchanged | Accepted |

Tests. Guest (host, `circuits/terms-core/tests/statement.rs`): `guest_refuses_h5_other_vault` (for both legs of KAS and KCC-20 cash: a plain input at the other slot, the other leg's vault of other terms, a duplicate of this vault, the other leg's vault under another authority key), `guest_refuses_h5_witness` (no `R`, an `R` that does not open `J.vault_spk`, the other leg's `R`, an `R` whose state differs from J's in each push byte and at each end of each field, an `R` too short for the state) and `h5_does_not_apply_to_external_cash_or_refunds`. Engine (kaspa-txscript at rusty-kaspa a41a333, covenants enabled): `tests/engine/v4_script.rs` holds the two residual cases of 22.15 and, for KAS cash, each vault omitted and a duplicate vault; the script does not change, so the probe's spend runs, and the statement over its view refuses at `[H5]`, so no receipt exists for it. `tests/engine/v4_live.rs`: in the real-receipt KCC-20 cash settle, the residual case carries the honest settle's receipt of the asset vault and the gate refuses it (input 1 of the view differs), and `impulse-zk-prove-terms` refuses to prove its witness (`ZK_H_STATEMENT_FALSE [H5]`). `tests/engine/v4_template.rs` (`v4_template_state_span_is_the_guests`) pins the state offset the guest reads. Differential (22.9): a v1 view holds v1 vaults, which have no v4 redeem script, so the shadow check runs the statement without `[H5]` (`statement_without_h5_for_v1_differential`, used by that test only) and asks the same rule of the v1 vaults itself: the input at the other slot is this trade's other v1 vault. Mutation run: `tests/engine/mutation-run-v4.txt`, guest section (each `[H5]` check of `statement.rs` and the slot it compares).
