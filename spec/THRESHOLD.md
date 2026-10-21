# Impulse threshold settlement authority (FROST)

Increment I13. Companion to `IMPULSE-SPEC.md` ("Terms": `authority_key`; "On-chain contract": settle check 6 and refund check 1). This file defines how a t-of-n group of key holders acts as one settlement authority, why no single party or single compromised share can settle, how key generation and signing run, and the `THRESHOLD_*` refusal codes. Reference implementation: `crates/impulse-core/src/threshold/`. Engine test: `tests/engine/threshold.rs`. CLI: `crates/impulse-cli/src/{frost.rs,keygen.rs,signing.rs}`, with the offline end-to-end test `crates/impulse-cli/tests/frost.rs`.

Phase 1 built the library, this document and the engine test. Phase 2 adds the byte encodings, the signing entry points over a transaction input, and the CLI commands `impulse frost keygen`, `sign` and `aggregate` over IPST (section "CLI"). Every signature is made by the key holders, not by anyone else.

## What the vault sees

- One x-only key in `authority_key` and one signature in `authSig`: 64 bytes of BIP-340 Schnorr signature followed by the sighash type byte (`SIG_HASH_ALL`, 0x01). The vault checks `checkSig(authSig, authorityKey)` (`[S6]`), exactly as for a single key.
- No contract change, no template change, `TEMPLATE_HASH` unchanged. On chain, a FROST group key and its signatures have the same form as a single key and its signatures.
- The authority may also sign refunds (refund check 1, `[R1]`). A group signs a refund the same way. The engine test (phase 1) covers settles only; the CLI tests (phase 2) also sign and aggregate a refund of the asset leg by the authority, and verify its signature under the authority key.

## Why no single party or single compromised share can settle

Measured (engine test `tests/engine/threshold.rs`, real kaspa-txscript at rusty-kaspa a41a333 with covenants enabled, and `threshold::tests` in impulse-core):
- A settle signed by any 2 of a 3-party group is accepted at every input, for KAS, KCC-20 and external cash, for each of the three signing sets.
- A lone party gets no signature from the library: signing and aggregating with one commitment are refused (`THRESHOLD_TOO_FEW_SIGNERS`).
- A lone share aggregated as if it were the whole signature (the signing set's group commitment R with that party's share z1 where z1 + z2 belongs) is refused by `[S6]` at every vault input, beside an accepted 2-of-3 control on the same trade.
- A valid 2-of-3 signature of another group is refused by `[S6]`: the vault binds the aggregate key in its terms, not the act of reaching a threshold.

Asserted by the cryptography, not proven here:
- Shamir secret sharing: any t shares determine the group secret, and fewer than t reveal nothing about it.
- FROST unforgeability: an adversary controlling fewer than t parties cannot produce a signature under the group key, and the DKG never forms the group secret in any one place. Sources: Komlo and Goldberg, "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" (2020), for key generation and signing, and RFC 9591 for signing. Both cover the base scheme. RFC 9591 specifies FROST(secp256k1, SHA-256) with its own challenge hash. Neither source covers the BIP-340 adaptations that frost-secp256k1-tr makes (the `BIP0340/challenge` challenge over x-only R and key, even-Y negation of the key and the nonce, the TapTweak applied after key generation), and the maintainers' statement of what their third-party review covered excludes that crate (see "Library"). For the ciphersuite Impulse uses, the property is asserted from the base scheme only.

What the vault still bounds, whoever signs: outputs are script-enforced, so even t colluding parties can only settle the agreed trade or refund it home. They cannot redirect proceeds. In external-cash mode the settle delivers the asset against an off-chain payment that the script never checks (IMPULSE-SPEC, "External cash leg"), so t colluding parties together with the buyer can settle the asset to the buyer unpaid.

What a threshold does not fix:
- t colluding parties are the full authority. In external-cash mode that includes delivering the asset without payment (above): the seller's protection in that mode is the honesty of every t-subset of the group.
- Liveness: if more than n - t parties are unavailable, the authority cannot settle. The legs still refund (in earmarked mode the depositor waits for expiry; the counterparty can refund at any time). In external-cash mode a buyer who has paid off chain then depends on an off-chain remedy.
- Losing more than n - t shares loses the authority for good; trades already funded refund as above.

## Group shape and parties

- A group is t-of-n with 2 <= t <= n (`THRESHOLD_PARAMS`). t = 1 would let one share settle alone.
- Parties are numbered 1..=n (`THRESHOLD_PARTY` otherwise). The FROST identifier of party i is the scalar i.

## Key generation

FROST distributed key generation (`frost_core::keys::dkg`, three rounds). No dealer: no party and no coordinator ever holds the group secret. Each party runs its own rounds on its own machine.

1. `dkg_round1(shape, me)`: the party samples its secret polynomial and keeps a round-1 secret in memory. It broadcasts a round-1 package: the commitment to its polynomial and a proof of knowledge of its constant term, bound to its identifier. The broadcast must be authenticated and consistent: every party must receive the same package from each sender.
2. Round-1 confirmation, before any round-2 package leaves a party: every party computes `dkg_round1_digest(shape, packages)` over the round-1 packages of all n parties, its own included, and compares it with every other party's out of band. It sends no round-2 package until all n digests are equal. A sender that broadcast different packages to different parties shows up here as a differing digest.
3. `dkg_round2(secret, round1)`: given the round-1 package of every other party, keyed by sender, the party verifies each proof of knowledge (`THRESHOLD_DKG_CULPRIT`, round 2, naming the sender). It keeps a round-2 secret in memory and produces one round-2 package per other party. A round-2 package carries a secret share for its recipient alone: it needs a confidential and authenticated transport.
4. `dkg_round3(secret, round1, round2)`: given the same round-1 packages and the round-2 package each other party sent it, the party verifies every share against its sender's commitment (`THRESHOLD_DKG_CULPRIT`, round 3, naming the sender) and obtains its key share and the group key.
5. Group key confirmation: every party compares its `GroupKey::fingerprint()` with every other party's out of band. Only an authority key whose fingerprint all n parties hold goes into the terms.

Each round must receive exactly one package from every other party: a missing package, the party's own package, or a package from an identifier outside the group is refused (`THRESHOLD_DKG_PACKAGES`, listing the missing and unexpected senders). The round-1 digest needs the package of every party, own included (`THRESHOLD_DKG_PACKAGES`, round 1).

Why the authority key alone is not a confirmation. The proof of knowledge covers only the constant term C0 of a sender's commitment. A sender can give one recipient its honest commitment and another the same C0 and proof with a higher coefficient changed, plus the matching round-2 share. Every round then succeeds and every party derives the same authority key, but the parties hold different public shares: some honest t-subsets can never sign, and the aggregator names an honest party. Measured in `threshold::tests::round1_equivocation_keeps_the_authority_key_but_changes_digest_and_fingerprint` (2-of-3, party 3 equivocates towards party 2: authority keys equal; digests and fingerprints of parties 1 and 2 differ; {1, 2} cannot sign; the control run agrees everywhere and every pair signs). If all n fingerprints are equal, every party holds the same public shares; they are points of one committed polynomial of degree t - 1 (n >= t points fix it), and each party's share was checked against its own point in round 3, so any t parties can sign.

Blame: `THRESHOLD_DKG_CULPRIT` and `THRESHOLD_SHARE_INVALID` name the party whose package or share failed against this party's view of the transcript. They identify a misbehaving party reliably only once the round-1 digest and the group fingerprint are confirmed at all n parties. Before that, an equivocating sender can make an honest party look at fault.

Encodings, both keyed blake2b-256 (32-byte digest):
- `dkg_round1_digest`, key `Impulse/thresholdround1/v1`: threshold and parties (u16 big-endian each), then for each party in order its identifier (u16 big-endian), the number of commitment coefficients (u16 big-endian), each coefficient (33-byte SEC1) and its proof of knowledge (64 bytes).
- `GroupKey::fingerprint`, key `Impulse/thresholdgroup/v1`: threshold and parties (u16 big-endian each), the authority key (32 bytes), then every party's public share (33-byte SEC1) in party order.

`impulse frost keygen` shows the round-1 digest and writes no round-2 package until the party types back the digest every party reported; it shows the fingerprint with the authority key and writes no share file until the party types back the fingerprint every party reported (section "CLI").

frost-secp256k1-tr adds a BIP-341 tweak with an unspendable script path to the DKG output (Q = P + int(hash_TapTweak(bytes(P)))G), against rogue tapscript tweaks. The authority key is the x coordinate of Q. Kaspa checks the key in the terms, so the tweak changes nothing for the vault.

## Signing

The message is the 32-byte Kaspa Schnorr sighash, `SIG_HASH_ALL`, of one vault input (`calc_schnorr_signature_hash`, rusty-kaspa a41a333). One signing session per vault input: a settle with KAS or KCC-20 cash has two vault inputs (0 and 1), with external cash one. The library does not enforce how the digest was made: `sign` takes any 32 bytes, and `[S6]` is `checkSig(authSig, authorityKey)` with no check of the sighash type byte. Each signer must therefore compute the `SIG_HASH_ALL` sighash itself from the transaction it approves and must not sign a digest handed to it; a digest of a weaker sighash type (for example `SIG_HASH_NONE` with `SIG_HASH_ANY_ONE_CAN_PAY`) would authorise less than the whole transaction. `sign_input` and `aggregate_input` take the transaction, the UTXO entries it spends and an input index, and compute that input's `SIG_HASH_ALL` sighash themselves with the I5 code (`impulse_core::tx::sighash`); they take no digest. They are the only signing and aggregation entry points the CLI calls (a source guard in the CLI tests checks it). `sign` and `aggregate` over a raw 32-byte digest stay for tests. An input index outside the transaction, or entries that do not match its inputs one for one, is `THRESHOLD_INPUT`.

1. `commit(share)`: fresh nonces from the OS RNG, kept in memory, and their public commitment, sent to the aggregator.
2. `sign(share, nonces, sighash, commitments)`: the signing set is the commitments, keyed by party, the signer's own included. Refused if a party is outside the group (`THRESHOLD_PARTY`), if the set has fewer than t parties (`THRESHOLD_TOO_FEW_SIGNERS`), or if the signer's commitment is absent or is not the commitment of the nonces it holds (`THRESHOLD_SIGNER_NOT_IN_SET`). The nonces are consumed: one commitment signs one message.
3. `aggregate(group, sighash, commitments, shares)`: anyone holding the group key can aggregate; it needs no secret. Refused if the set is malformed as above, if the shares do not come from exactly the parties of the set (`THRESHOLD_SHARES_MISMATCH`), or if the shares do not form a valid signature (`THRESHOLD_SHARE_INVALID`). FROST sums the shares and checks the sum under the group key first; only if that fails does it check each share against its party's public share, and every party whose share fails is named (frost-core `aggregate_custom` with `CheaterDetection::AllCheaters`). Shares that are individually invalid but sum to a valid signature are not refused; the vault sees only the sum. Blame is reliable only after key generation confirmation (see "Key generation"). The aggregate is then verified under the authority key with libsecp256k1, the verifier the Kaspa engine uses (`THRESHOLD_SIGNATURE_INVALID`), before it is returned. `authSig` is the 64 bytes followed by 0x01.
4. `verify(authority_key, sighash, signature)`: the BIP-340 check alone (`THRESHOLD_KEY_INVALID` for a key that is not an x-only point).

Any t or more of the n parties can form a signing set.

### A signed settle does not expire

A signed settle is a bearer instrument. The authority's signature covers the transaction's inputs (outpoints) and outputs, and the contract checks only a lower time bound (`[S3]`): there is no upper bound, and nothing revokes a signature once it exists. Whoever holds the signed transaction can broadcast it at any time the vault inputs are still unspent, including after `expiry_daa`, when the seller's refund also opens. Example, external cash: the authority signs a settle after it sees the off-chain payment, and the buyer keeps the signed transaction. The payment is then reversed (card or bank). The authority cannot revoke the signature; it can only race its own refund, which the buyer pre-empts by broadcasting first. Late settle is accepted in the design; a held-back signature that outlives the authority's own decision is the same property, and no contract change closes it (the template hash is fixed).

Guidance for an authority, whether one key or the threshold group:

- Sign only when the signing party will broadcast at once. Do not hand a signed settle to a party that may hold it.
- Keep the fee input under the authority's own control. The signature binds the fee outpoints, so a signed settle can only be broadcast with the fee UTXO the authority chose; spend that UTXO elsewhere to withdraw a held signature.
- Sign nothing before the off-chain payment is final.


Nonce reuse leaks the signer's share. Nonces never leave the process, and `sign` and `sign_input` consume them. In the CLI a signer's nonces stay in the memory of the one `impulse frost sign` process between round 1 and round 2, never in a file; a process that ends or refuses before round 2 erases them, and the signer starts again with fresh nonces.

## Encodings

Byte forms Impulse defines over the values FROST exposes (decision D20, option (a)): FROST's own `serialization` feature stays off (see "Library"). Integers are big-endian. A point is 33-byte SEC1 compressed, a scalar 32 bytes. Every decoder refuses another length, a point not on the curve, a scalar out of range and any inconsistency below with `THRESHOLD_ENCODING`; it never returns a partly decoded value.

| Value | Bytes |
| --- | --- |
| `DkgRound1Package` | coefficient count c (u16, at least 1), c commitment coefficients (point each), the proof of knowledge (64 bytes: x-only R, then z) |
| `DkgRound2Package` | the secret share for its recipient (scalar) |
| `KeyShare` | threshold (u16), parties (u16), party (u16), signing share (scalar), the party's public share (point), the group key (point). Decoding checks the shape (2 <= t <= n), the party (1..=n), that the public share is the signing share times G, and that the group key has an x-only form |
| `GroupKey` | threshold (u16), parties (u16), the group key (point), then every party's public share (point) in party order. Decoding checks the shape and recomputes the authority key and the fingerprint |
| `Commitment` | hiding nonce commitment (point), binding nonce commitment (point) |
| `SignatureShare` | the share (scalar) |

The group key is the key after the TapTweak of "Key generation"; its x coordinate is the authority key.

## Key material

- In the library, a party's key share, its key generation secrets and its signing nonces are held in memory, inside FROST types that erase themselves on drop (`ZeroizeOnDrop`; a compile-time test fails if a FROST upgrade drops that). Their `Debug` output names the party only. Key generation secrets and nonces are never written anywhere; the key share is written only by the CLI, as below.
- Nothing in `impulse_core::threshold` writes, logs, prints or transmits them. Its byte encodings of secret values (`KeyShare::to_bytes`, `DkgRound2Package::to_bytes`) return buffers zeroed on drop, and their decoders read from the caller's buffer.
- The CLI writes a key share only to the file the party names with `--share-file`, on its own machine: created new (an existing file is never overwritten) with mode 0600, never printed, logged or sent. `impulse frost sign` reads it only if it is a regular file that neither group nor others may access (Unix), into buffers zeroed on drop. Round-2 files carry a secret share for one recipient: they are written with mode 0600, read only by their recipient's key generation after the same access check, and removed by it once its share file is written; the sender deletes its own copies once each recipient has its file.
- Removing a file unlinks it; it does not overwrite the content on disk, which stays readable to whoever reads the raw device until the space is reused. A round-2 file the recipient's key generation cannot remove is named on the output, and the command ends with `FROST_ROUND2_NOT_REMOVED` after the share and group files are written.
- In the CLI only two modules touch FROST secrets: `keygen` (key generation, one entry point) and `signing` (signing, through its one entry point `signing::sign`, which also serves the I7 key file). A source guard in the CLI tests checks it.

## Transport

Decision D16 (default): the parties choose their own channels, and the CLI only writes and reads files they move themselves. It neither encrypts nor authenticates a file. The requirements on those channels:
- Round-1 files: an authenticated and consistent broadcast. Every party must receive the same file from each sender. The round-1 digest comparison, out of band, is what detects a sender that broadcast different packages.
- Round-2 files: a confidential and authenticated channel to their one recipient. Anyone who reads every round-2 file addressed to a party learns that party's share.
- Commitment and signature-share files: public, but they must reach the right signers and the aggregator. A changed or swapped file makes the session fail (`FROST_SESSION_MISMATCH`, `THRESHOLD_SHARE_INVALID`); it never yields a signature under the authority key for another message, since every signer computes its message itself and the aggregate is verified under the authority key before it enters the IPST.

## CLI

`impulse frost keygen`, `impulse frost sign` and `impulse frost aggregate`. Every other convention is that of spec/CLI.md: a refusal prints `impulse: CODE: detail` on stderr and exits with status 1. Key generation and signing are interactive: the command writes a file into the session directory, prints one line that starts with `> ` and says what it waits for, and reads one line from standard input. Use a fresh directory (`--dir`) for every key generation and every signing session.

### Files

Each file is ASCII text: a tag, `:`, the lowercase hex of the body, then at most one line feed. Integers are big-endian; packages, shares and commitments use the encodings above.

| File | Tag | Body | Secret |
| --- | --- | --- | --- |
| `round1-<i>.frost` | `impulse-frost-round1-v1` | threshold (u16), parties (u16), sender i (u16), `DkgRound1Package` | no |
| `round2-<i>-to-<j>.frost` | `impulse-frost-round2-v1` | threshold (u16), parties (u16), sender i (u16), recipient j (u16), the sender's round-1 digest (32), `DkgRound2Package` | yes, mode 0600 |
| the share file (`--share-file`) | `impulse-frost-share-v1` | `KeyShare` | yes, mode 0600 |
| the group file (`--group-out`) | `impulse-frost-group-v1` | `GroupKey` | no |
| `commit-<i>.frost` | `impulse-frost-commit-v1` | session (32), sender i (u16), input count (u16), then per authority input in ascending order: input index (u32), `Commitment` | no |
| `sigshare-<i>.frost` | `impulse-frost-sigshare-v1` | session (32), commitment set digest (32), sender i (u16), input count (u16), then per authority input in ascending order: input index (u32), `SignatureShare` | no |

`<i>` and `<j>` are party numbers in decimal. A file read from the session directory must carry the sender (and recipient) its name gives.

Signing session, keyed blake2b-256, key `Impulse/frostsession/v1`: the authority key (32), the number of signers (u16), each signer (u16) in ascending order, the number of authority inputs (u16), then per authority input in ascending order its index (u32) and its `SIG_HASH_ALL` sighash (32) as this party computed it from the IPST. Two parties derive the same session only for the same authority key, signing set, inputs and messages.

Commitment set digest, keyed blake2b-256, key `Impulse/frostcommitments/v1`: the session (32), then per signer in ascending order its number (u16) and its commitment (66) for each authority input in ascending order. A signer computes it over the commitments it signed against, the aggregator over the commitment files it reads.

The authority inputs of an IPST are the inputs whose slot names the terms' `authority_key` as signer and holds no signature yet. Every slot that names the authority key, signed or not, must spend a UTXO at a vault of the terms (the asset vault, or the cash vault for KAS or KCC-20 cash): otherwise the IPST is refused (`FROST_AUTHORITY_INPUT_NOT_VAULT`), so a fee input locked to the authority key is never signed or aggregated by the group.

### `impulse frost keygen`

`impulse frost keygen --threshold <t> --parties <n> --party <i> --dir <dir> --share-file <path> --group-out <path>`. Each party runs it on its own machine; the process holds the party's round-1 and round-2 secrets in memory from start to end.

Checks before anything is written or printed: the shape (`THRESHOLD_PARAMS`), the party (`THRESHOLD_PARTY`), `--dir` is a directory (`CLI_FILE_READ`), the share file and the group file do not exist (`CLI_OUTPUT_EXISTS`) and the directory each is to be created in exists (`CLI_FILE_WRITE`), and `round1-<i>.frost` does not exist (`CLI_OUTPUT_EXISTS`). Every file it writes is created new: one that appears in its place while the command runs is never overwritten (`CLI_OUTPUT_EXISTS`). Then:
1. Writes `round1-<i>.frost` and waits until the round-1 files of every other party are in `--dir`.
2. Prints the round-1 digest and waits for the digest every party reported. Anything else is `FROST_NOT_CONFIRMED`, and no round-2 file is written.
3. Writes `round2-<i>-to-<j>.frost` for every other party j, mode 0600, and waits until the round-2 files addressed to it are in `--dir`.
4. Prints the authority key and the group fingerprint and waits for the fingerprint every party reported. Anything else is `FROST_NOT_CONFIRMED`, and no share or group file is written.
5. Writes the share file (mode 0600) and the group file, removes the round-2 files addressed to it, and prints `ok:` with the party, the shape and the authority key. A round-2 file it cannot remove is printed as `could not remove: <path>: <reason>`, and the command ends with `FROST_ROUND2_NOT_REMOVED` instead of `ok:`.

While it waits, an empty line or any line makes it look for the files again and name those still missing. Refusals during the run: a received file that cannot be read (`CLI_FILE_READ`) or does not decode (`FROST_FILE_MALFORMED`); one of another shape, sender or recipient, or a round-2 file made for another round-1 transcript (`FROST_SESSION_MISMATCH`); a round-2 file that group or others may access (`FROST_FILE_PERMISSIONS`); a proof of knowledge or a secret share that fails (`THRESHOLD_DKG_CULPRIT`, naming the sender); the end of input before a step completes (`FROST_ABORTED`). A refused run writes nothing more, and its secrets are erased with the process.

### `impulse frost sign`

`impulse [--network mainnet] frost sign --share-file <path> --ipst <file> --signers <i,j,...> (--terms <file> | --terms-hash <hex>) --dir <dir> --asset-template <file> [--cash-template <file>] (--daa <score> | --node <url>) (--kas-equivalent <sompi> | --i-accept-the-risk)`. The signers agree on the signing set before they start; each runs the command on its own machine.

Checks, in this order, before anything is printed or written:
1. The IPST reads (spec/IPST.md, "Reading an IPST", which recomputes every sighash) and its terms name the command's network (`CLI_NETWORK_MISMATCH`).
2. The terms name an authority (`FROST_NO_AUTHORITY_INPUT`), every slot that names the authority key spends a vault UTXO (`FROST_AUTHORITY_INPUT_NOT_VAULT`; section "Files"), and at least one of them waits for its signature (`FROST_NO_AUTHORITY_INPUT`).
2a. After the authority checks, the agreed trade, as for `ipst sign`: the IPST's terms hash equals the terms hash of `--terms` (a terms file) or `--terms-hash` (`FROST_TERMS_NOT_AGREED`). A group's key can be named as `authority_key` in terms its members never saw, and shares over such a trade attest a payment the group never agreed to, so the signer names the trade before the share file is read.
3. `--signers` is a comma-separated list of distinct party numbers (`FROST_SIGNERS_INVALID`).
4. The terms check (spec/IPST.md, "Terms check") against the KCC-20 templates given (silverc artifacts; `--cash-template` for KCC-20 cash) and the current DAA score: `--node` reads it from a synced node of the command's network; on mainnet a typed `--daa` is refused (`CLI_MAINNET_NEEDS_NODE`), as in spec/CLI.md. What the check found must be a settle or a refund by the authority, the two transactions in which the authority signs vault inputs (`FROST_AUTHORITY_INPUT_NOT_VAULT`).
5. The value cap of spec/CLI.md.
6. `--dir` is a directory (`CLI_FILE_READ`).
7. In the signing module: the network rule (`SIGN_MAINNET_NOT_EXPLICIT`, `SIGN_NETWORK_MISMATCH`); the share file (`FROST_SHARE_FILE_UNREADABLE`, `FROST_SHARE_FILE_PERMISSIONS`, `FROST_SHARE_FILE_FORMAT`); the share's authority key is the terms' `authority_key` (`FROST_KEY_NOT_AUTHORITY`); the signing set lies in 1..=n (`THRESHOLD_PARTY`), has at least t signers (`THRESHOLD_TOO_FEW_SIGNERS`) and includes this party (`THRESHOLD_SIGNER_NOT_IN_SET`).
8. `commit-<i>.frost` and `sigshare-<i>.frost` do not exist in `--dir` (`CLI_OUTPUT_EXISTS`), where i is this party's number, read from the share.

Then it prints the decoded terms (spec/CLI.md, "Terms summary"), what the terms check found (the transaction kind and ID, and the fee), every output (`output <n>: <value> sompi to <destination>`, with its covenant if it has one), the change (`change: <value> sompi to <destination> (the fee payer's)`, the output after the trade outputs, or `change: none`), the authority inputs, the signers, the session and the cap used; draws fresh nonces for every authority input; writes `commit-<i>.frost`; and waits until the commitment files of the other signers are in `--dir`. A commitment file that cannot be read, does not decode, or belongs to another session, sender or set of inputs is refused (`CLI_FILE_READ`, `FROST_FILE_MALFORMED`, `FROST_SESSION_MISMATCH`), as is the end of input (`FROST_ABORTED`). It then asks the signer to approve (`> sign:`) by typing back the session shown with the transaction (the prompt repeats the terms hash): anything else is `FROST_NOT_CONFIRMED`, the end of input `FROST_ABORTED`, and nothing is signed. Only then does it sign every authority input with `sign_input`, write `sigshare-<i>.frost` with the commitment set digest it signed against, and print `ok:`.

The command sets no fee bound: the fee comes from the fee payer's inputs alone (IMPULSE-SPEC, "Exact amounts": fees always come from a separate input), the group never signs one of them (section "Files"), and the fee payer's own signing of its input (`ipst sign --max-fee`, I7) bounds it. The fee and the change are printed so that the signers see the whole transaction they approve.

### `impulse frost aggregate`

`impulse [--network mainnet] frost aggregate --group <file> --ipst <file> --signers <i,j,...> --dir <dir> --out <file>`. Anyone holding the group file can run it; it needs no secret and is not interactive.

Checks, in this order: the IPST reads and names the command's network (`CLI_NETWORK_MISMATCH`); the terms name an authority (`FROST_NO_AUTHORITY_INPUT`), every slot that names the authority key spends a vault UTXO (`FROST_AUTHORITY_INPUT_NOT_VAULT`), and at least one of them waits for its signature (`FROST_NO_AUTHORITY_INPUT`); `--signers` parses (`FROST_SIGNERS_INVALID`); the group file reads and decodes (`CLI_FILE_READ`, `FROST_FILE_MALFORMED`) and its authority key is the terms' (`FROST_KEY_NOT_AUTHORITY`); the signing set fits the group (`THRESHOLD_PARTY`, `THRESHOLD_TOO_FEW_SIGNERS`); `--out` does not exist (`CLI_OUTPUT_EXISTS`); every signer's `commit-<j>.frost` and `sigshare-<j>.frost` read and decode (`CLI_FILE_READ`, `FROST_FILE_MALFORMED`), name the session the aggregator computes, their sender and the authority inputs, and every signature-share file names the commitment set digest of the commitment files (`FROST_SESSION_MISMATCH`). Then, per authority input, `aggregate_input` (`THRESHOLD_SHARE_INVALID`, `THRESHOLD_SIGNATURE_INVALID`), and the signature enters the IPST slot through I5's check (`TX_SIGNATURE`). It writes the IPST to `--out` and prints the group fingerprint, the inputs signed and `ok:`. The IPST then goes on as any other: `ipst merge` and `submit` (I7) finish it.

## Library

- frost-secp256k1-tr 3.0.0 from crates.io, pinned `=3.0.0`, default features off. With it: frost-core 3.0.0, frost-rerandomized 3.0.0 (not used) and k256 0.13.4.
- Third-party review status, as stated by its maintainers (ZcashFoundation/frost README, main at 99aca96, read 2026-10-07): NCC performed a review of the v0.6.0 release (commit 5fa17ed) of frost-core, frost-ed25519, frost-ed448, frost-p256, frost-secp256k1 and frost-ristretto255, covering key generation (trusted dealer and DKG) and FROST signing; "This does not include frost-secp256k1-tr and rerandomized FROST." The frost-core changelog records frost-secp256k1-tr as added in release 2.1.0, after the reviewed release. frost-core 3.0.0, which Impulse uses, is not the reviewed v0.6.0 release, and frost-secp256k1-tr is outside that review at any version. Impulse claims nothing further.
- `cargo audit --deny warnings` is clean with default features off. The crate's default `serialization` feature pulls postcard with heapless 0.7 and atomic-polyfill (RUSTSEC-2023-0089, unmaintained), so it stays off.

## Error codes

Stable codes for every threshold refusal. Integrators match on the code, never on the message text. The list is frozen by the test `threshold::tests::threshold_error_codes_are_frozen` and may only grow. `spec/ERRORS.md` (I10) will absorb this table.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `THRESHOLD_PARAMS` | group shape | Threshold below 2 or above the number of parties |
| `THRESHOLD_PARTY` | key generation, sign, aggregate | A party identifier outside 1..=n |
| `THRESHOLD_DKG_PACKAGES` | key generation rounds 2 and 3, round-1 digest | Not exactly one package from every other party (rounds 2 and 3) or from every party (round-1 digest, round 1) |
| `THRESHOLD_DKG_CULPRIT` | key generation rounds 2 and 3 | A proof of knowledge (round 2) or a secret share (round 3) failed verification; names the sender |
| `THRESHOLD_TOO_FEW_SIGNERS` | sign, aggregate | Fewer signing commitments than the threshold |
| `THRESHOLD_SIGNER_NOT_IN_SET` | sign | The signer's commitment is absent from the set or is not the commitment of its nonces |
| `THRESHOLD_SHARES_MISMATCH` | aggregate | Signature shares not from exactly the parties of the signing set |
| `THRESHOLD_SHARE_INVALID` | aggregate | The shares do not sum to a valid signature; names every party whose share fails verification |
| `THRESHOLD_KEY_INVALID` | verify | The authority key is not an x-only secp256k1 point |
| `THRESHOLD_SIGNATURE_INVALID` | aggregate, verify | The signature does not verify under the authority key |
| `THRESHOLD_REFUSED` | any | Any other refusal by the FROST library (fail closed) |
| `THRESHOLD_ENCODING` | decoders of "Encodings" | The bytes are not the encoding of the value, or the value is inconsistent |
| `THRESHOLD_INPUT` | `sign_input`, `aggregate_input` | No such input in the transaction, or UTXO entries that do not match its inputs one for one |

Codes of the `impulse frost` commands (section "CLI"). Frozen by the CLI test `frost_tests::frost_error_codes_are_frozen` (`crates/impulse-cli/src/frost_tests.rs`); the list may only grow. The commands also return `THRESHOLD_*`, `SIGN_*`, `CLI_*`, `IPST_*`, `TX_*`, `TERMS_*` and `TEMPLATE_*` codes as stated above.

| Code | Meaning |
| --- | --- |
| `FROST_SHARE_FILE_UNREADABLE` | The share file cannot be opened or read, or is not a regular file |
| `FROST_SHARE_FILE_PERMISSIONS` | Group or others have any access to the share file (Unix) |
| `FROST_SHARE_FILE_FORMAT` | The share file is not its tag and the hex of a key share, or the key share does not decode |
| `FROST_FILE_MALFORMED` | A round-1, round-2, group, commitment or signature-share file is not its tag and the hex of its body, or the body does not decode |
| `FROST_FILE_PERMISSIONS` | Group or others have any access to a round-2 file (Unix) |
| `FROST_SESSION_MISMATCH` | A file of another key generation or signing session: another shape, sender, recipient, round-1 transcript, session, set of authority inputs or commitment set |
| `FROST_NOT_CONFIRMED` | The round-1 digest, group fingerprint or signing session typed back is not this party's |
| `FROST_ABORTED` | The input ended before the step completed |
| `FROST_SIGNERS_INVALID` | `--signers` is not a comma-separated list of distinct party numbers |
| `FROST_NO_AUTHORITY_INPUT` | No input of the IPST waits for the terms' authority signature |
| `FROST_KEY_NOT_AUTHORITY` | The share's or the group file's authority key is not the terms' `authority_key` |
| `FROST_AUTHORITY_INPUT_NOT_VAULT` | A slot that names the authority key spends no vault UTXO of the terms, or the terms check found a transaction other than a settle or a refund by the authority |
| `FROST_ROUND2_NOT_REMOVED` | Key generation wrote the share and group files but could not remove a round-2 file addressed to this party |
| `FROST_TERMS_NOT_AGREED` | The IPST is for other terms than `--terms` or `--terms-hash`, or neither was given |
