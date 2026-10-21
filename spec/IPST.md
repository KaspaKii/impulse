# Impulse partially signed transaction (IPST)

IPST version 1, fixed in increment I5. Companion to `spec/TRANSACTIONS.md`, which defines the transactions the builders make, and `spec/ENCODING.md`, which defines the terms. This file defines the interchange format a party uses to pass an unsigned or partly signed Impulse transaction to the other signers and to the submitter. Reference implementation: `crates/impulse-core/src/tx/ipst.rs`. Golden vectors: `tests/vectors/ipst/`, frozen.

An IPST holds no private key and no secret. It carries the trade's terms, the unsigned transaction, the UTXO each input spends, and one signature slot per input. Signing happens where the key lives (`impulse ipst sign`, I7); an IPST only ever receives finished 65-byte signatures.

## Trust model

An IPST is untrusted input. A consumer recomputes everything it can and refuses the document if any stated value disagrees:

- Each sighash is recomputed from the transaction and the UTXO entries. A stated sighash that differs is refused; a signer never signs a sighash it did not compute.
- Each present signature is verified against its slot's signer key and the recomputed sighash.
- The terms are decoded and structure-checked.

Some fields cannot be checked from the document alone, and need not be:

- A UTXO entry's amount and scriptPubKey. The sighash of input `i` commits to the amount and scriptPubKey of the UTXO input `i` spends, so a signer is protected for its own input: a false entry makes its signature invalid at the node, not misdirected.
- The signature-script parts around the signature (`script_before`, `script_after`). They are not signed. They select the contract entry and carry the redeem script; the contract still checks the signed outputs, so a wrong part can only make the transaction invalid.
- Each input's `compute_budget`, and the UTXO entry's `block_daa_score`, `is_coinbase` and `covenant_id`. The version-1 sighash (rusty-kaspa a41a333, `consensus/core/src/hashing/sighash.rs`, `calc_schnorr_signature_hash`) covers none of them, and the transaction ID (`hashing/tx.rs`, `id`) does not cover the budget. So anyone holding the document, or the finalized transaction, can change them without breaking a signature or the transaction ID. A raised budget raises the compute mass and lowers the fee rate; a lowered one makes the node refuse the input; false entry fields mislead only local checks, since the node reads the spent UTXOs from its own UTXO set. Finalize therefore checks the masses and the relay fee of the assembled transaction again (`TX_MASS`, `TX_FEE_TOO_LOW`), which catches a large raise but not a small change or a lowered budget. The terms check below compares every budget with the builders'; the submitter (I7 `submit`) repeats both immediately before broadcast.
- Whether the transaction is the right one for the terms. Reading does not answer it; the terms check (below) does, from the terms and the inputs this document carries. A signer runs it before signing (I7 `ipst sign`).

## Document

A JSON object (RFC 8259), UTF-8. Every key below is required, and no other key is allowed, at any level. Keys may appear in any order and whitespace is free on input; the canonical rendering is fixed (below).

Value forms:

- `u64`: a decimal string with no sign, no leading zero (except `"0"`), at most 18,446,744,073,709,551,615. JSON numbers above 2^53 lose precision in JavaScript, so 64-bit values are strings.
- `u16`, `u32`: a JSON integer in range, no fraction or exponent.
- `bool`: `true` or `false`.
- `hexN`: lowercase hex of exactly N bytes. `hex`: lowercase hex of any even length, possibly empty.
- `null` where a field is marked optional.

### Top level

| Key | Form | Content |
| --- | --- | --- |
| `ipst` | u16 | Format version, `1` |
| `terms` | hex | The terms' canonical bytes (`spec/ENCODING.md`) |
| `lock_time` | u64 | The transaction lock time |
| `inputs` | array of Input, at least one | In transaction order |
| `outputs` | array of Output, at least one | In transaction order |

### Input

| Key | Form | Content |
| --- | --- | --- |
| `transaction_id` | hex32 | Outpoint transaction ID, the 32 bytes in the order rusty-kaspa holds and prints them (`Hash::as_bytes`, `Display`) |
| `index` | u32 | Outpoint index |
| `sequence` | u64 | Input sequence |
| `compute_budget` | u16 | Input compute budget (version-1 transactions) |
| `utxo` | UtxoEntry | The UTXO this input spends |
| `signer` | hex32 or null | x-only public key whose signature fills the slot; null when the input needs none |
| `sighash` | hex32 or null | SIG_HASH_ALL Schnorr sighash of this input; present exactly when `signer` is |
| `signature` | hex65 or null | 64-byte BIP-340 signature then the sighash type byte `0x01`; null until signed, always null without a signer |
| `script_before` | hex | Signature script bytes before the signature push; the whole signature script when there is no signer |
| `script_after` | hex | Signature script bytes after the signature push; empty when there is no signer |

### UtxoEntry

| Key | Form | Content |
| --- | --- | --- |
| `amount` | u64 | Value in sompi |
| `script_public_key` | ScriptPublicKey | The UTXO's scriptPubKey |
| `block_daa_score` | u64 | DAA score of the block that created it |
| `is_coinbase` | bool | Whether it is a coinbase output |
| `covenant_id` | hex32 or null | Its covenant ID, if any |

### Output

| Key | Form | Content |
| --- | --- | --- |
| `value` | u64 | Value in sompi |
| `script_public_key` | ScriptPublicKey | Where it pays |
| `covenant` | object or null | `{"authorizing_input": u16, "covenant_id": hex32}`, the output's covenant binding |

### ScriptPublicKey

| Key | Form | Content |
| --- | --- | --- |
| `version` | u16 | Script version |
| `script` | hex | Script bytes |

### Fixed transaction fields

Every Impulse transaction has version 1 (`TX_VERSION_TOCCATA`), the native subnetwork, gas 0, an empty payload and a storage-mass commitment of 0 (the node computes and sets it when it accepts the transaction). An IPST therefore does not carry them. The transaction an IPST describes is these fields, `lock_time`, the inputs (outpoint, sequence, compute budget, empty signature script) and the outputs.

## Signature script

When a slot has a signer, the input's final signature script is

```
script_before || 0x41 || signature || script_after
```

`0x41` is `OpData65`, the push of the 65-byte signature. Without a signer it is `script_before` alone. The sighash does not commit to signature scripts, so they are filled in after every signature is collected.

## Reading an IPST

In this order, first failure returned:

1. The text parses as JSON and is an object with an `ipst` key holding an integer: `IPST_MALFORMED`.
2. `ipst` is 1: `IPST_UNSUPPORTED_VERSION`.
3. Every key is present, no other key is, and every value has its form; `inputs` and `outputs` are not empty; each output's `authorizing_input`, if any, names an existing input; every UTXO `amount` and output `value` is above zero and at most `MAX_SOMPI` (2,900,000,000,000,000,000 sompi), the UTXO amounts add up to at most `MAX_SOMPI`, and the outputs pay no more than the inputs hold: `IPST_MALFORMED`. Consensus refuses any other values, and the fee is then the difference of the two sums.
4. `terms` decodes and passes the structure checks: the `TERMS_*` code of `spec/ENCODING.md`.
5. Per input, in order: `signer`, `sighash` and `signature` are null together, or `signer` and `sighash` are present together; a slot without a signer has an empty `script_after`; a signer is a valid x-only key: `IPST_MALFORMED`.
6. Per input, in order: the stated sighash equals the one recomputed from the transaction and the UTXO entries: `IPST_SIGHASH_MISMATCH`.
7. Per input, in order: a present signature has the sighash type `0x01` and verifies against the signer and the sighash: `TX_SIGNATURE`.

Every value that passes is exactly one document: rendering it gives the canonical form, and reading the canonical form gives the value back.

## Operations

- **Sign** (I7, local key only). Recompute the sighash of each slot whose signer is the local key, sign it, and add the signature. Adding a signature verifies it first; a wrong length, a sighash type other than `0x01`, or a signature that does not verify is `TX_SIGNATURE`. A slot index out of range, or a slot without a signer, is `TX_SIGNATURE_SLOT`.
- **Combine.** Two IPSTs combine only if they describe the same transaction: same terms, lock time, inputs (with their UTXO entries) and outputs, every field equal except `signature`. Several of those fields are covered by no sighash (the terms, a UTXO entry's `block_daa_score`, the signature-script parts), so they are compared one by one. A slot signed in one and empty in the other takes the signature, verified first against the receiving slot's signer and sighash (`TX_SIGNATURE`); a slot signed differently in both is refused. Any difference is `IPST_CONFLICT`.
- **Finalize.** Every slot with a signer holds a signature, else `TX_SIGNATURE_SLOT`. The result is the signed transaction, with each signature script assembled as above, provided its masses are within the standard cap (`TX_MASS`) and its fee covers the minimum relay fee (`TX_FEE_TOO_LOW`), as `spec/TRANSACTIONS.md` defines them.

## Terms check

`Ipst::verify_against_terms(asset template, cash template, current DAA score)` answers whether a document is the transaction the builders (`spec/TRANSACTIONS.md`) make for its terms from its own inputs. Reading proves that the stated sighashes and signatures are the transaction's; it cannot see a transaction that is well formed but wrong, such as a Direct transaction that pays the buyer less than the seller's token carries, takes the fee from a trade input, sets every sequence to the maximum (so the lock time no longer holds), drops the lock time, or carries other compute budgets. In Direct mode no contract runs, so nothing else would refuse such a transaction.

The check rebuilds the transaction with the builders and compares it with the document:

1. Which builder made it, from the terms and the inputs: Direct terms give `direct`. Under vault terms, input 0 at the asset vault spent through the `settle` entry gives `settle`; input 0 at a vault otherwise gives `refund` of that leg, the signer role being slot 0's signer, with the escrowed token if input 1 is of the leg's covenant; output 0 at the KAS cash vault gives `fund_kas`; input 0 a token of a KCC-20 leg's covenant, with output 1 at that leg's vault, gives `fund_kcc20`. Anything else is `IPST_TERMS_MISMATCH`.
2. The builder's inputs, from the document: the trade UTXOs where the layout puts them; each token's state from the redeem script its signature script carries (prefix, state, suffix of the given template); the fee inputs after the trade inputs; the fee, the inputs less the outputs; the change destination, the output after the trade outputs; for a deposit, its carrier and authorizer KAS.
3. The builder runs, with every check of `spec/TRANSACTIONS.md`. A refusal keeps its code (for example `TX_EXPIRED` for a trade that can no longer settle by expiry, `TX_LEG_AMOUNT`, `TX_TOKEN_TEMPLATE`).
4. Everything but the signatures is compared byte for byte: every output with its value and covenant binding, the lock time, every input's outpoint, sequence and compute budget, the UTXO entries, and every slot's signer, sighash and script parts. Any difference is `IPST_TERMS_MISMATCH`.

On success the result names the builder, the fee and the change output. The check takes those, and a deposit's carrier and authorizer KAS, from the document, so the payer confirms that the change goes to its own address and the fee is the one it chose; the terms cannot say either.

## Canonical rendering

The canonical text is what impulse-core writes and the golden vectors hold:

- Keys in the order of the tables above.
- An object is `{`, a line break, then one `"key": value` per line, then `}` on its own line. An array is `[`, a line break, one element per line, then `]` on its own line. Members and elements are separated by `,` at the end of the line, and indented two spaces deeper than their container.
- `null`, `true`, `false`, integers in decimal, strings in double quotes. Strings hold only hex or decimal digits, so nothing is escaped; an empty string is `""`.
- `\n` line ends and a final newline. No other whitespace.

## Golden vectors

`tests/vectors/ipst/<NN>-<name>.json`, one unsigned IPST per vector. Each file holds:

| Key | Content |
| --- | --- |
| `name` | The file name without `.json` |
| `description` | The builder and mode the vector exercises |
| `ipst` | The IPST document, unsigned (every `signature` null) |

The vectors use terms built for them, with the KCC-20 templates of the test fixtures (`crates/impulse-core/src/tx/testdata/`, the pinned kcc20.sil compiled by silverscript v1.0.0), label-derived keys and outpoints, and fixed values. Party keys are label-derived x-coordinates on secp256k1, so nobody holds a private key for them, and the vectors are unsigned.

Frozen. Three checks hold the files fixed:

- `cargo test` (`tx::golden::golden_files_match`) builds every vector with the builders and compares it byte for byte with the committed file, and reads every committed file back.
- `scripts/vectors.sh` refuses any change to a vector file already on `main` and any file no generator owns, regenerates the set and diffs it.
- `scripts/vectors.sh` then recomputes every sighash in Python from this document and the rusty-kaspa a41a333 sighash definition alone (`consensus/core/src/hashing/sighash.rs`, version 1, SIG_HASH_ALL), without the Rust code.

## Error codes

Stable codes for IPST refusals. Integrators match on the code, never on the message text. The list is frozen together with the `TX_*` codes by `tx::tests::tx_error_codes_are_frozen` and may only grow. `spec/ERRORS.md` (I10) will absorb this table.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `IPST_MALFORMED` | read | Not an IPST document: bad JSON, a missing or unknown key, a value of the wrong form, or inconsistent slot fields |
| `IPST_UNSUPPORTED_VERSION` | read | `ipst` is not 1 |
| `IPST_SIGHASH_MISMATCH` | read | A stated sighash differs from the recomputed one |
| `IPST_CONFLICT` | combine | The two IPSTs describe different transactions, or hold different signatures in one slot |
| `IPST_TERMS_MISMATCH` | terms check | The document is not the transaction the builders make for its terms from its own inputs |

`TX_SIGNATURE` and `TX_SIGNATURE_SLOT` are defined in `spec/TRANSACTIONS.md`.
