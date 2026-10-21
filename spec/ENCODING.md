# Impulse canonical encoding

Terms encoding version 1, fixed in increment I2. Companion to `IMPULSE-SPEC.md`, section "Terms", which defines the fields. This file defines their bytes, the terms hash, validation and the refusal codes. Reference implementation: `crates/impulse-core/src/terms/`. Golden vectors: `tests/vectors/terms/`, frozen.

## Terms hash

```
terms_hash = BLAKE2b-256(key = "Impulse/terms/v1", message = canonical bytes)
```

BLAKE2b in keyed mode (RFC 7693), digest length 32 bytes, key the 16 ASCII bytes `Impulse/terms/v1`, no salt, no personalisation. rusty-kaspa a41a333 builds its own domain-separated hashes the same way (`crypto/hashes/src/hashers.rs`). Known answers, checked in the tests against Python's `hashlib`:

| Message | terms_hash |
| --- | --- |
| empty | `5d7790670ef4684cf722b07a37bfd3cf139175af62d4a34126327d713d895141` |
| `abc` | `b5afc4eb7af8dde5dc9187962d434012b7c0559089e5502099ed3b59944a9dd9` |

The hash is defined for every value that decodes, valid or not, so a verifier can hash whatever it is shown.

## Conventions

- Integers are unsigned, fixed width and little-endian: u8, u16, u32, u64.
- Fixed-size byte arrays (keys, hashes, identifiers, `trade_ref`) are 32 bytes, written as they are.
- A variable-length byte string is a u32 length followed by that many bytes. The length is at most 10,000 (`MAX_SCRIPT_LEN`, the pre-Toccata consensus script size limit). The only byte string is a KAS destination script.
- An optional field starts with a presence byte: `0x00` absent (nothing follows) or `0x01` present (the value follows). Any other value is refused.
- A variant starts with a kind byte, followed by that variant's fields only. An unknown kind is refused.
- No padding, no alignment, nothing after the last field.

Decoding refuses every byte string that is not exactly this form, so each terms value has exactly one encoding: `decode(encode(t)) = t`, and `encode(decode(b)) = b` whenever `decode(b)` succeeds.

## Layout

Fields in this order, the order of the spec's terms table:

| # | Field | Encoding | Bytes |
| --- | --- | --- | --- |
| 1 | version | u8, `0x01` (the terms encoding version) | 1 |
| 2 | network | u8: `0x00` mainnet, `0x01` testnet (any testnet suffix) | 1 |
| 3 | settlement_mode | u8: `0x00` Direct, `0x01` Vault | 1 |
| 4 | nonce | u64 | 8 |
| 5 | seller_key | 32-byte x-only Schnorr public key | 32 |
| 6 | buyer_key | 32-byte x-only Schnorr public key | 32 |
| 7 | authority_key | optional 32-byte x-only Schnorr public key | 1 or 33 |
| 8 | asset_leg | Leg | 9 or 81 |
| 9 | cash_leg | Leg | 9 or 81 |
| 10 | buyer_delivery | Destination (asset leg) | see below |
| 11 | seller_proceeds | Destination (cash leg) | see below |
| 12 | seller_refund | Destination (asset leg) | see below |
| 13 | buyer_refund | Destination (cash leg) | see below |
| 14 | earliest_daa | optional u64 DAA score | 1 or 9 |
| 15 | expiry_daa | u64 DAA score | 8 |
| 16 | funding_mode | u8: `0x00` revocable, `0x01` earmarked | 1 |
| 17 | trade_ref | 32 bytes, opaque | 32 |

The vault sub-modes have no byte of their own. A Vault trade with an authority key and on-chain cash is "vault, authority"; without an authority it is "vault, self-settling"; with an external cash leg it is "vault, external cash" (an authority is then required).

**Leg.** A kind byte, the kind's fields, then the amount.

| Kind | Byte | Fields after the kind byte |
| --- | --- | --- |
| KAS | `0x00` | amount u64 (sompi) |
| KCC-20 | `0x01` | covenant_id 32, template_hash 32, template_prefix_len u32, template_suffix_len u32, amount u64 (token units) |
| External | `0x02` | amount u64 (opaque to Impulse) |

Every kind is encodable on both legs, so later versions need no layout change. Validation narrows v1: the asset leg must be KCC-20, and only the cash leg may be KAS or external.

**Destination.** A kind byte, then the kind's fields.

| Kind | Byte | Fields after the kind byte |
| --- | --- | --- |
| KAS scriptPubKey | `0x00` | version u16, script byte string (u32 length, bytes) |
| KCC-20 owner | `0x01` | identifier_type u8 (`0x00` PUBKEY, `0x01` SCRIPT_HASH, `0x02` COVENANT_ID, as in kcc20.sil), identifier 32 |
| Off chain | `0x02` | nothing; the only kind for an external cash leg |

### Decoding and encoding refusals

Decoding reads the fields in order and stops at the first problem.

1. The version byte is read first. Any value other than `0x01` is `TERMS_UNSUPPORTED_VERSION`, because the rest of the layout depends on it.
2. Then each field: input that ends inside it is `TERMS_TRUNCATED`; a settlement mode byte other than 0 or 1 is `TERMS_UNKNOWN_SETTLEMENT_MODE`; any other unknown kind or enumeration byte is `TERMS_INVALID_TAG`; a presence byte other than 0 or 1 is `TERMS_INVALID_PRESENCE`; a byte string length above 10,000 is `TERMS_FIELD_TOO_LONG`, checked before the bytes are read.
3. Bytes left after `trade_ref` are `TERMS_TRAILING_BYTES`.

Encoding refuses a version other than 1 (`TERMS_UNSUPPORTED_VERSION`) and a script longer than 10,000 bytes (`TERMS_FIELD_TOO_LONG`). The terms hash refuses the same, since it hashes the encoding.

## Validation

Decoding checks form. Validation checks that the terms are safe to act on, in two stages. Within each stage the checks run in the order below and the first failure is returned, so every implementation reports the same code for the same terms. The structure stage always runs first.

### Structure checks

Time-independent and mandatory. They hold or fail the same way whenever and wherever they are run, so a trade past its expiry still passes them. `Terms::validate_structure` is the only way to obtain `ValidatedTerms`, which carries the terms with their canonical bytes and hash; template instantiation (I4) and the builders (I5) take only `ValidatedTerms`.

1. version is 1: `TERMS_UNSUPPORTED_VERSION`.
2. seller_key, buyer_key, then authority_key if present, each a valid BIP-340 x-only public key: `TERMS_INVALID_KEY`.
3. buyer_key differs from seller_key (`TERMS_PARTIES_NOT_DISTINCT`), then authority_key, if present, differs from seller_key and then from buyer_key (`TERMS_AUTHORITY_IS_PARTY`, added in I4).
4. The asset leg is KCC-20: an external asset is `TERMS_ASSET_EXTERNAL`; a KAS asset is `TERMS_ASSET_KIND_UNSUPPORTED` (a v1 limit, decision D13).
5. An external cash leg has an authority: `TERMS_EXTERNAL_WITHOUT_AUTHORITY`.
6. In Direct mode, the cash leg is not external, then funding_mode is revocable: `TERMS_DIRECT_INCOMPATIBLE`.
7. Asset leg, then cash leg: amount above zero (`TERMS_AMOUNT_ZERO`); amount at most `MAX_SOMPI` (2,900,000,000,000,000,000) for KAS and at most `i64::MAX` for KCC-20 and external (`TERMS_AMOUNT_OUT_OF_RANGE`); for KCC-20, covenant_id then template_hash not all zero (`TERMS_ZERO_IDENTIFIER`), then template_prefix_len and template_suffix_len both above zero with a sum of at most 1,000,000, the post-Toccata consensus script size limit (`TERMS_TEMPLATE_LENGTH`). Then, when both legs are KCC-20, their covenant IDs differ (`TERMS_SAME_COVENANT`, added in I4).
8. buyer_delivery and seller_refund against the asset leg, seller_proceeds and buyer_refund against the cash leg, in field order:
   - the destination kind matches the leg kind (KAS to KAS scriptPubKey, KCC-20 to KCC-20 owner, external to off chain): `TERMS_DESTINATION_KIND`;
   - a KAS scriptPubKey is version 0 and of a standard class, P2PK, P2PK-ECDSA or P2SH (`TERMS_NONSTANDARD_SCRIPT`); its P2PK key is a valid x-only key and its P2PK-ECDSA key a valid compressed key (`TERMS_INVALID_KEY`); its P2SH hash is not all zero (`TERMS_ZERO_IDENTIFIER`);
   - a KCC-20 owner identifier is not all zero (`TERMS_ZERO_IDENTIFIER`), and a PUBKEY identifier is a valid x-only key (`TERMS_INVALID_KEY`).
9. expiry_daa, then earliest_daa if present, is below 500,000,000,000 (`LOCK_TIME_THRESHOLD`), so a lock time at it is a DAA score and not a timestamp: `TERMS_EXPIRY_NOT_DAA`, `TERMS_EARLIEST_NOT_DAA`.
10. earliest_daa, if present, is not zero (`TERMS_EARLIEST_ZERO`) and not above expiry_daa (`TERMS_EARLIEST_AFTER_EXPIRY`).

### Creation checks

Run when terms are made or accepted, against a context: the caller's network, the DAA score at creation, and the maximum expiry horizon. They are not rerun when an existing trade is settled, refunded or verified. The default horizon is 315,360,000 DAA (365 days at 10 DAA per second). That figure is modelled, not measured: it assumes the 10 blocks per second mainnet and TN10 target. Callers may pass their own.

1. network equals the context's network: `TERMS_NETWORK_MISMATCH`.
2. expiry_daa is above the creation DAA score: `TERMS_EXPIRY_NOT_AFTER_CREATION`.
3. expiry_daa is at most creation plus horizon (saturating): `TERMS_EXPIRY_BEYOND_HORIZON`.

### Why the checks beyond amounts, horizon, ordering, distinct parties and network

- Keys must be on the curve because the contract runs `checkSig` with them. An invalid refund key would leave no party able to send a leg home.
- The v1 vault escrows a KCC-20 asset only (decision D13). KAS against a KCC-20 token is the same trade with buyer and seller swapped, so it is expressed with the token as the asset. KAS against external cash is not supported in v1.
- An authority equal to a party removes the independent attestation. With external cash it would let the buyer release the asset unpaid. The contract also tells roles apart by key, so a shared key would give the authority the depositor's refund exemptions and earmark gate.
- External cash without an authority would let anyone settle the asset leg, because the vault skips the cash output check in that mode.
- Direct mode moves both legs in one transaction, so both must be on chain. Nothing is deposited, so there is nothing to earmark until expiry. expiry_daa and earliest_daa stay meaningful in Direct and are not refused: the Direct builder (I5) uses them to bound when the transaction may be built and settled. The refund destinations are committed but unused in Direct.
- An input with no covenant reports the zero covenant ID (`OpInputCovenantId`, rusty-kaspa a41a333), so a zero covenant ID in terms would match any plain input.
- Each vault requires its escrow to be the only input of its leg's covenant in the settle transaction (`[E1]`). With one token on both legs, every settle holds two inputs of that covenant, so neither vault would ever release and both legs could only be refunded. In Direct mode the same terms would trade a token for itself. Such terms never become `ValidatedTerms`, so no trade is made from them.
- The KCC-20 state sits between a non-empty template prefix and suffix, inside one script. Lengths outside that range cannot describe a real template, and a wrong template description could block a KCC-20 leg's settle and refund. The range check does not prove the lengths match the token's template; I4 and I6 check that.
- A non-standard destination makes the settle or refund transaction non-standard, so it would not relay.
- `earliest_daa` absent means no lower bound. Present and zero would be a second spelling of the same rule, and a script that compiles absence as 0 could not be decoded back to one terms value.

Not checked here: nonce and trade_ref (any value is meaningful); whether the template prefix and suffix lengths match the token's actual template (I4, I6); storage mass and dust limits on KAS values, which are transaction-level (I5 adds a minimum derived from the KIP-9 storage mass rule, enforced by the builders: `spec/TRANSACTIONS.md`).

## Error codes

Stable codes for every terms refusal. Integrators match on the code, never on the message text. The list is frozen by the test `terms::tests::error_codes_are_frozen` and may only grow. `spec/ERRORS.md` is the authoritative catalogue of every Impulse code: it lists these codes in this order, with the same raised-by and meaning, and a test in `tests/parity` fails if the two tables differ. It also records the I4 narrowing of `TERMS_PARTIES_NOT_DISTINCT` and the retirement of `TEMPLATE_SAME_COVENANT` (reserved, never reused) in favour of `TERMS_SAME_COVENANT`.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `TERMS_TRUNCATED` | decode | Input ends inside a field |
| `TERMS_TRAILING_BYTES` | decode | Bytes after the last field |
| `TERMS_INVALID_TAG` | decode | Unknown kind or enumeration byte |
| `TERMS_INVALID_PRESENCE` | decode | Presence byte other than 0 or 1 |
| `TERMS_UNKNOWN_SETTLEMENT_MODE` | decode | Settlement mode byte other than Direct (0) or Vault (1) |
| `TERMS_FIELD_TOO_LONG` | decode, encode | Byte string longer than 10,000 bytes |
| `TERMS_UNSUPPORTED_VERSION` | decode, encode, structure | Version other than 1 |
| `TERMS_INVALID_KEY` | structure | A public key is not a valid point in the required form |
| `TERMS_PARTIES_NOT_DISTINCT` | structure | Buyer equals seller |
| `TERMS_ASSET_EXTERNAL` | structure | Asset leg is external |
| `TERMS_ASSET_KIND_UNSUPPORTED` | structure | Asset leg is KAS, which the v1 vault cannot escrow |
| `TERMS_EXTERNAL_WITHOUT_AUTHORITY` | structure | External cash with no authority |
| `TERMS_DIRECT_INCOMPATIBLE` | structure | Direct mode with external cash or earmarked funding |
| `TERMS_AMOUNT_ZERO` | structure | A leg amount is zero |
| `TERMS_AMOUNT_OUT_OF_RANGE` | structure | A leg amount is above its kind's maximum |
| `TERMS_ZERO_IDENTIFIER` | structure | A covenant ID, template hash, owner identifier or script hash is all zero |
| `TERMS_TEMPLATE_LENGTH` | structure | A KCC-20 template prefix or suffix length is zero, or their sum exceeds 1,000,000 |
| `TERMS_DESTINATION_KIND` | structure | A destination's kind does not match its leg |
| `TERMS_NONSTANDARD_SCRIPT` | structure | A KAS destination is not a standard version-0 script |
| `TERMS_EXPIRY_NOT_DAA` | structure | expiry_daa is not in the DAA-score lock-time domain |
| `TERMS_EARLIEST_NOT_DAA` | structure | earliest_daa is not in the DAA-score lock-time domain |
| `TERMS_EARLIEST_ZERO` | structure | earliest_daa present and zero |
| `TERMS_EARLIEST_AFTER_EXPIRY` | structure | earliest_daa above expiry_daa |
| `TERMS_NETWORK_MISMATCH` | creation | Terms name another network |
| `TERMS_EXPIRY_NOT_AFTER_CREATION` | creation | expiry_daa is not above the creation DAA score |
| `TERMS_EXPIRY_BEYOND_HORIZON` | creation | expiry_daa is beyond the horizon |
| `TERMS_AUTHORITY_IS_PARTY` | structure | Authority equals the seller or the buyer (added in I4; until I4, `TERMS_PARTIES_NOT_DISTINCT`) |
| `TERMS_SAME_COVENANT` | structure | Both legs are KCC-20 with the same covenant ID (added in I4) |

## Golden vectors

`tests/vectors/terms/<NN>-<name>.json`, one file per vector, eleven in version 1. Each file holds:

| Key | Content |
| --- | --- |
| `name` | The file name without `.json` |
| `description` | Mode, legs and destinations the vector exercises |
| `terms` | The terms in JSON form, keys in field order (below) |
| `canonical` | The canonical bytes, lowercase hex |
| `terms_hash` | The terms hash, lowercase hex |

JSON form of terms: u64 values as decimal strings (JSON numbers above 2^53 lose precision in JavaScript); u8, u16 and u32 as numbers; byte arrays and scripts as lowercase hex; an absent optional as `null`; kinds and enumerations as lowercase strings (`mainnet`, `testnet`; `direct`, `vault`; `kas`, `kcc20`, `external`, `off_chain`; `pubkey`, `script_hash`, `covenant_id`; `revocable`, `earmarked`).

The set covers Direct with each on-chain cash kind and the three vault sub-modes (authority, self-settling, external cash), both funding modes, a KCC-20 asset against KAS, KCC-20 and external cash, every destination form, both networks, optional fields present and absent, and the upper and lower bounds of each range. A test asserts that coverage. Every vector passes both validation stages with a creation DAA score of 400,000,000.

Every key, covenant ID, template hash and script hash in the vectors is derived from a public label with BLAKE2b (`impulse/vectors/...`). Party keys are the first label-derived x-coordinates on secp256k1, so nobody holds a private key for them. The token values are synthetic, not a deployed token.

Frozen. Three checks hold the files fixed:

- `cargo test` (`terms::golden::golden_files_match`) renders every vector from its definition and compares it byte for byte with the committed file, so a codec change fails CI.
- `scripts/vectors.sh`, a step of `scripts/ci-local.sh`, regenerates the set and diffs it. It also refuses any change to a vector file that already exists on `main`, refuses files under `tests/vectors/` that no generator owns, and decodes and hashes every vector again in Python from this document alone. Its base override `IMPULSE_VECTORS_BASE` is refused when `CI` is set.
- Later increments add vectors as new files (I4 adds per-leg script and address vectors in `tests/vectors/vaults/`, specified in `spec/TEMPLATE.md`); they never edit these.
