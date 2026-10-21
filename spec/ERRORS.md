# Impulse error catalogue

Every stable code Impulse software returns, and every refusal the on-chain contract makes. Created in increment I10. Companion to the per-layer specs that define when each code is raised (the Families table below); this file is the single list.

## Rules

- Integrators match on the code, never on the message text. Message text may quote what a counterparty supplied (an address, artifact names, a parser's error about either). The verifier escapes every character outside printable ASCII in such text as `\u{..}` before it reaches a message, so no message carries a terminal control sequence or an invisible or bidirectional character. It does not escape for HTML or any other medium: an integrator that displays message text (the CLI, a decoder page) escapes it for its medium.
- Append-only. A code on `main` is never renamed, reused or removed, and new codes go at the end of their family. A code retired before it reached `main` is listed under "Retired and changed codes" and is never reused. A code on `main` whose case no longer exists keeps its row and its place in its frozen list, is never raised again, and is also listed there (I26: `TOKEN_FOREIGN_AT_VAULT`, `WATCH_FOREIGN_TOKEN`).
- A code's meaning is never widened. The one narrowing so far, of `TERMS_PARTIES_NOT_DISTINCT` in I4 before any release, is recorded below. Whether any further narrowing is allowed before 1.0 is an open owner question (I10 Report).
- The contract tags `[S1]` to `[R14]` name the requires of template v1 and are fixed with it: the template hash pins the source, so a tag cannot change without a new template. They are names for reading and for `PARITY.md`, not codes: the contract returns none (see "On-chain refusals").
- Warnings are data. The `TOKEN_` warnings and the `WATCH_` event flags ride beside a successful result and never mean that an operation was refused. They are listed so that integrators can match them.
- Each family's order is pinned by a test in the crate that raises it: `terms::tests::error_codes_are_frozen`, `template::tests::template_error_codes_are_frozen`, `tx::tests::tx_error_codes_are_frozen`, `verify::tests::verify_error_codes_are_frozen`, `verify::tests::token_warning_codes_are_frozen`, `decode::tests::decode_error_codes_are_frozen`, `threshold::tests::threshold_error_codes_are_frozen`, `zk::error::tests::zk_error_codes_are_frozen`, the CLI's `error_codes_are_frozen`, its `frost_tests::frost_error_codes_are_frozen`, the watcher's `watch_codes_are_frozen` and the SDK's `sdk_error_codes_are_frozen`. Three lists have no constant in the code, so the parity tests freeze them: the signing and receipt codes of the command line, which it raises as string literals, and the release dry run's finding codes.
- The tests in `tests/parity` keep this file in step with the code, and fail until the file is updated:
  - `errors_md_lists_every_stable_code`: the `TERMS_` and `TEMPLATE_` codes, in order, and the tables in `ENCODING.md` and `TEMPLATE.md` list the same codes in the same order, with the same raised-by and meaning text. A meaning is compared in full; the trailing parenthetical notes on which the two texts differ (four `TERMS_` codes) are frozen in the test, and any other difference fails.
  - `errors_md_lists_every_code_of_the_core_builders_verifier_and_decoder` and `errors_md_lists_every_code_of_the_cli_watcher_sdk_and_threshold`: each other family equals its frozen list, in order (the lists of impulse-core's default build are linked, the others are read from the source text), and agrees row by row with the per-layer spec that defines it, by the same comparison (eight more frozen notes, on five `CLI_URI_` and three `WATCH_` codes).
  - `errors_md_lists_every_release_dry_run_code`: the frozen 41 codes, equal to the set the maintainers' release dry run raises.
  - `every_code_in_the_rust_sources_is_in_errors_md`: every code literal in the four Rust crates is listed in a family table here (a code raised under a name no list holds fails), none is a retired code (a reserved name that is raised again fails), an ALL_CAPS literal under a prefix the Families table lacks fails until it becomes a family or is listed in the test as not a code, and the signing and receipt codes are exactly those the CLI raises.
  - `no_code_is_listed_twice_in_errors_md`.
  - `errors_md_lists_every_contract_refusal`: the contract tags below are exactly the tagged requires in `contracts/impulse_vault.sil`. Their "Refuses unless" text has no second source to compare with; `PARITY.md` shows this file's sha256, so an edit shows in its diff.
- What the tests do not compare. The Since column is compared nowhere. The Raised-by column is not compared for every family whose per-layer spec has no such column (`CLI_`, `SIGN_`, `TOKEN_`, `WATCH_`, `FROST_`) or has no table (`SDK_`, `RECEIPT_`, `RELEASE_`). The Meaning column is not compared for the families with no table to compare with (`SDK_`, `RECEIPT_`, `RELEASE_`). For those the tests guard the code names, their order and their count only (the `SDK_` codes are also checked against the package README, the `RECEIPT_` codes against the prose of `CLI.md`, the `RELEASE_` codes against the script), so a change to such a column shows only in the sha256 `PARITY.md` records for this file.

## Families

| Prefix | Layer | Defined in | Since |
| --- | --- | --- | --- |
| `TERMS_` | Terms decoding, encoding, structure checks and creation checks (`impulse_core::terms`) | `ENCODING.md` | I2 |
| `TEMPLATE_` | Template startup check, instantiation and decoding (`impulse_core::template`) | `TEMPLATE.md` | I4 |
| `TX_`, `IPST_` | Transaction builders and the IPST interchange form (`impulse_core::tx`), one frozen list | `TRANSACTIONS.md`, `IPST.md` | I5 |
| `VERIFY_` | Verifier (`impulse_core::verify`) | `VERIFY.md` | I6 |
| `DECODE_` | Transaction decoder (`impulse_core::decode`) | `VERIFY.md` | I6 |
| `TOKEN_` | Token warnings, data and not refusals (`impulse_core::verify`) | `VERIFY.md` | I6 |
| `CLI_` | The `impulse` command line (`crates/impulse-cli`) | `CLI.md` | I7 |
| `SIGN_` | Signing module of the command line | `CLI.md` | I7 |
| `RECEIPT_` | Settlement receipts of the command line | `CLI.md` | I7 |
| `WATCH_` | Reference watcher (`crates/impulse-watch`): refusals of a call, and event flags | `WATCH.md` | I8 |
| `SDK_` | TypeScript and WASM SDK (`crates/impulse-wasm`) | this file | I9 |
| `RELEASE_` | Release pre-flight findings of the maintainers' tooling, not refusals of the protocol software | the maintainers' release checklist | I12 |
| `THRESHOLD_` | FROST threshold settlement authority (`impulse_core::threshold`, cargo feature `threshold`) | `THRESHOLD.md` | I13 |
| `FROST_` | The `impulse frost` commands (`crates/impulse-cli`) | `THRESHOLD.md` | I13 |
| `ZK_` | Proof-carrying settlement: terms v3, template v3, issuer lists, manifests, proofs, v3 builders and verifier (`impulse_core::zk`, cargo feature `zk`), and the `impulse zk` commands | `V3-ZK.md` | I20 |
| `HTLC_` | Hashlock terms, template, builders and verifier (`impulse_core::htlc`) | `V2.md` section 10 | I18 |
| `XCHAIN_` | The `impulse xchain` commands (`crates/impulse-cli`) | `V2.md` sections 8.5 and 10.9 | I18 |
| `LINKED_` | Linked trades: the sheet, its derived trades, the return gate and the linked receipt (`impulse_core::linked`) | `V2.md` section 17 | I22 |

A refusal met on the way keeps its own family's code: a template operation that meets a terms refusal returns the `TERMS_*` code, and so does a CLI command, a watcher call or an SDK call. The `TERMS_`, `TEMPLATE_`, `TX_`, `IPST_`, `VERIFY_` and `DECODE_` families are refusals of impulse-core, made for whoever runs it; the contract repeats none of the structure or creation checks, so terms that fail one can still be funded and spent wherever no contract tag below refuses them (`PARITY.md` shows, row by row, what the contract does with such terms). Later increments append their families here, each with its own prefix and frozen list.

## TERMS_ codes

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `TERMS_TRUNCATED` | decode | Input ends inside a field | I2 |
| 2 | `TERMS_TRAILING_BYTES` | decode | Bytes after the last field | I2 |
| 3 | `TERMS_INVALID_TAG` | decode | Unknown kind or enumeration byte | I2 |
| 4 | `TERMS_INVALID_PRESENCE` | decode | Presence byte other than 0 or 1 | I2 |
| 5 | `TERMS_UNKNOWN_SETTLEMENT_MODE` | decode | Settlement mode byte other than Direct (0) or Vault (1) | I2 |
| 6 | `TERMS_FIELD_TOO_LONG` | decode, encode | Byte string longer than 10,000 bytes | I2 |
| 7 | `TERMS_UNSUPPORTED_VERSION` | decode, encode, structure | Version other than 1 | I2 |
| 8 | `TERMS_INVALID_KEY` | structure | A public key is not a valid point in the required form | I2 |
| 9 | `TERMS_PARTIES_NOT_DISTINCT` | structure | Buyer equals seller (narrowed in I4, see below) | I2 |
| 10 | `TERMS_ASSET_EXTERNAL` | structure | Asset leg is external | I2 |
| 11 | `TERMS_ASSET_KIND_UNSUPPORTED` | structure | Asset leg is KAS, which the v1 vault cannot escrow (decision D13) | I2 |
| 12 | `TERMS_EXTERNAL_WITHOUT_AUTHORITY` | structure | External cash with no authority | I2 |
| 13 | `TERMS_DIRECT_INCOMPATIBLE` | structure | Direct mode with external cash or earmarked funding | I2 |
| 14 | `TERMS_AMOUNT_ZERO` | structure | A leg amount is zero | I2 |
| 15 | `TERMS_AMOUNT_OUT_OF_RANGE` | structure | A leg amount is above its kind's maximum | I2 |
| 16 | `TERMS_ZERO_IDENTIFIER` | structure | A covenant ID, template hash, owner identifier or script hash is all zero | I2 |
| 17 | `TERMS_TEMPLATE_LENGTH` | structure | A KCC-20 template prefix or suffix length is zero, or their sum exceeds 1,000,000 | I2 |
| 18 | `TERMS_DESTINATION_KIND` | structure | A destination's kind does not match its leg | I2 |
| 19 | `TERMS_NONSTANDARD_SCRIPT` | structure | A KAS destination is not a standard version-0 script | I2 |
| 20 | `TERMS_EXPIRY_NOT_DAA` | structure | expiry_daa is not in the DAA-score lock-time domain | I2 |
| 21 | `TERMS_EARLIEST_NOT_DAA` | structure | earliest_daa is not in the DAA-score lock-time domain | I2 |
| 22 | `TERMS_EARLIEST_ZERO` | structure | earliest_daa present and zero | I2 |
| 23 | `TERMS_EARLIEST_AFTER_EXPIRY` | structure | earliest_daa above expiry_daa | I2 |
| 24 | `TERMS_NETWORK_MISMATCH` | creation | Terms name another network | I2 |
| 25 | `TERMS_EXPIRY_NOT_AFTER_CREATION` | creation | expiry_daa is not above the creation DAA score | I2 |
| 26 | `TERMS_EXPIRY_BEYOND_HORIZON` | creation | expiry_daa is beyond the horizon | I2 |
| 27 | `TERMS_AUTHORITY_IS_PARTY` | structure | Authority equals the seller or the buyer | I4 |
| 28 | `TERMS_SAME_COVENANT` | structure | Both legs are KCC-20 with the same covenant ID | I4 |
| 29 | `TERMS_V2_VERSION` | decode v2, structure v2 | The terms v2 decoder was given a version byte other than 2 | I16 |
| 30 | `TERMS_VERSION_UNKNOWN` | decode_any | The version byte is neither 1 nor 2 | I16 |
| 31 | `TERMS_LEG_COUNT` | structure | leg_count is below 2 or above MAX_LEGS | I16 |
| 32 | `TERMS_LEGS_ONE_PARTY` | structure | Every leg has the same depositor key | I16 |
| 33 | `TERMS_AUTHORITY_IS_DEPOSITOR` | structure | The authority key equals a depositor key | I16 |
| 34 | `TERMS_LEG_KIND` | structure | A v2 leg is external | I16 |
| 35 | `TERMS_LEG_ORDER` | structure | A KCC-20 leg follows a KAS leg | I16 |
| 36 | `TERMS_LEGS_SAME_COVENANT` | structure | Two KCC-20 legs have the same covenant ID | I16 |
| 37 | `TERMS_PARTIAL_LOTS` | structure | lot_count is below 2, or min_lot is zero or above lot_count | I16 |
| 38 | `TERMS_PARTIAL_INDIVISIBLE` | structure | A leg amount is not a multiple of lot_count | I16 |

## TEMPLATE_ codes

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `TEMPLATE_ARTIFACT_INVALID` | startup check | The embedded artifact or `TEMPLATE_HASH` file cannot be used | I4 |
| 2 | `TEMPLATE_HASH_MISMATCH` | startup check | The template hash differs from the artifact's declared hash or from `TEMPLATE_HASH` | I4 |
| 3 | `TEMPLATE_LEG_INDEX` | leg index, decode | A leg index other than 0 or 1 | I4 |
| 4 | `TEMPLATE_NO_VAULT` | instantiate, decode | The terms give this leg no vault (Direct, or the cash leg of external cash) | I4 |
| 5 | `TEMPLATE_NOT_IMPULSE_VAULT` | decode, template hash of an instance | The script does not run the ImpulseVault template | I4 |
| 6 | `TEMPLATE_STATE_MALFORMED` | decode | The state does not parse as the ImpulseVault state | I4 |
| 7 | `TEMPLATE_STATE_INVALID` | decode | A state field holds a value no terms value encodes to | I4 |
| 8 | `TEMPLATE_NONCANONICAL` | decode | The script is not the instantiation of the terms it decodes to | I4 |
| 9 | `TEMPLATE_V2_ARTIFACT_INVALID` | v2 startup check | The embedded v2 artifact or `TEMPLATE_HASH_V2` file cannot be used | I16 |
| 10 | `TEMPLATE_V2_HASH_MISMATCH` | v2 startup check | The v2 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V2` | I16 |
| 11 | `TEMPLATE_V2_LEG_INDEX` | v2 leg index, decode v2 | A leg index outside 0 to leg_count - 1 | I16 |
| 12 | `TEMPLATE_V2_NOT_VAULT` | decode v2, v2 template hash of an instance | The script does not run the ImpulseVault v2 template | I16 |
| 13 | `TEMPLATE_V2_STATE_MALFORMED` | decode v2 | The state does not parse as the ImpulseVault v2 state | I16 |
| 14 | `TEMPLATE_V2_STATE_INVALID` | decode v2 | A v2 state field holds a value no terms v2 value encodes to | I16 |
| 15 | `TEMPLATE_V2_NONCANONICAL` | decode v2 | The script is not the v2 instantiation of the terms it decodes to | I16 |

## TX_ and IPST_ codes

Transaction builders (`impulse_core::tx`, `TRANSACTIONS.md`) and the IPST interchange form (`IPST.md`). One frozen list holds both prefixes, in the order the code declares them: the five `IPST_` codes sit among the `TX_` codes where they were added. `TX_UTXO_VALUE` and `IPST_TERMS_MISMATCH` were added in the I5 review, at the end. `TX_TOO_MANY_INPUTS` was added at the end of the v1 list, so it sits before the v2 codes, which follow that list. `TX_SIGNATURE` and `TX_SIGNATURE_SLOT` are defined in `TRANSACTIONS.md`.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `TX_WRONG_MODE` | all builders | The builder does not apply to these terms or this leg: a vault builder on Direct terms or the reverse, a fund builder for another leg kind, a cash leg passed of another kind, a token offered with a KAS cash refund | I5 |
| 2 | `TX_VAULT_MISMATCH` | fund | The funding vault is not the vault these terms give for its leg | I5 |
| 3 | `TX_EXPIRED` | fund, settle, direct | The trade can no longer settle by `expiry_daa`: the current DAA score is at or past it, or `earliest_daa` equals it | I5 |
| 4 | `TX_NOT_AT_VAULT` | settle, refund | A vault input is not a plain UTXO (no covenant ID) at the vault's scriptPubKey | I5 |
| 5 | `TX_ESCROW_MISMATCH` | settle, refund | The escrowed token UTXO is not the vault's: covenant, owner, amount, minter flag or template | I5 |
| 6 | `TX_LEG_AMOUNT` | settle, refund, direct | A leg UTXO does not hold exactly the leg amount where required (KAS cash vault, a non-depositor refund's token, Direct inputs) | I5 |
| 7 | `TX_TOKEN_TEMPLATE` | all builders with a KCC-20 leg | The KCC-20 artifact is not a KCC-20 template, or not the one the terms name for the leg | I5 |
| 8 | `TX_TOKEN_INPUT` | fund_kcc20, direct | A party's token input cannot be spent here: covenant, owner not a valid public key, a minter, a state the script does not hold, mixed owners, too little in total | I5 |
| 9 | `TX_KAS_INPUT` | all builders | A fee, funding or Direct KAS input is not a version-0 Schnorr P2PK UTXO without a covenant ID, or there is no fee input | I5 |
| 10 | `TX_DUPLICATE_INPUT` | all builders | One outpoint is spent twice | I5 |
| 11 | `TX_INSUFFICIENT_FUNDS` | all builders | The inputs do not cover the outputs and the fee | I5 |
| 12 | `TX_BELOW_MIN_KAS` | fund, direct, every change output | An output the builder creates holds less than the minimum KAS for its plurality | I5 |
| 13 | `TX_MASS` | all builders | The compute, transient or storage mass exceeds 100,000 grams | I5 |
| 14 | `TX_FEE_TOO_LOW` | all builders | The fee is below the minimum relay fee for the transaction's mass | I5 |
| 15 | `TX_NONSTANDARD_CHANGE` | all builders | The change scriptPubKey is not a standard version-0 script | I5 |
| 16 | `TX_REFUND_SIGNER` | refund | The role is not available: an authority refund without an authority, or a counterparty or authority refund of a KCC-20 leg without its token | I5 |
| 17 | `TX_SIGNATURE` | verify, IPST | A signature is not 65 bytes, its sighash type is not SIG_HASH_ALL, it is malformed, or it does not verify against the slot's signer and sighash | I5 |
| 18 | `TX_SIGNATURE_SLOT` | sighash, IPST | An input that does not exist or takes no signature, entries that do not match the inputs, or a signature missing at finalization | I5 |
| 19 | `TX_ENCODING` | all builders | A signature script or token state could not be encoded (for example a token amount above the script integer range) | I5 |
| 20 | `IPST_MALFORMED` | read | Not an IPST document: bad JSON, a missing or unknown key, a value of the wrong form, or inconsistent slot fields | I5 |
| 21 | `IPST_UNSUPPORTED_VERSION` | read | `ipst` is not 1 | I5 |
| 22 | `IPST_SIGHASH_MISMATCH` | read | A stated sighash differs from the recomputed one | I5 |
| 23 | `IPST_CONFLICT` | combine | The two IPSTs describe different transactions, or hold different signatures in one slot | I5 |
| 24 | `TX_UTXO_VALUE` | all builders | A UTXO the transaction spends holds zero sompi or more than `MAX_SOMPI`, or the spent UTXOs hold more than `MAX_SOMPI` together | I5 |
| 25 | `IPST_TERMS_MISMATCH` | terms check | The document is not the transaction the builders make for its terms from its own inputs | I5 |
| 26 | `TX_TOO_MANY_INPUTS` | settle, refund (v1, v2, v3 and hashlock builders) | The transaction would have more inputs than the vault template it spends allows: 12, or N + 18 for a template v2 settle (`TEMPLATE.md`, "Inputs outside the layout") | v0.4 |
| 27 | `TX_V2_NOT_AT_VAULT` | v2 settle, v2 refund | A v2 vault input is not at its vault's scriptPubKey, or carries a covenant ID under terms without partial | I16 |
| 28 | `TX_LEGS` | v2 settle | The settle is not offered exactly one vault UTXO per leg and one escrow per KCC-20 leg | I16 |
| 29 | `TX_TRANCHE` | v2 settle | The lots are not a whole number from 1 to what every escrow holds, are below min_lot, leave a remainder below min_lot lots, or name a tranche on terms without partial | I16 |
| 30 | `TX_LINEAGE` | v2 fund, v2 settle, v2 verify | A tranche from a vault input without a covenant ID, a genesis covenant ID that does not match the funding outpoint and output, or two vault UTXOs of one trade with the same covenant ID | I16 |
| 31 | `TX_LEGS_OUT_OF_STEP` | v2 settle | The legs' escrows do not hold the same number of lots | I16 |
| 32 | `TX_V2_MASS` | v2 builders | The compute, storage or transient mass exceeds its CAP_V2 cap (section 6.2) | I16 |
| 33 | `IPST_V2_VERSION` | IPST read | `ipst` is neither 1 nor 2 | I16 |

## VERIFY_ codes

The verifier (`impulse_core::verify`, `VERIFY.md`). `VERIFY_TOKEN_EXTENDED_STATE` and `VERIFY_INPUT_NOT_VAULT` were added in the I6 review, at the end. Template and terms refusals met on the way keep their own codes.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `VERIFY_ADDRESS_MALFORMED` | addresses | The offered address does not parse as a Kaspa address | I6 |
| 2 | `VERIFY_ADDRESS_NETWORK` | addresses | The offered address carries another network's prefix than the terms name | I6 |
| 3 | `VERIFY_ADDRESS_MISMATCH` | addresses | The offered address pays neither this leg's vault nor the other leg's | I6 |
| 4 | `VERIFY_ADDRESS_MISSING` | addresses | A leg with a vault was offered no address | I6 |
| 5 | `VERIFY_ADDRESS_UNEXPECTED` | addresses | An address was offered for a leg the terms give no vault | I6 |
| 6 | `VERIFY_LEGS_SWAPPED` | addresses, revealed script | What was offered as one leg is the other leg's vault of these terms | I6 |
| 7 | `VERIFY_TEMPLATE_MISMATCH` | revealed script | The script does not run the published template | I6 |
| 8 | `VERIFY_TERMS_MISMATCH` | revealed script | The script is a vault of other terms | I6 |
| 9 | `VERIFY_TOKEN_LEG_KIND` | token warnings | Token evidence for a leg that is not KCC-20 | I6 |
| 10 | `VERIFY_TOKEN_ARTIFACT_INVALID` | token warnings | The token artifact is too long, does not parse, does not hold one contract, declares a name that is not an identifier or a struct-typed state field, fails the consistency check, or, for a pinned template, declares an entry beyond the two KCC-20 entries | I6 |
| 11 | `VERIFY_TOKEN_TEMPLATE_MISMATCH` | token warnings | The token's template is not the one the terms name for the leg | I6 |
| 12 | `VERIFY_TOKEN_NOT_KCC20` | token warnings | The token's state or entries are not the KCC-20 ones the vault relies on | I6 |
| 13 | `VERIFY_NOTHING_REVEALED` | spent input | The input's signature script is not push only or reveals no script | I6 |
| 14 | `VERIFY_TOKEN_EXTENDED_STATE` | token warnings | The token's state has fields beyond KCC-20's four; the vault cannot settle or refund it | I6 |
| 15 | `VERIFY_INPUT_NOT_VAULT` | spent input | The input does not spend the version 0 P2SH of the script it reveals, so consensus never ran that script there | I6 |
| 16 | `VERIFY_V2_ADDRESS_MISMATCH` | v2 addresses | The offered address pays no leg's vault of these terms | I16 |
| 17 | `VERIFY_V2_WRONG_LEG` | v2 addresses | The offered address pays another leg's vault of these terms | I16 |
| 18 | `VERIFY_V2_TEMPLATE_MISMATCH` | v2 revealed script, v2 spent input | The revealed script does not run the pinned v2 template | I16 |

## DECODE_ codes

The transaction decoder (`impulse_core::decode`, `VERIFY.md`). `DECODE_ENTRY_UNKNOWN` and `DECODE_INPUT_NOT_VAULT` are also reported per input, beside the legs that did decode. `DECODE_INPUT_NOT_VAULT` was added in the I6 review, at the end.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `DECODE_TX_MALFORMED` | decode | The raw bytes are not one borsh-encoded transaction | I6 |
| 2 | `DECODE_TX_ID_MISMATCH` | decode | The transaction ID carried is not the ID of the contents | I6 |
| 3 | `DECODE_ENTRY_UNKNOWN` | decode, per input | A vault input calls no entry of the template | I6 |
| 4 | `DECODE_NO_VAULT_INPUT` | decode | No input spends an Impulse vault | I6 |
| 5 | `DECODE_SPENT_COUNT` | decode | The spent scriptPublicKeys supplied are not one per input | I6 |
| 6 | `DECODE_INPUT_NOT_VAULT` | decode, per input | An input reveals a vault script but does not spend its version 0 P2SH | I6 |

## TOKEN_ warnings

Data, not refusals: `token_warnings` and `before_funding` return them beside a successful check. A warning is read from the evidence supplied and never states that a token is safe: an empty list is not a safety claim. The refusals about a token are `VERIFY_TOKEN_*`.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `TOKEN_UNASSESSED` | token_warnings | No evidence was supplied for a KCC-20 leg | I6 |
| 2 | `TOKEN_MINTER_BRANCH` | token_warnings | The token's state declares the KCC-20 minter flag | I6 |
| 3 | `TOKEN_EXTRA_ENTRIES` | token_warnings | An unpinned token's artifact declares entries beyond KCC-20's transfer leader and delegate | I6 |
| 4 | `TOKEN_PARTY_IS_ISSUER` | token_warnings | A party key is among the issuer keys supplied | I6 |
| 5 | `TOKEN_TEMPLATE_UNPINNED` | token_warnings | The token's template is not a pinned kcc20.sil build; its declared state and entries are unauthenticated | I6 |
| 6 | `TOKEN_ISSUER_UNKNOWN` | token_warnings | No issuer keys were supplied | I6 |
| 7 | `TOKEN_FOREIGN_AT_VAULT` | none (retired; was fund, settle and refund build) | Retired in I26, never raised: a token of the other leg's own covenant owned by a vault's script hash cannot move, since every template requires the other leg's vault in a settle. Reserved: the name is never reused | security review, retired I26 |

## CLI_ codes

The `impulse` command line (`crates/impulse-cli`, `CLI.md`). Terms and template refusals met on the way keep their own `TERMS_*` and `TEMPLATE_*` codes. `CLI_DEPTH_BELOW_MINIMUM` to `CLI_URI_NOT_YOUR_LEG` were added in the I7 review rounds, at the end. `CLI_KAS_LEG_BELOW_MIN` to `CLI_IPST_OUTFLOW_TOO_HIGH` were added with the build, sign, merge, submit and decode commands (I7 phase 2), at the end. `CLI_CANCEL_NOT_DIRECT` and `CLI_CANCEL_INPUT_NOT_KAS` were added with `direct cancel build`, the Direct refund (I7 integration follow-up, 2026-10-11), at the end. `CLI_CANCEL_INPUT_AMBIGUOUS` and `CLI_CANCEL_INPUT_MISMATCH` were added in its review round 1, at the end. `CLI_TOKEN_TESTNET_ONLY` to `CLI_TOKEN_CARRIER_MISMATCH` were added with the testnet token helper, `token mint build` and `token list` (I7, 2026-10-11), at the end.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `CLI_FILE_READ` | any command that reads a file | An input file cannot be read, or is larger than its type's size cap (read only up to the cap) | I7 |
| 2 | `CLI_FILE_WRITE` | any command that writes a file | An output file cannot be written | I7 |
| 3 | `CLI_OUTPUT_EXISTS` | any command that writes a file | The output path already exists | I7 |
| 4 | `CLI_TERMS_JSON` | terms draft and terms file | A draft or terms file is not the JSON form of terms | I7 |
| 5 | `CLI_TERMS_FILE_INCONSISTENT` | terms file | A terms file's `terms`, `canonical` and `terms_hash` disagree | I7 |
| 6 | `CLI_NETWORK_MISMATCH` | terms, receipt | The terms or receipt name another network than the command acts on | I7 |
| 7 | `CLI_HEX` | argument parsing | A hash, txid or key argument is not 64 lowercase hex digits | I7 |
| 8 | `CLI_URI_MALFORMED` | verify --uri, check 1 | Funding URI check 1 (the URI is not of the exact form: address, amount, impulse hash) | I7 |
| 9 | `CLI_URI_TERMS_HASH_MISMATCH` | verify --uri, check 2 | Funding URI check 2 (the impulse parameter is not the terms hash) | I7 |
| 10 | `CLI_URI_ADDRESS_MISMATCH` | verify --uri, check 3 | Funding URI check 3 (the address is neither of the terms' vault addresses) | I7 |
| 11 | `CLI_URI_LEG_NOT_KAS` | verify --uri, check 4 | Funding URI check 4 (the vault's leg is not native KAS) | I7 |
| 12 | `CLI_URI_AMOUNT_MISMATCH` | verify --uri, check 5 | Funding URI check 5 (the amount is not the leg amount exactly) | I7 |
| 13 | `CLI_VALUE_CAP_INVALID` | value cap | `IMPULSE_MAX_VALUE` does not parse or is above the default | I7 |
| 14 | `CLI_VALUE_UNKNOWN` | value cap | A leg is not native KAS and no nonzero `--kas-equivalent` was given | I7 |
| 15 | `CLI_VALUE_CAP_EXCEEDED` | value cap | The trade value is above the cap (v4: funding only; a v4 settle or refund warns instead, I21) | I7 |
| 16 | `CLI_NODE_URL_INVALID` | node connection | The node URL is not `ws://` or `wss://` | I7 |
| 17 | `CLI_NODE_UNREACHABLE` | node connection | The connection to the node failed | I7 |
| 18 | `CLI_NODE_RPC` | node connection | An RPC call failed or returned something malformed | I7 |
| 19 | `CLI_NODE_NETWORK_MISMATCH` | node connection | The node is on another network | I7 |
| 20 | `CLI_NODE_NOT_SYNCED` | node connection | The node is not synced | I7 |
| 21 | `CLI_NODE_TXID_MISMATCH` | submit | The node returned another transaction ID than the one submitted | I7 |
| 22 | `CLI_TX_NOT_ACCEPTED` | status | The transaction is not accepted on the chain walked from `--from-block` | I7 |
| 23 | `CLI_QR` | address | The URI does not fit a QR code | I7 |
| 24 | `CLI_ROLE_KEY_MISMATCH` | role check | `--my-key` is not the terms' party key for `--role` | I7 |
| 25 | `CLI_DESTINATION_NOT_MINE` | role check | A delivery, proceeds or refund destination of the user's role pays the counterparty or the authority, differs from its pin, or without a pin does not pay `--my-key` | I7 |
| 26 | `CLI_DEPTH_BELOW_MINIMUM` | status --key-file | `status --key-file`: the depth is below `--min-depth`; nothing is signed | I7 |
| 27 | `CLI_NODE_INSECURE` | node connection | On mainnet, the node URL is neither `wss://` nor `ws://` to a loopback host | I7 |
| 28 | `CLI_MAINNET_NEEDS_NODE` | node connection | On mainnet, `--daa` was given: the creation DAA score must come from `--node` | I7 |
| 29 | `CLI_DESTINATION_PIN_INVALID` | role check | A `--my-delivery`, `--my-proceeds` or `--my-refund` pin does not parse, names another network, or names a destination the role does not have | I7 |
| 30 | `CLI_URI_NOT_YOUR_LEG` | verify --uri, check 7 | Funding URI check 7: the URI funds the vault of the counterparty's leg | I7 |
| 31 | `CLI_KAS_LEG_BELOW_MIN` | terms new, address, verify, fund build, ipst sign | The KAS cash leg is below `MIN_KAS_OUTPUT`: it has no standard settle; refused before funding | I7 |
| 32 | `CLI_TEMPLATE_UNPINNED` | address, verify, fund build, ipst sign | `address`, `verify`, `fund build`, `ipst sign` of a funding: a KCC-20 leg's template is not a pinned kcc20.sil build | I7 |
| 33 | `CLI_TEMPLATE_MISSING` | fund build, settle build, refund build, ipst sign, ipst merge, submit | A KCC-20 template the command needs was not given | I7 |
| 34 | `CLI_FUND_NOT_YOUR_LEG` | fund build, ipst sign | `fund build`: the leg is the counterparty's to fund, or `--pay-from` is not the P2PK address of `--my-key`; `ipst sign`: the funding is not the signer's leg | I7 |
| 35 | `CLI_ADDRESS_INVALID` | fund build, settle build, refund build | `--pay-from` is not a P2PK address of the network, or `--change` not a standard address of the network | I7 |
| 36 | `CLI_OUTPOINT_INVALID` | fund build, refund build | An outpoint or token argument is not `<txid>:<index>` or `<txid>:<index>:<amount>` | I7 |
| 37 | `CLI_UTXO_NOT_FOUND` | fund build, settle build, refund build | A UTXO the command looks for is not in the node's UTXO set | I7 |
| 38 | `CLI_UTXO_AMBIGUOUS` | refund build | `refund build`: several UTXOs at the vault and no `--vault-utxo` | I7 |
| 39 | `CLI_IPST_NOTHING_TO_SIGN` | ipst sign | `ipst sign`: no unsigned slot is for `--my-key` | I7 |
| 40 | `CLI_IPST_CHANGE_NOT_MINE` | ipst sign | `ipst sign` of a fee input: the change does not pay `--change` or the P2PK of `--my-key` | I7 |
| 41 | `CLI_IPST_FEE_TOO_HIGH` | ipst sign | `ipst sign` of a fee input: the fee is above `--max-fee` (default twice the minimum relay fee), or the signer signs more than three fee inputs and `--max-fee` is not given | I7 |
| 42 | `CLI_TX_NOT_FINAL` | submit | `submit`: the node would not yet accept the transaction's lock time | I7 |
| 43 | `CLI_IPST_TERMS_NOT_AGREED` | ipst sign | `ipst sign`: the IPST is for other terms than `--terms` or `--terms-hash` | I7 |
| 44 | `CLI_IPST_DEPOSIT_MISMATCH` | ipst sign | `ipst sign` of a KCC-20 funding: the carrier or authorizer KAS differs from `--carrier` or `--authorizer` | I7 |
| 45 | `CLI_IPST_TOPUP_TOO_HIGH` | ipst sign | `ipst sign` of a fee input of a settle, refund or Direct transaction: the payer cost beyond the fee is above `--max-topup` (default 0) | I7 |
| 46 | `CLI_IPST_OUTFLOW_TOO_HIGH` | ipst sign | `ipst sign`: the inputs the signer signs hold more of its KAS, less what comes back to it, than the trade takes plus `--max-fee` and `--max-topup` | I7 |
| 47 | `CLI_CANCEL_NOT_DIRECT` | direct cancel build | `direct cancel build`: the terms are vault terms, whose legs go home with `refund build` | I7 |
| 48 | `CLI_CANCEL_INPUT_NOT_KAS` | direct cancel build | `direct cancel build`: the role's Direct input is a KCC-20 token, which no builder spends back to its holder | I7 |
| 49 | `CLI_CANCEL_INPUT_AMBIGUOUS` | direct cancel build | `direct cancel build`: several UTXOs of exactly the cash amount at the buyer's address, and neither `--for-ipst` nor `--direct-input` names one | I7 |
| 50 | `CLI_CANCEL_INPUT_MISMATCH` | direct cancel build | `direct cancel build --for-ipst`: the IPST is not a Direct transaction of `--terms` whose input 1 is the buyer's exact KAS cash, or `--direct-input` names another UTXO | I7 |
| 51 | `CLI_TOKEN_TESTNET_ONLY` | token mint build, token list, any command that reads an IPST | `token mint build` or `token list` on mainnet, or a token genesis IPST whose terms name mainnet: the token helper acts on testnet only | I7 |
| 52 | `CLI_TOKEN_OWNER_INVALID` | token mint build, token list | `token mint build`, `token list`: `--owner` is not a valid x-only public key | I7 |
| 53 | `CLI_TOKEN_AMOUNT_INVALID` | token mint build, token list | `token mint build`, `token list`: `--amount` is 0 or above `i64::MAX` | I7 |
| 54 | `CLI_TOKEN_TEMPLATE_UNPINNED` | token mint build, token list, ipst sign, ipst merge, submit | `token mint build`, `token list`, or the genesis check: the KCC-20 template is not a pinned kcc20.sil build | I7 |
| 55 | `CLI_TOKEN_CARRIER_MISMATCH` | ipst sign | `ipst sign` of a token genesis: the KAS on the token output differs from `--carrier` | I7 |

## SIGN_ codes

The one module of the command line that reads a key file and signs (`CLI.md`, "Key file and the signing module"), in the order it checks. Messages name the path and never the key. The list is frozen by the test `errors_md_lists_every_code_of_the_cli_watcher_sdk_and_threshold`, since the code keeps no list of its own.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `SIGN_MAINNET_NOT_EXPLICIT` | signing::sign | The digest is for mainnet and `--network mainnet` was not passed | I7 |
| 2 | `SIGN_NETWORK_MISMATCH` | signing::sign | `--network mainnet` was passed for a testnet digest | I7 |
| 3 | `SIGN_KEY_FILE_UNREADABLE` | signing::sign | The path cannot be opened or read, or is not a regular file | I7 |
| 4 | `SIGN_KEY_FILE_PERMISSIONS` | signing::sign | Group or others have any access to the file (Unix) | I7 |
| 5 | `SIGN_KEY_FILE_FORMAT` | signing::sign | The content is not 64 hex digits with at most one final line feed | I7 |
| 6 | `SIGN_KEY_INVALID` | signing::sign | The 32 bytes are not a valid secp256k1 secret key | I7 |
| 7 | `SIGN_KEY_NOT_EXPECTED` | signing::sign | The key's x-only public key is not the expected signer | I7 |
| 8 | `SIGN_SELF_CHECK_FAILED` | signing::sign | The signature does not verify against the key's public key | I7 |

## RECEIPT_ codes

Settlement receipts (`CLI.md`, "Settlement receipt"). `impulse receipt verify` stops at the first refusal, in the order of the steps of that section. The order here is the one `CLI.md` lists the codes in.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `RECEIPT_MALFORMED` | receipt verify | The file is not the JSON form of a version 1 receipt, or names a key twice | I7 |
| 2 | `RECEIPT_SIGNATURE_INVALID` | receipt verify | The signature does not verify over the receipt digest for its signer | I7 |
| 3 | `RECEIPT_SIGNER_MISMATCH` | receipt verify | With --signer, the receipt names another signer | I7 |
| 4 | `RECEIPT_DAA_MISMATCH` | receipt verify | With --node, the accepting block has another DAA score than the receipt states | I7 |
| 5 | `RECEIPT_NOT_ACCEPTED` | receipt verify | With --node, the accepting block is not a chain block, or the virtual chain from it removes blocks or does not list the transaction among those it accepted | I7 |
| 6 | `RECEIPT_DEPTH_UNREACHED` | receipt verify | With --node, the node's current depth is below the depth the receipt states | I7 |
| 7 | `RECEIPT_TERMS_MISMATCH` | receipt verify | With --terms or --terms-hash, the receipt names another terms hash | I7 |
| 8 | `RECEIPT_TXID_MISMATCH` | receipt verify | With --txid, the receipt names another transaction | I7 |
| 9 | `RECEIPT_QUANTITY_MISSING` | v2 receipt verify | A version 2 receipt lacks the lots, cumulative, total, previous-receipt or per-leg quantity fields, or a version 1 receipt is offered for partial terms (spec/V2.md 4.6) | I17 |
| 10 | `RECEIPT_QUANTITY_MISMATCH` | v2 receipt verify, v2 status | The stated quantities do not follow from the terms, the cumulative passes the lot count or is not the previous cumulative plus the lots, or with --node the transaction moves other lots | I17 |
| 11 | `RECEIPT_LINEAGE_MISMATCH` | v2 receipt verify, v2 status | With a previous receipt: it is another trade's, its digest is not `prior_receipt`, or a vault input did not spend its continuation of the same covenant ID; with --node, the transaction's spent outpoints or covenant IDs differ from the receipt's | I17 |

## WATCH_ codes

Refusals of a call to the reference watcher (`crates/impulse-watch`, `WATCH.md`). Instantiation refusals met while adding a trade keep their own `TEMPLATE_*` and `TERMS_*` codes.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `WATCH_NETWORK_MISMATCH` | add trade | Terms of another network than the watcher's | I8 |
| 2 | `WATCH_TRADE_DUPLICATE` | add trade | Terms already watched | I8 |
| 3 | `WATCH_FINALITY_DEPTH_ZERO` | tracker setup | A finality depth of 0 | I8 |
| 4 | `WATCH_STRAY_SCRIPT_UNDERIVABLE` | add trade | The cash-vault script of external-cash terms could not be derived and checked against impulse-core's decode | I8 |
| 5 | `WATCH_TX_UNSIGNED` | keep_signed | `keep_signed`: an input with no signature script | I8 |
| 6 | `WATCH_TX_NOT_TRACKED` | keep_signed | `keep_signed`: settles or refunds no watched vault | I8 |
| 7 | `WATCH_TX_DUPLICATE` | keep_signed | `keep_signed`: the txid is already kept | I8 |
| 8 | `WATCH_SOURCE_FAILED` | poll | A node call failed, or the node's data was malformed (spent entries that do not match the inputs one for one); nothing was applied | I8 |
| 9 | `WATCH_TRADE_NOT_RESUMED` | poll | A poll while a trade of a resumed state has not been added again; nothing was walked | I8 |
| 10 | `WATCH_TRADE_UNKNOWN` | retire trade | Retiring a trade the state does not hold | I8 |
| 11 | `WATCH_RETENTION_TOO_SHORT` | retention setup | A retention window that is not above the finality depth | I8 |
| 12 | `WATCH_NODE_URL_INVALID` | node connection | The node URL is not `ws://` or `wss://` | I8 |
| 13 | `WATCH_NODE_INSECURE` | node connection | On mainnet, the node URL is neither `wss://` nor `ws://` to a loopback host | I8 |
| 14 | `WATCH_NODE_UNREACHABLE` | node connection | The connection to the node failed | I8 |
| 15 | `WATCH_NODE_NETWORK_MISMATCH` | node connection | The node is on another network than `--network` | I8 |
| 16 | `WATCH_NODE_NOT_SYNCED` | node connection | The node is not synced | I8 |
| 17 | `WATCH_NODE_RPC` | node connection, probe | A call made while starting, or by `probe`, failed or returned something malformed | I8 |
| 18 | `WATCH_FILE_READ` | terms file, signed-transaction file, state file | A terms file, a signed-transaction file or the state file cannot be read | I8 |
| 19 | `WATCH_TERMS_FILE_INVALID` | terms file | A terms file is not a terms file | I8 |
| 20 | `WATCH_TERMS_FILE_INCONSISTENT` | terms file | A terms file's canonical bytes and terms hash disagree | I8 |
| 21 | `WATCH_SIGNED_TX_INVALID` | signed-transaction file | A signed-transaction file is not the raw form of one transaction with the right carried ID | I8 |
| 22 | `WATCH_STATE_INVALID` | state file | A state file is not in the accepted form, or is not consistent with itself | I8 |
| 23 | `WATCH_STATE_MISMATCH` | state file | A state file belongs to another network | I8 |
| 24 | `WATCH_STATE_WRITE_FAILED` | state file | The state file (or its lock file) could not be written, or a new one has no directory to go in; a state file already there is untouched | I8 |
| 25 | `WATCH_STATE_LOCKED` | state file | Another watcher holds the state file | I8 |
| 26 | `WATCH_RETIRE_WATCHED` | run | A trade is both retired and given a terms file in one run | I8 |
| 27 | `WATCH_PROBE_FAILED` | probe | A check of `probe` failed | I8 |
| 28 | `WATCH_STATE_MISSING` | state file | The state file does not exist (its directory included) and `--init` was not given | I8 |
| 29 | `WATCH_STATE_EXISTS` | state file | `--init` was given and the state file exists | I8 |
| 30 | `WATCH_OUTPUT_FAILED` | run | The events of a round could not be written to stdout; the round's state was not saved | I8 |

## WATCH_ event flags

Flags an event carries in its `code` field. A flagged event is something the operator must look at; it is never reported as a plain funding or spend. These are reports, not refusals of a call.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `WATCH_STRAY_DEPOSIT` | watcher event | `stray_deposit` (an output pays the cash-vault script of external-cash terms, which Impulse never instantiates; no recovery builder, decision D14) | I8 |
| 2 | `WATCH_FUNDING_NOT_EXACT` | watcher event | `funded` with `exact: false` (a UTXO at the vault that is not the leg amount; only an exact UTXO can settle) | I8 |
| 3 | `WATCH_SPEND_UNCLASSIFIED` | watcher event | `unclassified_spend` (a spend of a vault UTXO the watcher cannot read as a settle or refund; never reported as one) | I8 |
| 4 | `WATCH_REBROADCAST_FAILED` | watcher event | `rebroadcast` refused; tried again after the next poll | I8 |
| 5 | `WATCH_REBROADCAST_ABANDONED` | watcher event | `rebroadcast` refused for the last allowed time; not tried again | I8 |
| 6 | `WATCH_REBROADCAST_PAST_EXPIRY` | watcher event | `rebroadcast` of a settle skipped at or past its trade's expiry | I8 |
| 7 | `WATCH_FINAL_REORGED` | watcher event | `reorg` of an acceptance already reported final | I8 |
| 8 | `WATCH_LINK_RETURN_EARLY` | watcher event | `linked` with a return vault funded while the opening is not settled | I22 |
| 9 | `WATCH_FOREIGN_TOKEN` | watcher event | `foreign_token`, retired in I26 and never raised: every template refuses a spend of a vault that also moves a token of a covenant that spend does not check. Reserved: the name is never reused | security review, retired I26 |

## SDK_ codes

The TypeScript and WASM SDK (`crates/impulse-wasm`), for what JavaScript can pass that Rust types cannot. impulse-core's `TERMS_*` and `TEMPLATE_*` codes pass through the SDK unchanged. A call on a freed object throws wasm-bindgen's own `Error` ("null pointer passed to rust"), and a call of any function before `init` throws a JavaScript `TypeError` raised by the engine, not by the SDK. Neither carries a `code`, both fail closed, and neither is in this catalogue. Measured once, with node 22.22.1 against the package built in this tree on 2026-10-10 (seven functions called before `init`, three calls on a freed `Terms`); no SDK test pins either behaviour yet (carried to I9).

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `SDK_ARGUMENT_TYPE` | argument check | An argument is not of the JavaScript type the API declares: bytes that are not a `Uint8Array` or whose buffer is detached, a leg index that is not an integer number of magnitude at most 2^53 - 1, a network that is not a string | I9 |
| 2 | `SDK_JSON_FORM` | JSON form | A terms object, creation context or network name breaks the JSON form of `ENCODING.md`, holds a value JSON cannot hold (undefined, NaN, an infinity, -0 where an integer is due, a bigint, a non-plain object, a getter, a symbol or non-enumerable key), or is past the SDK bounds (2^18 characters in all, 64 keys in one object, four levels of objects; a network name over 64 characters) | I9 |
| 3 | `SDK_MAINNET_NEEDS_NODE` | funding instructions | `fundingInstructions` on mainnet with a creation DAA score not marked as read from a node: a typed score is refused (`CLI.md`, "Terms draft and terms file") | I11 |
| 4 | `SDK_VALUE_CAP_INVALID` | value cap | The value cap in force is unusable: a `max_value` or `cap` that is not a decimal number of sompi or is above the default cap, or one given together with the flag that lifts the cap | I11 |
| 5 | `SDK_VALUE_UNKNOWN` | value cap | The trade's value is unknown: a leg is not native KAS and no KAS equivalent was declared, or a declared 0 stands for none | I11 |
| 6 | `SDK_VALUE_CAP_EXCEEDED` | value cap | The trade's value is above the cap that holds in v0.1; only `i_accept_the_risk` lifts it | I11 |
| 7 | `SDK_QR` | QR code | The text does not fit a QR code | I11 |
| 8 | `SDK_TERMS_INCONSISTENT` | terms text reader, requireSameAs | A terms document's `canonical` or `terms_hash` is not that of its `terms`, or terms read back from a form are not the terms they were to equal | I11 |
| 9 | `SDK_ROLE_KEY_MISMATCH` | role check | The key the user gave is not the terms' party key for the role the user claims (`CLI.md`, "Terms summary and role check") | I11 |
| 10 | `SDK_DESTINATION_NOT_MINE` | role check, wallet signing | A destination of the user's role pays the counterparty or the authority (whatever is pinned), differs from its pin, or without a pin does not pay the user's key | I11 |
| 11 | `SDK_DESTINATION_PIN_INVALID` | role check | A pin does not parse, names another network, or is not a destination | I11 |
| 12 | `SDK_WALLET_WIPED` | wallet | The wallet was wiped (or freed): its key is gone and it signs nothing | I11 |
| 13 | `SDK_WALLET_RANDOM` | wallet | The browser gave no randomness for a key, or eight draws in a row were not a valid key | I11 |
| 14 | `SDK_SIGN_MAINNET_NOT_EXPLICIT` | wallet signing | A mainnet document is signed without the explicit mainnet choice (`SIGN_MAINNET_NOT_EXPLICIT` of `CLI.md`) | I11 |
| 15 | `SDK_SIGN_NETWORK_MISMATCH` | wallet signing | A testnet document is signed with the mainnet choice made (`SIGN_NETWORK_MISMATCH`) | I11 |
| 16 | `SDK_SIGN_NOTHING_TO_SIGN` | wallet signing | The wallet's key signs no input of the document that still lacks its signature (`CLI_IPST_NOTHING_TO_SIGN`) | I11 |
| 17 | `SDK_SIGN_SELF_CHECK_FAILED` | wallet signing | The signature the wallet made did not verify under its public key before it left the wallet (`SIGN_SELF_CHECK_FAILED`) | I11 |
| 18 | `SDK_NODE_URL_INVALID` | node client | The node URL is not `ws://` or `wss://` with a host (`CLI_NODE_URL_INVALID`) | I11 |
| 19 | `SDK_NODE_INSECURE` | node client | On mainnet the node link is neither `wss://` nor `ws://` to `127.0.0.1` or `localhost` (`CLI_NODE_INSECURE`, which also allows `[::1]`; the SDK does not) | I11 |
| 20 | `SDK_NODE_NETWORK_MISMATCH` | node client | The node is on another network than the page acts on (`CLI_NODE_NETWORK_MISMATCH`) | I11 |
| 21 | `SDK_NODE_NOT_SYNCED` | node client | The node says it is not synced (`CLI_NODE_NOT_SYNCED`) | I11 |
| 22 | `SDK_RPC_REPLY` | node client | A node's reply is not the reply to the request, is malformed, or is an error of the node's (`CLI_NODE_RPC`); the node's words are quoted and cut | I11 |
| 23 | `SDK_TXID_MISMATCH` | node client | The node returned another transaction than the one asked for or submitted (`CLI_NODE_TXID_MISMATCH`) | I11 |
| 24 | `SDK_UTXO_NOT_FOUND` | plan builders | A UTXO a builder needs is not among those the node reported | I11 |
| 25 | `SDK_SIGN_CHANGE_NOT_MINE` | wallet signing | The wallet signs a fee input, and the change output does not pay the address it accepts, its own key unless it was given another (`CLI_IPST_CHANGE_NOT_MINE`) | I11 |
| 26 | `SDK_SIGN_FEE_TOO_HIGH` | wallet signing | The wallet signs a fee input, and the fee is above `max_fee` (default twice the minimum relay fee), or it signs more than three fee inputs and `max_fee` is not given (`CLI_IPST_FEE_TOO_HIGH`) | I11 |
| 27 | `SDK_SIGN_TOPUP_TOO_HIGH` | wallet signing | The wallet signs a fee input of a settle, refund or Direct transaction, and the fee inputs also put more into the trade outputs than `max_topup` (default none): the top-up of an authorizer or carrier funded below its minimum (`CLI_IPST_TOPUP_TOO_HIGH`) | I11 |
| 28 | `SDK_SIGN_OUTFLOW_TOO_HIGH` | wallet signing | The inputs the wallet signs hold more of its KAS, less what comes back to it, than the trade takes plus `max_fee` and `max_topup` (`CLI_IPST_OUTFLOW_TOO_HIGH`) | I11 |
| 29 | `SDK_DESTINATION_IN_WALLET` | role check, wallet signing | On mainnet, a destination of the user's role, the change, or another output pays a key that lives only in a wallet of the page, where nothing can spend it; pinned or not. On testnet it passes and the result says so | I11 |
| 30 | `SDK_RPC_NOT_FOUND` | node client | The node answered that the transaction asked for is not there (kaspad's `Transaction <id> not found` to `getMempoolEntry`), as against a reply that cannot be read | I11 |
| 31 | `SDK_FUND_NOT_YOUR_LEG` | plan builders, wallet signing | A funding of the cash leg is asked for by a key that is not the terms' buyer key (the first check of the buyer's cash funding, as in `fund build`), or a wallet signs a funding whose leg its key does not deposit: the seller funds the asset leg and the buyer the cash leg (`CLI_FUND_NOT_YOUR_LEG`) | I11 |
| 32 | `SDK_TEMPLATE_UNPINNED` | instructions, plan builders, wallet signing | A funding is given or signed for terms with a KCC-20 leg whose template (hash, prefix length, suffix length) is not one of the pinned kcc20.sil builds (`PINNED_KCC20_TEMPLATES`): the funding instructions, the addresses and builder of the buyer's cash funding, and the signature of a funding refuse it, with no override (`CLI_TEMPLATE_UNPINNED`) | I11 |
| 33 | `SDK_FUND_ASSET_NOT_FUNDED` | plan builders | The buyer's cash funding is built while the node reports no authorizer at the asset vault, or no token in the exact state the asset leg needs (owner the asset vault, the leg amount, the leg's covenant): the seller's asset leg is not funded | I11 |
| 34 | `SDK_FUND_ALREADY_FUNDED` | plan builders | The buyer's cash funding is built while the cash vault already holds a UTXO of exactly the cash amount, the deposit a settle takes | I11 |
| 35 | `SDK_SIGN_DEPOSIT_MISMATCH` | wallet signing | The wallet signs a KCC-20 funding whose output 0 (the KAS on the escrowed token) or output 1 (the authorizer) holds another amount than the signer confirms, by default the minimum of a KCC-20 output and of a KAS output; the terms check takes both amounts from the document, so only the signer can confirm them (`CLI_IPST_DEPOSIT_MISMATCH`) | I11 |

## THRESHOLD_ codes

The FROST threshold settlement authority (`impulse_core::threshold`, behind the non-default cargo feature `threshold`, `THRESHOLD.md`). The default build links none of it, so the parity tests read this list from the source text.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `THRESHOLD_PARAMS` | group shape | Threshold below 2 or above the number of parties | I13 |
| 2 | `THRESHOLD_PARTY` | key generation, sign, aggregate | A party identifier outside 1..=n | I13 |
| 3 | `THRESHOLD_DKG_PACKAGES` | key generation rounds 2 and 3, round-1 digest | Not exactly one package from every other party (rounds 2 and 3) or from every party (round-1 digest, round 1) | I13 |
| 4 | `THRESHOLD_DKG_CULPRIT` | key generation rounds 2 and 3 | A proof of knowledge (round 2) or a secret share (round 3) failed verification; names the sender | I13 |
| 5 | `THRESHOLD_TOO_FEW_SIGNERS` | sign, aggregate | Fewer signing commitments than the threshold | I13 |
| 6 | `THRESHOLD_SIGNER_NOT_IN_SET` | sign | The signer's commitment is absent from the set or is not the commitment of its nonces | I13 |
| 7 | `THRESHOLD_SHARES_MISMATCH` | aggregate | Signature shares not from exactly the parties of the signing set | I13 |
| 8 | `THRESHOLD_SHARE_INVALID` | aggregate | The shares do not sum to a valid signature; names every party whose share fails verification | I13 |
| 9 | `THRESHOLD_KEY_INVALID` | verify | The authority key is not an x-only secp256k1 point | I13 |
| 10 | `THRESHOLD_SIGNATURE_INVALID` | aggregate, verify | The signature does not verify under the authority key | I13 |
| 11 | `THRESHOLD_REFUSED` | any | Any other refusal by the FROST library (fail closed) | I13 |
| 12 | `THRESHOLD_ENCODING` | decoders of "Encodings" | The bytes are not the encoding of the value, or the value is inconsistent | I13 |
| 13 | `THRESHOLD_INPUT` | sign_input, aggregate_input | No such input in the transaction, or UTXO entries that do not match its inputs one for one | I13 |

## FROST_ codes

The `impulse frost` commands of the command line (`crates/impulse-cli`, `THRESHOLD.md`, section "CLI"): key generation, signing and aggregation of a FROST group. The commands also return `THRESHOLD_*`, `SIGN_*`, `CLI_*`, `IPST_*`, `TX_*`, `TERMS_*` and `TEMPLATE_*` codes unchanged. The list is frozen by the CLI test `frost_tests::frost_error_codes_are_frozen`. The CLI is not linked into the parity tests, so they read the list from the source text.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `FROST_SHARE_FILE_UNREADABLE` | frost sign (signing module) | The share file cannot be opened or read, or is not a regular file | I13 |
| 2 | `FROST_SHARE_FILE_PERMISSIONS` | frost sign (signing module) | Group or others have any access to the share file (Unix) | I13 |
| 3 | `FROST_SHARE_FILE_FORMAT` | frost sign (signing module) | The share file is not its tag and the hex of a key share, or the key share does not decode | I13 |
| 4 | `FROST_FILE_MALFORMED` | frost keygen, sign, aggregate | A round-1, round-2, group, commitment or signature-share file is not its tag and the hex of its body, or the body does not decode | I13 |
| 5 | `FROST_FILE_PERMISSIONS` | frost keygen | Group or others have any access to a round-2 file (Unix) | I13 |
| 6 | `FROST_SESSION_MISMATCH` | frost keygen, sign, aggregate | A file of another key generation or signing session: another shape, sender, recipient, round-1 transcript, session, set of authority inputs or commitment set | I13 |
| 7 | `FROST_NOT_CONFIRMED` | frost keygen, sign | The round-1 digest, group fingerprint or signing session typed back is not this party's | I13 |
| 8 | `FROST_ABORTED` | frost keygen, sign | The input ended before the step completed | I13 |
| 9 | `FROST_SIGNERS_INVALID` | frost sign, aggregate | `--signers` is not a comma-separated list of distinct party numbers | I13 |
| 10 | `FROST_NO_AUTHORITY_INPUT` | frost sign, aggregate | No input of the IPST waits for the terms' authority signature | I13 |
| 11 | `FROST_KEY_NOT_AUTHORITY` | frost sign, aggregate | The share's or the group file's authority key is not the terms' `authority_key` | I13 |
| 12 | `FROST_AUTHORITY_INPUT_NOT_VAULT` | frost sign, aggregate | A slot that names the authority key spends no vault UTXO of the terms, or the terms check found a transaction other than a settle or a refund by the authority | I13 |
| 13 | `FROST_ROUND2_NOT_REMOVED` | frost keygen | Key generation wrote the share and group files but could not remove a round-2 file addressed to this party | I13 |
| 14 | `FROST_TERMS_NOT_AGREED` | frost sign | The IPST is for other terms than `--terms` or `--terms-hash`, or neither was given | I14 |

## RELEASE_ codes

Finding codes of the maintainers' release pre-flight, a tool that is not part of the public tree. They are not refusals of the protocol software: the dry run prints one line per finding, PROBLEM (a defect to fix) or PENDING (owner-gated or later), and exits 0 unless a gate is asked for. The script keeps no list, so the test `errors_md_lists_every_release_dry_run_code` freezes the order and, where the script exists (the maintainers' checkout), compares the set with the codes the script raises.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `RELEASE_USAGE` | option parsing | Misuse of the dry run's options (exit 2) | I12 |
| 2 | `RELEASE_PKG_LIST_FAILED` | package check | `cargo metadata` or `cargo package --list` failed for a crate | I12 |
| 3 | `RELEASE_PKG_METADATA` | package check | A publishable crate has no description or no licence | I12 |
| 4 | `RELEASE_PKG_UNPUBLISHABLE_DEP` | package check | A crate depends on a git source, which crates.io refuses | I12 |
| 5 | `RELEASE_PKG_ESCAPES_CRATE` | package check | A crate reads paths outside its own directory | I12 |
| 6 | `RELEASE_PKG_FORBIDDEN_FILE` | package check | A crate package would include a file whose name looks like key material | I12 |
| 7 | `RELEASE_NPM_PACK_FAILED` | package check | `npm pack` failed, npm cannot run, or a `package.json` is unreadable | I12 |
| 8 | `RELEASE_NPM_FORBIDDEN_FILE` | package check | An npm package would include a file whose name looks like key material | I12 |
| 9 | `RELEASE_CHECKLIST_MISSING` | checklist | the release checklist is missing (the maintainers' plan may be absent: the public tree does not hold it) | I12 |
| 10 | `RELEASE_CHECKLIST_DRIFT` | checklist | A section 8 box has no A row or an A row is no box any more, or a required B or C row is missing | I12 |
| 11 | `RELEASE_CHECKLIST_ROW` | checklist | A checklist row is malformed: an id twice, the wrong number of cells, an empty cell, or evidence that is generic, missing or in the wrong place | I12 |
| 12 | `RELEASE_CHECKLIST_ORDER` | checklist | A row is not named in the step of "Order of the gates" at which it closes | I12 |
| 13 | `RELEASE_CHECKLIST_PENDING` | checklist | A checklist row is not done (a PENDING line, one per row) | I12 |
| 14 | `RELEASE_NOTES_PLACEHOLDER_MISSING` | release notes | The notes file, one of its headings or one of its placeholders is missing | I12 |
| 15 | `RELEASE_NOTES_STATUS` | release notes | The notes have no `Status: TEMPLATE` or `Status: FINAL` line | I12 |
| 16 | `RELEASE_NOTES_UNRESOLVED` | release notes | Placeholders remain in the notes (PENDING while the status is TEMPLATE, a problem once it is FINAL) | I12 |
| 17 | `RELEASE_NOTES_HASH_MISMATCH` | release notes | The notes do not state the hash in `contracts/TEMPLATE_HASH` | I12 |
| 18 | `RELEASE_NOTES_RISK` | release notes | The risk notice lacks one of its required sentences | I12 |
| 19 | `RELEASE_NOTES_VALUE_CAP` | release notes | The value cap guidance is empty, lacks its placeholder or states no default cap | I12 |
| 20 | `RELEASE_NOTES_MAINTAINER_SECTION` | release notes | FINAL notes still hold the maintainer instructions | I12 |
| 21 | `RELEASE_NOTES_TXID_ROW` | release notes | The transaction table lacks a row, a row lacks one transaction ID in its cell, or the IDs are not distinct | I12 |
| 22 | `RELEASE_NOTES_TXID_UNEVIDENCED` | release notes | A listed transaction ID is not recorded for its mode and direction in the evidence file | I12 |
| 23 | `RELEASE_PLACEHOLDER_URL` | release documents | A link on a reserved or example host | I12 |
| 24 | `RELEASE_INVENTED_VALUE` | release documents | A transaction ID or an amount in a TEMPLATE, or a reward figure in a draft | I12 |
| 25 | `RELEASE_DRAFT_MARKER` | publication drafts | A draft's status line is missing or contradicts the record | I12 |
| 26 | `RELEASE_DRAFT_UNRESOLVED` | publication drafts | A published draft holds unresolved placeholders | I12 |
| 27 | `RELEASE_BOUNTY_UNPUBLISHED` | publication drafts | The bounty terms are still a draft (PENDING) | I12 |
| 28 | `RELEASE_KGPR_RECORD_MISSING` | publication record | There is no KGPR record; the publication is an owner action (PENDING) | I12 |
| 29 | `RELEASE_KGPR_RECORD_FIELD` | publication record | The KGPR record is unreadable, or a field is missing, a placeholder, a filler value or invalid | I12 |
| 30 | `RELEASE_KGPR_RECORD_NETWORK` | publication record | The KGPR anchor network is not mainnet | I12 |
| 31 | `RELEASE_PLACEHOLDER` | release documents | A known placeholder remains (PENDING) | I12 |
| 32 | `RELEASE_SECURITY_NO_CONTACT` | release documents | `SECURITY.md` has no `security@` contact line | I12 |
| 33 | `RELEASE_EMDASH` | wording screen | An em dash in a file | I12 |
| 34 | `RELEASE_OWNERSHIP_WORDING` | wording screen | Wording that contradicts the ownership rule | I12 |
| 35 | `RELEASE_VEHICLE_WORDING` | wording screen | Wording that contradicts the owner's ruling that the release is commercialised through KiiLabs | I12 |
| 36 | `RELEASE_UNVERIFIED_CLAIM` | wording screen | Wording of a claim that cannot be verified (rule 7, docs/ENGINEERING-RULES.md) | I12 |
| 37 | `RELEASE_SPEC_WORDING` | wording screen | The three wording screens applied to `spec/` (PENDING: a hit needs a spec change the owner approves) | I12 |
| 38 | `RELEASE_DRAFT_HASH` | publication drafts | A published draft's template hash or an attachment hash differs from the one it must state | I12 |
| 39 | `RELEASE_NOTES_TOOLCHAIN` | release notes | The toolchain pins in the notes differ from those of `scripts/ci-local.sh` | I12 |
| 40 | `RELEASE_NOTES_TXID_TESTNET` | release notes | A listed transaction appears on a testnet line or under a testnet heading of the evidence file | I12 |
| 41 | `RELEASE_DRAFT_UNFILLED` | publication drafts | A draft has placeholders to fill before publication (PENDING) | I12 |
| 42 | `RELEASE_ZK_V4_LIVE_PENDING` | template v4 | The real-receipt tests of template v4 have not run (PENDING; blocks every gate) | I21 |

## ZK_ codes

Proof-carrying settlement (`impulse_core::zk`, behind the non-default cargo feature `zk`, `V3-ZK.md` section 12). The default build links none of it, so the parity tests read this list from the source text. `ZK_PROVER` and `ZK_PROVER_IMAGE` are raised by the prover under `circuits/`, which is its own cargo workspace; the frozen list holds them so that every `ZK_` code has one place. The v3 terms also return the v1 `TERMS_` codes whose meaning applies unchanged, the v3 template the `TEMPLATE_` codes and the v3 builders the v1 `TX_` codes, with `ZK_TX_MASS` in place of `TX_MASS` (`V3-ZK.md` sections 7.2, 7.3, 12).

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `ZK_TERMS_VERSION` | decode v3, structure v3 | The terms v3 decoder was given a version byte other than 3 | I20 |
| 2 | `ZK_TERMS_DIRECT` | structure v3 | Terms v3 name Direct settlement | I20 |
| 3 | `ZK_DELIVERY_OWNER_TYPE` | structure v3 | The buyer delivery owner is not of type PUBKEY or SCRIPT_HASH | I20 |
| 4 | `ZK_ROOT_INVALID` | structure v3 | list_root is all zero or the root of the empty tree | I20 |
| 5 | `ZK_ARTIFACT_INVALID` | v3 startup check | The embedded v3 artifact, `TEMPLATE_HASH_V3` or `IMAGE_ID` cannot be used | I20 |
| 6 | `ZK_TEMPLATE_HASH_MISMATCH` | v3 startup check | The v3 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V3` | I20 |
| 7 | `ZK_IMAGE_ID_MISMATCH` | v3 startup check, prove | The image ID in template v3 differs from `circuits/IMAGE_ID` or from the prover's guest | I20 |
| 8 | `ZK_NOT_V3_VAULT` | decode v3 | The script does not run template v3 | I20 |
| 9 | `ZK_STATE_MALFORMED` | decode v3 | The state does not parse as the v3 state | I20 |
| 10 | `ZK_STATE_INVALID` | decode v3 | A v3 state field holds a value no terms v3 value encodes to | I20 |
| 11 | `ZK_NONCANONICAL` | decode v3 | The script is not the v3 instantiation of the terms it decodes to | I20 |
| 12 | `ZK_LIST_ENTRY` | list build | An entry is not a Schnorr P2PK or P2SH address or owner of the terms' network | I20 |
| 13 | `ZK_LIST_SIZE` | list build | The list is empty or has more than 1,048,576 entries | I20 |
| 14 | `ZK_NOT_MEMBER` | list path | The delivery owner is not in the list | I20 |
| 15 | `ZK_PATH_INVALID` | prove, settle build, verify | The path file is malformed or does not lead from the owner's salted leaf to list_root | I20 |
| 16 | `ZK_PROOF_MALFORMED` | settle build, IPST read | The proof is not 128 bytes or does not parse as a compressed Groth16 proof | I20 |
| 17 | `ZK_PROOF_INVALID` | settle build | The proof does not verify for this vault's journal in the pinned engine | I20 |
| 18 | `ZK_PROVER` | prove | No receipt was produced: r0vm or the Groth16 step is missing or of another version, or the guest refused | I20 |
| 19 | `ZK_TX_MASS` | v3 builders | The compute, storage or transient mass exceeds its v3 cap (section 10) | I20 |
| 20 | `ZK_IPST_VERSION` | v3 IPST read | `ipst` is not 4 | I20 |
| 21 | `ZK_VERIFY_ADDRESS_MISMATCH` | v3 addresses | The offered address pays neither vault of these v3 terms | I20 |
| 22 | `ZK_VERIFY_TEMPLATE_MISMATCH` | v3 revealed script | The revealed script does not run the pinned template v3 | I20 |
| 23 | `ZK_ISSUER_KEY` | structure v3 | list_issuer_key is not a valid BIP-340 x-only public key | I20 |
| 24 | `ZK_AUTHORITY_ABSENT` | `impulse zk terms new` | Terms v3 without an authority were requested without `--no-authority` | I20 |
| 25 | `ZK_MANIFEST_INVALID` | list manifest, verify | The manifest is malformed, names another root or network, or its signature does not verify under list_issuer_key | I20 |
| 26 | `ZK_PROVER_IMAGE` | prove | The local Groth16 prover image's digest differs from `circuits/GROTH16_PROVER_IMAGE` | I20 |

## ZK_H_ codes

Hashed-terms vault, template v4 (`impulse_core::zkh`, behind the non-default cargo feature `zk-hashed`, `V3-ZK.md` section 22.8). The rows number 1 to 19 here; `V3-ZK.md` section 22.8 numbers the same codes 27 to 45 after `ZK_` code 26. In the sentence below, codes are named by that spec number. The same rules hold: v1's `TERMS_` and `TX_` codes apply where `V3-ZK.md` section 22 says so, and the meanings of `ZK_PROVER`, `ZK_PROVER_IMAGE`, `ZK_IMAGE_ID_MISMATCH` (with `IMAGE_ID_V4`) and `ZK_TX_MASS` apply to v4 unchanged. In I21 the verifier raises codes 27 to 39 (`impulse decode --with-terms`, `impulse zk terms reveal`, `zk address`, `zk verify`) and the builders raise codes 40 to 45 (`impulse zk terms new-hashed`, `fund build`, `settle build`, `refund build`, `witness`, and `ipst sign`, `merge`, `raw` and `submit` for IPST version 5), each with a negative test.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `ZK_H_TERMS_VERSION` | decode terms v4 | The version byte is not 4 | I21 |
| 2 | `ZK_H_TERMS_DIRECT` | structure v4 | Terms v4 name Direct settlement | I21 |
| 3 | `ZK_H_AUTHORITY_REQUIRED` | structure v4 | Terms v4 name no authority | I21 |
| 4 | `ZK_H_BLIND_INVALID` | structure v4 | `blind` is all zero | I21 |
| 5 | `ZK_H_ARTIFACT_INVALID` | v4 startup check | The embedded v4 artifact, `TEMPLATE_HASH_V4` or `IMAGE_ID_V4` cannot be used | I21 |
| 6 | `ZK_H_TEMPLATE_HASH_MISMATCH` | v4 startup check | The v4 template hash differs from the artifact's or from `TEMPLATE_HASH_V4` | I21 |
| 7 | `ZK_H_NOT_V4_VAULT` | decode | The script does not run template v4 | I21 |
| 8 | `ZK_H_STATE_MALFORMED` | decode | The state is not (commitment, authority key) | I21 |
| 9 | `ZK_H_NONCANONICAL` | decode | The script is not the v4 instantiation of its state | I21 |
| 10 | `ZK_H_TERMS_MISMATCH` | decode, verify | The terms' commitment for neither leg equals the vault's | I21 |
| 11 | `ZK_H_STATEMENT_FALSE` | prove, decode `--with-terms`, builders | A tag of 22.4 fails on the view; the message names the tag | I21 |
| 12 | `ZK_H_WITNESS_INVALID` | prove | A scriptPubKey or redeem script given does not open to its view item | I21 |
| 13 | `ZK_H_SHAPE` | builders, prove | `n_in` or `n_out` is not the layout of the terms, or a settle or refund would have more than eight inputs | I21 |
| 14 | `ZK_H_PROOF_MALFORMED` | settle and refund build, `ipst raw`, `submit` | A proof file or an IPST holds no usable proof: not 128 bytes, all zero bytes, another form of file, or a vault input still holds the zero placeholder of a plan | I21 |
| 15 | `ZK_H_PROOF_INVALID` | settle and refund build, `ipst raw`, `submit` | A proof file's journal is not the one the vault input builds, or the pinned engine refuses the vault input because the precompile refused the proof | I21 |
| 16 | `ZK_H_IPST_VERSION` | v4 IPST read | `ipst` is not 5 | I21 |
| 17 | `ZK_H_VERIFY_ADDRESS_MISMATCH` | verify | The offered address is not the v4 vault of these terms for its leg | I21 |
| 18 | `ZK_H_TERMS_FILE` | `terms new-hashed`, every v4 command that reads a terms file | The terms file cannot be read, is not exactly the lowercase hex of the canonical terms, or did not read back to the terms written | I21 |
| 19 | `ZK_H_CAP_OVERRIDE` | every v4 command that takes the cap arguments | The value-cap override flag was given; v4 never accepts it | I21 |

## HTLC_ codes

The hashlock terms, template, builders and verifier (`impulse_core::htlc`, `V2.md` section 10, I18). The frozen list is `HTLC_ERROR_CODES`, pinned by `htlc::tests::htlc_error_codes_are_frozen` and compared with `V2.md` section 8.5 by the parity test `htlc::errors_md_lists_every_htlc_code`. The hashlock code also returns, unchanged in meaning, the `TERMS_` codes `V2.md` section 8.5 names, the builders' `TX_` and `IPST_TERMS_MISMATCH` codes, and the verifier's `VERIFY_ADDRESS_MALFORMED`, `VERIFY_ADDRESS_NETWORK`, `VERIFY_ADDRESS_MISMATCH`, `VERIFY_ADDRESS_MISSING`, `VERIFY_TERMS_MISMATCH`, `VERIFY_NOTHING_REVEALED` and `VERIFY_INPUT_NOT_VAULT` (decision D51).

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `HTLC_VERSION` | decode, structure | The hashlock terms version byte is not 1 | I18 |
| 2 | `HTLC_ASSET_KIND` | structure | The hashlock asset leg is not KCC-20 | I18 |
| 3 | `HTLC_HASH_ZERO` | structure | hash_lock is all zero | I18 |
| 4 | `HTLC_COUNTERPART` | decode, structure, creation | The counterpart record names an unknown chain, has a zero amount, an all-zero identifier, or a timeout of zero or above `i64::MAX`; at creation, its timeout is at or before the time of the check | I18 |
| 5 | `HTLC_TIMEOUT_MARGIN` | creation | expiry_daa does not reach past the counterpart timeout by the required margin | I18 |
| 6 | `HTLC_ARTIFACT_INVALID` | startup check | The embedded hashlock artifact or `TEMPLATE_HASH_HASHLOCK` cannot be used | I18 |
| 7 | `HTLC_HASH_MISMATCH` | startup check | The hashlock template hash differs from the artifact's or from `TEMPLATE_HASH_HASHLOCK` | I18 |
| 8 | `HTLC_NOT_HASHLOCK_VAULT` | decode | The script does not run the hashlock template | I18 |
| 9 | `HTLC_STATE_MALFORMED` | decode | The state does not parse as the hashlock state | I18 |
| 10 | `HTLC_STATE_INVALID` | decode | A state field holds a value no hashlock terms value encodes to | I18 |
| 11 | `HTLC_NONCANONICAL` | decode | The script is not the instantiation of the terms it decodes to | I18 |
| 12 | `HTLC_SECRET_LENGTH` | claim | The secret is not 32 bytes | I18 |
| 13 | `HTLC_SECRET_MISMATCH` | claim | sha256 of the secret is not hash_lock | I18 |
| 14 | `HTLC_DAA_SAMPLE` | creation | On mainnet, no DAA rate sample is given, or it is older than 30 days, or it was taken at another blocks-per-second than the configured network's, or its mean DAA rate is below half the network's target rate (section 10.5) | I18 |
| 15 | `HTLC_MAINNET_GATED` | creation, fund, verify_address | Reserved, no longer returned: the mainnet gate was lifted by D39 (b) and D40 (section 10.5) | I18 |
| 16 | `HTLC_FUNDING` | verify_funding | A funding transaction does not fund the terms' vault: no output, or more than one, holds the escrowed token (the asset's covenant and template, owned by the vault's script hash, exactly the amount, not a minter), or no authorizer pays the vault's address (section 10.5, step 3) | I18 |

The hashlock contract (`contracts/impulse_hashlock.sil`, template hash in `contracts/TEMPLATE_HASH_HASHLOCK`) refuses a spend by failing the script, as the v1 contract does (see "On-chain refusals"). Its tags are scoped to it: `[H1]` to `[HR14]` name its requires only. The engine tests in `tests/engine/htlc_settle.rs` and `tests/engine/htlc_refund.rs` are named after them, and `tests/engine/mutation-run-htlc.txt` records that removing any one is caught by its test.

### Hashlock: settleWithPreimage

| Tag | Refuses unless |
| --- | --- |
| `[HF2]` | the transaction has at most 12 inputs |
| `[H1]` | The hashlock vault input is input 0 |
| `[H2]` | The preimage is exactly 32 bytes |
| `[H3]` | sha256 of the preimage is hash_lock |
| `[HE1]` | The escrowed token is the only input of the asset covenant |
| `[HE2]` | That input is input 1 |
| `[HE3]` | The escrowed token's owner type is SCRIPT_HASH |
| `[HE4]` | The escrowed token's owner is this vault's script hash |
| `[HE5]` | The escrowed token holds exactly the amount |
| `[HE6]` | The escrowed token is not a minter |
| `[HF1]` | every input from input 1 on carries no covenant or the asset leg's covenant |
| `[HD1]` | Output 0 carries the asset covenant ID |
| `[HD2]` | Output 0 carries at least the escrowed token's own KAS |
| `[HS8]` | Output 1 pays the seller's key |
| `[HS9]` | Output 1 holds at least the vault input's value |

### Hashlock: refund

| Tag | Refuses unless |
| --- | --- |
| `[HF4]` | the transaction has at most 12 inputs |
| `[HR1]` | The named signer is the seller or the buyer |
| `[HR2]` | The signature verifies for the named signer |
| `[HR3]` | A refund signed by the seller has a lock time of at least expiry_daa (an unsatisfied lock time) |
| `[HR4]` | The vault UTXO being refunded is input 0 |
| `[HR5]` | Output 0 holds exactly input 0's value |
| `[HR7]` | Output 0 pays the seller's key |
| `[HF3]` | every input from input 1 on carries no covenant or the asset leg's covenant |
| `[HR11]` | A refund signed by the buyer carries exactly one input of the asset covenant |
| `[HR8]` | At most one input of the asset covenant |
| `[HR9]` | That input is input 1 |
| `[HR12]` | The token at input 1 is owned by this vault's script hash |
| `[HR14]` | A refund signed by the buyer returns a token holding exactly the amount |
| `[HR10]` | Output 1 carries the asset covenant ID |
| `[HR13]` | Output 1 carries at least the token input's KAS |

Two builtins refuse without a tag, as in the v1 contract: `readInputStateWithTemplate` (the escrowed token runs the KCC-20 template the terms name, and holds the state it claims) and `validateOutputStateWithInputTemplate` (output 0 of a claim is that template with the buyer's delivery owner, exactly the amount and no minter flag; output 1 of a refund with the token is that template with the seller's refund owner and the token's own amount and minter flag).

## XCHAIN_ codes

The `impulse xchain` commands (`crates/impulse-cli/src/xchain.rs`, `V2.md` section 10.9, I18). The frozen list is `XCHAIN_ERROR_CODES`, pinned by `xchain::tests::xchain_error_codes_are_frozen` and compared with `V2.md` by the parity test `htlc::errors_md_lists_every_xchain_code`: rows 1 to 7 with the `XCHAIN_` table of section 8.5, rows 8 to 10 with the table of section 10.9, which section 8.5 takes at its next edit (decision D55; row 10 from I18 review round 4). The commands also return, unchanged in meaning, the `CLI_`, `SIGN_`, `HTLC_`, `TERMS_`, `TX_` and `IPST_` codes `V2.md` section 10.9 names for each check.

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `XCHAIN_CHAIN_UNSUPPORTED` | xchain | The counterpart chain has no source in this build | I18 |
| 2 | `XCHAIN_COUNTERPART_MISMATCH` | xchain verify-counterpart | The counterpart HTLC found on its chain differs from the counterpart record (program, asset, amount, recipient, refund, hash, timeout) or is not funded | I18 |
| 3 | `XCHAIN_NOT_FINAL` | xchain verify-counterpart, watch, verify-funding | The counterpart lock or reveal, or the Kaspa funding, is not yet at the required finality | I18 |
| 4 | `XCHAIN_REVEAL_NOT_FOUND` | xchain watch | No counterpart claim revealing the secret was found | I18 |
| 5 | `XCHAIN_MARGIN_TOO_SHORT` | xchain new, claim | Less time remains than the configured safety margin | I18 |
| 6 | `XCHAIN_HASH_REUSED` | xchain new, xchain verify | The hash_lock already appears in a hashlock vault known to this installation or found at verify | I18 |
| 7 | `XCHAIN_NODE_BPS` | xchain new, claim | The node reports a blocks-per-second rate other than the configured network's | I18 |
| 8 | `XCHAIN_MAINNET_GATED` | every xchain command but daa-sample | Reserved, no longer returned: the mainnet gate was lifted by D39 (b) and D40 (section 10.5) | I18 |
| 9 | `XCHAIN_SECRET_FILE` | xchain claim, counterpart-claim | The secret file is not a regular file of 64 lowercase hex digits with at most one final line feed, or group or others can access it | I18 |
| 10 | `XCHAIN_TX_UNRELATED` | xchain status | The transaction is not part of this trade: it neither spends the trade's vault nor pays the vault's address or its escrow | I18 |

## LINKED_ codes

Linked trades, an opening and a return described by one sheet (`impulse_core::linked`, `V2.md` section 17, I22). The frozen list is `LINKED_ERROR_CODES`, pinned by `linked::tests::linked_error_codes_are_frozen` and compared with `V2.md` section 17.10 by the parity test `linked::errors_md_lists_every_linked_code`. The linked code also returns, unchanged in meaning, the `TERMS_` codes of the sheet's opening and of the derived return, the builders' `TX_` codes, and the `VERIFY_` codes of the v2 verifier. The `impulse linked` commands add no code of their own: they use `CLI_TERMS_JSON`, `CLI_TERMS_FILE_INCONSISTENT`, `CLI_TX_NOT_ACCEPTED`, `CLI_DEPTH_BELOW_MINIMUM`, and the `RECEIPT_` codes of a linked receipt (D104).

| # | Code | Raised by | Meaning | Since |
| --- | --- | --- | --- | --- |
| 1 | `LINKED_VERSION` | sheet decode, checks | The sheet's link_version is not 1 | I22 |
| 2 | `LINKED_TRUNCATED` | sheet decode | The sheet ends inside a field | I22 |
| 3 | `LINKED_TRAILING_BYTES` | sheet decode | Bytes follow the sheet's last field | I22 |
| 4 | `LINKED_LEG_COUNT` | sheet checks | The opening does not have exactly two legs | I22 |
| 5 | `LINKED_PARTIAL` | sheet checks | The opening has partial settlement | I22 |
| 6 | `LINKED_TRADE_REF_SET` | sheet checks | The opening's trade_ref is not zero | I22 |
| 7 | `LINKED_RETURN_NOT_LATER` | sheet checks | return_earliest_daa is not above the opening's expiry_daa | I22 |
| 8 | `LINKED_NOT_A_LEG` | verify terms | The terms are not a derived trade of the sheet | I22 |
| 9 | `LINKED_ROLE_MISMATCH` | verify terms | The terms are the other role's derived trade | I22 |
| 10 | `LINKED_TRADE_REF` | verify terms | The terms are the derived trade except for trade_ref | I22 |
| 11 | `LINKED_OPENING_NOT_SETTLED` | return fund, return settle | No evidence of an opening settle for this sheet | I22 |
| 12 | `LINKED_SETTLE_EVIDENCE` | settle evidence | The transaction is not a settle of both vaults of the trade of the role | I22 |
| 13 | `LINKED_RECEIPT_TERMS` | receipt verify | The receipt names another sheet, another leg trade or another network than the sheet gives | I22 |
| 14 | `LINKED_RECEIPT_PAIR` | receipt pair | The two receipts are not an opening then a return of one sheet | I22 |

## Retired and changed codes

| Code | Change | When | Integrator note |
| --- | --- | --- | --- |
| `TERMS_PARTIES_NOT_DISTINCT` | Narrowed before 1.0: it now means buyer equals seller only. An authority key equal to the seller's or the buyer's key is `TERMS_AUTHORITY_IS_PARTY` | I4 | Until I4 both cases returned `TERMS_PARTIES_NOT_DISTINCT`. Code that matched it for the authority case must also match `TERMS_AUTHORITY_IS_PARTY` |
| `TEMPLATE_SAME_COVENANT` | Retired before it reached `main`: one token on both legs is refused by the structure checks as `TERMS_SAME_COVENANT`, so no `ValidatedTerms`, and no vault, exists for such terms | I4 (review item 2) | Never returned by any merged build. Reserved: the name is never reused |
| `DECODE_SIGSCRIPT_MALFORMED` | Withdrawn before it reached `main`: an input whose signature script is not push only is no vault spend and is skipped, so the decoder needs no refusal for it | I6 (review round 1) | Never returned by any merged build. Reserved: the name is never reused |
| `TOKEN_EXTENDED_STATE` | Withdrawn before it reached `main`: a token with state beyond KCC-20's four fields is the refusal `VERIFY_TOKEN_EXTENDED_STATE`, not a warning, because the vault cannot settle or refund it | I6 (review round 1) | Never returned by any merged build. Reserved: the name is never reused |
| `TOKEN_FOREIGN_AT_VAULT` | Retired after it reached `main`: known limitation L20 is closed in every template (each settle requires the other leg's vault), so a token of a leg's own covenant at the other leg's vault cannot move and there is nothing to warn about | I26 | No build from I26 on raises it. Its row stays in `## TOKEN_ warnings` and in the frozen list. Reserved: the name is never reused |
| `WATCH_FOREIGN_TOKEN` | Retired after it reached `main`: every template refuses a spend of a vault that also moves a token of a covenant that spend does not check, so the watcher no longer looks for one | I26 | No build from I26 on raises it; an earlier state file holding a `foreign_token` effect still reads back. Its row stays in `## WATCH_ event flags` and in the frozen list. Reserved: the name is never reused |

## On-chain refusals

The contract (`contracts/impulse_vault.sil`, template hash in `contracts/TEMPLATE_HASH`) refuses a spend by failing the script. The engine reports a failed script, for `[S3]` and `[R3]` an unsatisfied lock time, never a code. The tags below name each `require` in the source; the engine tests in `tests/engine` are named after them, and `tests/engine/mutation-run.txt` records that removing any one is caught by its test. They are listed so that refusals off chain and on chain share one catalogue, and so that `PARITY.md` can name the check behind a row.

### settle

| Tag | Refuses unless |
| --- | --- |
| `[F4]` | the transaction has at most 12 inputs |
| `[S1]` | The vault input sits at its leg's canonical index: the asset authorizer at input 0, the cash authorizer at input 1 |
| `[E1]` | The leg's escrowed token is the only input of the leg's covenant in the transaction |
| `[E2]` | That input sits at the escrow position: input 2 for the asset (input 1 under external cash), input 3 for KCC-20 cash |
| `[E3]` | The escrowed token's owner type is SCRIPT_HASH |
| `[E4]` | The escrowed token's owner is this vault's script hash |
| `[E5]` | The escrowed token holds exactly the leg amount |
| `[E6]` | The escrowed token is not a minter |
| `[S2]` | A KAS cash vault UTXO holds exactly amount_b |
| `[S3]` | When earliest_daa is set, the lock time is at least earliest_daa (an unsatisfied lock time) |
| `[D1]` | A KCC-20 delivery output carries the leg's covenant ID |
| `[D2]` | A KCC-20 delivery output carries at least the escrowed token's own KAS |
| `[S4]` | KAS cash: output 1 pays the seller_proceeds scriptPubKey |
| `[S5]` | KAS cash: output 1 holds exactly amount_b |
| `[S6]` | When the terms name an authority, the authority's signature verifies |
| `[S7]` | External cash settles only when the terms name an authority |
| `[S10]` | Where the other leg has a vault (KAS or KCC-20 cash), the input at that leg's canonical index (1 for the asset vault, 0 for the cash vault) is that vault: its scriptPubKey is the P2SH of this vault's own redeem script with legIndex replaced by the other leg's |
| `[F1]` | every input other than this vault carries no covenant, the asset leg's covenant, or (KCC-20 cash) the cash leg's covenant |
| `[F2]` | the other leg's covenant, when it has one, is carried by exactly one input |
| `[S8]` | A KCC-20 leg's authorizer KAS goes to its depositor's key: output 2 for the asset (output 1 under external cash), output 3 for KCC-20 cash |
| `[S9]` | That return holds at least the authorizer's value |

### refund

| Tag | Refuses unless |
| --- | --- |
| `[F5]` | the transaction has at most 12 inputs |
| `[R1]` | The named signer is the leg's depositor, its counterparty, or the authority when the terms name one |
| `[R2]` | The signature verifies for the named signer |
| `[R3]` | Earmarked funding: a refund signed by the depositor has a lock time of at least expiry_daa (an unsatisfied lock time) |
| `[R4]` | The vault UTXO being refunded is input 0 |
| `[R5]` | Output 0 holds exactly input 0's value |
| `[F3]` | every input from input 1 on carries no covenant or the leg's covenant |
| `[R6]` | KAS cash leg: output 0 pays the buyer_refund scriptPubKey |
| `[R7]` | KCC-20 leg (or the cash script of external-cash terms): output 0 pays the depositor's key |
| `[R8]` | At most one input of the leg's covenant |
| `[R9]` | That input is input 1 |
| `[R10]` | Output 1 carries the leg's covenant ID |
| `[R11]` | A refund not signed by the depositor carries exactly one input of the leg's covenant |
| `[R12]` | The token at input 1 is owned by this vault's script hash |
| `[R13]` | Output 1 carries at least the token input's KAS |
| `[R14]` | A refund not signed by the depositor returns a token holding exactly the leg amount |

Two builtins refuse without a tag: `readInputStateWithTemplate` (the escrowed token runs the KCC-20 template the terms name, at the template hash, prefix length and suffix length they give, and holds the state it claims) and `validateOutputStateWithInputTemplate` (a delivery or home output is that template with exactly the expected owner, amount and minter flag). The terms may name any KCC-20 template; the contract does not limit what that template allows.

## On-chain refusals, template v3

Template v3 (`contracts/impulse_vault_v3.sil`, template hash in `contracts/TEMPLATE_HASH_V3`, design in `V3-ZK.md`) refuses a spend by failing the script, like template v1. Its tags are scoped to v3: v3's `[S1]` is not v1's `[S1]`, though its text is the same. The engine tests are `tests/engine/v3_*.rs` and `tests/engine/v3p_*.rs`; `tests/engine/mutation-run-v3.txt` records that removing any one require, the verify call, or any one field of the journal is caught by a named test, on the probe (template v3 with the one verify call replaced), not on the shipped bytecode, because a real proof binds one vault address and a mutated contract is another address. The shipped bytecode is covered by the failing test per tag in `tests/engine/V3-SHIPPED-COVERAGE.md`.

### Template v3: settle

`settle(sig authSig, byte[] proof)`. Every v1 require runs first in v1's order, then the asset vault's proof gate (`[Z1]` and the builtin below), then `[S6]`. A refusal before the gate uses fewer script units than the precompile's fixed cost; the engine tests rely on that to show which side of the gate refused.

| Tag | Refuses unless |
| --- | --- |
| `[F4]` | the transaction has at most 12 inputs |
| `[S1]` | The vault input sits at its leg's canonical index: the asset authorizer at input 0, the cash authorizer at input 1 |
| `[E1]` | The leg's escrowed token is the only input of the leg's covenant in the transaction |
| `[E2]` | That input sits at the escrow position: input 2 for the asset (input 1 under external cash), input 3 for KCC-20 cash |
| `[E3]` | The escrowed token's owner type is SCRIPT_HASH |
| `[E4]` | The escrowed token's owner is this vault's script hash |
| `[E5]` | The escrowed token holds exactly the leg amount |
| `[E6]` | The escrowed token is not a minter |
| `[S2]` | A KAS cash vault UTXO holds exactly amount_b |
| `[S3]` | When earliest_daa is set, the lock time is at least earliest_daa (an unsatisfied lock time) |
| `[D1]` | A KCC-20 delivery output carries the leg's covenant ID |
| `[D2]` | A KCC-20 delivery output carries at least the escrowed token's own KAS |
| `[S4]` | KAS cash: output 1 pays the seller_proceeds scriptPubKey |
| `[S5]` | KAS cash: output 1 holds exactly amount_b |
| `[S6]` | When the terms name an authority, the authority's signature verifies |
| `[S7]` | External cash settles only when the terms name an authority |
| `[S10]` | Where the other leg has a vault (KAS or KCC-20 cash), the input at that leg's canonical index (1 for the asset vault, 0 for the cash vault) is that vault: its scriptPubKey is the P2SH of this vault's own redeem script with legIndex replaced by the other leg's |
| `[F1]` | every input other than this vault carries no covenant, the asset leg's covenant, or (KCC-20 cash) the cash leg's covenant |
| `[F2]` | the other leg's covenant, when it has one, is carried by exactly one input |
| `[S8]` | A KCC-20 leg's authorizer KAS goes to its depositor's key: output 2 for the asset (output 1 under external cash), output 3 for KCC-20 cash |
| `[S9]` | That return holds at least the authorizer's value |
| `[Z1]` | Asset vault: the buyer delivery owner is of type PUBKEY or SCRIPT_HASH (a COVENANT_ID owner has no scriptPubKey to be a leaf) |
| `[Z2]` | Cash vault: the `proof` witness item is empty |
| builtin | `r0.g16.verify`: asset vault only; `proof` is a RISC Zero Groth16 receipt of the list guest (image ID `circuits/IMAGE_ID`, a constant of the template) whose journal is the tag `Impulse/zk/wl/v1`, the list root of the vault state, this vault's own scriptPubKey and the buyer delivery owner's scriptPubKey, verified by the Kaspa ZK precompile (KIP-16, tag `0x20`). A failed verification fails the script; there is no false result |

### Template v3: refund

Unchanged from template v1: `[F5]`, `[R1]` to `[R14]` and `[F3]` as in `### refund` above, and the engine tests of the v1 refund suite pass unchanged against template v3 (`tests/engine/v3_refund.rs`).

The builtins `readInputStateWithTemplate` and `validateOutputStateWithInputTemplate` are as in template v1.

## On-chain refusals, template v4

Template v4 (`contracts/impulse_vault_v4.sil`, template hash in `contracts/TEMPLATE_HASH_V4`, design in `V3-ZK.md` section 22) refuses a spend by failing the script. Its tags are scoped to v4: `[T1]` to `[T11]` are script requires (`[T10]` and `[T11]` check the covenant ID of every input, `V3-ZK.md` 22.15); the checks of v1 that read the terms run in the terms guest (`circuits/terms-guest`, image ID `circuits/IMAGE_ID_V4`) under their v1 tags, and a false statement means no receipt exists. `tests/engine/mutation-run-v4.txt` records that removing any one script require is caught.

### Template v4: settle

`settle(sig authSig, byte[] proof, int nIn, int nOut, byte[32] covA, byte[32] covC)`.

| Tag | Refuses unless |
| --- | --- |
| `[T1]` | The vault input is at input 0 or 1 |
| `[T2]` | The view has 2 to 4 inputs and lies inside the transaction |
| `[T3]` | The view has 2 to 4 outputs and lies inside the transaction |
| `[T4]` | The authority's signature verifies |
| `[T8]` | The lock time is at most the transaction's DAA score (the lock time is final) |
| `[T10]` | The transaction has at most eight inputs, the asset escrow slot (input 1 for external cash, else input 2) carries `covA`, input 3 carries `covC`, and every other input carries no covenant ID (`V3-ZK.md` 22.15) |
| builtin | `r0.g16.verify`: `proof` is a receipt of the terms guest whose journal is the one the script builds from the spending transaction |

### Template v4: refund

`refund(sig s, pubkey signer, byte leg, byte[] proof, int nIn, int nOut, byte[32] cov)`.

| Tag | Refuses unless |
| --- | --- |
| `[T5]` | The signature verifies for the named signer |
| `[T6]` | The leg byte is 0 or 1 |
| `[T7]` | The refund view has 1 or 2 inputs and 1 or 2 outputs and lies inside the transaction |
| `[T9]` | The lock time is at most the transaction's DAA score (the lock time is final) |
| `[T11]` | The transaction has at most eight inputs, input 1 of a two-input view carries `cov`, and every other input carries no covenant ID (`V3-ZK.md` 22.15) |
| builtin | `r0.g16.verify`, as in settle, for the refund journal |

### Template v4: where each v1 tag lives

`scripts/check-tag-parity-v4.sh` fails if a tag of `### settle` or `### refund` above has no row here.

| v1 tag | Home in v4 |
| --- | --- |
| `[S1]` | guest, tag `[S1]` of `circuits/terms-core/src/statement.rs` |
| `[E1]` | guest, tag `[E1]` of `circuits/terms-core/src/statement.rs` |
| `[E2]` | guest, tag `[E2]` of `circuits/terms-core/src/statement.rs` |
| `[E3]` | guest, tag `[E3]` of `circuits/terms-core/src/statement.rs` |
| `[E4]` | guest, tag `[E4]` of `circuits/terms-core/src/statement.rs` |
| `[E5]` | guest, tag `[E5]` of `circuits/terms-core/src/statement.rs` |
| `[E6]` | guest, tag `[E6]` of `circuits/terms-core/src/statement.rs` |
| `[S2]` | guest, tag `[S2]` of `circuits/terms-core/src/statement.rs` |
| `[S3]` | guest, tag `[S3]` of `circuits/terms-core/src/statement.rs` |
| `[D1]` | guest, tag `[D1]` of `circuits/terms-core/src/statement.rs` |
| `[D2]` | guest, tag `[D2]` of `circuits/terms-core/src/statement.rs` |
| `[S4]` | guest, tag `[S4]` of `circuits/terms-core/src/statement.rs` |
| `[S5]` | guest, tag `[S5]` of `circuits/terms-core/src/statement.rs` |
| `[S6]` | script `[T4]` |
| `[S7]` | structure (`ZK_H_AUTHORITY_REQUIRED`: terms v4 always name an authority, so the case cannot arise) |
| `[S8]` | guest, tag `[S8]` of `circuits/terms-core/src/statement.rs` |
| `[S9]` | guest, tag `[S9]` of `circuits/terms-core/src/statement.rs` |
| `[S10]` | guest, tag `[H5]` of `circuits/terms-core/src/statement.rs` |
| `[R1]` | guest, tag `[R1]` of `circuits/terms-core/src/statement.rs` |
| `[R2]` | script `[T5]` |
| `[R3]` | guest, tag `[R3]` of `circuits/terms-core/src/statement.rs` |
| `[R4]` | guest, tag `[R4]` of `circuits/terms-core/src/statement.rs` |
| `[R5]` | guest, tag `[R5]` of `circuits/terms-core/src/statement.rs` |
| `[R6]` | guest, tag `[R6]` of `circuits/terms-core/src/statement.rs` |
| `[R7]` | guest, tag `[R7]` of `circuits/terms-core/src/statement.rs` |
| `[R8]` | guest, tag `[R8]` of `circuits/terms-core/src/statement.rs` |
| `[R9]` | guest, tag `[R9]` of `circuits/terms-core/src/statement.rs` |
| `[R10]` | guest, tag `[R10]` of `circuits/terms-core/src/statement.rs` |
| `[R11]` | guest, tag `[R11]` of `circuits/terms-core/src/statement.rs` |
| `[R12]` | guest, tag `[R12]` of `circuits/terms-core/src/statement.rs` |
| `[R13]` | guest, tag `[R13]` of `circuits/terms-core/src/statement.rs` |
| `[R14]` | guest, tag `[R14]` of `circuits/terms-core/src/statement.rs` |
| `[F1]` | script, `[T10]` |
| `[F4]` | script, `[T10]` (at most eight inputs) |
| `[F3]` | script, `[T11]` |
| `[F5]` | script, `[T11]` (at most eight inputs) |
| `[F2]` | none: a second input of the other leg's covenant is counted by the guest (`count_a`, `count_c`); a token of a leg's own covenant at the other leg's vault cannot stand in for the escrow, since a settle must spend the other vault at its slot (guest `[H5]`, `V3-ZK.md` 22.16) |
## On-chain refusals, template v2

Template v2 (`contracts/impulse_vault_v2.sil`, template hash in `contracts/TEMPLATE_HASH_V2`; design in `spec/V2.md` 4.4 and 4.5) refuses a spend by failing the script, as v1 does: for `[S3]` and `[R3]` an unsatisfied lock time, otherwise a failed script, never a code. Its tags are scoped to template v2: `[S1]` here is not v1's `[S1]`. The engine tests `tests/engine/v2_settle.rs` and `tests/engine/v2_refund.rs` are named after the tags, and `tests/engine/mutation-run-v2.txt` records that removing any one is caught by its named test. N is legCount, i is legIndex, K the number of KCC-20 legs.

### Template v2: settle

| Tag | Refuses unless |
| --- | --- |
| `[F4]` | the transaction has at most N + 18 inputs |
| `[S1]` | The vault input sits at input legIndex |
| `[V1]` | legCount is at most MAX_LEGS |
| `[V2]` | The leg list is exactly legCount records long |
| `[V5]` | legIndex is from 0 to legCount - 1 |
| `[P1]` | lots is at least 1 |
| `[E1]` | A KCC-20 leg's escrowed token is the only input of the leg's covenant |
| `[E2]` | That input sits at input N + i |
| `[E3]` | The escrowed token's owner type is SCRIPT_HASH |
| `[E4]` | The escrowed token's owner is this vault's script hash |
| `[E6]` | The escrowed token is not a minter |
| `[P2]` | The escrow (the token's amount, or a KAS leg's vault value) holds at most the leg amount |
| `[P3]` | The escrow holds a whole number of lots (unit = amount / lotCount) |
| `[P4]` | lots times the unit is at most what the escrow holds |
| `[P5]` | lots is at least minLot |
| `[P6]` | The remainder is zero or at least minLot lots |
| `[S3]` | When earliest_daa is set, the lock time is at least earliest_daa (an unsatisfied lock time) |
| `[V6]` | Every leg record's kind byte is KAS (0) or KCC-20 (1) |
| `[V7]` | Every KAS leg's delivery type is P2PK (0) or P2SH (1) |
| `[S10]` | Every other vault input j (0 to N - 1) is this trade's vault of leg j: its scriptPubKey is the P2SH of this vault's redeem script with legIndex j |
| `[S4]` | A KAS leg j's delivery output j pays its delivery scriptPubKey |
| `[S5]` | That output holds exactly lots times the leg's unit |
| `[D1]` | A KCC-20 leg j's delivery output j carries the leg's covenant ID |
| `[D2]` | That output carries at least the KAS of input N + j |
| `[F1]` | every input from input N on is the escrow of a KCC-20 leg (input N + i of leg i, checked by that leg's vault through `[E1]` and `[E2]`) or carries no covenant |
| `[C1]` | A final settle leaves no output of this vault's covenant |
| `[S8]` | Final, KCC-20 leg: output N + i pays the leg depositor's key |
| `[S9]` | That output holds at least this vault input's value |
| `[C2]` | A tranche spends a vault that carries a covenant ID |
| `[C3]` | A tranche leaves exactly one output of this vault's covenant |
| `[C4]` | That continuation is output N + i |
| `[C5]` | Output N + i has this vault's scriptPubKey |
| `[C6]` | Tranche, KAS leg: output N + i holds exactly the remainder |
| `[C7]` | Tranche, KCC-20 leg: output N + i holds at least this vault input's value |
| `[C8]` | Tranche, KCC-20 leg: output 2N + i carries the leg's covenant ID |
| `[C9]` | That output carries at least the KAS of input N + i |
| `[S6]` | When the terms name an authority, the authority's signature verifies |

### Template v2: refund

| Tag | Refuses unless |
| --- | --- |
| `[F5]` | the transaction has at most 12 inputs |
| `[V3]` | legCount is at most MAX_LEGS |
| `[V4]` | The leg list is exactly legCount records long |
| `[V8]` | legIndex is from 0 to legCount - 1 |
| `[V9]` | This leg's kind byte is KAS (0) or KCC-20 (1) |
| `[V10]` | A KAS leg's refund type is P2PK (0) or P2SH (1) |
| `[R1]` | signerLeg is from 0 to legCount (legCount names the authority) |
| `[R16]` | signerLeg names the authority only when the terms name one |
| `[R2]` | The signature verifies for the named key |
| `[R3]` | Earmarked funding: a refund signed by this leg's depositor's key has a lock time of at least expiry_daa (an unsatisfied lock time) |
| `[R4]` | The vault UTXO being refunded is input 0 |
| `[R5]` | Output 0 holds exactly input 0's value |
| `[R15]` | The refund leaves no output of this vault's covenant |
| `[F3]` | every input from input 1 on carries no covenant or the leg's covenant |
| `[R6]` | KAS leg: output 0 pays the leg's refund scriptPubKey |
| `[R7]` | KCC-20 leg: output 0 pays the leg depositor's key |
| `[R11]` | A refund not signed by the depositor's key carries exactly one input of the leg's covenant |
| `[R8]` | At most one input of the leg's covenant |
| `[R9]` | That input is input 1 |
| `[R12]` | The token at input 1 is owned by this vault's script hash |
| `[R14]` | A refund not signed by the depositor's key returns a token holding at least one lot |
| `[R17]` | And at most the leg amount |
| `[R18]` | And a whole number of lots |
| `[R10]` | Output 1 carries the leg's covenant ID |
| `[R13]` | Output 1 carries at least the token input's KAS |

The same two builtins as v1 refuse without a tag: `readInputStateWithTemplate` (an escrow runs the KCC-20 template the leg record names and holds the state it claims) and `validateOutputStateWithInputTemplate` (a delivery, remainder or home output is that template with exactly the expected owner, amount and minter flag).
