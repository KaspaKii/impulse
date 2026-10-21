# Impulse verifier and decoder

Fixed in increment I6. Companion to `IMPULSE-SPEC.md` ("Off-chain components", the verifier), `TEMPLATE.md` (one redeem script: instantiation, decoding, the `TEMPLATE_*` codes) and `ENCODING.md` (the terms and the `TERMS_*` codes). This file defines what the verifier checks before funding and after a spend, what it reports about a KCC-20 token, how a transaction is decoded, and the `VERIFY_*`, `DECODE_*` and `TOKEN_*` codes. Reference implementation: `crates/impulse-core/src/verify/` and `crates/impulse-core/src/decode/`.

Nothing here talks to a node. A caller that starts from a transaction ID fetches the transaction itself (`impulse decode <txid>`, I7) and passes it in.

Every check takes structure-checked terms (`ValidatedTerms`). Checks run in the order given and the first failure is returned, so every implementation reports the same code for the same input. A template or terms refusal met on the way keeps its own `TEMPLATE_*` or `TERMS_*` code.

## Before funding: the addresses

Input: the agreed terms, a creation context (the caller's network, the current DAA score, the expiry horizon; `ENCODING.md`, "Creation checks"), and the address offered for each leg, or none.

1. Both legs instantiate for creation (`TEMPLATE.md`, `Vault::instantiate_for_creation`), so the creation checks run first: `TERMS_NETWORK_MISMATCH`, `TERMS_EXPIRY_NOT_AFTER_CREATION`, `TERMS_EXPIRY_BEYOND_HORIZON`. Direct terms escrow nothing and are `TEMPLATE_NO_VAULT`. The cash leg of external cash has no vault and is not a refusal here.
2. Then the asset leg, then the cash leg:
   - a leg with no vault must be offered no address: `VERIFY_ADDRESS_UNEXPECTED`;
   - a leg with a vault must be offered one: `VERIFY_ADDRESS_MISSING`;
   - it parses as a Kaspa address (rusty-kaspa a41a333 `kaspa-addresses`): `VERIFY_ADDRESS_MALFORMED`. Before the parser runs, the text after the first colon must be lowercase bech32 symbols, 8 of them the checksum, with the canonical payload length for the version byte its first symbols encode: 53 symbols for PubKey (0) and ScriptHash (8), 32-byte payloads; 55 for PubKeyECDSA (1), 33 bytes. Anything else is `VERIFY_ADDRESS_MALFORMED` unparsed: once the checksum passes, the a41a333 parser panics on 0 or 1 payload symbols and on a payload length other than its version's, and anyone can compute a valid checksum;
   - its prefix is the terms' network's (`kaspa` mainnet, `kaspatest` testnet): `VERIFY_ADDRESS_NETWORK`;
   - it is version ScriptHash with this leg's vault script hash as payload. If instead it pays the other leg's vault: `VERIFY_LEGS_SWAPPED`. Anything else: `VERIFY_ADDRESS_MISMATCH`.

The result is each leg's address as Impulse renders it, with its script hash.

Why:

- A funder recomputes the address from the terms. An address that does not match means there is nothing to fund; the code says why.
- The creation checks run first so an expired or mis-networked trade is never verified as fundable. Its vaults still verify after a spend (below).
- External-cash terms have no cash vault. Anyone can compile the template with those terms and legIndex 1 and fund its address, and that script must never be funded (`TEMPLATE.md`, "The cash-vault script of external-cash terms"). An address offered for it is refused.
- Swapped legs are a labelling error, not a forgery, so they have their own code.

## After a spend: a revealed redeem script

Input: the agreed terms, the leg, and either the redeem script a spend revealed (`verify_revealed_script`) or the spent input itself with the scriptPublicKey of the UTXO it spends, as the node reports it (`verify_spent_input`).

For a spent input, first, in order: its revealed script is the last push of its signature script, which must be push only: `VERIFY_NOTHING_REVEALED`; and the UTXO it spends is the version 0 P2SH of that script: `VERIFY_INPUT_NOT_VAULT`. The binding is needed for the reasons the decoder binds its vault inputs (below, "Why the spent scriptPublicKeys"): the transaction ID does not commit to signature scripts, so a signature script can be swapped for another trade's under an unchanged ID, and consensus runs a signature script only when the spent scriptPublicKey has version 0, accepting the input unrun above that. The version 0 P2SH of the revealed script is the one UTXO whose spend runs that script.

The script is accepted exactly when it is the agreed leg's vault: `Vault::instantiate_existing(terms, leg)`, byte for byte. No creation checks run, so a trade past its expiry still verifies. Otherwise the reason, in order:

1. The terms give the leg a vault: `TEMPLATE_NO_VAULT`.
2. The script runs the published template: its template hash, recomputed from its own first prefix-length and last suffix-length bytes without trusting any declared hash, is the pinned `TEMPLATE_HASH`. A script shorter than the template, or of another template: `VERIFY_TEMPLATE_MISMATCH`.
3. It decodes (`TEMPLATE.md`, "Decoding"): `TEMPLATE_*` and `TERMS_*` codes.
4. Its terms are the agreed terms: `VERIFY_TERMS_MISMATCH`, naming the terms fields that differ, in field order (`version`, `network`, `settlement_mode`, `nonce`, `seller_key`, `buyer_key`, `authority_key`, `asset_leg`, `cash_leg`, `buyer_delivery`, `seller_proceeds`, `seller_refund`, `buyer_refund`, `earliest_daa`, `expiry_daa`, `funding_mode`, `trade_ref`).
5. Its leg is the expected leg: `VERIFY_LEGS_SWAPPED`.

The revealed-script check reads the script alone and is unbound: it says whether a script is the agreed vault, not that a transaction ran it. Only the spent-input check, with the scriptPublicKey the node reports for the spent UTXO, says that the input spent the agreed vault and so ran its script, and only for a transaction consensus accepted.

## Token warnings

For each KCC-20 leg, asset leg first, the verifier reads what the caller knows about the token and reports it as a list of warnings. The warnings are data. Impulse does not check the covenant ID (chain data, I7), and it cannot see issuer powers the evidence does not show. An empty list is never a statement that a token is safe or ordinary.

Evidence for one leg:

- `artifact_json`: the token template's compiled artifact, as `silverc` writes it (schema 1, one contract). It must come from the token publisher's reproducible build, never from the counterparty. The template hash covers the template's bytecode outside the state, not the artifact's state field names or entry names: silverscript-abi's consistency check does not tie entries to bytecode, and its own documentation says it cannot make an attacker-supplied artifact trustworthy. Those names are therefore authenticated only for a pinned template (below); for any other they are the artifact's own claim.
- `issuer_keys`: x-only keys the caller knows to hold issuer power over the token, for example the owner key of a PUBKEY-owned minter UTXO, or of a minter controller such as KCC20Minter. Finding them on chain is I7's. An empty list means the issuers are unknown, not that there are none.

**Pinned KCC-20 templates.** `PINNED_KCC20_TEMPLATES` (`crates/impulse-core/src/verify/pins.rs`) lists the template triple (hash, prefix length, suffix length) of kcc20.sil from silverscript v1.0.0 (commit `3ed9733`) compiled with the pinned silverc, for every `maxCovIns` and `maxCovOuts` from 1 to 4: 16 builds. The engine test `the_pinned_kcc20_templates_are_kcc20_sil_built_with_the_pinned_compiler` recompiles each and fails on any difference. A leg whose triple is pinned runs kcc20.sil's code, whatever its artifact declares.

Checks, in order, first failure returned:

1. A leg that is not KCC-20 takes no evidence: `VERIFY_TOKEN_LEG_KIND`.
2. A KCC-20 leg without evidence: warning `TOKEN_UNASSESSED`, and nothing more for that leg.
3. The artifact is at most 65536 bytes (`MAX_TOKEN_ARTIFACT_LEN`), parses, holds exactly one contract, names every state field and entry with 1 to 64 ASCII letters, digits and underscores (the names are reported in warnings and refusals), has no state field of a type that is or holds a struct, and passes silverscript-abi v1.0.0's consistency check (`check_consistency`: schema, state span, canonical state, declared template hash, distinct dispatch tags): `VERIFY_TOKEN_ARTIFACT_INVALID`. All but the last run before the consistency check, which flattens the struct types of the state fields with a cycle check only, so a few kilobytes declaring a DAG of structs would cost time and memory exponential in its depth. KCC-20's state has no struct-typed field, and without one the check is linear in the artifact. Struct types declared for other uses (entry arguments, as KCC20Minter declares) are not expanded by the check and are allowed. The 16 pinned kcc20.sil builds are at most 13675 bytes as silverc writes them (measured by `the_pinned_kcc20_templates_are_kcc20_sil_built_with_the_pinned_compiler`, which asserts the bound for each).
4. Its template hash, recomputed from its prefix and suffix, and its prefix and suffix lengths, are the leg's `template_hash`, `template_prefix_len` and `template_suffix_len`: `VERIFY_TOKEN_TEMPLATE_MISMATCH`. This is the check of the terms' template description against the token's template that `ENCODING.md` leaves to I6.
5. Its state begins with the four fields the vault reads, by name and type, in order: `ownerIdentifier` (byte[32]), `identifierType` (byte), `amount` (int), `isMinter` (bool); and it has both KCC-20 entries as silverc v1.0.0 names them, `__leader_transfer` and `__delegate`: `VERIFY_TOKEN_NOT_KCC20`.
6. Its state has no field after those four: `VERIFY_TOKEN_EXTENDED_STATE`, naming the fields. The vault reads and rebuilds the four-field KCC-20 state, so it can neither settle nor refund such a token: a depositor could only refund the authorizer and leave the token owned by the vault's script hash with no spend path. The engine test `a_kcc20_token_with_extended_state_cannot_settle_or_refund_and_is_refused` pins this: kcc20.sil with one more field transfers on its own, and the vault refuses it in settle and refund.
7. A pinned template's artifact declares no entry beyond the two: `VERIFY_TOKEN_ARTIFACT_INVALID`. Its bytecode is kcc20.sil's, so such an artifact is doctored.

Then the warnings, in this order:

| Code | When | What it reports |
| --- | --- | --- |
| `TOKEN_UNASSESSED` | No evidence for a KCC-20 leg | Nothing about the token's issuer powers was read |
| `TOKEN_MINTER_BRANCH` | Every token that passes the checks | The state declares the KCC-20 `isMinter` flag. Under kcc20.sil a UTXO with the flag set is exempt from amount conservation and can create supply and further minters. The vault refuses to settle a minter escrow (`[E6]`) |
| `TOKEN_TEMPLATE_UNPINNED` | The template triple is not pinned | The artifact's state field names and entry names are its own unauthenticated claim and support no statement about the token; an artifact can hide entries or state under the same triple |
| `TOKEN_EXTRA_ENTRIES` | An unpinned template's artifact declares entries other than the two KCC-20 entries | Their names, as declared |
| `TOKEN_ISSUER_UNKNOWN` | `issuer_keys` is empty | No party was checked as issuer |
| `TOKEN_PARTY_IS_ISSUER` | The seller, buyer or authority key is among `issuer_keys`, in that order | The party and its relation to the leg: depositor (the seller for the asset, the buyer for the cash), counterparty, or authority |

A token of another covenant at a vault (`TRANSACTIONS.md`, "A token of another covenant at a vault"). Send each leg only to its own vault address. A vault refuses any spend that moves a token of a covenant the layout does not name (`TEMPLATE.md`, "Inputs outside the layout"), and every settle requires the other leg's vault (`TEMPLATE.md`, "The other leg's vault"), so a token of any covenant sent to a vault's address, the other leg's own included, cannot move at all. Known limitation L20 is closed in every template. The warning `TOKEN_FOREIGN_AT_VAULT`, which the builders that read the node gave for a token of the other leg's covenant at a vault, is retired (`ERRORS.md`, "Retired and changed codes"): no builder looks for such a token any more.

The check before funding (`before_funding`) also says whether evidence was read for every KCC-20 leg (`FundingCheck::token_legs_assessed`). A caller must not present a leg as checked when it was not.

Why `TOKEN_PARTY_IS_ISSUER`: a refund signed by the counterparty or the authority must carry a vault-owned token of the full leg amount (`[R11]`, `[R14]`). Anyone can make such a decoy at the cost of the leg amount, which goes home to the depositor; for an issuer that cost can be nothing. The residual is accepted and pinned by the engine test `r14_decoy_of_the_full_leg_amount_pays_the_depositor` (I3); the warning surfaces it before funding.

## Decoding a transaction

Input: a transaction, the scriptPublicKey of the UTXO each input spends, in input order (from the node, I7), and the network the caller is on. A transaction may be given as a value or as raw bytes.

**Why the spent scriptPublicKeys.** The transaction ID does not commit to signature scripts: rusty-kaspa a41a333 hashes the transaction for its ID with `EXCLUDE_SIGNATURE_SCRIPT`. A vault spend reveals its terms in its signature script, so anyone can swap a vault input's signature script for another trade's, or add one, under an unchanged ID. And consensus runs an input's signature script only when the spent scriptPublicKey's version is 0: above that it accepts the input without running anything (`AcceptedUnknownVersion`). So a vault input is accepted only when the UTXO it spends is the version 0 P2SH of the script it reveals, the one case where consensus runs that script. `decode_unbound` skips this binding and reports `bound: false`; what it reports is only as trustworthy as the source of the transaction.

**Raw form.** The borsh encoding rusty-kaspa a41a333 derives for `kaspa_consensus_core::tx::Transaction` (`consensus/core/src/tx.rs`). It carries the transaction ID as its last 32 bytes. Bytes that do not decode, or leave bytes over: `DECODE_TX_MALFORMED`. One such transaction is committed as a fixture (`crates/impulse-core/src/decode/fixtures/settle-vector-01.hex`, the shaped settle of terms vector 1); its test fails if the form changes.

Then, for the whole transaction, in order, first failure returned:

1. The ID the transaction carries is the ID of its contents (`hashing::tx::id`): `DECODE_TX_ID_MISMATCH`. This catches a value or byte string edited outside its signature scripts after its ID was computed; it says nothing about signature scripts.
2. There is one spent scriptPublicKey per input: `DECODE_SPENT_COUNT`.

Then each input, in order:

- An input whose signature script is not push only (data pushes `0x00` to `0x4e`, small-integer pushes `OP_1NEGATE`, `OP_1` to `OP_16`), or that ends inside a push, is not a vault spend and is skipped: consensus refuses it at a version 0 P2SH input and never runs it at an input of a higher version.
- The input is a vault input when its last push is data whose template hash, recomputed as above, is the pinned template's. Any other input (a fee input, an escrowed KCC-20 token) is skipped.
- A vault input is refused on its own, in this order, without hiding the others: the UTXO it spends is not the version 0 P2SH of the script it reveals, `DECODE_INPUT_NOT_VAULT`; the script does not decode, `TEMPLATE_*` and `TERMS_*`; its terms name another network than the caller's, `TERMS_NETWORK_MISMATCH`; its dispatch tag, the push before the redeem script, is neither the template's `settle` nor its `refund` tag, `DECODE_ENTRY_UNKNOWN`. For a refund, the push before the tag is the `signer` argument; when it is a 32-byte key it is reported, with the role it holds under the terms (seller, buyer, authority) or none.

If no vault input decodes, the first refusal is returned, or `DECODE_NO_VAULT_INPUT` if there was no vault input. Otherwise the result is the transaction ID, whether it was bound, and, per decoded vault input: its index, the outpoint it spends, the leg, the vault's script hash, the terms, and the entry; and beside them the refused vault inputs with their codes. A third party can add a refused vault input (a version 2 vault, a vault of another network, the cash-vault script of external-cash terms) to a transaction that settles a trade; the trade's legs are still reported. `strict()` turns any refused input into a refusal of the whole transaction, for callers that need that.

Grouped by terms hash, in order of first appearance, the legs give the trades the transaction touches: one for a canonical settle, two when the asset vault of one trade and the cash vault of another settle together (spec "Red team", cross-trade mixing).

Each leg's outcome, if the transaction is valid:

- `settle`: exactly the leg amount delivered to `buyer_delivery` (asset) or `seller_proceeds` (cash), and a KCC-20 leg's authorizer KAS back to its depositor. The contract enforces both outputs.
- `refund`: what the vault UTXO holds goes home whole, an authorizer's KAS to the depositor's key. The destination named, `seller_refund` (asset) or `buyer_refund` (cash), is where the escrowed token or KAS cash goes if the transaction carries it. Decoding does not read the outputs, and a depositor may refund an authorizer without its token, so the destination may receive nothing from this transaction and no amount is stated.

Decoding reads what a transaction reveals. It does not check that the transaction is valid or accepted, and it does not check a spend against agreed terms; the revealed-script check above does. The entry and signer reported are what the input calls; consensus binds them only when the transaction is accepted. `impulse decode <txid>` (I7) decodes transactions a node has accepted, bound to the scriptPublicKeys the node reports for their inputs.

## Error codes

Stable codes for every verifier and decoder refusal, and for every token warning. Integrators match on the code, never on the message text. Message text may quote what a counterparty supplied (an address, artifact names, a parser's error about either). The verifier escapes every character outside printable ASCII in such text as `\u{..}` before it reaches a message, so no message carries a terminal control sequence or an invisible or bidirectional character; it does not escape for HTML or any other medium, and an integrator that displays message text (the CLI, I7; the decoder page, I11) escapes it for its medium. The lists are frozen by the tests `verify::tests::verify_error_codes_are_frozen`, `decode::tests::decode_error_codes_are_frozen` and `verify::tests::token_warning_codes_are_frozen`, and may only grow. `spec/ERRORS.md` (I10) will absorb these tables.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `VERIFY_ADDRESS_MALFORMED` | addresses | The offered address does not parse as a Kaspa address |
| `VERIFY_ADDRESS_NETWORK` | addresses | The offered address carries another network's prefix than the terms name |
| `VERIFY_ADDRESS_MISMATCH` | addresses | The offered address pays neither this leg's vault nor the other leg's |
| `VERIFY_ADDRESS_MISSING` | addresses | A leg with a vault was offered no address |
| `VERIFY_ADDRESS_UNEXPECTED` | addresses | An address was offered for a leg the terms give no vault |
| `VERIFY_LEGS_SWAPPED` | addresses, revealed script | What was offered as one leg is the other leg's vault of these terms |
| `VERIFY_TEMPLATE_MISMATCH` | revealed script | The script does not run the published template |
| `VERIFY_TERMS_MISMATCH` | revealed script | The script is a vault of other terms |
| `VERIFY_TOKEN_LEG_KIND` | token warnings | Token evidence for a leg that is not KCC-20 |
| `VERIFY_TOKEN_ARTIFACT_INVALID` | token warnings | The token artifact is too long, does not parse, does not hold one contract, declares a name that is not an identifier or a struct-typed state field, fails the consistency check, or, for a pinned template, declares an entry beyond the two KCC-20 entries |
| `VERIFY_TOKEN_TEMPLATE_MISMATCH` | token warnings | The token's template is not the one the terms name for the leg |
| `VERIFY_TOKEN_NOT_KCC20` | token warnings | The token's state or entries are not the KCC-20 ones the vault relies on |
| `VERIFY_NOTHING_REVEALED` | spent input | The input's signature script is not push only or reveals no script |
| `VERIFY_TOKEN_EXTENDED_STATE` | token warnings | The token's state has fields beyond KCC-20's four; the vault cannot settle or refund it |
| `VERIFY_INPUT_NOT_VAULT` | spent input | The input does not spend the version 0 P2SH of the script it reveals, so consensus never ran that script there |
| `DECODE_TX_MALFORMED` | decode | The raw bytes are not one borsh-encoded transaction |
| `DECODE_TX_ID_MISMATCH` | decode | The transaction ID carried is not the ID of the contents |
| `DECODE_ENTRY_UNKNOWN` | decode, per input | A vault input calls no entry of the template |
| `DECODE_NO_VAULT_INPUT` | decode | No input spends an Impulse vault |
| `DECODE_SPENT_COUNT` | decode | The spent scriptPublicKeys supplied are not one per input |
| `DECODE_INPUT_NOT_VAULT` | decode, per input | An input reveals a vault script but does not spend its version 0 P2SH |

Token warnings (data, not refusals):

| Code | Meaning |
| --- | --- |
| `TOKEN_UNASSESSED` | No evidence was supplied for a KCC-20 leg |
| `TOKEN_MINTER_BRANCH` | The token's state declares the KCC-20 minter flag |
| `TOKEN_EXTRA_ENTRIES` | An unpinned token's artifact declares entries beyond KCC-20's transfer leader and delegate |
| `TOKEN_PARTY_IS_ISSUER` | A party key is among the issuer keys supplied |
| `TOKEN_TEMPLATE_UNPINNED` | The token's template is not a pinned kcc20.sil build; its declared state and entries are unauthenticated |
| `TOKEN_ISSUER_UNKNOWN` | No issuer keys were supplied |
| `TOKEN_FOREIGN_AT_VAULT` | Retired in I26, never raised: a token of the other leg's own covenant owned by a vault's script hash cannot move, since every template requires the other leg's vault in a settle. Reserved: the name is never reused |
