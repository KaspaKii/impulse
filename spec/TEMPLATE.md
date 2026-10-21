# Impulse vault template and instantiation

ImpulseVault v1, template hash `ec92ce9d06ff2f57a4f547b724b6fdfe9d9fa62814e687d8670ae96d331e6f02`. Companion to `IMPULSE-SPEC.md` ("On-chain contract: ImpulseVault", "Terms") and `ENCODING.md` (the terms, their validation and the `TERMS_*` codes). This file defines how a leg's redeem script, script hash and address are made from the terms, how a redeem script is decoded back, and the `TEMPLATE_*` refusal codes. Reference implementation: `crates/impulse-core/src/template/` and `crates/impulse-core/src/address.rs`. Golden vectors: `tests/vectors/vaults/`, frozen.

## Template

- Source: `contracts/impulse_vault.sil`. Artifact: `contracts/compiled/impulse_vault.v1.json`, the output of `silverc` built from silverscript v1.0.0 (commit 3ed9733) for the placeholder constructor values in `contracts/compiled/impulse_vault.v1.ctor.json`. Pin: `contracts/TEMPLATE_HASH`.
- The terms are the contract state, so the bytecode is a template prefix (1 byte), the state, and a template suffix (3,437 bytes). The prefix and suffix are the same for every trade.
- The template hash is silverscript's: BLAKE3 over the prefix length, the prefix, the suffix length and the suffix, each length an 8-byte script number.
- `scripts/build-template.sh`, a step of `scripts/ci-local.sh`, rebuilds the artifact with the pinned `silverc` and fails unless it is byte-identical to the committed file and its hash equals `TEMPLATE_HASH`.

The other vault templates have their own source, artifact and pin, built and checked the same way (`scripts/build-template-v2.sh`, `scripts/build-template-v3.sh`, `scripts/build-template-hashlock.sh`, `scripts/build-template-v4.sh`):

| Template | Pin | Hash |
| --- | --- | --- |
| v1 | `contracts/TEMPLATE_HASH` | `ec92ce9d06ff2f57a4f547b724b6fdfe9d9fa62814e687d8670ae96d331e6f02` |
| v2 | `contracts/TEMPLATE_HASH_V2` | `75d754c16299e7707787f0e66d9880d7657d09b1bea4ef3bd508cefdb6dd7548` |
| v3 | `contracts/TEMPLATE_HASH_V3` | `f00009e88c562fc529d1c30e406c783eb7532e39f6426be518616eb9a7283d4c` |
| hashlock | `contracts/TEMPLATE_HASH_HASHLOCK` | `1e708d70c86ace8015778ccb693573b109dcd7135cf921366525a6f4aeef43d6` |

## Inputs outside the layout

kcc20.sil lets a token owned by a script hash move in any transaction that also spends an input at that script hash's address. A vault that constrained only the token of the covenant it escrows would let a KCC-20 token of any other covenant owned by its script hash move with any spend of it, wherever the spender sends it (L20). The vault refuses every settle and refund in which an input other than the vault itself carries a covenant the layout does not name, and bounds the inputs of the spend so the check covers all of them. "Carries no covenant" is `OpInputCovenantId(i)` equal to 32 zero bytes: in rusty-kaspa a41a333 the opcode returns `ZERO_HASH` for a UTXO without a covenant ID (`crypto/txscript/src/opcodes/mod.rs`, `OpInputCovenantId`). A fee input carries none (spec/TRANSACTIONS.md, "Fee inputs and change"), nor does a vault UTXO the builders fund.

| Tag | Entry | Require | Purpose |
| --- | --- | --- | --- |
| `[F4]` | settle | `tx.inputs.length <= MAX_INPUTS` (12) | The bound of the check below, checked by the contract and not left to the compiler's loop assertion |
| `[F1]` | settle | every input but this vault: `OpInputCovenantId(i)` is zero, `assetCovenantId`, or (KCC-20 cash only) `cashCovenantId` | No token of another covenant rides along |
| `[F2]` | settle | the other leg's covenant, if that leg is KCC-20, has exactly one input: in the asset vault `OpCovInputCount(cashCovenantId) == 1` (KCC-20 cash only), in the cash vault `OpCovInputCount(assetCovenantId) == 1` | No second token of a leg's covenant rides along, even where that leg's own vault is not spent: `[E1]` counts only this leg's covenant |
| `[F5]` | refund | `tx.inputs.length <= MAX_INPUTS` (12) | The bound of the check below |
| `[F3]` | refund | every input from input 1 on: `OpInputCovenantId(i)` is zero or this leg's covenant (the asset covenant for the asset vault, the cash covenant for a KCC-20 cash vault, none for a KAS or external-cash cash vault) | No token of another covenant rides along; `[R8]` and `[R9]` place the leg's own token at input 1 |

Together with `[E1]`, `[E2]`, `[R8]` and `[R9]`, the covenant-carrying inputs of a spend are exactly the layout's escrows. Per layout (the vault inputs carry no covenant):

| Spend | Covenant allowed at each input | Count |
| --- | --- | --- |
| Settle, KCC-20 cash | 0 and 1: none (the vaults); 2: asset (`[E2]`); 3: cash (`[E2]` of the cash vault); 4 on: none | one asset input (`[E1]`, `[F2]` of the cash vault), one cash input (`[E1]` of the cash vault, `[F2]` of the asset vault) |
| Settle, KAS cash | 0 and 1: none; 2: asset; 3 on: none | one asset input (`[E1]`, `[F2]` of the cash vault) |
| Settle, external cash | 0: none; 1: asset; 2 on: none | one asset input (`[E1]`) |
| Refund, KCC-20 leg | 0: the vault; 1: the leg's covenant or none (the depositor may leave the token out); 2 on: none | at most one input of the leg's covenant (`[R8]`) |
| Refund, KAS cash or external-cash cash vault | 0: the vault; 1 on: none | |

The vault input itself is not checked by its own vault, so a UTXO at the vault's address that carries a covenant can still be refunded; in a settle the other vault's input is checked like any other (a covenant there refuses the settle, never the refund).

Consequences:

- A spend of a vault has at most 12 inputs: 8 fee inputs at most beside a KCC-20 cash settle, 10 beside a refund with its token. The builders refuse more (`TX_TOO_MANY_INPUTS`).
- A token of another covenant sent to a vault's address cannot move at all: kcc20.sil lets it move only beside an input at that address, and every spend of the vault refuses it. Send each leg only to its own vault address still holds: the mistake does not give the token to whoever spends the vault, but nobody can recover it.
- A token of a leg's own covenant at the other leg's vault (for example the asset token sent to the cash vault's address) cannot move either: every settle spends the other vault beside this one (`[S10]`, next section), and that vault's `[E1]` and `[E4]` admit only its own escrow; a refund refuses it with `[F3]`. Before `[S10]` such a token could stand in for that leg's escrow in a settle that omitted the other vault (the last case of known limitation L20); `[S10]` closes it in templates v1 and v3, as it was never open in template v2.
- Cost, measured in the pinned engine (`docs/evidence/template-fix-2026-10-19/v0.4-template-units.txt`): the input check grew the suffix from 2,429 to 3,345 bytes; each input after the vault costs a settle about 235 script units and a refund about 168. `[S10]` adds its own cost (next section).

Engine tests: `tests/engine/foreign_covenant.rs` (each require, fee inputs without covenants up to the bound, the bound), run again against the template v3 probe by `tests/engine/v3p_foreign_covenant.rs`.

## The other leg's vault

A vault checks its own escrow and both legs' deliveries. Without more, it does not check that the other leg's vault is spent, so a token of a leg's own covenant owned by the other vault's script hash (misdirected funding) could stand in for that leg's escrow in a settle that omits the other vault, and the vaults of two trades with identical deliveries could settle together (known limitations L20 and L8). Each settle therefore requires the other leg's vault at its canonical input, as template v2 does with its own `[S10]`.

| Tag | Entry | Require | Purpose |
| --- | --- | --- | --- |
| `[S10]` | settle | where the other leg has a vault (KAS or KCC-20 cash, not external cash): `tx.inputs[1 - legIndex].scriptPubKey` is the P2SH of this vault's own redeem script with `legIndex` replaced by `1 - legIndex` | The input at the other leg's canonical slot (input 1 for the asset vault, input 0 for the cash vault) runs this template with this trade's terms |

How the other vault's script is built. A vault's redeem script is the template prefix (1 byte), the state and the template suffix, and `legIndex` is the last state field, an 8-byte script number. The vault reads its own redeem script from the last push of its own signature script (`OpTxInputScriptSigLen`, `OpTxInputScriptSigSubstr`), which consensus has already hashed against the vault's P2SH scriptPubKey, so the bytes are authenticated. The state is `STATE_FIXED` bytes of pushes plus the payloads of the two KAS scriptPubKey fields (`sellerProceedsSpk`, `buyerRefundSpk`), each a single push of at most 75 bytes, so the state's length is `STATE_FIXED` plus the two field lengths; the suffix is `SUFFIX_LEN` bytes. The other vault's redeem script is this vault's with the 8 bytes of `legIndex` replaced by `OpNum2Bin(1 - legIndex, 8)`, and its scriptPubKey is `ScriptPubKeyP2SHFromRedeemScript` of that. `PREFIX_LEN`, `STATE_FIXED` and `SUFFIX_LEN` are constants of the source; `SUFFIX_LEN` is the template's own suffix length, a fixed point found by compiling (v1: 1, 508 and 3,437; v3: 1, 574 and 4,356). `scripts/build-template.sh` and `scripts/build-template-v3.sh` fail when a constant differs from the compiled layout.

Red team (each line names the case and what the contract does under `[S10]`; engine tests in `tests/engine/foreign_covenant_residual.rs`, run against the template v3 probe by `tests/engine/v3p_sibling.rs`, and on the shipped template v3 with the committed receipts in `tests/engine/v3_settle.rs`):

- Misdirected token. A cash token owned by the asset vault, or an asset token owned by the cash vault, cannot be an escrow: the vault it would stand in for is required at its slot and admits only a token it owns (`[E1]`, `[E4]`), and every other vault's `[F2]` or `[E1]` counts one input of each covenant. It cannot go home in a refund either (`[F3]`). Such a token cannot move at all; nobody can recover it. Tests `s10_a_cash_token_at_the_asset_vault_cannot_pay_the_seller_without_the_cash_vault` and `s10_an_asset_token_at_the_cash_vault_cannot_deliver_to_the_buyer_without_the_asset_vault`, each with the KCC-20 transfer itself shown valid.
- Missing vault. A settle whose other slot is a plain input is refused, also under KAS cash, where the seller's proceeds could otherwise be paid from any input (`s10_asset_vault_refuses_a_kas_cash_settle_without_the_cash_vault`).
- Duplicate vault. A second UTXO of this vault's own address at the other slot is refused (`s10_this_vault_again_at_the_other_slot_is_refused`). A second UTXO of the other vault can be spent only at its own slot (`[S1]`) or, through `refund`, at input 0 (`[R4]`), so only one vault UTXO per leg is in a settle; the swapped order is refused by both (`s10_vaults_at_each_others_slots_are_refused`).
- Another trade. The vaults of a repeat trade between the same parties differ in nonce and trade_ref, so their scripts differ and are refused (`s10_cross_trade_mixing_is_refused`): L8 is closed for templates v1 and v3 (template v2 by its own `[S10]`, template v4 by the guest's `[H5]`, `V3-ZK.md` 22.16).
- Another template. The other vault is rebuilt from this vault's own template, so a template v1 vault and a template v3 vault of the same terms do not settle together; in particular a v3 cash vault refuses a v1 asset vault, so the v3 cash vault settles only beside the gated v3 asset vault of its terms (`V3-ZK.md` 6.5; `v3_settle::v3_s10_v3_cash_vault_refuses_a_v1_asset_vault`).
- The other vault spent through `refund` in the same transaction. A refund runs only at input 0 (`[R4]`), so the cash vault cannot; the asset vault's refund pays output 0 to the seller's key (`[R7]`), while the cash vault's settle requires output 0 to be the asset delivery under the asset covenant and template (`[D1]`): no transaction satisfies both.
- External cash. There is no cash vault, so the asset vault does not apply `[S10]` (`s10_external_cash_asset_vault_settles_with_no_cash_vault`). The cash-vault script of external-cash terms still never settles (`[E1]`, "The cash-vault script of external-cash terms" below).
- Refunds. Unchanged. A refund spends one vault at input 0 and no other vault can be an input beside it (above), so a token owned by the other vault cannot move with it; the residual never existed there (`[F3]`, `[R8]`, `[R9]`, `[R12]`).
- Tranches and linked trades. Templates v1 and v3 have neither; both are template v2, whose `[S10]` already binds every vault of the trade.
- Encodings the rebuild does not cover. A KAS scriptPubKey state field longer than 75 bytes would take a two-byte push header and the rebuilt script would be wrong. The terms admit only P2PK, P2PK-ECDSA and P2SH scriptPubKeys (at most 37 bytes with the version, `ENCODING.md`), so no vault Impulse instantiates or decodes has one; a script compiled by hand with one fails `[S10]` on settle (fail closed) and stays refundable.

Cost, measured in the pinned engine (`docs/evidence/template-fix-I26/s10-units.txt`): the suffix grows from 3,345 to 3,437 bytes (v1) and from 4,264 to 4,356 bytes (v3). Rebuilding and hashing the other vault's script costs each v1 settle vault input 20,610 to 21,126 more script units with one fee input (an external-cash settle, which skips it, 186 more; a refund, which does not run it, 184 more, for the longer script); at the bound of 12 inputs the most is 177,722 units, a KCC-20 cash settle's cash vault, against the builders' rule of 198,057. The fixed part of a settle beside its signature check and template bytes is at most 33,285 units, measured with padded KCC-20 templates (`builders::per_byte_script_units_are_measured`); the builders' allowance for it is 45,000 fixed units per vault input (`TRANSACTIONS.md`, "Compute budgets"), so every budget of the committed vectors stays at its floor. The largest v1 settle at exact budgets has a compute mass of 17,623 grams, below the 100,000-gram standard cap. Template v3, whose script is 985 bytes longer, pays about 26,100 more script units per settle vault input (`docs/measurements/v3-zk-units.txt`).

### Startup check

impulse-core embeds the artifact and `TEMPLATE_HASH` and checks them once, before the first instantiation or decode, in this order. Every later call returns the same refusal, so a template that fails the check never produces or accepts a script.

1. The artifact parses, has schema version 1 and holds exactly one contract, `ImpulseVault`: `TEMPLATE_ARTIFACT_INVALID`.
2. Its state fields are the 34 of the table below, by name, type and order: `TEMPLATE_ARTIFACT_INVALID`. This pins the mapping to the contract.
3. The state span lies inside the bytecode, and the prefix and suffix are not empty: `TEMPLATE_ARTIFACT_INVALID`.
4. The template hash of the prefix and suffix equals the artifact's declared hash, then the hash in `TEMPLATE_HASH` (64 lowercase hex digits, an optional final newline; anything else is `TEMPLATE_ARTIFACT_INVALID`): `TEMPLATE_HASH_MISMATCH`.
5. silverscript's own consistency check (canonical example state, distinct dispatch tags): `TEMPLATE_ARTIFACT_INVALID`.

## Which legs have a vault

| Terms | Asset leg (index 0) | Cash leg (index 1) |
| --- | --- | --- |
| Vault, KAS or KCC-20 cash | vault | vault |
| Vault, external cash | vault | none |
| Direct | none | none |

Asking for a leg with no vault is `TEMPLATE_NO_VAULT`.

## Instantiation

Instantiation takes structure-checked terms (`ValidatedTerms`, whose only constructor is `Terms::validate_structure`) and a leg index. There are two entry points, and they give values of two types:

- `Vault::instantiate_existing` gives a `Vault` for an existing trade: settle, refund, verify, decode. It does not depend on the time, so a trade past its expiry still yields its vaults for refunds. A `Vault` has no funding address.
- `Vault::instantiate_for_creation` gives a `FundableVault` for a trade being created or accepted, before anyone funds it. It runs the creation checks of `ENCODING.md` first (`TERMS_NETWORK_MISMATCH`, `TERMS_EXPIRY_NOT_AFTER_CREATION`, `TERMS_EXPIRY_BEYOND_HORIZON`). Only a `FundableVault` has a funding address, so an expired or mis-networked trade is never shown as something to fund; the type checker enforces it.

Then, in order:

1. The startup check.
2. The leg has a vault: Direct terms first, then the cash leg of external cash (`TEMPLATE_NO_VAULT`).
3. The state is encoded, and the redeem script is prefix, state, suffix.

Terms with one KCC-20 token on both legs never reach instantiation: the structure checks refuse them (`TERMS_SAME_COVENANT`).

A leg index is 0 (asset) or 1 (cash); any other value, wherever one is read as a number, is `TEMPLATE_LEG_INDEX`.

### State

Each field is one explicit data push, as silverscript-abi encodes contract state: empty data is `OP_0`, 1 to 75 bytes `OP_DATA_n`, 76 to 255 bytes `OP_PUSHDATA1`. Field encodings: `byte` 1 byte; `bool` 1 byte, 0 or 1; `int` 8 bytes, a fixed-width script number (little-endian magnitude, sign in the top bit of the last byte); `pubkey` 32 bytes; `byte[N]` N bytes; `byte[]` any length.

| # | Field | Type | Value |
| --- | --- | --- | --- |
| 1 | version | byte | terms version (1) |
| 2 | network | byte | 0 mainnet, 1 testnet |
| 3 | nonce | byte[8] | nonce, u64 little-endian |
| 4 | sellerKey | pubkey | seller_key |
| 5 | buyerKey | pubkey | buyer_key |
| 6 | hasAuthority | bool | authority_key present |
| 7 | authorityKey | pubkey | authority_key, or 32 zero bytes when absent |
| 8 | assetCovenantId | byte[32] | asset leg covenant_id |
| 9 | assetTemplateHash | byte[32] | asset leg template_hash |
| 10 | assetPrefixLen | int | asset leg template_prefix_len |
| 11 | assetSuffixLen | int | asset leg template_suffix_len |
| 12 | amountA | int | asset leg amount |
| 13 | cashKind | byte | 0 KAS, 1 KCC-20, 2 external |
| 14 | cashCovenantId | byte[32] | KCC-20 cash: covenant_id; otherwise zero |
| 15 | cashTemplateHash | byte[32] | KCC-20 cash: template_hash; otherwise zero |
| 16 | cashPrefixLen | int | KCC-20 cash: template_prefix_len; otherwise 0 |
| 17 | cashSuffixLen | int | KCC-20 cash: template_suffix_len; otherwise 0 |
| 18 | amountB | int | cash leg amount |
| 19 | buyerDeliveryType | byte | buyer_delivery identifier type: 0 PUBKEY, 1 SCRIPT_HASH, 2 COVENANT_ID |
| 20 | buyerDeliveryId | byte[32] | buyer_delivery identifier |
| 21 | sellerProceedsType | byte | KCC-20 cash: seller_proceeds identifier type; otherwise 0 |
| 22 | sellerProceedsId | byte[32] | KCC-20 cash: seller_proceeds identifier; otherwise zero |
| 23 | sellerProceedsSpk | byte[] | KAS cash: seller_proceeds as script introspection returns it, the version as u16 big-endian then the script; otherwise empty |
| 24 | sellerRefundType | byte | seller_refund identifier type |
| 25 | sellerRefundId | byte[32] | seller_refund identifier |
| 26 | buyerRefundType | byte | as 21, for buyer_refund |
| 27 | buyerRefundId | byte[32] | as 22, for buyer_refund |
| 28 | buyerRefundSpk | byte[] | as 23, for buyer_refund |
| 29 | hasEarliest | bool | earliest_daa present |
| 30 | earliestDaa | int | earliest_daa, or 0 when absent |
| 31 | expiryDaa | int | expiry_daa |
| 32 | fundingMode | byte | 0 revocable, 1 earmarked |
| 33 | tradeRef | byte[32] | trade_ref |
| 34 | legIndex | int | 0 asset, 1 cash |

The byte values equal the terms encoding's kind bytes and the contract's constants. Two terms fields are not in the state: settlement_mode (a script always means Vault) and the asset leg kind (always KCC-20 in v1, decision D13). Every value fits its field, since the structure checks bound amounts by `i64::MAX` and lock times below 500,000,000,000, and template lengths are u32.

## Script hash, scriptPubKey and address

- Script hash: BLAKE2b-256, unkeyed, of the redeem script. It is also the KCC-20 SCRIPT_HASH owner identifier of the leg's escrowed token.
- scriptPubKey (what the depositor funds): version 0, `OpBlake2b OpData32 <script hash> OpEqual`.
- Address: shown for a `FundableVault` only (`address::vault_address`). A Kaspa address of version 8 (ScriptHash) with the script hash as payload, and the prefix of the terms' network: `kaspa` for mainnet, `kaspatest` for testnet. The encoding is rusty-kaspa a41a333's (`crypto/addresses`): the version byte and payload in 5-bit groups, then a 40-bit BCH-style checksum over the prefix, alphabet `qpzry9x8gf2tvdw0s3jn54khce6mua7l`. An address for another network than the terms' is never produced.

## Decoding

Decoding takes any byte string offered as a redeem script, for example one revealed by a spend. In order, first failure returned:

1. The startup check.
2. The script is at least prefix plus suffix long, starts with the prefix and ends with the suffix: `TEMPLATE_NOT_IMPULSE_VAULT`.
3. The state between them parses as exactly the 34 pushes of the table, each of its type and size: `TEMPLATE_STATE_MALFORMED`.
4. Each field becomes its terms value, in state order. An enumeration byte with no meaning (network, cashKind, an identifier type, fundingMode), a negative integer, a template length above u32, or a KAS scriptPubKey shorter than its 2-byte version is `TEMPLATE_STATE_INVALID`. A legIndex other than 0 or 1 is `TEMPLATE_LEG_INDEX`. A cash destination reads only the part its cash kind uses.
5. The structure checks of `ENCODING.md`, with their `TERMS_*` codes.
6. The instantiation refusal `TEMPLATE_NO_VAULT`.
7. Instantiating the decoded terms at the decoded leg gives the input byte for byte: `TEMPLATE_NONCANONICAL`. This refuses non-minimal pushes, a negative zero, a key under an absent authority, a value under an absent earliest_daa, and anything in a field the cash kind leaves unused.

The result is structure-checked terms (settlement_mode Vault) and the leg index. Hence decoding the script of `Vault::instantiate_existing(t, leg)` gives `(t, leg)`, and a script `s` that decodes to `(t, leg)` is exactly that instantiation. Creation checks are not part of decoding: a vault may be decoded after its trade has expired.

The template hash of an instance is recomputed from its first prefix-length and last suffix-length bytes, without trusting any declared hash. Every vault gives the template hash, whatever its state; a script of another template gives another hash; a script shorter than prefix plus suffix is `TEMPLATE_NOT_IMPULSE_VAULT`. The state length varies (KAS cash puts two scriptPubKeys in it), so the split always uses the template's prefix and suffix lengths, never the example artifact's state span.

## Why these refusals

- **Leg index.** The contract treats legIndex 0 as the asset leg and every other value as the cash leg, and requires the vault input to sit at position legIndex. A vault at index 2 could never settle.
- **No vault.** Direct terms escrow nothing, and the state has no settlement mode, so a Direct "vault" would decode as Vault terms. Under external cash the spec escrows only the asset: a cash vault could never settle (`[E1]` finds no input of the zero cash covenant), and only the buyer could refund it.
- **Unknown cash kind.** The contract treats any cash kind other than 0 and 2 as KCC-20, and any funding mode other than 0 as earmarked. Instantiation writes only the defined values, since the terms types have no others, and decoding refuses the rest.
- **Zero amounts, timestamp-domain lock times, an authority equal to a party, one token on both legs.** Refused by the structure checks every `ValidatedTerms` has passed (`TERMS_AMOUNT_ZERO`, `TERMS_EXPIRY_NOT_DAA`, `TERMS_EARLIEST_NOT_DAA`, `TERMS_AUTHORITY_IS_PARTY`, `TERMS_SAME_COVENANT`); decoding runs them again. With one token on both legs, `[E1]` (each escrow the only input of its covenant) would stop both vaults from ever settling.
- **Expiry beyond the creation horizon.** A creation check, run by `instantiate_for_creation` before anyone funds a vault (`TERMS_EXPIRY_BEYOND_HORIZON`). It is not run for an existing trade, which must stay refundable after it expires.

## The cash-vault script of external-cash terms

Impulse never instantiates a cash vault for external-cash terms. The script still exists: anyone can compile the template with those terms and legIndex 1, and fund its P2SH address. It must never be funded. The engine tests in `tests/engine/instantiate.rs` pin what the contract does with a UTXO there; the behaviour is recorded, not changed:

- Only the buyer can refund it. A refund signed by the seller or the authority is refused, in both funding modes: a refund not signed by the depositor must carry a token of the leg's covenant (`[R11]`), and the cash covenant of these terms is zero.
- The refund returns only as KAS, whole, to the buyer's P2PK. A refund that pays it elsewhere, or short, is refused.
- A KCC-20 token held by that script's hash is refused: the buyer's refund authorizes its transfer, and `[F3]` refuses a token of any covenant at an input after the vault (`foreign_covenant::f3_external_cash_vault_refund_refuses_any_token`); no token has the zero cash covenant these terms name.

Impulse tools give no address for this script (`TEMPLATE_NO_VAULT`), and decoding refuses it.

## Error codes

Stable codes for every template refusal. Integrators match on the code, never on the message text. A terms refusal met on the way keeps its `TERMS_*` code. The list is frozen by the test `template::tests::template_error_codes_are_frozen` and may only grow. `spec/ERRORS.md` is the authoritative catalogue of every Impulse code: it lists these codes in this order, with the same raised-by and meaning, and a test in `tests/parity` fails if the two tables differ. `TEMPLATE_SAME_COVENANT` was retired before it reached `main`, in favour of `TERMS_SAME_COVENANT`, and is reserved, never reused (`spec/ERRORS.md`, "Retired and changed codes").

| Code | Raised by | Meaning |
| --- | --- | --- |
| `TEMPLATE_ARTIFACT_INVALID` | startup check | The embedded artifact or `TEMPLATE_HASH` file cannot be used |
| `TEMPLATE_HASH_MISMATCH` | startup check | The template hash differs from the artifact's declared hash or from `TEMPLATE_HASH` |
| `TEMPLATE_LEG_INDEX` | leg index, decode | A leg index other than 0 or 1 |
| `TEMPLATE_NO_VAULT` | instantiate, decode | The terms give this leg no vault (Direct, or the cash leg of external cash) |
| `TEMPLATE_NOT_IMPULSE_VAULT` | decode, template hash of an instance | The script does not run the ImpulseVault template |
| `TEMPLATE_STATE_MALFORMED` | decode | The state does not parse as the ImpulseVault state |
| `TEMPLATE_STATE_INVALID` | decode | A state field holds a value no terms value encodes to |
| `TEMPLATE_NONCANONICAL` | decode | The script is not the instantiation of the terms it decodes to |

## Golden vectors

`tests/vectors/vaults/<NN>-<name>.json`, one file per terms vector, with the terms vector's name. Each file holds:

| Key | Content |
| --- | --- |
| `name` | The terms vector's name |
| `terms_hash` | That vector's terms hash, lowercase hex |
| `template_hash` | The template hash, lowercase hex |
| `asset_vault`, `cash_vault` | The leg's vault: `leg_index`, `redeem_script`, `script_hash` (lowercase hex) and `address`; or, for a leg with no vault, `leg_index` and the refusal code under `refused` |

Frozen for this template. A new template needs a new vector set; these files never change. Three checks hold them:

- `cargo test` (`template::golden::golden_files_match`) renders every vector from the terms vectors and compares it byte for byte with the committed file, and decodes every committed redeem script back to its terms.
- `scripts/vectors.sh` refuses any change to a vector file already on `main` and any file no generator owns, regenerates the set and diffs it.
- `scripts/vectors.sh` then checks every file in Python from this document alone. It decodes each redeem script's state and compares it, field by field, with the terms vector's `terms` object and the leg index. It checks the prefix and suffix against the committed artifact, the declared template hash against `TEMPLATE_HASH`, and recomputes the script hash with `hashlib` and the address with its own encoder.
