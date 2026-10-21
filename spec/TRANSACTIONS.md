# Impulse transactions

Builders version 1, fixed in increment I5. Companion to `IMPULSE-SPEC.md` ("Entries", "Canonical settle transaction", "Settlement modes"), `TEMPLATE.md` (the vault of each leg) and `IPST.md` (the interchange format every builder returns). This file defines the transactions the builders make, their lock times, the minimum KAS and fee rules, and the `TX_*` refusal codes. Reference implementation: `crates/impulse-core/src/tx/` and `crates/impulse-core/src/locktime.rs`. Engine proof: `tests/engine/builders.rs`. Golden vectors: `tests/vectors/ipst/`.

The builders take structure-checked terms (`ValidatedTerms`) only, hold no key, and return an unsigned IPST: the transaction, the UTXOs it spends, and one signature slot per input with its sighash. Signing happens where the key lives; signatures come back as 65-byte values and are verified before they are assembled.

## Common form

Every transaction a builder makes:

- Version 1 (`TX_VERSION_TOCCATA`), the native subnetwork, gas 0, an empty payload, and a storage-mass commitment of 0 (the node sets it).
- Every input's sequence is 0 (`locktime::INPUT_SEQUENCE`): below the maximum, so a lock time stays in force and `OpCheckLockTimeVerify` accepts the input; the relative-lock bits are zero, so the node's sequence lock asks for nothing.
- Trade inputs first, in the order of the layouts below, then the fee inputs. Trade outputs first, then one change output, which is omitted when it would be zero.
- Fees only from the fee inputs. Leg amounts are exact: a token output holds exactly its leg amount, and a KAS cash output exactly `amount_b`. A trade UTXO's KAS passes through to its output unchanged, except that a pass-through output holding less than its minimum KAS (below) is topped up to the minimum from the fee inputs. That happens only where the contract checks "at least" (a token's carrier KAS, `[D2]` and `[R13]`; an authorizer's KAS going home on settle, `[S9]`) or no contract runs (Direct token deliveries); a refund's output 0 equals its input (`[R5]`) and is never topped up.
- The fee is exactly the `fee` the caller names: change is the inputs less the trade outputs less the fee.

### Fee inputs and change

The caller's `FeePayment` holds the fee inputs, the fee in sompi, and the change scriptPubKey. A fee input is a version-0 Schnorr P2PK UTXO (`OpData32 <x-only key> OpCheckSig`) without a covenant ID, whose key is a valid x-only point; its slot is signed by that key and its signature script is the one push of the signature. At least one is required. A settle or refund of a vault has at most 12 inputs in all (a template v2 settle at most N + 18, a template v4 spend at most 8, `ZK_H_SHAPE`), the bound of the vault's input check (spec/TEMPLATE.md, "Inputs outside the layout"): more is `TX_TOO_MANY_INPUTS`, checked right after the fee inputs. Fund transactions and Direct transactions have no such bound. In the fund builders the same inputs also pay the deposit. The change scriptPubKey must be a standard version-0 script (P2PK, P2PK-ECDSA or P2SH).

### Signature scripts and slots

| Spend | Signature script (then the redeem script push for P2SH spends) | Signer of the slot |
| --- | --- | --- |
| ImpulseVault `settle(sig authSig)` | `authSig`, the entry's dispatch tag | The authority; without one, no slot and `authSig` is 65 zero bytes (the contract does not read it) |
| ImpulseVault `refund(sig s, pubkey signer)` | `s`, the signer's key, the dispatch tag | The refund signer |
| KCC-20 `transfer`, covenant leader | the new states of the covenant's outputs, `sig`, the witness input index, the dispatch tag | The owner key for a PUBKEY-owned token; no slot for a vault-owned (SCRIPT_HASH) token, whose `sig` is 65 zero bytes and whose witness is the vault input (kcc20.sil) |
| KCC-20 `transfer`, covenant delegate | `sig`, the witness, the dispatch tag | The owner key |
| P2PK | the signature | The P2PK key |

Arguments are encoded with silverscript-abi from the ImpulseVault artifact (embedded, checked against `TEMPLATE_HASH`) and from the token's KCC-20 artifact (below). A slot is the signature script cut around the one 65-byte signature push (`IPST.md`, "Signature script").

### KCC-20 templates

Terms name a token's template by hash and by prefix and suffix lengths only. To build a token UTXO's redeem script and a `transfer` call, the builder takes the token's silverscript ABI artifact (`Kcc20Template`). It accepts an artifact only if it holds one contract whose state is the KCC-20 state of kcc20.sil (owner identifier `byte[32]`, identifier type `byte`, amount `int`, minter flag `bool`), whose `transfer` covenant has a leader entry `(newStates, sig, witness)` and a delegate entry `(sig, witness)`, whose prefix and suffix are not empty and hash to its declared template hash, and which passes silverscript's consistency check. Per leg it must match the hash and lengths the terms name. Any failure is `TX_TOKEN_TEMPLATE`.

A token UTXO is identified by its covenant ID and by its scriptPubKey, the P2SH of the template holding its state. A builder recomputes that scriptPubKey from the state and refuses a UTXO whose script differs.

### A token of another covenant at a vault

kcc20.sil (silverscript v1.0.0, `checkInputSig`) lets a token whose owner is SCRIPT_HASH move in any transaction that also spends an input at that script hash's address. A vault (spec/TEMPLATE.md, "Inputs outside the layout": `[F1]` to `[F5]`; the same in template v2, v3 and the hashlock template, spec/V2.md and spec/V3-ZK.md; in template v4 `[T10]` and `[T11]`) refuses every settle and refund in which an input other than the vault carries a covenant the layout does not name, or a second input of the other leg's covenant. So no token of a covenant the layout does not name moves with a spend of a vault. Such a token sent to a vault's address cannot move at all, since every spend that could move it spends the vault: send each leg only to its own vault address. The builders never put such a token in a transaction (their fee inputs carry no covenant ID, their vault UTXOs none either) and keep every spend within the inputs the template allows (`TX_TOO_MANY_INPUTS`).

A token of a leg's own covenant at the other leg's vault address (for example a buyer who sends the KCC-20 cash token to the asset vault's address) cannot move either: in every template a settle requires the other leg's vault beside this one (template v1 and v3 `[S10]`, spec/TEMPLATE.md, "The other leg's vault"; template v2 `[S10]`; template v4 the guest's `[H5]`, spec/V3-ZK.md 22.16), and that vault admits only its own escrow, while a refund refuses the token as one of another covenant. So known limitation L20 is closed in every template, with no remaining case: a misdirected token is not taken by whoever spends a vault, but nobody can recover it. Engine tests: `foreign_covenant_residual.rs` (template v1, and template v3 on the probe through `v3p_sibling.rs`), `v3_settle.rs` (template v3 with the committed receipts) and `v4_script.rs` (template v4). The builders' warning `TOKEN_FOREIGN_AT_VAULT` and the watcher's flag `WATCH_FOREIGN_TOKEN`, which pointed at the case closed here, are retired (`ERRORS.md`, "Retired and changed codes").

### Compute budgets

Each input carries a compute budget: 100 grams of compute mass and 10,000 script units per unit, on top of 9,999 free units per input. The script engine (rusty-kaspa a41a333) charges 100,000 script units per signature check, 1 per byte that an operation other than a literal push puts on the stack, and 2 per byte hashed with Blake2b. A spend that reads or rebuilds a KCC-20 token script therefore costs units in proportion to the token template's length (its prefix and suffix, as the terms name them). The builders size every budget from those lengths and never go below a floor, the budget measured for the fixture tokens with margin:

| Spend | Script units budgeted | Floor (`tx::*_BUDGET`) |
| --- | --- | --- |
| ImpulseVault settle or refund | 100,000 + 45,000 + 17 per byte of each KCC-20 template the entry reads: on settle the asset template, and the cash template too for KCC-20 cash; on a refund the leg's template when the token goes home with it, else none | 20 (`VAULT_BUDGET`) |
| KCC-20 `transfer` leader | 100,000 when a key owns the token + 10,000 + 1,000 per covenant input and output + (2 + 4 per covenant output) per template byte | 14 owned by a key (`KCC20_KEY_OWNED_BUDGET`), 3 owned by a vault (`KCC20_VAULT_OWNED_BUDGET`) |
| KCC-20 `transfer` delegate | 100,000 + 10,000 + 2 per template byte | 14 |
| P2PK | 100,001, exact | 10 (`P2PK_BUDGET`) |

An input's budget is the smallest whose allowance covers its units. The per-byte rules are measured, not assumed (`builders::per_byte_script_units_are_measured` asserts them and prints the measurements with `-- --nocapture`): with kcc20.sil padded so the asset template has 1,461 (the fixture), 3,771 and 6,081 bytes and the cash template 199 bytes more, an ImpulseVault entry costs exactly 17 units per byte of its own leg's template (read with `readInputStateWithTemplate`, 7, and its delivery validated, 10) and 10 per byte of a template it only validates; a `transfer` leader costs 2 per byte plus 4 per covenant output it validates, a delegate 2 per byte. Besides the signature check and the template bytes, an ImpulseVault entry measured at most 33,273 units with one fee input and 34,911 at the bound of 12 inputs (the KCC-20 cash settle's asset vault input, 176,348 units in all, most of it the settle's `[S10]`; raw data in `docs/evidence/template-fix-I26/s10-units.txt`), and a `transfer` at most 4,299 (two covenant inputs, two outputs). For the fixture tokens (`cargo test -p impulse-engine-tests --test builders budgets -- --nocapture`, rusty-kaspa a41a333, mainnet parameters):

| Spend | Most script units measured | Covering budget | Committed |
| --- | --- | --- | --- |
| ImpulseVault settle or refund | 176,089 | 17 | 20 |
| KCC-20 transfer, PUBKEY owner | 119,992 | 11 | 14 |
| KCC-20 transfer, vault owner | 12,392 | 1 | 3 |
| P2PK | 100,001 | 10 | 10 |

The engine tests run every input at its committed budget, for the fixture tokens and for templates of about 3,800 and 6,100 bytes, where the vault and token budgets rise above their floors (`builders::budgets_follow_the_template_length`). The KCC-20 rules hold for kcc20.sil's `transfer` code at any template length. A token whose `transfer` does more work per byte (more hashing or rebuilding of its own script) needs more than these rules give and is outside v1. Every budget unit adds 100 grams of compute mass, so a budget too large for the standard cap is refused by the mass check (`TX_MASS`); for long templates the transient mass reaches the cap first (a settle with two templates of about 10,700 bytes, same test).

## Lock time

Two rules decide when a transaction with a lock time may enter a block:

- **Script rule** (I1). ImpulseVault's `require(tx.daa >= x)` compiles to `OpCheckLockTimeVerify`: the transaction's lock time must be a DAA score (below 500,000,000,000) of at least `x`, and the spending input's sequence below the maximum.
- **Node rule** (rusty-kaspa a41a333, `consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs`, `check_tx_is_finalized`). A transaction with a nonzero DAA-score lock time `L` is final in a block of DAA score `d` only if `L < d`, unless every input's sequence is the maximum. Mempool admission applies the same rule with the virtual DAA score.

So a transaction locked at `x` enters a block from DAA score `x + 1` on. The effective earliest settle is `earliest_daa + 1`, and the depositor's earmarked refund opens at `expiry_daa + 1`.

| Transaction | Lock time | First block DAA score |
| --- | --- | --- |
| Settle | `earliest_daa`, or 0 without one | `earliest_daa + 1` |
| Direct | `earliest_daa`, or 0 without one | `earliest_daa + 1`. No contract runs in Direct; the node rule alone holds it back |
| Refund by the depositor of an earmarked leg | `expiry_daa` | `expiry_daa + 1` |
| Any other refund, and funding | 0 | any |

impulse-core ports both node rules line for line from the pinned revision (`locktime::check_tx_is_finalized`, `locktime::check_sequence_lock`), because the `kaspa-consensus` crate that holds them would bring the node's storage engine into the build. A test keeps the ports tied to that source: `builders::node_rule_ports_follow_the_pinned_source` finds the pinned checkout through `cargo metadata` and requires every load-bearing statement of the upstream functions, whitespace and comments aside, both there and in the port. The engine tests compose the ports with the script engine. One DAA score either side of each bound:

| Test (`builders::`) | Script rule | Node rule |
| --- | --- | --- |
| `boundary_settle_before_earliest_is_refused` | lock time `earliest_daa - 1` refused by both vaults (`[S3]`) | the settle (lock time `earliest_daa`) not final in a block at `earliest_daa` |
| `boundary_settle_from_earliest_is_accepted` | lock time `earliest_daa` accepted | final in a block at `earliest_daa + 1`, every input accepted |
| `boundary_refund_before_expiry_is_refused` | the earmarked depositor's refund at lock time `expiry_daa - 1` refused (`[R3]`) | the refund (lock time `expiry_daa`) not final in a block at `expiry_daa` |
| `boundary_refund_from_expiry_is_accepted` | lock time `expiry_daa` accepted | final in a block at `expiry_daa + 1`, every input accepted |

### Expiry

The contract cannot forbid a settle after expiry (IMPULSE-SPEC.md, red team). The builders do: `fund_kas`, `fund_kcc20`, `settle` and `direct` take the caller's current DAA score and refuse to build (`TX_EXPIRED`) when the trade can no longer settle in a block at or below `expiry_daa`, before the depositor's earmarked refund opens: when the current DAA score is at or past `expiry_daa`, or when `earliest_daa` equals `expiry_daa` (the structure checks allow it, but such a settle enters a block only from `expiry_daa + 1`). A transaction built earlier can still be broadcast late; the authority and the submitter refuse that by policy. A refund is never refused for expiry: it is what expiry is for.

## Builders

### fund_kas: a KAS cash leg

Takes the terms, the cash leg's `FundableVault` (`TEMPLATE.md`), the funding `FeePayment` and the current DAA score.

| Position | Input | Output |
| --- | --- | --- |
| 0 | The payer's P2PK inputs, signed by their keys | Exactly `amount_b` at the cash vault's scriptPubKey |
| 1 | | Change |

### fund_kcc20: a KCC-20 leg (asset, or KCC-20 cash)

Takes the terms, the leg's `FundableVault`, the token's `Kcc20Template`, the deposit (the depositor's token UTXOs, the carrier KAS of the escrowed token, the KAS of the authorizer), the funding `FeePayment` and the current DAA score. The token UTXOs are of the leg's covenant, all owned by one public key, not minters, and hold at least the leg amount together.

Inputs, in order: the token UTXOs (the first is the `transfer` leader, the others delegates, each signed by the owner key), then the payer's P2PK inputs. A token template limits the covenant inputs and outputs of one transfer (`maxCovIns`, `maxCovOuts`; two inputs for the fixture tokens). Its ABI artifact does not state the limits, so the builder cannot check the number of token inputs; the token's own script refuses a transfer beyond them (`builders::a_transfer_beyond_the_tokens_max_cov_ins_is_refused_by_the_token`). A depositor holding the leg in more UTXOs than its token allows merges them first with an ordinary transfer.

| Output | Content |
| --- | --- |
| 0 | The escrowed token: exactly the leg amount, owner SCRIPT_HASH of the vault's script hash, not a minter, `carrier` KAS, covenant binding to input 0 |
| 1 | The authorizer: `authorizer` KAS at the vault's scriptPubKey |
| 2, if the tokens hold more | Token change: the rest to the same owner, `MIN_KCC20_OUTPUT` KAS, covenant binding to input 0 |
| last | KAS change |

The leader's new states are the escrow state and, if any, the change state, in output order.

### settle: the canonical layout (IMPULSE-SPEC.md, "Canonical settle transaction")

Takes the terms (Vault), the funded vault UTXOs with the token templates, the fee payment and the current DAA score. The authorizers must be plain UTXOs at their vaults' scriptPubKeys; each escrow must be its vault's token (the leg's covenant, the template holding exactly the leg amount, owner SCRIPT_HASH of the vault, not a minter); a KAS cash vault UTXO must hold exactly `amount_b`.

| Position | Input | Output |
| --- | --- | --- |
| 0 | Asset authorizer, `settle`, signed by the authority if any | Asset to `buyer_delivery`: `amount_a`, the asset escrow's KAS (topped up to `MIN_KCC20_OUTPUT`), covenant binding to the asset escrow's input |
| 1 | KAS cash vault UTXO, or cash authorizer, `settle`, signed by the authority if any | KAS cash: exactly `amount_b` to `seller_proceeds`. KCC-20 cash: `amount_b` to `seller_proceeds`, the cash escrow's KAS (topped up to `MIN_KCC20_OUTPUT`), covenant binding to input 3 |
| 2 | Asset escrow, `transfer` leader, witness 0 | The asset authorizer's KAS, whole (topped up to `MIN_KAS_OUTPUT`), to the seller's P2PK |
| 3 | Cash escrow (KCC-20 cash only), `transfer` leader, witness 1 | The cash authorizer's KAS, whole (topped up to `MIN_KAS_OUTPUT`), to the buyer's P2PK (KCC-20 cash only) |
| next | Fee inputs | Change |

External cash drops positions 1 and 3: the asset escrow is input 1 (witness 0, the asset delivery's covenant binding names input 1) and the seller's authorizer KAS is output 1. The authority signs inputs 0 and 1 separately: each vault input has its own sighash.

### refund: one vault UTXO home, per signer role

Takes the terms (Vault), the leg, the signer role (depositor, counterparty, authority), the vault UTXO, optionally the escrowed token with its amount, minter flag and template, and the fee payment. The leg must have a vault (`TEMPLATE_NO_VAULT` otherwise, in particular for the cash leg of external cash: no builder recovers a stray deposit there, owner decision D14).

| Position | Input | Output |
| --- | --- | --- |
| 0 | The vault UTXO, `refund`, signed by the signer | Its KAS, whole: to `buyer_refund` for KAS cash, else to the depositor's P2PK |
| 1 | KCC-20 leg: the escrowed token, `transfer` leader, witness 0 | The token, whole (same amount and minter flag), to the leg's refund owner, its own KAS (topped up to `MIN_KCC20_OUTPUT`), covenant binding to input 1 |
| next | Fee inputs | Change |

The escrowed token must be the vault's: the leg's covenant, owner SCRIPT_HASH of the vault, the template holding the stated amount and minter flag. Only the depositor may leave the token out, or refund a token holding another amount than the leg's; a counterparty or authority refund of a KCC-20 leg takes the token, which must hold exactly the leg amount (`[R14]` checks the amount only). A minter flag bars no signer: the token goes home with its amount and flag unchanged (engine `builders::refunds_of_stray_tokens_validate_in_the_engine`). A KAS cash leg has no token. Any UTXO at a vault address can be refunded this way, whenever it arrived.

A depositor's refund without the token sends the authorizer home alone and leaves the escrowed token where it is: owned by the vault's script hash, it can move only in a transaction that also spends a UTXO at the vault's address. To get it back, the depositor funds a new authorizer at the vault address (any KAS UTXO there) and refunds that one with the token. The builder allows the authorizer-alone refund because it is how a stray authorizer goes home; a tool should ask for it explicitly and say that the token stays escrowed (carried to I7).

### direct: Direct mode

Takes the terms (Direct), the seller's asset token UTXO (owned by a public key, exactly `amount_a`), the buyer's cash (a P2PK UTXO of exactly `amount_b` KAS, or a token UTXO of exactly `amount_b` owned by a public key) with the templates, the fee payment and the current DAA score.

| Position | Input | Output |
| --- | --- | --- |
| 0 | The seller's token, `transfer` leader, signed by its owner | Asset to `buyer_delivery`: `amount_a`, the token's KAS (topped up to `MIN_KCC20_OUTPUT`), covenant binding to input 0 |
| 1 | The buyer's cash: P2PK or token `transfer` leader, signed by its owner | KAS: exactly `amount_b` to `seller_proceeds`. KCC-20: `amount_b` to `seller_proceeds`, the token's KAS (topped up to `MIN_KCC20_OUTPUT`), covenant binding to input 1 |
| next | Fee inputs | Change |

Each party signs only its own input; the IPST carries the transaction between them. Either party aborts by spending its input elsewhere first.

## Mass, minimum KAS and fee

### Masses and the standard cap

The builders compute the masses of the signed transaction (every signature is 65 bytes, so the size is known before signing) with the pinned `MassCalculator` and the network's parameters (mainnet, or testnet for TN10): compute and transient mass, and the KIP-9 storage mass from the UTXO entries. Each must be at most 100,000 grams (`STANDARD_MASS_CAP`), else `TX_MASS`. That is kaspa-mining's `MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA` and kaspa-wallet-core's `MAXIMUM_STANDARD_TRANSACTION_MASS` at a41a333. After Toccata the mempool's only per-transaction cap is the block limit, 500,000 grams; Impulse keeps the stricter figure, so its transactions also pass nodes and wallets that still apply 100,000.

For the engine test fixtures (rusty-kaspa a41a333, mainnet parameters, every vault UTXO at the minimum below), the settle transactions compute to the following (golden vectors `tests/vectors/ipst/` 04, 05 and 07, pinned by the SDK's `results.test.ts`):

| Settle | Inputs, outputs | Compute mass | Transient mass | Minimum relay fee (sompi) |
| --- | --- | --- | --- | --- |
| KAS cash, with or without an authority | 4, 4 | 17,182 | 41,728 | 2,086,400 |
| KCC-20 cash, with or without an authority | 5, 5 | 19,676 | 49,024 | 2,451,200 |
| External cash | 3, 3 | 10,552 | 24,648 | 1,232,400 |

These are computed by the pinned calculator for these transactions, not observed on a network.

### Minimum KAS per leg

Derived from the pinned KIP-9 storage mass rule, not measured on a network.

- Storage mass (`calc_storage_mass`, a41a333): `max(0, C * sum over outputs of p^2 / v - relief)`, with `C = 10^12` (`STORAGE_MASS_PARAMETER`), `v` an output's value and `p` its plurality, `ceil((63 + script length + 32 if it has a covenant) / 100)`. A standard KAS output (P2PK, P2PK-ECDSA, P2SH) has `p = 1`; a KCC-20 token output (P2SH and a covenant ID) has `p = 2`. The relief term depends on the inputs and is never negative, so the storage mass is at most `C * sum(p^2 / v)` whatever the inputs are, including any fee input.
- An Impulse transaction has at most five outputs (`MAX_OUTPUTS`: a settle with KCC-20 cash, four trade outputs and change).
- If every output holds at least `p^2 * C * MAX_OUTPUTS / CAP`, each adds at most `CAP / MAX_OUTPUTS` and the storage mass is at most the cap. With `CAP = 100,000`: `SOMPI_PER_STORAGE_UNIT` = 50,000,000 sompi.

| Output | Plurality | Minimum |
| --- | --- | --- |
| KAS: an authorizer, a KAS cash leg, change (`MIN_KAS_OUTPUT`) | 1 | 50,000,000 sompi (0.5 KAS) |
| KCC-20 token: a token's carrier KAS (`MIN_KCC20_OUTPUT`) | 2 | 200,000,000 sompi (2 KAS) |

So a KAS cash leg is at least 0.5 KAS, and a KCC-20 leg locks at least 2.5 KAS (the escrowed token's carrier and the authorizer), all of which goes on with the leg: to the receiving party on settle, home on refund. The bound is of the right size, not loose: five outputs at half these minimums put the worst case at twice the cap (`tx::tests::at_the_minimum_the_worst_case_fits_the_cap`).

Where the minimum is checked (`TX_BELOW_MIN_KAS`): every output a builder creates as a new leg UTXO or chooses the value of, namely the escrowed token's carrier and the authorizer in `fund_kcc20`, the deposit in `fund_kas`, the KAS cash payment in `direct`, the token change in `fund_kcc20` (always `MIN_KCC20_OUTPUT`), and every change output.

Outputs that pass a UTXO's KAS through take their input's value, topped up to the minimum where the contract allows it (see "Common form"). So an authorizer or a token carrier below its minimum, funded by hand or by a depositor who wants to block the trade, does not block the settle: the settler pays the difference, at most 0.5 KAS per authorizer and 2 KAS per carrier, and it goes on with the leg (`tx::tests::under_funded_pass_through_outputs_are_topped_up`, engine `builders::topped_up_outputs_validate_in_the_engine`). Two outputs cannot be topped up, and for them the exact storage mass is checked (`TX_MASS`):

- the KAS cash output of a settle, which must equal `amount_b` (`[S5]`). Terms whose `amount_b` is below `MIN_KAS_OUTPUT` have no standard settle (`tx::tests::mass_above_the_cap`); `fund_kas` refuses to fund them (`TX_BELOW_MIN_KAS`), and flagging such terms before anyone funds is carried to the verifier (I6);
- a refund's output 0, which must equal the vault UTXO (`[R5]`). The depositor can still refund a stray authorizer below the minimum on its own, because with at most two inputs and two outputs KIP-9 also takes the harmonic mean of the inputs, so the equal small input offsets the small output. With the token at input 1 (three inputs) that relief does not apply, so a refund of a KCC-20 leg whose authorizer is far below the minimum is refused (`TX_MASS`, same test); the depositor then refunds the authorizer alone, funds a new authorizer at the vault address, and refunds that with the token.

Dust: the pinned mempool has no separate dust rule (kaspa-wallet-core's `is_transaction_output_dust` says so); its wallet dust heuristic flags P2PK outputs below roughly 60,000 sompi, far under these minimums.

### Minimum relay fee

The fee must be at least the minimum relay fee for the transaction's mass, as kaspa-mining computes it after Toccata (`TX_FEE_TOO_LOW`): the fee mass is the larger of the compute mass and the transient mass normalized to the compute scale (`ceil(transient * 500,000 / 1,000,000)`, the post-Toccata mempool limits), and the minimum is `fee mass * 100,000 / 1,000` sompi (`DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE`, 100 sompi per gram), at least 100,000 sompi. `Ipst::masses` and `tx::min_relay_fee` give a caller the figure before it chooses the fee.

## Refusal order

The first failing check is returned, so every implementation reports the same code for the same input. Each builder runs its own checks first, in this order:

- `fund_kas`: the vault is the terms' (`TX_VAULT_MISMATCH`), the leg is KAS cash (`TX_WRONG_MODE`), expiry (`TX_EXPIRED`), the deposit's minimum (`TX_BELOW_MIN_KAS`).
- `fund_kcc20`: the vault (`TX_VAULT_MISMATCH`), the leg is KCC-20 (`TX_WRONG_MODE`), expiry, the template (`TX_TOKEN_TEMPLATE`), each token input in order and then their total (`TX_TOKEN_INPUT`), the carrier's and then the authorizer's minimum (`TX_BELOW_MIN_KAS`).
- `settle`: Vault terms, then the cash kind (`TX_WRONG_MODE`), expiry, the asset authorizer (`TX_NOT_AT_VAULT`), the asset template (`TX_TOKEN_TEMPLATE`), the asset escrow (`TX_ESCROW_MISMATCH`); then for KAS cash the cash vault UTXO (`TX_NOT_AT_VAULT`, then `TX_LEG_AMOUNT`), for KCC-20 cash the cash authorizer (`TX_NOT_AT_VAULT`), the cash template and the cash escrow.
- `refund`: Vault terms (`TX_WRONG_MODE`), the leg has a vault (`TEMPLATE_NO_VAULT`), an authority for the authority role (`TX_REFUND_SIGNER`), the vault UTXO (`TX_NOT_AT_VAULT`); then for KAS cash no token (`TX_WRONG_MODE`), for a KCC-20 leg the token present unless the depositor signs (`TX_REFUND_SIGNER`), its template, the escrow (`TX_ESCROW_MISMATCH`) and, unless the depositor signs, the exact leg amount (`TX_LEG_AMOUNT`).
- `direct`: Direct terms, then the cash kind (`TX_WRONG_MODE`), expiry, the asset template, the seller's token (`TX_TOKEN_INPUT`, then `TX_LEG_AMOUNT`); then for KAS cash the buyer's input (`TX_KAS_INPUT`, `TX_LEG_AMOUNT`, `TX_BELOW_MIN_KAS`), for KCC-20 cash the cash template and the buyer's token (`TX_TOKEN_INPUT`, then `TX_LEG_AMOUNT`).

Then the checks every transaction shares: the fee inputs (`TX_KAS_INPUT`), at most the inputs a vault spend allows (`TX_TOO_MANY_INPUTS`), no outpoint spent twice (`TX_DUPLICATE_INPUT`), every spent UTXO above zero and at most `MAX_SOMPI` (2,900,000,000,000,000,000 sompi, the KAS supply cap) and all of them together at most `MAX_SOMPI` (`TX_UTXO_VALUE`; consensus refuses anything else, and the pinned mass calculator divides by every value), a standard change script (`TX_NONSTANDARD_CHANGE`), enough funds (`TX_INSUFFICIENT_FUNDS`), the change minimum (`TX_BELOW_MIN_KAS`), the masses (`TX_MASS`), the relay fee (`TX_FEE_TOO_LOW`). A terms or template refusal met on the way keeps its `TERMS_*` or `TEMPLATE_*` code. `TX_ENCODING` can arise wherever a script is encoded.

## Error codes

Stable codes for every builder and signature refusal. Integrators match on the code, never on the message text. The list, with the `IPST_*` codes of `IPST.md`, is frozen by the test `tx::tests::tx_error_codes_are_frozen` and may only grow. `spec/ERRORS.md` (I10) will absorb this table.

| Code | Raised by | Meaning |
| --- | --- | --- |
| `TX_WRONG_MODE` | all builders | The builder does not apply to these terms or this leg: a vault builder on Direct terms or the reverse, a fund builder for another leg kind, a cash leg passed of another kind, a token offered with a KAS cash refund |
| `TX_VAULT_MISMATCH` | fund | The funding vault is not the vault these terms give for its leg |
| `TX_EXPIRED` | fund, settle, direct | The trade can no longer settle by `expiry_daa`: the current DAA score is at or past it, or `earliest_daa` equals it |
| `TX_NOT_AT_VAULT` | settle, refund | A vault input is not a plain UTXO (no covenant ID) at the vault's scriptPubKey |
| `TX_ESCROW_MISMATCH` | settle, refund | The escrowed token UTXO is not the vault's: covenant, owner, amount, minter flag or template |
| `TX_LEG_AMOUNT` | settle, refund, direct | A leg UTXO does not hold exactly the leg amount where required (KAS cash vault, a non-depositor refund's token, Direct inputs) |
| `TX_TOKEN_TEMPLATE` | all builders with a KCC-20 leg | The KCC-20 artifact is not a KCC-20 template, or not the one the terms name for the leg |
| `TX_TOKEN_INPUT` | fund_kcc20, direct | A party's token input cannot be spent here: covenant, owner not a valid public key, a minter, a state the script does not hold, mixed owners, too little in total |
| `TX_KAS_INPUT` | all builders | A fee, funding or Direct KAS input is not a version-0 Schnorr P2PK UTXO without a covenant ID, or there is no fee input |
| `TX_DUPLICATE_INPUT` | all builders | One outpoint is spent twice |
| `TX_INSUFFICIENT_FUNDS` | all builders | The inputs do not cover the outputs and the fee |
| `TX_BELOW_MIN_KAS` | fund, direct, every change output | An output the builder creates holds less than the minimum KAS for its plurality |
| `TX_MASS` | all builders | The compute, transient or storage mass exceeds 100,000 grams |
| `TX_FEE_TOO_LOW` | all builders | The fee is below the minimum relay fee for the transaction's mass |
| `TX_NONSTANDARD_CHANGE` | all builders | The change scriptPubKey is not a standard version-0 script |
| `TX_REFUND_SIGNER` | refund | The role is not available: an authority refund without an authority, or a counterparty or authority refund of a KCC-20 leg without its token |
| `TX_SIGNATURE` | verify, IPST | A signature is not 65 bytes, its sighash type is not SIG_HASH_ALL, it is malformed, or it does not verify against the slot's signer and sighash |
| `TX_SIGNATURE_SLOT` | sighash, IPST | An input that does not exist or takes no signature, entries that do not match the inputs, or a signature missing at finalization |
| `TX_ENCODING` | all builders | A signature script or token state could not be encoded (for example a token amount above the script integer range) |
| `TX_UTXO_VALUE` | all builders | A UTXO the transaction spends holds zero sompi or more than `MAX_SOMPI`, or the spent UTXOs hold more than `MAX_SOMPI` together |
| `TX_TOO_MANY_INPUTS` | settle, refund (v1, v2, v3 and hashlock builders) | The transaction would have more inputs than the vault template it spends allows: 12, or N + 18 for a template v2 settle (`TEMPLATE.md`, "Inputs outside the layout") |

## Golden vectors

`tests/vectors/ipst/`, specified in `IPST.md`: thirteen unsigned IPSTs covering both fund builders, settle in the authority, self-settling and external-cash modes, refunds by each role (with and without the token), and Direct with KAS and KCC-20 cash.
