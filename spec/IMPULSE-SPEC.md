# Impulse by WarpCore: Open-Source Atomic DvP for Kaspa

Product specification v0.1 · Oct 6, 2026

## Purpose and positioning

WarpCore Impulse is a standalone, open-source atomic delivery-versus-payment (DvP) primitive for Kaspa, the first public product under the WarpCore name. It covers each instruction of the Solana Foundation DvP program, and PARITY.md states, row by row, where Impulse's answer differs. It differs from the program in properties that PARITY.md lists, among them an escrow address bound to the terms (EDGE-17) and earmarked funding (EDGE-25).

The split is open core:

- **Impulse (open source):** the escrow contract, the Rust crate, a TypeScript/WASM SDK, a CLI, an address verifier and a funding watcher.
- **WarpCore (commercial):** the bank-facing lifecycle on top of Impulse. That covers ISO 20022 instructions, matching, compliance, CSDR fails, ledger and reporting.

The primitive is a commodity; Solana's program is published under the MIT licence. Impulse is the open primitive on Kaspa; the bank-facing lifecycle is built on top of it separately.

Short-term goal: a developer at a custodian can agree terms, derive both escrow addresses independently, fund, settle and refund on Kaspa mainnet. Everything runs from the CLI or SDK, with no WarpCore account and no trust in the publisher.

Where Impulse differs from the Solana program on day one:

1. **The escrow address is the terms.** Each leg's address is a hash of the agreed terms. There is no stored trade record to forge or tamper with; the funder recomputes each address from the agreed terms before funding.
2. **Earmarked funding.** An irrevocable mode locks a leg against its depositor until expiry, as settlement systems expect. The counterparty and the authority can still send the leg home. Solana only offers revocable funding.
3. **No mandatory central authority.** A self-settling mode lets anyone complete a fully funded trade, because the outputs are fixed by the contract.
4. **External cash leg.** The asset leg can be released against an off-chain RTGS or bank payment, so Impulse works before regulated cash tokens exist on Kaspa.
5. **No account baggage.** There is no rent, no recovery instruction, no permanent tombstone, and dust deposited separately does not block settlement: settle ignores third-party dust, and an authorizer or token carrier funded below the minimum KAS is topped up by the settler (`spec/TRANSACTIONS.md`). Terms whose KAS cash leg is below the 0.5 KAS minimum cannot settle, and the builders refuse to fund them.

Impulse ships on mainnet from v0.1 with a default per-trade value cap and a risk notice in its README and release notes.

## The baseline: Solana Foundation DvP

The Solana program is a minimal settlement primitive and nothing else: no messaging, matching, compliance or reporting ([solana-foundation/dvp](https://github.com/solana-foundation/dvp)).

What it ships:

- **Program:** a pinocchio-based on-chain program with six instructions and 24 error codes.
  - Instructions: Create, Reclaim, Settle, Cancel, Reject, Recover.
- **Clients:** generated Rust and TypeScript clients, plus checked verification helpers.
- **Tests and assurance:** LiteSVM integration tests.
- **Licence:** MIT.
- **Deployment:** its README calls the declared program ID a placeholder, but the pinned lib.rs declares an ID at which an executable program account was measured on 2026-10-07.

How it works:

- **Parties:** a seller and buyer swap an asset leg for a cash leg, and a named settlement authority is the only key that can settle.
- **Funding:** each side funds an escrow account by plain token transfer.
- **Settlement:** one transaction moves both legs.
- **Unwinding:** either party can pull back its own leg at any time, and either party or the authority can abort and refund both.

Behaviours that its README discloses, each compared in PARITY.md:

- **Unbound terms.** Create is permissionless and the terms are not part of the account address. Anyone can create a record with forged terms or attacker-chosen destinations.
  - Every funder must read and verify the stored terms, owner and account size before depositing.
- **Late deposits.** A transfer can land after the trade closed. Recovering it needs a dedicated instruction and a nonce tombstone account that is never closed.
- **Dust breaks settlement.** Anyone can over-deposit into an escrow, which forces a surplus refund. Settle then reverts unless all four recipient token accounts already exist.
- **Token account hazards.** It has to defend against several token-model quirks:
  - legacy token accounts can have their owner reassigned;
  - escrows can be preloaded with SOL;
  - Token-2022 extensions (hooks, fees, freeze, pause, permanent delegate) can stall or tax a leg.
- **Rent and time.** Rent paid by the creator goes to whoever closes the trade. Time gates use cluster time, which the README says lags wall-clock time and can jump forward; it advises budgeting about 60 seconds.
- **Revocable funding only.** A funded leg can be withdrawn by its depositor at any time before settlement, so a counterparty cannot rely on it until settlement.
- **Both legs on-chain.** There is no off-chain cash leg and no cross-chain leg.
- **Authority required.** No trade settles without the settlement authority.

## Scope and open-core boundary

Impulse depends on nothing in WarpCore; WarpCore depends on Impulse. That keeps the open-source release genuinely standalone and makes commercial WarpCore its first downstream user.

| Area | Impulse (open source) | WarpCore (commercial) |
| --- | --- | --- |
| Escrow contract | ImpulseVault template, compiled artifact, published template hash | Uses it unchanged |
| Terms | Canonical schema, encoding, terms hash, address derivation | Builds terms from matched sese.023 pairs |
| Transactions | Unsigned settle and refund builders, sighash, signature verify, assembly; FROST t-of-n threshold authority library (impulse-core feature `threshold`, off by default) and `impulse frost` CLI | Authority signing through HSM; managed threshold ceremonies |
| Tooling | Rust crate, TS/WASM SDK, CLI, verifier | REST API, multi-tenant, idempotency, leader election |
| Monitoring | Reference funding and settlement watcher (single node) | Virtual-chain finality tracker, reorg policy, alerting |
| Securities lifecycle | None | sese.023/024/025, cancellation, allegements, hold and release |
| Compliance | None | Sanctions, KYC/AML, travel rule, party binding |
| Post-trade | None | CSDR fails and penalties, GL postings, unit sub-ledger, billing, reporting |
| Support | Community, security policy | SLA, onboarding, operator rulebook |

Extracted from WarpCore into Impulse and relicensed:

- **Split signing flow** (`warpcore-pvp` spend module). Unsigned transaction, then per-input sighash, then signature verify, then assembly. No component ever holds a party key.
- **Sequence-lock helpers** (`consensus_lock`) and their consensus-level timeout tests.
- **Runtime template instantiation.** The SilverScript ABI pattern, plus template-hash checking against the published artifact.

Out of scope for Impulse at every version:

- multi-party netting;
- price discovery;
- custody;
- any server that holds keys.

## Design principles

Eight rules govern every design choice; anything that breaks one needs a written exception.

1. **Terms are the address.** Every economic term is inside the leg's script, so the escrow address commits to the whole deal.
2. **Each vault enforces the whole exchange.** Both vaults check both delivery outputs. No vault references the other, so there is no circular dependency and no cross-vault state.
3. **One trade per settle transaction.** A canonical input and output layout fixes where each leg and each delivery sits.
4. **Exact amounts.** A leg settles only from a UTXO holding exactly its amount. Fees always come from a separate input.
5. **Refunds are stateless and always go home.** Any UTXO at a vault address can be refunded to its depositor, at any time the mode allows. It does not matter when it arrived. A counterparty or authority refund of a KCC-20 leg returns the authorizer and its escrowed token together, so a refund never separates them; only the depositor can refund an authorizer on its own, or a token that does not hold exactly the leg amount.
6. **Smallest possible contract.** One template, two entries. A small contract is a small surface to review.
7. **No custody anywhere.** Signing happens where the key lives; Impulse builds and verifies, never signs on anyone's behalf.
8. **Fail closed, tested at consensus level.** Every entry and every refusal path runs through the real Kaspa script engine in tests.

## On-chain contract: ImpulseVault

One SilverScript template, `ImpulseVault`, with two entries (`settle`, `refund`), instantiated per trade leg from the agreed terms. In v1 the asset leg is any KCC-20 token, and the cash leg is native KAS, any KCC-20 token, or external (off-chain). Selling KAS for a KCC-20 token is expressed by swapping the buyer and seller roles, so that the token is the asset leg. Native KAS against external cash is not supported in v1 (owner decision D13).

### Why KCC-20

KCC-20 is the fungible-token convention published with silverscript ([kcc20.sil](https://github.com/kaspanet/silverscript/blob/3ed973335b59269293564805cc2c58a14595ec03/silverscript-lang/tests/examples/kcc20.sil), listed in the [Toccata references](https://docs.kaspa.org/toccata/references)). It gives Impulse three things KTT v0.2 cannot:

- **Script ownership.** A token's owner can be a public key, a P2SH script hash, or a covenant ID. A script-hash owner can only move the token in a transaction that also spends an input at that script's address.
- **Position-free outputs.** Token continuations are bound by covenant ID (KIP-20), not by a fixed output index. A security token and a cash token can therefore settle in the same transaction.
- **Market reach.** It is the core-team convention, so Impulse works with any KCC-20 token, not only Kii's.

### How a leg is escrowed

A KCC-20 leg uses two UTXOs, both created by the depositor in one ordinary funding transaction:

1. **The escrowed token.** A KCC-20 output for exactly the leg amount, with owner type script hash and owner identifier equal to the leg's vault script hash. The token's own KAS travels with it to whoever finally receives it.
2. **The authorizer.** A small KAS UTXO at the vault's P2SH address, carrying the Impulse rules.

KCC-20 lets the escrowed token move only in a transaction that spends the authorizer, and the authorizer only spends if Impulse's rules hold. A KAS leg needs no token: the vault UTXO itself holds exactly the leg amount.

### Terms

The terms hash is blake2b-256 keyed with the tag `Impulse/terms/v1`, taken over the canonical encoding of the fields below. Byte layout, validation and refusal codes are in `spec/ENCODING.md`. Each leg's redeem script is the template plus the terms plus that leg's index, and its address is the P2SH of that script; the script layout, decoding and instantiation refusals are in `spec/TEMPLATE.md`.

| Field | Type | Purpose |
| --- | --- | --- |
| version, network | u8, u8 | Terms encoding version (1); mainnet or testnet |
| settlement\_mode | u8 | Direct or vault. The vault sub-modes (authority, self-settling, external cash) follow from authority\_key and the cash leg kind |
| nonce | u64, random | Distinguishes repeat trades between the same parties |
| seller\_key, buyer\_key | x-only pubkeys | Parties who may trigger refunds |
| authority\_key | x-only pubkey, optional | Settlement authority; absent means self-settling |
| asset leg | kind (KCC-20 in v1), covenant ID, template hash, template prefix and suffix lengths, amount\_a | What the seller delivers. KAS against a token is expressed by swapping buyer and seller; KAS against external cash is not supported in v1 (decision D13) |
| cash leg | kind (KAS, KCC-20, external), covenant ID, template hash, template prefix and suffix lengths, amount\_b | What the buyer pays |
| buyer\_delivery, seller\_proceeds | KCC-20 owner (type + identifier) or KAS scriptPubKey | Where each leg lands; custodian or multisig P2SH allowed |
| seller\_refund, buyer\_refund | same | Where each leg goes home |
| earliest\_daa | DAA score, optional | Settlement not before |
| expiry\_daa | DAA score, at most about one year ahead | Opens the depositor's refund in earmarked mode |
| funding\_mode | revocable or earmarked | Whether a depositor can withdraw before expiry; vault only, Direct terms are revocable |
| trade\_ref | 32 bytes | Hash of ISIN, trade ID and settlement date; opaque to the contract |

Validation (`spec/ENCODING.md`) has two stages. Structure checks are time-independent and mandatory: builders take only terms that pass them. Creation checks run when terms are made: the network matches the creator's, and the expiry lies after the creation DAA score and within the horizon. Validation enforces amounts above zero, the expiry horizon, earliest not after expiry, distinct parties and the expected network. It also refuses:

- a seller, buyer or authority key that is not a valid x-only point, and an authority equal to either party;
- an asset leg that is not KCC-20 (external, or KAS in v1), and external cash without an authority;
- in Direct mode, external cash or earmarked funding;
- a KAS amount above the supply cap, or a KCC-20 or external amount above the signed 64-bit range of script integers;
- an all-zero covenant ID, template hash, KCC-20 owner identifier or P2SH script hash, and KCC-20 template prefix or suffix lengths that are zero or sum past the post-Toccata script size limit;
- a destination whose kind does not match its leg, a KAS destination that is not a standard version-0 P2PK, P2PK-ECDSA or P2SH script, and an invalid key inside a destination;
- an expiry\_daa or earliest\_daa outside the DAA-score lock-time domain (at or above 500,000,000,000), and an earliest\_daa that is present but zero.

### Entries

`settle` succeeds only if all of these hold:

1. This input sits at its leg's canonical index: asset authorizer at input 0, cash authorizer at input 1.
2. The escrowed value is exactly the leg amount: the KCC-20 state amount, or the KAS value for a KAS leg. A KCC-20 escrow must not be a minter (a minter escrow still refunds, as a minter).
3. Lock time is at least `earliest_daa`.
4. Output 0 delivers `amount_a` of the asset to `buyer_delivery`. For KCC-20, the output must carry the asset's covenant ID, match the pinned template hash, and equal the script rebuilt from that template and the expected state (that owner and amount). Output state is matched, not decoded (see "KCC-20 delivery output" below). The output also carries at least the escrowed token's own KAS.
5. Output 1 delivers `amount_b` of cash to `seller_proceeds`. A KCC-20 cash output also carries at least the escrowed cash token's own KAS. This check is skipped in external-cash mode.
6. If an authority is set, its signature verifies.
7. External cash needs an authority: a vault whose terms combine external cash with no authority never settles (its legs can still be refunded).
8. Each KCC-20 leg's authorizer KAS goes back to its depositor's key, at least in full: the asset authorizer's at output 2 (output 1 in external-cash mode), a KCC-20 cash authorizer's at output 3.
9. No token rides along: every input other than this vault carries no covenant, the asset covenant or (KCC-20 cash only) the cash covenant; the other leg's covenant, if that leg is KCC-20, has exactly one input; the transaction has at most 12 inputs.
10. The other leg's vault, where that leg has one (KAS or KCC-20 cash), is the input at its canonical index: the vault of these same terms with the other leg index (`spec/TEMPLATE.md`, "The other leg's vault").

`refund` succeeds only if all of these hold:

1. The signer is the leg's depositor, the counterparty, or the authority. Every refund goes home, so letting any of them trigger it is harmless. For a KCC-20 leg, a refund signed by the counterparty or the authority must also spend the escrowed token (this vault's, at input 1, holding exactly the leg amount); only the depositor can refund the authorizer without it. Anyone can make a token owned by a vault, so a decoy that passes this costs the whole leg amount, which goes home to the depositor.
2. In earmarked mode, a depositor-triggered refund needs lock time of at least `expiry_daa`.
3. The escrowed token or KAS returns whole to the depositor's refund target, and the authorizer's KAS returns to the depositor. A returned token carries at least its own KAS home.
4. No token rides along: every input after the vault carries no covenant or this leg's covenant; the transaction has at most 12 inputs.

Rules 9 of `settle` and 4 of `refund` close known limitation L20 (`docs/security/KNOWN-LIMITATIONS.md`): kcc20.sil lets a token owned by a script hash move in any transaction that also spends an input at that address, so without them a KCC-20 token of another covenant sent to a vault's address moves with any spend of that vault. They are specified in `spec/TEMPLATE.md`, "Inputs outside the layout". Rule 10 of `settle` closes what they left open, a token of a leg's own covenant at the other leg's vault (`spec/TEMPLATE.md`, "The other leg's vault"), and with it cross-trade mixing (known limitation L8).

```
contract ImpulseVault(/* terms fields */, int legIndex) {
    entrypoint function settle(sig authSig) {
        require(this.activeInputIndex == legIndex);
        require(escrowHoldsExactly(legIndex));
        require(tx.daa >= earliestDaa);
        require(deliversAsset(0, buyerDelivery, amountA));
        if (cashKind != EXTERNAL) { require(deliversCash(1, sellerProceeds, amountB)); }
        if (hasAuthority) { require(checkSig(authSig, authorityKey)); }
    }
    entrypoint function refund(sig s, pubkey signer) {
        require(signer == depositor || signer == counterparty || signer == authority);
        require(checkSig(s, signer));
        if (earmarked && signer == depositor) { require(tx.daa >= expiryDaa); }
        require(returnsWholeLegTo(depositorRefund));
    }
}
```

The sketch is illustrative. Exact syntax, KCC-20 state decoding (the template-validation pattern used by `KCC20Minter`) and the lock-time builtins are fixed against the pinned silverscript version.

Fixed in I1 against silverscript v1.0.0 and rusty-kaspa a41a333 (measured in the engine; the engine tests under `tests/engine/` hold the method):

- **Escrowed KCC-20 input.** `OpInputCovenantId(i)` equals the leg's covenant ID, and `readInputStateWithTemplate(i, prefixLen, suffixLen, templateHash)` reads its state. That builtin also proves the input's UTXO is the P2SH of the redeem script it carries, so the state read is the state held. The vault then requires owner type script hash, owner equal to its own script hash, and amount equal to the leg amount.
- **KCC-20 delivery output.** An output is a P2SH hash, so its state cannot be decoded, only matched. `OpOutputCovenantId(k)` must equal the leg's covenant ID, and `validateOutputStateWithInputTemplate(k, expectedState, i, prefixLen, suffixLen, templateHash)` rebuilds the expected script from the template bytes carried by KCC-20 input `i` and compares it with output `k`. The template is identified by its hash together with its prefix and suffix lengths, hence those two terms fields.
- **Lock time.** `require(tx.daa >= x)` compiles to `OpCheckLockTimeVerify` in the DAA-score domain. The settle or refund transaction sets its lock time to at least `x` (a DAA score, below the timestamp threshold) and the spending vault input's sequence below the maximum, otherwise the engine refuses it. The node then includes a transaction with lock time `x` only in a block whose DAA score is above `x`, so the effective earliest settle is `earliest_daa + 1` and the depositor's earmarked refund opens at `expiry_daa + 1`. The builders, their layouts, the minimum KAS per leg and the refusal codes are in `spec/TRANSACTIONS.md`; the partially signed transaction format is in `spec/IPST.md`.

## Settlement transaction and lifecycle

A trade either settles in one transaction or each leg goes home whole. There is no third state and no on-chain record to clean up.

&#91;embedded content: vault-mode lifecycle · settle or refund\]

Funding needs no program call: each side makes an ordinary transfer to an address it derived itself from the terms.

### Canonical settle transaction

The positions are fixed, so one transaction settles exactly one trade.

| Position | Input | Output |
| --- | --- | --- |
| 0 | Asset-leg authorizer (KAS at the asset vault) | Asset to `buyer_delivery` |
| 1 | Cash-leg authorizer, or the KAS cash itself | Cash to `seller_proceeds` |
| 2 | Escrowed asset token (KCC-20) | Asset authorizer's KAS back to the seller |
| 3 | Escrowed cash token (KCC-20 cash only) | Cash authorizer's KAS back to the buyer (KCC-20 cash only) |
| 4 onward | Submitter's fee inputs (no covenant ID; 12 inputs in all at most) | Submitter's change |

How the layout varies by mode:

- **External cash:** positions 1 and 3 drop out.
- **Direct mode:** outputs 0 and 1 are the same, and the inputs are the parties' own UTXOs.
- **Fees:** always come from the submitter's inputs, never from a leg, so delivered amounts are exact.

## Settlement modes

v0.1 ships four modes on mainnet; only cross-chain waits for v0.2. Solana's program has one mode: escrow with a mandatory authority and both legs on-chain.

| Mode | Escrow | Who settles | Cash leg | New contract risk | Ships |
| --- | --- | --- | --- | --- | --- |
| Direct | None. Both parties sign one transaction that spends their own UTXOs: the seller's KCC-20 asset and the buyer's KAS or KCC-20 cash. | Whoever holds the fully signed transaction; can be routed through an authority | KAS or KCC-20 | None beyond KCC-20 | v0.1 |
| Vault, authority | ImpulseVault per leg | Settlement authority | KAS or KCC-20 | ImpulseVault | v0.1 |
| Vault, self-settling | ImpulseVault per leg, no authority | Anyone, once both legs are funded | KAS or KCC-20 | ImpulseVault | v0.1 |
| Vault, external cash | Asset vault only | Authority, after the off-chain payment is confirmed | RTGS or bank money | ImpulseVault | v0.1 |
| Cross-chain | Asset vault released on a hash preimage | Anyone holding the preimage | HTLC on another chain | Hashlock entry | v0.2 |

How each mode behaves:

- **Direct mode** is the zero-escrow path. The parties exchange an Impulse partially signed transaction (IPST), and atomicity comes from the single transaction.
  - Either party aborts by spending its own input elsewhere before broadcast.
  - It adds no escrow contract.
- **Funding mode** (revocable or earmarked) applies to every vault mode.
  - Earmarked is the institutional default: the depositor cannot withdraw before expiry, but the counterparty or authority can still send the leg home.
- **External cash** is how most institutions will settle until regulated cash tokens exist on Kaspa.
  - The trust in the cash leg sits with the authority, exactly as with a settlement agent today.

## Off-chain components

Five deliverables. Default builds are keyless: they build, verify and watch, and signing always happens where the key lives. The exception is opt-in: the impulse-core `threshold` feature and the `impulse frost` commands hold one FROST party's own share in a file that party names on its own machine (mode 0600), with signing nonces in process memory only.

| Component | What it does |
| --- | --- |
| `impulse-core` (Rust) | Builds and checks everything the other components use:\<br>- **Terms:** schema, canonical encoding, terms hash, per-leg redeem scripts and addresses.\<br>- **Transactions:** unsigned settle, refund and Direct transactions, per-input sighashes, signature verification and assembly. Extracted from the `warpcore-pvp` split flow.\<br>- **KCC-20 checks:** state encoding and template-hash checks. |
| `impulse-sdk` (TypeScript/WASM) | The same API for wallets, custodians and web apps. Built with wasm-bindgen on `impulse-core`. |
| `impulse` CLI | `terms new`, `address`, `verify`, `fund`, `settle build`, `refund build`, `ipst sign` (local key only), `submit`, `status`. |
| `impulse-watch` | Reference single-node watcher over wRPC:\<br>- reports funded, settled and refunded per trade as JSON events;\<br>- tracks acceptance through the virtual chain;\<br>- rebroadcasts a settle transaction that a reorg removed. |
| Test kit | Golden vectors (terms to hash to script to address) plus a test for every entry and every refusal path in the real Kaspa script engine.\<br>Also property tests on encoding. |

The verifier recomputes both addresses from the terms, so there is no stored record to check.

- **Before funding**, `impulse verify` recomputes both addresses from the terms. If an address doesn't match, there is nothing to fund.
- **After a spend**, it decodes the revealed redeem script and checks it against the published template hash.

The checks, their order and their codes, the KCC-20 token warnings and the transaction decoder are in `spec/VERIFY.md`.

An error catalogue (`spec/ERRORS.md`) lists the stable codes that the off-chain software returns for its refusals, so integrators can handle failures programmatically. The contract returns no codes; the catalogue lists its refusals by tag. Solana's program declares 24 error codes.

## Head-to-head with Solana DvP

Impulse v0.1 differs from the Solana program in the design properties compared in the table below, and PARITY.md traces each row. Each row is traced in PARITY.md to a parity test or a cited line of the pinned program, and the rows that cannot be are marked.

| Capability | Solana DvP | Impulse v0.1 |
| --- | --- | --- |
| Atomic single-transaction settlement | Yes | Yes |
| Fund with a plain transfer, no program call | Yes | Yes |
| Escrow address bound to the terms | No: terms stored in the account, create is permissionless | Yes: address is the P2SH of the terms |
| Verification before funding | Mandatory, using checked helpers | Recompute the address; a mismatch means nothing to fund |
| Late deposits | Recover instruction plus a permanent tombstone | Ordinary refund, no state |
| Dust or over-deposit | Forces a surplus refund; a missing account reverts settle | Ignored by settle, refundable; an under-funded authorizer or carrier is topped up by the settler |
| Earmarked (irrevocable) funding | No | Yes |
| Settlement without an authority | No | Yes (self-settling and Direct modes) |
| Zero-escrow mode | No | Yes (Direct) |
| Authority can redirect proceeds | No | No: outputs enforced by script |
| Off-chain cash leg | No | Yes (external cash) |
| Cross-chain leg | No | v0.2 (hashlock) |
| Earliest and expiry gates | Cluster time; the README advises budgeting about 60 s of drift | DAA-score lock time; settle-after-expiry is policy (see red team) |
| Rent and account lifecycle | Creator pays, closer collects | None |
| Custodian multisig as a party | Rejected; must route through a smart wallet | Native P2SH or KCC-20 script owner as a destination (delivery, proceeds, refund); v1 builders fund and pay fees from key-owned UTXOs only |
| Program upgrade authority to trust | Program-level deployment | None: each trade is its own script from a hash-pinned template |
| On mainnet | Its README calls the declared program ID a placeholder; an executable program account was measured at the declared ID on 2026-10-07 | Yes, with a default per-trade value cap and a risk notice |
| Trade reference | 64-byte opaque string | 32-byte reference inside the terms hash |
| Clients | Rust, TypeScript | Rust, TypeScript/WASM, CLI, watcher |
| Licence | MIT | Apache-2.0 |
| Path to a full lifecycle | Not in the repository's scope | WarpCore: ISO 20022, compliance, CSDR, GL |

## Release sequence and gates

Impulse goes to mainnet at v0.1, with a default per-trade value cap and a risk notice.

&#91;embedded content: release sequence · 5 phases, 4 gates\]

The sequence is fixed and no dates are published. Each phase starts only when the gate above it is met.

## Licensing, IP and governance

Impulse is released under Apache-2.0. Impulse is a KiiLabs product. The design is defensively published through KGPR before the repository goes public.

- **Ownership.** Impulse is a KiiLabs product (the vehicle ruling, settled 2026-10-06).
  - Open-sourcing Impulse is a licence grant, not a transfer of ownership.
  - Stewardship of the specification by the Kii Foundation remains an option later.
- **Licence.** Apache-2.0 over MIT. It carries an explicit patent grant and a patent retaliation clause.
  - It is compatible with the ISC-licensed rusty-kaspa and silverscript dependencies.
- **Defensive publication.** Publish the ImpulseVault design (terms-bound vault addresses, the authorizer-plus-script-owned-token escrow, fixed authorizer indices) through KGPR first, so no third party can patent it.
- **Clean extraction.** Only the `warpcore-pvp` signing flow, `consensus_lock` and the template-instantiation pattern move across.
  - Run gitleaks, review licences, and strip all WarpCore configuration and test data.
- **Contributions.** Use a contributor licence agreement, so KiiLabs can keep shipping the commercial lifecycle products on top of community changes.
- **Template versioning.** A template is immutable once published. A change means a new version with a new hash, and old versions stay valid for trades already funded.
- **Security.** SECURITY.md, a disclosure address, and a bug bounty.
- **Hard rule.** No Impulse component holds or transmits private keys.

## Red team

No CRITICAL risk remains open. The one found during drafting (the asset leg could not be escrowed under KTT v0.2) is resolved by building on KCC-20. Four HIGH risks are resolved in this design or carried as open questions.

| Risk | Area | Rating | Resolution |
| --- | --- | --- | --- |
| KTT v0.2 has key-only ownership, fixed output 0 and has not been deployed, so a token cannot sit in a vault | Technical | CRITICAL, resolved | Build legs on KCC-20, which supports script-hash and covenant-ID owners and binds outputs by covenant ID |
| KCC-20 is a published example and proposal, not a ratified standard, and may change | Technical | HIGH, flagged | Pin the template by commit and hash, and verify the hash on every leg. Ask the core team about ratification plans (open question) |
| A contract holding value on mainnet; a loss in the first release damages WarpCore's name | Commercial, technical | HIGH, resolved | A risk notice in the README and release notes. SDK default per-trade value cap, overridable. Direct mode adds no escrow contract. One-template contract |
| One cash payment satisfying two trades (double satisfaction) | Technical | HIGH, resolved | Authorizers must sit at inputs 0 and 1, so one transaction settles one trade. Trades with identical outputs complete each other's exchange, so nobody loses |
| Cross-trade mixing: the asset vault of one trade and the cash vault of another settle together when their delivery terms (destinations, amounts, covenants) match, for example a repeat trade between the same parties | Technical | Closed (I26) | Each vault requires its own trade's other vault in a settle (settle rule 10, `[S10]`), so vaults of two trades never settle together. Pinned by an engine test (`foreign_covenant_residual::s10_cross_trade_mixing_is_refused`) |
| Whoever runs the authority may be operating a securities settlement system (CSDR, DLT Pilot Regime) | Regulatory | HIGH, flagged | Impulse is software, not a service. The README states that operators carry their own authorisation. Make no compliance claims |
| Public claims that cannot be verified (speed, finality, superiority claims over another program) | Legal, reputational | MEDIUM, resolved | Compare design properties only, each checkable from both public repos. No performance or finality numbers without measured evidence |
| Settle after expiry cannot be forbidden in script | Technical | MEDIUM, accepted | Authorities refuse past expiry and the SDK refuses to build such a transaction. The worst case is the agreed trade settling late |
| Revocable funding hands the counterparty a free option | Commercial | MEDIUM, partially mitigated | Earmarked mode, default for institutional profiles, blocks a depositor's own withdrawal before expiry (R3). It does not stop either party cancelling the other's leg: the counterparty's refund needs no lock time, so a party whose price has moved can send the other leg home at any time before expiry, at the cost of a fee and its own lock-up. Pinned by an engine test (`a3_earmarked_counterparty_cancels_the_other_leg_before_expiry`). The same refund races any settle already broadcast, since both spend vault input 0 |
| An authority-signed settle is a bearer instrument: the signature covers the outpoints and outputs, the contract has only a lower time bound (S3), and a signed settle stays valid after expiry. Example, external cash: the authority signs after seeing the off-chain payment, the buyer keeps the signed transaction, the payment is then reversed, and the authority cannot revoke the signature; it can only race its own refund, which the buyer pre-empts by broadcasting first | Operational | MEDIUM, accepted | No contract change (the template hash is fixed). Authorities sign only when the signing party will broadcast at once, keep the fee input under their own control (the signature binds the fee outpoints), and sign nothing before the off-chain payment is final (`docs/OPERATIONS.md`, `spec/THRESHOLD.md`) |
| Direct mode: a party can abort after signing by spending its input elsewhere | Operational | MEDIUM, accepted | Disclosed. Use vault mode when earmarking matters |
| Issuer powers on a token (minter branches, any extended-state freeze or clawback) can stall or move an escrowed leg | Technical | MEDIUM, resolved | `verify` refuses a token whose state goes beyond KCC-20's four fields, which the vault cannot settle or refund, and surfaces minter branches, issuer keys and templates outside the pinned kcc20.sil builds before funding; it does not present such a token as ordinary (`spec/VERIFY.md`) |
| A reorg removes a settle transaction | Technical | MEDIUM, resolved | The signed transaction stays valid; `impulse-watch` rebroadcasts it. Finality depth is the operator's parameter |
| Authority key compromise | Operational | MEDIUM, resolved | Outputs are script-enforced, so the worst case is liveness or an early settle of the agreed trade. Use threshold or HSM keys |
| Users must trust that the compiled template matches its source | Technical | MEDIUM, resolved | Reproducible silverc build, published template hash, `verify` checks it |
| Terms are revealed when a vault is spent | Competitive | MEDIUM, accepted | Terms are revealed when a vault is spent. Solana's program stores them in the trade account from Create. Commitments or ZK are later work |
| Toolchain churn (silverscript release candidate, rusty-kaspa versions) | Technical | MEDIUM, resolved | Pin versions; golden vectors catch drift |
| Storage mass on token carrier outputs | Technical | LOW, resolved | Carrier KAS travels with the token; the SDK validates minimum values |
| Name conflict on "WarpCore Impulse" | Legal | LOW, flagged | Quick clearance search before publication (open question) |

## Open questions

Eight owner decisions; the first three gate the start of build.

- [x] **Vehicle.** Settled 2026-10-06: Impulse is a KiiLabs product. Still open: whether the Kii Foundation stewards the specification later.
- [x] **Licence.** Settled: Apache-2.0 (LICENSE and Cargo.toml).
- [x] **KCC-20 pin.** Settled 2026-10-06: the silverscript v1.0.0 copy (commit `3ed9733`), consistent with the silverscript pin; `cd3857d` is an older ancestor with different kcc20.sil and kcc20-minter.sil. Still open: ask the Kaspa core team about ratification plans for KCC-01 and KCC-20.
- [ ] **KTT direction.** Rebuild KTT as KCC-20 plus KTT extended state, so Kii's compliance tokens settle through Impulse natively? Note (I6): the v1 vault reads and rebuilds the four-field KCC-20 state only, so a token with extended state cannot settle or refund through it, and `verify` refuses one (`VERIFY_TOKEN_EXTENDED_STATE`). Native settlement of KTT extended state needs a template change.
- [ ] **Self-settling mode.** Ship it in v0.1, or hold it back for regulatory optics?
- [x] **Value cap.** Settled (owner decision D4): 10 KAS equivalent per trade, lifted only by an explicit flag.
- [ ] **Name.** Is "WarpCore Impulse" cleared for use?
- [ ] **Messaging.** Name Solana in public comparisons, or describe the properties only?
