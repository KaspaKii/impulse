# Glossary

Terms as Impulse v0.1 uses them. Each entry points to the document that defines it. Where an entry and a spec differ, the spec is right.

**Asset leg.** The leg the seller delivers. In v0.1 it is always a KCC-20 token. Selling KAS for a token is expressed by swapping the buyer and seller roles. (`spec/IMPULSE-SPEC.md`)

**Authority.** The optional settlement authority named by `authority_key`. Its signature is required for `settle`, and it may sign refunds. It cannot redirect outputs, which the script fixes. May be one key or a FROST group. A trade with no authority is self-settling. (`spec/IMPULSE-SPEC.md`, `spec/THRESHOLD.md`)

**Authorizer.** The small KAS UTXO at a KCC-20 leg's vault address that carries the Impulse rules. The escrowed token can move only in a transaction that spends it, and it spends only if the rules hold. Its KAS returns to the depositor's key on settle and refund. (`spec/IMPULSE-SPEC.md`, "How a leg is escrowed")

**Canonical bytes.** The one byte encoding of terms that the terms hash covers. (`spec/ENCODING.md`)

**Canonical settle transaction.** The fixed input and output layout of a settle, so one transaction settles exactly one trade. (`spec/IMPULSE-SPEC.md`, `spec/TRANSACTIONS.md`)

**Cash leg.** The leg the buyer pays: native KAS, a KCC-20 token, or external (off chain). (`spec/IMPULSE-SPEC.md`)

**Counterparty.** For a leg, the party that is not its depositor. May trigger a refund of that leg; the refund still goes to the depositor. (`spec/IMPULSE-SPEC.md`, "Entries")

**Covenant ID.** The identifier of a KIP-20 covenant. A KCC-20 token's covenant ID identifies the token; Impulse binds each KCC-20 leg to one. (`spec/ENCODING.md`)

**DAA score.** Kaspa's difficulty-adjustment-algorithm score, used as the clock. `earliest_daa` and `expiry_daa` are DAA scores. A transaction locked at `x` enters a block from score `x + 1`. The nominal rate of 10 per second used in this documentation is a modelled figure, not a measured one. (`spec/TRANSACTIONS.md`)

**Depositor.** The party that funds a leg: the seller for the asset leg, the buyer for the cash leg.

**Direct mode.** A settlement mode with no escrow. Both parties sign one transaction spending their own UTXOs. Its refund is a cancellation after expiry. (`spec/IMPULSE-SPEC.md`, `spec/CLI.md`)

**Earmarked funding.** A funding mode in which the depositor cannot refund before `expiry_daa`. The counterparty and authority can still send the leg home. Vault modes only. (`spec/IMPULSE-SPEC.md`)

**Escrowed token.** The KCC-20 UTXO of exactly the leg amount whose owner is the vault's script hash. (`spec/IMPULSE-SPEC.md`)

**Expiry.** `expiry_daa`: a settle is refused at or after it; in earmarked mode the depositor's refund opens after it. At most about one year ahead at creation.

**External cash.** A cash leg paid off chain (RTGS or bank). Only the asset vault exists; the authority settles after confirming payment, which the script cannot check. (`spec/IMPULSE-SPEC.md`)

**Fee payer.** The party whose own UTXOs pay a transaction's fee. Fees never come from a leg. Signs with `--role payer`.

**FROST.** A threshold Schnorr signature scheme. Impulse uses it so a t-of-n group can act as one authority key. (`spec/THRESHOLD.md`)

**Funding mode.** Revocable or earmarked.

**Funding URI.** `<vault address>?amount=<sompi>&impulse=<terms_hash>`, printed for native KAS legs. (`spec/CLI.md`)

**Golden vectors.** Committed terms with their canonical bytes, hashes, scripts and addresses, checked by `scripts/vectors.sh`. (`tests/vectors`)

**Impulse.** This software: the template, core, CLI, SDK and watcher. Not a service, and it issues no asset.

**ImpulseVault.** The one contract template, with entries `settle` and `refund`. (`contracts/impulse_vault.sil`, `spec/TEMPLATE.md`)

**IPST.** Impulse partially signed transaction: the interchange format that carries an unsigned or partly signed transaction, its terms and sighashes between parties. Untrusted input until checked. (`spec/IPST.md`)

**KCC-20.** The fungible-token convention published with silverscript. (`spec/IMPULSE-SPEC.md`, "Why KCC-20")

**Leg.** One side of the trade, with an index (asset 0, cash 1), a kind, a token identity if any, and an exact amount.

**Mode.** One of Direct, Vault with authority, Vault self-settling, Vault with external cash.

**Nonce.** Random 64-bit value in the terms that distinguishes repeat trades between the same parties.

**Pin (destination pin).** A destination you tell the CLI to expect (`--my-delivery`, `--my-proceeds`, `--my-refund`), used when your destination is a custodian's script rather than your own key. (`spec/CLI.md`)

**Pinned KCC-20 template.** A kcc20.sil build from silverscript v1.0.0, listed in `crates/impulse-core/src/verify/pins.rs`. Only these are funded. (`spec/VERIFY.md`)

**Receipt.** A signer's BIP-340 assertion that a transaction was accepted at a depth, made by `impulse status --key-file`. (`spec/CLI.md`)

**Redeem script.** The vault script revealed when a vault is spent: template plus terms plus leg index. `impulse decode` reads terms back from it.

**Refund.** The vault entry that returns a leg whole to its depositor's refund destination. Stateless: it works for any UTXO at the vault.

**Revocable funding.** The depositor may refund at any time.

**Role check.** The CLI and SDK check that your destinations pay you (or your pin) and not the counterparty or authority. (`spec/CLI.md`)

**Settle.** The vault entry, used in one transaction spending both vaults, that pays each side the agreed leg.

**Self-settling.** A vault trade with no authority; anyone can settle once both legs are funded.

**Sighash.** The digest a signature covers. It commits to the amount and script of the UTXO spent, so a node that lies about a UTXO cannot redirect a signature.

**sompi.** The smallest KAS unit; 100,000,000 sompi = 1 KAS.

**Template hash.** Hash of the compiled template, pinned in `contracts/TEMPLATE_HASH`. For a KCC-20 leg, also the hash identifying the token's template in the terms.

**Terms.** All economic facts of a trade: parties, legs, destinations, times, funding mode, nonce, trade reference. (`spec/ENCODING.md`)

**Terms hash.** blake2b-256 keyed with `Impulse/terms/v1` over the canonical bytes. Names the trade; the vault addresses commit to it.

**Trade reference.** `trade_ref`: 32 opaque bytes (for example a hash of ISIN, trade ID and settlement date). The contract does not interpret it.

**Value cap.** Per-trade limit enforced by the CLI, SDK and demo: default 10 KAS. (`spec/CLI.md`)

**Vault.** A leg's escrow: the template instantiated with the terms and the leg index, at a pay-to-script-hash address.

**Watcher.** `impulse-watch`: reports per-leg events from a node's virtual chain. Holds no key. (`spec/WATCH.md`)
