# User guide

Task-oriented instructions for the `impulse` command line. The authoritative definition of every command, flag and refusal is `spec/CLI.md`; this guide shows the order to run them in. If they differ, the spec is right. Terms are explained in `docs/GLOSSARY.md`, the parts in `docs/ARCHITECTURE.md`.

Use only values you can lose.

## Before you start

Rules that hold for every task:

- **Testnet unless you say otherwise.** Every command acts on testnet unless you pass `--network mainnet`. There is no configuration file or environment variable that selects mainnet.
- **No key leaves your machine.** Signing happens only through `--key-file <path>`, a file you name: 64 hex digits, mode 0600 on Unix. Impulse never generates, stores or transmits a key for you (the opt-in FROST share file is the one exception, see "FROST authority").
- **Start in Direct mode and with the smallest value that exercises your flow.** Direct mode adds no escrow contract.
- **Mainnet transactions are the key holder's.** Nothing here asks anyone else or a service to sign or submit on your behalf.

Install (from a tagged commit; the toolchain is pinned to Rust 1.94.0):

```
cargo build --locked --release -p impulse-cli -p impulse-watch
install -m 0755 target/release/impulse target/release/impulse-watch /usr/local/bin/
impulse --version
```

You need a Kaspa node you trust, reachable as `ws://` or `wss://` wRPC (Borsh), with the UTXO index enabled (`kaspad --utxoindex`) for the builders. There is no default node. On mainnet the URL must be `wss://`, or `ws://` to a loopback host. `docs/OPERATIONS.md` section 2 covers running one. Check the connection:

```
impulse tip --node <url>          # network, sync state, virtual DAA score, sink
```

Two things are specific to v0.1:

- **The asset leg is always a KCC-20 token.** To trade native KAS against a token, make the token the asset leg and swap the buyer and seller roles. Native KAS against external cash is not supported.
- **Only pinned kcc20.sil builds are funded.** A leg whose token template is not one of the pinned builds is refused by `address`, `verify`, `fund build` and `ipst sign` (`CLI_TEMPLATE_UNPINNED`). `impulse token info --template <artifact>` shows a template's hash, lengths and whether it is pinned. On testnet only, `impulse token mint build` makes a test token (`spec/CLI.md`, "Token helper"); no command mints a mainnet token.

## Getting a key file

`impulse` has no command that generates a key. `impulse key` has one subcommand, `show`. You bring the key, and the CLI only reads it.

- **Format.** A regular file holding exactly 64 hex digits (a 32-byte secp256k1 secret key) and at most one final line feed. Anything else is `SIGN_KEY_FILE_FORMAT`.
- **Mode.** On Unix, no group or other access: `chmod 600 <file>`. Anything looser is `SIGN_KEY_FILE_PERMISSIONS`.
- **Source.** Use a key you generated yourself, on your own machine, with a tool you trust. For a throwaway testnet key, a shell on a trusted machine is enough:

```
( umask 077; openssl rand -hex 32 > buyer.key )
impulse key show --key-file buyer.key
```

  `key show` prints the x-only public key and P2PK address, which is what `--my-key` and the terms take. Keep the file out of version control and never paste its content into a chat, ticket or issue. For mainnet, use a key you hold under your own custody policy.
- **Authority groups.** A FROST authority does not use a key file. `impulse frost keygen` writes each party's share file (see "FROST authority").

## 1. Create terms

Terms are agreed off chain. One party writes a draft; both check the result.

1. Write a draft: a JSON object in the JSON form of terms (`spec/ENCODING.md`), every key present. Only `nonce` may be absent or `null`, in which case the CLI draws it from the operating system's random source. Worked examples are in `tests/vectors/terms/`. u64 values are decimal strings, byte arrays lowercase hex.
2. Create the terms file:

```
impulse terms new --draft draft.json --out terms.json --node <url> \
  --role buyer|seller --my-key <your x-only public key> (--kas-equivalent <sompi> | --i-accept-the-risk)
```

`terms new` runs the role check and the value cap (sections 2 and 8) before it writes anything, so it needs your side and public key and a value declaration. On testnet you may give `--daa <score>` instead of `--node`. On mainnet a typed score is refused (`CLI_MAINNET_NEEDS_NODE`).

The terms file holds `terms`, `canonical` (the canonical bytes) and `terms_hash`. Send the file to the counterparty. Both of you must see the same `terms_hash`; compare it over a second channel.

Choices that matter when drafting:

| Field | Guidance |
| --- | --- |
| `settlement_mode` | `direct` or `vault`. A vault with no `authority_key` is self-settling; with one, it is authority-settled; external cash needs an authority. |
| `funding_mode` | `revocable`: the depositor can refund at any time. `earmarked`: the depositor cannot refund before `expiry_daa`; the counterparty or authority can still send the leg home. Direct terms must be revocable. |
| `expiry_daa` | Must be after the current DAA score and within 315,360,000 DAA scores (365 days at 10 per second, modelled from the nominal rate, not measured). A settle is refused at or after it. |
| `earliest_daa` | Optional. Settle not before. If present it must be nonzero and not after the expiry. |
| Destinations | Where each side is paid and where each leg goes home. Use addresses you control. A destination that pays the counterparty's key or the authority's is refused by the role check. |
| KAS cash leg | At least 0.5 KAS (50,000,000 sompi); a smaller cash leg has no standard settle and is refused before funding (`CLI_KAS_LEG_BELOW_MIN`). A KCC-20 leg locks at least 2.5 KAS of carrier and authorizer (`spec/TRANSACTIONS.md`, "Minimum KAS per leg"). |

## 2. Verify before you fund

Never fund an address someone else gave you. Derive it yourself from the terms:

```
impulse address --terms terms.json --node <url> --role buyer --my-key <your x-only public key> \
  [--my-delivery <dest>] [--my-proceeds <dest>] [--my-refund <dest>] \
  (--kas-equivalent <sompi> | --i-accept-the-risk)
```

`--role` and `--my-key` are required and are public information; the CLI never takes a private key here. Before it prints any address it:

1. prints the terms hash, network and trade reference, and a decoded summary of every field;
2. runs the role check: your key is the role's key in the terms, and each of your destinations pays you (or equals the pin you gave). A destination that pays the counterparty or the authority is refused (`CLI_DESTINATION_NOT_MINE`);
3. labels each vault with who funds it. It prints funding instructions only for the vault your role funds.

For a native KAS leg it prints a funding URI and QR code:

```
<vault address>?amount=<sompi>&impulse=<terms_hash>
```

To check a URI someone sent you against the terms:

```
impulse verify --terms terms.json --uri '<uri>' --node <url> --role buyer --my-key <hex> (--kas-equivalent <sompi> | --i-accept-the-risk)
```

It stops at the first refusal: malformed URI, wrong terms hash, address not one of the terms' vaults, leg not native KAS, wrong amount, role check, wrong party's leg (`CLI_URI_NOT_YOUR_LEG`), value cap. If an address does not match, there is nothing to fund.

## 3. Fund

Each depositor funds its own leg: the seller the asset vault, the buyer the cash vault. Funding is an ordinary transaction built by the CLI, signed by you, submitted to a node.

```
# 1. build the unsigned funding IPST
impulse fund build --terms terms.json --leg cash --node <url> --role buyer --my-key <hex> \
  --pay-from <your P2PK address> (--kas-equivalent <sompi> | --i-accept-the-risk) --out fund-cash.ipst

# 2. sign it with a key file you hold
impulse ipst sign --ipst fund-cash.ipst --terms terms.json --key-file <path> --role buyer \
  --my-key <hex> --node <url> (--kas-equivalent <sompi> | --i-accept-the-risk) --out fund-cash.signed.ipst

# 3. submit
impulse submit --ipst fund-cash.signed.ipst --node <url>
```

Notes:

- A **KAS leg** is one output of exactly the leg amount at the vault. Fees come from `--pay-from`, never from the leg.
- A **KCC-20 leg** is two UTXOs created together: the escrowed token (exactly the leg amount) and a small KAS authorizer. Pass `--token <txid>:<index>:<amount>` for the token UTXOs you hold, `--asset-template` or `--cash-template` for the token's silverc artifact, and optionally `--carrier` and `--authorizer`. The CLI prints a `token change` line if token change is returned to you. A browser cannot make this funding; use the CLI.
- `ipst sign` re-checks everything before it signs: that the IPST is for the terms you named, that it is exactly the transaction the builders make, that you are the leg's depositor (`CLI_FUND_NOT_YOUR_LEG` otherwise), the value cap, and that the fee and change are bounded (`--max-fee`, `--change`). It prints `you commit:` with the outflow it is about to sign.
- Do not fund a leg twice, and do not send anything to a vault address other than the funding transaction the CLI builds. Only an exact UTXO can settle; any other amount at a vault can only be refunded.
- **Send each leg only to its own vault address.** Every template (v1, v2, v3, hashlock, v4) refuses any settle or refund that also moves a token of another covenant, and every settle requires the other leg's vault beside this one, so a token sent to the wrong vault address, the other leg's token included, cannot be taken by whoever spends that vault; it cannot be moved by anyone at all, so it is lost (known limitation L20, closed; spec/TRANSACTIONS.md, docs/security/KNOWN-LIMITATIONS.md L20). The tools do not warn about such a token: the warnings `TOKEN_FOREIGN_AT_VAULT` and `WATCH_FOREIGN_TOKEN` are retired.
- **A settle or refund of a vault has at most 12 inputs** (a basket settle N + 18; template v4: 8, refused as `ZK_H_SHAPE`). If your fee address holds many small UTXOs, the builder stops at the bound with `TX_TOO_MANY_INPUTS`: send them to one address of yours first, or pay from another address.
- **Never fund the cash vault script of external-cash terms.** Impulse gives no address for it and builds no recovery (`WATCH_STRAY_DEPOSIT` flags such a deposit).

To confirm a transaction is accepted, use the block `submit` prints:

```
impulse status --node <url> --terms terms.json --txid <txid> --from-block <block>
```

It reports the accepting block, its DAA score and the depth in DAA scores. Depth is a distance, not a count of confirmations; choose your own threshold.

## 4. Settle (vault trades)

Once both legs are funded and `earliest_daa` has passed, a settle can be built by anyone: there is no role.

```
impulse settle build --terms terms.json --node <url> --pay-from <fee payer P2PK address> \
  --asset-template <file> [--cash-template <file>] \
  (--kas-equivalent <sompi> | --i-accept-the-risk) --out settle.ipst
```

The CLI finds the vault UTXOs on the node and refuses (`CLI_UTXO_NOT_FOUND`, naming what it looked for) if a leg is not funded. The fee payer's UTXOs pay the fee. If a counterparty funded an authorizer below the minimum KAS, the settler tops up the difference and the output says so (`payer cost beyond the fee`).

Signatures needed:

| Mode | Who signs |
| --- | --- |
| Self-settling | The fee payer only (`--role payer`). The vaults need no signature. |
| Authority | The authority signs each vault input (`--role authority`), and the fee payer signs its own input. |
| External cash | As authority mode, and the authority's signature attests that the off-chain payment arrived. The script cannot check it. |

Each signer runs `ipst sign` on its own copy, then anyone merges and submits:

```
impulse ipst sign  --ipst settle.ipst --terms terms.json --key-file <path> --role authority --my-key <hex> \
                   --node <url> --asset-template <file> (--kas-equivalent <sompi> | --i-accept-the-risk) --out settle.a.ipst
impulse ipst merge --ipst settle.a.ipst settle.p.ipst --node <url> --asset-template <file> --out settle.signed.ipst
impulse submit     --ipst settle.signed.ipst --node <url> --asset-template <file> --signed-tx-out settle.tx
```

`--signed-tx-out` writes the signed transaction so `impulse-watch run --keep-signed` can rebroadcast it after a reorg. Signing is randomised, so signing the same slot twice gives two different valid signatures, and merging both is `IPST_CONFLICT`.

A settle delivers exactly the agreed amounts to the agreed destinations; nobody, the settler and the authority included, can change them. Read the transaction lines the CLI prints (`input`, `output`, `fee`, `pending`) before you sign.

## 5. Refund

Every refund sends a leg to its depositor's refund destination as named in the terms.

```
impulse refund build --terms terms.json --leg asset --signer depositor|counterparty|authority \
  --node <url> --pay-from <address> --asset-template <file> \
  (--kas-equivalent <sompi> | --i-accept-the-risk) --out refund.ipst
```

Then `ipst sign`, `ipst merge` if there are several signers, and `submit`, as in section 4.

| Who | When | Notes |
| --- | --- | --- |
| Depositor | Revocable: any time. Earmarked: from `expiry_daa` (effective one DAA score later). | For a KCC-20 leg the default also returns the escrowed token. Only the depositor may pass `--without-token`, which sends the authorizer home alone and leaves the token owned by the vault's script hash; moving it later needs a new authorizer funded at the vault (`spec/TRANSACTIONS.md`). |
| Counterparty or authority | Any time | For a KCC-20 leg, must also spend the escrowed token, so the token and authorizer return together (`TX_REFUND_SIGNER` without it). |

If several UTXOs sit at a vault, name one with `--vault-utxo <txid>:<index>` (`CLI_UTXO_AMBIGUOUS` otherwise). Rebroadcasting a stuck refund or settle is not a refund; see `docs/OPERATIONS.md` section 6.

## 6. Direct mode

Direct mode escrows nothing. The seller's KCC-20 asset and the buyer's cash are spent together in one transaction, so atomicity comes from the single transaction. Either party aborts by spending its own input elsewhere before the transaction is broadcast.

```
# anyone builds
impulse settle build --terms direct-terms.json --node <url> --pay-from <address> --asset-template <file> \
  [--cash-template <file>] (--kas-equivalent <sompi> | --i-accept-the-risk) --out direct.ipst
# each party signs its own copy
impulse ipst sign --ipst direct.ipst --terms direct-terms.json --key-file <seller key> --role seller --my-key <hex> ...
impulse ipst sign --ipst direct.ipst --terms direct-terms.json --key-file <buyer key>  --role buyer  --my-key <hex> ...
# merge both copies, then submit
impulse ipst merge --ipst direct.seller.ipst direct.buyer.ipst --node <url> --asset-template <file> --out direct.signed.ipst
impulse submit --ipst direct.signed.ipst --node <url> --asset-template <file>
```

The builder looks for the seller's token at its own key (exactly the asset amount) and the buyer's cash as a UTXO of exactly the cash amount at the buyer's key; make sure both exist before building.

**Cancelling a Direct trade.** Direct terms have no refund entry. After the agreed expiry one party spends one of its own Direct inputs back to itself, which makes the Direct transaction unsubmittable. Only the buyer's KAS cash can be cancelled this way:

```
impulse direct cancel build --terms direct-terms.json --node <url> --role buyer --my-key <hex> \
  --for-ipst direct.signed.ipst (--kas-equivalent <sompi> | --i-accept-the-risk) --out cancel.ipst
```

Sign and submit as usual. It can be built and signed before the expiry, but the node takes it only into a block of DAA score `expiry_daa + 1` or later. Its input is named by `--for-ipst` or `--direct-input`; with several candidate UTXOs and neither, the CLI refuses (`CLI_CANCEL_INPUT_AMBIGUOUS`). A seller's token input, or a buyer's KCC-20 cash, cannot be cancelled this way (`CLI_CANCEL_INPUT_NOT_KAS`); rely on never signing the Direct transaction until you are ready to send it.

## 7. FROST authority

A settlement authority can be a t-of-n group with 2 <= t <= n. On chain it is one key and one signature, so vault and template are unchanged. No single share, and no group below the threshold, can settle. The group can still only settle the agreed trade or refund it home. Full protocol and the split between what is measured and what rests on the cryptography: `spec/THRESHOLD.md`.

**Each party's share is a secret key share.** `impulse frost keygen` writes it to the file you name with `--share-file`, created new, mode 0600, never printed, logged or sent. Keep it on your own machine and back it up yourself; losing more than n - t shares loses the authority for good (funded trades can still be refunded).

1. **Generate the key (once, all parties, each on its own machine).**

```
impulse frost keygen --threshold 2 --parties 3 --party <i> --dir <shared dir> \
  --share-file <path> --group-out group.json
```

The parties exchange `round1-*.frost` and `round2-*.frost` files in `--dir` by any channel. The command stops twice for out-of-band comparison: every party must report the same round-1 digest, then the same group fingerprint. Anything else is `FROST_NOT_CONFIRMED` and nothing is written. Put only an authority key whose fingerprint all parties hold into terms as `authority_key`.

2. **Sign a settle or refund (agreed signing set, each signer on its machine).**

```
impulse [--network mainnet] frost sign --share-file <path> --ipst settle.ipst --signers 1,2 \
  --terms terms.json --dir <shared dir> --asset-template <file> [--cash-template <file>] \
  --node <url> (--kas-equivalent <sompi> | --i-accept-the-risk)
```

The command prints the decoded terms, the transaction, every output and the fee, and only then writes its commitment and signature share. Read them: you are signing that exact transaction. A group key can be named as `authority_key` in terms its members never saw, which is why the terms hash must match `--terms` or `--terms-hash` (`FROST_TERMS_NOT_AGREED`).

3. **Aggregate (anyone holding the group file; no secret needed).**

```
impulse frost aggregate --group group.json --ipst settle.ipst --signers 1,2 --dir <shared dir> --out settle.auth.ipst
```

Then the fee payer signs its own input with `ipst sign --role payer`, and `ipst merge` and `submit` as in section 4. The group never signs a fee input.

If more than n - t parties are unavailable the authority cannot settle; legs still refund (in earmarked mode the depositor waits for expiry, the counterparty can refund at any time). Try the group on TN10 before any mainnet use.

## 8. Value cap

The CLI refuses to build, fund or sign a trade above a per-trade cap. Default: 10 KAS (1,000,000,000 sompi, owner decision D4). `IMPULSE_MAX_VALUE` (sompi, decimal) can only lower it; a value that does not parse or is above the default is `CLI_VALUE_CAP_INVALID`. Only `--i-accept-the-risk` lifts it.

Because the asset leg is always a KCC-20 token whose KAS value the CLI cannot know, the trade value is unknown unless you declare it: `--kas-equivalent <sompi>`, the KAS value of the larger leg. Nothing checks your figure. Without a declaration or the risk flag the command ends in `CLI_VALUE_UNKNOWN`; above the cap, `CLI_VALUE_CAP_EXCEEDED`. The cap is a guard against slips, not a guarantee against loss.

## 9. Verify a counterparty or a past trade

Before funding:

1. Recompute the terms hash and both addresses yourself (`impulse address`), and compare the hash with the counterparty's over a second channel.
2. Read the summary line by line. Check that `buyer_delivery`, `seller_proceeds` and both refund destinations are what you expect, that the authority key is the party you agreed, that the token's covenant ID, template and amounts are right, and the expiry gives you time.
3. Heed `TOKEN_UNASSESSED`: Impulse did not read the token's issuer powers. Impulse issues and assesses no token; an issuer's transfer restrictions stay your responsibility.

After the fact, a settlement reveals its own terms. Decode the redeem script a spend revealed, from a node you run:

```
impulse decode <txid> --node <url> --from-block <chain block at or before acceptance>
```

It shows each vault the transaction spent, the entry used, what was delivered or refunded and to whom, and the terms hash with the terms. A node keeps no index of transactions by ID, so the starting block is needed.

A signed settlement receipt (a signer's assertion that a transaction was accepted at a depth) is made with `impulse status ... --key-file <path> --min-depth <n> --out receipt.json` and checked with `impulse receipt verify`. A version 1 receipt binds the terms hash to the transaction ID only by the signer's assertion; use `decode` to see which trades a transaction really spends.

To watch a trade instead of polling: `impulse-watch run --network <net> --node <url> --finality-depth <N> --state <file> --trade terms.json` prints one JSON event per line (`funded`, `authorizer_seen`, `settled`, `refunded`, `final`, `reorg`). Events are per leg and are data from one node. Operation: `docs/OPERATIONS.md`; event meanings: `spec/WATCH.md`.

## 10. Browser demo and SDK

The static page in `demo/` derives and checks terms and addresses in a browser, and can build, sign (with in-page wallets whose keys exist only in that tab) and submit a Direct trade, a settle, a refund and the buyer's KAS cash funding. It cannot fund a KCC-20 leg. See `demo/README.md`. Programmatic use: `crates/impulse-wasm/npm/README.md`.

## Troubleshooting by error code

Integrators and scripts should match on the code, never the message. The full catalogue, with the layer that raises each code, is `spec/ERRORS.md`. The most frequent ones:

| Code | Meaning | What to do |
| --- | --- | --- |
| `CLI_MAINNET_NEEDS_NODE` | `--daa` given on mainnet | Use `--node`; a typed DAA score is accepted on testnet only. |
| `CLI_NODE_INSECURE` | Mainnet node URL is not `wss://` or loopback | Use `wss://`, or tunnel to `ws://localhost`. |
| `CLI_NODE_UNREACHABLE`, `CLI_NODE_RPC`, `CLI_NODE_NOT_SYNCED` | Node problem | Check the URL, that the node is synced and runs `--utxoindex`. |
| `CLI_NODE_NETWORK_MISMATCH`, `CLI_NETWORK_MISMATCH`, `TERMS_NETWORK_MISMATCH` | Terms, node and `--network` disagree | All three must name the same network. |
| `CLI_TEMPLATE_UNPINNED`, `CLI_TEMPLATE_MISSING` | Token template not a pinned kcc20.sil build / not supplied | Pass `--asset-template` / `--cash-template` for a pinned build (`impulse token info`). |
| `CLI_VALUE_UNKNOWN`, `CLI_VALUE_CAP_EXCEEDED`, `CLI_VALUE_CAP_INVALID` | Value cap | Declare `--kas-equivalent`, lower the trade, or fix `IMPULSE_MAX_VALUE`. |
| `CLI_ROLE_KEY_MISMATCH`, `CLI_DESTINATION_NOT_MINE`, `CLI_DESTINATION_PIN_INVALID` | Role check failed | Check `--role`, `--my-key` and your pins. A destination that pays the counterparty or authority is never accepted: renegotiate the terms. |
| `CLI_KAS_LEG_BELOW_MIN` | KAS cash leg under 0.5 KAS | Raise the amount in the terms. |
| `CLI_FUND_NOT_YOUR_LEG` | You are not the depositor of that leg | Seller funds the asset vault, buyer the cash vault. |
| `CLI_UTXO_NOT_FOUND`, `CLI_UTXO_AMBIGUOUS` | The node does not list a needed UTXO / several match | Wait for acceptance, check `--pay-from`, or name the UTXO (`--vault-utxo`, `--direct-input`). |
| `TX_EXPIRED` | The trade can no longer settle | Refund instead. |
| `CLI_TX_NOT_FINAL` | Lock time not yet reachable | Wait until the DAA score the CLI printed. |
| `TX_INSUFFICIENT_FUNDS`, `TX_BELOW_MIN_KAS`, `TX_FEE_TOO_LOW`, `TX_MASS` | Fee payer too small / output under minimum / fee under relay minimum / transaction too heavy | Fund `--pay-from`; give `--fee`; reduce inputs. |
| `TX_REFUND_SIGNER` | Role unavailable for this refund | Counterparty or authority refunds of a KCC-20 leg must spend the token; an authority refund needs an authority. |
| `TX_ESCROW_MISMATCH`, `TX_LEG_AMOUNT` | Escrowed token or UTXO is not exactly the vault's | A leg settles only from exactly the leg amount; refund it and fund again. |
| `CLI_IPST_TERMS_NOT_AGREED`, `IPST_TERMS_MISMATCH` | The IPST is for other terms, or is not the transaction the builders make | Do not sign. Ask the builder to rebuild, and compare terms hashes. |
| `CLI_IPST_FEE_TOO_HIGH`, `CLI_IPST_CHANGE_NOT_MINE`, `CLI_IPST_TOPUP_TOO_HIGH`, `CLI_IPST_OUTFLOW_TOO_HIGH` | Fee-payer protections in `ipst sign` | Read the transaction. Raise `--max-fee` or `--max-topup` only for a document you have read. |
| `CLI_IPST_NOTHING_TO_SIGN` | No unsigned slot is for `--my-key` | Wrong key or role, or already signed. |
| `IPST_CONFLICT`, `TX_SIGNATURE` | Merge of different documents / bad signature | Merge only copies of the same IPST. Signing is randomised: sign once per slot. |
| `CLI_OUTPUT_EXISTS` | Output path exists | Choose a new path; the CLI never overwrites. |
| `SIGN_KEY_FILE_PERMISSIONS`, `SIGN_KEY_FILE_FORMAT`, `SIGN_KEY_NOT_EXPECTED` | Key file problem | `chmod 600`; the file is 64 hex digits and one optional line feed; the key must be the role's key. |
| `SIGN_MAINNET_NOT_EXPLICIT` | Mainnet digest without `--network mainnet` | Pass it deliberately, on the command that signs. |
| `FROST_NOT_CONFIRMED`, `FROST_TERMS_NOT_AGREED`, `FROST_KEY_NOT_AUTHORITY` | FROST checks | Compare digests and fingerprints out of band; use the agreed terms; use the share of the terms' authority. |
| `THRESHOLD_TOO_FEW_SIGNERS` | Fewer commitments than the threshold | Add signers to `--signers`. |
| `CLI_CANCEL_NOT_DIRECT`, `CLI_CANCEL_INPUT_NOT_KAS` | Cancellation does not apply | Vault legs go home with `refund build`; token inputs are not cancelled this way. |
| `WATCH_FUNDING_NOT_EXACT` (event flag) | A deposit at a KAS vault is not the leg amount | It can only be refunded; it cannot settle. |
| `WATCH_STRAY_DEPOSIT` (event flag) | A deposit to the cash script of external-cash terms | Impulse builds no recovery for it. |

A code not in this table is in `spec/ERRORS.md`. For anything that looks like a defect, report it as `SECURITY.md` describes, with the code and the command, and without any key material.
