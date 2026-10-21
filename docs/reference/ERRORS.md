# Error index and remedies

This page is the user-facing index to [spec/ERRORS.md](../../spec/ERRORS.md), the single authoritative list of stable codes. It says, for each code, what to do about it. The meaning and the raising component of a code are in the spec; where this page and the spec differ, the spec is right.

## How errors reach you

- The CLI prints `impulse: CODE: detail` on stderr and exits with status 1; a usage error (a flag the parser rejects) exits with status 2. The watcher prints its codes the same way.
- The SDK throws an `Error` named `ImpulseError` with a `code` property. `nodeError: true` is set only when the node itself refused the very request (see [SDK.md](SDK.md#errors)).
- Match on the code, never on the message. A message may quote text a counterparty supplied, escaped to printable ASCII; escape it again for HTML or any other medium you display it in.
- Codes are append-only: a code on `main` is never renamed, reused or removed.
- Nothing is signed or sent when a code is returned. After a refusal of a submit, read the code before retrying: `CLI_NODE_TXID_MISMATCH` and `SDK_TXID_MISMATCH` mean the outcome at the node is unknown, not that nothing happened.

## Where to start

| You see | Do this |
| --- | --- |
| `*_VALUE_CAP_EXCEEDED`, `*_VALUE_UNKNOWN` | Value cap. Lower the trade, or declare a nonzero KAS equivalent (`--kas-equivalent`). `--i-accept-the-risk` lifts the cap; see [spec/CLI.md](../../spec/CLI.md), "Value cap" |
| `SIGN_MAINNET_NOT_EXPLICIT` | Mainnet is used only with `--network mainnet`, passed explicitly. Check you mean it |
| `SIGN_KEY_FILE_PERMISSIONS` | `chmod 600` the key file; the CLI refuses a file that group or others can read |
| `*_NODE_NOT_SYNCED`, `*_NODE_UNREACHABLE` | Wait for the node to sync, or fix the node URL and its wRPC JSON listener; see [OPERATIONS.md](../OPERATIONS.md) |
| `TERMS_*`, `TX_*`, `IPST_*` | The inputs are wrong, not the tool. Fix the terms or UTXOs; the tables below say which |

## Families

Each section below lists every code of one family, in the order of the spec. The family names link to the spec's table.

| Family | Spec table | Component |
| --- | --- | --- |
| `TERMS_` | [TERMS_ codes](../../spec/ERRORS.md#terms_-codes) | Terms decoding, structure and creation checks |
| `TEMPLATE_` | [TEMPLATE_ codes](../../spec/ERRORS.md#template_-codes) | Vault template and scripts |
| `TX_`, `IPST_` | [TX_ and IPST_ codes](../../spec/ERRORS.md#tx_-and-ipst_-codes) | Transaction builders and IPST files |
| `VERIFY_`, `DECODE_`, `TOKEN_` | [VERIFY_ codes](../../spec/ERRORS.md#verify_-codes) | Verifier and decoder |
| `CLI_`, `SIGN_`, `RECEIPT_` | [CLI_ codes](../../spec/ERRORS.md#cli_-codes) | The `impulse` command line |
| `WATCH_` | [WATCH_ codes](../../spec/ERRORS.md#watch_-codes) | `impulse-watch` |
| `SDK_` | [SDK_ codes](../../spec/ERRORS.md#sdk_-codes) | TypeScript and WASM SDK |
| `THRESHOLD_`, `FROST_` | [THRESHOLD_ codes](../../spec/ERRORS.md#threshold_-codes) | FROST threshold authority |
| `ZK_` | [ZK_ codes](../../spec/ERRORS.md#zk_-codes) | List-gated settle, template v3 (cargo feature `zk`) |
| `ZK_H_` | [ZK_H_ codes](../../spec/ERRORS.md#zk_h_-codes) | Hashed-terms vault, template v4 (cargo feature `zk-hashed`) |
| `LINKED_` | [LINKED_ codes](../../spec/ERRORS.md#linked_-codes) | Linked trades: sheet, return gate, linked receipt (`impulse linked`) |
| `RELEASE_` | [RELEASE_ codes](../../spec/ERRORS.md#release_-codes) | Release pre-flight findings of the maintainers' tooling; not refusals |
| Contract tags | [On-chain refusals](../../spec/ERRORS.md#on-chain-refusals) | The contract returns no codes; see the end of this page |

## TERMS_ codes

Raised when terms are decoded, checked or created ([spec/ENCODING.md](../../spec/ENCODING.md)). The check never leaves your machine; fix the terms file and run it again.

| Code | Remedy |
| --- | --- |
| `TERMS_TRUNCATED`, `TERMS_TRAILING_BYTES`, `TERMS_INVALID_TAG`, `TERMS_INVALID_PRESENCE`, `TERMS_UNKNOWN_SETTLEMENT_MODE`, `TERMS_FIELD_TOO_LONG` | The canonical bytes are corrupt or not Impulse terms. Get the terms again from the counterparty, or regenerate them from the JSON form with `impulse terms new` |
| `TERMS_UNSUPPORTED_VERSION` | Only terms version 1 exists in v0.1. Use terms written by a v0.1 tool |
| `TERMS_INVALID_KEY` | A public key must be a valid x-only secp256k1 point, 64 lowercase hex digits. Recheck the key you were given |
| `TERMS_PARTIES_NOT_DISTINCT` | Buyer and seller must be different keys |
| `TERMS_AUTHORITY_IS_PARTY` | The settlement authority must be a third key, not the seller or the buyer |
| `TERMS_ASSET_EXTERNAL`, `TERMS_ASSET_KIND_UNSUPPORTED` | The asset leg must be a KCC-20 token in v0.1; native KAS and external assets cannot be escrowed as the asset |
| `TERMS_EXTERNAL_WITHOUT_AUTHORITY` | External cash is attested by the authority: name an authority key |
| `TERMS_DIRECT_INCOMPATIBLE` | Direct mode takes neither external cash nor earmarked funding. Change the mode or the leg |
| `TERMS_AMOUNT_ZERO`, `TERMS_AMOUNT_OUT_OF_RANGE` | Set each leg amount above zero and within its kind's maximum |
| `TERMS_ZERO_IDENTIFIER` | A covenant ID, template hash, owner or script hash is all zero, which is never a real value. Fill it in |
| `TERMS_TEMPLATE_LENGTH` | Take the KCC-20 prefix and suffix lengths from the token's artifact; neither may be zero |
| `TERMS_DESTINATION_KIND` | A destination must match its leg: a Kaspa script for KAS, a `kcc20` owner for a token |
| `TERMS_NONSTANDARD_SCRIPT` | A KAS destination must be a standard version-0 script (an ordinary address) |
| `TERMS_EXPIRY_NOT_DAA`, `TERMS_EARLIEST_NOT_DAA` | Times are DAA scores, not timestamps; use a value below the DAA lock-time threshold |
| `TERMS_EARLIEST_ZERO`, `TERMS_EARLIEST_AFTER_EXPIRY` | Omit `earliest_daa`, or set it above zero and not after the expiry |
| `TERMS_SAME_COVENANT` | The two legs must be different tokens |
| `TERMS_NETWORK_MISMATCH` | The terms name another network than the command acts on. Pass the matching `--network` or fix the terms |
| `TERMS_EXPIRY_NOT_AFTER_CREATION` | The expiry is already past. Read the current DAA score from your node (`impulse tip`) and set a later expiry |
| `TERMS_EXPIRY_BEYOND_HORIZON` | The expiry is further away than the creation horizon. Choose a nearer expiry |

## TEMPLATE_ codes

Raised when a vault script is built or read ([spec/TEMPLATE.md](../../spec/TEMPLATE.md)).

| Code | Remedy |
| --- | --- |
| `TEMPLATE_ARTIFACT_INVALID`, `TEMPLATE_HASH_MISMATCH` | The embedded template does not match `contracts/TEMPLATE_HASH`. This is a build problem, not a user error: rebuild from a clean checkout (`scripts/build-template.sh`) or use a release artifact, and report it if it persists |
| `TEMPLATE_SAME_COVENANT` | Reserved, never returned. One token on both legs is refused as `TERMS_SAME_COVENANT`; use two different tokens |
| `TEMPLATE_LEG_INDEX` | A leg is 0 (asset) or 1 (cash) |
| `TEMPLATE_NO_VAULT` | These terms give this leg no vault: Direct terms have none, and external cash has no cash vault. Pick the other leg or mode |
| `TEMPLATE_NOT_IMPULSE_VAULT`, `TEMPLATE_STATE_MALFORMED`, `TEMPLATE_STATE_INVALID`, `TEMPLATE_NONCANONICAL` | The script is not an ImpulseVault instance of those terms. Do not fund or sign anything that uses it; ask the counterparty for the terms and derive the address yourself with `impulse address` |

## TX_ and IPST_ codes

Raised by the builders and the IPST reader ([spec/TRANSACTIONS.md](../../spec/TRANSACTIONS.md), [spec/IPST.md](../../spec/IPST.md)).

| Code | Remedy |
| --- | --- |
| `TX_WRONG_MODE` | The command does not apply to these terms or this leg: vault builders are for vault terms, `direct` for Direct terms |
| `TX_VAULT_MISMATCH` | The funding address is not the vault these terms give. Recompute it with `impulse address` |
| `TX_EXPIRED` | The trade can no longer settle before its expiry. For a vault trade, refund (`impulse refund build`); for a Direct trade, cancel (`impulse direct cancel build`) after the expiry |
| `TX_NOT_AT_VAULT`, `TX_ESCROW_MISMATCH`, `TX_LEG_AMOUNT` | A UTXO named for the vault is not what the terms require. Only a UTXO holding exactly the leg amount settles; re-read the vault's UTXOs from your node and name the right outpoints |
| `TX_TOKEN_TEMPLATE` | The KCC-20 artifact is not the template the terms name for that leg. Use the token publisher's reproducible build, not one the counterparty supplies |
| `TX_TOKEN_INPUT`, `TX_KAS_INPUT` | An input is not spendable here (wrong covenant or owner, or not a plain Schnorr P2PK UTXO). Choose another UTXO |
| `TX_DUPLICATE_INPUT` | The same outpoint was named twice |
| `TX_INSUFFICIENT_FUNDS` | The inputs do not cover outputs plus fee. Add a fee input |
| `TX_BELOW_MIN_KAS` | An output would be below the minimum. A KAS cash leg below the minimum has no standard settle: change the terms |
| `TX_MASS`, `TX_FEE_TOO_LOW` | The transaction is too heavy for standard relay, or the fee is under the minimum relay fee for its mass. Use fewer or larger inputs, or raise the fee |
| `TX_NONSTANDARD_CHANGE` | The change address must be a standard version-0 address of the network |
| `TX_REFUND_SIGNER` | The refund role is not available for these terms, for example an authority refund where there is no authority |
| `TX_SIGNATURE`, `TX_SIGNATURE_SLOT` | A signature must be 65 bytes (BIP-340 Schnorr plus SIG_HASH_ALL) and verify for its slot. Re-sign the current sighash |
| `TX_ENCODING`, `TX_UTXO_VALUE` | A value or state cannot be encoded, or a UTXO reports zero or an out-of-range amount. Re-read the UTXO from your node |
| `IPST_MALFORMED`, `IPST_UNSUPPORTED_VERSION`, `IPST_SIGHASH_MISMATCH` | The file is not a version 1 IPST, or was altered. Ask the sender for a fresh copy; do not edit IPST files by hand |
| `IPST_CONFLICT` | Two copies describe different transactions, or hold different signatures in one slot. Merge only copies of the same document |
| `IPST_TERMS_MISMATCH` | The document is not the transaction the builders make for its terms from its own inputs (a skimmed output, an extra fee input, other budgets). Do not sign it |
| `TX_TOO_MANY_INPUTS` | The transaction would have more inputs than a vault allows: 12 for a settle or refund, N + 18 for a basket settle. Pay the fee from fewer, larger UTXOs (send them to one address of yours first) |

## VERIFY_, DECODE_ and TOKEN_ codes

Raised by the verifier and decoder ([spec/VERIFY.md](../../spec/VERIFY.md)). A `VERIFY_` refusal before funding means do not fund.

| Code | Remedy |
| --- | --- |
| `VERIFY_ADDRESS_MALFORMED`, `VERIFY_ADDRESS_NETWORK`, `VERIFY_ADDRESS_MISMATCH` | The offered address is not a vault address of these terms. Do not pay it; derive the addresses yourself from the terms |
| `VERIFY_ADDRESS_MISSING`, `VERIFY_ADDRESS_UNEXPECTED` | An address was missing for a leg that has a vault, or given for one that has none. Check which legs the terms escrow |
| `VERIFY_LEGS_SWAPPED` | The address or script is the other leg's vault. Fund your own leg only |
| `VERIFY_TEMPLATE_MISMATCH`, `VERIFY_TERMS_MISMATCH` | The revealed script is not the published template, or is a vault of other terms. Treat the transaction as not yours |
| `VERIFY_TOKEN_LEG_KIND`, `VERIFY_TOKEN_ARTIFACT_INVALID`, `VERIFY_TOKEN_TEMPLATE_MISMATCH`, `VERIFY_TOKEN_NOT_KCC20` | The token evidence does not fit the leg. Take the artifact from the token publisher's reproducible build |
| `VERIFY_TOKEN_EXTENDED_STATE` | The token has state fields beyond KCC-20's four, which the vault cannot settle or refund. Do not trade it |
| `VERIFY_NOTHING_REVEALED`, `VERIFY_INPUT_NOT_VAULT` | The input reveals no vault script, or does not spend the vault's address. It is not a vault spend |
| `DECODE_TX_MALFORMED`, `DECODE_TX_ID_MISMATCH` | The raw transaction is damaged or its carried ID is wrong. Fetch it again from your node |
| `DECODE_ENTRY_UNKNOWN`, `DECODE_INPUT_NOT_VAULT` | An input calls no entry of the template or does not spend a vault address; it is reported, not read as a settle or refund |
| `DECODE_SIGSCRIPT_MALFORMED` | Reserved, never returned. An input whose signature script is not push only is no vault spend and is skipped by the decoder |
| `DECODE_NO_VAULT_INPUT` | No input of the transaction spends an Impulse vault |
| `DECODE_SPENT_COUNT` | Supply exactly one spent scriptPublicKey per input, as the node reports them |
| `TOKEN_UNASSESSED`, `TOKEN_ISSUER_UNKNOWN` | Warnings: no token evidence or issuer keys were supplied. Supply them if you want the check; an empty warning list is not a safety claim |
| `TOKEN_FOREIGN_AT_VAULT` | Retired: never raised from v0.4.0 on. Known limitation L20 is closed in every template, so a token sent to the wrong vault address cannot move, and nobody can recover it. Send each leg only to its own vault address |
| `TOKEN_MINTER_BRANCH`, `TOKEN_EXTRA_ENTRIES`, `TOKEN_PARTY_IS_ISSUER`, `TOKEN_TEMPLATE_UNPINNED` | Warnings, not refusals. Read each: the token can mint, declares extra entries, is issued by a party of the trade, or is not a pinned kcc20.sil build. Decide whether you accept that |

## CLI_ codes

Raised by the `impulse` command line ([spec/CLI.md](../../spec/CLI.md), [CLI.md](CLI.md)).

| Code | Remedy |
| --- | --- |
| `CLI_FILE_READ`, `CLI_FILE_WRITE` | Check the path and permissions. An input over its size cap is refused without being read whole: 16 MiB for a document (terms, draft, IPST, receipt, proof, template, manifest), 256 MiB for an owner list |
| `CLI_OUTPUT_EXISTS` | The CLI never overwrites. Choose a new output path or remove the old file yourself |
| `CLI_TERMS_JSON`, `CLI_TERMS_FILE_INCONSISTENT` | The draft or terms file is not valid, or its `terms`, `canonical` and `terms_hash` disagree. Regenerate it with `impulse terms new`; never edit the hash by hand |
| `CLI_NETWORK_MISMATCH` | The terms or receipt are for another network than `--network`. Testnet is the default; mainnet needs `--network mainnet` |
| `CLI_HEX` | Pass a 64-digit lowercase hex value |
| `CLI_URI_MALFORMED`, `CLI_URI_TERMS_HASH_MISMATCH`, `CLI_URI_ADDRESS_MISMATCH`, `CLI_URI_LEG_NOT_KAS`, `CLI_URI_AMOUNT_MISMATCH`, `CLI_URI_NOT_YOUR_LEG` | `impulse verify --uri` refused the funding URI at the check named. Do not pay it. Regenerate the URI yourself with `impulse address` |
| `CLI_VALUE_CAP_INVALID`, `CLI_VALUE_UNKNOWN`, `CLI_VALUE_CAP_EXCEEDED` | Value cap. `IMPULSE_MAX_VALUE` may only lower the cap; declare a nonzero `--kas-equivalent` for a token leg; or use a smaller trade |
| `CLI_NODE_URL_INVALID` | `--node` must be `ws://` or `wss://` |
| `CLI_NODE_INSECURE` | On mainnet, use `wss://`, or `ws://` to a loopback host only |
| `CLI_NODE_UNREACHABLE`, `CLI_NODE_RPC` | The node did not answer or answered wrongly. Check that it runs with the wRPC JSON listener and try again |
| `CLI_NODE_NETWORK_MISMATCH` | The node is on another network. Use a node of the network you act on |
| `CLI_NODE_NOT_SYNCED` | Wait until the node is synced |
| `CLI_NODE_TXID_MISMATCH` | The node returned a different transaction ID than submitted. Check the node's mempool and the chain before retrying |
| `CLI_TX_NOT_ACCEPTED` | Not accepted on the chain walked from `--from-block`. Wait, or widen the range |
| `CLI_TX_NOT_FINAL` | The transaction's lock time has not been reached. Submit after the DAA score it names |
| `CLI_QR` | The URI is too long for a QR code. Use the text URI |
| `CLI_ROLE_KEY_MISMATCH` | `--my-key` is not the terms' key for `--role`. Check the role and key |
| `CLI_DESTINATION_NOT_MINE`, `CLI_DESTINATION_PIN_INVALID` | A destination of your role does not pay you. Refuse these terms, or pin the destination you control with `--my-delivery`, `--my-proceeds` or `--my-refund` |
| `CLI_DEPTH_BELOW_MINIMUM` | The transaction is not yet `--min-depth` deep. Wait; nothing was signed |
| `CLI_MAINNET_NEEDS_NODE` | On mainnet the creation DAA score comes from `--node`, not `--daa` |
| `CLI_KAS_LEG_BELOW_MIN` | The KAS cash leg is under the minimum output and has no standard settle. Raise the amount |
| `CLI_TEMPLATE_UNPINNED`, `CLI_TOKEN_TEMPLATE_UNPINNED` | Only pinned kcc20.sil builds are funded, because the builders' budgets are measured for them. Use a pinned token or do not trade it |
| `CLI_TEMPLATE_MISSING` | Pass the token's artifact file the command needs |
| `CLI_FUND_NOT_YOUR_LEG` | Fund your own leg only; `--pay-from` must be the P2PK address of `--my-key` |
| `CLI_ADDRESS_INVALID`, `CLI_OUTPOINT_INVALID` | Fix the address (P2PK of the network, or a standard change address) or the `<txid>:<index>` form |
| `CLI_UTXO_NOT_FOUND` | The node does not hold that UTXO. It may be spent or not yet accepted; check with `impulse tip` and your node |
| `CLI_UTXO_AMBIGUOUS` | Several UTXOs at the vault. Name one with `--vault-utxo` |
| `CLI_IPST_NOTHING_TO_SIGN` | No unsigned slot is for your key. Check you hold the right document |
| `CLI_IPST_CHANGE_NOT_MINE` | The change does not pay `--change` or your key. Do not sign |
| `CLI_IPST_FEE_TOO_HIGH` | The fee exceeds `--max-fee` (default twice the minimum relay fee), or you sign more than three fee inputs without `--max-fee`. Do not sign unless you accept the fee, then pass `--max-fee` |
| `CLI_IPST_TOPUP_TOO_HIGH` | The fee inputs also fund trade outputs beyond `--max-topup` (default 0). Do not sign unless you accept the cost |
| `CLI_IPST_OUTFLOW_TOO_HIGH` | The inputs you sign take more of your KAS than the trade plus `--max-fee` and `--max-topup`. Do not sign |
| `CLI_IPST_TERMS_NOT_AGREED` | The IPST is for other terms than the ones you agreed. Pass your own `--terms` or `--terms-hash`; do not sign |
| `CLI_IPST_DEPOSIT_MISMATCH`, `CLI_TOKEN_CARRIER_MISMATCH` | The carrier or authorizer KAS differs from `--carrier` or `--authorizer`. Confirm the amounts, then pass them |
| `CLI_CANCEL_NOT_DIRECT` | Vault terms go home with `impulse refund build`, not `direct cancel build` |
| `CLI_CANCEL_INPUT_NOT_KAS` | A Direct input that is a token has no builder that spends it back |
| `CLI_CANCEL_INPUT_AMBIGUOUS`, `CLI_CANCEL_INPUT_MISMATCH` | Name the cash UTXO with `--for-ipst` or `--direct-input`, and make sure it is the buyer's exact cash amount |
| `CLI_TOKEN_TESTNET_ONLY` | The token helper acts on testnet only |
| `CLI_TOKEN_OWNER_INVALID`, `CLI_TOKEN_AMOUNT_INVALID` | `--owner` must be a valid x-only key; `--amount` must be above 0 and at most `i64::MAX` |

## SIGN_ codes

Raised by the single signing module of the CLI, which reads a key file you name and signs on your machine. Messages name the path and never the key.

| Code | Remedy |
| --- | --- |
| `SIGN_MAINNET_NOT_EXPLICIT` | The digest is for mainnet. Pass `--network mainnet` only if you intend to sign for mainnet |
| `SIGN_NETWORK_MISMATCH` | `--network mainnet` was passed for a testnet digest. Remove it or use the right document |
| `SIGN_KEY_FILE_UNREADABLE` | The path is wrong, unreadable, or not a regular file |
| `SIGN_KEY_FILE_PERMISSIONS` | Remove all group and other access: `chmod 600 <file>` |
| `SIGN_KEY_FILE_FORMAT` | The file must hold exactly 64 hex digits and at most one final line feed |
| `SIGN_KEY_INVALID` | The 32 bytes are not a valid secp256k1 secret key. Use a key file made by your own key tooling; `impulse key show --key-file <file>` prints its public key without printing the secret |
| `SIGN_KEY_NOT_EXPECTED` | This key is not the signer the slot needs. You may be using the wrong key file |
| `SIGN_SELF_CHECK_FAILED` | The signature did not verify before leaving the module. Nothing is output; report it with the command and the (non-secret) document |

## RECEIPT_ codes

Raised by `impulse receipt verify` ([spec/CLI.md](../../spec/CLI.md), "Settlement receipt"). It stops at the first refusal.

| Code | Remedy |
| --- | --- |
| `RECEIPT_MALFORMED` | The file is not a version 1 receipt. Get it again |
| `RECEIPT_SIGNATURE_INVALID`, `RECEIPT_SIGNER_MISMATCH` | The signature does not verify, or is by another signer than `--signer`. Do not rely on the receipt |
| `RECEIPT_DAA_MISMATCH`, `RECEIPT_NOT_ACCEPTED`, `RECEIPT_DEPTH_UNREACHED` | Your node disagrees with the receipt about acceptance. Wait for depth, or check that the node is synced and on the right network |
| `RECEIPT_TERMS_MISMATCH`, `RECEIPT_TXID_MISMATCH` | The receipt is for other terms or another transaction than you expected |

## WATCH_ codes

Raised by `impulse-watch` ([spec/WATCH.md](../../spec/WATCH.md)). The first table is refusals of a call; the second is flags on events and means look at this event, not that a call failed.

| Code | Remedy |
| --- | --- |
| `WATCH_NETWORK_MISMATCH`, `WATCH_NODE_NETWORK_MISMATCH`, `WATCH_STATE_MISMATCH` | Terms, node or state file belong to another network than `--network` |
| `WATCH_TRADE_DUPLICATE`, `WATCH_TRADE_UNKNOWN`, `WATCH_RETIRE_WATCHED`, `WATCH_TRADE_NOT_RESUMED` | Trade bookkeeping: add each terms file once, retire only trades the state holds, and add every trade of a resumed state again before polling |
| `WATCH_FINALITY_DEPTH_ZERO`, `WATCH_RETENTION_TOO_SHORT` | Finality depth must be above 0 and retention above the finality depth |
| `WATCH_STRAY_SCRIPT_UNDERIVABLE` | The external-cash vault script could not be derived; check the terms |
| `WATCH_TX_UNSIGNED`, `WATCH_TX_NOT_TRACKED`, `WATCH_TX_DUPLICATE`, `WATCH_SIGNED_TX_INVALID` | The signed-transaction file must be a fully signed transaction that settles or refunds a watched vault, kept once |
| `WATCH_SOURCE_FAILED`, `WATCH_NODE_UNREACHABLE`, `WATCH_NODE_RPC`, `WATCH_PROBE_FAILED` | The node failed or returned malformed data; nothing was applied. Run `impulse-watch probe` against the node and retry |
| `WATCH_NODE_URL_INVALID`, `WATCH_NODE_INSECURE`, `WATCH_NODE_NOT_SYNCED` | As the `CLI_NODE_*` codes: `ws://` or `wss://`; on mainnet `wss://` or loopback `ws://`; wait for sync |
| `WATCH_FILE_READ`, `WATCH_TERMS_FILE_INVALID`, `WATCH_TERMS_FILE_INCONSISTENT` | Fix the terms file; regenerate it with `impulse terms new` |
| `WATCH_STATE_INVALID`, `WATCH_STATE_WRITE_FAILED`, `WATCH_OUTPUT_FAILED` | The state file is unusable or could not be written, or the events could not be written to stdout (the round was not saved). Check the directory and disk; an existing state file is left untouched |
| `WATCH_STATE_LOCKED` | Another watcher holds the state file. Stop it first |
| `WATCH_STATE_MISSING`, `WATCH_STATE_EXISTS` | Pass `--init` to create a new state file; never pass it for an existing one |
| `WATCH_STRAY_DEPOSIT` | Event flag: a deposit to an external-cash vault script. Impulse has no recovery builder for it (decision D14) |
| `WATCH_FUNDING_NOT_EXACT` | Event flag: a UTXO at the vault is not the exact leg amount, and only an exact UTXO settles. See [spec/WATCH.md](../../spec/WATCH.md) |
| `WATCH_SPEND_UNCLASSIFIED` | Event flag: a vault UTXO was spent in a way the watcher cannot read as a settle or refund. Inspect it with `impulse decode` |
| `WATCH_REBROADCAST_FAILED`, `WATCH_REBROADCAST_ABANDONED`, `WATCH_REBROADCAST_PAST_EXPIRY` | Event flags on a kept transaction: retried after the next poll, given up, or skipped at or past the expiry |
| `WATCH_FOREIGN_TOKEN` | Retired: never raised from v0.4.0 on. Every template refuses a vault spend that also moves a token of a covenant that spend does not check |
| `WATCH_LINK_RETURN_EARLY` | Event flag on a `linked` event: a return vault is funded while the opening is not settled. The watcher reports it and does not block; check the sheet and the opening before you go on |
| `WATCH_FINAL_REORGED` | Event flag: an acceptance already reported final was reorganised. Treat the earlier report as void |

## SDK_ codes

Raised by the TypeScript and WASM SDK ([SDK.md](SDK.md), [package README](../../crates/impulse-wasm/npm/README.md)). impulse-core codes (`TERMS_*`, `TX_*` and the rest) pass through unchanged and keep the remedies above.

| Code | Remedy |
| --- | --- |
| `SDK_ARGUMENT_TYPE`, `SDK_JSON_FORM` | A call received a value of the wrong JavaScript type or a JSON form that breaks [spec/ENCODING.md](../../spec/ENCODING.md): u64 values are decimal strings, bytes are `Uint8Array`, no duplicate or unknown keys |
| `SDK_MAINNET_NEEDS_NODE` | On mainnet the creation DAA score must be read from a node and marked `creation_daa_source: "node"` |
| `SDK_VALUE_CAP_INVALID`, `SDK_VALUE_UNKNOWN`, `SDK_VALUE_CAP_EXCEEDED` | Pass a value declaration as the last argument; see [SDK.md](SDK.md#value-cap) |
| `SDK_QR` | The text does not fit a QR code |
| `SDK_TERMS_INCONSISTENT` | A terms document's `canonical` or `terms_hash` is not that of its `terms`, or two terms were to be equal and are not |
| `SDK_ROLE_KEY_MISMATCH`, `SDK_DESTINATION_NOT_MINE`, `SDK_DESTINATION_PIN_INVALID`, `SDK_DESTINATION_IN_WALLET` | The role check: your key is not the role's key, a destination does not pay you, a pin is invalid, or (mainnet) a destination pays a key that lives only in a page wallet. Do not fund or sign |
| `SDK_WALLET_WIPED`, `SDK_WALLET_RANDOM` | The wallet was wiped or freed and signs nothing, or the browser gave no randomness. Generate a new wallet |
| `SDK_SIGN_MAINNET_NOT_EXPLICIT`, `SDK_SIGN_NETWORK_MISMATCH` | Set `mainnet` in the sign options only for a mainnet document, and never for a testnet one |
| `SDK_SIGN_NOTHING_TO_SIGN`, `SDK_SIGN_SELF_CHECK_FAILED` | The wallet's key signs no pending input, or a signature failed its own check; nothing was signed |
| `SDK_SIGN_CHANGE_NOT_MINE`, `SDK_SIGN_FEE_TOO_HIGH`, `SDK_SIGN_TOPUP_TOO_HIGH`, `SDK_SIGN_OUTFLOW_TOO_HIGH`, `SDK_SIGN_DEPOSIT_MISMATCH` | The same checks as the matching `CLI_IPST_*` codes, with `change`, `max_fee`, `max_topup`, `carrier` and `authorizer` as the sign options. Do not sign unless you accept the cost |
| `SDK_NODE_URL_INVALID`, `SDK_NODE_INSECURE`, `SDK_NODE_NETWORK_MISMATCH`, `SDK_NODE_NOT_SYNCED` | As the `CLI_NODE_*` codes. The SDK allows loopback `ws://` to `127.0.0.1` and `localhost` only |
| `SDK_RPC_REPLY`, `SDK_RPC_NOT_FOUND`, `SDK_TXID_MISMATCH` | A node reply was unreadable, was an error, said not found, or named another transaction. Check `error.nodeError`: true means the node refused the request and nothing was taken |
| `SDK_UTXO_NOT_FOUND` | The node reported no UTXO the plan needs |
| `SDK_FUND_NOT_YOUR_LEG` | Only the terms' buyer key funds the cash leg through these builders |
| `SDK_TEMPLATE_UNPINNED` | Only pinned kcc20.sil builds are funded (`pinnedKcc20Templates()` lists them) |
| `SDK_FUND_ASSET_NOT_FUNDED` | The seller has not yet escrowed the token in the exact state the asset leg needs; the buyer's cash funding waits |
| `SDK_FUND_ALREADY_FUNDED` | The cash vault already holds the exact deposit; do not fund twice |

## THRESHOLD_ and FROST_ codes

Raised by `impulse frost` and the threshold module ([spec/THRESHOLD.md](../../spec/THRESHOLD.md)). Share files hold one party's own FROST share; keep them mode 0600 and never send them.

| Code | Remedy |
| --- | --- |
| `THRESHOLD_PARAMS`, `THRESHOLD_PARTY` | The threshold must be at least 2 and at most the number of parties; party numbers are 1 to n |
| `THRESHOLD_DKG_PACKAGES`, `THRESHOLD_ENCODING`, `FROST_FILE_MALFORMED` | A key-generation or signing file is missing, duplicated, or damaged. Collect exactly one file from every other party |
| `THRESHOLD_DKG_CULPRIT` | A party's proof or share failed verification; the message names the sender. Restart key generation without that party's data |
| `THRESHOLD_TOO_FEW_SIGNERS`, `THRESHOLD_SIGNER_NOT_IN_SET`, `THRESHOLD_SHARES_MISMATCH`, `FROST_SIGNERS_INVALID` | The signing set must hold at least the threshold of distinct parties and the shares must come from exactly that set |
| `THRESHOLD_SHARE_INVALID` | A signature share failed verification; the message names the parties. Ask them to sign again |
| `THRESHOLD_KEY_INVALID`, `THRESHOLD_SIGNATURE_INVALID`, `THRESHOLD_REFUSED`, `THRESHOLD_INPUT` | The authority key or signature is invalid, the FROST library refused, or the named input does not exist. Fail closed: start the signing round again |
| `FROST_SHARE_FILE_UNREADABLE`, `FROST_SHARE_FILE_PERMISSIONS`, `FROST_SHARE_FILE_FORMAT`, `FROST_FILE_PERMISSIONS` | The share file is unreadable, not 0600, or not a share file. Fix the permissions with `chmod 600` |
| `FROST_SESSION_MISMATCH` | A file belongs to another session or party set. Use files of one session only |
| `FROST_NOT_CONFIRMED`, `FROST_ABORTED` | The digest or fingerprint you typed back is not yours, or input ended. Compare it with the other parties out of band and run the step again |
| `FROST_NO_AUTHORITY_INPUT`, `FROST_KEY_NOT_AUTHORITY`, `FROST_AUTHORITY_INPUT_NOT_VAULT` | The IPST has no authority slot for these terms, the share's group key is not the terms' `authority_key`, or the slot does not spend a vault of the terms. Check the terms and the document |
| `FROST_ROUND2_NOT_REMOVED` | Key generation finished but a round-2 file addressed to you remains. Delete it yourself |
| `FROST_TERMS_NOT_AGREED` | Pass `--terms` or `--terms-hash` for the terms you agreed |

## v2 and hashlock codes

Codes of the multi-leg and partial-fill terms (version 2) and of the hashlock flow (`impulse xchain`). The spec table of each family holds the meaning; this table says what to do. The hashlock flow on mainnet runs under the per-trade value cap with race R2 disclosed (spec/V2.md sections 10.5 and 10.6).

| Code | Do this |
| --- | --- |
| `TERMS_V2_VERSION`, `TERMS_VERSION_UNKNOWN` | The file is not a version 2 terms file, or is of an unknown version. Check you passed the right file |
| `TERMS_LEG_COUNT`, `TERMS_LEGS_ONE_PARTY`, `TERMS_AUTHORITY_IS_DEPOSITOR`, `TERMS_LEG_KIND`, `TERMS_LEG_ORDER`, `TERMS_LEGS_SAME_COVENANT` | The legs of the terms break a structure rule of spec/V2.md. Fix the terms; the order is KAS legs first, then KCC-20 legs |
| `TERMS_PARTIAL_LOTS`, `TERMS_PARTIAL_INDIVISIBLE` | Lot count or minimum lot is invalid, or a leg amount does not divide into whole lots. Change the amounts or the lot count |
| `TEMPLATE_V2_ARTIFACT_INVALID`, `TEMPLATE_V2_HASH_MISMATCH` | The v2 template does not match its pinned hash. Rebuild from the pinned toolchain; do not use the build |
| `TEMPLATE_V2_LEG_INDEX`, `TEMPLATE_V2_NOT_VAULT`, `TEMPLATE_V2_STATE_MALFORMED`, `TEMPLATE_V2_STATE_INVALID`, `TEMPLATE_V2_NONCANONICAL` | The script or state offered is not a v2 vault of these terms. Do not fund or spend it |
| `TX_V2_NOT_AT_VAULT`, `TX_LEGS`, `TX_LINEAGE`, `TX_LEGS_OUT_OF_STEP` | The UTXOs offered do not form the trade: one vault UTXO per leg, escrows in step, one covenant lineage. Re-read the vault UTXOs from the node |
| `TX_TRANCHE`, `TX_V2_MASS` | Choose a whole number of lots within what every escrow holds and at or above the minimum lot; or reduce the legs so the transaction fits its mass cap |
| `IPST_V2_VERSION` | The IPST file has an unknown version |
| `VERIFY_V2_ADDRESS_MISMATCH`, `VERIFY_V2_WRONG_LEG`, `VERIFY_V2_TEMPLATE_MISMATCH` | The address or script does not belong to these terms (or belongs to another leg). Do not fund it |
| `RECEIPT_QUANTITY_MISSING`, `RECEIPT_QUANTITY_MISMATCH`, `RECEIPT_LINEAGE_MISMATCH` | The receipt's lot quantities or chain do not follow from the terms and the previous receipt. Ask for the earlier receipts |
| `HTLC_VERSION`, `HTLC_ASSET_KIND`, `HTLC_HASH_ZERO`, `HTLC_COUNTERPART` | The hashlock terms are malformed. Fix the terms |
| `HTLC_TIMEOUT_MARGIN`, `XCHAIN_MARGIN_TOO_SHORT` | Too little time between the counterpart timeout and the Kaspa expiry. Choose a later expiry |
| `HTLC_ARTIFACT_INVALID`, `HTLC_HASH_MISMATCH` | The hashlock template does not match its pinned hash. Rebuild from the pinned toolchain |
| `HTLC_NOT_HASHLOCK_VAULT`, `HTLC_STATE_MALFORMED`, `HTLC_STATE_INVALID`, `HTLC_NONCANONICAL` | The script or state is not a hashlock vault of these terms. Do not fund or spend it |
| `HTLC_SECRET_LENGTH`, `HTLC_SECRET_MISMATCH`, `XCHAIN_SECRET_FILE` | The secret is not the 32-byte preimage of the hash lock, or its file is wrong (64 hex digits, owner-only). Use the seller's own secret file |
| `HTLC_DAA_SAMPLE`, `XCHAIN_NODE_BPS` | The DAA rate sample is missing, old or taken at another rate. Take a fresh one with `impulse xchain daa-sample` |
| `HTLC_MAINNET_GATED`, `XCHAIN_MAINNET_GATED` | Reserved, no longer returned: the mainnet gate was lifted by D39 (b) and D40. Nothing to do |
| `HTLC_FUNDING` | The funding transaction does not fund the vault with the exact token amount. Do not treat the trade as funded |
| `XCHAIN_CHAIN_UNSUPPORTED` | The counterpart chain has no source in this build |
| `XCHAIN_COUNTERPART_MISMATCH` | The counterpart lock differs from the record, is unfunded, or its escrow is frozen. Do not proceed or reveal |
| `XCHAIN_NOT_FINAL` | Wait for the required finality and run the command again |
| `XCHAIN_REVEAL_NOT_FOUND` | No claim revealing the secret yet. Keep watching; do not guess |
| `XCHAIN_HASH_REUSED` | The hash lock was used before. Draw a fresh secret |
| `XCHAIN_TX_UNRELATED` | The transaction is not part of this trade. Check the transaction id |

## ZK_ codes

Raised by the list-gated settle, template v3 (`impulse zk ...`, [spec/V3-ZK.md](../../spec/V3-ZK.md)). They exist only in a build with the `zk` feature. Nothing is signed or sent when one is returned.

| Code | Remedy |
| --- | --- |
| `ZK_TERMS_VERSION`, `ZK_TERMS_DIRECT`, `ZK_DELIVERY_OWNER_TYPE`, `ZK_ROOT_INVALID`, `ZK_ISSUER_KEY` | The terms v3 are not valid terms v3: another version byte, Direct settlement, a buyer delivery owner that is not a public key or a script hash, a list root that is zero or the empty tree's, or an issuer key that is not a valid x-only key. Correct the draft and run `impulse zk terms new` again |
| `ZK_AUTHORITY_ABSENT` | Terms v3 without an authority need `--no-authority`. Without one, removal from the list after the terms were made cannot stop the settle. Name an authority, or pass the flag knowing that |
| `ZK_ARTIFACT_INVALID`, `ZK_TEMPLATE_HASH_MISMATCH`, `ZK_IMAGE_ID_MISMATCH` | This build's template v3 or its pinned image ID is damaged or not the pinned one. Do not use the build: reinstall from a release, or rebuild with `scripts/build-template.sh` and `scripts/build-guest.sh` and compare |
| `ZK_NOT_V3_VAULT`, `ZK_STATE_MALFORMED`, `ZK_STATE_INVALID`, `ZK_NONCANONICAL`, `ZK_VERIFY_TEMPLATE_MISMATCH` | The script is not a template v3 vault of these terms. Do not fund it. Ask the counterparty for the address `impulse zk address` prints and check it with `impulse zk verify` |
| `ZK_VERIFY_ADDRESS_MISMATCH` | An offered address pays neither vault of these terms. Recompute both with `impulse zk address` and use those |
| `ZK_LIST_ENTRY`, `ZK_LIST_SIZE` | A list entry is not a Schnorr P2PK or P2SH address or owner of the network, or the list is empty or too long. Fix the list file |
| `ZK_NOT_MEMBER`, `ZK_PATH_INVALID` | The delivery owner is not in the list, or the path file does not lead from its salted leaf to the root in the terms. Ask the issuer for your own path file for this root |
| `ZK_MANIFEST_INVALID` | The manifest is malformed, names another root or network, or its signature does not verify under the issuer key. Get the signed manifest from the issuer again |
| `ZK_PROOF_MALFORMED`, `ZK_PROOF_INVALID` | The proof is not 128 bytes, or does not verify for this vault's journal. Make it again with `impulse-zk-prove` for these terms (`impulse zk prove-args` prints the arguments) |
| `ZK_IPST_VERSION` | A terms v3 command reads IPST version 4 only |
| `ZK_PROVER`, `ZK_PROVER_IMAGE` | No receipt was produced: Docker is not running, the Groth16 prover image is missing or is not the pinned one (`circuits/GROTH16_PROVER_IMAGE`), or the guest refused. Start Docker, pull the pinned image by digest and run again |
| `ZK_TX_MASS` | The transaction is above a per-dimension mass cap, so the shape is not shipped. Do not retry with the same inputs |

## ZK_H_ codes

Raised by the hashed-terms vault, template v4 (`impulse zk ...` with a terms v4 file or an IPST version 5, [spec/V3-ZK.md](../../spec/V3-ZK.md) section 22). They exist only in a build with the `zk` feature (core feature `zk-hashed`). Nothing is signed or sent when one is returned. `ZK_TX_MASS` and `ZK_IMAGE_ID_MISMATCH` apply to v4 as well.

| Code | Remedy |
| --- | --- |
| `ZK_H_TERMS_VERSION`, `ZK_H_TERMS_DIRECT`, `ZK_H_AUTHORITY_REQUIRED`, `ZK_H_BLIND_INVALID` | The terms are not valid terms v4: not version 4 (or not the canonical bytes), Direct settlement, no authority, or an all-zero blind. Terms v4 always name an authority. Let `impulse zk terms new-hashed` write the file: it draws the blind itself |
| `ZK_H_TERMS_FILE` | The terms file cannot be read, is not exactly the lowercase hex of the canonical terms, or did not read back after it was written. Use the file `terms new-hashed` wrote, byte for byte, and keep a copy before funding: settle and refund both need it |
| `ZK_H_TERMS_MISMATCH` | The terms' commitment for neither leg equals the vault's: these are not the terms of that vault (another blind or another file). Find the file that was written when the trade was made |
| `ZK_H_VERIFY_ADDRESS_MISMATCH` | An offered address is not the v4 vault of these terms for its leg, or an address is missing. `impulse zk verify` needs the terms file and both addresses; recompute them with `impulse zk address` |
| `ZK_H_ARTIFACT_INVALID`, `ZK_H_TEMPLATE_HASH_MISMATCH` | This build's template v4, `TEMPLATE_HASH_V4` or `IMAGE_ID_V4` is damaged or not the pinned one. Do not use the build: reinstall from a release, or rebuild with `scripts/build-template-v4.sh` and `scripts/build-guest.sh` and compare |
| `ZK_H_NOT_V4_VAULT`, `ZK_H_STATE_MALFORMED`, `ZK_H_NONCANONICAL` | The script is not a template v4 vault, its state is not (commitment, authority key), or it is not the v4 instantiation of its state. Do not fund it |
| `ZK_H_STATEMENT_FALSE` | The terms are not satisfied by this transaction; the message names the tag of the statement ([spec/V3-ZK.md](../../spec/V3-ZK.md) 22.4) that fails. Nothing was written. For a settle or refund you are building, a UTXO or an amount is not what the terms name; for `decode --with-terms`, the trade did not follow these terms |
| `ZK_H_WITNESS_INVALID`, `ZK_H_SHAPE` | A witness file or a transaction view is not the layout of the terms: a script that does not open to its view item, a view beyond four inputs or outputs, a leg that is not 0 or 1, or external cash given a cash vault; or a settle or refund with more than eight inputs (template v4 takes at most eight: consolidate the fee UTXOs). Write the witness again with `impulse zk witness` from the IPST |
| `ZK_H_PROOF_MALFORMED` | The proof file is not a proof file, not 128 bytes, or all zero; or a vault input of an IPST still holds the zero placeholder of a plan. Prove each witness (`impulse-zk-prove-terms`) and build again with `--proof` and `--proof-cash` |
| `ZK_H_PROOF_INVALID` | A proof file's journal is not the one this vault input builds (it was made for another transaction, lock time or vault), or the pinned script engine refused the vault input at `ipst raw` or `submit`. Prove again from the witness of the exact IPST; `impulse-zk-prove-terms --verify` checks a proof file alone |
| `ZK_H_IPST_VERSION` | A terms v4 command reads IPST version 5 only |
| `ZK_H_CAP_OVERRIDE` | Template v4 has no value-cap override: `--i-accept-the-risk` is refused. Lower the trade to the cap |

## On-chain refusals

The contract returns no codes. A spend that breaks a rule fails the script and the node refuses it. The tags `[S1]` to `[R14]` name each rule ([spec/ERRORS.md](../../spec/ERRORS.md#on-chain-refusals)). The builders check these rules first, so a tag appearing in a node's refusal usually means a transaction was built by other software, or a lock time was not yet reached (`[S3]`, `[R3]`: wait for the DAA score, then submit again). Rebuild with `impulse settle build` or `impulse refund build` rather than editing a transaction.

## v0.2 codes (terms, templates, receipts and hashlock trades of version 2)

Raised by the version 2 builders, verifiers, receipts and the `impulse xchain` commands ([spec/V2.md](../../spec/V2.md), [spec/ERRORS.md](../../spec/ERRORS.md)). Each row gives the family's raising point and the refusal in the words of the spec; fix the input it names and run the command again. Nothing is signed or sent when a code is returned.

| Code | Raised by, and what is refused |
| --- | --- |
| `HTLC_ARTIFACT_INVALID` | startup check: The embedded hashlock artifact or `TEMPLATE_HASH_HASHLOCK` cannot be used |
| `HTLC_ASSET_KIND` | structure: The hashlock asset leg is not KCC-20 |
| `HTLC_COUNTERPART` | decode, structure, creation: The counterpart record names an unknown chain, has a zero amount, an all-zero identifier, or a timeout of zero or above `i64::MAX`; at creation, its timeout is at or before the time of the check |
| `HTLC_DAA_SAMPLE` | creation: On mainnet, no DAA rate sample is given, or it is older than 30 days, or it was taken at another blocks-per-second than the configured network's, or its mean DAA rate is below half the network's target rate (section 10.5) |
| `HTLC_FUNDING` | verify_funding: A funding transaction does not fund the terms' vault: no output, or more than one, holds the escrowed token (the asset's covenant and template, owned by the vault's script hash, exactly the amount, not a minter), or no authorizer pays the vault's address (section 10.5, step 3) |
| `HTLC_HASH_MISMATCH` | startup check: The hashlock template hash differs from the artifact's or from `TEMPLATE_HASH_HASHLOCK` |
| `HTLC_HASH_ZERO` | structure: hash_lock is all zero |
| `HTLC_MAINNET_GATED` | Reserved, no longer returned: the mainnet gate was lifted by D39 (b) and D40 |
| `HTLC_NONCANONICAL` | decode: The script is not the instantiation of the terms it decodes to |
| `HTLC_NOT_HASHLOCK_VAULT` | decode: The script does not run the hashlock template |
| `HTLC_SECRET_LENGTH` | claim: The secret is not 32 bytes |
| `HTLC_SECRET_MISMATCH` | claim: sha256 of the secret is not hash_lock |
| `HTLC_STATE_INVALID` | decode: A state field holds a value no hashlock terms value encodes to |
| `HTLC_STATE_MALFORMED` | decode: The state does not parse as the hashlock state |
| `HTLC_TIMEOUT_MARGIN` | creation: expiry_daa does not reach past the counterpart timeout by the required margin |
| `HTLC_VERSION` | decode, structure: The hashlock terms version byte is not 1 |
| `IPST_V2_VERSION` | IPST read: `ipst` is neither 1 nor 2 |
| `RECEIPT_LINEAGE_MISMATCH` | v2 receipt verify, v2 status: With a previous receipt: it is another trade's, its digest is not `prior_receipt`, or a vault input did not spend its continuation of the same covenant ID; with --node, the transaction's spent outpoints or covenant IDs differ from the receipt's |
| `RECEIPT_QUANTITY_MISMATCH` | v2 receipt verify, v2 status: The stated quantities do not follow from the terms, the cumulative passes the lot count or is not the previous cumulative plus the lots, or with --node the transaction moves other lots |
| `RECEIPT_QUANTITY_MISSING` | v2 receipt verify: A version 2 receipt lacks the lots, cumulative, total, previous-receipt or per-leg quantity fields, or a version 1 receipt is offered for partial terms (spec/V2.md 4.6) |
| `TEMPLATE_V2_ARTIFACT_INVALID` | v2 startup check: The embedded v2 artifact or `TEMPLATE_HASH_V2` file cannot be used |
| `TEMPLATE_V2_HASH_MISMATCH` | v2 startup check: The v2 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V2` |
| `TEMPLATE_V2_LEG_INDEX` | v2 leg index, decode v2: A leg index outside 0 to leg_count - 1 |
| `TEMPLATE_V2_NONCANONICAL` | decode v2: The script is not the v2 instantiation of the terms it decodes to |
| `TEMPLATE_V2_NOT_VAULT` | decode v2, v2 template hash of an instance: The script does not run the ImpulseVault v2 template |
| `TEMPLATE_V2_STATE_INVALID` | decode v2: A v2 state field holds a value no terms v2 value encodes to |
| `TEMPLATE_V2_STATE_MALFORMED` | decode v2: The state does not parse as the ImpulseVault v2 state |
| `TERMS_AUTHORITY_IS_DEPOSITOR` | structure: The authority key equals a depositor key |
| `TERMS_LEGS_ONE_PARTY` | structure: Every leg has the same depositor key |
| `TERMS_LEGS_SAME_COVENANT` | structure: Two KCC-20 legs have the same covenant ID |
| `TERMS_LEG_COUNT` | structure: leg_count is below 2 or above MAX_LEGS |
| `TERMS_LEG_KIND` | structure: A v2 leg is external |
| `TERMS_LEG_ORDER` | structure: A KCC-20 leg follows a KAS leg |
| `TERMS_PARTIAL_INDIVISIBLE` | structure: A leg amount is not a multiple of lot_count |
| `TERMS_PARTIAL_LOTS` | structure: lot_count is below 2, or min_lot is zero or above lot_count |
| `TERMS_V2_VERSION` | decode v2, structure v2: The terms v2 decoder was given a version byte other than 2 |
| `TERMS_VERSION_UNKNOWN` | decode_any: The version byte is neither 1 nor 2 |
| `TX_LEGS` | v2 settle: The settle is not offered exactly one vault UTXO per leg and one escrow per KCC-20 leg |
| `TX_LEGS_OUT_OF_STEP` | v2 settle: The legs' escrows do not hold the same number of lots |
| `TX_LINEAGE` | v2 fund, v2 settle, v2 verify: A tranche from a vault input without a covenant ID, a genesis covenant ID that does not match the funding outpoint and output, or two vault UTXOs of one trade with the same covenant ID |
| `TX_TRANCHE` | v2 settle: The lots are not a whole number from 1 to what every escrow holds, are below min_lot, leave a remainder below min_lot lots, or name a tranche on terms without partial |
| `TX_V2_MASS` | v2 builders: The compute, storage or transient mass exceeds its CAP_V2 cap (section 6.2) |
| `TX_V2_NOT_AT_VAULT` | v2 settle, v2 refund: A v2 vault input is not at its vault's scriptPubKey, or carries a covenant ID under terms without partial |
| `VERIFY_V2_ADDRESS_MISMATCH` | v2 addresses: The offered address pays no leg's vault of these terms |
| `VERIFY_V2_TEMPLATE_MISMATCH` | v2 revealed script, v2 spent input: The revealed script does not run the pinned v2 template |
| `VERIFY_V2_WRONG_LEG` | v2 addresses: The offered address pays another leg's vault of these terms |
| `XCHAIN_CHAIN_UNSUPPORTED` | xchain: The counterpart chain has no source in this build |
| `XCHAIN_COUNTERPART_MISMATCH` | xchain verify-counterpart: The counterpart HTLC found on its chain differs from the counterpart record (program, asset, amount, recipient, refund, hash, timeout) or is not funded |
| `XCHAIN_HASH_REUSED` | xchain new, xchain verify: The hash_lock already appears in a hashlock vault known to this installation or found at verify |
| `XCHAIN_MAINNET_GATED` | Reserved, no longer returned: the mainnet gate was lifted by D39 (b) and D40 |
| `XCHAIN_MARGIN_TOO_SHORT` | xchain new, claim: Less time remains than the configured safety margin |
| `XCHAIN_NODE_BPS` | xchain new, claim: The node reports a blocks-per-second rate other than the configured network's |
| `XCHAIN_NOT_FINAL` | xchain verify-counterpart, watch, verify-funding: The counterpart lock or reveal, or the Kaspa funding, is not yet at the required finality |
| `XCHAIN_REVEAL_NOT_FOUND` | xchain watch: No counterpart claim revealing the secret was found |
| `XCHAIN_SECRET_FILE` | xchain claim, counterpart-claim: The secret file is not a regular file of 64 lowercase hex digits with at most one final line feed, or group or others can access it |
| `XCHAIN_TX_UNRELATED` | xchain status: The transaction is not part of this trade: it neither spends the trade's vault nor pays the vault's address or its escrow |

## v0.3 codes (proof-carrying and hashed-terms settlement, ZK_)

Raised by `impulse_core::zk`, `impulse_core::zkh` and the `impulse zk` commands ([spec/V3-ZK.md](../../spec/V3-ZK.md), [spec/ERRORS.md](../../spec/ERRORS.md)). Each row gives where the code is raised and what is refused, in the words of the spec; fix the input it names and run the command again. Nothing is signed or sent when a code is returned.

| Code | Raised by, and what is refused |
| --- | --- |
| `ZK_ARTIFACT_INVALID` | v3 startup check: The embedded v3 artifact, `TEMPLATE_HASH_V3` or `IMAGE_ID` cannot be used |
| `ZK_AUTHORITY_ABSENT` | `impulse zk terms new`: Terms v3 without an authority were requested without `--no-authority` |
| `ZK_DELIVERY_OWNER_TYPE` | structure v3: The buyer delivery owner is not of type PUBKEY or SCRIPT_HASH |
| `ZK_H_ARTIFACT_INVALID` | v4 startup check: The embedded v4 artifact, `TEMPLATE_HASH_V4` or `IMAGE_ID_V4` cannot be used |
| `ZK_H_AUTHORITY_REQUIRED` | structure v4: Terms v4 name no authority |
| `ZK_H_BLIND_INVALID` | structure v4: `blind` is all zero |
| `ZK_H_CAP_OVERRIDE` | v4 builders: The value-cap override flag was given; v4 never accepts it |
| `ZK_H_IPST_VERSION` | v4 IPST read: `ipst` is not 5 |
| `ZK_H_NONCANONICAL` | decode: The script is not the v4 instantiation of its state |
| `ZK_H_NOT_V4_VAULT` | decode: The script does not run template v4 |
| `ZK_H_PROOF_INVALID` | settle and refund build: The proof does not verify for this vault's journal in the pinned engine |
| `ZK_H_PROOF_MALFORMED` | settle and refund build, IPST read: The proof is not 128 bytes or does not parse |
| `ZK_H_SHAPE` | builders, prove: `n_in` or `n_out` is not the layout of the terms, or a settle or refund would have more than eight inputs |
| `ZK_H_STATEMENT_FALSE` | prove, decode `--with-terms`, builders: A tag of 22.4 fails on the view; the message names the tag |
| `ZK_H_STATE_MALFORMED` | decode: The state is not (commitment, authority key) |
| `ZK_H_TEMPLATE_HASH_MISMATCH` | v4 startup check: The v4 template hash differs from the artifact's or from `TEMPLATE_HASH_V4` |
| `ZK_H_TERMS_DIRECT` | structure v4: Terms v4 name Direct settlement |
| `ZK_H_TERMS_FILE` | fund build: The terms file was not written and read back to the same bytes before funding |
| `ZK_H_TERMS_MISMATCH` | decode, verify: The terms' commitment for neither leg equals the vault's |
| `ZK_H_TERMS_VERSION` | decode terms v4: The version byte is not 4 |
| `ZK_H_VERIFY_ADDRESS_MISMATCH` | verify: The offered address is not the v4 vault of these terms for its leg |
| `ZK_H_WITNESS_INVALID` | prove: A scriptPubKey or redeem script given does not open to its view item |
| `ZK_IMAGE_ID_MISMATCH` | v3 startup check, prove: The image ID in template v3 differs from `circuits/IMAGE_ID` or from the prover's guest |
| `ZK_IPST_VERSION` | v3 IPST read: `ipst` is not 4 |
| `ZK_ISSUER_KEY` | structure v3: list_issuer_key is not a valid BIP-340 x-only public key |
| `ZK_LIST_ENTRY` | list build: An entry is not a Schnorr P2PK or P2SH address or owner of the terms' network |
| `ZK_LIST_SIZE` | list build: The list is empty or has more than 1,048,576 entries |
| `ZK_MANIFEST_INVALID` | list manifest, verify: The manifest is malformed, names another root or network, or its signature does not verify under list_issuer_key |
| `ZK_NONCANONICAL` | decode v3: The script is not the v3 instantiation of the terms it decodes to |
| `ZK_NOT_MEMBER` | list path: The delivery owner is not in the list |
| `ZK_NOT_V3_VAULT` | decode v3: The script does not run template v3 |
| `ZK_PATH_INVALID` | prove, settle build, verify: The path file is malformed or does not lead from the owner's salted leaf to list_root |
| `ZK_PROOF_INVALID` | settle build: The proof does not verify for this vault's journal in the pinned engine |
| `ZK_PROOF_MALFORMED` | settle build, IPST read: The proof is not 128 bytes or does not parse as a compressed Groth16 proof |
| `ZK_PROVER` | prove: No receipt was produced: r0vm or the Groth16 step is missing or of another version, or the guest refused |
| `ZK_PROVER_IMAGE` | prove: The local Groth16 prover image's digest differs from `circuits/GROTH16_PROVER_IMAGE` |
| `ZK_ROOT_INVALID` | structure v3: list_root is all zero or the root of the empty tree |
| `ZK_STATE_INVALID` | decode v3: A v3 state field holds a value no terms v3 value encodes to |
| `ZK_STATE_MALFORMED` | decode v3: The state does not parse as the v3 state |
| `ZK_TEMPLATE_HASH_MISMATCH` | v3 startup check: The v3 template hash differs from the artifact's declared hash or from `TEMPLATE_HASH_V3` |
| `ZK_TERMS_DIRECT` | structure v3: Terms v3 name Direct settlement |
| `ZK_TERMS_VERSION` | decode v3, structure v3: The terms v3 decoder was given a version byte other than 3 |
| `ZK_TX_MASS` | v3 builders: The compute, storage or transient mass exceeds its v3 cap (section 10) |
| `ZK_VERIFY_ADDRESS_MISMATCH` | v3 addresses: The offered address pays neither vault of these v3 terms |
| `ZK_VERIFY_TEMPLATE_MISMATCH` | v3 revealed script: The revealed script does not run the pinned template v3 |

## LINKED_ codes

Raised by `impulse_core::linked` and the `impulse linked` commands ([spec/V2.md](../../spec/V2.md) section 17, [spec/ERRORS.md](../../spec/ERRORS.md#linked_-codes)). Each row gives where the code is raised and what is refused; fix the input it names and run the command again. Nothing is signed or sent when a code is returned.

| Code | Raised by, and what is refused |
| --- | --- |
| `LINKED_VERSION` | sheet decode, checks: The sheet's link_version is not 1 |
| `LINKED_TRUNCATED` | sheet decode: The sheet ends inside a field |
| `LINKED_TRAILING_BYTES` | sheet decode: Bytes follow the sheet's last field |
| `LINKED_LEG_COUNT` | sheet checks: The opening does not have exactly two legs |
| `LINKED_PARTIAL` | sheet checks: The opening has partial settlement |
| `LINKED_TRADE_REF_SET` | sheet checks: The opening's trade_ref is not zero |
| `LINKED_RETURN_NOT_LATER` | sheet checks: return_earliest_daa is not above the opening's expiry_daa |
| `LINKED_NOT_A_LEG` | verify terms: The terms are not a derived trade of the sheet |
| `LINKED_ROLE_MISMATCH` | verify terms: The terms are the other role's derived trade |
| `LINKED_TRADE_REF` | verify terms: The terms are the derived trade except for trade_ref |
| `LINKED_OPENING_NOT_SETTLED` | return fund, return settle: No evidence of an opening settle for this sheet |
| `LINKED_SETTLE_EVIDENCE` | settle evidence: The transaction is not a settle of both vaults of the trade of the role |
| `LINKED_RECEIPT_TERMS` | receipt verify: The receipt names another sheet, another leg trade or another network than the sheet gives |
| `LINKED_RECEIPT_PAIR` | receipt pair: The two receipts are not an opening then a return of one sheet |

## Release findings

`RELEASE_*` codes are findings of the maintainers' release pre-flight, printed as PROBLEM (a defect to fix) or PENDING (an owner-gated item). The pre-flight is not part of the public tree.
