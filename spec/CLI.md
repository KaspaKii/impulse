# Impulse CLI: files, funding URI, signing, value cap and receipts

Companion to `IMPULSE-SPEC.md`, section "Off-chain components". Fixed in increment I7 before the code: phase 1 (terms, funding URI, signing, value cap, node, receipts), phase 2 ("Building, signing and submitting" below), the integration follow-up of 2026-10-11 (the Direct cancellation, `submit --signed-tx-out`) and the testnet token helper of 2026-10-11 ("Token helper (testnet only)"). Reference implementation: `crates/impulse-cli/`. The partially signed transaction format (IPST) is specified separately in `spec/IPST.md` (I5); the transactions the builders make in `spec/TRANSACTIONS.md`; decoding in `spec/VERIFY.md` (I6).

Conventions are those of `spec/ENCODING.md`, "Golden vectors": u64 values in JSON as decimal strings, byte arrays as lowercase hex, kinds as lowercase strings.

## Network selection

Every command acts on one network: testnet unless the user passes `--network mainnet`. No configuration file or environment variable selects mainnet. The network a command acts on must be the network its terms name (`TERMS_NETWORK_MISMATCH` where the creation checks run, `CLI_NETWORK_MISMATCH` elsewhere) and the network the node reports (`CLI_NODE_NETWORK_MISMATCH`). The signing module refuses mainnet unless `--network mainnet` was passed, independently of these checks.

## Terms draft and terms file

`impulse terms new --draft <file> --out <file>` reads a draft and writes a terms file.

- **Draft.** A JSON object in the JSON form of terms (`spec/ENCODING.md`), every key present and no other key, except `nonce`, which may be absent or `null`; the CLI then draws it from the operating system's random source.
- **Terms file.** A JSON object with exactly three keys: `terms` (the JSON form, nonce included), `canonical` (the canonical bytes, hex) and `terms_hash` (hex). A reader parses `terms`, encodes it and refuses the file unless the encoding equals `canonical` and its hash equals `terms_hash` (`CLI_TERMS_FILE_INCONSISTENT`). Any JSON that is not the JSON form is `CLI_TERMS_JSON`, including an object (at any depth, in a draft or a terms file) that names a key twice. Messages that echo content read from a file echo it escaped.

A terms hash or funding address is shown only after the terms pass the structure checks (`ValidatedTerms`) and the creation checks, and after every leg the terms escrow has instantiated as a `FundableVault`. A leg the terms do not escrow (both legs in Direct mode, the cash leg in external-cash mode, `TEMPLATE_NO_VAULT`) is reported as having no vault; any other refusal on either leg refuses the whole command, so nothing is shown. `--out` must not exist (`CLI_OUTPUT_EXISTS`).

The creation checks need the DAA score at creation: `--node <url>`, which reads the virtual DAA score of a synced node on the operating network, or on testnet only `--daa <score>` from the user. On mainnet a typed score is refused (`CLI_MAINNET_NEEDS_NODE`): the expiry and horizon checks, and the time left that the terms summary shows, would rest on a number a counterparty could supply.

## Terms summary and role check

The contract lets the counterparty or the authority trigger a refund, and a refund returns a leg to its depositor's refund target as the terms name it (`IMPULSE-SPEC.md`, "Entries", refund rules 1 and 3). Terms that name a counterparty's script as your refund, delivery or proceeds destination therefore pay your leg to the counterparty once you fund it, and the contract works as specified. Reading the terms is the only defence, so `terms new`, `address` and `verify` take the user's party and show the decoded terms before anything else.

- `--role buyer|seller` and `--my-key <x-only public key, 64 lowercase hex digits>` are required. A public key only; the CLI never takes a private key here.
- `--my-key` must be the role's party key in the terms (`buyer_key` or `seller_key`): `CLI_ROLE_KEY_MISMATCH`.
- The role's own destinations (buyer: `buyer_delivery`, `buyer_refund`; seller: `seller_proceeds`, `seller_refund`) are checked one by one, and any failure is `CLI_DESTINATION_NOT_MINE`:
  1. A destination that pays the counterparty's party key or the authority key is refused, always. Such a destination is never the user's custodian, and no argument accepts it.
  2. A destination the user pinned must equal the pin exactly. Pins name what the user expects to be paid at: `--my-delivery` (buyer, `buyer_delivery`), `--my-proceeds` (seller, `seller_proceeds`) and `--my-refund` (either role, its own refund). A pin is a Kaspa address of the command's network in canonical form (P2PK, P2PK-ECDSA or P2SH; it stands for the version-0 script of that address), or a KCC-20 owner written `kcc20:pubkey:<hex>`, `kcc20:script_hash:<hex>` or `kcc20:covenant_id:<hex>` with 64 lowercase hex digits. This is how a custodian or multisig destination is accepted: the user states the exact destination it controls, and terms that name any other script are refused.
  3. A destination without a pin must pay `--my-key`: a version-0 P2PK script of that x-only key, a P2PK-ECDSA script of that x with either parity prefix (the same secret controls both), or a KCC-20 owner of type `pubkey` with that identifier. Off-chain destinations (external cash) are not checked.

  A pin that does not parse, names another network, or names a destination the role does not have (`--my-delivery` for a seller, `--my-proceeds` for a buyer) is `CLI_DESTINATION_PIN_INVALID`. The output states, for each own destination, whether it pays `--my-key`, equals its pin, or is off chain.
- Each vault is funded by its leg's depositor: the asset vault by the seller, the cash vault by the buyer. `address` labels every vault with who funds it and prints funding instructions (URI, QR code, amount line, token owner) only for the vault the user's role funds; for the counterparty's vault it prints the address and that the user sends nothing to it. KAS sent to the counterparty's vault is refunded to the counterparty's refund target, not to the sender.
- Before any vault address, funding URI, QR code or `ok:` line, and only after every check of the command has passed, the command prints: the terms hash and network; the trade reference `trade_ref` in hex (any value is meaningful and whoever drafts the terms chooses it, `spec/ENCODING.md`); the settlement mode; both party keys and the authority key; both legs with kind, token and amount (a KAS amount also in KAS); `buyer_delivery`, `seller_proceeds`, `seller_refund` and `buyer_refund` as Kaspa addresses or KCC-20 owners, each marked with the party key it pays or as a script to check; `earliest_daa`; `expiry_daa` with the approximate time left from the creation DAA score at the nominal 10 DAA scores per second; the funding mode; and the role check result. `verify` prints its `ok:` line last.

## Funding URI

`impulse address` prints, for a leg whose vault holds native KAS, the funding URI

```
<vault address>?amount=<sompi>&impulse=<terms_hash>
```

`<vault address>` is the leg's P2SH address with its network prefix (`kaspa:` or `kaspatest:`), `<sompi>` is the leg amount in sompi as a decimal integer with no sign and no leading zero, and `<terms_hash>` is 64 lowercase hex digits. Nothing else may appear: no other parameter, no other order, no fragment, no percent-encoding. The URI is also rendered as a QR code of exactly that text in the terminal, light modules drawn as blocks for a dark terminal background (`--no-qr` turns it off; on a light background use the printed URI). Beside the URI `address` prints the amount in KAS and sompi and asks the user to confirm the wallet shows exactly that amount before sending: whether wallets read `amount` as sompi is not yet checked against real wallets.

A KCC-20 leg is funded with two UTXOs (the escrowed token and the authorizer KAS, `IMPULSE-SPEC.md`, "How a leg is escrowed"), which a single-payment URI cannot express, so no URI is printed for it; `impulse address` prints the vault address and the token owner (SCRIPT_HASH, the vault's script hash). Its funding is built by `impulse fund build`.

`impulse verify --terms <file> --uri <uri>` checks a URI against a terms file, in this order, stopping at the first refusal:

1. The URI has exactly the form above: `CLI_URI_MALFORMED`.
2. `impulse` equals the terms hash: `CLI_URI_TERMS_HASH_MISMATCH`.
3. The address is the funding address of one of the terms' vaults, recomputed through the creation path above: `CLI_URI_ADDRESS_MISMATCH`.
4. That vault's leg is native KAS: `CLI_URI_LEG_NOT_KAS`.
5. `amount` equals that leg's amount exactly: `CLI_URI_AMOUNT_MISMATCH`.
6. The role check of "Terms summary and role check": `CLI_ROLE_KEY_MISMATCH`, `CLI_DESTINATION_PIN_INVALID`, `CLI_DESTINATION_NOT_MINE`.
7. The vault is the one the user's role funds (cash: buyer, asset: seller): `CLI_URI_NOT_YOUR_LEG`.
8. The value cap of "Value cap": `CLI_VALUE_CAP_INVALID`, `CLI_VALUE_UNKNOWN`, `CLI_VALUE_CAP_EXCEEDED`.

Only then does `verify` print the terms summary, the cap used and, last, its `ok:` line, which names the user's role.

## Key file and the signing module

The CLI signs only with a key file the user names with `--key-file <path>`; there is no default path and no environment variable. One module (`crates/impulse-cli/src/signing.rs`) reads key files and signs, through one entry point, `signing::sign`, which takes the key file path, the network of what is signed, whether `--network mainnet` was passed, an optional expected signer and a 32-byte digest, and returns 65 bytes: the 64-byte BIP-340 Schnorr signature followed by the sighash type `SIG_HASH_ALL` (`0x01`), the form the ImpulseVault `sig` argument takes.

The file holds exactly 64 hexadecimal digits (a 32-byte secp256k1 secret key), optionally followed by one line feed. On Unix it must be a regular file that neither group nor others may read, write or execute. Key bytes read from the file are held in buffers that are zeroed when dropped, and the key pair is overwritten after the one signature on a best-effort basis: secp256k1 documents that erase as best effort (the compiler may leave copies), and no test can observe it. No key material is printed, logged, written or sent; error messages name the path, never the content. Refusals, checked in this order:

| Code | Meaning |
| --- | --- |
| `SIGN_MAINNET_NOT_EXPLICIT` | The digest is for mainnet and `--network mainnet` was not passed |
| `SIGN_NETWORK_MISMATCH` | `--network mainnet` was passed for a testnet digest |
| `SIGN_KEY_FILE_UNREADABLE` | The path cannot be opened or read, or is not a regular file |
| `SIGN_KEY_FILE_PERMISSIONS` | Group or others have any access to the file (Unix) |
| `SIGN_KEY_FILE_FORMAT` | The content is not 64 hex digits with at most one final line feed |
| `SIGN_KEY_INVALID` | The 32 bytes are not a valid secp256k1 secret key |
| `SIGN_KEY_NOT_EXPECTED` | The key's x-only public key is not the expected signer |
| `SIGN_SELF_CHECK_FAILED` | The signature does not verify against the key's public key |

## Value cap

The CLI refuses to build, fund or sign for a trade above a per-trade cap. The default cap is 10 KAS (1,000,000,000 sompi), as the owner decided (D4). The environment variable `IMPULSE_MAX_VALUE` (sompi, decimal) may lower it; a value that does not parse, or that is above the default, is `CLI_VALUE_CAP_INVALID`. Only `--i-accept-the-risk` lifts the cap.

The exposure the contract holds is both escrowed legs, and in v1 the asset leg is always a KCC-20 token, whose KAS value the CLI cannot know. So the trade value is unknown unless the user declares it: `--kas-equivalent <sompi>`, the KAS value of the larger leg, is required for every trade with a leg that is not native KAS, which is every v1 trade (`CLI_VALUE_UNKNOWN` without it; a declared `0` is no declaration). The trade value is the larger of the declared value and every native KAS leg amount, so a declaration can raise the value but never lower it below a KAS leg. A value above the cap is `CLI_VALUE_CAP_EXCEEDED`. The declaration is the user's own; nothing on chain checks it. `--i-accept-the-risk` skips all of these checks. Every run that applies the cap prints the value and the cap it used, or that the cap was lifted. The cap applies in `terms new`, `address` and `verify` (the command a user runs on a counterparty's URI just before sending), in every builder (`fund build`, `settle build`, `refund build`) and in `ipst sign`. A refund is never stuck behind it: `--i-accept-the-risk` lifts it for any command.

## Node

The user supplies the node with `--node <url>`, a `ws://` or `wss://` wRPC (Borsh) endpoint; there is no default endpoint and no resolver. Any other URL is `CLI_NODE_URL_INVALID`. On mainnet the node is the trust anchor for the creation DAA score and for signed receipts, so the link must be private: `wss://`, or `ws://` to `127.0.0.1`, `[::1]` or `localhost` with an optional port (`CLI_NODE_INSECURE` otherwise, checked before anything is read or contacted; a remote node is reached through an SSH tunnel to a loopback port). There is no override. After connecting, the CLI reads the node's server info and refuses a node on another network (`CLI_NODE_NETWORK_MISMATCH`; mainnet terms need a mainnet node, testnet terms any testnet) or not synced (`CLI_NODE_NOT_SYNCED`). A failed connection is `CLI_NODE_UNREACHABLE`; a failed or malformed RPC answer is `CLI_NODE_RPC`. The transport check runs in the command before anything is read, and again in the wRPC client itself before it connects, so no caller reaches a node without it. Text a node or the connection supplies (an RPC error message) is echoed escaped, never raw, so a node cannot write control sequences to the user's terminal. The node URL is echoed as scheme, host and port only, never its user information, path or query, which can carry a credential or an API key. Connecting has a 10 second timeout and every call after it a 30 second one (policy figures, the watcher's, not measured ones); a call with no answer in time is `CLI_NODE_RPC` (`no answer in 30000 ms`), so a node that takes the connection and goes silent cannot hold a command for ever. A refused or unanswered submission names the transaction ID and the `impulse status` command line that finds it, because the node may have taken it.

## Settlement receipt

`impulse status --node <url> --terms <file> --txid <hex> --from-block <hash>` finds the chain block that accepted the transaction by walking the node's virtual selected parent chain from `--from-block` (a chain block at or before the submission, which `submit` prints), following removals as well as additions. Not found is `CLI_TX_NOT_ACCEPTED`. It reports the accepting block, that block's DAA score, and the depth: the node's virtual DAA score minus that DAA score. The terms file is read as an existing trade: its escrowed legs must instantiate (only `TEMPLATE_NO_VAULT` reads as no vault; any other refusal refuses the command before the node is contacted), with no creation checks, so `status` works after the expiry. With `--key-file` it signs the result as a receipt and writes it to `--out`; `--key-file` requires `--min-depth <DAA>`, and a depth below it is refused (`CLI_DEPTH_BELOW_MINIMUM`) before anything is signed or written, so a receipt is never issued for a block the user did not consider buried. Every `status` run prints a note on stderr that the terms binding is not checked (see the version 1 limit below).

**JSON form.** An object with exactly these keys, in this order:

| Key | Content |
| --- | --- |
| `version` | `1` (number) |
| `network` | `mainnet` or `testnet` |
| `terms_hash` | 32 bytes, hex |
| `txid` | 32 bytes, hex |
| `accepting_block` | 32 bytes, hex |
| `daa_score` | DAA score of the accepting block, decimal string |
| `depth` | Virtual DAA score at observation minus `daa_score`, decimal string |
| `signer` | x-only public key of the signer, hex |
| `signature` | 64-byte BIP-340 signature over the digest below, hex |

**Digest.** BLAKE2b-256 in keyed mode, digest length 32, keyed with the 18 ASCII bytes `Impulse/receipt/v1` (as the terms hash is keyed with its tag), over the canonical bytes, where the canonical bytes are: version u8, network u8 (`0x00` mainnet, `0x01` testnet), terms_hash 32, txid 32, accepting_block 32, daa_score u64 little-endian, depth u64 little-endian (114 bytes). The signer is not in the digest: a BIP-340 signature already commits to the signer's public key. The key differs from the transaction sighash key, so a receipt signature is never a transaction signature. Known answer, checked in the tests against Python's `hashlib`: testnet, terms_hash `11` x 32, txid `22` x 32, accepting_block `33` x 32, daa_score 1000, depth 10 give the digest `b8683e8aaf6727cc2256bfc64dca118b03c7902993783cbb44e7e8abbeaaee36`.

**Verification.** `impulse receipt verify --receipt <file> [--signer <hex>] [--terms <file> | --terms-hash <hex>] [--txid <hex>] [--node <url>]`, stopping at the first refusal:

1. The file is the JSON form above, nothing more, and names no key twice: `RECEIPT_MALFORMED`.
2. The signature verifies over the digest for `signer`: `RECEIPT_SIGNATURE_INVALID`.
3. With `--signer`, `signer` equals it: `RECEIPT_SIGNER_MISMATCH`.
4. With `--terms` (a terms file, read as in "Terms draft and terms file") or `--terms-hash`, `terms_hash` equals that terms hash: `RECEIPT_TERMS_MISMATCH`.
5. With `--txid`, `txid` equals it: `RECEIPT_TXID_MISMATCH`.
6. With `--node`, after the node checks above for the receipt's network: the accepting block is a chain block whose DAA score is `daa_score` (`RECEIPT_DAA_MISMATCH` for a different score, `RECEIPT_NOT_ACCEPTED` if not a chain block); the virtual chain from its selected parent starts with it, removes nothing and lists `txid` among the transactions it accepted (`RECEIPT_NOT_ACCEPTED`); and the node's current depth is at least `depth` (`RECEIPT_DEPTH_UNREACHED`).

`receipt verify` prints `ok:` with the signer, then the receipt's `terms_hash` and `txid`, each with whether it was compared with the user's own, so the output always states which trade and transaction it covers; with `--node` the chain line names both again. It then states what it did not establish: without `--terms` or `--terms-hash`, that the receipt was not compared with the user's trade; without `--txid`, that the transaction was not compared; without `--signer`, that the signer is not authenticated (anyone can sign a receipt with their own key); without `--node`, that the on-chain facts were not checked; and always, for version 1, that the terms binding is not checked.

Version 1 limit: a version 1 receipt binds `terms_hash` to `txid` by the signer's assertion only; nothing checks that the transaction spends the terms' vaults. `impulse decode <txid>` (below) shows which trades a transaction spends, from the node; a receipt that carries that check is not specified yet. It will carry another version number and digest key, and a reader of that version never accepts a version 1 receipt as bound.

## Building, signing and submitting

Phase 2 of I7. The builders, the IPST and the decoder are impulse-core's (`spec/TRANSACTIONS.md`, `spec/IPST.md`, `spec/VERIFY.md`); the CLI finds the UTXOs on the user's node, applies the checks below, writes and reads IPST files, signs through the signing module and submits. Every command here prints nothing until all of its checks have passed, and acts on testnet unless `--network mainnet` is passed.

### Before funding

Two properties of the terms are checked before anyone funds (carried from the I5 review):

- **A KAS cash leg below the minimum.** A KAS cash leg of less than `MIN_KAS_OUTPUT` (50,000,000 sompi, `spec/TRANSACTIONS.md`, "Minimum KAS per leg") has no standard settle: the settle's cash output must equal the leg amount (`[S5]`), and `fund_kas` refuses to fund it. `terms new`, `address`, `verify`, `fund build` and `ipst sign` of a funding transaction refuse such terms (`CLI_KAS_LEG_BELOW_MIN`), whichever leg the user funds. The first four check it as soon as the terms are read and their legs instantiated, before the role check and the URI checks.
- **A KCC-20 template that is not kcc20.sil.** The builders' compute budgets are measured for kcc20.sil's `transfer` code (silverscript v1.0.0) at any template length, not for other code. A KCC-20 leg whose template (hash, prefix length, suffix length) is not one of `PINNED_KCC20_TEMPLATES` (`spec/VERIFY.md`, "Pinned KCC-20 templates") is flagged: `terms new` prints a `warning:` line for it after the terms summary, and `address`, `verify`, `fund build` and `ipst sign` of a funding transaction refuse such terms (`CLI_TEMPLATE_UNPINNED`), so no command gives funding instructions, an `ok:` line or a signature for a trade that `fund build` would not fund: a settle or refund the budgets do not cover could leave a token escrowed with no spend path. `address` and `verify` run this check right after the KAS minimum check. There is no override; such tokens are outside v1.

### Node calls

Besides the calls of "Node", the builders read UTXOs with `get_utxos_by_addresses`, which needs a node that keeps the UTXO index (kaspad `--utxoindex`), and `decode` reads accepted transactions with `get_virtual_chain_from_block_v2` at full verbosity, which returns each accepted transaction with the UTXO entry each of its inputs spent. Every command that uses a node checks its network and sync first, as above, and takes the current DAA score from the node's virtual DAA score.

A UTXO a node reports is used only if its scriptPublicKey is the one the CLI computed for what it looks for. A node that reports a false amount or script cannot redirect a signature: each sighash commits to the amount and scriptPublicKey of the UTXO it spends (`spec/IPST.md`, "Trust model"), so the transaction is then invalid at an honest node.

### Common arguments of the builders

- `--terms <file>` and `--node <url>`, both required.
- `--pay-from <address>`: a P2PK (Schnorr) address of the command's network. Its UTXOs without a covenant ID pay the fee, and when funding the deposit. Any other address is `CLI_ADDRESS_INVALID`; none there is `CLI_UTXO_NOT_FOUND`. A UTXO the transaction already spends as a trade input is never taken as a fee input. For `fund build` it must be the P2PK address of `--my-key` (`CLI_FUND_NOT_YOUR_LEG`): `ipst sign` lets only a funding's depositor sign it, so a funding whose fee inputs another key holds could never be completed.
- `--change <address>`: where the change goes, a P2PK, P2PK-ECDSA or P2SH address of the network (`CLI_ADDRESS_INVALID`); default `--pay-from`.
- `--fee <sompi>`: the exact fee. Without it the fee is the minimum relay fee of the transaction (`tx::min_relay_fee` of its fee mass): the CLI builds once with the 100,000 sompi floor and, if the builder answers `TX_FEE_TOO_LOW`, once more with the minimum it names.
- Fee inputs: the `--pay-from` UTXOs largest first (equal amounts by outpoint), the first one, then the first two, and so on, until the builder accepts; an attempt refused for too little (`TX_INSUFFICIENT_FUNDS`) or for change below the minimum (`TX_BELOW_MIN_KAS`) takes one more. The last refusal is returned when all have been tried.
- `--asset-template <file>`, `--cash-template <file>`: the silverc artifact of a KCC-20 leg's token. Required where a builder or the terms check needs that leg's template (`CLI_TEMPLATE_MISSING`): the terms check (`ipst sign`, `ipst merge`, `submit`) needs the asset template for every IPST, and the cash template for KCC-20 cash. An artifact that is not a KCC-20 template, or not the one the terms name, is `TX_TOKEN_TEMPLATE`.
- The value cap arguments of "Value cap".
- `--out <file>`: where the unsigned IPST is written in canonical form; it must not exist (`CLI_OUTPUT_EXISTS`).
- Outpoints are written `<txid>:<index>`, a token `<txid>:<index>:<amount>` (64 lowercase hex digits, decimal index and amount): `CLI_OUTPOINT_INVALID` otherwise.

Every builder prints the terms summary, the value cap line, then the transaction (below) and `wrote: <file>`. Builder refusals keep their `TX_*`, `TEMPLATE_*` and `TERMS_*` codes.

The builders no longer look for a token of the other leg's covenant owned by a vault: such a token cannot move under any template, and the warning `TOKEN_FOREIGN_AT_VAULT` is retired (`spec/TRANSACTIONS.md`, "A token of another covenant at a vault"). A spend has at most 12 inputs (a v2 settle N + 18): the builders add fee inputs, largest first, until the fee is covered and refuse with `TX_TOO_MANY_INPUTS` past the bound.

### The transaction lines

What a builder, `ipst sign`, `ipst merge` and `submit` print about an IPST, one fact per line, `key: value`, so that scripts can read them:

- `ipst:` the builder that makes it (the terms check's kind): `fund_kas`, `fund_kcc20 asset` or `fund_kcc20 cash`, `settle`, `direct`, or `refund <leg> by <depositor|counterparty|authority>, with the token` or `, without the token`; or, for the CLI's own Direct cancellation (below), `direct cancel by buyer`; or, for a token genesis ("Token helper (testnet only)"), `token genesis`.
- `txid:` the transaction ID. It does not cover signature scripts, so it is fixed before signing.
- `lock_time:` and, when nonzero, the first DAA score at which a block can include it.
- `input <i>:` outpoint, amount, the address it spends from, its covenant ID if any, and its signer and whether it is signed (`pending` or `signed`), or that it takes no signature.
- `output <i>:` amount, the address it pays, and its covenant binding if any.
- `fee:` the fee and the minimum relay fee; `payer cost beyond the fee: <sompi> sompi into trade outputs`, what the fee inputs put into the trade outputs (the trade outputs less the trade inputs, or 0): for a funding the deposit, for a settle, a refund or a Direct transaction the top-up of under-funded pass-through outputs (`spec/TRANSACTIONS.md`); `change:` the change output or `none`; `masses:` compute, transient and storage mass.
- `token change: <txid>:<index>:<amount>` when a funding returns token change to the depositor, in the `--token` form a later funding takes. `ipst sign`, `ipst merge` and `submit` do not know the amount and print `token change: <txid>:<index>`.
- `pending:` the signers whose signatures are missing, or `complete`.

### fund build

`impulse fund build --terms <file> --leg asset|cash --node <url> --role buyer|seller --my-key <hex> [pins] --pay-from <address> [--change <address>] [--fee <sompi>] [--asset-template <file>] [--cash-template <file>] [--token <txid>:<index>:<amount>]... [--carrier <sompi>] [--authorizer <sompi>] (--kas-equivalent <sompi> | --i-accept-the-risk) --out <file>`

Checks, in order: the node and the terms as `address` reads them (creation checks with the node's DAA score, every escrowed leg a `FundableVault`); the KAS minimum of "Before funding"; the role check; the leg is the user's own, the asset leg the seller's and the cash leg the buyer's (`CLI_FUND_NOT_YOUR_LEG`); the leg has a vault (`TEMPLATE_NO_VAULT`); the template check of "Before funding"; the value cap; the addresses, `--pay-from` the P2PK address of `--my-key` (`CLI_FUND_NOT_YOUR_LEG`); then the leg's own arguments. A KAS cash leg takes no `--token`, `--carrier` or `--authorizer` (`TX_WRONG_MODE`). A KCC-20 leg takes its template and at least one `--token`: the depositor's token UTXOs, each looked up on the node at the P2SH of the template holding the state (owner `--my-key` as a public key, that amount, not a minter) with the leg's covenant ID (`CLI_UTXO_NOT_FOUND` if it is not there). `--carrier` and `--authorizer` default to `MIN_KCC20_OUTPUT` and `MIN_KAS_OUTPUT`. Then `fund_kas` or `fund_kcc20` builds it.

### settle build

`impulse settle build --terms <file> --node <url> --pay-from <address> [--change <address>] [--fee <sompi>] --asset-template <file> [--cash-template <file>] (--kas-equivalent <sompi> | --i-accept-the-risk) --out <file>`

Anyone may build a settle: there is no role. The terms are read as an existing trade (every escrowed leg instantiates; the expiry is the builder's `TX_EXPIRED`), on the command's network (`CLI_NETWORK_MISMATCH`), then the value cap. The UTXOs are found on the node:

- Vault terms: the asset authorizer, the UTXO at the asset vault's address without a covenant ID holding the most KAS (equal amounts by outpoint), so the settler tops up least; the asset escrow, at the P2SH of the asset template holding the vault's escrow state (owner the vault's script hash, the leg amount, not a minter) with the leg's covenant ID; for KAS cash, a UTXO at the cash vault's address without a covenant ID holding exactly the cash amount; for KCC-20 cash, the cash authorizer and escrow as for the asset. Then `settle`.
- Direct terms: the seller's asset token, at the P2SH of the asset template holding (owner `seller_key`, exactly the asset amount, not a minter) with its covenant ID; the buyer's cash, for KAS a UTXO at the P2PK address of `buyer_key` holding exactly the cash amount, for KCC-20 a token held by `buyer_key` of exactly the cash amount. Then `direct`.

Where several UTXOs qualify, the one with the lowest outpoint is taken (for the asset authorizer, after the amount). None is `CLI_UTXO_NOT_FOUND`, naming what was looked for.

### refund build

`impulse refund build --terms <file> --leg asset|cash --signer depositor|counterparty|authority --node <url> --pay-from <address> [--change <address>] [--fee <sompi>] [--asset-template <file>] [--cash-template <file>] [--vault-utxo <txid>:<index>] [--without-token | --token-amount <amount> [--token-minter]] (--kas-equivalent <sompi> | --i-accept-the-risk) --out <file>`

The terms are read as an existing trade on the command's network, then the leg's vault (`TEMPLATE_NO_VAULT`, which covers the cash leg of external cash: no builder recovers a stray deposit there, owner decision D14), then the value cap. The vault UTXO is `--vault-utxo`, which must be a UTXO at the vault's address without a covenant ID, or else the only such UTXO there (`CLI_UTXO_AMBIGUOUS` listing them if there are several, `CLI_UTXO_NOT_FOUND` if none). A KCC-20 leg's escrowed token is looked up at the P2SH of the leg's template holding (owner the vault's script hash, `--token-amount` or the leg amount, the minter flag `--token-minter`) with the leg's covenant ID, unless `--without-token`; a KAS cash leg takes none of the three (`TX_WRONG_MODE`). Then `refund`, whose `TX_REFUND_SIGNER` refuses `--without-token` for any signer but the depositor. With `--without-token` the output says that the escrowed token stays owned by the vault, and how to get it back: fund a new authorizer at the vault's address and refund that one with the token (`spec/TRANSACTIONS.md`, "refund").

### direct cancel build (the Direct refund)

Direct terms escrow nothing, so a Direct trade has no refund entry. Its refund is a cancellation (owner decision 2026-10-11): after the agreed expiry one party spends one of its own Direct inputs back to itself. A signed Direct transaction that anyone still holds then spends an input that no longer exists, so the abandoned trade cannot be submitted; a new Direct transaction would need both parties to sign again. The design already accepts that a Direct party can abort by spending its input (`IMPULSE-SPEC.md`, red team, "Direct mode: a party can abort after signing by spending its input elsewhere"); this command makes that abort, after the expiry, a transaction the CLI builds, checks and can show. It is not one of impulse-core's builders (`spec/TRANSACTIONS.md`), and the IPST that carries it is an ordinary version 1 IPST (`spec/IPST.md`).

`impulse direct cancel build --terms <file> --node <url> --role buyer|seller --my-key <hex> [--for-ipst <file>] [--direct-input <txid>:<index>] [--change <address>] [--fee <sompi>] (--kas-equivalent <sompi> | --i-accept-the-risk) --out <file>`

A cancellation makes unsubmittable exactly the Direct transactions that spend its input 0, and no other. The buyer can hold several UTXOs of exactly the cash amount, and one that arrived after a Direct transaction was built can have a lower outpoint than the one that transaction spends, so the command never guesses: `--for-ipst` names the abandoned Direct transaction, and the cancellation spends that transaction's input 1, the buyer's Direct cash.

Checks, in order, first refusal returned; nothing is printed or written before all have passed:

1. The terms are read as an existing trade (every escrowed leg instantiates; no creation checks, so it works after the expiry) on the command's network (`CLI_NETWORK_MISMATCH`), and they are Direct terms (`CLI_CANCEL_NOT_DIRECT`: a vault leg goes home with `refund build`).
2. `--my-key` is 64 lowercase hex digits (`CLI_HEX`) and the role's party key in the terms (`CLI_ROLE_KEY_MISMATCH`).
3. The role's Direct input is native KAS (`CLI_CANCEL_INPUT_NOT_KAS`). Only the buyer's KAS cash is: the seller's Direct input is the asset, a KCC-20 token in v1 (decision D13), and a buyer's KCC-20 cash is a token too. Spending a token back to its holder is a KCC-20 transfer, which no Impulse builder makes.
4. The value cap of "Value cap".
5. `--for-ipst`, when given: the IPST of the Direct transaction to cancel, signed or not, read as in "Reading an IPST" (`IPST_*`, `TERMS_*`, `TX_SIGNATURE`) on the command's network (`CLI_NETWORK_MISMATCH`). It must be for the terms of `--terms`, not itself a cancellation (its input 0 is not a P2PK UTXO without a covenant ID), and its input 1 must be the buyer's Direct cash of `spec/TRANSACTIONS.md`, "direct": a UTXO at the P2PK address of `buyer_key` without a covenant ID holding exactly the cash amount (`CLI_CANCEL_INPUT_MISMATCH` otherwise). With `--direct-input` as well, the two must name the same outpoint (`CLI_CANCEL_INPUT_MISMATCH`). `--direct-input` is checked for form here (`CLI_OUTPOINT_INVALID`).
6. The node, checked as in "Node", then the Direct input: a UTXO at the P2PK address of `--my-key` without a covenant ID holding exactly the cash amount. It is the input 1 of `--for-ipst`, or the UTXO `--direct-input` names (`CLI_UTXO_NOT_FOUND` if the node has no such UTXO at that outpoint: for `--for-ipst`, that Direct transaction's input is already spent, so it cannot be submitted). Without either, the only such UTXO (`CLI_UTXO_NOT_FOUND` if there is none; `CLI_CANCEL_INPUT_AMBIGUOUS`, listing them, if there are several).
7. The fee inputs and the fee as in "Common arguments of the builders", from the UTXOs at the P2PK address of `--my-key` without a covenant ID other than the Direct input; there is no `--pay-from` (`CLI_UTXO_NOT_FOUND` if there is no other UTXO). `--change`, default that address, as there (`CLI_ADDRESS_INVALID`).

The transaction has the fixed fields of every Impulse transaction (`spec/IPST.md`, "Fixed transaction fields") and:

- lock time `expiry_daa`, and every input's sequence `INPUT_SEQUENCE` (0, `locktime`), so a node takes it only into a block of DAA score `expiry_daa + 1` or later (the node rule `locktime::check_tx_is_finalized` ports). It can be built and signed before the expiry; `submit` refuses it until then (`CLI_TX_NOT_FINAL`).
- input 0 the Direct input, then the fee inputs (the command takes them largest first); each is a P2PK spend with compute budget `P2PK_BUDGET`, signer `--my-key`, and an empty `script_before` and `script_after`.
- output 0 pays the Direct input's amount, exactly, to the Direct input's own scriptPublicKey (the P2PK of `--my-key`); output 1 is the change, omitted when zero. The fee comes from the fee inputs only (rule 5, docs/ENGINEERING-RULES.md): the Direct input goes home whole.
- The rules of the builders, with their codes: every fee input a version-0 P2PK UTXO of `--my-key` without a covenant ID (`TX_KAS_INPUT`), no outpoint twice (`TX_DUPLICATE_INPUT`), every spent UTXO and their total within the supply (`TX_UTXO_VALUE`), enough funds (`TX_INSUFFICIENT_FUNDS`), the change at least its minimum (`TX_BELOW_MIN_KAS`, `spec/TRANSACTIONS.md`, "Minimum KAS per leg"), every mass within `STANDARD_MASS_CAP` (`TX_MASS`), and the fee at least the minimum relay fee (`TX_FEE_TOO_LOW`).

The CLI renders the transaction as an IPST whose terms are the Direct terms and reads it back with the IPST reader (`spec/IPST.md`, "Reading an IPST") before it writes the canonical text to `--out` (`CLI_OUTPUT_EXISTS`). It prints the terms summary, the value cap line, the transaction lines (`ipst: direct cancel by buyer`), the line that says what it cancels, and `wrote:`. With `--for-ipst` that line is `cancels: Direct transaction <txid>, its input 1 <outpoint>`; without it, `cancels: no Direct transaction named; only one that spends <outpoint> (name it with --for-ipst)`. `decode` refuses the accepted cancellation with `DECODE_NO_VAULT_INPUT`, as it refuses a Direct transaction: neither spends a vault.

**The cancellation check.** `ipst sign`, `ipst merge` and `submit` take an IPST as a cancellation when its terms are Direct terms and its input 0 spends a version-0 P2PK UTXO without a covenant ID (a Direct transaction's input 0 is always the seller's token). In place of `Ipst::verify_against_terms`, which knows only impulse-core's builders, they run the cancellation check, which needs no template: input 0 must be the buyer's Direct cash (the terms' cash leg native KAS, and input 0 a UTXO at the P2PK address of `buyer_key` holding exactly the cash amount: `IPST_TERMS_MISMATCH` otherwise); then the transaction is rebuilt as above from the document's own parts (input 0 as the Direct input, the inputs after it as the fee inputs in their order, the document's fee, and the change destination, output 1's scriptPublicKey or, without output 1, output 0's), with the builder rules and their codes, and the two documents are compared in canonical form with every signature left out. Any difference is `IPST_TERMS_MISMATCH`. The rest of `ipst sign` applies as for a settle: the signer names the agreed Direct terms and signs as the buyer; step 9's payer checks hold for its fee inputs, and a cancellation's payer cost beyond the fee is 0; in step 10 the trade takes nothing from the signer and output 0 comes back to it with the change, so what it commits is the fee.

### ipst sign

`impulse ipst sign --ipst <file> (--terms <file> | --terms-hash <hex>) --key-file <file> --role buyer|seller|authority|payer --my-key <hex> [--my-delivery <destination>] [--my-proceeds <destination>] [--my-refund <destination>] (--node <url> | --daa <score>) [--asset-template <file>] [--cash-template <file>] [--change <address>] [--max-fee <sompi>] [--max-topup <sompi>] [--carrier <sompi>] [--authorizer <sompi>] (--kas-equivalent <sompi> | --i-accept-the-risk) --out <file>`

An IPST is untrusted input that someone else may have built. The signer names the trade it agreed to and its own role, and every check below runs before the signing module is called; the signed IPST is written, and the command prints, only after the last signature. Checks, in order, first refusal returned:

1. The IPST reads (`spec/IPST.md`, "Reading an IPST": `IPST_*`, `TERMS_*`, `TX_SIGNATURE`) and its terms name the command's network (`CLI_NETWORK_MISMATCH`); `--my-key` is 64 lowercase hex digits (`CLI_HEX`).
2. The agreed trade: the IPST's terms hash equals the terms hash of `--terms` (a terms file, read as in "Terms draft and terms file") or `--terms-hash` (`CLI_IPST_TERMS_NOT_AGREED`). The terms' escrowed legs instantiate.
3. The role: `--my-key` is the role's key in the terms, `buyer_key`, `seller_key` or `authority_key`; a payer's key is none of the three (`CLI_ROLE_KEY_MISMATCH`). For a buyer or seller, the role's own destinations are checked as in "Terms summary and role check", with the same pins (`CLI_DESTINATION_PIN_INVALID`, `CLI_DESTINATION_NOT_MINE`); the authority and a payer take no pins (`CLI_DESTINATION_PIN_INVALID`).
4. The current DAA score: from `--node`, or on testnet only `--daa` (`CLI_MAINNET_NEEDS_NODE`).
5. The terms check, `Ipst::verify_against_terms` with the templates and that score (`spec/IPST.md`, "Terms check"): the document is the transaction the builders make for its terms from its own inputs (`IPST_TERMS_MISMATCH`, or the builder's own code such as `TX_EXPIRED`); for a Direct cancellation, the cancellation check of "direct cancel build" in its place; for a token genesis, the genesis check of "Token helper (testnet only)", which also lists how `ipst sign` treats a genesis. `--authorizer` is for a KCC-20 funding only and `--carrier` for a KCC-20 funding or a Direct transaction (`TX_WRONG_MODE`).
6. For a funding transaction: the signer is the leg's depositor, the seller for the asset leg and the buyer for the cash leg (`CLI_FUND_NOT_YOUR_LEG`); the terms pass the creation checks at the current DAA score with every escrowed leg a `FundableVault`, as `address` reads them (`TERMS_*`, `TEMPLATE_*`); the two "Before funding" checks; and for a KCC-20 funding, the KAS on the escrowed token (output 0) and on the authorizer (output 1) equal `--carrier` and `--authorizer`, default `MIN_KCC20_OUTPUT` and `MIN_KAS_OUTPUT` (`CLI_IPST_DEPOSIT_MISMATCH`). The terms check takes both amounts from the document, so only the signer can confirm them.
7. The value cap.
8. The slots to sign: every slot whose signer is `--my-key` and that holds no signature yet. None is `CLI_IPST_NOTHING_TO_SIGN`.
9. The payer's checks, when a slot to sign spends one of the fee inputs (the inputs after the trade inputs of the builder's layout): the change output, if the transaction has one, must pay `--change`, or without it the P2PK address of `--my-key` (`CLI_IPST_CHANGE_NOT_MINE`); the fee must be at most `--max-fee`, by default twice the minimum relay fee of the transaction (`CLI_IPST_FEE_TOO_HIGH`). The default applies only when the signer signs at most three fee inputs; more without `--max-fee` is `CLI_IPST_FEE_TOO_HIGH`. The minimum relay fee grows with every input, and whoever built the document chose which of the signer's UTXOs it spends, so a limit derived from the document must not grow with an input count its builder controls (the builders take the payer's largest UTXOs first, "Common arguments of the builders"). For a settle, a refund or a Direct transaction, the payer cost beyond the fee (the top-up of under-funded pass-through outputs, "The transaction lines") must be at most `--max-topup`, default 0 (`CLI_IPST_TOPUP_TOO_HIGH`). Without a change output, everything the fee inputs hold beyond the fee goes to the trade outputs the terms check has fixed.
10. What the signer commits, when it signs any input holding its own funds: every input it signs, except the vault inputs of a settle or refund (the contract governs those). The outflow is what those inputs hold less what comes back to the signer: the change output when it pays `--change` (or the P2PK of `--my-key`), and a KCC-20 funding's token change when the signer owns the tokens. It must be at most what the trade takes from the signer plus `--max-fee` and `--max-topup` (`CLI_IPST_OUTFLOW_TOO_HIGH`), where the trade takes the leg amount of a KAS funding, the carrier and authorizer of a KCC-20 funding, in a Direct transaction the KAS cash for the buyer's KAS input and `--carrier` (default `MIN_KCC20_OUTPUT`) for each token input the signer gives, and nothing in a settle or refund. Unless the cap is lifted, the outflow must also be within the value cap (`CLI_VALUE_CAP_EXCEEDED`). So a signer whose token UTXO carries more KAS than the trade needs, or whose change goes elsewhere, is refused, whoever pays the fee.
11. Each slot is signed through `signing::sign` with the slot's sighash, the terms' network, `--network mainnet` as given, and `--my-key` as the expected signer (`SIGN_*`), and the signature is added to the IPST (`TX_SIGNATURE`).

Then the IPST is written to `--out` (`CLI_OUTPUT_EXISTS`), and the command prints the terms summary, the role check result, the cap line, the transaction lines, `you commit:` with the outflow and its limit when step 10 applies, `signed: <inputs>` and `wrote:`. Nothing is printed before every step has passed; the terms the signer reviewed are the agreed terms of step 2, which `terms new`, `address` and `verify` showed before funding.

### ipst merge

`impulse ipst merge --ipst <file> <file> [<file>]... (--node <url> | --daa <score>) [--asset-template <file>] [--cash-template <file>] --out <file>`

Reads every IPST, combines them in order (`IPST_CONFLICT`, `TX_SIGNATURE`), checks the network and runs the terms check (or the genesis check, or the cancellation check) on the result as `ipst sign` does, then writes it and prints the transaction lines.

`ipst sign` signs with BIP-340 auxiliary randomness (`secp256k1` `sign_schnorr`, random auxiliary data per signature), so the same key signing the same slot twice makes two different valid signatures, and combining two copies that hold them is `IPST_CONFLICT` (`spec/IPST.md`, "Combine": a slot signed differently in both is refused). Each signer signs its slots in one copy only; a signer who signed twice merges only one of its signed copies, either of which is valid.

### submit

`impulse submit --ipst <file> --node <url> [--asset-template <file>] [--cash-template <file>] [--signed-tx-out <file>]`

Reads the IPST and checks its network; checks the node; runs the terms check (or the genesis check of "Token helper (testnet only)", or the cancellation check of "direct cancel build") at the node's DAA score, so a settle past its expiry is refused (`TX_EXPIRED`); finalizes it (`TX_SIGNATURE_SLOT` for a missing signature, `TX_MASS`, `TX_FEE_TOO_LOW`); refuses a transaction whose lock time the node would not yet accept, the node rule ported in `locktime::check_tx_is_finalized` applied at the node's virtual DAA score (`CLI_TX_NOT_FINAL`, naming the DAA score the node must pass); then submits it and checks the returned ID (`CLI_NODE_RPC`, `CLI_NODE_TXID_MISMATCH`). It prints the transaction lines (with `txid:`), `from_block:`, the node's sink just before submission, which `status` and `decode` take as `--from-block`, and `submitted:` with the ID the node returned.

**Signed-transaction file.** With `--signed-tx-out <file>`, `submit` also writes the signed transaction it submits, for `impulse-watch run --keep-signed` (`spec/WATCH.md`, "The binary"): the raw form of `spec/VERIFY.md` ("Raw form": rusty-kaspa a41a333's borsh encoding of the transaction, which carries the transaction ID last) as lowercase hex followed by one line feed, and nothing else. A broadcast cannot be undone, so every way the file can fail is found before the node sees the transaction:

- Right after the node URL's transport check, before the IPST is read or the node contacted, the path is created as a new, empty file: `CLI_OUTPUT_EXISTS` if anything is there, a dangling symbolic link included (it is never followed); `CLI_FILE_WRITE` if it cannot be created, as in a missing or read-only directory. Either refuses with nothing submitted.
- Once every check above has passed and just before the transaction goes to the node, the content is written to that file (`CLI_FILE_WRITE` if the write fails; nothing is submitted).
- If any check or the submission is refused, the file is removed, so a refused submission leaves no file. A node answer that never arrived is a refusal too (`CLI_NODE_RPC`), although the node may have taken the transaction: the refusal then names the transaction ID, and if `status` later shows it accepted, `ipst raw` writes the file from the signed IPST.

After a submission the node took, nothing is left to fail: the line `signed_tx: <file>` follows `submitted:`. The watcher keeps only a transaction that settles or refunds a vault of a trade it watches (`WATCH_TX_NOT_TRACKED` otherwise), so the file is of use for a vault settle or refund; a funding, a Direct transaction or a Direct cancellation is written as asked, and the watcher refuses it.

### ipst raw

`impulse ipst raw --ipst <file> --out <file>`

Writes a fully signed IPST's transaction as the signed-transaction file of "submit", offline: for a transaction submitted without `--signed-tx-out`, or whose file a refused `submit` removed. It reads the IPST and checks its network (`IPST_*`, `TERMS_*`, `TX_SIGNATURE`, `CLI_NETWORK_MISMATCH`), finalizes it (`TX_SIGNATURE_SLOT` for a missing signature, `TX_MASS`, `TX_FEE_TOO_LOW`), writes `--out` (`CLI_OUTPUT_EXISTS`, `CLI_FILE_WRITE`) and prints `txid:` and `wrote:`. It contacts no node and submits nothing, so it runs no terms check, which would refuse a settle that was submitted in time once its expiry has passed; `impulse-watch` checks the transaction in the file against the trades it watches (`WATCH_TX_NOT_TRACKED`, `WATCH_SIGNED_TX_INVALID`).

### decode

`impulse decode <txid> --node <url> --from-block <hash>`

Walks the node's virtual chain from `--from-block` (a chain block at or before the transaction's acceptance) with `get_virtual_chain_from_block_v2`, following removals, until the sink, and takes the transaction whose ID, recomputed from its contents, is `<txid>` among those the chain accepted, with the UTXO entry each of its inputs spent (`CLI_TX_NOT_ACCEPTED` if no chain block accepts it; `CLI_NODE_RPC` if the node's answer lacks a field). Then it decodes the transaction with impulse-core's `decode_transaction`, bound to the scriptPublicKeys the node reports the inputs spent, on the command's network (`DECODE_*`, `TEMPLATE_*`, `TERMS_*`). It prints the txid, the accepting block, that the decoding is bound, and per trade the terms summary (expiry measured from the accepting block's DAA score) and each decoded leg: input, outpoint, leg, vault script hash, entry (with a refund's signer and role) and outcome; then each refused vault input with its code.

#### decode with a terms file (template v4, behind the `zk` feature)

`impulse decode <txid> --node <url> --from-block <hash> [--with-terms <file>]`

A v4 vault input (the hashed-terms vault, `V3-ZK.md` section 22) decoded without `--with-terms` is printed as one line: its input index, the commitment, the authority key, the entry (settle or refund), whether a 128-byte proof is present, and `terms not revealed`. That is not an error. A transaction whose only vault inputs are v4 decodes without the v1 refusal `DECODE_NO_VAULT_INPUT`. With `--with-terms` the file is read as lowercase hex of the canonical terms v4 (`ZK_H_TERMS_FILE`, `ZK_H_TERMS_VERSION`, then the structure codes), each v4 input is matched to a leg by its commitment (`ZK_H_TERMS_MISMATCH` if neither leg fits), the view is rebuilt from the node's data, and the statement of `circuits/terms-core` runs on it natively: the first false tag is `ZK_H_STATEMENT_FALSE` naming it. The check repeats what the proof states, without a proof, and is bound to the scriptPublicKeys the node reports. A transaction with no v4 input given `--with-terms` is `ZK_H_NOT_V4_VAULT`. The fixed texts of `V3-ZK.md` 22.11 follow.

`impulse zk terms reveal --terms <file> --leg <0|1>` prints the terms hash, the leg's commitment, the authority key and the leg's vault address, and the three fixed texts, before anything is funded. `--leg` other than 0 or 1, or 1 under external cash, is `ZK_H_SHAPE`; terms for another network than the command's is `ZK_H_TERMS_MISMATCH`.

#### zk, template v4 (hashed terms; behind the `zk` feature)

The `impulse zk` commands below take a terms v4 file (lowercase hex of the canonical terms v4, `V3-ZK.md` 22.2) where their v3 form takes a terms v3 file; a command routes on the file (hex or JSON) or on the IPST version (5 or 4). Every v4 command prints the three fixed texts of `V3-ZK.md` 22.11 first, takes `--kas-equivalent` for the value cap, and refuses `--i-accept-the-risk` as `ZK_H_CAP_OVERRIDE`: template v4 has no override. The cap applies to funding (`fund build`, and `ipst sign` of a funding), where new value enters. `settle build`, `refund build` and `ipst sign` of a settle or refund spend an already funded vault and are never refused for value: above the cap they print `warning:` on the notes stream (stderr) and the value cap line says the spend is not blocked, so a vault funded above the cap, by anyone or before `IMPULSE_MAX_VALUE` was lowered, can still be refunded or settled.

- `impulse zk terms new-hashed --draft <file> --out <file> (--daa | --node) --role --my-key --kas-equivalent`: the draft is the terms JSON with `"version": 4` and an authority. The command draws `blind` from the operating system's random number generator (there is no flag to set it), runs the structure checks of v1 and of v4 (`ZK_H_TERMS_VERSION`, `ZK_H_TERMS_DIRECT`, `ZK_H_AUTHORITY_REQUIRED`, `ZK_H_BLIND_INVALID`), the creation checks, the role check and the cap, writes the terms file (mode 0600, never over an existing file) and reads it back; a file that does not read back to the same terms is `ZK_H_TERMS_FILE` and no vault address is printed. Keep a copy of the file: settle and refund both need it.
- `impulse zk address --terms <file>` and `impulse zk verify --terms <file> --asset-address <a> [--cash-address <c>]`: the two vault addresses and their commitments. `verify` needs the terms file and both addresses and refuses an address that is not the v4 vault of the terms for its leg (`ZK_H_VERIFY_ADDRESS_MISMATCH`); `--manifest` and `--path` belong to terms v3 (`TX_WRONG_MODE`).
- `impulse zk fund build --terms <file> --leg <asset|cash> ...`: as the v3 command, over the v4 vaults. It reads the terms file as `ZK_H_TERMS_FILE` says, so it refuses without a saved terms file.
- `impulse zk settle build --terms <file> --node ... --pay-from ... --out <file> [--proof <asset vault proof>] [--proof-cash <cash vault proof>]` and `impulse zk refund build ... [--proof <file>]`: without proof files the result is a plan for the prover (the vault inputs hold 128 zero bytes); with them each proof file is checked first: `format`, a proof of 128 bytes that are not all zero (`ZK_H_PROOF_MALFORMED`), the journal of the file equal to the journal the vault input builds and the image ID equal to `circuits/IMAGE_ID_V4` (`ZK_H_PROOF_INVALID`, `ZK_IMAGE_ID_MISMATCH`). Both builders run the statement of `terms-core` natively on the view of every vault input they made, so a transaction the guest would refuse is never returned (`ZK_H_STATEMENT_FALSE`), and refuse a spend of more than eight inputs (`ZK_H_SHAPE`, the bound of template v4, `V3-ZK.md` 22.15).
- `impulse zk witness --ipst <file> --out-dir <new dir>`: writes `witness-input<N>-leg<L>.bin` for each vault input of the IPST (mode 0600) and prints the `impulse-zk-prove-terms --witness ... --out ...` command and the journal hash for each. A witness holds the terms: it stays on the machine that proves.
- `impulse zk ipst sign`, `ipst merge`, `ipst raw` and `submit` read IPST version 5 (an IPST of another version is `ZK_H_IPST_VERSION`) and run the v4 terms check before they sign, merge or broadcast: the transaction is rebuilt by the v4 builders from the document's own inputs and proofs and compared byte for byte, and the statement of `terms-core` is run on each vault input. `ipst raw` and `submit` finalize the document: every proof present (`ZK_H_PROOF_MALFORMED`), the masses under the caps (`ZK_TX_MASS`), the fee (`TX_FEE_TOO_LOW`), and then every input of the signed transaction runs in the pinned script engine, a vault input the engine refuses being `ZK_H_PROOF_INVALID`. `submit --flip-proof-bit` (testnet only) submits a copy with one bit of the first proof flipped, which the node must refuse.
- `impulse zk prove-args`, `zk status` and `zk receipt` have no v4 form: `prove-args` on a terms v4 file is `TX_WRONG_MODE` (use `zk witness`); a trade is shown by `decode --with-terms`.

### Helpers

- `impulse tip --node <url>`: the node's network, sync state, virtual DAA score and sink, after the node checks. The scripts take the DAA score for drafts and the sink as a `--from-block` from it.
- `impulse key show --key-file <file>`: the key file's x-only public key and P2PK address on the command's network. It reads the key only through `signing::sign`, over a fixed digest, and discards the signature.
- `impulse token info --template <file>`: a KCC-20 artifact's template hash, prefix and suffix lengths (the terms' `template_*` fields), and whether that template is pinned.

### Token helper (testnet only)

Added on 2026-10-11 for testnet use, which needs two KCC-20 tokens of a pinned kcc20.sil build (`spec/VERIFY.md`, "Pinned KCC-20 templates"): an asset token held by the seller key and a cash token held by the buyer key. No other Impulse command creates a token.

The helper acts on testnet only. With `--network mainnet`, `token mint build` and `token list` refuse with `CLI_TOKEN_TESTNET_ONLY` before anything is read or contacted, and every command that reads an IPST (`ipst sign`, `ipst merge`, `ipst raw`, `submit`, `direct cancel build --for-ipst`, `frost sign` and `frost aggregate`) refuses a token genesis IPST (below) whose terms name mainnet with the same code as soon as it is read. No flag lifts it. A mainnet token comes from its issuer's own KCC-20 tooling.

**The genesis.** A token is a fresh KCC-20 covenant created by one genesis transaction, under KIP-20 covenant IDs as rusty-kaspa a41a333 validates them (`crypto/txscript/src/covenants.rs`, `CovenantsContext::from_tx`): an output whose covenant binding names an authorizing input that does not carry that covenant ID is a genesis output, and its covenant ID must equal `covenant_id(outpoint of the authorizing input, the authorized outputs)` (`consensus/core/src/hashing/covenant_id.rs`: each authorized output's index, value, script version and script; the binding itself is left out). No script runs for an output, so a genesis output may hold any KCC-20 state. The helper uses the smallest shape that gives a token held by a public key: one genesis output, a non-minter kcc20.sil state that owns the whole supply. The supply is fixed at genesis: kcc20.sil conserves the amount on every transfer of a non-minter (`checkAmounts`) and lets no non-minter create a minter (`checkMintingTransfer`), so no unit can be added later. kcc20-minter.sil, a controller covenant that issues more over time (the KCC-20 book, "Lifecycle"), is not needed for a fixed test supply and is not built.

#### token mint build

`impulse token mint build --node <url> --template <file> --owner <hex> --pay-from <address> --amount <units> [--carrier <sompi>] [--change <address>] [--fee <sompi>] --out <file>`

Checks, in order, first refusal returned; nothing is printed or written before all have passed:

1. The command acts on testnet (`CLI_TOKEN_TESTNET_ONLY`).
2. The node URL passes the transport check of "Node".
3. `--template` is a KCC-20 artifact (`CLI_FILE_READ`, `TX_TOKEN_TEMPLATE`) and a pinned kcc20.sil build (`CLI_TOKEN_TEMPLATE_UNPINNED`).
4. `--owner` is 64 lowercase hex digits (`CLI_HEX`) and a valid BIP-340 x-only public key (`CLI_TOKEN_OWNER_INVALID`).
5. `--amount` is above 0 and at most `i64::MAX`, the range of script integers (`CLI_TOKEN_AMOUNT_INVALID`).
6. `--pay-from`, the payer (a P2PK address of the network, of any key), and `--change` (default `--pay-from`), as in "Common arguments of the builders" (`CLI_ADDRESS_INVALID`).
7. The node (network and sync, as in "Node"), then the payer's UTXOs without a covenant ID, taken largest first and one more at a time with the fee as in "Common arguments of the builders" (`CLI_UTXO_NOT_FOUND` if there is none); the builder rules below.
8. `--out` must not exist (`CLI_OUTPUT_EXISTS`).

The transaction has the fixed fields of every Impulse transaction (`spec/IPST.md`, "Fixed transaction fields"), lock time 0, and:

- Inputs: the payer's UTXOs, each a version-0 P2PK UTXO of the key of input 0 without a covenant ID (`TX_KAS_INPUT`), with sequence `INPUT_SEQUENCE`, compute budget `P2PK_BUDGET`, that key as signer, and an empty `script_before` and `script_after`.
- Output 0, the token: `--carrier` sompi (default `MIN_KCC20_OUTPUT`, 200,000,000; at least the output's minimum, `TX_BELOW_MIN_KAS`) to the P2SH of the template holding the state {owner `--owner`, identifier type PUBKEY, amount `--amount`, not a minter}, with the covenant binding {authorizing input 0, covenant ID `covenant_id(input 0's outpoint, [(0, output 0)])`}.
- Output 1: the change to `--change`, omitted when zero, at least its minimum (`TX_BELOW_MIN_KAS`).
- There is no trade input: the carrier and the fee come from the payer's inputs. The rules of the builders apply with their codes: no outpoint twice (`TX_DUPLICATE_INPUT`), every spent UTXO and their total within the supply (`TX_UTXO_VALUE`), enough funds (`TX_INSUFFICIENT_FUNDS`), a standard change script (`TX_NONSTANDARD_CHANGE`), every mass within `STANDARD_MASS_CAP` (`TX_MASS`) and the fee at least the minimum relay fee (`TX_FEE_TOO_LOW`).

The CLI renders the transaction as an IPST that carries the token genesis terms (below), reads it back with the IPST reader (`spec/IPST.md`, "Reading an IPST") and writes the canonical text to `--out`. It prints the genesis summary: `token_genesis:` (testnet, a fixed supply), `terms_hash:` (the hash of the token genesis terms, which `ipst sign --terms-hash` takes), `owner:`, `amount:`, `template:` (hash, prefix and suffix lengths, and the pinned build) and `carrier:`; then the transaction lines and `wrote:`. The value cap is applied when the payer signs (`ipst sign`, step 10).

#### The token genesis terms

Every IPST carries terms (`spec/IPST.md`), and a genesis is not a trade. Rather than change the IPST format, which belongs to impulse-core, the CLI gives a genesis IPST terms derived from the token alone, which no trade can use. Field by field (`spec/ENCODING.md`):

| Field | Value |
| --- | --- |
| version | 1 |
| network | testnet |
| settlement_mode | Direct |
| nonce | 0 |
| seller_key | `6d755c66e18318a2ac4b2a3f0c0d517d1613dffa6ccfe5280efb000fab816b54`, a key nobody holds (below) |
| buyer_key | `b2196ec23a3f518d771a97f3fd2fce494b3e8e1b0624c7ba226adafb5bd05965`, a key nobody holds (below) |
| authority_key | none |
| asset_leg | KCC-20: the token's covenant ID, the template's hash, prefix length and suffix length, and the minted amount |
| cash_leg | KAS: the carrier, in sompi |
| buyer_delivery | KCC-20 owner, PUBKEY, the token's owner |
| seller_proceeds | the version-0 P2PK script of seller_key |
| seller_refund | KCC-20 owner, PUBKEY, seller_key |
| buyer_refund | the version-0 P2PK script of buyer_key |
| earliest_daa | none |
| expiry_daa | 1 |
| funding_mode | revocable |
| trade_ref | the genesis tag: the 24 ASCII bytes `Impulse/token-genesis/v1` followed by 8 zero bytes |

The two party keys are, for the labels `seller` and `buyer`, the first 32-byte digest that is a valid x-only key (an x-coordinate on secp256k1) among BLAKE2b-256 in keyed mode, key the 24 ASCII bytes `Impulse/token-genesis/v1`, over the ASCII label followed by a u32 counter, big-endian, from 0. Both are found at counter 0; the values above were computed in Python's `hashlib` and are checked in the tests. Nobody knows a secret key for either.

The terms pass the structure checks, so the IPST reader takes them, and their hash commits to the token: its covenant ID (which commits to the payer's input 0 and to the token output), owner, amount, template and carrier. They can never be a live trade: their expiry has passed on any chain (`TERMS_EXPIRY_NOT_AFTER_CREATION` for a command that creates or funds, `TX_EXPIRED` for a settle), and neither party key has a holder. Terms are token genesis terms when all four of these hold: `trade_ref` is the genesis tag, `seller_key` and `buyer_key` are the two party keys above, the settlement mode is Direct, and `expiry_daa` is 1. An IPST that carries them is a token genesis IPST. Whoever drafts a trade's terms chooses its `trade_ref`, so the tag alone selects nothing and reserves no `trade_ref` value (`spec/ENCODING.md`: any value is meaningful). A party to a trade holds its own party key, which is neither of the two above, so terms that carry the tag with any other party key, mode or expiry are a trade's terms, and every command treats them as it treats any trade's.

#### The genesis check

`ipst sign`, `ipst merge` and `submit` take a token genesis IPST through the genesis check in place of the terms check, and before the cancellation check, whose test a genesis also meets (Direct terms, input 0 a P2PK UTXO):

1. The terms name testnet (`CLI_TOKEN_TESTNET_ONLY`). Every command that reads an IPST refuses a mainnet genesis already; the check repeats it.
2. `--asset-template` is given (`CLI_TEMPLATE_MISSING`), is the template the terms name (`TX_TOKEN_TEMPLATE`) and is a pinned kcc20.sil build (`CLI_TOKEN_TEMPLATE_UNPINNED`).
3. The genesis is rebuilt as in "token mint build" from the document's own parts: the inputs in their order as the payer's, the document's fee, the change destination (output 1's scriptPublicKey or, without output 1, input 0's), and from the terms the owner (the identifier of `buyer_delivery`), the amount (the asset leg's) and the carrier (the cash leg's amount), with the builder rules and their codes. The two documents, terms included, are compared in canonical form with every signature left out; any difference is `IPST_TERMS_MISMATCH`. The comparison holds every field of the terms to the genesis terms of the rebuilt token, so token genesis terms that differ from them in anything else (the owner, its identifier type, the amount, the token, the carrier, a destination, the funding mode) are refused.

`ipst sign` signs a genesis with these differences from its steps:

- Step 2: the agreed terms are the token genesis terms, named with `--terms-hash` (the `terms_hash:` line of `token mint build`). That hash comes from whoever built the document, so it holds the payer to that document and gives no protection against its builder: it does not tell the payer which owner and amount it pays for. A payer signs only a genesis it built itself, as runbook 1.1 does, or reads the owner (`buyer_delivery`) and the amount (the asset leg's) in the IPST's terms before signing; `ipst sign` prints the genesis summary only once it has signed. There is no separate confirmation of the owner and the amount (owner decision of 2026-10-11, default applied).
- Step 3: the signer signs as `--role payer`. The genesis terms' party keys have no holder, so any other role is `CLI_ROLE_KEY_MISMATCH`.
- Step 5 is the genesis check. `--carrier` (default `MIN_KCC20_OUTPUT`) must equal the KAS on output 0 (`CLI_TOKEN_CARRIER_MISMATCH`); `--authorizer` is `TX_WRONG_MODE`.
- Step 7: a genesis is not a trade, so no trade value is checked; the value cap holds what the signer commits (step 10).
- Step 9: what the payer's inputs put into output 0 is a deposit, not a top-up, so `--max-topup` does not apply. The change and fee checks apply.
- Step 10: the trade takes `--carrier` from the signer.
- It prints the genesis summary in place of the terms summary.

`ipst merge` and `submit` take `--asset-template` for the genesis check; `submit` then finalizes and submits as for any IPST. The transaction lines of a genesis name it `ipst: token genesis` and end with `token: <txid>:0:<amount>`, the new token in the `--token` form `fund build` takes, and `covenant: <hex>`, its covenant ID.

#### token list

`impulse token list --node <url> --template <file> --owner <hex> --covenant <hex> --amount <units>`

A read-only lookup. Checks 1 to 5 of "token mint build", and `--covenant` is 64 lowercase hex digits (`CLI_HEX`); then the node (network and sync), then the UTXOs it reports at the P2SH of the template holding {owner `--owner`, identifier type PUBKEY, amount `--amount`, not a minter} with covenant ID `--covenant`, lowest outpoint first. None is `CLI_UTXO_NOT_FOUND`. It prints `network:`, `template:`, `owner:`, `covenant:` and, per UTXO, `token: <txid>:<index>:<amount>` and `token_kas: <sompi>`. A token UTXO's script holds its amount, so the lookup needs it: after a funding, the depositor's remaining token is found under the amount of the funding's `token change:` line.

### Offline fake node (tests only)

A build with the cargo feature `offline-fake-node`, which is off by default and absent from release builds, also accepts node URLs of the form `fake://<path of a state file>`, and the hidden command `impulse fake-node` that creates such a file and gives it UTXOs. The fake node holds a linear chain, a UTXO set and the virtual DAA score in that file. On submit it applies the node rules a test needs: every input unspent, the lock time by `locktime::check_tx_is_finalized`, every input run in the pinned script engine (`kaspa-txscript` at a41a333, covenants enabled) at its committed budget, outputs no more than inputs; it then adds a chain block that accepts the transaction. Every `get_block_dag_info` call advances the virtual DAA score by the state's tick, so a test can wait for an expiry, and `impulse fake-node advance --state <file> --daa <n>` adds n at once. It exists to test the CLI and the scripts end to end without a network; it is not a node and proves nothing about one.

## Error codes

Codes of the CLI's own refusals. Terms and template refusals keep their `TERMS_*` and `TEMPLATE_*` codes. `spec/ERRORS.md` (I10) will absorb this table; the list may only grow.

| Code | Meaning |
| --- | --- |
| `CLI_FILE_READ` | An input file cannot be read, or is larger than its type's size cap (read only up to the cap) |
| `CLI_FILE_WRITE` | An output file cannot be written |
| `CLI_OUTPUT_EXISTS` | The output path already exists |
| `CLI_TERMS_JSON` | A draft or terms file is not the JSON form of terms |
| `CLI_TERMS_FILE_INCONSISTENT` | A terms file's `terms`, `canonical` and `terms_hash` disagree |
| `CLI_NETWORK_MISMATCH` | The terms or receipt name another network than the command acts on |
| `CLI_HEX` | A hash, txid or key argument is not 64 lowercase hex digits |
| `CLI_URI_MALFORMED` | Funding URI check 1 |
| `CLI_URI_TERMS_HASH_MISMATCH` | Funding URI check 2 |
| `CLI_URI_ADDRESS_MISMATCH` | Funding URI check 3 |
| `CLI_URI_LEG_NOT_KAS` | Funding URI check 4 |
| `CLI_URI_AMOUNT_MISMATCH` | Funding URI check 5 |
| `CLI_VALUE_CAP_INVALID` | `IMPULSE_MAX_VALUE` does not parse or is above the default |
| `CLI_VALUE_UNKNOWN` | A leg is not native KAS and no nonzero `--kas-equivalent` was given |
| `CLI_VALUE_CAP_EXCEEDED` | The trade value is above the cap (v4: funding only; a v4 settle or refund warns instead, I21) |
| `CLI_NODE_URL_INVALID` | The node URL is not `ws://` or `wss://` |
| `CLI_NODE_UNREACHABLE` | The connection to the node failed |
| `CLI_NODE_RPC` | An RPC call failed or returned something malformed |
| `CLI_NODE_NETWORK_MISMATCH` | The node is on another network |
| `CLI_NODE_NOT_SYNCED` | The node is not synced |
| `CLI_NODE_TXID_MISMATCH` | The node returned another transaction ID than the one submitted |
| `CLI_TX_NOT_ACCEPTED` | The transaction is not accepted on the chain walked from `--from-block` |
| `CLI_QR` | The URI does not fit a QR code |
| `CLI_ROLE_KEY_MISMATCH` | `--my-key` is not the terms' party key for `--role` |
| `CLI_DESTINATION_NOT_MINE` | A delivery, proceeds or refund destination of the user's role pays the counterparty or the authority, differs from its pin, or without a pin does not pay `--my-key` |
| `CLI_DEPTH_BELOW_MINIMUM` | `status --key-file`: the depth is below `--min-depth`; nothing is signed |
| `CLI_NODE_INSECURE` | On mainnet, the node URL is neither `wss://` nor `ws://` to a loopback host |
| `CLI_MAINNET_NEEDS_NODE` | On mainnet, `--daa` was given: the creation DAA score must come from `--node` |
| `CLI_DESTINATION_PIN_INVALID` | A `--my-delivery`, `--my-proceeds` or `--my-refund` pin does not parse, names another network, or names a destination the role does not have |
| `CLI_URI_NOT_YOUR_LEG` | Funding URI check 7: the URI funds the vault of the counterparty's leg |
| `CLI_KAS_LEG_BELOW_MIN` | The KAS cash leg is below `MIN_KAS_OUTPUT`: it has no standard settle; refused before funding |
| `CLI_TEMPLATE_UNPINNED` | `address`, `verify`, `fund build`, `ipst sign` of a funding: a KCC-20 leg's template is not a pinned kcc20.sil build |
| `CLI_TEMPLATE_MISSING` | A KCC-20 template the command needs was not given |
| `CLI_FUND_NOT_YOUR_LEG` | `fund build`: the leg is the counterparty's to fund, or `--pay-from` is not the P2PK address of `--my-key`; `ipst sign`: the funding is not the signer's leg |
| `CLI_ADDRESS_INVALID` | `--pay-from` is not a P2PK address of the network, or `--change` not a standard address of the network |
| `CLI_OUTPOINT_INVALID` | An outpoint or token argument is not `<txid>:<index>` or `<txid>:<index>:<amount>` |
| `CLI_UTXO_NOT_FOUND` | A UTXO the command looks for is not in the node's UTXO set |
| `CLI_UTXO_AMBIGUOUS` | `refund build`: several UTXOs at the vault and no `--vault-utxo` |
| `CLI_IPST_NOTHING_TO_SIGN` | `ipst sign`: no unsigned slot is for `--my-key` |
| `CLI_IPST_CHANGE_NOT_MINE` | `ipst sign` of a fee input: the change does not pay `--change` or the P2PK of `--my-key` |
| `CLI_IPST_FEE_TOO_HIGH` | `ipst sign` of a fee input: the fee is above `--max-fee` (default twice the minimum relay fee), or the signer signs more than three fee inputs and `--max-fee` is not given |
| `CLI_TX_NOT_FINAL` | `submit`: the node would not yet accept the transaction's lock time |
| `CLI_IPST_TERMS_NOT_AGREED` | `ipst sign`: the IPST is for other terms than `--terms` or `--terms-hash` |
| `CLI_IPST_DEPOSIT_MISMATCH` | `ipst sign` of a KCC-20 funding: the carrier or authorizer KAS differs from `--carrier` or `--authorizer` |
| `CLI_IPST_TOPUP_TOO_HIGH` | `ipst sign` of a fee input of a settle, refund or Direct transaction: the payer cost beyond the fee is above `--max-topup` (default 0) |
| `CLI_IPST_OUTFLOW_TOO_HIGH` | `ipst sign`: the inputs the signer signs hold more of its KAS, less what comes back to it, than the trade takes plus `--max-fee` and `--max-topup` |
| `CLI_CANCEL_NOT_DIRECT` | `direct cancel build`: the terms are vault terms, whose legs go home with `refund build` |
| `CLI_CANCEL_INPUT_NOT_KAS` | `direct cancel build`: the role's Direct input is a KCC-20 token, which no builder spends back to its holder |
| `CLI_CANCEL_INPUT_AMBIGUOUS` | `direct cancel build`: several UTXOs of exactly the cash amount at the buyer's address, and neither `--for-ipst` nor `--direct-input` names one |
| `CLI_CANCEL_INPUT_MISMATCH` | `direct cancel build --for-ipst`: the IPST is not a Direct transaction of `--terms` whose input 1 is the buyer's exact KAS cash, or `--direct-input` names another UTXO |
| `CLI_TOKEN_TESTNET_ONLY` | `token mint build` or `token list` on mainnet, or a token genesis IPST whose terms name mainnet: the token helper acts on testnet only |
| `CLI_TOKEN_OWNER_INVALID` | `token mint build`, `token list`: `--owner` is not a valid x-only public key |
| `CLI_TOKEN_AMOUNT_INVALID` | `token mint build`, `token list`: `--amount` is 0 or above `i64::MAX` |
| `CLI_TOKEN_TEMPLATE_UNPINNED` | `token mint build`, `token list`, or the genesis check: the KCC-20 template is not a pinned kcc20.sil build |
| `CLI_TOKEN_CARRIER_MISMATCH` | `ipst sign` of a token genesis: the KAS on the token output differs from `--carrier` |

Signing codes (`SIGN_*`) are listed above. Receipt codes: `RECEIPT_MALFORMED`, `RECEIPT_SIGNATURE_INVALID`, `RECEIPT_SIGNER_MISMATCH`, `RECEIPT_DAA_MISMATCH`, `RECEIPT_NOT_ACCEPTED`, `RECEIPT_DEPTH_UNREACHED`, `RECEIPT_TERMS_MISMATCH`, `RECEIPT_TXID_MISMATCH`, `RECEIPT_QUANTITY_MISSING`, `RECEIPT_QUANTITY_MISMATCH`, `RECEIPT_LINEAGE_MISMATCH` (version 2 receipts, below).

## impulse xchain (I18, v0.2)

The hashlock commands (`impulse xchain new`, `verify`, `fund build`, `verify-counterpart`, `counterpart-claim`, `watch`, `claim`, `refund`, `sign`, `submit`, `status`, `daa-sample`) are specified in `spec/V2.md` section 10.9, with their own `XCHAIN_` codes (`spec/ERRORS.md`). They follow the conventions of this file and return its `CLI_` and `SIGN_` codes where the meaning is unchanged. On mainnet they run under the per-trade value cap with race R2 disclosed (owner decisions D39 and D40, 2026-10-15); `XCHAIN_MAINNET_GATED` is reserved and no longer returned. Their partially signed transaction is the version 3 document of `spec/V2.md` section 10.9; `ipst sign`, `ipst merge` and `submit` of this file read version 1 only and refuse it (`IPST_UNSUPPORTED_VERSION`).

## Settlement receipt, version 2 (I17)

`impulse v2 status --key-file <file> --out <file> --min-depth <n> [--previous <receipt>]` signs, for a transaction that is a v2 settle of the terms (every vault input reveals the terms' v2 vault script, `impulse_core::v2::read_settle`), one receipt per transaction, so one per tranche. Keys, in order: `version` (`2`), `network`, `terms_hash`, `txid`, `accepting_block`, `daa_score`, `depth`, `state` (`accepted`, the only state a receipt names, spec/V2.md 4.8), `lots` (lots moved by this transaction, decimal string), `cumulative_lots`, `total_lots` (the terms' lot count), `prior_receipt` (digest of the previous receipt of the lineage, 32 zero bytes for the first), `legs` (array, one object per leg with `moved`, `cumulative`, `total` as decimal strings, `spent_txid`, `spent_index`, `covenant` and `continuation`, hex or null), `signer`, `signature`.

Digest: BLAKE2b-256, keyed with the 18 ASCII bytes `Impulse/receipt/v2`, over: the 114 canonical bytes of version 1 with the first byte `2`; lots, cumulative_lots, total_lots u64 little-endian; prior_receipt 32; leg count u32 little-endian; per leg moved, cumulative, total u64 little-endian, spent txid 32, spent index u32 little-endian, covenant 32, continuation 32 (zero when none). Known answer in `receipt_v2::tests::digest_known_answer`, checked against Python's `hashlib`.

`impulse v2 receipt verify --receipt <file> [--signer] [--terms | --terms-hash] [--txid] [--previous <receipt>] [--node]` stops at the first refusal: the form (`RECEIPT_MALFORMED`, a missing quantity field `RECEIPT_QUANTITY_MISSING`); the signature; signer, terms hash and txid as version 1; with `--terms`, the quantities against the terms (`RECEIPT_QUANTITY_MISMATCH`); with `--previous`, its signature and the chain (`RECEIPT_LINEAGE_MISMATCH`, `RECEIPT_QUANTITY_MISMATCH`); with `--node`, the acceptance as version 1 and, with `--terms`, the transaction read again and its lots, spent outpoints and covenant IDs compared with the receipt. The quantity is not enforced across tranches by the contract (spec/V2.md 4.6): the receipt states it, and a receipt without those fields is not read. Without `--previous` the lineage before this transaction is not covered, and the output says so. `v2 status --key-file` verifies a `--previous` receipt (signature, then its quantities against the terms: `RECEIPT_SIGNATURE_INVALID`, `RECEIPT_QUANTITY_MISMATCH`) before it chains onto it, and without `--previous` it refuses (`RECEIPT_LINEAGE_MISMATCH`) when a KAS leg's vault held fewer lots than the terms' lot count, since earlier tranches then exist. A trade whose legs are all KCC-20 cannot be checked this way: its first-receipt claim stays the signer's assertion (D114).

## impulse linked (I22, v0.3)

Two linked trades, an opening and a return, described by one sheet (`V2.md` section 17). Each is an ordinary template v2 trade; the commands add the sheet checks and, for the return, the opening gate. The command reads no key file except `linked receipt sign`, which passes the file to the signing module. Mainnet needs `--network mainnet`; template v2 vaults wait for the freeze (D30).

| Command | Does |
| --- | --- |
| `linked new --draft <file> --return-amount-0 <n> --return-amount-1 <n> --return-earliest-daa <n> --return-expiry-daa <n> --out <sheet> [--node <url> \| --daa <n>]` | Reads an opening draft (terms v2 JSON with an all-zero `trade_ref`), runs the sheet checks and the opening's creation checks, writes the sheet file (`sheet`, `canonical`, `linked_hash`) and prints both trades. Refuses to overwrite. |
| `linked show --sheet <file> [--my-key <hex>]` | Prints both trades, what each party deposits and gets back, the difference per asset and the exposure sentences. |
| `linked terms --sheet <file> --role opening\|return --out <file>` | Writes the derived terms v2 file of the role, the file `v2 address`, `v2 verify`, `v2 ipst sign` and `v2 status` read. |
| `linked check --sheet <file> --role <role> --terms <file>` | Checks that the terms file is exactly the role's derived trade (`LINKED_NOT_A_LEG`, `LINKED_ROLE_MISMATCH`, `LINKED_TRADE_REF`). |
| `linked return-gate --sheet <file> --node <url> --opening-txid <txid> --opening-from-block <hash> --min-depth <DAA>` | Reads the node: the opening's settle must be accepted at that depth and must settle both opening vaults. Prints the transaction, block, DAA score and depth. Read only. |
| `linked fund build`, `linked settle build`, `linked refund build` | `--sheet <file> --role <role>`, then the arguments of `v2 fund build`, `v2 settle build` and `v2 refund build`. The return's fund and settle also take `--opening-txid`, `--opening-from-block` and `--min-depth` (no default) and run the gate first (`LINKED_OPENING_NOT_SETTLED`, `LINKED_SETTLE_EVIDENCE`, `CLI_TX_NOT_ACCEPTED`, `CLI_DEPTH_BELOW_MINIMUM`). The refund takes no gate. Nothing is written if either part refuses. |
| `linked receipt sign --sheet <file> --role <role> --node <url> --txid <txid> --from-block <hash> --min-depth <DAA> --key-file <file> --out <file>` | Finds the role's settle on the node at that depth, checks it settles the role's two vaults, and signs a linked receipt (`V2.md` 17.8). |
| `linked receipt verify --receipt <file> --sheet <file> [--signer <hex>] [--txid <txid>] [--node <url>]` | Verifies the signature and that the receipt names the sheet and the role's derived trade; with `--node`, the chain facts. |
| `linked receipt pair --opening <file> --return <file> --sheet <file> [--signer <hex>]` | Accepts an opening receipt and a return receipt only if both name the sheet's `linked_hash`, distinct transactions, and the return is later. |
