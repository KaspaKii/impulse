# TypeScript SDK reference

The SDK is `impulse-core` compiled to WebAssembly (`crates/impulse-wasm`) with a thin ES module in front. Every operation is implemented once, in Rust; the JavaScript only re-exports the generated bindings. This page is the task-oriented reference. The package's own [README](../../crates/impulse-wasm/npm/README.md) is the long form (every refusal case and the reasons behind them), and the types are in `crates/impulse-wasm/npm/index.d.ts` and the generated `pkg/impulse_wasm.d.ts`. Where this page and the code differ, the code and the specs are right. The terms JSON form is defined in [spec/ENCODING.md](../../spec/ENCODING.md), the transactions in [spec/TRANSACTIONS.md](../../spec/TRANSACTIONS.md), the interchange document in [spec/IPST.md](../../spec/IPST.md).

Status: the package is `@warpcore/impulse` (name pending) and is `"private": true` until the release increment, so it is not on npm. Use only values you can lose.

Keys: the SDK never takes a secret key. A signature reaches it as 65 bytes made elsewhere. The one class that holds a key is `Wallet`, which draws its own key in the module and never hands it out (see [Wallet](#wallet)).

v0.2 and v0.3 add basket and partial settlement, a cross-chain hashlock leg, ZK settle, linked trades and the hashed-terms vault. They are not in this package; see `spec/V2.md` and `spec/V3-ZK.md` on the release branches.

## Build and load

Build the package from the repository (needs the pinned toolchain and Node 22.18 or later; `crates/impulse-wasm/ci.sh` lists the pins and runs the whole gate):

```sh
cd crates/impulse-wasm
./ci.sh
```

The build leaves `crates/impulse-wasm/npm/pkg/`. The module is initialised once before any call.

Node:

```js
import { readFileSync } from "node:fs";
import { initSync, Terms } from "@warpcore/impulse";
initSync({ module: readFileSync(new URL(import.meta.resolve("@warpcore/impulse/impulse_wasm_bg.wasm"))) });
```

Browser, with `pkg/impulse_wasm_bg.wasm` served next to the module:

```js
import init, { Terms } from "@warpcore/impulse";
await init();
```

Import the package entry only. The generated module also carries wasm-bindgen exports of linked rusty-kaspa crates that the entry deliberately does not export.

## Conventions

- A u64 argument or field is a decimal string (a scalar argument also takes a `bigint`); a result amount is a decimal string.
- Bytes are `Uint8Array`. Hex fields of the JSON forms are lowercase.
- A leg index is the number `0` (asset) or `1` (cash). A network is `"mainnet"` or `"testnet"`.
- JSON forms are plain objects with exactly the keys of the type; an unknown, missing or duplicate key is `SDK_JSON_FORM`.
- Every refusal throws `ImpulseError` with a stable `code` ([Errors](#errors)).
- Objects returned from the module own WebAssembly memory; call `.free()` when done with a long-lived one.

## Quick start: terms to funding address

This example was run against the built package with the golden vector `tests/vectors/terms/01-vault-authority-earmarked-kcc20-kcc20.json`. The terms hash it prints equals the `terms_hash` in that file.

```js
import { readFileSync } from "node:fs";
import { initSync, Terms } from "@warpcore/impulse";

initSync({ module: readFileSync(new URL(import.meta.resolve("@warpcore/impulse/impulse_wasm_bg.wasm"))) });

// Read a terms file (or the bare JSON form). The text, not a parsed object, is the argument:
// JSON.parse would keep the last of two equal keys and read a number past 2^53 inexactly.
const text = readFileSync("tests/vectors/terms/01-vault-authority-earmarked-kcc20-kcc20.json", "utf8");
const validated = Terms.fromFileText(text).validateStructure();
console.log(Buffer.from(validated.termsHash()).toString("hex"));
// a893ed5e7dfd3558159a58f449b0d7b562901c5edeb7c79a38283787aa652b34

// The creation context: the DAA score comes from a node you trust. The SDK has no node.
const ctx = { network: "mainnet", creation_daa: "400000000" };
validated.validateCreation(ctx);                       // throws on a refusal

// Leg 0 (asset). The last argument is the value declaration (see Value cap).
const fundable = validated.instantiateForCreation(0, ctx, { kas_equivalent: "100000000" });
console.log(fundable.address());                       // the leg's vault address
```

The same vector fails closed when the value is too high or undeclared:

```js
try {
  validated.instantiateForCreation(0, ctx, { kas_equivalent: "2000000000" });
} catch (e) {
  console.log(e.name, e.code); // ImpulseError SDK_VALUE_CAP_EXCEEDED
}
try {
  validated.instantiateForCreation(0, ctx, {});
} catch (e) {
  console.log(e.name, e.code); // ImpulseError SDK_VALUE_UNKNOWN
}
```

## Value cap

The SDK refuses a trade above a per-trade cap (default 10 KAS, `defaultValueCapSompi()`), before it does anything else. Every builder, `instantiateForCreation`, the address checks and `verifyAgainstTerms` take the declaration as their last argument:

```js
{ kas_equivalent: "100000000" }                  // KAS value of the larger leg, in sompi
{ kas_equivalent: "1", max_value: "50000000" }   // a lower cap
{ i_accept_the_risk: true }                      // the only way to lift the cap
```

In v0.1 the asset leg is always a KCC-20 token whose value the SDK cannot know, so `kas_equivalent` (nonzero) is required unless the cap is lifted. It is the caller's word and nothing checks it. `max_value` can only lower the cap. Codes: `SDK_VALUE_UNKNOWN`, `SDK_VALUE_CAP_EXCEEDED`, `SDK_VALUE_CAP_INVALID`. The rule mirrors the CLI's ([spec/CLI.md](../../spec/CLI.md), "Value cap"); the package README lists where it does and does not hold.

## Terms

| Call | Returns |
| --- | --- |
| `Terms.fromJson(json)` | `Terms` from the JSON form |
| `Terms.fromFileText(text)` | `Terms` from the text of a bare JSON form, a terms file or a golden vector file; refuses duplicate keys and inconsistent `canonical` or `terms_hash` |
| `Terms.decode(bytes)` | `Terms` from canonical bytes |
| `terms.toJson()`, `terms.encode()`, `terms.termsHash()` | JSON form, canonical bytes, the 32-byte terms hash |
| `terms.requireSameAs(other)` | nothing; throws `SDK_TERMS_INCONSISTENT` unless equal |
| `terms.validateStructure()` | `ValidatedTerms` |
| `ValidatedTerms.decode(bytes)` | `ValidatedTerms` from canonical bytes |
| `validated.terms()`, `.canonical()`, `.termsHash()` | the terms, canonical bytes, the hash |
| `validated.validateCreation(ctx)` | nothing; throws a `TERMS_*` code. `ctx` is `{ network, creation_daa, max_expiry_horizon_daa? }` |

Constants: `termsVersion()`, `termsHashDomain()`, `maxScriptLen()`, `maxTemplateLen()`, `defaultMaxExpiryHorizonDaa()`, `contractName()`.

## Vaults and addresses

| Call | Returns |
| --- | --- |
| `templateCheck()` | `Template` with `.hash()`, `.prefix()`, `.suffix()`; its hash is the template hash pinned in `contracts/TEMPLATE_HASH` |
| `validated.instantiateExisting(leg)` | `Vault` (no address; for reading an existing trade) |
| `validated.instantiateForCreation(leg, ctx, value)` | `FundableVault` after the value cap and the creation checks |
| `fundable.address()`, `fundable.vault()` | the funding address, the `Vault` |
| `vault.network()`, `.leg()`, `.redeemScript()`, `.scriptPublicKey()`, `.scriptHash()` | the vault's parts |
| `decodeVault(redeemScript)` | `DecodedVault` with `.terms()` and `.leg()` |
| `templateHashOfInstance(script)` | the template hash of an instance |
| `addressPrefix(network)` | `"kaspa"` or `"kaspatest"` |
| `kcc20Template(artifact)`, `kcc20ScriptPublicKey(artifact, state)` | a KCC-20 leg's template triple; the scriptPublicKey of a token UTXO in a state |
| `pinnedKcc20Templates()` | the sixteen pinned kcc20.sil builds (silverscript v1.0.0) |

Only `FundableVault` has `address()`, and only `instantiateForCreation` makes one, so a funding address cannot be derived without the creation checks and the value cap.

## Funding instructions and the role check

```js
const instructions = validated.fundingInstructions({
  context: ctx,
  creation_daa_source: "node",        // mainnet refuses a typed creation score
  party: { role: "seller", key: "<64 hex digits: your x-only public key>" },
  kas_equivalent: "100000000",
});
const check = validated.roleCheck({ role: "seller", key: "<same key>" });
```

`fundingInstructions` is the SDK's `impulse address`; it returns nothing until every check has passed, in the order the package README gives. Terms whose KCC-20 template is not a pinned kcc20.sil build are refused with `SDK_TEMPLATE_UNPINNED`: run against the golden vector `01-...` above, which names an unpinned template, it throws that code, as `instantiateForCreation` does not (it does not check the pins). `roleCheck` throws `SDK_ROLE_KEY_MISMATCH` unless the key is the role's party key, and `SDK_DESTINATION_NOT_MINE` when a destination of your role does not pay you. Run against the vector above, `roleCheck({ role: "seller", key: <seller key> })` returns the lines `seller_proceeds pays your key` and `seller_refund pays your key`; with the buyer's role and the seller's key it throws `SDK_ROLE_KEY_MISMATCH`.

Helpers: `qrCode(text)` returns `{ width, modules }`; `kasFromSompi(sompi)` formats an amount (`"100000000"` gives `1.00000000`).

## Transactions

Builders are methods of `ValidatedTerms`, so a builder works only from checked terms. Each takes JSON-form UTXOs as a node reports them (`UtxoJson`, `TokenUtxoJson`, `FeePaymentJson`) and returns an unsigned `Ipst`.

| Call | Builds |
| --- | --- |
| `validated.fundKas(context, funding, value)` | funding of a native KAS cash vault |
| `validated.fundKcc20(leg, context, deposit, funding, value)` | funding of a KCC-20 leg (token escrow) |
| `validated.settle(legs, funding, currentDaa, value)` | the settle transaction of vault terms |
| `validated.refund(leg, signer, vaultUtxo, escrow \| null, funding, value)` | a refund of one vault UTXO; `signer` is `"depositor"`, `"counterparty"` or `"authority"` |
| `validated.direct(legs, funding, currentDaa, value)` | the Direct transaction |

Plan builders work from the text of a node's `getUtxosByAddresses` reply, so no UTXO list passes through JavaScript: `settleAddresses`, `refundAddresses`, `directAddresses`, `fundCashAddresses` name the addresses to ask about; `settleFromReply`, `refundFromReply`, `directFromReply`, `fundCashFromReply` choose the UTXOs by fixed rules and build the transaction (rules: the top of `crates/impulse-wasm/src/plan.rs`).

KCC-20 templates are passed as the text of the token's silverscript ABI artifact (the JSON `silverc` writes), in `deposit.artifact`, `legs.asset_artifact`, `legs.cash.artifact` and `escrow.artifact`. Use the token publisher's reproducible build, never one the counterparty supplies.

### The IPST document

| Call | Does |
| --- | --- |
| `Ipst.fromJson(text)`, `ipst.toJson()` | read and write the interchange document |
| `ipst.terms()`, `.fee()`, `.masses()`, `.pending()`, `.isComplete()`, `.slots()` | inspect it; `slots()` names the key each input needs |
| `ipst.verifyAgainstTerms({ asset, cash }, currentDaa, value)` | rebuild the transaction from the document's own inputs and compare; throws `IPST_TERMS_MISMATCH` on a wrong document |
| `ipst.review(artifacts, currentDaa, value, held?)` | what a signer reads before signing: title, inputs and outputs with labels, fee, masses |
| `ipst.sighash(input)` | the 32 bytes to sign for an input |
| `ipst.addSignature(input, signature)` | verify and store a 65-byte signature |
| `ipst.combine(otherJsonText)` | merge another copy's signatures; any other difference is `IPST_CONFLICT` |
| `ipst.finalize()`, `ipst.assemble([{ input, signature }])` | a `SignedTransaction` with `.txid()` and `.raw()` |
| `verifySchnorrSig65(pubkeyXonly, sighash, signature)` | check a 65-byte signature |

### The flow

```js
// 1. Build (the inputs come from your node; values here are placeholders you supply).
const ipst = validated.settle(legs, funding, currentDaa, { kas_equivalent: "100000000" });

// 2. Check before anyone signs. Throws if the document is not what the builders make.
const review = ipst.verifyAgainstTerms({ asset: assetArtifact, cash: null }, currentDaa, { kas_equivalent: "100000000" });

// 3. Sign outside the SDK. slots() names the key each input needs; sighash(i) is what to sign.
//    `signWithMyKey` is your own code (BIP-340 Schnorr over the sighash, then the byte 0x01).
for (const slot of ipst.slots()) {
  if (slot.signer === myPublicKeyHex && slot.signature === null) {
    ipst.addSignature(slot.input, signWithMyKey(ipst.sighash(slot.input)));
  }
}

// 4. Merge the copies other signers return, then assemble.
const merged = Ipst.fromJson(ipst.toJson()).combine(otherSignersCopy);
const signed = merged.finalize();       // checks masses and the relay fee again
signed.txid();                          // the transaction ID
signed.raw();                           // rusty-kaspa borsh bytes, the form decodeRaw reads
```

The exercise of this flow, with runtime throwaway keys, for every trade mode, is the test `crates/impulse-wasm/npm/test/trade.test.ts`; the flow above is a sketch with your own inputs and signer in place of its fixtures. `ipst.verifyAgainstTerms` is the signer's responsibility: a signature is made outside the SDK, so the SDK cannot make a signer run it, and a signer that signs without it signs without the value cap.

## Wallet

For the browser demo, a key the module draws once and never hands out.

```js
const wallet = Wallet.generate();         // one crypto.getRandomValues call, 32 bytes
wallet.publicKey();                       // x-only, 64 hex digits
wallet.address("testnet");                // its P2PK address
const { ipst: signedCopy, signed_inputs } = wallet.sign(ipst, {
  artifacts: { asset: assetArtifact, cash: null },
  current_daa: currentDaa,
  value: { kas_equivalent: "100000000" },
  mainnet: false,
});
wallet.wipe();                            // zeroes the key; wallet.isWiped() is now true
```

`sign` runs the same checks as `impulse ipst sign` in the same order (explicit mainnet choice, a slot for this key, `verifyAgainstTerms`, the funding checks, the role check, the fee, change and outflow limits). Options `pins`, `held`, `change`, `max_fee`, `max_topup`, `carrier` and `authorizer` mirror the CLI's flags; the package README documents each. No member returns the key. A wallet's key exists only in the page's memory: anything sent to it is lost with the page, and on mainnet the SDK refuses a destination that pays a key it knows only a wallet holds (`SDK_DESTINATION_IN_WALLET`).

## Verifying and decoding

| Call | Does |
| --- | --- |
| `validated.verifyAddresses(context, { asset, cash }, value)` | recompute each leg's address from the terms and compare with the one offered |
| `validated.beforeFunding(context, offered, evidence, value)` | the address check plus the token warnings |
| `validated.tokenWarnings(evidence)` | `TOKEN_*` warnings as data, never a statement that a token is safe |
| `validated.verifyRevealedScript(leg, script)` | whether a revealed script is this leg's vault |
| `validated.verifySpentInput(leg, signatureScript, spent)` | check a spent input against the scriptPublicKey the node reports for it |
| `decodeRaw(raw, spent, network)` | find the vault inputs of a transaction and say what each does, bound to the scriptPublicKeys they spend |
| `decodeRawUnbound(raw, network)` | the same without the binding; the result says `bound: false` |

A warning list that is empty is not a safety claim, and `token_legs_assessed: false` must not be shown as checked.

## Node forms

The SDK has no socket. The page opens the WebSocket to a node started with `--rpclisten-json` and hands the text of each reply to the SDK.

```js
import { rpcMethods, rpcRequest, rpcReply } from "@warpcore/impulse";

rpcMethods();
// ["getServerInfo","getBlockDagInfo","getUtxosByAddresses","submitTransaction","getMempoolEntry","getVirtualChainFromBlockV2"]
rpcRequest(1, "getServerInfo", null);   // the JSON text to send: {"id":1,"method":"getServerInfo","params":{}}
// ... send it, receive replyText ...
const info = rpcReply(replyText, 1, "getServerInfo");   // refuses a reply to another request or an error
```

Also: `rpcSubmitRequest(id, signed)`, `rpcTransactionReply(text, id, method, txid)`, `rpcSubmitReply(text, id, signed)` (returns the txid), `checkNodeUrl(url, network)` and `checkNode(serverInfo, network)` (the URL rule: on mainnet only `wss://` or `ws://` to `127.0.0.1` or `localhost`), and `decodeFetched(fetched, txid, network)`.

## Errors

Every refusal throws an `Error` named `ImpulseError` with a stable `code`. Match on the code, never on the message.

```js
try {
  validated.validateCreation(ctx);
} catch (e) {
  if (e.name === "ImpulseError") console.error(e.code); // e.g. TERMS_EXPIRY_NOT_AFTER_CREATION
  else throw e;
}
```

`e.nodeError === true` only when the node itself answered the very request with an error: a caller that sent a transaction then knows the node refused it. It is absent on every other error, including an unreadable reply, after which what the node did is unknown. Code lists are `termsErrorCodes()`, `templateErrorCodes()`, `txErrorCodes()`, `verifyErrorCodes()`, `decodeErrorCodes()`, `tokenWarningCodes()` and `sdkErrorCodes()`. The meaning and remedy of each code are in [ERRORS.md](ERRORS.md) and [spec/ERRORS.md](../../spec/ERRORS.md).

## Tests and further reading

- Run the gate: `crates/impulse-wasm/ci.sh` (a step of `scripts/ci-local.sh`). The TypeScript tests in `crates/impulse-wasm/npm/test/` are the best worked examples: `vectors.test.ts` checks the golden vectors through the SDK, `trade.test.ts` runs every trade mode end to end.
- The browser demo ([demo/README.md](../../demo/README.md)) is built on this SDK.
- [CLI.md](CLI.md) is the command-line counterpart of each operation.
