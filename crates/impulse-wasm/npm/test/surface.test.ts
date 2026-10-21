// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The package's public surface: exactly impulse-core's phase 1 and phase 2 API, its constants and
// its code lists, which must equal the code tables of spec/ENCODING.md, spec/TEMPLATE.md,
// spec/TRANSACTIONS.md, spec/IPST.md and spec/VERIFY.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as entry from "../index.js";
import { hex, load, root } from "./sdk.ts";

const sdk = load();

test("the package entry exports impulse-core's phase 1 and phase 2 surface, the funding helpers and nothing else", () => {
  assert.deepEqual(Object.keys(entry).sort(), [
    "DecodedVault",
    "FundableVault",
    "Ipst",
    "IpstV2",
    "SignedTransaction",
    "Template",
    "Terms",
    "TermsV2",
    "ValidatedTerms",
    "ValidatedTermsV2",
    "Vault",
    "Wallet",
    "addressPrefix",
    "capsV2",
    "checkNode",
    "checkNodeUrl",
    "contractName",
    "decodeErrorCodes",
    "decodeFetched",
    "decodeRaw",
    "decodeRawUnbound",
    "decodeVault",
    "default",
    "defaultMaxExpiryHorizonDaa",
    "defaultMaxValueSompi",
    "defaultValueCapSompi",
    "initSync",
    "ipstVersion",
    "kasFromSompi",
    "kcc20ScriptPublicKey",
    "kcc20Template",
    "maxLegs",
    "maxScriptLen",
    "maxTemplateLen",
    "minKasOutput",
    "minKcc20Output",
    "minRelayFee",
    "pinnedKcc20Templates",
    "qrCode",
    "rpcMethods",
    "rpcReply",
    "rpcRequest",
    "rpcSubmitReply",
    "rpcSubmitRequest",
    "rpcTransactionReply",
    "sdkErrorCodes",
    "standardMassCap",
    "templateCheck",
    "templateErrorCodes",
    "templateHashOfInstance",
    "templateHashV2",
    "termsErrorCodes",
    "termsHashDomain",
    "termsV2Version",
    "termsVersion",
    "tokenWarningCodes",
    "txErrorCodes",
    "v2ErrorCodes",
    "verifyErrorCodes",
    "verifySchnorrSig65",
]);
});

test("index.d.ts declares exactly the values the entry exports", () => {
  // A name declared there but not exported would type-check and fail at run time.
  const text = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const values = text.match(/^export \{([^}]*)\} from/m);
  assert.ok(values, "a value export block");
  const declared = values[1].split(",").map((name) => name.trim()).filter((name) => name !== "");
  assert.deepEqual(declared.sort(), Object.keys(entry).sort());
});

test("constants are impulse-core's", () => {
  assert.equal(sdk.termsVersion(), 1);
  assert.equal(hex(sdk.termsHashDomain()), Buffer.from("Impulse/terms/v1").toString("hex"));
  assert.equal(sdk.maxScriptLen(), 10_000);
  assert.equal(sdk.maxTemplateLen(), "1000000");
  assert.equal(sdk.defaultMaxExpiryHorizonDaa(), "315360000");
  assert.equal(sdk.contractName(), "ImpulseVault");
  assert.equal(sdk.addressPrefix("mainnet"), "kaspa");
  assert.equal(sdk.addressPrefix("testnet"), "kaspatest");
});

/** The codes in the first column of a spec's error-code table, in table order. */
function specCodes(file: string, prefix: string): string[] {
  const text = readFileSync(new URL(file, root), "utf8");
  const re = new RegExp(`^\\| \`(${prefix}_[A-Z0-9_]+)\` \\|`, "gm");
  return [...text.matchAll(re)].map((m) => m[1]);
}

test("code lists equal the spec tables and the SDK list", () => {
  assert.deepEqual(sdk.termsErrorCodes(), specCodes("spec/ENCODING.md", "TERMS"));
  assert.deepEqual(sdk.templateErrorCodes(), specCodes("spec/TEMPLATE.md", "TEMPLATE"));
  assert.equal(sdk.termsErrorCodes().length, 28);
  assert.equal(sdk.templateErrorCodes().length, 8);
  assert.deepEqual(sdk.sdkErrorCodes(), [
    "SDK_ARGUMENT_TYPE",
    "SDK_JSON_FORM",
    "SDK_MAINNET_NEEDS_NODE",
    "SDK_VALUE_CAP_INVALID",
    "SDK_VALUE_UNKNOWN",
    "SDK_VALUE_CAP_EXCEEDED",
    "SDK_QR",
    "SDK_TERMS_INCONSISTENT",
    "SDK_ROLE_KEY_MISMATCH",
    "SDK_DESTINATION_NOT_MINE",
    "SDK_DESTINATION_PIN_INVALID",
    "SDK_WALLET_WIPED",
    "SDK_WALLET_RANDOM",
    "SDK_SIGN_MAINNET_NOT_EXPLICIT",
    "SDK_SIGN_NETWORK_MISMATCH",
    "SDK_SIGN_NOTHING_TO_SIGN",
    "SDK_SIGN_SELF_CHECK_FAILED",
    "SDK_NODE_URL_INVALID",
    "SDK_NODE_INSECURE",
    "SDK_NODE_NETWORK_MISMATCH",
    "SDK_NODE_NOT_SYNCED",
    "SDK_RPC_REPLY",
    "SDK_TXID_MISMATCH",
    "SDK_UTXO_NOT_FOUND",
    "SDK_SIGN_CHANGE_NOT_MINE",
    "SDK_SIGN_FEE_TOO_HIGH",
    "SDK_SIGN_TOPUP_TOO_HIGH",
    "SDK_SIGN_OUTFLOW_TOO_HIGH",
    "SDK_DESTINATION_IN_WALLET",
    "SDK_RPC_NOT_FOUND",
    "SDK_FUND_NOT_YOUR_LEG",
    "SDK_TEMPLATE_UNPINNED",
    "SDK_FUND_ASSET_NOT_FUNDED",
    "SDK_FUND_ALREADY_FUNDED",
    "SDK_SIGN_DEPOSIT_MISMATCH",
  ]);
});

test("phase 2 code lists equal the spec tables, in table order", () => {
  // spec/TRANSACTIONS.md holds the TX_* codes and spec/IPST.md the IPST_* codes; the core list
  // interleaves them in the order they were added (the review round 1 codes last).
  const tx = specCodes("spec/TRANSACTIONS.md", "TX");
  const ipst = specCodes("spec/IPST.md", "IPST");
  assert.equal(tx.length + ipst.length, sdk.txErrorCodes().length);
  assert.deepEqual([...sdk.txErrorCodes()].sort(), [...tx, ...ipst].sort());
  assert.deepEqual(sdk.verifyErrorCodes(), specCodes("spec/VERIFY.md", "VERIFY"));
  assert.deepEqual(sdk.decodeErrorCodes(), specCodes("spec/VERIFY.md", "DECODE"));
  // The warnings appear in two tables of spec/VERIFY.md, in two orders.
  assert.deepEqual([...sdk.tokenWarningCodes()].sort(), [...new Set(specCodes("spec/VERIFY.md", "TOKEN"))].sort());
  assert.equal(sdk.txErrorCodes().length, 26);
  assert.equal(sdk.verifyErrorCodes().length, 15);
  assert.equal(sdk.decodeErrorCodes().length, 6);
  assert.equal(sdk.tokenWarningCodes().length, 7);
});

test("phase 2 constants are impulse-core's", () => {
  assert.equal(sdk.ipstVersion(), 1);
  assert.equal(sdk.minKasOutput(), "50000000");
  assert.equal(sdk.minKcc20Output(), "200000000");
  assert.equal(sdk.standardMassCap(), "100000");
  assert.equal(sdk.defaultMaxValueSompi(), "1000000000");
  // One cap: the builders and the funding instructions read the same constant.
  assert.equal(sdk.defaultValueCapSompi(), sdk.defaultMaxValueSompi());
  // kaspa-mining's rule: mass times 100,000 sompi per kilogram over 1,000, and that rate itself
  // when the result is 0.
  assert.equal(sdk.minRelayFee("0"), "100000");
  assert.equal(sdk.minRelayFee("1000"), "100000");
  assert.equal(sdk.minRelayFee(2000n), "200000");
});

test("each class has exactly its members; only FundableVault has the address of a vault and only Wallet the address of a key", () => {
  // wasm-bindgen's own members: constructor, free, __destroy_into_raw, and the static __wrap.
  const own = ["__destroy_into_raw", "constructor", "free"];
  const want: Record<string, [string[], string[]]> = {
    Terms: [
      ["encode", "requireSameAs", "termsHash", "toJson", "validateStructure"],
      ["decode", "fromFileText", "fromJson"],
    ],
    ValidatedTerms: [
      [
        "beforeFunding",
        "canonical",
        "direct",
        "directAddresses",
        "directFromReply",
        "fundCashAddresses",
        "fundCashFromReply",
        "fundKas",
        "fundKcc20",
        "fundingInstructions",
        "instantiateExisting",
        "instantiateForCreation",
        "refund",
        "refundAddresses",
        "refundFromReply",
        "roleCheck",
        "settle",
        "settleAddresses",
        "settleFromReply",
        "terms",
        "termsHash",
        "tokenWarnings",
        "validateCreation",
        "verifyAddresses",
        "verifyRevealedScript",
        "verifySpentInput",
      ],
      ["decode"],
    ],
    Ipst: [
      [
        "addSignature",
        "assemble",
        "combine",
        "fee",
        "finalize",
        "isComplete",
        "masses",
        "pending",
        "review",
        "sighash",
        "slots",
        "terms",
        "toJson",
        "verifyAgainstTerms",
      ],
      ["fromJson"],
    ],
    SignedTransaction: [["raw", "txid"], []],
    Vault: [["leg", "network", "redeemScript", "scriptHash", "scriptPublicKey"], []],
    FundableVault: [["address", "vault"], []],
    DecodedVault: [["leg", "terms"], []],
    Template: [["hash", "prefix", "suffix"], []],
    Wallet: [["address", "isWiped", "publicKey", "sign", "wipe"], ["generate"]],
    TermsV2: [["encode", "termsHash", "toJson", "validateStructure"], ["decode", "fromJson"]],
    ValidatedTermsV2: [
      [
        "canonical",
        "fundKas",
        "fundKcc20",
        "minV2",
        "minVaultV2",
        "quantities",
        "refund",
        "settle",
        "settleTranche",
        "terms",
        "termsHash",
        "validateCreation",
        "vaultAddresses",
      ],
      ["decode"],
    ],
    IpstV2: [
      [
        "abovePreToccataCap",
        "addSignature",
        "assemble",
        "combine",
        "fee",
        "finalize",
        "isComplete",
        "masses",
        "pending",
        "sighash",
        "slots",
        "terms",
        "toJson",
        "verifyAgainstTerms",
      ],
      ["fromJson"],
    ],
  };
  const classes = entry as unknown as Record<string, { prototype: object }>;
  for (const [name, [methods, statics]] of Object.entries(want)) {
    const c = classes[name];
    assert.deepEqual(Object.getOwnPropertyNames(c.prototype).sort(), [...own, ...methods].sort(), name);
    assert.deepEqual(
      Object.getOwnPropertyNames(c).sort(),
      ["__wrap", "length", "name", "prototype", ...statics].sort(),
      `${name} statics`,
    );
    assert.equal(Object.getOwnPropertySymbols(c.prototype).length, 0, name);
    assert.equal("address" in c.prototype, name === "FundableVault" || name === "Wallet", `${name}: address`);
  }
});

test("objects stay usable after the operations that consume them in Rust", () => {
  const terms = sdk.Terms.decode(sdk.Terms.fromJson(sdk.Terms.fromJson(
    JSON.parse(readFileSync(new URL("tests/vectors/terms/01-vault-authority-earmarked-kcc20-kcc20.json", root), "utf8")).terms,
  ).toJson()).encode());
  const a = terms.validateStructure();
  const b = terms.validateStructure();
  assert.equal(hex(a.termsHash()), hex(b.termsHash()));
  assert.equal(hex(terms.termsHash()), hex(a.termsHash()));
});
