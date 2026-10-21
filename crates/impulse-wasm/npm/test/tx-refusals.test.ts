// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Every stable refusal code of the phase 2 API through the published package, each refusal beside
// an accepted control that differs from it only in the refused value: impulse-core's TX_*,
// IPST_*, VERIFY_* and DECODE_* codes unchanged, and the SDK's value cap codes. Each call is
// recorded with its answer, and the same calls run natively at the end (oracle.ts), so the host
// build must refuse with the same code.
//
// A code a call through the API cannot reach (the API never builds the input that raises it)
// is listed in `unreachable` with the reason, and the Rust test in src/wasm_tests.rs shows it
// still crosses into JavaScript unchanged. The last tests require every code to be one or the
// other.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Hex, Ipst, SettleLegsJson, ValidatedTerms } from "../index.js";
import { rec } from "./calls.ts";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  CASH_ARTIFACT,
  KAS_CASH,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  funded,
  newParties,
  ownToken,
  p2pk,
  settleLegs,
  signedBy,
  spentScripts,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import type { Mode } from "./fixtures.ts";
import { checkAgainstNative } from "./oracle.ts";
import { hex, load, refusal, unhex } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();
const EXPIRY_DAA = "2000000";
const artifacts = { asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT };

interface Case {
  code: string;
  what: string;
  accept: () => unknown;
  refuse: () => unknown;
}
const cases: Case[] = [];
function add(code: string, what: string, accept: () => unknown, refuse: () => unknown): void {
  cases.push({ code, what, accept, refuse });
}

/** Codes no call through the API reaches, with the reason. */
const unreachable: Record<string, string> = {
  TX_VAULT_MISMATCH: "the API makes the funding vault from the terms itself, so it is always the terms' vault",
  TX_ENCODING: "a push or a token amount too large to encode is refused earlier, as TX_TOKEN_INPUT or TX_MASS",
};

const terms = (mode: Mode): ValidatedTerms => validated(sdk, termsJson(sdk, p, mode));
const T = terms(MODES.vaultKas);
const T_KCC20 = terms(MODES.vaultKcc20);
const T_SELF = terms(MODES.selfSettling);
const T_EXTERNAL = terms(MODES.external);
const T_DIRECT = terms(MODES.directKas);
const fee = (label = "fee") => feePayment(p.payer, label);

const F = funded(sdk, T, MODES.vaultKas);
const legs = (): SettleLegsJson => structuredClone(settleLegs(F));
const settle = (t: ValidatedTerms = T, l: SettleLegsJson = legs(), f = fee(), when = daa) => rec.settle(t, l, f, when, VALUE);

const sellerToken = (amount: bigint, label = "seller-token") =>
  ownToken(sdk, label, ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, amount);
const deposit = (tokens = [sellerToken(1_000n)], carrier = CARRIER, authorizer = AUTHORIZER) => ({
  artifact: ASSET_ARTIFACT,
  tokens,
  carrier: carrier.toString(),
  authorizer: authorizer.toString(),
});
const fundAsset = (d = deposit(), f = fee(), c = ctx()) => rec.fundKcc20(T, 0, c, d, f, VALUE);
const fundCash = (t: ValidatedTerms = T, f = fee(), c = ctx()) => rec.fundKas(t, c, f, VALUE);

const directLegs = () => ({
  asset_artifact: ASSET_ARTIFACT,
  asset: sellerToken(1_000n, "direct-seller"),
  cash: { kind: "kas" as const, utxo: utxo("direct-buyer", KAS_CASH, p2pk(p.buyer.publicHex)) },
});
const direct = (l = directLegs(), f = fee(), when = daa, t: ValidatedTerms = T_DIRECT) => rec.direct(t, l, f, when, VALUE);

// Builders (spec/TRANSACTIONS.md, "Error codes").
add(
  "TX_WRONG_MODE",
  "fund_kas on terms whose cash leg is KCC-20",
  () => fundCash(T),
  () => fundCash(T_KCC20),
);
add(
  "TX_EXPIRED",
  "settle at the expiry DAA score (one before it settles)",
  () => settle(),
  () => settle(T, legs(), fee(), EXPIRY_DAA),
);
// Direct runs no contract: the builder's refusal is the only guard against building a trade that
// can no longer settle (IMPULSE-SPEC.md, red team: "the SDK refuses to build such a transaction").
add(
  "TX_EXPIRED",
  "direct at the expiry DAA score (the builder's current DAA score is read)",
  () => direct(),
  () => direct(directLegs(), fee(), EXPIRY_DAA),
);
add(
  "TX_EXPIRED",
  "direct at the expiry DAA score (one before it builds: the boundary)",
  () => direct(directLegs(), fee(), (BigInt(EXPIRY_DAA) - 1n).toString()),
  () => direct(directLegs(), fee(), EXPIRY_DAA),
);
add(
  "TX_EXPIRED",
  "direct on terms whose earliest DAA score equals the expiry (one before it builds)",
  () => direct(),
  () => {
    const equal = validated(sdk, { ...termsJson(sdk, p, MODES.directKas), earliest_daa: EXPIRY_DAA });
    return direct(directLegs(), fee(), daa, equal);
  },
);
add(
  "TX_NOT_AT_VAULT",
  "settle with the asset authorizer at a key's scriptPublicKey",
  () => settle(),
  () => {
    const l = legs();
    l.asset_authorizer.script_public_key = p2pk(p.seller.publicHex);
    return settle(T, l);
  },
);
add(
  "TX_ESCROW_MISMATCH",
  "settle with the asset escrow under another covenant",
  () => settle(),
  () => {
    const l = legs();
    l.asset_escrow.covenant_id = "5a".repeat(32);
    return settle(T, l);
  },
);
add(
  "TX_LEG_AMOUNT",
  "settle with a cash vault UTXO one sompi over the cash amount",
  () => settle(),
  () => {
    const l = legs();
    if (l.cash.kind !== "kas") throw new Error("KAS cash");
    l.cash.vault.amount = (KAS_CASH + 1n).toString();
    return settle(T, l);
  },
);
add(
  "TX_TOKEN_TEMPLATE",
  "settle with the cash token's template for the asset leg",
  () => settle(),
  () => {
    const l = legs();
    l.asset_artifact = CASH_ARTIFACT;
    return settle(T, l);
  },
);
add(
  "TX_TOKEN_TEMPLATE",
  "settle with an artifact that is not a token",
  () => settle(),
  () => {
    const l = legs();
    l.asset_artifact = "{}";
    return settle(T, l);
  },
);
add(
  "TX_TOKEN_INPUT",
  "fund_kcc20 from a token UTXO holding one unit less than the leg amount",
  () => fundAsset(),
  () => fundAsset(deposit([sellerToken(999n)])),
);
add(
  "TX_KAS_INPUT",
  "fund_kas paid from a UTXO that is not a Schnorr P2PK output",
  () => fundCash(),
  () => {
    const f = fee();
    f.inputs[0].script_public_key = { version: 0, script: "aa20" + "11".repeat(32) + "87" };
    return fundCash(T, f);
  },
);
add(
  "TX_KAS_INPUT",
  "fund_kas paid from a Schnorr P2PK script under scriptPublicKey version 1",
  () => fundCash(),
  () => {
    const f = fee();
    f.inputs[0].script_public_key = { ...f.inputs[0].script_public_key, version: 1 };
    return fundCash(T, f);
  },
);
add(
  "TX_DUPLICATE_INPUT",
  "fund_kas paid from the same outpoint twice",
  () => {
    const f = fee();
    f.inputs.push(utxo("second-fee", 10_000_000n, p2pk(p.payer.publicHex)));
    return fundCash(T, f);
  },
  () => {
    const f = fee();
    f.inputs.push(structuredClone(f.inputs[0]));
    return fundCash(T, f);
  },
);
add(
  "TX_INSUFFICIENT_FUNDS",
  "fund_kas paid from a UTXO that holds only the cash amount",
  () => fundCash(),
  () => fundCash(T, feePayment(p.payer, "short", KAS_CASH)),
);
add(
  "TX_BELOW_MIN_KAS",
  "fund_kcc20 with 1 sompi on the escrowed token's output",
  () => fundAsset(),
  () => fundAsset(deposit([sellerToken(1_000n)], 1n)),
);
add(
  "TX_MASS",
  "fund_kas paid from 250 inputs against 1 input",
  () => fundCash(),
  () => {
    const f = fee();
    f.inputs = Array.from({ length: 250 }, (_, i) => utxo(`many-${i}`, 10_000_000n, p2pk(p.payer.publicHex)));
    f.fee = "100000000";
    return fundCash(T, f);
  },
);
add(
  "TX_TOO_MANY_INPUTS",
  "a settle paid from 10 fee inputs (13 inputs) against 9 (12, the bound)",
  () => {
    const f = fee();
    f.inputs = Array.from({ length: 9 }, (_, i) => utxo(`fee-${i}`, 100_000_000n, p2pk(p.payer.publicHex)));
    return settle(T, legs(), f);
  },
  () => {
    const f = fee();
    f.inputs = Array.from({ length: 10 }, (_, i) => utxo(`fee-${i}`, 100_000_000n, p2pk(p.payer.publicHex)));
    return settle(T, legs(), f);
  },
);
add(
  "TX_FEE_TOO_LOW",
  "fund_kas with a fee of 1 sompi",
  () => fundCash(),
  () => {
    const f = fee();
    f.fee = "1";
    return fundCash(T, f);
  },
);
add(
  "TX_NONSTANDARD_CHANGE",
  "fund_kas with the change at a version 1 scriptPublicKey",
  () => fundCash(),
  () => {
    const f = fee();
    f.change = { version: 1, script: "51" };
    return fundCash(T, f);
  },
);
add(
  "TX_UTXO_VALUE",
  "fund_kas paid from a UTXO of 0 sompi",
  () => fundCash(),
  () => {
    const f = fee();
    f.inputs.push(utxo("zero", 0n, p2pk(p.payer.publicHex)));
    return fundCash(T, f);
  },
);
add(
  "TX_REFUND_SIGNER",
  "refund by the authority of terms that have none",
  () => rec.refund(T_SELF, 0, "depositor", structuredClone(funded(sdk, T_SELF, MODES.selfSettling).assetAuthorizer), null, fee(), VALUE),
  () => rec.refund(T_SELF, 0, "authority", structuredClone(funded(sdk, T_SELF, MODES.selfSettling).assetAuthorizer), null, fee(), VALUE),
);
add(
  "TX_REFUND_SIGNER",
  "refund of a KCC-20 leg by the counterparty without the escrowed token",
  () =>
    rec.refund(
      T,
      0,
      "counterparty",
      structuredClone(F.assetAuthorizer),
      { artifact: ASSET_ARTIFACT, utxo: structuredClone(F.assetEscrow), amount: "1000", is_minter: false },
      fee(),
      VALUE,
    ),
  () => rec.refund(T, 0, "counterparty", structuredClone(F.assetAuthorizer), null, fee(), VALUE),
);

// Signatures and the IPST.
const base = (): Ipst => direct();
add(
  "TX_SIGNATURE",
  "a signature made by the wrong key on a slot",
  () => {
    const d = base();
    d.addSignature(0, p.seller.sign(d.sighash(0)));
  },
  () => {
    const d = base();
    d.addSignature(0, p.buyer.sign(d.sighash(0)));
  },
);
add(
  "TX_SIGNATURE",
  "a signature that is 64 bytes",
  () => {
    const d = base();
    d.addSignature(0, p.seller.sign(d.sighash(0)));
  },
  () => {
    const d = base();
    d.addSignature(0, p.seller.sign(d.sighash(0)).slice(0, 64));
  },
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a sighash type other than SIG_HASH_ALL",
  () => {
    const d = base();
    sdk.verifySchnorrSig65(p.seller.publicKey, d.sighash(0), p.seller.sign(d.sighash(0)));
  },
  () => {
    const d = base();
    const sig = p.seller.sign(d.sighash(0));
    sig[64] = 0x02;
    sdk.verifySchnorrSig65(p.seller.publicKey, d.sighash(0), sig);
  },
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a public key of 31 bytes",
  () => {
    const d = base();
    sdk.verifySchnorrSig65(p.seller.publicKey, d.sighash(0), p.seller.sign(d.sighash(0)));
  },
  () => {
    const d = base();
    sdk.verifySchnorrSig65(p.seller.publicKey.slice(1), d.sighash(0), p.seller.sign(d.sighash(0)));
  },
);
// verifySchnorrSig65 takes its three arguments at exactly 32, 32 and 65 bytes. The message ends in
// a zero byte, so a sighash of 31 bytes padded with a zero, and one of 33 bytes cut to 32, both
// become the signed message: an implementation that fits the length instead of refusing it
// accepts these.
const message = (() => {
  const m = new Uint8Array(createHash("sha256").update("verifySchnorrSig65").digest());
  m[31] = 0;
  return m;
})();
const withByte = (bytes: Uint8Array, extra: number): Uint8Array => Uint8Array.from([...bytes, extra]);
const sig65 = () => p.seller.sign(message);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a sighash of 31 bytes",
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65()),
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message.slice(0, 31), sig65()),
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a sighash of 33 bytes",
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65()),
  () => sdk.verifySchnorrSig65(p.seller.publicKey, withByte(message, 7), sig65()),
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a public key of 33 bytes",
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65()),
  () => sdk.verifySchnorrSig65(withByte(p.seller.publicKey, 0), message, sig65()),
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a signature of 64 bytes",
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65()),
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65().slice(0, 64)),
);
add(
  "TX_SIGNATURE",
  "verifySchnorrSig65 with a signature of 66 bytes",
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, sig65()),
  () => sdk.verifySchnorrSig65(p.seller.publicKey, message, withByte(sig65(), 1)),
);
add(
  "TX_SIGNATURE_SLOT",
  "a signature for input 9 of a 3-input document",
  () => {
    const d = base();
    d.addSignature(2, p.payer.sign(d.sighash(2)));
  },
  () => {
    const d = base();
    d.addSignature(9, p.payer.sign(d.sighash(2)));
  },
);
add(
  "TX_SIGNATURE_SLOT",
  "a signature for a vault input that takes none (self-settling terms)",
  () => {
    const s = rec.settle(T_SELF, settleLegs(funded(sdk, T_SELF, MODES.selfSettling)), fee(), daa, VALUE);
    s.addSignature(s.pending()[0], p.payer.sign(s.sighash(s.pending()[0])));
  },
  () => {
    const s = rec.settle(T_SELF, settleLegs(funded(sdk, T_SELF, MODES.selfSettling)), fee(), daa, VALUE);
    s.addSignature(0, p.payer.sign(s.sighash(0)));
  },
);
add(
  "TX_SIGNATURE_SLOT",
  "assemble from a document missing a signature",
  () => {
    const d = base();
    const signed = ["seller", "buyer", "payer"].map((who, i) => {
      const s = p[who as "seller"];
      return { input: i, signature: hex(s.sign(d.sighash(i))) };
    });
    return rec.assemble(d, signed);
  },
  () => {
    const d = base();
    return rec.assemble(d, [{ input: 0, signature: hex(p.seller.sign(d.sighash(0))) }]);
  },
);

const goodText = (): string => base().toJson();
add(
  "IPST_MALFORMED",
  "an IPST with no outputs",
  () => sdk.Ipst.fromJson(goodText()),
  () => {
    const doc = JSON.parse(goodText());
    doc.outputs = [];
    return sdk.Ipst.fromJson(JSON.stringify(doc));
  },
);
add(
  "IPST_MALFORMED",
  "an IPST with a key written twice",
  () => sdk.Ipst.fromJson(goodText()),
  () => sdk.Ipst.fromJson(goodText().replace('"ipst": 1,', '"ipst": 1,\n  "ipst": 1,')),
);
add(
  "IPST_UNSUPPORTED_VERSION",
  "an IPST of version 2",
  () => sdk.Ipst.fromJson(goodText()),
  () => sdk.Ipst.fromJson(goodText().replace('"ipst": 1,', '"ipst": 2,')),
);
add(
  "IPST_SIGHASH_MISMATCH",
  "an IPST whose first output was changed after the sighashes were stated",
  () => sdk.Ipst.fromJson(goodText()),
  () => {
    const doc = JSON.parse(goodText());
    doc.outputs[0].value = (BigInt(doc.outputs[0].value) - 1n).toString();
    return sdk.Ipst.fromJson(JSON.stringify(doc, null, 2));
  },
);
add(
  "IPST_CONFLICT",
  "combine two documents of different transactions",
  () => rec.combine(base(), base().toJson()),
  () => {
    const other = rec.direct(T_DIRECT, directLegs(), feePayment(p.payer, "other-fee"), daa, VALUE);
    return rec.combine(base(), other.toJson());
  },
);
add(
  "IPST_TERMS_MISMATCH",
  "a document whose compute budget was raised after it was built",
  () => rec.verifyAgainstTerms(base(), artifacts, daa),
  () => {
    const doc = JSON.parse(goodText());
    doc.inputs[0].compute_budget += 1;
    return rec.verifyAgainstTerms(sdk.Ipst.fromJson(JSON.stringify(doc, null, 2)), artifacts, daa);
  },
);

// Verify (spec/VERIFY.md).
const assetAddress = T.instantiateForCreation(0, ctx(), VALUE).address();
const cashAddress = T.instantiateForCreation(1, ctx(), VALUE).address();
const offered = { asset: assetAddress, cash: cashAddress };
const verify = (t: ValidatedTerms = T, o: { asset: string | null; cash: string | null } = offered) =>
  rec.verifyAddresses(t, ctx(), o);
const otherTrade = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), nonce: "42" });
const testnetTrade = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), network: "testnet" });
add(
  "VERIFY_ADDRESS_MALFORMED",
  "an offered address that is not an address",
  () => verify(),
  () => verify(T, { ...offered, asset: "not an address" }),
);
add(
  "VERIFY_ADDRESS_NETWORK",
  "an offered address with the testnet prefix",
  () => verify(),
  () =>
    verify(T, {
      ...offered,
      asset: testnetTrade.instantiateForCreation(0, { network: "testnet", creation_daa: (NOW - 1n).toString() }, VALUE).address(),
    }),
);
add(
  "VERIFY_ADDRESS_MISMATCH",
  "an offered address that pays another trade's vault",
  () => verify(),
  () => verify(T, { ...offered, asset: otherTrade.instantiateForCreation(0, ctx(), VALUE).address() }),
);
add(
  "VERIFY_ADDRESS_MISSING",
  "no address offered for a leg that has a vault",
  () => verify(),
  () => verify(T, { ...offered, cash: null }),
);
add(
  "VERIFY_ADDRESS_UNEXPECTED",
  "an address offered for the cash leg of external-cash terms",
  () => verify(T_EXTERNAL, { asset: T_EXTERNAL.instantiateForCreation(0, ctx(), VALUE).address(), cash: null }),
  () => verify(T_EXTERNAL, { asset: T_EXTERNAL.instantiateForCreation(0, ctx(), VALUE).address(), cash: cashAddress }),
);
add(
  "VERIFY_LEGS_SWAPPED",
  "the cash leg's address offered for the asset leg",
  () => verify(),
  () => verify(T, { asset: cashAddress, cash: assetAddress }),
);

const script = (t: ValidatedTerms, leg: 0 | 1): Uint8Array => t.instantiateExisting(leg).redeemScript();
add(
  "VERIFY_TEMPLATE_MISMATCH",
  "a revealed script with one byte of the template changed",
  () => T.verifyRevealedScript(0, script(T, 0)),
  () => {
    const s = script(T, 0).slice();
    s[s.length - 1] ^= 1; // the template's last byte, outside the terms it carries
    return T.verifyRevealedScript(0, s);
  },
);
add(
  "VERIFY_TERMS_MISMATCH",
  "a revealed script of another trade's terms",
  () => T.verifyRevealedScript(0, script(T, 0)),
  () => T.verifyRevealedScript(0, script(otherTrade, 0)),
);
add(
  "VERIFY_LEGS_SWAPPED",
  "a revealed script of the other leg",
  () => T.verifyRevealedScript(1, script(T, 1)),
  () => T.verifyRevealedScript(0, script(T, 1)),
);

const vaultSpk = (t: ValidatedTerms, leg: 0 | 1) => {
  const spk = t.instantiateExisting(leg).scriptPublicKey();
  return { version: spk.version, script: hex(spk.script) };
};
/** The signature script of a settle's vault input 0: the authority's signature, then the rest. */
function vaultSigScript(): Uint8Array {
  const s = settle();
  const doc = JSON.parse(s.toJson()).inputs[0];
  const signed = signedBy(sdk, s.toJson(), p.authority);
  const sig = JSON.parse(signed).inputs[0].signature as Hex;
  return unhex(`${doc.script_before}41${sig}${doc.script_after}`);
}
const sigScript = vaultSigScript();
add(
  "VERIFY_NOTHING_REVEALED",
  "a spent input whose signature script is empty",
  () => T.verifySpentInput(0, sigScript, vaultSpk(T, 0)),
  () => T.verifySpentInput(0, new Uint8Array(0), vaultSpk(T, 0)),
);
add(
  "VERIFY_INPUT_NOT_VAULT",
  "a spent input whose UTXO is a key's output, not the vault's P2SH",
  () => T.verifySpentInput(0, sigScript, vaultSpk(T, 0)),
  () => T.verifySpentInput(0, sigScript, p2pk(p.seller.publicHex)),
);

const evidence = (artifact: string | null) => (artifact === null ? null : { artifact, issuer_keys: [] as string[] });
const funding = (asset: string | null, cash: string | null = null) =>
  rec.beforeFunding(T, ctx(), offered, { asset: evidence(asset), cash: evidence(cash) });
/** The asset token's artifact, edited. Its template triple, which the terms name, is unchanged. */
const doctored = (edit: (contract: any) => void): string => {
  const artifact = JSON.parse(ASSET_ARTIFACT);
  edit(artifact.contracts.KCC20);
  return JSON.stringify(artifact);
};
add(
  "VERIFY_TOKEN_LEG_KIND",
  "token evidence for a leg that is native KAS",
  () => funding(ASSET_ARTIFACT),
  () => funding(ASSET_ARTIFACT, CASH_ARTIFACT),
);
add(
  "VERIFY_TOKEN_ARTIFACT_INVALID",
  "token evidence whose artifact is not an artifact",
  () => funding(ASSET_ARTIFACT),
  () => funding("{}"),
);
add(
  "VERIFY_TOKEN_TEMPLATE_MISMATCH",
  "token evidence of another token's template",
  () => funding(ASSET_ARTIFACT),
  () => funding(CASH_ARTIFACT),
);

add(
  "VERIFY_TOKEN_NOT_KCC20",
  "token evidence whose fourth state field is not named isMinter",
  () => funding(ASSET_ARTIFACT),
  () => funding(doctored((c) => (c.runtime_state.fields[3].name = "isFrozen"))),
);
add(
  "VERIFY_TOKEN_EXTENDED_STATE",
  "token evidence whose state has a fifth field (the template bytes outside the state are unchanged)",
  () => funding(ASSET_ARTIFACT),
  () =>
    funding(
      doctored((c) => {
        c.runtime_state.fields.push({ name: "frozen", type: { kind: "bool" } });
        const span = c.compiled.state_span;
        c.compiled.bytecode.splice(span.offset + span.len, 0, 1, 0); // a one-byte push of false
        span.len += 2;
      }),
    ),
);

// Decode (spec/VERIFY.md).
const settleIpst = settle();
const settleText = settleIpst.toJson();
const settled = (() => {
  const merged = sdk.Ipst.fromJson(signedBy(sdk, settleText, p.authority));
  return merged.combine(signedBy(sdk, settleText, p.payer)).finalize();
})();
const rawSettle = settled.raw();
const spentOk = spentScripts(settleText);
const decode = (raw: Uint8Array = rawSettle, spent = spentOk) => rec.decodeRaw(sdk, raw, spent, "mainnet");
add(
  "DECODE_TX_MALFORMED",
  "bytes that are not a transaction",
  () => decode(),
  () => decode(rawSettle.slice(0, 20)),
);
add(
  "DECODE_TX_ID_MISMATCH",
  "a settle whose carried transaction ID has one bit changed",
  () => decode(),
  () => {
    const raw = rawSettle.slice();
    raw[raw.length - 1] ^= 1;
    return decode(raw);
  },
);
add(
  "DECODE_NO_VAULT_INPUT",
  "a transaction that spends no vault (a deposit)",
  () => decode(),
  () => {
    const d = fundCash();
    const text = d.toJson();
    const tx = sdk.Ipst.fromJson(signedBy(sdk, text, p.payer)).finalize();
    return decode(tx.raw(), spentScripts(text));
  },
);
add(
  "DECODE_SPENT_COUNT",
  "one spent scriptPublicKey too few",
  () => decode(),
  () => decode(rawSettle, spentOk.slice(1)),
);
add(
  "DECODE_INPUT_NOT_VAULT",
  "every spent UTXO a key's output",
  () => decode(),
  () => decode(rawSettle, spentOk.map(() => p2pk(p.seller.publicHex))),
);
/**
 * `raw` with the last byte of the 4-byte dispatch tag of each vault input changed (or of the
 * first only). The tag is found by the push that follows it, the start of the redeem script, so
 * a copy of the same bytes inside a redeem script is left alone.
 */
function withTagsChanged(onlyFirst: boolean): Uint8Array {
  const after = JSON.parse(settleText).inputs[0].script_after as string; // 04 <tag> <push of the script>
  const key = unhex(after.slice(0, 16));
  assert.equal(key[0], 4);
  const raw = rawSettle.slice();
  let changed = 0;
  for (let i = 0; i + key.length <= raw.length; i += 1) {
    if (key.every((b, k) => raw[i + k] === b)) {
      raw[i + 4] ^= 0xff;
      changed += 1;
      if (onlyFirst) break;
    }
  }
  assert.equal(changed, onlyFirst ? 1 : 2, "the tag is in the two vault signature scripts");
  return raw;
}
add(
  "DECODE_ENTRY_UNKNOWN",
  "a settle whose vault inputs call an entry the template does not have",
  () => decode(),
  () => decode(withTagsChanged(false)),
);

// The SDK's value cap (spec/CLI.md, "Value cap", for the builders).
add(
  "SDK_VALUE_UNKNOWN",
  "a builder called with no declared value",
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1" }),
  () => rec.fundKas(T, ctx(), fee(), {}),
);
add(
  "SDK_VALUE_UNKNOWN",
  "a builder called with a declared value of 0",
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1" }),
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "0" }),
);
add(
  "SDK_VALUE_CAP_EXCEEDED",
  "a declared value one sompi over 10 KAS",
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1000000000" }),
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1000000001" }),
);
add(
  "SDK_VALUE_CAP_INVALID",
  "a max_value above the default cap",
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1", max_value: "1000000000" }),
  () => rec.fundKas(T, ctx(), fee(), { kas_equivalent: "1", max_value: "1000000001" }),
);
add(
  "SDK_VALUE_CAP_INVALID",
  "a max_value together with the flag that lifts the cap",
  () => rec.fundKas(T, ctx(), fee(), { i_accept_the_risk: true }),
  () => rec.fundKas(T, ctx(), fee(), { max_value: "1", i_accept_the_risk: true }),
);

for (const c of cases) {
  test(`${c.code}: ${c.what}`, () => {
    c.accept();
    assert.equal(refusal(c.refuse), c.code);
  });
}

test("every phase 2 stable code has a refusal case beside an accepted control, or is listed as unreachable", () => {
  const all = [
    ...sdk.txErrorCodes(),
    ...sdk.verifyErrorCodes(),
    ...sdk.decodeErrorCodes(),
    ...sdk.sdkErrorCodes().filter((c) => c.startsWith("SDK_VALUE_")),
  ];
  assert.equal(new Set(all).size, all.length, "codes are unique");
  const covered = new Set(cases.map((c) => c.code));
  const missing = all.filter((c) => !covered.has(c)).sort();
  assert.deepEqual(missing, Object.keys(unreachable).sort(), "only the listed codes lack a case");
  for (const code of covered) assert.ok(all.includes(code), `${code} is a code of the API`);
});

test("the refusals above answer with the same codes natively", () => {
  assert.ok(checkAgainstNative() > cases.length);
});

