// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The phase 2 argument readers, each refusal beside an accepted control: u64 and index scalars,
// bounded text, the plain-array reader, and the value declaration every builder requires. The
// codes are the SDK's (SDK_ARGUMENT_TYPE, SDK_JSON_FORM); impulse-core never sees these values.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import type { FeePaymentJson } from "../index.js";
import {
  ASSET_ARTIFACT,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  newParties,
  termsJson,
  validated,
} from "./fixtures.ts";
import { load, memory, refusal, refusalError } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));

const T = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
const fundKas = (f: unknown = feePayment(p.payer), v: unknown = VALUE, c: unknown = ctx()) =>
  T.fundKas(c as never, f as never, v as never);
test("a u64 scalar is a canonical decimal string or a bigint that holds one", () => {
  const settle = (daa: unknown) => () => T.settle({} as never, {} as never, daa as never, {} as never);
  // Control: both spellings of 1500000 are read, and reach the next check, the legs' form.
  assert.equal(refusal(settle("1500000")), "SDK_JSON_FORM");
  assert.equal(refusal(settle(1_500_000n)), "SDK_JSON_FORM");
  for (const bad of [1_500_000, "01", "-1", "1e6", " 1", "", "1.5", "18446744073709551616", -1n, 2n ** 64n, null, undefined, {}, true]) {
    assert.equal(refusal(settle(bad)), "SDK_ARGUMENT_TYPE", String(bad));
  }
  // The largest u64 is read.
  assert.equal(refusal(settle("18446744073709551615")), "SDK_JSON_FORM");
  assert.equal(refusal(settle(2n ** 64n - 1n)), "SDK_JSON_FORM");
  // A bigint of a million digits is refused by its length, not parsed.
  assert.equal(refusal(settle(10n ** 1_000_000n)), "SDK_ARGUMENT_TYPE");
  assert.equal(sdk.minRelayFee("1000"), sdk.minRelayFee(1000n));
  assert.equal(refusal(() => sdk.minRelayFee(1000 as never)), "SDK_ARGUMENT_TYPE");
});

test("an input index is an integer number from 0 to 2^32 - 1", () => {
  const doc = sdk.Ipst.fromJson(
    // A fund_kas document is enough to read slots from.
    fundKas().toJson(),
  );
  assert.equal(doc.sighash(0).length, 32, "control");
  assert.equal(doc.sighash(-0).length, 32, "-0 is 0, as in leg arguments");
  for (const bad of [1.5, -1, NaN, Infinity, 2 ** 32, "0", 0n, null, undefined, {}]) {
    assert.equal(refusal(() => doc.sighash(bad as never)), "SDK_ARGUMENT_TYPE", String(bad));
  }
  // In range for the type, no such input.
  assert.equal(refusal(() => doc.sighash(7)), "TX_SIGNATURE_SLOT");
  assert.equal(refusal(() => doc.sighash(2 ** 32 - 1)), "TX_SIGNATURE_SLOT");
});

test("text is read only up to its bound, and a longer string is not copied", () => {
  const text = fundKas().toJson();
  assert.ok(sdk.Ipst.fromJson(text), "control");
  for (const bad of [null, undefined, 5, {}, new String(text), new Uint8Array(4)]) {
    assert.equal(refusal(() => sdk.Ipst.fromJson(bad as never)), "SDK_ARGUMENT_TYPE", String(bad));
  }
  const before = memory().buffer.byteLength;
  const e = refusalError(() => sdk.Ipst.fromJson("x".repeat((1 << 23) + 1)));
  assert.equal(e.code, "SDK_JSON_FORM");
  assert.ok(e.message.length < 200, "the message does not echo the string");
  assert.equal(memory().buffer.byteLength, before, "the string was not copied into wasm memory");
  // A combine partner is read the same way.
  assert.equal(refusal(() => sdk.Ipst.fromJson(text).combine("x".repeat((1 << 23) + 1))), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.Ipst.fromJson(text).combine(5 as never)), "SDK_ARGUMENT_TYPE");
  assert.equal(refusal(() => sdk.Ipst.fromJson(text).combine("{")), "IPST_MALFORMED");
  // An artifact: at most 64 KiB of JSON, whatever the transport bound.
  assert.ok(sdk.kcc20Template(ASSET_ARTIFACT), "control");
  assert.equal(refusal(() => sdk.kcc20Template(" ".repeat(70_000))), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.kcc20Template(" ".repeat(1 << 18))), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.kcc20Template("{}")), "TX_TOKEN_TEMPLATE");
});

/** The calls that take bytes, with the bound of each (src/lib.rs: TX_BYTES 200,000, SHORT_BYTES 1,024). */
const spk = { version: 0, script: "aa20" + "11".repeat(32) + "87" };
const bytesCalls: [string, number, (b: Uint8Array) => unknown, RegExp | null][] = [
  ["decodeRaw", 200_000, (b) => sdk.decodeRaw(b, [spk], "mainnet"), /^DECODE_/],
  ["decodeRawUnbound", 200_000, (b) => sdk.decodeRawUnbound(b, "mainnet"), /^DECODE_/],
  ["verifyRevealedScript", 200_000, (b) => T.verifyRevealedScript(0, b), /^(VERIFY|TEMPLATE|TERMS)_/],
  ["verifySpentInput", 200_000, (b) => T.verifySpentInput(0, b, spk), /^(VERIFY|TEMPLATE|TERMS)_/],
  ["decodeVault", 200_000, (b) => sdk.decodeVault(b), /^(TEMPLATE|TERMS)_/],
  // Any bytes have a template hash of their own prefix and suffix: at the bound it answers.
  ["templateHashOfInstance", 200_000, (b) => sdk.templateHashOfInstance(b), null],
  ["Terms.decode", 200_000, (b) => sdk.Terms.decode(b), /^TERMS_/],
  ["ValidatedTerms.decode", 200_000, (b) => sdk.ValidatedTerms.decode(b), /^TERMS_/],
  ["addSignature", 1_024, (b) => sdk.Ipst.fromJson(fundKas().toJson()).addSignature(0, b), /^TX_SIGNATURE$/],
  ["verifySchnorrSig65 signature", 1_024, (b) => sdk.verifySchnorrSig65(new Uint8Array(32), new Uint8Array(32), b), /^TX_SIGNATURE$/],
  ["verifySchnorrSig65 public key", 1_024, (b) => sdk.verifySchnorrSig65(b, new Uint8Array(32), new Uint8Array(65)), /^TX_SIGNATURE$/],
  ["verifySchnorrSig65 sighash", 1_024, (b) => sdk.verifySchnorrSig65(new Uint8Array(32), b, new Uint8Array(65)), /^TX_SIGNATURE$/],
];

test("bytes are read only up to their bound, and a longer value is not copied into the module", () => {
  for (const [name, bound, call, code] of bytesCalls) {
    // Control: a value at the bound is read, and refused for what it is by impulse-core (or
    // answered, where any bytes are an input).
    if (code === null) {
      assert.ok(call(new Uint8Array(bound)), `${name}: at the bound`);
      continue;
    }
    const e = refusalError(() => call(new Uint8Array(bound)));
    assert.match(e.code, code, `${name}: at the bound`);
    assert.notEqual(e.code, "SDK_ARGUMENT_TYPE", `${name}: at the bound`);
  }
  // One byte over, and far over, is refused as an argument before any copy: the module's memory
  // does not grow by a byte, though a 64 MiB value would have grown it by 64 MiB.
  const huge = new Uint8Array(64 << 20);
  const before = memory().buffer.byteLength;
  for (const [name, bound, call] of bytesCalls) {
    for (const length of [bound + 1, bound * 2, huge.length]) {
      const e = refusalError(() => call(length === huge.length ? huge : new Uint8Array(length)));
      assert.equal(e.code, "SDK_ARGUMENT_TYPE", `${name}: ${length} bytes`);
      assert.match(e.message, /at most [0-9]+ bytes/);
    }
  }
  assert.equal(memory().buffer.byteLength, before, "no byte of an oversized value was copied into wasm memory");
});

test("a subclass that lies about its length is not a way past the bound", () => {
  // Long claims more than the bound, Short claims less than it has; the real length decides.
  class Long extends Uint8Array {}
  Object.defineProperty(Long.prototype, "length", { get: () => 1 << 20 });
  class Short extends Uint8Array {}
  Object.defineProperty(Short.prototype, "length", { get: () => 1 });
  assert.equal(refusal(() => sdk.decodeRawUnbound(new Long(4), "mainnet")), "SDK_ARGUMENT_TYPE", "an overstated length is refused");
  assert.equal(refusal(() => sdk.decodeRawUnbound(new Short(4), "mainnet")), "DECODE_TX_MALFORMED", "control: a short value is read");
  assert.equal(refusal(() => sdk.decodeRawUnbound(new Short(200_000), "mainnet")), "DECODE_TX_MALFORMED", "control: at the bound");
  assert.equal(refusal(() => sdk.decodeRawUnbound(new Short(200_001), "mainnet")), "SDK_ARGUMENT_TYPE", "an understated length is refused");
});

test("arrays are read when the API takes them: plain arrays only, bounded, with no hole", () => {
  const f = feePayment(p.payer);
  assert.ok(fundKas(f), "control");
  const withInputs = (inputs: unknown): FeePaymentJson => ({ ...f, inputs: inputs as never });
  const one = f.inputs[0];

  // A hole, an extra property, a subclass, a null-prototype array, and a too-long length.
  const sparse = [one, , one]; // eslint-disable-line no-sparse-arrays
  assert.equal(refusal(() => fundKas(withInputs(sparse))), "SDK_JSON_FORM");
  const extra = Object.assign([one], { note: "x" });
  assert.equal(refusal(() => fundKas(withInputs(extra))), "SDK_JSON_FORM");
  class Inputs extends Array {}
  assert.equal(refusal(() => fundKas(withInputs(Inputs.from([one])))), "SDK_JSON_FORM");
  const bare = Object.setPrototypeOf([one], null);
  assert.equal(refusal(() => fundKas(withInputs(bare))), "SDK_JSON_FORM");
  const huge: unknown[] = [one];
  huge.length = 1e9;
  assert.equal(refusal(() => fundKas(withInputs(huge))), "SDK_JSON_FORM");
  assert.equal(refusal(() => fundKas(withInputs(Array.from({ length: 257 }, () => one)))), "SDK_JSON_FORM");

  // A getter element, a non-enumerable element, a frozen array (control: frozen is plain).
  const getter: unknown[] = [];
  Object.defineProperty(getter, 0, { get: () => one, enumerable: true });
  assert.equal(refusal(() => fundKas(withInputs(getter))), "SDK_JSON_FORM");
  const hidden: unknown[] = [];
  Object.defineProperty(hidden, 0, { value: one, enumerable: false });
  assert.equal(refusal(() => fundKas(withInputs(hidden))), "SDK_JSON_FORM");
  assert.ok(fundKas(withInputs(Object.freeze([one]))), "a frozen array is plain");

  // An array where an object is due, and an object where an array is due.
  assert.equal(refusal(() => fundKas([f])), "SDK_JSON_FORM");
  assert.equal(refusal(() => fundKas(withInputs({ 0: one }))), "SDK_JSON_FORM");
  assert.equal(refusal(() => fundKas(withInputs([[one]]))), "SDK_JSON_FORM");

  // A Proxy of an array reads through its traps; a revoked one is refused, not thrown through.
  assert.ok(fundKas(withInputs(new Proxy([one], {}))), "a transparent Proxy of a plain array");
  const revoked = Proxy.revocable([one], {});
  revoked.revoke();
  assert.equal(refusal(() => fundKas(withInputs(revoked.proxy))), "SDK_JSON_FORM");
  const throwing = new Proxy([one], {
    ownKeys() {
      throw new Error("trap");
    },
  });
  assert.equal(refusal(() => fundKas(withInputs(throwing))), "SDK_JSON_FORM");

  // The bound on nesting: an array of arrays of arrays is cut off before it is walked.
  let deep: unknown = one;
  for (let i = 0; i < 20; i += 1) deep = [deep];
  assert.equal(refusal(() => fundKas(withInputs(deep))), "SDK_JSON_FORM");
  // And a cyclic array ends the walk.
  const cycle: unknown[] = [];
  cycle.push(cycle);
  assert.equal(refusal(() => fundKas(withInputs(cycle))), "SDK_JSON_FORM");
});

test("terms and contexts still take objects only: the phase 1 reader is unchanged by arrays", () => {
  const json = termsJson(sdk, p, MODES.vaultKas);
  assert.ok(sdk.Terms.fromJson(json), "control");
  assert.equal(refusal(() => sdk.Terms.fromJson({ ...json, trade_ref: [json.trade_ref] } as never)), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.Terms.fromJson([json] as never)), "SDK_JSON_FORM");
  assert.equal(refusal(() => T.validateCreation({ ...ctx(), network: ["mainnet"] } as never)), "SDK_JSON_FORM");
});

test("every builder needs its value declaration and its other arguments in form", () => {
  assert.ok(fundKas(), "control");
  for (const bad of [undefined, null, 5, "10", [], { kas_equivalent: 5 }, { kas_equivalent: "1", cap: "1" }, { i_accept_the_risk: 1 }]) {
    assert.equal(refusal(() => T.fundKas(ctx(), feePayment(p.payer), bad as never)), "SDK_JSON_FORM", String(bad));
  }
  // `undefined` is not a default here: the arguments are passed to the method as they are.
  assert.equal(refusal(() => T.fundKas(ctx(), undefined as never, VALUE)), "SDK_JSON_FORM");
  assert.equal(refusal(() => T.fundKas(undefined as never, feePayment(p.payer), VALUE)), "SDK_JSON_FORM");
  // The creation context is the one the terms need: a testnet context for mainnet terms.
  assert.equal(refusal(() => fundKas(feePayment(p.payer), VALUE, { network: "testnet", creation_daa: (NOW - 1n).toString() })), "TERMS_NETWORK_MISMATCH");
  // A builder name that is not there is a TypeError, not a refusal: the class has no such member.
  assert.equal((T as unknown as Record<string, unknown>).fundKcc21, undefined);
});
