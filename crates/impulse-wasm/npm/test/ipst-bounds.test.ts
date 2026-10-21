// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The IPST reader's bound. impulse-core's reader recomputes every signer's sighash from the whole
// transaction, which is quadratic in the input count (the review measured 117.8 s for 11,000
// inputs), and the text bound alone (2^23 characters) admits tens of thousands. So the SDK
// refuses a text with more than 256 inputs or outputs (`SDK_JSON_FORM`) before any of that work:
// in `Ipst.fromJson` and in the other document of `combine`. `verifyAgainstTerms` runs on an Ipst
// that `fromJson`, `combine` or a builder made; the builders refuse a transaction of that size on
// mass, so no Ipst past the bound exists to be checked.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  ASSET_ARTIFACT,
  CASH_ARTIFACT,
  MODES,
  NOW,
  LIFT,
  VALUE,
  ctx,
  erase,
  feePayment,
  newParties,
  p2pk,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import { ipstVector, load, refusalError } from "./sdk.ts";

const sdk = load();
const BOUND = 256;
const base = ipstVector("02").doc;

/** Vector 02's document with `inputs` unsigned inputs and `outputs` outputs of 1 sompi each. */
function ipstWith(inputs: number, outputs: number): string {
  const input = { ...base.inputs[0], signer: null, sighash: null };
  const output = { ...base.outputs[0], value: "1" };
  return JSON.stringify({
    ...base,
    inputs: Array.from({ length: inputs }, (_, n) => ({
      ...input,
      transaction_id: createHash("sha256").update(`bound-${n}`).digest("hex"),
    })),
    outputs: Array.from({ length: outputs }, () => output),
  });
}

test("Ipst.fromJson reads 256 inputs and 256 outputs and refuses one more of either", () => {
  assert.ok(sdk.Ipst.fromJson(ipstWith(BOUND, 1)), "control: 256 inputs");
  assert.ok(sdk.Ipst.fromJson(ipstWith(1, BOUND)), "control: 256 outputs");
  assert.ok(sdk.Ipst.fromJson(ipstWith(BOUND, BOUND)), "control: both at the bound");
  const inputs = refusalError(() => sdk.Ipst.fromJson(ipstWith(BOUND + 1, 1)));
  assert.equal(inputs.code, "SDK_JSON_FORM");
  assert.match(inputs.message, /257 inputs/);
  const outputs = refusalError(() => sdk.Ipst.fromJson(ipstWith(1, BOUND + 1)));
  assert.equal(outputs.code, "SDK_JSON_FORM");
  assert.match(outputs.message, /257 outputs/);
});

test("a hostile document of thousands of inputs is refused at once, not after the sighash work", () => {
  // 15,000 inputs are about 6 MB of text, under the 2^23 character bound. Read in full, the
  // reader needs minutes; the unsigned inputs here would skip the sighash but not the rebuild.
  const text = ipstWith(15_000, 1);
  assert.ok(text.length < 1 << 23, "under the text bound, so the count is what refuses it");
  const started = Date.now();
  const e = refusalError(() => sdk.Ipst.fromJson(text));
  assert.equal(e.code, "SDK_JSON_FORM");
  assert.match(e.message, /15000 inputs/);
  assert.ok(Date.now() - started < 10_000, "refused quickly");
});

test("combine reads the other document through the same bound", () => {
  const mine = sdk.Ipst.fromJson(ipstWith(1, 1));
  assert.equal(refusalError(() => mine.combine(ipstWith(BOUND + 1, 1))).code, "SDK_JSON_FORM");
  assert.equal(refusalError(() => mine.combine(ipstWith(1, BOUND + 1))).code, "SDK_JSON_FORM");
  // Control: at the bound the other document is read, and combine then refuses it for what it
  // is, another transaction.
  const other = refusalError(() => mine.combine(ipstWith(BOUND, 1)));
  assert.notEqual(other.code, "SDK_JSON_FORM");
  assert.match(other.code, /^IPST_/);
});

test("verifyAgainstTerms runs on a document read at the bound, and none past it can be held", () => {
  const read = sdk.Ipst.fromJson(ipstWith(BOUND, 1));
  // Control: the check runs through, and answers with the builders' code, not the bound's. (The
  // document pays its 2,560 KAS of inputs away as a fee, which the cap would refuse: lifted.)
  const e = refusalError(() => read.verifyAgainstTerms({ asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT }, NOW.toString(), LIFT));
  assert.notEqual(e.code, "SDK_JSON_FORM");
  assert.match(e.code, /^(IPST|TX)_/);
  // A builder cannot make a document past the bound: the mass cap refuses far sooner. 256 fee
  // inputs are 256 signature checks, each 1,000 grams of the 100,000 gram cap.
  const p = newParties();
  try {
    const t = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
    const inputs = (n: number) => ({
      ...feePayment(p.buyer),
      inputs: Array.from({ length: n }, (_, i) => utxo(`fee-${i}`, 1_000_000_000n, p2pk(p.buyer.publicHex))),
    });
    assert.ok(t.fundKas(ctx(), inputs(1), VALUE), "control: one fee input");
    assert.equal(refusalError(() => t.fundKas(ctx(), inputs(BOUND), VALUE)).code, "TX_MASS");
  } finally {
    erase(p);
  }
});
