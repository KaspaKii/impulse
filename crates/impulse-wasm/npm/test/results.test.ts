// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What a signer is shown: the fields of the results a person confirms before signing. The README
// tells the signer that `verifyAgainstTerms` returns the change, the fee and the builder, that
// `masses` gives the fee floor, that `slots` names who signs which sighash, and that
// `verifyAddresses` names the script behind each address. Each is asserted here against the
// committed vectors or the spec, value by value, so that a result which drops, zeroes or swaps a
// field fails.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import type { IpstKindJson } from "../index.js";
import {
  ASSET_ARTIFACT,
  CASH_ARTIFACT,
  FEE,
  KAS_CASH,
  MODES,
  VALUE,
  ctx,
  erase,
  feePayment,
  newParties,
  termsJson,
  validated,
} from "./fixtures.ts";
import { hex, ipstVector, ipstVectors, load } from "./sdk.ts";

const sdk = load();
const artifacts = { asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT };
const daa = "1500000";

/** The builder each vector is made by, as `verifyAgainstTerms` must name it. */
const KIND: Record<string, IpstKindJson> = {
  "01": { builder: "fund_kcc20", leg: 0 },
  "02": { builder: "fund_kas" },
  "03": { builder: "fund_kcc20", leg: 1 },
  "04": { builder: "settle" },
  "05": { builder: "settle" },
  "06": { builder: "settle" },
  "07": { builder: "settle" },
  "08": { builder: "refund", leg: 0, signer: "depositor", with_token: true },
  "09": { builder: "refund", leg: 0, signer: "counterparty", with_token: true },
  "10": { builder: "refund", leg: 1, signer: "authority", with_token: false },
  "11": { builder: "refund", leg: 1, signer: "depositor", with_token: false },
  "12": { builder: "direct" },
  "13": { builder: "direct" },
};

test("verifyAgainstTerms names the builder, the fee and the change output of every vector", () => {
  assert.equal(ipstVectors.length, 13);
  for (const v of ipstVectors) {
    const key = v.file.slice(0, 2);
    const checked = sdk.Ipst.fromJson(v.text).verifyAgainstTerms(artifacts, daa, VALUE);
    assert.deepEqual(checked.kind, KIND[key], `${v.name}: the builder`);
    assert.equal(checked.fee, "5000000", `${v.name}: the fee`);
    // Every vector pays its change back to the payer, as its last output.
    const last = v.doc.outputs[v.doc.outputs.length - 1];
    assert.deepEqual(checked.change, { value: last.value, script_public_key: last.script_public_key }, `${v.name}: the change`);
  }
});

test("verifyAgainstTerms reports no change when the funding leaves none", () => {
  const p = newParties();
  try {
    const t = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
    // Control: a fee input with change returns it as the last output.
    const withChange = t.fundKas(ctx(), feePayment(p.payer), VALUE);
    const doc = JSON.parse(withChange.toJson()) as { outputs: { value: string; script_public_key: unknown }[] };
    const last = doc.outputs[doc.outputs.length - 1];
    assert.equal(doc.outputs.length, 2);
    assert.deepEqual(withChange.verifyAgainstTerms(artifacts, daa, VALUE).change, {
      value: last.value,
      script_public_key: last.script_public_key,
    });
    // The input holds exactly the deposit and the fee: one output, no change.
    const exact = t.fundKas(ctx(), feePayment(p.payer, "exact", KAS_CASH + FEE), VALUE);
    assert.equal((JSON.parse(exact.toJson()) as { outputs: unknown[] }).outputs.length, 1);
    assert.equal(exact.verifyAgainstTerms(artifacts, daa, VALUE).change, null);
  } finally {
    erase(p);
  }
});

/** The masses of the engine-test settle transactions, spec/TRANSACTIONS.md, "Masses and the standard cap". */
const SPEC_SETTLE: Record<string, { compute: string; transient: string; min_relay_fee: string }> = {
  "04": { compute: "17182", transient: "41728", min_relay_fee: "2086400" },
  "05": { compute: "19676", transient: "49024", min_relay_fee: "2451200" },
  "07": { compute: "10552", transient: "24648", min_relay_fee: "1232400" },
};
/**
 * The storage masses of the same transactions, recorded from the pinned calculator in this build.
 * The spec gives the formula (KIP-9) and no table for them, so these are regression pins, not
 * independent figures.
 */
const STORAGE_PIN: Record<string, string> = { "04": "32490", "05": "48343", "07": "28205" };

test("masses equal the figures of spec/TRANSACTIONS.md for the settle vectors 04, 05 and 07", () => {
  for (const [key, want] of Object.entries(SPEC_SETTLE)) {
    const m = sdk.Ipst.fromJson(ipstVector(key).text).masses();
    assert.equal(m.compute, want.compute, `${key}: compute mass`);
    assert.equal(m.transient, want.transient, `${key}: transient mass`);
    assert.equal(m.min_relay_fee, want.min_relay_fee, `${key}: minimum relay fee`);
    assert.equal(m.storage, STORAGE_PIN[key], `${key}: storage mass (a pin)`);
    assert.notEqual(m.compute, m.storage);
  }
});

test("masses of every vector follow the spec's fee rule and stay under the cap", () => {
  const cap = BigInt(sdk.standardMassCap());
  for (const v of ipstVectors) {
    const m = sdk.Ipst.fromJson(v.text).masses();
    const [compute, transient, storage] = [BigInt(m.compute), BigInt(m.transient), BigInt(m.storage)];
    // The fee mass is the larger of the compute mass and the transient mass normalised to the
    // compute scale (ceil(transient * 500,000 / 1,000,000)); the minimum is 100 sompi a gram and
    // at least 100,000 (spec/TRANSACTIONS.md, "Minimum relay fee").
    const normalised = (transient + 1n) / 2n;
    const feeMass = compute > normalised ? compute : normalised;
    assert.equal(m.fee_mass, feeMass.toString(), `${v.name}: fee mass`);
    const floor = feeMass * 100n > 100_000n ? feeMass * 100n : 100_000n;
    assert.equal(m.min_relay_fee, floor.toString(), `${v.name}: minimum relay fee`);
    assert.equal(sdk.minRelayFee(m.fee_mass), m.min_relay_fee, `${v.name}: minRelayFee agrees`);
    for (const mass of [compute, transient, storage]) assert.ok(mass > 0n && mass <= cap, v.name);
  }
});

test("slots name each signer and the sighash the document states, and hold a signature once added", () => {
  for (const v of ipstVectors) {
    const ipst = sdk.Ipst.fromJson(v.text);
    assert.deepEqual(
      ipst.slots(),
      v.doc.inputs.map((input, n) => ({ input: n, signer: input.signer, sighash: input.sighash, signature: input.signature })),
      `${v.name}: the slots are the document's`,
    );
    assert.deepEqual(
      ipst.pending(),
      v.doc.inputs.flatMap((input, n) => (input.signer === null ? [] : [n])),
      `${v.name}: the pending inputs are the signers'`,
    );
  }
  // A built document: after one signature the slot holds it, the others stay empty, and the
  // sighash of the slot is the one `sighash(i)` computes.
  const p = newParties();
  try {
    const t = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
    const ipst = t.fundKas(ctx(), feePayment(p.payer), VALUE);
    const before = ipst.slots();
    assert.equal(before.length, 1);
    assert.equal(before[0].signer, p.payer.publicHex);
    assert.equal(before[0].sighash, hex(ipst.sighash(0)));
    assert.equal(before[0].signature, null);
    const signature = p.payer.sign(ipst.sighash(0));
    ipst.addSignature(0, signature);
    assert.deepEqual(ipst.slots(), [{ ...before[0], signature: hex(signature) }]);
    assert.deepEqual(ipst.pending(), []);
  } finally {
    erase(p);
  }
});

test("verifyAddresses names the script hash of each leg's vault beside its address", () => {
  const p = newParties();
  try {
    const t = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
    const addresses = {
      asset: t.instantiateForCreation(0, ctx(), VALUE).address(),
      cash: t.instantiateForCreation(1, ctx(), VALUE).address(),
    };
    const verified = t.verifyAddresses(ctx(), addresses, VALUE);
    assert.deepEqual(verified, [
      { leg: 0, address: addresses.asset, script_hash: hex(t.instantiateExisting(0).scriptHash()) },
      { leg: 1, address: addresses.cash, script_hash: hex(t.instantiateExisting(1).scriptHash()) },
    ]);
    assert.notEqual(verified[0].script_hash, verified[1].script_hash);
    // The funding check reports the same entries.
    assert.deepEqual(t.beforeFunding(ctx(), addresses, { asset: null, cash: null }, VALUE).addresses, verified);
  } finally {
    erase(p);
  }
});
