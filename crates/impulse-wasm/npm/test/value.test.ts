// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The per-trade value cap (owner decision D4: 10 KAS equivalent)
// in every builder path: fund (KAS and KCC-20), settle, refund and Direct each refuse a trade
// above the cap before they build, beside an accepted control. Only the explicit flag
// `i_accept_the_risk: true` lifts it; `max_value` can only lower it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import type { FeePaymentJson, ValueJson } from "../index.js";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
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
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import { load, refusal } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();

const T = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
const T_DIRECT = validated(sdk, termsJson(sdk, p, MODES.directKas));
const F = funded(sdk, T, MODES.vaultKas);

/** The deposit of fundKcc20: the seller's token, with the carrier and authorizer KAS that go with it. */
const deposit = (carrier = CARRIER, authorizer = AUTHORIZER) => ({
  artifact: ASSET_ARTIFACT,
  tokens: [ownToken(sdk, "seller-token", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n)],
  carrier: carrier.toString(),
  authorizer: authorizer.toString(),
});

/** The cap in sompi: 10 KAS. */
const CAP = BigInt(sdk.defaultMaxValueSompi());
/** A fee payment that can carry a fee, carrier and authorizer of the size of the cap. */
const rich = (fee: bigint): FeePaymentJson => feePayment(p.payer, "rich", 50_000_000_000n, fee);

/** Each builder, called with a declaration `v` and otherwise valid arguments. */
const builders: Record<string, (v: ValueJson, funding?: FeePaymentJson) => unknown> = {
  fundKas: (v, f = feePayment(p.buyer)) => T.fundKas(ctx(), f, v),
  fundKcc20: (v, f = feePayment(p.payer)) => T.fundKcc20(0, ctx(), deposit(), f, v),
  settle: (v, f = feePayment(p.payer)) => T.settle(settleLegs(F), f, daa, v),
  refund: (v, f = feePayment(p.payer)) => T.refund(0, "depositor", F.assetAuthorizer, null, f, v),
  direct: (v, f = feePayment(p.payer)) =>
    T_DIRECT.direct(
      {
        asset_artifact: ASSET_ARTIFACT,
        asset: ownToken(sdk, "direct-seller", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
        cash: { kind: "kas", utxo: utxo("direct-buyer", KAS_CASH, p2pk(p.buyer.publicHex)) },
      },
      f,
      daa,
      v,
    ),
};

for (const [name, build] of Object.entries(builders)) {
  test(`${name} applies the value cap: refused above it, built within it or with the flag`, () => {
    assert.ok(build({ kas_equivalent: "1000000000" }), "control: a declared value at the cap");
    assert.equal(refusal(() => build({ kas_equivalent: "1000000001" })), "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(refusal(() => build({})), "SDK_VALUE_UNKNOWN");
    assert.equal(refusal(() => build({ kas_equivalent: "0" })), "SDK_VALUE_UNKNOWN");
    assert.ok(build({ i_accept_the_risk: true }), "lifted by the explicit flag");
    assert.equal(refusal(() => build({ kas_equivalent: "1", max_value: "1000000001" })), "SDK_VALUE_CAP_INVALID");
    assert.equal(refusal(() => build({ max_value: "1", i_accept_the_risk: true })), "SDK_VALUE_CAP_INVALID");
    assert.ok(build({ kas_equivalent: "1" }), "control: a small declaration is enough");
  });
}

for (const [name, build] of Object.entries(builders)) {
  test(`${name}: the cap comes before the builder's own checks`, () => {
    // A funding of 1,000 sompi is refused by every builder for what it is, within the cap.
    const short = (): FeePaymentJson => feePayment(p.payer, "short", 1_000n);
    assert.equal(refusal(() => build({ kas_equivalent: "1" }, short())), "TX_INSUFFICIENT_FUNDS");
    // The same call, over the cap, is refused for that first.
    assert.equal(refusal(() => build({ kas_equivalent: "1000000001" }, short())), "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(refusal(() => build({}, short())), "SDK_VALUE_UNKNOWN");
  });

  test(`${name}: the fee counts toward the cap`, () => {
    const v = { kas_equivalent: "1" };
    assert.ok(build(v, rich(5_000_000n)), "control: the usual fee");
    assert.ok(build(v, rich(CAP)), "control: a fee of exactly the cap");
    assert.equal(refusal(() => build(v, rich(CAP + 1n))), "SDK_VALUE_CAP_EXCEEDED", "one sompi over");
    assert.equal(refusal(() => build(v, rich(5_000n * 100_000_000n))), "SDK_VALUE_CAP_EXCEEDED", "5,000 KAS");
    assert.ok(build({ i_accept_the_risk: true }, rich(CAP + 1n)), "lifted by the explicit flag");
    // A lowered cap holds the fee to the lowered cap.
    assert.equal(refusal(() => build({ kas_equivalent: "1", max_value: "1000000" }, rich(5_000_000n))), "SDK_VALUE_CAP_EXCEEDED");
  });
}

// The calls that hand out a funding address, check a counterparty's addresses, or check a received
// document before it is signed (spec/CLI.md applies the cap in `address`, `verify` and `ipst
// sign`): each takes the same declaration as the builders and refuses the same way.
const artifacts = { asset: ASSET_ARTIFACT, cash: null };
const offered = {
  asset: T.instantiateForCreation(0, ctx(), VALUE).address(),
  cash: T.instantiateForCreation(1, ctx(), VALUE).address(),
};
const received = T.fundKas(ctx(), feePayment(p.buyer), VALUE);
const expired = { ...ctx(), creation_daa: "2000000" };
const entryPoints: Record<string, (v: ValueJson) => unknown> = {
  instantiateForCreation: (v) => T.instantiateForCreation(1, ctx(), v).address(),
  verifyAddresses: (v) => T.verifyAddresses(ctx(), offered, v),
  beforeFunding: (v) => T.beforeFunding(ctx(), offered, { asset: null, cash: null }, v),
  verifyAgainstTerms: (v) => received.verifyAgainstTerms(artifacts, daa, v),
};
/** The same call made invalid for its own reasons, within the cap it gives this code. */
const invalid: Record<string, [string, (v: ValueJson) => unknown]> = {
  instantiateForCreation: ["TERMS_EXPIRY_NOT_AFTER_CREATION", (v) => T.instantiateForCreation(1, expired, v)],
  verifyAddresses: ["VERIFY_ADDRESS_MISSING", (v) => T.verifyAddresses(ctx(), { ...offered, cash: null }, v)],
  beforeFunding: [
    "VERIFY_ADDRESS_MISSING",
    (v) => T.beforeFunding(ctx(), { ...offered, cash: null }, { asset: null, cash: null }, v),
  ],
  verifyAgainstTerms: ["TX_EXPIRED", (v) => received.verifyAgainstTerms(artifacts, "2000000", v)],
};

for (const [name, call] of Object.entries(entryPoints)) {
  test(`${name} applies the value cap: refused above it, answered within it or with the flag`, () => {
    assert.ok(call({ kas_equivalent: "1000000000" }), "control: a declared value at the cap");
    assert.equal(refusal(() => call({ kas_equivalent: "1000000001" })), "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(refusal(() => call({})), "SDK_VALUE_UNKNOWN");
    assert.equal(refusal(() => call({ kas_equivalent: "0" })), "SDK_VALUE_UNKNOWN");
    assert.ok(call({ i_accept_the_risk: true }), "lifted by the explicit flag");
    assert.equal(refusal(() => call({ kas_equivalent: "1", max_value: "1000000001" })), "SDK_VALUE_CAP_INVALID");
    assert.equal(refusal(() => call({ max_value: "1", i_accept_the_risk: true })), "SDK_VALUE_CAP_INVALID");
    assert.ok(call({ kas_equivalent: "1" }), "control: a small declaration is enough");
    // A KAS leg above the cap is over it whatever is declared: the cash leg of 10 KAS + 1 sompi.
    const big = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), cash_leg: { kind: "kas", amount: "1000000001" } });
    const bigOffered = {
      asset: big.instantiateForCreation(0, ctx(), { i_accept_the_risk: true }).address(),
      cash: big.instantiateForCreation(1, ctx(), { i_accept_the_risk: true }).address(),
    };
    const again: Record<string, (v: ValueJson) => unknown> = {
      instantiateForCreation: (v) => big.instantiateForCreation(1, ctx(), v),
      verifyAddresses: (v) => big.verifyAddresses(ctx(), bigOffered, v),
      beforeFunding: (v) => big.beforeFunding(ctx(), bigOffered, { asset: null, cash: null }, v),
      verifyAgainstTerms: (v) =>
        big.fundKas(ctx(), feePayment(p.buyer, "big", 5_000_000_000n), { i_accept_the_risk: true }).verifyAgainstTerms(artifacts, daa, v),
    };
    assert.equal(refusal(() => again[name]({ kas_equivalent: "1" })), "SDK_VALUE_CAP_EXCEEDED");
    assert.ok(again[name]({ i_accept_the_risk: true }), "lifted");
  });

  test(`${name}: the cap comes before the call's own checks`, () => {
    const [code, bad] = invalid[name];
    assert.equal(refusal(() => bad({ kas_equivalent: "1" })), code, "control: within the cap, the call's own refusal");
    assert.equal(refusal(() => bad({ kas_equivalent: "1000000001" })), "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(refusal(() => bad({})), "SDK_VALUE_UNKNOWN");
  });
}

test("no funding address is handed out for a trade above the cap", () => {
  const big = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), cash_leg: { kind: "kas", amount: "500000000000" } });
  // 5,000 KAS: refused with the declaration that is enough for the usual trade, and with none.
  assert.equal(refusal(() => big.instantiateForCreation(1, ctx(), { kas_equivalent: "1" })), "SDK_VALUE_CAP_EXCEEDED");
  assert.equal(refusal(() => big.instantiateForCreation(0, ctx(), {})), "SDK_VALUE_UNKNOWN");
  assert.match(big.instantiateForCreation(1, ctx(), { i_accept_the_risk: true }).address(), /^kaspa:/);
  // The signer's check counts the fee the document pays, as the builders count the fee they take.
  const fee = BigInt(sdk.defaultMaxValueSompi()) + 1n;
  const doc = T.fundKas(ctx(), feePayment(p.buyer, "fat", 5_000_000_000n, fee), { i_accept_the_risk: true });
  assert.equal(refusal(() => doc.verifyAgainstTerms(artifacts, daa, { kas_equivalent: "1" })), "SDK_VALUE_CAP_EXCEEDED");
  assert.ok(doc.verifyAgainstTerms(artifacts, daa, { i_accept_the_risk: true }));
});

test("fundKcc20: the carrier and the authorizer count toward the cap, singly and together", () => {
  const fund = (d: ReturnType<typeof deposit>, v: ValueJson = { kas_equivalent: "1" }) =>
    T.fundKcc20(0, ctx(), d, rich(5_000_000n), v);
  assert.ok(fund(deposit()), "control: the minimums");
  assert.ok(fund(deposit(CAP - AUTHORIZER, AUTHORIZER)), "control: together exactly the cap");
  assert.equal(refusal(() => fund(deposit(CAP - AUTHORIZER + 1n, AUTHORIZER))), "SDK_VALUE_CAP_EXCEEDED", "together one over");
  assert.equal(refusal(() => fund(deposit(CAP + 1n))), "SDK_VALUE_CAP_EXCEEDED", "a carrier over the cap");
  assert.equal(refusal(() => fund(deposit(CARRIER, CAP + 1n))), "SDK_VALUE_CAP_EXCEEDED", "an authorizer over the cap");
  assert.equal(refusal(() => fund(deposit(1_000_000n * 100_000_000n))), "SDK_VALUE_CAP_EXCEEDED", "a carrier of 1,000,000 KAS");
  assert.ok(fund(deposit(CAP + 1n), { i_accept_the_risk: true }), "lifted by the explicit flag");
});

test("the cap comes before any builder check, and the declaration cannot lower a KAS leg", () => {
  const short = feePayment(p.buyer, "short", 1_000n);
  // Control: within the cap, the short funding is the builder's refusal.
  assert.equal(refusal(() => T.fundKas(ctx(), short, { kas_equivalent: "1" })), "TX_INSUFFICIENT_FUNDS");
  assert.equal(refusal(() => T.fundKas(ctx(), short, { kas_equivalent: "1000000001" })), "SDK_VALUE_CAP_EXCEEDED");
  // A KAS cash leg of 10 KAS + 1 sompi is over the cap whatever is declared.
  const big = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), cash_leg: { kind: "kas", amount: "1000000001" } });
  assert.equal(refusal(() => big.fundKas(ctx(), feePayment(p.buyer, "big", 5_000_000_000n), { kas_equivalent: "1" })), "SDK_VALUE_CAP_EXCEEDED");
  assert.ok(big.fundKas(ctx(), feePayment(p.buyer, "big", 5_000_000_000n), { i_accept_the_risk: true }), "lifted");
  // max_value lowers the cap: the 1 KAS cash leg passes at 1 KAS and not a sompi under.
  assert.ok(T.fundKas(ctx(), feePayment(p.buyer), { kas_equivalent: "1", max_value: KAS_CASH.toString() }));
  assert.equal(
    refusal(() => T.fundKas(ctx(), feePayment(p.buyer), { kas_equivalent: "1", max_value: (KAS_CASH - 1n).toString() })),
    "SDK_VALUE_CAP_EXCEEDED",
  );
  assert.equal(sdk.defaultMaxValueSompi(), "1000000000");
});
