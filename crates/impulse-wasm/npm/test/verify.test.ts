// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The verifier and the decoder through the package: what they report, beside what they refuse
// (the refusal codes are in tx-refusals.test.ts). A token warning is data read from the evidence
// supplied; none of these tests treats an empty list as a safety claim.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  AMOUNT_A,
  ASSET_ARTIFACT,
  ASSET_COV,
  CASH_ARTIFACT,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  funded,
  newParties,
  p2pk,
  settleLegs,
  signedBy,
  spentScripts,
  termsJson,
  tokenLeg,
  unpinnedToken,
  validated,
} from "./fixtures.ts";
import { hex, load, refusal, unhex } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();

const T = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
const T_TOKENS = validated(sdk, termsJson(sdk, p, MODES.vaultKcc20));
const offered = (t: typeof T) => ({
  asset: t.instantiateForCreation(0, ctx(), VALUE).address(),
  cash: t.instantiateForCreation(1, ctx(), VALUE).address(),
});
const evidence = (artifact: string, issuer_keys: string[] = []) => ({ artifact, issuer_keys });

test("token warnings are data: what the evidence shows, never a statement that a token is safe", () => {
  // Evidence for the asset leg, no issuer keys known: the minter branch of kcc20.sil, and that
  // nobody was checked as an issuer.
  const plain = T.beforeFunding(ctx(), offered(T), { asset: evidence(ASSET_ARTIFACT), cash: null }, VALUE);
  assert.deepEqual(plain.warnings, [
    { leg: 0, code: "TOKEN_MINTER_BRANCH" },
    { leg: 0, code: "TOKEN_ISSUER_UNKNOWN" },
  ]);
  assert.equal(plain.token_legs_assessed, true);
  assert.deepEqual(
    plain.addresses.map((a) => a.leg),
    [0, 1],
  );

  // No evidence for a KCC-20 leg: unassessed, and the result says so.
  const none = T.beforeFunding(ctx(), offered(T), { asset: null, cash: null }, VALUE);
  assert.deepEqual(none.warnings, [{ leg: 0, code: "TOKEN_UNASSESSED" }]);
  assert.equal(none.token_legs_assessed, false);

  // Issuer keys the caller knows: the authority is among them, and so is the seller.
  const keyed = T.tokenWarnings({
    asset: evidence(ASSET_ARTIFACT, [p.authority.publicHex, p.seller.publicHex]),
    cash: null,
  });
  assert.deepEqual(keyed, [
    { leg: 0, code: "TOKEN_MINTER_BRANCH" },
    { leg: 0, code: "TOKEN_PARTY_IS_ISSUER", party: "seller", relation: "depositor" },
    { leg: 0, code: "TOKEN_PARTY_IS_ISSUER", party: "authority", relation: "authority" },
  ]);
  // A stranger's key is no party: no warning of that kind, and no unknown-issuer warning either.
  const stranger = T.tokenWarnings({ asset: evidence(ASSET_ARTIFACT, ["02".repeat(32)]), cash: null });
  assert.deepEqual(stranger, [{ leg: 0, code: "TOKEN_MINTER_BRANCH" }]);

  // Both legs KCC-20: the cash leg's warnings carry leg 1, and its relations are the buyer's.
  const both = T_TOKENS.tokenWarnings({
    asset: evidence(ASSET_ARTIFACT, [p.buyer.publicHex]),
    cash: evidence(CASH_ARTIFACT, [p.buyer.publicHex]),
  });
  assert.deepEqual(
    both.filter((w) => w.code === "TOKEN_PARTY_IS_ISSUER").map((w) => [w.leg, w.party, w.relation]),
    [
      [0, "buyer", "counterparty"],
      [1, "buyer", "depositor"],
    ],
  );
  assert.deepEqual(sdk.tokenWarningCodes().sort(), [
    "TOKEN_EXTRA_ENTRIES",
    "TOKEN_FOREIGN_AT_VAULT",
    "TOKEN_ISSUER_UNKNOWN",
    "TOKEN_MINTER_BRANCH",
    "TOKEN_PARTY_IS_ISSUER",
    "TOKEN_TEMPLATE_UNPINNED",
    "TOKEN_UNASSESSED",
  ]);
});

test("a template outside the pinned set is flagged, and the entries it declares beyond KCC-20's are named", () => {
  const unpinned = unpinnedToken();
  const named = unpinnedToken(["freeze", "clawback"]);
  // Both name the same template: entries are not in the template hash.
  const triple = sdk.kcc20Template(unpinned);
  assert.deepEqual(sdk.kcc20Template(named), triple);
  assert.notDeepEqual(triple, sdk.kcc20Template(ASSET_ARTIFACT), "not the pinned build");
  const terms = validated(sdk, { ...termsJson(sdk, p, MODES.vaultKas), asset_leg: tokenLeg(sdk, unpinned, ASSET_COV, AMOUNT_A) });

  // Control: the pinned build has neither warning (above). The same token off the pinned set is
  // flagged, the minter branch and the unknown issuer beside it.
  assert.deepEqual(terms.tokenWarnings({ asset: evidence(unpinned), cash: null }), [
    { leg: 0, code: "TOKEN_MINTER_BRANCH" },
    { leg: 0, code: "TOKEN_TEMPLATE_UNPINNED" },
    { leg: 0, code: "TOKEN_ISSUER_UNKNOWN" },
  ]);
  // The entries it declares beyond KCC-20's two are named, sorted by name.
  assert.deepEqual(terms.tokenWarnings({ asset: evidence(named), cash: null }), [
    { leg: 0, code: "TOKEN_MINTER_BRANCH" },
    { leg: 0, code: "TOKEN_TEMPLATE_UNPINNED" },
    { leg: 0, code: "TOKEN_EXTRA_ENTRIES", entries: ["clawback", "freeze"] },
    { leg: 0, code: "TOKEN_ISSUER_UNKNOWN" },
  ]);
  // beforeFunding reports the same warnings beside the addresses.
  const offeredFor = {
    asset: terms.instantiateForCreation(0, ctx(), VALUE).address(),
    cash: terms.instantiateForCreation(1, ctx(), VALUE).address(),
  };
  const funding = terms.beforeFunding(ctx(), offeredFor, { asset: evidence(named), cash: null }, VALUE);
  assert.deepEqual(
    funding.warnings.map((w) => w.code),
    ["TOKEN_MINTER_BRANCH", "TOKEN_TEMPLATE_UNPINNED", "TOKEN_EXTRA_ENTRIES", "TOKEN_ISSUER_UNKNOWN"],
  );
  // A pinned template that declares an entry it does not have is refused, not warned about.
  const pinnedWithEntry = JSON.parse(ASSET_ARTIFACT);
  pinnedWithEntry.contracts.KCC20.entries.clawback = {
    ...pinnedWithEntry.contracts.KCC20.entries.__delegate,
    dispatch_tag: "0badf00d",
  };
  assert.equal(
    refusal(() => T.tokenWarnings({ asset: evidence(JSON.stringify(pinnedWithEntry)), cash: null })),
    "VERIFY_TOKEN_ARTIFACT_INVALID",
  );
});

test("the evidence form is strict", () => {
  const ok = { asset: evidence(ASSET_ARTIFACT), cash: null };
  assert.ok(T.tokenWarnings(ok), "control");
  const refused = (e: unknown) => refusal(() => T.tokenWarnings(e as never));
  assert.equal(refused({ asset: evidence(ASSET_ARTIFACT) }), "SDK_JSON_FORM", "cash missing");
  assert.equal(refused({ ...ok, extra: null }), "SDK_JSON_FORM");
  assert.equal(refused({ asset: { artifact: ASSET_ARTIFACT }, cash: null }), "SDK_JSON_FORM", "no issuer_keys");
  assert.equal(refused({ asset: evidence(ASSET_ARTIFACT, ["AB".repeat(32)]), cash: null }), "SDK_JSON_FORM");
  assert.equal(refused({ asset: evidence(ASSET_ARTIFACT, ["ab".repeat(31)]), cash: null }), "SDK_JSON_FORM");
  assert.equal(refused({ asset: evidence(ASSET_ARTIFACT, Array(257).fill("ab".repeat(32))), cash: null }), "SDK_JSON_FORM");
  assert.equal(refused({ asset: evidence(5 as never), cash: null }), "SDK_JSON_FORM");
  const offeredForm = (o: unknown) => refusal(() => T.verifyAddresses(ctx(), o as never, VALUE));
  assert.ok(T.verifyAddresses(ctx(), offered(T), VALUE), "control");
  assert.equal(offeredForm({ asset: offered(T).asset }), "SDK_JSON_FORM", "cash missing");
  assert.equal(offeredForm({ ...offered(T), extra: null }), "SDK_JSON_FORM");
  assert.equal(offeredForm({ asset: 5, cash: null }), "SDK_JSON_FORM");
});

test("decoding reports each vault input, and the unbound form says it is unbound", () => {
  const f = funded(sdk, T, MODES.vaultKas);
  const settle = T.settle(settleLegs(f), feePayment(p.payer), daa, VALUE);
  const text = settle.toJson();
  const tx = sdk.Ipst.fromJson(signedBy(sdk, text, p.authority)).combine(signedBy(sdk, text, p.payer)).finalize();
  const spent = spentScripts(text);

  const bound = sdk.decodeRaw(tx.raw(), spent, "mainnet");
  const unbound = sdk.decodeRawUnbound(tx.raw(), "mainnet");
  assert.equal(bound.bound, true);
  assert.equal(unbound.bound, false);
  assert.deepEqual({ ...unbound, bound: true }, bound, "the same legs");
  assert.equal(bound.txid, hex(tx.txid()));
  assert.deepEqual(
    bound.legs.map((l) => ({ input: l.input_index, leg: l.leg, hash: l.script_hash })),
    [
      { input: 0, leg: 0, hash: hex(T.instantiateExisting(0).scriptHash()) },
      { input: 1, leg: 1, hash: hex(T.instantiateExisting(1).scriptHash()) },
    ],
  );
  assert.deepEqual(bound.legs[0].terms, termsJson(sdk, p, MODES.vaultKas), "the terms read back");
  assert.equal(sdk.Terms.fromJson(bound.legs[1].terms).validateStructure().canonical().length, T.canonical().length);

  // One vault input whose spent UTXO is not its vault is refused on its own, beside the leg that
  // decodes; with the binding gone (unbound) both decode.
  const one = spent.map((s, i) => (i === 1 ? p2pk(p.seller.publicHex) : s));
  const mixed = sdk.decodeRaw(tx.raw(), one, "mainnet");
  assert.deepEqual(
    mixed.legs.map((l) => l.input_index),
    [0],
  );
  assert.deepEqual(
    mixed.refused.map((r) => [r.code, r.input_index]),
    [["DECODE_INPUT_NOT_VAULT", 1]],
  );
  assert.ok(mixed.refused[0].message.startsWith("DECODE_INPUT_NOT_VAULT") || mixed.refused[0].message.includes("input 1"));

  // The scriptPublicKey version is part of the binding: the vault's own script under version 1
  // is not its vault. Control: the same transaction under version 0 decodes both inputs (above).
  const versioned = sdk.decodeRaw(tx.raw(), spent.map((s, i) => (i === 1 ? { ...s, version: 1 } : s)), "mainnet");
  assert.deepEqual(
    versioned.legs.map((l) => l.input_index),
    [0],
  );
  assert.deepEqual(
    versioned.refused.map((r) => [r.code, r.input_index]),
    [["DECODE_INPUT_NOT_VAULT", 1]],
  );

  // The network is the caller's: a vault of another network is refused for it.
  assert.equal(refusal(() => sdk.decodeRaw(tx.raw(), spent, "testnet")), "TERMS_NETWORK_MISMATCH");
  assert.equal(refusal(() => sdk.decodeRaw(tx.raw(), spent, "tn10" as never)), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.decodeRaw(tx.raw(), spent as never, 5 as never)), "SDK_ARGUMENT_TYPE");
  assert.equal(refusal(() => sdk.decodeRaw("00" as never, spent, "mainnet")), "SDK_ARGUMENT_TYPE");
  assert.equal(refusal(() => sdk.decodeRaw(tx.raw(), { length: 2 } as never, "mainnet")), "SDK_JSON_FORM");
  assert.equal(refusal(() => sdk.decodeRaw(tx.raw(), Array(257).fill(spent[0]), "mainnet")), "SDK_JSON_FORM");
});

test("a spent input verifies against the script it reveals and the UTXO it spends", () => {
  const f = funded(sdk, T, MODES.vaultKas);
  const settle = T.settle(settleLegs(f), feePayment(p.payer), daa, VALUE);
  const signed = JSON.parse(signedBy(sdk, settle.toJson(), p.authority)).inputs;
  const vaultSpk = (leg: 0 | 1) => {
    const spk = T.instantiateExisting(leg).scriptPublicKey();
    return { version: spk.version, script: hex(spk.script) };
  };
  for (const input of [0, 1] as const) {
    const sigScript = unhex(`${signed[input].script_before}41${signed[input].signature}${signed[input].script_after}`);
    T.verifySpentInput(input, sigScript, vaultSpk(input)); // control: accepted
    assert.equal(refusal(() => T.verifySpentInput(input, sigScript, vaultSpk(input === 0 ? 1 : 0))), "VERIFY_INPUT_NOT_VAULT");
    assert.equal(refusal(() => T.verifySpentInput(input === 0 ? 1 : 0, sigScript, vaultSpk(input))), "VERIFY_LEGS_SWAPPED");
  }
  // The revealed script alone: the vault's own, accepted; the other leg's, swapped.
  T.verifyRevealedScript(0, T.instantiateExisting(0).redeemScript());
  assert.equal(refusal(() => T.verifyRevealedScript(1, T.instantiateExisting(0).redeemScript())), "VERIFY_LEGS_SWAPPED");
  // A leg number that is no leg is the template's refusal, as in phase 1.
  assert.equal(refusal(() => T.verifyRevealedScript(2, T.instantiateExisting(0).redeemScript())), "TEMPLATE_LEG_INDEX");
  assert.equal(refusal(() => T.verifySpentInput(0, "00" as never, vaultSpk(0))), "SDK_ARGUMENT_TYPE");
});
