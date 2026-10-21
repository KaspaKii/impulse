// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Every builder in every trade mode, through the package: settle in each vault mode, refund by
// each role of each leg, fund of each leg kind, Direct with KAS and KCC-20 cash. Each document is
// built, signed by the keys its slots name (runtime throwaway keys), merged, assembled, decoded
// where it spends a vault, and answered natively (oracle.ts) the same, byte for byte.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import type { Ipst, RefundSignerName, ValidatedTerms } from "../index.js";
import { rec } from "./calls.ts";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  CASH_ARTIFACT,
  CASH_COV,
  KCC20_CASH,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  funded,
  newParties,
  ownToken,
  ring,
  settleLegs,
  signedBy,
  spentScripts,
  termsJson,
  validated,
} from "./fixtures.ts";
import type { Mode } from "./fixtures.ts";
import { checkAgainstNative } from "./oracle.ts";
import { hex, load } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();
const artifacts = { asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT };
const keys = ring(p);

/** Signs with every key the slots name, merges the copies and assembles: a complete transaction. */
function complete(unsigned: Ipst) {
  const text = unsigned.toJson();
  const names = [...new Set(unsigned.slots().map((s) => s.signer).filter((s): s is string => s !== null))];
  const copies = names.map((n) => signedBy(sdk, text, keys.get(n) as never));
  let merged = sdk.Ipst.fromJson(copies[0]);
  for (const copy of copies.slice(1)) merged = rec.combine(merged, copy);
  assert.deepEqual(merged.pending(), []);
  const signed = merged.finalize();
  const signatures = merged
    .slots()
    .filter((s) => s.signature !== null)
    .map((s) => ({ input: s.input, signature: s.signature as string }));
  const assembled = rec.assemble(unsigned, signatures);
  assert.equal(hex(assembled.raw()), hex(signed.raw()));
  return { signed, text };
}

const T = (mode: Mode): ValidatedTerms => validated(sdk, termsJson(sdk, p, mode));

for (const [name, mode] of Object.entries(MODES).filter(([, m]) => m.settlement === "vault")) {
  test(`settle in ${name}: built, signed, merged, assembled and decoded`, () => {
    const terms = T(mode);
    const f = funded(sdk, terms, mode);
    // The vault UTXOs sit at output indices other than 0, so that the decoded outpoint is read
    // from the input and not defaulted.
    f.assetAuthorizer.index = 3;
    if (f.cashVault) f.cashVault.index = 5;
    if (f.cashAuthorizer) f.cashAuthorizer.index = 5;
    const unsigned = rec.settle(terms, settleLegs(f), feePayment(p.payer), daa, VALUE);
    assert.equal(rec.verifyAgainstTerms(unsigned, artifacts, daa).kind.builder, "settle");
    const { signed, text } = complete(unsigned);
    const decoded = rec.decodeRaw(sdk, signed.raw(), spentScripts(text), "mainnet");
    assert.deepEqual(decoded.refused, []);
    // External cash settles the asset leg only: the cash is paid off chain.
    const legs = mode.cash === "external" ? [0] : [0, 1];
    assert.deepEqual(decoded.legs.map((l) => l.leg), legs);
    assert.ok(decoded.legs.every((l) => l.entry.kind === "settle" && l.outcome.kind === "delivered"));
    // What each decoded leg says: the outpoint it spends (from the document's input), the
    // amount it delivers and where to, as the terms agreed.
    const doc = JSON.parse(text) as { inputs: { transaction_id: string; index: number }[] };
    const agreed = termsJson(sdk, p, mode);
    for (const l of decoded.legs) {
      assert.deepEqual(
        l.outpoint,
        { transaction_id: doc.inputs[l.input_index].transaction_id, index: doc.inputs[l.input_index].index },
        `leg ${l.leg}: outpoint`,
      );
      assert.equal(l.outpoint.index, l.leg === 0 ? 3 : 5);
      assert.equal(l.terms_hash, hex(terms.termsHash()), `leg ${l.leg}: terms hash`);
      assert.equal(l.script_hash, hex(terms.instantiateExisting(l.leg === 0 ? 0 : 1).scriptHash()), `leg ${l.leg}: script hash`);
      assert.deepEqual(
        l.outcome,
        l.leg === 0
          ? { kind: "delivered", amount: agreed.asset_leg.amount, to: agreed.buyer_delivery }
          : { kind: "delivered", amount: agreed.cash_leg.amount, to: agreed.seller_proceeds },
        `leg ${l.leg}: outcome`,
      );
    }
    // The authority signs the vault inputs in the authority modes; in self-settling there is no
    // vault signature at all.
    const vaultSigners = unsigned.slots().slice(0, legs.length * 2).map((s) => s.signer);
    assert.equal(vaultSigners.includes(p.authority.publicHex), mode.authority);
  });
}

type Refund = { mode: Mode; leg: 0 | 1; signer: RefundSignerName; withToken: boolean };
const refunds: Refund[] = [];
for (const signer of ["depositor", "counterparty", "authority"] as const) {
  refunds.push({ mode: MODES.vaultKas, leg: 0, signer, withToken: true });
  refunds.push({ mode: MODES.vaultKas, leg: 1, signer, withToken: false });
  refunds.push({ mode: MODES.vaultKcc20, leg: 1, signer, withToken: true });
}
refunds.push({ mode: MODES.vaultKas, leg: 0, signer: "depositor", withToken: false });
refunds.push({ mode: MODES.vaultKcc20, leg: 1, signer: "depositor", withToken: false });
refunds.push({ mode: MODES.selfSettling, leg: 0, signer: "depositor", withToken: true });
refunds.push({ mode: MODES.selfSettling, leg: 1, signer: "counterparty", withToken: true });

for (const { mode, leg, signer, withToken } of refunds) {
  const label = `${mode.cash} cash, leg ${leg}, by the ${signer}${withToken ? " with the token" : " alone"}`;
  test(`refund: ${label}`, () => {
    const terms = T(mode);
    const f = funded(sdk, terms, mode);
    const [vaultUtxo, escrowUtxo, artifact, amount] =
      leg === 0
        ? [f.assetAuthorizer, f.assetEscrow, ASSET_ARTIFACT, "1000"]
        : f.cashVault
          ? [f.cashVault, undefined, CASH_ARTIFACT, "0"]
          : [f.cashAuthorizer as never, f.cashEscrow, CASH_ARTIFACT, KCC20_CASH.toString()];
    const escrow = withToken && escrowUtxo ? { artifact, utxo: escrowUtxo, amount, is_minter: false } : null;
    vaultUtxo.index = 7; // not 0, so that the decoded outpoint is read from the input
    const unsigned = rec.refund(terms, leg, signer, vaultUtxo, escrow, feePayment(p.payer), VALUE);
    const checked = rec.verifyAgainstTerms(unsigned, artifacts, daa);
    assert.deepEqual(checked.kind, { builder: "refund", leg, signer, with_token: escrow !== null });
    const { signed, text } = complete(unsigned);
    const decoded = rec.decodeRaw(sdk, signed.raw(), spentScripts(text), "mainnet");
    assert.deepEqual(decoded.refused, []);
    assert.equal(decoded.legs[0].entry.kind, "refund");
    assert.equal(decoded.legs[0].outcome.kind, "refunded");
    assert.equal(decoded.legs[0].leg, leg);
    const party = { depositor: leg === 0 ? "seller" : "buyer", counterparty: leg === 0 ? "buyer" : "seller", authority: "authority" }[signer];
    assert.equal((decoded.legs[0].entry as { party: string | null }).party, party);
    // The key that signed the refund, the outpoint it spends, and where the leg went home.
    const key = { seller: p.seller.publicHex, buyer: p.buyer.publicHex, authority: p.authority.publicHex }[party as "seller"];
    assert.equal((decoded.legs[0].entry as { signer: string | null }).signer, key, "the refund signer's key");
    const doc = JSON.parse(text) as { inputs: { transaction_id: string; index: number }[] };
    assert.deepEqual(decoded.legs[0].outpoint, { transaction_id: doc.inputs[0].transaction_id, index: 7 }, "the outpoint");
    const agreed = termsJson(sdk, p, mode);
    assert.deepEqual(
      decoded.legs[0].outcome,
      { kind: "refunded", to: leg === 0 ? agreed.seller_refund : agreed.buyer_refund },
      "refunded to the depositor's refund destination",
    );
  });
}

test("fund_kcc20 funds the cash leg of KCC-20 cash terms, from exactly the leg amount", () => {
  const terms = T(MODES.vaultKcc20);
  const deposit = {
    artifact: CASH_ARTIFACT,
    tokens: [ownToken(sdk, "buyer-cash", CASH_ARTIFACT, CASH_COV, p.buyer.publicHex, KCC20_CASH)],
    carrier: CARRIER.toString(),
    authorizer: AUTHORIZER.toString(),
  };
  const unsigned = rec.fundKcc20(terms, 1, ctx(), deposit, feePayment(p.payer), VALUE);
  assert.deepEqual(rec.verifyAgainstTerms(unsigned, artifacts, daa).kind, { builder: "fund_kcc20", leg: 1 });
  const { signed } = complete(unsigned);
  assert.equal(signed.txid().length, 32);
  // Exactly the leg amount: no token change output (escrow, authorizer, KAS change).
  assert.equal(JSON.parse(unsigned.toJson()).outputs.length, 3);
});

test("Direct with KCC-20 cash: built, signed by seller, buyer and payer, merged and assembled", () => {
  const terms = T(MODES.directKcc20);
  const legs = {
    asset_artifact: ASSET_ARTIFACT,
    asset: ownToken(sdk, "seller-asset", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
    cash: {
      kind: "kcc20" as const,
      artifact: CASH_ARTIFACT,
      token: ownToken(sdk, "buyer-cash", CASH_ARTIFACT, CASH_COV, p.buyer.publicHex, KCC20_CASH),
    },
  };
  const unsigned = rec.direct(terms, legs, feePayment(p.payer), daa, VALUE);
  assert.deepEqual(rec.verifyAgainstTerms(unsigned, artifacts, daa).kind, { builder: "direct" });
  const { signed } = complete(unsigned);
  assert.ok(signed.raw().length > 0);
});

test("every call above answers as impulse-core's native builders do, byte for byte", () => {
  assert.ok(checkAgainstNative() > 40);
});
