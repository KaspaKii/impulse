// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// What a signer reads before signing (`Ipst.review`, I11 phase 2): every input and output with its
// amount, address and what the terms say it is, the fee, the lock time, and when the transaction
// can be submitted. The expectations are written from the fixtures (the amounts the funded UTXOs
// hold, the addresses of the keys) and not from the review, and each refusal sits beside the
// review it refuses to give.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Ipst, ReviewJson } from "../index.js";
import { utxosFrame } from "./fakenode.ts";
import {
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  EARLIEST,
  EXPIRY,
  FEE_INPUT,
  KAS_CASH,
  NOW,
  VALUE,
  validated,
} from "./fixtures.ts";
import { load, pinOf, refusalError } from "./sdk.ts";
import { MODES, addressFor, freeAll, world } from "./world.ts";
import type { World } from "./world.ts";

const sdk = load();
const daa = NOW.toString();

const reply = (w: World) => utxosFrame(1, w.pool, addressFor(w.network));
const payer = (w: World, fee = "auto") => ({ payer: w.wallets.payer.publicKey(), fee });
const sum = (items: { amount: string }[]) => items.reduce((total, i) => total + BigInt(i.amount), 0n);
const address = (w: World, key: string) => pinOf(w.network, { kind: "kas", version: 0, script: `20${key}ac` });

function checkBooks(r: ReviewJson, ipst: Ipst): void {
  assert.equal(sum(r.inputs) - sum(r.outputs), BigInt(r.fee), "inputs less outputs is the fee");
  assert.equal(r.fee, ipst.fee());
  assert.match(r.fee_kas, /^\d+\.\d{8}$/);
  assert.equal(r.masses.storage, ipst.masses().storage);
  assert.ok(BigInt(r.fee) >= BigInt(r.min_relay_fee), "the fee is not below the minimum relay fee");
}

test("the review of a settle lists every input and output with amount, address and name", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const ipst = w.terms.settleFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
    const r = ipst.review(w.artifacts, daa, VALUE);
    checkBooks(r, ipst);
    assert.deepEqual(r.kind, { builder: "settle" });
    assert.equal(r.network, "testnet");
    assert.equal(r.inputs.length, 4);
    assert.equal(r.outputs.length, 4);
    const [i0, i1, i2, i3] = r.inputs;
    assert.deepEqual([i0.what, i1.what, i2.what], ["the asset vault", "the cash vault", "the asset token escrowed in the asset vault"]);
    assert.match(i3.what, /^a fee input \(P2PK of the key [0-9a-f]{64}\)$/);
    assert.deepEqual([i0.amount, i1.amount, i2.amount, i3.amount], [AUTHORIZER, KAS_CASH, CARRIER, FEE_INPUT].map(String));
    assert.equal(i2.covenant_id, ASSET_COV);
    assert.equal(i3.address, w.wallets.payer.address(w.network));
    assert.deepEqual(r.inputs.map((i) => i.signer), [w.wallets.authority.publicKey(), w.wallets.authority.publicKey(), null, w.wallets.payer.publicKey()]);
    assert.deepEqual(r.inputs.map((i) => i.signed), [false, false, false, false]);
    assert.deepEqual(r.pending, [0, 1, 3]);
    for (const input of r.inputs) assert.match(input.outpoint.transaction_id, /^[0-9a-f]{64}$/);
    const [o0, o1, o2, o3] = r.outputs;
    // The asset to the buyer's delivery, with the token's KAS; the cash to the seller's proceeds;
    // the authorizer's KAS to the seller; the change to the payer.
    assert.match(o0.what, /^buyer_delivery \(the asset arrives here\), as a KCC-20 token$/);
    assert.equal(o0.covenant_id, ASSET_COV);
    assert.equal(o0.amount, CARRIER.toString());
    assert.match(o1.what, /^seller_proceeds \(the cash arrives here\)/);
    assert.equal(o1.amount, KAS_CASH.toString());
    assert.equal(o1.address, address(w, w.wallets.seller.publicKey()));
    assert.match(o2.what, /the seller's key \(P2PK\)/);
    assert.equal(o2.amount, AUTHORIZER.toString());
    assert.match(o3.what, /^change, back to the fee payer/);
    assert.equal(o3.address, w.wallets.payer.address(w.network));
    assert.equal(o3.amount, (FEE_INPUT - BigInt(r.fee)).toString());
    // The lock time of a settle with an earliest score; the node's DAA score is past it.
    assert.equal(r.lock_time, EARLIEST.toString());
    assert.equal(r.final_from_daa, (EARLIEST + 1n).toString());
    assert.equal(r.current_daa, daa);
    assert.equal(r.submit_ready, true);
    assert.equal(r.wait, null);
    // Before the lock time passes the review says so, and how long it is.
    const early = ipst.review(w.artifacts, (EARLIEST - 100n).toString(), VALUE);
    assert.equal(early.submit_ready, false);
    assert.match(early.wait ?? "", /^about \d+ minutes$/);
    const atLock = ipst.review(w.artifacts, EARLIEST.toString(), VALUE);
    assert.equal(atLock.submit_ready, false, "final only from the score after the lock time");
    assert.equal(ipst.review(w.artifacts, (EARLIEST + 1n).toString(), VALUE).submit_ready, true);
  } finally {
    freeAll(w.wallets);
  }
});

test("the review of a Direct trade names the parties' own tokens and cash", () => {
  const w = world(sdk, MODES.directKcc20);
  try {
    const ipst = w.terms.directFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
    const r = ipst.review(w.artifacts, daa, VALUE);
    checkBooks(r, ipst);
    assert.deepEqual(r.kind, { builder: "direct" });
    assert.match(r.inputs[0].what, /^the seller's asset token \(KCC-20, owner the seller's key\)$/);
    assert.match(r.inputs[1].what, /^the buyer's cash token \(KCC-20, owner the buyer's key\)$/);
    assert.match(r.outputs[0].what, /^buyer_delivery/);
    assert.match(r.outputs[1].what, /^seller_proceeds \(the cash arrives here\), as a KCC-20 token$/);
    assert.deepEqual(r.pending, [0, 1, 2]);
    assert.deepEqual(r.inputs.map((i) => i.signer), [w.wallets.seller.publicKey(), w.wallets.buyer.publicKey(), w.wallets.payer.publicKey()]);
  } finally {
    freeAll(w.wallets);
  }
});

test("the review of a refund names where the leg goes home, and when it can be submitted", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const refund = (signer: "depositor" | "counterparty") =>
      w.terms.refundFromReply(1, signer, false, w.artifacts, reply(w), payer(w), VALUE);
    // The buyer's cash goes home to the buyer's refund destination.
    const byCounterparty = refund("counterparty");
    const c = byCounterparty.review(w.artifacts, daa, VALUE);
    checkBooks(c, byCounterparty);
    assert.deepEqual(c.kind, { builder: "refund", leg: 1, signer: "counterparty", with_token: false });
    assert.match(c.outputs[0].what, /^buyer_refund \(the cash returns here\)/);
    assert.equal(c.outputs[0].amount, KAS_CASH.toString());
    assert.equal(c.lock_time, "0");
    assert.equal(c.final_from_daa, null);
    assert.equal(c.submit_ready, true);
    // The depositor of an earmarked leg waits for the expiry.
    const byDepositor = refund("depositor");
    const d = byDepositor.review(w.artifacts, daa, VALUE);
    assert.equal(d.lock_time, EXPIRY.toString());
    assert.equal(d.final_from_daa, (EXPIRY + 1n).toString());
    assert.equal(d.submit_ready, false);
    assert.match(d.wait ?? "", /^about \d+ hours$/);
    assert.equal(byDepositor.review(w.artifacts, (EXPIRY + 1n).toString(), VALUE).submit_ready, true);
  } finally {
    freeAll(w.wallets);
  }
});

test("a document the builders would not make, or above the cap, has no review, beside the one that has", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const ipst = w.terms.settleFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
    assert.ok(ipst.review(w.artifacts, daa, VALUE).outputs.length > 0, "control");
    const doc = JSON.parse(ipst.toJson()) as { inputs: { compute_budget: number }[] };
    doc.inputs[0].compute_budget += 1;
    const raised = sdk.Ipst.fromJson(JSON.stringify(doc, null, 2));
    assert.equal(refusalError(() => raised.review(w.artifacts, daa, VALUE)).code, "IPST_TERMS_MISMATCH");
    assert.equal(refusalError(() => ipst.review(w.artifacts, daa, { kas_equivalent: "1000000001" })).code, "SDK_VALUE_CAP_EXCEEDED");
    assert.equal(refusalError(() => ipst.review(w.artifacts, daa, {})).code, "SDK_VALUE_UNKNOWN");
    assert.equal(refusalError(() => ipst.review(w.artifacts, "99999999999", VALUE)).code, "TX_EXPIRED");
    assert.equal(refusalError(() => ipst.review({ asset: "{}", cash: null }, daa, VALUE)).code, "TX_TOKEN_TEMPLATE");
    assert.equal(refusalError(() => ipst.review(w.artifacts, 5 as unknown as string, VALUE)).code, "SDK_ARGUMENT_TYPE");
  } finally {
    freeAll(w.wallets);
  }
});

test("the review is a pure reading: it changes nothing in the document and shows the same twice", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const ipst = w.terms.directFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
    const text = ipst.toJson();
    const first = ipst.review(w.artifacts, daa, VALUE);
    assert.deepEqual(ipst.review(w.artifacts, daa, VALUE), first);
    assert.equal(ipst.toJson(), text);
  } finally {
    freeAll(w.wallets);
  }
});

test("the review titles the document by what it does, and for external cash says the cash is paid outside Kaspa and what the authority's signature means", () => {
  const titles = {
    vault: "Settle: the asset to the buyer, the cash to the seller",
    direct: "Direct trade: the asset to the buyer, the cash to the seller",
    external:
      "Settle: the asset to the buyer; the cash is paid outside Kaspa, and the authority's signature attests it",
  };
  const cases = [
    ["vaultKas", "settle", titles.vault],
    ["directKas", "direct", titles.direct],
    ["external", "settle", titles.external],
  ] as const;
  for (const [mode, builder, title] of cases) {
    const w = world(sdk, MODES[mode]);
    try {
      const ipst =
        builder === "direct"
          ? w.terms.directFromReply(w.artifacts, reply(w), payer(w), daa, VALUE)
          : w.terms.settleFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
      const r = ipst.review(w.artifacts, daa, VALUE);
      assert.equal(r.title, title, mode);
      // Who each signature is for, as the terms name the key.
      const authority = w.wallets.authority.publicKey();
      const roles = r.inputs.map((i) => [i.signer === null ? null : i.signer === w.wallets.payer.publicKey() ? "payer" : i.signer_role, i.signer_role]);
      assert.ok(roles.every(([, role]) => role !== undefined), mode);
      const authorityInputs = r.inputs.filter((i) => i.signer === authority).map((i) => i.index);
      if (mode === "external") {
        assert.deepEqual(authorityInputs.length > 0, true);
        assert.equal(r.notes.length, 1);
        assert.match(r.notes[0], /^Inputs? [0-9, ]+ (is|are) signed by the authority\. The cash leg is paid outside Kaspa/);
        assert.match(r.notes[0], /signing it attests that the cash was paid\. Impulse does not check the payment\.$/);
        assert.ok(r.inputs.filter((i) => i.signer_role === "authority").every((i) => i.signer === authority));
      } else if (mode === "vaultKas") {
        // An authority signs the vault inputs of this trade; the note says only whose key it is.
        assert.match(r.notes[0], /signed by the authority_key of the terms\. Sign it only if you are the authority\.$/);
        assert.doesNotMatch(r.notes[0], /outside Kaspa/);
      } else {
        assert.deepEqual(r.notes, [], "no authority, no note");
      }
      // A fee input's key is none of the parties' in the world, and the review says so.
      const fee = r.inputs[r.inputs.length - 1];
      assert.equal(fee.signer, w.wallets.payer.publicKey());
      assert.equal(fee.signer_role, "other");
    } finally {
      freeAll(w.wallets);
    }
  }
  // The refund titles, beside the settle's.
  const w = world(sdk, MODES.vaultKas);
  try {
    const refund = (leg: 0 | 1, signer: "depositor" | "counterparty" | "authority", token: boolean) =>
      w.terms.refundFromReply(leg, signer, token, w.artifacts, reply(w), payer(w), VALUE).review(w.artifacts, daa, VALUE).title;
    assert.equal(refund(1, "counterparty", false), "Refund of the cash leg, signed by the counterparty");
    assert.equal(refund(0, "depositor", true), "Refund of the asset leg, signed by the depositor, the escrowed token going home too");
    assert.equal(refund(0, "depositor", false), "Refund of the asset leg, signed by the depositor");
    assert.equal(refund(0, "authority", true), "Refund of the asset leg, signed by the authority, the escrowed token going home too");
  } finally {
    freeAll(w.wallets);
  }
});

test("the review shows what the fee payer pays beyond the fee: nothing for a funded vault, the top-up for a starved one", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const ok = w.terms.settleFromReply(w.artifacts, reply(w), payer(w), daa, VALUE).review(w.artifacts, daa, VALUE);
    assert.deepEqual([ok.payer_cost, ok.payer_cost_kas, ok.payer_cost_text], ["0", "0.00000000", "none"]);
    const starvedPool = w.pool.map((u) => (u.amount === AUTHORIZER.toString() && u.covenant_id === null ? { ...u, amount: "1" } : u));
    const starvedReply = utxosFrame(1, starvedPool, addressFor(w.network));
    const bad = w.terms.settleFromReply(w.artifacts, starvedReply, payer(w), daa, VALUE).review(w.artifacts, daa, VALUE);
    const topup = AUTHORIZER - 1n;
    assert.equal(bad.payer_cost, topup.toString());
    assert.equal(bad.payer_cost_kas, "0.49999999");
    assert.equal(
      bad.payer_cost_text,
      `${topup} sompi (0.49999999 KAS) into trade outputs: the fee inputs top up under-funded pass-through outputs to their minimum, on top of the fee`,
    );
    // The books still balance: the payer's input pays the fee and the top-up, and the change is the rest.
    assert.equal(sum(bad.inputs) - sum(bad.outputs), BigInt(bad.fee));
    assert.equal(BigInt(bad.outputs[3].amount), FEE_INPUT - BigInt(bad.fee) - topup);
  } finally {
    freeAll(w.wallets);
  }
});

test("the review marks the outputs that pay a key held only in a wallet of the page, and says what that means; with no held keys it marks none", () => {
  const w = world(sdk, MODES.directKas);
  try {
    const ipst = w.terms.directFromReply(w.artifacts, reply(w), payer(w), daa, VALUE);
    const seller = w.wallets.seller.publicKey();
    const buyer = w.wallets.buyer.publicKey();
    const none = ipst.review(w.artifacts, daa, VALUE);
    assert.deepEqual([none.held_outputs, none.held_amount, none.notes], [[], "0", []], "control");
    assert.ok(none.outputs.every((o) => o.held_key === false));
    // The token to the buyer and the cash to the seller pay the wallets' keys; the change pays the payer.
    const both = ipst.review(w.artifacts, daa, VALUE, [seller, buyer]);
    assert.deepEqual(both.outputs.map((o) => o.held_key), [true, true, false]);
    assert.deepEqual(both.held_outputs, [0, 1]);
    assert.equal(both.held_amount, (CARRIER + KAS_CASH).toString());
    assert.deepEqual(both.notes, [
      "Outputs 0, 1 (3.00000000 KAS in all, and any token they carry) pay a key that lives only in a wallet of this page. Nothing in this page can spend it, and it is lost when the page unloads. On mainnet signing refuses it.",
    ]);
    // Naming only the buyer's key marks only what pays the buyer; naming the payer marks the change.
    assert.deepEqual(ipst.review(w.artifacts, daa, VALUE, [buyer]).held_outputs, [0]);
    const withPayer = ipst.review(w.artifacts, daa, VALUE, [w.wallets.payer.publicKey()]);
    assert.deepEqual(withPayer.held_outputs, [2]);
    assert.match(withPayer.notes[0], /^Output 2 \(\d+\.\d{8} KAS, and any token it carries\) pays a key that lives/);
    // The list is a strict form.
    for (const bad of [["AB".repeat(32)], ["ab".repeat(31)], ["zz".repeat(32)], Array(9).fill(seller)]) {
      assert.equal(refusalError(() => ipst.review(w.artifacts, daa, VALUE, bad as string[])).code, "SDK_JSON_FORM");
    }
    assert.equal(ipst.review(w.artifacts, daa, VALUE, []).held_outputs.length, 0);
  } finally {
    freeAll(w.wallets);
  }
});

test("the review of a funding says how the deposit comes back, whose key signs the refund and from when, and what losing the key does; no other document has that note", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const funding = w.terms.fundKas(
      { network: w.network, creation_daa: daa },
      { inputs: [{ ...w.fee, script_public_key: { version: 0, script: `20${buyer}ac` } }], fee: "5000000", change: { version: 0, script: `20${buyer}ac` } },
      VALUE,
    );
    const refund = (r: ReviewJson) => r.exit_note as string;
    // The buyer's key held in a wallet of the page (testnet): the key, the expiry plus one, the
    // refund by the others, where it pays, and the loss of the key with the page.
    const held = funding.review(w.artifacts, daa, VALUE, [buyer]);
    const note = refund(held);
    assert.ok(note.startsWith(`Until this trade settles, the only way you can take this deposit back yourself is a refund of the cash leg signed with the buyer's key ${buyer}, from DAA score ${EXPIRY + 1n} `), note);
    assert.ok(note.includes(`(earmarked funding: the depositor's refund opens after the expiry, DAA score ${EXPIRY})`), note);
    assert.ok(note.includes("That key lives only in a wallet of this page: closing or reloading the page, or wiping the wallet, destroys it, and nothing in this page can bring it back."), note);
    assert.ok(note.includes("The seller or the authority can also trigger that refund at any time, and it pays the buyer's refund destination ("), note);
    assert.ok(note.endsWith(") whoever signs it, but nothing makes them."), note);
    assert.deepEqual(held.notes.filter((n) => n === note), [note], "also the first note of the review");
    assert.equal(held.notes[0], note);
    // How long the trade has left to settle, from the score the review is made at: the next note,
    // with the figures and no threshold; a settle is refused at or after the expiry.
    const window = held.notes[1];
    assert.equal(held.notes.filter((n) => n.startsWith("A settle of this trade can be built only before")).length, 1);
    assert.ok(
      window.startsWith(
        `A settle of this trade can be built only before the expiry, DAA score ${EXPIRY}: at or after it the settle is refused (TX_EXPIRED). The node is at DAA score ${daa}, so this funding, once accepted, has ${EXPIRY - NOW} DAA scores (about `,
      ),
      window,
    );
    assert.ok(window.endsWith(" at the nominal 10 DAA scores a second; the real rate varies) to be listed by the node and settled. A trade that is not settled by then can only be refunded."), window);
    const close = funding.review(w.artifacts, (EXPIRY - 1n).toString(), VALUE, [buyer]).notes[1];
    assert.ok(close.includes(`The node is at DAA score ${EXPIRY - 1n}, so this funding, once accepted, has 1 DAA score (about 0 minutes at the nominal`), close);
    // The key held elsewhere: the page does not claim to destroy it, and says to keep it.
    const elsewhere = refund(funding.review(w.artifacts, daa, VALUE));
    assert.ok(elsewhere.includes("Keep that key until the trade has settled."), elsewhere);
    assert.ok(!elsewhere.includes("lives only in a wallet of this page"), elsewhere);
    // A settle has no such note: nothing is deposited, and the note would be false.
    const settle = w.terms.settleFromReply(w.artifacts, reply(w), payer(w), daa, VALUE).review(w.artifacts, daa, VALUE, [buyer]);
    assert.equal(settle.exit_note, null);
    assert.ok(!settle.notes.some((n) => n.startsWith("Until this trade settles")));
    assert.ok(!settle.notes.some((n) => n.startsWith("A settle of this trade can be built only before")));
    // Revocable terms without an authority: at any time, and the seller alone.
    const open = validated(sdk, { ...w.json, funding_mode: "revocable", authority_key: null });
    const doc = open.fundKas(
      { network: w.network, creation_daa: daa },
      { inputs: [{ ...w.fee, script_public_key: { version: 0, script: `20${buyer}ac` } }], fee: "5000000", change: { version: 0, script: `20${buyer}ac` } },
      VALUE,
    );
    const revocable = refund(doc.review(w.artifacts, daa, VALUE, [buyer]));
    assert.ok(revocable.includes(`signed with the buyer's key ${buyer}, at any time (revocable funding). That key lives`), revocable);
    assert.ok(revocable.includes(" The seller can also trigger that refund at any time"), revocable);
    assert.ok(!revocable.includes("authority") && !revocable.includes("DAA score"), revocable);
  } finally {
    freeAll(w.wallets);
  }
});
