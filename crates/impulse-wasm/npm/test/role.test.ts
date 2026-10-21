// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The role check (I11 phase 2, spec/CLI.md "Terms summary and role check") through the package:
// which party the user is, before any funding instruction. Expectations are built here from the
// vector files alone: whom a destination pays is read from its script, and a pin is the address
// this file encodes itself (sdk.ts, kaspaAddress), so the SDK's own address code builds nothing
// it is then compared with. Each refusal sits beside an accepted control; the refusal codes also
// have their cases in refusals.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { kaspaAddress, load, partyFor, pinOf, pinTerms, refusalError, termsVectors, unhex, vaultVectors } from "./sdk.ts";
import type { DestinationJson, FundingOptionsJson, PartyJson, TermsJson } from "../index.js";

const sdk = load();

const validated = (t: TermsJson) => sdk.Terms.fromJson(t).validateStructure();
const owner = (key: string): DestinationJson => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });
const p2pk = (key: string): DestinationJson => ({ kind: "kas", version: 0, script: `20${key}ac` });
const vector = (prefix: string) => {
  const v = termsVectors.find((x) => x.name.startsWith(`${prefix}-`));
  assert.ok(v, prefix);
  return v;
};

test("the address encoder of these tests reproduces the committed vault addresses", () => {
  let checked = 0;
  for (const v of vaultVectors) {
    const network = termsVectors.find((t) => t.name === v.name)?.terms.network;
    assert.ok(network);
    for (const leg of [v.asset_vault, v.cash_vault]) {
      if (leg.address === undefined) continue;
      checked += 1;
      assert.equal(kaspaAddress(network === "mainnet" ? "kaspa" : "kaspatest", 8, unhex(leg.script_hash as string)), leg.address, v.name);
    }
  }
  assert.ok(checked >= 5, `${checked} addresses`);
});

/** Whether a destination pays `key` as the role check reads it, decoded here from the file. */
function paysKey(d: DestinationJson, key: string): boolean | "off_chain" {
  if (d.kind === "off_chain") return "off_chain";
  if (d.kind === "kcc20") return d.identifier_type === "pubkey" && d.identifier === key;
  return d.version === 0 && [`20${key}ac`, `2102${key}ab`, `2103${key}ab`].includes(d.script);
}

test("every vector for both roles: accepted exactly when each own destination pays the role's key or is off chain, and always with the right pins", () => {
  let accepted = 0;
  let refused = 0;
  for (const t of termsVectors) {
    const terms = validated(t.terms);
    for (const role of ["buyer", "seller"] as const) {
      const key = role === "buyer" ? t.terms.buyer_key : t.terms.seller_key;
      const own = role === "buyer" ? [t.terms.buyer_delivery, t.terms.buyer_refund] : [t.terms.seller_proceeds, t.terms.seller_refund];
      const expectedOk = own.every((d) => paysKey(d, key) !== false);
      const bare: PartyJson = { role, key };
      const where = `${t.name} ${role}`;
      if (expectedOk) {
        accepted += 1;
        const got = terms.roleCheck(bare);
        assert.equal(got.role, role, where);
        assert.equal(got.key, key, where);
        assert.equal(got.funds_leg, role === "buyer" ? "cash" : "asset", where);
        assert.equal(got.lines.length, 2, where);
      } else {
        refused += 1;
        assert.equal(refusalError(() => terms.roleCheck(bare)).code, "SDK_DESTINATION_NOT_MINE", where);
      }
      // Beside the refusal: the same party with the pins the destinations call for is accepted.
      const pinned = terms.roleCheck(partyFor(role, t.terms));
      assert.equal(pinned.lines.length, 2, where);
    }
  }
  assert.ok(accepted >= 8 && refused >= 2, `${accepted} accepted, ${refused} refused`);
});

test("the key must be the role's party key: the other party's, the authority's and a stranger's are refused beside the right one", () => {
  const t = vector("08").terms;
  const terms = validated(t);
  assert.equal(terms.roleCheck(partyFor("buyer", t)).role, "buyer");
  for (const key of [t.seller_key, t.authority_key as string, "ab".repeat(32)]) {
    const e = refusalError(() => terms.roleCheck({ ...partyFor("buyer", t), key }));
    assert.equal(e.code, "SDK_ROLE_KEY_MISMATCH");
    assert.ok(e.message.includes(t.buyer_key), "the message names the key the terms hold");
  }
  // A role claimed with the other role's key.
  assert.equal(refusalError(() => terms.roleCheck({ ...partyFor("seller", t), key: t.buyer_key })).code, "SDK_ROLE_KEY_MISMATCH");
});

test("a destination of the role that pays the counterparty or the authority is refused, pinned or not, beside the honest terms", () => {
  const cases: [string, "buyer" | "seller", (t: TermsJson) => void][] = [
    ["buyer_refund -> seller", "buyer", (t) => (t.buyer_refund = p2pk(t.seller_key))],
    ["buyer_delivery -> seller", "buyer", (t) => (t.buyer_delivery = owner(t.seller_key))],
    ["buyer_refund -> authority", "buyer", (t) => (t.buyer_refund = p2pk(t.authority_key as string))],
    ["buyer_delivery -> authority", "buyer", (t) => (t.buyer_delivery = owner(t.authority_key as string))],
  ];
  const base = vector("08").terms;
  for (const [what, role, edit] of cases) {
    const honest = structuredClone(base);
    const control = partyFor(role, honest);
    assert.equal(validated(honest).roleCheck(control).role, role, `${what}: control`);
    const evil = structuredClone(base);
    edit(evil);
    // Unpinned, and pinned to exactly the evil destination (the pins partyFor writes).
    for (const party of [{ role, key: control.key } as PartyJson, partyFor(role, evil)]) {
      const e = refusalError(() => validated(evil).roleCheck(party));
      assert.equal(e.code, "SDK_DESTINATION_NOT_MINE", what);
      assert.match(e.message, /(buyer_refund|buyer_delivery) pays .*: the (counterparty|authority)'s key/, what);
    }
  }
  // The seller's destinations, on vector 01, where they pay the seller.
  const seller = vector("01").terms;
  const sellerCases: [string, (t: TermsJson) => void][] = [
    ["seller_proceeds -> buyer", (t) => (t.seller_proceeds = owner(t.buyer_key))],
    ["seller_refund -> buyer", (t) => (t.seller_refund = owner(t.buyer_key))],
    ["seller_proceeds -> authority", (t) => (t.seller_proceeds = owner(t.authority_key as string))],
    ["seller_refund -> authority", (t) => (t.seller_refund = owner(t.authority_key as string))],
  ];
  assert.equal(validated(seller).roleCheck(partyFor("seller", seller)).role, "seller", "control");
  for (const [what, edit] of sellerCases) {
    const evil = structuredClone(seller);
    edit(evil);
    for (const party of [{ role: "seller", key: seller.seller_key } as PartyJson, partyFor("seller", evil)]) {
      assert.equal(refusalError(() => validated(evil).roleCheck(party)).code, "SDK_DESTINATION_NOT_MINE", what);
    }
  }
});

test("a custodian's destination is accepted only as pinned, exactly", () => {
  const t = structuredClone(vector("08").terms);
  // The buyer is delivered to a script hash owner and refunded to a P2SH it says it controls.
  t.buyer_delivery = { kind: "kcc20", identifier_type: "script_hash", identifier: "05".repeat(32) };
  t.buyer_refund = { kind: "kas", version: 0, script: `aa20${"06".repeat(32)}87` };
  const terms = validated(t);
  const bare: PartyJson = { role: "buyer", key: t.buyer_key };
  assert.equal(refusalError(() => terms.roleCheck(bare)).code, "SDK_DESTINATION_NOT_MINE");
  const pins = { receive: pinOf("testnet", t.buyer_delivery), refund: pinOf("testnet", t.buyer_refund) };
  assert.equal(terms.roleCheck({ ...bare, pins }).lines.length, 2, "both pinned");
  // One pinned is not enough, and the message names the other.
  const half = refusalError(() => terms.roleCheck({ ...bare, pins: { receive: pins.receive } }));
  assert.equal(half.code, "SDK_DESTINATION_NOT_MINE");
  assert.ok(half.message.includes("buyer_refund") && !half.message.includes("buyer_delivery"), half.message);
  // A pin of another script than the terms name.
  const other = { receive: pins.receive, refund: kaspaAddress("kaspatest", 8, new Uint8Array(32).fill(7)) };
  assert.equal(refusalError(() => terms.roleCheck({ ...bare, pins: other })).code, "SDK_DESTINATION_NOT_MINE");
  // A pin that does not parse is its own refusal.
  for (const bad of ["not an address", "kcc20:pubkey:xyz", "", pins.refund + " "]) {
    assert.equal(
      refusalError(() => terms.roleCheck({ ...bare, pins: { receive: pins.receive, refund: bad } })).code,
      "SDK_DESTINATION_PIN_INVALID",
      JSON.stringify(bad),
    );
  }
});

test("the funding instructions run the role check first and give a URI only for the leg the role funds", () => {
  const t = vector("08").terms;
  const ctx = { network: "testnet", creation_daa: "400000000" } as const;
  const options = (party: PartyJson): FundingOptionsJson => ({ context: ctx, creation_daa_source: "typed", party, kas_equivalent: "100000000" });
  // The vector's synthetic token is no kcc20.sil build, which no funding instruction accepts: the
  // same terms with the token pinned (pinned.test.ts holds the refusal beside this control).
  const terms = validated(pinTerms(t));
  const buyer = terms.fundingInstructions(options(partyFor("buyer", t)));
  const seller = terms.fundingInstructions(options(partyFor("seller", t)));
  assert.equal(buyer.role.role, "buyer");
  assert.equal(seller.role.role, "seller");
  // The buyer funds the cash leg: a URI. The seller funds the asset leg, a KCC-20 token: none.
  assert.deepEqual(buyer.legs.map((l) => l.you_fund), [false, true]);
  assert.deepEqual(seller.legs.map((l) => l.you_fund), [true, false]);
  assert.match(buyer.legs[1].funding_uri as string, /^kaspatest:[a-z0-9]+\?amount=100000000&impulse=[0-9a-f]{64}$/);
  assert.equal(seller.legs[1].funding_uri, null, "the seller is shown no URI for the buyer's leg");
  assert.equal(buyer.legs[0].funding_uri, null);
  // The counterparty's vault is still shown, with its address, for the party to see and not fund.
  assert.equal(seller.legs[1].vault?.address, buyer.legs[1].vault?.address);
  assert.equal(buyer.legs[0].vault?.address, seller.legs[0].vault?.address);

  // Beside the control: the same call with the wrong key returns nothing.
  const wrong = refusalError(() => terms.fundingInstructions(options({ ...partyFor("buyer", t), key: t.seller_key })));
  assert.equal(wrong.code, "SDK_ROLE_KEY_MISMATCH");
  // The order: the creation checks first, then the role check, then the value cap.
  const wrongKey = { ...partyFor("buyer", t), key: "ab".repeat(32) };
  assert.equal(
    refusalError(() => terms.fundingInstructions({ ...options(wrongKey), context: { network: "mainnet", creation_daa: "400000000" } })).code,
    "TERMS_NETWORK_MISMATCH",
  );
  assert.equal(refusalError(() => terms.fundingInstructions(options(wrongKey))).code, "SDK_ROLE_KEY_MISMATCH");
  const over = { ...options(partyFor("buyer", t)), kas_equivalent: "1000000001" };
  assert.equal(refusalError(() => terms.fundingInstructions(over)).code, "SDK_VALUE_CAP_EXCEEDED");
  assert.equal(refusalError(() => terms.fundingInstructions({ ...over, party: wrongKey })).code, "SDK_ROLE_KEY_MISMATCH");
  // The lift of the value cap lifts nothing of the role check.
  const { kas_equivalent: _declared, ...undeclared } = options(wrongKey);
  const lifted: FundingOptionsJson = { ...undeclared, accept_the_risk: true };
  assert.equal(refusalError(() => terms.fundingInstructions(lifted)).code, "SDK_ROLE_KEY_MISMATCH");
  assert.equal(terms.fundingInstructions({ ...lifted, party: partyFor("buyer", t) }).value.lifted, true);
});

test("a key that lives only in a wallet of the page: passed with a warning on testnet, refused on mainnet, pinned or not; a custodian's script is not a wallet", () => {
  const base = vector("08").terms;
  const buyer = base.buyer_key;
  const own: TermsJson = { ...base, buyer_delivery: owner(buyer), buyer_refund: p2pk(buyer) };
  const bare: PartyJson = { role: "buyer", key: buyer };
  const testnet = validated(own);
  // Control: with no held key the check says nothing about wallets.
  const plain = testnet.roleCheck(bare);
  assert.deepEqual(plain.in_wallet, []);
  assert.deepEqual(plain.lines, ["buyer_delivery pays your key", "buyer_refund pays your key"]);
  assert.deepEqual(testnet.roleCheck({ ...bare, held: [] }).in_wallet, []);
  assert.deepEqual(testnet.roleCheck({ ...bare, held: null }).in_wallet, []);
  assert.deepEqual(testnet.roleCheck({ ...bare, held: ["ab".repeat(32)] }).in_wallet, [], "another key held says nothing about this one");
  // Testnet: allowed, and the result says what it means.
  const held = testnet.roleCheck({ ...bare, held: [buyer] });
  assert.deepEqual(held.in_wallet, ["buyer_delivery", "buyer_refund"]);
  assert.equal(held.lines.length, 2);
  for (const [line, name] of [
    [held.lines[0], "buyer_delivery"],
    [held.lines[1], "buyer_refund"],
  ]) {
    assert.ok(line.startsWith(`${name} pays your key: a key that lives only in a wallet of this page`), line);
    assert.ok(line.endsWith("cannot be spent from this page and is lost when it unloads"), line);
  }
  // Only the destination that pays the held key is named.
  const half = validated({ ...own, buyer_refund: { kind: "kas", version: 0, script: `aa20${"cc".repeat(32)}87` } });
  const halfPins = { ...bare, pins: { refund: pinOf("testnet", { kind: "kas", version: 0, script: `aa20${"cc".repeat(32)}87` }) } };
  assert.deepEqual(half.roleCheck({ ...halfPins, held: [buyer] }).in_wallet, ["buyer_delivery"]);

  // Mainnet: refused, with both destinations named, whatever the pins.
  const mainnetTerms = validated({ ...own, network: "mainnet" });
  assert.deepEqual(mainnetTerms.roleCheck(bare).in_wallet, [], "control: mainnet with no held key");
  const refused = refusalError(() => mainnetTerms.roleCheck({ ...bare, held: [buyer] }));
  assert.equal(refused.code, "SDK_DESTINATION_IN_WALLET");
  assert.match(refused.message, /buyer_delivery pays .*a key that lives only in a wallet of this page/);
  assert.match(refused.message, /buyer_refund pays .*a key that lives only in a wallet of this page/);
  assert.match(refused.message, /Pin an address you control elsewhere$/);
  const pinned: PartyJson = {
    role: "buyer",
    key: buyer,
    held: [buyer],
    pins: { receive: pinOf("mainnet", owner(buyer)), refund: pinOf("mainnet", p2pk(buyer)) },
  };
  assert.equal(refusalError(() => mainnetTerms.roleCheck(pinned)).code, "SDK_DESTINATION_IN_WALLET", "a pin that equals the destination pays the same key");
  // The honest custodian: destinations that are scripts the user pins. A script is not a held key.
  const custodian = { kind: "kas", version: 0, script: `aa20${"cc".repeat(32)}87` } as const;
  const scripted = validated({ ...own, network: "mainnet", buyer_delivery: { kind: "kcc20", identifier_type: "script_hash", identifier: "05".repeat(32) }, buyer_refund: custodian });
  const custodianParty: PartyJson = {
    role: "buyer",
    key: buyer,
    held: [buyer],
    pins: { receive: `kcc20:script_hash:${"05".repeat(32)}`, refund: pinOf("mainnet", custodian) },
  };
  const ok = scripted.roleCheck(custodianParty);
  assert.deepEqual(ok.in_wallet, []);
  assert.equal(ok.lines.length, 2);
  // The funding instructions run it too, before anything is returned.
  const options = (party: PartyJson): FundingOptionsJson => ({
    context: { network: "mainnet", creation_daa: "400000000" },
    creation_daa_source: "node",
    party,
    kas_equivalent: "100000000",
  });
  const mainnetBase = pinTerms({ ...own, network: "mainnet" } as TermsJson);
  assert.equal(validated(mainnetBase).fundingInstructions(options(bare)).role.role, "buyer", "control: no held key");
  assert.equal(
    refusalError(() => validated(mainnetBase).fundingInstructions(options({ ...bare, held: [buyer] }))).code,
    "SDK_DESTINATION_IN_WALLET",
  );
  // The held list is a strict form.
  for (const bad of [["AB".repeat(32)], ["ab".repeat(31)], [5], "ab".repeat(32), Array(9).fill(buyer)]) {
    assert.equal(refusalError(() => testnet.roleCheck({ ...bare, held: bad as never })).code, "SDK_JSON_FORM", String(bad).slice(0, 20));
  }
});
