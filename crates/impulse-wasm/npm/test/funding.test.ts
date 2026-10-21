// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Funding instructions (I11): for every golden vector the SDK's vault addresses equal the
// committed files, and the funding URI is the address, the amount and the terms hash joined as
// spec/CLI.md writes them. The expectation is built here from the vector files alone, not from
// the SDK. The golden vectors name a synthetic token that is no kcc20.sil build, which no funding
// instruction accepts (SDK_TEMPLATE_UNPINNED, pinned.test.ts), so the instructions are those of
// each vector with its tokens pinned (`pinTerms`: the first pinned build, a different trade with
// a hash of its own); the committed vault files are matched by the vault instantiation of the
// vectors as committed. Refusals of fundingInstructions, qrCode and kasFromSompi, each beside an
// accepted control, are in refusals.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, ECDH } from "node:crypto";
import { readFileSync } from "node:fs";
import { hex, load, partyFor, pinTerms, refusal, root, termsVectors, unhex, vaultVectors } from "./sdk.ts";
import { LIFT } from "./fixtures.ts";
import type { DestinationJson, FundingInstructions, FundingOptionsJson, TermsJson } from "../index.js";

const sdk = load();

// The vectors' own creation DAA score (spec/ENCODING.md). The party is the buyer, with a pin for
// each of its destinations that does not pay its key: the funding URI of the cash leg is the
// buyer's, and every vector's buyer passes the role check that way.
const options = (terms: TermsJson): FundingOptionsJson => ({
  context: { network: terms.network, creation_daa: "400000000" },
  creation_daa_source: "node",
  party: partyFor("buyer", terms),
  kas_equivalent: "100000000",
  // Most vectors hold amounts above the default cap; the lift is the SDK's own option.
  accept_the_risk: true,
});

/** The instructions for the buyer of a vector with its tokens pinned (see the header). */
const instructionsFor = (name: string): FundingInstructions => {
  const t = termsVectors.find((v) => v.name === name);
  assert.ok(t, name);
  const terms = pinTerms(t.terms);
  return sdk.Terms.fromJson(terms).validateStructure().fundingInstructions(options(terms));
};

const hashOf = (terms: TermsJson) => hex(sdk.Terms.fromJson(terms).termsHash());

test("the vault instantiation of all 11 vectors as committed gives the golden vault files' template hash, addresses and script hashes", () => {
  let addresses = 0;
  let noVault = 0;
  for (const t of termsVectors) {
    const v = vaultVectors.find((x) => x.name === t.name);
    assert.ok(v, t.name);
    const terms = sdk.Terms.fromJson(t.terms).validateStructure();
    assert.equal(hashOf(t.terms), t.terms_hash, `${t.name}: terms hash`);
    assert.equal(hex(sdk.templateCheck().hash()), v.template_hash, `${t.name}: template hash`);
    const ctx = { network: t.terms.network, creation_daa: "400000000" } as const;
    for (const [leg, vault] of [[0, v.asset_vault], [1, v.cash_vault]] as const) {
      if (vault.refused !== undefined) {
        noVault += 1;
        assert.equal(refusal(() => terms.instantiateForCreation(leg, ctx, LIFT)), vault.refused, `${t.name} leg ${leg}`);
        continue;
      }
      addresses += 1;
      const fundable = terms.instantiateForCreation(leg, ctx, LIFT);
      assert.equal(fundable.address(), vault.address, `${t.name} leg ${leg}`);
      assert.equal(hex(fundable.vault().scriptHash()), vault.script_hash, `${t.name} leg ${leg}`);
    }
  }
  assert.equal(noVault, 6, "legs without a vault (I4)");
  assert.ok(addresses >= 5, `${addresses} vault addresses`);
});

test("funding instructions: hashes, addresses and URIs of all 11 vectors with their tokens pinned equal the terms' own vaults, and the URI is joined as spec/CLI.md writes it", () => {
  let uris = 0;
  let noVault = 0;
  for (const t of termsVectors) {
    const pinned = pinTerms(t.terms);
    const v = vaultVectors.find((x) => x.name === t.name);
    assert.ok(v, t.name);
    const got = instructionsFor(t.name);
    const terms = sdk.Terms.fromJson(pinned).validateStructure();
    const ctx = { network: pinned.network, creation_daa: "400000000" } as const;
    assert.equal(got.network, t.terms.network, t.name);
    assert.equal(got.terms_hash, hashOf(pinned), `${t.name}: terms hash`);
    assert.equal(got.template_hash, v.template_hash, `${t.name}: template hash`);
    assert.equal(got.value.lifted, true, t.name);
    const legs = [
      { got: got.legs[0], vault: v.asset_vault, terms: t.terms.asset_leg, name: "asset", depositor: "seller" },
      { got: got.legs[1], vault: v.cash_vault, terms: t.terms.cash_leg, name: "cash", depositor: "buyer" },
    ];
    for (const [i, leg] of legs.entries()) {
      const where = `${t.name} ${leg.name}`;
      assert.equal(leg.got.name, leg.name, where);
      assert.equal(leg.got.depositor, leg.depositor, where);
      assert.equal(leg.got.you_fund, leg.depositor === "buyer", `${where}: the party is the buyer`);
      assert.equal(leg.got.kind, leg.terms.kind, where);
      assert.equal(leg.got.amount, leg.terms.amount, where);
      // A leg has a vault exactly when the committed vector's has one (the pinned token changes
      // the address, not whether the terms escrow the leg).
      if (leg.vault.refused !== undefined) {
        noVault += 1;
        assert.equal(leg.got.vault, null, where);
        assert.equal(leg.got.funding_uri, null, where);
        assert.equal(typeof leg.got.no_vault_reason, "string", where);
        continue;
      }
      assert.equal(leg.got.no_vault_reason, null, where);
      const fundable = terms.instantiateForCreation(i as 0 | 1, ctx, LIFT);
      assert.deepEqual(leg.got.vault, { address: fundable.address(), script_hash: hex(fundable.vault().scriptHash()) }, where);
      if (leg.terms.kind === "kas") {
        uris += 1;
        // spec/CLI.md, "Funding URI": nothing else, no other order, no percent-encoding.
        assert.equal(
          leg.got.funding_uri,
          `${fundable.address()}?amount=${leg.terms.amount}&impulse=${hashOf(pinned)}`,
          `${where}: funding URI`,
        );
        assert.equal(leg.got.amount_kas, sdk.kasFromSompi(leg.terms.amount), where);
      } else {
        assert.equal(leg.got.funding_uri, null, `${where}: only a native KAS leg has a URI`);
        assert.equal(leg.got.amount_kas, null, where);
      }
    }
  }
  assert.equal(noVault, 6, "legs without a vault (I4)");
  assert.ok(uris >= 3, `native KAS legs with a vault: ${uris}`);
});

test("the value check reports what it measured, and the lift reports that it was lifted", () => {
  const t = termsVectors.find((v) => v.name.startsWith("08-"));
  assert.ok(t);
  const validated = sdk.Terms.fromJson(pinTerms(t.terms)).validateStructure();
  const ctx = { network: t.terms.network, creation_daa: "400000000" } as const;
  const party = partyFor("buyer", t.terms);
  const got = validated.fundingInstructions({ context: ctx, creation_daa_source: "typed", party, kas_equivalent: "100000000" });
  assert.equal(got.creation_daa_source, "typed");
  assert.equal(got.creation_daa, "400000000");
  assert.deepEqual(got.value, {
    lifted: false,
    value: String(Math.max(Number(t.terms.cash_leg.amount), 100000000)),
    value_kas: sdk.kasFromSompi(String(Math.max(Number(t.terms.cash_leg.amount), 100000000))),
    cap: "1000000000",
    cap_kas: "10.00000000",
    declared: "100000000",
    largest_kas_leg: t.terms.cash_leg.amount,
  });
  assert.equal(sdk.defaultValueCapSompi(), "1000000000");
  const lifted = validated.fundingInstructions({
    context: ctx,
    creation_daa_source: "typed",
    party,
    accept_the_risk: true,
  });
  assert.deepEqual(lifted.value, {
    lifted: true,
    value: null,
    value_kas: null,
    cap: null,
    cap_kas: null,
    declared: null,
    largest_kas_leg: null,
  });
});

test("kasFromSompi writes eight decimals", () => {
  assert.equal(sdk.kasFromSompi("0"), "0.00000000");
  assert.equal(sdk.kasFromSompi("1"), "0.00000001");
  assert.equal(sdk.kasFromSompi("1000000000"), "10.00000000");
  assert.equal(sdk.kasFromSompi("18446744073709551615"), "184467440737.09551615");
});

test("qrCode: a square of dark and light modules with the three finder patterns", () => {
  const uri = instructionsFor(termsVectors.find((v) => v.name.startsWith("08-"))?.name ?? "").legs[1].funding_uri;
  assert.ok(uri);
  const qr = sdk.qrCode(uri);
  assert.ok(Number.isInteger((qr.width - 17) / 4) && qr.width >= 21 && qr.width <= 177, `width ${qr.width}`);
  assert.equal(qr.modules.length, qr.width * qr.width);
  assert.ok(qr.modules.every((m) => m === 0 || m === 1));
  const at = (x: number, y: number) => qr.modules[y * qr.width + x];
  for (const [x, y] of [
    [0, 0],
    [qr.width - 7, 0],
    [0, qr.width - 7],
  ]) {
    assert.equal(at(x, y), 1);
    assert.equal(at(x + 3, y + 3), 1);
    assert.equal(at(x + 1, y + 1), 0);
  }
  assert.deepEqual(sdk.qrCode(uri).modules, qr.modules, "deterministic");
  assert.notDeepEqual(sdk.qrCode(uri.replace("amount=", "amount=1")).modules, qr.modules, "bound to the text");
});

// Who a destination pays, decoded here from the vector file alone: an x-only P2PK script
// (OpData32 key OpCheckSig), a P2PK-ECDSA script of either parity of that x (OpData33 02|03 x
// OpCheckSigECDSA), or a KCC-20 pubkey owner pays a key; any other script or owner is a script.
function payeeKey(d: DestinationJson): string | "script" | "off_chain" {
  if (d.kind === "off_chain") return "off_chain";
  if (d.kind === "kcc20") return d.identifier_type === "pubkey" ? d.identifier : "script";
  const script = unhex(d.script);
  const body = Buffer.from(script).toString("hex");
  if (d.version === 0 && script.length === 34 && script[0] === 0x20 && script[33] === 0xac) return body.slice(2, 66);
  if (d.version === 0 && script.length === 35 && script[0] === 0x21 && (script[1] === 2 || script[1] === 3) && script[34] === 0xab) {
    return body.slice(4, 68);
  }
  return "script";
}
function validXOnlyKey(label: string): string {
  for (let i = 0; ; i += 1) {
    const x = createHash("sha256").update(`${label}/${i}`).digest("hex");
    try {
      ECDH.convertKey(`02${x}`, "secp256k1", "hex", "hex", "uncompressed");
      return x;
    } catch {
      // Not a point of the curve; the next label.
    }
  }
}
function expectedPays(t: TermsJson, d: DestinationJson): string {
  const who = payeeKey(d);
  if (who === "script" || who === "off_chain") return who;
  if (who === t.seller_key) return "seller_key";
  if (who === t.buyer_key) return "buyer_key";
  if (who === t.authority_key) return "authority_key";
  return "other_key";
}

test("destinations: four, in the order of the terms summary, each marked with whom it pays, for all 11 vectors", () => {
  const seen = new Set<string>();
  for (const t of termsVectors) {
    const got = instructionsFor(t.name).destinations;
    const names = ["buyer_delivery", "seller_proceeds", "seller_refund", "buyer_refund"] as const;
    assert.deepEqual(got.map((d) => d.name), names, t.name);
    for (const d of got) {
      const terms = t.terms[d.name];
      assert.equal(d.owner, d.name.startsWith("buyer") ? "buyer" : "seller", `${t.name} ${d.name}`);
      assert.equal(d.kind, terms.kind, `${t.name} ${d.name}`);
      assert.equal(d.pays, expectedPays(t.terms, terms), `${t.name} ${d.name}`);
      seen.add(d.pays);
      // The words say the same as the code, and nothing in the golden vectors pays a party that
      // does not own the destination.
      assert.ok(d.mark.length > 0, `${t.name} ${d.name}`);
      if (d.pays === "seller_key" || d.pays === "buyer_key" || d.pays === "authority_key") assert.ok(d.mark.includes(d.pays), d.mark);
      if (d.pays === "script") assert.match(d.mark, /^script to check/);
      assert.equal(d.pays_counterparty_or_authority, false, `${t.name} ${d.name}`);
      // The destination text names the owner or the address; a KAS destination is an address
      // of the terms' network when its script has one.
      if (terms.kind === "kcc20") assert.ok(d.destination.endsWith(terms.identifier), d.destination);
      if (terms.kind === "kas" && payeeKey(terms) !== "script") {
        assert.ok(d.destination.startsWith(t.terms.network === "mainnet" ? "kaspa:" : "kaspatest:"), d.destination);
      }
      if (terms.kind === "off_chain") assert.match(d.destination, /^off chain/);
    }
  }
  for (const pays of ["seller_key", "buyer_key", "script", "off_chain"]) assert.ok(seen.has(pays), `no vector pays ${pays}`);
});

test("a destination that pays the counterparty or the authority is flagged to the party it attacks, beside the same trade with its own destinations", () => {
  const base = termsVectors.find((v) => v.name.startsWith("08-"));
  assert.ok(base);
  const ctx = { network: "testnet", creation_daa: "400000000" } as const;
  // The attacked party is refused by the role check (role.test.ts), so the flag is what the other
  // party sees: each case runs as the party that is not attacked.
  const run = (edit: (t: TermsJson) => void, as: "buyer" | "seller") => {
    const terms = pinTerms(base.terms);
    edit(terms);
    return sdk.Terms.fromJson(terms).validateStructure().fundingInstructions({
      context: ctx,
      creation_daa_source: "typed",
      party: partyFor(as, terms),
      kas_equivalent: "100000000",
    }).destinations;
  };
  const p2pk = (key: string): DestinationJson => ({ kind: "kas", version: 0, script: `20${key}ac` });
  const owner = (key: string): DestinationJson => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });
  const flagged = (ds: ReturnType<typeof run>) => ds.filter((d) => d.pays_counterparty_or_authority).map((d) => `${d.name} ${d.pays}`);
  assert.deepEqual(flagged(run(() => {}, "seller")), [], "control: the vector's own destinations");
  assert.deepEqual(flagged(run((t) => (t.buyer_refund = p2pk(t.buyer_key)), "seller")), [], "control: a buyer refund to the buyer");
  assert.deepEqual(flagged(run((t) => (t.buyer_refund = p2pk(t.seller_key)), "seller")), ["buyer_refund seller_key"]);
  assert.deepEqual(flagged(run((t) => (t.buyer_delivery = owner(t.seller_key)), "seller")), ["buyer_delivery seller_key"]);
  assert.deepEqual(flagged(run((t) => (t.buyer_refund = p2pk(t.authority_key as string)), "seller")), ["buyer_refund authority_key"]);
  assert.deepEqual(flagged(run((t) => (t.seller_proceeds = p2pk(t.buyer_key)), "buyer")), ["seller_proceeds buyer_key"]);
  assert.deepEqual(flagged(run((t) => (t.seller_refund = owner(t.authority_key as string)), "buyer")), ["seller_refund authority_key"]);
  // A key that is neither party's nor the authority's is marked, not flagged: it may be a custodian.
  // A valid x-only key that is none of this trade's: a public label hashed until the digest is an
  // x coordinate on the curve. Nobody holds its secret, and none is made here.
  const stranger = validXOnlyKey("impulse/tests/stranger");
  assert.ok(![base.terms.seller_key, base.terms.buyer_key, base.terms.authority_key].includes(stranger));
  const other = run((t) => (t.buyer_refund = p2pk(stranger)), "seller");
  assert.equal(other[3].pays, "other_key");
  assert.equal(other[3].pays_counterparty_or_authority, false);
});

test("a KCC-20 leg carries TOKEN_UNASSESSED and a leg that is not KCC-20 carries nothing; the expiry has its time left", () => {
  for (const t of termsVectors) {
    const got = instructionsFor(t.name);
    for (const [i, terms] of [t.terms.asset_leg, t.terms.cash_leg].entries()) {
      const warnings = got.legs[i].token_warnings;
      if (terms.kind === "kcc20") {
        assert.equal(warnings.length, 1, `${t.name} leg ${i}`);
        assert.equal(warnings[0].code, "TOKEN_UNASSESSED");
        assert.ok(warnings[0].message.startsWith("TOKEN_UNASSESSED: "), warnings[0].message);
      } else {
        assert.deepEqual(warnings, [], `${t.name} leg ${i}`);
      }
    }
    assert.equal(got.expiry.expiry_daa, t.terms.expiry_daa, t.name);
    assert.match(got.expiry.time_left, /^about \d+ (days|hours|minutes)$/, t.name);
  }
  // 425,920,000 - 400,000,000 = 25,920,000 DAA scores at 10 per second: 2,592,000 s, 30 days.
  assert.equal(instructionsFor(termsVectors.find((v) => v.name.startsWith("08-"))?.name ?? "").expiry.time_left, "about 30 days");
});

test("fromFileText reads each committed vector file as it is, and the bare and three-key forms of it", () => {
  for (const t of termsVectors) {
    const text = readFileSync(new URL(`tests/vectors/terms/${t.name}.json`, root), "utf8");
    const hash = (terms: { termsHash(): Uint8Array }) => Buffer.from(terms.termsHash()).toString("hex");
    const fromFile = sdk.Terms.fromFileText(text);
    assert.equal(hash(fromFile), t.terms_hash, t.name);
    assert.deepEqual(fromFile.toJson(), t.terms, t.name);
    assert.equal(hash(sdk.Terms.fromFileText(JSON.stringify(t.terms))), t.terms_hash, `${t.name}: bare`);
    const file = JSON.stringify({ terms: t.terms, canonical: t.canonical, terms_hash: t.terms_hash });
    assert.equal(hash(sdk.Terms.fromFileText(file)), t.terms_hash, `${t.name}: terms file`);
    fromFile.requireSameAs(sdk.Terms.fromJson(t.terms));
  }
});
