// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The template v2 surface (I16, spec/V2.md 6.5) through the published package: the terms v2,
// vault v2 and IPST v2 golden vectors byte for byte, a v2 funding signed with a throwaway key
// and finalized, each version refusing the other's documents, the v2 value cap and constants.
// Each refusal beside an accepted control. The throwaway key is generated at runtime and erased.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import type { FeePaymentJson, UtxoJson } from "../index.js";
import { ASSET_ARTIFACT, Signer } from "./fixtures.ts";
import { hex, load, refusal, root, unhex } from "./sdk.ts";

const sdk = load();
const payer = new Signer();
after(() => payer.erase());

const NOW = "1500000";
const VALUE = { kas_equivalent: "1" };

function docs(set: string): [string, any][] {
  const dir = new URL(`tests/vectors/${set}/`, root);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(new URL(f, dir), "utf8"))]);
}

test("terms v2 vectors: JSON form, canonical bytes, terms hash and every leg's vault address", () => {
  const terms = docs("terms_v2");
  const vaults = new Map(docs("vaults_v2").map(([f, d]) => [f, d]));
  assert.equal(terms.length, 8);
  for (const [file, doc] of terms) {
    const t = sdk.TermsV2.fromJson(doc.terms);
    assert.equal(hex(t.encode()), doc.canonical, file);
    assert.equal(hex(t.termsHash()), doc.terms_hash, file);
    assert.deepEqual(t.toJson(), doc.terms, file);
    const v = t.validateStructure();
    assert.equal(hex(sdk.ValidatedTermsV2.decode(unhex(doc.canonical)).termsHash()), doc.terms_hash);
    const context = { network: doc.terms.network, creation_daa: NOW };
    const addresses = v.vaultAddresses(context, VALUE);
    assert.deepEqual(
      addresses,
      vaults.get(file).vaults.map((x: { address: string }) => x.address),
      file,
    );
  }
});

test("the v2 value cap holds before an address is handed out", () => {
  const [, doc] = docs("terms_v2")[0];
  const v = sdk.TermsV2.fromJson(doc.terms).validateStructure();
  const context = { network: doc.terms.network, creation_daa: NOW };
  assert.equal(refusal(() => v.vaultAddresses(context, {})), "SDK_VALUE_UNKNOWN");
  assert.equal(refusal(() => v.vaultAddresses(context, { kas_equivalent: "1000000001" })), "SDK_VALUE_CAP_EXCEEDED");
  assert.equal(v.vaultAddresses(context, { kas_equivalent: "1000000000" }).length, 3);
  // The creation checks run too: a creation DAA score at the expiry.
  assert.equal(refusal(() => v.vaultAddresses({ ...context, creation_daa: doc.terms.expiry_daa }, VALUE)), "TERMS_EXPIRY_NOT_AFTER_CREATION");
});

test("IPST v2 vectors read, render back and pass the terms check; each version refuses the other's", () => {
  const all = docs("ipst_v2");
  assert.equal(all.length, 15);
  for (const [file, doc] of all) {
    const text = JSON.stringify(doc.ipst);
    const ipst = sdk.IpstV2.fromJson(text);
    assert.deepEqual(JSON.parse(ipst.toJson()), doc.ipst, file);
    const checked = ipst.verifyAgainstTerms([ASSET_ARTIFACT], NOW, VALUE);
    assert.ok(file.includes(checked.kind.builder.split("_")[0]), `${file}: ${checked.kind.builder}`);
    assert.equal(refusal(() => sdk.Ipst.fromJson(text)), "IPST_UNSUPPORTED_VERSION", file);
  }
  const [, v1] = docs("ipst")[0];
  assert.equal(refusal(() => sdk.IpstV2.fromJson(JSON.stringify(v1.ipst))), "IPST_UNSUPPORTED_VERSION");
});

test("a v2 KAS funding is built, signed with a throwaway key, refused with a bad signature and finalized", () => {
  const [, doc] = docs("terms_v2").find(([f]) => f.startsWith("02-"))!;
  const v = sdk.TermsV2.fromJson(doc.terms).validateStructure();
  const p2pk = { version: 0, script: `20${payer.publicHex}ac` };
  const utxo: UtxoJson = {
    transaction_id: "ab".repeat(32),
    index: 0,
    amount: "100000000000",
    script_public_key: p2pk,
    block_daa_score: "100",
    is_coinbase: false,
    covenant_id: null,
  };
  const funding: FeePaymentJson = { inputs: [utxo], fee: "1000000", change: p2pk };
  const context = { network: "testnet" as const, creation_daa: NOW };
  // Leg 2 is the KAS leg; leg 0 is a KCC-20 leg, which fund_kas refuses.
  assert.equal(refusal(() => v.fundKas(0, context, funding, VALUE)), "TX_WRONG_MODE");
  assert.equal(refusal(() => v.fundKas(3, context, funding, VALUE)), "TEMPLATE_V2_LEG_INDEX");
  const ipst = v.fundKas(2, context, funding, VALUE);
  assert.deepEqual(ipst.pending(), [0]);
  const sighash = ipst.sighash(0);
  const bad = payer.sign(sighash);
  bad[0] ^= 1;
  assert.equal(refusal(() => ipst.addSignature(0, bad)), "TX_SIGNATURE");
  assert.equal(refusal(() => ipst.finalize()), "TX_SIGNATURE_SLOT");
  ipst.addSignature(0, payer.sign(sighash));
  assert.ok(ipst.isComplete());
  const signed = ipst.finalize();
  assert.equal(signed.txid().length, 32);
  // The document read back passes the terms check as a funding of leg 2.
  const back = sdk.IpstV2.fromJson(ipst.toJson());
  // The terms check takes the template of every KCC-20 leg, as v1's takes the asset template.
  assert.equal(refusal(() => back.verifyAgainstTerms([], NOW, VALUE)), "TX_TOKEN_TEMPLATE");
  assert.deepEqual(back.verifyAgainstTerms([ASSET_ARTIFACT], NOW, VALUE).kind, { builder: "fund_kas", leg: 2 });
  assert.equal(back.abovePreToccataCap(), false);
});

test("v2 constants and code lists are impulse-core's", () => {
  assert.equal(sdk.termsV2Version(), 2);
  assert.equal(sdk.maxLegs(), 10);
  const pinned = readFileSync(new URL("contracts/TEMPLATE_HASH_V2", root), "utf8").trim();
  assert.equal(hex(sdk.templateHashV2()), pinned);
  assert.deepEqual(sdk.capsV2("mainnet"), { compute: "450000", storage: "450000", transient: "900000" });
  const codes = sdk.v2ErrorCodes();
  assert.equal(codes.length, 27);
  assert.ok(codes.includes("TX_V2_MASS") && codes.includes("VERIFY_V2_WRONG_LEG"));
  const errors = readFileSync(new URL("spec/ERRORS.md", root), "utf8");
  for (const c of codes) {
    assert.ok(errors.includes(`\`${c}\``), c);
  }
  const [, doc] = docs("terms_v2")[0];
  const v = sdk.TermsV2.fromJson(doc.terms).validateStructure();
  assert.equal(refusal(() => v.minV2(3)), "SDK_JSON_FORM");
  assert.ok(BigInt(v.minV2(2)) > BigInt(v.minV2(1)));
});

/** A vector input as the builders take a UTXO. */
function inputUtxo(i: any): UtxoJson {
  return {
    transaction_id: i.transaction_id,
    index: i.index,
    amount: i.utxo.amount,
    script_public_key: i.utxo.script_public_key,
    block_daa_score: i.utxo.block_daa_score,
    is_coinbase: i.utxo.is_coinbase,
    covenant_id: i.utxo.covenant_id,
  };
}

test("a v2 tranche is built from TypeScript as vector 14; its quantity and its faults are impulse-core's", () => {
  const doc = docs("ipst_v2").find(([f]) => f.startsWith("14-"))![1].ipst;
  const terms = sdk.ValidatedTermsV2.decode(unhex(doc.terms));
  const legs = [
    { kind: "kcc20" as const, artifact: ASSET_ARTIFACT, authorizer: inputUtxo(doc.inputs[0]), escrow: inputUtxo(doc.inputs[2]), amount: "1000" },
    { kind: "kas" as const, vault: inputUtxo(doc.inputs[1]) },
  ];
  const held = doc.inputs.reduce((n: bigint, i: any) => n + BigInt(i.utxo.amount), 0n);
  const paid = doc.outputs.reduce((n: bigint, o: any) => n + BigInt(o.value), 0n);
  const funding: FeePaymentJson = {
    inputs: [inputUtxo(doc.inputs[3])],
    fee: (held - paid).toString(),
    change: doc.outputs[doc.outputs.length - 1].script_public_key,
  };
  const built = terms.settleTranche("1", legs, funding, NOW, VALUE);
  assert.deepEqual(JSON.parse(built.toJson()), doc);
  assert.deepEqual(sdk.IpstV2.fromJson(built.toJson()).verifyAgainstTerms([ASSET_ARTIFACT], NOW, VALUE).kind, { builder: "tranche", lots: "1" });
  // Faults carry the core's codes: no lots, more lots than the escrows hold, and the final layout.
  assert.equal(refusal(() => terms.settleTranche("0", legs, funding, NOW, VALUE)), "TX_TRANCHE");
  assert.equal(refusal(() => terms.settleTranche("5", legs, funding, NOW, VALUE)), "TX_TRANCHE");
  assert.equal(JSON.parse(terms.settleTranche("4", legs, funding, NOW, VALUE).toJson()).outputs.length, 4);
  // The quantity a receipt states: this transaction, the lineage so far, the terms total.
  const q = terms.quantities("1", "0");
  assert.deepEqual(q.legs[0], { leg: 0, moved: "250", cumulative: "250", total: "1000" });
  assert.deepEqual([q.lots, q.cumulative_lots, q.total_lots], ["1", "1", "4"]);
  assert.equal(terms.quantities("3", "1").legs[1].cumulative, "100000000");
  assert.equal(refusal(() => terms.quantities("1", "4")), "TX_TRANCHE");
  // A vault output of a partial trade carries a covenant ID: two storage units.
  assert.equal(terms.minVaultV2(), terms.minV2(2));
});
