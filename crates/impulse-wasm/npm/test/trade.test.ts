// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The phase 2 exit test: a Direct trade and a Vault trade run end to end through the package
// (build, sign with runtime throwaway keys, merge, assemble), and every transaction they make is
// the one impulse-core's builders make natively for the same inputs, byte for byte.
//
// The signing is the test's: the SDK never sees a secret key. A Signer draws a random key when
// the test starts and zero-fills its secret buffer when the test ends (the BigInt copies inside
// @noble/curves cannot be erased; see fixtures.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import type { Ipst, SettleLegsJson, SignatureJson, ValidatedTerms } from "../index.js";
import { rec } from "./calls.ts";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  FEE,
  KAS_CASH,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  newParties,
  outputsAsUtxos,
  ownToken,
  p2pk,
  ring,
  signedBy,
  spentScripts,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import { checkAgainstNative, recorded } from "./oracle.ts";
import { hex, load } from "./sdk.ts";

const sdk = load();
const daa = NOW.toString();

/**
 * Every signer returns the IPST with its own signatures; the copies are merged with `combine`,
 * which verifies each signature it copies. Returns the merged IPST, complete.
 */
function mergeSigned(text: string, signers: Parameters<typeof signedBy>[2][]): Ipst {
  const copies = signers.map((s) => signedBy(sdk, text, s));
  let merged = sdk.Ipst.fromJson(copies[0]);
  for (const copy of copies.slice(1)) merged = rec.combine(merged, copy);
  return merged;
}

/** The signatures a merged IPST holds, as `assemble` takes them. */
function signaturesOf(ipst: Ipst): SignatureJson[] {
  return ipst
    .slots()
    .filter((s) => s.signature !== null)
    .map((s) => ({ input: s.input, signature: s.signature as string }));
}

/**
 * Finalizes a merged IPST, and assembles the same signatures into the unsigned document: both
 * must give the same transaction.
 */
function finish(unsigned: Ipst, merged: Ipst) {
  assert.deepEqual(merged.pending(), []);
  assert.equal(merged.isComplete(), true);
  const signed = merged.finalize();
  const assembled = rec.assemble(unsigned, signaturesOf(merged));
  assert.equal(hex(assembled.txid()), hex(signed.txid()));
  assert.equal(hex(assembled.raw()), hex(signed.raw()));
  assert.equal(signed.txid().length, 32);
  return signed;
}

test("a Direct trade runs end to end and is the builders' transaction", () => {
  const p = newParties();
  try {
    const terms = validated(sdk, termsJson(sdk, p, MODES.directKas));
    const artifacts = { asset: ASSET_ARTIFACT, cash: null };
    // The seller's token and the buyer's KAS each hold exactly their leg amount.
    const legs = {
      asset_artifact: ASSET_ARTIFACT,
      asset: ownToken(sdk, "seller-asset", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
      cash: { kind: "kas" as const, utxo: utxo("buyer-kas", KAS_CASH, p2pk(p.buyer.publicHex)) },
    };
    const direct = rec.direct(terms, legs, feePayment(p.payer), daa, VALUE);

    // Whoever holds the document checks it before signing: it is what the builders make.
    const checked = rec.verifyAgainstTerms(direct, artifacts, daa);
    assert.deepEqual(checked.kind, { builder: "direct" });
    assert.equal(checked.fee, FEE.toString());
    assert.equal(direct.fee(), FEE.toString());
    assert.deepEqual(
      direct.slots().map((s) => s.signer),
      [p.seller.publicHex, p.buyer.publicHex, p.payer.publicHex],
    );
    assert.deepEqual(direct.pending(), [0, 1, 2]);
    assert.ok(BigInt(direct.masses().min_relay_fee) <= FEE, "the fee covers the relay minimum");

    // Each party signs its own input and returns the document; the copies are merged.
    const merged = mergeSigned(direct.toJson(), [p.seller, p.buyer, p.payer]);
    const signed = finish(direct, merged);

    // The merged document reads back, its signatures verified, and is the same document.
    assert.equal(sdk.Ipst.fromJson(merged.toJson()).toJson(), merged.toJson());
    assert.ok(signed.raw().length > 0);
  } finally {
    erase(p);
  }
});

test("a Vault trade runs end to end and is the builders' transactions", () => {
  const p = newParties();
  try {
    const signers = ring(p);
    const terms: ValidatedTerms = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
    const artifacts = { asset: ASSET_ARTIFACT, cash: null };

    // Before funding, both sides recompute the addresses from the terms.
    const asset = terms.instantiateForCreation(0, ctx(), VALUE);
    const cash = terms.instantiateForCreation(1, ctx(), VALUE);
    const verified = rec.verifyAddresses(terms, ctx(), { asset: asset.address(), cash: cash.address() });
    assert.deepEqual(
      verified.map((v) => [v.leg, v.address]),
      [
        [0, asset.address()],
        [1, cash.address()],
      ],
    );

    // 1. The seller escrows the asset: two tokens holding 1300 for a leg of 1000, so the
    //    builder returns 300 as token change. The payer pays the fee.
    const deposit = {
      artifact: ASSET_ARTIFACT,
      tokens: [
        ownToken(sdk, "seller-token-1", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 600n),
        ownToken(sdk, "seller-token-2", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 700n),
      ],
      carrier: CARRIER.toString(),
      authorizer: AUTHORIZER.toString(),
    };
    const fundAsset = rec.fundKcc20(terms, 0, ctx(), deposit, feePayment(p.payer, "fee-1"), VALUE);
    assert.equal(rec.verifyAgainstTerms(fundAsset, artifacts, daa).kind.builder, "fund_kcc20");
    const assetTx = finish(fundAsset, mergeSigned(fundAsset.toJson(), [p.seller, p.payer]));
    const assetOut = outputsAsUtxos(hex(assetTx.txid()), fundAsset.toJson());
    // Escrowed token, authorizer, token change, KAS change.
    assert.equal(assetOut.length, 4);
    assert.equal(assetOut[0].covenant_id, ASSET_COV);
    assert.equal(assetOut[1].script_public_key.script, hex(terms.instantiateExisting(0).scriptPublicKey().script));

    // 2. The buyer deposits exactly the cash amount at the cash vault.
    const fundCash = rec.fundKas(terms, ctx(), feePayment(p.buyer, "buyer-kas-fee"), VALUE);
    assert.equal(rec.verifyAgainstTerms(fundCash, artifacts, daa).kind.builder, "fund_kas");
    const cashTx = finish(fundCash, mergeSigned(fundCash.toJson(), [p.buyer]));
    const cashOut = outputsAsUtxos(hex(cashTx.txid()), fundCash.toJson());
    assert.equal(cashOut[0].amount, KAS_CASH.toString());

    // 3. The authority settles, spending the funded outputs; the payer pays the fee.
    const legs: SettleLegsJson = {
      asset_artifact: ASSET_ARTIFACT,
      asset_authorizer: assetOut[1],
      asset_escrow: assetOut[0],
      cash: { kind: "kas", vault: cashOut[0] },
    };
    const settle = rec.settle(terms, legs, feePayment(p.payer, "fee-3"), daa, VALUE);
    const checked = rec.verifyAgainstTerms(settle, artifacts, daa);
    assert.deepEqual(checked.kind, { builder: "settle" });
    assert.equal(checked.fee, FEE.toString());
    // The authority signs the two vault inputs, the payer the fee input.
    assert.deepEqual(
      settle.slots().map((s) => s.signer),
      [p.authority.publicHex, p.authority.publicHex, null, p.payer.publicHex],
    );
    const settled = finish(settle, mergeSigned(settle.toJson(), [p.authority, p.payer]));

    // 4. Anyone can decode the settle, bound to the scripts its inputs spend.
    const decoded = rec.decodeRaw(sdk, settled.raw(), spentScripts(settle.toJson()), "mainnet");
    assert.equal(decoded.bound, true);
    assert.deepEqual(decoded.refused, []);
    assert.equal(decoded.txid, hex(settled.txid()));
    assert.deepEqual(
      decoded.legs.map((l) => [l.input_index, l.leg, l.entry.kind, l.outcome.kind]),
      [
        [0, 0, "settle", "delivered"],
        [1, 1, "settle", "delivered"],
      ],
    );
    assert.deepEqual(
      decoded.legs.map((l) => l.terms_hash),
      [hex(terms.termsHash()), hex(terms.termsHash())],
    );
    const [assetLeg, cashLeg] = decoded.legs;
    assert.deepEqual(assetLeg.outcome, {
      kind: "delivered",
      amount: "1000",
      to: { kind: "kcc20", identifier_type: "pubkey", identifier: p.buyer.publicHex },
    });
    assert.deepEqual(cashLeg.outcome, {
      kind: "delivered",
      amount: KAS_CASH.toString(),
      to: { kind: "kas", ...p2pk(p.seller.publicHex) },
    });
    // The signed transactions chain: the settle spends the outputs of the two deposits.
    const spent = JSON.parse(settle.toJson()).inputs.map((i: { transaction_id: string }) => i.transaction_id);
    assert.deepEqual(spent.slice(0, 3), [hex(assetTx.txid()), hex(cashTx.txid()), hex(assetTx.txid())]);
  } finally {
    erase(p);
  }
});

test("a signature made for another input or another key is refused where it is added", () => {
  const p = newParties();
  try {
    const terms = validated(sdk, termsJson(sdk, p, MODES.directKas));
    const legs = {
      asset_artifact: ASSET_ARTIFACT,
      asset: ownToken(sdk, "seller-asset", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
      cash: { kind: "kas" as const, utxo: utxo("buyer-kas", KAS_CASH, p2pk(p.buyer.publicHex)) },
    };
    const direct = terms.direct(legs, feePayment(p.payer), daa, VALUE);
    const [seller, buyer] = [direct.slots()[0], direct.slots()[1]];
    // Control: the seller's signature on the seller's input.
    const good = p.seller.sign(direct.sighash(0));
    assert.equal(seller.signer, p.seller.publicHex);
    direct.addSignature(0, good);
    assert.equal(direct.slots()[0].signature, hex(good));
    // The buyer's input takes the buyer's signature and nobody else's.
    assert.equal(buyer.signer, p.buyer.publicHex);
    assert.throws(() => direct.addSignature(1, p.seller.sign(direct.sighash(1))), { code: "TX_SIGNATURE" });
    assert.throws(() => direct.addSignature(1, p.buyer.sign(direct.sighash(0))), { code: "TX_SIGNATURE" });
    direct.addSignature(1, p.buyer.sign(direct.sighash(1)));
    assert.deepEqual(direct.pending(), [2]);
    // verify_schnorr_sig65 is the check addSignature makes.
    sdk.verifySchnorrSig65(p.buyer.publicKey, direct.sighash(1), p.buyer.sign(direct.sighash(1)));
    assert.throws(() => sdk.verifySchnorrSig65(p.seller.publicKey, direct.sighash(1), p.buyer.sign(direct.sighash(1))), {
      code: "TX_SIGNATURE",
    });
  } finally {
    erase(p);
  }
});

test("every call above answers as impulse-core's native builders do, byte for byte", () => {
  const calls = recorded();
  assert.ok(calls >= 16, `the trades made ${calls} recorded calls`);
  const checked = checkAgainstNative();
  assert.equal(checked, calls);
});

