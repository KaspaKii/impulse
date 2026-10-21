// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The IPST golden vectors (tests/vectors/ipst) through the published package: each file reads,
// renders back to the same text, and is the transaction the builders make from its own inputs.
// All thirteen are also rebuilt from the vector's own inputs by the builders called from
// TypeScript (`fundKas`, `fundKcc20`, `settle`, `refund`, `direct`), and the rebuilt text must
// equal the file, byte for byte. The UTXOs, the artifacts and the fee payment of each vector are
// in its file; the token amounts and the signer of a refund are the ones the vector's name and
// description give (impulse-core tx/golden.rs).
import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  DirectLegsJson,
  FeePaymentJson,
  Ipst,
  Kcc20DepositJson,
  Kcc20StateJson,
  RefundEscrowJson,
  RefundSignerName,
  SettleLegsJson,
  TokenUtxoJson,
  UtxoJson,
} from "../index.js";
import { ASSET_ARTIFACT, AUTHORIZER, CARRIER, CASH_ARTIFACT, VALUE, ctx } from "./fixtures.ts";
import { hex, ipstVector, ipstVectors, load, unhex, vectorFiles } from "./sdk.ts";
import type { IpstDoc, IpstInputDoc, IpstVectorFile } from "./sdk.ts";

const sdk = load();

/** The DAA score the vectors were built at. */
const NOW = "1500000";
const artifacts = { asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT };

const files = vectorFiles("ipst");
const vectors = ipstVectors;

/** The builder each vector is named for. */
function builderOf(name: string): string {
  const kind = name.split("-")[1];
  return kind === "fund" ? `fund_${name.split("-")[2]}` : kind;
}

test("IPST vectors: the thirteen files of I5, each named after its file", () => {
  assert.equal(files.length, 13);
  assert.deepEqual(
    vectors.map((v) => `${v.name}.json`),
    files,
  );
  for (const v of vectors) assert.ok(v.description.length > 0, v.name);
  assert.equal(vectors.reduce((n, v) => n + v.doc.inputs.filter((i) => i.signer !== null).length, 0), 29);
});

test("IPST vectors: each reads, renders back to the same text, and recomputes its sighashes", () => {
  let sighashes = 0;
  for (const v of vectors) {
    const ipst = sdk.Ipst.fromJson(v.text);
    assert.equal(ipst.toJson(), v.text, `${v.name}: canonical rendering, byte for byte`);
    assert.equal(hex(ipst.terms().canonical()), v.doc.terms, `${v.name}: terms`);
    // Reading recomputed every sighash; sighash(i) is the same value.
    for (const slot of ipst.slots()) {
      assert.equal(slot.signer, v.doc.inputs[slot.input].signer);
      assert.equal(slot.signature, null, `${v.name}: the vectors are unsigned`);
      if (slot.signer === null) continue;
      assert.equal(hex(ipst.sighash(slot.input)), v.doc.inputs[slot.input].sighash, `${v.name}: input ${slot.input}`);
      sighashes += 1;
    }
    assert.equal(sdk.ipstVersion(), v.doc.ipst);
  }
  assert.equal(sighashes, 29);
});

test("IPST vectors: each is the transaction the builders make from its own inputs", () => {
  for (const v of vectors) {
    const ipst = sdk.Ipst.fromJson(v.text);
    const checked = ipst.verifyAgainstTerms(artifacts, NOW, VALUE);
    assert.equal(checked.kind.builder, builderOf(v.name), v.name);
    assert.equal(checked.fee, "5000000", `${v.name}: the fee`);
    assert.equal(ipst.fee(), "5000000");
    assert.ok(BigInt(ipst.masses().min_relay_fee) <= 5_000_000n, `${v.name}: the fee covers the relay minimum`);
  }
});

function utxoOf(input: IpstInputDoc): UtxoJson {
  return {
    transaction_id: input.transaction_id,
    index: input.index,
    amount: input.utxo.amount,
    script_public_key: input.utxo.script_public_key,
    block_daa_score: input.utxo.block_daa_score,
    is_coinbase: input.utxo.is_coinbase,
    covenant_id: input.utxo.covenant_id,
  };
}

function stateOf(input: IpstInputDoc, amount: string): Kcc20StateJson {
  assert.ok(input.signer, "a token input owned by a key");
  return { identifier_type: "pubkey", identifier: input.signer, amount, is_minter: false };
}

/** The fee payment of a vector: its last input pays, its last output is the change. */
function paymentOf(doc: IpstDoc): FeePaymentJson {
  const held = doc.inputs.reduce((n, i) => n + BigInt(i.utxo.amount), 0n);
  const paid = doc.outputs.reduce((n, o) => n + BigInt(o.value), 0n);
  return {
    inputs: [utxoOf(doc.inputs[doc.inputs.length - 1])],
    fee: (held - paid).toString(),
    change: doc.outputs[doc.outputs.length - 1].script_public_key,
  };
}

function vector(prefix: string): { v: IpstVectorFile; text: string; doc: IpstDoc; terms: ReturnType<typeof sdk.ValidatedTerms.decode> } {
  const v = ipstVector(prefix);
  return { v, text: v.text, doc: v.doc, terms: sdk.ValidatedTerms.decode(unhex(v.doc.terms)) };
}

test("IPST vectors: the builders called from TypeScript make vectors 02, 12 and 13 byte for byte", () => {
  // 02: fund_kas. The vector's payer input funds the deposit; its change is the last output.
  {
    const { text, doc, terms } = vector("02");
    const built = terms.fundKas(ctx(), paymentOf(doc), VALUE);
    assert.equal(built.toJson(), text, "02-fund-kas-cash");
  }
  // 12: Direct, seller token against buyer KAS.
  {
    const { text, doc, terms } = vector("12");
    const legs: DirectLegsJson = {
      asset_artifact: ASSET_ARTIFACT,
      asset: { utxo: utxoOf(doc.inputs[0]), state: stateOf(doc.inputs[0], terms.terms().toJson().asset_leg.amount) },
      cash: { kind: "kas", utxo: utxoOf(doc.inputs[1]) },
    };
    const built = terms.direct(legs, paymentOf(doc), NOW, VALUE);
    assert.equal(built.toJson(), text, "12-direct-kas");
  }
  // 13: Direct, seller token against buyer KCC-20 cash.
  {
    const { text, doc, terms } = vector("13");
    const t = terms.terms().toJson();
    const legs: DirectLegsJson = {
      asset_artifact: ASSET_ARTIFACT,
      asset: { utxo: utxoOf(doc.inputs[0]), state: stateOf(doc.inputs[0], t.asset_leg.amount) },
      cash: {
        kind: "kcc20",
        artifact: CASH_ARTIFACT,
        token: { utxo: utxoOf(doc.inputs[1]), state: stateOf(doc.inputs[1], t.cash_leg.amount) },
      },
    };
    const built = terms.direct(legs, paymentOf(doc), NOW, VALUE);
    assert.equal(built.toJson(), text, "13-direct-kcc20");
  }
});

/** A key-owned token input of a vector as a builder takes it. */
function tokenOf(doc: IpstDoc, input: number, amount: string): TokenUtxoJson {
  return { utxo: utxoOf(doc.inputs[input]), state: stateOf(doc.inputs[input], amount) };
}

/** The settle legs of a vector, from its inputs: the authorizers come first, then the escrows. */
function settleLegsOf(prefix: string, doc: IpstDoc): SettleLegsJson {
  const input = (n: number) => utxoOf(doc.inputs[n]);
  switch (prefix) {
    case "04": // KAS cash: asset authorizer, cash vault, asset escrow
      return { asset_artifact: ASSET_ARTIFACT, asset_authorizer: input(0), asset_escrow: input(2), cash: { kind: "kas", vault: input(1) } };
    case "05": // KCC-20 cash: both authorizers, then both escrows
    case "06":
      return {
        asset_artifact: ASSET_ARTIFACT,
        asset_authorizer: input(0),
        asset_escrow: input(2),
        cash: { kind: "kcc20", artifact: CASH_ARTIFACT, authorizer: input(1), escrow: input(3) },
      };
    case "07": // external cash: no cash inputs
      return { asset_artifact: ASSET_ARTIFACT, asset_authorizer: input(0), asset_escrow: input(1), cash: { kind: "external" } };
    default:
      throw new Error(`no settle vector ${prefix}`);
  }
}

test("IPST vectors: the builders called from TypeScript make vectors 01 and 03 byte for byte (fund_kcc20)", () => {
  // 01: the seller's two tokens, 600 and 700, hold 1300 for an asset leg of 1000: token change.
  {
    const { text, doc, terms } = vector("01");
    const deposit: Kcc20DepositJson = {
      artifact: ASSET_ARTIFACT,
      tokens: [tokenOf(doc, 0, "600"), tokenOf(doc, 1, "700")],
      carrier: CARRIER.toString(),
      authorizer: AUTHORIZER.toString(),
    };
    const built = terms.fundKcc20(0, ctx(), deposit, paymentOf(doc), VALUE);
    assert.equal(built.toJson(), text, "01-fund-kcc20-asset-with-token-change");
  }
  // 03: the buyer's one token holds exactly the cash leg: no token change.
  {
    const { text, doc, terms } = vector("03");
    const deposit: Kcc20DepositJson = {
      artifact: CASH_ARTIFACT,
      tokens: [tokenOf(doc, 0, terms.terms().toJson().cash_leg.amount)],
      carrier: CARRIER.toString(),
      authorizer: AUTHORIZER.toString(),
    };
    const built = terms.fundKcc20(1, ctx(), deposit, paymentOf(doc), VALUE);
    assert.equal(built.toJson(), text, "03-fund-kcc20-cash");
  }
});

test("IPST vectors: the builders called from TypeScript make vectors 04 to 07 byte for byte (settle)", () => {
  for (const prefix of ["04", "05", "06", "07"]) {
    const { v, text, doc, terms } = vector(prefix);
    const built = terms.settle(settleLegsOf(prefix, doc), paymentOf(doc), NOW, VALUE);
    assert.equal(built.toJson(), text, v.name);
  }
});

test("IPST vectors: the builders called from TypeScript make vectors 08 to 11 byte for byte (refund)", () => {
  const refunds: [string, 0 | 1, RefundSignerName, boolean][] = [
    ["08", 0, "depositor", true],
    ["09", 0, "counterparty", true],
    ["10", 1, "authority", false],
    ["11", 1, "depositor", false],
  ];
  for (const [prefix, leg, signer, withToken] of refunds) {
    const { v, text, doc, terms } = vector(prefix);
    // The vault UTXO is input 0; a refund with its token carries the escrow at input 1.
    const t = terms.terms().toJson();
    const escrow: RefundEscrowJson | null = withToken
      ? { artifact: ASSET_ARTIFACT, utxo: utxoOf(doc.inputs[1]), amount: t.asset_leg.amount, is_minter: false }
      : null;
    const built = terms.refund(leg, signer, utxoOf(doc.inputs[0]), escrow, paymentOf(doc), VALUE);
    assert.equal(built.toJson(), text, v.name);
  }
});

test("IPST vectors: a rebuilt document differs from the vector when one input does (control for the rebuilds)", () => {
  const { text, doc, terms } = vector("12");
  const legs = (amount: string): DirectLegsJson => ({
    asset_artifact: ASSET_ARTIFACT,
    asset: tokenOf(doc, 0, amount),
    cash: { kind: "kas", utxo: utxoOf(doc.inputs[1]) },
  });
  const amount = terms.terms().toJson().asset_leg.amount;
  assert.equal(terms.direct(legs(amount), paymentOf(doc), NOW, VALUE).toJson(), text);
  // The same token UTXO stated with another amount is not the UTXO the entry names.
  assert.throws(() => terms.direct(legs("1001"), paymentOf(doc), NOW, VALUE), { code: "TX_TOKEN_INPUT" });

  // Settle (vector 04): a field of one input's entry that no signature covers reaches the text.
  const s = vector("04");
  const rebuilt = (edit: (u: UtxoJson) => void): string => {
    const l = settleLegsOf("04", s.doc);
    if (l.cash.kind !== "kas") throw new Error("KAS cash");
    edit(l.cash.vault);
    return s.terms.settle(l, paymentOf(s.doc), NOW, VALUE).toJson();
  };
  assert.equal(rebuilt(() => {}), s.text, "control: unedited");
  assert.notEqual(rebuilt((u) => (u.block_daa_score = "101")), s.text, "block_daa_score");
  assert.notEqual(rebuilt((u) => (u.is_coinbase = true)), s.text, "is_coinbase");
  assert.notEqual(rebuilt((u) => (u.index = 1)), s.text, "index");
});

test("UTXO fields reach the document: a non-zero index, a coinbase flag, a DAA score, a covenant", () => {
  const { doc, terms } = vector("02");
  const fee = paymentOf(doc);
  const read = (ipst: Ipst) => (JSON.parse(ipst.toJson()) as { inputs: IpstInputDoc[] }).inputs[0];
  const plain = read(terms.fundKas(ctx(), fee, VALUE));
  assert.equal(plain.index, 0);
  assert.equal(plain.utxo.is_coinbase, false);
  const odd: FeePaymentJson = {
    ...fee,
    inputs: [{ ...fee.inputs[0], index: 3, is_coinbase: true, block_daa_score: "424242" }],
  };
  const got = read(terms.fundKas(ctx(), odd, VALUE));
  assert.equal(got.index, 3, "the outpoint index");
  assert.equal(got.utxo.is_coinbase, true, "the coinbase flag");
  assert.equal(got.utxo.block_daa_score, "424242", "the DAA score");
  // The document reads back the same, and a changed field is a changed outpoint.
  assert.equal(sdk.Ipst.fromJson(terms.fundKas(ctx(), odd, VALUE).toJson()).toJson(), terms.fundKas(ctx(), odd, VALUE).toJson());
  assert.notEqual(got.sighash, plain.sighash, "the index is in the sighash");
});
