// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The plan builders (I11 phase 2): from the text of a node's `getUtxosByAddresses` reply to the
// IPST a builder makes. Every choice of a UTXO is checked against the builder called by hand with
// the UTXOs the test names, so the expectation is the builder's own transaction and not the plan's
// opinion of it. Each refusal sits beside an accepted control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { ArtifactsJson, FeePaymentJson, Ipst, PlanFundingJson, RefundEscrowJson, TermsJson, ValidatedTerms } from "../index.js";
import { utxosFrame } from "./fakenode.ts";
import type { FakeUtxo } from "./fakenode.ts";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AMOUNT_A,
  CASH_ARTIFACT,
  CARRIER,
  KAS_CASH,
  NOW,
  VALUE,
  kcc20State,
  ownToken,
  p2pk,
  tokenLeg,
  unpinnedToken,
  utxo,
  validated,
} from "./fixtures.ts";
import { hex, load, pinOf, refusalError } from "./sdk.ts";
import { MODES, addressFor, freeAll, legsOf, payment, world } from "./world.ts";
import type { World } from "./world.ts";

const sdk = load();
const daa = NOW.toString();

const reply = (w: World, pool: FakeUtxo[] = w.pool) => utxosFrame(1, pool, addressFor(w.network));
const funding = (w: World, fee: string = "auto"): PlanFundingJson => ({ payer: w.wallets.payer.publicKey(), fee });
const settle = (w: World, pool: FakeUtxo[] = w.pool, fee: string = "auto") =>
  w.terms.settleFromReply(w.artifacts, reply(w, pool), funding(w, fee), daa, VALUE);

/** A UTXO at the same scriptPublicKey as `like`, another amount and another outpoint. */
function sibling(like: FakeUtxo, label: string, amount: bigint, covenant: string | null = like.covenant_id): FakeUtxo {
  return { ...utxo(label, amount, like.script_public_key, covenant) } as FakeUtxo;
}

test("the addresses to ask about are the legs' vaults, their escrowed tokens and the payer", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const vault = (leg: 0 | 1) => w.terms.instantiateExisting(leg);
    const addressOfVault = (leg: 0 | 1) =>
      w.terms
        .instantiateForCreation(leg, { network: w.network, creation_daa: (NOW - 1n).toString() }, VALUE)
        .address();
    const escrowSpk = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
      identifier_type: "script_hash",
      identifier: hex(vault(0).scriptHash()),
      amount: AMOUNT_A.toString(),
      is_minter: false,
    });
    const asAddress = (spk: { version: number; script: string }) => pinOf(w.network, { kind: "kas", ...spk });
    assert.deepEqual(w.terms.settleAddresses(w.artifacts, w.wallets.payer.publicKey()), [
      addressOfVault(0),
      asAddress(escrowSpk),
      addressOfVault(1),
      w.wallets.payer.address(w.network),
    ]);
    // An external-cash trade has no cash vault to ask about.
    const ext = world(sdk, MODES.external);
    try {
      assert.equal(ext.terms.settleAddresses(ext.artifacts, ext.wallets.payer.publicKey()).length, 3);
    } finally {
      freeAll(ext.wallets);
    }
    // The payer is a key: 64 hex digits.
    assert.equal(refusalError(() => w.terms.settleAddresses(w.artifacts, "ab")).code, "SDK_JSON_FORM");
    assert.equal(
      refusalError(() => w.terms.settleAddresses({ asset: "{}", cash: null }, w.wallets.payer.publicKey())).code,
      "TX_TOKEN_TEMPLATE",
    );
  } finally {
    freeAll(w.wallets);
  }
});

test("a settle from a reply is the transaction the builder makes from the UTXOs named, for KAS cash and KCC-20 cash", () => {
  for (const mode of [MODES.vaultKas, MODES.selfSettling, MODES.vaultKcc20, MODES.external]) {
    const w = world(sdk, mode);
    try {
      const ipst = settle(w);
      const by = w.terms.settle(legsOf(w), payment(w, BigInt(ipst.fee())), daa, VALUE);
      assert.equal(ipst.toJson(), by.toJson(), `${mode.cash} cash`);
      assert.equal(ipst.fee(), by.fee());
    } finally {
      freeAll(w.wallets);
    }
  }
});

test("the plan chooses by its rules among UTXOs that look alike", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const [assetAuthorizer, assetEscrow, cashVault] = w.pool;
    // The authorizer: the largest plain UTXO at the vault, ties to the lowest outpoint.
    const bigger = sibling(assetAuthorizer, "authorizer-bigger", 90_000_000n);
    const smaller = sibling(assetAuthorizer, "authorizer-smaller", 10_000_000n);
    const chosen = (ipst: Ipst) => ipst.toJson();
    const withBigger = settle(w, [...w.pool, smaller, bigger]);
    const legs = legsOf(w);
    const by = (authorizer: FakeUtxo) =>
      w.terms.settle({ ...legs, asset_authorizer: authorizer }, payment(w, BigInt(withBigger.fee())), daa, VALUE);
    assert.equal(chosen(withBigger), chosen(by(bigger)), "the largest authorizer");
    assert.notEqual(chosen(withBigger), chosen(by(assetAuthorizer)));
    // Two equal ones: the lower outpoint, whatever the order of the reply.
    const twin = sibling(assetAuthorizer, "authorizer-twin", BigInt(assetAuthorizer.amount));
    const lower = [assetAuthorizer, twin].sort((a, b) => a.transaction_id.localeCompare(b.transaction_id))[0];
    const higher = lower === assetAuthorizer ? twin : assetAuthorizer;
    for (const order of [[assetAuthorizer, twin], [twin, assetAuthorizer]]) {
      const pool = [...order, assetEscrow, cashVault, w.fee];
      assert.equal(chosen(settle(w, pool)), chosen(by(lower)), "ties go to the lowest outpoint");
    }
    assert.notEqual(chosen(by(lower)), chosen(by(higher)));
    // The escrowed token: exact state and the leg's covenant. Decoys of another amount or another
    // covenant are not it.
    const wrongCovenant = sibling(assetEscrow, "escrow-wrong-covenant", BigInt(assetEscrow.amount), "11".repeat(32));
    assert.equal(chosen(settle(w, [...w.pool, wrongCovenant])), chosen(settle(w)), "a token of another covenant is ignored");
    const noEscrow = w.pool.filter((u) => u !== assetEscrow);
    assert.equal(refusalError(() => settle(w, [...noEscrow, wrongCovenant])).code, "SDK_UTXO_NOT_FOUND");
    // A KAS cash vault UTXO of exactly the leg amount; others at the vault are ignored.
    const moreCash = sibling(cashVault, "cash-bigger", KAS_CASH + 1n);
    const lessCash = sibling(cashVault, "cash-smaller", KAS_CASH - 1n);
    assert.equal(chosen(settle(w, [...w.pool, moreCash, lessCash])), chosen(settle(w)), "only the exact amount");
    const noCash = w.pool.filter((u) => u !== cashVault);
    assert.equal(refusalError(() => settle(w, [...noCash, moreCash, lessCash])).code, "SDK_UTXO_NOT_FOUND");
    // Missing pieces, each beside the control of the whole pool.
    for (const [what, gone] of [
      ["the asset authorizer", assetAuthorizer],
      ["the asset escrow", assetEscrow],
      ["the cash vault UTXO", cashVault],
    ] as const) {
      const e = refusalError(() => settle(w, w.pool.filter((u) => u !== gone)));
      assert.equal(e.code, "SDK_UTXO_NOT_FOUND", what);
    }
    // A UTXO with a covenant at the vault's script is not a plain authorizer.
    const covenantAtVault = sibling(assetAuthorizer, "authorizer-covenant", 99_000_000n, ASSET_COV);
    assert.equal(chosen(settle(w, [...w.pool, covenantAtVault])), chosen(settle(w)), "a covenant UTXO is not an authorizer");
  } finally {
    freeAll(w.wallets);
  }
});

test("fee inputs are the payer's own plain UTXOs, largest first, and never a UTXO a leg uses", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const payer = w.wallets.payer.publicKey();
    const small = utxo("payer-small", 60_000_000n, p2pk(payer)) as FakeUtxo;
    const mid = utxo("payer-mid", 300_000_000n, p2pk(payer)) as FakeUtxo;
    const stranger = utxo("stranger", 5_000_000_000n, p2pk("ab".repeat(32))) as FakeUtxo;
    const covenant = utxo("payer-covenant", 5_000_000_000n, p2pk(payer), ASSET_COV) as FakeUtxo;
    const inputs = (ipst: Ipst) => ipst.toJson();
    const fee = 5_000_000n;
    const only = (u: FakeUtxo[]) => w.terms.settleFromReply(w.artifacts, reply(w, [...w.pool.filter((p) => p !== w.fee), ...u]), funding(w, fee.toString()), daa, VALUE);
    const by = (u: FakeUtxo[]) => w.terms.settle(legsOf(w), payment(w, fee, u), daa, VALUE);
    // One UTXO that covers the fee and leaves change of at least the minimum: only it.
    assert.equal(inputs(only([w.fee, small, mid, stranger, covenant])), inputs(by([w.fee])), "the largest covers the fee");
    // Largest first: a payer with a mid and a small UTXO pays from the mid one.
    assert.equal(inputs(only([small, mid, stranger])), inputs(by([mid])));
    // Change below the minimum is not left: the next UTXO is added until the change is zero or enough.
    const tight = utxo("payer-tight", fee + 47_000_000n, p2pk(payer)) as FakeUtxo; // change 0.47 KAS, under 0.5
    const top = utxo("payer-top-up", 3_000_000n, p2pk(payer)) as FakeUtxo;
    assert.equal(inputs(only([tight, top])), inputs(by([tight, top])), "a change of 0.47 KAS is not left behind");
    assert.equal(refusalError(() => only([tight])).code, "TX_BELOW_MIN_KAS", "and with nothing to add the builder refuses it");
    // Nothing of the payer's: the builder says it has no funds.
    const e = refusalError(() => only([stranger, covenant]));
    assert.equal(e.code, "TX_KAS_INPUT");
    // Too little: insufficient funds.
    assert.equal(refusalError(() => only([utxo("payer-dust", 1_000_000n, p2pk(payer)) as FakeUtxo])).code, "TX_INSUFFICIENT_FUNDS");
  } finally {
    freeAll(w.wallets);
  }
});

test("the fee: a typed fee is the fee, 'auto' is the minimum relay fee and a tenth more", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const auto = settle(w);
    const minimum = BigInt(sdk.minRelayFee(auto.masses().fee_mass));
    const fee = BigInt(auto.fee());
    assert.ok(fee >= minimum, "at least the minimum relay fee");
    assert.ok(fee - minimum <= (minimum + 9n) / 10n, "and no more than a tenth over");
    // The same transaction at a typed fee.
    const typed = settle(w, w.pool, minimum.toString());
    assert.equal(typed.fee(), minimum.toString());
    assert.equal(
      refusalError(() => settle(w, w.pool, (minimum - 1n).toString())).code,
      "TX_FEE_TOO_LOW",
    );
    // The funding form is strict.
    for (const bad of [
      { payer: w.wallets.payer.publicKey(), fee: "12.5" },
      { payer: w.wallets.payer.publicKey(), fee: "AUTO" },
      { payer: w.wallets.payer.publicKey(), fee: 5 },
      { payer: "xy", fee: "auto" },
      { payer: w.wallets.payer.publicKey() },
      { payer: w.wallets.payer.publicKey(), fee: "auto", extra: 1 },
    ]) {
      assert.equal(
        refusalError(() => w.terms.settleFromReply(w.artifacts, reply(w), bad as unknown as PlanFundingJson, daa, VALUE)).code,
        "SDK_JSON_FORM",
        JSON.stringify(bad),
      );
    }
    // The cap counts the fee: a fee past the cap is refused with the rest.
    assert.equal(
      refusalError(() => settle(w, w.pool, "2000000000")).code,
      "SDK_VALUE_CAP_EXCEEDED",
    );
  } finally {
    freeAll(w.wallets);
  }
});

test("the reply is read as a reply: another method, an error and a stray list are refused beside the real one", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const good = reply(w);
    const call = (text: string) => w.terms.settleFromReply(w.artifacts, text, funding(w), daa, VALUE);
    assert.equal(call(good).pending().length > 0, true, "control");
    const frame = JSON.parse(good) as { id: number; method: string; params: unknown };
    for (const [what, text] of [
      ["another method", JSON.stringify({ ...frame, method: "getBlockDagInfo" })],
      ["an error", JSON.stringify({ id: 1, error: { code: 1, message: "no index" } })],
      ["not JSON", "{"],
      ["entries that are not a list", JSON.stringify({ ...frame, params: { entries: 5 } })],
      ["an entry with no outpoint", JSON.stringify({ ...frame, params: { entries: [{}] } })],
    ] as const) {
      assert.equal(refusalError(() => call(text)).code, "SDK_RPC_REPLY", what);
    }
    assert.equal(
      refusalError(() => w.terms.settleFromReply(w.artifacts, 5 as unknown as string, funding(w), daa, VALUE)).code,
      "SDK_ARGUMENT_TYPE",
    );
  } finally {
    freeAll(w.wallets);
  }
});

test("a Direct trade from a reply is the builder's transaction; the payer may be a party whose exact UTXO is not spent for the fee", () => {
  for (const mode of [MODES.directKas, MODES.directKcc20]) {
    const w = world(sdk, mode);
    try {
      const direct = (payer: string, pool: FakeUtxo[] = w.pool) =>
        w.terms.directFromReply(w.artifacts, reply(w, pool), { payer, fee: "auto" }, daa, VALUE);
      const ipst = direct(w.wallets.payer.publicKey());
      const [sellerToken, buyerCash] = w.pool;
      const cash =
        mode.cash === "kas"
          ? ({ kind: "kas", utxo: buyerCash } as const)
          : ({
              kind: "kcc20",
              artifact: CASH_ARTIFACT,
              token: { utxo: buyerCash, state: kcc20State(w.wallets.buyer.publicKey(), BigInt(250_000)) },
            } as const);
      const legs = {
        asset_artifact: ASSET_ARTIFACT,
        asset: { utxo: sellerToken, state: kcc20State(w.wallets.seller.publicKey(), AMOUNT_A) },
        cash,
      };
      const by = w.terms.direct(legs, payment(w, BigInt(ipst.fee())), daa, VALUE);
      assert.equal(ipst.toJson(), by.toJson(), mode.cash);
      // The buyer pays the fee from a UTXO of its own that is not the cash: the exact cash UTXO is
      // reserved, so the fee does not come out of it.
      if (mode.cash === "kas") {
        const buyerKey = w.wallets.buyer.publicKey();
        const fee = utxo("buyer-fee", 700_000_000n, p2pk(buyerKey)) as FakeUtxo;
        const own = direct(buyerKey, [...w.pool, fee]);
        const inputsOf = (d: Ipst) => JSON.parse(d.toJson()).inputs.map((i: { transaction_id: string }) => i.transaction_id);
        assert.ok(inputsOf(own).includes(fee.transaction_id), "the fee comes from the buyer's other UTXO");
        assert.equal(inputsOf(own).filter((id: string) => id === buyerCash.transaction_id).length, 1, "the cash UTXO is spent once");
        // With no other UTXO the buyer cannot pay the fee: the cash UTXO is not offered for it.
        const e = refusalError(() => direct(buyerKey));
        assert.equal(e.code, "TX_KAS_INPUT");
      }
      // Missing pieces.
      assert.equal(refusalError(() => direct(w.wallets.payer.publicKey(), w.pool.filter((u) => u !== sellerToken))).code, "SDK_UTXO_NOT_FOUND");
      assert.equal(refusalError(() => direct(w.wallets.payer.publicKey(), w.pool.filter((u) => u !== buyerCash))).code, "SDK_UTXO_NOT_FOUND");
      // The addresses to ask about: the seller's token, the buyer's cash, the payer.
      const asked = w.terms.directAddresses(w.artifacts, w.wallets.payer.publicKey());
      assert.equal(asked.length, 3);
      assert.ok(asked.includes(w.wallets.payer.address(w.network)));
    } finally {
      freeAll(w.wallets);
    }
  }
  const v = world(sdk, MODES.vaultKas);
  try {
    assert.equal(
      refusalError(() => v.terms.directFromReply(v.artifacts, reply(v), funding(v), daa, VALUE)).code,
      "SDK_UTXO_NOT_FOUND",
    );
  } finally {
    freeAll(v.wallets);
  }
});

test("a refund from a reply is the builder's, with the token home or left in the vault", () => {
  for (const mode of [MODES.vaultKas, MODES.selfSettling]) {
    const w = world(sdk, mode);
    try {
      const refund = (leg: 0 | 1, signer: "depositor" | "counterparty" | "authority", withToken: boolean, pool: FakeUtxo[] = w.pool) =>
        w.terms.refundFromReply(leg, signer, withToken, w.artifacts, reply(w, pool), funding(w), VALUE);
      const legs = legsOf(w);
      const escrow = (utxoJson: FakeUtxo, artifact: string, amount: bigint): RefundEscrowJson => ({
        artifact,
        utxo: utxoJson,
        amount: amount.toString(),
        is_minter: false,
      });
      // The asset leg, with its token.
      const ipst = refund(0, "depositor", true);
      const by = w.terms.refund(0, "depositor", legs.asset_authorizer, escrow(legs.asset_escrow, ASSET_ARTIFACT, AMOUNT_A), payment(w, BigInt(ipst.fee())), VALUE);
      assert.equal(ipst.toJson(), by.toJson());
      // Without the token only the authorizer goes home: a smaller transaction.
      const bare = refund(0, "depositor", false);
      const bareBy = w.terms.refund(0, "depositor", legs.asset_authorizer, null, payment(w, BigInt(bare.fee())), VALUE);
      assert.equal(bare.toJson(), bareBy.toJson());
      assert.ok(bare.toJson().length < ipst.toJson().length);
      // A counterparty may take the token home too; asking for the token that is not there is refused.
      assert.ok(refund(0, "counterparty", true).pending().length > 0, "control");
      assert.equal(
        refusalError(() => refund(0, "depositor", true, w.pool.filter((u) => u !== legs.asset_escrow))).code,
        "SDK_UTXO_NOT_FOUND",
      );
      assert.ok(refund(0, "depositor", false, w.pool.filter((u) => u !== legs.asset_escrow)).pending().length > 0, "without the token it is not needed");
      // No UTXO at the vault: nothing to refund.
      assert.equal(refusalError(() => refund(0, "depositor", false, w.pool.filter((u) => u !== legs.asset_authorizer))).code, "SDK_UTXO_NOT_FOUND");
      // The signer is one of three names.
      assert.equal(refusalError(() => refund(0, "owner" as "depositor", true)).code, "SDK_JSON_FORM");
      // The addresses: the vault, the escrow, the payer.
      assert.equal(w.terms.refundAddresses(0, w.artifacts, w.wallets.payer.publicKey()).length, 3);
      // The cash leg: a KAS cash vault has no token, whatever is asked.
      if (mode.cash === "kas") {
        const cashRefund = refund(1, "depositor", true);
        const cashBy = w.terms.refund(1, "depositor", legs.cash.kind === "kas" ? legs.cash.vault : legs.asset_authorizer, null, payment(w, BigInt(cashRefund.fee())), VALUE);
        assert.equal(cashRefund.toJson(), cashBy.toJson());
        assert.equal(w.terms.refundAddresses(1, w.artifacts, w.wallets.payer.publicKey()).length, 2);
      }
    } finally {
      freeAll(w.wallets);
    }
  }
});

// The buyer's funding of a KAS cash vault (integration follow-up of I11).

/** The UTXO of the world's pool that a label names. */
const labelled = (id: string) => (u: FakeUtxo) => u.transaction_id === createHash("sha256").update(id).digest("hex");

/** The seller's funding of the asset leg, as the node reports it: the authorizer and the escrowed token. */
const assetLegOf = (w: World): FakeUtxo[] => w.pool.filter((u) => labelled("asset-authorizer")(u) || labelled("asset-escrow")(u));

test("the addresses to ask about for the cash funding are the cash vault, the asset vault with its escrowed token, and the buyer; the builder is refused beforehand for what it cannot fund", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    // The same three vault addresses the settle asks about (the cash vault, the asset vault, the
    // token escrowed in it), the buyer's last.
    const vaultAddress = (leg: 0 | 1) =>
      w.terms.instantiateForCreation(leg, { network: w.network, creation_daa: (NOW - 1n).toString() }, VALUE).address();
    const escrowSpk = sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, {
      identifier_type: "script_hash",
      identifier: hex(w.terms.instantiateExisting(0).scriptHash()),
      amount: AMOUNT_A.toString(),
      is_minter: false,
    });
    assert.deepEqual(w.terms.fundCashAddresses(w.artifacts, buyer), [
      vaultAddress(1),
      vaultAddress(0),
      pinOf(w.network, { kind: "kas", ...escrowSpk }),
      w.wallets.buyer.address(w.network),
    ]);
    // Not the buyer's leg to fund: the seller's key, the authority's, a stranger's.
    for (const other of [w.wallets.seller, w.wallets.authority, w.wallets.payer]) {
      assert.equal(refusalError(() => w.terms.fundCashAddresses(w.artifacts, other.publicKey())).code, "SDK_FUND_NOT_YOUR_LEG");
    }
    assert.equal(refusalError(() => w.terms.fundCashAddresses(w.artifacts, "ab")).code, "SDK_JSON_FORM");
    // An artifact that is not the asset token's is refused when the escrow is asked about.
    assert.equal(refusalError(() => w.terms.fundCashAddresses({ asset: "{}", cash: null }, buyer)).code, "TX_TOKEN_TEMPLATE");
    // A leg with no vault, and a token leg. Whose leg it is comes first, as in `fund build`: a
    // stranger asking about any of them is told it is not his.
    for (const [mode, code] of [
      [MODES.directKas, "TEMPLATE_NO_VAULT"],
      [MODES.external, "TEMPLATE_NO_VAULT"],
      [MODES.vaultKcc20, "TX_WRONG_MODE"],
    ] as const) {
      const other = world(sdk, mode);
      try {
        assert.equal(refusalError(() => other.terms.fundCashAddresses(other.artifacts, other.wallets.buyer.publicKey())).code, code, mode.cash);
        assert.equal(
          refusalError(() => other.terms.fundCashAddresses(other.artifacts, other.wallets.payer.publicKey())).code,
          "SDK_FUND_NOT_YOUR_LEG",
          `${mode.cash}: a stranger`,
        );
      } finally {
        freeAll(other.wallets);
      }
    }
  } finally {
    freeAll(w.wallets);
  }
});

test("the buyer's cash funding is the builder's transaction: the exact deposit at the cash vault, the buyer's own UTXOs largest first, the change where it is told", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const big = utxo("buyer-big", 130_000_000n, p2pk(buyer)) as FakeUtxo;
    const mid = utxo("buyer-mid", 40_000_000n, p2pk(buyer)) as FakeUtxo;
    const dust = utxo("buyer-dust", 1_000_000n, p2pk(buyer)) as FakeUtxo;
    const stranger = utxo("stranger", 5_000_000_000n, p2pk("ab".repeat(32))) as FakeUtxo;
    const covenant = utxo("buyer-covenant", 5_000_000_000n, p2pk(buyer), ASSET_COV) as FakeUtxo;
    const asset = assetLegOf(w);
    const fund = (pool: FakeUtxo[], fee = "auto", change?: string) =>
      w.terms.fundCashFromReply(
        w.artifacts,
        reply(w, [...asset, ...pool]),
        { payer: buyer, fee, ...(change === undefined ? {} : { change }) },
        daa,
        VALUE,
      );
    const by = (inputs: FakeUtxo[], fee: string, changeKey = buyer) =>
      w.terms.fundKas({ network: w.network, creation_daa: daa }, { inputs, fee, change: p2pk(changeKey) }, VALUE);
    // 1.3 KAS alone leaves 0.3 KAS less the fee, under the minimum output: the next largest is
    // added, and the 0.01 KAS UTXO, the stranger's and the token-carrying one are not touched.
    const ipst = fund([dust, stranger, covenant, mid, big]);
    assert.equal(ipst.toJson(), by([big, mid], ipst.fee()).toJson());
    // Output 0 is the deposit, exactly the cash amount, at the cash vault's address.
    const vaultAddress = w.terms
      .instantiateForCreation(1, { network: w.network, creation_daa: daa }, VALUE)
      .address();
    const out = JSON.parse(ipst.toJson()).outputs as { value: string; script_public_key: { version: number; script: string } }[];
    assert.equal(out[0].value, KAS_CASH.toString());
    assert.equal(pinOf(w.network, { kind: "kas", ...out[0].script_public_key }), vaultAddress);
    assert.equal(out.length, 2, "the deposit and the change");
    // The change goes to the buyer's key, or to the address given.
    assert.deepEqual(out[1].script_public_key, p2pk(buyer));
    const elsewhere = sdk.Wallet.generate();
    try {
      const to = elsewhere.address(w.network);
      const moved = fund([mid, big], "auto", to);
      assert.equal(moved.toJson(), by([big, mid], moved.fee(), elsewhere.publicKey()).toJson());
      assert.notEqual(moved.toJson(), ipst.toJson());
    } finally {
      elsewhere.free();
    }
    // The buyer signs every input and the document is complete once it has.
    assert.deepEqual(ipst.slots().map((s) => s.signer), [buyer, buyer]);
    assert.equal(ipst.isComplete(), false);
    // The review names the deposit as the cash vault and the cost beyond the fee as the deposit.
    const review = ipst.review(w.artifacts, daa, VALUE);
    assert.deepEqual(review.kind, { builder: "fund_kas" });
    assert.equal(review.outputs[0].what, "the cash vault");
    assert.equal(review.payer_cost, KAS_CASH.toString());
    // A typed fee is the fee, and one UTXO that covers the deposit and it with the change kept is enough.
    const huge = utxo("buyer-huge", 300_000_000n, p2pk(buyer)) as FakeUtxo;
    const typed = fund([big, huge], "5000000");
    assert.equal(typed.fee(), "5000000");
    assert.equal(typed.toJson(), by([huge], "5000000").toJson());
    // The inputs stop at exactly enough: the deposit and the fee, with no change output and the
    // next UTXO untouched; and at a change of exactly the minimum output, one sompi less lifts it.
    const fee = 5_000_000n;
    const exact = fund([utxo("buyer-exact", KAS_CASH + fee, p2pk(buyer)) as FakeUtxo, dust], fee.toString());
    assert.equal(JSON.parse(exact.toJson()).inputs.length, 1);
    assert.equal(JSON.parse(exact.toJson()).outputs.length, 1, "no change output");
    const edge = fund([utxo("buyer-edge", KAS_CASH + fee + 50_000_000n, p2pk(buyer)) as FakeUtxo, dust], fee.toString());
    assert.equal(JSON.parse(edge.toJson()).inputs.length, 1);
    assert.equal(JSON.parse(edge.toJson()).outputs[1].value, "50000000", "a change of exactly the minimum output");
    const under = fund([utxo("buyer-under", KAS_CASH + fee + 49_999_999n, p2pk(buyer)) as FakeUtxo, dust], fee.toString());
    assert.equal(JSON.parse(under.toJson()).inputs.length, 2, "one sompi under the minimum change takes the next UTXO");
    // A UTXO the node lists twice is one UTXO: the second input is the next one, not a repeat.
    const twice = fund([big, big, mid]);
    assert.equal(twice.toJson(), by([big, mid], twice.fee()).toJson());
  } finally {
    freeAll(w.wallets);
  }
});

test("the cash funding is refused for what is not the buyer's KAS cash leg, or not funded, each beside the accepted control", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const coin = (label: string, amount: bigint, key = buyer) => utxo(label, amount, p2pk(key)) as FakeUtxo;
    const asset = assetLegOf(w);
    const fund = (pool: FakeUtxo[], over: Partial<PlanFundingJson> = {}, value = VALUE, now = daa) =>
      w.terms.fundCashFromReply(w.artifacts, reply(w, [...asset, ...pool]), { payer: buyer, fee: "auto", ...over }, now, value);
    const rich = [coin("buyer-rich", 300_000_000n)];
    assert.ok(fund(rich).pending().length > 0, "control");
    // Only the buyer funds the cash leg, whoever else holds the coins. The refusal names the
    // buyer's key first and the asker's second.
    const seller = w.wallets.seller.publicKey();
    const notYours = refusalError(() => fund([coin("seller-rich", 300_000_000n, seller)], { payer: seller }));
    assert.equal(notYours.code, "SDK_FUND_NOT_YOUR_LEG");
    assert.equal(notYours.message, `SDK_FUND_NOT_YOUR_LEG: the cash leg is funded by the buyer, whose key is ${buyer}, not by ${seller}`);
    // No UTXO of the buyer's, too little for the deposit, a fee that is not covered, a change that would
    // be left under the minimum with nothing to lift it.
    assert.equal(refusalError(() => fund([coin("stranger-rich", 300_000_000n, "ab".repeat(32))])).code, "TX_KAS_INPUT");
    assert.equal(refusalError(() => fund([])).code, "TX_KAS_INPUT");
    assert.equal(refusalError(() => fund([coin("buyer-exact", KAS_CASH)])).code, "TX_INSUFFICIENT_FUNDS");
    assert.equal(refusalError(() => fund([coin("buyer-short", KAS_CASH - 1n)])).code, "TX_INSUFFICIENT_FUNDS");
    assert.equal(refusalError(() => fund([coin("buyer-tight", KAS_CASH + 10_000_000n)], { fee: "5000000" })).code, "TX_BELOW_MIN_KAS");
    assert.ok(fund([coin("buyer-tight", KAS_CASH + 10_000_000n), coin("buyer-lift", 50_000_000n)], { fee: "5000000" }).pending().length > 0, "a second UTXO lifts the change");
    // A fee below the relay minimum is the builder's refusal, and a typed fee is not raised.
    assert.equal(refusalError(() => fund(rich, { fee: "1" })).code, "TX_FEE_TOO_LOW");
    // The creation checks run at the node's score: at the expiry, no.
    assert.equal(refusalError(() => fund(rich, {}, VALUE, "2000000")).code, "TERMS_EXPIRY_NOT_AFTER_CREATION");
    assert.ok(fund(rich, {}, VALUE, "1999999").pending().length > 0, "one DAA score earlier");
    // The value cap holds: above it, and with no declaration (the asset leg is a token).
    assert.equal(refusalError(() => fund(rich, {}, { kas_equivalent: "1000000001" })).code, "SDK_VALUE_CAP_EXCEEDED");
    assert.ok(fund(rich, {}, { kas_equivalent: "1000000000" }).pending().length > 0, "exactly at the cap");
    assert.equal(refusalError(() => fund(rich, {}, { kas_equivalent: "0" })).code, "SDK_VALUE_UNKNOWN");
    // The reply is read as a reply, and its text is bounded before it is copied into the module.
    const call = (text: string) => w.terms.fundCashFromReply(w.artifacts, text, { payer: buyer, fee: "auto" }, daa, VALUE);
    assert.equal(refusalError(() => call("{")).code, "SDK_RPC_REPLY");
    const text = reply(w, [...asset, ...rich]);
    assert.ok(call(text).pending().length > 0, "control: the reply as the node wrote it");
    const longest = 1 << 23;
    assert.ok(call(text.padEnd(longest, " ")).pending().length > 0, "control: a reply of exactly the bound is read");
    assert.equal(refusalError(() => call(text.padEnd(longest + 1, " "))).code, "SDK_JSON_FORM", "one character past the bound is refused before it is copied");
    assert.equal(
      refusalError(() => w.terms.fundCashFromReply(w.artifacts, text, { payer: buyer, fee: "auto", extra: 1 } as unknown as PlanFundingJson, daa, VALUE)).code,
      "SDK_JSON_FORM",
    );
    // Terms that do not have a KAS cash vault to fund.
    for (const [mode, code] of [
      [MODES.directKas, "TEMPLATE_NO_VAULT"],
      [MODES.external, "TEMPLATE_NO_VAULT"],
      [MODES.vaultKcc20, "TX_WRONG_MODE"],
    ] as const) {
      const other = world(sdk, mode);
      try {
        const key = other.wallets.buyer.publicKey();
        const pool = [...other.pool, utxo("buyer-rich", 300_000_000n, p2pk(key)) as FakeUtxo];
        assert.equal(
          refusalError(() => other.terms.fundCashFromReply(other.artifacts, reply(other, pool), { payer: key, fee: "auto" }, daa, VALUE)).code,
          code,
          mode.cash,
        );
      } finally {
        freeAll(other.wallets);
      }
    }
  } finally {
    freeAll(w.wallets);
  }
});

test("the cash funding waits for the seller's asset leg and is refused a second time, beside the accepted control", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const coin = utxo("buyer-coin", 300_000_000n, p2pk(buyer)) as FakeUtxo;
    const [authorizer, escrow] = [w.pool.find(labelled("asset-authorizer")), w.pool.find(labelled("asset-escrow"))] as FakeUtxo[];
    const cashVault = w.pool.find(labelled("cash-vault")) as FakeUtxo;
    const fund = (pool: FakeUtxo[]) =>
      w.terms.fundCashFromReply(w.artifacts, reply(w, pool), { payer: buyer, fee: "auto" }, daa, VALUE);
    assert.ok(fund([authorizer, escrow, coin]).pending().length > 0, "control: the asset leg is funded, the cash vault empty");
    // The asset leg is not on the node: nothing, only one of its two UTXOs, a token of another
    // covenant, an authorizer that carries a covenant, a token owned by a key and not by the vault.
    const keyOwned = ownToken(sdk, "key-owned", ASSET_ARTIFACT, ASSET_COV, buyer, AMOUNT_A).utxo as FakeUtxo;
    for (const [what, pool] of [
      ["nothing", [coin]],
      ["only the authorizer", [authorizer, coin]],
      ["only the token", [escrow, coin]],
      ["a token of another covenant", [authorizer, sibling(escrow, "escrow-other-covenant", BigInt(escrow.amount), "11".repeat(32)), coin]],
      ["an authorizer with a covenant", [sibling(authorizer, "authorizer-covenant", BigInt(authorizer.amount), ASSET_COV), escrow, coin]],
      ["a token owned by a key", [authorizer, keyOwned, coin]],
    ] as const) {
      assert.equal(refusalError(() => fund([...pool])).code, "SDK_FUND_ASSET_NOT_FUNDED", what);
    }
    const said = refusalError(() => fund([escrow, coin])).message;
    assert.ok(said.startsWith("SDK_FUND_ASSET_NOT_FUNDED: the seller's asset leg is not funded on this node: no plain UTXO at the asset vault (the authorizer)."), said);
    assert.ok(refusalError(() => fund([authorizer, coin])).message.includes("no token UTXO of exactly 1000 units in the asset vault"));
    // An artifact that is not the asset token's is refused, not read as an empty vault.
    assert.equal(
      refusalError(() => w.terms.fundCashFromReply({ asset: CASH_ARTIFACT, cash: null }, reply(w, [authorizer, escrow, coin]), { payer: buyer, fee: "auto" }, daa, VALUE)).code,
      "TX_TOKEN_TEMPLATE",
    );
    // The cash vault already holds the exact deposit: the one a settle takes. Other amounts there, and a
    // UTXO that carries a covenant, are not it.
    assert.equal(refusalError(() => fund([authorizer, escrow, coin, cashVault])).code, "SDK_FUND_ALREADY_FUNDED");
    for (const [what, other] of [
      ["one sompi less", sibling(cashVault, "cash-less", KAS_CASH - 1n)],
      ["one sompi more", sibling(cashVault, "cash-more", KAS_CASH + 1n)],
      ["the amount with a covenant", sibling(cashVault, "cash-covenant", KAS_CASH, ASSET_COV)],
    ] as const) {
      assert.ok(fund([authorizer, escrow, coin, other]).pending().length > 0, what);
    }
    const second = refusalError(() => fund([authorizer, escrow, coin, cashVault])).message;
    assert.match(second, /^SDK_FUND_ALREADY_FUNDED: the cash vault already holds a deposit of exactly 100000000 sompi \([0-9a-f]{64}:0\)/);
    // Both at once: the deposit is told first.
    assert.equal(refusalError(() => fund([cashVault, coin])).code, "SDK_FUND_ALREADY_FUNDED");
  } finally {
    freeAll(w.wallets);
  }
});

test("a token that is no pinned kcc20.sil build is never funded: the addresses, the builder and the signature are refused beside the pinned control", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const coin = utxo("buyer-coin", 300_000_000n, p2pk(buyer)) as FakeUtxo;
    // The same trade with a token one suffix byte longer than the pinned build it is made from.
    const json: TermsJson = { ...w.json, asset_leg: tokenLeg(sdk, unpinnedToken(), ASSET_COV, AMOUNT_A) };
    const unpinned = validated(sdk, json);
    const artifacts = { asset: unpinnedToken(), cash: null };
    assert.deepEqual(
      [sdk.kcc20Template(unpinnedToken()).template_prefix_len, sdk.kcc20Template(unpinnedToken()).template_suffix_len],
      [1, 1461],
      "the fixture is the pinned (2,2) build with a suffix of 1460 plus one",
    );
    assert.equal(refusalError(() => unpinned.fundCashAddresses(artifacts, buyer)).code, "SDK_TEMPLATE_UNPINNED");
    assert.ok(w.terms.fundCashAddresses(w.artifacts, buyer).length > 0, "control: the pinned build");
    const unpinnedReply = reply(w, [coin]);
    const e = refusalError(() => unpinned.fundCashFromReply(artifacts, unpinnedReply, { payer: buyer, fee: "auto" }, daa, VALUE));
    assert.equal(e.code, "SDK_TEMPLATE_UNPINNED");
    assert.match(e.message, /^SDK_TEMPLATE_UNPINNED: the asset leg's KCC-20 template [0-9a-f]{64} \(1\+1461\) is not a pinned kcc20\.sil build /);
    assert.ok(e.message.endsWith("such tokens are outside v1"), e.message);
    // The check comes before the node is read: a reply that is no reply is still told the token.
    assert.equal(refusalError(() => unpinned.fundCashFromReply(artifacts, "{", { payer: buyer, fee: "auto" }, daa, VALUE)).code, "SDK_TEMPLATE_UNPINNED");
    // A signature: the builder (impulse-core's `fundKas`) makes the funding for any terms, and the
    // wallet refuses to sign it for a token that is not pinned, as `ipst sign` does.
    const funding = (terms: ValidatedTerms) =>
      terms.fundKas({ network: w.network, creation_daa: daa }, { inputs: [coin], fee: "5000000", change: p2pk(buyer) }, VALUE);
    const options = (arts: ArtifactsJson) => ({ artifacts: arts, current_daa: daa, value: VALUE, mainnet: false, max_fee: "5000000" });
    const pinnedDoc = funding(w.terms);
    const signed = w.wallets.buyer.sign(pinnedDoc, options(w.artifacts));
    assert.deepEqual(signed.signed_inputs, [0], "control: the pinned funding is signed");
    signed.ipst.free();
    const unpinnedDoc = funding(unpinned);
    assert.equal(refusalError(() => w.wallets.buyer.sign(unpinnedDoc, options(artifacts))).code, "SDK_TEMPLATE_UNPINNED");
  } finally {
    freeAll(w.wallets);
  }
});
