// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// "Before funding" (spec/CLI.md, I11 review round 2): a KCC-20 leg whose template is not one of the
// pinned kcc20.sil builds is never funded, and a native KAS cash leg below the minimum output is
// not either. The expectation is the command line's: `impulse address`, `fund build` and
// `ipst sign` of a funding refuse such terms with CLI_TEMPLATE_UNPINNED and CLI_KAS_LEG_BELOW_MIN;
// the SDK refuses with SDK_TEMPLATE_UNPINNED and TX_BELOW_MIN_KAS in every place a funding is
// given: the instructions (and with them the URI and the QR), the addresses and the builder of the
// buyer's cash funding, and the signature of a funding. The pinned list is read from the Rust
// source that holds it, not from the SDK. impulse-wasm's native tests compare each check with the
// command line's on all 11 vectors, the pinned builds and near misses; the cases here are the
// package's, each refusal beside an accepted control.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { load, partyFor, pinTerms, pinnedBuilds, refusalError, root, termsVector, termsVectors } from "./sdk.ts";
import type { FundingOptionsJson, TermsJson } from "../index.js";
import { AMOUNT_A, ASSET_COV, NOW, VALUE, p2pk, tokenLeg, unpinnedToken, utxo, validated } from "./fixtures.ts";
import { MODES, world } from "./world.ts";

const sdk = load();

const options = (terms: TermsJson, over: Partial<FundingOptionsJson> = {}): FundingOptionsJson => ({
  context: { network: terms.network, creation_daa: "400000000" },
  creation_daa_source: "node",
  party: partyFor("buyer", terms),
  kas_equivalent: "100000000",
  accept_the_risk: true,
  ...over,
});
const instructions = (terms: TermsJson, over: Partial<FundingOptionsJson> = {}) =>
  sdk.Terms.fromJson(terms).validateStructure().fundingInstructions(options(terms, over));

test("the SDK lists the pinned kcc20.sil builds the Rust source lists, in order, and they are the sixteen of silverscript v1.0.0", () => {
  const got = sdk.pinnedKcc20Templates();
  assert.equal(pinnedBuilds.length, 16, "the source holds sixteen builds, maxCovIns and maxCovOuts from 1 to 4");
  assert.deepEqual(
    got.map((p) => [p.max_cov_ins, p.max_cov_outs, p.template_hash, p.template_prefix_len, p.template_suffix_len]),
    pinnedBuilds.map((p) => [p.maxCovIns, p.maxCovOuts, p.hash, p.prefix, p.suffix]),
  );
  assert.deepEqual(
    got.map((p) => [p.max_cov_ins, p.max_cov_outs]),
    [1, 2, 3, 4].flatMap((ins) => [1, 2, 3, 4].map((outs) => [ins, outs])),
  );
  assert.equal(new Set(got.map((p) => p.template_hash)).size, 16, "sixteen different builds");
  // The fixture tokens of these tests are among them: the asset token is the (2,2) build.
  const asset = sdk.kcc20Template(readFileSync(new URL("crates/impulse-core/src/tx/testdata/kcc20-asset.json", root), "utf8"));
  assert.ok(got.some((p) => p.template_hash === asset.template_hash && p.template_suffix_len === asset.template_suffix_len));
});

test("no funding instruction is given for any golden vector as committed: its synthetic token is no kcc20.sil build, and the same vector with a pinned token is given one", () => {
  for (const t of termsVectors) {
    const e = refusalError(() => instructions(t.terms));
    assert.equal(e.code, "SDK_TEMPLATE_UNPINNED", t.name);
    assert.match(e.message, /^SDK_TEMPLATE_UNPINNED: the asset leg's KCC-20 template a227fc3a[0-9a-f]{56} \(40\+1420\) is not a pinned kcc20\.sil build /, t.name);
    assert.ok(e.message.endsWith("such tokens are outside v1"), t.name);
    assert.ok(instructions(pinTerms(t.terms)).legs.length === 2, `${t.name}: control, the token pinned`);
  }
});

test("every pinned build is accepted and each of its three parts one off is refused, for the asset leg and the cash leg", () => {
  const base = termsVector("01").terms; // KCC-20 against KCC-20, authority, mainnet
  const withTriple = (leg: "asset_leg" | "cash_leg", hash: string, prefix: number, suffix: number): TermsJson => {
    const t = pinTerms(base);
    const l = t[leg];
    assert.equal(l.kind, "kcc20");
    if (l.kind === "kcc20") {
      l.template_hash = hash;
      l.template_prefix_len = prefix;
      l.template_suffix_len = suffix;
    }
    return t;
  };
  for (const p of pinnedBuilds) {
    for (const leg of ["asset_leg", "cash_leg"] as const) {
      const where = `(${p.maxCovIns},${p.maxCovOuts}) ${leg}`;
      assert.equal(instructions(withTriple(leg, p.hash, p.prefix, p.suffix)).legs.length, 2, `${where}: pinned`);
      for (const [what, t] of [
        ["hash", withTriple(leg, `${p.hash.slice(0, 63)}${p.hash.endsWith("0") ? "1" : "0"}`, p.prefix, p.suffix)],
        ["prefix", withTriple(leg, p.hash, p.prefix + 1, p.suffix)],
        ["suffix", withTriple(leg, p.hash, p.prefix, p.suffix + 1)],
      ] as const) {
        const e = refusalError(() => instructions(t));
        assert.equal(e.code, "SDK_TEMPLATE_UNPINNED", `${where}: ${what} off by one`);
        assert.ok(e.message.includes(`the ${leg === "asset_leg" ? "asset" : "cash"} leg's KCC-20 template`), e.message);
      }
    }
  }
});

test("the order: the creation checks, then the KAS minimum, then the template, then the role check", () => {
  const unpinned = termsVector("08").terms;
  const pinned = pinTerms(unpinned);
  assert.equal(refusalError(() => instructions(unpinned, { context: { network: "mainnet", creation_daa: "400000000" } })).code, "TERMS_NETWORK_MISMATCH");
  const stranger = { ...partyFor("buyer", unpinned), key: "ab".repeat(32) };
  assert.equal(refusalError(() => instructions(unpinned, { party: stranger })).code, "SDK_TEMPLATE_UNPINNED", "before the role check");
  assert.equal(refusalError(() => instructions(pinned, { party: stranger })).code, "SDK_ROLE_KEY_MISMATCH", "control: pinned, then the role check");
  // A cash leg below the minimum output: 0.5 KAS is the least; both wrong, the minimum is told first.
  const cash = (t: TermsJson, amount: string): TermsJson => ({ ...t, cash_leg: { kind: "kas", amount } });
  assert.equal(instructions(cash(pinned, "50000000")).legs.length, 2, "exactly the minimum");
  assert.equal(refusalError(() => instructions(cash(pinned, "49999999"))).code, "TX_BELOW_MIN_KAS");
  assert.equal(refusalError(() => instructions(cash(unpinned, "49999999"))).code, "TX_BELOW_MIN_KAS");
  assert.match(refusalError(() => instructions(cash(pinned, "49999999"))).message, /output 0 would hold 49999999 sompi, the minimum is 50000000/);
});

test("the signature of a funding: the key must be the leg's depositor, the terms fundable at the node's score, and the token pinned; each beside the accepted control", () => {
  const w = world(sdk, MODES.vaultKas);
  try {
    const buyer = w.wallets.buyer.publicKey();
    const coin = utxo("buyer-coin", 300_000_000n, p2pk(buyer));
    const fund = (terms = w.terms) =>
      terms.fundKas({ network: w.network, creation_daa: NOW.toString() }, { inputs: [coin], fee: "5000000", change: p2pk(buyer) }, VALUE);
    const options = (over: object = {}) => ({
      artifacts: w.artifacts,
      current_daa: NOW.toString(),
      value: VALUE,
      mainnet: false,
      max_fee: "5000000",
      ...over,
    });
    const doc = fund();
    // The control: the buyer's wallet signs the buyer's funding at a score before the expiry.
    const signed = w.wallets.buyer.sign(doc, options());
    assert.deepEqual(signed.signed_inputs, [0]);
    signed.ipst.free();
    // Fundable at the score the wallet is told. At the expiry the document is no longer what the
    // builders make (the terms check comes first); and a trade whose expiry is further from the node's
    // score than the creation horizon is not fundable, which only the creation checks of a funding see.
    const expiry = BigInt(w.json.expiry_daa);
    assert.equal(
      refusalError(() => w.wallets.buyer.sign(fund(), options({ current_daa: expiry.toString() }))).code,
      "TX_EXPIRED",
    );
    w.wallets.buyer.sign(fund(), options({ current_daa: (expiry - 1n).toString() })).ipst.free();
    const horizon = BigInt(sdk.defaultMaxExpiryHorizonDaa());
    const far = (extra: bigint) => validated(sdk, { ...w.json, expiry_daa: (NOW + horizon + extra).toString() });
    const farOptions = options();
    w.wallets.buyer.sign(far(0n).fundKas({ network: w.network, creation_daa: NOW.toString() }, { inputs: [coin], fee: "5000000", change: p2pk(buyer) }, VALUE), farOptions).ipst.free();
    assert.equal(
      refusalError(() =>
        w.wallets.buyer.sign(far(1n).fundKas({ network: w.network, creation_daa: NOW.toString() }, { inputs: [coin], fee: "5000000", change: p2pk(buyer) }, VALUE), farOptions),
      ).code,
      "TERMS_EXPIRY_BEYOND_HORIZON",
      "one DAA score past the horizon",
    );
    // A key that is not the depositor's: the seller's wallet holds no input of this funding, so it
    // has nothing to sign; a funding whose inputs it does hold, for the buyer's leg, is refused as
    // not its leg to fund.
    assert.equal(refusalError(() => w.wallets.seller.sign(doc, options())).code, "SDK_SIGN_NOTHING_TO_SIGN");
    const sellerCoin = utxo("seller-coin", 300_000_000n, p2pk(w.wallets.seller.publicKey()));
    const sellersFunding = w.terms.fundKas(
      { network: w.network, creation_daa: NOW.toString() },
      { inputs: [sellerCoin], fee: "5000000", change: p2pk(w.wallets.seller.publicKey()) },
      VALUE,
    );
    const e = refusalError(() => w.wallets.seller.sign(sellersFunding, options()));
    assert.equal(e.code, "SDK_FUND_NOT_YOUR_LEG");
    assert.ok(e.message.includes(`which the buyer funds (key ${buyer})`), e.message);
    // A token that is no pinned build.
    const unpinned = validated(sdk, { ...w.json, asset_leg: tokenLeg(sdk, unpinnedToken(), ASSET_COV, AMOUNT_A) });
    const arts = { asset: unpinnedToken(), cash: null };
    assert.equal(refusalError(() => w.wallets.buyer.sign(fund(unpinned), options({ artifacts: arts }))).code, "SDK_TEMPLATE_UNPINNED");
  } finally {
    for (const k of Object.values(w.wallets)) k.free();
  }
});
