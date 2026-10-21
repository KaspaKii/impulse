// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The strictness of the builder-input forms (src/forms.rs): every key is required, no other key
// is read, every value has its JSON type, and an enumeration takes only its names. For each form
// there is an accepted control, and from it every variant that breaks the form in one place: each
// key of each object removed, one extra key added to each object, each value replaced by a value
// of another JSON type, each enumeration set to a name it does not have. Every variant must be
// refused with SDK_JSON_FORM, not read leniently and not refused for another reason.
//
// The variants are generated from the control by walking it, so a form that gains a key is
// covered without a new case. The walk covers the forms nested in the control as well (a UTXO, a
// scriptPublicKey, a KCC-20 state, a token UTXO, a fee payment).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  ASSET_ARTIFACT,
  ASSET_COV,
  AUTHORIZER,
  CARRIER,
  CASH_ARTIFACT,
  CASH_COV,
  KAS_CASH,
  KCC20_CASH,
  MODES,
  NOW,
  VALUE,
  ctx,
  erase,
  feePayment,
  funded,
  kcc20State,
  newParties,
  ownToken,
  p2pk,
  settleLegs,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import { load, refusal } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();

interface Variant {
  what: string;
  form: unknown;
}

type Path = (string | number)[];

const at = (root: unknown, path: Path): any => path.reduce((node: any, key) => node[key], root);
const show = (path: Path): string => path.map((k) => (typeof k === "number" ? `[${k}]` : `.${k}`)).join("") || "(form)";

/** Names an enumeration of the forms takes, by key; every variant sets one to a name it lacks. */
const ENUMS = new Set(["kind", "identifier_type"]);

/** Every one-place break of `control`. */
function variants(control: unknown): Variant[] {
  const out: Variant[] = [];
  const edit = (what: string, path: Path, change: (parent: any, key: string | number) => void) => {
    const form = structuredClone(control) as any;
    if (path.length === 0) throw new Error("the walk edits inside the form");
    change(path.length === 1 ? form : at(form, path.slice(0, -1)), path[path.length - 1]);
    out.push({ what: `${what} at ${show(path)}`, form });
  };
  const walk = (node: unknown, path: Path) => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => walk(item, [...path, i]));
      if (path.length > 0) edit("an object where an array is due", path, (parent, key) => (parent[key] = {}));
      return;
    }
    if (node !== null && typeof node === "object") {
      for (const key of Object.keys(node)) {
        edit(`key ${key} removed`, [...path, key], (parent, k) => delete parent[k]);
        walk((node as Record<string, unknown>)[key], [...path, key]);
      }
      // One extra key in this object.
      const form = structuredClone(control) as any;
      (path.length === 0 ? form : at(form, path))["extra"] = "x";
      out.push({ what: `an extra key at ${show(path)}`, form });
      if (path.length > 0) {
        edit("an array where an object is due", path, (parent, key) => (parent[key] = []));
        edit("null where an object is due", path, (parent, key) => (parent[key] = null));
      }
      return;
    }
    const key = String(path[path.length - 1]);
    const other = typeof node === "string" ? 5 : typeof node === "number" ? "5" : typeof node === "boolean" ? "true" : 5;
    edit(`${node === null ? "null" : typeof node} replaced by ${typeof other}`, path, (parent, k) => (parent[k] = other));
    if (typeof node === "string" && ENUMS.has(key)) {
      // Names that are none of this form's, among them the kinds of the other forms.
      for (const name of ["x", "", node.toUpperCase(), "direct", "settle", "vault", "token", "script_hash "]) {
        if (name === node) continue;
        edit(`${key} set to ${JSON.stringify(name)}`, path, (parent, k) => (parent[k] = name));
      }
    }
    if (typeof node === "string" && /^[0-9]+$/.test(node)) {
      edit("a u64 with a leading zero", path, (parent, k) => (parent[k] = `0${node}`));
      edit("a u64 with a sign", path, (parent, k) => (parent[k] = `-${node}`));
    }
  };
  walk(control, []);
  return out;
}

/** Runs the control, then every variant, which must each be refused with SDK_JSON_FORM. */
function strict(name: string, control: unknown, call: (form: any) => unknown, atLeast: number): void {
  test(`${name}: accepted as it is, and every one-place break of it is SDK_JSON_FORM`, () => {
    assert.ok(call(structuredClone(control)), "control");
    const broken = variants(control);
    assert.ok(broken.length >= atLeast, `${broken.length} variants, at least ${atLeast}`);
    for (const v of broken) {
      assert.equal(refusal(() => call(v.form)), "SDK_JSON_FORM", `${name}: ${v.what}`);
    }
  });
}

const T = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
const T_KCC20 = validated(sdk, termsJson(sdk, p, MODES.vaultKcc20));
const T_EXTERNAL = validated(sdk, termsJson(sdk, p, MODES.external));
const T_DIRECT = validated(sdk, termsJson(sdk, p, MODES.directKas));
const T_DIRECT_KCC20 = validated(sdk, termsJson(sdk, p, MODES.directKcc20));
const funding = () => feePayment(p.payer);

// Fee payment (and with it the UTXO and scriptPublicKey forms), through fundKas.
strict("fee payment", funding(), (f) => T.fundKas(ctx(), f, VALUE), 30);

// The deposit of fundKcc20, with two tokens: the deposit, token UTXO and KCC-20 state forms.
strict(
  "KCC-20 deposit",
  {
    artifact: ASSET_ARTIFACT,
    tokens: [
      ownToken(sdk, "token-a", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 600n),
      ownToken(sdk, "token-b", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 700n),
    ],
    carrier: CARRIER.toString(),
    authorizer: AUTHORIZER.toString(),
  },
  (d) => T.fundKcc20(0, ctx(), d, funding(), VALUE),
  80,
);

// The legs of a settle, for each kind of cash leg.
strict("settle legs, KAS cash", settleLegs(funded(sdk, T, MODES.vaultKas)), (l) => T.settle(l, funding(), daa, VALUE), 50);
strict(
  "settle legs, KCC-20 cash",
  settleLegs(funded(sdk, T_KCC20, MODES.vaultKcc20)),
  (l) => T_KCC20.settle(l, funding(), daa, VALUE),
  70,
);
strict(
  "settle legs, external cash",
  settleLegs(funded(sdk, T_EXTERNAL, MODES.external)),
  (l) => T_EXTERNAL.settle(l, funding(), daa, VALUE),
  40,
);

// The legs of a Direct trade, for each kind of cash leg.
const buyerToken = ownToken(sdk, "direct-buyer-token", CASH_ARTIFACT, CASH_COV, p.buyer.publicHex, KCC20_CASH);
strict(
  "Direct legs, KAS cash",
  {
    asset_artifact: ASSET_ARTIFACT,
    asset: ownToken(sdk, "direct-seller", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
    cash: { kind: "kas", utxo: utxo("direct-buyer", KAS_CASH, p2pk(p.buyer.publicHex)) },
  },
  (l) => T_DIRECT.direct(l, funding(), daa, VALUE),
  50,
);
strict(
  "Direct legs, KCC-20 cash",
  {
    asset_artifact: ASSET_ARTIFACT,
    asset: ownToken(sdk, "direct-seller", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
    cash: { kind: "kcc20", artifact: CASH_ARTIFACT, token: buyerToken },
  },
  (l) => T_DIRECT_KCC20.direct(l, funding(), daa, VALUE),
  70,
);

// The escrowed token a refund carries home.
const F = funded(sdk, T, MODES.vaultKas);
strict(
  "refund escrow",
  { artifact: ASSET_ARTIFACT, utxo: F.assetEscrow, amount: "1000", is_minter: false },
  (e) => T.refund(0, "depositor", F.assetAuthorizer, e, funding(), VALUE),
  20,
);

// The templates the terms check takes, on a document the builders make.
const received = T_DIRECT.direct(
  {
    asset_artifact: ASSET_ARTIFACT,
    asset: ownToken(sdk, "direct-seller", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
    cash: { kind: "kas", utxo: utxo("direct-buyer", KAS_CASH, p2pk(p.buyer.publicHex)) },
  },
  funding(),
  daa,
  VALUE,
);
strict("artifacts", { asset: ASSET_ARTIFACT, cash: null }, (a) => received.verifyAgainstTerms(a, daa, VALUE), 4);
strict("artifacts with a cash template", { asset: ASSET_ARTIFACT, cash: CASH_ARTIFACT }, (a) => received.verifyAgainstTerms(a, daa, VALUE), 5);

// A KCC-20 state, through kcc20ScriptPublicKey.
strict(
  "KCC-20 state",
  kcc20State(p.seller.publicHex, 1_000n),
  (s) => sdk.kcc20ScriptPublicKey(ASSET_ARTIFACT, s),
  8,
);
