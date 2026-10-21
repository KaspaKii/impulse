// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Fail closed, with a stable code, on values at the edge of their range: every amount in the
// arguments of every builder is replaced in turn by 0, 1, the edges of the script integer and of
// u64, and the KAS supply plus one. Each call must build or refuse with an ImpulseError; any
// other exception (a trap from a Rust panic reads as a RuntimeError) fails the test, and so does
// a refusal without a stable code.
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
  ctx,
  erase,
  feePayment,
  funded,
  newParties,
  ownToken,
  p2pk,
  settleLegs,
  termsJson,
  utxo,
  validated,
} from "./fixtures.ts";
import { load } from "./sdk.ts";

const sdk = load();
const p = newParties();
after(() => erase(p));
const daa = NOW.toString();

const EDGES = [
  "0",
  "1",
  "9223372036854775807", // i64::MAX, the largest script integer
  "9223372036854775808",
  "18446744073709551615", // u64::MAX
  "2900000000000000000", // MAX_SOMPI
  "2900000000000000001",
];
// Declared in full, so that only the amount under test can refuse.
const LIFTED = { i_accept_the_risk: true } as const;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Paths of the string leaves that spell a u64, in `value`. */
function amountPaths(value: Json, path: (string | number)[] = []): (string | number)[][] {
  if (typeof value === "string") return /^[0-9]+$/.test(value) && value.length < 21 ? [path] : [];
  if (Array.isArray(value)) return value.flatMap((v, i) => amountPaths(v, [...path, i]));
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) => amountPaths(v, [...path, k]));
  }
  return [];
}

function withAt(root: Json, path: (string | number)[], to: string): Json {
  const copy = structuredClone(root);
  let at: Json = copy;
  for (const key of path.slice(0, -1)) at = (at as Record<string | number, Json>)[key];
  (at as Record<string | number, Json>)[path[path.length - 1]] = to;
  return copy;
}

/** Runs `call` on every edge value at every amount of `args`; returns how many calls ran. */
function sweep(name: string, args: Json[], call: (args: Json[]) => unknown): number {
  let calls = 0;
  args.forEach((arg, which) => {
    for (const path of amountPaths(arg)) {
      for (const edge of EDGES) {
        const edited = args.map((a, i) => (i === which ? withAt(a, path, edge) : a));
        try {
          call(edited);
        } catch (thrown) {
          const e = thrown as { name?: string; code?: unknown; message?: string };
          assert.equal(e.name, "ImpulseError", `${name}: ${path.join(".")} = ${edge}: ${e.name}: ${e.message}`);
          assert.equal(typeof e.code, "string");
        }
        calls += 1;
      }
    }
  });
  return calls;
}

const T = validated(sdk, termsJson(sdk, p, MODES.vaultKas));
const T_TOKENS = validated(sdk, termsJson(sdk, p, MODES.vaultKcc20));
const T_DIRECT = validated(sdk, termsJson(sdk, p, MODES.directKas));
const F = funded(sdk, T, MODES.vaultKas);
const F_TOKENS = funded(sdk, T_TOKENS, MODES.vaultKcc20);
const fee = (owner = p.payer) => feePayment(owner) as unknown as Json;

test("fund_kas and fund_kcc20 fail closed at the edges of every amount", () => {
  let n = sweep("fundKas", [ctx() as unknown as Json, fee(p.buyer)], ([c, f]) => T.fundKas(c as never, f as never, LIFTED));
  const deposit = {
    artifact: ASSET_ARTIFACT,
    tokens: [
      ownToken(sdk, "a", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 600n),
      ownToken(sdk, "b", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 700n),
    ],
    carrier: CARRIER.toString(),
    authorizer: AUTHORIZER.toString(),
  };
  n += sweep("fundKcc20", [ctx() as unknown as Json, deposit as unknown as Json, fee()], ([c, d, f]) =>
    T.fundKcc20(0, c as never, d as never, f as never, LIFTED),
  );
  const cashDeposit = {
    artifact: CASH_ARTIFACT,
    tokens: [ownToken(sdk, "c", CASH_ARTIFACT, CASH_COV, p.buyer.publicHex, KCC20_CASH)],
    carrier: CARRIER.toString(),
    authorizer: AUTHORIZER.toString(),
  };
  n += sweep("fundKcc20 cash", [cashDeposit as unknown as Json, fee()], ([d, f]) =>
    T_TOKENS.fundKcc20(1, ctx(), d as never, f as never, LIFTED),
  );
  assert.ok(n > 100, `${n} calls`);
});

test("settle, refund and Direct fail closed at the edges of every amount", () => {
  let n = sweep("settle KAS", [settleLegs(F) as unknown as Json, fee()], ([l, f]) =>
    T.settle(l as never, f as never, daa, LIFTED),
  );
  n += sweep("settle KCC-20", [settleLegs(F_TOKENS) as unknown as Json, fee()], ([l, f]) =>
    T_TOKENS.settle(l as never, f as never, daa, LIFTED),
  );
  const escrow = { artifact: ASSET_ARTIFACT, utxo: F.assetEscrow, amount: "1000", is_minter: false };
  n += sweep("refund", [F.assetAuthorizer as unknown as Json, escrow as unknown as Json, fee()], ([u, e, f]) =>
    T.refund(0, "depositor", u as never, e as never, f as never, LIFTED),
  );
  const legs = {
    asset_artifact: ASSET_ARTIFACT,
    asset: ownToken(sdk, "s", ASSET_ARTIFACT, ASSET_COV, p.seller.publicHex, 1_000n),
    cash: { kind: "kas", utxo: utxo("b", KAS_CASH, p2pk(p.buyer.publicHex)) },
  };
  n += sweep("direct", [legs as unknown as Json, fee()], ([l, f]) =>
    T_DIRECT.direct(l as never, f as never, daa, LIFTED),
  );
  assert.ok(n > 150, `${n} calls`);
});

test("the controls of the sweeps build", () => {
  // The unedited arguments are accepted, so every refusal above is the edited amount's.
  assert.ok(T.fundKas(ctx(), feePayment(p.buyer), LIFTED));
  assert.ok(T.settle(settleLegs(F), feePayment(p.payer), daa, LIFTED));
  assert.ok(T.refund(0, "depositor", F.assetAuthorizer, null, feePayment(p.payer), LIFTED));
});
