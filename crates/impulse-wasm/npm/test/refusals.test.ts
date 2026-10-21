// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Every stable refusal code through the published package, each refusal beside an accepted
// control that differs from it only in the refused value. impulse-core's TERMS_* and TEMPLATE_*
// codes must reach TypeScript unchanged; the SDK adds SDK_* codes for JavaScript arguments.
// The last test requires every code of termsErrorCodes, templateErrorCodes and sdkErrorCodes to
// have a case here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  hex,
  load,
  memory,
  partyFor,
  pinOf,
  pinTerms,
  refusal,
  refusalError,
  root,
  templateHashFile,
  termsVector,
  unhex,
  vaultVector,
  wasmUrl,
  type Sdk,
} from "./sdk.ts";
import type { CreationContextJson, FundingOptionsJson, ServerInfoJson, TermsJson } from "../index.js";
import { AMOUNT_A, ASSET_ARTIFACT, ASSET_COV, AUTHORIZER, LIFT, NOW, VALUE, ownToken, p2pk, tokenLeg, unpinnedToken, utxo, validated } from "./fixtures.ts";
import { FakeNode, utxosFrame } from "./fakenode.ts";
import { MODES, addressFor, pinsFor, world } from "./world.ts";
import type { FakeUtxo } from "./fakenode.ts";

const sdk = load();

interface Case {
  code: string;
  what: string;
  accept: () => unknown;
  refuse: () => unknown;
}
const cases: Case[] = [];
function add(code: string, what: string, accept: () => unknown, refuse: () => unknown): void {
  cases.push({ code, what, accept, refuse });
}

// The JSON form of a terms vector, edited. `any` because the edits break the declared types.
function edited(prefix: string, edit: (t: any) => void = () => {}): TermsJson {
  const t = structuredClone(termsVector(prefix).terms);
  edit(t);
  return t;
}
const structure = (t: TermsJson) => sdk.Terms.fromJson(t).validateStructure();
const checked = (prefix: string) => structure(edited(prefix));

/** A copy of `bytes` with `bytes[at]` (which must hold `was`) set to `value`. */
function patched(bytes: Uint8Array, at: number, was: number, value: number): Uint8Array {
  assert.equal(bytes[at], was, `layout: byte ${at}`);
  const out = bytes.slice();
  out[at] = value;
  return out;
}

// Decoding (spec/ENCODING.md, "Decoding and encoding refusals"), on vector 02's canonical bytes.
// Offsets: 0 version, 1 network, 2 settlement_mode, 75 authority presence; vector 02's
// seller_proceeds is a KAS scriptPubKey whose u32 length sits at 235.
const c02 = unhex(termsVector("02").canonical);
const decode = (b: Uint8Array) => sdk.Terms.decode(b);
add("TERMS_TRUNCATED", "decode one byte short", () => decode(c02), () => decode(c02.slice(0, -1)));
add(
  "TERMS_TRAILING_BYTES",
  "decode one byte long",
  () => decode(c02),
  () => decode(Uint8Array.from([...c02, 0])),
);
add(
  "TERMS_UNSUPPORTED_VERSION",
  "decode version byte 2",
  () => decode(patched(c02, 0, 1, 1)),
  () => decode(patched(c02, 0, 1, 2)),
);
add(
  "TERMS_INVALID_TAG",
  "decode network byte 2 (1, testnet, decodes)",
  () => decode(patched(c02, 1, 0, 1)),
  () => decode(patched(c02, 1, 0, 2)),
);
add(
  "TERMS_UNKNOWN_SETTLEMENT_MODE",
  "decode settlement mode byte 2 (0, Direct, decodes)",
  () => decode(patched(c02, 2, 1, 0)),
  () => decode(patched(c02, 2, 1, 2)),
);
add(
  "TERMS_INVALID_PRESENCE",
  "decode authority presence byte 2",
  () => decode(patched(c02, 75, 1, 1)),
  () => decode(patched(c02, 75, 1, 2)),
);
add(
  "TERMS_FIELD_TOO_LONG",
  "decode a script length of 10,001",
  () => decode(patched(c02, 235, 0x22, 0x22)),
  () => decode(patched(patched(c02, 235, 0x22, 0x11), 236, 0x00, 0x27)),
);
const longScript = (n: number) =>
  sdk.Terms.fromJson(edited("02", (t) => (t.seller_proceeds.script = "51".repeat(n))));
add(
  "TERMS_FIELD_TOO_LONG",
  "encode a 10,001-byte script (10,000 encodes)",
  () => longScript(10_000).encode(),
  () => longScript(10_001).encode(),
);
add(
  "TERMS_FIELD_TOO_LONG",
  "terms hash of a 10,001-byte script",
  () => longScript(10_000).termsHash(),
  () => longScript(10_001).termsHash(),
);
add(
  "TERMS_UNSUPPORTED_VERSION",
  "encode version 2",
  () => sdk.Terms.fromJson(edited("02", (t) => (t.version = 1))).encode(),
  () => sdk.Terms.fromJson(edited("02", (t) => (t.version = 2))).encode(),
);

// Structure checks (spec/ENCODING.md, "Structure checks"), in check order.
const v01 = termsVector("01").terms;
const v05 = termsVector("05").terms;
add(
  "TERMS_UNSUPPORTED_VERSION",
  "structure: version 2",
  () => structure(edited("01", (t) => (t.version = 1))),
  () => structure(edited("01", (t) => (t.version = 2))),
);
add(
  "TERMS_INVALID_KEY",
  "structure: seller key above the field prime",
  () => structure(edited("01")),
  () => structure(edited("01", (t) => (t.seller_key = "ff".repeat(32)))),
);
add(
  "TERMS_PARTIES_NOT_DISTINCT",
  "structure: buyer key equal to the seller key",
  () => structure(edited("01")),
  () => structure(edited("01", (t) => (t.buyer_key = v01.seller_key))),
);
add(
  "TERMS_AUTHORITY_IS_PARTY",
  "structure: authority key equal to the buyer key",
  () => structure(edited("01")),
  () => structure(edited("01", (t) => (t.authority_key = v01.buyer_key))),
);
add(
  "TERMS_ASSET_EXTERNAL",
  "structure: external asset leg",
  () => structure(edited("01")),
  () => structure(edited("01", (t) => (t.asset_leg = { kind: "external", amount: "1000" }))),
);
add(
  "TERMS_ASSET_KIND_UNSUPPORTED",
  "structure: KAS asset leg (D13)",
  () => structure(edited("01")),
  () => structure(edited("01", (t) => (t.asset_leg = { kind: "kas", amount: "1000" }))),
);
add(
  "TERMS_EXTERNAL_WITHOUT_AUTHORITY",
  "structure: external cash without an authority",
  () => structure(edited("05")),
  () => structure(edited("05", (t) => (t.authority_key = null))),
);
add(
  "TERMS_DIRECT_INCOMPATIBLE",
  "structure: Direct with earmarked funding",
  () => structure(edited("07", (t) => (t.funding_mode = "revocable"))),
  () => structure(edited("07", (t) => (t.funding_mode = "earmarked"))),
);
add(
  "TERMS_AMOUNT_ZERO",
  "structure: asset amount 0 (1 passes)",
  () => structure(edited("01", (t) => (t.asset_leg.amount = "1"))),
  () => structure(edited("01", (t) => (t.asset_leg.amount = "0"))),
);
add(
  "TERMS_AMOUNT_OUT_OF_RANGE",
  "structure: KAS cash one sompi above MAX_SOMPI",
  () => structure(edited("02", (t) => (t.cash_leg.amount = "2900000000000000000"))),
  () => structure(edited("02", (t) => (t.cash_leg.amount = "2900000000000000001"))),
);
add(
  "TERMS_ZERO_IDENTIFIER",
  "structure: all-zero asset covenant ID",
  () => structure(edited("01", (t) => (t.asset_leg.covenant_id = "00".repeat(31) + "01"))),
  () => structure(edited("01", (t) => (t.asset_leg.covenant_id = "00".repeat(32)))),
);
add(
  "TERMS_TEMPLATE_LENGTH",
  "structure: template prefix length 0 (1 passes)",
  () => structure(edited("01", (t) => (t.asset_leg.template_prefix_len = 1))),
  () => structure(edited("01", (t) => (t.asset_leg.template_prefix_len = 0))),
);
add(
  "TERMS_SAME_COVENANT",
  "structure: one covenant on both legs",
  () => structure(edited("01")),
  () =>
    structure(
      edited("01", (t) => {
        assert.equal(v01.asset_leg.kind, "kcc20");
        if (v01.asset_leg.kind === "kcc20") t.cash_leg.covenant_id = v01.asset_leg.covenant_id;
      }),
    ),
);
add(
  "TERMS_DESTINATION_KIND",
  "structure: KCC-20 owner for KAS proceeds",
  () => structure(edited("02")),
  () =>
    structure(
      edited("02", (t) => {
        t.seller_proceeds = { kind: "kcc20", identifier_type: "pubkey", identifier: t.seller_key };
      }),
    ),
);
add(
  "TERMS_NONSTANDARD_SCRIPT",
  "structure: OP_TRUE as the KAS proceeds script",
  () => structure(edited("02")),
  () => structure(edited("02", (t) => (t.seller_proceeds.script = "51"))),
);
add(
  "TERMS_EXPIRY_NOT_DAA",
  "structure: expiry at LOCK_TIME_THRESHOLD",
  () => structure(edited("02", (t) => (t.expiry_daa = "499999999999"))),
  () => structure(edited("02", (t) => (t.expiry_daa = "500000000000"))),
);
add(
  "TERMS_EARLIEST_NOT_DAA",
  "structure: earliest at LOCK_TIME_THRESHOLD",
  () => structure(edited("01", (t) => (t.earliest_daa = v01.expiry_daa))),
  () => structure(edited("01", (t) => (t.earliest_daa = "500000000000"))),
);
add(
  "TERMS_EARLIEST_ZERO",
  "structure: earliest present and 0 (1 passes)",
  () => structure(edited("01", (t) => (t.earliest_daa = "1"))),
  () => structure(edited("01", (t) => (t.earliest_daa = "0"))),
);
add(
  "TERMS_EARLIEST_AFTER_EXPIRY",
  "structure: earliest one above expiry",
  () => structure(edited("01", (t) => (t.earliest_daa = v01.expiry_daa))),
  () => structure(edited("01", (t) => (t.earliest_daa = String(BigInt(v01.expiry_daa) + 1n)))),
);

// Creation checks (spec/ENCODING.md, "Creation checks"), through validateCreation and through
// instantiateForCreation. Vector 01 is mainnet with expiry 425,920,000.
const expiry = BigInt(v01.expiry_daa);
const ctx = (over: Partial<CreationContextJson> = {}): CreationContextJson => ({
  network: "mainnet",
  creation_daa: "400000000",
  ...over,
});
const creationCases: [string, string, CreationContextJson, CreationContextJson][] = [
  ["TERMS_NETWORK_MISMATCH", "testnet context", ctx(), ctx({ network: "testnet" })],
  [
    "TERMS_EXPIRY_NOT_AFTER_CREATION",
    "creation DAA equal to expiry",
    ctx({ creation_daa: String(expiry - 1n) }),
    ctx({ creation_daa: String(expiry) }),
  ],
  [
    "TERMS_EXPIRY_BEYOND_HORIZON",
    "horizon one short of expiry",
    ctx({ max_expiry_horizon_daa: String(expiry - 400_000_000n) }),
    ctx({ max_expiry_horizon_daa: String(expiry - 400_000_000n - 1n) }),
  ],
];
for (const [code, what, good, bad] of creationCases) {
  add(code, `validateCreation: ${what}`, () => checked("01").validateCreation(good), () =>
    checked("01").validateCreation(bad),
  );
  add(code, `instantiateForCreation: ${what}`, () =>
    checked("01").instantiateForCreation(0, good, LIFT), () =>
    checked("01").instantiateForCreation(0, bad, LIFT),
  );
}

// instantiateForCreation is the only path to a funding address, so each of its arguments is
// refused here too (review round 1), beside the same call with the accepted value.
const anyLeg = (x: unknown) => x as number;
const creationArgs: [string, string, () => unknown, () => unknown][] = [
  ["SDK_ARGUMENT_TYPE", "leg as a string", () => anyLeg(0), () => anyLeg("0")],
  ["SDK_ARGUMENT_TYPE", "leg 0.5", () => anyLeg(0), () => anyLeg(0.5)],
  ["TEMPLATE_LEG_INDEX", "leg 2", () => anyLeg(1), () => anyLeg(2)],
  ["TEMPLATE_LEG_INDEX", "leg -1", () => anyLeg(0), () => anyLeg(-1)],
];
for (const [code, what, good, bad] of creationArgs) {
  add(code, `instantiateForCreation: ${what}`, () =>
    checked("01").instantiateForCreation(good() as number, ctx(), LIFT), () =>
    checked("01").instantiateForCreation(bad() as number, ctx(), LIFT),
  );
}
const badContexts: [string, CreationContextJson][] = [
  ["creation DAA as a number", { network: "mainnet", creation_daa: 400000000 } as unknown as CreationContextJson],
  ["an unknown key", { ...ctx(), creation: "400000000" } as unknown as CreationContextJson],
  ["network Mainnet", { ...ctx(), network: "Mainnet" } as unknown as CreationContextJson],
  ["no creation DAA", { network: "mainnet" } as unknown as CreationContextJson],
  ["not an object", "mainnet" as unknown as CreationContextJson],
];
for (const [what, bad] of badContexts) {
  add("SDK_JSON_FORM", `instantiateForCreation: context with ${what}`, () =>
    checked("01").instantiateForCreation(0, ctx(), LIFT), () =>
    checked("01").instantiateForCreation(0, bad, LIFT),
  );
}

// ValidatedTerms.decode runs the structure checks on the bytes it decodes (review round 1), on
// vector 02's canonical bytes: the seller key sits at bytes 11 to 43, the buyer key at 43 to 75.
const vdecode = (b: Uint8Array) => sdk.ValidatedTerms.decode(b);
assert.equal(hex(c02.slice(11, 43)), termsVector("02").terms.seller_key, "layout: seller key");
assert.equal(hex(c02.slice(43, 75)), termsVector("02").terms.buyer_key, "layout: buyer key");
const buyerIsSeller = c02.slice();
buyerIsSeller.set(c02.slice(11, 43), 43);
add(
  "TERMS_PARTIES_NOT_DISTINCT",
  "ValidatedTerms.decode of bytes whose buyer key is the seller key (Terms.decode reads them)",
  () => {
    vdecode(c02);
    return sdk.Terms.decode(buyerIsSeller);
  },
  () => vdecode(buyerIsSeller),
);
add("TERMS_TRUNCATED", "ValidatedTerms.decode one byte short", () => vdecode(c02), () =>
  vdecode(c02.slice(0, -1)),
);
add("TERMS_TRAILING_BYTES", "ValidatedTerms.decode one byte long", () => vdecode(c02), () =>
  vdecode(Uint8Array.from([...c02, 0])),
);
add(
  "TERMS_INVALID_KEY",
  "ValidatedTerms.decode of a seller key above the field prime",
  () => vdecode(c02),
  () => {
    const b = c02.slice();
    b.fill(0xff, 11, 43);
    return vdecode(b);
  },
);

// Template (spec/TEMPLATE.md). The state starts right after the template prefix: version push
// (2 bytes), network push (2), nonce (9), seller key (33), buyer key (33), hasAuthority (2),
// authorityKey (33); legIndex is the last push (9 bytes) before the suffix.
const template = sdk.templateCheck();
const p = template.prefix().length;
const s = template.suffix().length;
const script01 = unhex(vaultVector("01").asset_vault.redeem_script ?? "");
const script04 = unhex(vaultVector("04").asset_vault.redeem_script ?? "");
const decodeVault = (b: Uint8Array) => sdk.decodeVault(b);
add(
  "TEMPLATE_LEG_INDEX",
  "instantiateExisting leg 2",
  () => checked("01").instantiateExisting(1),
  () => checked("01").instantiateExisting(2),
);
add(
  "TEMPLATE_LEG_INDEX",
  "instantiateExisting leg -1",
  () => checked("01").instantiateExisting(0),
  () => checked("01").instantiateExisting(-1),
);
const legAt = script01.length - s - 8;
add(
  "TEMPLATE_LEG_INDEX",
  "decode a script whose legIndex is 2",
  () => decodeVault(patched(script01, legAt, 0, 0)),
  () => decodeVault(patched(patched(script01, legAt - 1, 0x08, 0x08), legAt, 0, 2)),
);
add(
  "TEMPLATE_NO_VAULT",
  "Direct terms have no asset vault",
  () => checked("01").instantiateExisting(0),
  () => checked("07").instantiateExisting(0),
);
add(
  "TEMPLATE_NO_VAULT",
  "external cash has no cash vault",
  () => checked("05").instantiateExisting(0),
  () => checked("05").instantiateExisting(1),
);
add(
  "TEMPLATE_NO_VAULT",
  "instantiateForCreation of an external-cash cash vault",
  () => checked("05").instantiateForCreation(0, ctx(), LIFT),
  () => checked("05").instantiateForCreation(1, ctx(), LIFT),
);
add(
  "TEMPLATE_NOT_IMPULSE_VAULT",
  "decode a script whose prefix differs",
  () => decodeVault(script01),
  () => decodeVault(patched(script01, 0, script01[0], script01[0] ^ 1)),
);
add(
  "TEMPLATE_NOT_IMPULSE_VAULT",
  "template hash of a script shorter than prefix plus suffix",
  () => sdk.templateHashOfInstance(script01.slice(0, p + s)),
  () => sdk.templateHashOfInstance(script01.slice(0, p + s - 1)),
);
add(
  "TEMPLATE_STATE_MALFORMED",
  "decode a state of one empty push",
  () => decodeVault(script01),
  () => decodeVault(Uint8Array.from([...template.prefix(), 0x00, ...template.suffix()])),
);
add(
  "TEMPLATE_STATE_INVALID",
  "decode network byte 2 in the state (1, testnet, decodes)",
  () => decodeVault(patched(patched(script01, p + 2, 0x01, 0x01), p + 3, 0, 1)),
  () => decodeVault(patched(script01, p + 3, 0, 2)),
);
add(
  "TEMPLATE_NONCANONICAL",
  "decode an authority key under an absent authority",
  () => decodeVault(patched(patched(script04, p + 80, 0, 0), p + 81, 0x20, 0x20)),
  () => decodeVault(patched(script04, p + 82, 0, 1)),
);
// A decoded state passes the structure checks before decodeVault returns it (review round 1):
// the seller key's 32 bytes start at p + 14, the buyer key's at p + 47.
assert.equal(hex(script01.slice(p + 14, p + 46)), v01.seller_key, "layout: seller key");
assert.equal(hex(script01.slice(p + 47, p + 79)), v01.buyer_key, "layout: buyer key");
const vaultBuyerIsSeller = script01.slice();
vaultBuyerIsSeller.set(script01.slice(p + 14, p + 46), p + 47);
add(
  "TERMS_PARTIES_NOT_DISTINCT",
  "decodeVault of a state whose buyer key is the seller key",
  () => decodeVault(script01),
  () => decodeVault(vaultBuyerIsSeller),
);

// The startup check, on copies of the shipped binary whose embedded contracts/TEMPLATE_HASH text
// is edited. Each copy runs as its own module instance; the control is a copy through the same
// path with the text left as it is.
async function instance(tag: string, firstChar: string): Promise<Sdk> {
  const bytes = readFileSync(wasmUrl);
  const text = Buffer.from(templateHashFile);
  const at = bytes.indexOf(text);
  assert.ok(at >= 0, "the binary embeds contracts/TEMPLATE_HASH");
  assert.equal(bytes.indexOf(text, at + 1), -1, "exactly once");
  const copy = Buffer.from(bytes);
  copy.write(firstChar, at, "latin1");
  const specifier = `../pkg/impulse_wasm.js?instance=${tag}`;
  const mod = (await import(specifier)) as Sdk;
  mod.initSync({ module: copy });
  return mod;
}
const pinnedFirst = templateHashFile[0];
const unchanged = await instance("unchanged", pinnedFirst);
const otherHash = await instance("other-hash", pinnedFirst === "0" ? "1" : "0");
const notHex = await instance("not-hex", "x");
const vaultOn = (m: Sdk) => m.Terms.fromJson(edited("01")).validateStructure().instantiateExisting(0);
const decodeOn = (m: Sdk) => m.decodeVault(script01);
add(
  "TEMPLATE_HASH_MISMATCH",
  "startup check with another TEMPLATE_HASH",
  () => unchanged.templateCheck(),
  () => otherHash.templateCheck(),
);
add(
  "TEMPLATE_HASH_MISMATCH",
  "instantiation with another TEMPLATE_HASH",
  () => vaultOn(unchanged),
  () => vaultOn(otherHash),
);
add(
  "TEMPLATE_HASH_MISMATCH",
  "decode with another TEMPLATE_HASH",
  () => decodeOn(unchanged),
  () => decodeOn(otherHash),
);
add(
  "TEMPLATE_ARTIFACT_INVALID",
  "startup check with a TEMPLATE_HASH that is not hex",
  () => unchanged.templateCheck(),
  () => notHex.templateCheck(),
);
add(
  "TEMPLATE_ARTIFACT_INVALID",
  "instantiation with a TEMPLATE_HASH that is not hex",
  () => vaultOn(unchanged),
  () => vaultOn(notHex),
);

// SDK codes: JavaScript values the Rust types cannot express.
const asBytes = (x: unknown) => x as Uint8Array;
add(
  "SDK_ARGUMENT_TYPE",
  "Terms.decode of a hex string",
  () => sdk.Terms.decode(c02),
  () => sdk.Terms.decode(asBytes(hex(c02))),
);
add(
  "SDK_ARGUMENT_TYPE",
  "decodeVault of a plain array",
  () => sdk.decodeVault(script01),
  () => sdk.decodeVault(asBytes([...script01])),
);
add(
  "SDK_ARGUMENT_TYPE",
  "ValidatedTerms.decode of undefined",
  () => sdk.ValidatedTerms.decode(c02),
  () => sdk.ValidatedTerms.decode(asBytes(undefined)),
);
add(
  "SDK_ARGUMENT_TYPE",
  "Terms.decode of a Uint8Array whose buffer is detached",
  () => sdk.Terms.decode(c02.slice()),
  () => {
    const bytes = c02.slice();
    structuredClone(bytes.buffer, { transfer: [bytes.buffer] }); // detaches it
    assert.equal(bytes.byteLength, 0);
    return sdk.Terms.decode(bytes);
  },
);
add(
  "SDK_ARGUMENT_TYPE",
  "decodeVault of an object that inherits from Uint8Array but is not one",
  () => sdk.decodeVault(script01),
  () => sdk.decodeVault(Object.create(Uint8Array.prototype)),
);
add(
  "SDK_ARGUMENT_TYPE",
  "templateHashOfInstance of a number",
  () => sdk.templateHashOfInstance(script01),
  () => sdk.templateHashOfInstance(asBytes(7)),
);
add(
  "SDK_ARGUMENT_TYPE",
  "leg index as a string",
  () => checked("01").instantiateExisting(0),
  () => checked("01").instantiateExisting("0" as unknown as number),
);
add(
  "SDK_ARGUMENT_TYPE",
  "leg index 0.5",
  () => checked("01").instantiateExisting(0),
  () => checked("01").instantiateExisting(0.5),
);

// Boundaries no other case pinned (review round 1: mutants that survived every stage).
const legValues: [string, string, unknown, unknown][] = [
  ["SDK_ARGUMENT_TYPE", "leg 2^53, past the integers JavaScript holds exactly", 0, 2 ** 53],
  ["SDK_ARGUMENT_TYPE", "leg -(2^53)", 0, -(2 ** 53)],
  ["TEMPLATE_LEG_INDEX", "leg 2^53 - 1, an exact integer but no leg", 0, Number.MAX_SAFE_INTEGER],
  ["SDK_ARGUMENT_TYPE", "leg NaN", 0, NaN],
  ["SDK_ARGUMENT_TYPE", "leg Infinity", 1, Infinity],
  ["SDK_ARGUMENT_TYPE", "leg 0n", 0, 0n],
  ["SDK_ARGUMENT_TYPE", "leg null", 0, null],
  ["SDK_ARGUMENT_TYPE", "leg undefined", 0, undefined],
  ["SDK_ARGUMENT_TYPE", "leg a boxed number", 0, new Number(0)],
];
for (const [code, what, good, bad] of legValues) {
  add(code, `instantiateExisting: ${what}`, () => checked("01").instantiateExisting(anyLeg(good)), () =>
    checked("01").instantiateExisting(anyLeg(bad)),
  );
}
const formEdits: [string, (t: any) => void, (t: any) => void][] = [
  [
    "template_suffix_len 2^32 (2^32 - 1 passes the form)",
    (t) => (t.asset_leg.template_suffix_len = 4294967295),
    (t) => (t.asset_leg.template_suffix_len = 4294967296),
  ],
  ["upper-case hex script", (t) => (t.seller_proceeds.script = "ab"), (t) => (t.seller_proceeds.script = "AB")],
  ["network tn10", (t) => (t.network = "testnet"), (t) => (t.network = "tn10")],
  ["network testnet-10", (t) => (t.network = "testnet"), (t) => (t.network = "testnet-10")],
];
for (const [what, good, bad] of formEdits) {
  add("SDK_JSON_FORM", `terms ${what}`, () => sdk.Terms.fromJson(edited("02", good)), () =>
    sdk.Terms.fromJson(edited("02", bad)),
  );
}
add(
  "SDK_JSON_FORM",
  "context network tn10",
  () => checked("08").validateCreation(ctx({ network: "testnet" })),
  () => checked("08").validateCreation(ctx({ network: "tn10" as "testnet" })),
);
add(
  "SDK_ARGUMENT_TYPE",
  "network as a number",
  () => sdk.addressPrefix("mainnet"),
  () => sdk.addressPrefix(0 as unknown as "mainnet"),
);
add(
  "SDK_JSON_FORM",
  "terms nonce as a number",
  () => sdk.Terms.fromJson(edited("02")),
  () => sdk.Terms.fromJson(edited("02", (t) => (t.nonce = 1))),
);
add(
  "SDK_JSON_FORM",
  "terms nonce as a bigint",
  () => sdk.Terms.fromJson(edited("02")),
  () => sdk.Terms.fromJson(edited("02", (t) => (t.nonce = 1n))),
);
add(
  "SDK_JSON_FORM",
  "terms with an unknown key",
  () => sdk.Terms.fromJson(edited("02")),
  () => sdk.Terms.fromJson(edited("02", (t) => (t.memo = "x"))),
);
add(
  "SDK_JSON_FORM",
  "terms without authority_key (null is absent)",
  () => sdk.Terms.fromJson(edited("03", (t) => (t.authority_key = null))),
  () => sdk.Terms.fromJson(edited("03", (t) => delete t.authority_key)),
);
add(
  "SDK_JSON_FORM",
  "upper-case hex key",
  () => sdk.Terms.fromJson(edited("02")),
  () => sdk.Terms.fromJson(edited("02", (t) => (t.seller_key = t.seller_key.toUpperCase()))),
);
add(
  "SDK_JSON_FORM",
  "context creation DAA as a number",
  () => checked("01").validateCreation(ctx()),
  () => checked("01").validateCreation({ network: "mainnet", creation_daa: 400000000 } as unknown as CreationContextJson),
);
add(
  "SDK_JSON_FORM",
  "unknown network name",
  () => sdk.addressPrefix("testnet"),
  () => sdk.addressPrefix("tn10" as unknown as "testnet"),
);
add(
  "SDK_JSON_FORM",
  "terms that are not an object",
  () => sdk.Terms.fromJson(edited("02")),
  () => sdk.Terms.fromJson("terms" as unknown as TermsJson),
);

// JSON-form values that JSON.stringify would rewrite or hide (review round 1). Rust reads the
// JavaScript value itself, so each is refused where it stands, beside the same terms with a JSON
// value in its place. Vector 01 has an authority key and an earliest DAA score; null, the
// accepted control there, makes either absent.
const fromJson = (t: unknown) => sdk.Terms.fromJson(t as TermsJson);
const termsWith = (key: string, value: unknown): unknown => {
  const t: any = edited("01");
  t[key] = value;
  return t;
};
const hostileValues: [string, string, unknown, unknown][] = [
  ["authority_key", "NaN", null, NaN],
  ["authority_key", "Infinity", null, Infinity],
  ["authority_key", "-Infinity", null, -Infinity],
  ["authority_key", "an invalid Date", null, new Date(NaN)],
  ["authority_key", "an object whose toJSON returns null", null, { toJSON: () => null }],
  ["earliest_daa", "NaN", null, NaN],
  ["earliest_daa", "a Date", null, new Date(0)],
  ["seller_key", "an object whose toJSON returns the key", v01.seller_key, { toJSON: () => v01.seller_key }],
  ["seller_key", "a boxed string", v01.seller_key, new String(v01.seller_key)],
  ["nonce", "undefined", v01.nonce, undefined],
  ["version", "-0 (0 passes the form)", 0, -0],
  ["version", "NaN", 1, NaN],
  ["asset_leg", "an array", v01.asset_leg, [v01.asset_leg]],
];
for (const [key, what, good, bad] of hostileValues) {
  add(
    "SDK_JSON_FORM",
    `terms ${key} ${what}`,
    () => fromJson(termsWith(key, good)),
    () => fromJson(termsWith(key, bad)),
  );
}
class TermsObject {
  constructor(t: TermsJson) {
    Object.assign(this, t);
  }
}
const plain = () => edited("01") as unknown;
const hostileObjects: [string, () => unknown, () => unknown][] = [
  ["terms that are a class instance", plain, () => new TermsObject(edited("01"))],
  ["terms that inherit their keys", plain, () => Object.create(edited("01"))],
  [
    "a getter for the nonce",
    plain,
    () => Object.defineProperty(edited("01"), "nonce", { get: () => v01.nonce, enumerable: true }),
  ],
  [
    "a non-enumerable extra key",
    plain,
    () => Object.defineProperty(edited("01"), "memo", { value: "x", enumerable: false }),
  ],
  ["a symbol key", plain, () => Object.assign(edited("01"), { [Symbol("memo")]: "x" })],
  [
    "an own __proto__ key",
    () => JSON.parse(JSON.stringify(edited("01"))),
    () => JSON.parse(`{"__proto__":{},${JSON.stringify(edited("01")).slice(1)}`),
  ],
  [
    "a leg that contains itself",
    plain,
    () => {
      const t: any = edited("01");
      t.asset_leg.self = t.asset_leg;
      return t;
    },
  ],
  [
    "a Proxy whose ownKeys trap throws (a transparent Proxy passes)",
    () => new Proxy(edited("01"), {}),
    () =>
      new Proxy(edited("01"), {
        ownKeys() {
          throw new Error("trap");
        },
      }),
  ],
  [
    "a revoked Proxy",
    () => Proxy.revocable(edited("01"), {}).proxy,
    () => {
      const r = Proxy.revocable(edited("01"), {});
      r.revoke();
      return r.proxy;
    },
  ],
  [
    "a leg with a getter (a leg without a prototype passes)",
    () => ({ ...edited("01"), asset_leg: Object.assign(Object.create(null), v01.asset_leg) }),
    () => ({
      ...edited("01"),
      asset_leg: Object.defineProperty({ ...v01.asset_leg }, "amount", {
        get: () => v01.asset_leg.amount,
        enumerable: true,
      }),
    }),
  ],
];
for (const [what, good, bad] of hostileObjects) {
  add("SDK_JSON_FORM", `terms: ${what}`, () => fromJson(good()), () => fromJson(bad()));
}
const contextWith = (key: string, value: unknown) =>
  ({ ...ctx(), [key]: value }) as unknown as CreationContextJson;
const hostileContexts: [string, CreationContextJson, CreationContextJson][] = [
  ["creation_daa NaN", ctx(), contextWith("creation_daa", NaN)],
  ["max_expiry_horizon_daa undefined (an absent key passes)", ctx(), contextWith("max_expiry_horizon_daa", undefined)],
  ["max_expiry_horizon_daa Infinity", ctx(), contextWith("max_expiry_horizon_daa", Infinity)],
];
for (const [what, good, bad] of hostileContexts) {
  add("SDK_JSON_FORM", `validateCreation: context ${what}`, () => checked("01").validateCreation(good), () =>
    checked("01").validateCreation(bad),
  );
  add("SDK_JSON_FORM", `instantiateForCreation: context ${what}`, () =>
    checked("01").instantiateForCreation(0, good, LIFT), () =>
    checked("01").instantiateForCreation(0, bad, LIFT),
  );
}

// Bounds (review round 1): a JSON-form value holds at most 2^18 characters in all, far above
// the longest legal terms, so a 10,001-byte script still reaches the terms checks.
add(
  "SDK_JSON_FORM",
  "terms: a 131,072-byte script passes no form (10,001 bytes passes the form)",
  () => longScript(10_001),
  () => longScript(1 << 17),
);
add(
  "SDK_JSON_FORM",
  "terms: 65 keys (17 pass the form)",
  () => fromJson(edited("01")),
  () => fromJson(Object.assign(edited("01"), Object.fromEntries([...Array(48)].map((_, i) => [`k${i}`, 1])))),
);

// Funding instructions and the QR code (I11). Vector 02 (mainnet, KCC-20 asset against KAS cash)
// with its cash leg cut to 1 KAS, so that the default cap can be tested on both sides.
// The vector's synthetic token is no kcc20.sil build, which no funding instruction accepts
// (SDK_TEMPLATE_UNPINNED, pinned.test.ts): these cases run on the same terms with the token pinned.
const small02 = () => structure(pinTerms(edited("02", (t) => (t.cash_leg.amount = "100000000"))));
const fundingOptions = (over: object = {}): FundingOptionsJson => ({
  context: ctx(),
  creation_daa_source: "node",
  party: partyFor("seller", edited("02")),
  kas_equivalent: "100000000",
  ...over,
});
const funding = (over: object = {}) => small02().fundingInstructions(fundingOptions(over));
add("SDK_MAINNET_NEEDS_NODE", "fundingInstructions: a typed creation DAA on mainnet", () => funding(), () =>
  funding({ creation_daa_source: "typed" }),
);
add("SDK_VALUE_CAP_INVALID", "fundingInstructions: a cap above the default", () => funding({ cap: "1000000000" }), () =>
  funding({ cap: "1000000001" }),
);
add("SDK_VALUE_CAP_INVALID", "fundingInstructions: a cap that is not a decimal number", () =>
  funding({ cap: "1000000000" }), () => funding({ cap: "1e9" }),
);
add("SDK_VALUE_UNKNOWN", "fundingInstructions: no declared KAS equivalent", () => funding(), () =>
  small02().fundingInstructions({ context: ctx(), creation_daa_source: "node", party: partyFor("seller", edited("02")) }),
);
add("SDK_VALUE_UNKNOWN", "fundingInstructions: a declared KAS equivalent of 0", () => funding(), () =>
  funding({ kas_equivalent: "0" }),
);
add("SDK_VALUE_CAP_EXCEEDED", "fundingInstructions: one sompi above the cap", () =>
  funding({ kas_equivalent: "1000000000" }), () => funding({ kas_equivalent: "1000000001" }),
);
add("SDK_VALUE_CAP_EXCEEDED", "fundingInstructions: a lower cap binds", () => funding({ cap: "100000000" }), () =>
  funding({ cap: "99999999" }),
);
add("SDK_VALUE_CAP_INVALID", "fundingInstructions: a lowered cap together with accept_the_risk", () =>
  funding({ accept_the_risk: true }), () => funding({ cap: "100000000", accept_the_risk: true }),
);
add("SDK_VALUE_CAP_EXCEEDED", "fundingInstructions: a native KAS leg above the cap", () => funding(), () =>
  structure(pinTerms(edited("02", (t) => (t.cash_leg.amount = "1000000001")))).fundingInstructions(fundingOptions()),
);
add("SDK_JSON_FORM", "fundingInstructions: an unknown option", () => funding(), () => funding({ note: "x" }));
add("SDK_JSON_FORM", "fundingInstructions: creation_daa_source other than typed and node", () => funding(), () =>
  funding({ creation_daa_source: "Node" }),
);
add("SDK_JSON_FORM", "fundingInstructions: accept_the_risk as text", () => funding({ accept_the_risk: true }), () =>
  funding({ accept_the_risk: "true" }),
);

// The role check (I11 phase 2): which party the user is, before any funding instruction.
const t02 = () => edited("02");
const evil01 = (edit: (t: any) => void) => structure(edited("01", edit));
const owner = (key: string) => ({ kind: "kcc20", identifier_type: "pubkey", identifier: key });
add("SDK_ROLE_KEY_MISMATCH", "roleCheck: the buyer's key given as the seller's", () => checked("02").roleCheck(partyFor("seller", t02())), () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), key: t02().buyer_key }),
);
add("SDK_ROLE_KEY_MISMATCH", "fundingInstructions: a key of nobody given as the seller's", () => funding(), () =>
  funding({ party: { ...partyFor("seller", t02()), key: "11".repeat(32) } }),
);
add("SDK_DESTINATION_NOT_MINE", "roleCheck: seller_proceeds paying the buyer", () => checked("01").roleCheck(partyFor("seller", edited("01"))), () =>
  evil01((t) => (t.seller_proceeds = owner(t.buyer_key))).roleCheck(partyFor("seller", edited("01"))),
);
add("SDK_DESTINATION_NOT_MINE", "roleCheck: seller_refund paying the authority, even pinned", () => checked("01").roleCheck(partyFor("seller", edited("01"))), () => {
  const evil = edited("01", (t) => (t.seller_refund = owner(t.authority_key as string)));
  return structure(evil).roleCheck(partyFor("seller", evil));
});
add("SDK_DESTINATION_NOT_MINE", "fundingInstructions: a script destination without a pin", () => funding(), () =>
  small02().fundingInstructions({ ...fundingOptions(), party: { role: "buyer", key: t02().buyer_key } }),
);
add("SDK_DESTINATION_PIN_INVALID", "roleCheck: a pin that is not a destination", () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), pins: { refund: pinOf("mainnet", t02().seller_refund), receive: pinOf("mainnet", t02().seller_proceeds) } }), () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), pins: { receive: "kaspa:not-an-address" } }),
);
add("SDK_DESTINATION_PIN_INVALID", "roleCheck: a pin of another network", () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), pins: { receive: pinOf("mainnet", t02().seller_proceeds) } }), () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), pins: { receive: pinOf("testnet", t02().seller_proceeds) } }),
);
add("SDK_JSON_FORM", "roleCheck: a role other than buyer and seller", () => checked("02").roleCheck(partyFor("seller", t02())), () =>
  checked("02").roleCheck({ ...partyFor("seller", t02()), role: "authority" as "seller" }),
);
add("SDK_JSON_FORM", "fundingInstructions: no party", () => funding(), () => {
  const { party: _party, ...rest } = fundingOptions();
  return small02().fundingInstructions(rest as unknown as FundingOptionsJson);
});
add("SDK_ARGUMENT_TYPE", "kasFromSompi: a number", () => sdk.kasFromSompi("1"), () =>
  sdk.kasFromSompi(1 as unknown as string),
);
add("SDK_ARGUMENT_TYPE", "kasFromSompi: a decimal point", () => sdk.kasFromSompi("1"), () => sdk.kasFromSompi("1.5"));
add("SDK_ARGUMENT_TYPE", "kasFromSompi: a leading zero", () => sdk.kasFromSompi("10"), () => sdk.kasFromSompi("010"));
add("SDK_ARGUMENT_TYPE", "qrCode: a number", () => sdk.qrCode("kaspa:"), () => sdk.qrCode(5 as unknown as string));
add("SDK_QR", "qrCode: 2,331 bytes fit (level M), 2,332 do not", () => sdk.qrCode("x".repeat(2331)), () =>
  sdk.qrCode("x".repeat(2332)),
);
add("SDK_QR", "qrCode: a text past the length bound is refused before it is copied", () =>
  sdk.qrCode("x".repeat(2331)), () => sdk.qrCode("x".repeat(5000)),
);

// Terms documents read from text, and terms read back from a form (I11 review round 1). The
// accepted control is the vector file as it is committed.
const vectorText = (prefix: string) => readFileSync(new URL(`tests/vectors/terms/${termsVector(prefix).name}.json`, root), "utf8");
const fromText = (text: string) => sdk.Terms.fromFileText(text);
/** `text` with the first `from` replaced; the layout of the committed file is asserted. */
const swapped = (text: string, from: string, to: string) => {
  assert.ok(text.includes(from), `layout: ${from}`);
  return text.replace(from, to);
};
const fileWith = (edit: (doc: any) => void, prefix = "08") => {
  const doc = JSON.parse(vectorText(prefix));
  edit(doc);
  return JSON.stringify(doc);
};
add("SDK_TERMS_INCONSISTENT", "fromFileText: terms_hash of another trade", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.terms_hash = "11".repeat(32)))),
);
add("SDK_TERMS_INCONSISTENT", "fromFileText: canonical of another encoding", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.canonical = "00"))),
);
add("SDK_TERMS_INCONSISTENT", "fromFileText: terms changed under their own canonical and hash", () =>
  fromText(vectorText("08")), () => fromText(fileWith((d) => (d.terms.nonce = "7989634765647131681"))),
);
add("SDK_TERMS_INCONSISTENT", "requireSameAs: another nonce", () => {
  const a = sdk.Terms.fromJson(edited("08"));
  a.requireSameAs(sdk.Terms.fromJson(edited("08")));
}, () => {
  const a = sdk.Terms.fromJson(edited("08"));
  a.requireSameAs(sdk.Terms.fromJson(edited("08", (t) => (t.nonce = "7989634765647131681"))));
});
add("SDK_JSON_FORM", "fromFileText: a u64 as a JSON number", () => fromText(vectorText("08")), () =>
  fromText(swapped(vectorText("08"), '"amount": "100000000"', '"amount": 100000000')),
);
add("SDK_JSON_FORM", "fromFileText: a nonce past 2^53 as a JSON number", () => fromText(vectorText("08")), () =>
  fromText(swapped(vectorText("08"), '"7989634765647131680"', "7989634765647131680")),
);
add("SDK_JSON_FORM", "fromFileText: an unknown top-level key", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.memo = "x"))),
);
add("SDK_JSON_FORM", "fromFileText: an unknown key in the terms", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.terms.memo = "x"))),
);
add("SDK_JSON_FORM", "fromFileText: a stray key in a leg", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.terms.cash_leg.covenant_id = "00".repeat(32)))),
);
add("SDK_JSON_FORM", "fromFileText: terms_hash missing", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => delete d.terms_hash)),
);
add("SDK_JSON_FORM", "fromFileText: terms_hash in capitals", () => fromText(vectorText("08")), () =>
  fromText(fileWith((d) => (d.terms_hash = d.terms_hash.toUpperCase()))),
);
add("SDK_JSON_FORM", "fromFileText: a key named twice, which JSON.parse would let pass", () => fromText(vectorText("08")), () =>
  fromText(swapped(vectorText("08"), '"name"', '"canonical": "00", "name"')),
);
add("SDK_JSON_FORM", "fromFileText: a key named twice inside a leg", () => fromText(vectorText("08")), () =>
  fromText(swapped(vectorText("08"), '"kind": "kas"', '"kind": "kas", "kind": "kas"')),
);
add("SDK_JSON_FORM", "fromFileText: not JSON", () => fromText(vectorText("08")), () => fromText("{not json"));
add("SDK_JSON_FORM", "fromFileText: an array", () => fromText(vectorText("08")), () => fromText("[]"));
add("SDK_JSON_FORM", "fromFileText: a text past the length bound is refused before it is copied", () =>
  fromText(vectorText("08")), () => fromText(" ".repeat(1 << 20) + vectorText("08")),
);
add("SDK_ARGUMENT_TYPE", "fromFileText: an object", () => fromText(vectorText("08")), () =>
  sdk.Terms.fromFileText(JSON.parse(vectorText("08")) as unknown as string),
);

test("a refusal cuts the caller's string it echoes, and never copies one past the bounds", () => {
  const mem = memory();
  // Copying a string longer than the whole memory would have to grow it by more than 1 MiB.
  const huge = () => "y".repeat(mem.buffer.byteLength + (1 << 20));
  const oversized: [string, (s: string) => unknown][] = [
    ["addressPrefix", (s) => sdk.addressPrefix(s as "mainnet")],
    ["terms network", (s) => fromJson(termsWith("network", s))],
    ["terms seller_key", (s) => fromJson(termsWith("seller_key", s))],
    ["terms unknown key", (s) => fromJson({ ...edited("01"), [s]: 1 })],
    ["context network", (s) => checked("01").validateCreation(contextWith("network", s))],
  ];
  for (const [what, f] of oversized) {
    const s = huge();
    const before = mem.buffer.byteLength;
    const e = refusalError(() => f(s));
    assert.equal(e.code, "SDK_JSON_FORM", what);
    assert.ok(e.message.length < 200, `${what}: a message of ${e.message.length} characters`);
    assert.ok(mem.buffer.byteLength - before < 1 << 20, `${what}: memory grew`);
  }
  // Within the bounds, an echoed string is cut to 32 characters, quoted values with "..." after
  // the closing quote; a short one is shown whole.
  const y40 = "y".repeat(40);
  for (const f of [
    () => sdk.addressPrefix(y40 as "mainnet"),
    () => fromJson(termsWith("network", y40)),
    () => fromJson({ ...edited("01"), [y40]: 1 }),
  ]) {
    const e = refusalError(f);
    assert.match(e.message, /(^|[^y])y{32}"?\.\.\./);
    assert.ok(!e.message.includes("y".repeat(33)), e.message);
  }
  assert.match(refusalError(() => sdk.addressPrefix("tn10" as "mainnet")).message, /"tn10" is not one of/);
  assert.match(
    refusalError(() => fromJson(Object.assign(edited("01"), Object.fromEntries([...Array(48)].map((_, i) => [`k${i}`, 1]))))).message,
    /more than 64 keys/,
  );
});

test("bytes are read through their own length, whatever a subclass's length getter says", () => {
  // Review round 1: to_vec trusted the getter, so Long hashed stale module memory after the
  // input and Short wrote past its copy. Buffer is the subclass Node callers pass.
  class Long extends Uint8Array {}
  Object.defineProperty(Long.prototype, "length", { get: () => 150_000 });
  class Short extends Uint8Array {}
  Object.defineProperty(Short.prototype, "length", { get: () => 1 });
  // Leaves 150,000 bytes of 0xaa in freed module memory (under the 200,000 byte bound).
  assert.equal(refusal(() => sdk.Terms.decode(new Uint8Array(150_000).fill(0xaa))), "TERMS_UNSUPPORTED_VERSION");
  const makers: [string, (b: Uint8Array) => Uint8Array, number | undefined][] = [
    ["Long", (b) => new Long(b), 150_000],
    ["Short", (b) => new Short(b), 1],
    ["Buffer", (b) => Buffer.from(b), undefined],
  ];
  for (const [name, make, lie] of makers) {
    const c = make(c02);
    const s = make(script01);
    assert.equal(c.length, lie ?? c02.length, `${name}: its length getter`);
    assert.equal(hex(sdk.Terms.decode(c).encode()), hex(c02));
    assert.equal(hex(sdk.ValidatedTerms.decode(c).canonical()), hex(c02));
    assert.equal(hex(sdk.templateHashOfInstance(s)), templateHashFile.trim());
    assert.equal(hex(sdk.decodeVault(s).terms().canonical()), termsVector("01").canonical);
  }
});

test("leg -0 is the asset leg, as -0 === 0 in JavaScript", () => {
  // A leg index is a number argument, not JSON text, so -0 (an integer, Number.isInteger(-0))
  // is 0. The JSON form refuses -0 instead, as serde_json refuses the text -0 for a u8.
  const v = checked("01");
  assert.equal(hex(v.instantiateExisting(-0).redeemScript()), hex(v.instantiateExisting(0).redeemScript()));
  assert.equal(v.instantiateForCreation(-0, ctx(), LIFT).address(), v.instantiateForCreation(0, ctx(), LIFT).address());
});

test("the vault vector 05 cash leg and v05 keep their external-cash shape", () => {
  // Guards the TEMPLATE_NO_VAULT and TERMS_EXTERNAL_WITHOUT_AUTHORITY cases above.
  assert.equal(v05.cash_leg.kind, "external");
  assert.notEqual(v05.authority_key, null);
  assert.equal(vaultVector("05").cash_vault.refused, "TEMPLATE_NO_VAULT");
});

// The wallet, the node and the plan (I11 phase 2). The longer flows are in wallet.test.ts,
// plan.test.ts and session.test.ts; each code has its case here beside a control.
// Mainnet, where the destinations pay a cold key the seller pins: a key that lives only in a
// wallet is refused there (SDK_DESTINATION_IN_WALLET, below).
const direct = world(sdk, MODES.directKas, "mainnet", true);
const directReply = utxosFrame(1, direct.pool, addressFor(direct.network));
const directFunding = { payer: direct.wallets.payer.publicKey(), fee: "auto" };
const directIpst = direct.terms.directFromReply(direct.artifacts, directReply, directFunding, NOW.toString(), VALUE);
const testnetDirect = world(sdk, MODES.directKas, "testnet");
const testnetIpst = testnetDirect.terms.directFromReply(
  testnetDirect.artifacts,
  utxosFrame(1, testnetDirect.pool, addressFor("testnet")),
  { payer: testnetDirect.wallets.payer.publicKey(), fee: "auto" },
  NOW.toString(),
  VALUE,
);
const signOptions = (w: typeof direct, over: object = {}) => ({
  artifacts: w.artifacts,
  current_daa: NOW.toString(),
  value: VALUE,
  mainnet: w.network === "mainnet",
  ...(w === direct ? { pins: pinsFor(direct, "seller") } : {}),
  ...over,
});
const spare = sdk.Wallet.generate();
spare.wipe();
add(
  "SDK_WALLET_WIPED",
  "a wallet signs, then a wiped wallet is asked to",
  () => direct.wallets.seller.sign(directIpst, signOptions(direct)),
  () => spare.sign(directIpst, signOptions(direct)),
);
add(
  "SDK_WALLET_RANDOM",
  "a wallet is generated, then the browser's randomness fails",
  () => sdk.Wallet.generate().free(),
  () => {
    const crypto = globalThis.crypto;
    const real = crypto.getRandomValues.bind(crypto);
    Object.defineProperty(crypto, "getRandomValues", {
      configurable: true,
      writable: true,
      value: () => {
        throw new Error("no randomness");
      },
    });
    try {
      return sdk.Wallet.generate();
    } finally {
      Object.defineProperty(crypto, "getRandomValues", { configurable: true, writable: true, value: real });
    }
  },
);
add(
  "SDK_SIGN_MAINNET_NOT_EXPLICIT",
  "mainnet terms signed with the mainnet choice, then without",
  () => direct.wallets.seller.sign(directIpst, signOptions(direct)),
  () => direct.wallets.seller.sign(directIpst, signOptions(direct, { mainnet: false })),
);
add(
  "SDK_SIGN_NETWORK_MISMATCH",
  "testnet terms signed without the mainnet choice, then with",
  () => testnetDirect.wallets.seller.sign(testnetIpst, signOptions(testnetDirect)),
  () => testnetDirect.wallets.seller.sign(testnetIpst, signOptions(testnetDirect, { mainnet: true })),
);
add(
  "SDK_SIGN_NOTHING_TO_SIGN",
  "the seller's wallet signs a Direct trade, then the authority's, which signs none of it",
  () => direct.wallets.seller.sign(directIpst, signOptions(direct)),
  () => direct.wallets.authority.sign(directIpst, signOptions(direct)),
);
const info = (over: object = {}): ServerInfoJson => ({
  network_id: "testnet-10",
  network: "testnet",
  is_synced: true,
  has_utxo_index: true,
  virtual_daa_score: "1500000",
  ...over,
});
add(
  "SDK_NODE_URL_INVALID",
  "a ws URL, then an http URL",
  () => sdk.checkNodeUrl("ws://127.0.0.1:18210", "testnet"),
  () => sdk.checkNodeUrl("http://127.0.0.1:18210", "testnet"),
);
add(
  "SDK_NODE_INSECURE",
  "plaintext to another machine on testnet, then on mainnet",
  () => sdk.checkNodeUrl("ws://203.0.113.9:17110", "testnet"),
  () => sdk.checkNodeUrl("ws://203.0.113.9:17110", "mainnet"),
);
add(
  "SDK_NODE_INSECURE",
  "plaintext to 127.0.0.1 on mainnet, then to the IPv6 loopback literal",
  () => sdk.checkNodeUrl("ws://127.0.0.1:17110", "mainnet"),
  () => sdk.checkNodeUrl("ws://[::1]:17110", "mainnet"),
);
add(
  "SDK_NODE_NETWORK_MISMATCH",
  "a testnet node for testnet, then for mainnet",
  () => sdk.checkNode(info(), "testnet"),
  () => sdk.checkNode(info(), "mainnet"),
);
add(
  "SDK_NODE_NOT_SYNCED",
  "a synced node, then one that is not",
  () => sdk.checkNode(info(), "testnet"),
  () => sdk.checkNode(info({ is_synced: false }), "testnet"),
);
const dagFrame = JSON.stringify({
  id: 4,
  method: "getBlockDagInfo",
  params: { virtualDaaScore: 1_500_000, sink: "ab".repeat(32) },
});
add(
  "SDK_RPC_REPLY",
  "a node's answer, then its error",
  () => sdk.rpcReply(dagFrame, 4, "getBlockDagInfo"),
  () => sdk.rpcReply(JSON.stringify({ id: 4, error: { code: -32000, message: "no" } }), 4, "getBlockDagInfo"),
);
const directTx = [testnetDirect.wallets.seller, testnetDirect.wallets.buyer, testnetDirect.wallets.payer]
  .reduce((doc, wallet) => wallet.sign(doc, signOptions(testnetDirect)).ipst, testnetIpst)
  .finalize();
const submitFrame = (id: string) => JSON.stringify({ id: 9, method: "submitTransaction", params: { transactionId: id } });
add(
  "SDK_TXID_MISMATCH",
  "the node names the transaction submitted, then another",
  () => sdk.rpcSubmitReply(submitFrame(hex(directTx.txid())), 9, directTx),
  () => sdk.rpcSubmitReply(submitFrame("ab".repeat(32)), 9, directTx),
);
const vault = world(sdk, MODES.vaultKas);
const vaultSettle = (pool: typeof vault.pool) =>
  vault.terms.settleFromReply(
    vault.artifacts,
    utxosFrame(1, pool, addressFor(vault.network)),
    { payer: vault.wallets.payer.publicKey(), fee: "auto" },
    NOW.toString(),
    VALUE,
  );
add(
  "SDK_UTXO_NOT_FOUND",
  "a settle over the funded vaults, then without the asset escrow",
  () => vaultSettle(vault.pool),
  () => vaultSettle(vault.pool.filter((u) => u.covenant_id === null)),
);

// The payer's side of signing, the held keys and the node's "not found" (review round 2).
const idOf = (label: string) => createHash("sha256").update(label).digest("hex");
const holding = (pool: FakeUtxo[], label: string, amount: bigint): FakeUtxo[] =>
  pool.map((u) => (u.transaction_id === idOf(label) ? { ...u, amount: amount.toString() } : u));
const vaultOptions = signOptions(vault);
const settleWith = (pool: FakeUtxo[], funding: object = {}) =>
  vault.terms.settleFromReply(
    vault.artifacts,
    utxosFrame(1, pool, addressFor(vault.network)),
    { payer: vault.wallets.payer.publicKey(), fee: "auto", ...funding },
    NOW.toString(),
    VALUE,
  );
add(
  "SDK_SIGN_TOPUP_TOO_HIGH",
  "the fee payer signs a settle over funded vaults, then one whose asset authorizer holds 1 sompi",
  () => vault.wallets.payer.sign(settleWith(vault.pool), vaultOptions),
  () => vault.wallets.payer.sign(settleWith(holding(vault.pool, "asset-authorizer", 1n)), vaultOptions),
);
const elsewhere = sdk.Wallet.generate();
add(
  "SDK_SIGN_CHANGE_NOT_MINE",
  "the fee payer signs a settle whose change comes back to it, then one whose change goes elsewhere",
  () => vault.wallets.payer.sign(settleWith(vault.pool), vaultOptions),
  () => vault.wallets.payer.sign(settleWith(vault.pool, { change: elsewhere.address(vault.network) }), vaultOptions),
);
add(
  "SDK_SIGN_FEE_TOO_HIGH",
  "the fee payer signs a settle at the automatic fee, then at ten times the minimum",
  () => vault.wallets.payer.sign(settleWith(vault.pool), vaultOptions),
  () => vault.wallets.payer.sign(settleWith(vault.pool, { fee: "20000000" }), vaultOptions),
);
const carrying = (kas: bigint) =>
  testnetDirect.terms.directFromReply(
    testnetDirect.artifacts,
    utxosFrame(1, holding(testnetDirect.pool, "seller-token", kas), addressFor("testnet")),
    { payer: testnetDirect.wallets.payer.publicKey(), fee: "auto" },
    NOW.toString(),
    VALUE,
  );
add(
  "SDK_SIGN_OUTFLOW_TOO_HIGH",
  "the seller signs a Direct trade whose token carries the carrier, then one that carries 3 KAS",
  () => testnetDirect.wallets.seller.sign(carrying(200_000_000n), signOptions(testnetDirect)),
  () => testnetDirect.wallets.seller.sign(carrying(300_000_000n), signOptions(testnetDirect)),
);
const walletDestinations = world(sdk, MODES.directKas, "mainnet");
const sellerParty = (held: string[]) => ({ role: "seller" as const, key: walletDestinations.wallets.seller.publicKey(), held });
add(
  "SDK_DESTINATION_IN_WALLET",
  "mainnet terms whose seller destinations pay the seller's key, checked with no key held, then with that key held in a wallet",
  () => walletDestinations.terms.roleCheck(sellerParty([])),
  () => walletDestinations.terms.roleCheck(sellerParty([walletDestinations.wallets.seller.publicKey()])),
);
// The node's own "not found" for a transaction it does not hold, beside the transaction it does.
const mempool = new FakeNode(sdk, addressFor(vault.network), vault.network);
mempool.autoAccept = false;
mempool.virtualDaa = Number(NOW);
for (const u of vault.pool) mempool.add(u);
const pending = [vault.wallets.authority, vault.wallets.payer]
  .reduce((doc, wallet) => wallet.sign(doc, vaultOptions).ipst, settleWith(vault.pool))
  .finalize();
mempool.handle(sdk.rpcSubmitRequest(1, pending));
const mempoolReply = (txid: string) =>
  sdk.rpcTransactionReply(mempool.handle(sdk.rpcRequest(2, "getMempoolEntry", txid)), 2, "getMempoolEntry", txid);
add(
  "SDK_RPC_NOT_FOUND",
  "the node is asked for a transaction in its mempool, then for one it does not hold",
  () => mempoolReply(hex(pending.txid())),
  () => mempoolReply("ab".repeat(32)),
);

// The buyer funds the cash leg; nobody else does; only a pinned kcc20.sil token is funded; and only
// once the seller's asset leg is on the node, and once.
const buyerCoins = utxo("buyer-coins", 300_000_000n, p2pk(vault.wallets.buyer.publicKey())) as FakeUtxo;
const sellerCoins = utxo("seller-coins", 300_000_000n, p2pk(vault.wallets.seller.publicKey())) as FakeUtxo;
const inVault = (label: string) =>
  vault.pool.find((u) => u.transaction_id === createHash("sha256").update(label).digest("hex")) as FakeUtxo;
/** What the seller's funding of the asset leg left on the node. */
const assetLeg = [inVault("asset-authorizer"), inVault("asset-escrow")];
const fundCash = (
  payer: string,
  pool: FakeUtxo[] = [...assetLeg, buyerCoins, sellerCoins],
  terms = vault.terms,
  artifacts = vault.artifacts,
) =>
  terms.fundCashFromReply(
    artifacts,
    utxosFrame(1, pool, addressFor(vault.network)),
    { payer, fee: "auto" },
    NOW.toString(),
    VALUE,
  );
add(
  "SDK_FUND_NOT_YOUR_LEG",
  "the buyer funds the cash leg, then the seller's key",
  () => fundCash(vault.wallets.buyer.publicKey()),
  () => fundCash(vault.wallets.seller.publicKey()),
);
add(
  "SDK_FUND_ASSET_NOT_FUNDED",
  "the cash leg is funded with the seller's asset leg on the node, then with only the buyer's coins",
  () => fundCash(vault.wallets.buyer.publicKey()),
  () => fundCash(vault.wallets.buyer.publicKey(), [buyerCoins]),
);
add(
  "SDK_FUND_ALREADY_FUNDED",
  "the cash leg is funded with the cash vault empty, then with the exact deposit already in it",
  () => fundCash(vault.wallets.buyer.publicKey()),
  () => fundCash(vault.wallets.buyer.publicKey(), [...assetLeg, buyerCoins, inVault("cash-vault")]),
);
const unpinnedJson = { ...vault.json, asset_leg: tokenLeg(sdk, unpinnedToken(), ASSET_COV, AMOUNT_A) };
add(
  "SDK_TEMPLATE_UNPINNED",
  "the cash leg is funded for a pinned kcc20.sil token, then for a token one suffix byte longer",
  () => fundCash(vault.wallets.buyer.publicKey()),
  () =>
    fundCash(
      vault.wallets.buyer.publicKey(),
      [...assetLeg, buyerCoins],
      validated(sdk, unpinnedJson),
      { asset: unpinnedToken(), cash: null },
    ),
);

// The signer of a KCC-20 funding confirms the deposit.
{
  const seller = vault.wallets.seller;
  const tokens = [ownToken(sdk, "dep-token", ASSET_ARTIFACT, ASSET_COV, seller.publicKey(), AMOUNT_A)];
  const deposit = (carrier: bigint) =>
    vault.terms.fundKcc20(
      0,
      { network: vault.network, creation_daa: (NOW - 1n).toString() },
      { artifact: ASSET_ARTIFACT, tokens, carrier: carrier.toString(), authorizer: AUTHORIZER.toString() },
      { inputs: [utxo("dep-fee", 1_000_000_000n, p2pk(seller.publicKey()))], fee: "1000000", change: p2pk(seller.publicKey()) },
      VALUE,
    );
  add(
    "SDK_SIGN_DEPOSIT_MISMATCH",
    "the seller signs a KCC-20 funding that puts the minimum carrier on the token, then one that puts 3 KAS",
    () => seller.sign(deposit(200_000_000n), vaultOptions),
    () => seller.sign(deposit(300_000_000n), vaultOptions),
  );
}

// A code whose refusal cannot be reached from the package: the signature a wallet made is
// checked before it leaves the wallet, and a wallet that signs correctly has no input that makes
// it fail. impulse-wasm's native tests drive it with a hook that exists only in test builds
// (wallet.rs, `the_self_check_refuses_a_signature_that_does_not_verify`).
const NATIVE_ONLY = ["SDK_SIGN_SELF_CHECK_FAILED"];

// Every case added above, one test each. (This loop sits after the last `add`: a case added after
// a loop that ran earlier was recorded for the coverage test below and never run.)
for (const c of cases) {
  test(`${c.code}: ${c.what}`, () => {
    c.accept();
    assert.equal(refusal(c.refuse), c.code);
  });
}

test("every stable code has a refusal case beside an accepted control", () => {
  // The value cap codes have their cases here for fundingInstructions, and with the builders in
  // tx-refusals.test.ts and value.test.ts.
  const all = [...sdk.termsErrorCodes(), ...sdk.templateErrorCodes(), ...sdk.sdkErrorCodes()];
  assert.equal(new Set(all).size, all.length, "codes are unique");
  const covered = [...new Set([...cases.map((c) => c.code), ...NATIVE_ONLY])].sort();
  assert.deepEqual(covered, [...all].sort());
  assert.ok(NATIVE_ONLY.every((code) => !cases.some((c) => c.code === code)), "native-only means no case here");
});
