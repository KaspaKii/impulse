// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Golden vectors through the published package: every file under tests/vectors/ must come out of
// the SDK byte for byte as impulse-core wrote it (JSON form, canonical encoding, terms hash,
// redeem scripts, script hashes, scriptPubKeys, addresses, decoding).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  hex,
  load,
  refusal,
  root,
  templateHashFile,
  termsVectors,
  unhex,
  vaultVectors,
  vectorFiles,
} from "./sdk.ts";
import type { CreationContextJson, Vault } from "../index.js";
import { LIFT } from "./fixtures.ts";

const sdk = load();

// spec/ENCODING.md: every vector passes both validation stages at creation DAA score 400,000,000.
const CREATION_DAA = "400000000";

// The vector files this suite covers, by SHA-256 (review round 1). Any change to a vector file,
// even one the SDK does not read, fails here as well as in scripts/vectors.sh. After an
// increment adds vectors: `cd tests/vectors && shasum -a 256 terms/* vaults/* ipst/*`, then cover
// them below.
test("vector files: exactly the ones this suite was written against", () => {
  const manifest = readFileSync(new URL("vectors.sha256", import.meta.url), "utf8");
  const files = (["terms", "vaults", "ipst"] as const).flatMap((set) => vectorFiles(set).map((f) => `${set}/${f}`));
  const lines = files.map((f) => {
    const digest = createHash("sha256").update(readFileSync(new URL(`tests/vectors/${f}`, root))).digest("hex");
    return `${digest}  ${f}\n`;
  });
  assert.equal(lines.join(""), manifest);
});

test("the vector sets are complete and correspond one to one", () => {
  // I2 and I4: eleven terms vectors and a vault file for each.
  assert.deepEqual(
    termsVectors.map((v) => `${v.name}.json`),
    vectorFiles("terms"),
    "every terms file is a vector named after its file",
  );
  assert.deepEqual(
    vaultVectors.map((v) => `${v.name}.json`),
    vectorFiles("vaults"),
    "every vault file is a vector named after its file",
  );
  assert.equal(termsVectors.length, 11);
  assert.deepEqual(
    vaultVectors.map((v) => v.name),
    termsVectors.map((v) => v.name),
  );
});

test("terms vectors: JSON form, canonical bytes and terms hash match byte for byte", () => {
  for (const v of termsVectors) {
    const committed = JSON.stringify(v.terms);

    const terms = sdk.Terms.fromJson(v.terms);
    assert.equal(hex(terms.encode()), v.canonical, `${v.name}: encode`);
    // Key order is not significant on input; toJson writes field order.
    const reversed = (o: object): object =>
      Object.fromEntries(
        Object.entries(o)
          .reverse()
          .map(([k, x]) => [k, x !== null && typeof x === "object" ? reversed(x) : x]),
      );
    const shuffled = sdk.Terms.fromJson(reversed(v.terms) as typeof v.terms);
    assert.equal(hex(shuffled.encode()), v.canonical, `${v.name}: keys in reverse order`);
    assert.equal(JSON.stringify(shuffled.toJson()), committed, `${v.name}: rendered in field order`);
    assert.equal(hex(terms.termsHash()), v.terms_hash, `${v.name}: terms hash`);
    assert.equal(JSON.stringify(terms.toJson()), committed, `${v.name}: JSON form`);

    const decoded = sdk.Terms.decode(unhex(v.canonical));
    assert.equal(JSON.stringify(decoded.toJson()), committed, `${v.name}: decode`);
    assert.equal(hex(decoded.encode()), v.canonical, `${v.name}: re-encode`);

    const checked = decoded.validateStructure();
    assert.equal(hex(checked.canonical()), v.canonical, `${v.name}: validated bytes`);
    assert.equal(hex(checked.termsHash()), v.terms_hash, `${v.name}: validated hash`);
    assert.equal(JSON.stringify(checked.terms().toJson()), committed);
    checked.validateCreation({ network: v.terms.network, creation_daa: CREATION_DAA });

    const again = sdk.ValidatedTerms.decode(unhex(v.canonical));
    assert.equal(hex(again.termsHash()), v.terms_hash, `${v.name}: ValidatedTerms.decode`);
  }
});

test("vault vectors: scripts, hashes, scriptPubKeys, addresses and decoding match byte for byte", () => {
  const pinned = templateHashFile.trim();
  assert.equal(hex(sdk.templateCheck().hash()), pinned, "the startup check passes on TEMPLATE_HASH");
  let vaults = 0;
  let refusals = 0;
  for (const v of vaultVectors) {
    const t = termsVectors.find((x) => x.name === v.name);
    assert.ok(t, v.name);
    assert.equal(v.terms_hash, t.terms_hash, v.name);
    assert.equal(v.template_hash, pinned, v.name);
    const checked = sdk.Terms.fromJson(t.terms).validateStructure();
    const ctx: CreationContextJson = { network: t.terms.network, creation_daa: CREATION_DAA };
    const legs: [string, typeof v.asset_vault, number][] = [
      ["asset_vault", v.asset_vault, 0],
      ["cash_vault", v.cash_vault, 1],
    ];
    for (const [key, want, leg] of legs) {
      const where = `${v.name} ${key}`;
      assert.equal(want.leg_index, leg, where);
      if (want.refused !== undefined) {
        assert.equal(refusal(() => checked.instantiateExisting(leg)), want.refused, where);
        assert.equal(refusal(() => checked.instantiateForCreation(leg, ctx, LIFT)), want.refused, where);
        refusals += 1;
        continue;
      }
      const fundable = checked.instantiateForCreation(leg, ctx, LIFT);
      const both: Vault[] = [checked.instantiateExisting(leg), fundable.vault()];
      for (const vault of both) {
        assert.equal(hex(vault.redeemScript()), want.redeem_script, `${where}: redeem script`);
        assert.equal(hex(vault.scriptHash()), want.script_hash, `${where}: script hash`);
        assert.equal(vault.leg(), leg, where);
        assert.equal(vault.network(), t.terms.network, where);
        // spec/TEMPLATE.md: version 0, OpBlake2b OpData32 <script hash> OpEqual.
        const spk = vault.scriptPublicKey();
        assert.equal(spk.version, 0, where);
        assert.equal(hex(spk.script), `aa20${want.script_hash}87`, `${where}: scriptPubKey`);
      }
      assert.equal(fundable.address(), want.address, `${where}: address`);
      assert.ok(fundable.address().startsWith(`${sdk.addressPrefix(t.terms.network)}:p`), where);

      const script = unhex(want.redeem_script ?? "");
      const decoded = sdk.decodeVault(script);
      assert.equal(hex(decoded.terms().canonical()), t.canonical, `${where}: decode`);
      assert.equal(decoded.leg(), leg, `${where}: decoded leg`);
      assert.equal(hex(sdk.templateHashOfInstance(script)), pinned, `${where}: template hash`);
      vaults += 1;
    }
  }
  // I4: 16 vaults and 6 legs without one (2 external-cash cash legs, both legs of 2 Direct).
  assert.equal(vaults, 16, "vaults");
  assert.equal(refusals, 6, "legs without a vault");
});
