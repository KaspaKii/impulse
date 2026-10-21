// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Writes the page's examples, demo/dist/examples, from the golden terms vectors (build.sh runs it).
//
// The golden vectors name a synthetic token (template a227fc3a, 40+1420) that is no kcc20.sil
// build, and no funding is ever given for such a token: the SDK refuses it with
// SDK_TEMPLATE_UNPINNED, as `impulse address` and `fund build` refuse it with CLI_TEMPLATE_UNPINNED
// (spec/CLI.md, "Before funding"). So the examples the page offers are the vectors with the
// template of each KCC-20 leg replaced by the first pinned build the SDK lists
// (`pinnedKcc20Templates()`), and the canonical bytes and the terms hash written again by the SDK.
// They are different trades, with hashes of their own; the vectors themselves, byte for byte, are
// what the SDK's own tests check against (crates/impulse-wasm/npm/test/vectors.test.ts). The file
// says so in its description. Nothing else in a vector is touched.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");
const vectors = join(here, "..", "tests", "vectors", "terms");

const hex = (bytes) => Buffer.from(bytes).toString("hex");

const sdk = await import(pathToFileURL(join(dist, "sdk", "index.js")).href);
sdk.initSync({ module: readFileSync(join(dist, "sdk", "pkg", "impulse_wasm_bg.wasm")) });
const pin = sdk.pinnedKcc20Templates()[0];

const names = readdirSync(vectors)
  .filter((f) => f.endsWith(".json"))
  .sort();
if (names.length === 0) {
  console.error("demo: FAIL: no golden vectors to list");
  process.exit(1);
}
mkdirSync(join(dist, "examples"), { recursive: true });
for (const name of names) {
  const vector = JSON.parse(readFileSync(join(vectors, name), "utf8"));
  const terms = structuredClone(vector.terms);
  for (const leg of [terms.asset_leg, terms.cash_leg]) {
    if (leg.kind === "kcc20") {
      leg.template_hash = pin.template_hash;
      leg.template_prefix_len = pin.template_prefix_len;
      leg.template_suffix_len = pin.template_suffix_len;
    }
  }
  const parsed = sdk.Terms.fromJson(terms);
  const example = {
    name: vector.name,
    description: `${vector.description} Page example: the golden vector with each KCC-20 token's template replaced by the first pinned kcc20.sil build, because no funding is given for the vector's synthetic token.`,
    terms,
    canonical: hex(parsed.encode()),
    terms_hash: hex(parsed.termsHash()),
  };
  parsed.free();
  writeFileSync(join(dist, "examples", name), `${JSON.stringify(example, null, 2)}\n`);
}
writeFileSync(join(dist, "examples", "index.json"), `${JSON.stringify(names)}\n`);
