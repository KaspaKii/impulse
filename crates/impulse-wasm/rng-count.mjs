// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Counts the calls the wasm module makes to the randomness imports of its glue (getRandomValues
// and randomFillSync, linked through getrandom; see wasm-imports.txt). ci.sh preloads this into
// the TypeScript suite (`node --import`, through NODE_OPTIONS, so it reaches the process of every
// test file). The module draws randomness for one thing, the key of `Wallet.generate`; the tests
// count the keys they ask for in globalThis.__rngExpected (test/sdk.ts, `load`), and ci.sh
// requires every process to report as many calls as keys asked for, and some process to have
// asked for one.
//
// Method: when a WebAssembly instance is made, every import of the "wbg" namespace whose name
// contains getRandomValues or randomFillSync is wrapped to count its calls, and the count of the
// process is appended to $RNG_COUNT_FILE at exit as "<calls> control=<n> wrapped=<names>".
// A positive control runs first in every process: a hand-assembled module that imports a function
// with such a name and calls it once must count exactly 1, else the process exits with 97.
//
// It sees only calls that cross the wasm import boundary, which is the only way the module reaches
// randomness. It does not see JavaScript code that draws randomness by itself, such as the
// throwaway-key generation of the tests.
import { appendFileSync } from "node:fs";

const names = /getRandomValues|randomFillSync/;
let calls = 0;
const seen = new Set();

function wrap(imports) {
  const wbg = imports && imports.wbg;
  if (!wbg) return imports;
  for (const key of Object.keys(wbg)) {
    if (names.test(key) && typeof wbg[key] === "function") {
      const original = wbg[key];
      seen.add(key);
      wbg[key] = function (...args) {
        calls += 1;
        return original.apply(this, args);
      };
    }
  }
  return imports;
}

const RealInstance = WebAssembly.Instance;
WebAssembly.Instance = new Proxy(RealInstance, {
  construct(target, args) {
    return Reflect.construct(target, [args[0], wrap(args[1])]);
  },
});
const realInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = function (source, imports) {
  return realInstantiate.call(WebAssembly, source, wrap(imports));
};

// For a test that draws on purpose (the wallet's key): the count so far, to assert a draw per
// operation. A draw the test does not expect still fails the run, through the count of the process.
globalThis.__rngCalls = () => calls;

// Positive control.
const bytes = Uint8Array.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02, 0x22, 0x01, 0x03,
  0x77, 0x62, 0x67, 0x1a, ...Buffer.from("__wbg_getRandomValues_ctrl"), 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
  0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x10, 0x00, 0x0b,
]);
let control = 0;
{
  const before = calls;
  const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), { wbg: { __wbg_getRandomValues_ctrl() {} } });
  instance.exports.run();
  control = calls - before;
  calls = before;
}
if (control !== 1) {
  console.error(`rng-count: the positive control counted ${control}, not 1`);
  process.exit(97);
}
process.on("exit", () => {
  if (process.env.RNG_COUNT_FILE) {
    appendFileSync(
      process.env.RNG_COUNT_FILE,
      `${calls} control=${control} wrapped=${[...seen].filter((k) => !k.includes("_ctrl")).join(",")} expected=${globalThis.__rngExpected ?? 0} file=${process.argv[1] ?? ""}\n`,
    );
  }
});
