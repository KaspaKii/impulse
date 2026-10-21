// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
//
// Regenerates the Rust client (solana/programs/impulse-solana-client/src/generated/) from the
// program IDL that `cargo check -p impulse-solana` writes to programs/impulse-solana/idl/.
// Impulse renders the Rust client only (upstream also renders a TypeScript client). The output
// is committed; scripts/ci-solana.sh never runs this. Run: pnpm --dir solana/codegen generate
import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { createDvpSwapCodamaBuilder } from "./lib/dvp-swap-codama-builder";
import { patchRustCpiAccountFlags } from "./lib/patch-rust-cpi-account-flags";
import { renderVisitor as renderRustVisitor } from "@codama/renderers-rust";

const programs = path.join(__dirname, "..", "..", "programs");
const idlPath = path.join(programs, "impulse-solana", "idl", "impulse_solana.json");
const rustClientDir = path.join(programs, "impulse-solana-client");
const generatedDir = path.join(rustClientDir, "src", "generated");

const HEADER =
  "// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.\n" +
  "// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT\n" +
  "// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.\n";

const codama = createDvpSwapCodamaBuilder(JSON.parse(fs.readFileSync(idlPath, "utf-8")))
  .setInstructionAccountDefaultValues()
  .setFixedAccountOptionFields()
  .build();

// The renderer may rewrite the crate manifest; keep the hand-maintained one.
const cargoToml = fs.readFileSync(path.join(rustClientDir, "Cargo.toml"), "utf-8");
codama.accept(
  renderRustVisitor(generatedDir, {
    formatCode: false,
    crateFolder: rustClientDir,
    deleteFolderBeforeRendering: true,
  }),
);
fs.writeFileSync(path.join(rustClientDir, "Cargo.toml"), cargoToml);

// Correct the swapped CPI remaining-account flags emitted by @codama/renderers-rust.
patchRustCpiAccountFlags(rustClientDir);

// Licence header on every generated file, then rustfmt with the workspace settings.
const walk = (dir: string): string[] =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : p.endsWith(".rs") ? [p] : [];
  });
for (const file of walk(generatedDir)) {
  fs.writeFileSync(file, HEADER + fs.readFileSync(file, "utf-8"));
}
execFileSync("cargo", ["fmt", "-p", "impulse-solana-client"], {
  cwd: path.join(programs, ".."),
  stdio: "inherit",
});
