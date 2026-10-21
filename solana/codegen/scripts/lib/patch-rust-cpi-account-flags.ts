// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// Derived from solana-foundation/dvp (commit df9919e), Copyright (c) 2026 Solana Foundation, MIT
// licence in solana/LICENSE-MIT; the Impulse modifications are Apache-2.0.
import fs from "fs";
import path from "path";

/**
 * Works around a bug in @codama/renderers-rust (present through v3.1.0).
 *
 * The generated CPI builder stores remaining accounts as tuples of
 * `(account, is_writable, is_signer)` (the documented `add_remaining_account`
 * argument order), but the generated invoke helper serializes them as
 * `is_signer: remaining_account.1, is_writable: remaining_account.2`, reading
 * `.1` (is_writable) as the signer flag and `.2` (is_signer) as the writable
 * flag. A caller who appends a readonly-signer extra as `(acct, false, true)`
 * gets a writable-non-signer AccountMeta instead. On ReclaimDvp, whose fixed
 * signer is readonly, the privilege union can upgrade that extra to a writable
 * signer forwarded into a transfer hook.
 *
 * Rewrite the two mapping lines so `.1` feeds is_writable and `.2` feeds
 * is_signer, matching the tuple order. A no-op if upstream fixes the template.
 */
export function patchRustCpiAccountFlags(rustClientsDir: string): void {
  const dir = path.join(rustClientsDir, "src", "generated", "instructions");
  const buggySigner = "is_signer: remaining_account.1,";
  const buggyWritable = "is_writable: remaining_account.2,";
  const fixedSigner = "is_signer: remaining_account.2,";
  const fixedWritable = "is_writable: remaining_account.1,";

  let filesPatched = 0;
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".rs")) continue;
    const filePath = path.join(dir, file);
    const src = fs.readFileSync(filePath, "utf-8");
    if (!src.includes(buggySigner)) continue;
    const patched = src
      .split(buggySigner)
      .join(fixedSigner)
      .split(buggyWritable)
      .join(fixedWritable);
    fs.writeFileSync(filePath, patched);
    filesPatched++;
  }

  // Safety net: the buggy mapping must not survive anywhere. (If upstream has
  // fixed the template, filesPatched is 0 and nothing here trips.)
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".rs")) continue;
    if (fs.readFileSync(path.join(dir, file), "utf-8").includes(buggySigner)) {
      throw new Error(
        `patchRustCpiAccountFlags: buggy remaining-account flag mapping still present in ${file}`,
      );
    }
  }

  console.log(
    `Patched remaining-account flag order in ${filesPatched} Rust CPI helper(s).`,
  );
}
