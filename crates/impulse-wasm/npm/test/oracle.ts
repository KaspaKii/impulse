// Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
// The native oracle. Every call a test makes through the wasm module can be recorded with its
// arguments and its answer; at the end of the test file the same calls run again, natively, in
// impulse-core's builders built for the host (the ignored `ops_tests::oracle` test of
// crates/impulse-wasm, which calls the same operations the bindings call), and the answers are
// compared byte for byte. The arguments are public data: terms, UTXOs, public keys and
// signatures. A secret key is never in a request.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import type { Ipst, SignedTransaction, ValidatedTerms } from "../index.js";
import { hex, root } from "./sdk.ts";

export interface Step {
  id: string;
  op: string;
  /** The terms' canonical bytes, hex; absent for operations that take an IPST. */
  terms?: string;
  args: unknown[];
  /** What the wasm module answered: `{ ok }` or `{ err }`. */
  expect: { ok: unknown } | { err: string };
}

const steps: Step[] = [];

/** What a result looks like in a request or an answer. */
function plain(value: unknown): unknown {
  if (value !== null && typeof value === "object") {
    if ("toJson" in value && typeof (value as Ipst).toJson === "function") return (value as Ipst).toJson();
    if ("raw" in value && "txid" in value) {
      const tx = value as SignedTransaction;
      return { txid: hex(tx.txid()), raw: hex(tx.raw()) };
    }
  }
  return value === undefined ? null : value;
}

/**
 * Runs `run` (a call into the wasm module) and records it. A refusal is recorded as its code
 * and rethrown, so the caller still sees it.
 */
export function record<T>(op: string, terms: ValidatedTerms | null, args: unknown[], run: () => T): T {
  const step: Omit<Step, "expect"> = {
    id: String(steps.length),
    op,
    ...(terms === null ? {} : { terms: hex(terms.canonical()) }),
    args,
  };
  try {
    const result = run();
    steps.push({ ...step, expect: { ok: plain(result) } });
    return result;
  } catch (thrown) {
    const code = (thrown as { code?: unknown }).code;
    if (typeof code === "string") steps.push({ ...step, expect: { err: code } });
    throw thrown;
  }
}

/** How many calls have been recorded. */
export function recorded(): number {
  return steps.length;
}

/** Runs every recorded call natively and requires the same answers. Returns how many ran. */
export function checkAgainstNative(): number {
  assert.ok(steps.length > 0, "calls were recorded");
  const dir = mkdtempSync(`${tmpdir()}/impulse-oracle-`);
  try {
    const input = `${dir}/requests.json`;
    const output = `${dir}/answers.json`;
    writeFileSync(input, JSON.stringify(steps));
    const run = spawnSync(
      "cargo",
      ["test", "--locked", "-p", "impulse-wasm", "--lib", "ops_tests::oracle", "--", "--ignored", "--exact"],
      {
        cwd: fileURLToPath(root),
        env: { ...process.env, IMPULSE_ORACLE_IN: input, IMPULSE_ORACLE_OUT: output },
        encoding: "utf8",
      },
    );
    assert.equal(run.status, 0, `the native oracle ran\n${run.stdout}\n${run.stderr}`);
    const answers = JSON.parse(readFileSync(output, "utf8")) as ({ id: string } & (
      | { ok: unknown }
      | { err: string }
    ))[];
    assert.equal(answers.length, steps.length, "one answer per request");
    for (const [i, step] of steps.entries()) {
      const answer = answers[i];
      assert.equal(answer.id, step.id);
      const got = "ok" in answer ? { ok: answer.ok } : { err: answer.err };
      assert.deepEqual(got, step.expect, `step ${step.id} (${step.op}): the native build answers as the wasm module did`);
    }
    return steps.length;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
