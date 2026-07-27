/**
 * Shared conformance suite — the same vectors run against the Python SDK.
 *
 * `conformance/vectors.json` at the repository root is language-neutral: input
 * plus expected detections, no Python or JavaScript detail. Both SDKs run it,
 * so a behavioural difference between them fails a test instead of going
 * unnoticed until someone diffs two corpora.
 *
 * The Python side is `euredact-python/tests/test_conformance.py`. When you add
 * a case there, both suites pick it up automatically.
 */

import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { EuRedact } from "../sdk.js";

interface Case {
  id: string;
  text: string;
  countries: string[] | null;
  mustDetect?: Record<string, string[]>;
  mustNotDetect?: string[];
}

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, "../../../conformance/vectors.json");

if (!existsSync(vectorsPath)) {
  console.error(`conformance vectors not found at ${vectorsPath}`);
  process.exit(1);
}

const cases: Case[] = JSON.parse(readFileSync(vectorsPath, "utf-8")).cases;
const sdk = new EuRedact();

let passed = 0;
const failures: string[] = [];

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

function detectionsByType(c: Case): Record<string, string[]> {
  const result = sdk.redact(c.text, {
    countries: c.countries,
    detectDates: true,
    cache: false,
  });
  const byType: Record<string, string[]> = {};
  for (const d of result.detections) {
    const t = d.entityType as string;
    (byType[t] ??= []).push(d.text);
  }
  return byType;
}

for (const c of cases) {
  check(c.id, () => {
    const got = detectionsByType(c);
    for (const etype of c.mustNotDetect ?? []) {
      assert.deepEqual(got[etype] ?? [], [], `expected no ${etype}, got ${JSON.stringify(got[etype])}`);
    }
    for (const [etype, expected] of Object.entries(c.mustDetect ?? {})) {
      assert.deepEqual(got[etype] ?? [], expected, `${etype} mismatch`);
    }
  });
}

check("vector ids are unique", () => {
  const ids = cases.map(c => c.id);
  assert.equal(ids.length, new Set(ids).size);
});

check("every case asserts something", () => {
  for (const c of cases) {
    assert.ok(c.mustDetect || c.mustNotDetect, `${c.id} asserts nothing`);
  }
});

console.log(`\nconformance: ${passed} passed, ${failures.length} failed (${cases.length} shared vectors)`);
if (failures.length > 0) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
