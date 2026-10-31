/**
 * Overlapping cloud spans (rules-engine#139): the cases live in
 * conformance/cloud_overlap.json and run in both SDKs. Mirrors
 * tests/test_cloud_overlap.py. Run with `npm run test:cloud-overlap`.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EuRedact, restore } from "../sdk.js";
import { configure, reset } from "../cloud/config.js";

interface Case {
  id: string; text: string; country: string;
  entities: Array<{ start: number; end: number; type: string }>;
  excludeTypes: string[]; expectRedactedText: string; expectDetections: Array<[string, string]>;
}

const CASES: Case[] = JSON.parse(
  readFileSync(new URL("../../../conformance/cloud_overlap.json", import.meta.url), "utf8"),
).cases;

let passed = 0;
const failures: string[] = [];

function payload(c: Case, entities = c.entities) {
  return {
    job_id: "00000000-0000-0000-0000-000000000139",
    status: "succeeded",
    redacted_text: "",
    entities: entities.map(e => ({
      start: e.start, end: e.end, type: e.type, text: c.text.slice(e.start, e.end), source: "model", match: "exact_body",
    })),
    unlocated: [],
  };
}

async function withService<T>(body: unknown, fn: () => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch;
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  globalThis.fetch = async () =>
    new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  try {
    return await fn();
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

async function check(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

(async () => {
  for (const c of CASES) {
    await check(c.id, () => withService(payload(c), async () => {
      const r = await new EuRedact().redactAsync(c.text, { countries: [c.country], mode: "cloud", excludeTypes: c.excludeTypes });
      assert.equal(r.redactedText, c.expectRedactedText);
      const got = r.detections.map(d => [String(d.entityType), d.text]).sort((a, b) => (a[0] + a[1] < b[0] + b[1] ? -1 : 1));
      assert.deepEqual(got, c.expectDetections);
    }));
    await check(`${c.id} (tokens round-trip)`, () => withService(payload(c), async () => {
      const r = await new EuRedact().redactAsync(c.text, { countries: [c.country], mode: "cloud", excludeTypes: c.excludeTypes, tokenize: true });
      assert.equal(restore(r.redactedText, r.tokens), c.text);
    }));
  }
  const imam = CASES.find(c => c.id === "overlap-imam-placeholder-does-not-reveal-the-category")!;
  await check("the label does not depend on span order", () =>
    withService(payload(imam, [...imam.entities].reverse()), async () => {
      const r = await new EuRedact().redactAsync(imam.text, { countries: ["BE"], mode: "cloud" });
      assert.equal(r.redactedText, imam.expectRedactedText);
    }));

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("\nFAILURES:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
})();
