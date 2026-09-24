/**
 * The evaluation harness must not score a partial redaction as a hit.
 *
 * Mirrors euredact-python/tests/test_eval_scoring.py so the two SDKs are
 * measured by the same definition (issue rules-engine#12; the rule is #8).
 * Run with `npm run test:eval-scoring`.
 */

import assert from "node:assert/strict";
import { coveredChars, recallOutcome } from "./evalScoringLib.js";
import { EntityType } from "../types.js";

let passed = 0;
const failures: string[] = [];
function test(name: string, fn: () => void): void {
  try { fn(); passed++; }
  catch (e) { failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`); }
}

const det = (start: number, end: number, entityType: unknown = EntityType.EMAIL) =>
  ({ start, end, entityType });
const EMAIL = [EntityType.EMAIL as string];

// ── coveredChars ───────────────────────────────────────────────────────────
test("a full cover counts every character", () =>
  assert.equal(coveredChars([det(0, 10)], 0, 10, null), 10));
test("a partial cover counts only what is masked", () =>
  assert.equal(coveredChars([det(0, 3)], 0, 10, null), 3));
test("overlapping detections are not double counted", () =>
  assert.equal(coveredChars([det(0, 6), det(4, 10)], 0, 10, null), 10));
test("a gap between detections is not covered", () =>
  assert.equal(coveredChars([det(0, 3), det(7, 10)], 0, 10, null), 6));
test("detections outside the span are ignored", () =>
  assert.equal(coveredChars([det(20, 30)], 0, 10, null), 0));
test("a detection wider than the span is clipped", () =>
  assert.equal(coveredChars([det(-5, 50)], 0, 10, null), 10));
test("the type filter is honoured", () => {
  const d = [det(0, 10, EntityType.PHONE)];
  assert.equal(coveredChars(d, 0, 10, EMAIL), 0);
  assert.equal(coveredChars(d, 0, 10, [EntityType.PHONE as string]), 10);
  assert.equal(coveredChars(d, 0, 10, null), 10);
});

// ── recallOutcome ──────────────────────────────────────────────────────────
test("a fully masked identifier is a hit", () =>
  assert.equal(recallOutcome("mail jan@example.com now", [det(5, 20)], "jan@example.com", EMAIL), "hit"));
test("a partially masked identifier is not a hit", () =>
  assert.equal(recallOutcome("mail sean_o'neill@x.ie now", [det(12, 22)], "sean_o'neill@x.ie", EMAIL), "partial"));
test("one character of overlap is not a hit", () =>
  assert.equal(
    recallOutcome("addr 2001:db8::ff00:42:8329 end", [det(5, 6, EntityType.IPV6_ADDRESS)],
                  "2001:db8::ff00:42:8329", [EntityType.IPV6_ADDRESS as string]),
    "partial"));
test("an undetected identifier is a miss", () =>
  assert.equal(recallOutcome("mail jan@example.com", [], "jan@example.com", EMAIL), "miss"));
test("masked under another type is reported separately", () =>
  assert.equal(recallOutcome("mail jan@example.com now", [det(5, 20, EntityType.PHONE)],
                             "jan@example.com", EMAIL), "mistyped"));
test("an identifier absent from the document is not credited", () =>
  assert.equal(recallOutcome("nothing here", [], "jan@example.com", EMAIL), "unlocatable"));
test("split detections that together cover the span are a hit", () =>
  assert.equal(
    recallOutcome("Jan de Vries called",
                  [det(0, 3, EntityType.PERSON_NAME), det(3, 12, EntityType.PERSON_NAME)],
                  "Jan de Vries", [EntityType.PERSON_NAME as string]),
    "hit"));

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
