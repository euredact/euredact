/**
 * The allowlist: values a caller declares are not PII to them.
 *
 * Mirrors the Python suite (tests/test_allowlist.py) so the two engines cannot
 * drift silently. Run with `npm run test:allowlist`.
 *
 * A customer's own email address or organisation name is not something they
 * want masked out of their own documents. The allowlist exempts exact values,
 * whole-span and case-insensitively — and nothing more, because a broader
 * match is how "our domain" turns into "every address at our domain".
 */

import assert from "node:assert/strict";
import { EuRedact, restore } from "../sdk.js";
import { redact } from "../index.js";
import { configure, reset } from "../cloud/config.js";
import { EntityType, type RedactResult } from "../types.js";

const DOC = "Contact jan@example.com or piet@example.com at ACME NV; ACME NV pays IBAN NL91 ABNA 0417 1643 00.";

let passed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

const asyncTests: Array<[string, () => Promise<void>]> = [];
function testAsync(name: string, fn: () => Promise<void>): void {
  asyncTests.push([name, fn]);
}

const texts = (r: RedactResult) => r.detections.map(d => d.text);

// ── Matching ───────────────────────────────────────────────────────────────

test("an exact value is not redacted", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] });
  assert.ok(r.redactedText.includes("jan@example.com"));
  assert.ok(!r.redactedText.includes("piet@example.com"));
  assert.ok(!texts(r).includes("jan@example.com"));
});

test("matching is case-insensitive", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["JAN@EXAMPLE.COM"] });
  assert.ok(r.redactedText.includes("jan@example.com"));
});

test("entries are trimmed", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["  jan@example.com\n"] });
  assert.ok(r.redactedText.includes("jan@example.com"));
});

test("a substring does not exempt", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["example.com"] });
  assert.ok(!r.redactedText.includes("jan@example.com"));
  assert.ok(!r.redactedText.includes("piet@example.com"));
});

test("an NFD document matches an NFC entry", () => {
  const nfd = "mail: zoë@example.be".normalize("NFD");
  const entry = "zoë@example.be".normalize("NFC");
  assert.notEqual(nfd, nfd.normalize("NFC"));
  const r = new EuRedact().redact(nfd, { countries: ["BE"], allowlist: [entry] });
  assert.deepEqual(r.detections, []);
});

test("other detections are untouched", () => {
  const sdk = new EuRedact();
  const before = sdk.redact(DOC, { countries: ["NL"] });
  const after = sdk.redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] });
  assert.equal(after.detections.length, before.detections.length - 1);
  assert.ok(after.detections.some(d => d.entityType === EntityType.BANK_ACCOUNT));
});

test("empty and null are no-ops", () => {
  const sdk = new EuRedact();
  const plain = sdk.redact(DOC, { countries: ["NL"] }).redactedText;
  assert.equal(sdk.redact(DOC, { countries: ["NL"], allowlist: [] }).redactedText, plain);
  assert.equal(sdk.redact(DOC, { countries: ["NL"], allowlist: null }).redactedText, plain);
  assert.equal(sdk.redact(DOC, { countries: ["NL"], allowlist: ["", "  "] }).redactedText, plain);
});

// ── Scope ──────────────────────────────────────────────────────────────────

test("the instance allowlist applies to every call", () => {
  const sdk = new EuRedact({ allowlist: ["jan@example.com"] });
  assert.ok(sdk.redact(DOC, { countries: ["NL"] }).redactedText.includes("jan@example.com"));
  const [r] = sdk.redactBatch([DOC], { countries: ["NL"] });
  assert.ok(r.redactedText.includes("jan@example.com"));
});

test("instance and call allowlists merge", () => {
  const sdk = new EuRedact({ allowlist: ["jan@example.com"] });
  const r = sdk.redact(DOC, { countries: ["NL"], allowlist: ["piet@example.com"] });
  assert.ok(r.redactedText.includes("jan@example.com"));
  assert.ok(r.redactedText.includes("piet@example.com"));
});

test("batch honours it", () => {
  for (const r of new EuRedact().redactBatch([DOC, "cc jan@example.com"], { countries: ["NL"], allowlist: ["jan@example.com"] })) {
    assert.ok(r.redactedText.includes("jan@example.com"));
  }
});

test("the module-level function accepts it", () => {
  assert.ok(redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] }).redactedText.includes("jan@example.com"));
});

test("works with tokenize", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"], tokenize: true });
  assert.ok(r.redactedText.includes("jan@example.com"));
  assert.ok(!Object.values(r.tokens).includes("jan@example.com"));
  assert.equal(restore(r.redactedText, r.tokens), DOC);
});

// ── Guards ─────────────────────────────────────────────────────────────────

test("a bare string is rejected", () => {
  assert.throws(() => new EuRedact().redact(DOC, { countries: ["NL"], allowlist: "jan@example.com" as unknown as string[] }),
                /allowlist must be an array/);
  assert.throws(() => new EuRedact({ allowlist: "ACME NV" as unknown as string[] }), /allowlist must be an array/);
});

testAsync("the guard runs before the cloud dispatch", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  try {
    await assert.rejects(
      new EuRedact().redactAsync(DOC, { countries: ["BE"], mode: "cloud", allowlist: "jan@example.com" as unknown as string[] }),
      /allowlist must be an array/,
    );
  } finally {
    reset();
  }
});

// ── Cache ──────────────────────────────────────────────────────────────────

test("a plain hit is not served to an allowlisted call", () => {
  const sdk = new EuRedact();
  assert.ok(!sdk.redact(DOC, { countries: ["NL"] }).redactedText.includes("jan@example.com"));
  assert.ok(sdk.redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] }).redactedText.includes("jan@example.com"));
});

test("different allowlists do not share a hit", () => {
  const sdk = new EuRedact();
  const a = sdk.redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] });
  const b = sdk.redact(DOC, { countries: ["NL"], allowlist: ["piet@example.com"] });
  assert.ok(a.redactedText.includes("jan@example.com") && !a.redactedText.includes("piet@example.com"));
  assert.ok(b.redactedText.includes("piet@example.com") && !b.redactedText.includes("jan@example.com"));
});

// ── Cloud ──────────────────────────────────────────────────────────────────

const CLOUD_DOC = "Patiënt Bas Verhoeven, mail bas@example.be";
const CLOUD_PAYLOAD = {
  job_id: "job-1",
  status: "succeeded",
  redacted_text: "Patiënt [PERSON_NAME], mail [EMAIL]",
  entities: [
    { start: 8, end: 21, text: "Bas Verhoeven", type: "PERSON_NAME", source: "model", match: "exact_body" },
    { start: 28, end: 42, text: "bas@example.be", type: "EMAIL", source: "rules" },
  ],
  unlocated: [],
};

async function withCloud(fn: () => Promise<void>): Promise<void> {
  const realFetch = globalThis.fetch;
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  globalThis.fetch = async () =>
    new Response(JSON.stringify(CLOUD_PAYLOAD), { status: 200, headers: { "Content-Type": "application/json" } });
  try {
    await fn();
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

testAsync("the allowlisted value is put back from the service spans", () =>
  withCloud(async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", allowlist: ["bas@example.be"] });
    assert.equal(r.redactedText, "Patiënt [PERSON_NAME], mail bas@example.be");
    assert.deepEqual(texts(r), ["Bas Verhoeven"]);
  }));

testAsync("the instance allowlist reaches cloud mode", () =>
  withCloud(async () => {
    const r = await new EuRedact({ allowlist: ["Bas Verhoeven"] }).redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud" });
    assert.equal(r.redactedText, "Patiënt Bas Verhoeven, mail [EMAIL]");
  }));

testAsync("allowlist and tokenize together in cloud mode", () =>
  withCloud(async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", allowlist: ["bas@example.be"], tokenize: true });
    assert.ok(r.redactedText.includes("bas@example.be"));
    assert.equal(Object.keys(r.tokens).length, 1);
    assert.equal(restore(r.redactedText, r.tokens), CLOUD_DOC);
  }));

(async () => {
  for (const [name, fn] of asyncTests) {
    try {
      await fn();
      passed++;
    } catch (e) {
      failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
    }
  }
  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("\nFAILURES:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
})();
