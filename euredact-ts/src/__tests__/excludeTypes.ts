/**
 * excludeTypes: entity types a caller leaves in the text (rules-engine#125).
 *
 * Mirrors the Python suite (tests/test_exclude_types.py) so the two engines
 * cannot drift silently. Run with `npm run test:exclude-types`.
 *
 * A deployment whose taxonomy is narrower than euRedact's switches those
 * types off instead of post-processing every result. The default is
 * unchanged. An excluded detection is neither reported nor masked, and is
 * recorded in `exempted` so an audit can see what was deliberately left in.
 */

import assert from "node:assert/strict";
import { EuRedact, restore } from "../sdk.js";
import { redact } from "../index.js";
import { configure, reset } from "../cloud/config.js";
import { EntityType, type RedactResult } from "../types.js";

const DOC = "Contact anna.kowalska@example.com or +32 470 12 34 56; IBAN BE71 0961 2345 6769.";

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

const types = (r: RedactResult) => r.detections.map(d => String(d.entityType));

// ── Filtering ──────────────────────────────────────────────────────────────

test("default excludes nothing", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"] });
  assert.deepEqual(types(r), ["EMAIL", "PHONE", "BANK_ACCOUNT"]);
  assert.deepEqual(r.exempted, []);
});
test("an excluded type is neither reported nor masked", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"] });
  assert.deepEqual(types(r), ["PHONE", "BANK_ACCOUNT"]);
  assert.ok(r.redactedText.includes("anna.kowalska@example.com"));
  assert.ok(r.redactedText.includes("[PHONE]") && r.redactedText.includes("[BANK_ACCOUNT]"));
});
test("several types", () =>
  assert.deepEqual(types(new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL", "PHONE"] })), ["BANK_ACCOUNT"]));
test("names are case-insensitive and aliases resolve", () =>
  assert.deepEqual(types(new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["iban", " email "] })), ["PHONE"]));
test("an enum member is accepted", () =>
  assert.ok(!types(new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: [EntityType.PHONE] })).includes("PHONE")));
test("the filter applies to the final type", () => {
  // The digits also pass the Austrian SVNr check: filtering candidates before
  // ranking would have re-masked them as SSN.
  const r = new EuRedact().redact("NHS Number: 5556953627.", { excludeTypes: ["HEALTH_INSURANCE"] });
  assert.deepEqual(r.detections, []);
  assert.equal(r.redactedText, "NHS Number: 5556953627.");
});
test("dates still need detectDates", () => {
  const text = "Geboortedatum: 12/03/1985, mail jan@example.nl";
  assert.deepEqual(types(new EuRedact().redact(text, { countries: ["NL"], excludeTypes: ["EMAIL"] })), []);
  assert.deepEqual(types(new EuRedact().redact(text, { countries: ["NL"], excludeTypes: ["EMAIL"], detectDates: true })), ["DOB"]);
});

// ── The exemption record ───────────────────────────────────────────────────

test("each excluded detection is recorded", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["email"] });
  assert.equal(r.exempted.length, 1);
  const e = r.exempted[0];
  assert.deepEqual([e.entityType, e.text, e.rule, e.ruleKind], [EntityType.EMAIL, "anna.kowalska@example.com", "EMAIL", "type"]);
  assert.equal(DOC.slice(e.start, e.end), e.text);
});
test("allowlist and type exemptions together, in text order", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["BANK_ACCOUNT"], allowlist: ["anna.kowalska@example.com"] });
  assert.deepEqual(r.exempted.map(e => [e.ruleKind, e.text]),
    [["value", "anna.kowalska@example.com"], ["type", "BE71 0961 2345 6769"]]);
});
test("an allowlisted value of an excluded type is recorded once", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"], allowlist: ["anna.kowalska@example.com"] });
  assert.deepEqual(r.exempted.map(e => e.ruleKind), ["value"]);
});

// ── Guards ─────────────────────────────────────────────────────────────────

test("an unknown name throws", () =>
  assert.throws(() => new EuRedact().redact(DOC, { excludeTypes: ["EMIAL"] }), /unknown entity type "EMIAL"/));
test("a bare string is rejected", () =>
  assert.throws(() => new EuRedact().redact(DOC, { excludeTypes: "EMAIL" as unknown as string[] }), /bare string/));
test("an unknown name on the instance throws at construction", () =>
  assert.throws(() => new EuRedact({ excludeTypes: ["JOBTITLE"] }), /unknown entity type/));
test("a registered custom pattern can be excluded", () => {
  const sdk = new EuRedact();
  sdk.addCustomPattern("TICKET_ID", String.raw`INC-\d{5}`);
  const r = sdk.redact("Ticket INC-20419", { excludeTypes: ["TICKET_ID"] });
  assert.deepEqual(r.detections, []);
  assert.equal(r.exempted[0].rule, "TICKET_ID");
});
test("an unregistered custom name throws", () =>
  assert.throws(() => new EuRedact().redact("Ticket INC-20419", { excludeTypes: ["TICKET_ID"] }), /unknown entity type "TICKET_ID"/));
testAsync("the guard runs before the cloud dispatch", () =>
  assert.rejects(new EuRedact().redactAsync(DOC, { countries: ["BE"], mode: "cloud", excludeTypes: ["EMIAL"] }), /unknown entity type/));

// ── Scope ──────────────────────────────────────────────────────────────────

test("the instance list applies to every call", () =>
  assert.ok(!types(new EuRedact({ excludeTypes: ["EMAIL"] }).redact(DOC, { countries: ["BE"] })).includes("EMAIL")));
test("instance and call lists merge", () =>
  assert.deepEqual(types(new EuRedact({ excludeTypes: ["EMAIL"] }).redact(DOC, { countries: ["BE"], excludeTypes: ["PHONE"] })), ["BANK_ACCOUNT"]));
test("the batch honours it", () => {
  const [r] = new EuRedact().redactBatch([DOC], { countries: ["BE"], excludeTypes: ["EMAIL"] });
  assert.ok(!types(r).includes("EMAIL"));
});
test("the module-level function accepts it", () =>
  assert.ok(!types(redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"] })).includes("EMAIL")));
test("works with tokenize", () => {
  const r = new EuRedact().redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"], tokenize: true });
  assert.ok(Object.keys(r.tokens).every(t => !t.startsWith("EMAIL_")));
  assert.equal(restore(r.redactedText, r.tokens), DOC);
});

// ── Cache ──────────────────────────────────────────────────────────────────

test("a plain hit is not served to an excluding call", () => {
  const sdk = new EuRedact();
  sdk.redact(DOC, { countries: ["BE"] });
  assert.ok(!types(sdk.redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"] })).includes("EMAIL"));
});
test("an excluding hit is not served to a plain call", () => {
  const sdk = new EuRedact();
  sdk.redact(DOC, { countries: ["BE"], excludeTypes: ["EMAIL"] });
  assert.ok(types(sdk.redact(DOC, { countries: ["BE"] })).includes("EMAIL"));
});

// ── Cloud ──────────────────────────────────────────────────────────────────

const CLOUD_DOC = "Anna Kowalska, Head of IT, mail anna@example.be";
const CLOUD_PAYLOAD = {
  job_id: "00000000-0000-0000-0000-000000000125",
  status: "succeeded",
  redacted_text: "[PERSON_NAME], [JOB_TITLE], mail [EMAIL]",
  entities: [
    // Relative to the text the service received, in which the address is
    // already `[EMAIL]`: the rules ran locally.
    { start: 0, end: 13, text: "Anna Kowalska", type: "PERSON_NAME", source: "model", match: "exact_body" },
    { start: 15, end: 25, text: "Head of IT", type: "JOB_TITLE", source: "model", match: "exact_body" },
  ],
  unlocated: [],
};

async function withCloud(fn: (sent: string[]) => Promise<void>): Promise<void> {
  const realFetch = globalThis.fetch;
  const sent: string[] = [];
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  globalThis.fetch = async (_url: unknown, init?: { body?: unknown }) => {
    if (typeof init?.body === "string") sent.push(JSON.parse(init.body).text);
    return new Response(JSON.stringify(CLOUD_PAYLOAD), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  try {
    await fn(sent);
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

testAsync("a model type is dropped from the result", () =>
  withCloud(async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", excludeTypes: ["JOB_TITLE"] });
    assert.equal(r.redactedText, "[PERSON_NAME], Head of IT, mail [EMAIL]");
    assert.deepEqual(r.exempted.map(e => e.text), ["Head of IT"]);
  }));
testAsync("an excluded rules type is still masked in the request", () =>
  withCloud(async (sent) => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", excludeTypes: ["EMAIL"] });
    // What may leave is not what the caller wants back.
    assert.deepEqual(sent, ["Anna Kowalska, Head of IT, mail [EMAIL]"]);
    assert.equal(r.redactedText, "[PERSON_NAME], [JOB_TITLE], mail anna@example.be");
  }));
testAsync("the instance list reaches cloud mode", () =>
  withCloud(async () => {
    const r = await new EuRedact({ excludeTypes: ["JOB_TITLE", "PERSON_NAME"] }).redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud" });
    assert.equal(r.redactedText, "Anna Kowalska, Head of IT, mail [EMAIL]");
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
