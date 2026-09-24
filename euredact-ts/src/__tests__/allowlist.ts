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


// ── Separator-insensitive matching (issue rules-engine#15) ────────────────

for (const written of ["NL91ABNA0417164300", "NL91 ABNA 0417 1643 00", "NL91-ABNA-0417-1643-00"]) {
  test(`an allowlisted IBAN is exempt written as ${written}`, () => {
    const r = new EuRedact().redact(`Pay to ${written} today.`, { countries: ["NL"], allowlist: ["NL91ABNA0417164300"] });
    assert.ok(r.redactedText.includes(written));
  });
}
test("a phone number folds too", () =>
  assert.ok(new EuRedact().redact("Call +32 475 12 34 56 now", { countries: ["BE"], allowlist: ["+32475123456"] })
    .redactedText.includes("+32 475 12 34 56")));
test("free-text types stay literal", () =>
  assert.ok(!new EuRedact().redact("mail jandevries@acme.be", { countries: ["NL"], allowlist: ["jan.devries@acme.be"] })
    .redactedText.includes("jandevries@acme.be")));
test("folding does not exempt a different account", () =>
  assert.ok(!new EuRedact().redact("Pay to NL02ABNA0123456789 today.", { countries: ["NL"], allowlist: ["NL91ABNA0417164300"] })
    .redactedText.includes("NL02ABNA0123456789")));

// ── Domain exemption (issue rules-engine#17) ──────────────────────────────

test("every address at an owned domain is exempt", () =>
  assert.equal(new EuRedact().redact("mail jan@acme.be or piet@acme.be", { countries: ["NL"], allowlistDomains: ["acme.be"] }).redactedText,
               "mail jan@acme.be or piet@acme.be"));
test("subdomains are covered", () =>
  assert.ok(new EuRedact().redact("mail jan@mail.acme.be", { countries: ["NL"], allowlistDomains: ["acme.be"] })
    .redactedText.includes("jan@mail.acme.be")));
test("a lookalike domain is not covered", () =>
  assert.ok(!new EuRedact().redact("mail jan@evilacme.be", { countries: ["NL"], allowlistDomains: ["acme.be"] })
    .redactedText.includes("jan@evilacme.be")));
test("other types are untouched by a domain rule", () => {
  const r = new EuRedact().redact("mail jan@acme.be, IBAN NL91 ABNA 0417 1643 00", { countries: ["NL"], allowlistDomains: ["acme.be"] });
  assert.ok(r.redactedText.includes("jan@acme.be"));
  assert.ok(!r.redactedText.includes("NL91 ABNA 0417 1643 00"));
});
for (const entry of ["acme.be", "@acme.be", ".acme.be", "ACME.BE"]) {
  test(`domain entry form ${entry} is accepted`, () =>
    assert.ok(new EuRedact().redact("mail jan@acme.be", { countries: ["NL"], allowlistDomains: [entry] })
      .redactedText.includes("jan@acme.be")));
}
test("instance-level domains apply", () =>
  assert.ok(new EuRedact({ allowlistDomains: ["acme.be"] }).redact("mail jan@acme.be", { countries: ["NL"] })
    .redactedText.includes("jan@acme.be")));
test("a bare string is rejected for domains", () =>
  assert.throws(() => new EuRedact().redact("x", { countries: ["NL"], allowlistDomains: "acme.be" as unknown as string[] }),
                /allowlistDomains must be an array/));

// ── The exemption record (issue rules-engine#16) ──────────────────────────

test("a value exemption is reported", () => {
  const r = new EuRedact().redact(DOC, { countries: ["NL"], allowlist: ["jan@example.com"] });
  assert.equal(r.exempted.length, 1);
  const e = r.exempted[0];
  assert.equal(e.text, "jan@example.com");
  assert.equal(e.entityType, EntityType.EMAIL);
  assert.deepEqual([e.rule, e.ruleKind], ["jan@example.com", "value"]);
  assert.equal(DOC.slice(e.start, e.end), e.text);
});
test("a domain exemption names the domain rule", () => {
  const r = new EuRedact().redact("mail jan@acme.be", { countries: ["NL"], allowlistDomains: ["acme.be"] });
  assert.deepEqual(r.exempted.map(e => [e.rule, e.ruleKind]), [["acme.be", "domain"]]);
});
test("the rule is reported as the caller wrote it", () => {
  const r = new EuRedact().redact("Pay NL91 ABNA 0417 1643 00", { countries: ["NL"], allowlist: ["NL91ABNA0417164300"] });
  assert.equal(r.exempted[0].rule, "NL91ABNA0417164300");
  assert.equal(r.exempted[0].text, "NL91 ABNA 0417 1643 00");
});
test("no allowlist means no exemptions", () =>
  assert.deepEqual(new EuRedact().redact(DOC, { countries: ["NL"] }).exempted, []));

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
