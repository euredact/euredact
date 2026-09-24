/**
 * Reversible tokenization: redact({ tokenize: true }) and restore().
 *
 * Mirrors the Python suite (tests/test_tokenize.py) so the two engines cannot
 * drift silently. Run with `npm run test:tokenize`.
 *
 * The use case is a prompt that goes to an LLM and comes back rewritten. The
 * tokens must survive that round trip verbatim, and restore() must put back
 * exactly what was taken out — so most tests assert on the round trip rather
 * than on the tokens themselves, which are random by design.
 */

import assert from "node:assert/strict";
import { EuRedact, TOKEN_ALPHABET, TokenMapper, applyReplacements, restore } from "../sdk.js";
import { CloudError } from "../cloud/errors.js";
import { configure, reset } from "../cloud/config.js";
import { resultChars } from "../cache.js";
import { DetectionSource, EntityType, type Detection, type RedactResult } from "../types.js";

const TOKEN = new RegExp(`^[A-Z][A-Z0-9_]*_[${TOKEN_ALPHABET}]{4}$`);
const PROMPT = "Write an email to Joren (joren.janssens@euredact.be) about the invoice.";

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

function det(start: number, end: number, text: string, entityType: EntityType | string = EntityType.OTHER): Detection {
  return { entityType, start, end, text, source: DetectionSource.CLOUD, country: null, confidence: "high" };
}

// ── Tokens ─────────────────────────────────────────────────────────────────

test("the prompt use case round-trips", () => {
  const r = new EuRedact().redact(PROMPT, { countries: ["BE"], tokenize: true });
  assert.ok(!r.redactedText.includes("joren.janssens@euredact.be"));
  assert.ok(Object.keys(r.tokens).length > 0);
  for (const [token, value] of Object.entries(r.tokens)) {
    assert.match(token, TOKEN);
    assert.ok(r.redactedText.includes(token));
    assert.ok(PROMPT.includes(value));
  }
  assert.equal(restore(r.redactedText, r.tokens), PROMPT);
});

test("tokens carry the entity type", () => {
  const r = new EuRedact().redact("mail: jan@example.com", { countries: ["NL"], tokenize: true });
  const [token] = Object.keys(r.tokens);
  assert.ok(token.startsWith("EMAIL_"));
  assert.equal(r.tokens[token], "jan@example.com");
});

test("same value, same token within a call", () => {
  const text = "jan@example.com wrote to piet@example.com, cc jan@example.com";
  const r = new EuRedact().redact(text, { countries: ["NL"], tokenize: true });
  assert.equal(Object.keys(r.tokens).length, 2);
  assert.equal(r.detections.length, 3);
  assert.equal(restore(r.redactedText, r.tokens), text);
});

test("a new call gets new tokens", () => {
  const sdk = new EuRedact();
  const a = sdk.redact("mail: jan@example.com", { countries: ["NL"], tokenize: true, cache: false });
  const b = sdk.redact("mail: jan@example.com", { countries: ["NL"], tokenize: true, cache: false });
  assert.notDeepEqual(Object.keys(a.tokens), Object.keys(b.tokens));
});

test("tokens are per call, not per instance", () => {
  const sdk = new EuRedact();
  sdk.redact("mail: jan@example.com", { countries: ["NL"], tokenize: true });
  const plain = sdk.redact("mail: jan@example.com", { countries: ["NL"] });
  assert.deepEqual(plain.tokens, {});
  assert.equal(plain.redactedText, "mail: [EMAIL]");
});

test("a custom pattern name is the type prefix", () => {
  const sdk = new EuRedact();
  sdk.addCustomPattern("TICKET", String.raw`\bTCK-\d{5}\b`);
  const r = sdk.redact("see TCK-12345", { tokenize: true });
  const [token] = Object.keys(r.tokens);
  assert.ok(token.startsWith("TICKET_"));
  assert.equal(restore(r.redactedText, r.tokens), "see TCK-12345");
});

test("tokenize and referentialIntegrity are exclusive", () => {
  const sdk = new EuRedact();
  assert.throws(() => sdk.redact("x", { tokenize: true, referentialIntegrity: true }),
                /tokenize and referentialIntegrity/);
});

testAsync("the exclusivity guard runs before the cloud dispatch", async () => {
  await assert.rejects(
    new EuRedact().redactAsync("x", { countries: ["BE"], mode: "cloud", tokenize: true, referentialIntegrity: true }),
    /tokenize and referentialIntegrity/,
  );
});

test("a document that already holds tokens is not collided with", () => {
  const text = "Reply to EMAIL_ABCD and jan@example.com";
  const mapper = new TokenMapper(text, [det(24, 39, "jan@example.com", EntityType.EMAIL)]);
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) seen.add(mapper.getToken(det(0, 1, "", EntityType.EMAIL), `v${i}`));
  assert.ok(!seen.has("EMAIL_ABCD"));
  assert.equal(seen.size, 50);
});

test("batch carries tokens", () => {
  const texts = ["mail: jan@example.com", "tel +31 6 12345678"];
  const results = new EuRedact().redactBatch(texts, { countries: ["NL"], tokenize: true });
  results.forEach((r, i) => assert.equal(restore(r.redactedText, r.tokens), texts[i]));
});

// ── restore ────────────────────────────────────────────────────────────────

test("an empty mapping is the identity", () =>
  assert.equal(restore("EMAIL_ABCD stays", {}), "EMAIL_ABCD stays"));
test("every occurrence is restored", () =>
  assert.equal(restore("EMAIL_ABCD, again EMAIL_ABCD.", { EMAIL_ABCD: "a@b.c" }), "a@b.c, again a@b.c."));
test("a token glued to other characters is still restored", () =>
  assert.equal(restore("EMAIL_ABCDs inbox", { EMAIL_ABCD: "a@b.c" }), "a@b.cs inbox"));
test("the longest token wins when one prefixes another", () =>
  assert.equal(restore("ID_ABCDEFGH_ABCD and ID_ABCD", { ID_ABCD: "short", ID_ABCDEFGH_ABCD: "long" }),
               "long and short"));
test("dollar patterns in values are literal", () =>
  assert.equal(restore("key SECRET_ABCD", { SECRET_ABCD: "p$&$1$$$'" }), "key p$&$1$$$'"));

// ── Cache ──────────────────────────────────────────────────────────────────

test("a plain hit is not served to a tokenized call", () => {
  const sdk = new EuRedact();
  const text = "mail: jan@example.com";
  assert.equal(sdk.redact(text, { countries: ["NL"] }).redactedText, "mail: [EMAIL]");
  const r = sdk.redact(text, { countries: ["NL"], tokenize: true });
  assert.ok(Object.keys(r.tokens).length > 0 && !r.redactedText.includes("[EMAIL]"));
});

test("tokens count towards the cache budget", () => {
  const base: RedactResult = {
    redactedText: "x", detections: [], source: "rules", degraded: false,
    inferredCountries: [], evidence: [], detectionMode: "declared", tokens: {}, exempted: [],
  };
  const withTokens = { ...base, tokens: { EMAIL_ABCD: "jan@example.com" } };
  assert.equal(resultChars(withTokens) - resultChars(base), "EMAIL_ABCD".length + "jan@example.com".length);
});

// ── applyReplacements: only the cloud path can hand it overlapping spans ────

test("an overlapping tail is masked, not leaked", () => {
  const out = applyReplacements("0123456789", [det(0, 5, "01234"), det(3, 8, "34567")], (_d, s) => `<${s}>`);
  assert.equal(out, "<01234><567>89");
});
test("a span inside an earlier one is dropped", () =>
  assert.equal(applyReplacements("0123456789", [det(0, 8, "01234567"), det(3, 5, "34")], () => "#"), "#89"));
test("tokens over overlapping spans still round-trip", () => {
  const text = "0123456789";
  const dets = [det(0, 5, "01234"), det(3, 8, "34567")];
  const mapper = new TokenMapper(text, dets);
  assert.equal(restore(applyReplacements(text, dets, mapper.getToken), mapper.tokens), text);
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

/** Run `fn` with the cloud tier answering every request with `payload`. */
async function withCloud(payload: unknown, fn: () => Promise<void>): Promise<void> {
  const realFetch = globalThis.fetch;
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  globalThis.fetch = async () =>
    new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } });
  try {
    await fn();
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

testAsync("without tokenize the service text is returned verbatim", () =>
  withCloud(CLOUD_PAYLOAD, async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud" });
    assert.equal(r.redactedText, CLOUD_PAYLOAD.redacted_text);
    assert.deepEqual(r.tokens, {});
  }));

testAsync("tokenize rebuilds from the service spans", () =>
  withCloud(CLOUD_PAYLOAD, async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", tokenize: true });
    assert.equal(r.source, "cloud");
    assert.ok(!r.redactedText.includes("Bas Verhoeven"));
    assert.ok(!r.redactedText.includes("bas@example.be"));
    assert.equal(Object.keys(r.tokens).length, 2);
    assert.equal(restore(r.redactedText, r.tokens), CLOUD_DOC);
  }));

testAsync("overlapping service spans are fully masked", () =>
  withCloud({ ...CLOUD_PAYLOAD, entities: [
    { start: 8, end: 21, text: "Bas Verhoeven", type: "PERSON_NAME", source: "model" },
    { start: 12, end: 27, text: "Verhoeven, mail", type: "OTHER", source: "model" },
  ] }, async () => {
    const r = await new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", tokenize: true });
    assert.ok(!r.redactedText.includes("Verhoeven"));
    assert.ok(!r.redactedText.includes("mail"));
    assert.equal(restore(r.redactedText, r.tokens), CLOUD_DOC);
  }));

testAsync("spans that do not match the document throw", () =>
  withCloud({ ...CLOUD_PAYLOAD, entities: [
    { start: 0, end: 7, text: "Someone", type: "PERSON_NAME", source: "model" },
  ] }, async () => {
    await assert.rejects(
      new EuRedact().redactAsync(CLOUD_DOC, { countries: ["BE"], mode: "cloud", tokenize: true }),
      (e: unknown) => e instanceof CloudError && /span offsets/.test(e.message),
    );
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
