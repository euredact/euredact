/**
 * Country inference, the generation invariant, and chunked documents.
 *
 * Mirrors the Python suite (tests/test_country_inference.py,
 * test_document_context.py, test_invariant_generation.py) so the two engines
 * cannot drift silently. Run with `npm run test:inference`.
 */

import assert from "node:assert/strict";
import { EuRedact } from "../sdk.js";
import { DocumentContext } from "../rules/context.js";
import { weightsToRanking, WEIGHTS } from "../rules/evidence.js";
import { EntityType, type RedactResult } from "../types.js";

const sdk = new EuRedact();

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

/** [entityType, country] pairs for a redaction. */
const types = (r: RedactResult): Array<[string, string | null]> =>
  r.detections.map(d => [String(d.entityType), d.country]);

const spans = (r: RedactResult): string =>
  JSON.stringify(r.detections.map(d => [d.start, d.end]).sort((a, b) => a[0] - b[0] || a[1] - b[1]));

// 0612345678 is a valid Dutch mobile number AND passes the Danish CPR
// checksum. Which one it is cannot be decided from the digits — only from the
// document.
const AMBIGUOUS = "0612345678";

// ── Ambiguity is resolved by the document, not the digits ──────────────

test("a Dutch document yields a Dutch phone", () => {
  const r = sdk.redact(`Bereikbaar op telefoon ${AMBIGUOUS}, mail jan@test.nl`, { cache: false });
  assert.ok(types(r).some(([t, c]) => t === EntityType.PHONE && c === "NL"));
});

test("a Danish document yields a Danish national ID", () => {
  const r = sdk.redact(`Kontakt: ${AMBIGUOUS}, e-mail jens@test.dk`, { cache: false });
  assert.ok(types(r).some(([t, c]) => t === EntityType.NATIONAL_ID && c === "DK"));
});

test("the same digits are masked either way", () => {
  for (const text of [`telefoon ${AMBIGUOUS}, mail jan@test.nl`,
                      `kontakt ${AMBIGUOUS}, e-mail jens@test.dk`]) {
    assert.ok(!sdk.redact(text, { cache: false }).redactedText.includes(AMBIGUOUS));
  }
});

// ── A foreign checksum does not beat a corroborated country ────────────

test("a Swedish phone is not a Danish national ID", () => {
  // 0708787668 passes the Danish CPR checksum and fails the Swedish
  // personnummer one. Neither fact makes it stop being a Swedish phone.
  const r = sdk.redact("Telefon: 0708787668", { countries: ["SE"], cache: false });
  assert.ok(types(r).some(([t, c]) => t === EntityType.PHONE && c === "SE"));
});

test("a failed checksum does not demote a different entity type", () => {
  const r = sdk.redact("Telefon: 0708787668", { countryHint: ["SE"], cache: false });
  assert.ok(types(r).some(([t, c]) => t === EntityType.PHONE && c === "SE"));
});

// ── I1: country influences scoring, never generation ───────────────────

const INVARIANT_DOCS = [
  "Werknemer met BSN 111222333 en rijksregisternummer 85.07.30-033.61",
  "Rekening: BE68 5390 0754 7034 - BIC: GEBABEBB",
  "Telefoon: +31 6 12345678, e-mail jan@test.nl",
  "Facture 2025-0031, TVA FR40303265045, tel 06 12 34 56 78",
  "Het nummer is 85041212399.",
  "",
];
const COUNTRY_ARGS: Array<string[] | null> = [
  null, [], ["NL"], ["BE"], ["DE"], ["ZZ"], ["GB"], ["gb"], ["NL", "BE"],
];

for (const [i, text] of INVARIANT_DOCS.entries()) {
  test(`no country argument changes which spans are found (doc ${i})`, () => {
    const baseline = spans(sdk.redact(text, { detectDates: true, cache: false }));
    for (const arg of COUNTRY_ARGS) {
      assert.equal(spans(sdk.redact(text, { countries: arg, detectDates: true, cache: false })),
                   baseline, `countries=${JSON.stringify(arg)} changed the spans found`);
      assert.equal(spans(sdk.redact(text, { countryHint: arg, detectDates: true, cache: false })),
                   baseline, `countryHint=${JSON.stringify(arg)} changed the spans found`);
    }
  });
}

test("a declared country cannot hide an entity", () => {
  // A Dutch BSN in a document declared Belgian used to vanish entirely.
  const r = sdk.redact("Werknemer met BSN 111222333", { countries: ["BE"], cache: false });
  assert.ok(r.detections.some(d => d.entityType === EntityType.NATIONAL_ID));
  assert.ok(!r.redactedText.includes("111222333"));
});

test("out of scope is flagged, not dropped", () => {
  const inScope = sdk.redact("Werknemer met BSN 111222333", { countries: ["NL"], cache: false });
  const outScope = sdk.redact("Werknemer met BSN 111222333", { countries: ["BE"], cache: false });
  assert.deepEqual(inScope.detections.map(d => d.outOfScope), [false]);
  assert.deepEqual(outScope.detections.map(d => d.outOfScope), [true]);
  assert.equal(spans(inScope), spans(outScope));
});

// ── The inference is auditable ─────────────────────────────────────────

test("every inference traces to a span", () => {
  const text = "IBAN NL91ABNA0417164300, BTW NL123456789B01, tel +31 6 12345678, mail info@jansen.nl";
  const r = sdk.redact(text, { cache: false });
  assert.deepEqual(new Set(r.evidence.map(e => e.source)),
                   new Set(["ibanPrefix", "vatPrefix", "e164Prefix", "emailTld"]));
  for (const e of r.evidence) {
    assert.equal(e.country, "NL");
    assert.ok(text.slice(e.span[0], e.span[1]).length > 0);
  }
});

test("evidence is returned in document order", () => {
  const r = sdk.redact("IBAN NL91ABNA0417164300, tel +31 6 12345678, mail info@jansen.nl", { cache: false });
  const starts = r.evidence.map(e => e.span[0]);
  assert.deepEqual(starts, [...starts].sort((a, b) => a - b));
});

test("no evidence, no inference", () => {
  const r = sdk.redact("geen pii hier", { cache: false });
  assert.deepEqual(r.inferredCountries, []);
  assert.deepEqual(r.evidence, []);
});

test("cross-border documents report both countries", () => {
  // Confidences are per-country, not a softmax: a Dutch invoice with a German
  // contact is genuinely both, and reporting DE at 0.00 would make
  // cross-border documents look like misattributions.
  const r = sdk.redact("IBAN NL91ABNA0417164300, tel +49 30 123456", { cache: false });
  const found = new Map(r.inferredCountries);
  assert.deepEqual(new Set(found.keys()), new Set(["NL", "DE"]));
  for (const v of found.values()) assert.ok(v > 0.5);
});

test("confidence is zero when only a checksum supports it", () => {
  const r = sdk.redact("Nummer: 0708787668", { cache: false });
  assert.deepEqual(r.detections.map(d => d.countryConfidence), [0]);
});

test("confidences do not sum to one", () => {
  const r = weightsToRanking(new Map([["NL", 4.0], ["DE", 4.0]]));
  assert.equal(r.get("NL"), r.get("DE"));
  assert.ok([...r.values()].reduce((a, b) => a + b, 0) > 1.0);
});

test("weights are capped so a single signal stays falsifiable", () => {
  assert.ok(WEIGHTS.e164Prefix <= 4.0);
  assert.ok(WEIGHTS.ibanPrefix < WEIGHTS.emailTld);
});

// ── Scope versus prior ─────────────────────────────────────────────────

test("a hint resolves without narrowing scope", () => {
  const r = sdk.redact("Telefon: 0708787668", { countryHint: ["SE"], cache: false });
  assert.equal(r.detectionMode, "inferred");
  assert.ok(!r.detections.some(d => d.outOfScope));
});

test("countries declares and flags", () => {
  assert.equal(sdk.redact("Telefon: 0708787668", { countries: ["SE"], cache: false }).detectionMode,
               "declared");
});

test("a hint and a declaration agree on attribution", () => {
  const a = sdk.redact("Telefon: 0708787668", { countries: ["SE"], cache: false });
  const b = sdk.redact("Telefon: 0708787668", { countryHint: ["SE"], cache: false });
  assert.deepEqual(types(a), types(b));
});

// ── Chunked documents ──────────────────────────────────────────────────

const PAGE_1 = "Factuur — IBAN NL91ABNA0417164300, info@jansen.nl";
const PAGE_7 = "Telefoon 0612345678";

test("a chunk alone cannot resolve it", () => {
  assert.deepEqual(types(sdk.redact(PAGE_7, { cache: false })),
                   [[EntityType.NATIONAL_ID, "DK"]]);
});

test("a context carries the document forward", () => {
  const ctx = new DocumentContext();
  sdk.redact(PAGE_1, { context: ctx, chunkOffset: 0 });
  const r = sdk.redact(PAGE_7, { context: ctx, chunkOffset: PAGE_1.length });
  assert.deepEqual(types(r), [[EntityType.PHONE, "NL"]]);
});

test("context spans point into the whole document", () => {
  const ctx = new DocumentContext();
  sdk.redact(PAGE_1, { context: ctx, chunkOffset: 500 });
  assert.ok(ctx.evidence().length > 0);
  for (const ev of ctx.evidence()) {
    assert.ok(ev.span[0] >= 500 && ev.span[1] <= 500 + PAGE_1.length);
  }
});

test("returned detections stay chunk-relative", () => {
  const ctx = new DocumentContext();
  const r = sdk.redact(PAGE_1, { context: ctx, chunkOffset: 9999 });
  for (const d of r.detections) assert.equal(PAGE_1.slice(d.start, d.end), d.text);
});

test("re-running a chunk does not let it vote twice", () => {
  const ctx = new DocumentContext();
  for (let i = 0; i < 5; i++) sdk.redact(PAGE_1, { context: ctx, chunkOffset: 0 });
  const keys = ctx.evidence().map(e => `${e.span[0]}:${e.span[1]}:${e.source}`);
  assert.equal(keys.length, new Set(keys).size);
});

test("a context disables caching", () => {
  // A context makes the result depend on state outside the text, so a cached
  // result keyed on the text alone would be wrong.
  const ctx = new DocumentContext();
  assert.deepEqual(types(sdk.redact(PAGE_7, { context: ctx, cache: true })),
                   [[EntityType.NATIONAL_ID, "DK"]]);
  sdk.redact(PAGE_1, { context: ctx, chunkOffset: PAGE_7.length });
  assert.deepEqual(types(sdk.redact(PAGE_7, { context: ctx, cache: true })),
                   [[EntityType.PHONE, "NL"]], "a stale cached result was returned");
});

test("a context cannot hide a span", () => {
  // I1 again: carried over from the wrong document it may misattribute, but it
  // must never cause a miss.
  const wrong = new DocumentContext();
  wrong.add([{ country: "DK", source: "ibanPrefix", logOdds: 4.0, span: [0, 10] }]);
  assert.equal(spans(sdk.redact(PAGE_1, { context: wrong, cache: false })),
               spans(sdk.redact(PAGE_1, { cache: false })));
});

// ── Report ─────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
