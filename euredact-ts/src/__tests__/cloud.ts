/**
 * [CLOUD EXTENSION] The cloud tier.
 *
 * Mirrors the Python suite (tests/test_cloud.py) so the two SDKs cannot drift
 * silently. Run with `npm run test:cloud`.
 *
 * The single most important test here is the first one. Before this was
 * implemented, `redact({ mode: "cloud" })` returned rules-only output with no
 * error: the caller believed names, employers and diagnoses had been checked,
 * saw a plausible redacted document, and shipped it with the PII still in it.
 */

import assert from "node:assert/strict";
import { EuRedact, restore } from "../sdk.js";
import { redact, redactAsync } from "../index.js";
import { CloudClient } from "../cloud/client.js";
import { configure, reset, requireSecureBaseUrl } from "../cloud/config.js";
import {
  CloudError,
  NotConfiguredError,
  QuotaExceededError,
  TooLargeError,
} from "../cloud/errors.js";
import { readFileSync } from "node:fs";
import { canonicalType, DetectionSource, EntityType, type Usage } from "../types.js";

const DOC = "Patiënt Bas Verhoeven, tel +32 475 12 34 56, mail bas@example.be";

let passed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    reset();
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  } finally {
    reset();
  }
}

const asyncTests: Array<[string, () => Promise<void>]> = [];
function testAsync(name: string, fn: () => Promise<void>): void {
  asyncTests.push([name, fn]);
}

/** A fetch that replays scripted responses and records what it was sent. */
function scripted(
  steps: Array<{ status: number; body?: unknown; headers?: Record<string, string> }>,
) {
  const calls: Array<{ url: string; method: string; headers: Headers; body?: string }> = [];
  let i = 0;
  const impl: typeof fetch = async (input, init) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers as HeadersInit),
      body: typeof init?.body === "string" ? init.body : undefined,
    });
    const step = steps[Math.min(i, steps.length - 1)];
    i++;
    return new Response(JSON.stringify(step.body ?? {}), {
      status: step.status,
      headers: { "Content-Type": "application/json", ...(step.headers ?? {}) },
    });
  };
  return { impl, calls };
}

const SUCCESS = {
  job_id: "job-1",
  status: "succeeded",
  redacted_text: "Patiënt [PERSON_NAME], tel [PHONE], mail [EMAIL]",
  entities: [
    { start: 8, end: 21, text: "Bas Verhoeven", type: "PERSON_NAME",
      source: "model", match: "exact_body" },
    { start: 27, end: 43, text: "+32 475 12 34 56", type: "PHONE", source: "rules" },
  ],
  unlocated: [],
  model_version: "euredact-9b@2026-08-31",
};

// ── The bug this closes ────────────────────────────────────────────────────

// ── TLS only (rules-engine#86) ────────────────────────────────────────
for (const url of ["http://api.example.com", "http://api.euredact.dev", "ftp://api.example.com",
                   "api.euredact.dev", "https://", "nohost"]) {
  test(`a base URL without TLS is refused: ${url}`, () => {
    assert.throws(() => configure({ apiKey: "erk_test", baseUrl: url }), /must start with https:\/\//);
  });
}
for (const url of ["https://api.euredact.dev", "https://gw.example.com:8443",
                   "http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"]) {
  test(`https and loopback http are accepted: ${url}`, () => {
    assert.equal(configure({ apiKey: "erk_test", baseUrl: url }).baseUrl, url);
  });
}
test("the TLS check does not depend on a URL global", () => {
  const saved = globalThis.URL;
  // Some minimal runtimes have no URL; https must still pass and http still fail.
  (globalThis as { URL?: unknown }).URL = undefined;
  try {
    assert.doesNotThrow(() => requireSecureBaseUrl("https://api.euredact.dev"));
    assert.doesNotThrow(() => requireSecureBaseUrl("http://[::1]:8000"));
    assert.throws(() => requireSecureBaseUrl("http://api.example.com"), /must start with https:\/\//);
  } finally {
    globalThis.URL = saved;
  }
});
test("a hand-built config is checked by the client too", () => {
  assert.throws(() => new CloudClient({ apiKey: "k", baseUrl: "http://api.example.com", timeoutMs: 1,
                                        pollTimeoutMs: 1, maxRetries: 0, headers: {} }),
                /must start with https:\/\//);
  assert.doesNotThrow(() => requireSecureBaseUrl("https://api.euredact.dev"));
});

test("sync redact with mode:cloud throws instead of returning rules-only", () => {
  assert.throws(
    () => redact(DOC, { countries: ["BE"], mode: "cloud" }),
    /asynchronous/,
  );
});

test("an unknown mode throws", () => {
  assert.throws(() => redact(DOC, { countries: ["BE"], mode: "magic" }), /unknown mode/);
});

test("rules mode is untouched by all of this", () => {
  const r = redact(DOC, { countries: ["BE"] });
  assert.equal(r.source, "rules");
  assert.ok(r.detections.some(d => d.entityType === EntityType.PHONE));
});

// ── Types ──────────────────────────────────────────────────────────────────

test("NAME is a legacy alias of PERSON_NAME", () => {
  assert.equal(EntityType.NAME, EntityType.PERSON_NAME);
  assert.equal(String(EntityType.NAME), "PERSON_NAME");
});

test("legacy type names canonicalise", () => {
  assert.equal(canonicalType("NAME"), "PERSON_NAME");
  assert.equal(canonicalType("IBAN"), "BANK_ACCOUNT");
  assert.equal(canonicalType("STREET_ADDRESS"), "ADDRESS");
  assert.equal(canonicalType("NATIONALITY_ETHNICITY"), "SENSITIVE_ATTRIBUTE");
});

test("an unknown type is passed through, not dropped", () => {
  assert.equal(canonicalType("BRAND_NEW_TYPE"), "BRAND_NEW_TYPE");
});

test("the cloud-only types exist", () => {
  for (const t of ["ORGANISATION_NAME", "JOB_TITLE", "MEDICAL_CONDITION",
                   "SENSITIVE_ATTRIBUTE", "BIOMETRIC_REF", "FINANCIAL_AMOUNT",
                   "QUASI_IDENTIFIER", "CREDENTIAL", "URL"]) {
    assert.ok((Object.values(EntityType) as string[]).includes(t), `${t} missing`);
  }
});

// ── Configuration ──────────────────────────────────────────────────────────

test("configure without a key anywhere throws", () => {
  const saved = process.env.EUREDACT_API_KEY;
  delete process.env.EUREDACT_API_KEY;
  try {
    assert.throws(() => configure(), /no API key/);
  } finally {
    if (saved !== undefined) process.env.EUREDACT_API_KEY = saved;
  }
});

test("configure reads the environment", () => {
  const saved = process.env.EUREDACT_API_KEY;
  process.env.EUREDACT_API_KEY = "erk_from_env";
  try {
    assert.equal(configure().apiKey, "erk_from_env");
  } finally {
    if (saved === undefined) delete process.env.EUREDACT_API_KEY;
    else process.env.EUREDACT_API_KEY = saved;
  }
});

test("a trailing slash on baseUrl is normalised", () => {
  assert.equal(configure({ apiKey: "k", baseUrl: "https://api.test/" }).baseUrl,
               "https://api.test");
});

test("an unconfigured CloudClient throws NotConfiguredError", () => {
  assert.throws(() => new CloudClient(), NotConfiguredError);
});

// ── The happy path ─────────────────────────────────────────────────────────

testAsync("redact returns cloud detections", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([{ status: 200, body: SUCCESS }]);
  const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });

  assert.equal(calls[0].url, "https://api.test/v1/redact");
  assert.equal(calls[0].headers.get("Authorization"), "Bearer erk_test");
  assert.ok(calls[0].headers.get("Idempotency-Key"), "must send an Idempotency-Key");
  assert.equal(JSON.parse(calls[0].body!).country, "BE");

  assert.equal(r.source, "cloud");
  assert.ok(!r.redactedText.includes("Bas Verhoeven"));
  const byType = new Map(r.detections.map(d => [d.entityType, d]));
  assert.equal(byType.get(EntityType.PERSON_NAME)!.source, DetectionSource.CLOUD);
  assert.equal(byType.get(EntityType.PHONE)!.source, DetectionSource.RULES);
});

testAsync("redactAsync routes rules mode without a network call", async () => {
  let called = false;
  const impl: typeof fetch = async () => { called = true; return new Response("{}"); };
  void impl;
  const r = await redactAsync(DOC, { countries: ["BE"] });
  assert.equal(r.source, "rules");
  assert.equal(called, false);
});

testAsync("detections come back sorted by position", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const reversed = { ...SUCCESS, entities: [...SUCCESS.entities].reverse() };
  const { impl } = scripted([{ status: 200, body: reversed }]);
  const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
  const starts = r.detections.map(d => d.start);
  assert.deepEqual(starts, [...starts].sort((a, b) => a - b));
});

testAsync("service offsets are code points and land on the right UTF-16 units", async () => {
  // The service counts code points; one emoji before a span shifts every
  // later offset by one UTF-16 unit unless the client converts.
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const doc = "🎉 Patiënt Bas Verhoeven, mail bas@example.be";
  const { impl } = scripted([{ status: 200, body: {
    ...SUCCESS,
    redacted_text: "🎉 Patiënt [PERSON_NAME], mail [EMAIL]",
    entities: [
      { start: 10, end: 23, text: "Bas Verhoeven", type: "PERSON_NAME", source: "model" },
      { start: 30, end: 44, text: "bas@example.be", type: "EMAIL", source: "rules" },
    ],
  } }]);
  const r = await new CloudClient().redact(doc, { country: "BE", fetchImpl: impl });
  for (const d of r.detections) assert.equal(doc.slice(d.start, d.end), d.text);
});

testAsync("an unknown type survives as a string", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl } = scripted([{ status: 200, body: {
    ...SUCCESS,
    entities: [{ start: 0, end: 7, text: "Patiënt", type: "BRAND_NEW_TYPE",
                 source: "model" }],
  } }]);
  const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
  assert.equal(r.detections[0].entityType, "BRAND_NEW_TYPE");
});

// ── The 202 -> polling upgrade ─────────────────────────────────────────────

testAsync("a job past the sync window is polled transparently", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test", pollTimeoutMs: 5000 });
  const { impl, calls } = scripted([
    { status: 202, body: { job_id: "job-1", location: "/v1/jobs/job-1" },
      headers: { Location: "/v1/jobs/job-1" } },
    { status: 200, body: { job_id: "job-1", status: "running" },
      headers: { "Retry-After": "0" } },
    { status: 200, body: SUCCESS },
  ]);
  const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
  assert.equal(r.source, "cloud");
  assert.ok(calls[0].url.endsWith("/v1/redact"));
  assert.ok(calls[1].url.endsWith("/v1/jobs/job-1"));
  assert.ok(!r.redactedText.includes("Bas Verhoeven"));
});

testAsync("polling gives up eventually", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test", pollTimeoutMs: 150 });
  const { impl } = scripted([
    { status: 202, body: { job_id: "j", location: "/v1/jobs/j" },
      headers: { Location: "/v1/jobs/j" } },
    { status: 200, body: { job_id: "j", status: "running" },
      headers: { "Retry-After": "0" } },
  ]);
  await assert.rejects(
    () => new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl }),
    /did not complete/,
  );
});

// ── Errors ─────────────────────────────────────────────────────────────────

testAsync("413 is permanent and not retried", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([
    { status: 413, body: { error: "prompt is 9000 tokens, over the 6400 limit" } },
  ]);
  await assert.rejects(
    () => new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl }),
    TooLargeError,
  );
  assert.equal(calls.length, 1, "413 is permanent; retrying walks into the same wall");
});

testAsync("401 is not retried", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([{ status: 401, body: { error: "invalid API key" } }]);
  await assert.rejects(
    () => new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl }),
    /authentication failed/,
  );
  assert.equal(calls.length, 1);
});

testAsync("429 is retried then surfaces as QuotaExceededError", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test", maxRetries: 2 });
  const { impl, calls } = scripted([
    { status: 429, body: { error: "daily quota exhausted",
                           detail: { used: 100, limit: 100 } },
      headers: { "Retry-After": "0" } },
  ]);
  await assert.rejects(
    () => new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl }),
    QuotaExceededError,
  );
  assert.equal(calls.length, 3, "initial attempt plus two retries");
});

testAsync("a transient 5xx recovers", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([
    { status: 502, body: { error: "bad gateway" }, headers: { "Retry-After": "0" } },
    { status: 200, body: SUCCESS },
  ]);
  const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
  assert.equal(r.source, "cloud");
  assert.equal(calls.length, 2);
});

testAsync("a retry reuses the idempotency key", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([
    { status: 503, body: { error: "nope" }, headers: { "Retry-After": "0" } },
    { status: 200, body: SUCCESS },
  ]);
  await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].headers.get("Idempotency-Key"),
               calls[1].headers.get("Idempotency-Key"));
});

// ── Options the service cannot honour ──────────────────────────────────────

const sdk = new EuRedact();
const unsupported: Array<[string, Record<string, unknown>, RegExp]> = [
  ["no countries", {}, /exactly one country/],
  ["two countries", { countries: ["BE", "NL"] }, /exactly one country/],
  ["countryHint", { countries: ["BE"], countryHint: ["NL"] }, /countryHint/],
  ["referentialIntegrity", { countries: ["BE"], referentialIntegrity: true },
   /referentialIntegrity/],
  ["chunkOffset", { countries: ["BE"], chunkOffset: 10 }, /chunkOffset/],
];
for (const [label, options, match] of unsupported) {
  testAsync(`cloud mode rejects ${label} rather than ignoring it`, async () => {
    configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
    await assert.rejects(
      () => sdk.redactAsync(DOC, { ...options, mode: "cloud" }),
      match,
    );
  });
}

// ── Local-first: what is sent, and where the answer lands (rules-engine#28) ─

interface Wire {
  sent: Array<Record<string, unknown>>;
  /** The one `text` that was sent. */
  text(): string;
}

/**
 * Run `fn` with `mode: "cloud"` going through the real client and a stand-in
 * service that follows the local-first contract: it looks for `found` in the
 * text it *received* and answers with code-point spans relative to that text.
 * It never sees the caller's original, so a test that passes here cannot be
 * relying on it.
 */
async function withWire(
  script: { found?: Record<string, string>; entities?: unknown[]; usage?: unknown },
  fn: (wire: Wire) => Promise<void>,
): Promise<void> {
  const realFetch = globalThis.fetch;
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const sent: Array<Record<string, unknown>> = [];
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    sent.push(body);
    const text = body.text as string;
    let entities = script.entities;
    if (!entities) {
      entities = [];
      const codePoints = (units: number): number => [...text.slice(0, units)].length;
      for (const [needle, type] of Object.entries(script.found ?? {})) {
        for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + 1)) {
          entities.push({
            start: codePoints(at), end: codePoints(at + needle.length), text: needle,
            type, source: "model", match: "exact_body",
          });
        }
      }
    }
    return new Response(
      JSON.stringify({
        job_id: "job-1", status: "succeeded", redacted_text: text, entities, unlocated: [],
        ...(script.usage !== undefined ? { usage: script.usage } : {}),
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };
  try {
    await fn({
      sent,
      text: () => {
        assert.equal(sent.length, 1, "exactly one request per document");
        return sent[0].text as string;
      },
    });
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

const PAYMENT = "Joren Janssens needs to pay 50EUR to Nick Bols on NL91 ABNA 0417 1643 00";
const LEDGER = "IBAN NL91 ABNA 0417 1643 00 belongs to Nick Bols, tel +31 6 12345678";
const VISIT = "Bezoekadres: Kerkstraat 12, 9000 Gent. Contact: jan@example.be";
const cloudNL = { countries: ["NL"], mode: "cloud" };
const cloudBE = { countries: ["BE"], mode: "cloud" };

// The claim the documentation makes: identifiers the rules engine can find
// are replaced on the caller's machine, before the request exists.
testAsync("cloud mode sends only the locally masked text", () =>
  withWire({}, async wire => {
    await new EuRedact().redactAsync(PAYMENT, cloudNL);
    assert.equal(wire.text(), "Joren Janssens needs to pay 50EUR to Nick Bols on [BANK_ACCOUNT]");
    assert.ok(!JSON.stringify(wire.sent).includes("NL91"));
  }));

// One `text` field: no types list, no offsets, no values beside it.
testAsync("nothing structured travels with the text", () =>
  withWire({}, async wire => {
    await new EuRedact().redactAsync(PAYMENT, cloudNL);
    assert.deepEqual(wire.sent[0], {
      text: "Joren Janssens needs to pay 50EUR to Nick Bols on [BANK_ACCOUNT]",
      country: "NL", language: "", priority: "interactive",
    });
  }));

// The service indexes the masked text; the caller gets the original's.
testAsync("service spans are mapped back onto the original", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async wire => {
    const r = await new EuRedact().redactAsync(LEDGER, cloudNL);
    assert.equal(wire.text(), "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]");
    assert.equal(r.source, "cloud");
    assert.equal(r.redactedText, "IBAN [BANK_ACCOUNT] belongs to [PERSON_NAME], tel [PHONE]");
    assert.deepEqual(r.detections.map(d => [d.entityType, d.text, d.source]), [
      [EntityType.BANK_ACCOUNT, "NL91 ABNA 0417 1643 00", DetectionSource.RULES],
      [EntityType.PERSON_NAME, "Nick Bols", DetectionSource.CLOUD],
      [EntityType.PHONE, "+31 6 12345678", DetectionSource.RULES],
    ]);
    for (const d of r.detections) assert.equal(LEDGER.slice(d.start, d.end), d.text);
  }));

// The model was trained on `[TYPE]`; a token on the wire would be read as
// ordinary text. Tokens are minted locally, after the response.
testAsync("tokenize does not change what is sent", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async wire => {
    const r = await new EuRedact().redactAsync(LEDGER, { ...cloudNL, tokenize: true });
    assert.equal(wire.text(), "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]");
    assert.equal(Object.keys(r.tokens).length, 3);
    assert.ok(!r.redactedText.includes("["));
    assert.equal(restore(r.redactedText, r.tokens), LEDGER);
  }));

// An exemption says what the caller wants back, not what may leave.
testAsync("an allowlisted value is still masked on the wire", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async wire => {
    const r = await new EuRedact({ allowlist: ["NL91ABNA0417164300"] }).redactAsync(LEDGER, cloudNL);
    assert.equal(wire.text(), "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]");
    assert.equal(r.redactedText, "IBAN NL91 ABNA 0417 1643 00 belongs to [PERSON_NAME], tel [PHONE]");
    assert.deepEqual(r.exempted.map(e => e.text), ["NL91 ABNA 0417 1643 00"]);
  }));

testAsync("an allowlisted cloud type is exempted after the response", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async () => {
    const r = await new EuRedact().redactAsync(LEDGER, { ...cloudNL, allowlist: ["Nick Bols"] });
    assert.equal(r.redactedText, "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]");
    assert.deepEqual(r.exempted.map(e => e.text), ["Nick Bols"]);
  }));

// The model is trained against rules output with dates on, and a date of
// birth the rules can place has no reason to travel.
testAsync("dates are masked before sending whatever detectDates says", () =>
  withWire({}, async wire => {
    const r = await new EuRedact().redactAsync("Mevrouw Peeters, geboren op 12/03/1985, woont in Gent.", cloudBE);
    assert.equal(wire.text(), "Mevrouw Peeters, geboren op [DOB], woont in Gent.");
    assert.deepEqual(r.detections.map(d => d.entityType), [EntityType.DOB]);
  }));

// The service has never heard of the caller's own patterns.
testAsync("custom patterns are masked before sending", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async wire => {
    const custom = new EuRedact();
    custom.addCustomPattern("EMPLOYEE_ID", "EMP-\\d{6}");
    const r = await custom.redactAsync("Badge EMP-004211 van Nick Bols", cloudBE);
    assert.equal(wire.text(), "Badge [EMPLOYEE_ID] van Nick Bols");
    assert.equal(r.redactedText, "Badge [EMPLOYEE_ID] van [PERSON_NAME]");
  }));

// An address the model reports around a locally masked postal code.
testAsync("a span across a placeholder takes the whole local detection", () =>
  withWire({ found: { "Kerkstraat 12, [POSTAL_CODE] Gent": "ADDRESS" } }, async () => {
    const r = await new EuRedact().redactAsync(VISIT, { ...cloudBE, tokenize: true });
    const address = r.detections.find(d => d.entityType === EntityType.ADDRESS)!;
    assert.equal(address.text, "Kerkstraat 12, 9000 Gent");
    assert.equal(VISIT.slice(address.start, address.end), address.text);
    assert.ok(!r.redactedText.includes("9000"));
    assert.ok(!r.redactedText.includes("POSTAL_CODE"), "the address covers it");
    assert.equal(restore(r.redactedText, r.tokens), VISIT);
  }));

// Offsets inside a label have no counterpart in the original, so they snap
// outward: over-masking is the safe direction.
testAsync("a span that ends inside a placeholder never splits the value", () =>
  withWire({ entities: [
    { start: 13, end: 31, text: "Kerkstraat 12, [PO", type: "ADDRESS", source: "model" },
  ] }, async wire => {
    const r = await new EuRedact().redactAsync(VISIT, cloudBE);
    assert.equal(wire.text(), "Bezoekadres: Kerkstraat 12, [POSTAL_CODE] Gent. Contact: [EMAIL]");
    assert.equal(r.redactedText, "Bezoekadres: [ADDRESS] Gent. Contact: [EMAIL]");
  }));

// The label is not part of the document; the local detection stands.
testAsync("a span naming only a placeholder adds nothing", () =>
  withWire({ found: { "[BANK_ACCOUNT]": "BANK_ACCOUNT", "Nick Bols": "PERSON_NAME" } }, async () => {
    const r = await new EuRedact().redactAsync(LEDGER, cloudNL);
    assert.deepEqual(r.detections.map(d => d.entityType),
      [EntityType.BANK_ACCOUNT, EntityType.PERSON_NAME, EntityType.PHONE]);
    assert.equal(r.detections[0].source, DetectionSource.RULES);
  }));

// Not only under tokenize: every span now has to be placed locally, and one
// that cannot be would mask the wrong characters.
testAsync("a span that does not match the sent text throws", () =>
  withWire({ entities: [
    { start: 0, end: 9, text: "Nick Bols", type: "PERSON_NAME", source: "model" },
  ] }, async () => {
    await assert.rejects(
      new EuRedact().redactAsync(LEDGER, cloudNL),
      (e: unknown) => e instanceof CloudError && /span offsets/.test(e.message),
    );
  }));

testAsync("a span past the end of the sent text throws", () =>
  withWire({ entities: [
    { start: 50, end: 500, text: "x", type: "PERSON_NAME", source: "model" },
  ] }, async () => {
    await assert.rejects(
      new EuRedact().redactAsync(LEDGER, cloudNL),
      (e: unknown) => e instanceof CloudError && /span offsets/.test(e.message),
    );
  }));

// NFD input changes length under NFC, and an emoji is two UTF-16 units: both
// sit between the service's numbers and the caller's.
testAsync("offsets survive normalisation and astral characters", () =>
  withWire({ found: { "Anna Berger": "PERSON_NAME" } }, async wire => {
    const doc = ("\u{1F600} Patiënt René Müller, IBAN NL91 ABNA 0417 1643 00, " +
                 "arts Zoë Smit \u{1F600} en Anna Berger").normalize("NFD");
    const r = await new EuRedact().redactAsync(doc, cloudNL);
    assert.ok(!wire.text().includes("NL91") && wire.text().includes("[BANK_ACCOUNT]"));
    const name = r.detections.find(d => d.entityType === EntityType.PERSON_NAME)!;
    assert.equal(doc.slice(name.start, name.end), "Anna Berger");
    assert.equal(r.redactedText, doc
      .replace("NL91 ABNA 0417 1643 00", "[BANK_ACCOUNT]")
      .replace("Anna Berger", "[PERSON_NAME]"));
  }));

testAsync("the local evidence is reported in cloud mode", () =>
  withWire({}, async () => {
    const r = await new EuRedact().redactAsync(LEDGER, cloudNL);
    assert.equal(r.detectionMode, "declared");
    assert.ok(new Map(r.inferredCountries).get("NL"));
  }));

// The local pass shares the result cache with rules mode.
testAsync("a cached rules result is not mutated by cloud mode", () =>
  withWire({ found: { "Nick Bols": "PERSON_NAME" } }, async () => {
    const shared = new EuRedact();
    await shared.redactAsync(LEDGER, cloudNL);
    const rules = shared.redact(LEDGER, { countries: ["NL"], detectDates: true });
    assert.equal(rules.source, "rules");
    assert.equal(rules.redactedText, "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]");
    assert.equal(rules.detections.length, 2);
  }));

// It never had a public surface in the SDK, and from a local-first client it
// means nothing: the rules already ran.
testAsync("the client has no rulesOnly switch", async () => {
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  const { impl, calls } = scripted([{ status: 200, body: SUCCESS }]);
  await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl, rulesOnly: true } as never);
  assert.ok(!("rules_only" in JSON.parse(calls[0].body!)));
});

// ── Report ─────────────────────────────────────────────────────────────────

// ── What a request cost (rules-engine#89) ──────────────────────────────────

const USAGE = JSON.parse(
  readFileSync(new URL("../../../conformance/cloud_usage.json", import.meta.url), "utf8"),
) as { cases: Array<{ id: string; usage?: unknown; expect: unknown }> };

/** The parsed Usage in the wire's snake_case, to compare with the shared expectation. */
function asWire(usage: Usage | undefined): unknown {
  if (!usage) return null;
  return {
    tokens: usage.tokens, billing_rate: usage.billingRate, credits: usage.credits,
    factors: usage.factors.map(f => ({ code: f.code, detail: f.detail, types: f.types ?? null })),
  };
}

for (const c of USAGE.cases) {
  testAsync(`the usage block is read as both SDKs read it: ${c.id}`, async () => {
    configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
    const body = "usage" in c ? { ...SUCCESS, usage: c.usage } : SUCCESS;
    const { impl } = scripted([{ status: 200, body }]);
    const r = await new CloudClient().redact(DOC, { country: "BE", fetchImpl: impl });
    assert.deepEqual(asWire(r.usage), c.expect);
  });
}

testAsync("usage reaches the caller through cloud mode", () =>
  withWire({ usage: USAGE.cases[0].usage }, async () => {
    const r = await new EuRedact().redactAsync(PAYMENT, cloudNL);
    assert.deepEqual(asWire(r.usage), USAGE.cases[0].expect);
  }));

test("a rules result has no usage", () => {
  assert.equal(redact(DOC, { countries: ["BE"] }).usage, undefined);
});

const run = async (): Promise<void> => {
  for (const [name, fn] of asyncTests) {
    try {
      reset();
      await fn();
      passed++;
    } catch (e) {
      failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
    } finally {
      reset();
    }
  }
  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("\nFAILURES:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
};

void run();
