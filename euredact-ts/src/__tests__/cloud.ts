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
import { EuRedact } from "../sdk.js";
import { redact, redactAsync } from "../index.js";
import { CloudClient } from "../cloud/client.js";
import { configure, reset } from "../cloud/config.js";
import {
  CloudError,
  NotConfiguredError,
  QuotaExceededError,
  TooLargeError,
} from "../cloud/errors.js";
import { canonicalType, DetectionSource, EntityType } from "../types.js";

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

// ── Report ─────────────────────────────────────────────────────────────────

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
