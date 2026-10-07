/**
 * [CLOUD EXTENSION] Everything an API key can do, through the SDK (rules-engine#89).
 *
 * Mirrors euredact-python/tests/test_cloud_api.py. The parsing cases live in
 * conformance/cloud_result.json and run in both SDKs; the rest pins what is
 * retried, what throws, and which request each call makes.
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Account, Jobs } from "../cloud/account.js";
import { Batches } from "../cloud/batches.js";
import { CloudClient } from "../cloud/client.js";
import { configure, reset, type CloudConfig } from "../cloud/config.js";
import {
  CloudError,
  NotFoundError,
  QuotaExceededError,
  RateLimitedError,
  ResultExpiredError,
} from "../cloud/errors.js";
import { EuRedact } from "../sdk.js";
import { redact } from "../index.js";

type Json = Record<string, unknown>;
const CASES = JSON.parse(
  readFileSync(new URL("../../../conformance/cloud_result.json", import.meta.url), "utf8"),
) as {
  results: Array<{ id: string; wire: Json; expect: Json }>;
  throttling: Array<{ id: string; status: number; json?: Json; text?: string; expect: string }>;
  batches: Array<{ id: string; wire: Json; expect: Json }>;
  account: Record<string, { wire: Json; expect: unknown }>;
};
const ACCOUNT = CASES.account;
const DOC = "Patiënt Bas Verhoeven, tel +32 475 12 34 56";

/** camelCase field names to the Python names the shared expectations use. */
function snake(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(snake);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Json)
      .filter(([k]) => k !== "raw")
      .map(([k, v]) => [k.replace(/([A-Z])/g, "_$1").replace(/([a-z])(\d)/g, "$1_$2").toLowerCase(), snake(v)]));
  }
  return value;
}

/** A scripted service: answers in order (the last one repeats), records every request. */
function service(...answers: Array<{ status: number; json?: unknown; text?: string }>) {
  const requests: Array<{ url: URL; method: string; headers: Headers }> = [];
  let i = 0;
  const fetchImpl: typeof fetch = async (input, init) => {
    requests.push({ url: new URL(String(input)), method: init?.method ?? "GET",
                    headers: new Headers(init?.headers as HeadersInit) });
    const a = answers[Math.min(i++, answers.length - 1)];
    return a.text !== undefined
      ? new Response(a.text, { status: a.status, headers: { "Content-Type": "text/html", "Retry-After": "0" } })
      : new Response(JSON.stringify(a.json ?? {}), {
        status: a.status, headers: { "Content-Type": "application/json", "Retry-After": "0" } });
  };
  return { requests, fetchImpl };
}

function config(extra: Partial<CloudConfig> = {}): CloudConfig {
  return configure({ apiKey: "erk_test", baseUrl: "https://api.test", ...extra });
}

let passed = 0;
const failures: string[] = [];
const tests: Array<[string, () => Promise<void>]> = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);

// ── a result's cloud block ──────────────────────────────────────────────────

for (const c of CASES.results) {
  test(`the cloud block is read as both SDKs read it: ${c.id}`, async () => {
    config();
    const { fetchImpl } = service({ status: 200, json: c.wire });
    const cloud = (await new CloudClient().redact(DOC, { country: "BE", fetchImpl })).cloud!;
    assert.deepEqual({
      job_id: cloud.jobId, model_version: cloud.modelVersion, has_usage: cloud.usage !== undefined,
      unlocated: cloud.unlocated.map(u => ({ text: u.text, entity_type: String(u.entityType) })),
    }, c.expect);
  });
}

// ── which 429 is final ──────────────────────────────────────────────────────

for (const c of CASES.throttling) {
  test(`a quota 429 is final and an edge 429 is retried: ${c.id}`, async () => {
    config({ maxRetries: 2 } as Partial<CloudConfig>);
    const { fetchImpl, requests } = service({ status: c.status, json: c.json, text: c.text });
    const err = await new CloudClient().redact(DOC, { country: "BE", fetchImpl }).then(() => null, e => e);
    assert.ok(err instanceof QuotaExceededError);
    if (c.expect === "quota") {
      assert.ok(!(err instanceof RateLimitedError));
      assert.equal(requests.length, 1);
    } else {
      assert.ok(err instanceof RateLimitedError);
      assert.equal(requests.length, 3);
    }
  });
}

// ── top-level idempotency key ───────────────────────────────────────────────

test("redactAsync in cloud mode sends the caller's idempotency key", async () => {
  config();
  const { fetchImpl, requests } = service({ status: 200, json: {
    job_id: "job-1", status: "succeeded", redacted_text: "x", entities: [] } });
  const realFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    const r = await new EuRedact().redactAsync(DOC, {
      countries: ["BE"], mode: "cloud", idempotencyKey: "invoice-2291-v1" });
    assert.equal(requests[0].headers.get("Idempotency-Key"), "invoice-2291-v1");
    assert.equal(r.cloud?.jobId, "job-1");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("an idempotency key without cloud mode throws", async () => {
  assert.throws(() => redact(DOC, { countries: ["BE"], idempotencyKey: "k" }), /mode: "cloud" only/);
});

// ── batches ─────────────────────────────────────────────────────────────────

function batches(fetchImpl: typeof fetch): Batches {
  const dir = mkdtempSync(join(tmpdir(), "euredact-cloudapi-"));
  return new Batches({ config: config(), fetchImpl, batchDir: join(dir, "batches") });
}

for (const c of CASES.batches) {
  test(`a batch carries its cost: ${c.id}`, async () => {
    const { fetchImpl } = service({ status: 200, json: c.wire });
    const batch = snake(await batches(fetchImpl).retrieve(String(c.wire.id))) as Json;
    assert.deepEqual(Object.fromEntries(Object.keys(c.expect).map(k => [k, batch[k]])), c.expect);
  });
}

test("Batches.list asks for the limit and types each batch", async () => {
  const { fetchImpl, requests } = service({ status: 200, json: { batches: [CASES.batches[0].wire, "junk"] } });
  const b = batches(fetchImpl);
  const listed = await b.list(5);
  assert.equal(requests[0].url.pathname, "/v1/batches");
  assert.equal(requests[0].url.searchParams.get("limit"), "5");
  assert.deepEqual(listed.map(x => x.id), ["b1"]);
  assert.equal(listed[0].creditsCharged, 765);
  await assert.rejects(() => b.list(101), RangeError);
});

// ── account ─────────────────────────────────────────────────────────────────

function account(...answers: Array<{ status: number; json?: unknown }>) {
  const s = service(...answers);
  return { ...s, account: new Account(config(), { fetchImpl: s.fetchImpl }) };
}

test("account summary", async () => {
  for (const name of ["summary", "summary_without_quota"]) {
    const { account: a, requests } = account({ status: 200, json: ACCOUNT[name].wire });
    assert.deepEqual(snake(await a.summary()), ACCOUNT[name].expect);
    assert.equal(requests[0].url.pathname, "/v1/account");
  }
});

test("account credits", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.credits.wire });
  assert.deepEqual(snake(await a.credits()), ACCOUNT.credits.expect);
  assert.equal(requests[0].url.pathname, "/v1/account/credits");
});

test("account credit history", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.credit_history.wire });
  assert.deepEqual(snake(await a.creditHistory(10)), ACCOUNT.credit_history.expect);
  assert.equal(requests[0].url.pathname, "/v1/account/credits/history");
  assert.equal(requests[0].url.searchParams.get("limit"), "10");
});

test("account usage", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.usage.wire });
  assert.deepEqual(snake(await a.usage(2)), ACCOUNT.usage.expect);
  assert.equal(requests[0].url.pathname, "/v1/account/usage");
  assert.equal(requests[0].url.searchParams.get("days"), "2");
});

test("account usage by key", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.usage_by_key.wire });
  assert.deepEqual(snake(await a.usageByKey(1)), ACCOUNT.usage_by_key.expect);
  assert.equal(requests[0].url.pathname, "/v1/account/usage/by-key");
});

test("account keys", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.keys.wire });
  assert.deepEqual(snake(await a.keys()), ACCOUNT.keys.expect);
  assert.equal(requests[0].url.pathname, "/v1/account/keys");
});

test("revoking a key is one POST", async () => {
  const { account: a, requests } = account({ status: 200, json: ACCOUNT.revoke_key.wire });
  assert.deepEqual(snake(await a.revokeKey(3)), ACCOUNT.revoke_key.expect);
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].url.pathname, "/v1/account/keys/3/revoke");
});

test("a revocation is never retried", async () => {
  const { account: a, requests } = account({ status: 503, json: { error: "restarting" } });
  const err = await a.revokeKey(3).then(() => null, e => e);
  assert.ok(err instanceof CloudError && err.status === 503);
  assert.equal(requests.length, 1);
});

test("revoking twice or a foreign key throws", async () => {
  let err = await account({ status: 409, json: { ok: false, error: "already revoked" } })
    .account.revokeKey(3).then(() => null, e => e);
  assert.ok(err instanceof CloudError && err.status === 409);
  err = await account({ status: 404, json: { ok: false, error: "no such key" } })
    .account.revokeKey(99).then(() => null, e => e);
  assert.ok(err instanceof NotFoundError);
});

test("a read is retried through a transient error", async () => {
  const { account: a, requests } = account({ status: 503, json: {} }, { status: 200, json: ACCOUNT.credits.wire });
  assert.equal((await a.credits()).balance, 94880);
  assert.equal(requests.length, 2);
});

test("an origin refusal surfaces as a 403", async () => {
  const err = await account({ status: 403, json: { error: "origin not allowed" } })
    .account.summary().then(() => null, e => e);
  assert.ok(err instanceof CloudError && err.status === 403);
});

test("account arguments are bounded", async () => {
  const { account: a } = account({ status: 200, json: {} });
  await assert.rejects(() => a.creditHistory(0), RangeError);
  await assert.rejects(() => a.usage(0), RangeError);
});

// ── jobs ────────────────────────────────────────────────────────────────────

function jobs(...answers: Array<{ status: number; json?: unknown }>) {
  const s = service(...answers);
  return { ...s, jobs: new Jobs(config(), { fetchImpl: s.fetchImpl }) };
}

for (const name of ["job_pending", "job_succeeded"]) {
  test(`a job is retrieved by id: ${name}`, async () => {
    const c = ACCOUNT[name];
    const { jobs: j, requests } = jobs({ status: 200, json: c.wire });
    const job = await j.retrieve(String(c.wire.job_id));
    assert.deepEqual({ job_id: job.jobId, status: job.status, created_at: job.createdAt,
                       has_result: job.result !== null }, c.expect);
    assert.equal(requests[0].url.pathname, `/v1/jobs/${c.wire.job_id}`);
  });
}

test("a retrieved result is over the text the service received", async () => {
  const result = (await jobs({ status: 200, json: ACCOUNT.job_succeeded.wire }).jobs.retrieve("job-7f3a")).result!;
  assert.equal(result.redactedText, "Patiënt [PERSON_NAME]");
  assert.equal(result.detections[0].text, "Bas Verhoeven");
  assert.equal(result.cloud?.jobId, "job-7f3a");
});

test("an expired result throws rather than reading as empty", async () => {
  await assert.rejects(
    () => jobs({ status: 410, json: { error: "result payload is no longer retained" } }).jobs.retrieve("job-old"),
    ResultExpiredError);
});

test("an unknown job throws NotFoundError", async () => {
  await assert.rejects(() => jobs({ status: 404, json: { error: "job not found" } }).jobs.retrieve("job-nope"),
    NotFoundError);
});

// ── runner ──────────────────────────────────────────────────────────────────

const run = async (): Promise<void> => {
  for (const [name, fn] of tests) {
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
