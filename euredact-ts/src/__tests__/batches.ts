/**
 * Batches keep the structured PII local (rules-engine#84). Mirrors
 * euredact-python/tests/test_batches.py against the same fake gateway, and runs
 * the shared conformance/batches.json, so both SDKs hold the same contract.
 * Run with `npm run test:batches`.
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { Batches, BatchError, MAX_DOCUMENTS, type BatchStore } from "../cloud/batches.js";
import { EuRedact, maskForCloud } from "../sdk.js";
import type { CloudConfig } from "../cloud/config.js";

const IBAN = "BE68 5390 0754 7034";
const TEXT = `Beste, gelieve ${IBAN} te crediteren voor Jan Peeters. Groeten.`;
const NAME = "Jan Peeters";
const CONFIG: CloudConfig = {
  apiKey: "erk_test", baseUrl: "https://gw.test", timeoutMs: 1000, pollTimeoutMs: 1000,
  maxRetries: 0, headers: {},
};

/** Code points, as the real gateway counts them. */
const cpIndex = (s: string, sub: string): number => {
  const at = s.indexOf(sub);
  return at < 0 ? -1 : Array.from(s.slice(0, at)).length;
};

class FakeGateway {
  uploaded: Array<Record<string, unknown>> = [];
  rawBodies: string[] = [];
  status = "in_progress";
  resultsStatus = 200;
  resultsExpireAt = "2099-01-01T00:00:00Z";
  override: Record<string, Record<string, unknown>> = {};

  fetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const path = url.pathname;
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    if (method === "POST" && path === "/v1/batches") {
      let body = Buffer.from(init!.body as Uint8Array);
      const headers = init!.headers as Record<string, string>;
      if (headers["Content-Encoding"] === "gzip") body = gunzipSync(body);
      const text = body.toString("utf-8");
      this.rawBodies.push(text);
      this.uploaded = text.split("\n").filter(Boolean).map(l => JSON.parse(l));
      return json(201, this.batch("validating"));
    }
    if (method === "GET" && path === "/v1/batches/bat_1") return json(200, this.batch(this.status));
    if (method === "POST" && path === "/v1/batches/bat_1/cancel") {
      this.status = "cancelling";
      return json(200, this.batch("cancelling"));
    }
    if (method === "GET" && path === "/v1/batches/bat_1/results") {
      if (this.resultsStatus !== 200) return json(this.resultsStatus, { error: "no" });
      const lines = this.uploaded.map(d => JSON.stringify({
        custom_id: d.custom_id,
        result: this.override[d.custom_id as string] ?? FakeGateway.succeeded(d.text as string),
      }));
      return new Response(lines.join("\n") + "\n", { status: 200 });
    }
    return json(404, { error: "not found" });
  };

  batch(status: string) {
    return {
      id: "bat_1", status, created_at: "2026-10-06T10:00:00Z", expires_at: "2026-10-07T10:00:00Z",
      results_expire_at: status === "ended" ? this.resultsExpireAt : null, counts: {},
    };
  }

  static succeeded(masked: string) {
    const start = cpIndex(masked, NAME);
    return {
      type: "succeeded",
      masked_sha256: createHash("sha256").update(masked).digest("hex"),
      entities: start < 0 ? [] : [{ type: "PERSON_NAME", start, end: start + NAME.length, text: NAME, source: "model" }],
    };
  }
}

const docs = (n = 1) =>
  Array.from({ length: n }, (_, i) => ({ customId: `doc-${i}`, text: TEXT, countries: ["BE"] }));

function setup(extra: Partial<ConstructorParameters<typeof Batches>[0]> = {}) {
  const gateway = new FakeGateway();
  const dir = mkdtempSync(join(tmpdir(), "euredact-batches-"));
  const batches = new Batches({ config: CONFIG, fetchImpl: gateway.fetch, batchDir: join(dir, "batches"), ...extra });
  return { gateway, dir: join(dir, "batches"), batches };
}

let passed = 0;
const failures: string[] = [];
const tests: Array<[string, () => Promise<void>]> = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);

// ── create ──────────────────────────────────────────────────────────────

test("only masked text is uploaded", async () => {
  const { gateway, batches } = setup();
  await batches.create(docs());
  assert.ok(!gateway.rawBodies[0].includes(IBAN) && gateway.rawBodies[0].includes("[BANK_ACCOUNT]"));
});

test("the local file is private and holds what mapping needs", async () => {
  const { batches, dir } = setup();
  const batch = await batches.create(docs());
  const path = join(dir, `${batch.id}.json`);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  const state = JSON.parse(readFileSync(path, "utf-8"));
  assert.equal(state.status, "pending");
  assert.equal(state.entries["doc-0"].text, TEXT);
});

test("what is sent is what cloud mode sends", async () => {
  const { gateway, batches } = setup();
  await batches.create(docs());
  const local = new EuRedact().redact(TEXT, { countries: ["BE"], detectDates: true, cache: false });
  assert.equal(gateway.uploaded[0].text, maskForCloud(TEXT, local.detections)[0]);
});

for (const [name, input, message] of [
  ["duplicate", [{ customId: "a", text: "x", countries: ["BE"] }, { customId: "a", text: "x", countries: ["BE"] }], /duplicate customId/],
  ["long id", [{ customId: "a".repeat(65), text: "x", countries: ["BE"] }], /longer than 64/],
  ["two countries", [{ customId: "a", text: "x", countries: ["BE", "NL"] }], /exactly one country/],
  ["empty", [], /at least one document/],
] as const) {
  test(`limits are checked before anything is sent: ${name}`, async () => {
    const { gateway, batches } = setup();
    await assert.rejects(batches.create(input as never), message);
    assert.equal(gateway.rawBodies.length, 0);
    assert.deepEqual(await batches.store.list(), []);
  });
}

test("more than the document limit is refused", async () => {
  const { gateway, batches } = setup();
  const many = Array.from({ length: MAX_DOCUMENTS + 1 }, (_, i) => ({ customId: `d${i}`, text: "x", countries: ["BE"] }));
  await assert.rejects(batches.create(many), BatchError);
  assert.equal(gateway.rawBodies.length, 0);
});

// ── results ─────────────────────────────────────────────────────────────

test("not ended changes nothing", async () => {
  const { batches, dir } = setup();
  const batch = await batches.create(docs());
  const before = readFileSync(join(dir, `${batch.id}.json`));
  assert.equal((await batches.results(batch.id)).status, "not_ended");
  assert.deepEqual(readFileSync(join(dir, `${batch.id}.json`)), before);
});

test("an ended batch is mapped onto the originals", async () => {
  const { gateway, batches } = setup();
  const batch = await batches.create(docs(2));
  gateway.status = "ended";
  const outcome = await batches.results(batch.id);
  assert.equal(outcome.status, "resolved");
  assert.equal(outcome.documents["doc-0"].result!.redactedText,
    "Beste, gelieve [BANK_ACCOUNT] te crediteren voor [PERSON_NAME]. Groeten.");
});

test("resolved once, then a text-free receipt", async () => {
  const { gateway, batches, dir } = setup();
  const batch = await batches.create(docs());
  gateway.status = "ended";
  await batches.results(batch.id);
  const raw = readFileSync(join(dir, `${batch.id}.json`), "utf-8");
  const state = JSON.parse(raw);
  assert.equal(state.status, "resolved");
  assert.deepEqual(state.entries, {});
  assert.ok(!raw.includes(IBAN) && !raw.includes(NAME));
  assert.equal((await batches.results(batch.id)).status, "already_resolved");
});

test("a changed local file is an error, not a wrong mapping", async () => {
  const { gateway, batches, dir } = setup();
  const batch = await batches.create(docs());
  const path = join(dir, `${batch.id}.json`);
  const state = JSON.parse(readFileSync(path, "utf-8"));
  state.entries["doc-0"].text = TEXT.replace("Beste", "Geachte");
  writeFileSync(path, JSON.stringify(state));
  gateway.status = "ended";
  const doc = (await batches.results(batch.id)).documents["doc-0"];
  assert.equal(doc.error, "local_mismatch");
  assert.equal(doc.result, null);
});

test("a hash the gateway disagrees with is an error", async () => {
  const { gateway, batches } = setup();
  const batch = await batches.create(docs());
  gateway.override["doc-0"] = { type: "succeeded", masked_sha256: "0".repeat(64), entities: [] };
  gateway.status = "ended";
  assert.equal((await batches.results(batch.id)).documents["doc-0"].error, "local_mismatch");
});

test("no local file is an error per document", async () => {
  const { gateway, batches } = setup();
  await batches.create(docs());
  await batches.purge("bat_1");
  gateway.status = "ended";
  assert.equal((await batches.results("bat_1")).documents["doc-0"].error, "missing_local_entry");
});

test("too_long says the SDK cannot check the token limit", async () => {
  const { gateway, batches } = setup();
  const batch = await batches.create(docs());
  gateway.override["doc-0"] = { type: "errored", error: { code: "too_long", message: "6,212 tokens" } };
  gateway.status = "ended";
  const doc = (await batches.results(batch.id)).documents["doc-0"];
  assert.equal(doc.error, "too_long");
  assert.match(doc.message, /cannot check it before upload/);
});

test("results gone from the gateway expire the file", async () => {
  const { gateway, batches, dir } = setup();
  const batch = await batches.create(docs());
  gateway.status = "ended";
  gateway.resultsStatus = 410;
  assert.equal((await batches.results(batch.id)).status, "expired");
  assert.deepEqual(JSON.parse(readFileSync(join(dir, `${batch.id}.json`), "utf-8")).entries, {});
});

// ── lifecycle and storage ───────────────────────────────────────────────

test("pending lists unresolved files; cancel keeps them", async () => {
  const { batches } = setup();
  const batch = await batches.create(docs());
  assert.equal((await batches.cancel(batch.id)).status, "cancelling");
  assert.deepEqual(await batches.pending(), [batch.id]);
});

test("sweep expires pending files and deletes receipts", async () => {
  const { gateway, batches, dir } = setup();
  const batch = await batches.create(docs());
  gateway.status = "ended";
  await batches.retrieve(batch.id);
  await batches.sweep(new Date("2099-01-02T00:00:00Z"));
  const state = JSON.parse(readFileSync(join(dir, `${batch.id}.json`), "utf-8"));
  assert.equal(state.status, "expired");
  await batches.sweep(new Date("2099-01-03T00:00:00Z"));
  assert.deepEqual(await batches.store.list(), []);
});

test("a cipher encrypts the file at rest", async () => {
  const xor = (d: Uint8Array) => d.map(b => b ^ 0x5a);
  const { gateway, batches, dir } = setup({ cipher: { encrypt: xor, decrypt: xor } });
  const batch = await batches.create(docs());
  const raw = readFileSync(join(dir, `${batch.id}.json`));
  assert.ok(!raw.includes(Buffer.from(IBAN)));
  gateway.status = "ended";
  assert.ok((await batches.results(batch.id)).documents["doc-0"].ok);
});

test("a caller-supplied store replaces the directory", async () => {
  const blobs = new Map<string, Uint8Array>();
  const store: BatchStore = {
    read: async id => blobs.get(id) ?? null,
    write: async (id, d) => void blobs.set(id, d),
    delete: async id => void blobs.delete(id),
    list: async () => [...blobs.keys()].sort(),
  };
  const gateway = new FakeGateway();
  const batches = new Batches({ config: CONFIG, fetchImpl: gateway.fetch, store });
  await batches.create(docs());
  gateway.status = "ended";
  assert.ok((await batches.results("bat_1")).documents["doc-0"].ok);
});

test("a plain-http base URL is refused", async () => {
  assert.throws(() => new Batches({ config: { ...CONFIG, baseUrl: "http://gw.test" } }), /https:\/\//);
});

// ── shared conformance vectors ──────────────────────────────────────────

const VECTORS = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "conformance", "batches.json"), "utf-8"));

for (const c of VECTORS.cases) {
  test(`vector: ${c.id}`, async () => {
    const { gateway, batches, dir } = setup();
    await batches.create([{ customId: c.id, text: c.text, countries: c.countries }]);
    assert.equal(gateway.uploaded[0].text, c.masked);
    const state = JSON.parse(readFileSync(join(dir, "bat_1.json"), "utf-8"));
    assert.equal(state.entries[c.id].masked_sha256, c.masked_sha256);
    gateway.override[c.id] = { type: "succeeded", masked_sha256: c.masked_sha256, entities: c.entities };
    gateway.status = "ended";
    const doc = (await batches.results("bat_1")).documents[c.id];
    assert.ok(doc.ok, doc.message);
    assert.equal(doc.result!.redactedText, c.redacted_text);
  });
}

test("vector: tampered original", async () => {
  const spec = VECTORS.mismatch;
  const c = VECTORS.cases.find((x: { id: string }) => x.id === spec.base);
  const { gateway, batches, dir } = setup();
  await batches.create([{ customId: c.id, text: c.text, countries: c.countries }]);
  const path = join(dir, "bat_1.json");
  const state = JSON.parse(readFileSync(path, "utf-8"));
  state.entries[c.id].text = spec.original_override;
  writeFileSync(path, JSON.stringify(state));
  gateway.override[c.id] = { type: "succeeded", masked_sha256: c.masked_sha256, entities: c.entities };
  gateway.status = "ended";
  assert.equal((await batches.results("bat_1")).documents[c.id].error, spec.expect_error);
});

for (const [name, fn] of tests) {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}
console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
