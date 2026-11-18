/**
 * Cloud mode for documents over the input cap (rules-engine#183). Mirrors
 * tests/test_cloud_chunking.py: through the real client and a scripted service
 * that refuses anything over its cap with 413, finds the names it is told to
 * in whatever text it receives, and reports usage. The cut positions are
 * shared with the Python SDK in conformance/cloud_chunking.json.
 * Run with `npm run test:cloud-chunking`.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EuRedact } from "../sdk.js";
import { configure, reset } from "../cloud/config.js";
import { CloudError, TooLargeError } from "../cloud/errors.js";
import { plan } from "../cloud/chunking.js";
import type { ChunkInfo, RedactOptions } from "../index.js";

const IBAN = "NL91 ABNA 0417 1643 00";
const NAME = "Anneke Verbruggen";

/** A long Dutch letter: a name and an IBAN in every fourth paragraph. */
function documentText(paragraphs = 60): string {
  const out: string[] = [];
  for (let i = 0; i < paragraphs; i++) {
    let body = ("De patiënt kwam op controle en vertelde over de klachten van "
      + "de afgelopen weken. Er werd een vervolgafspraak gemaakt. ").repeat(4);
    if (i % 4 === 0) body += `Contact: ${NAME}, rekening ${IBAN}. `;
    out.push(`Paragraaf ${i}. ${body}`);
  }
  return out.join("\n\n");
}

class Service {
  sent: string[] = [];
  keys: string[] = [];
  constructor(readonly opts: { cap?: number; failOn?: number; findOnlyFirst?: boolean } = {}) {}
  get cap(): number { return this.opts.cap ?? 13_000; }

  handle(text: string, key: string): Response {
    this.sent.push(text);
    this.keys.push(key);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    if (text.length > this.cap) return json(413, { error: "input too large" });
    if (this.opts.failOn === this.sent.length) return json(400, { error: "bad request" });
    const entities = [];
    if (!(this.opts.findOnlyFirst && this.sent.length > 1)) {
      // The service counts code points, as the real one does.
      for (let at = text.indexOf(NAME); at >= 0; at = text.indexOf(NAME, at + 1)) {
        const cp = [...text.slice(0, at)].length;
        entities.push({ start: cp, end: cp + NAME.length, text: NAME, type: "PERSON_NAME",
          source: "model", score: 0.97, confidence: "high" });
      }
    }
    const tokens = Math.floor(text.length / 4);
    return json(200, {
      job_id: `job-${this.sent.length}`, status: "succeeded", redacted_text: text, entities,
      unlocated: [], model_version: "euredact-4b@test",
      usage: { tokens, billing_rate: 1.0, credits: tokens, factors: [] },
    });
  }

  get tokens(): number {
    return this.sent.filter(t => t.length <= this.cap).reduce((a, t) => a + Math.floor(t.length / 4), 0);
  }
}

let service = new Service();

async function withService<T>(fn: () => Promise<T>): Promise<T> {
  const realFetch = globalThis.fetch;
  configure({ apiKey: "erk_test", baseUrl: "https://api.test" });
  globalThis.fetch = async (_url: unknown, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    return service.handle(JSON.parse(String(init?.body)).text, headers.get("Idempotency-Key") ?? "");
  };
  try {
    return await fn();
  } finally {
    globalThis.fetch = realFetch;
    reset();
  }
}

const redact = (text: string, options: RedactOptions = {}) =>
  withService(() => new EuRedact().redactAsync(text, { countries: ["NL"], mode: "cloud", ...options }));

let passed = 0;
const failures: string[] = [];

async function check(name: string, fn: () => Promise<void> | void): Promise<void> {
  service = new Service();
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

const names = (r: { detections: Array<{ entityType: string }> }) =>
  r.detections.filter(d => d.entityType === "PERSON_NAME");
const count = (text: string, needle: string) => text.split(needle).length - 1;

interface Case { id: string; text: string; protected: Array<[number, number]>; max_chars: number; overlap: number;
  expect: Array<[number, number]> }
const CASES: Case[] = JSON.parse(
  readFileSync(new URL("../../../conformance/cloud_chunking.json", import.meta.url), "utf8"),
).cases;

(async () => {
  await check("a long document is split, sent and merged into one result", async () => {
    const text = documentText();
    assert.ok(text.length > 20_000);
    const r = await redact(text);
    assert.ok(service.sent.length > 1);
    for (const d of r.detections) assert.equal(text.slice(d.start, d.end), d.text);
    assert.equal(names(r).length, count(text, NAME));
    assert.ok(!r.redactedText.includes(NAME) && !r.redactedText.includes(IBAN));
    const spans = r.detections.map(d => `${d.start}|${d.end}|${d.entityType}`);
    assert.equal(new Set(spans).size, spans.length);
    const chunks = r.cloud!.chunks!;
    assert.equal(chunks.length, service.sent.length);
    assert.equal(chunks[0].start, 0);
    assert.equal(chunks[chunks.length - 1].end, text.length);
    assert.ok(chunks.every(c => c.total === chunks.length && c.jobId));
    assert.equal(r.cloud!.usage!.tokens, service.tokens);
    assert.equal(r.cloud!.usage!.tokens, chunks.reduce((a, c) => a + c.tokens!, 0));
    assert.equal(r.cloud!.jobId, null);
  });

  await check("only masked text is sent and no placeholder is cut", async () => {
    await redact(documentText());
    for (const part of service.sent) {
      assert.ok(!part.includes(IBAN));
      assert.equal(count(part, "["), count(part, "]"));
    }
  });

  await check("a short document is one request under the caller's key", async () => {
    const r = await redact(`Mail ${NAME} over de afspraak.`, { idempotencyKey: "doc-7" });
    assert.deepEqual(service.keys, ["doc-7"]);
    assert.equal(r.cloud!.chunks, undefined);
    assert.equal(r.cloud!.jobId, "job-1");
  });

  await check('chunking: "off" is today\'s behaviour', async () => {
    await assert.rejects(redact(documentText(), { chunking: "off" }), TooLargeError);
    assert.equal(service.sent.length, 1);
  });

  await check("a retried document reuses every part key", async () => {
    const text = documentText();
    await redact(text, { idempotencyKey: "letter-1" });
    const first = [...service.keys];
    service = new Service();
    await redact(text, { idempotencyKey: "letter-1" });
    assert.deepEqual(service.keys, first);
    assert.equal(new Set(first).size, first.length);
    assert.ok(first.every(k => k.startsWith("letter-1:")));
  });

  await check("the part keys match the Python SDK's", async () => {
    // sha256 of the part, as part_key computes it: a document retried from
    // the other SDK bills no part twice.
    const { partKey } = await import("../cloud/chunking.js");
    assert.equal(partKey("k", 2, "abc"), "k:2:ba7816bf8f01cfea");
  });

  await check("a failed part fails the document", async () => {
    service = new Service({ failOn: 2 });
    await assert.rejects(redact(documentText()), (err: unknown) => {
      assert.ok(err instanceof CloudError);
      assert.equal((err as CloudError & { chunksCompleted: number }).chunksCompleted, 1);
      assert.match(err.message, /1 completed and billed/);
      return true;
    });
  });

  await check("a part the service still refuses is halved", async () => {
    service = new Service({ cap: 5_000 });
    const text = documentText();
    const r = await redact(text, { chunking: { maxChars: 8_000 } });
    assert.ok(service.sent.every(t => t.length <= 8_000));
    assert.equal(names(r).length, count(text, NAME));
  });

  await check("maxChunks refuses before anything is sent", async () => {
    await assert.rejects(redact(documentText(), { chunking: { maxChunks: 1 } }), /maxChunks/);
    assert.deepEqual(service.sent, []);
  });

  await check("a value found in one part is masked in the others", async () => {
    service = new Service({ findOnlyFirst: true });
    const text = documentText();
    const r = await redact(text);
    assert.ok(!r.redactedText.includes(NAME));
    service = new Service({ findOnlyFirst: true });
    const kept = await redact(text, { chunking: { propagate: false } });
    assert.ok(kept.redactedText.includes(NAME));
  });

  await check("parts sent in parallel give the same result", async () => {
    const text = documentText();
    const one = await redact(text);
    service = new Service();
    const many = await redact(text, { chunking: { concurrency: 3 } });
    assert.deepEqual(many.detections.map(d => [d.start, d.end]), one.detections.map(d => [d.start, d.end]));
  });

  await check("a custom splitter and progress", async () => {
    const text = [documentText(10), documentText(10), documentText(10)].join("\f");
    const seen: ChunkInfo[] = [];
    const splitter = (t: string) => [...t].flatMap((c, i) => (c === "\f" ? [i] : []));
    const r = await redact(text, { chunking: { splitter, onChunk: c => seen.push(c) } });
    assert.deepEqual(seen.map(c => c.index), r.cloud!.chunks!.map((_, i) => i));
    assert.ok(seen.every(c => c.total === r.cloud!.chunks!.length));
  });

  await check("the splitter cuts where it says", async () => {
    // Three sections that would go as one request: the splitter makes them three.
    const text = [documentText(2), documentText(2), documentText(2)].join("\f");
    assert.ok(text.length < 12_000);
    const splitter = (t: string) => [...t].flatMap((c, i) => (c === "\f" ? [i] : []));
    const r = await redact(text, { chunking: { splitter, overlapChars: 0 } });
    assert.equal(service.sent.length, 3);
    const [first, ...rest] = text.split("\f");
    assert.deepEqual(r.cloud!.chunks!.map(c => text.slice(c.start, c.end)), [first, ...rest.map(x => "\f" + x)]);
  });

  await check("chunking is cloud-only", () => {
    assert.throws(() => new EuRedact().redact("x", { chunking: "off" }), /cloud/);
  });

  await check("the plan never cuts a placeholder and stays under the limit", () => {
    const text = ("woord ".repeat(30) + "[BANK_ACCOUNT] ").repeat(20);
    const prot: Array<[number, number]> = [];
    for (let at = text.indexOf("[BANK_ACCOUNT]"); at >= 0; at = text.indexOf("[BANK_ACCOUNT]", at + 1)) {
      prot.push([at, at + 14]);
    }
    const parts = plan(text, prot, 200, 20);
    assert.equal(parts[0][0], 0);
    assert.equal(parts[parts.length - 1][1], text.length);
    for (const [start, end] of parts) {
      assert.ok(end - start <= 200);
      assert.ok(!prot.some(([s, e]) => (s < start && start < e) || (s < end && end < e)));
    }
    for (let i = 1; i < parts.length; i++) assert.ok(parts[i][0] < parts[i - 1][1]);
  });

  await check("text outside the BMP is cut and placed by code point", async () => {
    // Every paragraph opens with an emoji: two UTF-16 units, one code point.
    const text = documentText().split("\n\n").map(p => `\u{1F4CB} ${p}`).join("\n\n");
    const r = await redact(text);
    assert.ok(service.sent.length > 1);
    for (const d of r.detections) assert.equal(text.slice(d.start, d.end), d.text);
    assert.equal(names(r).length, count(text, NAME));
    assert.ok(service.sent.every(t => !/[\uD800-\uDBFF]$/.test(t) && !/^[\uDC00-\uDFFF]/.test(t)));
    for (const c of r.cloud!.chunks!) assert.ok(!/[\uDC00-\uDFFF]/.test(text[c.start] ?? ""));
  });

  await check("cloud sources are kept", async () => {
    const r = await redact(documentText());
    assert.deepEqual(new Set(r.detections.map(d => d.source)), new Set(["rules", "cloud"]));
  });

  for (const c of CASES) {
    await check(`both SDKs cut at the same places: ${c.id}`, () => {
      assert.deepEqual(plan(c.text, c.protected, c.max_chars, c.overlap), c.expect);
    });
  }

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    console.log("\nFAILURES:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
})();
