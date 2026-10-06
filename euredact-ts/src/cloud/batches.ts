/**
 * [CLOUD EXTENSION] Batches: cloud mode, with hours between masking and mapping
 * (rules-engine#84; the gateway side is `docs/BATCHES.md` in euredact-inference).
 *
 * Cloud mode masks a document here, sends only the masked text and maps the
 * service's answer back onto the original, all in one call. A batch returns up
 * to 24 h later, so `create()` writes one **local batch file** per batch: each
 * original, its local detections and the SHA-256 of the masked text that was
 * sent. None of it is uploaded. `results()` maps the service's spans back from
 * that file, checking the hash before placing a span, then wipes the originals
 * and leaves a text-free receipt.
 *
 * The file format is shared with the Python SDK, offsets counted in code points,
 * so a batch created by one can be resolved by the other.
 *
 * In Node the file is `~/.euredact/batches/<batchId>.json` (`0600` in a `0700`
 * directory); `batchDir` moves it. A page has no filesystem, so there `store`
 * is required: any object with async `read`, `write`, `delete` and `list`.
 * `cipher` encrypts the file at rest with a key the caller holds.
 */

import type { Detection, RedactResult } from "../types.js";
import { DetectionSource } from "../types.js";
import { EuRedact, applyReplacements, maskForCloud, ontoOriginal } from "../sdk.js";
import { defaultBatchStore, gzip, sha256Hex } from "../platform.js";
import { codePointOffsets, toResult } from "./client.js";
import { getConfig, requireSecureBaseUrl, type CloudConfig } from "./config.js";
import { CloudError, NotConfiguredError, QuotaExceededError, TooLargeError } from "./errors.js";

/** The gateway's limits (docs/BATCHES.md §2-§3), checked before upload. */
export const MAX_DOCUMENTS = 5000;
export const MAX_CUSTOM_ID = 64;
/** The gateway's customId rule (euredact-inference gateway/batches.py), whole string. */
export const CUSTOM_ID = /^[A-Za-z0-9_.:\-]{1,64}$/;
export const MAX_BODY_BYTES = 128 * 1024 * 1024;
/**
 * Per document, counted by the model's tokenizer on the gateway. The SDK has no
 * copy of it and no character count decides it, so it is **not** checked before
 * upload: a document over it comes back as an error with code `too_long`.
 */
export const MAX_DOCUMENT_TOKENS = 5000;

export const FILE_FORMAT = "euredact-batch/1";

export class BatchError extends CloudError {
  constructor(message: string) {
    super(message);
    this.name = "BatchError";
  }
}

/** Where local batch files live. One opaque blob per batch id. */
export interface BatchStore {
  read(batchId: string): Promise<Uint8Array | null>;
  write(batchId: string, data: Uint8Array): Promise<void>;
  delete(batchId: string): Promise<void>;
  list(): Promise<string[]>;
}

/** Encryption at rest, with a key the caller holds. The SDK does not pick a scheme. */
export interface Cipher {
  encrypt(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
  decrypt(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface BatchDocument {
  customId: string;
  text: string;
  /** Exactly one, as in cloud mode. */
  countries: string[];
  language?: string;
}

export interface Batch {
  id: string;
  status: string;
  createdAt: string | null;
  expiresAt: string | null;
  endedAt: string | null;
  resultsExpireAt: string | null;
  counts: Record<string, number>;
  raw: Record<string, unknown>;
}

/** One document of a resolved batch: a result, or why there is none. */
export interface DocumentOutcome {
  customId: string;
  ok: boolean;
  result: RedactResult | null;
  /**
   * `null` on success. Otherwise a code: the gateway's (`too_long`, …),
   * `expired`, `cancelled`, or the SDK's own `local_mismatch` (the local file
   * does not match what was sent) or `missing_local_entry`.
   */
  error: string | null;
  message: string;
}

/**
 * `status`: `not_ended` (nothing changed locally), `resolved` (mapped now; the
 * file is a text-free receipt), `already_resolved` (never mapped twice), or
 * `expired` (the gateway no longer holds the results; the entries are wiped).
 */
export interface BatchResults {
  batchId: string;
  status: "not_ended" | "resolved" | "already_resolved" | "expired";
  documents: Record<string, DocumentOutcome>;
  batch: Batch | null;
}

export interface BatchesOptions {
  config?: CloudConfig | null;
  batchDir?: string;
  store?: BatchStore;
  cipher?: Cipher;
  sdk?: EuRedact;
  /** Injectable for tests. Defaults to the platform `fetch`. */
  fetchImpl?: typeof fetch;
}

// ── the local batch file ──────────────────────────────────────────────────

interface StoredDetection {
  type: string;
  start: number;
  end: number;
  text: string;
  source: string;
  country: string | null;
  confidence: string;
  country_confidence: number;
  out_of_scope: boolean;
}

interface StoredEntry {
  text: string;
  masked_sha256: string;
  countries: string[];
  language: string;
  detections: StoredDetection[];
  detection_mode: string;
  inferred_countries: Array<[string, number]>;
}

interface BatchFile {
  format: string;
  batch_id: string;
  status: "pending" | "resolved" | "expired";
  created_at: string | null;
  expires_at: string | null;
  results_expire_at: string | null;
  resolved_at: string | null;
  engine: string;
  engine_version: string | null;
  counts: Record<string, number>;
  entries: Record<string, StoredEntry>;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** UTF-16 offset -> code point offset, for writing the shared file format. */
function utf16ToCodePoints(text: string): (unit: number) => number {
  if (!/[\uD800-\uDBFF]/.test(text)) return unit => unit;
  const map = new Map<number, number>();
  let cp = 0;
  let unit = 0;
  for (const ch of text) {
    map.set(unit, cp);
    unit += ch.length;
    cp += 1;
  }
  map.set(unit, cp);
  return u => map.get(u) ?? u;
}

function toStored(d: Detection, cp: (u: number) => number): StoredDetection {
  return {
    type: String(d.entityType), start: cp(d.start), end: cp(d.end), text: d.text,
    source: String(d.source), country: d.country ?? null, confidence: d.confidence ?? "high",
    country_confidence: d.countryConfidence ?? 0, out_of_scope: d.outOfScope ?? false,
  };
}

function fromStored(raw: StoredDetection, unit: (cp: number) => number): Detection {
  return {
    entityType: raw.type as Detection["entityType"], start: unit(raw.start), end: unit(raw.end),
    text: raw.text, source: raw.source as DetectionSource, country: raw.country,
    confidence: raw.confidence, countryConfidence: raw.country_confidence,
    outOfScope: raw.out_of_scope,
  } as Detection;
}

// ── the client ────────────────────────────────────────────────────────────

export class Batches {
  readonly config: CloudConfig;
  readonly store: BatchStore;
  private readonly cipher: Cipher | null;
  private readonly fetchImpl: typeof fetch | undefined;
  private sdk: EuRedact | null;

  constructor(options: BatchesOptions = {}) {
    const config = options.config ?? getConfig();
    if (config === null) throw new NotConfiguredError();
    requireSecureBaseUrl(config.baseUrl);
    this.config = config;
    if (options.batchDir !== undefined && options.store !== undefined) {
      throw new Error("pass batchDir or store, not both");
    }
    const store = options.store ?? defaultBatchStore(options.batchDir);
    if (store === null) {
      throw new Error(
        "no filesystem here: pass a store ({ read, write, delete, list }) to Batches",
      );
    }
    this.store = store;
    this.cipher = options.cipher ?? null;
    this.fetchImpl = options.fetchImpl;
    this.sdk = options.sdk ?? null;
  }

  // -- plumbing ---------------------------------------------------------

  private engine(): EuRedact {
    if (this.sdk === null) this.sdk = new EuRedact();
    return this.sdk;
  }

  private async request(method: string, path: string, body?: Uint8Array,
                        headers: Record<string, string> = {}): Promise<Response> {
    const impl = this.fetchImpl ?? (globalThis as { fetch?: typeof fetch }).fetch;
    if (!impl) throw new CloudError("no fetch implementation available");
    try {
      return await impl(`${this.config.baseUrl}${path}`, {
        method,
        body: body as BodyInit | undefined,
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "Idempotency-Key": headers["Idempotency-Key"] ?? crypto.randomUUID(),
          ...this.config.headers,
          ...headers,
        },
      });
    } catch (err) {
      throw new CloudError(`batch request failed: ${(err as Error).message}`);
    }
  }

  private async json(resp: Response): Promise<Record<string, unknown>> {
    try {
      return (await resp.json()) as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  private raiseFor(status: number, payload: Record<string, unknown>): never {
    const message = String(payload.error ?? `HTTP ${status}`);
    const detail = (payload.detail as Record<string, unknown>) ?? {};
    if (status === 401) throw new CloudError(`authentication failed: ${message}`, status);
    if (status === 413) throw new TooLargeError(message, status, detail);
    if (status === 429) throw new QuotaExceededError(message, status, detail);
    throw new CloudError(message, status, detail);
  }

  private async load(batchId: string): Promise<BatchFile | null> {
    let data = await this.store.read(batchId);
    if (data === null) return null;
    if (this.cipher) data = await this.cipher.decrypt(data);
    const state = JSON.parse(decoder.decode(data)) as BatchFile;
    if (state.format !== FILE_FORMAT) {
      throw new BatchError(`local batch file ${batchId}: unknown format ${JSON.stringify(state.format)}`);
    }
    return state;
  }

  private async save(state: BatchFile): Promise<void> {
    let data: Uint8Array = encoder.encode(JSON.stringify(state));
    if (this.cipher) data = await this.cipher.encrypt(data);
    await this.store.write(state.batch_id, data);
  }

  private static batch(raw: Record<string, unknown>): Batch {
    const str = (k: string): string | null => (typeof raw[k] === "string" ? (raw[k] as string) : null);
    return {
      id: str("id") ?? "", status: str("status") ?? "",
      createdAt: str("created_at"), expiresAt: str("expires_at"), endedAt: str("ended_at"),
      resultsExpireAt: str("results_expire_at"),
      counts: { ...((raw.counts as Record<string, number>) ?? {}) }, raw,
    };
  }

  // -- create -----------------------------------------------------------

  /**
   * Mask every document here, upload only the masked text, keep the rest in
   * the local batch file. The document count, `customId`s, countries and body
   * size are checked before anything is uploaded or written. The 5,000-token
   * limit per document is **not**: it is counted by the model's tokenizer on
   * the gateway, which the SDK does not have, so a document over it comes back
   * from `results()` as an error with code `too_long` that says so.
   */
  async create(documents: BatchDocument[], options: { idempotencyKey?: string } = {}): Promise<Batch> {
    if (documents.length === 0) throw new BatchError("a batch needs at least one document");
    if (documents.length > MAX_DOCUMENTS) {
      throw new BatchError(
        `${documents.length.toLocaleString("en-US")} documents; a batch holds at most ` +
        `${MAX_DOCUMENTS.toLocaleString("en-US")}`,
      );
    }
    // Every document is checked before any is masked: masking 5,000 documents
    // and then learning that the gateway refuses the batch for one bad customId
    // wastes the whole pass (rules-engine#88).
    const seen = new Set<string>();
    const checked: Array<{ customId: string; text: string; countries: string[]; language: string }> = [];
    documents.forEach((doc, index) => {
      const number = index + 1;
      const customId = doc.customId;
      if (typeof customId !== "string" || !CUSTOM_ID.test(customId)) {
        throw new BatchError(
          `document ${number}: customId must be 1-${MAX_CUSTOM_ID} characters of A-Z a-z 0-9 _ . : -`,
        );
      }
      if (seen.has(customId)) {
        throw new BatchError(`document ${number}: duplicate customId ${JSON.stringify(customId)}`);
      }
      seen.add(customId);
      if (typeof doc.text !== "string") throw new BatchError(`document ${number}: text must be a string`);
      const countries = (doc.countries ?? []).map(c => c.toUpperCase());
      if (countries.length !== 1) {
        throw new BatchError(`document ${number}: exactly one country is needed, as in cloud mode`);
      }
      checked.push({ customId, text: doc.text, countries, language: doc.language ?? "" });
    });

    const lines: string[] = [];
    const entries: Record<string, StoredEntry> = {};
    const engine = this.engine();
    for (const { customId, text, countries, language } of checked) {
      // The same local pass as redactAsync(..., { mode: "cloud" }): dates on, no
      // allowlist, no tokens. What is sent is what cloud mode would send.
      const local = engine.redact(text, { countries, detectDates: true, cache: false });
      const [masked] = maskForCloud(text, local.detections);
      const line: Record<string, unknown> = { custom_id: customId, text: masked, countries };
      if (language) line.language = language;
      lines.push(JSON.stringify(line));
      const cp = utf16ToCodePoints(text);
      entries[customId] = {
        text: text,
        masked_sha256: sha256Hex([masked]),
        countries,
        language,
        detections: local.detections.map(d => toStored(d, cp)),
        detection_mode: local.detectionMode,
        inferred_countries: local.inferredCountries,
      };
    }

    const body = encoder.encode(lines.join("\n") + "\n");
    if (body.length > MAX_BODY_BYTES) {
      throw new BatchError(
        `the masked batch is ${body.length.toLocaleString("en-US")} bytes; the limit is ` +
        `${MAX_BODY_BYTES.toLocaleString("en-US")}`,
      );
    }
    const compressed = gzip(body);
    const headers: Record<string, string> = {
      "Content-Type": "application/x-ndjson",
      "Idempotency-Key": options.idempotencyKey ?? crypto.randomUUID(),
    };
    if (compressed !== null) headers["Content-Encoding"] = "gzip";
    const resp = await this.request("POST", "/v1/batches", compressed ?? body, headers);
    const payload = await this.json(resp);
    if (resp.status !== 200 && resp.status !== 201) this.raiseFor(resp.status, payload);
    const batch = Batches.batch(payload);
    if (!batch.id) throw new BatchError("the gateway accepted the batch but returned no id");

    await this.save({
      format: FILE_FORMAT,
      batch_id: batch.id,
      status: "pending",
      created_at: batch.createdAt ?? now(),
      expires_at: batch.expiresAt,
      results_expire_at: null,
      resolved_at: null,
      engine: "euredact-ts",
      engine_version: null,
      counts: { documents: Object.keys(entries).length },
      entries,
    });
    return batch;
  }

  // -- retrieve, cancel, pending, purge, sweep ------------------------------

  /** The gateway's view: status, counts and timestamps. */
  async retrieve(batchId: string): Promise<Batch> {
    await this.sweep();
    const resp = await this.request("GET", `/v1/batches/${encodeURIComponent(batchId)}`);
    const payload = await this.json(resp);
    if (resp.status !== 200) this.raiseFor(resp.status, payload);
    const batch = Batches.batch(payload);
    const state = await this.load(batchId);
    if (state !== null && batch.resultsExpireAt && state.results_expire_at !== batch.resultsExpireAt) {
      state.results_expire_at = batch.resultsExpireAt;
      await this.save(state);
    }
    return batch;
  }

  /** Cancel queued documents; the local file stays pending until the finished
   *  ones are mapped by `results()`. */
  async cancel(batchId: string): Promise<Batch> {
    const resp = await this.request("POST", `/v1/batches/${encodeURIComponent(batchId)}/cancel`);
    const payload = await this.json(resp);
    if (resp.status !== 200 && resp.status !== 202) this.raiseFor(resp.status, payload);
    return Batches.batch(payload);
  }

  /** Batch ids whose local file still waits to be mapped. Reads files only. */
  async pending(): Promise<string[]> {
    await this.sweep();
    const out: string[] = [];
    for (const id of await this.store.list()) {
      const state = await this.load(id);
      if (state !== null && state.status === "pending") out.push(id);
    }
    return out;
  }

  /** Delete the local file, whatever its status. */
  async purge(batchId: string): Promise<void> {
    await this.store.delete(batchId);
  }

  /**
   * Delete receipts and expire pending files past `results_expire_at`. Runs at
   * the start of the calls that look in the store, so nothing has to be
   * scheduled. A pending file past that time can never be mapped -- the gateway
   * has swept the results -- so its originals are wiped.
   */
  async sweep(at: Date = new Date()): Promise<void> {
    for (const id of await this.store.list()) {
      let state: BatchFile | null;
      try {
        state = await this.load(id);
      } catch {
        continue;
      }
      if (state === null || !state.results_expire_at) continue;
      if (at < new Date(state.results_expire_at)) continue;
      if (state.status === "pending") await this.wipe(state, "expired");
      else await this.store.delete(id);
    }
  }

  private async wipe(state: BatchFile, status: BatchFile["status"]): Promise<void> {
    state.entries = {};
    state.status = status;
    state.resolved_at = now();
    await this.save(state);
  }

  // -- results ----------------------------------------------------------

  /**
   * Map an ended batch back onto the originals in its local file. Each
   * document's masked text is rebuilt from the file and must hash to both the
   * stored SHA-256 and the gateway's `masked_sha256` before a span is placed.
   * Anything that cannot be mapped is a per-document error, never the masked
   * text passed off as a result.
   */
  async results(batchId: string): Promise<BatchResults> {
    const state = await this.load(batchId);
    if (state !== null && (state.status === "resolved" || state.status === "expired")) {
      return {
        batchId, documents: {}, batch: null,
        status: state.status === "resolved" ? "already_resolved" : "expired",
      };
    }
    const batch = await this.retrieve(batchId);
    if (batch.status !== "ended") return { batchId, status: "not_ended", documents: {}, batch };

    const resp = await this.request("GET", `/v1/batches/${encodeURIComponent(batchId)}/results`);
    if (resp.status === 410) {
      if (state !== null) await this.wipe(state, "expired");
      return { batchId, status: "expired", documents: {}, batch };
    }
    if (resp.status === 409) return { batchId, status: "not_ended", documents: {}, batch };
    if (resp.status !== 200) this.raiseFor(resp.status, await this.json(resp));

    const entries = state?.entries ?? {};
    const documents: Record<string, DocumentOutcome> = {};
    for (const line of (await resp.text()).split("\n")) {
      if (!line.trim()) continue;
      const row = JSON.parse(line) as { custom_id?: string; result?: Record<string, unknown> };
      const customId = row.custom_id ?? "";
      documents[customId] = this.outcome(customId, row.result ?? {}, entries[customId], state !== null);
    }

    if (state !== null) {
      const counts: Record<string, number> = {
        documents: Object.keys(documents).length,
        mapped: Object.values(documents).filter(o => o.ok).length,
      };
      for (const o of Object.values(documents)) {
        if (o.error) counts[o.error] = (counts[o.error] ?? 0) + 1;
      }
      state.counts = counts;
      await this.wipe(state, "resolved");
    }
    return { batchId, status: "resolved", documents, batch };
  }

  private outcome(customId: string, result: Record<string, unknown>,
                  entry: StoredEntry | undefined, fileExists: boolean): DocumentOutcome {
    const fail = (error: string, message: string): DocumentOutcome =>
      ({ customId, ok: false, result: null, error, message });

    if (result.type !== "succeeded") {
      const err = (result.error as { code?: string; message?: string }) ?? {};
      const code = err.code ?? (result.type as string) ?? "errored";
      let message = err.message ?? "";
      if (code === "too_long") {
        message = `${message}. The ${MAX_DOCUMENT_TOKENS.toLocaleString("en-US")}-token limit is ` +
          "counted by the model's tokenizer on the gateway; the SDK cannot check it before " +
          "upload. Split the document and submit the parts.";
        message = message.replace(/^\. /, "");
      }
      return fail(code, message);
    }
    if (entry === undefined) {
      return fail("missing_local_entry", fileExists
        ? "no entry for this document in the local batch file"
        : "no local batch file on this machine");
    }

    const text = entry.text;
    const unit = codePointOffsets(text);
    const local = entry.detections.map(d => fromStored(d, unit));
    const [masked, labels] = maskForCloud(text, local);
    if (sha256Hex([masked]) !== entry.masked_sha256 || result.masked_sha256 !== entry.masked_sha256) {
      return fail("local_mismatch", "the local batch file does not match what was sent");
    }
    // The gateway's offsets count code points of the masked text; toResult
    // converts them to UTF-16 units, as the cloud client does for redactAsync.
    const remote = toResult({ entities: result.entities as never }, masked);
    let placed: Detection[];
    try {
      placed = ontoOriginal(remote.detections, masked, text, labels, CloudError);
    } catch (err) {
      return fail("local_mismatch", (err as Error).message);
    }
    const detections = [...local, ...placed].sort((a, b) => a.start - b.start || b.end - a.end);
    return {
      customId, ok: true, error: null, message: "",
      result: {
        redactedText: applyReplacements(text, detections, det => `[${det.entityType}]`),
        detections,
        source: "cloud",
        degraded: false,
        inferredCountries: entry.inferred_countries,
        evidence: [],
        detectionMode: entry.detection_mode,
        tokens: {},
        exempted: [],
      },
    };
  }
}
