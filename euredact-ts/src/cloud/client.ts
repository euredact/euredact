/**
 * [CLOUD EXTENSION] The cloud client.
 *
 * Speaks to the euRedact inference service: a deterministic rules engine
 * followed by a fine-tuned model asked only *what did the rules miss?* The
 * service returns both the redacted document and located spans, so this
 * module's job is transport and translation, not detection.
 *
 * Three things it hides from the caller:
 *
 * - **Whether the document finished inside the service's sync window.** A short
 *   document comes back on the original request; a long one, or one arriving
 *   while a GPU node is cold, returns a job handle and is polled. Callers
 *   should never write that branch, so `redact()` resolves either way.
 * - **Retries.** Every request carries an `Idempotency-Key`, so a retry after a
 *   timeout cannot produce a second job or a second usage row.
 * - **`Retry-After`.** When the service says how long to wait, that is obeyed
 *   rather than second-guessed with a backoff curve.
 *
 * Zero dependencies, like the rest of the package: this uses the platform's
 * own `fetch`.
 */

import {
  type CloudConfig,
  getConfig,
} from "./config.js";
import {
  CloudError,
  NotConfiguredError,
  QuotaExceededError,
  TooLargeError,
} from "./errors.js";
import {
  canonicalType,
  DetectionSource,
  EntityType,
  type Detection,
  type RedactResult,
} from "../types.js";

const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
const MAX_BACKOFF_MS = 30_000;

/** One span as the service reports it. */
interface WireSpan {
  start: number;
  end: number;
  text: string;
  type: string;
  source: string;
  match?: string;
  confidence?: string;
}

interface WireResult {
  job_id?: string;
  status?: string;
  redacted_text?: string;
  entities?: WireSpan[];
  unlocated?: Array<{ text: string; type: string }>;
  model_version?: string | null;
  stats?: Record<string, unknown>;
  error?: string;
  detail?: Record<string, unknown>;
  location?: string;
}

export interface CloudRedactOptions {
  country: string;
  language?: string;
  priority?: "interactive" | "batch";
  rulesOnly?: boolean;
  idempotencyKey?: string;
  /** Injectable for tests. Defaults to the platform `fetch`. */
  fetchImpl?: typeof fetch;
}

function requireFetch(supplied?: typeof fetch): typeof fetch {
  const impl = supplied ?? (globalThis as { fetch?: typeof fetch }).fetch;
  if (typeof impl !== "function") {
    throw new NotConfiguredError(
      "the cloud tier needs a global fetch. Node 18+ provides one; on Node 16 " +
        "supply one via the fetchImpl option or install a polyfill.",
    );
  }
  return impl;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function retryAfterMs(headers: Headers | undefined): number | null {
  const raw = headers?.get("Retry-After");
  if (!raw) return null;
  const seconds = Number(raw);
  // The HTTP-date form is legal too; fall back to backoff rather than parse it.
  return Number.isFinite(seconds) ? Math.max(0, seconds * 1000) : null;
}

/**
 * Full jitter. A synchronised retry storm from many clients is how a
 * recovering service is knocked back over.
 */
function backoffMs(attempt: number, retryAfter: number | null): number {
  if (retryAfter !== null) return Math.min(retryAfter, MAX_BACKOFF_MS);
  return Math.min(MAX_BACKOFF_MS, Math.random() * 2 ** attempt * 1000);
}

function uuid(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return `idem-${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Canon name -> EntityType, tolerating one this build has not heard of.
 *
 * An unknown type is passed through as a plain string rather than dropped:
 * `Detection.entityType` is `EntityType | string` precisely so a client one
 * release behind the service does not silently lose a whole category of PII.
 */
function toEntityType(raw: string): EntityType | string {
  const canonical = canonicalType(raw);
  const known = (Object.values(EntityType) as string[]).includes(canonical);
  return known ? (canonical as EntityType) : canonical;
}

function toResult(payload: WireResult, text: string): RedactResult {
  const detections: Detection[] = (payload.entities ?? []).map(span => ({
    entityType: toEntityType(span.type),
    start: span.start,
    end: span.end,
    text: span.text,
    source: span.source === "model" ? DetectionSource.CLOUD : DetectionSource.RULES,
    country: null,
    confidence: span.confidence ?? "high",
  }));
  detections.sort((a, b) => a.start - b.start || b.end - a.end);
  return {
    redactedText: payload.redacted_text ?? text,
    detections,
    source: "cloud",
    degraded: false,
    inferredCountries: [],
    evidence: [],
    detectionMode: "declared",
  };
}

export class CloudClient {
  readonly config: CloudConfig;

  constructor(config?: CloudConfig | null) {
    const resolved = config ?? getConfig();
    if (resolved === null) throw new NotConfiguredError();
    this.config = resolved;
  }

  private headers(idempotencyKey: string): Record<string, string> {
    return {
      Authorization: `Bearer ${this.config.apiKey}`,
      "Content-Type": "application/json",
      // A retry after a timeout must not create a second job or a second usage
      // row. The key is per logical document, not per attempt.
      "Idempotency-Key": idempotencyKey,
      ...this.config.headers,
    };
  }

  private raiseFor(status: number, payload: WireResult): never {
    const message = payload.error ?? `HTTP ${status}`;
    const detail = payload.detail ?? {};
    if (status === 401) throw new CloudError(`authentication failed: ${message}`, status);
    if (status === 413) throw new TooLargeError(message, status, detail);
    if (status === 429) throw new QuotaExceededError(message, status, detail);
    throw new CloudError(message, status, detail);
  }

  async redact(text: string, options: CloudRedactOptions): Promise<RedactResult> {
    const doFetch = requireFetch(options.fetchImpl);
    const key = options.idempotencyKey ?? uuid();
    const body = JSON.stringify({
      text,
      country: options.country.toUpperCase(),
      language: options.language ?? "",
      priority: options.priority ?? "interactive",
      rules_only: options.rulesOnly ?? false,
    });

    let attempt = 0;
    for (;;) {
      let response: Response | undefined;
      let payload: WireResult = {};
      try {
        response = await this.withTimeout(doFetch, `${this.config.baseUrl}/v1/redact`, {
          method: "POST",
          headers: this.headers(key),
          body,
        });
        payload = await readJson(response);
      } catch (e) {
        if (attempt >= this.config.maxRetries) {
          throw new CloudError(
            `cloud request failed: ${e instanceof Error ? e.message : String(e)}`,
          );
        }
      }

      if (response) {
        if (response.status === 202) {
          // Outlived the sync window. Location is where the answer will appear;
          // polling it is this client's job, not the caller's.
          const location =
            response.headers.get("Location") ??
            payload.location ??
            `/v1/jobs/${payload.job_id ?? ""}`;
          return toResult(await this.poll(doFetch, location, key), text);
        }
        if (response.status === 200) return toResult(payload, text);
        if (!RETRY_STATUS.has(response.status) || attempt >= this.config.maxRetries) {
          this.raiseFor(response.status, payload);
        }
      }

      await sleep(backoffMs(attempt, retryAfterMs(response?.headers)));
      attempt++;
    }
  }

  private async poll(
    doFetch: typeof fetch,
    location: string,
    key: string,
  ): Promise<WireResult> {
    const url = location.startsWith("http")
      ? location
      : `${this.config.baseUrl}${location}`;
    const deadline = Date.now() + this.config.pollTimeoutMs;
    let delay = 500;
    for (;;) {
      const response = await this.withTimeout(doFetch, url, {
        method: "GET",
        headers: this.headers(key),
      });
      const payload = await readJson(response);
      if (response.status === 200 && payload.redacted_text !== undefined) {
        return payload;
      }
      if (response.status !== 200 && !RETRY_STATUS.has(response.status)) {
        this.raiseFor(response.status, payload);
      }
      if (Date.now() >= deadline) {
        throw new CloudError(
          `document did not complete within ${Math.round(
            this.config.pollTimeoutMs / 1000,
          )}s (${url})`,
        );
      }
      const after = retryAfterMs(response.headers);
      await sleep(after ?? delay);
      delay = Math.min(delay * 1.5, 5000);
    }
  }

  private async withTimeout(
    doFetch: typeof fetch,
    url: string,
    init: RequestInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await doFetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}

async function readJson(response: Response): Promise<WireResult> {
  try {
    const data = await response.json();
    return data && typeof data === "object" ? (data as WireResult) : {};
  } catch {
    return {};
  }
}
