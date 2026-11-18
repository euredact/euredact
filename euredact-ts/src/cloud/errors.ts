/** [CLOUD EXTENSION] Errors the cloud tier can raise. */

export class CloudError extends Error {
  readonly status?: number;
  readonly detail: Record<string, unknown>;

  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message);
    this.name = "CloudError";
    this.status = status;
    this.detail = detail ?? {};
  }
}

/**
 * Raised when the cloud tier is used without configuration.
 *
 * Deliberately an error rather than a quiet fallback to rules-only output.
 * `mode: "cloud"` that silently returns rules-only results is the worst failure
 * this library can have: the caller believes names, employers and diagnoses
 * were checked, sees a plausible redacted document, and ships it with the PII
 * still in it.
 */
export class NotConfiguredError extends CloudError {
  constructor(message?: string) {
    super(
      message ??
        "Cloud tier not configured. Call euredact.configure({ apiKey }) first, " +
          "or configure() with EUREDACT_API_KEY set.",
    );
    this.name = "NotConfiguredError";
  }
}

/**
 * 429: the account's daily document quota is used up. Thrown at once, not
 * after retries: the gateway's quota answer (JSON with `detail.used` and
 * `detail.limit`) will not change before the day does (rules-engine#89).
 */
export class QuotaExceededError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "QuotaExceededError";
  }
}

/**
 * 429 from the edge's rate limit, still there after every retry. It clears
 * within seconds, so it is retried with backoff first. A subclass of
 * `QuotaExceededError`, which is what every 429 threw before the two were told apart.
 */
export class RateLimitedError extends QuotaExceededError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "RateLimitedError";
  }
}

const detailInt = (detail: Record<string, unknown>, key: string): number | null => {
  const v = detail[key];
  return typeof v === "number" && Number.isInteger(v) ? v : null;
};

/**
 * 402: the account's Budget and extra volume are spent. Thrown at once and
 * never retried: like the daily quota, it holds until the next period or a
 * top-up (rules-engine#145). The numbers come from the gateway's `detail`; one
 * it did not send, or sent malformed, is null, and `detail` keeps the object.
 */
export class InsufficientCreditsError extends CloudError {
  /** Credits left on the account. */
  readonly balance: number | null;
  /** Credits the request needed: its prompt plus the largest response. */
  readonly required: number | null;
  /** `required - balance`: what a top-up has to cover. */
  readonly shortfall: number | null;
  readonly promptTokens: number | null;
  readonly maxResponseTokens: number | null;

  constructor(message: string, status = 402, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "InsufficientCreditsError";
    this.balance = detailInt(this.detail, "balance");
    this.required = detailInt(this.detail, "required");
    this.shortfall = detailInt(this.detail, "shortfall");
    this.promptTokens = detailInt(this.detail, "prompt_tokens");
    this.maxResponseTokens = detailInt(this.detail, "max_response_tokens");
  }
}

/**
 * 502 with the gateway's "inference failed": the job ran and failed. Thrown at
 * once and never retried or polled again: the service has answered, and asking
 * again returns the same failed job. A 502 without that body (the edge, a
 * restarting gateway) is still transient and retried (rules-engine#184).
 */
export class InferenceFailedError extends CloudError {
  /** The failed job's id, for support and for the gateway's logs. */
  readonly jobId: string | null;
  /** Why it failed, as the service put it, or null. */
  readonly reason: string | null;

  constructor(message: string, status = 502, detail?: Record<string, unknown>, jobId?: string | null) {
    super(message, status, detail);
    this.name = "InferenceFailedError";
    const fromDetail = typeof this.detail.job_id === "string" ? this.detail.job_id : null;
    this.jobId = jobId ?? fromDetail;
    this.reason = typeof this.detail.reason === "string" ? this.detail.reason : null;
  }
}

/** 404: no such job, batch or key -- or another account's, which the service
 *  deliberately does not distinguish. */
export class NotFoundError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "NotFoundError";
  }
}

/**
 * 410: the job succeeded, but its result is no longer retained -- swept by the
 * account's retention period, or discarded on delivery under no-retention. An
 * empty result here would read like a document with no personal data in it.
 */
export class ResultExpiredError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "ResultExpiredError";
  }
}

/**
 * 413. The document is over the service's input cap.
 *
 * Permanent and not retryable: the service refuses oversized input rather than
 * splitting it. `redactAsync({ mode: "cloud" })` splits such a document itself
 * unless `chunking: "off"` (rules-engine#183); the client never does.
 */
export class TooLargeError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "TooLargeError";
  }
}
