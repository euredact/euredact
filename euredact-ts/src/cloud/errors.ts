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
          "or set EUREDACT_API_KEY.",
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
 * Permanent and not retryable. The model has never seen a chunk boundary, so
 * the service refuses oversized input rather than splitting it and changing the
 * accuracy story silently.
 */
export class TooLargeError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "TooLargeError";
  }
}
