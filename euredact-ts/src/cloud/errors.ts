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

/** 429 after retries were exhausted. */
export class QuotaExceededError extends CloudError {
  constructor(message: string, status?: number, detail?: Record<string, unknown>) {
    super(message, status, detail);
    this.name = "QuotaExceededError";
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
