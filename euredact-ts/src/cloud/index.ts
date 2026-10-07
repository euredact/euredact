/**
 * [CLOUD EXTENSION] Cloud tier — rules engine plus a fine-tuned model.
 *
 * The rule engine catches what has a shape: IBANs, national IDs, phone
 * numbers, anything with a checksum. It cannot catch what does not — a
 * person's name, an employer, a diagnosis, a job title. Those are what the
 * cloud tier adds, and the `EntityType` members marked `[CLOUD EXTENSION]` are
 * exactly that gap.
 *
 * ```ts
 * import { configure, redactAsync } from "euredact";
 *
 * configure({ apiKey: "erk_..." });
 * const result = await redactAsync(text, { countries: ["BE"], mode: "cloud" });
 * ```
 */

export { CloudClient, type CloudRedactOptions } from "./client.js";
export {
  Account,
  Jobs,
  type AccountSummary,
  type ApiClientOptions,
  type ApiKey,
  type CreditEntry,
  type Credits,
  type Job,
  type KeyRevocation,
  type KeyUsage,
  type UsageDay,
} from "./account.js";
export {
  Batches,
  BatchError,
  MAX_DOCUMENTS,
  MAX_CUSTOM_ID,
  CUSTOM_ID,
  MAX_BODY_BYTES,
  MAX_DOCUMENT_TOKENS,
  type Batch,
  type BatchDocument,
  type BatchResults,
  type BatchStore,
  type BatchesOptions,
  type Cipher,
  type DocumentOutcome,
} from "./batches.js";
export {
  configure,
  getConfig,
  reset,
  requireSecureBaseUrl,
  DEFAULT_BASE_URL,
  type CloudConfig,
  type ConfigureOptions,
} from "./config.js";
export {
  CloudError,
  NotConfiguredError,
  NotFoundError,
  QuotaExceededError,
  RateLimitedError,
  ResultExpiredError,
  TooLargeError,
} from "./errors.js";
