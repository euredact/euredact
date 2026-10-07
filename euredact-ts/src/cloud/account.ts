/**
 * [CLOUD EXTENSION] The account and job endpoints an API key may call.
 *
 * Everything a customer's key can do on the service is reachable from the SDK
 * (rules-engine#89): redaction (`CloudClient`, `redactAsync`), batches
 * (`Batches`), a past job (`Jobs`) and the account itself (`Account`). What
 * needs a signed-in person -- logging in, minting keys, changing settings,
 * members, accepting terms -- is not here, because a key cannot do it.
 *
 * Every typed value carries `raw`, the service's JSON, so a field the SDK does
 * not know yet is still reachable.
 */

import { type CloudConfig, getConfig, requireSecureBaseUrl } from "./config.js";
import { CloudError, NotConfiguredError } from "./errors.js";
import {
  RETRY_STATUS,
  backoffMs,
  cloudErrorFor,
  isInteger,
  isQuota,
  readJson,
  requireFetch,
  retryAfterMs,
  sleep,
  toResult,
  uuid,
} from "./client.js";
import type { RedactResult } from "../types.js";

type Json = Record<string, unknown>;

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const int = (v: unknown): number | null => (isInteger(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const obj = (v: unknown): Json => (v && typeof v === "object" && !Array.isArray(v) ? v as Json : {});
const objects = (v: unknown): Json[] =>
  (Array.isArray(v) ? v : []).filter((x): x is Json => !!x && typeof x === "object" && !Array.isArray(x));

/** `GET /v1/account`: plan limits, retention and usage against quota. */
export interface AccountSummary {
  tenantId: string | null;
  tenantName: string | null;
  active: boolean | null;
  memberSince: string | null;
  role: string | null;
  /** `"ttl"`, or `"none"` when text is discarded on delivery. */
  retentionMode: string | null;
  payloadTtlHours: number | null;
  documentsToday: number | null;
  documentsThisMonth: number | null;
  tokensThisMonth: number | null;
  failures24h: number | null;
  /** `null` for an account without a daily quota. */
  dailyQuota: number | null;
  quotaRemaining: number | null;
  activeKeys: number | null;
  batchesAvailable: boolean | null;
  raw: Json;
}

/** `GET /v1/account/credits`: the balance, in credits. */
export interface Credits {
  balance: number | null;
  granted: number | null;
  spent: number | null;
  unit: string | null;
  raw: Json;
}

/** One line of the credit history: movements rolled up per minute, reason and direction, newest first. */
export interface CreditEntry {
  at: string | null;
  /** Negative for a debit. */
  delta: number | null;
  reason: string | null;
  count: number | null;
  jobId: string | null;
  sourceRef: string | null;
  raw: Json;
}

/** One day of `GET /v1/account/usage`, or of one key's series. */
export interface UsageDay {
  day: string | null;
  documents: number | null;
  tokens: number | null;
  failures: number | null;
  rulesOnly: number | null;
  raw: Json;
}

/** One key of `GET /v1/account/usage/by-key`; the rest are rolled into one with `keyId` null. */
export interface KeyUsage {
  keyId: number | null;
  name: string | null;
  documents: number | null;
  tokens: number | null;
  failures: number | null;
  series: UsageDay[];
  raw: Json;
}

/** One key of `GET /v1/account/keys`. Never its secret. */
export interface ApiKey {
  id: number | null;
  name: string | null;
  createdBy: string | null;
  createdAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  active: boolean | null;
  raw: Json;
}

/** The answer to `POST /v1/account/keys/{id}/revoke`. */
export interface KeyRevocation {
  id: number | null;
  keysRemaining: number | null;
  /** True when no active key is left: nothing can call the service until a person mints one. */
  lockedOut: boolean | null;
  /** True when the key revoked is the one that made this call. */
  selfRevoked: boolean | null;
  raw: Json;
}

/** `GET /v1/jobs/{id}`: a job's state, and its result once it has one. */
export interface Job {
  jobId: string;
  /** `queued`, `running` or `succeeded`. A failed or rejected job throws instead. */
  status: string;
  createdAt: string | null;
  /**
   * Set when the job succeeded. Its text and offsets are those of the text the
   * service received -- under the local-first cloud mode, the locally masked
   * text, not the caller's original.
   */
  result: RedactResult | null;
  raw: Json;
}

const usageDay = (r: Json): UsageDay => ({
  day: str(r.day), documents: int(r.documents), tokens: int(r.tokens),
  failures: int(r.failures), rulesOnly: int(r.rules_only), raw: r,
});

export interface ApiClientOptions {
  /** Injectable for tests. Defaults to the platform `fetch`. */
  fetchImpl?: typeof fetch;
}

/** A JSON client: GETs are retried like the redact call; writes are sent once. */
class ApiClient {
  readonly config: CloudConfig;
  private readonly fetchImpl?: typeof fetch;

  constructor(config?: CloudConfig | null, options: ApiClientOptions = {}) {
    const resolved = config ?? getConfig();
    if (resolved === null) throw new NotConfiguredError();
    requireSecureBaseUrl(resolved.baseUrl);
    this.config = resolved;
    this.fetchImpl = options.fetchImpl;
  }

  protected async call(method: "GET" | "POST", path: string,
                       params: Record<string, number> = {}, retry = method === "GET"): Promise<Json> {
    const doFetch = requireFetch(this.fetchImpl);
    const query = Object.entries(params).map(([k, v]) => `${k}=${v}`).join("&");
    const url = `${this.config.baseUrl}${path}${query ? `?${query}` : ""}`;
    const maxRetries = retry ? this.config.maxRetries : 0;
    for (let attempt = 0; ; attempt++) {
      let response: Response | undefined;
      let payload: Json = {};
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        response = await doFetch(url, {
          method,
          headers: {
            Authorization: `Bearer ${this.config.apiKey}`,
            "Idempotency-Key": uuid(),
            ...this.config.headers,
          },
          signal: controller.signal,
        });
        payload = (await readJson(response)) as Json;
      } catch (e) {
        if (attempt >= maxRetries) {
          throw new CloudError(`cloud request failed: ${e instanceof Error ? e.message : String(e)}`);
        }
      } finally {
        clearTimeout(timer);
      }
      if (response) {
        if (response.status === 200) return payload;
        if (!RETRY_STATUS.has(response.status) || attempt >= maxRetries
            || (response.status === 429 && isQuota(payload))) {
          throw cloudErrorFor(response.status, payload);
        }
      }
      await sleep(backoffMs(attempt, retryAfterMs(response?.headers)));
    }
  }
}

/**
 * The account an API key belongs to: summary, credits, usage and keys.
 *
 * These calls pass with an API key while the service accepts account calls
 * without a browser `Origin` (its `EUREDACT_CONSOLE_REQUIRE_ORIGIN=0`); a
 * refusal arrives as a `CloudError` with status 403.
 */
export class Account extends ApiClient {
  async summary(): Promise<AccountSummary> {
    const raw = await this.call("GET", "/v1/account");
    const tenant = obj(raw.tenant), retention = obj(raw.retention), usage = obj(raw.usage);
    return {
      tenantId: str(tenant.id), tenantName: str(tenant.name), active: bool(tenant.active),
      memberSince: str(tenant.member_since), role: str(raw.role),
      retentionMode: str(retention.mode), payloadTtlHours: int(retention.payload_ttl_hours),
      documentsToday: int(usage.documents_today), documentsThisMonth: int(usage.documents_this_month),
      tokensThisMonth: int(usage.tokens_this_month), failures24h: int(usage.failures_24h),
      dailyQuota: int(usage.daily_quota), quotaRemaining: int(usage.quota_remaining),
      activeKeys: int(obj(raw.keys).active), batchesAvailable: bool(obj(raw.batches).available),
      raw,
    };
  }

  async credits(): Promise<Credits> {
    const raw = await this.call("GET", "/v1/account/credits");
    return { balance: int(raw.balance), granted: int(raw.granted), spent: int(raw.spent),
             unit: str(raw.unit), raw };
  }

  /** Recent credit movements, newest first (1-500). */
  async creditHistory(limit = 50): Promise<CreditEntry[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new RangeError("limit must be between 1 and 500");
    }
    const data = await this.call("GET", "/v1/account/credits/history", { limit });
    return objects(data.entries).map(r => ({
      at: str(r.at), delta: int(r.delta), reason: str(r.reason), count: int(r.count),
      jobId: str(r.job_id), sourceRef: str(r.source_ref), raw: r,
    }));
  }

  /** Documents, tokens and failures per day over the last `days`. */
  async usage(days = 30): Promise<UsageDay[]> {
    if (!Number.isInteger(days) || days < 1) throw new RangeError("days must be at least 1");
    const data = await this.call("GET", "/v1/account/usage", { days });
    return objects(data.series).map(usageDay);
  }

  /** The same window, split by the key that submitted the work. */
  async usageByKey(days = 30): Promise<KeyUsage[]> {
    if (!Number.isInteger(days) || days < 1) throw new RangeError("days must be at least 1");
    const data = await this.call("GET", "/v1/account/usage/by-key", { days });
    return objects(data.keys).map(r => ({
      keyId: int(r.key_id), name: str(r.name), documents: int(r.documents),
      tokens: int(r.tokens), failures: int(r.failures), series: objects(r.series).map(usageDay), raw: r,
    }));
  }

  async keys(): Promise<ApiKey[]> {
    const data = await this.call("GET", "/v1/account/keys");
    return objects(data.keys).map(r => ({
      id: int(r.id), name: str(r.name), createdBy: str(r.created_by), createdAt: str(r.created_at),
      lastUsedAt: str(r.last_used_at), revokedAt: str(r.revoked_at), active: bool(r.active), raw: r,
    }));
  }

  /**
   * Revoke a key, e.g. one that leaked: the one write a key may make. Sent once,
   * never retried. Already revoked throws a `CloudError` with status 409; a key
   * that does not exist, or is another account's, throws `NotFoundError`.
   * Revoking the key this client uses works, and is reported by `selfRevoked`.
   */
  async revokeKey(keyId: number): Promise<KeyRevocation> {
    if (!Number.isInteger(keyId)) throw new RangeError("keyId must be an integer");
    const raw = await this.call("POST", `/v1/account/keys/${keyId}/revoke`);
    return { id: int(raw.id), keysRemaining: int(raw.keys_remaining), lockedOut: bool(raw.locked_out),
             selfRevoked: bool(raw.self_revoked), raw };
  }
}

/** Past jobs, by id. */
export class Jobs extends ApiClient {
  /**
   * A job's state, and its result if it has one. Throws `ResultExpiredError`
   * when the job succeeded but its result is no longer retained, and
   * `NotFoundError` for an unknown job (or another account's).
   */
  async retrieve(jobId: string): Promise<Job> {
    const raw = await this.call("GET", `/v1/jobs/${encodeURIComponent(jobId)}`);
    const result = typeof raw.redacted_text === "string"
      ? toResult(raw as never, raw.redacted_text)
      : null;
    return {
      jobId: str(raw.job_id) ?? jobId,
      status: str(raw.status) ?? (result ? "succeeded" : ""),
      createdAt: str(raw.created_at),
      result,
      raw,
    };
  }
}
