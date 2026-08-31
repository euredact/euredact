/** [CLOUD EXTENSION] Cloud tier configuration. */

export const DEFAULT_BASE_URL = "https://api.euredact.dev";

/**
 * How long to wait for a single document. The service holds a connection open
 * for its sync window and then hands back a job handle, so this has to exceed
 * that window or the client abandons requests the service is about to answer.
 */
export const DEFAULT_TIMEOUT_MS = 90_000;

/**
 * Total wall-clock budget for a document that outlives the sync window and has
 * to be polled. Cold-starting a GPU node and loading an ~18 GB checkpoint takes
 * minutes, and an async job absorbs that invisibly — but not forever.
 */
export const DEFAULT_POLL_TIMEOUT_MS = 900_000;

export const DEFAULT_MAX_RETRIES = 3;

export interface CloudConfig {
  apiKey: string;
  baseUrl: string;
  timeoutMs: number;
  pollTimeoutMs: number;
  maxRetries: number;
  /** Extra headers, for a proxy or a self-hosted deployment. */
  headers: Record<string, string>;
}

export interface ConfigureOptions {
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  pollTimeoutMs?: number;
  maxRetries?: number;
  headers?: Record<string, string>;
}

let config: CloudConfig | null = null;

/** Read an env var where there is an environment to read. Browsers have none. */
function env(name: string): string | undefined {
  const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return proc?.env?.[name];
}

/**
 * Configure the cloud tier.
 *
 * Falls back to `EUREDACT_API_KEY` and `EUREDACT_BASE_URL` so a key never has
 * to be written into source to get started.
 */
export function configure(options: ConfigureOptions = {}): CloudConfig {
  const apiKey = options.apiKey ?? env("EUREDACT_API_KEY") ?? "";
  if (!apiKey) {
    throw new Error(
      "no API key: pass configure({ apiKey }) or set EUREDACT_API_KEY",
    );
  }
  config = {
    apiKey,
    baseUrl: (options.baseUrl ?? env("EUREDACT_BASE_URL") ?? DEFAULT_BASE_URL)
      .replace(/\/+$/, ""),
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    pollTimeoutMs: options.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS,
    maxRetries: options.maxRetries ?? DEFAULT_MAX_RETRIES,
    headers: { ...(options.headers ?? {}) },
  };
  return config;
}

/** The active configuration, or null. Never throws. */
export function getConfig(): CloudConfig | null {
  return config;
}

/** Forget the configuration. Mainly for tests. */
export function reset(): void {
  config = null;
}
