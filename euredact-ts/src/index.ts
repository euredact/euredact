export { EntityType, DetectionSource, LEGACY_TYPE_ALIASES, canonicalType } from "./types.js";
export type { Detection, RedactResult, PatternDef, CountryConfig, CountryEvidence } from "./types.js";
export { DocumentContext } from "./rules/context.js";
export { EuRedact, type RedactOptions } from "./sdk.js";
export { COUNTRY_CONFIGS } from "./rules/countries/index.js";
export { setBicRegistry, getBicRegistry, SEED_BIC6_PREFIXES, type BicRegistryProvider } from "./rules/bicRegistry.js";
export {
  configure,
  getConfig,
  CloudClient,
  CloudError,
  NotConfiguredError,
  QuotaExceededError,
  TooLargeError,
  type CloudConfig,
  type ConfigureOptions,
  type CloudRedactOptions,
} from "./cloud/index.js";

import { EuRedact, type RedactOptions } from "./sdk.js";
import type { RedactResult } from "./types.js";
import { COUNTRY_CONFIGS } from "./rules/countries/index.js";

let _instance: EuRedact | null = null;

function getInstance(): EuRedact {
  if (_instance === null) _instance = new EuRedact();
  return _instance;
}

export function availableCountries(): string[] {
  return Object.keys(COUNTRY_CONFIGS).filter(c => c !== "SHARED").sort();
}

export function redact(text: string, options?: RedactOptions): RedactResult {
  return getInstance().redact(text, options);
}

/**
 * Redact, awaiting the cloud tier when `mode: "cloud"` is asked for.
 *
 * `mode: "rules"` resolves immediately with exactly what `redact()` returns,
 * so a caller that may or may not use the cloud tier can hold one code path.
 */
export function redactAsync(
  text: string,
  options?: RedactOptions,
): Promise<RedactResult> {
  return getInstance().redactAsync(text, options);
}

export function addCustomPattern(name: string, pattern: string): void {
  getInstance().addCustomPattern(name, pattern);
}

export function clear(): void {
  getInstance().clear();
}

export function redactBatch(texts: string[], options?: RedactOptions): RedactResult[] {
  return getInstance().redactBatch(texts, options);
}
