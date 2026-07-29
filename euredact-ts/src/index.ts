export { EntityType, DetectionSource, LEGACY_TYPE_ALIASES } from "./types.js";
export type { Detection, RedactResult, PatternDef, CountryConfig, CountryEvidence } from "./types.js";
export { DocumentContext } from "./rules/context.js";
export { EuRedact, type RedactOptions } from "./sdk.js";
export { COUNTRY_CONFIGS } from "./rules/countries/index.js";
export { setBicRegistry, getBicRegistry, SEED_BIC6_PREFIXES, type BicRegistryProvider } from "./rules/bicRegistry.js";

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

export function addCustomPattern(name: string, pattern: string): void {
  getInstance().addCustomPattern(name, pattern);
}

export function clear(): void {
  getInstance().clear();
}

export function redactBatch(texts: string[], options?: RedactOptions): RedactResult[] {
  return getInstance().redactBatch(texts, options);
}
