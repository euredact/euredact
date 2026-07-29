export enum EntityType {
  NAME = "NAME",
  ADDRESS = "ADDRESS",
  /**
   * Canonical name for a bank account identifier. `IBAN` is kept below as a
   * legacy alias with the same value, so `EntityType.IBAN === EntityType.BANK_ACCOUNT`
   * and existing code keeps working — but the emitted value, and therefore the
   * `[BANK_ACCOUNT]` placeholder written into redacted text, is canonical.
   */
  BANK_ACCOUNT = "BANK_ACCOUNT",
  /** @deprecated legacy alias of {@link EntityType.BANK_ACCOUNT} */
  IBAN = "BANK_ACCOUNT",
  BIC = "BIC",
  CREDIT_CARD = "CREDIT_CARD",
  PHONE = "PHONE",
  EMAIL = "EMAIL",
  DOB = "DOB",
  DATE_OF_DEATH = "DATE_OF_DEATH",
  NATIONAL_ID = "NATIONAL_ID",
  SSN = "SSN",
  TAX_ID = "TAX_ID",
  PASSPORT = "PASSPORT",
  DRIVERS_LICENSE = "DRIVERS_LICENSE",
  RESIDENCE_PERMIT = "RESIDENCE_PERMIT",
  LICENSE_PLATE = "LICENSE_PLATE",
  VIN = "VIN",
  VAT = "VAT",
  POSTAL_CODE = "POSTAL_CODE",
  IP_ADDRESS = "IP_ADDRESS",
  IPV6_ADDRESS = "IPV6_ADDRESS",
  MAC_ADDRESS = "MAC_ADDRESS",
  HEALTH_INSURANCE = "HEALTH_INSURANCE",
  HEALTHCARE_PROVIDER = "HEALTHCARE_PROVIDER",
  CHAMBER_OF_COMMERCE = "CHAMBER_OF_COMMERCE",
  IMEI = "IMEI",
  GPS_COORDINATES = "GPS_COORDINATES",
  UUID = "UUID",
  SOCIAL_HANDLE = "SOCIAL_HANDLE",
  SECRET = "SECRET",
  OTHER = "OTHER",
}

/**
 * Legacy type names accepted on input and mapped to their canonical form.
 * Kept in sync with the pipeline canon (config/entity_types.json →
 * legacy_aliases). The engine never *emits* these names.
 */
export const LEGACY_TYPE_ALIASES: Record<string, string> = {
  IBAN: "BANK_ACCOUNT",
};

export enum DetectionSource {
  RULES = "rules",
  CLOUD = "cloud",
}

/**
 * One reason to believe a document belongs to a country.
 *
 * Emitted by entities that carry their country in the string — an IBAN's
 * country code, a `+CC` dialling prefix, a VAT prefix, an email ccTLD.
 * Auditable by design: every inference traces back to the span and the source
 * that produced it.
 */
export interface CountryEvidence {
  /** ISO 3166-1 alpha-2. */
  country: string;
  /** Which signal produced this — "ibanPrefix", "e164Prefix", ... */
  source: string;
  /** Natural-log odds. Derived from the corpus, not hand-tuned. */
  logOdds: number;
  /** Offsets into the text that was scanned. */
  span: [number, number];
}

export interface Detection {
  entityType: EntityType | string;
  start: number;
  end: number;
  text: string;
  source: DetectionSource;
  country: string | null;
  confidence: string;
  /**
   * How strongly the document supports {@link Detection.country}, in [0, 1].
   *
   * 0 when no country was attributed or nothing corroborated it — which is the
   * signal that an attribution rests on a checksum alone.
   */
  countryConfidence?: number;
  /**
   * True when attributed to a country the caller did not declare.
   *
   * `countries` narrows *scoring*, never detection. An entity from outside the
   * declared set is emitted and flagged, not dropped: callers assert context,
   * they do not suppress evidence.
   */
  outOfScope?: boolean;
}

export interface RedactResult {
  redactedText: string;
  detections: Detection[];
  source: string;
  degraded: boolean;
  /**
   * Countries this document appears to belong to, strongest first, as
   * `[country, confidence]` with confidence in [0, 1].
   *
   * Inferred from entities that carry their country in the string. Reported so
   * the inference can be audited; it influences which national scheme is
   * attributed to an ambiguous value, never which spans are found.
   */
  inferredCountries: Array<[string, number]>;
  /** Every signal behind {@link RedactResult.inferredCountries}, with the span
   *  that produced it. The audit trail for a country attribution. */
  evidence: CountryEvidence[];
  /**
   * `"declared"` when the caller passed `countries`, `"inferred"` when the
   * country was worked out from the content.
   *
   * Named `detectionMode` rather than `mode` because `redact({ mode })`
   * already means the tier selector, which {@link RedactResult.source} reports.
   */
  detectionMode: string;
}

export interface PatternDef {
  entityType: EntityType | string;
  pattern: string;
  validator: string | null;
  description: string;
  contextKeywords: string[];
  requiresContext: boolean;
}

export interface CountryConfig {
  code: string;
  name: string;
  patterns: PatternDef[];
}
