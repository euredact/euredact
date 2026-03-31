export enum EntityType {
  NAME = "NAME",
  ADDRESS = "ADDRESS",
  IBAN = "IBAN",
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

export enum DetectionSource {
  RULES = "rules",
  CLOUD = "cloud",
}

export interface Detection {
  entityType: EntityType | string;
  start: number;
  end: number;
  text: string;
  source: DetectionSource;
  country: string | null;
  confidence: string;
}

export interface RedactResult {
  redactedText: string;
  detections: Detection[];
  source: string;
  degraded: boolean;
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
