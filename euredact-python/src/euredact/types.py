"""Shared types for EuRedact PII detection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntityType(str, Enum):
    """PII entity categories. Shared between rule engine and cloud tier."""

    NAME = "NAME"  # [CLOUD EXTENSION]
    ADDRESS = "ADDRESS"  # [CLOUD EXTENSION]
    IBAN = "IBAN"
    BIC = "BIC"
    CREDIT_CARD = "CREDIT_CARD"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    DOB = "DOB"
    DATE_OF_DEATH = "DATE_OF_DEATH"
    NATIONAL_ID = "NATIONAL_ID"
    SSN = "SSN"
    TAX_ID = "TAX_ID"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    RESIDENCE_PERMIT = "RESIDENCE_PERMIT"
    LICENSE_PLATE = "LICENSE_PLATE"
    VIN = "VIN"
    VAT = "VAT"
    POSTAL_CODE = "POSTAL_CODE"
    IP_ADDRESS = "IP_ADDRESS"
    IPV6_ADDRESS = "IPV6_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    HEALTH_INSURANCE = "HEALTH_INSURANCE"
    HEALTHCARE_PROVIDER = "HEALTHCARE_PROVIDER"
    CHAMBER_OF_COMMERCE = "CHAMBER_OF_COMMERCE"
    IMEI = "IMEI"
    GPS_COORDINATES = "GPS_COORDINATES"
    UUID = "UUID"
    SOCIAL_HANDLE = "SOCIAL_HANDLE"
    SECRET = "SECRET"
    OTHER = "OTHER"


class DetectionSource(str, Enum):
    """Where a detection originated."""

    RULES = "rules"
    CLOUD = "cloud"  # [CLOUD EXTENSION]


@dataclass(frozen=True)
class Detection:
    """A single PII detection in the input text."""

    entity_type: EntityType | str
    start: int
    end: int
    text: str
    source: DetectionSource
    country: str | None
    confidence: str = "high"


@dataclass
class RedactResult:
    """Returned by redact()."""

    redacted_text: str
    detections: list[Detection]
    source: str = "rules"
    degraded: bool = False
