"""Shared types for EuRedact PII detection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntityType(str, Enum):
    """PII entity categories. Shared between rule engine and cloud tier.

    Names are canonical. ``EntityType.IBAN`` is kept as a **legacy alias** of
    :attr:`BANK_ACCOUNT` so existing code continues to work, but the emitted
    value — and therefore the ``[BANK_ACCOUNT]`` placeholder written into
    redacted text — is the canonical name.
    """

    NAME = "NAME"  # [CLOUD EXTENSION]
    ADDRESS = "ADDRESS"  # [CLOUD EXTENSION]
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IBAN = "BANK_ACCOUNT"  # legacy alias -> BANK_ACCOUNT
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

    @classmethod
    def _missing_(cls, value: object) -> "EntityType | None":
        """Resolve legacy type names so ``EntityType("IBAN")`` keeps working."""
        if isinstance(value, str):
            canonical = LEGACY_TYPE_ALIASES.get(value.upper())
            if canonical is not None:
                return cls(canonical)
        return None


# Legacy type names accepted on input and mapped to their canonical form.
# Kept in sync with the pipeline canon (config/entity_types.json →
# legacy_aliases). The engine never *emits* these names.
LEGACY_TYPE_ALIASES: dict[str, str] = {
    "IBAN": "BANK_ACCOUNT",
}


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
    out_of_scope: bool = False
    """True when attributed to a country the caller did not declare.

    ``countries=`` narrows *scoring*, never detection. An entity from outside
    the declared set is emitted and flagged, not dropped: callers assert
    context, they do not suppress evidence.
    """


@dataclass
class RedactResult:
    """Returned by redact()."""

    redacted_text: str
    detections: list[Detection]
    source: str = "rules"
    degraded: bool = False
