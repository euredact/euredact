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

    PERSON_NAME = "PERSON_NAME"  # [CLOUD EXTENSION]
    NAME = "PERSON_NAME"  # legacy alias -> PERSON_NAME
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
    INTERNAL_ID = "INTERNAL_ID"
    """Employee, badge or customer number tied to a person.

    Emitted **only** when an explicit label names it — see
    :mod:`euredact.rules.cues`. There is no pattern for an internal identifier
    because there is no shape for one; without the label, a digit run is not
    distinguishable from any other. The type exists so that a labelled employee
    number is filed correctly instead of being claimed by the phone pattern.
    """
    IMEI = "IMEI"
    GPS_COORDINATES = "GPS_COORDINATES"
    UUID = "UUID"
    SOCIAL_HANDLE = "SOCIAL_HANDLE"
    SECRET = "SECRET"

    # [CLOUD EXTENSION] Types only the cloud tier can detect. The rule engine
    # never emits these -- there is no shape to match on -- which is exactly why
    # they exist: the model's job is what the rules cannot catch. Present in the
    # enum so a cloud detection is a first-class Detection rather than a bare
    # string, and named to match the detection canon the service returns.
    ORGANISATION_NAME = "ORGANISATION_NAME"
    JOB_TITLE = "JOB_TITLE"
    MEDICAL_CONDITION = "MEDICAL_CONDITION"
    SENSITIVE_ATTRIBUTE = "SENSITIVE_ATTRIBUTE"
    BIOMETRIC_REF = "BIOMETRIC_REF"
    FINANCIAL_AMOUNT = "FINANCIAL_AMOUNT"
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"
    CREDENTIAL = "CREDENTIAL"
    URL = "URL"

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
    # The cloud extension shipped as NAME while the detection canon the service
    # is trained and evaluated against calls it PERSON_NAME. Renamed rather than
    # translated at the boundary: two names for one type is how a whole category
    # goes missing when someone filters on the spelling they happened to know.
    # Nothing could depend on the old value -- the cloud tier was stubbed, so
    # NAME was never emitted by anything.
    "NAME": "PERSON_NAME",
    "STREET_ADDRESS": "ADDRESS",
    "NATIONALITY_ETHNICITY": "SENSITIVE_ATTRIBUTE",
}


class DetectionSource(str, Enum):
    """Where a detection originated."""

    RULES = "rules"
    CLOUD = "cloud"  # [CLOUD EXTENSION]


@dataclass(frozen=True)
class CountryEvidence:
    """One reason to believe a document belongs to a country.

    Emitted by entities that carry their country in the string — an IBAN's
    country code, a `+CC` dialling prefix, a VAT prefix, an email ccTLD.
    Auditable by design: every inference traces back to the span and the source
    that produced it.
    """

    country: str
    """ISO 3166-1 alpha-2."""
    source: str
    """Which signal produced this — "iban_prefix", "e164_prefix", ..."""
    log_odds: float
    """Natural-log odds. Derived from the corpus, not hand-tuned; see
    euredact.rules.evidence.WEIGHTS."""
    span: tuple[int, int]
    """Offsets into the text that was scanned."""


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
    country_confidence: float = 0.0
    """How strongly the document supports :attr:`country`, in [0, 1].

    0.0 when no country was attributed or nothing corroborated it — which is
    the signal that an attribution rests on a checksum alone.
    """
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

    inferred_countries: tuple[tuple[str, float], ...] = ()
    """Countries this document appears to belong to, strongest first, as
    ``(country, confidence)`` with confidence in [0, 1].

    Inferred from entities that carry their country in the string. Reported so
    the inference can be audited; it influences which national scheme is
    attributed to an ambiguous value, never which spans are found.
    """

    evidence: tuple[CountryEvidence, ...] = ()
    """Every signal behind :attr:`inferred_countries`, with the span that
    produced it. The audit trail for a country attribution."""

    detection_mode: str = "declared"
    """``"declared"`` when the caller passed ``countries=``, ``"inferred"``
    when the country was worked out from the content.

    Named ``detection_mode`` rather than ``mode`` because ``redact(mode=...)``
    already means the tier selector (``"rules"`` / ``"cloud"``), which
    :attr:`source` reports.
    """
