"""United Kingdom (UK) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class UKConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "UK"
        self.name = "United Kingdom"
        self.patterns = [
            # National Insurance Number: LL NN NN NN L
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[ABCD]\b",
                       validator=None,
                       description="UK National Insurance Number — NINO"),
            # NHS Number: 10 digits (XXX XXX XXXX)
            PatternDef(entity_type=EntityType.HEALTH_INSURANCE,
                       pattern=r"\b\d{3}\s?\d{3}\s?\d{4}\b",
                       validator="uk_nhs",
                       description="UK NHS Number — 10 digits with mod-11 check",
                       context_keywords=["NHS", "NHS number", "health number", "NHS no"],
                       requires_context=True),
            # IBAN
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bGB\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                       validator="iban", description="UK IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bGB\d{2}[A-Z]{4}\d{14}\b",
                       validator="iban", description="UK IBAN — compact"),
            # VAT
            PatternDef(entity_type=EntityType.VAT,
                       pattern=r"\bGB\d{9}\b",
                       validator=None, description="UK VAT — GB + 9 digits"),
            # Phone (mobile: 07XXX XXXXXX)
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b07[4-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="UK mobile — 07XXX XXX XXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b07[4-9]\d{8}\b",
                       validator=None, description="UK mobile — compact"),
            # Landline: 01XX/02X XXX XXXX or 0XXX XXX XXXX
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[12]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="UK landline — 01XX/02XX XXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[12]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}\b",
                       validator=None, description="UK landline — 01XX XXXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[12]\d{9,10}\b",
                       validator=None, description="UK landline — compact"),
            # International
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+44\s?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
                       validator=None, description="UK international phone — +44"),
            # Postcode (A9 9AA, A99 9AA, A9A 9AA, AA9 9AA, AA99 9AA, AA9A 9AA)
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
                       validator=None, description="UK postcode"),
        ]
