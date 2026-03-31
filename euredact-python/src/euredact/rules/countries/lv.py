"""Latvia (LV) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class LVConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "LV"
        self.name = "Latvia"
        self.patterns = [
            # Personas kods: DDMMYY-XXXXX (11 digits with dash)
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b\d{6}-\d{5}\b",
                       validator=None,
                       description="Latvian personas kods — DDMMYY-XXXXX with dash"),
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{7}\b",
                       validator=None,
                       description="Latvian personas kods — 11 digits compact",
                       context_keywords=["personas kods", "PK", "identifikācijas"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bLV\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d\b",
                       validator="iban", description="Latvian IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bLV\d{2}[A-Z]{4}\d{13}\b",
                       validator="iban", description="Latvian IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT,
                       pattern=r"\bLV\d{11}\b",
                       validator=None, description="Latvian VAT (PVN) — LV + 11 digits"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[2]\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="Latvian phone — XXXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[2]\d{7}\b",
                       validator=None, description="Latvian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+371\s?[2]\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Latvian international phone — +371"),
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\bLV-\d{4}\b",
                       validator=None, description="Latvian postal code — LV-XXXX"),
        ]
