"""Slovakia (SK) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class SKConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "SK"
        self.name = "Slovakia"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{6}/?\d{3,4}\b",
                       validator="czech_birth_number", description="Slovak rodné číslo — same as Czech"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bSK\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Slovak IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bSK\d{22}\b",
                       validator="iban", description="Slovak IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bSK\d{10}\b",
                       validator=None, description="Slovak VAT — SK + 10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?9\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Slovak phone — 09XX XXX XXX"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+421\s?9\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                       validator=None, description="Slovak international phone — +421"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{3}\s?\d{2}\b",
                       validator=None, description="Slovak postal code — XXX XX",
                       context_keywords=["PSČ", "poštové", "adresa", "ulica", "Postal:", "Address:"],
                       requires_context=True),
        ]
