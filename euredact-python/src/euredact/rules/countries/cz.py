"""Czech Republic (CZ) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class CZConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "CZ"
        self.name = "Czech Republic"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{6}/?\d{3,4}\b",
                       validator="czech_birth_number", description="Czech rodné číslo — YYMMDD/SSSC"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bCZ\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Czech IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bCZ\d{22}\b",
                       validator="iban", description="Czech IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bCZ\d{8,10}\b",
                       validator=None, description="Czech DIČ — CZ + 8-10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[67]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Czech phone — 9 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[67]\d{8}\b",
                       validator=None, description="Czech phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+420\s?[67]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                       validator=None, description="Czech international phone — +420"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{3}\s?\d{2}\b",
                       validator=None, description="Czech postal code — XXX XX",
                       context_keywords=["PSČ", "poštovní", "adresa", "ulice", "Postal:", "Address:"],
                       requires_context=True),
        ]
