"""Hungary (HU) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class HUConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "HU"
        self.name = "Hungary"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{9}\b",
                       validator="hungarian_taj", description="Hungarian TAJ — 9 digits compact"),
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{3}\s\d{3}\s\d{3}\b",
                       validator="hungarian_taj", description="Hungarian TAJ — 9 digits spaced"),
            PatternDef(entity_type=EntityType.TAX_ID, pattern=r"\b8\d{9}\b",
                       validator=None, description="Hungarian tax ID — 10 digits starting with 8",
                       context_keywords=["adóazonosító", "adószám", "adóazonosító jel"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bHU\d{8,11}\b",
                       validator=None, description="Hungarian VAT — HU + 8-11 digits",
                       context_keywords=["adószám", "ÁFA"]),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bHU\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Hungarian IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bHU\d{26}\b",
                       validator="iban", description="Hungarian IBAN — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b06\s?\d{1,2}[\s\-]?\d{3}[\s\-]?\d{3,4}\b",
                       validator=None, description="Hungarian phone — 06 XX XXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+36\s?\d{1,2}[\s\-]?\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Hungarian international phone — +36"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b[1-9]\d{3}\b",
                       validator=None, description="Hungarian postal code — 4 digits",
                       context_keywords=["irányítószám", "postai", "cím", "utca", "Postal:", "Address:"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                       validator=None, description="Hungarian postal code — in address structure"),
        ]
