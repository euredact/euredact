"""Croatia (HR) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class HRConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "HR"
        self.name = "Croatia"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{11}\b",
                       validator="croatian_oib", description="Croatian OIB — 11 digits ISO 7064"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bHR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                       validator="iban", description="Croatian IBAN — 4+4+4+4+3 grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bHR\d{2}\s\d{4}\s\d{4}\s\d{4}\s\d{5}\b",
                       validator="iban", description="Croatian IBAN — 4+4+4+5 grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bHR\d{19}\b",
                       validator="iban", description="Croatian IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bHR\d{11}\b",
                       validator=None, description="Croatian PDV — HR + 11 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?9[12579][\s\-]?\d{3}[\s\-]?\d{3,4}\b",
                       validator=None, description="Croatian phone — 09X XXX XXX(X)"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?9[12579]\d{7,8}\b",
                       validator=None, description="Croatian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+385\s?9[12579][\s\-]?\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Croatian international phone — +385"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b[1-5]\d{4}\b",
                       validator=None, description="Croatian postal code — 5 digits",
                       context_keywords=["poštanski broj", "poštanski", "adresa", "ulica", "Postal:", "Address:"],
                       requires_context=True),
        ]
