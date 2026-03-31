"""Slovenia (SI) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class SIConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "SI"
        self.name = "Slovenia"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{13}\b",
                       validator="slovenian_emso", description="Slovenian EMŠO — 13 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bSI\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                       validator="iban", description="Slovenian IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bSI\d{17}\b",
                       validator="iban", description="Slovenian IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bSI\d{8}\b",
                       validator=None, description="Slovenian DDV — SI + 8 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?[34567]\d{1}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Slovenian phone — 0XX XXX XXX"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?[34567]\d{7}\b",
                       validator=None, description="Slovenian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+386\s?[34567]\d{1}[\s\-]?\d{3}[\s\-]?\d{3}",
                       validator=None, description="Slovenian international phone — +386"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b[1-9]\d{3}\b",
                       validator=None, description="Slovenian postal code — 4 digits",
                       context_keywords=["poštna številka", "poštna", "naslov", "ulica", "Postal:", "Address:"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                       validator=None, description="Slovenian postal code — in address structure"),
        ]
