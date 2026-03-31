"""Estonia (EE) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class EEConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "EE"
        self.name = "Estonia"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b[1-6]\d{10}\b",
                       validator="estonian_id",
                       description="Estonian isikukood — 11 digits with mod-11 check"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bEE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Estonian IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bEE\d{18}\b",
                       validator="iban", description="Estonian IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT,
                       pattern=r"\bEE\d{9}\b",
                       validator=None, description="Estonian VAT (KMKR) — EE + 9 digits"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b5\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="Estonian phone — 5XXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b5\d{7}\b",
                       validator=None, description="Estonian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+372\s?5\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Estonian international phone — +372"),
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\b\d{5}\b",
                       validator=None, description="Estonian postal code — 5 digits",
                       context_keywords=["postiindeks", "sihtnumber", "aadress", "address", "Address:", "Postal:"],
                       requires_context=True),
        ]
