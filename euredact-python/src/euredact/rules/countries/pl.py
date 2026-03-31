"""Poland (PL) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class PLConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "PL"
        self.name = "Poland"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{11}\b",
                       validator="polish_pesel", description="Polish PESEL — 11 digits"),
            PatternDef(entity_type=EntityType.TAX_ID, pattern=r"\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b",
                       validator="polish_nip", description="Polish NIP — 10 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bPL\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Polish IBAN — PL + 26 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bPL\d{26}\b",
                       validator="iban", description="Polish IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bPL\d{10}\b",
                       validator=None, description="Polish VAT — PL + 10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Polish phone — 9 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[5-8]\d{8}\b",
                       validator=None, description="Polish phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+48\s?[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                       validator=None, description="Polish international phone — +48"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{2}-\d{3}\b",
                       validator=None, description="Polish postal code — XX-XXX",
                       context_keywords=["kod pocztowy", "adres", "ulica", "Postal:", "Address:"]),
        ]
