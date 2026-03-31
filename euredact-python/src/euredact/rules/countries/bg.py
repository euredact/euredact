"""Bulgaria (BG) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class BGConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "BG"
        self.name = "Bulgaria"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{10}\b",
                       validator="bulgarian_egn", description="Bulgarian EGN — 10 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bBG\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                       validator="iban", description="Bulgarian IBAN — spaced/compact"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bBG\d{9,10}\b",
                       validator=None, description="Bulgarian VAT — BG + 9/10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?[89][789][\s\-]?\d{3}[\s\-]?\d{3,4}\b",
                       validator=None, description="Bulgarian phone — 08X/09X XXX XXX(X)"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?[89][789]\d{7,8}\b",
                       validator=None, description="Bulgarian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+359\s?[89][789][\s\-]?\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Bulgarian international phone — +359"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b[1-9]\d{3}\b",
                       validator=None, description="Bulgarian postal code — 4 digits",
                       context_keywords=["пощенски код", "пощенски", "адрес", "ул.", "Postal:", "Address:"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                       validator=None, description="Bulgarian postal code — in address structure"),
        ]
