"""Romania (RO) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ROConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "RO"
        self.name = "Romania"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b[1-8]\d{12}\b",
                       validator="romanian_cnp", description="Romanian CNP — 13 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bRO\d{2}[A-Z]{4}\d{16}\b",
                       validator="iban", description="Romanian IBAN — RO + 4 letters + 16 digits"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bRO\d{2,10}\b",
                       validator=None, description="Romanian CUI — RO + 2-10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?7[2-9]\d{1}[\s\-]?\d{3}[\s\-]?\d{3,4}\b",
                       validator=None, description="Romanian phone — 07XX XXX XXX(X)"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b0?7[2-9]\d{7,8}\b",
                       validator=None, description="Romanian phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+40\s?7[2-9]\d{1}[\s\-]?\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Romanian international phone — +40"),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{6}\b",
                       validator=None, description="Romanian postal code — 6 digits",
                       context_keywords=["cod poștal", "cod postal", "adresă", "strada", "Postal:", "Address:"],
                       requires_context=True),
        ]
