"""Ireland (IE) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class IEConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "IE"
        self.name = "Ireland"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b\d{7}[A-W][ABWTXZ]?\b",
                       validator="irish_pps",
                       description="Irish PPS Number — 7 digits + check letter(s)"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bIE\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                       validator="iban", description="Irish IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bIE\d{2}[A-Z]{4}\d{14}\b",
                       validator="iban", description="Irish IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT,
                       pattern=r"\bIE\d{7}[A-Z]\b",
                       validator=None, description="Irish VAT — IE + 7 digits + letter"),
            # Mobile: 08X/09X
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[89]\d[\s\-]?\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="Irish mobile — 08X XXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[89]\d{8}\b",
                       validator=None, description="Irish mobile — compact"),
            # Landline: 01/0XX/0XXX
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b0[1-9]\d{0,2}[\s\-]?\d{5,8}\b",
                       validator=None, description="Irish landline — 0XX XXXXXXX"),
            # International
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+353\s?\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
                       validator=None, description="Irish international phone — +353"),
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b",
                       validator=None, description="Irish Eircode — A65 F4E2",
                       context_keywords=["Eircode", "postcode", "postal code", "address", "Address:", "Postal:"],
                       requires_context=True),
        ]
