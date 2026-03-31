"""Greece (EL) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ELConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "EL"
        self.name = "Greece"
        self.patterns = [
            # AFM (Tax ID, 9 digits)
            PatternDef(entity_type=EntityType.TAX_ID, pattern=r"\b\d{9}\b",
                       validator="greek_afm",
                       description="Greek AFM — 9 digits with mod-11 check"),
            # AMKA (Social Security, 11 digits with Luhn)
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{11}\b",
                       validator="greek_amka",
                       description="Greek AMKA — 11 digits with Luhn check"),
            # IBAN
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bGR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                       validator="iban", description="Greek IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bGR\d{25}\b",
                       validator="iban", description="Greek IBAN — compact"),
            # VAT
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bEL\d{9}\b",
                       validator=None, description="Greek VAT — EL + 9 digits"),
            # Phone (mobile 69X, landline 2XX)
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b69\d[\s\-]?\d{3,4}[\s\-]?\d{4}\b",
                       validator=None, description="Greek mobile phone — 69X XXXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b69\d{8}\b",
                       validator=None, description="Greek mobile phone — compact"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b2\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b",
                       validator=None, description="Greek landline — 2XX XXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+30\s?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
                       validator=None, description="Greek international phone — +30"),
            # Postal Code (XXX XX)
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{3}\s?\d{2}\b",
                       validator=None, description="Greek postal code — XXX XX",
                       context_keywords=["Τ.Κ.", "ταχυδρομικός", "address", "Address:", "Postal:",
                                         "διεύθυνση", "οδός"],
                       requires_context=True),
        ]
