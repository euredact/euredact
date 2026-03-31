"""Cyprus (CY) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class CYConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "CY"
        self.name = "Cyprus"
        self.patterns = [
            # TIC (Tax ID, 8 digits + letter) — also used as national ID
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{8}[A-Z]\b",
                       validator=None,
                       description="Cypriot TIC / ID — 8 digits + letter"),
            # IBAN
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bCY\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Cypriot IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bCY\d{26}\b",
                       validator="iban", description="Cypriot IBAN — compact"),
            # VAT
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bCY\d{8}[A-Z]\b",
                       validator=None, description="Cypriot VAT — CY + 8 digits + letter"),
            # Phone (8 digits: mobile 9X, landline 2X — various groupings)
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[29]\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="Cypriot phone — XXXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[29]\d[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Cypriot phone — XX XXX XXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[29]\d{7}\b",
                       validator=None, description="Cypriot phone — compact"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+357\s?[29]\d[\s\-]?\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Cypriot international phone — +357"),
            # Postal Code (4 digits)
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b[1-9]\d{3}\b",
                       validator=None, description="Cypriot postal code — 4 digits",
                       context_keywords=["Τ.Κ.", "ταχυδρομικός", "address", "Address:", "Postal:",
                                         "διεύθυνση"],
                       requires_context=True),
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                       validator=None, description="Cypriot postal code — address structure"),
        ]
