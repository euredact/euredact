"""Malta (MT) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class MTConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "MT"
        self.name = "Malta"
        self.patterns = [
            # ID Card (5-7 digits + letter from MGAPLHBZ)
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b\d{5,7}[MGAPLHBZ]\b",
                       validator=None,
                       description="Maltese ID card — 5-7 digits + letter"),
            # IBAN (31 chars: MT + 2 check + 4 bank letters + 5 branch digits + 18 account)
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=(
                           r"\bMT\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?[A-Z0-9]{4}\s?"
                           r"[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{3}\b"
                       ),
                       validator="iban", description="Maltese IBAN — 4-char grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bMT\d{2}[A-Z]{4}\d{5}[A-Z0-9]{18}\b",
                       validator="iban", description="Maltese IBAN — compact"),
            # VAT
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bMT\d{8}\b",
                       validator=None, description="Maltese VAT — MT + 8 digits"),
            # Phone (77/79/99 + 6 digits)
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[79]\d{3}[\s\-]?\d{4}\b",
                       validator=None, description="Maltese phone — XXXX XXXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b[79]\d{7}\b",
                       validator=None, description="Maltese phone — compact"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+356\s?[79]\d{3}[\s\-]?\d{3,4}",
                       validator=None, description="Maltese international phone — +356"),
            # Postal Code (XXX XXXX)
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\b[A-Z]{3}\s?\d{4}\b",
                       validator=None, description="Maltese postal code — XXX XXXX",
                       context_keywords=["kodiċi postali", "postcode", "address", "Address:", "Postal:"],
                       requires_context=True),
        ]
