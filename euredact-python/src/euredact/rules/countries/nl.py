"""Netherlands (NL) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class NLConfig(CountryConfig):
    """Dutch PII patterns: BSN, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "NL"
        self.name = "Netherlands"
        self.patterns = [
            # --- BSN (Burgerservicenummer) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[0-9]{9}\b",
                validator="bsn",
                description="BSN (Burgerservicenummer) — 9 digits with 11-proof check",
            ),
            # BSN with dots (xxx.xxx.xxx or other dot-separated groupings)
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[0-9]{2,4}\.[0-9]{2,4}\.[0-9]{2,4}\b",
                validator="bsn",
                description="BSN formatted with dots",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="Dutch IBAN — NLxx BANK 0123456789",
            ),
            # --- VAT (BTW) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bNL\d{9}B\d{2}\b",
                validator="vat_nl",
                description="Dutch VAT number — NL + 9 digits + B + 2 digits",
            ),
            # --- KvK (Chamber of Commerce) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{8}\b",
                validator="kvk",
                description="Dutch KvK number — 8 digits",
                context_keywords=[
                    "KvK", "Kamer van Koophandel", "kvk-nummer", "KVK-nummer",
                    "handelsregister", "chamber of commerce",
                ],
                requires_context=True,
            ),
            # --- Phone (national landline — 3-digit area code) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0[1-9]\d[\s\-]?\d{3}[\s\-]?\d{4}\b",
                validator=None,
                description="Dutch landline — 0xx xxx xxxx (3-digit area)",
            ),
            # Phone (national landline — 4-digit area code)
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0[1-9]\d{2}[\s\-]?\d{6,7}\b",
                validator=None,
                description="Dutch landline — 0xxx xxxxxxx (4-digit area)",
            ),
            # Dutch mobile
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b06[\s\-]?\d{4}[\s\-]?\d{4}\b",
                validator=None,
                description="Dutch mobile phone — 06 xxxx xxxx",
            ),
            # Dutch mobile compact (10 digits starting with 06)
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b06\d{8}\b",
                validator=None,
                description="Dutch mobile phone — 06xxxxxxxx compact",
            ),
            # Dutch mobile with pair grouping (06 xx xx xx xx)
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b06[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b",
                validator=None,
                description="Dutch mobile phone — 06 xx xx xx xx",
            ),
            # Dutch landline with various separator patterns
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0[1-9]\d{1,2}[\s\-]?\d{2,3}[\s\-]?\d{2}[\s\-]?\d{2}\b",
                validator=None,
                description="Dutch landline — flexible separator pattern",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+31\s?[1-9]\d{0,2}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b",
                validator=None,
                description="Dutch international phone — +31",
            ),
            # --- Passport ---
            # Dutch passport: letters + digits, 9 chars total, various patterns
            PatternDef(
                entity_type=EntityType.PASSPORT,
                pattern=r"\b[A-Z][A-Z0-9]{8}\b",
                validator=None,
                description="Dutch passport — letter + 8 alphanumeric",
                context_keywords=[
                    "paspoort", "passport", "reisdocument", "travel document",
                    "paspoortnummer", "identiteitsbewijs",
                ],
                requires_context=True,
            ),
            # --- License Plate (XX-999-X, 99-XXX-9, etc.) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=(
                    r"\b(?:"
                    r"[A-Z]{2}[\-\s]?\d{3}[\-\s]?[A-Z]"
                    r"|\d[\-\s]?[A-Z]{3}[\-\s]?\d{2}"
                    r"|\d{2}[\-\s]?[A-Z]{3}[\-\s]?\d"
                    r"|[A-Z]{2}[\-\s]?\d{2}[\-\s]?[A-Z]{2}"
                    r"|\d{2}[\-\s]?[A-Z]{2}[\-\s]?\d{2}"
                    r"|\d[\-\s]?[A-Z]{2}[\-\s]?\d{3}"
                    r")\b"
                ),
                validator=None,
                description="Dutch license plate — various formats",
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{3}\s?[A-Z]{2}\b",
                validator=None,
                description="Dutch postal code — 4 digits + 2 letters",
            ),
        ]
