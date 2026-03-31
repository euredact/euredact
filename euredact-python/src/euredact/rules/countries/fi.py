"""Finland (FI) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class FIConfig(CountryConfig):
    """Finnish PII patterns: HETU, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "FI"
        self.name = "Finland"
        self.patterns = [
            # --- HETU (henkilötunnus): DDMMYYCZZZQ ---
            # Century separator: - (1900s), + (1800s), A (2000s), B-F/Y/X/W/V/U
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{6}[-+ABCDEFYXWVU]\d{3}[0-9A-FHJK-NPR-Y]\b",
                validator="finnish_hetu",
                description="Finnish HETU — DDMMYYCZZZQ with mod-31 check",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bFI\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="Finnish IBAN — FI + 16 digits",
            ),
            # --- VAT ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bFI\d{8}\b",
                validator=None,
                description="Finnish VAT — FI + 8 digits",
            ),
            # --- Y-tunnus (Business ID: 1234567-8) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{7}-\d\b",
                validator="finnish_business_id",
                description="Finnish Y-tunnus — 7 digits + check digit",
            ),
            # --- Phone (national) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{1,2}\s?\d{3,4}\s?\d{3,4}\b",
                validator=None,
                description="Finnish national phone",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+358\s?\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
                validator=None,
                description="Finnish international phone — +358",
            ),
            # --- License Plate (ABC-123) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2,3}[\-\s]?\d{3}\b",
                validator=None,
                description="Finnish license plate — ABC-123",
                context_keywords=[
                    "rekisteritunnus", "rekisterinumero", "rekisterikilpi",
                    "ajoneuvo",
                ],
                requires_context=True,
            ),
            # --- Postal Code (5 digits) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{5}\b",
                validator=None,
                description="Finnish postal code — 5 digits",
                context_keywords=[
                    "postinumero", "postitoimipaikka", "osoite",
                    "kotiosoite", "katuosoite",
                ],
                requires_context=True,
            ),
        ]
