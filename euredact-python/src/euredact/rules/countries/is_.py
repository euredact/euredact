"""Iceland (IS) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ISConfig(CountryConfig):
    """Icelandic PII patterns: kennitala, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "IS"
        self.name = "Iceland"
        self.patterns = [
            # --- Kennitala (DDMMYY-RRCK, 10 digits) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{6}-?\d{4}\b",
                validator="icelandic_kt",
                description="Icelandic kennitala — 10 digits with mod-11 check",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bIS\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="Icelandic IBAN — IS + 24 digits",
            ),
            # --- Phone (national, 7 digits with space: XXX XXXX) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[3-9]\d{2}\s\d{4}\b",
                validator=None,
                description="Icelandic phone — XXX XXXX (space-separated)",
            ),
            # 7 digits compact — needs context (too many 7-digit numbers)
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[3-9]\d{6}\b",
                validator=None,
                description="Icelandic phone — 7 digits compact",
                context_keywords=[
                    "sími", "símanúmer", "farsími", "gsm", "phone", "tel",
                    "hringja", "hringdu", "ná í", "nás á", "nás",
                    "SMS", "sent to",
                ],
                requires_context=True,
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+354\s?\d{3}\s?\d{4}",
                validator=None,
                description="Icelandic international phone — +354",
            ),
            # --- License Plate (XX XXX or XXX XX) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}\s?\d{3}\b",
                validator=None,
                description="Icelandic license plate — XX 123",
                context_keywords=[
                    "skráningarnúmer", "bílnúmer", "ökutæki",
                    "bifreið", "plata",
                ],
                requires_context=True,
            ),
            # --- Postal Code (3 digits, 101-999) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{2}\b",
                validator=None,
                description="Icelandic postal code — 3 digits",
                context_keywords=[
                    "póstnúmer", "póstfang", "staður", "heimilisfang",
                ],
                requires_context=True,
            ),
        ]
