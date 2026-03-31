"""Spain (ES) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ESConfig(CountryConfig):
    """Spanish PII patterns: DNI, NIE, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "ES"
        self.name = "Spain"
        self.patterns = [
            # --- DNI (8 digits + check letter) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{8}[A-Z]\b",
                validator="spanish_dni",
                description="Spanish DNI — 8 digits + mod-23 check letter",
            ),
            # --- NIE (X/Y/Z + 7 digits + check letter) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[XYZ]\d{7}[A-Z]\b",
                validator="spanish_nie",
                description="Spanish NIE — X/Y/Z + 7 digits + check letter",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bES\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                validator="iban",
                description="Spanish IBAN — ES + 22 digits",
            ),
            # --- VAT (NIF/CIF) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bES[A-Z0-9]\d{7}[A-Z0-9]\b",
                validator=None,
                description="Spanish VAT (NIF/CIF) — ES + letter/digit + 7 digits + letter/digit",
            ),
            # --- Phone (9 digits, various groupings) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[679]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                validator=None,
                description="Spanish phone — XXX XXX XXX",
            ),
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[679]\d{8}\b",
                validator=None,
                description="Spanish phone — 9 digits compact",
            ),
            # Spaced pair format: XX XXX XX XX
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[679]\d[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b",
                validator=None,
                description="Spanish phone — XX XXX XX XX",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+34\s?[679]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                validator=None,
                description="Spanish international phone — +34",
            ),
            # --- License Plate (XXXX AAA) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b\d{4}\s?[BCDFGHJKLMNPRSTVWXYZ]{3}\b",
                validator=None,
                description="Spanish license plate — 4 digits + 3 letters",
            ),
            # --- Postal Code (5 digits) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b(?:0[1-9]|[1-4]\d|5[0-2])\d{3}\b",
                validator=None,
                description="Spanish postal code — 5 digits (01000-52999)",
                context_keywords=[
                    "código postal", "C.P.", "CP", "dirección",
                    "domicilio", "calle", "avenida", "plaza",
                    "paseo", "camino", "Postal:",
                ],
                requires_context=True,
            ),
        ]
