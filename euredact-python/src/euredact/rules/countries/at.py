"""Austria (AT) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ATConfig(CountryConfig):
    """Austrian PII patterns: SVNR, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "AT"
        self.name = "Austria"
        self.patterns = [
            # --- SVNR (Sozialversicherungsnummer) — 10 digits ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{4}\s?\d{6}\b",
                validator="austrian_svnr",
                description="Austrian SVNR — 10 digits with check digit",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bAT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                validator="iban",
                description="Austrian IBAN — AT + 18 digits",
            ),
            # --- VAT (UID) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bATU\d{8}\b",
                validator=None,
                description="Austrian VAT (UID) — ATU + 8 digits",
            ),
            # --- Phone (national) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{3,4}[\s\-]?\d{5,8}\b",
                validator=None,
                description="Austrian national phone",
            ),
            # Short area codes (Vienna is "01") split across three groups:
            # "01 53460 2215". The pattern above requires 3-4 digits after the
            # trunk 0, so it never matched these. Both separators are
            # mandatory here, which keeps "01 2025" (a date fragment) out.
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{1,4}[\s\-/]\d{3,7}[\s\-/]\d{2,6}\b",
                validator=None,
                description="Austrian national phone — short area code, grouped",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+43\s?\d{3,4}[\s\-]?\d{5,8}",
                validator=None,
                description="Austrian international phone — +43",
            ),
            # --- License Plate ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-ZÄÖÜ]{1,2}\s?\d{1,5}\s?[A-Z]{1,2}\b",
                validator=None,
                description="Austrian license plate — district + number + letters",
                context_keywords=[
                    "Kennzeichen", "Nummernschild", "Kfz-Kennzeichen",
                ],
                requires_context=True,
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{3}\b",
                validator=None,
                description="Austrian postal code — 4 digits",
                context_keywords=[
                    "PLZ", "Postleitzahl", "Adresse", "Anschrift",
                    "Straße", "Str.", "Gasse", "Weg", "Platz",
                    "Postal:", "Wohnort",
                ],
                requires_context=True,
            ),
            # Structural: "City, XXXX" or ", XXXX City"
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                validator=None,
                description="Austrian postal code — in address structure",
            ),
        ]
