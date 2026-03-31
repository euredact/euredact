"""Switzerland (CH) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class CHConfig(CountryConfig):
    """Swiss PII patterns: AHV, UID, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "CH"
        self.name = "Switzerland"
        self.patterns = [
            # --- AHV number (756.XXXX.XXXX.XX) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b756\.\d{4}\.\d{4}\.\d{2}\b",
                validator="swiss_ahv",
                description="Swiss AHV number — 756.XXXX.XXXX.XY with EAN-13 check",
            ),
            # AHV compact (no dots)
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b756\d{10}\b",
                validator="swiss_ahv",
                description="Swiss AHV number — compact 13 digits",
            ),
            # --- UID (Unternehmens-ID) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\bCHE[\-\s]?\d{3}\.?\d{3}\.?\d{3}\b",
                validator=None,
                description="Swiss UID — CHE-XXX.XXX.XXX",
            ),
            # --- VAT (UID + MWST/TVA/IVA) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bCHE[\-\s]?\d{3}\.?\d{3}\.?\d{3}\s?(?:MWST|TVA|IVA)\b",
                validator=None,
                description="Swiss VAT — CHE + digits + MWST/TVA/IVA",
            ),
            # --- IBAN (Swiss IBANs can have alphanumeric account numbers) ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bCH\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]\b",
                validator="iban",
                description="Swiss IBAN — CH + 19 alphanumeric",
            ),
            # --- Phone (national) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{2}\s?\d{3}\s?\d{2}\s?\d{2}\b",
                validator=None,
                description="Swiss national phone — 0XX XXX XX XX",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+41\s?\d{2}\s?\d{3}\s?\d{2}\s?\d{2}",
                validator=None,
                description="Swiss international phone — +41",
            ),
            # --- License Plate ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}\s?\d{1,6}\b",
                validator=None,
                description="Swiss license plate — canton + number",
                context_keywords=[
                    "Kontrollschild", "Nummernschild", "plaque",
                    "immatriculation", "Kennzeichen",
                ],
                requires_context=True,
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{3}\b",
                validator=None,
                description="Swiss postal code — 4 digits",
                context_keywords=[
                    "PLZ", "Postleitzahl", "code postal", "NPA",
                    "Adresse", "Anschrift", "adresse", "rue",
                    "Straße", "Str.", "Gasse", "chemin",
                    "Postal:", "Wohnort",
                ],
                requires_context=True,
            ),
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                validator=None,
                description="Swiss postal code — in address structure",
            ),
        ]
