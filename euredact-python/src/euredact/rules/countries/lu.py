"""Luxembourg (LU) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class LUConfig(CountryConfig):
    """Luxembourg PII patterns: Matricule, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "LU"
        self.name = "Luxembourg"
        self.patterns = [
            # --- Matricule (National ID) ---
            # Format: YYYYMMDDXXXXX (13 digits: birth date + sequence + check)
            # Spaced: 1985 09 08 149 50 — date prefix makes this distinctive
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b(?:19|20)\d{2}\s(?:0[1-9]|1[0-2])\s(?:0[1-9]|[12]\d|3[01])\s\d{3}\s\d{2}\b",
                validator=None,
                description="Luxembourg Matricule — spaced (YYYY MM DD XXX XX)",
            ),
            # Matricule compact (no spaces)
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{5}\b",
                validator=None,
                description="Luxembourg Matricule — 13 digits compact",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bLU\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\b",
                validator="iban",
                description="Luxembourg IBAN — LU + 2 check digits + 16 alphanumeric",
            ),
            # --- VAT ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bLU\s?\d{8}\b",
                validator="vat_lu",
                description="Luxembourg VAT — LU + 8 digits",
            ),
            # --- Phone (national) ---
            # LU landline: 2-digit prefix + 6 digits; mobile: 6xx xxx xxx
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b(?:2[0-9]|[4-9]\d)[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b",
                validator=None,
                description="Luxembourg national phone — 8 digits with separators",
            ),
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b(?:2[0-9]|[4-9]\d)\d{6}\b",
                validator=None,
                description="Luxembourg national phone — 8 digits compact",
            ),
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b6[2-9]\d[\s\-]?\d{3}[\s\-]?\d{3}\b",
                validator=None,
                description="Luxembourg mobile phone — 6xx xxx xxx",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+352\s?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2,4}",
                validator=None,
                description="Luxembourg international phone — +352",
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\bL[\-\s]?\d{4}\b",
                validator=None,
                description="Luxembourg postal code — L-XXXX",
            ),
            # --- License Plate ---
            # Format since 2013: 2 letters + 3-5 digits
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}[\s\-]?\d{3,5}\b",
                validator=None,
                description="Luxembourg license plate — 2 letters + 3-5 digits",
                context_keywords=[
                    "plaque", "immatriculation", "Kennzeichen", "nummerplaat",
                    "véhicule", "voiture", "Fahrzeug", "immatriculé",
                ],
                requires_context=True,
            ),
            # --- Chamber of Commerce (RCS Luxembourg) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b[ABCDEFGJ]\s?\d{4,6}\b",
                validator=None,
                description="Luxembourg RCS number — letter + digits",
                context_keywords=[
                    "RCS", "Registre de Commerce", "Handelsregister",
                    "registre", "inscrit",
                ],
                requires_context=True,
            ),
        ]
