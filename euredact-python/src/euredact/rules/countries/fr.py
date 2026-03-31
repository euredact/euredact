"""France (FR) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class FRConfig(CountryConfig):
    """French PII patterns: NIR/INSEE, CNI, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "FR"
        self.name = "France"
        self.patterns = [
            # --- NIR (Numéro d'Inscription au Répertoire / INSEE number) ---
            # Format: S AA MM DDD CCC NNN CC (15 digits)
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=(
                    r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?"
                    r"\d{2}[0-9AB]?\s?\d{3}\s?\d{3}\s?\d{2}\b"
                ),
                validator="french_nir",
                description="French NIR/INSEE — 15 digits with mod-97 check",
            ),
            # --- CNI (Carte Nationale d'Identité) ---
            # Old format: 12 digits; New format (2021+): alphanumeric
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{12}\b",
                validator=None,
                description="French CNI (old format) — 12 digits",
                context_keywords=[
                    "carte d'identité", "CNI", "carte nationale", "identity card",
                    "pièce d'identité",
                ],
                requires_context=True,
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                validator="iban",
                description="French IBAN — FR + 25 digits/letters",
            ),
            # --- VAT (TVA) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bFR\s?[0-9A-HJ-NP-Z]{2}\s?\d{9}\b",
                validator="vat_fr",
                description="French VAT — FR + 2 chars + 9 digits (SIREN)",
            ),
            # --- Phone (national) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=(
                    r"\b0[1-9][\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}\b"
                ),
                validator=None,
                description="French national phone — 0x xx xx xx xx",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=(
                    r"\+33\s?[1-9][\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}"
                ),
                validator=None,
                description="French international phone — +33",
            ),
            # --- Passport ---
            PatternDef(
                entity_type=EntityType.PASSPORT,
                pattern=r"\b\d{2}[A-Z]{2}\d{5}\b",
                validator=None,
                description="French passport — 2 digits + 2 letters + 5 digits",
                context_keywords=[
                    "passeport", "passport", "numéro de passeport",
                ],
                requires_context=True,
            ),
            # --- License Plate (since 2009: AA-123-AA) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}[\-\s]?\d{3}[\-\s]?[A-Z]{2}\b",
                validator=None,
                description="French license plate — AA-123-AA",
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b(?:0[1-9]|[1-8]\d|9[0-5]|97[1-6])\d{3}\b",
                validator=None,
                description="French postal code — 5 digits (department prefix)",
                context_keywords=[
                    "code postal", "CP", "postal code", "postcode",
                    "adresse", "domicilié", "résidant", "rue",
                    "avenue", "boulevard", "place", "chemin",
                    "allée", "impasse", "ville",
                ],
                requires_context=True,
            ),
            # --- Numéro de Sécurité Sociale (same as NIR for healthcare) ---
            # Covered by NIR pattern above
            # --- SIREN (9-digit enterprise number) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{3}\s?\d{3}\s?\d{3}\b",
                validator=None,
                description="French SIREN — 9 digits",
                context_keywords=[
                    "SIREN", "siren", "RCS", "entreprise", "immatricul",
                    "numéro d'entreprise", "registre du commerce",
                ],
                requires_context=True,
            ),
            # --- SIRET (14-digit establishment number) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b",
                validator=None,
                description="French SIRET — 14 digits (SIREN + NIC)",
                context_keywords=[
                    "SIRET", "siret", "établissement", "immatricul",
                ],
                requires_context=True,
            ),
            # --- Numéro fiscal (SPI) — 13 digits ---
            PatternDef(
                entity_type=EntityType.TAX_ID,
                pattern=r"\b\d{13}\b",
                validator=None,
                description="French numéro fiscal (SPI) — 13 digits",
                context_keywords=[
                    "numéro fiscal", "SPI", "référence fiscale",
                    "avis d'impôt", "impôt sur le revenu",
                    "déclaration fiscale", "fiscal",
                ],
                requires_context=True,
            ),
        ]
