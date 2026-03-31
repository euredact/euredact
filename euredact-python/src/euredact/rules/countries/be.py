"""Belgium (BE) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class BEConfig(CountryConfig):
    """Belgian PII patterns: Rijksregisternummer, IBAN, phone, VAT, etc."""

    def __post_init__(self) -> None:
        self.code = "BE"
        self.name = "Belgium"
        self.patterns = [
            # --- National ID (Rijksregisternummer / Numéro de registre national) ---
            # Format: YY.MM.DD-XXX.CC (11 digits)
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{2}\.?\d{2}\.?\d{2}[\-.]?\d{3}\.?\d{2}\b",
                validator="belgian_nn",
                description="Belgian Rijksregisternummer — 11 digits with mod-97 check",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bBE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                validator="iban",
                description="Belgian IBAN — BE + 14 digits",
            ),
            # --- VAT (BTW-nummer / Numéro TVA) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bBE\s?0\d{3}\.?\d{3}\.?\d{3}\b",
                validator="belgian_vat",
                description="Belgian VAT / enterprise number — BE0XXX.XXX.XXX",
            ),
            # --- Chamber of Commerce (KBO/BCE) — same format as VAT without prefix ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b0\d{3}\.?\d{3}\.?\d{3}\b",
                validator=None,
                description="Belgian KBO/BCE enterprise number — 0XXX.XXX.XXX",
                context_keywords=[
                    "KBO", "BCE", "ondernemingsnummer", "numéro d'entreprise",
                    "enterprise number", "bedrijfsnummer",
                ],
                requires_context=True,
            ),
            # --- Phone (national) ---
            # Landline: 0x or 0xx + 7 digits; Mobile: 04xx + 6 digits
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=(
                    r"\b0[1-9]\d{0,2}[/\s.\-]?\d{2,3}[.\s\-]?\d{2,3}[.\s\-]?\d{2,3}\b"
                ),
                validator=None,
                description="Belgian national phone number",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=(
                    r"\+32\s?\d{1,3}[\s.\-]?\d{2,3}[\s.\-]?\d{2}[\s.\-]?\d{2}"
                ),
                validator=None,
                description="Belgian international phone number (+32)",
            ),
            # --- Passport ---
            PatternDef(
                entity_type=EntityType.PASSPORT,
                pattern=r"\b[A-Z]{2}\d{6}\b",
                validator=None,
                description="Belgian passport — 2 letters + 6 digits",
                context_keywords=[
                    "paspoort", "passport", "passeport", "reisdocument",
                    "travel document", "document de voyage",
                ],
                requires_context=True,
            ),
            # --- Driving Licence ---
            PatternDef(
                entity_type=EntityType.DRIVERS_LICENSE,
                pattern=r"\b\d{10}\b",
                validator=None,
                description="Belgian driving licence — 10 digits",
                context_keywords=[
                    "rijbewijs", "permis de conduire", "driving licence",
                    "driving license", "rijbewijsnummer",
                ],
                requires_context=True,
            ),
            # --- License Plate (since 2010: 1-ABC-234) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[12][\-\s]?[A-Z]{3}[\-\s]?\d{3}\b",
                validator=None,
                description="Belgian license plate — 1-ABC-234 format",
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{3}\b",
                validator=None,
                description="Belgian postal code — 4 digits (1000-9999)",
                context_keywords=[
                    "postcode", "code postal", "postnummer", "postal code",
                    "zip", "B-", "adres", "adresse", "wonende", "woonplaats",
                    "rue", "straat", "laan", "avenue", "boulevard", "plein",
                    "steenweg", "chaussée", "domicilié", "gedomicilieerd",
                    "Levering:", "siège",
                ],
                requires_context=True,
            ),
            # Postal code in address structure: "Street 123, XXXX City"
            # The comma-space before a 4-digit code is a structural address signal
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"(?<=, )[1-9]\d{3}(?= [A-Z])",
                validator=None,
                description="Belgian postal code — in address structure (comma + city)",
            ),
            # --- RIZIV/INAMI Healthcare Provider Number ---
            PatternDef(
                entity_type=EntityType.HEALTHCARE_PROVIDER,
                pattern=r"\b\d{1}[\-.]?\d{5}[\-.]?\d{2}[\-.]?\d{3}\b",
                validator=None,
                description="Belgian RIZIV/INAMI provider number",
                context_keywords=[
                    "RIZIV", "INAMI", "arts", "médecin", "zorgverlener",
                    "prestataire", "dokter", "doctor",
                ],
                requires_context=True,
            ),
        ]
