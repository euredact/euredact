"""Denmark (DK) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class DKConfig(CountryConfig):
    """Danish PII patterns: CPR-nummer, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "DK"
        self.name = "Denmark"
        self.patterns = [
            # --- CPR-nummer (DDMMYY-XXXX, 10 digits) ---
            # Dash-separated form is unambiguous enough without context
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}-\d{4}\b",
                validator=None,
                description="Danish CPR-nummer — DDMMYY-XXXX with dash",
            ),
            # Compact 10-digit form — date prefix validation reduces FP
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{6}\b",
                validator="danish_cpr",
                description="Danish CPR-nummer — 10 digits compact (date-validated)",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bDK\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="Danish IBAN — DK + 16 digits",
            ),
            # --- VAT (CVR) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bDK\s?\d{8}\b",
                validator="danish_vat",
                description="Danish VAT (CVR) — DK + 8 digits with mod-11",
            ),
            # --- CVR (Chamber of Commerce) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{8}\b",
                validator="danish_vat",
                description="Danish CVR number — 8 digits with mod-11",
                context_keywords=[
                    "CVR", "CVR-nummer", "virksomhedsnummer",
                    "virksomhedsregisteret",
                ],
                requires_context=True,
            ),
            # --- Phone (national, 8 digits no area code) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[2-9]\d\s?\d{2}\s?\d{2}\s?\d{2}\b",
                validator=None,
                description="Danish phone — 8 digits",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+45\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}",
                validator=None,
                description="Danish international phone — +45",
            ),
            # --- License Plate (AA XX XXX) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}\s?\d{2}\s?\d{3}\b",
                validator=None,
                description="Danish license plate — AA XX XXX",
                context_keywords=[
                    "nummerplade", "registreringsnummer", "reg.nr", "køretøj",
                ],
                requires_context=True,
            ),
            # --- Postal Code (4 digits) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b[1-9]\d{3}\b",
                validator=None,
                description="Danish postal code — 4 digits (1000-9999)",
                context_keywords=[
                    "postnummer", "postby", "postnr", "adresse",
                    "bopæl", "bopælsadresse",
                    # Street indicators — postal code follows a street address
                    "gade", "vej", "allé", "plads", "torv", "stræde",
                    "boulevard", "Arbejdssted",
                ],
                requires_context=True,
            ),
        ]
