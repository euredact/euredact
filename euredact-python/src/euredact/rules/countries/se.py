"""Sweden (SE) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class SEConfig(CountryConfig):
    """Swedish PII patterns: personnummer, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "SE"
        self.name = "Sweden"
        self.patterns = [
            # --- Personnummer (12-digit YYYYMMDD-XXXX or 10-digit YYMMDD-XXXX) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{8}[-+]?\d{4}\b",
                validator="swedish_pnr",
                description="Swedish personnummer — 12-digit form with Luhn check",
            ),
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{6}[-+]\d{4}\b",
                validator="swedish_pnr",
                description="Swedish personnummer — 10-digit with separator",
            ),
            # 10-digit compact (no separator) — Luhn check is strong enough
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{10}\b",
                validator="swedish_pnr",
                description="Swedish personnummer — 10-digit compact (Luhn-validated)",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bSE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                validator="iban",
                description="Swedish IBAN — SE + 22 digits",
            ),
            # --- VAT ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bSE\d{12}\b",
                validator=None,
                description="Swedish VAT — SE + 12 digits",
            ),
            # --- Phone (national) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{1,3}[\-\s]?\d{2,3}[\s]?\d{2,3}[\s]?\d{2}\b",
                validator=None,
                description="Swedish national phone",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+46\s?\d{1,3}[\s\-]?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2}",
                validator=None,
                description="Swedish international phone — +46",
            ),
            # --- License Plate (ABC 123 or ABC 12A) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{3}\s?\d{2}[A-Z0-9]\b",
                validator=None,
                description="Swedish license plate — ABC 123 or ABC 12A",
            ),
            # --- Postal Code (XXX XX, or XXXXX, or XXXX XX in synthetic data) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{3}\s?\d{2}\b",
                validator=None,
                description="Swedish postal code — 5 digits (XXX XX)",
                context_keywords=[
                    "postnummer", "postort", "postkod", "adress",
                    "bostadsadress", "gatuadress", "boende",
                    # Street indicators
                    "gatan", "vägen", "gata", "väg", "allé", "plats",
                    "torg", "stigen", "Bostadsadress",
                ],
                requires_context=True,
            ),
            # 6-digit variant and XXXX XX (synthetic data formats)
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{4}\s\d{2}\b",
                validator=None,
                description="Swedish postal code — XXXX XX variant",
                context_keywords=[
                    "postnummer", "postort", "postkod", "adress",
                    "bostadsadress", "gatuadress", "boende",
                    "gatan", "vägen", "gata", "väg", "allé",
                ],
                requires_context=True,
            ),
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{6}\b",
                validator=None,
                description="Swedish postal code — 6-digit compact",
                context_keywords=[
                    "postnummer", "postort", "postkod", "adress",
                    "bostadsadress", "gatuadress", "boende",
                    "gatan", "vägen", "gata", "väg", "allé",
                ],
                requires_context=True,
            ),
            # --- Organisation Number (XXXXXX-XXXX) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b\d{6}-?\d{4}\b",
                validator=None,
                description="Swedish organisationsnummer — 10 digits",
                context_keywords=[
                    "organisationsnummer", "org.nr", "org nr",
                    "Bolagsverket", "registreringsnummer",
                ],
                requires_context=True,
            ),
        ]
