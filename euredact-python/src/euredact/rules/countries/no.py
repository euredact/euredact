"""Norway (NO) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class NOConfig(CountryConfig):
    """Norwegian PII patterns: fødselsnummer, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "NO"
        self.name = "Norway"
        self.patterns = [
            # --- Fødselsnummer (11 digits, dual mod-11 check) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{11}\b",
                validator="norwegian_fnr",
                description="Norwegian fødselsnummer — 11 digits compact",
            ),
            # With space: DDMMYY XXXXX
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{6}\s\d{5}\b",
                validator="norwegian_fnr",
                description="Norwegian fødselsnummer — with space",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bNO\d{2}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                validator="iban",
                description="Norwegian IBAN — NO + 13 digits",
            ),
            # --- VAT (NO + 9 digits + MVA) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bNO\s?\d{9}\s?MVA\b",
                validator=None,
                description="Norwegian VAT — NO + 9 digits + MVA",
            ),
            # --- Organisation Number ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\b[89]\d{8}\b",
                validator="norwegian_org",
                description="Norwegian organisasjonsnummer — 9 digits (starts 8/9)",
            ),
            # --- Phone (national, 8 digits no area code) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[2-9]\d\s?\d{2}\s?\d{2}\s?\d{2}\b",
                validator=None,
                description="Norwegian phone — 8 digits",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+47\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}",
                validator=None,
                description="Norwegian international phone — +47",
            ),
            # --- License Plate (AA XXXXX) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}\s?\d{5}\b",
                validator=None,
                description="Norwegian license plate — AA XXXXX",
            ),
            # --- Postal Code (4 digits) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{4}\b",
                validator=None,
                description="Norwegian postal code — 4 digits",
                context_keywords=[
                    "postnummer", "poststed", "postnr", "adresse",
                    "bostedsadresse", "gate", "vei", "veien",
                    "gata", "plass", "stien", "allé",
                ],
                requires_context=True,
            ),
        ]
