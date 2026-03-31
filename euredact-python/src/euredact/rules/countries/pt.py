"""Portugal (PT) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class PTConfig(CountryConfig):
    """Portuguese PII patterns: NIF, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "PT"
        self.name = "Portugal"
        self.patterns = [
            # --- NIF (Tax ID, 9 digits, mod-11) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[1-35-9]\d{8}\b",
                validator="portuguese_nif",
                description="Portuguese NIF — 9 digits compact",
            ),
            # NIF with spaces: XXX XXX XXX
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[1-35-9]\d{2}[\s.]\d{3}[\s.]\d{3}\b",
                validator="portuguese_nif",
                description="Portuguese NIF — spaced (XXX XXX XXX)",
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bPT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{5}\b",
                validator="iban",
                description="Portuguese IBAN — PT + 23 digits",
            ),
            # --- VAT ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bPT\d{9}\b",
                validator=None,
                description="Portuguese VAT — PT + 9 digits",
            ),
            # --- Phone (mobile: 9X, landline: 2X) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[29]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                validator=None,
                description="Portuguese phone — 9 digits",
            ),
            # Phone compact
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b[29]\d{8}\b",
                validator=None,
                description="Portuguese phone — 9 digits compact",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+351\s?[29]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                validator=None,
                description="Portuguese international phone — +351",
            ),
            # --- License Plate (AA-XX-XX, mixed) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z0-9]{2}-[A-Z0-9]{2}-[A-Z0-9]{2}\b",
                validator=None,
                description="Portuguese license plate — AA-XX-XX",
            ),
            # --- Postal Code (XXXX-XXX) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{4}-\d{3}\b",
                validator=None,
                description="Portuguese postal code — XXXX-XXX",
            ),
        ]
