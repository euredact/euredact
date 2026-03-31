"""Italy (IT) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class ITConfig(CountryConfig):
    """Italian PII patterns: Codice Fiscale, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "IT"
        self.name = "Italy"
        self.patterns = [
            # --- Codice Fiscale (16 alphanumeric) ---
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
                validator="italian_cf",
                description="Italian Codice Fiscale — 16 chars with check letter",
            ),
            # --- IBAN (IT + check letter + bank/branch + account) ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bIT\d{2}\s?[A-Z]\d{3}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b",
                validator="iban",
                description="Italian IBAN — IT + 25 chars (grouped)",
            ),
            # Compact form
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bIT\d{2}[A-Z]\d{22}\b",
                validator="iban",
                description="Italian IBAN — compact",
            ),
            # --- VAT (Partita IVA) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bIT\d{11}\b",
                validator=None,
                description="Italian Partita IVA — IT + 11 digits",
            ),
            # --- Phone (mobile: 3XX) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b3\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b",
                validator=None,
                description="Italian mobile phone — 3XX XXXXXXX",
            ),
            # --- Phone (landline: 0X, various groupings) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{1,3}[\s\-]?\d{6,8}\b",
                validator=None,
                description="Italian landline phone — compact",
            ),
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\b0\d{1,2}[\s\-]\d{3}[\s\-]\d{4}\b",
                validator=None,
                description="Italian landline phone — 0XX XXX XXXX",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+39\s?\d{2,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
                validator=None,
                description="Italian international phone — +39",
            ),
            # --- License Plate (AA 123 CD) ---
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-Z]{2}\s?\d{3}\s?[A-Z]{2}\b",
                validator=None,
                description="Italian license plate — AA XXX AA",
            ),
            # --- Postal Code (CAP, 5 digits) ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{5}\b",
                validator=None,
                description="Italian CAP — 5 digits",
                context_keywords=[
                    "CAP", "codice postale", "codice di avviamento",
                    "indirizzo", "via", "viale", "piazza", "corso",
                    "largo", "vicolo", "Domicilio", "domicilio",
                    "Residenza", "residenza", "Postal:",
                ],
                requires_context=True,
            ),
        ]
