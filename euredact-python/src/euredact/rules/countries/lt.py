"""Lithuania (LT) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class LTConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "LT"
        self.name = "Lithuania"
        self.patterns = [
            # Asmens kodas: same format as Estonian (GYYMMDDNNNC, 11 digits)
            PatternDef(entity_type=EntityType.NATIONAL_ID,
                       pattern=r"\b[1-6]\d{10}\b",
                       validator="estonian_id",
                       description="Lithuanian asmens kodas — 11 digits with mod-11 check"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bLT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Lithuanian IBAN — grouped"),
            PatternDef(entity_type=EntityType.IBAN,
                       pattern=r"\bLT\d{18}\b",
                       validator="iban", description="Lithuanian IBAN — compact"),
            PatternDef(entity_type=EntityType.VAT,
                       pattern=r"\bLT\d{9,12}\b",
                       validator=None, description="Lithuanian VAT (PVM) — LT + 9 or 12 digits"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}\b",
                       validator=None, description="Lithuanian phone — 6XX XX XXX"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b6\d{7}\b",
                       validator=None, description="Lithuanian phone — compact"),
            # Legacy 8 prefix (= +370)
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\b8[\s\-]?6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}\b",
                       validator=None, description="Lithuanian phone — 8 6XX XX XXX (legacy)"),
            PatternDef(entity_type=EntityType.PHONE,
                       pattern=r"\+370\s?6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}",
                       validator=None, description="Lithuanian international phone — +370"),
            PatternDef(entity_type=EntityType.POSTAL_CODE,
                       pattern=r"\bLT-\d{5}\b",
                       validator=None, description="Lithuanian postal code — LT-XXXXX"),
        ]
