"""Poland (PL) PII patterns."""
from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class PLConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "PL"
        self.name = "Poland"
        self.patterns = [
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b\d{11}\b",
                       validator="polish_pesel", description="Polish PESEL — 11 digits"),
            # NIP in the company grouping (3-3-2-2) or the one used for natural
            # persons (3-2-2-3); same digits, same check (rules-engine#94).
            PatternDef(entity_type=EntityType.TAX_ID,
                       pattern=r"\b(?:\d{3}-?\d{3}-?\d{2}-?\d{2}|\d{3}-\d{2}-\d{2}-\d{3})\b",
                       validator="polish_nip", description="Polish NIP — 10 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bPL\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
                       validator="iban", description="Polish IBAN — PL + 26 digits"),
            PatternDef(entity_type=EntityType.IBAN, pattern=r"\bPL\d{26}\b",
                       validator="iban", description="Polish IBAN — compact"),
            # NRB, the domestic account number: the IBAN without "PL", spaced
            # 2+4x6 or compact. The IBAN check digits make it self-validating
            # (rules-engine#93).
            PatternDef(entity_type=EntityType.BANK_ACCOUNT, pattern=r"\b\d{2}(?: ?\d{4}){6}\b",
                       validator="polish_nrb", description="Polish NRB — 26 digits, IBAN without PL"),
            PatternDef(entity_type=EntityType.VAT, pattern=r"\bPL[\s.]?\d{10}\b",
                       validator=None, description="Polish VAT — PL + 10 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b",
                       validator=None, description="Polish phone — 9 digits"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\b[5-8]\d{8}\b",
                       validator=None, description="Polish phone — compact"),
            PatternDef(entity_type=EntityType.PHONE, pattern=r"\+48\s?[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}",
                       validator=None, description="Polish international phone — +48"),
            # Identity card (dowód osobisty), REGON and driving licence: each
            # behind its own label. The card number and REGON carry check
            # digits; a licence number has none, so the label is everything
            # (rules-engine#75, #76, #77).
            PatternDef(entity_type=EntityType.NATIONAL_ID, pattern=r"\b[A-Z]{3}\s?\d{6}\b",
                       validator="polish_id_card", description="Polish identity card — 3 letters + 6 digits",
                       context_keywords=["dowód osobisty", "dowodu osobistego", "dowodem osobistym", "dowód", "dowodu", "nr dowodu", "identity card", "ID card"], requires_context=True),
            PatternDef(entity_type=EntityType.CHAMBER_OF_COMMERCE, pattern=r"\b\d{9}(?:\d{5})?\b",
                       validator="polish_regon", description="Polish REGON — 9 or 14 digits",
                       context_keywords=["REGON"], requires_context=True),
            # KRS (National Court Register): ten digits, issued in sequence and
            # written with the leading zeros, so it begins "00" -- which no
            # dialled number does (rules-engine#90). No check digit.
            PatternDef(entity_type=EntityType.CHAMBER_OF_COMMERCE, pattern=r"\b00\d{8}\b",
                       validator=None, description="Polish KRS — 10 digits with leading zeros",
                       context_keywords=["KRS"], requires_context=True),
            # Field 5 of the licence: digits in slash-separated groups, whose
            # widths vary with the year of issue ("01234/12/1234").
            PatternDef(entity_type=EntityType.DRIVERS_LICENSE, pattern=r"\b\d{3,6}/\d{2}/\d{3,7}\b",
                       validator=None, description="Polish driving licence number — field 5",
                       context_keywords=["prawo jazdy", "prawa jazdy", "prawem jazdy", "driving licence", "driving license"], requires_context=True),
            # The document (blank) number: two letters and six or seven digits.
            PatternDef(entity_type=EntityType.DRIVERS_LICENSE, pattern=r"\b[A-Z]{2}\s?\d{6,7}\b",
                       validator=None, description="Polish driving licence document number",
                       context_keywords=["prawo jazdy", "prawa jazdy", "prawem jazdy", "driving licence", "driving license"], requires_context=True),
            PatternDef(entity_type=EntityType.POSTAL_CODE, pattern=r"\b\d{2}-\d{3}\b",
                       validator=None, description="Polish postal code — XX-XXX",
                       context_keywords=["kod pocztowy", "adres", "ulica", "Postal:", "Address:"]),
        ]
