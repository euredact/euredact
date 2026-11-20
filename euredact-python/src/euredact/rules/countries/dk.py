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
                # An underscore is a boundary here: a CPR in a file name or an
                # export column, "personoplysningsblanket_1202794846.pdf",
                # was missed because "_" is a word character (#195).
                pattern=r"(?<![A-Za-z0-9])(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{6}(?![A-Za-z0-9])",
                validator="danish_cpr",
                description="Danish CPR-nummer — 10 digits compact (date-validated)",
            ),
            # Space-separated form, "CPR: 120385 4417". Written that way on
            # forms and in letters, and without this the last four digits were
            # the only thing masked, as a postcode (rules-engine#188). A date
            # and four digits apart is also a timestamp or a reference, so the
            # label is required.
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2} \d{4}\b",
                validator="danish_cpr",
                description="Danish CPR-nummer — DDMMYY XXXX with a space (label required)",
                context_keywords=[
                    "CPR", "cpr-nr", "cpr-nummer", "personnummer",
                    "sygesikring",
                    # "Vedr. 110573 1449 Frederik Nissen": a letter about a
                    # citizen names them by CPR and name (#195).
                    "vedr",
                ],
                requires_context=True,
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bDK\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="Danish IBAN — DK + 16 digits",
            ),
            # --- Domestic account: reg.nr. + kontonr. (rules-engine#188) ---
            # The NemKonto form, "reg.nr. 5301 kontonr. 0012345678": a 4-digit
            # bank registration number and an account number of up to 10
            # digits. One span from the first digit to the last, so neither
            # half is left readable; the account number alone was a PHONE.
            # No checksum covers every bank, so a label is required.
            PatternDef(
                entity_type=EntityType.BANK_ACCOUNT,
                pattern=(
                    r"\b\d{4}(?:[ \t]*[,/\-][ \t]*|[ \t]+)"
                    r"(?:(?:[Kk]onto(?:nummer|nr\.?)?|[Kk]onto[ \t]*nr\.?)[ \t]*:?[ \t]*)?"
                    r"\d{6,10}\b"
                ),
                validator=None,
                description="Danish domestic account — reg.nr. + kontonr. (label required)",
                context_keywords=[
                    "reg.nr", "reg. nr", "regnr", "registreringsnummer",
                    "kontonr", "konto nr", "kontonummer", "NemKonto",
                ],
                requires_context=True,
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
            # --- Driving licence (kørekort, 8 digits; rules-engine#188) ---
            # The national phone pattern below claims every 8-digit number, so
            # without this a kørekort number was masked as PHONE.
            PatternDef(
                entity_type=EntityType.DRIVERS_LICENSE,
                pattern=r"\b\d{8}\b",
                validator=None,
                description="Danish driving licence — 8 digits (label required)",
                context_keywords=["kørekort", "kørekortnummer", "kørekort nr"],
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
            # --- Postal Code with the country prefix (rules-engine#188) ---
            # "DK-2100 København Ø", the form written for abroad and on
            # letterheads. The prefix belongs to the code: masking the digits
            # alone left "DK-[POSTAL_CODE]". The prefix and the town after it
            # are the evidence, so no street word is required.
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\bDK-[1-9]\d{3}\b(?=[ \t]+[A-ZÆØÅ])",
                validator=None,
                description="Danish postal code — DK-NNNN before a town",
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
