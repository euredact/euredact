"""Germany (DE) PII patterns."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class DEConfig(CountryConfig):
    """German PII patterns: Steuer-ID, Personalausweis, IBAN, phone, etc."""

    def __post_init__(self) -> None:
        self.code = "DE"
        self.name = "Germany"
        self.patterns = [
            # --- Steuerliche Identifikationsnummer (Tax ID) ---
            # 11 digits, first digit != 0, ISO 7064 check digit
            # Can appear as 11 consecutive digits or grouped with spaces/dots
            PatternDef(
                entity_type=EntityType.TAX_ID,
                pattern=r"\b[1-9]\d{10}\b",
                validator="german_tax_id",
                description="German Steuer-ID — 11 digits compact",
            ),
            PatternDef(
                entity_type=EntityType.TAX_ID,
                pattern=r"\b[1-9]\d[\s.]?\d{3}[\s.]?\d{3}[\s.]?\d{3}\b",
                validator="german_tax_id",
                description="German Steuer-ID — 11 digits with spaces/dots",
            ),
            # --- Personalausweisnummer (ID card) ---
            # Format: LXXXXXXXX (1 letter + 8 alphanumeric) or LLXXXXXXX
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b[CFGHJKLMNPRTVWXYZ][0-9A-Z]{8,9}\b",
                validator=None,
                description="German Personalausweisnummer — letter + 8 alphanumeric",
                context_keywords=[
                    "Personalausweis", "Personalausweisnummer", "Ausweis",
                    "Ausweisnummer", "Ausweis-Nr", "identity card",
                    "Identitätskarte", "Perso", "PA-Nummer",
                ],
                requires_context=True,
            ),
            # --- IBAN ---
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
                validator="iban",
                description="German IBAN — DE + 20 digits",
            ),
            # --- VAT (USt-IdNr) ---
            PatternDef(
                entity_type=EntityType.VAT,
                pattern=r"\bDE\s?\d{9}\b",
                validator="vat_de",
                description="German VAT — DE + 9 digits",
            ),
            # --- Phone (national) ---
            # German phone: 0xxx followed by various lengths
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=(
                    r"\b0[1-9]\d{1,4}[\s/\-]?\d{3,8}\b"
                ),
                validator=None,
                description="German national phone number",
            ),
            # --- Phone (international) ---
            PatternDef(
                entity_type=EntityType.PHONE,
                pattern=r"\+49\s?\d{2,5}[\s/\-]?\d{3,8}\b",
                validator=None,
                description="German international phone — +49",
            ),
            # --- Passport ---
            PatternDef(
                entity_type=EntityType.PASSPORT,
                pattern=r"\b[CFGHJK][0-9A-Z]{8,9}\b",
                validator=None,
                description="German passport number",
                context_keywords=[
                    "Reisepass", "passport", "Passnummer", "Reisepassnummer",
                    "Reisepass Nummer", "Reisepass-Nr", "Pass Nr",
                ],
                requires_context=True,
            ),
            # --- License Plate ---
            # Format: 1-3 letter city code + 1-2 letters + 1-4 digits
            PatternDef(
                entity_type=EntityType.LICENSE_PLATE,
                pattern=r"\b[A-ZÄÖÜ]{1,3}[\s\-]?[A-Z]{1,2}[\s\-]?\d{1,4}[EH]?\b",
                validator=None,
                description="German license plate — city code + letters + digits",
            ),
            # --- Postal Code ---
            PatternDef(
                entity_type=EntityType.POSTAL_CODE,
                pattern=r"\b\d{5}\b",
                validator=None,
                description="German postal code — 5 digits",
                context_keywords=[
                    "PLZ", "Postleitzahl", "postal code", "postcode",
                    "Anschrift", "Adresse", "Wohnort", "Ort", "Stadt",
                    "wohnt", "wohnhaft", "Straße", "Str.", "Weg",
                    "Platz", "Allee", "Ring",
                ],
                requires_context=True,
            ),
            # --- Handelsregisternummer (Commercial Register) ---
            PatternDef(
                entity_type=EntityType.CHAMBER_OF_COMMERCE,
                pattern=r"\bHR[AB]\s?\d{4,6}\b",
                validator=None,
                description="German Handelsregisternummer — HRA/HRB + digits",
            ),
            # --- Rentenversicherungsnummer (Social Security) ---
            # Format: 2-digit area + 6-digit DOB + letter + 3-digit serial
            PatternDef(
                entity_type=EntityType.SSN,
                pattern=r"\b\d{2}[\s]?\d{6}[\s]?[A-Z][\s]?\d{3}\b",
                validator=None,
                description="German Rentenversicherungsnummer — 12 chars",
                context_keywords=[
                    "Rentenversicherung", "RV-Nummer", "Sozialversicherung",
                    "SV-Nummer", "Versicherungsnummer", "Rentenversicherungsnummer",
                    "Sozialversicherungsnummer",
                ],
                requires_context=True,
            ),
            # --- Steuernummer (business tax number with slashes) ---
            PatternDef(
                entity_type=EntityType.TAX_ID,
                pattern=r"\b\d{2,3}/\d{3,4}/\d{4,5}\b",
                validator=None,
                description="German Steuernummer — FF/BBB/UUUUP format",
                context_keywords=[
                    "Steuernummer", "St.-Nr", "StNr", "Finanzamt", "Steuer",
                ],
                requires_context=True,
            ),
            # --- Steuernummer (13-digit ELSTER unified format) ---
            PatternDef(
                entity_type=EntityType.TAX_ID,
                pattern=r"\b\d{13}\b",
                validator=None,
                description="German Steuernummer — 13-digit ELSTER format",
                context_keywords=[
                    "Steuernummer", "St.-Nr", "StNr", "Finanzamt", "Steuer",
                ],
                requires_context=True,
            ),
            # --- Versichertennummer (Health Insurance) ---
            # Format: 1 letter + 9 digits
            PatternDef(
                entity_type=EntityType.HEALTH_INSURANCE,
                pattern=r"\b[A-Z]\d{9}\b",
                validator=None,
                description="German Versichertennummer — letter + 9 digits",
                context_keywords=[
                    "Versichertennummer", "Krankenversicherung", "KV-Nummer",
                    "Krankenkasse", "GKV", "Versichertenkarte", "Versicherter",
                    "Versicherte", "KVNR", "Krankenversichertennummer",
                ],
                requires_context=True,
            ),
        ]
