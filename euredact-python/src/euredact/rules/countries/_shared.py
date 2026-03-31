"""Shared (EU-wide) PII patterns: email, generic IBAN, international phone, dates, digital IDs."""

from __future__ import annotations

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType


class SharedConfig(CountryConfig):
    """Patterns shared across all EU countries."""

    def __post_init__(self) -> None:
        self.code = "SHARED"
        self.name = "Shared EU Patterns"
        self.patterns = [
            # --- Email ---
            PatternDef(
                entity_type=EntityType.EMAIL,
                pattern=r"\b[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}\b",
                validator=None,
                description="Email address (RFC 5322 simplified)",
            ),
            # --- BIC/SWIFT ---
            PatternDef(
                entity_type=EntityType.BIC,
                pattern=r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
                validator="bic",
                description="BIC/SWIFT code (8 or 11 characters)",
            ),
            # --- Credit Card (Visa, Mastercard, Amex) ---
            PatternDef(
                entity_type=EntityType.CREDIT_CARD,
                pattern=(
                    r"\b(?:"
                    r"4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # Visa
                    r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # MC
                    r"|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}"  # Amex
                    r")\b"
                ),
                validator="luhn",
                description="Credit card number (Visa, Mastercard, Amex) with Luhn",
            ),
            # --- VIN ---
            PatternDef(
                entity_type=EntityType.VIN,
                pattern=r"\b[A-HJ-NPR-Z0-9]{17}\b",
                validator="vin",
                description="Vehicle Identification Number (ISO 3779)",
            ),
            # --- IPv4 ---
            PatternDef(
                entity_type=EntityType.IP_ADDRESS,
                pattern=(
                    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
                ),
                validator=None,
                description="IPv4 address",
            ),
            # --- IPv6 ---
            PatternDef(
                entity_type=EntityType.IPV6_ADDRESS,
                pattern=(
                    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
                    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
                    r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
                    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
                ),
                validator=None,
                description="IPv6 address",
            ),
            # --- MAC Address (colon/dash: 00:1A:2B:3C:4D:5E) ---
            PatternDef(
                entity_type=EntityType.MAC_ADDRESS,
                pattern=r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b",
                validator=None,
                description="MAC address (colon or dash separated)",
            ),
            # MAC Address Cisco format (dot: 0670.3A83.C107)
            PatternDef(
                entity_type=EntityType.MAC_ADDRESS,
                pattern=r"\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b",
                validator=None,
                description="MAC address (Cisco dot notation)",
            ),
            # --- IMEI (15 digits, Luhn check) ---
            # Luhn + TAC validation is strong enough to not require context
            PatternDef(
                entity_type=EntityType.IMEI,
                pattern=r"\b\d{15}\b",
                validator="imei",
                description="IMEI — 15 digits with Luhn check",
            ),
            # IMEI with separators: XX-XXXXXX-XXXXXX-X
            PatternDef(
                entity_type=EntityType.IMEI,
                pattern=r"\b\d{2}[\-\s]\d{6}[\-\s]\d{6}[\-\s]\d\b",
                validator="imei",
                description="IMEI — formatted with separators",
            ),
            # --- GPS Coordinates (decimal degrees) ---
            # Latitude: -90 to 90, Longitude: -180 to 180, at least 4 decimal places
            PatternDef(
                entity_type=EntityType.GPS_COORDINATES,
                pattern=(
                    r"-?(?:[1-8]?\d(?:\.\d{4,})|90(?:\.0{4,}))"
                    r"\s*[,;/]\s*"
                    r"-?(?:1[0-7]\d(?:\.\d{4,})|180(?:\.0{4,})|\d{1,2}(?:\.\d{4,}))"
                ),
                validator=None,
                description="GPS coordinates — decimal degrees (lat, lon) with 4+ decimals",
            ),
            # --- UUID (version 1–5, standard 8-4-4-4-12 hex format) ---
            PatternDef(
                entity_type=EntityType.UUID,
                pattern=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
                validator=None,
                description="UUID (RFC 4122, versions 1-5)",
            ),
            # --- Social Media Handles (@username) ---
            # Must be preceded by whitespace or start-of-string, 1-30 alphanumeric/underscore/dot chars
            PatternDef(
                entity_type=EntityType.SOCIAL_HANDLE,
                pattern=r"(?<!\w)@[a-zA-Z][a-zA-Z0-9_.]{1,29}\b",
                validator=None,
                description="Social media handle (@username)",
            ),
            # --- Secret / API Key (known prefixes — always active) ---
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bAKIA[A-Z0-9]{16}\b",
                validator=None,
                description="AWS Access Key ID",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bgh[poas]_[a-zA-Z0-9]{36,}\b",
                validator=None,
                description="GitHub token (PAT, OAuth, app, server)",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bgithub_pat_[a-zA-Z0-9_]{22,}\b",
                validator=None,
                description="GitHub fine-grained personal access token",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\b[sp]k_(?:live|test)_[a-zA-Z0-9]{24,}\b",
                validator=None,
                description="Stripe secret or publishable key",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bsk-(?:ant-)?[a-zA-Z0-9\-_]{20,}\b",
                validator=None,
                description="OpenAI / Anthropic API key",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bxox[bpas]-[a-zA-Z0-9\-]{10,}\b",
                validator=None,
                description="Slack token",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b",
                validator=None,
                description="JWT token (3-part base64url)",
            ),
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
                validator=None,
                description="SendGrid API key",
            ),
            # --- Secret / API Key (entropy-based fallback — requires context) ---
            PatternDef(
                entity_type=EntityType.SECRET,
                pattern=r"\b[A-Za-z0-9_\-]{32,}\b",
                validator="high_entropy",
                description="High-entropy token or secret near context keyword",
                context_keywords=[
                    "key", "token", "secret", "password", "credential",
                    "api_key", "apikey", "api-key", "auth", "bearer",
                    "wachtwoord", "mot de passe", "Passwort", "Schlüssel",
                    "clé", "sleutel", "lösenord", "hasło", "heslo",
                    "jelszó", "contraseña", "senha", "parola",
                ],
                requires_context=True,
            ),
            # --- Date of Birth (EU formats, requires context) ---
            PatternDef(
                entity_type=EntityType.DOB,
                pattern=r"\b(?:0[1-9]|[12][0-9]|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b",
                validator=None,
                description="Date in DD/MM/YYYY format (EU standard) — requires context",
                context_keywords=[
                    "geboren", "geboortedatum", "date de naissance", "né le", "née le",
                    "né(e) le", "nee le", "nee(e) le",
                    "date of birth", "DOB", "Geburtsdatum", "geboren am", "geboren op",
                    "nascido", "nacido", "data di nascita", "nato il", "nata il",
                    "geb.", "geb.datum", "geb ", "birth date", "birthday",
                    "naissance", "geboorte", "geburtstag",
                ],
                requires_context=True,
            ),
            # --- Date of Death (requires context) ---
            PatternDef(
                entity_type=EntityType.DATE_OF_DEATH,
                pattern=r"\b(?:0[1-9]|[12][0-9]|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b",
                validator=None,
                description="Date of death — requires context",
                context_keywords=[
                    "overleden", "overlijdensdatum", "date de décès", "décédé le",
                    "date of death", "Sterbedatum", "verstorben am", "gestorven",
                    "death date", "died on", "mort le", "décès",
                ],
                requires_context=True,
            ),
            # --- ISO date format YYYY-MM-DD (DOB, requires context) ---
            PatternDef(
                entity_type=EntityType.DOB,
                pattern=r"\b(?:19|20)\d{2}[/.\-](?:0[1-9]|1[0-2])[/.\-](?:0[1-9]|[12][0-9]|3[01])\b",
                validator=None,
                description="Date in YYYY-MM-DD format (ISO) — requires context",
                context_keywords=[
                    "geboren", "geboortedatum", "date de naissance", "né le", "née le",
                    "né(e) le", "nee le",
                    "date of birth", "DOB", "Geburtsdatum", "geboren am", "geboren op",
                    "geb.", "birth date", "birthday", "naissance", "geboorte",
                ],
                requires_context=True,
            ),
        ]
