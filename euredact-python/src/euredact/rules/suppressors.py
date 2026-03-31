"""Pass-2 suppression filters for false positive reduction.

Each suppressor examines a candidate match and its surrounding context to decide
whether the match is a false positive. Returning True means the match should be
**suppressed** (i.e., it is NOT PII).
"""

from __future__ import annotations

import re
from typing import Callable

from euredact.rules.matchers import RawMatch
from euredact.types import EntityType

# Context window: number of characters before/after a match to examine
_CONTEXT_CHARS = 150

# ── Currency ────────────────────────────────────────────────────────────

_CURRENCY_AFTER = re.compile(
    r"^\s*(?:EUR|€|\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK|"
    r"euro|euros|dollar|dollars|pond|kronor|kroner|kr)\b",
    re.IGNORECASE,
)
# "12385,84 €" or "12385.84 €" — number is integer part of decimal amount
_CURRENCY_COMMA_AFTER = re.compile(
    r"^[.,]\d{1,2}\s*(?:EUR|€|\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK|"
    r"euro|euros|kr(?:onor|oner)?|pond)\b",
    re.IGNORECASE,
)
_CURRENCY_BEFORE = re.compile(
    r"(?:EUR|€|\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK)\s*$",
)
# Also catch "Montant TTC :" or "Beløb:" before a number
_AMOUNT_LABEL_BEFORE = re.compile(
    r"(?:Montant|Beløb|Summa|Summe|Bedrag|Amount|Total|TTC|inkl|"
    r"Upphæð)\s*:?\s*$",
    re.IGNORECASE,
)

# ── Units ───────────────────────────────────────────────────────────────

_UNIT_AFTER = re.compile(
    r"^\s*(?:kg|km|cm|mm|m[²³]?|m\b|g\b|l\b|ml|mg|GB|MB|KB|TB|%|"
    r"jaar|maanden|weken|dagen|uur|minuten|seconden|"
    r"stuks|st\b|pcs|pieces|"
    r"ans|mois|semaines|jours|heures|"
    r"Jahre|Monate|Wochen|Tage|Stunden)\b",
    re.IGNORECASE,
)

# ── Reference / invoice numbers ─────────────────────────────────────────

_REFERENCE_BEFORE = re.compile(
    r"(?:dossier|ref\.?|referentie|reference|référence|factuurnummer|"
    r"invoice\s*(?:nr|number|no)?|bestelnummer|order\s*(?:nr|number|no)?|"
    r"kenmerk|ordernummer|Aktenzeichen|numéro\s*de\s*(?:dossier|facture|commande)|"
    r"bestellnummer|Rechnungsnummer|artikelnr|article\s*no|"
    r"contract\s*(?:nr|number|no)?|pagina|page|Seite|blz\.?|"
    r"Facture\s*n[°o]?|Faktura\s*n[°or]\.?|Lasku\s*n[°or]o?\.?|"
    r"Rechnung\s*(?:Nr|n[°o])?|faktura\s*(?:nr|n[°o])?|"
    r"bestilling\s*(?:nr|n[°o])?|bestelling\s*n[°or]\.?|"
    r"Reikningur\s*nr)\s*[:.]?\s*$",
    re.IGNORECASE,
)

# ── Legal / structural reference ────────────────────────────────────────

_LEGAL_BEFORE = re.compile(
    r"(?:Art(?:ikel|icle|\.)|§|Artikel|Section|Sectie|Afdeling|"
    r"paragraaf|Absatz|alinéa|punt|point|Punkt|lid)\s*$",
    re.IGNORECASE,
)

# ── Mathematical / formula ──────────────────────────────────────────────

_MATH_BEFORE = re.compile(r"[=+\-×÷*/]\s*$")
_MATH_AFTER = re.compile(r"^\s*[=+\-×÷*/]")

# ── Sequential / test data ──────────────────────────────────────────────

_SEQUENTIAL_PATTERNS = re.compile(
    r"^(?:0{6,}|1234567890?|0123456789|9876543210?|1111111111?|"
    r"000000000|123456789)$"
)

# ── Year-like 4-digit number (not a postal code) ───────────────────────

_YEAR_PATTERN = re.compile(r"^(?:19[4-9]\d|20[0-3]\d)$")
_DATE_KEYWORD_NEAR = re.compile(
    r"(?:jaar|year|année|Jahr|datum|date|Datum|in\s+\d{4}|since|sinds|depuis|seit|"
    # Nordic date keywords
    r"født|fødselsdato|fødsel|Fødselsdato|"
    r"född|födelsedatum|födelsedag|"
    r"syntynyt|syntymäaika|"
    r"fæddur|fæðingardagur|"
    # Also: date-like context where year follows DD.MM. pattern
    r"\d{2}\.\d{2}\.|"
    # Also: "januar|februar|..." month names preceding a year
    r"(?:januar|februar|marts|april|maj|juni|juli|august|september|"
    r"oktober|november|december|"
    r"januari|februari|mars|april|mei|juin|juillet|août|"
    r"Tiltr[æa]delsesdato|Tiltredelsesdato))",
    re.IGNORECASE,
)

# ── Phone: preceded by ID/tax label ────────────────────────────────────

_ID_LABEL_BEFORE = re.compile(
    r"(?:BSN|RR|NN|NIR|INSZ|NISS|NIS|Steuer-?ID|TIN|NIF|NIE|SSN|"
    r"rijksregisternummer|numéro\s*national|national\s*number|"
    r"matricule|Ausweisnummer|Personalausweis|"
    r"Versichertennummer|KVNR|KV-Nr|"
    r"Steuernummer|St\.\-Nr|StNr|Finanzamt\s+ist|"
    # Belgian enterprise number context
    r"Ondernemingen\s+onder\s+nummer|ondernemingsnummer|"
    r"numéro\s*d'entreprise|enterprise\s*number|"
    r"Kruispuntbank)\s*[:.]?\s*$",
    re.IGNORECASE,
)

# ── Phone: 0800 service numbers ─────────────────────────────────────────

_SERVICE_NUMBER = re.compile(r"^0800[\-\s]")

# ── Phone: date overlap ─────────────────────────────────────────────────

_DATE_PATTERN_FULL = re.compile(r"^\d{2}[-/.]\d{2}[-/.]\d{4}$")

# ── License plate: compound words and non-city codes ────────────────────

_HYPHEN_COMPOUND_BEFORE = re.compile(r"[A-Za-zÄÖÜäöüß]-$")

_NOT_CITY_CODES = {
    "ID", "NR", "NO", "ST", "DR", "MR", "MS", "HR", "FR",
    "IM", "IN", "OR", "IF", "IS", "IT", "AT", "AD", "AG", "AV",
    "BE", "DE", "EU", "NL", "LU",
    "WS", "SS",  # Semester (Wintersemester, Sommersemester)
    "IP",        # IP addresses
}

# License plate: Semester context
_SEMESTER_NEAR = re.compile(r"(?:Semester|Hochschule|Uni\b)", re.IGNORECASE)

# ── National ID: passport context → should be PASSPORT not NATIONAL_ID ──

_PASSPORT_CONTEXT_BEFORE = re.compile(
    r"(?:Reisepass|passport|passeport|paspoort|Bisheriger\s+Reisepass)\s*"
    r"(?:Nr\.?|Nummer|nummer|number|n[°o])?\s*[:.]?\s*$",
    re.IGNORECASE,
)

# ── National ID SE: org.nr context → CHAMBER_OF_COMMERCE not NATIONAL_ID

_SE_ORG_CONTEXT_BEFORE = re.compile(
    r"(?:org\.?\s*nr\.?|organisationsnummer|organisationsnr|"
    r"Bolagsverket|företag)\s*[:.]?\s*$",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════
# Suppressor functions
# ═══════════════════════════════════════════════════════════════════════

_ctx_cache: tuple[int, int, tuple[str, str]] | None = None


def _get_context(text: str, start: int, end: int, match: RawMatch | None = None) -> tuple[str, str]:
    """Get text before and after a match. Uses module-level cache for current match."""
    global _ctx_cache
    if _ctx_cache is not None and _ctx_cache[0] == start and _ctx_cache[1] == end:
        return _ctx_cache[2]
    ctx_start = max(0, start - _CONTEXT_CHARS)
    ctx_end = min(len(text), end + _CONTEXT_CHARS)
    result = (text[ctx_start:start], text[end:ctx_end])
    _ctx_cache = (start, end, result)
    return result


def suppress_currency(text: str, match: RawMatch) -> bool:
    """Suppress numbers in currency context, including comma-decimal amounts."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, after = _get_context(text, match.start, match.end, match)
    if _CURRENCY_AFTER.search(after) or _CURRENCY_BEFORE.search(before):
        return True
    if _CURRENCY_COMMA_AFTER.search(after):
        return True
    if _AMOUNT_LABEL_BEFORE.search(before):
        return True
    return False


def suppress_units(text: str, match: RawMatch) -> bool:
    """Suppress numbers followed by unit measurements."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.POSTAL_CODE,
    ):
        return False
    _, after = _get_context(text, match.start, match.end, match)
    return bool(_UNIT_AFTER.search(after))


def suppress_reference(text: str, match: RawMatch) -> bool:
    """Suppress numbers preceded by reference/invoice/dossier keywords."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE,
    ):
        return False
    before, _ = _get_context(text, match.start, match.end, match)
    return bool(_REFERENCE_BEFORE.search(before))


def suppress_legal(text: str, match: RawMatch) -> bool:
    """Suppress numbers after legal/structural reference words."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, _ = _get_context(text, match.start, match.end, match)
    return bool(_LEGAL_BEFORE.search(before))


def suppress_math(text: str, match: RawMatch) -> bool:
    """Suppress numbers in mathematical context."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, after = _get_context(text, match.start, match.end, match)
    return bool(_MATH_BEFORE.search(before) or _MATH_AFTER.search(after))


def suppress_sequential(text: str, match: RawMatch) -> bool:
    """Suppress sequential / test data patterns."""
    clean = re.sub(r"[\s.\-]", "", match.text)
    return bool(_SEQUENTIAL_PATTERNS.match(clean))


def suppress_year_as_postal(text: str, match: RawMatch) -> bool:
    """Suppress 4-digit years misidentified as postal codes."""
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    clean = match.text.strip()
    if not _YEAR_PATTERN.match(clean):
        return False
    # Don't suppress if in address structure: "City, XXXX." or "City, XXXX "
    immediate_before = text[max(0, match.start - 3):match.start]
    if immediate_before.endswith(", ") or immediate_before.endswith(",\n"):
        return False
    before, after = _get_context(text, match.start, match.end, match)
    context = before + after
    return bool(_DATE_KEYWORD_NEAR.search(context))


def suppress_phone_after_id_label(text: str, match: RawMatch) -> bool:
    """Suppress phone detections preceded by an ID-type or enterprise label."""
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    before, _ = _get_context(text, match.start, match.end, match)
    return bool(_ID_LABEL_BEFORE.search(before))


def suppress_phone_service_number(text: str, match: RawMatch) -> bool:
    """Suppress 0800 toll-free / service numbers — not personal PII."""
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    return bool(_SERVICE_NUMBER.match(match.text))


def suppress_phone_date_overlap(text: str, match: RawMatch) -> bool:
    """Suppress phone detections that are actually dates (DD-MM-YYYY)."""
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    return bool(_DATE_PATTERN_FULL.match(match.text.strip()))


def suppress_plate_in_compound(text: str, match: RawMatch) -> bool:
    """Suppress license plates that are part of a hyphenated compound word,
    use a non-city code, or appear in semester/IP context."""
    if match.pattern_def.entity_type != EntityType.LICENSE_PLATE:
        return False

    # Hyphen-compound: "Steuer-ID 88" — but NOT "AB-123-C" (plate with dashes)
    # Only suppress if there are 2+ letters before the hyphen (a real word, not a plate segment)
    if match.start >= 3:
        three_before = text[max(0, match.start - 10):match.start]
        if re.search(r"[A-Za-zÄÖÜäöüß]{2,}-$", three_before):
            return True

    matched = match.text.strip()
    parts = re.split(r"[\s\-]+", matched)
    if parts and parts[0] in _NOT_CITY_CODES:
        # Check if digits continue after (part of longer number)
        after_char = text[match.end:match.end + 1] if match.end < len(text) else ""
        before_char = text[match.start - 1:match.start] if match.start > 0 else ""
        if after_char.isdigit() or before_char == "-":
            return True
        # WS/SS → always suppress (semester or abbreviation, never a real plate)
        if parts[0] in ("WS", "SS"):
            return True
        # IP followed by dot+digit → IP address context
        if parts[0] == "IP":
            after_two = text[match.end:match.end + 2] if match.end + 1 < len(text) else ""
            if after_two and after_two[0] == "." and len(after_two) > 1 and after_two[1].isdigit():
                return True

    # HRA/HRB numbers already caught as CHAMBER_OF_COMMERCE
    if matched.startswith("HRA") or matched.startswith("HRB"):
        return True

    # Semester context nearby
    before, after = _get_context(text, match.start, match.end, match)
    if _SEMESTER_NEAR.search(before + after):
        if parts and parts[0] in ("WS", "SS"):
            return True

    return False


def suppress_natid_as_passport(text: str, match: RawMatch) -> bool:
    """Suppress NATIONAL_ID when context clearly says passport."""
    if match.pattern_def.entity_type != EntityType.NATIONAL_ID:
        return False
    before, _ = _get_context(text, match.start, match.end, match)
    return bool(_PASSPORT_CONTEXT_BEFORE.search(before))


def suppress_se_natid_as_org(text: str, match: RawMatch) -> bool:
    """Suppress SE NATIONAL_ID (personnummer) when context says org.nr."""
    if match.pattern_def.entity_type != EntityType.NATIONAL_ID:
        return False
    if match.country_code != "SE":
        return False
    before, _ = _get_context(text, match.start, match.end, match)
    return bool(_SE_ORG_CONTEXT_BEFORE.search(before))


def suppress_postal_inside_iban(text: str, match: RawMatch) -> bool:
    """Suppress postal code matches that fall inside an IBAN."""
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    # Check if the match is embedded in a longer alphanumeric sequence (IBAN)
    start = match.start
    end = match.end
    # Look at chars before and after
    before_char = text[start - 1] if start > 0 else " "
    after_char = text[end] if end < len(text) else " "
    # If surrounded by alphanumeric (inside IBAN/account number), suppress
    if before_char.isalnum() and after_char.isalnum():
        return True
    # Also: if preceded by a digit and a space (inside "IS47 0111 0147...")
    if start >= 5:
        prefix = text[start - 5:start]
        if re.search(r"[A-Z]{2}\d{2}\s$", prefix):
            return True
    return False


def suppress_postal_as_house_number(text: str, match: RawMatch) -> bool:
    """Suppress short postal codes (3 digits) that are house numbers."""
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    clean = re.sub(r"\s", "", match.text)
    if len(clean) > 3:
        return False
    # If preceded by a street name pattern (word + space), it's a house number
    before = text[max(0, match.start - 30):match.start]
    # Street name immediately before: "Austurstræti 186" → 186 is house number
    if re.search(r"[a-záéíóúýþæöðA-ZÁÉÍÓÚÝÞÆÖÐ]{3,}\s+$", before):
        # Check if followed by comma + space + digit (address structure)
        after = text[match.end:match.end + 5]
        if not re.match(r",?\s+[A-ZÁÉÍÓÚÝÞÆÖÐ]", after):
            return True
    return False


def suppress_requires_context(text: str, match: RawMatch) -> bool:
    """Suppress patterns that require context keywords."""
    if not match.pattern_def.requires_context:
        return False
    if not match.pattern_def.context_keywords:
        return False
    before, after = _get_context(text, match.start, match.end, match)
    context = (before + " " + after).lower()
    return not any(kw.lower() in context for kw in match.pattern_def.context_keywords)


# ── Dispatch table: entity type → applicable suppressors ────────────────
# This avoids calling 16 functions that each start with "if type != X: return False"

_UNIVERSAL = [suppress_sequential]  # Applies to all types
_CONTEXT_ONLY = [suppress_requires_context]  # Always last

_TYPE_SUPPRESSORS: dict[EntityType, list[Callable[..., bool]]] = {
    EntityType.PHONE: [
        suppress_currency, suppress_units, suppress_reference, suppress_math,
        suppress_phone_after_id_label, suppress_phone_service_number,
        suppress_phone_date_overlap,
    ],
    EntityType.NATIONAL_ID: [
        suppress_currency, suppress_units, suppress_reference, suppress_legal,
        suppress_math, suppress_natid_as_passport, suppress_se_natid_as_org,
    ],
    EntityType.SSN: [
        suppress_currency, suppress_units, suppress_reference, suppress_math,
    ],
    EntityType.TAX_ID: [
        suppress_currency, suppress_units, suppress_reference, suppress_math,
    ],
    EntityType.POSTAL_CODE: [
        suppress_currency, suppress_units, suppress_math, suppress_legal,
        suppress_year_as_postal, suppress_postal_inside_iban,
        suppress_postal_as_house_number,
    ],
    EntityType.IBAN: [suppress_reference],
    EntityType.LICENSE_PLATE: [suppress_plate_in_compound],
    EntityType.CHAMBER_OF_COMMERCE: [suppress_reference],
}


def should_suppress(text: str, match: RawMatch) -> bool:
    """Run applicable suppression filters. Returns True if match should be discarded."""
    global _ctx_cache
    # Prime context cache
    ctx_start = max(0, match.start - _CONTEXT_CHARS)
    ctx_end = min(len(text), match.end + _CONTEXT_CHARS)
    _ctx_cache = (match.start, match.end, (text[ctx_start:match.start], text[match.end:ctx_end]))

    # Universal suppressors (all types)
    for s in _UNIVERSAL:
        if s(text, match):
            return True

    # Type-specific suppressors
    etype = match.pattern_def.entity_type
    type_suppressors = _TYPE_SUPPRESSORS.get(etype)
    if type_suppressors:
        for s in type_suppressors:
            if s(text, match):
                return True

    # Context-keyword check (applies to any type with requires_context)
    if match.pattern_def.requires_context:
        return suppress_requires_context(text, match)

    return False
