"""Pass-2 suppression filters for false positive reduction.

Each suppressor examines a candidate match and its surrounding context to decide
whether the match is a false positive. Returning True means the match should be
**suppressed** (i.e., it is NOT PII).
"""

from __future__ import annotations

import re
from typing import Callable

from euredact.rules.bic_registry import is_registered_bic
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
    # "st" (stuks/pieces) must not swallow the "St." of a place name —
    # "Postal: 9600 St. Paul's Bay", "Adresse: 8386 St. Gallen".
    r"stuks|st\b(?!\.\s*[A-ZÄÖÜÅÆØÁÉÍÓÚ])|pcs|pieces|"
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

# "A-1010", "B-2000", "L-1234", "CH-8000", "D-10115": a country prefix on a
# postal code, not a minus sign.
_COUNTRY_PREFIX_HYPHEN = re.compile(r"(?:^|[^A-Za-z0-9])[A-Z]{1,2}-\s*$")

# ── Sequential / test data ──────────────────────────────────────────────

_SEQUENTIAL_PATTERNS = re.compile(
    r"^(?:0{6,}|1234567890?|0123456789|9876543210?|1111111111?|"
    r"000000000|123456789)$"
)

# ── Year-like 4-digit number (not a postal code) ───────────────────────

_RECENT_YEAR = re.compile(r"^(?:19[5-9]\d|20[0-3]\d)$")
_POSTAL_CONTEXT_NEAR = re.compile(
    r"(?:postcode|postal|code\s*postal|PLZ|Postleitzahl|postnummer|postinumero|"
    r"póstnúmer|zip|straat|straße|strasse|rue\s|via\s|calle\s|rua\s|ulica|utca|"
    r"street|avenue|laan\s|weg\s|plein|adres|adresse|address|woonplaats|"
    # Residence phrasing that introduces an address without the word "adres":
    # "wonende te 2000 Antwerpen", "domicilié à 1000 Bruxelles".
    r"wonende|woonachtig|gevestigd|domicili|demeurant|résidant|residant|"
    r"bosatt|bopæl|wohnhaft|ansässig|"
    r"stad\b|ville\b|city\b|Stadt|città|ciudad|cidade|miasto|město|város)",
    re.IGNORECASE,
)
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

# ── Postal code: digits belonging to a longer identifier ────────────────

# An identifier label immediately before the digits. A postal code is never
# introduced this way; an SVNr, policy number or service number always is.
_ID_CUE_BEFORE = re.compile(
    r"(?:"
    r"[\w\-]*Nr|[\w\-]*N[°ºo]|[\w\-]*Nummer|[\w\-]*Numero|[\w\-]*Numéro|"
    r"No|number|num|Kennzahl|Aktenzeichen|Az|e-?card|Polizze|Police|Policen"
    r")\.?\s*:?\s*$",
    re.IGNORECASE,
)

# An international dialling prefix earlier on the same line, with nothing but
# number punctuation in between: these digits belong to the phone detector.
_DIALLING_PREFIX_BEFORE = re.compile(r"\+\d{1,3}[\d\s\-().]*$")

# A country prefix on a postal code — "A-1010 Wien", "B-2000", "L-1234",
# "CH-8000", "D-10115". One or two letters before the hyphen, at a boundary.
_COUNTRY_PREFIXED = re.compile(r"(?:^|[^A-Za-z0-9])[A-Z]{1,2}$")

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

_DATE_PATTERN_FULL = re.compile(r"^\d{2}[-/.]\d{2}[-/.]\d{4}$|^\d{4}[-/.]\d{2}[-/.]\d{2}$")

# ── License plate: compound words and non-city codes ────────────────────

_HYPHEN_COMPOUND_BEFORE = re.compile(r"[A-Za-zÄÖÜäöüß]-$")
_CURRENCY_PLATE = re.compile(r"^(?:EUR|USD|GBP|CHF|SEK|NOK|DKK|ISK|CZK|PLN|HUF|RON|BGN|HRK)\s", re.IGNORECASE)

_NOT_CITY_CODES = {
    "ID", "NR", "NO", "ST", "DR", "MR", "MS", "HR", "FR",
    "IM", "IN", "OR", "IF", "IS", "IT", "AT", "AD", "AG", "AV",
    "BE", "DE", "EU", "NL", "LU",
    "WS", "SS",  # Semester (Wintersemester, Sommersemester)
    "IP",        # IP addresses
}

# License plate: Semester context
_SEMESTER_NEAR = re.compile(r"(?:Semester|Hochschule|Uni\b)", re.IGNORECASE)

# ── BIC: banking-context cues and heading shapes ────────────────────────

# BIC/SWIFT keyword. \bSWIFT\b also covers SWIFT-Code / SWIFT-BIC / Code SWIFT,
# and \bBIC\b covers BIC-code / BIC/SWIFT.
_BIC_KEYWORD = re.compile(r"\b(?:BIC|SWIFT)\b", re.IGNORECASE)

# Structured bank-details block.
_BANK_BLOCK = re.compile(
    r"\b(?:IBAN|Bankverbindung|Bankgegevens|Bankrekening|"
    r"Rekening(?:nummer)?|Kontonummer|Konto|Kontoinhaber|"
    r"Compte|Coordonn[ée]es\s+bancaires|Banque|"
    r"Account\s+(?:number|holder)|Bankleitzahl|BLZ|"
    r"Betaalgegevens|Zahlungsdaten)\b",
    re.IGNORECASE,
)

# A line that is nothing but a BIC/SWIFT label, as used in table and column
# layouts where the code sits on the following line.
_BIC_LABEL_LINE = re.compile(
    r"^\s*(?:BIC|SWIFT|SWIFT[-\s]?BIC|BIC\s?/\s?SWIFT|SWIFT[-\s]?Code|"
    r"BIC[-\s]?code|Code\s+SWIFT)\s*:?\s*$",
    re.IGNORECASE,
)

# An IBAN in the same structural unit: CC + 2 check digits + 2 or more groups.
_IBAN_SHAPE = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,}")

# Largest paragraph still treated as one structural unit. Beyond this the
# unit falls back to the enclosing line, so a run-on document body cannot
# lend banking context to a token 2,000 characters away.
_MAX_UNIT_CHARS = 600

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

def _get_context(text: str, start: int, end: int) -> tuple[str, str]:
    """Get text before and after a match position."""
    ctx_start = max(0, start - _CONTEXT_CHARS)
    ctx_end = min(len(text), end + _CONTEXT_CHARS)
    return (text[ctx_start:start], text[end:ctx_end])


def suppress_currency(text: str, match: RawMatch) -> bool:
    """Suppress numbers in currency context, including comma-decimal amounts."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, after = _get_context(text, match.start, match.end)
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
    _, after = _get_context(text, match.start, match.end)
    return bool(_UNIT_AFTER.search(after))


def suppress_reference(text: str, match: RawMatch) -> bool:
    """Suppress numbers preceded by reference/invoice/dossier keywords."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE,
    ):
        return False
    before, _ = _get_context(text, match.start, match.end)
    return bool(_REFERENCE_BEFORE.search(before))


def suppress_legal(text: str, match: RawMatch) -> bool:
    """Suppress numbers after legal/structural reference words."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, _ = _get_context(text, match.start, match.end)
    return bool(_LEGAL_BEFORE.search(before))


def suppress_math(text: str, match: RawMatch) -> bool:
    """Suppress numbers in mathematical context."""
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.POSTAL_CODE,
    ):
        return False
    before, after = _get_context(text, match.start, match.end)
    # A country-prefixed postal code is an address, not a subtraction:
    # "A-1010 Wien", "B-2000 Antwerpen", "D-10115 Berlin".
    if (
        match.pattern_def.entity_type == EntityType.POSTAL_CODE
        and _COUNTRY_PREFIX_HYPHEN.search(before)
    ):
        return False
    return bool(_MATH_BEFORE.search(before) or _MATH_AFTER.search(after))


def suppress_sequential(text: str, match: RawMatch) -> bool:
    """Suppress sequential / test data patterns."""
    clean = re.sub(r"[\s.\-]", "", match.text)
    return bool(_SEQUENTIAL_PATTERNS.match(clean))


def suppress_year_as_postal(text: str, match: RawMatch) -> bool:
    """Suppress year-like numbers (1950-2039) misidentified as postal codes.

    Years are almost never postal codes in running text.
    Only keep as postal code if there's postal/address context nearby.
    """
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    clean = match.text.strip()
    if not _RECENT_YEAR.match(clean):
        return False
    # Keep as postal code if postal/address context nearby
    before, after = _get_context(text, match.start, match.end)
    context = before + after
    if _POSTAL_CONTEXT_NEAR.search(context):
        return False
    # Keep if preceded by comma+space (address pattern: "Amsterdam, 2026")
    immediate_before = text[max(0, match.start - 3):match.start]
    if re.search(r",\s*$", immediate_before):
        return False
    # Suppress: years without postal context are almost never postal codes
    return True


def suppress_phone_after_id_label(text: str, match: RawMatch) -> bool:
    """Suppress phone detections preceded by an ID-type or enterprise label."""
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    before, _ = _get_context(text, match.start, match.end)
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

    # Suppress currency + number misread as plate (e.g. "EUR 2")
    if _CURRENCY_PLATE.match(match.text):
        return True

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
    before, after = _get_context(text, match.start, match.end)
    if _SEMESTER_NEAR.search(before + after):
        if parts and parts[0] in ("WS", "SS"):
            return True

    return False


def suppress_natid_as_passport(text: str, match: RawMatch) -> bool:
    """Suppress NATIONAL_ID when context clearly says passport."""
    if match.pattern_def.entity_type != EntityType.NATIONAL_ID:
        return False
    before, _ = _get_context(text, match.start, match.end)
    return bool(_PASSPORT_CONTEXT_BEFORE.search(before))


def suppress_se_natid_as_org(text: str, match: RawMatch) -> bool:
    """Suppress SE NATIONAL_ID (personnummer) when context says org.nr."""
    if match.pattern_def.entity_type != EntityType.NATIONAL_ID:
        return False
    if match.country_code != "SE":
        return False
    before, _ = _get_context(text, match.start, match.end)
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


def _enclosing_line(text: str, start: int, end: int) -> tuple[int, int]:
    """Return (start, end) offsets of the line containing [start, end)."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    return line_start, line_end


def _structural_unit(text: str, start: int, end: int) -> str:
    """Return the enclosing line / record / paragraph around a match.

    The context window for BIC is scoped structurally, not by character
    count. A tight character window measured on the corpus rejects 97.3% of
    dictionary false positives but wrongly discards ~316 real-looking codes,
    because the banking cue often sits further away in the same record — e.g.
    a CSV row carrying the IBAN in one field and the BIC several fields
    later. Paragraphs longer than :data:`_MAX_UNIT_CHARS` fall back to the
    enclosing line so a long body cannot lend context to a distant token.
    """
    line_start, line_end = _enclosing_line(text, start, end)

    # Expand upwards to the start of the blank-line-delimited paragraph
    para_start = line_start
    while para_start > 0:
        prev_end = para_start - 1
        prev_start = text.rfind("\n", 0, prev_end) + 1
        if not text[prev_start:prev_end].strip():
            break
        para_start = prev_start

    # Expand downwards to the end of the paragraph
    para_end = line_end
    while para_end < len(text):
        next_start = para_end + 1
        next_end = text.find("\n", next_start)
        if next_end == -1:
            next_end = len(text)
        if not text[next_start:next_end].strip():
            break
        para_end = next_end

    if para_end - para_start <= _MAX_UNIT_CHARS:
        return text[para_start:para_end]
    return text[line_start:line_end]


def _previous_nonblank_line(text: str, line_start: int) -> str:
    """Return the nearest non-blank line above *line_start* (empty if none)."""
    pos = line_start
    while pos > 0:
        prev_end = pos - 1
        prev_start = text.rfind("\n", 0, prev_end) + 1
        line = text[prev_start:prev_end]
        if line.strip():
            return line
        pos = prev_start
    return ""


def _occurs_as_lowercase_word(text: str, token: str) -> bool:
    """Does *token* also occur as an ordinary lowercase word in this document?

    ``hospital``/``HOSPITAL``, ``gegevens``/``GEGEVENS`` — a token that appears
    in ordinary case elsewhere in the same document is a word, not a bank code.
    Email and domain contexts are excluded, so ``ing.nl`` does not vouch for a
    heading. Measured on the corpus this alone identifies ~78% of the BIC
    false positives with no dictionaries and no labelled data.
    """
    if not token.isalpha():
        return False
    for form in (token.lower(), token.capitalize()):
        # Substring pre-check: a plain `in` test is far cheaper than compiling
        # and running a word-boundary scan, and almost always answers "no".
        if form not in text:
            continue
        for m in re.finditer(rf"\b{re.escape(form)}\b", text):
            before = text[m.start() - 1] if m.start() > 0 else ""
            after = text[m.end():m.end() + 8]
            # Email local part / domain label: "ing@x", "mail.hospital", "hospital.nl"
            if before == "@" or (before == "." and m.start() >= 2 and text[m.start() - 2].isalnum()):
                continue
            if after[:1] == "@" or re.match(r"\.[a-zA-Z]{2,6}\b", after):
                continue
            return True
    return False


def _is_heading_shape(text: str, start: int, end: int, token: str) -> bool:
    """Is the candidate positioned as a section heading rather than a value?

    Headings and shouted words are never bank codes. Lines carrying an
    explicit BIC/SWIFT keyword are exempt from the all-caps rule, so a
    genuine ``BIC: GEBABEBB`` line is not mistaken for a heading.
    """
    line_start, line_end = _enclosing_line(text, start, end)
    line = text[line_start:line_end]

    # The token is the entire line — unless the line above is a bare
    # BIC/SWIFT label, which makes this a labelled value in a table or
    # column layout rather than a heading.
    if line.strip() == token:
        return not _BIC_LABEL_LINE.match(_previous_nonblank_line(text, line_start))

    # The token starts its line and is immediately followed by a colon
    if text[line_start:start].strip() == "":
        if text[end:line_end].lstrip().startswith(":"):
            return True

    # A shouted line: no lowercase, no digits, and no banking keyword
    if (
        not any(ch.islower() for ch in line)
        and not any(ch.isdigit() for ch in line)
        and not _BIC_KEYWORD.search(line)
    ):
        return True

    return False


def suppress_bic_without_evidence(text: str, match: RawMatch) -> bool:
    """Emit a BIC only on registry membership or banking context.

    BIC is the only bank identifier here with no check digit, so ISO 9362
    structure cannot carry the decision on its own — characters 5-6 of
    ordinary uppercase words are frequently valid country codes
    (``DRINGEND`` -> ``GE``, ``HOSPITAL`` -> ``IT``). Gates apply in order:

    0. the token also occurs as an ordinary lowercase word here -> reject;
    1. registry hit (deployment-supplied, then bundled seed prefixes) -> emit;
    2. heading / shouted-word shape -> reject;
    3. BIC-SWIFT keyword, IBAN or bank block in the structural unit -> emit;

    and a bare shape match reaching the end with none of the above is never
    emitted. Gate 0 outranks every tier below it — no genuine BIC is also an
    ordinary lowercase word — so it is applied on both emitting paths.
    """
    if match.pattern_def.entity_type != EntityType.BIC:
        return False

    token = match.text.strip()

    # Gate 0 scans the whole document, so it is evaluated only on the paths
    # that would otherwise emit — the rejecting paths below are all cheap and
    # reach the same verdict either way.

    # Tier 1 — known institution.
    if is_registered_bic(token):
        return _occurs_as_lowercase_word(text, token)

    # Gate 2 — heading and shouted-word shapes.
    if _is_heading_shape(text, match.start, match.end, token):
        return True

    # Tier 2 — banking context in the enclosing line / record / paragraph.
    # The token itself is blanked out so it cannot vouch for itself.
    unit = _structural_unit(text, match.start, match.end)
    unit = unit.replace(token, " " * len(token))
    if _BIC_KEYWORD.search(unit) or _IBAN_SHAPE.search(unit) or _BANK_BLOCK.search(unit):
        return _occurs_as_lowercase_word(text, token)

    # No tier satisfied.
    return True


def suppress_postal_in_longer_identifier(text: str, match: RawMatch) -> bool:
    """Suppress bare digit runs that belong to a longer number, not an address.

    A bare 4- or 5-digit run is the weakest shape in the engine, and when it
    cuts into a longer identifier the damage is worse than a plain false
    positive: ``SV-Nummer: [POSTAL_CODE] 040390`` leaves half an Austrian
    social-security number exposed with no way to label the remainder.

    Applies only to digits-only matches, so structured forms keep their own
    behaviour — NL ``1234 AB``, PT ``1234-567``, LU ``L-1234``.
    """
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    clean = match.text.strip()
    if not clean.isdigit():
        return False

    before_char = text[match.start - 1] if match.start > 0 else ""
    after_char = text[match.end] if match.end < len(text) else ""

    # Directly glued to more digits
    if before_char.isdigit() or after_char.isdigit():
        return True

    # Joined by identifier punctuation: "0456.2398.71-02", "4471/2025".
    # The punctuation only counts when it actually *joins two digit groups* —
    # a trailing period is ordinary sentence punctuation, and treating it as a
    # separator discards every postal code that ends a sentence
    # ("Domicilio: Palma, 13867. Pagos a ...").
    prev_prev = text[match.start - 2] if match.start >= 2 else ""
    next_next = text[match.end + 1] if match.end + 1 < len(text) else ""
    if before_char in "._/" and prev_prev.isdigit():
        return True
    if after_char in "._/" and next_next.isdigit():
        return True
    if after_char == "-" and next_next.isdigit():
        return True
    if before_char == "-" and not _COUNTRY_PREFIXED.search(text[:match.start - 1]):
        # "A-1010 Wien" is an address; "12-3456" is one number
        return True

    # A further digit group on the same line: "1268 040390", "1234 5678 925",
    # "+43 664 8213 907", "2140 1.912". Horizontal whitespace only — a digit
    # on the *next* line is a separate field, not a continuation.
    if re.match(r"[ \t]+\d", text[match.end:match.end + 4]):
        return True

    # An identifier label introduces the digits: "DiNr. 4471", "Policen-Nr."
    before = text[max(0, match.start - 40):match.start]
    if _ID_CUE_BEFORE.search(before):
        return True

    # Digits after an international dialling prefix belong to PHONE
    line_start, _ = _enclosing_line(text, match.start, match.end)
    if _DIALLING_PREFIX_BEFORE.search(text[line_start:match.start]):
        return True

    return False


def suppress_requires_context(text: str, match: RawMatch) -> bool:
    """Suppress patterns that require context keywords."""
    if not match.pattern_def.requires_context:
        return False
    if not match.pattern_def.context_keywords:
        return False
    before, after = _get_context(text, match.start, match.end)
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
        suppress_postal_as_house_number, suppress_postal_in_longer_identifier,
    ],
    EntityType.BIC: [suppress_bic_without_evidence],
    EntityType.IBAN: [suppress_reference],
    EntityType.LICENSE_PLATE: [suppress_plate_in_compound],
    EntityType.CHAMBER_OF_COMMERCE: [suppress_reference],
}


def should_suppress(text: str, match: RawMatch) -> bool:
    """Run applicable suppression filters. Returns True if match should be discarded."""
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
