"""Pass-2 suppression filters for false positive reduction.

Each suppressor examines a candidate match and its surrounding context to decide
whether the match is a false positive. Returning True means the match should be
**suppressed** (i.e., it is NOT PII).
"""

from __future__ import annotations

import re
from typing import Callable

from euredact.rules.bic_registry import is_known_institution, is_registered_bic
from euredact.rules.de_districts import DE_DISTRICT_CODES
from euredact.rules.matchers import RawMatch
from euredact.types import EntityType

# Context window: number of characters before/after a match to examine
_CONTEXT_CHARS = 150

# ── Currency ────────────────────────────────────────────────────────────

#: Currency *symbols*. Kept apart from the alphabetic codes below because "\b"
#: does the wrong thing next to them: "€" is not a word character, so "€\b"
#: demands a word character after the symbol and fails on the overwhelmingly
#: common "1163 €," / "20744 €." — the trailing punctuation kills the match.
#: That bug made every euro amount at the end of a clause a postal code.
_CURRENCY_SYMBOL = r"€|\$|£|¥|₺|zł|Kč|лв|kn|Ft|₽"
#: Alphabetic codes and words, where "\b" is correct and necessary.
_CURRENCY_WORD = (
    r"EUR|USD|GBP|CHF|ISK|SEK|NOK|DKK|PLN|CZK|HUF|RON|BGN|HRK|"
    r"euro|euros|dollar|dollars|pond|kronor|kroner|kronur|kr|"
    r"złoty|korun|forint|lei|leva"
)
_CURRENCY_AFTER = re.compile(
    rf"^\s*(?:(?:{_CURRENCY_SYMBOL})|(?:{_CURRENCY_WORD})\b)",
    re.IGNORECASE,
)
# "12385,84 €" or "12385.84 €" — number is integer part of decimal amount
_CURRENCY_COMMA_AFTER = re.compile(
    rf"^[.,]\d{{1,2}}\s*(?:(?:{_CURRENCY_SYMBOL})|(?:{_CURRENCY_WORD})\b)",
    re.IGNORECASE,
)
_CURRENCY_BEFORE = re.compile(
    rf"(?:(?:{_CURRENCY_SYMBOL})|\b(?:{_CURRENCY_WORD}))\s*$",
    re.IGNORECASE,
)
# Also catch "Montant TTC :" or "Beløb:" before a number
_AMOUNT_LABEL_BEFORE = re.compile(
    r"\b(?:Montant|Beløb|Summa|Summe|Bedrag|Amount|Total|TTC|inkl|"
    r"Upphæð|Importe|Importo|Valore|Wartość|Kwota|Částka|Összeg|"
    r"Sum|Beloop|Prix|Preis|Price|Loyer|Miete|Huur|Rent|Betrag)"
    r"\s*(?:\w+\s*)?:?\s*$",
    re.IGNORECASE,
)

# ── Units ───────────────────────────────────────────────────────────────

# Horizontal space only: a unit is on the number's own line. Read across the
# break, "Mob: +49 172 634 85 21" followed by "m.k@example.de" on the next line
# was "21 m" and the whole phone number was dropped (rules-engine#51).
_UNIT_AFTER = re.compile(
    r"^[ \t]*(?:kg|km|cm|mm|m[²³]?|m\b|g\b|l\b|ml|mg|GB|MB|KB|TB|%|"
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
    r"\b(?:dossier|ref\.?|referentie|reference|référence|factuurnummer|"
    r"invoice\s*(?:nr|number|no)?|bestelnummer|order\s*(?:nr|number|no)?|"
    r"kenmerk|ordernummer|Aktenzeichen|numéro\s*de\s*(?:dossier|facture|commande)|"
    r"bestellnummer|Rechnungsnummer|artikelnr|article\s*no|"
    r"contract\s*(?:nr|number|no)?|pagina|page|Seite|blz\.?|"
    r"Facture\s*n[°o]?|Faktura\s*n[°or]\.?|Lasku\s*n[°or]o?\.?|"
    r"Rechnung\s*(?:Nr|n[°o])?|faktura\s*(?:nr|n[°o])?|"
    r"bestilling\s*(?:nr|n[°o])?|bestelling\s*n[°or]\.?|"
    r"Reikningur\s*nr|"
    # Support-desk vocabulary. "Ticket #94730" and "Kundenservice Ticket #121929"
    # were read as postal codes 104 times.
    r"ticket|incident\s*(?:report|nr|no)?|case\s*(?:nr|no|id)?|"
    r"zaaknummer|meldingsnummer|Vorgangsnummer|Vorgang|Störungsmeldung|"
    r"saksnummer|ärendenummer|sagsnummer|asianumero|"
    # The Dutch two-word form. "factuurnummer" was here, "Factuur nr." was not,
    # and the latter is what documents actually write.
    r"Factuur\s*n[ro]?\.?|Nota\s*n[ro]?\.?)\s*[:.#]?\s*$",
    re.IGNORECASE,
)

#: A "#" immediately before the number. Across every language in scope this
#: marks a reference — a ticket, an order, a line item — and never a postcode or
#: a national identifier.
_HASH_BEFORE = re.compile(r"#\s*$")

#: A short uppercase tag joined to the number by a hyphen: "IR-43433",
#: "INC-2024", "REF-88120". The tag is what makes it a document reference; a
#: postal code is never introduced this way.
_REF_PREFIX_BEFORE = re.compile(r"(?:^|[\s(\[])[A-Z]{2,5}-$")

#: The cross-border address form, "CH-8004 Zürich", "NL-1012 LG Amsterdam":
#: an ISO country code hyphenated to a postal code. `_REF_PREFIX_BEFORE` reads
#: those two letters as a reference tag, which is what it is for "IR-43433",
#: so the address form is told apart by position rather than by shape -- the
#: prefix opens an address line (after a comma or at a line start) and a place
#: name follows the code (rules-engine#58).
_COUNTRY_PREFIX_OPENS_LINE = re.compile(r"(?:^|\n|,)[ \t]*([A-Z]{2})-$")
_POSTAL_PREFIX_COUNTRIES = frozenset({
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI",
    "FR", "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV",
    "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "UK",
})

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

#: An identifier cue that is really a postal label. See
#: `suppress_postal_in_longer_identifier` for why this exemption exists.
_POSTAL_LABEL_CUE = re.compile(r"post", re.IGNORECASE)

# A country prefix on a postal code — "A-1010 Wien", "B-2000", "L-1234",
# "CH-8000", "D-10115". One or two letters before the hyphen, at a boundary.
#
# The boundary excludes a hyphen, which is what makes this a *prefix* rather
# than a segment. It did not, so any `XX-NNNNN` tail of a hyphenated reference
# read as a country-prefixed address: in "PV-2026-LU-09143" the `LU` is
# preceded by `-`, the escape hatch below fired, and the German five-digit
# postal pattern kept `09143` — a police file number masked as an address, with
# the rest of the reference left in the clear (rules-engine#31).
#
# A real prefix opens its token: it follows the start of the text, whitespace,
# or punctuation that is not a hyphen joining it to a previous segment.
_COUNTRY_PREFIXED = re.compile(r"(?:^|[^A-Za-z0-9\-])[A-Z]{1,2}$")

# ── Phone: preceded by ID/tax label ────────────────────────────────────
#
# `_ID_LABEL_BEFORE` and `suppress_phone_after_id_label` lived here. Their
# labels are now typed entries in `rules/cues.py`, and a phone-shaped span
# behind one is *relabelled* rather than dropped.
#
# Dropping was the wrong verb. The span is found either way, so removing the
# claim decided only whether the value was masked — and the answer was "no":
# "Rijksregisternummer: 85.03.19-284.73" produced no detection at all, a
# redaction library printing in full an identifier it had recognised and
# rejected. The 653-miss word-boundary lesson recorded here moved with the
# labels; see the module docstring in `cues.py`.

# ── Phone: 0800 service numbers ─────────────────────────────────────────

_SERVICE_NUMBER = re.compile(r"^0800[\-\s]")

# ── Phone: date overlap ─────────────────────────────────────────────────

_DATE_PATTERN_FULL = re.compile(r"^\d{2}[-/.]\d{2}[-/.]\d{4}$|^\d{4}[-/.]\d{2}[-/.]\d{2}$")

# ── License plate: compound words and non-city codes ────────────────────

_HYPHEN_COMPOUND_BEFORE = re.compile(r"[A-Za-zÄÖÜäöüß]-$")
_CURRENCY_PLATE = re.compile(r"^(?:EUR|USD|GBP|CHF|SEK|NOK|DKK|ISK|CZK|PLN|HUF|RON|BGN|HRK)\s", re.IGNORECASE)

# Standards and classification prefixes that are plate-shaped once a letter and
# digits follow: "ATC-N06", "ICD-O3". None is a German district code, but the
# guard is still gated on the absence of a plate cue, so a genuine plate that
# happens to collide is not lost.
_STANDARDS_PREFIX = {"ICD", "ISO", "DIN", "IEC", "RFC", "DSM", "ATC", "MDR"}

_PLATE_CUE_NEAR = re.compile(
    r"(?:Kennzeichen|Nummernschild|Kfz|Fahrzeug|amtliche[sn]?\s+Kennz|"
    r"nummerplaat|plaque\s+d'immatriculation|license\s+plate|number\s+plate)",
    re.IGNORECASE,
)

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


#: How far the address rescue in `suppress_year_as_postal` may look. Much
#: shorter than `_CONTEXT_CHARS`, and stopped by a blank line.
_ADDRESS_BLOCK_CHARS = 60

#: A paragraph break. An address is a contiguous block: its postal code sits
#: beside its street and city, possibly on the next line, never in the next
#: paragraph.
_BLANK_LINE = re.compile(r"\n[ \t]*\n")


def _address_block_context(text: str, start: int, end: int) -> str:
    """Context for the address rescue: near, and within the same block.

    `_get_context` reads 150 characters either side, which crosses paragraphs.
    That is how one real address in a document licensed every later four-digit
    run as a postal code -- a year in a law citation, a CV date range, a
    narrative sentence -- because the rescue below only asks whether an address
    word appears *somewhere* in the window (rules-engine#32).

    The window is narrowed and clamped at a blank line on each side. A single
    newline is still crossed, because a postal code legitimately sits on its own
    line inside an address block:

        Adresse:
        Am Europlatz 2
        1120 Wien
    """
    lo = max(0, start - _ADDRESS_BLOCK_CHARS)
    hi = min(len(text), end + _ADDRESS_BLOCK_CHARS)
    before = text[lo:start]
    after = text[end:hi]
    # Keep only what is on this side of the nearest paragraph break.
    breaks = list(_BLANK_LINE.finditer(before))
    if breaks:
        before = before[breaks[-1].end():]
    found = _BLANK_LINE.search(after)
    if found:
        after = after[:found.start()]
    return before + after


# ── Date adjacency, for the postal-code year gate ───────────────────────
#
# Month names in the languages this engine covers. Long, but it is data: the
# alternative is a proximity heuristic, and proximity is what caused the defect
# these guard against. Kept in sync with the TypeScript port.
_MONTH_NAMES = (
    # en
    "january|february|march|april|may|june|july|august|september|october"
    "|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec"
    # de (incl. Austrian Jänner)
    "|januar|jänner|februar|märz|mai|juni|juli|oktober|dezember|dez|okt|mrz"
    # fr
    "|janvier|février|février|mars|avril|juin|juillet|août|aout|septembre"
    "|octobre|novembre|décembre|decembre"
    # nl
    "|januari|februari|maart|mei|juni|juli|augustus|oktober|mrt"
    # it
    "|gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre"
    "|ottobre|novembre|dicembre"
    # es / pt
    "|enero|febrero|abril|mayo|junio|julio|septiembre|octubre|noviembre"
    "|diciembre|janeiro|fevereiro|março|marco|maio|junho|julho|setembro"
    "|outubro|novembro|dezembro"
    # da / no / sv / is — "desember" (nb/nn/is) was the one December spelling
    # missing from a list that already carried ten others, which is why
    # "1. desember 2025" was a Norwegian postcode.
    "|marts|maj|augusti|oktober|desember"
    "|janúar|febrúar|apríl|maí|júní|júlí|ágúst|október|nóvember"
    # fi
    "|tammikuu|helmikuu|maaliskuu|huhtikuu|toukokuu|kesäkuu|heinäkuu|elokuu"
    "|syyskuu|lokakuu|marraskuu|joulukuu"
    # et / lv / lt
    "|jaanuar|veebruar|aprill|juuni|juuli|oktoober|detsember"
    "|janvāris|februāris|marts|aprīlis|maijs|jūnijs|jūlijs|augusts"
    "|septembris|oktobris|novembris|decembris"
    # pl (genitive, as used in dates)
    "|stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|września"
    "|października|listopada|grudnia"
    # cs / sk
    "|ledna|února|března|dubna|května|června|července|srpna|září|října"
    "|listopadu|prosince"
    # sl / hr
    "|januar|februar|marec|maj|junij|julij|avgust|siječnja|veljače|ožujka"
    "|travnja|svibnja|lipnja|srpnja|kolovoza|rujna|studenoga|prosinca"
    # hu / ro
    "|március|április|május|június|július|augusztus|szeptember|október"
    "|ianuarie|februarie|martie|aprilie|iunie|iulie|septembrie|octombrie"
    "|noiembrie|decembrie"
    # el / bg
    "|ιανουαρίου|φεβρουαρίου|μαρτίου|απριλίου|μαΐου|ιουνίου|ιουλίου"
    "|αυγούστου|σεπτεμβρίου|οκτωβρίου|νοεμβρίου|δεκεμβρίου"
    "|януари|февруари|март|април|май|юни|юли|август|септември|октомври"
    "|ноември|декември"
)

#: "since" cues, which introduce a bare year in every one of these languages.
_SINCE_CUES = (
    "seit|since|depuis|sinds|sedert|vanaf|desde|dal|dall'|od|sedan|siden"
    "|alates|alkaen|από|от|din|iz|ab"
)

#: A month name, a "since" cue, or a numeric date tail immediately before the
#: candidate. Deliberately adjacent-only — a cue 150 characters away is what
#: made this a bug in the first place.
_DATE_BEFORE = re.compile(
    rf"(?:\b(?:{_MONTH_NAMES})\b\.?|\b(?:{_SINCE_CUES})\b|"
    rf"\d{{1,2}}[./\-]\d{{1,2}}[./\-])\s*$",
    re.IGNORECASE | re.UNICODE,
)

#: A date separator immediately after, making the candidate a leading year:
#: "2026-03-14", "2026/03/14".
_DATE_AFTER = re.compile(r"^[./\-]\d{1,2}[./\-]\d{1,2}\b")

#: ISO 4217 codes made only of the consonants a Spanish plate accepts, so a
#: money amount reads as a registration. This is why "2297 DKK" was a plate.
#: Crypto tickers are the same shape and the same mistake — every one of the 130
#: surviving plate false positives was "4499 BTC" or a sibling. A ticker is a
#: unit, exactly as an ISO 4217 code is.
_CURRENCY_CODE = (
    r"(?:DKK|SEK|NOK|ISK|CZK|PLN|HUF|RON|BGN|HRK|CHF|GBP|TRY|RSD|MKD"
    r"|BYN|KZT|CNY|JPY|KRW|ZAR|BRL|MXN|CLP|COP|PLZ|SKK|TRL"
    r"|BTC|ETH|LTC|XRP|BCH|XLM|XMR|DOT|SOL|ADA|TRX|DOGE|USDT|USDC)"
)
#: The code usually falls *inside* the plate span, because the plate shape ends
#: in exactly the three letters the code occupies: "2297 DKK" matched whole.
_CURRENCY_CODE_TAIL = re.compile(rf"\s{_CURRENCY_CODE}$")
_CURRENCY_CODE_AFTER = re.compile(rf"^\s*{_CURRENCY_CODE}\b")

#: Log-timestamp tails, which the ":"-anchored secret rule picks up:
#: "57:22.283Z]", "11:11.231Z".
_TIMESTAMP_FRAGMENT = re.compile(
    r"^\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,6})?Z?$"
)

#: Cloud region names and similar well-known configuration values. Not secrets,
#: and they sit after "region = " in every infrastructure dump.
_NOT_A_SECRET = re.compile(
    r"^(?:af|ap|ca|cn|eu|il|me|sa|us|gov)-(?:north|south|east|west|central"
    r"|northeast|northwest|southeast|southwest)-\d[a-z]?$"
    r"|^(?:application|text|image|audio|video|multipart)/[\w.+-]+$"
    r"|^(?:utf|iso|windows)-[\d-]+$"
    r"|^(?:no-cache|no-store|max-age|gzip|deflate|identity|chunked)\b",
    re.IGNORECASE,
)

#: Trailing and leading punctuation the greedy "[^\\s]{8,}" secret rule sweeps
#: up with the token: it matched "TRIONL2U)." out of "(BIC: TRIONL2U).". Stripped
#: only for the shape tests below — the emitted span is never altered here.
_PUNCT_EDGES = re.compile(r"^[\s(\[{<\"'`]+|[\s)\]}>\"'`.,;:!?]+$")


def _core_token(raw: str) -> str:
    return _PUNCT_EDGES.sub("", _PUNCT_EDGES.sub("", raw))


#: A UUID, exactly. SECRET must not claim one — see
#: suppress_secret_over_structured.
_EXACT_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{12}$"
)

#: A BIC, and the cue that licenses one.
_BIC_SHAPE = re.compile(r"^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$")
_BIC_CUE_BEFORE = re.compile(r"(?:BIC|SWIFT|BIC/SWIFT)\s*[:=]?\s*\(?\s*$", re.IGNORECASE)

#: An email address, exactly. Same argument as the UUID and the BIC: the EMAIL
#: rule owns this span, and a generic high-entropy rule must not contest it.
_EXACT_EMAIL = re.compile(r"^[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+$")

#: A URL, or the tail of one after the scheme has been split off. The secret
#: rules are anchored on ":" and "=", so "https://api.sendgrid.com/v3/mail/send"
#: hands them "//api.sendgrid.com/v3/mail/send" and a slash-separated path scores
#: as high-entropy. An endpoint is published documentation, not a credential.
_URL_LIKE = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*:)?//[^\s/]+(?:/\S*)?$"
    r"|^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d{1,5})?(?:/\S*)?$",
    re.IGNORECASE,
)

#: A URL that *carries* a credential is the opposite case, and it is the common
#: one: "mongodb://admin:DFKDKi1eb51OOhuHPYz@rds-main.eu-west-1.rds.amazonaws.com"
#: is a connection string with a live password in it. Suppressing those as
#: "just a URL" lost 347 real secrets, so the endpoint test below must not fire
#: when userinfo or a credential-bearing query parameter is present.
_URL_WITH_CREDENTIALS = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*:)?//[^/@\s]*:[^/@\s]*@"
    r"|[?&](?:api_?key|access_?token|auth|token|secret|password|pwd|sig|"
    r"signature|credential)=",
    re.IGNORECASE,
)

#: An LDAP distinguished name: "cn=github-actions,dc=corp,dc=eu". Every
#: component is a key=value pair, which is precisely what the "="-anchored
#: secret rule is looking for.
_LDAP_DN = re.compile(
    r"^(?:cn|ou|dc|uid|o|l|st|c)=[^,=]+(?:,\s*(?:cn|ou|dc|uid|o|l|st|c)=[^,=]+)+$",
    re.IGNORECASE,
)

#: Lower-case words joined by hyphens, optionally with a short id suffix:
#: "service-account", "analytics-engine", "data-lake-33e061". The existing
#: single-word test already rejects "sozialversicherungsnummer" on the reasoning
#: that a real secret would be mixed case; a hyphenated compound is the same
#: token with a separator in it.
_HYPHENATED_WORDS = re.compile(r"^[a-z]{2,}(?:-[a-z]{2,})+(?:-[0-9a-f]{4,8})?$")


def suppress_secret_over_structured(text: str, match: RawMatch) -> bool:
    """A generic secret must not claim a span that is a specific known type.

    The high-entropy rules are deliberately broad, and they carry a validator,
    so they reach the top priority tier while the structured detector for the
    same characters sits at the bottom with no validator to offer. The generic
    rule therefore wins spans it should never have contested.

    Measured on 152,300 documents: 687 UUIDs and 140 BICs were reported as
    SECRET. Each was counted twice over — a false positive for SECRET and a miss
    for the type that should have had it — so this single check moves 1,654
    outcomes.
    """
    if match.pattern_def.entity_type != EntityType.SECRET:
        return False
    token = _core_token(match.text)
    if _EXACT_UUID.match(token) or _EXACT_EMAIL.match(token):
        return True
    if _BIC_SHAPE.match(token):
        before = text[max(0, match.start - 24):match.start]
        if _BIC_CUE_BEFORE.search(before):
            return True
    return False


def suppress_secret_not_a_secret(text: str, match: RawMatch) -> bool:
    """Reject the three things the ":"-anchored secret rule reliably mistakes.

    All three sit after a colon or an equals sign, which is all that rule asks
    for, and all three clear the entropy threshold:

      timestamps      "57:22.283Z]"   — 310 occurrences
      ordinary words  "Sozialversicherungsnummer" — 73
      region names    "us-east-1"     — 54

    The word test is narrow on purpose: purely alphabetic *and* shaped like one
    natural word (all lower case, or capitalised then lower case). A random
    all-letter token would be mixed case, and is left alone — losing a real
    secret is the expensive direction.
    """
    if match.pattern_def.entity_type != EntityType.SECRET:
        return False
    bare = _core_token(match.text)
    if _TIMESTAMP_FRAGMENT.match(bare):
        return True
    if _NOT_A_SECRET.match(bare):
        return True
    if _URL_LIKE.match(bare) and not _URL_WITH_CREDENTIALS.search(bare):
        return True
    if _LDAP_DN.match(bare):
        return True
    if _HYPHENATED_WORDS.match(bare):
        return True
    if bare.isalpha() and (bare.islower() or (bare[:1].isupper() and bare[1:].islower())):
        return True
    return False


def suppress_plate_as_currency_amount(text: str, match: RawMatch) -> bool:
    """A money amount followed by its ISO 4217 code is not a registration.

    Spain's plate shape is four digits then three consonants, and the codes for
    the Nordic and Central European currencies are all consonants: "2297 DKK"
    read as a Spanish plate 487 times across the corpus.
    """
    if match.pattern_def.entity_type != EntityType.LICENSE_PLATE:
        return False
    if _CURRENCY_CODE_TAIL.search(match.text):
        return True
    return bool(_CURRENCY_CODE_AFTER.match(text[match.end:match.end + 12]))


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


#: A dotted quad with every octet in range. The German tax-number shape
#: "[1-9]\d[\s.]?\d{3}[\s.]?\d{3}[\s.]?\d{3}" matches an IPv4 address exactly:
#: "45.175.147.128" was reported as a TAX_ID 31 times.
_DOTTED_QUAD = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

#: Two plausible years joined by a hyphen — a school year, a contract term, a
#: reporting period. Read as a phone number 96 times.
_YEAR_RANGE = re.compile(r"^(19|20)\d{2}\s?[-–/]\s?(19|20)\d{2}$")

#: A digit and a decimal point immediately before the candidate, so the match is
#: the fractional part of an amount: "0.034865 BTC" gave a PHONE of "034865".
_DECIMAL_TAIL_BEFORE = re.compile(r"\d[.,]$")


def suppress_taxid_as_ip_address(text: str, match: RawMatch) -> bool:
    """A dotted quad is an address, not a tax number.

    Germany's tax-number shape allows dots between its digit groups, which makes
    it a superset of IPv4. The address is still redacted — the IP_ADDRESS rule
    claims the same span — so this only corrects the label.
    """
    if match.pattern_def.entity_type != EntityType.TAX_ID:
        return False
    return bool(_DOTTED_QUAD.match(match.text.strip()))


def suppress_phone_as_number_range(text: str, match: RawMatch) -> bool:
    """Reject two phone shapes that are arithmetic rather than contact details.

    A year range ("Schooljaar 2025-2026") and the fractional part of a decimal
    amount ("0.034865 BTC"). Both clear every phone pattern's shape test, and
    neither has ever been a telephone number.
    """
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    if _YEAR_RANGE.match(match.text.strip()):
        return True
    return bool(_DECIMAL_TAIL_BEFORE.search(text[max(0, match.start - 2):match.start]))


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
    """Suppress numbers preceded by reference/invoice/dossier keywords.

    POSTAL_CODE belongs here for the same reason every other numeric type does,
    and its absence was an oversight: a five-digit ticket number sits in exactly
    the shape a German or French postcode occupies, so "Ticket #94730" and
    "Incident report IR-43433" were masked as addresses 169 times.

    The "#" and "XX-" markers are checked adjacently rather than through the
    150-character keyword window. That window is what made the postal rule claim
    years in dates; widening its reach again to fix a different symptom would be
    repeating the mistake.
    """
    if match.pattern_def.entity_type not in (
        EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN,
        EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE,
        EntityType.POSTAL_CODE,
    ):
        return False
    before, _ = _get_context(text, match.start, match.end)
    if _REFERENCE_BEFORE.search(before):
        return True
    adjacent = text[max(0, match.start - 8):match.start]
    if _HASH_BEFORE.search(adjacent):
        return True
    if not _REF_PREFIX_BEFORE.search(adjacent):
        return False
    return not (
        match.pattern_def.entity_type == EntityType.POSTAL_CODE
        and _is_country_prefixed_address(text, match.start, match.end)
    )


def _is_country_prefixed_address(text: str, start: int, end: int) -> bool:
    """"CH-8004 Zürich" on an address line, not the reference "IT-20431"."""
    found = _COUNTRY_PREFIX_OPENS_LINE.search(text[max(0, start - 12):start])
    return (
        found is not None
        and found.group(1) in _POSTAL_PREFIX_COUNTRIES
        and bool(_CITY_AFTER.match(text[end:end + 24]))
    )


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


# ── The engine's own output ─────────────────────────────────────────────
#
# Redaction has to be idempotent: running it over a document it already
# produced must leave the placeholders it wrote alone. It did not.
# `[POSTAL_CODE]` is thirteen characters of mixed case with an underscore, so
# the entropy-based SECRET rule read it as a credential and a second pass
# replaced it with `[SECRET]` -- corrupting the first pass's output and
# reporting a credential that never existed (rules-engine#33).
#
# Three forms are emitted, and all three are guarded because all three come
# back as input in a re-processing pipeline:
#
#   [TYPE]        the default mask
#   TYPE_1        referential_integrity=True
#   TYPE_K7Q2     tokenize=True -- and here a false detection is worse than
#                 cosmetic, because it breaks restore()
#
# Only names that are real entity types count. Guarding any bracketed
# upper-case token would be simpler and wrong: `[AKIAIOSFODNN7EXAMPLE]` is a
# bracketed upper-case token and also a live AWS key, and a redaction library
# may not trade a false negative for tidiness. A placeholder for a *custom*
# pattern is therefore not covered -- the suppressor cannot know which names
# were registered.
# The closing bracket is optional, and that is load-bearing rather than
# permissive. Another pattern's span need not agree with this one about where
# the marker ends: the assigned-secret rule stops before sentence punctuation
# (rules-engine#35), so it claims "[POSTAL_CODE" without the "]" and a guard
# that required the closer let it through. The opening bracket is still
# required, so a bare word that happens to be a type name is not swallowed.
_PLACEHOLDER = re.compile(
    r"\A(?:\[([A-Z][A-Z0-9_]*)\]?"         # [TYPE] or a span that lost the ]
    r"|([A-Z][A-Z0-9_]*?)_(?:\d+|[A-HJ-NP-Z2-9]{4}))\Z"   # TYPE_1 / TYPE_K7Q2
)


def _known_type_names() -> frozenset[str]:
    return frozenset(e.value for e in EntityType)


def suppress_redaction_placeholder(text: str, match: RawMatch) -> bool:
    """Suppress a span that is entirely one of the engine's own placeholders."""
    found = _PLACEHOLDER.match(match.text)
    if found is None:
        return False
    name = found.group(1) or found.group(2)
    return name in _known_type_names()


#: A postal label whose only distance from the value is punctuation:
#: "PLZ: 2011", "code postal : 2011", "Woonplaats: 1950".
_POSTAL_LABEL_TOUCHING = re.compile(
    r"(?:" + _POSTAL_CONTEXT_NEAR.pattern + r")[\s:.\-]{0,4}$", re.IGNORECASE)

#: A capitalised place name after the code: "2000 Antwerpen", "2011 Haarlem".
#: A following label ("1970 Fødselsnummer:") is excluded by the colon.
_CITY_AFTER = re.compile(r"^[ \t](?!\w+\s*:)[A-ZÀ-ÞŁŠŽ][\w\-']{2,}")


#: A sentence boundary: a full stop, question or exclamation mark followed by
#: space, or a line break. Written so it cannot fire inside "11.03.1970", where
#: the periods are not followed by whitespace -- that date is one of the
#: false positives this gate has to reject.
_SENTENCE_BREAK = re.compile(r"[.!?][ \t\n]|\n")


def _sentence_around(text: str, start: int, end: int, reach: int = 160) -> str:
    """The value's own sentence, bounded by `reach` characters either side."""
    before = text[max(0, start - reach):start]
    after = text[end:end + reach]
    last = None
    for found in _SENTENCE_BREAK.finditer(before):
        last = found
    if last is not None:
        before = before[last.end():]
    found = _SENTENCE_BREAK.search(after)
    if found is not None:
        after = after[:found.start()]
    return before + after


def _year_sits_in_address_structure(text: str, start: int, end: int) -> bool:
    """True when a year-shaped value is positioned as a postal code.

    Every position is local to the value or inside its own sentence. Proximity
    to an address *word* anywhere in a 300-character window is what the old
    rescue asked, and that is a neighbourhood rather than a position.
    """
    before = text[max(0, start - 28):start]
    # "Amsterdam, 2026" — the comma of an address line.
    if re.search(r",[ \t]*$", before):
        return True
    # "PLZ: 2011" — a postal label with nothing but punctuation between.
    if _POSTAL_LABEL_TOUCHING.search(before):
        return True
    # A capitalised place name immediately after: "2000 Antwerpen",
    # "B-2000 Antwerpen", "wonende te 2000 Antwerpen". A following *label* is
    # excluded by the colon in `_CITY_AFTER`, so "1970 Fødselsnummer:" is not
    # an address.
    if _CITY_AFTER.match(text[end:end + 24]):
        return True
    # An address word in the value's own sentence. "Te huur: Lange Nieuwstraat
    # 12, rustige ligging in 2018, vlakbij openbaar vervoer." is an Antwerp
    # postal code in prose, and the street is the evidence. The sentence is what
    # separates it from the false positives: there the year and the address sit
    # in different sentences ("... revenus 2022. ... Adresse : rue du Commerce
    # 130, 89654 Angers.") and the address carries its own code.
    return bool(_POSTAL_CONTEXT_NEAR.search(_sentence_around(text, start, end)))


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
    # A date construction *touching* the candidate settles it, whatever the
    # rest of the document says. Without this, the postal-context test below
    # rescued every year in every document with an address in it — and
    # "Adresse", "rue" and "Str." appear in the header of essentially every
    # business letter. Measured: 1,691 of 3,322 postal false positives were
    # plausible years, 1,636 of them literally "2025".
    if _DATE_BEFORE.search(text[max(0, match.start - 24):match.start]):
        return True
    if _DATE_AFTER.match(text[match.end:match.end + 8]):
        return True

    # Keep as postal code only when the value sits in address *structure*.
    #
    # The old rescue asked whether an address word appeared anywhere in a
    # 300-character window, which is an address *neighbourhood* and not the
    # same thing. Narrowing the window was not enough: in
    #
    #   "Déclaration de revenus 2022. Laurent Leroy. Numéro fiscal :
    #    1167724166806. Adresse : rue du Commerce 130, 89654 Angers."
    #
    # the real postal code and the year are on one line, so no blank line
    # separates them and "Adresse" sits 60 characters from "2022". 47 of the 81
    # POSTAL_CODE false positives on the 152,300-record corpus were bare years
    # of this shape (rules-engine#32).
    #
    # What separates the two is local: "89654" follows ", " and precedes a
    # capitalised city, while "2022" follows "revenus " and precedes ". ".
    # So a year is rescued only by structure that touches it.
    if _year_sits_in_address_structure(text, match.start, match.end):
        return False
    # Keep if preceded by comma+space (address pattern: "Amsterdam, 2026")
    immediate_before = text[max(0, match.start - 3):match.start]
    if re.search(r",\s*$", immediate_before):
        return False
    # Suppress: years without postal context are almost never postal codes
    return True


# ── Postal code: disqualified by the word in front of it ───────────────
#
# The mirror image of `rules/cues.py`. There a label promotes a type; here a
# word refuses one. Both were reported together: a bare four-digit run becomes a
# POSTAL_CODE as soon as *any* real postal code establishes the country, which
# is to say in almost every real document, because `_POSTAL_CONTEXT_NEAR` above
# then rescues it from `suppress_year_as_postal`. Measured on the training
# corpus: 55 bare years in prose ("Opgericht in 2016", "Fondée en 2017") plus
# telephone extensions ("(toest. 3841)", "(poste interne 3318)", "(ext. 2219)").

#: Prepositions that can only be temporal. Nothing is ever located "since 2018",
#: so these disqualify a postal code on their own.
_YEAR_WORD_BEFORE = re.compile(
    r"(?<![A-Za-z0-9_])(?:sinds|since|depuis|seit|siden|sedan|desde"
    r"|vuonna|anno|dal)\s+$",
    re.IGNORECASE,
)

#: "in", "en" and "im" are *both* temporal and locative, and in exactly the
#: countries whose postal codes are year-shaped. Belgian 2000 is Antwerp and
#: 2018 is one of its districts, so "Rustige ligging in 2018, vlakbij openbaar
#: vervoer" is an address, not a date — an earlier version of this rule
#: suppressed it and lost a real postal code, which is the worse error for a
#: redaction tool. So an ambiguous preposition needs a founding or payment
#: participle in front of it, which is what every case in the report had:
#: "Opgericht in 2016", "Fondée en 2017", "versé en 2025".
_YEAR_VERB_BEFORE = re.compile(
    r"(?<![A-Za-z0-9_])(?:opgericht|gesticht|opgestart|founded|established"
    r"|created|fond[ée]e?|cr[ée][ée]e?|gegründet|gegruendet|errichtet"
    r"|grundlagt|grundad|perustettu|fundada|fundado|fondata|costituita"
    r"|vers[ée]|betaald|uitbetaald|ausgezahlt|paid|geboren|born)"
    r"\s+(?:in|en|im|op|the)\s+$",
    re.IGNORECASE,
)

#: A capitalised word immediately after keeps the candidate: "in 2000 Antwerpen"
#: really is a postal code, and so is the "AZ" of a Dutch "1105 AZ". Without
#: this the rule would suppress the very addresses it is meant to leave alone.
_TOWN_AFTER = re.compile(r"\s*[A-ZÀ-ÞĀ-Ž]")

#: A telephone extension marker. "poste interne 3318" puts one qualifier word
#: between the marker and the number, so allow exactly one.
_EXTENSION_BEFORE = re.compile(
    r"(?<![A-Za-z0-9_])(?:toest(?:el)?|ext|extension|poste|durchwahl"
    r"|doorkiesnummer|tst|nebenstelle)\.?\s*(?:[a-zà-ÿ]{2,10}\s*)?[:.]?\s*$",
    re.IGNORECASE,
)


def suppress_postal_after_disqualifying_word(text: str, match: RawMatch) -> bool:
    """Suppress a postal code the word in front of it rules out."""
    if match.pattern_def.entity_type != EntityType.POSTAL_CODE:
        return False
    before = text[max(0, match.start - 24):match.start]
    if _EXTENSION_BEFORE.search(before):
        return True
    if (_RECENT_YEAR.match(match.text.strip())
            and (_YEAR_WORD_BEFORE.search(before)
                 or _YEAR_VERB_BEFORE.search(before))
            and not _TOWN_AFTER.match(text[match.end:match.end + 3])):
        return True
    return False


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


#: Characters that join a token to more of an identifier: "FR-S2-2026",
#: "FR-S2/2026", "FR-S2.2026", "FR_S2", "FR-S2+7". Only when a letter or digit
#: follows on the far side; a spaced dash or slash ("A / B") does not join.
_ID_CONNECTORS = "-/._+"

#: A reference marker directly before the token: "#FR-S2", "№ …", "n° …".
_REFERENCE_MARK_BEFORE = re.compile(r"(?:#|№|(?<![A-Za-z])[nN][°º])\s?$")


def _joined_to_more(text: str, start: int, end: int) -> bool:
    """A connector glues [start, end) to a letter or digit outside it."""
    after = text[end:end + 2]
    before = text[max(0, start - 2):start]
    return (
        (len(after) == 2 and after[0] in _ID_CONNECTORS and after[1].isalnum())
        or (len(before) == 2 and before[1] in _ID_CONNECTORS and before[0].isalnum())
    )


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

    # A plate is a token of its own. Inside a longer identifier -- "TF-284-KL-00874",
    # "LU-TS-2023-004512" (rules-engine#50), and with any other connector,
    # "FR-S2/2026", "FR-S2.2026" (rules-engine#81) -- a plate-shaped run is a
    # segment of a reference, and taking it left the rest readable. A spaced
    # dash or slash ("AB-123-CD / EF-456-GH") does not join.
    if _joined_to_more(text, match.start, match.end):
        return True

    # After a reference marker it is a reference ("Form Ref #FR-S2"), unless a
    # plate cue says otherwise: "Plaque d'immatriculation n° AB-123-CD" is a
    # plate (rules-engine#81).
    if _REFERENCE_MARK_BEFORE.search(text[max(0, match.start - 4):match.start]):
        before, after = _get_context(text, match.start, match.end)
        if not _PLATE_CUE_NEAR.search(before + after):
            return True

    matched = match.text.strip()
    parts = re.split(r"[\s\-]+", matched)

    # A standards or classification reference, not a plate — unless a plate
    # cue nearby says otherwise.
    if parts and parts[0].upper() in _STANDARDS_PREFIX:
        before, after = _get_context(text, match.start, match.end)
        if not _PLATE_CUE_NEAR.search(before + after):
            return True

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


def suppress_de_plate_unknown_district(text: str, match: RawMatch) -> bool:
    """Reject a German plate whose district code is not a real one.

    The district-code set is closed (see :mod:`euredact.rules.de_districts`),
    which makes it a whitelist rather than the open-ended blocklist of
    standards prefixes: ``REF-A12``, ``SYS-B3``, ``KTO-A1`` and every other
    document reference of that shape fail it without needing to be enumerated.

    Applied as a tier — an unknown code still emits when a plate cue is
    nearby, so a code missing from the list costs recall only in the absence
    of any other evidence.
    """
    if match.pattern_def.entity_type != EntityType.LICENSE_PLATE:
        return False
    if match.country_code != "DE":
        return False

    parts = re.split(r"[\s\-]+", match.text.strip())
    if not parts or not parts[0]:
        return False
    if parts[0].upper() in DE_DISTRICT_CODES:
        return False

    before, after = _get_context(text, match.start, match.end)
    if _PLATE_CUE_NEAR.search(before + after):
        return False
    return True


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


#: An IBAN-shaped run: two letters, two check digits, then grouped
#: alphanumerics. Deliberately *not* checksum-gated -- the point is to describe
#: the run a human wrote as one account number, including the ones that fail
#: their checksum, because those are exactly the ones no structured detector
#: claims and a generic digit pattern is therefore free to cut into.
_ACCOUNT_RUN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){2,8}\b")


def suppress_phone_inside_account_run(text: str, match: RawMatch) -> bool:
    """Suppress a phone match that lies inside an IBAN-shaped run.

    "Compte: FR76 3000 4008 0300 0109 5374" fails the IBAN checksum, so no
    BANK_ACCOUNT candidate survives and the span is unclaimed. The Danish
    eight-digit phone pattern -- the most permissive shape in the engine, and
    one that ran because `countries` scores rather than gates -- then took
    "3000 4008" out of the middle of it, producing
    "FR76 [PHONE] 0300 0109 5374": two digit groups masked under a type the
    document never mentioned and the rest of the account number in the clear
    (rules-engine#30).

    0.3.3 fixed the same shape of defect ("the generic phone pattern claimed
    fragments of rejected identifiers") for the cases reachable then; a spaced
    account run was not one of them. POSTAL_CODE has carried its own version of
    this guard since then, in ``suppress_postal_inside_iban``.

    Scoped to the match's own line: an account number is not written across a
    line break, and scanning the line rather than the document keeps this O(line).
    """
    if match.pattern_def.entity_type != EntityType.PHONE:
        return False
    line_start = text.rfind("\n", 0, match.start) + 1
    line_end = text.find("\n", match.end)
    if line_end < 0:
        line_end = len(text)
    for run in _ACCOUNT_RUN.finditer(text, line_start, line_end):
        if run.start() <= match.start and match.end <= run.end():
            # The run must be longer than the match, or it *is* the match.
            if run.end() - run.start() > match.end - match.start:
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

    # Both walks stop as soon as the paragraph is too wide to be used, because
    # everything past that point is discarded by the cap below anyway. The cap
    # used to be applied only to the *result*, so on a document with no blank
    # lines each walk ran to the top and bottom of the whole text — O(document)
    # per candidate, O(n^2) overall. A 256 KB file of bank details took 32 s,
    # which extrapolates to roughly 14 hours at the 10 MB input limit.
    para_start = line_start
    while para_start > 0:
        if line_end - para_start > _MAX_UNIT_CHARS:
            return text[line_start:line_end]
        prev_end = para_start - 1
        prev_start = text.rfind("\n", 0, prev_end) + 1
        if not text[prev_start:prev_end].strip():
            break
        para_start = prev_start

    # Expand downwards to the end of the paragraph
    para_end = line_end
    while para_end < len(text):
        if para_end - para_start > _MAX_UNIT_CHARS:
            return text[line_start:line_end]
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


#: A personal title right before the token: "Dr. HOFFMANN", "Mme JANSSENS".
_TITLE_BEFORE = re.compile(
    r"(?<![A-Za-z])(?:dr|prof|mr|mrs|ms|mme|mlle|m|herr|frau|dhr|mevr|sig|sra?)"
    r"\.?\s+$", re.IGNORECASE)


#: A BIC/SWIFT label touching the token: "BIC: ", "SWIFT-Code:\n", "Code SWIFT : ",
#: "BIC/SWIFT: ", "BIC Bank A: ", "(BIC ".
_BIC_LABEL_BEFORE = re.compile(
    r"(?<![A-Za-z])(?:bic|swift)(?:[\s/\-]*(?:code|swift|bic))?(?:\s+bank\s+\w{1,3})?"
    r"[\s:.\-()]*$", re.IGNORECASE)


def _bic_shaped_word(text: str, start: int, end: int, token: str) -> bool:
    """A registry miss sitting where only a word or a name can.

    Banking context alone admitted any word whose letters 5-6 are a country
    code -- about 100 per 968 banking documents (rules-engine#57). Most cannot
    be told from an unlisted bank code by shape, and the context gate exists for
    those codes, but three positions are never a bank code's:

    * joined to a word by a hyphen: "Dr. Joëlle NGUYEN-HOFFMANN" two lines under
      an IBAN, where masking HOFFMANN also broke the model's span for the name;
    * right after a personal title: "BIC: BCEELULL, Dr. HOFFMANN";
    * letters only -- eight, or eleven without the `XXX` branch -- which is the
      only shape a word can have: `BETALING`, `MAANDELIJKS`, `JANSSENS`. Unless
      the GLEIF mapping knows the institution (about 10,400 prefixes), such a
      code needs a BIC/SWIFT label touching it. A code with a digit, or with an `XXX` branch, is no word and keeps the
      context gate.
    """
    before = text[max(0, start - 2):start]
    after = text[end:end + 2]
    if (len(before) == 2 and before[1] == "-" and before[0].isalpha()) or (
            len(after) == 2 and after[0] == "-" and after[1].isalpha()):
        return True
    if _TITLE_BEFORE.search(text[max(0, start - 8):start]):
        return True
    return (token.isalpha() and not (len(token) == 11 and token.endswith("XXX"))
            and not is_known_institution(token)
            and not _BIC_LABEL_BEFORE.search(text[max(0, start - 30):start]))


def suppress_bic_without_evidence(text: str, match: RawMatch) -> bool:
    """Emit a BIC only on registry membership or banking context.

    BIC is the only bank identifier here with no check digit, so ISO 9362
    structure cannot carry the decision on its own — characters 5-6 of
    ordinary uppercase words are frequently valid country codes
    (``DRINGEND`` -> ``GE``, ``HOSPITAL`` -> ``IT``). Gates apply in order:

    0. the token also occurs as an ordinary lowercase word here -> reject;
    1. registry hit (deployment-supplied, then bundled seed prefixes) -> emit;
    2. heading / shouted-word shape -> reject;
    3. BIC-SWIFT keyword, IBAN or bank block in the structural unit -> emit,
       unless the token sits where only a word or a name can (see
       `_bic_shaped_word`);

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
        if _bic_shaped_word(text, match.start, match.end, token):
            return True
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
    #
    # Unless the label is a *postal* one. `_ID_CUE_BEFORE` matches any word
    # ending in "Nummer", "Nr", "Numero" or "Numéro" -- the wildcards are
    # `[\w\-]*` -- so it matches `postnummer`, `postnr` and `postinumero`,
    # which are the canonical postal labels of Norway, Denmark and Finland.
    # Those countries write a bare four- or five-digit code, so `isdigit()`
    # above lets the check run and the code was suppressed by its own label:
    # `postnummer: 5020 Bergen` produced nothing at all (rules-engine#41).
    #
    # Sweden escaped only because it spaces its code ("374 294"), which fails
    # the `isdigit()` guard, and Germany and Iceland because "Postleitzahl" and
    # "póstnúmer" do not end in any of those four words.
    #
    # A cue beginning "post" is a postal label, not a record-number label.
    before = text[max(0, match.start - 40):match.start]
    cue = _ID_CUE_BEFORE.search(before)
    if cue is not None and not _POSTAL_LABEL_CUE.match(cue.group(0).lstrip()):
        return True

    # Digits after an international dialling prefix belong to PHONE
    line_start, _ = _enclosing_line(text, match.start, match.end)
    if _DIALLING_PREFIX_BEFORE.search(text[line_start:match.start]):
        return True

    return False


#: A delimited data row: at least three fields separated by one delimiter.
#: Export formats carry their meaning in the column, not in a nearby word, so a
#: value that fills an entire field has structural context even when the line
#: contains no cue at all — which is why Icelandic phone numbers in
#: "name,dob,email,8773252,IS55..." rows were suppressed for lack of one.
_DELIMITED_ROW = re.compile(r"^[^\n]*?([,;|\t])[^\n]*?\1[^\n]*?\1", re.MULTILINE)


#: Types for which filling a delimited field counts as context. Narrow shapes
#: only — see suppress_requires_context.
_DELIMITED_FIELD_TYPES = frozenset({
    EntityType.PHONE, EntityType.DOB, EntityType.DATE_OF_DEATH,
})


def _fills_a_delimited_field(text: str, start: int, end: int) -> bool:
    """True when the span is exactly one field of a delimited row."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    if not _DELIMITED_ROW.match(line):
        return False
    before = text[line_start:start]
    after = text[end:line_end]
    opens = not before or before[-1] in ",;|\t"
    closes = not after or after[0] in ",;|\t"
    return opens and closes


def suppress_requires_context(text: str, match: RawMatch) -> bool:
    """Suppress patterns that require context keywords."""
    if not match.pattern_def.requires_context:
        return False
    if not match.pattern_def.context_keywords:
        return False
    # A value filling an entire field of a delimited row is introduced by its
    # column, not by a word, so that is context — but only for patterns narrow
    # enough to carry their own evidence.
    #
    # Applied to every type it was measured a net loss: SECRET gained 1,678
    # false positives, CHAMBER_OF_COMMERCE 456 and POSTAL_CODE 295, because a
    # broad shape plus a required cue is a deliberate pairing and removing the
    # cue leaves only the broad shape. The types below have shapes specific
    # enough that a whole field matching one is already strong evidence.
    if (match.pattern_def.entity_type in _DELIMITED_FIELD_TYPES
            and _fills_a_delimited_field(text, match.start, match.end)):
        return False
    if match.pattern_def.entity_type in _DATE_LABEL_TYPES:
        return not _labels_this_date(
            text, match.start, match.end, match.pattern_def.context_keywords,
            match.pattern_def.entity_type)
    before, after = _get_context(text, match.start, match.end)
    context = (before + " " + after).lower()
    return not any(kw.lower() in context for kw in match.pattern_def.context_keywords)


#: Date types decided by a label. DOB and DATE_OF_DEATH share one date shape,
#: so the label is the only thing that tells them apart -- and a date with
#: neither label (an admission date, an invoice date) is neither.
_DATE_LABEL_TYPES = frozenset({EntityType.DOB, EntityType.DATE_OF_DEATH})

#: Any common numeric date, to tell whether a label belongs to another date.
_ANY_DATE = re.compile(r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}")


def _labels_this_date(
    text: str, start: int, end: int, keywords: list[str], entity_type: object = None,
) -> bool:
    """True when one of *keywords* is this date's own label.

    Anywhere in the context window was the old test, and it typed every date in
    a document from whichever date label the document carried: with "Date of
    Death:" two lines down, "Date of Admission: 12/02/2024" became
    DATE_OF_DEATH, and with a birth date present the death date became DOB
    (rules-engine#52). A label belongs to the date it introduces, so it counts
    before the date only when no other date sits between them, and after the
    date only inside the date's own sentence ("03/05/1940 (date of birth)").

    A label on an earlier line counts only when the date opens its own line
    ("Date of birth:\n03/05/1940") or the label was asked as a question, which
    is how a call transcript carries it ("AGENT: … date of birth?\n\nCALLER:
    09/06/1987."); otherwise a table header two lines up would label every cell
    under it. A table's column header is the fallback for a
    date with no label of its own, and never overrules one: when it did,
    ordinary comma-separated prose read as a table row and
    "Geboortedatum en -plaats: 11/04/1989, Sint-Niklaas" lost its mask.
    """
    before, after = _get_context(text, start, end)
    lower_before, lower_after = before.lower(), after.lower()
    line_start = lower_before.rfind("\n") + 1
    opens_line = not lower_before[line_start:].strip(" \t:|;*-•([")
    # "°" is the birth sign in Belgian, Luxembourg and Dutch records:
    # "Wasserbillig °09.07.1968". Not "n°", the number sign.
    if entity_type == EntityType.DOB and _BIRTH_SIGN.search(lower_before):
        return True
    for keyword in keywords:
        kw = keyword.lower()
        i = lower_before.rfind(kw)
        if (i >= 0 and _nothing_but_a_list_between(lower_before[i + len(kw):])
                and (i >= line_start or opens_line
                     or "?" in lower_before[i + len(kw):line_start])):
            return True
        j = lower_after.find(kw)
        if j >= 0:
            gap = lower_after[:j]
            if (not _ANY_DATE.search(gap) and not _SENTENCE_BREAK.search(gap)
                    and not _LEADS_TO_A_DATE.match(lower_after[j + len(kw):])):
                return True
    header = _column_header(text, start)
    return header is not None and any(kw.lower() in header for kw in keywords)


#: A label followed by a list of dates labels each of them: "DOBs e.g.
#: 04/09/1978, 22/11/1985, 07/03/1990", "geboren op 14/05/1983 respectievelijk
#: 02/11/1990". A date followed by a list separator is a list item.
_LIST_ITEM = re.compile(
    r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}\s*"
    r"(?:,|;|–|&|\band\b|\ben\b|\bet\b|\bund\b|\bor\b|\bof\b|\bou\b|\boder\b"
    r"|\brespectievelijk\b|\bbzw\.?)\s*")

#: What may remain between a label and its date once list items are removed:
#: punctuation and at most two short words ("e.g.", "bv.", "op", "le").
_LABEL_TAIL = re.compile(
    r"[\s:.,()\-]*(?:[^\W\d_]{1,4}(?:\.[^\W\d_]{1,2})*\.?(?:[\s:.,()\-]+|\Z)){0,2}")


def _nothing_but_a_list_between(gap: str) -> bool:
    """No other date between a label and the date, except items of its list."""
    if not _ANY_DATE.search(gap):
        return True
    rest = _LIST_ITEM.sub(" ", gap)
    return not _ANY_DATE.search(rest) and _LABEL_TAIL.fullmatch(rest) is not None


#: The birth sign "°" directly before the date, but not the number sign "n°".
_BIRTH_SIGN = re.compile(r"(?<![a-z])°\s?$")


#: A label that runs straight into a date of its own -- punctuation, at most one
#: short word ("am", "le", "on"), then the date -- introduces that date, not the
#: one before it: in "Verstorben am 01.02.2020, geboren am 12.03.1940" the
#: "geboren" is the second date's. A verb-final clause ("am 12.03.1940 geboren
#: und ist am …") is not this shape and still labels the date before it.
_LEADS_TO_A_DATE = re.compile(
    r"[\s:.\-]*(?:[a-zà-ÿ]{1,3}[\s:.]+)?\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}")


#: Field separators a table row may use.
_COLUMN_SEPARATORS = ";|\t,"


def _column_header(text: str, start: int) -> str | None:
    """The lower-cased header cell above the value, if it sits in a table.

    Consulted only for a date with no label of its own. In a table the column
    supplies the label:
    "Name | Aufnahme | Sterbedatum" over "Müller | 12.02.2024 | 15.02.2024" has
    "Sterbedatum" before the admission date with no date between, and only the
    column says it labels the other one. A header is one of the three lines
    above, split by the row's separator into the same number of cells.
    """
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    line = text[line_start:line_end if line_end >= 0 else len(text)]
    # The three lines above, found by rfind: splitting the whole prefix made
    # this quadratic in the document, once per date candidate.
    above_start = line_start - 1
    for _ in range(3):
        if above_start < 0:
            break
        above_start = text.rfind("\n", 0, above_start)
    above = text[above_start + 1:max(0, line_start - 1)].split("\n") if line_start else []
    for sep in _COLUMN_SEPARATORS:
        if sep not in line:
            continue
        cells = line.split(sep)
        column = text[line_start:start].count(sep)
        for header in reversed(above):
            heads = header.split(sep)
            if len(heads) == len(cells) and not _ANY_DATE.search(header):
                return heads[column].lower()
    return None


# ── Dispatch table: entity type → applicable suppressors ────────────────
# This avoids calling 16 functions that each start with "if type != X: return False"

_UNIVERSAL = [suppress_sequential, suppress_redaction_placeholder]  # Applies to all types
_CONTEXT_ONLY = [suppress_requires_context]  # Always last

_TYPE_SUPPRESSORS: dict[EntityType, list[Callable[..., bool]]] = {
    EntityType.PHONE: [
        suppress_currency, suppress_units, suppress_reference, suppress_math,
        suppress_phone_service_number, suppress_phone_inside_account_run,
        suppress_phone_date_overlap, suppress_phone_as_number_range,
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
        suppress_taxid_as_ip_address,
    ],
    EntityType.POSTAL_CODE: [
        suppress_currency, suppress_units, suppress_math, suppress_legal,
        suppress_year_as_postal, suppress_postal_after_disqualifying_word,
        suppress_postal_inside_iban,
        suppress_postal_as_house_number, suppress_postal_in_longer_identifier,
        suppress_reference,
    ],
    EntityType.BIC: [suppress_bic_without_evidence],
    EntityType.IBAN: [suppress_reference],
    EntityType.LICENSE_PLATE: [
        suppress_plate_in_compound, suppress_de_plate_unknown_district,
        suppress_plate_as_currency_amount,
    ],
    EntityType.SECRET: [
        suppress_secret_over_structured, suppress_secret_not_a_secret,
    ],
    EntityType.CHAMBER_OF_COMMERCE: [suppress_reference],
}


# ── Span-pure vs claim-sensitive ────────────────────────────────────────
#
# Most suppressors read only the document and the matched span: same span, same
# entity type, same answer — regardless of which country's pattern produced the
# match. Those results can be reused across the many patterns that claim the
# same span (measured: 48.3 surviving matches collapse to 15.0 distinct
# (span, type) pairs, and 6.2x for POSTAL_CODE alone).
#
# These three are the exceptions, because they read the *claim* rather than the
# span. They must run per match and must never be memoised on span alone.
_CLAIM_SENSITIVE: frozenset[Callable[..., bool]] = frozenset({
    suppress_de_plate_unknown_district,  # reads match.country_code
    suppress_se_natid_as_org,            # reads match.country_code
    suppress_requires_context,           # reads requires_context / context_keywords
})

# Derived from _TYPE_SUPPRESSORS rather than restated, so a suppressor added to
# the table above cannot be forgotten here.
_SPAN_SUPPRESSORS: dict[EntityType, list[Callable[..., bool]]] = {
    etype: [s for s in sups if s not in _CLAIM_SENSITIVE]
    for etype, sups in _TYPE_SUPPRESSORS.items()
}
_CLAIM_SUPPRESSORS: dict[EntityType, list[Callable[..., bool]]] = {
    etype: [s for s in sups if s in _CLAIM_SENSITIVE]
    for etype, sups in _TYPE_SUPPRESSORS.items()
}


def should_suppress_span(text: str, match: RawMatch) -> bool:
    """Suppressors whose answer depends only on the document and the span.

    The result is a pure function of ``(entity_type, start, end)`` for a given
    document, so callers may cache it across matches sharing a span.
    """
    for s in _UNIVERSAL:
        if s(text, match):
            return True
    for s in _SPAN_SUPPRESSORS.get(match.pattern_def.entity_type, ()):
        if s(text, match):
            return True
    return False


def should_suppress_claim(text: str, match: RawMatch) -> bool:
    """Suppressors that read the claim — its country, or its context keywords."""
    for s in _CLAIM_SUPPRESSORS.get(match.pattern_def.entity_type, ()):
        if s(text, match):
            return True
    if match.pattern_def.requires_context:
        return suppress_requires_context(text, match)
    return False


def should_suppress(text: str, match: RawMatch) -> bool:
    """Run applicable suppression filters. Returns True if match should be discarded."""
    return should_suppress_span(text, match) or should_suppress_claim(text, match)
