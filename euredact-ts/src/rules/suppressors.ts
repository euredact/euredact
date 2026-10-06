import { EntityType, type PatternDef } from "../types.js";
import { isKnownInstitution, isRegisteredBic } from "./bicRegistry.js";
import { DE_DISTRICT_CODES } from "./deDistricts.js";

const CONTEXT_CHARS = 150;

export interface RawMatch {
  start: number;
  end: number;
  text: string;
  patternDef: PatternDef;
  countryCode: string;
}

function getContext(text: string, start: number, end: number): [string, string] {
  const ctxStart = Math.max(0, start - CONTEXT_CHARS);
  const ctxEnd = Math.min(text.length, end + CONTEXT_CHARS);
  return [text.slice(ctxStart, start), text.slice(end, ctxEnd)];
}

// Unicode-safe word boundary: negative lookahead for any letter (including accented)
const _UWB = "(?![a-zA-Z\\u00C0-\\u024F\\u0400-\\u04FF])";
// Symbols are held apart from the alphabetic codes because a word boundary
// after "€" is meaningless — the symbol is not a word character. Python used a
// bare "\b" here and so could never match "1163 €," at all; this port used the
// lookahead below and did not have that defect. Kept split so the difference
// cannot come back.
const CURRENCY_SYMBOL = "€|\\$|£|¥|₺|zł|Kč|лв|kn|Ft|₽";
const CURRENCY_WORD =
  "EUR|USD|GBP|CHF|ISK|SEK|NOK|DKK|PLN|CZK|HUF|RON|BGN|HRK|" +
  "euro|euros|dollar|dollars|pond|kronor|kroner|kronur|kr|" +
  "złoty|korun|forint|lei|leva";
const CURRENCY_AFTER = new RegExp(`^\\s*(?:(?:${CURRENCY_SYMBOL})|(?:${CURRENCY_WORD})${_UWB})`, "i");
const CURRENCY_COMMA_AFTER = new RegExp(`^[.,]\\d{1,2}\\s*(?:(?:${CURRENCY_SYMBOL})|(?:${CURRENCY_WORD})${_UWB})`, "i");
const CURRENCY_BEFORE = new RegExp(`(?:(?:${CURRENCY_SYMBOL})|\\b(?:${CURRENCY_WORD}))\\s*$`, "i");
const AMOUNT_LABEL_BEFORE =
  /\b(?:Montant|Beløb|Summa|Summe|Bedrag|Amount|Total|TTC|inkl|Upphæð|Importe|Importo|Valore|Wartość|Kwota|Částka|Összeg|Sum|Beloop|Prix|Preis|Price|Loyer|Miete|Huur|Rent|Betrag)\s*(?:\w+\s*)?:?\s*$/i;

// Use Unicode-aware word boundary via \p{L} negative lookahead instead of \b
// because JS \b is ASCII-only and fails on Unicode letters (e.g. "München" → \bm\b matches M before ü)
// Horizontal space only: a unit is on the number's own line (rules-engine#51).
const UNIT_AFTER = /^[ \t]*(?:kg|km|cm|mm|m[²³]|ml|mg|GB|MB|KB|TB|%|jaar|maanden|weken|dagen|uur|minuten|seconden|stuks|pcs|pieces|ans|mois|semaines|jours|heures|Jahre|Monate|Wochen|Tage|Stunden)(?![a-zA-Z\u00C0-\u024F\u0400-\u04FF])/i;

// Same missing-boundary flaw: "ref" matched the tail of "kortref".
const REFERENCE_BEFORE = /\b(?:dossier|ref\.?|referentie|reference|référence|factuurnummer|invoice\s*(?:nr|number|no)?|bestelnummer|order\s*(?:nr|number|no)?|kenmerk|ordernummer|Aktenzeichen|numéro\s*de\s*(?:dossier|facture|commande)|bestellnummer|Rechnungsnummer|artikelnr|article\s*no|contract\s*(?:nr|number|no)?|pagina|page|Seite|blz\.?|Facture\s*n[°o]?|Faktura\s*n[°or]\.?|Lasku\s*n[°or]o?\.?|Rechnung\s*(?:Nr|n[°o])?|faktura\s*(?:nr|n[°o])?|bestilling\s*(?:nr|n[°o])?|bestelling\s*n[°or]\.?|Reikningur\s*nr|ticket|incident\s*(?:report|nr|no)?|case\s*(?:nr|no|id)?|zaaknummer|meldingsnummer|Vorgangsnummer|Vorgang|Störungsmeldung|saksnummer|ärendenummer|sagsnummer|asianumero|Factuur\s*n[ro]?\.?|Nota\s*n[ro]?\.?)\s*[:.#]?\s*$/i;

// "#" before a number marks a reference in every language in scope — a ticket,
// an order, a line item — and never a postcode or a national identifier.
const HASH_BEFORE = /#\s*$/;

// A short uppercase tag hyphenated to the number: "IR-43433", "INC-2024".
const REF_PREFIX_BEFORE = /(?:^|[\s([])[A-Z]{2,5}-$/;

// The cross-border address form, "CH-8004 Zürich": a country code hyphenated to
// a postal code, told apart from a reference tag by position -- it opens an
// address line and a place name follows (rules-engine#58).
const COUNTRY_PREFIX_OPENS_LINE = /(?:^|\n|,)[ \t]*([A-Z]{2})-$/;
const POSTAL_PREFIX_COUNTRIES = new Set([
  "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI",
  "FR", "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV",
  "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "UK",
]);

const LEGAL_BEFORE = /(?:Art(?:ikel|icle|\.)|§|Artikel|Section|Sectie|Afdeling|paragraaf|Absatz|alinéa|punt|point|Punkt|lid)\s*$/i;

const MATH_BEFORE = /[=+\-×÷*/]\s*$/;
const MATH_AFTER = /^\s*[=+\-×÷*/]/;

// "A-1010", "B-2000", "L-1234", "CH-8000", "D-10115": a country prefix on a
// postal code, not a minus sign.
const COUNTRY_PREFIX_HYPHEN = /(?:^|[^A-Za-z0-9])[A-Z]{1,2}-\s*$/;

const SEQUENTIAL_PATTERNS = /^(?:0{6,}|1234567890?|0123456789|9876543210?|1111111111?|000000000|123456789)$/;

// YEAR_PATTERN kept for reference but replaced by RECENT_YEAR in suppressYearAsPostal

// `ID_LABEL_BEFORE` and `suppressPhoneAfterIdLabel` lived here. Their labels are
// now typed entries in `cues.ts`, and a phone-shaped span behind one is
// *relabelled* rather than dropped.
//
// Dropping was the wrong verb. The span is found either way, so removing the
// claim decided only whether the value was masked — and the answer was "no":
// "Rijksregisternummer: 85.03.19-284.73" produced no detection at all, a
// redaction library printing in full an identifier it had recognised and
// rejected. The 653-miss word-boundary lesson recorded here moved with the
// labels; see the module comment in `cues.ts`.

const SERVICE_NUMBER = /^0800[\-\s]/;
const DATE_PATTERN_FULL = /^\d{2}[-/.]\d{2}[-/.]\d{4}$|^\d{4}[-/.]\d{2}[-/.]\d{2}$/;

const PASSPORT_CONTEXT_BEFORE = /(?:Reisepass|passport|passeport|paspoort|Bisheriger\s+Reisepass)\s*(?:Nr\.?|Nummer|nummer|number|n[°o])?\s*[:.]?\s*$/i;
const SE_ORG_CONTEXT_BEFORE = /(?:org\.?\s*nr\.?|organisationsnummer|organisationsnr|Bolagsverket|företag)\s*[:.]?\s*$/i;

const NUMERIC_TYPES = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.POSTAL_CODE]);

// ── Date adjacency, for the postal-code year gate ───────────────────────
//
// Month names in the languages this engine covers. Long, but it is data: the
// alternative is a proximity heuristic, and proximity is what caused the defect
// this guards against. Kept in sync with the Python SDK's suppressors.py.
const MONTH_NAMES =
  "january|february|march|april|may|june|july|august|september|october|november|december" +
  "|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec" +
  "|januar|jänner|februar|märz|mai|juni|juli|oktober|dezember|dez|okt|mrz" +
  "|janvier|février|mars|avril|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre" +
  "|januari|februari|maart|mei|augustus|mrt" +
  "|gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|dicembre" +
  "|enero|febrero|abril|mayo|junio|julio|septiembre|octubre|noviembre|diciembre" +
  "|janeiro|fevereiro|março|marco|maio|junho|julho|setembro|outubro|novembro|dezembro" +
  // "desember" (nb/nn/is) was the one December spelling missing from a list
  // that already carried ten others — "1. desember 2025" was a Norwegian
  // postcode because of it.
  "|marts|augusti|desember" +
  "|janúar|febrúar|apríl|maí|júní|júlí|ágúst|nóvember" +
  "|tammikuu|helmikuu|maaliskuu|huhtikuu|toukokuu|kesäkuu|heinäkuu|elokuu|syyskuu|lokakuu|marraskuu|joulukuu" +
  "|jaanuar|veebruar|aprill|juuni|juuli|oktoober|detsember" +
  "|janvāris|februāris|aprīlis|maijs|jūnijs|jūlijs|augusts|septembris|oktobris|novembris|decembris" +
  "|stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|września|października|listopada|grudnia" +
  "|ledna|února|března|dubna|května|června|července|srpna|září|října|listopadu|prosince" +
  "|marec|junij|julij|avgust|siječnja|veljače|ožujka|travnja|svibnja|lipnja|srpnja|kolovoza|rujna|studenoga|prosinca" +
  "|március|április|május|június|július|augusztus|szeptember|október" +
  "|ianuarie|februarie|martie|aprilie|iunie|iulie|septembrie|octombrie|noiembrie|decembrie" +
  "|ιανουαρίου|φεβρουαρίου|μαρτίου|απριλίου|μαΐου|ιουνίου|ιουλίου|αυγούστου|σεπτεμβρίου|οκτωβρίου|νοεμβρίου|δεκεμβρίου" +
  "|януари|февруари|март|април|май|юни|юли|август|септември|октомври|ноември|декември";

/** "since" cues, which introduce a bare year in every one of these languages. */
const SINCE_CUES =
  "seit|since|depuis|sinds|sedert|vanaf|desde|dal|od|sedan|siden|alates|alkaen|από|от|din|iz|ab";

/**
 * A month name, a "since" cue, or a numeric date tail immediately before the
 * candidate. Adjacent-only on purpose — a cue 150 characters away is what made
 * this a bug in the first place.
 */
const DATE_BEFORE = new RegExp(
  `(?:\\b(?:${MONTH_NAMES})\\b\\.?|\\b(?:${SINCE_CUES})\\b|\\d{1,2}[./-]\\d{1,2}[./-])\\s*$`,
  "iu",
);

/** A date separator immediately after, making the candidate a leading year. */
const DATE_AFTER = /^[./-]\d{1,2}[./-]\d{1,2}\b/;

/**
 * ISO 4217 codes made only of the consonants a Spanish plate accepts, so a money
 * amount reads as a registration. This is why "2297 DKK" was a plate.
 */
// Crypto tickers are the same shape and the same mistake — every surviving
// plate false positive was "4499 BTC" or a sibling. A ticker is a unit, exactly
// as an ISO 4217 code is.
const CURRENCY_CODE =
  "(?:DKK|SEK|NOK|ISK|CZK|PLN|HUF|RON|BGN|HRK|CHF|GBP|TRY|RSD|MKD|BYN|KZT|CNY|JPY|KRW|ZAR|BRL|MXN|CLP|COP|PLZ|SKK|TRL" +
  "|BTC|ETH|LTC|XRP|BCH|XLM|XMR|DOT|SOL|ADA|TRX|DOGE|USDT|USDC)";
const CURRENCY_CODE_TAIL = new RegExp(`\\s${CURRENCY_CODE}$`);
const CURRENCY_CODE_AFTER = new RegExp(`^\\s*${CURRENCY_CODE}\\b`);

/** Log-timestamp tails, which the ":"-anchored secret rule picks up. */
const TIMESTAMP_FRAGMENT = /^\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,6})?Z?$/;

/** Cloud region names and similar well-known configuration values. */
const NOT_A_SECRET = new RegExp(
  "^(?:af|ap|ca|cn|eu|il|me|sa|us|gov)-(?:north|south|east|west|central" +
  "|northeast|northwest|southeast|southwest)-\\d[a-z]?$" +
  "|^(?:application|text|image|audio|video|multipart)/[\\w.+-]+$" +
  "|^(?:utf|iso|windows)-[\\d-]+$" +
  "|^(?:no-cache|no-store|max-age|gzip|deflate|identity|chunked)\\b",
  "i",
);

const EXACT_UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const BIC_SHAPE = /^[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?$/;
const BIC_CUE_BEFORE = /(?:BIC|SWIFT|BIC\/SWIFT)\s*[:=]?\s*\(?\s*$/i;

/** An email address, exactly. Same argument as the UUID and the BIC. */
const EXACT_EMAIL = /^[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+$/;

/**
 * A URL, or the tail of one after the scheme has been split off. The secret
 * rules anchor on ":" and "=", so "https://api.sendgrid.com/v3/mail/send" hands
 * them "//api.sendgrid.com/v3/mail/send" and a slash-separated path scores as
 * high-entropy. An endpoint is published documentation, not a credential.
 */
const URL_LIKE =
  /^(?:[a-z][a-z0-9+.-]*:)?\/\/[^\s/]+(?:\/\S*)?$|^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d{1,5})?(?:\/\S*)?$/i;

/**
 * A URL that *carries* a credential is the opposite case, and it is the common
 * one: "mongodb://admin:DFKDKi1eb51OOhuHPYz@rds-main.eu-west-1.rds.amazonaws.com"
 * is a connection string with a live password in it. Suppressing those as "just
 * a URL" lost 347 real secrets, so the endpoint test must not fire when userinfo
 * or a credential-bearing query parameter is present.
 */
const URL_WITH_CREDENTIALS =
  /^(?:[a-z][a-z0-9+.-]*:)?\/\/[^/@\s]*:[^/@\s]*@|[?&](?:api_?key|access_?token|auth|token|secret|password|pwd|sig|signature|credential)=/i;

/** An LDAP distinguished name: "cn=github-actions,dc=corp,dc=eu". */
const LDAP_DN = /^(?:cn|ou|dc|uid|o|l|st|c)=[^,=]+(?:,\s*(?:cn|ou|dc|uid|o|l|st|c)=[^,=]+)+$/i;

/**
 * Lower-case words joined by hyphens, optionally with a short id suffix:
 * "service-account", "data-lake-33e061". The single-word test below already
 * rejects "sozialversicherungsnummer" on the reasoning that a real secret would
 * be mixed case; a hyphenated compound is the same token with a separator.
 */
const HYPHENATED_WORDS = /^[a-z]{2,}(?:-[a-z]{2,})+(?:-[0-9a-f]{4,8})?$/;

/** A dotted quad with every octet in range. */
const DOTTED_QUAD =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Two plausible years joined by a hyphen — a school year, a contract term. */
const YEAR_RANGE = /^(19|20)\d{2}\s?[-–/]\s?(19|20)\d{2}$/;

/** A digit and a decimal point immediately before, so the match is a fraction. */
const DECIMAL_TAIL_BEFORE = /\d[.,]$/;

/**
 * Punctuation the greedy "[^\s]{8,}" secret rule sweeps up with the token: it
 * matched "TRIONL2U)." out of "(BIC: TRIONL2U).". Stripped only for the shape
 * tests — the emitted span is never altered here.
 */
const PUNCT_EDGES = /^[\s([{<"'`]+|[\s)\]}>"'`.,;:!?]+$/g;

function coreToken(raw: string): string {
  return raw.replace(PUNCT_EDGES, "").replace(PUNCT_EDGES, "");
}

/**
 * A generic secret must not claim a span that is a specific known type.
 *
 * The high-entropy rules are deliberately broad and they carry a validator, so
 * they reach the top priority tier while the structured detector for the same
 * characters sits at the bottom with nothing to offer. Measured on 152,300
 * documents: 687 UUIDs and 140 BICs were reported as SECRET, each counted twice
 * over — a false positive for SECRET and a miss for the type that should have
 * had it.
 */
function suppressSecretOverStructured(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.SECRET) return false;
  const token = coreToken(match.text);
  if (EXACT_UUID.test(token) || EXACT_EMAIL.test(token)) return true;
  if (BIC_SHAPE.test(token)) {
    return BIC_CUE_BEFORE.test(text.slice(Math.max(0, match.start - 24), match.start));
  }
  return false;
}

/**
 * Reject the three things the ":"-anchored secret rule reliably mistakes:
 * timestamps ("57:22.283Z]"), ordinary words ("Sozialversicherungsnummer") and
 * region names ("us-east-1"). All three sit after a colon or equals sign, which
 * is all that rule asks for, and all three clear the entropy threshold.
 *
 * The word test is narrow on purpose: purely alphabetic *and* shaped like one
 * natural word. A random all-letter token would be mixed case and is left alone
 * — losing a real secret is the expensive direction.
 */
function suppressSecretNotASecret(_text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.SECRET) return false;
  const bare = coreToken(match.text);
  if (TIMESTAMP_FRAGMENT.test(bare)) return true;
  if (NOT_A_SECRET.test(bare)) return true;
  if (URL_LIKE.test(bare) && !URL_WITH_CREDENTIALS.test(bare)) return true;
  if (LDAP_DN.test(bare)) return true;
  if (HYPHENATED_WORDS.test(bare)) return true;
  const alpha = /^[A-Za-zÀ-ÿ]+$/.test(bare);
  const oneWord =
    bare === bare.toLowerCase() ||
    (bare.slice(0, 1) === bare.slice(0, 1).toUpperCase() &&
      bare.slice(1) === bare.slice(1).toLowerCase());
  return alpha && oneWord;
}

/**
 * A money amount followed by its ISO 4217 code is not a registration. Spain's
 * plate shape is four digits then three consonants, and the Nordic and Central
 * European currency codes are all consonants: "2297 DKK" read as a Spanish plate
 * 487 times across the corpus.
 */
function suppressPlateAsCurrencyAmount(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.LICENSE_PLATE) return false;
  if (CURRENCY_CODE_TAIL.test(match.text)) return true;
  return CURRENCY_CODE_AFTER.test(text.slice(match.end, match.end + 12));
}

/**
 * A dotted quad is an address, not a tax number. Germany's tax-number shape
 * allows dots between its digit groups, which makes it a superset of IPv4. The
 * address is still redacted — the IP_ADDRESS rule claims the same span — so this
 * only corrects the label.
 */
function suppressTaxidAsIpAddress(_text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.TAX_ID) return false;
  return DOTTED_QUAD.test(match.text.trim());
}

/**
 * Reject two phone shapes that are arithmetic rather than contact details: a
 * year range ("Schooljaar 2025-2026") and the fractional part of a decimal
 * amount ("0.034865 BTC"). Both clear every phone pattern's shape test.
 */
function suppressPhoneAsNumberRange(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.PHONE) return false;
  if (YEAR_RANGE.test(match.text.trim())) return true;
  return DECIMAL_TAIL_BEFORE.test(text.slice(Math.max(0, match.start - 2), match.start));
}

function suppressCurrency(text: string, match: RawMatch): boolean {
  if (!NUMERIC_TYPES.has(match.patternDef.entityType)) return false;
  const [before, after] = getContext(text, match.start, match.end);
  if (CURRENCY_AFTER.test(after) || CURRENCY_BEFORE.test(before)) return true;
  if (CURRENCY_COMMA_AFTER.test(after)) return true;
  if (AMOUNT_LABEL_BEFORE.test(before)) return true;
  return false;
}

function suppressUnits(text: string, match: RawMatch): boolean {
  if (!NUMERIC_TYPES.has(match.patternDef.entityType)) return false;
  const [, after] = getContext(text, match.start, match.end);
  return UNIT_AFTER.test(after);
}

/**
 * Suppress numbers preceded by reference/invoice/dossier keywords.
 *
 * POSTAL_CODE belongs here for the same reason every other numeric type does,
 * and its absence was an oversight: a five-digit ticket number sits in exactly
 * the shape a German or French postcode occupies, so "Ticket #94730" and
 * "Incident report IR-43433" were masked as addresses.
 *
 * "#" and "XX-" are checked adjacently rather than through the 150-character
 * keyword window. That window is what made the postal rule claim years in
 * dates; widening its reach to fix a different symptom would repeat the error.
 */
// Hoisted out of the suppressor bodies: rebuilding these per candidate cost
// ~260k Set allocations per 1 MB document, and GC was 10.7% of the profile.
const REFERENCE_TYPES = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE, EntityType.POSTAL_CODE]);
const LEGAL_TYPES = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.POSTAL_CODE]);

function suppressReference(text: string, match: RawMatch): boolean {
  const applicable = REFERENCE_TYPES;
  if (!applicable.has(match.patternDef.entityType)) return false;
  const [before] = getContext(text, match.start, match.end);
  if (REFERENCE_BEFORE.test(before)) return true;
  const adjacent = text.slice(Math.max(0, match.start - 8), match.start);
  if (HASH_BEFORE.test(adjacent)) return true;
  if (!REF_PREFIX_BEFORE.test(adjacent)) return false;
  return !(
    match.patternDef.entityType === EntityType.POSTAL_CODE &&
    isCountryPrefixedAddress(text, match.start, match.end)
  );
}

/** "CH-8004 Zürich" on an address line, not the reference "IT-20431". */
function isCountryPrefixedAddress(text: string, start: number, end: number): boolean {
  const found = COUNTRY_PREFIX_OPENS_LINE.exec(text.slice(Math.max(0, start - 12), start));
  return (
    found !== null &&
    POSTAL_PREFIX_COUNTRIES.has(found[1]) &&
    CITY_AFTER.test(text.slice(end, end + 24))
  );
}

function suppressLegal(text: string, match: RawMatch): boolean {
  const applicable = LEGAL_TYPES;
  if (!applicable.has(match.patternDef.entityType)) return false;
  const [before] = getContext(text, match.start, match.end);
  return LEGAL_BEFORE.test(before);
}

function suppressMath(text: string, match: RawMatch): boolean {
  if (!NUMERIC_TYPES.has(match.patternDef.entityType)) return false;
  const [before, after] = getContext(text, match.start, match.end);
  // A country-prefixed postal code is an address, not a subtraction:
  // "A-1010 Wien", "B-2000 Antwerpen", "D-10115 Berlin".
  if (match.patternDef.entityType === EntityType.POSTAL_CODE && COUNTRY_PREFIX_HYPHEN.test(before)) {
    return false;
  }
  return MATH_BEFORE.test(before) || MATH_AFTER.test(after);
}

function suppressSequential(_text: string, match: RawMatch): boolean {
  const clean = match.text.replace(/[\s.\-]/g, "");
  return SEQUENTIAL_PATTERNS.test(clean);
}

// ── The engine's own output ───────────────────────────────────────────────
//
// Redaction has to be idempotent: running it over a document it already
// produced must leave the placeholders it wrote alone. It did not.
// `[POSTAL_CODE]` is thirteen characters of mixed case with an underscore, so
// the entropy-based SECRET rule read it as a credential and a second pass
// replaced it with `[SECRET]` (rules-engine#33).
//
// All three emitted forms are guarded, because all three come back as input in
// a re-processing pipeline: `[TYPE]`, `TYPE_1` (referentialIntegrity) and
// `TYPE_K7Q2` (tokenize -- where a false detection breaks restore()).
//
// Only real entity-type names count. Guarding any bracketed upper-case token
// would be simpler and wrong: `[AKIAIOSFODNN7EXAMPLE]` is one, and also a live
// AWS key. A placeholder for a *custom* pattern is therefore not covered.
// The closing bracket is optional: another pattern's span need not agree with
// this one about where the marker ends. The assigned-secret rule stops before
// sentence punctuation (rules-engine#35), so it claims "[POSTAL_CODE" without
// the "]". The opening bracket is still required.
const PLACEHOLDER = /^(?:\[([A-Z][A-Z0-9_]*)\]?|([A-Z][A-Z0-9_]*?)_(?:\d+|[A-HJ-NP-Z2-9]{4}))$/;

const KNOWN_TYPE_NAMES: ReadonlySet<string> = new Set(Object.values(EntityType));

function suppressRedactionPlaceholder(_text: string, match: RawMatch): boolean {
  const found = PLACEHOLDER.exec(match.text);
  if (found === null) return false;
  const name = found[1] ?? found[2];
  return KNOWN_TYPE_NAMES.has(name);
}

const RECENT_YEAR = /^(?:19[5-9]\d|20[0-3]\d)$/;
const POSTAL_CONTEXT_NEAR = /(?:postcode|postal|code\s*postal|PLZ|Postleitzahl|postnummer|postinumero|póstnúmer|zip|straat|straße|strasse|rue\s|via\s|calle\s|rua\s|ulica|utca|street|avenue|laan\s|weg\s|plein|adres|adresse|address|woonplaats|wonende|woonachtig|gevestigd|domicili|demeurant|résidant|residant|bosatt|bopæl|wohnhaft|ansässig|stad\b|ville\b|city\b|Stadt|città|ciudad|cidade|miasto|město|város)/i;
const DATE_KEYWORD_NEAR = /(?:født|fødselsdato|fødsel|Fødselsdato|född|födelsedatum|födelsedag|syntynyt|syntymäaika|fæddur|fæðingardagur|geboren|geboortedatum|Geburtsdatum|nascido|nacido|data di nascita|nato il|nata il|Tiltr[æa]delsesdato|Tiltredelsesdato|datum|date\b|Datum|jaar|year|année|Jahr|since|sinds|depuis|seit|\d{2}\.\d{2}\.|(?:januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december|januari|februari|mars|mei|juin|juillet|août))/i;

// A sentence boundary: a full stop, question or exclamation mark followed by
// space, or a line break. Written so it cannot fire inside "11.03.1970", where
// the periods are not followed by whitespace -- that date is one of the false
// positives this gate has to reject.
const SENTENCE_BREAK = /[.!?][ \t\n]|\n/;
const SENTENCE_BREAK_G = /[.!?][ \t\n]|\n/g;

// The value's own sentence, bounded either side.
function sentenceAround(text: string, start: number, end: number, reach = 160): string {
  let before = text.slice(Math.max(0, start - reach), start);
  let after = text.slice(end, end + reach);
  let lastEnd = -1;
  SENTENCE_BREAK_G.lastIndex = 0;
  for (let m = SENTENCE_BREAK_G.exec(before); m !== null; m = SENTENCE_BREAK_G.exec(before)) {
    lastEnd = m.index + m[0].length;
  }
  if (lastEnd >= 0) before = before.slice(lastEnd);
  const found = SENTENCE_BREAK.exec(after);
  if (found !== null) after = after.slice(0, found.index);
  return before + after;
}

// A postal label whose only distance from the value is punctuation:
// "PLZ: 2011", "code postal : 2011", "Woonplaats: 1950".
const POSTAL_LABEL_TOUCHING = new RegExp(
  `(?:${POSTAL_CONTEXT_NEAR.source})[\\s:.\\-]{0,4}$`, "i");

// A capitalised place name after the code: "2000 Antwerpen". A following label
// ("1970 Fødselsnummer:") is excluded by the colon.
// `\p{L}\p{N}_` rather than `\w`: JS `\w` is ASCII-only, so "8004 Zürich" failed
// at the ü here while Python's Unicode `\w` accepted it (rules-engine#58).
const CITY_AFTER = /^[ \t](?![\p{L}\p{N}_]+\s*:)[A-ZÀ-ÞŁŠŽ][\p{L}\p{N}_\-']{2,}/u;

// Every position is local to the value or inside its own sentence. Proximity to
// an address *word* anywhere in a 300-character window is what the old rescue
// asked, and that is a neighbourhood rather than a position (rules-engine#32).
function yearSitsInAddressStructure(text: string, start: number, end: number): boolean {
  const before = text.slice(Math.max(0, start - 28), start);
  // "Amsterdam, 2026" -- the comma of an address line.
  if (/,[ \t]*$/.test(before)) return true;
  // "PLZ: 2011" -- a postal label with nothing but punctuation between.
  if (POSTAL_LABEL_TOUCHING.test(before)) return true;
  // A capitalised place name immediately after.
  if (CITY_AFTER.test(text.slice(end, end + 24))) return true;
  // An address word in the value's own sentence. "Te huur: Lange Nieuwstraat
  // 12, rustige ligging in 2018, vlakbij openbaar vervoer." is an Antwerp
  // postal code in prose; the false positives put the year and the address in
  // different sentences.
  return POSTAL_CONTEXT_NEAR.test(sentenceAround(text, start, end));
}

function suppressYearAsPostal(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const clean = match.text.trim();
  if (!RECENT_YEAR.test(clean)) return false;
  // A date construction *touching* the candidate settles it, whatever the rest
  // of the document says. Without this, the postal-context test below rescued
  // every year in every document with an address in it — and "Adresse", "rue"
  // and "Str." appear in the header of essentially every business letter.
  // Measured: 1,691 of 3,322 postal false positives were plausible years,
  // 1,636 of them literally "2025".
  if (DATE_BEFORE.test(text.slice(Math.max(0, match.start - 24), match.start))) return true;
  if (DATE_AFTER.test(text.slice(match.end, match.end + 8))) return true;

  const [before, after] = getContext(text, match.start, match.end);
  const context = before + after;
  // Keep as postal code only when the value sits in address *structure* --
  // see yearSitsInAddressStructure for why a 300-character window of address
  // words was the defect rather than the keyword list.
  if (yearSitsInAddressStructure(text, match.start, match.end)) return false;
  // Keep if preceded by comma+space (address pattern: "Amsterdam, 2026")
  const immediateBefore = text.slice(Math.max(0, match.start - 3), match.start);
  if (/,\s*$/.test(immediateBefore)) return false;
  // Suppress if date keyword nearby (birth date, employment date, etc.)
  if (DATE_KEYWORD_NEAR.test(context)) return true;
  // Suppress: recent years without postal context are almost never postal codes
  return true;
}

// ── Postal code: disqualified by the word in front of it ───────────────
//
// The mirror image of `rules/cues.ts`. There a label promotes a type; here a
// word refuses one. Both were reported together: a bare four-digit run becomes
// a POSTAL_CODE as soon as *any* real postal code establishes the country,
// which is to say in almost every real document, because POSTAL_CONTEXT_NEAR
// above then rescues it from suppressYearAsPostal. Measured on the training
// corpus: 55 bare years in prose ("Opgericht in 2016", "Fondée en 2017") plus
// telephone extensions ("(toest. 3841)", "(poste interne 3318)", "(ext. 2219)").

/**
 * Prepositions that can only be temporal. Nothing is ever located "since 2018",
 * so these disqualify a postal code on their own.
 */
const YEAR_WORD_BEFORE =
  /(?<![A-Za-z0-9_])(?:sinds|since|depuis|seit|siden|sedan|desde|vuonna|anno|dal)\s+$/i;

/**
 * "in", "en" and "im" are *both* temporal and locative, and in exactly the
 * countries whose postal codes are year-shaped. Belgian 2000 is Antwerp and
 * 2018 is one of its districts, so "Rustige ligging in 2018, vlakbij openbaar
 * vervoer" is an address, not a date — an earlier version of this rule
 * suppressed it and lost a real postal code, which is the worse error for a
 * redaction tool. So an ambiguous preposition needs a founding or payment
 * participle in front of it, which is what every case in the report had:
 * "Opgericht in 2016", "Fondée en 2017", "versé en 2025".
 */
const YEAR_VERB_BEFORE =
  /(?<![A-Za-z0-9_])(?:opgericht|gesticht|opgestart|founded|established|created|fond[ée]e?|cr[ée][ée]e?|gegründet|gegruendet|errichtet|grundlagt|grundad|perustettu|fundada|fundado|fondata|costituita|vers[ée]|betaald|uitbetaald|ausgezahlt|paid|geboren|born)\s+(?:in|en|im|op|the)\s+$/i;

/**
 * A capitalised word immediately after keeps the candidate: "in 2000 Antwerpen"
 * really is a postal code, and so is the "AZ" of a Dutch "1105 AZ". Without
 * this the rule would suppress the very addresses it is meant to leave alone.
 */
const TOWN_AFTER = /^\s*[A-ZÀ-ÞĀ-Ž]/;

/**
 * A telephone extension marker. "poste interne 3318" puts one qualifier word
 * between the marker and the number, so allow exactly one.
 */
const EXTENSION_BEFORE =
  /(?<![A-Za-z0-9_])(?:toest(?:el)?|ext|extension|poste|durchwahl|doorkiesnummer|tst|nebenstelle)\.?\s*(?:[a-zà-ÿ]{2,10}\s*)?[:.]?\s*$/i;

/** Suppress a postal code the word in front of it rules out. */
function suppressPostalAfterDisqualifyingWord(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const before = text.slice(Math.max(0, match.start - 24), match.start);
  if (EXTENSION_BEFORE.test(before)) return true;
  return RECENT_YEAR.test(match.text.trim())
    && (YEAR_WORD_BEFORE.test(before) || YEAR_VERB_BEFORE.test(before))
    && !TOWN_AFTER.test(text.slice(match.end, match.end + 3));
}

function suppressPhoneServiceNumber(_text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.PHONE) return false;
  return SERVICE_NUMBER.test(match.text);
}

function suppressPhoneDateOverlap(_text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.PHONE) return false;
  return DATE_PATTERN_FULL.test(match.text.trim());
}

// Standards and classification prefixes that are plate-shaped once a letter and
// digits follow: "ATC-N06", "ICD-O3". None is a German district code, but the
// guard is still gated on the absence of a plate cue, so a genuine plate that
// happens to collide is not lost.
const STANDARDS_PREFIX = new Set(["ICD", "ISO", "DIN", "IEC", "RFC", "DSM", "ATC", "MDR"]);

const PLATE_CUE_NEAR = /(?:Kennzeichen|Nummernschild|Kfz|Fahrzeug|amtliche[sn]?\s+Kennz|nummerplaat|plaque\s+d'immatriculation|license\s+plate|number\s+plate)/i;

const NOT_CITY_CODES = new Set([
  "ID","NR","NO","ST","DR","MR","MS","HR","FR","IM","IN","OR","IF","IS","IT","AT","AD","AG","AV",
  "BE","DE","EU","NL","LU","WS","SS","IP",
]);

const CURRENCY_PLATE = /^(?:EUR|USD|GBP|CHF|SEK|NOK|DKK|ISK|CZK|PLN|HUF|RON|BGN|HRK)\s/i;

const ALNUM = /[\p{L}\p{N}]/u;

/** Characters that join a token to more of an identifier (rules-engine#50, #81). */
const ID_CONNECTORS = "-/._+";

/** A reference marker directly before the token: "#FR-S2", "№ …", "n° …". */
const REFERENCE_MARK_BEFORE = /(?:#|№|(?<![A-Za-z])[nN][°º])\s?$/;

/** A connector glues [start, end) to a letter or digit outside it. */
function joinedToMore(text: string, start: number, end: number): boolean {
  return (
    (end + 1 < text.length && ID_CONNECTORS.includes(text[end]) && ALNUM.test(text[end + 1])) ||
    (start >= 2 && ID_CONNECTORS.includes(text[start - 1]) && ALNUM.test(text[start - 2]))
  );
}

function suppressPlateInCompound(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.LICENSE_PLATE) return false;
  // Suppress currency + number misread as plate (e.g. "EUR 2")
  if (CURRENCY_PLATE.test(match.text)) return true;
  if (match.start >= 3) {
    const before = text.slice(Math.max(0, match.start - 10), match.start);
    if (/[A-Za-zÄÖÜäöüß]{2,}-$/.test(before)) return true;
  }
  // A plate is a token of its own: joined by a connector to more of an
  // identifier ("TF-284-KL-00874", "FR-S2/2026") it is a segment of a reference
  // (rules-engine#50, #81). A spaced dash or slash does not join.
  if (joinedToMore(text, match.start, match.end)) return true;
  // After a reference marker ("Ref #FR-S2") it is a reference, unless a plate
  // cue says otherwise (rules-engine#81).
  if (REFERENCE_MARK_BEFORE.test(text.slice(Math.max(0, match.start - 4), match.start))) {
    const [b, a] = getContext(text, match.start, match.end);
    if (!PLATE_CUE_NEAR.test(b + a)) return true;
  }
  const matched = match.text.trim();
  const parts = matched.split(/[\s\-]+/);

  // A standards or classification reference, not a plate — unless a plate cue
  // nearby says otherwise.
  if (parts.length > 0 && STANDARDS_PREFIX.has(parts[0].toUpperCase())) {
    const [b, a] = getContext(text, match.start, match.end);
    if (!PLATE_CUE_NEAR.test(b + a)) return true;
  }

  if (parts.length > 0 && NOT_CITY_CODES.has(parts[0])) {
    const afterChar = match.end < text.length ? text[match.end] : "";
    const beforeChar = match.start > 0 ? text[match.start - 1] : "";
    if (/\d/.test(afterChar) || beforeChar === "-") return true;
    if (parts[0] === "WS" || parts[0] === "SS") return true;
    if (parts[0] === "IP") {
      const afterTwo = text.slice(match.end, match.end + 2);
      if (afterTwo.length >= 2 && afterTwo[0] === "." && /\d/.test(afterTwo[1])) return true;
    }
  }
  if (matched.startsWith("HRA") || matched.startsWith("HRB")) return true;
  const [before, after] = getContext(text, match.start, match.end);
  if (/(?:Semester|Hochschule|Uni\b)/i.test(before + after)) {
    if (parts.length > 0 && (parts[0] === "WS" || parts[0] === "SS")) return true;
  }
  return false;
}

/**
 * Reject a German plate whose district code is not a real one.
 *
 * The district-code set is closed, which makes it a whitelist rather than the
 * open-ended blocklist of standards prefixes: "REF-A12", "SYS-B3", "KTO-A1"
 * and every other document reference of that shape fail it without needing to
 * be enumerated. Applied as a tier — an unknown code still emits when a plate
 * cue is nearby, so a missing code costs recall only in the absence of any
 * other evidence.
 */
function suppressDePlateUnknownDistrict(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.LICENSE_PLATE) return false;
  if (match.countryCode !== "DE") return false;

  const parts = match.text.trim().split(/[\s\-]+/);
  if (parts.length === 0 || !parts[0]) return false;
  if (DE_DISTRICT_CODES.has(parts[0].toUpperCase())) return false;

  const [before, after] = getContext(text, match.start, match.end);
  if (PLATE_CUE_NEAR.test(before + after)) return false;
  return true;
}

function suppressNatidAsPassport(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.NATIONAL_ID) return false;
  const [before] = getContext(text, match.start, match.end);
  return PASSPORT_CONTEXT_BEFORE.test(before);
}

function suppressSeNatidAsOrg(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.NATIONAL_ID) return false;
  if (match.countryCode !== "SE") return false;
  const [before] = getContext(text, match.start, match.end);
  return SE_ORG_CONTEXT_BEFORE.test(before);
}

function suppressPostalInsideIban(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const beforeChar = match.start > 0 ? text[match.start - 1] : " ";
  const afterChar = match.end < text.length ? text[match.end] : " ";
  if (/[A-Za-z0-9]/.test(beforeChar) && /[A-Za-z0-9]/.test(afterChar)) return true;
  if (match.start >= 5) {
    const prefix = text.slice(match.start - 5, match.start);
    if (/[A-Z]{2}\d{2}\s$/.test(prefix)) return true;
  }
  return false;
}

// An IBAN-shaped run: two letters, two check digits, then grouped
// alphanumerics. Deliberately not checksum-gated -- the point is to describe the
// run a human wrote as one account number, including the ones that fail their
// checksum, because those are exactly the ones no structured detector claims.
const ACCOUNT_RUN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){2,8}\b/g;

// "Compte: FR76 3000 4008 0300 0109 5374" fails the IBAN checksum, so no
// BANK_ACCOUNT candidate survives and the Danish eight-digit phone pattern took
// "3000 4008" out of the middle of it, leaving the rest in the clear
// (rules-engine#30). POSTAL_CODE has carried its own version of this guard
// since 0.3.3, in suppressPostalInsideIban.
function suppressPhoneInsideAccountRun(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.PHONE) return false;
  const lineStart = text.lastIndexOf("\n", match.start) + 1;
  let lineEnd = text.indexOf("\n", match.end);
  if (lineEnd < 0) lineEnd = text.length;
  const line = text.slice(lineStart, lineEnd);
  ACCOUNT_RUN.lastIndex = 0;
  for (let m = ACCOUNT_RUN.exec(line); m !== null; m = ACCOUNT_RUN.exec(line)) {
    const runStart = lineStart + m.index;
    const runEnd = runStart + m[0].length;
    if (runStart <= match.start && match.end <= runEnd
        && runEnd - runStart > match.end - match.start) {
      return true;
    }
  }
  return false;
}

function suppressPostalAsHouseNumber(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const clean = match.text.replace(/\s/g, "");
  if (clean.length > 3) return false;
  const before = text.slice(Math.max(0, match.start - 30), match.start);
  if (/[a-záéíóúýþæöðA-ZÁÉÍÓÚÝÞÆÖÐ]{3,}\s+$/.test(before)) {
    const after = text.slice(match.end, match.end + 5);
    if (!/^,?\s+[A-ZÁÉÍÓÚÝÞÆÖÐ]/.test(after)) return true;
  }
  return false;
}

// ── BIC: banking-context cues and heading shapes ────────────────────────

// \bSWIFT\b also covers SWIFT-Code / SWIFT-BIC / Code SWIFT, and \bBIC\b
// covers BIC-code / BIC/SWIFT.
const BIC_KEYWORD = /\b(?:BIC|SWIFT)\b/i;

const BANK_BLOCK = /\b(?:IBAN|Bankverbindung|Bankgegevens|Bankrekening|Rekening(?:nummer)?|Kontonummer|Konto|Kontoinhaber|Compte|Coordonn[ée]es\s+bancaires|Banque|Account\s+(?:number|holder)|Bankleitzahl|BLZ|Betaalgegevens|Zahlungsdaten)\b/i;

// A line that is nothing but a BIC/SWIFT label, as used in table and column
// layouts where the code sits on the following line.
const BIC_LABEL_LINE = /^\s*(?:BIC|SWIFT|SWIFT[-\s]?BIC|BIC\s?\/\s?SWIFT|SWIFT[-\s]?Code|BIC[-\s]?code|Code\s+SWIFT)\s*:?\s*$/i;

// An IBAN in the same structural unit: CC + 2 check digits + 2 or more groups.
const IBAN_SHAPE = /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,}/;

// Largest paragraph still treated as one structural unit. Beyond this the unit
// falls back to the enclosing line, so a run-on document body cannot lend
// banking context to a token 2,000 characters away.
const MAX_UNIT_CHARS = 600;

function enclosingLine(text: string, start: number, end: number): [number, number] {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = text.indexOf("\n", end);
  if (lineEnd === -1) lineEnd = text.length;
  return [lineStart, lineEnd];
}

/**
 * Return the enclosing line / record / paragraph around a match.
 *
 * The context window for BIC is scoped structurally, not by character count.
 * A tight character window measured on the corpus rejects 97.3% of dictionary
 * false positives but wrongly discards ~316 real-looking codes, because the
 * banking cue often sits further away in the same record — e.g. a CSV row
 * carrying the IBAN in one field and the BIC several fields later.
 */
function structuralUnit(text: string, start: number, end: number): string {
  const [lineStart, lineEnd] = enclosingLine(text, start, end);

  // Both walks stop as soon as the paragraph is too wide to be used, because
  // everything past that point is discarded by the cap below anyway. Applying
  // the cap only to the *result* meant that on a document with no blank lines
  // each walk ran to the top and bottom of the whole text — O(document) per
  // candidate, O(n^2) overall.
  let paraStart = lineStart;
  while (paraStart > 0) {
    if (lineEnd - paraStart > MAX_UNIT_CHARS) return text.slice(lineStart, lineEnd);
    const prevEnd = paraStart - 1;
    const prevStart = text.lastIndexOf("\n", prevEnd - 1) + 1;
    if (text.slice(prevStart, prevEnd).trim() === "") break;
    paraStart = prevStart;
  }

  let paraEnd = lineEnd;
  while (paraEnd < text.length) {
    if (paraEnd - paraStart > MAX_UNIT_CHARS) return text.slice(lineStart, lineEnd);
    const nextStart = paraEnd + 1;
    let nextEnd = text.indexOf("\n", nextStart);
    if (nextEnd === -1) nextEnd = text.length;
    if (text.slice(nextStart, nextEnd).trim() === "") break;
    paraEnd = nextEnd;
  }

  if (paraEnd - paraStart <= MAX_UNIT_CHARS) return text.slice(paraStart, paraEnd);
  return text.slice(lineStart, lineEnd);
}

function previousNonblankLine(text: string, lineStart: number): string {
  let pos = lineStart;
  while (pos > 0) {
    const prevEnd = pos - 1;
    const prevStart = text.lastIndexOf("\n", prevEnd - 1) + 1;
    const line = text.slice(prevStart, prevEnd);
    if (line.trim() !== "") return line;
    pos = prevStart;
  }
  return "";
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Does `token` also occur as an ordinary lowercase word in this document?
 *
 * `hospital`/`HOSPITAL`, `gegevens`/`GEGEVENS` — a token that appears in
 * ordinary case elsewhere in the same document is a word, not a bank code.
 * Email and domain contexts are excluded, so `ing.nl` does not vouch for a
 * heading. Measured on the corpus this alone identifies ~78% of the BIC false
 * positives with no dictionaries and no labelled data.
 */
/**
 * Every all-letter word in the document that is not part of an email address
 * or a domain name.
 *
 * `\b<word>\b` can only match a maximal run of word characters, so collecting
 * the runs once answers the question for every candidate. Re-scanning the whole
 * document per candidate made this quadratic: 1.58 s on a 400 KB document
 * dense in bank codes, against ~1 ms to build this set.
 */
function buildDocumentWords(text: string): Set<string> {
  const words = new Set<string>();
  const re = /[A-Za-z0-9_]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const word = m[0];
    if (!/^[A-Za-z]+$/.test(word)) continue;
    const i = m.index;
    const before = i > 0 ? text[i - 1] : "";
    if (before === "@") continue;
    if (before === "." && i >= 2 && /[A-Za-z0-9]/.test(text[i - 2])) continue;
    const after = text.slice(i + word.length, i + word.length + 8);
    if (after.startsWith("@")) continue;
    if (/^\.[a-zA-Z]{2,6}\b/.test(after)) continue;
    words.add(word);
  }
  return words;
}

/**
 * Per-document scratch space for suppressors that would otherwise re-derive the
 * same whole-document facts for every candidate.
 *
 * Built lazily and held only for the duration of one `detect()` call, so no
 * document text outlives the call that supplied it.
 */
export class SuppressionScratch {
  private words: Set<string> | null = null;

  constructor(private readonly text: string) {}

  documentWords(): Set<string> {
    if (this.words === null) this.words = buildDocumentWords(this.text);
    return this.words;
  }
}

/**
 * Does `token` also occur as an ordinary lowercase word in this document?
 *
 * `hospital`/`HOSPITAL`, `gegevens`/`GEGEVENS` — a token that appears in
 * ordinary case elsewhere in the same document is a word, not a bank code.
 * Email and domain contexts are excluded, so `ing.nl` does not vouch for a
 * heading. Measured on the corpus this alone identifies ~78% of the BIC false
 * positives with no dictionaries and no labelled data.
 */
function occursAsLowercaseWord(text: string, token: string, scratch?: SuppressionScratch): boolean {
  if (!/^[A-Za-z]+$/.test(token)) return false;
  const lower = token.toLowerCase();
  const capitalised = lower[0].toUpperCase() + lower.slice(1);
  const words = scratch ? scratch.documentWords() : buildDocumentWords(text);
  return words.has(lower) || words.has(capitalised);
}

/**
 * Is the candidate positioned as a section heading rather than a value?
 * Headings and shouted words are never bank codes. Lines carrying an explicit
 * BIC/SWIFT keyword are exempt from the all-caps rule, so a genuine
 * `BIC: GEBABEBB` line is not mistaken for a heading.
 */
function isHeadingShape(text: string, start: number, end: number, token: string): boolean {
  const [lineStart, lineEnd] = enclosingLine(text, start, end);
  const line = text.slice(lineStart, lineEnd);

  // The token is the entire line — unless the line above is a bare BIC/SWIFT
  // label, which makes this a labelled value in a table layout, not a heading.
  if (line.trim() === token) {
    return !BIC_LABEL_LINE.test(previousNonblankLine(text, lineStart));
  }

  // The token starts its line and is immediately followed by a colon
  if (text.slice(lineStart, start).trim() === "" && text.slice(end, lineEnd).trimStart().startsWith(":")) {
    return true;
  }

  // A shouted line: no lowercase, no digits, and no banking keyword
  if (!/[a-z]/.test(line) && !/\d/.test(line) && !BIC_KEYWORD.test(line)) return true;

  return false;
}

/**
 * Emit a BIC only on registry membership or banking context.
 *
 * 0. the token also occurs as an ordinary lowercase word here -> reject;
 * 1. registry hit (deployment-supplied, then bundled seed prefixes) -> emit;
 * 2. heading / shouted-word shape -> reject;
 * 3. BIC/SWIFT keyword, IBAN or bank block in the structural unit -> emit;
 *
 * and a bare shape match reaching the end with none of the above is never
 * emitted. Gate 0 outranks every tier below it — no genuine BIC is also an
 * ordinary lowercase word — so it is applied on both emitting paths. It scans
 * the whole document, so it runs only on the paths that would otherwise emit.
 */
function suppressBicWithoutEvidence(text: string, match: RawMatch, scratch?: SuppressionScratch): boolean {
  if (match.patternDef.entityType !== EntityType.BIC) return false;
  const token = match.text.trim();

  if (isRegisteredBic(token)) return occursAsLowercaseWord(text, token, scratch);

  if (isHeadingShape(text, match.start, match.end, token)) return true;

  // The token itself is blanked out so it cannot vouch for itself.
  const unit = structuralUnit(text, match.start, match.end).split(token).join(" ".repeat(token.length));
  if (BIC_KEYWORD.test(unit) || IBAN_SHAPE.test(unit) || BANK_BLOCK.test(unit)) {
    if (bicShapedWord(text, match.start, match.end, token)) return true;
    return occursAsLowercaseWord(text, token, scratch);
  }
  return true;
}

/** A personal title right before the token: "Dr. HOFFMANN", "Mme JANSSENS". */
const TITLE_BEFORE = /(?<![A-Za-z])(?:dr|prof|mr|mrs|ms|mme|mlle|m|herr|frau|dhr|mevr|sig|sra?)\.?\s+$/i;
const LETTER = /\p{L}/u;

/** A BIC/SWIFT label touching the token: "BIC: ", "SWIFT-Code:\n", "Code SWIFT : ", "BIC Bank A: ". */
const BIC_LABEL_BEFORE = /(?<![A-Za-z])(?:bic|swift)(?:[\s/\-]*(?:code|swift|bic))?(?:\s+bank\s+\w{1,3})?[\s:.\-()]*$/i;

/**
 * A registry miss sitting where only a word or a name can (rules-engine#57):
 * joined to a word by a hyphen ("NGUYEN-HOFFMANN"), right after a personal
 * title ("Dr. HOFFMANN"), or letters only (eight, or eleven without an `XXX`
 * branch: "BETALING", "MAANDELIJKS") that the GLEIF mapping does not know and
 * no BIC/SWIFT label touches.
 */
function bicShapedWord(text: string, start: number, end: number, token: string): boolean {
  if ((start >= 2 && text[start - 1] === "-" && LETTER.test(text[start - 2])) ||
      (text[end] === "-" && end + 1 < text.length && LETTER.test(text[end + 1]))) return true;
  if (TITLE_BEFORE.test(text.slice(Math.max(0, start - 8), start))) return true;
  return /^[A-Za-z]+$/.test(token) && !(token.length === 11 && token.endsWith("XXX"))
    && !isKnownInstitution(token)
    && !BIC_LABEL_BEFORE.test(text.slice(Math.max(0, start - 30), start));
}

// ── Postal code: digits belonging to a longer identifier ────────────────

// An identifier label immediately before the digits. A postal code is never
// introduced this way; an SVNr, policy number or service number always is.
// The `[\w\-]*` prefix is factored out of the five alternatives that share it.
// Repeated per alternative, the engine retried the same unbounded prefix five
// times per starting position — the most expensive single regex in the engine
// at 197 ms per 1 MB document. Same language, 8x faster on the worst case.
// An identifier cue that is really a postal label -- see the use below.
const POSTAL_LABEL_CUE = /^post/i;

const ID_CUE_BEFORE = /(?:[\w\-]*(?:Nr|N[°ºo]|Nummer|Numero|Numéro)|No|number|num|Kennzahl|Aktenzeichen|Az|e-?card|Polizze|Police|Policen)\.?\s*:?\s*$/i;

// An international dialling prefix earlier on the same line, with nothing but
// number punctuation in between: these digits belong to the phone detector.
const DIALLING_PREFIX_BEFORE = /\+\d{1,3}[\d\s\-().]*$/;

// A country prefix on a postal code — "A-1010 Wien", "B-2000", "L-1234".
// The boundary excludes a hyphen, which is what makes this a *prefix* rather
// than a segment. It did not, so any `XX-NNNNN` tail of a hyphenated reference
// read as a country-prefixed address: in "PV-2026-LU-09143" the `LU` is
// preceded by `-` and the German five-digit postal pattern kept `09143`
// (rules-engine#31).
const COUNTRY_PREFIXED = /(?:^|[^A-Za-z0-9\-])[A-Z]{1,2}$/;

/**
 * Suppress bare digit runs that belong to a longer number, not an address.
 *
 * A bare 4- or 5-digit run is the weakest shape in the engine, and when it
 * cuts into a longer identifier the damage is worse than a plain false
 * positive: `SV-Nummer: [POSTAL_CODE] 040390` leaves half an Austrian social
 * security number exposed with no way to label the remainder.
 *
 * Applies only to digits-only matches, so structured forms keep their own
 * behaviour — NL `1234 AB`, PT `1234-567`, LU `L-1234`.
 */
function suppressPostalInLongerIdentifier(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const clean = match.text.trim();
  if (!/^\d+$/.test(clean)) return false;

  const beforeChar = match.start > 0 ? text[match.start - 1] : "";
  const afterChar = match.end < text.length ? text[match.end] : "";
  const prevPrev = match.start >= 2 ? text[match.start - 2] : "";
  const nextNext = match.end + 1 < text.length ? text[match.end + 1] : "";

  // Directly glued to more digits
  if (/\d/.test(beforeChar) || /\d/.test(afterChar)) return true;

  // Joined by identifier punctuation: "0456.2398.71-02", "4471/2025".
  // The punctuation only counts when it actually *joins two digit groups* — a
  // trailing period is ordinary sentence punctuation, and treating it as a
  // separator discards every postal code that ends a sentence
  // ("Domicilio: Palma, 13867. Pagos a ...").
  if ("._/".includes(beforeChar) && /\d/.test(prevPrev)) return true;
  if ("._/".includes(afterChar) && /\d/.test(nextNext)) return true;
  if (afterChar === "-" && /\d/.test(nextNext)) return true;
  if (beforeChar === "-" && !COUNTRY_PREFIXED.test(text.slice(0, match.start - 1))) return true;

  // A further digit group on the same line: "1268 040390", "1234 5678 925",
  // "+43 664 8213 907". Horizontal whitespace only — a digit on the *next*
  // line is a separate field, not a continuation.
  if (/^[ \t]+\d/.test(text.slice(match.end, match.end + 4))) return true;

  // An identifier label introduces the digits: "DiNr. 4471", "Policen-Nr."
  // Unless the label is a *postal* one. ID_CUE_BEFORE matches any word ending
  // in "Nummer", "Nr", "Numero" or "Numéro" -- the wildcard is `[\w\-]*` -- so
  // it matches `postnummer`, `postnr` and `postinumero`, the canonical postal
  // labels of Norway, Denmark and Finland. Those countries write a bare
  // four- or five-digit code, so the isdigit() guard above lets this run and
  // the code was suppressed by its own label: `postnummer: 5020 Bergen`
  // produced nothing at all (rules-engine#41).
  const before = text.slice(Math.max(0, match.start - 40), match.start);
  const cue = ID_CUE_BEFORE.exec(before);
  if (cue !== null && !POSTAL_LABEL_CUE.test(cue[0].trimStart())) return true;

  // Digits after an international dialling prefix belong to PHONE
  const [lineStart] = enclosingLine(text, match.start, match.end);
  if (DIALLING_PREFIX_BEFORE.test(text.slice(lineStart, match.start))) return true;

  return false;
}

/**
 * A delimited data row: at least three fields separated by one delimiter.
 * Export formats carry their meaning in the column, not in a nearby word, so a
 * value filling an entire field has structural context even when the line
 * contains no cue.
 */
const DELIMITED_ROW = /^[^\n]*?([,;|\t])[^\n]*?\1[^\n]*?\1/;

/**
 * Types for which filling a delimited field counts as context. Narrow shapes
 * only: applied to every type it was measured a net loss — SECRET gained 1,678
 * false positives, CHAMBER_OF_COMMERCE 456 and POSTAL_CODE 295. A broad shape
 * plus a required cue is a deliberate pairing, and removing the cue leaves only
 * the broad shape.
 */
const DELIMITED_FIELD_TYPES = new Set<EntityType | string>([
  EntityType.PHONE, EntityType.DOB, EntityType.DATE_OF_DEATH,
]);

/** True when the span is exactly one field of a delimited row. */
function fillsADelimitedField(text: string, start: number, end: number): boolean {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  let lineEnd = text.indexOf("\n", end);
  if (lineEnd < 0) lineEnd = text.length;
  if (!DELIMITED_ROW.test(text.slice(lineStart, lineEnd))) return false;
  const before = text.slice(lineStart, start);
  const after = text.slice(end, lineEnd);
  const opens = before === "" || ",;|\t".includes(before[before.length - 1]);
  const closes = after === "" || ",;|\t".includes(after[0]);
  return opens && closes;
}

function suppressRequiresContext(text: string, match: RawMatch): boolean {
  if (!match.patternDef.requiresContext || match.patternDef.contextKeywords.length === 0) return false;
  // A value filling an entire field of a delimited row is introduced by its
  // column, not by a word, so that is context — but only for narrow shapes.
  if (DELIMITED_FIELD_TYPES.has(match.patternDef.entityType) &&
      fillsADelimitedField(text, match.start, match.end)) return false;
  if (DATE_LABEL_TYPES.has(match.patternDef.entityType)) {
    return !labelsThisDate(text, match.start, match.end, match.patternDef.contextKeywords,
                           match.patternDef.entityType);
  }
  const [before, after] = getContext(text, match.start, match.end);
  const context = (before + " " + after).toLowerCase();
  return !match.patternDef.contextKeywords.some(kw => context.includes(kw.toLowerCase()));
}

/** Date types decided by a label: DOB and DATE_OF_DEATH share one date shape. */
const DATE_LABEL_TYPES = new Set<EntityType | string>([EntityType.DOB, EntityType.DATE_OF_DEATH]);

/** Any common numeric date, to tell whether a label belongs to another date. */
const ANY_DATE = /\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}/;

/**
 * True when one of `keywords` is this date's own label: before the date with no
 * other date between, or after it inside the date's own sentence. Anywhere in
 * the window typed every date from whichever date label the document carried
 * (rules-engine#52).
 */
/** A date followed by a list separator: an item of the list a label introduces. */
const LIST_ITEM = /\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}\s*(?:,|;|–|&|\band\b|\ben\b|\bet\b|\bund\b|\bor\b|\bof\b|\bou\b|\boder\b|\brespectievelijk\b|\bbzw\.?)\s*/g;

/** Punctuation and at most two short words ("e.g.", "bv.", "op") between label and date. */
const LABEL_TAIL = /^[\s:.,()\-]*(?:\p{L}{1,4}(?:\.\p{L}{1,2})*\.?(?:[\s:.,()\-]+|$)){0,2}$/u;

/** The birth sign "°" directly before the date, but not the number sign "n°". */
const BIRTH_SIGN = /(?<![a-z])°\s?$/;

/** No other date between a label and the date, except items of its list. */
function nothingButAListBetween(gap: string): boolean {
  if (!ANY_DATE.test(gap)) return true;
  const rest = gap.replace(LIST_ITEM, " ");
  return !ANY_DATE.test(rest) && LABEL_TAIL.test(rest);
}

function labelsThisDate(
  text: string, start: number, end: number, keywords: string[], entityType?: EntityType | string,
): boolean {
  const [before, after] = getContext(text, start, end);
  const lowerBefore = before.toLowerCase();
  const lowerAfter = after.toLowerCase();
  // A label on an earlier line counts only when the date opens its own line or
  // the label was asked as a question (a call transcript's answer turn);
  // a column header is a fallback and never overrules a label of the date's own.
  const lineStart = lowerBefore.lastIndexOf("\n") + 1;
  const opensLine = lowerBefore.slice(lineStart).replace(/[ \t:|;*\-•(\[]/g, "") === "";
  if (entityType === EntityType.DOB && BIRTH_SIGN.test(lowerBefore)) return true;
  for (const keyword of keywords) {
    const kw = keyword.toLowerCase();
    const i = lowerBefore.lastIndexOf(kw);
    if (i >= 0 && nothingButAListBetween(lowerBefore.slice(i + kw.length))
        && (i >= lineStart || opensLine
            || lowerBefore.slice(i + kw.length, lineStart).includes("?"))) return true;
    const j = lowerAfter.indexOf(kw);
    if (j >= 0) {
      const gap = lowerAfter.slice(0, j);
      if (!ANY_DATE.test(gap) && !SENTENCE_BREAK.test(gap)
          && !LEADS_TO_A_DATE.test(lowerAfter.slice(j + kw.length))) return true;
    }
  }
  const header = columnHeader(text, start);
  return header !== null && keywords.some(kw => header.includes(kw.toLowerCase()));
}

/**
 * A label running straight into a date of its own introduces that date, not the
 * one before it ("Verstorben am 01.02.2020, geboren am 12.03.1940").
 */
const LEADS_TO_A_DATE = /^[\s:.\-]*(?:[a-zà-ÿ]{1,3}[\s:.]+)?\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}/;

/** Field separators a table row may use. */
const COLUMN_SEPARATORS = [";", "|", "\t", ","];

/**
 * The lower-cased header cell above the value, if it sits in a table: in a table
 * the column decides the label, not proximity. A header is one of the three
 * lines above, split by the row's separator into the same number of cells.
 */
function columnHeader(text: string, start: number): string | null {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const lineEndAt = text.indexOf("\n", start);
  const line = text.slice(lineStart, lineEndAt >= 0 ? lineEndAt : text.length);
  // The three lines above, by lastIndexOf: splitting the whole prefix was
  // quadratic in the document, once per date candidate.
  let aboveStart = lineStart - 1;
  for (let k = 0; k < 3 && aboveStart >= 0; k++) {
    aboveStart = aboveStart === 0 ? -1 : text.lastIndexOf("\n", aboveStart - 1);
  }
  const above = lineStart ? text.slice(aboveStart + 1, Math.max(0, lineStart - 1)).split("\n") : [];
  for (const sep of COLUMN_SEPARATORS) {
    if (!line.includes(sep)) continue;
    const cells = line.split(sep);
    const column = text.slice(lineStart, start).split(sep).length - 1;
    for (const header of [...above].reverse()) {
      const heads = header.split(sep);
      if (heads.length === cells.length && !ANY_DATE.test(header)) return heads[column].toLowerCase();
    }
  }
  return null;
}

// Suppressors that need whole-document facts take the optional scratch; the
// rest ignore it, and a narrower function stays assignable to this type.
type Suppressor = (text: string, match: RawMatch, scratch?: SuppressionScratch) => boolean;

const TYPE_SUPPRESSORS: Partial<Record<string, Suppressor[]>> = {
  [EntityType.PHONE]: [suppressCurrency, suppressUnits, suppressReference, suppressMath, suppressPhoneServiceNumber, suppressPhoneInsideAccountRun, suppressPhoneDateOverlap, suppressPhoneAsNumberRange],
  [EntityType.NATIONAL_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressLegal, suppressMath, suppressNatidAsPassport, suppressSeNatidAsOrg],
  [EntityType.SSN]: [suppressCurrency, suppressUnits, suppressReference, suppressMath],
  [EntityType.TAX_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressMath, suppressTaxidAsIpAddress],
  [EntityType.POSTAL_CODE]: [suppressCurrency, suppressUnits, suppressMath, suppressLegal, suppressYearAsPostal, suppressPostalAfterDisqualifyingWord, suppressPostalInsideIban, suppressPostalAsHouseNumber, suppressPostalInLongerIdentifier, suppressReference],
  [EntityType.BIC]: [suppressBicWithoutEvidence],
  [EntityType.BANK_ACCOUNT]: [suppressReference],
  [EntityType.LICENSE_PLATE]: [suppressPlateInCompound, suppressDePlateUnknownDistrict, suppressPlateAsCurrencyAmount],
  [EntityType.SECRET]: [suppressSecretOverStructured, suppressSecretNotASecret],
  [EntityType.CHAMBER_OF_COMMERCE]: [suppressReference],
};

export function shouldSuppress(text: string, match: RawMatch, scratch?: SuppressionScratch): boolean {
  if (suppressSequential(text, match)) return true;
  if (suppressRedactionPlaceholder(text, match)) return true;
  const typeSups = TYPE_SUPPRESSORS[match.patternDef.entityType];
  if (typeSups) {
    for (const s of typeSups) {
      if (s(text, match, scratch)) return true;
    }
  }
  if (match.patternDef.requiresContext) return suppressRequiresContext(text, match);
  return false;
}
