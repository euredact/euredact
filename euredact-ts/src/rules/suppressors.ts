import { EntityType, type PatternDef } from "../types.js";
import { isRegisteredBic } from "./bicRegistry.js";

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
const CURRENCY_AFTER = new RegExp(`^\\s*(?:EUR|€|\\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK|euro|euros|dollar|dollars|pond|kronor|kroner|kr)${_UWB}`, "i");
const CURRENCY_COMMA_AFTER = new RegExp(`^[.,]\\d{1,2}\\s*(?:EUR|€|\\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK|euro|euros|kr(?:onor|oner)?|pond)${_UWB}`, "i");
const CURRENCY_BEFORE = /(?:EUR|€|\$|USD|GBP|£|CHF|ISK|SEK|NOK|DKK)\s*$/;
const AMOUNT_LABEL_BEFORE = /(?:Montant|Beløb|Summa|Summe|Bedrag|Amount|Total|TTC|inkl|Upphæð)\s*:?\s*$/i;

// Use Unicode-aware word boundary via \p{L} negative lookahead instead of \b
// because JS \b is ASCII-only and fails on Unicode letters (e.g. "München" → \bm\b matches M before ü)
const UNIT_AFTER = /^\s*(?:kg|km|cm|mm|m[²³]|ml|mg|GB|MB|KB|TB|%|jaar|maanden|weken|dagen|uur|minuten|seconden|stuks|pcs|pieces|ans|mois|semaines|jours|heures|Jahre|Monate|Wochen|Tage|Stunden)(?![a-zA-Z\u00C0-\u024F\u0400-\u04FF])/i;

const REFERENCE_BEFORE = /(?:dossier|ref\.?|referentie|reference|référence|factuurnummer|invoice\s*(?:nr|number|no)?|bestelnummer|order\s*(?:nr|number|no)?|kenmerk|ordernummer|Aktenzeichen|numéro\s*de\s*(?:dossier|facture|commande)|bestellnummer|Rechnungsnummer|artikelnr|article\s*no|contract\s*(?:nr|number|no)?|pagina|page|Seite|blz\.?|Facture\s*n[°o]?|Faktura\s*n[°or]\.?|Lasku\s*n[°or]o?\.?|Rechnung\s*(?:Nr|n[°o])?|faktura\s*(?:nr|n[°o])?|bestilling\s*(?:nr|n[°o])?|bestelling\s*n[°or]\.?|Reikningur\s*nr)\s*[:.]?\s*$/i;

const LEGAL_BEFORE = /(?:Art(?:ikel|icle|\.)|§|Artikel|Section|Sectie|Afdeling|paragraaf|Absatz|alinéa|punt|point|Punkt|lid)\s*$/i;

const MATH_BEFORE = /[=+\-×÷*/]\s*$/;
const MATH_AFTER = /^\s*[=+\-×÷*/]/;

// "A-1010", "B-2000", "L-1234", "CH-8000", "D-10115": a country prefix on a
// postal code, not a minus sign.
const COUNTRY_PREFIX_HYPHEN = /(?:^|[^A-Za-z0-9])[A-Z]{1,2}-\s*$/;

const SEQUENTIAL_PATTERNS = /^(?:0{6,}|1234567890?|0123456789|9876543210?|1111111111?|000000000|123456789)$/;

// YEAR_PATTERN kept for reference but replaced by RECENT_YEAR in suppressYearAsPostal

const ID_LABEL_BEFORE = /(?:BSN|RR|NN|NIR|INSZ|NISS|NIS|Steuer-?ID|TIN|NIF|NIE|SSN|rijksregisternummer|numéro\s*national|national\s*number|matricule|Ausweisnummer|Personalausweis|Versichertennummer|KVNR|KV-Nr|Steuernummer|St\.\-Nr|StNr|Finanzamt\s+ist|Ondernemingen\s+onder\s+nummer|ondernemingsnummer|numéro\s*d'entreprise|enterprise\s*number|Kruispuntbank)\s*[:.]?\s*$/i;

const SERVICE_NUMBER = /^0800[\-\s]/;
const DATE_PATTERN_FULL = /^\d{2}[-/.]\d{2}[-/.]\d{4}$|^\d{4}[-/.]\d{2}[-/.]\d{2}$/;

const PASSPORT_CONTEXT_BEFORE = /(?:Reisepass|passport|passeport|paspoort|Bisheriger\s+Reisepass)\s*(?:Nr\.?|Nummer|nummer|number|n[°o])?\s*[:.]?\s*$/i;
const SE_ORG_CONTEXT_BEFORE = /(?:org\.?\s*nr\.?|organisationsnummer|organisationsnr|Bolagsverket|företag)\s*[:.]?\s*$/i;

const NUMERIC_TYPES = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.POSTAL_CODE]);

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

function suppressReference(text: string, match: RawMatch): boolean {
  const applicable = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE]);
  if (!applicable.has(match.patternDef.entityType)) return false;
  const [before] = getContext(text, match.start, match.end);
  return REFERENCE_BEFORE.test(before);
}

function suppressLegal(text: string, match: RawMatch): boolean {
  const applicable = new Set<EntityType | string>([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.POSTAL_CODE]);
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

const RECENT_YEAR = /^(?:19[5-9]\d|20[0-3]\d)$/;
const POSTAL_CONTEXT_NEAR = /(?:postcode|postal|code\s*postal|PLZ|Postleitzahl|postnummer|postinumero|póstnúmer|zip|straat|straße|strasse|rue\s|via\s|calle\s|rua\s|ulica|utca|street|avenue|laan\s|weg\s|plein|adres|adresse|address|woonplaats|wonende|woonachtig|gevestigd|domicili|demeurant|résidant|residant|bosatt|bopæl|wohnhaft|ansässig|stad\b|ville\b|city\b|Stadt|città|ciudad|cidade|miasto|město|város)/i;
const DATE_KEYWORD_NEAR = /(?:født|fødselsdato|fødsel|Fødselsdato|född|födelsedatum|födelsedag|syntynyt|syntymäaika|fæddur|fæðingardagur|geboren|geboortedatum|Geburtsdatum|nascido|nacido|data di nascita|nato il|nata il|Tiltr[æa]delsesdato|Tiltredelsesdato|datum|date\b|Datum|jaar|year|année|Jahr|since|sinds|depuis|seit|\d{2}\.\d{2}\.|(?:januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december|januari|februari|mars|mei|juin|juillet|août))/i;

function suppressYearAsPostal(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const clean = match.text.trim();
  if (!RECENT_YEAR.test(clean)) return false;
  const [before, after] = getContext(text, match.start, match.end);
  const context = before + after;
  // Keep as postal code if postal/address context nearby
  if (POSTAL_CONTEXT_NEAR.test(context)) return false;
  // Keep if preceded by comma+space (address pattern: "Amsterdam, 2026")
  const immediateBefore = text.slice(Math.max(0, match.start - 3), match.start);
  if (/,\s*$/.test(immediateBefore)) return false;
  // Suppress if date keyword nearby (birth date, employment date, etc.)
  if (DATE_KEYWORD_NEAR.test(context)) return true;
  // Suppress: recent years without postal context are almost never postal codes
  return true;
}

function suppressPhoneAfterIdLabel(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.PHONE) return false;
  const [before] = getContext(text, match.start, match.end);
  return ID_LABEL_BEFORE.test(before);
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

function suppressPlateInCompound(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.LICENSE_PLATE) return false;
  // Suppress currency + number misread as plate (e.g. "EUR 2")
  if (CURRENCY_PLATE.test(match.text)) return true;
  if (match.start >= 3) {
    const before = text.slice(Math.max(0, match.start - 10), match.start);
    if (/[A-Za-zÄÖÜäöüß]{2,}-$/.test(before)) return true;
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

  let paraStart = lineStart;
  while (paraStart > 0) {
    const prevEnd = paraStart - 1;
    const prevStart = text.lastIndexOf("\n", prevEnd - 1) + 1;
    if (text.slice(prevStart, prevEnd).trim() === "") break;
    paraStart = prevStart;
  }

  let paraEnd = lineEnd;
  while (paraEnd < text.length) {
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
function occursAsLowercaseWord(text: string, token: string): boolean {
  if (!/^[A-Za-z]+$/.test(token)) return false;
  const lower = token.toLowerCase();
  const capitalised = lower[0].toUpperCase() + lower.slice(1);
  for (const form of [lower, capitalised]) {
    // Cheap pre-check: a plain substring test almost always answers "no".
    if (!text.includes(form)) continue;
    const re = new RegExp(`\\b${escapeRe(form)}\\b`, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const before = m.index > 0 ? text[m.index - 1] : "";
      const after = text.slice(m.index + form.length, m.index + form.length + 8);
      if (before === "@" || (before === "." && m.index >= 2 && /[A-Za-z0-9]/.test(text[m.index - 2]))) continue;
      if (after.startsWith("@") || /^\.[a-zA-Z]{2,6}\b/.test(after)) continue;
      return true;
    }
  }
  return false;
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
function suppressBicWithoutEvidence(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.BIC) return false;
  const token = match.text.trim();

  if (isRegisteredBic(token)) return occursAsLowercaseWord(text, token);

  if (isHeadingShape(text, match.start, match.end, token)) return true;

  // The token itself is blanked out so it cannot vouch for itself.
  const unit = structuralUnit(text, match.start, match.end).split(token).join(" ".repeat(token.length));
  if (BIC_KEYWORD.test(unit) || IBAN_SHAPE.test(unit) || BANK_BLOCK.test(unit)) {
    return occursAsLowercaseWord(text, token);
  }
  return true;
}

// ── Postal code: digits belonging to a longer identifier ────────────────

// An identifier label immediately before the digits. A postal code is never
// introduced this way; an SVNr, policy number or service number always is.
const ID_CUE_BEFORE = /(?:[\w\-]*Nr|[\w\-]*N[°ºo]|[\w\-]*Nummer|[\w\-]*Numero|[\w\-]*Numéro|No|number|num|Kennzahl|Aktenzeichen|Az|e-?card|Polizze|Police|Policen)\.?\s*:?\s*$/i;

// An international dialling prefix earlier on the same line, with nothing but
// number punctuation in between: these digits belong to the phone detector.
const DIALLING_PREFIX_BEFORE = /\+\d{1,3}[\d\s\-().]*$/;

// A country prefix on a postal code — "A-1010 Wien", "B-2000", "L-1234".
const COUNTRY_PREFIXED = /(?:^|[^A-Za-z0-9])[A-Z]{1,2}$/;

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
  if (ID_CUE_BEFORE.test(text.slice(Math.max(0, match.start - 40), match.start))) return true;

  // Digits after an international dialling prefix belong to PHONE
  const [lineStart] = enclosingLine(text, match.start, match.end);
  if (DIALLING_PREFIX_BEFORE.test(text.slice(lineStart, match.start))) return true;

  return false;
}

function suppressRequiresContext(text: string, match: RawMatch): boolean {
  if (!match.patternDef.requiresContext || match.patternDef.contextKeywords.length === 0) return false;
  const [before, after] = getContext(text, match.start, match.end);
  const context = (before + " " + after).toLowerCase();
  return !match.patternDef.contextKeywords.some(kw => context.includes(kw.toLowerCase()));
}

type Suppressor = (text: string, match: RawMatch) => boolean;

const TYPE_SUPPRESSORS: Partial<Record<string, Suppressor[]>> = {
  [EntityType.PHONE]: [suppressCurrency, suppressUnits, suppressReference, suppressMath, suppressPhoneAfterIdLabel, suppressPhoneServiceNumber, suppressPhoneDateOverlap],
  [EntityType.NATIONAL_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressLegal, suppressMath, suppressNatidAsPassport, suppressSeNatidAsOrg],
  [EntityType.SSN]: [suppressCurrency, suppressUnits, suppressReference, suppressMath],
  [EntityType.TAX_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressMath],
  [EntityType.POSTAL_CODE]: [suppressCurrency, suppressUnits, suppressMath, suppressLegal, suppressYearAsPostal, suppressPostalInsideIban, suppressPostalAsHouseNumber, suppressPostalInLongerIdentifier],
  [EntityType.BIC]: [suppressBicWithoutEvidence],
  [EntityType.BANK_ACCOUNT]: [suppressReference],
  [EntityType.LICENSE_PLATE]: [suppressPlateInCompound],
  [EntityType.CHAMBER_OF_COMMERCE]: [suppressReference],
};

export function shouldSuppress(text: string, match: RawMatch): boolean {
  if (suppressSequential(text, match)) return true;
  const typeSups = TYPE_SUPPRESSORS[match.patternDef.entityType];
  if (typeSups) {
    for (const s of typeSups) {
      if (s(text, match)) return true;
    }
  }
  if (match.patternDef.requiresContext) return suppressRequiresContext(text, match);
  return false;
}
