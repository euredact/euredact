import { EntityType, type PatternDef } from "../types.js";

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

const SEQUENTIAL_PATTERNS = /^(?:0{6,}|1234567890?|0123456789|9876543210?|1111111111?|000000000|123456789)$/;

const YEAR_PATTERN = /^(?:19[4-9]\d|20[0-3]\d)$/;
const DATE_KEYWORD_NEAR = /(?:jaar|year|année|Jahr|datum|date|Datum|in\s+\d{4}|since|sinds|depuis|seit|født|fødselsdato|fødsel|Fødselsdato|född|födelsedatum|födelsedag|syntynyt|syntymäaika|fæddur|fæðingardagur|\d{2}\.\d{2}\.|(?:januar|februar|marts|april|maj|juni|juli|august|september|oktober|november|december|januari|februari|mars|april|mei|juin|juillet|août|Tiltr[æa]delsesdato|Tiltredelsesdato))/i;

const ID_LABEL_BEFORE = /(?:BSN|RR|NN|NIR|INSZ|NISS|NIS|Steuer-?ID|TIN|NIF|NIE|SSN|rijksregisternummer|numéro\s*national|national\s*number|matricule|Ausweisnummer|Personalausweis|Versichertennummer|KVNR|KV-Nr|Steuernummer|St\.\-Nr|StNr|Finanzamt\s+ist|Ondernemingen\s+onder\s+nummer|ondernemingsnummer|numéro\s*d'entreprise|enterprise\s*number|Kruispuntbank)\s*[:.]?\s*$/i;

const SERVICE_NUMBER = /^0800[\-\s]/;
const DATE_PATTERN_FULL = /^\d{2}[-/.]\d{2}[-/.]\d{4}$/;

const PASSPORT_CONTEXT_BEFORE = /(?:Reisepass|passport|passeport|paspoort|Bisheriger\s+Reisepass)\s*(?:Nr\.?|Nummer|nummer|number|n[°o])?\s*[:.]?\s*$/i;
const SE_ORG_CONTEXT_BEFORE = /(?:org\.?\s*nr\.?|organisationsnummer|organisationsnr|Bolagsverket|företag)\s*[:.]?\s*$/i;

const NUMERIC_TYPES = new Set([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.POSTAL_CODE]);

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
  const applicable = new Set([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID, EntityType.IBAN, EntityType.CHAMBER_OF_COMMERCE]);
  if (!applicable.has(match.patternDef.entityType)) return false;
  const [before] = getContext(text, match.start, match.end);
  return REFERENCE_BEFORE.test(before);
}

function suppressLegal(text: string, match: RawMatch): boolean {
  const applicable = new Set([EntityType.PHONE, EntityType.NATIONAL_ID, EntityType.POSTAL_CODE]);
  if (!applicable.has(match.patternDef.entityType)) return false;
  const [before] = getContext(text, match.start, match.end);
  return LEGAL_BEFORE.test(before);
}

function suppressMath(text: string, match: RawMatch): boolean {
  if (!NUMERIC_TYPES.has(match.patternDef.entityType)) return false;
  const [before, after] = getContext(text, match.start, match.end);
  return MATH_BEFORE.test(before) || MATH_AFTER.test(after);
}

function suppressSequential(_text: string, match: RawMatch): boolean {
  const clean = match.text.replace(/[\s.\-]/g, "");
  return SEQUENTIAL_PATTERNS.test(clean);
}

function suppressYearAsPostal(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.POSTAL_CODE) return false;
  const clean = match.text.trim();
  if (!YEAR_PATTERN.test(clean)) return false;
  const immediateBefore = text.slice(Math.max(0, match.start - 3), match.start);
  if (immediateBefore.endsWith(", ") || immediateBefore.endsWith(",\n")) return false;
  const [before, after] = getContext(text, match.start, match.end);
  return DATE_KEYWORD_NEAR.test(before + after);
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

const NOT_CITY_CODES = new Set([
  "ID","NR","NO","ST","DR","MR","MS","HR","FR","IM","IN","OR","IF","IS","IT","AT","AD","AG","AV",
  "BE","DE","EU","NL","LU","WS","SS","IP",
]);

function suppressPlateInCompound(text: string, match: RawMatch): boolean {
  if (match.patternDef.entityType !== EntityType.LICENSE_PLATE) return false;
  if (match.start >= 3) {
    const before = text.slice(Math.max(0, match.start - 10), match.start);
    if (/[A-Za-zÄÖÜäöüß]{2,}-$/.test(before)) return true;
  }
  const matched = match.text.trim();
  const parts = matched.split(/[\s\-]+/);
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

function suppressRequiresContext(text: string, match: RawMatch): boolean {
  if (!match.patternDef.requiresContext || match.patternDef.contextKeywords.length === 0) return false;
  const [before, after] = getContext(text, match.start, match.end);
  const context = (before + " " + after).toLowerCase();
  return !match.patternDef.contextKeywords.some(kw => context.includes(kw.toLowerCase()));
}

type Suppressor = (text: string, match: RawMatch) => boolean;

const TYPE_SUPPRESSORS: Partial<Record<EntityType, Suppressor[]>> = {
  [EntityType.PHONE]: [suppressCurrency, suppressUnits, suppressReference, suppressMath, suppressPhoneAfterIdLabel, suppressPhoneServiceNumber, suppressPhoneDateOverlap],
  [EntityType.NATIONAL_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressLegal, suppressMath, suppressNatidAsPassport, suppressSeNatidAsOrg],
  [EntityType.SSN]: [suppressCurrency, suppressUnits, suppressReference, suppressMath],
  [EntityType.TAX_ID]: [suppressCurrency, suppressUnits, suppressReference, suppressMath],
  [EntityType.POSTAL_CODE]: [suppressCurrency, suppressUnits, suppressMath, suppressLegal, suppressYearAsPostal, suppressPostalInsideIban, suppressPostalAsHouseNumber],
  [EntityType.IBAN]: [suppressReference],
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
