import { EntityType, type CountryConfig, type PatternDef } from "../../types.js";

/**
 * Helper to create a PatternDef with sensible defaults.
 */
function p(
  entityType: EntityType,
  pattern: string,
  validator: string | null = null,
  description: string = "",
  contextKeywords: string[] = [],
  requiresContext: boolean = false,
): PatternDef {
  return { entityType, pattern, validator, description, contextKeywords, requiresContext };
}

// ---------------------------------------------------------------------------
// DOB context keywords (reused across SHARED patterns)
// ---------------------------------------------------------------------------

const DOB_CONTEXT = [
  "geboren", "geboortedatum", "date de naissance", "né le", "née le",
  "né(e) le", "nee le", "nee(e) le", "date of birth", "DOB",
  "Geburtsdatum", "geboren am", "geboren op", "nascido", "nacido",
  "data di nascita", "nato il", "nata il", "geb.", "geb.datum", "geb ",
  "birth date", "birthday", "naissance", "geboorte", "geburtstag",
];

const DOB_ISO_CONTEXT = [
  "geboren", "geboortedatum", "date de naissance", "né le", "née le",
  "né(e) le", "nee le", "date of birth", "DOB", "Geburtsdatum",
  "geboren am", "geboren op", "geb.", "birth date", "birthday",
  "naissance", "geboorte",
];

const DATE_OF_DEATH_CONTEXT = [
  "overleden", "overlijdensdatum", "date de décès", "décédé le",
  "date of death", "Sterbedatum", "verstorben am", "gestorven",
  "death date", "died on", "mort le", "décès",
];

// ---------------------------------------------------------------------------
// Country configurations
// ---------------------------------------------------------------------------

const SHARED: CountryConfig = {
  code: "SHARED",
  name: "Shared EU Patterns",
  patterns: [
    p(EntityType.EMAIL, String.raw`\b[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}\b`),
    p(EntityType.BIC, String.raw`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`, "bic"),
    p(EntityType.CREDIT_CARD, String.raw`\b(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5})\b`, "luhn"),
    p(EntityType.VIN, String.raw`\b[A-HJ-NPR-Z0-9]{17}\b`, "vin"),
    p(EntityType.IP_ADDRESS, String.raw`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
    p(EntityType.IPV6_ADDRESS, String.raw`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b`),
    p(EntityType.MAC_ADDRESS, String.raw`\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b`, null, "colon/dash"),
    p(EntityType.MAC_ADDRESS, String.raw`\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b`, null, "Cisco"),
    p(EntityType.IMEI, String.raw`\b\d{15}\b`, "imei"),
    p(EntityType.IMEI, String.raw`\b\d{2}[\-\s]\d{6}[\-\s]\d{6}[\-\s]\d\b`, "imei", "formatted"),
    p(EntityType.GPS_COORDINATES, String.raw`-?(?:[1-8]?\d(?:\.\d{4,})|90(?:\.0{4,}))\s*[,;/]\s*-?(?:1[0-7]\d(?:\.\d{4,})|180(?:\.0{4,})|\d{1,2}(?:\.\d{4,}))`),
    p(EntityType.UUID, String.raw`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b`),
    p(EntityType.SOCIAL_HANDLE, String.raw`(?<!\w)@[a-zA-Z][a-zA-Z0-9_.]{1,29}\b`),
    // --- Secret / API Key (known prefixes — always active) ---
    p(EntityType.SECRET, String.raw`\bAKIA[A-Z0-9]{16}\b`, null, "AWS Access Key ID"),
    p(EntityType.SECRET, String.raw`\bgh[poas]_[a-zA-Z0-9]{36,}\b`, null, "GitHub token"),
    p(EntityType.SECRET, String.raw`\bgithub_pat_[a-zA-Z0-9_]{22,}\b`, null, "GitHub fine-grained PAT"),
    p(EntityType.SECRET, String.raw`\b[sp]k_(?:live|test)_[a-zA-Z0-9]{24,}\b`, null, "Stripe key"),
    p(EntityType.SECRET, String.raw`\bsk-(?:ant-)?[a-zA-Z0-9\-_]{20,}\b`, null, "OpenAI/Anthropic key"),
    p(EntityType.SECRET, String.raw`\bxox[bpas]-[a-zA-Z0-9\-]{10,}\b`, null, "Slack token"),
    p(EntityType.SECRET, String.raw`\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b`, null, "JWT token"),
    p(EntityType.SECRET, String.raw`\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b`, null, "SendGrid key"),
    // --- Secret / API Key (entropy-based fallback — requires context) ---
    p(EntityType.SECRET, String.raw`\b[A-Za-z0-9_\-]{32,}\b`, "high_entropy", "High-entropy token", [
      "key", "token", "secret", "password", "credential",
      "api_key", "apikey", "api-key", "auth", "bearer",
      "wachtwoord", "mot de passe", "Passwort", "Schlüssel",
      "clé", "sleutel", "lösenord", "hasło", "heslo",
      "jelszó", "contraseña", "senha", "parola",
    ], true),
    p(EntityType.DOB, String.raw`\b(?:0[1-9]|[12][0-9]|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b`, null, "DD/MM/YYYY", DOB_CONTEXT, true),
    p(EntityType.DATE_OF_DEATH, String.raw`\b(?:0[1-9]|[12][0-9]|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b`, null, "", DATE_OF_DEATH_CONTEXT, true),
    p(EntityType.DOB, String.raw`\b(?:19|20)\d{2}[/.\-](?:0[1-9]|1[0-2])[/.\-](?:0[1-9]|[12][0-9]|3[01])\b`, null, "ISO YYYY-MM-DD", DOB_ISO_CONTEXT, true),
  ],
};

const NL: CountryConfig = {
  code: "NL",
  name: "Netherlands",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[0-9]{9}\b`, "bsn"),
    p(EntityType.NATIONAL_ID, String.raw`\b[0-9]{2,4}\.[0-9]{2,4}\.[0-9]{2,4}\b`, "bsn"),
    p(EntityType.IBAN, String.raw`\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bNL\d{9}B\d{2}\b`, "vat_nl"),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{8}\b`, "kvk", "", ["KvK", "Kamer van Koophandel", "kvk-nummer", "KVK-nummer", "handelsregister", "chamber of commerce"], true),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d[\s\-]?\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d{2}[\s\-]?\d{6,7}\b`),
    p(EntityType.PHONE, String.raw`\b06[\s\-]?\d{4}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b06\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b06[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d{1,2}[\s\-]?\d{2,3}[\s\-]?\d{2}[\s\-]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+31\s?[1-9]\d{0,2}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b`),
    p(EntityType.PASSPORT, String.raw`\b[A-Z][A-Z0-9]{8}\b`, null, "", ["paspoort", "passport", "reisdocument", "travel document", "paspoortnummer", "identiteitsbewijs"], true),
    p(EntityType.LICENSE_PLATE, String.raw`\b(?:[A-Z]{2}[\-\s]?\d{3}[\-\s]?[A-Z]|\d[\-\s]?[A-Z]{3}[\-\s]?\d{2}|\d{2}[\-\s]?[A-Z]{3}[\-\s]?\d|[A-Z]{2}[\-\s]?\d{2}[\-\s]?[A-Z]{2}|\d{2}[\-\s]?[A-Z]{2}[\-\s]?\d{2}|\d[\-\s]?[A-Z]{2}[\-\s]?\d{3})\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\s?[A-Z]{2}\b`),
  ],
};

const BE: CountryConfig = {
  code: "BE",
  name: "Belgium",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{2}\.?\d{2}\.?\d{2}[\-.]?\d{3}\.?\d{2}\b`, "belgian_nn"),
    p(EntityType.IBAN, String.raw`\bBE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bBE\s?0\d{3}\.?\d{3}\.?\d{3}\b`, "belgian_vat"),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b0\d{3}\.?\d{3}\.?\d{3}\b`, null, "", ["KBO", "BCE", "ondernemingsnummer", "numéro d'entreprise", "enterprise number", "bedrijfsnummer"], true),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d{0,2}[/\s.\-]?\d{2,3}[.\s\-]?\d{2,3}[.\s\-]?\d{2,3}\b`),
    p(EntityType.PHONE, String.raw`\+32\s?\d{1,3}[\s.\-]?\d{2,3}[\s.\-]?\d{2}[\s.\-]?\d{2}`),
    p(EntityType.PASSPORT, String.raw`\b[A-Z]{2}\d{6}\b`, null, "", ["paspoort", "passport", "passeport", "reisdocument", "travel document", "document de voyage"], true),
    p(EntityType.DRIVERS_LICENSE, String.raw`\b\d{10}\b`, null, "", ["rijbewijs", "permis de conduire", "driving licence", "driving license", "rijbewijsnummer"], true),
    p(EntityType.LICENSE_PLATE, String.raw`\b[12][\-\s]?[A-Z]{3}[\-\s]?\d{3}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["postcode", "code postal", "postnummer", "postal code", "zip", "B-", "adres", "adresse", "wonende", "woonplaats", "rue", "straat", "laan", "avenue", "boulevard", "plein", "steenweg", "chaussée", "domicilié", "gedomicilieerd", "Levering:", "siège"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
    p(EntityType.HEALTHCARE_PROVIDER, String.raw`\b\d{1}[\-.]?\d{5}[\-.]?\d{2}[\-.]?\d{3}\b`, null, "", ["RIZIV", "INAMI", "arts", "médecin", "zorgverlener", "prestataire", "dokter", "doctor"], true),
  ],
};

const DE: CountryConfig = {
  code: "DE",
  name: "Germany",
  patterns: [
    p(EntityType.TAX_ID, String.raw`\b[1-9]\d{10}\b`, "german_tax_id"),
    p(EntityType.TAX_ID, String.raw`\b[1-9]\d[\s.]?\d{3}[\s.]?\d{3}[\s.]?\d{3}\b`, "german_tax_id"),
    p(EntityType.NATIONAL_ID, String.raw`\b[CFGHJKLMNPRTVWXYZ][0-9A-Z]{8,9}\b`, null, "", ["Personalausweis", "Personalausweisnummer", "Ausweis", "Ausweisnummer", "Ausweis-Nr", "identity card", "Identitätskarte", "Perso", "PA-Nummer"], true),
    p(EntityType.IBAN, String.raw`\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bDE\s?\d{9}\b`, "vat_de"),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d{1,4}[\s/\-]?\d{3,8}\b`),
    p(EntityType.PHONE, String.raw`\+49\s?\d{2,5}[\s/\-]?\d{3,8}\b`),
    p(EntityType.PASSPORT, String.raw`\b[CFGHJK][0-9A-Z]{8,9}\b`, null, "", ["Reisepass", "passport", "Passnummer", "Reisepassnummer", "Reisepass Nummer", "Reisepass-Nr", "Pass Nr"], true),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-ZÄÖÜ]{1,3}[\s\-]?[A-Z]{1,2}[\s\-]?\d{1,4}[EH]?\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{5}\b`, null, "", ["PLZ", "Postleitzahl", "postal code", "postcode", "Anschrift", "Adresse", "Wohnort", "Ort", "Stadt", "wohnt", "wohnhaft", "Straße", "Str.", "Weg", "Platz", "Allee", "Ring"], true),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\bHR[AB]\s?\d{4,6}\b`),
    p(EntityType.SSN, String.raw`\b\d{2}[\s]?\d{6}[\s]?[A-Z][\s]?\d{3}\b`, null, "", ["Rentenversicherung", "RV-Nummer", "Sozialversicherung", "SV-Nummer", "Versicherungsnummer", "Rentenversicherungsnummer", "Sozialversicherungsnummer"], true),
    p(EntityType.TAX_ID, String.raw`\b\d{2,3}/\d{3,4}/\d{4,5}\b`, null, "", ["Steuernummer", "St.-Nr", "StNr", "Finanzamt", "Steuer"], true),
    p(EntityType.TAX_ID, String.raw`\b\d{13}\b`, null, "", ["Steuernummer", "St.-Nr", "StNr", "Finanzamt", "Steuer"], true),
    p(EntityType.HEALTH_INSURANCE, String.raw`\b[A-Z]\d{9}\b`, null, "", ["Versichertennummer", "Krankenversicherung", "KV-Nummer", "Krankenkasse", "GKV", "Versichertenkarte", "Versicherter", "Versicherte", "KVNR", "Krankenversichertennummer"], true),
  ],
};

const AT: CountryConfig = {
  code: "AT",
  name: "Austria",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{4}\s?\d{6}\b`, "austrian_svnr"),
    p(EntityType.IBAN, String.raw`\bAT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bATU\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b0\d{3,4}[\s\-]?\d{5,8}\b`),
    p(EntityType.PHONE, String.raw`\+43\s?\d{3,4}[\s\-]?\d{5,8}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-ZÄÖÜ]{1,2}\s?\d{1,5}\s?[A-Z]{1,2}\b`, null, "", ["Kennzeichen", "Nummernschild", "Kfz-Kennzeichen"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["PLZ", "Postleitzahl", "Adresse", "Anschrift", "Straße", "Str.", "Gasse", "Weg", "Platz", "Postal:", "Wohnort"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const CH: CountryConfig = {
  code: "CH",
  name: "Switzerland",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b756\.\d{4}\.\d{4}\.\d{2}\b`, "swiss_ahv"),
    p(EntityType.NATIONAL_ID, String.raw`\b756\d{10}\b`, "swiss_ahv"),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\bCHE[\-\s]?\d{3}\.?\d{3}\.?\d{3}\b`),
    p(EntityType.VAT, String.raw`\bCHE[\-\s]?\d{3}\.?\d{3}\.?\d{3}\s?(?:MWST|TVA|IVA)\b`),
    p(EntityType.IBAN, String.raw`\bCH\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]\b`, "iban"),
    p(EntityType.PHONE, String.raw`\b0\d{2}\s?\d{3}\s?\d{2}\s?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+41\s?\d{2}\s?\d{3}\s?\d{2}\s?\d{2}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}\s?\d{1,6}\b`, null, "", ["Kontrollschild", "Nummernschild", "plaque", "immatriculation", "Kennzeichen"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["PLZ", "Postleitzahl", "code postal", "NPA", "Adresse", "Anschrift", "adresse", "rue", "Straße", "Str.", "Gasse", "chemin", "Postal:", "Wohnort"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const FR: CountryConfig = {
  code: "FR",
  name: "France",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?\d{2}[0-9AB]?\s?\d{3}\s?\d{3}\s?\d{2}\b`, "french_nir"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{12}\b`, null, "", ["carte d'identité", "CNI", "carte nationale", "identity card", "pièce d'identité"], true),
    p(EntityType.IBAN, String.raw`\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bFR\s?[0-9A-HJ-NP-Z]{2}\s?\d{9}\b`, "vat_fr"),
    p(EntityType.PHONE, String.raw`\b0[1-9][\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+33\s?[1-9][\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?\d{2}`),
    p(EntityType.PASSPORT, String.raw`\b\d{2}[A-Z]{2}\d{5}\b`, null, "", ["passeport", "passport", "numéro de passeport"], true),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}[\-\s]?\d{3}[\-\s]?[A-Z]{2}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b(?:0[1-9]|[1-8]\d|9[0-5]|97[1-6])\d{3}\b`, null, "", ["code postal", "CP", "postal code", "postcode", "adresse", "domicilié", "résidant", "rue", "avenue", "boulevard", "place", "chemin", "allée", "impasse", "ville"], true),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{3}\s?\d{3}\s?\d{3}\b`, null, "", ["SIREN", "siren", "RCS", "entreprise", "immatricul", "numéro d'entreprise", "registre du commerce"], true),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b`, null, "", ["SIRET", "siret", "établissement", "immatricul"], true),
    p(EntityType.TAX_ID, String.raw`\b\d{13}\b`, null, "", ["numéro fiscal", "SPI", "référence fiscale", "avis d'impôt", "impôt sur le revenu", "déclaration fiscale", "fiscal"], true),
  ],
};

const DK: CountryConfig = {
  code: "DK",
  name: "Denmark",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}-\d{4}\b`),
    p(EntityType.NATIONAL_ID, String.raw`\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{6}\b`, "danish_cpr"),
    p(EntityType.IBAN, String.raw`\bDK\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bDK\s?\d{8}\b`, "danish_vat"),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{8}\b`, "danish_vat", "", ["CVR", "CVR-nummer", "virksomhedsnummer", "virksomhedsregisteret"], true),
    p(EntityType.PHONE, String.raw`\b[2-9]\d\s?\d{2}\s?\d{2}\s?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+45\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}\s?\d{2}\s?\d{3}\b`, null, "", ["nummerplade", "registreringsnummer", "reg.nr", "køretøj"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["postnummer", "postby", "postnr", "adresse", "bopæl", "bopælsadresse", "gade", "vej", "allé", "plads", "torv", "stræde", "boulevard", "Arbejdssted"], true),
  ],
};

const SE: CountryConfig = {
  code: "SE",
  name: "Sweden",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{8}[-+]?\d{4}\b`, "swedish_pnr"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}[-+]\d{4}\b`, "swedish_pnr"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{10}\b`, "swedish_pnr"),
    p(EntityType.IBAN, String.raw`\bSE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bSE\d{12}\b`),
    p(EntityType.PHONE, String.raw`\b0\d{1,3}[\-\s]?\d{2,3}[\s]?\d{2,3}[\s]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+46\s?\d{1,3}[\s\-]?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{3}\s?\d{2}[A-Z0-9]\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{3}\s?\d{2}\b`, null, "", ["postnummer", "postort", "postkod", "adress", "bostadsadress", "gatuadress", "boende", "gatan", "vägen", "gata", "väg", "allé", "plats", "torg", "stigen", "Bostadsadress"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{4}\s\d{2}\b`, null, "", ["postnummer", "postort", "postkod", "adress", "bostadsadress", "gatuadress", "boende", "gatan", "vägen", "gata", "väg", "allé"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{6}\b`, null, "", ["postnummer", "postort", "postkod", "adress", "bostadsadress", "gatuadress", "boende", "gatan", "vägen", "gata", "väg", "allé"], true),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{6}-?\d{4}\b`, null, "", ["organisationsnummer", "org.nr", "org nr", "Bolagsverket", "registreringsnummer"], true),
  ],
};

const NO: CountryConfig = {
  code: "NO",
  name: "Norway",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{11}\b`, "norwegian_fnr"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}\s\d{5}\b`, "norwegian_fnr"),
    p(EntityType.IBAN, String.raw`\bNO\d{2}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bNO\s?\d{9}\s?MVA\b`),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b[89]\d{8}\b`, "norwegian_org"),
    p(EntityType.PHONE, String.raw`\b[2-9]\d\s?\d{2}\s?\d{2}\s?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+47\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}\s?\d{5}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{4}\b`, null, "", ["postnummer", "poststed", "postnr", "adresse", "bostedsadresse", "gate", "vei", "veien", "gata", "plass", "stien", "allé"], true),
  ],
};

const FI: CountryConfig = {
  code: "FI",
  name: "Finland",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}[-+ABCDEFYXWVU]\d{3}[0-9A-FHJK-NPR-Y]\b`, "finnish_hetu"),
    p(EntityType.IBAN, String.raw`\bFI\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bFI\d{8}\b`),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b\d{7}-\d\b`, "finnish_business_id"),
    p(EntityType.PHONE, String.raw`\b0\d{1,2}\s?\d{3,4}\s?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\+358\s?\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2,3}[\-\s]?\d{3}\b`, null, "", ["rekisteritunnus", "rekisterinumero", "rekisterikilpi", "ajoneuvo"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{5}\b`, null, "", ["postinumero", "postitoimipaikka", "osoite", "kotiosoite", "katuosoite"], true),
  ],
};

const IS: CountryConfig = {
  code: "IS",
  name: "Iceland",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}-?\d{4}\b`, "icelandic_kt"),
    p(EntityType.IBAN, String.raw`\bIS\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.PHONE, String.raw`\b[3-9]\d{2}\s\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b[3-9]\d{6}\b`, null, "", ["sími", "símanúmer", "farsími", "gsm", "phone", "tel", "hringja", "hringdu", "ná í", "nás á", "nás", "SMS", "sent to"], true),
    p(EntityType.PHONE, String.raw`\+354\s?\d{3}\s?\d{4}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}\s?\d{3}\b`, null, "", ["skráningarnúmer", "bílnúmer", "ökutæki", "bifreið", "plata"], true),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{2}\b`, null, "", ["póstnúmer", "póstfang", "staður", "heimilisfang"], true),
  ],
};

const IT: CountryConfig = {
  code: "IT",
  name: "Italy",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b`, "italian_cf"),
    p(EntityType.IBAN, String.raw`\bIT\d{2}\s?[A-Z]\d{3}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bIT\d{2}[A-Z]\d{22}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bIT\d{11}\b`),
    p(EntityType.PHONE, String.raw`\b3\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b0\d{1,3}[\s\-]?\d{6,8}\b`),
    p(EntityType.PHONE, String.raw`\b0\d{1,2}[\s\-]\d{3}[\s\-]\d{4}\b`),
    p(EntityType.PHONE, String.raw`\+39\s?\d{2,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}\s?\d{3}\s?[A-Z]{2}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{5}\b`, null, "", ["CAP", "codice postale", "codice di avviamento", "indirizzo", "via", "viale", "piazza", "corso", "largo", "vicolo", "Domicilio", "domicilio", "Residenza", "residenza", "Postal:"], true),
  ],
};

const ES: CountryConfig = {
  code: "ES",
  name: "Spain",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{8}[A-Z]\b`, "spanish_dni"),
    p(EntityType.NATIONAL_ID, String.raw`\b[XYZ]\d{7}[A-Z]\b`, "spanish_nie"),
    p(EntityType.IBAN, String.raw`\bES\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bES[A-Z0-9]\d{7}[A-Z0-9]\b`),
    p(EntityType.PHONE, String.raw`\b[679]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b[679]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b[679]\d[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\+34\s?[679]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b\d{4}\s?[BCDFGHJKLMNPRSTVWXYZ]{3}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b(?:0[1-9]|[1-4]\d|5[0-2])\d{3}\b`, null, "", ["código postal", "C.P.", "CP", "dirección", "domicilio", "calle", "avenida", "plaza", "paseo", "camino", "Postal:"], true),
  ],
};

const PT: CountryConfig = {
  code: "PT",
  name: "Portugal",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[1-35-9]\d{8}\b`, "portuguese_nif"),
    p(EntityType.NATIONAL_ID, String.raw`\b[1-35-9]\d{2}[\s.]\d{3}[\s.]\d{3}\b`, "portuguese_nif"),
    p(EntityType.IBAN, String.raw`\bPT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{5}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bPT\d{9}\b`),
    p(EntityType.PHONE, String.raw`\b[29]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b[29]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\+351\s?[29]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z0-9]{2}-[A-Z0-9]{2}-[A-Z0-9]{2}\b`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{4}-\d{3}\b`),
  ],
};

const LU: CountryConfig = {
  code: "LU",
  name: "Luxembourg",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b(?:19|20)\d{2}\s(?:0[1-9]|1[0-2])\s(?:0[1-9]|[12]\d|3[01])\s\d{3}\s\d{2}\b`),
    p(EntityType.NATIONAL_ID, String.raw`\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{5}\b`),
    p(EntityType.IBAN, String.raw`\bLU\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bLU\s?\d{8}\b`, "vat_lu"),
    p(EntityType.PHONE, String.raw`\b(?:2[0-9]|[4-9]\d)[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b`),
    p(EntityType.PHONE, String.raw`\b(?:2[0-9]|[4-9]\d)\d{6}\b`),
    p(EntityType.PHONE, String.raw`\b6[2-9]\d[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\+352\s?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\bL[\-\s]?\d{4}\b`),
    p(EntityType.LICENSE_PLATE, String.raw`\b[A-Z]{2}[\s\-]?\d{3,5}\b`, null, "", ["plaque", "immatriculation", "Kennzeichen", "nummerplaat", "véhicule", "voiture", "Fahrzeug", "immatriculé"], true),
    p(EntityType.CHAMBER_OF_COMMERCE, String.raw`\b[ABCDEFGJ]\s?\d{4,6}\b`, null, "", ["RCS", "Registre de Commerce", "Handelsregister", "registre", "inscrit"], true),
  ],
};

const PL: CountryConfig = {
  code: "PL",
  name: "Poland",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{11}\b`, "polish_pesel"),
    p(EntityType.TAX_ID, String.raw`\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b`, "polish_nip"),
    p(EntityType.IBAN, String.raw`\bPL\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bPL\d{26}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bPL\d{10}\b`),
    p(EntityType.PHONE, String.raw`\b[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b[5-8]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\+48\s?[5-8]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{2}-\d{3}\b`, null, "", ["kod pocztowy", "adres", "ulica", "Postal:", "Address:"]),
  ],
};

const IE: CountryConfig = {
  code: "IE",
  name: "Ireland",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{7}[A-W][ABWTXZ]?\b`, "irish_pps"),
    p(EntityType.IBAN, String.raw`\bIE\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bIE\d{2}[A-Z]{4}\d{14}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bIE\d{7}[A-Z]\b`),
    p(EntityType.PHONE, String.raw`\b0[89]\d[\s\-]?\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b0[89]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b0[1-9]\d{0,2}[\s\-]?\d{5,8}\b`),
    p(EntityType.PHONE, String.raw`\+353\s?\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[A-Z]\d{2}\s?[A-Z0-9]{4}\b`, null, "", ["Eircode", "postcode", "postal code", "address", "Address:", "Postal:"], true),
  ],
};

const UK: CountryConfig = {
  code: "UK",
  name: "United Kingdom",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[ABCD]\b`),
    p(EntityType.HEALTH_INSURANCE, String.raw`\b\d{3}\s?\d{3}\s?\d{4}\b`, "uk_nhs", "", ["NHS", "NHS number", "health number", "NHS no"], true),
    p(EntityType.IBAN, String.raw`\bGB\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bGB\d{2}[A-Z]{4}\d{14}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bGB\d{9}\b`),
    p(EntityType.PHONE, String.raw`\b07[4-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b07[4-9]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b0[12]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b0[12]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b0[12]\d{9,10}\b`),
    p(EntityType.PHONE, String.raw`\+44\s?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b`),
  ],
};

const BG: CountryConfig = {
  code: "BG",
  name: "Bulgaria",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{10}\b`, "bulgarian_egn"),
    p(EntityType.IBAN, String.raw`\bBG\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bBG\d{9,10}\b`),
    p(EntityType.PHONE, String.raw`\b0?[89][789][\s\-]?\d{3}[\s\-]?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\b0?[89][789]\d{7,8}\b`),
    p(EntityType.PHONE, String.raw`\+359\s?[89][789][\s\-]?\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["пощенски код", "пощенски", "адрес", "ул.", "Postal:", "Address:"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const CY: CountryConfig = {
  code: "CY",
  name: "Cyprus",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{8}[A-Z]\b`),
    p(EntityType.IBAN, String.raw`\bCY\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bCY\d{26}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bCY\d{8}[A-Z]\b`),
    p(EntityType.PHONE, String.raw`\b[29]\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b[29]\d[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b[29]\d{7}\b`),
    p(EntityType.PHONE, String.raw`\+357\s?[29]\d[\s\-]?\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["Τ.Κ.", "ταχυδρομικός", "address", "Address:", "Postal:", "διεύθυνση"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const CZ: CountryConfig = {
  code: "CZ",
  name: "Czech Republic",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}/?\d{3,4}\b`, "czech_birth_number"),
    p(EntityType.IBAN, String.raw`\bCZ\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bCZ\d{22}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bCZ\d{8,10}\b`),
    p(EntityType.PHONE, String.raw`\b[67]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b[67]\d{8}\b`),
    p(EntityType.PHONE, String.raw`\+420\s?[67]\d{2}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{3}\s?\d{2}\b`, null, "", ["PSČ", "poštovní", "adresa", "ulice", "Postal:", "Address:"], true),
  ],
};

const SK: CountryConfig = {
  code: "SK",
  name: "Slovakia",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}/?\d{3,4}\b`, "czech_birth_number"),
    p(EntityType.IBAN, String.raw`\bSK\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bSK\d{22}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bSK\d{10}\b`),
    p(EntityType.PHONE, String.raw`\b0?9\d{2}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\+421\s?9\d{2}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{3}\s?\d{2}\b`, null, "", ["PSČ", "poštové", "adresa", "ulica", "Postal:", "Address:"], true),
  ],
};

const EE: CountryConfig = {
  code: "EE",
  name: "Estonia",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[1-6]\d{10}\b`, "estonian_id"),
    p(EntityType.IBAN, String.raw`\bEE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bEE\d{18}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bEE\d{9}\b`),
    p(EntityType.PHONE, String.raw`\b5\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b5\d{7}\b`),
    p(EntityType.PHONE, String.raw`\+372\s?5\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{5}\b`, null, "", ["postiindeks", "sihtnumber", "aadress", "address", "Address:", "Postal:"], true),
  ],
};

const LT: CountryConfig = {
  code: "LT",
  name: "Lithuania",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[1-6]\d{10}\b`, "estonian_id"),
    p(EntityType.IBAN, String.raw`\bLT\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bLT\d{18}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bLT\d{9,12}\b`),
    p(EntityType.PHONE, String.raw`\b6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b6\d{7}\b`),
    p(EntityType.PHONE, String.raw`\b8[\s\-]?6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\+370\s?6\d{2}[\s\-]?\d{2}[\s\-]?\d{3}`),
    p(EntityType.POSTAL_CODE, String.raw`\bLT-\d{5}\b`),
  ],
};

const LV: CountryConfig = {
  code: "LV",
  name: "Latvia",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{6}-\d{5}\b`),
    p(EntityType.NATIONAL_ID, String.raw`\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{7}\b`, null, "", ["personas kods", "PK", "identifikācijas"], true),
    p(EntityType.IBAN, String.raw`\bLV\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bLV\d{2}[A-Z]{4}\d{13}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bLV\d{11}\b`),
    p(EntityType.PHONE, String.raw`\b[2]\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b[2]\d{7}\b`),
    p(EntityType.PHONE, String.raw`\+371\s?[2]\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\bLV-\d{4}\b`),
  ],
};

const HR: CountryConfig = {
  code: "HR",
  name: "Croatia",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{11}\b`, "croatian_oib"),
    p(EntityType.IBAN, String.raw`\bHR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bHR\d{2}\s\d{4}\s\d{4}\s\d{4}\s\d{5}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bHR\d{19}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bHR\d{11}\b`),
    p(EntityType.PHONE, String.raw`\b0?9[12579][\s\-]?\d{3}[\s\-]?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\b0?9[12579]\d{7,8}\b`),
    p(EntityType.PHONE, String.raw`\+385\s?9[12579][\s\-]?\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-5]\d{4}\b`, null, "", ["poštanski broj", "poštanski", "adresa", "ulica", "Postal:", "Address:"], true),
  ],
};

const HU: CountryConfig = {
  code: "HU",
  name: "Hungary",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{9}\b`, "hungarian_taj"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{3}\s\d{3}\s\d{3}\b`, "hungarian_taj"),
    p(EntityType.TAX_ID, String.raw`\b8\d{9}\b`, null, "", ["adóazonosító", "adószám", "adóazonosító jel"], true),
    p(EntityType.VAT, String.raw`\bHU\d{8,11}\b`, null, "", ["adószám", "ÁFA"]),
    p(EntityType.IBAN, String.raw`\bHU\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bHU\d{26}\b`, "iban"),
    p(EntityType.PHONE, String.raw`\b06\s?\d{1,2}[\s\-]?\d{3}[\s\-]?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\+36\s?\d{1,2}[\s\-]?\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["irányítószám", "postai", "cím", "utca", "Postal:", "Address:"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const RO: CountryConfig = {
  code: "RO",
  name: "Romania",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b[1-8]\d{12}\b`, "romanian_cnp"),
    p(EntityType.IBAN, String.raw`\bRO\d{2}[A-Z]{4}\d{16}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bRO\d{2,10}\b`),
    p(EntityType.PHONE, String.raw`\b0?7[2-9]\d{1}[\s\-]?\d{3}[\s\-]?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\b0?7[2-9]\d{7,8}\b`),
    p(EntityType.PHONE, String.raw`\+40\s?7[2-9]\d{1}[\s\-]?\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{6}\b`, null, "", ["cod poștal", "cod postal", "adresă", "strada", "Postal:", "Address:"], true),
  ],
};

const EL: CountryConfig = {
  code: "EL",
  name: "Greece",
  patterns: [
    p(EntityType.TAX_ID, String.raw`\b\d{9}\b`, "greek_afm"),
    p(EntityType.NATIONAL_ID, String.raw`\b\d{11}\b`, "greek_amka"),
    p(EntityType.IBAN, String.raw`\bGR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bGR\d{25}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bEL\d{9}\b`),
    p(EntityType.PHONE, String.raw`\b69\d[\s\-]?\d{3,4}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b69\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b2\d{1,3}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b`),
    p(EntityType.PHONE, String.raw`\+30\s?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b\d{3}\s?\d{2}\b`, null, "", ["Τ.Κ.", "ταχυδρομικός", "address", "Address:", "Postal:", "διεύθυνση", "οδός"], true),
  ],
};

const SI: CountryConfig = {
  code: "SI",
  name: "Slovenia",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{13}\b`, "slovenian_emso"),
    p(EntityType.IBAN, String.raw`\bSI\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bSI\d{17}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bSI\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b0?[34567]\d{1}[\s\-]?\d{3}[\s\-]?\d{3}\b`),
    p(EntityType.PHONE, String.raw`\b0?[34567]\d{7}\b`),
    p(EntityType.PHONE, String.raw`\+386\s?[34567]\d{1}[\s\-]?\d{3}[\s\-]?\d{3}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[1-9]\d{3}\b`, null, "", ["poštna številka", "poštna", "naslov", "ulica", "Postal:", "Address:"], true),
    p(EntityType.POSTAL_CODE, String.raw`(?<=, )[1-9]\d{3}(?= [A-Z])`),
  ],
};

const MT: CountryConfig = {
  code: "MT",
  name: "Malta",
  patterns: [
    p(EntityType.NATIONAL_ID, String.raw`\b\d{5,7}[MGAPLHBZ]\b`),
    p(EntityType.IBAN, String.raw`\bMT\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{3}\b`, "iban"),
    p(EntityType.IBAN, String.raw`\bMT\d{2}[A-Z]{4}\d{5}[A-Z0-9]{18}\b`, "iban"),
    p(EntityType.VAT, String.raw`\bMT\d{8}\b`),
    p(EntityType.PHONE, String.raw`\b[79]\d{3}[\s\-]?\d{4}\b`),
    p(EntityType.PHONE, String.raw`\b[79]\d{7}\b`),
    p(EntityType.PHONE, String.raw`\+356\s?[79]\d{3}[\s\-]?\d{3,4}`),
    p(EntityType.POSTAL_CODE, String.raw`\b[A-Z]{3}\s?\d{4}\b`, null, "", ["kodiċi postali", "postcode", "address", "Address:", "Postal:"], true),
  ],
};

// ---------------------------------------------------------------------------
// Export all configs as a single Record
// ---------------------------------------------------------------------------

export const COUNTRY_CONFIGS: Record<string, CountryConfig> = {
  SHARED,
  NL,
  BE,
  DE,
  AT,
  CH,
  FR,
  DK,
  SE,
  NO,
  FI,
  IS,
  IT,
  ES,
  PT,
  LU,
  PL,
  IE,
  UK,
  BG,
  CY,
  CZ,
  SK,
  EE,
  LT,
  LV,
  HR,
  HU,
  RO,
  EL,
  SI,
  MT,
};
