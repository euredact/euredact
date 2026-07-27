/**
 * Assertion tests for the detection contract.
 *
 * Mirrors the Python suite (tests/test_bic.py, test_postal_code.py,
 * test_international.py, test_api_contract.py) so the two engines cannot drift
 * silently. Run with `npm run test:spec`.
 */

import assert from "node:assert/strict";
import { EuRedact } from "../sdk.js";
import { EntityType, LEGACY_TYPE_ALIASES } from "../types.js";
import { setBicRegistry } from "../rules/bicRegistry.js";
import { resolveCountryCode } from "../rules/engine.js";
import { validateBic, validateE164, validateIban } from "../rules/validators.js";

const sdk = new EuRedact();

let passed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
  } catch (e) {
    failures.push(`${name}\n      ${e instanceof Error ? e.message.split("\n")[0] : e}`);
  }
}

/** Detections of one type, as text. */
function of(text: string, country: string | null, type: EntityType): string[] {
  const r = sdk.redact(text, country ? { countries: [country] } : {});
  return r.detections.filter(d => d.entityType === type).map(d => d.text);
}

// ── BUG 1: BIC is gated, not shape-only ────────────────────────────────

const BIC_MUST_NOT: Array<[string, string]> = [
  ["DRINGEND", "DE"], ["MAANDELIJKS", "NL"], ["BENEFICIARY", "NL"],
  ["CUSTOMER", "NL"], ["GEGEVENS", "NL"], ["HOSPITAL", "UK"], ["PERSONAL", "UK"],
  ["DIAGNOSE", "DE"], ["ANAMNESE", "DE"], ["NACHNAME", "DE"], ["HELPDESK", "NL"],
  ["INCIDENT", "NL"], ["PAIEMENT", "FR"], ["FOURNISSEUR", "FR"], ["REFERENTIES", "NL"],
  ["CONCLUSIONS", "FR"], ["AUTOMATIQUE", "FR"], ["ARBEITGEBER", "DE"],
  ["ARBEITSZEIT", "DE"], ["NEXALINK", "NL"],
];
for (const [token, cc] of BIC_MUST_NOT) {
  test(`BIC rejects bare word ${token}`, () =>
    assert.deepEqual(of(token, cc, EntityType.BIC), []));
}

test("BIC rejects heading in context", () =>
  assert.deepEqual(of("QUEEN ELIZABETH HOSPITAL BIRMINGHAM", "UK", EntityType.BIC), []));
test("BIC rejects label-colon heading", () =>
  assert.deepEqual(of("DRINGEND: Frau Yilmaz ist verantwortlich.", "DE", EntityType.BIC), []));
test("BIC rejects all-caps line", () =>
  assert.deepEqual(of("GEGEVENS VAN DE BETROKKENE", "NL", EntityType.BIC), []));
test("BIC gate 0 beats context (word + IBAN nearby)", () =>
  assert.deepEqual(
    of("GEGEVENS\nIBAN: NL91 ABNA 0417 1643 00\nDeze gegevens zijn vertrouwelijk.", "NL", EntityType.BIC),
    []));

for (const bic of ["BBRUBEBB", "KREDBEBB", "BCEELULL", "ARSPBE22", "BNPAFRPPXXX", "GIBAATWWXXX", "ABNANL2A"]) {
  test(`BIC tier 1 keeps ${bic}`, () => assert.deepEqual(of(bic, "BE", EntityType.BIC), [bic]));
}
for (const bic of ["ABNANL9X", "INGBNL7Q", "BUNQNL4T", "TRIONL3M"]) {
  test(`BIC tier 1 keeps synthetic suffix ${bic}`, () =>
    assert.deepEqual(of(bic, "NL", EntityType.BIC), [bic]));
}
test("BIC tier 2 keyword", () =>
  assert.deepEqual(of("BIC: VOLKNL2A", "NL", EntityType.BIC), ["VOLKNL2A"]));
test("BIC tier 2 SWIFT-Code", () =>
  assert.deepEqual(of("SWIFT-Code: MEDBFRPP", "FR", EntityType.BIC), ["MEDBFRPP"]));
test("BIC tier 2 IBAN same line", () =>
  assert.deepEqual(of("Overboeking naar NL91 ABNA 0417 1643 00 via SOLAESMM.", "NL", EntityType.BIC), ["SOLAESMM"]));
test("BIC tier 2 cue several lines away in one record", () =>
  assert.deepEqual(
    of("Overzicht\nIBAN: NL91 ABNA 0417 1643 00\nBedrag: 1.250,00 EUR\nDe tegenpartij gebruikt BOREHU2B hiervoor.",
       "NL", EntityType.BIC),
    ["BOREHU2B"]));
test("BIC label on line above (table layout)", () =>
  assert.deepEqual(of("BIC\nVIKKDKKK", "DK", EntityType.BIC), ["VIKKDKKK"]));
test("BIC no tier: mid-sentence, no cue", () =>
  assert.deepEqual(of("Das Projekt NEXALINK wurde gestartet.", "DE", EntityType.BIC), []));
test("BIC registry provider is consulted", () => {
  assert.deepEqual(of("NEXABE22 in het dossier.", "BE", EntityType.BIC), []);
  setBicRegistry(["NEXABE"]);
  sdk.clear();
  assert.deepEqual(of("NEXABE22 in het dossier.", "BE", EntityType.BIC), ["NEXABE22"]);
  setBicRegistry(null);
  sdk.clear();
});
test("validateBic requires a real ISO country", () => {
  assert.equal(validateBic("DEUTDEFF"), true);
  assert.equal(validateBic("AABORIHH"), false); // "RI" is not ISO 3166
});

// ── BUG 7: space-separated BICs ────────────────────────────────────────

for (const [bic, cc] of [["RZBA AT WW", "AT"], ["NICA BE BB", "BE"], ["GIBA AT WW", "AT"]] as const) {
  test(`spaced BIC ${bic}`, () => assert.deepEqual(of(`SWIFT: ${bic}`, cc, EntityType.BIC), [bic]));
}
test("spaced BIC does not absorb a following word", () =>
  assert.deepEqual(of("SWIFT: GEBABEBB KBC", "BE", EntityType.BIC), ["GEBABEBB"]));
test("spaced BIC does not span a line break", () =>
  assert.deepEqual(of("SWIFT: RZBA\nAT WW", "AT", EntityType.BIC), []));

// ── BUG 2: postal codes must not shred longer identifiers ──────────────

const inAddressDoc = (s: string) => `Anschrift: Hauptstrasse 5, 1010 Wien\n${s}\n`;
const SHRED = [
  "SV-Nummer: 1268 040390",
  "Policen-Nr. 0456.2398.71-02",
  "e-card Nr. 1234 5678 925",
  "Telefon: +43 664 8213 907",
  "Sachbearbeiter: Huber, DiNr. 4471",
  "Die Abteilung hat 2140 1.912 Patientinnen behandelt.",
  "Rechnung 2025/4471/02",
  "Seriennummer 7788-9900",
  "Konto 1234.5678",
  "Bestellnummer: 8899 0011",
];
for (const s of SHRED) {
  test(`postal not claimed in: ${s.slice(0, 34)}`, () =>
    assert.deepEqual(of(inAddressDoc(s), "AT", EntityType.POSTAL_CODE), ["1010"]));
}

const ADDRESSES: Array<[string, string, string[]]> = [
  ["Kaerntner Strasse 12/3, 1010 Wien", "AT", ["1010"]],
  ["Grote Markt 1, 2000 Antwerpen", "BE", ["2000"]],
  ["Bahnhofplatz 3, 5400 Baden", "CH", ["5400"]],
  ["PLZ: 1010\nOrt: Wien", "AT", ["1010"]],
  ["Anschrift: Musterstrasse 5, 10115 Berlin", "DE", ["10115"]],
  // Sentence-final: the separator rule must require a digit on the far side,
  // or every postal code ending a sentence is discarded.
  ["Domicilio: Palma, 13867. Pagos a IBAN.", "ES", ["13867"]],
  ["Adresse: Fribourg, 8386. Auszahlung folgt.", "CH", ["8386"]],
  ["Anschrift: Hauptstrasse 5, 1010 Wien.", "AT", ["1010"]],
  ["Anschrift: Hauptstrasse 5, 1010 Wien, Oesterreich", "AT", ["1010"]],
];
for (const [text, cc, expected] of ADDRESSES) {
  test(`postal detected: ${text.slice(0, 34)}`, () =>
    assert.deepEqual(of(text, cc, EntityType.POSTAL_CODE), expected));
}

test("structured postal forms unaffected (NL letters)", () =>
  assert.deepEqual(of("Postcode 1012 AB Amsterdam", "NL", EntityType.POSTAL_CODE), ["1012 AB"]));
test("postal never overlaps a structured span", () => {
  const r = sdk.redact("Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390", { countries: ["AT"] });
  const structured = new Set([EntityType.PHONE, EntityType.SSN, EntityType.NATIONAL_ID, EntityType.BANK_ACCOUNT, EntityType.VAT]);
  for (const p of r.detections.filter(d => d.entityType === EntityType.POSTAL_CODE)) {
    for (const s of r.detections.filter(d => structured.has(d.entityType as EntityType))) {
      assert.ok(p.end <= s.start || p.start >= s.end, `${p.text} overlaps ${s.text}`);
    }
  }
});

// ── BUG 3: international + Austrian national phones ────────────────────

const PHONES: Array<[string, string]> = [
  ["+43 664 8213 907", "AT"], ["+43 664 8213907", "AT"], ["+43 1 53460 2215", "AT"],
  ["+43 (0)664 8213907", "AT"], ["+43-664-8213907", "AT"],
  ["+32 498 22 67 31", "BE"], ["+32 (0)2 555 12 34", "BE"],
  ["+31 20 916 34 70", "NL"], ["+31 6 23 45 67 89", "NL"], ["+31 (0)6 12345678", "NL"],
  ["+49 30 1234 5678", "DE"], ["+49 (0)30 12345678", "DE"],
  ["+33 6 12 34 56 78", "FR"], ["+353 87 123 4567", "IE"], ["+41 79 123 45 67", "CH"],
  ["+44 7911 123456", "UK"], ["+34 612 34 56 78", "ES"], ["+351 21 123 4567", "PT"],
  ["+48 22 123 45 67", "PL"], ["+47 412 34 567", "NO"], ["+352 26 20 1", "LU"],
  ["+420 2 1234 5678", "CZ"], ["+40 21 123 4567", "RO"],
  ["01 53460 2215", "AT"], ["0664 8213907", "AT"], ["0512 507 1234", "AT"],
];
for (const [num, cc] of PHONES) {
  test(`phone detected: ${num}`, () => {
    const got = of(`Tel: ${num} erreichbar.`, cc, EntityType.PHONE);
    assert.ok(got.length > 0, `${num} not detected`);
    assert.ok(got[0].replace(/\s/g, "").includes(num.replace(/\s/g, "")), `${num} not whole: got ${got[0]}`);
  });
}
test("foreign phone detected under another country", () =>
  assert.ok(of("Kontakt: +32 498 22 67 31", "AT", EntityType.PHONE).length > 0));
test("short numeric fragment is not a phone", () =>
  assert.deepEqual(of("Zimmer +43 12", "AT", EntityType.PHONE), []));
test("date fragment is not an AT phone", () =>
  assert.deepEqual(of("Termin am 01 2025 vereinbart", "AT", EntityType.PHONE), []));
test("validateE164 bounds", () => {
  assert.equal(validateE164("+3161234567"), true);
  assert.equal(validateE164("+431234"), false);
  assert.equal(validateE164("+43 664 8213 907 1234 5678"), false);
  assert.equal(validateE164("0664 8213907"), false);
  assert.equal(validateE164("+43 (0)664 8213907"), true);
});

// ── BUG 4: IBANs are self-identifying ──────────────────────────────────

const IBANS: Array<[string, string]> = [
  ["BE68 5390 0754 7034", "AT"], ["NL91 ABNA 0417 1643 00", "AT"],
  ["DE89 3704 0044 0532 0130 00", "BE"], ["FR76 3000 6000 0112 3456 7890 189", "DE"],
  ["AT61 1904 3002 3457 3201", "NL"], ["CH93 0076 2011 6238 5295 7", "FR"],
  ["GB33 BUKB 2020 1555 5555 55", "IE"], ["IE29 AIBK 9311 5212 3456 78", "UK"],
  ["ES91 2100 0418 4502 0005 1332", "PT"], ["PT50 0002 0123 1234 5678 9015 4", "ES"],
  ["LU28 0019 4006 4475 0000", "BE"], ["DK50 0040 0440 1162 43", "SE"],
  ["NO93 8601 1117 947", "DK"], ["FI21 1234 5600 0007 85", "NO"],
  ["SE45 5000 0000 0583 9825 7466", "FI"], ["PL61 1090 1014 0000 0712 1981 2874", "CZ"],
];
for (const [iban, cc] of IBANS) {
  test(`IBAN detected under countries=[${cc}]: ${iban.slice(0, 12)}`, () =>
    assert.deepEqual(of(`Betaling naar ${iban} uitgevoerd.`, cc, EntityType.BANK_ACCOUNT), [iban]));
}
test("IBAN detected with no country requested", () =>
  assert.deepEqual(of("Payment to BE68 5390 0754 7034 please.", null, EntityType.BANK_ACCOUNT), ["BE68 5390 0754 7034"]));
test("IBAN does not absorb a following uppercase word", () =>
  assert.deepEqual(of("IBAN BE68 5390 0754 7034 KBC BRUSSEL", "AT", EntityType.BANK_ACCOUNT), ["BE68 5390 0754 7034"]));
test("invalid checksum IBAN is rejected", () =>
  assert.deepEqual(of("Rekening BE68 5390 0754 7035 hier.", "AT", EntityType.BANK_ACCOUNT), []));
test("validateIban length table", () => {
  assert.equal(validateIban("NO93 8601 1117 947"), true);
  assert.equal(validateIban("BE68 5390 0754 70345"), false);
});

// ── BUG 5: country codes ───────────────────────────────────────────────

test("GB and UK are equivalent", () => {
  const t = "NHS Number: 943 476 5919, postcode SW1A 1AA";
  assert.equal(sdk.redact(t, { countries: ["GB"] }).redactedText,
               sdk.redact(t, { countries: ["UK"] }).redactedText);
});
test("GB loads the UK patterns, not just SHARED", () =>
  assert.ok(of("NHS Number: 943 476 5919", "GB", EntityType.HEALTH_INSURANCE).length > 0));
test("GR and EL are equivalent", () =>
  assert.equal(resolveCountryCode("GR"), resolveCountryCode("EL")));
test("codes are normalised", () => {
  for (const c of ["GB", "gb", " GB ", "Gb"]) assert.equal(resolveCountryCode(c), "UK");
});
test("unknown code does not throw and keeps shared patterns", () => {
  const r = sdk.redact("Call +44 7911 123456, mail a@b.com, IBAN BE68 5390 0754 7034", { countries: ["ZZ"] });
  const types = new Set(r.detections.map(d => d.entityType));
  for (const t of [EntityType.PHONE, EntityType.EMAIL, EntityType.BANK_ACCOUNT]) assert.ok(types.has(t), `missing ${t}`);
});
test("resolveCountryCode returns null for unknown", () =>
  assert.equal(resolveCountryCode("ZZ"), null));

// ── BUG 6: canonical type names ────────────────────────────────────────

test("BANK_ACCOUNT is the emitted name", () => {
  const r = sdk.redact("Rekening: BE68 5390 0754 7034", { countries: ["BE"] });
  assert.equal(r.detections[0].entityType, "BANK_ACCOUNT");
});
test("placeholder uses the canonical name", () =>
  assert.equal(sdk.redact("Rekening: BE68 5390 0754 7034", { countries: ["BE"] }).redactedText,
               "Rekening: [BANK_ACCOUNT]"));
test("EntityType.IBAN is an alias of BANK_ACCOUNT", () =>
  assert.equal(EntityType.IBAN, EntityType.BANK_ACCOUNT));
test("legacy alias map is published", () =>
  assert.equal(LEGACY_TYPE_ALIASES["IBAN"], "BANK_ACCOUNT"));
test("no emitted type name is a legacy alias", () => {
  const emitted = new Set(Object.values(EntityType));
  for (const legacy of Object.keys(LEGACY_TYPE_ALIASES)) assert.ok(!emitted.has(legacy as EntityType));
});

// ── Known-issue fixes (0.3.0) ──────────────────────────────────────────

const COUNTRY_PREFIXED: Array<[string, string, string[]]> = [
  ["Anschrift: A-1010 Wien", "AT", ["1010"]],
  ["Adres: B-2000 Antwerpen", "BE", ["2000"]],
  ["Anschrift: D-10115 Berlin", "DE", ["10115"]],
];
for (const [text, cc, expected] of COUNTRY_PREFIXED) {
  test(`country-prefixed postal is not a subtraction: ${text.slice(0, 28)}`, () =>
    assert.deepEqual(of(text, cc, EntityType.POSTAL_CODE), expected));
}
test("maths context still suppresses a postal code", () =>
  assert.deepEqual(of("Ergebnis = 1010 Punkte", "AT", EntityType.POSTAL_CODE), []));

test("residence phrasing counts as postal context (nl)", () =>
  assert.deepEqual(of("De betrokkene is wonende te 2000 Antwerpen.", "BE", EntityType.POSTAL_CODE), ["2000"]));
test("residence phrasing counts as postal context (fr)", () =>
  assert.deepEqual(of("Le titulaire est domicilié à 1000 Bruxelles.", "BE", EntityType.POSTAL_CODE), ["1000"]));

// JavaScript's \w and \b are ASCII-only; these failed before 0.3.0.
const UNICODE_EMAILS: Array<[string, string]> = [
  ["Mail: petras_ž@example.com", "petras_ž@example.com"],
  ["Contact: józef.wiśniewski@poczta.pl", "józef.wiśniewski@poczta.pl"],
  ["Mail: αλέξης@example.gr", "αλέξης@example.gr"],
  ["Mail: jan@test.nl", "jan@test.nl"],
];
for (const [text, expected] of UNICODE_EMAILS) {
  test(`unicode email local part: ${expected}`, () =>
    assert.deepEqual(of(text, "NL", EntityType.EMAIL), [expected]));
}
test("unicode social handle", () =>
  assert.deepEqual(of("Handle: @žilvinas", "NL", EntityType.SOCIAL_HANDLE), ["@žilvinas"]));
test("email is not misread as a social handle", () => {
  const types = new Set(sdk.redact("Contact: petras_ž@simnet.is", { countries: ["NL"] }).detections.map(d => d.entityType));
  assert.ok(types.has(EntityType.EMAIL));
  assert.ok(!types.has(EntityType.SOCIAL_HANDLE));
});

// ── Report ─────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
