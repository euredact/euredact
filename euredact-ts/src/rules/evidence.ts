/**
 * Country evidence: what a document says about which country it belongs to.
 *
 * Some entities carry their country in the string — an IBAN's country code, a
 * `+CC` dialling prefix, a VAT prefix, an email ccTLD. Those are used to work
 * out which country a document belongs to, which in turn decides which
 * national scheme owns an ambiguous value elsewhere in the same document.
 * 36.6% of national-ID values in the corpus validate under more than one
 * country's checksum, so without this the engine cannot tell a Dutch BSN from
 * a Polish PESEL.
 *
 * Evidence influences **scoring only**. It ranks candidates that already exist
 * and annotates the result; it never decides what is looked for. A wrong
 * inference must not be able to cause a miss.
 *
 * Weights are derived, not chosen — measured as P(document country = X |
 * signal claims X) across the corpus. Kept identical to the Python SDK's
 * `rules/evidence.py`; re-derive there and port, rather than tuning by feel.
 */

import { EntityType, type CountryEvidence, type Detection } from "../types.js";

// ── Derived weights ─────────────────────────────────────────────────────
//
// Measured on 152,300 documents:
//
//   signal          agree    total   P(doc=X|signal)   raw log-odds
//   e164Prefix     41,402   41,402          0.9999             9.21
//   bicCountry      2,588    2,588          0.9999             9.21
//   emailTld       97,865   98,949          0.9890             4.50
//   vatPrefix      19,022   20,136          0.9447             2.84
//   ibanPrefix    110,572  126,428          0.8746             1.94
//
// The IBAN prefix being the *weakest* signal is real and worth knowing: a
// Belgian IBAN in a Dutch invoice is ordinary, so the account's country is only
// weak evidence about the document's.
//
// The perfect scores are capped. They are perfect because the generator emits
// country-consistent values, not because a foreign mobile number never appears
// in a real document. Treating a synthetic 1.0 as certainty would make a single
// phone number unfalsifiable by any amount of contrary evidence.
const MAX_LOG_ODDS = 4.0;

export const WEIGHTS: Record<string, number> = {
  e164Prefix: Math.min(9.21, MAX_LOG_ODDS),
  bicCountry: Math.min(9.21, MAX_LOG_ODDS),
  emailTld: Math.min(4.5, MAX_LOG_ODDS),
  vatPrefix: 2.84,
  ibanPrefix: 1.94,
  declared: 2.0, // the caller's `countries`, a prior rather than a measurement
};

// ── Signal tables ───────────────────────────────────────────────────────

/**
 * E.164 calling code -> country, for the countries this engine supports. Codes
 * are unique within this set; a shared code (+1, +7) would have to emit
 * evidence for every candidate country rather than one.
 */
export const DIALLING_CODES: Record<string, string> = {
  "43": "AT", "32": "BE", "359": "BG", "41": "CH", "357": "CY", "420": "CZ",
  "49": "DE", "45": "DK", "372": "EE", "30": "EL", "34": "ES", "358": "FI",
  "33": "FR", "385": "HR", "36": "HU", "353": "IE", "354": "IS", "39": "IT",
  "370": "LT", "352": "LU", "371": "LV", "356": "MT", "31": "NL", "47": "NO",
  "48": "PL", "351": "PT", "40": "RO", "46": "SE", "386": "SI", "421": "SK",
  "44": "UK",
};

/**
 * ccTLD -> country. Deliberately excludes .eu/.com/.org/.net: those are not
 * weak evidence, they are no evidence, and treating them as weak would let a
 * .com address outvote a genuine national signal.
 */
export const CC_TLDS: Record<string, string> = {
  at: "AT", be: "BE", bg: "BG", ch: "CH", cy: "CY", cz: "CZ",
  de: "DE", dk: "DK", ee: "EE", gr: "EL", es: "ES", fi: "FI",
  fr: "FR", hr: "HR", hu: "HU", ie: "IE", is: "IS", it: "IT",
  lt: "LT", lu: "LU", lv: "LV", mt: "MT", nl: "NL", no: "NO",
  pl: "PL", pt: "PT", ro: "RO", se: "SE", si: "SI", sk: "SK",
  uk: "UK",
};

/** VAT prefixes that are not the ISO code: Greece trades as EL, Northern
 *  Ireland as XI. Naive alpha-2 handling gets both wrong. */
const VAT_PREFIX_OVERRIDES: Record<string, string> = { EL: "EL", XI: "UK" };

type Emitter = (det: Detection) => CountryEvidence[];

const emitIban: Emitter = (det) => {
  const code = det.text.slice(0, 2).toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return [];
  return [{ country: code, source: "ibanPrefix", logOdds: WEIGHTS.ibanPrefix,
            span: [det.start, det.end] }];
};

const emitE164: Emitter = (det) => {
  if (!det.text.trimStart().startsWith("+")) return [];
  const digits = det.text.replace(/\D/g, "");
  for (const len of [3, 2]) {
    const country = DIALLING_CODES[digits.slice(0, len)];
    if (country) {
      return [{ country, source: "e164Prefix", logOdds: WEIGHTS.e164Prefix,
                span: [det.start, det.end] }];
    }
  }
  return [];
};

const emitVat: Emitter = (det) => {
  const prefix = det.text.slice(0, 2).toUpperCase();
  if (!/^[A-Z]{2}$/.test(prefix)) return [];
  const country = VAT_PREFIX_OVERRIDES[prefix] ?? prefix;
  return [{ country, source: "vatPrefix", logOdds: WEIGHTS.vatPrefix,
            span: [det.start, det.end] }];
};

const emitBic: Emitter = (det) => {
  const clean = det.text.replace(/ /g, "").toUpperCase();
  if (clean.length < 6) return [];
  return [{ country: clean.slice(4, 6), source: "bicCountry",
            logOdds: WEIGHTS.bicCountry, span: [det.start, det.end] }];
};

const emitTld: Emitter = (det) => {
  const parts = det.text.split(".");
  const country = CC_TLDS[parts[parts.length - 1].toLowerCase()];
  if (!country) return [];
  return [{ country, source: "emailTld", logOdds: WEIGHTS.emailTld,
            span: [det.start, det.end] }];
};

/** Dispatch by entity type, mirroring the suppressor tables. */
const TYPE_EMITTERS: Record<string, Emitter[]> = {
  [EntityType.BANK_ACCOUNT]: [emitIban],
  [EntityType.PHONE]: [emitE164],
  [EntityType.VAT]: [emitVat],
  [EntityType.BIC]: [emitBic],
  [EntityType.EMAIL]: [emitTld],
};

/** Entity types that can carry country evidence. */
export const EVIDENCE_TYPES: ReadonlySet<string> = new Set(Object.keys(TYPE_EMITTERS));

/**
 * Country evidence carried by *detections*, in document order.
 *
 * Deduplicated by (span, source): several countries' patterns can match the
 * same IBAN, and counting that span once per pattern would let a single entity
 * outvote the rest of the document.
 */
export function collect(detections: Detection[]): CountryEvidence[] {
  const evidence: CountryEvidence[] = [];
  const seen = new Set<string>();
  for (const det of detections) {
    for (const emit of TYPE_EMITTERS[det.entityType as string] ?? []) {
      for (const ev of emit(det)) {
        const key = `${ev.span[0]}:${ev.span[1]}:${ev.source}`;
        if (!seen.has(key)) {
          seen.add(key);
          evidence.push(ev);
        }
      }
    }
  }
  // Document order, not pattern-registration order: this list is an audit
  // trail, and a reader checking it against the text should not have to jump
  // around. Also keeps the two SDKs byte-comparable.
  evidence.sort((a, b) => a.span[0] - b.span[0] || a.span[1] - b.span[1]);
  return evidence;
}

/**
 * Sum evidence into a per-country log-odds score.
 *
 * Returns a weighted set, never a single winner: a Belgian supplier invoicing a
 * German customer is not "70% Belgian", both countries are genuinely present,
 * and an ambiguous value must be resolvable against either.
 */
export function accumulate(
  evidence: CountryEvidence[],
  declared?: Iterable<string> | null,
): Map<string, number> {
  const scores = new Map<string, number>();
  for (const ev of evidence) {
    scores.set(ev.country, (scores.get(ev.country) ?? 0) + ev.logOdds);
  }
  for (const country of declared ?? []) {
    if (country !== "SHARED" && country !== "CUSTOM") {
      scores.set(country, (scores.get(country) ?? 0) + WEIGHTS.declared);
    }
  }
  return scores;
}

/**
 * Convert per-country log-odds into confidences in [0, 1].
 *
 * Each country is scored independently — a logistic on its own log-odds —
 * because document countries are not mutually exclusive. A Belgian supplier
 * invoicing a German customer is genuinely both; softmaxing across countries
 * would report the German side of that invoice at 0.00 and make cross-border
 * documents indistinguishable from misattributions.
 *
 * Confidences therefore do not sum to 1, by design.
 */
export function weightsToRanking(scores: Map<string, number>): Map<string, number> {
  const out = new Map<string, number>();
  for (const [country, score] of scores) {
    out.set(country, 1 / (1 + Math.exp(-score)));
  }
  return out;
}
