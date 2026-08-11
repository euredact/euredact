/**
 * Local cues: what the document calls the value sitting next to it.
 *
 * A label touching the left edge of a span is the strongest statement a
 * document makes about what that value *is*. "Phone: 0705237535" is a phone
 * number even though those digits pass the Swedish personnummer checksum, and
 * "Αρ. Ταυτότητας: 00892341" is an identity-card number even though nothing in
 * the engine can checksum it.
 *
 * This table is the single source of that knowledge. Three callers read it, and
 * none of them may move a span:
 *
 * 1. `localCueBonus` — ranks a candidate above its rivals on the *same span*
 *    when the cue names its type. The oldest use, and why the table exists.
 * 2. `detectWithEvidence` — re-admits a candidate whose checksum failed when the
 *    cue names that same type. A declined identifier with its own label in front
 *    of it is still that identifier, mistyped or truncated.
 * 3. `retypedBy` — relabels a winning generic candidate whose type the cue
 *    contradicts, when nothing of the cued type claimed the span.
 *
 * Consolidated here from two places that had drifted apart: `LOCAL_CUES` in
 * `engine.ts` (typed, but missing most of Europe) and `ID_LABEL_BEFORE` in
 * `suppressors.ts` (broader, but untyped — it could only *delete* a phone
 * candidate, which left the value unmasked).
 *
 * Kept character-for-character in step with `euredact/rules/cues.py`. Two
 * constructs are written the way they are so that both engines agree:
 *
 * * Boundaries are `(?<![A-Za-z0-9_])`, not `\b`. JavaScript's `\b` is
 *   ASCII-only, so `\bΑΦΜ` never matches — a Greek letter is not a word
 *   character there, and a space before it is not a transition. A boundary of
 *   some kind is required regardless: without one the short alternatives match
 *   the *tail* of an ordinary word. "NIS" matched "tālru**nis**", the Latvian
 *   for telephone, and suppressed 653 real phone numbers; "iva" matched
 *   "Pr**iva**t:" and read a personal e-mail address as a VAT number.
 * * The qualifier class is spelled out rather than written `[^\W\d_]`, which
 *   would reject "εταιρειας" here for the same ASCII reason.
 *
 * Every label ends in `(?:\w*|\s+<one word>)`: the label either runs on into a
 * longer word ("telefoon" → "telefoonnummer") **or** takes one qualifier word
 * naming whose identifier it is ("ΑΦΜ εταιρειας:", "Tel Nr:") — never both.
 * Allowing both let "nie" grow into the surname "Nieminen" and then swallow the
 * real label in "Matti Nieminen\nDOB: 08.05.1994", reading a date of birth as a
 * Spanish NIE: 52 false positives across the corpus.
 */

import { EntityType } from "../types.js";

/**
 * How far back a cue may sit. Short on purpose: a cue is only evidence about
 * the value it introduces, which is the lesson of the postal-code year defect,
 * where a cue 150 characters away licensed every number in the window.
 */
export const CUE_WINDOW = 22;

/**
 * (entity type, label pattern). Ordered: the first match wins, so the narrower
 * label comes first where two could read the same text.
 */
export const CUES: Array<[EntityType, RegExp]> = [
  // Phone. Ranking only — nothing is ever relabelled *to* PHONE: a phone cue in
  // front of a span that no phone pattern matched says the document is laid out
  // unusually, not that the value is a phone number.
  [EntityType.PHONE,
   /(?<![A-Za-z0-9_])(?:phone|tel|telephone|téléphone|telefoon|telefon|telefono|teléfono|tlf|mobil|mobile|gsm|handy|sími|puh|móvil|cell|tālrunis|τηλέφωνο|τηλ)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // National identity number.
  [EntityType.NATIONAL_ID,
   /(?<![A-Za-z0-9_])(?:bsn|personnummer|rijksregisternummer|nationaal\s*nummer|numéro\s*national|national\s*(?:id|number)|identiteitsnummer|henkilötunnus|kennitala|cpr(?:-?nummer)?|nif|nie|dni|rr|nn|nir|insz|niss|nis|matricule|ausweisnummer|personalausweis|osobní\s*číslo|ЕГН|EGN)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],
  // Cyprus: "ID number" in both official languages, plus the Greek abbreviation
  // ΑΔΤ (Αστυνομική Ταυτότητα). Neither has a phone reading.
  [EntityType.NATIONAL_ID,
   /(?<![A-Za-z0-9_])(?:αρ\.?\s*ταυτότητας|ταυτότητας|αδτ|kimlik\s*numaras[ıi])(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // Social security.
  [EntityType.SSN,
   /(?<![A-Za-z0-9_])(?:ssn|social\s*security|sozialversicherungsnummer|svnr|sofi)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // Tax number. Greece's ΑΦΜ is issued by the tax authority; the identity-card
  // number is the ΑΔΤ, above. The engine used to return NATIONAL_ID for a value
  // cued ΑΦΜ, which is wrong independently of the phone problem.
  [EntityType.TAX_ID,
   /(?<![A-Za-z0-9_])(?:αφμ|α\.φ\.μ\.|steuer-?id|steuernummer|st\.?-?nr|stnr|tin|finanzamt\s+ist|tax\s*(?:id|no|number)|daňové\s*číslo|numer\s*podatkowy)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // Health insurance.
  [EntityType.HEALTH_INSURANCE,
   /(?<![A-Za-z0-9_])(?:versichertennummer|krankenversicherung|kvnr|kv-?nr|mutualité|ziekenfonds|aansluitingsnummer)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // Company / trade register.
  [EntityType.CHAMBER_OF_COMMERCE,
   /(?<![A-Za-z0-9_])(?:siren|siret|kbo|bce|kvk|ondernemingsnummer|ondernemingen\s+onder\s+nummer|kruispuntbank|numéro\s*d'entreprise|enterprise\s*number|handelsregister|company\s*(?:no|number|reg)|organisationsnummer|orgnr|i[čc]o|identifikační\s*číslo|ЕИК|eik|bulstat|cvr(?:-?nummer)?|virksomhedsnummer)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // VAT.
  [EntityType.VAT,
   /(?<![A-Za-z0-9_])(?:vat|btw|tva|ust|iva|moms|alv|mwst|dič|vsk)(?:[\w.\-]*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // BIC / SWIFT.
  [EntityType.BIC,
   /(?<![A-Za-z0-9_])(?:bic|swift)[\w/]*\s*[:.\-]?\s*\(?\s*$/i],

  // Postal code. A postal code loses every contested span on priority (it is
  // the weakest evidence the engine has), so without a cue entry
  // "Cod postal: 040171" was handed to a German phone pattern.
  [EntityType.POSTAL_CODE,
   /(?<![A-Za-z0-9_])(?:cod\s*po[sș]tal|postnummer|postnr|postleitzahl|plz|postcode|code\s*postal|codice\s*postale|kod\s*pocztowy|ps[čc]|τ\.?κ\.?|пощенски\s*код)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],

  // Internal / employee identifier. The canon calls these INTERNAL_ID and
  // annotates them with an LLM, so the engine has no pattern for them — but it
  // does have a phone pattern that was happily claiming them. The cue is the
  // only thing that identifies one, which is why the engine emits this type
  // from here and nowhere else.
  [EntityType.INTERNAL_ID,
   /(?<![A-Za-z0-9_])(?:medarbejdernummer|ansattnummer|anställningsnummer|personalnummer|personeelsnummer|matricule\s*salarié|employee\s*(?:no|number|id)|badge\s*(?:no|number)|osobní\s*(?:číslo\s*)?zaměstnance)(?:\w*|\s+[^\s:.\-\d,;()/]{2,20})\s*[:.\-]?\s*$/i],
];

/**
 * The entity type a label immediately before `start` names, or null.
 *
 * Reads at most `CUE_WINDOW` characters, and every pattern is anchored to the
 * end of that window, so the cue must *touch* the span. A label further away is
 * about some other value.
 */
export function cuedType(text: string, start: number): EntityType | null {
  const before = text.slice(Math.max(0, start - CUE_WINDOW), start);
  for (const [entityType, pattern] of CUES) {
    if (pattern.test(before)) return entityType;
  }
  return null;
}

/**
 * Shapes so generic that a label in front is better evidence than the pattern
 * that matched. A bare digit run is not a phone number because it *could* be
 * dialled.
 */
const RETYPABLE = new Set<string>([
  EntityType.PHONE, EntityType.POSTAL_CODE, EntityType.LICENSE_PLATE,
]);

/**
 * Types a label can assert on its own. Also the types eligible for the rescue
 * in `engine.ts`, for the same reason read the other way — a label may vouch
 * for one of these, so it may also vouch for a malformed one.
 *
 * PHONE is absent on purpose: "Tel:" in front of something no phone pattern
 * matched means the document is laid out oddly, not that the value is a phone
 * number. So are EMAIL, SECRET, DOB, VIN and the rest — those carry their own
 * structure, and a nearby word is not entitled to overrule it.
 *
 * BIC's absence is what keeps the rescue honest. Its validator is a *registry
 * lookup*, not a checksum, so a failure means "no such bank", which no label can
 * talk you out of. Rescuing it read 34 unlisted codes behind a "BIC:" label as
 * real ones. The same reasoning keeps CREDIT_CARD and BANK_ACCOUNT out: Luhn and
 * mod-97 are strong enough that a failure really does mean "not one of these".
 */
export const CUE_TARGETS = new Set<string>([
  EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID,
  EntityType.HEALTH_INSURANCE, EntityType.CHAMBER_OF_COMMERCE,
  EntityType.VAT, EntityType.POSTAL_CODE, EntityType.PASSPORT,
  EntityType.INTERNAL_ID,
]);

/**
 * The type a cue overrules `entityType` with, or null to leave it alone.
 *
 * Both gates are load-bearing. Measured over 2,000 corpus documents, re-typing
 * without them fired 52 times and got roughly 30 of those wrong — EMAIL read as
 * VAT, a date of birth as a phone number, a VIN as VAT — against 20 real fixes.
 * With them: 14 re-typings, every one of them PHONE to a structured identifier.
 */
export function retypedBy(
  text: string, start: number, entityType: EntityType | string,
): EntityType | null {
  if (!RETYPABLE.has(String(entityType))) return null;
  const cued = cuedType(text, start);
  if (cued === null || cued === entityType || !CUE_TARGETS.has(String(cued))) return null;
  return cued;
}
