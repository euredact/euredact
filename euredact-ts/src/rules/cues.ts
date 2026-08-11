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
 * * Neither the qualifier nor the run-on may use `\w`. The qualifier is a
 *   negated ASCII class, fixed for this in 0.3.8; `[^\W\d_]` would reject
 *   "εταιρειας" here for the same ASCII reason. The run-on was *not* fixed then
 *   and went on diverging for another release: Slovak "telefón 0956550012"
 *   needs it to absorb "efón" after `tel`, and Bulgarian
 *   "пощенски кодове 4000-4999" needs "ове" after `пощенски код`. Python's
 *   Unicode `\w` did; this SDK's ASCII `\w` did not, so one engine said `PHONE`
 *   and the other `NATIONAL_ID` on the same document. They were the last two
 *   type divergences on the corpus, and only the type-aware half of
 *   `make parity` could see them.
 *
 *   The run-on is spelled `(?:[A-Za-z0-9_]|[^\x00-\x7F])` — an ASCII word
 *   character, or any non-ASCII character — rather than as a negated class of
 *   separators. A negated class also admits `'`, `%`, `&`, `@` and the rest of
 *   ASCII punctuation, which `\w` never did, and widening it that far was
 *   measured at 46 extra false positives with hints and 57 blind over the
 *   152,300-document corpus. This is `\w` plus the non-ASCII letters `\w`
 *   should have matched all along, and nothing else.
 *
 * Every label ends in `(?:<run-on>|\s+<one word>)`: the label either runs on
 * into a longer word ("telefoon" → "telefoonnummer") **or** takes one qualifier
 * word naming whose identifier it is ("ΑΦΜ εταιρειας:", "Tel Nr:") — never both.
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
export const CUE_WINDOW = 32;

/**
 * (entity type, label pattern). Ordered: the first match wins, so the narrower
 * label comes first where two could read the same text.
 */
export const CUES: Array<[EntityType, RegExp]> = [
  // Phone. Ranking only — nothing is ever relabelled *to* PHONE: a phone cue in
  // front of a span that no phone pattern matched says the document is laid out
  // unusually, not that the value is a phone number.
  [EntityType.PHONE,
   /(?<![A-Za-z0-9_])(?:phone|tel|telephone|téléphone|telefoon|telefon|telefono|teléfono|tlf|mobil|mobile|gsm|handy|sími|puh|móvil|cell|tālrunis|τηλέφωνο|τηλ)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // National identity number.
  [EntityType.NATIONAL_ID,
   /(?<![A-Za-z0-9_])(?:bsn|burgerservicenummer(?:\s*\(bsn\))?|personnummer|rijksregisternummer|nationaal\s*nummer|numéro\s*national|national\s*(?:id|number)|identiteitsnummer|henkilötunnus|kennitala|cpr(?:-?nummer)?|nif|nie|dni|rr|nn|nir|insz|niss|nis|matricule|ausweisnummer|personalausweis|osobní\s*číslo|ЕГН|EGN)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Cyprus: "ID number" in both official languages, plus the Greek abbreviation
  // ΑΔΤ (Αστυνομική Ταυτότητα). Neither has a phone reading.
  [EntityType.NATIONAL_ID,
   /(?<![A-Za-z0-9_])(?:αρ\.?\s*ταυτότητας|ταυτότητας|αδτ|kimlik\s*numaras[ıi])(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Social security.
  [EntityType.SSN,
   /(?<![A-Za-z0-9_])(?:ssn|social\s*security|sozialversicherungsnummer|svnr|sofi)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Tax number. Greece's ΑΦΜ is issued by the tax authority; the identity-card
  // number is the ΑΔΤ, above.
  [EntityType.TAX_ID,
   /(?<![A-Za-z0-9_])(?:αφμ|α\.φ\.μ\.|steuer-?id|steuernummer|st\.?-?nr|stnr|tin|finanzamt\s+ist|tax\s*(?:id|no|number)|daňové\s*číslo|numer\s*podatkowy)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Health insurance: the insured person.
  [EntityType.HEALTH_INSURANCE,
   /(?<![A-Za-z0-9_])(?:versichertennummer|krankenversicherung|kvnr|kv-?nr|mutualité|ziekenfonds|aansluitingsnummer|medical\s*card(?:\s*(?:no|number))?)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Healthcare provider: the clinician or practice, not the patient — the Dutch
  // AGB-code, the German LANR, the UK GMC number.
  [EntityType.HEALTHCARE_PROVIDER,
   /(?<![A-Za-z0-9_])(?:agb-?code|lanr|bsnr|gmc(?:\s*(?:no|number|reg))?|big-?nummer|zorgverlener(?:snummer)?)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Company / trade register. "Companies House" and "Company Registration
  // Number" are written out: the tail allows a run-on *or* one qualifier word,
  // never a second word, so a three-word label needs to be spelled.
  [EntityType.CHAMBER_OF_COMMERCE,
   /(?<![A-Za-z0-9_])(?:siren|siret|kbo|bce|kvk|ondernemingsnummer|ondernemingen\s+onder\s+nummer|kruispuntbank|numéro\s*d'entreprise|enterprise\s*number|handelsregister|companies\s*house(?:\s*(?:registration|reg|no|number))?|company\s*registration(?:\s*(?:number|no))?|company\s*(?:no|number|reg)|organisationsnummer|orgnr|i[čc]o|identifikační\s*číslo|ЕИК|eik|bulstat|cvr(?:-?nummer)?|virksomhedsnummer)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // VAT.
  [EntityType.VAT,
   /(?<![A-Za-z0-9_])(?:vat|btw|tva|ust|iva|moms|alv|mwst|dič|vsk)(?:(?:[A-Za-z0-9_.\-]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Bank account. A UK sort code is NN-NN-NN, also a licence-plate shape, so
  // "sort code 20-45-91" was typed LICENSE_PLATE with the label in front of it.
  // Retype target only — a failed mod-97 is never rescued by a label.
  [EntityType.BANK_ACCOUNT,
   /(?<![A-Za-z0-9_])(?:sort\s*code|account\s*(?:no|number)|rekeningnummer|kontonummer|numéro\s*de\s*compte|sort-?code)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Passport.
  [EntityType.PASSPORT,
   /(?<![A-Za-z0-9_])(?:passport(?:\s*(?:no|number))?|paspoort(?:nummer)?|reisepass(?:nummer)?|passeport|passnummer)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // BIC / SWIFT.
  [EntityType.BIC,
   /(?<![A-Za-z0-9_])(?:bic|swift)(?:[A-Za-z0-9_\/]|[^\x00-\x7F])*\s*[:.\-]?\s*\(?\s*$/i],

  // Postal code. A postal code loses every contested span on priority (it is
  // the weakest evidence the engine has), so without a cue entry
  // "Cod postal: 040171" was handed to a German phone pattern.
  [EntityType.POSTAL_CODE,
   /(?<![A-Za-z0-9_])(?:cod\s*po[sș]tal|postnummer|postnr|postleitzahl|plz(?:-?bereiche?)?|postcode|code\s*postal|codice\s*postale|kod\s*pocztowy|ps[čc]|τ\.?κ\.?|пощенски\s*код)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Internal / employee identifier. The canon calls these INTERNAL_ID and
  // annotates them with an LLM, so the engine has no pattern for them — but it
  // does have a phone pattern that was happily claiming them. The cue is the
  // only thing that identifies one, which is why the engine emits this type
  // from here and nowhere else.
  [EntityType.INTERNAL_ID,
   /(?<![A-Za-z0-9_])(?:medarbejdernummer|ansattnummer|anställningsnummer|personalnummer|personeelsnummer|matricule\s*salarié|employee\s*(?:no|number|id)|badge(?:\s*(?:no|number))?|betriebsstätten(?:nr|nummer)|grundstücks(?:nr|nummer)|dossier-?(?:nr|nummer)|aktenzeichen|osobní\s*(?:číslo\s*)?zaměstnance)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],

  // Credential. Typed SECRET because that is the type this SDK has; the
  // training pipeline's report asks for CREDENTIAL, which does not exist here.
  [EntityType.SECRET,
   /(?<![A-Za-z0-9_])(?:tan-?activatiecode|activatiecode|activation\s*code|verificatiecode|verification\s*code|otp|pincode)(?:(?:[A-Za-z0-9_]|[^\x00-\x7F])*|\s+[^\s:.\-\d,;()\/]{2,20})\s*\)?\s*[:.\-]*\s*$/i],
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
 * Retypable, but only when the document gives its country no support at all.
 *
 * These carry a checksum, so normally the pattern outranks any label. But a
 * checksum only says the digits fit *some* national scheme, and a weak one fits
 * by luck — the same reasoning that demotes an uncorroborated validated
 * candidate to priority 1 in `engine.ts`. At a country score of 0.0 the engine
 * is already saying "this passed a Czech checksum in a document with nothing
 * Czech about it", and an explicit "Passport No.:" is the better evidence.
 *
 * Restricted to zero country support on purpose: a Dutch BSN in a Dutch
 * document scores above zero and stays a NATIONAL_ID whatever label sits near
 * it, so this cannot relabel a domestic identifier — only the coincidental
 * foreign ones, which is where "Passport No.: 512847603" and
 * "Betriebsstättennr. 260326822" both landed, each reported as Czech.
 */
const RETYPABLE_UNCORROBORATED = new Set<string>([EntityType.NATIONAL_ID]);

/**
 * Types a label can assert on its own.
 *
 * PHONE is absent on purpose: "Tel:" in front of something no phone pattern
 * matched means the document is laid out oddly, not that the value is a phone
 * number. So are EMAIL, DOB, VIN and the rest — those carry their own
 * structure, and a nearby word is not entitled to overrule it.
 */
export const CUE_TARGETS = new Set<string>([
  EntityType.NATIONAL_ID, EntityType.SSN, EntityType.TAX_ID,
  EntityType.HEALTH_INSURANCE, EntityType.HEALTHCARE_PROVIDER,
  EntityType.CHAMBER_OF_COMMERCE, EntityType.VAT, EntityType.POSTAL_CODE,
  EntityType.PASSPORT, EntityType.INTERNAL_ID, EntityType.BANK_ACCOUNT,
  EntityType.SECRET,
]);

/**
 * Which of those a label may also *rescue* — re-admit after its checksum
 * failed. Until 0.3.9 this was the same set as CUE_TARGETS and it cannot stay
 * that way: re-typing a span the engine already decided to mask is cheap to be
 * wrong about, while rescuing one asserts that a value which failed its check
 * digit is a real identifier anyway.
 *
 * BIC's absence is what keeps the rescue honest. Its validator is a *registry
 * lookup*, not a checksum, so a failure means "no such bank", which no label can
 * talk you out of. Rescuing it read 34 unlisted codes behind a "BIC:" label as
 * real ones. The same reasoning keeps CREDIT_CARD and BANK_ACCOUNT out: Luhn and
 * mod-97 are strong enough that a failure really does mean "not one of these".
 * BANK_ACCOUNT joined CUE_TARGETS in 0.3.9 so "sort code 20-45-91" stops being a
 * LICENSE_PLATE, and is kept out here for exactly the 0.3.8 reason.
 *
 * HEALTHCARE_PROVIDER and SECRET are absent because neither is checksummed;
 * there is no failed validation for a label to overrule in the first place.
 */
export const RESCUE_TARGETS = new Set<string>([
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
 *
 * `countryScore` is the document's support for the country the winning pattern
 * came from; see RETYPABLE_UNCORROBORATED.
 */
export function retypedBy(
  text: string, start: number, entityType: EntityType | string,
  countryScore: number,
): EntityType | null {
  const type = String(entityType);
  if (!RETYPABLE.has(type)
      && !(RETYPABLE_UNCORROBORATED.has(type) && countryScore === 0)) return null;
  const cued = cuedType(text, start);
  if (cued === null || cued === entityType || !CUE_TARGETS.has(String(cued))) return null;
  return cued;
}
