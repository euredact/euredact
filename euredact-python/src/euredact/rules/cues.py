"""Local cues: what the document calls the value sitting next to it.

A label touching the left edge of a span is the strongest statement a document
makes about what that value *is*. "Phone: 0705237535" is a phone number even
though those digits pass the Swedish personnummer checksum, and
"Αρ. Ταυτότητας: 00892341" is an identity-card number even though nothing in
the engine can checksum it.

This table is the single source of that knowledge. Three callers read it, and
none of them may move a span:

1. ``RuleEngine._local_cue_bonus`` — ranks a candidate above its rivals on the
   *same span* when the cue names its type. The oldest use, and the reason the
   table exists.
2. ``RuleEngine.detect_with_evidence`` — re-admits a candidate whose checksum
   failed when the cue names that same type. A declined identifier with its own
   label in front of it is still that identifier, mistyped or truncated.
3. ``RuleEngine._deduplicate`` — relabels a winning generic candidate whose type
   the cue contradicts, when nothing of the cued type claimed the span.

Consolidated here from two places that had drifted apart: ``_LOCAL_CUES`` in
``engine.py`` (typed, but missing most of Europe) and ``_ID_LABEL_BEFORE`` in
``suppressors.py`` (broader, but untyped — it could only *delete* a phone
candidate, which left the value unmasked).

Boundaries are written ``(?<![A-Za-z0-9_])`` rather than ``\\b``. Two reasons,
and both are load-bearing:

* **The lookbehind is required for parity.** JavaScript's ``\\b`` is ASCII-only,
  so ``\\bΑΦΜ`` never matches — a Greek letter is not a word character there,
  and a space before it is not a transition. The Python and TypeScript SDKs
  would then disagree on every non-Latin cue. This is the same reasoning that
  rewrites ``\\b`` at compile time in ``matchers.py``.
* **A boundary of some kind is required for correctness.** Without one the short
  alternatives match the *tail* of an ordinary word: ``NIS`` matched
  "tālru**nis**", the Latvian for telephone, and suppressed 653 real phone
  numbers; ``iva`` matched "Pr**iva**t:" and read a personal e-mail address as a
  VAT number.
"""

from __future__ import annotations

import re

from euredact.types import EntityType

#: How far back a cue may sit.
#:
#: This bounds how long a *label* may be, not how far it may sit from the value:
#: every pattern is anchored to the end of the window with ``$``, so the label
#: still has to reach the span through the tail below, which allows a run-on or
#: one qualifier word and nothing more. The postal-code year defect — a cue 150
#: characters away licensing every number in the window — is prevented by that
#: anchor, not by this number.
#:
#: 22 was too short for the languages that build compound nouns.
#: ``"Sozialversicherungsnummer: "`` is 27 characters, so the window held
#: ``"lversicherungsnummer: "`` and the label's own start was outside it, where
#: the ``(?<![A-Za-z0-9_])`` boundary could not anchor. The cue was in the table
#: for the whole of 0.3.8 and unreachable the entire time, which reads exactly
#: like a missing label and is not one. ``"Companies House Registration: "`` is
#: 30, the longest of the labels the corpus actually contains.
#:
#: Raising it is not free: the qualifier branch needs label + space + up to 20
#: characters + punctuation, so a longer window lets short labels reach a
#: qualifier they could not reach before. Measured over the 152,300-document
#: corpus when this moved from 22 to 32.
CUE_WINDOW = 32

#: ASCII-only left boundary. See the module docstring for why this is not ``\b``.
_B = r"(?<![A-Za-z0-9_])"

def _tail(run_on: str = r"\w*") -> str:
    """Everything a cue may put between its label and the span.

    The label either **runs on** into a longer word ("telefoon" →
    "telefoonnummer") **or** is followed by **one qualifier word** naming whose
    identifier it is ("ΑΦΜ εταιρειας:" — the *company's* tax number; "Tel Nr:").
    Then optional punctuation, then the span itself.

    The two are alternatives, never both at once, and that is the whole point of
    writing it this way. Allowing a run-on *and* a qualifier let "nie" grow into
    the surname "Nieminen" and then swallow the real label in
    "Matti Nieminen\\nDOB: 08.05.1994", reading a date of birth as a Spanish NIE
    — 52 false positives across the 152,300-document corpus. A cue is a label,
    and a label is one word or two; it is not any two words that happen to end
    in a colon.

    **Neither half may use ``\\w``.** Both are spelled as negated classes of
    ASCII characters, which is the only way to write "a letter, in any script"
    that Python and JavaScript agree on: ``\\w`` is Unicode-aware in Python and
    ASCII-only in JavaScript, so ``\\w*`` silently stops at the first non-ASCII
    letter in the TypeScript SDK and matches straight through it in Python.

    That is not hypothetical. The qualifier was fixed for this in 0.3.8 — hence
    ``[^\\s:.\\-\\d,;()/]{2,20}`` rather than ``[^\\W\\d_]`` — but the run-on
    kept ``\\w*`` and went on diverging for another release. Slovak
    "telefón 0956550012" needs the run-on to absorb "efón" after ``tel``, and
    Bulgarian "пощенски кодове 4000-4999" needs it to absorb "ове" after
    ``пощенски код``. Python did; Node did not, so the same document produced
    ``PHONE`` in one engine and ``NATIONAL_ID`` in the other. Both were the last
    two type divergences left on the corpus after the ranking fix, and only the
    type-aware half of ``make parity`` could see them.

    The run-on is spelled as "an ASCII word character, or any non-ASCII
    character" rather than as a negated class of separators. That distinction
    was measured: a negated class also admits ``'``, ``%``, ``&``, ``@`` and the
    rest of ASCII punctuation, which ``\\w`` never did, and widening it that far
    cost 46 false positives with hints and 57 blind over the 152,300-document
    corpus. This spelling is ``\\w`` plus the non-ASCII letters ``\\w`` should
    have matched all along, and nothing else.

    The trailing punctuation is ``[:.\\-]*`` rather than ``[:.\\-]?`` and a
    closing parenthesis is allowed before it, because real labels end in more
    than one mark: "Passport No.:" needs both the abbreviating full stop and the
    colon, and "Burgerservicenummer (BSN):" closes a parenthesis first. Both are
    bounded — they can absorb punctuation, never another word.
    """
    return rf"(?:{run_on}|\s+[^\s:.\-\d,;()/]{{2,20}})\s*\)?\s*[:.\-]*\s*$"


#: One character of a label's run-on. The second branch is what ``\w`` means in
#: Python and fails to mean in JavaScript; spelling it out is what makes the two
#: engines agree on "telefón" and "пощенски кодове".
_WORDISH = r"(?:[A-Za-z0-9_]|[^\x00-\x7F])"
_SEP = _tail(_WORDISH + "*")
#: VAT labels carry punctuation inside the run-on: "USt-IdNr:", "VAT.no:".
_SEP_VAT = _tail(r"(?:[A-Za-z0-9_.\-]|[^\x00-\x7F])*")


#: (entity type, label pattern). Ordered: the first match wins, so put the
#: narrower label first where two could read the same text.
CUES: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    # ── Phone ──────────────────────────────────────────────────────────
    # Ranking only. Nothing is ever *relabelled to* PHONE: a phone cue in
    # front of a span that no phone pattern matched says the document is
    # laid out unusually, not that the value is a phone number.
    (EntityType.PHONE, re.compile(
        _B + r"(?:phone|tel|telephone|téléphone|telefoon|telefon|telefono"
        r"|teléfono|tlf|mobil|mobile|gsm|handy|sími|puh|móvil|cell"
        r"|tālrunis|τηλέφωνο|τηλ)" + _SEP, re.IGNORECASE)),

    # ── National identity number ───────────────────────────────────────
    (EntityType.NATIONAL_ID, re.compile(
        _B + r"(?:bsn|burgerservicenummer(?:\s*\(bsn\))?"
        r"|personnummer|rijksregisternummer|nationaal\s*nummer"
        r"|numéro\s*national|national\s*(?:id|number)|identiteitsnummer"
        r"|henkilötunnus|kennitala|cpr(?:-?nummer)?|nif|nie|dni"
        r"|rr|nn|nir|insz|niss|nis|matricule"
        r"|ausweisnummer|personalausweis|osobní\s*číslo|ЕГН|EGN)"
        + _SEP, re.IGNORECASE)),
    # Cyprus: "ID number" in both official languages, plus the Greek
    # abbreviation ΑΔΤ (Αστυνομική Ταυτότητα). Neither has a phone reading.
    (EntityType.NATIONAL_ID, re.compile(
        _B + r"(?:αρ\.?\s*ταυτότητας|ταυτότητας|αδτ|kimlik\s*numaras[ıi])"
        + _SEP, re.IGNORECASE)),

    # ── Social security ────────────────────────────────────────────────
    (EntityType.SSN, re.compile(
        _B + r"(?:ssn|social\s*security|sozialversicherungsnummer|svnr"
        r"|sofi)" + _SEP, re.IGNORECASE)),

    # ── Tax number ─────────────────────────────────────────────────────
    # Greece's ΑΦΜ is issued by the tax authority; the identity-card number
    # is the ΑΔΤ, above. The engine used to return NATIONAL_ID for a value
    # cued ΑΦΜ, which is wrong independently of the phone problem.
    (EntityType.TAX_ID, re.compile(
        _B + r"(?:αφμ|α\.φ\.μ\.|steuer-?id|steuernummer|st\.?-?nr|stnr|tin"
        r"|finanzamt\s+ist|tax\s*(?:id|no|number)|daňové\s*číslo"
        r"|numer\s*podatkowy)" + _SEP, re.IGNORECASE)),

    # ── Health insurance ───────────────────────────────────────────────
    (EntityType.HEALTH_INSURANCE, re.compile(
        _B + r"(?:versichertennummer|krankenversicherung|kvnr|kv-?nr"
        r"|mutualité|ziekenfonds|aansluitingsnummer"
        r"|medical\s*card(?:\s*(?:no|number))?)" + _SEP,
        re.IGNORECASE)),

    # ── Healthcare provider ────────────────────────────────────────────
    # The clinician or practice, not the patient: the Dutch AGB-code, the
    # German LANR, the UK GMC number. Distinct from HEALTH_INSURANCE, which
    # identifies the insured person.
    (EntityType.HEALTHCARE_PROVIDER, re.compile(
        _B + r"(?:agb-?code|lanr|bsnr|gmc(?:\s*(?:no|number|reg))?"
        r"|big-?nummer|zorgverlener(?:snummer)?)" + _SEP, re.IGNORECASE)),

    # ── Company / trade register ───────────────────────────────────────
    (EntityType.CHAMBER_OF_COMMERCE, re.compile(
        _B + r"(?:siren|siret|kbo|bce|kvk|ondernemingsnummer"
        r"|ondernemingen\s+onder\s+nummer|kruispuntbank"
        r"|numéro\s*d'entreprise|enterprise\s*number|handelsregister"
        # The UK register, by the name documents actually use. Written out
        # rather than left to `company\s*(?:no|number|reg)` plus a run-on,
        # because "Company Registration Number:" is three words and the tail
        # allows a run-on *or* one qualifier — never a second word.
        r"|companies\s*house(?:\s*(?:registration|reg|no|number))?"
        r"|company\s*registration(?:\s*(?:number|no))?"
        r"|company\s*(?:no|number|reg)|organisationsnummer|orgnr"
        r"|i[čc]o|identifikační\s*číslo|ЕИК|eik|bulstat|cvr(?:-?nummer)?"
        r"|virksomhedsnummer)" + _SEP, re.IGNORECASE)),

    # ── VAT ────────────────────────────────────────────────────────────
    (EntityType.VAT, re.compile(
        _B + r"(?:vat|btw|tva|ust|iva|moms|alv|mwst|dič|vsk)" + _SEP_VAT,
        re.IGNORECASE)),

    # ── Bank account ───────────────────────────────────────────────────
    # A UK sort code is NN-NN-NN, which is also a licence-plate shape, so
    # "sort code 20-45-91" was typed LICENSE_PLATE with the label sitting
    # right in front of it. Note these are *retype* targets only: a failed
    # mod-97 or Luhn is not rescued by a label — see _RESCUE_TARGETS.
    (EntityType.BANK_ACCOUNT, re.compile(
        _B + r"(?:sort\s*code|account\s*(?:no|number)|rekeningnummer"
        r"|kontonummer|numéro\s*de\s*compte|sort-?code)" + _SEP,
        re.IGNORECASE)),

    # ── Passport ───────────────────────────────────────────────────────
    (EntityType.PASSPORT, re.compile(
        _B + r"(?:passport(?:\s*(?:no|number))?|paspoort(?:nummer)?"
        r"|reisepass(?:nummer)?|passeport|passnummer)" + _SEP,
        re.IGNORECASE)),

    # ── BIC / SWIFT ────────────────────────────────────────────────────
    (EntityType.BIC, re.compile(
        _B + r"(?:bic|swift)(?:[A-Za-z0-9_/]|[^\x00-\x7F])*"
        r"\s*[:.\-]?\s*\(?\s*$", re.IGNORECASE)),

    # ── Postal code ────────────────────────────────────────────────────
    # A postal code loses every contested span on priority (it is the weakest
    # evidence the engine has), so without a cue entry "Cod postal: 040171"
    # was handed to a German phone pattern.
    (EntityType.POSTAL_CODE, re.compile(
        _B + r"(?:cod\s*po[sș]tal|postnummer|postnr|postleitzahl"
        r"|plz(?:-?bereiche?)?"
        r"|postcode|code\s*postal|codice\s*postale|kod\s*pocztowy"
        r"|ps[čc]|τ\.?κ\.?|пощенски\s*код)" + _SEP, re.IGNORECASE)),

    # ── Internal / employee identifier ─────────────────────────────────
    # The canon calls these INTERNAL_ID and annotates them with an LLM, so the
    # engine has no pattern for them — but it does have a phone pattern that
    # was happily claiming them. The cue is the only thing that identifies
    # one, which is why the engine emits this type from here and nowhere else.
    (EntityType.INTERNAL_ID, re.compile(
        _B + r"(?:medarbejdernummer|ansattnummer|anställningsnummer"
        r"|personalnummer|personeelsnummer|matricule\s*salarié"
        r"|employee\s*(?:no|number|id)|badge(?:\s*(?:no|number))?"
        # German administrative numbers the corpus carries: practice site,
        # land parcel, case file. None has a shape of its own, so like every
        # INTERNAL_ID they exist only behind their label.
        r"|betriebsstätten(?:nr|nummer)|grundstücks(?:nr|nummer)"
        r"|dossier-?(?:nr|nummer)|aktenzeichen"
        r"|osobní\s*(?:číslo\s*)?zaměstnance)" + _SEP, re.IGNORECASE)),

    # ── Credential ─────────────────────────────────────────────────────
    # An activation code or one-time credential. Typed SECRET because that is
    # the type this SDK has; the training pipeline's report asks for
    # CREDENTIAL, which does not exist here. Flagged rather than invented —
    # adding a public EntityType is the caller's decision, not this table's.
    (EntityType.SECRET, re.compile(
        _B + r"(?:tan-?activatiecode|activatiecode|activation\s*code"
        r"|verificatiecode|verification\s*code|otp|pincode)"
        + _SEP, re.IGNORECASE)),
)


def cued_type(text: str, start: int) -> EntityType | None:
    """The entity type a label immediately before *start* names, if any.

    Reads at most :data:`CUE_WINDOW` characters, and every pattern is anchored
    to the end of that window, so the cue must *touch* the span. A label
    further away is about some other value.
    """
    before = text[max(0, start - CUE_WINDOW):start]
    for entity_type, pattern in CUES:
        if pattern.search(before):
            return entity_type
    return None
