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

#: How far back a cue may sit. Short on purpose: a cue is only evidence about
#: the value it introduces, which is the lesson of the postal-code year defect,
#: where a cue 150 characters away licensed every number in the window.
CUE_WINDOW = 22

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

    The qualifier class is spelled out rather than written ``[^\\W\\d_]``
    because JavaScript's ``\\w`` is ASCII-only, so that class would reject
    "εταιρειας" in the TypeScript SDK and the two would disagree.
    """
    return rf"(?:{run_on}|\s+[^\s:.\-\d,;()/]{{2,20}})\s*[:.\-]?\s*$"


_SEP = _tail()
#: VAT labels carry punctuation inside the run-on: "USt-IdNr:", "VAT.no:".
_SEP_VAT = _tail(r"[\w.\-]*")


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
        _B + r"(?:bsn|personnummer|rijksregisternummer|nationaal\s*nummer"
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
        r"|mutualité|ziekenfonds|aansluitingsnummer)" + _SEP,
        re.IGNORECASE)),

    # ── Company / trade register ───────────────────────────────────────
    (EntityType.CHAMBER_OF_COMMERCE, re.compile(
        _B + r"(?:siren|siret|kbo|bce|kvk|ondernemingsnummer"
        r"|ondernemingen\s+onder\s+nummer|kruispuntbank"
        r"|numéro\s*d'entreprise|enterprise\s*number|handelsregister"
        r"|company\s*(?:no|number|reg)|organisationsnummer|orgnr"
        r"|i[čc]o|identifikační\s*číslo|ЕИК|eik|bulstat|cvr(?:-?nummer)?"
        r"|virksomhedsnummer)" + _SEP, re.IGNORECASE)),

    # ── VAT ────────────────────────────────────────────────────────────
    (EntityType.VAT, re.compile(
        _B + r"(?:vat|btw|tva|ust|iva|moms|alv|mwst|dič|vsk)" + _SEP_VAT,
        re.IGNORECASE)),

    # ── BIC / SWIFT ────────────────────────────────────────────────────
    (EntityType.BIC, re.compile(
        _B + r"(?:bic|swift)[\w/]*\s*[:.\-]?\s*\(?\s*$", re.IGNORECASE)),

    # ── Postal code ────────────────────────────────────────────────────
    # A postal code loses every contested span on priority (it is the weakest
    # evidence the engine has), so without a cue entry "Cod postal: 040171"
    # was handed to a German phone pattern.
    (EntityType.POSTAL_CODE, re.compile(
        _B + r"(?:cod\s*po[sș]tal|postnummer|postnr|postleitzahl|plz"
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
        r"|employee\s*(?:no|number|id)|badge\s*(?:no|number)"
        r"|osobní\s*(?:číslo\s*)?zaměstnance)" + _SEP, re.IGNORECASE)),
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
