"""Country evidence: what a document says about which country it belongs to.

Some entities carry their country in the string — an IBAN's country code, a
`+CC` dialling prefix, a VAT prefix, an email ccTLD. Those are used to work out
which country a document belongs to, which in turn decides which national
scheme owns an ambiguous value elsewhere in the same document. 36.6% of
national-ID values in the corpus validate under more than one country's
checksum, so without this the engine cannot tell a Dutch BSN from a Polish
PESEL.

Evidence influences **scoring only**. It ranks candidates that already exist
and annotates the result; it never decides what is looked for. A wrong
inference must not be able to cause a miss — see
``tests/test_invariant_generation.py``.

Weights are derived, not chosen. ``scripts/derive_evidence_weights.py``
measures P(document country = X | signal claims X) across the corpus and prints
the log-odds; the values below come from that run. Re-derive them when the
corpus changes rather than adjusting them by feel.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict

from euredact.types import CountryEvidence, Detection, EntityType

# ── Derived weights ─────────────────────────────────────────────────────
#
# Measured on 152,300 documents (see module docstring):
#
#   signal          agree    total   P(doc=X|signal)   raw log-odds
#   e164_prefix    41,402   41,402          0.9999             9.21
#   bic_country     2,588    2,588          0.9999             9.21
#   email_tld      97,865   98,949          0.9890             4.50
#   vat_prefix     19,022   20,136          0.9447             2.84
#   iban_prefix   110,572  126,428          0.8746             1.94
#
# The IBAN prefix being the *weakest* signal is real and worth knowing: a
# Belgian IBAN in a Dutch invoice is ordinary, so the account's country is only
# weak evidence about the document's.
#
# The perfect scores are capped. They are perfect because the generator emits
# country-consistent values, not because a foreign mobile number never appears
# in a real document. Treating a synthetic 1.0 as certainty would make a single
# phone number unfalsifiable by any amount of contrary evidence.
_MAX_LOG_ODDS = 4.0

WEIGHTS: dict[str, float] = {
    "e164_prefix": min(9.21, _MAX_LOG_ODDS),
    "bic_country": min(9.21, _MAX_LOG_ODDS),
    "email_tld": min(4.50, _MAX_LOG_ODDS),
    "vat_prefix": 2.84,
    "iban_prefix": 1.94,
    "declared": 2.00,  # the caller's countries=, a prior rather than a measurement
}

# ── Signal tables ───────────────────────────────────────────────────────

# E.164 calling code -> country, for the countries this engine supports. Codes
# are unique within this set; a shared code (+1, +7) would have to emit
# evidence for every candidate country rather than one.
DIALLING_CODES: dict[str, str] = {
    "43": "AT", "32": "BE", "359": "BG", "41": "CH", "357": "CY", "420": "CZ",
    "49": "DE", "45": "DK", "372": "EE", "30": "EL", "34": "ES", "358": "FI",
    "33": "FR", "385": "HR", "36": "HU", "353": "IE", "354": "IS", "39": "IT",
    "370": "LT", "352": "LU", "371": "LV", "356": "MT", "31": "NL", "47": "NO",
    "48": "PL", "351": "PT", "40": "RO", "46": "SE", "386": "SI", "421": "SK",
    "44": "UK",
}

# ccTLD -> country. Deliberately excludes .eu/.com/.org/.net: those are not
# weak evidence, they are no evidence, and treating them as weak would let a
# .com address outvote a genuine national signal.
CC_TLDS: dict[str, str] = {
    "at": "AT", "be": "BE", "bg": "BG", "ch": "CH", "cy": "CY", "cz": "CZ",
    "de": "DE", "dk": "DK", "ee": "EE", "gr": "EL", "es": "ES", "fi": "FI",
    "fr": "FR", "hr": "HR", "hu": "HU", "ie": "IE", "is": "IS", "it": "IT",
    "lt": "LT", "lu": "LU", "lv": "LV", "mt": "MT", "nl": "NL", "no": "NO",
    "pl": "PL", "pt": "PT", "ro": "RO", "se": "SE", "si": "SI", "sk": "SK",
    "uk": "UK",
}

# VAT prefixes that are not the ISO code: Greece trades as EL, Northern Ireland
# as XI. Naive alpha-2 handling gets both wrong.
_VAT_PREFIX_OVERRIDES = {"EL": "EL", "XI": "UK"}

_NON_DIGIT = re.compile(r"\D")


def _emit_iban(det: Detection) -> list[CountryEvidence]:
    code = det.text[:2].upper()
    if not code.isalpha():
        return []
    return [CountryEvidence(code, "iban_prefix", WEIGHTS["iban_prefix"],
                            (det.start, det.end))]


def _emit_e164(det: Detection) -> list[CountryEvidence]:
    if not det.text.lstrip().startswith("+"):
        return []
    digits = _NON_DIGIT.sub("", det.text)
    for length in (3, 2):
        country = DIALLING_CODES.get(digits[:length])
        if country:
            return [CountryEvidence(country, "e164_prefix", WEIGHTS["e164_prefix"],
                                    (det.start, det.end))]
    return []


def _emit_vat(det: Detection) -> list[CountryEvidence]:
    prefix = det.text[:2].upper()
    if not prefix.isalpha():
        return []
    country = _VAT_PREFIX_OVERRIDES.get(prefix, prefix)
    return [CountryEvidence(country, "vat_prefix", WEIGHTS["vat_prefix"],
                            (det.start, det.end))]


def _emit_bic(det: Detection) -> list[CountryEvidence]:
    clean = det.text.replace(" ", "").upper()
    if len(clean) < 6:
        return []
    return [CountryEvidence(clean[4:6], "bic_country", WEIGHTS["bic_country"],
                            (det.start, det.end))]


def _emit_tld(det: Detection) -> list[CountryEvidence]:
    tld = det.text.rsplit(".", 1)[-1].lower()
    country = CC_TLDS.get(tld)
    if country is None:
        return []
    return [CountryEvidence(country, "email_tld", WEIGHTS["email_tld"],
                            (det.start, det.end))]


# Dispatch by entity type, mirroring suppressors._TYPE_SUPPRESSORS.
_TYPE_EMITTERS = {
    EntityType.BANK_ACCOUNT: [_emit_iban],
    EntityType.PHONE: [_emit_e164],
    EntityType.VAT: [_emit_vat],
    EntityType.BIC: [_emit_bic],
    EntityType.EMAIL: [_emit_tld],
}


#: Entity types that can carry country evidence. Used to pick the small subset
#: of candidates worth building Detections for during the evidence pass.
EVIDENCE_TYPES = frozenset(_TYPE_EMITTERS)


def collect(detections: list[Detection]) -> list[CountryEvidence]:
    """Country evidence carried by *detections*, in document order.

    Deduplicated by (span, source): several countries' patterns can match the
    same IBAN, and counting that span once per pattern would let a single
    entity outvote the rest of the document.
    """
    evidence: list[CountryEvidence] = []
    seen: set[tuple[tuple[int, int], str]] = set()
    for det in detections:
        for emit in _TYPE_EMITTERS.get(det.entity_type, ()):
            for ev in emit(det):
                key = (ev.span, ev.source)
                if key not in seen:
                    seen.add(key)
                    evidence.append(ev)
    # Document order, not pattern-registration order: this list is an audit
    # trail, and a reader checking it against the text should not have to jump
    # around. Also keeps the two SDKs byte-comparable.
    evidence.sort(key=lambda ev: ev.span)
    return evidence


def accumulate(
    evidence: list[CountryEvidence],
    declared: set[str] | None = None,
) -> dict[str, float]:
    """Sum evidence into a per-country log-odds score.

    Returns a weighted set, never a single winner: a Belgian supplier invoicing
    a German customer is not "70% Belgian", both countries are genuinely
    present, and an ambiguous value must be resolvable against either.
    """
    scores: dict[str, float] = defaultdict(float)
    for ev in evidence:
        scores[ev.country] += ev.log_odds
    for country in declared or ():
        if country not in ("SHARED", "CUSTOM"):
            scores[country] += WEIGHTS["declared"]
    return dict(scores)


def weights_to_ranking(scores: dict[str, float]) -> dict[str, float]:
    """Convert per-country log-odds into confidences in [0, 1].

    Each country is scored independently — a logistic on its own log-odds —
    because document countries are not mutually exclusive. A Belgian supplier
    invoicing a German customer is genuinely both; softmaxing across countries
    would report the German side of that invoice at 0.00 and make cross-border
    documents indistinguishable from misattributions.

    Confidences therefore do not sum to 1, by design.
    """
    return {c: 1.0 / (1.0 + math.exp(-s)) for c, s in scores.items()}
