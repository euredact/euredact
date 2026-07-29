"""Properties that must hold for *every* input, checked over many documents.

These are deliberately not about any one pattern. Each is a property a caller
can rely on without reading the rule set, and each has caught something:

* offsets that index the text — the redaction contract itself;
* non-overlapping spans — callers slice on them;
* determinism and cache transparency;
* **span length outranking priority** — a shorter match winning re-cuts a
  longer one and leaves the remainder in the clear. Found by sweeping these
  properties over 4,611 documents: ``countries=["NL"]`` turned the IP address
  ``194.232.104.77`` into the Dutch national ID ``194.232.104`` and exposed
  ``.77``. It broke the country invariant at the same time, because the
  promotion depends on whether the document corroborates the country.

The document set below is small but chosen: every entry is either a case that
broke one of these properties or a shape that nearly did.
"""

import pytest

import euredact
from euredact.rules.context import DocumentContext
from euredact.types import EntityType

DOCUMENTS = [
    # The truncation leak, and its neighbours.
    "Login-Versuche: 194.232.104.77 (09.04.2026, 22:14 Uhr)",
    "VPN-Konzentrator: 185.220.101.47\n\nNB: Die IP fuer den Zugang",
    "Bel ons op 06 12 34 56 78 of mail info@example.nl",
    # Mixed entities competing for neighbouring spans.
    "Werknemer met BSN 111222333 en rijksregisternummer 85.07.30-033.61",
    "Rekening: BE68 5390 0754 7034 - BIC: GEBABEBB, BTW BE0123456749",
    "QUANTECH SOLUTIONS GMBH\n1120 Wien\nUID: ATU 64831290\nFN: 412837 f",
    "Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390",
    "Facture 2025-0031, TVA FR40303265045, tel 06 12 34 56 78",
    "NHS Number: 943 476 5919, postcode SW1A 1AA",
    # Rejected identifiers and their fragments.
    "Rijksregisternummer: 85.03.19-284.73",
    "Rijksregisternummer: 85.03.19-284.79",
    "Telefon: 0708787668",
    # Non-ASCII adjacency, both directions.
    "ЕГН7523169263",
    "Mail: αλέξης@example.gr",
    "Mail: petras_ž@example.com",
    # Structural / degenerate.
    "Diagnose: Diabetes mellitus Typ 2 (ICD-10: E11.9), Kennzeichen B-AB 1234",
    "geen pii hier",
    "",
    "1234567890" * 8,
    "\n\n\n",
]

COUNTRY_ARGS = [None, [], ["NL"], ["BE"], ["DE"], ["ZZ"], ["GB"], ["NL", "BE"]]

IDS = [f"doc{i}" for i in range(len(DOCUMENTS))]


def _detect(text, **kw):
    return euredact.redact(text, detect_dates=True, cache=False, **kw).detections


# ── The redaction contract ──────────────────────────────────────────────

@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_offsets_index_the_original_text(text):
    """``text[start:end] == detection.text``, always.

    Callers slice the original on these offsets to build previews and audit
    trails. Normalisation runs before detection, so this is the assertion that
    the offsets were mapped back.
    """
    for d in _detect(text):
        assert 0 <= d.start < d.end <= len(text)
        assert text[d.start:d.end] == d.text


@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_detections_never_overlap(text):
    spans = sorted((d.start, d.end) for d in _detect(text))
    for (_, prev_end), (next_start, _) in zip(spans, spans[1:]):
        assert next_start >= prev_end, f"overlapping spans in {text!r}"


@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_redacted_text_is_exactly_the_reported_spans_replaced(text):
    """Rebuild the output from the detections and require an exact match.

    Stronger than "the value is gone": it pins the offsets, the replacement
    labels and the right-to-left substitution order together, so a detection
    that reports a span it did not actually replace cannot pass.
    """
    result = euredact.redact(text, detect_dates=True, cache=False)
    expected = text
    for d in sorted(result.detections, key=lambda d: d.start, reverse=True):
        # `.value`, not the enum: f"{EntityType.PHONE}" renders
        # "EntityType.PHONE" for a (str, Enum) mixin, which is the same slip
        # that put "[EntityType.BIC]" into the LLM training prompts.
        label = d.entity_type.value if isinstance(d.entity_type, EntityType) else d.entity_type
        expected = expected[:d.start] + f"[{label}]" + expected[d.end:]
    assert result.redacted_text == expected


@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_detection_is_deterministic(text):
    first = [(d.start, d.end, d.entity_type, d.country) for d in _detect(text)]
    for _ in range(3):
        assert [(d.start, d.end, d.entity_type, d.country) for d in _detect(text)] == first


@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_the_cache_is_transparent(text):
    """A cached result must equal the uncached one. The cache key has grown
    twice (mode, then country_hint); each time, missing a field here would
    return a confidently wrong answer rather than an error."""
    euredact.clear()
    cached = euredact.redact(text, detect_dates=True, cache=True)
    uncached = euredact.redact(text, detect_dates=True, cache=False)
    assert [(d.start, d.end, d.entity_type) for d in cached.detections] == \
           [(d.start, d.end, d.entity_type) for d in uncached.detections]
    assert cached.redacted_text == uncached.redacted_text


# ── Country influences scoring, never spans ─────────────────────────────

@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_no_country_argument_changes_which_spans_are_found(text):
    baseline = {(d.start, d.end) for d in _detect(text)}
    for arg in COUNTRY_ARGS:
        assert {(d.start, d.end) for d in _detect(text, countries=arg)} == baseline, \
            f"countries={arg!r} changed the spans found in {text!r}"
        assert {(d.start, d.end) for d in _detect(text, country_hint=arg)} == baseline, \
            f"country_hint={arg!r} changed the spans found in {text!r}"


@pytest.mark.parametrize("text", DOCUMENTS, ids=IDS)
def test_a_context_never_changes_which_spans_are_found(text):
    baseline = {(d.start, d.end) for d in _detect(text)}
    ctx = DocumentContext()
    found = {(d.start, d.end)
             for d in euredact.redact(text, context=ctx, detect_dates=True).detections}
    assert found == baseline


class TestShorterMatchesNeverTruncateLongerOnes:
    """The leak this file was written for.

    A validated pattern outranking a longer one re-cuts it and leaves the tail
    in the clear. Both cases below were found by sweeping the properties above
    over the corpus, not by reasoning about the rules.
    """

    def test_a_national_id_does_not_re_cut_an_ip_address(self):
        text = "Login-Versuche: 194.232.104.77 (09.04.2026, 22:14 Uhr)"
        for arg in (None, ["NL"], ["AT"]):
            result = euredact.redact(text, countries=arg, cache=False)
            texts = [d.text for d in result.detections]
            assert "194.232.104.77" in texts, f"truncated under countries={arg!r}"
            assert ".77" not in result.redacted_text, "the tail leaked"

    def test_a_phone_pattern_does_not_re_cut_a_longer_number(self):
        text = "Bel ons op 06 12 34 56 78"
        for arg in (None, ["BE"], ["NL"]):
            result = euredact.redact(text, countries=arg, cache=False)
            assert "06 12 34 56 78" in [d.text for d in result.detections], \
                f"truncated under countries={arg!r}"

    def test_priority_still_decides_between_equal_spans(self):
        """Length first must not cost the thing priority was for: a valid IBAN
        beats a coincidental match on the same characters."""
        result = euredact.redact("Rekening: BE68 5390 0754 7034", countries=["BE"],
                                 cache=False)
        assert any(d.entity_type == EntityType.BANK_ACCOUNT for d in result.detections)


# ── Argument handling ───────────────────────────────────────────────────

class TestCountryArgumentShapes:
    @pytest.mark.parametrize("param", ["countries", "country_hint"])
    @pytest.mark.parametrize("value", ["NL", b"NL", ""])
    def test_string_like_values_are_rejected(self, param, value):
        with pytest.raises(TypeError, match="not a bare string"):
            euredact.redact("BSN 111222333", **{param: value})

    @pytest.mark.parametrize("value", [None, [], ["NL"], ("NL",), {"NL"}, ["nl"]])
    def test_iterable_shapes_are_accepted(self, value):
        result = euredact.redact("Werknemer met BSN 111222333", countries=value,
                                 cache=False)
        assert result.detections
