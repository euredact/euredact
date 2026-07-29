"""Invariant I1/I2: country influences scoring, never generation.

The single most important property in the suite. A wrong or absent country must
never cause an entity to go undetected — silent recall loss is invisible in
testing and surfaces in a breach report. A false positive is recoverable; a
silent miss is not.

Before this held, ``countries=["BE"]`` made a valid Dutch BSN invisible: the
Dutch patterns were never even run. See ``test_declared_country_cannot_hide_an_entity``.
"""

import inspect

import pytest

from euredact.rules.engine import RuleEngine
from euredact.sdk import EuRedact
from euredact.types import EntityType

ALL_COUNTRIES = [
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI",
    "FR", "HR", "HU", "IE", "IS", "IT", "LT", "LU", "LV", "MT", "NL", "NO",
    "PL", "PT", "RO", "SE", "SI", "SK", "UK",
]

# Country arguments that must all produce the same candidate set: the caller's
# own country, someone else's, an unknown code, an ISO alias, all of them, none.
COUNTRY_ARGS = [
    None, [], ["NL"], ["BE"], ["DE"], ["ZZ"], ["GB"], ["gb"],
    ["NL", "BE"], ALL_COUNTRIES,
]

DOCUMENTS = [
    "Werknemer met BSN 111222333 en rijksregisternummer 85.07.30-033.61",
    "Rekening: BE68 5390 0754 7034 - BIC: GEBABEBB",
    "Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390",
    "Telefoon: +31 6 12345678, e-mail jan@test.nl",
    "Diagnose: Diabetes mellitus Typ 2 (ICD-10: E11.9), Kennzeichen B-AB 1234",
    "Facture 2025-0031, TVA FR40303265045, tel 06 12 34 56 78",
    "NHS Number: 943 476 5919, postcode SW1A 1AA",
    "Het nummer is 85041212399.",
    "",
    "geen pii hier",
]


@pytest.fixture(scope="module")
def engine():
    return RuleEngine()


@pytest.fixture(scope="module")
def sdk():
    return EuRedact()


def _canonical(matches):
    return sorted(
        (m.start, m.end, str(m.pattern_def.entity_type), m.pattern_def.pattern,
         m.country_code)
        for m in matches
    )


# ── A: generation cannot see a country at all ───────────────────────────

def test_generate_candidates_takes_no_country_argument():
    """The structural guarantee. If a country parameter is ever added here,
    every other assertion in this file becomes bypassable."""
    params = list(inspect.signature(RuleEngine.generate_candidates).parameters)
    assert params == ["self", "text"], (
        f"generate_candidates must take only text; got {params}"
    )


@pytest.mark.parametrize("text", DOCUMENTS, ids=[f"doc{i}" for i in range(len(DOCUMENTS))])
def test_candidate_set_is_invariant(engine, text):
    """Generation is country-blind, so repeated calls agree regardless of what
    the caller has previously asked for."""
    baseline = _canonical(engine.generate_candidates(text))
    for _ in range(3):
        assert _canonical(engine.generate_candidates(text)) == baseline


# ── B: no country argument may cause a miss, at the public boundary ─────

@pytest.mark.parametrize("text", DOCUMENTS, ids=[f"doc{i}" for i in range(len(DOCUMENTS))])
def test_no_country_argument_changes_which_spans_are_found(sdk, text, recwarn):
    """Span-set **equality**, not superset.

    Entity type, attributed country and out_of_scope may all differ with the
    caller's declared countries — those are scoring outputs. Which characters
    get masked may not.
    """
    def spans(countries):
        result = sdk.redact(text, countries=countries, detect_dates=True, cache=False)
        return {(d.start, d.end) for d in result.detections}

    baseline = spans(None)
    for arg in COUNTRY_ARGS:
        assert spans(arg) == baseline, f"countries={arg!r} changed the spans found"


# ── C: the reported defect, as a named regression ───────────────────────

def test_declared_country_cannot_hide_an_entity(sdk):
    """A Dutch BSN in a document declared Belgian used to vanish entirely."""
    text = "Werknemer met BSN 111222333"
    result = sdk.redact(text, countries=["BE"], detect_dates=True, cache=False)
    national_ids = [d for d in result.detections if d.entity_type == EntityType.NATIONAL_ID]
    assert national_ids, "the BSN must be detected even under countries=['BE']"
    assert "111222333" not in result.redacted_text


def test_out_of_scope_is_flagged_not_dropped(sdk):
    """I2: entities outside the declared set are emitted, marked."""
    text = "Werknemer met BSN 111222333"
    in_scope = sdk.redact(text, countries=["NL"], detect_dates=True, cache=False)
    out_scope = sdk.redact(text, countries=["BE"], detect_dates=True, cache=False)

    assert [d.out_of_scope for d in in_scope.detections] == [False]
    assert [d.out_of_scope for d in out_scope.detections] == [True]
    # Same span either way — only the attribution and the flag differ.
    assert {(d.start, d.end) for d in in_scope.detections} == \
           {(d.start, d.end) for d in out_scope.detections}


def test_declared_country_still_wins_attribution(sdk):
    """Scoring, the half country IS still allowed to influence.

    The same digits validate under several national schemes; the declared
    country decides which one is reported.
    """
    text = "Werknemer met BSN 111222333"
    result = sdk.redact(text, countries=["NL"], detect_dates=True, cache=False)
    assert [d.country for d in result.detections] == ["NL"]
