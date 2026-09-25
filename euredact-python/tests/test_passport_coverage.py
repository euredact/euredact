"""Passport coverage across all 31 countries, and the keyword trap.

Before this, four countries had a passport pattern (BE, DE, FR, NL) and each
kept its own context keywords. A passport was therefore only recognised when
its *shape* and its *label* came from the same country: `Reisepass: CA1234567`
was missed because the German pattern rejects that alphabet while the Dutch
pattern, whose shape fits, had never heard of "Reisepass". A foreign passport
recorded in a German, Polish or Greek document is the ordinary case
(issue rules-engine#23).

The fix is one shared multilingual keyword list plus one country-independent,
label-gated pattern. The pattern is deliberately generic, so *everything*
rests on that list — which is why most of this file is about what must not be
in it.
"""
from __future__ import annotations

import pytest

import euredact
from euredact.rules.countries._shared import PASSPORT_CONTEXT
from euredact.types import EntityType


@pytest.fixture
def sdk():
    return euredact.EuRedact()


class TestCoverageBeyondTheFourCountries:
    @pytest.mark.parametrize("label,value", [
        ("passport", "AB1234567"),            # English
        ("Reisepass", "CA1234567"),           # German shape not German
        ("numer paszportu", "AB1234567"),     # Polish
        ("διαβατήριο", "GR1234567"),          # Greek
        ("útlevélszám", "HU7654321"),         # Hungarian
        ("cestovní pas", "CZ1234567"),        # Czech
        ("potni list", "SI1234567"),          # Slovene
        ("passinumero", "FI7654321"),         # Finnish
        ("pases numurs", "LV1234567"),        # Latvian
        ("pașaport", "XR1234567"),            # Romanian. Not "RO…": a token
                                              # shaped like a Romanian VAT
                                              # number is claimed as VAT, which
                                              # is the more specific rule.
        ("passaporto", "YA1234567"),          # Italian
        ("pasaporte", "ES1234567"),           # Spanish
    ])
    def test_a_labelled_passport_is_detected(self, sdk, label, value):
        result = sdk.redact(f"{label}: {value}", countries=None)
        assert [d.text for d in result.detections] == [value]
        assert result.detections[0].entity_type == EntityType.PASSPORT

    def test_a_national_pattern_still_decides_its_own_case(self, sdk):
        """The generic rule ranks below the national ones and must not displace
        them."""
        result = sdk.redact("Reisepass: KMM767RVL2 vorgelegt.", countries=["DE"])
        assert result.redacted_text == "Reisepass: [PASSPORT] vorgelegt."


class TestTheLabelCarriesThePrecision:
    """The shape is generic on purpose, so an unlabelled token is never a
    passport. If this class ever fails, the pattern has become dangerous."""

    @pytest.mark.parametrize("text", [
        "Reference AB1234567 attached.",
        "Order XY9876543 shipped.",
        "See AB1234567 for details.",
    ])
    def test_an_unlabelled_token_is_never_a_passport(self, sdk, text):
        assert sdk.redact(text, countries=None).redacted_text == text


class TestKeywordsThatWouldMisfire:
    """Context matching is substring, not word-boundary, so a short keyword
    fires inside an unrelated word. The bare Scandinavian "pass", Finnish
    "passi" and Latvian "pase" were all measured doing exactly that before
    they were removed."""

    @pytest.mark.parametrize("text", [
        "password: ABC123456",
        "Passwort: XY9876543",
        "db_password=QQ7788991",
        "passenger XY1234567 boarded",
        "Passstrasse AB123456",
        "phase AB123456 complete",
        "passive AB123456 mode",
    ])
    def test_a_word_merely_containing_a_keyword_is_not_context(self, sdk, text):
        result = sdk.redact(text, countries=None)
        assert not any(d.entity_type == EntityType.PASSPORT for d in result.detections), (
            f"{text!r} produced a PASSPORT detection"
        )

    @pytest.mark.parametrize("trap", ["pass", "passi", "pase"])
    def test_the_known_traps_stay_out_of_the_keyword_list(self, trap):
        """A regression guard on the list itself: re-adding any of these
        reintroduces the false positives above, and the failure would be a
        silent over-redaction rather than a test error somewhere obvious."""
        assert trap not in [k.lower() for k in PASSPORT_CONTEXT]

    def test_no_keyword_is_short_enough_to_hide_in_another_word(self):
        """Every keyword is either long or contains a space. A short bare word
        is what caused the problem above."""
        risky = [k for k in PASSPORT_CONTEXT if len(k) < 6 and " " not in k]
        assert risky == [], f"keywords short enough to misfire as substrings: {risky}"
