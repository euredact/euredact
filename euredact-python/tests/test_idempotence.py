"""Redaction over already-redacted text must be a no-op on its own markers.

`[POSTAL_CODE]` is thirteen characters of mixed case with an underscore, which
the entropy-based SECRET rule read as a credential: a second pass replaced the
first pass's marker with `[SECRET]` and reported a credential that never
existed (rules-engine#33). It reproduced on 3.4% of a 1,081-document corpus,
which is partially-redacted text by construction.

Idempotence is the property worth asserting rather than the single symptom: any
future pattern that learns to like `[TYPE]` fails here instead of silently
corrupting a re-processed document.
"""

from __future__ import annotations

import pytest

from euredact import EntityType, EuRedact, redact, restore

DOCUMENT = """Klant: Jan de Vries, BSN 111222333, IBAN NL91ABNA0417164300.
E-mail jan@example.nl, telefoon +31 20 123 4567.
Adresse: Am Europlatz 2, 1120 Wien.
credentials rotated; api_key = sk_live_4eC39HqLyjWDarjtT1zdp7dc

INSERT INTO POLICYHOLDER (POLICY_ID, DOB, BSN, EMAIL, POSTAL_CODE, CITY)
VALUES ('POL-2024-88412', '[DOB]', '[NATIONAL_ID]', '[EMAIL]', '[POSTAL_CODE]', 'Den Haag');
"""


class TestPlaceholdersAreNotData:
    @pytest.mark.parametrize("type_name", [e.value for e in EntityType])
    def test_no_bracketed_type_name_is_ever_detected(self, type_name: str) -> None:
        # The credential word is what licensed the entropy rule in the report,
        # so it is included deliberately rather than being a neutral carrier.
        text = f"credentials: [{type_name}] rotated."
        assert redact(text, countries=["NL"]).detections == []

    @pytest.mark.parametrize("type_name", ["EMAIL", "NATIONAL_ID", "BANK_ACCOUNT"])
    def test_referential_and_token_labels_are_not_detected(self, type_name: str) -> None:
        for label in (f"{type_name}_1", f"{type_name}_42", f"{type_name}_K7Q2"):
            text = f"credentials: {label} rotated."
            assert redact(text, countries=["NL"]).detections == [], label

    def test_a_bracketed_token_that_is_not_a_type_name_is_still_scanned(self) -> None:
        # The guard is restricted to real type names for exactly this reason: a
        # bracketed upper-case token can also be a live credential, and a
        # redaction library may not trade a false negative for tidiness.
        result = redact("credentials: [AKIAIOSFODNN7EXAMPLE] rotated.", countries=["NL"])
        assert [d.entity_type for d in result.detections] == [EntityType.SECRET]

    def test_an_unknown_bracketed_word_does_not_shield_what_follows(self) -> None:
        result = redact("[UNKNOWN_TYPE] BSN 111222333", countries=["NL"])
        assert any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)


class TestIdempotence:
    def test_bracketed_output_is_stable(self) -> None:
        once = redact(DOCUMENT, countries=["NL"]).redacted_text
        assert redact(once, countries=["NL"]).redacted_text == once

    def test_referential_output_is_stable(self) -> None:
        engine = EuRedact()
        once = engine.redact(DOCUMENT, countries=["NL"], referential_integrity=True).redacted_text
        twice = engine.redact(once, countries=["NL"], referential_integrity=True).redacted_text
        assert twice == once

    def test_tokenized_output_survives_a_second_pass(self) -> None:
        first = redact(DOCUMENT, countries=["NL"], tokenize=True)
        second = redact(first.redacted_text, countries=["NL"]).redacted_text
        assert second == first.redacted_text
        # The point of the property: a re-pass must not break restore().
        assert restore(second, first.tokens) == DOCUMENT

    def test_the_reported_sql_block_keeps_its_markers(self) -> None:
        once = redact(DOCUMENT, countries=["NL"]).redacted_text
        for marker in ("[DOB]", "[NATIONAL_ID]", "[EMAIL]", "[POSTAL_CODE]"):
            assert marker in once, marker
        assert "[SECRET]" not in once.split("VALUES")[1]


class TestTheGuardSurvivesOtherPatternsSpans:
    """A placeholder is engine output whatever span another pattern gives it.

    The assigned-secret rule stops before sentence punctuation
    (rules-engine#35), so it claims ``[POSTAL_CODE`` without the closing
    bracket. A guard that required the ``]`` let that straight through, and the
    two fixes only met when both landed on main -- 30 of these cases failed.
    """

    @pytest.mark.parametrize("type_name", ["POSTAL_CODE", "NATIONAL_ID", "BANK_ACCOUNT"])
    def test_a_span_missing_the_closing_bracket_is_still_a_placeholder(
        self, type_name: str
    ) -> None:
        from euredact.rules.suppressors import _PLACEHOLDER, _known_type_names

        for span in (f"[{type_name}]", f"[{type_name}"):
            found = _PLACEHOLDER.match(span)
            assert found is not None, span
            assert (found.group(1) or found.group(2)) in _known_type_names(), span

    def test_a_bare_type_name_without_a_bracket_is_not_a_placeholder(self) -> None:
        # The opening bracket stays required, so an ordinary word that happens
        # to be a type name is still scanned normally.
        from euredact.rules.suppressors import _PLACEHOLDER

        assert _PLACEHOLDER.match("POSTAL_CODE") is None
