"""The cue table and the two things it is allowed to do to a span.

The conformance vectors cover the *outcomes* — "ΑΦΜ: 147382965 is a TAX_ID" —
and both SDKs run them. What lives here is the machinery those outcomes rest
on, and in particular the gates: a cue may relabel a span, and it may re-admit
a declined identifier, but it may never move one, never reach across a word,
and never overrule a claim that carries its own structure.

Every gate below was calibrated against the corpus. Re-typing without them
fired 52 times over 2,000 documents and got roughly 30 of those wrong.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from euredact.rules.cues import CUE_WINDOW, CUES, cued_type
from euredact.rules.engine import (
    _CUE_TARGETS,
    _RESCUE_TARGETS,
    _RETYPABLE,
    _RETYPABLE_UNCORROBORATED,
    _retyped,
)
from euredact.sdk import EuRedact
from euredact.types import EntityType


@pytest.fixture(scope="module")
def sdk() -> EuRedact:
    return EuRedact()


def types_of(sdk: EuRedact, text: str, countries: list[str] | None = None) -> list[str]:
    result = sdk.redact(text, countries=countries, detect_dates=True, cache=False)
    return [
        d.entity_type.value if isinstance(d.entity_type, EntityType) else d.entity_type
        for d in result.detections
    ]


# ── cued_type: the cue must touch the span ─────────────────────────────


class TestCueProximity:
    def test_cue_touching_the_span_is_read(self) -> None:
        assert cued_type("ΑΦΜ: 147382965", 5) == EntityType.TAX_ID

    def test_cue_further_than_the_window_is_not(self) -> None:
        # The postal-code year defect: a cue 150 characters away licensed every
        # number in the window. CUE_WINDOW is the fix, so push the label just
        # past it and the cue must fall silent.
        text = "ΑΦΜ:" + " " * (CUE_WINDOW + 1) + "147382965"
        assert cued_type(text, len(text) - 9) is None

    def test_a_word_between_the_label_and_the_value_breaks_the_cue(self) -> None:
        # One qualifier word is allowed ("ΑΦΜ εταιρειας:"); a sentence is not.
        assert cued_type("ΑΦΜ van de klant: 147382965", 18) is None

    def test_one_qualifier_word_is_allowed(self) -> None:
        assert cued_type("ΑΦΜ εταιρειας: 998765432", 15) == EntityType.TAX_ID


class TestCueBoundaries:
    """Every alternative needs a left boundary, and it cannot be ``\\b``."""

    def test_label_at_the_tail_of_a_word_is_not_a_cue(self) -> None:
        # "NIS" inside "tālrunis" — the Latvian for telephone. 653 phone
        # numbers were once suppressed by this.
        assert cued_type("tālrunis 24329456", 9) != EntityType.NATIONAL_ID

    def test_iva_inside_privat_is_not_a_vat_label(self) -> None:
        assert cued_type("Privat: 12345678", 8) != EntityType.VAT

    def test_non_ascii_labels_are_reachable(self) -> None:
        # A JavaScript \b cannot match before a Greek letter, so the shared
        # table uses an ASCII lookbehind instead. If that regressed to \b the
        # TypeScript SDK would silently stop seeing every non-Latin cue.
        assert cued_type("ΑΦΜ: 1", 5) == EntityType.TAX_ID
        assert cued_type("Αρ. Ταυτότητας: 1", 16) == EntityType.NATIONAL_ID

    def test_no_cue_pattern_uses_a_bare_word_boundary(self) -> None:
        for entity_type, pattern in CUES:
            assert r"\b" not in pattern.pattern, (
                f"{entity_type} uses \\b, which is ASCII-only in JavaScript and "
                f"would diverge from the TypeScript SDK on non-Latin labels"
            )


# ── Re-typing: what a cue may and may not overrule ─────────────────────


class TestRetypingGate:
    def test_a_generic_numeric_claim_is_relabelled(self, sdk: EuRedact) -> None:
        assert types_of(sdk, "IČO: 08234567", ["CZ"]) == ["CHAMBER_OF_COMMERCE"]

    @pytest.mark.parametrize("text,countries", [
        ("BTW: klant@voorbeeld.nl", ["NL"]),
        ("Steuernummer: hans@beispiel.de", ["DE"]),
    ])
    def test_an_email_is_never_relabelled(self, sdk: EuRedact, text, countries) -> None:
        # EMAIL carries its own structure; a nearby word is not entitled to
        # overrule it. Ungated, this misfiled 13 addresses per 2,000 documents.
        assert types_of(sdk, text, countries) == ["EMAIL"]

    def test_only_generic_numeric_shapes_are_retypable(self) -> None:
        # The left half of the gate. Listed explicitly so that widening it is a
        # deliberate edit with a corpus measurement behind it, not a drive-by.
        assert _RETYPABLE == {
            EntityType.PHONE, EntityType.POSTAL_CODE, EntityType.LICENSE_PLATE,
        }
        # The conditional half, pinned for the same reason. Every type here is
        # checksummed, so each one added is a claim that its checksum can pass
        # by luck often enough for a label to be better evidence.
        assert _RETYPABLE_UNCORROBORATED == {EntityType.NATIONAL_ID}

    def test_a_label_never_rescues_a_failed_luhn_or_mod97(self) -> None:
        # Retyping and rescuing are different powers and 0.3.9 split the sets.
        # BANK_ACCOUNT became retypable so "sort code 20-45-91" stops being a
        # LICENSE_PLATE; it must not thereby become rescuable, because mod-97
        # failing really does mean "not an account number".
        assert EntityType.BANK_ACCOUNT in _CUE_TARGETS
        assert EntityType.BANK_ACCOUNT not in _RESCUE_TARGETS
        assert EntityType.BIC not in _RESCUE_TARGETS
        assert EntityType.CREDIT_CARD not in _RESCUE_TARGETS

    def test_nothing_is_ever_relabelled_to_phone(self) -> None:
        # A phone cue in front of a span no phone pattern matched means the
        # document is laid out oddly, not that the value is a phone number.
        # Asserted against the gate directly: an end-to-end case would have to
        # find text where a postal code survives behind a "Tel:" label, and if
        # it stopped detecting anything the test would pass for the wrong
        # reason.
        assert EntityType.PHONE not in _CUE_TARGETS
        assert _retyped("Tel: 1006", 5, EntityType.POSTAL_CODE, 0.0) is None

    def test_the_gate_admits_a_structured_target(self) -> None:
        # The counterpart to the two refusals above: with both halves satisfied
        # the gate does fire, so those None results mean "blocked", not
        # "unreachable".
        assert _retyped("IČO: 08234567", len("IČO: "), EntityType.PHONE, 0.0) == \
            EntityType.CHAMBER_OF_COMMERCE

    def test_a_checksummed_type_is_retyped_only_without_country_support(self) -> None:
        # NATIONAL_ID carries a checksum, so it is retypable only where that
        # checksum can be coincidence: a country the document does not support
        # at all. "Passport No.: 512847603" was reported as a Czech national ID
        # in a British document, on a checksum that fits about one 9-digit run
        # in eleven.
        text, start = "Passport No.: 512847603", len("Passport No.: ")
        assert _retyped(text, start, EntityType.NATIONAL_ID, 0.0) == EntityType.PASSPORT
        # The same span in a document that *does* support the country keeps its
        # type, whatever label sits in front of it. This is what stops a
        # domestic identifier being relabelled.
        assert _retyped(text, start, EntityType.NATIONAL_ID, 0.88) is None

    def test_retyping_never_moves_a_span(self, sdk: EuRedact) -> None:
        # Invariant I1: a cue decides the label, never which characters are
        # masked. Compare against the same text with the label filed off.
        cued = "Αρ. Ταυτότητας: 00892341"
        bare = "Referentie....: 00892341"
        assert [(d.start, d.end) for d in sdk.redact(cued, countries=["CY"], cache=False).detections] \
            == [(d.start, d.end) for d in sdk.redact(bare, countries=["CY"], cache=False).detections]

    def test_a_relabelled_detection_drops_its_country(self, sdk: EuRedact) -> None:
        # The country came from the pattern that was just overruled — a Finnish
        # phone rule vouching for Finland is worthless once the value is filed
        # as a Cypriot identity number.
        (det,) = sdk.redact("Αρ. Ταυτότητας: 00892341", countries=["CY"], cache=False).detections
        assert det.country is None
        assert det.out_of_scope is False
        assert det.confidence == "medium"


# ── Rescue: a declined identifier the document itself labels ───────────


class TestDeclinedIdentifierRescue:
    def test_a_labelled_checksum_failure_is_masked(self, sdk: EuRedact) -> None:
        # 0.3.3 suppressed the phone claim here and emitted nothing, leaving a
        # recognised-and-rejected national number printed in full.
        result = sdk.redact(
            "Rijksregisternummer: 85.03.19-284.73", countries=["BE"], cache=False)
        assert result.redacted_text == "Rijksregisternummer: [NATIONAL_ID]"
        assert result.detections[0].confidence == "low"

    def test_a_passing_checksum_stays_high_confidence(self, sdk: EuRedact) -> None:
        result = sdk.redact(
            "Rijksregisternummer: 85.03.19-284.79", countries=["BE"], cache=False)
        assert result.detections[0].confidence == "high"

    def test_an_unlabelled_checksum_failure_is_still_declined(self, sdk: EuRedact) -> None:
        # The rescue is gated on the document naming the type. Without the
        # label a failed checksum means what it always meant.
        assert types_of(sdk, "Referentie 85.03.19-284.73", ["BE"]) == []

    def test_a_cue_for_a_different_type_does_not_rescue(self, sdk: EuRedact) -> None:
        # "Tel:" in front of a rejected Belgian national number is not a reason
        # to emit a national ID; only the type's own label is. The whole list is
        # asserted, so this cannot pass by the span quietly ceasing to exist.
        assert types_of(sdk, "Tel: 85.03.19-284.73", ["BE"]) == []


class TestCrossSdkCueTable:
    """The TypeScript cue table is generated from this one and must match it.

    0.3.9's cross-SDK type divergence came from the two engines behaving
    differently on the same label, and the cheapest way to keep them honest is
    to assert the tables are the same text rather than to trust that whoever
    edits one remembers the other. The TypeScript table is regenerated from
    `CUES`, so a drift here means someone hand-edited it.
    """

    TS_CUES = (
        Path(__file__).resolve().parents[2] / "euredact-ts" / "src" / "rules" / "cues.ts"
    )

    def _ts_entries(self) -> list[tuple[str, str]]:
        source = self.TS_CUES.read_text(encoding="utf-8")
        start = source.index("export const CUES")
        block = source[start:source.index("];", start)]
        return re.findall(r"\[EntityType\.([A-Z_]+),\s*\n\s*/(.*)/i\],", block)

    @pytest.mark.skipif(not TS_CUES.exists(), reason="TypeScript SDK not in this checkout")
    def test_every_cue_matches_the_typescript_table(self) -> None:
        entries = self._ts_entries()
        assert len(entries) == len(CUES), (
            f"{len(CUES)} Python cues, {len(entries)} TypeScript cues"
        )
        for (py_type, py_pattern), (ts_type, ts_pattern) in zip(CUES, entries):
            assert py_type.value == ts_type
            # Python leaves "/" unescaped; a JavaScript regex literal cannot.
            expected = re.sub(r"(?<!\\)/", r"\\/", py_pattern.pattern)
            assert expected == ts_pattern, f"{py_type.value} differs between the SDKs"

    @pytest.mark.skipif(not TS_CUES.exists(), reason="TypeScript SDK not in this checkout")
    def test_the_cue_window_matches_the_typescript_one(self) -> None:
        source = self.TS_CUES.read_text(encoding="utf-8")
        found = re.search(r"CUE_WINDOW = (\d+);", source)
        assert found is not None
        assert int(found.group(1)) == CUE_WINDOW
