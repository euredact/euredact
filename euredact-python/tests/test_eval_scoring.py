"""The evaluation harness must not score a partial redaction as a hit.

`make eval` is the check that exists to catch under-redaction, so a leak it
reports as a perfect score is worse than no check at all. Before this was
fixed, IPv6 scored 100% recall and 100% precision over 636 corpus entities
while the engine left the interface identifier of every compressed address in
the clear (issue rules-engine#8, found via rules-engine#5).

Two separate leniencies produced that:

* the primary test was ``pii_text not in redacted_text`` -- masking a single
  character already destroys the literal, so any partial masking passed;
* the fallback accepted one character of span overlap as a full detection.

These tests pin the replacement: a gold identifier counts as recalled only
when every character of its span is masked.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from eval_full import _covered_chars, _recall_outcome  # noqa: E402

from euredact.types import Detection, DetectionSource, EntityType  # noqa: E402


def _det(start: int, end: int, text: str, etype=EntityType.EMAIL) -> Detection:
    return Detection(
        entity_type=etype, start=start, end=end, text=text,
        source=DetectionSource.RULES, country=None,
    )


class TestCoveredChars:
    def test_a_full_cover_counts_every_character(self):
        assert _covered_chars([_det(0, 10, "x")], 0, 10) == 10

    def test_a_partial_cover_counts_only_what_is_masked(self):
        assert _covered_chars([_det(0, 3, "x")], 0, 10) == 3

    def test_overlapping_detections_are_not_double_counted(self):
        dets = [_det(0, 6, "x"), _det(4, 10, "y")]
        assert _covered_chars(dets, 0, 10) == 10

    def test_a_gap_between_detections_is_not_covered(self):
        dets = [_det(0, 3, "x"), _det(7, 10, "y")]
        assert _covered_chars(dets, 0, 10) == 6

    def test_detections_outside_the_span_are_ignored(self):
        assert _covered_chars([_det(20, 30, "x")], 0, 10) == 0

    def test_a_detection_wider_than_the_span_is_clipped(self):
        assert _covered_chars([_det(-5, 50, "x")], 0, 10) == 10

    def test_the_type_filter_is_honoured(self):
        dets = [_det(0, 10, "x", EntityType.PHONE)]
        assert _covered_chars(dets, 0, 10, {"EMAIL"}) == 0
        assert _covered_chars(dets, 0, 10, {"PHONE"}) == 10
        assert _covered_chars(dets, 0, 10, None) == 10


class TestRecallOutcome:
    ACCEPT = {EntityType.EMAIL.value}

    def test_a_fully_masked_identifier_is_a_hit(self):
        text = "mail jan@example.com now"
        dets = [_det(5, 20, "jan@example.com")]
        assert _recall_outcome(text, dets, "jan@example.com", self.ACCEPT) == "hit"

    def test_a_partially_masked_identifier_is_not_a_hit(self):
        """The regression: this is the `sean_o'[EMAIL]` shape."""
        text = "mail sean_o'neill@x.ie now"
        dets = [_det(12, 22, "neill@x.ie")]          # local part before the quote survives
        assert _recall_outcome(text, dets, "sean_o'neill@x.ie", self.ACCEPT) == "partial"

    def test_one_character_of_overlap_is_not_a_hit(self):
        """The old fallback accepted exactly this."""
        text = "addr 2001:db8::ff00:42:8329 end"
        dets = [_det(5, 6, "2", EntityType.IPV6_ADDRESS)]
        got = _recall_outcome(text, dets, "2001:db8::ff00:42:8329",
                              {EntityType.IPV6_ADDRESS.value})
        assert got == "partial"

    def test_an_undetected_identifier_is_a_miss(self):
        assert _recall_outcome("mail jan@example.com", [], "jan@example.com", self.ACCEPT) == "miss"

    def test_masked_under_another_type_is_reported_separately(self):
        """The data is protected; the label is wrong. A mislabel, not a leak."""
        text = "mail jan@example.com now"
        dets = [_det(5, 20, "jan@example.com", EntityType.PHONE)]
        assert _recall_outcome(text, dets, "jan@example.com", self.ACCEPT) == "mistyped"

    def test_an_identifier_absent_from_the_document_is_not_credited(self):
        """The old test counted it as a hit: absent from the text means absent
        from the redacted text, so `not in` was satisfied."""
        assert _recall_outcome("nothing here", [], "jan@example.com", self.ACCEPT) == "unlocatable"

    def test_split_detections_that_together_cover_the_span_are_a_hit(self):
        """A name masked as two adjacent detections is still fully masked."""
        text = "Jan de Vries called"
        dets = [_det(0, 3, "Jan", EntityType.PERSON_NAME),
                _det(3, 12, " de Vries", EntityType.PERSON_NAME)]
        got = _recall_outcome(text, dets, "Jan de Vries", {EntityType.PERSON_NAME.value})
        assert got == "hit"

    @pytest.mark.parametrize("dets,expected", [
        ([], "miss"),
        ([_det(5, 20, "jan@example.com")], "hit"),
        ([_det(5, 12, "jan@exa")], "partial"),
    ])
    def test_outcomes_are_exhaustive(self, dets, expected):
        assert _recall_outcome("mail jan@example.com now", dets, "jan@example.com",
                               self.ACCEPT) == expected
