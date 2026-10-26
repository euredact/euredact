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

import json
import sys
from collections import Counter
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


# ── Every occurrence, and per-type results (rules-engine#109) ─────────────

from eval_full import CATEGORY_MAP, _occurrences, evaluate  # noqa: E402

import corpus_results  # noqa: E402


class TestOccurrences:
    def test_every_standalone_occurrence_is_found(self):
        text = "BIC GEBABEBB, again GEBABEBB."
        assert _occurrences(text, "GEBABEBB") == [4, 20]

    def test_a_later_occurrence_inside_a_longer_token_is_not_one(self):
        assert _occurrences("Postcode 1000, Kantoor 10000", "1000") == [9]

    def test_the_first_occurrence_counts_as_before_even_inside_a_token(self):
        assert _occurrences("ref10007", "1000") == [3]

    def test_absent_is_empty(self):
        assert _occurrences("nothing here", "1000") == []


class TestEveryOccurrenceMustBeMasked:
    TEXT = "Mail a@b.be or a@b.be"

    def test_both_masked_is_a_hit(self):
        dets = [_det(5, 11, "a@b.be"), _det(15, 21, "a@b.be")]
        assert _recall_outcome(self.TEXT, dets, "a@b.be", {"EMAIL"}) == "hit"

    def test_one_left_readable_is_partial(self):
        dets = [_det(5, 11, "a@b.be")]
        assert _recall_outcome(self.TEXT, dets, "a@b.be", {"EMAIL"}) == "partial"

    def test_none_masked_is_a_miss(self):
        assert _recall_outcome(self.TEXT, [], "a@b.be", {"EMAIL"}) == "miss"


def test_a_second_occurrence_is_not_a_false_positive():
    data = [{"source_text": "IBAN BE68 5390 0754 7034, repeat BE68 5390 0754 7034.",
             "PII": [{"PII_identifier": "BE68 5390 0754 7034", "PII_category": "IBAN",
                      "PII_country": "BE"}]}]
    s = evaluate(data, use_country_hints=True)
    assert s["det_fp_by_type"].get("BANK_ACCOUNT", 0) == 0
    assert s["det_tp_by_type"]["BANK_ACCOUNT"] == 2
    assert s["cat_tp"]["IBAN"] == 1


DATA = [
    {"source_text": "Mail jan@example.be, IBAN BE68 5390 0754 7034, BIC GEBABEBB.",
     "PII": [{"PII_identifier": "jan@example.be", "PII_category": "EMAIL", "PII_country": "BE"},
             {"PII_identifier": "BE68 5390 0754 7034", "PII_category": "IBAN", "PII_country": "BE"},
             {"PII_identifier": "GEBABEBB", "PII_category": "SWIFT_BIC", "PII_country": "BE"}]},
    {"source_text": "Burgerservicenummer 111222333, tel 06 12345678, mail x@y.nl",
     "PII": [{"PII_identifier": "111222333", "PII_category": "SOCIAL_SECURITY", "PII_country": "NL"},
             {"PII_identifier": "x@y.nl", "PII_category": "EMAIL", "PII_country": "NL"}]},
]


class TestTypeRows:
    def test_rows_are_api_types_and_add_up_to_the_totals(self):
        s = evaluate(DATA, use_country_hints=True)
        rows = corpus_results.type_rows(s, CATEGORY_MAP)
        assert {"EMAIL", "BANK_ACCOUNT", "BIC", "SSN"} <= set(rows)
        assert "IBAN" not in rows and "SWIFT_BIC" not in rows
        assert sum(r["support"] for r in rows.values()) == sum(s["cat_total"].values())
        assert sum(r["hits"] for r in rows.values()) == sum(s["cat_tp"].values())
        assert sum(r["tp"] for r in rows.values()) == s["total_tp_det"]
        assert sum(r["fp"] for r in rows.values()) == s["total_fp_det"]
        for r in rows.values():
            assert r["support"] == (r["hits"] + r["mistyped"] + r["partial"]
                                    + r["misses"] + r["unlocatable"])

    def test_a_category_that_accepts_other_types_says_so(self):
        rows = corpus_results.type_rows(evaluate(DATA, True), CATEGORY_MAP)
        assert rows["SSN"]["categories"] == ["SOCIAL_SECURITY"]
        assert rows["SSN"]["also_accepts"] == ["NATIONAL_ID"]

    def test_a_type_detected_but_never_labelled_has_precision_and_no_recall(self):
        stats = {"cat_total": Counter(), "cat_tp": Counter(), "cat_mistyped": Counter(),
                 "cat_partial": Counter(), "cat_unlocatable": Counter(),
                 "det_tp_by_type": Counter(), "det_fp_by_type": Counter({"URL": 3})}
        row = corpus_results.type_rows(stats, CATEGORY_MAP)["URL"]
        assert row["recall"] is None and row["precision"] == 0.0 and row["fp"] == 3


def test_the_results_render_and_carry_composition_and_conditions():
    modes = {"hinted": evaluate(DATA, True), "blind": evaluate(DATA, False)}
    corpus = corpus_results.composition([("a.json", DATA)], {"euromask_regressions.json"})
    assert corpus["documents"] == 2 and corpus["labels"] == 5
    assert corpus["countries"] == ["BE", "NL"]
    res = corpus_results.build_results(version="0.0.0", modes=modes, category_map=CATEGORY_MAP,
                                       corpus=corpus, regressions={"records": 1, "failures": 0},
                                       generated="2026-10-25")
    md = corpus_results.render_markdown(res)
    assert "## Per entity type — hinted" in md and "## Per entity type — blind" in md
    assert "`BANK_ACCOUNT`" in md and "| `IBAN` | `BANK_ACCOUNT` |" in md
    assert "lower bound" in md and "euromask_regressions.json" in md
    assert json.loads(json.dumps(res))["modes"]["hinted"]["EMAIL"]["support"] == 2


class TestPlacesInsideOtherLabels:
    """A short value's first occurrence is often inside another identifier."""

    def test_a_postal_code_inside_a_national_id_is_not_its_place(self):
        from eval_full import _label_places
        text = "kennitala 3101718919. Heimilisfang: Selfoss, 171."
        labels = [{"PII_identifier": "3101718919", "PII_category": "NATIONAL_ID"},
                  {"PII_identifier": "171", "PII_category": "POSTAL_CODE"}]
        assert _label_places(text, labels) == [[10], [text.index("Selfoss, 171") + 9]]

    def test_a_postal_code_inside_a_phone_label_is_not_its_place(self):
        from eval_full import _label_places
        text = "Reykjavík, 776. sími +354 776 9806"
        labels = [{"PII_identifier": "776", "PII_category": "POSTAL_CODE"},
                  {"PII_identifier": "+354 776 9806", "PII_category": "PHONE"}]
        assert _label_places(text, labels)[0] == [11]

    def test_with_no_standalone_place_the_first_stands_in(self):
        from eval_full import _label_places
        labels = [{"PII_identifier": "1000", "PII_category": "POSTAL_CODE"}]
        assert _label_places("ref10007", labels) == [[3]]


class TestEngineLabel:
    """Which release the published figures are labelled with (rules-engine#116)."""

    @staticmethod
    def _info(monkeypatch, version, describe, tags):
        def fake_git(*args):
            if args[:2] == ("describe", "--tags"):
                return describe
            if args[:2] == ("rev-parse", "--short"):
                return "abc1234"
            if args[:2] == ("tag", "--list"):
                return "\n".join(t for t in tags if t == args[2])
            return None
        monkeypatch.setattr(corpus_results, "_git", fake_git)
        return corpus_results.engine_info(version)

    @staticmethod
    def _heading(info):
        res = corpus_results.build_results(
            version=info["version"], modes={"hinted": evaluate(DATA, True)},
            category_map=CATEGORY_MAP,
            corpus=corpus_results.composition([("a.json", DATA)], set()),
            regressions={"records": 0, "failures": 0}, generated="2026-10-26")
        res["engine"] = info
        return corpus_results.render_markdown(res).splitlines()[0]

    def test_on_the_tag_is_released(self, monkeypatch):
        assert self._info(monkeypatch, "0.6.0", "v0.6.0", ["v0.6.0"])["released"]

    def test_past_the_tag_is_unreleased(self, monkeypatch):
        info = self._info(monkeypatch, "0.6.0", "v0.6.0-63-g3dfcb1a", ["v0.6.0"])
        assert not info["released"]
        assert self._heading(info) == (
            "# Corpus results — euredact 0.6.0, unreleased (v0.6.0-63-g3dfcb1a)")

    def test_without_git_it_is_not_called_released(self, monkeypatch):
        assert not self._info(monkeypatch, "0.7.0", None, [])["released"]

    def test_a_bumped_version_not_yet_tagged_is_the_release_being_cut(self, monkeypatch):
        # The release skill measures after the bump and tags after the commit.
        info = self._info(monkeypatch, "0.7.0", "v0.6.0-77-g79ef1dd", ["v0.6.0"])
        assert info["released"]
        assert self._heading(info) == "# Corpus results — euredact 0.7.0 (`abc1234`)"
