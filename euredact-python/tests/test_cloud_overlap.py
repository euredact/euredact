"""Overlapping cloud spans (rules-engine#139): the cases live in
``conformance/cloud_overlap.json`` and run in both SDKs.

From gen 14 the service may return spans of different types over the same
characters (canon cross-cutting rule 17): "Imam" is JOB_TITLE and
SENSITIVE_ATTRIBUTE, "Rotterdam" is LOCATION inside the SENSITIVE_ATTRIBUTE
"Geboorteplaats: Rotterdam". Switching one type off must not expose characters
another enabled type covers, and the placeholder must not reveal the special
category when a non-sensitive type covers the same text.

``conformance/cloud_allowlist.json`` (rules-engine#141) runs through the same
harness: an allowlisted value inside a longer cloud span is cut out of it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import _to_result

_CONFORMANCE = Path(__file__).resolve().parents[2] / "conformance"
CASES = [c for name in ("cloud_overlap.json", "cloud_allowlist.json")
         for c in json.loads((_CONFORMANCE / name).read_text())["cases"]]


def _payload(case: dict) -> dict:
    return {
        "job_id": "00000000-0000-0000-0000-000000000139",
        "status": "succeeded",
        "redacted_text": "",
        "entities": [
            {"start": e["start"], "end": e["end"], "type": e["type"],
             "text": case["text"][e["start"]:e["end"]], "source": "model", "match": "exact_body"}
            for e in case["entities"]
        ],
        "unlocated": [],
    }


@pytest.fixture
def service(monkeypatch):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    state = {}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def redact(self, text, *, country, **kw):
            assert text == state["case"]["text"], "the fixture text must carry no rules detection"
            return _to_result(_payload(state["case"]), text=text)

    monkeypatch.setattr("euredact.cloud.client.CloudClient", FakeClient)
    yield state
    cloud_config.reset()


def _value(t) -> str:
    return getattr(t, "value", t)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_overlap_case(case, service):
    service["case"] = case
    r = euredact.EuRedact().redact(case["text"], countries=[case["country"]], mode="cloud",
                                   exclude_types=case["excludeTypes"],
                                   allowlist=case.get("allowlist"))
    assert r.redacted_text == case["expectRedactedText"]
    assert sorted([_value(d.entity_type), d.text] for d in r.detections) == case["expectDetections"]
    if "expectExempted" in case:
        assert sorted([_value(e.entity_type), e.text, e.rule] for e in r.exempted) == case["expectExempted"]
        assert all(e.rule_kind == "value" for e in r.exempted)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_overlap_case_round_trips_through_tokens(case, service):
    service["case"] = case
    r = euredact.EuRedact().redact(case["text"], countries=[case["country"]], mode="cloud",
                                   exclude_types=case["excludeTypes"],
                                   allowlist=case.get("allowlist"), tokenize=True)
    assert euredact.restore(r.redacted_text, r.tokens) == case["text"]
    # One token per masked region, whatever the number of spans in it.
    assert r.redacted_text.count("_") >= len(r.tokens)


def test_the_label_does_not_depend_on_span_order(service):
    case = next(c for c in CASES if c["id"] == "overlap-imam-placeholder-does-not-reveal-the-category")
    service["case"] = dict(case, entities=list(reversed(case["entities"])))
    r = euredact.EuRedact().redact(case["text"], countries=["BE"], mode="cloud")
    assert r.redacted_text == case["expectRedactedText"]
