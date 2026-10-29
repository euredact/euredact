"""exclude_types: entity types a caller leaves in the text (rules-engine#125).

A deployment whose taxonomy is narrower than euRedact's -- no job titles, no
amounts -- switches those types off instead of post-processing every result.
The default is unchanged: every type is detected and redacted. An excluded
detection is neither reported nor masked, and is recorded in ``exempted`` so an
audit can see what was deliberately left in.
"""
from __future__ import annotations

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import _to_result
from euredact.types import EntityType

DOC = "Contact anna.kowalska@example.com or +32 470 12 34 56; IBAN BE71 0961 2345 6769."


@pytest.fixture
def sdk():
    return euredact.EuRedact()


def _types(result):
    return [d.entity_type.value for d in result.detections]


class TestFiltering:
    def test_default_excludes_nothing(self, sdk):
        r = sdk.redact(DOC, countries=["BE"])
        assert _types(r) == ["EMAIL", "PHONE", "BANK_ACCOUNT"]
        assert r.exempted == []

    def test_an_excluded_type_is_neither_reported_nor_masked(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL"])
        assert _types(r) == ["PHONE", "BANK_ACCOUNT"]
        assert "anna.kowalska@example.com" in r.redacted_text
        assert "[PHONE]" in r.redacted_text and "[BANK_ACCOUNT]" in r.redacted_text

    def test_several_types(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL", "PHONE"])
        assert _types(r) == ["BANK_ACCOUNT"]

    def test_names_are_case_insensitive_and_aliases_resolve(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["iban", " email "])
        assert _types(r) == ["PHONE"]

    def test_an_enum_member_is_accepted(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=[EntityType.PHONE])
        assert "PHONE" not in _types(r)

    def test_the_filter_applies_to_the_final_type(self, sdk):
        # The digits also pass the Austrian SVNr check: filtering candidates
        # before ranking would have re-masked them as SSN.
        r = sdk.redact("NHS Number: 5556953627.", exclude_types=["HEALTH_INSURANCE"])
        assert r.detections == []
        assert r.redacted_text == "NHS Number: 5556953627."

    def test_dates_still_need_detect_dates(self, sdk):
        text = "Geboortedatum: 12/03/1985, mail jan@example.nl"
        r = sdk.redact(text, countries=["NL"], exclude_types=["EMAIL"])
        assert _types(r) == []
        r = sdk.redact(text, countries=["NL"], exclude_types=["EMAIL"], detect_dates=True)
        assert _types(r) == ["DOB"]


class TestExemptionRecord:
    def test_each_excluded_detection_is_recorded(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["email"])
        [e] = r.exempted
        assert (e.entity_type, e.text, e.rule, e.rule_kind) == (
            EntityType.EMAIL, "anna.kowalska@example.com", "EMAIL", "type")
        assert DOC[e.start:e.end] == e.text

    def test_allowlist_and_type_exemptions_together_in_text_order(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["BANK_ACCOUNT"],
                       allowlist=["anna.kowalska@example.com"])
        assert [(e.rule_kind, e.text) for e in r.exempted] == [
            ("value", "anna.kowalska@example.com"), ("type", "BE71 0961 2345 6769")]

    def test_an_allowlisted_value_of_an_excluded_type_is_recorded_once(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL"],
                       allowlist=["anna.kowalska@example.com"])
        assert [e.rule_kind for e in r.exempted] == ["value"]


class TestGuards:
    def test_an_unknown_name_raises(self, sdk):
        with pytest.raises(ValueError, match="unknown entity type 'EMIAL'"):
            sdk.redact(DOC, exclude_types=["EMIAL"])

    def test_a_bare_string_is_rejected(self, sdk):
        with pytest.raises(TypeError, match="bare string"):
            sdk.redact(DOC, exclude_types="EMAIL")

    def test_an_unknown_name_on_the_instance_raises_at_construction(self):
        with pytest.raises(ValueError, match="unknown entity type"):
            euredact.EuRedact(exclude_types=["JOBTITLE"])

    def test_a_registered_custom_pattern_can_be_excluded(self, sdk):
        sdk.add_custom_pattern("TICKET_ID", r"INC-\d{5}")
        r = sdk.redact("Ticket INC-20419", exclude_types=["TICKET_ID"])
        assert r.detections == [] and r.exempted[0].rule == "TICKET_ID"

    def test_an_unregistered_custom_name_raises(self, sdk):
        with pytest.raises(ValueError, match="unknown entity type 'TICKET_ID'"):
            sdk.redact("Ticket INC-20419", exclude_types=["TICKET_ID"])

    def test_the_guard_runs_before_the_cloud_dispatch(self, sdk):
        with pytest.raises(ValueError, match="unknown entity type"):
            sdk.redact(DOC, countries=["BE"], mode="cloud", exclude_types=["EMIAL"])


class TestScope:
    def test_instance_list_applies_to_every_call(self):
        sdk = euredact.EuRedact(exclude_types=["EMAIL"])
        assert "EMAIL" not in _types(sdk.redact(DOC, countries=["BE"]))

    def test_instance_and_call_lists_merge(self):
        sdk = euredact.EuRedact(exclude_types=["EMAIL"])
        assert _types(sdk.redact(DOC, countries=["BE"], exclude_types=["PHONE"])) == ["BANK_ACCOUNT"]

    def test_batch_and_iter_honour_it(self, sdk):
        [r] = sdk.redact_batch([DOC], countries=["BE"], exclude_types=["EMAIL"])
        assert "EMAIL" not in _types(r)
        [r] = list(sdk.redact_iter([DOC], countries=["BE"], exclude_types=["EMAIL"]))
        assert "EMAIL" not in _types(r)

    @pytest.mark.asyncio
    async def test_async_entry_points_honour_it(self, sdk):
        r = await sdk.aredact(DOC, countries=["BE"], exclude_types=["EMAIL"])
        assert "EMAIL" not in _types(r)
        [r] = await sdk.aredact_batch([DOC], countries=["BE"], exclude_types=["EMAIL"])
        assert "EMAIL" not in _types(r)

    def test_module_level_functions_accept_it(self):
        r = euredact.redact(DOC, countries=["BE"], exclude_types=["EMAIL"])
        assert "EMAIL" not in _types(r)

    def test_works_with_tokenize(self, sdk):
        r = sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL"], tokenize=True)
        assert all(not t.startswith("EMAIL_") for t in r.tokens)
        assert euredact.restore(r.redacted_text, r.tokens) == DOC


class TestCache:
    def test_a_plain_hit_is_not_served_to_an_excluding_call(self, sdk):
        sdk.redact(DOC, countries=["BE"])
        assert "EMAIL" not in _types(sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL"]))

    def test_an_excluding_hit_is_not_served_to_a_plain_call(self, sdk):
        sdk.redact(DOC, countries=["BE"], exclude_types=["EMAIL"])
        assert "EMAIL" in _types(sdk.redact(DOC, countries=["BE"]))


# ── Cloud mode ──────────────────────────────────────────────────────────────

CLOUD_DOC = "Anna Kowalska, Head of IT, mail anna@example.be"
CLOUD_PAYLOAD = {
    "job_id": "00000000-0000-0000-0000-000000000125",
    "status": "succeeded",
    "redacted_text": "[PERSON_NAME], [JOB_TITLE], mail [EMAIL]",
    "entities": [
        # Relative to the text the service received, in which the address is
        # already `[EMAIL]`: the rules ran locally.
        {"start": 0, "end": 13, "text": "Anna Kowalska", "type": "PERSON_NAME",
         "source": "model", "match": "exact_body"},
        {"start": 15, "end": 25, "text": "Head of IT", "type": "JOB_TITLE",
         "source": "model", "match": "exact_body"},
    ],
    "unlocated": [],
}


@pytest.fixture
def cloud(monkeypatch):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    sent: list[str] = []

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def redact(self, text, *, country, **kw):
            sent.append(text)
            return _to_result(CLOUD_PAYLOAD, text=text)

    monkeypatch.setattr("euredact.cloud.client.CloudClient", FakeClient)
    yield sent
    cloud_config.reset()


class TestCloud:
    def test_a_model_type_is_dropped_from_the_result(self, sdk, cloud):
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", exclude_types=["JOB_TITLE"])
        assert r.redacted_text == "[PERSON_NAME], Head of IT, mail [EMAIL]"
        assert [e.text for e in r.exempted] == ["Head of IT"]

    def test_an_excluded_rules_type_is_still_masked_in_the_request(self, sdk, cloud):
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", exclude_types=["EMAIL"])
        # What may leave is not what the caller wants back.
        assert cloud == ["Anna Kowalska, Head of IT, mail [EMAIL]"]
        assert r.redacted_text == "[PERSON_NAME], [JOB_TITLE], mail anna@example.be"

    def test_the_instance_list_reaches_cloud_mode(self, cloud):
        sdk = euredact.EuRedact(exclude_types=["JOB_TITLE", "PERSON_NAME"])
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud")
        assert r.redacted_text == "Anna Kowalska, Head of IT, mail [EMAIL]"
