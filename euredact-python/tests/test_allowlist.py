"""The allowlist: values a caller declares are not PII to them.

A customer's own email address or organisation name is not something they
want masked out of their own documents. The allowlist exempts exact values,
whole-span and case-insensitively — and nothing more, because a broader
match is how "our domain" turns into "every address at our domain".
"""
from __future__ import annotations

import unicodedata

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import _to_result
from euredact.types import EntityType

DOC = "Contact jan@example.com or piet@example.com at ACME NV; ACME NV pays IBAN NL91 ABNA 0417 1643 00."


@pytest.fixture
def sdk():
    return euredact.EuRedact()


def _texts(result):
    return [d.text for d in result.detections]


class TestMatching:
    def test_an_exact_value_is_not_redacted(self, sdk):
        r = sdk.redact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        assert "jan@example.com" in r.redacted_text
        assert "piet@example.com" not in r.redacted_text
        assert "jan@example.com" not in _texts(r)

    def test_matching_is_case_insensitive(self, sdk):
        r = sdk.redact(DOC, countries=["NL"], allowlist=["JAN@EXAMPLE.COM"])
        assert "jan@example.com" in r.redacted_text

    def test_entries_are_trimmed(self, sdk):
        r = sdk.redact(DOC, countries=["NL"], allowlist=["  jan@example.com\n"])
        assert "jan@example.com" in r.redacted_text

    def test_a_substring_does_not_exempt(self, sdk):
        """'example.com' must not quietly exempt every address at example.com."""
        r = sdk.redact(DOC, countries=["NL"], allowlist=["example.com"])
        assert "jan@example.com" not in r.redacted_text
        assert "piet@example.com" not in r.redacted_text

    def test_an_nfd_document_matches_an_nfc_entry(self, sdk):
        nfd = unicodedata.normalize("NFD", "mail: zoë@example.be")
        entry = unicodedata.normalize("NFC", "zoë@example.be")
        assert nfd != unicodedata.normalize("NFC", nfd)
        r = sdk.redact(nfd, countries=["BE"], allowlist=[entry])
        assert r.detections == []

    def test_other_detections_are_untouched(self, sdk):
        before = sdk.redact(DOC, countries=["NL"])
        after = sdk.redact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        assert len(after.detections) == len(before.detections) - 1
        assert [d for d in after.detections if d.entity_type == EntityType.BANK_ACCOUNT]

    def test_empty_and_none_are_no_ops(self, sdk):
        plain = sdk.redact(DOC, countries=["NL"]).redacted_text
        assert sdk.redact(DOC, countries=["NL"], allowlist=[]).redacted_text == plain
        assert sdk.redact(DOC, countries=["NL"], allowlist=None).redacted_text == plain
        assert sdk.redact(DOC, countries=["NL"], allowlist=["", "  "]).redacted_text == plain


class TestScope:
    def test_instance_allowlist_applies_to_every_call(self):
        sdk = euredact.EuRedact(allowlist=["jan@example.com"])
        assert "jan@example.com" in sdk.redact(DOC, countries=["NL"]).redacted_text
        (r,) = sdk.redact_batch([DOC], countries=["NL"])
        assert "jan@example.com" in r.redacted_text

    def test_instance_and_call_allowlists_merge(self):
        sdk = euredact.EuRedact(allowlist=["jan@example.com"])
        r = sdk.redact(DOC, countries=["NL"], allowlist=["piet@example.com"])
        assert "jan@example.com" in r.redacted_text
        assert "piet@example.com" in r.redacted_text

    def test_batch_iter_and_async_honour_it(self, sdk):
        texts = [DOC, "cc jan@example.com"]
        for r in sdk.redact_batch(texts, countries=["NL"], allowlist=["jan@example.com"]):
            assert "jan@example.com" in r.redacted_text
        for r in sdk.redact_iter(iter(texts), countries=["NL"], allowlist=["jan@example.com"]):
            assert "jan@example.com" in r.redacted_text

    @pytest.mark.asyncio
    async def test_async_entry_points_honour_it(self, sdk):
        r = await sdk.aredact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        assert "jan@example.com" in r.redacted_text
        (r,) = await sdk.aredact_batch([DOC], countries=["NL"], allowlist=["jan@example.com"])
        assert "jan@example.com" in r.redacted_text

    def test_module_level_functions_accept_it(self):
        r = euredact.redact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        assert "jan@example.com" in r.redacted_text

    def test_works_with_tokenize(self, sdk):
        r = sdk.redact(DOC, countries=["NL"], allowlist=["jan@example.com"], tokenize=True)
        assert "jan@example.com" in r.redacted_text
        assert "jan@example.com" not in r.tokens.values()
        assert euredact.restore(r.redacted_text, r.tokens) == DOC


class TestGuards:
    def test_a_bare_string_is_rejected(self, sdk):
        with pytest.raises(TypeError, match="allowlist must be a list"):
            sdk.redact(DOC, countries=["NL"], allowlist="jan@example.com")
        with pytest.raises(TypeError, match="allowlist must be a list"):
            euredact.EuRedact(allowlist="ACME NV")

    def test_the_guard_runs_before_the_cloud_dispatch(self, sdk):
        with pytest.raises(TypeError, match="allowlist must be a list"):
            sdk.redact(DOC, countries=["BE"], mode="cloud", allowlist="jan@example.com")


class TestCache:
    def test_a_plain_hit_is_not_served_to_an_allowlisted_call(self, sdk):
        assert "jan@example.com" not in sdk.redact(DOC, countries=["NL"]).redacted_text
        r = sdk.redact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        assert "jan@example.com" in r.redacted_text

    def test_different_allowlists_do_not_share_a_hit(self, sdk):
        a = sdk.redact(DOC, countries=["NL"], allowlist=["jan@example.com"])
        b = sdk.redact(DOC, countries=["NL"], allowlist=["piet@example.com"])
        assert "jan@example.com" in a.redacted_text and "piet@example.com" not in a.redacted_text
        assert "piet@example.com" in b.redacted_text and "jan@example.com" not in b.redacted_text


CLOUD_DOC = "Patiënt Bas Verhoeven, mail bas@example.be"
CLOUD_PAYLOAD = {
    "job_id": "job-1",
    "status": "succeeded",
    "redacted_text": "Patiënt [PERSON_NAME], mail [EMAIL]",
    "entities": [
        {"start": 8, "end": 21, "text": "Bas Verhoeven", "type": "PERSON_NAME",
         "source": "model", "match": "exact_body"},
        {"start": 28, "end": 42, "text": "bas@example.be", "type": "EMAIL",
         "source": "rules"},
    ],
    "unlocated": [],
}


@pytest.fixture
def cloud(monkeypatch):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def redact(self, text, *, country, **kw):
            return _to_result(CLOUD_PAYLOAD, text=text)

    monkeypatch.setattr("euredact.cloud.client.CloudClient", FakeClient)
    yield
    cloud_config.reset()


class TestCloud:
    def test_the_allowlisted_value_is_put_back_from_the_service_spans(self, sdk, cloud):
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", allowlist=["bas@example.be"])
        assert r.redacted_text == "Patiënt [PERSON_NAME], mail bas@example.be"
        assert _texts(r) == ["Bas Verhoeven"]

    def test_the_instance_allowlist_reaches_cloud_mode(self, cloud):
        sdk = euredact.EuRedact(allowlist=["Bas Verhoeven"])
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud")
        assert r.redacted_text == "Patiënt Bas Verhoeven, mail [EMAIL]"

    def test_allowlist_and_tokenize_together_in_cloud_mode(self, sdk, cloud):
        r = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud",
                       allowlist=["bas@example.be"], tokenize=True)
        assert "bas@example.be" in r.redacted_text
        assert len(r.tokens) == 1
        assert euredact.restore(r.redacted_text, r.tokens) == CLOUD_DOC
