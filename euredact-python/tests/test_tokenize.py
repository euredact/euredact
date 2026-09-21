"""Reversible tokenization: redact(tokenize=True) and restore().

The use case is a prompt that goes to an LLM and comes back rewritten. The
tokens must survive that round trip verbatim, and restore() must put back
exactly what was taken out -- so most tests here assert on the round trip
rather than on the tokens themselves, which are random by design.
"""
from __future__ import annotations

import re

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import CloudError, _to_result
from euredact.sdk import TOKEN_ALPHABET, TokenMapper, _apply_replacements, restore
from euredact.types import Detection, DetectionSource, EntityType

TOKEN = re.compile(rf"^[A-Z][A-Z0-9_]*_[{TOKEN_ALPHABET}]{{4}}$")
PROMPT = "Write an email to Joren (joren.janssens@euredact.be) about the invoice."


@pytest.fixture
def sdk():
    return euredact.EuRedact()


class TestTokens:
    def test_the_prompt_use_case_round_trips(self, sdk):
        result = sdk.redact(PROMPT, countries=["BE"], tokenize=True)
        assert "joren.janssens@euredact.be" not in result.redacted_text
        assert result.tokens
        for token, value in result.tokens.items():
            assert TOKEN.match(token), token
            assert token in result.redacted_text
            assert value in PROMPT
        assert restore(result.redacted_text, result.tokens) == PROMPT

    def test_tokens_carry_the_entity_type(self, sdk):
        result = sdk.redact("mail: jan@example.com", countries=["NL"], tokenize=True)
        (token,) = result.tokens
        assert token.startswith("EMAIL_")
        assert result.tokens[token] == "jan@example.com"

    def test_same_value_same_token_within_a_call(self, sdk):
        text = "jan@example.com wrote to piet@example.com, cc jan@example.com"
        result = sdk.redact(text, countries=["NL"], tokenize=True)
        assert len(result.tokens) == 2
        assert len(result.detections) == 3
        assert restore(result.redacted_text, result.tokens) == text

    def test_a_new_call_gets_new_tokens(self, sdk):
        a = sdk.redact("mail: jan@example.com", countries=["NL"], tokenize=True, cache=False)
        b = sdk.redact("mail: jan@example.com", countries=["NL"], tokenize=True, cache=False)
        assert set(a.tokens) != set(b.tokens)

    def test_tokens_are_per_call_not_per_instance(self, sdk):
        """Unlike referential labels, nothing is retained between calls."""
        sdk.redact("mail: jan@example.com", countries=["NL"], tokenize=True)
        plain = sdk.redact("mail: jan@example.com", countries=["NL"])
        assert plain.tokens == {}
        assert plain.redacted_text == "mail: [EMAIL]"

    def test_custom_pattern_name_is_the_type_prefix(self, sdk):
        sdk.add_custom_pattern("TICKET", r"\bTCK-\d{5}\b")
        result = sdk.redact("see TCK-12345", tokenize=True)
        (token,) = result.tokens
        assert token.startswith("TICKET_")
        assert restore(result.redacted_text, result.tokens) == "see TCK-12345"

    def test_tokenize_and_referential_integrity_are_exclusive(self, sdk):
        with pytest.raises(ValueError, match="tokenize and referential_integrity"):
            sdk.redact("x", tokenize=True, referential_integrity=True)
        # The guard runs before the cloud dispatch, so cloud mode says the same.
        with pytest.raises(ValueError, match="tokenize and referential_integrity"):
            sdk.redact("x", countries=["BE"], mode="cloud",
                       tokenize=True, referential_integrity=True)

    def test_a_document_that_already_holds_tokens_is_not_collided_with(self):
        """Redacting an LLM's reply to a tokenized prompt is the common case."""
        text = "Reply to EMAIL_ABCD and jan@example.com"
        mapper = TokenMapper(text, [Detection(
            entity_type=EntityType.EMAIL, start=24, end=39, text="jan@example.com",
            source=DetectionSource.RULES, country=None)])
        assert "EMAIL_ABCD" in mapper._taken
        seen = {mapper.get_token(d, "v%d" % i) for i, d in enumerate([Detection(
            entity_type=EntityType.EMAIL, start=0, end=1, text="", source=DetectionSource.RULES,
            country=None)] * 50)}
        assert "EMAIL_ABCD" not in seen and len(seen) == 50

    def test_batch_and_iter_carry_tokens(self, sdk):
        texts = ["mail: jan@example.com", "tel +31 6 12345678"]
        for result, text in zip(sdk.redact_batch(texts, countries=["NL"], tokenize=True), texts):
            assert restore(result.redacted_text, result.tokens) == text
        for result, text in zip(sdk.redact_iter(iter(texts), countries=["NL"], tokenize=True), texts):
            assert restore(result.redacted_text, result.tokens) == text

    @pytest.mark.asyncio
    async def test_async_entry_points_carry_tokens(self, sdk):
        text = "mail: jan@example.com"
        result = await sdk.aredact(text, countries=["NL"], tokenize=True)
        assert restore(result.redacted_text, result.tokens) == text
        (result,) = await sdk.aredact_batch([text], countries=["NL"], tokenize=True)
        assert restore(result.redacted_text, result.tokens) == text


class TestRestore:
    def test_empty_mapping_is_identity(self):
        assert restore("EMAIL_ABCD stays", {}) == "EMAIL_ABCD stays"

    def test_every_occurrence_is_restored(self):
        out = restore("EMAIL_ABCD, again EMAIL_ABCD.", {"EMAIL_ABCD": "a@b.c"})
        assert out == "a@b.c, again a@b.c."

    def test_a_token_glued_to_other_characters_is_still_restored(self):
        assert restore("EMAIL_ABCDs inbox", {"EMAIL_ABCD": "a@b.c"}) == "a@b.cs inbox"

    def test_longest_token_wins_when_one_prefixes_another(self):
        tokens = {"ID_ABCD": "short", "ID_ABCDEFGH_ABCD": "long"}
        assert restore("ID_ABCDEFGH_ABCD and ID_ABCD", tokens) == "long and short"

    def test_backslashes_and_group_references_in_values_are_literal(self):
        tokens = {"SECRET_ABCD": r"p\1$&\g<0>"}
        assert restore("key SECRET_ABCD", tokens) == r"key p\1$&\g<0>"


class TestCache:
    def test_a_plain_hit_is_not_served_to_a_tokenized_call(self, sdk):
        text = "mail: jan@example.com"
        assert sdk.redact(text, countries=["NL"]).redacted_text == "mail: [EMAIL]"
        result = sdk.redact(text, countries=["NL"], tokenize=True)
        assert result.tokens and "[EMAIL]" not in result.redacted_text

    def test_tokens_count_towards_the_cache_budget(self):
        from euredact.cache import _result_chars
        from euredact.types import RedactResult

        bare = RedactResult(redacted_text="x", detections=[])
        with_tokens = RedactResult(redacted_text="x", detections=[],
                                   tokens={"EMAIL_ABCD": "jan@example.com"})
        assert _result_chars(with_tokens) - _result_chars(bare) == len("EMAIL_ABCD") + len(
            "jan@example.com")


class TestApplyReplacements:
    """The helper is shared by the rules and cloud paths; only the cloud path
    can hand it spans that overlap, so that is tested on the helper itself."""

    @staticmethod
    def _det(start, end, text):
        return Detection(entity_type=EntityType.OTHER, start=start, end=end, text=text,
                         source=DetectionSource.CLOUD, country=None)

    def test_an_overlapping_tail_is_masked_not_leaked(self):
        text = "0123456789"
        dets = [self._det(0, 5, "01234"), self._det(3, 8, "34567")]
        out = _apply_replacements(text, dets, lambda d, s: f"<{s}>")
        assert out == "<01234><567>89"

    def test_a_span_inside_an_earlier_one_is_dropped(self):
        text = "0123456789"
        dets = [self._det(0, 8, "01234567"), self._det(3, 5, "34")]
        assert _apply_replacements(text, dets, lambda d, s: "#") == "#89"

    def test_tokens_over_overlapping_spans_still_round_trip(self):
        text = "0123456789"
        dets = [self._det(0, 5, "01234"), self._det(3, 8, "34567")]
        mapper = TokenMapper(text, dets)
        out = _apply_replacements(text, dets, mapper.get_token)
        assert restore(out, mapper.tokens) == text


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
    """Route mode="cloud" through a scripted service response."""
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    payloads = {}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def redact(self, text, *, country, **kw):
            return _to_result(payloads.get("payload", CLOUD_PAYLOAD), text=text)

    monkeypatch.setattr("euredact.cloud.client.CloudClient", FakeClient)
    yield payloads
    cloud_config.reset()


class TestCloud:
    def test_without_tokenize_the_service_text_is_returned_verbatim(self, sdk, cloud):
        result = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud")
        assert result.redacted_text == CLOUD_PAYLOAD["redacted_text"]
        assert result.tokens == {}

    def test_tokenize_rebuilds_from_the_service_spans(self, sdk, cloud):
        result = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", tokenize=True)
        assert result.source == "cloud"
        assert "Bas Verhoeven" not in result.redacted_text
        assert "bas@example.be" not in result.redacted_text
        assert len(result.tokens) == 2
        assert restore(result.redacted_text, result.tokens) == CLOUD_DOC

    def test_overlapping_service_spans_are_fully_masked(self, sdk, cloud):
        cloud["payload"] = dict(CLOUD_PAYLOAD, entities=[
            {"start": 8, "end": 21, "text": "Bas Verhoeven", "type": "PERSON_NAME",
             "source": "model"},
            {"start": 12, "end": 27, "text": "Verhoeven, mail", "type": "OTHER",
             "source": "model"},
        ])
        result = sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", tokenize=True)
        assert "Verhoeven" not in result.redacted_text
        assert "mail" not in result.redacted_text
        assert restore(result.redacted_text, result.tokens) == CLOUD_DOC

    def test_spans_that_do_not_match_the_document_raise(self, sdk, cloud):
        cloud["payload"] = dict(CLOUD_PAYLOAD, entities=[
            {"start": 0, "end": 7, "text": "Someone", "type": "PERSON_NAME",
             "source": "model"},
        ])
        with pytest.raises(CloudError, match="span offsets"):
            sdk.redact(CLOUD_DOC, countries=["BE"], mode="cloud", tokenize=True)
