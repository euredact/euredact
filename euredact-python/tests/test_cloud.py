"""[CLOUD EXTENSION] The cloud tier.

The single most important test in this file is
`test_unconfigured_cloud_mode_raises_instead_of_returning_rules_only`. Before
this was implemented, `redact(mode="cloud")` returned rules-only output with no
error: the caller believed names, employers and diagnoses had been checked, saw
a plausible redacted document, and shipped it with the PII still in it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import (
    CloudClient, CloudError, NotConfiguredError, QuotaExceededError, RateLimitedError,
    TooLargeError,
)
from euredact.types import DetectionSource, EntityType

httpx = pytest.importorskip("httpx")

DOC = "Patiënt Bas Verhoeven, tel +32 475 12 34 56, mail bas@example.be"


@pytest.fixture(autouse=True)
def _clean_config():
    cloud_config.reset()
    yield
    cloud_config.reset()


def _response(status, payload=None, headers=None):
    return httpx.Response(status, json=payload if payload is not None else {},
                          headers=headers or {})


def _client(handler, **cfg):
    """A CloudClient wired to a scripted transport."""
    cloud_config.configure(api_key="erk_test", base_url="https://api.test", **cfg)
    transport = httpx.MockTransport(handler)
    return CloudClient(client=httpx.Client(transport=transport))


SUCCESS = {
    "job_id": "job-1",
    "status": "succeeded",
    "redacted_text": "Patiënt [PERSON_NAME], tel [PHONE], mail [EMAIL]",
    "entities": [
        {"start": 8, "end": 21, "text": "Bas Verhoeven", "type": "PERSON_NAME",
         "source": "model", "match": "exact_body"},
        {"start": 27, "end": 43, "text": "+32 475 12 34 56", "type": "PHONE",
         "source": "rules"},
    ],
    "unlocated": [],
    "model_version": "euredact-9b@2026-08-31",
}


# -- the bug this closes ----------------------------------------------------

def test_unconfigured_cloud_mode_raises_instead_of_returning_rules_only():
    """Silent degradation is the worst failure this library can have."""
    with pytest.raises(NotConfiguredError) as exc:
        euredact.redact(DOC, countries=["BE"], mode="cloud")
    assert "configure" in str(exc.value)


def test_rules_mode_is_untouched_by_all_of_this():
    result = euredact.redact(DOC, countries=["BE"])
    assert result.source == "rules"
    assert any(d.entity_type == EntityType.PHONE for d in result.detections)


def test_unknown_mode_raises():
    with pytest.raises(ValueError, match="unknown mode"):
        euredact.redact(DOC, countries=["BE"], mode="magic")


# -- configuration ----------------------------------------------------------

def test_configure_reads_the_environment(monkeypatch):
    monkeypatch.setenv("EUREDACT_API_KEY", "erk_from_env")
    cfg = euredact.configure()
    assert cfg.api_key == "erk_from_env"


def test_configure_without_a_key_anywhere_raises(monkeypatch):
    monkeypatch.delenv("EUREDACT_API_KEY", raising=False)
    with pytest.raises(ValueError, match="no API key"):
        euredact.configure()


def test_base_url_trailing_slash_is_normalised():
    cfg = euredact.configure(api_key="k", base_url="https://api.test/")
    assert cfg.base_url == "https://api.test"


# -- the happy path ---------------------------------------------------------

def test_redact_returns_cloud_detections():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["Authorization"]
        seen["idem"] = request.headers.get("Idempotency-Key")
        seen["body"] = json.loads(request.content)
        return _response(200, SUCCESS)

    with _client(handler) as client:
        result = client.redact(DOC, country="BE")

    assert seen["url"] == "https://api.test/v1/redact"
    assert seen["auth"] == "Bearer erk_test"
    assert seen["idem"], "every request must carry an Idempotency-Key"
    assert seen["body"]["country"] == "BE"

    assert result.source == "cloud"
    assert "Bas Verhoeven" not in result.redacted_text
    types = {d.entity_type for d in result.detections}
    assert EntityType.PERSON_NAME in types
    by_type = {d.entity_type: d for d in result.detections}
    assert by_type[EntityType.PERSON_NAME].source is DetectionSource.CLOUD
    assert by_type[EntityType.PHONE].source is DetectionSource.RULES


def test_detections_are_sorted_by_position():
    payload = dict(SUCCESS, entities=list(reversed(SUCCESS["entities"])))
    with _client(lambda r: _response(200, payload)) as client:
        result = client.redact(DOC, country="BE")
    assert [d.start for d in result.detections] == sorted(d.start for d in result.detections)


def test_an_unknown_type_survives_as_a_string():
    """A client one release behind the service must not lose a whole category."""
    payload = dict(SUCCESS, entities=[
        {"start": 0, "end": 7, "text": "Patiënt", "type": "BRAND_NEW_TYPE",
         "source": "model"}])
    with _client(lambda r: _response(200, payload)) as client:
        result = client.redact(DOC, country="BE")
    assert result.detections[0].entity_type == "BRAND_NEW_TYPE"


def test_the_canon_spelling_is_what_callers_see():
    """NAME was the old cloud-extension name; PERSON_NAME is the canon."""
    assert EntityType.NAME is EntityType.PERSON_NAME
    assert EntityType("NAME").value == "PERSON_NAME"


# -- the 202 -> polling upgrade ---------------------------------------------

def test_a_job_past_the_sync_window_is_polled_transparently():
    """Callers never write the branch for 'did it finish in time?'."""
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.method == "POST":
            return _response(202, {"job_id": "job-1", "status": "queued",
                                   "location": "/v1/jobs/job-1"},
                             headers={"Location": "/v1/jobs/job-1"})
        if len(calls) < 4:
            return _response(200, {"job_id": "job-1", "status": "running"})
        return _response(200, SUCCESS)

    with _client(handler, poll_timeout_s=10) as client:
        result = client.redact(DOC, country="BE")

    assert result.source == "cloud"
    assert calls[0].endswith("/v1/redact")
    assert calls[1].endswith("/v1/jobs/job-1")


def test_polling_gives_up_eventually():
    def handler(request):
        if request.method == "POST":
            return _response(202, {"job_id": "j", "location": "/v1/jobs/j"},
                             headers={"Location": "/v1/jobs/j"})
        return _response(200, {"job_id": "j", "status": "running"})

    with _client(handler, poll_timeout_s=0.2) as client:
        with pytest.raises(CloudError, match="did not complete"):
            client.redact(DOC, country="BE")


# -- errors -----------------------------------------------------------------

def test_413_is_permanent_and_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return _response(413, {"error": "prompt is 9000 tokens, over the 6400 limit"})

    with _client(handler) as client:
        with pytest.raises(TooLargeError, match="over the 6400 limit"):
            client.redact(DOC, country="BE")
    assert len(calls) == 1, "413 is permanent; retrying walks into the same wall"


def test_401_is_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return _response(401, {"error": "invalid API key"})

    with _client(handler) as client:
        with pytest.raises(CloudError, match="authentication failed"):
            client.redact(DOC, country="BE")
    assert len(calls) == 1


def test_a_quota_429_raises_at_once():
    """The gateway's daily quota will not reset before the day does; retrying
    it only delayed the error through every backoff (rules-engine#89)."""
    calls = []

    def handler(request):
        calls.append(1)
        return _response(429, {"error": "daily quota exhausted",
                               "detail": {"used": 100, "limit": 100}},
                         headers={"Retry-After": "0"})

    with _client(handler, max_retries=2) as client:
        with pytest.raises(QuotaExceededError) as exc:
            client.redact(DOC, country="BE")
    assert not isinstance(exc.value, RateLimitedError)
    assert exc.value.detail == {"used": 100, "limit": 100}
    assert len(calls) == 1, "a quota answer is final"


def test_an_edge_429_is_retried_then_surfaces_as_rate_limited():
    """nginx's rate limit answers in HTML and clears within seconds."""
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, text="<html><body>429 Too Many Requests</body></html>",
                              headers={"Retry-After": "0", "Content-Type": "text/html"})

    with _client(handler, max_retries=2) as client:
        with pytest.raises(RateLimitedError) as exc:
            client.redact(DOC, country="BE")
    assert isinstance(exc.value, QuotaExceededError), "what every 429 raised before"
    assert len(calls) == 3, "initial attempt plus two retries"


def test_an_edge_429_that_clears_recovers():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, text="<html>429</html>", headers={"Retry-After": "0"})
        return _response(200, SUCCESS)

    with _client(handler) as client:
        assert client.redact(DOC, country="BE").source == "cloud"
    assert len(calls) == 2


def test_retry_after_is_obeyed(monkeypatch):
    slept = []
    monkeypatch.setattr("euredact.cloud.client.time.sleep", slept.append)
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return _response(503, {"error": "restarting"},
                             headers={"Retry-After": "7"})
        return _response(200, SUCCESS)

    with _client(handler) as client:
        client.redact(DOC, country="BE")
    assert slept == [7.0], "the service said 7s; do not second-guess it"


def test_transient_5xx_recovers():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return _response(502, {"error": "bad gateway"},
                             headers={"Retry-After": "0"})
        return _response(200, SUCCESS)

    with _client(handler) as client:
        result = client.redact(DOC, country="BE")
    assert result.source == "cloud" and len(calls) == 2


def test_a_retry_reuses_the_idempotency_key():
    """A network blip must not create a second job or a second usage row."""
    keys = []

    def handler(request):
        keys.append(request.headers["Idempotency-Key"])
        if len(keys) == 1:
            return _response(503, {"error": "nope"}, headers={"Retry-After": "0"})
        return _response(200, SUCCESS)

    with _client(handler) as client:
        client.redact(DOC, country="BE")
    assert len(keys) == 2 and keys[0] == keys[1]


# -- options the service cannot honour --------------------------------------

@pytest.mark.parametrize("kwargs,match", [
    ({"countries": None}, "exactly one country"),
    ({"countries": ["BE", "NL"]}, "exactly one country"),
    ({"countries": ["BE"], "country_hint": ["NL"]}, "country_hint"),
    ({"countries": ["BE"], "referential_integrity": True}, "referential_integrity"),
    ({"countries": ["BE"], "coref": True}, "coref"),
])
def test_unsupported_options_raise_rather_than_being_ignored(kwargs, match):
    """Ignoring one silently returns a result that is not what was asked for."""
    euredact.configure(api_key="erk_test", base_url="https://api.test")
    with pytest.raises(ValueError, match=match):
        euredact.redact(DOC, mode="cloud", **kwargs)


# -- async twin -------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_client_matches_the_sync_contract():
    from euredact.cloud.client import AsyncCloudClient

    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    transport = httpx.MockTransport(lambda r: _response(200, SUCCESS))
    async with AsyncCloudClient(client=httpx.AsyncClient(transport=transport)) as c:
        result = await c.redact(DOC, country="BE")
    assert result.source == "cloud"
    assert EntityType.PERSON_NAME in {d.entity_type for d in result.detections}


@pytest.mark.asyncio
async def test_async_client_polls_a_202():
    from euredact.cloud.client import AsyncCloudClient

    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.method == "POST":
            return _response(202, {"job_id": "j", "location": "/v1/jobs/j"},
                             headers={"Location": "/v1/jobs/j"})
        return _response(200, SUCCESS)

    cloud_config.configure(api_key="erk_test", base_url="https://api.test",
                           poll_timeout_s=10)
    transport = httpx.MockTransport(handler)
    async with AsyncCloudClient(client=httpx.AsyncClient(transport=transport)) as c:
        result = await c.redact(DOC, country="BE")
    assert result.source == "cloud" and len(calls) == 2


@pytest.mark.asyncio
async def test_async_413_is_permanent():
    from euredact.cloud.client import AsyncCloudClient

    calls = []

    def handler(request):
        calls.append(1)
        return _response(413, {"error": "too big"})

    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    transport = httpx.MockTransport(handler)
    async with AsyncCloudClient(client=httpx.AsyncClient(transport=transport)) as c:
        with pytest.raises(TooLargeError):
            await c.redact(DOC, country="BE")
    assert len(calls) == 1


# -- the extra --------------------------------------------------------------

def test_missing_httpx_says_which_extra_to_install(monkeypatch):
    """`pip install euredact` alone has no HTTP client; say so usefully."""
    import builtins

    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("No module named 'httpx'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    cloud_config.configure(api_key="erk_test")
    with pytest.raises(NotConfiguredError, match=r"euredact\[cloud\]"):
        CloudClient()


# -- local-first: what is sent, and where the answer lands (rules-engine#28) --

class _Wire:
    """mode="cloud" through the real client and a scripted transport.

    The stand-in service follows the local-first contract: it looks for
    ``found`` in the text it *received* and answers with spans relative to
    that text. It never sees the caller's original, so a test that passes
    here cannot be relying on it.
    """

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.found: dict[str, str] = {}
        self.entities: list[dict] | None = None

    def handler(self, request):
        body = json.loads(request.content)
        self.sent.append(body)
        text = body["text"]
        entities = self.entities
        if entities is None:
            entities = []
            for needle, type_ in self.found.items():
                start = text.find(needle)
                while start != -1:
                    entities.append({
                        "start": start, "end": start + len(needle), "text": needle,
                        "type": type_, "source": "model", "match": "exact_body"})
                    start = text.find(needle, start + 1)
        return _response(200, {"job_id": "job-1", "status": "succeeded",
                               "redacted_text": text, "entities": entities,
                               "unlocated": []})

    @property
    def text(self) -> str:
        assert len(self.sent) == 1, "exactly one request per document"
        return self.sent[0]["text"]


@pytest.fixture
def wire(monkeypatch):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    w = _Wire()
    monkeypatch.setattr(
        "euredact.cloud.client.CloudClient",
        lambda *a, **kw: CloudClient(
            client=httpx.Client(transport=httpx.MockTransport(w.handler))))
    return w


PAYMENT = "Joren Janssens needs to pay 50EUR to Nick Bols on NL91 ABNA 0417 1643 00"
LEDGER = "IBAN NL91 ABNA 0417 1643 00 belongs to Nick Bols, tel +31 6 12345678"
VISIT = "Bezoekadres: Kerkstraat 12, 9000 Gent. Contact: jan@example.be"


def test_cloud_mode_sends_only_the_locally_masked_text(wire):
    """The claim the documentation makes: identifiers the rules engine can
    find are replaced on the caller's machine, before the request exists."""
    euredact.EuRedact().redact(PAYMENT, countries=["NL"], mode="cloud")
    assert wire.text == (
        "Joren Janssens needs to pay 50EUR to Nick Bols on [BANK_ACCOUNT]")
    assert "NL91" not in json.dumps(wire.sent)


def test_nothing_structured_travels_with_the_text(wire):
    """One ``text`` field: no types list, no offsets, no values beside it."""
    euredact.EuRedact().redact(PAYMENT, countries=["NL"], mode="cloud")
    assert wire.sent[0] == {
        "text": "Joren Janssens needs to pay 50EUR to Nick Bols on [BANK_ACCOUNT]",
        "country": "NL", "language": "", "priority": "interactive"}


def test_service_spans_are_mapped_back_onto_the_original(wire):
    """The service indexes the masked text; the caller gets the original's."""
    wire.found = {"Nick Bols": "PERSON_NAME"}
    result = euredact.EuRedact().redact(LEDGER, countries=["NL"], mode="cloud")

    assert wire.text == "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]"
    assert result.source == "cloud"
    assert result.redacted_text == (
        "IBAN [BANK_ACCOUNT] belongs to [PERSON_NAME], tel [PHONE]")
    assert [(d.entity_type, d.text, d.source) for d in result.detections] == [
        (EntityType.BANK_ACCOUNT, "NL91 ABNA 0417 1643 00", DetectionSource.RULES),
        (EntityType.PERSON_NAME, "Nick Bols", DetectionSource.CLOUD),
        (EntityType.PHONE, "+31 6 12345678", DetectionSource.RULES),
    ]
    for d in result.detections:
        assert LEDGER[d.start:d.end] == d.text


def test_tokenize_does_not_change_what_is_sent(wire):
    """The model was trained on ``[TYPE]``; a token on the wire would be read
    as ordinary text. Tokens are minted locally, after the response."""
    wire.found = {"Nick Bols": "PERSON_NAME"}
    result = euredact.EuRedact().redact(
        LEDGER, countries=["NL"], mode="cloud", tokenize=True)
    assert wire.text == "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]"
    assert len(result.tokens) == 3
    assert "[" not in result.redacted_text
    assert euredact.restore(result.redacted_text, result.tokens) == LEDGER


def test_an_allowlisted_value_is_still_masked_on_the_wire(wire):
    """An exemption says what the caller wants back, not what may leave."""
    wire.found = {"Nick Bols": "PERSON_NAME"}
    sdk = euredact.EuRedact(allowlist=["NL91ABNA0417164300"])
    result = sdk.redact(LEDGER, countries=["NL"], mode="cloud")
    assert wire.text == "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]"
    assert result.redacted_text == (
        "IBAN NL91 ABNA 0417 1643 00 belongs to [PERSON_NAME], tel [PHONE]")
    assert [e.text for e in result.exempted] == ["NL91 ABNA 0417 1643 00"]


def test_an_allowlisted_cloud_type_is_exempted_after_the_response(wire):
    wire.found = {"Nick Bols": "PERSON_NAME"}
    result = euredact.EuRedact().redact(
        LEDGER, countries=["NL"], mode="cloud", allowlist=["Nick Bols"])
    assert result.redacted_text == (
        "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]")
    assert [e.text for e in result.exempted] == ["Nick Bols"]


def test_dates_are_masked_before_sending_whatever_detect_dates_says(wire):
    """The model is trained against rules output with dates on, and a date of
    birth the rules can place has no reason to travel."""
    doc = "Mevrouw Peeters, geboren op 12/03/1985, woont in Gent."
    result = euredact.EuRedact().redact(doc, countries=["BE"], mode="cloud")
    assert wire.text == "Mevrouw Peeters, geboren op [DOB], woont in Gent."
    assert [d.entity_type for d in result.detections] == [EntityType.DOB]


def test_custom_patterns_are_masked_before_sending(wire):
    """The service has never heard of the caller's own patterns."""
    sdk = euredact.EuRedact()
    sdk.add_custom_pattern("EMPLOYEE_ID", r"EMP-\d{6}")
    wire.found = {"Nick Bols": "PERSON_NAME"}
    result = sdk.redact("Badge EMP-004211 van Nick Bols", countries=["BE"], mode="cloud")
    assert wire.text == "Badge [EMPLOYEE_ID] van Nick Bols"
    assert result.redacted_text == "Badge [EMPLOYEE_ID] van [PERSON_NAME]"


def test_a_span_across_a_placeholder_takes_the_whole_local_detection(wire):
    """An address the model reports around a locally masked postal code."""
    wire.found = {"Kerkstraat 12, [POSTAL_CODE] Gent": "ADDRESS"}
    result = euredact.EuRedact().redact(
        VISIT, countries=["BE"], mode="cloud", tokenize=True)
    address = next(d for d in result.detections
                   if d.entity_type == EntityType.ADDRESS)
    assert address.text == "Kerkstraat 12, 9000 Gent"
    assert VISIT[address.start:address.end] == address.text
    assert "9000" not in result.redacted_text
    assert "POSTAL_CODE" not in result.redacted_text, "the address covers it"
    assert euredact.restore(result.redacted_text, result.tokens) == VISIT


def test_a_span_that_ends_inside_a_placeholder_never_splits_the_value(wire):
    """Offsets inside a label have no counterpart in the original, so they
    snap outward: over-masking is the safe direction."""
    wire.entities = [{"start": 13, "end": 31, "text": "Kerkstraat 12, [PO",
                      "type": "ADDRESS", "source": "model"}]
    result = euredact.EuRedact().redact(VISIT, countries=["BE"], mode="cloud")
    assert wire.text == (
        "Bezoekadres: Kerkstraat 12, [POSTAL_CODE] Gent. Contact: [EMAIL]")
    assert result.redacted_text == "Bezoekadres: [ADDRESS] Gent. Contact: [EMAIL]"


def test_a_span_naming_only_a_placeholder_adds_nothing(wire):
    """The label is not part of the document; the local detection stands."""
    wire.found = {"[BANK_ACCOUNT]": "BANK_ACCOUNT", "Nick Bols": "PERSON_NAME"}
    result = euredact.EuRedact().redact(LEDGER, countries=["NL"], mode="cloud")
    assert [d.entity_type for d in result.detections] == [
        EntityType.BANK_ACCOUNT, EntityType.PERSON_NAME, EntityType.PHONE]
    assert result.detections[0].source is DetectionSource.RULES


def test_a_span_that_does_not_match_the_sent_text_raises(wire):
    """Not only under tokenize: every span now has to be placed locally, and
    one that cannot be would mask the wrong characters."""
    wire.entities = [{"start": 0, "end": 9, "text": "Nick Bols",
                      "type": "PERSON_NAME", "source": "model"}]
    with pytest.raises(CloudError, match="span offsets"):
        euredact.EuRedact().redact(LEDGER, countries=["NL"], mode="cloud")


def test_a_span_past_the_end_of_the_sent_text_raises(wire):
    wire.entities = [{"start": 50, "end": 500, "text": "x",
                      "type": "PERSON_NAME", "source": "model"}]
    with pytest.raises(CloudError, match="span offsets"):
        euredact.EuRedact().redact(LEDGER, countries=["NL"], mode="cloud")


def test_offsets_survive_normalisation_and_astral_characters(wire):
    """NFD input changes length under NFC, and an emoji is two UTF-16 units:
    both sit between the service's numbers and the caller's."""
    import unicodedata

    doc = unicodedata.normalize(
        "NFD", "\U0001F600 Patiënt René Müller, IBAN NL91 ABNA 0417 1643 00, "
               "arts Zoë Smit \U0001F600 en Anna Berger")
    wire.found = {"Anna Berger": "PERSON_NAME"}
    result = euredact.EuRedact().redact(doc, countries=["NL"], mode="cloud")
    assert "NL91" not in wire.text and "[BANK_ACCOUNT]" in wire.text
    name = next(d for d in result.detections
                if d.entity_type == EntityType.PERSON_NAME)
    assert doc[name.start:name.end] == "Anna Berger"
    assert result.redacted_text == doc.replace(
        "NL91 ABNA 0417 1643 00", "[BANK_ACCOUNT]").replace(
        "Anna Berger", "[PERSON_NAME]")


def test_the_local_evidence_is_reported_in_cloud_mode(wire):
    result = euredact.EuRedact().redact(LEDGER, countries=["NL"], mode="cloud")
    assert result.detection_mode == "declared"
    assert dict(result.inferred_countries).get("NL")


def test_a_cached_rules_result_is_not_mutated_by_cloud_mode(wire):
    """The local pass shares the result cache with rules mode."""
    sdk = euredact.EuRedact()
    wire.found = {"Nick Bols": "PERSON_NAME"}
    sdk.redact(LEDGER, countries=["NL"], mode="cloud")
    rules = sdk.redact(LEDGER, countries=["NL"], detect_dates=True)
    assert rules.source == "rules"
    assert rules.redacted_text == "IBAN [BANK_ACCOUNT] belongs to Nick Bols, tel [PHONE]"
    assert len(rules.detections) == 2


def test_the_client_has_no_rules_only_switch():
    """It never had a public surface in the SDK, and from a local-first
    client it means nothing: the rules already ran."""
    with _client(lambda r: _response(200, SUCCESS)) as client:
        with pytest.raises(TypeError):
            client.redact(DOC, country="BE", rules_only=True)


# ── TLS only (rules-engine#86) ─────────────────────────────────────────


@pytest.mark.parametrize("url", [
    "http://api.example.com", "http://api.euredact.dev", "HTTP://api.example.com",
    "ftp://api.example.com", "api.euredact.dev", "https://", "",
])
def test_a_base_url_without_tls_is_refused(url):
    with pytest.raises(ValueError, match="must start with https://"):
        cloud_config.configure(api_key="erk_test", base_url=url or "nohost")


@pytest.mark.parametrize("url", [
    "https://api.euredact.dev", "https://gw.example.com:8443/",
    "http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000",
])
def test_https_and_loopback_http_are_accepted(url):
    assert cloud_config.configure(api_key="erk_test", base_url=url).base_url == url.rstrip("/")


def test_the_environment_variable_is_checked_too(monkeypatch):
    monkeypatch.setenv("EUREDACT_BASE_URL", "http://api.example.com")
    with pytest.raises(ValueError, match="must start with https://"):
        cloud_config.configure(api_key="erk_test")


def test_a_hand_built_config_is_checked_too():
    with pytest.raises(ValueError, match="must start with https://"):
        cloud_config.CloudConfig(api_key="erk_test", base_url="http://api.example.com")


# -- what a request cost (rules-engine#89) -----------------------------------

USAGE = json.loads(
    (Path(__file__).resolve().parents[2] / "conformance" / "cloud_usage.json").read_text())


def _as_wire(usage):
    if usage is None:
        return None
    return {"tokens": usage.tokens, "billing_rate": usage.billing_rate,
            "credits": usage.credits,
            "factors": [{"code": f.code, "detail": f.detail,
                         "types": list(f.types) if f.types is not None else None}
                        for f in usage.factors]}


@pytest.mark.parametrize("case", USAGE["cases"], ids=lambda c: c["id"])
def test_the_usage_block_is_read_as_both_sdks_read_it(case):
    payload = dict(SUCCESS)
    if "usage" in case:
        payload["usage"] = case["usage"]
    with _client(lambda r: _response(200, payload)) as client:
        result = client.redact(DOC, country="BE")
    assert _as_wire(result.cloud.usage) == case["expect"]


def test_usage_reaches_the_caller_through_cloud_mode(wire, monkeypatch):
    usage = USAGE["cases"][0]["usage"]
    original = wire.handler

    def with_usage(request):
        response = original(request)
        return _response(200, dict(response.json(), usage=usage))
    monkeypatch.setattr(wire, "handler", with_usage)
    result = euredact.EuRedact().redact(PAYMENT, countries=["NL"], mode="cloud")
    assert result.cloud.usage == euredact.Usage(
        tokens=3644, billing_rate=1.0, credits=3644,
        factors=tuple(euredact.UsageFactor(code=f["code"], detail=f["detail"],
                                           types=tuple(f["types"]) if "types" in f else None)
                      for f in usage["factors"]))


def test_a_rules_result_has_no_cloud_info():
    assert euredact.redact(DOC, countries=["BE"]).cloud is None
