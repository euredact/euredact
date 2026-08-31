"""[CLOUD EXTENSION] The cloud tier.

The single most important test in this file is
`test_unconfigured_cloud_mode_raises_instead_of_returning_rules_only`. Before
this was implemented, `redact(mode="cloud")` returned rules-only output with no
error: the caller believed names, employers and diagnoses had been checked, saw
a plausible redacted document, and shipped it with the PII still in it.
"""
from __future__ import annotations

import json

import pytest

import euredact
from euredact.cloud import config as cloud_config
from euredact.cloud.client import (
    CloudClient, CloudError, NotConfiguredError, QuotaExceededError, TooLargeError,
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


def test_429_is_retried_then_surfaces_as_quota_exceeded():
    calls = []

    def handler(request):
        calls.append(1)
        return _response(429, {"error": "daily quota exhausted",
                               "detail": {"used": 100, "limit": 100}},
                         headers={"Retry-After": "0"})

    with _client(handler, max_retries=2) as client:
        with pytest.raises(QuotaExceededError) as exc:
            client.redact(DOC, country="BE")
    assert exc.value.detail == {"used": 100, "limit": 100}
    assert len(calls) == 3, "initial attempt plus two retries"


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
