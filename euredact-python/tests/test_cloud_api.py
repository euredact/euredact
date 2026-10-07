"""[CLOUD EXTENSION] Everything an API key can do, through the SDK (rules-engine#89).

The parsing cases live in ``conformance/cloud_result.json`` and run in both
SDKs; the rest of this file pins the behaviour around them -- what is retried,
what raises, and which request each call makes.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

import euredact
from euredact.cloud import (
    Account,
    Batches,
    CloudClient,
    CloudError,
    Jobs,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    ResultExpiredError,
)
from euredact.cloud import config as cloud_config

httpx = pytest.importorskip("httpx")

CASES = json.loads(
    (
        Path(__file__).resolve().parents[2] / "conformance" / "cloud_result.json"
    ).read_text()
)
DOC = "Patiënt Bas Verhoeven, tel +32 475 12 34 56"


@pytest.fixture(autouse=True)
def _clean_config(monkeypatch):
    cloud_config.reset()
    monkeypatch.setattr("euredact.cloud.client.time.sleep", lambda s: None)
    monkeypatch.setattr("euredact.cloud.account.time.sleep", lambda s: None)
    yield
    cloud_config.reset()


class _Service:
    """A scripted service: answers in order, records every request."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests: list[httpx.Request] = []

    def handler(self, request):
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, httpx.Response):
            return answer
        status, body = answer
        return httpx.Response(status, json=body)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def _configure(**cfg):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test", **cfg)


def _without_raw(value):
    data = asdict(value)
    data.pop("raw", None)
    if "series" in data:
        data["series"] = [
            {k: v for k, v in item.items() if k != "raw"} for item in data["series"]
        ]
    return data


# -- a result's cloud block --------------------------------------------------


@pytest.mark.parametrize("case", CASES["results"], ids=lambda c: c["id"])
def test_the_cloud_block_is_read_as_both_sdks_read_it(case):
    _configure()
    service = _Service((200, case["wire"]))
    with CloudClient(client=service.client()) as client:
        cloud = client.redact(DOC, country="BE").cloud
    assert {
        "job_id": cloud.job_id,
        "model_version": cloud.model_version,
        "has_usage": cloud.usage is not None,
        "unlocated": [
            {
                "text": u.text,
                "entity_type": str(getattr(u.entity_type, "value", u.entity_type)),
            }
            for u in cloud.unlocated
        ],
    } == case["expect"]


# -- which 429 is final --------------------------------------------------------


@pytest.mark.parametrize("case", CASES["throttling"], ids=lambda c: c["id"])
def test_a_quota_429_is_final_and_an_edge_429_is_retried(case):
    _configure(max_retries=2)
    response = (
        httpx.Response(case["status"], json=case["json"])
        if "json" in case
        else httpx.Response(
            case["status"], text=case["text"], headers={"Content-Type": "text/html"}
        )
    )
    service = _Service(response)
    with CloudClient(client=service.client()) as client:
        with pytest.raises(QuotaExceededError) as exc:
            client.redact(DOC, country="BE")
    if case["expect"] == "quota":
        assert not isinstance(exc.value, RateLimitedError)
        assert len(service.requests) == 1
    else:
        assert isinstance(exc.value, RateLimitedError)
        assert len(service.requests) == 3


# -- top-level idempotency key -------------------------------------------------


def test_redact_in_cloud_mode_sends_the_callers_idempotency_key(monkeypatch):
    _configure()
    service = _Service(
        (
            200,
            {
                "job_id": "job-1",
                "status": "succeeded",
                "redacted_text": "x",
                "entities": [],
            },
        )
    )
    monkeypatch.setattr(
        "euredact.cloud.client.CloudClient",
        lambda *a, **kw: CloudClient(client=service.client()),
    )
    result = euredact.EuRedact().redact(
        DOC, countries=["BE"], mode="cloud", idempotency_key="invoice-2291-v1"
    )
    assert service.requests[0].headers["Idempotency-Key"] == "invoice-2291-v1"
    assert result.cloud.job_id == "job-1"


def test_an_idempotency_key_without_cloud_mode_raises():
    with pytest.raises(ValueError, match="mode='cloud' only"):
        euredact.redact(DOC, countries=["BE"], idempotency_key="k")


# -- batches -------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES["batches"], ids=lambda c: c["id"])
def test_a_batch_carries_its_cost(case):
    batch = Batches._batch(case["wire"])
    assert {k: getattr(batch, k) for k in case["expect"]} == case["expect"]


def test_batches_list_asks_for_the_limit_and_types_each_batch(tmp_path):
    _configure()
    wire = CASES["batches"][0]["wire"]
    service = _Service((200, {"batches": [wire, "junk"]}))
    batches = Batches(batch_dir=tmp_path, client=service.client())
    listed = batches.list(limit=5)
    assert service.requests[0].url.path == "/v1/batches"
    assert service.requests[0].url.params["limit"] == "5"
    assert [b.id for b in listed] == ["b1"]
    assert listed[0].credits_charged == 765
    with pytest.raises(ValueError):
        batches.list(limit=101)


# -- account -------------------------------------------------------------------

ACCOUNT = CASES["account"]


def _account(*answers):
    _configure()
    service = _Service(*answers)
    return service, Account(client=service.client())


def test_account_summary():
    for name in ("summary", "summary_without_quota"):
        service, account = _account((200, ACCOUNT[name]["wire"]))
        assert _without_raw(account.summary()) == ACCOUNT[name]["expect"]
        assert service.requests[0].url.path == "/v1/account"


def test_account_credits():
    service, account = _account((200, ACCOUNT["credits"]["wire"]))
    assert _without_raw(account.credits()) == ACCOUNT["credits"]["expect"]
    assert service.requests[0].url.path == "/v1/account/credits"


def test_account_credit_history():
    service, account = _account((200, ACCOUNT["credit_history"]["wire"]))
    entries = account.credit_history(limit=10)
    assert [_without_raw(e) for e in entries] == ACCOUNT["credit_history"]["expect"]
    assert service.requests[0].url.path == "/v1/account/credits/history"
    assert service.requests[0].url.params["limit"] == "10"


def test_account_usage():
    service, account = _account((200, ACCOUNT["usage"]["wire"]))
    days = account.usage(days=2)
    assert [_without_raw(d) for d in days] == ACCOUNT["usage"]["expect"]
    assert service.requests[0].url.path == "/v1/account/usage"
    assert service.requests[0].url.params["days"] == "2"


def test_account_usage_by_key():
    service, account = _account((200, ACCOUNT["usage_by_key"]["wire"]))
    keys = account.usage_by_key(days=1)
    assert [_without_raw(k) for k in keys] == ACCOUNT["usage_by_key"]["expect"]
    assert service.requests[0].url.path == "/v1/account/usage/by-key"


def test_account_keys():
    service, account = _account((200, ACCOUNT["keys"]["wire"]))
    assert [_without_raw(k) for k in account.keys()] == ACCOUNT["keys"]["expect"]
    assert service.requests[0].url.path == "/v1/account/keys"


def test_revoking_a_key_is_one_post():
    service, account = _account((200, ACCOUNT["revoke_key"]["wire"]))
    assert _without_raw(account.revoke_key(3)) == ACCOUNT["revoke_key"]["expect"]
    assert service.requests[0].method == "POST"
    assert service.requests[0].url.path == "/v1/account/keys/3/revoke"


def test_a_revocation_is_never_retried():
    service, account = _account((503, {"error": "restarting"}))
    with pytest.raises(CloudError) as exc:
        account.revoke_key(3)
    assert exc.value.status == 503
    assert len(service.requests) == 1


def test_revoking_twice_or_a_foreign_key_raises():
    _, account = _account((409, {"ok": False, "error": "already revoked"}))
    with pytest.raises(CloudError) as exc:
        account.revoke_key(3)
    assert exc.value.status == 409
    _, account = _account((404, {"ok": False, "error": "no such key"}))
    with pytest.raises(NotFoundError):
        account.revoke_key(99)


def test_a_read_is_retried_through_a_transient_error():
    service, account = _account(
        (503, {"error": "restarting"}), (200, ACCOUNT["credits"]["wire"])
    )
    assert account.credits().balance == 94880
    assert len(service.requests) == 2


def test_an_origin_refusal_surfaces_as_a_403():
    _, account = _account((403, {"error": "origin not allowed"}))
    with pytest.raises(CloudError) as exc:
        account.summary()
    assert exc.value.status == 403


def test_account_arguments_are_bounded():
    _, account = _account((200, {}))
    with pytest.raises(ValueError):
        account.credit_history(limit=0)
    with pytest.raises(ValueError):
        account.usage(days=0)


# -- jobs ----------------------------------------------------------------------


def _jobs(*answers):
    _configure()
    service = _Service(*answers)
    return service, Jobs(client=service.client())


@pytest.mark.parametrize("name", ["job_pending", "job_succeeded"])
def test_a_job_is_retrieved_by_id(name):
    case = ACCOUNT[name]
    service, jobs = _jobs((200, case["wire"]))
    job = jobs.retrieve(case["wire"]["job_id"])
    assert {
        "job_id": job.job_id,
        "status": job.status,
        "created_at": job.created_at,
        "has_result": job.result is not None,
    } == case["expect"]
    assert service.requests[0].url.path == f"/v1/jobs/{case['wire']['job_id']}"


def test_a_retrieved_result_is_over_the_text_the_service_received():
    _, jobs = _jobs((200, ACCOUNT["job_succeeded"]["wire"]))
    result = jobs.retrieve("job-7f3a").result
    assert result.redacted_text == "Patiënt [PERSON_NAME]"
    assert result.detections[0].text == "Bas Verhoeven"
    assert result.cloud.job_id == "job-7f3a"


def test_an_expired_result_raises_rather_than_reading_as_empty():
    _, jobs = _jobs((410, {"error": "result payload is no longer retained"}))
    with pytest.raises(ResultExpiredError):
        jobs.retrieve("job-old")


def test_an_unknown_job_raises_not_found():
    _, jobs = _jobs((404, {"error": "job not found"}))
    with pytest.raises(NotFoundError):
        jobs.retrieve("job-nope")


def test_a_job_id_is_escaped_into_the_path():
    service, jobs = _jobs((200, ACCOUNT["job_pending"]["wire"]))
    jobs.retrieve("a/b")
    assert service.requests[0].url.raw_path == b"/v1/jobs/a%2Fb"
