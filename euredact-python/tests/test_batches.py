"""Batches keep the structured PII local (rules-engine#84).

A fake gateway stands in for euredact-inference's /v1/batches
(docs/BATCHES.md): it keeps what was uploaded, and answers with model spans
on the masked text, as the real one will. The tests hold the SDK to the
promise -- only masked text leaves, the mapping happens from the local batch
file, and nothing is ever mapped onto text it was not computed for.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

httpx = pytest.importorskip("httpx")

from euredact.cloud.batches import (  # noqa: E402
    MAX_DOCUMENTS,
    BatchError,
    Batches,
    FileBatchStore,
)
from euredact.cloud.config import CloudConfig  # noqa: E402
from euredact.types import EntityType  # noqa: E402

IBAN = "BE68 5390 0754 7034"
TEXT = f"Beste, gelieve {IBAN} te crediteren voor Jan Peeters. Groeten."
NAME = "Jan Peeters"


class FakeGateway:
    """Just enough of /v1/batches to drive the SDK end to end."""

    def __init__(self) -> None:
        self.uploaded: list[dict] = []
        self.raw_bodies: list[bytes] = []
        self.status = "in_progress"
        self.results_status = 200
        self.results_expire_at = "2099-01-01T00:00:00Z"
        self.override: dict[str, dict] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/batches":
            body = request.content
            if request.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            self.raw_bodies.append(body)
            self.uploaded = [json.loads(line) for line in body.splitlines() if line]
            return httpx.Response(201, json=self._batch("validating"))
        if request.method == "GET" and path == "/v1/batches/bat_1":
            return httpx.Response(200, json=self._batch(self.status))
        if request.method == "POST" and path == "/v1/batches/bat_1/cancel":
            self.status = "cancelling"
            return httpx.Response(200, json=self._batch("cancelling"))
        if request.method == "GET" and path == "/v1/batches/bat_1/results":
            if self.results_status != 200:
                return httpx.Response(self.results_status, json={"error": "no"})
            lines = [json.dumps({"custom_id": d["custom_id"],
                                 "result": self.override.get(d["custom_id"])
                                 or self._succeeded(d["text"])})
                     for d in self.uploaded]
            return httpx.Response(200, text="\n".join(lines) + "\n")
        return httpx.Response(404, json={"error": "not found"})

    def _batch(self, status: str) -> dict:
        return {"id": "bat_1", "status": status,
                "created_at": "2026-10-06T10:00:00Z", "expires_at": "2026-10-07T10:00:00Z",
                "results_expire_at": self.results_expire_at if status == "ended" else None,
                "counts": {"processing": 0}}

    @staticmethod
    def _succeeded(masked: str) -> dict:
        start = masked.find(NAME)
        entities = [] if start < 0 else [{
            "type": "PERSON_NAME", "start": start, "end": start + len(NAME),
            "text": NAME, "source": "model"}]
        return {"type": "succeeded",
                "masked_sha256": hashlib.sha256(masked.encode()).hexdigest(),
                "entities": entities}


@pytest.fixture
def gateway() -> FakeGateway:
    return FakeGateway()


@pytest.fixture
def batches(gateway: FakeGateway, tmp_path) -> Batches:
    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    return Batches(CloudConfig(api_key="erk_test", base_url="https://gw.test"),
                   batch_dir=tmp_path / "batches", client=client)


def _docs(n: int = 1) -> list[dict]:
    return [{"custom_id": f"doc-{i}", "text": TEXT, "countries": ["BE"]} for i in range(n)]


# ── create: only masked text leaves; the file is private ────────────────


def test_only_masked_text_is_uploaded(batches, gateway):
    batches.create(_docs())
    body = gateway.raw_bodies[0].decode()
    assert IBAN not in body and "[BANK_ACCOUNT]" in body
    assert gateway.uploaded[0]["countries"] == ["BE"]


def test_the_local_file_is_private_and_holds_what_mapping_needs(batches, tmp_path):
    batch = batches.create(_docs())
    path = tmp_path / "batches" / f"{batch.id}.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    state = json.loads(path.read_text())
    entry = state["entries"]["doc-0"]
    assert state["status"] == "pending" and entry["text"] == TEXT
    assert any(d["text"] == IBAN for d in entry["detections"])


def test_what_is_sent_is_what_cloud_mode_sends(batches, gateway):
    from euredact.sdk import EuRedact, _mask_for_cloud
    batches.create(_docs())
    local = EuRedact().redact(TEXT, countries=["BE"], detect_dates=True, cache=False)
    assert gateway.uploaded[0]["text"] == _mask_for_cloud(TEXT, local.detections)[0]


@pytest.mark.parametrize("docs,message", [
    ([{"custom_id": "a", "text": "x", "countries": ["BE"]}] * 2, "duplicate custom_id"),
    ([{"custom_id": "a" * 65, "text": "x", "countries": ["BE"]}], "custom_id must be 1-64 characters"),
    ([{"custom_id": "a", "text": "x", "countries": ["BE", "NL"]}], "exactly one country"),
    ([{"custom_id": "a", "text": "x"}], "exactly one country"),
    ([{"text": "x", "countries": ["BE"]}], "custom_id must be 1-64 characters"),
    ([], "at least one document"),
])
def test_limits_are_checked_before_anything_is_sent(batches, gateway, tmp_path, docs, message):
    with pytest.raises(BatchError, match=message):
        batches.create(docs)
    assert gateway.raw_bodies == [] and batches.store.list() == []


def test_more_than_the_document_limit_is_refused(batches, gateway):
    docs = [{"custom_id": f"d{i}", "text": "x", "countries": ["BE"]}
            for i in range(MAX_DOCUMENTS + 1)]
    with pytest.raises(BatchError, match="at most 5,000"):
        batches.create(docs)
    assert gateway.raw_bodies == []


# ── results: map from the file, once ───────────────────────────────────


def test_not_ended_changes_nothing(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    before = (tmp_path / "batches" / f"{batch.id}.json").read_bytes()
    assert batches.results(batch.id).status == "not_ended"
    assert (tmp_path / "batches" / f"{batch.id}.json").read_bytes() == before


def test_ended_batch_is_mapped_onto_the_originals(batches, gateway):
    batch = batches.create(_docs(2))
    gateway.status = "ended"
    outcome = batches.results(batch.id)
    assert outcome.status == "resolved" and set(outcome.documents) == {"doc-0", "doc-1"}
    result = outcome.documents["doc-0"].result
    assert result.redacted_text == (
        "Beste, gelieve [BANK_ACCOUNT] te crediteren voor [PERSON_NAME]. Groeten.")
    assert {d.text for d in result.detections} == {IBAN, NAME}
    assert result.source == "cloud"


def test_resolved_once_then_a_text_free_receipt(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    gateway.status = "ended"
    batches.results(batch.id)
    raw = (tmp_path / "batches" / f"{batch.id}.json").read_text()
    state = json.loads(raw)
    assert state["status"] == "resolved" and state["entries"] == {}
    assert TEXT not in raw and IBAN not in raw and NAME not in raw
    assert state["counts"]["mapped"] == 1
    again = batches.results(batch.id)
    assert again.status == "already_resolved" and again.documents == {}
    assert batch.id not in batches.pending()


def test_a_changed_local_file_is_an_error_not_a_wrong_mapping(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    path = tmp_path / "batches" / f"{batch.id}.json"
    state = json.loads(path.read_text())
    state["entries"]["doc-0"]["text"] = TEXT.replace("Beste", "Geachte")
    path.write_text(json.dumps(state))
    gateway.status = "ended"
    outcome = batches.results(batch.id).documents["doc-0"]
    assert not outcome.ok and outcome.error == "local_mismatch" and outcome.result is None


def test_a_hash_the_gateway_disagrees_with_is_an_error(batches, gateway):
    batch = batches.create(_docs())
    gateway.override["doc-0"] = {"type": "succeeded", "masked_sha256": "0" * 64, "entities": []}
    gateway.status = "ended"
    assert batches.results(batch.id).documents["doc-0"].error == "local_mismatch"


def test_no_local_file_is_an_error_per_document(batches, gateway):
    batches.create(_docs())
    batches.purge("bat_1")
    gateway.status = "ended"
    outcome = batches.results("bat_1")
    assert outcome.documents["doc-0"].error == "missing_local_entry"
    assert outcome.documents["doc-0"].result is None


def test_a_gateway_error_passes_through(batches, gateway):
    batch = batches.create(_docs())
    gateway.override["doc-0"] = {"type": "errored",
                                 "error": {"code": "too_long", "message": "6,212 tokens"}}
    gateway.status = "ended"
    outcome = batches.results(batch.id).documents["doc-0"]
    assert outcome.error == "too_long" and "6,212" in outcome.message
    # The SDK says why it did not catch this before upload.
    assert "counted by the model's tokenizer" in outcome.message
    assert "cannot check it before upload" in outcome.message


def test_results_gone_from_the_gateway_expire_the_file(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    gateway.status, gateway.results_status = "ended", 410
    assert batches.results(batch.id).status == "expired"
    state = json.loads((tmp_path / "batches" / f"{batch.id}.json").read_text())
    assert state["status"] == "expired" and state["entries"] == {}


# ── lifecycle: pending, cancel, sweep, purge ───────────────────────────


def test_pending_lists_unresolved_files_for_a_restarted_worker(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    restarted = Batches(batches.config, batch_dir=tmp_path / "batches",
                        client=httpx.Client(transport=httpx.MockTransport(gateway.handler)))
    assert restarted.pending() == [batch.id]


def test_cancel_keeps_the_file_pending(batches, gateway):
    batch = batches.create(_docs())
    assert batches.cancel(batch.id).status == "cancelling"
    assert batches.pending() == [batch.id]


def test_sweep_expires_pending_and_deletes_receipts(batches, gateway, tmp_path):
    batch = batches.create(_docs())
    gateway.status = "ended"
    batches.retrieve(batch.id)  # learns results_expire_at
    later = datetime(2099, 1, 2, tzinfo=timezone.utc)
    batches.sweep(now=later)
    state = json.loads((tmp_path / "batches" / f"{batch.id}.json").read_text())
    assert state["status"] == "expired" and state["entries"] == {}
    batches.sweep(now=later + timedelta(days=1))
    assert batches.store.list() == []


def test_purge_deletes_the_file(batches, gateway):
    batch = batches.create(_docs())
    batches.purge(batch.id)
    assert batches.store.list() == []


# ── where and how the file is kept ─────────────────────────────────────


class XorCipher:
    """Stand-in for a real cipher: proves the hook is applied both ways."""

    def encrypt(self, data: bytes) -> bytes:
        return bytes(b ^ 0x5A for b in data)

    def decrypt(self, data: bytes) -> bytes:
        return bytes(b ^ 0x5A for b in data)


def test_a_cipher_encrypts_the_file_at_rest(gateway, tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    b = Batches(CloudConfig(api_key="k", base_url="https://gw.test"),
                batch_dir=tmp_path, client=client, cipher=XorCipher())
    batch = b.create(_docs())
    raw = (tmp_path / f"{batch.id}.json").read_bytes()
    assert IBAN.encode() not in raw and TEXT.encode() not in raw
    gateway.status = "ended"
    assert b.results(batch.id).documents["doc-0"].ok


class MemoryStore:
    """A store with no filesystem, as a browser or a shared KV would be."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def read(self, batch_id):
        return self.blobs.get(batch_id)

    def write(self, batch_id, data):
        self.blobs[batch_id] = data

    def delete(self, batch_id):
        self.blobs.pop(batch_id, None)

    def list(self):
        return sorted(self.blobs)


def test_a_caller_supplied_store_replaces_the_directory(gateway):
    store = MemoryStore()
    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    b = Batches(CloudConfig(api_key="k", base_url="https://gw.test"), store=store, client=client)
    b.create(_docs())
    assert store.list() == ["bat_1"]
    gateway.status = "ended"
    assert b.results("bat_1").documents["doc-0"].ok


def test_batch_ids_cannot_escape_the_directory(tmp_path):
    store = FileBatchStore(tmp_path)
    for bad in ("../x", "a/b", "..", ""):
        with pytest.raises(BatchError):
            store.write(bad, b"{}")


# ── shared conformance vectors (both SDKs run conformance/batches.json) ──

from pathlib import Path  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "conformance" / "batches.json").read_text("utf-8"))


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["id"] for c in VECTORS["cases"]])
def test_batch_vector_round_trip(case, gateway, tmp_path):
    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    b = Batches(CloudConfig(api_key="k", base_url="https://gw.test"),
                batch_dir=tmp_path, client=client)
    b.create([{"custom_id": case["id"], "text": case["text"], "countries": case["countries"]}])
    assert gateway.uploaded[0]["text"] == case["masked"]
    state = json.loads((tmp_path / "bat_1.json").read_text())
    assert state["entries"][case["id"]]["masked_sha256"] == case["masked_sha256"]
    gateway.override[case["id"]] = {"type": "succeeded", "masked_sha256": case["masked_sha256"],
                                    "entities": case["entities"]}
    gateway.status = "ended"
    outcome = b.results("bat_1").documents[case["id"]]
    assert outcome.ok, outcome.message
    assert outcome.result.redacted_text == case["redacted_text"]


def test_batch_vector_tampered_original(gateway, tmp_path):
    spec = VECTORS["mismatch"]
    case = next(c for c in VECTORS["cases"] if c["id"] == spec["base"])
    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    b = Batches(CloudConfig(api_key="k", base_url="https://gw.test"),
                batch_dir=tmp_path, client=client)
    b.create([{"custom_id": case["id"], "text": case["text"], "countries": case["countries"]}])
    path = tmp_path / "bat_1.json"
    state = json.loads(path.read_text())
    state["entries"][case["id"]]["text"] = spec["original_override"]
    path.write_text(json.dumps(state))
    gateway.override[case["id"]] = {"type": "succeeded", "masked_sha256": case["masked_sha256"],
                                    "entities": case["entities"]}
    gateway.status = "ended"
    assert b.results("bat_1").documents[case["id"]].error == spec["expect_error"]


# ── custom_id characters, checked before any masking (rules-engine#88) ──


@pytest.mark.parametrize("custom_id", VECTORS["custom_ids"]["invalid"])
def test_an_invalid_custom_id_is_refused_with_the_gateways_wording(custom_id, batches, gateway):
    with pytest.raises(BatchError, match=r"document 1: custom_id must be 1-64 characters "
                                         r"of A-Z a-z 0-9 _ \. : -"):
        batches.create([{"custom_id": custom_id, "text": TEXT, "countries": ["BE"]}])
    assert gateway.raw_bodies == []


@pytest.mark.parametrize("custom_id", VECTORS["custom_ids"]["valid"])
def test_a_valid_custom_id_is_accepted(custom_id, batches, gateway):
    batches.create([{"custom_id": custom_id, "text": TEXT, "countries": ["BE"]}])
    assert gateway.uploaded[0]["custom_id"] == custom_id


def test_nothing_is_masked_before_a_late_document_is_refused(gateway, tmp_path):
    """The bad custom_id is the last of many: no document may be masked first."""

    class CountingEngine:
        calls = 0

        def redact(self, *args, **kwargs):
            CountingEngine.calls += 1
            raise AssertionError("masked a document before validating the batch")

    client = httpx.Client(transport=httpx.MockTransport(gateway.handler))
    b = Batches(CloudConfig(api_key="k", base_url="https://gw.test"),
                batch_dir=tmp_path, client=client, sdk=CountingEngine())
    docs = _docs(50) + [{"custom_id": "invoice 2291", "text": TEXT, "countries": ["BE"]}]
    with pytest.raises(BatchError, match="document 51: custom_id must be"):
        b.create(docs)
    assert CountingEngine.calls == 0 and gateway.raw_bodies == []


def test_a_document_carries_the_model_and_what_it_could_not_place(batches, gateway, monkeypatch):
    """A batch line has no job id or usage of its own, but it does say which
    model answered and what could not be placed (rules-engine#89)."""
    plain = FakeGateway._succeeded

    def with_cloud_fields(masked: str) -> dict:
        return {**plain(masked), "model_version": "euredact-9b@2026-08-31",
                "unlocated": [{"text": "Dr. Peeters", "type": "PERSON_NAME"}]}

    monkeypatch.setattr(FakeGateway, "_succeeded", staticmethod(with_cloud_fields))
    batch = batches.create(_docs())
    gateway.status = "ended"
    cloud = batches.results(batch.id).documents["doc-0"].result.cloud
    assert cloud.model_version == "euredact-9b@2026-08-31"
    assert [(u.text, u.entity_type) for u in cloud.unlocated] == [
        ("Dr. Peeters", EntityType.PERSON_NAME)]
    assert cloud.job_id is None and cloud.usage is None
