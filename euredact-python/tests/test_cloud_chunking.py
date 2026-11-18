"""Cloud mode for documents over the input cap (rules-engine#183).

Through the real client and a scripted service that refuses anything over its
cap with 413, finds the names it is told to in whatever text it receives, and
reports usage. The service never sees the original, so nothing here can lean
on it.
"""

from __future__ import annotations

import json

import pytest

import euredact
from euredact import Chunking, EntityType
from euredact.cloud import CloudError, TooLargeError
from euredact.cloud import config as cloud_config
from euredact.cloud.chunking import plan
from euredact.types import DetectionSource

httpx = pytest.importorskip("httpx")

IBAN = "NL91 ABNA 0417 1643 00"
NAME = "Anneke Verbruggen"


def _document(paragraphs: int = 60) -> str:
    """A long Dutch letter: a name and an IBAN in every fourth paragraph."""
    out = []
    for i in range(paragraphs):
        body = ("De patiënt kwam op controle en vertelde over de klachten van "
                "de afgelopen weken. Er werd een vervolgafspraak gemaakt. ") * 4
        if i % 4 == 0:
            body += f"Contact: {NAME}, rekening {IBAN}. "
        out.append(f"Paragraaf {i}. {body}")
    return "\n\n".join(out)


class _Service:
    def __init__(self, *, cap: int = 13_000, find: tuple[str, ...] = (NAME,),
                 fail_on: int | None = None, find_only_first: bool = False):
        self.cap, self.find, self.fail_on = cap, find, fail_on
        self.find_only_first = find_only_first
        self.sent: list[dict] = []
        self.keys: list[str] = []

    def handler(self, request):
        body = json.loads(request.content)
        self.sent.append(body)
        self.keys.append(request.headers["Idempotency-Key"])
        text = body["text"]
        if len(text) > self.cap:
            return httpx.Response(413, json={"error": "input too large"})
        if self.fail_on is not None and len(self.sent) == self.fail_on:
            return httpx.Response(400, json={"error": "bad request"})
        entities = []
        if not (self.find_only_first and len(self.sent) > 1):
            for needle in self.find:
                at = text.find(needle)
                while at >= 0:
                    entities.append({"start": at, "end": at + len(needle), "text": needle,
                                     "type": "PERSON_NAME", "source": "model",
                                     "score": 0.97, "confidence": "high"})
                    at = text.find(needle, at + 1)
        tokens = len(text) // 4
        return httpx.Response(200, json={
            "job_id": f"job-{len(self.sent)}", "status": "succeeded",
            "redacted_text": text, "entities": entities, "unlocated": [],
            "model_version": "euredact-4b@test",
            "usage": {"tokens": tokens, "billing_rate": 1.0, "credits": tokens, "factors": []},
        })

    @property
    def tokens(self) -> int:
        return sum(len(b["text"]) // 4 for b in self.sent if len(b["text"]) <= self.cap)


@pytest.fixture
def service(monkeypatch):
    cloud_config.configure(api_key="erk_test", base_url="https://api.test")
    holder = {"s": _Service()}
    from euredact.cloud.client import CloudClient

    def factory(*a, **kw):
        return CloudClient(client=httpx.Client(
            transport=httpx.MockTransport(lambda r: holder["s"].handler(r))))
    monkeypatch.setattr("euredact.cloud.client.CloudClient", factory)
    monkeypatch.setattr("euredact.cloud.client.time.sleep", lambda s: None)
    yield holder
    cloud_config.reset()


def _redact(text, **kw):
    return euredact.EuRedact().redact(text, countries=["NL"], mode="cloud", **kw)


def test_a_long_document_is_split_sent_and_merged_into_one_result(service):
    text = _document()
    assert len(text) > 20_000
    result = _redact(text)
    svc = service["s"]
    assert len(svc.sent) > 1
    # Every detection points at the characters it names in the original.
    for d in result.detections:
        assert text[d.start:d.end] == d.text
    names = [d for d in result.detections if d.entity_type == EntityType.PERSON_NAME]
    assert len(names) == text.count(NAME)
    assert NAME not in result.redacted_text and IBAN not in result.redacted_text
    # No span twice, though parts overlap.
    spans = [(d.start, d.end, d.entity_type) for d in result.detections]
    assert len(spans) == len(set(spans))
    # The parts: in order, covering the document, billed in sum.
    chunks = result.cloud.chunks
    assert len(chunks) == len(svc.sent) and chunks[0].start == 0 and chunks[-1].end == len(text)
    assert all(c.total == len(chunks) and c.job_id for c in chunks)
    assert result.cloud.usage.tokens == svc.tokens == sum(c.tokens for c in chunks)
    assert result.cloud.job_id is None


def test_only_masked_text_is_sent_and_no_placeholder_is_cut(service):
    _redact(_document())
    for body in service["s"].sent:
        part = body["text"]
        assert IBAN not in part
        assert part.count("[") == part.count("]")


def test_a_short_document_is_one_request_under_the_callers_key(service):
    result = _redact(f"Mail {NAME} over de afspraak.", idempotency_key="doc-7")
    assert service["s"].keys == ["doc-7"]
    assert result.cloud.chunks == () and result.cloud.job_id == "job-1"


def test_chunking_off_is_todays_behaviour(service):
    with pytest.raises(TooLargeError):
        _redact(_document(), chunking="off")
    assert len(service["s"].sent) == 1


def test_a_retried_document_reuses_every_part_key(service):
    text = _document()
    _redact(text, idempotency_key="letter-1")
    first = list(service["s"].keys)
    service["s"] = _Service()
    _redact(text, idempotency_key="letter-1")
    assert service["s"].keys == first and len(set(first)) == len(first)
    assert all(k.startswith("letter-1:") for k in first)


def test_a_failed_part_fails_the_document(service):
    service["s"] = _Service(fail_on=2)
    with pytest.raises(CloudError) as exc:
        _redact(_document())
    assert exc.value.chunks_completed == 1
    assert "1 completed and billed" in str(exc.value)


def test_a_part_the_service_still_refuses_is_halved(service):
    # The service's cap is below the part size: each part draws a 413 once.
    service["s"] = _Service(cap=5_000)
    text = _document()
    result = _redact(text, chunking=Chunking(max_chars=8_000))
    assert all(len(b["text"]) <= 8_000 for b in service["s"].sent)
    names = [d for d in result.detections if d.entity_type == EntityType.PERSON_NAME]
    assert len(names) == text.count(NAME)


def test_max_chunks_refuses_before_anything_is_sent(service):
    with pytest.raises(ValueError, match="max_chunks"):
        _redact(_document(), chunking=Chunking(max_chunks=1))
    assert service["s"].sent == []


def test_a_value_found_in_one_part_is_masked_in_the_others(service):
    service["s"] = _Service(find_only_first=True)
    text = _document()
    result = _redact(text)
    assert NAME not in result.redacted_text
    service["s"] = _Service(find_only_first=True)
    kept = _redact(text, chunking=Chunking(propagate=False))
    assert NAME in kept.redacted_text


def test_parts_sent_in_parallel_give_the_same_result(service):
    text = _document()
    one = _redact(text)
    service["s"] = _Service()
    many = _redact(text, chunking=Chunking(concurrency=3))
    assert [(d.start, d.end) for d in many.detections] == [(d.start, d.end) for d in one.detections]


def test_a_custom_splitter_and_progress(service):
    text = "\f".join(_document(10) for _ in range(3))
    seen = []
    result = _redact(text, chunking=Chunking(
        splitter=lambda t: [i for i, c in enumerate(t) if c == "\f"], on_chunk=seen.append))
    assert [c.index for c in seen] == list(range(len(result.cloud.chunks)))
    assert all(c.total == len(result.cloud.chunks) for c in seen)


def test_the_splitter_cuts_where_it_says(service):
    # Three sections that would go as one request: the splitter makes them three.
    text = "\f".join(_document(2) for _ in range(3))
    assert len(text) < 12_000
    result = _redact(text, chunking=Chunking(
        splitter=lambda t: [i for i, c in enumerate(t) if c == "\f"], overlap_chars=0))
    assert len(service["s"].sent) == 3
    first, *rest = text.split("\f")
    assert [text[c.start:c.end] for c in result.cloud.chunks] == [first, *("\f" + r for r in rest)]


def test_chunking_is_cloud_only():
    with pytest.raises(ValueError, match="cloud"):
        euredact.EuRedact().redact("x", chunking="off")


def test_the_plan_never_cuts_a_placeholder_and_stays_under_the_limit():
    text = ("woord " * 30 + "[BANK_ACCOUNT] ") * 20
    protected = []
    at = text.find("[BANK_ACCOUNT]")
    while at >= 0:
        protected.append((at, at + 14))
        at = text.find("[BANK_ACCOUNT]", at + 1)
    parts = plan(text, protected, 200, 20)
    assert parts[0][0] == 0 and parts[-1][1] == len(text)
    for start, end in parts:
        assert end - start <= 200
        assert not any(s < start < e or s < end < e for s, e in protected)
    assert all(b[0] < a[1] for a, b in zip(parts, parts[1:]))        # they overlap


def test_cloud_sources_are_kept(service):
    result = _redact(_document())
    assert {d.source for d in result.detections} == {DetectionSource.RULES, DetectionSource.CLOUD}


_CASES = json.loads(
    (__import__("pathlib").Path(__file__).resolve().parents[2]
     / "conformance" / "cloud_chunking.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", _CASES, ids=lambda c: c["id"])
def test_both_sdks_cut_at_the_same_places(case):
    """``conformance/cloud_chunking.json``, run by the TypeScript SDK too."""
    parts = plan(case["text"], [tuple(p) for p in case["protected"]],
                 case["max_chars"], case["overlap"])
    assert [list(p) for p in parts] == case["expect"]
