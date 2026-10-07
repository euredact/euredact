"""[CLOUD EXTENSION] The cloud client.

Speaks to the euRedact inference service: a fine-tuned model asked only *what
did the rules miss?* The service returns located spans, so this module's job is
transport and translation, not detection.

It sends the text it is given, as given. ``euredact.redact(mode="cloud")`` is
what runs the rules engine first and hands this client only the masked text;
call the client directly and whatever you pass is what leaves the machine. The
spans that come back index the text that was sent.

Three things it hides from the caller:

* **Whether the document finished inside the service's sync window.** A short
  document comes back on the original request; a long one, or one that arrives
  while a GPU node is cold, returns a job handle and is polled. Callers should
  never have to write that branch, so :meth:`CloudClient.redact` blocks either
  way and the difference is invisible.
* **Retries.** Every request carries an ``Idempotency-Key``, so a retry after a
  timeout cannot produce a second job or a second usage row. Without that a
  network blip on a slow document would double-bill it.
* **``Retry-After``.** When the service says how long to wait, that is obeyed
  rather than second-guessed with a backoff curve.
"""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass
from typing import Any

from euredact.cloud.config import CloudConfig, get_config
from euredact.types import (
    Detection,
    DetectionSource,
    EntityType,
    RedactResult,
    Usage,
    UsageFactor,
)

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_BACKOFF_S = 30.0


class CloudError(Exception):
    """The cloud tier could not answer."""

    def __init__(self, message: str, *, status: int | None = None,
                 detail: dict | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.detail = detail or {}


class NotConfiguredError(CloudError):
    """Raised when the cloud tier is used without configuration.

    This is deliberately an error rather than a quiet fallback to rules-only
    output. ``mode="cloud"`` that silently returns rules-only results is the
    worst failure this library can have: the caller believes names, employers
    and diagnoses were checked, sees a plausible redacted document, and ships it
    with the PII still in it.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or (
            "Cloud tier not configured. Call euredact.configure(api_key=...) "
            "first, or set EUREDACT_API_KEY."))


class QuotaExceededError(CloudError):
    """429 after retries were exhausted."""


class TooLargeError(CloudError):
    """413. The document is over the service's input cap.

    Permanent and not retryable. The model has never seen a chunk boundary, so
    the service refuses oversized input rather than splitting it and changing
    the accuracy story silently.
    """


def _require_httpx():
    try:
        import httpx
    except ImportError as exc:                             # pragma: no cover
        raise NotConfiguredError(
            "the cloud tier needs httpx. Install with: pip install 'euredact[cloud]'"
        ) from exc
    return httpx


@dataclass
class _Attempt:
    """Bookkeeping for one retry loop, shared by the sync and async clients."""

    max_retries: int
    attempt: int = 0

    def should_retry(self, status: int | None) -> bool:
        return self.attempt < self.max_retries and (
            status is None or status in _RETRY_STATUS)

    def backoff(self, retry_after: float | None) -> float:
        if retry_after is not None:
            # The service knows when it will be ready. Believe it.
            return min(retry_after, _MAX_BACKOFF_S)
        # Full jitter: a synchronised retry storm from many clients is how a
        # recovering service is knocked back over.
        return min(_MAX_BACKOFF_S, random.uniform(0, 2 ** self.attempt))


def _retry_after_seconds(headers: Any) -> float | None:
    raw = headers.get("Retry-After") if headers else None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None                      # HTTP-date form: fall back to backoff


def _entity_type(raw: str) -> EntityType | str:
    """Canon name -> EntityType, tolerating one this build has not heard of.

    An unknown type is passed through as a plain string rather than dropped.
    `Detection.entity_type` is typed `EntityType | str` precisely so a client
    that is one release behind the service does not silently lose a whole
    category of PII.
    """
    try:
        return EntityType(raw)
    except ValueError:
        return raw


def _integer(value: object) -> int | None:
    """A JSON integer, or None. ``True`` is not one, nor is ``1.5``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if float(value).is_integer() else None


def _usage(raw: object) -> Usage | None:
    """The ``usage`` block, or None when absent or malformed.

    Shared rules with the TypeScript SDK (``conformance/cloud_usage.json``):
    ``tokens`` and ``credits`` are integers, ``billing_rate`` a number,
    ``factors`` a list whose entries carry a string ``code``. Anything else in
    those four places drops the whole block rather than reporting a cost
    nobody can trust; keys the SDK does not know are ignored.
    """
    if not isinstance(raw, dict):
        return None
    tokens, credits = _integer(raw.get("tokens")), _integer(raw.get("credits"))
    rate = raw.get("billing_rate")
    factors_raw = raw.get("factors")
    if (tokens is None or credits is None or isinstance(rate, bool)
            or not isinstance(rate, (int, float)) or not isinstance(factors_raw, list)):
        return None
    factors = []
    for f in factors_raw:
        if not isinstance(f, dict) or not isinstance(f.get("code"), str):
            return None
        detail = f.get("detail")
        types = f.get("types")
        factors.append(UsageFactor(
            code=f["code"],
            detail=detail if isinstance(detail, str) else "",
            types=(tuple(x for x in types if isinstance(x, str))
                   if isinstance(types, list) else None),
        ))
    return Usage(tokens=tokens, billing_rate=float(rate), credits=credits,
                 factors=tuple(factors))


def _to_result(payload: dict, *, text: str) -> RedactResult:
    """Translate the wire response into the library's own types."""
    detections: list[Detection] = []
    for span in payload.get("entities", []):
        source = (DetectionSource.CLOUD if span.get("source") == "model"
                  else DetectionSource.RULES)
        detections.append(Detection(
            entity_type=_entity_type(span.get("type", "OTHER")),
            start=int(span["start"]),
            end=int(span["end"]),
            text=span.get("text", ""),
            source=source,
            country=None,
            confidence=span.get("confidence") or "high",
        ))
    detections.sort(key=lambda d: (d.start, -d.end))
    return RedactResult(
        redacted_text=payload.get("redacted_text", text),
        detections=detections,
        source="cloud",
        usage=_usage(payload.get("usage")),
    )


class _BaseClient:
    def __init__(self, config: CloudConfig | None = None) -> None:
        cfg = config or get_config()
        if cfg is None:
            raise NotConfiguredError()
        self.config = cfg

    def _headers(self, idempotency_key: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            # A retry after a timeout must not create a second job or a second
            # usage row. The key is per logical document, not per attempt.
            "Idempotency-Key": idempotency_key,
            **self.config.headers,
        }

    def _body(self, text: str, country: str, language: str, priority: str) -> dict:
        return {"text": text, "country": country, "language": language,
                "priority": priority}

    def _raise_for(self, status: int, payload: dict) -> None:
        error = payload.get("error", f"HTTP {status}")
        detail = payload.get("detail") or {}
        if status == 401:
            raise CloudError(f"authentication failed: {error}", status=status)
        if status == 413:
            raise TooLargeError(error, status=status, detail=detail)
        if status == 429:
            raise QuotaExceededError(error, status=status, detail=detail)
        raise CloudError(error, status=status, detail=detail)


class CloudClient(_BaseClient):
    """Synchronous client."""

    def __init__(self, config: CloudConfig | None = None, *, client=None) -> None:
        super().__init__(config)
        self._httpx = _require_httpx()
        self._client = client
        self._owned = client is None

    def _http(self):
        if self._client is None:
            self._client = self._httpx.Client(timeout=self.config.timeout_s)
        return self._client

    def close(self) -> None:
        if self._owned and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "CloudClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def redact(self, text: str, *, country: str, language: str = "",
               priority: str = "interactive",
               idempotency_key: str | None = None) -> RedactResult:
        key = idempotency_key or str(uuid.uuid4())
        payload = self._submit(text, country, language, priority, key)
        if payload.get("_accepted"):
            payload = self._poll(payload["location"], key)
        return _to_result(payload, text=text)

    def _submit(self, text, country, language, priority, key) -> dict:
        attempt = _Attempt(self.config.max_retries)
        url = f"{self.config.base_url}/v1/redact"
        body = self._body(text, country, language, priority)
        while True:
            status, data, headers = None, {}, None
            try:
                resp = self._http().post(url, json=body, headers=self._headers(key))
                status, headers = resp.status_code, resp.headers
                data = _json_or_empty(resp)
            except self._httpx.TimeoutException as exc:
                if not attempt.should_retry(None):
                    raise CloudError(f"cloud request timed out: {exc}") from exc
            except self._httpx.HTTPError as exc:
                if not attempt.should_retry(None):
                    raise CloudError(f"cloud request failed: {exc}") from exc
            else:
                if status == 202:
                    # Outlived the sync window. Location is where the answer
                    # will appear; polling it is this client's job, not the
                    # caller's.
                    location = (headers.get("Location")
                                or data.get("location")
                                or f"/v1/jobs/{data.get('job_id', '')}")
                    return {"_accepted": True, "location": location}
                if status == 200:
                    return data
                if status not in _RETRY_STATUS or not attempt.should_retry(status):
                    self._raise_for(status, data)

            attempt.attempt += 1
            time.sleep(attempt.backoff(_retry_after_seconds(headers)))

    def _poll(self, location: str, key: str) -> dict:
        url = (location if location.startswith("http")
               else f"{self.config.base_url}{location}")
        deadline = time.monotonic() + self.config.poll_timeout_s
        delay = 0.5
        while True:
            resp = self._http().get(url, headers=self._headers(key))
            data = _json_or_empty(resp)
            if resp.status_code == 200 and "redacted_text" in data:
                return data
            if resp.status_code == 200:
                pass                                  # still queued or running
            elif resp.status_code in _RETRY_STATUS:
                pass                                  # transient; keep polling
            else:
                self._raise_for(resp.status_code, data)

            if time.monotonic() >= deadline:
                raise CloudError(
                    f"document did not complete within "
                    f"{self.config.poll_timeout_s:.0f}s ({url})")
            retry_after = _retry_after_seconds(resp.headers)
            time.sleep(retry_after if retry_after is not None else delay)
            delay = min(delay * 1.5, 5.0)


class AsyncCloudClient(_BaseClient):
    """Async twin. Same contract, same retry and polling semantics."""

    def __init__(self, config: CloudConfig | None = None, *, client=None) -> None:
        super().__init__(config)
        self._httpx = _require_httpx()
        self._client = client
        self._owned = client is None

    def _http(self):
        if self._client is None:
            self._client = self._httpx.AsyncClient(timeout=self.config.timeout_s)
        return self._client

    async def aclose(self) -> None:
        if self._owned and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "AsyncCloudClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def redact(self, text: str, *, country: str, language: str = "",
                     priority: str = "interactive",
                     idempotency_key: str | None = None) -> RedactResult:
        import asyncio

        key = idempotency_key or str(uuid.uuid4())
        attempt = _Attempt(self.config.max_retries)
        url = f"{self.config.base_url}/v1/redact"
        body = self._body(text, country, language, priority)

        payload: dict | None = None
        while payload is None:
            status, data, headers = None, {}, None
            try:
                resp = await self._http().post(url, json=body,
                                               headers=self._headers(key))
                status, headers = resp.status_code, resp.headers
                data = _json_or_empty(resp)
            except self._httpx.TimeoutException as exc:
                if not attempt.should_retry(None):
                    raise CloudError(f"cloud request timed out: {exc}") from exc
            except self._httpx.HTTPError as exc:
                if not attempt.should_retry(None):
                    raise CloudError(f"cloud request failed: {exc}") from exc
            else:
                if status == 202:
                    location = (headers.get("Location") or data.get("location")
                                or f"/v1/jobs/{data.get('job_id', '')}")
                    payload = await self._poll(location, key)
                    break
                if status == 200:
                    payload = data
                    break
                if status not in _RETRY_STATUS or not attempt.should_retry(status):
                    self._raise_for(status, data)

            attempt.attempt += 1
            await asyncio.sleep(attempt.backoff(_retry_after_seconds(headers)))

        return _to_result(payload, text=text)

    async def _poll(self, location: str, key: str) -> dict:
        import asyncio

        url = (location if location.startswith("http")
               else f"{self.config.base_url}{location}")
        loop_deadline = time.monotonic() + self.config.poll_timeout_s
        delay = 0.5
        while True:
            resp = await self._http().get(url, headers=self._headers(key))
            data = _json_or_empty(resp)
            if resp.status_code == 200 and "redacted_text" in data:
                return data
            if resp.status_code not in (200, *_RETRY_STATUS):
                self._raise_for(resp.status_code, data)
            if time.monotonic() >= loop_deadline:
                raise CloudError(
                    f"document did not complete within "
                    f"{self.config.poll_timeout_s:.0f}s ({url})")
            retry_after = _retry_after_seconds(resp.headers)
            await asyncio.sleep(retry_after if retry_after is not None else delay)
            delay = min(delay * 1.5, 5.0)


def _json_or_empty(resp) -> dict:
    try:
        data = resp.json()
    except Exception:                                       # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}
