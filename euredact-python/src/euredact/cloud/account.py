"""[CLOUD EXTENSION] The account and job endpoints an API key may call.

Everything a customer's key can do on the service is reachable from the SDK
(rules-engine#89): redaction (:class:`~euredact.cloud.CloudClient`), batches
(:class:`~euredact.cloud.Batches`), a past job (:class:`Jobs`) and the account
itself (:class:`Account`). What needs a signed-in person -- logging in, minting
keys, changing settings, members, accepting terms -- is not here, because a key
cannot do it.

    from euredact.cloud import Account, Jobs
    with Account() as account:
        print(account.summary().quota_remaining)
        for key in account.keys():
            print(key.id, key.name, key.active)

Every typed value carries ``raw``, the service's JSON, so a field the SDK does
not know yet is still reachable.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from euredact.cloud.client import (
    _RETRY_STATUS,
    CloudError,
    _Attempt,
    _BaseClient,
    _integer,
    _is_quota,
    _json_or_empty,
    _require_httpx,
    _retry_after_seconds,
    _string,
    _to_result,
)
from euredact.cloud.config import CloudConfig
from euredact.types import RedactResult


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


# ── Values ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AccountSummary:
    """``GET /v1/account``: plan limits, retention and usage against quota."""

    tenant_id: str | None
    tenant_name: str | None
    active: bool | None
    member_since: str | None
    role: str | None
    retention_mode: str | None
    """``"ttl"``, or ``"none"`` when text is discarded on delivery."""
    payload_ttl_hours: int | None
    documents_today: int | None
    documents_this_month: int | None
    tokens_this_month: int | None
    failures_24h: int | None
    daily_quota: int | None
    """``None`` for an account without a daily quota."""
    quota_remaining: int | None
    active_keys: int | None
    batches_available: bool | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> AccountSummary:
        tenant, retention = _dict(raw.get("tenant")), _dict(raw.get("retention"))
        usage = _dict(raw.get("usage"))
        return cls(
            tenant_id=_string(tenant.get("id")),
            tenant_name=_string(tenant.get("name")),
            active=_boolean(tenant.get("active")),
            member_since=_string(tenant.get("member_since")),
            role=_string(raw.get("role")),
            retention_mode=_string(retention.get("mode")),
            payload_ttl_hours=_integer(retention.get("payload_ttl_hours")),
            documents_today=_integer(usage.get("documents_today")),
            documents_this_month=_integer(usage.get("documents_this_month")),
            tokens_this_month=_integer(usage.get("tokens_this_month")),
            failures_24h=_integer(usage.get("failures_24h")),
            daily_quota=_integer(usage.get("daily_quota")),
            quota_remaining=_integer(usage.get("quota_remaining")),
            active_keys=_integer(_dict(raw.get("keys")).get("active")),
            batches_available=_boolean(_dict(raw.get("batches")).get("available")),
            raw=raw,
        )


@dataclass(frozen=True)
class Credits:
    """``GET /v1/account/credits``: the balance, in credits."""

    balance: int | None
    granted: int | None
    spent: int | None
    unit: str | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> Credits:
        return cls(
            balance=_integer(raw.get("balance")),
            granted=_integer(raw.get("granted")),
            spent=_integer(raw.get("spent")),
            unit=_string(raw.get("unit")),
            raw=raw,
        )


@dataclass(frozen=True)
class CreditEntry:
    """One line of ``GET /v1/account/credits/history``: movements rolled up per
    minute, reason and direction, newest first."""

    at: str | None
    delta: int | None
    """Negative for a debit."""
    reason: str | None
    count: int | None
    job_id: str | None
    source_ref: str | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> CreditEntry:
        return cls(
            at=_string(raw.get("at")),
            delta=_integer(raw.get("delta")),
            reason=_string(raw.get("reason")),
            count=_integer(raw.get("count")),
            job_id=_string(raw.get("job_id")),
            source_ref=_string(raw.get("source_ref")),
            raw=raw,
        )


@dataclass(frozen=True)
class UsageDay:
    """One day of ``GET /v1/account/usage`` (or of one key's series)."""

    day: str | None
    documents: int | None
    tokens: int | None
    failures: int | None = None
    rules_only: int | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> UsageDay:
        return cls(
            day=_string(raw.get("day")),
            documents=_integer(raw.get("documents")),
            tokens=_integer(raw.get("tokens")),
            failures=_integer(raw.get("failures")),
            rules_only=_integer(raw.get("rules_only")),
            raw=raw,
        )


@dataclass(frozen=True)
class KeyUsage:
    """One key of ``GET /v1/account/usage/by-key``. The busiest keys come one
    by one; the rest are rolled into one entry with ``key_id`` ``None``."""

    key_id: int | None
    name: str | None
    documents: int | None
    tokens: int | None
    failures: int | None
    series: tuple[UsageDay, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> KeyUsage:
        return cls(
            key_id=_integer(raw.get("key_id")),
            name=_string(raw.get("name")),
            documents=_integer(raw.get("documents")),
            tokens=_integer(raw.get("tokens")),
            failures=_integer(raw.get("failures")),
            series=tuple(
                UsageDay._from(d)
                for d in _list(raw.get("series"))
                if isinstance(d, dict)
            ),
            raw=raw,
        )


@dataclass(frozen=True)
class ApiKey:
    """One key of ``GET /v1/account/keys``. Never its secret: the service
    shows that once, when the key is minted."""

    id: int | None
    name: str | None
    created_by: str | None
    created_at: str | None
    last_used_at: str | None
    revoked_at: str | None
    active: bool | None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> ApiKey:
        return cls(
            id=_integer(raw.get("id")),
            name=_string(raw.get("name")),
            created_by=_string(raw.get("created_by")),
            created_at=_string(raw.get("created_at")),
            last_used_at=_string(raw.get("last_used_at")),
            revoked_at=_string(raw.get("revoked_at")),
            active=_boolean(raw.get("active")),
            raw=raw,
        )


@dataclass(frozen=True)
class KeyRevocation:
    """The answer to ``POST /v1/account/keys/{id}/revoke``."""

    id: int | None
    keys_remaining: int | None
    locked_out: bool | None
    """True when no active key is left: nothing can call the service until a
    person mints a new one in the console."""
    self_revoked: bool | None
    """True when the key revoked is the one that made this call."""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def _from(cls, raw: dict[str, Any]) -> KeyRevocation:
        return cls(
            id=_integer(raw.get("id")),
            keys_remaining=_integer(raw.get("keys_remaining")),
            locked_out=_boolean(raw.get("locked_out")),
            self_revoked=_boolean(raw.get("self_revoked")),
            raw=raw,
        )


@dataclass(frozen=True)
class Job:
    """``GET /v1/jobs/{id}``: a job's state, and its result once it has one."""

    job_id: str
    status: str
    """``queued``, ``running`` or ``succeeded``. A failed or rejected job
    raises instead (502, 413)."""
    created_at: str | None = None
    result: RedactResult | None = None
    """Set when the job succeeded. Its text and offsets are those of the text
    the service received -- under the local-first cloud mode, the locally
    masked text, not the caller's original."""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


# ── Clients ──────────────────────────────────────────────────────────────


class _ApiClient(_BaseClient):
    """A synchronous JSON client. GETs are retried like the redact call
    (timeouts, 5xx, the edge's 429); writes are sent once."""

    def __init__(
        self, config: CloudConfig | None = None, *, client: Any = None
    ) -> None:
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

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _call(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        retry: bool,
    ) -> dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        attempt = _Attempt(self.config.max_retries if retry else 0)
        while True:
            status, data, headers = None, {}, None
            try:
                resp = self._http().request(
                    method, url, params=params, headers=self._headers(str(uuid.uuid4()))
                )
                status, headers, data = (
                    resp.status_code,
                    resp.headers,
                    _json_or_empty(resp),
                )
            except self._httpx.HTTPError as exc:
                if not attempt.should_retry(None):
                    raise CloudError(f"cloud request failed: {exc}") from exc
            else:
                if status == 200:
                    return data
                if (
                    status not in _RETRY_STATUS
                    or not attempt.should_retry(status)
                    or (status == 429 and _is_quota(data))
                ):
                    self._raise_for(status, data)
            attempt.attempt += 1
            time.sleep(attempt.backoff(_retry_after_seconds(headers)))


class Account(_ApiClient):
    """The account an API key belongs to: summary, credits, usage and keys.

    These calls pass with an API key while the service accepts account calls
    without a browser ``Origin`` (its ``EUREDACT_CONSOLE_REQUIRE_ORIGIN=0``); a
    refusal arrives as a :class:`~euredact.cloud.CloudError` with status 403.
    """

    def summary(self) -> AccountSummary:
        return AccountSummary._from(self._call("GET", "/v1/account", retry=True))

    def credits(self) -> Credits:
        return Credits._from(self._call("GET", "/v1/account/credits", retry=True))

    def credit_history(self, limit: int = 50) -> list[CreditEntry]:
        """Recent credit movements, newest first (1-500)."""
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        data = self._call(
            "GET", "/v1/account/credits/history", {"limit": int(limit)}, retry=True
        )
        return [
            CreditEntry._from(e)
            for e in _list(data.get("entries"))
            if isinstance(e, dict)
        ]

    def usage(self, days: int = 30) -> list[UsageDay]:
        """Documents, tokens and failures per day over the last *days*."""
        if days < 1:
            raise ValueError("days must be at least 1")
        data = self._call("GET", "/v1/account/usage", {"days": int(days)}, retry=True)
        return [
            UsageDay._from(d) for d in _list(data.get("series")) if isinstance(d, dict)
        ]

    def usage_by_key(self, days: int = 30) -> list[KeyUsage]:
        """The same window, split by the key that submitted the work."""
        if days < 1:
            raise ValueError("days must be at least 1")
        data = self._call(
            "GET", "/v1/account/usage/by-key", {"days": int(days)}, retry=True
        )
        return [
            KeyUsage._from(k) for k in _list(data.get("keys")) if isinstance(k, dict)
        ]

    def keys(self) -> list[ApiKey]:
        data = self._call("GET", "/v1/account/keys", retry=True)
        return [ApiKey._from(k) for k in _list(data.get("keys")) if isinstance(k, dict)]

    def revoke_key(self, key_id: int) -> KeyRevocation:
        """Revoke a key, e.g. one that leaked. The one write a key may make.

        Sent once, never retried. A key already revoked raises
        :class:`~euredact.cloud.CloudError` with status 409; one that does not
        exist, or belongs to another account, raises
        :class:`~euredact.cloud.NotFoundError`. Revoking the key this client
        uses works, and is reported by ``self_revoked``; the next call fails.
        """
        return KeyRevocation._from(
            self._call("POST", f"/v1/account/keys/{int(key_id)}/revoke", retry=False)
        )


class Jobs(_ApiClient):
    """Past jobs, by id."""

    def retrieve(self, job_id: str) -> Job:
        """A job's state, and its result if it has one.

        Raises :class:`~euredact.cloud.ResultExpiredError` when the job
        succeeded but its result is no longer retained, and
        :class:`~euredact.cloud.NotFoundError` for an unknown job (or one of
        another account's).
        """
        data = self._call("GET", f"/v1/jobs/{job_id}", retry=True)
        result = None
        if "redacted_text" in data:
            result = _to_result(data, text=data.get("redacted_text") or "")
        return Job(
            job_id=_string(data.get("job_id")) or job_id,
            status=_string(data.get("status")) or ("succeeded" if result else ""),
            created_at=_string(data.get("created_at")),
            result=result,
            raw=data,
        )


__all__ = [
    "Account",
    "AccountSummary",
    "ApiKey",
    "CreditEntry",
    "Credits",
    "Job",
    "Jobs",
    "KeyRevocation",
    "KeyUsage",
    "UsageDay",
]
