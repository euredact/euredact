"""[CLOUD EXTENSION] Batches: cloud mode, with hours between masking and mapping.

Cloud mode masks a document here, sends only the masked text and maps the
service's answer back onto the original, all in one call. A batch hands up to
5,000 documents to the service and collects the answers within 24 hours, so
there is no single call to do the mapping in. The structured PII the rules
engine found must still never leave this machine (rules-engine#84; the gateway
side is ``docs/BATCHES.md`` in euredact-inference).

So :meth:`Batches.create` writes one **local batch file** per batch. It holds
each original, its local detections and the SHA-256 of the masked text that
was sent, and nothing of it is uploaded. :meth:`Batches.results` maps the
service's spans back from that file, checking the hash before placing a single
span, then wipes the originals and leaves a text-free receipt.

    from euredact.cloud.batches import Batches

    batches = Batches()                       # uses euredact.configure(...)
    batch = batches.create([
        {"custom_id": "invoice-2291", "text": text, "countries": ["BE"]},
    ])
    ...                                       # hours later, maybe elsewhere
    outcome = batches.results(batch.id)
    if outcome.status == "resolved":
        for custom_id, item in outcome.documents.items():
            print(custom_id, item.result.redacted_text if item.ok else item.error)

The file is written with mode ``0600`` in a ``0700`` directory,
``~/.euredact/batches`` by default. Pass ``batch_dir=`` to put it somewhere
several workers share, ``store=`` to keep it somewhere else entirely, and
``cipher=`` to encrypt it at rest with a key you hold.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from euredact.cloud.client import (
    CloudError,
    _BaseClient,
    _cloud_info,
    _integer,
    _json_or_empty,
    _require_httpx,
    _to_result,
)
from euredact.cloud.config import CloudConfig
from euredact.types import Detection, DetectionSource, EntityType, RedactResult

#: The gateway's limits (docs/BATCHES.md §2-§3), checked before anything is
#: uploaded so a batch the gateway would refuse never leaves the machine.
MAX_DOCUMENTS = 5000
MAX_CUSTOM_ID = 64
#: The gateway's custom_id rule (euredact-inference gateway/batches.py),
#: matched against the whole string.
CUSTOM_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")
MAX_BODY_BYTES = 128 * 1024 * 1024
#: Per document, counted by the model's tokenizer on the gateway. The SDK has
#: no copy of it, and no character count decides it either way, so a document
#: over the limit comes back as an ``errored`` result with code ``too_long``.
MAX_DOCUMENT_TOKENS = 5000

FILE_FORMAT = "euredact-batch/1"
DEFAULT_BATCH_DIR = Path.home() / ".euredact" / "batches"


class BatchError(CloudError):
    """A batch could not be created, or its local file cannot be used."""


# ── Storage ──────────────────────────────────────────────────────────────


class BatchStore(Protocol):
    """Where local batch files live. One opaque blob per batch id."""

    def read(self, batch_id: str) -> bytes | None: ...
    def write(self, batch_id: str, data: bytes) -> None: ...
    def delete(self, batch_id: str) -> None: ...
    def list(self) -> list[str]: ...


class FileBatchStore:
    """``<dir>/<batch_id>.json``: directory ``0700``, files ``0600``.

    Writes go to a temporary file in the same directory, created ``0600``
    before any byte is written, then renamed over the old one. A crash leaves
    the previous version or the new one, never half of either, and the
    originals are never readable by another user, not even briefly.
    """

    def __init__(self, directory: str | os.PathLike[str] | None = None) -> None:
        self.directory = Path(directory) if directory is not None else DEFAULT_BATCH_DIR

    def _path(self, batch_id: str) -> Path:
        if (
            not batch_id
            or "/" in batch_id
            or "\\" in batch_id
            or batch_id in (".", "..")
        ):
            raise BatchError(f"not a batch id: {batch_id!r}")
        return self.directory / f"{batch_id}.json"

    def _ensure_dir(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass

    def read(self, batch_id: str) -> bytes | None:
        try:
            return self._path(batch_id).read_bytes()
        except FileNotFoundError:
            return None

    def write(self, batch_id: str, data: bytes) -> None:
        self._ensure_dir()
        target = self._path(batch_id)
        fd, tmp = tempfile.mkstemp(
            prefix=f".{batch_id}.", suffix=".tmp", dir=self.directory
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise

    def delete(self, batch_id: str) -> None:
        try:
            self._path(batch_id).unlink()
        except FileNotFoundError:
            pass

    def list(self) -> list[str]:
        if not self.directory.is_dir():
            return []
        return sorted(
            p.stem for p in self.directory.glob("*.json") if not p.name.startswith(".")
        )


class Cipher(Protocol):
    """Encryption at rest for the local batch file, with a key the caller holds.

    The SDK has no cryptography dependency, so it does not pick a scheme: pass
    any object with these two methods (for example AES-GCM from the
    ``cryptography`` package, with a fresh nonce per call).
    """

    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...


# ── Results ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Batch:
    """A batch as the gateway reports it."""

    id: str
    status: str
    created_at: str | None = None
    expires_at: str | None = None
    ended_at: str | None = None
    results_expire_at: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    documents: int | None = None
    tokens: dict[str, int] = field(default_factory=dict)
    """``{"prompt": n, "completion": n}`` so far (rules-engine#89)."""
    credits_charged: int | None = None
    """Credits debited for the batch so far, at :attr:`billing_rate`."""
    billing_rate: float | None = None
    """The batch rate, e.g. ``0.75``: batches are billed at their own rate."""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class DocumentOutcome:
    """One document of a resolved batch: a result, or why there is none."""

    custom_id: str
    result: RedactResult | None = None
    error: str | None = None
    """``None`` on success. Otherwise a code: the gateway's (``too_long``, …),
    ``expired``, ``cancelled``, or one of the SDK's own:
    ``local_mismatch`` -- the local file does not match what was sent;
    ``missing_local_entry`` -- no local entry for this ``custom_id``."""
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class BatchResults:
    """What :meth:`Batches.results` found.

    ``status`` is one of:

    * ``"not_ended"`` -- the batch is still running; nothing changed locally.
    * ``"resolved"`` -- mapped now; ``documents`` holds every outcome, and the
      local file has been reduced to a text-free receipt.
    * ``"already_resolved"`` -- an earlier call mapped it; ``documents`` is
      empty, because the originals are gone. A batch is never mapped twice.
    * ``"expired"`` -- the gateway no longer holds the results; the local
      entries have been wiped.
    """

    batch_id: str
    status: str
    documents: dict[str, DocumentOutcome] = field(default_factory=dict)
    batch: Batch | None = None


# ── The local batch file ─────────────────────────────────────────────────


def _now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _detection_to_json(d: Detection) -> dict[str, Any]:
    return {
        "type": d.entity_type.value
        if isinstance(d.entity_type, EntityType)
        else d.entity_type,
        "start": d.start,
        "end": d.end,
        "text": d.text,
        "source": d.source.value,
        "country": d.country,
        "confidence": d.confidence,
        "country_confidence": d.country_confidence,
        "out_of_scope": d.out_of_scope,
    }


def _detection_from_json(raw: dict[str, Any]) -> Detection:
    try:
        entity_type: EntityType | str = EntityType(raw["type"])
    except ValueError:
        entity_type = raw["type"]
    return Detection(
        entity_type=entity_type,
        start=int(raw["start"]),
        end=int(raw["end"]),
        text=raw["text"],
        source=DetectionSource(raw["source"]),
        country=raw.get("country"),
        confidence=raw.get("confidence", "high"),
        country_confidence=float(raw.get("country_confidence", 0.0)),
        out_of_scope=bool(raw.get("out_of_scope", False)),
    )


# ── The client ───────────────────────────────────────────────────────────


class Batches(_BaseClient):
    """Create, track and resolve batches, keeping the structured PII local."""

    def __init__(
        self,
        config: CloudConfig | None = None,
        *,
        batch_dir: str | os.PathLike[str] | None = None,
        store: BatchStore | None = None,
        cipher: Cipher | None = None,
        sdk: Any = None,
        client: Any = None,
    ) -> None:
        super().__init__(config)
        if batch_dir is not None and store is not None:
            raise ValueError("pass batch_dir= or store=, not both")
        self.store: BatchStore = (
            store if store is not None else FileBatchStore(batch_dir)
        )
        self.cipher = cipher
        self._sdk = sdk
        self._httpx = _require_httpx()
        self._client = client
        self._owned = client is None

    # -- plumbing ----------------------------------------------------------

    def _engine(self):
        if self._sdk is None:
            from euredact.sdk import EuRedact

            self._sdk = EuRedact()
        return self._sdk

    def _http(self):
        if self._client is None:
            self._client = self._httpx.Client(timeout=self.config.timeout_s)
        return self._client

    def close(self) -> None:
        if self._owned and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "Batches":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ):
        all_headers = self._headers(str(uuid.uuid4()))
        all_headers.update(headers or {})
        try:
            return self._http().request(
                method, self._url(path), content=content, headers=all_headers
            )
        except self._httpx.HTTPError as exc:
            raise CloudError(f"batch request failed: {exc}") from exc

    def _load(self, batch_id: str) -> dict[str, Any] | None:
        data = self.store.read(batch_id)
        if data is None:
            return None
        if self.cipher is not None:
            data = self.cipher.decrypt(data)
        state = json.loads(data.decode("utf-8"))
        if state.get("format") != FILE_FORMAT:
            raise BatchError(
                f"local batch file {batch_id}: unknown format {state.get('format')!r}"
            )
        return state

    def _save(self, state: dict[str, Any]) -> None:
        data = json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if self.cipher is not None:
            data = self.cipher.encrypt(data)
        self.store.write(state["batch_id"], data)

    @staticmethod
    def _batch(raw: dict[str, Any]) -> Batch:
        return Batch(
            id=raw.get("id", ""),
            status=raw.get("status", ""),
            created_at=raw.get("created_at"),
            expires_at=raw.get("expires_at"),
            ended_at=raw.get("ended_at"),
            results_expire_at=raw.get("results_expire_at"),
            counts=dict(raw.get("counts") or {}),
            documents=_integer(raw.get("documents")),
            tokens={k: v for k, v in (raw.get("tokens") or {}).items()
                    if isinstance(v, int) and not isinstance(v, bool)}
            if isinstance(raw.get("tokens"), dict) else {},
            credits_charged=_integer(raw.get("credits_charged")),
            billing_rate=(float(raw["billing_rate"])
                          if isinstance(raw.get("billing_rate"), (int, float))
                          and not isinstance(raw.get("billing_rate"), bool) else None),
            raw=raw,
        )

    # -- create ------------------------------------------------------------

    def create(
        self, documents: Iterable[dict[str, Any]], *, idempotency_key: str | None = None
    ) -> Batch:
        """Mask every document here, upload only the masked text, keep the rest.

        Each document is ``{"custom_id", "text", "countries", "language"?}``
        with exactly one country, as in cloud mode. The document count,
        ``custom_id``s, countries and body size are checked before anything is
        uploaded or written. The 5,000-token limit per document is **not**: it
        is counted by the model's tokenizer on the gateway, which the SDK does
        not have, so a document over it comes back from :meth:`results` as an
        error with code ``too_long`` that says so. The local batch file is
        written only once the gateway has accepted the batch and named it.
        """
        from euredact.sdk import _mask_for_cloud

        docs = list(documents)
        if not docs:
            raise BatchError("a batch needs at least one document")
        if len(docs) > MAX_DOCUMENTS:
            raise BatchError(
                f"{len(docs):,} documents; a batch holds at most {MAX_DOCUMENTS:,}"
            )
        # Every document is checked before any is masked. Masking 5,000
        # documents and then learning that the gateway refuses the batch for
        # one bad custom_id wastes the whole pass (rules-engine#88).
        seen: set[str] = set()
        checked: list[tuple[str, str, list[str], str]] = []
        for number, doc in enumerate(docs, start=1):
            custom_id = doc.get("custom_id")
            if not isinstance(custom_id, str) or not CUSTOM_ID.fullmatch(custom_id):
                raise BatchError(
                    f"document {number}: custom_id must be 1-{MAX_CUSTOM_ID} "
                    "characters of A-Z a-z 0-9 _ . : -"
                )
            if custom_id in seen:
                raise BatchError(
                    f"document {number}: duplicate custom_id {custom_id!r}"
                )
            seen.add(custom_id)
            text = doc.get("text")
            if not isinstance(text, str):
                raise BatchError(f"document {number}: text must be a string")
            countries = [c.upper() for c in (doc.get("countries") or [])]
            if len(countries) != 1:
                raise BatchError(
                    f"document {number}: exactly one country is needed, "
                    "as in cloud mode"
                )
            checked.append((custom_id, text, countries, doc.get("language") or ""))

        lines: list[bytes] = []
        entries: dict[str, dict[str, Any]] = {}
        engine = self._engine()
        for custom_id, text, countries, language in checked:
            # The same local pass as redact(mode="cloud"): dates on, no
            # allowlist, no tokens. What is sent is byte for byte what cloud
            # mode would send for this document.
            local = engine.redact(
                text, countries=countries, detect_dates=True, cache=False
            )
            masked, _labels = _mask_for_cloud(text, local.detections)
            line = {"custom_id": custom_id, "text": masked, "countries": countries}
            if language:
                line["language"] = language
            lines.append(json.dumps(line, ensure_ascii=False).encode("utf-8"))
            entries[custom_id] = {
                "text": text,
                "masked_sha256": _sha256(masked),
                "countries": countries,
                "language": language,
                "detections": [_detection_to_json(d) for d in local.detections],
                "detection_mode": local.detection_mode,
                "inferred_countries": [list(pair) for pair in local.inferred_countries],
            }

        body = b"\n".join(lines) + b"\n"
        if len(body) > MAX_BODY_BYTES:
            raise BatchError(
                f"the masked batch is {len(body):,} bytes; "
                f"the limit is {MAX_BODY_BYTES:,}"
            )

        key = idempotency_key or str(uuid.uuid4())
        resp = self._request(
            "POST",
            "/v1/batches",
            content=gzip.compress(body),
            headers={
                "Content-Type": "application/x-ndjson",
                "Content-Encoding": "gzip",
                "Idempotency-Key": key,
            },
        )
        payload = _json_or_empty(resp)
        if resp.status_code not in (200, 201):
            self._raise_for(resp.status_code, payload)
        batch = self._batch(payload)
        if not batch.id:
            raise BatchError("the gateway accepted the batch but returned no id")

        from euredact import __version__

        self._save(
            {
                "format": FILE_FORMAT,
                "batch_id": batch.id,
                "status": "pending",
                "created_at": batch.created_at or _now(),
                "expires_at": batch.expires_at,
                "results_expire_at": None,
                "resolved_at": None,
                "engine_version": __version__,
                "counts": {"documents": len(entries)},
                "entries": entries,
            }
        )
        return batch

    # -- retrieve, cancel, pending, purge ----------------------------------

    def retrieve(self, batch_id: str) -> Batch:
        """The gateway's view: status, counts and timestamps."""
        self.sweep()
        resp = self._request("GET", f"/v1/batches/{batch_id}")
        payload = _json_or_empty(resp)
        if resp.status_code != 200:
            self._raise_for(resp.status_code, payload)
        batch = self._batch(payload)
        state = self._load(batch_id)
        if (
            state is not None
            and batch.results_expire_at
            and state.get("results_expire_at") != batch.results_expire_at
        ):
            state["results_expire_at"] = batch.results_expire_at
            self._save(state)
        return batch

    def list(self, limit: int = 20) -> list[Batch]:
        """This account's batches, newest first (1-100, the gateway's bound).

        The gateway's view only: a batch created elsewhere has no local file
        here, and :meth:`pending` lists the ones that do.
        """
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        resp = self._request("GET", f"/v1/batches?limit={int(limit)}")
        payload = _json_or_empty(resp)
        if resp.status_code != 200:
            self._raise_for(resp.status_code, payload)
        return [self._batch(raw) for raw in payload.get("batches") or []
                if isinstance(raw, dict)]

    def cancel(self, batch_id: str) -> Batch:
        """Cancel queued documents. The local file stays ``pending`` until the
        documents that did finish have been mapped by :meth:`results`."""
        resp = self._request("POST", f"/v1/batches/{batch_id}/cancel")
        payload = _json_or_empty(resp)
        if resp.status_code not in (200, 202):
            self._raise_for(resp.status_code, payload)
        return self._batch(payload)

    def pending(self) -> list[str]:
        """Batch ids whose local file still waits to be mapped. A restarted
        worker resumes from here; this reads files only, no gateway call."""
        self.sweep()
        out = []
        for batch_id in self.store.list():
            state = self._load(batch_id)
            if state is not None and state.get("status") == "pending":
                out.append(batch_id)
        return out

    def purge(self, batch_id: str) -> None:
        """Delete the local file, whatever its status. A pending batch can no
        longer be mapped afterwards."""
        self.store.delete(batch_id)

    def sweep(self, now: datetime | None = None) -> None:
        """Delete receipts and expire pending files past ``results_expire_at``.

        Runs at the start of the calls that look in the store, so nothing has
        to be scheduled. A pending file past that time can never be mapped --
        the gateway has swept the results -- so its originals are wiped.
        """
        now = now or datetime.now(timezone.utc)
        for batch_id in self.store.list():
            try:
                state = self._load(batch_id)
            except (BatchError, ValueError):
                continue
            if state is None:
                continue
            expiry = _parse_time(state.get("results_expire_at"))
            if expiry is None or now < expiry:
                continue
            if state["status"] == "pending":
                self._wipe(state, "expired")
            else:
                self.store.delete(batch_id)

    def _wipe(self, state: dict[str, Any], status: str) -> None:
        state["entries"] = {}
        state["status"] = status
        state["resolved_at"] = _now()
        self._save(state)

    # -- results -----------------------------------------------------------

    def results(self, batch_id: str) -> BatchResults:
        """Map an ended batch back onto the originals in its local file.

        Integrity first: each document's masked text is rebuilt from its
        stored original and detections, and must hash to both the stored
        SHA-256 and the gateway's ``masked_sha256`` before a single span is
        placed. Anything that cannot be mapped is a per-document error, never
        the masked text passed off as a result.
        """
        state = self._load(batch_id)
        if state is not None and state["status"] in ("resolved", "expired"):
            return BatchResults(
                batch_id,
                "already_resolved" if state["status"] == "resolved" else "expired",
            )

        batch = self.retrieve(batch_id)
        if batch.status != "ended":
            return BatchResults(batch_id, "not_ended", batch=batch)

        resp = self._request("GET", f"/v1/batches/{batch_id}/results")
        if resp.status_code == 410:
            if state is not None:
                self._wipe(state, "expired")
            return BatchResults(batch_id, "expired", batch=batch)
        if resp.status_code == 409:
            return BatchResults(batch_id, "not_ended", batch=batch)
        if resp.status_code != 200:
            self._raise_for(resp.status_code, _json_or_empty(resp))

        entries = (state or {}).get("entries", {})
        documents: dict[str, DocumentOutcome] = {}
        for line in resp.text.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            custom_id = row.get("custom_id", "")
            documents[custom_id] = self._outcome(
                custom_id,
                row.get("result") or {},
                entries.get(custom_id),
                file_exists=state is not None,
            )

        if state is not None:
            counts = {
                "documents": len(documents),
                "mapped": sum(1 for o in documents.values() if o.ok),
            }
            for outcome in documents.values():
                if outcome.error:
                    counts[outcome.error] = counts.get(outcome.error, 0) + 1
            state["counts"] = counts
            self._wipe(state, "resolved")
        return BatchResults(batch_id, "resolved", documents, batch=batch)

    def _outcome(
        self,
        custom_id: str,
        result: dict[str, Any],
        entry: dict[str, Any] | None,
        *,
        file_exists: bool,
    ) -> DocumentOutcome:
        from euredact.sdk import (
            _apply_replacements,
            _mask_for_cloud,
            _onto_original,
            _type_label,
        )

        kind = result.get("type")
        if kind != "succeeded":
            error = result.get("error") or {}
            code = error.get("code") or kind or "errored"
            message = error.get("message", "")
            if code == "too_long":
                message = (
                    f"{message}. The {MAX_DOCUMENT_TOKENS:,}-token limit is counted by "
                    "the model's tokenizer on the gateway; the SDK cannot check it "
                    "before upload. Split the document and submit the parts."
                ).lstrip(". ")
            return DocumentOutcome(custom_id, error=code, message=message)
        if entry is None:
            reason = (
                "no local batch file on this machine"
                if not file_exists
                else "no entry for this document in the local batch file"
            )
            return DocumentOutcome(
                custom_id, error="missing_local_entry", message=reason
            )

        text = entry["text"]
        local = [_detection_from_json(d) for d in entry["detections"]]
        masked, labels = _mask_for_cloud(text, local)
        if (
            _sha256(masked) != entry["masked_sha256"]
            or result.get("masked_sha256") != entry["masked_sha256"]
        ):
            return DocumentOutcome(
                custom_id,
                error="local_mismatch",
                message="the local batch file does not match what was sent",
            )
        remote = _to_result({"entities": result.get("entities", [])}, text=masked)
        try:
            placed = _onto_original(remote.detections, masked, text, labels)
        except CloudError as exc:
            return DocumentOutcome(custom_id, error="local_mismatch", message=str(exc))
        detections = sorted(local + placed, key=lambda d: (d.start, -d.end))
        redacted = _apply_replacements(
            text, detections, lambda det, _slice: f"[{_type_label(det.entity_type)}]"
        )
        return DocumentOutcome(
            custom_id,
            result=RedactResult(
                redacted_text=redacted,
                detections=detections,
                source="cloud",
                inferred_countries=tuple(
                    (c, float(s)) for c, s in entry.get("inferred_countries", [])
                ),
                detection_mode=entry.get("detection_mode", "declared"),
                # A batch line carries the model and anything unplaced; it has
                # no job id and no usage of its own (the batch carries those).
                cloud=_cloud_info({"model_version": result.get("model_version"),
                                   "unlocated": result.get("unlocated")}),
            ),
        )


__all__ = [
    "CUSTOM_ID",
    "Batch",
    "BatchError",
    "BatchResults",
    "BatchStore",
    "Batches",
    "Cipher",
    "DocumentOutcome",
    "FileBatchStore",
    "MAX_CUSTOM_ID",
    "MAX_DOCUMENTS",
    "MAX_BODY_BYTES",
    "MAX_DOCUMENT_TOKENS",
]
