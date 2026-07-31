"""LRU result cache with SHA-256 content hashing."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

from euredact.types import RedactResult

# Default ceiling on retained characters, not entries. A count-only cap of
# 1024 entries says nothing about memory: 1024 cached 1 MB documents is a
# gigabyte of PII-bearing text held live. ~16M characters is a few tens of MB.
DEFAULT_MAX_CHARS = 16_000_000


def _result_chars(result: RedactResult) -> int:
    """Approximate retained size of a cached result, in characters."""
    return len(result.redacted_text) + sum(len(d.text) for d in result.detections)


class ResultCache:
    """LRU cache keyed on SHA-256 of input text + config hash.

    Bounded by both entry count and total retained characters — see
    :data:`DEFAULT_MAX_CHARS`.
    """

    def __init__(
        self,
        maxsize: int = 1024,
        enabled: bool = True,
        max_chars: int = DEFAULT_MAX_CHARS,
    ) -> None:
        self._maxsize = maxsize
        self._max_chars = max_chars
        self._enabled = enabled
        self._store: OrderedDict[str, RedactResult] = OrderedDict()
        self._sizes: dict[str, int] = {}
        self._chars = 0
        self._lock = threading.Lock()

    def key(self, text: str, countries: tuple[str, ...], mode: str) -> str:
        """Compute cache key from input text and configuration."""
        # Fed to the hash in pieces rather than joined into one f-string: the
        # f-string copied the whole document before hashing it.
        h = hashlib.sha256()
        h.update(text.encode())
        h.update(b"|")
        h.update("|".join(sorted(countries)).encode())
        h.update(b"|")
        h.update(mode.encode())
        return h.hexdigest()

    def get(self, key: str) -> RedactResult | None:
        """Retrieve a cached result, or None on miss."""
        if not self._enabled:
            return None
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                return self._store[key]
        return None

    def put(self, key: str, result: RedactResult) -> None:
        """Store a result in the cache."""
        if not self._enabled:
            return
        size = _result_chars(result)
        with self._lock:
            self._evict(key)
            # A single result larger than the whole budget would evict
            # everything else and still not fit; skip it rather than empty the
            # cache for one document.
            if size > self._max_chars:
                return
            self._store[key] = result
            self._sizes[key] = size
            self._chars += size
            while self._store and (
                len(self._store) > self._maxsize or self._chars > self._max_chars
            ):
                oldest = next(iter(self._store))
                self._evict(oldest)

    def _evict(self, key: str) -> None:
        """Drop *key* and its accounting. Caller holds the lock."""
        if key in self._store:
            del self._store[key]
        self._chars -= self._sizes.pop(key, 0)

    def clear(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self._store.clear()
            self._sizes.clear()
            self._chars = 0
