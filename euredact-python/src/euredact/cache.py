"""LRU result cache with SHA-256 content hashing."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

from euredact.types import RedactResult


class ResultCache:
    """LRU cache keyed on SHA-256 of input text + config hash."""

    def __init__(self, maxsize: int = 1024, enabled: bool = True) -> None:
        self._maxsize = maxsize
        self._enabled = enabled
        self._store: OrderedDict[str, RedactResult] = OrderedDict()
        self._lock = threading.Lock()

    def key(self, text: str, countries: tuple[str, ...], mode: str) -> str:
        """Compute cache key from input text and configuration."""
        raw = f"{text}|{'|'.join(sorted(countries))}|{mode}"
        return hashlib.sha256(raw.encode()).hexdigest()

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
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = result
            while len(self._store) > self._maxsize:
                self._store.popitem(last=False)

    def clear(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self._store.clear()
