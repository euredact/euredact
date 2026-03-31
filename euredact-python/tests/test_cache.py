"""Tests for result cache."""

from euredact.cache import ResultCache
from euredact.types import RedactResult


class TestResultCache:
    def test_put_and_get(self):
        cache = ResultCache(maxsize=10)
        result = RedactResult(redacted_text="test", detections=[], source="rules")
        cache.put("key1", result)
        assert cache.get("key1") is result

    def test_cache_miss(self):
        cache = ResultCache(maxsize=10)
        assert cache.get("missing") is None

    def test_lru_eviction(self):
        cache = ResultCache(maxsize=2)
        r1 = RedactResult(redacted_text="t1", detections=[], source="rules")
        r2 = RedactResult(redacted_text="t2", detections=[], source="rules")
        r3 = RedactResult(redacted_text="t3", detections=[], source="rules")
        cache.put("k1", r1)
        cache.put("k2", r2)
        cache.put("k3", r3)
        assert cache.get("k1") is None  # Evicted
        assert cache.get("k2") is r2
        assert cache.get("k3") is r3

    def test_disabled(self):
        cache = ResultCache(enabled=False)
        r = RedactResult(redacted_text="t", detections=[], source="rules")
        cache.put("k", r)
        assert cache.get("k") is None

    def test_clear(self):
        cache = ResultCache(maxsize=10)
        r = RedactResult(redacted_text="t", detections=[], source="rules")
        cache.put("k", r)
        cache.clear()
        assert cache.get("k") is None

    def test_key_deterministic(self):
        cache = ResultCache()
        k1 = cache.key("hello", ("NL",), "rules")
        k2 = cache.key("hello", ("NL",), "rules")
        assert k1 == k2

    def test_key_different_for_different_input(self):
        cache = ResultCache()
        k1 = cache.key("hello", ("NL",), "rules")
        k2 = cache.key("world", ("NL",), "rules")
        assert k1 != k2
