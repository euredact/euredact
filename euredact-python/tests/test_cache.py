"""Tests for result cache."""

from euredact.cache import ResultCache
from euredact.types import RedactResult


class TestResultCache:
    def test_put_and_get(self):
        cache = ResultCache(maxsize=10)
        result = RedactResult(redacted_text="test", detections=[], source="rules")
        cache.put("key1", result)
        # An equal result, not the stored one: callers may mutate what they get
        # (rules-engine#150).
        got = cache.get("key1")
        assert got == result and got is not result

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
        assert cache.get("k2") == r2  # an equal copy (rules-engine#150)
        assert cache.get("k3") == r3

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


class TestCachedResultsAreTheCallersOwn:
    """rules-engine#150: the cache handed out its stored result, keyed on the
    normalised text."""

    def test_mutating_a_result_does_not_change_the_next_one(self):
        from euredact import EuRedact
        sdk = EuRedact()
        first = sdk.redact("Mail piet@example.be", countries=["BE"])
        first.detections.clear()
        first.tokens["x"] = "y"
        again = sdk.redact("Mail piet@example.be", countries=["BE"])
        assert [d.text for d in again.detections] == ["piet@example.be"]
        assert again.tokens == {}

    def test_an_nfc_spelling_is_not_answered_with_the_nfd_result(self):
        import unicodedata

        from euredact import EuRedact
        sdk = EuRedact()
        nfd = unicodedata.normalize("NFD", "Ré: jan@example.be")
        nfc = unicodedata.normalize("NFC", nfd)
        sdk.redact(nfd, countries=["BE"])
        r = sdk.redact(nfc, countries=["BE"])
        assert r.redacted_text == "Ré: [EMAIL]"
        assert nfc[r.detections[0].start:r.detections[0].end] == "jan@example.be"

    def test_a_new_bic_registry_is_not_answered_from_the_cache(self):
        from euredact import EuRedact
        from euredact.rules import bic_registry
        sdk = EuRedact()
        before = bic_registry.registry_generation()
        # ABCD is no known bank, so without a label the code is left alone
        # until a registry vouches for it.
        assert sdk.redact("ABCDBEBB", countries=["BE"]).redacted_text == "ABCDBEBB"
        try:
            bic_registry.set_bic_registry({"ABCDBE"})
            assert bic_registry.registry_generation() == before + 1
            # A stale cache answer would still be the unmasked text.
            assert sdk.redact("ABCDBEBB", countries=["BE"]).redacted_text == "[BIC]"
            # The second call computed afresh: its key differs, so the cache
            # now holds two entries for the one text.
            assert len(sdk._cache._store) == 2
        finally:
            bic_registry.set_bic_registry(None)
