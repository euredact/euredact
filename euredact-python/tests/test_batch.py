"""Tests for batch processing, async, and iterator APIs."""

import asyncio

import euredact
from euredact.types import EntityType


class TestRedactBatch:
    def test_batch_returns_list(self):
        results = euredact.redact_batch(
            ["jan@test.nl", "BE68539007547034"],
            countries=["NL", "BE"],
        )
        assert isinstance(results, list)
        assert len(results) == 2

    def test_batch_order_preserved(self):
        texts = ["first@test.nl", "second@test.nl", "third@test.nl"]
        results = euredact.redact_batch(texts)
        for i, r in enumerate(results):
            assert r.detections[0].text == texts[i]

    def test_batch_empty(self):
        results = euredact.redact_batch([])
        assert results == []

    def test_batch_single(self):
        results = euredact.redact_batch(["jan@test.nl"])
        assert len(results) == 1
        assert "[EMAIL]" in results[0].redacted_text

    def test_batch_with_referential_integrity(self):
        results = euredact.redact_batch(
            ["jan@test.nl", "jan@test.nl"],
            referential_integrity=True,
        )
        # Same email should get same label across batch
        assert results[0].redacted_text == results[1].redacted_text

    def test_batch_with_countries(self):
        results = euredact.redact_batch(
            ["BSN: 111222333", "IBAN: BE68539007547034"],
            countries=["NL", "BE"],
        )
        assert "[NATIONAL_ID]" in results[0].redacted_text
        assert "[IBAN]" in results[1].redacted_text


class TestAredact:
    def test_aredact_returns_result(self):
        async def run():
            return await euredact.aredact("jan@test.nl")
        result = asyncio.run(run())
        assert "[EMAIL]" in result.redacted_text

    def test_aredact_with_countries(self):
        async def run():
            return await euredact.aredact("BSN: 111222333", countries=["NL"])
        result = asyncio.run(run())
        assert "[NATIONAL_ID]" in result.redacted_text


class TestAredactBatch:
    def test_aredact_batch_returns_list(self):
        async def run():
            return await euredact.aredact_batch(
                ["jan@test.nl", "piet@test.nl"],
                max_concurrency=2,
            )
        results = asyncio.run(run())
        assert len(results) == 2
        assert all("[EMAIL]" in r.redacted_text for r in results)

    def test_aredact_batch_order_preserved(self):
        async def run():
            texts = [f"user{i}@test.nl" for i in range(10)]
            return await euredact.aredact_batch(texts, max_concurrency=3)
        results = asyncio.run(run())
        assert len(results) == 10
        for i, r in enumerate(results):
            assert f"user{i}@test.nl" not in r.redacted_text

    def test_aredact_batch_empty(self):
        async def run():
            return await euredact.aredact_batch([])
        results = asyncio.run(run())
        assert results == []


class TestRedactIter:
    def test_iter_yields_results(self):
        texts = ["jan@test.nl", "piet@test.nl"]
        results = list(euredact.redact_iter(iter(texts)))
        assert len(results) == 2
        assert all("[EMAIL]" in r.redacted_text for r in results)

    def test_iter_lazy(self):
        """Iterator should not process all items upfront."""
        call_count = 0

        def gen():
            nonlocal call_count
            for i in range(100):
                call_count += 1
                yield f"user{i}@test.nl"

        it = euredact.redact_iter(gen())
        # Take only first 3
        for _, r in zip(range(3), it):
            assert "[EMAIL]" in r.redacted_text
        # Should have only processed ~3, not all 100
        assert call_count <= 4  # generator may read one ahead

    def test_iter_with_countries(self):
        texts = iter(["BSN: 111222333"])
        results = list(euredact.redact_iter(texts, countries=["NL"]))
        assert "[NATIONAL_ID]" in results[0].redacted_text
