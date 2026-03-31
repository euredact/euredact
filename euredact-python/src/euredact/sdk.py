"""Orchestrator: runs the detection pipeline and applies replacements."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator

from euredact.cache import ResultCache
from euredact.normalizer import map_offset_to_original, normalize
from euredact.rules.engine import RuleEngine
from euredact.types import Detection, EntityType, RedactResult

# Date entity types — opt-in via detect_dates=True
_DATE_TYPES = frozenset({EntityType.DOB, EntityType.DATE_OF_DEATH})

# Default thread pool for async offloading
_DEFAULT_POOL = ThreadPoolExecutor()


class PseudonymMapper:
    """Maps real PII values to consistent pseudonyms within a session."""

    def __init__(self) -> None:
        self._counters: dict[EntityType, int] = {}
        self._mapping: dict[str, str] = {}

    def get_pseudonym(self, text: str, entity_type: EntityType | str) -> str:
        """Return consistent pseudonym. Same input always returns same output."""
        if text not in self._mapping:
            self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
            n = self._counters[entity_type]
            label = entity_type.value if isinstance(entity_type, EntityType) else entity_type
            self._mapping[text] = f"{label}_{n}"
        return self._mapping[text]


class EuRedact:
    """Main EuRedact SDK orchestrator."""

    def __init__(self) -> None:
        self._engine = RuleEngine()
        self._cache = ResultCache()
        self._pseudonym_mapper = PseudonymMapper()

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Register a custom regex pattern detected as *name*."""
        self._engine.add_custom_pattern(name, pattern)
        self._cache.clear()

    def redact(
        self,
        text: str,
        *,
        countries: list[str] | None = None,
        mode: str = "rules",
        pseudonymize: bool = False,
        detect_dates: bool = False,
        coref: bool = False,
        coref_model: str = "default",
        cache: bool = True,
    ) -> RedactResult:
        """Redact PII from text. Main entry point.

        Args:
            detect_dates: Include date-of-birth / date-of-death detections.
                Off by default — bare dates without strong indicators are
                better handled by the cloud LLM tier. When True, the rule
                engine applies keyword and structural (JSON/CSV header)
                checks before emitting a date detection.
        """
        # Step 1: Normalize
        normalized_text, offset_mapping = normalize(text)

        # Step 2: Check cache
        countries_tuple = tuple(sorted(c.upper() for c in countries)) if countries else ("ALL",)
        cache_mode = f"{mode}|dates={detect_dates}"
        if cache:
            cache_key = self._cache.key(normalized_text, countries_tuple, cache_mode)
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # Steps 3-6: Rule engine detection
        detections = self._engine.detect(normalized_text, countries)

        # Map offsets back to original text if normalization changed length
        if offset_mapping is not None:
            detections = [
                Detection(
                    entity_type=d.entity_type,
                    start=map_offset_to_original(d.start, offset_mapping),
                    end=map_offset_to_original(d.end, offset_mapping),
                    text=d.text,
                    source=d.source,
                    country=d.country,
                    confidence=d.confidence,
                )
                for d in detections
            ]

        # Filter date types unless opted in
        if not detect_dates:
            detections = [d for d in detections if d.entity_type not in _DATE_TYPES]

        # Steps 7-13: [CLOUD EXTENSION] — no-ops in rules-only mode

        # Step 14: Sort detections by position
        detections.sort(key=lambda d: (d.start, -d.end))

        # Step 15: Apply replacements right-to-left
        redacted = text  # Use original text for replacements
        for det in reversed(detections):
            if pseudonymize:
                replacement = self._pseudonym_mapper.get_pseudonym(
                    det.text, det.entity_type
                )
            else:
                label = det.entity_type.value if isinstance(det.entity_type, EntityType) else det.entity_type
                replacement = f"[{label}]"
            redacted = redacted[: det.start] + replacement + redacted[det.end :]

        # Step 16: [COREF EXTENSION] — no-op

        result = RedactResult(
            redacted_text=redacted,
            detections=detections,
            source="rules",
            degraded=False,
        )

        # Step 17: Cache
        if cache:
            self._cache.put(cache_key, result)

        return result

    async def aredact(
        self,
        text: str,
        *,
        countries: list[str] | None = None,
        mode: str = "rules",
        pseudonymize: bool = False,
        detect_dates: bool = False,
        coref: bool = False,
        coref_model: str = "default",
        cache: bool = True,
    ) -> RedactResult:
        """Async version of redact().

        Offloads the CPU-bound rule engine work to a thread pool so it
        doesn't block the event loop. Safe to call concurrently from
        multiple async tasks.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _DEFAULT_POOL,
            lambda: self.redact(
                text,
                countries=countries,
                mode=mode,
                pseudonymize=pseudonymize,
                detect_dates=detect_dates,
                coref=coref,
                coref_model=coref_model,
                cache=cache,
            ),
        )

    def redact_batch(
        self,
        texts: list[str],
        *,
        countries: list[str] | None = None,
        mode: str = "rules",
        pseudonymize: bool = False,
        detect_dates: bool = False,
        cache: bool = True,
    ) -> list[RedactResult]:
        """Redact PII from multiple texts.

        Processes all texts sequentially using the same engine state.
        More efficient than calling ``redact()`` in a loop because
        country configs are loaded once.

        Returns results in the same order as the input texts.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        return [
            self.redact(
                text,
                countries=countries,
                mode=mode,
                pseudonymize=pseudonymize,
                detect_dates=detect_dates,
                cache=cache,
            )
            for text in texts
        ]

    async def aredact_batch(
        self,
        texts: list[str],
        *,
        countries: list[str] | None = None,
        mode: str = "rules",
        pseudonymize: bool = False,
        detect_dates: bool = False,
        cache: bool = True,
        max_concurrency: int = 4,
    ) -> list[RedactResult]:
        """Async batch redaction with controlled concurrency.

        Processes texts concurrently using a thread pool. The
        ``max_concurrency`` parameter limits how many texts are
        processed in parallel (default 4).

        Returns results in the same order as the input texts.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _process(text: str) -> RedactResult:
            async with semaphore:
                return await self.aredact(
                    text,
                    countries=countries,
                    mode=mode,
                    pseudonymize=pseudonymize,
                    detect_dates=detect_dates,
                    cache=cache,
                )

        return await asyncio.gather(*[_process(t) for t in texts])

    def redact_iter(
        self,
        texts: Iterator[str],
        *,
        countries: list[str] | None = None,
        mode: str = "rules",
        pseudonymize: bool = False,
        detect_dates: bool = False,
        cache: bool = True,
    ) -> Iterator[RedactResult]:
        """Lazy iterator that yields results one at a time.

        Useful for processing large datasets without loading all results
        into memory at once.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        for text in texts:
            yield self.redact(
                text,
                countries=countries,
                mode=mode,
                pseudonymize=pseudonymize,
                detect_dates=detect_dates,
                cache=cache,
            )
