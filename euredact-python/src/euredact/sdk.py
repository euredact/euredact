"""Orchestrator: runs the detection pipeline and applies replacements."""

from __future__ import annotations

import asyncio
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Iterator

from euredact.cache import ResultCache
from euredact.normalizer import map_offset_to_original, normalize
from euredact.rules.context import DocumentContext
from euredact.rules.engine import RuleEngine, check_country_arg
from euredact.rules.evidence import weights_to_ranking
from euredact.types import EntityType, RedactResult

# Date entity types — opt-in via detect_dates=True
_DATE_TYPES = frozenset({EntityType.DOB, EntityType.DATE_OF_DEATH})

# Default thread pool for async offloading
_DEFAULT_POOL = ThreadPoolExecutor()


class ReferentialMapper:
    """Maps real PII values to consistent labels within a session.

    Ensures referential integrity: the same input value always maps to
    the same label (e.g. ``EMAIL_1``), so relationships between
    occurrences are preserved in the redacted output.

    .. warning::
       The mapping is keyed on the **raw PII value** and is never evicted —
       evicting would hand a previously seen value a second label and quietly
       break the guarantee above. Two consequences worth designing around:

       * It grows for as long as the process runs. Call :meth:`clear` (or
         :meth:`EuRedact.clear`) between workloads; a warning is emitted once
         the mapping passes :data:`MAPPING_WARN_THRESHOLD` entries.
       * Labels are shared by every caller of the same instance — including
         every caller of the module-level :func:`euredact.redact`. A label
         repeated across two documents reveals that they contain the same
         underlying value, so give each tenant its own :class:`EuRedact`
         instance rather than sharing the module-level one.
    """

    #: Entry count at which a one-time warning is emitted.
    MAPPING_WARN_THRESHOLD = 100_000

    def __init__(self) -> None:
        self._counters: dict[EntityType, int] = {}
        self._mapping: dict[str, str] = {}
        self._warned = False

    def get_label(self, text: str, entity_type: EntityType | str) -> str:
        """Return consistent label. Same input always returns same output."""
        if text not in self._mapping:
            self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
            n = self._counters[entity_type]
            type_label = entity_type.value if isinstance(entity_type, EntityType) else entity_type
            self._mapping[text] = f"{type_label}_{n}"
            if not self._warned and len(self._mapping) > self.MAPPING_WARN_THRESHOLD:
                self._warned = True
                warnings.warn(
                    f"Referential integrity mapping holds "
                    f"{len(self._mapping)} raw PII values and is never evicted. "
                    f"Call clear() between workloads to release them.",
                    ResourceWarning,
                    stacklevel=2,
                )
        return self._mapping[text]

    def clear(self) -> None:
        """Remove all stored PII mappings from memory."""
        self._counters.clear()
        self._mapping.clear()


class EuRedact:
    """Main EuRedact SDK orchestrator."""

    DEFAULT_MAX_INPUT_LENGTH = 10_485_760  # ~10 MB of text

    def __init__(self, *, max_input_length: int = DEFAULT_MAX_INPUT_LENGTH) -> None:
        self._engine = RuleEngine()
        self._cache = ResultCache()
        self._referential_mapper = ReferentialMapper()
        self._max_input_length = max_input_length

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Register a custom regex pattern detected as *name*."""
        self._engine.add_custom_pattern(name, pattern)
        self._cache.clear()

    def clear(self) -> None:
        """Clear the result cache and referential integrity mappings.

        Call this in long-running processes to free PII from memory.
        The cache and mapper will be rebuilt as new texts are processed.
        """
        self._cache.clear()
        self._referential_mapper.clear()

    def redact(
        self,
        text: str,
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        context: DocumentContext | None = None,
        chunk_offset: int = 0,
        mode: str = "rules",
        referential_integrity: bool = False,
        detect_dates: bool = False,
        coref: bool = False,
        coref_model: str = "default",
        cache: bool = True,
    ) -> RedactResult:
        """Redact PII from text. Main entry point.

        Args:
            countries: Scope. Detections attributed elsewhere are flagged
                ``out_of_scope``, never dropped, and this also acts as a prior
                when resolving which national scheme owns an ambiguous value.
            country_hint: A prior only. Helps resolve ambiguity without
                narrowing scope or flagging anything out of scope. Neither
                argument gates what is looked for — see
                ``tests/test_invariant_generation.py``.
            context: Shares country evidence across the chunks of one
                document, so a chunk carrying no country signal of its own is
                still scored against what the rest of the document showed.
                Pass the same object for every chunk, with *chunk_offset* set
                to where the chunk starts in the whole document.
            chunk_offset: Offset of this chunk within the document. Used only
                to rebase spans recorded in *context*; the returned detections
                are always relative to *text*.
            detect_dates: Include date-of-birth / date-of-death detections.
                Off by default — bare dates without strong indicators are
                better handled by the cloud LLM tier. When True, the rule
                engine applies keyword and structural (JSON/CSV header)
                checks before emitting a date detection.
        """
        # Step 0: argument and input-size guards. The country check runs here
        # as well as in the engine so that a bare string is rejected before any
        # work happens, and on every entry point that funnels through redact().
        check_country_arg(countries, "countries")
        check_country_arg(country_hint, "country_hint")

        if len(text) > self._max_input_length:
            raise ValueError(
                f"Input text length ({len(text):,} chars) exceeds the maximum "
                f"({self._max_input_length:,} chars). Split the input or "
                f"increase max_input_length when constructing EuRedact."
            )

        # Step 1: Normalize
        normalized_text, offset_mapping = normalize(text)

        # Step 2: Check cache
        countries_tuple = tuple(sorted(c.upper() for c in countries)) if countries else ("ALL",)
        # country_hint changes attribution, so it must key the cache too.
        hint_key = ",".join(sorted(c.upper() for c in country_hint)) if country_hint else ""
        cache_mode = f"{mode}|dates={detect_dates}|hint={hint_key}"
        # A context makes the result depend on evidence from other chunks, so
        # the text no longer identifies the result. Caching is disabled rather
        # than keyed on the context, whose contents change as chunks arrive.
        if context is not None:
            cache = False
        if cache:
            cache_key = self._cache.key(normalized_text, countries_tuple, cache_mode)
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # Steps 3-6: Rule engine detection
        detections, evidence, country_scores = self._engine.detect_with_evidence(
            normalized_text, countries, country_hint,
            prior_evidence=context.evidence() if context is not None else None,
        )
        if context is not None:
            context.add(evidence, chunk_offset)

        # Map offsets back to original text if normalization changed length
        if offset_mapping is not None:
            # replace() rather than a field-by-field rebuild: this listed every
            # field explicitly and so silently dropped any new one, which is
            # how out_of_scope and country_confidence would have been lost on
            # exactly the inputs that need normalising.
            detections = [
                replace(
                    d,
                    start=map_offset_to_original(d.start, offset_mapping),
                    end=map_offset_to_original(d.end, offset_mapping),
                )
                for d in detections
            ]

        # Filter date types unless opted in
        if not detect_dates:
            detections = [d for d in detections if d.entity_type not in _DATE_TYPES]

        # Steps 7-13: [CLOUD EXTENSION] — no-ops in rules-only mode

        # Step 14: Sort detections by position
        detections.sort(key=lambda d: (d.start, -d.end))

        # Step 15: Apply replacements.
        #
        # Labels are resolved right-to-left because the referential mapper
        # numbers each entity type in call order, and that order is part of the
        # output contract. The string itself is then assembled in a single
        # forward pass: rebuilding it per detection copied the whole document
        # each time, which is O(document x detections) — 268 ms of pure copying
        # on a 1 MB document with 8,000 detections, versus 0.7 ms here.
        replacements: list[str] = [""] * len(detections)
        for idx in range(len(detections) - 1, -1, -1):
            det = detections[idx]
            if referential_integrity:
                replacements[idx] = self._referential_mapper.get_label(
                    det.text, det.entity_type
                )
            else:
                label = det.entity_type.value if isinstance(det.entity_type, EntityType) else det.entity_type
                replacements[idx] = f"[{label}]"

        parts: list[str] = []
        pos = 0
        for det, replacement in zip(detections, replacements):
            # Spans reach here deduplicated and non-overlapping; a span that
            # starts behind the cursor would silently corrupt the output, so
            # drop it rather than splice it into the middle of a label.
            if det.start < pos:
                continue
            parts.append(text[pos : det.start])
            parts.append(replacement)
            pos = det.end
        parts.append(text[pos:])
        redacted = "".join(parts)

        # Step 16: [COREF EXTENSION] — no-op

        # Report the inference so it can be audited. Spans in `evidence` are
        # offsets into the normalised text, matching `detections`.
        ranked = sorted(
            weights_to_ranking(country_scores).items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        result = RedactResult(
            redacted_text=redacted,
            detections=detections,
            source="rules",
            degraded=False,
            inferred_countries=tuple(ranked),
            evidence=tuple(evidence),
            detection_mode="declared" if countries else "inferred",
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
        country_hint: list[str] | None = None,
        context: DocumentContext | None = None,
        chunk_offset: int = 0,
        mode: str = "rules",
        referential_integrity: bool = False,
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
                country_hint=country_hint,
                context=context,
                chunk_offset=chunk_offset,
                mode=mode,
                referential_integrity=referential_integrity,
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
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
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
                country_hint=country_hint,
                mode=mode,
                referential_integrity=referential_integrity,
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
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
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
                    country_hint=country_hint,
                    mode=mode,
                    referential_integrity=referential_integrity,
                    detect_dates=detect_dates,
                    cache=cache,
                )

        return await asyncio.gather(*[_process(t) for t in texts])

    def redact_iter(
        self,
        texts: Iterator[str],
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
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
                country_hint=country_hint,
                mode=mode,
                referential_integrity=referential_integrity,
                detect_dates=detect_dates,
                cache=cache,
            )
