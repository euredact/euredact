"""EuRedact -- European PII redaction SDK.

Quick start::

    import euredact

    result = euredact.redact("Jan Janssens, BSN 123456782, woont in Gent.")
    print(result.redacted_text)
    print(result.detections)

    # Batch processing:
    results = euredact.redact_batch(["text one", "text two"], countries=["NL"])

    # Async:
    result = await euredact.aredact("some text")

    # Available countries:
    print(euredact.available_countries())  # ['AT', 'BE', 'DE', 'NL', ...]
"""

from __future__ import annotations

from typing import Iterator

__version__ = "0.2.0"

from euredact.sdk import EuRedact
from euredact.types import Detection, DetectionSource, EntityType, RedactResult

__all__ = [
    "__version__",
    "add_custom_pattern",
    "aredact",
    "aredact_batch",
    "available_countries",
    "Detection",
    "DetectionSource",
    "EntityType",
    "EuRedact",
    "redact",
    "redact_batch",
    "redact_iter",
    "RedactResult",
]

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instance: EuRedact | None = None


def _get_instance() -> EuRedact:
    global _instance
    if _instance is None:
        _instance = EuRedact()
    return _instance


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def add_custom_pattern(name: str, pattern: str) -> None:
    """Register a custom regex pattern detected as *name*."""
    _get_instance().add_custom_pattern(name, pattern)


def available_countries() -> list[str]:
    """Return a sorted list of supported country codes (e.g. ``['AT', 'BE', ...]``)."""
    from euredact.rules.registry import CountryRegistry
    return CountryRegistry().available_countries


def redact(
    text: str,
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
    detect_dates: bool = False,
    coref: bool = False,
    coref_model: str = "default",
    cache: bool = True,
) -> RedactResult:
    """Redact PII from text. Main entry point.

    Args:
        detect_dates: Include date-of-birth / date-of-death detections.
            Off by default -- bare dates are better handled by the cloud
            LLM tier. When True, the rule engine applies keyword and
            structural (JSON/CSV header) checks before emitting a date.
    """
    return _get_instance().redact(
        text,
        countries=countries,
        mode=mode,
        referential_integrity=referential_integrity,
        detect_dates=detect_dates,
        coref=coref,
        coref_model=coref_model,
        cache=cache,
    )


async def aredact(
    text: str,
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
) -> RedactResult:
    """Async version of redact().

    Offloads CPU-bound work to a thread pool so it doesn't block the
    event loop. Safe to ``await`` from multiple concurrent tasks.
    """
    return await _get_instance().aredact(
        text,
        countries=countries,
        mode=mode,
        referential_integrity=referential_integrity,
        detect_dates=detect_dates,
        cache=cache,
    )


def redact_batch(
    texts: list[str],
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
) -> list[RedactResult]:
    """Redact PII from multiple texts at once.

    More efficient than calling ``redact()`` in a loop -- loads country
    configs once. Returns results in the same order as the input.
    """
    return _get_instance().redact_batch(
        texts,
        countries=countries,
        mode=mode,
        referential_integrity=referential_integrity,
        detect_dates=detect_dates,
        cache=cache,
    )


async def aredact_batch(
    texts: list[str],
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
    max_concurrency: int = 4,
) -> list[RedactResult]:
    """Async batch redaction with controlled concurrency.

    Processes texts concurrently in a thread pool. ``max_concurrency``
    limits parallel threads (default 4). Returns results in input order.
    """
    return await _get_instance().aredact_batch(
        texts,
        countries=countries,
        mode=mode,
        referential_integrity=referential_integrity,
        detect_dates=detect_dates,
        cache=cache,
        max_concurrency=max_concurrency,
    )


def redact_iter(
    texts: Iterator[str],
    *,
    countries: list[str] | None = None,
    mode: str = "rules",
    referential_integrity: bool = False,
    detect_dates: bool = False,
    cache: bool = True,
) -> Iterator[RedactResult]:
    """Lazy iterator that yields results one at a time.

    Useful for processing large datasets without loading all results
    into memory. Loads country configs once on the first item.
    """
    return _get_instance().redact_iter(
        texts,
        countries=countries,
        mode=mode,
        referential_integrity=referential_integrity,
        detect_dates=detect_dates,
        cache=cache,
    )
