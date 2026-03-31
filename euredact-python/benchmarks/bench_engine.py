"""Performance benchmarks for the EuRedact rule engine.

Run with: python benchmarks/bench_engine.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import euredact


def _make_text(size: int) -> str:
    base = (
        "Naam: Jan de Vries, BSN 111222333, email jan@test.nl, "
        "IBAN NL91ABNA0417164300. Telefoon +31 6 12345678. "
        "Adres: Kerkstraat 42, 1234 AB Amsterdam. BTW: NL123456789B01. "
    )
    return (base * (size // len(base) + 1))[:size]


def bench_single_page():
    """Benchmark: single ~1,200 char document."""
    text = _make_text(1200)
    euredact._instance = None
    # Warm up
    euredact.redact(text, countries=["NL"], cache=False)

    N = 1000
    t0 = time.perf_counter()
    for _ in range(N):
        euredact.redact(text, countries=["NL"], cache=False)
    elapsed = time.perf_counter() - t0

    print(f"Single page ({len(text)} chars):")
    print(f"  {elapsed/N*1000:.2f} ms/call")
    print(f"  {N/elapsed:,.0f} calls/s")
    print(f"  {len(text)*N/elapsed:,.0f} chars/s")
    print()


def bench_batch():
    """Benchmark: batch of 1,000 texts."""
    texts = [_make_text(300) for _ in range(1000)]
    euredact._instance = None

    t0 = time.perf_counter()
    results = euredact.redact_batch(texts, countries=["NL"], cache=False)
    elapsed = time.perf_counter() - t0

    print(f"Batch (1,000 x {len(texts[0])} chars):")
    print(f"  {elapsed:.2f}s total")
    print(f"  {len(texts)/elapsed:,.0f} texts/s")
    print(f"  {sum(len(t) for t in texts)/elapsed:,.0f} chars/s")
    print()


def bench_countries_loaded():
    """Benchmark: all countries loaded vs single country."""
    text = _make_text(500)
    euredact._instance = None
    N = 500

    # Single country
    t0 = time.perf_counter()
    for _ in range(N):
        euredact.redact(text, countries=["NL"], cache=False)
    t_single = time.perf_counter() - t0

    euredact._instance = None

    # All countries
    t0 = time.perf_counter()
    for _ in range(N):
        euredact.redact(text, countries=None, cache=False)
    t_all = time.perf_counter() - t0

    print(f"Country loading ({N} calls, {len(text)} chars):")
    print(f"  Single country (NL): {t_single/N*1000:.2f} ms/call")
    print(f"  All 31 countries:    {t_all/N*1000:.2f} ms/call")
    print(f"  Overhead:            {(t_all/t_single - 1)*100:.0f}%")
    print()


def bench_cache_effect():
    """Benchmark: cache hit vs cache miss."""
    text = _make_text(500)
    euredact._instance = None
    N = 10000

    # With cache (second call hits cache)
    euredact.redact(text, countries=["NL"], cache=True)
    t0 = time.perf_counter()
    for _ in range(N):
        euredact.redact(text, countries=["NL"], cache=True)
    t_cached = time.perf_counter() - t0

    # Without cache
    euredact._instance = None
    t0 = time.perf_counter()
    for _ in range(N):
        euredact.redact(text, countries=["NL"], cache=False)
    t_uncached = time.perf_counter() - t0

    print(f"Cache effect ({N} calls, {len(text)} chars):")
    print(f"  Cached:   {t_cached/N*1000:.3f} ms/call ({N/t_cached:,.0f} calls/s)")
    print(f"  Uncached: {t_uncached/N*1000:.3f} ms/call ({N/t_uncached:,.0f} calls/s)")
    print(f"  Speedup:  {t_uncached/t_cached:.0f}x")
    print()


if __name__ == "__main__":
    print(f"EuRedact v{euredact.__version__}")
    print(f"Countries: {len(euredact.available_countries())}")
    print()
    bench_single_page()
    bench_batch()
    bench_countries_loaded()
    bench_cache_effect()
