"""Concurrent detection must never lose a span to a concurrent registration.

`add_custom_pattern` rebuilds the matcher's scan structures. Scans deliberately
run without the engine lock so that concurrent `detect()` calls do not
serialise, so the rebuild has to be published atomically. When the structures
were rebuilt in place instead, a scan racing the rebuild could zip a fresh
slot list against a stale pattern list, truncate to the shorter of the two and
skip patterns — returning fewer detections with no error raised. A redaction
tool that silently drops PII under load is the failure this whole codebase is
arranged to prevent, so it gets an explicit test.
"""

from __future__ import annotations

import threading

import pytest

from euredact.rules.engine import RuleEngine

# Every line carries an email and an IBAN, both from the SHARED country config
# and therefore unaffected by anything the writer thread registers.
DOC = "\n".join(
    f"Contact user{i}@example.com about NL91ABNA0417164300 today." for i in range(40)
)


def _baseline_spans() -> set[tuple[int, int]]:
    engine = RuleEngine()
    return {(d.start, d.end) for d in engine.detect(DOC)}


def test_detect_loses_nothing_while_patterns_are_registered() -> None:
    baseline = _baseline_spans()
    assert baseline, "fixture must produce detections for the test to mean anything"

    engine = RuleEngine()
    engine.detect(DOC)  # force the initial compile before the race starts

    missing: list[set[tuple[int, int]]] = []
    stop = threading.Event()
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            while not stop.is_set():
                spans = {(d.start, d.end) for d in engine.detect(DOC)}
                dropped = baseline - spans
                if dropped:
                    missing.append(dropped)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion
            errors.append(exc)

    def writer() -> None:
        try:
            for i in range(60):
                if stop.is_set():
                    break
                engine.add_custom_pattern(f"CUSTOM_{i}", rf"\bZZ{i}[0-9]{{4}}\b")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(6)]
    for t in readers:
        t.start()
    w = threading.Thread(target=writer)
    w.start()
    w.join()
    stop.set()
    for t in readers:
        t.join()

    assert not errors, f"worker raised: {errors[0]!r}"
    assert not missing, (
        f"{len(missing)} scan(s) lost spans that a quiet engine finds; "
        f"first loss: {sorted(missing[0])[:5]}"
    )


def test_concurrent_referential_labels_are_never_shared() -> None:
    """aredact labels from pool threads. Without a lock two new values could
    read the same counter and get the same label, which says they are one
    value: 11,656 duplicates over 30 runs before the fix (rules-engine#150)."""
    import sys

    from euredact.sdk import ReferentialMapper
    from euredact.types import EntityType

    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for _ in range(5):
            mapper = ReferentialMapper()

            def work(k: int) -> None:
                for i in range(300):
                    mapper.get_label(f"v{k}-{i}@example.be", EntityType.EMAIL)

            threads = [threading.Thread(target=work, args=(k,)) for k in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            labels = list(mapper._mapping.values())
            assert len(labels) == len(set(labels)) == 2400
    finally:
        sys.setswitchinterval(interval)


_FIRST_CALL_SCRIPT = r"""
import sys, threading
import euredact
from euredact import EuRedact
per_tenant = sys.argv[1] == "instances"
N = 16
DOC = ("Ring Jo Bloggs on 07700 900123, post code SW1A 1AA. Pay GB33BUKB20201555555555, "
       "NI number QQ 12 34 56 C. Ref 12345 67890 and VAT GB123456789. ") * 3
barrier = threading.Barrier(N)
out = [None] * N
def work(i):
    barrier.wait()   # every thread's FIRST call, at once
    sdk = EuRedact() if per_tenant else euredact
    r = sdk.redact(DOC, countries=["GB"])
    out[i] = tuple(sorted((d.start, d.end, str(d.entity_type)) for d in r.detections))
threads = [threading.Thread(target=work, args=(i,)) for i in range(N)]
for t in threads: t.start()
for t in threads: t.join()
print(len(set(out)), len(out[0]))
"""


@pytest.mark.parametrize("how", ["default-instance", "instances"])
def test_concurrent_first_calls_print_nothing_and_agree(how) -> None:
    """With [fast], threads making their first call together printed hundreds
    of re2 "Error parsing" lines: each built its own instance, and their
    process-wide stderr swaps interleaved (rules-engine#157). A fresh process,
    because only the first call shows it; the test above warms up first."""
    import subprocess
    import sys
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src"
    run = subprocess.run(
        [sys.executable, "-c", _FIRST_CALL_SCRIPT, how], capture_output=True, text=True,
        timeout=300, env={**__import__("os").environ, "PYTHONPATH": str(src)})
    assert run.returncode == 0, run.stderr
    assert run.stderr == ""
    distinct, spans = run.stdout.split()
    assert distinct == "1" and int(spans) > 0
