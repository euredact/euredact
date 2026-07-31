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
