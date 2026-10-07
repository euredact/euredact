"""The regression records hold: see tests/regression_corpus.py.

The same records are written into the corpus by `make regression-corpus`, where
eval, sweep and parity see them; here they are a gate that needs no corpus.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from regression_corpus import TEMPLATES, build, check  # noqa: E402


def test_every_regression_record_holds():
    failures = check(build())
    assert not failures, f"{len(failures)} failures:\n" + "\n".join(failures[:25])


def test_the_records_are_deterministic():
    assert build() == build()


def test_every_template_produces_records():
    names = {r["regression"] for r in build()}
    assert names == {name for name, _ in TEMPLATES}
