"""Shared conformance suite — the same vectors run against the TypeScript SDK.

``conformance/vectors.json`` at the repository root is language-neutral: input
plus expected detections, no Python or JavaScript detail. Both SDKs run it, so
a behavioural difference between them fails a test instead of going unnoticed
until someone diffs two corpora.

The TypeScript side is ``euredact-ts/src/__tests__/conformance.ts``. When you
add a case here, both suites pick it up automatically.
"""

import json
from pathlib import Path

import pytest

from euredact.sdk import EuRedact
from euredact.types import EntityType

VECTORS_PATH = Path(__file__).resolve().parents[2] / "conformance" / "vectors.json"


def _load() -> list[dict]:
    if not VECTORS_PATH.exists():  # pragma: no cover - repository layout guard
        pytest.skip(f"conformance vectors not found at {VECTORS_PATH}")
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["cases"]


CASES = _load()


@pytest.fixture(scope="module")
def conformance_sdk():
    return EuRedact()


# Vector options are spelled as in the TypeScript RedactOptions; this maps
# them onto the Python keyword names.
_OPTION_NAMES = {"allowlist": "allowlist"}


def _redact(sdk, case):
    options = {_OPTION_NAMES[k]: v for k, v in (case.get("options") or {}).items()}
    return sdk.redact(
        case["text"],
        countries=case.get("countries"),
        detect_dates=True,
        cache=False,
        **options,
    )


def _detections_by_type(result) -> dict[str, list[str]]:
    by_type: dict[str, list[str]] = {}
    for d in result.detections:
        etype = d.entity_type.value if isinstance(d.entity_type, EntityType) else d.entity_type
        by_type.setdefault(etype, []).append(d.text)
    return by_type


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_conformance_vector(conformance_sdk, case):
    result = _redact(conformance_sdk, case)
    got = _detections_by_type(result)

    if "expectRedactedText" in case:
        assert result.redacted_text == case["expectRedactedText"], (
            f"{case['id']}: redacted text {result.redacted_text!r}"
        )

    for etype in case.get("mustNotDetect", []):
        assert got.get(etype, []) == [], (
            f"{case['id']}: expected no {etype}, got {got.get(etype)}"
        )

    for etype, expected in (case.get("mustDetect") or {}).items():
        assert got.get(etype, []) == expected, (
            f"{case['id']}: {etype} expected {expected}, got {got.get(etype, [])}"
        )


def test_vector_ids_are_unique():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))


def test_every_case_asserts_something():
    """A case with neither expectation would pass silently and prove nothing."""
    for c in CASES:
        assert (
            c.get("mustDetect") or c.get("mustNotDetect") or "expectRedactedText" in c
        ), f"{c['id']} asserts nothing"
