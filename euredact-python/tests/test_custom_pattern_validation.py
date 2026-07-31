"""The custom-pattern ReDoS screen.

The screen used to be a single regex looking for the literal spelling `+)+`,
so every other shape of catastrophic backtracking walked straight through it
while the error message promised the pattern had been checked. These are the
shapes that used to pass and then run exponentially.
"""

from __future__ import annotations

import pytest

from euredact.rules.engine import RuleEngine, _validate_custom_pattern

# Each of these was accepted by the old screen. `(a|a)+$` took 1.99 s on a
# 24-character input and doubled with every added character.
CATASTROPHIC = [
    r"(?:a+)+b",        # the one shape the old screen did catch
    r"(a|a)+$",
    r"(a|ab)+c",
    r"(\d|\d\d)+$",
    r"(a{1,10})+$",
    r"^(\w+\s?)*$",
    r"(x*)*y",
    r"([0-9]|[0-9][0-9])+$",
]

# Ordinary patterns a user would reasonably register. None may be rejected.
BENIGN = [
    r"\bACME-\d{4}\b",
    r"(?:foo|bar)",
    r"(A|B)+",                  # distinct branches: unambiguous
    r"([0-9]|[a-z])+",          # disjoint classes: unambiguous
    r"\b[A-Z]{2}\d{6}\b",
    r"(?:INV|ORD)-\d{2,8}",
    r"(?i:case)-\d+",
    r"colou?r",
    r"(?P<id>[A-Z]+)\d+",
    r"(ab)+",
    r"[A-Z]+\d{1,3}",
]


@pytest.mark.parametrize("pattern", CATASTROPHIC)
def test_catastrophic_patterns_are_rejected(pattern: str) -> None:
    with pytest.raises(ValueError, match="backtracking"):
        _validate_custom_pattern(pattern)


@pytest.mark.parametrize("pattern", BENIGN)
def test_ordinary_patterns_are_accepted(pattern: str) -> None:
    _validate_custom_pattern(pattern)


def test_invalid_syntax_still_reported_separately() -> None:
    with pytest.raises(ValueError, match="Invalid regex"):
        _validate_custom_pattern(r"(unclosed")


def test_rejection_happens_before_registration() -> None:
    engine = RuleEngine()
    with pytest.raises(ValueError):
        engine.add_custom_pattern("EVIL", r"(a|a)+$")
    # The rejected pattern must not have been added to the matcher.
    assert all(
        code != "CUSTOM" for _c, _p, code in engine._matcher._patterns
    ), "a rejected pattern was registered anyway"


def test_accepted_custom_pattern_still_detects() -> None:
    engine = RuleEngine()
    engine.add_custom_pattern("TICKET", r"\bTCK-\d{5}\b")
    found = engine.detect("Please see TCK-12345 for details.")
    assert any(d.entity_type == "TICKET" for d in found)
