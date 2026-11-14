"""Rule engine unit tests."""

import pytest

from euredact.rules.engine import RuleEngine
from euredact.types import EntityType


class TestRuleEngine:
    def test_load_single_country(self):
        engine = RuleEngine()
        engine.load_countries(["NL"])
        assert "NL" in engine.loaded_countries

    def test_load_all_countries(self):
        engine = RuleEngine()
        engine.load_countries()
        assert "NL" in engine.loaded_countries
        assert "BE" in engine.loaded_countries
        assert "DE" in engine.loaded_countries

    def test_detect_email(self):
        engine = RuleEngine()
        engine.load_countries(["NL"])
        dets = engine.detect("test@example.com", ["NL"])
        assert any(d.entity_type == EntityType.EMAIL for d in dets)

    def test_detect_multiple_types(self):
        engine = RuleEngine()
        text = "BSN 111222333, email test@example.com"
        dets = engine.detect(text, ["NL"])
        types = {d.entity_type for d in dets}
        assert EntityType.NATIONAL_ID in types
        assert EntityType.EMAIL in types

    def test_deduplication(self):
        engine = RuleEngine()
        # Same text, same position should be deduplicated
        dets = engine.detect("test@example.com", ["NL", "BE"])
        email_dets = [d for d in dets if d.entity_type == EntityType.EMAIL]
        assert len(email_dets) == 1


@pytest.mark.parametrize("separator", ["\n", "; "], ids=["one-per-line", "one-line"])
def test_time_grows_linearly_on_text_dense_with_phone_numbers(separator):
    """A list of phone numbers took quadratic time: 115 s for 117 KB with one
    number per line, 127 s for 125 KB on one line (rules-engine#150). Four
    times the text must take well under the sixteen times a quadratic pass
    needs; the threshold leaves room for timing noise."""
    import time

    from euredact import EuRedact

    sdk = EuRedact()
    sdk.redact("warm-up", countries=["NL"], cache=False)

    def seconds(n: int) -> float:
        text = ("Tel 0612345678" + separator) * n
        best = float("inf")
        for _ in range(2):
            start = time.perf_counter()
            sdk.redact(text, countries=["NL"], cache=False)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = seconds(500), seconds(2000)
    assert large / small < 8, f"{small:.2f}s -> {large:.2f}s"


def test_the_line_memos_do_not_outlive_the_call():
    """The account-run and column-header memos are module globals. They held
    the last document, IBAN and phone included, after the call and after
    clear(), whose docstring promises to free PII (rules-engine#159)."""
    from euredact import EuRedact
    from euredact.rules import suppressors

    text = "naam | iban\nJan | NL91ABNA0417164300 tel 0612345678\n"
    EuRedact().redact(text, countries=["NL"], cache=False)
    held = [suppressors._ACCOUNT_RUNS_MEMO[0], suppressors._COLUMN_MEMO[0]]
    assert text not in held
    assert all("NL91ABNA0417164300" not in h for h in held)
