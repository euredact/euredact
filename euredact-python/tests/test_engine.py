"""Rule engine unit tests."""

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
