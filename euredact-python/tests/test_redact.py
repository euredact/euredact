"""Integration tests: full pipeline."""

import euredact
from euredact.types import EntityType


class TestMultiCountry:
    def test_dutch_and_belgian_pii(self):
        text = (
            "Jan heeft BSN 111222333 en woont in België. "
            "Zijn Belgische IBAN is BE68 5390 0754 7034."
        )
        result = euredact.redact(text, countries=["NL", "BE"])
        types = {d.entity_type for d in result.detections}
        assert EntityType.NATIONAL_ID in types
        assert EntityType.IBAN in types

    def test_all_countries(self):
        text = "Contact: jan@example.com, +31 6 12345678"
        result = euredact.redact(text)
        types = {d.entity_type for d in result.detections}
        assert EntityType.EMAIL in types
        assert EntityType.PHONE in types


class TestRedactionOutput:
    def test_default_tags(self):
        result = euredact.redact(
            "Email: jan@example.com", countries=["NL"]
        )
        assert "[EMAIL]" in result.redacted_text
        assert "jan@example.com" not in result.redacted_text

    def test_referential_integrity(self):
        result = euredact.redact(
            "Email: jan@example.com en piet@example.com",
            countries=["NL"],
            referential_integrity=True,
        )
        assert "EMAIL_1" in result.redacted_text
        assert "EMAIL_2" in result.redacted_text

    def test_referential_integrity_consistency(self):
        result = euredact.redact(
            "jan@example.com en later jan@example.com opnieuw.",
            countries=["NL"],
            referential_integrity=True,
        )
        # Same email should get same label (whatever counter value)
        dets = result.detections
        assert len(dets) == 2
        # Both should have been replaced with the same label
        label = result.redacted_text.split(" en later ")[0]
        assert label.startswith("EMAIL_")
        assert result.redacted_text.count(label) == 2

    def test_source_is_rules(self):
        result = euredact.redact("Test", countries=["NL"])
        assert result.source == "rules"
        assert result.degraded is False


class TestDetectionPositions:
    def test_positions_correct(self):
        text = "IBAN: NL91ABNA0417164300 hier."
        result = euredact.redact(text, countries=["NL"])
        for det in result.detections:
            assert text[det.start : det.end] == det.text


class TestSuppressionFilters:
    def test_currency_context_suppressed(self):
        result = euredact.redact("Het kost 0612345678 EUR.", countries=["NL"])
        # This should be suppressed as currency context
        phone_dets = [d for d in result.detections if d.entity_type == EntityType.PHONE]
        assert len(phone_dets) == 0

    def test_reference_context_suppressed(self):
        result = euredact.redact(
            "Factuurnummer: 111222333.", countries=["NL"]
        )
        # Should be suppressed — reference number context
        assert not any(d.entity_type == EntityType.NATIONAL_ID for d in result.detections)


class TestCache:
    def test_cache_hit(self):
        text = "Email: test@example.com"
        r1 = euredact.redact(text, countries=["NL"])
        r2 = euredact.redact(text, countries=["NL"])
        assert r1.redacted_text == r2.redacted_text

    def test_cache_disabled(self):
        text = "Email: test@example.com"
        r1 = euredact.redact(text, countries=["NL"], cache=False)
        assert "[EMAIL]" in r1.redacted_text


class TestEmptyInput:
    def test_empty_string(self):
        result = euredact.redact("", countries=["NL"])
        assert result.redacted_text == ""
        assert result.detections == []

    def test_no_pii(self):
        result = euredact.redact("Dit is een gewone zin.", countries=["NL"])
        assert result.redacted_text == "Dit is een gewone zin."
        assert result.detections == []
