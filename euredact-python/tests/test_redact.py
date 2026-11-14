"""Integration tests: full pipeline."""

import pytest

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
        # Own instance: the module-level mapper is shared with every other
        # test that labels through euredact.redact(), and its counters carry
        # over. The result cache used to hide that by serving this call the
        # bracketed result of an earlier plain call on the same text.
        result = euredact.EuRedact().redact(
            "Email: jan@example.com en piet@example.com",
            countries=["NL"],
            referential_integrity=True,
        )
        assert "EMAIL_1" in result.redacted_text
        assert "EMAIL_2" in result.redacted_text

    def test_referential_integrity_is_not_served_from_a_plain_cache_hit(self):
        sdk = euredact.EuRedact()
        text = "Email: jan@example.com en piet@example.com"
        plain = sdk.redact(text, countries=["NL"])
        labelled = sdk.redact(text, countries=["NL"], referential_integrity=True)
        assert plain.redacted_text == "Email: [EMAIL] en [EMAIL]"
        assert "EMAIL_1" in labelled.redacted_text
        assert "EMAIL_2" in labelled.redacted_text

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

    @pytest.mark.parametrize("text, expected", [
        ("Mail jose\u0301@x.be of jos\u00e9@x.be", "Mail EMAIL_1 of EMAIL_1"),
        ("Bel 0612345678 of \uff10\uff16\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18",
         "Bel PHONE_1 of PHONE_1"),
    ], ids=["nfd-and-nfc", "ascii-and-full-width-digits"])
    def test_referential_integrity_labels_a_value_once_however_it_is_spelled(self, text, expected):
        """Since a detection's text is the document's (#150), the mapper keyed
        on it gave two spellings of one value two labels (rules-engine#159)."""
        result = euredact.EuRedact().redact(
            text, countries=["NL"], referential_integrity=True, cache=False)
        assert result.redacted_text == expected

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


def test_an_empty_matching_custom_pattern_next_to_an_emoji():
    """The TypeScript SDK hung on this input (rules-engine#151); both SDKs
    must answer it the same way."""
    from euredact import EuRedact
    sdk = EuRedact()
    sdk.add_custom_pattern("ORDER_REF", r"(?:ORD-)?\d*")
    assert sdk.redact("order ORD-123 ok \U0001F44D", cache=False).redacted_text == "order [ORDER_REF] ok \U0001F44D"
