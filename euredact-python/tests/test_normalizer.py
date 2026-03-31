"""Tests for Unicode normalizer."""

from euredact.normalizer import normalize


class TestNormalize:
    def test_nfc_passthrough(self):
        text = "Hello World"
        result, mapping = normalize(text)
        assert result == text
        assert mapping is None

    def test_nfc_composition(self):
        # e + combining acute accent -> é
        decomposed = "e\u0301"
        result, mapping = normalize(decomposed)
        assert result == "\u00e9"  # é as single codepoint
        assert len(result) == 1

    def test_already_nfc(self):
        text = "café"
        result, mapping = normalize(text)
        assert result == "café"
        assert mapping is None
