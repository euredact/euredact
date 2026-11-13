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

    def test_offsets_are_mapped_when_nfc_keeps_the_length(self):
        # A composition (e + U+0301 -> é, one shorter) and an expansion (U+0958,
        # one longer) cancel out in the length. The mapping used to be skipped,
        # and every character between them was one place off (rules-engine#150).
        text = "Café jan@example.be क़"
        result, mapping = normalize(text)
        assert len(result) == len(text) and result != text
        assert mapping is not None
        at = result.index("jan@")
        assert text[mapping[at]:mapping[at] + 4] == "jan@"

    def test_digits_are_folded_to_ascii_one_for_one(self):
        result, mapping = normalize("Tel ０６１２３４５６７８ / ٠١٢٣")
        assert result == "Tel 0612345678 / 0123"
        assert mapping is None

    def test_digits_outside_the_bmp_are_left_alone(self):
        # Two UTF-16 units in the TypeScript SDK: folding them would move every
        # offset after them there, so neither SDK does.
        text = "\U0001D7D8\U0001D7D9"  # mathematical double-struck 0, 1
        assert normalize(text) == (text, None)


def test_the_digit_table_is_every_bmp_decimal_run():
    import unicodedata

    from euredact.normalizer import _DIGIT_ZEROS
    found = tuple(cp for cp in range(0x80, 0x10000)
                  if unicodedata.category(chr(cp)) == "Nd" and unicodedata.decimal(chr(cp)) == 0)
    # This Python's Unicode may be newer than the table; it must not be older.
    assert set(_DIGIT_ZEROS) <= set(found)
    for zero in _DIGIT_ZEROS:
        assert [unicodedata.decimal(chr(zero + k)) for k in range(10)] == list(range(10))
