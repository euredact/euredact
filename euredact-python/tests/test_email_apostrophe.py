"""An apostrophe in an email local part, and the cost of allowing it.

The leak (issue rules-engine#10): the local-part class had no apostrophe, so
`johno'neill@outlook.ie` matched only from `neill` and masked as
`johno'[EMAIL]`, leaving the surname in the clear. 1,415 corpus entities.

The trap: the obvious fixes both fail in their own direction. Putting `'` in
the character class lets the match absorb a quote belonging to the surrounding
text (the defect of rules-engine#3). Allowing it between word characters but
leaving the start guard alone turns every apostrophe into a fresh start offset,
and the scan goes quadratic — 64 KB of `x'x'x'...` took 12.8 s, which is the
blowup the lookbehind in that pattern exists to prevent in the first place.

The timing test below is the regression that pins the second half of that.
"""
from __future__ import annotations

import time

import pytest

import euredact
from euredact.types import EntityType


@pytest.fixture
def sdk():
    return euredact.EuRedact()


class TestApostropheIsPartOfTheAddress:
    @pytest.mark.parametrize("text,address", [
        ("Contact johno'neill@outlook.ie today", "johno'neill@outlook.ie"),
        ("Mail aoife_o'sullivan@eircom.net", "aoife_o'sullivan@eircom.net"),
        ("From: siobhan.o'connor@yahoo.ie", "siobhan.o'connor@yahoo.ie"),
        ("cc padraig_o'murchu@gmail.com here", "padraig_o'murchu@gmail.com"),
    ])
    def test_the_whole_address_is_one_span(self, sdk, text, address):
        result = sdk.redact(text, countries=["IE"])
        assert [d.text for d in result.detections] == [address]
        assert address not in result.redacted_text
        assert "'" not in result.redacted_text, "the surname prefix survived"

    def test_several_in_one_document(self, sdk):
        text = "From: siobhano'connor@yahoo.ie To: padraig_o'neill@x.ie"
        result = sdk.redact(text, countries=["IE"])
        assert result.redacted_text == "From: [EMAIL] To: [EMAIL]"


class TestSurroundingPunctuationStaysOut:
    """The other direction: an apostrophe that belongs to the text, not the
    address. Absorbing it would repeat rules-engine#3."""

    @pytest.mark.parametrize("text,expected", [
        ("config: 'john@x.ie' set", "config: '[EMAIL]' set"),
        ("'o'neill@x.ie'", "'[EMAIL]'"),
        ("don't mail john@x.ie please", "don't mail [EMAIL] please"),
        ("O'Brien's address is jan@x.ie", "O'Brien's address is [EMAIL]"),
    ])
    def test_quotes_and_possessives_are_preserved(self, sdk, text, expected):
        assert sdk.redact(text, countries=["IE"]).redacted_text == expected

    def test_a_quoted_address_is_still_detected(self, sdk):
        """Refusing to start after `<word>'` must not lose the quoted form,
        where the apostrophe follows a non-word character."""
        result = sdk.redact("config: 'john@x.ie' set", countries=["IE"])
        assert [d.text for d in result.detections] == ["john@x.ie"]


class TestOrdinaryAddressesAreUnaffected:
    @pytest.mark.parametrize("text,address", [
        ("plain jan@example.com", "jan@example.com"),
        ("tag jan+news@example.com", "jan+news@example.com"),
        ("dots a.b.c@example.co.uk", "a.b.c@example.co.uk"),
        ("under jan_de_vries@example.nl", "jan_de_vries@example.nl"),
    ])
    def test_unchanged(self, sdk, text, address):
        result = sdk.redact(text, countries=["NL"])
        assert [d.text for d in result.detections] == [address]
        assert result.detections[0].entity_type == EntityType.EMAIL


class TestNoQuadraticBacktracking:
    """A run of word characters and apostrophes with no `@` must not be
    scanned repeatedly. Before the second lookbehind this was O(n^2): 4 KB
    took 48 ms, 16 KB 742 ms, 64 KB 12.8 s."""

    def test_a_long_apostrophe_run_stays_linear(self, sdk):
        small = "x'" * 8_000 + " end"
        large = "x'" * 64_000 + " end"          # 8x the input

        t0 = time.perf_counter()
        sdk.redact(small, countries=["IE"], cache=False)
        small_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        sdk.redact(large, countries=["IE"], cache=False)
        large_s = time.perf_counter() - t0

        # Linear would be ~8x. Quadratic would be ~64x. A generous ceiling
        # keeps this from flaking on a loaded machine while still failing
        # decisively on the old pattern, which was ~250x here.
        assert large_s < max(small_s * 24, 2.0), (
            f"scan looks superlinear: {small_s*1000:.0f} ms -> {large_s*1000:.0f} ms"
        )

    def test_an_apostrophe_run_ending_in_an_address_still_matches(self, sdk):
        text = "x'" * 500 + "jan@example.com"
        assert "jan@example.com" not in sdk.redact(text, countries=["IE"]).redacted_text
