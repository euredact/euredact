"""The Aho-Corasick and sequential scan paths must produce identical output.

`pyahocorasick` is an optional extra. Before this suite existed, installing it
silently changed detection: prefix-indexed patterns are only run over a bounded
window after their prefix hit, so any pattern that can match further than that
window was truncated. The PEM private-key pattern matches up to 16 KB, so
`pip install euredact[fast]` stopped redacting private keys — the block was
left in the output.

These tests run BOTH paths in one process and compare, so the two can never
diverge again regardless of which extras are installed.
"""

import contextlib
import json
import re
from pathlib import Path

import pytest

import euredact.rules.matchers as matchers
from euredact.rules.matchers import (
    _AC_WINDOW,
    _RE2_OVERLAP,
    _extract_literal_prefix,
    _max_match_width,
    _strip_lookarounds,
)
from euredact.rules.registry import CountryRegistry
from euredact.sdk import EuRedact
from euredact.types import EntityType

PEM_BODY = "MIIEowIBAAKCAQEA" * 30
PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----"

# Inputs whose match is longer than the AC window, plus ordinary ones.
PARITY_DOCS = [
    f"Deployment config:\n{PEM}\nContact: ops@example.com",
    "token: ghp_" + "a" * 40,
    "NPM_TOKEN=npm_" + "b" * 40,
    "slack: xoxb-" + "c" * 30,
    "Rekening: BE68 5390 0754 7034 - BIC: GEBABEBB",
    "Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390",
    "Tel: +43 664 8213 907, mail petras_ž@example.com",
    # Lookaround-guarded patterns, now prefiltered by their stripped superset
    # (rules-engine#72): a guard that holds, one that refuses, and the CH
    # postal lookbehinds -- once inside a window and once across a boundary.
    "Mob: 0170 1234567 12.03.2024, Tel. 0664 1234567 85 21",
    "Tel. 01 5123456 14:30 Uhr; Hauptstrasse 5, CH-8004 Zürich",
    "x" * 1010 + " Mob: +49 170 1234567 85 21 am 12.03.2024, Hauptstrasse 5, CH-8004 Zürich",
]


# Which scan paths this environment can actually exercise. Selecting a path
# means suppressing the ones that outrank it — scan() prefers re2, then
# Aho-Corasick, then sequential — and a path whose library is missing cannot be
# forced on, so it is skipped rather than failed.
_PATHS = ["sequential"]
if matchers._HAS_AC:
    _PATHS.append("aho-corasick")
if matchers._HAS_RE2:
    _PATHS.append("re2")


@contextlib.contextmanager
def _force_path(path):
    """Run the block with exactly one scan path enabled."""
    saved = (matchers._HAS_AC, matchers._HAS_RE2)
    matchers._HAS_AC = path == "aho-corasick"
    matchers._HAS_RE2 = path == "re2"
    try:
        yield
    finally:
        matchers._HAS_AC, matchers._HAS_RE2 = saved


def _detect(text, path):
    with _force_path(path):
        result = EuRedact().redact(
            text, countries=["NL"], detect_dates=True, cache=False
        )
        return sorted((d.start, d.end, d.entity_type.value) for d in result.detections)


@pytest.mark.parametrize(
    "text", PARITY_DOCS, ids=[f"doc{i}" for i in range(len(PARITY_DOCS))]
)
@pytest.mark.parametrize("path", _PATHS)
def test_scan_paths_agree(text, path):
    """Every accelerated path must agree with the sequential reference.

    Installing an optional extra must not change what gets redacted. It did
    once: `pip install euredact[fast]` stopped redacting private keys.
    """
    assert _detect(text, path) == _detect(text, "sequential")


@pytest.mark.parametrize("path", _PATHS)
def test_pem_private_key_is_redacted_on_both_paths(path):
    """The regression that motivated this file: the key must not survive."""
    with _force_path(path):
        result = EuRedact().redact(f"config:\n{PEM}\n", countries=["NL"], cache=False)
    assert PEM_BODY not in result.redacted_text, "private key survived redaction"
    assert any(d.entity_type == EntityType.SECRET and len(d.text) > _AC_WINDOW
               for d in result.detections)


@pytest.mark.skipif(not matchers._HAS_AC, reason="pyahocorasick not installed")
def test_no_prefix_indexed_pattern_can_outrun_the_window():
    """The structural guarantee, not just the symptom.

    Every pattern the AC path indexes must be unable to match beyond the window
    it is given, or it would be silently truncated.
    """
    registry = CountryRegistry()
    matcher = matchers.MultiPatternMatcher()
    for code in registry.available_countries + ["SHARED"]:
        config = registry.load(code)
        if config is not None:
            matcher.add_country(config)
    matcher.compile()
    if not matchers._HAS_AC:  # pragma: no cover - depends on optional extra
        pytest.skip("pyahocorasick not installed")
    for group in matcher._plan.ac_patterns:
        for _compiled, pdef, code in group:
            assert _max_match_width(pdef.pattern) <= _AC_WINDOW, (
                f"{code} pattern can match beyond the AC window: "
                f"{pdef.description or pdef.pattern}"
            )


@pytest.mark.skipif(not matchers._HAS_AC, reason="pyahocorasick not installed")
def test_unbounded_patterns_are_routed_to_full_scan():
    registry = CountryRegistry()
    matcher = matchers.MultiPatternMatcher()
    for code in registry.available_countries + ["SHARED"]:
        config = registry.load(code)
        if config is not None:
            matcher.add_country(config)
    matcher.compile()
    if not matchers._HAS_AC:  # pragma: no cover
        pytest.skip("pyahocorasick not installed")
    routed = [
        pdef for _c, pdef, _code in matcher._plan.no_prefix
        if _extract_literal_prefix(pdef.pattern)
        and _max_match_width(pdef.pattern) > _AC_WINDOW
    ]
    assert routed, (
        "expected the unbounded SECRET patterns to be routed off the AC path"
    )
    # The pattern spells it "PRIVATE\\sKEY", so match on the unescaped stem.
    assert any("PRIVATE" in p.pattern for p in routed), (
        f"PEM pattern not routed off the AC path; routed: "
        f"{[p.description for p in routed]}"
    )


# ── RE2 prefilter ───────────────────────────────────────────────────────
#
# The RE2 path only decides *which* patterns are worth running; each survivor
# is then run over the whole text exactly as the sequential path runs it. So
# unlike the AC path — which windows patterns and can surface overlapping
# matches a single left-to-right pass skips — this one must agree with
# sequential exactly, on every input.


def _all_countries_matcher():
    registry = CountryRegistry()
    matcher = matchers.MultiPatternMatcher()
    for code in registry.available_countries + ["SHARED"]:
        config = registry.load(code)
        if config is not None:
            matcher.add_country(config)
    matcher.compile()
    return matcher


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
@pytest.mark.parametrize(
    "text", PARITY_DOCS, ids=[f"doc{i}" for i in range(len(PARITY_DOCS))]
)
def test_re2_path_matches_sequential_exactly(text):
    matcher = _all_countries_matcher()

    def key(matches):
        return sorted(
            (m.start, m.end, m.text, id(m.pattern_def), m.country_code)
            for m in matches
        )

    assert key(matcher._scan_re2(text, matcher._plan)) == key(
        matcher._scan_sequential(text, matcher._plan)
    )


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_re2_emits_in_pattern_registration_order():
    """Deduplication breaks ties by registration order, so the prefilter must
    not reorder what it emits — only drop patterns that match nowhere."""
    matcher = _all_countries_matcher()
    text = "Rekening: BE68 5390 0754 7034 - BIC: GEBABEBB, tel +32 2 123 45 67"
    got = [id(m.pattern_def) for m in matcher._scan_re2(text, matcher._plan)]
    expected = [id(m.pattern_def) for m in matcher._scan_sequential(text, matcher._plan)]
    assert got == expected


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_patterns_re2_cannot_express_still_run():
    """A pattern RE2 rejects must fall back, not vanish. The lookbehind-based
    SECRET rules are the ones that matter — silently dropping them would be
    the private-key leak again, by a different route."""
    matcher = _all_countries_matcher()
    opted_out = sum(1 for slot in matcher._plan.re2_slot if slot is None)
    assert opted_out > 0, "expected some patterns to opt out of the prefilter"
    assert len(matcher._plan.re2_slot) == len(matcher._plan.patterns)

    # The rule under test is the generic "high-entropy token after a
    # delimiter" lookbehind, so the token deliberately carries no vendor
    # prefix and is assembled from fragments: a literal that looks like a real
    # provider key trips secret scanners on push, and a fixture is not worth
    # teaching a repository to wave those through.
    token = "Zx4Qv" + "7Rt2Mw" + "9Kd5Np" + "3Hb8Lf"
    text = f"config:\n  api_key = {token}"
    found = matcher._scan_re2(text, matcher._plan)
    assert [m.text for m in found] == [
        m.text for m in matcher._scan_sequential(text, matcher._plan)
    ]
    assert any(m.pattern_def.entity_type == EntityType.SECRET for m in found), \
        "the lookbehind SECRET rule did not fire — the fallback is not running"


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_prefilter_never_windows_a_pattern_that_could_outrun_the_overlap():
    """The sliding window would straddle such a pattern's match."""
    matcher = _all_countries_matcher()
    for slot, (_compiled, pdef, code) in zip(matcher._plan.re2_slot, matcher._plan.patterns):
        if slot is not None:
            assert _max_match_width(pdef.pattern) <= _RE2_OVERLAP, (
                f"{code} pattern can outrun the prefilter overlap: "
                f"{pdef.description or pdef.pattern}"
            )


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_pem_private_key_survives_the_prefilter():
    """The 0.3.2 security regression, re-asserted against the new path."""
    sdk = EuRedact()
    text = f"Deployment config:\n{PEM}\nContact: ops@example.com"
    result = sdk.redact(text, cache=False)
    assert PEM_BODY not in result.redacted_text
    assert any(d.entity_type == EntityType.SECRET for d in result.detections)


# ── Lookarounds and the prefilter (rules-engine#72) ──────────────────────


@pytest.mark.parametrize("pattern,expected", [
    (r"\d{2}(?![.,/:]\d)", r"\d{2}"),
    (r"(?:(?<=, )|(?<=, CH-))[1-9]\d{3}(?= [A-Z])", r"(?:|)[1-9]\d{3}"),
    (r"(?<![A-Za-z0-9_])tel(?=(?:a|b))x", r"telx"),
    # An escaped paren and a character class are not groups.
    (r"\(?!x\)[(?=]y", r"\(?!x\)[(?=]y"),
    (r"[\](?!]z", r"[\](?!]z"),
])
def test_strip_lookarounds(pattern, expected):
    assert _strip_lookarounds(pattern) == expected


def test_a_quantified_lookaround_is_not_stripped():
    # Removing it would leave the quantifier dangling on the previous atom.
    assert _strip_lookarounds(r"a(?=b)?c") is None
    assert _strip_lookarounds(r"a(?!b") is None


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_lookahead_guarded_phone_patterns_keep_the_prefilter():
    """The #51/#60 guards cost these broad patterns their prefilter."""
    matcher = _all_countries_matcher()
    guarded = [
        (slot, pdef.description)
        for slot, (_c, pdef, _code) in zip(matcher._plan.re2_slot, matcher._plan.patterns)
        if pdef.description in (
            "German national phone number", "German international phone — +49",
            "Austrian national phone — short area code, grouped",
        )
    ]
    assert len(guarded) == 3
    assert all(slot is not None for slot, _ in guarded), guarded


# -- Unicode text: every path reads it as Python does (rules-engine#150) -------
#
# RE2 reads \d, \s, \w and \b as ASCII, Python as Unicode. Fed the patterns
# unchanged, the re2 prefilter matched less than the patterns it filters for
# and skipped them: a French phone grouped with no-break spaces, the way French
# typography writes numbers, was redacted without [fast] and left in the text
# with it. The vectors' texts are re-spelled with Unicode spaces, digits and
# letters, and every accelerated path must report what the sequential scan does.

_VECTORS = [c["text"] for c in json.loads(
    (Path(__file__).resolve().parents[2] / "conformance" / "vectors.json").read_text()
)["cases"]]

_UNICODE_SPELLINGS = {
    "no-break-space": lambda t: t.replace(" ", "\xa0"),
    "narrow-no-break-space": lambda t: t.replace(" ", " "),
    "thin-space": lambda t: t.replace(" ", " "),
    "figure-space": lambda t: t.replace(" ", " "),
    "ideographic-space": lambda t: t.replace(" ", "　"),
    "full-width-digits": lambda t: t.translate(str.maketrans("0123456789", "０１２３４５６７８９")),
    "arabic-indic-digits": lambda t: t.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")),
    "accented-letters": lambda t: "Ünïcödé " + t.replace("e", "é").replace("a", "ä"),
    "letter-before-each-space": lambda t: t.replace(" ", "é "),
    # ASCII whitespace that Python's \s matches and RE2's does not
    # (rules-engine#159). Text extracted from Word carries vertical tabs.
    "vertical-tab": lambda t: t.replace(" ", "\x0b"),
    "file-separator": lambda t: t.replace(" ", "\x1c"),
    # Letters an IGNORECASE ASCII letter matches: Kelvin sign, long s,
    # dotless i (rules-engine#159).
    "case-folding-letters": lambda t: t.replace("k", "\u212a").replace("s", "\u017f").replace("i", "\u0131"),
    # A lone surrogate, as json.loads gives for a "\ud800" escape; the re2
    # prefilter raised UnicodeEncodeError on it (rules-engine#159).
    "lone-surrogate": lambda t: t + " \ud800",
    # A non-ASCII letter or digit glued to a number. The engine's digit
    # boundary is ASCII ("é123" matches \b\d{3}\b); the prefilter writes it as
    # a class that also accepts what a letter folds to, and a text with a
    # non-ASCII digit skips the prefilter (rules-engine#176).
    "accented-letter-before-each-number": lambda t: re.sub(r"(\d+)", "é\\1", t),
    "folding-letters-around-each-number": lambda t: re.sub(r"(\d+)", "ı\\1\u017f", t),
    "kelvin-sign-before-each-number": lambda t: re.sub(r"(\d+)", "\u212a\\1", t),
    "astral-digit-before-each-number": lambda t: re.sub(r"(\d+)", "x\U0001d7ce\\1", t),
    "full-width-digit-after-each-number": lambda t: re.sub(r"(\d+)", "\\1\uff11y", t),
    "as-written": lambda t: t,
}


def _scan_key(matches):
    return sorted((m.start, m.end, id(m.pattern_def), m.country_code) for m in matches)


@pytest.mark.skipif(not (matchers._HAS_RE2 or matchers._HAS_AC), reason="no accelerated path installed")
@pytest.mark.parametrize("spelling", list(_UNICODE_SPELLINGS))
def test_accelerated_scans_read_unicode_text_as_python_does(spelling):
    matcher = _all_countries_matcher()
    plan = matcher._plan
    respell = _UNICODE_SPELLINGS[spelling]
    differing = []
    for text in _VECTORS:
        text = respell(text)
        reference = _scan_key(matcher._scan_sequential(text, plan))
        if plan.re2_set is not None and _scan_key(matcher._scan_re2(text, plan)) != reference:
            differing.append(("re2", text))
        if plan.ac_automaton is not None and _scan_key(matcher._scan_ac(text, plan)) != reference:
            differing.append(("aho-corasick", text))
    assert differing == [], f"{len(differing)} texts differ, first: {differing[:3]}"


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("text, country, expected", [
    ("Tél : 06\xa012\xa034\xa056\xa078", "FR", "Tél : [PHONE]"),
    ("Tél : 06 12 34 56 78", "FR", "Tél : [PHONE]"),
    ("IBAN NL91\xa0ABNA\xa00417\xa01643\xa000", "NL", "IBAN [BANK_ACCOUNT]"),
    ("Tel ０６１２３４５６７８", "FR", "Tel [PHONE]"),
], ids=["fr-phone-nbsp", "fr-phone-nnbsp", "iban-nbsp", "full-width-phone"])
def test_values_written_with_unicode_spaces_and_digits_are_redacted_on_every_path(
        path, text, country, expected):
    """The leak itself: before the fix the first three came back unchanged
    with [fast], and the last was "Tel [TAX_ID]８" without it."""
    with _force_path(path):
        result = EuRedact().redact(text, countries=[country], cache=False)
    assert result.redacted_text == expected


@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("source, text", [
    (r"CASE[^A-Za-z ]\d{6}", "Dossier CASE\xa0123456 ok"),
    (r"CASE[^ ]\d{6}", "Dossier CASE\xa0123456 ok"),
    # An astral digit: normalize() folds BMP digits only, re2's fold reads it as "0".
    (r"CASE\s[^0-9]\d{6}", "Dossier CASE \U0001d7ce123456 ok"),
], ids=["not-letter-or-space", "not-space", "not-digit"])
def test_a_negated_class_in_a_custom_pattern_is_not_narrowed_by_the_fold(path, source, text):
    """The fold turns a no-break space into " ", letters into "a" and digits
    into "0". A negated class that excludes a stand-in then refused, in the
    re2 prefilter, text Python accepts, and the value was left in the text
    (rules-engine#159). Such a pattern now runs without a prefilter slot."""
    with _force_path(path):
        sdk = EuRedact()
        sdk.add_custom_pattern("CASE_REF", source)
        result = sdk.redact(text, cache=False)
    assert "[CASE_REF]" in result.redacted_text, result.redacted_text


def test_the_folded_word_stand_ins_are_all_there_are():
    """The digit boundary the prefilter reads accepts each ASCII word character
    a non-ASCII non-digit folds to. A Unicode update that adds one must add it
    there too, or "<letter>123" is skipped (rules-engine#176)."""
    import sys
    produced = set()
    for cp in range(0x80, sys.maxunicode + 1):
        ch = chr(cp)
        if 0xD800 <= cp <= 0xDFFF or ch.isdecimal():
            continue
        folded = matchers._fold_char(ch)
        if folded != ch and (folded.isalnum() or folded == "_") and folded.isascii():
            produced.add(folded)
    assert produced <= set(matchers._FOLDED_WORD_STAND_INS), produced


@pytest.mark.skipif(not matchers._HAS_RE2, reason="google-re2 not installed")
def test_a_digit_pattern_keeps_its_boundaries_in_the_prefilter():
    """The prefilter read "\\b\\d{9}\\b" as a bare "\\d{9}" and let it through on
    any longer number: 2.5 times the candidates, and [fast] slower than no
    accelerator (rules-engine#176). It must still let "é123456789" through,
    which the engine's ASCII digit boundary matches."""
    import re2
    source = matchers._digit_boundaries(matchers._for_re2(matchers._ascii_word_boundaries(
        r"\b\d{9}\b", matchers._DIGITS_START_MARK, matchers._DIGITS_END_MARK)))
    s = re2.Set.SearchSet()
    s.Add(source)
    s.Compile()
    fold = matchers._fold_for_re2
    assert not s.Match(fold("Tel 0612345678"))
    assert s.Match(fold("Tel 061234567"))
    assert s.Match(fold("Ref é123456789"))
    assert s.Match(fold("Ref \u0131123456789\u017f"))
    assert matchers._RE2_MAX_MEM >= 64 << 20
