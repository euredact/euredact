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

import pytest

import euredact.rules.matchers as matchers
from euredact.rules.matchers import (
    _AC_WINDOW,
    _RE2_OVERLAP,
    _extract_literal_prefix,
    _max_match_width,
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
