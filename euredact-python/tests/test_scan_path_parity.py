"""The Aho-Corasick and sequential scan paths must produce identical output.

`pyahocorasick` is an optional extra. Before this suite existed, installing it
silently changed detection: prefix-indexed patterns are only run over a bounded
window after their prefix hit, so any pattern that can match further than that
window was truncated. The PEM private-key pattern matches up to 16 KB, so
`pip install euredact[fast]` stopped redacting private keys — the block was left
in the output.

These tests run BOTH paths in one process and compare, so the two can never
diverge again regardless of which extras are installed.
"""

import pytest

import euredact.rules.matchers as matchers
from euredact.rules.matchers import _AC_WINDOW, _extract_literal_prefix, _max_match_width
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


def _detect(text, use_ac):
    original = matchers._HAS_AC
    matchers._HAS_AC = use_ac
    try:
        result = EuRedact().redact(text, countries=["NL"], detect_dates=True, cache=False)
        return sorted((d.start, d.end, d.entity_type.value) for d in result.detections)
    finally:
        matchers._HAS_AC = original


@pytest.mark.parametrize("text", PARITY_DOCS, ids=[f"doc{i}" for i in range(len(PARITY_DOCS))])
def test_scan_paths_agree(text):
    assert _detect(text, use_ac=True) == _detect(text, use_ac=False)


@pytest.mark.parametrize("use_ac", [True, False], ids=["aho-corasick", "sequential"])
def test_pem_private_key_is_redacted_on_both_paths(use_ac):
    """The regression that motivated this file: the key must not survive."""
    original = matchers._HAS_AC
    matchers._HAS_AC = use_ac
    try:
        result = EuRedact().redact(f"config:\n{PEM}\n", countries=["NL"], cache=False)
    finally:
        matchers._HAS_AC = original
    assert PEM_BODY not in result.redacted_text, "private key survived redaction"
    assert any(d.entity_type == EntityType.SECRET and len(d.text) > _AC_WINDOW
               for d in result.detections)


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
    matcher._build_ac() if matchers._HAS_AC else None
    if not matchers._HAS_AC:  # pragma: no cover - depends on optional extra
        pytest.skip("pyahocorasick not installed")
    for group in matcher._ac_patterns:
        for _compiled, pdef, code in group:
            assert _max_match_width(pdef.pattern) <= _AC_WINDOW, (
                f"{code} pattern can match beyond the AC window: {pdef.description or pdef.pattern}"
            )


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
        pdef for _c, pdef, _code in matcher._no_prefix
        if _extract_literal_prefix(pdef.pattern) and _max_match_width(pdef.pattern) > _AC_WINDOW
    ]
    assert routed, "expected the unbounded SECRET patterns to be routed off the AC path"
    # The pattern spells it "PRIVATE\\sKEY", so match on the unescaped stem.
    assert any("PRIVATE" in p.pattern for p in routed), (
        f"PEM pattern not routed off the AC path; routed: "
        f"{[p.description for p in routed]}"
    )
