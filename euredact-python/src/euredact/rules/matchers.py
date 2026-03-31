"""Multi-pattern matcher with Aho-Corasick acceleration.

Patterns with a literal prefix (e.g., "BE", "NL", "+31", "06") are indexed
in an Aho-Corasick automaton. On each scan, the automaton finds prefix hits
in O(text_length), then only the matching regexes run on small windows around
each hit — avoiding full-text scans for ~20 prefix-indexed patterns.

Patterns without an extractable prefix run as sequential regex (unavoidable).

Falls back gracefully to sequential-only if pyahocorasick is not installed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.rules.validators import VALIDATORS

try:
    import ahocorasick
    _HAS_AC = True
except ImportError:
    _HAS_AC = False



@dataclass(frozen=True)
class RawMatch:
    """A raw pattern match before validation."""

    start: int
    end: int
    text: str
    pattern_def: PatternDef
    country_code: str


def _extract_literal_prefix(pattern: str) -> str | None:
    """Extract a literal prefix (>= 2 chars) from a regex pattern, skipping \\b."""
    prefix: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] == "b":
            i += 2
            continue
        if ch in r"\[](){}*+?|^$.":
            break
        prefix.append(ch)
        i += 1
    result = "".join(prefix)
    return result if len(result) >= 2 else None


class MultiPatternMatcher:
    """Compiles all active patterns and scans text adaptively."""

    def __init__(self) -> None:
        self._patterns: list[tuple[re.Pattern[str], PatternDef, str]] = []
        self._compiled = False

        # AC structures (built on compile, used for long texts)
        self._ac_automaton: object | None = None
        # For each AC entry: list of (compiled_regex, PatternDef, country_code)
        self._ac_patterns: list[list[tuple[re.Pattern[str], PatternDef, str]]] = []
        # Patterns without extractable prefix (always scanned sequentially)
        self._no_prefix: list[tuple[re.Pattern[str], PatternDef, str]] = []

    def add_pattern(self, pattern_def: PatternDef, country_code: str) -> None:
        """Add a single pattern."""
        compiled = re.compile(pattern_def.pattern, re.UNICODE)
        self._patterns.append((compiled, pattern_def, country_code))
        self._compiled = False

    def add_country(self, config: CountryConfig) -> None:
        """Add a country's patterns."""
        for pdef in config.patterns:
            compiled = re.compile(pdef.pattern, re.UNICODE)
            self._patterns.append((compiled, pdef, config.code))
        self._compiled = False

    def compile(self) -> None:
        """Build scan structures."""
        if _HAS_AC:
            self._build_ac()
        self._compiled = True

    def _build_ac(self) -> None:
        """Build Aho-Corasick automaton from patterns with literal prefixes."""
        prefix_map: dict[str, list[tuple[re.Pattern[str], PatternDef, str]]] = {}
        self._no_prefix = []

        for compiled, pdef, code in self._patterns:
            prefix = _extract_literal_prefix(pdef.pattern)
            if prefix:
                prefix_map.setdefault(prefix, []).append((compiled, pdef, code))
            else:
                self._no_prefix.append((compiled, pdef, code))

        A = ahocorasick.Automaton()
        self._ac_patterns = []
        self._ac_prefix_lens: list[int] = []
        for idx, (prefix, patterns) in enumerate(prefix_map.items()):
            A.add_word(prefix, idx)
            self._ac_patterns.append(patterns)
            self._ac_prefix_lens.append(len(prefix))
        A.make_automaton()
        self._ac_automaton = A

    def scan(self, text: str) -> list[RawMatch]:
        """Scan text against all patterns."""
        if not self._compiled:
            self.compile()

        if self._ac_automaton is not None:
            return self._scan_ac(text)
        return self._scan_sequential(text)

    def _scan_sequential(self, text: str) -> list[RawMatch]:
        """Scan all patterns sequentially. Optimal for short texts."""
        matches: list[RawMatch] = []
        for regex, pdef, country_code in self._patterns:
            for m in regex.finditer(text):
                matches.append(
                    RawMatch(
                        start=m.start(), end=m.end(),
                        text=m.group(), pattern_def=pdef,
                        country_code=country_code,
                    )
                )
        return matches

    def _scan_ac(self, text: str) -> list[RawMatch]:
        """AC-accelerated scan for long texts.

        Phase 1: AC automaton finds prefix hits → targeted regex on regions.
        Phase 2: No-prefix patterns scanned sequentially (unavoidable).
        """
        matches: list[RawMatch] = []
        seen: set[tuple[int, int, int]] = set()  # dedup (start, end, pattern_id)

        # Phase 1: prefix-indexed patterns via AC
        ac: Any = self._ac_automaton
        for end_pos, entry_idx in ac.iter(text):
            patterns = self._ac_patterns[entry_idx]
            prefix_len = self._ac_prefix_lens[entry_idx]
            # AC reports end_pos as the last char index of the prefix match
            # So the prefix starts at (end_pos - prefix_len + 1)
            # Allow some margin before for \b and after for the rest of the pattern
            window_start = max(0, end_pos - prefix_len - 2)
            window_end = min(len(text), end_pos + 200)

            for compiled, pdef, code in patterns:
                for m in compiled.finditer(text, window_start, window_end):
                    key = (m.start(), m.end(), id(pdef))
                    if key not in seen:
                        seen.add(key)
                        matches.append(
                            RawMatch(
                                start=m.start(), end=m.end(),
                                text=m.group(), pattern_def=pdef,
                                country_code=code,
                            )
                        )

        # Phase 2: no-prefix patterns (full scan, but fewer patterns)
        for regex, pdef, code in self._no_prefix:
            for m in regex.finditer(text):
                matches.append(
                    RawMatch(
                        start=m.start(), end=m.end(),
                        text=m.group(), pattern_def=pdef,
                        country_code=code,
                    )
                )

        return matches

    def validate(self, match: RawMatch) -> bool:
        """Run checksum validator on a raw match. Returns True if valid (or no validator)."""
        if match.pattern_def.validator is None:
            return True
        validator = VALIDATORS.get(match.pattern_def.validator)
        if validator is None:
            return True
        return validator(match.text)
