"""Multi-pattern matcher with Aho-Corasick acceleration.

Patterns with a literal prefix (e.g., "BE", "NL", "+31", "06") are indexed
in an Aho-Corasick automaton. On each scan, the automaton finds prefix hits
in O(text_length), then only the matching regexes run on small windows around
each hit — avoiding full-text scans for ~20 prefix-indexed patterns.

Patterns without an extractable prefix run as sequential regex (unavoidable).

Falls back gracefully to sequential-only if pyahocorasick is not installed.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterator

from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.rules.validators import VALIDATORS

try:
    import ahocorasick
    _HAS_AC = True
except ImportError:
    _HAS_AC = False

try:
    import re2 as _re2
    _HAS_RE2 = True
except ImportError:
    _HAS_RE2 = False



@dataclass(frozen=True)
class RawMatch:
    """A raw pattern match before validation."""

    start: int
    end: int
    text: str
    pattern_def: PatternDef
    country_code: str


# How far past a prefix hit the AC path lets a pattern match. Any pattern that
# can match further than this must not be prefix-indexed — see _build_ac.
_AC_WINDOW = 200

# RE2 prefilter geometry. The automaton is asked which patterns match inside a
# sliding window rather than the whole text: over a long document nearly every
# pattern matches *somewhere*, so a whole-document question stops filtering
# (measured: 2.48x on a 188-char document decaying to 1.11x at 12 KB).
#
# The window only decides *which* patterns are worth running. Each surviving
# pattern is then run over the whole text, so the result is exactly what the
# sequential path produces — this path skips patterns, it never re-cuts spans.
# Restricting each pattern to its window instead is measurably faster (3.21x vs
# 2.70x on real documents) but diverges from the sequential path on 44 matches,
# which is not worth a third set of scan semantics.
_RE2_WINDOW = 1024
_RE2_OVERLAP = 256


@contextlib.contextmanager
def _silence_stderr() -> Iterator[None]:
    """Suppress RE2's rejection logging for the duration of the block.

    RE2 reports patterns it cannot compile by writing to file descriptor 2 from
    C++, which ``contextlib.redirect_stderr`` cannot intercept. Those
    rejections are expected and handled — the pattern falls back to Python's
    engine — so surfacing eleven alarming-looking parse errors on first use
    would be noise, and wrong.

    Only wraps one-time automaton construction, never a scan.
    """
    sys.stderr.flush()
    saved_fd = os.dup(2)
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull_fd, 2)
        yield
    finally:
        os.dup2(saved_fd, 2)
        os.close(devnull_fd)
        os.close(saved_fd)


# Python's \b is Unicode-aware: a Cyrillic or accented letter counts as a word
# character, so "\b\d{10}\b" does not match the digits in "ЕГН7523169263". JS's
# \b is ASCII-only, so Node matched and redacted exactly those cases and Python
# did not — five of five, across the alphabets this engine targets.
#
# Which rule is "right" is arguable: Python's is self-consistent, JS's is
# script-dependent. But for a redaction tool the argument is settled by the
# failure direction. Python's principled rule leaves a national ID glued to a
# non-ASCII letter unredacted; JS's limitation catches it.
#
# So \b is rewritten at compile time rather than in 303 pattern sources.
# re.ASCII is not usable: it would also narrow \w, breaking Unicode e-mail local
# parts, which are deliberately supported.
#
# The rewrite is chosen per boundary, by what sits next to it.
#
# **Next to a digit** — the ASCII reading alone is *exactly* the union of both
# readings, because a Unicode letter is never an ASCII word character, so the
# ASCII branch already succeeds everywhere the Unicode branch does. One
# lookaround replaces a three-way alternation.
#
# **Anything else** — plain \b, which is what "Mail: αλέξης@example.gr" needs:
# α is not an ASCII word character, so an ASCII-only boundary would refuse to
# start the match and the address would go unredacted.
#
# An earlier version applied the three-branch union everywhere. It was correct
# but cost 1.8x on short records and 2.8x on real documents, and its ASCII branch
# manufactured boundaries *inside* words at non-ASCII letters — truncating
# "@Ciarán" to "@Ciar" and typing the fragment "FICIAIRES" of "BÉNÉFICIAIRES" as
# a national ID. Choosing per boundary is both faster and cleaner.
_ASCII_WORD = "0-9A-Za-z_"


def _digit_only_element(source: str, i: int) -> bool:
    """Does the pattern element starting at *source[i]* match only digits?"""
    if source.startswith(r"\d", i):
        return True
    if i >= len(source) or source[i] != "[":
        return False
    close = source.find("]", i + 1)
    if close < 0:
        return False
    body = source[i + 1:close]
    return bool(body) and not body.startswith("^") and all(
        c.isdigit() or c == "-" for c in body
    )


def _preceding_element_is_digits(source: str, i: int) -> bool:
    """Looking left from *source[i]*, skip a quantifier and test the element."""
    j = i - 1
    if j >= 0 and source[j] == "}":
        brace = source.rfind("{", 0, j)
        if brace < 0:
            return False
        j = brace - 1
    elif j >= 0 and source[j] in "+*?":
        j -= 1
    if j < 0:
        return False
    if source[j] == "]":
        open_ = source.rfind("[", 0, j)
        return open_ >= 0 and _digit_only_element(source, open_)
    return j >= 1 and source[j - 1] == "\\" and source[j] == "d"


def _ascii_word_boundaries(pattern: str) -> str:
    """Rewrite each ``\b`` in *pattern* per the reasoning above.

    Skips escaped backslashes and character classes, where ``\b`` means a
    backspace rather than a boundary. Neither occurs in the shipped patterns
    today; the scan is here so that adding one cannot silently corrupt it.
    """
    out: list[str] = []
    i = 0
    in_class = False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            if pattern[i + 1] == "b" and not in_class:
                if _digit_only_element(pattern, i + 2):
                    out.append(f"(?<![{_ASCII_WORD}])")
                elif _preceding_element_is_digits(pattern, i):
                    out.append(f"(?![{_ASCII_WORD}])")
                else:
                    out.append(r"\b")
            else:
                out.append(pattern[i:i + 2])
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        out.append(ch)
        i += 1
    return "".join(out)


def _max_match_width(pattern: str) -> int:
    """Longest string *pattern* can match, or a huge number if unbounded.

    Uses the stdlib parser rather than inspecting the source, so quantifiers,
    alternation and nesting are all accounted for. Anything that cannot be
    analysed is treated as unbounded, which is the safe direction: the pattern
    falls back to a full scan rather than being silently windowed.
    """
    try:
        import re._parser as _parser  # Python 3.11+
    except ImportError:  # pragma: no cover - older interpreters
        import sre_parse as _parser  # type: ignore[no-redef]
    try:
        return int(_parser.parse(pattern).getwidth()[1])
    except Exception:  # noqa: BLE001 - an unparseable pattern is treated as unbounded
        return _AC_WINDOW + 1


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

        # RE2 prefilter. _re2_slot is parallel to _patterns: the automaton
        # index for a pattern the prefilter covers, or None for one that must
        # always run. Keeping it parallel means the scan emits matches in
        # pattern-registration order, which deduplication relies on to break
        # ties the same way every path does.
        self._re2_set: object | None = None
        self._re2_slot: list[int | None] = []

    def add_pattern(self, pattern_def: PatternDef, country_code: str) -> None:
        """Add a single pattern."""
        compiled = re.compile(_ascii_word_boundaries(pattern_def.pattern), re.UNICODE)
        self._patterns.append((compiled, pattern_def, country_code))
        self._compiled = False

    def add_country(self, config: CountryConfig) -> None:
        """Add a country's patterns."""
        for pdef in config.patterns:
            compiled = re.compile(_ascii_word_boundaries(pdef.pattern), re.UNICODE)
            self._patterns.append((compiled, pdef, config.code))
        self._compiled = False

    def compile(self) -> None:
        """Build scan structures."""
        if _HAS_AC:
            self._build_ac()
        if _HAS_RE2:
            self._build_re2()
        self._compiled = True

    def _build_re2(self) -> None:
        """Build the RE2 prefilter over every pattern it can express.

        Two kinds of pattern opt out and always run: those RE2 cannot compile
        (lookbehind, lazy bounded repeats — 11 of 345 today, chiefly postal
        codes and secrets), and those that can match further than the window
        overlap, which the sliding window could otherwise straddle.
        """
        # The *original* source goes to RE2, not the rewritten one: RE2's \b is
        # already ASCII-only, so the semantics match, while the rewrite uses
        # lookbehind that RE2 cannot compile.
        automaton = _re2.Set.SearchSet()
        self._re2_slot = []
        added = 0
        with _silence_stderr():
            for _compiled, pdef, _code in self._patterns:
                if _max_match_width(pdef.pattern) > _RE2_OVERLAP:
                    self._re2_slot.append(None)
                    continue
                try:
                    automaton.Add(pdef.pattern)
                except Exception:  # noqa: BLE001 - RE2 rejects some Python syntax
                    self._re2_slot.append(None)
                    continue
                self._re2_slot.append(added)
                added += 1
            if added:
                automaton.Compile()
        if added:
            self._re2_set = automaton
        else:  # pragma: no cover - only if every pattern opted out
            self._re2_set = None

    def _build_ac(self) -> None:
        """Build Aho-Corasick automaton from patterns with literal prefixes.

        A prefix-indexed pattern is only ever run over a bounded window after
        its prefix hit (see :meth:`_scan_ac`), so a pattern whose match can be
        longer than that window would be silently truncated. Those patterns are
        routed to the sequential path instead.

        This is not hypothetical: the PEM private-key pattern matches up to
        16 KB, and before this check ``pip install euredact[fast]`` stopped
        redacting private keys altogether — the block was left in the output.
        """
        prefix_map: dict[str, list[tuple[re.Pattern[str], PatternDef, str]]] = {}
        self._no_prefix = []

        for compiled, pdef, code in self._patterns:
            prefix = _extract_literal_prefix(pdef.pattern)
            if prefix and _max_match_width(pdef.pattern) <= _AC_WINDOW:
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

    def scan(self, text: str, country_codes: set[str] | None = None) -> list[RawMatch]:
        """Scan text against patterns.

        *country_codes* restricts which patterns run. **The engine never passes
        it.** Generation is country-blind by contract — see
        ``RuleEngine.generate_candidates`` and
        ``tests/test_invariant_generation.py`` — because gating generation on
        the caller's declared country caused silent misses. The parameter is
        kept for a future opt-in ``mode="fast"``, which would be the only
        caller permitted to trade recall for speed, and the only exemption from
        that invariant.
        """
        if not self._compiled:
            self.compile()

        if self._re2_set is not None:
            return self._scan_re2(text, country_codes)
        if self._ac_automaton is not None:
            return self._scan_ac(text, country_codes)
        return self._scan_sequential(text, country_codes)

    def _scan_re2(self, text: str, country_codes: set[str] | None = None) -> list[RawMatch]:
        """RE2-prefiltered scan. Identical output to :meth:`_scan_sequential`.

        One DFA pass per window reports which patterns match anywhere in it —
        typically 42 of 314 for a real document. Only those are then run, over
        the full text, exactly as the sequential path would run them. Skipping
        a pattern that matches nowhere cannot change the result, so this is a
        pure speed-up rather than a second set of semantics.
        """
        candidates: set[int] = set()
        length = len(text)
        step = _RE2_WINDOW - _RE2_OVERLAP
        pos = 0
        while pos < length:
            end = min(length, pos + _RE2_WINDOW)
            hits = self._re2_set.Match(text[pos:end])  # type: ignore[attr-defined]
            if hits:
                candidates.update(hits)
            if end >= length:
                break
            pos += step

        matches: list[RawMatch] = []
        for slot, (regex, pdef, country_code) in zip(self._re2_slot, self._patterns):
            if slot is not None and slot not in candidates:
                continue
            if country_codes is not None and country_code not in country_codes:
                continue
            for m in regex.finditer(text):
                matches.append(
                    RawMatch(
                        start=m.start(), end=m.end(),
                        text=m.group(), pattern_def=pdef,
                        country_code=country_code,
                    )
                )
        return matches

    def _scan_sequential(self, text: str, country_codes: set[str] | None = None) -> list[RawMatch]:
        """Scan patterns sequentially. Optimal for short texts."""
        matches: list[RawMatch] = []
        for regex, pdef, country_code in self._patterns:
            if country_codes is not None and country_code not in country_codes:
                continue
            for m in regex.finditer(text):
                matches.append(
                    RawMatch(
                        start=m.start(), end=m.end(),
                        text=m.group(), pattern_def=pdef,
                        country_code=country_code,
                    )
                )
        return matches

    def _scan_ac(self, text: str, country_codes: set[str] | None = None) -> list[RawMatch]:
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
                if country_codes is not None and code not in country_codes:
                    continue
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
            if country_codes is not None and code not in country_codes:
                continue
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
