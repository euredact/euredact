"""RuleEngine: loads countries, runs detection pipeline."""

from __future__ import annotations

import bisect
import re
import threading

from euredact.rules.countries._base import PatternDef
from euredact.rules.matchers import MultiPatternMatcher, RawMatch
from euredact.rules.registry import CountryRegistry
from euredact.rules.structural import detect_structural_dob
from euredact.rules.suppressors import should_suppress_claim, should_suppress_span
from euredact.types import Detection, DetectionSource, EntityType

# Heuristic to detect nested quantifiers that cause catastrophic backtracking.
# After stripping escaped chars and character classes, look for an unbounded
# quantifier (+/*) closing a group that is itself quantified (+/*).
_NESTED_QUANTIFIER_RE = re.compile(r"[+*]\)[+*]")


def _validate_custom_pattern(pattern: str) -> None:
    """Validate a custom regex pattern for syntax and basic ReDoS safety."""
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc
    # Strip escaped characters and character classes so their contents
    # don't trigger false positives in the nested-quantifier check.
    stripped = re.sub(r"\\.", "X", pattern)
    stripped = re.sub(r"\[(?:[^\]\\]|\\.)*\]", "X", stripped)
    if _NESTED_QUANTIFIER_RE.search(stripped):
        raise ValueError(
            "Pattern contains nested quantifiers (e.g. (a+)+) which can cause "
            "catastrophic backtracking (ReDoS). Restructure the pattern to "
            "avoid quantifiers inside quantified groups."
        )


class RuleEngine:
    """The core rule-based PII detection engine.

    Thread-safe: multiple threads can call detect() concurrently.
    """

    def __init__(self) -> None:
        self._registry = CountryRegistry()
        self._matcher = MultiPatternMatcher()
        self._loaded_countries: set[str] = set()
        self._lock = threading.Lock()

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Add a user-defined regex pattern that is detected as *name*.

        Raises ValueError if the pattern is syntactically invalid or
        contains constructs likely to cause catastrophic backtracking.
        """
        _validate_custom_pattern(pattern)
        pdef = PatternDef(entity_type=name, pattern=pattern)
        with self._lock:
            self._matcher.add_pattern(pdef, "CUSTOM")
            self._matcher.compile()

    def load_countries(self, country_codes: list[str] | None = None) -> None:
        """Load country configs into the matcher. Idempotent per country."""
        with self._lock:
            if country_codes is None:
                configs = self._registry.load_all()
            else:
                # An unknown code warns and yields None; detection continues
                # with the shared patterns rather than raising.
                configs = [self._registry.load(c) for c in country_codes]
                configs = [c for c in configs if c is not None]
                # Always load shared patterns
                configs.append(self._registry.load("SHARED"))

            new_countries = False
            for config in configs:
                if config.code not in self._loaded_countries:
                    self._matcher.add_country(config)
                    self._loaded_countries.add(config.code)
                    new_countries = True

            if new_countries:
                self._matcher.compile()

    def detect(self, text: str, country_codes: list[str] | None = None) -> list[Detection]:
        """Detect PII in text using the two-pass architecture.

        Pass 1: Liberal pattern matching
        Pass 2: Suppression filters + checksum validation
        """
        self.load_countries(country_codes)

        # Pass 1: scan patterns (scoped to requested countries for efficiency).
        # Resolve through the alias table so `countries=["GB"]` actually scans
        # the patterns registered under "UK".
        if country_codes is not None:
            resolved = {self._registry.resolve(c) for c in country_codes}
            scan_codes = {c for c in resolved if c} | {"SHARED", "CUSTOM"}
        else:
            scan_codes = None
        raw_matches = self._matcher.scan(text, scan_codes)

        # Pass 2a: checksum validation + collect suppression zones
        # Matches that have a validator but fail it create suppression zones:
        # the span is recognisably a specific entity (e.g. IBAN-shaped) so
        # overlapping regex-only matches (license plate, phone) are false
        # positives and must be suppressed.
        validated: list[tuple[RawMatch, bool]] = []  # (match, is_valid)
        suppression_zones: list[tuple[int, int]] = []
        for m in raw_matches:
            is_valid = self._matcher.validate(m)
            if is_valid:
                validated.append((m, m.pattern_def.validator is not None))
            elif m.pattern_def.validator is not None and not m.pattern_def.requires_context:
                suppression_zones.append((m.start, m.end))

        # Merge overlapping suppression zones and build sorted index for
        # O(log n) containment checks instead of O(n) per match.
        zone_starts: list[int] = []
        zone_ends: list[int] = []
        if suppression_zones:
            suppression_zones.sort()
            ms, me = suppression_zones[0]
            for zs, ze in suppression_zones[1:]:
                if zs <= me:
                    me = max(me, ze)
                else:
                    zone_starts.append(ms)
                    zone_ends.append(me)
                    ms, me = zs, ze
            zone_starts.append(ms)
            zone_ends.append(me)

        # Pass 2b: build candidates with priority.
        # Priority: validated (3) > custom (2) > regex-only (1)
        #
        # Suppression is deliberately NOT run here. Most candidates lose their
        # span in deduplication, and suppressing a candidate that was going to
        # lose is wasted work — suppression was measured at ~65% of detect().
        # It runs inside _deduplicate instead, on the candidates that actually
        # win. This is equivalent because suppression depends only on the
        # document and the match, never on the other candidates: a suppressed
        # candidate is skipped without claiming its span, exactly as if it had
        # been filtered out here.
        # A candidate is (priority, start, end, match, prebuilt). Detection
        # objects are built only for candidates that survive deduplication and
        # suppression — most candidates lose their span, and allocating a
        # frozen dataclass for each one is pure waste.
        candidates: list[tuple[int, int, int, RawMatch | None, Detection | None]] = []
        for match, has_valid_validator in validated:
            # Matches without a validator that are fully contained in a
            # failed-validation zone are false positives (e.g. license plate
            # inside an invalid IBAN).  O(log n) binary search on merged zones.
            if match.pattern_def.validator is None and zone_starts:
                idx = bisect.bisect_right(zone_starts, match.start) - 1
                if idx >= 0 and zone_ends[idx] >= match.end:
                    continue

            if has_valid_validator:
                priority = 3
            elif match.country_code == "CUSTOM":
                priority = 2
            elif match.pattern_def.entity_type == EntityType.POSTAL_CODE:
                # A bare digit run is the weakest evidence in the engine and
                # must never re-cut a span a structured detector claims
                # (PHONE, SSN, NATIONAL_ID, BANK_ACCOUNT, VAT...). Postal
                # codes take unclaimed spans only, whatever the span lengths.
                priority = 0
            else:
                priority = 1

            candidates.append((priority, match.start, match.end, match, None))

        # Structural detectors (JSON field names, CSV headers). These arrive as
        # finished Detections, carry no RawMatch, and are not suppressed.
        for d in detect_structural_dob(text):
            candidates.append((1, d.start, d.end, None, d))

        # Deduplicate: validated > custom > regex-only, then longer wins
        detections = self._deduplicate(text, candidates)

        # Sort by position
        detections.sort(key=lambda d: (d.start, -d.end))
        return detections

    @staticmethod
    def _deduplicate(
        text: str,
        candidates: list[tuple[int, int, int, RawMatch | None, Detection | None]],
    ) -> list[Detection]:
        """Resolve overlapping candidates, suppressing only those that win.

        Priority: validated patterns (3) > custom patterns (2) > regex-only (1)
        > postal codes (0). Within a tier, longer span wins.

        Suppression runs here rather than before the sort, so a candidate that
        was going to lose its span never pays for it. A suppressed candidate is
        skipped *without* claiming its span, which is what makes this equivalent
        to filtering beforehand.

        The span-pure half of suppression is memoised on
        ``(entity_type, start, end)``: many countries' patterns claim the same
        span, and those suppressors cannot tell them apart. The claim-sensitive
        half runs per candidate.
        """
        if not candidates:
            return []

        # Sort by (priority, span_length) descending. Stable, so ties fall back
        # to pattern registration order, as before.
        sorted_cands = sorted(
            candidates,
            key=lambda c: (c[0], c[2] - c[1]),
            reverse=True,
        )
        result: list[Detection] = []
        occupied: set[int] = set()
        span_verdicts: dict[tuple[object, int, int], bool] = {}

        for _priority, start, end, match, prebuilt in sorted_cands:
            if any(p in occupied for p in range(start, end)):
                continue

            if match is not None:
                key = (match.pattern_def.entity_type, start, end)
                verdict = span_verdicts.get(key)
                if verdict is None:
                    verdict = should_suppress_span(text, match)
                    span_verdicts[key] = verdict
                if verdict or should_suppress_claim(text, match):
                    continue
                detection = Detection(
                    entity_type=match.pattern_def.entity_type,
                    start=start,
                    end=end,
                    text=match.text,
                    source=DetectionSource.RULES,
                    country=(
                        match.country_code
                        if match.country_code not in ("SHARED", "CUSTOM")
                        else None
                    ),
                    confidence="high",
                )
            else:
                assert prebuilt is not None
                detection = prebuilt

            occupied.update(range(start, end))
            result.append(detection)
        return result

    @property
    def loaded_countries(self) -> set[str]:
        """Return set of currently loaded country codes."""
        return self._loaded_countries.copy()
