"""RuleEngine: loads countries, runs detection pipeline."""

from __future__ import annotations

import threading

from euredact.rules.countries._base import PatternDef
from euredact.rules.matchers import MultiPatternMatcher, RawMatch
from euredact.rules.registry import CountryRegistry
from euredact.rules.structural import detect_structural_dob
from euredact.rules.suppressors import should_suppress
from euredact.types import Detection, DetectionSource


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
        """Add a user-defined regex pattern that is detected as *name*."""
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
                configs = [self._registry.load(c.upper()) for c in country_codes]
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

        # Pass 1: scan all patterns
        raw_matches = self._matcher.scan(text)

        # Filter to requested countries if specified
        if country_codes is not None:
            codes_upper = {c.upper() for c in country_codes}
            # Keep shared patterns (country=SHARED) and country-specific
            raw_matches = [
                m for m in raw_matches
                if m.country_code in codes_upper
                or m.country_code in ("SHARED", "CUSTOM")
            ]

        # Pass 2a: checksum validation + collect suppression zones
        # Matches that have a validator but fail it create suppression zones:
        # the span is recognisably a specific entity (e.g. IBAN-shaped) so
        # overlapping regex-only matches (license plate, phone) are false
        # positives and must be suppressed.
        validated: list[RawMatch] = []
        suppression_zones: list[tuple[int, int]] = []
        for m in raw_matches:
            if self._matcher.validate(m):
                validated.append(m)
            elif m.pattern_def.validator is not None:
                suppression_zones.append((m.start, m.end))

        # Pass 2b: suppression filters + build candidates with priority
        # Priority: validated (3) > custom (2) > regex-only (1)
        candidates: list[tuple[Detection, int]] = []
        for match in validated:
            if should_suppress(text, match):
                continue
            # Matches without a validator that are fully contained in a
            # failed-validation zone are false positives (e.g. license plate
            # inside an invalid IBAN).
            if match.pattern_def.validator is None and suppression_zones:
                if any(
                    match.start >= z_start and match.end <= z_end
                    for z_start, z_end in suppression_zones
                ):
                    continue

            has_validator = match.pattern_def.validator is not None
            is_valid = self._matcher.validate(match)
            if has_validator and is_valid:
                priority = 3
            elif match.country_code == "CUSTOM":
                priority = 2
            else:
                priority = 1

            candidates.append((
                Detection(
                    entity_type=match.pattern_def.entity_type,
                    start=match.start,
                    end=match.end,
                    text=match.text,
                    source=DetectionSource.RULES,
                    country=match.country_code if match.country_code not in ("SHARED", "CUSTOM") else None,
                    confidence="high",
                ),
                priority,
            ))

        # Structural detectors (JSON field names, CSV headers)
        for d in detect_structural_dob(text):
            candidates.append((d, 1))

        # Deduplicate: validated > custom > regex-only, then longer wins
        detections = self._deduplicate(candidates)

        # Sort by position
        detections.sort(key=lambda d: (d.start, -d.end))
        return detections

    @staticmethod
    def _deduplicate(
        candidates: list[tuple[Detection, int]],
    ) -> list[Detection]:
        """Remove overlapping detections with priority-aware resolution.

        Priority: validated patterns (3) > custom patterns (2) > regex-only (1).
        Within the same tier, longer span wins.
        """
        if not candidates:
            return []

        # Sort by (priority, span_length) descending
        sorted_cands = sorted(
            candidates,
            key=lambda c: (c[1], c[0].end - c[0].start),
            reverse=True,
        )
        result: list[Detection] = []
        for det, _priority in sorted_cands:
            overlaps = False
            for kept in result:
                if det.start < kept.end and det.end > kept.start:
                    overlaps = True
                    break
            if not overlaps:
                result.append(det)
        return result

    @property
    def loaded_countries(self) -> set[str]:
        """Return set of currently loaded country codes."""
        return self._loaded_countries.copy()
