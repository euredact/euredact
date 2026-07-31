"""RuleEngine: loads countries, runs detection pipeline."""

from __future__ import annotations

import bisect
import re
import threading
from dataclasses import replace

from euredact.rules import evidence as evidence_mod
from euredact.rules.countries._base import PatternDef
from euredact.rules.matchers import MultiPatternMatcher, RawMatch
from euredact.rules.registry import CountryRegistry
from euredact.rules.structural import detect_structural_dob
from euredact.rules.suppressors import should_suppress_claim, should_suppress_span
from euredact.types import CountryEvidence, Detection, DetectionSource, EntityType


def _mask_atoms(pattern: str) -> str:
    """Replace escapes and character classes with one placeholder char each.

    Equal fragments get equal placeholders and unequal fragments get unequal
    ones, so the structural comparisons below still distinguish ``[0-9]`` from
    ``[a-z]``. Collapsing every class to the same letter — which the previous
    version did — would have read ``([0-9]|[a-z])+`` as a repeated alternation
    of two identical branches and rejected it.
    """
    tokens: dict[str, str] = {}
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            frag, i = pattern[i : i + 2], i + 2
        elif ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":  # literal ] as first member
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            frag, i = pattern[i : j + 1], j + 1
        else:
            out.append(ch)
            i += 1
            continue
        tok = tokens.get(frag)
        if tok is None:
            # Private-use range: cannot collide with anything in the source.
            tok = chr(0xE000 + len(tokens))
            tokens[frag] = tok
        out.append(tok)
    return "".join(out)


def _repeats_more_than_once(masked: str, pos: int) -> bool:
    """Is there a quantifier at *pos* that can repeat its atom 2+ times?"""
    if pos >= len(masked):
        return False
    ch = masked[pos]
    if ch in "*+":
        return True
    if ch != "{":
        return False
    close = masked.find("}", pos)
    if close == -1:
        return False
    spec = masked[pos + 1 : close]
    if "," not in spec:
        return spec.isdigit() and int(spec) > 1
    low, _, high = spec.partition(",")
    if not high:  # {n,} is unbounded
        return True
    return high.isdigit() and int(high) > 1


def _split_alternatives(body: str) -> list[str]:
    """Top-level ``|`` branches of *body*, ignoring nested groups."""
    branches, depth, start = [], 0, 0
    for i, ch in enumerate(body):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            branches.append(body[start:i])
            start = i + 1
    branches.append(body[start:])
    return branches


_GROUP_PREFIX_RE = re.compile(r"^\?(?:P<[^>]*>|P=[^)]*|<[=!]|[:=!>#]|[aiLmsux]*[-aiLmsux]*:)")


def _risky_repetition(pattern: str) -> str | None:
    """Describe the first repetition-related ReDoS risk found, else None.

    Deliberately conservative: it reports *shapes* known to backtrack badly
    rather than proving a pattern unsafe, and it cannot certify one safe.
    """
    masked = _mask_atoms(pattern)
    stack: list[int] = []
    for i, ch in enumerate(masked):
        if ch == "(":
            stack.append(i)
            continue
        if ch != ")" or not stack:
            continue
        start = stack.pop()
        if not _repeats_more_than_once(masked, i + 1):
            continue
        body = _GROUP_PREFIX_RE.sub("", masked[start + 1 : i])

        # A quantifier inside a repeated group: (a+)+, (a{1,10})+, (\w+\s?)*
        for j, inner in enumerate(body):
            if inner in "*+" or (inner == "{" and _repeats_more_than_once(body, j)):
                return (
                    "a quantifier inside a repeated group (e.g. (a+)+), which "
                    "makes the number of ways to split the input grow "
                    "exponentially"
                )

        # An ambiguous alternation inside a repeated group: (a|a)+, (\d|\d\d)+.
        # Distinct branches such as (A|B)+ are unambiguous and allowed.
        branches = _split_alternatives(body)
        if len(branches) > 1:
            for a_idx, first in enumerate(branches):
                for second in branches[a_idx + 1 :]:
                    if first == second or first.startswith(second) or second.startswith(first):
                        return (
                            "a repeated group whose alternatives overlap "
                            "(e.g. (a|a)+ or (a|ab)+), so the same text can be "
                            "matched in exponentially many ways"
                        )
    return None


def _validate_custom_pattern(pattern: str) -> None:
    """Validate a custom regex pattern for syntax and basic ReDoS safety.

    The ReDoS screen is a conservative heuristic over known-bad shapes, not a
    proof of safety — the previous version only recognised the literal spelling
    ``+)+``, so ``(a|a)+``, ``(a{1,10})+`` and ``^(\\w+\\s?)*$`` all passed and
    then ran exponentially. Treat a pattern that passes as *not obviously*
    catastrophic; do not accept patterns from untrusted input on the strength
    of this check alone.
    """
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc
    risk = _risky_repetition(pattern)
    if risk is not None:
        raise ValueError(
            f"Pattern contains {risk}. This can cause catastrophic "
            f"backtracking (ReDoS). Restructure the pattern so that no "
            f"repeated group can match the same text two different ways."
        )


# ── Local cues: what the document calls the value next to it ────────────
#
# Country evidence resolves which *national scheme* owns an ambiguous value, but
# it never looks at the label sitting immediately in front of it. So
# "Phone: 0705237535" was reported as a Swedish national ID: the digits pass that
# checksum, the document is Swedish, and nothing consulted the word "Phone".
#
# A cue touching the span is the strongest statement the document makes about
# what the value *is*. It therefore outranks the checksum — but only among
# candidates covering the **same span**, so it decides the label and can never
# change which characters are masked. That is what keeps invariant I1 intact.
#
# Measured: 263 phone numbers were reported as national IDs and 18 French SIREN
# as national IDs, each with an explicit cue in front of it.
_LOCAL_CUES: tuple[tuple[EntityType, re.Pattern[str]], ...] = (
    (EntityType.PHONE, re.compile(
        r"(?:phone|tel|telephone|téléphone|telefoon|telefon|telefono|teléfono"
        r"|tlf|mobil|mobile|gsm|handy|sími|puh|móvil|cell)\w*\s*[:.\-]?\s*$",
        re.IGNORECASE)),
    (EntityType.CHAMBER_OF_COMMERCE, re.compile(
        r"(?:siren|siret|kbo|bce|kvk|ondernemingsnummer|handelsregister"
        r"|company\s*(?:no|number|reg)|organisationsnummer|orgnr)\w*"
        r"\s*[:.\-]?\s*$", re.IGNORECASE)),
    (EntityType.VAT, re.compile(
        r"(?:vat|btw|tva|ust|iva|moms|alv|mwst)[\w.\-]*\s*[:.\-]?\s*$",
        re.IGNORECASE)),
    (EntityType.BIC, re.compile(
        r"(?:bic|swift)[\w/]*\s*[:.\-]?\s*\(?\s*$", re.IGNORECASE)),
    (EntityType.NATIONAL_ID, re.compile(
        r"(?:bsn|personnummer|rijksregisternummer|national\s*id"
        r"|identiteitsnummer|henkilötunnus|kennitala|cpr|nif|dni)\w*"
        r"\s*[:.\-]?\s*$", re.IGNORECASE)),
)

#: How far back a cue may sit. Short on purpose: a cue is only evidence about
#: the value it introduces, which is the lesson of the postal-code year defect,
#: where a cue 150 characters away licensed every number in the window.
_CUE_WINDOW = 22


def _local_cue_bonus(text: str, start: int, entity_type: object) -> int:
    """1 when a cue naming *entity_type* sits immediately before the span."""
    before = text[max(0, start - _CUE_WINDOW):start]
    for cued_type, pattern in _LOCAL_CUES:
        if cued_type == entity_type and pattern.search(before):
            return 1
    return 0


def check_country_arg(value: object, param: str) -> None:
    """Reject a bare string where a list of country codes is expected.

    ``countries="NL"`` is iterable, so Python walks it into the codes ``"N"``
    and ``"L"``. Neither resolves, so nothing is declared — and every detection
    that *does* carry a country is then flagged ``out_of_scope``. A caller
    following the documented pattern of filtering on that field silently keeps
    none of them, while ``redacted_text`` still looks perfectly correct. The
    failure direction is "no PII here", from a one-character typo.

    A wrong *code* is data and only warns (see ``CountryRegistry.warn_unknown``)
    — raising there would invite callers to wrap redaction in try/except and
    skip it. A wrong *type* is a programming error, surfaces immediately, and
    has no correct interpretation to fall back on.
    """
    if isinstance(value, (str, bytes)):
        shown = value.decode(errors="replace") if isinstance(value, bytes) else value
        raise TypeError(
            f"{param} must be a list of country codes, not a bare string. "
            f"Pass {param}=[{shown!r}] rather than {param}={shown!r} — a string "
            f"is iterated character by character, which silently declares "
            f"nothing and flags every detection out_of_scope."
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

    def generate_candidates(self, text: str) -> list[RawMatch]:
        """Produce every candidate span in *text*, for every country.

        The **only** call site of :meth:`MultiPatternMatcher.scan`, and it takes
        no country argument — deliberately. Candidate generation must not depend
        on which country the caller declared, because a wrong or absent country
        would then cause a silent miss, and a missed entity in a redaction tool
        is invisible in testing and surfaces in a breach report.

        Country influences *scoring* — which candidate wins a contested span,
        and how a detection is flagged — never what is looked for. See
        ``tests/test_invariant_generation.py``, which asserts that this
        signature has no country parameter and that the candidate set is
        identical under every possible ``countries=`` value.
        """
        self.load_countries(None)
        return self._matcher.scan(text, None)

    def detect(self, text: str, country_codes: list[str] | None = None) -> list[Detection]:
        """Detect PII in text using the two-pass architecture.

        Pass 1: Liberal pattern matching, country-blind
        Pass 2: Suppression filters + checksum validation, country-aware scoring
        """
        return self.detect_with_evidence(text, country_codes)[0]

    def detect_with_evidence(
        self,
        text: str,
        country_codes: list[str] | None = None,
        country_hint: list[str] | None = None,
        prior_evidence: list[CountryEvidence] | None = None,
    ) -> tuple[list[Detection], list[CountryEvidence], dict[str, float]]:
        """:meth:`detect`, plus the country evidence it reasoned from.

        Returns ``(detections, evidence, scores)`` where *scores* maps country
        to accumulated log-odds. Exposed so a caller can audit why an ambiguous
        value was attributed to one national scheme over another.

        *country_codes* is **scope**: it flags detections from elsewhere as
        ``out_of_scope`` and, like *country_hint*, contributes a prior.
        *country_hint* is **only** a prior — it helps resolve ambiguity without
        marking anything out of scope. Neither gates what is looked for.

        *prior_evidence* is evidence carried in from elsewhere — earlier chunks
        of the same document, via :class:`~euredact.rules.context.DocumentContext`.
        It is scored alongside this text's own evidence but is **not** returned,
        so a caller accumulating evidence never counts it twice.
        """
        check_country_arg(country_codes, "countries")
        check_country_arg(country_hint, "country_hint")

        raw_matches = self.generate_candidates(text)

        # The declared countries are a scoring signal from here on: they rank
        # candidates and flag out-of-scope detections. They do not gate.
        declared: set[str] | None = None
        if country_codes is not None:
            resolved = set()
            for code in country_codes:
                match_code = self._registry.resolve(code)
                if match_code is None:
                    # Generation no longer consults the registry, so warn here
                    # instead — a caller passing an unrecognised code should
                    # still hear about it.
                    self._registry.warn_unknown(code)
                else:
                    resolved.add(match_code)
            declared = resolved | {"SHARED", "CUSTOM"}

        # The prior fed to the evidence bus. Declared countries count too — a
        # caller naming a country is asserting context, which is exactly what a
        # prior is — but a hint never narrows scope, so it is kept out of
        # `declared` and cannot flag anything out_of_scope.
        prior: set[str] = set(declared) if declared else set()
        for code in country_hint or ():
            resolved_hint = self._registry.resolve(code)
            if resolved_hint is None:
                self._registry.warn_unknown(code)
            else:
                prior.add(resolved_hint)

        # Pass 2a: checksum validation + collect failed-validator spans.
        #
        # A span that matched a checksummed pattern but failed the checksum is
        # recognisably a specific entity gone wrong (e.g. IBAN-shaped), so a
        # regex-only match inside it is weak evidence. It is *demoted* below
        # every other candidate rather than deleted — see the priority
        # assignment below for why deletion was wrong.
        validated: list[tuple[RawMatch, bool]] = []  # (match, is_valid)
        failed_spans: list[tuple[int, int, str]] = []
        for m in raw_matches:
            is_valid = self._matcher.validate(m)
            if is_valid:
                validated.append((m, m.pattern_def.validator is not None))
            elif m.pattern_def.validator is not None and not m.pattern_def.requires_context:
                failed_spans.append(
                    (m.start, m.end, m.country_code, m.pattern_def.entity_type)
                )

        # Evidence pass: work out which countries this document belongs to,
        # from the entities that carry their country in the string. Runs on
        # surviving candidates rather than final detections, because waiting
        # for deduplication would mean deduplicating twice.
        #
        # Every surviving candidate is eligible, not only checksum-backed ones.
        # An earlier version required a validator here, which silently dropped
        # the email ccTLD — the second-strongest signal at 4.50 log-odds and
        # present in 98,949 of 152,300 corpus documents — because EMAIL has
        # nothing to checksum. That left most documents with no evidence at
        # all. Candidates that failed a validator never reach `validated`, so
        # this admits the unvalidatable, not the invalid.
        #
        # Emitters are self-gating on the evidence-bearing substring rather
        # than the pattern's country: _emit_e164 requires a literal `+CC`, and
        # collect() dedupes by (span, source), so eleven countries' phone
        # patterns matching one number yield one piece of evidence, not eleven.
        evidence_dets = [
            Detection(
                entity_type=m.pattern_def.entity_type,
                start=m.start, end=m.end, text=m.text,
                source=DetectionSource.RULES,
                country=m.country_code if m.country_code not in ("SHARED", "CUSTOM") else None,
            )
            for m, _has_validator in validated
            if m.pattern_def.entity_type in evidence_mod.EVIDENCE_TYPES
        ]
        country_evidence = evidence_mod.collect(evidence_dets)
        # Score against this chunk's evidence plus whatever earlier chunks
        # established. Only this chunk's is returned — see the docstring.
        country_scores = evidence_mod.accumulate(
            (country_evidence + prior_evidence) if prior_evidence else country_evidence,
            prior,
        )

        # Now that the document's countries are known, decide which failed
        # validators are entitled to demote anything. A checksum failure only
        # means "not a valid X"; it says nothing about the span unless X was
        # plausible here in the first place. A Belgian national-ID pattern
        # failing on 0612345678 is not evidence against that span being a Dutch
        # phone number — and demoting on it cost every PHONE candidate in the
        # document its rank, which is how a Dutch mobile came back as a Danish
        # NATIONAL_ID even after the digits were correctly ranked.
        # Two rules, because a failed checksum carries two different messages
        # depending on how the spans line up.
        #
        # Same type, any containment: "these digits are not a valid X" is
        # evidence against X, not against the span. Demoting *every* type on an
        # equal span meant Sweden's own personnummer checksum failing on
        # 0708787668 demoted the Swedish *phone* candidate for the same digits,
        # handing the span to a Danish CPR that happened to validate — 878
        # mistyped phone numbers per 30,000 documents.
        #
        # Any type, strict subset: a candidate covering only *part* of a
        # rejected identifier is a fragment of it, not a different entity. The
        # generic separator-tolerant phone pattern claimed characters 3-14 of
        # the rejected Belgian national number in
        # "Rijksregisternummer: 85.03.19-284.73" and reported it as a PHONE.
        # This is the case the original suppression zones were written for —
        # licence-plate fragments inside an invalid IBAN — which the per-type
        # split above had given up along with the over-reach.
        #
        # An equal span is two schemes competing for the whole value; a strict
        # subset is one scheme picking over another's wreckage.
        corroborated: list[tuple[int, int, object]] = [
            (start, end, etype)
            for start, end, cc, etype in failed_spans
            if not country_scores or cc in ("SHARED", "CUSTOM") or cc in country_scores
        ]
        corroborated.sort()

        # Fragment detection deliberately ignores corroboration and uses every
        # failed span, because it *removes* candidates and must therefore be
        # country-blind. Gating it on the document's countries made the set of
        # spans found depend on `countries=`, which is precisely invariant I1 —
        # caught by tests/test_invariant_generation.py within seconds of being
        # written. Demotion may be country-aware because it only reorders; a
        # demoted candidate still claims a span nothing else wants.
        #
        # Kept unmerged: merging adjacent spans would invent strict-subset
        # relationships that neither original span had.
        all_failed = sorted((start, end) for start, end, _cc, _et in failed_spans)
        strict_starts = [f[0] for f in all_failed]

        # Running maximum of the end offsets, so the fragment test below can
        # answer "does any span starting at or before me reach past my end?"
        # in O(1) instead of walking the whole prefix. `failed_prefix_max[i]`
        # is the largest end among `all_failed[:i]`; index 0 is the empty
        # prefix. Without this the fragment test was O(candidates x spans) —
        # 125M iterations on a 1 MB document, ~43% of total runtime.
        failed_prefix_max = [0] * (len(all_failed) + 1)
        running_max = 0
        for i, (_zs, ze) in enumerate(all_failed):
            if ze > running_max:
                running_max = ze
            failed_prefix_max[i + 1] = running_max

        by_type: dict[object, list[tuple[int, int]]] = {}
        for start, end, etype in corroborated:
            by_type.setdefault(etype, []).append((start, end))

        # Merge overlapping zones per type and index them for O(log n)
        # containment checks instead of O(n) per match.
        zones: dict[object, tuple[list[int], list[int]]] = {}
        for etype, spans in by_type.items():
            spans.sort()
            starts: list[int] = []
            ends: list[int] = []
            ms, me = spans[0]
            for zs, ze in spans[1:]:
                if zs <= me:
                    me = max(me, ze)
                else:
                    starts.append(ms)
                    ends.append(me)
                    ms, me = zs, ze
            starts.append(ms)
            ends.append(me)
            zones[etype] = (starts, ends)

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
        # (priority, in_scope, start, end, match, prebuilt). in_scope ranks
        # candidates within a priority tier; it never removes any.
        candidates: list[
            tuple[int, int, int, float, int, int, int, RawMatch | None,
                  Detection | None]
        ] = []
        for match, has_valid_validator in validated:
            # A validator-less match inside a failed-validation span used to be
            # deleted outright. Measured across the corpus, that mechanism
            # removed 454 detections of which 454 overlapped real labelled PII
            # — it bought no precision at all — and cost 1.05 points of recall
            # with country hints and 5.01 without, because one country's failed
            # checksum silently deleted another country's correct detection.
            #
            # It is now a demotion instead: such a candidate may still claim a
            # span that nothing else wants, but loses to every other candidate.
            # Demotion cannot silence a detection, which is the property that
            # deletion lacked.
            demoted = False
            if match.pattern_def.validator is None:
                zone = zones.get(match.pattern_def.entity_type)
                if zone is not None:
                    zone_starts, zone_ends = zone
                    idx = bisect.bisect_right(zone_starts, match.start) - 1
                    demoted = idx >= 0 and zone_ends[idx] >= match.end
            # Strict subset of a rejected identifier, whatever its type: the
            # candidate covers only part of something already recognised and
            # rejected, so it is a fragment of that, not a separate entity.
            #
            # Dropped rather than demoted. Demotion cannot help here: nothing
            # else wants a fragment, so a demoted candidate still wins its span
            # by default — the generic phone pattern kept claiming characters
            # 3-14 of a rejected Belgian national number. Dropping is safe in a
            # way that whole-span deletion was not, because the characters stay
            # covered by whatever claims the enclosing span, or by nothing —
            # and "nothing" is the right answer for the tail of a rejected
            # identifier.
            fragment = False
            if match.pattern_def.validator is None and not demoted:
                hi = bisect.bisect_right(strict_starts, match.start)
                # Every span in all_failed[:hi] starts at or before match.start,
                # so containment reduces to how far the furthest one reaches.
                reach = failed_prefix_max[hi]
                if reach > match.end:
                    # Something starting no later than us ends strictly later:
                    # we are a proper subset of it.
                    fragment = True
                elif reach == match.end:
                    # Same end offset — a proper subset only if some span with
                    # that end starts strictly earlier. Scanning backwards finds
                    # the enclosing span first; the equal case is rare enough
                    # that the walk does not show up in the profile.
                    for i in range(hi - 1, -1, -1):
                        zs, ze = all_failed[i]
                        if ze == match.end and zs < match.start:
                            fragment = True
                            break
            if fragment:
                continue

            if demoted:
                priority = -1
                blind_priority = -1
            elif has_valid_validator:
                # A passing checksum normally outranks everything. But a
                # checksum only says the digits fit *some* national scheme, and
                # weak ones fit by luck — a mod-11 scheme accepts a random
                # number about one time in eleven. So a validated candidate
                # from a country the document shows no trace of is treated as
                # coincidence, not evidence.
                #
                # Concretely: the Dutch phone number 0612345678 also passes the
                # Danish CPR checksum. Without this, it is reported as a Danish
                # NATIONAL_ID in a document that is otherwise unmistakably
                # Dutch — measured at 306 phone numbers lost and 312 spurious
                # national IDs on 3,000 documents.
                #
                # Entities that carry their own country vouch for themselves:
                # an IBAN emits evidence for its own country, so a foreign IBAN
                # in a domestic invoice keeps its rank.
                vouched = (
                    not country_scores
                    or match.country_code in ("SHARED", "CUSTOM")
                    or match.country_code in country_scores
                )
                priority = 3 if vouched else 1
                blind_priority = 3
            elif match.country_code == "CUSTOM":
                priority = 2
                blind_priority = 2
            elif match.pattern_def.entity_type == EntityType.POSTAL_CODE:
                # A bare digit run is the weakest evidence in the engine and
                # must never re-cut a span a structured detector claims
                # (PHONE, SSN, NATIONAL_ID, BANK_ACCOUNT, VAT...). Postal
                # codes take unclaimed spans only, whatever the span lengths.
                priority = 0
                blind_priority = 0
            else:
                priority = 1
                blind_priority = 1

            in_scope = 1 if (declared is None or match.country_code in declared) else 0
            country_score = country_scores.get(match.country_code, 0.0)
            cue = _local_cue_bonus(text, match.start, match.pattern_def.entity_type)
            candidates.append(
                (blind_priority, cue, priority, country_score, in_scope,
                 match.start, match.end, match, None)
            )

        # Structural detectors (JSON field names, CSV headers). These arrive as
        # finished Detections, carry no RawMatch, and are not suppressed.
        for d in detect_structural_dob(text):
            candidates.append((1, 0, 1, 0.0, 1, d.start, d.end, None, d))

        # Deduplicate: validated > custom > regex-only, then longer wins
        detections = self._deduplicate(text, candidates, declared)

        # Sort by position
        detections.sort(key=lambda d: (d.start, -d.end))

        # Attach the confidence behind each country attribution, so a caller
        # can tell "Danish, and the document is plainly Danish" from "Danish,
        # on a checksum alone".
        ranking = evidence_mod.weights_to_ranking(country_scores)
        if ranking:
            detections = [
                replace(d, country_confidence=ranking[d.country])
                if d.country in ranking else d
                for d in detections
            ]
        return detections, country_evidence, country_scores

    @staticmethod
    def _deduplicate(
        text: str,
        candidates: list[
            tuple[int, int, int, float, int, int, int, RawMatch | None,
                  Detection | None]
        ],
        declared: set[str] | None = None,
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

        # Ordering between *different* spans is country-blind; the country
        # only ever picks the winner among candidates covering the *same* span.
        #
        # That split is what makes invariant I1 structural rather than merely
        # tested. Country-aware promotion had twice decided which span won:
        # under countries=["NL"] a validated national ID outranked a longer IP
        # address and exposed ".77", and two equal-length candidates at
        # different offsets swapped places. Both were found by sweeping the
        # corpus, not by reasoning, and both are impossible now — the key below
        # is country-blind up to and including `start`, and (length, start)
        # already identifies a span uniquely.
        #
        # Ordering, in words: longest first (a shorter match winning re-cuts a
        # longer one and leaks the remainder), then the structural tier, then
        # leftmost. Only after a span is fixed do the country-aware fields
        # break the tie, deciding the label rather than the extent.
        #
        # The structural tier is a property of the *span*, not of the candidate:
        # the best tier anything claiming those exact characters can offer. Used
        # per candidate it would also discriminate *within* a span, where the
        # country-aware tier is supposed to have the final word — that silently
        # disabled country inference entirely, handing every ambiguous value to
        # whichever foreign scheme happened to validate.
        span_tier: dict[tuple[int, int], int] = {}
        for c in candidates:
            key = (c[5], c[6])
            if c[0] > span_tier.get(key, -2):
                span_tier[key] = c[0]

        sorted_cands = sorted(
            candidates,
            key=lambda c: (
                -(c[6] - c[5]),                # longest first    } country-blind
                -span_tier[(c[5], c[6])],      # best tier here   } — decides
                c[5],                          # leftmost         } WHICH span
                -c[1],                         # local cue        } country-aware
                -c[2],                         # country priority } — decides the
                -c[3],                         # country evidence } LABEL only
                -c[4],                         # declared scope   }
            ),
        )
        result: list[Detection] = []
        occupied: set[int] = set()
        span_verdicts: dict[tuple[object, int, int], bool] = {}

        for (_bp, _cue, _prio, _score, in_scope,
             start, end, match, prebuilt) in sorted_cands:
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
                    out_of_scope=not in_scope,
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
