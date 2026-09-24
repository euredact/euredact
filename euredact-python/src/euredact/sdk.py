"""Orchestrator: runs the detection pipeline and applies replacements."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import unicodedata
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Callable, Iterator, Mapping

from euredact.cache import ResultCache
from euredact.normalizer import map_offset_to_original, normalize
from euredact.rules.context import DocumentContext
from euredact.rules.engine import RuleEngine, check_country_arg
from euredact.rules.evidence import weights_to_ranking
from euredact.types import Detection, EntityType, Exemption, RedactResult

# Date entity types — opt-in via detect_dates=True
_DATE_TYPES = frozenset({EntityType.DOB, EntityType.DATE_OF_DEATH})

# Default thread pool for async offloading
_DEFAULT_POOL = ThreadPoolExecutor()


def _apply_replacements(
    text: str,
    detections: list[Detection],
    label_for: Callable[[Detection, str], str],
) -> str:
    """Splice a label over every detection and return the masked text.

    *detections* must be sorted by ``(start, -end)``. *label_for* receives the
    detection and the exact slice of *text* the label replaces, and returns the
    label.

    Labels are resolved right-to-left because the referential mapper numbers
    each entity type in call order, and that order is part of the output
    contract. The string itself is then assembled in a single forward pass:
    rebuilding it per detection copied the whole document each time, which is
    O(document x detections) -- 268 ms of pure copying on a 1 MB document with
    8,000 detections, versus 0.7 ms here.

    Spans from the rule engine are deduplicated and non-overlapping. Spans
    from elsewhere (the cloud service) are only sorted, so a span may start
    behind the cursor. Its uncovered tail is still masked rather than dropped:
    dropping the span would leave those characters in the clear, and splicing
    it whole would corrupt the label already emitted over its head.
    """
    kept: list[tuple[Detection, int, int]] = []
    pos = 0
    for det in detections:
        start = max(det.start, pos)
        if det.end <= start:
            continue
        kept.append((det, start, det.end))
        pos = det.end

    labels: list[str] = [""] * len(kept)
    for idx in range(len(kept) - 1, -1, -1):
        det, start, end = kept[idx]
        labels[idx] = label_for(det, text[start:end])

    parts: list[str] = []
    pos = 0
    for (_det, start, end), label in zip(kept, labels):
        parts.append(text[pos:start])
        parts.append(label)
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


class ReferentialMapper:
    """Maps real PII values to consistent labels within a session.

    Ensures referential integrity: the same input value always maps to
    the same label (e.g. ``EMAIL_1``), so relationships between
    occurrences are preserved in the redacted output.

    .. warning::
       The mapping is keyed on the **raw PII value** and is never evicted —
       evicting would hand a previously seen value a second label and quietly
       break the guarantee above. Two consequences worth designing around:

       * It grows for as long as the process runs. Call :meth:`clear` (or
         :meth:`EuRedact.clear`) between workloads; a warning is emitted once
         the mapping passes :data:`MAPPING_WARN_THRESHOLD` entries.
       * Labels are shared by every caller of the same instance — including
         every caller of the module-level :func:`euredact.redact`. A label
         repeated across two documents reveals that they contain the same
         underlying value, so give each tenant its own :class:`EuRedact`
         instance rather than sharing the module-level one.
    """

    #: Entry count at which a one-time warning is emitted.
    MAPPING_WARN_THRESHOLD = 100_000

    def __init__(self) -> None:
        self._counters: dict[EntityType, int] = {}
        self._mapping: dict[str, str] = {}
        self._warned = False

    def get_label(self, text: str, entity_type: EntityType | str) -> str:
        """Return consistent label. Same input always returns same output."""
        if text not in self._mapping:
            self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
            n = self._counters[entity_type]
            type_label = entity_type.value if isinstance(entity_type, EntityType) else entity_type
            self._mapping[text] = f"{type_label}_{n}"
            if not self._warned and len(self._mapping) > self.MAPPING_WARN_THRESHOLD:
                self._warned = True
                warnings.warn(
                    f"Referential integrity mapping holds "
                    f"{len(self._mapping)} raw PII values and is never evicted. "
                    f"Call clear() between workloads to release them.",
                    ResourceWarning,
                    stacklevel=2,
                )
        return self._mapping[text]

    def clear(self) -> None:
        """Remove all stored PII mappings from memory."""
        self._counters.clear()
        self._mapping.clear()


#: Types whose separators are presentational: the same identifier stays the
#: same value however it is spaced, hyphenated or dotted. An allowlisted IBAN
#: must be exempted whether the document writes NL91ABNA0417164300 or
#: NL91 ABNA 0417 1643 00 (issue rules-engine#15).
#:
#: Free-text types are deliberately absent. Folding separators in an address
#: would make `jan.devries@acme.be` exempt `jandevries@acme.be`, a different
#: mailbox at most providers; folding an organisation name would make
#: `ACME NV` exempt `ACMENV`, which can be a different company.
_SEPARATOR_INSENSITIVE = frozenset({
    EntityType.BANK_ACCOUNT, EntityType.BIC, EntityType.CREDIT_CARD,
    EntityType.PHONE, EntityType.VAT, EntityType.NATIONAL_ID, EntityType.SSN,
    EntityType.TAX_ID, EntityType.PASSPORT, EntityType.DRIVERS_LICENSE,
    EntityType.RESIDENCE_PERMIT, EntityType.HEALTH_INSURANCE,
    EntityType.CHAMBER_OF_COMMERCE, EntityType.IMEI, EntityType.VIN,
})

#: Types that carry a domain an owner may want exempted wholesale.
_DOMAIN_BEARING = frozenset({EntityType.EMAIL, EntityType.URL})

_SEPARATORS = re.compile(r"[\s.\-/()]+")


def check_allowlist_arg(value: object, param: str = "allowlist") -> None:
    """Reject a bare string where a list of allowlisted values is expected.

    ``allowlist="ACME NV"`` is iterable, so it would become the one-character
    entries ``"A"``, ``"C"``, ... -- none of which is a whole detection, so
    nothing is exempted and the caller's own name is redacted after all. Same
    reasoning as :func:`check_country_arg`: a wrong type is a programming
    error with no correct interpretation to fall back on.
    """
    if isinstance(value, (str, bytes)):
        shown = value.decode(errors="replace") if isinstance(value, bytes) else value
        raise TypeError(
            f"{param} must be a list of values, not a bare string. "
            f"Pass {param}=[{shown!r}] rather than {param}={shown!r}.")


def _allowlist_key(value: str) -> str:
    """The form an allowlist entry and a detected value are compared in.

    NFC because the rule engine matches on NFC-normalised text while the
    document may be NFD; case-insensitive because an org name in a heading
    is the same org name.
    """
    return unicodedata.normalize("NFC", value).strip().lower()


def _folded_key(value: str) -> str:
    """:func:`_allowlist_key` with presentational separators removed."""
    return _SEPARATORS.sub("", _allowlist_key(value))


def _normalize_allowlist(values: list[str] | None) -> dict[str, str]:
    """Comparison key -> the entry as the caller wrote it (for reporting)."""
    check_allowlist_arg(values)
    out: dict[str, str] = {}
    for v in values or ():
        if v and v.strip():
            out.setdefault(_allowlist_key(v), v)
            out.setdefault(_folded_key(v), v)
    return out


def _normalize_domains(values: list[str] | None) -> dict[str, str]:
    """Domain key -> the entry as written. A leading ``@`` or ``.`` is ignored."""
    check_allowlist_arg(values, "allowlist_domains")
    out: dict[str, str] = {}
    for v in values or ():
        if v and v.strip():
            out.setdefault(_allowlist_key(v).lstrip("@."), v)
    return out


def _domain_of(entity_type: EntityType | str, value: str) -> str | None:
    """The domain an exemption rule would apply to, or None."""
    if entity_type not in _DOMAIN_BEARING:
        return None
    v = _allowlist_key(value)
    if "@" in v:
        return v.rsplit("@", 1)[1].strip("<>[](),;:\"'")
    v = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", v)
    return v.split("/", 1)[0].split(":", 1)[0].strip("<>[](),;:\"'") or None


def _matching_rule(
    det: Detection, slice_: str, allowed: dict[str, str], domains: dict[str, str]
) -> tuple[str, str] | None:
    """The (rule, kind) exempting this detection, or None.

    Both the original slice and the detection's own text are checked: the two
    differ when normalisation changed the document, and the cloud tier's text
    is whatever the service reported.
    """
    for candidate in (slice_, det.text):
        if not candidate:
            continue
        rule = allowed.get(_allowlist_key(candidate))
        if rule is not None:
            return rule, "value"
        if det.entity_type in _SEPARATOR_INSENSITIVE:
            rule = allowed.get(_folded_key(candidate))
            if rule is not None:
                return rule, "value"
        host = _domain_of(det.entity_type, candidate)
        if host:
            for owned, entry in domains.items():
                if host == owned or host.endswith("." + owned):
                    return entry, "domain"
    return None


def _apply_allowlist(
    text: str,
    detections: list[Detection],
    allowed: dict[str, str],
    domains: dict[str, str],
) -> tuple[list[Detection], list[Exemption]]:
    """Split detections into those to redact and those the caller exempted.

    Whole span only: ``euredact.be`` as a *value* does not exempt
    ``joren@euredact.be``; that is what ``allowlist_domains`` is for.
    """
    if not allowed and not domains:
        return detections, []
    kept: list[Detection] = []
    exempted: list[Exemption] = []
    for d in detections:
        hit = _matching_rule(d, text[d.start : d.end], allowed, domains)
        if hit is None:
            kept.append(d)
        else:
            rule, kind = hit
            exempted.append(Exemption(
                entity_type=d.entity_type, start=d.start, end=d.end,
                text=text[d.start : d.end], rule=rule, rule_kind=kind))
    return kept, exempted


#: Characters a token suffix is drawn from. No vowels, so a suffix never spells
#: a word; no 0/1/I/O, so it survives being read back by a person; no
#: underscore, so the type prefix stays unambiguous.
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TOKEN_SUFFIX_LENGTH = 4
_TOKEN_MAX_DRAWS = 100


def _type_label(entity_type: EntityType | str) -> str:
    return entity_type.value if isinstance(entity_type, EntityType) else entity_type


class TokenMapper:
    """Maps each distinct PII value in one call to a reversible token.

    A token is ``TYPE_XXXX``: the entity type, then :data:`TOKEN_SUFFIX_LENGTH`
    random characters from :data:`TOKEN_ALPHABET`. The same value gets the same
    token within the call, so relationships survive; across calls it gets a
    different one, so two tokenized documents never reveal a shared value.

    Nothing is kept beyond the call. The mapping goes to the caller in
    :attr:`RedactResult.tokens`, and only the caller can turn it back into
    text with :func:`restore`.

    Tokens are also kept clear of any token-shaped string already in the
    document. A caller that redacts an LLM's reply to a tokenized prompt has
    exactly such a document, and a fresh token colliding with an old one would
    make :func:`restore` put the wrong value back.
    """

    def __init__(self, text: str, detections: list[Detection]) -> None:
        self._by_value: dict[str, str] = {}
        self._tokens: dict[str, str] = {}
        self._taken: set[str] = set()
        types = {_type_label(d.entity_type) for d in detections}
        if types:
            shaped = re.compile(
                "(?:" + "|".join(re.escape(t) for t in sorted(types)) + ")"
                f"_[{TOKEN_ALPHABET}]{{{TOKEN_SUFFIX_LENGTH}}}"
            )
            self._taken.update(m.group(0) for m in shaped.finditer(text))

    def get_token(self, det: Detection, value: str) -> str:
        """Return the token for *value*, minting one on first sight."""
        token = self._by_value.get(value)
        if token is None:
            prefix = _type_label(det.entity_type) + "_"
            for _ in range(_TOKEN_MAX_DRAWS):
                suffix = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_SUFFIX_LENGTH))
                token = prefix + suffix
                if token not in self._taken:
                    break
            else:
                raise RuntimeError(
                    f"could not mint a unique token with prefix {prefix!r} "
                    f"after {_TOKEN_MAX_DRAWS} draws")
            self._taken.add(token)
            self._by_value[value] = token
            self._tokens[token] = value
        return token

    @property
    def tokens(self) -> dict[str, str]:
        """Token -> original value, for :attr:`RedactResult.tokens`."""
        return self._tokens


def restore(text: str, tokens: Mapping[str, str]) -> str:
    """Put the original values back into *text*.

    *tokens* is :attr:`RedactResult.tokens` from the ``redact(tokenize=True)``
    call that produced the text this one derives from -- typically the reply
    an LLM wrote to the tokenized prompt. Every occurrence of every token is
    replaced; a token an LLM glued to other characters (``EMAIL_K7Q2s``) is
    still restored, since leaving a token behind is the worse failure.
    """
    if not tokens:
        return text
    # Longest first so a token that is a prefix of another (custom pattern
    # names allow it) cannot be matched short. The replacement is a callable
    # so backslashes and group references in the original values are literal.
    pattern = re.compile("|".join(
        re.escape(t) for t in sorted(tokens, key=len, reverse=True)))
    return pattern.sub(lambda m: tokens[m.group(0)], text)


class EuRedact:
    """Main EuRedact SDK orchestrator."""

    DEFAULT_MAX_INPUT_LENGTH = 10_485_760  # ~10 MB of text

    def __init__(
        self,
        *,
        max_input_length: int = DEFAULT_MAX_INPUT_LENGTH,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
    ) -> None:
        """
        Args:
            max_input_length: Longest document ``redact`` accepts, in characters.
            allowlist: Values never to redact, for every call on this instance
                -- an organisation's own name, its own addresses. Merged with
                the per-call ``allowlist``. Matched whole, case-insensitively.
            allowlist_domains: Domains whose addresses are never redacted, e.g.
                ``["acme.be"]``. Applies to EMAIL and URL only, and covers
                subdomains. Merged with the per-call value.
        """
        self._engine = RuleEngine()
        self._cache = ResultCache()
        self._referential_mapper = ReferentialMapper()
        self._max_input_length = max_input_length
        self._allowlist = _normalize_allowlist(allowlist)
        self._allowlist_domains = _normalize_domains(allowlist_domains)

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Register a custom regex pattern detected as *name*."""
        self._engine.add_custom_pattern(name, pattern)
        self._cache.clear()

    def clear(self) -> None:
        """Clear the result cache and referential integrity mappings.

        Call this in long-running processes to free PII from memory.
        The cache and mapper will be rebuilt as new texts are processed.
        """
        self._cache.clear()
        self._referential_mapper.clear()

    def _label_for(
        self, referential_integrity: bool, token_mapper: TokenMapper | None
    ) -> Callable[[Detection, str], str]:
        """The label function for one call, given its output options."""
        if token_mapper is not None:
            return token_mapper.get_token
        if referential_integrity:
            mapper = self._referential_mapper
            return lambda det, _slice: mapper.get_label(det.text, det.entity_type)
        return lambda det, _slice: f"[{_type_label(det.entity_type)}]"

    def redact(
        self,
        text: str,
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        context: DocumentContext | None = None,
        chunk_offset: int = 0,
        mode: str = "rules",
        referential_integrity: bool = False,
        tokenize: bool = False,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
        detect_dates: bool = False,
        coref: bool = False,
        coref_model: str = "default",
        cache: bool = True,
    ) -> RedactResult:
        """Redact PII from text. Main entry point.

        Args:
            countries: Scope. Detections attributed elsewhere are flagged
                ``out_of_scope``, never dropped, and this also acts as a prior
                when resolving which national scheme owns an ambiguous value.
            country_hint: A prior only. Helps resolve ambiguity without
                narrowing scope or flagging anything out of scope. Neither
                argument gates what is looked for — see
                ``tests/test_invariant_generation.py``.
            context: Shares country evidence across the chunks of one
                document, so a chunk carrying no country signal of its own is
                still scored against what the rest of the document showed.
                Pass the same object for every chunk, with *chunk_offset* set
                to where the chunk starts in the whole document.
            chunk_offset: Offset of this chunk within the document. Used only
                to rebase spans recorded in *context*; the returned detections
                are always relative to *text*.
            detect_dates: Include date-of-birth / date-of-death detections.
                Off by default — bare dates without strong indicators are
                better handled by the cloud LLM tier. When True, the rule
                engine applies keyword and structural (JSON/CSV header)
                checks before emitting a date detection.
            tokenize: Replace each value with a reversible token
                (``EMAIL_K7Q2``) and return the token -> value mapping in
                ``RedactResult.tokens``; see :func:`restore`. Tokens are unique
                to the call. Cannot be combined with *referential_integrity*.
            allowlist: Values never to redact, matched whole and
                case-insensitively against each detection. Merged with the
                instance's allowlist.
        """
        # Step 0: argument and input-size guards. The country check runs here
        # as well as in the engine so that a bare string is rejected before any
        # work happens, and on every entry point that funnels through redact().
        check_country_arg(countries, "countries")
        check_country_arg(country_hint, "country_hint")
        if tokenize and referential_integrity:
            raise ValueError(
                "tokenize and referential_integrity are two label schemes for "
                "the same spans; pass one of them")
        allowed = {**self._allowlist, **_normalize_allowlist(allowlist)}
        domains = {**self._allowlist_domains, **_normalize_domains(allowlist_domains)}

        if mode == "cloud":
            # Routed before any local work: the service runs its own rules
            # engine, and running ours first would waste the pass and risk
            # disagreeing with it on version.
            return self._redact_cloud(
                text, countries=countries, country_hint=country_hint,
                context=context, chunk_offset=chunk_offset,
                referential_integrity=referential_integrity, tokenize=tokenize,
                allowed=allowed, domains=domains, coref=coref,
            )
        if mode != "rules":
            raise ValueError(
                f"unknown mode {mode!r}: expected 'rules' or 'cloud'")

        if len(text) > self._max_input_length:
            raise ValueError(
                f"Input text length ({len(text):,} chars) exceeds the maximum "
                f"({self._max_input_length:,} chars). Split the input or "
                f"increase max_input_length when constructing EuRedact."
            )

        # Step 1: Normalize
        normalized_text, offset_mapping = normalize(text)

        # Step 2: Check cache
        countries_tuple = tuple(sorted(c.upper() for c in countries)) if countries else ("ALL",)
        # country_hint changes attribution, so it must key the cache too.
        hint_key = ",".join(sorted(c.upper() for c in country_hint)) if country_hint else ""
        # referential_integrity changes the labels, not the spans, so a cached
        # bracketed result is the wrong answer for a labelled call on the same
        # text — it has to key the cache too.
        # JSON rather than a joined string: an entry may itself contain the
        # separator, and two different lists must never share a key.
        allow_key = json.dumps(sorted(allowed)) if allowed else ""
        if domains:
            allow_key += "|dom=" + json.dumps(sorted(domains))
        cache_mode = f"{mode}|dates={detect_dates}|hint={hint_key}|ri={referential_integrity}|tok={tokenize}|allow={allow_key}"
        # A context makes the result depend on evidence from other chunks, so
        # the text no longer identifies the result. Caching is disabled rather
        # than keyed on the context, whose contents change as chunks arrive.
        if context is not None:
            cache = False
        if cache:
            cache_key = self._cache.key(normalized_text, countries_tuple, cache_mode)
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        # Steps 3-6: Rule engine detection
        detections, evidence, country_scores = self._engine.detect_with_evidence(
            normalized_text, countries, country_hint,
            prior_evidence=context.evidence() if context is not None else None,
        )
        if context is not None:
            context.add(evidence, chunk_offset)

        # Map offsets back to original text if normalization changed length
        if offset_mapping is not None:
            # replace() rather than a field-by-field rebuild: this listed every
            # field explicitly and so silently dropped any new one, which is
            # how out_of_scope and country_confidence would have been lost on
            # exactly the inputs that need normalising.
            detections = [
                replace(
                    d,
                    start=map_offset_to_original(d.start, offset_mapping),
                    end=map_offset_to_original(d.end, offset_mapping),
                )
                for d in detections
            ]

        # Filter date types unless opted in
        if not detect_dates:
            detections = [d for d in detections if d.entity_type not in _DATE_TYPES]
        detections, exempted = _apply_allowlist(text, detections, allowed, domains)

        # Steps 7-13: [CLOUD EXTENSION] — no-ops in rules-only mode

        # Step 14: Sort detections by position
        detections.sort(key=lambda d: (d.start, -d.end))

        # Step 15: Apply replacements.
        token_mapper = TokenMapper(text, detections) if tokenize else None
        redacted = _apply_replacements(
            text, detections, self._label_for(referential_integrity, token_mapper)
        )

        # Step 16: [COREF EXTENSION] — no-op

        # Report the inference so it can be audited. Spans in `evidence` are
        # offsets into the normalised text, matching `detections`.
        ranked = sorted(
            weights_to_ranking(country_scores).items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        result = RedactResult(
            redacted_text=redacted,
            detections=detections,
            source="rules",
            degraded=False,
            inferred_countries=tuple(ranked),
            evidence=tuple(evidence),
            detection_mode="declared" if countries else "inferred",
            tokens=token_mapper.tokens if token_mapper is not None else {},
            exempted=exempted,
        )

        # Step 17: Cache
        if cache:
            self._cache.put(cache_key, result)

        return result

    def _redact_cloud(
        self,
        text: str,
        *,
        countries: list[str] | None,
        country_hint: list[str] | None,
        context: "DocumentContext | None",
        chunk_offset: int,
        referential_integrity: bool,
        tokenize: bool,
        allowed: dict[str, str],
        domains: dict[str, str],
        coref: bool,
    ) -> RedactResult:
        """Send the document to the cloud tier.

        Options the service cannot honour raise rather than being ignored.
        Silently dropping one would mean returning a result that does not match
        what was asked for -- which, for anything that changes which spans come
        back, is under-redaction wearing a plausible face.
        """
        from euredact.cloud.client import CloudClient

        if not countries or len(countries) != 1:
            raise ValueError(
                "cloud mode needs exactly one country, e.g. countries=['BE']. "
                "The model is trained and evaluated per country, so a "
                "multi-country request has no defined behaviour.")
        if country_hint:
            raise ValueError("country_hint is not supported in cloud mode")
        if context is not None or chunk_offset:
            raise ValueError(
                "context/chunk_offset are not supported in cloud mode: the "
                "model has never seen a chunk boundary, so the service rejects "
                "oversized input rather than splitting it")
        if referential_integrity:
            raise ValueError(
                "referential_integrity is not supported in cloud mode")
        if coref:
            raise ValueError("coref is not supported in cloud mode")

        # detect_dates is deliberately NOT forwarded. The service always runs
        # its rules engine with dates on, because that is what the model was
        # trained against; the caller's value cannot change that. It is the one
        # ignored option that is safe to ignore -- it can only cause MORE to be
        # detected, never less, so it cannot produce under-redaction.
        with CloudClient() as client:
            result = client.redact(text, country=countries[0].upper())
        if tokenize or allowed or domains:
            self._remask_cloud_result(
                result, text, tokenize=tokenize, allowed=allowed, domains=domains)
        return result

    def _remask_cloud_result(
        self, result: RedactResult, text: str, *, tokenize: bool,
        allowed: dict[str, str], domains: dict[str, str],
    ) -> None:
        """Rebuild the masked text from the service's spans, in place.

        The service masks with bracketed labels only. Any other output
        option is applied here, from its spans: the service builds its
        ``redacted_text`` from exactly the spans it returns (entities it
        reports but cannot place are listed separately and never applied),
        so nothing it masked is lost by masking again from the same spans.
        """
        from euredact.cloud.client import CloudError

        for det in result.detections:
            if text[det.start : det.end] != det.text:
                raise CloudError(
                    "span offsets do not match the document; cannot apply "
                    "tokenize/allowlist locally")
        result.detections, result.exempted = _apply_allowlist(
            text, result.detections, allowed, domains)
        token_mapper = TokenMapper(text, result.detections) if tokenize else None
        result.redacted_text = _apply_replacements(
            text, result.detections, self._label_for(False, token_mapper)
        )
        result.tokens = token_mapper.tokens if token_mapper is not None else {}

    async def aredact(
        self,
        text: str,
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        context: DocumentContext | None = None,
        chunk_offset: int = 0,
        mode: str = "rules",
        referential_integrity: bool = False,
        tokenize: bool = False,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
        detect_dates: bool = False,
        coref: bool = False,
        coref_model: str = "default",
        cache: bool = True,
    ) -> RedactResult:
        """Async version of redact().

        Offloads the CPU-bound rule engine work to a thread pool so it
        doesn't block the event loop. Safe to call concurrently from
        multiple async tasks.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _DEFAULT_POOL,
            lambda: self.redact(
                text,
                countries=countries,
                country_hint=country_hint,
                context=context,
                chunk_offset=chunk_offset,
                mode=mode,
                referential_integrity=referential_integrity,
                tokenize=tokenize,
                allowlist=allowlist,
                allowlist_domains=allowlist_domains,
                detect_dates=detect_dates,
                coref=coref,
                coref_model=coref_model,
                cache=cache,
            ),
        )

    def redact_batch(
        self,
        texts: list[str],
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
        tokenize: bool = False,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
        detect_dates: bool = False,
        cache: bool = True,
    ) -> list[RedactResult]:
        """Redact PII from multiple texts.

        Processes all texts sequentially using the same engine state.
        More efficient than calling ``redact()`` in a loop because
        country configs are loaded once.

        Returns results in the same order as the input texts.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        return [
            self.redact(
                text,
                countries=countries,
                country_hint=country_hint,
                mode=mode,
                referential_integrity=referential_integrity,
                tokenize=tokenize,
                allowlist=allowlist,
                allowlist_domains=allowlist_domains,
                detect_dates=detect_dates,
                cache=cache,
            )
            for text in texts
        ]

    async def aredact_batch(
        self,
        texts: list[str],
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
        tokenize: bool = False,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
        detect_dates: bool = False,
        cache: bool = True,
        max_concurrency: int = 4,
    ) -> list[RedactResult]:
        """Async batch redaction with controlled concurrency.

        Processes texts concurrently using a thread pool. The
        ``max_concurrency`` parameter limits how many texts are
        processed in parallel (default 4).

        Returns results in the same order as the input texts.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _process(text: str) -> RedactResult:
            async with semaphore:
                return await self.aredact(
                    text,
                    countries=countries,
                    country_hint=country_hint,
                    mode=mode,
                    referential_integrity=referential_integrity,
                    tokenize=tokenize,
                    allowlist=allowlist,
                    allowlist_domains=allowlist_domains,
                    detect_dates=detect_dates,
                    cache=cache,
                )

        return await asyncio.gather(*[_process(t) for t in texts])

    def redact_iter(
        self,
        texts: Iterator[str],
        *,
        countries: list[str] | None = None,
        country_hint: list[str] | None = None,
        mode: str = "rules",
        referential_integrity: bool = False,
        tokenize: bool = False,
        allowlist: list[str] | None = None,
        allowlist_domains: list[str] | None = None,
        detect_dates: bool = False,
        cache: bool = True,
    ) -> Iterator[RedactResult]:
        """Lazy iterator that yields results one at a time.

        Useful for processing large datasets without loading all results
        into memory at once.
        """
        # Pre-load countries once
        self._engine.load_countries(
            [c.upper() for c in countries] if countries else None
        )
        for text in texts:
            yield self.redact(
                text,
                countries=countries,
                country_hint=country_hint,
                mode=mode,
                referential_integrity=referential_integrity,
                tokenize=tokenize,
                allowlist=allowlist,
                allowlist_domains=allowlist_domains,
                detect_dates=detect_dates,
                cache=cache,
            )
