"""Cloud mode for documents over the service's input cap (rules-engine#183).

The service refuses a request over 5,000 tokens with 413. In cloud mode the SDK
splits such a document itself, sends the parts and returns one result, so a
long document takes the same single call as a short one.

What is split is the *masked* text: the local rules pass has already replaced
every structured identifier with a placeholder, a cut never falls inside one,
and only masked text is sent, as for a short document. Parts are cut at a
blank line, a line break, a sentence end or a space, in that order of
preference, and overlap their neighbour so that a name near a cut is seen
whole by one of them. The TypeScript SDK cuts at the same places: positions
are code points, and only ASCII characters are tested
(``conformance/cloud_chunking.json``).

Fail closed: if any part fails, the call raises, and the error says how many
parts were completed and billed. A document is never returned with some parts
read by the model and others not.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

from euredact.types import (
    ChunkInfo,
    CloudInfo,
    Detection,
    RedactResult,
    Review,
    Unlocated,
    Usage,
)

#: Characters per part. The cap is 5,000 tokens, about 16,000 characters of
#: Dutch or French and 20,000 of English; 12,000 leaves room for the per-request
#: instructions and for denser text. A part that still draws a 413 is halved.
DEFAULT_MAX_CHARS = 12_000

#: Characters each part repeats of the one before, so a name or address near a
#: cut is seen whole once. Billed in both parts. Provisional: the issue asks for
#: it to be set from a benchmark measurement.
DEFAULT_OVERLAP_CHARS = 300

#: A part this short that still draws a 413 is not halved again: the error
#: is raised. It cannot be the text's length that the service refuses.
MIN_PART_CHARS = 500


@dataclass(frozen=True)
class Chunking:
    """How cloud mode splits a document over the input cap.

    ``chunking="auto"`` is this with its defaults; ``chunking="off"`` sends
    every document whole, so an oversized one raises ``TooLargeError`` and
    nothing is sent. A document no longer than ``max_chars`` is sent whole
    either way, and is split only if the service still refuses it.
    """

    max_chars: int = DEFAULT_MAX_CHARS
    """The longest part, in characters (code points) of the masked text."""
    overlap_chars: int = DEFAULT_OVERLAP_CHARS
    """How much each part repeats of the one before. 0 for none."""
    splitter: Callable[[str], Sequence[int]] | None = None
    """A function given the masked text and returning the positions to cut it
    at, for documents with real structure (pages, sections, messages). A part
    it leaves over ``max_chars`` is split further at the built-in boundaries."""
    concurrency: int = 1
    """Parts sent at once. 1 by default: a free plan queues further requests."""
    max_chunks: int | None = None
    """Refuse, before anything is sent, a document needing more parts."""
    propagate: bool = True
    """Mask a value the model found in one part wherever the same text occurs
    in the others: a full name on page 1, the surname alone on page 6 is not
    covered by this, but the same name on page 6 is."""
    on_chunk: Callable[[ChunkInfo], None] | None = None
    """Called after each part is answered, for progress on long documents."""

    def __post_init__(self) -> None:
        if self.max_chars < 2 * MIN_PART_CHARS:
            raise ValueError(
                f"Chunking.max_chars must be at least {2 * MIN_PART_CHARS}")
        if not 0 <= self.overlap_chars <= self.max_chars // 4:
            raise ValueError(
                "Chunking.overlap_chars must be between 0 and max_chars / 4")
        if self.concurrency < 1:
            raise ValueError("Chunking.concurrency must be at least 1")
        if self.max_chunks is not None and self.max_chunks < 1:
            raise ValueError("Chunking.max_chunks must be at least 1")


def resolve(chunking: object) -> Chunking | None:
    """``"auto"`` -> the defaults, ``"off"`` -> None, a :class:`Chunking` as is."""
    if chunking == "auto":
        return Chunking()
    if chunking == "off":
        return None
    if isinstance(chunking, Chunking):
        return chunking
    raise ValueError(f'chunking must be "auto", "off" or a Chunking, not {chunking!r}')


# ── Where to cut ─────────────────────────────────────────────────────────


def _inside(protected: Sequence[tuple[int, int]], pos: int) -> tuple[int, int] | None:
    """The placeholder strictly containing *pos*, if any."""
    for start, end in protected:
        if start < pos < end:
            return start, end
        if start >= pos:
            break
    return None


def _cut(text: str, lo: int, hi: int) -> int:
    """The best cut in ``text[lo:hi]``: after a blank line, a line break, a
    sentence end or a space or tab, the last one found; else *hi*."""
    window = text[lo:hi]
    at = window.rfind("\n\n")
    if at >= 0:
        return lo + at + 2
    at = window.rfind("\n")
    if at >= 0:
        return lo + at + 1
    best = -1
    for i in range(len(window) - 1, 0, -1):
        if window[i] in " \t" and window[i - 1] in ".!?":
            best = i
            break
    if best >= 0:
        return lo + best + 1
    for i in range(len(window) - 1, -1, -1):
        if window[i] in " \t":
            return lo + i + 1
    return hi


def _split_long(text: str, lo: int, hi: int, max_chars: int,
                protected: Sequence[tuple[int, int]]) -> list[int]:
    """Cut points inside ``text[lo:hi]`` so that no piece exceeds *max_chars*."""
    cuts = []
    pos = lo
    while hi - pos > max_chars:
        cut = _cut(text, pos + max_chars // 2, pos + max_chars)
        held = _inside(protected, cut)
        if held is not None:
            cut = held[0] if held[0] > pos else held[1]
        cuts.append(cut)
        pos = cut
    return cuts


def plan(
    text: str,
    protected: Sequence[tuple[int, int]],
    max_chars: int,
    overlap: int,
    splitter: Callable[[str], Sequence[int]] | None = None,
) -> list[tuple[int, int]]:
    """The parts to send, as ``(start, end)`` in *text*, overlapping.

    *protected* are the placeholders, sorted; no cut or part start falls
    inside one. The overlap never exceeds a quarter of a part.
    """
    n = len(text)
    overlap = min(overlap, max_chars // 4)
    if splitter is not None:
        points = sorted({int(p) for p in splitter(text) if 0 < int(p) < n})
        points = [p for p in points if _inside(protected, p) is None]
    else:
        points = []
    bounds = [0, *points, n]
    cuts: list[int] = []
    # Room for the overlap a part carries in front, so that no part, overlap
    # included, is longer than max_chars.
    step = max_chars - overlap
    for lo, hi in zip(bounds, bounds[1:]):
        cuts.extend(_split_long(text, lo, hi, step, protected))
        if hi != n:
            cuts.append(hi)
    if not cuts:
        return [(0, n)]
    parts = []
    start = 0
    for cut in [*cuts, n]:
        parts.append((start, cut))
        if cut != n:
            start = _overlap_start(text, cut, max(start + 1, cut - overlap), protected)
    return parts


def _overlap_start(
    text: str, cut: int, lo: int, protected: Sequence[tuple[int, int]]
) -> int:
    """Where the part after *cut* starts: back to *lo*, then forward to just
    after a space or line break, so that it does not start mid-word."""
    if lo >= cut:
        return cut
    start = lo
    for i in range(lo, cut):
        if text[i] in " \t\n":
            start = i + 1
            break
    held = _inside(protected, start)
    return held[0] if held is not None else start


# ── Sending and merging ──────────────────────────────────────────────────


def part_key(key: str | None, index: int, part: str) -> str:
    """Each part's Idempotency-Key: derived from the caller's, so a retried
    document bills no part twice; random when the caller gave none."""
    if key is None:
        return str(uuid.uuid4())
    digest = hashlib.sha256(part.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{key}:{index}:{digest}"


def _shift(d: Detection, by: int) -> Detection:
    return replace(d, start=d.start + by, end=d.end + by)


def run(
    send: Callable[[str, str], RedactResult],
    text: str,
    protected: Sequence[tuple[int, int]],
    options: Chunking,
    *,
    key: str | None,
    to_original: Callable[[int, int], tuple[int, int]],
    too_large: type[Exception],
) -> RedactResult:
    """Send *text* in parts and merge the answers into one result over *text*.

    *send(part, idempotency_key)* is one cloud request. Offsets in the result,
    and in ``cloud.chunks`` before :func:`to_original` maps them, are in *text*.
    """
    parts = plan(text, protected, options.max_chars, options.overlap_chars,
                 options.splitter)
    if options.max_chunks is not None and len(parts) > options.max_chunks:
        raise ValueError(
            f"the document needs {len(parts)} parts, more than max_chunks="
            f"{options.max_chunks}; nothing was sent")
    if len(parts) == 1:
        # Short enough to go whole: today's request, under the caller's own
        # key. Split only if the service refuses it after all.
        try:
            return send(text, key or str(uuid.uuid4()))
        except too_large:
            if len(text) < 2 * MIN_PART_CHARS:
                raise
            parts = plan(text, protected, (len(text) + 1) // 2 + 1,
                         options.overlap_chars)

    Answer = list[tuple[tuple[int, int], RedactResult]]

    def one(index: int, span: tuple[int, int]) -> Answer:
        start, end = span
        piece = text[start:end]
        try:
            return [(span, send(piece, part_key(key, index, piece)))]
        except too_large:
            if end - start < 2 * MIN_PART_CHARS:
                raise
            # Over the cap after all: halve it and send both halves.
            shifted = [(s - start, e - start) for s, e in protected
                       if start <= s and e <= end]
            halves = plan(piece, shifted, (end - start + 1) // 2 + 1,
                          options.overlap_chars)
            out = []
            for j, (s, e) in enumerate(halves):
                out.extend(one(index * 1000 + j + 1, (start + s, start + e)))
            return out

    total = len(parts)
    answers: list[Answer | None] = [None] * total
    failure: BaseException | None = None

    def done(index: int, got: Answer) -> None:
        answers[index] = got
        if options.on_chunk is not None:
            s, e = to_original(*parts[index])
            options.on_chunk(ChunkInfo(
                index=index, total=total, start=s, end=e,
                job_id=got[0][1].cloud.job_id if got[0][1].cloud else None,
                tokens=_tokens([r for _, r in got])))

    if options.concurrency == 1 or total == 1:
        for index, span in enumerate(parts):
            try:
                done(index, one(index, span))
            except Exception as exc:  # noqa: BLE001 - re-raised below with the count
                failure = exc
                break
    else:
        with ThreadPoolExecutor(max_workers=min(options.concurrency, total)) as pool:
            futures = [pool.submit(one, i, span) for i, span in enumerate(parts)]
            for index, future in enumerate(futures):
                try:
                    done(index, future.result())
                except Exception as exc:  # noqa: BLE001
                    failure = failure or exc
    if failure is not None:
        completed = sum(1 for a in answers if a is not None)
        _annotate(failure, completed, total)
        raise failure

    return _merge(text, answers, parts, options, to_original)


def _annotate(exc: BaseException, completed: int, total: int) -> None:
    """Say on the error how far the document got; parts answered are billed."""
    exc.chunks_completed = completed  # type: ignore[attr-defined]
    exc.chunks_total = total  # type: ignore[attr-defined]
    note = (f" (split into {total} parts; {completed} completed and billed, "
            f"the result discarded)")
    if exc.args and isinstance(exc.args[0], str):
        exc.args = (exc.args[0] + note, *exc.args[1:])


def _tokens(results: Sequence[RedactResult]) -> int | None:
    found = [r.cloud.usage.tokens for r in results if r.cloud and r.cloud.usage]
    return sum(found) if found else None


def _merge(text, answers, parts, options, to_original) -> RedactResult:
    flat = [(span, r) for got in answers for span, r in got]
    detections: list[Detection] = []
    seen: set[tuple[int, int, str]] = set()
    for (start, _end), result in flat:
        for d in result.detections:
            moved = _shift(d, start)
            key = (moved.start, moved.end, str(moved.entity_type))
            if key in seen:
                continue
            seen.add(key)
            detections.append(moved)
    # A span another part found whole, of the same type, is the same value seen
    # from the overlap: keep the whole one.
    detections = [
        d for d in detections
        if not any(o is not d and o.entity_type == d.entity_type
                   and o.start <= d.start and d.end <= o.end
                   and (o.end - o.start) > (d.end - d.start)
                   for o in detections)
    ]
    if options.propagate and len(parts) > 1:
        detections.extend(_propagated(text, detections))
    detections.sort(key=lambda d: (d.start, -d.end))

    unlocated: list[Unlocated] = []
    for _, result in flat:
        for u in result.cloud.unlocated if result.cloud else ():
            if u not in unlocated:
                unlocated.append(u)
    usages = [r.cloud.usage for _, r in flat if r.cloud and r.cloud.usage]
    usage = None
    if usages:
        factors = []
        for u in usages:
            for f in u.factors:
                if f not in factors:
                    factors.append(f)
        tokens = sum(u.tokens for u in usages)
        credits = sum(u.credits for u in usages)
        usage = Usage(tokens=tokens, billing_rate=(credits / tokens if tokens else 0.0),
                      credits=credits, factors=tuple(factors))
    first = flat[0][1].cloud
    chunks = []
    for index, (start, end) in enumerate(parts):
        mine = [r for _span, r in answers[index]]
        s, e = to_original(start, end)
        chunks.append(ChunkInfo(index=index, total=len(parts), start=s, end=e,
                                job_id=mine[0].cloud.job_id if mine[0].cloud else None,
                                tokens=_tokens(mine)))
    cloud = CloudInfo(
        job_id=None if len(parts) > 1 else (first.job_id if first else None),
        model_version=first.model_version if first else None,
        usage=usage, unlocated=tuple(unlocated),
        chunks=tuple(chunks) if len(parts) > 1 else (),
    )
    return RedactResult(
        redacted_text=text, detections=detections, source="cloud", cloud=cloud,
        review=_merge_reviews([(s, r.review) for (s, _e), r in flat]),
    )


def _boundary(text: str, i: int) -> bool:
    return i < 0 or i >= len(text) or not (text[i].isalnum() or text[i] == "_")


def _propagated(text: str, detections: list[Detection]) -> list[Detection]:
    """The other occurrences of each value the model found (``propagate``)."""
    covered = sorted((d.start, d.end) for d in detections)
    taken = [False] * (len(text) + 1)
    for s, e in covered:
        for i in range(s, e):
            taken[i] = True
    out = []
    values = {}
    for d in detections:
        if d.source.value == "cloud" and len(d.text.strip()) >= 3 and "[" not in d.text:
            values.setdefault(d.text, d)
    for value, model in values.items():
        at = text.find(value)
        while at >= 0:
            end = at + len(value)
            if (not any(taken[at:end]) and _boundary(text, at - 1)
                    and _boundary(text, end)):
                out.append(replace(model, start=at, end=end))
                for i in range(at, end):
                    taken[i] = True
            at = text.find(value, at + 1)
    return out


def _merge_reviews(reviews: Sequence[tuple[int, Review | None]]) -> Review | None:
    """One review for the document: any part recommended is a recommendation,
    the flags are the union, and the score is the chance that some part still
    holds a miss, ``1 - prod(1 - score)``."""
    present = [(s, r) for s, r in reviews if r is not None]
    if not present:
        return None
    scores = [r.score for _, r in present]
    score = None
    if all(x is not None for x in scores):
        clean = 1.0
        for x in scores:
            clean *= 1.0 - x
        score = 1.0 - clean
    recommending = [r for _, r in present if r.recommended]
    flags: list[str] = []
    uncertain: list[Detection] = []
    for start, r in present:
        flags.extend(f for f in r.flags if f not in flags)
        for d in r.uncertain:
            moved = _shift(d, start)
            if all((u.start, u.end) != (moved.start, moved.end) for u in uncertain):
                uncertain.append(moved)
    return Review(
        score=score, recommended=bool(recommending),
        basis=(recommending[0] if recommending else present[0][1]).basis,
        flags=tuple(flags),
        uncertain=tuple(sorted(uncertain, key=lambda d: (d.start, d.end))),
    )
