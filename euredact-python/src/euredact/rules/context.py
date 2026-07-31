"""Country evidence shared across the chunks of one document.

A long document is usually redacted in pieces. Each piece is scanned
independently, so each infers its own country — and a chunk that happens to
contain no IBAN, no `+CC` number and no ccTLD infers nothing at all, even when
the first page identified the document beyond doubt.

That is the failure this exists to prevent:

    page 1   "Factuur — IBAN NL91ABNA0417164300, info@example.nl"
    page 7   "Telefoon 0612345678"        <- Dutch mobile, or Danish CPR?

Scanned alone, page 7 has nothing to go on. Sharing a context across the two
carries page 1's evidence forward, and the number resolves as a Dutch phone.

Spans are rebased by ``chunk_offset`` on the way in, so evidence collected from
a chunk points at offsets in the whole document rather than the chunk. What
comes back out is therefore quotable against the original text.

The invariant from ``euredact.rules.evidence`` still holds here: a context
influences **scoring only**. It can change which national scheme is attributed
to a value. It can never change which spans are found, so a context carried
over from the wrong document cannot cause a miss.
"""

from __future__ import annotations

import threading

from euredact.types import CountryEvidence


class DocumentContext:
    """Accumulates country evidence across the chunks of one document.

    Thread-safe: ``aredact_batch`` fans chunks out across a thread pool, so
    several may report evidence at once.

    Usage::

        ctx = DocumentContext()
        for offset, chunk in chunks:
            euredact.redact(chunk, context=ctx, chunk_offset=offset)

    Reuse a context only for chunks of the *same* document. Sharing one across
    unrelated documents mixes their countries together, which will not hide
    anything but will attribute values to the wrong national scheme.
    """

    __slots__ = ("_evidence", "_lock", "_seen")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._evidence: list[CountryEvidence] = []
        # Deduped on the same key evidence.collect() uses, so re-running a
        # chunk — a retry, an overlapping window — cannot let one entity vote
        # twice and outweigh the rest of the document.
        self._seen: set[tuple[tuple[int, int], str]] = set()

    def add(self, evidence: list[CountryEvidence], chunk_offset: int = 0) -> None:
        """Record *evidence* from a chunk starting at *chunk_offset*."""
        if not evidence:
            return
        with self._lock:
            for ev in evidence:
                span = (ev.span[0] + chunk_offset, ev.span[1] + chunk_offset)
                key = (span, ev.source)
                if key in self._seen:
                    continue
                self._seen.add(key)
                self._evidence.append(
                    ev if chunk_offset == 0 else CountryEvidence(
                        country=ev.country, source=ev.source,
                        log_odds=ev.log_odds, span=span,
                    )
                )

    def evidence(self) -> list[CountryEvidence]:
        """Everything recorded so far, spans rebased to the whole document."""
        with self._lock:
            return list(self._evidence)

    def __len__(self) -> int:
        with self._lock:
            return len(self._evidence)
