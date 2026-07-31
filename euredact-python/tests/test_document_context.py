"""Country evidence shared across the chunks of one document.

The failure this prevents: a chunk carrying no country signal of its own is
scored as if the rest of the document did not exist.
"""

import threading

import euredact
from euredact.rules.context import DocumentContext
from euredact.types import CountryEvidence, EntityType

# Page 1 identifies the document; page 7 carries a value that is ambiguous
# without it — 0612345678 is both a Dutch mobile and a valid Danish CPR.
PAGE_1 = "Factuur — IBAN NL91ABNA0417164300, info@example.nl"
# Deliberately cue-free. "Telefoon 0612345678" would be decided by the local-cue
# tiebreak before the context was ever consulted, which is correct behaviour but
# makes the test vacuous — it would pass with contexts removed entirely.
PAGE_7 = "Nummer 0612345678"


def _types(result):
    return [(d.entity_type, d.country) for d in result.detections]


class TestEvidenceCarriesAcrossChunks:
    def test_chunk_alone_cannot_resolve_it(self):
        """Baseline: the defect exists without a context."""
        r = euredact.redact(PAGE_7, cache=False)
        assert _types(r) == [(EntityType.NATIONAL_ID, "DK")]

    def test_context_carries_the_document_forward(self):
        ctx = DocumentContext()
        euredact.redact(PAGE_1, context=ctx, chunk_offset=0)
        r = euredact.redact(PAGE_7, context=ctx, chunk_offset=len(PAGE_1))
        assert _types(r) == [(EntityType.PHONE, "NL")]

    def test_order_matters_only_for_what_is_known_yet(self):
        """A context accumulates; it cannot reach backwards in time. The first
        chunk is scored on its own evidence, which is honest, not a bug."""
        ctx = DocumentContext()
        first = euredact.redact(PAGE_7, context=ctx, chunk_offset=0)
        assert _types(first) == [(EntityType.NATIONAL_ID, "DK")]
        euredact.redact(PAGE_1, context=ctx, chunk_offset=len(PAGE_7))
        second = euredact.redact(PAGE_7, context=ctx, chunk_offset=0)
        assert _types(second) == [(EntityType.PHONE, "NL")]


class TestSpansAreRebased:
    def test_context_spans_point_into_the_whole_document(self):
        ctx = DocumentContext()
        offset = 500
        euredact.redact(PAGE_1, context=ctx, chunk_offset=offset)
        assert ctx.evidence(), "expected evidence from page 1"
        for ev in ctx.evidence():
            assert ev.span[0] >= offset
            assert ev.span[1] <= offset + len(PAGE_1)

    def test_returned_detections_stay_chunk_relative(self):
        """The context is rebased; the result is not. Detections must keep
        indexing the text the caller passed in."""
        ctx = DocumentContext()
        r = euredact.redact(PAGE_1, context=ctx, chunk_offset=9999)
        for d in r.detections:
            assert PAGE_1[d.start:d.end] == d.text


class TestDeduplication:
    def test_rerunning_a_chunk_does_not_let_it_vote_twice(self):
        ctx = DocumentContext()
        for _ in range(5):
            euredact.redact(PAGE_1, context=ctx, chunk_offset=0)
        sources = [(e.span, e.source) for e in ctx.evidence()]
        assert len(sources) == len(set(sources))

    def test_same_span_different_offsets_is_different_evidence(self):
        ctx = DocumentContext()
        euredact.redact(PAGE_1, context=ctx, chunk_offset=0)
        n = len(ctx.evidence())
        euredact.redact(PAGE_1, context=ctx, chunk_offset=1000)
        assert len(ctx.evidence()) == 2 * n


class TestThreadSafety:
    def test_concurrent_chunks(self):
        """aredact_batch fans chunks across a thread pool."""
        ctx = DocumentContext()
        errors = []

        def worker(i):
            try:
                euredact.redact(PAGE_1, context=ctx, chunk_offset=i * 100)
            except Exception as exc:  # noqa: BLE001 - surfaced via `errors`
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        # 16 distinct offsets x the evidence page 1 carries, none lost or doubled.
        spans = [(e.span, e.source) for e in ctx.evidence()]
        assert len(spans) == len(set(spans))
        assert len(spans) == 16 * 2  # iban_prefix + email_tld


class TestCaching:
    def test_context_disables_caching(self):
        """A context makes the result depend on state outside the text, so a
        cached result keyed on the text alone would be wrong."""
        ctx = DocumentContext()
        first = euredact.redact(PAGE_7, context=ctx, cache=True)
        assert _types(first) == [(EntityType.NATIONAL_ID, "DK")]
        euredact.redact(PAGE_1, context=ctx, chunk_offset=len(PAGE_7))
        again = euredact.redact(PAGE_7, context=ctx, cache=True)
        assert _types(again) == [(EntityType.PHONE, "NL")], \
            "a stale cached result was returned"


class TestInvariantHolds:
    def test_a_context_cannot_hide_a_span(self):
        """I1 again: a context is a scoring input. Carried over from the wrong
        document it may misattribute, but it must never cause a miss."""
        wrong = DocumentContext()
        wrong.add([CountryEvidence("DK", "iban_prefix", 4.0, (0, 10))])
        blind = euredact.redact(PAGE_1, cache=False)
        with_wrong = euredact.redact(PAGE_1, context=wrong, cache=False)
        assert {(d.start, d.end) for d in blind.detections} == \
               {(d.start, d.end) for d in with_wrong.detections}
