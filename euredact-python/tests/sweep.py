"""Corpus-scale property sweep: the same invariants, over every document we have.

``tests/test_structural_invariants.py`` checks these properties over twenty
chosen documents and runs in CI. This runs them over the whole corpus, which is
where they actually earn their keep — the truncation leak that put ``.77`` of
an IP address into the output was found here, not by reasoning about the rules,
and not by the twenty-document version.

It is a separate entry point because the corpus lives outside the repository
(``Data-Generation/``), so CI cannot run it. Run it before a release, and after
any change to ranking, suppression or validation.

    python tests/sweep.py                # everything we can find
    python tests/sweep.py --limit 2000   # quick pass
    python tests/sweep.py --quiet        # exit code only

Exits non-zero if any property is violated.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import euredact  # noqa: E402
from euredact.rules.context import DocumentContext  # noqa: E402
from euredact.types import EntityType  # noqa: E402

#: Corpus location. Override with EUREDACT_CORPUS so this is runnable by anyone
#: who has the datasets somewhere else.
DATA_DIR = Path(os.environ.get(
    "EUREDACT_CORPUS",
    # The corpus lives beside the code checkout, not inside it.
    str(Path(__file__).resolve().parents[3] / "Data-Generation"),
))

#: Country arguments that must all yield the same spans. Cheap enough to run on
#: every document; this is the pair that caught the IP-address truncation.
COUNTRY_ARGS: list[list[str] | None] = [None, ["NL"], ["BE"], ["ZZ"]]


_DET_LINE = re.compile(r'^- \[(?:EntityType\.)?(\w+)\] "(.*)" \(chars (\d+)-(\d+)\)$')


def _training_documents() -> list[str]:
    """Reconstruct the original documents from the LLM training set.

    Each record holds the rules-engine detections (original value plus offsets)
    and the text with those spans replaced by ``[TYPE]`` placeholders. Putting
    the values back, in offset order, recovers the original; the recorded
    offsets then verify the reconstruction, and anything that fails is skipped
    rather than swept.

    Worth the trouble because these are real documents — a mean of 3,400
    characters of prose around the identifiers, against the corpus\'s 186-
    character records. The cross-SDK divergence that mattered showed up only
    here.
    """
    docs: list[str] = []
    paths = sorted(DATA_DIR.rglob("*/test.jsonl"))
    paths += sorted(DATA_DIR.rglob("*/train.jsonl"))
    for path in paths:
        for line in path.open():
            try:
                rec = json.loads(line)
                user = next(m["content"] for m in rec["messages"]
                            if m["role"] == "user")
            except (json.JSONDecodeError, KeyError, StopIteration):
                continue
            head, sep, body = user.partition("## Partially Redacted Text")
            if not sep:
                continue
            body = body.lstrip("\n")
            dets = []
            for ln in head.splitlines():
                mo = _DET_LINE.match(ln.strip())
                if mo:
                    dets.append((mo.group(1), mo.group(2), int(mo.group(3))))
            dets.sort(key=lambda d: d[2])
            out, pos, ok = [], 0, True
            for etype, value, _start in dets:
                tag = f"[{etype}]"
                idx = body.find(tag, pos)
                if idx < 0:
                    ok = False
                    break
                out.append(body[pos:idx])
                out.append(value)
                pos = idx + len(tag)
            if not ok:
                continue
            out.append(body[pos:])
            text = "".join(out)
            if all(text[s:s + len(v)] == v for _t, v, s in dets):
                docs.append(text)
    return docs


def load_documents(limit: int | None = None) -> list[str]:
    """Every document we can find: the synthetic corpus, plus real documents
    reconstructed from the LLM training set when it is present.

    A *limit* takes an evenly spaced sample rather than a prefix. The two
    sources differ in kind — 186-character synthetic records against real
    documents averaging ten times that, with prose around the identifiers — and
    they are concatenated, so a prefix would quietly sweep only the short ones.
    Every cross-SDK divergence worth having found lived in the long documents.
    """
    docs: list[str] = []

    for path in sorted(DATA_DIR.glob("*.json")):
        try:
            records = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        docs.extend(rec["source_text"] for rec in records if rec.get("source_text"))

    docs.extend(_training_documents())

    if limit and limit < len(docs):
        step = len(docs) / limit
        docs = [docs[int(i * step)] for i in range(limit)]
    return docs


class Sweep:
    """Accumulates property violations with one worked example each."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.examples: dict[str, str] = {}
        self.checked = 0

    def fail(self, prop: str, detail: str) -> None:
        self.counts[prop] += 1
        self.examples.setdefault(prop, detail)

    def check(self, text: str) -> None:
        self.checked += 1
        result = euredact.redact(text, detect_dates=True, cache=False)
        dets = result.detections

        # The redaction contract: offsets index the text the caller passed in.
        for d in dets:
            if not (0 <= d.start < d.end <= len(text)):
                self.fail("span out of range", f"{(d.start, d.end)} in len {len(text)}")
            elif text[d.start:d.end] != d.text:
                self.fail("offset does not match text",
                          f"{d.entity_type} {d.text!r} vs {text[d.start:d.end]!r}")

        spans = sorted((d.start, d.end) for d in dets)
        for (_, prev_end), (start, end) in zip(spans, spans[1:]):
            if start < prev_end:
                self.fail("overlapping detections",
                          f"ends {prev_end} then starts {start}")

        # redacted_text must be exactly the reported spans replaced.
        expected = text
        for d in sorted(dets, key=lambda d: d.start, reverse=True):
            label = (d.entity_type.value if isinstance(d.entity_type, EntityType)
                     else d.entity_type)
            expected = expected[:d.start] + f"[{label}]" + expected[d.end:]
        if result.redacted_text != expected:
            self.fail("redacted_text is not the reported spans replaced",
                      repr(text[:70]))

        # Determinism, and the cache telling the truth.
        again = euredact.redact(text, detect_dates=True, cache=False).detections
        if [(d.start, d.end, d.entity_type) for d in again] != \
           [(d.start, d.end, d.entity_type) for d in dets]:
            self.fail("non-deterministic", repr(text[:70]))
        euredact.clear()
        cached = euredact.redact(text, detect_dates=True, cache=True)
        if cached.redacted_text != result.redacted_text:
            self.fail("cache differs from uncached", repr(text[:70]))

        # I1: country influences scoring, never which spans are found.
        baseline = {(d.start, d.end) for d in dets}
        for arg in COUNTRY_ARGS:
            found = {(d.start, d.end) for d in euredact.redact(
                text, countries=arg, detect_dates=True, cache=False).detections}
            if found != baseline:
                self.fail(f"countries={arg!r} changed the spans found",
                          f"{repr(text[:60])} diff={sorted(baseline ^ found)[:3]}")

        # A context is a scoring input too.
        ctx = DocumentContext()
        with_ctx = {(d.start, d.end) for d in euredact.redact(
            text, context=ctx, detect_dates=True).detections}
        if with_ctx != baseline:
            self.fail("a context changed the spans found", repr(text[:70]))

    def report(self, quiet: bool = False) -> int:
        if not quiet:
            print(f"documents swept: {self.checked:,}")
        if not self.counts:
            if not quiet:
                print("all properties hold")
            return 0
        for prop, n in self.counts.most_common():
            print(f"  VIOLATED  {n:>7,}  {prop}")
            if not quiet:
                print(f"                     e.g. {self.examples[prop]}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=None, help="documents to sweep")
    ap.add_argument("--quiet", action="store_true",
                    help="exit code and violations only")
    args = ap.parse_args()

    docs = load_documents(args.limit)
    if not docs:
        print(f"No corpus found under {DATA_DIR}.")
        print("The sweep needs the generated datasets; skipping is not a pass.")
        return 77  # distinct from 0 (clean) and 1 (violations)

    sweep = Sweep()
    for text in docs:
        sweep.check(text)
    return sweep.report(args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
