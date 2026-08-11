"""Cross-SDK parity: do the two engines mask the same characters, and agree on
what they masked?

`conformance/vectors.json` pins named cases and runs in both test suites. This
is the broad counterpart: the same corpus through both SDKs.

Two questions, reported separately, because they fail differently.

**Characters.** A character masked by one engine and not the other is PII left
in the clear by one of them. Measured that way, TypeScript was leaving 19,014
characters unmasked that Python caught, across 611 documents; conformance
vectors alone never showed it. This is the leak gate.

**Types.** For a span both engines masked identically, do they call it the same
thing? This half was added after 0.3.8 shipped with the two engines disagreeing
on type while this script reported byte-identical masking and stayed green:
`Burgerservicenummer (BSN): 274839165` was `NATIONAL_ID` attributed to Czechia
in Python and `PHONE` attributed to Portugal in Node. Both masked exactly the
same characters, so a character-only gate cannot see it, and the 0.3.8 release
notes quoted this script's 0.61% as evidence the SDKs agreed. It was not.

Type divergence is compared only over spans where both engines chose the same
start and end. Where the spans themselves differ the type comparison would be
measuring the span disagreement again, which the character half already reports.

    python scripts/parity.py               # whole corpus
    python scripts/parity.py --limit 2000

Exits non-zero if either divergence exceeds its threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "euredact-python" / "src"))
sys.path.insert(0, str(ROOT / "euredact-python" / "tests"))

import euredact
from sweep import load_documents


def covered(spans) -> set[int]:
    out: set[int] = set()
    for start, end, *_ in spans:
        out.update(range(start, end))
    return out


def norm_type(value: object) -> str:
    """The entity type as a bare name, comparable across the two SDKs.

    Python yields an ``EntityType`` whose ``str()`` is ``"EntityType.PHONE"``,
    the TypeScript dump yields ``"PHONE"``, and a custom pattern yields a plain
    string in both. Without this the two would differ on every single span and
    the type half would report 100% divergence.
    """
    value = getattr(value, "value", value)
    text = str(value)
    return text.split(".", 1)[1] if text.startswith("EntityType.") else text


def typed(spans) -> dict[tuple[int, int], str]:
    """``{(start, end): type}``, for comparing what each engine called a span."""
    return {(s, e): norm_type(t) for s, e, t, *_ in spans}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-divergence", type=float, default=2.0,
                    help="percent of masked characters allowed to differ")
    # Zero, and not by aspiration: 0.3.9 closed the last case, and 21,172
    # identically-masked spans over 4,000 documents agree on all 21,172.
    #
    # Tighter than the character threshold on purpose. A character difference
    # can be a benign span split — one engine cutting a value into two spans
    # masks the same text. Two engines calling the *identical* span two
    # different things is a straight contradiction: one of them is wrong, and a
    # caller routing on entity type acts on it. There is no tolerance to spend.
    ap.add_argument("--max-type-divergence", type=float, default=0.0,
                    help="percent of identically-masked spans allowed to differ in type")
    args = ap.parse_args()

    docs = load_documents(args.limit)
    if not docs:
        print("No corpus found; set EUREDACT_CORPUS.")
        return 77

    with tempfile.TemporaryDirectory() as tmp:
        docs_path = Path(tmp) / "docs.json"
        ts_path = Path(tmp) / "ts.json"
        docs_path.write_text(json.dumps(docs))

        proc = subprocess.run(
            ["npm", "run", "--silent", "dump", "--", str(docs_path), str(ts_path)],
            cwd=ROOT / "euredact-ts", capture_output=True, text=True, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        if proc.returncode != 0:
            print("the TypeScript dump failed:")
            print(proc.stderr[-2000:])
            return 1
        ts_dets = json.loads(ts_path.read_text())

    identical = 0
    py_only = ts_only = total = 0
    worst: list[tuple[int, str]] = []
    shared_spans = type_agree = 0
    type_pairs: Counter[tuple[str, str]] = Counter()
    type_examples: dict[tuple[str, str], str] = {}
    for text, ts in zip(docs, ts_dets):
        dets = euredact.redact(text, detect_dates=True, cache=False).detections
        py = [(d.start, d.end, d.entity_type) for d in dets]
        p, q = covered(py), covered(ts)
        total += len(q | p)
        if p == q:
            identical += 1
        else:
            py_only += len(p - q)
            ts_only += len(q - p)
            worst.append((len(p ^ q), text[:70]))

        # Types, over the spans both engines chose identically.
        py_t, ts_t = typed(py), typed(ts)
        for span in py_t.keys() & ts_t.keys():
            shared_spans += 1
            if py_t[span] == ts_t[span]:
                type_agree += 1
            else:
                pair = (py_t[span], ts_t[span])
                type_pairs[pair] += 1
                type_examples.setdefault(pair, text[span[0]:span[1]][:40])

    divergence = (py_only + ts_only) / total * 100 if total else 0.0
    type_diff = shared_spans - type_agree
    type_divergence = type_diff / shared_spans * 100 if shared_spans else 0.0

    print(f"documents compared      : {len(docs):,}")
    print(f"masking identically     : {identical:,} ({identical / len(docs) * 100:.1f}%)")
    print(f"characters only Python  : {py_only:,}")
    print(f"characters only Node    : {ts_only:,}")
    print(f"divergence              : {divergence:.2f}%")
    if worst:
        print("\nlargest disagreements:")
        for n, snippet in sorted(worst, reverse=True)[:5]:
            print(f"  {n:>6} chars  {snippet!r}")

    # The type half. Reported even at zero, because "0 type disagreements" is
    # the claim the release notes are entitled to make and silence is not.
    print(f"\nspans masked identically: {shared_spans:,}")
    print(f"  same type             : {type_agree:,}")
    print(f"  different type        : {type_diff:,}")
    print(f"type divergence         : {type_divergence:.2f}%")
    if type_pairs:
        print("\ntype disagreements (python -> node):")
        for (py_type, ts_type), n in type_pairs.most_common(10):
            example = type_examples[(py_type, ts_type)]
            print(f"  {n:>6}  {py_type} -> {ts_type}    e.g. {example!r}")

    failed = False
    if divergence > args.max_divergence:
        print(f"\nFAIL: character divergence exceeds {args.max_divergence}%")
        failed = True
    if type_divergence > args.max_type_divergence:
        print(f"FAIL: type divergence exceeds {args.max_type_divergence}%")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
