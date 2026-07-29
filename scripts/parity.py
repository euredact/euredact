"""Cross-SDK parity: do the two engines mask the same characters?

`conformance/vectors.json` pins named cases and runs in both test suites. This
is the broad counterpart: the same corpus through both SDKs, compared on the
characters each one masks.

That distinction matters. Detection *tuples* differ harmlessly all the time —
one engine may split a value into two spans, or attribute a different country —
but a character masked by one and not the other is PII left in the clear by one
of them. Measured that way, TypeScript was leaving 19,014 characters unmasked
that Python caught, across 611 documents; conformance vectors alone never
showed it.

    python scripts/parity.py               # whole corpus
    python scripts/parity.py --limit 2000

Exits non-zero if divergence exceeds --max-divergence (default 2%).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--max-divergence", type=float, default=2.0,
                    help="percent of masked characters allowed to differ")
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
    for text, ts in zip(docs, ts_dets):
        py = [(d.start, d.end) for d in
              euredact.redact(text, detect_dates=True, cache=False).detections]
        p, q = covered(py), covered(ts)
        total += len(q | p)
        if p == q:
            identical += 1
        else:
            py_only += len(p - q)
            ts_only += len(q - p)
            worst.append((len(p ^ q), text[:70]))

    divergence = (py_only + ts_only) / total * 100 if total else 0.0
    print(f"documents compared      : {len(docs):,}")
    print(f"masking identically     : {identical:,} ({identical / len(docs) * 100:.1f}%)")
    print(f"characters only Python  : {py_only:,}")
    print(f"characters only Node    : {ts_only:,}")
    print(f"divergence              : {divergence:.2f}%")
    if worst:
        print("\nlargest disagreements:")
        for n, snippet in sorted(worst, reverse=True)[:5]:
            print(f"  {n:>6} chars  {snippet!r}")

    if divergence > args.max_divergence:
        print(f"\nFAIL: divergence exceeds {args.max_divergence}%")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
