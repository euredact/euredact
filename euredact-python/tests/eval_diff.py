"""Detection-equivalence harness.

Several planned refactors claim to change *only* performance. This records what
the engine detects, so that claim is checked rather than asserted. The eval
harness (`eval_full.py`) measures accuracy against ground truth and will happily
show identical headline numbers while individual detections move around; this
compares detections directly.

Records per document, for both hinted and blind modes:

* every detection as ``(start, end, entity_type, country)`` — country included
  because dedup ties are broken by pattern registration order, so a reordering
  can change the attributed country without moving a span;
* a digest of the merged suppression-zone list, an internal invariant that
  detection output can hide.

Usage::

    python tests/eval_diff.py --baseline before.jsonl
    # ... make the change ...
    python tests/eval_diff.py --baseline after.jsonl
    python tests/eval_diff.py --compare before.jsonl after.jsonl

Prove the harness itself first: two runs against unmodified code must be
zero-diff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import eval_full  # noqa: E402  - reuse its DATASETS glob and hint semantics
from euredact.rules.registry import CountryRegistry  # noqa: E402
from euredact.sdk import EuRedact  # noqa: E402

KNOWN = set(CountryRegistry().available_countries)


def load_documents(limit: int | None, seed: int) -> list[dict]:
    data: list[dict] = []
    for path in eval_full.DATASETS:
        if path.name.endswith(".bak"):
            continue
        data.extend(json.loads(path.read_text(encoding="utf-8")))
    data = [d for d in data if d.get("source_text") and d.get("PII")]
    if limit is not None and limit < len(data):
        random.Random(seed).shuffle(data)
        data = data[:limit]
    return data


def _zone_digest(engine, text: str) -> str:
    """Digest of the merged suppression zones for *text*.

    Reaches into the engine deliberately: zones are an internal mechanism whose
    regressions can be invisible in detection output on any given corpus.
    Returns "n/a" once the mechanism is gone, so the harness keeps working
    across the change that removes it.
    """
    matcher = getattr(engine, "_matcher", None)
    if matcher is None:
        return "n/a"
    try:
        spans = sorted(
            (m.start, m.end)
            for m in matcher.scan(text, None)
            if m.pattern_def.validator is not None
            and not m.pattern_def.requires_context
            and not matcher.validate(m)
        )
    except Exception:  # noqa: BLE001 - harness must not fail the run
        return "n/a"
    return hashlib.sha256(repr(spans).encode()).hexdigest()[:16]


def record(out_path: Path, limit: int | None, seed: int) -> None:
    docs = load_documents(limit, seed)
    sdk = EuRedact()
    with out_path.open("w", encoding="utf-8") as fh:
        for i, item in enumerate(docs):
            text = item["source_text"]
            countries = [
                c for c in {p["PII_country"] for p in item["PII"] if p.get("PII_country")}
                if c in KNOWN
            ]
            row: dict = {"i": i, "zones": _zone_digest(sdk._engine, text)}
            for label, arg in (("hinted", countries or None), ("blind", None)):
                dets = sdk.redact(
                    text, countries=arg, detect_dates=True, cache=False
                ).detections
                row[label] = sorted(
                    [d.start, d.end, d.entity_type.value, d.country or ""] for d in dets
                )
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(docs):,} records to {out_path}")


def compare(a_path: Path, b_path: Path, show: int) -> int:
    a = [json.loads(line) for line in a_path.read_text(encoding="utf-8").splitlines()]
    b = [json.loads(line) for line in b_path.read_text(encoding="utf-8").splitlines()]
    if len(a) != len(b):
        print(f"record count differs: {len(a):,} vs {len(b):,}")
        return 1

    diffs = {"hinted": [], "blind": [], "zones": []}
    for x, y in zip(a, b):
        for key in ("hinted", "blind"):
            if x[key] != y[key]:
                diffs[key].append((x["i"], x[key], y[key]))
        if x["zones"] != y["zones"] and "n/a" not in (x["zones"], y["zones"]):
            diffs["zones"].append((x["i"], x["zones"], y["zones"]))

    total = sum(len(v) for v in diffs.values())
    print(f"compared {len(a):,} records")
    for key, rows in diffs.items():
        print(f"  {key:<7} {len(rows):,} differing")
    if total == 0:
        print("\nzero-diff")
        return 0

    for key in ("hinted", "blind"):
        for i, before, after in diffs[key][:show]:
            lost = [d for d in before if d not in after]
            gained = [d for d in after if d not in before]
            print(f"\n  [{key}] record {i}")
            if lost:
                print(f"    lost  : {lost[:6]}")
            if gained:
                print(f"    gained: {gained[:6]}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", type=Path, help="record detections to this file")
    ap.add_argument("--compare", type=Path, nargs=2, metavar=("A", "B"))
    ap.add_argument("--limit", type=int, default=8000, help="documents to sample (0 = all)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--show", type=int, default=5, help="differing records to print")
    args = ap.parse_args()

    if args.compare:
        return compare(args.compare[0], args.compare[1], args.show)
    if args.baseline:
        record(args.baseline, args.limit or None, args.seed)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
