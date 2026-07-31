"""Per-entity-type precision, recall, F1 and false-positive counts.

`eval_full.py` renders an HTML report with recall and precision per type and
country. This is the plain-text counterpart: one row per PII type, four numbers,
both detection modes, and definitions stated rather than implied — so a figure
quoted from it can be reproduced and argued with.

    python tests/metrics.py                    # both modes, whole corpus
    python tests/metrics.py --mode blind
    python tests/metrics.py --limit 20000
    python tests/metrics.py --csv out.csv

Definitions
-----------
Matching is span-overlap plus type-acceptability, the same rule `eval_full.py`
uses: a detection matches a ground-truth label when their spans overlap **and**
the detection's entity type is in that label category's acceptable set (see
``CATEGORY_MAP``). Overlap rather than exact equality, because the engine's
notion of where an identifier ends can legitimately differ by a separator.

    TP   a labelled span with at least one matching detection
    FN   a labelled span with none
    FP   a detection that satisfied no label — including one that landed on a
         labelled span under the wrong type, which is both a miss and a false
         positive, and a duplicate detection of an already-satisfied label

Rows are keyed on the **ground-truth category**, since that is what the corpus
labels. A false positive is charged to the category its entity type would have
satisfied (printed as the type→category map below, so the attribution is
auditable). Types the corpus never labels get their own row and have no recall.

DOB is reported but excluded from the totals: bare dates are handled by the
cloud tier, and the rules engine only emits them with a keyword or structural
cue, so its recall here is not a defect.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import euredact  # noqa: E402
from euredact.rules.registry import CountryRegistry  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eval_full import CATEGORY_MAP, DOB_CATEGORIES, EXCLUDED_CATEGORIES  # noqa: E402

DATA_DIR = Path(os.environ.get(
    "EUREDACT_CORPUS",
    # The corpus lives beside the code checkout, not inside it.
    str(Path(__file__).resolve().parents[3] / "Data-Generation"),
))

#: The ten canonical datasets. `euromask_international_10k.json.bak` is
#: deliberately absent: it is the *same* 10,000 documents with the same texts,
#: differing only in carrying 640 BIC labels that were removed as false
#: positives when the dataset was corrected. Including it would double-count
#: those documents and score the engine against labels known to be wrong.
DATASETS = [
    "euromask_allcountries_20k.json",
    "euromask_dach_south_20k.json",
    "euromask_eastern_20k.json",
    "euromask_el_cy_mt_20k.json",
    "euromask_ie_baltics_uk_20k.json",
    "euromask_international_10k.json",
    "euromask_nordic_20k.json",
    "euromask_secrets_5k.json",
    "euromask_training_core.json",
    "euromask_training_core2.json",
]


def canonical_category_of_type(support: Counter[str]) -> dict[str, str]:
    """Entity type -> the category a false positive of that type is charged to.

    Preference order: the category named after the type *if the corpus labels
    it*, then whichever candidate the corpus labels most often, then the one
    with the fewest acceptable types, then alphabetical.

    Both halves of that are load-bearing. Without the support check, BIC false
    positives were charged to a ``BIC`` row with zero support while every real
    label sat under ``SWIFT_BIC`` — one type's precision split across two rows,
    reading as 0.00%. Without the name check first, TAX_ID false positives were
    charged to NATIONAL_ID purely because it is a hundred times larger, even
    though TAX_ID has a real row of its own.
    """
    owners: dict[str, list[str]] = defaultdict(list)
    for category, types in CATEGORY_MAP.items():
        for etype in types:
            owners[etype].append(category)
    resolved = {}
    for etype, cats in owners.items():
        resolved[etype] = sorted(
            cats,
            key=lambda c: (
                0 if (c == etype and support.get(c, 0)) else 1,  # own row, if real
                -support.get(c, 0),                              # else the busiest
                len(CATEGORY_MAP[c]), c,
            ),
        )[0]
    return resolved


def load(limit: int | None):
    records = []
    for name in DATASETS:
        path = DATA_DIR / name
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            continue
        records.extend(json.loads(path.read_text()))
        if limit and len(records) >= limit:
            break
    return records[:limit] if limit else records


ROOT = Path(__file__).resolve().parents[2]


def _countries_for(item, known):
    labelled = {p["PII_country"] for p in (item.get("PII") or [])}
    return [c for c in labelled if c in known]


def detect_python(records, hinted: bool, known):
    """Detections from the Python SDK, one list per record."""
    euredact._instance = None
    out = []
    for item in records:
        cc = _countries_for(item, known)
        out.append([
            (d.start, d.end, d.entity_type.value, d.country)
            for d in euredact.redact(
                item["source_text"], countries=(cc or None) if hinted else None,
                detect_dates=True, cache=False,
            ).detections
        ])
    return out


def detect_typescript(records, hinted: bool, known):
    """Detections from the TypeScript SDK, via `npm run dump`.

    The TypeScript SDK is measured by dumping its detections and scoring them
    with the scorer below, rather than porting the metrics to TypeScript. If the
    two reports used different scorers, a difference between them would say
    nothing about the engines.
    """
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = Path(tmp) / "in.json", Path(tmp) / "out.json"
        src.write_text(json.dumps([
            {"text": item["source_text"],
             "countries": (_countries_for(item, known) or None) if hinted else None}
            for item in records
        ]))
        proc = subprocess.run(
            ["npm", "run", "--silent", "dump", "--", str(src), str(dst)],
            cwd=ROOT / "euredact-ts", capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"TypeScript dump failed:\n{proc.stderr[-1500:]}")
        return [[tuple(d) for d in doc] for doc in json.loads(dst.read_text())]


ENGINES = {"python": detect_python, "typescript": detect_typescript}


def evaluate(records, hinted: bool, engine: str = "python"):
    known = set(CountryRegistry().available_countries)
    support: Counter[str] = Counter()
    for item in records:
        for pii in item.get("PII") or []:
            if pii["PII_category"] not in EXCLUDED_CATEGORIES:
                support[pii["PII_category"]] += 1
    charge_to = canonical_category_of_type(support)
    tp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    fp: Counter[str] = Counter()
    euredact._instance = None
    t0 = time.time()

    all_detections = ENGINES[engine](records, hinted, known)

    for item, detections in zip(records, all_detections):
        text = item["source_text"]
        expected = item.get("PII") or []
        if not expected:
            continue

        labels = []
        for pii in expected:
            category = pii["PII_category"]
            if category in EXCLUDED_CATEGORIES:
                continue
            idx = text.find(pii["PII_identifier"])
            if idx < 0:
                continue  # not present verbatim; not scoreable
            labels.append((idx, idx + len(pii["PII_identifier"]), category))

        matched_detections = set()
        for start, end, category in labels:
            acceptable = CATEGORY_MAP.get(category, {category})
            hit = None
            for i, (d_start, d_end, d_type, _c) in enumerate(detections):
                if d_start < end and d_end > start and d_type in acceptable:
                    hit = i
                    break
            if hit is None:
                fn[category] += 1
            else:
                tp[category] += 1
                matched_detections.add(hit)

        for i, (_ds, _de, d_type, _dc) in enumerate(detections):
            if i in matched_detections:
                continue
            # Strict: a detection that did not satisfy a label is a false
            # positive, including one that landed on a labelled span under the
            # wrong type. That case is a miss *and* a false positive — the
            # value is masked but filed wrongly, which is exactly what
            # type-aware downstream handling gets hurt by. Exempting it would
            # let mistypes disappear from both columns and flatter precision.
            fp[charge_to.get(d_type, d_type)] += 1

    return tp, fn, fp, time.time() - t0, charge_to


def report(tp, fn, fp, elapsed, rows_csv=None, label=""):
    keys = sorted(set(tp) | set(fn) | set(fp))
    core = [k for k in keys if k not in DOB_CATEGORIES]

    def prf(k):
        t, f_n, f_p = tp[k], fn[k], fp[k]
        p = t / (t + f_p) if t + f_p else 0.0
        r = t / (t + f_n) if t + f_n else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        return t, f_p, f_n, p, r, f1

    print(f"\n{label}  ({elapsed:.0f}s)")
    print(f"{'type':26s} {'support':>9s} {'TP':>8s} {'FP':>7s} {'FN':>7s} "
          f"{'prec':>7s} {'recall':>7s} {'F1':>7s}")
    print("-" * 84)
    for k in core:
        t, f_p, f_n, p, r, f1 = prf(k)
        print(f"{k:26s} {t + f_n:9,} {t:8,} {f_p:7,} {f_n:7,} "
              f"{p * 100:6.2f}% {r * 100:6.2f}% {f1 * 100:6.2f}%")

    T, FP_, FN_ = (sum(tp[k] for k in core), sum(fp[k] for k in core),
                   sum(fn[k] for k in core))
    P = T / (T + FP_) if T + FP_ else 0.0
    R = T / (T + FN_) if T + FN_ else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    print("-" * 84)
    print(f"{'TOTAL (excl. DOB)':26s} {T + FN_:9,} {T:8,} {FP_:7,} {FN_:7,} "
          f"{P * 100:6.2f}% {R * 100:6.2f}% {F * 100:6.2f}%")
    for k in keys:
        if k in DOB_CATEGORIES:
            t, f_p, f_n, p, r, f1 = prf(k)
            print(f"{k + ' (cloud tier)':26s} {t + f_n:9,} {t:8,} {f_p:7,} {f_n:7,} "
                  f"{p * 100:6.2f}% {r * 100:6.2f}% {f1 * 100:6.2f}%")

    if rows_csv is not None:
        for k in keys:
            t, f_p, f_n, p, r, f1 = prf(k)
            rows_csv.append({"mode": label, "type": k, "support": t + f_n, "tp": t,
                             "fp": f_p, "fn": f_n, "precision": round(p * 100, 4),
                             "recall": round(r * 100, 4), "f1": round(f1 * 100, 4)})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=["hinted", "blind", "both"], default="both")
    ap.add_argument("--engine", choices=["python", "typescript", "both"],
                    default="python")
    ap.add_argument("--per-file", action="store_true",
                    help="one totals row per dataset instead of the type table")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--csv", type=Path, default=None)
    args = ap.parse_args()

    records = load(args.limit)
    if not records:
        print("No datasets found; set EUREDACT_CORPUS.")
        return 77
    labelled = sum(1 for r in records if r.get("PII"))
    print(f"datasets : {len(DATASETS)} files "
          f"(the .bak is excluded — see module docstring)")
    print(f"records  : {len(records):,} ({labelled:,} carrying labels)")

    rows: list[dict] = [] if args.csv else None
    modes = ["hinted", "blind"] if args.mode == "both" else [args.mode]
    engines = ["python", "typescript"] if args.engine == "both" else [args.engine]
    charge_to = None

    if args.per_file:
        # One totals row per dataset, per engine, per mode. Answers "which
        # dataset is dragging a figure down" without reading 28 type rows.
        for engine in engines:
            for mode in modes:
                print(f"\n{engine} · {mode} detection")
                print(f"{'dataset':38s} {'labels':>9s} {'TP':>8s} {'FP':>7s} "
                      f"{'FN':>7s} {'prec':>7s} {'recall':>7s} {'F1':>7s}")
                print("-" * 96)
                agg = [Counter(), Counter(), Counter()]
                for name in DATASETS:
                    path = DATA_DIR / name
                    if not path.exists():
                        continue
                    subset = json.loads(path.read_text())
                    if args.limit:
                        subset = subset[:args.limit]
                    tp, fn, fp, elapsed, charge_to = evaluate(
                        subset, hinted=(mode == "hinted"), engine=engine)
                    for target, src in zip(agg, (tp, fn, fp)):
                        target.update(src)
                    core = [k for k in set(tp) | set(fn) | set(fp)
                            if k not in DOB_CATEGORIES]
                    T = sum(tp[k] for k in core)
                    FN_ = sum(fn[k] for k in core)
                    FP_ = sum(fp[k] for k in core)
                    P = T / (T + FP_) if T + FP_ else 0.0
                    R = T / (T + FN_) if T + FN_ else 0.0
                    F = 2 * P * R / (P + R) if P + R else 0.0
                    print(f"{name:38s} {T + FN_:9,} {T:8,} {FP_:7,} {FN_:7,} "
                          f"{P * 100:6.2f}% {R * 100:6.2f}% {F * 100:6.2f}%")
                    if rows is not None:
                        rows.append({"engine": engine, "mode": mode, "dataset": name,
                                     "labels": T + FN_, "tp": T, "fp": FP_, "fn": FN_,
                                     "precision": round(P * 100, 4),
                                     "recall": round(R * 100, 4),
                                     "f1": round(F * 100, 4)})
                tp, fn, fp = agg
                core = [k for k in set(tp) | set(fn) | set(fp)
                        if k not in DOB_CATEGORIES]
                T = sum(tp[k] for k in core)
                FN_ = sum(fn[k] for k in core)
                FP_ = sum(fp[k] for k in core)
                P = T / (T + FP_) if T + FP_ else 0.0
                R = T / (T + FN_) if T + FN_ else 0.0
                F = 2 * P * R / (P + R) if P + R else 0.0
                print("-" * 96)
                print(f"{'ALL TEN DATASETS':38s} {T + FN_:9,} {T:8,} {FP_:7,} "
                      f"{FN_:7,} {P * 100:6.2f}% {R * 100:6.2f}% {F * 100:6.2f}%")
    else:
        for engine in engines:
            for mode in modes:
                tp, fn, fp, elapsed, charge_to = evaluate(
                    records, hinted=(mode == "hinted"), engine=engine)
                report(tp, fn, fp, elapsed, rows,
                       label=f"{engine} · {mode} detection")

    print("\nfalse positives are charged to the category their type would satisfy:")
    shown = sorted({f"{t}->{c}" for t, c in charge_to.items() if t != c})
    print("  " + ", ".join(shown) if shown else "  (all types map to themselves)")

    if args.csv:
        with args.csv.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\ncsv written to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
