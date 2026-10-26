"""Per-type corpus results under the API's type names (rules-engine#109).

`eval_full.py` scores the corpus by its own categories (`IBAN`,
`SOCIAL_SECURITY`, `TAX_ID_PERSONAL`, ...). What a caller sees in
`detections` are the API types (`BANK_ACCOUNT`, `SSN`, `TAX_ID`, ...), and the
Instructions for use on euredact.dev publish recall *and* precision per type,
with their conditions and no aggregate figure. This module turns one
`evaluate()` run per country mode into that table, as JSON (which the site
reads) and as the markdown results document rendered from the same JSON, so no
figure is copied by hand.

Recall is measured against corpus labels, so each category is attributed to the
one API type it is primarily expected as (:data:`API_TYPE`); a category that
also accepts other types counts a value masked by any of them as a hit, and the
table says which. Precision needs no attribution: the scorer already counts
true and false positives per emitted type.
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

from euredact.types import EntityType

#: Corpus category -> the API type a caller sees for it. The accepted types,
#: which decide a hit, are `eval_full.CATEGORY_MAP`; this decides the row.
API_TYPE: dict[str, str] = {
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "IBAN": "BANK_ACCOUNT",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "CREDIT_CARD": "CREDIT_CARD",
    "SWIFT_BIC": "BIC",
    "BIC": "BIC",
    "NATIONAL_ID": "NATIONAL_ID",
    "NATIONAL_ID_CARD": "NATIONAL_ID",
    "SOCIAL_SECURITY": "SSN",
    "TAX_ID": "TAX_ID",
    "TAX_ID_PERSONAL": "TAX_ID",
    "TAX_ID_BUSINESS": "VAT",
    "VAT_NUMBER": "VAT",
    "CHAMBER_OF_COMMERCE": "CHAMBER_OF_COMMERCE",
    "HEALTH_INSURANCE": "HEALTH_INSURANCE",
    "HEALTH_ID": "HEALTH_INSURANCE",
    "PASSPORT": "PASSPORT",
    "POSTAL_CODE": "POSTAL_CODE",
    "LICENSE_PLATE": "LICENSE_PLATE",
    "VIN": "VIN",
    "IP_ADDRESS": "IP_ADDRESS",
    "IP_ADDRESS_V6": "IPV6_ADDRESS",
    "IPV6_ADDRESS": "IPV6_ADDRESS",
    "MAC_ADDRESS": "MAC_ADDRESS",
    "IMEI": "IMEI",
    "GPS_COORDINATES": "GPS_COORDINATES",
    "UUID": "UUID",
    "SOCIAL_HANDLE": "SOCIAL_HANDLE",
    "SECRET": "SECRET",
    "DOB": "DOB",
}

#: What every published figure assumes. Rendered with the table, and read by
#: the site as RULES_CONDITIONS.
CONDITIONS: tuple[str, ...] = (
    'Rules engine only (mode="rules"); the cloud tier is not measured here.',
    "Synthetic corpus, generated for evaluation; no real person's data.",
    "Two country modes: 'hinted' passes each document's labelled countries as "
    "`countries`; 'blind' passes none.",
    "A hit is a labelled value whose every character is masked, at every place "
    "it occurs, by a type its category accepts. Fully masked by another type "
    "is 'mistyped': protected, but a miss for recall.",
    "A detection is a true positive when it overlaps a labelled value whose "
    "category accepts its type, and a false positive otherwise; a mistyped "
    "detection is a false positive for the type it was emitted as.",
    "Support and detections are counted differently: support is the labels of "
    "the categories attributed to a type, detections are everything the engine "
    "emitted as that type, and a detection is a true positive on any label "
    "whose category accepts its type. Most SSN and TAX_ID detections land on "
    "NATIONAL_ID labels, so their detections exceed their support.",
    "Precision is a lower bound: a real identifier the corpus left unlabelled "
    "counts as a false positive when the engine masks it.",
    "DOB is optional (the cloud tier owns bare dates) and reported separately, "
    "with detect_dates=True.",
    "CRYPTO_ADDRESS_BTC and CRYPTO_ADDRESS_ETH labels are excluded: no API type "
    "exists for them.",
    "The regression records (euromask_regressions.json) are excluded from the "
    "figures; they are adversarial by design and are reported as pass/fail.",
)


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 2) if d else None


def type_rows(stats: dict, category_map: dict[str, set[str]]) -> dict[str, dict]:
    """One row per API type from one `evaluate()` result."""
    rows: dict[str, dict] = {}
    for cat, total in stats["cat_total"].items():
        api = API_TYPE.get(cat, cat)
        row = rows.setdefault(
            api,
            {
                "support": 0,
                "hits": 0,
                "mistyped": 0,
                "partial": 0,
                "misses": 0,
                "unlocatable": 0,
                "categories": [],
                "accepts": set(),
            },
        )
        hits = stats["cat_tp"][cat]
        mistyped = stats["cat_mistyped"][cat]
        partial = stats["cat_partial"][cat]
        unloc = stats["cat_unlocatable"][cat]
        row["support"] += total
        row["hits"] += hits
        row["mistyped"] += mistyped
        row["partial"] += partial
        row["unlocatable"] += unloc
        row["misses"] += total - hits - mistyped - partial - unloc
        row["categories"].append(cat)
        row["accepts"] |= set(category_map.get(cat, {cat}))
    for api in set(stats["det_tp_by_type"]) | set(stats["det_fp_by_type"]):
        rows.setdefault(
            api,
            {
                "support": 0,
                "hits": 0,
                "mistyped": 0,
                "partial": 0,
                "misses": 0,
                "unlocatable": 0,
                "categories": [],
                "accepts": set(),
            },
        )
    for api, row in rows.items():
        tp, fp = (
            stats["det_tp_by_type"].get(api, 0),
            stats["det_fp_by_type"].get(api, 0),
        )
        row.update(
            detections=tp + fp,
            tp=tp,
            fp=fp,
            recall=_pct(row["hits"], row["support"]),
            precision=_pct(tp, tp + fp),
        )
        row["categories"] = sorted(row["categories"])
        row["also_accepts"] = sorted(row.pop("accepts") - {api})
    return dict(sorted(rows.items()))


def composition(datasets: list[tuple[str, list[dict]]], excluded: set[str]) -> dict:
    """What the figures were measured on, computed from the data itself."""
    files, labels, countries = [], Counter(), set()
    for name, records in datasets:
        n_labels = sum(len(r.get("PII", [])) for r in records)
        files.append({"file": name, "documents": len(records), "labels": n_labels})
        for r in records:
            for p in r.get("PII", []):
                labels[p["PII_category"]] += 1
                countries.add(p["PII_country"])
    return {
        "files": files,
        "documents": sum(f["documents"] for f in files),
        "labels": sum(f["labels"] for f in files),
        "labels_by_category": dict(labels.most_common()),
        "countries": sorted(countries),
        "excluded_files": sorted(excluded),
        "not_recorded": "The corpus records carry no language or document type; "
        "neither is reported until they do.",
    }


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).parent,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def engine_info(version: str) -> dict:
    """Which engine was measured. `version` alone misleads between releases:
    `main` keeps the last release's number until the next one is cut, so the
    figures say how far past the tag they were measured (rules-engine#109).

    A version with no tag yet is the release being cut: the release skill
    measures after the version bump and tags after the commit, so on the tag
    alone the figures it publishes would read "unreleased" (rules-engine#116).
    """
    describe = _git("describe", "--tags")
    tag = f"v{version}"
    return {
        "package": "euredact",
        "version": version,
        "commit": _git("rev-parse", "--short", "HEAD"),
        "describe": describe,
        # Without git (no repository, no tags) nothing can be said: unreleased.
        "released": describe is not None and (
            describe == tag or not _git("tag", "--list", tag)),
    }


def rules_types() -> list[str]:
    """Every type the rules engine can emit: its patterns and its label cues."""
    from euredact.rules import cues
    from euredact.rules.engine import RuleEngine

    engine = RuleEngine()
    engine.generate_candidates("")
    types = set()
    for entry in engine._matcher._patterns:
        pdef = entry[1] if isinstance(entry, tuple) else entry
        types.add(getattr(pdef, "entity_type", pdef).value)
    types |= {t.value for t, _ in cues.CUES}
    return sorted(types)


def coverage(modes: dict[str, dict]) -> dict:
    """Types the figures cannot speak for: emitted but never labelled
    (precision only), or neither labelled nor emitted (not measured)."""
    measured = {
        api for rows in modes.values() for api, r in rows.items() if r["support"]
    }
    detected = {
        api for rows in modes.values() for api, r in rows.items() if r["detections"]
    }
    every = set(rules_types())
    return {
        "precision_only": sorted((detected - measured) & every),
        "not_measured": sorted(every - measured - detected),
    }


def build_results(
    *,
    version: str,
    modes: dict[str, dict],
    category_map: dict[str, set[str]],
    corpus: dict,
    regressions: dict,
    generated: str,
) -> dict:
    rows = {name: type_rows(stats, category_map) for name, stats in modes.items()}
    return {
        "engine": engine_info(version),
        "generated": generated,
        "corpus": corpus,
        "mapping": [
            {
                "category": c,
                "api_type": API_TYPE.get(c, c),
                "accepts": sorted(category_map.get(c, {c})),
            }
            for c in sorted(corpus["labels_by_category"])
            if c in API_TYPE
        ],
        "conditions": list(CONDITIONS),
        "modes": rows,
        "coverage": coverage(rows),
        "regressions": regressions,
    }


def _fmt(v) -> str:
    return "—" if v is None else f"{v:.2f}%"


def render_markdown(results: dict) -> str:
    e, c = results["engine"], results["corpus"]
    out = [
        f"# Corpus results — euredact {e['version']}"
        + (
            ""
            if e.get("released", True)
            else f", unreleased ({e.get('describe') or e.get('commit')})"
        )
        + (
            f" (`{e['commit']}`)" if e.get("commit") and e.get("released", True) else ""
        ),
        "",
        f"Generated {results['generated']} by `make eval` from "
        "`corpus-results.json`, which carries the same figures. Per entity "
        "type, under the names the API returns. No aggregate figure is given: "
        "each row stands with the conditions below (rules-engine#109).",
        "",
        "## Conditions",
        "",
        *[f"- {line}" for line in results["conditions"]],
        "",
    ]
    known = {t.value for t in EntityType}
    for mode, rows in results["modes"].items():
        out += [
            f"## Per entity type — {mode}",
            "",
            "| Type | Support | Hits | Mistyped | Partial | Misses | Recall "
            "| Detections | FP | Precision | Corpus categories |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
        for api, r in rows.items():
            if api == "DOB":
                continue
            cats = ", ".join(r["categories"]) or "—"
            if r["also_accepts"]:
                cats += f" (also accepts {', '.join(r['also_accepts'])})"
            name = f"`{api}`" if api in known else f"`{api}`*"
            out.append(
                f"| {name} | {r['support']:,} | {r['hits']:,} | {r['mistyped']:,} | "
                f"{r['partial']:,} | {r['misses']:,} | {_fmt(r['recall'])} | "
                f"{r['detections']:,} | {r['fp']:,} | {_fmt(r['precision'])} | {cats} |"
            )
        if "DOB" in rows:
            r = rows["DOB"]
            out += [
                "",
                f"Optional: `DOB` — support {r['support']:,}, recall "
                f"{_fmt(r['recall'])}, detections {r['detections']:,}, FP {r['fp']:,}, "
                f"precision {_fmt(r['precision'])}.",
            ]
        out.append("")
    cov = results.get("coverage", {})
    if cov.get("precision_only"):
        out += [
            "Emitted but never labelled in this corpus — precision is "
            "measured, recall is not: "
            + ", ".join(f"`{t}`" for t in cov["precision_only"])
            + ".",
            "",
        ]
    if cov.get("not_measured"):
        out += [
            "The rules engine can emit these types, but this corpus neither "
            "labels nor produces them, so no figure is given: "
            + ", ".join(f"`{t}`" for t in cov["not_measured"])
            + ".",
            "",
        ]
    out += [
        "",
        "## Category → API type",
        "",
        "| Corpus category | API type | A hit accepts |",
        "|---|---|---|",
    ]
    for m in results["mapping"]:
        out.append(
            f"| `{m['category']}` | `{m['api_type']}` | "
            f"{', '.join(f'`{a}`' for a in m['accepts'])} |"
        )
    out += [
        "",
        "## Corpus",
        "",
        f"{c['documents']:,} documents, {c['labels']:,} labels, "
        f"{len([x for x in c['countries'] if x != 'INTL'])} countries"
        + (" plus `INTL`" if "INTL" in c["countries"] else "")
        + ".",
        "",
        "| File | Documents | Labels |",
        "|---|---:|---:|",
    ]
    for f in c["files"]:
        out.append(f"| `{f['file']}` | {f['documents']:,} | {f['labels']:,} |")
    out += [
        "",
        f"Countries: {', '.join(c['countries'])}.",
        "",
        f"Excluded: {', '.join(f'`{x}`' for x in c['excluded_files']) or 'none'}. "
        + c["not_recorded"],
        "",
        "Labels per category: "
        + ", ".join(f"`{k}` {v:,}" for k, v in c["labels_by_category"].items())
        + ".",
        "",
    ]
    reg = results["regressions"]
    out += [
        "## Regression records",
        "",
        f"{reg['records']:,} records from `tests/regression_corpus.py`, "
        f"{reg['failures']:,} failures, checked in both modes.",
        "",
    ]
    return "\n".join(out)


def write(results: dict, stem: Path) -> tuple[Path, Path]:
    stem = Path(stem)
    js, md = stem.with_suffix(".json"), stem.with_suffix(".md")
    js.write_text(
        json.dumps(results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md.write_text(render_markdown(results), encoding="utf-8")
    return js, md
