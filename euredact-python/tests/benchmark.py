"""euredact benchmark — Python

Evaluates recall, precision, and latency across all test datasets.
Run: python tests/benchmark.py
     python tests/benchmark.py --json
     python tests/benchmark.py --json --sample-size 999999 --output results.json
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import euredact

DATA_DIR = Path(
    "/Users/jorenjanssens/Library/Mobile Documents"
    "/com~apple~CloudDocs/Werken/JNJS/Apps/PII-EuroMask/Data-Generation"
)

FILES = [
    "euromask_training_core2.json",
    "euromask_training_core.json",
    "euromask_nordic_20k.json",
    "euromask_international_10k.json",
    "euromask_ie_baltics_uk_20k.json",
    "euromask_el_cy_mt_20k.json",
    "euromask_eastern_20k.json",
    "euromask_dach_south_20k.json",
    "euromask_allcountries_20k.json",
    "euromask_secrets_5k.json",
]

CATEGORY_MAP: dict[str, str] = {
    "EMAIL": "EMAIL",
    "IBAN": "IBAN",
    "PHONE": "PHONE",
    "NATIONAL_ID": "NATIONAL_ID",
    "NATIONAL_ID_CARD": "NATIONAL_ID",
    "POSTAL_CODE": "POSTAL_CODE",
    "VAT_NUMBER": "VAT",
    "SWIFT_BIC": "BIC",
    "TAX_ID": "TAX_ID",
    "TAX_ID_PERSONAL": "TAX_ID",
    "TAX_ID_BUSINESS": "TAX_ID",
    "SOCIAL_SECURITY": "SSN",
    "IP_ADDRESS": "IP_ADDRESS",
    "IP_ADDRESS_V6": "IPV6_ADDRESS",
    "VIN": "VIN",
    "CHAMBER_OF_COMMERCE": "CHAMBER_OF_COMMERCE",
    "UUID": "UUID",
    "LICENSE_PLATE": "LICENSE_PLATE",
    "CREDIT_CARD": "CREDIT_CARD",
    "MAC_ADDRESS": "MAC_ADDRESS",
    "IMEI": "IMEI",
    "SOCIAL_HANDLE": "SOCIAL_HANDLE",
    "GPS_COORDINATES": "GPS_COORDINATES",
    "PASSPORT": "PASSPORT",
    "HEALTH_INSURANCE": "HEALTH_INSURANCE",
    "HEALTH_ID": "HEALTHCARE_PROVIDER",
    "SECRET": "SECRET",
    "DOB": "DOB",
}


def clean_str(s: str) -> str:
    return re.sub(r"[\s.\-]", "", s)


def run_benchmark(sample_size: int = 500) -> dict:
    countries = list(euredact.available_countries())

    file_results: list[dict] = []
    files_skipped: list[str] = []
    total_expected = 0
    total_detected = 0
    total_tp = 0
    total_samples = 0
    total_elapsed = 0.0
    category_stats: dict[str, dict[str, int]] = {}

    for filename in FILES:
        path = DATA_DIR / filename
        if not path.exists():
            files_skipped.append(filename)
            continue

        with open(path) as f:
            data = json.load(f)

        sample = data[:sample_size]
        n = len(sample)
        total_samples += n

        file_expected = 0
        file_detected = 0
        file_tp = 0

        t0 = time.perf_counter()

        for entry in sample:
            expected_pii = [
                {**p, "mapped": CATEGORY_MAP[p["PII_category"]]}
                for p in entry["PII"]
                if p["PII_category"] in CATEGORY_MAP
                and CATEGORY_MAP[p["PII_category"]] != "DOB"
            ]

            file_expected += len(expected_pii)

            known = set(euredact.available_countries())
            entry_countries = [
                c for c in {p["PII_country"] for p in entry["PII"] if p["PII_country"]}
                if c in known
            ]

            result = euredact.redact(
                entry["source_text"],
                countries=entry_countries if entry_countries else None,
                detect_dates=False,
            )

            non_dob = [
                d for d in result.detections
                if (d.entity_type.value if hasattr(d.entity_type, "value") else d.entity_type)
                   not in ("DOB", "DATE_OF_DEATH")
            ]
            file_detected += len(non_dob)

            for exp in expected_pii:
                cat = exp["mapped"]
                if cat not in category_stats:
                    category_stats[cat] = {"expected": 0, "detected": 0, "tp": 0}
                category_stats[cat]["expected"] += 1

                exp_clean = clean_str(exp["PII_identifier"])
                found = any(
                    exp_clean in clean_str(d.text) or clean_str(d.text) in exp_clean
                    for d in non_dob
                )

                if found:
                    file_tp += 1
                    category_stats[cat]["tp"] += 1

            for d in non_dob:
                etype = d.entity_type.value if hasattr(d.entity_type, "value") else d.entity_type
                if etype not in category_stats:
                    category_stats[etype] = {"expected": 0, "detected": 0, "tp": 0}
                category_stats[etype]["detected"] += 1

        elapsed = time.perf_counter() - t0
        total_elapsed += elapsed

        file_results.append({
            "filename": filename,
            "n": n,
            "expected": file_expected,
            "detected": file_detected,
            "tp": file_tp,
            "elapsed_s": round(elapsed, 4),
        })

        total_expected += file_expected
        total_detected += file_detected
        total_tp += file_tp

    return {
        "runtime": "python",
        "runtime_version": sys.version.split()[0],
        "library_version": euredact.__version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_size_per_file": sample_size,
        "countries": countries,
        "files": file_results,
        "files_skipped": files_skipped,
        "overall": {
            "samples": total_samples,
            "expected": total_expected,
            "detected": total_detected,
            "tp": total_tp,
            "total_time_s": round(total_elapsed, 2),
        },
        "categories": category_stats,
    }


def print_text_report(result: dict) -> None:
    print(f"euredact benchmark — Python {result['runtime_version']}")
    print(f"Available countries: {', '.join(result['countries'])}")
    print(f"Sample size per file: {result['sample_size_per_file']}")
    print()

    for f in result["files"]:
        recall = f"{f['tp'] / f['expected'] * 100:.1f}" if f["expected"] else "N/A"
        precision = f"{f['tp'] / f['detected'] * 100:.1f}" if f["detected"] else "N/A"
        ms = f"{f['elapsed_s'] / f['n'] * 1000:.2f}"
        print(
            f"{f['filename']:<40} n={f['n']} expected={f['expected']} "
            f"detected={f['detected']} TP={f['tp']} "
            f"recall={recall}% precision={precision}% "
            f"{ms}ms/sample"
        )

    for skip in result["files_skipped"]:
        print(f"SKIP {skip}: not found")

    o = result["overall"]
    print()
    print("=== OVERALL (excl. DOB) ===")
    recall = f"{o['tp'] / o['expected'] * 100:.1f}" if o["expected"] else "N/A"
    precision = f"{o['tp'] / o['detected'] * 100:.1f}" if o["detected"] else "N/A"
    f1 = (
        f"{2 * o['tp'] / (o['expected'] + o['detected']):.3f}"
        if o["expected"] and o["detected"] else "N/A"
    )
    print(f"Samples: {o['samples']}, Expected: {o['expected']}, Detected: {o['detected']}, TP: {o['tp']}")
    print(f"Recall: {recall}%, Precision: {precision}%, F1: {f1}")
    print(f"Total time: {o['total_time_s']:.2f}s, avg: {o['total_time_s'] / o['samples'] * 1000:.2f}ms/sample")

    print()
    print("=== BY CATEGORY ===")
    cats = result["categories"]
    for cat, stats in sorted(cats.items(), key=lambda x: -x[1]["expected"]):
        r = f"{stats['tp'] / stats['expected'] * 100:.1f}" if stats["expected"] else "N/A"
        p = f"{stats['tp'] / stats['detected'] * 100:.1f}" if stats["detected"] else "N/A"
        print(
            f"  {cat:<25} expected={stats['expected']:>5} "
            f"detected={stats['detected']:>5} TP={stats['tp']:>5} "
            f"recall={r}% precision={p}%"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="euredact benchmark — Python")
    parser.add_argument("--json", action="store_true", help="Output JSON results")
    parser.add_argument("--sample-size", type=int, default=500, help="Max samples per file (default: 500)")
    parser.add_argument("--output", type=str, default=None, help="Write JSON to file instead of stdout")
    args = parser.parse_args()

    result = run_benchmark(args.sample_size)

    if args.json:
        out = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(out)
        else:
            print(out)
    else:
        print_text_report(result)


if __name__ == "__main__":
    main()
