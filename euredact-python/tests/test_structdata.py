"""Extensive evaluation against structured test data."""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import euredact
from euredact.types import EntityType

DATA_FILE = Path(__file__).resolve().parents[2] / "Data-Generation" / "euredact_structdata_BENLLUFRDE.json"

# Map test data PII categories to our EntityType values
CATEGORY_MAP: dict[str, set[str]] = {
    "NATIONAL_ID": {EntityType.NATIONAL_ID.value, EntityType.SSN.value},
    "NATIONAL_ID_CARD": {EntityType.NATIONAL_ID.value},
    "SOCIAL_SECURITY": {EntityType.NATIONAL_ID.value, EntityType.SSN.value},
    "TAX_ID": {EntityType.TAX_ID.value},
    "TAX_ID_PERSONAL": {EntityType.TAX_ID.value},
    "TAX_ID_BUSINESS": {EntityType.VAT.value, EntityType.TAX_ID.value},
    "IBAN": {EntityType.IBAN.value},
    "CREDIT_CARD": {EntityType.CREDIT_CARD.value},
    "VAT_NUMBER": {EntityType.VAT.value, EntityType.CHAMBER_OF_COMMERCE.value},
    "PHONE": {EntityType.PHONE.value},
    "EMAIL": {EntityType.EMAIL.value},
    "DOB": {EntityType.DOB.value},
    "POSTAL_CODE": {EntityType.POSTAL_CODE.value},
    "LICENSE_PLATE": {EntityType.LICENSE_PLATE.value},
    "VIN": {EntityType.VIN.value},
    "PASSPORT": {EntityType.PASSPORT.value},
    "HEALTH_INSURANCE": {EntityType.HEALTH_INSURANCE.value, EntityType.NATIONAL_ID.value},
    "CHAMBER_OF_COMMERCE": {EntityType.CHAMBER_OF_COMMERCE.value, EntityType.VAT.value},
}


def load_data():
    if not DATA_FILE.exists():
        # Try alternate path
        alt = Path("/Users/jorenjanssens/Library/Mobile Documents/com~apple~CloudDocs/Werken/JNJS/Apps/PII-EuRedact/Data-Generation/euredact_structdata_BENLLUFRDE.json")
        if alt.exists():
            with open(alt) as f:
                return json.load(f)
        return None
    with open(DATA_FILE) as f:
        return json.load(f)


def run_evaluation():
    data = load_data()
    if data is None:
        print("Test data file not found, skipping.")
        return

    total_pii = 0
    detected_pii = 0
    missed_pii = 0

    # Track per category and per country
    cat_total: Counter = Counter()
    cat_detected: Counter = Counter()
    country_total: Counter = Counter()
    country_detected: Counter = Counter()
    cat_country_total: Counter = Counter()
    cat_country_detected: Counter = Counter()

    missed_examples: defaultdict[str, list] = defaultdict(list)

    for i, item in enumerate(data):
        text = item["source_text"]
        expected_pii = item["PII"]

        if not expected_pii:
            continue

        # Determine countries from annotations
        countries_in_item = list({p["PII_country"] for p in expected_pii})

        result = euredact.redact(text, countries=countries_in_item, cache=False)

        # Check each expected PII
        for pii in expected_pii:
            pii_text = pii["PII_identifier"]
            pii_cat = pii["PII_category"]
            pii_country = pii["PII_country"]
            acceptable_types = CATEGORY_MAP.get(pii_cat, {pii_cat})

            total_pii += 1
            cat_total[pii_cat] += 1
            country_total[pii_country] += 1
            cat_country_total[(pii_cat, pii_country)] += 1

            # Check if this PII was detected:
            # The PII text should appear in the redacted output replaced (i.e., NOT present)
            # OR one of our detections should overlap with the PII text position
            found = False

            # Method 1: Check if the PII text was removed from output
            if pii_text not in result.redacted_text:
                found = True

            # Method 2: Check if any detection covers this PII text
            if not found:
                pii_start = text.find(pii_text)
                if pii_start >= 0:
                    pii_end = pii_start + len(pii_text)
                    for det in result.detections:
                        # Check overlap
                        if det.start < pii_end and det.end > pii_start:
                            if det.entity_type.value in acceptable_types:
                                found = True
                                break

            if found:
                detected_pii += 1
                cat_detected[pii_cat] += 1
                country_detected[pii_country] += 1
                cat_country_detected[(pii_cat, pii_country)] += 1
            else:
                missed_pii += 1
                key = f"{pii_cat}|{pii_country}"
                if len(missed_examples[key]) < 3:
                    missed_examples[key].append({
                        "text_snippet": text[:120] + "..." if len(text) > 120 else text,
                        "pii_text": pii_text,
                        "detections_found": [
                            f"{d.entity_type.value}:{d.text}"
                            for d in result.detections
                        ],
                    })

    # Print results
    recall = detected_pii / total_pii * 100 if total_pii else 0
    print(f"\n{'='*70}")
    print(f"EUROMASK RULE ENGINE — STRUCTURED DATA EVALUATION")
    print(f"{'='*70}")
    print(f"Total PII items:  {total_pii}")
    print(f"Detected:         {detected_pii} ({recall:.1f}%)")
    print(f"Missed:           {missed_pii} ({100-recall:.1f}%)")
    print()

    # Per category
    print(f"{'CATEGORY':<25} {'TOTAL':>7} {'DETECTED':>9} {'RECALL':>8}")
    print(f"{'-'*25} {'-'*7} {'-'*9} {'-'*8}")
    for cat in sorted(cat_total, key=lambda c: -cat_total[c]):
        t = cat_total[cat]
        d = cat_detected[cat]
        r = d / t * 100 if t else 0
        flag = " ⚠" if r < 80 else ""
        print(f"{cat:<25} {t:>7} {d:>9} {r:>7.1f}%{flag}")

    print()

    # Per country
    print(f"{'COUNTRY':<10} {'TOTAL':>7} {'DETECTED':>9} {'RECALL':>8}")
    print(f"{'-'*10} {'-'*7} {'-'*9} {'-'*8}")
    for c in sorted(country_total, key=lambda x: -country_total[x]):
        t = country_total[c]
        d = country_detected[c]
        r = d / t * 100 if t else 0
        print(f"{c:<10} {t:>7} {d:>9} {r:>7.1f}%")

    print()

    # Per category+country for low-recall combinations
    print("LOW RECALL (<80%) by category + country:")
    print(f"{'CATEGORY':<25} {'COUNTRY':<8} {'TOTAL':>7} {'DETECTED':>9} {'RECALL':>8}")
    print(f"{'-'*25} {'-'*8} {'-'*7} {'-'*9} {'-'*8}")
    for (cat, country) in sorted(cat_country_total, key=lambda x: -cat_country_total[x]):
        t = cat_country_total[(cat, country)]
        d = cat_country_detected[(cat, country)]
        r = d / t * 100 if t else 0
        if r < 80 and t >= 5:
            print(f"{cat:<25} {country:<8} {t:>7} {d:>9} {r:>7.1f}%")

    # Show missed examples
    if missed_examples:
        print(f"\n{'='*70}")
        print("MISSED EXAMPLES (up to 3 per category+country):")
        print(f"{'='*70}")
        for key in sorted(missed_examples):
            print(f"\n--- {key} ---")
            for ex in missed_examples[key]:
                print(f"  PII: \"{ex['pii_text']}\"")
                print(f"  Text: {ex['text_snippet']}")
                if ex['detections_found']:
                    print(f"  Detections found: {ex['detections_found'][:5]}")
                print()


if __name__ == "__main__":
    run_evaluation()
