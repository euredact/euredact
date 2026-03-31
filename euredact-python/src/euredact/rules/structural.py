"""Structural detectors for DOB in JSON and delimited data.

These detect dates based on field names / column headers rather than
surrounding prose keywords. A JSON key like "date_naissance" or a CSV
header like "geboortedatum" is an unambiguous signal that the associated
value is a date of birth.
"""

from __future__ import annotations

import re

from euredact.types import Detection, DetectionSource, EntityType

# Date patterns (DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY, YYYY-MM-DD)
_DATE_RE = re.compile(
    r"(?:0[1-9]|[12]\d|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}"
    r"|(?:19|20)\d{2}[/.\-](?:0[1-9]|1[0-2])[/.\-](?:0[1-9]|[12]\d|3[01])"
)

# Keywords that indicate a date-of-birth field (lowercased for matching)
_DOB_FIELD_NAMES = [
    "geboortedatum", "date_naissance", "date de naissance", "geburtsdatum",
    "dob", "birth_date", "birthdate", "date_of_birth",
    "fecha_nacimiento", "data_nascita", "born",
    "naissance", "geboren",
]

# ── JSON detector ──────────────────────────────────────────────────────

# Matches: "key": "value" or "key":"value" where key contains a DOB keyword
# Captures: (full match start, value start, value end)
_JSON_KV = re.compile(
    r'"([^"]+?)"\s*:\s*"([^"]*?)"'
)


def detect_json_dob(text: str) -> list[Detection]:
    """Detect DOB values in JSON structures by inspecting field names."""
    detections: list[Detection] = []
    for m in _JSON_KV.finditer(text):
        key = m.group(1).lower().strip()
        value = m.group(2)
        # Check if the key is a DOB field
        if not any(kw in key for kw in _DOB_FIELD_NAMES):
            continue
        # Check if the value is a date
        dm = _DATE_RE.search(value)
        if dm:
            # Calculate absolute offset of the date within the original text
            val_start = m.start(2)
            abs_start = val_start + dm.start()
            abs_end = val_start + dm.end()
            detections.append(Detection(
                entity_type=EntityType.DOB,
                start=abs_start,
                end=abs_end,
                text=text[abs_start:abs_end],
                source=DetectionSource.RULES,
                country=None,
                confidence="high",
            ))
    return detections


# ── CSV / delimited detector ──────────────────────────────────────────

def detect_csv_dob(text: str) -> list[Detection]:
    """Detect DOB values in delimited data by inspecting header row.

    Supports comma, semicolon, pipe, and tab as delimiters.
    The first line must contain recognisable column names.
    """
    detections: list[Detection] = []

    # Split into lines; need at least a header + one data row
    lines = text.split("\n")
    if len(lines) < 2:
        return detections

    header_line = lines[0]

    # Detect delimiter
    delimiter = _detect_delimiter(header_line)
    if delimiter is None:
        return detections

    headers = [h.strip().lower() for h in header_line.split(delimiter)]
    if len(headers) < 2:
        return detections

    # Find which column indices are DOB fields
    dob_columns: list[int] = []
    for i, h in enumerate(headers):
        if any(kw in h for kw in _DOB_FIELD_NAMES):
            dob_columns.append(i)

    if not dob_columns:
        return detections

    # Track cumulative offset through the text (to compute absolute positions)
    offset = len(lines[0]) + 1  # +1 for the \n

    for line in lines[1:]:
        if not line.strip():
            offset += len(line) + 1
            continue

        fields = line.split(delimiter)

        for col_idx in dob_columns:
            if col_idx >= len(fields):
                continue

            field = fields[col_idx]
            dm = _DATE_RE.search(field)
            if dm:
                # Calculate field offset within the line
                field_offset = 0
                for fi in range(col_idx):
                    field_offset += len(fields[fi]) + len(delimiter)

                abs_start = offset + field_offset + dm.start()
                abs_end = offset + field_offset + dm.end()
                detections.append(Detection(
                    entity_type=EntityType.DOB,
                    start=abs_start,
                    end=abs_end,
                    text=text[abs_start:abs_end],
                    source=DetectionSource.RULES,
                    country=None,
                    confidence="high",
                ))

        offset += len(line) + 1

    return detections


def _detect_delimiter(header: str) -> str | None:
    """Detect the delimiter used in a header line."""
    # Count candidate delimiters
    for delim in ["|", ";", "\t", ","]:
        if header.count(delim) >= 2:
            return delim
    return None


def detect_structural_dob(text: str) -> list[Detection]:
    """Run all structural DOB detectors. Returns combined results."""
    results: list[Detection] = []
    results.extend(detect_json_dob(text))
    results.extend(detect_csv_dob(text))
    return results
