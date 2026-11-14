#!/usr/bin/env python3
"""What a refresh of the bundled GLEIF BIC list would change, as a Markdown report.

    python3 scripts/bic_mapping_diff.py --dir DIR          # download what it needs
    python3 scripts/bic_mapping_diff.py --dir DIR --offline OLD.zip [MID.zip ...] NEW.zip

Compares the bundled list (``euredact-python/src/euredact/rules/bic_gleif.py``)
with the latest GLEIF BIC-to-LEI mapping. Online, it downloads into *DIR* the
file the bundled list was built from and every file published since, so it can
tell a real drop from a prefix that is missing for one month. ``--offline``
takes those files instead, oldest first; the first stands for the bundled list.

The report answers what decides a refresh (rules-engine#161):

* counts: prefixes and BIC codes added and removed, kept BICs whose LEI changed;
* which changes detection can see. The bundled list only decides whether a
  letters-only code beside an IBAN, with no BIC label, is a bank or a word
  (``is_known_institution``, rules-engine#57); a prefix matters only if one of
  its BICs is letters-only in its first eight characters;
* for each removed prefix, where its LEI went (a rename or merger shows up as
  the same LEI under another BIC) and in which of the downloaded months it
  was present;
* for each added prefix, the same months.

It writes nothing outside *DIR* and changes nothing in the repository; the
refresh itself is ``scripts/refresh_bic_registry.py``. Stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "euredact-python" / "src" / "euredact" / "rules" / "bic_gleif.py"
LISTING = "https://mapping.gleif.org/api/v2/bic-lei?page%5Bnumber%5D={page}&page%5Bsize%5D=15"

#: The engine's 31 countries as BIC country codes (GR for EL, GB for UK); the
#: same tuple as refresh_bic_registry.py.
COUNTRIES = frozenset((
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
    "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LT", "LU", "LV", "MT", "NL",
    "NO", "PL", "PT", "RO", "SE", "SI", "SK",
))


def file_date(name: str) -> str:
    """The YYYYMMDD a mapping file is named for: LEI-BIC-20261030.zip, lei-bic-20261030T000000.csv."""
    found = re.search(r"(20\d{6})", name)
    if not found:
        sys.exit(f"cannot read a date from {name!r}")
    return found[1]


def path_date(path: Path) -> str:
    """A file's date, from the CSV's name inside a zip, which GLEIF sets."""
    if path.suffix.lower() == ".zip":
        return file_date(next(n for n in zipfile.ZipFile(path).namelist() if n.lower().endswith(".csv")))
    return file_date(path.name)


def read_rows(path: Path) -> set[tuple[str, str]]:
    """(BIC, LEI) pairs for the engine's countries, from a GLEIF zip or CSV."""
    if path.suffix.lower() == ".zip":
        archive = zipfile.ZipFile(path)
        data = archive.read(next(n for n in archive.namelist() if n.lower().endswith(".csv")))
    else:
        data = path.read_bytes()
    rows: set[tuple[str, str]] = set()
    for row in csv.DictReader(io.StringIO(data.decode("utf-8-sig"))):
        bic = (row.get("BIC") or "").strip().upper()
        if len(bic) in (8, 11) and bic[:6].isalpha() and bic[4:6] in COUNTRIES:
            rows.add((bic, (row.get("LEI") or "").strip().upper()))
    return rows


def bundled() -> tuple[str, frozenset[str]]:
    """The bundled list's source file date and its prefixes."""
    text = BUNDLED.read_text(encoding="utf-8")
    found = re.search(r"lei-\s*#?\s*bic-(20\d{6})", text.replace("\n", ""), re.IGNORECASE)
    if not found:
        sys.exit(f"cannot read the source file from the header of {BUNDLED}")
    namespace: dict = {}
    exec(compile(text, str(BUNDLED), "exec"), namespace)  # noqa: S102 - our own generated module
    return found[1], namespace["bic6_prefixes"]()


def download(directory: Path, since: str) -> list[Path]:
    """Every published file from *since* on, oldest first, saved in *directory*."""
    wanted: list[tuple[str, str]] = []
    page = 1
    while True:
        with urllib.request.urlopen(LISTING.format(page=page), timeout=60) as resp:
            listing = json.load(resp)
        for item in listing["data"]:
            attrs = item["attributes"]
            date = file_date(attrs["fileName"])
            if date >= since:
                wanted.append((date, attrs["downloadLink"].replace("\\/", "/")))
        oldest = min(file_date(i["attributes"]["fileName"]) for i in listing["data"])
        if oldest <= since or page >= listing["meta"]["page"]["last-page"]:
            break
        page += 1
    if not any(date == since for date, _ in wanted):
        sys.exit(f"GLEIF no longer lists the bundled list's source file ({since})")
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for date, link in sorted(wanted):
        path = directory / f"LEI-BIC-{date}.zip"
        if not path.exists():
            with urllib.request.urlopen(link, timeout=180) as resp:
                path.write_bytes(resp.read())
        paths.append(path)
    return paths


def letters_only(bic: str) -> bool:
    """Can this BIC be written as a code only the GLEIF list tells from a word?"""
    return bic[:8].isalpha()


def report(paths: list[Path], bundled_prefixes: frozenset[str] | None = None) -> str:
    """The Markdown report for files *paths*, oldest (the bundled one) first."""
    months = [path_date(p) for p in paths]
    rows = [read_rows(p) for p in paths]
    prefixes = [{b[:6] for b, _ in r} for r in rows]
    old_rows, new_rows = rows[0], rows[-1]
    old_p, new_p = prefixes[0], prefixes[-1]

    out: list[str] = []
    if bundled_prefixes is not None and bundled_prefixes != old_p:
        out.append(f"> **The bundled list is not {months[0]}'s file**: {len(bundled_prefixes ^ old_p)} "
                   "prefixes differ. Regenerate it from that file, or find out who edited it, "
                   "before trusting this report.\n")

    old_bics, new_bics = {b for b, _ in old_rows}, {b for b, _ in new_rows}
    leis_old, leis_new = defaultdict(set), defaultdict(set)
    for b, lei in old_rows:
        leis_old[b].add(lei)
    for b, lei in new_rows:
        leis_new[b].add(lei)
    bics_of_lei = defaultdict(set)
    for b, lei in new_rows:
        bics_of_lei[lei].add(b)
    added, removed = sorted(new_p - old_p), sorted(old_p - new_p)
    relevant = lambda ps, rs: [p for p in ps if any(letters_only(b) for b, _ in rs if b[:6] == p)]  # noqa: E731
    added_seen, removed_seen = relevant(added, new_rows), relevant(removed, old_rows)

    out.append(f"## GLEIF BIC list: {months[0]} → {months[-1]}\n")
    out.append("| | bundled | latest |\n|---|---:|---:|")
    out.append(f"| BIC6 prefixes (31 countries) | {len(old_p):,} | {len(new_p):,} |")
    out.append(f"| BIC codes | {len(old_bics):,} | {len(new_bics):,} |")
    out.append(f"\n- Prefixes: **{len(added)} added, {len(removed)} removed**.")
    out.append(f"- BIC codes: {len(new_bics - old_bics)} added, {len(old_bics - new_bics)} removed; "
               f"{sum(1 for b in old_bics & new_bics if leis_old[b] != leis_new[b])} kept BICs changed LEI.")
    out.append(f"- **Visible to detection** (a letters-only code): {len(added_seen)} of the additions, "
               f"{len(removed_seen)} of the removals.")
    out.append(f"- Months read: {', '.join(months)}.\n")

    def by_country(ps):
        return ", ".join(f"{c} {n}" for c, n in sorted(Counter(p[4:6] for p in ps).items())) or "none"

    out.append(f"Added by country: {by_country(added)}.  \nRemoved by country: {by_country(removed)}.\n")

    def seen(p):
        return " ".join("●" if p in ps else "○" for ps in prefixes)

    header = " ".join(m[2:6] for m in months)
    out.append(f"### Removed\n\n| prefix | its BICs | letters-only | its LEI now under | months ({header}) |")
    out.append("|---|---|:-:|---|---|")
    for p in removed:
        bics = sorted(b for b, _ in old_rows if b[:6] == p)
        moved = sorted({x for b in bics for lei in leis_old[b] for x in bics_of_lei.get(lei, ())})
        out.append(f"| `{p}` | {' '.join(bics)} | {'yes' if p in removed_seen else ''} | "
                   f"{' '.join(moved) or '—'} | {seen(p)} |")
    out.append(f"\n### Added\n\n| prefix | its BICs | letters-only | months ({header}) |")
    out.append("|---|---|:-:|---|")
    for p in added:
        bics = sorted(b for b, _ in new_rows if b[:6] == p)
        out.append(f"| `{p}` | {' '.join(bics)} | {'yes' if p in added_seen else ''} | {seen(p)} |")
    flapping = sorted(p for p in (added + removed) if any(p in ps for ps in prefixes[1:-1])
                      and any(p not in ps for ps in prefixes[1:-1]))
    if flapping:
        out.append(f"\nIn and out between the two: {' '.join(f'`{p}`' for p in flapping)}.")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dir", type=Path, required=True,
                        help="where downloads go; an empty directory of its own")
    parser.add_argument("--offline", nargs="+", type=Path, metavar="FILE",
                        help="mapping files, oldest (the bundled one) first, instead of downloading")
    args = parser.parse_args()
    since, prefixes = bundled()
    if args.offline:
        paths = args.offline
    else:
        paths = download(args.dir, since)
    if len(paths) < 2:
        print(f"The bundled list ({since}) is the latest GLEIF file; nothing to refresh.")
        return 0
    text = report(paths, prefixes if path_date(paths[0]) == since else None)
    args.dir.mkdir(parents=True, exist_ok=True)
    (args.dir / "report.md").write_text(text, encoding="utf-8")
    print(text)
    print(f"Latest file: {paths[-1]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
