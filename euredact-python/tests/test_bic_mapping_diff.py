"""The BIC-list refresh tooling: the diff report and the zip input (rules-engine#163).

Runs on small synthetic mapping files, offline; the real files are 1.3 MB each
and a month apart.
"""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


diff = _load("bic_mapping_diff")
refresh = _load("refresh_bic_registry")

LEI_A, LEI_B, LEI_C, LEI_D, LEI_E = ("5299" + c * 16 for c in "ABCDE")


def _mapping(tmp_path: Path, date: str, rows: list[tuple[str, str]]) -> Path:
    """A file as GLEIF publishes it: a zip named for the day, a dated CSV inside."""
    path = tmp_path / f"LEI-BIC-{date}.zip"
    body = "LEI,BIC\n" + "".join(f"{lei},{bic}\n" for bic, lei in rows)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"lei-bic-{date}T000000.csv", body)
    return path


@pytest.fixture
def three_months(tmp_path):
    old = _mapping(tmp_path, "20260925", [
        ("SCFBESMMXXX", LEI_A),   # renamed: its LEI moves to OPENESMM
        ("SWEDGB21XXX", LEI_B),   # dropped, not letters-only
        ("ABNANL2AXXX", LEI_C),   # kept
        ("ZZZZUS33XXX", LEI_D),   # outside the 31 countries: ignored
    ])
    mid = _mapping(tmp_path, "20261030", [
        ("ABNANL2AXXX", LEI_C),
    ])
    new = _mapping(tmp_path, "20261127", [
        ("OPENESMMXXX", LEI_A),
        ("ABNANL2AXXX", LEI_E),   # kept, but its LEI changed
        ("REVOATWW", LEI_D),
    ])
    return old, mid, new


def test_the_report_counts_and_names_what_detection_can_see(three_months):
    text = diff.report(list(three_months))
    assert "| BIC6 prefixes (31 countries) | 3 | 3 |" in text
    assert "Prefixes: **2 added, 2 removed**" in text
    assert "1 kept BICs changed LEI" in text
    # REVOATWW and OPENESMM are letters-only; SCFBESMM is, SWEDGB21 is not.
    assert "2 of the additions, 1 of the removals" in text
    assert "| `SCFBES` | SCFBESMMXXX | yes | OPENESMMXXX | ● ○ ○ |" in text
    assert "| `SWEDGB` | SWEDGB21XXX |  | — | ● ○ ○ |" in text
    assert "| `REVOAT` | REVOATWW | yes | ○ ○ ● |" in text
    assert "ZZZZ" not in text
    assert "Months read: 20260925, 20261030, 20261127" in text


def test_a_prefix_missing_for_one_month_is_called_out(tmp_path):
    """ABGRDE and PIRBGR were in July and August, out in September, back in
    October (rules-engine#161): an addition that is a return, not news."""
    months = [
        _mapping(tmp_path, "20260724", [("ABNANL2AXXX", LEI_A)]),
        _mapping(tmp_path, "20260828", [("ABNANL2AXXX", LEI_A), ("PIRBGRAAXXX", LEI_B)]),
        _mapping(tmp_path, "20260925", [("ABNANL2AXXX", LEI_A)]),
        _mapping(tmp_path, "20261030", [("ABNANL2AXXX", LEI_A), ("PIRBGRAAXXX", LEI_B)]),
    ]
    text = diff.report(months)
    assert "| `PIRBGR` | PIRBGRAAXXX | yes | ○ ● ○ ● |" in text
    assert "In and out between the two: `PIRBGR`." in text
    assert "In and out" not in diff.report([months[0], months[3]])


def test_a_bundled_list_that_is_not_its_source_file_is_flagged(three_months):
    text = diff.report(list(three_months), bundled_prefixes=frozenset({"ABNANL"}))
    assert text.startswith("> **The bundled list is not 20260925's file**")
    same = diff.report(list(three_months), bundled_prefixes=frozenset({"SCFBES", "SWEDGB", "ABNANL"}))
    assert same.startswith("## GLEIF BIC list")


def test_the_date_of_a_zip_is_the_csv_inside_it(tmp_path):
    path = _mapping(tmp_path, "20261030", [("ABNANL2AXXX", LEI_A)])
    renamed = path.rename(tmp_path / "lei-bic.zip")
    assert diff.path_date(renamed) == "20261030"


def test_the_bundled_list_is_read_with_its_source_date():
    since, prefixes = diff.bundled()
    assert len(since) == 8 and since.startswith("20")
    assert len(prefixes) > 10_000 and "ABNANL" in prefixes


def test_refresh_takes_the_zip_gleif_publishes(tmp_path, monkeypatch):
    """It read the version from the file name and refused LEI-BIC-…zip."""
    for package in ("euredact-python", "euredact-ts"):
        (tmp_path / package).mkdir()
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "PY_OUT", tmp_path / "bic_gleif.py")
    monkeypatch.setattr(refresh, "TS_OUT", tmp_path / "bicGleif.ts")
    source = _mapping(tmp_path, "20261030", [("ABNANL2AXXX", LEI_A), ("REVOATWW", LEI_B)])
    monkeypatch.setattr("sys.argv", ["refresh_bic_registry.py", str(source.rename(tmp_path / "x.zip"))])
    assert refresh.main() == 0
    generated = (tmp_path / "bic_gleif.py").read_text(encoding="utf-8")
    assert "VERSION = 'October 2026'" in generated
    assert "lei-bic-20261030T000000.csv" in generated.replace("\n# ", "")
    assert "October 2026" in (tmp_path / "euredact-ts" / "NOTICE").read_text(encoding="utf-8")
