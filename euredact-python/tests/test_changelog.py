"""The root changelog is a contract, so it is tested like one.

A convention that lives only in a CONTRIBUTING note decays: this repository
accumulated sixteen distinct ``###`` section names across its two package
changelogs -- ``Accuracy``, ``Performance``, ``CI``, ``Breaking``,
``Measured effect``, ``Also in this release`` and more -- because nothing
enforced a vocabulary. Five of the sixteen are Keep a Changelog types. These
tests are what keep the root file from going the same way.

They deliberately do **not** police the per-package changelogs' historical
sections. Those are a record of what was written at the time; rewriting them to
match a vocabulary adopted later would be editing history to look tidier than
it was. Only the things that are defects under any vocabulary are checked
there: a heading with trailing whitespace (none today -- this is prevention,
not a repair), and a shipped version with no entry at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from euredact import __version__

ROOT = Path(__file__).resolve().parents[2]
ROOT_CHANGELOG = ROOT / "CHANGELOG.md"
PACKAGE_CHANGELOGS = [
    ROOT / "euredact-python" / "CHANGELOG.md",
    ROOT / "euredact-ts" / "CHANGELOG.md",
]

#: Keep a Changelog 1.1.0's six types, plus the two blocks this project
#: declares in the file's own header. Anything else is a typo or drift.
ALLOWED_SECTIONS = {
    "Added", "Changed", "Deprecated", "Removed", "Fixed", "Security",
    "Known issues", "Notes",
}

RELEASE = re.compile(r"^## (?:\[(?P<linked>[^\]]+)\]|(?P<plain>\S+))(?: - (?P<date>\S+))?\s*$")


def _text() -> str:
    return ROOT_CHANGELOG.read_text(encoding="utf-8")


def _releases(text: str) -> list[tuple[str, str | None]]:
    out = []
    for line in text.splitlines():
        m = RELEASE.match(line)
        if m:
            out.append((m.group("linked") or m.group("plain"), m.group("date")))
    return out


class TestRootChangelog:
    def test_it_exists(self) -> None:
        assert ROOT_CHANGELOG.is_file(), (
            "the root CHANGELOG.md is what PyPI and npm readers are pointed at"
        )

    def test_it_declares_the_format(self) -> None:
        text = _text()
        assert "keepachangelog.com" in text
        assert "semver.org" in text

    def test_every_section_is_an_allowed_type(self) -> None:
        bad = {
            line for line in _text().splitlines()
            if line.startswith("### ") and line[4:].strip() not in ALLOWED_SECTIONS
        }
        assert not bad, f"sections outside the declared vocabulary: {sorted(bad)}"

    def test_no_heading_has_trailing_whitespace(self) -> None:
        # "### Fixed " and "### Fixed" are different anchors and group
        # separately in every tool that reads this file.
        bad = [
            line for line in _text().splitlines()
            if line.startswith("#") and line != line.rstrip()
        ]
        assert not bad, f"headings with trailing whitespace: {bad}"

    def test_the_current_version_has_an_entry(self) -> None:
        versions = [v for v, _ in _releases(_text())]
        assert __version__ in versions, (
            f"{__version__} is the shipped version and has no changelog entry; "
            f"the file lists {versions[:4]}"
        )

    def test_there_is_an_unreleased_section(self) -> None:
        assert "## [Unreleased]" in _text(), (
            "Keep a Changelog keeps an Unreleased section so work in flight "
            "has somewhere to go"
        )

    def test_releases_are_newest_first(self) -> None:
        def key(v: str) -> tuple[int, ...]:
            return tuple(int(p) for p in v.split("."))

        versions = [v for v, _ in _releases(_text()) if v != "Unreleased"]
        assert versions == sorted(versions, key=key, reverse=True), (
            f"releases are out of order: {versions}"
        )

    def test_every_release_is_dated_except_the_undated_one(self) -> None:
        # 0.2.0 predates this repository dating its releases; everything after
        # it must carry a date, because "which release am I running" is the
        # first question an auditor asks.
        undated = [v for v, d in _releases(_text()) if d is None and v != "Unreleased"]
        assert undated == ["0.2.0"], f"undated releases: {undated}"

    def test_every_link_reference_is_defined(self) -> None:
        text = _text()
        used = {m.group(1) for m in re.finditer(r"^## \[([^\]]+)\]", text, re.M)}
        defined = {m.group(1) for m in re.finditer(r"^\[([^\]]+)\]:", text, re.M)}
        assert not (used - defined), f"undefined link references: {sorted(used - defined)}"

    def test_both_sdks_are_pointed_at(self) -> None:
        text = _text()
        assert "euredact-python/CHANGELOG.md" in text
        assert "euredact-ts/CHANGELOG.md" in text


class TestPackageChangelogs:
    @pytest.mark.parametrize("path", PACKAGE_CHANGELOGS, ids=lambda p: p.parent.name)
    def test_no_heading_has_trailing_whitespace(self, path: Path) -> None:
        bad = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("#") and line != line.rstrip()
        ]
        assert not bad, f"{path.name}: headings with trailing whitespace: {bad}"

    @pytest.mark.parametrize("path", PACKAGE_CHANGELOGS, ids=lambda p: p.parent.name)
    def test_the_current_version_has_an_entry(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        assert re.search(rf"^## {re.escape(__version__)}\b", text, re.M), (
            f"{path.name} has no entry for the shipped version {__version__}"
        )

    @pytest.mark.parametrize("path", PACKAGE_CHANGELOGS, ids=lambda p: p.parent.name)
    def test_it_points_at_the_root_changelog(self, path: Path) -> None:
        assert "CHANGELOG.md" in path.read_text(encoding="utf-8")
