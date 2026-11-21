#!/usr/bin/env python3
"""Bump the version and date the changelogs: the release skill's steps 1 and 2.

    scripts/bump_version.py X.Y.Z [--date YYYY-MM-DD] [--branch BRANCH]
    scripts/bump_version.py --check

It changes, and nothing else:

- the version in ``euredact-python/pyproject.toml``,
  ``euredact-python/src/euredact/__init__.py``, ``euredact-ts/package.json``
  and the two entries of ``euredact-ts/package-lock.json`` that name the
  package itself;
- ``## Unreleased`` to ``## X.Y.Z (date)`` in both package changelogs;
- in the root ``CHANGELOG.md`` (Keep a Changelog): an empty
  ``## [Unreleased]`` above a new ``## [X.Y.Z] - date``, the ``[Unreleased]``
  link to ``compare/vX.Y.Z...BRANCH`` and a new ``[X.Y.Z]`` link to
  ``compare/vPREV...vX.Y.Z``.

``BRANCH`` is ``main`` by default, or the line's ``release/X.Y.x`` for a
maintenance release; ``PREV`` is the version the files declare now. It refuses
anything it cannot do exactly (a changelog without its Unreleased section, a
version file it cannot parse, a version that does not move forward) rather
than leaving the four files disagreeing, which is the failure step 1 of the
skill exists to prevent (rules-engine#204).

``--check`` prints the version each file declares and fails unless they agree.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = "euredact-python/pyproject.toml"
INIT = "euredact-python/src/euredact/__init__.py"
PACKAGE = "euredact-ts/package.json"
LOCK = "euredact-ts/package-lock.json"
PACKAGE_CHANGELOGS = ("euredact-python/CHANGELOG.md", "euredact-ts/CHANGELOG.md")
ROOT_CHANGELOG = "CHANGELOG.md"
COMPARE = "https://git.euredact.dev/euredact/rules-engine/compare"

_VERSION = re.compile(r"\d+\.\d+\.\d+")
_PYPROJECT_LINE = re.compile(r'(?m)^version = "(\d+\.\d+\.\d+)"$')
_INIT_LINE = re.compile(r'(?m)^__version__ = "(\d+\.\d+\.\d+)"$')
_PACKAGE_LINE = re.compile(r'(?m)^  "version": "(\d+\.\d+\.\d+)",$')


class BumpError(Exception):
    pass


def _one(pattern: re.Pattern[str], text: str, path: str) -> re.Match[str]:
    found = list(pattern.finditer(text))
    if len(found) != 1:
        raise BumpError(f"{path}: expected one version line, found {len(found)}")
    return found[0]


def declared(root: Path = ROOT) -> dict[str, str]:
    """The version each of the four places declares."""
    lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
    return {
        PYPROJECT: _one(_PYPROJECT_LINE, (root / PYPROJECT).read_text(encoding="utf-8"), PYPROJECT)[1],
        INIT: _one(_INIT_LINE, (root / INIT).read_text(encoding="utf-8"), INIT)[1],
        PACKAGE: _one(_PACKAGE_LINE, (root / PACKAGE).read_text(encoding="utf-8"), PACKAGE)[1],
        LOCK: f'{lock["version"]} / {lock["packages"][""]["version"]}',
    }


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def _replace(path: Path, pattern: re.Pattern[str], new: str) -> None:
    text = path.read_text(encoding="utf-8")
    m = _one(pattern, text, str(path))
    path.write_text(text[:m.start(1)] + new + text[m.end(1):], encoding="utf-8")


def bump(version: str, date: str, branch: str = "main", root: Path = ROOT) -> str:
    """Apply the bump; return the previous version."""
    if not _VERSION.fullmatch(version):
        raise BumpError(f"not an X.Y.Z version: {version!r}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise BumpError(f"not a YYYY-MM-DD date: {date!r}")
    now = declared(root)
    prev = now[PYPROJECT]
    if len({v for k, v in now.items() if k != LOCK} | set(now[LOCK].split(" / "))) != 1:
        raise BumpError(f"the version files disagree before the bump: {now}")
    if _key(version) <= _key(prev):
        raise BumpError(f"{version} does not move forward from {prev}")

    # Check every changelog before writing anything, so a refusal leaves the
    # tree as it was.
    package_logs = [(root / p, (root / p).read_text(encoding="utf-8")) for p in PACKAGE_CHANGELOGS]
    for path, text in package_logs:
        if text.count("\n## Unreleased\n") != 1:
            raise BumpError(f"{path}: expected one '## Unreleased' section")
    root_log = (root / ROOT_CHANGELOG).read_text(encoding="utf-8")
    unreleased_link = re.compile(r"(?m)^\[Unreleased\]: .*$")
    if root_log.count("\n## [Unreleased]\n") != 1 or len(unreleased_link.findall(root_log)) != 1:
        raise BumpError(f"{ROOT_CHANGELOG}: expected one '## [Unreleased]' section and its link")
    if f"## [{version}]" in root_log:
        raise BumpError(f"{ROOT_CHANGELOG} already has a [{version}] section")

    _replace(root / PYPROJECT, _PYPROJECT_LINE, version)
    _replace(root / INIT, _INIT_LINE, version)
    _replace(root / PACKAGE, _PACKAGE_LINE, version)
    lock_path = root / LOCK
    lock_text = lock_path.read_text(encoding="utf-8")
    # Only the two entries that name the package: the top level and
    # packages[""], which precede every dependency entry.
    head, sep, rest = lock_text.partition('\n    "node_modules/')
    old = f'"version": "{prev}"'
    if head.count(old) != 2:
        raise BumpError(f"{LOCK}: expected the package's own version twice, found {head.count(old)}")
    lock_path.write_text(head.replace(old, f'"version": "{version}"') + sep + rest, encoding="utf-8")

    for path, text in package_logs:
        path.write_text(text.replace("\n## Unreleased\n", f"\n## {version} ({date})\n", 1), encoding="utf-8")
    root_log = root_log.replace("\n## [Unreleased]\n", f"\n## [Unreleased]\n\n## [{version}] - {date}\n", 1)
    root_log = unreleased_link.sub(
        f"[Unreleased]: {COMPARE}/v{version}...{branch}\n[{version}]: {COMPARE}/v{prev}...v{version}",
        root_log, count=1)
    (root / ROOT_CHANGELOG).write_text(root_log, encoding="utf-8")
    return prev


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("version", nargs="?")
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--branch", default="main")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    if args.check:
        now = declared()
        for path, v in now.items():
            print(f"{v:>16}  {path}")
        values = {v for k, v in now.items() if k != LOCK} | set(now[LOCK].split(" / "))
        if len(values) != 1:
            print("FAIL: the version files disagree", file=sys.stderr)
            return 1
        return 0
    if not args.version:
        ap.error("a version is required unless --check")
    try:
        prev = bump(args.version, args.date, args.branch)
    except BumpError as exc:
        print(f"bump_version: {exc}", file=sys.stderr)
        return 1
    print(f"{prev} -> {args.version}, dated {args.date}; compare links against {args.branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
