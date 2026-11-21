#!/usr/bin/env python3
"""The npm dist-tag to publish a version under (rules-engine#204).

    scripts/npm_dist_tag.py VERSION [LATEST]

Prints ``latest`` when VERSION is newer than LATEST, the version npm's
``latest`` dist-tag points at now (``npm view euredact dist-tags.latest``), or
when nothing is published yet. Otherwise it prints ``release-X.Y``.

npm moves ``latest`` to whatever is published last unless ``--tag`` says
otherwise, so a patch on an older line (1.0.1 after 1.1.0) would otherwise
make ``npm install euredact`` install the old line. PyPI has no such tag: it
serves the highest version. ``release-X.Y`` rather than ``X.Y.x`` because npm
refuses a dist-tag that parses as a semver range.
"""

from __future__ import annotations

import re
import sys

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse(version: str) -> tuple[int, int, int]:
    m = _VERSION.fullmatch(version.strip())
    if not m:
        raise ValueError(f"not an X.Y.Z version: {version!r}")
    return int(m[1]), int(m[2]), int(m[3])


def dist_tag(version: str, latest: str | None) -> str:
    ours = parse(version)
    if not latest or not latest.strip():
        return "latest"
    if ours > parse(latest):
        return "latest"
    return f"release-{ours[0]}.{ours[1]}"


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        print(dist_tag(argv[1], argv[2] if len(argv) == 3 else None))
    except ValueError as exc:
        print(f"npm_dist_tag: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
