"""No tracked file may hold a token a secret scanner can verify as live-shaped.

GitHub and npm tokens end in a CRC32 checksum of their body. GitHub's push
protection checks it, and a checksum-valid token anywhere in the history
blocks every push of the repository. A conformance vector once carried one,
copied from a synthetic benchmark document whose generator gives its tokens
valid checksums, and the Forgejo -> GitHub mirror stopped until the history
was rewritten (rules-engine#132).

Test values must therefore be deliberately broken: keep the shape, and change
a character of the checksum. The engine detects them all the same.
"""
from __future__ import annotations

import re
import string
import subprocess
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase

#: GitHub (classic, OAuth, user, server, refresh) and npm access tokens: a
#: prefix, a 30-character body and a 6-character base62 CRC32 of the body.
_CHECKSUMMED = re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_|npm_)([A-Za-z0-9]{30})([A-Za-z0-9]{6})(?![A-Za-z0-9])")


def _base62(n: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _BASE62[r] + out
    return out.rjust(6, "0")


def checksum_valid_tokens(text: str) -> list[str]:
    """Every GitHub or npm token in *text* whose checksum verifies."""
    return [m.group(0) for m in _CHECKSUMMED.finditer(text)
            if _base62(zlib.crc32(m.group(2).encode())) == m.group(3)]


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                             capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / p for p in out.decode().split("\0") if p]


def test_no_tracked_file_holds_a_checksum_valid_token():
    found = []
    for path in _tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found += [f"{path.relative_to(ROOT)}: {t}" for t in checksum_valid_tokens(text)]
    assert not found, (
        "checksum-valid tokens would block the GitHub mirror (push protection); "
        "change a checksum character:\n" + "\n".join(found))


def test_the_check_recognises_a_valid_token_and_passes_a_broken_one():
    # Built here, never written down: a literal would trip the check itself.
    body = "ByBkqAWTzuHwNaSuIHuoJuW6cyMqxj"
    valid = "ghp_" + body + _base62(zlib.crc32(body.encode()))
    broken = valid[:-1] + ("A" if valid[-1] != "A" else "B")
    assert checksum_valid_tokens(f'GH_TOKEN = "{valid}"') == [valid]
    assert checksum_valid_tokens(f'GH_TOKEN = "{broken}"') == []
    npm_valid = "npm_" + body + _base62(zlib.crc32(body.encode()))
    assert checksum_valid_tokens(npm_valid) == [npm_valid]
