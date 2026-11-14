"""No regex in the rules engine ends on a bare ``$`` (rules-engine#166).

Without ``re.MULTILINE``, Python's ``$`` matches at the end of the text and
also just before a final newline; JavaScript's ``$`` without the ``m`` flag
matches only at the end. A context pattern tested on ``text[...:match.start]``
therefore fired across a line break in Python: "Termin 19.10." on one line
dropped the postcode "04-002" starting the next, which TypeScript kept. The
Python patterns end in ``\\Z``, which means what the TypeScript ``$`` means.
This test reads every string literal under ``rules/`` so a new pattern cannot
bring the bare ``$`` back.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "src" / "euredact" / "rules"

#: String literals that contain a "$" and are not regular expressions.
NOT_REGEXES = {
    ("matchers.py", r'r"\[](){}*+?|^$."'),   # the metacharacters, as a set
    ("suppressors.py", '"${"'),              # a ${VAR} reference's opening
}


def _bare_dollars(body: str) -> list[int]:
    """Offsets of "$" that anchor: not escaped, not inside a character class."""
    out, i, in_class = [], 0, False
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
            if body[i + 1:i + 2] == "^":
                i += 1
            if body[i + 1:i + 2] == "]":
                i += 1
        elif ch == "$":
            out.append(i)
        i += 1
    return out


def _literals(source: str):
    """Every single-quoted string literal, f-strings whole, with its line."""
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    at = lambda rc: offsets[rc[0] - 1] + rc[1]  # noqa: E731
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.type == tokenize.STRING:
            yield tok.start[0], source[at(tok.start):at(tok.end)]
        elif fstring_start is not None and tok.type == fstring_start:
            depth, j = 1, i + 1
            while depth:
                if tokens[j].type == fstring_start:
                    depth += 1
                elif tokens[j].type == tokenize.FSTRING_END:
                    depth -= 1
                j += 1
            yield tok.start[0], source[at(tok.start):at(tokens[j - 1].end)]
            i = j
            continue
        i += 1


def test_no_rules_regex_anchors_on_a_bare_dollar():
    found = []
    for path in sorted(RULES.rglob("*.py")):
        for line, literal in _literals(path.read_text(encoding="utf-8")):
            quote = re.match(r"(?i)[rbuf]*('''|\"\"\"|'|\")", literal)
            if len(quote.group(1)) == 3 or (path.name, literal) in NOT_REGEXES:
                continue  # docstrings and known non-regexes
            body = literal[quote.end():len(literal) - len(quote.group(1))]
            if _bare_dollars(body):
                found.append(f"{path.relative_to(RULES)}:{line}: {literal[:70]}")
    assert found == [], "end on \\Z, not $ (rules-engine#166):\n" + "\n".join(found)


def test_python_dollar_is_why():
    """The difference itself, so the reason survives a Python upgrade."""
    assert re.search(r"\d[./]$", "19.10.\n")
    assert not re.search(r"\d[./]\Z", "19.10.\n")
