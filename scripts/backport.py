#!/usr/bin/env python3
"""Backport fixes from main to a maintenance line, by issue number.

    scripts/backport.py --issues 188,195,192 [--source origin/main] [--since v1.0.0] [--dry-run]

Run it on the branch that will become the backport PR, cut from the line:

    git switch -c issue/205-backport-1.0.1 origin/release/1.0.x
    scripts/backport.py --issues 188,195,192,193,196 --since v1.0.0

A fix is found by this repository's conventions, not by hand:

- a commit whose subject starts ``issue-N:`` (or ``issue-N/M:`` for a combined
  fix);
- ``corpus: regression records for #N`` (and "for #N, #M and #K");
- a ``Closes euredact/rules-engine#N`` or ``Refs euredact/rules-engine#N``
  trailer.

Merge commits are skipped: they carry no fix of their own, only a resolution
against main that the backport resolves again against the line. The commits
are applied in the order their pull requests merged into main, and in
topological order within one. Two branches written in parallel then arrive
in the order main took them, so a conflict between them is the one main's
merge already resolved, and the regression records come out in main's order,
with main's values (#192 before #195 in 1.0.1).

Each one is cherry-picked with ``-x``, which records the main commit it came
from; a commit already on the branch with that record is skipped, so the
script can be run again after a conflict:

    # resolve the files it lists, then
    git add <files> && git cherry-pick --continue
    scripts/backport.py --issues ...   # the same command: it resumes

It changes nothing but the current branch, and never pushes (rules-engine#204).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_SUBJECT_ISSUES = re.compile(r"^issue-(\d+(?:/\d+)*):")
_RECORDS = re.compile(r"^corpus: regression records for (.*)$")
_TRAILER = re.compile(r"(?m)^(?:Closes|Refs) euredact/rules-engine#(\d+)\s*$")
_PICKED = re.compile(r"\(cherry picked from commit ([0-9a-f]{40})\)")


@dataclass
class Commit:
    sha: str
    subject: str
    issues: set[int]


def git(*args: str, check: bool = True, cwd: Path | None = None) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed:\n{r.stderr.strip()}")
    return r.stdout


def issues_of(subject: str, body: str) -> set[int]:
    """The issue numbers a commit belongs to, by the conventions above."""
    found: set[int] = set()
    m = _SUBJECT_ISSUES.match(subject)
    if m:
        found |= {int(n) for n in m[1].split("/")}
    m = _RECORDS.match(subject)
    if m:
        found |= {int(n) for n in re.findall(r"#(\d+)", m[1])}
    found |= {int(n) for n in _TRAILER.findall(body)}
    return found


def _arrival(since: str, source: str, cwd: Path | None) -> dict[str, int]:
    """For every commit in since..source, the position on source's first-parent
    history of the mainline commit that brought it in: its PR's merge, or the
    commit itself if it went onto main directly."""
    mainline = git("rev-list", "--reverse", "--first-parent", f"{since}..{source}", cwd=cwd).split()
    arrived: dict[str, int] = {}
    for i, m in enumerate(mainline):
        parents = git("rev-list", "--parents", "-n", "1", m, cwd=cwd).split()[1:]
        arrived.setdefault(m, i)
        if len(parents) > 1:
            for c in git("rev-list", f"{parents[0]}..{m}", cwd=cwd).split():
                arrived.setdefault(c, i)
    return arrived


def candidates(since: str, source: str, wanted: set[int], cwd: Path | None = None) -> list[Commit]:
    """Non-merge commits in since..source that belong to a wanted issue, in the
    order their pull requests merged, oldest first."""
    out = git("log", "--reverse", "--topo-order", "--no-merges",
              "--format=%H%x00%s%x00%b%x1e", f"{since}..{source}", cwd=cwd)
    arrived = _arrival(since, source, cwd)
    picked = []
    for record in out.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, subject, body = record.split("\x00", 2)
        mine = issues_of(subject, body) & wanted
        if mine:
            picked.append(Commit(sha, subject, mine))
    topo = {c.sha: i for i, c in enumerate(picked)}
    picked.sort(key=lambda c: (arrived.get(c.sha, len(arrived)), topo[c.sha]))
    return picked


def already_applied(since: str, cwd: Path | None = None) -> set[str]:
    """Main commits whose cherry-pick record is on the current branch."""
    return set(_PICKED.findall(git("log", "--format=%B", f"{since}..HEAD", cwd=cwd)))


def main(argv: list[str] | None = None, cwd: Path | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--issues", required=True, help="comma-separated issue numbers, e.g. 188,195")
    ap.add_argument("--source", default="origin/main", help="where the fixes are (default origin/main)")
    ap.add_argument("--since", required=True, help="the line's base tag, e.g. v1.0.0")
    ap.add_argument("--dry-run", action="store_true", help="list the commits, apply nothing")
    args = ap.parse_args(argv)
    wanted = {int(n) for n in args.issues.replace(" ", "").split(",") if n}

    git_dir = Path(git("rev-parse", "--git-dir", cwd=cwd).strip())
    if not git_dir.is_absolute():
        git_dir = (cwd or Path.cwd()) / git_dir
    if (git_dir / "CHERRY_PICK_HEAD").exists():
        print("A cherry-pick is in progress: resolve it and run `git cherry-pick --continue` "
              "(or `--abort`), then run this again.", file=sys.stderr)
        return 1

    commits = candidates(args.since, args.source, wanted, cwd)
    found = set().union(*(c.issues for c in commits)) if commits else set()
    missing = sorted(wanted - found)
    done = already_applied(args.since, cwd)
    print(f"{len(commits)} commit(s) for issue(s) {sorted(wanted)} in {args.since}..{args.source}:")
    for c in commits:
        state = "applied" if c.sha in done else ("would apply" if args.dry_run else "to apply")
        print(f"  {c.sha[:9]}  {state:11}  {c.subject[:90]}")
    if missing:
        print(f"no commit found for issue(s) {missing}", file=sys.stderr)
        return 1
    if args.dry_run:
        return 0

    for c in commits:
        if c.sha in done:
            continue
        r = subprocess.run(["git", "cherry-pick", "-x", c.sha], cwd=cwd,
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            conflicted = git("diff", "--name-only", "--diff-filter=U", cwd=cwd).split()
            print(f"\nconflict applying {c.sha[:9]} {c.subject}", file=sys.stderr)
            for f in conflicted:
                print(f"  {f}", file=sys.stderr)
            if not conflicted:
                print(r.stderr.strip(), file=sys.stderr)
            print("\nResolve, `git add` the files, `git cherry-pick --continue`, then run "
                  "the same backport command again.", file=sys.stderr)
            return 1
        print(f"  applied {c.sha[:9]}")
    print("all applied. Next: make verify on this branch, then the changelog entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
