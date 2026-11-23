"""The maintenance-release scripts (rules-engine#204).

``npm_dist_tag.py`` keeps a patch on an older line off npm's ``latest``;
``bump_version.py`` does the release skill's steps 1 and 2; ``backport.py``
replays a fix's commits from main onto a line in the order main merged them.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


npm_dist_tag = _load("npm_dist_tag")
bump_version = _load("bump_version")
backport = _load("backport")


# ── npm_dist_tag ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(("version", "latest", "tag"), [
    ("1.0.1", "1.1.0", "release-1.0"),   # the case this exists for
    ("1.1.1", "1.1.0", "latest"),
    ("1.2.0", "1.1.0", "latest"),
    ("2.0.0", "1.9.9", "latest"),
    ("1.0.0", "", "latest"),            # nothing published yet
    ("1.0.0", None, "latest"),
    ("1.10.0", "1.9.0", "latest"),      # numeric, not string, comparison
    ("1.9.1", "1.10.0", "release-1.9"),
])
def test_dist_tag(version: str, latest: str | None, tag: str) -> None:
    assert npm_dist_tag.dist_tag(version, latest) == tag


def test_dist_tag_refuses_a_non_version() -> None:
    with pytest.raises(ValueError):
        npm_dist_tag.dist_tag("1.0", "1.1.0")


# ── bump_version ─────────────────────────────────────────────────────────

_FILES = [bump_version.PYPROJECT, bump_version.INIT, bump_version.PACKAGE, bump_version.LOCK,
          *bump_version.PACKAGE_CHANGELOGS, bump_version.ROOT_CHANGELOG]


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """The real version files and changelogs, with an Unreleased entry each."""
    for rel in _FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp_path / rel)
    current = bump_version.declared(tmp_path)[bump_version.PYPROJECT]
    for rel in bump_version.PACKAGE_CHANGELOGS:
        p = tmp_path / rel
        text = p.read_text(encoding="utf-8")
        if "\n## Unreleased\n" not in text:
            head = text.index(f"\n## {current} (")
            text = text[:head] + "\n## Unreleased\n\n### Fixed\n\n- A fix.\n" + text[head:]
        p.write_text(text, encoding="utf-8")
    return tmp_path


def _next(tree: Path) -> tuple[str, str]:
    prev = bump_version.declared(tree)[bump_version.PYPROJECT]
    x, y, z = (int(p) for p in prev.split("."))
    return prev, f"{x}.{y}.{z + 1}"


def test_bump_moves_every_version_and_dates_the_changelogs(tree: Path) -> None:
    prev, new = _next(tree)
    assert bump_version.bump(new, "2030-01-02", "release/9.9.x", tree) == prev
    assert set(bump_version.declared(tree).values()) == {new, f"{new} / {new}"}
    for rel in bump_version.PACKAGE_CHANGELOGS:
        text = (tree / rel).read_text(encoding="utf-8")
        assert f"\n## {new} (2030-01-02)\n" in text and "\n## Unreleased\n" not in text
    root = (tree / bump_version.ROOT_CHANGELOG).read_text(encoding="utf-8")
    assert f"## [Unreleased]\n\n## [{new}] - 2030-01-02\n" in root
    assert f"[Unreleased]: {bump_version.COMPARE}/v{new}...release/9.9.x" in root
    assert f"[{new}]: {bump_version.COMPARE}/v{prev}...v{new}" in root


def test_bump_touches_only_the_package_entries_of_the_lockfile(tree: Path) -> None:
    before = (tree / bump_version.LOCK).read_text(encoding="utf-8").splitlines()
    _, new = _next(tree)
    bump_version.bump(new, "2030-01-02", "main", tree)
    after = (tree / bump_version.LOCK).read_text(encoding="utf-8").splitlines()
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert len(before) == len(after) and len(changed) == 2


@pytest.mark.parametrize("version", ["0.0.1", "1.1", "x"])
def test_bump_refuses_and_changes_nothing(tree: Path, version: str) -> None:
    snapshot = {rel: (tree / rel).read_bytes() for rel in _FILES}
    with pytest.raises(bump_version.BumpError):
        bump_version.bump(version, "2030-01-02", "main", tree)
    assert {rel: (tree / rel).read_bytes() for rel in _FILES} == snapshot


def test_bump_refuses_without_an_unreleased_section(tree: Path) -> None:
    p = tree / bump_version.PACKAGE_CHANGELOGS[0]
    p.write_text(p.read_text(encoding="utf-8").replace("\n## Unreleased\n", "\n## Later\n"), encoding="utf-8")
    snapshot = {rel: (tree / rel).read_bytes() for rel in _FILES}
    with pytest.raises(bump_version.BumpError, match="Unreleased"):
        bump_version.bump(_next(tree)[1], "2030-01-02", "main", tree)
    assert {rel: (tree / rel).read_bytes() for rel in _FILES} == snapshot


# ── backport ─────────────────────────────────────────────────────────────

pytestmark_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _commit(repo: Path, name: str, content: str, message: str) -> None:
    (repo / name).write_text(content, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture(autouse=True)
def _git_identity(monkeypatch) -> None:
    """A fixed identity and no signing, for the fixture's git and the script's
    own cherry-picks alike: CI runners have no identity, and a signing setup
    on a developer machine would otherwise sign (or fail to sign) these."""
    for who in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{who}_NAME", "t")
        monkeypatch.setenv(f"GIT_{who}_EMAIL", "t@t")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "tag.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "false")


@pytest.fixture
def history(tmp_path: Path) -> Path:
    """v1.0.0, then two PRs written in parallel and merged in the other order:
    issue-2 is written first but merged after issue-3."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "a.txt", "base\n", "base")
    _git(repo, "tag", "v1.0.0")
    _git(repo, "checkout", "-q", "-b", "issue/2")
    _commit(repo, "two.txt", "2\n", "issue-2: the fix\n\nCloses euredact/rules-engine#2")
    _commit(repo, "two.txt", "2\nrecords\n", "corpus: regression records for #2")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "checkout", "-q", "-b", "issue/3")
    _commit(repo, "three.txt", "3\n", "issue-3: another fix")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "Merge #3", "issue/3")
    _git(repo, "merge", "-q", "--no-ff", "-m", "Merge #2", "issue/2")
    _commit(repo, "four.txt", "4\n", "issue-4: not wanted")
    _git(repo, "checkout", "-q", "-b", "line", "v1.0.0")
    return repo


@pytestmark_git
def test_backport_finds_by_convention_in_merge_order(history: Path) -> None:
    found = backport.candidates("v1.0.0", "main", {2, 3}, history)
    assert [c.subject for c in found] == [
        "issue-3: another fix", "issue-2: the fix", "corpus: regression records for #2"]


@pytestmark_git
def test_backport_applies_records_and_resumes(history: Path, capsys) -> None:
    assert backport.main(["--issues", "2,3", "--since", "v1.0.0", "--source", "main"], history) == 0
    log = _git(history, "log", "--format=%s", "v1.0.0..HEAD")
    assert log.splitlines() == [
        "corpus: regression records for #2", "issue-2: the fix", "issue-3: another fix"]
    assert "cherry picked from commit" in _git(history, "log", "-1", "--format=%B")
    # Run again: nothing is applied twice.
    assert backport.main(["--issues", "2,3", "--since", "v1.0.0", "--source", "main"], history) == 0
    assert len(_git(history, "log", "--format=%s", "v1.0.0..HEAD").splitlines()) == 3


@pytestmark_git
def test_backport_stops_at_a_conflict(history: Path, capsys) -> None:
    _commit(history, "two.txt", "the line's own text\n", "line change")
    assert backport.main(["--issues", "2", "--since", "v1.0.0", "--source", "main"], history) == 1
    err = capsys.readouterr().err
    assert "conflict applying" in err and "two.txt" in err
    # While it is in progress, a second run refuses rather than piling on.
    assert backport.main(["--issues", "2", "--since", "v1.0.0", "--source", "main"], history) == 1
    assert "in progress" in capsys.readouterr().err


@pytestmark_git
def test_backport_reports_an_issue_with_no_commits(history: Path, capsys) -> None:
    assert backport.main(["--issues", "2,99", "--since", "v1.0.0", "--source", "main", "--dry-run"],
                         history) == 1
    assert "[99]" in capsys.readouterr().err
