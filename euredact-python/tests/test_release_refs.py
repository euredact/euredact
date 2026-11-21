"""``scripts/release_refs.sh`` is the gate that 0.6.0 did not have.

0.6.0 was pushed to Forgejo only. GitHub's ``main`` was still on the 0.5.1
commit, the GitHub Release created its own ``v0.6.0`` there, and publish rebuilt
0.5.1 -- reported as success, because both registries skipped it as already
published. These tests replay that against two local bare repositories standing
in for Forgejo and GitHub, so the gate is shown to refuse it rather than assumed
to.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release_refs.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="needs git and bash",
)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "tag.gpgsign=false",
         "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repos(tmp_path: Path) -> dict[str, Path]:
    """A clone at the 0.6.0 commit; Forgejo has it, GitHub stopped at 0.5.1."""
    forgejo, github, work = tmp_path / "forgejo.git", tmp_path / "github.git", tmp_path / "work"
    for bare in (forgejo, github):
        _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    _git(tmp_path, "init", "-q", "-b", "main", str(work))
    _git(work, "commit", "-q", "--allow-empty", "-m", "Release 0.5.1")
    _git(work, "remote", "add", "origin", str(forgejo))
    _git(work, "push", "-q", "origin", "main")
    _git(work, "push", "-q", str(github), "main")
    _git(work, "commit", "-q", "--allow-empty", "-m", "Release 0.6.0")
    _git(work, "push", "-q", "origin", "main")
    return {"forgejo": forgejo, "github": github, "work": work}


def _check(repos: dict[str, Path], *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GITHUB_REMOTE": str(repos["github"])}
    env.pop("FORGEJO_REMOTE", None)
    return subprocess.run(
        ["bash", str(SCRIPT), *args], cwd=repos["work"], env=env, capture_output=True, text=True,
    )


def test_refuses_to_tag_when_github_main_is_behind(repos: dict[str, Path]) -> None:
    r = _check(repos, "v0.6.0")
    assert r.returncode == 1
    assert "github main is not HEAD" in r.stderr
    assert "forgejo main is not HEAD" not in r.stderr


def test_refuses_a_tag_github_created_on_the_old_commit(repos: dict[str, Path]) -> None:
    # What the GitHub Release did: a lightweight v0.6.0 on GitHub's stale main.
    old = _git(repos["work"], "rev-parse", "HEAD~1")
    _git(repos["work"], "push", "-q", str(repos["github"]), "HEAD:refs/heads/main")
    _git(repos["work"], "push", "-q", str(repos["github"]), f"{old}:refs/tags/v0.6.0")
    r = _check(repos, "v0.6.0")
    assert r.returncode == 1
    assert f"github already has v0.6.0 on {old}" in r.stderr


def test_passes_once_both_remotes_are_on_head(repos: dict[str, Path]) -> None:
    _git(repos["work"], "push", "-q", str(repos["github"]), "HEAD:refs/heads/main")
    assert _check(repos, "v0.6.0").returncode == 0


def test_tagged_requires_the_annotated_tag_on_both(repos: dict[str, Path]) -> None:
    work = repos["work"]
    _git(work, "push", "-q", str(repos["github"]), "HEAD:refs/heads/main")
    _git(work, "tag", "-a", "v0.6.0", "-m", "0.6.0")
    _git(work, "push", "-q", "origin", "v0.6.0")

    r = _check(repos, "v0.6.0", "--tagged")
    assert r.returncode == 1
    assert "github has no v0.6.0" in r.stderr

    _git(work, "push", "-q", str(repos["github"]), "v0.6.0")
    r = _check(repos, "v0.6.0", "--tagged")
    assert r.returncode == 0, r.stderr


def test_refuses_a_dirty_tree(repos: dict[str, Path]) -> None:
    _git(repos["work"], "push", "-q", str(repos["github"]), "HEAD:refs/heads/main")
    (repos["work"] / "stray").write_text("x")
    r = _check(repos, "v0.6.0")
    assert r.returncode == 1
    assert "not clean" in r.stderr


def test_rejects_a_malformed_version(repos: dict[str, Path]) -> None:
    assert _check(repos, "0.6.0").returncode == 2


# ── Maintenance releases: a patch on its line's branch (rules-engine#204) ──


@pytest.fixture
def line(repos: dict[str, Path]) -> dict[str, Path]:
    """release/0.5.x carries a 0.5.2 patch; main has moved on to 0.6.0."""
    work = repos["work"]
    _git(work, "push", "-q", str(repos["github"]), "HEAD:refs/heads/main")
    _git(work, "checkout", "-q", "-b", "release/0.5.x", "HEAD~1")
    _git(work, "commit", "-q", "--allow-empty", "-m", "Release 0.5.2")
    _git(work, "push", "-q", "origin", "release/0.5.x")
    return repos


def test_a_patch_is_checked_against_its_line_not_main(line: dict[str, Path]) -> None:
    _git(line["work"], "push", "-q", str(line["github"]), "release/0.5.x")
    r = _check(line, "v0.5.2", "--branch", "release/0.5.x")
    assert r.returncode == 0, r.stderr
    assert "release/0.5.x" in r.stdout


def test_refuses_when_github_lacks_the_line(line: dict[str, Path]) -> None:
    r = _check(line, "v0.5.2", "--branch", "release/0.5.x")
    assert r.returncode == 1
    assert "github release/0.5.x is not HEAD" in r.stderr


def test_refuses_a_tag_from_another_line(line: dict[str, Path]) -> None:
    _git(line["work"], "push", "-q", str(line["github"]), "release/0.5.x")
    r = _check(line, "v0.6.1", "--branch", "release/0.5.x")
    assert r.returncode == 1
    assert "not a release of release/0.5.x" in r.stderr


def test_refuses_a_branch_that_is_not_a_release_line(line: dict[str, Path]) -> None:
    r = _check(line, "v0.5.2", "--branch", "feature/x")
    assert r.returncode == 1


def test_the_tagged_check_on_a_line(line: dict[str, Path]) -> None:
    work = line["work"]
    _git(work, "push", "-q", str(line["github"]), "release/0.5.x")
    assert _check(line, "v0.5.2", "--branch", "release/0.5.x", "--tagged").returncode == 1
    _git(work, "tag", "v0.5.2")
    for remote in (line["forgejo"], line["github"]):
        _git(work, "push", "-q", str(remote), "refs/tags/v0.5.2")
    assert _check(line, "v0.5.2", "--branch", "release/0.5.x", "--tagged").returncode == 0
