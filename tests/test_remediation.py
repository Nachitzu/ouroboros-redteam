"""Owner-mode remediation: real local git for apply/commit, fakes for the PR."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from tests.conftest import FakeGithub

from ouroboros.agents.patch_generator import generate
from ouroboros.agents.static_analyzer import analyze
from ouroboros.remediation import (
    RemediationError,
    apply_patches,
    commit_on_branch,
    open_pull_request,
)
from ouroboros.schemas.proposed_patch import ProposedPatch
from ouroboros.schemas.repo_profile import RepoProfile


@pytest.fixture
def repo_with_patches(tmp_path: Path) -> tuple[Path, list[ProposedPatch]]:
    src = Path("tests/fixtures/vulnerable_agent").resolve()
    repo = tmp_path / "repo"
    subprocess.run(["cp", "-r", str(src), str(repo)], check=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=repo,
        check=True,
    )
    profile = RepoProfile(source=str(repo), resolved_mode="owner")
    findings = analyze(profile, root=repo)
    patches = generate(findings, [], root=repo)
    return repo, patches


def test_apply_patches_modifies_the_checkout(
    repo_with_patches: tuple[Path, list[ProposedPatch]],
) -> None:
    repo, patches = repo_with_patches
    applied = apply_patches(repo, patches)
    assert applied
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
    )
    assert status.stdout.strip()  # there are staged/unstaged changes


def test_apply_patches_raises_when_nothing_applies(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    bogus = ProposedPatch(
        finding_ref="x",
        title="t",
        guardrail_type="delimiters",
        diff=(
            "diff --git a/nope.py b/nope.py\n--- a/nope.py\n+++ b/nope.py\n@@ -1 +1,2 @@\n x\n+y\n"
        ),
        rationale="r",
    )
    with pytest.raises(RemediationError):
        apply_patches(tmp_path, [bogus])


def test_commit_on_branch_creates_commit(
    repo_with_patches: tuple[Path, list[ProposedPatch]],
) -> None:
    repo, patches = repo_with_patches
    apply_patches(repo, patches)
    sha = commit_on_branch(repo, "ouroboros/guardrails", "guardrails")
    assert len(sha) >= 7
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=repo, capture_output=True, text=True
    )
    assert branch.stdout.strip() == "ouroboros/guardrails"


def test_open_pull_request_pushes_and_creates_pr(
    repo_with_patches: tuple[Path, list[ProposedPatch]],
) -> None:
    repo, patches = repo_with_patches
    apply_patches(repo, patches)
    commit_on_branch(repo, "ouroboros/guardrails", "guardrails")
    pushed: list[tuple] = []
    gh = FakeGithub(push=True)
    url = open_pull_request(
        "o/n",
        root=repo,
        branch="ouroboros/guardrails",
        base="main",
        title="Ouroboros guardrails",
        body="body",
        token="tok",
        github_client=gh,
        push=lambda *args: pushed.append(args),
    )
    assert url == "https://github.com/o/n/pull/1"
    assert pushed  # the (injected) push ran
    assert gh.repo.pulls[0]["head"] == "ouroboros/guardrails"
    assert gh.repo.pulls[0]["base"] == "main"
