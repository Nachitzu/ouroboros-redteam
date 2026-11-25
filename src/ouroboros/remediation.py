"""Owner-mode remediation: apply guardrail patches and open a pull request.

In owner mode Ouroboros may write to the target, so this module takes the
patches the generator produced and turns them into a real change: it applies
them to the checkout, commits them on a collision-free branch, and (when asked)
pushes and opens a PR against the repository's default branch via PyGithub.

Everything with a side effect is injectable so it can be exercised without touching
GitHub: ``apply_patches`` and ``commit_on_branch`` run against a real local git repo
(a throwaway one in tests), and ``open_pull_request`` takes a ``push`` callable and a
GitHub client, both faked in tests. Nothing here runs unless the caller is in owner
mode and explicitly opted in.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ouroboros.github_access import _default_client
from ouroboros.schemas.proposed_patch import ProposedPatch

# Where a live push sends the branch, and what PR it targets, by default.
DEFAULT_BRANCH = "ouroboros/guardrails"
DEFAULT_BASE = "main"


class RemediationError(RuntimeError):
    """A remediation step failed (patch did not apply, push/PR rejected)."""


# ---------------------------------------------------------------------------
# applying patches
# ---------------------------------------------------------------------------
def apply_patches(root: Path, patches: list[ProposedPatch]) -> list[str]:
    """Apply each patch's diff to ``root`` with ``git apply``; return applied refs.

    Prompt-hardening patches are applied before advisory comment patches so
    rewritten prompts land cleanly; any patch that still fails to apply is
    skipped rather than aborting the batch.
    """
    ordered = sorted(patches, key=lambda p: 0 if p.kind == "prompt_hardening" else 1)
    applied: list[str] = []
    for patch in ordered:
        result = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "-"],
            cwd=root,
            input=patch.diff,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            applied.append(patch.finding_ref)
    if not applied:
        raise RemediationError("no patch applied cleanly to the checkout")
    return applied


def unique_branch_name(root: Path, base_name: str = DEFAULT_BRANCH) -> str:
    """Return ``base_name`` or a numbered suffix if that branch already exists."""
    existing = _existing_branches(root)
    if base_name not in existing:
        return base_name
    for idx in range(2, 100):
        candidate = f"{base_name}-{idx}"
        if candidate not in existing:
            return candidate
    raise RemediationError(f"could not pick an unused branch name starting with {base_name!r}")


def _existing_branches(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "branch", "-a", "--format=%(refname:short)"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()
    names: set[str] = set()
    for line in result.stdout.splitlines():
        name = line.strip()
        if not name:
            continue
        names.add(name.removeprefix("origin/"))
    return names


def detect_default_branch(root: Path, fallback: str = DEFAULT_BASE) -> str:
    """Infer the checkout's default branch from HEAD or ``origin/HEAD``."""
    head = subprocess.run(
        ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if head.returncode == 0 and head.stdout.strip():
        return head.stdout.strip().removeprefix("origin/")
    current = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if current.returncode == 0 and current.stdout.strip():
        return current.stdout.strip()
    return fallback


def commit_on_branch(root: Path, branch: str, message: str) -> str:
    """Create ``branch``, stage everything, commit, and return the commit sha."""
    _git(root, "checkout", "-b", branch)
    _git(root, "add", "-A")
    _git(
        root,
        "-c",
        "user.name=ouroboros",
        "-c",
        "user.email=ouroboros@localhost",
        "commit",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD").strip()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    if result.returncode != 0:
        raise RemediationError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


# ---------------------------------------------------------------------------
# opening the pull request
# ---------------------------------------------------------------------------
def _live_push(root: Path, slug: str, branch: str, token: str) -> None:
    """Push ``branch`` to the token-authenticated origin. The real side effect."""
    url = f"https://x-access-token:{token}@github.com/{slug}.git"
    _git(root, "push", url, f"HEAD:refs/heads/{branch}")


def open_pull_request(
    slug: str,
    *,
    root: Path,
    branch: str,
    base: str,
    title: str,
    body: str,
    token: str,
    github_client: Any | None = None,
    push: Callable[[Path, str, str, str], None] | None = None,
) -> str:
    """Push the branch and open a PR against ``slug``; return the PR URL.

    ``push`` and ``github_client`` are injected so tests drive the whole flow with
    no network. Resolved at call time so a monkeypatched ``_live_push`` is honored.
    Uses PyGithub's ``repo.create_pull`` and returns ``pr.html_url``.
    """
    (push or _live_push)(root, slug, branch, token)
    client: Any = github_client if github_client is not None else _default_client(token)
    try:
        repo = client.get_repo(slug)
        pull = repo.create_pull(title=title, body=body, head=branch, base=base)
    except Exception as exc:
        raise RemediationError(f"could not open pull request on {slug}: {exc}") from exc
    return str(pull.html_url)
