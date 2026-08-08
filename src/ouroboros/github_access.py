"""Resolve whether Ouroboros may write to a target — and fail safe when unsure.

The whole owner/auditor distinction hinges on one question: does the caller have
push access to the target repo? This module answers it via the GitHub API and,
crucially, treats *every* uncertainty — no token, a local path, a private repo,
an API error — as "no". The result is a ``Mode``, and the only way to reach
``owner`` is an explicit, confirmed ``push`` permission. Nothing here ever
guesses upward.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ouroboros.schemas.common import Mode

# Matches the owner/name slug of common GitHub URL forms:
#   https://github.com/owner/name(.git)   git@github.com:owner/name.git
_GITHUB_SLUG_RE = re.compile(r"github\.com[:/]+([^/]+)/([^/.]+)(?:\.git)?/?$")


@dataclass(slots=True)
class ModeDecision:
    """The resolved mode plus the human-readable reason it was chosen.

    The reason is not decorative: it is copied into ``RepoProfile.notes`` so a
    report always says *why* it ran as an auditor, never leaving the reader to
    guess whether write access was declined or simply never checked.
    """

    mode: Mode
    reason: str
    slug: str | None = None


def parse_github_slug(source: str) -> str | None:
    """Return ``owner/name`` for a GitHub URL, or ``None`` for anything else.

    A local path returns ``None`` — there is no remote to check permissions on,
    which the caller reads as "auditor".
    """
    match = _GITHUB_SLUG_RE.search(source.strip())
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2)}"


def resolve_mode(
    source: str,
    *,
    requested: Mode | None = None,
    token: str | None = None,
    client: object | None = None,
) -> ModeDecision:
    """Decide whether to run as ``owner`` or ``auditor`` for ``source``.

    Fail-safe by construction: ``owner`` is returned only when the GitHub API
    confirms ``push`` permission. A missing token, a non-GitHub source, or any
    API error all resolve to ``auditor`` with an explanatory reason. ``requested``
    can *ask* for owner but never grants it — it only narrows a would-be owner to
    auditor when the user explicitly wants a read-only run.
    """
    slug = parse_github_slug(source)
    if slug is None:
        return ModeDecision("auditor", "target is not a GitHub remote; running read-only", None)

    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        return ModeDecision("auditor", "no GITHUB_TOKEN available to prove write access", slug)

    try:
        gh = client if client is not None else _default_client(token)
        repo = gh.get_repo(slug)  # type: ignore[attr-defined]
        can_push = bool(getattr(repo.permissions, "push", False))
    except Exception as exc:
        return ModeDecision(
            "auditor", f"could not verify permissions ({type(exc).__name__}); failing safe", slug
        )

    if not can_push:
        return ModeDecision("auditor", "token lacks push permission on the target", slug)

    if requested == "auditor":
        return ModeDecision(
            "auditor", "write access confirmed, but a read-only run was requested", slug
        )

    return ModeDecision("owner", "confirmed push permission on the target", slug)


def _default_client(token: str) -> object:
    """Build a real PyGithub client. Isolated so tests inject a fake instead."""
    from github import Github  # imported lazily; keeps the offline path import-free

    return Github(token)
