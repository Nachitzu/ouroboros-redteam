"""The fail-safe is the point: prove owner is unreachable without confirmed push."""

from __future__ import annotations

from tests.conftest import FakeGithub

from ouroboros.github_access import parse_github_slug, resolve_mode


def test_local_path_is_auditor() -> None:
    decision = resolve_mode("./some/local/path")
    assert decision.mode == "auditor"
    assert decision.slug is None


def test_github_url_without_token_is_auditor() -> None:
    decision = resolve_mode("https://github.com/owner/name")
    assert decision.mode == "auditor"
    assert "GITHUB_TOKEN" in decision.reason


def test_push_permission_yields_owner() -> None:
    decision = resolve_mode(
        "https://github.com/owner/name", token="t", client=FakeGithub(push=True)
    )
    assert decision.mode == "owner"


def test_no_push_permission_is_auditor() -> None:
    decision = resolve_mode(
        "https://github.com/owner/name", token="t", client=FakeGithub(push=False)
    )
    assert decision.mode == "auditor"


def test_api_error_fails_safe_to_auditor() -> None:
    decision = resolve_mode(
        "https://github.com/owner/name", token="t", client=FakeGithub(raise_on_get=True)
    )
    assert decision.mode == "auditor"
    assert "fail" in decision.reason.lower()


def test_requested_auditor_narrows_a_would_be_owner() -> None:
    decision = resolve_mode(
        "https://github.com/owner/name",
        token="t",
        requested="auditor",
        client=FakeGithub(push=True),
    )
    assert decision.mode == "auditor"


def test_slug_parsing() -> None:
    assert parse_github_slug("https://github.com/a/b.git") == "a/b"
    assert parse_github_slug("git@github.com:a/b.git") == "a/b"
    assert parse_github_slug("./local") is None
