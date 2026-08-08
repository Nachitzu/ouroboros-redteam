"""Shared fixtures. The Anthropic client is faked, never real — no test hits the network."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VULN_AGENT = FIXTURES / "vulnerable_agent"


class FakeMessages:
    """Replays a scripted queue of replies and records every request it received."""

    def __init__(self, owner: FakeClient) -> None:
        self._owner = owner

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self._owner.calls.append(kwargs)
        if not self._owner.replies:
            raise AssertionError("FakeClient ran out of scripted replies")
        reply = self._owner.replies.pop(0)
        text = reply if isinstance(reply, str) else json.dumps(reply)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            stop_reason="end_turn",
        )


class FakeClient:
    """Stands in for anthropic.Anthropic(). Feed it dicts or strings to return."""

    def __init__(self, replies: list[Any] | None = None) -> None:
        self.replies: list[Any] = list(replies or [])
        self.calls: list[dict[str, Any]] = []
        self.messages = FakeMessages(self)


class FakePermissions:
    def __init__(self, push: bool) -> None:
        self.push = push


class FakePull:
    def __init__(self, html_url: str) -> None:
        self.html_url = html_url


class FakeRepo:
    def __init__(self, push: bool) -> None:
        self.permissions = FakePermissions(push)
        self.pulls: list[dict[str, Any]] = []

    def create_pull(self, **kwargs: Any) -> FakePull:
        self.pulls.append(kwargs)
        return FakePull("https://github.com/o/n/pull/1")


class FakeGithub:
    """Stands in for github.Github(). ``push`` controls the resolved mode."""

    def __init__(self, push: bool = True, raise_on_get: bool = False) -> None:
        self._push = push
        self._raise = raise_on_get
        self.repo = FakeRepo(push)

    def get_repo(self, slug: str) -> FakeRepo:
        if self._raise:
            raise RuntimeError(f"boom for {slug}")
        return self.repo


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may reach a live API or leak a real token, even by accident."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("OUROBOROS_MODEL", raising=False)


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient()


@pytest.fixture
def vuln_agent() -> Path:
    return VULN_AGENT
