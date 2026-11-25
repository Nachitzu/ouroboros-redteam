"""Tests for LLM plumbing: model resolution, block extraction, and validation retries."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import BaseModel
from tests.conftest import FakeClient

from ouroboros._llm import (
    DEFAULT_MODEL,
    LLMError,
    _text_of,
    complete_validated,
    extract_json_object,
    load_prompt,
    resolve_model,
)


class _Answer(BaseModel):
    verdict: str


def test_extract_json_from_plain_fenced_and_prose() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}
    assert extract_json_object('```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json_object('Here it is: {"a": 3}. Done.') == {"a": 3}


def test_extract_json_raises_when_absent() -> None:
    with pytest.raises(LLMError):
        extract_json_object("no object here")


def test_complete_validated_returns_first_valid() -> None:
    client = FakeClient(replies=[{"verdict": "ok"}])
    result = complete_validated(_Answer, client=client, system="s", user="u")
    assert result.verdict == "ok"
    assert len(client.calls) == 1
    assert client.calls[0]["model"] == DEFAULT_MODEL


def test_complete_validated_retries_then_succeeds() -> None:
    # First reply is invalid (missing field), second is good — the error is fed
    # back and the model corrects itself.
    client = FakeClient(replies=[{"wrong": "x"}, {"verdict": "fixed"}])
    result = complete_validated(_Answer, client=client, system="s", user="u")
    assert result.verdict == "fixed"
    assert len(client.calls) == 2


def test_complete_validated_gives_up_and_raises() -> None:
    client = FakeClient(replies=[{"bad": 1}, {"bad": 2}, {"bad": 3}])
    with pytest.raises(LLMError):
        complete_validated(_Answer, client=client, system="s", user="u", max_attempts=3)


def test_load_prompt_reads_text_fence() -> None:
    prompt = load_prompt("static_enrichment")
    assert "security reviewer" in prompt.lower()


def test_resolve_model_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    assert resolve_model() == DEFAULT_MODEL
    monkeypatch.setenv("OUROBOROS_MODEL", "claude-custom-env")
    assert resolve_model() == "claude-custom-env"
    assert resolve_model("explicit-model") == "explicit-model"
    assert resolve_model("  ") == "claude-custom-env"


def test_complete_validated_uses_ouroboros_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUROBOROS_MODEL", "gemini-2.5-pro")
    client = FakeClient(replies=[{"verdict": "ok"}])
    complete_validated(_Answer, client=client, system="s", user="u")
    assert client.calls[0]["model"] == "gemini-2.5-pro"


def test_text_of_handles_dict_and_object_blocks() -> None:
    blocks = [
        {"type": "text", "text": "hello"},
        SimpleNamespace(type="tool_use", name="t", input={}),
        SimpleNamespace(type="text", text="world"),
        {"type": "other", "text": "ignored"},
    ]
    assert _text_of(blocks) == "hello\nworld"
    assert _text_of(None) == ""
    assert _text_of("  plain  ") == "plain"
