"""The validation loop is the LLM safety boundary; prove it retries and recovers."""

from __future__ import annotations

import pytest
from pydantic import BaseModel
from tests.conftest import FakeClient

from ouroboros._llm import LLMError, complete_validated, extract_json_object, load_prompt


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
