"""Tests for provider adapters (OpenAI/OpenAI-compatible and Gemini) with fake SDKs."""

from __future__ import annotations

import builtins
import json
from types import SimpleNamespace
from typing import Any

import pytest

from ouroboros.providers import GeminiAdapter, OpenAIAdapter, ProviderError, build_client


class _FakeOpenAISDK:
    def __init__(self, response: SimpleNamespace) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return self._response


class _FakeGeminiSDK:
    def __init__(self, response: SimpleNamespace) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []
        self.models = SimpleNamespace(generate_content=self._generate)

    def _generate(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return self._response


def test_openai_adapter_translates_messages_tools_and_usage() -> None:
    fake_resp = SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason="tool_calls",
                message=SimpleNamespace(
                    content="Let me run that.",
                    tool_calls=[
                        SimpleNamespace(
                            id="call_42",
                            function=SimpleNamespace(
                                name="send_email",
                                arguments=json.dumps({"to": "a@b.c", "body": "OURO-1234"}),
                            ),
                        )
                    ],
                ),
            )
        ],
        usage=SimpleNamespace(prompt_tokens=110, completion_tokens=25),
    )
    sdk = _FakeOpenAISDK(fake_resp)
    client = OpenAIAdapter(sdk_client=sdk)
    assert client.provider_name == "openai"

    resp = client.messages.create(
        model="gpt-4o-mini",
        max_tokens=512,
        system=[{"type": "text", "text": "Be careful.", "cache_control": {"type": "ephemeral"}}],
        messages=[
            {"role": "user", "content": "Hi"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "t1", "name": "lookup", "input": {"q": "x"}},
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}],
            },
        ],
        tools=[
            {
                "name": "send_email",
                "description": "Send email",
                "input_schema": {"type": "object", "properties": {"body": {"type": "string"}}},
            }
        ],
    )

    sent = sdk.calls[0]
    assert sent["model"] == "gpt-4o-mini"
    assert sent["messages"][0] == {"role": "system", "content": "Be careful."}
    assert sent["messages"][2]["tool_calls"][0]["function"]["name"] == "lookup"
    assert sent["messages"][3] == {"role": "tool", "tool_call_id": "t1", "content": "ok"}
    assert sent["tools"][0]["type"] == "function"
    assert sent["tools"][0]["function"]["name"] == "send_email"

    assert resp.stop_reason == "tool_use"
    assert resp.content[0].type == "text"
    assert resp.content[0].text == "Let me run that."
    assert resp.content[1].type == "tool_use"
    assert resp.content[1].id == "call_42"
    assert resp.content[1].name == "send_email"
    assert resp.content[1].input == {"to": "a@b.c", "body": "OURO-1234"}
    assert resp.usage.input_tokens == 110
    assert resp.usage.output_tokens == 25


def test_gemini_adapter_translates_system_tools_and_usage() -> None:
    fake_resp = SimpleNamespace(
        candidates=[
            SimpleNamespace(
                finish_reason="STOP",
                content=SimpleNamespace(
                    parts=[
                        SimpleNamespace(text="Done.", function_call=None),
                        SimpleNamespace(
                            text=None,
                            function_call=SimpleNamespace(
                                name="delete_file",
                                args={"path": "OURO-9999"},
                            ),
                        ),
                    ]
                ),
            )
        ],
        usage_metadata=SimpleNamespace(prompt_token_count=80, candidates_token_count=15),
    )
    sdk = _FakeGeminiSDK(fake_resp)
    client = GeminiAdapter(sdk_client=sdk)
    assert client.provider_name == "gemini"

    resp = client.messages.create(
        model="gemini-2.5-flash",
        max_tokens=256,
        system="System rules.",
        messages=[
            {"role": "user", "content": "First"},
            {"role": "assistant", "content": "Reply"},
            {"role": "user", "content": "Second"},
        ],
        tools=[
            {
                "name": "delete_file",
                "description": "Delete a file",
                "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
    )

    sent = sdk.calls[0]
    assert sent["model"] == "gemini-2.5-flash"
    assert sent["config"]["system_instruction"] == "System rules."
    assert sent["config"]["tools"][0]["function_declarations"][0]["name"] == "delete_file"
    assert [c["role"] for c in sent["contents"]] == ["user", "model", "user"]

    assert resp.stop_reason == "tool_use"
    assert resp.content[0].type == "text"
    assert resp.content[0].text == "Done."
    assert resp.content[1].type == "tool_use"
    assert resp.content[1].name == "delete_file"
    assert resp.content[1].input == {"path": "OURO-9999"}
    assert resp.usage.input_tokens == 80
    assert resp.usage.output_tokens == 15


def test_build_client_anthropic_and_unknown() -> None:
    client = build_client("anthropic", api_key="sk-ant-test")
    assert hasattr(client, "messages")

    with pytest.raises(ProviderError, match="Unknown provider"):
        build_client("bedrock")


def test_missing_optional_sdk_raises_clear_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def _block(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "openai" or name == "google" or name.startswith("google."):
            raise ImportError(f"blocked {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block)

    with pytest.raises(ProviderError, match=r"ouroboros-redteam\[openai\]"):
        build_client("openai", api_key="x")

    with pytest.raises(ProviderError, match=r"ouroboros-redteam\[gemini\]"):
        build_client("gemini", api_key="x")
