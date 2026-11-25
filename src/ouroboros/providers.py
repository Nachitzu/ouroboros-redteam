"""Provider adapters presenting a unified Anthropic-shaped client surface.

Ouroboros' attacker and validator call ``client.messages.create(model, max_tokens,
system, messages, tools=...)`` and read Anthropic-shaped response blocks
(``text`` and ``tool_use``) plus ``usage(input_tokens, output_tokens)``. This
module adapts OpenAI (including Ollama/vLLM/LM Studio OpenAI-compatible
endpoints) and Google Gemini (``google-genai``) behind that same shape.

All third-party SDKs are imported lazily so plain offline scans never require
optional extras to be installed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from types import SimpleNamespace
from typing import Any


class ProviderError(RuntimeError):
    """A configured LLM provider could not be constructed or is missing its SDK."""


def _flatten_system(system: Any) -> str:
    """Convert an Anthropic ``system`` argument (str or block list) to plain text."""
    if system is None:
        return ""
    if isinstance(system, str):
        return system
    if isinstance(system, Sequence):
        parts: list[str] = []
        for block in system:
            if isinstance(block, Mapping):
                if block.get("type", "text") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
            else:
                if getattr(block, "type", "text") == "text":
                    text = getattr(block, "text", None)
                    if isinstance(text, str):
                        parts.append(text)
        return "\n".join(parts)
    return str(system)


def _block_field(block: Any, key: str, default: Any = None) -> Any:
    if isinstance(block, Mapping):
        return block.get(key, default)
    return getattr(block, key, default)


def _stringify_tool_result(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence) and not isinstance(content, (bytes, bytearray)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, Mapping) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, str):
                parts.append(item)
            else:
                parts.append(json.dumps(item, default=str))
        return "\n".join(parts)
    return json.dumps(content, default=str)


def _parse_json_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except json.JSONDecodeError:
            return {"raw": raw}
    return {}


# ---------------------------------------------------------------------------
# OpenAI (and OpenAI-compatible: Ollama, vLLM, LM Studio)
# ---------------------------------------------------------------------------
class _OpenAIMessages:
    def __init__(self, owner: OpenAIAdapter) -> None:
        self._owner = owner

    def create(
        self,
        *,
        model: str,
        max_tokens: int = 4096,
        system: Any = None,
        messages: Sequence[Mapping[str, Any]] = (),
        tools: Sequence[Mapping[str, Any]] | None = None,
        **kwargs: Any,
    ) -> SimpleNamespace:
        oai_messages = _to_openai_messages(system, messages)
        call_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": oai_messages,
            **kwargs,
        }
        if tools:
            call_kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                    },
                }
                for t in tools
            ]
        response = self._owner._client.chat.completions.create(**call_kwargs)
        return _from_openai_response(response)


class OpenAIAdapter:
    """Wraps ``openai.OpenAI`` behind an Anthropic-shaped ``.messages.create`` API."""

    provider_name = "openai"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is not None:
            self._client = sdk_client
        else:
            try:
                import openai  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ProviderError(
                    "The 'openai' package is required for provider='openai'. "
                    "Install it with: pip install 'ouroboros-redteam[openai]'"
                ) from exc
            client_kwargs: dict[str, Any] = {}
            if base_url is not None:
                client_kwargs["base_url"] = base_url
            if api_key is not None:
                client_kwargs["api_key"] = api_key
            elif base_url is not None and not os.environ.get("OPENAI_API_KEY"):
                # OpenAI-compatible local servers (Ollama/vLLM/LM Studio) ignore the key,
                # but the OpenAI SDK requires a non-empty string unless env is set.
                client_kwargs["api_key"] = "local"
            self._client = openai.OpenAI(**client_kwargs)
        self.messages = _OpenAIMessages(self)


def _to_openai_messages(system: Any, messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sys_text = _flatten_system(system)
    if sys_text:
        out.append({"role": "system", "content": sys_text})

    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        if not isinstance(content, Sequence):
            out.append({"role": role, "content": str(content)})
            continue

        if role == "assistant":
            text_parts: list[str] = []
            tool_calls: list[dict[str, Any]] = []
            for idx, block in enumerate(content):
                btype = _block_field(block, "type")
                if btype == "text":
                    text_parts.append(str(_block_field(block, "text", "")))
                elif btype == "tool_use":
                    tc_id = str(_block_field(block, "id") or f"call_{idx}")
                    name = str(_block_field(block, "name", ""))
                    args = _block_field(block, "input", {})
                    tool_calls.append(
                        {
                            "id": tc_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(args, default=str),
                            },
                        }
                    )
            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": "\n".join(text_parts) if text_parts else (None if tool_calls else ""),
            }
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            out.append(assistant_msg)
        else:
            user_text_parts: list[str] = []
            for block in content:
                btype = _block_field(block, "type")
                if btype == "tool_result":
                    if user_text_parts:
                        out.append({"role": role, "content": "\n".join(user_text_parts)})
                        user_text_parts.clear()
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": str(_block_field(block, "tool_use_id", "")),
                            "content": _stringify_tool_result(_block_field(block, "content", "")),
                        }
                    )
                elif btype == "text":
                    user_text_parts.append(str(_block_field(block, "text", "")))
            if user_text_parts:
                out.append({"role": role, "content": "\n".join(user_text_parts)})
    return out


def _from_openai_response(response: Any) -> SimpleNamespace:
    choices = getattr(response, "choices", None) or []
    content: list[SimpleNamespace] = []
    stop_reason = "end_turn"
    if choices:
        choice = choices[0]
        msg = getattr(choice, "message", None)
        msg_text = getattr(msg, "content", None) if msg is not None else None
        if isinstance(msg_text, str) and msg_text:
            content.append(SimpleNamespace(type="text", text=msg_text))
        tool_calls = getattr(msg, "tool_calls", None) if msg is not None else None
        if tool_calls:
            for idx, tc in enumerate(tool_calls):
                fn = getattr(tc, "function", None)
                name = getattr(fn, "name", "") if fn is not None else ""
                raw_args = getattr(fn, "arguments", "{}") if fn is not None else "{}"
                tc_id = getattr(tc, "id", None) or f"call_{idx}"
                content.append(
                    SimpleNamespace(
                        type="tool_use",
                        id=str(tc_id),
                        name=str(name),
                        input=_parse_json_args(raw_args),
                    )
                )
        finish = getattr(choice, "finish_reason", None)
        if finish == "tool_calls" or any(b.type == "tool_use" for b in content):
            stop_reason = "tool_use"
        elif finish == "length":
            stop_reason = "max_tokens"
        elif finish in ("stop", None):
            stop_reason = "end_turn"
        else:
            stop_reason = str(finish)

    usage_obj = getattr(response, "usage", None)
    input_tokens = int(
        getattr(usage_obj, "prompt_tokens", None) or getattr(usage_obj, "input_tokens", 0) or 0
    )
    output_tokens = int(
        getattr(usage_obj, "completion_tokens", None) or getattr(usage_obj, "output_tokens", 0) or 0
    )
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
    )


# ---------------------------------------------------------------------------
# Google Gemini (google-genai)
# ---------------------------------------------------------------------------
class _GeminiMessages:
    def __init__(self, owner: GeminiAdapter) -> None:
        self._owner = owner

    def create(
        self,
        *,
        model: str,
        max_tokens: int = 4096,
        system: Any = None,
        messages: Sequence[Mapping[str, Any]] = (),
        tools: Sequence[Mapping[str, Any]] | None = None,
        **kwargs: Any,
    ) -> SimpleNamespace:
        sys_text = _flatten_system(system)
        contents = _to_gemini_contents(messages)
        config: dict[str, Any] = {"max_output_tokens": max_tokens}
        if sys_text:
            config["system_instruction"] = sys_text
        if tools:
            config["tools"] = [
                {
                    "function_declarations": [
                        {
                            "name": t["name"],
                            "description": t.get("description", ""),
                            "parameters": t.get(
                                "input_schema", {"type": "object", "properties": {}}
                            ),
                        }
                        for t in tools
                    ]
                }
            ]
        response = self._owner._client.models.generate_content(
            model=model,
            contents=contents,
            config=config,
            **kwargs,
        )
        return _from_gemini_response(response)


class GeminiAdapter:
    """Wraps ``google.genai.Client`` behind an Anthropic-shaped ``.messages.create`` API."""

    provider_name = "gemini"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is not None:
            self._client = sdk_client
        else:
            try:
                from google import genai  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ProviderError(
                    "The 'google-genai' package is required for provider='gemini'. "
                    "Install it with: pip install 'ouroboros-redteam[gemini]'"
                ) from exc
            client_kwargs: dict[str, Any] = {}
            if api_key is not None:
                client_kwargs["api_key"] = api_key
            if base_url is not None:
                client_kwargs["http_options"] = {"base_url": base_url}
            self._client = genai.Client(**client_kwargs)
        self.messages = _GeminiMessages(self)


def _to_gemini_contents(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    contents: list[dict[str, Any]] = []
    for msg in messages:
        role = "model" if msg.get("role") == "assistant" else "user"
        raw_content = msg.get("content", "")
        parts: list[dict[str, Any]] = []
        if isinstance(raw_content, str):
            parts.append({"text": raw_content})
        elif isinstance(raw_content, Sequence):
            for block in raw_content:
                btype = _block_field(block, "type")
                if btype == "text":
                    parts.append({"text": str(_block_field(block, "text", ""))})
                elif btype == "tool_use":
                    args = _block_field(block, "input", {})
                    parts.append(
                        {
                            "function_call": {
                                "name": str(_block_field(block, "name", "")),
                                "args": dict(args) if isinstance(args, Mapping) else {},
                            }
                        }
                    )
                elif btype == "tool_result":
                    parts.append(
                        {
                            "function_response": {
                                "name": str(
                                    _block_field(block, "name")
                                    or _block_field(block, "tool_use_id", "tool")
                                ),
                                "response": {
                                    "result": _stringify_tool_result(
                                        _block_field(block, "content", "")
                                    )
                                },
                            }
                        }
                    )
        else:
            parts.append({"text": str(raw_content)})
        contents.append({"role": role, "parts": parts})
    return contents


def _from_gemini_response(response: Any) -> SimpleNamespace:
    content: list[SimpleNamespace] = []
    candidates = getattr(response, "candidates", None) or []
    parts: list[Any] = []
    finish_reason: Any = None
    if candidates:
        cand = candidates[0]
        finish_reason = getattr(cand, "finish_reason", None)
        cand_content = getattr(cand, "content", None)
        parts = list(getattr(cand_content, "parts", None) or [])
    elif getattr(response, "parts", None):
        parts = list(response.parts)
    elif isinstance(getattr(response, "text", None), str) and response.text:
        content.append(SimpleNamespace(type="text", text=response.text))

    for idx, part in enumerate(parts):
        text = _block_field(part, "text")
        if isinstance(text, str) and text:
            content.append(SimpleNamespace(type="text", text=text))
        fc = _block_field(part, "function_call")
        if fc is not None:
            name = _block_field(fc, "name", "")
            raw_args = _block_field(fc, "args", {})
            args_dict = dict(raw_args) if isinstance(raw_args, Mapping) else {}
            fc_id = _block_field(fc, "id") or f"gemini_call_{idx}"
            content.append(
                SimpleNamespace(
                    type="tool_use",
                    id=str(fc_id),
                    name=str(name),
                    input=args_dict,
                )
            )

    if any(b.type == "tool_use" for b in content):
        stop_reason = "tool_use"
    elif str(finish_reason).upper().endswith("MAX_TOKENS"):
        stop_reason = "max_tokens"
    else:
        stop_reason = "end_turn"

    um = getattr(response, "usage_metadata", None)
    input_tokens = int(getattr(um, "prompt_token_count", 0) or 0)
    output_tokens = int(getattr(um, "candidates_token_count", 0) or 0)
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
    )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def build_client(
    provider: str = "anthropic",
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Any:
    """Return an Anthropic-shaped LLM client for ``provider``.

    Supported providers: ``"anthropic"``, ``"openai"`` (including OpenAI-compatible
    endpoints such as Ollama/vLLM/LM Studio via ``base_url``), and ``"gemini"``.
    """
    normalized = provider.strip().lower()
    if normalized == "anthropic":
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError(
                "The 'anthropic' package is required for provider='anthropic'."
            ) from exc
        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url
        if api_key is not None:
            kwargs["api_key"] = api_key
        return anthropic.Anthropic(**kwargs)
    if normalized == "openai":
        return OpenAIAdapter(base_url=base_url, api_key=api_key)
    if normalized == "gemini":
        return GeminiAdapter(api_key=api_key, base_url=base_url)
    raise ProviderError(
        f"Unknown provider {provider!r}. Supported providers: anthropic, openai, gemini."
    )
