"""Shared Anthropic plumbing for the LLM-assisted agents.

Only some of Ouroboros touches a model: the optional Static Analyzer enrichment
pass and, from week 4, the Dynamic Attacker. Everything they share — loading a
system prompt from a Markdown file, wrapping it in a cacheable block, pulling a
JSON object out of a noisy reply, and validating it against a contract with a
retry that feeds the error back — lives here once.

Nothing in this module builds a client. ``complete_validated`` takes the client
as an argument, so every caller stays testable against a fake client that never
touches the network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

# The default model for every LLM-assisted pass. A single constant so a model
# migration is one edit, not a grep. Kept in sync with the sibling projects.
DEFAULT_MODEL = "claude-sonnet-5"

MAX_TOKENS = 4096
MAX_VALIDATION_ATTEMPTS = 3

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

_TEXT_FENCE = re.compile(r"```text\n(.*?)```", re.DOTALL)

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    """The model could not produce a valid contract within the retry budget."""


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------
def load_prompt(name: str) -> str:
    """Return the verbatim system prompt for an agent.

    Prompt files are Markdown so a human can read the rationale alongside the
    prompt; only the fenced ``text`` block is sent to the model. Both run modes
    (API and Claude Code console) read the same file, so the two can never drift.
    """
    path = PROMPT_DIR / f"{name}.md"
    text = path.read_text(encoding="utf-8")
    match = _TEXT_FENCE.search(text)
    if match is None:
        raise LLMError(f"{path.name} has no ```text block to use as a system prompt")
    return match.group(1).strip()


def cacheable_system(prompt: str) -> list[dict[str, Any]]:
    """Wrap a system prompt in a cache-eligible block.

    The prompts are long and identical across every run, so marking them
    ephemeral turns most of the per-call system cost into a cache read.
    """
    return [{"type": "text", "text": prompt, "cache_control": {"type": "ephemeral"}}]


# --------------------------------------------------------------------------
# JSON recovery
# --------------------------------------------------------------------------
def extract_json_object(text: str) -> dict[str, Any]:
    """Pull a JSON object out of a model reply, tolerating the usual noise.

    Three escalating strategies: the reply is already JSON; the JSON sits inside a
    code fence; or it is embedded in prose and has to be found by balancing
    braces. Anything that survives one of them is parsed, so an otherwise good
    answer is never thrown away over a stray "Here is the result:".
    """
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*\n(.*?)```", stripped, re.DOTALL)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = stripped.find("{")
    if start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(stripped)):
            char = stripped[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(stripped[start : index + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break

    raise LLMError(f"no JSON object found in model reply: {stripped[:200]!r}")


def _text_of(blocks: Any) -> str:
    return "\n".join(
        block.text for block in blocks if getattr(block, "type", None) == "text"
    ).strip()


# --------------------------------------------------------------------------
# completion
# --------------------------------------------------------------------------
def complete_validated(
    schema: type[T],
    *,
    client: Any,
    system: str,
    user: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = MAX_TOKENS,
    max_attempts: int = MAX_VALIDATION_ATTEMPTS,
) -> T:
    """Call the model and return a validated ``schema`` instance, retrying on error.

    Nothing downstream trusts the model's text. Each reply is parsed as JSON and
    validated against ``schema``; on failure the loop feeds the exact
    ``ValidationError`` back as a user turn so the model can correct itself, up to
    ``max_attempts`` times, then raises ``LLMError``. A loud failure is always
    preferable to an unvalidated finding reaching a report.
    """
    messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
    last_error = ""
    for _ in range(max_attempts):
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=cacheable_system(system),
            messages=messages,
        )
        raw = _text_of(response.content)
        try:
            return schema.model_validate(extract_json_object(raw))
        except (ValidationError, LLMError) as exc:
            last_error = str(exc)
            messages.append({"role": "assistant", "content": raw})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "That did not validate against the required schema. Fix it and "
                        f"return only the corrected JSON.\n\nError:\n{last_error}"
                    ),
                }
            )
    raise LLMError(f"model never produced a valid {schema.__name__}: {last_error}")
