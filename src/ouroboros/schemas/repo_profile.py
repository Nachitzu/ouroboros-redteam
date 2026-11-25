"""What the Recon Agent learns about a target before anyone attacks it.

``RepoProfile`` is the first contract in the pipeline. It records where the target
came from, whether Ouroboros may write to it, and — the part that matters for
prompt-injection analysis — every system prompt, LLM entry point and tool recon
could find. Everything downstream reasons over this object, never over the raw
repo, so the profile is the single place a target is "understood".
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ouroboros.schemas.common import Mode

# Coarse capability classes for a tool. They drive the excessive-agency detector
# and the tool-hijack oracle: hijacking a "read" tool is bad, hijacking a
# "shell" or "network" one is worse.
ToolCapability = Literal[
    "shell",
    "network",
    "filesystem_write",
    "filesystem_read",
    "database",
    "email",
    "code_exec",
    "payment",
    "other",
]


class ExtractedPrompt(BaseModel):
    """A system/instruction prompt recovered from the target, with its provenance.

    ``method`` records *how* it was found (a fenced ``text`` block in a prompt
    file, a string literal passed to ``system=``, a template file...), because a
    prompt lifted from a Markdown file and one reconstructed from source do not
    warrant the same confidence downstream. ``span`` is the exact character
    offset of ``text`` inside ``file_path`` when known, which is what lets the
    Patch Generator rewrite the prompt in place.
    """

    file_path: str
    method: str = Field(
        description="How the prompt was located, e.g. text-fence, system-kwarg, assignment, "
        "template-file, chat-template."
    )
    text: str = Field(min_length=1)
    line: int | None = None

    @property
    def ref(self) -> str:
        return f"{self.file_path}:{self.line}" if self.line else self.file_path


class EntryPoint(BaseModel):
    """A place where the target hands control to an LLM or exposes a CLI.

    Either a console script declared in ``pyproject.toml`` or a call site that
    reaches an LLM SDK (``messages.create``, ``chat.completions.create``,
    ``generate_content``, ``litellm.completion``, a LangChain ``invoke``...).
    """

    kind: str = Field(description="'console_script' or 'llm_call'.")
    location: str = Field(description="Dotted target or file:line.")
    detail: str | None = None


class ExtractedTool(BaseModel):
    """A tool/function the target exposes to its model.

    Recovered from Anthropic/OpenAI ``tools=[...]`` schemas, ``@tool`` /
    ``@mcp.tool`` / ``@function_tool`` decorators and Gemini function
    declarations. Never executed — only described, so the Dynamic Attacker can
    offer the same tool surface to a model and see if an injection steers it.
    """

    name: str = Field(min_length=1)
    description: str = ""
    file_path: str
    line: int | None = None
    source: str = Field(description="e.g. 'anthropic-schema', 'mcp-decorator', 'langchain-tool'.")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="JSON-schema 'input_schema' when recoverable."
    )
    capabilities: list[ToolCapability] = Field(default_factory=list)
    requires_confirmation: bool = Field(
        default=False, description="True if a human-approval gate was detected around the tool."
    )


class RepoProfile(BaseModel):
    """The Recon Agent's structured understanding of a target repository."""

    source: str = Field(description="The URL or local path the scan was pointed at.")
    resolved_mode: Mode
    is_remote: bool = False
    commit_sha: str | None = None
    language: str | None = None
    framework: str | None = None
    frameworks: list[str] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    system_prompts: list[ExtractedPrompt] = Field(default_factory=list)
    tools: list[ExtractedTool] = Field(default_factory=list)
    default_branch: str | None = None
    notes: list[str] = Field(
        default_factory=list,
        description="Human-readable caveats, e.g. why the mode was downgraded to auditor.",
    )
