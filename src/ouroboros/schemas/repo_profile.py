"""What the Recon Agent learns about a target before anyone attacks it.

``RepoProfile`` is the first contract in the pipeline. It records where the target
came from, whether Ouroboros may write to it, and — the part that matters for
prompt-injection analysis — every system prompt and LLM entry point recon could
find. Everything downstream reasons over this object, never over the raw repo, so
the profile is the single place a target is "understood".
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ouroboros.schemas.common import Mode


class ExtractedPrompt(BaseModel):
    """A system/instruction prompt recovered from the target, with its provenance.

    ``method`` records *how* it was found (a fenced ``text`` block in a prompt
    file, or a string literal passed to ``system=``), because a prompt lifted from
    a Markdown file and one reconstructed from source do not warrant the same
    confidence downstream.
    """

    file_path: str
    method: str = Field(description="How the prompt was located, e.g. text-fence or system-kwarg.")
    text: str = Field(min_length=1)
    line: int | None = None


class EntryPoint(BaseModel):
    """A place where the target hands control to an LLM or exposes a CLI.

    Either a console script declared in ``pyproject.toml`` or a call site that
    reaches ``*.messages.create(...)``. These are the surfaces an attacker would
    aim at, so recon collects them for the analyzers that come next.
    """

    kind: str = Field(description="'console_script' or 'llm_call'.")
    location: str = Field(description="Dotted target or file:line.")
    detail: str | None = None


class RepoProfile(BaseModel):
    """The Recon Agent's structured understanding of a target repository."""

    source: str = Field(description="The URL or local path the scan was pointed at.")
    resolved_mode: Mode
    is_remote: bool = False
    commit_sha: str | None = None
    language: str | None = None
    framework: str | None = None
    entry_points: list[EntryPoint] = Field(default_factory=list)
    system_prompts: list[ExtractedPrompt] = Field(default_factory=list)
    notes: list[str] = Field(
        default_factory=list,
        description="Human-readable caveats, e.g. why the mode was downgraded to auditor.",
    )
