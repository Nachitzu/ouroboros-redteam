"""A concrete guardrail the Patch Generator proposes for a finding.

A patch is a real unified diff — ``git apply`` accepts it — plus the rationale a
reviewer needs to trust it before it is committed (owner) or handed over
(auditor). ``kind`` separates the two shapes the generator emits: an advisory
comment placed above offending code, and a real rewrite of a system prompt that
adds the missing defenses (which ``--verify-patches`` can then re-attack).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

PatchKind = Literal["advisory_comment", "prompt_hardening"]


class ProposedPatch(BaseModel):
    """A single suggested guardrail, expressed as an applicable diff."""

    finding_ref: str = Field(min_length=1, description="Which finding(s) this patch answers.")
    title: str = Field(min_length=1)
    guardrail_type: str = Field(
        min_length=1,
        description="e.g. 'delimiters', 'instruction_hierarchy', 'output_validation'.",
    )
    diff: str = Field(min_length=1, description="Unified diff, applicable with `git apply`.")
    rationale: str = Field(min_length=1)
    kind: PatchKind = "advisory_comment"
    file_path: str | None = None
    finding_refs: list[str] = Field(
        default_factory=list, description="Every finding folded into this (per-file) patch."
    )
