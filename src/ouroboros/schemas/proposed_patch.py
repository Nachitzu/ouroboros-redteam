"""A concrete guardrail the Patch Generator proposes for a finding.

Poblado from week 6 onward; the contract lands now so ``AuditReport`` can carry
patches without a shape change later. A patch is a real unified diff — the
week-6 success criterion is that ``git apply`` accepts it — plus the rationale a
reviewer needs to trust it before it is committed (owner) or handed over
(auditor).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProposedPatch(BaseModel):
    """A single suggested guardrail, expressed as an applicable diff."""

    finding_ref: str = Field(min_length=1, description="Which finding this patch answers.")
    title: str = Field(min_length=1)
    guardrail_type: str = Field(
        min_length=1,
        description="e.g. 'delimiters', 'instruction_hierarchy', 'output_validation'.",
    )
    diff: str = Field(min_length=1, description="Unified diff, applicable with `git apply`.")
    rationale: str = Field(min_length=1)
