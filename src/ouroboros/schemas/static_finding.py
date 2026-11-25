"""A weakness the Static Analyzer found by reading code and prompts.

A ``StaticFinding`` never claims the target *was* exploited — only that a known
weak pattern is present. Its confidence is fixed to ``"static"`` by the type
system so it can never be confused with a dynamically confirmed hit, and it
carries the exact file/line and evidence snippet so a human (or the Patch
Generator) can go straight to the source.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ouroboros.schemas.common import AtlasTechnique, FindingCategory, OwaspRisk, Severity


class StaticFinding(BaseModel):
    """One statically detected weakness in the target."""

    category: FindingCategory
    severity: Severity
    confidence: Literal["static"] = "static"
    file_path: str
    line: int | None = None
    evidence: str = Field(min_length=1, description="The offending code/prompt fragment.")
    explanation: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    atlas: list[AtlasTechnique] = Field(default_factory=list)
    owasp: list[OwaspRisk] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list, description="e.g. 'CWE-77'.")
    enriched: bool = Field(
        default=False, description="True if explanation/recommendation came from the LLM pass."
    )
