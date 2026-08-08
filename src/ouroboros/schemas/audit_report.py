"""The top-level contract Ouroboros produces for every scan.

``AuditReport`` binds together the target profile and every finding and patch, and
records what Ouroboros actually *did* — reported, committed, or opened a PR. The
model enforces the project's central safety rule structurally: in ``auditor``
mode the only permitted action is ``report``. That invariant lives in the type,
not in a comment, so no future code path can auto-commit against a repo it lacks
write access to without failing validation first.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ouroboros.schemas.common import Mode, now_utc
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.proposed_patch import ProposedPatch
from ouroboros.schemas.repo_profile import RepoProfile
from ouroboros.schemas.static_finding import StaticFinding

AppliedAction = Literal["report", "commit", "pull_request"]


class ReportSummary(BaseModel):
    """Roll-up counts so a reader sees the shape of a scan before the detail."""

    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    static_count: int = 0
    dynamic_count: int = 0
    patch_count: int = 0


class AuditReport(BaseModel):
    """Everything one Ouroboros scan concluded about one target."""

    repo: RepoProfile
    mode: Mode
    generated_at: datetime = Field(default_factory=now_utc)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    dynamic_findings: list[DynamicFinding] = Field(default_factory=list)
    proposed_patches: list[ProposedPatch] = Field(default_factory=list)
    summary: ReportSummary = Field(default_factory=ReportSummary)
    applied_action: AppliedAction = "report"

    @model_validator(mode="after")
    def _auditor_never_writes(self) -> AuditReport:
        # The fail-safe, encoded in the contract: without confirmed write access
        # the only thing Ouroboros may have done is produce a report.
        if self.mode == "auditor" and self.applied_action != "report":
            raise ValueError(
                f"auditor mode may only 'report', not {self.applied_action!r} — "
                "auto-writing a repo without confirmed write access is forbidden"
            )
        return self

    def with_summary(self) -> AuditReport:
        """Return a copy with ``summary`` recomputed from the current findings.

        Kept explicit rather than a validator so callers assemble findings first
        and derive the roll-up once, at the end, in a single obvious place.
        """
        severity: Counter[str] = Counter()
        category: Counter[str] = Counter()
        for static in self.static_findings:
            severity[static.severity] += 1
            category[static.category] += 1
        for dynamic in self.dynamic_findings:
            severity[dynamic.severity] += 1
            category[dynamic.category] += 1
        summary = ReportSummary(
            total_findings=len(self.static_findings) + len(self.dynamic_findings),
            by_severity=dict(severity),
            by_category=dict(category),
            static_count=len(self.static_findings),
            dynamic_count=len(self.dynamic_findings),
            patch_count=len(self.proposed_patches),
        )
        return self.model_copy(update={"summary": summary})
