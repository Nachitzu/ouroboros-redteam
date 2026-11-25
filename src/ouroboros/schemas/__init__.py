"""The Pydantic contracts every agent boundary in Ouroboros must speak.

Re-exported here so the rest of the codebase imports from one place
(``from ouroboros.schemas import RepoProfile``) rather than reaching into the
individual modules. If it is not in ``__all__``, it is not part of the contract
surface.
"""

from __future__ import annotations

from ouroboros.schemas.audit_report import AppliedAction, AuditReport, ReportSummary
from ouroboros.schemas.common import (
    SEVERITY_ORDER,
    AtlasTechnique,
    Confidence,
    FindingCategory,
    Mode,
    Oracle,
    OwaspRisk,
    PayloadFamily,
    Severity,
    now_utc,
)
from ouroboros.schemas.dynamic_finding import (
    DynamicFinding,
    DynamicRunStats,
    FamilyStats,
    PatchVerification,
)
from ouroboros.schemas.proposed_patch import PatchKind, ProposedPatch
from ouroboros.schemas.repo_profile import (
    EntryPoint,
    ExtractedPrompt,
    ExtractedTool,
    RepoProfile,
    ToolCapability,
)
from ouroboros.schemas.static_finding import StaticFinding

__all__ = [
    "SEVERITY_ORDER",
    "AppliedAction",
    "AtlasTechnique",
    "AuditReport",
    "Confidence",
    "DynamicFinding",
    "DynamicRunStats",
    "EntryPoint",
    "ExtractedPrompt",
    "ExtractedTool",
    "FamilyStats",
    "FindingCategory",
    "Mode",
    "Oracle",
    "OwaspRisk",
    "PatchKind",
    "PatchVerification",
    "PayloadFamily",
    "ProposedPatch",
    "RepoProfile",
    "ReportSummary",
    "Severity",
    "StaticFinding",
    "ToolCapability",
    "now_utc",
]
