"""The Pydantic contracts every agent boundary in Ouroboros must speak.

Re-exported here so the rest of the codebase imports from one place
(``from ouroboros.schemas import RepoProfile``) rather than reaching into the
individual modules. If it is not in ``__all__``, it is not part of the contract
surface.
"""

from __future__ import annotations

from ouroboros.schemas.audit_report import AppliedAction, AuditReport, ReportSummary
from ouroboros.schemas.common import (
    AtlasTechnique,
    Confidence,
    FindingCategory,
    Mode,
    Severity,
    now_utc,
)
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.proposed_patch import ProposedPatch
from ouroboros.schemas.repo_profile import EntryPoint, ExtractedPrompt, RepoProfile
from ouroboros.schemas.static_finding import StaticFinding

__all__ = [
    "AppliedAction",
    "AtlasTechnique",
    "AuditReport",
    "Confidence",
    "DynamicFinding",
    "EntryPoint",
    "ExtractedPrompt",
    "FindingCategory",
    "Mode",
    "ProposedPatch",
    "RepoProfile",
    "ReportSummary",
    "Severity",
    "StaticFinding",
    "now_utc",
]
