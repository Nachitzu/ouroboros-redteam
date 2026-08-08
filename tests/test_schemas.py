"""The contracts are the safety boundary; these tests pin their invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ouroboros.schemas import (
    AtlasTechnique,
    AuditReport,
    DynamicFinding,
    RepoProfile,
    StaticFinding,
)


def _profile(mode: str = "auditor") -> RepoProfile:
    return RepoProfile(source="./x", resolved_mode=mode)  # type: ignore[arg-type]


def _static() -> StaticFinding:
    return StaticFinding(
        category="direct_interpolation",
        severity="HIGH",
        file_path="a.py",
        line=1,
        evidence='f"{x}"',
        explanation="bad",
        recommendation="fix",
    )


def test_atlas_id_shape_is_enforced() -> None:
    AtlasTechnique(technique_id="AML.T0051", name="x", tactic="y")
    AtlasTechnique(technique_id="AML.T0051.001", name="x", tactic="y")
    with pytest.raises(ValidationError):
        AtlasTechnique(technique_id="T1566", name="x", tactic="y")


def test_static_finding_confidence_is_frozen() -> None:
    assert _static().confidence == "static"


def test_auditor_mode_may_not_write() -> None:
    with pytest.raises(ValidationError):
        AuditReport(repo=_profile("auditor"), mode="auditor", applied_action="commit")


def test_owner_mode_may_commit() -> None:
    report = AuditReport(repo=_profile("owner"), mode="owner", applied_action="commit")
    assert report.applied_action == "commit"


def test_summary_counts_by_severity_and_category() -> None:
    dyn = DynamicFinding(
        category="direct_interpolation",
        severity="CRITICAL",
        confidence="simulated",
        family="direct",
        payload_id="p1",
        payload="ignore all",
        observed_behavior="obeyed",
        success=True,
    )
    report = AuditReport(
        repo=_profile(),
        mode="auditor",
        static_findings=[_static()],
        dynamic_findings=[dyn],
    ).with_summary()
    assert report.summary.total_findings == 2
    assert report.summary.by_severity == {"HIGH": 1, "CRITICAL": 1}
    assert report.summary.static_count == 1
    assert report.summary.dynamic_count == 1
