"""End-to-end wiring: a scan produces a well-typed, correctly-summarized report."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import FakeClient, FakeGithub

from ouroboros.orchestrator import ScanError, _resolve_attack_client, run


def test_scan_fixture_is_auditor_with_static_findings(vuln_agent: Path, tmp_path: Path) -> None:
    result = run(str(vuln_agent), out_dir=tmp_path)
    report = result.report
    assert report.mode == "auditor"
    assert report.applied_action == "report"
    assert report.summary.static_count >= 3
    assert report.dynamic_findings == []
    # both artifacts written
    assert (tmp_path / "vulnerable_agent.md").exists()
    assert (tmp_path / "vulnerable_agent.json").exists()


def test_scan_writes_roundtrippable_json(vuln_agent: Path, tmp_path: Path) -> None:
    import json

    from ouroboros.schemas.audit_report import AuditReport

    run(str(vuln_agent), out_dir=tmp_path)
    payload = json.loads((tmp_path / "vulnerable_agent.json").read_text())
    restored = AuditReport.model_validate(payload)
    assert restored.summary.static_count >= 3


def test_local_target_ignores_push_granting_client(vuln_agent: Path, tmp_path: Path) -> None:
    # Even handed a client that would grant push, a local path stays auditor.
    result = run(str(vuln_agent), github_client=FakeGithub(push=True), out_dir=tmp_path)
    assert result.report.mode == "auditor"


def test_attack_in_auditor_mode_simulates_offline(vuln_agent: Path, tmp_path: Path) -> None:
    # A local path resolves to auditor, so --attack runs the offline SimulatedTarget
    # with no client and no API key. The undefended fixture falls for every payload.
    result = run(str(vuln_agent), attack=True, min_interval_seconds=0, out_dir=tmp_path)
    report = result.report
    assert report.dynamic_run is not None
    assert report.dynamic_run.attempts == 12
    assert report.dynamic_run.confidence == "simulated"
    assert report.summary.dynamic_count > 0


def test_no_attack_flag_leaves_dynamic_empty(vuln_agent: Path, tmp_path: Path) -> None:
    result = run(str(vuln_agent), attack=False, out_dir=tmp_path)
    assert result.report.dynamic_run is None
    assert result.report.dynamic_findings == []


def test_owner_attack_without_client_raises_scan_error() -> None:
    from ouroboros.schemas.repo_profile import RepoProfile

    profile = RepoProfile(source="x", resolved_mode="owner")
    with pytest.raises(ScanError):
        _resolve_attack_client("owner", True, None, profile, [])


def test_owner_attack_with_client_is_confirmed_live() -> None:
    from ouroboros.schemas.repo_profile import RepoProfile

    profile = RepoProfile(source="x", resolved_mode="owner")
    resolved = _resolve_attack_client("owner", True, FakeClient(), profile, [])
    assert resolved is not None
    _, confidence = resolved
    assert confidence == "confirmed_live"


def test_no_attack_resolves_to_none() -> None:
    from ouroboros.schemas.repo_profile import RepoProfile

    profile = RepoProfile(source="x", resolved_mode="auditor")
    assert _resolve_attack_client("auditor", False, None, profile, []) is None


def test_hardened_target_resists_more_than_vulnerable(tmp_path: Path) -> None:
    result = run(
        "tests/fixtures/hardened_agent", attack=True, min_interval_seconds=0, out_dir=tmp_path
    )
    dr = result.report.dynamic_run
    assert dr is not None
    assert 0 < dr.successes < dr.attempts  # a gradient, not all-or-nothing
