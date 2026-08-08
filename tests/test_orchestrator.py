"""End-to-end wiring: a scan produces a well-typed, correctly-summarized report."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import FakeClient, FakeGithub

from ouroboros.orchestrator import run


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


def test_attack_flag_runs_a_campaign_and_records_stats(vuln_agent: Path, tmp_path: Path) -> None:
    # A random canary means the scripted replies never match, so successes is 0 —
    # but the campaign still ran and the run stats are recorded, which is the wiring
    # this test pins.
    client = FakeClient(replies=["I cannot help." for _ in range(12)])
    result = run(
        str(vuln_agent), attack=True, llm_client=client, min_interval_seconds=0, out_dir=tmp_path
    )
    report = result.report
    assert report.dynamic_run is not None
    assert report.dynamic_run.attempts == 12
    assert report.dynamic_run.confidence == "simulated"  # local path -> auditor
    assert len(client.calls) == 12


def test_no_attack_flag_leaves_dynamic_empty(vuln_agent: Path, tmp_path: Path) -> None:
    result = run(str(vuln_agent), attack=False, out_dir=tmp_path)
    assert result.report.dynamic_run is None
    assert result.report.dynamic_findings == []
