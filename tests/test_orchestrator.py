"""End-to-end wiring: a scan produces a well-typed, correctly-summarized report."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import FakeClient, FakeGithub

from ouroboros.orchestrator import (
    ScanError,
    _dispatch_output,
    _resolve_attack_client,
    run,
)


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


def test_auditor_fix_still_only_reports(vuln_agent: Path, tmp_path: Path) -> None:
    # fix=True on a local (auditor) target must not write: patches are generated for
    # the report, but applied_action stays "report" (the schema fail-safe).
    result = run(str(vuln_agent), fix=True, out_dir=tmp_path)
    assert result.report.applied_action == "report"
    assert len(result.report.proposed_patches) > 0


def test_dispatch_auditor_returns_report() -> None:
    from ouroboros.agents.recon import Checkout

    checkout = Checkout(root=Path("."), is_remote=False, commit_sha=None, cleanup=lambda: None)
    assert _dispatch_output(
        mode="auditor",
        fix=True,
        open_pr=True,
        checkout=checkout,
        patches=[],
        slug="o/n",
        token="t",
        github_client=None,
    ) == ("report", None)


def test_dispatch_owner_no_fix_returns_report() -> None:
    from ouroboros.agents.recon import Checkout

    checkout = Checkout(root=Path("."), is_remote=True, commit_sha=None, cleanup=lambda: None)
    assert _dispatch_output(
        mode="owner",
        fix=False,
        open_pr=False,
        checkout=checkout,
        patches=[],
        slug="o/n",
        token="t",
        github_client=None,
    ) == ("report", None)


def test_dispatch_owner_open_pr_opens_pull_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from ouroboros import remediation
    from ouroboros.agents.patch_generator import generate
    from ouroboros.agents.recon import Checkout
    from ouroboros.agents.static_analyzer import analyze
    from ouroboros.schemas.repo_profile import RepoProfile

    repo = tmp_path / "repo"
    subprocess.run(["cp", "-r", "tests/fixtures/vulnerable_agent", str(repo)], check=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
        cwd=repo,
        check=True,
    )
    monkeypatch.setattr(remediation, "_live_push", lambda *a, **k: None)  # no network

    profile = RepoProfile(source=str(repo), resolved_mode="owner")
    patches = generate(analyze(profile, root=repo), [], root=repo)
    checkout = Checkout(root=repo, is_remote=True, commit_sha=None, cleanup=lambda: None)

    action, ref = _dispatch_output(
        mode="owner",
        fix=True,
        open_pr=True,
        checkout=checkout,
        patches=patches,
        slug="o/n",
        token="tok",
        github_client=FakeGithub(push=True),
    )
    assert action == "pull_request"
    assert ref and ref.startswith("https://github.com/")


def test_dispatch_owner_open_pr_without_slug_raises() -> None:
    import subprocess
    import tempfile

    from ouroboros.agents.patch_generator import generate
    from ouroboros.agents.recon import Checkout
    from ouroboros.agents.static_analyzer import analyze
    from ouroboros.schemas.repo_profile import RepoProfile

    repo = Path(tempfile.mkdtemp()) / "repo"
    subprocess.run(["cp", "-r", "tests/fixtures/vulnerable_agent", str(repo)], check=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
        cwd=repo,
        check=True,
    )
    profile = RepoProfile(source=str(repo), resolved_mode="owner")
    patches = generate(analyze(profile, root=repo), [], root=repo)
    checkout = Checkout(root=repo, is_remote=True, commit_sha=None, cleanup=lambda: None)
    with pytest.raises(ScanError):
        _dispatch_output(
            mode="owner",
            fix=True,
            open_pr=True,
            checkout=checkout,
            patches=patches,
            slug=None,
            token=None,
            github_client=None,
        )
