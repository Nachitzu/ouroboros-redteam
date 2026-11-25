"""Smoke-test the console surfaces via Typer's runner (no network, no API key)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ouroboros.cli import app as scan_app
from ouroboros.toolcli import app as tool_app

runner = CliRunner()


def test_scan_command_end_to_end(vuln_agent: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--sarif"]
    )
    assert result.exit_code == 0, result.output
    assert "auditor mode" in result.output
    assert (tmp_path / "vulnerable_agent.md").exists()
    assert (tmp_path / "vulnerable_agent.json").exists()
    assert (tmp_path / "vulnerable_agent.sarif").exists()


def test_version_command() -> None:
    result = runner.invoke(scan_app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip()


def test_atlas_verify_known() -> None:
    result = runner.invoke(tool_app, ["atlas", "verify", "AML.T0051"])
    assert result.exit_code == 0
    assert "LLM Prompt Injection" in result.output


def test_atlas_verify_unknown_exits_nonzero() -> None:
    result = runner.invoke(tool_app, ["atlas", "verify", "AML.T9999"])
    assert result.exit_code == 1


def test_atlas_search() -> None:
    result = runner.invoke(tool_app, ["atlas", "search", "injection"])
    assert result.exit_code == 0
    assert "AML.T0051" in result.output


def test_attack_on_local_target_simulates_offline(vuln_agent: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        scan_app,
        [
            "scan",
            "--repo",
            str(vuln_agent),
            "--out",
            str(tmp_path),
            "--attack",
            "--pack",
            "core,soc-blueteam",
            "--max-payloads",
            "5",
            "--min-interval",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "simulated" in result.output


def test_fail_on_and_fail_on_asr_exit_3(vuln_agent: Path, tmp_path: Path) -> None:
    res = runner.invoke(
        scan_app,
        ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--fail-on", "HIGH"],
    )
    assert res.exit_code == 3
    assert "--fail-on HIGH" in res.output

    res_asr = runner.invoke(
        scan_app,
        [
            "scan",
            "--repo",
            str(vuln_agent),
            "--out",
            str(tmp_path),
            "--attack",
            "--max-payloads",
            "4",
            "--min-interval",
            "0",
            "--fail-on-asr",
            "0.1",
        ],
    )
    assert res_asr.exit_code == 3
    assert "--fail-on-asr" in res_asr.output


def test_invalid_provider_and_fail_on_exit_2(vuln_agent: Path, tmp_path: Path) -> None:
    r1 = runner.invoke(
        scan_app,
        ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--provider", "bogus"],
    )
    assert r1.exit_code == 2
    r2 = runner.invoke(
        scan_app,
        ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--fail-on", "BOGUS"],
    )
    assert r2.exit_code == 2


def test_fix_on_local_target_still_reports(vuln_agent: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--fix"]
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "vulnerable_agent.md").exists()


def test_open_pr_without_token_errors(vuln_agent: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--open-pr"]
    )
    assert result.exit_code == 2
    assert "GITHUB_TOKEN" in result.output


def test_diff_command_clean_and_regression(vuln_agent: Path, tmp_path: Path) -> None:
    out_vuln = tmp_path / "v"
    out_hard = tmp_path / "h"
    runner.invoke(scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(out_vuln)])
    runner.invoke(
        scan_app, ["scan", "--repo", "tests/fixtures/hardened_agent", "--out", str(out_hard)]
    )

    v_json = out_vuln / "vulnerable_agent.json"
    h_json = out_hard / "hardened_agent.json"

    # vulnerable -> hardened has only resolved findings (no regression)
    ok = runner.invoke(scan_app, ["diff", str(v_json), str(h_json), "--fail-on-regression"])
    assert ok.exit_code == 0, ok.output

    # hardened -> vulnerable introduces regressions (exit 3)
    reg = runner.invoke(scan_app, ["diff", str(h_json), str(v_json), "--fail-on-regression"])
    assert reg.exit_code == 3
