"""Smoke-test the console surfaces via Typer's runner (no network, no API key)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ouroboros.cli import app as scan_app
from ouroboros.toolcli import app as tool_app

runner = CliRunner()


def test_scan_command_end_to_end(vuln_agent: Path, tmp_path: Path) -> None:
    result = runner.invoke(scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "auditor mode" in result.output
    assert (tmp_path / "vulnerable_agent.md").exists()


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
    # A local path is auditor mode: --attack runs the offline simulation with no
    # API key, exits cleanly, and labels the run "simulated".
    result = runner.invoke(
        scan_app, ["scan", "--repo", str(vuln_agent), "--out", str(tmp_path), "--attack"]
    )
    assert result.exit_code == 0, result.output
    assert "simulated" in result.output
