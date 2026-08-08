"""Recon must understand a target from files alone — no model, no network."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import FakeGithub

from ouroboros.agents.recon import ReconError, profile

SIBLING = Path(__file__).resolve().parents[2] / "ai-soc-triage-agent"


def test_missing_path_raises() -> None:
    with pytest.raises(ReconError):
        profile("./definitely/not/here")


def test_profiles_the_vulnerable_fixture(vuln_agent: Path) -> None:
    prof = profile(str(vuln_agent))
    assert prof.language == "python"
    assert prof.framework == "anthropic-sdk"
    assert prof.resolved_mode == "auditor"
    # the messages.create call and the declared console script are both found
    kinds = {e.kind for e in prof.entry_points}
    assert "llm_call" in kinds
    assert "console_script" in kinds


def test_remote_slug_still_fails_safe_without_token(vuln_agent: Path) -> None:
    # A local path with a push-granting client still resolves auditor, because the
    # source is not a GitHub URL — recon never invents a remote.
    prof = profile(str(vuln_agent), github_client=FakeGithub(push=True))
    assert prof.resolved_mode == "auditor"


@pytest.mark.skipif(not SIBLING.exists(), reason="sibling repo not checked out")
def test_extracts_real_system_prompt_from_sibling() -> None:
    """Week-2 success criterion: pull the real prompt out of ai-soc-triage-agent."""
    prof = profile(str(SIBLING))
    fences = [p for p in prof.system_prompts if p.method == "text-fence"]
    assert fences, "expected a text-fence system prompt"
    assert any("SOC" in p.text or "triage" in p.text.lower() for p in fences)
