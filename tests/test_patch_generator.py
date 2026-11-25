"""Applicable diffs for every static category, multi-hunk files, and prompt hardening."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ouroboros.agents.patch_generator import generate, harden_prompt_text
from ouroboros.schemas.common import FindingCategory
from ouroboros.schemas.repo_profile import ExtractedPrompt, RepoProfile
from ouroboros.schemas.static_finding import StaticFinding

# A small module with a distinct line per category, so each patch anchors cleanly.
_TARGET = """\
import anthropic


def run(client, user_input, tool_output):
    system = f"You are helpful. {user_input}"
    prompt = f"summarize: {user_input}"
    response = client.messages.create(model="m", max_tokens=1, system=system, messages=[])
    hierarchy = "no precedence stated"
    merged = f"tool says: {tool_output}"
    eval(response.content[0].text)
    subprocess.run(tool_output, shell=True)
    # poisoned tool description
    secret = "sk-1234567890"
    return response
"""

_LINES: dict[FindingCategory, int] = {
    "direct_interpolation": 5,
    "missing_delimiters": 6,
    "no_output_validation": 7,
    "no_instruction_hierarchy": 8,
    "untrusted_tool_output": 9,
    "improper_output_handling": 10,
    "excessive_agency": 11,
    "mcp_tool_poisoning": 12,
    "prompt_leakage_risk": 13,
}


def _finding(category: FindingCategory, line: int) -> StaticFinding:
    return StaticFinding(
        category=category,
        severity="HIGH",
        file_path="agent.py",
        line=line,
        evidence="x",
        explanation="y",
        recommendation="apply the guardrail",
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    (tmp_path / "agent.py").write_text(_TARGET, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    return tmp_path


@pytest.mark.parametrize("category,line", list(_LINES.items()))
def test_each_category_produces_a_git_appliable_diff(
    category: FindingCategory, line: int, git_repo: Path
) -> None:
    patches = generate([_finding(category, line)], [], root=git_repo)
    assert len(patches) == 1
    check = subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=git_repo,
        input=patches[0].diff,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_multiple_findings_in_same_file_merge_into_one_appliable_diff(git_repo: Path) -> None:
    findings = [_finding("direct_interpolation", 5), _finding("improper_output_handling", 10)]
    patches = generate(findings, [], root=git_repo)
    assert len(patches) == 1
    assert len(patches[0].finding_refs) == 2
    subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=git_repo,
        input=patches[0].diff,
        text=True,
        check=True,
    )


def test_overlapping_findings_are_deduped(git_repo: Path) -> None:
    # Two findings on the same line collapse to one patch (their inserts would clash).
    findings = [_finding("direct_interpolation", 5), _finding("missing_delimiters", 5)]
    patches = generate(findings, [], root=git_repo)
    assert len(patches) == 1
    assert len(patches[0].finding_refs) == 1


def test_finding_without_line_is_skipped(git_repo: Path) -> None:
    f = _finding("direct_interpolation", 5).model_copy(update={"line": None})
    assert generate([f], [], root=git_repo) == []


def test_patch_carries_guardrail_type_and_rationale(git_repo: Path) -> None:
    patch = generate([_finding("no_output_validation", 7)], [], root=git_repo)[0]
    assert patch.guardrail_type == "output_validation"
    assert patch.rationale == "apply the guardrail"
    assert patch.diff.startswith("diff --git a/agent.py b/agent.py")


def test_prompt_hardening_rewrites_markdown_prompt_cleanly(tmp_path: Path) -> None:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    prompt_text = "You are a SOC triage assistant. Summarize incoming security alerts."
    (prompts_dir / "system.md").write_text(
        f"# Prompt\n\n```text\n{prompt_text}\n```\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    profile = RepoProfile(
        source=str(tmp_path),
        resolved_mode="auditor",
        system_prompts=[
            ExtractedPrompt(file_path="prompts/system.md", method="text-fence", text=prompt_text)
        ],
    )
    static = [
        StaticFinding(
            category="no_instruction_hierarchy",
            severity="MEDIUM",
            file_path="prompts/system.md",
            line=1,
            evidence=prompt_text,
            explanation="Missing hierarchy",
            recommendation="Add hierarchy",
        )
    ]
    patches = generate(static, [], root=tmp_path, profile=profile)
    assert len(patches) == 1
    assert patches[0].kind == "prompt_hardening"
    subprocess.run(
        ["git", "apply", "-"], cwd=tmp_path, input=patches[0].diff, text=True, check=True
    )
    updated = (prompts_dir / "system.md").read_text(encoding="utf-8")
    assert "<data>" in updated
    assert "Never reveal" in updated


def test_harden_prompt_text_respects_spanish_and_is_idempotent() -> None:
    es = "Eres un asistente de soporte técnico. Responde las consultas del usuario."
    hardened = harden_prompt_text(es, include_tool_rule=True)
    assert "etiquetas <data>" in hardened
    assert "Nunca reveles" in hardened
    assert "Solo usa herramientas" in hardened
    assert harden_prompt_text(hardened, include_tool_rule=True) == hardened
