"""The week-6 criterion: an applicable diff for every week-3 finding category."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ouroboros.agents.patch_generator import generate
from ouroboros.schemas.common import FindingCategory
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
    return response
"""

_LINES = {
    "direct_interpolation": 5,
    "missing_delimiters": 6,
    "no_output_validation": 7,
    "no_instruction_hierarchy": 8,
    "untrusted_tool_output": 9,
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
    category: str, line: int, git_repo: Path
) -> None:
    patches = generate([_finding(category, line)], [], root=git_repo)  # type: ignore[list-item]
    assert len(patches) == 1
    check = subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=git_repo,
        input=patches[0].diff,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_overlapping_findings_are_deduped(git_repo: Path) -> None:
    # Two findings on the same line collapse to one patch (their inserts would clash).
    findings = [_finding("direct_interpolation", 5), _finding("missing_delimiters", 5)]
    assert len(generate(findings, [], root=git_repo)) == 1


def test_finding_without_line_is_skipped(git_repo: Path) -> None:
    f = _finding("direct_interpolation", 5).model_copy(update={"line": None})
    assert generate([f], [], root=git_repo) == []


def test_patch_carries_guardrail_type_and_rationale(git_repo: Path) -> None:
    patch = generate([_finding("no_output_validation", 7)], [], root=git_repo)[0]
    assert patch.guardrail_type == "output_validation"
    assert patch.rationale == "apply the guardrail"
    assert patch.diff.startswith("diff --git a/agent.py b/agent.py")
