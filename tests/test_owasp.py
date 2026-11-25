"""Tests for the offline OWASP GenAI (LLM Top 10 2025 + Agentic Top 10) catalog."""

from __future__ import annotations

from typing import get_args

from ouroboros.schemas.common import FindingCategory
from ouroboros.tools.atlas import verify_atlas_technique
from ouroboros.tools.owasp import (
    all_owasp_risks,
    atlas_for_owasp,
    cwe_for_category,
    owasp_for_atlas,
    owasp_for_category,
    owasp_for_ids,
    search_owasp,
    verify_owasp_risk,
)


def test_all_twenty_owasp_risks_present() -> None:
    risks = all_owasp_risks()
    ids = {r.risk_id for r in risks}
    expected_llm = {f"LLM{i:02d}:2025" for i in range(1, 11)}
    expected_asi = {f"ASI{i:02d}:2026" for i in range(1, 11)}
    assert expected_llm <= ids
    assert expected_asi <= ids


def test_verify_known_and_unknown() -> None:
    llm01 = verify_owasp_risk("LLM01:2025")
    assert llm01 is not None
    assert llm01.name == "Prompt Injection"

    asi01 = verify_owasp_risk("ASI01:2026")
    assert asi01 is not None
    assert asi01.name == "Agent Goal Hijack"

    assert verify_owasp_risk("LLM99:2025") is None


def test_category_mappings_cover_every_finding_category() -> None:
    for cat in get_args(FindingCategory):
        risks = owasp_for_category(cat)
        cwes = cwe_for_category(cat)
        if cat == "over_refusal":
            assert risks == []
            assert cwes == []
        else:
            assert risks, f"Expected OWASP mapping for {cat}"
            assert cwes, f"Expected CWE mapping for {cat}"

    assert [r.risk_id for r in owasp_for_category("untrusted_tool_output")] == [
        "LLM01:2025",
        "ASI01:2026",
    ]
    assert [r.risk_id for r in owasp_for_category("excessive_agency")] == [
        "LLM06:2025",
        "ASI02:2026",
        "ASI03:2026",
    ]
    assert [r.risk_id for r in owasp_for_category("mcp_tool_poisoning")] == [
        "LLM01:2025",
        "LLM03:2025",
        "ASI04:2026",
    ]
    assert "CWE-1427" in cwe_for_category("direct_interpolation")
    assert "CWE-94" in cwe_for_category("improper_output_handling")


def test_owasp_for_ids_and_search() -> None:
    resolved = owasp_for_ids(["LLM01:2025", "UNKNOWN:2025", "LLM01:2025", "ASI02:2026"])
    assert [r.risk_id for r in resolved] == ["LLM01:2025", "ASI02:2026"]

    matches = search_owasp("excessive agency")
    assert any(r.risk_id == "LLM06:2025" for r in matches)
    assert search_owasp("   ") == []


def test_atlas_owasp_crosswalk() -> None:
    mapped = owasp_for_atlas("AML.T0051.001")
    assert {r.risk_id for r in mapped} >= {"LLM01:2025", "ASI01:2026"}
    tids = atlas_for_owasp("LLM07:2025")
    assert "AML.T0056" in tids
    for tid in tids:
        assert verify_atlas_technique(tid) is not None
