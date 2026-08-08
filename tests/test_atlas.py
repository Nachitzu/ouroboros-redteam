"""ATLAS lookups back the anti-hallucination guarantee; verify known/unknown ids."""

from __future__ import annotations

from ouroboros.tools.atlas import search_atlas_techniques, verify_atlas_technique


def test_known_id_verifies() -> None:
    technique = verify_atlas_technique("AML.T0051")
    assert technique is not None
    assert technique.name == "LLM Prompt Injection"


def test_unknown_id_returns_none() -> None:
    assert verify_atlas_technique("AML.T9999") is None


def test_search_matches_name_and_id() -> None:
    ids = {t.technique_id for t in search_atlas_techniques("injection")}
    assert "AML.T0051" in ids


def test_empty_search_is_empty() -> None:
    assert search_atlas_techniques("   ") == []
