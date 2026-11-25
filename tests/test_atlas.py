"""ATLAS lookups and YAML sync back the anti-hallucination guarantee."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.sync_atlas import main as sync_cli_main

from ouroboros.tools.atlas import (
    all_techniques,
    atlas_mitigations_for,
    clear_atlas_cache,
    search_atlas_techniques,
    sync_atlas_from_yaml,
    verify_atlas_technique,
)

REQUIRED_ATLAS_IDS = {
    "AML.T0051",
    "AML.T0051.000",
    "AML.T0051.001",
    "AML.T0053",
    "AML.T0054",
    "AML.T0055",
    "AML.T0056",
    "AML.T0057",
    "AML.T0048",
    "AML.T0077",
    "AML.T0068",
    "AML.T0065",
    "AML.T0061",
    "AML.T0062",
    "AML.T0066",
    "AML.T0067",
    "AML.T0069",
    "AML.T0069.000",
    "AML.T0069.001",
    "AML.T0070",
    "AML.T0071",
    "AML.T0050",
    "AML.T0086",
    "AML.T0080",
    "AML.T0080.000",
    "AML.T0080.001",
    "AML.T0024",
    "AML.T0040",
    "AML.T0043",
    "AML.T0010",
    "AML.T0018",
    "AML.T0020",
    "AML.T0029",
    "AML.T0034",
    "AML.T0049",
    "AML.T0052",
}


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


def test_catalog_is_expanded_and_includes_required_ids() -> None:
    techniques = all_techniques()
    assert len(techniques) >= 50
    present = {t.technique_id for t in techniques}
    missing = REQUIRED_ATLAS_IDS - present
    assert not missing, f"Missing required ATLAS ids: {missing}"


def test_mitigations_for_technique_and_subtechnique() -> None:
    mits = atlas_mitigations_for("AML.T0051")
    mit_ids = {m["mitigation_id"] for m in mits}
    assert "AML.M0015" in mit_ids
    assert "AML.M0020" in mit_ids
    sub_mits = atlas_mitigations_for("AML.T0051.001")
    assert sub_mits


def test_data_dir_override_filters_extra_json_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    atlas_dir = tmp_path / "atlas"
    atlas_dir.mkdir()
    (atlas_dir / "atlas-techniques.json").write_text(
        json.dumps(
            {
                "techniques": [
                    {
                        "technique_id": "AML.T0051",
                        "name": "LLM Prompt Injection",
                        "tactic": "initial-access",
                        "description": "extra description ignored by schema",
                        "unknown_field": 123,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OUROBOROS_DATA_DIR", str(tmp_path))
    clear_atlas_cache()
    try:
        tech = verify_atlas_technique("AML.T0051")
        assert tech is not None
        assert tech.name == "LLM Prompt Injection"
    finally:
        monkeypatch.delenv("OUROBOROS_DATA_DIR", raising=False)
        clear_atlas_cache()


def test_sync_atlas_from_synthetic_yaml(tmp_path: Path) -> None:
    dist_dir = tmp_path / "atlas-data" / "dist"
    dist_dir.mkdir(parents=True)
    yaml_file = dist_dir / "ATLAS.yaml"
    yaml_file.write_text(
        """\
id: ATLAS
name: MITRE ATLAS
version: "9.9.0"
tactics:
  - id: AML.TA0004
    name: Initial Access
  - id: AML.TA0005
    name: Execution
techniques:
  - id: AML.T0051
    name: LLM Prompt Injection
    tactics:
      - AML.TA0004
    description: Prompt injection description.
  - id: AML.T0051.000
    name: Direct Prompt Injection
    subtechnique-of: AML.T0051
  - id: AML.T0053
    name: LLM Plugin Compromise
    tactics:
      - AML.TA0005
mitigations:
  - id: AML.M0020
    name: Generative AI Guardrails
    description: Runtime guardrails.
    techniques:
      - id: AML.T0051
      - AML.T0053
""",
        encoding="utf-8",
    )
    out_dir = tmp_path / "compiled"
    tech_count, mit_count = sync_atlas_from_yaml(tmp_path / "atlas-data", out_dir=out_dir)
    assert tech_count == 3
    assert mit_count == 1

    tech_json = json.loads((out_dir / "atlas-techniques.json").read_text(encoding="utf-8"))
    mit_json = json.loads((out_dir / "atlas-mitigations.json").read_text(encoding="utf-8"))
    assert tech_json["_meta"]["atlas_version"] == "9.9.0"
    by_id = {t["technique_id"]: t for t in tech_json["techniques"]}
    assert by_id["AML.T0051"]["tactic"] == "initial-access"
    assert by_id["AML.T0051.000"]["tactic"] == "initial-access"
    assert by_id["AML.T0053"]["tactic"] == "execution"
    assert by_id["AML.T0053"]["mitigations"] == ["AML.M0020"]
    assert mit_json["mitigations"][0]["techniques"] == ["AML.T0051", "AML.T0053"]

    # Also verify CLI wrapper entry point works cleanly.
    out_dir2 = tmp_path / "compiled2"
    assert sync_cli_main(["--from", str(yaml_file), "--out", str(out_dir2)]) == 0
    assert (out_dir2 / "atlas-techniques.json").is_file()
