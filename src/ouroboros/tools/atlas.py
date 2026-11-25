"""The MITRE ATLAS catalog, loaded once and queried offline.

Ouroboros maps every finding to ATLAS the way its sibling projects map to
ATT&CK. A model — or a careless detector — can invent a plausible-looking
technique id, so the id a finding carries is verified against this local catalog
before it is trusted. The catalog is a bundled JSON file, cached with
``lru_cache`` and overridable via ``OUROBOROS_DATA_DIR`` so tests can point at a
fixture without monkeypatching the loader.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from ouroboros.schemas.common import AtlasTechnique

# Bundled inside the package (src/ouroboros/data/) so a wheel install ships it.
_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _data_dir() -> Path:
    override = os.environ.get("OUROBOROS_DATA_DIR")
    return Path(override) if override else _DEFAULT_DATA_DIR


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


@lru_cache(maxsize=1)
def _atlas_catalog() -> dict[str, AtlasTechnique]:
    """Return the ATLAS catalog keyed by technique id.

    Cached because it is read on every finding; call ``_atlas_catalog.cache_clear()``
    in tests that swap the data directory.
    """
    path = _data_dir() / "atlas" / "atlas-techniques.json"
    payload = _load_json(path)
    catalog: dict[str, AtlasTechnique] = {}
    for entry in payload["techniques"]:
        # Filter unknown JSON keys (e.g. description, mitigations) so AtlasTechnique stays minimal.
        technique = AtlasTechnique(
            technique_id=entry["technique_id"],
            name=entry["name"],
            tactic=entry["tactic"],
        )
        catalog[technique.technique_id] = technique
    return catalog


@lru_cache(maxsize=4)
def _atlas_raw_for_dir(data_dir_str: str) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Load technique->mitigations links and mitigations list for ``data_dir_str``."""
    data_dir = Path(data_dir_str)
    tech_path = data_dir / "atlas" / "atlas-techniques.json"
    tech_mit_ids: dict[str, list[str]] = {}
    if tech_path.exists():
        tech_payload = _load_json(tech_path)
        for entry in tech_payload.get("techniques", []):
            tid = entry.get("technique_id")
            mids = entry.get("mitigations") or []
            if isinstance(tid, str) and isinstance(mids, list):
                tech_mit_ids[tid] = [str(m) for m in mids]

    mit_path = data_dir / "atlas" / "atlas-mitigations.json"
    if not mit_path.exists() and data_dir != _DEFAULT_DATA_DIR:
        mit_path = _DEFAULT_DATA_DIR / "atlas" / "atlas-mitigations.json"
    mitigations: list[dict[str, Any]] = []
    if mit_path.exists():
        mit_payload = _load_json(mit_path)
        mitigations = [m for m in mit_payload.get("mitigations", []) if isinstance(m, dict)]
    return tech_mit_ids, mitigations


def clear_atlas_cache() -> None:
    """Clear both technique and mitigation caches (useful after OUROBOROS_DATA_DIR swaps)."""
    _atlas_catalog.cache_clear()
    _atlas_raw_for_dir.cache_clear()


def verify_atlas_technique(technique_id: str) -> AtlasTechnique | None:
    """Return the catalog entry for ``technique_id``, or ``None`` if unknown.

    A ``None`` here means the id does not exist in ATLAS — the caller should treat
    the mapping as a hallucination rather than surface it.
    """
    return _atlas_catalog().get(technique_id)


def all_techniques() -> list[AtlasTechnique]:
    """Return every MITRE ATLAS technique in the offline catalog."""
    return list(_atlas_catalog().values())


def search_atlas_techniques(query: str) -> list[AtlasTechnique]:
    """Return catalog entries whose id, name or tactic contains ``query``.

    Case-insensitive substring match — enough for the CLI helper and for a
    detector that knows a weakness by name but not by id.
    """
    needle = query.strip().lower()
    if not needle:
        return []
    return [
        technique
        for technique in _atlas_catalog().values()
        if needle in technique.technique_id.lower()
        or needle in technique.name.lower()
        or needle in technique.tactic.lower()
    ]


def atlas_mitigations_for(technique_id: str) -> list[dict[str, Any]]:
    """Return MITRE ATLAS mitigation dicts applicable to ``technique_id``.

    Matches both direct technique references in ``atlas-mitigations.json`` and
    optional ``mitigations`` ids listed on the technique entry itself, falling
    back to the parent technique id (e.g. ``AML.T0051`` for ``AML.T0051.000``)
    when no direct match exists.
    """
    tech_mit_ids, mitigations = _atlas_raw_for_dir(str(_data_dir()))
    by_id = {m["mitigation_id"]: m for m in mitigations if "mitigation_id" in m}

    def _collect(tid: str) -> list[dict[str, Any]]:
        seen: set[str] = set()
        results: list[dict[str, Any]] = []
        for mid in tech_mit_ids.get(tid, ()):
            if mid in by_id and mid not in seen:
                seen.add(mid)
                results.append(dict(by_id[mid]))
        for mitigation in mitigations:
            mid = mitigation.get("mitigation_id", "")
            if mid in seen:
                continue
            if tid in (mitigation.get("techniques") or ()):
                seen.add(mid)
                results.append(dict(mitigation))
        return results

    direct = _collect(technique_id)
    if direct:
        return direct
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        return _collect(parent)
    return []


def _slug_tactic(raw: str) -> str:
    return raw.strip().lower().replace("_", "-").replace(" ", "-")


def compile_atlas_dict(data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile a parsed ``ATLAS.yaml`` mapping into Ouroboros JSON payloads."""
    version = str(data.get("version") or "unknown")
    generated = datetime.now(UTC).strftime("%Y-%m-%d")

    tactic_map: dict[str, str] = {}
    for tac in data.get("tactics") or []:
        if isinstance(tac, dict) and tac.get("id") and tac.get("name"):
            tactic_map[str(tac["id"])] = _slug_tactic(str(tac["name"]))

    raw_techniques = [t for t in (data.get("techniques") or []) if isinstance(t, dict)]
    raw_by_id = {str(t["id"]): t for t in raw_techniques if t.get("id")}

    # First collect mitigation -> techniques links so we can attach them both ways.
    mitigation_entries: list[dict[str, Any]] = []
    tech_to_mits: dict[str, list[str]] = {}
    for mit in data.get("mitigations") or []:
        if not isinstance(mit, dict) or not mit.get("id") or not mit.get("name"):
            continue
        mid = str(mit["id"])
        linked_techs: list[str] = []
        for ref in mit.get("techniques") or []:
            tid = str(ref["id"]) if isinstance(ref, dict) and ref.get("id") else str(ref)
            if tid:
                linked_techs.append(tid)
                tech_to_mits.setdefault(tid, [])
                if mid not in tech_to_mits[tid]:
                    tech_to_mits[tid].append(mid)
        entry: dict[str, Any] = {
            "mitigation_id": mid,
            "name": str(mit["name"]).strip(),
            "description": str(mit.get("description") or "").strip(),
            "techniques": linked_techs,
        }
        mitigation_entries.append(entry)

    technique_entries: list[dict[str, Any]] = []
    for tech in raw_techniques:
        tid = str(tech.get("id") or "").strip()
        name = str(tech.get("name") or "").strip()
        if not tid or not name:
            continue
        tactics = tech.get("tactics") or []
        if not tactics and tech.get("subtechnique-of"):
            parent = raw_by_id.get(str(tech["subtechnique-of"]))
            if parent:
                tactics = parent.get("tactics") or []
        first_tactic = str(tactics[0]) if tactics else "unknown"
        tactic_name = tactic_map.get(first_tactic, _slug_tactic(first_tactic))

        mids = list(tech_to_mits.get(tid, []))
        for mref in tech.get("mitigations") or []:
            mid = str(mref["id"]) if isinstance(mref, dict) and mref.get("id") else str(mref)
            if mid and mid not in mids:
                mids.append(mid)

        t_entry: dict[str, Any] = {
            "technique_id": tid,
            "name": name,
            "tactic": tactic_name,
        }
        desc = str(tech.get("description") or "").strip()
        if desc:
            t_entry["description"] = desc
        if mids:
            t_entry["mitigations"] = mids
        technique_entries.append(t_entry)

    meta = {
        "atlas_version": version,
        "generated": generated,
        "note": "Compiled from upstream ATLAS YAML data.",
    }
    techniques_doc = {"_meta": meta, "techniques": technique_entries}
    mitigations_doc = {"_meta": meta, "mitigations": mitigation_entries}
    return techniques_doc, mitigations_doc


def _resolve_atlas_yaml(source: Path) -> Path:
    if source.is_dir():
        for candidate in (source / "ATLAS.yaml", source / "dist" / "ATLAS.yaml"):
            if candidate.is_file():
                return candidate
        raise FileNotFoundError(f"No ATLAS.yaml or dist/ATLAS.yaml found in {source}")
    if not source.is_file():
        raise FileNotFoundError(f"ATLAS YAML file not found: {source}")
    return source


def sync_atlas_from_yaml(source: Path, out_dir: Path | None = None) -> tuple[int, int]:
    """Compile ``ATLAS.yaml`` (or a directory containing it) into the JSON catalogs.

    Imports ``yaml`` lazily so PyYAML remains an optional dependency at runtime.
    Returns ``(technique_count, mitigation_count)``.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to sync ATLAS.yaml (install with `pip install pyyaml`)."
        ) from exc

    yaml_path = _resolve_atlas_yaml(source)
    parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected YAML mapping at root of {yaml_path}")

    techniques_doc, mitigations_doc = compile_atlas_dict(parsed)
    target_dir = out_dir or (_data_dir() / "atlas")
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "atlas-techniques.json").write_text(
        json.dumps(techniques_doc, indent=2) + "\n", encoding="utf-8"
    )
    (target_dir / "atlas-mitigations.json").write_text(
        json.dumps(mitigations_doc, indent=2) + "\n", encoding="utf-8"
    )
    clear_atlas_cache()
    return len(techniques_doc["techniques"]), len(mitigations_doc["mitigations"])
