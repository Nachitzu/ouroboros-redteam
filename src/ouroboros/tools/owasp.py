"""The OWASP GenAI catalog, loaded once and queried offline.

Provides verified lookups for OWASP Top 10 for LLM Applications 2025
(``LLM01:2025``..``LLM10:2025``) and OWASP Top 10 for Agentic Applications
(``ASI01:2026``..``ASI10:2026``), plus deterministic mappings from Ouroboros
``FindingCategory`` to OWASP risks and CWE identifiers, and an ATLAS<->OWASP
cross-walk.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

from ouroboros.schemas.common import FindingCategory, OwaspRisk

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _data_dir() -> Path:
    override = os.environ.get("OUROBOROS_DATA_DIR")
    return Path(override) if override else _DEFAULT_DATA_DIR


@lru_cache(maxsize=1)
def _owasp_payload() -> dict[str, Any]:
    path = _data_dir() / "owasp" / "owasp-genai.json"
    if not path.exists() and _data_dir() != _DEFAULT_DATA_DIR:
        path = _DEFAULT_DATA_DIR / "owasp" / "owasp-genai.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


@lru_cache(maxsize=1)
def _owasp_catalog() -> dict[str, OwaspRisk]:
    payload = _owasp_payload()
    catalog: dict[str, OwaspRisk] = {}
    for entry in payload["risks"]:
        risk = OwaspRisk(risk_id=entry["risk_id"], name=entry["name"])
        catalog[risk.risk_id] = risk
    return catalog


def clear_owasp_cache() -> None:
    """Clear cached OWASP catalog data (useful in tests swapping OUROBOROS_DATA_DIR)."""
    _owasp_payload.cache_clear()
    _owasp_catalog.cache_clear()


def verify_owasp_risk(risk_id: str) -> OwaspRisk | None:
    """Return the catalog entry for ``risk_id``, or ``None`` if unknown."""
    return _owasp_catalog().get(risk_id)


def all_owasp_risks() -> list[OwaspRisk]:
    """Return every OWASP LLM / Agentic risk in the offline catalog."""
    return list(_owasp_catalog().values())


def owasp_for_ids(ids: Iterable[str]) -> list[OwaspRisk]:
    """Resolve an iterable of OWASP risk ids to verified ``OwaspRisk`` objects."""
    catalog = _owasp_catalog()
    resolved: list[OwaspRisk] = []
    seen: set[str] = set()
    for risk_id in ids:
        if risk_id in seen:
            continue
        risk = catalog.get(risk_id)
        if risk is not None:
            seen.add(risk_id)
            resolved.append(risk)
    return resolved


def owasp_for_category(cat: FindingCategory) -> list[OwaspRisk]:
    """Return the verified ``OwaspRisk`` list mapped to ``cat``."""
    mapping: dict[str, list[str]] = _owasp_payload().get("category_to_owasp", {})
    return owasp_for_ids(mapping.get(cat, ()))


def cwe_for_category(cat: FindingCategory) -> list[str]:
    """Return the CWE identifiers mapped to ``cat``."""
    mapping: dict[str, list[str]] = _owasp_payload().get("category_to_cwe", {})
    return list(mapping.get(cat, ()))


def owasp_for_atlas(technique_id: str) -> list[OwaspRisk]:
    """Return OWASP risks cross-walked from an ATLAS ``technique_id``."""
    crosswalk: dict[str, list[str]] = _owasp_payload().get("atlas_to_owasp", {})
    ids = crosswalk.get(technique_id)
    if not ids and "." in technique_id:
        ids = crosswalk.get(technique_id.split(".", 1)[0], [])
    return owasp_for_ids(ids or ())


def atlas_for_owasp(risk_id: str) -> list[str]:
    """Return ATLAS technique ids cross-walked to ``risk_id``."""
    crosswalk: dict[str, list[str]] = _owasp_payload().get("atlas_to_owasp", {})
    return [tid for tid, rids in crosswalk.items() if risk_id in rids]


def search_owasp(query: str) -> list[OwaspRisk]:
    """Return catalog risks whose id, name, framework, or description matches ``query``."""
    needle = query.strip().lower()
    if not needle:
        return []
    catalog = _owasp_catalog()
    matches: list[OwaspRisk] = []
    for entry in _owasp_payload().get("risks", ()):
        risk_id = str(entry.get("risk_id", ""))
        name = str(entry.get("name", ""))
        framework = str(entry.get("framework", ""))
        description = str(entry.get("description", ""))
        if (
            needle in risk_id.lower()
            or needle in name.lower()
            or needle in framework.lower()
            or needle in description.lower()
        ):
            risk = catalog.get(risk_id)
            if risk is not None:
                matches.append(risk)
    return matches
