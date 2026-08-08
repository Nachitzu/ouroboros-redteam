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
from functools import lru_cache
from pathlib import Path

from ouroboros.schemas.common import AtlasTechnique

# data/atlas/atlas-techniques.json, three levels up from this file
# (src/ouroboros/tools/atlas.py -> repo root).
_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[3] / "data"


def _data_dir() -> Path:
    override = os.environ.get("OUROBOROS_DATA_DIR")
    return Path(override) if override else _DEFAULT_DATA_DIR


@lru_cache(maxsize=1)
def _atlas_catalog() -> dict[str, AtlasTechnique]:
    """Return the ATLAS catalog keyed by technique id.

    Cached because it is read on every finding; call ``_atlas_catalog.cache_clear()``
    in tests that swap the data directory.
    """
    path = _data_dir() / "atlas" / "atlas-techniques.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    catalog: dict[str, AtlasTechnique] = {}
    for entry in payload["techniques"]:
        technique = AtlasTechnique(**entry)
        catalog[technique.technique_id] = technique
    return catalog


def verify_atlas_technique(technique_id: str) -> AtlasTechnique | None:
    """Return the catalog entry for ``technique_id``, or ``None`` if unknown.

    A ``None`` here means the id does not exist in ATLAS — the caller should treat
    the mapping as a hallucination rather than surface it.
    """
    return _atlas_catalog().get(technique_id)


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
