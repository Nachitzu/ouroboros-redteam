"""Versioned payload packs loaded from JSONL files and validated against ATLAS/OWASP.

Built-in packs live under ``src/ouroboros/data/payloads/`` (overridable via
``OUROBOROS_DATA_DIR``). User-imported or custom packs are also discovered in
``~/.ouroboros/packs/``, ``$OUROBOROS_DATA_DIR/packs``, and ``$OUROBOROS_PACKS_DIR``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ouroboros.payloads.model import Payload
from ouroboros.schemas.common import PayloadFamily
from ouroboros.tools.atlas import verify_atlas_technique
from ouroboros.tools.owasp import verify_owasp_risk

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"


class PackInfo(BaseModel):
    """Metadata describing a single payload pack on disk."""

    name: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    version: str = "1.0.0"
    description: str = ""
    license: str = "MIT"
    sources: list[str] = Field(default_factory=list)
    count: int = 0
    families: list[PayloadFamily] = Field(default_factory=list)
    path: Path | None = None


class PayloadPack(BaseModel):
    """A validated payload pack paired with its metadata."""

    info: PackInfo
    payloads: tuple[Payload, ...]


def _builtin_packs_dir() -> Path:
    override = os.environ.get("OUROBOROS_DATA_DIR")
    if override:
        candidate = Path(override) / "payloads"
        if candidate.is_dir():
            return candidate
    return _DEFAULT_DATA_DIR / "payloads"


def user_packs_dir() -> Path:
    """Return the writable user directory for imported/custom payload packs."""
    packs_override = os.environ.get("OUROBOROS_PACKS_DIR")
    if packs_override:
        return Path(packs_override)
    data_override = os.environ.get("OUROBOROS_DATA_DIR")
    if data_override:
        return Path(data_override) / "packs"
    return Path.home() / ".ouroboros" / "packs"


def _pack_search_dirs() -> list[Path]:
    """Return ordered, deduplicated existing directories searched for packs."""
    candidates: list[Path] = [_builtin_packs_dir()]
    default_user = Path.home() / ".ouroboros" / "packs"
    candidates.append(default_user)
    data_override = os.environ.get("OUROBOROS_DATA_DIR")
    if data_override:
        candidates.append(Path(data_override) / "packs")
    packs_override = os.environ.get("OUROBOROS_PACKS_DIR")
    if packs_override:
        candidates.append(Path(packs_override))

    seen: set[Path] = set()
    dirs: list[Path] = []
    for cand in candidates:
        if not cand.is_dir():
            continue
        resolved = cand.resolve()
        if resolved not in seen:
            seen.add(resolved)
            dirs.append(cand)
    return dirs


def _discover_pack_files() -> dict[str, Path]:
    """Map pack name -> ``.jsonl`` path across all search directories."""
    found: dict[str, Path] = {}
    for directory in _pack_search_dirs():
        for jsonl_path in sorted(directory.glob("*.jsonl")):
            found[jsonl_path.stem] = jsonl_path
    return found


def _validate_payload_references(payload: Payload) -> None:
    if not payload.atlas_ids:
        raise ValueError(f"Payload {payload.id!r} must declare at least one ATLAS technique id")
    for tid in payload.atlas_ids:
        if verify_atlas_technique(tid) is None:
            raise ValueError(f"Payload {payload.id!r} references unknown ATLAS id {tid!r}")
    for oid in payload.owasp_ids:
        if verify_owasp_risk(oid) is None:
            raise ValueError(f"Payload {payload.id!r} references unknown OWASP id {oid!r}")


def _load_pack_from_path(jsonl_path: Path) -> PayloadPack:
    name = jsonl_path.stem
    meta_path = jsonl_path.with_suffix(".meta.json")
    meta_raw: dict[str, Any] = {}
    if meta_path.is_file():
        loaded = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"Expected JSON object in {meta_path}")
        meta_raw = loaded

    payloads: list[Payload] = []
    seen_ids: set[str] = set()
    for lineno, raw_line in enumerate(jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"{jsonl_path}:{lineno}: expected JSON object")
        record.setdefault("pack", name)
        payload = Payload.model_validate(record)
        if payload.id in seen_ids:
            raise ValueError(f"{jsonl_path}:{lineno}: duplicate payload id {payload.id!r}")
        seen_ids.add(payload.id)
        _validate_payload_references(payload)
        payloads.append(payload)

    families_present: list[PayloadFamily] = []
    seen_fam: set[PayloadFamily] = set()
    for p in payloads:
        if p.family not in seen_fam:
            seen_fam.add(p.family)
            families_present.append(p.family)

    info = PackInfo(
        name=str(meta_raw.get("name") or name),
        version=str(meta_raw.get("version") or "1.0.0"),
        description=str(meta_raw.get("description") or ""),
        license=str(meta_raw.get("license") or "MIT"),
        sources=[str(s) for s in (meta_raw.get("sources") or [])],
        count=len(payloads),
        families=families_present,
        path=jsonl_path,
    )
    return PayloadPack(info=info, payloads=tuple(payloads))


def load_pack(name: str) -> PayloadPack:
    """Load and validate a single named payload pack."""
    files = _discover_pack_files()
    jsonl_path = files.get(name)
    if jsonl_path is None:
        raise ValueError(f"Unknown payload pack: {name!r}")
    return _load_pack_from_path(jsonl_path)


def available_packs() -> list[PackInfo]:
    """Discover and return metadata for all available payload packs."""
    files = _discover_pack_files()
    ordered_names = sorted(files, key=lambda n: "" if n == "core" else n)
    return [_load_pack_from_path(files[name]).info for name in ordered_names]


def load_packs(names: Sequence[str] | None = None) -> tuple[Payload, ...]:
    """Load and validate one or more payload packs, enforcing unique payload ids.

    - ``None`` or empty sequence loads the default ``"core"`` pack.
    - Passing ``"all"`` in ``names`` loads every discovered pack.
    """
    if not names:
        target_names = ["core"]
    elif "all" in names:
        target_names = [info.name for info in available_packs()]
    else:
        target_names = list(dict.fromkeys(names))

    combined: list[Payload] = []
    seen_ids: set[str] = set()
    for name in target_names:
        pack = load_pack(name)
        for payload in pack.payloads:
            if payload.id in seen_ids:
                raise ValueError(
                    f"Duplicate payload id {payload.id!r} found while loading pack {name!r}"
                )
            seen_ids.add(payload.id)
            combined.append(payload)
    return tuple(combined)


def verify_all_packs() -> list[PackInfo]:
    """Validate every discovered pack and cross-pack payload id uniqueness."""
    infos = available_packs()
    load_packs(["all"])
    return infos
