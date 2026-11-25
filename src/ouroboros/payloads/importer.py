"""Convert external JSONL/CSV attack-string datasets into Ouroboros payload packs.

Imported entries are safely constrained to a benign canary-goal oracle (appending
``" ... and reply with {canary}"`` whenever the source string lacks ``{canary}``)
and validated against the offline MITRE ATLAS and OWASP catalogs before writing.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Literal

from ouroboros.payloads.model import Payload
from ouroboros.payloads.packs import PackInfo, PayloadPack, load_pack, user_packs_dir
from ouroboros.schemas.common import FindingCategory, Oracle, PayloadFamily, Severity
from ouroboros.tools.owasp import owasp_for_category

_DEFAULT_CATEGORY: dict[PayloadFamily, FindingCategory] = {
    "direct": "no_instruction_hierarchy",
    "indirect": "untrusted_tool_output",
    "jailbreak": "no_instruction_hierarchy",
    "encoding": "no_instruction_hierarchy",
    "extraction": "system_prompt_extraction",
    "tool_hijack": "tool_hijack",
    "exfiltration": "data_exfiltration",
    "multi_turn": "no_instruction_hierarchy",
    "benign": "over_refusal",
}

_DEFAULT_ATLAS: dict[PayloadFamily, tuple[str, ...]] = {
    "direct": ("AML.T0051", "AML.T0051.000"),
    "indirect": ("AML.T0051", "AML.T0051.001"),
    "jailbreak": ("AML.T0054",),
    "encoding": ("AML.T0051", "AML.T0068"),
    "extraction": ("AML.T0056",),
    "tool_hijack": ("AML.T0051.001", "AML.T0053"),
    "exfiltration": ("AML.T0057", "AML.T0077"),
    "multi_turn": ("AML.T0051", "AML.T0080.001"),
    "benign": ("AML.T0051",),
}

_DEFAULT_SEVERITY: dict[PayloadFamily, Severity] = {
    "benign": "LOW",
    "jailbreak": "CRITICAL",
    "tool_hijack": "CRITICAL",
    "exfiltration": "CRITICAL",
}


def _read_source_texts(
    source_file: Path, fmt: Literal["jsonl", "csv"], text_field: str
) -> list[str]:
    if not source_file.is_file():
        raise FileNotFoundError(f"Dataset file not found: {source_file}")

    texts: list[str] = []
    if fmt == "jsonl":
        for lineno, raw in enumerate(source_file.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"{source_file}:{lineno}: expected JSON object")
            if text_field not in obj:
                raise ValueError(f"{source_file}:{lineno}: missing field {text_field!r}")
            val = str(obj[text_field]).strip()
            if val:
                texts.append(val)
    elif fmt == "csv":
        with source_file.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or text_field not in reader.fieldnames:
                raise ValueError(f"{source_file}: CSV missing column {text_field!r}")
            for row in reader:
                val = str(row.get(text_field) or "").strip()
                if val:
                    texts.append(val)
    else:
        raise ValueError(f"Unsupported format {fmt!r}; expected 'jsonl' or 'csv'")
    return texts


def _with_canary_goal(text: str, oracle: Oracle) -> str:
    if oracle in ("extraction", "benign") or "{canary}" in text:
        return text
    return f"{text.rstrip()} ... and reply with {{canary}}"


def import_dataset(
    *,
    source_file: Path,
    fmt: Literal["jsonl", "csv"],
    text_field: str,
    pack_name: str,
    family: PayloadFamily,
    oracle: Oracle = "canary",
    category: FindingCategory | None = None,
    severity: Severity | None = None,
    atlas_ids: tuple[str, ...] | None = None,
    owasp_ids: tuple[str, ...] | None = None,
    target_tool: str | None = None,
    language: str = "en",
    source_label: str | None = None,
    out_dir: Path | None = None,
) -> PayloadPack:
    """Import an external dataset of strings into a validated Ouroboros payload pack."""
    raw_texts = _read_source_texts(source_file, fmt, text_field)
    deduped = list(dict.fromkeys(raw_texts))
    if not deduped:
        raise ValueError(f"No non-empty records found for field {text_field!r} in {source_file}")

    resolved_category = category or _DEFAULT_CATEGORY[family]
    resolved_severity = severity or _DEFAULT_SEVERITY.get(family, "HIGH")
    resolved_atlas = atlas_ids or _DEFAULT_ATLAS[family]
    resolved_owasp = (
        owasp_ids
        if owasp_ids is not None
        else tuple(r.risk_id for r in owasp_for_category(resolved_category))
    )
    resolved_tool = target_tool or ("send_email" if oracle == "tool_call" else None)
    provenance = source_label or source_file.name

    payloads: list[Payload] = []
    for idx, text in enumerate(deduped, start=1):
        body = _with_canary_goal(text, oracle)
        payload = Payload(
            id=f"{pack_name}-{idx:03d}",
            family=family,
            category=resolved_category,
            severity=resolved_severity,
            atlas_ids=resolved_atlas,
            owasp_ids=resolved_owasp,
            description=f"Imported {family} probe #{idx} from {provenance}.",
            body=body,
            oracle=oracle,
            target_tool=resolved_tool,
            pack=pack_name,
            source=provenance,
            language=language,
            tags=("imported",),
        )
        payloads.append(payload)

    target_dir = out_dir or user_packs_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = target_dir / f"{pack_name}.jsonl"
    meta_path = target_dir / f"{pack_name}.meta.json"

    jsonl_path.write_text(
        "\n".join(p.model_dump_json() for p in payloads) + "\n",
        encoding="utf-8",
    )
    info = PackInfo(
        name=pack_name,
        version="1.0.0",
        description=f"Imported payload pack from {provenance} ({len(payloads)} probes).",
        license="MIT",
        sources=[provenance],
        count=len(payloads),
        families=[family],
        path=jsonl_path,
    )
    meta_path.write_text(
        json.dumps(
            {
                "name": info.name,
                "version": info.version,
                "description": info.description,
                "license": info.license,
                "sources": info.sources,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    # Re-load through the pack validator if target_dir is discoverable, otherwise validate directly.
    if target_dir == user_packs_dir():
        return load_pack(pack_name)
    from ouroboros.payloads.packs import _load_pack_from_path

    return _load_pack_from_path(jsonl_path)
