"""Render an ``AuditReport`` to Markdown and JSON.

The report is the auditor mode's whole deliverable, so it has to be readable on
its own. Two rules shape it: findings are grouped and counted so severity is
visible at a glance, and every finding's confidence is shown explicitly —
"static" from reading code, "simulated" from a mocked attack, "confirmed live"
from a real one — so nobody mistakes a code smell for a proven exploit.
"""

from __future__ import annotations

import json
from pathlib import Path

from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.static_finding import StaticFinding

_CONFIDENCE_LABEL = {
    "static": "static (found by reading code)",
    "simulated": "simulated (mocked attack — reduced confidence)",
    "confirmed_live": "confirmed live (real agent)",
}


def render_markdown(report: AuditReport) -> str:
    """Return the full Markdown body for a report."""
    r = report
    lines: list[str] = []
    lines.append("# Ouroboros Red Team — Audit Report")
    lines.append("")
    lines.append(f"- **Target:** `{r.repo.source}`")
    lines.append(f"- **Mode:** {r.mode}")
    lines.append(f"- **Action taken:** {r.applied_action}")
    lines.append(f"- **Generated:** {r.generated_at.isoformat()}")
    if r.repo.commit_sha:
        lines.append(f"- **Commit:** `{r.repo.commit_sha[:12]}`")
    if r.repo.language or r.repo.framework:
        lines.append(f"- **Stack:** {r.repo.language or '?'} / {r.repo.framework or '?'}")
    lines.append("")
    for note in r.repo.notes:
        lines.append(f"> {note}")
    if r.repo.notes:
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    s = r.summary
    lines.append(
        f"- Total findings: **{s.total_findings}** "
        f"(static {s.static_count}, dynamic {s.dynamic_count})"
    )
    if s.by_severity:
        by_sev = ", ".join(f"{k} {v}" for k, v in _ordered_severity(s.by_severity))
        lines.append(f"- By severity: {by_sev}")
    if s.by_category:
        by_cat = ", ".join(f"{k} {v}" for k, v in sorted(s.by_category.items()))
        lines.append(f"- By category: {by_cat}")
    lines.append(f"- Proposed patches: {s.patch_count}")
    if r.dynamic_run is not None:
        dr = r.dynamic_run
        lines.append(
            f"- Dynamic testing: {dr.successes}/{dr.attempts} payloads landed "
            f"({dr.success_rate:.0%}) — confidence {dr.confidence}, "
            f"families {', '.join(dr.families) or '—'}"
        )
    lines.append("")

    lines.append("## Static findings")
    lines.append("")
    if r.static_findings:
        for i, sf in enumerate(r.static_findings, 1):
            lines.extend(_static_block(i, sf))
    else:
        lines.append("_None._")
        lines.append("")

    lines.append("## Dynamic findings")
    lines.append("")
    if r.dynamic_findings:
        for i, df in enumerate(r.dynamic_findings, 1):
            lines.extend(_dynamic_block(i, df))
    else:
        lines.append("_No dynamic testing was performed in this run (pass `--attack`)._")
        lines.append("")

    lines.append("## Proposed patches")
    lines.append("")
    if r.proposed_patches:
        for p in r.proposed_patches:
            lines.append(f"### {p.title}")
            lines.append(f"- Guardrail: {p.guardrail_type}")
            lines.append(f"- Answers: {p.finding_ref}")
            lines.append("")
            lines.append("```diff")
            lines.append(p.diff)
            lines.append("```")
            lines.append("")
    else:
        lines.append("_None generated in this run._")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _static_block(i: int, f: StaticFinding) -> list[str]:
    atlas = ", ".join(a.technique_id for a in f.atlas) or "—"
    return [
        f"### {i}. `{f.category}` — {f.severity}",
        f"- Location: `{f.file_path}:{f.line if f.line is not None else '?'}`",
        f"- Confidence: {_CONFIDENCE_LABEL.get(f.confidence, f.confidence)}",
        f"- MITRE ATLAS: {atlas}",
        "",
        f"{f.explanation}",
        "",
        "```",
        f.evidence,
        "```",
        "",
        f"**Fix:** {f.recommendation}",
        "",
    ]


def _dynamic_block(i: int, f: DynamicFinding) -> list[str]:
    atlas = ", ".join(a.technique_id for a in f.atlas) or "—"
    return [
        f"### {i}. `{f.category}` — {f.severity} ({'HIT' if f.success else 'no effect'})",
        f"- Family: {f.family}",
        f"- Confidence: {_CONFIDENCE_LABEL.get(f.confidence, f.confidence)}",
        f"- Payload `{f.payload_id}`: `{f.payload}`",
        f"- MITRE ATLAS: {atlas}",
        "",
        f"Observed: {f.observed_behavior}",
        "",
    ]


def _ordered_severity(by_severity: dict[str, int]) -> list[tuple[str, int]]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(by_severity.items(), key=lambda kv: order.get(kv[0], 99))


def write_report(report: AuditReport, out_dir: Path, stem: str) -> list[Path]:
    """Write ``<stem>.md`` and ``<stem>.json`` into ``out_dir``; return the paths.

    JSON is the model dump (round-trippable back into ``AuditReport``); Markdown is
    the human view. Both are written so a run serves an automated consumer and a
    reader from the same command.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return [md_path, json_path]
