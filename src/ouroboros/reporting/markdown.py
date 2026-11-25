"""Render an ``AuditReport`` to Markdown, JSON, and optionally SARIF 2.1.0.

The report is the auditor mode's whole deliverable, so it has to be readable on
its own. Findings are grouped and counted so severity, ATLAS, and OWASP exposure
are visible at a glance, and dynamic findings are split by confidence into a
"confirmed live" group and a "simulated" group with a standing caveat, so nobody
mistakes a mocked hit for a proven exploit.
"""

from __future__ import annotations

import json
from pathlib import Path

from ouroboros.reporting.sarif import write_sarif
from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.common import SEVERITY_ORDER
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.static_finding import StaticFinding

_CONFIDENCE_LABEL = {
    "static": "static (found by reading code)",
    "simulated": "simulated (mocked attack — reduced confidence)",
    "confirmed_live": "confirmed live (real agent)",
}

_CONFIDENCE_BADGE = {
    "confirmed_live": "🔴 LIVE",
    "simulated": "🟡 SIM",
}

_SIMULATED_CAVEAT = (
    "> ⚠️ **Simulated** — produced against a mocked target, not a live agent. "
    "Treat these as leads to verify, not confirmed exploits."
)


def render_markdown(report: AuditReport) -> str:
    """Return the full Markdown body for a report."""
    r = report
    lines: list[str] = []
    lines.append("# Ouroboros Red Team — Audit Report")
    lines.append("")
    lines.append(f"- **Target:** `{r.repo.source}`")
    lines.append(f"- **Mode:** {r.mode}")
    action_line = f"- **Action taken:** {r.applied_action}"
    if r.action_ref:
        action_line += f" → {r.action_ref}"
    lines.append(action_line)
    lines.append(f"- **Generated:** {r.generated_at.isoformat()}")
    if r.repo.commit_sha:
        lines.append(f"- **Commit:** `{r.repo.commit_sha[:12]}`")
    if r.repo.language or r.repo.frameworks or r.repo.framework:
        fws = ", ".join(r.repo.frameworks) if r.repo.frameworks else (r.repo.framework or "?")
        lines.append(f"- **Stack:** {r.repo.language or '?'} / {fws}")
    if r.repo.system_prompts:
        lines.append(f"- **Recovered prompts:** {len(r.repo.system_prompts)}")
    if r.repo.tools:
        lines.append(f"- **Extracted tools:** {len(r.repo.tools)}")
    lines.append("")
    for note in r.repo.notes:
        lines.append(f"> {note}")
    if r.repo.notes:
        lines.append("")

    if r.repo.tools:
        lines.append("## Tool surface")
        lines.append("")
        for tool in r.repo.tools:
            caps = ", ".join(tool.capabilities) or "none"
            gate = "confirmed" if tool.requires_confirmation else "no confirmation"
            lines.append(
                f"- `{tool.name}` (`{tool.file_path}:{tool.line or '?'}` — {tool.source}): "
                f"capabilities [{caps}], {gate}"
            )
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
    if s.by_owasp:
        by_owasp = ", ".join(f"{k} {v}" for k, v in sorted(s.by_owasp.items()))
        lines.append(f"- By OWASP: {by_owasp}")
    lines.append(f"- Proposed patches: {s.patch_count}")
    if r.dynamic_run is not None:
        dr = r.dynamic_run
        provider_info = (
            f" [{dr.provider}{f'/{dr.model}' if dr.model else ''}]" if dr.provider else ""
        )
        lines.append(
            f"- Dynamic testing{provider_info}: {dr.successes}/{dr.attempts} payloads landed "
            f"({dr.success_rate:.0%}) — confidence {dr.confidence}, "
            f"packs {', '.join(dr.packs) or 'core'}, "
            f"families {', '.join(dr.families) or '—'}"
        )
        if dr.benign_attempts:
            lines.append(
                f"- Benign controls: {dr.over_refusals}/{dr.benign_attempts} over-refusals"
            )
        if dr.adaptive_mutations:
            lines.append(f"- Adaptive mutations tried: {dr.adaptive_mutations}")
        if dr.input_tokens or dr.output_tokens:
            lines.append(f"- Token usage: {dr.input_tokens} in / {dr.output_tokens} out")
    if r.patch_verification is not None:
        pv = r.patch_verification
        lines.append(
            f"- Patch verification: ASR {pv.before.success_rate:.0%} → "
            f"{pv.after.success_rate:.0%} ({pv.asr_delta:+.1%}) across "
            f"{pv.patched_prompts} hardened prompt(s)"
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
        lines.extend(_dynamic_section(r.dynamic_findings))
    else:
        lines.append(
            "_No dynamic testing was performed in this run "
            "(pass `--attack`: live in owner mode, simulated in auditor mode)._"
        )
        lines.append("")

    lines.append("## Proposed patches")
    lines.append("")
    if r.proposed_patches:
        for p in r.proposed_patches:
            lines.append(f"### {p.title}")
            lines.append(f"- Kind: `{p.kind}` · Guardrail: {p.guardrail_type}")
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
    owasp = ", ".join(o.risk_id for o in f.owasp) or "—"
    cwe = ", ".join(f.cwe) or "—"
    enriched_tag = " *(LLM-enriched)*" if f.enriched else ""
    return [
        f"### {i}. `{f.category}` — {f.severity}{enriched_tag}",
        f"- Location: `{f.file_path}:{f.line if f.line is not None else '?'}`",
        f"- Confidence: {_CONFIDENCE_LABEL.get(f.confidence, f.confidence)}",
        f"- MITRE ATLAS: {atlas} | OWASP: {owasp} | CWE: {cwe}",
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


def _dynamic_section(findings: list[DynamicFinding]) -> list[str]:
    """Render dynamic findings split into confirmed-live and simulated groups."""
    live = [f for f in findings if f.confidence == "confirmed_live"]
    simulated = [f for f in findings if f.confidence == "simulated"]
    lines: list[str] = []
    if live:
        lines.append("### 🔴 Confirmed-live findings")
        lines.append("")
        for i, f in enumerate(live, 1):
            lines.extend(_dynamic_block(i, f))
    if simulated:
        lines.append("### 🟡 Simulated findings (reduced confidence)")
        lines.append("")
        lines.append(_SIMULATED_CAVEAT)
        lines.append("")
        for i, f in enumerate(simulated, 1):
            lines.extend(_dynamic_block(i, f))
    return lines


def _dynamic_block(i: int, f: DynamicFinding) -> list[str]:
    atlas = ", ".join(a.technique_id for a in f.atlas) or "—"
    owasp = ", ".join(o.risk_id for o in f.owasp) or "—"
    badge = _CONFIDENCE_BADGE.get(f.confidence, f.confidence)
    meta = f"pack `{f.pack}`, oracle `{f.oracle}`, turns {f.turns}"
    if f.mutation:
        meta += f", mutation `{f.mutation}`"
    if f.prompt_ref:
        meta += f", target `{f.prompt_ref}`"
    return [
        f"#### {i}. {badge} — `{f.category}` — {f.severity} "
        f"({'HIT' if f.success else 'no effect'})",
        f"- Family: {f.family} ({meta})",
        f"- Confidence: {_CONFIDENCE_LABEL.get(f.confidence, f.confidence)}",
        f"- Payload `{f.payload_id}`: `{f.payload}`",
        f"- MITRE ATLAS: {atlas} | OWASP: {owasp}",
        "",
        f"Observed: {f.observed_behavior}",
        "",
    ]


def _ordered_severity(by_severity: dict[str, int]) -> list[tuple[str, int]]:
    return sorted(by_severity.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))


def write_report(
    report: AuditReport, out_dir: Path, stem: str, *, sarif: bool = False
) -> list[Path]:
    """Write ``<stem>.md``, ``<stem>.json``, and optionally ``<stem>.sarif``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{stem}.md"
    json_path = out_dir / f"{stem}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    written = [md_path, json_path]
    if sarif:
        written.append(write_sarif(report, out_dir, stem))
    return written
