"""Compare two ``AuditReport`` snapshots to spot security regressions in CI."""

from __future__ import annotations

from pydantic import BaseModel, Field

from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.static_finding import StaticFinding


class FindingKey(BaseModel):
    """Canonical fingerprint used to match findings across two runs."""

    kind: str  # "static" | "dynamic"
    category: str
    severity: str
    location: str  # file:line or payload_id@prompt_ref


class ReportDiff(BaseModel):
    """Structured delta between a baseline (``before``) and a candidate (``after``) scan."""

    before_target: str
    after_target: str
    new_findings: list[FindingKey] = Field(default_factory=list)
    resolved_findings: list[FindingKey] = Field(default_factory=list)
    unchanged_count: int = 0
    asr_before: float | None = None
    asr_after: float | None = None
    asr_delta: float | None = None

    @property
    def has_regressions(self) -> bool:
        """True if new findings appeared or the dynamic ASR increased."""
        if self.new_findings:
            return True
        return self.asr_delta is not None and self.asr_delta > 0


def compare_reports(before: AuditReport, after: AuditReport) -> ReportDiff:
    """Compute new/resolved findings and ASR delta between ``before`` and ``after``."""
    before_keys = _fingerprints(before)
    after_keys = _fingerprints(after)

    before_set = set(before_keys)
    after_set = set(after_keys)

    new = [after_keys[k] for k in sorted(after_set - before_set)]
    resolved = [before_keys[k] for k in sorted(before_set - after_set)]
    unchanged = len(before_set & after_set)

    asr_before = before.dynamic_run.success_rate if before.dynamic_run else None
    asr_after = after.dynamic_run.success_rate if after.dynamic_run else None
    asr_delta = (
        round(asr_after - asr_before, 3)
        if asr_before is not None and asr_after is not None
        else None
    )

    return ReportDiff(
        before_target=before.repo.source,
        after_target=after.repo.source,
        new_findings=new,
        resolved_findings=resolved,
        unchanged_count=unchanged,
        asr_before=asr_before,
        asr_after=asr_after,
        asr_delta=asr_delta,
    )


def render_diff_markdown(diff: ReportDiff) -> str:
    """Render a concise Markdown summary of ``diff``."""
    lines = [
        "# Ouroboros Audit Diff",
        "",
        f"- **Before:** `{diff.before_target}`",
        f"- **After:** `{diff.after_target}`",
        f"- **New findings:** {len(diff.new_findings)}",
        f"- **Resolved findings:** {len(diff.resolved_findings)}",
        f"- **Unchanged:** {diff.unchanged_count}",
    ]
    if diff.asr_before is not None or diff.asr_after is not None:
        b = f"{diff.asr_before:.1%}" if diff.asr_before is not None else "—"
        a = f"{diff.asr_after:.1%}" if diff.asr_after is not None else "—"
        d = f"{diff.asr_delta:+.1%}" if diff.asr_delta is not None else "—"
        lines.append(f"- **Dynamic ASR:** {b} → {a} ({d})")
    if diff.new_findings:
        lines.extend(["", "## New findings"])
        for item in diff.new_findings:
            lines.append(f"- [{item.severity}] `{item.kind}:{item.category}` @ `{item.location}`")
    if diff.resolved_findings:
        lines.extend(["", "## Resolved findings"])
        for item in diff.resolved_findings:
            lines.append(f"- [{item.severity}] `{item.kind}:{item.category}` @ `{item.location}`")
    return "\n".join(lines).rstrip() + "\n"


def _fingerprints(report: AuditReport) -> dict[tuple[str, str, str], FindingKey]:
    out: dict[tuple[str, str, str], FindingKey] = {}
    for sf in report.static_findings:
        k, val = _static_key(sf)
        out[k] = val
    for df in report.dynamic_findings:
        k, val = _dynamic_key(df)
        out[k] = val
    return out


def _static_key(f: StaticFinding) -> tuple[tuple[str, str, str], FindingKey]:
    loc = f"{f.file_path}:{f.line or 0}"
    key = ("static", f.category, loc)
    return key, FindingKey(kind="static", category=f.category, severity=f.severity, location=loc)


def _dynamic_key(f: DynamicFinding) -> tuple[tuple[str, str, str], FindingKey]:
    loc = f"{f.payload_id}@{f.prompt_ref or '<default>'}"
    key = ("dynamic", f.category, loc)
    return key, FindingKey(kind="dynamic", category=f.category, severity=f.severity, location=loc)
