"""The Orchestrator: run the pipeline, decide the mode, assemble the report.

This is the one place that knows the whole flow. It resolves owner vs auditor,
runs recon, then the analyzers, then assembles an ``AuditReport`` and writes it
out. Every step speaks a Pydantic contract; the orchestrator never passes free
text between agents.

Scope note (weeks 1-3): recon and the static analyzer are real; the dynamic
attacker and patch generator are stubs returning empty results. Owner-mode
auto-commit / PR arrives in week 7 — until then a run always ``report``s, even
when write access exists, and says so. The auditor fail-safe is enforced by
``AuditReport`` itself, so this module cannot accidentally over-reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ouroboros.agents import dynamic_attacker, patch_generator, recon, static_analyzer
from ouroboros.reporting.markdown import write_report
from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.common import Mode


@dataclass
class ScanResult:
    """A completed scan: the report plus wherever it was written."""

    report: AuditReport
    written: list[Path]


def run(
    source: str,
    *,
    requested_mode: Mode | None = None,
    token: str | None = None,
    github_client: object | None = None,
    llm_client: Any | None = None,
    max_payloads: int = 20,
    out_dir: Path | None = None,
) -> ScanResult:
    """Scan ``source`` end-to-end and return the assembled report.

    ``out_dir`` defaults to ``./out``. The report is always written (Markdown +
    JSON); the return value carries both the model and the paths so a caller can
    print a summary without re-reading the files.
    """
    # 1. Recon also resolves the mode (it needs the decision to fill the profile).
    profile = recon.profile(
        source, requested_mode=requested_mode, token=token, github_client=github_client
    )
    mode = profile.resolved_mode

    # 2. Static analysis over recon's checkout (local-path targets read in place).
    static_root = None if profile.is_remote else Path(source).expanduser().resolve()
    static_findings = static_analyzer.analyze(profile, root=static_root, client=llm_client)

    # 3. Dynamic + patch: stubs today, real in weeks 4-6. Wired now so the shape
    #    of a full run is already correct.
    dynamic_findings = dynamic_attacker.attack(
        profile, client=llm_client, max_payloads=max_payloads
    )
    patches = patch_generator.generate(static_findings, dynamic_findings)

    # 4. Assemble. applied_action stays "report": owner-mode writing lands in
    #    week 7, and the auditor fail-safe in AuditReport forbids anything else.
    report = AuditReport(
        repo=profile,
        mode=mode,
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        proposed_patches=patches,
        applied_action="report",
    ).with_summary()

    if mode == "owner":
        report.repo.notes.append(
            "owner mode: write access confirmed, but auto-commit/PR is not enabled "
            "until week 7 — this run only reports."
        )

    out = out_dir or Path("out")
    written = write_report(report, out, _stem(source))
    return ScanResult(report=report, written=written)


def _stem(source: str) -> str:
    """A filesystem-safe stem derived from the target, for the output files."""
    name = source.rstrip("/").split("/")[-1] or "scan"
    return name.removesuffix(".git") or "scan"
