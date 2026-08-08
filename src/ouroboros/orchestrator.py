"""The Orchestrator: run the pipeline, decide the mode, assemble the report.

This is the one place that knows the whole flow. It resolves owner vs auditor,
runs recon, then the analyzers, then assembles an ``AuditReport`` and writes it
out. Every step speaks a Pydantic contract; the orchestrator never passes free
text between agents.

Scope note (weeks 1-4): recon, the static analyzer and the dynamic attacker are
real; the patch generator is a stub. Dynamic testing is opt-in (``attack=True``
with a client) so a plain scan stays offline and free. Owner-mode auto-commit /
PR arrives in week 7 — until then a run always ``report``s, even when write
access exists, and says so. The auditor fail-safe is enforced by ``AuditReport``
itself, so this module cannot accidentally over-reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ouroboros.agents import dynamic_attacker, patch_generator, recon, static_analyzer
from ouroboros.reporting.markdown import write_report
from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.common import Mode
from ouroboros.schemas.dynamic_finding import DynamicFinding, DynamicRunStats


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
    attack: bool = False,
    max_payloads: int = 20,
    min_interval_seconds: float = 1.0,
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

    # 3. Dynamic attack (real, opt-in). Only runs when the caller both asks for
    #    it and provides a client, so a plain scan never sends a payload. The
    #    confidence label follows the mode: a real model in owner mode is
    #    confirmed-live; anything else is simulated.
    dynamic_findings: list[DynamicFinding] = []
    dynamic_run: DynamicRunStats | None = None
    if attack and llm_client is not None:
        confidence: Literal["confirmed_live", "simulated"] = (
            "confirmed_live" if mode == "owner" else "simulated"
        )
        campaign = dynamic_attacker.run_campaign(
            profile,
            client=llm_client,
            confidence=confidence,
            max_payloads=max_payloads,
            min_interval_seconds=min_interval_seconds,
        )
        dynamic_findings = campaign.findings
        dynamic_run = campaign.stats()

    # 4. Patch generation: stub until week 6.
    patches = patch_generator.generate(static_findings, dynamic_findings)

    # 5. Assemble. applied_action stays "report": owner-mode writing lands in
    #    week 7, and the auditor fail-safe in AuditReport forbids anything else.
    report = AuditReport(
        repo=profile,
        mode=mode,
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        dynamic_run=dynamic_run,
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
