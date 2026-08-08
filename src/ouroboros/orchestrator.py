"""The Orchestrator: run the pipeline, decide the mode, assemble the report.

This is the one place that knows the whole flow. It resolves owner vs auditor,
runs recon, then the analyzers, then assembles an ``AuditReport`` and writes it
out. Every step speaks a Pydantic contract; the orchestrator never passes free
text between agents.

Scope note (weeks 1-5): recon, the static analyzer and the dynamic attacker are
real; the patch generator is a stub. Dynamic testing is opt-in (``attack=True``).
A ``--attack`` decides by mode: owner runs live against a real client
(``confirmed_live``); auditor runs the same payloads against an offline
``SimulatedTarget`` (``simulated``, reduced confidence), so a repo without write
access is still exercised without touching the real agent or needing a key.
Owner-mode auto-commit / PR arrives in week 7 — until then a run always
``report``s, even when write access exists, and says so. The auditor fail-safe is
enforced by ``AuditReport`` itself, so this module cannot accidentally over-reach.
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
from ouroboros.schemas.repo_profile import RepoProfile
from ouroboros.schemas.static_finding import StaticFinding
from ouroboros.simulation import SimulatedTarget


class ScanError(RuntimeError):
    """A scan could not proceed as asked (e.g. owner-mode --attack without a key)."""


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

    # 3. Dynamic attack (real, opt-in). `--attack` decides by mode: owner hits a
    #    real client (confirmed_live); auditor hits an offline SimulatedTarget
    #    (simulated). A plain scan sends nothing.
    dynamic_findings: list[DynamicFinding] = []
    dynamic_run: DynamicRunStats | None = None
    resolved = _resolve_attack_client(mode, attack, llm_client, profile, static_findings)
    if resolved is not None:
        client, confidence = resolved
        campaign = dynamic_attacker.run_campaign(
            profile,
            client=client,
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


def _resolve_attack_client(
    mode: Mode,
    attack: bool,
    llm_client: Any | None,
    profile: RepoProfile,
    static_findings: list[StaticFinding],
) -> tuple[Any, Literal["confirmed_live", "simulated"]] | None:
    """Pick the client and confidence for a dynamic run, or None if not attacking.

    Owner mode attacks a real client and needs one; auditor mode attacks an
    offline SimulatedTarget built from what recon and the static pass learned, so
    it never requires a key and never touches the real agent.
    """
    if not attack:
        return None
    if mode == "owner":
        if llm_client is None:
            raise ScanError("owner-mode --attack needs a live LLM client (set ANTHROPIC_API_KEY)")
        return llm_client, "confirmed_live"
    return SimulatedTarget.from_profile(profile, static_findings), "simulated"


def _stem(source: str) -> str:
    """A filesystem-safe stem derived from the target, for the output files."""
    name = source.rstrip("/").split("/")[-1] or "scan"
    return name.removesuffix(".git") or "scan"
