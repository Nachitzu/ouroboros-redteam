"""The Orchestrator: run the pipeline, decide the mode, assemble the report.

This is the one place that knows the whole flow. It resolves owner vs auditor,
runs recon, then the analyzers, then assembles an ``AuditReport`` and writes it
out. Every step speaks a Pydantic contract; the orchestrator never passes free
text between agents.

Scope note (weeks 1-7): every agent is real. The checkout is acquired once and
held open across recon -> static -> dynamic -> patch, then cleaned up. Output
splits by mode: auditor hands over a report with suggested diffs; owner (with
``fix``/``open_pr``) applies the patches, commits on a branch, and opens a PR.
The auditor fail-safe is enforced by ``AuditReport`` itself, so this module
cannot accidentally over-reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ouroboros import remediation
from ouroboros.agents import dynamic_attacker, patch_generator, recon, static_analyzer
from ouroboros.reporting.markdown import write_report
from ouroboros.schemas.audit_report import AppliedAction, AuditReport
from ouroboros.schemas.common import Mode
from ouroboros.schemas.dynamic_finding import DynamicFinding, DynamicRunStats
from ouroboros.schemas.proposed_patch import ProposedPatch
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
    fix: bool = False,
    open_pr: bool = False,
    max_payloads: int = 20,
    min_interval_seconds: float = 1.0,
    out_dir: Path | None = None,
) -> ScanResult:
    """Scan ``source`` end-to-end and return the assembled report.

    ``out_dir`` defaults to ``./out``. The report is always written (Markdown +
    JSON); the return value carries both the model and the paths so a caller can
    print a summary without re-reading the files.
    """
    # Acquire the checkout once and hold it open across the whole run; clean it up
    # at the end. This is what lets static analysis, patch generation and owner-mode
    # remediation all operate on the same files, even for a cloned remote repo.
    checkout, decision = recon.acquire(
        source, requested_mode=requested_mode, token=token, github_client=github_client
    )
    try:
        # 1. Recon.
        profile = recon.profile_checkout(checkout, decision, source)
        mode = profile.resolved_mode

        # 2. Static analysis over the persistent checkout.
        static_findings = static_analyzer.analyze(profile, root=checkout.root, client=llm_client)

        # 3. Dynamic attack (real, opt-in). owner -> real client (confirmed_live);
        #    auditor -> offline SimulatedTarget (simulated). A plain scan sends nothing.
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

        # 4. Patch generation (real): applicable guardrail diffs, always produced so
        #    the report can carry them as suggestions.
        patches = patch_generator.generate(static_findings, dynamic_findings, root=checkout.root)

        # 5. Output by mode. Owner-mode side effects (apply/commit/push/PR) happen
        #    here; auditor is structurally limited to "report".
        applied_action, action_ref = _dispatch_output(
            mode=mode,
            fix=fix,
            open_pr=open_pr,
            checkout=checkout,
            patches=patches,
            slug=decision.slug,
            token=token,
            github_client=github_client,
        )

        # 6. Assemble and write.
        report = AuditReport(
            repo=profile,
            mode=mode,
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            dynamic_run=dynamic_run,
            proposed_patches=patches,
            applied_action=applied_action,
            action_ref=action_ref,
        ).with_summary()

        out = out_dir or Path("out")
        written = write_report(report, out, _stem(source))
        return ScanResult(report=report, written=written)
    finally:
        checkout.cleanup()


def _dispatch_output(
    *,
    mode: Mode,
    fix: bool,
    open_pr: bool,
    checkout: recon.Checkout,
    patches: list[ProposedPatch],
    slug: str | None,
    token: str | None,
    github_client: Any | None,
) -> tuple[AppliedAction, str | None]:
    """Decide what a run actually *did*, performing owner-mode side effects.

    Auditor mode (and any run without patches or without ``fix``) only reports.
    Owner mode with ``fix`` applies the patches and commits them on a branch;
    with ``open_pr`` it also pushes and opens a PR. Any remediation failure becomes
    a ``ScanError`` so the CLI can report it cleanly.
    """
    if mode == "auditor" or not fix or not patches:
        return "report", None
    try:
        applied = remediation.apply_patches(checkout.root, patches)
        message = "ouroboros: reinforce prompt-injection guardrails\n\n" + "\n".join(
            f"- {ref}" for ref in applied
        )
        sha = remediation.commit_on_branch(checkout.root, remediation.DEFAULT_BRANCH, message)
        if not open_pr:
            return "commit", f"{remediation.DEFAULT_BRANCH}@{sha[:12]}"
        if slug is None or not token:
            raise ScanError("owner-mode --open-pr needs a GitHub remote and a GITHUB_TOKEN")
        url = remediation.open_pull_request(
            slug,
            root=checkout.root,
            branch=remediation.DEFAULT_BRANCH,
            base=remediation.DEFAULT_BASE,
            title="Ouroboros: reinforce prompt-injection guardrails",
            body=_pr_body(applied),
            token=token,
            github_client=github_client,
        )
        return "pull_request", url
    except remediation.RemediationError as exc:
        raise ScanError(str(exc)) from exc


def _pr_body(applied: list[str]) -> str:
    lines = [
        "Automated guardrail proposals from **Ouroboros Red Team** (prompt-injection audit).",
        "",
        "Reinforced guardrails for:",
        *[f"- `{ref}`" for ref in applied],
        "",
        "Each change is an advisory guardrail comment; review before merging.",
    ]
    return "\n".join(lines)


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
