"""The Orchestrator: run the pipeline, decide the mode, assemble the report.

This is the one place that knows the whole flow. It resolves owner vs auditor,
runs recon, static analysis, optional dynamic attacks + patch verification,
generates guardrail patches, dispatches output by mode, and writes the report
artifacts (Markdown, JSON, and optionally SARIF 2.1.0).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ouroboros import remediation
from ouroboros.agents import dynamic_attacker, patch_generator, recon, static_analyzer
from ouroboros.reporting.markdown import write_report
from ouroboros.schemas.audit_report import AppliedAction, AuditReport
from ouroboros.schemas.common import Mode
from ouroboros.schemas.dynamic_finding import DynamicFinding, DynamicRunStats, PatchVerification
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
    packs: Sequence[str] | None = None,
    adaptive: bool = False,
    all_prompts: bool = True,
    model: str | None = None,
    enrich: bool = False,
    verify_patches: bool = False,
    sarif: bool = False,
    out_dir: Path | None = None,
) -> ScanResult:
    """Scan ``source`` end-to-end and return the assembled report.

    ``out_dir`` defaults to ``./out``. Markdown and JSON are always written;
    passing ``sarif=True`` also writes ``<stem>.sarif``.
    """
    checkout, decision = recon.acquire(
        source, requested_mode=requested_mode, token=token, github_client=github_client
    )
    try:
        # 1. Recon.
        profile = recon.profile_checkout(checkout, decision, source)
        if decision.default_branch:
            profile = profile.model_copy(update={"default_branch": decision.default_branch})
        mode = profile.resolved_mode

        # 2. Static analysis over the persistent checkout.
        static_findings = static_analyzer.analyze(
            profile, root=checkout.root, client=llm_client, enrich=enrich
        )

        # 3. Dynamic attack (opt-in). owner -> real client (confirmed_live);
        #    auditor -> offline SimulatedTarget (simulated).
        dynamic_findings: list[DynamicFinding] = []
        dynamic_run: DynamicRunStats | None = None
        resolved = _resolve_attack_client(mode, attack, llm_client, profile, static_findings)
        if resolved is not None:
            client, confidence = resolved
            campaign = dynamic_attacker.run_campaign(
                profile,
                client=client,
                confidence=confidence,
                model=model,
                max_payloads=max_payloads,
                min_interval_seconds=min_interval_seconds,
                packs=packs,
                adaptive=adaptive,
                all_prompts=all_prompts,
            )
            dynamic_findings = campaign.findings
            dynamic_run = campaign.stats()

        # 4. Patch generation: applicable guardrail diffs + prompt hardening.
        patches = patch_generator.generate(
            static_findings, dynamic_findings, root=checkout.root, profile=profile
        )

        # 4b. Optional verification: re-attack the hardened prompts to measure ASR drop.
        patch_verification: PatchVerification | None = None
        if verify_patches and resolved is not None and dynamic_run is not None:
            hardened = patch_generator.hardened_prompts_for_verification(
                profile, static_findings, dynamic_findings
            )
            if hardened:
                client, confidence = resolved
                verify_client = (
                    SimulatedTarget.from_profile(
                        profile.model_copy(update={"system_prompts": hardened}),
                        static_findings=[],
                    )
                    if confidence == "simulated"
                    else client
                )
                after_campaign = dynamic_attacker.run_campaign(
                    profile,
                    client=verify_client,
                    confidence=confidence,
                    model=model,
                    max_payloads=max_payloads,
                    min_interval_seconds=min_interval_seconds,
                    packs=packs,
                    adaptive=adaptive,
                    all_prompts=all_prompts,
                    prompt_override=hardened,
                )
                patch_verification = PatchVerification(
                    before=dynamic_run,
                    after=after_campaign.stats(),
                    patched_prompts=len(hardened),
                )

        # 5. Output by mode. Owner-mode side effects (apply/commit/push/PR) happen
        #    here; auditor is structurally limited to "report".
        applied_action, action_ref = _dispatch_output(
            mode=mode,
            fix=fix,
            open_pr=open_pr,
            checkout=checkout,
            patches=patches,
            slug=decision.slug,
            base_branch=profile.default_branch,
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
            patch_verification=patch_verification,
            applied_action=applied_action,
            action_ref=action_ref,
        ).with_summary()

        out = out_dir or Path("out")
        written = write_report(report, out, _stem(source), sarif=sarif)
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
    base_branch: str | None = None,
) -> tuple[AppliedAction, str | None]:
    """Decide what a run actually *did*, performing owner-mode side effects.

    Auditor mode (and any run without patches or without ``fix``) only reports.
    Owner mode with ``fix`` applies the patches and commits them on a collision-free
    branch; with ``open_pr`` it also pushes and opens a PR against the target's
    default branch.
    """
    if mode == "auditor" or not fix or not patches:
        return "report", None
    try:
        applied = remediation.apply_patches(checkout.root, patches)
        branch = remediation.unique_branch_name(checkout.root, remediation.DEFAULT_BRANCH)
        base = base_branch or remediation.detect_default_branch(
            checkout.root, remediation.DEFAULT_BASE
        )
        message = "ouroboros: reinforce prompt-injection guardrails\n\n" + "\n".join(
            f"- {ref}" for ref in applied
        )
        sha = remediation.commit_on_branch(checkout.root, branch, message)
        if not open_pr:
            return "commit", f"{branch}@{sha[:12]}"
        if slug is None or not token:
            raise ScanError("owner-mode --open-pr needs a GitHub remote and a GITHUB_TOKEN")
        url = remediation.open_pull_request(
            slug,
            root=checkout.root,
            branch=branch,
            base=base,
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
        "Review the prompt-hardening and advisory diffs before merging.",
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
            raise ScanError(
                "owner-mode --attack needs a live LLM client (set provider API key or --base-url)"
            )
        return llm_client, "confirmed_live"
    return SimulatedTarget.from_profile(profile, static_findings), "simulated"


def _stem(source: str) -> str:
    """A filesystem-safe stem derived from the target, for the output files."""
    # Split on both separators: a Windows path must not become the whole stem
    # (which would write the report next to the target instead of into out_dir).
    name = source.replace("\\", "/").rstrip("/").split("/")[-1].split(":")[-1] or "scan"
    return name.removesuffix(".git") or "scan"
