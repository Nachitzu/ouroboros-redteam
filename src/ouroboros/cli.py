"""The ``ouroboros`` command line interface.

Thin shell around :mod:`ouroboros.orchestrator` and :mod:`ouroboros.reporting`:
parse flags, load a ``.env`` if present, construct provider clients only when
needed, run the scan or diff, and enforce optional CI exit gates.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from ouroboros import __version__
from ouroboros.agents.recon import ReconError
from ouroboros.orchestrator import ScanError, run
from ouroboros.providers import ProviderError, build_client
from ouroboros.reporting.diff import compare_reports, render_diff_markdown
from ouroboros.schemas.audit_report import AuditReport
from ouroboros.schemas.common import SEVERITY_ORDER
from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.static_finding import StaticFinding

app = typer.Typer(
    name="ouroboros",
    help="Red-team LLM agents for prompt injection: audit, attack, verify, and patch.",
    no_args_is_help=True,
    add_completion=False,
)

_PROVIDER_KEY_ENV = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}


def _err(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _ok(message: str) -> None:
    typer.secho(message, fg=typer.colors.GREEN, err=True)


def _load_dotenv() -> None:
    """Pull API keys / tokens from a local .env if one exists."""
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return
    load_dotenv(find_dotenv(usecwd=True), override=False)


def _has_provider_credentials(provider: str, base_url: str | None) -> bool:
    if provider == "openai" and base_url:
        # Local OpenAI-compatible servers (Ollama, vLLM) often need no real key.
        return True
    keys = _PROVIDER_KEY_ENV.get(provider, ())
    return any(bool(os.environ.get(k)) for k in keys)


def _build_llm_client(provider: str = "anthropic", *, base_url: str | None = None) -> object:
    """Build a provider client at the CLI edge."""
    return build_client(provider=provider, base_url=base_url)


def _build_github_client(token: str | None) -> object:
    """Build a PyGithub client for opening a PR. Only called when --open-pr is set."""
    from github import Github

    return Github(token)


def _parse_packs(packs: list[str] | None) -> list[str] | None:
    if not packs:
        return None
    out: list[str] = []
    for item in packs:
        for part in item.split(","):
            name = part.strip()
            if name and name not in out:
                out.append(name)
    return out or None


def _check_ci_gates(
    report: AuditReport, *, fail_on: str | None, fail_on_asr: float | None
) -> str | None:
    if fail_on is not None:
        threshold = SEVERITY_ORDER[fail_on]
        all_findings: list[StaticFinding | DynamicFinding] = [
            *report.static_findings,
            *report.dynamic_findings,
        ]
        hits = [
            f"{f.category} ({f.severity})"
            for f in all_findings
            if SEVERITY_ORDER.get(f.severity, 99) <= threshold
        ]
        if hits:
            return f"--fail-on {fail_on}: {len(hits)} finding(s) at or above {fail_on}"
    if (
        fail_on_asr is not None
        and report.dynamic_run is not None
        and report.dynamic_run.success_rate >= fail_on_asr
    ):
        return (
            f"--fail-on-asr {fail_on_asr:.0%}: "
            f"ASR {report.dynamic_run.success_rate:.1%} meets/exceeds threshold"
        )
    return None


@app.callback()
def main() -> None:
    """Load local configuration before any command runs."""
    _load_dotenv()


@app.command()
def version() -> None:
    """Print the Ouroboros version."""
    typer.echo(__version__)


@app.command()
def scan(
    repo: Annotated[
        str, typer.Option("--repo", "-r", help="Target: a local path or a GitHub URL.")
    ],
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Force 'auditor' for a read-only run. Never grants owner."),
    ] = None,
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory.")] = Path("out"),
    attack: Annotated[
        bool,
        typer.Option(
            "--attack/--no-attack",
            help=(
                "Run a dynamic prompt-injection campaign — live in owner mode, "
                "simulated against an offline mock in auditor mode."
            ),
        ),
    ] = False,
    pack: Annotated[
        list[str] | None,
        typer.Option(
            "--pack",
            help="Payload pack(s) to run (comma-separated or repeated; e.g. core,soc-blueteam).",
        ),
    ] = None,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive/--no-adaptive",
            help="Retry failed attacks with deterministic encoding/framing mutations.",
        ),
    ] = False,
    all_prompts: Annotated[
        bool,
        typer.Option(
            "--all-prompts/--first-prompt",
            help="Attack every recovered system prompt rather than only the first.",
        ),
    ] = True,
    max_payloads: Annotated[
        int, typer.Option("--max-payloads", help="Cap on payloads sent per prompt.")
    ] = 20,
    min_interval: Annotated[
        float,
        typer.Option("--min-interval", help="Minimum seconds between attack requests."),
    ] = 1.0,
    provider: Annotated[
        str,
        typer.Option("--provider", help="LLM provider for live runs: anthropic, openai, gemini."),
    ] = "anthropic",
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Custom OpenAI-compatible base URL (Ollama/vLLM/etc.)."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Override target model id (defaults to OUROBOROS_MODEL)."),
    ] = None,
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich/--no-enrich",
            help="Enrich static findings with LLM prose (requires provider credentials).",
        ),
    ] = False,
    verify_patches: Annotated[
        bool,
        typer.Option(
            "--verify-patches/--no-verify-patches",
            help="Re-run the dynamic campaign against hardened prompts to measure ASR drop.",
        ),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option("--sarif/--no-sarif", help="Also emit <target>.sarif (SARIF 2.1.0)."),
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="CI gate: exit 3 if any finding >= threshold (CRITICAL|HIGH|MEDIUM|LOW).",
        ),
    ] = None,
    fail_on_asr: Annotated[
        float | None,
        typer.Option(
            "--fail-on-asr",
            help="CI gate: exit 3 if dynamic ASR >= threshold (e.g. 0.2).",
        ),
    ] = None,
    fix: Annotated[
        bool,
        typer.Option(
            "--fix/--no-fix",
            help="Owner mode: apply the guardrail patches and commit them on a branch.",
        ),
    ] = False,
    open_pr: Annotated[
        bool,
        typer.Option(
            "--open-pr/--no-open-pr",
            help="Owner mode: push the branch and open a PR (implies --fix; needs GITHUB_TOKEN).",
        ),
    ] = False,
) -> None:
    """Scan a target agent and write audit reports (Markdown, JSON, optional SARIF)."""
    if mode is not None and mode not in {"owner", "auditor"}:
        _err(f"--mode must be 'owner' or 'auditor', got {mode!r}")
        raise typer.Exit(code=2)
    if provider not in _PROVIDER_KEY_ENV:
        _err(f"--provider must be one of anthropic, openai, gemini; got {provider!r}")
        raise typer.Exit(code=2)
    if fail_on is not None:
        fail_on = fail_on.upper()
        if fail_on not in SEVERITY_ORDER:
            _err(f"--fail-on must be CRITICAL, HIGH, MEDIUM, or LOW; got {fail_on!r}")
            raise typer.Exit(code=2)
    if fail_on_asr is not None and not (0.0 <= fail_on_asr <= 1.0):
        _err(f"--fail-on-asr must be between 0.0 and 1.0, got {fail_on_asr!r}")
        raise typer.Exit(code=2)

    fix = fix or open_pr
    token = os.environ.get("GITHUB_TOKEN")
    if open_pr and not token:
        _err("--open-pr needs GITHUB_TOKEN (a token with repo scope on the target).")
        raise typer.Exit(code=2)

    llm_client: object | None = None
    if (attack or enrich) and _has_provider_credentials(provider, base_url):
        try:
            llm_client = _build_llm_client(provider, base_url=base_url)
        except ProviderError as exc:
            _err(str(exc))
            raise typer.Exit(code=2) from exc

    github_client = _build_github_client(token) if open_pr else None
    try:
        result = run(
            repo,
            requested_mode=mode,  # type: ignore[arg-type]
            token=token,
            github_client=github_client,
            llm_client=llm_client,
            attack=attack,
            fix=fix,
            open_pr=open_pr,
            max_payloads=max_payloads,
            min_interval_seconds=min_interval,
            packs=_parse_packs(pack),
            adaptive=adaptive,
            all_prompts=all_prompts,
            model=model,
            enrich=enrich,
            verify_patches=verify_patches,
            sarif=sarif,
            out_dir=out,
        )
    except ReconError as exc:
        _err(f"recon failed: {exc}")
        raise typer.Exit(code=1) from exc
    except ScanError as exc:
        _err(str(exc))
        raise typer.Exit(code=2) from exc

    report = result.report
    _ok(f"Scanned {repo} in {report.mode} mode.")
    typer.echo(
        f"Findings: {report.summary.total_findings} "
        f"(static {report.summary.static_count}, dynamic {report.summary.dynamic_count})"
    )
    if report.dynamic_run is not None:
        dr = report.dynamic_run
        typer.echo(
            f"Dynamic: {dr.successes}/{dr.attempts} payloads landed "
            f"({dr.success_rate:.0%}), confidence {dr.confidence}"
        )
    if report.patch_verification is not None:
        pv = report.patch_verification
        typer.echo(
            f"Verified patches: ASR {pv.before.success_rate:.0%} -> "
            f"{pv.after.success_rate:.0%} ({pv.asr_delta:+.1%})"
        )
    if report.applied_action != "report":
        detail = f" ({report.action_ref})" if report.action_ref else ""
        _ok(f"Action: {report.applied_action}{detail}")
    for path in result.written:
        typer.echo(f"  wrote {path}")

    gate_failure = _check_ci_gates(report, fail_on=fail_on, fail_on_asr=fail_on_asr)
    if gate_failure:
        _err(gate_failure)
        raise typer.Exit(code=3)


@app.command()
def diff(
    before: Annotated[Path, typer.Argument(help="Baseline AuditReport JSON file.")],
    after: Annotated[Path, typer.Argument(help="Candidate AuditReport JSON file.")],
    out_md: Annotated[
        Path | None, typer.Option("--out-md", help="Optional path to write Markdown diff.")
    ] = None,
    fail_on_regression: Annotated[
        bool,
        typer.Option(
            "--fail-on-regression/--no-fail-on-regression",
            help="Exit 3 if new findings appeared or dynamic ASR increased.",
        ),
    ] = False,
) -> None:
    """Compare two JSON audit reports to spot new/resolved findings and ASR drift."""
    try:
        before_report = AuditReport.model_validate_json(before.read_text(encoding="utf-8"))
        after_report = AuditReport.model_validate_json(after.read_text(encoding="utf-8"))
    except Exception as exc:
        _err(f"could not read audit report(s): {exc}")
        raise typer.Exit(code=2) from exc

    delta = compare_reports(before_report, after_report)
    rendered = render_diff_markdown(delta)
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(rendered, encoding="utf-8")
    typer.echo(rendered, nl=False)
    if fail_on_regression and delta.has_regressions:
        _err("Security regression detected between baseline and candidate reports.")
        raise typer.Exit(code=3)
