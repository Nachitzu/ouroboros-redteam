"""The ``ouroboros`` command line interface.

The one place a client is actually built. Everything under ``ouroboros`` is a
thin shell around :mod:`ouroboros.orchestrator`: parse flags, load a ``.env`` if
present, run the scan, print where the report landed. The deterministic pipeline
(recon + static) needs no API key, so ``scan`` works fully offline.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from ouroboros import __version__
from ouroboros.agents.recon import ReconError
from ouroboros.orchestrator import ScanError, run

app = typer.Typer(
    name="ouroboros",
    help="Red-team LLM agents for prompt injection: audit, and (soon) patch.",
    no_args_is_help=True,
    add_completion=False,
)


def _err(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _ok(message: str) -> None:
    typer.secho(message, fg=typer.colors.GREEN, err=True)


def _load_dotenv() -> None:
    """Pull ANTHROPIC_API_KEY / GITHUB_TOKEN from a local .env if one exists.

    Optional by design: python-dotenv missing must never break the offline path,
    and an already-exported variable always wins.
    """
    try:
        from dotenv import find_dotenv, load_dotenv
    except ImportError:
        return
    load_dotenv(find_dotenv(usecwd=True), override=False)


def _build_llm_client() -> object:
    """Build a real Anthropic client for a live (owner-mode) attack.

    Built only here, at the edge, and only when a key is present — the rest of the
    pipeline takes the client as an argument and never constructs one. Whether a
    live client is actually required is the orchestrator's call (owner mode); in
    auditor mode it runs an offline simulation and never uses this.
    """
    import anthropic

    return anthropic.Anthropic()


def _build_github_client(token: str | None) -> object:
    """Build a PyGithub client for opening a PR. Only called when --open-pr is set."""
    from github import Github

    return Github(token)


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
                "Run a dynamic prompt-injection campaign — live in owner mode "
                "(needs ANTHROPIC_API_KEY), simulated against a mock in auditor mode (offline)."
            ),
        ),
    ] = False,
    max_payloads: Annotated[
        int, typer.Option("--max-payloads", help="Cap on payloads sent per dynamic run.")
    ] = 20,
    min_interval: Annotated[
        float,
        typer.Option("--min-interval", help="Minimum seconds between attack requests."),
    ] = 1.0,
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
    """Scan a target agent and write an audit report (Markdown + JSON)."""
    if mode is not None and mode not in {"owner", "auditor"}:
        _err(f"--mode must be 'owner' or 'auditor', got {mode!r}")
        raise typer.Exit(code=2)

    fix = fix or open_pr  # opening a PR implies applying the patches first
    token = os.environ.get("GITHUB_TOKEN")
    if open_pr and not token:
        _err("--open-pr needs GITHUB_TOKEN (a token with repo scope on the target).")
        raise typer.Exit(code=2)
    # Build a real client only if a key exists; the orchestrator decides whether a
    # live client is required (owner) or an offline simulation runs (auditor).
    llm_client = _build_llm_client() if attack and os.environ.get("ANTHROPIC_API_KEY") else None
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
    if report.applied_action != "report":
        detail = f" ({report.action_ref})" if report.action_ref else ""
        _ok(f"Action: {report.applied_action}{detail}")
    for path in result.written:
        typer.echo(f"  wrote {path}")
