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
from ouroboros.orchestrator import run

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
    max_payloads: Annotated[
        int, typer.Option("--max-payloads", help="Dynamic Attacker rate limit (weeks 4+).")
    ] = 20,
) -> None:
    """Scan a target agent and write an audit report (Markdown + JSON)."""
    if mode is not None and mode not in {"owner", "auditor"}:
        _err(f"--mode must be 'owner' or 'auditor', got {mode!r}")
        raise typer.Exit(code=2)

    token = os.environ.get("GITHUB_TOKEN")
    try:
        result = run(
            repo,
            requested_mode=mode,  # type: ignore[arg-type]
            token=token,
            max_payloads=max_payloads,
            out_dir=out,
        )
    except ReconError as exc:
        _err(f"recon failed: {exc}")
        raise typer.Exit(code=1) from exc

    report = result.report
    _ok(f"Scanned {repo} in {report.mode} mode.")
    typer.echo(
        f"Findings: {report.summary.total_findings} "
        f"(static {report.summary.static_count}, dynamic {report.summary.dynamic_count})"
    )
    for path in result.written:
        typer.echo(f"  wrote {path}")
