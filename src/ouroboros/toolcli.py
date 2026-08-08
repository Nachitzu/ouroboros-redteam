"""The ``ouroboros-tool`` companion CLI: query the offline ATLAS catalog.

A small console surface over :mod:`ouroboros.tools.atlas`, mirroring the sibling
projects' ``*-tool`` command. It lets a human confirm or search MITRE ATLAS
technique ids without an API key — the same catalog the analyzers verify against.
"""

from __future__ import annotations

import typer

from ouroboros.tools.atlas import search_atlas_techniques, verify_atlas_technique

app = typer.Typer(
    name="ouroboros-tool",
    help="Offline helpers for Ouroboros (MITRE ATLAS lookups).",
    no_args_is_help=True,
    add_completion=False,
)

atlas_app = typer.Typer(help="Query the local MITRE ATLAS catalog.", no_args_is_help=True)
app.add_typer(atlas_app, name="atlas")


@atlas_app.command()
def verify(technique_id: str) -> None:
    """Confirm a technique id exists in the catalog and print it."""
    technique = verify_atlas_technique(technique_id)
    if technique is None:
        typer.secho(f"unknown ATLAS technique: {technique_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{technique.technique_id}  {technique.name}  [{technique.tactic}]")


@atlas_app.command()
def search(query: str) -> None:
    """List catalog techniques matching a substring of id, name or tactic."""
    matches = search_atlas_techniques(query)
    if not matches:
        typer.secho(f"no ATLAS techniques match {query!r}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    for technique in matches:
        typer.echo(f"{technique.technique_id}  {technique.name}  [{technique.tactic}]")
