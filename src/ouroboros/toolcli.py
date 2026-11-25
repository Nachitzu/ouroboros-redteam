"""The ``ouroboros-tool`` companion CLI: offline catalog & payload pack helpers.

Exposes commands over MITRE ATLAS (verify, search, mitigations, sync), OWASP
GenAI Top 10 & Agentic (verify, search, map), payload packs (list, show,
verify), and external dataset import/validation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, get_args

import typer

from ouroboros.payloads.importer import import_dataset
from ouroboros.payloads.packs import available_packs, load_packs, verify_all_packs
from ouroboros.schemas.common import FindingCategory, Oracle, PayloadFamily
from ouroboros.tools.atlas import (
    atlas_mitigations_for,
    search_atlas_techniques,
    sync_atlas_from_yaml,
    verify_atlas_technique,
)
from ouroboros.tools.owasp import (
    cwe_for_category,
    owasp_for_category,
    search_owasp,
    verify_owasp_risk,
)

app = typer.Typer(
    name="ouroboros-tool",
    help="Offline helpers for Ouroboros (MITRE ATLAS, OWASP GenAI, and payload packs).",
    no_args_is_help=True,
    add_completion=False,
)

atlas_app = typer.Typer(help="Query or sync the local MITRE ATLAS catalog.", no_args_is_help=True)
owasp_app = typer.Typer(help="Query the local OWASP GenAI catalog.", no_args_is_help=True)
payloads_app = typer.Typer(help="Inspect and verify payload packs.", no_args_is_help=True)
datasets_app = typer.Typer(help="List, verify, and import payload datasets.", no_args_is_help=True)

app.add_typer(atlas_app, name="atlas")
app.add_typer(owasp_app, name="owasp")
app.add_typer(payloads_app, name="payloads")
app.add_typer(datasets_app, name="datasets")

_VALID_CATEGORIES: tuple[str, ...] = get_args(FindingCategory)
_VALID_FAMILIES: tuple[str, ...] = get_args(PayloadFamily)
_VALID_ORACLES: tuple[str, ...] = get_args(Oracle)


# ---------------------------------------------------------------------------
# atlas
# ---------------------------------------------------------------------------


@atlas_app.command("verify")
def atlas_verify(technique_id: str) -> None:
    """Confirm a technique id exists in the catalog and print it."""
    technique = verify_atlas_technique(technique_id)
    if technique is None:
        typer.secho(f"unknown ATLAS technique: {technique_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{technique.technique_id}  {technique.name}  [{technique.tactic}]")


@atlas_app.command("search")
def atlas_search(query: str) -> None:
    """List catalog techniques matching a substring of id, name or tactic."""
    matches = search_atlas_techniques(query)
    if not matches:
        typer.secho(f"no ATLAS techniques match {query!r}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    for technique in matches:
        typer.echo(f"{technique.technique_id}  {technique.name}  [{technique.tactic}]")


@atlas_app.command("mitigations")
def atlas_mitigations(technique_id: str) -> None:
    """List mitigations mapped to an ATLAS technique id."""
    if verify_atlas_technique(technique_id) is None:
        typer.secho(f"unknown ATLAS technique: {technique_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    mitigations = atlas_mitigations_for(technique_id)
    if not mitigations:
        typer.echo(f"no mitigations mapped for {technique_id}")
        return
    for mit in mitigations:
        typer.echo(f"{mit['mitigation_id']}  {mit['name']}")


@atlas_app.command("sync")
def atlas_sync(
    source: Annotated[
        Path,
        typer.Option("--from", help="Path to ATLAS.yaml or directory containing dist/ATLAS.yaml."),
    ],
    out_dir: Annotated[
        Path | None,
        typer.Option("--out", help="Optional output directory for compiled JSON files."),
    ] = None,
) -> None:
    """Compile upstream ATLAS.yaml into local JSON catalogs."""
    try:
        tech_count, mit_count = sync_atlas_from_yaml(source, out_dir=out_dir)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Synced {tech_count} ATLAS techniques and {mit_count} mitigations.")


# ---------------------------------------------------------------------------
# owasp
# ---------------------------------------------------------------------------


@owasp_app.command("verify")
def owasp_verify(risk_id: str) -> None:
    """Confirm an OWASP GenAI risk id exists in the catalog."""
    risk = verify_owasp_risk(risk_id)
    if risk is None:
        typer.secho(f"unknown OWASP risk: {risk_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{risk.risk_id}  {risk.name}")


@owasp_app.command("search")
def owasp_search(query: str) -> None:
    """Search OWASP GenAI risks by id, name, framework, or description."""
    matches = search_owasp(query)
    if not matches:
        typer.secho(f"no OWASP risks match {query!r}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=1)
    for risk in matches:
        typer.echo(f"{risk.risk_id}  {risk.name}")


@owasp_app.command("map")
def owasp_map(category: str) -> None:
    """Show OWASP risks and CWE ids mapped to a FindingCategory."""
    if category not in _VALID_CATEGORIES:
        typer.secho(f"unknown FindingCategory: {category}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    cat: FindingCategory = category  # type: ignore[assignment]
    risks = owasp_for_category(cat)
    cwes = cwe_for_category(cat)
    risk_str = ", ".join(f"{r.risk_id} ({r.name})" for r in risks) or "none"
    cwe_str = ", ".join(cwes) or "none"
    typer.echo(f"Category: {cat}")
    typer.echo(f"OWASP:    {risk_str}")
    typer.echo(f"CWE:      {cwe_str}")


# ---------------------------------------------------------------------------
# payloads
# ---------------------------------------------------------------------------


@payloads_app.command("list")
def payloads_list(
    pack: Annotated[
        list[str] | None,
        typer.Option("--pack", help="Pack name(s) to list (defaults to all packs)."),
    ] = None,
) -> None:
    """List payloads across packs."""
    names = pack if pack else ["all"]
    try:
        items = load_packs(names)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    for p in items:
        typer.echo(f"{p.id}  [{p.pack}/{p.family}]  {p.oracle}  {p.description}")


@payloads_app.command("show")
def payloads_show(payload_id: str) -> None:
    """Print full details for a single payload id."""
    for p in load_packs(["all"]):
        if p.id == payload_id:
            typer.echo(p.model_dump_json(indent=2))
            return
    typer.secho(f"unknown payload id: {payload_id}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


@payloads_app.command("verify")
def payloads_verify() -> None:
    """Validate all payload packs, unique ids, and ATLAS/OWASP references."""
    try:
        infos = verify_all_packs()
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    total = sum(info.count for info in infos)
    typer.echo(f"Verified {len(infos)} packs ({total} payloads).")


# ---------------------------------------------------------------------------
# datasets
# ---------------------------------------------------------------------------


@datasets_app.command("list")
def datasets_list() -> None:
    """List available payload packs / datasets with counts and families."""
    for info in available_packs():
        fams = ",".join(info.families)
        typer.echo(f"{info.name}  v{info.version}  count={info.count}  families=[{fams}]")


@datasets_app.command("verify")
def datasets_verify() -> None:
    """Verify every discovered pack/dataset."""
    payloads_verify()


@datasets_app.command("import")
def datasets_import(
    file: Annotated[Path, typer.Option("--file", help="Path to source JSONL or CSV file.")],
    fmt: Annotated[
        Literal["jsonl", "csv"],
        typer.Option("--format", help="Input format: jsonl or csv."),
    ],
    text_field: Annotated[
        str, typer.Option("--text-field", help="Field/column containing probe text.")
    ],
    pack: Annotated[str, typer.Option("--pack", help="Output pack name.")],
    family: Annotated[str, typer.Option("--family", help="PayloadFamily for imported entries.")],
    oracle: Annotated[
        str, typer.Option("--oracle", help="Oracle type (default: canary).")
    ] = "canary",
    target_tool: Annotated[
        str | None,
        typer.Option("--target-tool", help="Target tool name when oracle=tool_call."),
    ] = None,
    language: Annotated[
        str, typer.Option("--language", help="Language code for imported probes.")
    ] = "en",
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Output directory (defaults to ~/.ouroboros/packs/)."),
    ] = None,
) -> None:
    """Import an external JSONL or CSV dataset into a safe canary-goal payload pack."""
    if family not in _VALID_FAMILIES:
        typer.secho(f"invalid family: {family}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if oracle not in _VALID_ORACLES:
        typer.secho(f"invalid oracle: {oracle}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    try:
        imported = import_dataset(
            source_file=file,
            fmt=fmt,
            text_field=text_field,
            pack_name=pack,
            family=family,  # type: ignore[arg-type]
            oracle=oracle,  # type: ignore[arg-type]
            target_tool=target_tool,
            language=language,
            out_dir=out,
        )
    except (FileNotFoundError, ValueError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Imported {imported.info.count} payloads into pack '{imported.info.name}' "
        f"({imported.info.path})."
    )
