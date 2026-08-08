"""The Static Analyzer: read the code recon found and flag weak prompt handling.

This pass is deterministic — it reasons over the AST of the target's Python
files, not with a model — so it is fully testable offline and produces the same
findings every run. An optional LLM enrichment pass can add prose, but never
changes which weaknesses are reported; the detectors below are the source of
truth.

Three weakness families, each mapped to a verified MITRE ATLAS technique:

  * ``direct_interpolation`` — untrusted-looking input spliced straight into a
    prompt via f-string / ``.format`` / ``%`` / ``+``. The classic injection hole.
  * ``missing_delimiters`` — external content dropped into a prompt with no fence
    or tag separating instructions from data.
  * ``no_output_validation`` — a model's reply consumed without being parsed and
    validated, so whatever the model says is trusted verbatim.

Every reported ATLAS id is checked against the offline catalog before it ships,
so a detector can never attach a technique that does not exist.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ouroboros.schemas.common import AtlasTechnique, FindingCategory, Severity
from ouroboros.schemas.repo_profile import RepoProfile
from ouroboros.schemas.static_finding import StaticFinding
from ouroboros.tools.atlas import verify_atlas_technique

# Keyword names that suggest a value carrying untrusted, externally-influenced
# text — the kind you must never splice raw into a prompt.
_UNTRUSTED_HINTS = (
    "input",
    "user",
    "message",
    "content",
    "query",
    "prompt_text",
    "email",
    "body",
    "alert",
    "tool_result",
    "tool_output",
    "observation",
    "data",
    "text",
    "payload",
    "response",
)

# Names of kwargs that carry a prompt to the model.
_PROMPT_KWARGS = {"system"}

# ATLAS ids each category maps to. Resolved to full techniques (and dropped if the
# id is somehow unknown) by ``_atlas_for``.
_CATEGORY_ATLAS: dict[FindingCategory, tuple[str, ...]] = {
    "direct_interpolation": ("AML.T0051", "AML.T0051.001"),
    "missing_delimiters": ("AML.T0051",),
    "no_output_validation": ("AML.T0077",),
    "no_instruction_hierarchy": ("AML.T0051.000",),
    "untrusted_tool_output": ("AML.T0051.001",),
}

_CATEGORY_SEVERITY: dict[FindingCategory, Severity] = {
    "direct_interpolation": "HIGH",
    "missing_delimiters": "MEDIUM",
    "no_output_validation": "MEDIUM",
    "no_instruction_hierarchy": "MEDIUM",
    "untrusted_tool_output": "HIGH",
}


@dataclass
class _FileCtx:
    """The one file a detector is currently looking at."""

    rel: str
    source: str
    lines: list[str]


def analyze(
    profile: RepoProfile,
    *,
    root: Path | None = None,
    client: Any | None = None,  # reserved for the optional enrichment pass
) -> list[StaticFinding]:
    """Return the static findings for a profiled target.

    ``root`` is the directory to read (recon's checkout). When omitted it falls
    back to ``profile.source`` for the local-path case, which is what the CLI and
    tests use.
    """
    base = root or Path(profile.source).expanduser().resolve()
    findings: list[StaticFinding] = []
    for py in _python_files(base):
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        ctx = _FileCtx(rel=str(py.relative_to(base)), source=source, lines=source.splitlines())
        findings.extend(_scan_tree(tree, ctx))
    return findings


# --------------------------------------------------------------------------
# detectors
# --------------------------------------------------------------------------
def _scan_tree(tree: ast.AST, ctx: _FileCtx) -> list[StaticFinding]:
    # Prompts are usually built into a variable and then passed as `system=var`,
    # so resolving simple name assignments is what makes the difference between
    # seeing the f-string and seeing an opaque Name. Last assignment wins — good
    # enough for detection, and it keeps the walk single-pass.
    assign_map = _assignment_map(tree)
    out: list[StaticFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            out.extend(_check_prompt_call(node, ctx, assign_map))
            out.extend(_check_unvalidated_output(node, ctx))
    return out


def _assignment_map(tree: ast.AST) -> dict[str, ast.AST]:
    """Map each assigned Name to its value node across the module."""
    mapping: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    mapping[target.id] = node.value
    return mapping


def _resolve(node: ast.AST, assign_map: dict[str, ast.AST]) -> ast.AST:
    """Follow a Name to the expression it was assigned, one hop, if we know it."""
    if isinstance(node, ast.Name) and node.id in assign_map:
        return assign_map[node.id]
    return node


def _check_prompt_call(
    call: ast.Call, ctx: _FileCtx, assign_map: dict[str, ast.AST]
) -> list[StaticFinding]:
    """Inspect ``*.messages.create(system=...)`` for unsafe prompt construction."""
    if not _is_messages_create(call):
        return []
    out: list[StaticFinding] = []
    for kw in call.keywords:
        if kw.arg not in _PROMPT_KWARGS:
            continue
        value = _resolve(kw.value, assign_map)
        if _is_dynamic_string(value):
            if _mentions_untrusted(value):
                out.append(
                    _finding(
                        "direct_interpolation",
                        ctx,
                        value,
                        "Untrusted input is interpolated directly into the system prompt. "
                        "A crafted value can inject instructions the model will follow.",
                        "Keep the system prompt static; pass external text in a separate, "
                        "clearly delimited user turn and never concatenate it into instructions.",
                    )
                )
            if not _has_delimiters(value, ctx):
                out.append(
                    _finding(
                        "missing_delimiters",
                        ctx,
                        value,
                        "External content is assembled into the prompt without delimiters "
                        "or tags separating trusted instructions from untrusted data.",
                        "Wrap injected content in explicit delimiters (e.g. XML-style tags) "
                        "and tell the model to treat everything inside them as data.",
                    )
                )
    return out


def _check_unvalidated_output(call: ast.Call, ctx: _FileCtx) -> list[StaticFinding]:
    """Flag ``.messages.create(...)`` whose result is used without validation.

    Heuristic: the create call is the value of an assignment (or bare expression)
    and the enclosing function contains no ``model_validate`` / ``json.loads`` /
    ``.parse`` in scope. Deliberately conservative — a false negative here is
    cheaper than crying wolf on code that does validate elsewhere.
    """
    if not _is_messages_create(call):
        return []
    if _module_validates(ctx.source):
        return []
    return [
        _finding(
            "no_output_validation",
            ctx,
            call,
            "The model's response is consumed without being parsed and validated "
            "against a schema, so injected or malformed output is trusted verbatim.",
            "Validate every model reply against a Pydantic model (or equivalent) "
            "before acting on it; treat validation failure as a hard error.",
        )
    ]


# --------------------------------------------------------------------------
# AST predicates
# --------------------------------------------------------------------------
def _is_messages_create(call: ast.Call) -> bool:
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "create"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "messages"
    )


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if ``node`` builds a string at runtime (f-string, format, %, concat)."""
    is_fstring = isinstance(node, ast.JoinedStr)
    is_concat_or_mod = isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
    is_format = (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )
    return is_fstring or is_concat_or_mod or is_format


def _mentions_untrusted(node: ast.AST) -> bool:
    """True if any Name/attribute inside ``node`` looks like untrusted input."""
    for sub in ast.walk(node):
        name: str | None = None
        if isinstance(sub, ast.Name):
            name = sub.id
        elif isinstance(sub, ast.Attribute):
            name = sub.attr
        if name is not None and any(hint in name.lower() for hint in _UNTRUSTED_HINTS):
            return True
    return False


def _has_delimiters(node: ast.AST, ctx: _FileCtx) -> bool:
    """True if the constant parts of ``node`` contain plausible delimiters.

    We look for XML-ish tags, triple backticks, or clearly fenced markers in the
    literal fragments; their presence means the author separated data from
    instructions, so we do not raise ``missing_delimiters``.
    """
    markers = ("<", "```", '"""', "###", "===")
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and any(marker in sub.value for marker in markers)
        ):
            return True
    return False


def _module_validates(source: str) -> bool:
    return any(
        token in source for token in ("model_validate", "json.loads", ".parse(", "ValidationError")
    )


# --------------------------------------------------------------------------
# finding construction
# --------------------------------------------------------------------------
def _finding(
    category: FindingCategory,
    ctx: _FileCtx,
    node: ast.AST,
    explanation: str,
    recommendation: str,
) -> StaticFinding:
    line = getattr(node, "lineno", None)
    return StaticFinding(
        category=category,
        severity=_CATEGORY_SEVERITY[category],
        file_path=ctx.rel,
        line=line,
        evidence=_snippet(ctx, line),
        explanation=explanation,
        recommendation=recommendation,
        atlas=_atlas_for(category),
    )


def _snippet(ctx: _FileCtx, line: int | None) -> str:
    if line is None or line < 1 or line > len(ctx.lines):
        return "<source unavailable>"
    return ctx.lines[line - 1].strip() or "<blank line>"


def _atlas_for(category: FindingCategory) -> list[AtlasTechnique]:
    """Resolve a category's ATLAS ids to real techniques, dropping any unknown one."""
    resolved: list[AtlasTechnique] = []
    for technique_id in _CATEGORY_ATLAS.get(category, ()):
        technique = verify_atlas_technique(technique_id)
        if technique is not None:
            resolved.append(technique)
    return resolved


# --------------------------------------------------------------------------
# file discovery (mirrors recon's skip list)
# --------------------------------------------------------------------------
def _python_files(root: Path) -> list[Path]:
    skip = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}
    return [p for p in root.rglob("*.py") if not any(part in skip for part in p.parts)]
