"""The Static Analyzer: read the code and prompts recon found and flag weaknesses.

This pass is deterministic — it reasons over the AST of the target's Python
files, extracted system prompts, and extracted tool definitions — so it is fully
testable offline and produces the same findings every run. An optional LLM
enrichment pass (``enrich=True``) rewrites ``explanation`` and ``recommendation``
for already-confirmed findings without ever adding, dropping, or re-ranking them.

Every reported ATLAS id is checked against the offline catalog before it ships,
and OWASP / CWE metadata are attached via :mod:`ouroboros.tools.owasp`.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ouroboros._llm import LLMError, complete_validated, load_prompt
from ouroboros.schemas.common import (
    SEVERITY_ORDER,
    AtlasTechnique,
    FindingCategory,
    OwaspRisk,
    Severity,
)
from ouroboros.schemas.repo_profile import ExtractedPrompt, ExtractedTool, RepoProfile
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

# Hints specifically associated with external / tool-supplied content in user/tool turns.
_TOOL_CONTENT_HINTS = (
    "tool",
    "observation",
    "search",
    "web",
    "document",
    "doc",
    "email",
    "result",
    "fetch",
    "scrape",
    "snippet",
    "page",
    "body",
    "external",
    "untrusted",
    "payload",
)

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}

# ATLAS ids each category maps to. Resolved to full techniques (and dropped if
# unknown) by ``_atlas_for``.
_CATEGORY_ATLAS: dict[FindingCategory, tuple[str, ...]] = {
    "direct_interpolation": ("AML.T0051", "AML.T0051.001"),
    "missing_delimiters": ("AML.T0051",),
    "no_output_validation": ("AML.T0077",),
    "no_instruction_hierarchy": ("AML.T0051.000",),
    "untrusted_tool_output": ("AML.T0051.001",),
    "improper_output_handling": ("AML.T0077", "AML.T0051", "AML.T0086"),
    "excessive_agency": ("AML.T0053", "AML.T0050"),
    "mcp_tool_poisoning": ("AML.T0053", "AML.T0051.001"),
    "prompt_leakage_risk": ("AML.T0056", "AML.T0057"),
}

_CATEGORY_SEVERITY: dict[FindingCategory, Severity] = {
    "direct_interpolation": "HIGH",
    "missing_delimiters": "MEDIUM",
    "no_output_validation": "MEDIUM",
    "no_instruction_hierarchy": "MEDIUM",
    "untrusted_tool_output": "HIGH",
    "improper_output_handling": "HIGH",
    "excessive_agency": "HIGH",
    "mcp_tool_poisoning": "HIGH",
    "prompt_leakage_risk": "MEDIUM",
}

_DANGEROUS_CAPABILITIES = {
    "shell",
    "code_exec",
    "filesystem_write",
    "payment",
    "email",
    "database",
}

_HIERARCHY_PATTERNS = (
    re.compile(
        r"ignore\s+(?:any|all)\s+(?:embedded\s+|injected\s+|user\s+)?instructions?",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:never|do\s+not|don't)\s+(?:follow|obey|execute)\s+(?:any\s+)?instructions?\s+"
        r"(?:from|inside|within|in)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"only\s+follow\s+(?:the\s+)?instructions?\s+(?:from|in)\s+this\s+(?:system\s+)?prompt",
        re.IGNORECASE,
    ),
    re.compile(r"treat\b.{0,50}\bas\s+(?:untrusted\s+)?data\b", re.IGNORECASE),
    re.compile(r"(?:never|not)\s+as\s+instructions?", re.IGNORECASE),
    re.compile(
        r"(?:instruction\s+hierarchy|take\s+precedence\s+over|higher\s+priority\s+than)",
        re.IGNORECASE,
    ),
    # Spanish
    re.compile(
        r"ignora\s+(?:cualquier|todas?\s+las)\s+instrucci(?:o|ó)n(?:es)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"no\s+(?:sigas|obedezcas|ejecutes)\s+(?:ninguna\s+)?instrucci(?:o|ó)n",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:solo|s[oó]lo|[uú]nicamente)\s+sigue\s+(?:las\s+)?instrucciones\s+de\s+est[ea]",
        re.IGNORECASE,
    ),
    re.compile(r"trata\b.{0,50}\bcomo\s+datos(?:\s+no\s+confiables)?\b", re.IGNORECASE),
    re.compile(r"(?:nunca|no)\s+como\s+instrucciones", re.IGNORECASE),
    re.compile(r"jerarqu[ií]a\s+de\s+instrucciones", re.IGNORECASE),
)

_ANTI_DISCLOSURE_PATTERNS = (
    re.compile(
        r"(?:never|do\s+not|don't)\s+(?:reveal|disclose|share|repeat|output|leak|expose|divulge)"
        r"\s+(?:this\s+|your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"keep\s+(?:this\s+|your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+"
        r"(?:secret|confidential|private)",
        re.IGNORECASE,
    ),
    # Spanish
    re.compile(
        r"(?:nunca|no|jam[aá]s)\s+(?:reveles|divulgues|compartas|muestres|repitas|expongas)"
        r"\s+(?:est[ea]\s+|tu\s+|el\s+)?(?:system\s+)?(?:prompt|instrucciones)",
        re.IGNORECASE,
    ),
    re.compile(
        r"mant[eé]n\s+(?:est[ea]\s+|tu\s+)?(?:prompt|instrucciones)\s+"
        r"(?:en\s+secreto|confidencial|privad[oa])",
        re.IGNORECASE,
    ),
)

_SECRET_PATTERNS = (
    re.compile(r"\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)"
        r"\s*[:=]\s*['\"]?(?!<)[A-Za-z0-9_./+=-]{8,}"
    ),
)

_HIDDEN_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]"
)

_POISONING_PATTERNS = (
    re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:do\s+not|don't|never)\s+(?:tell|inform|show|mention\s+to)\s+(?:the\s+)?user",
        re.IGNORECASE,
    ),
    re.compile(r"<\s*(?:important|system|instruction|secret|hidden)\s*>", re.IGNORECASE),
    re.compile(
        r"(?:before|after|when)\s+(?:using|calling|invoking)\s+this\s+tool\b.{0,80}"
        r"\b(?:read|send|exfiltrate|pass|include|upload|curl|fetch|ssh|env|secret|password|key|token)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:read|cat|dump|exfiltrate)\b.{0,50}"
        r"(?:~/\.ssh|/etc/passwd|\.env|id_rsa|credentials|api[_-]?key)",
        re.IGNORECASE,
    ),
    re.compile(r"\bsend\s+(?:the\s+)?contents?\s+(?:of|to)\b", re.IGNORECASE),
    re.compile(
        r"\bsilently\s+(?:send|post|upload|forward|exfiltrate|execute)\b",
        re.IGNORECASE,
    ),
)

_LONG_DESC_IMPERATIVE_RE = re.compile(
    r"\b(?:you\s+must|always\s+call|must\s+first|do\s+not\s+mention|secretly)\b",
    re.IGNORECASE,
)

_XML_OPEN_TAG_RE = re.compile(r"<([A-Za-z_][A-Za-z0-9_-]*)(?:\s[^>]*)?>")
_FENCE_MARKER_RE = re.compile(r"(?:^|\n)\s*(?:```|\"\"\"|###(?:\s|$)|===+|----+)")

_VALIDATION_METHOD_NAMES = {
    "model_validate",
    "model_validate_json",
    "model_validate_strings",
    "validate_json",
    "validate_python",
    "parse",
}


class EnrichmentSchema(BaseModel):
    """Structured reply returned by the optional LLM prose-enrichment pass."""

    explanation: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)


@dataclass
class _FileCtx:
    """The one file a detector is currently looking at."""

    rel: str
    source: str
    lines: list[str]


@dataclass
class _ScopeInfo:
    """Function (or module) scope: assignments, parameter taint, and enclosing AST."""

    node: ast.AST
    assigns: dict[str, ast.AST]
    params: set[str]
    module_assigns: dict[str, ast.AST]


def analyze(
    profile: RepoProfile,
    *,
    root: Path | None = None,
    client: Any | None = None,
    enrich: bool = False,
) -> list[StaticFinding]:
    """Return the static findings for a profiled target.

    ``root`` is the directory to read (recon's checkout). When omitted it falls
    back to ``profile.source`` for the local-path case, which is what the CLI and
    tests use. When ``enrich=True`` and ``client`` is provided, enriches each
    finding's explanation and recommendation via :func:`complete_validated`.
    """
    base = root or Path(profile.source).expanduser().resolve()
    findings: list[StaticFinding] = []
    for py in _python_files(base):
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        ctx = _FileCtx(
            rel=py.relative_to(base).as_posix(),
            source=source,
            lines=source.splitlines(),
        )
        findings.extend(_scan_tree(tree, ctx))

    findings.extend(_analyze_prompts(profile.system_prompts, base))
    findings.extend(_analyze_tools(profile.tools, base))

    deduped = _dedupe_findings(findings)
    if enrich and client is not None and deduped:
        return _enrich_findings(deduped, client)
    return deduped


# --------------------------------------------------------------------------
# AST scanning per file / scope
# --------------------------------------------------------------------------
def _scan_tree(tree: ast.Module, ctx: _FileCtx) -> list[StaticFinding]:
    module_assigns = _collect_block_assigns(tree.body)
    out: list[StaticFinding] = []

    module_scope = _ScopeInfo(
        node=tree,
        assigns=module_assigns,
        params=set(),
        module_assigns=module_assigns,
    )
    out.extend(_scan_scope_calls(tree.body, ctx, module_scope, recurse_defs=False))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_assigns = _collect_block_assigns(node.body)
            params = _function_params(node)
            scope = _ScopeInfo(
                node=node,
                assigns=fn_assigns,
                params=params,
                module_assigns=module_assigns,
            )
            out.extend(_scan_scope_calls(node.body, ctx, scope, recurse_defs=False))
    return out


def _function_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
        if arg.arg not in ("self", "cls"):
            names.add(arg.arg)
    if fn.args.vararg:
        names.add(fn.args.vararg.arg)
    if fn.args.kwarg:
        names.add(fn.args.kwarg.arg)
    return names


def _collect_block_assigns(stmts: list[ast.stmt]) -> dict[str, ast.AST]:
    """Collect assignments in statement order within a single scope (not entering defs)."""
    mapping: dict[str, ast.AST] = {}
    for stmt in _iter_scope_stmts(stmts):
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    mapping[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            if isinstance(stmt.target, ast.Name):
                mapping[stmt.target.id] = stmt.value
        elif (
            isinstance(stmt, ast.AugAssign)
            and isinstance(stmt.op, ast.Add)
            and isinstance(stmt.target, ast.Name)
        ):
            prev = mapping.get(stmt.target.id, ast.Name(id=stmt.target.id, ctx=ast.Load()))
            if isinstance(prev, ast.expr):
                combined = ast.BinOp(left=prev, op=ast.Add(), right=stmt.value)
                combined.lineno = stmt.lineno
                combined.col_offset = stmt.col_offset
                mapping[stmt.target.id] = combined
    return mapping


def _iter_scope_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Flatten compound control-flow bodies in the same function/module scope."""
    out: list[ast.stmt] = []
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        out.append(stmt)
        for attr in ("body", "orelse", "finalbody"):
            sub = getattr(stmt, attr, None)
            if isinstance(sub, list):
                out.extend(_iter_scope_stmts(sub))
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                out.extend(_iter_scope_stmts(handler.body))
    return out


def _iter_scope_nodes(stmts: list[ast.stmt]) -> list[ast.AST]:
    """Return AST nodes inside ``stmts`` without descending into nested defs/classes."""
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(stmts)
    while stack:
        cur = stack.pop()
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nodes.append(cur)
        stack.extend(ast.iter_child_nodes(cur))
    return nodes


def _scan_scope_calls(
    stmts: list[ast.stmt],
    ctx: _FileCtx,
    scope: _ScopeInfo,
    *,
    recurse_defs: bool = False,
) -> list[StaticFinding]:
    del recurse_defs
    out: list[StaticFinding] = []
    scope_nodes = _iter_scope_nodes(stmts)
    llm_tainted_vars = _collect_llm_output_vars(stmts, scope)

    for node in scope_nodes:
        if not isinstance(node, ast.Call):
            continue
        sdk = _classify_llm_sink(node)
        if sdk is not None:
            out.extend(_check_prompt_call(node, sdk, ctx, scope))
            out.extend(_check_untrusted_turns(node, sdk, ctx, scope))
            if _is_response_producing_call(node, sdk):
                out.extend(_check_unvalidated_output(node, ctx, stmts, scope))
        else:
            # Also inspect standalone ChatPromptTemplate / SystemMessage constructors
            prompt_exprs = _extract_prompt_constructor_exprs(node)
            for expr in prompt_exprs:
                out.extend(_check_prompt_expr(expr, ctx, scope))

        out.extend(_check_improper_output_handling(node, ctx, llm_tainted_vars))
    return out


# --------------------------------------------------------------------------
# SDK call classification and prompt sinks
# --------------------------------------------------------------------------
def _classify_llm_sink(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        if (
            func.attr in ("create", "stream")
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "messages"
        ):
            return f"messages.{func.attr}"
        if (
            func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "completions"
            and isinstance(func.value.value, ast.Attribute)
            and func.value.value.attr == "chat"
        ):
            return "chat.completions.create"
        if (
            func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "responses"
        ):
            return "responses.create"
        if (
            func.attr in ("generate_content", "generate_content_stream")
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "models"
        ):
            return f"models.{func.attr}"
        if (
            func.attr in ("completion", "acompletion")
            and isinstance(func.value, ast.Name)
            and func.value.id == "litellm"
        ):
            return f"litellm.{func.attr}"
        if func.attr == "create_react_agent":
            return "langgraph.create_react_agent"
        if func.attr == "Agent" and _has_agent_prompt_kwargs(call):
            return "Agent"
        if (
            func.attr in ("invoke", "ainvoke")
            and isinstance(func.value, ast.Call)
            and _is_with_structured_output(func.value)
        ):
            return "langchain.structured_invoke"

    if isinstance(func, ast.Name):
        if func.id in ("completion", "acompletion") and any(
            kw.arg in ("messages", "model") for kw in call.keywords
        ):
            return f"litellm.{func.id}"
        if func.id == "create_react_agent":
            return "langgraph.create_react_agent"
        if func.id == "Agent" and _has_agent_prompt_kwargs(call):
            return "Agent"
    return None


def _has_agent_prompt_kwargs(call: ast.Call) -> bool:
    kw_names = {kw.arg for kw in call.keywords if kw.arg}
    return bool(kw_names & {"system_prompt", "instructions", "role", "backstory", "goal"})


def _is_response_producing_call(call: ast.Call, sdk: str) -> bool:
    del call
    return sdk in {
        "messages.create",
        "messages.stream",
        "chat.completions.create",
        "responses.create",
        "models.generate_content",
        "models.generate_content_stream",
        "litellm.completion",
        "litellm.acompletion",
    }


def _extract_prompt_constructor_exprs(call: ast.Call) -> list[ast.AST]:
    func = call.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else func.attr
        if isinstance(func, ast.Attribute)
        else None
    )
    exprs: list[ast.AST] = []
    if name == "SystemMessage":
        for kw in call.keywords:
            if kw.arg == "content":
                exprs.append(kw.value)
        if not exprs and call.args:
            exprs.append(call.args[0])
    elif (
        isinstance(func, ast.Attribute)
        and func.attr == "from_messages"
        and isinstance(func.value, ast.Name)
        and func.value.id == "ChatPromptTemplate"
    ):
        seq = call.args[0] if call.args else None
        if seq is None:
            for kw in call.keywords:
                if kw.arg == "messages":
                    seq = kw.value
                    break
        if isinstance(seq, (ast.List, ast.Tuple)):
            for elt in seq.elts:
                if isinstance(elt, (ast.Tuple, ast.List)) and len(elt.elts) >= 2:
                    role = _const_str(elt.elts[0])
                    if role in ("system", "developer"):
                        exprs.append(elt.elts[1])
                elif isinstance(elt, ast.Dict):
                    pairs = _dict_pairs(elt)
                    if (
                        "role" in pairs
                        and "content" in pairs
                        and _const_str(pairs["role"]) in ("system", "developer")
                    ):
                        exprs.append(pairs["content"])
    return exprs


def _system_prompt_exprs_for_call(call: ast.Call, sdk: str, scope: _ScopeInfo) -> list[ast.AST]:
    kw_map = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    exprs: list[ast.AST] = []

    if sdk.startswith("messages.") and "system" in kw_map:
        exprs.append(kw_map["system"])

    if (
        sdk in ("chat.completions.create", "litellm.completion", "litellm.acompletion")
        and "messages" in kw_map
    ):
        exprs.extend(_messages_role_contents(kw_map["messages"], {"system", "developer"}, scope))

    if sdk == "responses.create":
        if "instructions" in kw_map:
            exprs.append(kw_map["instructions"])
        if "input" in kw_map:
            exprs.extend(_messages_role_contents(kw_map["input"], {"system", "developer"}, scope))

    if sdk.startswith("models.generate_content"):
        if "system_instruction" in kw_map:
            exprs.append(kw_map["system_instruction"])
        if "config" in kw_map:
            cfg = _resolve(kw_map["config"], scope)
            if isinstance(cfg, ast.Call):
                for kw in cfg.keywords:
                    if kw.arg == "system_instruction":
                        exprs.append(kw.value)
            elif isinstance(cfg, ast.Dict):
                pairs = _dict_pairs(cfg)
                if "system_instruction" in pairs:
                    exprs.append(pairs["system_instruction"])

    if sdk == "langgraph.create_react_agent":
        for key in ("prompt", "state_modifier"):
            if key in kw_map:
                exprs.append(kw_map[key])

    if sdk == "Agent":
        for key in ("system_prompt", "instructions", "role", "goal", "backstory"):
            if key in kw_map:
                exprs.append(kw_map[key])

    return exprs


def _messages_role_contents(node: ast.AST, roles: set[str], scope: _ScopeInfo) -> list[ast.AST]:
    resolved = _resolve(node, scope)
    if not isinstance(resolved, (ast.List, ast.Tuple)):
        return []
    out: list[ast.AST] = []
    for item in resolved.elts:
        item_node = _resolve(item, scope)
        if not isinstance(item_node, ast.Dict):
            continue
        pairs = _dict_pairs(item_node)
        role_node = pairs.get("role")
        content_node = pairs.get("content")
        if role_node is not None and content_node is not None and _const_str(role_node) in roles:
            out.append(content_node)
    return out


# --------------------------------------------------------------------------
# resolution and light taint
# --------------------------------------------------------------------------
def _resolve(node: ast.AST, scope: _ScopeInfo, max_hops: int = 4) -> ast.AST:
    """Follow Name assignments in function scope (fallback to module) up to ``max_hops``."""
    cur = node
    visited: set[str] = set()
    for _ in range(max_hops):
        if not isinstance(cur, ast.Name):
            break
        name = cur.id
        if name in visited:
            break
        visited.add(name)
        if name in scope.assigns:
            cur = scope.assigns[name]
        elif name in scope.module_assigns:
            cur = scope.module_assigns[name]
        else:
            break
    return cur


def _is_dynamic_string(node: ast.AST, scope: _ScopeInfo, depth: int = 0) -> bool:
    """True if ``node`` builds a string at runtime (f-string, format, %, +, join)."""
    if depth > 4:
        return False
    resolved = _resolve(node, scope)
    if isinstance(resolved, ast.JoinedStr):
        return True
    if isinstance(resolved, ast.BinOp) and isinstance(resolved.op, (ast.Add, ast.Mod)):
        # Static + static is NOT dynamic; at least one side must be dynamic or non-const
        if _const_str(resolved.left) is not None and _const_str(resolved.right) is not None:
            return False
        if isinstance(resolved.op, ast.Mod):
            return True
        # Concatenation is dynamic if either operand is non-constant or recursively dynamic
        return (
            _is_dynamic_string(resolved.left, scope, depth + 1)
            or _is_dynamic_string(resolved.right, scope, depth + 1)
            or _const_str(resolved.left) is None
            or _const_str(resolved.right) is None
        )
    return bool(
        isinstance(resolved, ast.Call)
        and isinstance(resolved.func, ast.Attribute)
        and resolved.func.attr in ("format", "join")
    )


def _is_tainted(
    node: ast.AST,
    scope: _ScopeInfo,
    *,
    hints: tuple[str, ...] = _UNTRUSTED_HINTS,
    depth: int = 0,
    visited: set[str] | None = None,
) -> bool:
    """True if ``node`` references a function parameter or untrusted-hinted name (through hops)."""
    if depth > 4:
        return False
    seen = visited if visited is not None else set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            name = sub.id
            if name in scope.params:
                return True
            if any(hint in name.lower() for hint in hints):
                return True
            if name not in seen:
                target = scope.assigns.get(name) or scope.module_assigns.get(name)
                if target is not None:
                    seen.add(name)
                    if _is_tainted(target, scope, hints=hints, depth=depth + 1, visited=seen):
                        return True
        elif isinstance(sub, ast.Attribute) and any(hint in sub.attr.lower() for hint in hints):
            return True
    return False


def _const_fragments(
    node: ast.AST, scope: _ScopeInfo, depth: int = 0, visited: set[str] | None = None
) -> list[str]:
    """Collect constant string fragments across an expression and resolved variables."""
    if depth > 4:
        return []
    seen = visited if visited is not None else set()
    out: list[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    elif isinstance(node, ast.Name) and node.id not in seen:
        target = scope.assigns.get(node.id) or scope.module_assigns.get(node.id)
        if target is not None:
            seen.add(node.id)
            out.extend(_const_fragments(target, scope, depth + 1, seen))
    else:
        for child in ast.iter_child_nodes(node):
            out.extend(_const_fragments(child, scope, depth, seen))
    return out


def _has_delimiters(node: ast.AST, scope: _ScopeInfo) -> bool:
    """True if constant fragments form balanced XML-style tags or fenced blocks.

    A bare ``<`` (such as ``x < 5``) does NOT qualify: XML-style delimiters must
    have a matching ``<tag>...</tag>`` pair across the fragments, or a fenced
    block marker (```` ``` ````, ``\"\"\"``, ``###``, ``===``, ``----``).
    """
    fragments = _const_fragments(node, scope)
    if not fragments:
        return False
    combined = "\n".join(fragments)

    for match in _XML_OPEN_TAG_RE.finditer(combined):
        tag = match.group(1)
        closing = f"</{tag}>"
        if combined.find(closing, match.end()) != -1:
            return True

    return bool(_FENCE_MARKER_RE.search(combined))


# --------------------------------------------------------------------------
# prompt-call & turn detectors
# --------------------------------------------------------------------------
def _check_prompt_call(
    call: ast.Call, sdk: str, ctx: _FileCtx, scope: _ScopeInfo
) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for raw_expr in _system_prompt_exprs_for_call(call, sdk, scope):
        out.extend(_check_prompt_expr(raw_expr, ctx, scope))
    return out


def _check_prompt_expr(raw_expr: ast.AST, ctx: _FileCtx, scope: _ScopeInfo) -> list[StaticFinding]:
    value = _resolve(raw_expr, scope)
    if not _is_dynamic_string(value, scope):
        return []
    out: list[StaticFinding] = []
    if _is_tainted(value, scope, hints=_UNTRUSTED_HINTS):
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
    if not _has_delimiters(value, scope):
        out.append(
            _finding(
                "missing_delimiters",
                ctx,
                value,
                "External content is assembled into the prompt without delimiters "
                "or tags separating trusted instructions from untrusted data.",
                "Wrap injected content in explicit delimiters (e.g. balanced XML-style tags) "
                "and tell the model to treat everything inside them as data.",
            )
        )
    return out


def _check_untrusted_turns(
    call: ast.Call, sdk: str, ctx: _FileCtx, scope: _ScopeInfo
) -> list[StaticFinding]:
    """Flag user/tool turns that splice tool/external content without delimiters."""
    del sdk
    kw_map = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    seq_node = kw_map.get("messages") or kw_map.get("input")
    if seq_node is None:
        return []
    resolved = _resolve(seq_node, scope)
    if not isinstance(resolved, (ast.List, ast.Tuple)):
        return []

    out: list[StaticFinding] = []
    for item in resolved.elts:
        item_node = _resolve(item, scope)
        if not isinstance(item_node, ast.Dict):
            continue
        pairs = _dict_pairs(item_node)
        content_node = pairs.get("content")
        if content_node is None:
            continue
        role = _const_str(pairs["role"]) if "role" in pairs else None
        msg_type = _const_str(pairs["type"]) if "type" in pairs else None

        is_tool_turn = role == "tool" or msg_type == "tool_result"
        is_user_turn = role == "user"
        if not (is_tool_turn or is_user_turn):
            continue

        content_expr = _resolve(content_node, scope)
        # Anthropic tool_result blocks can sit inside a user turn's content=[{...}] list.
        if is_user_turn and isinstance(content_expr, (ast.List, ast.Tuple)):
            for block in content_expr.elts:
                block_node = _resolve(block, scope)
                if not isinstance(block_node, ast.Dict):
                    continue
                bpairs = _dict_pairs(block_node)
                btype = _const_str(bpairs["type"]) if "type" in bpairs else None
                bcontent = bpairs.get("content")
                if btype == "tool_result" and bcontent is not None:
                    b_expr = _resolve(bcontent, scope)
                    if not _has_delimiters(b_expr, scope) and (
                        _is_dynamic_string(b_expr, scope)
                        or _is_tainted(b_expr, scope, hints=_UNTRUSTED_HINTS)
                    ):
                        out.append(_untrusted_tool_finding(ctx, b_expr))
            continue

        if _has_delimiters(content_expr, scope):
            continue

        if is_tool_turn:
            is_risky = _is_dynamic_string(content_expr, scope) or _is_tainted(
                content_expr, scope, hints=_UNTRUSTED_HINTS
            )
        else:
            # User turn: splicing tool/observation/search/web/document/email content
            is_risky = _is_dynamic_string(content_expr, scope) and _is_tainted(
                content_expr, scope, hints=_TOOL_CONTENT_HINTS
            )

        if is_risky:
            out.append(_untrusted_tool_finding(ctx, content_expr))
    return out


def _untrusted_tool_finding(ctx: _FileCtx, node: ast.AST) -> StaticFinding:
    return _finding(
        "untrusted_tool_output",
        ctx,
        node,
        "External or tool-returned content is spliced into a conversation turn "
        "without explicit delimiters, enabling indirect prompt injection.",
        "Wrap tool, search, web, document, or email output in balanced delimiter "
        "tags (e.g. <tool_output>...</tool_output>) and treat it strictly as data.",
    )


# --------------------------------------------------------------------------
# output validation (function-scoped) & improper output handling
# --------------------------------------------------------------------------
def _check_unvalidated_output(
    call: ast.Call,
    ctx: _FileCtx,
    stmts: list[ast.stmt],
    scope: _ScopeInfo,
) -> list[StaticFinding]:
    if _uses_structured_output(call, stmts, scope):
        return []
    if _call_is_validated_in_scope(call, stmts):
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


def _uses_structured_output(call: ast.Call, stmts: list[ast.stmt], scope: _ScopeInfo) -> bool:
    for kw in call.keywords:
        if kw.arg in ("response_format", "output_type", "response_schema", "result_type"):
            return True
        if kw.arg == "tool_choice":
            val = _const_str(kw.value)
            if val not in ("none", "auto"):
                return True
    if _is_with_structured_output(call.func):
        return True
    # Also check if receiver variable was built with .with_structured_output(...)
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        assigned = scope.assigns.get(call.func.value.id) or scope.module_assigns.get(
            call.func.value.id
        )
        if assigned is not None and _is_with_structured_output(assigned):
            return True
    # Also check config=GenerateContentConfig(response_schema=...)
    for kw in call.keywords:
        if kw.arg == "config":
            cfg = _resolve(kw.value, scope)
            if isinstance(cfg, ast.Call) and any(
                ckw.arg == "response_schema" for ckw in cfg.keywords
            ):
                return True
    del stmts
    return False


def _is_with_structured_output(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "with_structured_output"
    if isinstance(node, ast.Attribute):
        return node.attr == "with_structured_output"
    return False


def _call_is_validated_in_scope(call: ast.Call, stmts: list[ast.stmt]) -> bool:
    scope_nodes = _iter_scope_nodes(stmts)
    # 1. Check if `call` is directly an argument inside a validation call or try/ValidationError
    for node in scope_nodes:
        if (
            isinstance(node, ast.Call)
            and _is_validation_call(node)
            and _subtree_contains_node(node, call)
        ):
            return True
        if (
            isinstance(node, ast.Try)
            and _handles_validation_error(node)
            and any(_subtree_contains_node(s, call) for s in node.body)
        ):
            return True

    # 2. Find assigned response variable(s) and transitive aliases in `stmts`
    resp_vars = _vars_assigned_from_call(stmts, call)
    if not resp_vars:
        return False
    derived = _propagate_derived_vars(stmts, resp_vars)

    for node in scope_nodes:
        if (
            isinstance(node, ast.Call)
            and _is_validation_call(node)
            and _call_args_reference_vars(node, derived)
        ):
            return True
        if (
            isinstance(node, ast.Try)
            and _handles_validation_error(node)
            and any(_subtree_references_vars(s, derived) for s in node.body)
        ):
            return True
    return False


def _vars_assigned_from_call(stmts: list[ast.stmt], target_call: ast.Call) -> set[str]:
    found: set[str] = set()
    for stmt in _iter_scope_stmts(stmts):
        if isinstance(stmt, ast.Assign) and _subtree_contains_node(stmt.value, target_call):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    found.add(t.id)
        elif (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and _subtree_contains_node(stmt.value, target_call)
            and isinstance(stmt.target, ast.Name)
        ):
            found.add(stmt.target.id)
    return found


def _propagate_derived_vars(stmts: list[ast.stmt], seeds: set[str]) -> set[str]:
    """Return ``seeds`` plus any local variables assigned from expressions referencing them."""
    derived = set(seeds)
    scope_stmts = _iter_scope_stmts(stmts)
    changed = True
    while changed:
        changed = False
        for stmt in scope_stmts:
            val: ast.AST | None = None
            targets: list[str] = []
            if isinstance(stmt, ast.Assign):
                val = stmt.value
                targets = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                val = stmt.value
                if isinstance(stmt.target, ast.Name):
                    targets = [stmt.target.id]
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                val = stmt.value
                targets = [stmt.target.id]
            if val is not None and _subtree_references_vars(val, derived):
                for name in targets:
                    if name not in derived:
                        derived.add(name)
                        changed = True
    return derived


def _collect_llm_output_vars(stmts: list[ast.stmt], scope: _ScopeInfo) -> set[str]:
    del scope
    seeds: set[str] = set()
    for node in _iter_scope_nodes(stmts):
        if isinstance(node, ast.Call):
            sdk = _classify_llm_sink(node)
            if sdk is not None and _is_response_producing_call(node, sdk):
                seeds.update(_vars_assigned_from_call(stmts, node))
    return _propagate_derived_vars(stmts, seeds)


def _is_validation_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in _VALIDATION_METHOD_NAMES:
            return True
        if func.attr == "loads" and isinstance(func.value, ast.Name) and func.value.id == "json":
            return True
    return False


def _handles_validation_error(try_node: ast.Try) -> bool:
    for handler in try_node.handlers:
        exc = handler.type
        if exc is None:
            continue
        for sub in ast.walk(exc):
            if isinstance(sub, ast.Name) and sub.id == "ValidationError":
                return True
            if isinstance(sub, ast.Attribute) and sub.attr == "ValidationError":
                return True
    return False


def _call_args_reference_vars(call: ast.Call, names: set[str]) -> bool:
    for arg in call.args:
        if _subtree_references_vars(arg, names):
            return True
    return any(_subtree_references_vars(kw.value, names) for kw in call.keywords)


def _subtree_references_vars(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(sub, ast.Name) and sub.id in names for sub in ast.walk(node))


def _subtree_contains_node(root: ast.AST, target: ast.AST) -> bool:
    return any(sub is target for sub in ast.walk(root))


def _check_improper_output_handling(
    call: ast.Call,
    ctx: _FileCtx,
    llm_tainted_vars: set[str],
) -> list[StaticFinding]:
    """Flag LLM output flowing into dangerous execution/deserialization/SQL/template sinks."""
    sink_info = _classify_dangerous_sink(call)
    if sink_info is None:
        return []
    sink_kind, base_severity, sink_desc = sink_info

    # Check if any argument (or inline LLM call) brings LLM taint into this sink
    arg_nodes: list[ast.AST] = [*call.args, *(kw.value for kw in call.keywords)]
    if sink_kind == "sql_execute":
        # Parameterized static SQL is safe; flag only dynamic string SQL carrying LLM taint
        if not call.args:
            return []
        sql_arg = call.args[0]
        if _const_str(sql_arg) is not None:
            return []
        tainted = _expr_carries_llm_output(sql_arg, llm_tainted_vars)
    elif sink_kind == "open_path":
        if not call.args:
            return []
        tainted = _expr_carries_llm_output(call.args[0], llm_tainted_vars)
    else:
        tainted = any(_expr_carries_llm_output(arg, llm_tainted_vars) for arg in arg_nodes)

    if not tainted:
        return []

    return [
        _finding(
            "improper_output_handling",
            ctx,
            call,
            f"Unconstrained model output flows into {sink_desc}, allowing prompt injection to "
            "escalate into arbitrary execution or injection.",
            "Never pass model output directly to execution, SQL, path, or template sinks. "
            "Validate against a strict allowlist or schema and use parameterized APIs.",
            severity=base_severity,
        )
    ]


def _classify_dangerous_sink(call: ast.Call) -> tuple[str, Severity, str] | None:
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in ("eval", "exec"):
            return ("code_exec", "CRITICAL", f"``{func.id}()``")
        if func.id == "open":
            return ("open_path", "HIGH", "``open()``")
        if func.id == "render_template_string":
            return ("template", "HIGH", "``render_template_string()``")
        if func.id == "Markup":
            return ("markup", "HIGH", "``Markup()``")

    if isinstance(func, ast.Attribute):
        recv = func.value
        recv_name = recv.id if isinstance(recv, ast.Name) else ""
        if recv_name == "subprocess" and func.attr in (
            "run",
            "Popen",
            "call",
            "check_output",
            "check_call",
        ):
            is_shell = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in call.keywords
            )
            sev: Severity = "CRITICAL" if is_shell else "HIGH"
            return ("subprocess", sev, f"``subprocess.{func.attr}()``")
        if recv_name == "os" and func.attr in ("system", "popen"):
            return ("os_shell", "CRITICAL", f"``os.{func.attr}()``")
        if func.attr == "execute":
            return ("sql_execute", "HIGH", "``cursor.execute()``")
        if recv_name == "pickle" and func.attr in ("loads", "load"):
            return ("pickle", "CRITICAL", f"``pickle.{func.attr}()``")
        if recv_name == "yaml" and func.attr == "load":
            has_safe_loader = any(
                kw.arg == "Loader" and _is_safe_yaml_loader(kw.value) for kw in call.keywords
            )
            if not has_safe_loader:
                return ("yaml_load", "HIGH", "``yaml.load()`` without SafeLoader")
        if func.attr == "render_template_string":
            return ("template", "HIGH", "``render_template_string()``")
        if func.attr == "Markup":
            return ("markup", "HIGH", "``Markup()``")
    return None


def _is_safe_yaml_loader(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id in ("SafeLoader", "CSafeLoader"):
        return True
    return bool(isinstance(node, ast.Attribute) and node.attr in ("SafeLoader", "CSafeLoader"))


def _expr_carries_llm_output(expr: ast.AST, llm_tainted_vars: set[str]) -> bool:
    if _subtree_references_vars(expr, llm_tainted_vars):
        return True
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            sdk = _classify_llm_sink(sub)
            if sdk is not None and _is_response_producing_call(sub, sdk):
                return True
    return False


# --------------------------------------------------------------------------
# prompt text & tool surface detectors
# --------------------------------------------------------------------------
def _analyze_prompts(prompts: list[ExtractedPrompt], base: Path) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for prompt in prompts:
        text = prompt.text
        evidence = _prompt_evidence(prompt, base)

        if not any(pat.search(text) for pat in _HIERARCHY_PATTERNS):
            out.append(
                _build_finding(
                    category="no_instruction_hierarchy",
                    severity=_CATEGORY_SEVERITY["no_instruction_hierarchy"],
                    file_path=prompt.file_path,
                    line=prompt.line,
                    evidence=evidence,
                    explanation=(
                        "The system prompt does not establish an instruction hierarchy or "
                        "direct the model to treat external/user input strictly as data."
                    ),
                    recommendation=(
                        "Add an explicit instruction-hierarchy rule telling the model to treat "
                        "delimited user/tool content as data and ignore instructions inside it."
                    ),
                )
            )

        has_secret = any(pat.search(text) for pat in _SECRET_PATTERNS)
        has_anti_disclosure = any(pat.search(text) for pat in _ANTI_DISCLOSURE_PATTERNS)
        if has_secret:
            out.append(
                _build_finding(
                    category="prompt_leakage_risk",
                    severity="HIGH",
                    file_path=prompt.file_path,
                    line=prompt.line,
                    evidence=evidence,
                    explanation=(
                        "The system prompt appears to embed a secret, token, or credential, "
                        "which can be extracted via prompt-leakage attacks."
                    ),
                    recommendation=(
                        "Remove all secrets or credentials from prompts (load them securely "
                        "at runtime) and add an anti-disclosure rule."
                    ),
                )
            )
        elif not has_anti_disclosure:
            out.append(
                _build_finding(
                    category="prompt_leakage_risk",
                    severity="MEDIUM",
                    file_path=prompt.file_path,
                    line=prompt.line,
                    evidence=evidence,
                    explanation=(
                        "The system prompt lacks an anti-disclosure directive, increasing "
                        "the risk of system-prompt extraction."
                    ),
                    recommendation=(
                        "Instruct the model never to reveal, repeat, or disclose its system "
                        "prompt or internal instructions."
                    ),
                )
            )
    return out


def _prompt_evidence(prompt: ExtractedPrompt, base: Path) -> str:
    line_snippet = _read_line_from_disk(base, prompt.file_path, prompt.line)
    if line_snippet:
        return line_snippet
    first_line = prompt.text.strip().splitlines()[0] if prompt.text.strip() else ""
    return (first_line or prompt.text)[:160]


def _analyze_tools(tools: list[ExtractedTool], base: Path) -> list[StaticFinding]:
    out: list[StaticFinding] = []
    for tool in tools:
        evidence = (
            _read_line_from_disk(base, tool.file_path, tool.line)
            or f"tool {tool.name!r} ({tool.source})"
        )
        dangerous = [c for c in tool.capabilities if c in _DANGEROUS_CAPABILITIES]
        if dangerous and not tool.requires_confirmation:
            sev: Severity = (
                "CRITICAL" if any(c in ("shell", "code_exec") for c in dangerous) else "HIGH"
            )
            out.append(
                _build_finding(
                    category="excessive_agency",
                    severity=sev,
                    file_path=tool.file_path,
                    line=tool.line,
                    evidence=evidence,
                    explanation=(
                        f"Tool {tool.name!r} exposes high-impact capabilities "
                        f"({', '.join(dangerous)}) without an explicit human-confirmation gate."
                    ),
                    recommendation=(
                        "Require explicit user confirmation or an allowlisted parameter schema "
                        "before executing high-impact tool actions."
                    ),
                )
            )

        if _is_poisoned_description(tool.description):
            out.append(
                _build_finding(
                    category="mcp_tool_poisoning",
                    severity="HIGH",
                    file_path=tool.file_path,
                    line=tool.line,
                    evidence=evidence,
                    explanation=(
                        f"Tool {tool.name!r} contains hidden or imperative instructions aimed "
                        "at the model inside its description/docstring (tool poisoning risk)."
                    ),
                    recommendation=(
                        "Keep tool descriptions strictly factual about parameters and behavior; "
                        "strip hidden Unicode, instruction tags, and covert directives."
                    ),
                )
            )
    return out


def _is_poisoned_description(description: str) -> bool:
    if not description:
        return False
    if _HIDDEN_UNICODE_RE.search(description):
        return True
    if any(pat.search(description) for pat in _POISONING_PATTERNS):
        return True
    return bool(len(description) > 400 and _LONG_DESC_IMPERATIVE_RE.search(description))


def _read_line_from_disk(base: Path, rel: str, line: int | None) -> str | None:
    if line is None or line < 1:
        return None
    target = base / rel
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if line > len(lines):
        return None
    return lines[line - 1].strip() or "<blank line>"


# --------------------------------------------------------------------------
# enrichment & finding construction
# --------------------------------------------------------------------------
def _enrich_findings(findings: list[StaticFinding], client: Any) -> list[StaticFinding]:
    system_prompt = load_prompt("static_enrichment")
    enriched: list[StaticFinding] = []
    for finding in findings:
        payload = json.dumps(
            {
                "category": finding.category,
                "file": finding.file_path,
                "line": finding.line,
                "evidence": finding.evidence,
            }
        )
        try:
            result = complete_validated(
                EnrichmentSchema,
                client=client,
                system=system_prompt,
                user=payload,
            )
        except LLMError:
            enriched.append(finding)
            continue
        enriched.append(
            finding.model_copy(
                update={
                    "explanation": result.explanation,
                    "recommendation": result.recommendation,
                    "enriched": True,
                }
            )
        )
    return enriched


def _finding(
    category: FindingCategory,
    ctx: _FileCtx,
    node: ast.AST,
    explanation: str,
    recommendation: str,
    *,
    severity: Severity | None = None,
) -> StaticFinding:
    line = getattr(node, "lineno", None)
    return _build_finding(
        category=category,
        severity=severity or _CATEGORY_SEVERITY[category],
        file_path=ctx.rel,
        line=line,
        evidence=_snippet(ctx, line),
        explanation=explanation,
        recommendation=recommendation,
    )


def _build_finding(
    *,
    category: FindingCategory,
    severity: Severity,
    file_path: str,
    line: int | None,
    evidence: str,
    explanation: str,
    recommendation: str,
) -> StaticFinding:
    return StaticFinding(
        category=category,
        severity=severity,
        file_path=file_path,
        line=line,
        evidence=evidence or "<source unavailable>",
        explanation=explanation,
        recommendation=recommendation,
        atlas=_atlas_for(category),
        owasp=_owasp_for(category),
        cwe=_cwe_for(category),
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


def _owasp_for(category: FindingCategory) -> list[OwaspRisk]:
    try:
        from ouroboros.tools.owasp import owasp_for_category
    except ImportError:
        return []
    return owasp_for_category(category)


def _cwe_for(category: FindingCategory) -> list[str]:
    try:
        from ouroboros.tools.owasp import cwe_for_category
    except ImportError:
        return []
    return cwe_for_category(category)


def _dedupe_findings(findings: list[StaticFinding]) -> list[StaticFinding]:
    """Dedupe by (category, file_path, line), keeping the highest-severity entry."""
    best: dict[tuple[FindingCategory, str, int | None], StaticFinding] = {}
    order: list[tuple[FindingCategory, str, int | None]] = []
    for f in findings:
        key = (f.category, f.file_path, f.line)
        if key not in best:
            best[key] = f
            order.append(key)
        elif SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[best[key].severity]:
            best[key] = f
    return [best[k] for k in order]


def _dict_pairs(node: ast.Dict) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for k, v in zip(node.keys, node.values, strict=False):
        key_str = _const_str(k) if k is not None else None
        if key_str is not None:
            out[key_str] = v
    return out


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# --------------------------------------------------------------------------
# file discovery (mirrors recon's skip list)
# --------------------------------------------------------------------------
def _python_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if not any(part in _SKIP_DIRS for part in p.parts)]
