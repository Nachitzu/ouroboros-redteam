"""The Recon Agent: turn a repo reference into a structured ``RepoProfile``.

Recon is deterministic and offline by design — it reads files, it does not ask a
model anything. Given a URL it clones into a temp directory (shallow); given a
local path it reads it in place. It then answers four questions the analyzers
downstream depend on:

  * What is this? — language and agent frameworks, inferred from files and imports.
  * Where does it talk to an LLM? — console scripts and multi-SDK LLM call sites,
    the surfaces an attacker aims at.
  * What is it telling the model? — every system prompt it can recover from source
    files (across SDKs, constants, assignments), Markdown, templates, configs, or JS/TS.
  * What tools can the model invoke? — schemas, decorators, and inferred capabilities.

Everything it finds is provenance-tagged, because a prompt read verbatim from a
file and one reconstructed from source do not deserve equal confidence later.
"""

from __future__ import annotations

import ast
import json
import re
import tempfile
import textwrap
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ouroboros.github_access import ModeDecision, resolve_mode
from ouroboros.schemas.common import Mode
from ouroboros.schemas.repo_profile import (
    EntryPoint,
    ExtractedPrompt,
    ExtractedTool,
    RepoProfile,
    ToolCapability,
)

# A zero-arg callable that releases whatever _materialize acquired (a temp
# clone dir, or nothing for a local path).
Cleanup = Callable[[], None]

# A ``text`` fence in a Markdown prompt file — the shape every sibling project
# uses to carry a system prompt verbatim next to its rationale.
_TEXT_FENCE = re.compile(r"```text\n(.*?)```", re.DOTALL)

# How long a string literal has to be before we treat it as a candidate prompt
# rather than an incidental message. Prompts are paragraphs; log lines are not.
_PROMPT_MIN_CHARS = 80

# Maximum size for an unfenced Markdown file under prompts/ to be captured whole.
_MARKDOWN_WHOLE_MAX_CHARS = 8000

# Minimum length for prompts extracted from config/template files.
_CONFIG_PROMPT_MIN_CHARS = 20

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}

# Top-level module prefixes to normalized framework names.
_FRAMEWORK_HINTS: dict[str, str] = {
    "anthropic": "anthropic-sdk",
    "openai": "openai-sdk",
    "litellm": "litellm",
    "langchain": "langchain",
    "langchain_core": "langchain",
    "langchain_openai": "langchain",
    "langchain_anthropic": "langchain",
    "langchain_community": "langchain",
    "langgraph": "langgraph",
    "llama_index": "llama-index",
    "pydantic_ai": "pydantic-ai",
    "crewai": "crewai",
    "autogen": "autogen",
    "autogen_agentchat": "autogen",
    "mcp": "mcp",
    "fastmcp": "mcp",
}

_PREFERRED_FRAMEWORKS = (
    "langgraph",
    "langchain",
    "llama-index",
    "pydantic-ai",
    "crewai",
    "autogen",
    "openai-agents",
    "mcp",
)

_TEMPLATE_SUFFIXES = {".txt", ".prompt", ".j2", ".jinja", ".jinja2"}
_CONFIG_SUFFIXES = {".yaml", ".yml", ".json"}
_CONFIG_PROMPT_KEYS = ("system_prompt", "system", "instructions", "prompt")

_JS_PROMPT_RE = re.compile(
    r"""\b(?:system|instructions)\s*:\s*(['"`])((?:\\.|(?!\1).)*)\1""",
    re.DOTALL,
)

_CONFIRM_KEYWORDS = ("confirm", "approval", "human_in_the_loop")


class ReconError(RuntimeError):
    """Recon could not read the target at all (bad path, clone failure)."""


@dataclass
class _FileImports:
    """Tracks imported SDK names within a single Python file."""

    modules: set[str] = field(default_factory=set)
    openai_agents_imported: bool = False
    litellm_call_names: set[str] = field(default_factory=set)
    pydantic_ai_imported: bool = False
    crewai_imported: bool = False
    langchain_imported: bool = False
    mcp_imported: bool = False
    crewai_agent_names: set[str] = field(default_factory=set)
    pydantic_agent_names: set[str] = field(default_factory=set)
    openai_agent_names: set[str] = field(default_factory=set)


@dataclass
class _Scan:
    """Mutable accumulator threaded through the walk over a repo's files."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    tools: list[ExtractedTool] = field(default_factory=list)


@dataclass
class Checkout:
    """A materialized copy of a target the rest of the pipeline can read and edit.

    Recon used to clone, analyze, and delete in one call, which left nothing on
    disk for the static/patch passes to work on for a remote repo. Splitting the
    checkout out lets the orchestrator hold it open across the whole run (recon ->
    static -> patch -> owner-mode apply/commit/push) and clean it up once at the end.
    """

    root: Path
    is_remote: bool
    commit_sha: str | None
    cleanup: Cleanup


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------
def acquire(
    source: str,
    *,
    requested_mode: Mode | None = None,
    token: str | None = None,
    github_client: object | None = None,
) -> tuple[Checkout, ModeDecision]:
    """Resolve the mode and materialize ``source`` without cleaning it up.

    The caller owns the returned ``Checkout`` and must call ``cleanup()`` when
    done. Use :func:`profile` instead when you only need the profile and want the
    temp clone removed for you.
    """
    decision = resolve_mode(source, requested=requested_mode, token=token, client=github_client)
    root, is_remote, commit_sha, cleanup = _materialize(source)
    return Checkout(root, is_remote, commit_sha, cleanup), decision


def profile_checkout(checkout: Checkout, decision: ModeDecision, source: str) -> RepoProfile:
    """Analyze an already-materialized checkout into a ``RepoProfile``."""
    scan = _walk(checkout.root)
    prompts = (
        scan.prompts
        + _prompts_from_prompt_files(checkout.root)
        + _prompts_from_template_files(checkout.root)
        + _prompts_from_config_files(checkout.root)
        + _prompts_from_js_files(checkout.root)
    )
    language = "python" if _has_python(checkout.root) else _guess_language(checkout.root)
    frameworks = sorted(scan.frameworks)
    framework = _pick_framework(scan.frameworks)
    return RepoProfile(
        source=source,
        resolved_mode=decision.mode,
        is_remote=checkout.is_remote,
        commit_sha=checkout.commit_sha,
        language=language,
        framework=framework,
        frameworks=frameworks,
        entry_points=_dedupe_entry_points(scan.entry_points + _scripts(checkout.root)),
        system_prompts=_dedupe_prompts(prompts),
        tools=_dedupe_tools(scan.tools),
        default_branch=None,
        notes=[f"mode: {decision.reason}"],
    )


def profile(
    source: str,
    *,
    requested_mode: Mode | None = None,
    token: str | None = None,
    github_client: object | None = None,
) -> RepoProfile:
    """Build a ``RepoProfile`` for ``source``, cleaning up any temp clone.

    A thin wrapper over :func:`acquire` + :func:`profile_checkout` for callers that
    do not need to keep the checkout around.
    """
    checkout, decision = acquire(
        source, requested_mode=requested_mode, token=token, github_client=github_client
    )
    try:
        return profile_checkout(checkout, decision, source)
    finally:
        checkout.cleanup()


# --------------------------------------------------------------------------
# acquiring the source
# --------------------------------------------------------------------------
def _materialize(source: str) -> tuple[Path, bool, str | None, Cleanup]:
    """Return a local root for ``source``, whether it was remote, and its HEAD sha.

    Local paths are used in place with a no-op cleanup; URLs are cloned shallow
    into a temp dir whose cleanup removes it.
    """
    if _looks_remote(source):
        return _clone(source)
    path = Path(source).expanduser().resolve()
    if not path.exists():
        raise ReconError(f"target path does not exist: {source}")
    return path, False, _local_head(path), _noop_cleanup


def _looks_remote(source: str) -> bool:
    return source.startswith(("http://", "https://", "git@")) or source.endswith(".git")


def _clone(source: str) -> tuple[Path, bool, str | None, Cleanup]:
    from git import Repo  # lazy: the local-path flow never imports git

    tmp = tempfile.mkdtemp(prefix="ouroboros-recon-")

    def cleanup() -> None:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)

    try:
        repo = Repo.clone_from(source, tmp, depth=1)
        sha = repo.head.commit.hexsha
    except Exception as exc:
        cleanup()
        raise ReconError(f"could not clone {source}: {exc}") from exc
    return Path(tmp), True, sha, cleanup


def _local_head(path: Path) -> str | None:
    try:
        from git import InvalidGitRepositoryError, Repo

        try:
            return Repo(path).head.commit.hexsha
        except (InvalidGitRepositoryError, ValueError):
            return None
    except Exception:
        return None


# --------------------------------------------------------------------------
# walking Python code
# --------------------------------------------------------------------------
def _walk(root: Path) -> _Scan:
    scan = _Scan()
    for py in _python_files(root):
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue
        rel = py.relative_to(root).as_posix()
        imports = _collect_frameworks(tree, scan)
        const_map, ast_map = _collect_constants(tree)
        func_map = _collect_functions(tree)
        _collect_inline_prompts(tree, rel, scan, const_map)
        _collect_llm_calls(tree, rel, scan, imports, const_map, ast_map)
        _collect_tools(tree, rel, source, scan, imports, ast_map, func_map)
    return scan


def _iter_files(root: Path, suffix: str) -> list[Path]:
    return [p for p in root.rglob(f"*{suffix}") if not any(part in _SKIP_DIRS for part in p.parts)]


def _python_files(root: Path) -> list[Path]:
    return _iter_files(root, ".py")


def _collect_frameworks(tree: ast.AST, scan: _Scan) -> _FileImports:
    imports = _FileImports()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _register_import_name(alias.name, scan, imports)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mod = node.module
            imported_names = {alias.name for alias in node.names}
            _register_import_name(mod, scan, imports, imported_names=imported_names)
            if mod == "litellm":
                for alias in node.names:
                    if alias.name in ("completion", "acompletion"):
                        imports.litellm_call_names.add(alias.asname or alias.name)
            elif mod == "agents" and "Agent" in imported_names:
                scan.frameworks.add("openai-agents")
                imports.openai_agents_imported = True
                for alias in node.names:
                    if alias.name == "Agent":
                        imports.openai_agent_names.add(alias.asname or alias.name)
            elif mod == "crewai":
                for alias in node.names:
                    if alias.name == "Agent":
                        imports.crewai_agent_names.add(alias.asname or alias.name)
            elif mod == "pydantic_ai":
                for alias in node.names:
                    if alias.name == "Agent":
                        imports.pydantic_agent_names.add(alias.asname or alias.name)
    return imports


def _register_import_name(
    name: str,
    scan: _Scan,
    imports: _FileImports,
    *,
    imported_names: set[str] | None = None,
) -> None:
    imports.modules.add(name)
    head = name.split(".")[0]
    if head in _FRAMEWORK_HINTS:
        fw = _FRAMEWORK_HINTS[head]
        scan.frameworks.add(fw)
        if fw == "pydantic-ai":
            imports.pydantic_ai_imported = True
        elif fw == "crewai":
            imports.crewai_imported = True
        elif fw == "langchain":
            imports.langchain_imported = True
        elif fw == "mcp":
            imports.mcp_imported = True
    if name.startswith(("google.genai", "google.generativeai")) or (
        name == "google" and imported_names and bool(imported_names & {"genai", "generativeai"})
    ):
        scan.frameworks.add("google-genai")


def _collect_constants(tree: ast.AST) -> tuple[dict[str, str], dict[str, ast.AST]]:
    """Collect static string constants and expression assignments across the module."""
    str_map: dict[str, str] = {}
    ast_map: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    ast_map[target.id] = node.value
                    val = _string_value(node.value, str_map)
                    if val is not None:
                        str_map[target.id] = val
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            ast_map[node.target.id] = node.value
            val = _string_value(node.value, str_map)
            if val is not None:
                str_map[node.target.id] = val
    return str_map, ast_map


def _collect_functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node
    return funcs


def _collect_inline_prompts(
    tree: ast.AST, rel: str, scan: _Scan, const_map: dict[str, str]
) -> None:
    """Capture long constant strings assigned to prompt-like names (Assign & AnnAssign)."""
    for node in ast.walk(tree):
        names: list[str] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            names = [node.target.id]
            value = node.value
        if value is None or not any(_looks_like_prompt_name(n) for n in names):
            continue
        text = _string_value(value, const_map)
        if text and len(text) >= _PROMPT_MIN_CHARS:
            scan.prompts.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="assignment",
                    text=text,
                    line=getattr(node, "lineno", None),
                )
            )


def _collect_llm_calls(
    tree: ast.AST,
    rel: str,
    scan: _Scan,
    imports: _FileImports,
    const_map: dict[str, str],
    ast_map: dict[str, ast.AST],
) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sdk = _classify_llm_call(node, imports)
        if sdk is not None:
            scan.entry_points.append(
                EntryPoint(
                    kind="llm_call",
                    location=f"{rel}:{node.lineno}",
                    detail=sdk,
                )
            )
            _extract_call_prompts(node, sdk, rel, scan, const_map, ast_map)
            continue
        # Non-call prompt constructors (LangChain SystemMessage / ChatPromptTemplate).
        _extract_langchain_prompt_constructors(node, rel, scan, const_map)


def _classify_llm_call(call: ast.Call, imports: _FileImports) -> str | None:
    """Identify supported SDK LLM/agent call sites, returning a descriptive detail string."""
    func = call.func
    if isinstance(func, ast.Attribute):
        # Anthropic: *.messages.create / *.messages.stream
        if (
            func.attr in ("create", "stream")
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "messages"
        ):
            return f"messages.{func.attr}"
        # OpenAI: *.chat.completions.create
        if (
            func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "completions"
            and isinstance(func.value.value, ast.Attribute)
            and func.value.value.attr == "chat"
        ):
            return "chat.completions.create"
        # OpenAI Responses: *.responses.create
        if (
            func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "responses"
        ):
            return "responses.create"
        # Google GenAI: *.models.generate_content / generate_content_stream
        if (
            func.attr in ("generate_content", "generate_content_stream")
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "models"
        ):
            return f"models.{func.attr}"
        # LiteLLM: litellm.completion / litellm.acompletion
        if (
            func.attr in ("completion", "acompletion")
            and isinstance(func.value, ast.Name)
            and func.value.id == "litellm"
        ):
            return f"litellm.{func.attr}"
        # Qualified LangGraph / Agent calls
        if func.attr == "create_react_agent":
            return "langgraph.create_react_agent"
        if func.attr == "Agent":
            return _classify_agent_call(call, imports)

    if isinstance(func, ast.Name):
        if func.id in imports.litellm_call_names:
            return f"litellm.{func.id}"
        if func.id == "create_react_agent":
            return "langgraph.create_react_agent"
        if func.id == "Agent" or func.id in (
            imports.crewai_agent_names | imports.pydantic_agent_names | imports.openai_agent_names
        ):
            return _classify_agent_call(call, imports, func.id)
    return None


def _classify_agent_call(
    call: ast.Call, imports: _FileImports, call_name: str | None = None
) -> str | None:
    kw_names = {kw.arg for kw in call.keywords if kw.arg}
    if call_name and call_name in imports.crewai_agent_names:
        return "crewai.Agent"
    if call_name and call_name in imports.pydantic_agent_names:
        return "pydantic_ai.Agent"
    if call_name and call_name in imports.openai_agent_names:
        return "agents.Agent"
    if "role" in kw_names and bool(kw_names & {"goal", "backstory"}):
        return "crewai.Agent"
    if "system_prompt" in kw_names:
        return "pydantic_ai.Agent"
    if "instructions" in kw_names:
        if imports.openai_agents_imported:
            return "agents.Agent"
        if imports.pydantic_ai_imported:
            return "pydantic_ai.Agent"
        return "agents.Agent"
    if imports.crewai_imported:
        return "crewai.Agent"
    if imports.pydantic_ai_imported:
        return "pydantic_ai.Agent"
    if imports.openai_agents_imported:
        return "agents.Agent"
    return None


def _extract_call_prompts(
    call: ast.Call,
    sdk: str,
    rel: str,
    scan: _Scan,
    const_map: dict[str, str],
    ast_map: dict[str, ast.AST],
) -> None:
    kw_map = {kw.arg: kw.value for kw in call.keywords if kw.arg}

    if sdk.startswith("messages.") and "system" in kw_map:
        _maybe_add_prompt(kw_map["system"], rel, "system-kwarg", scan, const_map)

    if (
        sdk in ("chat.completions.create", "litellm.completion", "litellm.acompletion")
        and "messages" in kw_map
    ):
        _extract_from_messages_list(kw_map["messages"], rel, scan, const_map, ast_map)

    if sdk == "responses.create":
        if "instructions" in kw_map:
            _maybe_add_prompt(kw_map["instructions"], rel, "instructions-kwarg", scan, const_map)
        if "input" in kw_map:
            _extract_from_messages_list(kw_map["input"], rel, scan, const_map, ast_map)

    if sdk.startswith("models.generate_content"):
        if "system_instruction" in kw_map:
            _maybe_add_prompt(
                kw_map["system_instruction"], rel, "system-instruction", scan, const_map
            )
        if "config" in kw_map:
            _extract_gemini_config_prompt(kw_map["config"], rel, scan, const_map, ast_map)

    if sdk == "langgraph.create_react_agent":
        for key in ("prompt", "state_modifier"):
            if key in kw_map:
                _maybe_add_prompt(kw_map[key], rel, "agent-prompt", scan, const_map)

    if sdk == "pydantic_ai.Agent":
        for key in ("system_prompt", "instructions"):
            if key in kw_map:
                _maybe_add_prompt(kw_map[key], rel, "agent-config", scan, const_map)

    if sdk == "agents.Agent" and "instructions" in kw_map:
        _maybe_add_prompt(kw_map["instructions"], rel, "agent-config", scan, const_map)

    if sdk == "crewai.Agent":
        parts: list[str] = []
        line: int | None = call.lineno
        for label, key in (("Role", "role"), ("Goal", "goal"), ("Backstory", "backstory")):
            if key in kw_map:
                text = _string_value(kw_map[key], const_map)
                if text:
                    parts.append(f"{label}: {text.strip()}")
        combined = "\n".join(parts)
        if len(combined) >= _PROMPT_MIN_CHARS:
            scan.prompts.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="agent-config",
                    text=combined,
                    line=line,
                )
            )


def _extract_from_messages_list(
    node: ast.AST,
    rel: str,
    scan: _Scan,
    const_map: dict[str, str],
    ast_map: dict[str, ast.AST],
) -> None:
    resolved = _resolve_ast(node, ast_map)
    if not isinstance(resolved, (ast.List, ast.Tuple)):
        return
    for item in resolved.elts:
        item_node = _resolve_ast(item, ast_map)
        if not isinstance(item_node, ast.Dict):
            continue
        pairs = _dict_str_key_nodes(item_node)
        role_node = pairs.get("role")
        content_node = pairs.get("content")
        if role_node is None or content_node is None:
            continue
        role = _string_value(role_node, const_map)
        if role in ("system", "developer"):
            _maybe_add_prompt(content_node, rel, "system-message", scan, const_map)


def _extract_gemini_config_prompt(
    node: ast.AST,
    rel: str,
    scan: _Scan,
    const_map: dict[str, str],
    ast_map: dict[str, ast.AST],
) -> None:
    resolved = _resolve_ast(node, ast_map)
    if isinstance(resolved, ast.Call):
        for kw in resolved.keywords:
            if kw.arg == "system_instruction":
                _maybe_add_prompt(kw.value, rel, "system-instruction", scan, const_map)
    elif isinstance(resolved, ast.Dict):
        pairs = _dict_str_key_nodes(resolved)
        if "system_instruction" in pairs:
            _maybe_add_prompt(
                pairs["system_instruction"], rel, "system-instruction", scan, const_map
            )


def _extract_langchain_prompt_constructors(
    call: ast.Call, rel: str, scan: _Scan, const_map: dict[str, str]
) -> None:
    func = call.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else func.attr
        if isinstance(func, ast.Attribute)
        else None
    )
    if name == "SystemMessage":
        target_node: ast.AST | None = None
        for kw in call.keywords:
            if kw.arg == "content":
                target_node = kw.value
                break
        if target_node is None and call.args:
            target_node = call.args[0]
        if target_node is not None:
            _maybe_add_prompt(target_node, rel, "system-message", scan, const_map)
        return

    if (
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
                    role = _string_value(elt.elts[0], const_map)
                    if role in ("system", "developer"):
                        _maybe_add_prompt(elt.elts[1], rel, "chat-template", scan, const_map)
                elif isinstance(elt, ast.Dict):
                    pairs = _dict_str_key_nodes(elt)
                    role_node = pairs.get("role")
                    content_node = pairs.get("content")
                    if role_node is not None and content_node is not None:
                        role = _string_value(role_node, const_map)
                        if role in ("system", "developer"):
                            _maybe_add_prompt(content_node, rel, "chat-template", scan, const_map)


def _maybe_add_prompt(
    node: ast.AST,
    rel: str,
    method: str,
    scan: _Scan,
    const_map: dict[str, str],
) -> None:
    if isinstance(node, (ast.List, ast.Tuple)):
        parts = [_string_value(elt, const_map) for elt in node.elts]
        valid = [p for p in parts if p is not None]
        if valid and len(valid) == len(node.elts):
            joined = "\n".join(valid)
            if len(joined) >= _PROMPT_MIN_CHARS:
                scan.prompts.append(
                    ExtractedPrompt(
                        file_path=rel,
                        method=method,
                        text=joined,
                        line=getattr(node, "lineno", None),
                    )
                )
        return
    text = _string_value(node, const_map)
    if text and len(text) >= _PROMPT_MIN_CHARS:
        scan.prompts.append(
            ExtractedPrompt(
                file_path=rel,
                method=method,
                text=text,
                line=getattr(node, "lineno", None),
            )
        )


def _resolve_ast(node: ast.AST, ast_map: dict[str, ast.AST], max_hops: int = 3) -> ast.AST:
    cur = node
    seen: set[str] = set()
    for _ in range(max_hops):
        if isinstance(cur, ast.Name) and cur.id in ast_map and cur.id not in seen:
            seen.add(cur.id)
            cur = ast_map[cur.id]
        else:
            break
    return cur


def _dict_str_key_nodes(node: ast.Dict) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for k, v in zip(node.keys, node.values, strict=False):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            out[k.value] = v
    return out


# --------------------------------------------------------------------------
# tool surface extraction
# --------------------------------------------------------------------------
def _collect_tools(
    tree: ast.AST,
    rel: str,
    source: str,
    scan: _Scan,
    imports: _FileImports,
    ast_map: dict[str, ast.AST],
    func_map: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> None:
    lines = source.splitlines()
    for node in ast.walk(tree):
        # 1. Decorated tool functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _tool_from_decorated_func(node, rel, lines, imports)
            if tool is not None:
                scan.tools.append(tool)
            continue

        # 2. Variable assignments to *tools* holding dict schemas
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any("tool" in name.lower() for name in target_names):
                _extract_tools_from_sequence(node.value, rel, scan, ast_map)
            continue

        # 3. Call-based tools: tools=[...], StructuredTool.from_function, Tool, FunctionDeclaration
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "tools":
                    _extract_tools_from_sequence(kw.value, rel, scan, ast_map)
            tool = _tool_from_call(node, rel, lines, func_map)
            if tool is not None:
                scan.tools.append(tool)


def _tool_from_decorated_func(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    lines: list[str],
    imports: _FileImports,
) -> ExtractedTool | None:
    tool_source: str | None = None
    explicit_name: str | None = None
    explicit_desc: str | None = None

    for dec in fn.decorator_list:
        dec_call = dec if isinstance(dec, ast.Call) else None
        dec_target = dec_call.func if dec_call else dec

        if isinstance(dec_target, ast.Name):
            if dec_target.id == "tool":
                tool_source = "langchain-tool" if imports.langchain_imported else "decorator-tool"
            elif dec_target.id == "function_tool":
                tool_source = "openai-agents-tool"
        elif isinstance(dec_target, ast.Attribute):
            recv = dec_target.value
            recv_name = recv.id if isinstance(recv, ast.Name) else ""
            if dec_target.attr == "tool" and (
                recv_name in ("mcp", "server", "app", "fastmcp") or imports.mcp_imported
            ):
                if recv_name in ("agent",) and imports.pydantic_ai_imported:
                    tool_source = "pydantic-ai-tool"
                elif recv_name in ("mcp", "server", "app", "fastmcp") or imports.mcp_imported:
                    tool_source = "mcp-decorator"
                else:
                    tool_source = "decorator-tool"
            elif dec_target.attr in ("tool", "tool_plain") and (
                recv_name == "agent" or imports.pydantic_ai_imported
            ):
                tool_source = "pydantic-ai-tool"
            elif dec_target.attr == "tool" and imports.langchain_imported:
                tool_source = "langchain-tool"

        if tool_source is not None:
            if dec_call is not None:
                if dec_call.args:
                    arg0 = _string_value(dec_call.args[0])
                    if arg0:
                        explicit_name = arg0
                for kw in dec_call.keywords:
                    if kw.arg == "name":
                        val = _string_value(kw.value)
                        if val:
                            explicit_name = val
                    elif kw.arg == "description":
                        val = _string_value(kw.value)
                        if val:
                            explicit_desc = val
            break

    if tool_source is None:
        return None

    name = explicit_name or fn.name
    description = explicit_desc if explicit_desc is not None else (ast.get_docstring(fn) or "")
    body_text = _node_source(fn, lines)
    capabilities = _infer_capabilities(
        name=name, description=description, body_ast=fn, body_text=body_text
    )
    requires_confirmation = _detect_confirmation(
        description=description, body_ast=fn, body_text=body_text
    )
    return ExtractedTool(
        name=name,
        description=description,
        file_path=rel,
        line=fn.lineno,
        source=tool_source,
        parameters=_params_from_func(fn),
        capabilities=capabilities,
        requires_confirmation=requires_confirmation,
    )


def _extract_tools_from_sequence(
    node: ast.AST,
    rel: str,
    scan: _Scan,
    ast_map: dict[str, ast.AST],
) -> None:
    resolved = _resolve_ast(node, ast_map)
    if not isinstance(resolved, (ast.List, ast.Tuple)):
        return
    for item in resolved.elts:
        item_node = _resolve_ast(item, ast_map)
        if not isinstance(item_node, ast.Dict):
            continue
        tool = _tool_from_schema_dict(item_node, rel)
        if tool is not None:
            scan.tools.append(tool)


def _tool_from_schema_dict(node: ast.Dict, rel: str) -> ExtractedTool | None:
    pairs = _dict_str_key_nodes(node)
    # OpenAI style: {"type": "function", "function": {"name", "description", "parameters"}}
    if "type" in pairs and "function" in pairs:
        kind = _string_value(pairs["type"])
        fn_node = pairs["function"]
        if kind == "function" and isinstance(fn_node, ast.Dict):
            fn_pairs = _dict_str_key_nodes(fn_node)
            name = _string_value(fn_pairs["name"]) if "name" in fn_pairs else None
            if name:
                desc = _string_value(fn_pairs["description"]) if "description" in fn_pairs else ""
                desc = desc or ""
                params = _literal_dict(fn_pairs.get("parameters"))
                return ExtractedTool(
                    name=name,
                    description=desc,
                    file_path=rel,
                    line=node.lineno,
                    source="openai-schema",
                    parameters=params,
                    capabilities=_infer_capabilities(name=name, description=desc),
                    requires_confirmation=_detect_confirmation(description=desc),
                )

    # Anthropic style: {"name": ..., "description": ..., "input_schema": {...}}
    if "name" in pairs and "input_schema" in pairs:
        name = _string_value(pairs["name"])
        if name:
            desc = _string_value(pairs["description"]) if "description" in pairs else ""
            desc = desc or ""
            params = _literal_dict(pairs.get("input_schema"))
            return ExtractedTool(
                name=name,
                description=desc,
                file_path=rel,
                line=node.lineno,
                source="anthropic-schema",
                parameters=params,
                capabilities=_infer_capabilities(name=name, description=desc),
                requires_confirmation=_detect_confirmation(description=desc),
            )
    return None


def _tool_from_call(
    call: ast.Call,
    rel: str,
    lines: list[str],
    func_map: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> ExtractedTool | None:
    func = call.func
    kw_map = {kw.arg: kw.value for kw in call.keywords if kw.arg}

    # StructuredTool.from_function(...)
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "from_function"
        and isinstance(func.value, ast.Name)
        and func.value.id == "StructuredTool"
    ):
        return _langchain_tool_from_call(call, kw_map, rel, lines, func_map)

    # Tool(name=..., func=...)
    if isinstance(func, ast.Name) and func.id == "Tool" and "name" in kw_map and "func" in kw_map:
        return _langchain_tool_from_call(call, kw_map, rel, lines, func_map)

    # Gemini FunctionDeclaration(name=..., description=..., parameters=...)
    is_func_decl = (isinstance(func, ast.Name) and func.id == "FunctionDeclaration") or (
        isinstance(func, ast.Attribute) and func.attr == "FunctionDeclaration"
    )
    if is_func_decl and "name" in kw_map:
        name = _string_value(kw_map["name"])
        if name:
            desc = _string_value(kw_map["description"]) if "description" in kw_map else ""
            desc = desc or ""
            params = _literal_dict(kw_map.get("parameters"))
            return ExtractedTool(
                name=name,
                description=desc,
                file_path=rel,
                line=call.lineno,
                source="gemini-declaration",
                parameters=params,
                capabilities=_infer_capabilities(name=name, description=desc),
                requires_confirmation=_detect_confirmation(description=desc),
            )
    return None


def _langchain_tool_from_call(
    call: ast.Call,
    kw_map: Mapping[str, ast.AST],
    rel: str,
    lines: list[str],
    func_map: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> ExtractedTool | None:
    func_node = kw_map.get("func") or (call.args[0] if call.args else None)
    fn_def = func_map.get(func_node.id) if isinstance(func_node, ast.Name) else None
    name = _string_value(kw_map["name"]) if "name" in kw_map else None
    if not name and isinstance(func_node, ast.Name):
        name = func_node.id
    if not name:
        return None
    desc = _string_value(kw_map["description"]) if "description" in kw_map else None
    if desc is None and fn_def is not None:
        desc = ast.get_docstring(fn_def)
    desc = desc or ""
    body_text = _node_source(fn_def, lines) if fn_def is not None else ""
    return ExtractedTool(
        name=name,
        description=desc,
        file_path=rel,
        line=call.lineno,
        source="langchain-tool",
        parameters=_params_from_func(fn_def) if fn_def is not None else {},
        capabilities=_infer_capabilities(
            name=name, description=desc, body_ast=fn_def, body_text=body_text
        ),
        requires_confirmation=_detect_confirmation(
            description=desc, body_ast=fn_def, body_text=body_text
        ),
    )


def _params_from_func(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    props: dict[str, Any] = {}
    for arg in fn.args.args:
        if arg.arg in ("self", "cls", "ctx"):
            continue
        props[arg.arg] = {"type": "string"}
    if not props:
        return {}
    return {"type": "object", "properties": props}


def _literal_dict(node: ast.AST | None) -> dict[str, Any]:
    if node is None:
        return {}
    try:
        val = ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return {}
    return val if isinstance(val, dict) else {}


def _node_source(node: ast.AST, lines: list[str]) -> str:
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start is None or end is None:
        return ""
    return "\n".join(lines[max(0, start - 1) : min(len(lines), end)])


def _infer_capabilities(
    *,
    name: str,
    description: str,
    body_ast: ast.AST | None = None,
    body_text: str = "",
) -> list[ToolCapability]:
    caps: list[ToolCapability] = []
    meta_text = f"{name} {description}".lower()
    combined = f"{meta_text}\n{body_text.lower()}"

    def add(cap: ToolCapability) -> None:
        if cap not in caps:
            caps.append(cap)

    if any(tok in combined for tok in ("subprocess", "os.system", "os.popen")) or re.search(
        r"\b(?:shell|bash|zsh|powershell|cmd)\b", combined
    ):
        add("shell")

    if any(tok in combined for tok in ("requests", "httpx", "urllib", "aiohttp")):
        add("network")

    has_write_open = False
    has_read_open = False
    has_eval_exec = False
    if body_ast is not None:
        for sub in ast.walk(body_ast):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Name) and sub.func.id in ("eval", "exec"):
                    has_eval_exec = True
                if (isinstance(sub.func, ast.Name) and sub.func.id == "open") or (
                    isinstance(sub.func, ast.Attribute) and sub.func.attr == "open"
                ):
                    mode = _open_mode(sub)
                    if mode and any(m in mode for m in ("w", "a", "x", "+")):
                        has_write_open = True
                    else:
                        has_read_open = True

    if has_write_open or any(
        tok in combined
        for tok in ("write_text", "write_bytes", "shutil.rmtree", "os.remove", "os.unlink")
    ):
        add("filesystem_write")

    if (
        has_read_open
        or any(tok in combined for tok in ("read_text", "read_bytes"))
        or re.search(r"\bopen\s*\(", body_text)
    ):
        add("filesystem_read")

    if any(tok in combined for tok in ("sqlite3", "cursor.execute", "sqlalchemy")):
        add("database")

    if any(tok in combined for tok in ("smtplib", "send_email", "sendmail")):
        add("email")

    if has_eval_exec or re.search(r"\b(?:eval|exec)\s*\(", body_text):
        add("code_exec")

    if re.search(r"\b(?:stripe|payment|transfer)\b", combined):
        add("payment")

    return caps


def _open_mode(call: ast.Call) -> str:
    if (
        len(call.args) >= 2
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    ):
        return call.args[1].value
    for kw in call.keywords:
        if (
            kw.arg == "mode"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            return kw.value.value
    return ""


def _detect_confirmation(
    *,
    description: str,
    body_ast: ast.AST | None = None,
    body_text: str = "",
) -> bool:
    combined_lower = f"{description}\n{body_text}".lower()
    if any(kw in combined_lower for kw in _CONFIRM_KEYWORDS):
        return True
    if body_ast is not None:
        for sub in ast.walk(body_ast):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Name) and sub.func.id in ("input", "interrupt"):
                    return True
                if isinstance(sub.func, ast.Attribute) and sub.func.attr == "interrupt":
                    return True
    return False


def _looks_like_prompt_name(name: str) -> bool:
    upper = name.upper()
    return any(token in upper for token in ("PROMPT", "SYSTEM", "INSTRUCTION"))


def _string_value(node: ast.AST, const_map: dict[str, str] | None = None) -> str | None:
    """Return the static string a node evaluates to, or ``None`` if not constant.

    Plain string constants, implicit concatenations, constant ``+``
    concatenations, ``textwrap.dedent(...)`` (and ``.strip()``) resolve;
    f-strings and ``.format`` calls deliberately do not — those are the
    *unsafe* shapes the Static Analyzer wants to flag.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if const_map and isinstance(node, ast.Name) and node.id in const_map:
        return const_map[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left, const_map)
        right = _string_value(node.right, const_map)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.Call):
        func = node.func
        is_dedent = (isinstance(func, ast.Name) and func.id == "dedent") or (
            isinstance(func, ast.Attribute)
            and func.attr == "dedent"
            and isinstance(func.value, ast.Name)
            and func.value.id == "textwrap"
        )
        if is_dedent and len(node.args) == 1 and not node.keywords:
            inner = _string_value(node.args[0], const_map)
            if inner is not None:
                return textwrap.dedent(inner)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "strip"
            and not node.args
            and not node.keywords
        ):
            inner = _string_value(func.value, const_map)
            if inner is not None:
                return inner.strip()
    return None


# --------------------------------------------------------------------------
# prompt files (Markdown, templates, YAML/JSON configs, JS/TS)
# --------------------------------------------------------------------------
def _prompts_from_prompt_files(root: Path) -> list[ExtractedPrompt]:
    out: list[ExtractedPrompt] = []
    for md in _iter_files(root, ".md"):
        in_prompt_dir = "prompts" in {p.lower() for p in md.parts}
        named_prompt = _looks_like_prompt_name(md.stem)
        if not (in_prompt_dir or named_prompt):
            continue
        raw = md.read_text(encoding="utf-8", errors="replace")
        rel = md.relative_to(root).as_posix()
        match = _TEXT_FENCE.search(raw)
        if match:
            line = raw[: match.start()].count("\n") + 1
            out.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="text-fence",
                    text=match.group(1).strip(),
                    line=line,
                )
            )
        elif in_prompt_dir:
            stripped = raw.strip()
            if 0 < len(stripped) <= _MARKDOWN_WHOLE_MAX_CHARS:
                out.append(
                    ExtractedPrompt(
                        file_path=rel,
                        method="markdown-file",
                        text=stripped,
                        line=1,
                    )
                )
    return out


def _prompts_from_template_files(root: Path) -> list[ExtractedPrompt]:
    out: list[ExtractedPrompt] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _TEMPLATE_SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        if not _looks_like_prompt_name(rel):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if text:
            out.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="template-file",
                    text=text,
                    line=1,
                )
            )
    return out


def _prompts_from_config_files(root: Path) -> list[ExtractedPrompt]:
    out: list[ExtractedPrompt] = []
    yaml_mod = _optional_yaml()
    for path in root.rglob("*"):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in _CONFIG_SUFFIXES:
            continue
        in_prompt_dir = "prompts" in {p.lower() for p in path.parts}
        stem_lower = path.stem.lower()
        named_config = any(tok in stem_lower for tok in ("prompt", "agent"))
        if not (in_prompt_dir or named_config):
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        data: Any = None
        if suffix == ".json":
            try:
                data = json.loads(raw)
            except ValueError:
                continue
        else:
            if yaml_mod is None:
                continue
            try:
                data = yaml_mod.safe_load(raw)
            except Exception:
                continue
        rel = path.relative_to(root).as_posix()
        for key, text in _walk_config_prompts(data):
            if len(text.strip()) >= _CONFIG_PROMPT_MIN_CHARS:
                out.append(
                    ExtractedPrompt(
                        file_path=rel,
                        method="config-file",
                        text=text.strip(),
                        line=_find_key_line(raw, key),
                    )
                )
    return out


def _optional_yaml() -> Any | None:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None
    return yaml


def _walk_config_prompts(obj: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(key, str) and key.lower() in _CONFIG_PROMPT_KEYS and isinstance(val, str):
                found.append((key, val))
            else:
                found.extend(_walk_config_prompts(val))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_config_prompts(item))
    return found


def _find_key_line(raw: str, key: str) -> int | None:
    pattern = re.compile(rf"""(?:^|\s)['"]?{re.escape(key)}['"]?\s*:""")
    for idx, line in enumerate(raw.splitlines(), start=1):
        if pattern.search(line):
            return idx
    return 1


def _prompts_from_js_files(root: Path) -> list[ExtractedPrompt]:
    out: list[ExtractedPrompt] = []
    for suffix in (".ts", ".tsx", ".js", ".jsx"):
        for path in _iter_files(root, suffix):
            raw = path.read_text(encoding="utf-8", errors="replace")
            rel = path.relative_to(root).as_posix()
            for match in _JS_PROMPT_RE.finditer(raw):
                text = match.group(2)
                if len(text) >= _PROMPT_MIN_CHARS:
                    line = raw[: match.start()].count("\n") + 1
                    out.append(
                        ExtractedPrompt(
                            file_path=rel,
                            method="js-literal",
                            text=text,
                            line=line,
                        )
                    )
    return out


# --------------------------------------------------------------------------
# pyproject console scripts
# --------------------------------------------------------------------------
def _scripts(root: Path) -> list[EntryPoint]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return []
    try:
        import tomllib

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return []
    scripts = data.get("project", {}).get("scripts", {})
    return [
        EntryPoint(kind="console_script", location=target, detail=name)
        for name, target in scripts.items()
    ]


# --------------------------------------------------------------------------
# language / framework helpers
# --------------------------------------------------------------------------
def _has_python(root: Path) -> bool:
    return bool(_python_files(root))


def _guess_language(root: Path) -> str | None:
    if (root / "tsconfig.json").exists() or _iter_files(root, ".ts") or _iter_files(root, ".tsx"):
        return "typescript"
    if (root / "package.json").exists() or _iter_files(root, ".js") or _iter_files(root, ".jsx"):
        return "javascript"
    for marker, lang in (
        ("go.mod", "go"),
        ("Cargo.toml", "rust"),
    ):
        if (root / marker).exists():
            return lang
    return None


def _pick_framework(frameworks: set[str]) -> str | None:
    if not frameworks:
        return None
    for preferred in _PREFERRED_FRAMEWORKS:
        if preferred in frameworks:
            return preferred
    return sorted(frameworks)[0]


# --------------------------------------------------------------------------
# dedupe
# --------------------------------------------------------------------------
def _dedupe_prompts(prompts: list[ExtractedPrompt]) -> list[ExtractedPrompt]:
    seen: set[tuple[str, str]] = set()
    out: list[ExtractedPrompt] = []
    for p in prompts:
        key = (p.file_path, p.text)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _dedupe_entry_points(points: list[EntryPoint]) -> list[EntryPoint]:
    seen: set[tuple[str, str]] = set()
    out: list[EntryPoint] = []
    for e in points:
        key = (e.kind, e.location)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def _dedupe_tools(tools: list[ExtractedTool]) -> list[ExtractedTool]:
    seen: set[tuple[str, str, int | None]] = set()
    out: list[ExtractedTool] = []
    for t in tools:
        key = (t.file_path, t.name, t.line)
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


def _noop_cleanup() -> None:
    """Cleanup for a local path: there is nothing to remove."""
