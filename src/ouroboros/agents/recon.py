"""The Recon Agent: turn a repo reference into a structured ``RepoProfile``.

Recon is deterministic and offline by design — it reads files, it does not ask a
model anything. Given a URL it clones into a temp directory (shallow); given a
local path it reads it in place. It then answers three questions the analyzers
downstream depend on:

  * What is this? — language and agent framework, inferred from files and imports.
  * Where does it talk to an LLM? — console scripts and ``*.messages.create`` call
    sites, the surfaces an attacker aims at.
  * What is it telling the model? — every system prompt it can recover, either
    from a fenced ``text`` block in a prompt file (the convention the sibling
    projects use) or from a string literal handed to ``system=``.

Everything it finds is provenance-tagged, because a prompt read verbatim from a
file and one reconstructed from source do not deserve equal confidence later.
"""

from __future__ import annotations

import ast
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ouroboros.github_access import resolve_mode
from ouroboros.schemas.common import Mode
from ouroboros.schemas.repo_profile import EntryPoint, ExtractedPrompt, RepoProfile

# A zero-arg callable that releases whatever _materialize acquired (a temp
# clone dir, or nothing for a local path).
Cleanup = Callable[[], None]

# A ``text`` fence in a Markdown prompt file — the shape every sibling project
# uses to carry a system prompt verbatim next to its rationale.
_TEXT_FENCE = re.compile(r"```text\n(.*?)```", re.DOTALL)

# How long a string literal has to be before we treat it as a candidate prompt
# rather than an incidental message. Prompts are paragraphs; log lines are not.
_PROMPT_MIN_CHARS = 80

# Framework fingerprints, checked against the set of imported modules.
_FRAMEWORK_HINTS = {
    "anthropic": "anthropic-sdk",
    "langchain": "langchain",
    "langgraph": "langgraph",
    "openai": "openai-sdk",
    "llama_index": "llama-index",
}


class ReconError(RuntimeError):
    """Recon could not read the target at all (bad path, clone failure)."""


@dataclass
class _Scan:
    """Mutable accumulator threaded through the walk over a repo's Python files."""

    prompts: list[ExtractedPrompt] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------
def profile(
    source: str,
    *,
    requested_mode: Mode | None = None,
    token: str | None = None,
    github_client: object | None = None,
) -> RepoProfile:
    """Build a ``RepoProfile`` for ``source`` (a local path or a GitHub URL)."""
    decision = resolve_mode(source, requested=requested_mode, token=token, client=github_client)

    root, is_remote, commit_sha, cleanup = _materialize(source)
    try:
        scan = _walk(root)
        prompts = scan.prompts + _prompts_from_prompt_files(root)
        language = "python" if _has_python(root) else _guess_language(root)
        framework = _pick_framework(scan.frameworks)
        return RepoProfile(
            source=source,
            resolved_mode=decision.mode,
            is_remote=is_remote,
            commit_sha=commit_sha,
            language=language,
            framework=framework,
            entry_points=_dedupe_entry_points(scan.entry_points + _scripts(root)),
            system_prompts=_dedupe_prompts(prompts),
            notes=[f"mode: {decision.reason}"],
        )
    finally:
        cleanup()


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
# walking the code
# --------------------------------------------------------------------------
def _walk(root: Path) -> _Scan:
    scan = _Scan()
    for py in _python_files(root):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        rel = str(py.relative_to(root))
        _collect_frameworks(tree, scan)
        _collect_llm_calls(tree, rel, scan)
        _collect_inline_prompts(tree, rel, scan)
    return scan


def _python_files(root: Path) -> list[Path]:
    skip = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}
    return [p for p in root.rglob("*.py") if not any(part in skip for part in p.parts)]


def _collect_frameworks(tree: ast.AST, scan: _Scan) -> None:
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            head = name.split(".")[0]
            if head in _FRAMEWORK_HINTS:
                scan.frameworks.add(_FRAMEWORK_HINTS[head])


def _collect_llm_calls(tree: ast.AST, rel: str, scan: _Scan) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # match ``<something>.messages.create(...)``
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "messages"
        ):
            scan.entry_points.append(
                EntryPoint(
                    kind="llm_call",
                    location=f"{rel}:{node.lineno}",
                    detail="messages.create",
                )
            )
            _prompt_from_system_kwarg(node, rel, scan)


def _prompt_from_system_kwarg(call: ast.Call, rel: str, scan: _Scan) -> None:
    for kw in call.keywords:
        if kw.arg != "system":
            continue
        text = _string_value(kw.value)
        if text and len(text) >= _PROMPT_MIN_CHARS:
            scan.prompts.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="system-kwarg",
                    text=text,
                    line=getattr(kw.value, "lineno", None),
                )
            )


def _collect_inline_prompts(tree: ast.AST, rel: str, scan: _Scan) -> None:
    """Capture long module-level string constants named like a prompt.

    Assignments such as ``SYSTEM_PROMPT = "..."`` are a common way to hold a
    prompt in source; anything long and named with PROMPT/SYSTEM/INSTRUCTION is a
    candidate worth surfacing for the analyzers.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not any(_looks_like_prompt_name(name) for name in target_names):
            continue
        text = _string_value(node.value)
        if text and len(text) >= _PROMPT_MIN_CHARS:
            scan.prompts.append(
                ExtractedPrompt(
                    file_path=rel,
                    method="assignment",
                    text=text,
                    line=node.lineno,
                )
            )


def _looks_like_prompt_name(name: str) -> bool:
    upper = name.upper()
    return any(token in upper for token in ("PROMPT", "SYSTEM", "INSTRUCTION"))


def _string_value(node: ast.AST) -> str | None:
    """Return the static string a node evaluates to, or ``None`` if not constant.

    Plain string constants and constant ``+`` concatenations resolve; f-strings
    and ``.format`` calls deliberately do not — those are the *unsafe* shapes the
    Static Analyzer wants to flag, not values recon should pretend to know.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left)
        right = _string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


# --------------------------------------------------------------------------
# prompt files (```text``` fences under prompts/)
# --------------------------------------------------------------------------
def _prompts_from_prompt_files(root: Path) -> list[ExtractedPrompt]:
    out: list[ExtractedPrompt] = []
    for md in root.rglob("*.md"):
        if ".git" in md.parts:
            continue
        # Only mine Markdown that plausibly holds a prompt, to avoid slurping the
        # README: a file under a prompts/ dir, or one whose name says so.
        in_prompt_dir = "prompts" in {p.lower() for p in md.parts}
        named_prompt = _looks_like_prompt_name(md.stem)
        if not (in_prompt_dir or named_prompt):
            continue
        match = _TEXT_FENCE.search(md.read_text(encoding="utf-8", errors="replace"))
        if match:
            out.append(
                ExtractedPrompt(
                    file_path=str(md.relative_to(root)),
                    method="text-fence",
                    text=match.group(1).strip(),
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
    return any(True for _ in _python_files(root))


def _guess_language(root: Path) -> str | None:
    for marker, lang in (
        ("package.json", "javascript"),
        ("go.mod", "go"),
        ("Cargo.toml", "rust"),
    ):
        if (root / marker).exists():
            return lang
    return None


def _pick_framework(frameworks: set[str]) -> str | None:
    if not frameworks:
        return None
    # Prefer a concrete agent framework over a bare SDK when both appear.
    for preferred in ("langgraph", "langchain", "llama-index"):
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


def _noop_cleanup() -> None:
    """Cleanup for a local path: there is nothing to remove."""
