# Architecture

Ouroboros is a pipeline of pure-function agents joined by validated Pydantic v2
contracts. Nothing between stages is free text; if a fact cannot be expressed as
a validated model, it does not cross an agent boundary.

## Flow

```
resolve mode ─▶ Recon ─▶ Static Analyzer ─▶ Dynamic Attacker ─▶ Patch Generator ─▶ [Verify] ─▶ Orchestrator ─▶ output
```

1. **Mode resolution** (`github_access.py`) — decides `owner` vs `auditor` from
   confirmed GitHub `push` permission, failing safe to `auditor` on any doubt.
   Records the repository's `default_branch` when available.
2. **Recon** (`agents/recon.py`) — clones (or reads a local path), detects the
   language/frameworks (Anthropic, OpenAI, Google GenAI, LiteLLM, LangChain,
   LangGraph, LlamaIndex, PydanticAI, CrewAI, AutoGen, OpenAI Agents SDK, MCP),
   extracts system prompts (code literals, `AnnAssign`, fenced Markdown,
   `.txt`/`.prompt`/`.j2` templates, YAML/JSON configs, JS/TS literals), LLM
   entry points, and exposed tools (`ExtractedTool` with inferred capabilities
   and confirmation gates) into `RepoProfile`. Deterministic; no model involved.
3. **Static Analyzer** (`agents/static_analyzer.py`) — runs function-scoped AST
   and taint analysis over Python code, recovered prompts, and tool schemas.
   Emits findings across 9 categories mapped to MITRE ATLAS, OWASP LLM Top 10
   (2025) / Agentic Top 10, and CWEs. An optional LLM enrichment pass
   (`--enrich`) rewrites prose via `complete_validated` without altering which
   findings exist.
4. **Dynamic Attacker** (`agents/dynamic_attacker.py`, `oracles.py`,
   `providers.py`) — loads versioned payload packs (`core`, `extraction`,
   `indirect-bipia`, `tool-hijack`, `soc-blueteam`, `multilingual`,
   `benign-controls`, or user packs), renders fresh per-attempt canaries, sends
   single- or multi-turn campaigns with recovered tool schemas (never executed),
   and evaluates responses with deterministic oracles (`canary`, `extraction`,
   `tool_call`, `exfiltration`, `benign`). Supports optional `--adaptive`
   encoding/framing retries and multiple providers (`anthropic`, `openai` /
   OpenAI-compatible `--base-url`, `gemini`).
   - **owner**: runs against the live configured model (`confirmed_live`).
   - **auditor**: runs against the offline `SimulatedTarget` (`simulation.py`,
     `simulated`), which models multilingual prompt defenses (EN/ES/PT/FR) and
     static contradictions.
5. **Patch Generator** (`agents/patch_generator.py`) — produces per-file
   multi-hunk advisory guardrail diffs and real `prompt_hardening` diffs that
   embed missing defenses directly into extracted system prompts. With
   `--verify-patches`, the orchestrator re-runs the dynamic campaign over the
   hardened prompts and records the `PatchVerification` ASR delta.
6. **Orchestrator & Remediation** (`orchestrator.py`, `remediation.py`) — holds a
   single checkout open across stages, writes Markdown, JSON, and optional SARIF
   2.1.0 (`reporting/`), and in owner mode with `--fix` / `--open-pr` applies
   patches on a collision-free branch and opens a PR against `default_branch`.

## Contracts

`RepoProfile`, `StaticFinding`, `DynamicFinding`, `ProposedPatch`, `AuditReport`,
`PatchVerification` live in `src/ouroboros/schemas/`. The central safety invariant
lives in `AuditReport`: an `auditor`-mode report may only carry
`applied_action="report"`.

## Configuration

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Live Anthropic runs (`--provider anthropic` + `--attack`/`--enrich`). |
| `OPENAI_API_KEY` | Live OpenAI runs (`--provider openai`; optional for local `--base-url`). |
| `GEMINI_API_KEY` | Live Gemini runs (`--provider gemini`). |
| `GITHUB_TOKEN` | Lets mode resolution confirm write access. Absent ⇒ `auditor`. |
| `OUROBOROS_MODEL` | Override the default model id (`claude-sonnet-5`). |
| `OUROBOROS_DATA_DIR` | Override bundled catalogs (`atlas/`, `owasp/`, `payloads/`). |
| `OUROBOROS_PACKS_DIR` | Directory for user-imported payload packs (default `~/.ouroboros/packs`). |
