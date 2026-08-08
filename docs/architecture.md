# Architecture

Ouroboros is a pipeline of pure-function agents joined by validated Pydantic v2
contracts. Nothing between stages is free text; if a fact cannot be expressed as
a validated model, it does not cross an agent boundary.

## Flow

```
resolve mode ─▶ Recon ─▶ Static Analyzer ─▶ Dynamic Attacker ─▶ Patch Generator ─▶ Orchestrator ─▶ output
```

1. **Mode resolution** (`github_access.py`) — decides `owner` vs `auditor` from
   confirmed GitHub `push` permission, failing safe to `auditor` on any doubt.
2. **Recon** (`agents/recon.py`) — clones (or reads a local path), detects the
   language/framework, and extracts system prompts and LLM entry points into a
   `RepoProfile`. Deterministic; no model involved.
3. **Static Analyzer** (`agents/static_analyzer.py`) — walks the target's Python
   AST for weak prompt handling and maps each finding to a verified MITRE ATLAS
   technique. Deterministic, with an optional LLM enrichment pass that only adds
   prose and never changes which findings exist.
4. **Dynamic Attacker** (`agents/dynamic_attacker.py`) — *real (weeks 4–5)*.
   Renders the payload library against a fresh canary per payload and sends each
   through the target's recovered system prompt; a returned canary is a hit. It
   **never executes the target's code** — it attacks the reconstructed prompt
   surface, which removes the sandboxing hazard entirely — is rate-limited, opt-in
   (`attack=True`), and never touches production. `--attack` splits by mode:
   **owner** hits a real model (`confirmed_live`); **auditor** hits an offline
   `SimulatedTarget` (`simulation.py`, `simulated`). A `DynamicRunStats` records
   attempts/successes so the run reports a success rate.

   The **SimulatedTarget** is a deterministic, offline stand-in for the target's
   LLM client. It classifies the recovered system prompt's defenses (delimiters,
   instruction hierarchy, refusal) — a static finding that contradicts a defense
   removes it — and answers each payload accordingly: an undefended prompt falls,
   a hardened one resists. So the simulation confirms, offline, what the static
   pass suspected, while its findings stay labelled reduced-confidence.
5. **Patch Generator** (`agents/patch_generator.py`) — *real (week 6)*. Emits a
   `git apply`-clean unified diff per static finding, computed deterministically
   with `difflib` from the real file so it always applies. Each diff inserts a
   marked guardrail (delimiters / instruction hierarchy / output validation) as an
   advisory comment above the offending line.
6. **Orchestrator** (`orchestrator.py`) — acquires the checkout once (`recon.acquire`)
   and holds it open across recon -> static -> dynamic -> patch, then dispatches
   output by mode (`_dispatch_output`) and cleans up. Assembles the `AuditReport`
   and writes Markdown + JSON.
7. **Remediation** (`remediation.py`) — *owner mode, week 7*. `--fix` applies the
   patches to the checkout and commits them on a branch; `--open-pr` pushes and
   opens a PR via PyGithub. Auditor mode is structurally limited to `report`
   (the `AuditReport` fail-safe), handing over the same diffs as suggestions.

## Contracts

`RepoProfile`, `StaticFinding`, `DynamicFinding`, `ProposedPatch`, `AuditReport`
live in `src/ouroboros/schemas/`. The central safety invariant is encoded in
`AuditReport`: an `auditor`-mode report may only carry `applied_action="report"`.

## Configuration

No settings module. Values follow the cascade `explicit arg → OUROBOROS_* env →
default`. A local `.env` is loaded lazily by the CLI (optional; the deterministic
path never depends on it).

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Only for LLM-assisted passes (static enrichment; dynamic, wk 4). |
| `GITHUB_TOKEN` | Lets mode resolution confirm write access. Absent ⇒ auditor. |
| `OUROBOROS_MODEL` | Override the default model id (`claude-sonnet-5`). |
| `OUROBOROS_DATA_DIR` | Override the directory holding `atlas/atlas-techniques.json`. |
