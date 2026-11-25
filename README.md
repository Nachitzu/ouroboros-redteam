<h1 align="center">Ouroboros Red Team</h1>

<p align="center">
  <em>An AI agent that red-teams AI agents — <code>prompt-injection-redteam-agent</code>.<br>
  It audits, attacks, verifies, and patches the very LLM agents its author builds.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/validation-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-166%20passing-2EA043">
  <img alt="Coverage" src="https://img.shields.io/badge/coverage-89%25-2EA043">
  <img alt="MITRE ATLAS" src="https://img.shields.io/badge/mapped%20to-MITRE%20ATLAS-8A2BE2">
  <img alt="OWASP LLM 2025" src="https://img.shields.io/badge/OWASP-LLM%20%26%20Agentic-orange">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center">English · <a href="README.es.md">Español</a></p>

---

## Overview

Ouroboros Red Team is a multi-stage agent that analyzes LLM-based agents for
prompt-injection and agentic security weaknesses, tests them with curated
canary-oracle payload packs, verifies prompt-hardening patches against the
attack suite, and emits SARIF 2.1.0, Markdown, JSON, and PR-ready guardrail diffs.

> **The Ouroboros** — the snake that eats its own tail — is the perfect image for
> an agent that audits and attacks the other agents you built yourself: a system
> that examines itself. That is exactly what this tool does.

**Author:** Nachitzu — AI Security Engineer, Blue Team + AI agent architecture.

---

## Capabilities

- **Multi-SDK Recon (`recon.py`):** Detects Anthropic, OpenAI, Google GenAI,
  LiteLLM, LangChain, LangGraph, LlamaIndex, PydanticAI, CrewAI, AutoGen, OpenAI
  Agents SDK, and MCP servers; extracts prompts from code, `AnnAssign`,
  Markdown fences, `.txt`/`.prompt`/`.j2` templates, YAML/JSON configs, and
  JS/TS literals; inventories exposed tools with inferred capabilities and
  confirmation gates.
- **Function-scoped Static & Taint Analyzer (`static_analyzer.py`):** Detects 9
  weakness categories (`direct_interpolation`, `missing_delimiters`,
  `no_output_validation`, `no_instruction_hierarchy`, `untrusted_tool_output`,
  `improper_output_handling`, `excessive_agency`, `mcp_tool_poisoning`,
  `prompt_leakage_risk`) mapped to MITRE ATLAS, OWASP LLM 2025 / Agentic Top 10,
  and CWEs. Optional `--enrich` LLM prose pass.
- **Dynamic Attacker & Deterministic Oracles (`dynamic_attacker.py`, `oracles.py`, `providers.py`):**
  Multi-turn & tool-schema attacks (tools are *never* executed) judged by
  deterministic oracles (`canary`, `extraction`, `tool_call`, `exfiltration`,
  `benign` over-refusal controls), optional `--adaptive` encoding/framing retries,
  and support for Anthropic, OpenAI / OpenAI-compatible (`--base-url`), Gemini,
  and the offline multilingual `SimulatedTarget` (`simulation.py`).
- **7 Built-in Payload Packs (132 probes):** `core`, `extraction`,
  `indirect-bipia`, `tool-hijack`, `soc-blueteam`, `multilingual`, and
  `benign-controls`, plus a dataset importer (`ouroboros-tool datasets import`).
  See [`docs/datasets.md`](docs/datasets.md).
- **Prompt Hardening, Verification & CI Integration:** Per-file multi-hunk
  advisory diffs plus real `prompt_hardening` rewrites (`patch_generator.py`),
  closed-loop `--verify-patches` ASR comparison, `--sarif` 2.1.0 output,
  `--fail-on` / `--fail-on-asr` CI gates, `ouroboros diff`, and owner-mode
  collision-free branches + PRs targeting `default_branch`.

166 unit tests passing (1 optional sibling-repo test skipped), 89% statement
coverage on `src/ouroboros/`. No test reaches a live API or GitHub.

---

## Quickstart

```bash
git clone https://github.com/Nachitzu/ouroboros-redteam.git
cd ouroboros-redteam
pip install -e '.[dev]'      # or with extras: pip install -e '.[all,dev]'

# Scan a target agent (local path or GitHub URL). Fully deterministic & offline:
ouroboros scan --repo ./path/to/some-agent --sarif

# Run a dynamic campaign against built-in packs (live in owner mode, offline
# SimulatedTarget in auditor mode):
ouroboros scan --repo ./path/to/some-agent --attack --pack core,soc-blueteam --adaptive --verify-patches

# Enforce CI gates or compare two audit runs:
ouroboros scan --repo ./path/to/some-agent --fail-on HIGH
ouroboros diff out/before.json out/after.json --fail-on-regression

# Owner mode remediation (requires GITHUB_TOKEN with push access):
ouroboros scan --repo https://github.com/you/agent --fix --open-pr

# Inspect MITRE ATLAS, OWASP GenAI, and payload packs offline:
ouroboros-tool atlas verify AML.T0051
ouroboros-tool owasp map excessive_agency
ouroboros-tool payloads list
ouroboros-tool datasets list
```

A scan writes `out/<target>.md`, `out/<target>.json`, and (with `--sarif`)
`out/<target>.sarif`.

---

## Architecture

Every boundary between agents is a validated Pydantic v2 contract — no free text
crosses between stages. See [`docs/architecture.md`](docs/architecture.md).

```
                 ┌──────────────┐
   repo/url ───▶ │ Recon Agent  │ ──▶ RepoProfile (prompts + tools + frameworks)
                 └──────────────┘         │
                          ┌───────────────┴───────────────┐
                          ▼                               ▼
                 ┌──────────────────┐          ┌────────────────────┐
                 │ Static Analyzer  │          │  Dynamic Attacker  │
                 │ (AST + Taint)    │          │  (Packs + Oracles) │
                 └──────────────────┘          └────────────────────┘
                          │  StaticFinding[]        DynamicFinding[]  │
                          └───────────────┬───────────────┘
                                          ▼
                                 ┌──────────────────┐
                                 │ Patch Generator  │ ──▶ ProposedPatch[] + [--verify-patches]
                                 └──────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────┐
                                 │  Orchestrator    │ ──▶ AuditReport (.md / .json / .sarif)
                                 └──────────────────┘        │
                          owner: commit / PR  ◀──────────────┴──────────────▶  auditor: report
```

---

## How it works — owner vs auditor

Ouroboros resolves write access via the GitHub API and **fails safe to `auditor`**
on any uncertainty (local path, missing token, no push permission, API error).
`AuditReport` structurally forbids any auditor-mode action other than `report`.

In auditor mode, `--attack` runs against the offline deterministic
`SimulatedTarget` (`simulated` confidence, rendered separately with a standing
caveat). Owner mode runs live (`confirmed_live`) and can commit + open a PR on a
throwaway clone via `--fix` / `--open-pr`.

---

## Threat catalogs & responsible use

- **Catalogs:** [`docs/mitre-atlas-mapping.md`](docs/mitre-atlas-mapping.md)
  covers the 82 bundled MITRE ATLAS techniques, 23 mitigations, OWASP LLM 2025 &
  Agentic risks, and CWE mappings. [`docs/datasets.md`](docs/datasets.md)
  documents all 7 payload packs and dataset import.
- **Responsible use:** [`docs/responsible-use.md`](docs/responsible-use.md).
  Never run against production or third-party agents without authorization.

---

## Repository structure

```
src/ouroboros/
├── schemas/          # Pydantic v2 contracts — the only inter-agent vocabulary
├── agents/           # recon, static_analyzer, dynamic_attacker, patch_generator
├── payloads/         # Payload model, encoders, pack loader, dataset importer
├── tools/            # Offline MITRE ATLAS & OWASP GenAI catalogs + sync
├── reporting/        # AuditReport -> Markdown, JSON, SARIF 2.1.0, diff
├── data/             # Packaged ATLAS, OWASP, and JSONL payload packs
├── oracles.py        # Deterministic judges (canary, extraction, tool_call, exfil, benign)
├── providers.py      # Anthropic, OpenAI/compatible, and Gemini adapters
├── simulation.py     # Offline multilingual SimulatedTarget
├── github_access.py  # Fail-safe owner/auditor resolution
├── remediation.py    # git apply, unique branch, PyGithub PR
├── orchestrator.py   # End-to-end pipeline + patch verification
├── cli.py            # `ouroboros scan` and `ouroboros diff`
└── toolcli.py        # `ouroboros-tool atlas|owasp|payloads|datasets ...`
scripts/              # `sync_atlas.py` compiler for mitre-atlas/atlas-data
docs/                 # architecture, ATLAS/OWASP mapping, datasets, responsible use
tests/                # 166 unit tests + vulnerable/hardened/agentic/multi-SDK/ES fixtures
```

---

## Testing

```bash
ruff check . && ruff format --check . && mypy src
ouroboros-tool payloads verify && ouroboros-tool datasets verify
pytest --cov=ouroboros --cov-report=term-missing
```

---

## Related

Part of an Agentic SOC series:

- [ai-soc-triage-agent](https://github.com/Nachitzu/ai-soc-triage-agent)
- [ai-ioc-extraction-agent](https://github.com/Nachitzu/ai-ioc-extraction-agent)
- [ai-incident-response-orchestrator](https://github.com/Nachitzu/ai-incident-response-orchestrator)

---

## License

MIT — see [LICENSE](LICENSE).
