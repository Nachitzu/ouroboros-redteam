<h1 align="center">Ouroboros Red Team</h1>

<p align="center">
  <em>An AI agent that red-teams AI agents — <code>prompt-injection-redteam-agent</code>.<br>
  It audits, attacks, and (soon) patches the very LLM agents its author builds.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/validation-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-74%20passing-2EA043">
  <img alt="Coverage" src="https://img.shields.io/badge/coverage-93%25-2EA043">
  <img alt="MITRE ATLAS" src="https://img.shields.io/badge/mapped%20to-MITRE%20ATLAS-8A2BE2">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center">English · <a href="README.es.md">Español</a></p>

---

## Overview

Ouroboros Red Team is a multi-stage agent that analyzes LLM-based agents for
prompt-injection weaknesses, attacks them where it safely can, and generates
concrete guardrail patches for what it finds. It is the fourth project in an
Agentic SOC series — after building defensive agents (triage, IOC extraction,
SOAR), this one closes the loop by turning on them.

> **The Ouroboros** — the snake that eats its own tail — is the perfect image for
> an agent that audits and attacks the other agents you built yourself: a system
> that examines itself. That is exactly what this tool does.

**Author:** Nachitzu — AI Security Engineer, Blue Team + AI agent architecture.

---

## Status

This repository implements the foundation and the first three real agents plus
the auditor-mode simulation (weeks 1–5 of the roadmap). The Patch Generator
remains an honest, well-typed stub so a scan always runs end-to-end.

| Phase | Scope | State |
|-------|-------|-------|
| 1 | Contracts, CLI, mode resolution, ATLAS catalog, governance | ✅ Complete |
| 2 | Recon Agent — clone, detect stack, extract prompts & entry points | ✅ Complete |
| 3 | Static Analyzer — weak-pattern detection mapped to MITRE ATLAS | ✅ Complete |
| 4 | Dynamic Attacker — live payload campaign, rate-limited, success rate | ✅ Complete |
| 5 | Dynamic Attacker — offline auditor simulation, confidence-split report | ✅ Complete |
| 6 | Patch Generator — applicable guardrail diffs | ⬜ Stubbed |
| 7 | Orchestrator output — owner-mode commit / PR | ⬜ Planned |

74 unit tests, 93% statement coverage on `src/`. No test reaches a live API.

---

## Quickstart

```bash
git clone https://github.com/Nachitzu/ouroboros-redteam.git
cd ouroboros-redteam
pip install -e '.[dev]'      # or: uv sync

# Scan a target agent (a local path or a GitHub URL). No API key needed —
# recon and static analysis are fully deterministic and offline.
ouroboros scan --repo ./path/to/some-agent

# Opt into a dynamic prompt-injection campaign. `--attack` decides by mode:
#   owner   -> live against a real model (needs ANTHROPIC_API_KEY), confirmed-live
#   auditor -> offline against a deterministic mock target, simulated (no key)
ouroboros scan --repo ./path/to/some-agent --attack --min-interval 1

# Inspect the MITRE ATLAS catalog the analyzers verify against:
ouroboros-tool atlas verify AML.T0051
ouroboros-tool atlas search injection
```

A scan writes `out/<target>.md` and `out/<target>.json`.

---

## Architecture

Every boundary between agents is a validated Pydantic v2 contract — there is no
free text passed between stages, the same principle the sibling projects use.

```
                 ┌──────────────┐
   repo/url ───▶ │ Recon Agent  │ ──▶ RepoProfile
                 └──────────────┘         │
                          ┌───────────────┴───────────────┐
                          ▼                               ▼
                 ┌──────────────────┐          ┌────────────────────┐
                 │ Static Analyzer  │          │  Dynamic Attacker  │
                 │ (AST + ATLAS)    │          │  (payloads, wk 4)  │
                 └──────────────────┘          └────────────────────┘
                          │  StaticFinding[]        DynamicFinding[]  │
                          └───────────────┬───────────────┘
                                          ▼
                                 ┌──────────────────┐
                                 │ Patch Generator  │ ──▶ ProposedPatch[]
                                 │   (wk 6)         │
                                 └──────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────┐
                                 │  Orchestrator    │ ──▶ AuditReport
                                 └──────────────────┘        │
                          owner: commit / PR  ◀──────────────┴──────────────▶  auditor: report
```

| Agent | Responsibility | Output contract |
|-------|----------------|-----------------|
| Recon | Clone, detect language/framework, extract system prompts & LLM entry points | `RepoProfile` |
| Static Analyzer | Detect weak prompt handling in code, map to MITRE ATLAS | `list[StaticFinding]` |
| Dynamic Attacker | Send adversarial payloads (direct/indirect/jailbreak/encoding), rate-limited | `list[DynamicFinding]` + run stats |
| Patch Generator | Emit applicable guardrail diffs per finding | `list[ProposedPatch]` |
| Orchestrator | Resolve mode, coordinate, assemble and act | `AuditReport` |

---

## How it works — owner vs auditor

Ouroboros resolves one question before it does anything: do you have write
access to the target?

- **owner** — confirmed `push` permission via the GitHub API. Only here may it
  (from week 7) commit a guardrail or open a PR.
- **auditor** — everything else. It produces a report with suggested diffs and
  never writes to the repo.

The resolution is **fail-safe by construction**: a missing token, a local path, a
private repo, or any API error all resolve to `auditor`. The rule is not a
convention — `AuditReport` itself rejects any auditor-mode run whose action is
anything but `report`, so no code path can auto-write a repo it lacks access to.

Dynamic testing follows the same split. In owner mode `--attack` sends real
payloads at a real model (`confirmed_live`). In auditor mode it never touches the
third-party agent: it runs the same payloads against an offline **simulated
target** whose responses follow the defenses recon and the static pass found, and
labels every hit `simulated` (reduced confidence). The report renders the two in
separate, clearly-marked groups so a mocked hit is never mistaken for a proven one.

---

## MITRE ATLAS mapping

Findings are mapped to [MITRE ATLAS](https://atlas.mitre.org/) — the adversarial
threat matrix for ML/LLM systems — the way the sibling projects map to ATT&CK.
Prompt injection is `AML.T0051`. Every technique id a finding carries is verified
against a bundled offline catalog before it ships, so a detector can never attach
a technique that does not exist. See [`docs/mitre-atlas-mapping.md`](docs/mitre-atlas-mapping.md).

---

## Responsible use

This is an **ethical red-team / defensive** tool. It is meant to harden agents
you own or are authorized to test.

- **Never run it against production.** It targets local checkouts or staging only.
- **Never attack third-party agents without permission.** The auditor fail-safe
  and the mocked-client analysis exist so an unauthorized run cannot mutate a
  target — but authorization is still your responsibility.

Full guidance in [`docs/responsible-use.md`](docs/responsible-use.md).

---

## Repository structure

```
src/ouroboros/
├── schemas/        # Pydantic v2 contracts — the only inter-agent vocabulary
├── agents/         # recon (real), static_analyzer (real), dynamic/patch (stubs)
├── tools/atlas.py  # offline MITRE ATLAS catalog + verify/search
├── github_access.py# owner/auditor resolution, fail-safe to auditor
├── orchestrator.py # the whole flow, in one place
├── reporting/      # AuditReport -> Markdown + JSON
├── cli.py          # `ouroboros scan`
└── toolcli.py      # `ouroboros-tool atlas ...`
data/atlas/         # bundled ATLAS technique catalog
docs/               # architecture, ATLAS mapping, responsible use
tests/              # per-module tests + a seeded vulnerable fixture
```

---

## Testing

```bash
ruff check . && ruff format --check . && mypy src
pytest --cov=ouroboros --cov-report=term-missing
```

The suite pins the two milestone criteria: the Static Analyzer detects ≥3 weakness
categories on a seeded fixture, and the Recon Agent extracts the real system
prompt from a sibling project when it is checked out alongside this one.

---

## Related

Part of an Agentic SOC series. Together they form a blue-team pipeline —
intelligence extraction → enrichment → alert triage → incident response — and
this project turns the lens back on the pipeline itself:

- [ai-soc-triage-agent](https://github.com/Nachitzu/ai-soc-triage-agent)
- [ai-ioc-extraction-agent](https://github.com/Nachitzu/ai-ioc-extraction-agent)
- [ai-incident-response-orchestrator](https://github.com/Nachitzu/ai-incident-response-orchestrator)

---

## License

MIT — see [LICENSE](LICENSE).
