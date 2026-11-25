<h1 align="center">Ouroboros Red Team</h1>

<p align="center">
  <em>Un agente de IA que hace red-team a agentes de IA — <code>prompt-injection-redteam-agent</code>.<br>
  Audita, ataca, verifica y parcha los propios agentes LLM que construye su autor.</em>
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

<p align="center"><a href="README.md">English</a> · Español</p>

---

## Visión general

Ouroboros Red Team es un agente multi-etapa que analiza agentes basados en LLM en
busca de debilidades ante *prompt injection* y riesgos agénticos, los prueba con
packs curados basados en oráculos deterministas, verifica el impacto real de los
parches sobre el prompt y genera salidas en SARIF 2.1.0, Markdown, JSON y PRs de
remediación.

> **El Ouroboros** —la serpiente que se muerde la cola— representa perfectamente un
> agente que audita y ataca a los otros agentes que tú mismo creaste: un sistema
> que se examina a sí mismo.

**Autor:** Nachitzu — AI Security Engineer, Blue Team + arquitectura de agentes de IA.

---

## Capacidades principales

- **Recon multi-SDK (`recon.py`):** Detecta Anthropic, OpenAI, Google GenAI,
  LiteLLM, LangChain, LangGraph, LlamaIndex, PydanticAI, CrewAI, AutoGen, OpenAI
  Agents SDK y servidores MCP; extrae prompts de código, `AnnAssign`, bloques
  Markdown, plantillas `.txt`/`.prompt`/`.j2`, YAML/JSON y literales JS/TS;
  inventaría herramientas expuestas con sus capacidades y confirmación humana.
- **Análisis estático y taint por función (`static_analyzer.py`):** 9 categorías
  (`direct_interpolation`, `missing_delimiters`, `no_output_validation`,
  `no_instruction_hierarchy`, `untrusted_tool_output`,
  `improper_output_handling`, `excessive_agency`, `mcp_tool_poisoning`,
  `prompt_leakage_risk`) mapeadas a MITRE ATLAS, OWASP LLM 2025 / Agentic Top 10
  y CWE, con enriquecimiento opcional vía LLM (`--enrich`).
- **Atacante dinámico y oráculos deterministas (`dynamic_attacker.py`, `oracles.py`, `providers.py`):**
  Ataques multi-turno y de secuestro de herramientas (sin ejecutar código del
  objetivo) evaluados por oráculos (`canary`, `extraction`, `tool_call`,
  `exfiltration`, `benign` anti sobre-rechazo), mutaciones adaptativas
  (`--adaptive`), soporte para Anthropic, OpenAI / compatibles (`--base-url`),
  Gemini y `SimulatedTarget` multilingüe offline (`simulation.py`).
- **7 packs de payloads integrados (132 sondas):** `core`, `extraction`,
  `indirect-bipia`, `tool-hijack`, `soc-blueteam`, `multilingual` y
  `benign-controls`, además de importador CSV/JSONL (`ouroboros-tool datasets import`).
  Ver [`docs/datasets.md`](docs/datasets.md).
- **Endurecimiento real de prompts, verificación e integración CI:** Diffs
  multi-hunk por archivo + reescritura real `prompt_hardening`, verificación de
  caída del ASR (`--verify-patches`), salida `--sarif` 2.1.0, gates `--fail-on` /
  `--fail-on-asr`, comando `ouroboros diff` y ramas sin colisiones + PR contra
  `default_branch`.

166 tests unitarios pasando (1 test opcional omitido por ausencia del repo hermano),
89% de cobertura en `src/ouroboros/`. Ningún test toca APIs reales ni GitHub.

---

## Inicio rápido

```bash
git clone https://github.com/Nachitzu/ouroboros-redteam.git
cd ouroboros-redteam
pip install -e '.[dev]'      # o con extras: pip install -e '.[all,dev]'

# Escaneo determinista y offline + SARIF:
ouroboros scan --repo ./ruta/a/algun-agente --sarif

# Campaña dinámica (en vivo en owner; SimulatedTarget offline en auditor):
ouroboros scan --repo ./ruta/a/algun-agente --attack --pack core,soc-blueteam --adaptive --verify-patches

# Gates de CI y comparación entre dos escaneos:
ouroboros scan --repo ./ruta/a/algun-agente --fail-on HIGH
ouroboros diff out/before.json out/after.json --fail-on-regression

# Remediación en modo owner (requiere GITHUB_TOKEN con permisos de push):
ouroboros scan --repo https://github.com/tu/agente --fix --open-pr

# Consultar catálogos ATLAS, OWASP y packs offline:
ouroboros-tool atlas verify AML.T0051
ouroboros-tool owasp map excessive_agency
ouroboros-tool payloads list
ouroboros-tool datasets list
```

Cada escaneo escribe `out/<objetivo>.md`, `out/<objetivo>.json` y (con `--sarif`)
`out/<objetivo>.sarif`.

---

## Arquitectura y modo owner vs auditor

Cada frontera entre agentes es un contrato Pydantic v2 validado (ver
[`docs/architecture.md`](docs/architecture.md)). La resolución de acceso es
**fail-safe a `auditor`**: rutas locales, ausencia de token, falta de permiso
`push` o errores de API resuelven siempre a solo lectura, y `AuditReport` prohíbe
estructuralmente cualquier acción distinta de `report` en modo auditor.

---

## Catálogos de amenazas y uso responsable

- **Catálogos:** [`docs/mitre-atlas-mapping.md`](docs/mitre-atlas-mapping.md)
  documenta las 82 técnicas ATLAS, 23 mitigaciones, riesgos OWASP LLM 2025 /
  Agentic y CWEs. [`docs/datasets.md`](docs/datasets.md) describe los 7 packs de
  payloads y el importador de datasets.
- **Uso responsable:** [`docs/responsible-use.md`](docs/responsible-use.md).
  Nunca ejecutes Ouroboros contra producción ni contra agentes sin autorización.

---

## Pruebas

```bash
ruff check . && ruff format --check . && mypy src
ouroboros-tool payloads verify && ouroboros-tool datasets verify
pytest --cov=ouroboros --cov-report=term-missing
```

---

## Licencia

MIT — ver [LICENSE](LICENSE).
