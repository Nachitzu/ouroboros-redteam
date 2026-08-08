<h1 align="center">Ouroboros Red Team</h1>

<p align="center">
  <em>Un agente de IA que hace red-team a agentes de IA — <code>prompt-injection-redteam-agent</code>.<br>
  Audita, ataca y (pronto) parcha a los propios agentes LLM que construye su autor.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/validation-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-74%20passing-2EA043">
  <img alt="Coverage" src="https://img.shields.io/badge/coverage-93%25-2EA043">
  <img alt="MITRE ATLAS" src="https://img.shields.io/badge/mapped%20to-MITRE%20ATLAS-8A2BE2">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.md">English</a> · Español</p>

---

## Visión general

Ouroboros Red Team es un agente multi-etapa que analiza agentes basados en LLM en
busca de debilidades ante *prompt injection*, los ataca donde puede hacerlo de
forma segura, y genera parches concretos (guardrails) para lo que encuentra. Es el
cuarto proyecto de una serie Agentic SOC: tras construir agentes defensivos
(triage, extracción de IOCs, SOAR), este cierra el ciclo volviéndose contra ellos.

> **El Ouroboros** —la serpiente que se muerde la cola— representa perfectamente un
> agente que audita y ataca a los otros agentes que tú mismo creaste: un sistema
> que se examina a sí mismo. Es exactamente lo que hace esta herramienta.

**Autor:** Nachitzu — AI Security Engineer, Blue Team + arquitectura de agentes de IA.

---

## Estado

Este repositorio implementa la fundación, los tres primeros agentes reales y la
simulación de modo auditor (semanas 1–5 del roadmap). El Patch Generator sigue
como stub honesto y bien tipado, de modo que un escaneo siempre corre de punta a punta.

| Fase | Alcance | Estado |
|------|---------|--------|
| 1 | Contratos, CLI, resolución de modo, catálogo ATLAS, gobernanza | ✅ Completa |
| 2 | Recon Agent — clona, detecta stack, extrae prompts y entry points | ✅ Completa |
| 3 | Static Analyzer — detección de patrones débiles mapeada a MITRE ATLAS | ✅ Completa |
| 4 | Dynamic Attacker — campaña de payloads en vivo, con rate limit y tasa de éxito | ✅ Completa |
| 5 | Dynamic Attacker — simulación offline de modo auditor, reporte por confianza | ✅ Completa |
| 6 | Patch Generator — diffs de guardrails aplicables | ⬜ Stub |
| 7 | Salida del Orchestrator — commit / PR en modo owner | ⬜ Planeada |

74 tests unitarios, 93% de cobertura de sentencias en `src/`. Ningún test toca una API real.

---

## Inicio rápido

```bash
git clone https://github.com/Nachitzu/ouroboros-redteam.git
cd ouroboros-redteam
pip install -e '.[dev]'      # o: uv sync

# Escanea un agente objetivo (ruta local o URL de GitHub). No requiere API key:
# recon y el análisis estático son totalmente deterministas y offline.
ouroboros scan --repo ./ruta/a/algun-agente

# Activa una campaña de inyección dinámica. `--attack` decide por modo:
#   owner   -> en vivo contra un modelo real (requiere ANTHROPIC_API_KEY), confirmed-live
#   auditor -> offline contra un mock determinista, simulated (sin key)
ouroboros scan --repo ./ruta/a/algun-agente --attack --min-interval 1

# Inspecciona el catálogo MITRE ATLAS contra el que los analizadores verifican:
ouroboros-tool atlas verify AML.T0051
ouroboros-tool atlas search injection
```

Un escaneo escribe `out/<objetivo>.md` y `out/<objetivo>.json`.

---

## Arquitectura

Cada frontera entre agentes es un contrato Pydantic v2 validado — no se pasa texto
libre entre etapas, el mismo principio de los proyectos hermanos.

```
                 ┌──────────────┐
   repo/url ───▶ │ Recon Agent  │ ──▶ RepoProfile
                 └──────────────┘         │
                          ┌───────────────┴───────────────┐
                          ▼                               ▼
                 ┌──────────────────┐          ┌────────────────────┐
                 │ Static Analyzer  │          │  Dynamic Attacker  │
                 │ (AST + ATLAS)    │          │  (payloads, sem 4) │
                 └──────────────────┘          └────────────────────┘
                          │  StaticFinding[]        DynamicFinding[]  │
                          └───────────────┬───────────────┘
                                          ▼
                                 ┌──────────────────┐
                                 │ Patch Generator  │ ──▶ ProposedPatch[]
                                 │   (sem 6)        │
                                 └──────────────────┘
                                          │
                                          ▼
                                 ┌──────────────────┐
                                 │  Orchestrator    │ ──▶ AuditReport
                                 └──────────────────┘        │
                          owner: commit / PR  ◀──────────────┴──────────────▶  auditor: reporte
```

| Agente | Responsabilidad | Contrato de salida |
|--------|-----------------|--------------------|
| Recon | Clona, detecta lenguaje/framework, extrae system prompts y entry points del LLM | `RepoProfile` |
| Static Analyzer | Detecta manejo débil de prompts en el código, mapea a MITRE ATLAS | `list[StaticFinding]` |
| Dynamic Attacker | Envía payloads adversariales (directo/indirecto/jailbreak/encoding), con rate limit | `list[DynamicFinding]` + stats |
| Patch Generator | Emite diffs de guardrails aplicables por hallazgo | `list[ProposedPatch]` |
| Orchestrator | Resuelve el modo, coordina, ensambla y actúa | `AuditReport` |

---

## Cómo funciona — owner vs auditor

Ouroboros resuelve una pregunta antes de hacer nada: ¿tienes permiso de escritura
sobre el objetivo?

- **owner** — permiso de `push` confirmado vía la API de GitHub. Solo aquí puede
  (desde la semana 7) commitear un guardrail o abrir un PR.
- **auditor** — todo lo demás. Produce un reporte con diffs sugeridos y nunca
  escribe en el repo.

La resolución es **fail-safe por construcción**: la ausencia de token, una ruta
local, un repo privado o cualquier error de la API resuelven a `auditor`. La regla
no es una convención: el propio `AuditReport` rechaza cualquier corrida en modo
auditor cuya acción no sea `report`, así que ningún camino de código puede
auto-escribir un repo al que no tiene acceso.

El testeo dinámico sigue la misma división. En modo owner, `--attack` envía
payloads reales a un modelo real (`confirmed_live`). En modo auditor nunca toca al
agente de terceros: corre los mismos payloads contra un **objetivo simulado**
offline cuyas respuestas siguen las defensas que hallaron recon y el análisis
estático, y etiqueta cada acierto como `simulated` (confianza reducida). El reporte
muestra ambos en grupos separados y marcados, para que un acierto simulado nunca se
confunda con uno confirmado.

---

## Mapeo a MITRE ATLAS

Los hallazgos se mapean a [MITRE ATLAS](https://atlas.mitre.org/) —la matriz de
amenazas adversariales para sistemas de ML/LLM— igual que los proyectos hermanos
mapean a ATT&CK. El *prompt injection* es `AML.T0051`. Cada id de técnica que
lleva un hallazgo se verifica contra un catálogo offline antes de publicarse, de
modo que un detector nunca puede adjuntar una técnica que no existe. Ver
[`docs/mitre-atlas-mapping.md`](docs/mitre-atlas-mapping.md).

---

## Uso responsable

Es una herramienta de **red team ético / defensa**. Sirve para endurecer agentes
que posees o que estás autorizado a probar.

- **Nunca la corras contra producción.** Apunta solo a checkouts locales o staging.
- **Nunca ataques agentes de terceros sin permiso.** El fail-safe a modo auditor y
  el análisis con cliente simulado existen para que una corrida no autorizada no
  pueda mutar un objetivo — pero la autorización sigue siendo tu responsabilidad.

Guía completa en [`docs/responsible-use.md`](docs/responsible-use.md).

---

## Estructura del repositorio

```
src/ouroboros/
├── schemas/        # contratos Pydantic v2 — el único vocabulario entre agentes
├── agents/         # recon (real), static_analyzer (real), dynamic/patch (stubs)
├── tools/atlas.py  # catálogo MITRE ATLAS offline + verify/search
├── github_access.py# resolución owner/auditor, fail-safe a auditor
├── orchestrator.py # todo el flujo, en un solo lugar
├── reporting/      # AuditReport -> Markdown + JSON
├── cli.py          # `ouroboros scan`
└── toolcli.py      # `ouroboros-tool atlas ...`
data/atlas/         # catálogo de técnicas ATLAS incluido
docs/               # arquitectura, mapeo ATLAS, uso responsable
tests/              # tests por módulo + un fixture vulnerable sembrado
```

---

## Pruebas

```bash
ruff check . && ruff format --check . && mypy src
pytest --cov=ouroboros --cov-report=term-missing
```

La suite fija los dos criterios de hito: el Static Analyzer detecta ≥3 categorías
de debilidad en un fixture sembrado, y el Recon Agent extrae el system prompt real
de un proyecto hermano cuando está clonado junto a este.

---

## Relacionados

Parte de una serie Agentic SOC. Juntos forman un pipeline de blue team —
extracción de inteligencia → enriquecimiento → triage de alertas → respuesta a
incidentes— y este proyecto gira la lente sobre el propio pipeline:

- [ai-soc-triage-agent](https://github.com/Nachitzu/ai-soc-triage-agent)
- [ai-ioc-extraction-agent](https://github.com/Nachitzu/ai-ioc-extraction-agent)
- [ai-incident-response-orchestrator](https://github.com/Nachitzu/ai-incident-response-orchestrator)

---

## Licencia

MIT — ver [LICENSE](LICENSE).
