# MITRE ATLAS & OWASP GenAI Mapping

Ouroboros maps every finding to [MITRE ATLAS](https://atlas.mitre.org/) and the
[OWASP Top 10 for LLM / Agentic Applications](https://genai.owasp.org/), plus
CWE identifiers for static code weaknesses.

## Anti-hallucination verification

Every `technique_id` (`AML.T####[.###]`) and OWASP `risk_id`
(`LLM##:2025` / `ASI##:2026`) is verified offline against the bundled catalogs at
`src/ouroboros/data/atlas/atlas-techniques.json` (82 techniques/sub-techniques,
plus 23 mitigations in `atlas-mitigations.json`) and
`src/ouroboros/data/owasp/owasp-genai.json` (20 risks + cross-walks). Unknown ids
are dropped rather than surfaced.

Inspect or sync the catalogs from the CLI:

```bash
ouroboros-tool atlas verify AML.T0051
ouroboros-tool atlas search injection
ouroboros-tool atlas mitigations AML.T0051
ouroboros-tool atlas sync --from /path/to/atlas-data/dist/ATLAS.yaml

ouroboros-tool owasp verify LLM01:2025
ouroboros-tool owasp map excessive_agency
```

## Category → ATLAS / OWASP / CWE

| Category | ATLAS | OWASP | CWE |
|----------|-------|-------|-----|
| `direct_interpolation` | `AML.T0051`, `AML.T0051.001` | `LLM01:2025` | `CWE-77`, `CWE-1427` |
| `missing_delimiters` | `AML.T0051` | `LLM01:2025` | `CWE-77` |
| `untrusted_tool_output` | `AML.T0051.001` | `LLM01:2025`, `ASI01:2026` | `CWE-77`, `CWE-20` |
| `no_instruction_hierarchy` | `AML.T0051.000` | `LLM01:2025` | `CWE-1427` |
| `no_output_validation` | `AML.T0077` | `LLM05:2025` | `CWE-20` |
| `improper_output_handling` | `AML.T0077`, `AML.T0051`, `AML.T0086` | `LLM05:2025`, `ASI05:2026` | `CWE-94`, `CWE-78`, `CWE-89`, `CWE-22` |
| `excessive_agency` | `AML.T0053`, `AML.T0050` | `LLM06:2025`, `ASI02:2026`, `ASI03:2026` | `CWE-250`, `CWE-862` |
| `mcp_tool_poisoning` | `AML.T0053`, `AML.T0051.001` | `LLM01:2025`, `LLM03:2025`, `ASI04:2026` | `CWE-94`, `CWE-77` |
| `prompt_leakage_risk` | `AML.T0056`, `AML.T0057` | `LLM07:2025` | `CWE-200`, `CWE-798` |
| `system_prompt_extraction` | `AML.T0056` | `LLM07:2025` | `CWE-200` |
| `tool_hijack` | `AML.T0053`, `AML.T0051.001` | `LLM06:2025`, `ASI02:2026`, `ASI01:2026` | `CWE-862` |
| `data_exfiltration` | `AML.T0057` | `LLM02:2025`, `LLM05:2025` | `CWE-201` |
| `over_refusal` | — | — | — |
