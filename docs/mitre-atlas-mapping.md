# MITRE ATLAS mapping

Ouroboros maps every finding to [MITRE ATLAS](https://atlas.mitre.org/), the
adversarial-threat matrix for ML/LLM systems — the ATLAS analogue of the ATT&CK
mapping used elsewhere in the series.

## How mapping is kept honest

A model, or a careless detector, can invent a plausible-looking technique id. So
the id a finding carries is verified for **shape** (by the `AtlasTechnique`
schema, regex `^AML\.T\d{4}(\.\d{3})?$`) and for **existence** (against the
bundled catalog at `data/atlas/atlas-techniques.json`, via
`ouroboros.tools.atlas.verify_atlas_technique`). A well-formed but non-existent id
is dropped rather than surfaced.

Confirm or search the catalog from the CLI:

```bash
ouroboros-tool atlas verify AML.T0051
ouroboros-tool atlas search injection
```

## Static detector → ATLAS

| Finding category | ATLAS technique(s) |
|------------------|--------------------|
| `direct_interpolation` | `AML.T0051` (LLM Prompt Injection), `AML.T0051.001` (Indirect) |
| `missing_delimiters` | `AML.T0051` |
| `no_output_validation` | `AML.T0077` (LLM Response Rendering) |
| `no_instruction_hierarchy` | `AML.T0051.000` (Direct) |
| `untrusted_tool_output` | `AML.T0051.001` (Indirect) |

## Dynamic payload family → ATLAS

The Dynamic Attacker's payload families map as follows; every id is verified
against the catalog before a finding carries it.

| Payload family | ATLAS technique(s) |
|----------------|--------------------|
| `direct` | `AML.T0051` (LLM Prompt Injection), `AML.T0051.000` (Direct) |
| `indirect` | `AML.T0051`, `AML.T0051.001` (Indirect) |
| `jailbreak` | `AML.T0054` (LLM Jailbreak) |
| `encoding` | `AML.T0051` (obfuscated direct injection) |

## Extending the catalog

Add entries to `data/atlas/atlas-techniques.json` as coverage grows; ids follow
`AML.T####[.###]`. The file carries a `_comment` documenting itself, and the
loader is cached (`_atlas_catalog.cache_clear()` in tests that swap the data dir).
