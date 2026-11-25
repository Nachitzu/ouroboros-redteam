# Payload Packs & Datasets

Ouroboros ships curated, offline-first JSONL payload packs under
`src/ouroboros/data/payloads/`. Every adversarial probe targets a harmless
per-attempt canary token (`OURO-XXXXXXXX`), system-prompt reproduction, a
non-executed decoy/recovered `tool_use` call, or a canary-bearing URL — never
harmful content.

## Built-in packs (132 probes)

| Pack | Count | Focus & inspiration |
|------|-------|---------------------|
| `core` | 35 | Balanced default pack: direct, indirect, jailbreak, all 8 encoders (`base64`, `rot13`, `hex`, `leetspeak`, `zero_width`, `homoglyph`, `reverse`, `url`), extraction, `tool_hijack`, `exfiltration`, and `multi_turn`. |
| `extraction` | 15 | System prompt leakage & rule-extraction probes inspired by TensorTrust / Gandalf patterns (`AML.T0056`, `LLM07:2025`). |
| `indirect-bipia` | 20 | Indirect prompt injection embedded in emails, HTML, Markdown, CSV tables, JSON API responses, code comments, PDF text, and RAG chunks (inspired by BIPIA). |
| `tool-hijack` | 15 | Tool-output injections attempting to steer sensitive tool calls (`send_email`, `transfer_funds`, `run_command`, `write_file`, `http_request`, `delete_records`) without executing code (inspired by InjecAgent / AgentDojo). |
| `soc-blueteam` | 20 | Domain probes for Agentic-SOC pipelines: injections inside SIEM alerts, Sysmon `CommandLine`, `User-Agent`, DNS queries, syslog, phishing headers/HTML, CTI/WHOIS reports, and SOAR ticket notes. |
| `multilingual` | 12 | Spanish, Portuguese, French, German, and translation-pivot framings. |
| `benign-controls` | 15 | Legitimate security-analyst requests that contain security jargon ("ignore previous instructions" explanations, log/code analysis) to detect **over-refusal**. Excluded from attack ASR. |

## Selecting packs & adaptive mutations

```bash
# Default core pack (up to --max-payloads per recovered prompt)
ouroboros scan --repo ./my-agent --attack

# SOC domain + indirect BIPIA + benign over-refusal controls
ouroboros scan --repo ./my-soc-agent --attack --pack soc-blueteam,indirect-bipia,benign-controls --max-payloads 50

# Retry failed probes with encoding/framing mutations
ouroboros scan --repo ./my-agent --attack --adaptive
```

## Importing external datasets

If you download external research datasets (e.g., TensorTrust, BIPIA, PINT, or
internal red-team CSV/JSONL corpora), convert them into a canary-oracle pack:

```bash
ouroboros-tool datasets import \
  --file ./tensortrust-sample.jsonl \
  --format jsonl \
  --text-field attack \
  --pack tensortrust-local \
  --family direct \
  --oracle canary
```

Imported packs land in `$OUROBOROS_PACKS_DIR` (default `~/.ouroboros/packs`) and
are automatically discovered by `ouroboros scan --pack tensortrust-local` and
`ouroboros-tool datasets list|verify`.
