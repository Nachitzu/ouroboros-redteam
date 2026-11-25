"""Shared vocabulary for the inter-agent contracts.

Every agent boundary in Ouroboros is a Pydantic model, and the models share a
small vocabulary: the severity scale, the run mode, the confidence of a finding,
the closed set of weakness categories, and the shape of a MITRE ATLAS technique
and an OWASP LLM Top 10 risk. Centralizing them here keeps ``RepoProfile``,
``StaticFinding``, ``DynamicFinding`` and ``AuditReport`` speaking exactly the
same language — and gives one place to enforce, for example, that a technique id
actually looks like an ATLAS id rather than an ATT&CK one.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# The blue-team severity scale, identical to the sibling projects so a reader who
# knows one knows them all.
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# How Ouroboros is allowed to act on a target. Resolved once, early, and never
# widened: the absence of proof of write access must land on "auditor".
Mode = Literal["owner", "auditor"]

# How much a finding can be trusted. "static" comes from reading code; "simulated"
# from attacking a mocked client (auditor mode); "confirmed_live" from an attack
# that actually moved a real agent (owner mode). The report renders these
# differently on purpose — a simulated hit must never read as a confirmed one.
Confidence = Literal["confirmed_live", "simulated", "static"]

# The closed catalog of weaknesses Ouroboros reasons about. New detectors must
# extend this list rather than emit a free-text category, so the reporting and
# patch layers can switch on it exhaustively.
FindingCategory = Literal[
    # prompt construction (static + dynamic)
    "direct_interpolation",
    "missing_delimiters",
    "no_output_validation",
    "no_instruction_hierarchy",
    "untrusted_tool_output",
    # agentic / OWASP LLM 2025 additions
    "improper_output_handling",  # model output reaches eval/exec/shell/SQL/paths
    "excessive_agency",  # destructive tools without allowlist / human approval
    "mcp_tool_poisoning",  # instructions hidden in tool descriptions/docstrings
    "prompt_leakage_risk",  # system prompt carries no anti-extraction rule / secrets
    # dynamic-only outcomes
    "system_prompt_extraction",
    "tool_hijack",
    "data_exfiltration",
    "over_refusal",
]

# The families of adversarial payload the Dynamic Attacker sends. Kept separate
# from FindingCategory (a weakness class) because a family is *how* the attack is
# shaped, not *what* weakness it demonstrates.
PayloadFamily = Literal[
    "direct",
    "indirect",
    "jailbreak",
    "encoding",
    "extraction",
    "tool_hijack",
    "exfiltration",
    "multi_turn",
    "benign",
]

# How a payload's success is judged. Every oracle is deterministic:
#   canary       — the target emitted the per-payload canary (and did not refuse)
#   extraction   — the reply reproduces a large share of the system prompt
#   tool_call    — the target emitted a tool call it was steered into
#   exfiltration — the reply carries a URL/markdown image smuggling the canary
#   benign       — control: a legitimate request; "success" = the target refused
#                  (an over-refusal), so benign hits measure over-blocking
Oracle = Literal["canary", "extraction", "tool_call", "exfiltration", "benign"]

_ATLAS_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
_OWASP_RE = re.compile(r"^(LLM(0[1-9]|10)|ASI(0[1-9]|1[0-5])):\d{4}$")


def now_utc() -> datetime:
    """Return a timezone-aware UTC timestamp.

    Centralized so every report is stamped the same way and two machines never
    disagree about what "now" means.
    """
    return datetime.now(UTC)


class AtlasTechnique(BaseModel):
    """A single MITRE ATLAS technique reference attached to a finding.

    The id is validated for *shape* here (``AML.T0051`` / ``AML.T0051.001``); its
    *existence* is checked separately against the offline catalog in
    :mod:`ouroboros.tools.atlas`, so a well-formed but invented id is caught by
    the verifier rather than sliding through as if it were real.
    """

    technique_id: str
    name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)

    @field_validator("technique_id")
    @classmethod
    def _well_formed(cls, value: str) -> str:
        if not _ATLAS_RE.match(value):
            raise ValueError(
                f"technique_id must look like AML.T0051 or AML.T0051.001, got {value!r}"
            )
        return value


class OwaspRisk(BaseModel):
    """An OWASP GenAI risk reference (LLM Top 10 2025 or Agentic ``ASI``).

    Ids look like ``LLM01:2025`` or ``ASI01:2026``; existence is verified against
    the bundled catalog in :mod:`ouroboros.tools.owasp`.
    """

    risk_id: str
    name: str = Field(min_length=1)

    @field_validator("risk_id")
    @classmethod
    def _well_formed(cls, value: str) -> str:
        if not _OWASP_RE.match(value):
            raise ValueError(f"risk_id must look like LLM01:2025, got {value!r}")
        return value
