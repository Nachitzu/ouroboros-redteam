"""The Patch Generator: turn findings into applicable guardrail diffs.

STATUS: typed stub (week 6). ``generate`` returns an empty list today. The real
version will template a guardrail per finding category — delimiters, an
instruction hierarchy, output validation — and emit a unified diff that
``git apply`` accepts, together with the rationale a reviewer needs before it is
committed (owner) or handed over (auditor).
"""

from __future__ import annotations

from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.proposed_patch import ProposedPatch
from ouroboros.schemas.static_finding import StaticFinding


def generate(
    static_findings: list[StaticFinding],
    dynamic_findings: list[DynamicFinding],
) -> list[ProposedPatch]:
    """Return proposed patches for a set of findings. Stub: none generated yet."""
    _ = (static_findings, dynamic_findings)
    return []
