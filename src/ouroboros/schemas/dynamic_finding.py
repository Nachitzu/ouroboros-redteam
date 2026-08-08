"""A weakness the Dynamic Attacker confirmed (or simulated) by sending payloads.

Poblado from week 4 onward; for now the Dynamic Attacker returns an empty list.
The contract exists already because the report and summary layers switch on it,
and freezing its shape now keeps the empty-but-well-typed run honest.

The key field is ``confidence``: ``"confirmed_live"`` means a payload actually
moved a real agent (owner mode), ``"simulated"`` means it moved a mocked client
(auditor mode). The two must never render the same way, which is why they are
distinct literals rather than a boolean flag.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ouroboros.schemas.common import AtlasTechnique, FindingCategory, Severity


class DynamicFinding(BaseModel):
    """One dynamically observed prompt-injection result against the target."""

    category: FindingCategory
    severity: Severity
    confidence: Literal["confirmed_live", "simulated"]
    payload_id: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    success: bool
    atlas: list[AtlasTechnique] = Field(default_factory=list)
