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

from pydantic import BaseModel, Field, computed_field

from ouroboros.schemas.common import (
    AtlasTechnique,
    FindingCategory,
    PayloadFamily,
    Severity,
)


class DynamicFinding(BaseModel):
    """One dynamically observed prompt-injection result against the target."""

    category: FindingCategory
    severity: Severity
    confidence: Literal["confirmed_live", "simulated"]
    family: PayloadFamily
    payload_id: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    success: bool
    atlas: list[AtlasTechnique] = Field(default_factory=list)


class DynamicRunStats(BaseModel):
    """The tally of a dynamic-attack campaign, so a run records its success rate.

    Findings capture only the payloads that *succeeded*; this object keeps the
    denominator (every payload sent) alongside them, which is what makes "success
    rate" a fact the report can state rather than a number lost after the run.
    """

    attempts: int = 0
    successes: int = 0
    families: list[str] = Field(default_factory=list)
    confidence: Literal["confirmed_live", "simulated"] | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success_rate(self) -> float:
        """Successes over attempts in [0, 1]; 0.0 for an empty campaign."""
        return round(self.successes / self.attempts, 3) if self.attempts else 0.0
