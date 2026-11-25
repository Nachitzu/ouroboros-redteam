"""A weakness the Dynamic Attacker confirmed (or simulated) by sending payloads.

The key field is ``confidence``: ``"confirmed_live"`` means a payload actually
moved a real agent (owner mode), ``"simulated"`` means it moved a mocked client
(auditor mode). The two must never render the same way, which is why they are
distinct literals rather than a boolean flag. ``oracle`` records *how* success was
judged, so a reader knows whether a hit is a leaked canary, an extracted prompt,
a hijacked tool call or a smuggled URL.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, computed_field

from ouroboros.schemas.common import (
    AtlasTechnique,
    FindingCategory,
    Oracle,
    OwaspRisk,
    PayloadFamily,
    Severity,
)


class DynamicFinding(BaseModel):
    """One dynamically observed result against the target."""

    category: FindingCategory
    severity: Severity
    confidence: Literal["confirmed_live", "simulated"]
    family: PayloadFamily
    payload_id: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    success: bool
    atlas: list[AtlasTechnique] = Field(default_factory=list)
    owasp: list[OwaspRisk] = Field(default_factory=list)
    oracle: Oracle = "canary"
    pack: str = "core"
    prompt_ref: str | None = Field(
        default=None, description="Which recovered prompt was attacked (file[:line])."
    )
    turns: int = Field(default=1, ge=1, description="User turns in the attack conversation.")
    mutation: str | None = Field(
        default=None, description="Adaptive mutation applied (e.g. 'hex'), if any."
    )


class FamilyStats(BaseModel):
    """Attempts/successes for one payload family."""

    attempts: int = 0
    successes: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success_rate(self) -> float:
        return round(self.successes / self.attempts, 3) if self.attempts else 0.0


class DynamicRunStats(BaseModel):
    """The tally of a dynamic-attack campaign, so a run records its success rate.

    Findings capture only the payloads that *succeeded*; this object keeps the
    denominator (every payload sent) alongside them, which is what makes "success
    rate" a fact the report can state rather than a number lost after the run.
    Benign controls are counted separately: they are not attacks, and folding
    them into the ASR would distort it.
    """

    attempts: int = 0
    successes: int = 0
    families: list[str] = Field(default_factory=list)
    confidence: Literal["confirmed_live", "simulated"] | None = None
    by_family: dict[str, FamilyStats] = Field(default_factory=dict)
    packs: list[str] = Field(default_factory=list)
    prompts_attacked: int = 0
    benign_attempts: int = 0
    over_refusals: int = 0
    adaptive_mutations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str | None = None
    model: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success_rate(self) -> float:
        """Successes over attempts in [0, 1]; 0.0 for an empty campaign."""
        return round(self.successes / self.attempts, 3) if self.attempts else 0.0


class PatchVerification(BaseModel):
    """ASR of the same campaign before and after applying prompt-hardening patches."""

    before: DynamicRunStats
    after: DynamicRunStats
    patched_prompts: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def asr_delta(self) -> float:
        """after - before; negative means the patches reduced the attack success rate."""
        return round(self.after.success_rate - self.before.success_rate, 3)
