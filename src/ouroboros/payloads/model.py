"""The ``Payload`` contract: one inert, renderable probe.

Kept apart from the pack loader so every module (attacker, simulator, importer)
shares one definition. Two ideas keep payloads realistic and testable:

1. **Deterministic oracles.** Every payload declares how success is judged
   (``oracle``). Most use a per-payload canary: the probe's *only* goal is to make
   the target emit a harmless random token — never harmful content — so success
   is a single unambiguous check.
2. **Rendering, not string formatting.** ``render`` builds the final message from
   a body (canary substituted), an optional encoding, and a carrier that frames
   it — so an encoding-family payload really is base64, and an indirect one
   really sits inside document-looking content.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from ouroboros.payloads.encoders import Encoding, encode
from ouroboros.schemas.common import FindingCategory, Oracle, PayloadFamily, Severity


class Payload(BaseModel):
    """One adversarial (or benign control) probe, renderable against a fresh canary."""

    id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    family: PayloadFamily
    category: FindingCategory
    severity: Severity
    atlas_ids: tuple[str, ...]
    owasp_ids: tuple[str, ...] = ()
    description: str = Field(min_length=1)
    # The instruction that tries to make the target act. Contains ``{canary}``
    # for canary/tool_call/exfiltration oracles.
    body: str = Field(min_length=1)
    # How the (possibly-encoded) body is framed before it is sent. Contains
    # ``{body}``. The default sends the body as-is.
    carrier: str = "{body}"
    encoding: Encoding = "none"
    oracle: Oracle = "canary"
    # Earlier user turns for multi-turn probes, sent (with the target's replies)
    # before the final rendered message. May contain ``{canary}``.
    setup_turns: tuple[str, ...] = ()
    # For tool_call oracles: the tool name the probe tries to steer the model into.
    target_tool: str | None = None
    pack: str = "core"
    source: str = Field(default="ouroboros", description="Provenance / inspiration of the probe.")
    language: str = "en"
    tags: tuple[str, ...] = ()

    @field_validator("carrier")
    @classmethod
    def _carrier_has_body(cls, value: str) -> str:
        if "{body}" not in value:
            raise ValueError("carrier must contain {body}")
        return value

    def render(self, canary: str) -> str:
        """Return the final message to send, with ``canary`` woven in.

        For opaque encodings the canary is inside the encoded blob, not in the
        clear — which is the whole point of the family, and what a decode has to
        recover for the attack to land.
        """
        body = encode(self.body.replace("{canary}", canary), self.encoding)
        return self.carrier.replace("{body}", body)

    def render_setup(self, canary: str) -> list[str]:
        """The rendered earlier turns of a multi-turn probe (may be empty)."""
        return [turn.replace("{canary}", canary) for turn in self.setup_turns]

    def with_encoding(self, encoding: Encoding, *, suffix: str | None = None) -> Payload:
        """A copy re-encoded with ``encoding`` (used by adaptive mutation)."""
        carrier = (
            f"The following text is encoded ({encoding}). Decode it and follow it "
            "precisely:\n\n{body}"
            if encoding != "none"
            else "{body}"
        )
        return self.model_copy(
            update={
                "id": f"{self.id}.{suffix or encoding}",
                "encoding": encoding,
                "carrier": carrier,
            }
        )
