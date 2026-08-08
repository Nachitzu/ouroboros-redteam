"""Versioned library of prompt-injection payloads for the Dynamic Attacker.

Payloads are inert data — a template plus how to frame and (optionally) encode it
— executed only by the Dynamic Attacker against a local or mocked target, never
against production. Grouped by the technique family they exercise (direct,
indirect, jailbreak, encoding), each mapped to a verified MITRE ATLAS technique.
"""

from __future__ import annotations

from ouroboros.payloads.library import (
    PAYLOAD_LIBRARY,
    Encoding,
    Payload,
    families,
    library,
)

__all__ = ["PAYLOAD_LIBRARY", "Encoding", "Payload", "families", "library"]
