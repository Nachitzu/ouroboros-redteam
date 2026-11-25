"""Versioned library and pack loader of prompt-injection payloads.

Payloads are inert data — a template plus how to frame and (optionally) encode it
— executed only by the Dynamic Attacker against a local or mocked target, never
against production.
"""

from __future__ import annotations

from ouroboros.payloads import encoders
from ouroboros.payloads.encoders import Encoding
from ouroboros.payloads.library import PAYLOAD_LIBRARY, families, library
from ouroboros.payloads.model import Payload
from ouroboros.payloads.packs import PackInfo, PayloadPack, available_packs, load_packs

__all__ = [
    "PAYLOAD_LIBRARY",
    "Encoding",
    "PackInfo",
    "Payload",
    "PayloadPack",
    "available_packs",
    "encoders",
    "families",
    "library",
    "load_packs",
]
