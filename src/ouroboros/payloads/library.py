"""The versioned library of prompt-injection payloads.

Each payload is inert data until the Dynamic Attacker renders and sends it.
Built-in payloads now live in JSONL packs under ``src/ouroboros/data/payloads/``;
``library()`` and ``PAYLOAD_LIBRARY`` expose the default ``core`` pack for
backward compatibility while ``available_packs()`` and ``load_packs()`` unlock
the full pack catalog.
"""

from __future__ import annotations

from ouroboros.payloads.encoders import Encoding
from ouroboros.payloads.model import Payload
from ouroboros.payloads.packs import available_packs, load_packs
from ouroboros.schemas.common import PayloadFamily

__all__ = [
    "PAYLOAD_LIBRARY",
    "Encoding",
    "Payload",
    "available_packs",
    "families",
    "library",
    "load_packs",
]


def library() -> tuple[Payload, ...]:
    """Return the default ``core`` payload pack, in a stable order."""
    return load_packs(None)


def families() -> set[PayloadFamily]:
    """Return the set of families represented in the default ``core`` library."""
    return {p.family for p in library()}


PAYLOAD_LIBRARY: tuple[Payload, ...] = library()
