"""The agents that make up the Ouroboros pipeline.

Each module here exposes one pure function — ``profile``, ``analyze``,
``attack``, ``generate`` — that takes its input contract and returns its output
contract, and nothing more. No agent knows about the orchestrator, and none of
them builds an LLM client or clones a repo behind the caller's back, so every one
of them is testable offline. State, when it is needed, lives in a
``@dataclass``, never in an agent object.

Reality check for this milestone (weeks 1-3): ``recon`` and ``static_analyzer``
are real; ``dynamic_attacker`` and ``patch_generator`` are honest, well-typed
stubs that return empty results until weeks 4-6.
"""

from __future__ import annotations
