"""Ouroboros Red Team — an agent that audits, attacks and patches other LLM agents.

The package is deliberately small at its core: a set of Pydantic contracts
(:mod:`ouroboros.schemas`) that every agent boundary must speak, and a handful of
pure-function agents (:mod:`ouroboros.agents`) wired together by
:mod:`ouroboros.orchestrator`. Nothing between agents is free text — a finding
that cannot be expressed as a validated model is a finding that does not exist.

The name is the point: the Ouroboros, the snake that eats its own tail, is a
system that examines itself. This tool red-teams the very agents its author
builds.
"""

from __future__ import annotations

__version__ = "0.1.0"
