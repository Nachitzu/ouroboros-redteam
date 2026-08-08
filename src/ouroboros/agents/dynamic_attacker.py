"""The Dynamic Attacker: send adversarial payloads and record what moves.

STATUS: typed stub (weeks 4-5). ``attack`` returns an empty list today so the
pipeline runs end-to-end and the report is honest about having done no dynamic
testing. The contract and signature are frozen now so wiring the real attacker in
later is an implementation change, not an interface change.

When it is real, it will run in two modes that must stay visibly distinct:
  * owner   — payloads hit a real, locally-run instance; hits are ``confirmed_live``.
  * auditor — payloads hit a mocked client; hits are ``simulated`` and labelled as
    reduced-confidence in the report.
Either way it will rate-limit itself and never touch a production endpoint.
"""

from __future__ import annotations

from typing import Any

from ouroboros.schemas.dynamic_finding import DynamicFinding
from ouroboros.schemas.repo_profile import RepoProfile


def attack(
    profile: RepoProfile,
    *,
    client: Any | None = None,
    max_payloads: int = 20,
) -> list[DynamicFinding]:
    """Return dynamic findings for a target. Stub: no payloads are sent yet.

    Kept a pure function with the real signature (``max_payloads`` is the future
    rate-limit knob) so callers written now do not change when week 4 lands.
    """
    _ = (profile, client, max_payloads)  # referenced so the stub reads as intentional
    return []
