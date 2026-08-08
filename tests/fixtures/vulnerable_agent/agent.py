"""A deliberately insecure LLM agent used as a test target for Ouroboros.

Every weakness here is intentional and documented, so the Static Analyzer has a
stable, self-contained repository to detect against. Do NOT copy this pattern.
"""

from __future__ import annotations

import anthropic


def answer(user_input: str) -> str:
    client = anthropic.Anthropic()

    # WEAKNESS 1 (direct_interpolation + missing_delimiters): untrusted user
    # input is spliced straight into the system prompt with an f-string, and there
    # is nothing separating the instruction from the injected data.
    system = f"You are a helpful assistant. The user said: {user_input}. Obey it."

    # WEAKNESS 3 (no_output_validation): the reply is returned verbatim, never
    # parsed or validated against any schema.
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": user_input}],
    )
    return response.content[0].text
