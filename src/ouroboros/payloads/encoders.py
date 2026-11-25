"""Deterministic, reversible text transforms used by payloads and adaptive mutation.

Each encoder hides the "emit the canary" instruction from naive keyword filters
while staying trivially decodable by a capable model — which is exactly what an
obfuscation-family probe tests (MITRE ATLAS ``AML.T0068`` LLM Prompt
Obfuscation). Every encoder has a matching decoder so the offline simulator (and
the tests) can recover the canary the same way a model would.
"""

from __future__ import annotations

import base64
import codecs
import urllib.parse
from collections.abc import Callable
from typing import Literal

Encoding = Literal[
    "none",
    "base64",
    "rot13",
    "hex",
    "leetspeak",
    "zero_width",
    "homoglyph",
    "reverse",
    "url",
]

# Zero-width space between every character: invisible when rendered, still
# trivially readable for a tokenizer once stripped.
_ZWSP = "\u200b"

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
_UNLEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"})

# Latin -> Cyrillic look-alikes (only lowercase letters; digits/uppercase pass
# through so a canary such as OURO-1A2B survives verbatim).
_HOMO = str.maketrans(
    {
        "a": "\u0430",
        "e": "\u0435",
        "o": "\u043e",
        "p": "\u0440",
        "c": "\u0441",
        "x": "\u0445",
        "y": "\u0443",
    }
)
_UNHOMO = str.maketrans(
    {
        v: k
        for k, v in {
            "a": "\u0430",
            "e": "\u0435",
            "o": "\u043e",
            "p": "\u0440",
            "c": "\u0441",
            "x": "\u0445",
            "y": "\u0443",
        }.items()
    }
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _unb64(text: str) -> str:
    return base64.b64decode(text.strip(), validate=True).decode("utf-8", "replace")


def _hex(text: str) -> str:
    return text.encode("utf-8").hex()


def _unhex(text: str) -> str:
    return bytes.fromhex(text.strip()).decode("utf-8", "replace")


def _leet(text: str) -> str:
    # Leave the canary (uppercase) intact: only lowercase letters are swapped.
    return "".join(ch.translate(_LEET) if ch.islower() else ch for ch in text)


def _unleet(text: str) -> str:
    return text.translate(_UNLEET)


ENCODERS: dict[Encoding, Callable[[str], str]] = {
    "none": lambda t: t,
    "base64": _b64,
    "rot13": lambda t: codecs.encode(t, "rot_13"),
    "hex": _hex,
    "leetspeak": _leet,
    "zero_width": lambda t: _ZWSP.join(t),
    "homoglyph": lambda t: t.translate(_HOMO),
    "reverse": lambda t: t[::-1],
    "url": lambda t: urllib.parse.quote(t, safe=""),
}

DECODERS: dict[Encoding, Callable[[str], str]] = {
    "none": lambda t: t,
    "base64": _unb64,
    "rot13": lambda t: codecs.decode(t, "rot_13"),
    "hex": _unhex,
    "leetspeak": _unleet,
    "zero_width": lambda t: t.replace(_ZWSP, ""),
    "homoglyph": lambda t: t.translate(_UNHOMO),
    "reverse": lambda t: t[::-1],
    "url": urllib.parse.unquote,
}

# Encodings whose output no longer contains the canary in the clear.
OPAQUE_ENCODINGS: frozenset[Encoding] = frozenset(
    {"base64", "rot13", "hex", "zero_width", "reverse", "url"}
)


def encode(text: str, encoding: Encoding) -> str:
    """Apply ``encoding`` to ``text``."""
    return ENCODERS[encoding](text)


def decode(text: str, encoding: Encoding) -> str:
    """Invert ``encoding``; raises ``ValueError`` on malformed input."""
    try:
        return DECODERS[encoding](text)
    except (ValueError, UnicodeDecodeError) as exc:  # binascii.Error is a ValueError
        raise ValueError(f"cannot decode as {encoding}: {exc}") from exc
