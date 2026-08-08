"""The payload library is data with invariants; pin the ones the attacker relies on."""

from __future__ import annotations

import base64
import codecs

from ouroboros.payloads import families, library
from ouroboros.tools.atlas import verify_atlas_technique

CANARY = "OURO-TESTCANARY"


def test_library_has_at_least_ten_payloads() -> None:
    assert len(library()) >= 10


def test_all_four_families_are_represented() -> None:
    assert families() == {"direct", "indirect", "jailbreak", "encoding"}


def test_payload_ids_are_unique() -> None:
    ids = [p.id for p in library()]
    assert len(ids) == len(set(ids))


def test_every_atlas_id_exists_in_the_catalog() -> None:
    for payload in library():
        assert payload.atlas_ids
        for technique_id in payload.atlas_ids:
            assert verify_atlas_technique(technique_id) is not None, technique_id


def test_plaintext_families_embed_the_canary() -> None:
    for payload in library():
        if payload.encoding == "none":
            assert CANARY in payload.render(CANARY)


def test_encoded_payloads_hide_but_recover_the_canary() -> None:
    for payload in library():
        rendered = payload.render(CANARY)
        if payload.encoding == "base64":
            assert CANARY not in rendered  # not in the clear
            blob = rendered.strip().splitlines()[-1]
            assert CANARY in base64.b64decode(blob).decode("utf-8")
        elif payload.encoding == "rot13":
            assert CANARY not in rendered
            blob = rendered.strip().splitlines()[-1]
            assert CANARY in codecs.decode(blob, "rot_13")
