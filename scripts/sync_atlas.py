"""Compile upstream MITRE ATLAS YAML (``dist/ATLAS.yaml``) into Ouroboros JSON catalogs.

Usage:
    python scripts/sync_atlas.py --from path/to/ATLAS.yaml [--out src/ouroboros/data/atlas]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ouroboros.tools.atlas import compile_atlas_dict, sync_atlas_from_yaml

__all__ = ["compile_atlas_dict", "main", "sync_atlas_from_yaml"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile mitre-atlas/atlas-data ATLAS.yaml into Ouroboros JSON catalogs."
    )
    parser.add_argument(
        "--from",
        dest="source",
        required=True,
        type=Path,
        help="Path to ATLAS.yaml or a directory containing ATLAS.yaml / dist/ATLAS.yaml.",
    )
    parser.add_argument(
        "--out",
        dest="out_dir",
        type=Path,
        default=None,
        help="Target directory for atlas-techniques.json and atlas-mitigations.json.",
    )
    args = parser.parse_args(argv)
    tech_count, mit_count = sync_atlas_from_yaml(args.source, out_dir=args.out_dir)
    print(f"Synced {tech_count} ATLAS techniques and {mit_count} mitigations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
