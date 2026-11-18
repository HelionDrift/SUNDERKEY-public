#!/usr/bin/env python3
"""Build an inactive authenticated plan replacement authority upgrade."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    build_collaboration_plan_replacement_authority_upgrade_from_files,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--army-registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    upgrade = build_collaboration_plan_replacement_authority_upgrade_from_files(
        preflight_path=args.preflight,
        army_registry_path=args.army_registry,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(upgrade.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    print(
        json.dumps(
            {
                "upgrade_id": upgrade.upgrade_id,
                "upgrade_sha256": upgrade.upgrade_sha256,
                "runtime_effect": "none",
                "output": str(args.output.resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
