"""Build the Phase 157 containment backend conformance suite catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_backend_conformance import (
    build_containment_conformance_suite_catalog,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "registry" / "candidate-containment-conformance-suites-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    catalog = build_containment_conformance_suite_catalog()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "catalog_sha256": catalog.catalog_sha256,
                "suite_count": len(catalog.suites),
                "status": "valid_nonqualifying",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
