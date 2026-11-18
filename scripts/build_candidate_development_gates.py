"""Build Phase 157 reference-candidate development gate records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from scripts.build_candidate_adapter_catalog import load_blueprints
except ModuleNotFoundError:
    from build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_evidence import build_candidate_development_gate_catalog
from sunderkey.candidate_adapter_sdk import load_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = ROOT / "registry"
OUTPUT_PATH = REGISTRY_DIR / "candidate-adapter-development-gates-v1.json"


def load_adapters():
    strategy = load_candidate_implementation_strategy(
        REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
    )
    return load_candidate_adapter_catalog(
        REGISTRY_DIR / "candidate-adapters-reference-v1.json",
        strategy,
        load_blueprints(),
        ROOT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    catalog = build_candidate_development_gate_catalog(load_adapters(), ROOT)
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
                **catalog.to_dict()["coverage_summary"],
                "phase158_admission_status": "blocked",
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
