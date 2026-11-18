"""Build the technical candidate implementation strategy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_implementation_strategy import build_candidate_implementation_strategy

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "registry" / "candidate-implementation-strategy-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    strategy = build_candidate_implementation_strategy()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(strategy.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "strategy_id": strategy.strategy_id,
                "strategy_sha256": strategy.strategy_sha256,
                "status": "valid",
                "operational_effect": "none",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
