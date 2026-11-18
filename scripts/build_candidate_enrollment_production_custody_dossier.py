"""Build the deterministic D012 production custody decision dossier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_implementation import (
    load_candidate_enrollment_activation_implementation_report,
)
from sunderkey.candidate_enrollment_canary import (
    load_candidate_enrollment_canary_preparation,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    build_candidate_enrollment_production_custody_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the D012 custody dossier")
    parser.add_argument(
        "--implementation",
        default=str(
            registry / "candidate-enrollment-activation-implementation-d011.json"
        ),
    )
    parser.add_argument(
        "--canary",
        default=str(registry / "candidate-enrollment-canary-preparation-d011.json"),
    )
    parser.add_argument(
        "--output",
        default=str(
            registry / "candidate-enrollment-production-custody-dossier-d012.json"
        ),
    )
    return parser


def build_dossier(args: argparse.Namespace) -> dict[str, object]:
    return build_candidate_enrollment_production_custody_dossier(
        load_candidate_enrollment_activation_implementation_report(
            args.implementation
        ),
        load_candidate_enrollment_canary_preparation(args.canary),
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    dossier = build_dossier(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(dossier, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {dossier['report_id']}: {output}")


if __name__ == "__main__":
    main()
