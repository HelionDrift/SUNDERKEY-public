"""Build the deterministic approved D012 production custody decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_production_custody_decision import (
    load_candidate_enrollment_production_custody_decision_submission,
    record_candidate_enrollment_production_custody_decision,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    load_candidate_enrollment_production_custody_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the approved D012 decision")
    parser.add_argument(
        "--dossier",
        default=str(
            registry / "candidate-enrollment-production-custody-dossier-d012.json"
        ),
    )
    parser.add_argument(
        "--submission",
        default=str(
            registry
            / "candidate-enrollment-production-custody-decision-submission-d012.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(
            registry / "candidate-enrollment-production-custody-decision-d012.json"
        ),
    )
    return parser


def build_record(args: argparse.Namespace) -> dict[str, object]:
    return record_candidate_enrollment_production_custody_decision(
        load_candidate_enrollment_production_custody_dossier(args.dossier),
        load_candidate_enrollment_production_custody_decision_submission(
            args.submission
        ),
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    record = build_record(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(record, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {record['decision_id']} {record['decision_status']}: {output}")


if __name__ == "__main__":
    main()
