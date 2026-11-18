"""Build the deterministic approved D011 activation decision record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_decision import (
    load_candidate_enrollment_activation_decision_submission,
    record_candidate_enrollment_activation_decision,
)
from sunderkey.candidate_enrollment_activation_dossier import (
    load_candidate_enrollment_activation_decision_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the approved D011 checkpoint custody decision record"
    )
    parser.add_argument(
        "--dossier",
        default=str(registry / "candidate-enrollment-activation-dossier-d011.json"),
    )
    parser.add_argument(
        "--submission",
        default=str(
            registry / "candidate-enrollment-activation-decision-submission-d011.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-activation-decision-d011.json"),
    )
    return parser


def build_record(args: argparse.Namespace) -> dict[str, object]:
    dossier = load_candidate_enrollment_activation_decision_dossier(args.dossier)
    submission = load_candidate_enrollment_activation_decision_submission(
        args.submission
    )
    return record_candidate_enrollment_activation_decision(
        dossier, submission
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
