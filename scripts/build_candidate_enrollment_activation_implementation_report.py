"""Build the deterministic D011 implementation completion report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_decision import (
    load_candidate_enrollment_activation_decision_record,
)
from sunderkey.candidate_enrollment_activation_implementation import (
    build_candidate_enrollment_activation_implementation_report,
)
from sunderkey.candidate_enrollment_canary import (
    load_candidate_enrollment_canary_preparation,
)
from sunderkey.candidate_enrollment_release_contract import (
    load_candidate_enrollment_release_policy,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the D011 implementation report")
    parser.add_argument(
        "--decision",
        default=str(registry / "candidate-enrollment-activation-decision-d011.json"),
    )
    parser.add_argument(
        "--policy",
        default=str(registry / "candidate-enrollment-release-policy-d011.json"),
    )
    parser.add_argument(
        "--canary",
        default=str(registry / "candidate-enrollment-canary-preparation-d011.json"),
    )
    parser.add_argument(
        "--output",
        default=str(
            registry / "candidate-enrollment-activation-implementation-d011.json"
        ),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    return build_candidate_enrollment_activation_implementation_report(
        load_candidate_enrollment_activation_decision_record(args.decision),
        load_candidate_enrollment_release_policy(args.policy),
        load_candidate_enrollment_canary_preparation(args.canary),
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    report = build_report(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {report['report_id']}: {output}")


if __name__ == "__main__":
    main()
