"""Build the deterministic D009 contract implementation completion report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_implementation import (
    build_candidate_enrollment_implementation_report,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the D009 enrollment implementation completion report"
    )
    parser.add_argument(
        "--decision",
        default=str(registry / "candidate-enrollment-decision-d009.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-implementation-d009.json"),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    decision = load_candidate_enrollment_decision_record(args.decision)
    return build_candidate_enrollment_implementation_report(decision).to_dict()


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
