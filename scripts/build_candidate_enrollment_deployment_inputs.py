"""Build the blank D009 deployment worksheet and its preflight report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_deployment import (
    load_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_deployment_inputs import (
    assess_candidate_enrollment_deployment_inputs,
    build_candidate_enrollment_deployment_worksheet,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the blank D009 deployment worksheet and preflight"
    )
    parser.add_argument(
        "--preparation",
        default=str(registry / "candidate-enrollment-deployment-preparation-d009.json"),
    )
    parser.add_argument(
        "--worksheet-output",
        default=str(registry / "candidate-enrollment-deployment-worksheet-d009.json"),
    )
    parser.add_argument(
        "--preflight-output",
        default=str(registry / "candidate-enrollment-deployment-preflight-d009.json"),
    )
    return parser


def build_documents(args: argparse.Namespace) -> tuple[dict[str, object], dict[str, object]]:
    packet = load_candidate_enrollment_deployment_preparation(args.preparation)
    worksheet = build_candidate_enrollment_deployment_worksheet(packet)
    preflight = assess_candidate_enrollment_deployment_inputs(packet, worksheet)
    return worksheet.to_dict(), preflight.to_dict()


def _write_json(path: str, value: dict[str, object]) -> None:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    args = build_parser().parse_args()
    worksheet, preflight = build_documents(args)
    _write_json(args.worksheet_output, worksheet)
    _write_json(args.preflight_output, preflight)
    print(f"Wrote {worksheet['template_id']}: {Path(args.worksheet_output).resolve()}")
    print(f"Wrote {preflight['report_id']}: {Path(args.preflight_output).resolve()}")


if __name__ == "__main__":
    main()
