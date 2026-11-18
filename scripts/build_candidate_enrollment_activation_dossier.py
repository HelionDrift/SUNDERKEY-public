"""Build the deterministic D011 checkpoint custody decision dossier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_dossier import (
    build_candidate_enrollment_activation_decision_dossier,
)
from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_deployment import (
    load_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_implementation import (
    load_candidate_enrollment_implementation_report,
)
from sunderkey.validation import loads_json_without_duplicate_keys


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the D011 checkpoint custody and activation dossier"
    )
    parser.add_argument(
        "--d009-decision",
        default=str(registry / "candidate-enrollment-decision-d009.json"),
    )
    parser.add_argument(
        "--implementation",
        default=str(registry / "candidate-enrollment-implementation-d009.json"),
    )
    parser.add_argument(
        "--preparation",
        default=str(registry / "candidate-enrollment-deployment-preparation-d009.json"),
    )
    parser.add_argument(
        "--verification-receipt-schema",
        default=str(
            registry
            / "schemas"
            / "candidate-enrollment-deployment-verification-receipt-v1.schema.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-activation-dossier-d011.json"),
    )
    return parser


def build_dossier(args: argparse.Namespace) -> dict[str, object]:
    schema_path = Path(args.verification_receipt_schema)
    schema = loads_json_without_duplicate_keys(schema_path.read_text(encoding="utf-8"))
    return build_candidate_enrollment_activation_decision_dossier(
        load_candidate_enrollment_decision_record(args.d009_decision),
        load_candidate_enrollment_implementation_report(args.implementation),
        load_candidate_enrollment_deployment_preparation(args.preparation),
        schema,
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
