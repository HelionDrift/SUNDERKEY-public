"""Build the deterministic D011 single-candidate canary preparation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_decision import (
    load_candidate_enrollment_activation_decision_record,
)
from sunderkey.candidate_enrollment_canary import (
    build_candidate_enrollment_canary_preparation,
)
from sunderkey.candidate_enrollment_release_contract import (
    load_candidate_enrollment_release_policy,
)
from sunderkey.validation import loads_json_without_duplicate_keys


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    schemas = registry / "schemas"
    parser = argparse.ArgumentParser(description="Build the D011 canary preparation")
    parser.add_argument(
        "--decision",
        default=str(registry / "candidate-enrollment-activation-decision-d011.json"),
    )
    parser.add_argument(
        "--policy",
        default=str(registry / "candidate-enrollment-release-policy-d011.json"),
    )
    parser.add_argument(
        "--normal-completion-schema",
        default=str(
            schemas / "candidate-enrollment-release-completion-receipt-v1.schema.json"
        ),
    )
    parser.add_argument(
        "--recovery-completion-schema",
        default=str(
            schemas / "candidate-enrollment-release-recovery-receipt-v1.schema.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-canary-preparation-d011.json"),
    )
    return parser


def build_packet(args: argparse.Namespace) -> dict[str, object]:
    normal = loads_json_without_duplicate_keys(
        Path(args.normal_completion_schema).read_text(encoding="utf-8")
    )
    recovery = loads_json_without_duplicate_keys(
        Path(args.recovery_completion_schema).read_text(encoding="utf-8")
    )
    return build_candidate_enrollment_canary_preparation(
        load_candidate_enrollment_activation_decision_record(args.decision),
        load_candidate_enrollment_release_policy(args.policy),
        normal,
        recovery,
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    packet = build_packet(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(packet, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {packet['packet_id']}: {output}")


if __name__ == "__main__":
    main()
