"""Build the deterministic D011 checkpoint and release policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_activation_decision import (
    load_candidate_enrollment_activation_decision_record,
)
from sunderkey.candidate_enrollment_release_contract import (
    build_candidate_enrollment_release_policy,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the approved D011 checkpoint and release policy"
    )
    parser.add_argument(
        "--decision",
        default=str(registry / "candidate-enrollment-activation-decision-d011.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-release-policy-d011.json"),
    )
    return parser


def build_policy(args: argparse.Namespace) -> dict[str, object]:
    decision = load_candidate_enrollment_activation_decision_record(args.decision)
    return build_candidate_enrollment_release_policy(decision).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    policy = build_policy(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(policy, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {policy['policy_id']}: {output}")


if __name__ == "__main__":
    main()
