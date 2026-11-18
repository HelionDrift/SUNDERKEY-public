"""Build the deterministic D009 deployment preparation packet."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_deployment import (
    build_candidate_enrollment_deployment_preparation,
)
from sunderkey.candidate_enrollment_implementation import (
    load_candidate_enrollment_implementation_report,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the D009 candidate enrollment deployment preparation packet"
    )
    parser.add_argument(
        "--implementation",
        default=str(registry / "candidate-enrollment-implementation-d009.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-deployment-preparation-d009.json"),
    )
    return parser


def build_packet(args: argparse.Namespace) -> dict[str, object]:
    implementation = load_candidate_enrollment_implementation_report(
        args.implementation
    )
    return build_candidate_enrollment_deployment_preparation(
        implementation
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
