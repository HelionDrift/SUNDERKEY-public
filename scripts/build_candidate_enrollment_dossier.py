"""Build the deterministic D009 candidate enrollment decision dossier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_dossier import (
    assess_candidate_enrollment_decision,
)
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_decision import (
    load_qualification_authority_decision_record,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the pending D009 candidate enrollment dossier"
    )
    parser.add_argument("--registry", default=str(registry / "army-v1.json"))
    parser.add_argument(
        "--capabilities",
        default=str(registry / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(registry / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--authority-decision",
        default=str(
            registry / "qualification-authority-decision-d008.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "candidate-enrollment-dossier-d009.json"),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard,
        registry,
        capabilities,
    )
    authority_decision = load_qualification_authority_decision_record(
        args.authority_decision
    )
    return assess_candidate_enrollment_decision(
        registry,
        capabilities,
        standard,
        authority_decision,
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
    print(
        "Wrote "
        f"{report['decision_id']} with "
        f"{len(report['alternatives'])} alternatives: {output}"
    )


if __name__ == "__main__":
    main()
