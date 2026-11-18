"""Build the deterministic D008 qualification authority decision dossier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.implementation_roadmap import (
    load_specialist_implementation_roadmap,
)
from sunderkey.implementation_work_packages import (
    load_implementation_work_package_report,
)
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_dossier import (
    assess_qualification_authority_decision,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the pending D008 qualification authority dossier"
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
        "--roadmap",
        default=str(registry / "implementation-roadmap-army-v1.json"),
    )
    parser.add_argument(
        "--packages",
        default=str(
            registry / "implementation-work-packages-army-v1.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(
            registry / "qualification-authority-dossier-d008.json"
        ),
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
    roadmap = load_specialist_implementation_roadmap(args.roadmap)
    work_packages = load_implementation_work_package_report(args.packages)
    return assess_qualification_authority_decision(
        registry,
        capabilities,
        standard,
        roadmap,
        work_packages,
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
