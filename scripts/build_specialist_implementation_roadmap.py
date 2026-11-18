"""Build the deterministic full-Army specialist implementation roadmap."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_components import load_candidate_component_catalog
from sunderkey.candidate_inventory import (
    load_candidate_implementation_catalog,
)
from sunderkey.implementation_roadmap import (
    assess_specialist_implementation_roadmap,
)
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import (
    load_capability_catalog,
    load_routing_policy,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build deterministic specialist implementation waves"
    )
    parser.add_argument("--registry", default=str(registry / "army-v1.json"))
    parser.add_argument(
        "--capabilities",
        default=str(registry / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--policy",
        default=str(registry / "routing-policy-army-qualified-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(registry / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(registry / "qualification-plans-army-v1.json"),
    )
    parser.add_argument(
        "--blueprints",
        default=str(registry / "candidate-blueprints-army-v1.json"),
    )
    parser.add_argument(
        "--components",
        default=str(registry / "candidate-components-v1.json"),
    )
    parser.add_argument(
        "--candidates",
        default=str(registry / "candidate-implementations-v1.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "implementation-roadmap-army-v1.json"),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, capabilities)
    standard = load_qualification_standard(
        args.standard,
        registry,
        capabilities,
    )
    plans = load_qualification_plan_catalog(
        args.plans,
        registry,
        capabilities,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        capabilities,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components,
        blueprints,
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        capabilities,
        standard,
        plans,
        blueprints,
    )
    return assess_specialist_implementation_roadmap(
        registry,
        capabilities,
        policy,
        standard,
        plans,
        blueprints,
        components,
        candidates,
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
        f"{report['summary']['scheduled_profile_count']} scheduled profiles "
        f"in {report['summary']['wave_count']} waves: {output}"
    )


if __name__ == "__main__":
    main()
