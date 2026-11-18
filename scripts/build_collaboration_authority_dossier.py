"""Build the deterministic D001-D005 collaboration authority dossier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.collaboration_authority_dossier import (
    assess_collaboration_authority_decisions,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog, load_routing_policy


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the pending D001-D005 collaboration authority dossier"
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
        "--output",
        default=str(registry / "collaboration-authority-dossier-d001-d005.json"),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    policy = load_routing_policy(args.policy, capabilities)
    return assess_collaboration_authority_decisions(
        registry,
        capabilities,
        policy,
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
        f"{len(report['decision_ids'])} collaboration decisions with "
        f"{len(report['alternatives'])} alternatives: {output}"
    )


if __name__ == "__main__":
    main()
