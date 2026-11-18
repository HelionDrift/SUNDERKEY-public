"""Build deterministic implementation blueprints for all specialists."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

BLUEPRINT_DOMAIN = "sunderkey.candidate-blueprint.v1"
REQUIRED_COMPONENT_IDS = [
    "behavior_contract",
    "instruction_bundle",
    "knowledge_manifest",
    "runtime_manifest",
    "tool_policy",
]


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build provider-neutral specialist candidate blueprints"
    )
    parser.add_argument(
        "--registry",
        default=str(root / "registry" / "army-v1.json"),
    )
    parser.add_argument(
        "--capabilities",
        default=str(root / "registry" / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(root / "registry" / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(
            root / "registry" / "qualification-plans-army-v1.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(
            root / "registry" / "candidate-blueprints-army-v1.json"
        ),
    )
    return parser


def _read_json(path: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {resolved}")
    return value


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _blueprint_sha256(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": BLUEPRINT_DOMAIN,
            "blueprint": body,
        }
    )


def build_catalog(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
) -> dict[str, Any]:
    policies = {
        item["id"]: item for item in registry["policy_templates"]
    }
    commands = {item["id"]: item for item in registry["commands"]}
    assignments = {
        item["profile_id"]: item
        for item in capabilities["profile_assignments"]
    }
    profile_plans = {
        item["profile_id"]: item for item in plans["profile_plans"]
    }
    blueprints: list[dict[str, Any]] = []
    for profile in sorted(
        (
            item
            for item in registry["profiles"]
            if item["kind"] == "specialist"
        ),
        key=lambda item: item["id"],
    ):
        policy = policies[profile["policy_template"]]
        command = commands[profile["command_id"]]
        assignment = assignments[profile["id"]]
        plan = profile_plans[profile["id"]]
        body = {
            "profile_id": profile["id"],
            "profile_version": profile["version"],
            "name": profile["name"],
            "group_id": profile["group_id"],
            "command_id": profile["command_id"],
            "category": profile["category"],
            "mission": profile["mission"],
            "policy_template_id": policy["id"],
            "allowed_actions": policy["may"],
            "prohibited_actions": policy["may_not"],
            "stop_conditions": policy["stop_conditions"],
            "maximum_autonomous_action_tier": profile[
                "max_autonomous_tier"
            ],
            "minimum_evidence_level": profile[
                "minimum_evidence_level"
            ],
            "primary_capability_ids": assignment[
                "primary_capability_ids"
            ],
            "supporting_capability_ids": assignment[
                "supporting_capability_ids"
            ],
            "scenario_family_id": plan["scenario_family_id"],
            "evaluation_objective": plan["evaluation_objective"],
            "required_gate_ids": plan["required_gate_ids"],
            "command_mission": command["mission"],
            "expected_inputs": command["inputs"],
            "expected_outputs": command["outputs"],
            "collaboration_contract": command["collaboration"],
            "command_boundary": command["boundary"],
        }
        blueprints.append(
            {
                **body,
                "blueprint_sha256": _blueprint_sha256(body),
            }
        )
    return {
        "schema_version": 1,
        "blueprint_catalog_id": "sunderkey-specialist-blueprints",
        "blueprint_catalog_version": "1.0.0",
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "qualification_plan_catalog_id": plans["plan_catalog_id"],
        "qualification_plan_catalog_version": plans[
            "plan_catalog_version"
        ],
        "qualification_plan_catalog_sha256": _canonical_sha256(plans),
        "required_component_ids": REQUIRED_COMPONENT_IDS,
        "blueprints": blueprints,
    }


def main() -> None:
    args = build_parser().parse_args()
    catalog = build_catalog(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
        _read_json(args.plans),
    )
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(catalog, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(catalog['blueprints'])} blueprints: {output}")


if __name__ == "__main__":
    main()
