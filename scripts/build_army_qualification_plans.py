"""Build the reviewed full-Army qualification plan catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SPECIALIST_ID_PATTERN = re.compile(
    r"AOE-G[A-E]-D[0-9]{2}-S[0-9]{2}"
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the full-Army specialist qualification plans"
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
        "--output",
        default=str(
            root / "registry" / "qualification-plans-army-v1.json"
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


def _scenario_family_id(profile_id: str) -> str:
    if SPECIALIST_ID_PATTERN.fullmatch(profile_id) is None:
        raise ValueError(f"Invalid specialist profile ID: {profile_id}")
    return "qualification." + profile_id.lower()


def build_plan_catalog(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
) -> dict[str, Any]:
    profiles = registry.get("profiles")
    assignments = capabilities.get("profile_assignments")
    gates = standard.get("gates")
    if not isinstance(profiles, list):
        raise ValueError("Registry profiles must be a list")
    if not isinstance(assignments, list):
        raise ValueError("Capability assignments must be a list")
    if not isinstance(gates, list) or not gates:
        raise ValueError("Qualification standard gates must be a list")
    specialists = sorted(
        (
            profile
            for profile in profiles
            if (
                isinstance(profile, dict)
                and profile.get("kind") == "specialist"
            )
        ),
        key=lambda profile: str(profile.get("id")),
    )
    assignments_by_profile = {
        str(assignment["profile_id"]): assignment
        for assignment in assignments
        if isinstance(assignment, dict)
    }
    gate_ids = sorted(str(gate["id"]) for gate in gates)
    plans: list[dict[str, Any]] = []
    for profile in specialists:
        profile_id = str(profile["id"])
        assignment = assignments_by_profile.get(profile_id)
        if assignment is None:
            raise ValueError(
                f"Missing capability assignment for {profile_id}"
            )
        name = str(profile["name"])
        category = str(profile["category"])
        plans.append(
            {
                "profile_id": profile_id,
                "scenario_family_id": _scenario_family_id(profile_id),
                "technical_focus": name,
                "evaluation_objective": (
                    f"Demonstrate {name} expertise for {category} missions "
                    "in offline, synthetic, or test scenarios."
                ),
                "primary_capability_ids": sorted(
                    str(item)
                    for item in assignment["primary_capability_ids"]
                ),
                "required_gate_ids": gate_ids,
            }
        )
    if set(assignments_by_profile) != {
        str(profile["id"]) for profile in specialists
    }:
        raise ValueError(
            "Capability assignments must exactly match all specialists"
        )
    return {
        "schema_version": 1,
        "plan_catalog_id": "sunderkey-army-qualification-plans",
        "plan_catalog_version": "1.0.0",
        "qualification_standard_id": str(standard["standard_id"]),
        "qualification_standard_version": str(
            standard["standard_version"]
        ),
        "qualification_standard_sha256": _canonical_sha256(standard),
        "expert_catalog_id": str(registry["catalog_id"]),
        "expert_catalog_version": str(registry["catalog_version"]),
        "capability_catalog_id": str(capabilities["catalog_id"]),
        "capability_catalog_version": str(
            capabilities["catalog_version"]
        ),
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "profile_plans": plans,
    }


def main() -> None:
    args = build_parser().parse_args()
    catalog = build_plan_catalog(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
    )
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(catalog, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(catalog['profile_plans'])} plans: {output}")


if __name__ == "__main__":
    main()
