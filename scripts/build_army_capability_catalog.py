"""Build the reviewed full-Army capability catalog artifact."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SPECIALIST_ID_PATTERN = re.compile(
    r"AOE-G([A-E])-D([0-9]{2})-S([0-9]{2})"
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the full-Army specialist capability catalog"
    )
    parser.add_argument(
        "--registry",
        default=str(root / "registry" / "army-v1.json"),
    )
    parser.add_argument(
        "--pilot-capabilities",
        default=str(
            root / "registry" / "capabilities-pilot-v1.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(
            root / "registry" / "capabilities-army-v1.json"
        ),
    )
    return parser


def _read_json(path: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {resolved}")
    return value


def _full_army_capability_id(profile_id: str) -> str:
    match = SPECIALIST_ID_PATTERN.fullmatch(profile_id)
    if match is None:
        raise ValueError(f"Invalid specialist profile ID: {profile_id}")
    group, command, specialist = match.groups()
    return (
        f"army.g{group.lower()}.d{command}.s{specialist}"
    )


def build_catalog(
    registry: dict[str, Any],
    pilot_catalog: dict[str, Any],
) -> dict[str, Any]:
    profiles = registry.get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("Registry profiles must be a list")
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
    pilot_capabilities = pilot_catalog.get("capabilities")
    pilot_assignments = pilot_catalog.get("profile_assignments")
    if not isinstance(pilot_capabilities, list) or not isinstance(
        pilot_assignments,
        list,
    ):
        raise ValueError("Pilot capability catalog is invalid")
    capabilities = {
        str(capability["id"]): dict(capability)
        for capability in pilot_capabilities
    }
    pilot_by_profile = {
        str(assignment["profile_id"]): dict(assignment)
        for assignment in pilot_assignments
    }
    assignments: list[dict[str, Any]] = []
    for profile in specialists:
        profile_id = str(profile["id"])
        pilot_assignment = pilot_by_profile.get(profile_id)
        if pilot_assignment is not None:
            assignments.append(pilot_assignment)
            continue
        capability_id = _full_army_capability_id(profile_id)
        if capability_id in capabilities:
            raise ValueError(
                f"Duplicate generated capability ID: {capability_id}"
            )
        capabilities[capability_id] = {
            "id": capability_id,
            "name": str(profile["name"]),
        }
        assignments.append(
            {
                "profile_id": profile_id,
                "primary_capability_ids": [capability_id],
                "supporting_capability_ids": [],
            }
        )
    specialist_ids = {str(profile["id"]) for profile in specialists}
    if set(pilot_by_profile) - specialist_ids:
        raise ValueError(
            "Pilot catalog contains a non-specialist assignment"
        )
    if len(capabilities) != len(specialists):
        raise ValueError(
            "Full-Army catalog must have one primary capability per "
            "specialist"
        )
    return {
        "schema_version": 2,
        "profile_scope": "all_specialists",
        "catalog_id": "sunderkey-army-capabilities",
        "catalog_version": "1.0.0",
        "expert_catalog_id": str(registry["catalog_id"]),
        "expert_catalog_version": str(registry["catalog_version"]),
        "capabilities": [
            capabilities[capability_id]
            for capability_id in sorted(capabilities)
        ],
        "profile_assignments": sorted(
            assignments,
            key=lambda assignment: str(assignment["profile_id"]),
        ),
    }


def main() -> None:
    args = build_parser().parse_args()
    catalog = build_catalog(
        _read_json(args.registry),
        _read_json(args.pilot_capabilities),
    )
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            catalog,
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(catalog['profile_assignments'])} assignments: {output}")


if __name__ == "__main__":
    main()
