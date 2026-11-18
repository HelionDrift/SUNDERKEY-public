#!/usr/bin/env python3
"""Build the additive SUNDERKEY Army v2 registry and its closed schema."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.army_registry_v2 import validate_army_v2_migration
from sunderkey.registry import ExpertRegistry

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "registry" / "army-v1.json"
DEFAULT_ROADMAP = ROOT / "registry" / "army-expansion-roadmap-v1.json"
DEFAULT_SCHEMA_SOURCE = ROOT / "registry" / "schemas" / "registry.schema.json"
DEFAULT_OUTPUT = ROOT / "registry" / "army-v2.json"
DEFAULT_SCHEMA_OUTPUT = ROOT / "registry" / "schemas" / "registry-v2.schema.json"

COMMAND_SPECS = {
    "AOE-GD-D24": {
        "mission": (
            "Assess platform firmware, privileged management controllers, peripheral "
            "buses, accelerators, measured boot, and heterogeneous compute isolation."
        ),
        "inputs": (
            "Firmware images; update bundles; hardware inventory; schematics where "
            "available; debug access; attestation evidence; isolated lab targets; "
            "recovery images."
        ),
        "outputs": (
            "Platform-trust findings; firmware and peripheral attack paths; isolation "
            "evidence; impact bounds; restoration and remediation guidance."
        ),
        "collaboration": (
            "Embedded and IoT; Exploit Engineering; Cryptography; Cloud; AI; Software "
            "Supply Chain; Independent Control and Assurance."
        ),
        "boundary": (
            "Firmware writes, DMA tests, controller resets, and accelerator disruption "
            "require explicit target authority, recovery proof, monitoring, and an "
            "independent stop path."
        ),
    },
    "AOE-GD-D25": {
        "mission": (
            "Assess connected transportation, space, navigation, autonomous, medical, "
            "and clinical systems with consequence-aware and human-safety controls."
        ),
        "inputs": (
            "System and safety architecture; asset and protocol inventories; process "
            "hazards; operator contacts; simulators or digital twins; maintenance and "
            "restoration procedures."
        ),
        "outputs": (
            "Cross-domain attack paths; safety and availability observations; protocol "
            "findings; bounded impact evidence; restoration and resilience guidance."
        ),
        "collaboration": (
            "OT and ICS; Embedded and IoT; Network and Telecom; Identity; Cloud; "
            "Cryptography; Independent Control and Assurance."
        ),
        "boundary": (
            "No live action may risk life, clinical care, navigation, transport safety, "
            "public infrastructure, or irreversible equipment impact. Simulation, "
            "passive evidence, and operator-supervised validation take precedence."
        ),
    },
}

SHARED_PROFILE_SPECS = {
    "AOE-HQ-33": {
        "mission": (
            "Independently verifies target restoration, credential revocation, temporary "
            "artifact removal, service recovery, and declared residual effects before "
            "mission closure."
        ),
        "tags": ["shared", "independent-assurance", "restoration"],
    },
    "AOE-HQ-34": {
        "mission": (
            "Examines evidence for secrets, personal data, hostile content, unsafe "
            "payloads, and minimization requirements before storage, review, or release."
        ),
        "tags": ["shared", "independent-assurance", "evidence-safety"],
    },
    "AOE-HQ-35": {
        "mission": (
            "Reconciles claimed and observed effects across targets, providers, telemetry, "
            "evidence stores, and collaborating specialists before findings are accepted."
        ),
        "tags": ["shared", "independent-assurance", "effect-reconciliation"],
    },
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def specialist_profile(
    profile_id: str,
    name: str,
    group_id: str,
    command_id: str,
    category: str,
) -> dict[str, Any]:
    return {
        "id": profile_id,
        "name": name,
        "kind": "specialist",
        "version": "1.0.0",
        "status": "defined",
        "mission": (f"Provide {name} expertise for {category} missions within approved scope."),
        "policy_template": "specialist-v1",
        "max_autonomous_tier": "R2",
        "minimum_evidence_level": "E2",
        "tags": ["specialist", group_id.lower(), command_id[-3:].lower()],
        "group_id": group_id,
        "command_id": command_id,
        "category": category,
        "pilot": False,
    }


def commander_profile(
    command_id: str,
    name: str,
    group_id: str,
) -> dict[str, Any]:
    return {
        "id": f"{command_id}-CMD",
        "name": f"{name} Commander",
        "kind": "domain_commander",
        "version": "1.0.0",
        "status": "defined",
        "mission": (
            "Holds domain-specific stop authority, validates consequence and restoration "
            "controls, coordinates specialists and independent reviewers, and requires "
            "safer alternatives when live action is not justified."
        ),
        "policy_template": "domain-commander-v1",
        "max_autonomous_tier": "R0",
        "minimum_evidence_level": "E0",
        "tags": ["domain-commander", group_id.lower(), command_id[-3:].lower()],
        "group_id": group_id,
        "command_id": command_id,
        "category": "domain command",
        "pilot": False,
    }


def shared_profile(profile_id: str, name: str) -> dict[str, Any]:
    spec = SHARED_PROFILE_SPECS[profile_id]
    return {
        "id": profile_id,
        "name": name,
        "kind": "shared",
        "version": "1.0.0",
        "status": "defined",
        "mission": spec["mission"],
        "policy_template": "independent-assurance-v1",
        "max_autonomous_tier": "R0",
        "minimum_evidence_level": "E0",
        "tags": spec["tags"],
        "group_id": None,
        "command_id": None,
        "category": "independent assurance",
        "pilot": False,
    }


def build_registry(
    baseline: dict[str, Any],
    roadmap_document: dict[str, Any],
) -> dict[str, Any]:
    target = copy.deepcopy(baseline)
    target["catalog_id"] = "sunderkey-offensive-expert-army"
    target["catalog_version"] = "2.0.0"
    commands_by_id = {item["id"]: item for item in target["commands"]}
    additions: list[dict[str, Any]] = []

    for command_addition in roadmap_document["existing_command_additions"]:
        command_id = command_addition["command_id"]
        command_record = commands_by_id[command_id]
        for item in command_addition["specialists"]:
            command_record["specialist_profile_ids"].append(item["profile_id"])
            additions.append(
                specialist_profile(
                    item["profile_id"],
                    item["name"],
                    command_addition["group_id"],
                    command_id,
                    command_addition["name"],
                )
            )

    for command_addition in roadmap_document["new_commands"]:
        command_id = command_addition["command_id"]
        spec = COMMAND_SPECS[command_id]
        target["commands"].append(
            {
                "id": command_id,
                "number": int(command_id[-2:]),
                "group_id": command_addition["group_id"],
                "name": command_addition["name"],
                "mission": spec["mission"],
                "commander_profile_id": command_addition["commander_profile_id"],
                "specialist_profile_ids": [
                    item["profile_id"] for item in command_addition["specialists"]
                ],
                "inputs": spec["inputs"],
                "outputs": spec["outputs"],
                "collaboration": spec["collaboration"],
                "boundary": spec["boundary"],
            }
        )
        additions.append(
            commander_profile(
                command_id,
                command_addition["name"],
                command_addition["group_id"],
            )
        )
        additions.extend(
            specialist_profile(
                item["profile_id"],
                item["name"],
                command_addition["group_id"],
                command_id,
                command_addition["name"],
            )
            for item in command_addition["specialists"]
        )

    group_targets = {
        item["group_id"]: item["target_specialists"] for item in roadmap_document["group_targets"]
    }
    for group in target["groups"]:
        group["specialist_count"] = group_targets[group["id"]]
        if group["id"] == "GD":
            group["command_ids"].extend(["AOE-GD-D24", "AOE-GD-D25"])

    additions.extend(
        shared_profile(item["profile_id"], item["name"])
        for item in roadmap_document["shared_profile_additions"]
    )
    target["profiles"].extend(additions)
    target["count_contract"] = copy.deepcopy(roadmap_document["counts"]["target"])
    return target


def build_schema(source: dict[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(source)
    schema["$id"] = "https://schemas.sunderkey.dev/expert-registry/v2"
    schema["title"] = "SUNDERKEY Army v2 Expert Registry"
    schema["description"] = (
        "Closed structural contract for the additive SUNDERKEY Army v2 catalog. "
        "Runtime migration validation remains authoritative for v1 preservation, "
        "approved additions, hierarchy membership, inactivity, and exact counts."
    )
    schema["properties"]["catalog_id"] = {"const": "sunderkey-offensive-expert-army"}
    schema["properties"]["catalog_version"] = {"const": "2.0.0"}
    expected = {
        "groups": 5,
        "commands": 25,
        "specialists": 391,
        "domain_commanders": 25,
        "shared_profiles": 35,
        "total_profiles": 451,
        "pilot_specialists": 20,
    }
    for field, value in expected.items():
        schema["$defs"]["countContract"]["properties"][field]["const"] = value
    return schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    parser.add_argument("--schema-source", type=Path, default=DEFAULT_SCHEMA_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--schema-output", type=Path, default=DEFAULT_SCHEMA_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    baseline_document = load_json(args.baseline)
    roadmap = load_army_expansion_roadmap(args.roadmap)
    target_document = build_registry(baseline_document, roadmap.to_dict())
    baseline = ExpertRegistry.from_dict(baseline_document)
    target = ExpertRegistry.from_dict(target_document)
    report = validate_army_v2_migration(baseline, target, roadmap)
    schema = build_schema(load_json(args.schema_source))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.schema_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(target.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    args.schema_output.write_text(
        json.dumps(schema, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
