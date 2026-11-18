#!/usr/bin/env python3
"""Build the Army v2 capability graph from v1 primaries and v2 vectors."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.capability_graph_v2 import validate_capability_graph_v2
from sunderkey.registry import load_registry
from sunderkey.routing import CapabilityCatalog, load_capability_catalog

ROOT = Path(__file__).resolve().parents[1]
BASELINE_REGISTRY = ROOT / "registry" / "army-v1.json"
TARGET_REGISTRY = ROOT / "registry" / "army-v2.json"
BASELINE_CAPABILITIES = ROOT / "registry" / "capabilities-army-v1.json"
VECTOR_CATALOG = ROOT / "registry" / "attack-vectors-v2.json"
ROADMAP = ROOT / "registry" / "army-expansion-roadmap-v1.json"
SCHEMA_SOURCE = ROOT / "registry" / "schemas" / "capability-catalog.schema.json"
DEFAULT_OUTPUT = ROOT / "registry" / "capabilities-army-v2.json"
DEFAULT_SCHEMA_OUTPUT = ROOT / "registry" / "schemas" / "capability-catalog-v2.schema.json"
SPECIALIST_PATTERN = re.compile(r"AOE-G([A-E])-D([0-9]{2})-S([0-9]{2})")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def generated_capability_id(profile_id: str) -> str:
    match = SPECIALIST_PATTERN.fullmatch(profile_id)
    if match is None:
        raise ValueError(f"Invalid specialist profile ID: {profile_id}")
    group, command, specialist = match.groups()
    return f"army.g{group.lower()}.d{command}.s{specialist}"


def build_catalog(
    target_registry: dict[str, Any],
    baseline_catalog: dict[str, Any],
    vector_catalog: dict[str, Any],
) -> dict[str, Any]:
    definitions = {item["id"]: copy.deepcopy(item) for item in baseline_catalog["capabilities"]}
    baseline_assignments = {
        item["profile_id"]: item for item in baseline_catalog["profile_assignments"]
    }
    specialists = sorted(
        (item for item in target_registry["profiles"] if item["kind"] == "specialist"),
        key=lambda item: item["id"],
    )
    primary_by_profile: dict[str, str] = {}
    for profile in specialists:
        profile_id = profile["id"]
        old = baseline_assignments.get(profile_id)
        if old is not None:
            if len(old["primary_capability_ids"]) != 1:
                raise ValueError(f"{profile_id} must have one v1 primary capability")
            primary_by_profile[profile_id] = old["primary_capability_ids"][0]
            continue
        capability_id = generated_capability_id(profile_id)
        if capability_id in definitions:
            raise ValueError(f"Duplicate generated capability ID: {capability_id}")
        definitions[capability_id] = {"id": capability_id, "name": profile["name"]}
        primary_by_profile[profile_id] = capability_id

    vectors_by_primary = {item["primary_specialist_id"]: item for item in vector_catalog["vectors"]}
    assignments: list[dict[str, Any]] = []
    for profile in specialists:
        profile_id = profile["id"]
        vector = vectors_by_primary[profile_id]
        assignments.append(
            {
                "profile_id": profile_id,
                "primary_capability_ids": [primary_by_profile[profile_id]],
                "supporting_capability_ids": sorted(
                    primary_by_profile[item] for item in vector["supporting_specialist_ids"]
                ),
            }
        )

    return {
        "schema_version": 2,
        "profile_scope": "all_specialists",
        "catalog_id": "sunderkey-army-capabilities-v2",
        "catalog_version": "2.0.0",
        "expert_catalog_id": target_registry["catalog_id"],
        "expert_catalog_version": target_registry["catalog_version"],
        "capabilities": [definitions[item] for item in sorted(definitions)],
        "profile_assignments": assignments,
    }


def build_schema(source: dict[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(source)
    schema["$id"] = "https://schemas.sunderkey.dev/capability-catalog-v2.json"
    schema["title"] = "SUNDERKEY Army v2 Capability Graph"
    schema["properties"]["schema_version"] = {"const": 2}
    schema["properties"]["catalog_id"] = {"const": "sunderkey-army-capabilities-v2"}
    schema["properties"]["catalog_version"] = {"const": "2.0.0"}
    schema["properties"]["expert_catalog_id"] = {"const": "sunderkey-offensive-expert-army"}
    schema["properties"]["expert_catalog_version"] = {"const": "2.0.0"}
    schema["properties"]["capabilities"]["minItems"] = 391
    schema["properties"]["capabilities"]["maxItems"] = 391
    schema["properties"]["profile_assignments"]["minItems"] = 391
    schema["properties"]["profile_assignments"]["maxItems"] = 391
    schema["properties"]["profile_assignments"]["items"]["properties"]["supporting_capability_ids"][
        "minItems"
    ] = 1
    return schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-registry", type=Path, default=BASELINE_REGISTRY)
    parser.add_argument("--registry", type=Path, default=TARGET_REGISTRY)
    parser.add_argument("--baseline-capabilities", type=Path, default=BASELINE_CAPABILITIES)
    parser.add_argument("--vectors", type=Path, default=VECTOR_CATALOG)
    parser.add_argument("--roadmap", type=Path, default=ROADMAP)
    parser.add_argument("--schema-source", type=Path, default=SCHEMA_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--schema-output", type=Path, default=DEFAULT_SCHEMA_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    document = build_catalog(
        load_json(args.registry),
        load_json(args.baseline_capabilities),
        load_json(args.vectors),
    )
    baseline_registry = load_registry(args.baseline_registry)
    registry = load_registry(args.registry)
    baseline = load_capability_catalog(args.baseline_capabilities, baseline_registry)
    target = CapabilityCatalog.from_dict(document, registry)
    roadmap = load_army_expansion_roadmap(args.roadmap)
    vectors = load_attack_vector_catalog(args.vectors, registry, roadmap)
    report = validate_capability_graph_v2(
        baseline_registry,
        baseline,
        target,
        registry,
        vectors,
    )
    schema = build_schema(load_json(args.schema_source))
    args.output.write_text(
        json.dumps(target.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.schema_output.write_text(
        json.dumps(schema, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
