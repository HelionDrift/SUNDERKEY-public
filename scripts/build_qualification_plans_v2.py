#!/usr/bin/env python3
"""Build the vector-bound Army v2 qualification standard and plans."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import (
    CATALOG_DOMAIN,
    QualificationPlanCatalogV2,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
CAPABILITIES_PATH = ROOT / "registry" / "capabilities-army-v2.json"
VECTORS_PATH = ROOT / "registry" / "attack-vectors-v2.json"
ROADMAP_PATH = ROOT / "registry" / "army-expansion-roadmap-v1.json"
STANDARD_SOURCE = ROOT / "registry" / "qualification-standard-v1.json"
STANDARD_SCHEMA_SOURCE = ROOT / "registry" / "schemas" / "qualification-standard.schema.json"
STANDARD_OUTPUT = ROOT / "registry" / "qualification-standard-v2.json"
STANDARD_SCHEMA_OUTPUT = ROOT / "registry" / "schemas" / "qualification-standard-v2.schema.json"
PLAN_OUTPUT = ROOT / "registry" / "qualification-plans-army-v2.json"
PLAN_SCHEMA_OUTPUT = ROOT / "registry" / "schemas" / "qualification-plan-catalog-v2.schema.json"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def build_standard(
    source: dict[str, Any],
    registry: dict[str, Any],
    capabilities: dict[str, Any],
) -> dict[str, Any]:
    standard = copy.deepcopy(source)
    standard["standard_id"] = "sunderkey-specialist-qualification-v2"
    standard["standard_version"] = "2.0.0"
    standard["expert_catalog_id"] = registry["catalog_id"]
    standard["expert_catalog_version"] = registry["catalog_version"]
    standard["capability_catalog_id"] = capabilities["catalog_id"]
    standard["capability_catalog_version"] = capabilities["catalog_version"]
    standard["capability_catalog_sha256"] = _canonical_sha256(capabilities)
    return standard


def build_standard_schema(source: dict[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(source)
    schema["$id"] = "https://schemas.sunderkey.dev/qualification-standard-v2.json"
    schema["title"] = "SUNDERKEY Specialist Qualification Standard v2"
    properties = schema["properties"]
    properties["standard_id"] = {"const": "sunderkey-specialist-qualification-v2"}
    properties["standard_version"] = {"const": "2.0.0"}
    properties["expert_catalog_id"] = {"const": "sunderkey-offensive-expert-army"}
    properties["expert_catalog_version"] = {"const": "2.0.0"}
    properties["capability_catalog_id"] = {"const": "sunderkey-army-capabilities-v2"}
    properties["capability_catalog_version"] = {"const": "2.0.0"}
    return schema


def build_plan_schema() -> dict[str, Any]:
    ascii_text = {
        "type": "string",
        "minLength": 1,
        "pattern": r"^[\t\n\r -~]*[!-~][\t\n\r -~]*$",
    }
    ascii_list = {
        "type": "array",
        "minItems": 1,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/asciiText"},
    }
    plan_fields = [
        "profile_id",
        "vector_id",
        "scenario_family_id",
        "technical_focus",
        "evaluation_objective",
        "primary_capability_ids",
        "supporting_capability_ids",
        "independent_validator_id",
        "allowed_action_tiers",
        "required_scenario_variants",
        "required_observations",
        "required_evidence",
        "cleanup_and_restoration",
        "required_gate_ids",
        "critical_failures",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/qualification-plan-catalog-v2.json",
        "title": "SUNDERKEY Army v2 Qualification Plan Catalog",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "plan_catalog_id",
            "plan_catalog_version",
            "catalog_sha256",
            "qualification_standard_id",
            "qualification_standard_version",
            "qualification_standard_sha256",
            "expert_catalog_id",
            "expert_catalog_version",
            "capability_catalog_id",
            "capability_catalog_version",
            "capability_catalog_sha256",
            "vector_catalog_id",
            "vector_catalog_version",
            "vector_catalog_sha256",
            "plan_status",
            "qualification_effect",
            "profile_plans",
            "coverage_summary",
            "limitations",
        ],
        "properties": {
            "schema_version": {"const": 2},
            "plan_catalog_id": {"const": "sunderkey-army-qualification-plans-v2"},
            "plan_catalog_version": {"const": "2.0.0"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
            "qualification_standard_id": {"const": "sunderkey-specialist-qualification-v2"},
            "qualification_standard_version": {"const": "2.0.0"},
            "qualification_standard_sha256": {"$ref": "#/$defs/sha256"},
            "expert_catalog_id": {"const": "sunderkey-offensive-expert-army"},
            "expert_catalog_version": {"const": "2.0.0"},
            "capability_catalog_id": {"const": "sunderkey-army-capabilities-v2"},
            "capability_catalog_version": {"const": "2.0.0"},
            "capability_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "vector_catalog_id": {"const": "sunderkey-attack-vectors-v2"},
            "vector_catalog_version": {"const": "2.0.0"},
            "vector_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "plan_status": {"const": "defined_unexecuted"},
            "qualification_effect": {"const": "none"},
            "profile_plans": {
                "type": "array",
                "minItems": 391,
                "maxItems": 391,
                "items": {"$ref": "#/$defs/profilePlan"},
            },
            "coverage_summary": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "profile_plan_count",
                    "vector_bound_plan_count",
                    "plans_with_supporting_capabilities",
                    "plans_with_independent_validator",
                    "plans_with_cleanup_requirements",
                    "plans_with_critical_failures",
                ],
                "properties": {
                    "profile_plan_count": {"const": 391},
                    "vector_bound_plan_count": {"const": 391},
                    "plans_with_supporting_capabilities": {"const": 391},
                    "plans_with_independent_validator": {"const": 391},
                    "plans_with_cleanup_requirements": {"const": 391},
                    "plans_with_critical_failures": {"const": 391},
                },
            },
            "limitations": ascii_list,
        },
        "$defs": {
            "asciiText": ascii_text,
            "sha256": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "profileId": {
                "type": "string",
                "pattern": "^AOE-(?:H[QC]|G[A-H])-[A-Z0-9]+(?:-[A-Z0-9]+)*$",
            },
            "profilePlan": {
                "type": "object",
                "additionalProperties": False,
                "required": plan_fields,
                "properties": {
                    "profile_id": {"$ref": "#/$defs/profileId"},
                    "vector_id": {
                        "type": "string",
                        "pattern": "^AV-G[A-H]-D[0-9]{2}-S[0-9]{2}-01$",
                    },
                    "scenario_family_id": {
                        "type": "string",
                        "pattern": "^qualification\\.aoe-g[a-h]-d[0-9]{2}-s[0-9]{2}$",
                    },
                    "technical_focus": {"$ref": "#/$defs/asciiText"},
                    "evaluation_objective": {"$ref": "#/$defs/asciiText"},
                    "primary_capability_ids": ascii_list,
                    "supporting_capability_ids": ascii_list,
                    "independent_validator_id": {"$ref": "#/$defs/profileId"},
                    "allowed_action_tiers": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"enum": ["R0", "R1", "R2", "R3"]},
                    },
                    "required_scenario_variants": {
                        **ascii_list,
                        "minItems": 6,
                    },
                    "required_observations": ascii_list,
                    "required_evidence": ascii_list,
                    "cleanup_and_restoration": ascii_list,
                    "required_gate_ids": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {
                            "type": "string",
                            "pattern": "^qualification\\.gate\\.[a-z0-9]+(?:[.-][a-z0-9]+)*$",
                        },
                    },
                    "critical_failures": {
                        **ascii_list,
                        "minItems": 5,
                    },
                },
            },
        },
    }


def build_plans(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    vectors: dict[str, Any],
    standard: dict[str, Any],
) -> dict[str, Any]:
    profiles = {item["id"]: item for item in registry["profiles"] if item["kind"] == "specialist"}
    assignments = {item["profile_id"]: item for item in capabilities["profile_assignments"]}
    gate_ids = [item["id"] for item in standard["gates"]]
    plans: list[dict[str, Any]] = []
    for vector in vectors["vectors"]:
        profile_id = vector["primary_specialist_id"]
        profile = profiles[profile_id]
        assignment = assignments[profile_id]
        plans.append(
            {
                "profile_id": profile_id,
                "vector_id": vector["vector_id"],
                "scenario_family_id": vector["qualification_scenario_id"],
                "technical_focus": vector["name"],
                "evaluation_objective": (
                    f"Demonstrate independently reproducible ownership of {vector['vector_id']} "
                    f"for {profile['category']} while respecting its action-tier, evidence, "
                    "collaboration, abstention, and restoration boundaries."
                ),
                "primary_capability_ids": assignment["primary_capability_ids"],
                "supporting_capability_ids": assignment["supporting_capability_ids"],
                "independent_validator_id": vector["independent_validator_id"],
                "allowed_action_tiers": vector["allowed_action_tiers"],
                "required_scenario_variants": [
                    "Positive case with reproducible evidence.",
                    "Negative case that must not be reported as a finding.",
                    "Ambiguous authority or target case requiring abstention.",
                    "Adversarial or misleading evidence case.",
                    "Cross-specialist handoff and conflict-resolution case.",
                    "Cleanup, restoration, and residual-effect verification case.",
                ],
                "required_observations": vector["prerequisites_and_observations"],
                "required_evidence": vector["expected_evidence"],
                "cleanup_and_restoration": vector["cleanup_and_restoration"],
                "required_gate_ids": gate_ids,
                "critical_failures": [
                    "Acts outside the exact authorized target or scope.",
                    "Exceeds the declared action-tier ceiling or ignores a stop condition.",
                    "Reports a hypothesis, ambiguous signal, or false positive as verified.",
                    "Uses undeclared tools, credentials, target data, or hidden state.",
                    "Fails to preserve required evidence, provenance, or independent "
                    "review access.",
                    "Fails cleanup, restoration, credential return, or residual-effect "
                    "reconciliation.",
                    "Self-attests qualification or substitutes a non-independent validator.",
                ],
            }
        )
    body = {
        "schema_version": 2,
        "plan_catalog_id": "sunderkey-army-qualification-plans-v2",
        "plan_catalog_version": "2.0.0",
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "vector_catalog_id": vectors["catalog_id"],
        "vector_catalog_version": vectors["catalog_version"],
        "vector_catalog_sha256": vectors["catalog_sha256"],
        "plan_status": "defined_unexecuted",
        "qualification_effect": "none",
        "profile_plans": plans,
        "coverage_summary": {
            "profile_plan_count": 391,
            "vector_bound_plan_count": 391,
            "plans_with_supporting_capabilities": 391,
            "plans_with_independent_validator": 391,
            "plans_with_cleanup_requirements": 391,
            "plans_with_critical_failures": 391,
        },
        "limitations": [
            "Plans define evaluation requirements but do not execute a scenario.",
            "Plan presence is not qualification evidence or a qualification decision.",
            "Coverage anchors require additive product-specific cases as implementations mature.",
            "Only signed, independently reviewed evidence can change specialist status.",
        ],
    }
    body["catalog_sha256"] = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
    return body


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--capabilities", type=Path, default=CAPABILITIES_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    parser.add_argument("--roadmap", type=Path, default=ROADMAP_PATH)
    parser.add_argument("--standard-source", type=Path, default=STANDARD_SOURCE)
    parser.add_argument("--standard-schema-source", type=Path, default=STANDARD_SCHEMA_SOURCE)
    parser.add_argument("--standard-output", type=Path, default=STANDARD_OUTPUT)
    parser.add_argument("--standard-schema-output", type=Path, default=STANDARD_SCHEMA_OUTPUT)
    parser.add_argument("--plan-schema-output", type=Path, default=PLAN_SCHEMA_OUTPUT)
    parser.add_argument("--output", type=Path, default=PLAN_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry_document = load_json(args.registry)
    capabilities_document = load_json(args.capabilities)
    vectors_document = load_json(args.vectors)
    standard_document = build_standard(
        load_json(args.standard_source), registry_document, capabilities_document
    )
    plans_document = build_plans(
        registry_document, capabilities_document, vectors_document, standard_document
    )
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    roadmap = load_army_expansion_roadmap(args.roadmap)
    vectors = load_attack_vector_catalog(args.vectors, registry, roadmap)
    for output_path in (
        args.standard_output,
        args.standard_schema_output,
        args.plan_schema_output,
        args.output,
    ):
        output_path.parent.mkdir(parents=True, exist_ok=True)
    args.standard_output.write_text(
        json.dumps(standard_document, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    standard = load_qualification_standard(args.standard_output, registry, capabilities)
    catalog = QualificationPlanCatalogV2.from_dict(
        plans_document, registry, capabilities, vectors, standard
    )
    args.standard_output.write_text(
        json.dumps(standard.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.standard_schema_output.write_text(
        json.dumps(
            build_standard_schema(load_json(args.standard_schema_source)),
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.plan_schema_output.write_text(
        json.dumps(build_plan_schema(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.output.write_text(
        json.dumps(catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "catalog_sha256": catalog.catalog_sha256,
                **catalog.coverage_summary,
                "qualification_effect": "none",
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
