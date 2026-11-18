#!/usr/bin/env python3
"""Build Army v2 commander work packages and implementation roadmap."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_blueprints_v2 import load_candidate_blueprint_catalog_v2
from sunderkey.implementation_program_v2 import (
    load_implementation_work_package_catalog_v2,
    load_specialist_implementation_roadmap_v2,
    build_implementation_program_v2,
)
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
CAPABILITIES_PATH = ROOT / "registry" / "capabilities-army-v2.json"
D015_PATH = ROOT / "registry" / "army-expansion-roadmap-v1.json"
VECTORS_PATH = ROOT / "registry" / "attack-vectors-v2.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v2.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v2.json"
BLUEPRINTS_PATH = ROOT / "registry" / "candidate-blueprints-army-v2.json"
PACKAGES_PATH = ROOT / "registry" / "implementation-work-packages-v2.json"
ROADMAP_PATH = ROOT / "registry" / "specialist-implementation-roadmap-v2.json"
PACKAGES_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "implementation-work-package-catalog-v2.schema.json"
)
ROADMAP_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "specialist-implementation-roadmap-v2.schema.json"
)


def text_list(minimum: int = 1) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": minimum,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/asciiText"},
    }


def effect_properties() -> dict[str, Any]:
    return {
        "qualification_effect": {"const": "none"},
        "routing_effect": {"const": "none"},
        "execution_effect": {"const": "none"},
        "deployment_effect": {"const": "none"},
    }


def common_defs() -> dict[str, Any]:
    return {
        "asciiText": {
            "type": "string",
            "minLength": 1,
            "pattern": r"^[\t\n\r -~]*[!-~][\t\n\r -~]*$",
        },
        "sha256": {
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
        },
        "profileId": {
            "type": "string",
            "pattern": "^AOE-(?:H[QC]|G[A-H])-[A-Z0-9]+(?:-[A-Z0-9]+)*$",
        },
        "validatorCapacity": {
            "type": "object",
            "additionalProperties": False,
            "required": ["AOE-HQ-19", "AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"],
            "properties": {
                "AOE-HQ-19": {"const": 12},
                "AOE-HQ-33": {"const": 3},
                "AOE-HQ-34": {"const": 3},
                "AOE-HQ-35": {"const": 2},
            },
        },
        "validatorLoad": {
            "type": "object",
            "additionalProperties": False,
            "required": ["AOE-HQ-19", "AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"],
            "properties": {
                "AOE-HQ-19": {"type": "integer", "minimum": 0, "maximum": 12},
                "AOE-HQ-33": {"type": "integer", "minimum": 0, "maximum": 3},
                "AOE-HQ-34": {"type": "integer", "minimum": 0, "maximum": 3},
                "AOE-HQ-35": {"type": "integer", "minimum": 0, "maximum": 2},
            },
        },
        "riskClassByValidator": {
            "type": "object",
            "additionalProperties": False,
            "required": ["AOE-HQ-19", "AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"],
            "properties": {
                "AOE-HQ-19": {"const": "standard_independent_reproduction"},
                "AOE-HQ-33": {"const": "human_safety_or_restoration"},
                "AOE-HQ-34": {"const": "hostile_content_or_redaction"},
                "AOE-HQ-35": {"const": "cross_system_reconciliation"},
            },
        },
        "riskWeightByValidator": {
            "type": "object",
            "additionalProperties": False,
            "required": ["AOE-HQ-19", "AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"],
            "properties": {
                "AOE-HQ-19": {"const": 200},
                "AOE-HQ-33": {"const": 400},
                "AOE-HQ-34": {"const": 300},
                "AOE-HQ-35": {"const": 350},
            },
        },
        "verificationCostByValidator": {
            "type": "object",
            "additionalProperties": False,
            "required": ["AOE-HQ-19", "AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"],
            "properties": {
                "AOE-HQ-19": {"const": 3},
                "AOE-HQ-33": {"const": 5},
                "AOE-HQ-34": {"const": 4},
                "AOE-HQ-35": {"const": 5},
            },
        },
        "riskClassCounts": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "standard_independent_reproduction",
                "human_safety_or_restoration",
                "hostile_content_or_redaction",
                "cross_system_reconciliation",
            ],
            "properties": {
                "standard_independent_reproduction": {
                    "type": "integer",
                    "minimum": 0,
                },
                "human_safety_or_restoration": {
                    "type": "integer",
                    "minimum": 0,
                },
                "hostile_content_or_redaction": {
                    "type": "integer",
                    "minimum": 0,
                },
                "cross_system_reconciliation": {
                    "type": "integer",
                    "minimum": 0,
                },
            },
        },
        "stageDefinition": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "stage_number",
                "stage_id",
                "objective",
                "required_evidence",
            ],
            "properties": {
                "stage_number": {"type": "integer", "minimum": 1, "maximum": 8},
                "stage_id": {"$ref": "#/$defs/asciiText"},
                "objective": {"$ref": "#/$defs/asciiText"},
                "required_evidence": text_list(),
            },
        },
    }


def build_packages_schema() -> dict[str, Any]:
    top_fields = [
        "schema_version",
        "package_catalog_id",
        "package_catalog_version",
        "catalog_sha256",
        "expert_catalog_id",
        "expert_catalog_version",
        "expert_catalog_sha256",
        "capability_catalog_id",
        "capability_catalog_version",
        "capability_catalog_sha256",
        "vector_catalog_sha256",
        "qualification_plan_catalog_sha256",
        "blueprint_catalog_id",
        "blueprint_catalog_version",
        "blueprint_catalog_sha256",
        "package_policy",
        "package_status",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "deployment_effect",
        "packages",
        "coverage_summary",
        "limitations",
    ]
    package_fields = [
        "package_id",
        "priority_sequence",
        "priority_score",
        "risk_class",
        "risk_weight",
        "coverage_gain",
        "verification_cost",
        "is_new_specialist",
        "profile_id",
        "profile_name",
        "group_id",
        "group_commander_profile_id",
        "command_id",
        "commander_profile_id",
        "vector_id",
        "primary_capability_ids",
        "supporting_capability_ids",
        "collaboration_package_ids",
        "external_dependency_package_ids",
        "independent_validator_id",
        "reviewer_profile_ids",
        "blueprint_sha256",
        "required_component_ids",
        "required_test_stages",
        "work_items",
        "package_status",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "deployment_effect",
        "scheduled_wave_id",
        "scheduled_wave_number",
    ]
    coverage = {
        "package_count": 391,
        "new_specialist_package_count": 43,
        "command_count": 25,
        "commander_queue_count": 25,
        "collaboration_edge_count": 782,
        "work_item_count": 3128,
    }
    defs = common_defs()
    defs.update(
        {
            "workItem": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "work_item_id",
                    "stage_number",
                    "stage_id",
                    "objective",
                    "dependency_work_item_ids",
                    "required_evidence",
                    "task_state",
                    "task_effect",
                ],
                "properties": {
                    "work_item_id": {"$ref": "#/$defs/asciiText"},
                    "stage_number": {"type": "integer", "minimum": 1, "maximum": 8},
                    "stage_id": {"$ref": "#/$defs/asciiText"},
                    "objective": {"$ref": "#/$defs/asciiText"},
                    "dependency_work_item_ids": {
                        "type": "array",
                        "uniqueItems": True,
                        "items": {"$ref": "#/$defs/asciiText"},
                    },
                    "required_evidence": text_list(),
                    "task_state": {"const": "planned_unassigned"},
                    "task_effect": {"const": "none"},
                },
            },
            "package": {
                "type": "object",
                "additionalProperties": False,
                "required": package_fields,
                "properties": {
                    "package_id": {
                        "type": "string",
                        "pattern": "^IWP2-AOE-G[A-H]-D[0-9]{2}-S[0-9]{2}$",
                    },
                    "priority_sequence": {"type": "integer", "minimum": 1, "maximum": 391},
                    "priority_score": {"type": "integer", "minimum": 1},
                    "risk_class": {"$ref": "#/$defs/asciiText"},
                    "risk_weight": {"type": "integer", "minimum": 1},
                    "coverage_gain": {"type": "integer", "minimum": 1},
                    "verification_cost": {"type": "integer", "minimum": 1},
                    "is_new_specialist": {"type": "boolean"},
                    "profile_id": {"$ref": "#/$defs/profileId"},
                    "profile_name": {"$ref": "#/$defs/asciiText"},
                    "group_id": {"type": "string", "pattern": "^G[A-H]$"},
                    "group_commander_profile_id": {"$ref": "#/$defs/profileId"},
                    "command_id": {"$ref": "#/$defs/asciiText"},
                    "commander_profile_id": {"$ref": "#/$defs/profileId"},
                    "vector_id": {"$ref": "#/$defs/asciiText"},
                    "primary_capability_ids": text_list(),
                    "supporting_capability_ids": text_list(),
                    "collaboration_package_ids": text_list(2),
                    "external_dependency_package_ids": {
                        "type": "array",
                        "maxItems": 0,
                    },
                    "independent_validator_id": {"$ref": "#/$defs/profileId"},
                    "reviewer_profile_ids": text_list(6),
                    "blueprint_sha256": {"$ref": "#/$defs/sha256"},
                    "required_component_ids": text_list(10),
                    "required_test_stages": text_list(6),
                    "work_items": {
                        "type": "array",
                        "minItems": 8,
                        "maxItems": 8,
                        "items": {"$ref": "#/$defs/workItem"},
                    },
                    "package_status": {"const": "scheduled_unassigned"},
                    **effect_properties(),
                    "scheduled_wave_id": {
                        "type": "string",
                        "pattern": "^IW2-[0-9]{3}$",
                    },
                    "scheduled_wave_number": {"type": "integer", "minimum": 1},
                },
            },
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/implementation-work-package-catalog-v2.json",
        "title": "SUNDERKEY Army v2 Implementation Work Package Catalog",
        "type": "object",
        "additionalProperties": False,
        "required": top_fields,
        "properties": {
            "schema_version": {"const": 2},
            "package_catalog_id": {"const": "sunderkey-implementation-work-packages-v2"},
            "package_catalog_version": {"const": "2.0.0"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
            "expert_catalog_id": {"const": "sunderkey-offensive-expert-army"},
            "expert_catalog_version": {"const": "2.0.0"},
            "expert_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "capability_catalog_id": {"const": "sunderkey-army-capabilities-v2"},
            "capability_catalog_version": {"const": "2.0.0"},
            "capability_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "vector_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "qualification_plan_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "blueprint_catalog_id": {"const": "sunderkey-specialist-blueprints-v2"},
            "blueprint_catalog_version": {"const": "2.0.0"},
            "blueprint_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "package_policy": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "policy_id",
                    "maximum_packages_per_wave",
                    "maximum_packages_per_command_per_wave",
                    "validator_capacity_per_wave",
                    "risk_class_by_validator",
                    "risk_weight_by_validator",
                    "verification_cost_by_validator",
                    "priority_formula",
                    "new_specialist_coverage_bonus",
                    "mapping_coverage_gain",
                    "cross_specialist_edges_are_collaboration_not_hard_dependencies",
                    "stage_definitions",
                ],
                "properties": {
                    "policy_id": {"const": "sunderkey-commander-work-package-policy-v2"},
                    "maximum_packages_per_wave": {"const": 20},
                    "maximum_packages_per_command_per_wave": {"const": 1},
                    "validator_capacity_per_wave": {"$ref": "#/$defs/validatorCapacity"},
                    "risk_class_by_validator": {"$ref": "#/$defs/riskClassByValidator"},
                    "risk_weight_by_validator": {"$ref": "#/$defs/riskWeightByValidator"},
                    "verification_cost_by_validator": {
                        "$ref": "#/$defs/verificationCostByValidator"
                    },
                    "priority_formula": {
                        "const": "risk_weight + coverage_gain + (6 - verification_cost)"
                    },
                    "new_specialist_coverage_bonus": {"const": 40},
                    "mapping_coverage_gain": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "exact_risk",
                            "related_technique",
                            "contextual_tactic",
                        ],
                        "properties": {
                            "exact_risk": {"const": 20},
                            "related_technique": {"const": 15},
                            "contextual_tactic": {"const": 10},
                        },
                    },
                    "cross_specialist_edges_are_collaboration_not_hard_dependencies": {
                        "const": True
                    },
                    "stage_definitions": {
                        "type": "array",
                        "minItems": 8,
                        "maxItems": 8,
                        "items": {"$ref": "#/$defs/stageDefinition"},
                    },
                },
            },
            "package_status": {"const": "planned_unassigned"},
            **effect_properties(),
            "packages": {
                "type": "array",
                "minItems": 391,
                "maxItems": 391,
                "items": {"$ref": "#/$defs/package"},
            },
            "coverage_summary": {
                "type": "object",
                "required": [*coverage, "wave_count"],
                "properties": {
                    **{key: {"const": value} for key, value in coverage.items()},
                    "wave_count": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
            "limitations": text_list(5),
        },
        "$defs": defs,
    }


def build_roadmap_schema() -> dict[str, Any]:
    top_fields = [
        "schema_version",
        "roadmap_id",
        "roadmap_version",
        "roadmap_sha256",
        "expert_catalog_id",
        "expert_catalog_version",
        "expert_catalog_sha256",
        "blueprint_catalog_id",
        "blueprint_catalog_version",
        "blueprint_catalog_sha256",
        "package_catalog_id",
        "package_catalog_version",
        "package_catalog_sha256",
        "scheduling_policy",
        "roadmap_status",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "deployment_effect",
        "waves",
        "commander_queues",
        "coverage_summary",
        "limitations",
    ]
    defs = common_defs()
    defs.update(
        {
            "wave": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "wave_id",
                    "wave_number",
                    "package_ids",
                    "command_ids",
                    "validator_load",
                    "risk_class_counts",
                    "new_specialist_package_count",
                    "wave_status",
                    "operational_effect",
                ],
                "properties": {
                    "wave_id": {"type": "string", "pattern": "^IW2-[0-9]{3}$"},
                    "wave_number": {"type": "integer", "minimum": 1},
                    "package_ids": text_list(),
                    "command_ids": text_list(),
                    "validator_load": {"$ref": "#/$defs/validatorLoad"},
                    "risk_class_counts": {"$ref": "#/$defs/riskClassCounts"},
                    "new_specialist_package_count": {"type": "integer", "minimum": 0},
                    "wave_status": {"const": "planned_unassigned"},
                    "operational_effect": {"const": "none"},
                },
            },
            "queue": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "command_id",
                    "commander_profile_id",
                    "package_ids",
                    "scheduled_wave_ids",
                    "package_count",
                    "maximum_concurrent_packages",
                    "queue_status",
                ],
                "properties": {
                    "command_id": {"$ref": "#/$defs/asciiText"},
                    "commander_profile_id": {"$ref": "#/$defs/profileId"},
                    "package_ids": text_list(),
                    "scheduled_wave_ids": text_list(),
                    "package_count": {"type": "integer", "minimum": 1},
                    "maximum_concurrent_packages": {"const": 1},
                    "queue_status": {"const": "defined_unassigned"},
                },
            },
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/specialist-implementation-roadmap-v2.json",
        "title": "SUNDERKEY Army v2 Specialist Implementation Roadmap",
        "type": "object",
        "additionalProperties": False,
        "required": top_fields,
        "properties": {
            "schema_version": {"const": 2},
            "roadmap_id": {"const": "sunderkey-specialist-implementation-roadmap-v2"},
            "roadmap_version": {"const": "2.0.0"},
            "roadmap_sha256": {"$ref": "#/$defs/sha256"},
            "expert_catalog_id": {"const": "sunderkey-offensive-expert-army"},
            "expert_catalog_version": {"const": "2.0.0"},
            "expert_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "blueprint_catalog_id": {"const": "sunderkey-specialist-blueprints-v2"},
            "blueprint_catalog_version": {"const": "2.0.0"},
            "blueprint_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "package_catalog_id": {"const": "sunderkey-implementation-work-packages-v2"},
            "package_catalog_version": {"const": "2.0.0"},
            "package_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "scheduling_policy": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "ordering",
                    "maximum_packages_per_wave",
                    "maximum_packages_per_command_per_wave",
                    "validator_capacity_per_wave",
                    "command_queue_concurrency",
                    "selection_effect",
                ],
                "properties": {
                    "ordering": {
                        "type": "array",
                        "minItems": 3,
                        "maxItems": 3,
                        "prefixItems": [
                            {"const": "priority_score_descending"},
                            {"const": "profile_id_ascending"},
                            {"const": "earliest_capacity_eligible_wave"},
                        ],
                        "items": False,
                    },
                    "maximum_packages_per_wave": {"const": 20},
                    "maximum_packages_per_command_per_wave": {"const": 1},
                    "validator_capacity_per_wave": {"$ref": "#/$defs/validatorCapacity"},
                    "command_queue_concurrency": {"const": 1},
                    "selection_effect": {"const": "none"},
                },
            },
            "roadmap_status": {"const": "planned_unassigned"},
            **effect_properties(),
            "waves": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "#/$defs/wave"},
            },
            "commander_queues": {
                "type": "array",
                "minItems": 25,
                "maxItems": 25,
                "items": {"$ref": "#/$defs/queue"},
            },
            "coverage_summary": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "package_count",
                    "new_specialist_package_count",
                    "command_count",
                    "commander_queue_count",
                    "collaboration_edge_count",
                    "work_item_count",
                    "wave_count",
                ],
                "properties": {
                    "package_count": {"const": 391},
                    "new_specialist_package_count": {"const": 43},
                    "command_count": {"const": 25},
                    "commander_queue_count": {"const": 25},
                    "collaboration_edge_count": {"const": 782},
                    "work_item_count": {"const": 3128},
                    "wave_count": {"const": 30},
                },
            },
            "limitations": text_list(5),
        },
        "$defs": defs,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--capabilities", type=Path, default=CAPABILITIES_PATH)
    parser.add_argument("--d015-roadmap", type=Path, default=D015_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    parser.add_argument("--standard", type=Path, default=STANDARD_PATH)
    parser.add_argument("--plans", type=Path, default=PLANS_PATH)
    parser.add_argument("--blueprints", type=Path, default=BLUEPRINTS_PATH)
    parser.add_argument("--packages-output", type=Path, default=PACKAGES_PATH)
    parser.add_argument("--roadmap-output", type=Path, default=ROADMAP_PATH)
    parser.add_argument("--packages-schema-output", type=Path, default=PACKAGES_SCHEMA_PATH)
    parser.add_argument("--roadmap-schema-output", type=Path, default=ROADMAP_SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    d015 = load_army_expansion_roadmap(args.d015_roadmap)
    vectors = load_attack_vector_catalog(args.vectors, registry, d015)
    standard = load_qualification_standard(args.standard, registry, capabilities)
    plans = load_qualification_plan_catalog_v2(
        args.plans,
        registry,
        capabilities,
        vectors,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog_v2(
        args.blueprints,
        registry,
        capabilities,
        vectors,
        standard,
        plans,
    )
    packages_document, roadmap_document = build_implementation_program_v2(
        registry,
        capabilities,
        d015,
        vectors,
        plans,
        blueprints,
    )
    for output in (
        args.packages_output,
        args.roadmap_output,
        args.packages_schema_output,
        args.roadmap_schema_output,
    ):
        output.parent.mkdir(parents=True, exist_ok=True)
    args.packages_output.write_text(
        json.dumps(packages_document, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.roadmap_output.write_text(
        json.dumps(roadmap_document, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.packages_schema_output.write_text(
        json.dumps(build_packages_schema(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.roadmap_schema_output.write_text(
        json.dumps(build_roadmap_schema(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    packages = load_implementation_work_package_catalog_v2(
        args.packages_output,
        registry,
        capabilities,
        d015,
        vectors,
        plans,
        blueprints,
    )
    roadmap = load_specialist_implementation_roadmap_v2(
        args.roadmap_output,
        packages,
        registry,
        capabilities,
        d015,
        vectors,
        plans,
        blueprints,
    )
    print(
        json.dumps(
            {
                "package_catalog_sha256": packages.catalog_sha256,
                "roadmap_sha256": roadmap.roadmap_sha256,
                **roadmap.coverage_summary,
                "operational_effect": "none",
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
