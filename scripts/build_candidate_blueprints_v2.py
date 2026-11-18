#!/usr/bin/env python3
"""Build implementation-ready, fail-closed Army v2 candidate blueprints."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.candidate_blueprints_v2 import (
    BLUEPRINT_DOMAIN,
    CATALOG_DOMAIN,
    REQUIRED_COMPONENT_IDS,
    REQUIRED_TEST_STAGES,
    CandidateBlueprintCatalogV2,
)
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
CAPABILITIES_PATH = ROOT / "registry" / "capabilities-army-v2.json"
ROADMAP_PATH = ROOT / "registry" / "army-expansion-roadmap-v1.json"
VECTORS_PATH = ROOT / "registry" / "attack-vectors-v2.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v2.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v2.json"
OUTPUT_PATH = ROOT / "registry" / "candidate-blueprints-army-v2.json"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "candidate-blueprint-catalog-v2.schema.json"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def test_requirements() -> list[dict[str, Any]]:
    return [
        {
            "stage": "static_analysis",
            "objective": (
                "Validate schemas, pinned dependencies, prohibited execution paths, "
                "and secret-handling rules before runtime."
            ),
            "required_evidence": [
                "Machine-readable lint, dependency, schema, and policy results.",
                "Artifact and dependency digests tied to the candidate version.",
            ],
        },
        {
            "stage": "unit",
            "objective": (
                "Exercise parsing, negative cases, action-tier enforcement, stop "
                "conditions, evidence capture, and cleanup branches without a network."
            ),
            "required_evidence": [
                "Deterministic unit results for positive, negative, and failure paths.",
                "Coverage of every control and critical-failure branch.",
            ],
        },
        {
            "stage": "integration",
            "objective": (
                "Run the declared adapter against an approved synthetic or test target "
                "with typed support handoffs."
            ),
            "required_evidence": [
                "Adapter request, response, tool provenance, and support-handoff records.",
                "Reproducible expected and observed state transitions.",
            ],
        },
        {
            "stage": "containment",
            "objective": (
                "Verify scope, network, credential, filesystem, process, timeout, "
                "cancellation, and rate-limit boundaries fail closed."
            ),
            "required_evidence": [
                "Denied out-of-scope and above-tier attempts.",
                "Timeout, cancellation, rate-limit, and credential-isolation results.",
            ],
        },
        {
            "stage": "evidence",
            "objective": (
                "Reproduce positive and negative conclusions from preserved evidence "
                "and provenance without hidden state."
            ),
            "required_evidence": [
                "Independent reproduction record for each asserted conclusion.",
                "False-positive, ambiguity, and limitation dispositions.",
            ],
        },
        {
            "stage": "restoration",
            "objective": (
                "Prove cleanup, credential return, target-state reconciliation, and "
                "zero unaccounted residual effects."
            ),
            "required_evidence": [
                "Cleanup and credential-return receipts.",
                "Before-and-after target-state and residual-effect reconciliation.",
            ],
        },
    ]


def build_blueprint(
    profile: dict[str, Any],
    command: dict[str, Any],
    policy: dict[str, Any],
    assignment: dict[str, Any],
    vector: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    primary_capability = assignment["primary_capability_ids"][0]
    supporting_capabilities = assignment["supporting_capability_ids"]
    body = {
        "profile_id": profile["id"],
        "profile_version": profile["version"],
        "name": profile["name"],
        "group_id": profile["group_id"],
        "command_id": profile["command_id"],
        "category": profile["category"],
        "mission": profile["mission"],
        "policy_template_id": policy["id"],
        "vector_id": vector["vector_id"],
        "scenario_family_id": plan["scenario_family_id"],
        "primary_capability_ids": assignment["primary_capability_ids"],
        "supporting_capability_ids": supporting_capabilities,
        "independent_validator_id": plan["independent_validator_id"],
        "maximum_autonomous_action_tier": profile["max_autonomous_tier"],
        "allowed_action_tiers": plan["allowed_action_tiers"],
        "minimum_evidence_level": profile["minimum_evidence_level"],
        "allowed_actions": policy["may"],
        "prohibited_actions": policy["may_not"],
        "stop_conditions": policy["stop_conditions"],
        "tool_adapter_requirements": [
            f"Declare one provider-neutral adapter for capability {primary_capability}.",
            (
                "Declare the exact platform and protocol coverage from the bound "
                f"vector: {'; '.join(vector['platforms_and_protocols'])}."
            ),
            (
                "Pin executable, dependency, configuration, and container or runtime "
                "digests in the runtime manifest."
            ),
            (
                "Expose dry-run, timeout, cancellation, rate-limit, structured-evidence, "
                "and cleanup-result hooks."
            ),
            (
                "Accept mission-scoped credentials only at invocation and prevent "
                "credential persistence in artifacts, logs, prompts, or caches."
            ),
            (
                "Never authorize an action, expand target scope, bypass terminal "
                "admission, or conceal an execution side effect."
            ),
        ],
        "input_contract": [
            *vector["prerequisites_and_observations"],
            *vector["tools_and_credentials"],
            (
                "Mission authority binding for the exact target, scope, environment, "
                "permitted action tier, and stop conditions."
            ),
            (
                "Typed collaborator inputs for supporting capabilities: "
                f"{', '.join(supporting_capabilities)}."
            ),
        ],
        "output_contract": [
            (
                f"Structured {vector['vector_id']} result that separates verified "
                "findings, negative results, hypotheses, ambiguity, and abstention."
            ),
            *vector["expected_evidence"],
            "Typed support, conflict, and commander handoff records.",
            "Cleanup, credential-return, state-reconciliation, and residual-effect receipt.",
        ],
        "control_requirements": [
            "Bind every proposed action to mission authority, target, scope, and action tier.",
            (
                f"Require independent validation by {plan['independent_validator_id']} "
                "for qualification evidence and critical-failure disposition."
            ),
            "Fail closed when identity, scope, authority, evidence, or impact is ambiguous.",
            "Preserve typed collaboration provenance for every supporting capability.",
            "Prevent self-authorization, self-qualification, and validator substitution.",
            "Block publication of a finding until evidence and uncertainty are explicit.",
        ],
        "evidence_contract": plan["required_evidence"],
        "restoration_contract": plan["cleanup_and_restoration"],
        "known_blind_spots": vector["known_blind_spots"],
        "required_scenario_variants": plan["required_scenario_variants"],
        "required_gate_ids": plan["required_gate_ids"],
        "critical_failures": plan["critical_failures"],
        "test_requirements": test_requirements(),
        "command_mission": command["mission"],
        "command_inputs": command["inputs"],
        "command_outputs": command["outputs"],
        "collaboration_contract": command["collaboration"],
        "command_boundary": command["boundary"],
        "required_component_ids": list(REQUIRED_COMPONENT_IDS),
        "implementation_status": "defined_unimplemented",
    }
    return {
        **body,
        "blueprint_sha256": _canonical_sha256({"domain": BLUEPRINT_DOMAIN, "blueprint": body}),
    }


def build_catalog(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    vectors: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
) -> dict[str, Any]:
    policies = {item["id"]: item for item in registry["policy_templates"]}
    commands = {item["id"]: item for item in registry["commands"]}
    assignments = {item["profile_id"]: item for item in capabilities["profile_assignments"]}
    plans_by_profile = {item["profile_id"]: item for item in plans["profile_plans"]}
    profiles = {item["id"]: item for item in registry["profiles"] if item["kind"] == "specialist"}
    blueprints = []
    for vector in vectors["vectors"]:
        profile = profiles[vector["primary_specialist_id"]]
        blueprints.append(
            build_blueprint(
                profile,
                commands[profile["command_id"]],
                policies[profile["policy_template"]],
                assignments[profile["id"]],
                vector,
                plans_by_profile[profile["id"]],
            )
        )
    body = {
        "schema_version": 2,
        "blueprint_catalog_id": "sunderkey-specialist-blueprints-v2",
        "blueprint_catalog_version": "2.0.0",
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "expert_catalog_sha256": _canonical_sha256(registry),
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "vector_catalog_id": vectors["catalog_id"],
        "vector_catalog_version": vectors["catalog_version"],
        "vector_catalog_sha256": vectors["catalog_sha256"],
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "qualification_plan_catalog_id": plans["plan_catalog_id"],
        "qualification_plan_catalog_version": plans["plan_catalog_version"],
        "qualification_plan_catalog_sha256": plans["catalog_sha256"],
        "required_component_ids": list(REQUIRED_COMPONENT_IDS),
        "required_test_stages": list(REQUIRED_TEST_STAGES),
        "blueprint_status": "defined_unimplemented",
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
        "blueprints": blueprints,
        "coverage_summary": {
            "specialist_count": 391,
            "blueprint_count": 391,
            "vector_bound_blueprint_count": 391,
            "blueprints_with_tool_contracts": 391,
            "blueprints_with_input_output_contracts": 391,
            "blueprints_with_control_contracts": 391,
            "blueprints_with_evidence_contracts": 391,
            "blueprints_with_restoration_contracts": 391,
            "blueprints_with_complete_test_matrix": 391,
            "component_requirement_count": 391 * len(REQUIRED_COMPONENT_IDS),
            "test_requirement_count": 391 * len(REQUIRED_TEST_STAGES),
        },
        "limitations": [
            "A blueprint is a deterministic build contract, not a candidate implementation.",
            "Provider-neutral adapter requirements do not select or install a tool.",
            "Blueprint presence is not qualification evidence or routing eligibility.",
            "No target, credential, provider, model, endpoint, or environment is selected.",
            "No action, network call, deployment, or runtime mutation is performed.",
        ],
    }
    body["catalog_sha256"] = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
    return body


def build_schema() -> dict[str, Any]:
    ascii_text = {
        "type": "string",
        "minLength": 1,
        "pattern": r"^[\t\n\r -~]*[!-~][\t\n\r -~]*$",
    }
    text_list = {
        "type": "array",
        "minItems": 1,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/asciiText"},
    }
    blueprint_fields = [
        "profile_id",
        "profile_version",
        "name",
        "group_id",
        "command_id",
        "category",
        "mission",
        "policy_template_id",
        "vector_id",
        "scenario_family_id",
        "primary_capability_ids",
        "supporting_capability_ids",
        "independent_validator_id",
        "maximum_autonomous_action_tier",
        "allowed_action_tiers",
        "minimum_evidence_level",
        "allowed_actions",
        "prohibited_actions",
        "stop_conditions",
        "tool_adapter_requirements",
        "input_contract",
        "output_contract",
        "control_requirements",
        "evidence_contract",
        "restoration_contract",
        "known_blind_spots",
        "required_scenario_variants",
        "required_gate_ids",
        "critical_failures",
        "test_requirements",
        "command_mission",
        "command_inputs",
        "command_outputs",
        "collaboration_contract",
        "command_boundary",
        "required_component_ids",
        "implementation_status",
        "blueprint_sha256",
    ]
    top_fields = [
        "schema_version",
        "blueprint_catalog_id",
        "blueprint_catalog_version",
        "catalog_sha256",
        "expert_catalog_id",
        "expert_catalog_version",
        "expert_catalog_sha256",
        "capability_catalog_id",
        "capability_catalog_version",
        "capability_catalog_sha256",
        "vector_catalog_id",
        "vector_catalog_version",
        "vector_catalog_sha256",
        "qualification_standard_id",
        "qualification_standard_version",
        "qualification_standard_sha256",
        "qualification_plan_catalog_id",
        "qualification_plan_catalog_version",
        "qualification_plan_catalog_sha256",
        "required_component_ids",
        "required_test_stages",
        "blueprint_status",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "deployment_effect",
        "blueprints",
        "coverage_summary",
        "limitations",
    ]
    component_schema = {
        "type": "array",
        "minItems": len(REQUIRED_COMPONENT_IDS),
        "maxItems": len(REQUIRED_COMPONENT_IDS),
        "prefixItems": [{"const": item} for item in REQUIRED_COMPONENT_IDS],
        "items": False,
    }
    test_stage_schema = {
        "type": "array",
        "minItems": len(REQUIRED_TEST_STAGES),
        "maxItems": len(REQUIRED_TEST_STAGES),
        "prefixItems": [{"const": item} for item in REQUIRED_TEST_STAGES],
        "items": False,
    }
    coverage_fields = {
        "specialist_count": 391,
        "blueprint_count": 391,
        "vector_bound_blueprint_count": 391,
        "blueprints_with_tool_contracts": 391,
        "blueprints_with_input_output_contracts": 391,
        "blueprints_with_control_contracts": 391,
        "blueprints_with_evidence_contracts": 391,
        "blueprints_with_restoration_contracts": 391,
        "blueprints_with_complete_test_matrix": 391,
        "component_requirement_count": 391 * len(REQUIRED_COMPONENT_IDS),
        "test_requirement_count": 391 * len(REQUIRED_TEST_STAGES),
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/candidate-blueprint-catalog-v2.json",
        "title": "SUNDERKEY Army v2 Candidate Blueprint Catalog",
        "type": "object",
        "additionalProperties": False,
        "required": top_fields,
        "properties": {
            "schema_version": {"const": 2},
            "blueprint_catalog_id": {"const": "sunderkey-specialist-blueprints-v2"},
            "blueprint_catalog_version": {"const": "2.0.0"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
            "expert_catalog_id": {"const": "sunderkey-offensive-expert-army"},
            "expert_catalog_version": {"const": "2.0.0"},
            "expert_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "capability_catalog_id": {"const": "sunderkey-army-capabilities-v2"},
            "capability_catalog_version": {"const": "2.0.0"},
            "capability_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "vector_catalog_id": {"const": "sunderkey-attack-vectors-v2"},
            "vector_catalog_version": {"const": "2.0.0"},
            "vector_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "qualification_standard_id": {"const": "sunderkey-specialist-qualification-v2"},
            "qualification_standard_version": {"const": "2.0.0"},
            "qualification_standard_sha256": {"$ref": "#/$defs/sha256"},
            "qualification_plan_catalog_id": {"const": "sunderkey-army-qualification-plans-v2"},
            "qualification_plan_catalog_version": {"const": "2.0.0"},
            "qualification_plan_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "required_component_ids": component_schema,
            "required_test_stages": test_stage_schema,
            "blueprint_status": {"const": "defined_unimplemented"},
            "qualification_effect": {"const": "none"},
            "routing_effect": {"const": "none"},
            "execution_effect": {"const": "none"},
            "deployment_effect": {"const": "none"},
            "blueprints": {
                "type": "array",
                "minItems": 391,
                "maxItems": 391,
                "items": {"$ref": "#/$defs/blueprint"},
            },
            "coverage_summary": {
                "type": "object",
                "additionalProperties": False,
                "required": list(coverage_fields),
                "properties": {key: {"const": value} for key, value in coverage_fields.items()},
            },
            "limitations": text_list,
        },
        "$defs": {
            "asciiText": ascii_text,
            "sha256": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "textList": text_list,
            "capabilityList": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": "^[a-z0-9]+(?:[.-][a-z0-9]+)*$",
                },
            },
            "testRequirement": {
                "type": "object",
                "additionalProperties": False,
                "required": ["stage", "objective", "required_evidence"],
                "properties": {
                    "stage": {"enum": list(REQUIRED_TEST_STAGES)},
                    "objective": {"$ref": "#/$defs/asciiText"},
                    "required_evidence": {"$ref": "#/$defs/textList"},
                },
            },
            "blueprint": {
                "type": "object",
                "additionalProperties": False,
                "required": blueprint_fields,
                "properties": {
                    "profile_id": {
                        "type": "string",
                        "pattern": "^AOE-G[A-H]-D[0-9]{2}-S[0-9]{2}$",
                    },
                    "profile_version": {"$ref": "#/$defs/asciiText"},
                    "name": {"$ref": "#/$defs/asciiText"},
                    "group_id": {"type": "string", "pattern": "^G[A-H]$"},
                    "command_id": {
                        "type": "string",
                        "pattern": "^AOE-G[A-H]-D[0-9]{2}$",
                    },
                    "category": {"$ref": "#/$defs/asciiText"},
                    "mission": {"$ref": "#/$defs/asciiText"},
                    "policy_template_id": {"$ref": "#/$defs/asciiText"},
                    "vector_id": {
                        "type": "string",
                        "pattern": "^AV-G[A-H]-D[0-9]{2}-S[0-9]{2}-01$",
                    },
                    "scenario_family_id": {
                        "type": "string",
                        "pattern": "^qualification\\.aoe-g[a-h]-d[0-9]{2}-s[0-9]{2}$",
                    },
                    "primary_capability_ids": {"$ref": "#/$defs/capabilityList"},
                    "supporting_capability_ids": {"$ref": "#/$defs/capabilityList"},
                    "independent_validator_id": {
                        "type": "string",
                        "pattern": "^AOE-HQ-[0-9]{2}$",
                    },
                    "maximum_autonomous_action_tier": {
                        "enum": ["R0", "R1", "R2", "R3", "R4", "R5"]
                    },
                    "allowed_action_tiers": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"enum": ["R0", "R1", "R2", "R3", "R4", "R5"]},
                    },
                    "minimum_evidence_level": {"enum": ["E0", "E1", "E2", "E3", "E4"]},
                    "allowed_actions": text_list,
                    "prohibited_actions": text_list,
                    "stop_conditions": text_list,
                    "tool_adapter_requirements": {**text_list, "minItems": 6},
                    "input_contract": text_list,
                    "output_contract": text_list,
                    "control_requirements": {**text_list, "minItems": 6},
                    "evidence_contract": text_list,
                    "restoration_contract": text_list,
                    "known_blind_spots": text_list,
                    "required_scenario_variants": {**text_list, "minItems": 6},
                    "required_gate_ids": text_list,
                    "critical_failures": {**text_list, "minItems": 5},
                    "test_requirements": {
                        "type": "array",
                        "minItems": len(REQUIRED_TEST_STAGES),
                        "maxItems": len(REQUIRED_TEST_STAGES),
                        "items": {"$ref": "#/$defs/testRequirement"},
                    },
                    "command_mission": {"$ref": "#/$defs/asciiText"},
                    "command_inputs": {"$ref": "#/$defs/asciiText"},
                    "command_outputs": {"$ref": "#/$defs/asciiText"},
                    "collaboration_contract": {"$ref": "#/$defs/asciiText"},
                    "command_boundary": {"$ref": "#/$defs/asciiText"},
                    "required_component_ids": component_schema,
                    "implementation_status": {"const": "defined_unimplemented"},
                    "blueprint_sha256": {"$ref": "#/$defs/sha256"},
                },
            },
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--capabilities", type=Path, default=CAPABILITIES_PATH)
    parser.add_argument("--roadmap", type=Path, default=ROADMAP_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    parser.add_argument("--standard", type=Path, default=STANDARD_PATH)
    parser.add_argument("--plans", type=Path, default=PLANS_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--schema-output", type=Path, default=SCHEMA_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    document = build_catalog(
        load_json(args.registry),
        load_json(args.capabilities),
        load_json(args.vectors),
        load_json(args.standard),
        load_json(args.plans),
    )
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    roadmap = load_army_expansion_roadmap(args.roadmap)
    vectors = load_attack_vector_catalog(args.vectors, registry, roadmap)
    standard = load_qualification_standard(args.standard, registry, capabilities)
    plans = load_qualification_plan_catalog_v2(
        args.plans,
        registry,
        capabilities,
        vectors,
        standard,
    )
    catalog = CandidateBlueprintCatalogV2.from_dict(
        document,
        registry,
        capabilities,
        vectors,
        standard,
        plans,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.schema_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.schema_output.write_text(
        json.dumps(build_schema(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "catalog_sha256": catalog.catalog_sha256,
                **catalog.coverage_summary,
                "implementation_effect": "none",
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
