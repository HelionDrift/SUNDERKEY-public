#!/usr/bin/env python3
"""Build deterministic Army v2 expert runtime packs and closed schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_blueprints_v2 import load_candidate_blueprint_catalog_v2
from sunderkey.expert_runtime import (
    CONTEXT_KINDS,
    PRODUCT_TYPES,
    SOURCE_NAMES,
    build_runtime_pack_catalog,
)
from sunderkey.implementation_program_v2 import load_implementation_work_package_catalog_v2
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from sunderkey.validation import loads_json_without_duplicate_keys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry"
SCHEMAS = REGISTRY / "schemas"


def _text() -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": r"^[\t\n\r -~]*[!-~][\t\n\r -~]*$",
    }


def _texts(minimum: int = 1) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": minimum,
        "maxItems": 256,
        "uniqueItems": True,
        "items": _text(),
    }


def _closed(required: list[str], properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _defs() -> dict[str, Any]:
    return {
        "text": _text(),
        "identifier": {
            "type": "string",
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$",
        },
        "sha256": {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"},
        "profileId": {
            "type": "string",
            "pattern": r"^AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})$",
        },
    }


def runtime_catalog_schema() -> dict[str, Any]:
    source_catalog = _closed(
        ["catalog_id", "catalog_version", "catalog_sha256"],
        {
            "catalog_id": {"$ref": "#/$defs/text"},
            "catalog_version": {"$ref": "#/$defs/text"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
        },
    )
    source_binding = _closed(
        [
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "binding_kind",
            "item_ids",
            "item_digests",
            "binding_sha256",
        ],
        {
            "catalog_id": {"$ref": "#/$defs/text"},
            "catalog_version": {"$ref": "#/$defs/text"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
            "binding_kind": {
                "enum": [
                    "exact_profile_command_and_policy",
                    "exact_specialist_record",
                    "exact_command_member_aggregate_no_direct_commander_record",
                ]
            },
            "item_ids": _texts(),
            "item_digests": {
                "type": "array",
                "minItems": 1,
                "items": {"$ref": "#/$defs/sha256"},
            },
            "binding_sha256": {"$ref": "#/$defs/sha256"},
        },
    )
    source_map = _closed(list(SOURCE_NAMES), {name: source_catalog for name in SOURCE_NAMES})
    binding_map = _closed(list(SOURCE_NAMES), {name: source_binding for name in SOURCE_NAMES})
    instruction = _closed(
        [
            "role",
            "mission",
            "may",
            "may_not",
            "stop_conditions",
            "required_operating_rules",
            "allowed_product_types",
            "model_output_effect",
            "tool_effect",
            "authorization_effect",
        ],
        {
            "role": {"enum": ["specialist", "domain_commander"]},
            "mission": {"$ref": "#/$defs/text"},
            "may": _texts(),
            "may_not": _texts(),
            "stop_conditions": _texts(),
            "required_operating_rules": _texts(6),
            "allowed_product_types": {
                "type": "array",
                "minItems": 8,
                "uniqueItems": True,
                "items": {"enum": list(PRODUCT_TYPES)},
            },
            "model_output_effect": {"const": "advisory_only"},
            "tool_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
        },
    )
    context_policy = _closed(
        [
            "maximum_context_items",
            "maximum_context_tokens",
            "maximum_tokens_per_item",
            "reserved_output_tokens",
            "total_token_ceiling",
            "selection_order",
            "overflow_policy",
            "untrusted_text_policy",
        ],
        {
            "maximum_context_items": {"const": 48},
            "maximum_context_tokens": {"const": 24000},
            "maximum_tokens_per_item": {"const": 4000},
            "reserved_output_tokens": {"const": 8000},
            "total_token_ceiling": {"const": 32000},
            "selection_order": {
                "type": "array",
                "minItems": 5,
                "maxItems": 5,
                "uniqueItems": True,
                "items": {"enum": list(CONTEXT_KINDS)},
            },
            "overflow_policy": {"const": "reject_before_model_invocation"},
            "untrusted_text_policy": {"const": "data_only_never_instruction"},
        },
    )
    specialist_role_fields = [
        "contract_kind",
        "vector_id",
        "technical_focus",
        "vector_description",
        "platforms_and_protocols",
        "prerequisites_and_observations",
        "allowed_action_tiers",
        "tools_and_credentials",
        "expected_evidence",
        "cleanup_and_restoration",
        "known_blind_spots",
        "primary_capability_ids",
        "supporting_capability_ids",
        "independent_validator_id",
        "scenario_family_id",
        "evaluation_objective",
        "required_gate_ids",
        "critical_failures",
        "input_contract",
        "output_contract",
        "control_requirements",
        "restoration_contract",
        "collaboration_contract",
        "implementation_package_id",
        "implementation_status",
    ]
    specialist_role = _closed(
        specialist_role_fields,
        {
            "contract_kind": {"const": "specialist"},
            "vector_id": {"$ref": "#/$defs/text"},
            "technical_focus": {"$ref": "#/$defs/text"},
            "vector_description": {"$ref": "#/$defs/text"},
            "platforms_and_protocols": _texts(),
            "prerequisites_and_observations": _texts(),
            "allowed_action_tiers": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": ["R0", "R1", "R2", "R3", "R4", "R5"]},
            },
            "tools_and_credentials": _texts(),
            "expected_evidence": _texts(),
            "cleanup_and_restoration": _texts(),
            "known_blind_spots": _texts(),
            "primary_capability_ids": _texts(),
            "supporting_capability_ids": _texts(),
            "independent_validator_id": {"$ref": "#/$defs/profileId"},
            "scenario_family_id": {"$ref": "#/$defs/text"},
            "evaluation_objective": {"$ref": "#/$defs/text"},
            "required_gate_ids": _texts(),
            "critical_failures": _texts(),
            "input_contract": _texts(),
            "output_contract": _texts(),
            "control_requirements": _texts(),
            "restoration_contract": _texts(),
            "collaboration_contract": {"$ref": "#/$defs/text"},
            "implementation_package_id": {"$ref": "#/$defs/text"},
            "implementation_status": {"const": "scheduled_unassigned"},
        },
    )
    commander_role = _closed(
        [
            "contract_kind",
            "command_mission",
            "command_inputs",
            "command_outputs",
            "collaboration_contract",
            "command_boundary",
            "specialist_profile_ids",
            "synthesis_requirements",
        ],
        {
            "contract_kind": {"const": "domain_commander"},
            "command_mission": {"$ref": "#/$defs/text"},
            "command_inputs": {"$ref": "#/$defs/text"},
            "command_outputs": {"$ref": "#/$defs/text"},
            "collaboration_contract": {"$ref": "#/$defs/text"},
            "command_boundary": {"$ref": "#/$defs/text"},
            "specialist_profile_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/profileId"},
            },
            "synthesis_requirements": _texts(4),
        },
    )
    pack_fields = [
        "schema_version",
        "profile_id",
        "profile_sha256",
        "profile_kind",
        "profile_name",
        "command_id",
        "command_sha256",
        "command_member_profile_ids",
        "registry_sha256",
        "source_bindings",
        "instruction_contract",
        "role_contract",
        "context_policy",
        "runtime_status",
        "network_call_performed",
        "model_call_performed",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "authorization_effect",
        "runtime_pack_id",
        "runtime_pack_sha256",
    ]
    pack = _closed(
        pack_fields,
        {
            "schema_version": {"const": 1},
            "profile_id": {"$ref": "#/$defs/profileId"},
            "profile_sha256": {"$ref": "#/$defs/sha256"},
            "profile_kind": {"enum": ["specialist", "domain_commander"]},
            "profile_name": {"$ref": "#/$defs/text"},
            "command_id": {"type": "string", "pattern": r"^AOE-G[A-E]-D[0-9]{2}$"},
            "command_sha256": {"$ref": "#/$defs/sha256"},
            "command_member_profile_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/profileId"},
            },
            "registry_sha256": {"$ref": "#/$defs/sha256"},
            "source_bindings": binding_map,
            "instruction_contract": instruction,
            "role_contract": {"oneOf": [specialist_role, commander_role]},
            "context_policy": context_policy,
            "runtime_status": {"const": "compiled_uninstantiated"},
            "network_call_performed": {"const": False},
            "model_call_performed": {"const": False},
            "qualification_effect": {"const": "none"},
            "routing_effect": {"const": "none"},
            "execution_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
            "runtime_pack_id": {"type": "string", "pattern": r"^ERP-[0-9A-F]{32}$"},
            "runtime_pack_sha256": {"$ref": "#/$defs/sha256"},
        },
    )
    gap = _closed(
        [
            "gap_id",
            "affected_profile_ids",
            "affected_source_catalogs",
            "direct_binding_status",
            "implemented_binding",
            "required_future_artifact",
        ],
        {
            "gap_id": {"const": "commander-direct-specialist-artifacts-not-defined"},
            "affected_profile_ids": {
                "type": "array",
                "minItems": 25,
                "maxItems": 25,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/profileId"},
            },
            "affected_source_catalogs": {
                "type": "array",
                "minItems": 5,
                "maxItems": 5,
                "uniqueItems": True,
                "items": {"enum": list(SOURCE_NAMES[1:])},
            },
            "direct_binding_status": {"const": "not_available_in_checked_sources"},
            "implemented_binding": {
                "const": ("exact_command_policy_records_and_child_specialist_aggregate")
            },
            "required_future_artifact": {"$ref": "#/$defs/text"},
        },
    )
    coverage_fields = [
        "runtime_pack_count",
        "specialist_pack_count",
        "domain_commander_pack_count",
        "specialist_exact_binding_count",
        "commander_exact_profile_command_policy_binding_count",
        "commander_child_aggregate_binding_count",
        "network_call_count",
        "model_call_count",
    ]
    coverage = _closed(
        coverage_fields,
        {
            "runtime_pack_count": {"const": 416},
            "specialist_pack_count": {"const": 391},
            "domain_commander_pack_count": {"const": 25},
            "specialist_exact_binding_count": {"const": 2346},
            "commander_exact_profile_command_policy_binding_count": {"const": 25},
            "commander_child_aggregate_binding_count": {"const": 125},
            "network_call_count": {"const": 0},
            "model_call_count": {"const": 0},
        },
    )
    fields = [
        "schema_version",
        "catalog_id",
        "catalog_version",
        "catalog_status",
        "source_catalogs",
        "runtime_packs",
        "source_gaps",
        "coverage_summary",
        "qualification_effect",
        "routing_effect",
        "execution_effect",
        "authorization_effect",
        "catalog_sha256",
    ]
    schema = _closed(
        fields,
        {
            "schema_version": {"const": 1},
            "catalog_id": {"const": "sunderkey-army-v2-expert-runtime-packs"},
            "catalog_version": {"const": "1.0.0"},
            "catalog_status": {"const": "compiled_uninstantiated"},
            "source_catalogs": source_map,
            "runtime_packs": {
                "type": "array",
                "minItems": 416,
                "maxItems": 416,
                "items": pack,
            },
            "source_gaps": {"type": "array", "minItems": 1, "maxItems": 1, "items": gap},
            "coverage_summary": coverage,
            "qualification_effect": {"const": "none"},
            "routing_effect": {"const": "none"},
            "execution_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
            "catalog_sha256": {"$ref": "#/$defs/sha256"},
        },
    )
    schema.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": _defs()})
    return schema


def execution_envelope_schema() -> dict[str, Any]:
    context = _closed(
        ["context_id", "context_kind", "content", "content_sha256", "estimated_tokens", "trust"],
        {
            "context_id": {"$ref": "#/$defs/identifier"},
            "context_kind": {"enum": list(CONTEXT_KINDS)},
            "content": {
                "type": "string",
                "minLength": 1,
                "maxLength": 16000,
                "pattern": (
                    r"^[^\u0000-\u0008\u000B\u000C\u000E-\u001F"
                    r"\u007F-\u009F\uD800-\uDFFF\u200B-\u200F"
                    r"\u202A-\u202E\u2060-\u206F\uFEFF]*$"
                ),
            },
            "content_sha256": {"$ref": "#/$defs/sha256"},
            "estimated_tokens": {"type": "integer", "minimum": 1, "maximum": 4000},
            "trust": {"const": "untrusted_data"},
        },
    )
    budget = _closed(
        ["context_tokens", "input_token_ceiling", "output_token_ceiling", "total_token_ceiling"],
        {
            "context_tokens": {"type": "integer", "minimum": 0, "maximum": 24000},
            "input_token_ceiling": {"type": "integer", "minimum": 1, "maximum": 24000},
            "output_token_ceiling": {"const": 8000},
            "total_token_ceiling": {"const": 32000},
        },
    )
    fields = [
        "schema_version",
        "envelope_id",
        "envelope_sha256",
        "runtime_catalog_sha256",
        "runtime_pack_id",
        "runtime_pack_sha256",
        "profile_id",
        "mission_id",
        "plan_id",
        "work_id",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "evidence_requirement_ids",
        "cleanup_requirement_ids",
        "approval_requirement_ids",
        "context_items",
        "token_budget",
        "untrusted_text_policy",
        "model_output_effect",
        "tool_effect",
        "authorization_effect",
    ]
    schema = _closed(
        fields,
        {
            "schema_version": {"const": 1},
            "envelope_id": {"type": "string", "pattern": r"^EEE-[0-9A-F]{32}$"},
            "envelope_sha256": {"$ref": "#/$defs/sha256"},
            "runtime_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "runtime_pack_id": {"type": "string", "pattern": r"^ERP-[0-9A-F]{32}$"},
            "runtime_pack_sha256": {"$ref": "#/$defs/sha256"},
            "profile_id": {"$ref": "#/$defs/profileId"},
            "mission_id": {"$ref": "#/$defs/identifier"},
            "plan_id": {"$ref": "#/$defs/identifier"},
            "work_id": {"$ref": "#/$defs/identifier"},
            "target_scope_sha256": {"$ref": "#/$defs/sha256"},
            "authority_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "evidence_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "evidence_requirement_ids": _texts(),
            "cleanup_requirement_ids": _texts(),
            "approval_requirement_ids": _texts(),
            "context_items": {
                "type": "array",
                "maxItems": 48,
                "uniqueItems": True,
                "items": context,
            },
            "token_budget": budget,
            "untrusted_text_policy": {"const": "data_only_never_instruction"},
            "model_output_effect": {"const": "advisory_only"},
            "tool_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
        },
    )
    schema.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "$defs": _defs()})
    return schema


def _payload_schema(product_type: str) -> dict[str, Any]:
    text_ref = {"$ref": "#/$defs/text"}
    sha_ref = {"$ref": "#/$defs/sha256"}
    if product_type == "observation":
        return _closed(
            ["observed_facts", "collection_limits"],
            {"observed_facts": _texts(), "collection_limits": _texts()},
        )
    if product_type == "negative_evidence":
        return _closed(
            ["searched_for", "methods", "non_observation", "coverage_limits"],
            {
                "searched_for": _texts(),
                "methods": _texts(),
                "non_observation": text_ref,
                "coverage_limits": _texts(),
            },
        )
    if product_type == "hypothesis":
        return _closed(
            ["claim", "supporting_reasons", "falsification_conditions"],
            {
                "claim": text_ref,
                "supporting_reasons": _texts(),
                "falsification_conditions": _texts(),
            },
        )
    if product_type == "finding":
        return _closed(
            ["claim", "severity", "reproduction_requirements", "limitations"],
            {
                "claim": text_ref,
                "severity": {"enum": ["informational", "low", "medium", "high", "critical"]},
                "reproduction_requirements": _texts(),
                "limitations": _texts(),
            },
        )
    if product_type == "clarification_question":
        return _closed(
            ["question", "decision_needed", "blocking"],
            {"question": text_ref, "decision_needed": text_ref, "blocking": {"type": "boolean"}},
        )
    if product_type == "action_proposal":
        return _closed(
            [
                "target_scope_sha256",
                "authority_snapshot_sha256",
                "evidence_snapshot_sha256",
                "mission_id",
                "plan_id",
                "work_id",
                "requested_action_tier",
                "proposed_actions",
                "evidence_requirement_ids",
                "cleanup_requirement_ids",
                "approval_requirement_ids",
                "stop_conditions",
            ],
            {
                "target_scope_sha256": sha_ref,
                "authority_snapshot_sha256": sha_ref,
                "evidence_snapshot_sha256": sha_ref,
                "mission_id": {"$ref": "#/$defs/identifier"},
                "plan_id": {"$ref": "#/$defs/identifier"},
                "work_id": {"$ref": "#/$defs/identifier"},
                "requested_action_tier": {"enum": ["R0", "R1", "R2", "R3", "R4", "R5"]},
                "proposed_actions": _texts(),
                "evidence_requirement_ids": _texts(),
                "cleanup_requirement_ids": _texts(),
                "approval_requirement_ids": _texts(),
                "stop_conditions": _texts(),
            },
        )
    if product_type == "blocker":
        return _closed(
            ["blocker_kind", "blocked_requirement_ids", "resolution_needed"],
            {
                "blocker_kind": text_ref,
                "blocked_requirement_ids": _texts(),
                "resolution_needed": text_ref,
            },
        )
    if product_type == "abstention":
        return _closed(
            ["reason", "missing_requirement_ids", "safe_alternative"],
            {"reason": text_ref, "missing_requirement_ids": _texts(), "safe_alternative": text_ref},
        )
    child = _closed(
        ["product_id", "product_sha256", "producer_profile_id", "product_type"],
        {
            "product_id": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
            "product_sha256": sha_ref,
            "producer_profile_id": {"$ref": "#/$defs/profileId"},
            "product_type": {"enum": list(PRODUCT_TYPES[:-1])},
        },
    )
    disagreement = _closed(
        ["product_ids", "description", "resolution_status"],
        {
            "product_ids": _texts(),
            "description": text_ref,
            "resolution_status": {"enum": ["unresolved", "proposed_resolution"]},
        },
    )
    return _closed(
        [
            "child_products",
            "disagreements",
            "unresolved_uncertainties",
            "recommendation",
            "independent_review_separation",
        ],
        {
            "child_products": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": child,
            },
            "disagreements": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": disagreement,
            },
            "unresolved_uncertainties": _texts(0),
            "recommendation": text_ref,
            "independent_review_separation": {"const": "not_performed_by_commander"},
        },
    )


def work_product_schema() -> dict[str, Any]:
    review = _closed(
        ["required", "status", "reviewer_profile_ids", "producer_excluded"],
        {
            "required": {"type": "boolean"},
            "status": {"const": "not_reviewed"},
            "reviewer_profile_ids": {"const": []},
            "producer_excluded": {"const": True},
        },
    )
    common = {
        "schema_version": {"const": 1},
        "product_id": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
        "product_sha256": {"$ref": "#/$defs/sha256"},
        "runtime_catalog_sha256": {"$ref": "#/$defs/sha256"},
        "runtime_pack_id": {"type": "string", "pattern": r"^ERP-[0-9A-F]{32}$"},
        "runtime_pack_sha256": {"$ref": "#/$defs/sha256"},
        "producer_profile_id": {"$ref": "#/$defs/profileId"},
        "execution_envelope_id": {"type": "string", "pattern": r"^EEE-[0-9A-F]{32}$"},
        "execution_envelope_sha256": {"$ref": "#/$defs/sha256"},
        "mission_id": {"$ref": "#/$defs/identifier"},
        "plan_id": {"$ref": "#/$defs/identifier"},
        "work_id": {"$ref": "#/$defs/identifier"},
        "summary": {"$ref": "#/$defs/text"},
        "confidence": {"enum": ["unknown", "low", "moderate", "high"]},
        "uncertainty": {"$ref": "#/$defs/text"},
        "evidence_refs": {
            "type": "array",
            "maxItems": 256,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/sha256"},
        },
        "lineage_product_ids": {
            "type": "array",
            "maxItems": 256,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
        },
        "independent_review": review,
        "model_output_effect": {"const": "advisory_only"},
        "tool_effect": {"const": "none"},
        "authorization_effect": {"const": "none"},
    }
    required = [*common, "product_type", "payload"]
    variants = []
    for product_type in PRODUCT_TYPES:
        variant_common = dict(common)
        if product_type in {"observation", "negative_evidence", "finding"}:
            variant_common["evidence_refs"] = {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/sha256"},
            }
        variants.append(
            _closed(
                required,
                {
                    **variant_common,
                    "product_type": {"const": product_type},
                    "payload": _payload_schema(product_type),
                },
            )
        )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": _defs(),
        "oneOf": variants,
    }


def load_sources() -> tuple[Any, ...]:
    for name in (
        "army-v2.json",
        "army-expansion-roadmap-v1.json",
        "attack-vectors-v2.json",
        "capabilities-army-v2.json",
        "qualification-standard-v2.json",
        "qualification-plans-army-v2.json",
        "candidate-blueprints-army-v2.json",
        "implementation-work-packages-v2.json",
    ):
        loads_json_without_duplicate_keys((REGISTRY / name).read_text(encoding="utf-8"))
    registry = load_registry(REGISTRY / "army-v2.json")
    roadmap = load_army_expansion_roadmap(REGISTRY / "army-expansion-roadmap-v1.json")
    vectors = load_attack_vector_catalog(REGISTRY / "attack-vectors-v2.json", registry, roadmap)
    capabilities = load_capability_catalog(REGISTRY / "capabilities-army-v2.json", registry)
    standard = load_qualification_standard(
        REGISTRY / "qualification-standard-v2.json", registry, capabilities
    )
    plans = load_qualification_plan_catalog_v2(
        REGISTRY / "qualification-plans-army-v2.json",
        registry,
        capabilities,
        vectors,
        standard,
    )
    blueprints = load_candidate_blueprint_catalog_v2(
        REGISTRY / "candidate-blueprints-army-v2.json",
        registry,
        capabilities,
        vectors,
        standard,
        plans,
    )
    packages = load_implementation_work_package_catalog_v2(
        REGISTRY / "implementation-work-packages-v2.json",
        registry,
        capabilities,
        roadmap,
        vectors,
        plans,
        blueprints,
    )
    return registry, vectors, capabilities, plans, blueprints, packages


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> None:
    sources = load_sources()
    write_json(REGISTRY / "expert-runtime-packs-army-v2.json", build_runtime_pack_catalog(*sources))
    write_json(SCHEMAS / "expert-runtime-pack-catalog-v1.schema.json", runtime_catalog_schema())
    write_json(SCHEMAS / "expert-execution-envelope-v1.schema.json", execution_envelope_schema())
    write_json(SCHEMAS / "expert-work-product-v1.schema.json", work_product_schema())


if __name__ == "__main__":
    main()
