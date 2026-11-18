"""Build the provider-neutral Passive OSINT development candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "development.passive-osint"
CANDIDATE_VERSION = "1.0.0"
COMPONENT_DOMAIN = "sunderkey.candidate-component.v1"
CANDIDATE_DOMAIN = "sunderkey.candidate-implementation.v1"
SOURCE_DOMAIN = "sunderkey.candidate-source-artifact.v1"
COMPONENT_TYPES = (
    "behavior_contract",
    "instruction_bundle",
    "knowledge_manifest",
    "runtime_manifest",
    "tool_policy",
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    source = root / "examples" / "implementation" / "passive-osint"
    parser = argparse.ArgumentParser(
        description="Build the non-executing Passive OSINT development candidate"
    )
    parser.add_argument("--registry", default=str(registry / "army-v1.json"))
    parser.add_argument(
        "--capabilities",
        default=str(registry / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(registry / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(registry / "qualification-plans-army-v1.json"),
    )
    parser.add_argument(
        "--blueprints",
        default=str(registry / "candidate-blueprints-army-v1.json"),
    )
    parser.add_argument(
        "--instructions",
        default=str(source / "instruction-bundle-v1.json"),
    )
    parser.add_argument(
        "--knowledge",
        default=str(source / "knowledge-source-manifest-v1.json"),
    )
    parser.add_argument(
        "--runtime",
        default=str(source / "runtime-config-v1.json"),
    )
    parser.add_argument(
        "--tools",
        default=str(source / "tool-manifest-v1.json"),
    )
    parser.add_argument(
        "--components-output",
        default=str(source / "candidate-components-v1.json"),
    )
    parser.add_argument(
        "--candidates-output",
        default=str(source / "candidate-implementations-v1.json"),
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


def _source_sha256(kind: str, document: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": SOURCE_DOMAIN,
            "kind": kind,
            "document": document,
        }
    )


def _component_sha256(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": COMPONENT_DOMAIN, "component": body})


def _candidate_sha256(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": CANDIDATE_DOMAIN, "candidate": body})


def _require_exact_fields(
    value: dict[str, Any],
    fields: set[str],
    label: str,
) -> None:
    if set(value) != fields:
        raise ValueError(f"{label} fields do not match the development contract")


def _validate_sources(
    instructions: dict[str, Any],
    knowledge: dict[str, Any],
    runtime: dict[str, Any],
    tools: dict[str, Any],
) -> None:
    _require_exact_fields(
        instructions,
        {
            "schema_version",
            "bundle_id",
            "bundle_version",
            "profile_id",
            "operating_mode",
            "mission",
            "input_contract",
            "workflow",
            "confidence_model",
            "evidence_rules",
            "prohibited_actions",
            "stop_conditions",
            "output_contract",
        },
        "instruction bundle",
    )
    if (
        instructions["schema_version"] != 1
        or instructions["profile_id"] != PROFILE_ID
        or instructions["operating_mode"] != "analysis_only"
        or instructions["output_contract"].get("finding_authority") is not False
    ):
        raise ValueError("Instruction bundle safety binding is invalid")
    if not instructions["workflow"] or not instructions["evidence_rules"]:
        raise ValueError("Instruction bundle workflow and evidence rules are required")

    _require_exact_fields(
        knowledge,
        {
            "schema_version",
            "manifest_id",
            "manifest_version",
            "profile_id",
            "retrieval_mode",
            "sources",
            "source_count",
            "reviewed_source_count",
            "rights_review_status",
            "minimum_evidence_level",
            "reason",
        },
        "knowledge source manifest",
    )
    if (
        knowledge["schema_version"] != 1
        or knowledge["profile_id"] != PROFILE_ID
        or knowledge["retrieval_mode"] != "disabled"
        or knowledge["sources"] != []
        or knowledge["source_count"] != 0
        or knowledge["reviewed_source_count"] != 0
        or knowledge["rights_review_status"] != "not_applicable"
    ):
        raise ValueError("Knowledge source manifest must keep retrieval disabled")

    _require_exact_fields(
        runtime,
        {
            "schema_version",
            "config_id",
            "config_version",
            "profile_id",
            "runtime_class",
            "provider_neutral",
            "provider_selection",
            "model_selection",
            "hosting_selection",
            "execution_enabled",
            "network_access",
            "process_access",
            "environment_inputs",
            "reason",
        },
        "runtime config",
    )
    if (
        runtime["schema_version"] != 1
        or runtime["profile_id"] != PROFILE_ID
        or runtime["runtime_class"] != "model_agent"
        or runtime["provider_neutral"] is not True
        or runtime["provider_selection"] != "unselected"
        or runtime["model_selection"] != "unselected"
        or runtime["hosting_selection"] != "unselected"
        or runtime["execution_enabled"] is not False
        or runtime["network_access"] is not False
        or runtime["process_access"] is not False
        or runtime["environment_inputs"] != []
    ):
        raise ValueError("Runtime config must remain provider-neutral and disabled")

    _require_exact_fields(
        tools,
        {
            "schema_version",
            "manifest_id",
            "manifest_version",
            "profile_id",
            "admission_mode",
            "tools",
            "allowed_tool_count",
            "credential_access",
            "target_access",
            "network_access",
            "execution_allowed",
            "reason",
        },
        "tool manifest",
    )
    if (
        tools["schema_version"] != 1
        or tools["profile_id"] != PROFILE_ID
        or tools["admission_mode"] != "deny_all"
        or tools["tools"] != []
        or tools["allowed_tool_count"] != 0
        or tools["credential_access"] is not False
        or tools["target_access"] is not False
        or tools["network_access"] is not False
        or tools["execution_allowed"] is not False
    ):
        raise ValueError("Tool manifest must remain deny-all and non-executing")


def _component(
    blueprint: dict[str, Any],
    component_type: str,
    specification: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "component_id": f"{CANDIDATE_ID}.{component_type.replace('_', '-')}",
        "component_version": "1.0.0",
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "profile_id": PROFILE_ID,
        "candidate_blueprint_sha256": blueprint["blueprint_sha256"],
        "component_type": component_type,
        "component_status": "development",
        "specification": specification,
    }
    return {**body, "component_sha256": _component_sha256(body)}


def build_catalogs(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
    blueprints: dict[str, Any],
    instructions: dict[str, Any],
    knowledge: dict[str, Any],
    runtime: dict[str, Any],
    tools: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_sources(instructions, knowledge, runtime, tools)
    profile = next(
        (item for item in registry["profiles"] if item["id"] == PROFILE_ID),
        None,
    )
    if profile is None or profile["kind"] != "specialist":
        raise ValueError("Passive OSINT specialist profile is missing")
    blueprint = next(
        (item for item in blueprints["blueprints"] if item["profile_id"] == PROFILE_ID),
        None,
    )
    if blueprint is None:
        raise ValueError("Passive OSINT candidate blueprint is missing")
    if instructions["mission"] != blueprint["mission"]:
        raise ValueError("Instruction bundle mission does not match the blueprint")
    if instructions["output_contract"] != {
        "required_sections": [
            "scope",
            "observations",
            "hypotheses",
            "evidence",
            "confidence",
            "limitations",
            "collection_gaps",
            "recommended_handoffs",
        ],
        "minimum_evidence_level": blueprint["minimum_evidence_level"],
        "maximum_autonomous_action_tier": blueprint["maximum_autonomous_action_tier"],
        "finding_authority": False,
    }:
        raise ValueError("Instruction output contract does not match the blueprint")

    specifications = {
        "behavior_contract": {
            "mission": blueprint["mission"],
            "allowed_actions": blueprint["allowed_actions"],
            "prohibited_actions": blueprint["prohibited_actions"],
            "stop_conditions": blueprint["stop_conditions"],
            "maximum_autonomous_action_tier": blueprint[
                "maximum_autonomous_action_tier"
            ],
            "minimum_evidence_level": blueprint["minimum_evidence_level"],
        },
        "instruction_bundle": {
            "bundle_format": "structured_bundle",
            "content_sha256": _source_sha256("instruction_bundle", instructions),
            "primary_capability_ids": blueprint["primary_capability_ids"],
            "supporting_capability_ids": blueprint["supporting_capability_ids"],
            "scenario_family_id": blueprint["scenario_family_id"],
            "required_gate_ids": blueprint["required_gate_ids"],
        },
        "knowledge_manifest": {
            "retrieval_mode": knowledge["retrieval_mode"],
            "source_manifest_sha256": _source_sha256(
                "knowledge_source_manifest", knowledge
            ),
            "source_count": knowledge["source_count"],
            "reviewed_source_count": knowledge["reviewed_source_count"],
            "rights_review_status": knowledge["rights_review_status"],
            "minimum_evidence_level": blueprint["minimum_evidence_level"],
        },
        "runtime_manifest": {
            "runtime_class": runtime["runtime_class"],
            "provider_ref": runtime["provider_selection"],
            "model_ref": runtime["model_selection"],
            "hosting_ref": runtime["hosting_selection"],
            "runtime_config_sha256": _source_sha256("runtime_config", runtime),
            "execution_enabled": runtime["execution_enabled"],
            "network_access": runtime["network_access"],
            "process_access": runtime["process_access"],
        },
        "tool_policy": {
            "policy_template_id": blueprint["policy_template_id"],
            "allowed_action_ids": blueprint["allowed_actions"],
            "prohibited_action_ids": blueprint["prohibited_actions"],
            "admission_mode": tools["admission_mode"],
            "tool_manifest_sha256": _source_sha256("tool_manifest", tools),
            "allowed_tool_count": tools["allowed_tool_count"],
            "credential_access": tools["credential_access"],
            "target_access": tools["target_access"],
            "network_access": tools["network_access"],
            "execution_allowed": tools["execution_allowed"],
        },
    }
    component_items = [
        _component(blueprint, component_type, specifications[component_type])
        for component_type in COMPONENT_TYPES
    ]
    component_catalog = {
        "schema_version": 1,
        "component_catalog_id": "sunderkey-passive-osint-development-components",
        "component_catalog_version": "1.0.0",
        "candidate_blueprint_catalog_id": blueprints["blueprint_catalog_id"],
        "candidate_blueprint_catalog_version": blueprints[
            "blueprint_catalog_version"
        ],
        "candidate_blueprint_catalog_sha256": _canonical_sha256(blueprints),
        "components": component_items,
    }
    by_type = {item["component_type"]: item for item in component_items}
    candidate_body = {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "profile_id": PROFILE_ID,
        "lifecycle": "development",
        "implementation_kind": "agent_bundle",
        "candidate_blueprint_sha256": blueprint["blueprint_sha256"],
        "behavior_contract_sha256": by_type["behavior_contract"]["component_sha256"],
        "instruction_bundle_sha256": by_type["instruction_bundle"]["component_sha256"],
        "knowledge_manifest_sha256": by_type["knowledge_manifest"]["component_sha256"],
        "runtime_manifest_sha256": by_type["runtime_manifest"]["component_sha256"],
        "tool_policy_sha256": by_type["tool_policy"]["component_sha256"],
    }
    candidate = {
        **candidate_body,
        "candidate_artifact_sha256": _candidate_sha256(candidate_body),
    }
    candidate_catalog = {
        "schema_version": 1,
        "candidate_catalog_id": "sunderkey-passive-osint-development-candidates",
        "candidate_catalog_version": "1.0.0",
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "qualification_plan_catalog_id": plans["plan_catalog_id"],
        "qualification_plan_catalog_version": plans["plan_catalog_version"],
        "qualification_plan_catalog_sha256": _canonical_sha256(plans),
        "candidate_blueprint_catalog_id": blueprints["blueprint_catalog_id"],
        "candidate_blueprint_catalog_version": blueprints[
            "blueprint_catalog_version"
        ],
        "candidate_blueprint_catalog_sha256": _canonical_sha256(blueprints),
        "candidates": [candidate],
    }
    return component_catalog, candidate_catalog


def build_reports(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    return build_catalogs(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
        _read_json(args.plans),
        _read_json(args.blueprints),
        _read_json(args.instructions),
        _read_json(args.knowledge),
        _read_json(args.runtime),
        _read_json(args.tools),
    )


def _write_json(path: str, value: dict[str, Any]) -> Path:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output


def main() -> None:
    args = build_parser().parse_args()
    components, candidates = build_reports(args)
    components_output = _write_json(args.components_output, components)
    candidates_output = _write_json(args.candidates_output, candidates)
    print(f"Wrote {len(components['components'])} components: {components_output}")
    print(f"Wrote {len(candidates['candidates'])} candidate: {candidates_output}")


if __name__ == "__main__":
    main()
