"""Implementation-ready, fail-closed candidate blueprints for Army v2."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .attack_vectors import AttackVector, AttackVectorCatalog
from .errors import QualificationError
from .qualification import QualificationStandard, _canonical_json, _canonical_sha256
from .qualification_plans_v2 import QualificationPlanCatalogV2
from .registry import DomainCommand, ExpertProfile, ExpertRegistry, PolicyTemplate
from .routing import CapabilityCatalog, ProfileCapabilityAssignment

BLUEPRINT_DOMAIN = "sunderkey.candidate-blueprint.v2"
CATALOG_DOMAIN = "sunderkey.candidate-blueprint-catalog.v2"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REQUIRED_COMPONENT_IDS = (
    "behavior_contract",
    "instruction_bundle",
    "knowledge_manifest",
    "runtime_manifest",
    "tool_policy",
    "input_contract",
    "output_contract",
    "evidence_contract",
    "restoration_contract",
    "test_manifest",
)
REQUIRED_TEST_STAGES = (
    "static_analysis",
    "unit",
    "integration",
    "containment",
    "evidence",
    "restoration",
)
BLUEPRINT_FIELDS = {
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
}
CATALOG_FIELDS = {
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
}


def _ascii_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _strings(value: Any, label: str, *, minimum: int = 1) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} must be a list")
    result = tuple(_ascii_text(item, f"{label} item") for item in value)
    if len(result) < minimum:
        raise QualificationError(f"{label} must contain at least {minimum} items")
    if len(result) != len(set(result)):
        raise QualificationError(f"{label} contains duplicates")
    return result


def candidate_blueprint_test_requirements() -> list[dict[str, Any]]:
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


def build_candidate_blueprint_v2_body(
    profile: ExpertProfile,
    command: DomainCommand,
    policy: PolicyTemplate,
    assignment: ProfileCapabilityAssignment,
    vector: AttackVector,
    plan: dict[str, Any],
) -> dict[str, Any]:
    primary_capability = assignment.primary_capability_ids[0]
    supporting_capabilities = assignment.supporting_capability_ids
    return {
        "profile_id": profile.id,
        "profile_version": profile.version,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "category": profile.category,
        "mission": profile.mission,
        "policy_template_id": policy.id,
        "vector_id": vector.vector_id,
        "scenario_family_id": plan["scenario_family_id"],
        "primary_capability_ids": list(assignment.primary_capability_ids),
        "supporting_capability_ids": list(assignment.supporting_capability_ids),
        "independent_validator_id": plan["independent_validator_id"],
        "maximum_autonomous_action_tier": profile.max_autonomous_tier.value,
        "allowed_action_tiers": list(plan["allowed_action_tiers"]),
        "minimum_evidence_level": profile.minimum_evidence_level.value,
        "allowed_actions": list(policy.may),
        "prohibited_actions": list(policy.may_not),
        "stop_conditions": list(policy.stop_conditions),
        "tool_adapter_requirements": [
            f"Declare one provider-neutral adapter for capability {primary_capability}.",
            (
                "Declare the exact platform and protocol coverage from the bound "
                f"vector: {'; '.join(vector.platforms_and_protocols)}."
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
            *vector.prerequisites_and_observations,
            *vector.tools_and_credentials,
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
                f"Structured {vector.vector_id} result that separates verified "
                "findings, negative results, hypotheses, ambiguity, and abstention."
            ),
            *vector.expected_evidence,
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
        "evidence_contract": list(plan["required_evidence"]),
        "restoration_contract": list(plan["cleanup_and_restoration"]),
        "known_blind_spots": list(vector.known_blind_spots),
        "required_scenario_variants": list(plan["required_scenario_variants"]),
        "required_gate_ids": list(plan["required_gate_ids"]),
        "critical_failures": list(plan["critical_failures"]),
        "test_requirements": candidate_blueprint_test_requirements(),
        "command_mission": command.mission,
        "command_inputs": command.inputs,
        "command_outputs": command.outputs,
        "collaboration_contract": command.collaboration,
        "command_boundary": command.boundary,
        "required_component_ids": list(REQUIRED_COMPONENT_IDS),
        "implementation_status": "defined_unimplemented",
    }


@dataclass(frozen=True)
class CandidateBlueprintCatalogV2:
    catalog_sha256: str
    blueprints: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, int]
    document_json: str

    @property
    def blueprints_by_profile_id(self) -> dict[str, dict[str, Any]]:
        return {item["profile_id"]: dict(item) for item in self.blueprints}

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        capabilities: CapabilityCatalog,
        vectors: AttackVectorCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalogV2,
    ) -> CandidateBlueprintCatalogV2:
        if not isinstance(raw, dict) or set(raw) != CATALOG_FIELDS:
            raise QualificationError("Candidate blueprint catalog v2 fields are invalid")
        if (
            raw.get("schema_version") != 2
            or raw.get("blueprint_catalog_id") != "sunderkey-specialist-blueprints-v2"
            or raw.get("blueprint_catalog_version") != "2.0.0"
            or raw.get("expert_catalog_id") != registry.catalog_id
            or raw.get("expert_catalog_version") != registry.catalog_version
            or raw.get("expert_catalog_sha256") != _canonical_sha256(registry.to_dict())
            or raw.get("capability_catalog_id") != capabilities.catalog_id
            or raw.get("capability_catalog_version") != capabilities.catalog_version
            or raw.get("capability_catalog_sha256") != capabilities.canonical_sha256
            or raw.get("vector_catalog_id") != "sunderkey-attack-vectors-v2"
            or raw.get("vector_catalog_version") != "2.0.0"
            or raw.get("vector_catalog_sha256") != vectors.catalog_sha256
            or raw.get("qualification_standard_id") != standard.standard_id
            or raw.get("qualification_standard_version") != standard.standard_version
            or raw.get("qualification_standard_sha256") != standard.canonical_sha256
            or raw.get("qualification_plan_catalog_id") != "sunderkey-army-qualification-plans-v2"
            or raw.get("qualification_plan_catalog_version") != "2.0.0"
            or raw.get("qualification_plan_catalog_sha256") != plans.catalog_sha256
            or raw.get("required_component_ids") != list(REQUIRED_COMPONENT_IDS)
            or raw.get("required_test_stages") != list(REQUIRED_TEST_STAGES)
            or raw.get("blueprint_status") != "defined_unimplemented"
            or raw.get("qualification_effect") != "none"
            or raw.get("routing_effect") != "none"
            or raw.get("execution_effect") != "none"
            or raw.get("deployment_effect") != "none"
        ):
            raise QualificationError("Candidate blueprint catalog v2 binding is invalid")

        raw_blueprints = raw.get("blueprints")
        if not isinstance(raw_blueprints, list):
            raise QualificationError("Candidate blueprints v2 must be a list")
        profiles = registry.profiles_by_id
        commands = registry.commands_by_id
        policies = {item.id: item for item in registry.policies}
        assignments = capabilities.assignments_by_profile_id
        vectors_by_profile = {item.primary_specialist_id: item for item in vectors.vectors}
        plans_by_profile = plans.plans_by_profile_id
        expected_order = tuple(item.primary_specialist_id for item in vectors.vectors)
        parsed: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, raw_blueprint in enumerate(raw_blueprints):
            label = f"blueprints[{index}]"
            if not isinstance(raw_blueprint, dict) or set(raw_blueprint) != {
                *BLUEPRINT_FIELDS,
                "blueprint_sha256",
            }:
                raise QualificationError(f"{label} fields are invalid")
            body = {key: value for key, value in raw_blueprint.items() if key != "blueprint_sha256"}
            profile_id = _ascii_text(body.get("profile_id"), f"{label}.profile_id")
            if profile_id in seen:
                raise QualificationError("Candidate blueprint profiles are duplicated")
            seen.add(profile_id)
            profile = profiles.get(profile_id)
            vector = vectors_by_profile.get(profile_id)
            assignment = assignments.get(profile_id)
            plan = plans_by_profile.get(profile_id)
            if (
                profile is None
                or vector is None
                or assignment is None
                or plan is None
                or profile.command_id is None
                or profile.policy_template not in policies
            ):
                raise QualificationError(f"{label} references an unknown specialist")
            command = commands.get(profile.command_id)
            if command is None:
                raise QualificationError(f"{label} references an unknown command")
            expected_body = build_candidate_blueprint_v2_body(
                profile,
                command,
                policies[profile.policy_template],
                assignment,
                vector,
                plan,
            )
            if body != expected_body:
                raise QualificationError(
                    f"Candidate blueprint does not match reviewed inputs: {profile_id}"
                )
            tests = body.get("test_requirements")
            if (
                not isinstance(tests, list)
                or tuple(item.get("stage") if isinstance(item, dict) else None for item in tests)
                != REQUIRED_TEST_STAGES
            ):
                raise QualificationError(f"{profile_id} test matrix is invalid")
            for test_index, test in enumerate(tests):
                if not isinstance(test, dict) or set(test) != {
                    "stage",
                    "objective",
                    "required_evidence",
                }:
                    raise QualificationError(f"{profile_id} test contract is invalid")
                _ascii_text(test["objective"], f"{label}.tests[{test_index}].objective")
                _strings(
                    test["required_evidence"],
                    f"{label}.tests[{test_index}].evidence",
                )
            for field, minimum in (
                ("tool_adapter_requirements", 6),
                ("input_contract", 1),
                ("output_contract", 1),
                ("control_requirements", 6),
                ("evidence_contract", 1),
                ("restoration_contract", 1),
                ("required_scenario_variants", 6),
                ("critical_failures", 5),
            ):
                _strings(body.get(field), f"{label}.{field}", minimum=minimum)
            blueprint_sha256 = raw_blueprint.get("blueprint_sha256")
            expected_hash = _canonical_sha256({"domain": BLUEPRINT_DOMAIN, "blueprint": body})
            if blueprint_sha256 != expected_hash:
                raise QualificationError(f"{label}.blueprint_sha256 is invalid")
            parsed.append(dict(raw_blueprint))

        if (
            len(parsed) != 391
            or tuple(item["profile_id"] for item in parsed) != expected_order
            or seen != set(expected_order)
        ):
            raise QualificationError(
                "Candidate blueprints v2 must cover every specialist in vector order"
            )
        expected_coverage = {
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
        if raw.get("coverage_summary") != expected_coverage:
            raise QualificationError("Candidate blueprint v2 coverage is invalid")
        _strings(raw.get("limitations"), "candidate blueprint v2 limitations", minimum=5)
        digest = raw.get("catalog_sha256")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise QualificationError("Candidate blueprint catalog v2 hash is invalid")
        canonical = dict(raw)
        canonical.pop("catalog_sha256")
        expected_digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": canonical})
        if digest != expected_digest:
            raise QualificationError("Candidate blueprint catalog v2 hash does not match content")
        return cls(
            catalog_sha256=digest,
            blueprints=tuple(parsed),
            coverage_summary=dict(expected_coverage),
            document_json=_canonical_json(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def load_candidate_blueprint_catalog_v2(
    source: str | Path,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    vectors: AttackVectorCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalogV2,
) -> CandidateBlueprintCatalogV2:
    path = Path(source)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load candidate blueprint catalog v2: {path}") from exc
    return CandidateBlueprintCatalogV2.from_dict(
        raw,
        registry,
        capabilities,
        vectors,
        standard,
        plans,
    )


__all__ = [
    "CandidateBlueprintCatalogV2",
    "REQUIRED_COMPONENT_IDS",
    "REQUIRED_TEST_STAGES",
    "build_candidate_blueprint_v2_body",
    "candidate_blueprint_test_requirements",
    "load_candidate_blueprint_catalog_v2",
]
