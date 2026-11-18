"""Commander-owned implementation queues and work packages for Army v2."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .army_expansion import ArmyExpansionRoadmap
from .attack_vectors import AttackVectorCatalog
from .candidate_blueprints_v2 import CandidateBlueprintCatalogV2
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256
from .qualification_plans_v2 import QualificationPlanCatalogV2
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

PACKAGE_DOMAIN = "sunderkey.implementation-work-packages.v2"
ROADMAP_DOMAIN = "sunderkey.specialist-implementation-roadmap.v2"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
VALIDATOR_CAPACITY = {
    "AOE-HQ-19": 12,
    "AOE-HQ-33": 3,
    "AOE-HQ-34": 3,
    "AOE-HQ-35": 2,
}
RISK_CLASS_BY_VALIDATOR = {
    "AOE-HQ-19": "standard_independent_reproduction",
    "AOE-HQ-33": "human_safety_or_restoration",
    "AOE-HQ-34": "hostile_content_or_redaction",
    "AOE-HQ-35": "cross_system_reconciliation",
}
RISK_WEIGHT_BY_VALIDATOR = {
    "AOE-HQ-19": 200,
    "AOE-HQ-33": 400,
    "AOE-HQ-34": 300,
    "AOE-HQ-35": 350,
}
VERIFICATION_COST_BY_VALIDATOR = {
    "AOE-HQ-19": 3,
    "AOE-HQ-33": 5,
    "AOE-HQ-34": 4,
    "AOE-HQ-35": 5,
}
MAX_PACKAGES_PER_WAVE = 20
MAX_PACKAGES_PER_COMMAND_PER_WAVE = 1
STAGES = (
    {
        "stage_number": 1,
        "stage_id": "blueprint_review",
        "objective": "Confirm exact source bindings, scope, ownership, and acceptance criteria.",
        "required_evidence": [
            "Commander review of the exact blueprint and vector bindings.",
            "Independent control review of authority and stop boundaries.",
        ],
    },
    {
        "stage_number": 2,
        "stage_id": "component_contract_authoring",
        "objective": "Author all ten versioned candidate components from the blueprint.",
        "required_evidence": [
            "Content digests for every required component.",
            "Traceability from each component to its blueprint requirement.",
        ],
    },
    {
        "stage_number": 3,
        "stage_id": "adapter_implementation",
        "objective": "Implement the bounded provider-neutral capability adapter.",
        "required_evidence": [
            "Pinned executable, dependency, configuration, and runtime digests.",
            "Dry-run, timeout, cancellation, rate-limit, evidence, and cleanup hooks.",
        ],
    },
    {
        "stage_number": 4,
        "stage_id": "safety_boundary_implementation",
        "objective": "Implement scope, tier, credential, evidence, stop, and restoration controls.",
        "required_evidence": [
            "Fail-closed policy enforcement results.",
            "Credential non-persistence and terminal-admission integration results.",
        ],
    },
    {
        "stage_number": 5,
        "stage_id": "static_and_unit_validation",
        "objective": "Pass static analysis and deterministic positive and negative unit tests.",
        "required_evidence": [
            "Static, dependency, schema, policy, and unit-test reports.",
            "Coverage of every declared critical-failure branch.",
        ],
    },
    {
        "stage_number": 6,
        "stage_id": "integration_and_containment_validation",
        "objective": "Pass synthetic integration and containment checks with typed handoffs.",
        "required_evidence": [
            "Synthetic or test-target integration records.",
            "Scope, network, process, filesystem, timeout, cancellation, and rate-limit denials.",
        ],
    },
    {
        "stage_number": 7,
        "stage_id": "evidence_and_restoration_validation",
        "objective": "Reproduce conclusions and verify cleanup and residual-effect reconciliation.",
        "required_evidence": [
            "Independent evidence reproduction and false-positive dispositions.",
            "Cleanup, credential-return, state, and residual-effect receipts.",
        ],
    },
    {
        "stage_number": 8,
        "stage_id": "candidate_assembly_and_commander_review",
        "objective": "Assemble the candidate manifest and obtain commander readiness review.",
        "required_evidence": [
            "Content-addressed candidate manifest bound to every component and test result.",
            "Commander readiness disposition and unresolved-risk list.",
        ],
    },
)


def _new_specialist_ids(roadmap: ArmyExpansionRoadmap) -> set[str]:
    document = roadmap.to_dict()
    result = {
        item["profile_id"]
        for command in document["existing_command_additions"]
        for item in command["specialists"]
    }
    result.update(
        item["profile_id"]
        for command in document["new_commands"]
        for item in command["specialists"]
    )
    return result


def _coverage_gain(vector: dict[str, Any], is_new: bool) -> int:
    relationship_scores = {
        "exact_risk": 20,
        "related_technique": 15,
        "contextual_tactic": 10,
    }
    mapping_gain = max(
        relationship_scores[item["relationship"]] for item in vector["standards_mappings"]
    )
    return mapping_gain + (40 if is_new else 0)


def _work_items(profile_id: str) -> list[dict[str, Any]]:
    work_ids = [f"IWI2-{profile_id}-{index:02d}" for index in range(1, 9)]
    items = []
    for stage in STAGES:
        number = stage["stage_number"]
        if number == 1:
            dependencies: list[str] = []
        elif number == 4:
            dependencies = [work_ids[1], work_ids[2]]
        else:
            dependencies = [work_ids[number - 2]]
        items.append(
            {
                "work_item_id": work_ids[number - 1],
                "stage_number": number,
                "stage_id": stage["stage_id"],
                "objective": stage["objective"],
                "dependency_work_item_ids": dependencies,
                "required_evidence": stage["required_evidence"],
                "task_state": "planned_unassigned",
                "task_effect": "none",
            }
        )
    return items


def _assign_waves(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    waves: list[dict[str, Any]] = []
    for package in packages:
        validator_id = package["independent_validator_id"]
        command_id = package["command_id"]
        selected: dict[str, Any] | None = None
        for wave in waves:
            if (
                len(wave["package_ids"]) < MAX_PACKAGES_PER_WAVE
                and command_id not in wave["command_ids"]
                and wave["validator_load"][validator_id] < VALIDATOR_CAPACITY[validator_id]
            ):
                selected = wave
                break
        if selected is None:
            number = len(waves) + 1
            selected = {
                "wave_id": f"IW2-{number:03d}",
                "wave_number": number,
                "package_ids": [],
                "command_ids": [],
                "validator_load": {key: 0 for key in VALIDATOR_CAPACITY},
                "risk_class_counts": {value: 0 for value in RISK_CLASS_BY_VALIDATOR.values()},
                "new_specialist_package_count": 0,
                "wave_status": "planned_unassigned",
                "operational_effect": "none",
            }
            waves.append(selected)
        selected["package_ids"].append(package["package_id"])
        selected["command_ids"].append(command_id)
        selected["validator_load"][validator_id] += 1
        selected["risk_class_counts"][package["risk_class"]] += 1
        selected["new_specialist_package_count"] += package["is_new_specialist"]
        package["scheduled_wave_id"] = selected["wave_id"]
        package["scheduled_wave_number"] = selected["wave_number"]
    return waves


def build_implementation_program_v2(
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    roadmap: ArmyExpansionRoadmap,
    vectors: AttackVectorCatalog,
    plans: QualificationPlanCatalogV2,
    blueprints: CandidateBlueprintCatalogV2,
) -> tuple[dict[str, Any], dict[str, Any]]:
    registry_document = registry.to_dict()
    vector_document = vectors.to_dict()
    blueprint_document = blueprints.to_dict()
    new_specialists = _new_specialist_ids(roadmap)
    profiles = registry.profiles_by_id
    commands = registry.commands_by_id
    groups = registry.groups_by_id
    blueprint_by_profile = blueprints.blueprints_by_profile_id
    vector_by_profile = {item["primary_specialist_id"]: item for item in vector_document["vectors"]}
    plan_by_profile = plans.plans_by_profile_id
    packages: list[dict[str, Any]] = []
    for profile_id, blueprint in blueprint_by_profile.items():
        profile = profiles[profile_id]
        command = commands[str(profile.command_id)]
        group = groups[str(profile.group_id)]
        vector = vector_by_profile[profile_id]
        plan = plan_by_profile[profile_id]
        validator_id = plan["independent_validator_id"]
        is_new = profile_id in new_specialists
        coverage_gain = _coverage_gain(vector, is_new)
        risk_weight = RISK_WEIGHT_BY_VALIDATOR[validator_id]
        verification_cost = VERIFICATION_COST_BY_VALIDATOR[validator_id]
        priority_score = risk_weight + coverage_gain + (6 - verification_cost)
        package_id = f"IWP2-{profile_id}"
        packages.append(
            {
                "package_id": package_id,
                "priority_sequence": 0,
                "priority_score": priority_score,
                "risk_class": RISK_CLASS_BY_VALIDATOR[validator_id],
                "risk_weight": risk_weight,
                "coverage_gain": coverage_gain,
                "verification_cost": verification_cost,
                "is_new_specialist": is_new,
                "profile_id": profile_id,
                "profile_name": profile.name,
                "group_id": str(profile.group_id),
                "group_commander_profile_id": group.commander_profile_id,
                "command_id": str(profile.command_id),
                "commander_profile_id": command.commander_profile_id,
                "vector_id": blueprint["vector_id"],
                "primary_capability_ids": blueprint["primary_capability_ids"],
                "supporting_capability_ids": blueprint["supporting_capability_ids"],
                "collaboration_package_ids": [
                    f"IWP2-{item}" for item in vector["supporting_specialist_ids"]
                ],
                "external_dependency_package_ids": [],
                "independent_validator_id": validator_id,
                "reviewer_profile_ids": [
                    command.commander_profile_id,
                    group.commander_profile_id,
                    "AOE-HQ-12",
                    validator_id,
                    "AOE-HQ-28",
                    "AOE-HQ-31",
                ],
                "blueprint_sha256": blueprint["blueprint_sha256"],
                "required_component_ids": blueprint["required_component_ids"],
                "required_test_stages": blueprint_document["required_test_stages"],
                "work_items": _work_items(profile_id),
                "package_status": "scheduled_unassigned",
                "qualification_effect": "none",
                "routing_effect": "none",
                "execution_effect": "none",
                "deployment_effect": "none",
            }
        )
    packages.sort(key=lambda item: (-item["priority_score"], item["profile_id"]))
    for index, package in enumerate(packages, start=1):
        package["priority_sequence"] = index
    waves = _assign_waves(packages)
    package_body = {
        "schema_version": 2,
        "package_catalog_id": "sunderkey-implementation-work-packages-v2",
        "package_catalog_version": "2.0.0",
        "expert_catalog_id": registry.catalog_id,
        "expert_catalog_version": registry.catalog_version,
        "expert_catalog_sha256": _canonical_sha256(registry_document),
        "capability_catalog_id": capabilities.catalog_id,
        "capability_catalog_version": capabilities.catalog_version,
        "capability_catalog_sha256": capabilities.canonical_sha256,
        "vector_catalog_sha256": vectors.catalog_sha256,
        "qualification_plan_catalog_sha256": plans.catalog_sha256,
        "blueprint_catalog_id": blueprint_document["blueprint_catalog_id"],
        "blueprint_catalog_version": blueprint_document["blueprint_catalog_version"],
        "blueprint_catalog_sha256": blueprints.catalog_sha256,
        "package_policy": {
            "policy_id": "sunderkey-commander-work-package-policy-v2",
            "maximum_packages_per_wave": MAX_PACKAGES_PER_WAVE,
            "maximum_packages_per_command_per_wave": (MAX_PACKAGES_PER_COMMAND_PER_WAVE),
            "validator_capacity_per_wave": VALIDATOR_CAPACITY,
            "risk_class_by_validator": RISK_CLASS_BY_VALIDATOR,
            "risk_weight_by_validator": RISK_WEIGHT_BY_VALIDATOR,
            "verification_cost_by_validator": VERIFICATION_COST_BY_VALIDATOR,
            "priority_formula": ("risk_weight + coverage_gain + (6 - verification_cost)"),
            "new_specialist_coverage_bonus": 40,
            "mapping_coverage_gain": {
                "exact_risk": 20,
                "related_technique": 15,
                "contextual_tactic": 10,
            },
            "cross_specialist_edges_are_collaboration_not_hard_dependencies": True,
            "stage_definitions": [dict(item) for item in STAGES],
        },
        "package_status": "planned_unassigned",
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
        "packages": packages,
        "coverage_summary": {
            "package_count": 391,
            "new_specialist_package_count": len(new_specialists),
            "command_count": 25,
            "commander_queue_count": 25,
            "collaboration_edge_count": sum(
                len(item["collaboration_package_ids"]) for item in packages
            ),
            "work_item_count": len(packages) * len(STAGES),
            "wave_count": len(waves),
        },
        "limitations": [
            "Packages are deterministic planning contracts and assign no runtime worker.",
            "Scheduling does not install tools, author components, or execute tests.",
            "Collaboration edges are not hard dependencies because the graph may be cyclic.",
            (
                "No provider, model, endpoint, credential, target, reviewer identity, "
                "or environment is selected."
            ),
            (
                "Qualification, routing, execution, deployment, and production "
                "authority remain unchanged."
            ),
        ],
    }
    package_body["catalog_sha256"] = _canonical_sha256(
        {"domain": PACKAGE_DOMAIN, "catalog": package_body}
    )

    package_by_id = {item["package_id"]: item for item in packages}
    commander_queues = []
    for command in registry.commands:
        queue_packages = [item for item in packages if item["command_id"] == command.id]
        queue_packages.sort(
            key=lambda item: (
                item["scheduled_wave_number"],
                item["priority_sequence"],
            )
        )
        commander_queues.append(
            {
                "command_id": command.id,
                "commander_profile_id": command.commander_profile_id,
                "package_ids": [item["package_id"] for item in queue_packages],
                "scheduled_wave_ids": list(
                    dict.fromkeys(item["scheduled_wave_id"] for item in queue_packages)
                ),
                "package_count": len(queue_packages),
                "maximum_concurrent_packages": 1,
                "queue_status": "defined_unassigned",
            }
        )
    roadmap_body = {
        "schema_version": 2,
        "roadmap_id": "sunderkey-specialist-implementation-roadmap-v2",
        "roadmap_version": "2.0.0",
        "expert_catalog_id": registry.catalog_id,
        "expert_catalog_version": registry.catalog_version,
        "expert_catalog_sha256": _canonical_sha256(registry_document),
        "blueprint_catalog_id": blueprint_document["blueprint_catalog_id"],
        "blueprint_catalog_version": blueprint_document["blueprint_catalog_version"],
        "blueprint_catalog_sha256": blueprints.catalog_sha256,
        "package_catalog_id": package_body["package_catalog_id"],
        "package_catalog_version": package_body["package_catalog_version"],
        "package_catalog_sha256": package_body["catalog_sha256"],
        "scheduling_policy": {
            "ordering": [
                "priority_score_descending",
                "profile_id_ascending",
                "earliest_capacity_eligible_wave",
            ],
            "maximum_packages_per_wave": MAX_PACKAGES_PER_WAVE,
            "maximum_packages_per_command_per_wave": (MAX_PACKAGES_PER_COMMAND_PER_WAVE),
            "validator_capacity_per_wave": VALIDATOR_CAPACITY,
            "command_queue_concurrency": 1,
            "selection_effect": "none",
        },
        "roadmap_status": "planned_unassigned",
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
        "waves": waves,
        "commander_queues": commander_queues,
        "coverage_summary": package_body["coverage_summary"],
        "limitations": [
            "The roadmap orders implementation work but does not assign or dispatch it.",
            "Wave capacity is a review and verification limit, not execution authority.",
            "Commander queues identify accountability but do not authenticate a commander.",
            "Package completion will require separately produced and reviewed evidence.",
            "No operational or qualification state changes are authorized by this roadmap.",
        ],
    }
    if set(package_by_id) != {package_id for wave in waves for package_id in wave["package_ids"]}:
        raise QualificationError("Implementation waves do not cover every package")
    roadmap_body["roadmap_sha256"] = _canonical_sha256(
        {"domain": ROADMAP_DOMAIN, "roadmap": roadmap_body}
    )
    return package_body, roadmap_body


@dataclass(frozen=True)
class ImplementationWorkPackageCatalogV2:
    catalog_sha256: str
    packages: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, int]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


@dataclass(frozen=True)
class SpecialistImplementationRoadmapV2:
    roadmap_sha256: str
    waves: tuple[dict[str, Any], ...]
    commander_queues: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, int]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load {label}: {path}") from exc
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    return value


def load_implementation_work_package_catalog_v2(
    source: str | Path,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    roadmap: ArmyExpansionRoadmap,
    vectors: AttackVectorCatalog,
    plans: QualificationPlanCatalogV2,
    blueprints: CandidateBlueprintCatalogV2,
) -> ImplementationWorkPackageCatalogV2:
    raw = _read_object(Path(source), "implementation work package catalog v2")
    expected, _ = build_implementation_program_v2(
        registry,
        capabilities,
        roadmap,
        vectors,
        plans,
        blueprints,
    )
    if raw != expected:
        raise QualificationError(
            "Implementation work package catalog v2 does not match reviewed inputs"
        )
    digest = raw.get("catalog_sha256")
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError("Implementation work package catalog hash is invalid")
    canonical = dict(raw)
    canonical.pop("catalog_sha256")
    if digest != _canonical_sha256({"domain": PACKAGE_DOMAIN, "catalog": canonical}):
        raise QualificationError("Implementation work package catalog hash does not match content")
    return ImplementationWorkPackageCatalogV2(
        catalog_sha256=digest,
        packages=tuple(raw["packages"]),
        coverage_summary=dict(raw["coverage_summary"]),
        document_json=_canonical_json(raw),
    )


def load_specialist_implementation_roadmap_v2(
    source: str | Path,
    packages: ImplementationWorkPackageCatalogV2,
    registry: ExpertRegistry,
    capabilities: CapabilityCatalog,
    roadmap: ArmyExpansionRoadmap,
    vectors: AttackVectorCatalog,
    plans: QualificationPlanCatalogV2,
    blueprints: CandidateBlueprintCatalogV2,
) -> SpecialistImplementationRoadmapV2:
    raw = _read_object(Path(source), "specialist implementation roadmap v2")
    expected_packages, expected = build_implementation_program_v2(
        registry,
        capabilities,
        roadmap,
        vectors,
        plans,
        blueprints,
    )
    if packages.to_dict() != expected_packages or raw != expected:
        raise QualificationError(
            "Specialist implementation roadmap v2 does not match reviewed inputs"
        )
    digest = raw.get("roadmap_sha256")
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError("Specialist implementation roadmap hash is invalid")
    canonical = dict(raw)
    canonical.pop("roadmap_sha256")
    if digest != _canonical_sha256({"domain": ROADMAP_DOMAIN, "roadmap": canonical}):
        raise QualificationError("Specialist implementation roadmap hash does not match content")
    return SpecialistImplementationRoadmapV2(
        roadmap_sha256=digest,
        waves=tuple(raw["waves"]),
        commander_queues=tuple(raw["commander_queues"]),
        coverage_summary=dict(raw["coverage_summary"]),
        document_json=_canonical_json(raw),
    )


__all__ = [
    "ImplementationWorkPackageCatalogV2",
    "SpecialistImplementationRoadmapV2",
    "build_implementation_program_v2",
    "load_implementation_work_package_catalog_v2",
    "load_specialist_implementation_roadmap_v2",
]
