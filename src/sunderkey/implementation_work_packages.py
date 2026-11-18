"""Deterministic domain commander work packages for implementation waves."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_blueprints import CandidateBlueprintCatalog
from .candidate_components import CandidateComponentCatalog
from .candidate_inventory import CandidateImplementationCatalog
from .errors import QualificationError
from .implementation_roadmap import (
    BUILD_SEQUENCE,
    SpecialistImplementationRoadmapReport,
    assess_specialist_implementation_roadmap,
)
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _load_json,
    _mapping,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog, RoutingPolicy

REPORT_SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.implementation-work-package-report.v1"
REPORT_ID_PATTERN = re.compile(r"IWR-[0-9A-F]{32}")
SELECTION_REPORT_ID_PATTERN = re.compile(r"IWS-[0-9A-F]{32}")
WAVE_ID_PATTERN = re.compile(r"IW-[0-9]{3}")
WORK_POLICY_ID = "domain_commander_stage_graph_v1"
QUALIFICATION_AUTHORITY_DECISION = "D008"
SELECTION_REPORT_DOMAIN = "sunderkey.implementation-wave-selection-report.v1"

DELIVERABLE_KINDS = {
    "behavior_contract": "candidate_component_artifact",
    "instruction_bundle": "candidate_component_artifact",
    "knowledge_manifest": "candidate_component_artifact",
    "runtime_manifest": "candidate_component_artifact",
    "tool_policy": "candidate_component_artifact",
    "candidate_artifact_binding": "candidate_catalog_revision",
    "candidate_onboarding": "candidate_onboarding_report",
    "synthetic_evaluation_preflight": "candidate_preflight_report",
    "authoritative_qualification": "qualification_registry_revision",
}

ACCEPTANCE_CONTRACTS = {
    "behavior_contract": [
        "matches_exact_candidate_blueprint",
        "content_addressed_component_identity_valid",
        "candidate_component_contract_valid",
    ],
    "instruction_bundle": [
        "matches_exact_candidate_blueprint",
        "content_addressed_component_identity_valid",
        "candidate_component_contract_valid",
    ],
    "knowledge_manifest": [
        "matches_exact_candidate_blueprint",
        "content_addressed_component_identity_valid",
        "candidate_component_contract_valid",
    ],
    "runtime_manifest": [
        "matches_exact_candidate_blueprint",
        "content_addressed_component_identity_valid",
        "candidate_component_contract_valid",
    ],
    "tool_policy": [
        "matches_exact_candidate_blueprint",
        "content_addressed_component_identity_valid",
        "candidate_component_contract_valid",
    ],
    "candidate_artifact_binding": [
        "all_required_component_digests_bound",
        "candidate_artifact_identity_valid",
        "candidate_lifecycle_is_nonfixture",
    ],
    "candidate_onboarding": [
        "all_required_components_present",
        "component_digest_bindings_match_candidate",
        "candidate_onboarding_effect_none",
    ],
    "synthetic_evaluation_preflight": [
        "candidate_submission_identity_valid",
        "all_advisory_preflight_checks_pass",
        "preflight_effect_none",
    ],
    "authoritative_qualification": [
        "D008_authority_contract_satisfied",
        "signed_evidence_provenance_verified",
        "independent_review_requirements_satisfied",
        "versioned_registry_revision_reviewed",
    ],
}


@dataclass(frozen=True)
class ImplementationWorkPackageReport:
    """Self-identifying, non-dispatching implementation task graph."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ImplementationWorkPackageReport:
        value = _mapping(raw, "implementation work package report")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "work_package_effect",
                "registry",
                "implementation_roadmap",
                "work_policy",
                "summary",
                "work_item_state_counts",
                "packages",
                "limitations",
            },
            "implementation work package report",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Implementation work package report schema version is "
                "invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Implementation work package report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if (
            report_sha256 != expected_hash
            or report_id != _report_id(expected_hash)
        ):
            raise QualificationError(
                "Implementation work package report hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Implementation work package report document is invalid"
            )
        return value


@dataclass(frozen=True)
class ImplementationWaveSelectionReport:
    """Self-identifying selection of one reviewed implementation wave."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ImplementationWaveSelectionReport:
        value = _mapping(raw, "implementation wave selection report")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "selection_effect",
                "work_package_report",
                "implementation_roadmap",
                "registry",
                "selected_wave_id",
                "selected_package_id",
                "summary",
                "package",
                "limitations",
            },
            "implementation wave selection report",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Implementation wave selection report schema version is "
                "invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or SELECTION_REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Implementation wave selection report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _selection_report_hash(body)
        if (
            report_sha256 != expected_hash
            or report_id != _selection_report_id(expected_hash)
        ):
            raise QualificationError(
                "Implementation wave selection report hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Implementation wave selection report document is invalid"
            )
        return value


def assess_implementation_work_packages(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    policy: RoutingPolicy,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
    components: CandidateComponentCatalog,
    candidates: CandidateImplementationCatalog,
    roadmap: SpecialistImplementationRoadmapReport,
) -> ImplementationWorkPackageReport:
    """Expand a current implementation roadmap into non-dispatching tasks."""

    if not isinstance(roadmap, SpecialistImplementationRoadmapReport):
        raise QualificationError(
            "roadmap must be a SpecialistImplementationRoadmapReport"
        )
    expected_roadmap = assess_specialist_implementation_roadmap(
        registry,
        capability_catalog,
        policy,
        standard,
        plans,
        blueprints,
        components,
        candidates,
    )
    if roadmap != expected_roadmap:
        raise QualificationError(
            "Implementation roadmap does not match current source artifacts"
        )
    roadmap_document = roadmap.to_dict()
    registry.validate()
    packages = [
        _package_record(registry, wave)
        for wave in roadmap_document["waves"]
    ]
    all_lanes = [
        lane for package in packages for lane in package["command_lanes"]
    ]
    all_work_items = [
        item for lane in all_lanes for item in lane["work_items"]
    ]
    work_item_ids = [str(item["work_item_id"]) for item in all_work_items]
    if len(work_item_ids) != len(set(work_item_ids)):
        raise QualificationError(
            "Implementation work package report contains duplicate work IDs"
        )
    state_counts = Counter(str(item["task_state"]) for item in all_work_items)
    stage_counts = Counter(str(item["stage_id"]) for item in all_work_items)
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "implementation_work_packages_ready",
        "work_package_effect": "none",
        "registry": roadmap_document["registry"],
        "implementation_roadmap": {
            "report_id": roadmap.report_id,
            "sha256": roadmap.report_sha256,
        },
        "work_policy": {
            "policy_id": WORK_POLICY_ID,
            "subject_role": "specialist_profile_being_implemented",
            "accountable_role": "existing_domain_commander",
            "runtime_assignment_effect": "none",
            "maximum_command_lanes_per_package": 23,
            "maximum_lanes_per_command_per_package": 1,
            "stages": [
                {
                    **stage,
                    "deliverable_kind": DELIVERABLE_KINDS[
                        str(stage["stage_id"])
                    ],
                    "acceptance_checks": ACCEPTANCE_CONTRACTS[
                        str(stage["stage_id"])
                    ],
                }
                for stage in BUILD_SEQUENCE
            ],
            "coordination_requirements": [
                "domain_commander_accountability",
                "group_commander_visibility",
                "independent_control_review",
                "independent_assurance_review",
                "readiness_tracking",
            ],
        },
        "summary": {
            "wave_package_count": len(packages),
            "group_count": len(
                {
                    str(lane["group_id"])
                    for lane in all_lanes
                }
            ),
            "domain_command_count": len(
                {
                    str(lane["command_id"])
                    for lane in all_lanes
                }
            ),
            "specialist_lane_count": len(all_lanes),
            "work_item_count": len(all_work_items),
            "component_authoring_work_item_count": sum(
                stage_counts[component_type]
                for component_type in (
                    "behavior_contract",
                    "instruction_bundle",
                    "knowledge_manifest",
                    "runtime_manifest",
                    "tool_policy",
                )
            ),
            "candidate_binding_work_item_count": stage_counts[
                "candidate_artifact_binding"
            ],
            "onboarding_work_item_count": stage_counts[
                "candidate_onboarding"
            ],
            "preflight_work_item_count": stage_counts[
                "synthetic_evaluation_preflight"
            ],
            "authoritative_qualification_work_item_count": stage_counts[
                "authoritative_qualification"
            ],
            "initially_ready_work_item_count": state_counts[
                "ready_for_authoring"
            ],
            "dependency_blocked_work_item_count": state_counts[
                "waiting_on_dependencies"
            ],
            "decision_blocked_work_item_count": state_counts[
                "blocked_by_decision"
            ],
        },
        "work_item_state_counts": {
            "ready_for_authoring": state_counts["ready_for_authoring"],
            "waiting_on_dependencies": state_counts[
                "waiting_on_dependencies"
            ],
            "blocked_by_decision": state_counts["blocked_by_decision"],
        },
        "packages": packages,
        "limitations": [
            (
                "These work packages are deterministic planning graphs. "
                "They do not assign a runtime worker or dispatch work."
            ),
            (
                "Domain commander accountability is inherited from the "
                "reviewed registry. It is not authentication or execution "
                "authority."
            ),
            (
                "The packages do not select a provider, model, endpoint, "
                "tool, credential, knowledge source, reviewer identity, "
                "evidence authority, or target."
            ),
            (
                "Component, binding, onboarding, and advisory preflight "
                "tasks can proceed without D008. Every authoritative "
                "qualification task remains blocked by D008."
            ),
            (
                "Task dependencies and acceptance checks do not prove work "
                "completion, correctness, provenance, independent review, "
                "qualification, routing eligibility, or safety."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return ImplementationWorkPackageReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def select_implementation_wave_package(
    work_packages: ImplementationWorkPackageReport,
    wave_id: str,
) -> ImplementationWaveSelectionReport:
    """Select one exact package without assignment, dispatch, or mutation."""

    if not isinstance(work_packages, ImplementationWorkPackageReport):
        raise QualificationError(
            "work_packages must be an ImplementationWorkPackageReport"
        )
    work_packages = ImplementationWorkPackageReport.from_dict(
        work_packages.to_dict()
    )
    if not isinstance(wave_id, str) or WAVE_ID_PATTERN.fullmatch(wave_id) is None:
        raise QualificationError("wave_id must use the IW-NNN form")
    work_package_document = work_packages.to_dict()
    matches = [
        package
        for package in work_package_document["packages"]
        if package["wave_id"] == wave_id
    ]
    if len(matches) != 1:
        raise QualificationError(
            f"Implementation wave package does not exist: {wave_id}"
        )
    package = matches[0]
    lanes = package["command_lanes"]
    work_items = [item for lane in lanes for item in lane["work_items"]]
    state_counts = Counter(str(item["task_state"]) for item in work_items)
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "implementation_wave_package_selected",
        "selection_effect": "none",
        "work_package_report": {
            "report_id": work_packages.report_id,
            "sha256": work_packages.report_sha256,
        },
        "implementation_roadmap": work_package_document[
            "implementation_roadmap"
        ],
        "registry": work_package_document["registry"],
        "selected_wave_id": wave_id,
        "selected_package_id": package["package_id"],
        "summary": {
            "group_count": package["group_count"],
            "domain_command_count": package["domain_command_count"],
            "specialist_lane_count": package["specialist_lane_count"],
            "work_item_count": package["work_item_count"],
            "ready_for_authoring_work_item_count": state_counts[
                "ready_for_authoring"
            ],
            "waiting_on_dependencies_work_item_count": state_counts[
                "waiting_on_dependencies"
            ],
            "blocked_by_decision_work_item_count": state_counts[
                "blocked_by_decision"
            ],
        },
        "package": package,
        "limitations": [
            (
                "This selection preserves one exact package from the bound "
                "full-Army report. It does not change that package."
            ),
            (
                "Selection does not assign a runtime worker, start a task, "
                "record progress, dispatch work, or grant authority."
            ),
            (
                "The selected package does not choose a provider, model, "
                "endpoint, tool, credential, reviewer identity, evidence "
                "authority, or target."
            ),
            (
                "Every authoritative qualification item remains blocked by "
                "D008 regardless of package selection."
            ),
        ],
    }
    report_hash = _selection_report_hash(body)
    return ImplementationWaveSelectionReport.from_dict(
        {
            **body,
            "report_id": _selection_report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _package_record(
    registry: ExpertRegistry,
    wave: dict[str, Any],
) -> dict[str, Any]:
    lanes = [
        _lane_record(profile, str(wave["wave_id"]))
        for profile in wave["profiles"]
    ]
    group_ids = sorted({str(lane["group_id"]) for lane in lanes})
    commander_ids = [
        str(lane["accountable_commander_profile_id"])
        for lane in lanes
    ]
    work_items = [item for lane in lanes for item in lane["work_items"]]
    state_counts = Counter(str(item["task_state"]) for item in work_items)
    return {
        "package_id": f"IWP-{wave['wave_id']}",
        "wave_id": wave["wave_id"],
        "wave_number": wave["wave_number"],
        "group_count": len(group_ids),
        "domain_command_count": len(lanes),
        "specialist_lane_count": len(lanes),
        "work_item_count": len(work_items),
        "initially_ready_work_item_count": state_counts[
            "ready_for_authoring"
        ],
        "decision_blocked_work_item_count": state_counts[
            "blocked_by_decision"
        ],
        "group_commanders": [
            {
                "group_id": group_id,
                "commander_profile_id": (
                    registry.groups_by_id[group_id].commander_profile_id
                ),
            }
            for group_id in group_ids
        ],
        "domain_commander_profile_ids": commander_ids,
        "coordination_state": "planning_only",
        "command_lanes": lanes,
    }


def _lane_record(
    profile: dict[str, Any],
    wave_id: str,
) -> dict[str, Any]:
    task_ids = [
        _work_item_id(wave_id, str(profile["profile_id"]), stage_number)
        for stage_number in range(1, len(BUILD_SEQUENCE) + 1)
    ]
    work_items: list[dict[str, Any]] = []
    for stage in BUILD_SEQUENCE:
        stage_number = int(stage["stage_number"])
        stage_id = str(stage["stage_id"])
        if stage_number == 1:
            dependencies: list[str] = []
            task_state = "ready_for_authoring"
        elif stage_number == 6:
            dependencies = task_ids[:5]
            task_state = "waiting_on_dependencies"
        else:
            dependencies = [task_ids[stage_number - 2]]
            task_state = (
                "blocked_by_decision"
                if stage_number == 9
                else "waiting_on_dependencies"
            )
        work_items.append(
            {
                "work_item_id": task_ids[stage_number - 1],
                "stage_number": stage_number,
                "stage_id": stage_id,
                "task_state": task_state,
                "dependency_work_item_ids": dependencies,
                "decision_blocker_ids": (
                    [QUALIFICATION_AUTHORITY_DECISION]
                    if stage_number == 9
                    else []
                ),
                "task_effect": "none",
            }
        )
    return {
        "lane_id": f"IL-{wave_id}-{profile['profile_id']}",
        "subject_profile_id": profile["profile_id"],
        "subject_profile_name": profile["name"],
        "group_id": profile["group_id"],
        "command_id": profile["command_id"],
        "accountable_commander_profile_id": profile[
            "commander_profile_id"
        ],
        "priority_tier": profile["priority_tier"],
        "candidate_blueprint_sha256": profile[
            "candidate_blueprint_sha256"
        ],
        "required_gate_ids": profile["required_gate_ids"],
        "work_item_count": len(work_items),
        "work_items": work_items,
    }


def _work_item_id(
    wave_id: str,
    profile_id: str,
    stage_number: int,
) -> str:
    return f"IWI-{wave_id}-{profile_id}-{stage_number:02d}"


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "IWR-" + report_hash.removeprefix("sha256:")[:32].upper()


def _selection_report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": SELECTION_REPORT_DOMAIN,
            "report": body,
        }
    )


def _selection_report_id(report_hash: str) -> str:
    return "IWS-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_implementation_work_package_report(
    path: str | Path,
) -> ImplementationWorkPackageReport:
    return ImplementationWorkPackageReport.from_dict(
        _load_json(path, "implementation work package report")
    )
