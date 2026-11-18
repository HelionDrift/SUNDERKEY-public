"""Deterministic implementation waves for specialist candidates."""

from __future__ import annotations

import json
import re
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_blueprints import (
    REQUIRED_COMPONENT_IDS,
    CandidateBlueprintCatalog,
)
from .candidate_components import CandidateComponentCatalog
from .candidate_inventory import (
    CandidateImplementationCatalog,
    assess_candidate_inventory,
)
from .errors import QualificationError
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _load_json,
    _mapping,
)
from .registry import DomainCommand, ExpertProfile, ExpertRegistry
from .routing import CapabilityCatalog, RoutingPolicy
from .types import ProfileKind

REPORT_SCHEMA_VERSION = 1
REPORT_DOMAIN = "sunderkey.specialist-implementation-roadmap-report.v1"
REPORT_ID_PATTERN = re.compile(r"IRR-[0-9A-F]{32}")
WAVE_POLICY_ID = "domain_commander_round_robin_v1"
MAXIMUM_PROFILES_PER_WAVE = 23
MAXIMUM_PROFILES_PER_COMMAND_PER_WAVE = 1
QUALIFICATION_AUTHORITY_DECISION = "D008"

PRIORITY_TIERS = (
    {
        "rank": 0,
        "priority_tier": "command_coverage_gap",
        "meaning": (
            "The command has no specialist eligible under the selected "
            "routing policy."
        ),
    },
    {
        "rank": 1,
        "priority_tier": "eligible_baseline_gap",
        "meaning": (
            "The specialist is policy eligible but lacks a nonfixture "
            "candidate implementation."
        ),
    },
    {
        "rank": 2,
        "priority_tier": "army_depth_gap",
        "meaning": (
            "The command has an eligible baseline and this specialist adds "
            "implementation depth."
        ),
    },
)

BUILD_SEQUENCE = tuple(
    {
        "stage_number": index,
        "stage_id": component_type,
        "effect": "build_and_review_component_artifact",
    }
    for index, component_type in enumerate(REQUIRED_COMPONENT_IDS, 1)
) + (
    {
        "stage_number": 6,
        "stage_id": "candidate_artifact_binding",
        "effect": "bind_exact_component_digests_to_candidate_identity",
    },
    {
        "stage_number": 7,
        "stage_id": "candidate_onboarding",
        "effect": "validate_candidate_and_component_contracts",
    },
    {
        "stage_number": 8,
        "stage_id": "synthetic_evaluation_preflight",
        "effect": "validate_advisory_evaluation_inputs",
    },
    {
        "stage_number": 9,
        "stage_id": "authoritative_qualification",
        "effect": "requires_separately_authorized_qualification_process",
        "blocked_by_decision": QUALIFICATION_AUTHORITY_DECISION,
    },
)


@dataclass(frozen=True)
class SpecialistImplementationRoadmapReport:
    """Self-identifying, read-only projection of implementation work."""

    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> SpecialistImplementationRoadmapReport:
        value = _mapping(raw, "specialist implementation roadmap report")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "roadmap_effect",
                "registry",
                "capability_catalog",
                "routing_policy",
                "qualification_standard",
                "qualification_plan_catalog",
                "candidate_blueprint_catalog",
                "candidate_component_catalog",
                "candidate_catalog",
                "wave_policy",
                "summary",
                "priority_counts",
                "commands",
                "waves",
                "limitations",
            },
            "specialist implementation roadmap report",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Specialist implementation roadmap report schema version "
                "is invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Specialist implementation roadmap report identity is "
                "invalid"
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
                "Specialist implementation roadmap report hash is invalid"
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
                "Specialist implementation roadmap report document is "
                "invalid"
            )
        return value


def assess_specialist_implementation_roadmap(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    policy: RoutingPolicy,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
    components: CandidateComponentCatalog,
    candidates: CandidateImplementationCatalog,
) -> SpecialistImplementationRoadmapReport:
    """Schedule candidate implementation gaps without executing work."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(policy, RoutingPolicy):
        raise QualificationError("policy must be a RoutingPolicy")
    if not isinstance(standard, QualificationStandard):
        raise QualificationError("standard must be a QualificationStandard")
    if not isinstance(plans, QualificationPlanCatalog):
        raise QualificationError("plans must be a QualificationPlanCatalog")
    if not isinstance(blueprints, CandidateBlueprintCatalog):
        raise QualificationError(
            "blueprints must be a CandidateBlueprintCatalog"
        )
    if not isinstance(components, CandidateComponentCatalog):
        raise QualificationError(
            "components must be a CandidateComponentCatalog"
        )
    if not isinstance(candidates, CandidateImplementationCatalog):
        raise QualificationError(
            "candidates must be a CandidateImplementationCatalog"
        )

    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
    policy = RoutingPolicy.from_dict(policy.to_dict(), capability_catalog)
    standard = standard.revalidated(registry, capability_catalog)
    plans = plans.revalidated(
        registry,
        capability_catalog,
        standard,
    )
    blueprints = blueprints.revalidated(
        registry,
        capability_catalog,
        standard,
        plans,
    )
    components = components.revalidated(blueprints)
    candidates = candidates.revalidated(
        registry,
        capability_catalog,
        standard,
        plans,
        blueprints,
    )

    inventory = assess_candidate_inventory(
        registry,
        capability_catalog,
        standard,
        plans,
        blueprints,
        candidates,
    ).to_dict()
    inventory_by_profile = {
        str(record["profile_id"]): record
        for record in inventory["profiles"]
    }
    specialists = tuple(
        sorted(
            (
                profile
                for profile in registry.profiles
                if profile.kind is ProfileKind.SPECIALIST
            ),
            key=lambda profile: profile.id,
        )
    )
    profiles_by_id = {profile.id: profile for profile in specialists}
    command_eligibility = {
        command.id: _policy_eligible_count(
            command,
            profiles_by_id,
            policy,
        )
        for command in registry.commands
    }
    command_order = tuple(
        sorted(
            registry.commands,
            key=lambda command: (
                int(command_eligibility[command.id] > 0),
                command_eligibility[command.id],
                command.id,
            ),
        )
    )
    queues: dict[str, deque[ExpertProfile]] = {}
    for command in command_order:
        profiles = (
            profiles_by_id[profile_id]
            for profile_id in command.specialist_profile_ids
            if inventory_by_profile[profile_id]["implementation_gap"]
        )
        queues[command.id] = deque(
            sorted(
                profiles,
                key=lambda profile: (
                    int(not _policy_eligible(profile, policy)),
                    profile.id,
                ),
            )
        )

    waves: list[dict[str, Any]] = []
    scheduled_profile_ids: set[str] = set()
    while any(queues.values()):
        wave_number = len(waves) + 1
        wave_profiles: list[dict[str, Any]] = []
        for command in command_order:
            queue = queues[command.id]
            if not queue:
                continue
            profile = queue.popleft()
            if profile.id in scheduled_profile_ids:
                raise QualificationError(
                    "Implementation roadmap scheduled a duplicate profile"
                )
            scheduled_profile_ids.add(profile.id)
            wave_profiles.append(
                _roadmap_profile_record(
                    profile,
                    command,
                    inventory_by_profile[profile.id],
                    policy,
                    command_eligibility[command.id],
                    plans,
                    blueprints,
                )
            )
        if len(wave_profiles) > MAXIMUM_PROFILES_PER_WAVE:
            raise QualificationError(
                "Implementation roadmap exceeded the maximum wave size"
            )
        tier_counts = Counter(
            str(profile["priority_tier"])
            for profile in wave_profiles
        )
        waves.append(
            {
                "wave_id": f"IW-{wave_number:03d}",
                "wave_number": wave_number,
                "profile_count": len(wave_profiles),
                "command_count": len(
                    {profile["command_id"] for profile in wave_profiles}
                ),
                "group_count": len(
                    {profile["group_id"] for profile in wave_profiles}
                ),
                "priority_counts": _complete_priority_counts(tier_counts),
                "command_ids": [
                    str(profile["command_id"])
                    for profile in wave_profiles
                ],
                "profiles": wave_profiles,
            }
        )

    gap_profile_ids = {
        str(record["profile_id"])
        for record in inventory["profiles"]
        if record["implementation_gap"]
    }
    if scheduled_profile_ids != gap_profile_ids:
        raise QualificationError(
            "Implementation roadmap does not cover every implementation gap"
        )

    flattened_profiles = [
        profile for wave in waves for profile in wave["profiles"]
    ]
    priority_counts = Counter(
        str(profile["priority_tier"])
        for profile in flattened_profiles
    )
    command_records = tuple(
        _command_record(
            command,
            command_eligibility[command.id],
            inventory_by_profile,
            waves,
        )
        for command in sorted(registry.commands, key=lambda item: item.id)
    )
    nonfixture_candidate_count = sum(
        candidate.lifecycle in {"development", "evaluation_candidate"}
        for candidate in candidates.candidates
    )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": (
            "implementation_roadmap_ready"
            if gap_profile_ids
            else "specialist_implementation_catalogued"
        ),
        "roadmap_effect": "none",
        "registry": _registry_binding(registry),
        "capability_catalog": _catalog_binding(
            capability_catalog.catalog_id,
            capability_catalog.catalog_version,
            capability_catalog.canonical_sha256,
        ),
        "routing_policy": _catalog_binding(
            policy.policy_id,
            policy.policy_version,
            policy.canonical_sha256,
        ),
        "qualification_standard": _catalog_binding(
            standard.standard_id,
            standard.standard_version,
            standard.canonical_sha256,
        ),
        "qualification_plan_catalog": _catalog_binding(
            plans.plan_catalog_id,
            plans.plan_catalog_version,
            plans.canonical_sha256,
        ),
        "candidate_blueprint_catalog": _catalog_binding(
            blueprints.blueprint_catalog_id,
            blueprints.blueprint_catalog_version,
            blueprints.canonical_sha256,
        ),
        "candidate_component_catalog": _catalog_binding(
            components.component_catalog_id,
            components.component_catalog_version,
            components.canonical_sha256,
        ),
        "candidate_catalog": _catalog_binding(
            candidates.candidate_catalog_id,
            candidates.candidate_catalog_version,
            candidates.canonical_sha256,
        ),
        "wave_policy": {
            "policy_id": WAVE_POLICY_ID,
            "maximum_profiles_per_wave": MAXIMUM_PROFILES_PER_WAVE,
            "maximum_profiles_per_command_per_wave": (
                MAXIMUM_PROFILES_PER_COMMAND_PER_WAVE
            ),
            "command_order": [
                "commands_without_policy_eligible_specialists_first",
                "fewest_policy_eligible_specialists_first",
                "command_id",
            ],
            "profile_order_within_command": [
                "policy_eligible_baseline_first",
                "profile_id",
            ],
            "priority_tiers": list(PRIORITY_TIERS),
            "build_sequence": list(BUILD_SEQUENCE),
        },
        "summary": {
            "group_count": len(registry.groups),
            "command_count": len(registry.commands),
            "specialist_count": len(specialists),
            "policy_eligible_specialist_count": sum(
                _policy_eligible(profile, policy)
                for profile in specialists
            ),
            "catalog_candidate_count": len(candidates.candidates),
            "nonfixture_candidate_count": nonfixture_candidate_count,
            "catalogued_component_artifact_count": len(
                components.components
            ),
            "implementation_gap_count": len(gap_profile_ids),
            "scheduled_profile_count": len(scheduled_profile_ids),
            "implemented_profile_count": (
                len(specialists) - len(gap_profile_ids)
            ),
            "wave_count": len(waves),
            "largest_wave_profile_count": max(
                (wave["profile_count"] for wave in waves),
                default=0,
            ),
            "commands_without_policy_eligible_specialists": sum(
                count == 0 for count in command_eligibility.values()
            ),
        },
        "priority_counts": _complete_priority_counts(priority_counts),
        "commands": list(command_records),
        "waves": waves,
        "limitations": [
            (
                "This roadmap schedules deterministic implementation work. "
                "It does not build, deploy, or execute a candidate."
            ),
            (
                "A wave position is a planning priority, not routing "
                "eligibility, qualification, execution authority, or proof "
                "of safety."
            ),
            (
                "The roadmap does not choose a provider, model, endpoint, "
                "tool, credential, evidence authority, reviewer, or target."
            ),
            (
                "Authoritative candidate qualification remains blocked by "
                "architecture decision D008. Component construction and "
                "advisory preflight can proceed independently."
            ),
            (
                "Every wave remains subject to domain commander review, "
                "independent Control review, and independent Assurance "
                "review before any separately authorized state transition."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return SpecialistImplementationRoadmapReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _roadmap_profile_record(
    profile: ExpertProfile,
    command: DomainCommand,
    inventory: dict[str, Any],
    policy: RoutingPolicy,
    command_eligible_count: int,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
) -> dict[str, Any]:
    eligible = _policy_eligible(profile, policy)
    if command_eligible_count == 0:
        tier = "command_coverage_gap"
    elif eligible:
        tier = "eligible_baseline_gap"
    else:
        tier = "army_depth_gap"
    blueprint = blueprints.blueprints_by_profile_id[profile.id]
    plan = plans.plans_by_profile_id[profile.id]
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "commander_profile_id": command.commander_profile_id,
        "registry_status": profile.status,
        "policy_eligible": eligible,
        "priority_tier": tier,
        "candidate_inventory_state": inventory[
            "candidate_inventory_state"
        ],
        "existing_candidates": [
            {
                "candidate_id": candidate["candidate_id"],
                "candidate_version": candidate["candidate_version"],
                "lifecycle": candidate["lifecycle"],
            }
            for candidate in inventory["candidates"]
        ],
        "candidate_blueprint_sha256": blueprint.blueprint_sha256,
        "scenario_family_id": plan.scenario_family_id,
        "required_gate_ids": list(plan.required_gate_ids),
        "required_component_ids": list(REQUIRED_COMPONENT_IDS),
        "component_build_ready": True,
        "authoritative_qualification_blocker": (
            f"{QUALIFICATION_AUTHORITY_DECISION}_pending"
        ),
    }


def _command_record(
    command: DomainCommand,
    policy_eligible_count: int,
    inventory_by_profile: dict[str, dict[str, Any]],
    waves: list[dict[str, Any]],
) -> dict[str, Any]:
    implementation_gap_ids = [
        profile_id
        for profile_id in command.specialist_profile_ids
        if inventory_by_profile[profile_id]["implementation_gap"]
    ]
    scheduled_waves = [
        int(wave["wave_number"])
        for wave in waves
        if command.id in wave["command_ids"]
    ]
    return {
        "command_id": command.id,
        "name": command.name,
        "group_id": command.group_id,
        "commander_profile_id": command.commander_profile_id,
        "specialist_count": len(command.specialist_profile_ids),
        "policy_eligible_specialist_count": policy_eligible_count,
        "implementation_gap_count": len(implementation_gap_ids),
        "implementation_gap_profile_ids": implementation_gap_ids,
        "scheduled_wave_numbers": scheduled_waves,
        "first_scheduled_wave": (
            scheduled_waves[0] if scheduled_waves else None
        ),
    }


def _policy_eligible(profile: ExpertProfile, policy: RoutingPolicy) -> bool:
    return (
        profile.status != "retired"
        and profile.status in policy.allowed_statuses
        and (not policy.require_pilot or profile.pilot)
    )


def _policy_eligible_count(
    command: DomainCommand,
    profiles_by_id: dict[str, ExpertProfile],
    policy: RoutingPolicy,
) -> int:
    return sum(
        _policy_eligible(profiles_by_id[profile_id], policy)
        for profile_id in command.specialist_profile_ids
    )


def _complete_priority_counts(counts: Counter[str]) -> dict[str, int]:
    return {
        str(tier["priority_tier"]): counts[str(tier["priority_tier"])]
        for tier in PRIORITY_TIERS
    }


def _registry_binding(registry: ExpertRegistry) -> dict[str, str]:
    return _catalog_binding(
        registry.catalog_id,
        registry.catalog_version,
        _canonical_sha256(registry.to_dict()),
    )


def _catalog_binding(
    identifier: str,
    version: str,
    sha256: str,
) -> dict[str, str]:
    return {"id": identifier, "version": version, "sha256": sha256}


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "IRR-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_specialist_implementation_roadmap(
    path: str | Path,
) -> SpecialistImplementationRoadmapReport:
    return SpecialistImplementationRoadmapReport.from_dict(
        _load_json(path, "specialist implementation roadmap report")
    )
