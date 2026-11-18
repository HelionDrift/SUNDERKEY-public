"""Provider-neutral specialist candidate implementation inventory."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_blueprints import CandidateBlueprintCatalog
from .errors import QualificationError
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _list,
    _load_json,
    _mapping,
    _text,
)
from .registry import (
    DomainCommand,
    ExpertProfile,
    ExpertRegistry,
    ManeuverGroup,
)
from .routing import CapabilityCatalog
from .types import ProfileKind

CANDIDATE_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REPORT_ID_PATTERN = re.compile(r"CIR-[0-9A-F]{32}")
CANDIDATE_ARTIFACT_DOMAIN = "sunderkey.candidate-implementation.v1"
REPORT_DOMAIN = "sunderkey.candidate-inventory-report.v1"
REPORT_SCHEMA_VERSION = 1
CANDIDATE_LIFECYCLES = {
    "contract_fixture",
    "development",
    "evaluation_candidate",
    "retired",
}
IMPLEMENTATION_KINDS = {
    "agent_bundle",
    "human_runbook",
    "hybrid_bundle",
}


def _sha256(value: Any, label: str) -> str:
    digest = _text(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return digest


def compute_candidate_artifact_sha256(
    candidate_body: dict[str, Any],
) -> str:
    """Compute the artifact identity for a closed candidate body."""

    return _canonical_sha256(
        {
            "domain": CANDIDATE_ARTIFACT_DOMAIN,
            "candidate": candidate_body,
        }
    )


@dataclass(frozen=True)
class SpecialistCandidateImplementation:
    candidate_id: str
    candidate_version: str
    profile_id: str
    lifecycle: str
    implementation_kind: str
    candidate_blueprint_sha256: str
    behavior_contract_sha256: str
    instruction_bundle_sha256: str
    knowledge_manifest_sha256: str
    runtime_manifest_sha256: str
    tool_policy_sha256: str
    candidate_artifact_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> SpecialistCandidateImplementation:
        label = f"candidates[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "candidate_id",
                "candidate_version",
                "profile_id",
                "lifecycle",
                "implementation_kind",
                "candidate_blueprint_sha256",
                "behavior_contract_sha256",
                "instruction_bundle_sha256",
                "knowledge_manifest_sha256",
                "runtime_manifest_sha256",
                "tool_policy_sha256",
                "candidate_artifact_sha256",
            },
            label,
        )
        candidate_id = _text(
            value.get("candidate_id"),
            f"{label}.candidate_id",
        )
        if CANDIDATE_ID_PATTERN.fullmatch(candidate_id) is None:
            raise QualificationError(
                f"Invalid specialist candidate ID: {candidate_id}"
            )
        lifecycle = _text(value.get("lifecycle"), f"{label}.lifecycle")
        if lifecycle not in CANDIDATE_LIFECYCLES:
            options = ", ".join(sorted(CANDIDATE_LIFECYCLES))
            raise QualificationError(
                f"{label}.lifecycle must be one of: {options}"
            )
        implementation_kind = _text(
            value.get("implementation_kind"),
            f"{label}.implementation_kind",
        )
        if implementation_kind not in IMPLEMENTATION_KINDS:
            options = ", ".join(sorted(IMPLEMENTATION_KINDS))
            raise QualificationError(
                f"{label}.implementation_kind must be one of: {options}"
            )
        candidate = cls(
            candidate_id=candidate_id,
            candidate_version=_text(
                value.get("candidate_version"),
                f"{label}.candidate_version",
            ),
            profile_id=_text(
                value.get("profile_id"),
                f"{label}.profile_id",
            ),
            lifecycle=lifecycle,
            implementation_kind=implementation_kind,
            candidate_blueprint_sha256=_sha256(
                value.get("candidate_blueprint_sha256"),
                f"{label}.candidate_blueprint_sha256",
            ),
            behavior_contract_sha256=_sha256(
                value.get("behavior_contract_sha256"),
                f"{label}.behavior_contract_sha256",
            ),
            instruction_bundle_sha256=_sha256(
                value.get("instruction_bundle_sha256"),
                f"{label}.instruction_bundle_sha256",
            ),
            knowledge_manifest_sha256=_sha256(
                value.get("knowledge_manifest_sha256"),
                f"{label}.knowledge_manifest_sha256",
            ),
            runtime_manifest_sha256=_sha256(
                value.get("runtime_manifest_sha256"),
                f"{label}.runtime_manifest_sha256",
            ),
            tool_policy_sha256=_sha256(
                value.get("tool_policy_sha256"),
                f"{label}.tool_policy_sha256",
            ),
            candidate_artifact_sha256=_sha256(
                value.get("candidate_artifact_sha256"),
                f"{label}.candidate_artifact_sha256",
            ),
        )
        if (
            candidate.candidate_artifact_sha256
            != compute_candidate_artifact_sha256(candidate.artifact_body())
        ):
            raise QualificationError(
                f"{label}.candidate_artifact_sha256 is invalid"
            )
        return candidate

    def artifact_body(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "profile_id": self.profile_id,
            "lifecycle": self.lifecycle,
            "implementation_kind": self.implementation_kind,
            "candidate_blueprint_sha256": (
                self.candidate_blueprint_sha256
            ),
            "behavior_contract_sha256": self.behavior_contract_sha256,
            "instruction_bundle_sha256": self.instruction_bundle_sha256,
            "knowledge_manifest_sha256": self.knowledge_manifest_sha256,
            "runtime_manifest_sha256": self.runtime_manifest_sha256,
            "tool_policy_sha256": self.tool_policy_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.artifact_body(),
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
        }


@dataclass(frozen=True)
class CandidateImplementationCatalog:
    schema_version: int
    candidate_catalog_id: str
    candidate_catalog_version: str
    expert_catalog_id: str
    expert_catalog_version: str
    capability_catalog_id: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    qualification_standard_id: str
    qualification_standard_version: str
    qualification_standard_sha256: str
    qualification_plan_catalog_id: str
    qualification_plan_catalog_version: str
    qualification_plan_catalog_sha256: str
    candidate_blueprint_catalog_id: str
    candidate_blueprint_catalog_version: str
    candidate_blueprint_catalog_sha256: str
    candidates: tuple[SpecialistCandidateImplementation, ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @property
    def candidates_by_id(
        self,
    ) -> dict[str, SpecialistCandidateImplementation]:
        return {candidate.candidate_id: candidate for candidate in self.candidates}

    @property
    def candidates_by_profile_id(
        self,
    ) -> dict[str, tuple[SpecialistCandidateImplementation, ...]]:
        result: dict[str, list[SpecialistCandidateImplementation]] = {}
        for candidate in self.candidates:
            result.setdefault(candidate.profile_id, []).append(candidate)
        return {
            profile_id: tuple(candidates)
            for profile_id, candidates in result.items()
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
        blueprints: CandidateBlueprintCatalog,
    ) -> CandidateImplementationCatalog:
        value = _mapping(raw, "candidate implementation catalog")
        _exact_fields(
            value,
            {
                "schema_version",
                "candidate_catalog_id",
                "candidate_catalog_version",
                "expert_catalog_id",
                "expert_catalog_version",
                "capability_catalog_id",
                "capability_catalog_version",
                "capability_catalog_sha256",
                "qualification_standard_id",
                "qualification_standard_version",
                "qualification_standard_sha256",
                "qualification_plan_catalog_id",
                "qualification_plan_catalog_version",
                "qualification_plan_catalog_sha256",
                "candidate_blueprint_catalog_id",
                "candidate_blueprint_catalog_version",
                "candidate_blueprint_catalog_sha256",
                "candidates",
            },
            "candidate implementation catalog",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Candidate implementation catalog schema_version must be 1"
            )
        candidates = tuple(
            sorted(
                (
                    SpecialistCandidateImplementation.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("candidates"), "candidates")
                    )
                ),
                key=lambda candidate: (
                    candidate.profile_id,
                    candidate.candidate_id,
                    candidate.candidate_version,
                ),
            )
        )
        candidate_catalog = cls(
            schema_version=1,
            candidate_catalog_id=_text(
                value.get("candidate_catalog_id"),
                "candidate_catalog_id",
            ),
            candidate_catalog_version=_text(
                value.get("candidate_catalog_version"),
                "candidate_catalog_version",
            ),
            expert_catalog_id=_text(
                value.get("expert_catalog_id"),
                "expert_catalog_id",
            ),
            expert_catalog_version=_text(
                value.get("expert_catalog_version"),
                "expert_catalog_version",
            ),
            capability_catalog_id=_text(
                value.get("capability_catalog_id"),
                "capability_catalog_id",
            ),
            capability_catalog_version=_text(
                value.get("capability_catalog_version"),
                "capability_catalog_version",
            ),
            capability_catalog_sha256=_sha256(
                value.get("capability_catalog_sha256"),
                "capability_catalog_sha256",
            ),
            qualification_standard_id=_text(
                value.get("qualification_standard_id"),
                "qualification_standard_id",
            ),
            qualification_standard_version=_text(
                value.get("qualification_standard_version"),
                "qualification_standard_version",
            ),
            qualification_standard_sha256=_sha256(
                value.get("qualification_standard_sha256"),
                "qualification_standard_sha256",
            ),
            qualification_plan_catalog_id=_text(
                value.get("qualification_plan_catalog_id"),
                "qualification_plan_catalog_id",
            ),
            qualification_plan_catalog_version=_text(
                value.get("qualification_plan_catalog_version"),
                "qualification_plan_catalog_version",
            ),
            qualification_plan_catalog_sha256=_sha256(
                value.get("qualification_plan_catalog_sha256"),
                "qualification_plan_catalog_sha256",
            ),
            candidate_blueprint_catalog_id=_text(
                value.get("candidate_blueprint_catalog_id"),
                "candidate_blueprint_catalog_id",
            ),
            candidate_blueprint_catalog_version=_text(
                value.get("candidate_blueprint_catalog_version"),
                "candidate_blueprint_catalog_version",
            ),
            candidate_blueprint_catalog_sha256=_sha256(
                value.get("candidate_blueprint_catalog_sha256"),
                "candidate_blueprint_catalog_sha256",
            ),
            candidates=candidates,
        )
        candidate_catalog._validate_relations(
            registry,
            catalog,
            standard,
            plans,
            blueprints,
        )
        return candidate_catalog

    def revalidated(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
        blueprints: CandidateBlueprintCatalog,
    ) -> CandidateImplementationCatalog:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed candidate catalog"
            ) from exc
        return CandidateImplementationCatalog.from_dict(
            raw,
            registry,
            catalog,
            standard,
            plans,
            blueprints,
        )

    def _validate_relations(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
        blueprints: CandidateBlueprintCatalog,
    ) -> None:
        expected_binding = (
            registry.catalog_id,
            registry.catalog_version,
            catalog.catalog_id,
            catalog.catalog_version,
            catalog.canonical_sha256,
            standard.standard_id,
            standard.standard_version,
            standard.canonical_sha256,
            plans.plan_catalog_id,
            plans.plan_catalog_version,
            plans.canonical_sha256,
            blueprints.blueprint_catalog_id,
            blueprints.blueprint_catalog_version,
            blueprints.canonical_sha256,
        )
        actual_binding = (
            self.expert_catalog_id,
            self.expert_catalog_version,
            self.capability_catalog_id,
            self.capability_catalog_version,
            self.capability_catalog_sha256,
            self.qualification_standard_id,
            self.qualification_standard_version,
            self.qualification_standard_sha256,
            self.qualification_plan_catalog_id,
            self.qualification_plan_catalog_version,
            self.qualification_plan_catalog_sha256,
            self.candidate_blueprint_catalog_id,
            self.candidate_blueprint_catalog_version,
            self.candidate_blueprint_catalog_sha256,
        )
        if actual_binding != expected_binding:
            raise QualificationError(
                "Candidate implementation catalog binding is invalid"
            )
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise QualificationError(
                "Candidate implementation catalog contains duplicate "
                "candidate IDs"
            )
        profiles = registry.profiles_by_id
        blueprints_by_profile = blueprints.blueprints_by_profile_id
        for candidate in self.candidates:
            profile = profiles.get(candidate.profile_id)
            if profile is None or profile.kind is not ProfileKind.SPECIALIST:
                raise QualificationError(
                    "Candidate implementation must reference a specialist: "
                    f"{candidate.candidate_id}"
                )
            if candidate.profile_id not in plans.plans_by_profile_id:
                raise QualificationError(
                    "Candidate implementation profile is not planned: "
                    f"{candidate.candidate_id}"
                )
            if (
                candidate.candidate_blueprint_sha256
                != blueprints_by_profile[
                    candidate.profile_id
                ].blueprint_sha256
            ):
                raise QualificationError(
                    "Candidate implementation blueprint binding is invalid: "
                    f"{candidate.candidate_id}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_catalog_id": self.candidate_catalog_id,
            "candidate_catalog_version": self.candidate_catalog_version,
            "expert_catalog_id": self.expert_catalog_id,
            "expert_catalog_version": self.expert_catalog_version,
            "capability_catalog_id": self.capability_catalog_id,
            "capability_catalog_version": self.capability_catalog_version,
            "capability_catalog_sha256": self.capability_catalog_sha256,
            "qualification_standard_id": self.qualification_standard_id,
            "qualification_standard_version": (
                self.qualification_standard_version
            ),
            "qualification_standard_sha256": (
                self.qualification_standard_sha256
            ),
            "qualification_plan_catalog_id": (
                self.qualification_plan_catalog_id
            ),
            "qualification_plan_catalog_version": (
                self.qualification_plan_catalog_version
            ),
            "qualification_plan_catalog_sha256": (
                self.qualification_plan_catalog_sha256
            ),
            "candidate_blueprint_catalog_id": (
                self.candidate_blueprint_catalog_id
            ),
            "candidate_blueprint_catalog_version": (
                self.candidate_blueprint_catalog_version
            ),
            "candidate_blueprint_catalog_sha256": (
                self.candidate_blueprint_catalog_sha256
            ),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


@dataclass(frozen=True)
class CandidateInventoryReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateInventoryReport:
        value = _mapping(raw, "candidate inventory report")
        expected = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "inventory_effect",
            "registry",
            "capability_catalog",
            "qualification_standard",
            "qualification_plan_catalog",
            "candidate_blueprint_catalog",
            "candidate_catalog",
            "summary",
            "groups",
            "commands",
            "profiles",
            "limitations",
        }
        _exact_fields(value, expected, "candidate inventory report")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Candidate inventory report schema version is invalid"
            )
        report_id = value.get("report_id")
        report_hash = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_hash, str)
        ):
            raise QualificationError(
                "Candidate inventory report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_hash != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError(
                "Candidate inventory report hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_hash,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Candidate inventory report document is invalid"
            )
        return value


def assess_candidate_inventory(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
    candidate_catalog: CandidateImplementationCatalog,
) -> CandidateInventoryReport:
    """Project candidate implementation gaps without executing candidates."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(standard, QualificationStandard):
        raise QualificationError(
            "standard must be a QualificationStandard"
        )
    if not isinstance(plans, QualificationPlanCatalog):
        raise QualificationError(
            "plans must be a QualificationPlanCatalog"
        )
    if not isinstance(blueprints, CandidateBlueprintCatalog):
        raise QualificationError(
            "blueprints must be a CandidateBlueprintCatalog"
        )
    if not isinstance(candidate_catalog, CandidateImplementationCatalog):
        raise QualificationError(
            "candidate_catalog must be a CandidateImplementationCatalog"
        )
    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
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
    candidate_catalog = candidate_catalog.revalidated(
        registry,
        capability_catalog,
        standard,
        plans,
        blueprints,
    )
    candidates_by_profile = candidate_catalog.candidates_by_profile_id
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
    profile_records = tuple(
        _profile_record(
            profile,
            candidates_by_profile.get(profile.id, ()),
            capability_catalog,
            plans,
        )
        for profile in specialists
    )
    profiles_by_id = {
        str(record["profile_id"]): record for record in profile_records
    }
    command_records = tuple(
        _command_record(command, profiles_by_id)
        for command in sorted(registry.commands, key=lambda item: item.id)
    )
    commands_by_id = {
        str(record["command_id"]): record for record in command_records
    }
    group_records = tuple(
        _group_record(group, commands_by_id)
        for group in sorted(registry.groups, key=lambda item: item.id)
    )
    lifecycle_counts = Counter(
        candidate.lifecycle for candidate in candidate_catalog.candidates
    )
    profile_state_counts = Counter(
        str(record["candidate_inventory_state"])
        for record in profile_records
    )
    implementation_gap_count = sum(
        bool(record["implementation_gap"]) for record in profile_records
    )
    status = (
        "candidate_implementation_catalogued"
        if implementation_gap_count == 0
        else "candidate_implementation_incomplete"
    )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": status,
        "inventory_effect": "none",
        "registry": {
            "id": registry.catalog_id,
            "version": registry.catalog_version,
            "sha256": _canonical_sha256(registry.to_dict()),
        },
        "capability_catalog": {
            "id": capability_catalog.catalog_id,
            "version": capability_catalog.catalog_version,
            "sha256": capability_catalog.canonical_sha256,
        },
        "qualification_standard": {
            "id": standard.standard_id,
            "version": standard.standard_version,
            "sha256": standard.canonical_sha256,
        },
        "qualification_plan_catalog": {
            "id": plans.plan_catalog_id,
            "version": plans.plan_catalog_version,
            "sha256": plans.canonical_sha256,
        },
        "candidate_blueprint_catalog": {
            "id": blueprints.blueprint_catalog_id,
            "version": blueprints.blueprint_catalog_version,
            "sha256": blueprints.canonical_sha256,
        },
        "candidate_catalog": {
            "id": candidate_catalog.candidate_catalog_id,
            "version": candidate_catalog.candidate_catalog_version,
            "sha256": candidate_catalog.canonical_sha256,
        },
        "summary": {
            "group_count": len(group_records),
            "command_count": len(command_records),
            "specialist_count": len(profile_records),
            "catalog_candidate_count": len(candidate_catalog.candidates),
            "contract_fixture_candidate_count": lifecycle_counts[
                "contract_fixture"
            ],
            "development_candidate_count": lifecycle_counts["development"],
            "evaluation_candidate_count": lifecycle_counts[
                "evaluation_candidate"
            ],
            "retired_candidate_count": lifecycle_counts["retired"],
            "profiles_with_any_candidate": sum(
                int(record["candidate_count"] > 0)
                for record in profile_records
            ),
            "profiles_with_nonfixture_candidates": sum(
                int(record["nonfixture_candidate_count"] > 0)
                for record in profile_records
            ),
            "profiles_with_contract_fixture_only": profile_state_counts[
                "contract_fixture_only"
            ],
            "profiles_with_retired_candidates_only": profile_state_counts[
                "retired_candidates_only"
            ],
            "profiles_without_candidates": profile_state_counts[
                "candidate_missing"
            ],
            "profile_implementation_gap_count": implementation_gap_count,
            "commands_with_nonfixture_candidates": sum(
                int(record["nonfixture_candidate_count"] > 0)
                for record in command_records
            ),
            "commands_with_implementation_gaps": sum(
                int(record["implementation_gap_count"] > 0)
                for record in command_records
            ),
        },
        "groups": list(group_records),
        "commands": list(command_records),
        "profiles": list(profile_records),
        "limitations": [
            (
                "A catalog entry is a content-addressed candidate "
                "definition, not proof that an implementation is deployed."
            ),
            (
                "Development and evaluation candidate lifecycle labels do "
                "not establish qualification, routing eligibility, or "
                "execution authority."
            ),
            (
                "Component digests provide deterministic bindings but do "
                "not establish provenance, ownership, safety, or quality."
            ),
            (
                "This report does not call a model, connect to a provider "
                "or tool, dispatch work, mutate state, or execute an action."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return CandidateInventoryReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _profile_record(
    profile: ExpertProfile,
    candidates: tuple[SpecialistCandidateImplementation, ...],
    capability_catalog: CapabilityCatalog,
    plans: QualificationPlanCatalog,
) -> dict[str, Any]:
    lifecycle_counts = Counter(candidate.lifecycle for candidate in candidates)
    nonfixture = tuple(
        candidate
        for candidate in candidates
        if candidate.lifecycle in {"development", "evaluation_candidate"}
    )
    if lifecycle_counts["evaluation_candidate"]:
        state = "evaluation_candidate_catalogued"
    elif lifecycle_counts["development"]:
        state = "development_candidate_catalogued"
    elif lifecycle_counts["contract_fixture"]:
        state = "contract_fixture_only"
    elif lifecycle_counts["retired"]:
        state = "retired_candidates_only"
    else:
        state = "candidate_missing"
    assignment = capability_catalog.assignments_by_profile_id[profile.id]
    plan = plans.plans_by_profile_id[profile.id]
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "registry_status": profile.status,
        "primary_capability_ids": list(assignment.primary_capability_ids),
        "scenario_family_id": plan.scenario_family_id,
        "candidate_count": len(candidates),
        "nonfixture_candidate_count": len(nonfixture),
        "contract_fixture_candidate_count": lifecycle_counts[
            "contract_fixture"
        ],
        "development_candidate_count": lifecycle_counts["development"],
        "evaluation_candidate_count": lifecycle_counts[
            "evaluation_candidate"
        ],
        "retired_candidate_count": lifecycle_counts["retired"],
        "implementation_gap": not nonfixture,
        "candidate_inventory_state": state,
        "candidates": [candidate.to_dict() for candidate in candidates],
    }


def _command_record(
    command: DomainCommand,
    profiles_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    records = tuple(
        profiles_by_id[profile_id]
        for profile_id in command.specialist_profile_ids
    )
    gap_ids = tuple(
        str(record["profile_id"])
        for record in records
        if record["implementation_gap"]
    )
    return {
        "command_id": command.id,
        "name": command.name,
        "group_id": command.group_id,
        "specialist_count": len(records),
        "candidate_count": sum(
            int(record["candidate_count"]) for record in records
        ),
        "nonfixture_candidate_count": sum(
            int(record["nonfixture_candidate_count"])
            for record in records
        ),
        "profiles_with_nonfixture_candidates": sum(
            int(record["nonfixture_candidate_count"] > 0)
            for record in records
        ),
        "implementation_gap_count": len(gap_ids),
        "implementation_gap_profile_ids": list(gap_ids),
    }


def _group_record(
    group: ManeuverGroup,
    commands_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    records = tuple(
        commands_by_id[command_id] for command_id in group.command_ids
    )
    return {
        "group_id": group.id,
        "name": group.name,
        "command_count": len(records),
        "specialist_count": sum(
            int(record["specialist_count"]) for record in records
        ),
        "candidate_count": sum(
            int(record["candidate_count"]) for record in records
        ),
        "nonfixture_candidate_count": sum(
            int(record["nonfixture_candidate_count"])
            for record in records
        ),
        "profiles_with_nonfixture_candidates": sum(
            int(record["profiles_with_nonfixture_candidates"])
            for record in records
        ),
        "implementation_gap_count": sum(
            int(record["implementation_gap_count"])
            for record in records
        ),
    }


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "CIR-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_candidate_implementation_catalog(
    path: str | Path,
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
) -> CandidateImplementationCatalog:
    return CandidateImplementationCatalog.from_dict(
        _load_json(path, "candidate implementation catalog"),
        registry,
        capability_catalog,
        standard,
        plans,
        blueprints,
    )
