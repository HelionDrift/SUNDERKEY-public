"""Deterministic implementation blueprints for specialist candidates."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    PolicyTemplate,
)
from .routing import CapabilityCatalog, ProfileCapabilityAssignment
from .types import ProfileKind

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REPORT_ID_PATTERN = re.compile(r"CBR-[0-9A-F]{32}")
BLUEPRINT_DOMAIN = "sunderkey.candidate-blueprint.v1"
REPORT_DOMAIN = "sunderkey.candidate-blueprint-coverage-report.v1"
REPORT_SCHEMA_VERSION = 1
REQUIRED_COMPONENT_IDS = (
    "behavior_contract",
    "instruction_bundle",
    "knowledge_manifest",
    "runtime_manifest",
    "tool_policy",
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
    "allowed_actions",
    "prohibited_actions",
    "stop_conditions",
    "maximum_autonomous_action_tier",
    "minimum_evidence_level",
    "primary_capability_ids",
    "supporting_capability_ids",
    "scenario_family_id",
    "evaluation_objective",
    "required_gate_ids",
    "command_mission",
    "expected_inputs",
    "expected_outputs",
    "collaboration_contract",
    "command_boundary",
}


def _sha256(value: Any, label: str) -> str:
    digest = _text(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return digest


def _text_tuple(value: Any, label: str) -> tuple[str, ...]:
    result = tuple(
        _text(item, f"{label}[{index}]")
        for index, item in enumerate(_list(value, label))
    )
    if len(result) != len(set(result)):
        raise QualificationError(f"{label} contains duplicate values")
    return result


def compute_candidate_blueprint_sha256(
    blueprint_body: dict[str, Any],
) -> str:
    """Compute the content identity of one closed blueprint body."""

    return _canonical_sha256(
        {
            "domain": BLUEPRINT_DOMAIN,
            "blueprint": blueprint_body,
        }
    )


@dataclass(frozen=True)
class SpecialistCandidateBlueprint:
    profile_id: str
    blueprint_sha256: str
    body_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> SpecialistCandidateBlueprint:
        label = f"blueprints[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {*BLUEPRINT_FIELDS, "blueprint_sha256"},
            label,
        )
        body = {
            "profile_id": _text(
                value.get("profile_id"),
                f"{label}.profile_id",
            ),
            "profile_version": _text(
                value.get("profile_version"),
                f"{label}.profile_version",
            ),
            "name": _text(value.get("name"), f"{label}.name"),
            "group_id": _text(
                value.get("group_id"),
                f"{label}.group_id",
            ),
            "command_id": _text(
                value.get("command_id"),
                f"{label}.command_id",
            ),
            "category": _text(
                value.get("category"),
                f"{label}.category",
            ),
            "mission": _text(value.get("mission"), f"{label}.mission"),
            "policy_template_id": _text(
                value.get("policy_template_id"),
                f"{label}.policy_template_id",
            ),
            "allowed_actions": list(
                _text_tuple(
                    value.get("allowed_actions"),
                    f"{label}.allowed_actions",
                )
            ),
            "prohibited_actions": list(
                _text_tuple(
                    value.get("prohibited_actions"),
                    f"{label}.prohibited_actions",
                )
            ),
            "stop_conditions": list(
                _text_tuple(
                    value.get("stop_conditions"),
                    f"{label}.stop_conditions",
                )
            ),
            "maximum_autonomous_action_tier": _text(
                value.get("maximum_autonomous_action_tier"),
                f"{label}.maximum_autonomous_action_tier",
            ),
            "minimum_evidence_level": _text(
                value.get("minimum_evidence_level"),
                f"{label}.minimum_evidence_level",
            ),
            "primary_capability_ids": list(
                _text_tuple(
                    value.get("primary_capability_ids"),
                    f"{label}.primary_capability_ids",
                )
            ),
            "supporting_capability_ids": list(
                _text_tuple(
                    value.get("supporting_capability_ids"),
                    f"{label}.supporting_capability_ids",
                )
            ),
            "scenario_family_id": _text(
                value.get("scenario_family_id"),
                f"{label}.scenario_family_id",
            ),
            "evaluation_objective": _text(
                value.get("evaluation_objective"),
                f"{label}.evaluation_objective",
            ),
            "required_gate_ids": list(
                _text_tuple(
                    value.get("required_gate_ids"),
                    f"{label}.required_gate_ids",
                )
            ),
            "command_mission": _text(
                value.get("command_mission"),
                f"{label}.command_mission",
            ),
            "expected_inputs": _text(
                value.get("expected_inputs"),
                f"{label}.expected_inputs",
            ),
            "expected_outputs": _text(
                value.get("expected_outputs"),
                f"{label}.expected_outputs",
            ),
            "collaboration_contract": _text(
                value.get("collaboration_contract"),
                f"{label}.collaboration_contract",
            ),
            "command_boundary": _text(
                value.get("command_boundary"),
                f"{label}.command_boundary",
            ),
        }
        blueprint_hash = _sha256(
            value.get("blueprint_sha256"),
            f"{label}.blueprint_sha256",
        )
        if blueprint_hash != compute_candidate_blueprint_sha256(body):
            raise QualificationError(
                f"{label}.blueprint_sha256 is invalid"
            )
        return cls(
            profile_id=str(body["profile_id"]),
            blueprint_sha256=blueprint_hash,
            body_json=_canonical_json(body),
        )

    def body(self) -> dict[str, Any]:
        value = json.loads(self.body_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate blueprint body is invalid")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "blueprint_sha256": self.blueprint_sha256,
        }


@dataclass(frozen=True)
class CandidateBlueprintCatalog:
    schema_version: int
    blueprint_catalog_id: str
    blueprint_catalog_version: str
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
    required_component_ids: tuple[str, ...]
    blueprints: tuple[SpecialistCandidateBlueprint, ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @property
    def blueprints_by_profile_id(
        self,
    ) -> dict[str, SpecialistCandidateBlueprint]:
        return {blueprint.profile_id: blueprint for blueprint in self.blueprints}

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        capability_catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> CandidateBlueprintCatalog:
        value = _mapping(raw, "candidate blueprint catalog")
        _exact_fields(
            value,
            {
                "schema_version",
                "blueprint_catalog_id",
                "blueprint_catalog_version",
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
                "required_component_ids",
                "blueprints",
            },
            "candidate blueprint catalog",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Candidate blueprint catalog schema_version must be 1"
            )
        required_component_ids = _text_tuple(
            value.get("required_component_ids"),
            "required_component_ids",
        )
        if required_component_ids != REQUIRED_COMPONENT_IDS:
            raise QualificationError(
                "Candidate blueprint required components are invalid"
            )
        blueprints = tuple(
            sorted(
                (
                    SpecialistCandidateBlueprint.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("blueprints"), "blueprints")
                    )
                ),
                key=lambda blueprint: blueprint.profile_id,
            )
        )
        blueprint_catalog = cls(
            schema_version=1,
            blueprint_catalog_id=_text(
                value.get("blueprint_catalog_id"),
                "blueprint_catalog_id",
            ),
            blueprint_catalog_version=_text(
                value.get("blueprint_catalog_version"),
                "blueprint_catalog_version",
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
            required_component_ids=required_component_ids,
            blueprints=blueprints,
        )
        blueprint_catalog._validate_relations(
            registry,
            capability_catalog,
            standard,
            plans,
        )
        return blueprint_catalog

    def revalidated(
        self,
        registry: ExpertRegistry,
        capability_catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> CandidateBlueprintCatalog:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed candidate blueprint catalog"
            ) from exc
        return CandidateBlueprintCatalog.from_dict(
            raw,
            registry,
            capability_catalog,
            standard,
            plans,
        )

    def _validate_relations(
        self,
        registry: ExpertRegistry,
        capability_catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> None:
        expected_binding = (
            registry.catalog_id,
            registry.catalog_version,
            capability_catalog.catalog_id,
            capability_catalog.catalog_version,
            capability_catalog.canonical_sha256,
            standard.standard_id,
            standard.standard_version,
            standard.canonical_sha256,
            plans.plan_catalog_id,
            plans.plan_catalog_version,
            plans.canonical_sha256,
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
        )
        if actual_binding != expected_binding:
            raise QualificationError(
                "Candidate blueprint catalog binding is invalid"
            )
        specialist_ids = {
            profile.id
            for profile in registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        }
        blueprint_ids = [blueprint.profile_id for blueprint in self.blueprints]
        if len(blueprint_ids) != len(set(blueprint_ids)):
            raise QualificationError(
                "Candidate blueprint catalog contains duplicate profiles"
            )
        if set(blueprint_ids) != specialist_ids:
            raise QualificationError(
                "Candidate blueprints must match all specialists"
            )
        policies = {policy.id: policy for policy in registry.policies}
        for blueprint in self.blueprints:
            profile = registry.profiles_by_id[blueprint.profile_id]
            command = registry.commands_by_id[str(profile.command_id)]
            policy = policies[profile.policy_template]
            assignment = capability_catalog.assignments_by_profile_id[
                profile.id
            ]
            plan = plans.plans_by_profile_id[profile.id]
            expected_body = _expected_blueprint_body(
                profile,
                command,
                policy,
                assignment,
                plan.to_dict(),
            )
            if blueprint.body() != expected_body:
                raise QualificationError(
                    "Candidate blueprint does not match reviewed inputs: "
                    f"{profile.id}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "blueprint_catalog_id": self.blueprint_catalog_id,
            "blueprint_catalog_version": self.blueprint_catalog_version,
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
            "required_component_ids": list(self.required_component_ids),
            "blueprints": [blueprint.to_dict() for blueprint in self.blueprints],
        }


@dataclass(frozen=True)
class CandidateBlueprintCoverageReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateBlueprintCoverageReport:
        value = _mapping(raw, "candidate blueprint coverage report")
        expected = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "blueprint_effect",
            "registry",
            "capability_catalog",
            "qualification_standard",
            "qualification_plan_catalog",
            "blueprint_catalog",
            "summary",
            "groups",
            "commands",
            "profiles",
            "limitations",
        }
        _exact_fields(value, expected, "candidate blueprint coverage report")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Candidate blueprint coverage report schema version is invalid"
            )
        report_id = value.get("report_id")
        report_hash = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_hash, str)
        ):
            raise QualificationError(
                "Candidate blueprint coverage report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_hash != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError(
                "Candidate blueprint coverage report hash is invalid"
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
                "Candidate blueprint coverage report document is invalid"
            )
        return value


def assess_candidate_blueprint_coverage(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
) -> CandidateBlueprintCoverageReport:
    """Assess exact blueprint coverage without creating candidates."""

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
    by_profile = blueprints.blueprints_by_profile_id
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
        {
            "profile_id": profile.id,
            "name": profile.name,
            "group_id": profile.group_id,
            "command_id": profile.command_id,
            "blueprint_sha256": by_profile[profile.id].blueprint_sha256,
            "primary_capability_ids": list(
                capability_catalog.assignments_by_profile_id[
                    profile.id
                ].primary_capability_ids
            ),
            "scenario_family_id": plans.plans_by_profile_id[
                profile.id
            ].scenario_family_id,
            "required_component_ids": list(REQUIRED_COMPONENT_IDS),
        }
        for profile in specialists
    )
    command_records = tuple(
        _command_record(command)
        for command in sorted(registry.commands, key=lambda item: item.id)
    )
    commands_by_id = {
        str(record["command_id"]): record for record in command_records
    }
    group_records = tuple(
        _group_record(group, commands_by_id)
        for group in sorted(registry.groups, key=lambda item: item.id)
    )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "blueprint_coverage_complete",
        "blueprint_effect": "none",
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
        "blueprint_catalog": {
            "id": blueprints.blueprint_catalog_id,
            "version": blueprints.blueprint_catalog_version,
            "sha256": blueprints.canonical_sha256,
        },
        "summary": {
            "group_count": len(group_records),
            "command_count": len(command_records),
            "specialist_count": len(profile_records),
            "blueprint_count": len(blueprints.blueprints),
            "required_component_count_per_blueprint": len(
                REQUIRED_COMPONENT_IDS
            ),
            "total_component_requirement_count": (
                len(profile_records) * len(REQUIRED_COMPONENT_IDS)
            ),
        },
        "groups": list(group_records),
        "commands": list(command_records),
        "profiles": list(profile_records),
        "limitations": [
            (
                "A blueprint is a deterministic build contract, not a "
                "candidate implementation or deployment."
            ),
            (
                "Blueprint coverage does not establish technical quality, "
                "qualification, routing eligibility, or authority."
            ),
            (
                "The catalog selects no provider, model, endpoint, tool, "
                "credential, target, or execution environment."
            ),
            (
                "This report does not dispatch work, mutate state, connect "
                "to a tool, or execute an action."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return CandidateBlueprintCoverageReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _expected_blueprint_body(
    profile: ExpertProfile,
    command: DomainCommand,
    policy: PolicyTemplate,
    assignment: ProfileCapabilityAssignment,
    plan: dict[str, Any],
) -> dict[str, Any]:
    return {
        "profile_id": profile.id,
        "profile_version": profile.version,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "category": profile.category,
        "mission": profile.mission,
        "policy_template_id": policy.id,
        "allowed_actions": list(policy.may),
        "prohibited_actions": list(policy.may_not),
        "stop_conditions": list(policy.stop_conditions),
        "maximum_autonomous_action_tier": profile.max_autonomous_tier.value,
        "minimum_evidence_level": profile.minimum_evidence_level.value,
        "primary_capability_ids": list(assignment.primary_capability_ids),
        "supporting_capability_ids": list(
            assignment.supporting_capability_ids
        ),
        "scenario_family_id": plan["scenario_family_id"],
        "evaluation_objective": plan["evaluation_objective"],
        "required_gate_ids": list(plan["required_gate_ids"]),
        "command_mission": command.mission,
        "expected_inputs": command.inputs,
        "expected_outputs": command.outputs,
        "collaboration_contract": command.collaboration,
        "command_boundary": command.boundary,
    }


def _command_record(command: DomainCommand) -> dict[str, Any]:
    count = len(command.specialist_profile_ids)
    return {
        "command_id": command.id,
        "name": command.name,
        "group_id": command.group_id,
        "specialist_count": count,
        "blueprint_count": count,
        "total_component_requirement_count": (
            count * len(REQUIRED_COMPONENT_IDS)
        ),
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
        "blueprint_count": sum(
            int(record["blueprint_count"]) for record in records
        ),
        "total_component_requirement_count": sum(
            int(record["total_component_requirement_count"])
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
    return "CBR-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_candidate_blueprint_catalog(
    path: str | Path,
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
) -> CandidateBlueprintCatalog:
    return CandidateBlueprintCatalog.from_dict(
        _load_json(path, "candidate blueprint catalog"),
        registry,
        capability_catalog,
        standard,
        plans,
    )
