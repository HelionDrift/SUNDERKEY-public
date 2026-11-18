"""Provider-neutral component manifests and candidate onboarding checks."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_blueprints import (
    REQUIRED_COMPONENT_IDS,
    CandidateBlueprintCatalog,
    SpecialistCandidateBlueprint,
)
from .candidate_inventory import (
    CandidateImplementationCatalog,
    SpecialistCandidateImplementation,
)
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
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
COMPONENT_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
REPORT_ID_PATTERN = re.compile(r"ONR-[0-9A-F]{32}")
COMPONENT_DOMAIN = "sunderkey.candidate-component.v1"
REPORT_DOMAIN = "sunderkey.candidate-onboarding-report.v1"
REPORT_SCHEMA_VERSION = 1
COMPONENT_STATUSES = {
    "contract_fixture",
    "development",
    "review_ready",
    "retired",
}
RUNTIME_CLASSES = {
    "disabled_fixture",
    "human_runbook",
    "hybrid",
    "model_agent",
}
RUNTIME_CLASS_BY_IMPLEMENTATION_KIND = {
    "agent_bundle": {"disabled_fixture", "model_agent"},
    "human_runbook": {"human_runbook"},
    "hybrid_bundle": {"hybrid"},
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


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} must be a boolean")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QualificationError(
            f"{label} must be a nonnegative integer"
        )
    return value


def compute_candidate_component_sha256(
    component_body: dict[str, Any],
) -> str:
    """Compute one closed component artifact identity."""

    return _canonical_sha256(
        {
            "domain": COMPONENT_DOMAIN,
            "component": component_body,
        }
    )


def _behavior_specification(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {
            "mission",
            "allowed_actions",
            "prohibited_actions",
            "stop_conditions",
            "maximum_autonomous_action_tier",
            "minimum_evidence_level",
        },
        label,
    )
    return {
        "mission": _text(value.get("mission"), f"{label}.mission"),
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
    }


def _instruction_specification(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {
            "bundle_format",
            "content_sha256",
            "primary_capability_ids",
            "supporting_capability_ids",
            "scenario_family_id",
            "required_gate_ids",
        },
        label,
    )
    bundle_format = _text(
        value.get("bundle_format"), f"{label}.bundle_format"
    )
    if bundle_format not in {
        "structured_bundle",
        "synthetic_placeholder",
        "text_bundle",
    }:
        raise QualificationError(f"{label}.bundle_format is invalid")
    return {
        "bundle_format": bundle_format,
        "content_sha256": _sha256(
            value.get("content_sha256"), f"{label}.content_sha256"
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
        "required_gate_ids": list(
            _text_tuple(
                value.get("required_gate_ids"),
                f"{label}.required_gate_ids",
            )
        ),
    }


def _knowledge_specification(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {
            "retrieval_mode",
            "source_manifest_sha256",
            "source_count",
            "reviewed_source_count",
            "rights_review_status",
            "minimum_evidence_level",
        },
        label,
    )
    retrieval_mode = _text(
        value.get("retrieval_mode"), f"{label}.retrieval_mode"
    )
    if retrieval_mode not in {"disabled", "retrieval_index", "static_manifest"}:
        raise QualificationError(f"{label}.retrieval_mode is invalid")
    rights_status = _text(
        value.get("rights_review_status"),
        f"{label}.rights_review_status",
    )
    if rights_status not in {"complete", "not_applicable", "not_performed"}:
        raise QualificationError(
            f"{label}.rights_review_status is invalid"
        )
    source_count = _nonnegative_integer(
        value.get("source_count"), f"{label}.source_count"
    )
    reviewed_count = _nonnegative_integer(
        value.get("reviewed_source_count"),
        f"{label}.reviewed_source_count",
    )
    if reviewed_count > source_count:
        raise QualificationError(
            f"{label}.reviewed_source_count exceeds source_count"
        )
    if retrieval_mode == "disabled" and (source_count or reviewed_count):
        raise QualificationError(
            f"{label} disabled retrieval must have zero sources"
        )
    return {
        "retrieval_mode": retrieval_mode,
        "source_manifest_sha256": _sha256(
            value.get("source_manifest_sha256"),
            f"{label}.source_manifest_sha256",
        ),
        "source_count": source_count,
        "reviewed_source_count": reviewed_count,
        "rights_review_status": rights_status,
        "minimum_evidence_level": _text(
            value.get("minimum_evidence_level"),
            f"{label}.minimum_evidence_level",
        ),
    }


def _runtime_specification(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {
            "runtime_class",
            "provider_ref",
            "model_ref",
            "hosting_ref",
            "runtime_config_sha256",
            "execution_enabled",
            "network_access",
            "process_access",
        },
        label,
    )
    runtime_class = _text(
        value.get("runtime_class"), f"{label}.runtime_class"
    )
    if runtime_class not in RUNTIME_CLASSES:
        raise QualificationError(f"{label}.runtime_class is invalid")
    result = {
        "runtime_class": runtime_class,
        "provider_ref": _optional_text(
            value.get("provider_ref"), f"{label}.provider_ref"
        ),
        "model_ref": _optional_text(
            value.get("model_ref"), f"{label}.model_ref"
        ),
        "hosting_ref": _optional_text(
            value.get("hosting_ref"), f"{label}.hosting_ref"
        ),
        "runtime_config_sha256": _sha256(
            value.get("runtime_config_sha256"),
            f"{label}.runtime_config_sha256",
        ),
        "execution_enabled": _boolean(
            value.get("execution_enabled"),
            f"{label}.execution_enabled",
        ),
        "network_access": _boolean(
            value.get("network_access"), f"{label}.network_access"
        ),
        "process_access": _boolean(
            value.get("process_access"), f"{label}.process_access"
        ),
    }
    if runtime_class == "disabled_fixture" and any(
        (
            result["provider_ref"] is not None,
            result["model_ref"] is not None,
            result["hosting_ref"] is not None,
            result["execution_enabled"],
            result["network_access"],
            result["process_access"],
        )
    ):
        raise QualificationError(
            f"{label} disabled fixture must not enable a runtime"
        )
    return result


def _tool_policy_specification(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(
        value,
        {
            "policy_template_id",
            "allowed_action_ids",
            "prohibited_action_ids",
            "admission_mode",
            "tool_manifest_sha256",
            "allowed_tool_count",
            "credential_access",
            "target_access",
            "network_access",
            "execution_allowed",
        },
        label,
    )
    admission_mode = _text(
        value.get("admission_mode"), f"{label}.admission_mode"
    )
    if admission_mode not in {"allowlisted", "deny_all"}:
        raise QualificationError(f"{label}.admission_mode is invalid")
    result = {
        "policy_template_id": _text(
            value.get("policy_template_id"),
            f"{label}.policy_template_id",
        ),
        "allowed_action_ids": list(
            _text_tuple(
                value.get("allowed_action_ids"),
                f"{label}.allowed_action_ids",
            )
        ),
        "prohibited_action_ids": list(
            _text_tuple(
                value.get("prohibited_action_ids"),
                f"{label}.prohibited_action_ids",
            )
        ),
        "admission_mode": admission_mode,
        "tool_manifest_sha256": _sha256(
            value.get("tool_manifest_sha256"),
            f"{label}.tool_manifest_sha256",
        ),
        "allowed_tool_count": _nonnegative_integer(
            value.get("allowed_tool_count"),
            f"{label}.allowed_tool_count",
        ),
        "credential_access": _boolean(
            value.get("credential_access"),
            f"{label}.credential_access",
        ),
        "target_access": _boolean(
            value.get("target_access"), f"{label}.target_access"
        ),
        "network_access": _boolean(
            value.get("network_access"), f"{label}.network_access"
        ),
        "execution_allowed": _boolean(
            value.get("execution_allowed"),
            f"{label}.execution_allowed",
        ),
    }
    if admission_mode == "deny_all" and any(
        (
            result["allowed_tool_count"],
            result["credential_access"],
            result["target_access"],
            result["network_access"],
            result["execution_allowed"],
        )
    ):
        raise QualificationError(
            f"{label} deny-all policy must not admit tool access"
        )
    return result


SPECIFICATION_LOADERS = {
    "behavior_contract": _behavior_specification,
    "instruction_bundle": _instruction_specification,
    "knowledge_manifest": _knowledge_specification,
    "runtime_manifest": _runtime_specification,
    "tool_policy": _tool_policy_specification,
}


@dataclass(frozen=True)
class CandidateComponentArtifact:
    component_id: str
    component_version: str
    candidate_id: str
    candidate_version: str
    profile_id: str
    candidate_blueprint_sha256: str
    component_type: str
    component_status: str
    specification_json: str
    component_sha256: str

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> CandidateComponentArtifact:
        label = f"components[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "component_id",
                "component_version",
                "candidate_id",
                "candidate_version",
                "profile_id",
                "candidate_blueprint_sha256",
                "component_type",
                "component_status",
                "specification",
                "component_sha256",
            },
            label,
        )
        component_id = _text(
            value.get("component_id"), f"{label}.component_id"
        )
        if COMPONENT_ID_PATTERN.fullmatch(component_id) is None:
            raise QualificationError(f"{label}.component_id is invalid")
        candidate_id = _text(
            value.get("candidate_id"), f"{label}.candidate_id"
        )
        if COMPONENT_ID_PATTERN.fullmatch(candidate_id) is None:
            raise QualificationError(f"{label}.candidate_id is invalid")
        component_type = _text(
            value.get("component_type"), f"{label}.component_type"
        )
        specification_loader = SPECIFICATION_LOADERS.get(component_type)
        if specification_loader is None:
            raise QualificationError(f"{label}.component_type is invalid")
        component_status = _text(
            value.get("component_status"), f"{label}.component_status"
        )
        if component_status not in COMPONENT_STATUSES:
            raise QualificationError(f"{label}.component_status is invalid")
        specification = specification_loader(
            value.get("specification"), f"{label}.specification"
        )
        component = cls(
            component_id=component_id,
            component_version=_text(
                value.get("component_version"),
                f"{label}.component_version",
            ),
            candidate_id=candidate_id,
            candidate_version=_text(
                value.get("candidate_version"),
                f"{label}.candidate_version",
            ),
            profile_id=_text(
                value.get("profile_id"), f"{label}.profile_id"
            ),
            candidate_blueprint_sha256=_sha256(
                value.get("candidate_blueprint_sha256"),
                f"{label}.candidate_blueprint_sha256",
            ),
            component_type=component_type,
            component_status=component_status,
            specification_json=_canonical_json(specification),
            component_sha256=_sha256(
                value.get("component_sha256"),
                f"{label}.component_sha256",
            ),
        )
        if component.component_sha256 != compute_candidate_component_sha256(
            component.artifact_body()
        ):
            raise QualificationError(f"{label}.component_sha256 is invalid")
        return component

    @property
    def specification(self) -> dict[str, Any]:
        value = json.loads(self.specification_json)
        if not isinstance(value, dict):
            raise QualificationError("Component specification is invalid")
        return value

    @property
    def candidate_key(self) -> tuple[str, str]:
        return self.candidate_id, self.candidate_version

    def artifact_body(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_version": self.component_version,
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "profile_id": self.profile_id,
            "candidate_blueprint_sha256": self.candidate_blueprint_sha256,
            "component_type": self.component_type,
            "component_status": self.component_status,
            "specification": self.specification,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.artifact_body(),
            "component_sha256": self.component_sha256,
        }


@dataclass(frozen=True)
class CandidateComponentCatalog:
    schema_version: int
    component_catalog_id: str
    component_catalog_version: str
    candidate_blueprint_catalog_id: str
    candidate_blueprint_catalog_version: str
    candidate_blueprint_catalog_sha256: str
    components: tuple[CandidateComponentArtifact, ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @property
    def components_by_candidate_key(
        self,
    ) -> dict[tuple[str, str], tuple[CandidateComponentArtifact, ...]]:
        result: dict[
            tuple[str, str], list[CandidateComponentArtifact]
        ] = {}
        for component in self.components:
            result.setdefault(component.candidate_key, []).append(component)
        return {
            key: tuple(components) for key, components in result.items()
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        blueprints: CandidateBlueprintCatalog,
    ) -> CandidateComponentCatalog:
        value = _mapping(raw, "candidate component catalog")
        _exact_fields(
            value,
            {
                "schema_version",
                "component_catalog_id",
                "component_catalog_version",
                "candidate_blueprint_catalog_id",
                "candidate_blueprint_catalog_version",
                "candidate_blueprint_catalog_sha256",
                "components",
            },
            "candidate component catalog",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Candidate component catalog schema_version must be 1"
            )
        components = tuple(
            sorted(
                (
                    CandidateComponentArtifact.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("components"), "components")
                    )
                ),
                key=lambda component: (
                    component.candidate_id,
                    component.candidate_version,
                    REQUIRED_COMPONENT_IDS.index(component.component_type),
                ),
            )
        )
        catalog = cls(
            schema_version=1,
            component_catalog_id=_text(
                value.get("component_catalog_id"),
                "component_catalog_id",
            ),
            component_catalog_version=_text(
                value.get("component_catalog_version"),
                "component_catalog_version",
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
            components=components,
        )
        catalog._validate_relations(blueprints)
        return catalog

    def revalidated(
        self,
        blueprints: CandidateBlueprintCatalog,
    ) -> CandidateComponentCatalog:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed candidate component catalog"
            ) from exc
        return CandidateComponentCatalog.from_dict(raw, blueprints)

    def _validate_relations(
        self,
        blueprints: CandidateBlueprintCatalog,
    ) -> None:
        if (
            self.candidate_blueprint_catalog_id,
            self.candidate_blueprint_catalog_version,
            self.candidate_blueprint_catalog_sha256,
        ) != (
            blueprints.blueprint_catalog_id,
            blueprints.blueprint_catalog_version,
            blueprints.canonical_sha256,
        ):
            raise QualificationError(
                "Candidate component catalog blueprint binding is invalid"
            )
        component_ids = [item.component_id for item in self.components]
        if len(component_ids) != len(set(component_ids)):
            raise QualificationError(
                "Candidate component catalog contains duplicate component IDs"
            )
        component_keys = [
            (*item.candidate_key, item.component_type)
            for item in self.components
        ]
        if len(component_keys) != len(set(component_keys)):
            raise QualificationError(
                "Candidate component catalog contains duplicate candidate "
                "component types"
            )
        blueprints_by_profile = blueprints.blueprints_by_profile_id
        for component in self.components:
            blueprint = blueprints_by_profile.get(component.profile_id)
            if blueprint is None:
                raise QualificationError(
                    "Candidate component must reference a specialist "
                    f"blueprint: {component.component_id}"
                )
            if (
                component.candidate_blueprint_sha256
                != blueprint.blueprint_sha256
            ):
                raise QualificationError(
                    "Candidate component blueprint binding is invalid: "
                    f"{component.component_id}"
                )
            _validate_specification_binding(component, blueprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "component_catalog_id": self.component_catalog_id,
            "component_catalog_version": self.component_catalog_version,
            "candidate_blueprint_catalog_id": (
                self.candidate_blueprint_catalog_id
            ),
            "candidate_blueprint_catalog_version": (
                self.candidate_blueprint_catalog_version
            ),
            "candidate_blueprint_catalog_sha256": (
                self.candidate_blueprint_catalog_sha256
            ),
            "components": [item.to_dict() for item in self.components],
        }


def _validate_specification_binding(
    component: CandidateComponentArtifact,
    blueprint: SpecialistCandidateBlueprint,
) -> None:
    specification = component.specification
    blueprint_document = blueprint.to_dict()
    if component.component_type == "behavior_contract":
        expected = {
            key: blueprint_document[key]
            for key in (
                "mission",
                "allowed_actions",
                "prohibited_actions",
                "stop_conditions",
                "maximum_autonomous_action_tier",
                "minimum_evidence_level",
            )
        }
        if specification != expected:
            raise QualificationError(
                "Behavior contract does not match its candidate blueprint"
            )
    elif component.component_type == "instruction_bundle":
        expected_fields = {
            "primary_capability_ids": blueprint_document[
                "primary_capability_ids"
            ],
            "supporting_capability_ids": blueprint_document[
                "supporting_capability_ids"
            ],
            "scenario_family_id": blueprint_document["scenario_family_id"],
            "required_gate_ids": blueprint_document["required_gate_ids"],
        }
        if any(
            specification[key] != value
            for key, value in expected_fields.items()
        ):
            raise QualificationError(
                "Instruction bundle does not match its candidate blueprint"
            )
    elif component.component_type == "knowledge_manifest":
        if (
            specification["minimum_evidence_level"]
            != blueprint_document["minimum_evidence_level"]
        ):
            raise QualificationError(
                "Knowledge manifest does not match its candidate blueprint"
            )
    elif component.component_type == "tool_policy":
        expected_fields = {
            "policy_template_id": blueprint_document["policy_template_id"],
            "allowed_action_ids": blueprint_document["allowed_actions"],
            "prohibited_action_ids": blueprint_document[
                "prohibited_actions"
            ],
        }
        if any(
            specification[key] != value
            for key, value in expected_fields.items()
        ):
            raise QualificationError(
                "Tool policy does not match its candidate blueprint"
            )


@dataclass(frozen=True)
class CandidateOnboardingReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateOnboardingReport:
        value = _mapping(raw, "candidate onboarding report")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "onboarding_effect",
                "registry",
                "capability_catalog",
                "qualification_standard",
                "qualification_plan_catalog",
                "candidate_blueprint_catalog",
                "candidate_component_catalog",
                "candidate_catalog",
                "summary",
                "candidates",
                "orphan_component_ids",
                "limitations",
            },
            "candidate onboarding report",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Candidate onboarding report schema version is invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Candidate onboarding report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": REPORT_DOMAIN, "report": body}
        )
        expected_id = (
            "ONR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        )
        if report_sha256 != expected_hash or report_id != expected_id:
            raise QualificationError(
                "Candidate onboarding report hash is invalid"
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
                "Candidate onboarding report document is invalid"
            )
        return value


def _component_digest_by_type(
    candidate: SpecialistCandidateImplementation,
) -> dict[str, str]:
    return {
        "behavior_contract": candidate.behavior_contract_sha256,
        "instruction_bundle": candidate.instruction_bundle_sha256,
        "knowledge_manifest": candidate.knowledge_manifest_sha256,
        "runtime_manifest": candidate.runtime_manifest_sha256,
        "tool_policy": candidate.tool_policy_sha256,
    }


def _status_is_compatible(
    candidate_lifecycle: str,
    component_status: str,
) -> bool:
    allowed = {
        "contract_fixture": {"contract_fixture"},
        "development": {"development", "review_ready"},
        "evaluation_candidate": {"review_ready"},
        "retired": {"retired"},
    }
    return component_status in allowed[candidate_lifecycle]


def _candidate_record(
    candidate: SpecialistCandidateImplementation,
    components: tuple[CandidateComponentArtifact, ...],
) -> dict[str, Any]:
    by_type = {item.component_type: item for item in components}
    expected_digests = _component_digest_by_type(candidate)
    missing = tuple(
        component_type
        for component_type in REQUIRED_COMPONENT_IDS
        if component_type not in by_type
    )
    mismatched = tuple(
        component_type
        for component_type in REQUIRED_COMPONENT_IDS
        if component_type in by_type
        and by_type[component_type].component_sha256
        != expected_digests[component_type]
    )
    lifecycle_mismatches = tuple(
        component_type
        for component_type in REQUIRED_COMPONENT_IDS
        if component_type in by_type
        and not _status_is_compatible(
            candidate.lifecycle,
            by_type[component_type].component_status,
        )
    )
    binding_mismatches = tuple(
        component_type
        for component_type in REQUIRED_COMPONENT_IDS
        if component_type in by_type
        and (
            by_type[component_type].profile_id != candidate.profile_id
            or by_type[component_type].candidate_blueprint_sha256
            != candidate.candidate_blueprint_sha256
        )
    )
    runtime = by_type.get("runtime_manifest")
    runtime_class = (
        str(runtime.specification["runtime_class"])
        if runtime is not None
        else None
    )
    runtime_compatible = (
        runtime_class
        in RUNTIME_CLASS_BY_IMPLEMENTATION_KIND[
            candidate.implementation_kind
        ]
        if runtime_class is not None
        else False
    )
    complete = not any(
        (missing, mismatched, binding_mismatches, lifecycle_mismatches)
    ) and runtime_compatible
    return {
        "candidate_id": candidate.candidate_id,
        "candidate_version": candidate.candidate_version,
        "profile_id": candidate.profile_id,
        "lifecycle": candidate.lifecycle,
        "implementation_kind": candidate.implementation_kind,
        "required_component_count": len(REQUIRED_COMPONENT_IDS),
        "catalogued_component_count": len(components),
        "missing_component_types": list(missing),
        "digest_mismatch_component_types": list(mismatched),
        "binding_mismatch_component_types": list(binding_mismatches),
        "lifecycle_mismatch_component_types": list(lifecycle_mismatches),
        "runtime_class": runtime_class,
        "runtime_compatible": runtime_compatible,
        "component_binding_complete": complete,
        "nonfixture_component_binding_complete": (
            complete and candidate.lifecycle != "contract_fixture"
        ),
        "components": [
            by_type[component_type].to_dict()
            for component_type in REQUIRED_COMPONENT_IDS
            if component_type in by_type
        ],
    }


def assess_candidate_onboarding(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
    components: CandidateComponentCatalog,
    candidates: CandidateImplementationCatalog,
) -> CandidateOnboardingReport:
    """Validate component bindings without deploying or qualifying a candidate."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
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
    standard = standard.revalidated(registry, capability_catalog)
    plans = plans.revalidated(registry, capability_catalog, standard)
    blueprints = blueprints.revalidated(
        registry, capability_catalog, standard, plans
    )
    components = components.revalidated(blueprints)
    candidates = candidates.revalidated(
        registry, capability_catalog, standard, plans, blueprints
    )
    components_by_candidate = components.components_by_candidate_key
    candidate_keys = {
        (candidate.candidate_id, candidate.candidate_version)
        for candidate in candidates.candidates
    }
    candidate_records = tuple(
        _candidate_record(
            candidate,
            components_by_candidate.get(
                (candidate.candidate_id, candidate.candidate_version), ()
            ),
        )
        for candidate in candidates.candidates
    )
    orphan_components = tuple(
        component.component_id
        for component in components.components
        if component.candidate_key not in candidate_keys
    )
    component_type_counts = Counter(
        component.component_type for component in components.components
    )
    complete_count = sum(
        bool(record["component_binding_complete"])
        for record in candidate_records
    )
    nonfixture_complete_count = sum(
        bool(record["nonfixture_component_binding_complete"])
        for record in candidate_records
    )
    fixture_complete_count = sum(
        bool(record["component_binding_complete"])
        and record["lifecycle"] == "contract_fixture"
        for record in candidate_records
    )
    if complete_count != len(candidate_records) or orphan_components:
        status = "candidate_component_incomplete"
    elif nonfixture_complete_count:
        status = "candidate_component_complete"
    else:
        status = "candidate_component_fixture_only"
    if nonfixture_complete_count:
        catalog_limitation = (
            "A structurally complete nonfixture candidate can still lack "
            "provider, model, runtime, tool, evidence, review, and "
            "qualification decisions."
        )
    else:
        catalog_limitation = (
            "The checked-in component set belongs only to a disabled "
            "synthetic contract fixture."
        )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": status,
        "onboarding_effect": "none",
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
        "candidate_component_catalog": {
            "id": components.component_catalog_id,
            "version": components.component_catalog_version,
            "sha256": components.canonical_sha256,
        },
        "candidate_catalog": {
            "id": candidates.candidate_catalog_id,
            "version": candidates.candidate_catalog_version,
            "sha256": candidates.canonical_sha256,
        },
        "summary": {
            "candidate_count": len(candidate_records),
            "component_artifact_count": len(components.components),
            "required_component_count_per_candidate": len(
                REQUIRED_COMPONENT_IDS
            ),
            "behavior_contract_count": component_type_counts[
                "behavior_contract"
            ],
            "instruction_bundle_count": component_type_counts[
                "instruction_bundle"
            ],
            "knowledge_manifest_count": component_type_counts[
                "knowledge_manifest"
            ],
            "runtime_manifest_count": component_type_counts[
                "runtime_manifest"
            ],
            "tool_policy_count": component_type_counts["tool_policy"],
            "component_binding_complete_candidate_count": complete_count,
            "contract_fixture_complete_candidate_count": (
                fixture_complete_count
            ),
            "nonfixture_complete_candidate_count": (
                nonfixture_complete_count
            ),
            "incomplete_candidate_count": (
                len(candidate_records) - complete_count
            ),
            "orphan_component_count": len(orphan_components),
        },
        "candidates": list(candidate_records),
        "orphan_component_ids": list(orphan_components),
        "limitations": [
            "Component binding proves content identity, not authorship, "
            "review, deployment, safety, or competence.",
            catalog_limitation,
            "This report does not qualify a candidate or change registry "
            "or routing status.",
            "This command does not connect to a provider, model, tool, "
            "credential, target, or execution environment.",
        ],
    }
    report_sha256 = _canonical_sha256(
        {"domain": REPORT_DOMAIN, "report": body}
    )
    document = {
        **body,
        "report_id": (
            "ONR-" + report_sha256.removeprefix("sha256:")[:32].upper()
        ),
        "report_sha256": report_sha256,
    }
    return CandidateOnboardingReport.from_dict(document)


def load_candidate_component_catalog(
    path: str | Path,
    blueprints: CandidateBlueprintCatalog,
) -> CandidateComponentCatalog:
    return CandidateComponentCatalog.from_dict(
        _load_json(path, "candidate component catalog"),
        blueprints,
    )
