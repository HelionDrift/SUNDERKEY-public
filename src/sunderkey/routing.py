"""Deterministic, policy-bound capability routing for expert missions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import MissionError, RoutingError
from .mission import (
    JointMissionCell,
    MissionRequest,
    assemble_joint_mission_cell,
)
from .registry import ExpertProfile, ExpertRegistry
from .types import MissionEnvironment, ProfileKind
from .validation import is_ascii_text

CAPABILITY_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
PROFILE_STATUSES = {"defined", "qualified"}


class CapabilityProfileScope(StrEnum):
    """Registry specialist set covered by a capability catalog."""

    PILOT_SPECIALISTS = "pilot_specialists"
    ALL_SPECIALISTS = "all_specialists"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RoutingError("Could not serialize canonical routing data") from exc


def _canonical_sha256(value: Any) -> str:
    payload = _canonical_json(value).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RoutingError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RoutingError(f"{label} must be a list")
    return value


def _text(value: Any, label: str) -> str:
    if not is_ascii_text(value):
        raise RoutingError(f"{label} must be non-empty ASCII text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise RoutingError(f"{label} must be a boolean")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RoutingError(f"{label} must be a positive integer")
    return value


def _exact_fields(
    value: dict[str, Any],
    allowed: set[str],
    label: str,
    *,
    optional: set[str] | None = None,
) -> None:
    unknown = set(value) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise RoutingError(f"{label} contains unsupported fields: {names}")
    missing = allowed - (optional or set()) - set(value)
    if missing:
        names = ", ".join(sorted(missing))
        raise RoutingError(f"{label} is missing required fields: {names}")


def _require_ascii(value: Any, label: str) -> None:
    if isinstance(value, str):
        for index, character in enumerate(value):
            code_point = ord(character)
            if code_point > 127 or (code_point < 32 and character not in "\t\n\r"):
                raise RoutingError(
                    f"{label} contains disallowed character "
                    f"U+{code_point:04X} at offset {index}"
                )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _require_ascii(key, f"{label}.key")
            _require_ascii(item, f"{label}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_ascii(item, f"{label}[{index}]")


def _string_tuple(
    value: Any,
    label: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    items = _list(value, label)
    result = tuple(
        sorted(_text(item, f"{label}[{index}]") for index, item in enumerate(items))
    )
    if not allow_empty and not result:
        raise RoutingError(f"{label} must not be empty")
    if len(result) != len(set(result)):
        raise RoutingError(f"{label} contains duplicate values")
    return result


def _capability_tuple(
    value: Any,
    label: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    result = _string_tuple(value, label, allow_empty=allow_empty)
    for capability_id in result:
        if CAPABILITY_ID_PATTERN.fullmatch(capability_id) is None:
            raise RoutingError(f"Invalid capability ID: {capability_id}")
    return result


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise RoutingError(f"{label} file does not exist: {resolved}")
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RoutingError(f"Could not read {label}: {resolved}") from exc
    value = _mapping(raw, label)
    _require_ascii(value, label)
    return value


@dataclass(frozen=True)
class CapabilityDefinition:
    id: str
    name: str

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> CapabilityDefinition:
        value = _mapping(raw, f"capabilities[{index}]")
        _exact_fields(value, {"id", "name"}, f"capabilities[{index}]")
        capability_id = _text(value.get("id"), f"capabilities[{index}].id")
        if CAPABILITY_ID_PATTERN.fullmatch(capability_id) is None:
            raise RoutingError(f"Invalid capability ID: {capability_id}")
        return cls(
            id=capability_id,
            name=_text(value.get("name"), f"capabilities[{index}].name"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
        }


@dataclass(frozen=True)
class ProfileCapabilityAssignment:
    profile_id: str
    primary_capability_ids: tuple[str, ...]
    supporting_capability_ids: tuple[str, ...]

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> ProfileCapabilityAssignment:
        value = _mapping(raw, f"profile_assignments[{index}]")
        _exact_fields(
            value,
            {
                "profile_id",
                "primary_capability_ids",
                "supporting_capability_ids",
            },
            f"profile_assignments[{index}]",
        )
        primary = _capability_tuple(
            value.get("primary_capability_ids"),
            f"profile_assignments[{index}].primary_capability_ids",
            allow_empty=False,
        )
        supporting = _capability_tuple(
            value.get("supporting_capability_ids"),
            f"profile_assignments[{index}].supporting_capability_ids",
            allow_empty=True,
        )
        overlap = set(primary) & set(supporting)
        if overlap:
            names = ", ".join(sorted(overlap))
            raise RoutingError(
                f"profile_assignments[{index}] has capabilities in both "
                f"primary and supporting sets: {names}"
            )
        return cls(
            profile_id=_text(
                value.get("profile_id"),
                f"profile_assignments[{index}].profile_id",
            ),
            primary_capability_ids=primary,
            supporting_capability_ids=supporting,
        )

    def match_type(self, capability_id: str) -> str | None:
        if capability_id in self.primary_capability_ids:
            return "primary"
        if capability_id in self.supporting_capability_ids:
            return "supporting"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "primary_capability_ids": list(self.primary_capability_ids),
            "supporting_capability_ids": list(self.supporting_capability_ids),
        }


@dataclass(frozen=True)
class CapabilityCatalog:
    schema_version: int
    profile_scope: CapabilityProfileScope
    catalog_id: str
    catalog_version: str
    expert_catalog_id: str
    expert_catalog_version: str
    capabilities: tuple[CapabilityDefinition, ...]
    profile_assignments: tuple[ProfileCapabilityAssignment, ...]

    @property
    def capabilities_by_id(self) -> dict[str, CapabilityDefinition]:
        return {capability.id: capability for capability in self.capabilities}

    @property
    def assignments_by_profile_id(
        self,
    ) -> dict[str, ProfileCapabilityAssignment]:
        return {
            assignment.profile_id: assignment
            for assignment in self.profile_assignments
        }

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "expert_catalog_id": self.expert_catalog_id,
            "expert_catalog_version": self.expert_catalog_version,
            "capabilities": [
                capability.to_dict() for capability in self.capabilities
            ],
            "profile_assignments": [
                assignment.to_dict()
                for assignment in self.profile_assignments
            ],
        }
        if self.schema_version >= 2:
            value["profile_scope"] = self.profile_scope.value
        return value

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
    ) -> CapabilityCatalog:
        value = _mapping(raw, "capability catalog")
        _require_ascii(value, "capability catalog")
        base_fields = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "expert_catalog_id",
            "expert_catalog_version",
            "capabilities",
            "profile_assignments",
        }
        schema_version = value.get("schema_version")
        if schema_version not in {1, 2}:
            raise RoutingError(
                "Capability catalog schema_version must be 1 or 2"
            )
        if schema_version == 1:
            _exact_fields(value, base_fields, "capability catalog")
            profile_scope = CapabilityProfileScope.PILOT_SPECIALISTS
        else:
            _exact_fields(
                value,
                base_fields | {"profile_scope"},
                "capability catalog",
            )
            try:
                profile_scope = CapabilityProfileScope(
                    value.get("profile_scope")
                )
            except ValueError as exc:
                raise RoutingError(
                    "Capability catalog profile_scope must be "
                    "all_specialists"
                ) from exc
            if profile_scope is not CapabilityProfileScope.ALL_SPECIALISTS:
                raise RoutingError(
                    "Capability catalog schema version 2 requires "
                    "profile_scope all_specialists"
                )
        capabilities = tuple(
            sorted(
                (
                    CapabilityDefinition.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("capabilities"), "capabilities")
                    )
                ),
                key=lambda item: item.id,
            )
        )
        assignments = tuple(
            sorted(
                (
                    ProfileCapabilityAssignment.from_dict(item, index)
                    for index, item in enumerate(
                        _list(
                            value.get("profile_assignments"),
                            "profile_assignments",
                        )
                    )
                ),
                key=lambda item: item.profile_id,
            )
        )
        catalog = cls(
            schema_version=schema_version,
            profile_scope=profile_scope,
            catalog_id=_text(value.get("catalog_id"), "catalog_id"),
            catalog_version=_text(
                value.get("catalog_version"),
                "catalog_version",
            ),
            expert_catalog_id=_text(
                value.get("expert_catalog_id"),
                "expert_catalog_id",
            ),
            expert_catalog_version=_text(
                value.get("expert_catalog_version"),
                "expert_catalog_version",
            ),
            capabilities=capabilities,
            profile_assignments=assignments,
        )
        catalog._validate_relations(registry)
        return catalog

    def revalidated(self, registry: ExpertRegistry) -> CapabilityCatalog:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise RoutingError(
                "Invalid directly constructed capability catalog"
            ) from exc
        return CapabilityCatalog.from_dict(raw, registry)

    def validate(self, registry: ExpertRegistry) -> None:
        self.revalidated(registry)

    def _validate_relations(self, registry: ExpertRegistry) -> None:
        if self.expert_catalog_id != registry.catalog_id:
            raise RoutingError(
                "Capability catalog expert_catalog_id does not match the registry"
            )
        if self.expert_catalog_version != registry.catalog_version:
            raise RoutingError(
                "Capability catalog expert_catalog_version does not match the registry"
            )
        capability_ids = [item.id for item in self.capabilities]
        if not capability_ids:
            raise RoutingError("Capability catalog must define capabilities")
        if len(capability_ids) != len(set(capability_ids)):
            raise RoutingError("Capability catalog contains duplicate capability IDs")
        assignment_ids = [
            assignment.profile_id for assignment in self.profile_assignments
        ]
        if len(assignment_ids) != len(set(assignment_ids)):
            raise RoutingError(
                "Capability catalog contains duplicate profile assignments"
            )

        known_capabilities = set(capability_ids)
        primary_coverage: set[str] = set()
        for assignment in self.profile_assignments:
            profile = registry.profiles_by_id.get(assignment.profile_id)
            if profile is None:
                raise RoutingError(
                    "Capability assignment references unknown profile: "
                    f"{assignment.profile_id}"
                )
            if profile.kind is not ProfileKind.SPECIALIST:
                raise RoutingError(
                    "Capability assignment does not reference a specialist: "
                    f"{assignment.profile_id}"
                )
            unknown = (
                set(assignment.primary_capability_ids)
                | set(assignment.supporting_capability_ids)
            ) - known_capabilities
            if unknown:
                names = ", ".join(sorted(unknown))
                raise RoutingError(
                    f"Capability assignment {assignment.profile_id} references "
                    f"unknown capabilities: {names}"
                )
            primary_coverage.update(assignment.primary_capability_ids)

        if self.profile_scope is CapabilityProfileScope.PILOT_SPECIALISTS:
            expected_profile_ids = {
                profile.id
                for profile in registry.profiles
                if (
                    profile.kind is ProfileKind.SPECIALIST
                    and profile.pilot
                )
            }
            missing_label = "missing pilot profiles"
            extra_label = "non-pilot profiles"
            assignment_error = (
                "Pilot capability assignments must match the registry "
                "pilot set; "
            )
        else:
            expected_profile_ids = {
                profile.id
                for profile in registry.profiles
                if profile.kind is ProfileKind.SPECIALIST
            }
            missing_label = "missing full-Army specialist profiles"
            extra_label = "out-of-scope profiles"
            assignment_error = (
                "Capability assignments must match the registry "
                "full-Army specialist set; "
            )
        if set(assignment_ids) != expected_profile_ids:
            missing = sorted(
                expected_profile_ids - set(assignment_ids)
            )
            extra = sorted(
                set(assignment_ids) - expected_profile_ids
            )
            details: list[str] = []
            if missing:
                details.append(
                    f"{missing_label}: {', '.join(missing)}"
                )
            if extra:
                details.append(
                    f"{extra_label}: {', '.join(extra)}"
                )
            raise RoutingError(
                assignment_error + "; ".join(details)
            )
        missing_primary = known_capabilities - primary_coverage
        if missing_primary:
            names = ", ".join(sorted(missing_primary))
            if (
                self.profile_scope
                is CapabilityProfileScope.PILOT_SPECIALISTS
            ):
                raise RoutingError(
                    "Capabilities without a primary pilot assignment: "
                    f"{names}"
                )
            raise RoutingError(
                f"Capabilities without a primary assignment: {names}"
            )
        if self.profile_scope is CapabilityProfileScope.ALL_SPECIALISTS:
            primary_counts = {
                capability_id: sum(
                    capability_id
                    in assignment.primary_capability_ids
                    for assignment in self.profile_assignments
                )
                for capability_id in known_capabilities
            }
            duplicated = sorted(
                capability_id
                for capability_id, count in primary_counts.items()
                if count != 1
            )
            if duplicated:
                raise RoutingError(
                    "Full-Army capabilities require exactly one primary "
                    "assignment: "
                    + ", ".join(duplicated)
                )


@dataclass(frozen=True)
class RoutingPolicy:
    schema_version: int
    policy_id: str
    policy_version: str
    capability_catalog_id: str
    capability_catalog_version: str
    allowed_statuses: tuple[str, ...]
    require_pilot: bool
    allowed_environments: tuple[MissionEnvironment, ...]
    allow_supporting_matches: bool
    allow_tier_escalation: bool
    max_specialists: int
    max_cell_size: int

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "capability_catalog_id": self.capability_catalog_id,
            "capability_catalog_version": self.capability_catalog_version,
            "allowed_statuses": list(self.allowed_statuses),
            "require_pilot": self.require_pilot,
            "allowed_environments": [
                environment.value
                if isinstance(environment, MissionEnvironment)
                else environment
                for environment in self.allowed_environments
            ],
            "allow_supporting_matches": self.allow_supporting_matches,
            "allow_tier_escalation": self.allow_tier_escalation,
            "max_specialists": self.max_specialists,
            "max_cell_size": self.max_cell_size,
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        catalog: CapabilityCatalog,
    ) -> RoutingPolicy:
        value = _mapping(raw, "routing policy")
        _require_ascii(value, "routing policy")
        allowed = {
            "schema_version",
            "policy_id",
            "policy_version",
            "capability_catalog_id",
            "capability_catalog_version",
            "allowed_statuses",
            "require_pilot",
            "allowed_environments",
            "allow_supporting_matches",
            "allow_tier_escalation",
            "max_specialists",
            "max_cell_size",
        }
        _exact_fields(value, allowed, "routing policy")
        if value.get("schema_version") != 1:
            raise RoutingError("Routing policy schema_version must be 1")
        statuses = _string_tuple(
            value.get("allowed_statuses"),
            "allowed_statuses",
            allow_empty=False,
        )
        unknown_statuses = set(statuses) - PROFILE_STATUSES
        if unknown_statuses:
            names = ", ".join(sorted(unknown_statuses))
            raise RoutingError(f"Unsupported allowed profile statuses: {names}")
        environment_names = _string_tuple(
            value.get("allowed_environments"),
            "allowed_environments",
            allow_empty=False,
        )
        try:
            environments = tuple(
                sorted(
                    (MissionEnvironment(item) for item in environment_names),
                    key=lambda item: item.value,
                )
            )
        except ValueError as exc:
            options = ", ".join(item.value for item in MissionEnvironment)
            raise RoutingError(
                f"allowed_environments values must be one of: {options}"
            ) from exc
        policy = cls(
            schema_version=1,
            policy_id=_text(value.get("policy_id"), "policy_id"),
            policy_version=_text(value.get("policy_version"), "policy_version"),
            capability_catalog_id=_text(
                value.get("capability_catalog_id"),
                "capability_catalog_id",
            ),
            capability_catalog_version=_text(
                value.get("capability_catalog_version"),
                "capability_catalog_version",
            ),
            allowed_statuses=statuses,
            require_pilot=_boolean(value.get("require_pilot"), "require_pilot"),
            allowed_environments=environments,
            allow_supporting_matches=_boolean(
                value.get("allow_supporting_matches"),
                "allow_supporting_matches",
            ),
            allow_tier_escalation=_boolean(
                value.get("allow_tier_escalation"),
                "allow_tier_escalation",
            ),
            max_specialists=_positive_integer(
                value.get("max_specialists"),
                "max_specialists",
            ),
            max_cell_size=_positive_integer(
                value.get("max_cell_size"),
                "max_cell_size",
            ),
        )
        policy._validate_binding(catalog)
        return policy

    def revalidated(self, catalog: CapabilityCatalog) -> RoutingPolicy:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise RoutingError(
                "Invalid directly constructed routing policy"
            ) from exc
        return RoutingPolicy.from_dict(raw, catalog)

    def validate(self, catalog: CapabilityCatalog) -> None:
        self.revalidated(catalog)

    def _validate_binding(self, catalog: CapabilityCatalog) -> None:
        if self.capability_catalog_id != catalog.catalog_id:
            raise RoutingError(
                "Routing policy capability_catalog_id does not match the catalog"
            )
        if self.capability_catalog_version != catalog.catalog_version:
            raise RoutingError(
                "Routing policy capability_catalog_version does not match the catalog"
            )


MISSION_TEMPLATE_FIELDS = {
    "schema_version",
    "mission_id",
    "objective",
    "environment",
    "max_action_tier",
    "required_evidence_level",
    "scope_reference",
    "scope_document_hash",
    "constraints",
}


@dataclass(frozen=True)
class RoutingRequest:
    schema_version: int
    mission_template: MissionRequest
    required_capability_ids: tuple[str, ...]
    optional_capability_ids: tuple[str, ...]
    pinned_specialist_ids: tuple[str, ...]
    preferred_specialist_ids: tuple[str, ...]
    excluded_specialist_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        if not isinstance(self.mission_template, MissionRequest):
            raise RoutingError(
                "routing request mission_template must be a MissionRequest"
            )
        mission = self.mission_template.to_dict()
        mission.pop("requested_specialist_ids", None)
        return {
            "schema_version": self.schema_version,
            "mission": mission,
            "required_capability_ids": list(self.required_capability_ids),
            "optional_capability_ids": list(self.optional_capability_ids),
            "pinned_specialist_ids": list(self.pinned_specialist_ids),
            "preferred_specialist_ids": list(self.preferred_specialist_ids),
            "excluded_specialist_ids": list(self.excluded_specialist_ids),
        }

    def revalidated(self) -> RoutingRequest:
        try:
            raw = self.to_dict()
        except RoutingError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise RoutingError(
                "Invalid directly constructed routing request"
            ) from exc
        return RoutingRequest.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Any) -> RoutingRequest:
        value = _mapping(raw, "routing request")
        _require_ascii(value, "routing request")
        allowed = {
            "schema_version",
            "mission",
            "required_capability_ids",
            "optional_capability_ids",
            "pinned_specialist_ids",
            "preferred_specialist_ids",
            "excluded_specialist_ids",
        }
        _exact_fields(value, allowed, "routing request")
        if value.get("schema_version") != 1:
            raise RoutingError("Routing request schema_version must be 1")
        mission_value = _mapping(value.get("mission"), "mission")
        _exact_fields(
            mission_value,
            MISSION_TEMPLATE_FIELDS,
            "mission",
            optional={"scope_document_hash"},
        )
        mission_raw = dict(mission_value)
        mission_raw["requested_specialist_ids"] = ["ROUTING-PENDING"]
        try:
            mission_template = MissionRequest.from_dict(mission_raw)
        except MissionError as exc:
            raise RoutingError(f"Invalid routing mission template: {exc}") from exc

        required = _capability_tuple(
            value.get("required_capability_ids"),
            "required_capability_ids",
            allow_empty=False,
        )
        optional = _capability_tuple(
            value.get("optional_capability_ids"),
            "optional_capability_ids",
            allow_empty=True,
        )
        overlap = set(required) & set(optional)
        if overlap:
            names = ", ".join(sorted(overlap))
            raise RoutingError(
                f"Capabilities cannot be both required and optional: {names}"
            )

        pinned = _string_tuple(
            value.get("pinned_specialist_ids"),
            "pinned_specialist_ids",
            allow_empty=True,
        )
        preferred = _string_tuple(
            value.get("preferred_specialist_ids"),
            "preferred_specialist_ids",
            allow_empty=True,
        )
        excluded = _string_tuple(
            value.get("excluded_specialist_ids"),
            "excluded_specialist_ids",
            allow_empty=True,
        )
        pin_conflicts = set(pinned) & set(excluded)
        if pin_conflicts:
            names = ", ".join(sorted(pin_conflicts))
            raise RoutingError(
                f"Specialists cannot be both pinned and excluded: {names}"
            )
        preference_conflicts = set(preferred) & set(excluded)
        if preference_conflicts:
            names = ", ".join(sorted(preference_conflicts))
            raise RoutingError(
                f"Specialists cannot be both preferred and excluded: {names}"
            )
        return cls(
            schema_version=1,
            mission_template=mission_template,
            required_capability_ids=required,
            optional_capability_ids=optional,
            pinned_specialist_ids=pinned,
            preferred_specialist_ids=preferred,
            excluded_specialist_ids=excluded,
        )


@dataclass(frozen=True)
class CandidateScore:
    required_coverage: int
    primary_required_coverage: int
    qualified_status: int
    autonomous_tier_fit: int
    preferred_profile: int
    optional_primary_coverage: int
    optional_supporting_coverage: int
    total_cell_size: int

    def rank_key(self, profile_id: str) -> tuple[Any, ...]:
        return (
            -self.required_coverage,
            -self.primary_required_coverage,
            -self.qualified_status,
            -self.autonomous_tier_fit,
            -self.preferred_profile,
            -self.optional_primary_coverage,
            -self.optional_supporting_coverage,
            self.total_cell_size,
            profile_id,
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "required_coverage": self.required_coverage,
            "primary_required_coverage": self.primary_required_coverage,
            "qualified_status": self.qualified_status,
            "autonomous_tier_fit": self.autonomous_tier_fit,
            "preferred_profile": self.preferred_profile,
            "optional_primary_coverage": self.optional_primary_coverage,
            "optional_supporting_coverage": self.optional_supporting_coverage,
            "total_cell_size": self.total_cell_size,
        }


@dataclass(frozen=True)
class SelectionStep:
    step: int
    profile_id: str
    reason: str
    newly_covered_capability_ids: tuple[str, ...]
    score: CandidateScore

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "profile_id": self.profile_id,
            "reason": self.reason,
            "newly_covered_capability_ids": list(
                self.newly_covered_capability_ids
            ),
            "score": self.score.to_dict(),
        }


@dataclass(frozen=True)
class CapabilityMatch:
    profile_id: str
    match_type: str

    def to_dict(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "match_type": self.match_type,
        }


@dataclass(frozen=True)
class CapabilityCoverage:
    capability_id: str
    required: bool
    matches: tuple[CapabilityMatch, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "required": self.required,
            "matches": [match.to_dict() for match in self.matches],
        }


@dataclass(frozen=True)
class RoutingDecision:
    schema_version: int
    status: str
    mission_id: str
    capability_catalog_id: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    routing_policy_id: str
    routing_policy_version: str
    routing_policy_sha256: str
    selected_specialist_ids: tuple[str, ...]
    effective_max_specialists: int
    effective_max_cell_size: int
    capability_coverage: tuple[CapabilityCoverage, ...]
    selection_steps: tuple[SelectionStep, ...]
    mission_request: MissionRequest
    joint_mission_cell: JointMissionCell
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "mission_id": self.mission_id,
            "capability_catalog": {
                "id": self.capability_catalog_id,
                "version": self.capability_catalog_version,
                "sha256": self.capability_catalog_sha256,
            },
            "routing_policy": {
                "id": self.routing_policy_id,
                "version": self.routing_policy_version,
                "sha256": self.routing_policy_sha256,
            },
            "selected_specialist_ids": list(self.selected_specialist_ids),
            "effective_limits": {
                "max_specialists": self.effective_max_specialists,
                "max_cell_size": self.effective_max_cell_size,
            },
            "capability_coverage": [
                coverage.to_dict() for coverage in self.capability_coverage
            ],
            "selection_steps": [
                selection.to_dict() for selection in self.selection_steps
            ],
            "mission_request": _mission_request_dict(self.mission_request),
            "joint_mission_cell": self.joint_mission_cell.to_dict(),
            "warnings": list(self.warnings),
        }


def _mission_request_dict(request: MissionRequest) -> dict[str, Any]:
    return request.to_dict()


def _resolve_mission(
    template: MissionRequest,
    specialist_ids: tuple[str, ...],
) -> MissionRequest:
    raw = _mission_request_dict(template)
    raw["requested_specialist_ids"] = list(specialist_ids)
    try:
        return MissionRequest.from_dict(raw)
    except MissionError as exc:
        raise RoutingError(f"Could not resolve routed mission: {exc}") from exc


def _assemble(
    registry: ExpertRegistry,
    template: MissionRequest,
    specialist_ids: set[str],
) -> tuple[MissionRequest, JointMissionCell]:
    ordered = tuple(sorted(specialist_ids))
    mission = _resolve_mission(template, ordered)
    try:
        cell = assemble_joint_mission_cell(registry, mission)
    except MissionError as exc:
        raise RoutingError(f"Could not assemble routed mission: {exc}") from exc
    return mission, cell


def _assignment_matches(
    assignment: ProfileCapabilityAssignment,
    capability_ids: set[str],
    *,
    allow_supporting: bool,
    primary_available: dict[str, bool] | None = None,
) -> set[str]:
    matches = set(assignment.primary_capability_ids) & capability_ids
    if allow_supporting:
        supporting = set(assignment.supporting_capability_ids) & capability_ids
        if primary_available is None:
            matches.update(supporting)
        else:
            matches.update(
                capability_id
                for capability_id in supporting
                if not primary_available.get(capability_id, False)
            )
    return matches


def _profile_is_eligible(
    profile: ExpertProfile,
    policy: RoutingPolicy,
    request: RoutingRequest,
) -> bool:
    if profile.status == "retired" or profile.status not in policy.allowed_statuses:
        return False
    if policy.require_pilot and not profile.pilot:
        return False
    if profile.id in request.excluded_specialist_ids:
        return False
    return policy.allow_tier_escalation or profile.max_autonomous_tier.allows(
        request.mission_template.max_action_tier
    )


def _score_for_request(
    profile: ExpertProfile,
    assignment: ProfileCapabilityAssignment,
    request: RoutingRequest,
    new_required: set[str],
    cell_size: int,
    *,
    allow_supporting_matches: bool,
) -> CandidateScore:
    optional_capabilities = set(request.optional_capability_ids)
    return CandidateScore(
        required_coverage=len(new_required),
        primary_required_coverage=len(
            set(assignment.primary_capability_ids) & new_required
        ),
        qualified_status=int(profile.status == "qualified"),
        autonomous_tier_fit=int(
            profile.max_autonomous_tier.allows(
                request.mission_template.max_action_tier
            )
        ),
        preferred_profile=int(profile.id in request.preferred_specialist_ids),
        optional_primary_coverage=len(
            set(assignment.primary_capability_ids) & optional_capabilities
        ),
        optional_supporting_coverage=(
            len(
                set(assignment.supporting_capability_ids)
                & optional_capabilities
            )
            if allow_supporting_matches
            else 0
        ),
        total_cell_size=cell_size,
    )


def route_mission(
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    policy: RoutingPolicy,
    request: RoutingRequest,
) -> RoutingDecision:
    """Select specialists and assemble a mission without prose inference."""

    if not isinstance(catalog, CapabilityCatalog):
        raise RoutingError("catalog must be a CapabilityCatalog")
    if not isinstance(policy, RoutingPolicy):
        raise RoutingError("policy must be a RoutingPolicy")
    if not isinstance(request, RoutingRequest):
        raise RoutingError("request must be a RoutingRequest")
    catalog = catalog.revalidated(registry)
    policy = policy.revalidated(catalog)
    request = request.revalidated()
    if request.mission_template.environment not in policy.allowed_environments:
        raise RoutingError(
            "Mission environment is not allowed by routing policy: "
            f"{request.mission_template.environment.value}"
        )

    known_capabilities = set(catalog.capabilities_by_id)
    requested_capabilities = (
        set(request.required_capability_ids)
        | set(request.optional_capability_ids)
    )
    unknown_capabilities = requested_capabilities - known_capabilities
    if unknown_capabilities:
        names = ", ".join(sorted(unknown_capabilities))
        raise RoutingError(f"Routing request contains unknown capabilities: {names}")

    assignments = catalog.assignments_by_profile_id
    requested_profile_ids = (
        set(request.pinned_specialist_ids)
        | set(request.preferred_specialist_ids)
        | set(request.excluded_specialist_ids)
    )
    unknown_profiles = requested_profile_ids - set(assignments)
    if unknown_profiles:
        names = ", ".join(sorted(unknown_profiles))
        if (
            catalog.profile_scope
            is CapabilityProfileScope.PILOT_SPECIALISTS
        ):
            raise RoutingError(
                "Routing request references profiles outside the pilot "
                f"catalog: {names}"
            )
        raise RoutingError(
            "Routing request references profiles outside the capability "
            f"catalog: {names}"
        )

    eligible: dict[str, ProfileCapabilityAssignment] = {}
    for profile_id, assignment in assignments.items():
        profile = registry.profiles_by_id[profile_id]
        if _profile_is_eligible(profile, policy, request):
            eligible[profile_id] = assignment
    primary_available = {
        capability_id: any(
            capability_id in assignment.primary_capability_ids
            for assignment in eligible.values()
        )
        for capability_id in requested_capabilities
    }

    for profile_id in request.pinned_specialist_ids:
        if profile_id not in eligible:
            raise RoutingError(
                f"Pinned specialist is not eligible under routing policy: {profile_id}"
            )
        covered = _assignment_matches(
            assignments[profile_id],
            requested_capabilities,
            allow_supporting=policy.allow_supporting_matches,
        )
        if not covered:
            raise RoutingError(
                "Pinned specialist does not cover a requested capability: "
                f"{profile_id}"
            )

    effective_max_specialists = policy.max_specialists
    effective_max_cell_size = min(
        policy.max_cell_size,
        request.mission_template.constraints.max_cell_size,
    )
    selected: set[str] = set()
    uncovered = set(request.required_capability_ids)
    steps: list[SelectionStep] = []

    for profile_id in request.pinned_specialist_ids:
        if len(selected) >= effective_max_specialists:
            raise RoutingError(
                "Pinned specialists exceed the effective specialist limit"
            )
        assignment = eligible[profile_id]
        new_required = _assignment_matches(
            assignment,
            uncovered,
            allow_supporting=policy.allow_supporting_matches,
            primary_available=primary_available,
        )
        provisional = selected | {profile_id}
        _, cell = _assemble(
            registry,
            request.mission_template,
            provisional,
        )
        if cell.size > effective_max_cell_size:
            raise RoutingError(
                "Pinned specialists exceed the effective cell-size limit"
            )
        profile = registry.profiles_by_id[profile_id]
        score = _score_for_request(
            profile,
            assignment,
            request,
            new_required,
            cell.size,
            allow_supporting_matches=policy.allow_supporting_matches,
        )
        selected.add(profile_id)
        uncovered.difference_update(new_required)
        steps.append(
            SelectionStep(
                step=len(steps) + 1,
                profile_id=profile_id,
                reason="pinned",
                newly_covered_capability_ids=tuple(sorted(new_required)),
                score=score,
            )
        )

    while uncovered:
        if len(selected) >= effective_max_specialists:
            names = ", ".join(sorted(uncovered))
            raise RoutingError(
                "Required capabilities exceed the effective specialist limit: "
                f"{names}"
            )
        ranked: list[
            tuple[
                tuple[Any, ...],
                str,
                set[str],
                CandidateScore,
            ]
        ] = []
        cell_limit_blocked = False
        for profile_id in sorted(eligible):
            if profile_id in selected:
                continue
            assignment = eligible[profile_id]
            new_required = _assignment_matches(
                assignment,
                uncovered,
                allow_supporting=policy.allow_supporting_matches,
                primary_available=primary_available,
            )
            if not new_required:
                continue
            _, provisional_cell = _assemble(
                registry,
                request.mission_template,
                selected | {profile_id},
            )
            if provisional_cell.size > effective_max_cell_size:
                cell_limit_blocked = True
                continue
            profile = registry.profiles_by_id[profile_id]
            score = _score_for_request(
                profile,
                assignment,
                request,
                new_required,
                provisional_cell.size,
                allow_supporting_matches=policy.allow_supporting_matches,
            )
            ranked.append(
                (
                    score.rank_key(profile_id),
                    profile_id,
                    new_required,
                    score,
                )
            )
        if not ranked:
            names = ", ".join(sorted(uncovered))
            if cell_limit_blocked:
                raise RoutingError(
                    "Required capabilities cannot fit within the effective "
                    f"cell-size limit: {names}"
                )
            qualifier = (
                "pilot specialist"
                if catalog.profile_scope
                is CapabilityProfileScope.PILOT_SPECIALISTS
                else "specialist"
            )
            raise RoutingError(
                f"No eligible {qualifier} covers required "
                f"capabilities: {names}"
            )
        _, profile_id, new_required, score = min(ranked, key=lambda item: item[0])
        selected.add(profile_id)
        uncovered.difference_update(new_required)
        steps.append(
            SelectionStep(
                step=len(steps) + 1,
                profile_id=profile_id,
                reason="required-capability-coverage",
                newly_covered_capability_ids=tuple(sorted(new_required)),
                score=score,
            )
        )

    mission, cell = _assemble(registry, request.mission_template, selected)
    if cell.size > effective_max_cell_size:
        raise RoutingError(
            "Assembled mission exceeds the effective cell-size limit"
        )

    coverage: list[CapabilityCoverage] = []
    required_set = set(request.required_capability_ids)
    for capability_id in sorted(requested_capabilities):
        matches: list[CapabilityMatch] = []
        for profile_id in sorted(selected):
            match_type = assignments[profile_id].match_type(capability_id)
            if match_type is None:
                continue
            if match_type == "supporting" and not policy.allow_supporting_matches:
                continue
            matches.append(
                CapabilityMatch(
                    profile_id=profile_id,
                    match_type=match_type,
                )
            )
        coverage.append(
            CapabilityCoverage(
                capability_id=capability_id,
                required=capability_id in required_set,
                matches=tuple(matches),
            )
        )

    return RoutingDecision(
        schema_version=1,
        status="routed",
        mission_id=mission.mission_id,
        capability_catalog_id=catalog.catalog_id,
        capability_catalog_version=catalog.catalog_version,
        capability_catalog_sha256=catalog.canonical_sha256,
        routing_policy_id=policy.policy_id,
        routing_policy_version=policy.policy_version,
        routing_policy_sha256=policy.canonical_sha256,
        selected_specialist_ids=tuple(sorted(selected)),
        effective_max_specialists=effective_max_specialists,
        effective_max_cell_size=effective_max_cell_size,
        capability_coverage=tuple(coverage),
        selection_steps=tuple(steps),
        mission_request=mission,
        joint_mission_cell=cell,
        warnings=tuple(sorted(set(cell.warnings))),
    )


def route_specialists(
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    policy: RoutingPolicy,
    request: RoutingRequest,
) -> RoutingDecision:
    """Compatibility name for deterministic mission routing."""

    return route_mission(registry, catalog, policy, request)


def load_capability_catalog(
    path: str | Path,
    registry: ExpertRegistry,
) -> CapabilityCatalog:
    return CapabilityCatalog.from_dict(
        _load_json(path, "capability catalog"),
        registry,
    )


def load_routing_policy(
    path: str | Path,
    catalog: CapabilityCatalog,
) -> RoutingPolicy:
    return RoutingPolicy.from_dict(
        _load_json(path, "routing policy"),
        catalog,
    )


def load_routing_request(path: str | Path) -> RoutingRequest:
    return RoutingRequest.from_dict(_load_json(path, "routing request"))
