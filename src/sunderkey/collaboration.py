"""Deterministic collaboration plans for assembled SUNDERKEY mission cells."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import CollaborationPlanError, MissionError, RegistryError
from .mission import (
    DOMAIN_SHARED_PROFILE_IDS,
    MISSION_ID_PATTERN,
    MissionRequest,
    assemble_joint_mission_cell,
)
from .registry import (
    DomainCommand,
    ExpertProfile,
    ExpertRegistry,
    ManeuverGroup,
)
from .types import ActionTier, EvidenceLevel, ProfileKind
from .validation import (
    DuplicateJsonKeyError,
    is_ascii_text,
    loads_json_without_duplicate_keys,
)

SCHEMA_VERSION = 1
MAX_WORK_ITEMS = 1024
MAX_TOPOLOGICAL_LAYERS = 128
MAX_RELATION_IDS = 1024
MAX_SUPPORTING_PROFILES = 512
MAX_WARNINGS = 1024
WORK_ITEM_ID_PATTERN = re.compile(r"WIT-[A-Z]{2,16}-[0-9A-F]{16}")
PLAN_ID_PATTERN = re.compile(r"CLP-[0-9A-F]{24}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PROFILE_ID_PATTERN = re.compile(
    r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})"
)
COMMAND_ID_PATTERN = re.compile(r"AOE-G[A-E]-D[0-9]{2}")
GROUP_ID_PATTERN = re.compile(r"G[A-E]")

READINESS_OWNER_ID = "AOE-HQ-08"
READINESS_SUPPORT_IDS = ("AOE-HQ-09", "AOE-HQ-12", "AOE-HQ-31")
READINESS_CONDITIONAL_SUPPORT_IDS = ("AOE-HQ-32",)
MISSION_GRAPH_PROFILE_ID = "AOE-HQ-11"
INTEGRATION_OWNER_ID = "AOE-HQ-10"
CONTROL_OWNER_ID = "AOE-HQ-12"
CONTROL_SUPPORT_IDS = (
    "AOE-HQ-13",
    "AOE-HQ-14",
    "AOE-HQ-15",
    "AOE-HQ-16",
    "AOE-HQ-17",
)
EVIDENCE_OWNER_ID = "AOE-HQ-18"
ASSURANCE_OWNER_ID = "AOE-HQ-19"
DETECTION_PROFILE_ID = "AOE-HQ-22"
CLOSURE_PROFILE_ID = "AOE-HQ-25"
FIXED_SHARED_ROLE_REQUIREMENTS = {
    "AOE-HQ-08": ("mission operations", "mission-operations", "shared-v1"),
    "AOE-HQ-09": ("mission operations", "mission-operations", "shared-v1"),
    "AOE-HQ-10": ("mission operations", "mission-operations", "shared-v1"),
    "AOE-HQ-11": ("mission operations", "mission-operations", "shared-v1"),
    "AOE-HQ-12": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-13": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-14": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-15": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-16": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-17": (
        "independent control",
        "independent-control",
        "independent-control-v1",
    ),
    "AOE-HQ-18": (
        "independent assurance",
        "independent-assurance",
        "independent-assurance-v1",
    ),
    "AOE-HQ-19": (
        "independent assurance",
        "independent-assurance",
        "independent-assurance-v1",
    ),
    "AOE-HQ-22": ("purple team", "purple-team", "shared-v1"),
    "AOE-HQ-23": ("purple team", "purple-team", "shared-v1"),
    "AOE-HQ-25": ("purple team", "purple-team", "shared-v1"),
    "AOE-HQ-27": (
        "doctrine and knowledge",
        "doctrine-and-knowledge",
        "shared-v1",
    ),
    "AOE-HQ-28": (
        "doctrine and knowledge",
        "doctrine-and-knowledge",
        "shared-v1",
    ),
    "AOE-HQ-30": (
        "operational infrastructure",
        "operational-infrastructure",
        "shared-v1",
    ),
    "AOE-HQ-31": (
        "operational infrastructure",
        "operational-infrastructure",
        "shared-v1",
    ),
    "AOE-HQ-32": (
        "operational infrastructure",
        "operational-infrastructure",
        "shared-v1",
    ),
}


class WorkItemKind(StrEnum):
    """Closed collaboration work item kinds."""

    READINESS = "readiness"
    SPECIALIST_ANALYSIS = "specialist_analysis"
    DOMAIN_SYNTHESIS = "domain_synthesis"
    GROUP_INTEGRATION = "group_integration"
    CROSS_SURFACE_INTEGRATION = "cross_surface_integration"
    CONTROL_REVIEW = "control_review"
    EVIDENCE_REVIEW = "evidence_review"
    ASSURANCE_REVIEW = "assurance_review"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CollaborationPlanError(
            "Collaboration plan hash material must be canonical JSON"
        ) from exc


def _sha256(value: Any) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()
    return f"sha256:{digest}"


def _domain_hash(domain: str, value: Any) -> str:
    material = f"{domain}\x00{_canonical_json(value)}".encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _text(
    value: Any,
    label: str,
    *,
    max_length: int | None = None,
) -> str:
    if not is_ascii_text(value):
        raise CollaborationPlanError(f"{label} must be non-empty ASCII text")
    if max_length is not None and len(value) > max_length:
        raise CollaborationPlanError(
            f"{label} must not exceed {max_length} characters"
        )
    return value


def _printable_text(
    value: Any,
    label: str,
    *,
    max_length: int | None = None,
) -> str:
    result = _text(value, label, max_length=max_length)
    if any(ord(character) < 32 or ord(character) > 126 for character in result):
        raise CollaborationPlanError(
            f"{label} must be non-empty printable ASCII text"
        )
    return result


def _identifier(
    value: Any,
    label: str,
    pattern: re.Pattern[str] | None = None,
) -> str:
    result = _text(value, label)
    if any(character.isspace() for character in result):
        raise CollaborationPlanError(f"{label} cannot contain whitespace")
    if pattern is not None and pattern.fullmatch(result) is None:
        raise CollaborationPlanError(f"{label} has an invalid format")
    return result


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        bounds = f"greater than or equal to {minimum}"
        if maximum is not None:
            bounds += f" and less than or equal to {maximum}"
        raise CollaborationPlanError(
            f"{label} must be an integer {bounds}"
        )
    return value


def _enum(enum_type: type[Any], value: Any, label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        options = ", ".join(item.value for item in enum_type)
        raise CollaborationPlanError(
            f"{label} must be one of: {options}"
        ) from exc


def _identifier_list(
    value: Any,
    label: str,
    pattern: re.Pattern[str],
    *,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CollaborationPlanError(f"{label} must be a list")
    if max_items is not None and len(value) > max_items:
        raise CollaborationPlanError(
            f"{label} must not contain more than {max_items} items"
        )
    result = tuple(
        _identifier(item, f"{label}[{index}]", pattern)
        for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise CollaborationPlanError(f"{label} contains duplicates")
    return result


def _identifier_tuple(
    value: Any,
    label: str,
    pattern: re.Pattern[str],
    *,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise CollaborationPlanError(f"{label} must be a tuple")
    if max_items is not None and len(value) > max_items:
        raise CollaborationPlanError(
            f"{label} must not contain more than {max_items} items"
        )
    result = tuple(
        _identifier(item, f"{label}[{index}]", pattern)
        for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise CollaborationPlanError(f"{label} contains duplicates")
    return result


def _exact_fields(
    raw: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CollaborationPlanError(f"{label} must be an object")
    actual = set(raw)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        names = ", ".join(sorted(missing))
        raise CollaborationPlanError(f"{label} is missing required fields: {names}")
    if unknown:
        names = ", ".join(sorted(unknown))
        raise CollaborationPlanError(f"{label} contains unsupported fields: {names}")
    return raw


def _validate_sha256(value: Any, label: str) -> str:
    result = _text(value, label)
    if SHA256_PATTERN.fullmatch(result) is None:
        raise CollaborationPlanError(
            f"{label} must use sha256 followed by 64 lowercase hexadecimal characters"
        )
    return result


def _work_item_id(token: str, mission_id: str, subject: str) -> str:
    digest = _domain_hash(
        "sunderkey.collaboration.work-item.v1",
        {
            "kind": token,
            "mission_id": mission_id,
            "subject": subject,
        },
    )
    return f"WIT-{token}-{digest[:16].upper()}"


def _action_ceiling(
    request: MissionRequest,
    owner: ExpertProfile,
) -> ActionTier:
    rank = min(request.max_action_tier.rank, owner.max_autonomous_tier.rank)
    return ActionTier(f"R{rank}")


def _required_evidence(
    request: MissionRequest,
    owner: ExpertProfile,
) -> EvidenceLevel:
    rank = max(
        request.required_evidence_level.rank,
        owner.minimum_evidence_level.rank,
    )
    return EvidenceLevel(f"E{rank}")


def _validated_inputs(
    registry: ExpertRegistry,
    request: MissionRequest,
) -> tuple[ExpertRegistry, MissionRequest]:
    if not isinstance(registry, ExpertRegistry):
        raise CollaborationPlanError(
            "registry must be an ExpertRegistry"
        )
    if not isinstance(request, MissionRequest):
        raise CollaborationPlanError(
            "request must be a MissionRequest"
        )
    if (
        not isinstance(registry.schema_version, int)
        or isinstance(registry.schema_version, bool)
        or registry.schema_version != 1
    ):
        raise CollaborationPlanError(
            "registry schema_version must be the integer 1"
        )
    if (
        not isinstance(request.schema_version, int)
        or isinstance(request.schema_version, bool)
        or request.schema_version != 1
    ):
        raise CollaborationPlanError(
            "mission schema_version must be the integer 1"
        )
    try:
        validated_registry = ExpertRegistry.from_dict(
            registry.to_dict()
        )
        validated_request = MissionRequest.from_dict(
            request.to_dict()
        )
    except (
        AttributeError,
        MissionError,
        RegistryError,
        TypeError,
        ValueError,
    ) as exc:
        raise CollaborationPlanError(
            "registry and mission must satisfy their strict source contracts"
        ) from exc
    if validated_registry != registry:
        raise CollaborationPlanError(
            "registry must use canonical immutable contract values"
        )
    if validated_request != request:
        raise CollaborationPlanError(
            "mission must use canonical immutable contract values"
        )
    return validated_registry, validated_request


@dataclass(frozen=True)
class WorkItem:
    """One immutable node in a deterministic collaboration plan."""

    schema_version: int
    work_item_id: str
    mission_id: str
    kind: WorkItemKind
    layer: int
    title: str
    role_mission: str
    owner_profile_id: str
    supporting_profile_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    action_tier_ceiling: ActionTier
    required_evidence_level: EvidenceLevel
    deliverable: str
    command_id: str | None
    group_id: str | None

    @classmethod
    def from_dict(cls, raw: Any) -> WorkItem:
        expected = {
            "schema_version",
            "work_item_id",
            "mission_id",
            "kind",
            "layer",
            "title",
            "role_mission",
            "owner_profile_id",
            "supporting_profile_ids",
            "dependency_ids",
            "action_tier_ceiling",
            "required_evidence_level",
            "deliverable",
            "command_id",
            "group_id",
        }
        value = _exact_fields(raw, expected, "work item")
        schema_version = _integer(
            value.get("schema_version"),
            "work item schema_version",
            minimum=1,
        )
        if schema_version != SCHEMA_VERSION:
            raise CollaborationPlanError("work item schema_version must be 1")
        item = cls(
            schema_version=SCHEMA_VERSION,
            work_item_id=_identifier(
                value.get("work_item_id"),
                "work_item_id",
                WORK_ITEM_ID_PATTERN,
            ),
            mission_id=_identifier(
                value.get("mission_id"),
                "work item mission_id",
                MISSION_ID_PATTERN,
            ),
            kind=_enum(WorkItemKind, value.get("kind"), "work item kind"),
            layer=_integer(
                value.get("layer"),
                "work item layer",
                maximum=MAX_TOPOLOGICAL_LAYERS - 1,
            ),
            title=_text(
                value.get("title"),
                "work item title",
            ),
            role_mission=_text(
                value.get("role_mission"),
                "work item role_mission",
            ),
            owner_profile_id=_identifier(
                value.get("owner_profile_id"),
                "work item owner_profile_id",
                PROFILE_ID_PATTERN,
            ),
            supporting_profile_ids=_identifier_list(
                value.get("supporting_profile_ids"),
                "work item supporting_profile_ids",
                PROFILE_ID_PATTERN,
                max_items=MAX_SUPPORTING_PROFILES,
            ),
            dependency_ids=_identifier_list(
                value.get("dependency_ids"),
                "work item dependency_ids",
                WORK_ITEM_ID_PATTERN,
                max_items=MAX_RELATION_IDS,
            ),
            action_tier_ceiling=_enum(
                ActionTier,
                value.get("action_tier_ceiling"),
                "work item action_tier_ceiling",
            ),
            required_evidence_level=_enum(
                EvidenceLevel,
                value.get("required_evidence_level"),
                "work item required_evidence_level",
            ),
            deliverable=_text(
                value.get("deliverable"),
                "work item deliverable",
            ),
            command_id=(
                None
                if value.get("command_id") is None
                else _identifier(
                    value.get("command_id"),
                    "work item command_id",
                    COMMAND_ID_PATTERN,
                )
            ),
            group_id=(
                None
                if value.get("group_id") is None
                else _identifier(
                    value.get("group_id"),
                    "work item group_id",
                    GROUP_ID_PATTERN,
                )
            ),
        )
        item._validate_integrity()
        return item

    def _validate_integrity(self) -> None:
        _integer(
            self.schema_version,
            "work item schema_version",
            minimum=1,
        )
        if self.schema_version != SCHEMA_VERSION:
            raise CollaborationPlanError("work item schema_version must be 1")
        _identifier(self.work_item_id, "work_item_id", WORK_ITEM_ID_PATTERN)
        _identifier(
            self.mission_id,
            "work item mission_id",
            MISSION_ID_PATTERN,
        )
        if not isinstance(self.kind, WorkItemKind):
            raise CollaborationPlanError(
                "work item kind must be a WorkItemKind"
            )
        _integer(
            self.layer,
            "work item layer",
            maximum=MAX_TOPOLOGICAL_LAYERS - 1,
        )
        _text(self.title, "work item title")
        _text(self.role_mission, "work item role_mission")
        _identifier(
            self.owner_profile_id,
            "work item owner_profile_id",
            PROFILE_ID_PATTERN,
        )
        _text(self.deliverable, "work item deliverable")
        _identifier_tuple(
            self.supporting_profile_ids,
            "work item supporting_profile_ids",
            PROFILE_ID_PATTERN,
            max_items=MAX_SUPPORTING_PROFILES,
        )
        _identifier_tuple(
            self.dependency_ids,
            "work item dependency_ids",
            WORK_ITEM_ID_PATTERN,
            max_items=MAX_RELATION_IDS,
        )
        if self.owner_profile_id in self.supporting_profile_ids:
            raise CollaborationPlanError(
                "work item owner cannot also be a supporting profile"
            )
        if not isinstance(self.action_tier_ceiling, ActionTier):
            raise CollaborationPlanError(
                "work item action_tier_ceiling must be an ActionTier"
            )
        if not isinstance(self.required_evidence_level, EvidenceLevel):
            raise CollaborationPlanError(
                "work item required_evidence_level must be an EvidenceLevel"
            )
        if self.command_id is not None:
            _identifier(
                self.command_id,
                "work item command_id",
                COMMAND_ID_PATTERN,
            )
        if self.group_id is not None:
            _identifier(
                self.group_id,
                "work item group_id",
                GROUP_ID_PATTERN,
            )

    def to_dict(self) -> dict[str, Any]:
        self._validate_integrity()
        return {
            "schema_version": self.schema_version,
            "work_item_id": self.work_item_id,
            "mission_id": self.mission_id,
            "kind": self.kind.value,
            "layer": self.layer,
            "title": self.title,
            "role_mission": self.role_mission,
            "owner_profile_id": self.owner_profile_id,
            "supporting_profile_ids": list(self.supporting_profile_ids),
            "dependency_ids": list(self.dependency_ids),
            "action_tier_ceiling": self.action_tier_ceiling.value,
            "required_evidence_level": self.required_evidence_level.value,
            "deliverable": self.deliverable,
            "command_id": self.command_id,
            "group_id": self.group_id,
        }


@dataclass(frozen=True)
class CollaborationPlan:
    """Immutable collaboration graph bound to a registry, mission, and cell."""

    schema_version: int
    plan_id: str
    mission_id: str
    mission_objective: str
    registry_catalog_id: str
    registry_catalog_version: str
    registry_sha256: str
    mission_sha256: str
    joint_mission_cell_sha256: str
    scope_reference: str
    work_items: tuple[WorkItem, ...]
    topological_layers: tuple[tuple[str, ...], ...]
    warnings: tuple[str, ...]
    content_sha256: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlan:
        expected = {
            "schema_version",
            "plan_id",
            "mission_id",
            "mission_objective",
            "registry_catalog_id",
            "registry_catalog_version",
            "registry_sha256",
            "mission_sha256",
            "joint_mission_cell_sha256",
            "scope_reference",
            "work_items",
            "topological_layers",
            "warnings",
            "content_sha256",
        }
        value = _exact_fields(raw, expected, "collaboration plan")
        schema_version = _integer(
            value.get("schema_version"),
            "collaboration plan schema_version",
            minimum=1,
        )
        if schema_version != SCHEMA_VERSION:
            raise CollaborationPlanError(
                "collaboration plan schema_version must be 1"
            )
        raw_work_items = value.get("work_items")
        if not isinstance(raw_work_items, list) or not raw_work_items:
            raise CollaborationPlanError("work_items must be a non-empty list")
        if len(raw_work_items) > MAX_WORK_ITEMS:
            raise CollaborationPlanError(
                f"work_items must not contain more than {MAX_WORK_ITEMS} items"
            )
        raw_layers = value.get("topological_layers")
        if not isinstance(raw_layers, list) or not raw_layers:
            raise CollaborationPlanError(
                "topological_layers must be a non-empty list"
            )
        if len(raw_layers) > MAX_TOPOLOGICAL_LAYERS:
            raise CollaborationPlanError(
                "topological_layers must not contain more than "
                f"{MAX_TOPOLOGICAL_LAYERS} items"
            )
        layers = tuple(
            _identifier_list(
                layer,
                f"topological_layers[{index}]",
                WORK_ITEM_ID_PATTERN,
                max_items=MAX_WORK_ITEMS,
            )
            for index, layer in enumerate(raw_layers)
        )
        if any(not layer for layer in layers):
            raise CollaborationPlanError(
                "topological_layers cannot contain an empty layer"
            )
        warnings = value.get("warnings")
        if not isinstance(warnings, list):
            raise CollaborationPlanError("warnings must be a list")
        if len(warnings) > MAX_WARNINGS:
            raise CollaborationPlanError(
                f"warnings must not contain more than {MAX_WARNINGS} items"
            )
        warning_values = tuple(
            _printable_text(
                item,
                f"warnings[{index}]",
                max_length=2048,
            )
            for index, item in enumerate(warnings)
        )
        if len(warning_values) != len(set(warning_values)):
            raise CollaborationPlanError("warnings contains duplicates")
        plan = cls(
            schema_version=SCHEMA_VERSION,
            plan_id=_identifier(
                value.get("plan_id"),
                "plan_id",
                PLAN_ID_PATTERN,
            ),
            mission_id=_identifier(
                value.get("mission_id"),
                "collaboration plan mission_id",
                MISSION_ID_PATTERN,
            ),
            mission_objective=_text(
                value.get("mission_objective"),
                "collaboration plan mission_objective",
            ),
            registry_catalog_id=_text(
                value.get("registry_catalog_id"),
                "registry_catalog_id",
            ),
            registry_catalog_version=_text(
                value.get("registry_catalog_version"),
                "registry_catalog_version",
            ),
            registry_sha256=_validate_sha256(
                value.get("registry_sha256"),
                "registry_sha256",
            ),
            mission_sha256=_validate_sha256(
                value.get("mission_sha256"),
                "mission_sha256",
            ),
            joint_mission_cell_sha256=_validate_sha256(
                value.get("joint_mission_cell_sha256"),
                "joint_mission_cell_sha256",
            ),
            scope_reference=_text(
                value.get("scope_reference"),
                "collaboration plan scope_reference",
            ),
            work_items=tuple(
                WorkItem.from_dict(item) for item in raw_work_items
            ),
            topological_layers=layers,
            warnings=warning_values,
            content_sha256=_validate_sha256(
                value.get("content_sha256"),
                "content_sha256",
            ),
        )
        plan._validate_integrity()
        return plan

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "mission_objective": self.mission_objective,
            "registry_catalog_id": self.registry_catalog_id,
            "registry_catalog_version": self.registry_catalog_version,
            "registry_sha256": self.registry_sha256,
            "mission_sha256": self.mission_sha256,
            "joint_mission_cell_sha256": self.joint_mission_cell_sha256,
            "scope_reference": self.scope_reference,
            "work_items": [item.to_dict() for item in self.work_items],
            "topological_layers": [
                list(layer) for layer in self.topological_layers
            ],
            "warnings": list(self.warnings),
        }

    def _validate_integrity(self) -> None:
        _integer(
            self.schema_version,
            "collaboration plan schema_version",
            minimum=1,
        )
        if self.schema_version != SCHEMA_VERSION:
            raise CollaborationPlanError(
                "collaboration plan schema_version must be 1"
            )
        _identifier(self.plan_id, "plan_id", PLAN_ID_PATTERN)
        _identifier(
            self.mission_id,
            "collaboration plan mission_id",
            MISSION_ID_PATTERN,
        )
        _text(
            self.mission_objective,
            "collaboration plan mission_objective",
        )
        _text(self.registry_catalog_id, "registry_catalog_id")
        _text(self.registry_catalog_version, "registry_catalog_version")
        _validate_sha256(self.registry_sha256, "registry_sha256")
        _validate_sha256(self.mission_sha256, "mission_sha256")
        _validate_sha256(
            self.joint_mission_cell_sha256,
            "joint_mission_cell_sha256",
        )
        _text(self.scope_reference, "collaboration plan scope_reference")
        _validate_sha256(self.content_sha256, "content_sha256")
        if not isinstance(self.work_items, tuple) or not self.work_items:
            raise CollaborationPlanError("work_items must be non-empty")
        if len(self.work_items) > MAX_WORK_ITEMS:
            raise CollaborationPlanError(
                f"work_items must not contain more than {MAX_WORK_ITEMS} items"
            )
        if (
            not isinstance(self.topological_layers, tuple)
            or not self.topological_layers
        ):
            raise CollaborationPlanError("topological_layers must be non-empty")
        if len(self.topological_layers) > MAX_TOPOLOGICAL_LAYERS:
            raise CollaborationPlanError(
                "topological_layers must not contain more than "
                f"{MAX_TOPOLOGICAL_LAYERS} items"
            )
        if not isinstance(self.warnings, tuple):
            raise CollaborationPlanError("warnings must be a tuple")
        if len(self.warnings) > MAX_WARNINGS:
            raise CollaborationPlanError(
                f"warnings must not contain more than {MAX_WARNINGS} items"
            )
        for item in self.work_items:
            if not isinstance(item, WorkItem):
                raise CollaborationPlanError(
                    "work_items must contain WorkItem values"
                )
            item._validate_integrity()
            if item.mission_id != self.mission_id:
                raise CollaborationPlanError(
                    f"Work item {item.work_item_id} has a different mission_id"
                )
        work_items_by_id = {item.work_item_id: item for item in self.work_items}
        if len(work_items_by_id) != len(self.work_items):
            raise CollaborationPlanError("work_items contains duplicate work_item_id values")
        all_ids = set(work_items_by_id)
        for item in self.work_items:
            missing = set(item.dependency_ids) - all_ids
            if missing:
                names = ", ".join(sorted(missing))
                raise CollaborationPlanError(
                    f"Work item {item.work_item_id} has unknown dependencies: {names}"
                )
            if item.work_item_id in item.dependency_ids:
                raise CollaborationPlanError(
                    f"Work item {item.work_item_id} cannot depend on itself"
                )
        expected_layers = _topological_layers(self.work_items)
        for index, layer in enumerate(self.topological_layers):
            if not isinstance(layer, tuple) or not layer:
                raise CollaborationPlanError(
                    f"topological_layers[{index}] must be a non-empty tuple"
                )
            _identifier_tuple(
                layer,
                f"topological_layers[{index}]",
                WORK_ITEM_ID_PATTERN,
                max_items=MAX_WORK_ITEMS,
            )
        if self.topological_layers != expected_layers:
            raise CollaborationPlanError(
                "topological_layers do not match the work item dependency graph"
            )
        for layer_index, work_item_ids in enumerate(expected_layers):
            for work_item_id in work_item_ids:
                if work_items_by_id[work_item_id].layer != layer_index:
                    raise CollaborationPlanError(
                        f"Work item {work_item_id} has an incorrect layer"
                    )
        if len(self.warnings) != len(set(self.warnings)):
            raise CollaborationPlanError("warnings contains duplicates")
        for index, warning in enumerate(self.warnings):
            _printable_text(
                warning,
                f"warnings[{index}]",
                max_length=2048,
            )
        expected_hash = _sha256(self.unsigned_dict())
        if self.content_sha256 != expected_hash:
            raise CollaborationPlanError(
                "content_sha256 does not match collaboration plan content"
            )

    def to_dict(self) -> dict[str, Any]:
        self._validate_integrity()
        value = self.unsigned_dict()
        value["content_sha256"] = self.content_sha256
        return value


def load_collaboration_plan(path: str | Path) -> CollaborationPlan:
    """Load one collaboration plan from duplicate-key-safe JSON."""

    plan_path = Path(path).resolve()
    if not plan_path.is_file():
        raise CollaborationPlanError(
            f"Collaboration plan file does not exist: {plan_path}"
        )
    try:
        raw = loads_json_without_duplicate_keys(
            plan_path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as exc:
        raise CollaborationPlanError(
            f"Could not read collaboration plan: {plan_path}"
        ) from exc
    return CollaborationPlan.from_dict(raw)


def _topological_layers(
    work_items: tuple[WorkItem, ...],
) -> tuple[tuple[str, ...], ...]:
    by_id = {item.work_item_id: item for item in work_items}
    if len(by_id) != len(work_items):
        raise CollaborationPlanError("work_items contains duplicate work_item_id values")
    remaining = {
        work_item_id: set(item.dependency_ids)
        for work_item_id, item in by_id.items()
    }
    completed: set[str] = set()
    layers: list[tuple[str, ...]] = []
    while remaining:
        ready = tuple(
            sorted(
                work_item_id
                for work_item_id, dependencies in remaining.items()
                if dependencies <= completed
            )
        )
        if not ready:
            raise CollaborationPlanError(
                "work item dependency graph contains a cycle"
            )
        layers.append(ready)
        completed.update(ready)
        for work_item_id in ready:
            del remaining[work_item_id]
    return tuple(layers)


def _work_item(
    *,
    registry: ExpertRegistry,
    request: MissionRequest,
    token: str,
    subject: str,
    kind: WorkItemKind,
    layer: int,
    title: str,
    role_mission: str,
    owner_profile_id: str,
    supporting_profile_ids: tuple[str, ...],
    dependency_ids: tuple[str, ...],
    deliverable: str,
    command_id: str | None = None,
    group_id: str | None = None,
) -> WorkItem:
    owner = registry.profile(owner_profile_id)
    return WorkItem(
        schema_version=SCHEMA_VERSION,
        work_item_id=_work_item_id(token, request.mission_id, subject),
        mission_id=request.mission_id,
        kind=kind,
        layer=layer,
        title=title,
        role_mission=role_mission,
        owner_profile_id=owner_profile_id,
        supporting_profile_ids=tuple(sorted(supporting_profile_ids)),
        dependency_ids=tuple(sorted(dependency_ids)),
        action_tier_ceiling=_action_ceiling(request, owner),
        required_evidence_level=_required_evidence(request, owner),
        deliverable=deliverable,
        command_id=command_id,
        group_id=group_id,
    )


def _represented_commands(
    registry: ExpertRegistry,
    specialist_ids: tuple[str, ...],
) -> tuple[DomainCommand, ...]:
    command_ids = {
        registry.profile(profile_id).command_id
        for profile_id in specialist_ids
    }
    return tuple(
        sorted(
            (
                registry.commands_by_id[command_id]
                for command_id in command_ids
                if command_id is not None
            ),
            key=lambda command: (command.number, command.id),
        )
    )


def _represented_groups(
    registry: ExpertRegistry,
    commands: tuple[DomainCommand, ...],
) -> tuple[ManeuverGroup, ...]:
    group_ids = {command.group_id for command in commands}
    return tuple(
        sorted(
            (registry.groups_by_id[group_id] for group_id in group_ids),
            key=lambda group: group.id,
        )
    )


def _build_work_items(
    registry: ExpertRegistry,
    request: MissionRequest,
) -> tuple[WorkItem, ...]:
    cell = assemble_joint_mission_cell(registry, request)
    profiles = registry.profiles_by_id
    for profile_id in cell.shared_profile_ids:
        requirement = FIXED_SHARED_ROLE_REQUIREMENTS.get(profile_id)
        if requirement is None:
            continue
        category, required_tag, policy_template = requirement
        profile = profiles[profile_id]
        forbidden_tag = (
            "independent-assurance"
            if required_tag == "independent-control"
            else "independent-control"
            if required_tag == "independent-assurance"
            else None
        )
        if (
            profile.kind is not ProfileKind.SHARED
            or profile.category != category
            or profile.policy_template != policy_template
            or required_tag not in profile.tags
            or (
                forbidden_tag is not None
                and forbidden_tag in profile.tags
            )
        ):
            raise CollaborationPlanError(
                f"Fixed collaboration role has invalid semantics: {profile_id}"
            )
    commands = _represented_commands(
        registry,
        cell.specialist_profile_ids,
    )
    groups = _represented_groups(registry, commands)
    items: list[WorkItem] = []

    readiness = _work_item(
        registry=registry,
        request=request,
        token="READY",
        subject="mission-readiness",
        kind=WorkItemKind.READINESS,
        layer=0,
        title="Mission readiness and scope checkpoint",
        role_mission=profiles[READINESS_OWNER_ID].mission,
        owner_profile_id=READINESS_OWNER_ID,
        supporting_profile_ids=(
            READINESS_SUPPORT_IDS
            + tuple(
                profile_id
                for profile_id in READINESS_CONDITIONAL_SUPPORT_IDS
                if profile_id in cell.shared_profile_ids
            )
        ),
        dependency_ids=(),
        deliverable=(
            "Validated mission decomposition, scope boundaries, coordination "
            "assumptions, and toolchain readiness record."
        ),
    )
    items.append(readiness)

    specialist_items: dict[str, WorkItem] = {}
    for profile_id in cell.specialist_profile_ids:
        profile = profiles[profile_id]
        if profile.command_id is None or profile.group_id is None:
            raise CollaborationPlanError(
                f"Specialist {profile_id} has incomplete hierarchy"
            )
        command = registry.commands_by_id[profile.command_id]
        group = registry.groups_by_id[profile.group_id]
        item = _work_item(
            registry=registry,
            request=request,
            token="SPEC",
            subject=profile.id,
            kind=WorkItemKind.SPECIALIST_ANALYSIS,
            layer=1,
            title=f"{profile.name} work package",
            role_mission=profile.mission,
            owner_profile_id=profile.id,
            supporting_profile_ids=(
                command.commander_profile_id,
                group.commander_profile_id,
                EVIDENCE_OWNER_ID,
            ),
            dependency_ids=(readiness.work_item_id,),
            deliverable=(
                "Structured observations, hypotheses, evidence references, "
                "blockers, and commander handoff."
            ),
            command_id=command.id,
            group_id=group.id,
        )
        specialist_items[profile.id] = item
        items.append(item)

    domain_items: dict[str, WorkItem] = {}
    for command in commands:
        selected_specialists = tuple(
            profile_id
            for profile_id in cell.specialist_profile_ids
            if profiles[profile_id].command_id == command.id
        )
        domain_shared_support = tuple(
            profile_id
            for profile_id in DOMAIN_SHARED_PROFILE_IDS.get(
                command.id,
                (),
            )
            if (
                profile_id in cell.shared_profile_ids
                and profile_id != CONTROL_OWNER_ID
                and profile_id not in CONTROL_SUPPORT_IDS
            )
        )
        item = _work_item(
            registry=registry,
            request=request,
            token="DOMAIN",
            subject=command.id,
            kind=WorkItemKind.DOMAIN_SYNTHESIS,
            layer=2,
            title=f"{command.name} synthesis",
            role_mission=command.mission,
            owner_profile_id=command.commander_profile_id,
            supporting_profile_ids=selected_specialists
            + (MISSION_GRAPH_PROFILE_ID,)
            + domain_shared_support,
            dependency_ids=tuple(
                specialist_items[profile_id].work_item_id
                for profile_id in selected_specialists
            ),
            deliverable=command.outputs,
            command_id=command.id,
            group_id=command.group_id,
        )
        domain_items[command.id] = item
        items.append(item)

    group_items: dict[str, WorkItem] = {}
    for group in groups:
        represented_commands = tuple(
            command for command in commands if command.group_id == group.id
        )
        item = _work_item(
            registry=registry,
            request=request,
            token="GROUP",
            subject=group.id,
            kind=WorkItemKind.GROUP_INTEGRATION,
            layer=3,
            title=f"{group.name} integration",
            role_mission=group.mission,
            owner_profile_id=group.commander_profile_id,
            supporting_profile_ids=tuple(
                command.commander_profile_id
                for command in represented_commands
            )
            + (INTEGRATION_OWNER_ID,),
            dependency_ids=tuple(
                domain_items[command.id].work_item_id
                for command in represented_commands
            ),
            deliverable=(
                "Integrated group findings, resolved internal conflicts, "
                "prioritized path transitions, and cross-group handoff."
            ),
            group_id=group.id,
        )
        group_items[group.id] = item
        items.append(item)

    cross_surface = _work_item(
        registry=registry,
        request=request,
        token="CROSS",
        subject="cross-surface-integration",
        kind=WorkItemKind.CROSS_SURFACE_INTEGRATION,
        layer=4,
        title="Cross-surface path integration",
        role_mission=profiles[INTEGRATION_OWNER_ID].mission,
        owner_profile_id=INTEGRATION_OWNER_ID,
        supporting_profile_ids=(
            MISSION_GRAPH_PROFILE_ID,
            DETECTION_PROFILE_ID,
        )
        + tuple(group.commander_profile_id for group in groups),
        dependency_ids=tuple(
            group_items[group.id].work_item_id for group in groups
        ),
        deliverable=(
            "Coherent cross-surface path, joined evidence map, transition "
            "gaps, detection expectations, and deconfliction decisions."
        ),
    )
    items.append(cross_surface)

    control_support = tuple(
        profile_id
        for profile_id in CONTROL_SUPPORT_IDS
        if profile_id in cell.shared_profile_ids
    )
    for profile_id in control_support:
        profile = profiles[profile_id]
        if (
            profile.kind is not ProfileKind.SHARED
            or profile.category != "independent control"
            or "independent-control" not in profile.tags
            or "independent-assurance" in profile.tags
        ):
            raise CollaborationPlanError(
                f"Control support profile has an invalid role: {profile_id}"
            )
    control = _work_item(
        registry=registry,
        request=request,
        token="CONTROL",
        subject="independent-control-review",
        kind=WorkItemKind.CONTROL_REVIEW,
        layer=5,
        title="Independent control review",
        role_mission=profiles[CONTROL_OWNER_ID].mission,
        owner_profile_id=CONTROL_OWNER_ID,
        supporting_profile_ids=control_support,
        dependency_ids=(cross_surface.work_item_id,),
        deliverable=(
            "Independent determination of scope adherence, tier compliance, "
            "stop conditions, unresolved conflicts, and required escalation."
        ),
    )
    items.append(control)

    evidence = _work_item(
        registry=registry,
        request=request,
        token="EVIDENCE",
        subject="evidence-package-review",
        kind=WorkItemKind.EVIDENCE_REVIEW,
        layer=5,
        title="Evidence package review",
        role_mission=profiles[EVIDENCE_OWNER_ID].mission,
        owner_profile_id=EVIDENCE_OWNER_ID,
        supporting_profile_ids=(
            DETECTION_PROFILE_ID,
            CLOSURE_PROFILE_ID,
        ),
        dependency_ids=(cross_surface.work_item_id,),
        deliverable=(
            "Complete evidence manifest with integrity, provenance, custody, "
            "telemetry correlation, retention, and closure criteria."
        ),
    )
    items.append(evidence)

    assurance = _work_item(
        registry=registry,
        request=request,
        token="ASSURE",
        subject="independent-assurance-review",
        kind=WorkItemKind.ASSURANCE_REVIEW,
        layer=6,
        title="Independent assurance review",
        role_mission=profiles[ASSURANCE_OWNER_ID].mission,
        owner_profile_id=ASSURANCE_OWNER_ID,
        supporting_profile_ids=(
            EVIDENCE_OWNER_ID,
            CLOSURE_PROFILE_ID,
        ),
        dependency_ids=(
            control.work_item_id,
            evidence.work_item_id,
        ),
        deliverable=(
            "Independent reproduction result, negative evidence, residual "
            "risk, closure recommendation, and documented exceptions."
        ),
    )
    items.append(assurance)
    referenced_profile_ids = {
        profile_id
        for item in items
        for profile_id in (
            item.owner_profile_id,
            *item.supporting_profile_ids,
        )
    }
    cell_profile_ids = set(cell.all_profile_ids)
    unassigned_profile_ids = cell_profile_ids - referenced_profile_ids
    if unassigned_profile_ids:
        names = ", ".join(sorted(unassigned_profile_ids))
        raise CollaborationPlanError(
            f"Assembled profiles have no collaboration assignment: {names}"
        )
    unassigned_support_ids = referenced_profile_ids - cell_profile_ids
    if unassigned_support_ids:
        names = ", ".join(sorted(unassigned_support_ids))
        raise CollaborationPlanError(
            f"Collaboration assignments use unassembled profiles: {names}"
        )
    return tuple(items)


def build_collaboration_plan(
    registry: ExpertRegistry,
    request: MissionRequest,
) -> CollaborationPlan:
    """Build and validate a deterministic collaboration plan."""

    registry, request = _validated_inputs(registry, request)
    cell = assemble_joint_mission_cell(registry, request)
    work_items = _build_work_items(registry, request)
    topological_layers = _topological_layers(work_items)
    registry_sha256 = _sha256(registry.to_dict())
    mission_sha256 = _sha256(request.to_dict())
    cell_sha256 = _sha256(cell.to_dict())
    identity_material = {
        "registry_sha256": registry_sha256,
        "mission_sha256": mission_sha256,
        "joint_mission_cell_sha256": cell_sha256,
        "work_item_ids": [item.work_item_id for item in work_items],
    }
    plan_id = (
        "CLP-"
        + _domain_hash(
            "sunderkey.collaboration.plan.v1",
            identity_material,
        )[:24].upper()
    )
    partial = CollaborationPlan(
        schema_version=SCHEMA_VERSION,
        plan_id=plan_id,
        mission_id=request.mission_id,
        mission_objective=request.objective,
        registry_catalog_id=registry.catalog_id,
        registry_catalog_version=registry.catalog_version,
        registry_sha256=registry_sha256,
        mission_sha256=mission_sha256,
        joint_mission_cell_sha256=cell_sha256,
        scope_reference=request.scope_reference,
        work_items=work_items,
        topological_layers=topological_layers,
        warnings=cell.warnings,
        content_sha256="sha256:" + ("0" * 64),
    )
    plan = CollaborationPlan(
        **{
            **partial.__dict__,
            "content_sha256": _sha256(partial.unsigned_dict()),
        }
    )
    plan._validate_integrity()
    return plan


def validate_collaboration_plan(
    registry: ExpertRegistry,
    request: MissionRequest,
    plan: CollaborationPlan,
) -> None:
    """Reject a plan that differs from the deterministic expected result."""

    if not isinstance(plan, CollaborationPlan):
        raise CollaborationPlanError(
            "plan must be a CollaborationPlan"
        )
    plan._validate_integrity()
    expected = build_collaboration_plan(registry, request)
    if plan.to_dict() != expected.to_dict():
        raise CollaborationPlanError(
            "collaboration plan does not match the registry and mission"
        )
