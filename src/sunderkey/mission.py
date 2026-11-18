"""Deterministic Joint Mission Cell assembly."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import MissionError
from .registry import ExpertProfile, ExpertRegistry
from .types import ActionTier, EvidenceLevel, MissionEnvironment, ProfileKind
from .validation import (
    DuplicateJsonKeyError,
    is_ascii_text,
    loads_json_without_duplicate_keys,
)

MISSION_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,63}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

CORE_SHARED_PROFILE_IDS = (
    "AOE-HQ-08",
    "AOE-HQ-09",
    "AOE-HQ-10",
    "AOE-HQ-11",
    "AOE-HQ-12",
    "AOE-HQ-18",
    "AOE-HQ-19",
    "AOE-HQ-22",
    "AOE-HQ-25",
    "AOE-HQ-31",
)

DOMAIN_SHARED_PROFILE_IDS = {
    "AOE-GA-D02": ("AOE-HQ-13", "AOE-HQ-15"),
    "AOE-GA-D04": ("AOE-HQ-13", "AOE-HQ-23"),
    "AOE-GB-D09": ("AOE-HQ-14", "AOE-HQ-15"),
    "AOE-GB-D10": ("AOE-HQ-14", "AOE-HQ-15"),
    "AOE-GC-D14": ("AOE-HQ-17",),
    "AOE-GD-D18": ("AOE-HQ-30",),
    "AOE-GD-D19": ("AOE-HQ-14", "AOE-HQ-30"),
    "AOE-GD-D20": ("AOE-HQ-28",),
    "AOE-GE-D21": ("AOE-HQ-15", "AOE-HQ-30"),
    "AOE-GE-D23": ("AOE-HQ-27",),
}


def _text(value: Any, label: str) -> str:
    if not is_ascii_text(value):
        raise MissionError(f"{label} must be non-empty ASCII text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise MissionError(f"{label} must be a boolean")
    return value


def _enum(enum_type: type[Any], value: Any, label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        options = ", ".join(item.value for item in enum_type)
        raise MissionError(f"{label} must be one of: {options}") from exc


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    result = _text(value, label)
    if SHA256_PATTERN.fullmatch(result) is None:
        raise MissionError(
            f"{label} must use sha256 followed by 64 lowercase hexadecimal characters"
        )
    return result


@dataclass(frozen=True)
class MissionConstraints:
    production: bool
    third_party: bool
    synthetic_data_only: bool
    isolated_research_range: bool
    max_cell_size: int

    @classmethod
    def from_dict(cls, raw: Any) -> MissionConstraints:
        if not isinstance(raw, dict):
            raise MissionError("constraints must be an object")
        allowed = {
            "production",
            "third_party",
            "synthetic_data_only",
            "isolated_research_range",
            "max_cell_size",
        }
        unknown = set(raw) - allowed
        if unknown:
            names = ", ".join(sorted(unknown))
            raise MissionError(f"constraints contains unsupported fields: {names}")
        max_cell_size = raw.get("max_cell_size", 20)
        if (
            not isinstance(max_cell_size, int)
            or isinstance(max_cell_size, bool)
            or max_cell_size < 1
        ):
            raise MissionError("constraints.max_cell_size must be a positive integer")
        return cls(
            production=_boolean(raw.get("production", False), "constraints.production"),
            third_party=_boolean(
                raw.get("third_party", False),
                "constraints.third_party",
            ),
            synthetic_data_only=_boolean(
                raw.get("synthetic_data_only", False),
                "constraints.synthetic_data_only",
            ),
            isolated_research_range=_boolean(
                raw.get("isolated_research_range", False),
                "constraints.isolated_research_range",
            ),
            max_cell_size=max_cell_size,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "production": self.production,
            "third_party": self.third_party,
            "synthetic_data_only": self.synthetic_data_only,
            "isolated_research_range": self.isolated_research_range,
            "max_cell_size": self.max_cell_size,
        }


@dataclass(frozen=True)
class MissionRequest:
    schema_version: int
    mission_id: str
    objective: str
    environment: MissionEnvironment
    requested_specialist_ids: tuple[str, ...]
    max_action_tier: ActionTier
    required_evidence_level: EvidenceLevel
    scope_reference: str
    constraints: MissionConstraints
    scope_document_hash: str | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> MissionRequest:
        if not isinstance(raw, dict):
            raise MissionError("mission request must be an object")
        allowed = {
            "schema_version",
            "mission_id",
            "objective",
            "environment",
            "requested_specialist_ids",
            "max_action_tier",
            "required_evidence_level",
            "scope_reference",
            "scope_document_hash",
            "constraints",
        }
        unknown = set(raw) - allowed
        if unknown:
            names = ", ".join(sorted(unknown))
            raise MissionError(f"mission request contains unsupported fields: {names}")
        schema_version = raw.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            raise MissionError("mission schema_version must be the integer 1")
        mission_id = _text(raw.get("mission_id"), "mission_id")
        if MISSION_ID_PATTERN.fullmatch(mission_id) is None:
            raise MissionError(f"Invalid mission_id: {mission_id}")
        requested = raw.get("requested_specialist_ids")
        if not isinstance(requested, list) or not requested:
            raise MissionError("requested_specialist_ids must be a non-empty list")
        requested_ids = tuple(
            _text(item, f"requested_specialist_ids[{index}]")
            for index, item in enumerate(requested)
        )
        if len(requested_ids) != len(set(requested_ids)):
            raise MissionError("requested_specialist_ids contains duplicates")
        request = cls(
            schema_version=1,
            mission_id=mission_id,
            objective=_text(raw.get("objective"), "objective"),
            environment=_enum(
                MissionEnvironment,
                raw.get("environment"),
                "environment",
            ),
            requested_specialist_ids=requested_ids,
            max_action_tier=_enum(
                ActionTier,
                raw.get("max_action_tier"),
                "max_action_tier",
            ),
            required_evidence_level=_enum(
                EvidenceLevel,
                raw.get("required_evidence_level"),
                "required_evidence_level",
            ),
            scope_reference=_text(raw.get("scope_reference"), "scope_reference"),
            constraints=MissionConstraints.from_dict(raw.get("constraints", {})),
            scope_document_hash=_optional_sha256(
                raw.get("scope_document_hash"),
                "scope_document_hash",
            ),
        )
        request.validate_policy()
        return request

    def validate_policy(self) -> None:
        if self.environment is MissionEnvironment.PRODUCTION and not self.constraints.production:
            raise MissionError(
                "Production environment requires constraints.production = true"
            )
        if self.constraints.production and self.environment is not MissionEnvironment.PRODUCTION:
            raise MissionError(
                "constraints.production can be true only for production missions"
            )
        if self.max_action_tier is ActionTier.R5 and (
            self.environment is not MissionEnvironment.SYNTHETIC
            or not self.constraints.isolated_research_range
        ):
            raise MissionError(
                "R5 planning is allowed only in a declared isolated synthetic range"
            )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "environment": self.environment.value,
            "requested_specialist_ids": list(self.requested_specialist_ids),
            "max_action_tier": self.max_action_tier.value,
            "required_evidence_level": self.required_evidence_level.value,
            "scope_reference": self.scope_reference,
            "constraints": self.constraints.to_dict(),
        }
        if self.scope_document_hash is not None:
            value["scope_document_hash"] = self.scope_document_hash
        return value


@dataclass(frozen=True)
class JointMissionCell:
    mission_id: str
    specialist_profile_ids: tuple[str, ...]
    domain_commander_profile_ids: tuple[str, ...]
    group_commander_profile_ids: tuple[str, ...]
    shared_profile_ids: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def all_profile_ids(self) -> tuple[str, ...]:
        return (
            self.specialist_profile_ids
            + self.domain_commander_profile_ids
            + self.group_commander_profile_ids
            + self.shared_profile_ids
        )

    @property
    def size(self) -> int:
        return len(set(self.all_profile_ids))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mission_id": self.mission_id,
            "size": self.size,
            "specialist_profile_ids": list(self.specialist_profile_ids),
            "domain_commander_profile_ids": list(self.domain_commander_profile_ids),
            "group_commander_profile_ids": list(self.group_commander_profile_ids),
            "shared_profile_ids": list(self.shared_profile_ids),
            "warnings": list(self.warnings),
        }


def load_mission_request(path: str | Path) -> MissionRequest:
    mission_path = Path(path).resolve()
    if not mission_path.is_file():
        raise MissionError(f"Mission file does not exist: {mission_path}")
    try:
        raw = loads_json_without_duplicate_keys(
            mission_path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as exc:
        raise MissionError(f"Could not read mission request: {mission_path}") from exc
    return MissionRequest.from_dict(raw)


def _profile_sort_key(profile_id: str) -> tuple[str, int, str]:
    command_match = re.search(r"-D(\d{2})", profile_id)
    command_number = int(command_match.group(1)) if command_match else 0
    return profile_id[:2], command_number, profile_id


def _required_shared_profiles(
    request: MissionRequest,
    command_ids: set[str],
) -> set[str]:
    required = set(CORE_SHARED_PROFILE_IDS)
    if request.max_action_tier.rank >= ActionTier.R1.rank:
        required.add("AOE-HQ-32")
    if request.max_action_tier.rank >= ActionTier.R3.rank or request.constraints.production:
        required.add("AOE-HQ-14")
    if request.constraints.production:
        required.add("AOE-HQ-15")
    if request.constraints.third_party:
        required.add("AOE-HQ-17")
    for command_id in command_ids:
        required.update(DOMAIN_SHARED_PROFILE_IDS.get(command_id, ()))
    return required


def _validate_profile_for_request(profile: ExpertProfile, request: MissionRequest) -> str | None:
    if profile.kind is not ProfileKind.SPECIALIST:
        raise MissionError(f"Requested profile is not a specialist: {profile.id}")
    if profile.status == "retired":
        raise MissionError(f"Requested specialist is retired: {profile.id}")
    if not profile.max_autonomous_tier.allows(request.max_action_tier):
        return (
            f"{profile.id} requires case-specific authorization above "
            f"{profile.max_autonomous_tier.value}"
        )
    return None


def _validate_required_profile(
    profile: ExpertProfile | None,
    profile_id: str,
    expected_kind: ProfileKind,
) -> None:
    if profile is None or profile.kind is not expected_kind:
        raise MissionError(f"Required profile is missing or invalid: {profile_id}")
    if profile.status == "retired":
        raise MissionError(f"Required profile is retired: {profile_id}")


def assemble_joint_mission_cell(
    registry: ExpertRegistry,
    request: MissionRequest,
) -> JointMissionCell:
    profiles_by_id = registry.profiles_by_id
    commands_by_id = registry.commands_by_id
    groups_by_id = registry.groups_by_id

    specialists: set[str] = set()
    command_ids: set[str] = set()
    domain_commanders: set[str] = set()
    group_commanders: set[str] = set()
    warnings: list[str] = []

    for profile_id in request.requested_specialist_ids:
        profile = profiles_by_id.get(profile_id)
        if profile is None:
            raise MissionError(f"Unknown requested specialist: {profile_id}")
        warning = _validate_profile_for_request(profile, request)
        if warning:
            warnings.append(warning)
        specialists.add(profile.id)
        if profile.command_id is None or profile.group_id is None:
            raise MissionError(f"Specialist has incomplete hierarchy: {profile.id}")
        command = commands_by_id[profile.command_id]
        group = groups_by_id[profile.group_id]
        command_ids.add(command.id)
        domain_commanders.add(command.commander_profile_id)
        group_commanders.add(group.commander_profile_id)

    shared = _required_shared_profiles(request, command_ids)
    for profile_id in domain_commanders:
        _validate_required_profile(
            profiles_by_id.get(profile_id),
            profile_id,
            ProfileKind.DOMAIN_COMMANDER,
        )
    for profile_id in shared | group_commanders:
        _validate_required_profile(
            profiles_by_id.get(profile_id),
            profile_id,
            ProfileKind.SHARED,
        )

    cell = JointMissionCell(
        mission_id=request.mission_id,
        specialist_profile_ids=tuple(sorted(specialists, key=_profile_sort_key)),
        domain_commander_profile_ids=tuple(
            sorted(domain_commanders, key=_profile_sort_key)
        ),
        group_commander_profile_ids=tuple(
            sorted(group_commanders, key=_profile_sort_key)
        ),
        shared_profile_ids=tuple(sorted(shared, key=_profile_sort_key)),
        warnings=tuple(sorted(warnings)),
    )
    if cell.size > request.constraints.max_cell_size:
        size_warning = (
            f"Assembled cell size {cell.size} exceeds the requested maximum "
            f"{request.constraints.max_cell_size}"
        )
        cell = JointMissionCell(
            mission_id=cell.mission_id,
            specialist_profile_ids=cell.specialist_profile_ids,
            domain_commander_profile_ids=cell.domain_commander_profile_ids,
            group_commander_profile_ids=cell.group_commander_profile_ids,
            shared_profile_ids=cell.shared_profile_ids,
            warnings=tuple(sorted(cell.warnings + (size_warning,))),
        )
    return cell
