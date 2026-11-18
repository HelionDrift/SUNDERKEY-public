"""Load and validate the versioned expert registry."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import RegistryError
from .types import ActionTier, EvidenceLevel, ProfileKind
from .validation import (
    DuplicateJsonKeyError,
    loads_json_without_duplicate_keys,
)

GROUP_ID_PATTERN = re.compile(r"G[A-E]")
COMMAND_ID_PATTERN = re.compile(r"AOE-G[A-E]-D\d{2}")
SPECIALIST_ID_PATTERN = re.compile(r"AOE-G[A-E]-D\d{2}-S\d{2}")
DOMAIN_COMMANDER_ID_PATTERN = re.compile(r"AOE-G[A-E]-D\d{2}-CMD")
SHARED_ID_PATTERN = re.compile(r"AOE-HQ-\d{2}")
QUALIFICATION_EVENT_ID_PATTERN = re.compile(r"(?:QKD|QST)-[0-9A-F]{32}")
QUALIFICATION_DECISION_ID_PATTERN = re.compile(r"QKD-[0-9A-F]{32}")
QUALIFICATION_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
QUALIFICATION_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
QUALIFICATION_IDENTIFIER_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}"
)

PROFILE_FIELDS = {
    "id",
    "name",
    "kind",
    "version",
    "status",
    "mission",
    "policy_template",
    "max_autonomous_tier",
    "minimum_evidence_level",
    "tags",
    "group_id",
    "command_id",
    "category",
    "pilot",
}
PROFILE_OPTIONAL_FIELDS = {"qualification"}


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RegistryError(f"{label} must be a list")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{label} must be a non-empty string")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    values = _list(value, label)
    result = tuple(_text(item, f"{label}[{index}]") for index, item in enumerate(values))
    if len(result) != len(set(result)):
        raise RegistryError(f"{label} contains duplicate values")
    return result


def _enum(enum_type: type[Any], value: Any, label: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        options = ", ".join(item.value for item in enum_type)
        raise RegistryError(f"{label} must be one of: {options}") from exc


def _exact_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise RegistryError(f"{label} contains unsupported fields: {names}")
    missing = allowed - set(value)
    if missing:
        names = ", ".join(sorted(missing))
        raise RegistryError(f"{label} is missing required fields: {names}")


def _require_ascii(value: Any, label: str) -> None:
    if isinstance(value, str):
        for index, character in enumerate(value):
            code_point = ord(character)
            if code_point > 127 or (code_point < 32 and character not in "\t\n\r"):
                raise RegistryError(
                    f"{label} contains disallowed character U+{code_point:04X} at offset {index}"
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


def _unique(items: Iterable[Any], key: str, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        item_key = getattr(item, key)
        if item_key in result:
            raise RegistryError(f"Duplicate {label}: {item_key}")
        result[item_key] = item
    return result


@dataclass(frozen=True)
class PolicyTemplate:
    id: str
    may: tuple[str, ...]
    may_not: tuple[str, ...]
    stop_conditions: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> PolicyTemplate:
        value = _mapping(raw, f"policy_templates[{index}]")
        _exact_fields(value, {"id", "may", "may_not", "stop_conditions"}, f"policy {index}")
        return cls(
            id=_text(value.get("id"), f"policy_templates[{index}].id"),
            may=_string_tuple(value.get("may"), f"policy_templates[{index}].may"),
            may_not=_string_tuple(
                value.get("may_not"),
                f"policy_templates[{index}].may_not",
            ),
            stop_conditions=_string_tuple(
                value.get("stop_conditions"),
                f"policy_templates[{index}].stop_conditions",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "may": list(self.may),
            "may_not": list(self.may_not),
            "stop_conditions": list(self.stop_conditions),
        }


@dataclass(frozen=True)
class ProfileQualificationRecord:
    """Structurally validated qualification chain head stored in a profile."""

    schema_version: int
    candidate_id: str
    candidate_version: str
    candidate_artifact_sha256: str
    sequence: int
    lifecycle_status: str
    source_event_id: str
    source_event_sha256: str
    current_review_decision_id: str
    current_review_decision_sha256: str
    qualification_valid_until: str
    changed_at: str
    status_binding_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        label: str,
    ) -> ProfileQualificationRecord:
        value = _mapping(raw, label)
        fields = {
            "schema_version",
            "candidate_id",
            "candidate_version",
            "candidate_artifact_sha256",
            "sequence",
            "lifecycle_status",
            "source_event_id",
            "source_event_sha256",
            "current_review_decision_id",
            "current_review_decision_sha256",
            "qualification_valid_until",
            "changed_at",
            "status_binding_sha256",
        }
        _exact_fields(value, fields, label)
        if value.get("schema_version") != 1:
            raise RegistryError(f"{label}.schema_version must be 1")
        sequence = value.get("sequence")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not 1 <= sequence <= 2_147_483_647
        ):
            raise RegistryError(f"{label}.sequence must be a positive integer")
        lifecycle_status = _text(
            value.get("lifecycle_status"),
            f"{label}.lifecycle_status",
        )
        if lifecycle_status not in {"active", "suspended", "revoked"}:
            raise RegistryError(f"{label}.lifecycle_status is invalid")

        def matched(pattern: re.Pattern[str], field: str) -> str:
            parsed = _text(value.get(field), f"{label}.{field}")
            if pattern.fullmatch(parsed) is None:
                raise RegistryError(f"{label}.{field} is invalid")
            return parsed

        valid_until = matched(
            QUALIFICATION_TIMESTAMP_PATTERN,
            "qualification_valid_until",
        )
        changed_at = matched(QUALIFICATION_TIMESTAMP_PATTERN, "changed_at")
        if changed_at >= valid_until:
            raise RegistryError(
                f"{label}.changed_at must precede qualification expiry"
            )
        return cls(
            schema_version=1,
            candidate_id=matched(QUALIFICATION_IDENTIFIER_PATTERN, "candidate_id"),
            candidate_version=matched(
                QUALIFICATION_IDENTIFIER_PATTERN,
                "candidate_version",
            ),
            candidate_artifact_sha256=matched(
                QUALIFICATION_SHA256_PATTERN,
                "candidate_artifact_sha256",
            ),
            sequence=sequence,
            lifecycle_status=lifecycle_status,
            source_event_id=matched(
                QUALIFICATION_EVENT_ID_PATTERN,
                "source_event_id",
            ),
            source_event_sha256=matched(
                QUALIFICATION_SHA256_PATTERN,
                "source_event_sha256",
            ),
            current_review_decision_id=matched(
                QUALIFICATION_DECISION_ID_PATTERN,
                "current_review_decision_id",
            ),
            current_review_decision_sha256=matched(
                QUALIFICATION_SHA256_PATTERN,
                "current_review_decision_sha256",
            ),
            qualification_valid_until=valid_until,
            changed_at=changed_at,
            status_binding_sha256=matched(
                QUALIFICATION_SHA256_PATTERN,
                "status_binding_sha256",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
            "sequence": self.sequence,
            "lifecycle_status": self.lifecycle_status,
            "source_event_id": self.source_event_id,
            "source_event_sha256": self.source_event_sha256,
            "current_review_decision_id": self.current_review_decision_id,
            "current_review_decision_sha256": (
                self.current_review_decision_sha256
            ),
            "qualification_valid_until": self.qualification_valid_until,
            "changed_at": self.changed_at,
            "status_binding_sha256": self.status_binding_sha256,
        }


@dataclass(frozen=True)
class ExpertProfile:
    id: str
    name: str
    kind: ProfileKind
    version: str
    status: str
    mission: str
    policy_template: str
    max_autonomous_tier: ActionTier
    minimum_evidence_level: EvidenceLevel
    tags: tuple[str, ...]
    group_id: str | None
    command_id: str | None
    category: str | None
    pilot: bool
    qualification: ProfileQualificationRecord | None = None

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> ExpertProfile:
        value = _mapping(raw, f"profiles[{index}]")
        unknown = set(value) - PROFILE_FIELDS - PROFILE_OPTIONAL_FIELDS
        if unknown:
            names = ", ".join(sorted(unknown))
            raise RegistryError(
                f"profile {index} contains unsupported fields: {names}"
            )
        missing = PROFILE_FIELDS - set(value)
        if missing:
            names = ", ".join(sorted(missing))
            raise RegistryError(
                f"profile {index} is missing required fields: {names}"
            )
        status = _text(value.get("status"), f"profiles[{index}].status")
        if status not in {
            "defined",
            "qualified",
            "suspended",
            "revoked",
            "retired",
        }:
            raise RegistryError(
                f"profiles[{index}].status is invalid"
            )
        pilot = value.get("pilot", False)
        if not isinstance(pilot, bool):
            raise RegistryError(f"profiles[{index}].pilot must be a boolean")
        return cls(
            id=_text(value.get("id"), f"profiles[{index}].id"),
            name=_text(value.get("name"), f"profiles[{index}].name"),
            kind=_enum(ProfileKind, value.get("kind"), f"profiles[{index}].kind"),
            version=_text(value.get("version"), f"profiles[{index}].version"),
            status=status,
            mission=_text(value.get("mission"), f"profiles[{index}].mission"),
            policy_template=_text(
                value.get("policy_template"),
                f"profiles[{index}].policy_template",
            ),
            max_autonomous_tier=_enum(
                ActionTier,
                value.get("max_autonomous_tier"),
                f"profiles[{index}].max_autonomous_tier",
            ),
            minimum_evidence_level=_enum(
                EvidenceLevel,
                value.get("minimum_evidence_level"),
                f"profiles[{index}].minimum_evidence_level",
            ),
            tags=_string_tuple(value.get("tags"), f"profiles[{index}].tags"),
            group_id=_optional_text(value.get("group_id"), f"profiles[{index}].group_id"),
            command_id=_optional_text(
                value.get("command_id"),
                f"profiles[{index}].command_id",
            ),
            category=_optional_text(value.get("category"), f"profiles[{index}].category"),
            pilot=pilot,
            qualification=(
                None
                if "qualification" not in value
                else ProfileQualificationRecord.from_dict(
                    value.get("qualification"),
                    f"profiles[{index}].qualification",
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "name": self.name,
            "kind": self.kind.value,
            "version": self.version,
            "status": self.status,
            "mission": self.mission,
            "policy_template": self.policy_template,
            "max_autonomous_tier": self.max_autonomous_tier.value,
            "minimum_evidence_level": self.minimum_evidence_level.value,
            "tags": list(self.tags),
            "group_id": self.group_id,
            "command_id": self.command_id,
            "category": self.category,
            "pilot": self.pilot,
        }
        if self.qualification is not None:
            value["qualification"] = self.qualification.to_dict()
        return value


@dataclass(frozen=True)
class DomainCommand:
    id: str
    number: int
    group_id: str
    name: str
    mission: str
    commander_profile_id: str
    specialist_profile_ids: tuple[str, ...]
    inputs: str
    outputs: str
    collaboration: str
    boundary: str

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> DomainCommand:
        value = _mapping(raw, f"commands[{index}]")
        allowed = {
            "id",
            "number",
            "group_id",
            "name",
            "mission",
            "commander_profile_id",
            "specialist_profile_ids",
            "inputs",
            "outputs",
            "collaboration",
            "boundary",
        }
        _exact_fields(value, allowed, f"command {index}")
        number = value.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            raise RegistryError(f"commands[{index}].number must be a positive integer")
        return cls(
            id=_text(value.get("id"), f"commands[{index}].id"),
            number=number,
            group_id=_text(value.get("group_id"), f"commands[{index}].group_id"),
            name=_text(value.get("name"), f"commands[{index}].name"),
            mission=_text(value.get("mission"), f"commands[{index}].mission"),
            commander_profile_id=_text(
                value.get("commander_profile_id"),
                f"commands[{index}].commander_profile_id",
            ),
            specialist_profile_ids=_string_tuple(
                value.get("specialist_profile_ids"),
                f"commands[{index}].specialist_profile_ids",
            ),
            inputs=_text(value.get("inputs"), f"commands[{index}].inputs"),
            outputs=_text(value.get("outputs"), f"commands[{index}].outputs"),
            collaboration=_text(
                value.get("collaboration"),
                f"commands[{index}].collaboration",
            ),
            boundary=_text(value.get("boundary"), f"commands[{index}].boundary"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "number": self.number,
            "group_id": self.group_id,
            "name": self.name,
            "mission": self.mission,
            "commander_profile_id": self.commander_profile_id,
            "specialist_profile_ids": list(self.specialist_profile_ids),
            "inputs": self.inputs,
            "outputs": self.outputs,
            "collaboration": self.collaboration,
            "boundary": self.boundary,
        }


@dataclass(frozen=True)
class ManeuverGroup:
    id: str
    name: str
    mission: str
    commander_profile_id: str
    command_ids: tuple[str, ...]
    specialist_count: int

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> ManeuverGroup:
        value = _mapping(raw, f"groups[{index}]")
        allowed = {
            "id",
            "name",
            "mission",
            "commander_profile_id",
            "command_ids",
            "specialist_count",
        }
        _exact_fields(value, allowed, f"group {index}")
        specialist_count = value.get("specialist_count")
        if (
            not isinstance(specialist_count, int)
            or isinstance(specialist_count, bool)
            or specialist_count <= 0
        ):
            raise RegistryError(
                f"groups[{index}].specialist_count must be a positive integer"
            )
        return cls(
            id=_text(value.get("id"), f"groups[{index}].id"),
            name=_text(value.get("name"), f"groups[{index}].name"),
            mission=_text(value.get("mission"), f"groups[{index}].mission"),
            commander_profile_id=_text(
                value.get("commander_profile_id"),
                f"groups[{index}].commander_profile_id",
            ),
            command_ids=_string_tuple(
                value.get("command_ids"),
                f"groups[{index}].command_ids",
            ),
            specialist_count=specialist_count,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "mission": self.mission,
            "commander_profile_id": self.commander_profile_id,
            "command_ids": list(self.command_ids),
            "specialist_count": self.specialist_count,
        }


@dataclass(frozen=True)
class CountContract:
    groups: int
    commands: int
    specialists: int
    domain_commanders: int
    shared_profiles: int
    total_profiles: int
    pilot_specialists: int

    @classmethod
    def from_dict(cls, raw: Any) -> CountContract:
        value = _mapping(raw, "count_contract")
        fields = {
            "groups",
            "commands",
            "specialists",
            "domain_commanders",
            "shared_profiles",
            "total_profiles",
            "pilot_specialists",
        }
        _exact_fields(value, fields, "count_contract")
        parsed: dict[str, int] = {}
        for field in fields:
            item = value.get(field)
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                raise RegistryError(f"count_contract.{field} must be a non-negative integer")
            parsed[field] = item
        return cls(**parsed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "groups": self.groups,
            "commands": self.commands,
            "specialists": self.specialists,
            "domain_commanders": self.domain_commanders,
            "shared_profiles": self.shared_profiles,
            "total_profiles": self.total_profiles,
            "pilot_specialists": self.pilot_specialists,
        }


@dataclass(frozen=True)
class ExpertRegistry:
    schema_version: int
    catalog_id: str
    catalog_version: str
    policies: tuple[PolicyTemplate, ...]
    groups: tuple[ManeuverGroup, ...]
    commands: tuple[DomainCommand, ...]
    profiles: tuple[ExpertProfile, ...]
    count_contract: CountContract

    @property
    def profiles_by_id(self) -> dict[str, ExpertProfile]:
        return {profile.id: profile for profile in self.profiles}

    @property
    def commands_by_id(self) -> dict[str, DomainCommand]:
        return {command.id: command for command in self.commands}

    @property
    def groups_by_id(self) -> dict[str, ManeuverGroup]:
        return {group.id: group for group in self.groups}

    def profile(self, profile_id: str) -> ExpertProfile:
        try:
            return self.profiles_by_id[profile_id]
        except KeyError as exc:
            raise RegistryError(f"Unknown profile ID: {profile_id}") from exc

    @classmethod
    def from_dict(cls, raw: Any) -> ExpertRegistry:
        value = _mapping(raw, "registry")
        _require_ascii(value, "registry")
        allowed = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "policy_templates",
            "groups",
            "commands",
            "profiles",
            "count_contract",
        }
        _exact_fields(value, allowed, "registry")
        schema_version = value.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != 1
        ):
            raise RegistryError("Registry schema_version must be the integer 1")

        policies = tuple(
            PolicyTemplate.from_dict(item, index)
            for index, item in enumerate(
                _list(value.get("policy_templates"), "policy_templates")
            )
        )
        groups = tuple(
            ManeuverGroup.from_dict(item, index)
            for index, item in enumerate(_list(value.get("groups"), "groups"))
        )
        commands = tuple(
            DomainCommand.from_dict(item, index)
            for index, item in enumerate(_list(value.get("commands"), "commands"))
        )
        profiles = tuple(
            ExpertProfile.from_dict(item, index)
            for index, item in enumerate(_list(value.get("profiles"), "profiles"))
        )
        registry = cls(
            schema_version=1,
            catalog_id=_text(value.get("catalog_id"), "catalog_id"),
            catalog_version=_text(
                value.get("catalog_version"),
                "catalog_version",
            ),
            policies=policies,
            groups=groups,
            commands=commands,
            profiles=profiles,
            count_contract=CountContract.from_dict(
                value.get("count_contract")
            ),
        )
        registry.validate()
        return registry

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "catalog_id": self.catalog_id,
            "catalog_version": self.catalog_version,
            "policy_templates": [
                policy.to_dict() for policy in self.policies
            ],
            "groups": [group.to_dict() for group in self.groups],
            "commands": [command.to_dict() for command in self.commands],
            "profiles": [profile.to_dict() for profile in self.profiles],
            "count_contract": self.count_contract.to_dict(),
        }

    def validate(self) -> None:
        policies = _unique(self.policies, "id", "policy template ID")
        groups = _unique(self.groups, "id", "group ID")
        commands = _unique(self.commands, "id", "command ID")
        profiles = _unique(self.profiles, "id", "profile ID")

        for group in self.groups:
            if GROUP_ID_PATTERN.fullmatch(group.id) is None:
                raise RegistryError(f"Invalid group ID: {group.id}")
            actual_command_ids = {
                command.id for command in self.commands if command.group_id == group.id
            }
            if set(group.command_ids) != actual_command_ids:
                raise RegistryError(f"Group {group.id} command membership is inconsistent")
            group_commander = profiles.get(group.commander_profile_id)
            if group_commander is None:
                raise RegistryError(
                    f"Group {group.id} commander does not exist: "
                    f"{group.commander_profile_id}"
                )
            if (
                group_commander.kind is not ProfileKind.SHARED
                or group_commander.category != "group command"
                or group_commander.group_id != group.id
            ):
                raise RegistryError(f"Group {group.id} commander profile is invalid")
            actual_specialists = sum(
                len(command.specialist_profile_ids)
                for command in self.commands
                if command.group_id == group.id
            )
            if actual_specialists != group.specialist_count:
                raise RegistryError(
                    f"Group {group.id} expects {group.specialist_count} specialists, "
                    f"found {actual_specialists}"
                )

        command_numbers: set[int] = set()
        for command in self.commands:
            if COMMAND_ID_PATTERN.fullmatch(command.id) is None:
                raise RegistryError(f"Invalid command ID: {command.id}")
            expected_command_id = f"AOE-{command.group_id}-D{command.number:02d}"
            if command.id != expected_command_id:
                raise RegistryError(
                    f"Command {command.id} does not match group and number "
                    f"{command.group_id}/{command.number}"
                )
            if command.number in command_numbers:
                raise RegistryError(f"Duplicate command number: {command.number}")
            command_numbers.add(command.number)
            if command.group_id not in groups:
                raise RegistryError(
                    f"Command {command.id} references unknown group {command.group_id}"
                )
            commander = profiles.get(command.commander_profile_id)
            if commander is None:
                raise RegistryError(
                    f"Command {command.id} commander does not exist: "
                    f"{command.commander_profile_id}"
                )
            if (
                commander.kind is not ProfileKind.DOMAIN_COMMANDER
                or commander.command_id != command.id
                or commander.group_id != command.group_id
                or commander.id != f"{command.id}-CMD"
            ):
                raise RegistryError(f"Command {command.id} commander profile is invalid")
            actual_specialist_ids = {
                profile.id
                for profile in self.profiles
                if (
                    profile.kind is ProfileKind.SPECIALIST
                    and profile.command_id == command.id
                )
            }
            if set(command.specialist_profile_ids) != actual_specialist_ids:
                raise RegistryError(
                    f"Command {command.id} specialist membership is inconsistent"
                )
            for profile_id in command.specialist_profile_ids:
                profile = profiles.get(profile_id)
                if profile is None:
                    raise RegistryError(
                        f"Command {command.id} specialist does not exist: {profile_id}"
                    )
                if (
                    profile.kind is not ProfileKind.SPECIALIST
                    or profile.command_id != command.id
                    or profile.group_id != command.group_id
                ):
                    raise RegistryError(
                        f"Command {command.id} specialist profile is invalid: {profile_id}"
                    )

        expected_command_numbers = set(range(1, len(self.commands) + 1))
        if command_numbers != expected_command_numbers:
            raise RegistryError("Command numbers must be contiguous from 1")

        for profile in self.profiles:
            if profile.policy_template not in policies:
                raise RegistryError(
                    f"Profile {profile.id} references unknown policy "
                    f"{profile.policy_template}"
                )
            if profile.kind is ProfileKind.SPECIALIST:
                pattern = SPECIALIST_ID_PATTERN
                if profile.command_id not in commands:
                    raise RegistryError(
                        f"Specialist {profile.id} references unknown command "
                        f"{profile.command_id}"
                    )
                if not profile.id.startswith(f"{profile.command_id}-S"):
                    raise RegistryError(
                        f"Specialist {profile.id} ID does not match "
                        f"command {profile.command_id}"
                    )
            elif profile.kind is ProfileKind.DOMAIN_COMMANDER:
                pattern = DOMAIN_COMMANDER_ID_PATTERN
                if profile.command_id not in commands:
                    raise RegistryError(
                        f"Commander {profile.id} references unknown command "
                        f"{profile.command_id}"
                    )
                if profile.id != f"{profile.command_id}-CMD":
                    raise RegistryError(
                        f"Commander {profile.id} ID does not match "
                        f"command {profile.command_id}"
                    )
            else:
                pattern = SHARED_ID_PATTERN
                if profile.command_id is not None:
                    raise RegistryError(
                        f"Shared profile {profile.id} cannot have a command_id"
                    )
            if profile.pilot and profile.kind is not ProfileKind.SPECIALIST:
                raise RegistryError(
                    f"Profile {profile.id} cannot be a pilot specialist"
                )
            qualification = profile.qualification
            if qualification is not None:
                if profile.kind is not ProfileKind.SPECIALIST:
                    raise RegistryError(
                        f"Profile {profile.id} cannot carry qualification state"
                    )
                expected_status = {
                    "active": "qualified",
                    "suspended": "suspended",
                    "revoked": "revoked",
                }[qualification.lifecycle_status]
                if profile.status != expected_status:
                    raise RegistryError(
                        f"Profile {profile.id} status does not match its "
                        "qualification state"
                    )
            elif profile.status in {"suspended", "revoked"}:
                raise RegistryError(
                    f"Profile {profile.id} requires qualification state for "
                    f"status {profile.status}"
                )
            if pattern.fullmatch(profile.id) is None:
                raise RegistryError(f"Profile ID does not match its kind: {profile.id}")
            if profile.group_id is not None and profile.group_id not in groups:
                raise RegistryError(
                    f"Profile {profile.id} references unknown group {profile.group_id}"
                )

        by_kind = {
            kind: sum(profile.kind is kind for profile in self.profiles)
            for kind in ProfileKind
        }
        actual_counts = {
            "groups": len(self.groups),
            "commands": len(self.commands),
            "specialists": by_kind[ProfileKind.SPECIALIST],
            "domain_commanders": by_kind[ProfileKind.DOMAIN_COMMANDER],
            "shared_profiles": by_kind[ProfileKind.SHARED],
            "total_profiles": len(self.profiles),
            "pilot_specialists": sum(
                profile.kind is ProfileKind.SPECIALIST and profile.pilot
                for profile in self.profiles
            ),
        }
        for field, actual in actual_counts.items():
            expected = getattr(self.count_contract, field)
            if actual != expected:
                raise RegistryError(
                    f"Count contract mismatch for {field}: expected {expected}, "
                    f"found {actual}"
                )


def load_registry(path: str | Path) -> ExpertRegistry:
    registry_path = Path(path).resolve()
    if not registry_path.is_file():
        raise RegistryError(f"Registry file does not exist: {registry_path}")
    try:
        raw = loads_json_without_duplicate_keys(
            registry_path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as exc:
        raise RegistryError(f"Could not read registry: {registry_path}") from exc

    return ExpertRegistry.from_dict(raw)
