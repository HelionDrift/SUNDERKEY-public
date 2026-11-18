"""Authenticated identity requirements for collaboration plan replacement."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collaboration_plan_replacement_preflight import (
    AUTHORITY_INTENT_DOMAIN,
    CollaborationPlanReplacementPreflight,
)
from .errors import CollaborationPlanError
from .identity import PrincipalOperation, compute_operation_intent_hash
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry, load_registry
from .types import ProfileKind
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 2
UPGRADE_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-upgrade.v2"
REQUIREMENT_DOMAIN = "sunderkey.collaboration-plan-replacement-authenticated-requirement.v2"
SOURCE_REQUIREMENT_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-requirement.v1"
COMMAND_AUTHORITY_BINDING_DOMAIN = (
    "sunderkey.collaboration-plan-replacement-command-authority-binding.v1"
)
ARMY_CATALOG_ID = "sunderkey-offensive-expert-army"
ARMY_CATALOG_VERSION = "2.0.0"
ARMY_REGISTRY_SHA256 = "sha256:2f9c94a2baa3f8445c646b473a87ee54c006a9d1298d2013ec484be83cc0882b"

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
UPGRADE_ID_PATTERN = re.compile(r"PRU-[0-9A-F]{32}")
REQUIREMENT_ID_PATTERN = re.compile(r"PRA-[0-9A-F]{32}")
SOURCE_REQUIREMENT_ID_PATTERN = re.compile(r"PAR-[0-9A-F]{32}")
PREFLIGHT_ID_PATTERN = re.compile(r"PRF-[0-9A-F]{32}")
MISSION_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,63}")
PLAN_ID_PATTERN = re.compile(r"CLP-[0-9A-F]{24}")
WORK_ITEM_ID_PATTERN = re.compile(r"WIT-[A-Z]{2,16}-[0-9A-F]{16}")
PROFILE_ID_PATTERN = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})")
COMMAND_ID_PATTERN = re.compile(r"AOE-G[A-E]-D[0-9]{2}")

PROFILE_OPERATION_CONTRACTS = {
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE: (
        "mission_owner",
        False,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE: (
        "independent_control",
        False,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE: (
        "current_owner",
        True,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT: (
        "proposed_owner",
        True,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL: (
        "current_owner",
        True,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE: (
        "independent_assurance",
        False,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE: (
        "second_control",
        False,
    ),
}
COMMAND_OPERATION_CONTRACTS = {
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW: (
        "source_technical_command",
        True,
    ),
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW: (
        "destination_technical_command",
        True,
    ),
}
OPERATION_CONTRACTS = {**PROFILE_OPERATION_CONTRACTS, **COMMAND_OPERATION_CONTRACTS}

SOURCE_REFERENCE_FIELDS = frozenset({"preflight_id", "preflight_sha256"})
PLAN_REFERENCE_FIELDS = frozenset({"plan_id", "plan_sha256"})
REGISTRY_REFERENCE_FIELDS = frozenset({"catalog_id", "catalog_version", "registry_sha256"})
PROFILE_REQUIREMENT_FIELDS = frozenset(
    {
        "requirement_id",
        "source_requirement_id",
        "role",
        "authority_id",
        "authority_kind",
        "operation",
        "work_item_id",
        "selection_sha256",
        "authority_intent_sha256",
        "principal_profile_id",
        "principal_operation_intent_sha256",
    }
)
COMMAND_REQUIREMENT_FIELDS = PROFILE_REQUIREMENT_FIELDS | {"command_authority_binding_sha256"}


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CollaborationPlanError(f"{label} must be an object")
    return value


def _exact_fields(value: dict[str, Any], fields: set[str], label: str) -> None:
    unknown = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if unknown:
        raise CollaborationPlanError(f"{label} contains unsupported fields: {', '.join(unknown)}")
    if missing:
        raise CollaborationPlanError(f"{label} is missing required fields: {', '.join(missing)}")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _optional_work_item_id(value: Any, *, required: bool, label: str) -> str | None:
    if value is None:
        if required:
            raise CollaborationPlanError(f"{label} requires a work item")
        return None
    if not required:
        raise CollaborationPlanError(f"{label} must not bind a work item")
    result = _identifier(value, label)
    if WORK_ITEM_ID_PATTERN.fullmatch(result) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return result


def _source_authority_intent_sha256(
    source: dict[str, Any],
    selection_sha256: str,
) -> str:
    body = {
        "role": source["role"],
        "authority_id": source["authority_id"],
        "authority_kind": source["authority_kind"],
        "operation": source["operation"],
        "work_item_id": source["work_item_id"],
        "selection_sha256": selection_sha256,
    }
    return _canonical_sha256({"domain": AUTHORITY_INTENT_DOMAIN, "authority_intent": body})


def _registry_binding(registry: ExpertRegistry) -> dict[str, str]:
    if not isinstance(registry, ExpertRegistry):
        raise CollaborationPlanError("army_registry must be an ExpertRegistry")
    normalized = ExpertRegistry.from_dict(registry.to_dict())
    if (
        normalized.catalog_id != ARMY_CATALOG_ID
        or normalized.catalog_version != ARMY_CATALOG_VERSION
    ):
        raise CollaborationPlanError("Plan replacement requires the exact Army v2 catalog")
    registry_sha256 = _canonical_sha256(normalized.to_dict())
    if registry_sha256 != ARMY_REGISTRY_SHA256:
        raise CollaborationPlanError("Plan replacement requires the exact Army v2 registry")
    return {
        "catalog_id": normalized.catalog_id,
        "catalog_version": normalized.catalog_version,
        "registry_sha256": registry_sha256,
    }


def _command_authority_binding_sha256(
    *,
    command_id: str,
    commander_profile_id: str,
    registry_sha256: str,
    mission_id: str,
    prior_plan: dict[str, str],
    replacement_plan: dict[str, str],
    operation: PrincipalOperation,
    role: str,
    work_item_id: str,
    selection_sha256: str,
) -> str:
    body = {
        "command_id": command_id,
        "commander_profile_id": commander_profile_id,
        "army_registry_sha256": registry_sha256,
        "mission_id": mission_id,
        "prior_plan_id": prior_plan["plan_id"],
        "prior_plan_sha256": prior_plan["plan_sha256"],
        "replacement_plan_id": replacement_plan["plan_id"],
        "replacement_plan_sha256": replacement_plan["plan_sha256"],
        "operation": operation.value,
        "role": role,
        "work_item_id": work_item_id,
        "selection_sha256": selection_sha256,
    }
    return _canonical_sha256({"domain": COMMAND_AUTHORITY_BINDING_DOMAIN, "binding": body})


def _authenticated_requirement(
    *,
    source: dict[str, Any],
    preflight_document: dict[str, Any],
    registry: ExpertRegistry,
    registry_binding: dict[str, str],
) -> dict[str, Any]:
    try:
        operation = PrincipalOperation(source["operation"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CollaborationPlanError(
            "Plan replacement authority operation is not supported by identity"
        ) from exc
    try:
        expected_role, requires_work_item = OPERATION_CONTRACTS[operation]
    except KeyError as exc:
        raise CollaborationPlanError(
            "Plan replacement authority operation is not an authenticated replacement operation"
        ) from exc
    role = _identifier(source.get("role"), "authority requirement role")
    if role != expected_role:
        raise CollaborationPlanError("Plan replacement authority role does not match operation")
    work_item_id = _optional_work_item_id(
        source.get("work_item_id"),
        required=requires_work_item,
        label="authority requirement work_item_id",
    )
    authority_id = _identifier(source.get("authority_id"), "authority requirement authority_id")
    selection_sha256 = _sha256(
        preflight_document["selection_sha256"],
        "preflight selection_sha256",
    )
    authority_intent_sha256 = _source_authority_intent_sha256(
        source,
        selection_sha256,
    )
    if source.get("operation_intent_sha256") != authority_intent_sha256:
        raise CollaborationPlanError("Phase184 authority intent binding is invalid")
    source_requirement_id = source.get("requirement_id")
    if (
        not isinstance(source_requirement_id, str)
        or SOURCE_REQUIREMENT_ID_PATTERN.fullmatch(source_requirement_id) is None
    ):
        raise CollaborationPlanError("Source authority requirement identity is invalid")

    command_binding_sha256: str | None = None
    if operation in COMMAND_OPERATION_CONTRACTS:
        if source.get("authority_kind") != "command" or work_item_id is None:
            raise CollaborationPlanError("Command authority requirement kind is invalid")
        command = registry.commands_by_id.get(authority_id)
        if command is None:
            raise CollaborationPlanError(
                "Command authority is absent from the exact Army v2 registry"
            )
        commander = registry.profiles_by_id.get(command.commander_profile_id)
        if (
            commander is None
            or commander.id != command.commander_profile_id
            or commander.command_id != command.id
        ):
            raise CollaborationPlanError("Command commander profile is invalid")
        principal_profile_id = commander.id
        command_binding_sha256 = _command_authority_binding_sha256(
            command_id=command.id,
            commander_profile_id=principal_profile_id,
            registry_sha256=registry_binding["registry_sha256"],
            mission_id=preflight_document["mission_id"],
            prior_plan=preflight_document["prior_plan"],
            replacement_plan=preflight_document["replacement_plan"],
            operation=operation,
            role=role,
            work_item_id=work_item_id,
            selection_sha256=selection_sha256,
        )
    else:
        if source.get("authority_kind") != "principal_profile":
            raise CollaborationPlanError("Profile authority requirement kind is invalid")
        principal_profile_id = authority_id
        profile = registry.profiles_by_id.get(principal_profile_id)
        if profile is None:
            raise CollaborationPlanError(
                "Profile authority is absent from the exact Army v2 registry"
            )
        independent_category = {
            "independent_control": (
                "independent control",
                "independent-control",
            ),
            "second_control": (
                "independent control",
                "independent-control",
            ),
            "independent_assurance": (
                "independent assurance",
                "independent-assurance",
            ),
        }.get(role)
        if independent_category is not None:
            category, tag = independent_category
            if (
                profile.kind is not ProfileKind.SHARED
                or profile.category != category
                or tag not in profile.tags
            ):
                raise CollaborationPlanError(
                    "Independent replacement authority has an invalid registry role"
                )

    principal_intent: dict[str, Any] = {
        "authority_intent_sha256": authority_intent_sha256,
        "mission_id": preflight_document["mission_id"],
        "principal_profile_id": principal_profile_id,
        "prior_plan_id": preflight_document["prior_plan"]["plan_id"],
        "prior_plan_sha256": preflight_document["prior_plan"]["plan_sha256"],
        "replacement_plan_id": preflight_document["replacement_plan"]["plan_id"],
        "replacement_plan_sha256": preflight_document["replacement_plan"]["plan_sha256"],
        "role": role,
        "selection_sha256": selection_sha256,
        "work_item_id": work_item_id,
    }
    if command_binding_sha256 is not None:
        principal_intent["command_authority_binding_sha256"] = command_binding_sha256
    principal_operation_intent_sha256 = compute_operation_intent_hash(
        operation,
        principal_intent,
    )
    body = {
        "source_requirement_id": source_requirement_id,
        "role": role,
        "authority_id": authority_id,
        "authority_kind": source["authority_kind"],
        "operation": operation.value,
        "work_item_id": work_item_id,
        "selection_sha256": selection_sha256,
        "authority_intent_sha256": authority_intent_sha256,
        "principal_profile_id": principal_profile_id,
        "principal_operation_intent_sha256": principal_operation_intent_sha256,
    }
    if command_binding_sha256 is not None:
        body["command_authority_binding_sha256"] = command_binding_sha256
    digest = _canonical_sha256({"domain": REQUIREMENT_DOMAIN, "requirement": body})
    return {
        "requirement_id": "PRA-" + digest.removeprefix("sha256:")[:32].upper(),
        **body,
    }


def _validate_requirement_shape(
    raw: Any,
    index: int,
    *,
    mission_id: str,
    prior_plan: dict[str, str],
    replacement_plan: dict[str, str],
    selection_sha256: str,
    registry_sha256: str,
) -> dict[str, Any]:
    label = f"authority_requirements[{index}]"
    value = _mapping(raw, label)
    authority_kind = value.get("authority_kind")
    expected_fields = (
        COMMAND_REQUIREMENT_FIELDS if authority_kind == "command" else PROFILE_REQUIREMENT_FIELDS
    )
    _exact_fields(value, set(expected_fields), label)
    requirement_id = value.get("requirement_id")
    if (
        not isinstance(requirement_id, str)
        or REQUIREMENT_ID_PATTERN.fullmatch(requirement_id) is None
    ):
        raise CollaborationPlanError(f"{label}.requirement_id is invalid")
    source_requirement_id = value.get("source_requirement_id")
    if (
        not isinstance(source_requirement_id, str)
        or SOURCE_REQUIREMENT_ID_PATTERN.fullmatch(source_requirement_id) is None
    ):
        raise CollaborationPlanError(f"{label}.source_requirement_id is invalid")
    for field in (
        "selection_sha256",
        "authority_intent_sha256",
        "principal_operation_intent_sha256",
    ):
        _sha256(value.get(field), f"{label}.{field}")
    _identifier(value.get("authority_id"), f"{label}.authority_id")
    _identifier(value.get("principal_profile_id"), f"{label}.principal_profile_id")
    try:
        operation = PrincipalOperation(value.get("operation"))
        expected_role, requires_work_item = OPERATION_CONTRACTS[operation]
    except (TypeError, ValueError, KeyError) as exc:
        raise CollaborationPlanError(f"{label}.operation is invalid") from exc
    if value.get("role") != expected_role:
        raise CollaborationPlanError(f"{label}.role does not match operation")
    _optional_work_item_id(
        value.get("work_item_id"),
        required=requires_work_item,
        label=f"{label}.work_item_id",
    )
    if authority_kind == "principal_profile":
        if operation not in PROFILE_OPERATION_CONTRACTS:
            raise CollaborationPlanError(f"{label} uses a command operation")
        if PROFILE_ID_PATTERN.fullmatch(value["authority_id"]) is None:
            raise CollaborationPlanError(f"{label}.authority_id is invalid")
        if PROFILE_ID_PATTERN.fullmatch(value["principal_profile_id"]) is None:
            raise CollaborationPlanError(f"{label}.principal_profile_id is invalid")
        if value["principal_profile_id"] != value["authority_id"]:
            raise CollaborationPlanError(f"{label}.principal_profile_id must equal authority_id")
    elif authority_kind == "command":
        if operation not in COMMAND_OPERATION_CONTRACTS:
            raise CollaborationPlanError(f"{label} uses a profile operation")
        if COMMAND_ID_PATTERN.fullmatch(value["authority_id"]) is None:
            raise CollaborationPlanError(f"{label}.authority_id is invalid")
        if PROFILE_ID_PATTERN.fullmatch(value["principal_profile_id"]) is None:
            raise CollaborationPlanError(f"{label}.principal_profile_id is invalid")
        if value["principal_profile_id"] != f"{value['authority_id']}-CMD":
            raise CollaborationPlanError(
                f"{label}.principal_profile_id does not identify the command commander"
            )
        _sha256(
            value.get("command_authority_binding_sha256"),
            f"{label}.command_authority_binding_sha256",
        )
    else:
        raise CollaborationPlanError(f"{label}.authority_kind is invalid")

    if value["selection_sha256"] != selection_sha256:
        raise CollaborationPlanError(f"{label}.selection_sha256 does not match the upgrade")
    source_shape = {
        "role": value["role"],
        "authority_id": value["authority_id"],
        "authority_kind": authority_kind,
        "operation": operation.value,
        "work_item_id": value["work_item_id"],
    }
    expected_authority_intent_sha256 = _source_authority_intent_sha256(
        source_shape,
        selection_sha256,
    )
    if value["authority_intent_sha256"] != expected_authority_intent_sha256:
        raise CollaborationPlanError(f"{label}.authority_intent_sha256 is invalid")
    source_requirement_body = {
        **source_shape,
        "selection_sha256": selection_sha256,
        "operation_intent_sha256": expected_authority_intent_sha256,
    }
    source_requirement_sha256 = _canonical_sha256(
        {
            "domain": SOURCE_REQUIREMENT_DOMAIN,
            "requirement": source_requirement_body,
        }
    )
    expected_source_requirement_id = (
        "PAR-" + source_requirement_sha256.removeprefix("sha256:")[:32].upper()
    )
    if source_requirement_id != expected_source_requirement_id:
        raise CollaborationPlanError(f"{label}.source_requirement_id is invalid")

    principal_intent: dict[str, Any] = {
        "authority_intent_sha256": expected_authority_intent_sha256,
        "mission_id": mission_id,
        "principal_profile_id": value["principal_profile_id"],
        "prior_plan_id": prior_plan["plan_id"],
        "prior_plan_sha256": prior_plan["plan_sha256"],
        "replacement_plan_id": replacement_plan["plan_id"],
        "replacement_plan_sha256": replacement_plan["plan_sha256"],
        "role": value["role"],
        "selection_sha256": selection_sha256,
        "work_item_id": value["work_item_id"],
    }
    if authority_kind == "command":
        expected_command_binding_sha256 = _command_authority_binding_sha256(
            command_id=value["authority_id"],
            commander_profile_id=value["principal_profile_id"],
            registry_sha256=registry_sha256,
            mission_id=mission_id,
            prior_plan=prior_plan,
            replacement_plan=replacement_plan,
            operation=operation,
            role=value["role"],
            work_item_id=value["work_item_id"],
            selection_sha256=selection_sha256,
        )
        if value["command_authority_binding_sha256"] != expected_command_binding_sha256:
            raise CollaborationPlanError(f"{label}.command_authority_binding_sha256 is invalid")
        principal_intent["command_authority_binding_sha256"] = expected_command_binding_sha256
    expected_principal_intent_sha256 = compute_operation_intent_hash(
        operation,
        principal_intent,
    )
    if value["principal_operation_intent_sha256"] != expected_principal_intent_sha256:
        raise CollaborationPlanError(f"{label}.principal_operation_intent_sha256 is invalid")
    body = {key: item for key, item in value.items() if key != "requirement_id"}
    digest = _canonical_sha256({"domain": REQUIREMENT_DOMAIN, "requirement": body})
    expected_id = "PRA-" + digest.removeprefix("sha256:")[:32].upper()
    if requirement_id != expected_id:
        raise CollaborationPlanError(f"{label} hash identity is invalid")
    return dict(value)


@dataclass(frozen=True)
class CollaborationPlanReplacementAuthorityUpgrade:
    """Inactive v2 identity upgrade for one Phase184 replacement preflight."""

    upgrade_id: str
    upgrade_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlanReplacementAuthorityUpgrade:
        value = _mapping(raw, "plan replacement authority upgrade")
        fields = {
            "schema_version",
            "upgrade_id",
            "upgrade_sha256",
            "source_preflight",
            "army_registry",
            "mission_id",
            "prior_plan",
            "replacement_plan",
            "selection_sha256",
            "authority_requirements",
            "authentication_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "plan replacement authority upgrade")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Plan replacement authority upgrade version is invalid")
        upgrade_id = value.get("upgrade_id")
        if not isinstance(upgrade_id, str) or UPGRADE_ID_PATTERN.fullmatch(upgrade_id) is None:
            raise CollaborationPlanError("Plan replacement authority upgrade identity is invalid")
        upgrade_sha256 = _sha256(value.get("upgrade_sha256"), "upgrade_sha256")
        source = _mapping(value.get("source_preflight"), "source_preflight")
        _exact_fields(source, set(SOURCE_REFERENCE_FIELDS), "source_preflight")
        preflight_id = _identifier(source.get("preflight_id"), "source_preflight.preflight_id")
        if PREFLIGHT_ID_PATTERN.fullmatch(preflight_id) is None:
            raise CollaborationPlanError("source_preflight.preflight_id is invalid")
        _sha256(source.get("preflight_sha256"), "source_preflight.preflight_sha256")
        registry = _mapping(value.get("army_registry"), "army_registry")
        _exact_fields(registry, set(REGISTRY_REFERENCE_FIELDS), "army_registry")
        if (
            registry.get("catalog_id") != ARMY_CATALOG_ID
            or registry.get("catalog_version") != ARMY_CATALOG_VERSION
            or registry.get("registry_sha256") != ARMY_REGISTRY_SHA256
        ):
            raise CollaborationPlanError("Army registry binding is not Army v2")
        _sha256(registry.get("registry_sha256"), "army_registry.registry_sha256")
        mission_id = _identifier(value.get("mission_id"), "mission_id")
        if MISSION_ID_PATTERN.fullmatch(mission_id) is None:
            raise CollaborationPlanError("mission_id is invalid")
        plans: dict[str, dict[str, str]] = {}
        for name in ("prior_plan", "replacement_plan"):
            reference = _mapping(value.get(name), name)
            _exact_fields(reference, set(PLAN_REFERENCE_FIELDS), name)
            plan_id = _identifier(reference.get("plan_id"), f"{name}.plan_id")
            if PLAN_ID_PATTERN.fullmatch(plan_id) is None:
                raise CollaborationPlanError(f"{name}.plan_id is invalid")
            _sha256(reference.get("plan_sha256"), f"{name}.plan_sha256")
            plans[name] = dict(reference)
        if plans["prior_plan"] == plans["replacement_plan"]:
            raise CollaborationPlanError("Replacement plan must differ from prior plan")
        selection_sha256 = _sha256(
            value.get("selection_sha256"),
            "selection_sha256",
        )
        raw_requirements = value.get("authority_requirements")
        if not isinstance(raw_requirements, list) or not raw_requirements:
            raise CollaborationPlanError("authority_requirements must be a non-empty list")
        requirements = [
            _validate_requirement_shape(
                item,
                index,
                mission_id=mission_id,
                prior_plan=plans["prior_plan"],
                replacement_plan=plans["replacement_plan"],
                selection_sha256=selection_sha256,
                registry_sha256=registry["registry_sha256"],
            )
            for index, item in enumerate(raw_requirements)
        ]
        ids = [item["requirement_id"] for item in requirements]
        source_ids = [item["source_requirement_id"] for item in requirements]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise CollaborationPlanError(
                "Authenticated authority requirements must be unique and sorted"
            )
        if len(source_ids) != len(set(source_ids)):
            raise CollaborationPlanError("Source authority requirements must be unique")
        if value.get("authentication_status") != "principal_assertions_required":
            raise CollaborationPlanError("Plan replacement authentication status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Plan replacement authority upgrade must be inactive")
        body = {
            key: item for key, item in value.items() if key not in {"upgrade_id", "upgrade_sha256"}
        }
        digest = _canonical_sha256({"domain": UPGRADE_DOMAIN, "upgrade": body})
        expected_id = "PRU-" + digest.removeprefix("sha256:")[:32].upper()
        if upgrade_sha256 != digest or upgrade_id != expected_id:
            raise CollaborationPlanError("Plan replacement authority upgrade hash is invalid")
        return cls(
            upgrade_id=upgrade_id,
            upgrade_sha256=upgrade_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Plan replacement authority upgrade is invalid")
        return value


def build_collaboration_plan_replacement_authority_upgrade(
    *,
    preflight: CollaborationPlanReplacementPreflight,
    army_registry: ExpertRegistry,
) -> CollaborationPlanReplacementAuthorityUpgrade:
    """Upgrade Phase184 requirements to exact authenticated principal intents."""

    if not isinstance(preflight, CollaborationPlanReplacementPreflight):
        raise CollaborationPlanError("preflight must be a CollaborationPlanReplacementPreflight")
    if not isinstance(army_registry, ExpertRegistry):
        raise CollaborationPlanError("army_registry must be an ExpertRegistry")
    parsed_preflight = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
    document = parsed_preflight.to_dict()
    registry = ExpertRegistry.from_dict(army_registry.to_dict())
    registry_binding = _registry_binding(registry)
    requirements = sorted(
        (
            _authenticated_requirement(
                source=dict(source),
                preflight_document=document,
                registry=registry,
                registry_binding=registry_binding,
            )
            for source in document["authority_requirements"]
        ),
        key=lambda item: item["requirement_id"],
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "source_preflight": {
            "preflight_id": parsed_preflight.preflight_id,
            "preflight_sha256": parsed_preflight.preflight_sha256,
        },
        "army_registry": registry_binding,
        "mission_id": document["mission_id"],
        "prior_plan": document["prior_plan"],
        "replacement_plan": document["replacement_plan"],
        "selection_sha256": document["selection_sha256"],
        "authority_requirements": requirements,
        "authentication_status": "principal_assertions_required",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": UPGRADE_DOMAIN, "upgrade": body})
    return CollaborationPlanReplacementAuthorityUpgrade.from_dict(
        {
            **body,
            "upgrade_id": "PRU-" + digest.removeprefix("sha256:")[:32].upper(),
            "upgrade_sha256": digest,
        }
    )


def verify_collaboration_plan_replacement_authority_upgrade(
    upgrade: CollaborationPlanReplacementAuthorityUpgrade,
    *,
    preflight: CollaborationPlanReplacementPreflight,
    army_registry: ExpertRegistry,
) -> CollaborationPlanReplacementAuthorityUpgrade:
    """Rebuild the v2 artifact and compare every offline identity binding."""

    parsed = CollaborationPlanReplacementAuthorityUpgrade.from_dict(upgrade.to_dict())
    expected = build_collaboration_plan_replacement_authority_upgrade(
        preflight=preflight,
        army_registry=army_registry,
    )
    if parsed.to_dict() != expected.to_dict():
        raise CollaborationPlanError(
            "Plan replacement authority upgrade semantic verification failed"
        )
    return parsed


def load_collaboration_plan_replacement_authority_upgrade(
    path: str | Path,
) -> CollaborationPlanReplacementAuthorityUpgrade:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load plan replacement authority upgrade: {resolved}"
        ) from exc
    return CollaborationPlanReplacementAuthorityUpgrade.from_dict(raw)


def build_collaboration_plan_replacement_authority_upgrade_from_files(
    *,
    preflight_path: str | Path,
    army_registry_path: str | Path,
) -> CollaborationPlanReplacementAuthorityUpgrade:
    """Load exact inputs and deterministically build an inactive v2 upgrade."""

    from .collaboration_plan_replacement_preflight import (
        load_collaboration_plan_replacement_preflight,
    )

    return build_collaboration_plan_replacement_authority_upgrade(
        preflight=load_collaboration_plan_replacement_preflight(preflight_path),
        army_registry=load_registry(army_registry_path),
    )


__all__ = [
    "ARMY_CATALOG_ID",
    "ARMY_CATALOG_VERSION",
    "ARMY_REGISTRY_SHA256",
    "COMMAND_AUTHORITY_BINDING_DOMAIN",
    "CollaborationPlanReplacementAuthorityUpgrade",
    "REQUIREMENT_DOMAIN",
    "SCHEMA_VERSION",
    "SOURCE_REQUIREMENT_DOMAIN",
    "UPGRADE_DOMAIN",
    "build_collaboration_plan_replacement_authority_upgrade",
    "build_collaboration_plan_replacement_authority_upgrade_from_files",
    "load_collaboration_plan_replacement_authority_upgrade",
    "verify_collaboration_plan_replacement_authority_upgrade",
]
