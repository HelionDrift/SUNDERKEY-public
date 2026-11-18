"""Offline authority contracts for collaboration plan replacement."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .collaboration import CollaborationPlan
from .collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    collaboration_mission_reconfiguration_selection_sha256,
    validate_collaboration_mission_reconfiguration_selection_bindings,
)
from .collaboration_plan_replacement_preflight import (
    CollaborationPlanReplacementPreflight,
    verify_collaboration_plan_replacement_preflight,
)
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .registry import ExpertRegistry
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
AUTHORITY_PLAN_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-plan.v1"
AUTHORITY_DOCUMENT_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-document.v1"
PRINCIPAL_INTENT_DOMAIN = "sunderkey.collaboration-plan-replacement-principal-intent.v1"
REPLAY_KEY_DOMAIN = "sunderkey.collaboration-plan-replacement-replay-key.v1"
AUTHORITY_COVERAGE_DOMAIN = "sunderkey.collaboration-plan-replacement-authority-coverage.v1"

_PLAN_ID_PATTERN = re.compile(r"APA-[0-9A-F]{32}")
_COVERAGE_ID_PATTERN = re.compile(r"ARC-[0-9A-F]{32}")
_PREFLIGHT_ID_PATTERN = re.compile(r"PRF-[0-9A-F]{32}")
_POLICY_ID_PATTERN = re.compile(r"(?:RAP|MRP)-[0-9A-F]{32}")
_REQUIREMENT_ID_PATTERN = re.compile(r"PAR-[0-9A-F]{32}")
_AUTHENTICATION_ID_PATTERN = re.compile(r"MPA-[0-9A-F]{32}")
_ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")
_PROFILE_ID_PATTERN = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})")
_COMMAND_ID_PATTERN = re.compile(r"AOE-G[A-E]-D[0-9]{2}")
_WORK_ITEM_ID_PATTERN = re.compile(r"WIT-[A-Z]{2,16}-[0-9A-F]{16}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class PlanReplacementPrincipalOperation(StrEnum):
    """Exact identity operations required by the Phase184 preflight."""

    OWNER_AUTHORIZE = "sunderkey.collaboration.plan-replacement.owner-authorize.v1"
    CONTROL_APPROVE = "sunderkey.collaboration.plan-replacement.control-approve.v1"
    CURRENT_OWNER_AUTHORIZE = "sunderkey.collaboration.plan-replacement.current-owner-authorize.v1"
    CURRENT_OWNER_CANCEL = "sunderkey.collaboration.plan-replacement.current-owner-cancel.v1"
    PROPOSED_OWNER_ACCEPT = "sunderkey.collaboration.plan-replacement.proposed-owner-accept.v1"
    SOURCE_COMMAND_REVIEW = "sunderkey.collaboration.plan-replacement.source-command-review.v1"
    DESTINATION_COMMAND_REVIEW = (
        "sunderkey.collaboration.plan-replacement.destination-command-review.v1"
    )
    ASSURANCE_APPROVE = "sunderkey.collaboration.plan-replacement.assurance-approve.v1"
    SECOND_CONTROL_APPROVE = "sunderkey.collaboration.plan-replacement.second-control-approve.v1"


OPERATION_CONTRACTS = (
    {
        "operation": PlanReplacementPrincipalOperation.OWNER_AUTHORIZE.value,
        "role": "mission_owner",
        "authority_kind": "principal_profile",
        "work_item_binding": "forbidden",
    },
    {
        "operation": PlanReplacementPrincipalOperation.CONTROL_APPROVE.value,
        "role": "independent_control",
        "authority_kind": "principal_profile",
        "work_item_binding": "forbidden",
    },
    {
        "operation": PlanReplacementPrincipalOperation.CURRENT_OWNER_AUTHORIZE.value,
        "role": "current_owner",
        "authority_kind": "principal_profile",
        "work_item_binding": "required",
    },
    {
        "operation": PlanReplacementPrincipalOperation.CURRENT_OWNER_CANCEL.value,
        "role": "current_owner",
        "authority_kind": "principal_profile",
        "work_item_binding": "required",
    },
    {
        "operation": PlanReplacementPrincipalOperation.PROPOSED_OWNER_ACCEPT.value,
        "role": "proposed_owner",
        "authority_kind": "principal_profile",
        "work_item_binding": "required",
    },
    {
        "operation": PlanReplacementPrincipalOperation.SOURCE_COMMAND_REVIEW.value,
        "role": "source_technical_command",
        "authority_kind": "command",
        "work_item_binding": "required",
    },
    {
        "operation": PlanReplacementPrincipalOperation.DESTINATION_COMMAND_REVIEW.value,
        "role": "destination_technical_command",
        "authority_kind": "command",
        "work_item_binding": "required",
    },
    {
        "operation": PlanReplacementPrincipalOperation.ASSURANCE_APPROVE.value,
        "role": "independent_assurance",
        "authority_kind": "principal_profile",
        "work_item_binding": "forbidden",
    },
    {
        "operation": PlanReplacementPrincipalOperation.SECOND_CONTROL_APPROVE.value,
        "role": "second_control",
        "authority_kind": "principal_profile",
        "work_item_binding": "forbidden",
    },
)

AUTHENTICATION_CONTRACT = {
    "assertion_format": "sunderkey_principal_assertion_v1",
    "trust_policy_verification_required": True,
    "scope_grant_verification_required": True,
    "assertion_signature_verification_required": True,
    "exact_operation_intent_required": True,
    "all_requirements_required": True,
    "partial_authorization_effect": "none",
}

REPLAY_POLICY = {
    "mode": "consume_once_per_requirement_and_authority_plan",
    "durable_atomic_consumption_required": True,
    "reject_any_consumed_replay_key": True,
    "partial_consumption_effect": "none",
}


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} must be a canonical SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise CollaborationPlanError(f"{label} is not canonical")
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _source_preflight(
    preflight: CollaborationPlanReplacementPreflight,
) -> dict[str, str]:
    return {
        "preflight_id": preflight.preflight_id,
        "preflight_sha256": preflight.preflight_sha256,
        "selection_sha256": preflight.selection_sha256,
    }


def _source_policies(
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    preflight: CollaborationPlanReplacementPreflight,
) -> dict[str, Any]:
    document = preflight.to_dict()
    commit = document["mission_policy_commit"]
    return {
        "reconfiguration_authority_policy": {
            "policy_id": authority_policy.policy_id,
            "policy_sha256": authority_policy.policy_sha256,
        },
        "mission_reconfiguration_policy": {
            "policy_id": mission_policy.policy_id,
            "policy_sha256": mission_policy.policy_sha256,
            "policy_selection_sha256": (
                collaboration_mission_reconfiguration_selection_sha256(mission_policy)
            ),
        },
        "mission_policy_commit": {
            "policy_id": commit["policy_id"],
            "policy_sha256": commit["policy_sha256"],
            "policy_selection_sha256": commit["policy_selection_sha256"],
            "authentication_id": commit["authentication_id"],
            "authentication_sha256": commit["authentication_sha256"],
            "committed_at": commit["committed_at"],
            "mission_owner_assertion_id": commit["mission_owner_assertion_id"],
            "mission_owner_assertion_sha256": commit["mission_owner_assertion_sha256"],
            "mission_owner_ledger_entry_sha256": commit["mission_owner_ledger_entry_sha256"],
            "independent_control_assertion_id": commit["independent_control_assertion_id"],
            "independent_control_assertion_sha256": commit["independent_control_assertion_sha256"],
            "independent_control_ledger_entry_sha256": commit[
                "independent_control_ledger_entry_sha256"
            ],
            "commit_status": commit["commit_status"],
        },
    }


def _source_registry(
    registry: ExpertRegistry,
    registry_source: bytes | str | Path,
) -> tuple[ExpertRegistry, dict[str, str]]:
    if isinstance(registry_source, bytes):
        raw = registry_source
    elif isinstance(registry_source, (str, Path)):
        resolved = Path(registry_source).resolve()
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise CollaborationPlanError(f"Could not read registry source: {resolved}") from exc
    else:
        raise CollaborationPlanError("registry_source must be exact bytes or a path")
    if not raw:
        raise CollaborationPlanError("Registry source bytes are empty")
    try:
        document = loads_json_without_duplicate_keys(raw.decode("utf-8"))
        source_registry = ExpertRegistry.from_dict(document)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CollaborationPlanError("Registry source bytes are invalid") from exc
    supplied_registry = ExpertRegistry.from_dict(registry.to_dict())
    if source_registry.to_dict() != supplied_registry.to_dict():
        raise CollaborationPlanError("Registry source and supplied registry differ")
    return source_registry, {
        "catalog_id": source_registry.catalog_id,
        "catalog_version": source_registry.catalog_version,
        "file_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "content_sha256": _canonical_sha256(source_registry.to_dict()),
    }


def _operation_contract(operation: str) -> dict[str, str]:
    try:
        return next(item for item in OPERATION_CONTRACTS if item["operation"] == operation)
    except StopIteration as exc:
        raise CollaborationPlanError("Plan replacement operation is unsupported") from exc


def _resolve_profile_id(
    requirement: Mapping[str, Any],
    registry: ExpertRegistry,
) -> str:
    authority_kind = requirement["authority_kind"]
    authority_id = requirement["authority_id"]
    if authority_kind == "principal_profile":
        registry.profile(authority_id)
        return authority_id
    if authority_kind == "command":
        try:
            command = registry.commands_by_id[authority_id]
        except KeyError as exc:
            raise CollaborationPlanError(
                "Plan replacement command authority is not in the registry"
            ) from exc
        registry.profile(command.commander_profile_id)
        return command.commander_profile_id
    raise CollaborationPlanError("Plan replacement authority kind is invalid")


def _base_assertion_requirement(
    requirement: Mapping[str, Any],
    registry: ExpertRegistry,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    operation = str(requirement["operation"])
    contract = _operation_contract(operation)
    if (
        requirement["role"] != contract["role"]
        or requirement["authority_kind"] != contract["authority_kind"]
    ):
        raise CollaborationPlanError("Authority requirement violates its operation contract")
    work_item_id = requirement["work_item_id"]
    if (work_item_id is None) != (contract["work_item_binding"] == "forbidden"):
        raise CollaborationPlanError("Authority requirement work-item binding is invalid")
    return {
        "requirement_id": requirement["requirement_id"],
        "role": requirement["role"],
        "authority_id": requirement["authority_id"],
        "authority_kind": requirement["authority_kind"],
        "resolved_profile_id": _resolve_profile_id(requirement, registry),
        "operation": operation,
        "work_item_id": work_item_id,
        "preflight_operation_intent_sha256": requirement["operation_intent_sha256"],
        "assertion_valid_after": issued_at,
        "assertion_expires_at": expires_at,
        "replay_status": "unused_required",
    }


def _validate_role_separation(requirements: list[dict[str, Any]]) -> None:
    by_role: dict[str, set[str]] = {}
    for item in requirements:
        by_role.setdefault(item["role"], set()).add(item["resolved_profile_id"])
    mission_owner = by_role.get("mission_owner", set())
    control = by_role.get("independent_control", set())
    if len(mission_owner) != 1 or len(control) != 1 or mission_owner == control:
        raise CollaborationPlanError("Mission owner and Control separation is invalid")
    work_owners = by_role.get("current_owner", set()) | by_role.get("proposed_owner", set())
    control_profile = next(iter(control))
    if control_profile in work_owners:
        raise CollaborationPlanError("Independent Control owns affected work")
    assurance = by_role.get("independent_assurance", set())
    second_control = by_role.get("second_control", set())
    if len(assurance) > 1 or len(second_control) > 1:
        raise CollaborationPlanError("Independent review roles are ambiguous")
    independent_profiles = control | assurance | second_control
    if len(independent_profiles) != len(control) + len(assurance) + len(second_control):
        raise CollaborationPlanError("Independent review roles must be distinct")
    if (assurance | second_control) & (mission_owner | work_owners):
        raise CollaborationPlanError("Independent review role owns affected work")
    source_commands = by_role.get("source_technical_command", set())
    destination_commands = by_role.get("destination_technical_command", set())
    if source_commands & destination_commands:
        raise CollaborationPlanError("Source and destination command reviewers must differ")
    if (source_commands | destination_commands) & independent_profiles:
        raise CollaborationPlanError("Command and independent review roles must differ")


def _authority_requirement_coverage(
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered_tuples = [
        {
            "requirement_id": item["requirement_id"],
            "operation": item["operation"],
            "role": item["role"],
            "authority_id": item["authority_id"],
            "authority_kind": item["authority_kind"],
            "work_item_id": item["work_item_id"],
        }
        for item in requirements
    ]
    body = {
        "requirement_count": len(ordered_tuples),
        "ordered_requirement_tuples": ordered_tuples,
    }
    digest = _canonical_sha256(
        {
            "domain": AUTHORITY_COVERAGE_DOMAIN,
            "authority_requirement_coverage": body,
        }
    )
    return {
        **body,
        "coverage_id": "ARC-" + digest.removeprefix("sha256:")[:32].upper(),
        "coverage_sha256": digest,
    }


def _parse_authority_requirement_coverage(raw: Any) -> dict[str, Any]:
    coverage = _mapping(raw, "authority_requirement_coverage")
    _exact_fields(
        coverage,
        {
            "coverage_id",
            "coverage_sha256",
            "requirement_count",
            "ordered_requirement_tuples",
        },
        "authority_requirement_coverage",
    )
    coverage_id = coverage.get("coverage_id")
    if not isinstance(coverage_id, str) or _COVERAGE_ID_PATTERN.fullmatch(coverage_id) is None:
        raise CollaborationPlanError("Authority requirement coverage identity is invalid")
    coverage_sha256 = _sha256(
        coverage.get("coverage_sha256"),
        "authority_requirement_coverage.coverage_sha256",
    )
    requirement_count = coverage.get("requirement_count")
    if (
        isinstance(requirement_count, bool)
        or not isinstance(requirement_count, int)
        or requirement_count < 2
        or requirement_count > 50_000
    ):
        raise CollaborationPlanError("Authority requirement coverage count is invalid")
    raw_tuples = coverage.get("ordered_requirement_tuples")
    if not isinstance(raw_tuples, list) or len(raw_tuples) != requirement_count:
        raise CollaborationPlanError("Authority requirement coverage tuples are invalid")
    ordered_tuples: list[dict[str, Any]] = []
    requirement_ids: set[str] = set()
    tuple_fields = {
        "requirement_id",
        "operation",
        "role",
        "authority_id",
        "authority_kind",
        "work_item_id",
    }
    for index, raw_tuple in enumerate(raw_tuples):
        label = f"authority_requirement_coverage.ordered_requirement_tuples[{index}]"
        item = _mapping(raw_tuple, label)
        _exact_fields(item, tuple_fields, label)
        requirement_id = item.get("requirement_id")
        if (
            not isinstance(requirement_id, str)
            or _REQUIREMENT_ID_PATTERN.fullmatch(requirement_id) is None
            or requirement_id in requirement_ids
        ):
            raise CollaborationPlanError("Authority requirement coverage identity is invalid")
        requirement_ids.add(requirement_id)
        authority_id = _identifier(item.get("authority_id"), f"{label}.authority_id")
        contract = _operation_contract(str(item.get("operation")))
        if (
            item.get("role") != contract["role"]
            or item.get("authority_kind") != contract["authority_kind"]
        ):
            raise CollaborationPlanError("Authority requirement coverage contract is invalid")
        work_item_id = item.get("work_item_id")
        if work_item_id is not None and (
            not isinstance(work_item_id, str)
            or _WORK_ITEM_ID_PATTERN.fullmatch(work_item_id) is None
        ):
            raise CollaborationPlanError("Authority requirement coverage work item is invalid")
        if (work_item_id is None) != (contract["work_item_binding"] == "forbidden"):
            raise CollaborationPlanError("Authority requirement coverage binding is invalid")
        if item["authority_kind"] == "principal_profile":
            if _PROFILE_ID_PATTERN.fullmatch(authority_id) is None:
                raise CollaborationPlanError("Authority requirement coverage profile is invalid")
        elif _COMMAND_ID_PATTERN.fullmatch(authority_id) is None:
            raise CollaborationPlanError("Authority requirement coverage command is invalid")
        ordered_tuples.append(dict(item))
    if [item["requirement_id"] for item in ordered_tuples] != sorted(requirement_ids):
        raise CollaborationPlanError("Authority requirement coverage is not canonically ordered")
    expected = _authority_requirement_coverage(ordered_tuples)
    if coverage_id != expected["coverage_id"] or coverage_sha256 != expected["coverage_sha256"]:
        raise CollaborationPlanError("Authority requirement coverage hash is invalid")
    return dict(coverage)


def _core_document(
    *,
    source_preflight: dict[str, str],
    source_policies: dict[str, Any],
    source_registry: dict[str, str],
    mission_id: str,
    issued_at: str,
    expires_at: str,
    authority_requirement_coverage: dict[str, Any],
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_preflight": source_preflight,
        "source_policies": source_policies,
        "source_registry": source_registry,
        "mission_id": mission_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "authority_requirement_coverage": authority_requirement_coverage,
        "operation_contracts": [dict(item) for item in OPERATION_CONTRACTS],
        "authentication_contract": dict(AUTHENTICATION_CONTRACT),
        "assertion_requirements": requirements,
        "replay_policy": dict(REPLAY_POLICY),
        "verification_status": "source_verification_required",
        "authentication_status": "authenticated_assertions_required",
        "assertions_authenticated": False,
        "runtime_authority_effect": "none",
        "runtime_effect": "none",
    }


def _plan_identity(core: dict[str, Any]) -> tuple[str, str]:
    digest = _canonical_sha256({"domain": AUTHORITY_PLAN_DOMAIN, "authority_plan": core})
    return "APA-" + digest.removeprefix("sha256:")[:32].upper(), digest


def _principal_intent(
    *,
    authority_plan_id: str,
    authority_plan_sha256: str,
    core: dict[str, Any],
    requirement: dict[str, Any],
) -> str:
    intent = {
        "authority_plan_id": authority_plan_id,
        "authority_plan_sha256": authority_plan_sha256,
        "mission_id": core["mission_id"],
        "source_preflight": core["source_preflight"],
        "source_policies": core["source_policies"],
        "requirement_id": requirement["requirement_id"],
        "role": requirement["role"],
        "authority_id": requirement["authority_id"],
        "authority_kind": requirement["authority_kind"],
        "resolved_profile_id": requirement["resolved_profile_id"],
        "operation": requirement["operation"],
        "work_item_id": requirement["work_item_id"],
        "preflight_operation_intent_sha256": requirement["preflight_operation_intent_sha256"],
        "assertion_valid_after": requirement["assertion_valid_after"],
        "assertion_expires_at": requirement["assertion_expires_at"],
    }
    return _canonical_sha256({"domain": PRINCIPAL_INTENT_DOMAIN, "principal_intent": intent})


def _expand_requirements(
    core: dict[str, Any],
    authority_plan_id: str,
    authority_plan_sha256: str,
) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for base in core["assertion_requirements"]:
        intent_sha256 = _principal_intent(
            authority_plan_id=authority_plan_id,
            authority_plan_sha256=authority_plan_sha256,
            core=core,
            requirement=base,
        )
        replay_key_sha256 = _canonical_sha256(
            {
                "domain": REPLAY_KEY_DOMAIN,
                "replay_key": {
                    "authority_plan_id": authority_plan_id,
                    "authority_plan_sha256": authority_plan_sha256,
                    "requirement_id": base["requirement_id"],
                    "resolved_profile_id": base["resolved_profile_id"],
                    "principal_operation_intent_sha256": intent_sha256,
                },
            }
        )
        expanded.append(
            {
                **base,
                "principal_operation_intent_sha256": intent_sha256,
                "replay_key_sha256": replay_key_sha256,
            }
        )
    return expanded


def _base_requirements(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not 2 <= len(raw) <= 50_000:
        raise CollaborationPlanError("Authority assertion requirements are invalid")
    fields = {
        "requirement_id",
        "role",
        "authority_id",
        "authority_kind",
        "resolved_profile_id",
        "operation",
        "work_item_id",
        "preflight_operation_intent_sha256",
        "assertion_valid_after",
        "assertion_expires_at",
        "replay_status",
        "principal_operation_intent_sha256",
        "replay_key_sha256",
    }
    result: list[dict[str, Any]] = []
    requirement_ids: set[str] = set()
    replay_keys: set[str] = set()
    for index, item_raw in enumerate(raw):
        label = f"assertion_requirements[{index}]"
        item = _mapping(item_raw, label)
        _exact_fields(item, fields, label)
        requirement_id = item.get("requirement_id")
        if (
            not isinstance(requirement_id, str)
            or _REQUIREMENT_ID_PATTERN.fullmatch(requirement_id) is None
            or requirement_id in requirement_ids
        ):
            raise CollaborationPlanError("Authority requirement identity is invalid")
        requirement_ids.add(requirement_id)
        authority_id = _identifier(item.get("authority_id"), f"{label}.authority_id")
        resolved_profile_id = _identifier(
            item.get("resolved_profile_id"), f"{label}.resolved_profile_id"
        )
        if _PROFILE_ID_PATTERN.fullmatch(resolved_profile_id) is None:
            raise CollaborationPlanError("Resolved authority profile is invalid")
        work_item_id = item.get("work_item_id")
        if work_item_id is not None and (
            not isinstance(work_item_id, str)
            or _WORK_ITEM_ID_PATTERN.fullmatch(work_item_id) is None
        ):
            raise CollaborationPlanError("Authority work-item identity is invalid")
        _sha256(
            item.get("preflight_operation_intent_sha256"),
            f"{label}.preflight_operation_intent_sha256",
        )
        _sha256(
            item.get("principal_operation_intent_sha256"),
            f"{label}.principal_operation_intent_sha256",
        )
        replay_key = _sha256(item.get("replay_key_sha256"), f"{label}.replay_key_sha256")
        if replay_key in replay_keys:
            raise CollaborationPlanError("Authority replay keys must be unique")
        replay_keys.add(replay_key)
        _timestamp(item.get("assertion_valid_after"), f"{label}.assertion_valid_after")
        _timestamp(item.get("assertion_expires_at"), f"{label}.assertion_expires_at")
        if item.get("replay_status") != "unused_required":
            raise CollaborationPlanError("Authority replay status is invalid")
        contract = _operation_contract(str(item.get("operation")))
        if (
            item.get("role") != contract["role"]
            or item.get("authority_kind") != contract["authority_kind"]
        ):
            raise CollaborationPlanError("Authority requirement violates its operation contract")
        if (work_item_id is None) != (contract["work_item_binding"] == "forbidden"):
            raise CollaborationPlanError("Authority requirement work-item binding is invalid")
        if item["authority_kind"] == "principal_profile":
            if (
                _PROFILE_ID_PATTERN.fullmatch(authority_id) is None
                or authority_id != resolved_profile_id
            ):
                raise CollaborationPlanError("Principal authority resolution is invalid")
        elif _COMMAND_ID_PATTERN.fullmatch(authority_id) is None:
            raise CollaborationPlanError("Command authority identity is invalid")
        result.append(
            {
                key: value
                for key, value in item.items()
                if key
                not in {
                    "principal_operation_intent_sha256",
                    "replay_key_sha256",
                }
            }
        )
    if [item["requirement_id"] for item in result] != sorted(requirement_ids):
        raise CollaborationPlanError("Authority requirements are not canonically ordered")
    return result


@dataclass(frozen=True)
class CollaborationPlanReplacementAuthorityPlan:
    """Inactive exact assertion plan for one Phase184 preflight."""

    authority_plan_id: str
    authority_plan_sha256: str
    document_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlanReplacementAuthorityPlan:
        value = _mapping(raw, "collaboration plan replacement authority plan")
        fields = {
            "schema_version",
            "authority_plan_id",
            "authority_plan_sha256",
            "document_sha256",
            "source_preflight",
            "source_policies",
            "source_registry",
            "mission_id",
            "issued_at",
            "expires_at",
            "authority_requirement_coverage",
            "operation_contracts",
            "authentication_contract",
            "assertion_requirements",
            "replay_policy",
            "verification_status",
            "authentication_status",
            "assertions_authenticated",
            "runtime_authority_effect",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration plan replacement authority plan")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Authority plan schema is invalid")
        authority_plan_id = value.get("authority_plan_id")
        if (
            not isinstance(authority_plan_id, str)
            or _PLAN_ID_PATTERN.fullmatch(authority_plan_id) is None
        ):
            raise CollaborationPlanError("Authority plan identity is invalid")
        authority_plan_sha256 = _sha256(value.get("authority_plan_sha256"), "authority_plan_sha256")
        document_sha256 = _sha256(value.get("document_sha256"), "document_sha256")
        preflight = _mapping(value.get("source_preflight"), "source_preflight")
        _exact_fields(
            preflight,
            {"preflight_id", "preflight_sha256", "selection_sha256"},
            "source_preflight",
        )
        if (
            not isinstance(preflight.get("preflight_id"), str)
            or _PREFLIGHT_ID_PATTERN.fullmatch(preflight["preflight_id"]) is None
        ):
            raise CollaborationPlanError("Source preflight identity is invalid")
        _sha256(preflight.get("preflight_sha256"), "source_preflight.preflight_sha256")
        _sha256(preflight.get("selection_sha256"), "source_preflight.selection_sha256")
        source_policies = _mapping(value.get("source_policies"), "source_policies")
        _exact_fields(
            source_policies,
            {
                "reconfiguration_authority_policy",
                "mission_reconfiguration_policy",
                "mission_policy_commit",
            },
            "source_policies",
        )
        for label in (
            "reconfiguration_authority_policy",
            "mission_reconfiguration_policy",
        ):
            policy = _mapping(source_policies.get(label), f"source_policies.{label}")
            expected_fields = {"policy_id", "policy_sha256"}
            if label == "mission_reconfiguration_policy":
                expected_fields.add("policy_selection_sha256")
            _exact_fields(policy, expected_fields, f"source_policies.{label}")
            if (
                not isinstance(policy.get("policy_id"), str)
                or _POLICY_ID_PATTERN.fullmatch(policy["policy_id"]) is None
            ):
                raise CollaborationPlanError("Source policy identity is invalid")
            for policy_field in expected_fields - {"policy_id"}:
                _sha256(
                    policy.get(policy_field),
                    f"source_policies.{label}.{policy_field}",
                )
        commit = _mapping(
            source_policies.get("mission_policy_commit"),
            "source_policies.mission_policy_commit",
        )
        _exact_fields(
            commit,
            {
                "policy_id",
                "policy_sha256",
                "policy_selection_sha256",
                "authentication_id",
                "authentication_sha256",
                "committed_at",
                "mission_owner_assertion_id",
                "mission_owner_assertion_sha256",
                "mission_owner_ledger_entry_sha256",
                "independent_control_assertion_id",
                "independent_control_assertion_sha256",
                "independent_control_ledger_entry_sha256",
                "commit_status",
            },
            "source_policies.mission_policy_commit",
        )
        if (
            not isinstance(commit.get("policy_id"), str)
            or re.fullmatch(r"MRP-[0-9A-F]{32}", commit["policy_id"]) is None
        ):
            raise CollaborationPlanError("Mission policy commit identity is invalid")
        _sha256(commit.get("policy_sha256"), "mission_policy_commit.policy_sha256")
        _sha256(
            commit.get("policy_selection_sha256"),
            "mission_policy_commit.policy_selection_sha256",
        )
        authentication_id = commit.get("authentication_id")
        if (
            not isinstance(authentication_id, str)
            or _AUTHENTICATION_ID_PATTERN.fullmatch(authentication_id) is None
        ):
            raise CollaborationPlanError("Mission policy commit authentication identity is invalid")
        _sha256(
            commit.get("authentication_sha256"),
            "mission_policy_commit.authentication_sha256",
        )
        _timestamp(commit.get("committed_at"), "mission_policy_commit.committed_at")
        for assertion_field in (
            "mission_owner_assertion_id",
            "independent_control_assertion_id",
        ):
            assertion_id = commit.get(assertion_field)
            if (
                not isinstance(assertion_id, str)
                or _ASSERTION_ID_PATTERN.fullmatch(assertion_id) is None
            ):
                raise CollaborationPlanError("Mission policy commit assertion identity is invalid")
        for digest_field in (
            "mission_owner_assertion_sha256",
            "mission_owner_ledger_entry_sha256",
            "independent_control_assertion_sha256",
            "independent_control_ledger_entry_sha256",
        ):
            _sha256(commit.get(digest_field), f"mission_policy_commit.{digest_field}")
        if commit.get("commit_status") != "committed_inactive":
            raise CollaborationPlanError("Mission policy commit status is invalid")
        mission_policy_reference = source_policies["mission_reconfiguration_policy"]
        if (
            commit["policy_id"] != mission_policy_reference["policy_id"]
            or commit["policy_sha256"] != mission_policy_reference["policy_sha256"]
            or commit["policy_selection_sha256"]
            != mission_policy_reference["policy_selection_sha256"]
        ):
            raise CollaborationPlanError("Mission policy commit binding is stale")
        registry = _mapping(value.get("source_registry"), "source_registry")
        _exact_fields(
            registry,
            {"catalog_id", "catalog_version", "file_sha256", "content_sha256"},
            "source_registry",
        )
        _identifier(registry.get("catalog_id"), "source_registry.catalog_id")
        _identifier(registry.get("catalog_version"), "source_registry.catalog_version")
        _sha256(registry.get("file_sha256"), "source_registry.file_sha256")
        _sha256(registry.get("content_sha256"), "source_registry.content_sha256")
        _identifier(value.get("mission_id"), "mission_id")
        issued_at = _timestamp(value.get("issued_at"), "issued_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(issued_at):
            raise CollaborationPlanError("Authority plan validity window is invalid")
        coverage = _parse_authority_requirement_coverage(
            value.get("authority_requirement_coverage")
        )
        if value.get("operation_contracts") != [dict(item) for item in OPERATION_CONTRACTS]:
            raise CollaborationPlanError("Authority operation contracts are invalid")
        if value.get("authentication_contract") != AUTHENTICATION_CONTRACT:
            raise CollaborationPlanError("Authority authentication contract is invalid")
        if value.get("replay_policy") != REPLAY_POLICY:
            raise CollaborationPlanError("Authority replay policy is invalid")
        if (
            value.get("verification_status") != "source_verification_required"
            or value.get("authentication_status") != "authenticated_assertions_required"
            or value.get("assertions_authenticated") is not False
            or value.get("runtime_authority_effect") != "none"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Authority plan boundary is invalid")
        base_requirements = _base_requirements(value.get("assertion_requirements"))
        if any(
            item["assertion_valid_after"] != issued_at or item["assertion_expires_at"] != expires_at
            for item in base_requirements
        ):
            raise CollaborationPlanError(
                "Authority requirement validity must equal the authority plan window"
            )
        expected_coverage = _authority_requirement_coverage(base_requirements)
        if coverage != expected_coverage:
            raise CollaborationPlanError("Authority requirement coverage is invalid")
        core = _core_document(
            source_preflight=dict(preflight),
            source_policies=dict(source_policies),
            source_registry=dict(registry),
            mission_id=value["mission_id"],
            issued_at=issued_at,
            expires_at=expires_at,
            authority_requirement_coverage=coverage,
            requirements=base_requirements,
        )
        expected_id, expected_sha256 = _plan_identity(core)
        if authority_plan_id != expected_id or authority_plan_sha256 != expected_sha256:
            raise CollaborationPlanError("Authority plan content address is invalid")
        expected_requirements = _expand_requirements(core, authority_plan_id, authority_plan_sha256)
        if value.get("assertion_requirements") != expected_requirements:
            raise CollaborationPlanError("Authority assertion intents are invalid")
        document_body = {key: item for key, item in value.items() if key != "document_sha256"}
        expected_document_sha256 = _canonical_sha256(
            {"domain": AUTHORITY_DOCUMENT_DOMAIN, "document": document_body}
        )
        if document_sha256 != expected_document_sha256:
            raise CollaborationPlanError("Authority plan document hash is invalid")
        _validate_role_separation(base_requirements)
        return cls(
            authority_plan_id,
            authority_plan_sha256,
            document_sha256,
            _canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Authority plan is invalid")
        return value


def build_collaboration_plan_replacement_authority_plan(
    *,
    preflight: CollaborationPlanReplacementPreflight,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    registry: ExpertRegistry,
    registry_source: bytes | str | Path,
    issued_at: str,
    expires_at: str,
) -> CollaborationPlanReplacementAuthorityPlan:
    """Build an inactive assertion plan from one exact Phase184 preflight."""

    if not isinstance(preflight, CollaborationPlanReplacementPreflight):
        raise CollaborationPlanError("preflight is invalid")
    preflight = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
    if not isinstance(authority_policy, CollaborationReconfigurationAuthorityPolicy):
        raise CollaborationPlanError("authority_policy is invalid")
    authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
        authority_policy.to_dict()
    )
    if not isinstance(mission_policy, CollaborationMissionReconfigurationPolicy):
        raise CollaborationPlanError("mission_policy is invalid")
    mission_policy = CollaborationMissionReconfigurationPolicy.from_dict(mission_policy.to_dict())
    if not isinstance(registry, ExpertRegistry):
        raise CollaborationPlanError("registry is invalid")
    registry, source_registry = _source_registry(registry, registry_source)
    preflight_document = preflight.to_dict()
    mission_document = mission_policy.to_dict()
    if mission_document["authority_policy"] != {
        "policy_id": authority_policy.policy_id,
        "policy_sha256": authority_policy.policy_sha256,
    }:
        raise CollaborationPlanError("Mission policy authority binding is stale")
    if preflight_document["mission_policy_commit"]["policy_id"] != mission_policy.policy_id:
        raise CollaborationPlanError("Preflight mission policy identity is stale")
    if preflight_document["mission_policy_commit"][
        "policy_sha256"
    ] != mission_policy.policy_sha256 or preflight_document["mission_policy_commit"][
        "policy_selection_sha256"
    ] != collaboration_mission_reconfiguration_selection_sha256(mission_policy):
        raise CollaborationPlanError("Preflight mission policy digest is stale")
    if (
        preflight_document["authentication_status"] != "authority_assertions_required"
        or preflight_document["runtime_effect"] != "none"
    ):
        raise CollaborationPlanError("Preflight is not awaiting authentication")
    issued = _timestamp(issued_at, "issued_at")
    expires = _timestamp(expires_at, "expires_at")
    if not (
        _timestamp_value(mission_document["effective_at"])
        <= _timestamp_value(issued)
        < _timestamp_value(expires)
        <= _timestamp_value(mission_document["expires_at"])
    ):
        raise CollaborationPlanError("Authority plan exceeds the mission policy window")
    requirements = [
        _base_assertion_requirement(item, registry, issued, expires)
        for item in preflight_document["authority_requirements"]
    ]
    requirements.sort(key=lambda item: item["requirement_id"])
    _validate_role_separation(requirements)
    authority_requirement_coverage = _authority_requirement_coverage(requirements)
    core = _core_document(
        source_preflight=_source_preflight(preflight),
        source_policies=_source_policies(authority_policy, mission_policy, preflight),
        source_registry=source_registry,
        mission_id=preflight_document["mission_id"],
        issued_at=issued,
        expires_at=expires,
        authority_requirement_coverage=authority_requirement_coverage,
        requirements=requirements,
    )
    authority_plan_id, authority_plan_sha256 = _plan_identity(core)
    body = {
        **core,
        "authority_plan_id": authority_plan_id,
        "authority_plan_sha256": authority_plan_sha256,
        "assertion_requirements": _expand_requirements(
            core, authority_plan_id, authority_plan_sha256
        ),
    }
    document_sha256 = _canonical_sha256({"domain": AUTHORITY_DOCUMENT_DOMAIN, "document": body})
    return CollaborationPlanReplacementAuthorityPlan.from_dict(
        {**body, "document_sha256": document_sha256}
    )


def _verify_collaboration_plan_replacement_authority_sources(
    plan: CollaborationPlanReplacementAuthorityPlan,
    *,
    preflight: CollaborationPlanReplacementPreflight,
    prior_plan: CollaborationPlan,
    replacement_plan: CollaborationPlan,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    mission_policy: CollaborationMissionReconfigurationPolicy,
    registry: ExpertRegistry,
    registry_source: bytes | str | Path,
    verified_at: str,
    consumed_replay_keys: Collection[str] = (),
) -> tuple[CollaborationPlanReplacementAuthorityPlan, str]:
    """Verify source bindings and replay keys, not committed policy chain or authority."""

    if not isinstance(plan, CollaborationPlanReplacementAuthorityPlan):
        raise CollaborationPlanError("plan is invalid")
    parsed = CollaborationPlanReplacementAuthorityPlan.from_dict(plan.to_dict())
    verified_preflight = verify_collaboration_plan_replacement_preflight(
        preflight,
        prior_plan=prior_plan,
        replacement_plan=replacement_plan,
        mission_policy=mission_policy,
    )
    preflight_document = verified_preflight.to_dict()
    validate_collaboration_mission_reconfiguration_selection_bindings(
        mission_policy,
        authority_policy=authority_policy,
        expected_mission_id=preflight_document["mission_id"],
        expected_collaboration_plan_id=preflight_document["prior_plan"]["plan_id"],
        expected_collaboration_plan_sha256=preflight_document["prior_plan"]["plan_sha256"],
    )
    document = parsed.to_dict()
    expected = build_collaboration_plan_replacement_authority_plan(
        preflight=verified_preflight,
        authority_policy=authority_policy,
        mission_policy=mission_policy,
        registry=registry,
        registry_source=registry_source,
        issued_at=document["issued_at"],
        expires_at=document["expires_at"],
    )
    if expected.to_dict() != document:
        raise CollaborationPlanError("Authority plan offline verification failed")
    now = _timestamp(verified_at, "verified_at")
    if not (
        _timestamp_value(document["issued_at"])
        <= _timestamp_value(now)
        < _timestamp_value(document["expires_at"])
    ):
        raise CollaborationPlanError("Authority plan is outside its validity window")
    consumed = tuple(consumed_replay_keys)
    if len(consumed) != len(set(consumed)):
        raise CollaborationPlanError("Consumed replay keys contain duplicates")
    for index, replay_key in enumerate(consumed):
        _sha256(replay_key, f"consumed_replay_keys[{index}]")
    required_replay_keys = {
        item["replay_key_sha256"] for item in document["assertion_requirements"]
    }
    if required_replay_keys & set(consumed):
        raise CollaborationPlanError("Authority requirement replay was already consumed")
    return parsed, now


def _build_verified_authority_plan_boundary() -> tuple[type[Any], Any, Any]:
    proof_key = secrets.token_bytes(32)
    construction_token = object()

    def proof_for(plan_json: str, verified_at: str, instance_id: int) -> bytes:
        material = _canonical_json(
            {
                "kind": "verified_collaboration_plan_replacement_authority_plan",
                "instance_id": instance_id,
                "plan_json": plan_json,
                "verified_at": verified_at,
            }
        ).encode("utf-8")
        return hmac.new(proof_key, material, "sha256").digest()

    class VerifiedAuthorityPlan:
        """Process-local proof of exact Phase184 source verification."""

        __slots__ = ("_plan_json", "_proof", "_verified_at")

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise TypeError(
                "VerifiedCollaborationPlanReplacementAuthorityPlan can be created only by "
                "verify_collaboration_plan_replacement_authority_plan_offline"
            )

        @property
        def plan(self) -> CollaborationPlanReplacementAuthorityPlan:
            return validate_instance(self)

        @property
        def verified_at(self) -> str:
            validate_instance(self)
            return object.__getattribute__(self, "_verified_at")

        def to_dict(self) -> dict[str, Any]:
            return validate_instance(self).to_dict()

        def __repr__(self) -> str:
            plan = validate_instance(self)
            return (
                "VerifiedCollaborationPlanReplacementAuthorityPlan("
                f"authority_plan_id={plan.authority_plan_id!r}, "
                f"verified_at={self.verified_at!r})"
            )

    def validate_instance(value: Any) -> CollaborationPlanReplacementAuthorityPlan:
        if type(value) is not VerifiedAuthorityPlan:
            raise TypeError("verified_plan must come from exact offline source verification")
        try:
            plan_json = object.__getattribute__(value, "_plan_json")
            verified_at = object.__getattribute__(value, "_verified_at")
            proof = object.__getattribute__(value, "_proof")
        except (AttributeError, TypeError) as exc:
            raise TypeError("verified authority plan proof is invalid") from exc
        if not isinstance(plan_json, str) or not isinstance(proof, bytes):
            raise TypeError("verified authority plan proof is invalid")
        try:
            canonical_verified_at = _timestamp(verified_at, "verified_at")
            raw = loads_json_without_duplicate_keys(plan_json)
            parsed = CollaborationPlanReplacementAuthorityPlan.from_dict(raw)
        except (CollaborationPlanError, TypeError, ValueError) as exc:
            raise TypeError("verified authority plan material is invalid") from exc
        if _canonical_json(parsed.to_dict()) != plan_json or not hmac.compare_digest(
            proof,
            proof_for(plan_json, canonical_verified_at, id(value)),
        ):
            raise TypeError("verified authority plan proof is invalid")
        return parsed

    def issue(
        plan: CollaborationPlanReplacementAuthorityPlan,
        verified_at: str,
        token: object,
    ) -> Any:
        if token is not construction_token:
            raise TypeError("verified authority plan issuance is unavailable")
        parsed = CollaborationPlanReplacementAuthorityPlan.from_dict(plan.to_dict())
        canonical_verified_at = _timestamp(verified_at, "verified_at")
        plan_json = _canonical_json(parsed.to_dict())
        value = object.__new__(VerifiedAuthorityPlan)
        object.__setattr__(value, "_plan_json", plan_json)
        object.__setattr__(value, "_verified_at", canonical_verified_at)
        object.__setattr__(
            value,
            "_proof",
            proof_for(plan_json, canonical_verified_at, id(value)),
        )
        validate_instance(value)
        return value

    def verify_offline(
        plan: CollaborationPlanReplacementAuthorityPlan,
        *,
        preflight: CollaborationPlanReplacementPreflight,
        prior_plan: CollaborationPlan,
        replacement_plan: CollaborationPlan,
        authority_policy: CollaborationReconfigurationAuthorityPolicy,
        mission_policy: CollaborationMissionReconfigurationPolicy,
        registry: ExpertRegistry,
        registry_source: bytes | str | Path,
        verified_at: str,
        consumed_replay_keys: Collection[str] = (),
    ) -> Any:
        parsed, canonical_verified_at = _verify_collaboration_plan_replacement_authority_sources(
            plan,
            preflight=preflight,
            prior_plan=prior_plan,
            replacement_plan=replacement_plan,
            authority_policy=authority_policy,
            mission_policy=mission_policy,
            registry=registry,
            registry_source=registry_source,
            verified_at=verified_at,
            consumed_replay_keys=consumed_replay_keys,
        )
        return issue(parsed, canonical_verified_at, construction_token)

    def validate_at_point_of_use(value: Any) -> CollaborationPlanReplacementAuthorityPlan:
        return validate_instance(value)

    VerifiedAuthorityPlan.__name__ = "VerifiedCollaborationPlanReplacementAuthorityPlan"
    VerifiedAuthorityPlan.__qualname__ = "VerifiedCollaborationPlanReplacementAuthorityPlan"
    verify_offline.__name__ = "verify_collaboration_plan_replacement_authority_plan_offline"
    validate_at_point_of_use.__name__ = (
        "validate_verified_collaboration_plan_replacement_authority_plan"
    )
    return VerifiedAuthorityPlan, verify_offline, validate_at_point_of_use


(
    VerifiedCollaborationPlanReplacementAuthorityPlan,
    verify_collaboration_plan_replacement_authority_plan_offline,
    validate_verified_collaboration_plan_replacement_authority_plan,
) = _build_verified_authority_plan_boundary()
del _build_verified_authority_plan_boundary


def load_collaboration_plan_replacement_authority_plan(
    path: str | Path,
) -> CollaborationPlanReplacementAuthorityPlan:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load authority plan: {resolved}") from exc
    return CollaborationPlanReplacementAuthorityPlan.from_dict(raw)


__all__ = [
    "AUTHENTICATION_CONTRACT",
    "CollaborationPlanReplacementAuthorityPlan",
    "OPERATION_CONTRACTS",
    "PlanReplacementPrincipalOperation",
    "REPLAY_POLICY",
    "VerifiedCollaborationPlanReplacementAuthorityPlan",
    "build_collaboration_plan_replacement_authority_plan",
    "load_collaboration_plan_replacement_authority_plan",
    "validate_verified_collaboration_plan_replacement_authority_plan",
    "verify_collaboration_plan_replacement_authority_plan_offline",
]
