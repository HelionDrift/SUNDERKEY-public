"""Mission-scoped collaboration reconfiguration policy contracts."""

from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
POLICY_DOMAIN = "sunderkey.collaboration-mission-reconfiguration-policy.v1"
SELECTION_DOMAIN = "sunderkey.collaboration-mission-reconfiguration-selection.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
POLICY_ID_PATTERN = re.compile(r"MRP-[0-9A-F]{32}")
ASSERTION_ID_PATTERN = re.compile(r"PAS-[0-9A-F]{32}")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_ANCHOR_PROOF_KEY = secrets.token_bytes(32)

PARAMETER_IDS = (
    "maximum_delegation_depth",
    "reconfiguration_validity_seconds",
    "execution_ack_timeout_seconds",
    "maximum_plan_replacement_items",
)
TRANSITION_FAMILIES = (
    "privileged_role_reassignment",
    "delegation_return_and_revocation",
    "cross_command_transfer",
    "activated_plan_replacement",
    "distributed_execution_transfer_or_cancellation",
)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} must be a positive integer")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is invalid") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _authority_policy_binding(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "mission reconfiguration authority_policy")
    _exact_fields(
        value,
        {"policy_id", "policy_sha256"},
        "mission reconfiguration authority_policy",
    )
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or re.fullmatch(r"RAP-[0-9A-F]{32}", policy_id) is None:
        raise CollaborationPlanError("authority_policy.policy_id is invalid")
    return {
        "policy_id": policy_id,
        "policy_sha256": _sha256(value.get("policy_sha256"), "authority_policy.policy_sha256"),
    }


def _selected_parameters(raw: Any) -> dict[str, int]:
    value = _mapping(raw, "mission reconfiguration selected_parameters")
    _exact_fields(value, set(PARAMETER_IDS), "mission reconfiguration selected_parameters")
    return {
        parameter_id: _positive_integer(value.get(parameter_id), parameter_id)
        for parameter_id in PARAMETER_IDS
    }


def _transition_activation(raw: Any) -> dict[str, bool]:
    value = _mapping(raw, "mission reconfiguration transition_activation")
    _exact_fields(value, set(TRANSITION_FAMILIES), "mission reconfiguration transition_activation")
    result: dict[str, bool] = {}
    for transition_family in TRANSITION_FAMILIES:
        enabled = value.get(transition_family)
        if not isinstance(enabled, bool):
            raise CollaborationPlanError(f"transition_activation.{transition_family} is invalid")
        result[transition_family] = enabled
    if not any(result.values()):
        raise CollaborationPlanError("Mission policy must activate at least one transition family")
    return result


def _assertion_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"profile_id", "assertion_id", "assertion_sha256"}, label)
    assertion_id = value.get("assertion_id")
    if not isinstance(assertion_id, str) or ASSERTION_ID_PATTERN.fullmatch(assertion_id) is None:
        raise CollaborationPlanError(f"{label}.assertion_id is invalid")
    return {
        "profile_id": _identifier(value.get("profile_id"), f"{label}.profile_id"),
        "assertion_id": assertion_id,
        "assertion_sha256": _sha256(value.get("assertion_sha256"), f"{label}.assertion_sha256"),
    }


def _approval_bindings(raw: Any) -> dict[str, dict[str, str]]:
    value = _mapping(raw, "mission reconfiguration approval_bindings")
    fields = {"mission_owner", "independent_control"}
    _exact_fields(value, fields, "mission reconfiguration approval_bindings")
    mission_owner = _assertion_binding(value.get("mission_owner"), "mission_owner")
    independent_control = _assertion_binding(
        value.get("independent_control"), "independent_control"
    )
    if mission_owner["profile_id"] == independent_control["profile_id"]:
        raise CollaborationPlanError("Mission owner and independent Control must be distinct")
    if mission_owner["assertion_id"] == independent_control["assertion_id"]:
        raise CollaborationPlanError("Mission policy approvals must use distinct assertions")
    return {
        "mission_owner": mission_owner,
        "independent_control": independent_control,
    }


def _parameter_bounds(
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
) -> dict[str, tuple[int, int]]:
    authority = authority_policy.to_dict()
    bounds: dict[str, tuple[int, int]] = {}
    for contract in authority["parameter_contracts"]:
        parameter_id = contract["parameter_id"]
        if parameter_id in PARAMETER_IDS:
            bounds[parameter_id] = (contract["minimum"], contract["maximum"])
    if set(bounds) != set(PARAMETER_IDS):
        raise CollaborationPlanError("Authority policy parameter contracts are incomplete")
    return bounds


def _validate_parameter_bounds(
    selected: dict[str, int],
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
) -> None:
    for parameter_id, value in selected.items():
        minimum, maximum = _parameter_bounds(authority_policy)[parameter_id]
        if value < minimum or value > maximum:
            raise CollaborationPlanError(
                f"{parameter_id} is outside the approved authority-policy bounds"
            )


@dataclass(frozen=True)
class CollaborationMissionReconfigurationPolicy:
    """Content-addressed mission selection awaiting assertion authentication."""

    policy_id: str
    policy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationMissionReconfigurationPolicy:
        value = _mapping(raw, "collaboration mission reconfiguration policy")
        fields = {
            "schema_version",
            "policy_id",
            "policy_sha256",
            "authority_policy",
            "policy_version",
            "previous_policy_sha256",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "selected_parameters",
            "transition_activation",
            "approval_bindings",
            "effective_at",
            "expires_at",
            "authentication_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration mission reconfiguration policy")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Mission reconfiguration policy schema is invalid")
        policy_id = value.get("policy_id")
        policy_sha256 = value.get("policy_sha256")
        if not isinstance(policy_id, str) or POLICY_ID_PATTERN.fullmatch(policy_id) is None:
            raise CollaborationPlanError("Mission reconfiguration policy identity is invalid")
        _sha256(policy_sha256, "policy_sha256")
        authority_policy = _authority_policy_binding(value.get("authority_policy"))
        policy_version = _positive_integer(value.get("policy_version"), "policy_version")
        previous = value.get("previous_policy_sha256")
        if policy_version == 1:
            if previous is not None:
                raise CollaborationPlanError("Initial mission policy cannot have a predecessor")
        else:
            _sha256(previous, "previous_policy_sha256")
        _identifier(value.get("mission_id"), "mission_id")
        _identifier(value.get("collaboration_plan_id"), "collaboration_plan_id")
        _sha256(value.get("collaboration_plan_sha256"), "collaboration_plan_sha256")
        selected = _selected_parameters(value.get("selected_parameters"))
        activation = _transition_activation(value.get("transition_activation"))
        approvals = _approval_bindings(value.get("approval_bindings"))
        effective_at = _timestamp(value.get("effective_at"), "effective_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(effective_at):
            raise CollaborationPlanError("Mission reconfiguration policy window is invalid")
        if value.get("authentication_status") != "assertions_pending_verification":
            raise CollaborationPlanError("Mission reconfiguration authentication status is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Mission reconfiguration runtime effect is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"policy_id", "policy_sha256"}
        }
        digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
        expected_id = "MRP-" + digest.removeprefix("sha256:")[:32].upper()
        if policy_sha256 != digest or policy_id != expected_id:
            raise CollaborationPlanError("Mission reconfiguration policy hash is invalid")
        return cls(
            policy_id=policy_id,
            policy_sha256=policy_sha256,
            document_json=_canonical_json(
                {
                    **value,
                    "authority_policy": authority_policy,
                    "selected_parameters": selected,
                    "transition_activation": activation,
                    "approval_bindings": approvals,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Mission reconfiguration policy is invalid")
        return value


def _native_anchor_lineage(value: Any) -> None:
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise CollaborationPlanError("Mission policy anchor lineage keys are invalid")
        for item in value.values():
            _native_anchor_lineage(item)
    elif type(value) is list:
        for item in value:
            _native_anchor_lineage(item)
    elif type(value) not in (str, int, bool, type(None)):
        raise CollaborationPlanError("Mission policy anchor lineage requires native JSON types")


def _anchor_transition_document(raw: Any) -> dict[str, Any]:
    """Reconstruct a native, exact, single-step signed replacement lineage."""

    if type(raw) is not dict:
        raise CollaborationPlanError("Mission policy anchor lineage must be a native object")
    _native_anchor_lineage(raw)
    fields = {
        "store_id",
        "previous_policy",
        "policy",
        "replacement_commit_id",
        "receipt_sha256",
        "preflight_id",
        "preflight_sha256",
        "authentication_sha256",
        "previous_plan_version",
        "plan_version",
        "previous_control_use_sequence",
        "first_authority_use_sequence",
        "last_authority_use_sequence",
        "owner_use_sequence",
        "previous_committed_at",
        "replacement_committed_at",
        "committed_at",
    }
    if set(raw) != fields:
        raise CollaborationPlanError("Mission policy anchor lineage fields are invalid")
    document = dict(raw)
    _identifier(document["store_id"], "anchor lineage store_id")
    for name in ("previous_policy", "policy"):
        if (
            type(document[name]) is not dict
            or type(document[name].get("schema_version")) is not int
            or type(document[name].get("policy_version")) is not int
        ):
            raise CollaborationPlanError("Mission policy anchor lineage policy is invalid")
        document[name] = CollaborationMissionReconfigurationPolicy.from_dict(
            document[name]
        ).to_dict()
    previous, policy = document["previous_policy"], document["policy"]
    if (
        previous["authority_policy"] != policy["authority_policy"]
        or previous["mission_id"] != policy["mission_id"]
        or policy["previous_policy_sha256"] != previous["policy_sha256"]
        or policy["policy_version"] != previous["policy_version"] + 1
        or policy["collaboration_plan_id"] == previous["collaboration_plan_id"]
    ):
        raise CollaborationPlanError("Mission policy anchor lineage policy chain is invalid")
    for name, prefix in (("replacement_commit_id", "CPR"), ("preflight_id", "PRF")):
        if (
            type(document[name]) is not str
            or re.fullmatch(prefix + r"-[0-9A-F]{32}", document[name]) is None
        ):
            raise CollaborationPlanError(f"Mission policy anchor lineage {name} is invalid")
    for name in ("receipt_sha256", "preflight_sha256", "authentication_sha256"):
        _sha256(document[name], f"anchor lineage {name}")
    if (
        document["replacement_commit_id"] != "CPR-" + document["receipt_sha256"][7:39].upper()
        or document["preflight_id"] != "PRF-" + document["preflight_sha256"][7:39].upper()
    ):
        raise CollaborationPlanError("Mission policy anchor lineage content identity is invalid")
    sequence_fields = (
        "previous_plan_version",
        "plan_version",
        "previous_control_use_sequence",
        "first_authority_use_sequence",
        "last_authority_use_sequence",
        "owner_use_sequence",
    )
    if any(type(document[name]) is not int or document[name] < 1 for name in sequence_fields):
        raise CollaborationPlanError("Mission policy anchor lineage sequence is invalid")
    if (
        document["plan_version"] != document["previous_plan_version"] + 1
        or not document["previous_control_use_sequence"]
        < document["first_authority_use_sequence"]
        <= document["last_authority_use_sequence"]
        < document["owner_use_sequence"]
    ):
        raise CollaborationPlanError("Mission policy anchor lineage is not contiguous")
    for name in ("previous_committed_at", "replacement_committed_at", "committed_at"):
        _timestamp(document[name], f"anchor lineage {name}")
    if not (
        document["previous_committed_at"]
        <= document["replacement_committed_at"]
        <= document["committed_at"]
    ):
        raise CollaborationPlanError("Mission policy anchor lineage chronology is invalid")
    return document


def _anchor_transition_proof(document_json: str) -> bytes:
    return hmac.new(_ANCHOR_PROOF_KEY, document_json.encode("utf-8"), "sha256").digest()


@dataclass(frozen=True)
class VerifiedMissionPolicyPlanAnchorTransition:
    """Process-local lineage reconstructed from verified durable signed custody."""

    document_json: str
    _proof: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        if (
            type(self) is not VerifiedMissionPolicyPlanAnchorTransition
            or type(self.document_json) is not str
            or type(self._proof) is not bytes
            or not hmac.compare_digest(self._proof, _anchor_transition_proof(self.document_json))
        ):
            raise CollaborationPlanError("Mission policy anchor lineage lacks durable verification")
        try:
            document = _anchor_transition_document(
                loads_json_without_duplicate_keys(self.document_json)
            )
        except (ValueError, TypeError) as exc:
            raise CollaborationPlanError("Mission policy anchor lineage is invalid") from exc
        if _canonical_json(document) != self.document_json:
            raise CollaborationPlanError("Mission policy anchor lineage is not canonical")
        return document


def _verified_mission_policy_plan_anchor_transition(
    document: dict[str, Any],
) -> VerifiedMissionPolicyPlanAnchorTransition:
    """Issue internal ephemeral context after durable custody verification."""

    document_json = _canonical_json(_anchor_transition_document(document))
    return VerifiedMissionPolicyPlanAnchorTransition(
        document_json, _anchor_transition_proof(document_json)
    )


def build_collaboration_mission_reconfiguration_policy(
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    policy_version: int,
    previous_policy_sha256: str | None,
    mission_id: str,
    collaboration_plan_id: str,
    collaboration_plan_sha256: str,
    maximum_delegation_depth: int,
    reconfiguration_validity_seconds: int,
    execution_ack_timeout_seconds: int,
    maximum_plan_replacement_items: int,
    transition_activation: dict[str, bool],
    mission_owner_approval: dict[str, str],
    independent_control_approval: dict[str, str],
    effective_at: str,
    expires_at: str,
) -> CollaborationMissionReconfigurationPolicy:
    """Build one exact mission selection without authenticating its assertions."""

    authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
        authority_policy.to_dict()
    )
    selected_parameters = {
        "maximum_delegation_depth": maximum_delegation_depth,
        "reconfiguration_validity_seconds": reconfiguration_validity_seconds,
        "execution_ack_timeout_seconds": execution_ack_timeout_seconds,
        "maximum_plan_replacement_items": maximum_plan_replacement_items,
    }
    selected_parameters = _selected_parameters(selected_parameters)
    _validate_parameter_bounds(selected_parameters, authority_policy)
    authority_document = authority_policy.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "authority_policy": {
            "policy_id": authority_policy.policy_id,
            "policy_sha256": authority_policy.policy_sha256,
        },
        "policy_version": policy_version,
        "previous_policy_sha256": previous_policy_sha256,
        "mission_id": mission_id,
        "collaboration_plan_id": collaboration_plan_id,
        "collaboration_plan_sha256": collaboration_plan_sha256,
        "selected_parameters": selected_parameters,
        "transition_activation": transition_activation,
        "approval_bindings": {
            "mission_owner": mission_owner_approval,
            "independent_control": independent_control_approval,
        },
        "effective_at": effective_at,
        "expires_at": expires_at,
        "authentication_status": "assertions_pending_verification",
        "runtime_effect": "none",
    }
    if authority_document["current_boundary"]["policy_status"] != "contract_defined_inactive":
        raise CollaborationPlanError("Authority policy boundary is not eligible for selection")
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    return CollaborationMissionReconfigurationPolicy.from_dict(
        {
            **body,
            "policy_id": "MRP-" + digest.removeprefix("sha256:")[:32].upper(),
            "policy_sha256": digest,
        }
    )


def validate_collaboration_mission_reconfiguration_selection_bindings(
    policy: CollaborationMissionReconfigurationPolicy,
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    expected_mission_id: str,
    expected_collaboration_plan_id: str,
    expected_collaboration_plan_sha256: str,
) -> CollaborationMissionReconfigurationPolicy:
    """Check read-only selection bindings, not predecessor chain or live authority."""

    parsed = CollaborationMissionReconfigurationPolicy.from_dict(policy.to_dict())
    authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
        authority_policy.to_dict()
    )
    document = parsed.to_dict()
    expected_authority = {
        "policy_id": authority_policy.policy_id,
        "policy_sha256": authority_policy.policy_sha256,
    }
    if document["authority_policy"] != expected_authority:
        raise CollaborationPlanError("Mission policy authority binding is stale")
    if document["mission_id"] != expected_mission_id:
        raise CollaborationPlanError("Mission policy mission binding is stale")
    if (
        document["collaboration_plan_id"] != expected_collaboration_plan_id
        or document["collaboration_plan_sha256"] != expected_collaboration_plan_sha256
    ):
        raise CollaborationPlanError("Mission policy collaboration-plan binding is stale")
    _validate_parameter_bounds(document["selected_parameters"], authority_policy)
    return parsed


def validate_collaboration_mission_reconfiguration_policy(
    policy: CollaborationMissionReconfigurationPolicy,
    *,
    authority_policy: CollaborationReconfigurationAuthorityPolicy,
    expected_mission_id: str,
    expected_collaboration_plan_id: str,
    expected_collaboration_plan_sha256: str,
    previous_policy: CollaborationMissionReconfigurationPolicy | None = None,
    plan_anchor_transition: VerifiedMissionPolicyPlanAnchorTransition | None = None,
) -> CollaborationMissionReconfigurationPolicy:
    """Validate selection bindings and the exact complete predecessor transition."""

    parsed = validate_collaboration_mission_reconfiguration_selection_bindings(
        policy,
        authority_policy=authority_policy,
        expected_mission_id=expected_mission_id,
        expected_collaboration_plan_id=expected_collaboration_plan_id,
        expected_collaboration_plan_sha256=expected_collaboration_plan_sha256,
    )
    document = parsed.to_dict()
    transition_document = None
    if plan_anchor_transition is not None:
        if type(plan_anchor_transition) is not VerifiedMissionPolicyPlanAnchorTransition:
            raise CollaborationPlanError("Mission policy anchor lineage must be verified")
        transition_document = plan_anchor_transition.to_dict()
    if document["policy_version"] == 1:
        if transition_document is not None:
            raise CollaborationPlanError("Initial mission policy cannot use replacement lineage")
        if previous_policy is not None:
            raise CollaborationPlanError("Initial mission policy cannot replace a predecessor")
    else:
        if previous_policy is None:
            raise CollaborationPlanError("Mission policy predecessor is required")
        predecessor = CollaborationMissionReconfigurationPolicy.from_dict(previous_policy.to_dict())
        previous_document = predecessor.to_dict()
        if document["previous_policy_sha256"] != predecessor.policy_sha256:
            raise CollaborationPlanError("Mission policy predecessor binding is stale")
        if document["policy_version"] != previous_document["policy_version"] + 1:
            raise CollaborationPlanError("Mission policy version is not monotonic")
        if any(
            document[field] != previous_document[field]
            for field in ("authority_policy", "mission_id")
        ):
            raise CollaborationPlanError("Mission policy replacement changed its anchor")
        plan_changed = any(
            document[field] != previous_document[field]
            for field in ("collaboration_plan_id", "collaboration_plan_sha256")
        )
        if plan_changed and (
            transition_document is None
            or transition_document["previous_policy"] != previous_document
            or transition_document["policy"] != document
        ):
            raise CollaborationPlanError("Mission policy replacement changed its anchor")
        if not plan_changed and transition_document is not None:
            raise CollaborationPlanError("Mission policy anchor lineage is unnecessary")
        if _timestamp_value(document["effective_at"]) < _timestamp_value(
            previous_document["effective_at"]
        ):
            raise CollaborationPlanError("Mission policy chronology is invalid")
    return parsed


def collaboration_mission_reconfiguration_selection_sha256(
    policy: CollaborationMissionReconfigurationPolicy,
) -> str:
    """Hash the exact policy selection without circular assertion references."""

    parsed = CollaborationMissionReconfigurationPolicy.from_dict(policy.to_dict())
    document = parsed.to_dict()
    approvals = document["approval_bindings"]
    selection = {
        "authority_policy": document["authority_policy"],
        "policy_version": document["policy_version"],
        "previous_policy_sha256": document["previous_policy_sha256"],
        "mission_id": document["mission_id"],
        "collaboration_plan_id": document["collaboration_plan_id"],
        "collaboration_plan_sha256": document["collaboration_plan_sha256"],
        "selected_parameters": document["selected_parameters"],
        "transition_activation": document["transition_activation"],
        "mission_owner_profile_id": approvals["mission_owner"]["profile_id"],
        "independent_control_profile_id": approvals["independent_control"]["profile_id"],
        "effective_at": document["effective_at"],
        "expires_at": document["expires_at"],
    }
    return _canonical_sha256({"domain": SELECTION_DOMAIN, "selection": selection})


def load_collaboration_mission_reconfiguration_policy(
    path: str | Path,
) -> CollaborationMissionReconfigurationPolicy:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(
            f"Could not load mission reconfiguration policy: {resolved}"
        ) from exc
    return CollaborationMissionReconfigurationPolicy.from_dict(raw)


__all__ = [
    "CollaborationMissionReconfigurationPolicy",
    "build_collaboration_mission_reconfiguration_policy",
    "collaboration_mission_reconfiguration_selection_sha256",
    "load_collaboration_mission_reconfiguration_policy",
    "validate_collaboration_mission_reconfiguration_policy",
    "validate_collaboration_mission_reconfiguration_selection_bindings",
]
