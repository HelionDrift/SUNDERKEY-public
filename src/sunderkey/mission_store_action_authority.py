"""MissionStore verification for exact authenticated-action authority sources."""

from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .action_admission_contracts import (
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    EvidenceObligation,
    HealthEvidence,
    RestorationDuties,
    StopConditions,
    WorkerSession,
)
from .action_authority_contracts import (
    RESOURCE_FIELDS,
    TIER_ORDER,
    ActionAuthorityPolicyRevision,
    ActionBudgetPolicyRevision,
    ActionSafetyPolicyRevision,
    AuthenticatedProposalMaterialImport,
    AuthoritativeActionCatalogRevision,
    AuthoritativeTargetDescriptorRevision,
    ExactActionSourceHeadBundle,
    parse_action_authority_contract,
)
from .action_resolution import (
    ActionParameterSet,
    ActionTier,
    ExecutableActionCatalog,
    TargetActionDescriptor,
    _authorization,
    _catalog_action,
    _resolved_action_sha256,
    parse_action_admission_revocation,
    parse_action_parameter_set,
    parse_executable_action_catalog,
    parse_target_action_descriptor,
)
from .errors import StoreIntegrityError
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
)
from .qualification import _canonical_json, _canonical_sha256
from .store import parse_timestamp
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

REVISION_TYPES = {
    value.KIND: value
    for value in (
        ActionAuthorityPolicyRevision,
        AuthoritativeActionCatalogRevision,
        AuthoritativeTargetDescriptorRevision,
        ActionBudgetPolicyRevision,
        ActionSafetyPolicyRevision,
    )
}
SOURCE_BINDINGS = {
    ActionAuthorityPolicyRevision.KIND: (
        "action_authority_policy_revision_id",
        "action_authority_policy_revision_sha256",
    ),
    AuthoritativeActionCatalogRevision.KIND: (
        "catalog_revision_id",
        "catalog_revision_sha256",
    ),
    AuthoritativeTargetDescriptorRevision.KIND: (
        "target_revision_id",
        "target_revision_sha256",
    ),
    ActionBudgetPolicyRevision.KIND: (
        "budget_revision_id",
        "budget_revision_sha256",
    ),
    ActionSafetyPolicyRevision.KIND: (
        "safety_revision_id",
        "safety_revision_sha256",
    ),
    AuthenticatedProposalMaterialImport.KIND: (
        "proposal_import_id",
        "proposal_import_sha256",
    ),
}
HEAD_DOMAIN = "sunderkey.action-authority-source-head.v1"
BUDGET_ACCOUNT_DOMAIN = "sunderkey.action-budget-account.v1"
BUDGET_POLICY_BINDING_DOMAIN = "sunderkey.action-budget-policy-binding.v1"
BUDGET_EVENT_DOMAIN = "sunderkey.action-budget-account-event.v1"
BUDGET_RESERVATION_DOMAIN = "sunderkey.action-budget-reservation.v1"
MATERIAL_DOMAIN = "sunderkey.action-authority-material-snapshot.v1"
PUBLICATION_DOMAIN = "sunderkey.action-authority-publication.v1"
MATERIAL_KIND = "action_authority_material_snapshot"
PUBLICATION_KIND = "authenticated_action_authority_publication"
OBSERVATION_KINDS = (
    "credential_lease_observation",
    "execution_fence_observation",
    "executor_deployment_observation",
    "executor_health_observation",
    "stop_monitor_observation",
    "workspace_high_water_observation",
)
MAX_AUTHORITY_DOCUMENT_BYTES = 1_048_576
MAX_AUTHORITY_STRING_BYTES = 32_768
MAX_AUTHORITY_COLLECTION_ITEMS = 4_096
REVIEW_REVOCATION_HEAD_DOMAIN = "sunderkey.action-review-revocation-head.v1"
REVOCATION_BUDGET_RELEASE_DOMAIN = (
    "sunderkey.action-budget-revocation-release.v1"
)
NO_EFFECTS = {
    "authorization_effect": "none",
    "model_call_performed": False,
    "network_call_performed": False,
    "qualification_effect": "none",
    "target_action_performed": False,
    "tool_effect": "none",
}
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def action_review_revocation_head_sha256(closure_id: str) -> str:
    if type(closure_id) is not str or not closure_id:
        raise StoreIntegrityError("Review closure identity is invalid")
    return _canonical_sha256(
        {
            "domain": REVIEW_REVOCATION_HEAD_DOMAIN,
            "review_revocation_head": {
                "closure_id": closure_id,
                "revocation_id": None,
                "revocation_sha256": None,
            },
        }
    )


def _historical_collaboration_role_principal(
    connection: sqlite3.Connection,
    *,
    mission_id: str,
    plan_id: str | None,
    role: str,
    effective_at: str,
) -> dict[str, str]:
    """Resolve an exact collaboration role from the policy current at an instant."""

    if role not in {"mission_owner", "independent_control"}:
        raise StoreIntegrityError("Historical collaboration role is invalid")
    instant = parse_timestamp(effective_at, "historical collaboration role time")
    rows = connection.execute(
        "SELECT * FROM collaboration_mission_policy_commits "
        "WHERE mission_id = ? ORDER BY policy_version DESC",
        (mission_id,),
    ).fetchall()
    selected: tuple[sqlite3.Row, dict[str, Any]] | None = None
    for row in rows:
        if (
            type(row["policy_version"]) is not int
            or type(row["policy_json"]) is not str
            or type(row["committed_at"]) is not str
        ):
            raise StoreIntegrityError(
                "Historical collaboration policy column type is invalid"
            )
        document = _canonical_document(
            row["policy_json"], "historical collaboration policy"
        )
        committed_at = parse_timestamp(
            row["committed_at"], "historical collaboration policy committed_at"
        )
        if committed_at <= instant:
            selected = (row, document)
            break
    if selected is None:
        raise StoreIntegrityError(
            "Historical collaboration authority policy is unavailable"
        )
    row, document = selected
    selected_plan_id = row["plan_id"] if plan_id is None else plan_id
    if (
        row["mission_id"] != mission_id
        or type(selected_plan_id) is not str
        or row["plan_id"] != selected_plan_id
        or document.get("mission_id") != mission_id
        or document.get("collaboration_plan_id") != selected_plan_id
        or document.get("policy_version") != row["policy_version"]
        or document.get("policy_sha256") != row["policy_sha256"]
        or not (
            parse_timestamp(
                document.get("effective_at"),
                "historical collaboration policy effective_at",
            )
            <= instant
            < parse_timestamp(
                document.get("expires_at"),
                "historical collaboration policy expires_at",
            )
        )
    ):
        raise StoreIntegrityError(
            "Historical collaboration authority policy binding is invalid"
        )
    approvals = document.get("approval_bindings")
    binding = approvals.get(role) if isinstance(approvals, dict) else None
    if not isinstance(binding, dict):
        raise StoreIntegrityError(
            "Historical collaboration role binding is unavailable"
        )
    issuer_field = "owner_issuer" if role == "mission_owner" else "control_issuer"
    assertion_field = (
        "owner_assertion_id" if role == "mission_owner" else "control_assertion_id"
    )
    issuer = row[issuer_field]
    assertion_id = row[assertion_field]
    if type(issuer) is not str or type(assertion_id) is not str:
        raise StoreIntegrityError("Historical collaboration principal type is invalid")
    principals = connection.execute(
        """
        SELECT issuer, subject, principal_profile_id, assertion_id,
               assertion_hash
        FROM principal_assertion_uses
        WHERE mission_id = ? AND issuer = ? AND assertion_id = ?
        """,
        (mission_id, issuer, assertion_id),
    ).fetchall()
    if len(principals) != 1:
        raise StoreIntegrityError(
            "Historical collaboration role has no exact authenticated principal"
        )
    principal = principals[0]
    expected = {
        "assertion_id": binding.get("assertion_id"),
        "assertion_hash": binding.get("assertion_sha256"),
        "issuer": issuer,
        "principal_profile_id": binding.get("profile_id"),
    }
    if any(principal[field] != value for field, value in expected.items()):
        raise StoreIntegrityError(
            "Historical collaboration role principal binding is invalid"
        )
    if type(principal["subject"]) is not str:
        raise StoreIntegrityError("Historical collaboration principal type is invalid")
    return {
        "assertion_issuer": issuer,
        "principal_profile_id": principal["principal_profile_id"],
        "principal_subject": principal["subject"],
    }


def action_fence_token_sha256(
    *,
    session_authority_id: str,
    execution_session_id: str,
    owner_epoch: int,
    fence_generation: int,
) -> str:
    if (
        type(session_authority_id) is not str
        or not session_authority_id
        or type(execution_session_id) is not str
        or not execution_session_id
        or type(owner_epoch) is not int
        or owner_epoch < 1
        or type(fence_generation) is not int
        or fence_generation < 1
    ):
        raise StoreIntegrityError("Execution fence source is invalid")
    return _canonical_sha256(
        {
            "domain": "sunderkey.action-execution-fence.v1",
            "fence": {
                "execution_session_id": execution_session_id,
                "fence_generation": fence_generation,
                "owner_epoch": owner_epoch,
                "session_authority_id": session_authority_id,
            },
        }
    )


def action_stop_contract_sha256(
    safety: ActionSafetyPolicyRevision,
) -> str:
    if type(safety) is not ActionSafetyPolicyRevision:
        raise TypeError("safety must be an ActionSafetyPolicyRevision")
    document = safety.to_dict()
    return _canonical_sha256(
        {
            "domain": "sunderkey.action-stop-contract.v1",
            "stop_contract": {
                "deadline": document["deadline"],
                "impact_limits": document["impact_limits"],
                "monitor": document["monitor"],
                "safety_revision_sha256": safety.safety_revision_sha256,
                "stop_conditions": document["stop_conditions"],
            },
        }
    )


def action_monitor_observation_sha256(
    *,
    monitor_id: str,
    principal_profile_id: str,
    principal_subject: str,
    monitor_session_id: str,
    monitor_worker_id: str,
    status: str,
    heartbeat_observed_at: str,
    heartbeat_expires_at: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": "sunderkey.action-stop-monitor-observation.v1",
            "monitor_observation": {
                "heartbeat_expires_at": heartbeat_expires_at,
                "heartbeat_observed_at": heartbeat_observed_at,
                "monitor_id": monitor_id,
                "monitor_session_id": monitor_session_id,
                "monitor_worker_id": monitor_worker_id,
                "principal_profile_id": principal_profile_id,
                "principal_subject": principal_subject,
                "status": status,
            },
        }
    )


def _address(
    domain: str,
    prefix: str,
    body: Mapping[str, Any],
    id_field: str,
    hash_field: str,
) -> dict[str, Any]:
    canonical_body = dict(body)
    digest = _canonical_sha256({"domain": domain, "record": canonical_body})
    return {
        **canonical_body,
        id_field: prefix + digest.removeprefix("sha256:")[:32].upper(),
        hash_field: digest,
    }


def _exact_fields(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise StoreIntegrityError(f"{label} fields are invalid")


def _strict_mapping(value: Any, label: str) -> dict[str, Any]:
    if type(value) is str:
        try:
            parsed = loads_json_without_duplicate_keys(value)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise StoreIntegrityError(f"{label} is not strict JSON") from exc
        if type(parsed) is not dict or _canonical_json(parsed) != value:
            raise StoreIntegrityError(f"{label} is not canonical JSON")
        value = parsed
    if type(value) is not dict:
        raise StoreIntegrityError(f"{label} must be an exact object")
    _validate_json_tree(value, label)
    canonical = _canonical_json(value)
    if len(canonical.encode("ascii")) > MAX_AUTHORITY_DOCUMENT_BYTES:
        raise StoreIntegrityError(f"{label} exceeds the byte ceiling")
    parsed = json.loads(canonical)
    if type(parsed) is not dict:
        raise StoreIntegrityError(f"{label} must be an object")
    _validate_json_tree(parsed, label)
    return parsed


def _validate_json_tree(value: Any, label: str) -> None:
    if type(value) is str:
        if (
            unicodedata.normalize("NFC", value) != value
            or len(value.encode("utf-8")) > MAX_AUTHORITY_STRING_BYTES
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            raise StoreIntegrityError(f"{label} contains unsafe text")
        return
    if type(value) is list:
        if len(value) > MAX_AUTHORITY_COLLECTION_ITEMS:
            raise StoreIntegrityError(f"{label} contains too many items")
        for item in value:
            _validate_json_tree(item, label)
        return
    if type(value) is dict:
        if len(value) > MAX_AUTHORITY_COLLECTION_ITEMS:
            raise StoreIntegrityError(f"{label} contains too many fields")
        for key, item in value.items():
            if type(key) is not str:
                raise StoreIntegrityError(f"{label} contains a non-string key")
            _validate_json_tree(key, label)
            _validate_json_tree(item, label)
        return
    if value is None or type(value) in {bool, int}:
        return
    raise StoreIntegrityError(f"{label} contains an invalid JSON value")


def _exact_sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise StoreIntegrityError(f"{label} must be a SHA-256 digest")
    return value


def _require_no_effects(value: Any, label: str) -> None:
    if (
        type(value) is not dict
        or value != NO_EFFECTS
        or any(
            type(value[key]) is not type(expected)
            for key, expected in NO_EFFECTS.items()
        )
    ):
        raise StoreIntegrityError(f"{label} effects are invalid")


@dataclass(frozen=True, slots=True)
class ActionAuthorityObservation:
    """Exact current observation authenticated by an authority publication."""

    document_json: str

    @property
    def KIND(self) -> str:
        return self.to_dict()["observation_kind"]

    @property
    def record_id(self) -> str:
        return self.to_dict()["observation_id"]

    @property
    def content_sha256(self) -> str:
        return self.to_dict()["observation_sha256"]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> ActionAuthorityObservation:
        value = _strict_mapping(raw, "action authority observation")
        _exact_fields(
            value,
            {
                "schema_version",
                "kind",
                "observation_kind",
                "observation_id",
                "observation_sha256",
                "tenant_id",
                "mission_id",
                "plan_id",
                "payload",
                "observed_at",
                "valid_until",
                "effects",
            },
            "action authority observation",
        )
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["kind"] != "action_authority_observation"
            or value["observation_kind"] not in OBSERVATION_KINDS
        ):
            raise StoreIntegrityError("Action authority observation header is invalid")
        _require_no_effects(value["effects"], "Action authority observation")
        for field in ("tenant_id", "mission_id", "plan_id"):
            if type(value[field]) is not str or not value[field]:
                raise StoreIntegrityError(f"Action authority observation {field} is invalid")
        observed = parse_timestamp(value["observed_at"], "observation observed_at")
        valid = parse_timestamp(value["valid_until"], "observation valid_until")
        if observed >= valid:
            raise StoreIntegrityError("Action authority observation window is invalid")
        payload = _strict_mapping(value["payload"], "action observation payload")
        kind = value["observation_kind"]
        payload_fields = {
            "execution_fence_observation": {
                "session_authority_id",
                "session_authority_sha256",
                "execution_session_id",
                "execution_session_sha256",
                "owner_epoch",
                "fence_generation",
                "fence_token_sha256",
            },
            "credential_lease_observation": {
                "credential_lease",
                "credential_lease_sha256",
            },
            "executor_health_observation": {
                "health",
                "health_observation_sha256",
            },
            "executor_deployment_observation": {
                "worker_session",
                "executor_deployment_sha256",
            },
            "stop_monitor_observation": {
                "monitor_id",
                "principal_profile_id",
                "principal_subject",
                "monitor_session_id",
                "monitor_worker_id",
                "monitor_observation_sha256",
                "status",
                "heartbeat_observed_at",
                "heartbeat_expires_at",
            },
            "workspace_high_water_observation": {
                "high_water",
                "high_water_sha256",
            },
        }[kind]
        _exact_fields(payload, payload_fields, "action observation payload")
        if kind == "execution_fence_observation":
            expected = action_fence_token_sha256(
                session_authority_id=payload["session_authority_id"],
                execution_session_id=payload["execution_session_id"],
                owner_epoch=payload["owner_epoch"],
                fence_generation=payload["fence_generation"],
            )
            if payload["fence_token_sha256"] != expected:
                raise StoreIntegrityError("Execution fence observation is invalid")
        elif kind == "credential_lease_observation":
            lease = CredentialLease.from_dict(payload["credential_lease"])
            if lease.credential_ref_sha256 != payload["credential_lease_sha256"]:
                raise StoreIntegrityError("Credential observation is invalid")
        elif kind == "executor_health_observation":
            health = HealthEvidence.from_dict(payload["health"])
            if health.evidence_sha256 != payload["health_observation_sha256"]:
                raise StoreIntegrityError("Health observation is invalid")
        elif kind == "executor_deployment_observation":
            worker = WorkerSession.from_dict(payload["worker_session"])
            expected = _canonical_sha256(
                {
                    "domain": "sunderkey.action-executor-deployment.v1",
                    "worker_session": worker.to_dict(),
                }
            )
            if payload["executor_deployment_sha256"] != expected:
                raise StoreIntegrityError("Deployment observation is invalid")
        elif kind == "stop_monitor_observation":
            expected_monitor_sha256 = action_monitor_observation_sha256(
                monitor_id=payload["monitor_id"],
                principal_profile_id=payload["principal_profile_id"],
                principal_subject=payload["principal_subject"],
                monitor_session_id=payload["monitor_session_id"],
                monitor_worker_id=payload["monitor_worker_id"],
                status=payload["status"],
                heartbeat_observed_at=payload["heartbeat_observed_at"],
                heartbeat_expires_at=payload["heartbeat_expires_at"],
            )
            if (
                payload["status"] != "healthy"
                or payload["monitor_worker_id"] != payload["principal_profile_id"]
                or payload["monitor_observation_sha256"]
                != expected_monitor_sha256
                or parse_timestamp(
                    payload["heartbeat_observed_at"], "monitor heartbeat observed_at"
                )
                >= parse_timestamp(
                    payload["heartbeat_expires_at"], "monitor heartbeat expires_at"
                )
            ):
                raise StoreIntegrityError("Stop monitor observation is invalid")
        else:
            high_water = _strict_mapping(payload["high_water"], "workspace high-water")
            _exact_fields(
                high_water,
                {
                    "application_id",
                    "application_sha256",
                    "closure_id",
                    "closure_sha256",
                    "event_count",
                    "event_head_occurred_at",
                    "event_head_sha256",
                    "high_water_id",
                    "high_water_sha256",
                    "mission_id",
                    "mission_store_id",
                    "revocation_id",
                    "revocation_sha256",
                    "snapshot_id",
                    "snapshot_sha256",
                    "state",
                    "workspace_id",
                    "workspace_revision",
                    "workspace_store_id",
                    "workspace_store_path",
                },
                "workspace high-water",
            )
            high_water_body = dict(high_water)
            high_water_id = high_water_body.pop("high_water_id")
            high_water_sha256 = high_water_body.pop("high_water_sha256")
            expected_sha256 = _canonical_sha256(
                {
                    "domain": "sunderkey.action-workspace-high-water.v1",
                    "high_water": high_water_body,
                }
            )
            if (
                high_water_sha256 != payload["high_water_sha256"]
                or high_water_sha256 != expected_sha256
                or high_water_id
                != "AWH-" + expected_sha256.removeprefix("sha256:")[:32].upper()
                or high_water["mission_id"] != value["mission_id"]
                or high_water["state"] != "closure_applied_unrevoked"
                or high_water["revocation_id"] is not None
                or high_water["revocation_sha256"] is not None
                or type(high_water["workspace_revision"]) is not int
                or high_water["workspace_revision"] < 1
                or type(high_water["event_count"]) is not int
                or high_water["event_count"] < 1
                or type(high_water["event_head_occurred_at"]) is not int
                or high_water["event_head_occurred_at"] < 0
            ):
                raise StoreIntegrityError("Workspace high-water observation is invalid")
        addressed = dict(value)
        record_id = addressed.pop("observation_id")
        record_hash = addressed.pop("observation_sha256")
        expected = _address(
            f"sunderkey.{kind}.v1",
            "AAO-",
            addressed,
            "observation_id",
            "observation_sha256",
        )
        if (
            record_id != expected["observation_id"]
            or record_hash != expected["observation_sha256"]
        ):
            raise StoreIntegrityError("Action observation content address is invalid")
        return cls(_canonical_json(value))


def build_action_authority_observation(
    *,
    observation_kind: str,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    payload: Mapping[str, Any],
    observed_at: str,
    valid_until: str,
) -> ActionAuthorityObservation:
    body = {
        "schema_version": 1,
        "kind": "action_authority_observation",
        "observation_kind": observation_kind,
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "plan_id": plan_id,
        "payload": dict(payload),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "effects": dict(NO_EFFECTS),
    }
    return ActionAuthorityObservation.from_dict(
        _address(
            f"sunderkey.{observation_kind}.v1",
            "AAO-",
            body,
            "observation_id",
            "observation_sha256",
        )
    )


@dataclass(frozen=True, slots=True)
class ActionAuthorityMaterialSnapshot:
    """Closed Phase165 material authenticated by one source publication."""

    document_json: str

    @property
    def material_snapshot_id(self) -> str:
        return self.to_dict()["material_snapshot_id"]

    @property
    def material_snapshot_sha256(self) -> str:
        return self.to_dict()["material_snapshot_sha256"]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> ActionAuthorityMaterialSnapshot:
        value = _strict_mapping(raw, "action authority material snapshot")
        fields = {
            "schema_version",
            "kind",
            "material_snapshot_id",
            "material_snapshot_sha256",
            "tenant_id",
            "mission_id",
            "plan_id",
            "proposal_import_id",
            "proposal_import_sha256",
            "catalog",
            "parameters",
            "target",
            "resolver_profile_id",
            "resolver_subject",
            "context",
            "worker_session",
            "credential_lease",
            "health",
            "budget",
            "evidence_obligations",
            "stop_conditions",
            "restoration_duties",
            "resolved_at",
            "approved_at",
            "quorum_expires_at",
            "requested_at",
            "expires_at",
            "credential_lease_sha256",
            "health_observation_sha256",
            "executor_deployment_sha256",
            "monitor_observation_sha256",
            "observed_at",
            "valid_until",
            "effects",
        }
        _exact_fields(value, fields, "action authority material snapshot")
        if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
            raise StoreIntegrityError("Action material schema version is invalid")
        if value["kind"] != MATERIAL_KIND:
            raise StoreIntegrityError("Action material kind or effects are invalid")
        _require_no_effects(value["effects"], "Action material")
        catalog = parse_executable_action_catalog(value["catalog"])
        parameters = parse_action_parameter_set(value["parameters"], catalog)
        target = parse_target_action_descriptor(value["target"])
        context = ContextBinding.from_dict(value["context"])
        worker = WorkerSession.from_dict(value["worker_session"])
        credential = CredentialLease.from_dict(value["credential_lease"])
        health = HealthEvidence.from_dict(value["health"])
        budget = BudgetBinding.from_dict(value["budget"])
        obligations = value["evidence_obligations"]
        if (
            type(obligations) is not list
            or not 1 <= len(obligations) <= 32
            or len({_canonical_json(item) for item in obligations})
            != len(obligations)
        ):
            raise StoreIntegrityError("Action material evidence obligations are invalid")
        parsed_obligations = tuple(EvidenceObligation.from_dict(item) for item in obligations)
        if [item.to_dict() for item in parsed_obligations] != obligations:
            raise StoreIntegrityError("Action material evidence obligations are noncanonical")
        stop = StopConditions.from_dict(value["stop_conditions"])
        restoration = RestorationDuties.from_dict(value["restoration_duties"])
        for field in (
            "tenant_id",
            "mission_id",
            "plan_id",
            "proposal_import_id",
            "resolver_profile_id",
            "resolver_subject",
        ):
            if type(value[field]) is not str or not value[field]:
                raise StoreIntegrityError(f"Action material {field} is invalid")
        for field in (
            "proposal_import_sha256",
            "credential_lease_sha256",
            "health_observation_sha256",
            "executor_deployment_sha256",
            "monitor_observation_sha256",
        ):
            _exact_sha256(value[field], f"Action material {field}")
        resolved, approved, requested, observed = tuple(
            parse_timestamp(value[field], f"action material {field}")
            for field in ("resolved_at", "approved_at", "requested_at", "observed_at")
        )
        expiries = tuple(
            parse_timestamp(value[field], f"action material {field}")
            for field in ("expires_at", "quorum_expires_at", "valid_until")
        )
        if not (
            resolved <= approved <= requested <= observed
            and all(observed < expiry for expiry in expiries)
        ):
            raise StoreIntegrityError("Action material chronology is invalid")
        if (
            catalog.to_dict() != value["catalog"]
            or parameters.to_dict() != value["parameters"]
            or target.to_dict() != value["target"]
            or context.to_dict() != value["context"]
            or worker.to_dict() != value["worker_session"]
            or credential.to_dict() != value["credential_lease"]
            or health.to_dict() != value["health"]
            or budget.to_dict() != value["budget"]
            or stop.to_dict() != value["stop_conditions"]
            or restoration.to_dict() != value["restoration_duties"]
        ):
            raise StoreIntegrityError("Action material nested records are noncanonical")
        if (
            context.tenant_id != value["tenant_id"]
            or context.mission_id != value["mission_id"]
            or worker.tenant_id != value["tenant_id"]
            or worker.mission_id != value["mission_id"]
            or credential.tenant_id != value["tenant_id"]
            or credential.mission_id != value["mission_id"]
            or budget.tenant_id != value["tenant_id"]
            or budget.mission_id != value["mission_id"]
            or credential.credential_ref_sha256 != value["credential_lease_sha256"]
            or health.evidence_sha256 != value["health_observation_sha256"]
            or _canonical_sha256(
                {
                    "domain": "sunderkey.action-executor-deployment.v1",
                    "worker_session": worker.to_dict(),
                }
            )
            != value["executor_deployment_sha256"]
        ):
            raise StoreIntegrityError("Action material source bindings are invalid")
        addressed = dict(value)
        record_id = addressed.pop("material_snapshot_id")
        record_hash = addressed.pop("material_snapshot_sha256")
        expected = _address(
            MATERIAL_DOMAIN,
            "AAM-",
            addressed,
            "material_snapshot_id",
            "material_snapshot_sha256",
        )
        if (
            record_id != expected["material_snapshot_id"]
            or record_hash != expected["material_snapshot_sha256"]
        ):
            raise StoreIntegrityError("Action material content address is invalid")
        return cls(_canonical_json(value))


def build_action_authority_material_snapshot(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    proposal: AuthenticatedProposalMaterialImport,
    catalog: ExecutableActionCatalog,
    parameters: ActionParameterSet,
    target: TargetActionDescriptor,
    resolver_profile_id: str,
    resolver_subject: str,
    context: ContextBinding,
    worker_session: WorkerSession,
    credential_lease: CredentialLease,
    health: HealthEvidence,
    budget: BudgetBinding,
    monitor_observation_sha256: str,
    evidence_obligations: tuple[EvidenceObligation, ...],
    stop_conditions: StopConditions,
    restoration_duties: RestorationDuties,
    resolved_at: str,
    approved_at: str,
    quorum_expires_at: str,
    requested_at: str,
    expires_at: str,
    observed_at: str,
    valid_until: str,
) -> ActionAuthorityMaterialSnapshot:
    body = {
        "schema_version": 1,
        "kind": MATERIAL_KIND,
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "plan_id": plan_id,
        "proposal_import_id": proposal.proposal_import_id,
        "proposal_import_sha256": proposal.proposal_import_sha256,
        "catalog": catalog.to_dict(),
        "parameters": parameters.to_dict(),
        "target": target.to_dict(),
        "resolver_profile_id": resolver_profile_id,
        "resolver_subject": resolver_subject,
        "context": context.to_dict(),
        "worker_session": worker_session.to_dict(),
        "credential_lease": credential_lease.to_dict(),
        "health": health.to_dict(),
        "budget": budget.to_dict(),
        "evidence_obligations": [item.to_dict() for item in evidence_obligations],
        "stop_conditions": stop_conditions.to_dict(),
        "restoration_duties": restoration_duties.to_dict(),
        "resolved_at": resolved_at,
        "approved_at": approved_at,
        "quorum_expires_at": quorum_expires_at,
        "requested_at": requested_at,
        "expires_at": expires_at,
        "credential_lease_sha256": credential_lease.credential_ref_sha256,
        "health_observation_sha256": health.evidence_sha256,
        "executor_deployment_sha256": _canonical_sha256(
            {
                "domain": "sunderkey.action-executor-deployment.v1",
                "worker_session": worker_session.to_dict(),
            }
        ),
        "monitor_observation_sha256": monitor_observation_sha256,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "effects": dict(NO_EFFECTS),
    }
    return ActionAuthorityMaterialSnapshot.from_dict(
        _address(
            MATERIAL_DOMAIN,
            "AAM-",
            body,
            "material_snapshot_id",
            "material_snapshot_sha256",
        )
    )


def phase165_budget_binding_from_policy(
    budget: ActionBudgetPolicyRevision,
    *,
    tenant_id: str,
    mission_id: str,
) -> BudgetBinding:
    if type(budget) is not ActionBudgetPolicyRevision:
        raise TypeError("budget must be an ActionBudgetPolicyRevision")
    document = budget.to_dict()
    if document["tenant_id"] != tenant_id or document["mission_id"] != mission_id:
        raise StoreIntegrityError("Budget policy crosses the material authority boundary")
    limits = document["limits"]
    ceiling = document["per_action_ceiling"]
    return BudgetBinding(
        tenant_id=tenant_id,
        mission_id=mission_id,
        budget_sha256=budget.budget_revision_sha256,
        request_limit=limits["rate_units"],
        requests_used=0,
        token_limit=limits["request_bytes"] + limits["response_bytes"],
        tokens_used=0,
        cost_limit_microunits=limits["money_microunits"],
        cost_used_microunits=0,
        action_request_cost=ceiling["rate_units"],
        action_token_cost=ceiling["request_bytes"] + ceiling["response_bytes"],
        action_cost_microunits=ceiling["money_microunits"],
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedActionAuthorityPublication:
    """Content address signed by current Mission Control before source insertion."""

    document_json: str

    @property
    def publication_id(self) -> str:
        return self.to_dict()["publication_id"]

    @property
    def publication_sha256(self) -> str:
        return self.to_dict()["publication_sha256"]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> AuthenticatedActionAuthorityPublication:
        value = _strict_mapping(raw, "action authority publication")
        fields = {
            "schema_version",
            "kind",
            "publication_id",
            "publication_sha256",
            "tenant_id",
            "mission_id",
            "plan_id",
            "source_records",
            "material_snapshot_id",
            "material_snapshot_sha256",
            "idempotency_key_sha256",
            "published_at",
            "effects",
        }
        _exact_fields(value, fields, "action authority publication")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["kind"] != PUBLICATION_KIND
        ):
            raise StoreIntegrityError("Action authority publication header is invalid")
        _require_no_effects(value["effects"], "Action authority publication")
        for field in (
            "tenant_id",
            "mission_id",
            "plan_id",
            "material_snapshot_id",
        ):
            if type(value[field]) is not str or not value[field]:
                raise StoreIntegrityError(f"Action publication {field} is invalid")
        for field in ("material_snapshot_sha256", "idempotency_key_sha256"):
            _exact_sha256(value[field], f"Action publication {field}")
        parse_timestamp(value["published_at"], "action publication published_at")
        sources = value["source_records"]
        expected_kinds = sorted(
            (*SOURCE_BINDINGS, *OBSERVATION_KINDS, ExactActionSourceHeadBundle.KIND)
        )
        if type(sources) is not list or len(sources) != len(expected_kinds):
            raise StoreIntegrityError("Action publication source set is incomplete")
        checked: list[dict[str, str]] = []
        for source in sources:
            if type(source) is not dict:
                raise StoreIntegrityError("Action publication source binding is invalid")
            _exact_fields(source, {"record_id", "record_kind", "record_sha256"}, "source binding")
            if any(type(source[field]) is not str for field in source):
                raise StoreIntegrityError("Action publication source binding type is invalid")
            if not source["record_id"]:
                raise StoreIntegrityError("Action publication source identity is invalid")
            _exact_sha256(
                source["record_sha256"],
                "Action publication source hash",
            )
            checked.append(dict(source))
        if checked != sorted(checked, key=lambda item: item["record_kind"]):
            raise StoreIntegrityError("Action publication source bindings are not ordered")
        if [item["record_kind"] for item in checked] != expected_kinds:
            raise StoreIntegrityError("Action publication source kinds are invalid")
        addressed = dict(value)
        record_id = addressed.pop("publication_id")
        record_hash = addressed.pop("publication_sha256")
        expected = _address(
            PUBLICATION_DOMAIN,
            "AAPB-",
            addressed,
            "publication_id",
            "publication_sha256",
        )
        if record_id != expected["publication_id"] or record_hash != expected["publication_sha256"]:
            raise StoreIntegrityError("Action publication content address is invalid")
        return cls(_canonical_json(value))


def build_authenticated_action_authority_publication(
    *,
    policy: ActionAuthorityPolicyRevision,
    catalog: AuthoritativeActionCatalogRevision,
    target: AuthoritativeTargetDescriptorRevision,
    budget: ActionBudgetPolicyRevision,
    safety: ActionSafetyPolicyRevision,
    proposal: AuthenticatedProposalMaterialImport,
    source_bundle: ExactActionSourceHeadBundle,
    material: ActionAuthorityMaterialSnapshot,
    observations: tuple[ActionAuthorityObservation, ...],
    idempotency_key_sha256: str,
    published_at: str,
) -> AuthenticatedActionAuthorityPublication:
    if (
        type(observations) is not tuple
        or tuple(sorted(item.KIND for item in observations)) != OBSERVATION_KINDS
        or any(type(item) is not ActionAuthorityObservation for item in observations)
    ):
        raise StoreIntegrityError("Action publication observations are incomplete")
    records = (
        policy,
        catalog,
        target,
        budget,
        safety,
        proposal,
        *observations,
        source_bundle,
    )
    bindings = sorted(
        (
            {
                "record_kind": record.KIND,
                "record_id": record.record_id,
                "record_sha256": record.content_sha256,
            }
            for record in records
        ),
        key=lambda item: item["record_kind"],
    )
    material_document = material.to_dict()
    source_document = source_bundle.to_dict()
    boundary = {
        "tenant_id": source_document["tenant_id"],
        "mission_id": source_document["mission_id"],
        "plan_id": source_document["plan_id"],
    }
    if any(material_document[field] != item for field, item in boundary.items()):
        raise StoreIntegrityError("Action material crosses the source publication boundary")
    published = parse_timestamp(published_at, "action publication published_at")
    if not (
        parse_timestamp(source_document["observed_at"], "source observed_at")
        <= published
        < parse_timestamp(source_document["valid_until"], "source valid_until")
        and parse_timestamp(material_document["observed_at"], "material observed_at")
        <= published
        < parse_timestamp(material_document["valid_until"], "material valid_until")
    ):
        raise StoreIntegrityError("Action publication is outside its source window")
    for revision in (policy, catalog, target, budget, safety):
        revision_document = revision.to_dict()
        if not (
            parse_timestamp(revision_document["effective_at"], "source effective_at")
            <= published
            < parse_timestamp(revision_document["expires_at"], "source expires_at")
        ):
            raise StoreIntegrityError("Action publication uses an expired source revision")
    source_valid_until = parse_timestamp(
        source_document["valid_until"], "source valid_until"
    )
    material_valid_until = parse_timestamp(
        material_document["valid_until"], "material valid_until"
    )
    for observation in observations:
        observation_document = observation.to_dict()
        observed = parse_timestamp(
            observation_document["observed_at"],
            "observation observed_at",
        )
        valid = parse_timestamp(
            observation_document["valid_until"],
            "observation valid_until",
        )
        if not (
            observed <= published < valid
            and source_valid_until <= valid
            and material_valid_until <= valid
        ):
            raise StoreIntegrityError(
                "Action publication uses a stale observation"
            )
    if (
        material_document["budget"]
        != phase165_budget_binding_from_policy(
            budget,
            tenant_id=boundary["tenant_id"],
            mission_id=boundary["mission_id"],
        ).to_dict()
    ):
        raise StoreIntegrityError("Action material budget is not the deterministic source mapping")
    expected = {
        "proposal_import_id": source_document["proposal_import_id"],
        "proposal_import_sha256": source_document["proposal_import_sha256"],
        "credential_lease_sha256": source_document["credential_lease_sha256"],
        "health_observation_sha256": source_document["health_observation_sha256"],
        "executor_deployment_sha256": source_document["executor_deployment_sha256"],
        "monitor_observation_sha256": source_document["monitor_observation_sha256"],
    }
    if any(material_document[field] != item for field, item in expected.items()):
        raise StoreIntegrityError("Action material differs from source bundle observations")
    observation_map = {item.KIND: item.to_dict()["payload"] for item in observations}
    fence_payload = observation_map["execution_fence_observation"]
    credential_payload = observation_map["credential_lease_observation"]
    health_payload = observation_map["executor_health_observation"]
    deployment_payload = observation_map["executor_deployment_observation"]
    monitor_payload = observation_map["stop_monitor_observation"]
    workspace_payload = observation_map["workspace_high_water_observation"]
    if (
        material_document["credential_lease"] != credential_payload["credential_lease"]
        or material_document["health"] != health_payload["health"]
        or material_document["worker_session"] != deployment_payload["worker_session"]
        or material_document["credential_lease_sha256"]
        != credential_payload["credential_lease_sha256"]
        or material_document["health_observation_sha256"]
        != health_payload["health_observation_sha256"]
        or material_document["executor_deployment_sha256"]
        != deployment_payload["executor_deployment_sha256"]
        or material_document["monitor_observation_sha256"]
        != monitor_payload["monitor_observation_sha256"]
        or source_document["workspace_high_water_sha256"]
        != workspace_payload["high_water_sha256"]
        or source_document["session_authority_id"]
        != fence_payload["session_authority_id"]
        or source_document["session_authority_sha256"]
        != fence_payload["session_authority_sha256"]
        or source_document["execution_session_id"]
        != fence_payload["execution_session_id"]
        or source_document["execution_session_sha256"]
        != fence_payload["execution_session_sha256"]
        or source_document["owner_epoch"] != fence_payload["owner_epoch"]
        or source_document["fence_generation"] != fence_payload["fence_generation"]
    ):
        raise StoreIntegrityError("Action publication observation source is inconsistent")
    worker = WorkerSession.from_dict(material_document["worker_session"])
    credential = CredentialLease.from_dict(material_document["credential_lease"])
    health = HealthEvidence.from_dict(material_document["health"])
    expected_fence = action_fence_token_sha256(
        session_authority_id=source_document["session_authority_id"],
        execution_session_id=source_document["execution_session_id"],
        owner_epoch=source_document["owner_epoch"],
        fence_generation=source_document["fence_generation"],
    )
    if (
        worker.session_id != source_document["execution_session_id"]
        or worker.leader_epoch != source_document["owner_epoch"]
        or worker.fence_token_sha256 != expected_fence
        or credential.session_id != worker.session_id
        or credential.worker_id != worker.worker_id
        or credential.leader_epoch != worker.leader_epoch
        or credential.fence_token_sha256 != expected_fence
        or health.session_id != worker.session_id
        or health.worker_id != worker.worker_id
        or health.leader_epoch != worker.leader_epoch
        or health.fence_token_sha256 != expected_fence
    ):
        raise StoreIntegrityError("Action material session or fence authority is inconsistent")
    phase165_catalog = parse_executable_action_catalog(material_document["catalog"])
    phase165_parameters = parse_action_parameter_set(
        material_document["parameters"],
        phase165_catalog,
    )
    phase165_target = parse_target_action_descriptor(material_document["target"])
    phase165_catalog_document = phase165_catalog.to_dict()
    phase165_target_document = phase165_target.to_dict()
    source_catalog_document = catalog.to_dict()
    source_target_document = target.to_dict()
    source_budget_document = budget.to_dict()
    source_safety_document = safety.to_dict()
    action_type = proposal.to_dict()["selected_action_type"]
    entry = _catalog_action(phase165_catalog, action_type)
    source_entry = next(
        item for item in source_catalog_document["entries"] if item["action_type"] == action_type
    )
    action_sha256 = _resolved_action_sha256(
        catalog=phase165_catalog,
        entry=entry,
        parameters=phase165_parameters,
        target=phase165_target,
        action_tier=ActionTier(proposal.to_dict()["requested_action_tier"]),
    )
    context = ContextBinding.from_dict(material_document["context"])
    stop = StopConditions.from_dict(material_document["stop_conditions"])
    restoration = RestorationDuties.from_dict(material_document["restoration_duties"])
    obligations = tuple(
        EvidenceObligation.from_dict(item) for item in material_document["evidence_obligations"]
    )
    requested_tier = proposal.to_dict()["requested_action_tier"]
    requested_at = parse_timestamp(material_document["requested_at"], "material requested_at")
    stop_deadline = parse_timestamp(stop.stop_deadline_at, "stop deadline")
    monitor_observed = parse_timestamp(
        monitor_payload["heartbeat_observed_at"], "monitor observed_at"
    )
    monitor_expires = parse_timestamp(
        monitor_payload["heartbeat_expires_at"], "monitor expires_at"
    )
    if (
        phase165_catalog_document["catalog_id"] != source_catalog_document["catalog_id"]
        or phase165_catalog_document["catalog_version"]
        != source_catalog_document["catalog_version"]
        or phase165_catalog_document["registry_sha256"]
        != source_catalog_document["registry_sha256"]
        or entry["parameter_contract_sha256"] != source_entry["parameter_schema_sha256"]
        or entry["tool_artifact_ref"] != source_entry["tool_artifact_ref"]
        or entry["tool_artifact_sha256"] != source_entry["tool_artifact_sha256"]
        or entry["tool_exact_version"] != source_entry["tool_exact_version"]
        or entry["maximum_action_tier"] != source_entry["maximum_action_tier"]
        or phase165_target_document["target_id"] != source_target_document["target_id"]
        or phase165_target_document["target_sha256"] != source_target_document["target_sha256"]
        or phase165_target_document["target_scope_sha256"] != source_target_document["scope_sha256"]
        or phase165_target_document["authority_snapshot_sha256"]
        != source_target_document["authority_snapshot_sha256"]
        or phase165_target_document["environment"] != source_target_document["environment"]
        or action_type not in source_target_document["allowed_action_types"]
        or action_type not in source_safety_document["action_types"]
        or source_target_document["target_kind"] not in source_entry["target_kinds"]
        or TIER_ORDER[requested_tier] > TIER_ORDER[entry["maximum_action_tier"]]
        or TIER_ORDER[requested_tier]
        > TIER_ORDER[source_target_document["maximum_action_tier"]]
        or TIER_ORDER[requested_tier]
        > TIER_ORDER[source_safety_document["maximum_action_tier"]]
        or phase165_parameters.parameter_set_id != proposal.to_dict()["parameter_set_id"]
        or phase165_parameters.parameter_set_sha256 != proposal.to_dict()["parameter_set_sha256"]
        or context.scope_sha256 != source_target_document["scope_sha256"]
        or credential.permitted_action_sha256 != action_sha256
        or stop.action_sha256 != action_sha256
        or restoration.action_sha256 != action_sha256
        or any(item.action_sha256 != action_sha256 for item in obligations)
        or stop.maximum_impact_events
        != source_safety_document["impact_limits"]["maximum_impact_events"]
        or stop.stop_contract_sha256 != action_stop_contract_sha256(safety)
        or stop.monitor_worker_id != source_safety_document["monitor"]["principal_profile_id"]
        or stop.monitor_worker_id != monitor_payload["monitor_worker_id"]
        or stop.monitor_session_id != monitor_payload["monitor_session_id"]
        or monitor_payload["monitor_id"]
        != source_safety_document["monitor"]["monitor_id"]
        or monitor_payload["principal_profile_id"]
        != source_safety_document["monitor"]["principal_profile_id"]
        or monitor_payload["principal_subject"]
        != source_safety_document["monitor"]["principal_subject"]
        or not (
            monitor_observed
            <= parse_timestamp(material_document["observed_at"], "material observed_at")
            < monitor_expires
        )
        or (monitor_expires - monitor_observed).total_seconds()
        > source_safety_document["monitor"]["heartbeat_timeout_seconds"]
        or (stop_deadline - requested_at).total_seconds() * 1000
        > source_safety_document["deadline"]["maximum_duration_ms"]
        or stop_deadline
        > parse_timestamp(material_document["expires_at"], "material expires_at")
        or source_budget_document["per_action_ceiling"]["request_bytes"]
        > source_safety_document["impact_limits"]["maximum_request_bytes"]
        or source_budget_document["per_action_ceiling"]["response_bytes"]
        > source_safety_document["impact_limits"]["maximum_response_bytes"]
        or source_budget_document["per_action_ceiling"]["duration_ms"]
        > source_safety_document["impact_limits"]["maximum_duration_ms"]
        or source_budget_document["per_action_ceiling"]["impact_events"]
        > source_safety_document["impact_limits"]["maximum_impact_events"]
        or source_budget_document["scope_sha256"] != context.scope_sha256
        or source_safety_document["scope_sha256"] != context.scope_sha256
        or source_safety_document["target_sha256"] != phase165_target_document["target_sha256"]
        or restoration.restoration_plan_sha256
        != source_safety_document["restoration"]["restoration_plan_sha256"]
        or restoration.owner_profile_id != source_safety_document["restoration"]["owner_profile_id"]
        or restoration.verifier_profile_id
        != source_safety_document["restoration"]["verifier_profile_id"]
    ):
        raise StoreIntegrityError("Action material does not reconstruct the published action")
    body = {
        "schema_version": 1,
        "kind": PUBLICATION_KIND,
        **boundary,
        "source_records": bindings,
        "material_snapshot_id": material.material_snapshot_id,
        "material_snapshot_sha256": material.material_snapshot_sha256,
        "idempotency_key_sha256": idempotency_key_sha256,
        "published_at": published_at,
        "effects": dict(NO_EFFECTS),
    }
    return AuthenticatedActionAuthorityPublication.from_dict(
        _address(
            PUBLICATION_DOMAIN,
            "AAPB-",
            body,
            "publication_id",
            "publication_sha256",
        )
    )


def _canonical_document(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not str:
        raise StoreIntegrityError(f"Stored {label} type is invalid")
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError(f"Stored {label} is invalid") from exc
    if type(document) is not dict or _canonical_json(document) != value:
        raise StoreIntegrityError(f"Stored {label} is not canonical")
    return document


def _record_identity(record: Any) -> tuple[str, str]:
    return record.record_id, record.content_sha256


def _head_sha256(
    *,
    mission_id: str,
    source_kind: str,
    head_sequence: int,
    record_id: str,
    record_sha256: str,
    previous_head_sha256: str | None,
    advanced_at: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": HEAD_DOMAIN,
            "head": {
                "advanced_at": advanced_at,
                "head_sequence": head_sequence,
                "mission_id": mission_id,
                "previous_head_sha256": previous_head_sha256,
                "record_id": record_id,
                "record_sha256": record_sha256,
                "source_kind": source_kind,
            },
        }
    )


def _verify_revision_rows(
    connection: sqlite3.Connection,
    mission_id: str | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM action_authority_revisions"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY mission_id, record_kind, revision",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    records: dict[tuple[str, str], dict[str, Any]] = {}
    chains: dict[tuple[str, str], tuple[int, str, Any, Any]] = {}
    for row in rows:
        for field in (
            "record_kind",
            "record_id",
            "record_sha256",
            "tenant_id",
            "mission_id",
            "plan_id",
            "effective_at",
            "expires_at",
            "record_json",
            "committed_at",
        ):
            if type(row[field]) is not str:
                raise StoreIntegrityError("Action authority revision column type is invalid")
        if type(row["revision"]) is not int or row["revision"] < 1:
            raise StoreIntegrityError("Action authority revision number is invalid")
        if (
            row["previous_revision_sha256"] is not None
            and type(row["previous_revision_sha256"]) is not str
        ):
            raise StoreIntegrityError("Action authority previous revision type is invalid")
        document = _canonical_document(row["record_json"], "action authority revision")
        try:
            record = parse_action_authority_contract(document)
        except (TypeError, ValueError) as exc:
            raise StoreIntegrityError("Action authority revision is invalid") from exc
        if type(record) is not REVISION_TYPES.get(row["record_kind"]):
            raise StoreIntegrityError("Action authority revision kind is invalid")
        record_id, record_sha256 = _record_identity(record)
        if (
            record_id != row["record_id"]
            or record_sha256 != row["record_sha256"]
            or document["tenant_id"] != row["tenant_id"]
            or document["mission_id"] != row["mission_id"]
            or document["plan_id"] != row["plan_id"]
            or document["revision"] != row["revision"]
            or document["previous_revision_sha256"] != row["previous_revision_sha256"]
            or document["effective_at"] != row["effective_at"]
            or document["expires_at"] != row["expires_at"]
            or parse_timestamp(row["committed_at"], "authority committed_at")
            < parse_timestamp(row["effective_at"], "authority effective_at")
        ):
            raise StoreIntegrityError("Action authority revision binding is invalid")
        chain_key = (row["mission_id"], row["record_kind"])
        previous = chains.get(chain_key)
        effective_at = parse_timestamp(row["effective_at"], "authority effective_at")
        expires_at = parse_timestamp(row["expires_at"], "authority expires_at")
        if (
            previous is None
            and (row["revision"] != 1 or row["previous_revision_sha256"] is not None)
        ) or (
            previous is not None
            and (
                row["revision"] != previous[0] + 1
                or row["previous_revision_sha256"] != previous[1]
                or effective_at <= previous[2]
                or expires_at <= previous[3]
            )
        ):
            raise StoreIntegrityError("Action authority revision chain is invalid")
        chains[chain_key] = (
            row["revision"],
            row["record_sha256"],
            effective_at,
            expires_at,
        )
        records[(row["record_kind"], row["record_id"])] = document
    return records


def _verify_proposal_rows(
    connection: sqlite3.Connection,
    mission_id: str | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM action_authority_proposal_imports"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY proposal_import_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Action proposal import column type is invalid")
        document = _canonical_document(row["proposal_json"], "action proposal import")
        try:
            record = AuthenticatedProposalMaterialImport.from_dict(document)
        except (TypeError, ValueError) as exc:
            raise StoreIntegrityError("Action proposal import is invalid") from exc
        product = document["reviewed_product"]
        catalog = document["catalog_binding"]
        target = document["target_binding"]
        expected = {
            "proposal_import_id": record.proposal_import_id,
            "proposal_import_sha256": record.proposal_import_sha256,
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "plan_id": document["plan_id"],
            "product_id": product["product_id"],
            "product_sha256": product["product_sha256"],
            "review_snapshot_id": document["review_snapshot_id"],
            "review_snapshot_sha256": document["review_snapshot_sha256"],
            "review_closure_id": document["review_closure_id"],
            "review_closure_sha256": document["review_closure_sha256"],
            "catalog_revision_id": catalog["catalog_revision_id"],
            "catalog_revision_sha256": catalog["catalog_revision_sha256"],
            "target_revision_id": target["target_revision_id"],
            "target_revision_sha256": target["target_revision_sha256"],
            "imported_at": document["imported_at"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise StoreIntegrityError("Action proposal import binding is invalid")
        parse_timestamp(row["committed_at"], "proposal committed_at")
        records[(AuthenticatedProposalMaterialImport.KIND, record.record_id)] = document
    return records


def _verify_observation_rows(
    connection: sqlite3.Connection,
    mission_id: str | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM action_authority_observations"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY mission_id, observation_kind, observed_at",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        document = _canonical_document(row["observation_json"], "action authority observation")
        observation = ActionAuthorityObservation.from_dict(document)
        expected = {
            "observation_kind": observation.KIND,
            "observation_id": observation.record_id,
            "observation_sha256": observation.content_sha256,
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "plan_id": document["plan_id"],
            "observed_at": document["observed_at"],
            "valid_until": document["valid_until"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise StoreIntegrityError("Action authority observation columns are inconsistent")
        if parse_timestamp(row["committed_at"], "observation committed_at") < parse_timestamp(
            row["observed_at"], "observation observed_at"
        ):
            raise StoreIntegrityError("Action observation commit chronology is invalid")
        records[(observation.KIND, observation.record_id)] = document
    return records


def _verify_source_heads(
    connection: sqlite3.Connection,
    records: Mapping[tuple[str, str], Mapping[str, Any]],
    mission_id: str | None,
) -> dict[tuple[str, str], sqlite3.Row]:
    rows = connection.execute(
        "SELECT * FROM action_authority_source_heads"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY mission_id, source_kind, head_sequence",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    latest: dict[tuple[str, str], sqlite3.Row] = {}
    previous: dict[tuple[str, str], tuple[int, str, Any]] = {}
    for row in rows:
        if (
            any(
                type(row[field]) is not str
                for field in (
                    "mission_id",
                    "source_kind",
                    "record_id",
                    "record_sha256",
                    "head_sha256",
                    "advanced_at",
                )
            )
            or type(row["head_sequence"]) is not int
        ):
            raise StoreIntegrityError("Action source head column type is invalid")
        if row["previous_head_sha256"] is not None and type(row["previous_head_sha256"]) is not str:
            raise StoreIntegrityError("Action source previous head type is invalid")
        key = (row["mission_id"], row["source_kind"])
        prior = previous.get(key)
        advanced_at = parse_timestamp(row["advanced_at"], "source head advanced_at")
        if (
            (
                prior is None
                and (row["head_sequence"] != 1 or row["previous_head_sha256"] is not None)
            )
            or (
                prior is not None
                and (
                    row["head_sequence"] != prior[0] + 1
                    or row["previous_head_sha256"] != prior[1]
                    or advanced_at <= prior[2]
                )
            )
            or row["head_sha256"]
            != _head_sha256(
                mission_id=row["mission_id"],
                source_kind=row["source_kind"],
                head_sequence=row["head_sequence"],
                record_id=row["record_id"],
                record_sha256=row["record_sha256"],
                previous_head_sha256=row["previous_head_sha256"],
                advanced_at=row["advanced_at"],
            )
        ):
            raise StoreIntegrityError("Action source head chain is invalid")
        document = records.get((row["source_kind"], row["record_id"]))
        if document is None:
            if row["source_kind"] != ExactActionSourceHeadBundle.KIND:
                raise StoreIntegrityError("Action source head record is missing")
        else:
            parsed = (
                ActionAuthorityObservation.from_dict(document)
                if row["source_kind"] in OBSERVATION_KINDS
                else parse_action_authority_contract(document)
            )
            if (
                parsed.content_sha256 != row["record_sha256"]
                or document["mission_id"] != row["mission_id"]
            ):
                raise StoreIntegrityError("Action source head binding is invalid")
        previous[key] = (row["head_sequence"], row["head_sha256"], advanced_at)
        latest[key] = row
    return latest


def _verify_budget_accounts(
    connection: sqlite3.Connection,
    revisions: Mapping[tuple[str, str], Mapping[str, Any]],
    mission_id: str | None,
) -> dict[str, tuple[str, frozenset[str], str, str, int, str]]:
    rows = connection.execute(
        "SELECT * FROM action_budget_accounts"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY account_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    heads: dict[str, tuple[str, frozenset[str], str, str, int, str]] = {}
    for row in rows:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Action budget account column type is invalid")
        opened_at = parse_timestamp(row["opened_at"], "action budget opened_at")
        initial_limits = _canonical_document(
            row["limits_json"], "initial action budget limits"
        )
        if set(initial_limits) != set(RESOURCE_FIELDS) or any(
            type(initial_limits[field]) is not int or initial_limits[field] < 1
            for field in RESOURCE_FIELDS
        ):
            raise StoreIntegrityError("Initial action budget limits are invalid")
        initial_revision = revisions.get(
            (ActionBudgetPolicyRevision.KIND, row["budget_revision_id"])
        )
        expected_id = (
            "ABA-"
            + _canonical_sha256(
                {
                    "account": {
                        "budget_id": row["budget_id"],
                        "mission_id": row["mission_id"],
                        "opened_at": row["opened_at"],
                        "tenant_id": row["tenant_id"],
                    },
                    "domain": BUDGET_ACCOUNT_DOMAIN,
                }
            )
            .removeprefix("sha256:")[:32]
            .upper()
        )
        if (
            initial_revision is None
            or initial_revision["budget_revision_sha256"]
            != row["budget_revision_sha256"]
            or initial_revision["budget_id"] != row["budget_id"]
            or initial_revision["limits"] != initial_limits
            or initial_revision["tenant_id"] != row["tenant_id"]
            or initial_revision["mission_id"] != row["mission_id"]
            or expected_id != row["account_id"]
        ):
            raise StoreIntegrityError("Action budget account binding is invalid")
        bindings = connection.execute(
            "SELECT * FROM action_budget_policy_bindings "
            "WHERE account_id = ? ORDER BY binding_sequence",
            (row["account_id"],),
        ).fetchall()
        if not bindings:
            raise StoreIntegrityError("Action budget account has no policy binding")
        previous_binding_sha256: str | None = None
        previous_bound_at = None
        bound_revisions: dict[tuple[str, str], dict[str, Any]] = {}
        bound_history: list[tuple[Any, dict[str, Any]]] = []
        for sequence, binding in enumerate(bindings, start=1):
            if (
                type(binding["binding_sequence"]) is not int
                or binding["binding_sequence"] != sequence
                or any(
                    type(binding[field]) is not str
                    for field in (
                        "account_id",
                        "budget_revision_id",
                        "budget_revision_sha256",
                        "limits_json",
                        "binding_sha256",
                        "bound_at",
                    )
                )
                or binding["account_id"] != row["account_id"]
                or binding["previous_binding_sha256"] != previous_binding_sha256
            ):
                raise StoreIntegrityError("Action budget policy binding chain is invalid")
            limits = _canonical_document(
                binding["limits_json"], "action budget policy limits"
            )
            revision = revisions.get(
                (ActionBudgetPolicyRevision.KIND, binding["budget_revision_id"])
            )
            if (
                revision is None
                or revision["budget_revision_sha256"]
                != binding["budget_revision_sha256"]
                or revision["budget_id"] != row["budget_id"]
                or revision["tenant_id"] != row["tenant_id"]
                or revision["mission_id"] != row["mission_id"]
                or revision["limits"] != limits
            ):
                raise StoreIntegrityError("Action budget policy link is invalid")
            bound_at = parse_timestamp(
                binding["bound_at"], "action budget policy bound_at"
            )
            if bound_at < opened_at:
                raise StoreIntegrityError("Action budget policy predates its account")
            if previous_bound_at is not None and bound_at <= previous_bound_at:
                raise StoreIntegrityError("Action budget policy chronology regressed")
            effective_at = parse_timestamp(
                revision["effective_at"], "action budget policy effective_at"
            )
            expires_at = parse_timestamp(
                revision["expires_at"], "action budget policy expires_at"
            )
            if not effective_at <= bound_at < expires_at:
                raise StoreIntegrityError("Action budget policy was bound outside its window")
            body = {
                "account_id": binding["account_id"],
                "binding_sequence": binding["binding_sequence"],
                "budget_revision_id": binding["budget_revision_id"],
                "budget_revision_sha256": binding["budget_revision_sha256"],
                "limits": limits,
                "previous_binding_sha256": binding["previous_binding_sha256"],
                "bound_at": binding["bound_at"],
            }
            expected_binding_sha256 = _canonical_sha256(
                {
                    "binding": body,
                    "domain": BUDGET_POLICY_BINDING_DOMAIN,
                }
            )
            if binding["binding_sha256"] != expected_binding_sha256:
                raise StoreIntegrityError("Action budget policy binding identity is invalid")
            if sequence == 1 and (
                binding["budget_revision_id"] != row["budget_revision_id"]
                or binding["budget_revision_sha256"]
                != row["budget_revision_sha256"]
                or limits != initial_limits
            ):
                raise StoreIntegrityError("Initial action budget policy link is inconsistent")
            previous_binding_sha256 = expected_binding_sha256
            previous_bound_at = bound_at
            bound_revisions[
                (binding["budget_revision_id"], binding["budget_revision_sha256"])
            ] = revision
            bound_history.append((bound_at, revision))
        events = connection.execute(
            "SELECT * FROM action_budget_account_events "
            "WHERE account_id = ? ORDER BY event_sequence",
            (row["account_id"],),
        ).fetchall()
        empty_head = _canonical_sha256(
            {
                "domain": BUDGET_EVENT_DOMAIN,
                "empty_account_id": row["account_id"],
            }
        )
        head_history = {empty_head}
        previous_sha: str | None = None
        previous_recorded_at = None
        usage = {field: 0 for field in RESOURCE_FIELDS}
        reservations: dict[str, dict[str, Any]] = {}
        settled: dict[str, dict[str, int]] = {}
        released: dict[str, dict[str, int]] = {}
        for sequence, event in enumerate(events, start=1):
            if (
                type(event["event_sequence"]) is not int
                or event["event_sequence"] != sequence
                or any(
                    type(event[field]) is not str
                    for field in (
                        "account_id",
                        "event_id",
                        "event_sha256",
                        "event_kind",
                        "receipt_id",
                        "budget_revision_id",
                        "budget_revision_sha256",
                        "reservation_id",
                        "reservation_sha256",
                        "idempotency_key_sha256",
                        "resources_json",
                        "recorded_at",
                    )
                )
                or event["previous_event_sha256"] != previous_sha
                or not event["receipt_id"]
            ):
                raise StoreIntegrityError("Action budget event chain is invalid")
            resources = _canonical_document(
                event["resources_json"], "action budget event resources"
            )
            if set(resources) != set(RESOURCE_FIELDS) or any(
                type(resources[field]) is not int or resources[field] < 0
                for field in RESOURCE_FIELDS
            ):
                raise StoreIntegrityError("Action budget event resources are invalid")
            recorded_at = parse_timestamp(
                event["recorded_at"], "action budget event recorded_at"
            )
            if previous_recorded_at is not None and recorded_at < previous_recorded_at:
                raise StoreIntegrityError("Action budget event chronology regressed")
            revision = bound_revisions.get(
                (event["budget_revision_id"], event["budget_revision_sha256"])
            )
            if revision is None:
                raise StoreIntegrityError("Action budget event revision is not bound")
            active = [item for bound_at, item in bound_history if bound_at <= recorded_at]
            if not active:
                raise StoreIntegrityError("Action budget event has no active policy")
            active_revision = active[-1]
            receipt_id = event["receipt_id"]
            if event["event_kind"] == "reserve":
                if (
                    receipt_id in reservations
                    or event["execution_id"] is not None
                    or event["execution_intent_sha256"] is not None
                    or event["claim_id"] is not None
                    or event["claim_sha256"] is not None
                    or event["dispatch_id"] is not None
                ):
                    raise StoreIntegrityError("Action budget receipt was reserved twice")
                if any(
                    resources[field] != revision["per_action_ceiling"][field]
                    for field in RESOURCE_FIELDS
                ) or revision is not active_revision:
                    raise StoreIntegrityError(
                        "Action budget reserve differs from its signed per-action ceiling"
                    )
                reservation_body = {
                    "account_id": event["account_id"],
                    "budget_revision_id": event["budget_revision_id"],
                    "budget_revision_sha256": event["budget_revision_sha256"],
                    "idempotency_key_sha256": event["idempotency_key_sha256"],
                    "receipt_id": receipt_id,
                    "reserved_at": event["recorded_at"],
                    "resources": resources,
                }
                reservation_sha256 = _canonical_sha256(
                    {
                        "domain": BUDGET_RESERVATION_DOMAIN,
                        "reservation": reservation_body,
                    }
                )
                reservation_id = (
                    "ABR-"
                    + reservation_sha256.removeprefix("sha256:")[:32].upper()
                )
                if (
                    event["reservation_id"] != reservation_id
                    or event["reservation_sha256"] != reservation_sha256
                ):
                    raise StoreIntegrityError("Action budget reservation identity is invalid")
                reservations[receipt_id] = {
                    "resources": resources,
                    "reservation_id": reservation_id,
                    "reservation_sha256": reservation_sha256,
                    "budget_revision_id": event["budget_revision_id"],
                    "budget_revision_sha256": event["budget_revision_sha256"],
                    "idempotency_key_sha256": event["idempotency_key_sha256"],
                    "event_id": event["event_id"],
                    "event_sha256": event["event_sha256"],
                    "recorded_at": event["recorded_at"],
                }
                for field in RESOURCE_FIELDS:
                    usage[field] += resources[field]
            elif event["event_kind"] == "settle":
                reservation = reservations.get(receipt_id)
                if (
                    reservation is None
                    or receipt_id in settled
                    or receipt_id in released
                    or any(
                        type(event[field]) is not str or not event[field]
                        for field in (
                            "execution_id",
                            "execution_intent_sha256",
                            "claim_id",
                            "claim_sha256",
                            "dispatch_id",
                        )
                    )
                ):
                    raise StoreIntegrityError("Action budget settlement is not conserved")
                if any(
                    resources[field] > reservation["resources"][field]
                    for field in RESOURCE_FIELDS
                ):
                    raise StoreIntegrityError("Action budget settlement exceeds reservation")
                settled[receipt_id] = resources
            elif event["event_kind"] == "release":
                reservation = reservations.get(receipt_id)
                charged_event = next(
                    (
                        item
                        for item in events
                        if item["receipt_id"] == receipt_id
                        and item["event_kind"] == "settle"
                        and item["event_sequence"] < event["event_sequence"]
                    ),
                    None,
                )
                predispatch_abort = None
                preinvocation_abort = None
                if (
                    charged_event is None
                    and event["dispatch_id"] is not None
                    and int(connection.execute("PRAGMA user_version").fetchone()[0]) >= 34
                ):
                    predispatch_abort = connection.execute(
                        "SELECT * FROM action_execution_predispatch_aborts "
                        "WHERE request_id = ? AND claim_id = ? AND dispatch_id = ? "
                        "AND receipt_id = ?",
                        (
                            event["execution_id"],
                            event["claim_id"],
                            event["dispatch_id"],
                            receipt_id,
                        ),
                    ).fetchone()
                    if (
                        predispatch_abort is None
                        and int(
                            connection.execute("PRAGMA user_version").fetchone()[0]
                        )
                        >= 37
                    ):
                        preinvocation_abort = connection.execute(
                            "SELECT pre.abort_id FROM "
                            "action_execution_preinvocation_aborts AS pre "
                            "JOIN action_execution_requests AS request "
                            "ON request.request_id = pre.request_id "
                            "AND request.request_sha256 = pre.request_sha256 "
                            "JOIN action_execution_claims AS claim "
                            "ON claim.claim_id = pre.claim_id "
                            "AND claim.claim_sha256 = pre.claim_sha256 "
                            "JOIN action_execution_dispatch_attempts AS dispatch "
                            "ON dispatch.dispatch_id = pre.dispatch_id "
                            "AND dispatch.dispatch_sha256 = pre.dispatch_sha256 "
                            "WHERE pre.request_id = ? AND pre.claim_id = ? "
                            "AND pre.dispatch_id = ? AND request.receipt_id = ? "
                            "AND pre.claim_sha256 = ?",
                            (
                                event["execution_id"],
                                event["claim_id"],
                                event["dispatch_id"],
                                receipt_id,
                                event["claim_sha256"],
                            ),
                        ).fetchone()
                if (
                    reservation is None
                    or receipt_id in released
                    or type(event["execution_id"]) is not str
                    or not event["execution_id"]
                    or type(event["execution_intent_sha256"]) is not str
                    or not event["execution_intent_sha256"]
                    or type(event["claim_id"]) is not str
                    or not event["claim_id"]
                    or type(event["claim_sha256"]) is not str
                    or not event["claim_sha256"]
                    or (
                        charged_event is None
                        and event["dispatch_id"] is not None
                        and predispatch_abort is None
                        and preinvocation_abort is None
                    )
                    or (
                        charged_event is not None
                        and (
                            event["execution_id"] != charged_event["execution_id"]
                            or event["execution_intent_sha256"]
                            != charged_event["execution_intent_sha256"]
                            or event["claim_id"] != charged_event["claim_id"]
                            or event["claim_sha256"]
                            != charged_event["claim_sha256"]
                            or event["dispatch_id"] != charged_event["dispatch_id"]
                        )
                    )
                ):
                    raise StoreIntegrityError("Action budget release is not conserved")
                charged = settled.get(receipt_id)
                expected_release = {
                    field: (
                        reservation["resources"][field]
                        if charged is None
                        else reservation["resources"][field] - charged[field]
                    )
                    for field in RESOURCE_FIELDS
                }
                if resources != expected_release:
                    raise StoreIntegrityError("Action budget release is not conserved")
                released[receipt_id] = resources
                for field in RESOURCE_FIELDS:
                    usage[field] -= resources[field]
                    if usage[field] < 0:
                        raise StoreIntegrityError("Action budget usage became negative")
            else:
                raise StoreIntegrityError("Action budget event kind is invalid")
            reservation = reservations[receipt_id]
            if (
                event["reservation_id"] != reservation["reservation_id"]
                or event["reservation_sha256"] != reservation["reservation_sha256"]
                or event["budget_revision_id"] != reservation["budget_revision_id"]
                or event["budget_revision_sha256"]
                != reservation["budget_revision_sha256"]
                or event["idempotency_key_sha256"]
                != reservation["idempotency_key_sha256"]
            ):
                raise StoreIntegrityError("Action budget terminal lineage is invalid")
            if any(
                usage[field] > active_revision["limits"][field]
                for field in RESOURCE_FIELDS
            ):
                raise StoreIntegrityError("Action budget account exceeds an active limit")
            body = {
                "account_id": event["account_id"],
                "budget_revision_id": event["budget_revision_id"],
                "budget_revision_sha256": event["budget_revision_sha256"],
                "claim_id": event["claim_id"],
                "claim_sha256": event["claim_sha256"],
                "dispatch_id": event["dispatch_id"],
                "event_kind": event["event_kind"],
                "event_sequence": event["event_sequence"],
                "execution_id": event["execution_id"],
                "execution_intent_sha256": event[
                    "execution_intent_sha256"
                ],
                "idempotency_key_sha256": event["idempotency_key_sha256"],
                "previous_event_sha256": event["previous_event_sha256"],
                "receipt_id": event["receipt_id"],
                "recorded_at": event["recorded_at"],
                "reservation_id": event["reservation_id"],
                "reservation_sha256": event["reservation_sha256"],
                "resources": resources,
            }
            expected_sha = _canonical_sha256(
                {"domain": BUDGET_EVENT_DOMAIN, "event": body}
            )
            expected_id = "ABE-" + expected_sha.removeprefix("sha256:")[:32].upper()
            if (
                event["event_sha256"] != expected_sha
                or event["event_id"] != expected_id
            ):
                raise StoreIntegrityError("Action budget event identity is invalid")
            receipt = connection.execute(
                "SELECT mission_id FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if receipt is None or receipt["mission_id"] != row["mission_id"]:
                raise StoreIntegrityError("Action budget event receipt is not in custody")
            if event["event_kind"] != "reserve":
                consumption = connection.execute(
                    "SELECT * FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if consumption is None:
                    revocation_row = connection.execute(
                        "SELECT * FROM action_admission_revocations "
                        "WHERE receipt_id = ?",
                        (receipt_id,),
                    ).fetchone()
                    if (
                        event["event_kind"] != "release"
                        or revocation_row is None
                        or type(revocation_row["revocation_json"]) is not str
                    ):
                        raise StoreIntegrityError(
                            "Action budget terminal event has no execution or revocation"
                        )
                    try:
                        revocation = parse_action_admission_revocation(
                            _canonical_document(
                                revocation_row["revocation_json"],
                                "budget release revocation",
                            )
                        )
                    except (TypeError, ValueError) as exc:
                        raise StoreIntegrityError(
                            "Action budget revocation release is invalid"
                        ) from exc
                    revocation_document = revocation.to_dict()
                    revocation_lineage_sha256 = _canonical_sha256(
                        {
                            "domain": REVOCATION_BUDGET_RELEASE_DOMAIN,
                            "revocation": revocation_document,
                        }
                    )
                    if (
                        event["execution_id"] != revocation.revocation_id
                        or event["execution_intent_sha256"]
                        != revocation.revocation_sha256
                        or event["claim_id"]
                        != revocation_document["control_authorization"][
                            "assertion_id"
                        ]
                        or event["claim_sha256"] != revocation_lineage_sha256
                        or event["dispatch_id"] is not None
                        or event["recorded_at"] != revocation_document["revoked_at"]
                    ):
                        raise StoreIntegrityError(
                            "Action budget release differs from revocation custody"
                        )
                elif (
                    event["execution_id"] != consumption["execution_id"]
                    or event["execution_intent_sha256"]
                    != consumption["execution_intent_sha256"]
                    or event["claim_id"] != consumption["claim_id"]
                    or event["claim_sha256"] != consumption["claim_sha256"]
                    or event["recorded_at"] < consumption["consumed_at"]
                ):
                    raise StoreIntegrityError(
                        "Action budget terminal event differs from execution consumption"
                    )
            previous_sha = expected_sha
            previous_recorded_at = recorded_at
            head_history.add(expected_sha)
        for receipt_id, charged in settled.items():
            reserved = reservations[receipt_id]["resources"]
            has_remainder = any(
                charged[field] < reserved[field] for field in RESOURCE_FIELDS
            )
            if has_remainder != (receipt_id in released):
                raise StoreIntegrityError(
                    "Action budget terminal settlement remainder is incomplete"
                )
        revocations = connection.execute(
            "SELECT revocation.receipt_id "
            "FROM action_admission_revocations AS revocation "
            "JOIN action_budget_receipt_reservations AS reservation "
            "ON reservation.receipt_id = revocation.receipt_id "
            "WHERE revocation.mission_id = ? AND reservation.account_id = ?",
            (row["mission_id"], row["account_id"]),
        ).fetchall()
        for revocation in revocations:
            receipt_id = revocation["receipt_id"]
            consumption = connection.execute(
                "SELECT 1 FROM action_admission_execution_consumptions "
                "WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if consumption is None and receipt_id not in released:
                raise StoreIntegrityError(
                    "Revoked unconsumed action budget reservation is not released"
                )
        current_revision = bound_history[-1][1]
        current_limits = current_revision["limits"]
        if any(usage[field] > current_limits[field] for field in RESOURCE_FIELDS):
            raise StoreIntegrityError("Action budget rotation undercuts committed usage")
        head = connection.execute(
            "SELECT * FROM action_budget_account_heads WHERE account_id = ?",
            (row["account_id"],),
        ).fetchone()
        if (
            head is None
            or type(head["policy_binding_count"]) is not int
            or type(head["event_count"]) is not int
            or any(
                type(head[field]) is not str
                for field in (
                    "account_id",
                    "policy_head_sha256",
                    "event_head_sha256",
                    "updated_at",
                )
            )
            or head["account_id"] != row["account_id"]
            or head["policy_binding_count"] != len(bindings)
            or head["policy_head_sha256"] != previous_binding_sha256
            or head["event_count"] != len(events)
            or head["event_head_sha256"] != (previous_sha or empty_head)
            or parse_timestamp(head["updated_at"], "action budget head updated_at")
            != max(
                parse_timestamp(bindings[-1]["bound_at"], "budget binding bound_at"),
                (
                    parse_timestamp(events[-1]["recorded_at"], "budget event recorded_at")
                    if events
                    else parse_timestamp(bindings[-1]["bound_at"], "budget binding bound_at")
                ),
            )
        ):
            raise StoreIntegrityError("Action budget account head is inconsistent")
        receipt_rows = connection.execute(
            "SELECT receipt_id, mission_id, idempotency_key_sha256, authority_state_json "
            "FROM action_admission_receipts WHERE mission_id = ?",
            (row["mission_id"],),
        ).fetchall()
        links = connection.execute(
            "SELECT * FROM action_budget_receipt_reservations WHERE account_id = ?",
            (row["account_id"],),
        ).fetchall()
        if len(receipt_rows) != len(reservations) or len(links) != len(reservations):
            raise StoreIntegrityError("Action budget receipt reservation coverage is incomplete")
        links_by_receipt = {link["receipt_id"]: link for link in links}
        for receipt in receipt_rows:
            reservation = reservations.get(receipt["receipt_id"])
            link = links_by_receipt.get(receipt["receipt_id"])
            if reservation is None or link is None:
                raise StoreIntegrityError("Action budget receipt has no exact reserve event")
            authority_state = _canonical_document(
                receipt["authority_state_json"], "receipt authority state"
            )
            receipt_bundle = connection.execute(
                "SELECT bundle_json FROM action_authority_source_bundles "
                "WHERE source_bundle_sha256 = ? AND mission_id = ?",
                (
                    authority_state.get("authority_revision_sha256"),
                    receipt["mission_id"],
                ),
            ).fetchall()
            if len(receipt_bundle) != 1:
                raise StoreIntegrityError("Action budget receipt source bundle is not exact")
            signed_bundle = _canonical_document(
                receipt_bundle[0]["bundle_json"], "receipt source bundle"
            )
            legacy = connection.execute(
                "SELECT * FROM action_admission_budget_reservations WHERE receipt_id = ?",
                (receipt["receipt_id"],),
            ).fetchall()
            if len(legacy) != 1:
                raise StoreIntegrityError("Legacy action budget reservation is not exact")
            legacy_row = legacy[0]
            resources = reservation["resources"]
            if (
                receipt["idempotency_key_sha256"]
                != reservation["idempotency_key_sha256"]
                or signed_bundle["budget_revision_id"]
                != reservation["budget_revision_id"]
                or signed_bundle["budget_revision_sha256"]
                != reservation["budget_revision_sha256"]
                or legacy_row["budget_sha256"]
                != reservation["budget_revision_sha256"]
                or legacy_row["request_cost"] != resources["rate_units"]
                or legacy_row["token_cost"]
                != resources["request_bytes"] + resources["response_bytes"]
                or legacy_row["cost_microunits"] != resources["money_microunits"]
                or legacy_row["reserved_at"] != reservation["recorded_at"]
                or any(
                    link[field] != reservation[field]
                    for field in (
                        "reservation_id",
                        "reservation_sha256",
                        "budget_revision_id",
                        "budget_revision_sha256",
                        "idempotency_key_sha256",
                    )
                )
                or link["reserve_event_id"] != reservation["event_id"]
                or link["reserve_event_sha256"] != reservation["event_sha256"]
                or link["resources_json"] != _canonical_json(resources)
                or link["reserved_at"] != reservation["recorded_at"]
            ):
                raise StoreIntegrityError("Action budget receipt reservation is inconsistent")
        heads[row["mission_id"]] = (
            previous_sha or empty_head,
            frozenset(head_history),
            bindings[-1]["budget_revision_id"],
            bindings[-1]["budget_revision_sha256"],
            int(bindings[-1]["binding_sequence"]),
            str(bindings[-1]["binding_sha256"]),
        )
    receipt_count = connection.execute(
        "SELECT COUNT(*) FROM action_admission_receipts"
        + (" WHERE mission_id = ?" if mission_id is not None else ""),
        () if mission_id is None else (mission_id,),
    ).fetchone()[0]
    linked_count = connection.execute(
        "SELECT COUNT(*) FROM action_budget_receipt_reservations AS link "
        "JOIN action_admission_receipts AS receipt ON receipt.receipt_id = link.receipt_id"
        + (" WHERE receipt.mission_id = ?" if mission_id is not None else ""),
        () if mission_id is None else (mission_id,),
    ).fetchone()[0]
    if receipt_count != linked_count:
        raise StoreIntegrityError("Action admission budget reserve coverage is incomplete")
    return heads


def _verify_bundles(
    connection: sqlite3.Connection,
    records: dict[tuple[str, str], dict[str, Any]],
    latest_heads: Mapping[tuple[str, str], sqlite3.Row],
    budget_heads: Mapping[str, tuple[str, frozenset[str], str, str, int, str]],
    mission_id: str | None,
    *,
    require_current_sources: bool,
) -> None:
    rows = connection.execute(
        "SELECT * FROM action_authority_source_bundles"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY source_bundle_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    for row in rows:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Action source bundle column type is invalid")
        document = _canonical_document(row["bundle_json"], "action source bundle")
        try:
            bundle = ExactActionSourceHeadBundle.from_dict(document)
        except (TypeError, ValueError) as exc:
            raise StoreIntegrityError("Action source bundle is invalid") from exc
        if (
            bundle.source_bundle_id != row["source_bundle_id"]
            or bundle.source_bundle_sha256 != row["source_bundle_sha256"]
            or document["tenant_id"] != row["tenant_id"]
            or document["mission_id"] != row["mission_id"]
            or document["plan_id"] != row["plan_id"]
            or document["observed_at"] != row["observed_at"]
            or document["valid_until"] != row["valid_until"]
        ):
            raise StoreIntegrityError("Action source bundle binding is invalid")
        parse_timestamp(row["committed_at"], "source bundle committed_at")
        current_bundle_head = latest_heads.get(
            (row["mission_id"], ExactActionSourceHeadBundle.KIND)
        )
        linked_bundle_head = connection.execute(
            "SELECT 1 FROM action_authority_source_heads "
            "WHERE mission_id = ? AND source_kind = ? "
            "AND record_id = ? AND record_sha256 = ?",
            (
                row["mission_id"],
                ExactActionSourceHeadBundle.KIND,
                bundle.record_id,
                bundle.content_sha256,
            ),
        ).fetchone()
        if linked_bundle_head is None:
            raise StoreIntegrityError("Action source bundle has no authenticated head")
        is_current_bundle = (
            current_bundle_head is not None
            and current_bundle_head["record_id"] == bundle.record_id
            and current_bundle_head["record_sha256"] == bundle.content_sha256
        )
        for source_kind, fields in SOURCE_BINDINGS.items():
            source = records.get((source_kind, document[fields[0]]))
            if source is None:
                raise StoreIntegrityError("Action source bundle record is missing")
            parsed = parse_action_authority_contract(source)
            linked_source_head = connection.execute(
                "SELECT 1 FROM action_authority_source_heads "
                "WHERE mission_id = ? AND source_kind = ? "
                "AND record_id = ? AND record_sha256 = ?",
                (
                    row["mission_id"],
                    source_kind,
                    document[fields[0]],
                    document[fields[1]],
                ),
            ).fetchone()
            if (
                parsed.content_sha256 != document[fields[1]]
                or source["mission_id"] != row["mission_id"]
                or linked_source_head is None
            ):
                raise StoreIntegrityError("Action source bundle head is invalid")
            if source_kind in REVISION_TYPES and not (
                parse_timestamp(source["effective_at"], "source effective_at")
                <= parse_timestamp(document["observed_at"], "source observed_at")
                < parse_timestamp(source["expires_at"], "source expires_at")
                and parse_timestamp(document["valid_until"], "source valid_until")
                <= parse_timestamp(source["expires_at"], "source expires_at")
            ):
                raise StoreIntegrityError(
                    "Action source bundle outlives a source revision"
                )
            if require_current_sources and is_current_bundle and (
                latest_heads.get((row["mission_id"], source_kind)) is None
                or latest_heads[(row["mission_id"], source_kind)]["record_id"]
                != document[fields[0]]
                or latest_heads[(row["mission_id"], source_kind)]["record_sha256"]
                != document[fields[1]]
            ):
                raise StoreIntegrityError("Current action source bundle head is stale")
        budget_state = budget_heads.get(row["mission_id"])
        if (
            budget_state is None
            or document["budget_ledger_head_sha256"] not in budget_state[1]
        ):
            raise StoreIntegrityError("Action source bundle budget head is invalid")
        bound_budget = connection.execute(
            """
            SELECT binding.bound_at, revision.record_json
            FROM action_budget_accounts AS account
            JOIN action_budget_policy_bindings AS binding
              ON binding.account_id = account.account_id
            JOIN action_authority_revisions AS revision
              ON revision.record_kind = 'action_budget_policy_revision'
             AND revision.record_id = binding.budget_revision_id
             AND revision.record_sha256 = binding.budget_revision_sha256
            WHERE account.mission_id = ?
              AND binding.binding_sequence = ?
              AND binding.binding_sha256 = ?
              AND binding.budget_revision_id = ?
              AND binding.budget_revision_sha256 = ?
            """,
            (
                row["mission_id"],
                document["budget_policy_binding_sequence"],
                document["budget_policy_binding_sha256"],
                document["budget_revision_id"],
                document["budget_revision_sha256"],
            ),
        ).fetchone()
        if bound_budget is None or type(bound_budget["record_json"]) is not str:
            raise StoreIntegrityError("Action source bundle budget policy head is invalid")
        budget_revision = _canonical_document(
            bound_budget["record_json"], "source bundle budget revision"
        )
        observed_at = parse_timestamp(document["observed_at"], "source bundle observed_at")
        if not (
            parse_timestamp(bound_budget["bound_at"], "budget binding bound_at")
            <= observed_at
            < parse_timestamp(budget_revision["expires_at"], "budget revision expires_at")
        ):
            raise StoreIntegrityError("Action source bundle budget policy is not current")
        if not is_current_bundle:
            records[(ExactActionSourceHeadBundle.KIND, bundle.record_id)] = document
            continue
        if require_current_sources and (
            document["budget_revision_id"] != budget_state[2]
            or document["budget_revision_sha256"] != budget_state[3]
            or document["budget_policy_binding_sequence"] != budget_state[4]
            or document["budget_policy_binding_sha256"] != budget_state[5]
        ):
            raise StoreIntegrityError("Current action source budget policy is stale")
        publication_row = connection.execute(
            "SELECT publication_json FROM action_authority_publications "
            "WHERE source_bundle_id = ? AND source_bundle_sha256 = ?",
            (bundle.record_id, bundle.content_sha256),
        ).fetchone()
        if publication_row is None:
            raise StoreIntegrityError("Current action source bundle is not published")
        publication_document = _canonical_document(
            publication_row["publication_json"],
            "current action authority publication",
        )
        observation_sources = {
            item["record_kind"]: item
            for item in publication_document["source_records"]
            if item["record_kind"] in OBSERVATION_KINDS
        }
        if set(observation_sources) != set(OBSERVATION_KINDS):
            raise StoreIntegrityError("Current action observations are incomplete")
        for source_kind, binding in observation_sources.items():
            current_observation_head = latest_heads.get(
                (row["mission_id"], source_kind)
            )
            if require_current_sources and (
                current_observation_head is None
                or current_observation_head["record_id"] != binding["record_id"]
                or current_observation_head["record_sha256"]
                != binding["record_sha256"]
            ):
                raise StoreIntegrityError("Current action observation head is stale")
        if not require_current_sources:
            records[(ExactActionSourceHeadBundle.KIND, bundle.record_id)] = document
            continue
        current = connection.execute(
            """
            SELECT mission.revision AS mission_revision,
                   control.state AS mission_state,
                   identity.trust_policy_hash,
                   plan.plan_id, plan.plan_content_sha256, plan.plan_version,
                   policy.policy_sha256 AS mission_policy_sha256,
                   scope.grant_hash AS scope_grant_sha256,
                   revocations.head_hash AS scope_revocation_head_sha256,
                   authority.session_authority_id,
                   authority.session_authority_sha256,
                   authority.session_id,
                   authority.session_sha256,
                   authority.owner_epoch,
                   authority.fence_generation,
                   authority.credential_sha256,
                   authority.effective_at AS session_effective_at,
                   authority.expires_at AS session_expires_at,
                   activation.authenticated_at AS session_authenticated_at,
                   projection.application_sha256 AS review_projection_sha256,
                   projection.closure_id
            FROM missions AS mission
            JOIN mission_controls AS control
              ON control.mission_id = mission.mission_id
            JOIN store_identity AS identity ON identity.singleton_id = 1
            JOIN collaboration_plan_active_heads AS plan_head
              ON plan_head.mission_id = mission.mission_id
            JOIN collaboration_plan_activations AS plan
              ON plan.plan_id = plan_head.active_plan_id
            JOIN collaboration_mission_policy_commits AS policy
              ON policy.mission_id = mission.mission_id
             AND policy.plan_id = plan.plan_id
            JOIN mission_scope_grants AS scope
              ON scope.mission_id = mission.mission_id
            JOIN mission_scope_revocation_baselines AS revocations
              ON revocations.mission_id = mission.mission_id
            JOIN execution_session_authority_commits AS authority
              ON authority.mission_id = mission.mission_id
            JOIN execution_session_activation_commits AS activation
              ON activation.session_authority_id = authority.session_authority_id
            JOIN authenticated_expert_review_closure_projections AS projection
              ON projection.mission_id = mission.mission_id
            WHERE mission.mission_id = ?
              AND policy.policy_version = (
                  SELECT MAX(current_policy.policy_version)
                  FROM collaboration_mission_policy_commits AS current_policy
                  WHERE current_policy.mission_id = mission.mission_id
              )
              AND scope.grant_hash = ?
              AND authority.session_authority_id = ?
              AND authority.work_item_id = (
                  SELECT json_extract(proposal_json, '$.reviewed_product.work_id')
                  FROM action_authority_proposal_imports
                  WHERE proposal_import_id = ?
              )
              AND authority.fence_generation = (
                  SELECT MAX(latest_authority.fence_generation)
                  FROM execution_session_authority_commits AS latest_authority
                  JOIN execution_session_activation_commits AS latest_activation
                    ON latest_activation.session_authority_id =
                       latest_authority.session_authority_id
                  WHERE latest_authority.mission_id = authority.mission_id
                    AND latest_authority.work_item_id = authority.work_item_id
              )
              AND projection.closure_id = (
                  SELECT json_extract(proposal_json, '$.review_closure_id')
                  FROM action_authority_proposal_imports
                  WHERE proposal_import_id = ?
              )
            """,
            (
                row["mission_id"],
                document["scope_grant_sha256"],
                document["session_authority_id"],
                document["proposal_import_id"],
                document["proposal_import_id"],
            ),
        ).fetchall()
        if len(current) != 1:
            raise StoreIntegrityError("Action source bundle current source set is absent")
        source = current[0]
        if (
            source["mission_state"] != "active"
            or source["mission_revision"] != document["mission_revision"]
            or source["plan_id"] != document["plan_id"]
            or source["plan_content_sha256"] != document["active_plan_sha256"]
            or source["plan_version"] != document["active_plan_version"]
            or source["mission_policy_sha256"] != document["mission_policy_sha256"]
            or source["trust_policy_hash"] != document["trust_policy_sha256"]
            or source["scope_grant_sha256"] != document["scope_grant_sha256"]
            or source["scope_revocation_head_sha256"] != document["scope_revocation_head_sha256"]
            or source["session_authority_id"] != document["session_authority_id"]
            or source["session_authority_sha256"] != document["session_authority_sha256"]
            or source["session_id"] != document["execution_session_id"]
            or source["session_sha256"] != document["execution_session_sha256"]
            or source["owner_epoch"] != document["owner_epoch"]
            or source["fence_generation"] != document["fence_generation"]
            or source["credential_sha256"] != document["credential_lease_sha256"]
            or source["review_projection_sha256"] != document["review_closure_projection_sha256"]
            or document["review_revocation_head_sha256"]
            != action_review_revocation_head_sha256(str(source["closure_id"]))
            or connection.execute(
                "SELECT 1 FROM mission_scope_grant_revocations WHERE scope_grant_hash = ?",
                (document["scope_grant_sha256"],),
            ).fetchone()
            is not None
            or connection.execute(
                "SELECT 1 FROM execution_session_revocation_commits WHERE session_authority_id = ?",
                (document["session_authority_id"],),
            ).fetchone()
            is not None
            or connection.execute(
                "SELECT 1 FROM authenticated_expert_review_revocation_projections "
                "WHERE closure_id = ?",
                (source["closure_id"],),
            ).fetchone()
            is not None
            or not (
                source["session_effective_at"]
                <= document["observed_at"]
                < source["session_expires_at"]
            )
            or parse_timestamp(
                document["valid_until"], "source bundle valid_until"
            )
            > parse_timestamp(
                source["session_expires_at"], "execution session expires_at"
            )
            or source["session_authenticated_at"] > document["observed_at"]
        ):
            raise StoreIntegrityError("Action source bundle is not current MissionStore state")
        records[(ExactActionSourceHeadBundle.KIND, bundle.record_id)] = document
    bundle_heads = connection.execute(
        "SELECT * FROM action_authority_source_heads "
        "WHERE source_kind = 'exact_action_source_head_bundle'"
        + (" AND mission_id = ?" if mission_id is not None else "")
        + " ORDER BY mission_id, head_sequence",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    for head in bundle_heads:
        source = records.get((ExactActionSourceHeadBundle.KIND, head["record_id"]))
        if source is None or source["source_bundle_sha256"] != head["record_sha256"]:
            raise StoreIntegrityError("Action source bundle head record is missing")


def _verify_grant_submissions(
    connection: sqlite3.Connection,
    mission_id: str | None,
) -> None:
    rows = connection.execute(
        "SELECT * FROM action_authority_grant_submissions"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY assertion_issuer, assertion_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    for row in rows:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Action grant submission column type is invalid")
        authorization_document = _canonical_document(
            row["authorization_json"], "action grant authorization"
        )
        assertion_document = _canonical_document(
            row["assertion_json"], "action grant assertion"
        )
        try:
            authorization = _authorization(
                authorization_document,
                "stored action grant authorization",
            )
            assertion = PrincipalAssertion.from_dict(assertion_document)
            operation = PrincipalOperation(row["operation"])
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Action grant submission is invalid") from exc
        allowed_roles = {
            PrincipalOperation.ACTION_RESOLVE: {"typed_resolver"},
            PrincipalOperation.ACTION_QUORUM_AUTHORIZE: {
                "mission_owner",
                "independent_control",
            },
            PrincipalOperation.ACTION_ADMIT: {"admission_control"},
            PrincipalOperation.ACTION_ADMISSION_REVOKE: {
                "independent_control"
            },
        }
        intent = {
            "action_intent_sha256": authorization["operation_intent_sha256"],
            "idempotency_key_sha256": authorization[
                "canonical_replay_key_sha256"
            ],
            "mission_id": authorization["mission_id"],
            "principal_profile_id": authorization["principal_profile_id"],
            "role": authorization["role"],
        }
        signed_intent_sha256 = compute_operation_intent_hash(operation, intent)
        if (
            authorization["assertion_issuer"] != row["assertion_issuer"]
            or authorization["assertion_id"] != row["assertion_id"]
            or authorization["assertion_sha256"] != row["assertion_sha256"]
            or authorization["mission_id"] != row["mission_id"]
            or authorization["role"] != row["role"]
            or authorization["operation_intent_sha256"]
            != row["operation_intent_sha256"]
            or authorization["canonical_replay_key_sha256"]
            != row["canonical_replay_key_sha256"]
            or authorization["role"] not in allowed_roles.get(operation, set())
            or assertion.issuer != row["assertion_issuer"]
            or assertion.assertion_id != row["assertion_id"]
            or assertion.content_sha256 != row["assertion_sha256"]
            or assertion.subject != authorization["principal_subject"]
            or assertion.profile_id != authorization["principal_profile_id"]
            or assertion.mission_id != authorization["mission_id"]
            or assertion.scope_grant_sha256
            != authorization["scope_grant_sha256"]
            or assertion.operation is not operation
            or assertion.operation_intent_sha256 != signed_intent_sha256
        ):
            raise StoreIntegrityError("Action grant submission binding is invalid")
        parse_timestamp(row["received_at"], "action grant received_at")


def _verify_material_snapshots(
    connection: sqlite3.Connection,
    mission_id: str | None,
) -> dict[str, ActionAuthorityMaterialSnapshot]:
    rows = connection.execute(
        "SELECT * FROM action_authority_material_snapshots"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY material_snapshot_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    result: dict[str, ActionAuthorityMaterialSnapshot] = {}
    for row in rows:
        document = _canonical_document(row["material_json"], "action material snapshot")
        try:
            material = ActionAuthorityMaterialSnapshot.from_dict(document)
        except (TypeError, ValueError, StoreIntegrityError) as exc:
            raise StoreIntegrityError("Action material snapshot is invalid") from exc
        expected = {
            "material_snapshot_id": material.material_snapshot_id,
            "material_snapshot_sha256": material.material_snapshot_sha256,
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "plan_id": document["plan_id"],
            "proposal_import_id": document["proposal_import_id"],
            "proposal_import_sha256": document["proposal_import_sha256"],
            "credential_lease_sha256": document["credential_lease_sha256"],
            "health_observation_sha256": document["health_observation_sha256"],
            "executor_deployment_sha256": document["executor_deployment_sha256"],
            "monitor_observation_sha256": document["monitor_observation_sha256"],
            "observed_at": document["observed_at"],
            "valid_until": document["valid_until"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise StoreIntegrityError("Action material snapshot columns are inconsistent")
        if type(row["committed_at"]) is not str or parse_timestamp(
            row["committed_at"], "material committed_at"
        ) < parse_timestamp(document["observed_at"], "material observed_at"):
            raise StoreIntegrityError("Action material commit chronology is invalid")
        result[material.material_snapshot_id] = material
    return result


def _source_record_bindings(connection: sqlite3.Connection) -> dict[tuple[str, str], str]:
    bindings: dict[tuple[str, str], str] = {}
    for row in connection.execute(
        "SELECT record_kind, record_id, record_sha256 FROM action_authority_revisions"
    ):
        bindings[(row["record_kind"], row["record_id"])] = row["record_sha256"]
    for row in connection.execute(
        "SELECT proposal_import_id, proposal_import_sha256 FROM action_authority_proposal_imports"
    ):
        bindings[(AuthenticatedProposalMaterialImport.KIND, row["proposal_import_id"])] = row[
            "proposal_import_sha256"
        ]
    for row in connection.execute(
        "SELECT source_bundle_id, source_bundle_sha256 FROM action_authority_source_bundles"
    ):
        bindings[(ExactActionSourceHeadBundle.KIND, row["source_bundle_id"])] = row[
            "source_bundle_sha256"
        ]
    for row in connection.execute(
        "SELECT observation_kind, observation_id, observation_sha256 "
        "FROM action_authority_observations"
    ):
        bindings[(row["observation_kind"], row["observation_id"])] = row[
            "observation_sha256"
        ]
    return bindings


def _verify_publications(
    connection: sqlite3.Connection,
    materials: Mapping[str, ActionAuthorityMaterialSnapshot],
    mission_id: str | None,
) -> None:
    rows = connection.execute(
        "SELECT * FROM action_authority_publications"
        + (" WHERE mission_id = ?" if mission_id is not None else "")
        + " ORDER BY published_at, publication_id",
        () if mission_id is None else (mission_id,),
    ).fetchall()
    bindings = _source_record_bindings(connection)
    authenticated: set[tuple[str, str]] = set()
    published_material_ids: set[str] = set()
    last_publication_at: dict[str, Any] = {}
    for row in rows:
        document = _canonical_document(row["publication_json"], "action authority publication")
        try:
            publication = AuthenticatedActionAuthorityPublication.from_dict(document)
        except (TypeError, ValueError, StoreIntegrityError) as exc:
            raise StoreIntegrityError("Action authority publication is invalid") from exc
        sources = document["source_records"]
        bundle_source = next(
            item for item in sources if item["record_kind"] == ExactActionSourceHeadBundle.KIND
        )
        expected = {
            "publication_id": publication.publication_id,
            "publication_sha256": publication.publication_sha256,
            "mission_id": document["mission_id"],
            "source_bundle_id": bundle_source["record_id"],
            "source_bundle_sha256": bundle_source["record_sha256"],
            "material_snapshot_id": document["material_snapshot_id"],
            "material_snapshot_sha256": document["material_snapshot_sha256"],
            "idempotency_key_sha256": document["idempotency_key_sha256"],
            "published_at": document["published_at"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise StoreIntegrityError("Action authority publication columns are inconsistent")
        published_at = parse_timestamp(document["published_at"], "publication published_at")
        previous_publication_at = last_publication_at.get(document["mission_id"])
        if previous_publication_at is not None and published_at <= previous_publication_at:
            raise StoreIntegrityError("Action authority publication chronology regressed")
        last_publication_at[document["mission_id"]] = published_at
        material = materials.get(document["material_snapshot_id"])
        if (
            material is None
            or material.material_snapshot_sha256 != document["material_snapshot_sha256"]
            or document["material_snapshot_id"] in published_material_ids
        ):
            raise StoreIntegrityError("Action publication material is absent or substituted")
        published_material_ids.add(document["material_snapshot_id"])
        material_document = material.to_dict()
        bundle_row = connection.execute(
            "SELECT bundle_json FROM action_authority_source_bundles WHERE source_bundle_id = ?",
            (bundle_source["record_id"],),
        ).fetchone()
        if bundle_row is None:
            raise StoreIntegrityError("Action publication bundle is absent")
        bundle_document = ExactActionSourceHeadBundle.from_dict(
            _canonical_document(bundle_row["bundle_json"], "published source bundle")
        ).to_dict()
        for field in (
            "tenant_id",
            "mission_id",
            "plan_id",
            "proposal_import_id",
            "proposal_import_sha256",
            "credential_lease_sha256",
            "health_observation_sha256",
            "executor_deployment_sha256",
            "monitor_observation_sha256",
        ):
            if material_document[field] != bundle_document[field]:
                raise StoreIntegrityError("Published material differs from its source bundle")
        for source in sources:
            key = (source["record_kind"], source["record_id"])
            if bindings.get(key) != source["record_sha256"]:
                raise StoreIntegrityError("Published source binding is absent")
            authenticated.add(key)
        parsed_sources: dict[str, Any] = {}
        for source in sources:
            if source["record_kind"] == ExactActionSourceHeadBundle.KIND:
                parsed_sources[source["record_kind"]] = ExactActionSourceHeadBundle.from_dict(
                    bundle_document
                )
                continue
            if source["record_kind"] == AuthenticatedProposalMaterialImport.KIND:
                stored = connection.execute(
                    "SELECT proposal_json AS document FROM action_authority_proposal_imports "
                    "WHERE proposal_import_id = ?",
                    (source["record_id"],),
                ).fetchone()
            elif source["record_kind"] in OBSERVATION_KINDS:
                stored = connection.execute(
                    "SELECT observation_json AS document FROM action_authority_observations "
                    "WHERE observation_kind = ? AND observation_id = ?",
                    (source["record_kind"], source["record_id"]),
                ).fetchone()
            else:
                stored = connection.execute(
                    "SELECT record_json AS document FROM action_authority_revisions "
                    "WHERE record_kind = ? AND record_id = ?",
                    (source["record_kind"], source["record_id"]),
                ).fetchone()
            if stored is None:
                raise StoreIntegrityError("Published source record is absent")
            stored_document = _canonical_document(
                stored["document"], "published source record"
            )
            parsed_sources[source["record_kind"]] = (
                ActionAuthorityObservation.from_dict(stored_document)
                if source["record_kind"] in OBSERVATION_KINDS
                else parse_action_authority_contract(stored_document)
            )
        rebuilt = build_authenticated_action_authority_publication(
            policy=parsed_sources[ActionAuthorityPolicyRevision.KIND],
            catalog=parsed_sources[AuthoritativeActionCatalogRevision.KIND],
            target=parsed_sources[AuthoritativeTargetDescriptorRevision.KIND],
            budget=parsed_sources[ActionBudgetPolicyRevision.KIND],
            safety=parsed_sources[ActionSafetyPolicyRevision.KIND],
            proposal=parsed_sources[AuthenticatedProposalMaterialImport.KIND],
            source_bundle=parsed_sources[ExactActionSourceHeadBundle.KIND],
            material=material,
            observations=tuple(
                parsed_sources[kind] for kind in OBSERVATION_KINDS
            ),
            idempotency_key_sha256=document["idempotency_key_sha256"],
            published_at=document["published_at"],
        )
        if rebuilt.document_json != publication.document_json:
            raise StoreIntegrityError("Stored action publication source set is inconsistent")
        use = connection.execute(
            "SELECT * FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
            (row["assertion_issuer"], row["assertion_id"]),
        ).fetchone()
        effect = connection.execute(
            "SELECT * FROM principal_assertion_effects WHERE issuer = ? AND assertion_id = ?",
            (row["assertion_issuer"], row["assertion_id"]),
        ).fetchall()
        if use is None or len(effect) != 1:
            raise StoreIntegrityError("Action publication assertion custody is incomplete")
        intent = {
            "idempotency_key_sha256": document["idempotency_key_sha256"],
            "mission_id": document["mission_id"],
            "principal_profile_id": use["principal_profile_id"],
            "publication_sha256": publication.publication_sha256,
        }
        intent_sha256 = compute_operation_intent_hash(
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            intent,
        )
        historical_control = _historical_collaboration_role_principal(
            connection,
            mission_id=document["mission_id"],
            plan_id=document["plan_id"],
            role="independent_control",
            effective_at=document["published_at"],
        )
        effect_document = _canonical_document(effect[0]["effect_json"], "action publication effect")
        expected_effect = {
            "effect_id": publication.publication_id,
            "effect_kind": PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value,
            "payload": document,
            "recorded_at": document["published_at"],
            "schema_version": 1,
        }
        if (
            row["assertion_issuer"] != use["issuer"]
            or row["assertion_id"] != use["assertion_id"]
            or use["issuer"] != historical_control["assertion_issuer"]
            or use["principal_profile_id"]
            != historical_control["principal_profile_id"]
            or use["subject"] != historical_control["principal_subject"]
            or use["operation"] != PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value
            or use["operation_intent_json"] != _canonical_json(intent)
            or use["signed_intent_hash"] != intent_sha256
            or use["domain_request_hash"] != publication.publication_sha256
            or use["idempotency_key_hash"] != document["idempotency_key_sha256"]
            or row["operation_intent_sha256"] != intent_sha256
            or effect[0]["effect_kind"] != PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value
            or effect[0]["effect_id"] != publication.publication_id
            or effect_document != expected_effect
            or effect[0]["recorded_at"] != document["published_at"]
            or use["consumed_at"] != document["published_at"]
            or parse_timestamp(document["published_at"], "publication published_at")
            < parse_timestamp(material_document["observed_at"], "material observed_at")
        ):
            raise StoreIntegrityError("Action publication assertion binding is invalid")
    relevant = {
        key: value
        for key, value in bindings.items()
        if mission_id is None
        or connection.execute(
            "SELECT 1 FROM action_authority_source_heads WHERE mission_id = ? "
            "AND source_kind = ? AND record_id = ?",
            (mission_id, key[0], key[1]),
        ).fetchone()
        is not None
    }
    if published_material_ids != set(materials):
        raise StoreIntegrityError("Action authority material publication custody is incomplete")
    published_principals = {
        (row["assertion_issuer"], row["assertion_id"]) for row in rows
    }
    central_publish_uses = {
        (row["issuer"], row["assertion_id"])
        for row in connection.execute(
            "SELECT issuer, assertion_id FROM principal_assertion_uses "
            "WHERE operation = ?"
            + (" AND mission_id = ?" if mission_id is not None else ""),
            (
                (PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value, mission_id)
                if mission_id is not None
                else (PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value,)
            ),
        ).fetchall()
    }
    if published_principals != central_publish_uses:
        raise StoreIntegrityError("Action authority publication assertions are orphaned")
    if authenticated != set(relevant):
        raise StoreIntegrityError("Action authority source records are not fully authenticated")


def load_current_action_material_snapshot(
    connection: sqlite3.Connection,
    source_bundle: ExactActionSourceHeadBundle,
    checked_at: str,
) -> ActionAuthorityMaterialSnapshot:
    document = source_bundle.to_dict()
    rows = connection.execute(
        """
        SELECT material.material_json
        FROM action_authority_publications AS publication
        JOIN action_authority_material_snapshots AS material
          ON material.material_snapshot_id = publication.material_snapshot_id
         AND material.material_snapshot_sha256 = publication.material_snapshot_sha256
        WHERE publication.source_bundle_id = ?
          AND publication.source_bundle_sha256 = ?
        """,
        (document["source_bundle_id"], document["source_bundle_sha256"]),
    ).fetchall()
    if len(rows) != 1:
        raise StoreIntegrityError("Current action material snapshot is absent or ambiguous")
    material = ActionAuthorityMaterialSnapshot.from_dict(
        _canonical_document(rows[0]["material_json"], "current action material")
    )
    checked = parse_timestamp(checked_at, "current action material checked_at")
    material_document = material.to_dict()
    if not (
        parse_timestamp(material_document["observed_at"], "material observed_at")
        <= checked
        < parse_timestamp(material_document["valid_until"], "material valid_until")
    ):
        raise StoreIntegrityError("Current action material snapshot is stale")
    return material


def verify_action_authority_repository(
    connection: sqlite3.Connection,
    *,
    mission_id: str | None = None,
    require_current_sources: bool = True,
) -> None:
    """Reconstruct authority sources and, by default, require live currentness."""

    if type(require_current_sources) is not bool:
        raise TypeError("require_current_sources must be a bool")
    records = _verify_revision_rows(connection, mission_id)
    records.update(_verify_proposal_rows(connection, mission_id))
    records.update(_verify_observation_rows(connection, mission_id))
    latest_heads = _verify_source_heads(connection, records, mission_id)
    budget_heads = _verify_budget_accounts(connection, records, mission_id)
    _verify_bundles(
        connection,
        records,
        latest_heads,
        budget_heads,
        mission_id,
        require_current_sources=require_current_sources,
    )
    materials = _verify_material_snapshots(connection, mission_id)
    _verify_publications(connection, materials, mission_id)
    _verify_grant_submissions(connection, mission_id)


def load_current_action_source_bundle(
    connection: sqlite3.Connection,
    mission_id: str,
    checked_at: str,
) -> ExactActionSourceHeadBundle:
    """Load the latest verified bundle from the caller's locked transaction."""

    verify_action_authority_repository(
        connection,
        mission_id=mission_id,
        require_current_sources=True,
    )
    row = connection.execute(
        """
        SELECT bundle.*
        FROM action_authority_source_heads AS head
        JOIN action_authority_source_bundles AS bundle
          ON bundle.source_bundle_id = head.record_id
         AND bundle.source_bundle_sha256 = head.record_sha256
        WHERE head.mission_id = ?
          AND head.source_kind = 'exact_action_source_head_bundle'
        ORDER BY head.head_sequence DESC LIMIT 1
        """,
        (mission_id,),
    ).fetchone()
    if row is None:
        raise StoreIntegrityError("Current action source bundle is absent")
    document = _canonical_document(row["bundle_json"], "action source bundle")
    bundle = ExactActionSourceHeadBundle.from_dict(document)
    checked = parse_timestamp(checked_at, "action source checked_at")
    if not (
        parse_timestamp(bundle.to_dict()["observed_at"], "source observed_at")
        <= checked
        < parse_timestamp(bundle.to_dict()["valid_until"], "source valid_until")
    ):
        raise StoreIntegrityError("Current action source bundle is stale")
    return bundle


__all__ = [
    "ActionAuthorityMaterialSnapshot",
    "AuthenticatedActionAuthorityPublication",
    "action_review_revocation_head_sha256",
    "build_action_authority_material_snapshot",
    "build_authenticated_action_authority_publication",
    "load_current_action_material_snapshot",
    "load_current_action_source_bundle",
    "phase165_budget_binding_from_policy",
    "verify_action_authority_repository",
]
