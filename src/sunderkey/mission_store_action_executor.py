"""MissionStore-integrated authenticated action execution custody."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import marshal
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .action_admission_contracts import ActionAdmissionRequest
from .action_resolution import ActionTier, AdmissionStatus, evaluate_action_admission
from .action_target_health_gate_use import (
    ActionExecutionTargetHealthGateLegacyBaseline,
    ActionTargetHealthGateUseKind,
    verify_action_target_health_gate_use_store,
)
from .authenticated_action_admission import ActionAdmissionCommand
from .authenticated_action_executor import (
    ACTION_EXECUTE,
    AUTHORITY_CHECKS,
    CUSTODY_DOMAIN,
    INPUT_DOMAIN,
    RESOURCE_FIELDS,
    ActionExecutionClaim,
    ActionExecutionCommand,
    ActionExecutionError,
    ActionExecutionReconciliationRequired,
    ActionExecutionRequest,
    ActionExecutionTerminal,
    ActionOutcome,
    AdapterBinding,
    AuthenticatedActionExecutionService,
    AxisStatus,
    BrowserPrimitiveActionAdapter,
    CurrentExecutionAuthorityState,
    ExecutionBudget,
    ExecutionResources,
    HttpPrimitiveActionAdapter,
    PrimitiveActionAdapter,
    SessionPrimitiveActionAdapter,
    SpecialistPrimitiveActionAdapter,
    TerminalStatus,
    _document,
    _immutable_document,
    _parse_adapter_result,
    _parse_authorization,
    _record,
    _reject_secret_material,
    _validate_record,
    action_execute_authorization_intent_sha256,
    parse_action_execution_claim,
    parse_action_execution_request,
    parse_action_execution_terminal,
)
from .errors import PrincipalAuthenticationError, StoreConflictError, StoreIntegrityError
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
    verify_trust_policy,
)
from .mission_store_action_admission import (
    MissionStoreActionPrincipalCustody,
    MissionStoreAuthenticatedActionAdmissionService,
    _action_principal_effect,
    _current_budget_state,
    verify_authenticated_action_admission_store,
)
from .mission_store_action_authority import (
    BUDGET_EVENT_DOMAIN,
    OBSERVATION_KINDS,
    SOURCE_BINDINGS,
    verify_action_authority_repository,
)
from .mission_store_target_health_gate import (
    _head_from_row,
    _observation_from_row,
    _transition_from_row,
)
from .qualification import _canonical_json, _canonical_sha256
from .store import (
    MISSION_STOP_EFFECT_KIND,
    SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    parse_timestamp,
    principal_assertion_effects_hash,
    sha256_text,
)
from .target_health_gate_contracts import (
    ExecutionBinding,
    TargetHealthGateDecision,
    TargetHealthGateDecisionStatus,
    TargetHealthGateState,
)

DISPATCH_DOMAIN = "sunderkey.authenticated-action-dispatch-attempt.v1"
PREDISPATCH_ABORT_DOMAIN = "sunderkey.authenticated-action-predispatch-abort.v1"
PREINVOCATION_ABORT_DOMAIN = (
    "sunderkey.authenticated-action-preinvocation-abort.v1"
)
CLOSURE_DOMAIN = "sunderkey.authenticated-action-execution-closure.v1"
DISPATCH_PROOF_DOMAIN = "sunderkey.process-local-action-dispatch-proof.v1"
ADAPTER_CAPABILITY_DOMAIN = "sunderkey.process-local-qualified-adapter-capability.v1"
AUTHORITY_HIGH_WATER_DOMAIN = "sunderkey.action-execution-authority-high-water.v1"
AUTHORITY_CHECKPOINT_DOMAIN = "sunderkey.action-execution-authority-checkpoint.v1"
CLAIM_CUSTODY_DOMAIN = "sunderkey.action-execution-claim-custody.v1"
RECONCILIATION_INTENT_DOMAIN = "sunderkey.action-execution-reconciliation-intent.v1"
RECONCILIATION_DOMAIN = "sunderkey.action-execution-reconciliation.v1"
ACTION_EXECUTION_RECONCILE = PrincipalOperation.ACTION_EXECUTION_RECONCILE.value
_ADAPTER_CAPABILITY_KEY = secrets.token_bytes(32)


def _is_execution_health_cutover_baseline_request(
    connection: sqlite3.Connection,
    request: ActionExecutionRequest,
) -> bool:
    row = connection.execute(
        "SELECT baseline_json FROM "
        "action_execution_target_health_gate_legacy_baselines "
        "WHERE singleton_id = 1"
    ).fetchone()
    if row is None or type(row["baseline_json"]) is not str:
        raise StoreIntegrityError(
            "Execution target-health cutover baseline is absent"
        )
    try:
        raw = json.loads(row["baseline_json"])
        baseline = ActionExecutionTargetHealthGateLegacyBaseline.from_dict(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError(
            "Execution target-health cutover baseline is invalid"
        ) from exc
    if _canonical_json(baseline.to_dict()) != row["baseline_json"]:
        raise StoreIntegrityError(
            "Execution target-health cutover baseline is not canonical"
        )
    return any(
        item.request_id == request.request_id
        and item.request_sha256 == request.request_sha256
        for item in baseline.records
    )


def _require_canonical_rfc3339(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ActionExecutionError(f"{label} must be a string")
    try:
        parsed = parse_timestamp(value, label)
    except StoreIntegrityError as exc:
        raise ActionExecutionError(str(exc)) from exc
    canonical = parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if parsed.microsecond != 0 or value != canonical:
        raise ActionExecutionError(f"{label} must be canonical RFC3339 UTC")
    return value

AUTHORITY_HIGH_WATER_FIELDS = (
    "admission",
    "budget",
    "control",
    "mission",
    "mission_policy",
    "ownership",
    "plan",
    "principal",
    "review",
    "scope",
    "session",
    "source_bundle",
    "source_heads",
    "trust",
    "workspace",
)
AUTHORITY_HIGH_WATER_SECTION_FIELDS = {
    "admission": {"receipt_id", "receipt_sha256", "revocation_id"},
    "budget": {
        "account_id",
        "binding_sequence",
        "binding_sha256",
        "budget_revision_id",
        "budget_revision_sha256",
        "event_id",
        "event_sequence",
        "event_sha256",
        "policy_binding_count",
        "policy_head_sha256",
        "event_count",
        "event_head_sha256",
        "reservation_id",
        "reservation_sha256",
        "reserve_event_id",
        "reserve_event_sha256",
        "reserve_event_sequence",
    },
    "control": {"mission_id", "version", "state", "stopped_at", "stop_event_id"},
    "mission": {"mission_id", "context_hash", "revision", "head_hash"},
    "mission_policy": {
        "policy_id",
        "policy_version",
        "policy_sha256",
        "plan_id",
        "owner_issuer",
        "owner_assertion_id",
        "control_issuer",
        "control_assertion_id",
        "owner_use_sequence",
        "control_use_sequence",
    },
    "ownership": {
        "entry_id",
        "entry_sha256",
        "owner_epoch",
        "owner_profile_id",
        "plan_id",
        "proposal_work_id",
        "sequence",
        "authority_use_sequences",
    },
    "plan": {
        "active_plan_id",
        "plan_version",
        "replacement_commit_id",
        "plan_sha256",
        "plan_content_sha256",
        "activation_kind",
        "activated_at",
        "issuer",
        "assertion_id",
        "activation_use_sequence",
        "authority_use_sequences",
        "authority_use_set_sha256",
    },
    "principal": {
        "baseline_root_hash",
        "assertion_count",
        "effect_count",
        "head_hash",
        "execute_use_sequence",
    },
    "review": {
        "closure_id",
        "closure_sha256",
        "workspace_id",
        "application_id",
        "application_sha256",
        "projected_at",
        "revocation_id",
        "review_revocation_head_sha256",
    },
    "scope": {
        "baseline_root_hash",
        "signed_revocation_count",
        "head_hash",
        "execution_scope_grant_sha256",
        "bundle_scope_grant_sha256",
    },
    "session": {
        "session_authority_id",
        "session_authority_sha256",
        "mission_id",
        "collaboration_plan_id",
        "collaboration_plan_sha256",
        "work_item_id",
        "session_id",
        "session_sha256",
        "owner_profile_id",
        "owner_epoch",
        "worker_principal_id",
        "fence_generation",
        "credential_reference_id",
        "credential_sha256",
        "effective_at",
        "expires_at",
        "activation_authentication_id",
        "activation_authentication_sha256",
        "activation_authenticated_at",
        "activation_control_issuer",
        "activation_control_assertion_id",
        "activation_control_use_sequence",
        "activation_worker_issuer",
        "activation_worker_assertion_id",
        "activation_worker_use_sequence",
    },
    "source_bundle": {
        "head_sequence",
        "record_id",
        "record_sha256",
        "previous_head_sha256",
        "head_sha256",
        "advanced_at",
    },
    "source_heads": {"items"},
    "trust": {"store_id", "trust_policy_id", "trust_policy_version", "trust_policy_hash"},
    "workspace": {
        "high_water_id",
        "high_water_sha256",
        "mission_store_id",
        "workspace_store_id",
        "workspace_id",
        "snapshot_id",
        "snapshot_sha256",
        "closure_id",
        "closure_sha256",
        "application_id",
        "application_sha256",
        "workspace_revision",
        "event_count",
        "event_head_sha256",
        "event_head_occurred_at",
        "state",
        "revocation_id",
        "revocation_sha256",
        "workspace_store_path",
        "imported_at",
    },
}


@dataclass(frozen=True, slots=True)
class SealedActionDispatch:
    """Process-local proof authorizing one final dispatch transition."""

    request_id: str
    request_sha256: str
    claim_id: str
    claim_sha256: str
    dispatch_id: str
    _proof: bytes


@dataclass(frozen=True, slots=True)
class ActionExecutionReconciliationIntent:
    """Content-addressed settlement intent for an independent reconciler."""

    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ActionExecutionReconciliationIntent:
        value = _document(raw, "action execution reconciliation intent")
        fields = {
            "schema_version",
            "kind",
            "reconciliation_intent_id",
            "reconciliation_intent_sha256",
            "tenant_id",
            "mission_id",
            "request_id",
            "request_sha256",
            "claim_id",
            "claim_sha256",
            "dispatch_id",
            "dispatch_sha256",
            "reconciliation_mode",
            "reason_code",
            "terminal_status",
            "action_outcome",
            "evidence_status",
            "cleanup_status",
            "restoration_status",
            "adapter_call_count_status",
            "adapter_call_count",
            "charged_resources",
            "active_plan_id",
            "active_plan_sha256",
            "collaboration_policy_id",
            "collaboration_policy_sha256",
            "scope_revocation_count",
            "scope_revocation_head_sha256",
            "authority_expires_at",
            "prepared_at",
        }
        if set(value) != fields:
            raise ActionExecutionError("Reconciliation intent fields are invalid")
        _validate_record(
            value,
            kind="reconciliation_intent",
            prefix="AXI",
            domain=RECONCILIATION_INTENT_DOMAIN,
        )
        string_fields = fields - {
            "schema_version",
            "adapter_call_count",
            "charged_resources",
            "dispatch_sha256",
            "scope_revocation_count",
        }
        if any(type(value[field]) is not str or not value[field] for field in string_fields):
            raise ActionExecutionError("Reconciliation intent strings are invalid")
        _require_canonical_rfc3339(
            value["prepared_at"],
            "reconciliation intent prepared_at",
        )
        _require_canonical_rfc3339(
            value["authority_expires_at"],
            "reconciliation intent authority_expires_at",
        )
        if value["dispatch_sha256"] is not None and (
            type(value["dispatch_sha256"]) is not str
            or not value["dispatch_sha256"].startswith("sha256:")
        ):
            raise ActionExecutionError("Reconciliation dispatch hash is invalid")
        if (
            type(value["scope_revocation_count"]) is not int
            or value["scope_revocation_count"] < 0
            or type(value["adapter_call_count"]) not in {int, type(None)}
        ):
            raise ActionExecutionError("Reconciliation counters are invalid")
        resources = ExecutionResources.from_dict(value["charged_resources"])
        zero = ExecutionResources(**{field: 0 for field in RESOURCE_FIELDS})
        mode = value["reconciliation_mode"]
        if mode == "predispatch_abort":
            valid = (
                value["terminal_status"] == TerminalStatus.PREDISPATCH_ABORTED.value
                and value["action_outcome"] == ActionOutcome.FAILED.value
                and value["adapter_call_count_status"] == "exactly_zero"
                and value["adapter_call_count"] == 0
                and resources == zero
            )
        elif mode == "dispatched_indeterminate":
            valid = (
                value["dispatch_sha256"] is not None
                and value["terminal_status"]
                == TerminalStatus.INDETERMINATE_QUARANTINED.value
                and value["action_outcome"] == ActionOutcome.INDETERMINATE.value
                and value["adapter_call_count_status"] == "unknown_zero_or_one"
                and value["adapter_call_count"] is None
            )
        else:
            valid = False
        if (
            not valid
            or any(
                value[field] != AxisStatus.UNKNOWN.value
                for field in ("evidence_status", "cleanup_status", "restoration_status")
            )
            or any(
                ord(character) < 33 or ord(character) > 126
                for character in value["reason_code"]
            )
            or len(value["reason_code"]) > 128
            or value["prepared_at"] >= value["authority_expires_at"]
        ):
            raise ActionExecutionError("Reconciliation intent semantics are invalid")
        return cls(document_json=_canonical_json(value))

    @property
    def reconciliation_intent_id(self) -> str:
        return str(json.loads(self.document_json)["reconciliation_intent_id"])

    @property
    def reconciliation_intent_sha256(self) -> str:
        return str(json.loads(self.document_json)["reconciliation_intent_sha256"])

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.document_json))


_RECONCILIATION_AUTHORIZATION_FIELDS = {
    "operation",
    "role",
    "principal_profile_id",
    "principal_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "tenant_id",
    "mission_id",
    "request_id",
    "request_sha256",
    "claim_id",
    "claim_sha256",
    "reconciliation_intent_id",
    "reconciliation_intent_sha256",
    "decision",
    "issued_at",
    "expires_at",
}


def action_execution_reconciliation_authorization_intent_sha256(
    intent: ActionExecutionReconciliationIntent,
) -> str:
    if type(intent) is not ActionExecutionReconciliationIntent:
        raise TypeError("intent must be an ActionExecutionReconciliationIntent")
    return intent.reconciliation_intent_sha256


def _parse_reconciliation_authorization(raw: Any) -> dict[str, Any]:
    value = _document(raw, "ACTION_EXECUTION_RECONCILE authorization")
    if set(value) != _RECONCILIATION_AUTHORIZATION_FIELDS:
        raise ActionExecutionError("Reconciliation authorization fields are invalid")
    if any(type(value[field]) is not str or not value[field] for field in value):
        raise ActionExecutionError("Reconciliation authorization values are invalid")
    if (
        value["operation"] != ACTION_EXECUTION_RECONCILE
        or value["role"] != "independent_control"
        or value["decision"] != "approved"
        or value["issued_at"] >= value["expires_at"]
    ):
        raise ActionExecutionError("Reconciliation authorization decision is invalid")
    _require_canonical_rfc3339(
        value["issued_at"],
        "reconciliation authorization issued_at",
    )
    _require_canonical_rfc3339(
        value["expires_at"],
        "reconciliation authorization expires_at",
    )
    for field in (
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "request_sha256",
        "claim_sha256",
        "reconciliation_intent_sha256",
    ):
        if len(value[field]) != 71 or not value[field].startswith("sha256:"):
            raise ActionExecutionError(f"Reconciliation authorization {field} is invalid")
    _reject_secret_material(value, "reconciliation authorization")
    return value


def _validate_reconciliation_authorization_binding(
    intent: ActionExecutionReconciliationIntent,
    authorization: Mapping[str, Any],
    *,
    checked_at: str,
) -> None:
    """Validate every signed authorization field against one exact intent."""

    document = intent.to_dict()
    expected = {
        "operation": ACTION_EXECUTION_RECONCILE,
        "role": "independent_control",
        "operation_intent_sha256": intent.reconciliation_intent_sha256,
        "tenant_id": document["tenant_id"],
        "mission_id": document["mission_id"],
        "request_id": document["request_id"],
        "request_sha256": document["request_sha256"],
        "claim_id": document["claim_id"],
        "claim_sha256": document["claim_sha256"],
        "reconciliation_intent_id": intent.reconciliation_intent_id,
        "reconciliation_intent_sha256": intent.reconciliation_intent_sha256,
        "decision": "approved",
        "expires_at": document["authority_expires_at"],
    }
    if (
        any(authorization.get(field) != value for field, value in expected.items())
        or not (
            document["prepared_at"]
            <= authorization["issued_at"]
            <= checked_at
            < authorization["expires_at"]
        )
    ):
        raise ActionExecutionError("Reconciliation authorization binding is invalid")


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    request: ActionExecutionRequest
    budget: ExecutionBudget
    target_health_binding: ExecutionBinding
    workspace_guard: sqlite3.Connection
    workspace_high_water: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _CommittedExecutionHealthDenial:
    boundary: str
    minimum_settlement_at: str | None = None
    health_decision: tuple[str, str, str] | None = None
    exact_settlement_at: str | None = None


def _adapter_binding_sha256(binding: AdapterBinding) -> str:
    return _canonical_sha256(
        {
            "adapter": binding.to_dict(),
            "domain": "sunderkey.action-adapter-binding.v1",
        }
    )


@dataclass(frozen=True, slots=True)
class _QualifiedPrimitiveAdapterCapability:
    adapter: PrimitiveActionAdapter
    binding: AdapterBinding
    conformance_evidence_sha256: str
    external_single_attempt_attested: bool
    _proof: bytes


def _adapter_capability_material(
    adapter: PrimitiveActionAdapter,
    binding: AdapterBinding,
    conformance_evidence_sha256: str,
    external_single_attempt_attested: bool,
) -> bytes:
    primitive = getattr(adapter, "_primitive", None)
    implementation = primitive if callable(primitive) else None
    if getattr(implementation, "__code__", None) is None and callable(primitive):
        implementation = type(primitive).__call__
    code = getattr(implementation, "__code__", None)
    implementation_sha256 = (
        "sha256:" + hashlib.sha256(marshal.dumps(code)).hexdigest()
        if code is not None
        else None
    )
    return _canonical_json(
        {
            "adapter_exact_type": (
                type(adapter).__module__ + "." + type(adapter).__qualname__
            ),
            "adapter_binding_sha256": _adapter_binding_sha256(binding),
            "adapter_identity": id(adapter),
            "conformance_evidence_sha256": conformance_evidence_sha256,
            "domain": ADAPTER_CAPABILITY_DOMAIN,
            "external_single_attempt_attested": external_single_attempt_attested,
            "primitive_exact_type": (
                type(primitive).__module__ + "." + type(primitive).__qualname__
            ),
            "primitive_identity": id(primitive),
            "primitive_implementation_sha256": implementation_sha256,
        }
    ).encode("ascii")


def _reference_adapter_capability(
    adapter: PrimitiveActionAdapter,
) -> _QualifiedPrimitiveAdapterCapability:
    """Seal a nonqualifying callable adapter for repository tests only."""

    binding = getattr(adapter, "binding", None)
    if type(adapter) not in {
        HttpPrimitiveActionAdapter,
        BrowserPrimitiveActionAdapter,
        SessionPrimitiveActionAdapter,
        SpecialistPrimitiveActionAdapter,
    } or type(binding) is not AdapterBinding:
        raise TypeError("reference adapter is invalid")
    evidence = _canonical_sha256(
        {
            "adapter": binding.to_dict(),
            "domain": "sunderkey.reference-adapter-conformance.v1",
            "qualification_effect": "none",
        }
    )
    proof = hmac.new(
        _ADAPTER_CAPABILITY_KEY,
        _adapter_capability_material(adapter, binding, evidence, False),
        hashlib.sha256,
    ).digest()
    return _QualifiedPrimitiveAdapterCapability(
        adapter=adapter,
        binding=binding,
        conformance_evidence_sha256=evidence,
        external_single_attempt_attested=False,
        _proof=proof,
    )


def _dispatch_id(request: ActionExecutionRequest, claim: ActionExecutionClaim) -> str:
    digest = _canonical_sha256(
        {
            "claim_id": claim.claim_id,
            "claim_sha256": claim.claim_sha256,
            "domain": DISPATCH_DOMAIN,
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
        }
    )
    return "AXD-" + digest.removeprefix("sha256:")[:32].upper()


def _authority_use_set_sha256(sequences: list[int]) -> str:
    return _canonical_sha256(
        {
            "domain": "sunderkey.collaboration-plan-authority-use-set.v1",
            "use_sequences": sequences,
        }
    )


def _plan_authority_use_sequences(
    connection: sqlite3.Connection,
    *,
    mission_id: str,
    plan: Mapping[str, Any],
) -> list[int]:
    if plan["activation_kind"] == "initial":
        if plan["issuer"] is None or plan["assertion_id"] is None:
            raise StoreIntegrityError("Initial plan activation authority is absent")
        row = connection.execute(
            "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
            "AND issuer = ? AND assertion_id = ?",
            (mission_id, plan["issuer"], plan["assertion_id"]),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Initial plan activation use is absent")
        return [row["use_sequence"]]
    if plan["activation_kind"] != "replacement" or plan["replacement_commit_id"] is None:
        raise StoreIntegrityError("Plan activation kind is invalid")
    rows = connection.execute(
        "SELECT use.use_sequence FROM collaboration_plan_replacement_commits AS "
        "replacement JOIN collaboration_plan_replacement_authentications AS "
        "authentication ON authentication.preflight_id = replacement.preflight_id JOIN "
        "collaboration_plan_replacement_authority_consumptions AS consumption ON "
        "consumption.preflight_id = authentication.preflight_id JOIN "
        "principal_assertion_uses AS use ON use.issuer = consumption.issuer AND "
        "use.assertion_id = consumption.assertion_id AND use.mission_id = "
        "replacement.mission_id JOIN principal_assertion_effects AS effect ON "
        "effect.issuer = consumption.issuer AND effect.assertion_id = "
        "consumption.assertion_id AND effect.mission_id = replacement.mission_id "
        "AND effect.effect_id = consumption.effect_id WHERE "
        "replacement.replacement_commit_id = ? AND "
        "replacement.mission_id = ? ORDER BY use.use_sequence",
        (plan["replacement_commit_id"], mission_id),
    ).fetchall()
    sequences = [row["use_sequence"] for row in rows]
    if (
        len(sequences) != 16
        or len(sequences) != len(set(sequences))
        or sequences != list(range(sequences[0], sequences[0] + 16))
    ):
        raise StoreIntegrityError("Replacement plan authority uses are incomplete")
    return sequences


def _capture_authority_high_water(
    connection: sqlite3.Connection,
    request: ActionExecutionRequest,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    document = request.to_dict()
    receipt = document["admission_receipt"]
    mission_id = receipt["mission_id"]

    def required(query: str, parameters: tuple[Any, ...]) -> sqlite3.Row:
        row = connection.execute(query, parameters).fetchone()
        if row is None:
            raise StoreIntegrityError("Dispatch authority high-water source is absent")
        return row

    mission = required(
        "SELECT mission_id, context_hash, revision, head_hash FROM missions "
        "WHERE mission_id = ?",
        (mission_id,),
    )
    control = required(
        "SELECT mission_id, version, state, stopped_at, stop_event_id FROM "
        "mission_controls "
        "WHERE mission_id = ?",
        (mission_id,),
    )
    trust = required(
        "SELECT store_id, trust_policy_id, trust_policy_version, trust_policy_hash "
        "FROM store_identity WHERE singleton_id = 1",
        (),
    )
    principal = required(
        "SELECT baseline_root_hash, assertion_count, effect_count, head_hash FROM "
        "mission_principal_ledgers WHERE mission_id = ?",
        (mission_id,),
    )
    execute_use = required(
        "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
        "AND issuer = ? AND assertion_id = ?",
        (
            mission_id,
            authorization["assertion_issuer"],
            authorization["assertion_id"],
        ),
    )
    scope = required(
        "SELECT baseline_root_hash, signed_revocation_count, head_hash FROM "
        "mission_scope_revocation_baselines WHERE mission_id = ?",
        (mission_id,),
    )
    plan = required(
        "SELECT head.active_plan_id, head.plan_version, "
        "head.replacement_commit_id, activation.plan_sha256, "
        "activation.plan_content_sha256, activation.activation_kind, "
        "activation.activated_at, activation.issuer, activation.assertion_id "
        "FROM collaboration_plan_active_heads AS head JOIN "
        "collaboration_plan_activations AS activation ON activation.plan_id = "
        "head.active_plan_id WHERE head.mission_id = ?",
        (mission_id,),
    )
    plan_authority_use_sequences = _plan_authority_use_sequences(
        connection,
        mission_id=mission_id,
        plan=plan,
    )
    plan_activation_use_sequence = (
        plan_authority_use_sequences[0]
        if plan["activation_kind"] == "initial"
        else None
    )
    mission_policy = required(
        "SELECT policy_id, policy_version, policy_sha256, plan_id, "
        "owner_issuer, owner_assertion_id, control_issuer, control_assertion_id "
        "FROM collaboration_mission_policy_commits WHERE mission_id = ? "
        "AND plan_id = ? ORDER BY policy_version DESC LIMIT 1",
        (mission_id, plan["active_plan_id"]),
    )
    owner_policy_use = required(
        "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
        "AND issuer = ? AND assertion_id = ?",
        (
            mission_id,
            mission_policy["owner_issuer"],
            mission_policy["owner_assertion_id"],
        ),
    )
    control_policy_use = required(
        "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
        "AND issuer = ? AND assertion_id = ?",
        (
            mission_id,
            mission_policy["control_issuer"],
            mission_policy["control_assertion_id"],
        ),
    )
    receipt_row = required(
        "SELECT resolution_json FROM action_admission_receipts WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    )
    try:
        resolution = json.loads(receipt_row["resolution_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Dispatch resolution source is invalid") from exc
    ownership_row = connection.execute(
        "SELECT * FROM collaboration_ownership_chain_entries WHERE plan_id = ? "
        "AND work_item_id = ? ORDER BY sequence DESC LIMIT 1",
        (plan["active_plan_id"], resolution["proposal_work_id"]),
    ).fetchone()
    ownership: dict[str, Any] = {
        "entry_id": None,
        "entry_sha256": None,
        "owner_epoch": 1,
        "owner_profile_id": resolution["proposal_producer_profile_id"],
        "plan_id": plan["active_plan_id"],
        "proposal_work_id": resolution["proposal_work_id"],
        "sequence": 0,
        "authority_use_sequences": [],
    }
    if ownership_row is not None:
        authority_use_sequences: list[int] = []
        for issuer_field, assertion_field in (
            ("current_owner_issuer", "current_owner_assertion_id"),
            ("proposed_owner_issuer", "proposed_owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
            ("second_authority_issuer", "second_authority_assertion_id"),
        ):
            if ownership_row[issuer_field] is None:
                continue
            use = required(
                "SELECT use_sequence FROM principal_assertion_uses WHERE "
                "mission_id = ? AND issuer = ? AND assertion_id = ?",
                (
                    mission_id,
                    ownership_row[issuer_field],
                    ownership_row[assertion_field],
                ),
            )
            authority_use_sequences.append(use["use_sequence"])
        ownership = {
            "entry_id": ownership_row["entry_id"],
            "entry_sha256": ownership_row["entry_sha256"],
            "owner_epoch": ownership_row["owner_epoch"],
            "owner_profile_id": ownership_row["to_owner_id"],
            "plan_id": ownership_row["plan_id"],
            "proposal_work_id": ownership_row["work_item_id"],
            "sequence": ownership_row["sequence"],
            "authority_use_sequences": sorted(authority_use_sequences),
        }
    session_id = document["adapter_input"]["session_id"]
    session = required(
        "SELECT session_authority_id, session_authority_sha256, mission_id, "
        "collaboration_plan_id, collaboration_plan_sha256, work_item_id, "
        "session_id, session_sha256, owner_profile_id, owner_epoch, "
        "worker_principal_id, fence_generation, credential_reference_id, "
        "credential_sha256, effective_at, expires_at FROM "
        "execution_session_authority_commits WHERE session_id = ?",
        (session_id,),
    )
    activation = required(
        "SELECT authentication_id, authentication_sha256, authenticated_at, control_issuer, "
        "control_assertion_id, worker_issuer, worker_assertion_id FROM "
        "execution_session_activation_commits WHERE session_authority_id = ?",
        (session["session_authority_id"],),
    )
    activation_control_use = required(
        "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
        "AND issuer = ? AND assertion_id = ?",
        (mission_id, activation["control_issuer"], activation["control_assertion_id"]),
    )
    activation_worker_use = required(
        "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
        "AND issuer = ? AND assertion_id = ?",
        (mission_id, activation["worker_issuer"], activation["worker_assertion_id"]),
    )
    source = required(
        "SELECT head_sequence, record_id, record_sha256, previous_head_sha256, "
        "head_sha256, advanced_at FROM "
        "action_authority_source_heads WHERE mission_id = ? AND "
        "source_kind = 'exact_action_source_head_bundle' "
        "ORDER BY head_sequence DESC LIMIT 1",
        (mission_id,),
    )
    reservation = required(
        "SELECT account_id, reservation_id, reservation_sha256, reserve_event_id, "
        "reserve_event_sha256, budget_revision_id, budget_revision_sha256 FROM "
        "action_budget_receipt_reservations "
        "WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    )
    budget = required(
        "SELECT policy_binding_count, policy_head_sha256, event_count, "
        "event_head_sha256 FROM action_budget_account_heads WHERE account_id = ?",
        (reservation["account_id"],),
    )
    binding = required(
        "SELECT binding_sequence, budget_revision_id, budget_revision_sha256, "
        "binding_sha256 FROM action_budget_policy_bindings WHERE account_id = ? "
        "AND binding_sequence = ?",
        (reservation["account_id"], budget["policy_binding_count"]),
    )
    budget_event = connection.execute(
        "SELECT event_sequence, event_id, event_sha256 FROM "
        "action_budget_account_events WHERE account_id = ? AND event_sequence = ?",
        (reservation["account_id"], budget["event_count"]),
    ).fetchone()
    if budget["event_count"] > 0 and budget_event is None:
        raise StoreIntegrityError("Dispatch budget event head is absent")
    reserve_event = required(
        "SELECT event_sequence, event_id, event_sha256 FROM "
        "action_budget_account_events WHERE account_id = ? AND event_id = ?",
        (reservation["account_id"], reservation["reserve_event_id"]),
    )
    publication_row = required(
        "SELECT publication_json FROM action_authority_publications "
        "WHERE source_bundle_id = ? AND source_bundle_sha256 = ?",
        (source["record_id"], source["record_sha256"]),
    )
    try:
        publication_document = json.loads(publication_row["publication_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Dispatch source publication is invalid") from exc
    source_bundle_row = required(
        "SELECT bundle_json FROM action_authority_source_bundles WHERE "
        "source_bundle_id = ? AND source_bundle_sha256 = ?",
        (source["record_id"], source["record_sha256"]),
    )
    try:
        source_bundle_document = json.loads(source_bundle_row["bundle_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Dispatch source bundle is invalid") from exc
    source_head_items = []
    for source_binding in publication_document["source_records"]:
        head = required(
            "SELECT source_kind, head_sequence, record_id, record_sha256, "
            "previous_head_sha256, head_sha256, advanced_at FROM "
            "action_authority_source_heads WHERE mission_id = ? AND "
            "source_kind = ? ORDER BY head_sequence DESC LIMIT 1",
            (
                mission_id,
                source_binding["record_kind"],
            ),
        )
        if (
            head["record_id"] != source_binding["record_id"]
            or head["record_sha256"] != source_binding["record_sha256"]
        ):
            raise StoreIntegrityError("Dispatch source publication is stale")
        source_head_items.append(dict(head))
    source_head_items.sort(key=lambda item: item["source_kind"])
    workspace = required(
        "SELECT high_water_id, high_water_sha256, mission_store_id, "
        "workspace_store_id, workspace_id, snapshot_id, snapshot_sha256, "
        "closure_id, closure_sha256, application_id, application_sha256, "
        "workspace_revision, event_count, event_head_sha256, "
        "event_head_occurred_at, state, revocation_id, revocation_sha256, "
        "workspace_store_path, imported_at FROM "
        "action_admission_workspace_high_waters WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    )
    review_projection = required(
        "SELECT closure_id, closure_sha256, workspace_id, application_id, "
        "application_sha256, projected_at FROM "
        "authenticated_expert_review_closure_projections WHERE closure_id = ?",
        (resolution["review_closure_id"],),
    )
    return {
        "admission": {
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "revocation_id": None,
        },
        "budget": {
            "account_id": reservation["account_id"],
            "binding_sequence": binding["binding_sequence"],
            "binding_sha256": binding["binding_sha256"],
            "budget_revision_id": binding["budget_revision_id"],
            "budget_revision_sha256": binding["budget_revision_sha256"],
            "event_id": None if budget_event is None else budget_event["event_id"],
            "event_sequence": budget["event_count"],
            "event_sha256": (
                budget["event_head_sha256"]
                if budget_event is None
                else budget_event["event_sha256"]
            ),
            "reservation_id": reservation["reservation_id"],
            "reservation_sha256": reservation["reservation_sha256"],
            "reserve_event_id": reservation["reserve_event_id"],
            "reserve_event_sha256": reservation["reserve_event_sha256"],
            "reserve_event_sequence": reserve_event["event_sequence"],
            **dict(budget),
        },
        "control": dict(control),
        "mission": dict(mission),
        "mission_policy": {
            **dict(mission_policy),
            "owner_use_sequence": owner_policy_use["use_sequence"],
            "control_use_sequence": control_policy_use["use_sequence"],
        },
        "ownership": ownership,
        "plan": {
            **dict(plan),
            "activation_use_sequence": plan_activation_use_sequence,
            "authority_use_sequences": plan_authority_use_sequences,
            "authority_use_set_sha256": _authority_use_set_sha256(
                plan_authority_use_sequences
            ),
        },
        "principal": {
            **dict(principal),
            "execute_use_sequence": execute_use["use_sequence"],
        },
        "review": {
            **dict(review_projection),
            "revocation_id": None,
            "review_revocation_head_sha256": source_bundle_document[
                "review_revocation_head_sha256"
            ],
        },
        "scope": {
            **dict(scope),
            "execution_scope_grant_sha256": authorization["scope_grant_sha256"],
            "bundle_scope_grant_sha256": source_bundle_document[
                "scope_grant_sha256"
            ],
        },
        "session": {
            **dict(session),
            "activation_authentication_id": activation["authentication_id"],
            "activation_authentication_sha256": activation[
                "authentication_sha256"
            ],
            "activation_authenticated_at": activation["authenticated_at"],
            "activation_control_issuer": activation["control_issuer"],
            "activation_control_assertion_id": activation["control_assertion_id"],
            "activation_control_use_sequence": activation_control_use["use_sequence"],
            "activation_worker_issuer": activation["worker_issuer"],
            "activation_worker_assertion_id": activation["worker_assertion_id"],
            "activation_worker_use_sequence": activation_worker_use["use_sequence"],
        },
        "source_bundle": dict(source),
        "source_heads": {"items": source_head_items},
        "trust": dict(trust),
        "workspace": dict(workspace),
    }


def _authority_high_water_sha256(high_water: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": AUTHORITY_HIGH_WATER_DOMAIN,
            "high_water": dict(high_water),
        }
    )


def _checkpoint_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _validate_authority_high_water(raw: Mapping[str, Any]) -> None:
    integer_fields = {
        "budget": {
            "binding_sequence": 1,
            "event_count": 1,
            "event_sequence": 1,
            "policy_binding_count": 1,
            "reserve_event_sequence": 1,
        },
        "control": {"version": 1},
        "mission": {"revision": 0},
        "mission_policy": {
            "control_use_sequence": 1,
            "owner_use_sequence": 1,
            "policy_version": 1,
        },
        "ownership": {"owner_epoch": 1, "sequence": 0},
        "plan": {"plan_version": 1},
        "principal": {
            "assertion_count": 1,
            "effect_count": 1,
            "execute_use_sequence": 1,
        },
        "review": {"projected_at": 0},
        "scope": {"signed_revocation_count": 0},
        "session": {
            "activation_control_use_sequence": 1,
            "activation_worker_use_sequence": 1,
            "fence_generation": 1,
            "owner_epoch": 1,
        },
        "source_bundle": {"head_sequence": 1},
        "trust": {"trust_policy_version": 1},
        "workspace": {
            "event_count": 1,
            "event_head_occurred_at": 0,
            "workspace_revision": 1,
        },
    }
    nullable_strings = {
        ("admission", "revocation_id"),
        ("control", "stop_event_id"),
        ("control", "stopped_at"),
        ("ownership", "entry_id"),
        ("ownership", "entry_sha256"),
        ("plan", "assertion_id"),
        ("plan", "issuer"),
        ("plan", "replacement_commit_id"),
        ("review", "revocation_id"),
        ("source_bundle", "previous_head_sha256"),
        ("workspace", "revocation_id"),
        ("workspace", "revocation_sha256"),
    }
    special_fields = {
        (section, field)
        for section, fields in integer_fields.items()
        for field in fields
    } | {
        ("ownership", "authority_use_sequences"),
        ("plan", "activation_use_sequence"),
        ("plan", "authority_use_sequences"),
        ("source_heads", "items"),
    }
    for section in AUTHORITY_HIGH_WATER_FIELDS:
        for field, value in raw[section].items():
            if (section, field) in special_fields:
                continue
            if (section, field) in nullable_strings and value is None:
                continue
            if type(value) is not str or not value:
                raise StoreIntegrityError(
                    "Execution authority high-water scalar type is invalid: "
                    f"{section}.{field}"
                )
            if ("sha256" in field or field.endswith("_hash")) and not _checkpoint_sha256(
                value
            ):
                raise StoreIntegrityError(
                    "Execution authority high-water hash type is invalid: "
                    f"{section}.{field}"
                )
    for section, fields in integer_fields.items():
        for field, minimum in fields.items():
            value = raw[section][field]
            if type(value) is not int or value < minimum:
                raise StoreIntegrityError(
                    "Execution authority high-water integer type is invalid"
                )
    for section in ("ownership", "plan"):
        sequences = raw[section]["authority_use_sequences"]
        if (
            type(sequences) is not list
            or any(type(item) is not int or item < 1 for item in sequences)
            or sequences != sorted(set(sequences))
        ):
            raise StoreIntegrityError(
                "Execution authority high-water authority uses are invalid"
            )
    plan = raw["plan"]
    activation_use_sequence = plan["activation_use_sequence"]
    if (
        activation_use_sequence is not None
        and (type(activation_use_sequence) is not int or activation_use_sequence < 1)
    ):
        raise StoreIntegrityError("Execution plan activation use type is invalid")
    if (
        not plan["authority_use_sequences"]
        or plan["authority_use_set_sha256"]
        != _authority_use_set_sha256(plan["authority_use_sequences"])
        or (
            plan["activation_kind"] == "initial"
            and (
                plan["replacement_commit_id"] is not None
                or plan["issuer"] is None
                or plan["assertion_id"] is None
                or activation_use_sequence != plan["authority_use_sequences"][0]
                or len(plan["authority_use_sequences"]) != 1
            )
        )
        or (
            plan["activation_kind"] == "replacement"
            and (
                plan["replacement_commit_id"] is None
                or plan["issuer"] is not None
                or plan["assertion_id"] is not None
                or activation_use_sequence is not None
            )
        )
        or plan["activation_kind"] not in {"initial", "replacement"}
    ):
        raise StoreIntegrityError("Execution plan checkpoint shape is invalid")
    ownership = raw["ownership"]
    if (
        ownership["sequence"] == 0
        and (
            ownership["entry_id"] is not None
            or ownership["entry_sha256"] is not None
            or ownership["owner_epoch"] != 1
            or ownership["authority_use_sequences"]
        )
    ) or (
        ownership["sequence"] > 0
        and (
            ownership["entry_id"] is None
            or ownership["entry_sha256"] is None
            or not ownership["authority_use_sequences"]
        )
    ):
        raise StoreIntegrityError("Execution ownership checkpoint shape is invalid")
    if (
        raw["admission"]["revocation_id"] is not None
        or raw["review"]["revocation_id"] is not None
        or raw["workspace"]["revocation_id"] is not None
        or raw["workspace"]["revocation_sha256"] is not None
        or raw["control"]["state"] != "active"
        or raw["control"]["stopped_at"] is not None
        or raw["control"]["stop_event_id"] is not None
        or raw["budget"]["policy_head_sha256"]
        != raw["budget"]["binding_sha256"]
    ):
        raise StoreIntegrityError("Execution authority high-water state is invalid")
    items = raw["source_heads"]["items"]
    expected_kinds = sorted(
        (*SOURCE_BINDINGS, *OBSERVATION_KINDS, "exact_action_source_head_bundle")
    )
    item_fields = {
        "source_kind",
        "head_sequence",
        "record_id",
        "record_sha256",
        "previous_head_sha256",
        "head_sha256",
        "advanced_at",
    }
    if type(items) is not list or len(items) != len(expected_kinds):
        raise StoreIntegrityError("Execution source-head checkpoint is incomplete")
    for item in items:
        if (
            type(item) is not dict
            or set(item) != item_fields
            or type(item["source_kind"]) is not str
            or type(item["head_sequence"]) is not int
            or item["head_sequence"] < 1
            or type(item["record_id"]) is not str
            or not item["record_id"]
            or not _checkpoint_sha256(item["record_sha256"])
            or not _checkpoint_sha256(item["head_sha256"])
            or (
                item["previous_head_sha256"] is not None
                and not _checkpoint_sha256(item["previous_head_sha256"])
            )
            or type(item["advanced_at"]) is not str
            or not item["advanced_at"]
            or (item["head_sequence"] == 1) != (
                item["previous_head_sha256"] is None
            )
        ):
            raise StoreIntegrityError("Execution source-head checkpoint item is invalid")
    if [item["source_kind"] for item in items] != expected_kinds:
        raise StoreIntegrityError("Execution source-head checkpoint kinds are invalid")


def _parse_authority_high_water(
    connection: sqlite3.Connection,
    raw_json: Any,
    raw_sha256: Any,
) -> dict[str, Any]:
    if type(raw_json) is not str or type(raw_sha256) is not str:
        raise StoreIntegrityError("Execution authority high-water type is invalid")
    try:
        raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Execution authority high-water JSON is invalid") from exc
    if (
        type(raw) is not dict
        or tuple(sorted(raw)) != tuple(sorted(AUTHORITY_HIGH_WATER_FIELDS))
        or any(type(raw[field]) is not dict for field in AUTHORITY_HIGH_WATER_FIELDS)
        or any(
            set(raw[field]) != AUTHORITY_HIGH_WATER_SECTION_FIELDS[field]
            for field in AUTHORITY_HIGH_WATER_FIELDS
        )
        or _canonical_json(raw) != raw_json
        or _authority_high_water_sha256(raw) != raw_sha256
    ):
        raise StoreIntegrityError("Execution authority high-water is invalid")
    _validate_authority_high_water(raw)
    return raw


def _insert_authority_checkpoint(
    connection: sqlite3.Connection,
    *,
    checkpoint_kind: str,
    request: ActionExecutionRequest,
    claim: ActionExecutionClaim,
    high_water: Mapping[str, Any],
    captured_at: str,
) -> tuple[str, str]:
    if checkpoint_kind not in {"claim", "dispatch"}:
        raise StoreIntegrityError("Execution authority checkpoint kind is invalid")
    high_water_document = dict(high_water)
    high_water_sha256 = _authority_high_water_sha256(high_water_document)
    body = {
        "schema_version": 1,
        "kind": "action_execution_authority_checkpoint",
        "checkpoint_kind": checkpoint_kind,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "claim_id": claim.claim_id,
        "claim_sha256": claim.claim_sha256,
        "high_water": high_water_document,
        "high_water_sha256": high_water_sha256,
        "captured_at": captured_at,
    }
    checkpoint_sha256 = _canonical_sha256(
        {"domain": AUTHORITY_CHECKPOINT_DOMAIN, "record": body}
    )
    checkpoint_id = (
        "AXH-" + checkpoint_sha256.removeprefix("sha256:")[:32].upper()
    )
    checkpoint_document = {**body, "checkpoint_id": checkpoint_id}
    connection.execute(
        """
        INSERT INTO action_execution_authority_checkpoints(
            checkpoint_id, checkpoint_sha256, request_id, request_sha256,
            claim_id, claim_sha256, checkpoint_kind, high_water_json,
            high_water_sha256, checkpoint_json, captured_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            checkpoint_id,
            checkpoint_sha256,
            request.request_id,
            request.request_sha256,
            claim.claim_id,
            claim.claim_sha256,
            checkpoint_kind,
            _canonical_json(high_water_document),
            high_water_sha256,
            _canonical_json(checkpoint_document),
            captured_at,
        ),
    )
    return checkpoint_id, checkpoint_sha256


def _closure_document(
    terminal: ActionExecutionTerminal,
) -> dict[str, Any]:
    document = terminal.to_dict()
    body = {
        "schema_version": 1,
        "kind": "action_execution_closure",
        "request_id": document["request_id"],
        "terminal_id": terminal.terminal_id,
        "terminal_sha256": terminal.terminal_sha256,
        "action_outcome": document["action_outcome"],
        "evidence_status": document["evidence_status"],
        "cleanup_status": document["cleanup_status"],
        "restoration_status": document["restoration_status"],
        "closed_at": document["settled_at"],
    }
    digest = _canonical_sha256({"domain": CLOSURE_DOMAIN, "record": body})
    return {
        **body,
        "closure_id": "AXL-" + digest.removeprefix("sha256:")[:32].upper(),
        "closure_sha256": digest,
    }


def _build_terminal_record(
    *,
    request: ActionExecutionRequest,
    claim: ActionExecutionClaim,
    status: TerminalStatus,
    outcome: ActionOutcome,
    evidence: AxisStatus,
    cleanup: AxisStatus,
    restoration: AxisStatus,
    result_document: Mapping[str, Any],
    charged: ExecutionResources,
    reason_code: str,
    settled_at: str,
    invocation_known: bool,
    invocation_zero: bool = False,
) -> ActionExecutionTerminal:
    return AuthenticatedActionExecutionService._build_terminal(
        request=request,
        claim=claim,
        status=status,
        outcome=outcome,
        evidence=evidence,
        cleanup=cleanup,
        restoration=restoration,
        result_document=result_document,
        charged=charged,
        reason_code=reason_code,
        settled_at=settled_at,
        invocation_known=invocation_known,
        invocation_zero=invocation_zero,
    )


class MissionStoreAuthenticatedActionExecutionService:
    """Execute one admitted action through one owned primitive adapter."""

    def __init__(
        self,
        store: MissionStore,
        admission: MissionStoreAuthenticatedActionAdmissionService,
        adapter: _QualifiedPrimitiveAdapterCapability,
        *,
        clock: Any | None = None,
        _allow_reference_capability: bool = False,
    ) -> None:
        if type(store) is not MissionStore:
            raise TypeError("store must be a MissionStore")
        if type(admission) is not MissionStoreAuthenticatedActionAdmissionService:
            raise TypeError("admission must be the MissionStore production service")
        if getattr(admission, "_store", None) is not store:
            raise TypeError("admission service must own the same MissionStore")
        if type(adapter) is not _QualifiedPrimitiveAdapterCapability:
            raise TypeError("adapter must be a sealed repository capability")
        binding = adapter.binding
        expected = hmac.new(
            _ADAPTER_CAPABILITY_KEY,
            _adapter_capability_material(
                adapter.adapter,
                binding,
                adapter.conformance_evidence_sha256,
                adapter.external_single_attempt_attested,
            ),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(adapter._proof, expected):
            raise TypeError("adapter capability proof is invalid")
        if not adapter.external_single_attempt_attested and not _allow_reference_capability:
            raise TypeError("adapter lacks external single-attempt conformance evidence")
        self._store = store
        self._admission = admission
        self._adapter_capability = adapter
        self._adapter = adapter.adapter
        self._adapter_binding = binding
        self._reference_clock = clock
        self._dispatch_proof_key = secrets.token_bytes(32)
        self._principal_custody = MissionStoreActionPrincipalCustody(
            store,
            admission._review_registry,
        )

    @classmethod
    def _reference_for_tests(
        cls,
        store: MissionStore,
        admission: MissionStoreAuthenticatedActionAdmissionService,
        adapter: PrimitiveActionAdapter,
        *,
        clock: Any | None = None,
    ) -> MissionStoreAuthenticatedActionExecutionService:
        return cls(
            store,
            admission,
            _reference_adapter_capability(adapter),
            clock=clock,
            _allow_reference_capability=True,
        )

    def initialize(self) -> None:
        self._store.initialize()

    @staticmethod
    def _format_time(value: datetime) -> str:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ActionExecutionError(
                "Execution clock must return an aware datetime"
            )
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _now(self) -> str:
        return self._admission._seal_execution_transaction_time().checked_at

    def _require_owned_current_schema_transaction(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        if type(connection) is not sqlite3.Connection or not connection.in_transaction:
            raise StoreIntegrityError(
                "Execution custody requires an active owned transaction"
            )
        mission_main = next(
            (
                item[2]
                for item in connection.execute("PRAGMA database_list").fetchall()
                if item[1] == "main"
            ),
            None,
        )
        if (
            type(mission_main) is not str
            or not mission_main
            or Path(mission_main).resolve() != self._store.path.resolve()
            or self._store._require_schema(connection) != SCHEMA_VERSION
        ):
            raise StoreIntegrityError(
                "Execution custody requires the owned current-schema store"
            )

    def _require_adapter_binding(self) -> None:
        if "_invoke_once" in getattr(self, "__dict__", {}):
            raise ActionExecutionError("Service adapter invocation path changed")
        binding = getattr(self._adapter, "binding", None)
        capability = self._adapter_capability
        expected = hmac.new(
            _ADAPTER_CAPABILITY_KEY,
            _adapter_capability_material(
                self._adapter,
                self._adapter_binding,
                capability.conformance_evidence_sha256,
                capability.external_single_attempt_attested,
            ),
            hashlib.sha256,
        ).digest()
        if (
            type(binding) is not AdapterBinding
            or binding != self._adapter_binding
            or not hmac.compare_digest(capability._proof, expected)
        ):
            raise ActionExecutionError("Service adapter binding changed")

    def prepare(self, command: ActionExecutionCommand) -> ActionExecutionRequest:
        """Build an unsigned exact request for external principal signing."""

        if type(command) is not ActionExecutionCommand:
            raise TypeError("command must be an ActionExecutionCommand")
        self._require_adapter_binding()
        prepared_at = self._now()
        context: _ExecutionContext | None = None
        try:
            with self._store._write_connection() as connection:
                context = self._load_context(
                    connection,
                    command,
                    prepared_at,
                    prepared_at=prepared_at,
                )
                verify_authenticated_action_execution_store(connection)
                return context.request
        finally:
            if context is not None:
                self._admission._transaction_review_verifier.close_local_workspace_guard(
                    context.workspace_guard
                )

    def prepare_reconciliation(
        self,
        request_id: str,
        *,
        reason_code: str,
        authority_expires_at: str,
    ) -> ActionExecutionReconciliationIntent:
        """Prepare exact settlement semantics for independent signing."""

        if type(request_id) is not str or not request_id:
            raise ActionExecutionError("request ID is invalid")
        with self._store._write_connection() as connection:
            prepared_at = self._now()
            request, claim = self._stored_request_claim(connection, request_id)
            if self._terminal_for_request(connection, request_id) is not None:
                raise StoreConflictError("Execution already has terminal custody")
            authorization = _parse_authorization(claim.to_dict()["authorization"])
            if prepared_at < authorization["expires_at"]:
                raise ActionExecutionReconciliationRequired(
                    "Execution claim lease is still active"
                )
            return self._build_reconciliation_intent(
                connection,
                request,
                claim,
                reason_code=reason_code,
                authority_expires_at=authority_expires_at,
                prepared_at=prepared_at,
            )

    def _stored_request_claim(
        self,
        connection: sqlite3.Connection,
        request_id: str,
    ) -> tuple[ActionExecutionRequest, ActionExecutionClaim]:
        row = connection.execute(
            "SELECT request_json FROM action_execution_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        claim_row = connection.execute(
            "SELECT claim_json FROM action_execution_claims WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None or claim_row is None:
            raise ActionExecutionError("Execution request or claim is absent")
        try:
            request = parse_action_execution_request(json.loads(row["request_json"]))
            claim = parse_action_execution_claim(json.loads(claim_row["claim_json"]))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Execution request or claim is invalid") from exc
        return request, claim

    def _build_reconciliation_intent(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        *,
        reason_code: str,
        authority_expires_at: str,
        prepared_at: str,
    ) -> ActionExecutionReconciliationIntent:
        if (
            type(reason_code) is not str
            or not reason_code
            or len(reason_code) > 128
            or any(ord(character) < 33 or ord(character) > 126 for character in reason_code)
        ):
            raise ActionExecutionError("Reconciliation reason code is invalid")
        if type(authority_expires_at) is not str or prepared_at >= authority_expires_at:
            raise ActionExecutionError("Reconciliation authority window is invalid")
        dispatch = connection.execute(
            "SELECT dispatch_id, dispatch_sha256 FROM action_execution_dispatch_attempts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        plan = connection.execute(
            "SELECT activation.plan_id, activation.plan_sha256 FROM "
            "collaboration_plan_active_heads AS head JOIN "
            "collaboration_plan_activations AS activation ON activation.plan_id = "
            "head.active_plan_id WHERE head.mission_id = ?",
            (request.to_dict()["authority_state"]["mission_id"],),
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM "
            "collaboration_mission_policy_commits WHERE mission_id = ? "
            "ORDER BY policy_version DESC LIMIT 1",
            (request.to_dict()["authority_state"]["mission_id"],),
        ).fetchone()
        scope_head = connection.execute(
            "SELECT baseline_root_hash, signed_revocation_count, head_hash FROM "
            "mission_scope_revocation_baselines WHERE mission_id = ?",
            (request.to_dict()["authority_state"]["mission_id"],),
        ).fetchone()
        reservation = self._reservation_for_request(connection, request.request_id)
        if plan is None or policy is None or scope_head is None:
            raise ActionExecutionError("Current reconciliation authority is absent")
        try:
            policy_document = json.loads(policy["policy_json"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Current collaboration policy is invalid") from exc
        if (
            _canonical_json(policy_document) != policy["policy_json"]
            or policy_document["collaboration_plan_id"] != plan["plan_id"]
            or policy_document["effective_at"] > prepared_at
            or policy_document["expires_at"] <= prepared_at
        ):
            raise ActionExecutionError("Current reconciliation policy is not eligible")
        no_dispatch = dispatch is None
        deterministic_dispatch_id = _dispatch_id(request, claim)
        if dispatch is not None and dispatch["dispatch_id"] != deterministic_dispatch_id:
            raise StoreIntegrityError("Reconciliation dispatch custody is invalid")
        invocation_count = 0
        baseline_request = False
        if dispatch is not None:
            invocation_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ? AND consumer_id = ? "
                    "AND consumer_sha256 = ?",
                    (
                        ActionTargetHealthGateUseKind
                        .ACTION_EXECUTION_INVOCATION.value,
                        dispatch["dispatch_id"],
                        dispatch["dispatch_sha256"],
                    ),
                ).fetchone()[0]
            )
            if invocation_count not in {0, 1}:
                raise StoreIntegrityError(
                    "Reconciliation invocation custody is duplicated"
                )
            baseline_request = _is_execution_health_cutover_baseline_request(
                connection,
                request,
            )
        exact_zero = no_dispatch or (
            dispatch is not None
            and not baseline_request
            and invocation_count == 0
        )
        charged = (
            ExecutionResources(**{field: 0 for field in RESOURCE_FIELDS})
            if exact_zero
            else reservation
        )
        document = request.to_dict()
        body = {
            "schema_version": 1,
            "kind": "reconciliation_intent",
            "tenant_id": document["authority_state"]["tenant_id"],
            "mission_id": document["authority_state"]["mission_id"],
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "claim_id": claim.claim_id,
            "claim_sha256": claim.claim_sha256,
            "dispatch_id": deterministic_dispatch_id,
            "dispatch_sha256": None if no_dispatch else dispatch["dispatch_sha256"],
            "reconciliation_mode": (
                "predispatch_abort" if exact_zero else "dispatched_indeterminate"
            ),
            "reason_code": reason_code,
            "terminal_status": (
                TerminalStatus.PREDISPATCH_ABORTED.value
                if exact_zero
                else TerminalStatus.INDETERMINATE_QUARANTINED.value
            ),
            "action_outcome": (
                ActionOutcome.FAILED.value
                if exact_zero
                else ActionOutcome.INDETERMINATE.value
            ),
            "evidence_status": AxisStatus.UNKNOWN.value,
            "cleanup_status": AxisStatus.UNKNOWN.value,
            "restoration_status": AxisStatus.UNKNOWN.value,
            "adapter_call_count_status": (
                "exactly_zero" if exact_zero else "unknown_zero_or_one"
            ),
            "adapter_call_count": 0 if exact_zero else None,
            "charged_resources": charged.to_dict(),
            "active_plan_id": plan["plan_id"],
            "active_plan_sha256": plan["plan_sha256"],
            "collaboration_policy_id": policy["policy_id"],
            "collaboration_policy_sha256": policy["policy_sha256"],
            "scope_revocation_count": scope_head["signed_revocation_count"],
            "scope_revocation_head_sha256": scope_head["head_hash"],
            "authority_expires_at": authority_expires_at,
            "prepared_at": prepared_at,
        }
        return ActionExecutionReconciliationIntent.from_dict(
            _record(
                "reconciliation_intent",
                "AXI",
                RECONCILIATION_INTENT_DOMAIN,
                body,
            )
        )

    def execute(
        self,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
    ) -> ActionExecutionTerminal:
        """Claim, dispatch once, and settle one authenticated action."""

        result = self._execute_with_health_result(
            command,
            request,
            assertion,
            authorization,
        )
        if isinstance(result, _CommittedExecutionHealthDenial):
            raise ActionExecutionError(
                f"Target health gate denied {result.boundary}"
            )
        return result

    def _execute_with_health_result(
        self,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        """Return a denial sentinel only after its PAUSED state commits."""

        if type(command) is not ActionExecutionCommand:
            raise TypeError("command must be an ActionExecutionCommand")
        request = parse_action_execution_request(request.to_dict())
        if type(assertion) is not PrincipalAssertion:
            raise TypeError("assertion must be a PrincipalAssertion")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        authorization = _parse_authorization(authorization)
        context: _ExecutionContext | None = None
        claim: ActionExecutionClaim | None = None
        dispatch_id: str | None = None
        try:
            with self._store._write_connection() as connection:
                transaction_time = self._admission._seal_execution_transaction_time()
                checked_at = transaction_time.checked_at
                existing = connection.execute(
                    "SELECT * FROM action_execution_requests "
                    "WHERE idempotency_key_sha256 = ?",
                    (command.idempotency_key_sha256,),
                ).fetchone()
                if existing is not None:
                    context = self._load_context(
                        connection,
                        command,
                        checked_at,
                        prepared_at=request.to_dict()["prepared_at"],
                    )
                    authority_row = connection.execute(
                        "SELECT authorization_json, assertion_issuer, assertion_id "
                        "FROM action_execution_authority_consumptions WHERE "
                        "request_id = ?",
                        (request.request_id,),
                    ).fetchone()
                    principal_row = (
                        None
                        if authority_row is None
                        else connection.execute(
                            "SELECT assertion_json FROM principal_assertion_uses "
                            "WHERE issuer = ? AND assertion_id = ?",
                            (
                                authority_row["assertion_issuer"],
                                authority_row["assertion_id"],
                            ),
                        ).fetchone()
                    )
                    if (
                        context.request.document_json != request.document_json
                        or authority_row is None
                        or principal_row is None
                        or authority_row["authorization_json"]
                        != _canonical_json(dict(authorization))
                        or principal_row["assertion_json"]
                        != canonical_json(assertion.to_dict())
                    ):
                        raise StoreConflictError(
                            "Execution replay authority differs from custody"
                        )
                    self._validate_authorization(
                        request,
                        assertion,
                        authorization,
                        action_execute_authorization_intent_sha256(request),
                        checked_at,
                    )
                    self._principal_custody.verify_stored_current(
                        connection,
                        authorization,
                        ACTION_EXECUTE,
                        checked_at,
                        receipt_id=command.receipt_id,
                    )
                    terminal = self._existing_result(
                        connection,
                        command,
                        request,
                        existing,
                    )
                    health_result = (
                        self._admission._observe_target_health_in_transaction(
                            connection,
                            binding=context.target_health_binding,
                            expected_at=checked_at,
                        )
                    )
                    if health_result.decision.status is not (
                        TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
                    ):
                        return _CommittedExecutionHealthDenial(
                            "action execution terminal replay"
                        )
                    self._admission._record_target_health_use(
                        connection,
                        use_kind=(
                            ActionTargetHealthGateUseKind
                            .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE
                        ),
                        consumer_id=terminal.terminal_id,
                        consumer_sha256=terminal.terminal_sha256,
                        binding=context.target_health_binding,
                        result=health_result,
                        used_at=checked_at,
                    )
                    return terminal
                prepared_at = request.to_dict()["prepared_at"]
                if prepared_at > checked_at:
                    raise ActionExecutionError("Execution request is future dated")
                context = self._load_context(
                    connection,
                    command,
                    checked_at,
                    prepared_at=prepared_at,
                )
                if context.request.document_json != request.document_json:
                    raise ActionExecutionError(
                        "Prepared execution request differs from current authority"
                    )
                intent = action_execute_authorization_intent_sha256(request)
                self._validate_authorization(
                    request,
                    assertion,
                    authorization,
                    intent,
                    checked_at,
                )
                claim = self._build_claim(request, authorization, checked_at)
                dispatch_id = _dispatch_id(request, claim)
                health_result = (
                    self._admission._observe_target_health_in_transaction(
                        connection,
                        binding=context.target_health_binding,
                        expected_at=checked_at,
                    )
                )
                if health_result.decision.status is not (
                    TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
                ):
                    return _CommittedExecutionHealthDenial(
                        "action execution claim"
                    )
                self._insert_request(
                    connection,
                    command,
                    request,
                    claim,
                )
                self._principal_custody.consume(
                    connection,
                    assertion,
                    authorization,
                    ACTION_EXECUTE,
                    checked_at,
                    receipt_id=command.receipt_id,
                    effect_document=authorization,
                    effect_id=request.request_id,
                )
                self._insert_authority_consumption(
                    connection,
                    request,
                    authorization,
                    checked_at,
                )
                self._insert_reservation(
                    connection,
                    request,
                    context.budget,
                    checked_at,
                )
                claim_high_water = _capture_authority_high_water(
                    connection,
                    request,
                    authorization,
                )
                claim_checkpoint_id, claim_checkpoint_sha256 = (
                    _insert_authority_checkpoint(
                        connection,
                        checkpoint_kind="claim",
                        request=request,
                        claim=claim,
                        high_water=claim_high_water,
                        captured_at=checked_at,
                    )
                )
                self._insert_claim(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    authorization,
                    claim_checkpoint_id,
                    claim_checkpoint_sha256,
                )
                self._admission._record_target_health_use(
                    connection,
                    use_kind=ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM,
                    consumer_id=claim.claim_id,
                    consumer_sha256=claim.claim_sha256,
                    binding=context.target_health_binding,
                    result=health_result,
                    used_at=checked_at,
                )
                self._admission._consume_for_execution_in_transaction(
                    connection,
                    receipt_id=command.receipt_id,
                    execution_id=request.request_id,
                    execution_intent_sha256=intent,
                    claim_id=claim.claim_id,
                    claim_sha256=claim.claim_sha256,
                    consumed_at=checked_at,
                    workspace_connection=context.workspace_guard,
                    workspace_high_water=context.workspace_high_water,
                    _transaction_time=transaction_time,
                )
                verify_authenticated_action_execution_store(connection)
                dispatch = self._seal_dispatch(request, claim, dispatch_id)
                reservation = context.budget.reservation
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Action execution conflicts with global custody"
            ) from exc
        finally:
            if context is not None:
                self._admission._transaction_review_verifier.close_local_workspace_guard(
                    context.workspace_guard
                )
        if claim is None or dispatch_id is None:
            raise StoreIntegrityError("Execution claim was not constructed")
        try:
            dispatch_result = self._commit_dispatch_attempt(
                command,
                request,
                claim,
                dispatch,
            )
        except BaseException as exc:
            return self._quarantine(
                request,
                claim,
                dispatch_id,
                "predispatch_recheck_failure_" + type(exc).__name__.lower(),
                invocation_known=False,
            )
        if isinstance(dispatch_result, _CommittedExecutionHealthDenial):
            return self._quarantine(
                request,
                claim,
                dispatch_id,
                "target_health_gate_denied_dispatch",
                invocation_known=False,
                invocation_zero=True,
                minimum_settlement_at=(
                    dispatch_result.minimum_settlement_at
                ),
            )
        return self._invoke_and_settle(
            request,
            claim,
            dispatch_id,
            reservation,
        )

    def _settlement_time_in_transaction(
        self,
        connection: sqlite3.Connection,
        claim: ActionExecutionClaim,
        request_id: str,
        *,
        recover_clock_failure: bool = False,
    ) -> str:
        dispatch = connection.execute(
            "SELECT attempted_at FROM action_execution_dispatch_attempts "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        budget_head = connection.execute(
            "SELECT head.updated_at FROM action_execution_reservations AS reservation "
            "JOIN action_budget_account_heads AS head ON head.account_id = "
            "reservation.account_id WHERE reservation.request_id = ?",
            (request_id,),
        ).fetchone()
        invocation_use = connection.execute(
            "SELECT use.used_at, head.updated_at AS health_head_updated_at "
            "FROM action_target_health_gate_uses AS use "
            "JOIN action_execution_dispatch_attempts AS dispatch "
            "ON dispatch.dispatch_id = use.consumer_id "
            "AND dispatch.dispatch_sha256 = use.consumer_sha256 "
            "JOIN target_health_gate_heads AS head "
            "ON head.subject_id = use.subject_id "
            "WHERE dispatch.request_id = ? AND use.use_kind = ?",
            (
                request_id,
                ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value,
            ),
        ).fetchone()
        durable_floor = max(
            claim.to_dict()["claimed_at"],
            *([] if dispatch is None else [dispatch["attempted_at"]]),
            *([] if budget_head is None else [budget_head["updated_at"]]),
            *([] if invocation_use is None else [invocation_use["used_at"]]),
            *(
                []
                if invocation_use is None
                else [invocation_use["health_head_updated_at"]]
            ),
        )
        try:
            return max(self._now(), durable_floor)
        except BaseException:
            if not recover_clock_failure:
                raise
            return durable_floor

    def _terminal_replay_for_use_in_transaction(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        terminal: ActionExecutionTerminal,
        *,
        boundary: str,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        self._require_owned_current_schema_transaction(connection)
        verify_authenticated_action_execution_store(connection)
        checked_at = self._now()
        request_document = request.to_dict()
        command = ActionExecutionCommand(
            receipt_id=request_document["admission_receipt"]["receipt_id"],
            idempotency_key_sha256=request_document["idempotency_key_sha256"],
        )
        context: _ExecutionContext | None = None
        try:
            context = self._load_context(
                connection,
                command,
                checked_at,
                prepared_at=request_document["prepared_at"],
            )
            if context.request.document_json != request.document_json:
                raise ActionExecutionError(
                    "Terminal replay current execution authority changed"
                )
            claim_row = connection.execute(
                "SELECT claim_json, authorization_json FROM "
                "action_execution_claims WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            authority_row = connection.execute(
                "SELECT authorization_json FROM "
                "action_execution_authority_consumptions WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if (
                claim_row is None
                or authority_row is None
                or type(claim_row["claim_json"]) is not str
                or type(claim_row["authorization_json"]) is not str
                or type(authority_row["authorization_json"]) is not str
            ):
                raise StoreIntegrityError(
                    "Terminal replay execution authority custody is absent"
                )
            try:
                claim = parse_action_execution_claim(
                    json.loads(claim_row["claim_json"])
                )
                authorization = _parse_authorization(
                    claim.to_dict()["authorization"]
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise StoreIntegrityError(
                    "Terminal replay execution authority custody is invalid"
                ) from exc
            authorization_json = _canonical_json(authorization)
            if (
                claim.to_dict()["request_id"] != request.request_id
                or claim.to_dict()["request_sha256"] != request.request_sha256
                or claim_row["authorization_json"] != authorization_json
                or authority_row["authorization_json"] != authorization_json
            ):
                raise StoreIntegrityError(
                    "Terminal replay execution authority custody differs"
                )
            self._principal_custody.verify_stored_current(
                connection,
                authorization,
                ACTION_EXECUTE,
                checked_at,
                receipt_id=command.receipt_id,
            )
            self._require_adapter_binding()
            health_result = (
                self._admission._observe_target_health_in_transaction(
                    connection,
                    binding=context.target_health_binding,
                    expected_at=checked_at,
                )
            )
            if health_result.decision.status is not (
                TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
            ):
                return _CommittedExecutionHealthDenial(boundary)
            self._admission._record_target_health_use(
                connection,
                use_kind=(
                    ActionTargetHealthGateUseKind
                    .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE
                ),
                consumer_id=terminal.terminal_id,
                consumer_sha256=terminal.terminal_sha256,
                binding=context.target_health_binding,
                result=health_result,
                used_at=checked_at,
            )
            return terminal
        finally:
            if context is not None:
                self._admission._transaction_review_verifier.close_local_workspace_guard(
                    context.workspace_guard
                )

    def _commit_invocation_authorization(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial | None:
        """Commit the final internal health authorization before target effect."""

        with self._store._write_connection() as connection:
            self._require_owned_current_schema_transaction(connection)
            existing = self._terminal_for_request(connection, request.request_id)
            if existing is not None:
                return self._terminal_replay_for_use_in_transaction(
                    connection,
                    request,
                    existing,
                    boundary="action execution pre-invocation terminal replay",
                )
            dispatch = connection.execute(
                "SELECT dispatch_id, dispatch_sha256, attempted_at "
                "FROM action_execution_dispatch_attempts WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if (
                dispatch is None
                or dispatch["dispatch_id"] != dispatch_id
                or connection.execute(
                    "SELECT 1 FROM action_execution_predispatch_aborts WHERE "
                    "request_id = ? UNION ALL SELECT 1 FROM "
                    "action_execution_preinvocation_aborts WHERE request_id = ? "
                    "UNION ALL SELECT 1 FROM action_execution_closures "
                    "WHERE request_id = ? LIMIT 1",
                    (
                        request.request_id,
                        request.request_id,
                        request.request_id,
                    ),
                ).fetchone()
                is not None
            ):
                raise ActionExecutionReconciliationRequired(
                    "Execution is no longer eligible for invocation"
                )
            existing_use = connection.execute(
                "SELECT 1 FROM action_target_health_gate_uses "
                "WHERE use_kind = ? AND consumer_id = ? AND consumer_sha256 = ?",
                (
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value,
                    dispatch["dispatch_id"],
                    dispatch["dispatch_sha256"],
                ),
            ).fetchone()
            if existing_use is not None:
                raise ActionExecutionReconciliationRequired(
                    "Invocation authorization is already committed"
                )
            connection.execute("SAVEPOINT action_execution_invocation_health")
            context: _ExecutionContext | None = None
            try:
                invocation_checked_at = self._now()
                command = ActionExecutionCommand(
                    receipt_id=request.to_dict()["admission_receipt"]["receipt_id"],
                    idempotency_key_sha256=request.to_dict()[
                        "idempotency_key_sha256"
                    ],
                )
                context = self._load_context(
                    connection,
                    command,
                    invocation_checked_at,
                    prepared_at=request.to_dict()["prepared_at"],
                )
                if context.request.document_json != request.document_json:
                    raise ActionExecutionError(
                        "Final invocation authority changed"
                    )
                authorization = _parse_authorization(
                    claim.to_dict()["authorization"]
                )
                self._principal_custody.verify_stored_current(
                    connection,
                    authorization,
                    ACTION_EXECUTE,
                    invocation_checked_at,
                    receipt_id=command.receipt_id,
                )
                self._require_adapter_binding()
                health_result = (
                    self._admission._observe_target_health_in_transaction(
                        connection,
                        binding=context.target_health_binding,
                        expected_at=invocation_checked_at,
                    )
                )
            except BaseException as exc:
                connection.execute(
                    "ROLLBACK TO action_execution_invocation_health"
                )
                connection.execute(
                    "RELEASE action_execution_invocation_health"
                )
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                    recover_clock_failure=True,
                )
                return self._quarantine_in_transaction(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    "invocation_health_unavailable_" + type(exc).__name__.lower(),
                    invocation_known=False,
                    invocation_zero=True,
                    settled_at=settled_at,
                    force_zero_invocation_abort=True,
                )
            finally:
                if context is not None:
                    self._admission._transaction_review_verifier.close_local_workspace_guard(
                        context.workspace_guard
                    )
            if health_result.decision.status is not (
                TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
            ):
                connection.execute(
                    "RELEASE action_execution_invocation_health"
                )
                return _CommittedExecutionHealthDenial(
                    "action execution invocation",
                    health_result.decision.head.updated_at,
                    health_decision=(
                        health_result.decision.decision_id,
                        health_result.decision.decision_sha256,
                        _canonical_json(health_result.decision.to_dict()),
                    ),
                    exact_settlement_at=(
                        health_result.decision.to_dict()["evaluated_at"]
                    ),
                )
            self._admission._record_target_health_use(
                connection,
                use_kind=(
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION
                ),
                consumer_id=dispatch["dispatch_id"],
                consumer_sha256=dispatch["dispatch_sha256"],
                binding=context.target_health_binding,
                result=health_result,
                used_at=invocation_checked_at,
            )
            connection.execute("RELEASE action_execution_invocation_health")
            verify_authenticated_action_execution_store(connection)
            return None

    def _invoke_and_settle(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        reservation: ExecutionResources,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        """Authorize once, then hold the writer lock across one adapter call."""

        invocation_result = self._commit_invocation_authorization(
            request,
            claim,
            dispatch_id,
        )
        if isinstance(invocation_result, _CommittedExecutionHealthDenial):
            if invocation_result.health_decision is None:
                return invocation_result
            return self._quarantine(
                request,
                claim,
                dispatch_id,
                "target_health_gate_denied_invocation",
                invocation_known=False,
                invocation_zero=True,
                minimum_settlement_at=(
                    invocation_result.minimum_settlement_at
                ),
                force_zero_invocation_abort=True,
                health_decision=invocation_result.health_decision,
                exact_settlement_at=invocation_result.exact_settlement_at,
            )
        if invocation_result is not None:
            return invocation_result

        with self._store._write_connection() as connection:
            self._require_owned_current_schema_transaction(connection)
            existing = self._terminal_for_request(connection, request.request_id)
            if existing is not None:
                return self._terminal_replay_for_use_in_transaction(
                    connection,
                    request,
                    existing,
                    boundary="action execution concurrent terminal replay",
                )
            dispatch = connection.execute(
                "SELECT dispatch_id, dispatch_sha256, attempted_at "
                "FROM action_execution_dispatch_attempts "
                "WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if (
                dispatch is None
                or dispatch["dispatch_id"] != dispatch_id
                or connection.execute(
                    "SELECT 1 FROM action_execution_predispatch_aborts WHERE "
                    "request_id = ? UNION ALL SELECT 1 FROM "
                    "action_execution_preinvocation_aborts WHERE request_id = ? "
                    "UNION ALL SELECT 1 FROM action_execution_closures "
                    "WHERE request_id = ? LIMIT 1",
                    (
                        request.request_id,
                        request.request_id,
                        request.request_id,
                    ),
                ).fetchone()
                is not None
            ):
                raise ActionExecutionReconciliationRequired(
                    "Execution is no longer eligible for invocation"
                )
            invocation_use = connection.execute(
                "SELECT use_id, use_sha256, decision_id, decision_sha256, "
                "decision_json, head_id, head_sha256 FROM "
                "action_target_health_gate_uses "
                "WHERE use_kind = ? AND consumer_id = ? AND consumer_sha256 = ?",
                (
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value,
                    dispatch["dispatch_id"],
                    dispatch["dispatch_sha256"],
                ),
            ).fetchone()
            if invocation_use is None:
                raise ActionExecutionReconciliationRequired(
                    "Committed invocation authorization is absent"
                )
            context: _ExecutionContext | None = None
            try:
                checked_at = self._now()
                request_document = request.to_dict()
                command = ActionExecutionCommand(
                    receipt_id=request_document["admission_receipt"]["receipt_id"],
                    idempotency_key_sha256=request_document[
                        "idempotency_key_sha256"
                    ],
                )
                context = self._load_context(
                    connection,
                    command,
                    checked_at,
                    prepared_at=request_document["prepared_at"],
                )
                if context.request.document_json != request.document_json:
                    raise ActionExecutionError(
                        "Final invocation authority changed after authorization"
                    )
                self._principal_custody.verify_stored_current(
                    connection,
                    _parse_authorization(claim.to_dict()["authorization"]),
                    ACTION_EXECUTE,
                    checked_at,
                    receipt_id=command.receipt_id,
                )
                current_head = connection.execute(
                    "SELECT head_id, head_sha256 FROM "
                    "target_health_gate_heads WHERE subject_id = "
                    "(SELECT subject_id FROM action_target_health_gate_uses "
                    "WHERE use_id = ? AND use_sha256 = ?)",
                    (
                        invocation_use["use_id"],
                        invocation_use["use_sha256"],
                    ),
                ).fetchone()
                if (
                    current_head is None
                    or current_head["head_id"] != invocation_use["head_id"]
                    or current_head["head_sha256"]
                    != invocation_use["head_sha256"]
                ):
                    raise ActionExecutionError(
                        "Invocation target-health head changed after authorization"
                    )
                self._require_adapter_binding()
            except BaseException as exc:
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                    recover_clock_failure=True,
                )
                return self._quarantine_in_transaction(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    "adapter_capability_invalid_" + type(exc).__name__.lower(),
                    invocation_known=False,
                    invocation_zero=True,
                    settled_at=settled_at,
                    force_zero_invocation_abort=True,
                    health_decision=(
                        invocation_use["decision_id"],
                        invocation_use["decision_sha256"],
                        invocation_use["decision_json"],
                    ),
                    invocation_use=(
                        invocation_use["use_id"],
                        invocation_use["use_sha256"],
                    ),
                )
            finally:
                if context is not None:
                    self._admission._transaction_review_verifier.close_local_workspace_guard(
                        context.workspace_guard
                    )
            verify_authenticated_action_execution_store(connection)
            try:
                raw_result = self._adapter.invoke_once(
                    _immutable_document(request.to_dict())
                )
            except BaseException as exc:
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                    recover_clock_failure=True,
                )
                return self._quarantine_in_transaction(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    "adapter_exception_" + type(exc).__name__.lower(),
                    invocation_known=True,
                    settled_at=settled_at,
                )
            try:
                result, used = _parse_adapter_result(
                    raw_result,
                    request,
                    self._adapter_binding,
                    reservation,
                )
            except BaseException as exc:
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                    recover_clock_failure=True,
                )
                return self._quarantine_in_transaction(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    "result_rejected_" + type(exc).__name__.lower(),
                    invocation_known=True,
                    settled_at=settled_at,
                )
            try:
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                )
                status = (
                    TerminalStatus.COMPLETED
                    if result["outcome"] == ActionOutcome.SUCCEEDED.value
                    else TerminalStatus.FAILED_KNOWN
                )
                terminal = self._build_terminal(
                    request=request,
                    claim=claim,
                    status=status,
                    outcome=ActionOutcome(result["outcome"]),
                    evidence=AxisStatus(result["evidence_status"]),
                    cleanup=AxisStatus(result["cleanup_status"]),
                    restoration=AxisStatus(result["restoration_status"]),
                    result_document=result,
                    charged=used,
                    reason_code="adapter_reported_" + result["outcome"],
                    settled_at=settled_at,
                    invocation_known=True,
                )
                connection.execute("SAVEPOINT action_execution_settlement")
                try:
                    settled = self._insert_terminal_and_settle(
                        connection,
                        request,
                        claim,
                        dispatch_id,
                        terminal,
                    )
                except BaseException:
                    connection.execute("ROLLBACK TO action_execution_settlement")
                    connection.execute("RELEASE action_execution_settlement")
                    raise
                connection.execute("RELEASE action_execution_settlement")
                return settled
            except BaseException:
                settled_at = self._settlement_time_in_transaction(
                    connection,
                    claim,
                    request.request_id,
                    recover_clock_failure=True,
                )
                return self._quarantine_in_transaction(
                    connection,
                    request,
                    claim,
                    dispatch_id,
                    "settlement_failure",
                    invocation_known=True,
                    settled_at=settled_at,
                )

    def reconcile_claim(
        self,
        intent: ActionExecutionReconciliationIntent,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
    ) -> ActionExecutionTerminal:
        result = self._reconcile_claim_with_health_result(
            intent,
            assertion,
            authorization,
        )
        if isinstance(result, _CommittedExecutionHealthDenial):
            raise ActionExecutionError(
                f"Target health gate denied {result.boundary}"
            )
        return result

    def _reconcile_claim_with_health_result(
        self,
        intent: ActionExecutionReconciliationIntent,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        intent = ActionExecutionReconciliationIntent.from_dict(intent.to_dict())
        if type(assertion) is not PrincipalAssertion:
            raise TypeError("assertion must be a PrincipalAssertion")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        authorization = _parse_reconciliation_authorization(authorization)
        intent_document = intent.to_dict()
        with self._store._write_connection() as connection:
            self._require_owned_current_schema_transaction(connection)
            reconciled_at = self._now()
            request, claim = self._stored_request_claim(
                connection,
                intent_document["request_id"],
            )
            reconciliation = connection.execute(
                "SELECT * FROM action_execution_reconciliations WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            terminal = self._terminal_for_request(connection, request.request_id)
            if terminal is not None:
                verify_authenticated_action_execution_store(connection)
                if (
                    reconciliation is None
                    or reconciliation["operation_intent_sha256"]
                    != intent.reconciliation_intent_sha256
                    or reconciliation["authorization_json"]
                    != _canonical_json(dict(authorization))
                    or reconciliation["assertion_issuer"] != assertion.issuer
                    or reconciliation["assertion_id"] != assertion.assertion_id
                    or reconciliation["assertion_sha256"]
                    != sha256_text(canonical_json(assertion.to_dict()))
                ):
                    raise StoreConflictError(
                        "Terminal custody is not an exact reconciliation replay"
                    )
                claim_authorization = _parse_authorization(
                    claim.to_dict()["authorization"]
                )
                self._validate_reconciliation_authorization(
                    intent,
                    assertion,
                    authorization,
                    claim_authorization,
                    reconciled_at,
                )
                expected = self._build_reconciliation_intent(
                    connection,
                    request,
                    claim,
                    reason_code=intent_document["reason_code"],
                    authority_expires_at=intent_document["authority_expires_at"],
                    prepared_at=reconciled_at,
                ).to_dict()
                for field in (
                    "tenant_id",
                    "mission_id",
                    "request_id",
                    "request_sha256",
                    "claim_id",
                    "claim_sha256",
                    "dispatch_id",
                    "dispatch_sha256",
                    "reconciliation_mode",
                    "reason_code",
                    "terminal_status",
                    "action_outcome",
                    "evidence_status",
                    "cleanup_status",
                    "restoration_status",
                    "adapter_call_count_status",
                    "adapter_call_count",
                    "charged_resources",
                    "active_plan_id",
                    "active_plan_sha256",
                    "collaboration_policy_id",
                    "collaboration_policy_sha256",
                    "scope_revocation_count",
                    "scope_revocation_head_sha256",
                    "authority_expires_at",
                ):
                    if intent_document[field] != expected[field]:
                        raise ActionExecutionError(
                            "Reconciliation replay authority is no longer current"
                        )
                self._principal_custody.verify_stored_current(
                    connection,
                    authorization,
                    ACTION_EXECUTION_RECONCILE,
                    reconciled_at,
                    receipt_id=request.to_dict()["admission_receipt"]["receipt_id"],
                )
                health_binding = self._target_health_binding_for_request(
                    connection,
                    request,
                )
                health_result = (
                    self._admission._observe_target_health_in_transaction(
                        connection,
                        binding=health_binding,
                        expected_at=reconciled_at,
                    )
                )
                if health_result.decision.status is not (
                    TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
                ):
                    return _CommittedExecutionHealthDenial(
                        "action execution reconciliation terminal replay"
                    )
                self._admission._record_target_health_use(
                    connection,
                    use_kind=(
                        ActionTargetHealthGateUseKind
                        .ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE
                    ),
                    consumer_id=terminal.terminal_id,
                    consumer_sha256=terminal.terminal_sha256,
                    binding=health_binding,
                    result=health_result,
                    used_at=reconciled_at,
                )
                return terminal
            verify_authenticated_action_execution_store(connection)
            claim_authorization = _parse_authorization(
                claim.to_dict()["authorization"]
            )
            if reconciled_at >= authorization["expires_at"]:
                raise ActionExecutionError(
                    "Reconciliation authority is not current"
                )
            if reconciled_at < claim_authorization["expires_at"]:
                raise ActionExecutionReconciliationRequired(
                    "Execution claim lease is still active"
                )
            if claim_authorization["expires_at"] > intent_document["prepared_at"]:
                raise ActionExecutionError(
                    "Reconciliation intent predates claim lease expiry"
                )
            expected = self._build_reconciliation_intent(
                connection,
                request,
                claim,
                reason_code=intent_document["reason_code"],
                authority_expires_at=intent_document["authority_expires_at"],
                prepared_at=reconciled_at,
            )
            expected_document = expected.to_dict()
            for field in (
                "tenant_id",
                "mission_id",
                "request_id",
                "request_sha256",
                "claim_id",
                "claim_sha256",
                "dispatch_id",
                "dispatch_sha256",
                "reconciliation_mode",
                "reason_code",
                "terminal_status",
                "action_outcome",
                "evidence_status",
                "cleanup_status",
                "restoration_status",
                "adapter_call_count_status",
                "adapter_call_count",
                "charged_resources",
                "active_plan_id",
                "active_plan_sha256",
                "collaboration_policy_id",
                "collaboration_policy_sha256",
                "scope_revocation_count",
                "scope_revocation_head_sha256",
                "authority_expires_at",
            ):
                if intent_document[field] != expected_document[field]:
                    raise ActionExecutionError(
                        "Reconciliation intent is not current"
                    )
            self._validate_reconciliation_authorization(
                intent,
                assertion,
                authorization,
                claim_authorization,
                reconciled_at,
            )
            reservation = self._reservation_for_request(
                connection,
                request.request_id,
            )
            charged = ExecutionResources.from_dict(
                intent_document["charged_resources"]
            )
            terminal = _build_terminal_record(
                request=request,
                claim=claim,
                status=TerminalStatus(intent_document["terminal_status"]),
                outcome=ActionOutcome(intent_document["action_outcome"]),
                evidence=AxisStatus.UNKNOWN,
                cleanup=AxisStatus.UNKNOWN,
                restoration=AxisStatus.UNKNOWN,
                result_document={
                    "reason_code": intent_document["reason_code"],
                    "trusted_result": False,
                },
                charged=charged,
                reason_code=intent_document["reason_code"],
                settled_at=max(
                    reconciled_at,
                    claim.to_dict()["claimed_at"],
                    connection.execute(
                        "SELECT updated_at FROM action_budget_account_heads WHERE "
                        "account_id = (SELECT account_id FROM "
                        "action_execution_reservations WHERE request_id = ?)",
                        (request.request_id,),
                    ).fetchone()["updated_at"],
                ),
                invocation_known=False,
                invocation_zero=(
                    intent_document["reconciliation_mode"] == "predispatch_abort"
                ),
            )
            if (
                intent_document["reconciliation_mode"]
                == "dispatched_indeterminate"
                and charged != reservation
            ):
                raise StoreIntegrityError("Reconciliation full charge is invalid")
            reconciliation_body = {
                "schema_version": 1,
                "kind": "action_execution_reconciliation",
                "intent": intent_document,
                "terminal_id": terminal.terminal_id,
                "terminal_sha256": terminal.terminal_sha256,
                "assertion_issuer": assertion.issuer,
                "assertion_id": assertion.assertion_id,
                "assertion_sha256": sha256_text(
                    canonical_json(assertion.to_dict())
                ),
                "authorization": dict(authorization),
                "reconciled_at": terminal.to_dict()["settled_at"],
            }
            reconciliation_document = _record(
                "reconciliation",
                "AXR",
                RECONCILIATION_DOMAIN,
                reconciliation_body,
            )
            self._principal_custody.consume(
                connection,
                assertion,
                authorization,
                ACTION_EXECUTION_RECONCILE,
                terminal.to_dict()["settled_at"],
                receipt_id=request.to_dict()["admission_receipt"]["receipt_id"],
                effect_document=reconciliation_document,
                effect_id=reconciliation_document["reconciliation_id"],
            )
            reconciliation_use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE "
                "mission_id = ? AND issuer = ? AND assertion_id = ?",
                (
                    intent_document["mission_id"],
                    assertion.issuer,
                    assertion.assertion_id,
                ),
            ).fetchone()
            if reconciliation_use is None:
                raise StoreIntegrityError(
                    "Reconciliation authority use was not recorded"
                )
            connection.execute(
                """
                INSERT INTO action_execution_reconciliations(
                    reconciliation_id, reconciliation_sha256, request_id,
                    request_sha256, claim_id, claim_sha256, dispatch_id,
                    dispatch_sha256, terminal_id, terminal_sha256, mission_id,
                    operation, operation_intent_sha256,
                    canonical_replay_key_sha256, assertion_issuer, assertion_id,
                    assertion_sha256, authority_use_sequence,
                    scope_revocation_count, scope_revocation_head_sha256,
                    authorization_json, reconciliation_json,
                    reconciliation_mode, reason_code, reconciled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reconciliation_document["reconciliation_id"],
                    reconciliation_document["reconciliation_sha256"],
                    request.request_id,
                    request.request_sha256,
                    claim.claim_id,
                    claim.claim_sha256,
                    intent_document["dispatch_id"],
                    intent_document["dispatch_sha256"],
                    terminal.terminal_id,
                    terminal.terminal_sha256,
                    intent_document["mission_id"],
                    ACTION_EXECUTION_RECONCILE,
                    intent.reconciliation_intent_sha256,
                    authorization["canonical_replay_key_sha256"],
                    assertion.issuer,
                    assertion.assertion_id,
                    reconciliation_document["assertion_sha256"],
                    reconciliation_use["use_sequence"],
                    intent_document["scope_revocation_count"],
                    intent_document["scope_revocation_head_sha256"],
                    _canonical_json(dict(authorization)),
                    _canonical_json(reconciliation_document),
                    intent_document["reconciliation_mode"],
                    intent_document["reason_code"],
                    terminal.to_dict()["settled_at"],
                ),
            )
            if intent_document["reconciliation_mode"] == "predispatch_abort":
                if intent_document["dispatch_sha256"] is None:
                    self._insert_predispatch_abort(
                        connection,
                        request,
                        claim,
                        intent_document["dispatch_id"],
                        intent_document["reason_code"],
                        terminal.to_dict()["settled_at"],
                    )
                else:
                    self._insert_preinvocation_abort(
                        connection,
                        request,
                        claim,
                        intent_document["dispatch_id"],
                        intent_document["reason_code"],
                        terminal.to_dict()["settled_at"],
                        health_decision=None,
                    )
            return self._insert_terminal_and_settle(
                connection,
                request,
                claim,
                intent_document["dispatch_id"],
                terminal,
                preverified=True,
            )

    def _target_health_binding_for_request(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
    ) -> ExecutionBinding:
        receipt = request.to_dict()["admission_receipt"]
        row = connection.execute(
            "SELECT request_json FROM action_admission_receipts "
            "WHERE tenant_id = ? AND mission_id = ? AND receipt_id = ? "
            "AND receipt_sha256 = ?",
            (
                receipt["tenant_id"],
                receipt["mission_id"],
                receipt["receipt_id"],
                receipt["receipt_sha256"],
            ),
        ).fetchone()
        if row is None or type(row["request_json"]) is not str:
            raise StoreIntegrityError(
                "Execution target-health admission lineage is absent"
            )
        try:
            admission_request = ActionAdmissionRequest.from_dict(
                json.loads(row["request_json"])
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError(
                "Execution target-health admission lineage is invalid"
            ) from exc
        return self._admission._target_health_binding_from_request(
            admission_request
        )

    def _validate_reconciliation_authorization(
        self,
        intent: ActionExecutionReconciliationIntent,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
        execute_authorization: Mapping[str, Any],
        checked_at: str,
    ) -> None:
        document = intent.to_dict()
        _validate_reconciliation_authorization_binding(
            intent,
            authorization,
            checked_at=checked_at,
        )
        assertion_sha256 = sha256_text(canonical_json(assertion.to_dict()))
        signed_intent = compute_operation_intent_hash(
            PrincipalOperation.ACTION_EXECUTION_RECONCILE,
            {
                "action_intent_sha256": intent.reconciliation_intent_sha256,
                "idempotency_key_sha256": authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": document["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "role": "independent_control",
            },
        )
        if (
            assertion.operation is not PrincipalOperation.ACTION_EXECUTION_RECONCILE
            or assertion.operation_intent_sha256 != signed_intent
            or assertion.issuer != authorization["assertion_issuer"]
            or assertion.assertion_id != authorization["assertion_id"]
            or assertion_sha256 != authorization["assertion_sha256"]
            or assertion.subject != authorization["principal_subject"]
            or assertion.profile_id != authorization["principal_profile_id"]
            or assertion.scope_grant_sha256 != authorization["scope_grant_sha256"]
            or assertion.issued_at != authorization["issued_at"]
            or assertion.expires_at != authorization["expires_at"]
            or authorization["principal_profile_id"]
            == execute_authorization["principal_profile_id"]
            or authorization["principal_subject"]
            == execute_authorization["principal_subject"]
        ):
            raise ActionExecutionError("Reconciliation authorization binding is invalid")

    def verify_store(self) -> dict[str, int | str]:
        with self._store._write_connection() as connection:
            return verify_authenticated_action_execution_store(connection)

    def _existing_result(
        self,
        connection: sqlite3.Connection,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        row: sqlite3.Row,
    ) -> ActionExecutionTerminal:
        if (
            row["command_sha256"] != command.command_sha256
            or row["request_sha256"] != request.request_sha256
        ):
            raise StoreConflictError(
                "Execution idempotency key is bound to different intent"
            )
        verify_authenticated_action_execution_store(connection)
        terminal = self._terminal_for_request(connection, request.request_id)
        if terminal is None:
            raise ActionExecutionReconciliationRequired(
                "Execution claim has no settlement and cannot be invoked again"
            )
        return terminal

    def _load_context(
        self,
        connection: sqlite3.Connection,
        command: ActionExecutionCommand,
        checked_at: str,
        *,
        prepared_at: str,
    ) -> _ExecutionContext:
        row = connection.execute(
            "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
            (command.receipt_id,),
        ).fetchone()
        if row is None:
            raise ActionExecutionError("Action admission receipt is absent")
        self._admission._require_not_revoked(connection, command.receipt_id)
        stored = self._admission._stored_from_row(connection, row)
        workspace_guard, high_water = (
            self._admission._transaction_review_verifier.open_local_workspace_guard(
                connection,
                stored.review_records,
            )
        )
        try:
            self._admission._verify_workspace_high_water(
                connection,
                stored.receipt,
                high_water,
            )
            self._admission._verify_central_receipt(
                connection,
                stored,
                checked_at=checked_at,
            )
            decision = evaluate_action_admission(
                stored.request,
                evaluated_at=checked_at,
            )
            if decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                raise ActionExecutionError("Action admission is not current")
            self._admission._verify_review_current(
                connection,
                stored.review_records,
            )
            current = self._admission._authority.verify_stored_current(
                connection,
                stored,
                checked_at,
            )
            self._admission._require_same_authority_state(
                stored.authority_state,
                current,
            )
            self._admission._transaction_review_verifier.verify_local_workspace_guard(
                connection,
                workspace_guard,
                stored.review_records,
                high_water,
            )
            resolution = stored.resolution.to_dict()
            admission_command = ActionAdmissionCommand(
                tenant_id=resolution["tenant_id"],
                mission_id=resolution["mission_id"],
                proposal_product_id=resolution["proposal_product_id"],
                action_type=resolution["action_type"],
                action_tier=ActionTier(resolution["action_tier"]),
                idempotency_key_sha256=resolution["idempotency_key_sha256"],
            )
            material = self._admission._authority.load_current_material(
                connection,
                admission_command,
                checked_at,
            )
            adapter = self._expected_adapter_binding(
                connection,
                resolution,
                resolution["mission_id"],
                current.authority_revision_sha256,
            )
            if adapter != self._adapter_binding:
                raise ActionExecutionError(
                    "Configured adapter differs from current catalog authority"
                )
            budget = self._execution_budget(
                connection,
                stored.receipt.receipt_id,
                checked_at,
            )
            target_document = material.target.to_dict()
            target_document = {
                field: target_document[field]
                for field in (
                    "target_id",
                    "target_sha256",
                    "target_scope_sha256",
                    "environment",
                    "authority_snapshot_sha256",
                )
            }
            adapter_input = {
                "action_sha256": resolution["action_sha256"],
                "action_type": resolution["action_type"],
                "credential_ref_sha256": material.credential_lease.credential_ref_sha256,
                "fence_token_sha256": material.worker_session.fence_token_sha256,
                "parameters": material.parameters.to_dict()["parameters"],
                "session_id": material.worker_session.session_id,
                "target": target_document,
            }
            request = self._build_request(
                command,
                stored.receipt,
                str(row["custody_sha256"]),
                resolution,
                stored.authority_state.to_dict(),
                current.authority_revision_sha256,
                adapter_input,
                budget,
                prepared_at,
            )
            return _ExecutionContext(
                request=request,
                budget=budget,
                target_health_binding=(
                    self._admission._target_health_binding_from_request(
                        stored.request
                    )
                ),
                workspace_guard=workspace_guard,
                workspace_high_water=MappingProxyType(dict(high_water)),
            )
        except BaseException:
            self._admission._transaction_review_verifier.close_local_workspace_guard(
                workspace_guard
            )
            raise

    def _expected_adapter_binding(
        self,
        connection: sqlite3.Connection,
        resolution: Mapping[str, Any],
        mission_id: str,
        authority_revision_sha256: str,
    ) -> AdapterBinding:
        row = connection.execute(
            """
            SELECT material.material_json
            FROM action_authority_source_bundles AS bundle
            JOIN action_authority_publications AS publication
              ON publication.source_bundle_id = bundle.source_bundle_id
             AND publication.source_bundle_sha256 = bundle.source_bundle_sha256
            JOIN action_authority_material_snapshots AS material
              ON material.material_snapshot_id = publication.material_snapshot_id
             AND material.material_snapshot_sha256 = publication.material_snapshot_sha256
            WHERE publication.mission_id = ?
              AND bundle.source_bundle_sha256 = ?
            """,
            (mission_id, authority_revision_sha256),
        ).fetchone()
        if row is None or type(row["material_json"]) is not str:
            raise ActionExecutionError("Current executor deployment is absent")
        material = json.loads(row["material_json"])
        action_type = str(resolution["action_type"])
        if action_type.startswith(("api.", "http.")):
            adapter_kind = "http"
        elif action_type.startswith("browser."):
            adapter_kind = "browser"
        elif action_type.startswith(("session.", "network.")):
            adapter_kind = "session"
        else:
            adapter_kind = "specialist"
        return AdapterBinding(
            adapter_id=str(resolution["tool_artifact_ref"]),
            adapter_kind=adapter_kind,
            adapter_version=str(resolution["tool_exact_version"]),
            adapter_build_sha256=str(resolution["tool_artifact_sha256"]),
            deployment_binding_sha256=str(
                material["executor_deployment_sha256"]
            ),
        )

    def _execution_budget(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
        checked_at: str,
    ) -> ExecutionBudget:
        link = connection.execute(
            "SELECT reservation.*, account.tenant_id, account.mission_id, "
            "account.budget_id FROM action_budget_receipt_reservations AS reservation "
            "JOIN action_budget_accounts AS account "
            "ON account.account_id = reservation.account_id "
            "WHERE reservation.receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if link is None or type(link["resources_json"]) is not str:
            raise StoreIntegrityError("Action admission reservation is absent")
        resources = json.loads(link["resources_json"])
        reservation = ExecutionResources.from_dict(resources)
        _account, revision, usage = _current_budget_state(
            connection,
            tenant_id=str(link["tenant_id"]),
            mission_id=str(link["mission_id"]),
            expected_revision_sha256=str(link["budget_revision_sha256"]),
            checked_at=checked_at,
        )
        used = {
            field: usage[field] - resources[field] for field in RESOURCE_FIELDS
        }
        if any(value < 0 for value in used.values()):
            raise StoreIntegrityError("Action budget usage is not conserved")
        return ExecutionBudget(
            budget_id=str(link["budget_id"]),
            budget_sha256=str(link["budget_revision_sha256"]),
            limits=ExecutionResources.from_dict(revision["limits"]),
            used=ExecutionResources.from_dict(used),
            reservation=reservation,
        )

    def _build_request(
        self,
        command: ActionExecutionCommand,
        receipt: Any,
        custody_sha256: str,
        resolution: Mapping[str, Any],
        admission_authority_state: Mapping[str, Any],
        authority_revision_sha256: str,
        adapter_input: Mapping[str, Any],
        budget: ExecutionBudget,
        prepared_at: str,
    ) -> ActionExecutionRequest:
        receipt_document = receipt.to_dict()
        checks = {name: True for name in AUTHORITY_CHECKS}
        state = CurrentExecutionAuthorityState(
            tenant_id=receipt_document["tenant_id"],
            mission_id=receipt_document["mission_id"],
            plan_id=resolution["plan_id"],
            scope_sha256=receipt_document["scope_sha256"],
            target_sha256=receipt_document["target_sha256"],
            action_sha256=receipt_document["action_sha256"],
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt.receipt_sha256,
            review_evidence_sha256=admission_authority_state[
                "review_evidence_sha256"
            ],
            catalog_id=admission_authority_state["catalog_id"],
            catalog_sha256=admission_authority_state["catalog_sha256"],
            catalog_version=admission_authority_state["catalog_version"],
            catalog_authority_sha256=admission_authority_state[
                "catalog_authority_sha256"
            ],
            authority_revision_sha256=authority_revision_sha256,
            checks=checks,
        )
        adapter_document = _document(adapter_input, "adapter input")
        _reject_secret_material(adapter_document, "adapter input")
        body = {
            "schema_version": 1,
            "kind": "action_execution_request",
            "command_sha256": command.command_sha256,
            "idempotency_key_sha256": command.idempotency_key_sha256,
            "admission_receipt": receipt_document,
            "admission_custody_sha256": custody_sha256,
            "authority_state": state.to_dict(),
            "authority_state_sha256": state.state_sha256,
            "adapter": self._adapter_binding.to_dict(),
            "adapter_input": adapter_document,
            "adapter_input_sha256": _canonical_sha256(
                {"adapter_input": adapter_document, "domain": INPUT_DOMAIN}
            ),
            "budget_id": budget.budget_id,
            "budget_sha256": budget.budget_sha256,
            "reservation": budget.reservation.to_dict(),
            "prepared_at": prepared_at,
            "execution_status": "reserved_pending_adapter",
        }
        return parse_action_execution_request(
            _record(
                "action_execution_request",
                "AXR",
                "sunderkey.authenticated-action-execution-request.v1",
                body,
            )
        )

    @staticmethod
    def _validate_authorization(
        request: ActionExecutionRequest,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
        intent: str,
        checked_at: str,
    ) -> None:
        document = request.to_dict()
        receipt = document["admission_receipt"]
        state = document["authority_state"]
        expected = {
            "action_sha256": state["action_sha256"],
            "mission_id": state["mission_id"],
            "operation_intent_sha256": intent,
            "receipt_sha256": receipt["receipt_sha256"],
            "request_sha256": request.request_sha256,
            "scope_sha256": state["scope_sha256"],
            "target_sha256": state["target_sha256"],
            "tenant_id": state["tenant_id"],
        }
        if any(authorization[field] != value for field, value in expected.items()):
            raise ActionExecutionError("ACTION_EXECUTE authorization binding is invalid")
        if not authorization["issued_at"] <= checked_at < authorization["expires_at"]:
            raise ActionExecutionError("ACTION_EXECUTE authorization is not current")
        signed_intent = compute_operation_intent_hash(
            PrincipalOperation.ACTION_EXECUTE,
            {
                "action_intent_sha256": intent,
                "idempotency_key_sha256": authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "role": authorization["role"],
            },
        )
        if (
            assertion.operation is not PrincipalOperation.ACTION_EXECUTE
            or assertion.operation_intent_sha256 != signed_intent
            or assertion.issuer != authorization["assertion_issuer"]
            or assertion.assertion_id != authorization["assertion_id"]
            or sha256_text(canonical_json(assertion.to_dict()))
            != authorization["assertion_sha256"]
        ):
            raise ActionExecutionError("Signed ACTION_EXECUTE assertion is substituted")

    @staticmethod
    def _build_claim(
        request: ActionExecutionRequest,
        authorization: Mapping[str, Any],
        claimed_at: str,
    ) -> ActionExecutionClaim:
        body = {
            "schema_version": 1,
            "kind": "action_execution_claim",
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "authorization": dict(authorization),
            "claimed_at": claimed_at,
            "claim_status": "claimed_pending_dispatch",
        }
        return parse_action_execution_claim(
            _record(
                "action_execution_claim",
                "AXC",
                "sunderkey.authenticated-action-execution-claim.v1",
                body,
            )
        )

    @staticmethod
    def _insert_request(
        connection: sqlite3.Connection,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
    ) -> None:
        request_document = request.to_dict()
        claim_document = claim.to_dict()
        receipt = request_document["admission_receipt"]
        custody = {
            "claim": claim_document,
            "command": command.to_dict(),
            "command_sha256": command.command_sha256,
            "request": request_document,
        }
        custody_sha256 = _canonical_sha256(
            {"custody": custody, "domain": CUSTODY_DOMAIN}
        )
        connection.execute(
            """
            INSERT INTO action_execution_requests(
                request_id, request_sha256, tenant_id, mission_id,
                receipt_id, receipt_sha256, idempotency_key_sha256,
                command_sha256, request_json, custody_sha256,
                authority_state_sha256, prepared_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.request_id,
                request.request_sha256,
                receipt["tenant_id"],
                receipt["mission_id"],
                receipt["receipt_id"],
                receipt["receipt_sha256"],
                command.idempotency_key_sha256,
                command.command_sha256,
                _canonical_json(request_document),
                custody_sha256,
                request_document["authority_state_sha256"],
                request_document["prepared_at"],
            ),
        )

    @staticmethod
    def _insert_claim(
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        authorization: Mapping[str, Any],
        checkpoint_id: str,
        checkpoint_sha256: str,
    ) -> None:
        claim_document = claim.to_dict()
        custody_sha256 = _canonical_sha256(
            {
                "custody": {
                    "authority_checkpoint_id": checkpoint_id,
                    "authority_checkpoint_sha256": checkpoint_sha256,
                    "claim": claim_document,
                    "dispatch_id": dispatch_id,
                    "request_id": request.request_id,
                    "request_sha256": request.request_sha256,
                },
                "domain": CLAIM_CUSTODY_DOMAIN,
            }
        )
        connection.execute(
            """
            INSERT INTO action_execution_claims(
                claim_id, claim_sha256, request_id, dispatch_id,
                authorization_json, claim_json, authority_checkpoint_id,
                authority_checkpoint_sha256, custody_sha256, claimed_at,
                claim_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                claim.claim_id,
                claim.claim_sha256,
                request.request_id,
                dispatch_id,
                _canonical_json(dict(authorization)),
                _canonical_json(claim_document),
                checkpoint_id,
                checkpoint_sha256,
                custody_sha256,
                claim_document["claimed_at"],
                claim_document["claim_status"],
            ),
        )

    @staticmethod
    def _insert_authority_consumption(
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        authorization: Mapping[str, Any],
        consumed_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO action_execution_authority_consumptions(
                assertion_issuer, assertion_id, mission_id, assertion_sha256,
                canonical_replay_key_sha256, operation,
                operation_intent_sha256, request_id, authorization_json,
                consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                authorization["mission_id"],
                authorization["assertion_sha256"],
                authorization["canonical_replay_key_sha256"],
                ACTION_EXECUTE,
                authorization["operation_intent_sha256"],
                request.request_id,
                _canonical_json(dict(authorization)),
                consumed_at,
            ),
        )

    @staticmethod
    def _insert_reservation(
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        budget: ExecutionBudget,
        reserved_at: str,
    ) -> None:
        receipt_id = request.to_dict()["admission_receipt"]["receipt_id"]
        link = connection.execute(
            "SELECT * FROM action_budget_receipt_reservations WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if link is None or type(link["resources_json"]) is not str:
            raise StoreIntegrityError("Action budget reservation link is absent")
        resources = json.loads(link["resources_json"])
        if resources != budget.reservation.to_dict():
            raise StoreIntegrityError("Execution reservation differs from admission")
        connection.execute(
            """
            INSERT INTO action_execution_reservations(
                request_id, receipt_id, account_id, budget_revision_id,
                budget_revision_sha256, reservation_id, reservation_sha256,
                money_microunits, rate_units, request_bytes, response_bytes,
                duration_ms, impact_events, reserved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.request_id,
                receipt_id,
                link["account_id"],
                link["budget_revision_id"],
                link["budget_revision_sha256"],
                link["reservation_id"],
                link["reservation_sha256"],
                *(resources[field] for field in RESOURCE_FIELDS),
                reserved_at,
            ),
        )

    def _seal_dispatch(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
    ) -> SealedActionDispatch:
        material = self._dispatch_proof_material(
            request,
            claim,
            dispatch_id,
        )
        return SealedActionDispatch(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            claim_id=claim.claim_id,
            claim_sha256=claim.claim_sha256,
            dispatch_id=dispatch_id,
            _proof=hmac.new(
                self._dispatch_proof_key,
                material,
                hashlib.sha256,
            ).digest(),
        )

    def _dispatch_proof_material(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
    ) -> bytes:
        return _canonical_json(
            {
                "adapter_binding_sha256": _adapter_binding_sha256(
                    self._adapter_binding
                ),
                "claim_id": claim.claim_id,
                "claim_sha256": claim.claim_sha256,
                "dispatch_id": dispatch_id,
                "domain": DISPATCH_PROOF_DOMAIN,
                "request_id": request.request_id,
                "request_sha256": request.request_sha256,
            }
        ).encode("ascii")

    def _commit_dispatch_attempt(
        self,
        command: ActionExecutionCommand,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch: SealedActionDispatch,
    ) -> _CommittedExecutionHealthDenial | None:
        self._require_adapter_binding()
        expected = hmac.new(
            self._dispatch_proof_key,
            self._dispatch_proof_material(request, claim, dispatch.dispatch_id),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(dispatch._proof, expected):
            raise ActionExecutionError("Process-local dispatch proof is invalid")
        context: _ExecutionContext | None = None
        try:
            with self._store._write_connection() as connection:
                transaction_time = self._admission._seal_execution_transaction_time()
                checked_at = transaction_time.checked_at
                if connection.execute(
                    "SELECT 1 FROM action_execution_terminals WHERE request_id = ? "
                    "UNION ALL SELECT 1 FROM action_execution_closures "
                    "WHERE request_id = ? UNION ALL SELECT 1 FROM "
                    "action_execution_predispatch_aborts WHERE request_id = ? LIMIT 1",
                    (request.request_id, request.request_id, request.request_id),
                ).fetchone() is not None:
                    raise ActionExecutionReconciliationRequired(
                        "Execution was terminalized before dispatch"
                    )
                if connection.execute(
                    "SELECT 1 FROM action_execution_dispatch_attempts "
                    "WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone() is not None:
                    raise ActionExecutionReconciliationRequired(
                        "Dispatch attempt already exists and cannot be repeated"
                    )
                context = self._load_context(
                    connection,
                    command,
                    checked_at,
                    prepared_at=request.to_dict()["prepared_at"],
                )
                if context.request.document_json != request.document_json:
                    raise ActionExecutionError("Final execution authority changed")
                authority = connection.execute(
                    "SELECT authorization_json FROM "
                    "action_execution_authority_consumptions WHERE request_id = ?",
                    (request.request_id,),
                ).fetchone()
                if authority is None or type(authority["authorization_json"]) is not str:
                    raise StoreIntegrityError("Execution authority consumption is absent")
                stored_authorization = _parse_authorization(
                    json.loads(authority["authorization_json"])
                )
                self._principal_custody.verify_stored_current(
                    connection,
                    stored_authorization,
                    ACTION_EXECUTE,
                    checked_at,
                    receipt_id=command.receipt_id,
                )
                self._admission._consume_for_execution_in_transaction(
                    connection,
                    receipt_id=command.receipt_id,
                    execution_id=request.request_id,
                    execution_intent_sha256=(
                        action_execute_authorization_intent_sha256(request)
                    ),
                    claim_id=claim.claim_id,
                    claim_sha256=claim.claim_sha256,
                    consumed_at=checked_at,
                    workspace_connection=context.workspace_guard,
                    workspace_high_water=context.workspace_high_water,
                    _transaction_time=transaction_time,
                )
                health_result = (
                    self._admission._observe_target_health_in_transaction(
                        connection,
                        binding=context.target_health_binding,
                        expected_at=checked_at,
                    )
                )
                if health_result.decision.status is not (
                    TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
                ):
                    return _CommittedExecutionHealthDenial(
                        "action execution dispatch",
                        health_result.decision.head.updated_at,
                    )
                authority_high_water = _capture_authority_high_water(
                    connection,
                    request,
                    stored_authorization,
                )
                authority_high_water_sha256 = _authority_high_water_sha256(
                    authority_high_water
                )
                checkpoint_id, checkpoint_sha256 = _insert_authority_checkpoint(
                    connection,
                    checkpoint_kind="dispatch",
                    request=request,
                    claim=claim,
                    high_water=authority_high_water,
                    captured_at=checked_at,
                )
                body = {
                    "schema_version": 1,
                    "kind": "action_execution_dispatch_attempt",
                    "dispatch_id": dispatch.dispatch_id,
                    "request_id": request.request_id,
                    "request_sha256": request.request_sha256,
                    "claim_id": claim.claim_id,
                    "claim_sha256": claim.claim_sha256,
                    "adapter_binding_sha256": _adapter_binding_sha256(
                        self._adapter_binding
                    ),
                    "authority_checkpoint_id": checkpoint_id,
                    "authority_checkpoint_sha256": checkpoint_sha256,
                    "authority_high_water": authority_high_water,
                    "authority_high_water_sha256": authority_high_water_sha256,
                    "attempted_at": checked_at,
                    "attempt_status": "dispatch_committed_single_attempt",
                }
                dispatch_sha256 = _canonical_sha256(
                    {"domain": DISPATCH_DOMAIN, "record": body}
                )
                connection.execute(
                    """
                    INSERT INTO action_execution_dispatch_attempts(
                        dispatch_id, dispatch_sha256, request_id, claim_id,
                        adapter_binding_sha256, authority_checkpoint_id,
                        authority_checkpoint_sha256, dispatch_json,
                        authority_high_water_json, authority_high_water_sha256,
                        attempted_at, attempt_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dispatch.dispatch_id,
                        dispatch_sha256,
                        request.request_id,
                        claim.claim_id,
                        body["adapter_binding_sha256"],
                        checkpoint_id,
                        checkpoint_sha256,
                        _canonical_json(body),
                        _canonical_json(authority_high_water),
                        authority_high_water_sha256,
                        checked_at,
                        body["attempt_status"],
                    ),
                )
                self._admission._record_target_health_use(
                    connection,
                    use_kind=(
                        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH
                    ),
                    consumer_id=dispatch.dispatch_id,
                    consumer_sha256=dispatch_sha256,
                    binding=context.target_health_binding,
                    result=health_result,
                    used_at=checked_at,
                )
                verify_authenticated_action_execution_store(connection)
                return None
        finally:
            if context is not None:
                self._admission._transaction_review_verifier.close_local_workspace_guard(
                    context.workspace_guard
                )

    @staticmethod
    def _build_terminal(
        *,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        status: TerminalStatus,
        outcome: ActionOutcome,
        evidence: AxisStatus,
        cleanup: AxisStatus,
        restoration: AxisStatus,
        result_document: Mapping[str, Any],
        charged: ExecutionResources,
        reason_code: str,
        settled_at: str,
        invocation_known: bool,
    ) -> ActionExecutionTerminal:
        return _build_terminal_record(
            request=request,
            claim=claim,
            status=status,
            outcome=outcome,
            evidence=evidence,
            cleanup=cleanup,
            restoration=restoration,
            result_document=result_document,
            charged=charged,
            reason_code=reason_code,
            settled_at=settled_at,
            invocation_known=invocation_known,
        )

    def _quarantine(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        reason_code: str,
        *,
        invocation_known: bool,
        invocation_zero: bool = False,
        minimum_settlement_at: str | None = None,
        force_zero_invocation_abort: bool = False,
        health_decision: tuple[str, str, str] | None = None,
        invocation_use: tuple[str, str] | None = None,
        exact_settlement_at: str | None = None,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        with self._store._write_connection() as connection:
            dispatch = connection.execute(
                "SELECT attempted_at FROM action_execution_dispatch_attempts "
                "WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            budget_head = connection.execute(
                "SELECT h.updated_at FROM action_execution_reservations r "
                "JOIN action_budget_account_heads h ON h.account_id = r.account_id "
                "WHERE r.request_id = ?",
                (request.request_id,),
            ).fetchone()
            durable_floor = max(
                claim.to_dict()["claimed_at"],
                *([dispatch["attempted_at"]] if dispatch is not None else []),
                *([budget_head["updated_at"]] if budget_head is not None else []),
                *(
                    []
                    if minimum_settlement_at is None
                    else [minimum_settlement_at]
                ),
            )
            if exact_settlement_at is not None:
                if exact_settlement_at < durable_floor:
                    raise StoreIntegrityError(
                        "Exact execution settlement precedes durable custody"
                    )
                settled_at = exact_settlement_at
            else:
                try:
                    settled_at = max(self._now(), durable_floor)
                except BaseException:
                    settled_at = durable_floor
            return self._quarantine_in_transaction(
                connection,
                request,
                claim,
                dispatch_id,
                reason_code,
                invocation_known=invocation_known if dispatch is not None else False,
                invocation_zero=invocation_zero if dispatch is not None else True,
                settled_at=settled_at,
                force_zero_invocation_abort=force_zero_invocation_abort,
                health_decision=health_decision,
                invocation_use=invocation_use,
            )

    def _quarantine_in_transaction(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        reason_code: str,
        *,
        invocation_known: bool,
        invocation_zero: bool = False,
        settled_at: str,
        force_zero_invocation_abort: bool = False,
        health_decision: tuple[str, str, str] | None = None,
        invocation_use: tuple[str, str] | None = None,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        self._require_owned_current_schema_transaction(connection)
        existing = self._terminal_for_request(connection, request.request_id)
        if existing is not None:
            return self._terminal_replay_for_use_in_transaction(
                connection,
                request,
                existing,
                boundary="action execution quarantine terminal replay",
            )
        reservation = self._reservation_for_request(
            connection,
            request.request_id,
        )
        dispatch = connection.execute(
            "SELECT 1 FROM action_execution_dispatch_attempts WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        verify_authenticated_action_execution_store(connection)
        zero_call_abort = dispatch is None or force_zero_invocation_abort
        if dispatch is None:
            self._insert_predispatch_abort(
                connection,
                request,
                claim,
                dispatch_id,
                reason_code,
                settled_at,
            )
        elif force_zero_invocation_abort:
            self._insert_preinvocation_abort(
                connection,
                request,
                claim,
                dispatch_id,
                reason_code,
                settled_at,
                health_decision=health_decision,
                invocation_use=invocation_use,
            )
        terminal = _build_terminal_record(
            request=request,
            claim=claim,
            status=(
                TerminalStatus.PREDISPATCH_ABORTED
                if zero_call_abort
                else TerminalStatus.INDETERMINATE_QUARANTINED
            ),
            outcome=(
                ActionOutcome.FAILED
                if zero_call_abort
                else ActionOutcome.INDETERMINATE
            ),
            evidence=AxisStatus.UNKNOWN,
            cleanup=AxisStatus.UNKNOWN,
            restoration=AxisStatus.UNKNOWN,
            result_document={
                "reason_code": reason_code,
                "trusted_result": False,
            },
            charged=(
                ExecutionResources(**{field: 0 for field in RESOURCE_FIELDS})
                if zero_call_abort
                else reservation
            ),
            reason_code=reason_code,
            settled_at=settled_at,
            invocation_known=invocation_known,
            invocation_zero=invocation_zero,
        )
        return self._insert_terminal_and_settle(
            connection,
            request,
            claim,
            dispatch_id,
            terminal,
            preverified=True,
        )

    def _insert_predispatch_abort(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        reason_code: str,
        aborted_at: str,
    ) -> None:
        self._require_owned_current_schema_transaction(connection)
        request_document = request.to_dict()
        receipt = request_document["admission_receipt"]
        authority = connection.execute(
            "SELECT * FROM action_execution_authority_consumptions "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if authority is None:
            raise StoreIntegrityError("Execution authority consumption is absent")
        body = {
            "schema_version": 1,
            "kind": "action_execution_predispatch_abort",
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "claim_id": claim.claim_id,
            "claim_sha256": claim.claim_sha256,
            "dispatch_id": dispatch_id,
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "assertion_issuer": authority["assertion_issuer"],
            "assertion_id": authority["assertion_id"],
            "assertion_sha256": authority["assertion_sha256"],
            "reason_code": reason_code,
            "aborted_at": aborted_at,
            "abort_status": "authenticated_no_dispatch_release",
        }
        digest = _canonical_sha256(
            {"domain": PREDISPATCH_ABORT_DOMAIN, "record": body}
        )
        abort_id = "AXA-" + digest.removeprefix("sha256:")[:32].upper()
        connection.execute(
            """
            INSERT INTO action_execution_predispatch_aborts(
                abort_id, abort_sha256, request_id, request_sha256,
                claim_id, claim_sha256, dispatch_id, receipt_id,
                receipt_sha256, assertion_issuer, assertion_id,
                assertion_sha256, reason_code, abort_json, aborted_at,
                abort_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                abort_id,
                digest,
                request.request_id,
                request.request_sha256,
                claim.claim_id,
                claim.claim_sha256,
                dispatch_id,
                receipt["receipt_id"],
                receipt["receipt_sha256"],
                authority["assertion_issuer"],
                authority["assertion_id"],
                authority["assertion_sha256"],
                reason_code,
                _canonical_json(body),
                aborted_at,
                body["abort_status"],
            ),
        )

    def _insert_preinvocation_abort(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        reason_code: str,
        aborted_at: str,
        *,
        health_decision: tuple[str, str, str] | None,
        invocation_use: tuple[str, str] | None = None,
    ) -> None:
        self._require_owned_current_schema_transaction(connection)
        dispatch = connection.execute(
            "SELECT dispatch_sha256 FROM action_execution_dispatch_attempts "
            "WHERE request_id = ? AND dispatch_id = ?",
            (request.request_id, dispatch_id),
        ).fetchone()
        if dispatch is None:
            raise StoreIntegrityError(
                "Preinvocation abort requires committed dispatch custody"
            )
        if health_decision is not None and (
            type(health_decision) is not tuple
            or len(health_decision) != 3
            or any(type(item) is not str or not item for item in health_decision)
        ):
            raise TypeError("health_decision must be an exact identity pair")
        if invocation_use is not None and (
            type(invocation_use) is not tuple
            or len(invocation_use) != 2
            or any(type(item) is not str or not item for item in invocation_use)
        ):
            raise TypeError("invocation_use must be an exact identity pair")
        if invocation_use is not None and health_decision is None:
            raise StoreIntegrityError(
                "Preinvocation abort invocation decision lineage is incomplete"
            )
        body = {
            "schema_version": 1,
            "kind": "action_execution_preinvocation_abort",
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "claim_id": claim.claim_id,
            "claim_sha256": claim.claim_sha256,
            "dispatch_id": dispatch_id,
            "dispatch_sha256": dispatch["dispatch_sha256"],
            "invocation_use_id": (
                None if invocation_use is None else invocation_use[0]
            ),
            "invocation_use_sha256": (
                None if invocation_use is None else invocation_use[1]
            ),
            "health_decision_id": (
                None if health_decision is None else health_decision[0]
            ),
            "health_decision_sha256": (
                None if health_decision is None else health_decision[1]
            ),
            "health_decision_json": (
                None if health_decision is None else health_decision[2]
            ),
            "reason_code": reason_code,
            "aborted_at": aborted_at,
            "abort_status": (
                "authenticated_postdispatch_preinvocation_release"
            ),
        }
        digest = _canonical_sha256(
            {"domain": PREINVOCATION_ABORT_DOMAIN, "record": body}
        )
        abort_id = "AXN-" + digest.removeprefix("sha256:")[:32].upper()
        document = {**body, "abort_id": abort_id, "abort_sha256": digest}
        connection.execute(
            """
            INSERT INTO action_execution_preinvocation_aborts(
                abort_id, abort_sha256, request_id, request_sha256,
                claim_id, claim_sha256, dispatch_id, dispatch_sha256,
                invocation_use_id, invocation_use_sha256,
                health_decision_id, health_decision_sha256,
                health_decision_json, reason_code, abort_json, aborted_at,
                abort_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                abort_id,
                digest,
                request.request_id,
                request.request_sha256,
                claim.claim_id,
                claim.claim_sha256,
                dispatch_id,
                dispatch["dispatch_sha256"],
                document["invocation_use_id"],
                document["invocation_use_sha256"],
                document["health_decision_id"],
                document["health_decision_sha256"],
                document["health_decision_json"],
                reason_code,
                _canonical_json(document),
                aborted_at,
                document["abort_status"],
            ),
        )

    def _settle(
        self,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        terminal: ActionExecutionTerminal,
    ) -> ActionExecutionTerminal | _CommittedExecutionHealthDenial:
        with self._store._write_connection() as connection:
            existing = self._terminal_for_request(connection, request.request_id)
            if existing is not None:
                if existing.document_json != terminal.document_json:
                    raise StoreConflictError(
                        "Execution has a different terminal settlement"
                    )
                return self._terminal_replay_for_use_in_transaction(
                    connection,
                    request,
                    existing,
                    boundary="action execution settlement terminal replay",
                )
            return self._insert_terminal_and_settle(
                connection,
                request,
                claim,
                dispatch_id,
                terminal,
            )

    def _insert_terminal_and_settle(
        self,
        connection: sqlite3.Connection,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        dispatch_id: str,
        terminal: ActionExecutionTerminal,
        *,
        preverified: bool = False,
    ) -> ActionExecutionTerminal:
        self._require_owned_current_schema_transaction(connection)
        if type(preverified) is not bool:
            raise TypeError("preverified must be an exact bool")
        if not preverified:
            verify_authenticated_action_execution_store(connection)
        request_row = connection.execute(
            "SELECT request_sha256, request_json FROM action_execution_requests "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        claim_row = connection.execute(
            "SELECT request_id, claim_sha256, claim_json, dispatch_id "
            "FROM action_execution_claims WHERE claim_id = ?",
            (claim.claim_id,),
        ).fetchone()
        dispatch = connection.execute(
            "SELECT dispatch_id FROM action_execution_dispatch_attempts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        abort = connection.execute(
            "SELECT dispatch_id FROM action_execution_predispatch_aborts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        preinvocation_abort = connection.execute(
            "SELECT * FROM action_execution_preinvocation_aborts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if abort is not None and preinvocation_abort is not None:
            raise StoreIntegrityError("Execution has conflicting abort custody")
        if abort is not None and dispatch is not None:
            raise StoreIntegrityError(
                "Predispatch abort conflicts with committed dispatch custody"
            )
        if preinvocation_abort is not None and dispatch is None:
            raise StoreIntegrityError(
                "Preinvocation abort lacks committed dispatch custody"
            )
        if (
            request_row is None
            or claim_row is None
            or request_row["request_sha256"] != request.request_sha256
            or request_row["request_json"] != _canonical_json(request.to_dict())
            or claim_row["request_id"] != request.request_id
            or claim_row["claim_sha256"] != claim.claim_sha256
            or claim_row["claim_json"] != _canonical_json(claim.to_dict())
            or claim_row["dispatch_id"] != dispatch_id
            or (dispatch is None and abort is None)
            or (dispatch is not None and dispatch["dispatch_id"] != dispatch_id)
            or (abort is not None and abort["dispatch_id"] != dispatch_id)
            or abort is not None and preinvocation_abort is not None
            or preinvocation_abort is not None
            and (
                dispatch is None
                or preinvocation_abort["dispatch_id"] != dispatch_id
            )
        ):
            raise StoreIntegrityError("Execution terminal preinsert lineage is invalid")
        document = terminal.to_dict()
        charged = ExecutionResources.from_dict(document["charged_resources"])
        reservation = self._reservation_for_request(
            connection,
            request.request_id,
        )
        if any(
            getattr(charged, field) > getattr(reservation, field)
            for field in RESOURCE_FIELDS
        ):
            raise StoreIntegrityError("Terminal charge exceeds reservation")
        connection.execute(
            """
            INSERT INTO action_execution_terminals(
                terminal_id, terminal_sha256, request_id, claim_id,
                dispatch_id, terminal_status, terminal_json,
                money_charged_microunits, rate_units_charged,
                request_bytes_charged, response_bytes_charged,
                duration_ms_charged, impact_events_charged, settled_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                terminal.terminal_id,
                terminal.terminal_sha256,
                request.request_id,
                claim.claim_id,
                dispatch_id,
                document["terminal_status"],
                _canonical_json(document),
                *(document["charged_resources"][field] for field in RESOURCE_FIELDS),
                document["settled_at"],
            ),
        )
        closure = _closure_document(terminal)
        connection.execute(
            """
            INSERT INTO action_execution_closures(
                closure_id, closure_sha256, request_id, terminal_id,
                action_outcome, evidence_status, cleanup_status,
                restoration_status, closure_json, closed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                closure["closure_id"],
                closure["closure_sha256"],
                request.request_id,
                terminal.terminal_id,
                closure["action_outcome"],
                closure["evidence_status"],
                closure["cleanup_status"],
                closure["restoration_status"],
                _canonical_json(closure),
                closure["closed_at"],
            ),
        )
        self._append_authenticated_terminal_budget_events(
            connection,
            request=request,
            claim=claim,
            terminal=terminal,
            charged_resources=charged.to_dict(),
            dispatch_id=dispatch_id,
            recorded_at=document["settled_at"],
            release_only=(
                abort is not None or preinvocation_abort is not None
            ),
        )
        verify_authenticated_action_execution_store(connection)
        return terminal

    def _append_authenticated_terminal_budget_events(
        self,
        connection: sqlite3.Connection,
        *,
        request: ActionExecutionRequest,
        claim: ActionExecutionClaim,
        terminal: ActionExecutionTerminal,
        charged_resources: Mapping[str, Any],
        dispatch_id: str,
        recorded_at: str,
        release_only: bool,
    ) -> tuple[str, ...]:
        """Settle one schema34 execution after reconstructing its durable lineage."""

        self._require_owned_current_schema_transaction(connection)
        request_document = request.to_dict()
        claim_document = claim.to_dict()
        terminal_document = terminal.to_dict()
        receipt = request_document["admission_receipt"]
        rows = {
            "request": connection.execute(
                "SELECT * FROM action_execution_requests WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "claim": connection.execute(
                "SELECT * FROM action_execution_claims WHERE claim_id = ?",
                (claim.claim_id,),
            ).fetchone(),
            "authority": connection.execute(
                "SELECT * FROM action_execution_authority_consumptions "
                "WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "admission": connection.execute(
                "SELECT * FROM action_admission_execution_consumptions "
                "WHERE receipt_id = ?",
                (receipt["receipt_id"],),
            ).fetchone(),
            "reservation": connection.execute(
                "SELECT * FROM action_execution_reservations WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "link": connection.execute(
                "SELECT * FROM action_budget_receipt_reservations WHERE receipt_id = ?",
                (receipt["receipt_id"],),
            ).fetchone(),
            "receipt": connection.execute(
                "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt["receipt_id"],),
            ).fetchone(),
            "dispatch": connection.execute(
                "SELECT * FROM action_execution_dispatch_attempts WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "abort": connection.execute(
                "SELECT * FROM action_execution_predispatch_aborts WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "preinvocation_abort": connection.execute(
                "SELECT * FROM action_execution_preinvocation_aborts "
                "WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
            "terminal": connection.execute(
                "SELECT * FROM action_execution_terminals WHERE terminal_id = ?",
                (terminal.terminal_id,),
            ).fetchone(),
            "closure": connection.execute(
                "SELECT * FROM action_execution_closures WHERE request_id = ?",
                (request.request_id,),
            ).fetchone(),
        }
        if any(
            rows[name] is None
            for name in (
                "request",
                "claim",
                "authority",
                "admission",
                "reservation",
                "link",
                "receipt",
                "terminal",
                "closure",
            )
        ):
            raise StoreIntegrityError("Execution terminal lineage is incomplete")
        if rows["abort"] is not None and rows["dispatch"] is not None:
            raise StoreIntegrityError(
                "Predispatch abort conflicts with committed dispatch custody"
            )
        if (
            rows["abort"] is not None
            and rows["preinvocation_abort"] is not None
        ):
            raise StoreIntegrityError("Execution has conflicting abort custody")
        if (
            rows["preinvocation_abort"] is not None
            and rows["dispatch"] is None
        ):
            raise StoreIntegrityError(
                "Preinvocation abort lacks committed dispatch custody"
            )
        if rows["dispatch"] is None and rows["abort"] is None:
            raise StoreIntegrityError(
                "Execution terminal requires exactly one dispatch or predispatch abort"
            )
        if release_only != (
            rows["abort"] is not None
            or rows["preinvocation_abort"] is not None
        ):
            raise StoreIntegrityError("Execution budget terminal mode is substituted")
        request_row = rows["request"]
        claim_row = rows["claim"]
        authority = rows["authority"]
        admission = rows["admission"]
        reservation = rows["reservation"]
        link = rows["link"]
        receipt_row = rows["receipt"]
        terminal_row = rows["terminal"]
        closure_row = rows["closure"]
        expected_closure = _closure_document(terminal)
        if (
            request_row["request_sha256"] != request.request_sha256
            or request_row["request_json"] != _canonical_json(request_document)
            or request_row["receipt_id"] != receipt["receipt_id"]
            or request_row["receipt_sha256"] != receipt["receipt_sha256"]
            or receipt_row["receipt_sha256"] != receipt["receipt_sha256"]
            or receipt_row["receipt_json"] != _canonical_json(receipt)
            or receipt_row["custody_sha256"]
            != request_document["admission_custody_sha256"]
            or json.loads(receipt_row["authority_state_json"])[
                "authority_revision_sha256"
            ]
            != request_document["authority_state"]["authority_revision_sha256"]
            or claim_row["request_id"] != request.request_id
            or claim_row["claim_sha256"] != claim.claim_sha256
            or claim_row["claim_json"] != _canonical_json(claim_document)
            or claim_row["dispatch_id"] != dispatch_id
            or authority["request_id"] != request.request_id
            or authority["consumed_at"] != claim_document["claimed_at"]
            or admission["receipt_id"] != receipt["receipt_id"]
            or admission["execution_id"] != request.request_id
            or admission["execution_intent_sha256"]
            != action_execute_authorization_intent_sha256(request)
            or admission["claim_id"] != claim.claim_id
            or admission["claim_sha256"] != claim.claim_sha256
            or admission["consumed_at"] != claim_document["claimed_at"]
            or reservation["receipt_id"] != receipt["receipt_id"]
            or reservation["account_id"] != link["account_id"]
            or reservation["reservation_id"] != link["reservation_id"]
            or reservation["reservation_sha256"] != link["reservation_sha256"]
            or reservation["budget_revision_id"] != link["budget_revision_id"]
            or reservation["budget_revision_sha256"]
            != link["budget_revision_sha256"]
            or terminal_row["request_id"] != request.request_id
            or terminal_row["claim_id"] != claim.claim_id
            or terminal_row["dispatch_id"] != dispatch_id
            or terminal_row["terminal_sha256"] != terminal.terminal_sha256
            or terminal_row["terminal_json"] != _canonical_json(terminal_document)
            or terminal_row["settled_at"] != recorded_at
            or closure_row["terminal_id"] != terminal.terminal_id
            or closure_row["closure_json"] != _canonical_json(expected_closure)
        ):
            raise StoreIntegrityError("Execution terminal lineage is inconsistent")
        authorization = _parse_authorization(json.loads(authority["authorization_json"]))
        central = connection.execute(
            "SELECT * FROM principal_assertion_uses WHERE issuer = ? "
            "AND assertion_id = ? AND mission_id = ?",
            (
                authority["assertion_issuer"],
                authority["assertion_id"],
                authority["mission_id"],
            ),
        ).fetchone()
        effect = connection.execute(
            "SELECT * FROM principal_assertion_effects WHERE issuer = ? "
            "AND assertion_id = ? AND mission_id = ? AND effect_kind = ? "
            "AND effect_id = ?",
            (
                authority["assertion_issuer"],
                authority["assertion_id"],
                authority["mission_id"],
                ACTION_EXECUTE,
                request.request_id,
            ),
        ).fetchone()
        expected_effect_json = _canonical_json(
            _action_principal_effect(
                operation=ACTION_EXECUTE,
                effect_id=request.request_id,
                payload=authorization,
                recorded_at=claim_document["claimed_at"],
            )
        )
        expected_effect_hash = sha256_text(expected_effect_json)
        if (
            central is None
            or effect is None
            or central["operation"] != ACTION_EXECUTE
            or central["assertion_hash"] != authority["assertion_sha256"]
            or central["consumed_at"] != claim_document["claimed_at"]
            or effect["effect_json"] != expected_effect_json
            or effect["effect_hash"] != expected_effect_hash
            or effect["recorded_at"] != claim_document["claimed_at"]
            or central["effects_hash"]
            != principal_assertion_effects_hash((expected_effect_hash,))
        ):
            raise StoreIntegrityError("Central ACTION_EXECUTE lineage is inconsistent")
        if rows["dispatch"] is not None:
            dispatch = rows["dispatch"]
            if (
                dispatch["dispatch_id"] != dispatch_id
                or dispatch["claim_id"] != claim.claim_id
                or dispatch["attempted_at"] > recorded_at
            ):
                raise StoreIntegrityError("Execution dispatch lineage is inconsistent")
            preinvocation_abort = rows["preinvocation_abort"]
            if preinvocation_abort is not None and (
                preinvocation_abort["request_id"] != request.request_id
                or preinvocation_abort["request_sha256"] != request.request_sha256
                or preinvocation_abort["claim_id"] != claim.claim_id
                or preinvocation_abort["claim_sha256"] != claim.claim_sha256
                or preinvocation_abort["dispatch_id"] != dispatch_id
                or preinvocation_abort["dispatch_sha256"]
                != dispatch["dispatch_sha256"]
                or preinvocation_abort["aborted_at"] != recorded_at
            ):
                raise StoreIntegrityError(
                    "Execution preinvocation abort lineage is inconsistent"
                )
        else:
            abort = rows["abort"]
            if (
                abort["dispatch_id"] != dispatch_id
                or abort["request_sha256"] != request.request_sha256
                or abort["claim_id"] != claim.claim_id
                or abort["claim_sha256"] != claim.claim_sha256
                or abort["receipt_id"] != receipt["receipt_id"]
                or abort["receipt_sha256"] != receipt["receipt_sha256"]
                or abort["assertion_issuer"] != authority["assertion_issuer"]
                or abort["assertion_id"] != authority["assertion_id"]
                or abort["assertion_sha256"] != authority["assertion_sha256"]
                or abort["aborted_at"] != recorded_at
            ):
                raise StoreIntegrityError("Execution predispatch abort lineage is inconsistent")
        verify_authenticated_action_admission_store(
            connection,
            mission_id=receipt["mission_id"],
        )
        verify_action_authority_repository(
            connection,
            mission_id=receipt["mission_id"],
            require_current_sources=False,
        )
        reserved = json.loads(link["resources_json"])
        if (
            set(reserved) != set(RESOURCE_FIELDS)
            or any(reservation[field] != reserved[field] for field in RESOURCE_FIELDS)
        ):
            raise StoreIntegrityError("Execution reservation vector is inconsistent")
        charged = dict(charged_resources)
        if set(charged) != set(RESOURCE_FIELDS) or any(
            type(charged[field]) is not int
            or charged[field] < 0
            or charged[field] > reserved[field]
            for field in RESOURCE_FIELDS
        ):
            raise StoreIntegrityError("Execution terminal charge vector is invalid")
        if release_only:
            if any(charged.values()):
                raise StoreIntegrityError("Predispatch abort must have an exact zero charge")
            event_specs = (("release", reserved),)
        else:
            remainder = {
                field: reserved[field] - charged[field] for field in RESOURCE_FIELDS
            }
            event_specs = (
                (("settle", charged), ("release", remainder))
                if any(remainder.values())
                else (("settle", charged),)
            )
        if connection.execute(
            "SELECT 1 FROM action_budget_account_events WHERE account_id = ? "
            "AND reservation_id = ? AND event_kind != 'reserve' LIMIT 1",
            (link["account_id"], link["reservation_id"]),
        ).fetchone() is not None:
            raise StoreConflictError("Execution budget reservation is already terminal")
        prior = connection.execute(
            "SELECT event_sequence, event_sha256, recorded_at FROM "
            "action_budget_account_events WHERE account_id = ? "
            "ORDER BY event_sequence DESC LIMIT 1",
            (link["account_id"],),
        ).fetchone()
        head = connection.execute(
            "SELECT event_count, event_head_sha256, updated_at FROM "
            "action_budget_account_heads WHERE account_id = ?",
            (link["account_id"],),
        ).fetchone()
        if (
            prior is None
            or head is None
            or prior["event_sequence"] != head["event_count"]
            or prior["event_sha256"] != head["event_head_sha256"]
            or prior["recorded_at"] > recorded_at
            or head["updated_at"] > recorded_at
        ):
            raise StoreConflictError("Execution budget terminal chronology regressed")
        sequence = int(prior["event_sequence"])
        previous_sha256 = str(prior["event_sha256"])
        event_ids: list[str] = []
        for event_kind, resources in event_specs:
            sequence += 1
            body = {
                "account_id": link["account_id"],
                "budget_revision_id": link["budget_revision_id"],
                "budget_revision_sha256": link["budget_revision_sha256"],
                "claim_id": claim.claim_id,
                "claim_sha256": claim.claim_sha256,
                "dispatch_id": dispatch_id,
                "event_kind": event_kind,
                "event_sequence": sequence,
                "execution_id": request.request_id,
                "execution_intent_sha256": action_execute_authorization_intent_sha256(
                    request
                ),
                "idempotency_key_sha256": link["idempotency_key_sha256"],
                "previous_event_sha256": previous_sha256,
                "receipt_id": receipt["receipt_id"],
                "recorded_at": recorded_at,
                "reservation_id": link["reservation_id"],
                "reservation_sha256": link["reservation_sha256"],
                "resources": resources,
            }
            event_sha256 = _canonical_sha256(
                {"domain": BUDGET_EVENT_DOMAIN, "event": body}
            )
            event_id = "ABE-" + event_sha256.removeprefix("sha256:")[:32].upper()
            connection.execute(
                """
                INSERT INTO action_budget_account_events(
                    account_id, event_sequence, event_id, event_sha256,
                    event_kind, receipt_id, budget_revision_id,
                    budget_revision_sha256, reservation_id, reservation_sha256,
                    idempotency_key_sha256, execution_id,
                    execution_intent_sha256, claim_id, claim_sha256, dispatch_id,
                    resources_json, previous_event_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    link["account_id"],
                    sequence,
                    event_id,
                    event_sha256,
                    event_kind,
                    receipt["receipt_id"],
                    link["budget_revision_id"],
                    link["budget_revision_sha256"],
                    link["reservation_id"],
                    link["reservation_sha256"],
                    link["idempotency_key_sha256"],
                    request.request_id,
                    body["execution_intent_sha256"],
                    claim.claim_id,
                    claim.claim_sha256,
                    dispatch_id,
                    canonical_json(resources),
                    previous_sha256,
                    recorded_at,
                ),
            )
            event_ids.append(event_id)
            previous_sha256 = event_sha256
        updated = connection.execute(
            "UPDATE action_budget_account_heads SET event_count = ?, "
            "event_head_sha256 = ?, updated_at = ? WHERE account_id = ? "
            "AND event_count = ? AND event_head_sha256 = ?",
            (
                sequence,
                previous_sha256,
                recorded_at,
                link["account_id"],
                prior["event_sequence"],
                prior["event_sha256"],
            ),
        )
        if updated.rowcount != 1:
            raise StoreConflictError("Execution budget account head changed")
        verify_action_authority_repository(
            connection,
            mission_id=receipt["mission_id"],
            require_current_sources=False,
        )
        return tuple(event_ids)

    @staticmethod
    def _reservation_for_request(
        connection: sqlite3.Connection,
        request_id: str,
    ) -> ExecutionResources:
        row = connection.execute(
            "SELECT * FROM action_execution_reservations WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Execution reservation is absent")
        return ExecutionResources(
            **{field: row[field] for field in RESOURCE_FIELDS}
        )

    @staticmethod
    def _terminal_for_request(
        connection: sqlite3.Connection,
        request_id: str,
    ) -> ActionExecutionTerminal | None:
        row = connection.execute(
            "SELECT terminal_json FROM action_execution_terminals "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if type(row["terminal_json"]) is not str:
            raise StoreIntegrityError("Execution terminal type is invalid")
        try:
            raw = json.loads(row["terminal_json"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Execution terminal JSON is invalid") from exc
        if _canonical_json(raw) != row["terminal_json"]:
            raise StoreIntegrityError("Execution terminal JSON is noncanonical")
        return parse_action_execution_terminal(raw)


def _historical_execution_basis(
    connection: sqlite3.Connection,
    request: ActionExecutionRequest,
) -> dict[str, Any]:
    """Reconstruct the exact Phase195 receipt-bound material for one execution."""

    document = request.to_dict()
    receipt = document["admission_receipt"]
    receipt_row = connection.execute(
        "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    ).fetchone()
    if receipt_row is None or any(
        type(receipt_row[field]) is not str
        for field in (
            "receipt_json",
            "resolution_json",
            "request_json",
            "authority_state_json",
        )
    ):
        raise StoreIntegrityError("Execution admission receipt basis is absent")
    try:
        stored_receipt = json.loads(receipt_row["receipt_json"])
        resolution = json.loads(receipt_row["resolution_json"])
        admission_request = json.loads(receipt_row["request_json"])
        admission_state = json.loads(receipt_row["authority_state_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Execution admission receipt basis is invalid") from exc
    expected_execution_state = {
        "action_sha256": receipt["action_sha256"],
        "authority_revision_sha256": admission_state[
            "authority_revision_sha256"
        ],
        "catalog_authority_sha256": admission_state[
            "catalog_authority_sha256"
        ],
        "catalog_id": admission_state["catalog_id"],
        "catalog_sha256": admission_state["catalog_sha256"],
        "catalog_version": admission_state["catalog_version"],
        "checks": {name: True for name in AUTHORITY_CHECKS},
        "mission_id": receipt["mission_id"],
        "plan_id": resolution["plan_id"],
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": receipt["receipt_sha256"],
        "review_evidence_sha256": admission_state[
            "review_evidence_sha256"
        ],
        "scope_sha256": receipt["scope_sha256"],
        "target_sha256": receipt["target_sha256"],
        "tenant_id": receipt["tenant_id"],
    }
    if (
        _canonical_json(stored_receipt) != receipt_row["receipt_json"]
        or stored_receipt != receipt
        or receipt_row["receipt_sha256"] != receipt["receipt_sha256"]
        or receipt_row["custody_sha256"] != document["admission_custody_sha256"]
        or document["authority_state"] != expected_execution_state
        or document["authority_state_sha256"]
        != CurrentExecutionAuthorityState(**expected_execution_state).state_sha256
        or admission_state["authority_revision_sha256"]
        != document["authority_state"]["authority_revision_sha256"]
    ):
        raise StoreIntegrityError("Execution admission receipt basis is substituted")
    bundle_row = connection.execute(
        "SELECT * FROM action_authority_source_bundles "
        "WHERE source_bundle_sha256 = ?",
        (admission_state["authority_revision_sha256"],),
    ).fetchone()
    if bundle_row is None or type(bundle_row["bundle_json"]) is not str:
        raise StoreIntegrityError("Execution source bundle is absent")
    bundle = json.loads(bundle_row["bundle_json"])
    publication = connection.execute(
        "SELECT * FROM action_authority_publications WHERE mission_id = ? "
        "AND source_bundle_id = ? AND source_bundle_sha256 = ?",
        (
            receipt["mission_id"],
            bundle["source_bundle_id"],
            bundle["source_bundle_sha256"],
        ),
    ).fetchone()
    if publication is None:
        raise StoreIntegrityError("Execution source publication is absent")
    material_row = connection.execute(
        "SELECT * FROM action_authority_material_snapshots "
        "WHERE material_snapshot_id = ? AND material_snapshot_sha256 = ?",
        (
            publication["material_snapshot_id"],
            publication["material_snapshot_sha256"],
        ),
    ).fetchone()
    policy_row = connection.execute(
        "SELECT record_json FROM action_authority_revisions "
        "WHERE record_kind = 'action_authority_policy_revision' "
        "AND record_id = ? AND record_sha256 = ?",
        (
            bundle["action_authority_policy_revision_id"],
            bundle["action_authority_policy_revision_sha256"],
        ),
    ).fetchone()
    if (
        material_row is None
        or type(material_row["material_json"]) is not str
        or policy_row is None
        or type(policy_row["record_json"]) is not str
    ):
        raise StoreIntegrityError("Execution source material is absent")
    material = json.loads(material_row["material_json"])
    policy = json.loads(policy_row["record_json"])
    action_type = resolution["action_type"]
    adapter_kind = (
        "http"
        if action_type.startswith(("api.", "http."))
        else (
            "browser"
            if action_type.startswith("browser.")
            else (
                "session"
                if action_type.startswith(("session.", "network."))
                else "specialist"
            )
        )
    )
    expected_adapter = AdapterBinding(
        adapter_id=resolution["tool_artifact_ref"],
        adapter_kind=adapter_kind,
        adapter_version=resolution["tool_exact_version"],
        adapter_build_sha256=resolution["tool_artifact_sha256"],
        deployment_binding_sha256=material["executor_deployment_sha256"],
    ).to_dict()
    target = material["target"]
    expected_input = {
        "action_sha256": resolution["action_sha256"],
        "action_type": resolution["action_type"],
        "credential_ref_sha256": material["credential_lease"][
            "credential_ref_sha256"
        ],
        "fence_token_sha256": material["worker_session"]["fence_token_sha256"],
        "parameters": material["parameters"]["parameters"],
        "session_id": material["worker_session"]["session_id"],
        "target": {
            field: target[field]
            for field in (
                "target_id",
                "target_sha256",
                "target_scope_sha256",
                "environment",
                "authority_snapshot_sha256",
            )
        },
    }
    account = connection.execute(
        "SELECT account.budget_id FROM action_budget_receipt_reservations AS link "
        "JOIN action_budget_accounts AS account ON account.account_id = link.account_id "
        "WHERE link.receipt_id = ?",
        (receipt["receipt_id"],),
    ).fetchone()
    if (
        account is None
        or document["adapter"] != expected_adapter
        or document["adapter_input"] != expected_input
        or document["adapter_input_sha256"]
        != _canonical_sha256(
            {"adapter_input": expected_input, "domain": INPUT_DOMAIN}
        )
        or document["budget_id"] != account["budget_id"]
        or document["budget_sha256"] != bundle["budget_revision_sha256"]
    ):
        raise StoreIntegrityError("Execution material or budget basis is substituted")
    return {
        "admission_request": admission_request,
        "bundle": bundle,
        "material": material,
        "policy": policy,
        "publication": publication,
        "receipt_row": receipt_row,
        "resolution": resolution,
    }


def _verify_historical_principal_credential(
    connection: sqlite3.Connection,
    *,
    central: sqlite3.Row,
    checked_at: str,
    expected_operation: str,
    trust: Mapping[str, Any],
) -> None:
    identity = connection.execute(
        "SELECT * FROM store_identity WHERE singleton_id = 1"
    ).fetchone()
    trust_row = connection.execute(
        "SELECT * FROM trust_policy_history WHERE policy_hash = ?",
        (trust["trust_policy_hash"],),
    ).fetchone()
    scope_row = connection.execute(
        "SELECT * FROM mission_scope_grants WHERE grant_hash = ?",
        (central["scope_grant_hash"],),
    ).fetchone()
    mission_row = connection.execute(
        "SELECT context_json, context_hash FROM missions WHERE mission_id = ?",
        (central["mission_id"],),
    ).fetchone()
    if any(item is None for item in (identity, trust_row, scope_row, mission_row)):
        raise StoreIntegrityError("Historical action principal custody is incomplete")
    try:
        policy = PrincipalTrustPolicy.from_dict(json.loads(trust_row["policy_json"]))
        grant = ScopeGrant.from_dict(json.loads(scope_row["grant_json"]))
        assertion = PrincipalAssertion.from_dict(json.loads(central["assertion_json"]))
        mission_context = json.loads(mission_row["context_json"])
        mission = mission_context["mission"]
        evaluated_at = parse_timestamp(checked_at, "execution checkpoint captured_at")
        root_public_key = base64.urlsafe_b64decode(
            str(identity["pinned_root_public_key"]) + "="
        )
        verified_policy = verify_trust_policy(
            policy,
            {str(identity["pinned_root_key_id"]): root_public_key},
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_root_key_id=str(identity["pinned_root_key_id"]),
            minimum_policy_version=policy.policy_version,
            clock=lambda: evaluated_at,
        )
        verified_scope = verify_scope_grant(
            grant,
            verified_policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=str(central["mission_id"]),
            expected_mission_context_hash=str(mission_row["context_hash"]),
            expected_scope_reference=mission["scope_reference"],
            expected_scope_document_hash=mission["scope_document_hash"],
            expected_environment=mission["environment"],
            expected_max_action_tier=mission["max_action_tier"],
            expected_constraints_hash=sha256_text(
                canonical_json(mission["constraints"])
            ),
            expected_operation=expected_operation,
            clock=lambda: evaluated_at,
        )
        principal = verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=str(central["mission_id"]),
            expected_operation=expected_operation,
            expected_operation_intent_sha256=str(central["signed_intent_hash"]),
            clock=lambda: evaluated_at,
        )
    except (
        json.JSONDecodeError,
        KeyError,
        PrincipalAuthenticationError,
        TypeError,
        ValueError,
    ) as exc:
        raise StoreIntegrityError(
            "Historical action principal credential is invalid"
        ) from exc
    if (
        verified_policy.policy_sha256 != trust["trust_policy_hash"]
        or grant.content_sha256 != scope_row["grant_hash"]
        or assertion.content_sha256 != central["assertion_hash"]
        or principal.key_sha256 != central["key_hash"]
        or principal.policy_sha256 != central["trust_policy_hash"]
    ):
        raise StoreIntegrityError(
            "Historical action principal credential binding is invalid"
        )


def _verify_historical_execution_currentness(
    connection: sqlite3.Connection,
    *,
    request: ActionExecutionRequest,
    basis: Mapping[str, Any],
    authorization: Mapping[str, Any],
    central: sqlite3.Row,
    checked_at: str,
    high_water: Mapping[str, Any],
) -> None:
    document = request.to_dict()
    receipt = document["admission_receipt"]
    admission_request = basis["admission_request"]
    bundle = basis["bundle"]
    material = basis["material"]
    policy = basis["policy"]
    publication = basis["publication"]
    resolution = basis["resolution"]
    try:
        publication_document = json.loads(publication["publication_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Execution source publication is invalid") from exc
    if _canonical_json(publication_document) != publication["publication_json"]:
        raise StoreIntegrityError("Execution source publication is noncanonical")
    try:
        historical_decision = evaluate_action_admission(
            ActionAdmissionRequest.from_dict(admission_request),
            evaluated_at=checked_at,
        )
    except Exception as exc:
        raise StoreIntegrityError(
            "Historical action admission request is invalid"
        ) from exc
    if historical_decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
        raise StoreIntegrityError("Historical action admission is not admissible")
    if not (
        receipt["evaluated_at"] <= checked_at
        and admission_request["requested_at"] <= checked_at
        < admission_request["expires_at"]
        and admission_request["worker_session"]["issued_at"] <= checked_at
        < admission_request["worker_session"]["expires_at"]
        and admission_request["credential_lease"]["issued_at"] <= checked_at
        < admission_request["credential_lease"]["expires_at"]
        and admission_request["health"]["observed_at"] <= checked_at
        < admission_request["health"]["expires_at"]
        and policy["effective_at"] <= checked_at < policy["expires_at"]
        and bundle["observed_at"] <= checked_at < bundle["valid_until"]
        and material["observed_at"] <= checked_at < material["valid_until"]
        and authorization["issued_at"] <= checked_at < authorization["expires_at"]
        and central["not_before"] <= checked_at < central["expires_at"]
    ):
        raise StoreIntegrityError("Historical execution authority window is invalid")
    mission_id = receipt["mission_id"]
    principal = high_water["principal"]
    assertion_count = principal["assertion_count"]
    if (
        type(assertion_count) is not int
        or type(principal["effect_count"]) is not int
        or type(principal["execute_use_sequence"]) is not int
        or principal["execute_use_sequence"] != central["use_sequence"]
        or assertion_count < principal["execute_use_sequence"]
    ):
        raise StoreIntegrityError("Execution principal checkpoint is invalid")
    ledger = connection.execute(
        "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    prefix = connection.execute(
        "SELECT entry_hash FROM principal_assertion_uses WHERE mission_id = ? "
        "AND use_sequence = ?",
        (mission_id, assertion_count),
    ).fetchone()
    effect_count = connection.execute(
        "SELECT COUNT(*) FROM principal_assertion_effects AS effect JOIN "
        "principal_assertion_uses AS use ON use.issuer = effect.issuer AND "
        "use.assertion_id = effect.assertion_id AND use.mission_id = "
        "effect.mission_id WHERE use.mission_id = ? AND use.use_sequence <= ?",
        (mission_id, assertion_count),
    ).fetchone()[0]
    expected_principal_head = (
        principal["baseline_root_hash"]
        if assertion_count == 0
        else None if prefix is None else prefix["entry_hash"]
    )
    if (
        ledger is None
        or ledger["baseline_root_hash"] != principal["baseline_root_hash"]
        or ledger["assertion_count"] < assertion_count
        or ledger["effect_count"] < principal["effect_count"]
        or effect_count != principal["effect_count"]
        or expected_principal_head != principal["head_hash"]
    ):
        raise StoreIntegrityError("Execution principal checkpoint prefix is invalid")

    mission = high_water["mission"]
    current_mission = connection.execute(
        "SELECT mission_id, context_hash, revision, head_hash FROM missions "
        "WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    mission_prefix = connection.execute(
        "SELECT entry_hash FROM mission_events WHERE mission_id = ? AND sequence = ?",
        (mission_id, mission["revision"]),
    ).fetchone()
    expected_mission_head = (
        mission["context_hash"]
        if mission["revision"] == 0
        else None if mission_prefix is None else mission_prefix["entry_hash"]
    )
    if (
        current_mission is None
        or mission["mission_id"] != mission_id
        or current_mission["context_hash"] != mission["context_hash"]
        or current_mission["revision"] < mission["revision"]
        or expected_mission_head != mission["head_hash"]
        or mission["revision"] != bundle["mission_revision"]
    ):
        raise StoreIntegrityError("Execution mission checkpoint prefix is invalid")

    control = high_water["control"]
    current_control = connection.execute(
        "SELECT mission_id, version, state, stopped_at, stop_event_id FROM "
        "mission_controls WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    stop_use_sequence = None
    if current_control is not None and current_control["stop_event_id"] is not None:
        stop_use = connection.execute(
            "SELECT use.use_sequence FROM principal_assertion_effects AS effect "
            "JOIN principal_assertion_uses AS use ON use.issuer = effect.issuer AND "
            "use.assertion_id = effect.assertion_id AND use.mission_id = "
            "effect.mission_id WHERE effect.mission_id = ? AND effect.effect_kind = ? "
            "AND effect.effect_id = ?",
            (
                mission_id,
                MISSION_STOP_EFFECT_KIND,
                current_control["stop_event_id"],
            ),
        ).fetchone()
        if stop_use is None:
            raise StoreIntegrityError("Mission stop authority use is absent")
        stop_use_sequence = stop_use["use_sequence"]
    if (
        current_control is None
        or control["mission_id"] != mission_id
        or type(control["version"]) is not int
        or current_control["version"] < control["version"]
        or control["state"] != "active"
        or control["stopped_at"] is not None
        or control["stop_event_id"] is not None
        or (
            current_control["version"] == control["version"]
            and any(current_control[field] != control[field] for field in control)
        )
        or (
            current_control["version"] > control["version"]
            and (
                stop_use_sequence is None
                or stop_use_sequence <= principal["assertion_count"]
            )
        )
    ):
        raise StoreIntegrityError("Execution mission control checkpoint is invalid")

    trust = high_water["trust"]
    trust_row = connection.execute(
        "SELECT policy_id, policy_version, policy_hash, store_id FROM "
        "trust_policy_history WHERE policy_id = ? AND policy_version = ?",
        (trust["trust_policy_id"], trust["trust_policy_version"]),
    ).fetchone()
    store_identity = connection.execute(
        "SELECT store_id, trust_policy_version FROM store_identity WHERE singleton_id = 1"
    ).fetchone()
    if (
        trust_row is None
        or store_identity is None
        or trust_row["policy_id"] != trust["trust_policy_id"]
        or trust_row["policy_version"] != trust["trust_policy_version"]
        or trust_row["policy_hash"] != trust["trust_policy_hash"]
        or trust_row["store_id"] != trust["store_id"]
        or store_identity["store_id"] != trust["store_id"]
        or store_identity["trust_policy_version"] < trust["trust_policy_version"]
        or central["trust_policy_id"] != trust["trust_policy_id"]
        or central["trust_policy_version"] != trust["trust_policy_version"]
        or central["trust_policy_hash"] != trust["trust_policy_hash"]
        or trust["trust_policy_hash"] != bundle["trust_policy_sha256"]
    ):
        raise StoreIntegrityError("Execution trust checkpoint is invalid")
    _verify_historical_principal_credential(
        connection,
        central=central,
        checked_at=checked_at,
        expected_operation=PrincipalOperation.ACTION_EXECUTE.value,
        trust=trust,
    )

    scope = high_water["scope"]
    scope_state = connection.execute(
        "SELECT * FROM mission_scope_revocation_baselines WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    scope_prefix = connection.execute(
        "SELECT entry_hash FROM mission_scope_grant_revocations WHERE mission_id = ? "
        "AND revocation_sequence = ?",
        (mission_id, scope["signed_revocation_count"]),
    ).fetchone()
    expected_scope_head = (
        scope["baseline_root_hash"]
        if scope["signed_revocation_count"] == 0
        else None if scope_prefix is None else scope_prefix["entry_hash"]
    )
    scoped_revocation = connection.execute(
        "SELECT 1 FROM mission_scope_grant_revocations WHERE mission_id = ? "
        "AND scope_grant_hash = ? AND revocation_sequence <= ? LIMIT 1",
        (
            mission_id,
            scope["execution_scope_grant_sha256"],
            scope["signed_revocation_count"],
        ),
    ).fetchone()
    bundle_scope_revocation = connection.execute(
        "SELECT 1 FROM mission_scope_grant_revocations WHERE mission_id = ? "
        "AND scope_grant_hash = ? AND revocation_sequence <= ? LIMIT 1",
        (
            mission_id,
            scope["bundle_scope_grant_sha256"],
            scope["signed_revocation_count"],
        ),
    ).fetchone()
    execution_scope = connection.execute(
        "SELECT * FROM mission_scope_grants WHERE grant_hash = ?",
        (scope["execution_scope_grant_sha256"],),
    ).fetchone()
    if (
        scope_state is None
        or execution_scope is None
        or scope_state["baseline_root_hash"] != scope["baseline_root_hash"]
        or scope_state["signed_revocation_count"] < scope["signed_revocation_count"]
        or expected_scope_head != scope["head_hash"]
        or scope["execution_scope_grant_sha256"] != central["scope_grant_hash"]
        or execution_scope["mission_id"] != mission_id
        or execution_scope["trust_policy_id"] != trust["trust_policy_id"]
        or execution_scope["trust_policy_version"] != trust["trust_policy_version"]
        or execution_scope["trust_policy_hash"] != trust["trust_policy_hash"]
        or execution_scope["accepted_at"] > checked_at
        or execution_scope["not_before"] > checked_at
        or execution_scope["expires_at"] <= checked_at
        or scope["bundle_scope_grant_sha256"] != bundle["scope_grant_sha256"]
        or scope["head_hash"] != bundle["scope_revocation_head_sha256"]
        or scoped_revocation is not None
        or bundle_scope_revocation is not None
    ):
        raise StoreIntegrityError("Execution scope checkpoint is invalid")

    plan = high_water["plan"]
    eligible_plans: list[tuple[int, sqlite3.Row, list[int]]] = []
    for candidate in connection.execute(
        "SELECT * FROM collaboration_plan_activations WHERE mission_id = ? "
        "ORDER BY plan_version",
        (mission_id,),
    ).fetchall():
        sequences = _plan_authority_use_sequences(
            connection,
            mission_id=mission_id,
            plan=candidate,
        )
        if max(sequences) <= assertion_count:
            eligible_plans.append((candidate["plan_version"], candidate, sequences))
    latest_eligible_plan = max(
        eligible_plans,
        default=None,
        key=lambda value: value[0],
    )
    plan_row = None if latest_eligible_plan is None else latest_eligible_plan[1]
    plan_uses = [] if latest_eligible_plan is None else latest_eligible_plan[2]
    current_plan = connection.execute(
        "SELECT * FROM collaboration_plan_active_heads WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    plan_fields = {
        "active_plan_id": "plan_id",
        "plan_version": "plan_version",
        "replacement_commit_id": "replacement_commit_id",
        "plan_sha256": "plan_sha256",
        "plan_content_sha256": "plan_content_sha256",
        "activation_kind": "activation_kind",
        "activated_at": "activated_at",
        "issuer": "issuer",
        "assertion_id": "assertion_id",
    }
    if (
        plan_row is None
        or current_plan is None
        or latest_eligible_plan is None
        or plan["active_plan_id"] != document["authority_state"]["plan_id"]
        or current_plan["plan_version"] < plan["plan_version"]
        or any(plan[field] != plan_row[column] for field, column in plan_fields.items())
        or plan["authority_use_sequences"] != plan_uses
        or plan["authority_use_set_sha256"] != _authority_use_set_sha256(plan_uses)
        or plan["activation_use_sequence"]
        != (plan_uses[0] if plan["activation_kind"] == "initial" else None)
        or plan["plan_content_sha256"] != bundle["active_plan_sha256"]
        or plan["plan_version"] != bundle["active_plan_version"]
        or plan["active_plan_id"] != bundle["plan_id"]
    ):
        raise StoreIntegrityError("Execution plan checkpoint is invalid")

    mission_policy = high_water["mission_policy"]
    eligible_policies: list[tuple[int, sqlite3.Row, list[int]]] = []
    for candidate in connection.execute(
        "SELECT * FROM collaboration_mission_policy_commits WHERE mission_id = ? "
        "ORDER BY policy_version",
        (mission_id,),
    ).fetchall():
        candidate_uses: list[int] = []
        for issuer_field, assertion_field in (
            ("owner_issuer", "owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
        ):
            use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
                "AND issuer = ? AND assertion_id = ?",
                (mission_id, candidate[issuer_field], candidate[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError("Mission policy authority use is absent")
            candidate_uses.append(use["use_sequence"])
        if max(candidate_uses) <= assertion_count:
            eligible_policies.append(
                (candidate["policy_version"], candidate, candidate_uses)
            )
    latest_eligible_policy = max(
        eligible_policies,
        default=None,
        key=lambda value: value[0],
    )
    policy_row = None if latest_eligible_policy is None else latest_eligible_policy[1]
    policy_uses = [] if latest_eligible_policy is None else latest_eligible_policy[2]
    policy_fields = (
        "policy_id",
        "policy_version",
        "policy_sha256",
        "plan_id",
        "owner_issuer",
        "owner_assertion_id",
        "control_issuer",
        "control_assertion_id",
    )
    if (
        policy_row is None
        or latest_eligible_policy is None
        or any(policy_row[field] != mission_policy[field] for field in policy_fields)
        or policy_uses
        != [mission_policy["owner_use_sequence"], mission_policy["control_use_sequence"]]
        or any(item is None or item > assertion_count for item in policy_uses)
        or mission_policy["plan_id"] != plan["active_plan_id"]
        or mission_policy["policy_sha256"] != bundle["mission_policy_sha256"]
    ):
        raise StoreIntegrityError("Execution mission policy checkpoint is invalid")

    ownership = high_water["ownership"]
    eligible_ownership: list[tuple[int, sqlite3.Row, list[int]]] = []
    for item in connection.execute(
        "SELECT * FROM collaboration_ownership_chain_entries WHERE plan_id = ? "
        "AND work_item_id = ? ORDER BY sequence",
        (ownership["plan_id"], ownership["proposal_work_id"]),
    ).fetchall():
        sequences: list[int] = []
        for issuer_field, assertion_field in (
            ("current_owner_issuer", "current_owner_assertion_id"),
            ("proposed_owner_issuer", "proposed_owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
            ("second_authority_issuer", "second_authority_assertion_id"),
        ):
            if item[issuer_field] is None:
                continue
            use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
                "AND issuer = ? AND assertion_id = ?",
                (mission_id, item[issuer_field], item[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError("Ownership authority use is absent")
            sequences.append(use["use_sequence"])
        if sequences and max(sequences) <= assertion_count:
            eligible_ownership.append((item["sequence"], item, sorted(sequences)))
    latest_ownership = max(eligible_ownership, default=None, key=lambda value: value[0])
    if ownership["sequence"] == 0:
        ownership_valid = (
            latest_ownership is None
            and ownership["entry_id"] is None
            and ownership["entry_sha256"] is None
            and ownership["owner_epoch"] == 1
            and ownership["owner_profile_id"]
            == resolution["proposal_producer_profile_id"]
            and not ownership["authority_use_sequences"]
        )
    else:
        ownership_valid = (
            latest_ownership is not None
            and latest_ownership[1]["entry_id"] == ownership["entry_id"]
            and latest_ownership[1]["entry_sha256"] == ownership["entry_sha256"]
            and latest_ownership[1]["sequence"] == ownership["sequence"]
            and latest_ownership[1]["owner_epoch"] == ownership["owner_epoch"]
            and latest_ownership[1]["to_owner_id"] == ownership["owner_profile_id"]
            and latest_ownership[2] == ownership["authority_use_sequences"]
        )
    if (
        not ownership_valid
        or ownership["plan_id"] != plan["active_plan_id"]
        or ownership["proposal_work_id"] != resolution["proposal_work_id"]
        or ownership["owner_epoch"] != bundle["owner_epoch"]
    ):
        raise StoreIntegrityError("Execution ownership checkpoint is invalid")

    try:
        mission_policy_document = json.loads(policy_row["policy_json"])
    except (json.JSONDecodeError, TypeError) as exc:
        raise StoreIntegrityError("Execution mission policy is invalid") from exc
    approvals = mission_policy_document.get("approval_bindings")
    if not isinstance(approvals, dict):
        raise StoreIntegrityError("Execution mission policy approvals are invalid")

    def historical_role_binding(role: str) -> Mapping[str, Any] | None:
        name = {
            "mission_owner": "mission_owner",
            "independent_control": "independent_control",
        }.get(role)
        if name is None:
            return None
        binding_value = approvals.get(name)
        if not isinstance(binding_value, dict):
            raise StoreIntegrityError("Execution mission role binding is absent")
        return binding_value

    expected_operations = {
        "typed_resolver": PrincipalOperation.ACTION_RESOLVE.value,
        "mission_owner": PrincipalOperation.ACTION_QUORUM_AUTHORIZE.value,
        "independent_control": PrincipalOperation.ACTION_QUORUM_AUTHORIZE.value,
        "admission_control": PrincipalOperation.ACTION_ADMIT.value,
    }
    supporting_rows = connection.execute(
        "SELECT * FROM action_admission_assertion_uses WHERE receipt_id = ? "
        "ORDER BY role, assertion_issuer, assertion_id",
        (receipt["receipt_id"],),
    ).fetchall()
    if not supporting_rows:
        raise StoreIntegrityError("Execution admission principals are absent")
    for supporting in supporting_rows:
        try:
            supporting_authorization = json.loads(supporting["authorization_json"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError(
                "Execution admission principal authorization is invalid"
            ) from exc
        supporting_central = connection.execute(
            "SELECT * FROM principal_assertion_uses WHERE mission_id = ? AND "
            "issuer = ? AND assertion_id = ?",
            (
                mission_id,
                supporting["assertion_issuer"],
                supporting["assertion_id"],
            ),
        ).fetchone()
        supporting_scope = (
            None
            if supporting_central is None
            else connection.execute(
                "SELECT * FROM mission_scope_grants WHERE grant_hash = ?",
                (supporting_central["scope_grant_hash"],),
            ).fetchone()
        )
        supporting_revocation = (
            None
            if supporting_central is None
            else connection.execute(
                "SELECT 1 FROM mission_scope_grant_revocations WHERE mission_id = ? "
                "AND scope_grant_hash = ? AND revocation_sequence <= ? LIMIT 1",
                (
                    mission_id,
                    supporting_central["scope_grant_hash"],
                    scope["signed_revocation_count"],
                ),
            ).fetchone()
        )
        role = supporting["role"]
        operation = expected_operations.get(role)
        if supporting_central is not None and operation is not None:
            _verify_historical_principal_credential(
                connection,
                central=supporting_central,
                checked_at=checked_at,
                expected_operation=operation,
                trust=trust,
            )
        role_valid = False
        if role == "typed_resolver":
            assigned = policy["typed_resolver"]
            role_valid = (
                supporting_authorization["principal_profile_id"]
                == assigned["principal_profile_id"]
                and supporting_authorization["principal_subject"]
                == assigned["principal_subject"]
                and supporting_authorization["assertion_issuer"]
                == assigned["assertion_issuer"]
                and supporting_authorization["principal_profile_id"]
                != ownership["owner_profile_id"]
                and supporting_authorization["principal_profile_id"]
                != resolution["proposal_producer_profile_id"]
            )
        elif role == "admission_control":
            assigned = policy["admission_control"]
            role_valid = (
                supporting_authorization["principal_profile_id"]
                == assigned["principal_profile_id"]
                and supporting_authorization["principal_subject"]
                == assigned["principal_subject"]
                and supporting_authorization["assertion_issuer"]
                == assigned["assertion_issuer"]
                and supporting_authorization["principal_subject"].startswith(
                    "service:"
                )
                and supporting_authorization["principal_profile_id"]
                not in {
                    ownership["owner_profile_id"],
                    resolution["proposal_producer_profile_id"],
                    resolution["resolver_profile_id"],
                }
            )
        elif role in {"mission_owner", "independent_control"}:
            role_binding = historical_role_binding(role)
            role_principal = connection.execute(
                "SELECT issuer, subject, principal_profile_id FROM "
                "principal_assertion_uses WHERE mission_id = ? AND assertion_id = ? "
                "AND assertion_hash = ? AND principal_profile_id = ?",
                (
                    mission_id,
                    role_binding["assertion_id"],
                    role_binding["assertion_sha256"],
                    role_binding["profile_id"],
                ),
            ).fetchone()
            role_valid = (
                role_principal is not None
                and supporting_authorization["principal_profile_id"]
                == role_binding["profile_id"]
                and supporting_authorization["assertion_issuer"]
                == role_principal["issuer"]
                and supporting_authorization["principal_subject"]
                == role_principal["subject"]
                and supporting_authorization["principal_profile_id"]
                not in {
                    resolution["proposal_producer_profile_id"],
                    resolution["resolver_profile_id"],
                    *(
                        {ownership["owner_profile_id"]}
                        if role == "independent_control"
                        else set()
                    ),
                }
            )
        if (
            supporting_central is None
            or supporting_scope is None
            or operation is None
            or supporting["operation"] != operation
            or supporting_central["operation"] != operation
            or supporting_central["use_sequence"] > assertion_count
            or supporting_central["trust_policy_id"] != trust["trust_policy_id"]
            or supporting_central["trust_policy_version"]
            != trust["trust_policy_version"]
            or supporting_central["trust_policy_hash"] != trust["trust_policy_hash"]
            or supporting_central["not_before"] > checked_at
            or supporting_central["expires_at"] <= checked_at
            or supporting_scope["mission_id"] != mission_id
            or supporting_scope["trust_policy_id"] != trust["trust_policy_id"]
            or supporting_scope["trust_policy_version"]
            != trust["trust_policy_version"]
            or supporting_scope["trust_policy_hash"] != trust["trust_policy_hash"]
            or supporting_scope["accepted_at"] > checked_at
            or supporting_scope["not_before"] > checked_at
            or supporting_scope["expires_at"] <= checked_at
            or supporting_revocation is not None
            or supporting_authorization["scope_grant_sha256"]
            != supporting_central["scope_grant_hash"]
            or not role_valid
        ):
            raise StoreIntegrityError(
                "Execution admission principal is not current at checkpoint"
            )

    session = high_water["session"]
    session_row = connection.execute(
        "SELECT * FROM execution_session_authority_commits WHERE "
        "session_authority_id = ?",
        (session["session_authority_id"],),
    ).fetchone()
    activation = connection.execute(
        "SELECT * FROM execution_session_activation_commits WHERE "
        "authentication_id = ?",
        (session["activation_authentication_id"],),
    ).fetchone()
    session_fields = (
        "session_authority_id",
        "session_authority_sha256",
        "mission_id",
        "collaboration_plan_id",
        "collaboration_plan_sha256",
        "work_item_id",
        "session_id",
        "session_sha256",
        "owner_profile_id",
        "owner_epoch",
        "worker_principal_id",
        "fence_generation",
        "credential_reference_id",
        "credential_sha256",
        "effective_at",
        "expires_at",
    )
    if session_row is None or activation is None:
        raise StoreIntegrityError("Execution session checkpoint is absent")
    session_use_pairs = (
        (
            session["activation_control_issuer"],
            session["activation_control_assertion_id"],
            session["activation_control_use_sequence"],
        ),
        (
            session["activation_worker_issuer"],
            session["activation_worker_assertion_id"],
            session["activation_worker_use_sequence"],
        ),
    )
    session_uses_valid = True
    for issuer, assertion_id, sequence in session_use_pairs:
        use = connection.execute(
            "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
            "AND issuer = ? AND assertion_id = ?",
            (mission_id, issuer, assertion_id),
        ).fetchone()
        if use is None or use["use_sequence"] != sequence or sequence > assertion_count:
            session_uses_valid = False
    later_session = connection.execute(
        "SELECT activation.control_issuer, activation.control_assertion_id, "
        "activation.worker_issuer, activation.worker_assertion_id FROM "
        "execution_session_authority_commits AS authority JOIN "
        "execution_session_activation_commits AS activation ON "
        "activation.session_authority_id = authority.session_authority_id "
        "WHERE authority.mission_id = ? AND authority.work_item_id = ? "
        "AND authority.fence_generation > ?",
        (mission_id, session["work_item_id"], session["fence_generation"]),
    ).fetchall()
    later_session_before_cutoff = False
    for item in later_session:
        sequences = []
        for issuer_field, assertion_field in (
            ("control_issuer", "control_assertion_id"),
            ("worker_issuer", "worker_assertion_id"),
        ):
            use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
                "AND issuer = ? AND assertion_id = ?",
                (mission_id, item[issuer_field], item[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError("Later session activation use is absent")
            sequences.append(use["use_sequence"])
        if max(sequences) <= assertion_count:
            later_session_before_cutoff = True
    session_revocation = connection.execute(
        "SELECT revocation.control_issuer, revocation.control_assertion_id FROM "
        "execution_session_revocation_commits AS revocation WHERE "
        "revocation.session_authority_id = ?",
        (session["session_authority_id"],),
    ).fetchone()
    session_revoked_before_cutoff = False
    if session_revocation is not None:
        use = connection.execute(
            "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
            "AND issuer = ? AND assertion_id = ?",
            (
                mission_id,
                session_revocation["control_issuer"],
                session_revocation["control_assertion_id"],
            ),
        ).fetchone()
        session_revoked_before_cutoff = use is not None and use["use_sequence"] <= assertion_count
    if (
        any(session_row[field] != session[field] for field in session_fields)
        or activation["authentication_sha256"]
        != session["activation_authentication_sha256"]
        or activation["authenticated_at"]
        != session["activation_authenticated_at"]
        or activation["session_authority_id"] != session["session_authority_id"]
        or activation["control_issuer"] != session["activation_control_issuer"]
        or activation["control_assertion_id"]
        != session["activation_control_assertion_id"]
        or activation["worker_issuer"] != session["activation_worker_issuer"]
        or activation["worker_assertion_id"]
        != session["activation_worker_assertion_id"]
        or not session_uses_valid
        or later_session_before_cutoff
        or session_revoked_before_cutoff
        or session["session_id"] != admission_request["worker_session"]["session_id"]
        or session["work_item_id"] != resolution["proposal_work_id"]
        or session["collaboration_plan_id"] != plan["active_plan_id"]
        or session["owner_profile_id"] != ownership["owner_profile_id"]
        or session["owner_epoch"] != ownership["owner_epoch"]
        or session["worker_principal_id"]
        != admission_request["worker_session"]["worker_id"]
        or session["owner_profile_id"]
        != admission_request["worker_session"]["worker_profile_id"]
        or session["credential_reference_id"]
        != admission_request["credential_lease"]["lease_id"]
        or session["credential_sha256"]
        != admission_request["credential_lease"]["credential_ref_sha256"]
        or session["effective_at"]
        != admission_request["worker_session"]["issued_at"]
        or session["expires_at"]
        != admission_request["worker_session"]["expires_at"]
        or material["worker_session"] != admission_request["worker_session"]
        or material["credential_lease"] != admission_request["credential_lease"]
        or not (
            session["effective_at"] <= checked_at < session["expires_at"]
            and session["effective_at"] <= bundle["observed_at"]
            and bundle["valid_until"] <= session["expires_at"]
            and session["activation_authenticated_at"] <= bundle["observed_at"]
        )
        or session["mission_id"] != mission_id
        or session["collaboration_plan_sha256"] != plan["plan_content_sha256"]
        or session["session_authority_id"] != bundle["session_authority_id"]
        or session["session_authority_sha256"] != bundle["session_authority_sha256"]
        or session["session_id"] != bundle["execution_session_id"]
        or session["session_sha256"] != bundle["execution_session_sha256"]
        or session["owner_epoch"] != bundle["owner_epoch"]
        or session["fence_generation"] != bundle["fence_generation"]
        or session["credential_sha256"] != bundle["credential_lease_sha256"]
    ):
        raise StoreIntegrityError("Execution session checkpoint is invalid")

    admission = high_water["admission"]
    receipt_revocation = connection.execute(
        "SELECT assertion_issuer, assertion_id, revocation_id FROM "
        "action_admission_revocations WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    ).fetchone()
    receipt_revoked_before_cutoff = False
    if receipt_revocation is not None:
        use = connection.execute(
            "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
            "AND issuer = ? AND assertion_id = ?",
            (
                mission_id,
                receipt_revocation["assertion_issuer"],
                receipt_revocation["assertion_id"],
            ),
        ).fetchone()
        receipt_revoked_before_cutoff = use is not None and use["use_sequence"] <= assertion_count
    if (
        admission["receipt_id"] != receipt["receipt_id"]
        or admission["receipt_sha256"] != receipt["receipt_sha256"]
        or admission["revocation_id"] is not None
        or receipt_revoked_before_cutoff
    ):
        raise StoreIntegrityError("Execution admission checkpoint is invalid")

    review = high_water["review"]
    review_row = connection.execute(
        "SELECT * FROM authenticated_expert_review_closure_projections "
        "WHERE closure_id = ?",
        (review["closure_id"],),
    ).fetchone()
    review_revocation = connection.execute(
        "SELECT assertion_issuer, assertion_id, revocation_id FROM "
        "authenticated_expert_review_revocations WHERE closure_id = ?",
        (review["closure_id"],),
    ).fetchone()
    review_revoked_before_cutoff = False
    if review_revocation is not None:
        use = connection.execute(
            "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
            "AND issuer = ? AND assertion_id = ?",
            (mission_id, review_revocation["assertion_issuer"], review_revocation["assertion_id"]),
        ).fetchone()
        review_revoked_before_cutoff = use is not None and use["use_sequence"] <= assertion_count
    review_fields = (
        "closure_id",
        "closure_sha256",
        "workspace_id",
        "application_id",
        "application_sha256",
        "projected_at",
    )
    if (
        review_row is None
        or any(review_row[field] != review[field] for field in review_fields)
        or review["closure_id"] != resolution["review_closure_id"]
        or review["revocation_id"] is not None
        or review_revoked_before_cutoff
        or review["review_revocation_head_sha256"]
        != bundle["review_revocation_head_sha256"]
        or review["application_sha256"]
        != bundle["review_closure_projection_sha256"]
    ):
        raise StoreIntegrityError("Execution review checkpoint is invalid")

    source = high_water["source_bundle"]
    source_row = connection.execute(
        "SELECT * FROM action_authority_source_heads WHERE mission_id = ? AND "
        "source_kind = 'exact_action_source_head_bundle' AND head_sequence = ?",
        (mission_id, source["head_sequence"]),
    ).fetchone()
    eligible_publications = connection.execute(
        "SELECT publication.*, use.use_sequence, head.head_sequence FROM "
        "action_authority_publications AS publication JOIN "
        "principal_assertion_uses AS use ON use.issuer = "
        "publication.assertion_issuer AND use.assertion_id = "
        "publication.assertion_id AND use.mission_id = publication.mission_id JOIN "
        "action_authority_source_heads AS head ON head.mission_id = "
        "publication.mission_id AND head.source_kind = "
        "'exact_action_source_head_bundle' AND head.record_id = "
        "publication.source_bundle_id AND head.record_sha256 = "
        "publication.source_bundle_sha256 WHERE publication.mission_id = ? AND "
        "use.use_sequence <= ? ORDER BY head.head_sequence DESC",
        (mission_id, assertion_count),
    ).fetchall()
    latest_publication = eligible_publications[0] if eligible_publications else None
    try:
        latest_publication_document = (
            None
            if latest_publication is None
            else json.loads(latest_publication["publication_json"])
        )
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Execution source publication is invalid") from exc
    source_items = high_water["source_heads"]["items"]
    expected_bindings = [
        {
            "record_id": item["record_id"],
            "record_kind": item["source_kind"],
            "record_sha256": item["record_sha256"],
        }
        for item in source_items
    ]
    source_heads_valid = True
    for item in source_items:
        stored_head = connection.execute(
            "SELECT source_kind, head_sequence, record_id, record_sha256, "
            "previous_head_sha256, head_sha256, advanced_at FROM "
            "action_authority_source_heads WHERE mission_id = ? AND "
            "source_kind = ? AND head_sequence = ?",
            (mission_id, item["source_kind"], item["head_sequence"]),
        ).fetchone()
        current_head = connection.execute(
            "SELECT head_sequence FROM action_authority_source_heads WHERE "
            "mission_id = ? AND source_kind = ? ORDER BY head_sequence DESC LIMIT 1",
            (mission_id, item["source_kind"]),
        ).fetchone()
        if (
            stored_head is None
            or current_head is None
            or dict(stored_head) != item
            or current_head["head_sequence"] < item["head_sequence"]
        ):
            source_heads_valid = False
    if (
        source_row is None
        or any(source_row[field] != source[field] for field in source)
        or source["record_id"] != bundle["source_bundle_id"]
        or source["record_sha256"] != bundle["source_bundle_sha256"]
        or publication["source_bundle_id"] != source["record_id"]
        or latest_publication is None
        or latest_publication["source_bundle_id"] != source["record_id"]
        or latest_publication["source_bundle_sha256"] != source["record_sha256"]
        or latest_publication["head_sequence"] != source["head_sequence"]
        or latest_publication_document is None
        or latest_publication["publication_id"] != publication["publication_id"]
        or latest_publication["publication_sha256"]
        != publication["publication_sha256"]
        or latest_publication_document != publication_document
        or latest_publication_document.get("source_records") != expected_bindings
        or not source_heads_valid
    ):
        raise StoreIntegrityError("Execution source checkpoint is invalid")

    budget = high_water["budget"]
    budget_head = connection.execute(
        "SELECT * FROM action_budget_account_heads WHERE account_id = ?",
        (budget["account_id"],),
    ).fetchone()
    binding = connection.execute(
        "SELECT * FROM action_budget_policy_bindings WHERE account_id = ? AND "
        "binding_sequence = ?",
        (budget["account_id"], budget["binding_sequence"]),
    ).fetchone()
    event = None
    if budget["event_sequence"]:
        event = connection.execute(
            "SELECT * FROM action_budget_account_events WHERE account_id = ? AND "
            "event_sequence = ?",
            (budget["account_id"], budget["event_sequence"]),
        ).fetchone()
    link = connection.execute(
        "SELECT * FROM action_budget_receipt_reservations WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    ).fetchone()
    reserve_event = connection.execute(
        "SELECT * FROM action_budget_account_events WHERE account_id = ? AND "
        "event_id = ?",
        (budget["account_id"], budget["reserve_event_id"]),
    ).fetchone()
    own_terminal_at_cutoff = connection.execute(
        "SELECT 1 FROM action_budget_account_events WHERE account_id = ? AND "
        "reservation_id = ? AND event_kind != 'reserve' AND event_sequence <= ?",
        (
            budget["account_id"],
            budget["reservation_id"],
            budget["event_count"],
        ),
    ).fetchone()
    expected_event_id = None if event is None else event["event_id"]
    expected_event_sha256 = budget["event_head_sha256"] if event is None else event["event_sha256"]
    bundle_budget_head_is_ancestor = (
        bundle["budget_ledger_head_sha256"]
        == _canonical_sha256(
            {
                "domain": BUDGET_EVENT_DOMAIN,
                "empty_account_id": budget["account_id"],
            }
        )
        or connection.execute(
            "SELECT 1 FROM action_budget_account_events WHERE account_id = ? "
            "AND event_sequence <= ? AND event_sha256 = ?",
            (
                budget["account_id"],
                budget["event_sequence"],
                bundle["budget_ledger_head_sha256"],
            ),
        ).fetchone()
        is not None
    )
    if (
        budget_head is None
        or binding is None
        or link is None
        or budget_head["policy_binding_count"] < budget["policy_binding_count"]
        or budget_head["event_count"] < budget["event_count"]
        or budget["binding_sequence"] != budget["policy_binding_count"]
        or budget["policy_head_sha256"] != budget["binding_sha256"]
        or binding["binding_sha256"] != budget["binding_sha256"]
        or binding["budget_revision_id"] != budget["budget_revision_id"]
        or binding["budget_revision_sha256"] != budget["budget_revision_sha256"]
        or budget["event_sequence"] != budget["event_count"]
        or budget["event_id"] != expected_event_id
        or budget["event_sha256"] != expected_event_sha256
        or budget["event_head_sha256"] != expected_event_sha256
        or link["account_id"] != budget["account_id"]
        or link["budget_revision_id"] != budget["budget_revision_id"]
        or link["budget_revision_sha256"] != budget["budget_revision_sha256"]
        or link["reservation_id"] != budget["reservation_id"]
        or link["reservation_sha256"] != budget["reservation_sha256"]
        or link["reserve_event_id"] != budget["reserve_event_id"]
        or link["reserve_event_sha256"] != budget["reserve_event_sha256"]
        or reserve_event is None
        or reserve_event["event_kind"] != "reserve"
        or reserve_event["event_sequence"] != budget["reserve_event_sequence"]
        or reserve_event["event_id"] != budget["reserve_event_id"]
        or reserve_event["event_sha256"] != budget["reserve_event_sha256"]
        or reserve_event["receipt_id"] != receipt["receipt_id"]
        or reserve_event["reservation_id"] != budget["reservation_id"]
        or reserve_event["reservation_sha256"] != budget["reservation_sha256"]
        or budget["reserve_event_sequence"] > budget["event_count"]
        or own_terminal_at_cutoff is not None
        or bundle["budget_policy_binding_sequence"] != budget["binding_sequence"]
        or bundle["budget_policy_binding_sha256"] != budget["binding_sha256"]
        or bundle["budget_revision_id"] != budget["budget_revision_id"]
        or bundle["budget_revision_sha256"] != budget["budget_revision_sha256"]
        or not bundle_budget_head_is_ancestor
    ):
        raise StoreIntegrityError("Execution budget checkpoint is invalid")

    workspace = high_water["workspace"]
    workspace_row = connection.execute(
        "SELECT * FROM action_admission_workspace_high_waters WHERE receipt_id = ?",
        (receipt["receipt_id"],),
    ).fetchone()
    if (
        workspace_row is None
        or any(workspace_row[field] != workspace[field] for field in workspace)
        or workspace["mission_store_id"] != trust["store_id"]
        or workspace["closure_id"] != review["closure_id"]
        or workspace["closure_sha256"] != review["closure_sha256"]
        or workspace["application_id"] != review["application_id"]
        or workspace["application_sha256"] != review["application_sha256"]
        or workspace["revocation_id"] is not None
        or workspace["revocation_sha256"] is not None
        or bundle["workspace_high_water_sha256"] != workspace["high_water_sha256"]
    ):
        raise StoreIntegrityError("Execution workspace checkpoint is invalid")


def _parse_authority_checkpoint(
    connection: sqlite3.Connection,
    row: sqlite3.Row | None,
    *,
    checkpoint_kind: str,
    request: ActionExecutionRequest,
    claim: ActionExecutionClaim,
    captured_at: str,
) -> dict[str, Any]:
    if row is None or any(
        type(row[field]) is not str
        for field in (
            "checkpoint_id",
            "checkpoint_sha256",
            "request_id",
            "request_sha256",
            "claim_id",
            "claim_sha256",
            "checkpoint_kind",
            "high_water_json",
            "high_water_sha256",
            "checkpoint_json",
            "captured_at",
        )
    ):
        raise StoreIntegrityError("Execution authority checkpoint is absent")
    high_water = _parse_authority_high_water(
        connection,
        row["high_water_json"],
        row["high_water_sha256"],
    )
    try:
        document = json.loads(row["checkpoint_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Execution authority checkpoint JSON is invalid") from exc
    expected_body = {
        "schema_version": 1,
        "kind": "action_execution_authority_checkpoint",
        "checkpoint_kind": checkpoint_kind,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "claim_id": claim.claim_id,
        "claim_sha256": claim.claim_sha256,
        "high_water": high_water,
        "high_water_sha256": row["high_water_sha256"],
        "captured_at": captured_at,
    }
    expected_sha256 = _canonical_sha256(
        {"domain": AUTHORITY_CHECKPOINT_DOMAIN, "record": expected_body}
    )
    expected_id = "AXH-" + expected_sha256.removeprefix("sha256:")[:32].upper()
    if (
        document != {**expected_body, "checkpoint_id": expected_id}
        or _canonical_json(document) != row["checkpoint_json"]
        or row["checkpoint_id"] != expected_id
        or row["checkpoint_sha256"] != expected_sha256
        or row["request_id"] != request.request_id
        or row["request_sha256"] != request.request_sha256
        or row["claim_id"] != claim.claim_id
        or row["claim_sha256"] != claim.claim_sha256
        or row["checkpoint_kind"] != checkpoint_kind
        or row["captured_at"] != captured_at
    ):
        raise StoreIntegrityError("Execution authority checkpoint is inconsistent")
    return high_water


def _require_checkpoint_progression(
    claim: Mapping[str, Any],
    dispatch: Mapping[str, Any],
) -> None:
    monotonic_fields = (
        ("mission", "revision"),
        ("control", "version"),
        ("trust", "trust_policy_version"),
        ("principal", "assertion_count"),
        ("principal", "effect_count"),
        ("scope", "signed_revocation_count"),
        ("plan", "plan_version"),
        ("mission_policy", "policy_version"),
        ("ownership", "sequence"),
        ("session", "fence_generation"),
        ("source_bundle", "head_sequence"),
        ("budget", "policy_binding_count"),
        ("budget", "event_count"),
        ("workspace", "workspace_revision"),
        ("workspace", "event_count"),
    )
    if any(dispatch[section][field] < claim[section][field] for section, field in monotonic_fields):
        raise StoreIntegrityError("Dispatch authority checkpoint regressed")
    claim_sources = {
        item["source_kind"]: item
        for item in claim["source_heads"]["items"]
    }
    dispatch_sources = {
        item["source_kind"]: item
        for item in dispatch["source_heads"]["items"]
    }
    if set(claim_sources) != set(dispatch_sources) or any(
        dispatch_sources[kind]["head_sequence"]
        < claim_sources[kind]["head_sequence"]
        for kind in claim_sources
    ):
        raise StoreIntegrityError("Dispatch source-head checkpoint regressed")


def _verify_reconciliation_row(
    connection: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    request: ActionExecutionRequest,
    claim: ActionExecutionClaim,
    execute_authorization: Mapping[str, Any],
    dispatch: sqlite3.Row | None,
    abort: sqlite3.Row | None,
    preinvocation_abort: sqlite3.Row | None,
    terminal: ActionExecutionTerminal,
) -> None:
    if type(row["reconciliation_json"]) is not str or type(row["authorization_json"]) is not str:
        raise StoreIntegrityError("Execution reconciliation JSON type is invalid")
    try:
        record = json.loads(row["reconciliation_json"])
        intent = ActionExecutionReconciliationIntent.from_dict(record["intent"])
        authorization = _parse_reconciliation_authorization(
            json.loads(row["authorization_json"])
        )
        _validate_reconciliation_authorization_binding(
            intent,
            authorization,
            checked_at=row["reconciled_at"],
        )
    except Exception as exc:
        raise StoreIntegrityError("Stored execution reconciliation is invalid") from exc
    intent_document = intent.to_dict()
    central = connection.execute(
        "SELECT * FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ? "
        "AND mission_id = ?",
        (row["assertion_issuer"], row["assertion_id"], row["mission_id"]),
    ).fetchone()
    effect = connection.execute(
        "SELECT * FROM principal_assertion_effects WHERE mission_id = ? AND "
        "effect_kind = ? AND effect_id = ?",
        (row["mission_id"], ACTION_EXECUTION_RECONCILE, row["reconciliation_id"]),
    ).fetchone()
    if central is None or effect is None:
        raise StoreIntegrityError("Execution reconciliation authority is absent")
    trust = {
        "trust_policy_id": central["trust_policy_id"],
        "trust_policy_version": central["trust_policy_version"],
        "trust_policy_hash": central["trust_policy_hash"],
    }
    _verify_historical_principal_credential(
        connection,
        central=central,
        checked_at=row["reconciled_at"],
        expected_operation=ACTION_EXECUTION_RECONCILE,
        trust=trust,
    )
    use_sequence = central["use_sequence"]
    signed_intent = compute_operation_intent_hash(
        PrincipalOperation.ACTION_EXECUTION_RECONCILE,
        {
            "action_intent_sha256": intent.reconciliation_intent_sha256,
            "idempotency_key_sha256": authorization[
                "canonical_replay_key_sha256"
            ],
            "mission_id": authorization["mission_id"],
            "principal_profile_id": authorization["principal_profile_id"],
            "role": authorization["role"],
        },
    )
    eligible_plans: list[tuple[int, sqlite3.Row]] = []
    for candidate in connection.execute(
        "SELECT * FROM collaboration_plan_activations WHERE mission_id = ? "
        "ORDER BY plan_version",
        (row["mission_id"],),
    ).fetchall():
        if max(
            _plan_authority_use_sequences(
                connection,
                mission_id=row["mission_id"],
                plan=candidate,
            )
        ) <= use_sequence:
            eligible_plans.append((candidate["plan_version"], candidate))
    selected_plan = max(eligible_plans, default=None, key=lambda item: item[0])
    eligible_policies: list[tuple[int, sqlite3.Row]] = []
    for candidate in connection.execute(
        "SELECT * FROM collaboration_mission_policy_commits WHERE mission_id = ? "
        "ORDER BY policy_version",
        (row["mission_id"],),
    ).fetchall():
        policy_uses = []
        for issuer_field, assertion_field in (
            ("owner_issuer", "owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
        ):
            use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE mission_id = ? "
                "AND issuer = ? AND assertion_id = ?",
                (row["mission_id"], candidate[issuer_field], candidate[assertion_field]),
            ).fetchone()
            if use is None:
                raise StoreIntegrityError("Reconciliation policy authority is absent")
            policy_uses.append(use["use_sequence"])
        if max(policy_uses) <= use_sequence:
            eligible_policies.append((candidate["policy_version"], candidate))
    selected_policy = max(eligible_policies, default=None, key=lambda item: item[0])
    if selected_plan is None or selected_policy is None:
        raise StoreIntegrityError("Reconciliation plan or policy history is absent")
    try:
        policy_document = json.loads(selected_policy[1]["policy_json"])
    except json.JSONDecodeError as exc:
        raise StoreIntegrityError("Reconciliation policy JSON is invalid") from exc
    control_binding = policy_document.get("approval_bindings", {}).get(
        "independent_control"
    )
    control_principal = (
        None
        if not isinstance(control_binding, dict)
        else connection.execute(
            "SELECT issuer, subject, principal_profile_id FROM principal_assertion_uses "
            "WHERE mission_id = ? AND assertion_id = ? AND assertion_hash = ? "
            "AND principal_profile_id = ?",
            (
                row["mission_id"],
                control_binding.get("assertion_id"),
                control_binding.get("assertion_sha256"),
                control_binding.get("profile_id"),
            ),
        ).fetchone()
    )
    receipt_row = connection.execute(
        "SELECT resolution_json FROM action_admission_receipts WHERE receipt_id = ?",
        (request.to_dict()["admission_receipt"]["receipt_id"],),
    ).fetchone()
    try:
        resolution = json.loads(receipt_row["resolution_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise StoreIntegrityError(
            "Reconciliation resolution source is invalid"
        ) from exc
    eligible_ownership: list[tuple[int, sqlite3.Row]] = []
    for candidate in connection.execute(
        "SELECT * FROM collaboration_ownership_chain_entries WHERE plan_id = ? "
        "AND work_item_id = ? ORDER BY sequence",
        (selected_plan[1]["plan_id"], resolution["proposal_work_id"]),
    ).fetchall():
        authority_sequences: list[int] = []
        for issuer_field, assertion_field in (
            ("current_owner_issuer", "current_owner_assertion_id"),
            ("proposed_owner_issuer", "proposed_owner_assertion_id"),
            ("control_issuer", "control_assertion_id"),
            ("second_authority_issuer", "second_authority_assertion_id"),
        ):
            if candidate[issuer_field] is None:
                continue
            authority_use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE "
                "mission_id = ? AND issuer = ? AND assertion_id = ?",
                (
                    row["mission_id"],
                    candidate[issuer_field],
                    candidate[assertion_field],
                ),
            ).fetchone()
            if authority_use is None:
                raise StoreIntegrityError(
                    "Reconciliation ownership authority is absent"
                )
            authority_sequences.append(authority_use["use_sequence"])
        if authority_sequences and max(authority_sequences) <= use_sequence:
            eligible_ownership.append((candidate["sequence"], candidate))
    selected_ownership = max(
        eligible_ownership,
        default=None,
        key=lambda item: item[0],
    )
    current_owner_profile_id = (
        resolution["proposal_producer_profile_id"]
        if selected_ownership is None
        else selected_ownership[1]["to_owner_id"]
    )
    scope_state = connection.execute(
        "SELECT * FROM mission_scope_revocation_baselines WHERE mission_id = ?",
        (row["mission_id"],),
    ).fetchone()
    scope_prefix = connection.execute(
        "SELECT entry_hash FROM mission_scope_grant_revocations WHERE mission_id = ? "
        "AND revocation_sequence = ?",
        (row["mission_id"], intent_document["scope_revocation_count"]),
    ).fetchone()
    expected_scope_head = (
        scope_state["baseline_root_hash"]
        if scope_state is not None and intent_document["scope_revocation_count"] == 0
        else None if scope_prefix is None else scope_prefix["entry_hash"]
    )
    revoked = connection.execute(
        "SELECT 1 FROM mission_scope_grant_revocations WHERE mission_id = ? AND "
        "scope_grant_hash = ? AND revocation_sequence <= ? LIMIT 1",
        (
            row["mission_id"],
            central["scope_grant_hash"],
            intent_document["scope_revocation_count"],
        ),
    ).fetchone()
    terminal_document = terminal.to_dict()
    expected_record = _record(
        "reconciliation",
        "AXR",
        RECONCILIATION_DOMAIN,
        {
            "schema_version": 1,
            "kind": "action_execution_reconciliation",
            "intent": intent_document,
            "terminal_id": terminal.terminal_id,
            "terminal_sha256": terminal.terminal_sha256,
            "assertion_issuer": central["issuer"],
            "assertion_id": central["assertion_id"],
            "assertion_sha256": central["assertion_hash"],
            "authorization": authorization,
            "reconciled_at": terminal_document["settled_at"],
        },
    )
    expected_effect_json = _canonical_json(
        _action_principal_effect(
            operation=ACTION_EXECUTION_RECONCILE,
            effect_id=row["reconciliation_id"],
            payload=expected_record,
            recorded_at=row["reconciled_at"],
        )
    )
    mode = intent_document["reconciliation_mode"]
    expected_dispatch_id = _dispatch_id(request, claim)
    dispatch_matches = (
        dispatch is not None
        and dispatch["dispatch_id"] == expected_dispatch_id
        and dispatch["dispatch_sha256"] == intent_document["dispatch_sha256"]
    )
    abort_matches = (
        abort is not None
        and abort["dispatch_id"] == expected_dispatch_id
        and abort["reason_code"] == intent_document["reason_code"]
        and abort["aborted_at"] == terminal_document["settled_at"]
    )
    preinvocation_abort_matches = (
        preinvocation_abort is not None
        and dispatch_matches
        and preinvocation_abort["dispatch_id"] == expected_dispatch_id
        and preinvocation_abort["dispatch_sha256"]
        == intent_document["dispatch_sha256"]
        and preinvocation_abort["reason_code"]
        == intent_document["reason_code"]
        and preinvocation_abort["aborted_at"]
        == terminal_document["settled_at"]
        and preinvocation_abort["health_decision_id"] is None
        and preinvocation_abort["health_decision_sha256"] is None
        and preinvocation_abort["health_decision_json"] is None
    )
    invocation_count = 0
    health_use_table_available = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'action_target_health_gate_uses'"
    ).fetchone() is not None
    if dispatch is not None and health_use_table_available:
        invocation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM action_target_health_gate_uses "
                "WHERE use_kind = ? AND consumer_id = ? "
                "AND consumer_sha256 = ?",
                (
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION.value,
                    dispatch["dispatch_id"],
                    dispatch["dispatch_sha256"],
                ),
            ).fetchone()[0]
        )
    execution_baseline_available = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = "
        "'action_execution_target_health_gate_legacy_baselines'"
    ).fetchone() is not None
    baseline_request = (
        not execution_baseline_available
        or _is_execution_health_cutover_baseline_request(connection, request)
    )
    if (
        record != expected_record
        or _canonical_json(record) != row["reconciliation_json"]
        or effect["issuer"] != central["issuer"]
        or effect["assertion_id"] != central["assertion_id"]
        or effect["effect_index"] != 1
        or effect["effect_json"] != expected_effect_json
        or effect["effect_hash"] != sha256_text(expected_effect_json)
        or effect["recorded_at"] != row["reconciled_at"]
        or central["effects_hash"]
        != principal_assertion_effects_hash((effect["effect_hash"],))
        or row["reconciliation_id"] != expected_record["reconciliation_id"]
        or row["reconciliation_sha256"] != expected_record["reconciliation_sha256"]
        or row["request_id"] != request.request_id
        or row["request_sha256"] != request.request_sha256
        or row["claim_id"] != claim.claim_id
        or row["claim_sha256"] != claim.claim_sha256
        or row["dispatch_id"] != intent_document["dispatch_id"]
        or row["dispatch_sha256"] != intent_document["dispatch_sha256"]
        or intent_document["dispatch_id"] != expected_dispatch_id
        or row["terminal_id"] != terminal.terminal_id
        or row["terminal_sha256"] != terminal.terminal_sha256
        or row["operation"] != ACTION_EXECUTION_RECONCILE
        or row["operation_intent_sha256"] != intent.reconciliation_intent_sha256
        or row["canonical_replay_key_sha256"]
        != authorization["canonical_replay_key_sha256"]
        or row["assertion_sha256"] != authorization["assertion_sha256"]
        or row["authority_use_sequence"] != use_sequence
        or row["scope_revocation_count"]
        != intent_document["scope_revocation_count"]
        or row["scope_revocation_head_sha256"]
        != intent_document["scope_revocation_head_sha256"]
        or row["authorization_json"] != _canonical_json(authorization)
        or row["reconciliation_mode"] != mode
        or row["reason_code"] != intent_document["reason_code"]
        or row["reconciled_at"] != terminal_document["settled_at"]
        or central["operation"] != ACTION_EXECUTION_RECONCILE
        or central["issuer"] != authorization["assertion_issuer"]
        or central["assertion_id"] != authorization["assertion_id"]
        or central["assertion_hash"] != authorization["assertion_sha256"]
        or central["key_hash"] != authorization["assertion_key_sha256"]
        or central["trust_policy_hash"] != authorization["trust_policy_sha256"]
        or central["scope_grant_hash"] != authorization["scope_grant_sha256"]
        or central["subject"] != authorization["principal_subject"]
        or central["principal_profile_id"]
        != authorization["principal_profile_id"]
        or central["signed_intent_hash"] != signed_intent
        or central["issued_at"] != authorization["issued_at"]
        or central["domain_request_hash"] != intent.reconciliation_intent_sha256
        or central["idempotency_key_hash"]
        != authorization["canonical_replay_key_sha256"]
        or central["consumed_at"] != row["reconciled_at"]
        or selected_plan[1]["plan_id"] != intent_document["active_plan_id"]
        or selected_plan[1]["plan_sha256"] != intent_document["active_plan_sha256"]
        or selected_policy[1]["policy_id"]
        != intent_document["collaboration_policy_id"]
        or selected_policy[1]["policy_sha256"]
        != intent_document["collaboration_policy_sha256"]
        or selected_policy[1]["plan_id"] != selected_plan[1]["plan_id"]
        or not (
            policy_document["effective_at"]
            <= row["reconciled_at"]
            < policy_document["expires_at"]
        )
        or control_principal is None
        or authorization["role"] != "independent_control"
        or authorization["principal_profile_id"] != control_binding["profile_id"]
        or authorization["assertion_issuer"] != control_principal["issuer"]
        or authorization["principal_subject"] != control_principal["subject"]
        or authorization["principal_profile_id"]
        == execute_authorization["principal_profile_id"]
        or authorization["principal_subject"]
        == execute_authorization["principal_subject"]
        or authorization["principal_profile_id"]
        in {
            current_owner_profile_id,
            resolution["proposal_producer_profile_id"],
            resolution["resolver_profile_id"],
        }
        or authorization["operation_intent_sha256"]
        != intent.reconciliation_intent_sha256
        or authorization["expires_at"] != intent_document["authority_expires_at"]
        or not (
            execute_authorization["expires_at"]
            <= intent_document["prepared_at"]
            <= authorization["issued_at"]
            <= row["reconciled_at"]
            < authorization["expires_at"]
        )
        or central["expires_at"] != authorization["expires_at"]
        or scope_state is None
        or scope_state["signed_revocation_count"]
        < intent_document["scope_revocation_count"]
        or expected_scope_head != intent_document["scope_revocation_head_sha256"]
        or revoked is not None
        or mode == "predispatch_abort"
        and (
            (
                intent_document["dispatch_sha256"] is None
                and (
                    dispatch is not None
                    or not abort_matches
                    or preinvocation_abort is not None
                )
            )
            or (
                intent_document["dispatch_sha256"] is not None
                and (
                    not preinvocation_abort_matches
                    or abort is not None
                    or invocation_count != 0
                    or baseline_request
                )
            )
        )
        or mode == "dispatched_indeterminate"
        and (
            not dispatch_matches
            or abort is not None
            or preinvocation_abort is not None
            or not baseline_request
            and invocation_count != 1
        )
        or intent_document["terminal_status"] != terminal_document["terminal_status"]
        or intent_document["action_outcome"] != terminal_document["action_outcome"]
        or intent_document["evidence_status"] != terminal_document["evidence_status"]
        or intent_document["cleanup_status"] != terminal_document["cleanup_status"]
        or intent_document["restoration_status"]
        != terminal_document["restoration_status"]
        or intent_document["reason_code"] != terminal_document["reason_code"]
        or intent_document["charged_resources"] != terminal_document["charged_resources"]
        or intent_document["adapter_call_count_status"]
        != terminal_document["adapter_call_count_status"]
        or intent_document["adapter_call_count"]
        != terminal_document["adapter_call_count"]
    ):
        raise StoreIntegrityError("Execution reconciliation custody is inconsistent")


def verify_authenticated_action_execution_store(
    connection: sqlite3.Connection,
) -> dict[str, int | str]:
    """Reconstruct and verify all schema34 action execution custody."""

    preinvocation_abort_table_available = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'action_execution_preinvocation_aborts'"
    ).fetchone() is not None
    requests = connection.execute(
        "SELECT * FROM action_execution_requests ORDER BY request_id"
    ).fetchall()
    for mission_id in {
        str(item["mission_id"])
        for item in requests
        if type(item["mission_id"]) is str
    }:
        verify_authenticated_action_admission_store(
            connection,
            mission_id=mission_id,
        )
        verify_action_authority_repository(
            connection,
            mission_id=mission_id,
            require_current_sources=False,
        )
    terminal_count = 0
    dispatch_count = 0
    abort_count = 0
    preinvocation_abort_count = 0
    reconciliation_count = 0
    for row in requests:
        if type(row["request_json"]) is not str:
            raise StoreIntegrityError("Execution request JSON type is invalid")
        try:
            raw_request = json.loads(row["request_json"])
            request = parse_action_execution_request(raw_request)
        except Exception as exc:
            raise StoreIntegrityError("Stored execution request is invalid") from exc
        document = request.to_dict()
        receipt = document["admission_receipt"]
        custody_row = {
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "tenant_id": receipt["tenant_id"],
            "mission_id": receipt["mission_id"],
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "idempotency_key_sha256": document["idempotency_key_sha256"],
            "command_sha256": document["command_sha256"],
            "request_json": _canonical_json(document),
            "authority_state_sha256": document["authority_state_sha256"],
            "prepared_at": document["prepared_at"],
        }
        if any(row[field] != value for field, value in custody_row.items()):
            raise StoreIntegrityError("Execution request columns are inconsistent")
        basis = _historical_execution_basis(connection, request)
        claim_row = connection.execute(
            "SELECT * FROM action_execution_claims WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        authority = connection.execute(
            "SELECT * FROM action_execution_authority_consumptions "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        reservation = connection.execute(
            "SELECT * FROM action_execution_reservations WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        admission_use = connection.execute(
            "SELECT * FROM action_admission_execution_consumptions "
            "WHERE execution_id = ?",
            (request.request_id,),
        ).fetchone()
        if None in (claim_row, authority, reservation, admission_use):
            raise StoreIntegrityError("Execution claim custody is incomplete")
        if type(claim_row["claim_json"]) is not str:
            raise StoreIntegrityError("Execution claim JSON type is invalid")
        claim = parse_action_execution_claim(json.loads(claim_row["claim_json"]))
        claim_document = claim.to_dict()
        claim_checkpoint_row = connection.execute(
            "SELECT * FROM action_execution_authority_checkpoints WHERE "
            "request_id = ? AND checkpoint_kind = 'claim'",
            (request.request_id,),
        ).fetchone()
        claim_high_water = _parse_authority_checkpoint(
            connection,
            claim_checkpoint_row,
            checkpoint_kind="claim",
            request=request,
            claim=claim,
            captured_at=claim_document["claimed_at"],
        )
        expected_claim_custody_sha256 = _canonical_sha256(
            {
                "custody": {
                    "authority_checkpoint_id": claim_checkpoint_row["checkpoint_id"],
                    "authority_checkpoint_sha256": claim_checkpoint_row[
                        "checkpoint_sha256"
                    ],
                    "claim": claim_document,
                    "dispatch_id": claim_row["dispatch_id"],
                    "request_id": request.request_id,
                    "request_sha256": request.request_sha256,
                },
                "domain": CLAIM_CUSTODY_DOMAIN,
            }
        )
        if (
            _canonical_json(claim_document) != claim_row["claim_json"]
            or claim.claim_id != claim_row["claim_id"]
            or claim.claim_sha256 != claim_row["claim_sha256"]
            or claim_document["request_id"] != request.request_id
            or claim_document["request_sha256"] != request.request_sha256
            or claim_document["claimed_at"] != claim_row["claimed_at"]
            or claim_document["claim_status"] != claim_row["claim_status"]
            or claim_row["dispatch_id"] != _dispatch_id(request, claim)
            or claim_row["authority_checkpoint_id"]
            != claim_checkpoint_row["checkpoint_id"]
            or claim_row["authority_checkpoint_sha256"]
            != claim_checkpoint_row["checkpoint_sha256"]
            or claim_row["custody_sha256"] != expected_claim_custody_sha256
            or document["prepared_at"] > claim_document["claimed_at"]
        ):
            raise StoreIntegrityError("Execution claim columns are inconsistent")
        command = ActionExecutionCommand(
            receipt_id=receipt["receipt_id"],
            idempotency_key_sha256=document["idempotency_key_sha256"],
        )
        expected_custody_sha256 = _canonical_sha256(
            {
                "custody": {
                    "claim": claim_document,
                    "command": command.to_dict(),
                    "command_sha256": command.command_sha256,
                    "request": document,
                },
                "domain": CUSTODY_DOMAIN,
            }
        )
        if (
            command.command_sha256 != document["command_sha256"]
            or row["custody_sha256"] != expected_custody_sha256
        ):
            raise StoreIntegrityError("Execution request custody hash is inconsistent")
        authorization = _parse_authorization(claim_document["authorization"])
        expected_principal = basis["policy"]["admission_control"]
        if (
            type(authority["authorization_json"]) is not str
            or _canonical_json(authorization) != authority["authorization_json"]
            or _canonical_json(authorization) != claim_row["authorization_json"]
            or authority["assertion_issuer"] != authorization["assertion_issuer"]
            or authority["assertion_id"] != authorization["assertion_id"]
            or authority["mission_id"] != authorization["mission_id"]
            or authority["assertion_sha256"] != authorization["assertion_sha256"]
            or authority["canonical_replay_key_sha256"]
            != authorization["canonical_replay_key_sha256"]
            or authority["operation"] != ACTION_EXECUTE
            or authority["operation_intent_sha256"]
            != authorization["operation_intent_sha256"]
            or authority["consumed_at"] != claim_document["claimed_at"]
            or authorization["operation"] != ACTION_EXECUTE
            or authorization["role"] != "admission_control"
            or authorization["request_sha256"] != request.request_sha256
            or authorization["receipt_sha256"] != receipt["receipt_sha256"]
            or authorization["tenant_id"] != receipt["tenant_id"]
            or authorization["mission_id"] != receipt["mission_id"]
            or authorization["scope_sha256"] != receipt["scope_sha256"]
            or authorization["target_sha256"] != receipt["target_sha256"]
            or authorization["action_sha256"] != receipt["action_sha256"]
            or authorization["assertion_issuer"]
            != expected_principal["assertion_issuer"]
            or authorization["principal_profile_id"]
            != expected_principal["principal_profile_id"]
            or authorization["principal_subject"]
            != expected_principal["principal_subject"]
            or authorization["operation_intent_sha256"]
            != action_execute_authorization_intent_sha256(request)
            or not (
                authorization["issued_at"]
                <= claim_document["claimed_at"]
                < authorization["expires_at"]
            )
            or not (
                basis["policy"]["effective_at"]
                <= claim_document["claimed_at"]
                < basis["policy"]["expires_at"]
            )
            or not (
                basis["bundle"]["observed_at"]
                <= claim_document["claimed_at"]
                < basis["bundle"]["valid_until"]
            )
            or not (
                basis["material"]["observed_at"]
                <= claim_document["claimed_at"]
                < basis["material"]["valid_until"]
            )
        ):
            raise StoreIntegrityError("Execution authority custody is inconsistent")
        central = connection.execute(
            "SELECT * FROM principal_assertion_uses "
            "WHERE issuer = ? AND assertion_id = ? AND mission_id = ?",
            (
                authority["assertion_issuer"],
                authority["assertion_id"],
                authority["mission_id"],
            ),
        ).fetchone()
        effect = connection.execute(
            "SELECT * FROM principal_assertion_effects "
            "WHERE issuer = ? AND assertion_id = ? AND mission_id = ? "
            "AND effect_kind = ? AND effect_id = ?",
            (
                authority["assertion_issuer"],
                authority["assertion_id"],
                authority["mission_id"],
                ACTION_EXECUTE,
                request.request_id,
            ),
        ).fetchone()
        signed_intent = compute_operation_intent_hash(
            PrincipalOperation.ACTION_EXECUTE,
            {
                "action_intent_sha256": authorization[
                    "operation_intent_sha256"
                ],
                "idempotency_key_sha256": authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "role": authorization["role"],
            },
        )
        expected_effect_json = _canonical_json(
            _action_principal_effect(
                operation=ACTION_EXECUTE,
                effect_id=request.request_id,
                payload=authorization,
                recorded_at=claim_document["claimed_at"],
            )
        )
        expected_effect_hash = sha256_text(expected_effect_json)
        if (
            central is None
            or effect is None
            or central["operation"] != ACTION_EXECUTE
            or central["signed_intent_hash"] != signed_intent
            or central["domain_request_hash"]
            != authorization["operation_intent_sha256"]
            or central["idempotency_key_hash"]
            != authorization["canonical_replay_key_sha256"]
            or central["assertion_hash"] != authorization["assertion_sha256"]
            or central["principal_profile_id"]
            != authorization["principal_profile_id"]
            or central["subject"] != authorization["principal_subject"]
            or central["key_hash"] != authorization["assertion_key_sha256"]
            or central["scope_grant_hash"] != authorization["scope_grant_sha256"]
            or central["trust_policy_hash"] != authorization["trust_policy_sha256"]
            or central["consumed_at"] != claim_document["claimed_at"]
            or effect["effect_index"] != 1
            or effect["effect_json"] != expected_effect_json
            or effect["effect_hash"] != expected_effect_hash
            or effect["recorded_at"] != claim_document["claimed_at"]
            or central["effects_hash"]
            != principal_assertion_effects_hash((expected_effect_hash,))
        ):
            raise StoreIntegrityError("Central ACTION_EXECUTE custody is inconsistent")
        _verify_historical_execution_currentness(
            connection,
            request=request,
            basis=basis,
            authorization=authorization,
            central=central,
            checked_at=claim_document["claimed_at"],
            high_water=claim_high_water,
        )
        reserved = {field: reservation[field] for field in RESOURCE_FIELDS}
        link = connection.execute(
            "SELECT * FROM action_budget_receipt_reservations "
            "WHERE receipt_id = ?",
            (receipt["receipt_id"],),
        ).fetchone()
        if (
            link is None
            or type(link["resources_json"]) is not str
            or json.loads(link["resources_json"]) != reserved
            or document["reservation"] != reserved
            or reservation["receipt_id"] != receipt["receipt_id"]
            or reservation["account_id"] != link["account_id"]
            or reservation["reservation_id"] != link["reservation_id"]
            or reservation["reservation_sha256"] != link["reservation_sha256"]
            or reservation["budget_revision_id"] != link["budget_revision_id"]
            or reservation["budget_revision_sha256"]
            != link["budget_revision_sha256"]
            or admission_use["receipt_id"] != receipt["receipt_id"]
            or admission_use["claim_id"] != claim.claim_id
            or admission_use["claim_sha256"] != claim.claim_sha256
            or admission_use["execution_intent_sha256"]
            != action_execute_authorization_intent_sha256(request)
            or claim_document["claimed_at"] != admission_use["consumed_at"]
            or reservation["reserved_at"] != claim_document["claimed_at"]
        ):
            raise StoreIntegrityError("Execution reservation lineage is inconsistent")
        dispatch = connection.execute(
            "SELECT * FROM action_execution_dispatch_attempts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        abort = connection.execute(
            "SELECT * FROM action_execution_predispatch_aborts "
            "WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        preinvocation_abort = (
            connection.execute(
                "SELECT * FROM action_execution_preinvocation_aborts "
                "WHERE request_id = ?",
                (request.request_id,),
            ).fetchone()
            if preinvocation_abort_table_available
            else None
        )
        if abort is not None and preinvocation_abort is not None:
            raise StoreIntegrityError("Execution has conflicting abort custody")
        if abort is not None and dispatch is not None:
            raise StoreIntegrityError(
                "Predispatch abort conflicts with committed dispatch custody"
            )
        if preinvocation_abort is not None and dispatch is None:
            raise StoreIntegrityError(
                "Preinvocation abort lacks committed dispatch custody"
            )
        if dispatch is not None:
            dispatch_count += 1
            if type(dispatch["dispatch_json"]) is not str:
                raise StoreIntegrityError("Dispatch attempt JSON type is invalid")
            dispatch_document = json.loads(dispatch["dispatch_json"])
            dispatch_checkpoint_row = connection.execute(
                "SELECT * FROM action_execution_authority_checkpoints WHERE "
                "request_id = ? AND checkpoint_kind = 'dispatch'",
                (request.request_id,),
            ).fetchone()
            dispatch_high_water = _parse_authority_checkpoint(
                connection,
                dispatch_checkpoint_row,
                checkpoint_kind="dispatch",
                request=request,
                claim=claim,
                captured_at=dispatch["attempted_at"],
            )
            dispatch_body = dict(dispatch_document)
            expected_dispatch_sha256 = _canonical_sha256(
                {"domain": DISPATCH_DOMAIN, "record": dispatch_body}
            )
            if (
                _canonical_json(dispatch_document) != dispatch["dispatch_json"]
                or dispatch["dispatch_id"] != claim_row["dispatch_id"]
                or dispatch_document["dispatch_id"] != dispatch["dispatch_id"]
                or dispatch["request_id"] != request.request_id
                or dispatch["claim_id"] != claim.claim_id
                or dispatch["authority_checkpoint_id"]
                != dispatch_checkpoint_row["checkpoint_id"]
                or dispatch["authority_checkpoint_sha256"]
                != dispatch_checkpoint_row["checkpoint_sha256"]
                or dispatch_document["authority_checkpoint_id"]
                != dispatch_checkpoint_row["checkpoint_id"]
                or dispatch_document["authority_checkpoint_sha256"]
                != dispatch_checkpoint_row["checkpoint_sha256"]
                or dispatch_document["authority_high_water"]
                != dispatch_high_water
                or dispatch_document["authority_high_water_sha256"]
                != dispatch_checkpoint_row["high_water_sha256"]
                or dispatch["authority_high_water_json"]
                != dispatch_checkpoint_row["high_water_json"]
                or dispatch["authority_high_water_sha256"]
                != dispatch_checkpoint_row["high_water_sha256"]
                or dispatch["dispatch_sha256"] != expected_dispatch_sha256
                or dispatch_document["request_id"] != request.request_id
                or dispatch_document["request_sha256"] != request.request_sha256
                or dispatch_document["claim_id"] != claim.claim_id
                or dispatch_document["claim_sha256"] != claim.claim_sha256
                or dispatch_document["adapter_binding_sha256"]
                != _adapter_binding_sha256(
                    AdapterBinding.from_dict(document["adapter"])
                )
                or dispatch["adapter_binding_sha256"]
                != dispatch_document["adapter_binding_sha256"]
                or claim_document["claimed_at"] > dispatch["attempted_at"]
                or dispatch_document["attempted_at"] != dispatch["attempted_at"]
                or dispatch_document["attempt_status"] != dispatch["attempt_status"]
                or not (
                    dispatch["attempted_at"] < authorization["expires_at"]
                    and dispatch["attempted_at"]
                    < basis["admission_request"]["expires_at"]
                    and dispatch["attempted_at"]
                    < basis["admission_request"]["worker_session"]["expires_at"]
                    and dispatch["attempted_at"]
                    < basis["admission_request"]["credential_lease"]["expires_at"]
                    and dispatch["attempted_at"]
                    < basis["admission_request"]["health"]["expires_at"]
                    and dispatch["attempted_at"] < basis["bundle"]["valid_until"]
                    and dispatch["attempted_at"] < basis["material"]["valid_until"]
                )
            ):
                raise StoreIntegrityError("Dispatch attempt custody is inconsistent")
            _verify_historical_execution_currentness(
                connection,
                request=request,
                basis=basis,
                authorization=authorization,
                central=central,
                checked_at=dispatch["attempted_at"],
                high_water=dispatch_high_water,
            )
            _require_checkpoint_progression(claim_high_water, dispatch_high_water)
        elif connection.execute(
            "SELECT 1 FROM action_execution_authority_checkpoints WHERE "
            "request_id = ? AND checkpoint_kind = 'dispatch'",
            (request.request_id,),
        ).fetchone() is not None:
            raise StoreIntegrityError("Execution dispatch checkpoint is orphaned")
        if abort is not None:
            abort_count += 1
            if type(abort["abort_json"]) is not str:
                raise StoreIntegrityError("Predispatch abort JSON type is invalid")
            try:
                abort_document = json.loads(abort["abort_json"])
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError("Predispatch abort JSON is invalid") from exc
            abort_body = dict(abort_document)
            expected_abort_sha256 = _canonical_sha256(
                {"domain": PREDISPATCH_ABORT_DOMAIN, "record": abort_body}
            )
            expected_abort_id = (
                "AXA-"
                + expected_abort_sha256.removeprefix("sha256:")[:32].upper()
            )
            expected_abort = {
                "schema_version": 1,
                "kind": "action_execution_predispatch_abort",
                "request_id": request.request_id,
                "request_sha256": request.request_sha256,
                "claim_id": claim.claim_id,
                "claim_sha256": claim.claim_sha256,
                "dispatch_id": claim_row["dispatch_id"],
                "receipt_id": receipt["receipt_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "assertion_issuer": authority["assertion_issuer"],
                "assertion_id": authority["assertion_id"],
                "assertion_sha256": authority["assertion_sha256"],
                "reason_code": abort["reason_code"],
                "aborted_at": abort["aborted_at"],
                "abort_status": "authenticated_no_dispatch_release",
            }
            if (
                abort_document != expected_abort
                or _canonical_json(abort_document) != abort["abort_json"]
                or abort["abort_id"] != expected_abort_id
                or abort["abort_sha256"] != expected_abort_sha256
                or abort["request_sha256"] != request.request_sha256
                or abort["claim_id"] != claim.claim_id
                or abort["claim_sha256"] != claim.claim_sha256
                or abort["dispatch_id"] != claim_row["dispatch_id"]
                or abort["receipt_id"] != receipt["receipt_id"]
                or abort["receipt_sha256"] != receipt["receipt_sha256"]
                or abort["assertion_issuer"] != authority["assertion_issuer"]
                or abort["assertion_id"] != authority["assertion_id"]
                or abort["assertion_sha256"] != authority["assertion_sha256"]
                or abort["abort_status"] != "authenticated_no_dispatch_release"
                or abort["aborted_at"] < claim_document["claimed_at"]
            ):
                raise StoreIntegrityError("Predispatch abort custody is inconsistent")
        if preinvocation_abort is not None:
            preinvocation_abort_count += 1
            pre_document = json.loads(preinvocation_abort["abort_json"])
            pre_body = {
                field: value
                for field, value in pre_document.items()
                if field not in {"abort_id", "abort_sha256"}
            }
            pre_sha256 = _canonical_sha256(
                {"domain": PREINVOCATION_ABORT_DOMAIN, "record": pre_body}
            )
            pre_id = "AXN-" + pre_sha256.removeprefix("sha256:")[:32].upper()
            exact_preinvocation_fields = {
                "schema_version",
                "kind",
                "abort_id",
                "abort_sha256",
                "request_id",
                "request_sha256",
                "claim_id",
                "claim_sha256",
                "dispatch_id",
                "dispatch_sha256",
                "invocation_use_id",
                "invocation_use_sha256",
                "health_decision_id",
                "health_decision_sha256",
                "health_decision_json",
                "reason_code",
                "aborted_at",
                "abort_status",
            }
            decision_json = preinvocation_abort["health_decision_json"]
            decision = None
            decision_lineage_valid = True
            if decision_json is not None:
                try:
                    decision = TargetHealthGateDecision.from_dict(
                        json.loads(decision_json)
                    )
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise StoreIntegrityError(
                        "Preinvocation health decision is invalid"
                    ) from exc
                if _canonical_json(decision.to_dict()) != decision_json:
                    raise StoreIntegrityError(
                        "Preinvocation health decision is not canonical"
                    )
                observation_row = connection.execute(
                    "SELECT * FROM target_health_gate_observations "
                    "WHERE observation_id = ? AND observation_sha256 = ?",
                    (
                        decision.current_observation.observation_id,
                        decision.current_observation.observation_sha256,
                    ),
                ).fetchone()
                transition_row = connection.execute(
                    "SELECT * FROM target_health_gate_transitions "
                    "WHERE subject_id = ? AND observation_id = ? "
                    "AND observation_sha256 = ?",
                    (
                        decision.subject.subject_id,
                        decision.current_observation.observation_id,
                        decision.current_observation.observation_sha256,
                    ),
                ).fetchone()
                head_row = connection.execute(
                    "SELECT * FROM target_health_gate_heads "
                    "WHERE subject_id = ?",
                    (decision.subject.subject_id,),
                ).fetchone()
                try:
                    stored_observation = (
                        None
                        if observation_row is None
                        else _observation_from_row(observation_row)
                    )
                    stored_transition = (
                        None
                        if transition_row is None
                        else _transition_from_row(transition_row)
                    )
                    stored_head = (
                        None if head_row is None else _head_from_row(head_row)
                    )
                    admission_request = ActionAdmissionRequest.from_dict(
                        basis["admission_request"]
                    )
                    expected_binding = (
                        MissionStoreAuthenticatedActionAdmissionService
                        ._target_health_binding_from_request(admission_request)
                    )
                except (TypeError, ValueError, StoreIntegrityError):
                    decision_lineage_valid = False
                else:
                    expected_latch_state = (
                        TargetHealthGateState.ACTIVE
                        if decision.status
                        is TargetHealthGateDecisionStatus
                        .PERMIT_HEALTH_GATE_EVALUATION
                        else TargetHealthGateState.PAUSED
                    )
                    decision_lineage_valid = (
                        stored_observation == decision.current_observation
                        and stored_head is not None
                        and stored_head.subject == decision.subject
                        and stored_head.transition_count
                        >= decision.head.transition_count
                        and stored_transition is not None
                        and stored_transition.subject == decision.subject
                        and stored_transition.observation_id
                        == decision.current_observation.observation_id
                        and stored_transition.observation_sha256
                        == decision.current_observation.observation_sha256
                        and stored_transition.transition_sha256
                        == decision.head.transition_head_sha256
                        and stored_transition.to_state
                        is expected_latch_state
                        and stored_transition.transition_sequence
                        == decision.head.transition_count
                        and stored_transition.pause_epoch
                        == decision.head.pause_epoch
                        and stored_transition.recovery_healthy_count
                        == decision.head.recovery_healthy_count
                        and decision.head.latch_state
                        is expected_latch_state
                        and decision.head.observation_count
                        == decision.current_observation.observation_sequence
                        and decision.head.observation_head_sha256
                        == decision.current_observation.observation_sha256
                        and decision.head.last_observation_id
                        == decision.current_observation.observation_id
                        and decision.head.last_observation_sha256
                        == decision.current_observation.observation_sha256
                        and decision.head.last_binding_sha256
                        == decision.current_observation.binding_sha256
                        and decision.head.last_inspection_id
                        == decision.current_observation.inspection_id
                        and decision.head.last_inspection_sha256
                        == decision.current_observation.inspection_sha256
                        and decision.head.updated_at
                        == stored_transition.occurred_at
                        and decision.binding == expected_binding
                        and decision.subject.tenant_id == receipt["tenant_id"]
                        and decision.subject.mission_id == receipt["mission_id"]
                        and decision.subject.scope_sha256
                        == receipt["scope_sha256"]
                        and decision.subject.target_sha256
                        == receipt["target_sha256"]
                        and (
                            decision.evaluated_at
                            == preinvocation_abort["aborted_at"]
                            if decision.status
                            is TargetHealthGateDecisionStatus
                            .DENY_NEW_TARGET_WORK
                            else decision.evaluated_at
                            <= preinvocation_abort["aborted_at"]
                        )
                    )
            invocation_use = None
            if preinvocation_abort["invocation_use_id"] is not None:
                invocation_use = connection.execute(
                    "SELECT * FROM action_target_health_gate_uses "
                    "WHERE use_id = ? AND use_sha256 = ? AND use_kind = ? "
                    "AND consumer_id = ? AND consumer_sha256 = ?",
                    (
                        preinvocation_abort["invocation_use_id"],
                        preinvocation_abort["invocation_use_sha256"],
                        ActionTargetHealthGateUseKind
                        .ACTION_EXECUTION_INVOCATION.value,
                        dispatch["dispatch_id"],
                        dispatch["dispatch_sha256"],
                    ),
                ).fetchone()
            invocation_lineage_valid = (
                invocation_use is not None
                and decision is not None
                and invocation_use["decision_id"] == decision.decision_id
                and invocation_use["decision_sha256"]
                == decision.decision_sha256
                and invocation_use["decision_json"] == decision_json
                and invocation_use["used_at"]
                <= preinvocation_abort["aborted_at"]
            )
            reason_is_health_denial = (
                preinvocation_abort["reason_code"]
                == "target_health_gate_denied_invocation"
            )
            reason_lineage_valid = (
                decision is not None
                and decision.status
                is TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK
                and invocation_use is None
                if reason_is_health_denial
                else (
                    decision is not None
                    and decision.status
                    is TargetHealthGateDecisionStatus
                    .PERMIT_HEALTH_GATE_EVALUATION
                    and invocation_lineage_valid
                    if preinvocation_abort["invocation_use_id"] is not None
                    else decision is None
                )
            )
            if (
                set(pre_document) != exact_preinvocation_fields
                or _canonical_json(pre_document)
                != preinvocation_abort["abort_json"]
                or pre_document != {
                    **pre_body,
                    "abort_id": pre_id,
                    "abort_sha256": pre_sha256,
                }
                or preinvocation_abort["abort_id"] != pre_id
                or preinvocation_abort["abort_sha256"] != pre_sha256
                or preinvocation_abort["request_sha256"] != request.request_sha256
                or preinvocation_abort["claim_id"] != claim.claim_id
                or preinvocation_abort["claim_sha256"] != claim.claim_sha256
                or preinvocation_abort["dispatch_id"] != dispatch["dispatch_id"]
                or preinvocation_abort["dispatch_sha256"]
                != dispatch["dispatch_sha256"]
                or preinvocation_abort["invocation_use_id"]
                != pre_document["invocation_use_id"]
                or preinvocation_abort["invocation_use_sha256"]
                != pre_document["invocation_use_sha256"]
                or preinvocation_abort["aborted_at"] < dispatch["attempted_at"]
                or (
                    decision is None
                    and (
                        preinvocation_abort["health_decision_id"] is not None
                        or preinvocation_abort["health_decision_sha256"] is not None
                    )
                )
                or (
                    decision is not None
                    and (
                        decision.decision_id
                        != preinvocation_abort["health_decision_id"]
                        or decision.decision_sha256
                        != preinvocation_abort["health_decision_sha256"]
                        or not decision_lineage_valid
                    )
                )
                or not reason_lineage_valid
            ):
                raise StoreIntegrityError(
                    "Preinvocation abort custody is inconsistent"
                )
        terminal_row = connection.execute(
            "SELECT * FROM action_execution_terminals WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        reconciliation_row = connection.execute(
            "SELECT * FROM action_execution_reconciliations WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        closure_row = connection.execute(
            "SELECT * FROM action_execution_closures WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if (terminal_row is None) != (closure_row is None):
            raise StoreIntegrityError("Execution terminal closure is incomplete")
        if terminal_row is None:
            if abort is not None or preinvocation_abort is not None:
                raise StoreIntegrityError(
                    "Execution abort custody lacks terminal closure"
                )
            if reconciliation_row is not None:
                raise StoreIntegrityError("Execution reconciliation is orphaned")
            continue
        terminal_count += 1
        if type(terminal_row["terminal_json"]) is not str:
            raise StoreIntegrityError("Terminal JSON type is invalid")
        terminal = parse_action_execution_terminal(
            json.loads(terminal_row["terminal_json"])
        )
        terminal_document = terminal.to_dict()
        charged = terminal_document["charged_resources"]
        active_abort = abort if abort is not None else preinvocation_abort
        if (
            _canonical_json(terminal_document) != terminal_row["terminal_json"]
            or terminal.terminal_id != terminal_row["terminal_id"]
            or terminal.terminal_sha256 != terminal_row["terminal_sha256"]
            or terminal_document["request_id"] != request.request_id
            or terminal_document["request_sha256"] != request.request_sha256
            or terminal_document["claim_id"] != claim.claim_id
            or terminal_document["claim_sha256"] != claim.claim_sha256
            or terminal_row["dispatch_id"] != claim_row["dispatch_id"]
            or terminal_document["settled_at"] != terminal_row["settled_at"]
            or terminal_document["settled_at"] < claim_document["claimed_at"]
            or (
                dispatch is not None
                and terminal_document["settled_at"] < dispatch["attempted_at"]
            )
            or (
                terminal_document["terminal_status"]
                in {TerminalStatus.COMPLETED.value, TerminalStatus.FAILED_KNOWN.value}
                and dispatch is None
            )
            or (
                terminal_document["terminal_status"]
                == TerminalStatus.PREDISPATCH_ABORTED.value
                and abort is None
                and preinvocation_abort is None
            )
            or (
                terminal_document["terminal_status"]
                != TerminalStatus.PREDISPATCH_ABORTED.value
                and (abort is not None or preinvocation_abort is not None)
            )
            or any(
                terminal_row[
                    {
                        "money_microunits": "money_charged_microunits",
                        "rate_units": "rate_units_charged",
                        "request_bytes": "request_bytes_charged",
                        "response_bytes": "response_bytes_charged",
                        "duration_ms": "duration_ms_charged",
                        "impact_events": "impact_events_charged",
                    }[field]
                ]
                != charged[field]
                for field in RESOURCE_FIELDS
            )
            or (
                terminal_document["terminal_status"]
                == TerminalStatus.INDETERMINATE_QUARANTINED.value
                and (dispatch is None or charged != reserved)
            )
            or (
                terminal_document["terminal_status"]
                == TerminalStatus.PREDISPATCH_ABORTED.value
                and (
                    charged != {field: 0 for field in RESOURCE_FIELDS}
                    or terminal_document["adapter_call_count"] != 0
                    or terminal_document["adapter_call_count_status"]
                    != "exactly_zero"
                    or terminal_document["settled_at"]
                    != active_abort["aborted_at"]
                )
            )
        ):
            raise StoreIntegrityError("Execution terminal custody is inconsistent")
        if type(closure_row["closure_json"]) is not str:
            raise StoreIntegrityError("Execution closure JSON type is invalid")
        expected_closure = _closure_document(terminal)
        if (
            _canonical_json(expected_closure) != closure_row["closure_json"]
            or closure_row["closure_id"] != expected_closure["closure_id"]
            or closure_row["closure_sha256"]
            != expected_closure["closure_sha256"]
            or closure_row["terminal_id"] != terminal.terminal_id
            or any(
                closure_row[field] != expected_closure[field]
                for field in (
                    "action_outcome",
                    "evidence_status",
                    "cleanup_status",
                    "restoration_status",
                    "closed_at",
                )
            )
        ):
            raise StoreIntegrityError("Execution closure axes are inconsistent")
        if reconciliation_row is not None:
            reconciliation_count += 1
            _verify_reconciliation_row(
                connection,
                row=reconciliation_row,
                request=request,
                claim=claim,
                execute_authorization=authorization,
                dispatch=dispatch,
                abort=abort,
                preinvocation_abort=preinvocation_abort,
                terminal=terminal,
            )
        events = connection.execute(
            "SELECT * FROM action_budget_account_events "
            "WHERE account_id = ? AND reservation_id = ? "
            "AND event_kind != 'reserve' ORDER BY event_sequence",
            (reservation["account_id"], reservation["reservation_id"]),
        ).fetchall()
        settled = [
            json.loads(item["resources_json"])
            for item in events
            if item["event_kind"] == "settle"
        ]
        released = [
            json.loads(item["resources_json"])
            for item in events
            if item["event_kind"] == "release"
        ]
        if abort is not None or preinvocation_abort is not None:
            if settled or len(released) != 1 or released[0] != reserved:
                raise StoreIntegrityError("Predispatch budget release is inconsistent")
        else:
            if len(settled) != 1 or settled[0] != charged or len(released) > 1:
                raise StoreIntegrityError("Execution budget settlement is inconsistent")
            if any(
                settled[0][field]
                + (released[0][field] if released else 0)
                != reserved[field]
                for field in RESOURCE_FIELDS
            ):
                raise StoreIntegrityError("Execution budget conservation is invalid")
        first_sequence = int(events[0]["event_sequence"])
        prior_global = connection.execute(
            "SELECT event_sha256 FROM action_budget_account_events "
            "WHERE account_id = ? AND event_sequence = ?",
            (link["account_id"], first_sequence - 1),
        ).fetchone()
        if prior_global is None:
            raise StoreIntegrityError("Execution budget predecessor is absent")
        previous = prior_global["event_sha256"]
        expected_sequence = first_sequence
        for index, event in enumerate(events):
            if index:
                expected_sequence += 1
            resources = json.loads(event["resources_json"])
            body = {
                "account_id": link["account_id"],
                "budget_revision_id": link["budget_revision_id"],
                "budget_revision_sha256": link["budget_revision_sha256"],
                "claim_id": claim.claim_id,
                "claim_sha256": claim.claim_sha256,
                "dispatch_id": claim_row["dispatch_id"],
                "event_kind": event["event_kind"],
                "event_sequence": expected_sequence,
                "execution_id": request.request_id,
                "execution_intent_sha256": action_execute_authorization_intent_sha256(
                    request
                ),
                "idempotency_key_sha256": link["idempotency_key_sha256"],
                "previous_event_sha256": previous,
                "receipt_id": receipt["receipt_id"],
                "recorded_at": terminal_document["settled_at"],
                "reservation_id": link["reservation_id"],
                "reservation_sha256": link["reservation_sha256"],
                "resources": resources,
            }
            expected_hash = _canonical_sha256(
                {"domain": BUDGET_EVENT_DOMAIN, "event": body}
            )
            expected_id = "ABE-" + expected_hash.removeprefix("sha256:")[:32].upper()
            if (
                event["account_id"] != body["account_id"]
                or event["event_sequence"] != expected_sequence
                or event["event_id"] != expected_id
                or event["event_sha256"] != expected_hash
                or event["receipt_id"] != body["receipt_id"]
                or event["budget_revision_id"] != body["budget_revision_id"]
                or event["budget_revision_sha256"]
                != body["budget_revision_sha256"]
                or event["reservation_id"] != body["reservation_id"]
                or event["reservation_sha256"] != body["reservation_sha256"]
                or event["idempotency_key_sha256"]
                != body["idempotency_key_sha256"]
                or event["execution_id"] != body["execution_id"]
                or event["execution_intent_sha256"]
                != body["execution_intent_sha256"]
                or event["claim_id"] != body["claim_id"]
                or event["claim_sha256"] != body["claim_sha256"]
                or event["dispatch_id"] != body["dispatch_id"]
                or event["resources_json"] != canonical_json(resources)
                or event["previous_event_sha256"] != previous
                or event["recorded_at"] != body["recorded_at"]
            ):
                raise StoreIntegrityError("Execution budget event lineage is inconsistent")
            previous = expected_hash
    expected_counts = {
        "action_execution_claims": len(requests),
        "action_execution_authority_checkpoints": len(requests) + dispatch_count,
        "action_execution_authority_consumptions": len(requests),
        "action_execution_reservations": len(requests),
        "action_admission_execution_consumptions": len(requests),
        "action_execution_dispatch_attempts": dispatch_count,
        "action_execution_predispatch_aborts": abort_count,
        "action_execution_terminals": terminal_count,
        "action_execution_closures": terminal_count,
        "action_execution_reconciliations": reconciliation_count,
    }
    if preinvocation_abort_table_available:
        expected_counts["action_execution_preinvocation_aborts"] = (
            preinvocation_abort_count
        )
    for table, expected in expected_counts.items():
        actual = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if actual != expected:
            raise StoreIntegrityError(f"{table} contains orphaned custody")
    central_use_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM principal_assertion_uses WHERE operation = ?",
            (ACTION_EXECUTE,),
        ).fetchone()[0]
    )
    central_effect_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM principal_assertion_effects WHERE effect_kind = ?",
            (ACTION_EXECUTE,),
        ).fetchone()[0]
    )
    if central_use_count != len(requests) or central_effect_count != len(requests):
        raise StoreIntegrityError("Central ACTION_EXECUTE custody contains orphans")
    reconciliation_use_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM principal_assertion_uses WHERE operation = ?",
            (ACTION_EXECUTION_RECONCILE,),
        ).fetchone()[0]
    )
    reconciliation_effect_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM principal_assertion_effects WHERE effect_kind = ?",
            (ACTION_EXECUTION_RECONCILE,),
        ).fetchone()[0]
    )
    if (
        reconciliation_use_count != reconciliation_count
        or reconciliation_effect_count != reconciliation_count
    ):
        raise StoreIntegrityError("Central reconciliation custody contains orphans")
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = "
        "'action_execution_target_health_gate_legacy_baselines'"
    ).fetchone() is not None:
        try:
            verify_action_target_health_gate_use_store(connection)
        except ValueError as exc:
            raise StoreIntegrityError(
                "Execution target-health custody is invalid"
            ) from exc
    return {
        "request_count": len(requests),
        "dispatch_count": dispatch_count,
        "terminal_count": terminal_count,
        "reconciliation_count": reconciliation_count,
        "reconciliation_required_count": len(requests) - terminal_count,
        "status": "valid",
    }


__all__ = [
    "MissionStoreAuthenticatedActionExecutionService",
    "SealedActionDispatch",
    "verify_authenticated_action_execution_store",
]
