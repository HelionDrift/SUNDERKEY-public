"""Authenticated durable admission and custody for expert model execution.

This module is the production admission boundary around the provider-neutral
Phase189 execution records. It deliberately keeps authentication, replay
consumption, budget reservation, dispatch, and settlement under database
custody while the provider call occurs outside a database transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol, runtime_checkable

from .authenticated import AuthenticatedMissionControlService
from .collaboration import CollaborationPlan
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .expert_model_execution_custody import (
    ExpertBudgetReservationCommit,
    ExpertBudgetSettlement,
    ExpertExecutionAuthority,
    ExpertInvocationPlan,
    ExpertModelExecutionError,
    ExpertModelExecutionReceipt,
    ExpertModelExecutionResult,
    ExpertProviderObservation,
    ProviderInvocationRejected,
    ProviderOutcomeIndeterminate,
    _instant,
    _post_dispatch_timestamp,
    _timestamp,
    _validate_authority_time,
    build_invocation_plan,
)
from .expert_runtime import (
    MAX_WORK_PRODUCT_BYTES,
    ExecutionEnvelope,
    RuntimePackCatalog,
    WorkProduct,
    parse_work_product,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .multi_model_routing import (
    BudgetEnvelope,
    ModelCapabilityDeclaration,
    RoutingDecision,
    canonical_sha256,
)
from .registry import ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

MODEL_EXECUTION_EFFECT_KIND = PrincipalOperation.MODEL_EXECUTE.value
MODEL_EXECUTION_ADMISSION_STATUS = "admitted_reserved"
_PROOF_KEY = secrets.token_bytes(32)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ExpertModelExecutionError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ExpertModelExecutionError(f"{label} is invalid")
    return value


def _natural(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExpertModelExecutionError(f"{label} must be a nonnegative integer")
    return value


def _record_identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "domain": kind, "schema_version": 1})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _strict_record(
    raw: Any,
    *,
    kind: str,
    id_field: str,
    sha_field: str,
    body_fields: set[str],
) -> dict[str, Any]:
    expected = {"schema_version", "kind", id_field, sha_field, *body_fields}
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise ExpertModelExecutionError(f"{kind} fields are invalid")
    value = dict(raw)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ExpertModelExecutionError(f"{kind} schema version is invalid")
    if value["kind"] != kind:
        raise ExpertModelExecutionError(f"{kind} header is invalid")
    return value


def _budget_from_dict(raw: Any) -> BudgetEnvelope:
    if not isinstance(raw, Mapping):
        raise ExpertModelExecutionError("budget document is invalid")
    expected = {
        "schema_version",
        "kind",
        "budget_id",
        "budget_sha256",
        "effects",
        "tenant_id",
        "assessment_id",
        "currency",
        "request_input_token_limit",
        "request_output_token_limit",
        "request_cost_limit_micros",
        "aggregate_input_token_limit",
        "aggregate_output_token_limit",
        "aggregate_cost_limit_micros",
        "aggregate_input_tokens_reserved",
        "aggregate_output_tokens_reserved",
        "aggregate_cost_reserved_micros",
        "budget_revision",
    }
    if set(raw) != expected:
        raise ExpertModelExecutionError("budget document fields are invalid")
    values = {
        key: raw[key]
        for key in expected
        if key not in {"schema_version", "kind", "budget_id", "budget_sha256", "effects"}
    }
    budget = BudgetEnvelope(**values)
    if budget.to_dict() != dict(raw):
        raise ExpertModelExecutionError("budget document is not canonical")
    return budget


def model_execution_admission_core_sha256(
    authority: ExpertExecutionAuthority,
) -> str:
    """Hash the complete authority request without its two proof outputs."""

    if type(authority) is not ExpertExecutionAuthority:
        raise ExpertModelExecutionError("execution authority is not canonical")
    value = authority.to_dict()
    body = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "authority_id",
            "authority_sha256",
            "issuer_assertion_sha256",
            "authentication_verification_sha256",
            "credential_reference",
        }
    }
    body["credential_reference_sha256"] = sha256_text(authority.credential_reference)
    return canonical_sha256(
        {
            "authority": body,
            "domain": "sunderkey.authenticated-model-execution-core.v1",
            "schema_version": 1,
        }
    )


def model_execution_operation_intent(
    mission_id: str,
    principal_profile_id: str,
    execution_admission_core_sha256: str,
) -> dict[str, str]:
    return {
        "execution_admission_core_sha256": _digest(
            execution_admission_core_sha256,
            "execution_admission_core_sha256",
        ),
        "mission_id": _identifier(mission_id, "mission_id"),
        "principal_profile_id": _identifier(
            principal_profile_id,
            "principal_profile_id",
        ),
    }


def model_execution_authentication_verification_sha256(
    *,
    trust_policy_sha256: str,
    scope_grant_sha256: str,
    assertion_sha256: str,
    assertion_key_sha256: str,
    execution_admission_core_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "assertion_key_sha256": _digest(assertion_key_sha256, "assertion_key_sha256"),
            "assertion_sha256": _digest(assertion_sha256, "assertion_sha256"),
            "domain": "sunderkey.authenticated-model-execution-verification.v1",
            "execution_admission_core_sha256": _digest(
                execution_admission_core_sha256,
                "execution_admission_core_sha256",
            ),
            "schema_version": 1,
            "scope_grant_sha256": _digest(scope_grant_sha256, "scope_grant_sha256"),
            "trust_policy_sha256": _digest(trust_policy_sha256, "trust_policy_sha256"),
        }
    )


def model_execution_canonical_replay_key_sha256(
    *,
    assertion: PrincipalAssertion,
    authority: ExpertExecutionAuthority,
    invocation_plan: ExpertInvocationPlan,
    operation_intent_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "assertion_id": assertion.assertion_id,
            "assertion_issuer": assertion.issuer,
            "assertion_sha256": assertion.content_sha256,
            "authority_id": authority.authority_id,
            "authority_sha256": authority.authority_sha256,
            "domain": "sunderkey.authenticated-model-execution-replay.v1",
            "invocation_plan_id": invocation_plan.plan_id,
            "invocation_plan_sha256": invocation_plan.plan_sha256,
            "operation_intent_sha256": _digest(operation_intent_sha256, "operation_intent_sha256"),
            "schema_version": 1,
        }
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedModelExecutionAdmissionReceipt:
    mission_id: str
    mission_revision: int
    tenant_id: str
    assessment_id: str
    active_plan_id: str
    active_plan_sha256: str
    active_plan_version: int
    work_id: str
    expert_profile_id: str
    runtime_catalog_sha256: str
    runtime_pack_sha256: str
    execution_envelope_sha256: str
    routing_decision_sha256: str
    capability_sha256: str
    reservation_sha256: str
    authority_id: str
    authority_sha256: str
    invocation_plan_id: str
    invocation_plan_sha256: str
    assertion_issuer: str
    assertion_id: str
    assertion_sha256: str
    scope_grant_sha256: str
    trust_policy_sha256: str
    execution_admission_core_sha256: str
    operation_intent_sha256: str
    canonical_replay_key_sha256: str
    budget_id_before: str
    budget_sha256_before: str
    budget_revision_before: str
    budget_id_after: str
    budget_sha256_after: str
    budget_revision_after: str
    reservation_commit_id: str
    reservation_commit_sha256: str
    admitted_at: str
    admission_status: str = MODEL_EXECUTION_ADMISSION_STATUS
    admission_id: str = field(init=False)
    admission_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.authenticated-model-execution-admission.v1"

    def __post_init__(self) -> None:
        for name in (
            "mission_id",
            "tenant_id",
            "assessment_id",
            "active_plan_id",
            "work_id",
            "expert_profile_id",
            "authority_id",
            "invocation_plan_id",
            "assertion_issuer",
            "assertion_id",
            "budget_id_before",
            "budget_revision_before",
            "budget_id_after",
            "budget_revision_after",
            "reservation_commit_id",
        ):
            _identifier(getattr(self, name), name)
        for name in (
            "active_plan_sha256",
            "runtime_catalog_sha256",
            "runtime_pack_sha256",
            "execution_envelope_sha256",
            "routing_decision_sha256",
            "capability_sha256",
            "reservation_sha256",
            "authority_sha256",
            "invocation_plan_sha256",
            "assertion_sha256",
            "scope_grant_sha256",
            "trust_policy_sha256",
            "execution_admission_core_sha256",
            "operation_intent_sha256",
            "canonical_replay_key_sha256",
            "budget_sha256_before",
            "budget_sha256_after",
            "reservation_commit_sha256",
        ):
            _digest(getattr(self, name), name)
        _natural(self.mission_revision, "mission_revision")
        if _natural(self.active_plan_version, "active_plan_version") < 1:
            raise ExpertModelExecutionError("active_plan_version is invalid")
        if self.budget_revision_before == self.budget_revision_after:
            raise ExpertModelExecutionError("budget revision did not advance")
        if self.admission_status != MODEL_EXECUTION_ADMISSION_STATUS:
            raise ExpertModelExecutionError("admission status is invalid")
        _timestamp(self.admitted_at, "admitted_at")
        record_id, digest = _record_identity("AME", self.KIND, self._body())
        object.__setattr__(self, "admission_id", record_id)
        object.__setattr__(self, "admission_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"admission_id", "admission_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AuthenticatedModelExecutionAdmissionReceipt:
        computed = {"admission_id", "admission_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _strict_record(
            raw,
            kind=cls.KIND,
            id_field="admission_id",
            sha_field="admission_sha256",
            body_fields=body_fields,
        )
        instance = cls(**{key: value[key] for key in body_fields})
        if (
            value["admission_id"] != instance.admission_id
            or value["admission_sha256"] != instance.admission_sha256
        ):
            raise ExpertModelExecutionError("admission content identity is invalid")
        return instance


@dataclass(frozen=True, slots=True)
class AuthenticatedModelExecutionDispatch:
    admission_id: str
    admission_sha256: str
    authority_id: str
    invocation_plan_id: str
    adapter_principal_id: str
    claimed_at: str
    dispatch_id: str = field(init=False)
    dispatch_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.authenticated-model-execution-dispatch.v1"

    def __post_init__(self) -> None:
        for name in (
            "admission_id",
            "authority_id",
            "invocation_plan_id",
            "adapter_principal_id",
        ):
            _identifier(getattr(self, name), name)
        _digest(self.admission_sha256, "admission_sha256")
        _timestamp(self.claimed_at, "claimed_at")
        record_id, digest = _record_identity("MED", self.KIND, self._body())
        object.__setattr__(self, "dispatch_id", record_id)
        object.__setattr__(self, "dispatch_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
            if name not in {"dispatch_id", "dispatch_sha256", "KIND"}
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": self.KIND,
            "dispatch_id": self.dispatch_id,
            "dispatch_sha256": self.dispatch_sha256,
            **self._body(),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AuthenticatedModelExecutionDispatch:
        computed = {"dispatch_id", "dispatch_sha256", "KIND"}
        body_fields = set(cls.__dataclass_fields__) - computed
        value = _strict_record(
            raw,
            kind=cls.KIND,
            id_field="dispatch_id",
            sha_field="dispatch_sha256",
            body_fields=body_fields,
        )
        instance = cls(**{key: value[key] for key in body_fields})
        if (
            value["dispatch_id"] != instance.dispatch_id
            or value["dispatch_sha256"] != instance.dispatch_sha256
        ):
            raise ExpertModelExecutionError("dispatch content identity is invalid")
        return instance


def _proof_material(
    receipt: AuthenticatedModelExecutionAdmissionReceipt,
    plan: ExpertInvocationPlan,
    authority: ExpertExecutionAuthority,
) -> bytes:
    return canonical_json(
        {
            "authority": authority.to_dict(),
            "invocation_plan": plan.to_dict(),
            "receipt": receipt.to_dict(),
        }
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class VerifiedModelExecutionAdmission:
    """Process-local proof that durable admission was verified for immediate use."""

    receipt: AuthenticatedModelExecutionAdmissionReceipt
    invocation_plan: ExpertInvocationPlan
    authority: ExpertExecutionAuthority
    _proof: bytes = field(repr=False, compare=False)

    @classmethod
    def _seal(
        cls,
        receipt: AuthenticatedModelExecutionAdmissionReceipt,
        plan: ExpertInvocationPlan,
        authority: ExpertExecutionAuthority,
    ) -> VerifiedModelExecutionAdmission:
        proof = hmac.new(
            _PROOF_KEY,
            _proof_material(receipt, plan, authority),
            hashlib.sha256,
        ).digest()
        return cls(receipt, plan, authority, proof)

    def _proof_is_valid(self) -> bool:
        expected = hmac.new(
            _PROOF_KEY,
            _proof_material(self.receipt, self.invocation_plan, self.authority),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(self._proof, expected)


@runtime_checkable
class AuthenticatedExpertModelProviderAdapter(Protocol):
    """Provider-neutral adapter callable only after proof revalidation."""

    adapter_principal_id: str
    qualifying: bool

    def invoke(
        self, plan: ExpertInvocationPlan, credential_reference: str
    ) -> ExpertProviderObservation: ...


def _budget_snapshot(
    previous: BudgetEnvelope,
    *,
    input_reserved: int,
    output_reserved: int,
    cost_reserved: int,
    revision: str,
) -> BudgetEnvelope:
    return BudgetEnvelope(
        tenant_id=previous.tenant_id,
        assessment_id=previous.assessment_id,
        currency=previous.currency,
        request_input_token_limit=previous.request_input_token_limit,
        request_output_token_limit=previous.request_output_token_limit,
        request_cost_limit_micros=previous.request_cost_limit_micros,
        aggregate_input_token_limit=previous.aggregate_input_token_limit,
        aggregate_output_token_limit=previous.aggregate_output_token_limit,
        aggregate_cost_limit_micros=previous.aggregate_cost_limit_micros,
        aggregate_input_tokens_reserved=input_reserved,
        aggregate_output_tokens_reserved=output_reserved,
        aggregate_cost_reserved_micros=cost_reserved,
        budget_revision=revision,
    )


def _next_budget_revision(operation: str, identifier: str, previous: str) -> str:
    return (
        "custody."
        + canonical_sha256(
            {"identifier": identifier, "operation": operation, "previous": previous}
        )[7:23]
    )


def _budget_baseline_hash(budget: BudgetEnvelope, initialized_at: str) -> str:
    return canonical_sha256(
        {
            "assessment_id": budget.assessment_id,
            "budget_id": budget.budget_id,
            "budget_sha256": budget.budget_sha256,
            "domain": "sunderkey.authenticated-model-budget-baseline.v1",
            "initialized_at": initialized_at,
            "schema_version": 1,
            "tenant_id": budget.tenant_id,
        }
    )


def _budget_event(
    *,
    tenant_id: str,
    assessment_id: str,
    sequence: int,
    kind: str,
    admission_id: str,
    custody_id: str,
    before: BudgetEnvelope,
    after: BudgetEnvelope,
    previous_event_sha256: str,
    recorded_at: str,
) -> tuple[str, str, str]:
    material = {
        "admission_id": admission_id,
        "after_budget_id": after.budget_id,
        "after_budget_sha256": after.budget_sha256,
        "assessment_id": assessment_id,
        "before_budget_id": before.budget_id,
        "before_budget_sha256": before.budget_sha256,
        "custody_id": custody_id,
        "domain": "sunderkey.authenticated-model-budget-event.v1",
        "event_kind": kind,
        "event_sequence": sequence,
        "previous_event_sha256": previous_event_sha256,
        "recorded_at": recorded_at,
        "schema_version": 1,
        "tenant_id": tenant_id,
    }
    digest = canonical_sha256(material)
    return "MBE-" + digest[7:39].upper(), digest, canonical_json(material)


class SQLiteAuthenticatedModelExecutionCustody:
    """Strict SQLite custody for authenticated provider-neutral execution."""

    qualifying = True
    durability = "sqlite_authenticated_atomic_custody"

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        workload_subject_principal_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        self._store = store
        self._registry = registry
        self._clock = clock or store._clock
        self._workload_subject = _identifier(
            workload_subject_principal_id,
            "workload_subject_principal_id",
        )
        self._authenticated = AuthenticatedMissionControlService(
            store,
            registry,
            clock=self._clock,
        )

    @staticmethod
    def _active_plan(
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[CollaborationPlan, int]:
        row = connection.execute(
            """
            SELECT activation.plan_json, activation.plan_content_sha256,
                   head.plan_version
            FROM collaboration_plan_active_heads AS head
            JOIN collaboration_plan_activations AS activation
              ON activation.plan_id = head.active_plan_id
             AND activation.mission_id = head.mission_id
            WHERE head.mission_id = ?
            """,
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Mission has no active collaboration plan")
        _require_stored_types(
            row,
            text_fields=("plan_json", "plan_content_sha256"),
            integer_fields=("plan_version",),
        )
        try:
            plan = CollaborationPlan.from_dict(
                _stored_canonical_object(row["plan_json"], "active collaboration plan")
            )
        except Exception as exc:
            raise StoreIntegrityError("Active collaboration plan is invalid") from exc
        if plan.content_sha256 != row["plan_content_sha256"]:
            raise StoreIntegrityError("Active collaboration plan digest is invalid")
        return plan, row["plan_version"]

    @staticmethod
    def _mission_is_active(connection: sqlite3.Connection, mission_id: str) -> None:
        row = connection.execute(
            "SELECT state FROM mission_controls WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreIntegrityError("Mission control state is missing")
        _require_stored_types(row, text_fields=("state",))
        if row["state"] != "active":
            raise StoreConflictError("Stopped mission cannot execute a model")

    def _verify_principal(
        self,
        connection: sqlite3.Connection,
        *,
        identity: Mapping[str, Any],
        trust_policies: Mapping[str, Any],
        mission: Any,
        scope_grants: Mapping[str, tuple[sqlite3.Row, Any]],
        assertion: PrincipalAssertion,
        operation_intent_sha256: str,
        now: datetime,
    ) -> VerifiedPrincipal:
        ledger = connection.execute(
            "SELECT updated_at FROM mission_principal_ledgers WHERE mission_id = ?",
            (assertion.mission_id,),
        ).fetchone()
        if ledger is None:
            raise StoreIntegrityError("Mission principal ledger is missing")
        _require_stored_types(ledger, text_fields=("updated_at",))
        if parse_timestamp(ledger["updated_at"], "principal ledger time") > now:
            raise PrincipalAuthenticationError("Runtime clock precedes principal ledger")
        current_policy_hash = identity["trust_policy_hash"]
        if current_policy_hash is None:
            raise StoreConflictError("A current trust policy is required")
        if any(type(identity[field]) is not str for field in ("audience", "store_id")):
            raise StoreIntegrityError("Store identity authentication fields are invalid")
        if type(current_policy_hash) is not str:
            raise StoreIntegrityError("Current trust policy identity is invalid")
        verified_policy = trust_policies.get(current_policy_hash)
        if verified_policy is None:
            raise StoreIntegrityError("Current trust policy is missing from history")
        high_water = self._store._trust_policy_high_water_at(trust_policies, now)
        if high_water.policy_sha256 != verified_policy.policy_sha256:
            raise PrincipalAuthenticationError("Runtime clock precedes the current trust policy")
        scope_entry = scope_grants.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Assertion scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        _require_stored_types(scope_row, text_fields=("accepted_at",))
        if parse_timestamp(scope_row["accepted_at"], "scope accepted_at") > now:
            raise PrincipalAuthenticationError("Scope grant was accepted in the future")
        if self._store._effective_scope_grant_revocation(connection, scope_row) is not None:
            raise PrincipalAuthenticationError("Scope grant is revoked")
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError("Mission has no authenticated scope document hash")
        constraints_hash = sha256_text(canonical_json(mission.mission.to_dict()["constraints"]))
        verified_scope = verify_scope_grant(
            scope_grant,
            verified_policy,
            expected_audience=identity["audience"],
            expected_store_id=identity["store_id"],
            expected_mission_id=assertion.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            expected_operation=PrincipalOperation.MODEL_EXECUTE,
            clock=lambda: now,
        )
        return verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=identity["audience"],
            expected_store_id=identity["store_id"],
            expected_mission_id=assertion.mission_id,
            expected_operation=PrincipalOperation.MODEL_EXECUTE,
            expected_operation_intent_sha256=operation_intent_sha256,
            clock=lambda: now,
        )

    @staticmethod
    def _assertion_entry(
        *,
        principal: VerifiedPrincipal,
        assertion: PrincipalAssertion,
        mission_id: str,
        use_sequence: int,
        assertion_hash: str,
        operation_intent_json: str,
        signed_intent_hash: str,
        domain_request_hash: str,
        replay_hash: str,
        consumed_at: str,
        effects_hash: str,
        previous_hash: str,
    ) -> dict[str, Any]:
        return {
            "mission_id": mission_id,
            "use_sequence": use_sequence,
            "issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_hash": assertion_hash,
            "subject": assertion.subject,
            "principal_profile_id": assertion.profile_id,
            "key_id": assertion.key_id,
            "key_hash": principal.key_sha256,
            "audience": assertion.audience,
            "store_id": assertion.store_id,
            "operation": assertion.operation.value,
            "operation_intent_json": operation_intent_json,
            "signed_intent_hash": signed_intent_hash,
            "domain_request_hash": domain_request_hash,
            "idempotency_key_hash": replay_hash,
            "scope_grant_hash": assertion.scope_grant_sha256,
            "trust_policy_id": assertion.policy_id,
            "trust_policy_version": assertion.policy_version,
            "trust_policy_hash": principal.policy_sha256,
            "issued_at": assertion.issued_at,
            "not_before": assertion.not_before,
            "expires_at": assertion.expires_at,
            "consumed_at": consumed_at,
            "effects_hash": effects_hash,
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _load_admission_row(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM authenticated_model_execution_admissions
            WHERE assertion_issuer = ? AND assertion_id = ?
            """,
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()

    @staticmethod
    def _admission_from_row(
        row: sqlite3.Row,
    ) -> tuple[
        AuthenticatedModelExecutionAdmissionReceipt,
        ExpertInvocationPlan,
        ExpertExecutionAuthority,
        ExpertBudgetReservationCommit,
    ]:
        _require_stored_types(
            row,
            text_fields=(
                "admission_id",
                "admission_sha256",
                "authority_id",
                "authority_sha256",
                "authority_json",
                "invocation_plan_id",
                "invocation_plan_sha256",
                "invocation_plan_json",
                "reservation_commit_id",
                "reservation_commit_sha256",
                "reservation_commit_json",
                "receipt_json",
            ),
            integer_fields=("budget_event_sequence",),
        )
        try:
            receipt = AuthenticatedModelExecutionAdmissionReceipt.from_dict(
                _stored_canonical_object(row["receipt_json"], "admission receipt")
            )
            plan = ExpertInvocationPlan.from_dict(
                _stored_canonical_object(row["invocation_plan_json"], "invocation plan")
            )
            authority = ExpertExecutionAuthority.from_dict(
                _stored_canonical_object(row["authority_json"], "execution authority")
            )
            commit = ExpertBudgetReservationCommit.from_dict(
                _stored_canonical_object(
                    row["reservation_commit_json"],
                    "reservation commit",
                )
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored model execution admission is invalid") from exc
        if (
            receipt.admission_id != row["admission_id"]
            or receipt.admission_sha256 != row["admission_sha256"]
            or plan.plan_id != row["invocation_plan_id"]
            or plan.plan_sha256 != row["invocation_plan_sha256"]
            or authority.authority_id != row["authority_id"]
            or authority.authority_sha256 != row["authority_sha256"]
            or commit.commit_id != row["reservation_commit_id"]
            or commit.commit_sha256 != row["reservation_commit_sha256"]
        ):
            raise StoreIntegrityError("Stored model execution admission identity is invalid")
        return receipt, plan, authority, commit

    def admit(
        self,
        assertion: PrincipalAssertion,
        runtime_catalog: RuntimePackCatalog,
        runtime_pack: Mapping[str, Any],
        envelope: ExecutionEnvelope,
        decision: RoutingDecision,
        capability: ModelCapabilityDeclaration,
        budget: BudgetEnvelope,
        authority: ExpertExecutionAuthority,
    ) -> VerifiedModelExecutionAdmission:
        """Authenticate and atomically reserve exactly one model request."""

        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError("assertion must be canonical")
        if type(authority) is not ExpertExecutionAuthority:
            raise ExpertModelExecutionError("execution authority is not canonical")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        authority = ExpertExecutionAuthority.from_dict(authority.to_dict())
        if authority.subject_principal_id != self._workload_subject:
            raise PrincipalAuthenticationError("Execution workload subject does not match")
        if assertion.subject != authority.issuer_principal_id:
            raise PrincipalAuthenticationError("Authority issuer assertion subject does not match")
        if assertion.issuer == assertion.subject:
            raise PrincipalAuthenticationError("Execution authority cannot self-authorize")
        if authority.issuer_assertion_sha256 != assertion.content_sha256:
            raise PrincipalAuthenticationError("Authority assertion digest does not match")
        request_time = format_timestamp(self._clock())
        plan = build_invocation_plan(
            runtime_catalog,
            runtime_pack,
            envelope,
            decision,
            capability,
            budget,
            authority,
            now=request_time,
        )
        core_sha256 = model_execution_admission_core_sha256(authority)
        operation_intent = model_execution_operation_intent(
            authority.mission_id,
            assertion.profile_id,
            core_sha256,
        )
        operation_intent_json = canonical_json(operation_intent)
        operation_intent_sha256 = compute_operation_intent_hash(
            PrincipalOperation.MODEL_EXECUTE,
            operation_intent,
        )
        replay_sha256 = model_execution_canonical_replay_key_sha256(
            assertion=assertion,
            authority=authority,
            invocation_plan=plan,
            operation_intent_sha256=operation_intent_sha256,
        )
        domain_request_sha256 = canonical_sha256(
            {
                "domain": "sunderkey.authenticated-model-execution-request.v1",
                "execution_admission_core_sha256": core_sha256,
                "invocation_plan_sha256": plan.plan_sha256,
                "schema_version": 1,
            }
        )
        assertion_json = canonical_json(assertion.to_dict())
        authority_json = canonical_json(authority.to_dict())
        plan_json = canonical_json(plan.to_dict())

        try:
            with self._store._write_connection() as connection:
                identity, policies, mission, scopes = self._authenticated._verified_mission_state(
                    connection,
                    authority.mission_id,
                )
                existing = self._load_admission_row(connection, assertion)
                if existing is not None:
                    receipt, stored_plan, stored_authority, _ = self._admission_from_row(existing)
                    if (
                        authority_json != existing["authority_json"]
                        or plan_json != existing["invocation_plan_json"]
                        or assertion.content_sha256 != existing["assertion_sha256"]
                        or operation_intent_sha256 != existing["operation_intent_sha256"]
                        or replay_sha256 != existing["canonical_replay_key_sha256"]
                        or budget.budget_id != receipt.budget_id_before
                        or budget.budget_sha256 != receipt.budget_sha256_before
                    ):
                        raise StoreConflictError(
                            "Model execution assertion replay has different content"
                        )
                    verify_authenticated_model_execution_store(
                        connection,
                        mission_id=authority.mission_id,
                    )
                    return VerifiedModelExecutionAdmission._seal(
                        receipt,
                        stored_plan,
                        stored_authority,
                    )
                principal_use = connection.execute(
                    "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if principal_use is not None:
                    raise StoreConflictError("Principal assertion was already consumed")
                if (
                    connection.execute(
                        """
                    SELECT 1 FROM authenticated_model_execution_admissions
                    WHERE canonical_replay_key_sha256 = ? OR domain_request_sha256 = ?
                    """,
                        (replay_sha256, domain_request_sha256),
                    ).fetchone()
                    is not None
                ):
                    raise StoreConflictError("Model execution request replay conflicts")
                self._mission_is_active(connection, authority.mission_id)
                active_plan, active_plan_version = self._active_plan(
                    connection,
                    authority.mission_id,
                )
                if authority.plan_id != active_plan.plan_id:
                    raise StoreConflictError("Execution plan is not the active plan")
                work_item = next(
                    (
                        item
                        for item in active_plan.work_items
                        if item.work_item_id == authority.work_id
                    ),
                    None,
                )
                if work_item is None:
                    raise StoreConflictError("Execution work item is not in the active plan")
                if work_item.owner_profile_id != authority.expert_profile_id:
                    raise PrincipalAuthenticationError(
                        "Execution expert is not the work-item owner"
                    )
                now = self._clock()
                consumed_at = format_timestamp(now)
                if consumed_at < request_time:
                    raise PrincipalAuthenticationError("Runtime clock rolled back")
                principal = self._verify_principal(
                    connection,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    assertion=assertion,
                    operation_intent_sha256=operation_intent_sha256,
                    now=now,
                )
                verification_sha256 = model_execution_authentication_verification_sha256(
                    trust_policy_sha256=principal.policy_sha256,
                    scope_grant_sha256=assertion.scope_grant_sha256,
                    assertion_sha256=assertion.content_sha256,
                    assertion_key_sha256=principal.key_sha256,
                    execution_admission_core_sha256=core_sha256,
                )
                if authority.authentication_verification_sha256 != verification_sha256:
                    raise PrincipalAuthenticationError(
                        "Authority authentication verification digest does not match"
                    )
                _validate_authority_time(authority, decision, consumed_at)
                budget_row = connection.execute(
                    """
                    SELECT * FROM authenticated_model_execution_budgets
                    WHERE tenant_id = ? AND assessment_id = ?
                    """,
                    (budget.tenant_id, budget.assessment_id),
                ).fetchone()
                if budget_row is None:
                    if any(
                        (
                            budget.aggregate_input_tokens_reserved,
                            budget.aggregate_output_tokens_reserved,
                            budget.aggregate_cost_reserved_micros,
                        )
                    ):
                        raise StoreConflictError(
                            "First authenticated budget snapshot must have zero counters"
                        )
                    baseline = _budget_baseline_hash(budget, consumed_at)
                    connection.execute(
                        """
                        INSERT INTO authenticated_model_execution_budgets(
                            tenant_id, assessment_id, budget_id, budget_json,
                            budget_sha256, budget_revision, event_count,
                            event_head_sha256, last_observed_at, initialized_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                        """,
                        (
                            budget.tenant_id,
                            budget.assessment_id,
                            budget.budget_id,
                            canonical_json(budget.to_dict()),
                            budget.budget_sha256,
                            budget.budget_revision,
                            baseline,
                            consumed_at,
                            consumed_at,
                        ),
                    )
                    event_count = 0
                    event_head = baseline
                else:
                    _require_stored_types(
                        budget_row,
                        text_fields=(
                            "budget_id",
                            "budget_json",
                            "budget_sha256",
                            "budget_revision",
                            "event_head_sha256",
                            "last_observed_at",
                        ),
                        integer_fields=("event_count",),
                    )
                    if (
                        parse_timestamp(
                            budget_row["last_observed_at"],
                            "model budget last_observed_at",
                        )
                        > now
                    ):
                        raise StoreConflictError("Runtime clock precedes model budget custody")
                    if (
                        budget_row["budget_json"] != canonical_json(budget.to_dict())
                        or budget_row["budget_id"] != budget.budget_id
                        or budget_row["budget_sha256"] != budget.budget_sha256
                        or budget_row["budget_revision"] != budget.budget_revision
                    ):
                        raise StoreConflictError("Model execution budget snapshot is stale")
                    event_count = budget_row["event_count"]
                    event_head = budget_row["event_head_sha256"]
                reservation = decision.budget_reservation
                if reservation is None:
                    raise ExpertModelExecutionError("Routing decision has no reservation")
                if (
                    reservation.reservation_state != "proposed"
                    or reservation.planning_only is not True
                ):
                    raise ExpertModelExecutionError("Routing reservation is not planning-only")
                after_counts = (
                    budget.aggregate_input_tokens_reserved + reservation.input_tokens,
                    budget.aggregate_output_tokens_reserved + reservation.output_tokens,
                    budget.aggregate_cost_reserved_micros + reservation.estimated_cost_micros,
                )
                limits = (
                    budget.aggregate_input_token_limit,
                    budget.aggregate_output_token_limit,
                    budget.aggregate_cost_limit_micros,
                )
                proposed = (
                    reservation.aggregate_input_tokens_after,
                    reservation.aggregate_output_tokens_after,
                    reservation.aggregate_cost_micros_after,
                )
                if proposed != after_counts or any(
                    count > limit for count, limit in zip(after_counts, limits, strict=True)
                ):
                    raise ExpertModelExecutionError(
                        "Proposed aggregate reservation is stale or over limit"
                    )
                revision_after = _next_budget_revision(
                    "reserve",
                    plan.plan_id,
                    budget.budget_revision,
                )
                after_budget = _budget_snapshot(
                    budget,
                    input_reserved=after_counts[0],
                    output_reserved=after_counts[1],
                    cost_reserved=after_counts[2],
                    revision=revision_after,
                )
                commit = ExpertBudgetReservationCommit(
                    authority_id=authority.authority_id,
                    authority_sha256=authority.authority_sha256,
                    invocation_plan_id=plan.plan_id,
                    invocation_plan_sha256=plan.plan_sha256,
                    routing_decision_sha256=decision.decision_sha256,
                    proposed_reservation_sha256=reservation.reservation_sha256,
                    budget_id=budget.budget_id,
                    budget_sha256=budget.budget_sha256,
                    budget_revision_before=budget.budget_revision,
                    budget_revision_after=revision_after,
                    tenant_id=budget.tenant_id,
                    assessment_id=budget.assessment_id,
                    task_id=decision.task_id,
                    capability_sha256=capability.capability_sha256,
                    reserved_input_tokens=reservation.input_tokens,
                    reserved_output_tokens=reservation.output_tokens,
                    reserved_cost_micros=reservation.estimated_cost_micros,
                    committed_at=consumed_at,
                )
                receipt = AuthenticatedModelExecutionAdmissionReceipt(
                    mission_id=authority.mission_id,
                    mission_revision=mission.revision,
                    tenant_id=authority.tenant_id,
                    assessment_id=authority.assessment_id,
                    active_plan_id=active_plan.plan_id,
                    active_plan_sha256=active_plan.content_sha256,
                    active_plan_version=active_plan_version,
                    work_id=authority.work_id,
                    expert_profile_id=authority.expert_profile_id,
                    runtime_catalog_sha256=runtime_catalog.catalog_sha256,
                    runtime_pack_sha256=authority.runtime_pack_sha256,
                    execution_envelope_sha256=envelope.envelope_sha256,
                    routing_decision_sha256=decision.decision_sha256,
                    capability_sha256=capability.capability_sha256,
                    reservation_sha256=reservation.reservation_sha256,
                    authority_id=authority.authority_id,
                    authority_sha256=authority.authority_sha256,
                    invocation_plan_id=plan.plan_id,
                    invocation_plan_sha256=plan.plan_sha256,
                    assertion_issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    assertion_sha256=assertion.content_sha256,
                    scope_grant_sha256=assertion.scope_grant_sha256,
                    trust_policy_sha256=principal.policy_sha256,
                    execution_admission_core_sha256=core_sha256,
                    operation_intent_sha256=operation_intent_sha256,
                    canonical_replay_key_sha256=replay_sha256,
                    budget_id_before=budget.budget_id,
                    budget_sha256_before=budget.budget_sha256,
                    budget_revision_before=budget.budget_revision,
                    budget_id_after=after_budget.budget_id,
                    budget_sha256_after=after_budget.budget_sha256,
                    budget_revision_after=after_budget.budget_revision,
                    reservation_commit_id=commit.commit_id,
                    reservation_commit_sha256=commit.commit_sha256,
                    admitted_at=consumed_at,
                )
                event_id, event_sha256, _ = _budget_event(
                    tenant_id=budget.tenant_id,
                    assessment_id=budget.assessment_id,
                    sequence=event_count + 1,
                    kind="reserve",
                    admission_id=receipt.admission_id,
                    custody_id=commit.commit_id,
                    before=budget,
                    after=after_budget,
                    previous_event_sha256=event_head,
                    recorded_at=consumed_at,
                )
                connection.execute(
                    """
                    INSERT INTO authenticated_model_execution_budget_events(
                        tenant_id, assessment_id, event_sequence, event_kind,
                        event_id, admission_id, custody_id, before_budget_json,
                        before_budget_sha256, after_budget_json, after_budget_sha256,
                        previous_event_sha256, event_sha256, recorded_at
                    ) VALUES (?, ?, ?, 'reserve', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        budget.tenant_id,
                        budget.assessment_id,
                        event_count + 1,
                        event_id,
                        receipt.admission_id,
                        commit.commit_id,
                        canonical_json(budget.to_dict()),
                        budget.budget_sha256,
                        canonical_json(after_budget.to_dict()),
                        after_budget.budget_sha256,
                        event_head,
                        event_sha256,
                        consumed_at,
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE authenticated_model_execution_budgets
                    SET budget_id = ?, budget_json = ?, budget_sha256 = ?,
                        budget_revision = ?, event_count = ?, event_head_sha256 = ?,
                        last_observed_at = ?
                    WHERE tenant_id = ? AND assessment_id = ?
                      AND budget_id = ? AND budget_sha256 = ?
                      AND budget_revision = ? AND event_count = ?
                      AND event_head_sha256 = ?
                    """,
                    (
                        after_budget.budget_id,
                        canonical_json(after_budget.to_dict()),
                        after_budget.budget_sha256,
                        after_budget.budget_revision,
                        event_count + 1,
                        event_sha256,
                        consumed_at,
                        budget.tenant_id,
                        budget.assessment_id,
                        budget.budget_id,
                        budget.budget_sha256,
                        budget.budget_revision,
                        event_count,
                        event_head,
                    ),
                )
                if updated.rowcount != 1:
                    raise StoreConflictError("Model execution budget head changed")
                effect = {
                    "effect_id": receipt.admission_id,
                    "effect_kind": MODEL_EXECUTION_EFFECT_KIND,
                    "payload": {
                        "admission_sha256": receipt.admission_sha256,
                        "authority_sha256": authority.authority_sha256,
                        "canonical_replay_key_sha256": replay_sha256,
                        "invocation_plan_sha256": plan.plan_sha256,
                        "reservation_commit_sha256": commit.commit_sha256,
                    },
                    "recorded_at": consumed_at,
                    "schema_version": 1,
                }
                effect_json = canonical_json(effect)
                effect_hash = sha256_text(effect_json)
                effects_hash = principal_assertion_effects_hash((effect_hash,))
                ledger = connection.execute(
                    "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
                    (authority.mission_id,),
                ).fetchone()
                if ledger is None:
                    raise StoreIntegrityError("Mission principal ledger is missing")
                _require_stored_types(
                    ledger,
                    text_fields=("head_hash",),
                    integer_fields=("assertion_count", "effect_count"),
                )
                sequence = ledger["assertion_count"] + 1
                previous_hash = ledger["head_hash"]
                entry = self._assertion_entry(
                    principal=principal,
                    assertion=assertion,
                    mission_id=authority.mission_id,
                    use_sequence=sequence,
                    assertion_hash=assertion.content_sha256,
                    operation_intent_json=operation_intent_json,
                    signed_intent_hash=operation_intent_sha256,
                    domain_request_hash=domain_request_sha256,
                    replay_hash=replay_sha256,
                    consumed_at=consumed_at,
                    effects_hash=effects_hash,
                    previous_hash=previous_hash,
                )
                entry_hash = principal_assertion_entry_hash(entry)
                self._authenticated._insert_assertion_use(
                    connection,
                    assertion_json=assertion_json,
                    entry=entry,
                    entry_hash=entry_hash,
                )
                connection.execute(
                    """
                    INSERT INTO principal_assertion_effects(
                        issuer, assertion_id, mission_id, effect_index,
                        effect_kind, effect_id, effect_json, effect_hash, recorded_at
                    ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                        authority.mission_id,
                        MODEL_EXECUTION_EFFECT_KIND,
                        receipt.admission_id,
                        effect_json,
                        effect_hash,
                        consumed_at,
                    ),
                )
                ledger_update = connection.execute(
                    """
                    UPDATE mission_principal_ledgers
                    SET head_hash = ?, assertion_count = assertion_count + 1,
                        effect_count = effect_count + 1, updated_at = ?
                    WHERE mission_id = ? AND assertion_count = ? AND head_hash = ?
                    """,
                    (
                        entry_hash,
                        consumed_at,
                        authority.mission_id,
                        sequence - 1,
                        previous_hash,
                    ),
                )
                if ledger_update.rowcount != 1:
                    raise StoreConflictError("Mission principal ledger changed")
                connection.execute(
                    """
                    INSERT INTO authenticated_model_execution_admissions(
                        admission_id, admission_sha256, mission_id, tenant_id,
                        assessment_id, plan_id, work_id, expert_profile_id,
                        authority_id, authority_sha256, authority_json,
                        invocation_plan_id, invocation_plan_sha256, invocation_plan_json,
                        assertion_issuer, assertion_id, assertion_sha256,
                        scope_grant_sha256, trust_policy_sha256,
                        canonical_replay_key_sha256, operation_intent_sha256,
                        domain_request_sha256, budget_id, budget_event_sequence,
                        reservation_commit_id, reservation_commit_sha256,
                        reservation_commit_json, receipt_json, admitted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.admission_id,
                        receipt.admission_sha256,
                        authority.mission_id,
                        authority.tenant_id,
                        authority.assessment_id,
                        authority.plan_id,
                        authority.work_id,
                        authority.expert_profile_id,
                        authority.authority_id,
                        authority.authority_sha256,
                        authority_json,
                        plan.plan_id,
                        plan.plan_sha256,
                        plan_json,
                        assertion.issuer,
                        assertion.assertion_id,
                        assertion.content_sha256,
                        assertion.scope_grant_sha256,
                        principal.policy_sha256,
                        replay_sha256,
                        operation_intent_sha256,
                        domain_request_sha256,
                        budget.budget_id,
                        event_count + 1,
                        commit.commit_id,
                        commit.commit_sha256,
                        canonical_json(commit.to_dict()),
                        canonical_json(receipt.to_dict()),
                        consumed_at,
                    ),
                )
                return VerifiedModelExecutionAdmission._seal(receipt, plan, authority)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authenticated model execution admission conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist model execution admission") from exc

    def current_budget(
        self,
        tenant_id: str,
        assessment_id: str,
    ) -> BudgetEnvelope:
        with self._store._read_connection() as connection:
            row = connection.execute(
                """
                SELECT budget_json FROM authenticated_model_execution_budgets
                WHERE tenant_id = ? AND assessment_id = ?
                """,
                (
                    _identifier(tenant_id, "tenant_id"),
                    _identifier(assessment_id, "assessment_id"),
                ),
            ).fetchone()
            if row is None:
                raise StoreConflictError("Authenticated model budget does not exist")
            try:
                return _budget_from_dict(
                    _stored_canonical_object(row["budget_json"], "model budget")
                )
            except Exception as exc:
                raise StoreIntegrityError("Stored model budget is invalid") from exc

    def _revalidate_admission_for_use(
        self,
        connection: sqlite3.Connection,
        admission: VerifiedModelExecutionAdmission,
        *,
        now: datetime,
    ) -> tuple[sqlite3.Row, PrincipalAssertion, ExpertBudgetReservationCommit]:
        if (
            type(admission) is not VerifiedModelExecutionAdmission
            or not admission._proof_is_valid()
        ):
            raise PrincipalAuthenticationError(
                "A process-local proof-sealed model execution admission is required"
            )
        receipt = AuthenticatedModelExecutionAdmissionReceipt.from_dict(admission.receipt.to_dict())
        plan = ExpertInvocationPlan.from_dict(admission.invocation_plan.to_dict())
        authority = ExpertExecutionAuthority.from_dict(admission.authority.to_dict())
        row = connection.execute(
            "SELECT * FROM authenticated_model_execution_admissions WHERE admission_id = ?",
            (receipt.admission_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Model execution admission is not durable")
        stored_receipt, stored_plan, stored_authority, commit = self._admission_from_row(row)
        if stored_receipt != receipt or stored_plan != plan or stored_authority != authority:
            raise StoreConflictError("Model execution admission proof is stale")
        identity, policies, mission, scopes = self._authenticated._verified_mission_state(
            connection,
            receipt.mission_id,
        )
        self._mission_is_active(connection, receipt.mission_id)
        active_plan, active_version = self._active_plan(connection, receipt.mission_id)
        if (
            active_plan.plan_id != receipt.active_plan_id
            or active_plan.content_sha256 != receipt.active_plan_sha256
            or active_version != receipt.active_plan_version
            or mission.revision != receipt.mission_revision
        ):
            raise StoreConflictError("Model execution admission source state is stale")
        use = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (receipt.assertion_issuer, receipt.assertion_id),
        ).fetchone()
        if use is None:
            raise StoreIntegrityError("Model execution principal assertion is missing")
        _require_stored_types(
            use,
            text_fields=(
                "assertion_json",
                "operation",
                "signed_intent_hash",
                "idempotency_key_hash",
            ),
        )
        try:
            assertion = PrincipalAssertion.from_dict(
                _stored_canonical_object(use["assertion_json"], "principal assertion")
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored model execution assertion is invalid") from exc
        if (
            assertion.content_sha256 != receipt.assertion_sha256
            or use["operation"] != PrincipalOperation.MODEL_EXECUTE.value
            or use["signed_intent_hash"] != receipt.operation_intent_sha256
            or use["idempotency_key_hash"] != receipt.canonical_replay_key_sha256
        ):
            raise StoreIntegrityError("Model execution assertion custody is invalid")
        principal = self._verify_principal(
            connection,
            identity=identity,
            trust_policies=policies,
            mission=mission,
            scope_grants=scopes,
            assertion=assertion,
            operation_intent_sha256=receipt.operation_intent_sha256,
            now=now,
        )
        expected_verification = model_execution_authentication_verification_sha256(
            trust_policy_sha256=principal.policy_sha256,
            scope_grant_sha256=assertion.scope_grant_sha256,
            assertion_sha256=assertion.content_sha256,
            assertion_key_sha256=principal.key_sha256,
            execution_admission_core_sha256=receipt.execution_admission_core_sha256,
        )
        if authority.authentication_verification_sha256 != expected_verification:
            raise PrincipalAuthenticationError(
                "Model execution admission authentication is no longer valid"
            )
        if authority.subject_principal_id != self._workload_subject:
            raise PrincipalAuthenticationError("Execution workload subject changed")
        if now < parse_timestamp(receipt.admitted_at, "admission admitted_at"):
            raise PrincipalAuthenticationError("Runtime clock precedes admission custody")
        return row, assertion, commit

    def _load_terminal_result(
        self,
        connection: sqlite3.Connection,
        admission_id: str,
        *,
        runtime_catalog: RuntimePackCatalog | None = None,
        runtime_pack: Mapping[str, Any] | None = None,
        envelope: ExecutionEnvelope | None = None,
    ) -> ExpertModelExecutionResult | None:
        row = connection.execute(
            """
            SELECT settlement.*, admission.mission_id,
                   admission.invocation_plan_json,
                   admission.reservation_commit_json
            FROM authenticated_model_execution_settlements AS settlement
            JOIN authenticated_model_execution_admissions AS admission
              ON admission.admission_id = settlement.admission_id
            WHERE settlement.admission_id = ?
            """,
            (admission_id,),
        ).fetchone()
        if row is None:
            return None
        _require_stored_types(
            row,
            text_fields=(
                "mission_id",
                "invocation_plan_json",
                "reservation_commit_json",
                "settlement_json",
                "execution_receipt_json",
            ),
        )
        for field_name in ("provider_observation_json", "work_product_json"):
            if row[field_name] is not None and type(row[field_name]) is not str:
                raise StoreIntegrityError(
                    "Authenticated model execution optional JSON storage type is invalid"
                )
        verify_authenticated_model_execution_store(
            connection,
            mission_id=row["mission_id"],
        )
        try:
            plan = ExpertInvocationPlan.from_dict(
                _stored_canonical_object(row["invocation_plan_json"], "invocation plan")
            )
            commit = ExpertBudgetReservationCommit.from_dict(
                _stored_canonical_object(
                    row["reservation_commit_json"],
                    "reservation commit",
                )
            )
            observation = (
                ExpertProviderObservation.from_dict(
                    _stored_canonical_object(
                        row["provider_observation_json"],
                        "provider observation",
                    )
                )
                if row["provider_observation_json"] is not None
                else None
            )
            settlement = ExpertBudgetSettlement.from_dict(
                _stored_canonical_object(row["settlement_json"], "settlement")
            )
            receipt = ExpertModelExecutionReceipt.from_dict(
                _stored_canonical_object(
                    row["execution_receipt_json"],
                    "execution receipt",
                )
            )
            product = None
            if row["work_product_json"] is not None:
                if runtime_catalog is None or runtime_pack is None or envelope is None:
                    raise StoreConflictError(
                        "Runtime sources are required to reconstruct a work product"
                    )
                product = parse_work_product(
                    _stored_canonical_object(row["work_product_json"], "work product"),
                    runtime_pack,
                    envelope,
                    runtime_catalog,
                )
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreIntegrityError("Stored model execution settlement is invalid") from exc
        return ExpertModelExecutionResult(
            receipt=receipt,
            invocation_plan=plan,
            reservation_commit=commit,
            observation=observation,
            settlement=settlement,
            work_product=product,
        )

    def _claim_dispatch(
        self,
        admission: VerifiedModelExecutionAdmission,
        *,
        adapter_principal_id: str,
        runtime_catalog: RuntimePackCatalog,
        runtime_pack: Mapping[str, Any],
        envelope: ExecutionEnvelope,
    ) -> ExpertModelExecutionResult | AuthenticatedModelExecutionDispatch:
        now = self._clock()
        claimed_at = format_timestamp(now)
        try:
            with self._store._write_connection() as connection:
                if (
                    type(admission) is not VerifiedModelExecutionAdmission
                    or not admission._proof_is_valid()
                ):
                    raise PrincipalAuthenticationError(
                        "A process-local proof-sealed model execution admission is required"
                    )
                terminal = self._load_terminal_result(
                    connection,
                    admission.receipt.admission_id,
                    runtime_catalog=runtime_catalog,
                    runtime_pack=runtime_pack,
                    envelope=envelope,
                )
                if terminal is not None:
                    return terminal
                self._revalidate_admission_for_use(connection, admission, now=now)
                existing = connection.execute(
                    """
                    SELECT dispatch_json
                    FROM authenticated_model_execution_dispatches
                    WHERE admission_id = ?
                    """,
                    (admission.receipt.admission_id,),
                ).fetchone()
                if existing is not None:
                    raise StoreConflictError("Model execution dispatch is pending reconciliation")
                if adapter_principal_id != admission.authority.provider_adapter_principal_id:
                    raise PrincipalAuthenticationError(
                        "Provider adapter principal does not match authority"
                    )
                dispatch = AuthenticatedModelExecutionDispatch(
                    admission_id=admission.receipt.admission_id,
                    admission_sha256=admission.receipt.admission_sha256,
                    authority_id=admission.authority.authority_id,
                    invocation_plan_id=admission.invocation_plan.plan_id,
                    adapter_principal_id=adapter_principal_id,
                    claimed_at=claimed_at,
                )
                connection.execute(
                    """
                    INSERT INTO authenticated_model_execution_dispatches(
                        admission_id, dispatch_id, dispatch_sha256,
                        dispatch_json, claimed_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        dispatch.admission_id,
                        dispatch.dispatch_id,
                        dispatch.dispatch_sha256,
                        canonical_json(dispatch.to_dict()),
                        claimed_at,
                    ),
                )
                return dispatch
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Model execution dispatch conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist model execution dispatch") from exc

    @staticmethod
    def _evaluate_observation(
        observation: ExpertProviderObservation | None,
        *,
        plan: ExpertInvocationPlan,
        commit: ExpertBudgetReservationCommit,
        completion_time: str,
        runtime_catalog: RuntimePackCatalog,
        runtime_pack: Mapping[str, Any],
        envelope: ExecutionEnvelope,
        initial_state: str,
        initial_reason: str,
        initial_output_status: str,
    ) -> tuple[str, str, str, ExpertProviderObservation | None, WorkProduct | None]:
        state = initial_state
        reason = initial_reason
        output_status = initial_output_status
        product: WorkProduct | None = None
        if observation is None:
            return state, reason, output_status, None, None
        if type(observation) is not ExpertProviderObservation:
            return (
                "indeterminate_quarantined",
                "provider_observation_type_invalid",
                "indeterminate",
                None,
                None,
            )
        try:
            observation = ExpertProviderObservation.from_dict(observation.to_dict())
        except Exception:
            return (
                "indeterminate_quarantined",
                "provider_observation_invalid",
                "indeterminate",
                None,
                None,
            )
        binding = (
            observation.invocation_plan_id == plan.plan_id
            and observation.invocation_plan_sha256 == plan.plan_sha256
            and observation.provider_id == plan.provider_id
            and observation.provider_api_version == plan.provider_api_version
            and observation.model_id == plan.model_id
            and observation.model_version == plan.model_version
        )
        timing = _instant(observation.started_at) >= _instant(commit.committed_at) and _instant(
            observation.completed_at
        ) <= _instant(completion_time)
        if not binding or not timing:
            return (
                "indeterminate_quarantined",
                "provider_route_request_or_time_substitution",
                "indeterminate",
                observation,
                None,
            )
        usage = (
            observation.input_tokens,
            observation.output_tokens,
            observation.billable_cost_micros,
        )
        ceilings = (
            commit.reserved_input_tokens,
            commit.reserved_output_tokens,
            commit.reserved_cost_micros,
        )
        if observation.usage_trustworthy and any(
            item is None or item > ceiling for item, ceiling in zip(usage, ceilings, strict=True)
        ):
            return (
                "indeterminate_quarantined",
                "usage_exceeds_committed_ceiling",
                "indeterminate",
                observation,
                None,
            )
        if observation.terminal_state == "failed":
            return (
                "provider_failed_settled",
                "provider_failed",
                "no_output",
                observation,
                None,
            )
        if observation.terminal_state == "incomplete":
            return (
                "incomplete_settled",
                "provider_incomplete",
                (
                    "referenced_output_not_parsed"
                    if observation.structured_output_reference
                    else "no_output"
                ),
                observation,
                None,
            )
        if observation.structured_output_reference is not None:
            return (
                "incomplete_settled",
                "referenced_output_requires_independent_retrieval_and_parsing",
                "referenced_output_not_parsed",
                observation,
                None,
            )
        try:
            raw = observation.structured_output_json
            if raw is None or len(raw.encode("utf-8")) > MAX_WORK_PRODUCT_BYTES:
                raise ExpertModelExecutionError("Provider output is absent or oversized")
            parsed = loads_json_without_duplicate_keys(raw)
            if not isinstance(parsed, dict) or canonical_json(parsed) != raw:
                raise ExpertModelExecutionError("Provider output is not canonical JSON")
            product = parse_work_product(
                parsed,
                runtime_pack,
                envelope,
                runtime_catalog,
            )
        except (ValueError, DuplicateJsonKeyError, ExpertModelExecutionError):
            return (
                "incomplete_settled",
                "malformed_structured_output",
                "malformed_output",
                observation,
                None,
            )
        return (
            "completed_settled",
            "completed_with_parsed_advisory_work_product",
            "parsed_advisory_work_product",
            observation,
            product,
        )

    def _settle(
        self,
        admission_id: str,
        *,
        observation: ExpertProviderObservation | None,
        terminal_state: str,
        outcome_reason: str,
        output_status: str,
        product: WorkProduct | None,
        settled_at: str,
        runtime_catalog: RuntimePackCatalog | None = None,
        runtime_pack: Mapping[str, Any] | None = None,
        envelope: ExecutionEnvelope | None = None,
    ) -> ExpertModelExecutionResult:
        allowed_states = {
            "completed_settled",
            "provider_failed_settled",
            "incomplete_settled",
            "indeterminate_quarantined",
        }
        if terminal_state not in allowed_states:
            raise ExpertModelExecutionError("Settlement terminal state is invalid")
        try:
            with self._store._write_connection() as connection:
                existing = self._load_terminal_result(
                    connection,
                    admission_id,
                    runtime_catalog=runtime_catalog,
                    runtime_pack=runtime_pack,
                    envelope=envelope,
                )
                if existing is not None:
                    return existing
                admission_row = connection.execute(
                    """
                    SELECT * FROM authenticated_model_execution_admissions
                    WHERE admission_id = ?
                    """,
                    (admission_id,),
                ).fetchone()
                dispatch_row = connection.execute(
                    """
                    SELECT * FROM authenticated_model_execution_dispatches
                    WHERE admission_id = ?
                    """,
                    (admission_id,),
                ).fetchone()
                if admission_row is None or dispatch_row is None:
                    raise StoreConflictError("Model execution is not durably dispatch-claimed")
                _, plan, authority, commit = self._admission_from_row(admission_row)
                _require_stored_types(
                    dispatch_row,
                    text_fields=(
                        "admission_id",
                        "dispatch_id",
                        "dispatch_sha256",
                        "dispatch_json",
                        "claimed_at",
                    ),
                )
                dispatch = AuthenticatedModelExecutionDispatch.from_dict(
                    _stored_canonical_object(dispatch_row["dispatch_json"], "dispatch")
                )
                if (
                    dispatch.admission_id != admission_id
                    or dispatch.dispatch_id != dispatch_row["dispatch_id"]
                    or dispatch.dispatch_sha256 != dispatch_row["dispatch_sha256"]
                    or dispatch.authority_id != authority.authority_id
                    or dispatch.invocation_plan_id != plan.plan_id
                    or dispatch.claimed_at != dispatch_row["claimed_at"]
                ):
                    raise StoreIntegrityError("Model execution dispatch custody is invalid")
                if observation is not None:
                    observation = ExpertProviderObservation.from_dict(observation.to_dict())
                duplicate_request = None
                if observation is not None:
                    duplicate_request = connection.execute(
                        """
                        SELECT admission_id
                        FROM authenticated_model_execution_provider_requests
                        WHERE provider_id = ? AND provider_request_id = ?
                        """,
                        (observation.provider_id, observation.provider_request_id),
                    ).fetchone()
                if (
                    duplicate_request is not None
                    and duplicate_request["admission_id"] != admission_id
                ):
                    observation = None
                    product = None
                    terminal_state = "indeterminate_quarantined"
                    outcome_reason = "duplicate_provider_request"
                    output_status = "indeterminate"
                budget_row = connection.execute(
                    """
                    SELECT * FROM authenticated_model_execution_budgets
                    WHERE tenant_id = ? AND assessment_id = ?
                    """,
                    (authority.tenant_id, authority.assessment_id),
                ).fetchone()
                if budget_row is None:
                    raise StoreIntegrityError("Authenticated model budget is missing")
                _require_stored_types(
                    budget_row,
                    text_fields=(
                        "budget_id",
                        "budget_json",
                        "budget_sha256",
                        "budget_revision",
                        "event_head_sha256",
                        "last_observed_at",
                    ),
                    integer_fields=("event_count",),
                )
                current = _budget_from_dict(
                    _stored_canonical_object(budget_row["budget_json"], "model budget")
                )
                requested_time = parse_timestamp(settled_at, "settled_at")
                last_time = parse_timestamp(
                    budget_row["last_observed_at"],
                    "model budget last_observed_at",
                )
                if requested_time < last_time:
                    settled_at = budget_row["last_observed_at"]
                    terminal_state = "indeterminate_quarantined"
                    outcome_reason = "coordinator_clock_indeterminate"
                    output_status = "indeterminate"
                    product = None
                trustworthy = (
                    observation is not None
                    and observation.usage_trustworthy
                    and terminal_state != "indeterminate_quarantined"
                    and observation.input_tokens is not None
                    and observation.output_tokens is not None
                    and observation.billable_cost_micros is not None
                    and observation.input_tokens <= commit.reserved_input_tokens
                    and observation.output_tokens <= commit.reserved_output_tokens
                    and observation.billable_cost_micros <= commit.reserved_cost_micros
                )
                charged = (
                    (
                        observation.input_tokens,
                        observation.output_tokens,
                        observation.billable_cost_micros,
                    )
                    if trustworthy and observation is not None
                    else (
                        commit.reserved_input_tokens,
                        commit.reserved_output_tokens,
                        commit.reserved_cost_micros,
                    )
                )
                if (
                    current.aggregate_input_tokens_reserved < commit.reserved_input_tokens
                    or current.aggregate_output_tokens_reserved < commit.reserved_output_tokens
                    or current.aggregate_cost_reserved_micros < commit.reserved_cost_micros
                ):
                    raise StoreIntegrityError(
                        "Model execution reservation is not represented in the budget"
                    )
                revision_after = _next_budget_revision(
                    "settle",
                    commit.commit_id,
                    current.budget_revision,
                )
                after = _budget_snapshot(
                    current,
                    input_reserved=(
                        current.aggregate_input_tokens_reserved
                        - commit.reserved_input_tokens
                        + charged[0]
                    ),
                    output_reserved=(
                        current.aggregate_output_tokens_reserved
                        - commit.reserved_output_tokens
                        + charged[1]
                    ),
                    cost_reserved=(
                        current.aggregate_cost_reserved_micros
                        - commit.reserved_cost_micros
                        + charged[2]
                    ),
                    revision=revision_after,
                )
                if any(type(item) is not int for item in charged):
                    raise StoreIntegrityError("Model execution charge type is invalid")
                if product is not None:
                    if (
                        type(product) is not WorkProduct
                        or runtime_catalog is None
                        or runtime_pack is None
                        or envelope is None
                    ):
                        raise StoreIntegrityError(
                            "Model execution work product lacks exact runtime sources"
                        )
                    try:
                        product = parse_work_product(
                            product.to_dict(),
                            runtime_pack,
                            envelope,
                            runtime_catalog,
                        )
                    except Exception as exc:
                        raise StoreIntegrityError(
                            "Model execution work product is not canonical"
                        ) from exc
                settlement = ExpertBudgetSettlement(
                    reservation_commit_id=commit.commit_id,
                    reservation_commit_sha256=commit.commit_sha256,
                    provider_observation_id=(
                        observation.observation_id if observation is not None else None
                    ),
                    provider_observation_sha256=(
                        observation.observation_sha256 if observation is not None else None
                    ),
                    terminal_state=terminal_state,
                    charged_input_tokens=charged[0],
                    charged_output_tokens=charged[1],
                    charged_cost_micros=charged[2],
                    usage_basis="trusted_actual" if trustworthy else "full_reservation",
                    outcome_reason=outcome_reason,
                    budget_revision_before=current.budget_revision,
                    budget_revision_after=after.budget_revision,
                    settled_at=settled_at,
                    quarantined=terminal_state == "indeterminate_quarantined",
                )
                receipt = ExpertModelExecutionReceipt(
                    authority_id=authority.authority_id,
                    authority_sha256=authority.authority_sha256,
                    invocation_plan_id=plan.plan_id,
                    invocation_plan_sha256=plan.plan_sha256,
                    reservation_commit_id=commit.commit_id,
                    reservation_commit_sha256=commit.commit_sha256,
                    provider_observation_id=(
                        observation.observation_id if observation is not None else None
                    ),
                    provider_observation_sha256=(
                        observation.observation_sha256 if observation is not None else None
                    ),
                    settlement_id=settlement.settlement_id,
                    settlement_sha256=settlement.settlement_sha256,
                    work_product_id=product.product_id if product is not None else None,
                    work_product_sha256=(product.product_sha256 if product is not None else None),
                    execution_state=terminal_state,
                    output_status=output_status,
                    recorded_at=settled_at,
                )
                sequence = budget_row["event_count"] + 1
                event_id, event_sha256, _ = _budget_event(
                    tenant_id=current.tenant_id,
                    assessment_id=current.assessment_id,
                    sequence=sequence,
                    kind="settle",
                    admission_id=admission_id,
                    custody_id=settlement.settlement_id,
                    before=current,
                    after=after,
                    previous_event_sha256=budget_row["event_head_sha256"],
                    recorded_at=settled_at,
                )
                connection.execute(
                    """
                    INSERT INTO authenticated_model_execution_budget_events(
                        tenant_id, assessment_id, event_sequence, event_kind,
                        event_id, admission_id, custody_id, before_budget_json,
                        before_budget_sha256, after_budget_json, after_budget_sha256,
                        previous_event_sha256, event_sha256, recorded_at
                    ) VALUES (?, ?, ?, 'settle', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        current.tenant_id,
                        current.assessment_id,
                        sequence,
                        event_id,
                        admission_id,
                        settlement.settlement_id,
                        canonical_json(current.to_dict()),
                        current.budget_sha256,
                        canonical_json(after.to_dict()),
                        after.budget_sha256,
                        budget_row["event_head_sha256"],
                        event_sha256,
                        settled_at,
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE authenticated_model_execution_budgets
                    SET budget_id = ?, budget_json = ?, budget_sha256 = ?,
                        budget_revision = ?, event_count = ?, event_head_sha256 = ?,
                        last_observed_at = ?
                    WHERE tenant_id = ? AND assessment_id = ?
                      AND budget_id = ? AND budget_sha256 = ?
                      AND budget_revision = ? AND event_count = ?
                      AND event_head_sha256 = ?
                    """,
                    (
                        after.budget_id,
                        canonical_json(after.to_dict()),
                        after.budget_sha256,
                        after.budget_revision,
                        sequence,
                        event_sha256,
                        settled_at,
                        current.tenant_id,
                        current.assessment_id,
                        current.budget_id,
                        current.budget_sha256,
                        current.budget_revision,
                        sequence - 1,
                        budget_row["event_head_sha256"],
                    ),
                )
                if updated.rowcount != 1:
                    raise StoreConflictError("Model budget changed during settlement")
                connection.execute(
                    """
                    INSERT INTO authenticated_model_execution_settlements(
                        admission_id, provider_observation_json,
                        provider_observation_sha256, settlement_json,
                        settlement_sha256, execution_receipt_json,
                        execution_receipt_sha256, work_product_json,
                        work_product_sha256, tenant_id, assessment_id,
                        budget_id, budget_event_sequence, terminal_state, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        admission_id,
                        (
                            canonical_json(observation.to_dict())
                            if observation is not None
                            else None
                        ),
                        (observation.observation_sha256 if observation is not None else None),
                        canonical_json(settlement.to_dict()),
                        settlement.settlement_sha256,
                        canonical_json(receipt.to_dict()),
                        receipt.receipt_sha256,
                        canonical_json(product.to_dict()) if product is not None else None,
                        product.product_sha256 if product is not None else None,
                        current.tenant_id,
                        current.assessment_id,
                        current.budget_id,
                        sequence,
                        terminal_state,
                        settled_at,
                    ),
                )
                if observation is not None:
                    connection.execute(
                        """
                        INSERT INTO authenticated_model_execution_provider_requests(
                            provider_id, provider_request_id, admission_id,
                            observation_sha256, recorded_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            observation.provider_id,
                            observation.provider_request_id,
                            admission_id,
                            observation.observation_sha256,
                            settled_at,
                        ),
                    )
                return ExpertModelExecutionResult(
                    receipt=receipt,
                    invocation_plan=plan,
                    reservation_commit=commit,
                    observation=observation,
                    settlement=settlement,
                    work_product=product,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Model execution settlement conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist model execution settlement") from exc

    def execute(
        self,
        admission: VerifiedModelExecutionAdmission,
        runtime_catalog: RuntimePackCatalog,
        runtime_pack: Mapping[str, Any],
        envelope: ExecutionEnvelope,
        decision: RoutingDecision,
        capability: ModelCapabilityDeclaration,
        provider: AuthenticatedExpertModelProviderAdapter,
    ) -> ExpertModelExecutionResult:
        """Revalidate, dispatch once, and durably settle every observed outcome."""

        if (
            type(admission) is not VerifiedModelExecutionAdmission
            or not admission._proof_is_valid()
        ):
            raise PrincipalAuthenticationError(
                "A process-local proof-sealed model execution admission is required"
            )
        if not isinstance(provider, AuthenticatedExpertModelProviderAdapter):
            raise ExpertModelExecutionError("Provider adapter contract is invalid")
        if not isinstance(provider.qualifying, bool):
            raise ExpertModelExecutionError("Provider qualification state is invalid")
        with self._store._read_connection() as connection:
            terminal = self._load_terminal_result(
                connection,
                admission.receipt.admission_id,
                runtime_catalog=runtime_catalog,
                runtime_pack=runtime_pack,
                envelope=envelope,
            )
            event = connection.execute(
                """
                SELECT before_budget_json
                FROM authenticated_model_execution_budget_events
                WHERE admission_id = ? AND event_kind = 'reserve'
                """,
                (admission.receipt.admission_id,),
            ).fetchone()
            if event is None:
                raise StoreIntegrityError("Admission reservation event is missing")
            _require_stored_types(event, text_fields=("before_budget_json",))
            before_budget = _budget_from_dict(
                _stored_canonical_object(event["before_budget_json"], "before budget")
            )
        validation_time = (
            admission.receipt.admitted_at
            if terminal is not None
            else format_timestamp(self._clock())
        )
        rebuilt = build_invocation_plan(
            runtime_catalog,
            runtime_pack,
            envelope,
            decision,
            capability,
            before_budget,
            admission.authority,
            now=validation_time,
        )
        if rebuilt.to_dict() != admission.invocation_plan.to_dict():
            raise StoreConflictError("Model execution source binding changed")
        if terminal is not None:
            return terminal
        claimed = self._claim_dispatch(
            admission,
            adapter_principal_id=provider.adapter_principal_id,
            runtime_catalog=runtime_catalog,
            runtime_pack=runtime_pack,
            envelope=envelope,
        )
        if type(claimed) is ExpertModelExecutionResult:
            return claimed
        if type(claimed) is not AuthenticatedModelExecutionDispatch:
            raise StoreIntegrityError("Model execution dispatch return type is invalid")
        observation: ExpertProviderObservation | None = None
        initial_state = "provider_failed_settled"
        initial_reason = "provider_rejected_before_dispatch"
        initial_output_status = "no_output"
        pending_base_exception: BaseException | None = None
        try:
            observation = provider.invoke(
                admission.invocation_plan,
                admission.authority.credential_reference,
            )
        except ProviderInvocationRejected:
            pass
        except ProviderOutcomeIndeterminate:
            initial_state = "indeterminate_quarantined"
            initial_reason = "provider_outcome_indeterminate"
            initial_output_status = "indeterminate"
        except Exception:
            initial_state = "indeterminate_quarantined"
            initial_reason = "provider_outcome_indeterminate"
            initial_output_status = "indeterminate"
        except BaseException as exc:
            pending_base_exception = exc
            initial_state = "indeterminate_quarantined"
            initial_reason = "provider_outcome_indeterminate"
            initial_output_status = "indeterminate"
        completion_time, clock_failure = _post_dispatch_timestamp(
            self._clock,
            claimed.claimed_at,
        )
        if clock_failure is not None:
            pending_base_exception = pending_base_exception or clock_failure
            initial_state = "indeterminate_quarantined"
            initial_reason = "coordinator_clock_indeterminate"
            initial_output_status = "indeterminate"
            observation = None
        state, reason, output_status, observation, product = self._evaluate_observation(
            observation,
            plan=admission.invocation_plan,
            commit=self._admission_commit(admission.receipt.admission_id),
            completion_time=completion_time,
            runtime_catalog=runtime_catalog,
            runtime_pack=runtime_pack,
            envelope=envelope,
            initial_state=initial_state,
            initial_reason=initial_reason,
            initial_output_status=initial_output_status,
        )
        if pending_base_exception is not None:
            state = "indeterminate_quarantined"
            reason = "provider_outcome_indeterminate"
            output_status = "indeterminate"
            product = None
        settled_time, settlement_clock_failure = _post_dispatch_timestamp(
            self._clock,
            completion_time,
        )
        if settlement_clock_failure is not None:
            pending_base_exception = pending_base_exception or settlement_clock_failure
            state = "indeterminate_quarantined"
            reason = "coordinator_clock_indeterminate"
            output_status = "indeterminate"
            product = None
        result = self._settle(
            admission.receipt.admission_id,
            observation=observation,
            terminal_state=state,
            outcome_reason=reason,
            output_status=output_status,
            product=product,
            settled_at=settled_time,
            runtime_catalog=runtime_catalog,
            runtime_pack=runtime_pack,
            envelope=envelope,
        )
        if pending_base_exception is not None:
            raise pending_base_exception
        return result

    def _admission_commit(self, admission_id: str) -> ExpertBudgetReservationCommit:
        with self._store._read_connection() as connection:
            row = connection.execute(
                """
                SELECT reservation_commit_json
                FROM authenticated_model_execution_admissions
                WHERE admission_id = ?
                """,
                (_identifier(admission_id, "admission_id"),),
            ).fetchone()
            if row is None:
                raise StoreConflictError("Model execution admission does not exist")
            _require_stored_types(row, text_fields=("reservation_commit_json",))
            try:
                return ExpertBudgetReservationCommit.from_dict(
                    _stored_canonical_object(
                        row["reservation_commit_json"],
                        "reservation commit",
                    )
                )
            except Exception as exc:
                raise StoreIntegrityError("Stored reservation commit is invalid") from exc

    def reconcile_incomplete(self, admission_id: str) -> ExpertModelExecutionResult:
        """Fully charge and quarantine a dispatch left nonterminal after restart."""

        admission_id = _identifier(admission_id, "admission_id")
        with self._store._read_connection() as connection:
            terminal = self._load_terminal_result(connection, admission_id)
            if terminal is not None:
                return terminal
            dispatch = connection.execute(
                """
                SELECT claimed_at FROM authenticated_model_execution_dispatches
                WHERE admission_id = ?
                """,
                (admission_id,),
            ).fetchone()
            if dispatch is None:
                raise StoreConflictError(
                    "Only a durably dispatch-claimed execution can be reconciled"
                )
            _require_stored_types(dispatch, text_fields=("claimed_at",))
        settled_at, _ = _post_dispatch_timestamp(
            self._clock,
            dispatch["claimed_at"],
        )
        return self._settle(
            admission_id,
            observation=None,
            terminal_state="indeterminate_quarantined",
            outcome_reason="dispatch_reconciled_after_restart",
            output_status="indeterminate",
            product=None,
            settled_at=settled_at,
        )


def _stored_canonical_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not str:
        raise StoreIntegrityError(f"{label} must be stored as text")
    try:
        parsed = loads_json_without_duplicate_keys(value)
    except Exception as exc:
        raise StoreIntegrityError(f"{label} is not valid JSON") from exc
    if type(parsed) is not dict or canonical_json(parsed) != value:
        raise StoreIntegrityError(f"{label} is not a canonical JSON object")
    return parsed


def _require_stored_types(
    row: sqlite3.Row,
    *,
    text_fields: tuple[str, ...] = (),
    integer_fields: tuple[str, ...] = (),
) -> None:
    if any(type(row[field]) is not str for field in text_fields):
        raise StoreIntegrityError("Authenticated model execution text storage type is invalid")
    if any(type(row[field]) is not int for field in integer_fields):
        raise StoreIntegrityError("Authenticated model execution integer storage type is invalid")


def verify_authenticated_model_execution_store(
    connection: sqlite3.Connection,
    *,
    mission_id: str | None = None,
) -> tuple[int, int, int, int]:
    """Verify every authenticated execution chain from source to budget head."""

    if mission_id is not None:
        verify_authenticated_model_execution_store(connection)

    admissions = connection.execute(
        """
        SELECT * FROM authenticated_model_execution_admissions
        WHERE (? IS NULL OR mission_id = ?)
        ORDER BY admission_id
        """,
        (mission_id, mission_id),
    ).fetchall()
    admission_by_id = {row["admission_id"]: row for row in admissions}
    for row in admissions:
        _require_stored_types(
            row,
            text_fields=(
                "admission_id",
                "admission_sha256",
                "mission_id",
                "tenant_id",
                "assessment_id",
                "plan_id",
                "work_id",
                "expert_profile_id",
                "authority_id",
                "authority_sha256",
                "authority_json",
                "invocation_plan_id",
                "invocation_plan_sha256",
                "invocation_plan_json",
                "assertion_issuer",
                "assertion_id",
                "assertion_sha256",
                "scope_grant_sha256",
                "trust_policy_sha256",
                "canonical_replay_key_sha256",
                "operation_intent_sha256",
                "domain_request_sha256",
                "budget_id",
                "reservation_commit_id",
                "reservation_commit_sha256",
                "reservation_commit_json",
                "receipt_json",
                "admitted_at",
            ),
            integer_fields=("budget_event_sequence",),
        )
        try:
            authority = ExpertExecutionAuthority.from_dict(
                _stored_canonical_object(row["authority_json"], "authority_json")
            )
            plan = ExpertInvocationPlan.from_dict(
                _stored_canonical_object(
                    row["invocation_plan_json"],
                    "invocation_plan_json",
                )
            )
            commit = ExpertBudgetReservationCommit.from_dict(
                _stored_canonical_object(
                    row["reservation_commit_json"],
                    "reservation_commit_json",
                )
            )
            receipt = AuthenticatedModelExecutionAdmissionReceipt.from_dict(
                _stored_canonical_object(row["receipt_json"], "admission receipt")
            )
        except ExpertModelExecutionError as exc:
            raise StoreIntegrityError("Authenticated model admission record is invalid") from exc
        core_sha256 = model_execution_admission_core_sha256(authority)
        use = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ?
            """,
            (row["assertion_issuer"], row["assertion_id"]),
        ).fetchone()
        effect = connection.execute(
            """
            SELECT * FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ?
            ORDER BY effect_index
            """,
            (row["assertion_issuer"], row["assertion_id"]),
        ).fetchall()
        if use is None or len(effect) != 1:
            raise StoreIntegrityError("Model execution assertion effect is missing")
        try:
            assertion = PrincipalAssertion.from_dict(
                _stored_canonical_object(use["assertion_json"], "principal assertion")
            )
        except Exception as exc:
            raise StoreIntegrityError("Model execution principal assertion is invalid") from exc
        operation_intent = model_execution_operation_intent(
            authority.mission_id,
            assertion.profile_id,
            core_sha256,
        )
        operation_intent_sha256 = compute_operation_intent_hash(
            PrincipalOperation.MODEL_EXECUTE,
            operation_intent,
        )
        replay_sha256 = model_execution_canonical_replay_key_sha256(
            assertion=assertion,
            authority=authority,
            invocation_plan=plan,
            operation_intent_sha256=operation_intent_sha256,
        )
        domain_request_sha256 = canonical_sha256(
            {
                "domain": "sunderkey.authenticated-model-execution-request.v1",
                "execution_admission_core_sha256": core_sha256,
                "invocation_plan_sha256": plan.plan_sha256,
                "schema_version": 1,
            }
        )
        activation = connection.execute(
            """
            SELECT plan_json, plan_content_sha256, plan_version
            FROM collaboration_plan_activations
            WHERE mission_id = ? AND plan_id = ?
            """,
            (row["mission_id"], row["plan_id"]),
        ).fetchone()
        if activation is None:
            raise StoreIntegrityError("Model execution plan activation is missing")
        _require_stored_types(
            activation,
            text_fields=("plan_json", "plan_content_sha256"),
            integer_fields=("plan_version",),
        )
        try:
            collaboration_plan = CollaborationPlan.from_dict(
                _stored_canonical_object(activation["plan_json"], "collaboration plan")
            )
        except Exception as exc:
            raise StoreIntegrityError("Model execution collaboration plan is invalid") from exc
        work = next(
            (item for item in collaboration_plan.work_items if item.work_item_id == row["work_id"]),
            None,
        )
        effect_value = _stored_canonical_object(
            effect[0]["effect_json"],
            "model execution effect",
        )
        expected_effect_payload = {
            "admission_sha256": receipt.admission_sha256,
            "authority_sha256": authority.authority_sha256,
            "canonical_replay_key_sha256": replay_sha256,
            "invocation_plan_sha256": plan.plan_sha256,
            "reservation_commit_sha256": commit.commit_sha256,
        }
        event = connection.execute(
            """
            SELECT * FROM authenticated_model_execution_budget_events
            WHERE tenant_id = ? AND assessment_id = ? AND event_sequence = ?
            """,
            (
                row["tenant_id"],
                row["assessment_id"],
                row["budget_event_sequence"],
            ),
        ).fetchone()
        if event is None:
            raise StoreIntegrityError("Model execution reservation event is missing")
        _require_stored_types(
            event,
            text_fields=(
                "tenant_id",
                "assessment_id",
                "event_kind",
                "event_id",
                "admission_id",
                "custody_id",
                "before_budget_json",
                "before_budget_sha256",
                "after_budget_json",
                "after_budget_sha256",
                "previous_event_sha256",
                "event_sha256",
                "recorded_at",
            ),
            integer_fields=("event_sequence",),
        )
        before_budget = _budget_from_dict(
            _stored_canonical_object(event["before_budget_json"], "before budget")
        )
        after_budget = _budget_from_dict(
            _stored_canonical_object(event["after_budget_json"], "after budget")
        )
        try:
            expected_after_budget = _budget_snapshot(
                before_budget,
                input_reserved=(
                    before_budget.aggregate_input_tokens_reserved + commit.reserved_input_tokens
                ),
                output_reserved=(
                    before_budget.aggregate_output_tokens_reserved + commit.reserved_output_tokens
                ),
                cost_reserved=(
                    before_budget.aggregate_cost_reserved_micros + commit.reserved_cost_micros
                ),
                revision=commit.budget_revision_after,
            )
        except Exception as exc:
            raise StoreIntegrityError("Model reservation budget arithmetic is invalid") from exc
        expected_receipt_bindings = (
            receipt.admission_id == row["admission_id"],
            receipt.admission_sha256 == row["admission_sha256"],
            receipt.mission_id == authority.mission_id == row["mission_id"],
            receipt.tenant_id == authority.tenant_id == row["tenant_id"],
            receipt.assessment_id == authority.assessment_id == row["assessment_id"],
            receipt.active_plan_id == authority.plan_id == row["plan_id"],
            receipt.active_plan_sha256 == collaboration_plan.content_sha256,
            receipt.active_plan_version == activation["plan_version"],
            receipt.work_id == authority.work_id == row["work_id"],
            receipt.expert_profile_id == authority.expert_profile_id == row["expert_profile_id"],
            receipt.runtime_catalog_sha256
            == authority.runtime_catalog_sha256
            == plan.runtime_catalog_sha256,
            receipt.runtime_pack_sha256
            == authority.runtime_pack_sha256
            == plan.runtime_pack_sha256,
            receipt.execution_envelope_sha256
            == authority.execution_envelope_sha256
            == plan.execution_envelope_sha256,
            receipt.routing_decision_sha256
            == authority.routing_decision_sha256
            == plan.routing_decision_sha256,
            receipt.capability_sha256
            == authority.capability_sha256
            == plan.capability_sha256
            == commit.capability_sha256,
            receipt.reservation_sha256
            == authority.reservation_sha256
            == plan.reservation_sha256
            == commit.proposed_reservation_sha256,
            receipt.authority_id == authority.authority_id == row["authority_id"],
            receipt.authority_sha256 == authority.authority_sha256 == row["authority_sha256"],
            receipt.invocation_plan_id == plan.plan_id == row["invocation_plan_id"],
            receipt.invocation_plan_sha256 == plan.plan_sha256 == row["invocation_plan_sha256"],
            receipt.assertion_issuer == assertion.issuer == row["assertion_issuer"],
            receipt.assertion_id == assertion.assertion_id == row["assertion_id"],
            receipt.assertion_sha256 == assertion.content_sha256 == row["assertion_sha256"],
            receipt.scope_grant_sha256 == assertion.scope_grant_sha256 == row["scope_grant_sha256"],
            receipt.trust_policy_sha256 == use["trust_policy_hash"] == row["trust_policy_sha256"],
            receipt.execution_admission_core_sha256 == core_sha256,
            receipt.operation_intent_sha256
            == operation_intent_sha256
            == row["operation_intent_sha256"],
            receipt.canonical_replay_key_sha256
            == replay_sha256
            == row["canonical_replay_key_sha256"],
            receipt.budget_id_before == before_budget.budget_id == row["budget_id"],
            receipt.budget_sha256_before == before_budget.budget_sha256,
            receipt.budget_revision_before == before_budget.budget_revision,
            receipt.budget_id_after == after_budget.budget_id,
            receipt.budget_sha256_after == after_budget.budget_sha256,
            receipt.budget_revision_after == after_budget.budget_revision,
            receipt.reservation_commit_id == commit.commit_id == row["reservation_commit_id"],
            receipt.reservation_commit_sha256
            == commit.commit_sha256
            == row["reservation_commit_sha256"],
            receipt.admitted_at == row["admitted_at"] == use["consumed_at"],
        )
        if (
            not all(expected_receipt_bindings)
            or work is None
            or work.owner_profile_id != authority.expert_profile_id
            or activation["plan_content_sha256"] != collaboration_plan.content_sha256
            or authority.issuer_assertion_sha256 != assertion.content_sha256
            or assertion.subject != authority.issuer_principal_id
            or assertion.issuer == assertion.subject
            or use["operation"] != PrincipalOperation.MODEL_EXECUTE.value
            or use["operation_intent_json"] != canonical_json(operation_intent)
            or use["signed_intent_hash"] != operation_intent_sha256
            or use["domain_request_hash"] != domain_request_sha256
            or row["domain_request_sha256"] != domain_request_sha256
            or use["idempotency_key_hash"] != replay_sha256
            or effect[0]["effect_index"] != 1
            or effect[0]["effect_kind"] != MODEL_EXECUTION_EFFECT_KIND
            or effect[0]["effect_id"] != receipt.admission_id
            or effect_value.get("payload") != expected_effect_payload
            or event["event_kind"] != "reserve"
            or event["tenant_id"] != row["tenant_id"]
            or event["assessment_id"] != row["assessment_id"]
            or event["event_sequence"] != row["budget_event_sequence"]
            or event["admission_id"] != receipt.admission_id
            or event["custody_id"] != commit.commit_id
            or event["before_budget_sha256"] != before_budget.budget_sha256
            or event["after_budget_sha256"] != after_budget.budget_sha256
            or after_budget.to_dict() != expected_after_budget.to_dict()
            or plan.authority_id != authority.authority_id
            or plan.authority_sha256 != authority.authority_sha256
            or commit.authority_id != authority.authority_id
            or commit.authority_sha256 != authority.authority_sha256
            or commit.invocation_plan_id != plan.plan_id
            or commit.invocation_plan_sha256 != plan.plan_sha256
            or commit.routing_decision_sha256 != plan.routing_decision_sha256
            or commit.tenant_id != authority.tenant_id
            or commit.assessment_id != authority.assessment_id
            or commit.task_id != authority.task_id
            or commit.budget_id != before_budget.budget_id
            or commit.budget_sha256 != before_budget.budget_sha256
            or commit.budget_revision_before != before_budget.budget_revision
            or commit.budget_revision_after != after_budget.budget_revision
        ):
            raise StoreIntegrityError("Authenticated model admission does not reconcile")

    dispatches = connection.execute(
        """
        SELECT dispatch.*
        FROM authenticated_model_execution_dispatches AS dispatch
        JOIN authenticated_model_execution_admissions AS admission
          ON admission.admission_id = dispatch.admission_id
        WHERE (? IS NULL OR admission.mission_id = ?)
        ORDER BY dispatch.admission_id
        """,
        (mission_id, mission_id),
    ).fetchall()
    for row in dispatches:
        _require_stored_types(
            row,
            text_fields=(
                "admission_id",
                "dispatch_id",
                "dispatch_sha256",
                "dispatch_json",
                "claimed_at",
            ),
        )
        try:
            dispatch = AuthenticatedModelExecutionDispatch.from_dict(
                _stored_canonical_object(row["dispatch_json"], "dispatch")
            )
        except ExpertModelExecutionError as exc:
            raise StoreIntegrityError("Authenticated model dispatch is invalid") from exc
        admission = admission_by_id.get(row["admission_id"])
        if admission is None:
            raise StoreIntegrityError("Model dispatch admission is missing")
        if (
            dispatch.admission_id != row["admission_id"]
            or dispatch.dispatch_id != row["dispatch_id"]
            or dispatch.dispatch_sha256 != row["dispatch_sha256"]
            or dispatch.claimed_at != row["claimed_at"]
            or dispatch.admission_sha256 != admission["admission_sha256"]
            or dispatch.authority_id != admission["authority_id"]
            or dispatch.invocation_plan_id != admission["invocation_plan_id"]
        ):
            raise StoreIntegrityError("Authenticated model dispatch does not reconcile")

    settlements = connection.execute(
        """
        SELECT settlement.*
        FROM authenticated_model_execution_settlements AS settlement
        JOIN authenticated_model_execution_admissions AS admission
          ON admission.admission_id = settlement.admission_id
        WHERE (? IS NULL OR admission.mission_id = ?)
        ORDER BY settlement.admission_id
        """,
        (mission_id, mission_id),
    ).fetchall()
    for row in settlements:
        _require_stored_types(
            row,
            text_fields=(
                "admission_id",
                "settlement_json",
                "settlement_sha256",
                "execution_receipt_json",
                "execution_receipt_sha256",
                "tenant_id",
                "assessment_id",
                "budget_id",
                "terminal_state",
                "recorded_at",
            ),
            integer_fields=("budget_event_sequence",),
        )
        for field_name in (
            "provider_observation_json",
            "provider_observation_sha256",
            "work_product_json",
            "work_product_sha256",
        ):
            if row[field_name] is not None and type(row[field_name]) is not str:
                raise StoreIntegrityError(
                    "Authenticated model settlement optional storage type is invalid"
                )
        admission = admission_by_id.get(row["admission_id"])
        if admission is None:
            raise StoreIntegrityError("Model settlement admission is missing")
        dispatch_row = connection.execute(
            """
            SELECT dispatch_json, claimed_at
            FROM authenticated_model_execution_dispatches
            WHERE admission_id = ?
            """,
            (row["admission_id"],),
        ).fetchone()
        if dispatch_row is None:
            raise StoreIntegrityError("Model settlement dispatch is missing")
        _require_stored_types(
            dispatch_row,
            text_fields=("dispatch_json", "claimed_at"),
        )
        try:
            plan = ExpertInvocationPlan.from_dict(
                _stored_canonical_object(
                    admission["invocation_plan_json"],
                    "invocation plan",
                )
            )
            authority = ExpertExecutionAuthority.from_dict(
                _stored_canonical_object(admission["authority_json"], "authority")
            )
            commit = ExpertBudgetReservationCommit.from_dict(
                _stored_canonical_object(
                    admission["reservation_commit_json"],
                    "reservation commit",
                )
            )
            settlement = ExpertBudgetSettlement.from_dict(
                _stored_canonical_object(row["settlement_json"], "settlement")
            )
            receipt = ExpertModelExecutionReceipt.from_dict(
                _stored_canonical_object(
                    row["execution_receipt_json"],
                    "execution receipt",
                )
            )
            observation = (
                ExpertProviderObservation.from_dict(
                    _stored_canonical_object(
                        row["provider_observation_json"],
                        "provider observation",
                    )
                )
                if row["provider_observation_json"] is not None
                else None
            )
        except ExpertModelExecutionError as exc:
            raise StoreIntegrityError("Authenticated model settlement is invalid") from exc
        product = (
            _stored_canonical_object(row["work_product_json"], "work product")
            if row["work_product_json"] is not None
            else None
        )
        event = connection.execute(
            """
            SELECT * FROM authenticated_model_execution_budget_events
            WHERE tenant_id = ? AND assessment_id = ? AND event_sequence = ?
            """,
            (
                row["tenant_id"],
                row["assessment_id"],
                row["budget_event_sequence"],
            ),
        ).fetchone()
        if event is None:
            raise StoreIntegrityError("Model settlement budget event is missing")
        _require_stored_types(
            event,
            text_fields=(
                "tenant_id",
                "assessment_id",
                "event_kind",
                "event_id",
                "admission_id",
                "custody_id",
                "before_budget_json",
                "before_budget_sha256",
                "after_budget_json",
                "after_budget_sha256",
                "previous_event_sha256",
                "event_sha256",
                "recorded_at",
            ),
            integer_fields=("event_sequence",),
        )
        before_budget = _budget_from_dict(
            _stored_canonical_object(event["before_budget_json"], "settlement before budget")
        )
        after_budget = _budget_from_dict(
            _stored_canonical_object(event["after_budget_json"], "settlement after budget")
        )
        after_counts = (
            before_budget.aggregate_input_tokens_reserved
            - commit.reserved_input_tokens
            + settlement.charged_input_tokens,
            before_budget.aggregate_output_tokens_reserved
            - commit.reserved_output_tokens
            + settlement.charged_output_tokens,
            before_budget.aggregate_cost_reserved_micros
            - commit.reserved_cost_micros
            + settlement.charged_cost_micros,
        )
        if any(type(item) is not int or item < 0 for item in after_counts):
            raise StoreIntegrityError("Model settlement budget arithmetic is invalid")
        try:
            expected_after_budget = _budget_snapshot(
                before_budget,
                input_reserved=after_counts[0],
                output_reserved=after_counts[1],
                cost_reserved=after_counts[2],
                revision=settlement.budget_revision_after,
            )
        except Exception as exc:
            raise StoreIntegrityError("Model settlement budget arithmetic is invalid") from exc
        observation_identity = (
            (observation.observation_id, observation.observation_sha256)
            if observation is not None
            else (None, None)
        )
        product_identity = (None, None)
        if product is not None:
            product_body = {
                key: value
                for key, value in product.items()
                if key not in {"product_id", "product_sha256"}
            }
            product_sha256 = canonical_sha256(
                {
                    "domain": "sunderkey.expert-work-product.v1",
                    "product": product_body,
                }
            )
            product_id = f"EWP-{product_sha256[7:39].upper()}"
            product_identity = (product_id, product_sha256)
        provider_request = connection.execute(
            """
            SELECT * FROM authenticated_model_execution_provider_requests
            WHERE admission_id = ?
            """,
            (row["admission_id"],),
        ).fetchone()
        if provider_request is not None:
            _require_stored_types(
                provider_request,
                text_fields=(
                    "provider_id",
                    "provider_request_id",
                    "admission_id",
                    "observation_sha256",
                    "recorded_at",
                ),
            )
        usage = (
            observation.input_tokens if observation is not None else None,
            observation.output_tokens if observation is not None else None,
            observation.billable_cost_micros if observation is not None else None,
        )
        ceilings = (
            commit.reserved_input_tokens,
            commit.reserved_output_tokens,
            commit.reserved_cost_micros,
        )
        trustworthy = (
            observation is not None
            and observation.usage_trustworthy
            and settlement.terminal_state != "indeterminate_quarantined"
            and all(
                type(item) is int and item <= ceiling
                for item, ceiling in zip(usage, ceilings, strict=True)
            )
        )
        expected_charged = usage if trustworthy else ceilings
        claimed_at = parse_timestamp(dispatch_row["claimed_at"], "dispatch claimed_at")
        settled_at = parse_timestamp(settlement.settled_at, "settlement settled_at")
        observation_binding_is_valid = observation is None or (
            observation.invocation_plan_id == plan.plan_id
            and observation.invocation_plan_sha256 == plan.plan_sha256
            and observation.provider_id == plan.provider_id
            and observation.provider_api_version == plan.provider_api_version
            and observation.model_id == plan.model_id
            and observation.model_version == plan.model_version
            and _instant(observation.started_at) >= _instant(commit.committed_at)
            and _instant(observation.completed_at) <= settled_at
        )
        if (
            settlement.settlement_sha256 != row["settlement_sha256"]
            or receipt.receipt_sha256 != row["execution_receipt_sha256"]
            or settlement.terminal_state != row["terminal_state"]
            or settlement.settled_at != row["recorded_at"]
            or settlement.reservation_commit_id != commit.commit_id
            or settlement.reservation_commit_sha256 != commit.commit_sha256
            or settlement.budget_revision_before != before_budget.budget_revision
            or settlement.budget_revision_after != after_budget.budget_revision
            or settlement.usage_basis != ("trusted_actual" if trustworthy else "full_reservation")
            or (
                settlement.charged_input_tokens,
                settlement.charged_output_tokens,
                settlement.charged_cost_micros,
            )
            != expected_charged
            or (
                settlement.provider_observation_id,
                settlement.provider_observation_sha256,
            )
            != observation_identity
            or (
                receipt.provider_observation_id,
                receipt.provider_observation_sha256,
            )
            != observation_identity
            or (receipt.work_product_id, receipt.work_product_sha256) != product_identity
            or receipt.authority_id != authority.authority_id
            or receipt.authority_sha256 != authority.authority_sha256
            or receipt.invocation_plan_id != plan.plan_id
            or receipt.invocation_plan_sha256 != plan.plan_sha256
            or receipt.reservation_commit_id != commit.commit_id
            or receipt.reservation_commit_sha256 != commit.commit_sha256
            or receipt.settlement_id != settlement.settlement_id
            or receipt.settlement_sha256 != settlement.settlement_sha256
            or receipt.execution_state != settlement.terminal_state
            or event["event_kind"] != "settle"
            or event["tenant_id"] != row["tenant_id"]
            or event["assessment_id"] != row["assessment_id"]
            or event["event_sequence"] != row["budget_event_sequence"]
            or event["admission_id"] != row["admission_id"]
            or event["custody_id"] != settlement.settlement_id
            or event["before_budget_sha256"] != before_budget.budget_sha256
            or event["after_budget_sha256"] != after_budget.budget_sha256
            or after_budget.to_dict() != expected_after_budget.to_dict()
            or row["tenant_id"] != authority.tenant_id
            or row["assessment_id"] != authority.assessment_id
            or row["budget_id"] != before_budget.budget_id
            or settlement.settled_at != event["recorded_at"]
            or settled_at < claimed_at
            or row["provider_observation_sha256"] != observation_identity[1]
            or row["work_product_sha256"] != product_identity[1]
            or (
                product is not None
                and (
                    product.get("product_id") != product_identity[0]
                    or product.get("product_sha256") != product_identity[1]
                    or product.get("model_output_effect") != "advisory_only"
                    or product.get("tool_effect") != "none"
                    or product.get("authorization_effect") != "none"
                )
            )
            or (
                settlement.terminal_state != "indeterminate_quarantined"
                and not observation_binding_is_valid
            )
            or (
                observation is not None
                and (
                    provider_request is None
                    or provider_request["provider_id"] != observation.provider_id
                    or provider_request["provider_request_id"] != observation.provider_request_id
                    or provider_request["observation_sha256"] != observation.observation_sha256
                    or provider_request["recorded_at"] != settlement.settled_at
                )
            )
            or (observation is None and provider_request is not None)
        ):
            raise StoreIntegrityError("Authenticated model settlement does not reconcile")

    if mission_id is None:
        budgets = connection.execute(
            """
            SELECT * FROM authenticated_model_execution_budgets
            ORDER BY tenant_id, assessment_id
            """
        ).fetchall()
        for row in budgets:
            _require_stored_types(
                row,
                text_fields=(
                    "tenant_id",
                    "assessment_id",
                    "budget_id",
                    "budget_json",
                    "budget_sha256",
                    "budget_revision",
                    "event_head_sha256",
                    "last_observed_at",
                    "initialized_at",
                ),
                integer_fields=("event_count",),
            )
            budget = _budget_from_dict(_stored_canonical_object(row["budget_json"], "budget head"))
            events = connection.execute(
                """
                SELECT * FROM authenticated_model_execution_budget_events
                WHERE tenant_id = ? AND assessment_id = ?
                ORDER BY event_sequence
                """,
                (row["tenant_id"], row["assessment_id"]),
            ).fetchall()
            if not events:
                raise StoreIntegrityError("Authenticated model budget has no durable custody event")
            if events:
                first_before = _budget_from_dict(
                    _stored_canonical_object(
                        events[0]["before_budget_json"],
                        "initial budget snapshot",
                    )
                )
            else:
                first_before = budget
            if (
                first_before.tenant_id != row["tenant_id"]
                or first_before.assessment_id != row["assessment_id"]
                or any(
                    (
                        first_before.aggregate_input_tokens_reserved,
                        first_before.aggregate_output_tokens_reserved,
                        first_before.aggregate_cost_reserved_micros,
                    )
                )
            ):
                raise StoreIntegrityError(
                    "Authenticated model budget baseline is not a zero-counter authority"
                )
            previous = first_before
            previous_event_sha256 = _budget_baseline_hash(
                first_before,
                row["initialized_at"],
            )
            previous_time = parse_timestamp(
                row["initialized_at"],
                "model budget initialized_at",
            )
            for sequence, event in enumerate(events, start=1):
                _require_stored_types(
                    event,
                    text_fields=(
                        "tenant_id",
                        "assessment_id",
                        "event_kind",
                        "event_id",
                        "admission_id",
                        "custody_id",
                        "before_budget_json",
                        "before_budget_sha256",
                        "after_budget_json",
                        "after_budget_sha256",
                        "previous_event_sha256",
                        "event_sha256",
                        "recorded_at",
                    ),
                    integer_fields=("event_sequence",),
                )
                before = _budget_from_dict(
                    _stored_canonical_object(event["before_budget_json"], "before budget")
                )
                after = _budget_from_dict(
                    _stored_canonical_object(event["after_budget_json"], "after budget")
                )
                expected_id, expected_sha256, _ = _budget_event(
                    tenant_id=row["tenant_id"],
                    assessment_id=row["assessment_id"],
                    sequence=sequence,
                    kind=event["event_kind"],
                    admission_id=event["admission_id"],
                    custody_id=event["custody_id"],
                    before=before,
                    after=after,
                    previous_event_sha256=previous_event_sha256,
                    recorded_at=event["recorded_at"],
                )
                event_time = parse_timestamp(
                    event["recorded_at"],
                    "model budget event recorded_at",
                )
                if (
                    event["event_sequence"] != sequence
                    or before.tenant_id != row["tenant_id"]
                    or before.assessment_id != row["assessment_id"]
                    or after.tenant_id != row["tenant_id"]
                    or after.assessment_id != row["assessment_id"]
                    or before.to_dict() != previous.to_dict()
                    or event["before_budget_sha256"] != before.budget_sha256
                    or event["after_budget_sha256"] != after.budget_sha256
                    or event["previous_event_sha256"] != previous_event_sha256
                    or event["event_id"] != expected_id
                    or event["event_sha256"] != expected_sha256
                    or event_time < previous_time
                ):
                    raise StoreIntegrityError("Model budget event chain is invalid")
                linked = (
                    connection.execute(
                        """
                        SELECT budget_event_sequence
                        FROM authenticated_model_execution_admissions
                        WHERE admission_id = ?
                        """,
                        (event["admission_id"],),
                    ).fetchone()
                    if event["event_kind"] == "reserve"
                    else connection.execute(
                        """
                        SELECT budget_event_sequence
                        FROM authenticated_model_execution_settlements
                        WHERE admission_id = ?
                        """,
                        (event["admission_id"],),
                    ).fetchone()
                )
                if (
                    linked is None
                    or type(linked["budget_event_sequence"]) is not int
                    or linked["budget_event_sequence"] != sequence
                ):
                    raise StoreIntegrityError("Model budget event has no exact custody record")
                previous = after
                previous_event_sha256 = expected_sha256
                previous_time = event_time
            if (
                budget.to_dict() != previous.to_dict()
                or row["budget_id"] != budget.budget_id
                or row["budget_sha256"] != budget.budget_sha256
                or row["budget_revision"] != budget.budget_revision
                or row["event_count"] != len(events)
                or row["event_head_sha256"] != previous_event_sha256
                or row["last_observed_at"]
                != (events[-1]["recorded_at"] if events else row["initialized_at"])
                or (
                    not events
                    and any(
                        (
                            budget.aggregate_input_tokens_reserved,
                            budget.aggregate_output_tokens_reserved,
                            budget.aggregate_cost_reserved_micros,
                        )
                    )
                )
            ):
                raise StoreIntegrityError("Authenticated model budget head is invalid")
    budget_count = 0
    if mission_id is None:
        budget_count_row = connection.execute(
            "SELECT COUNT(*) FROM authenticated_model_execution_budgets"
        ).fetchone()
        if budget_count_row is None or type(budget_count_row[0]) is not int:
            raise StoreIntegrityError("Model execution budget count storage type is invalid")
        budget_count = budget_count_row[0]
    return len(admissions), len(dispatches), len(settlements), budget_count
