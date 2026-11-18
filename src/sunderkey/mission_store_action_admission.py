"""MissionStore-backed authenticated typed action admission custody."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .action_admission_contracts import (
    ActionAdmissionRequest,
    AdmissionStatus,
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    EvidenceObligation,
    HealthEvidence,
    RestorationDuties,
    StopConditions,
    TargetBinding,
    WorkerSession,
    evaluate_action_admission,
)
from .action_authority_contracts import (
    RESOURCE_FIELDS,
    ActionAuthorityPolicyRevision,
    ActionBudgetPolicyRevision,
    ActionSafetyPolicyRevision,
    AuthenticatedProposalMaterialImport,
    AuthoritativeActionCatalogRevision,
    AuthoritativeTargetDescriptorRevision,
    ExactActionSourceHeadBundle,
)
from .action_resolution import (
    NO_EFFECTS,
    ActionAdmissionRevocation,
    ActionResolutionError,
    AuthenticatedActionAdmissionReceipt,
    AuthorizationRole,
    _address_record,
    _authorization,
    _identifier,
    _sha256,
    _timestamp,
    _verify_current_expert_review_closure,
    parse_action_admission_revocation,
    parse_action_parameter_set,
    parse_executable_action_catalog,
    parse_target_action_descriptor,
)
from .action_target_health_gate_use import (
    ActionTargetHealthGateUse,
    ActionTargetHealthGateUseKind,
    insert_action_target_health_gate_use,
    verify_action_target_health_gate_use_store,
)
from .authenticated import AuthenticatedMissionControlService
from .authenticated_action_admission import (
    ActionAdmissionCommand,
    AuthenticatedActionAdmissionService,
    CurrentActionAdmission,
    CurrentActionAdmissionMaterial,
    CurrentActionAuthorityState,
    StoredActionAdmission,
    _canonical_sha256,
    _current_proof_material,
    admission_authorization_intent_sha256,
    revocation_authorization_intent_sha256,
)
from .authenticated_action_review_authority import (
    AuthenticatedExpertReviewClosureVerifierAdapter,
)
from .collaboration import CollaborationPlan
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from .execution_control_runtime import ExecutionBinding
from .expert_review import ExpertReviewRecordSet
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .mission_store_action_authority import (
    BUDGET_ACCOUNT_DOMAIN,
    BUDGET_EVENT_DOMAIN,
    BUDGET_POLICY_BINDING_DOMAIN,
    BUDGET_RESERVATION_DOMAIN,
    OBSERVATION_KINDS,
    ActionAuthorityMaterialSnapshot,
    ActionAuthorityObservation,
    AuthenticatedActionAuthorityPublication,
    _head_sha256,
    _historical_collaboration_role_principal,
    build_authenticated_action_authority_publication,
    load_current_action_material_snapshot,
    load_current_action_source_bundle,
    verify_action_authority_repository,
)
from .mission_store_target_health_gate import (
    MissionStoreTargetHealthGateService,
    TargetHealthGateObservationResult,
)
from .qualification import _canonical_json
from .registry import ExpertRegistry
from .store import (
    ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from .target_health_gate_contracts import (
    TargetHealthGateDecisionStatus,
    build_target_health_execution_binding,
    execution_binding_sha256,
)
from .types import ProfileKind

ACTION_RESOLVE_OPERATION = "sunderkey.action.resolve.v1"
ACTION_QUORUM_OPERATION = "sunderkey.action.quorum-authorize.v1"
ACTION_ADMIT_OPERATION = "sunderkey.action.admit.v1"
ACTION_REVOKE_OPERATION = "sunderkey.action.admission-revoke.v1"
ACTION_AUTHORITY_PUBLISH_OPERATION = "sunderkey.action.authority-publish.v1"
ACTION_OPERATIONS = frozenset(
    {
        ACTION_RESOLVE_OPERATION,
        ACTION_QUORUM_OPERATION,
        ACTION_ADMIT_OPERATION,
        ACTION_REVOKE_OPERATION,
    }
)
REVOCATION_BUDGET_RELEASE_DOMAIN = (
    "sunderkey.action-budget-revocation-release.v1"
)


def _action_principal_effect(
    *,
    operation: str,
    effect_id: str,
    payload: Mapping[str, Any],
    recorded_at: str,
) -> dict[str, Any]:
    return {
        "effect_id": effect_id,
        "effect_kind": operation,
        "payload": dict(payload),
        "recorded_at": recorded_at,
        "schema_version": 1,
    }


def _revocation_budget_release_lineage(
    revocation: ActionAdmissionRevocation,
) -> dict[str, str]:
    if type(revocation) is not ActionAdmissionRevocation:
        raise TypeError("revocation must be an ActionAdmissionRevocation")
    document = revocation.to_dict()
    authorization = document["control_authorization"]
    return {
        "claim_id": authorization["assertion_id"],
        "claim_sha256": _canonical_sha256(
            {
                "domain": REVOCATION_BUDGET_RELEASE_DOMAIN,
                "revocation": document,
            }
        ),
        "execution_id": revocation.revocation_id,
        "execution_intent_sha256": revocation.revocation_sha256,
    }


def _current_budget_state(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    mission_id: str,
    expected_revision_sha256: str,
    checked_at: str,
) -> tuple[sqlite3.Row, dict[str, Any], dict[str, int]]:
    row = connection.execute(
        """
        SELECT account.*, binding.budget_revision_id,
               binding.budget_revision_sha256, binding.limits_json,
               revision.record_json
        FROM action_budget_accounts AS account
        JOIN action_budget_policy_bindings AS binding
          ON binding.account_id = account.account_id
        JOIN action_authority_revisions AS revision
          ON revision.record_kind = 'action_budget_policy_revision'
         AND revision.record_id = binding.budget_revision_id
         AND revision.record_sha256 = binding.budget_revision_sha256
        WHERE account.mission_id = ? AND account.tenant_id = ?
        ORDER BY binding.binding_sequence DESC LIMIT 1
        """,
        (mission_id, tenant_id),
    ).fetchone()
    if (
        row is None
        or row["budget_revision_sha256"] != expected_revision_sha256
        or type(row["record_json"]) is not str
        or type(row["limits_json"]) is not str
    ):
        raise StoreIntegrityError("Current six-axis action budget is absent or stale")
    try:
        revision = ActionBudgetPolicyRevision.from_dict(
            json.loads(row["record_json"])
        ).to_dict()
        limits = json.loads(row["limits_json"])
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Current six-axis action budget is invalid") from exc
    if (
        canonical_json(revision) != row["record_json"]
        or canonical_json(limits) != row["limits_json"]
        or revision["limits"] != limits
        or set(limits) != set(RESOURCE_FIELDS)
    ):
        raise StoreIntegrityError("Current six-axis action budget binding is invalid")
    checked_time = parse_timestamp(checked_at, "action budget checked_at")
    if not (
        parse_timestamp(revision["effective_at"], "action budget effective_at")
        <= checked_time
        < parse_timestamp(revision["expires_at"], "action budget expires_at")
    ):
        raise StoreIntegrityError("Current six-axis action budget is outside its window")
    usage = {field: 0 for field in RESOURCE_FIELDS}
    reservations: dict[str, dict[str, int]] = {}
    settled: set[str] = set()
    released: set[str] = set()
    events = connection.execute(
        "SELECT event_kind, receipt_id, resources_json "
        "FROM action_budget_account_events WHERE account_id = ? "
        "ORDER BY event_sequence",
        (row["account_id"],),
    ).fetchall()
    for event in events:
        if type(event["resources_json"]) is not str:
            raise StoreIntegrityError("Action budget event resources are invalid")
        resources = json.loads(event["resources_json"])
        receipt_id = event["receipt_id"]
        if event["event_kind"] == "reserve":
            reservations[receipt_id] = resources
            for field in RESOURCE_FIELDS:
                usage[field] += resources[field]
        elif event["event_kind"] == "release":
            if receipt_id not in reservations or receipt_id in released:
                raise StoreIntegrityError("Action budget release is not conserved")
            released.add(receipt_id)
            for field in RESOURCE_FIELDS:
                usage[field] -= resources[field]
        elif event["event_kind"] == "settle":
            if receipt_id not in reservations or receipt_id in settled:
                raise StoreIntegrityError("Action budget settlement is not conserved")
            settled.add(receipt_id)
        else:
            raise StoreIntegrityError("Action budget event kind is invalid")
    return row, revision, usage


class _FixedReviewVerifier:
    def __init__(self, sealed: Any) -> None:
        self._sealed = sealed

    def verify_current(self, records: Any, registry: Any) -> Any:
        del records, registry
        return self._sealed


@dataclass(frozen=True, slots=True)
class ActionAdmissionExecutionConsumption:
    consumption_id: str
    receipt_id: str
    receipt_sha256: str
    custody_sha256: str
    execution_id: str
    execution_intent_sha256: str
    claim_id: str
    claim_sha256: str
    consumed_at: str

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class MissionStoreActionAuthority:
    """Repository-owned authority accepted by the production service."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        review_custody: Any,
    ) -> None:
        if type(store) is not MissionStore:
            raise TypeError("store must be a MissionStore")
        if type(registry) is not ExpertRegistry:
            raise TypeError("registry must be an ExpertRegistry")
        self._store = store
        self._registry = registry
        if getattr(review_custody, "_store", None) is not store:
            raise TypeError("review_custody must share the authority MissionStore")
        if getattr(review_custody, "_registry", None) is not registry:
            raise TypeError("review_custody must share the authority registry")
        self._review_custody = review_custody

    @staticmethod
    def _require_transaction(connection: sqlite3.Connection) -> None:
        if type(connection) is not sqlite3.Connection or not connection.in_transaction:
            raise ActionResolutionError(
                "Action authority requires the active MissionStore transaction"
            )

    def load_current_material(
        self,
        connection: sqlite3.Connection,
        command: ActionAdmissionCommand,
        evaluated_at: str,
    ) -> CurrentActionAdmissionMaterial:
        self._require_transaction(connection)
        mission = connection.execute(
            "SELECT mission_id FROM missions WHERE mission_id = ?",
            (command.mission_id,),
        ).fetchone()
        active = connection.execute(
            "SELECT active_plan_id FROM collaboration_plan_active_heads WHERE mission_id = ?",
            (command.mission_id,),
        ).fetchone()
        if mission is None or active is None:
            raise ActionResolutionError("Action authority mission or active plan is absent")
        bundle = load_current_action_source_bundle(
            connection,
            command.mission_id,
            evaluated_at,
        ).to_dict()
        material = load_current_action_material_snapshot(
            connection,
            ExactActionSourceHeadBundle.from_dict(bundle),
            evaluated_at,
        ).to_dict()
        proposal = connection.execute(
            """
            SELECT proposal_json FROM action_authority_proposal_imports
            WHERE proposal_import_id = ? AND mission_id = ? AND tenant_id = ?
            """,
            (
                bundle["proposal_import_id"],
                command.mission_id,
                command.tenant_id,
            ),
        ).fetchone()
        if proposal is None or type(proposal["proposal_json"]) is not str:
            raise ActionResolutionError("Current reviewed proposal import is absent")
        proposal_document = json.loads(proposal["proposal_json"])
        if (
            bundle["plan_id"] != active["active_plan_id"]
            or proposal_document["reviewed_product"]["product_id"] != command.proposal_product_id
            or proposal_document["selected_action_type"] != command.action_type
            or proposal_document["requested_action_tier"] != command.action_tier.value
        ):
            raise ActionResolutionError(
                "Action command differs from the current repository authority"
            )
        if (
            material["proposal_import_id"] != bundle["proposal_import_id"]
            or material["proposal_import_sha256"] != bundle["proposal_import_sha256"]
        ):
            raise ActionResolutionError("Current action material proposal is stale")
        records, _registration = self._review_custody._load_records(
            connection,
            proposal_document["review_closure_id"],
        )
        snapshot = records.snapshot.to_dict()
        closure = records.closure.to_dict()
        product = next(
            (
                item
                for item in snapshot["products"]
                if item["product_id"] == command.proposal_product_id
            ),
            None,
        )
        if (
            product is None
            or product["product_sha256"] != proposal_document["reviewed_product"]["product_sha256"]
            or records.snapshot.snapshot_id != proposal_document["review_snapshot_id"]
            or records.snapshot.snapshot_sha256 != proposal_document["review_snapshot_sha256"]
            or records.closure.closure_id != proposal_document["review_closure_id"]
            or records.closure.closure_sha256 != proposal_document["review_closure_sha256"]
            or closure["disposition"] != "accepted"
            or records.revocation is not None
        ):
            raise ActionResolutionError("Current reviewed proposal material is substituted")
        catalog = parse_executable_action_catalog(material["catalog"])
        parameters = parse_action_parameter_set(material["parameters"], catalog)
        target = parse_target_action_descriptor(material["target"])
        catalog_revision = connection.execute(
            "SELECT record_json FROM action_authority_revisions "
            "WHERE record_kind = 'authoritative_action_catalog_revision' "
            "AND record_id = ? AND record_sha256 = ?",
            (bundle["catalog_revision_id"], bundle["catalog_revision_sha256"]),
        ).fetchone()
        target_revision = connection.execute(
            "SELECT record_json FROM action_authority_revisions "
            "WHERE record_kind = 'authoritative_target_descriptor_revision' "
            "AND record_id = ? AND record_sha256 = ?",
            (bundle["target_revision_id"], bundle["target_revision_sha256"]),
        ).fetchone()
        authority_policy = connection.execute(
            "SELECT record_json FROM action_authority_revisions "
            "WHERE record_kind = 'action_authority_policy_revision' "
            "AND record_id = ? AND record_sha256 = ?",
            (
                bundle["action_authority_policy_revision_id"],
                bundle["action_authority_policy_revision_sha256"],
            ),
        ).fetchone()
        if catalog_revision is None or target_revision is None or authority_policy is None:
            raise ActionResolutionError("Current action source revisions are absent")
        catalog_source = json.loads(catalog_revision["record_json"])
        target_source = json.loads(target_revision["record_json"])
        policy_source = json.loads(authority_policy["record_json"])
        catalog_document = catalog.to_dict()
        target_document = target.to_dict()
        entry = next(
            (
                item
                for item in catalog_document["entries"]
                if item["action_type"] == command.action_type
            ),
            None,
        )
        source_entry = next(
            (
                item
                for item in catalog_source["entries"]
                if item["action_type"] == command.action_type
            ),
            None,
        )
        if (
            entry is None
            or source_entry is None
            or catalog_source["registry_sha256"]
            != _canonical_sha256(self._registry.to_dict())
            or catalog_document["catalog_id"] != catalog_source["catalog_id"]
            or catalog_document["catalog_version"] != catalog_source["catalog_version"]
            or catalog_document["registry_sha256"] != catalog_source["registry_sha256"]
            or entry["parameter_contract_sha256"] != source_entry["parameter_schema_sha256"]
            or entry["tool_artifact_ref"] != source_entry["tool_artifact_ref"]
            or entry["tool_artifact_sha256"] != source_entry["tool_artifact_sha256"]
            or entry["tool_exact_version"] != source_entry["tool_exact_version"]
            or entry["maximum_action_tier"] != source_entry["maximum_action_tier"]
            or target_document["target_id"] != target_source["target_id"]
            or target_document["target_sha256"] != target_source["target_sha256"]
            or target_document["environment"] != target_source["environment"]
            or target_document["target_scope_sha256"] != target_source["scope_sha256"]
            or target_document["authority_snapshot_sha256"]
            != target_source["authority_snapshot_sha256"]
            or parameters.parameter_set_id != proposal_document["parameter_set_id"]
            or parameters.parameter_set_sha256 != proposal_document["parameter_set_sha256"]
            or material["resolver_profile_id"]
            != policy_source["typed_resolver"]["principal_profile_id"]
            or material["resolver_subject"] != policy_source["typed_resolver"]["principal_subject"]
        ):
            raise ActionResolutionError("Current action material differs from source policy")
        _budget_account, budget_revision, budget_usage = _current_budget_state(
            connection,
            tenant_id=command.tenant_id,
            mission_id=command.mission_id,
            expected_revision_sha256=bundle["budget_revision_sha256"],
            checked_at=evaluated_at,
        )
        budget_limits = budget_revision["limits"]
        budget_ceiling = budget_revision["per_action_ceiling"]
        current_budget = BudgetBinding(
            tenant_id=command.tenant_id,
            mission_id=command.mission_id,
            budget_sha256=bundle["budget_revision_sha256"],
            request_limit=budget_limits["rate_units"],
            requests_used=budget_usage["rate_units"],
            token_limit=(
                budget_limits["request_bytes"]
                + budget_limits["response_bytes"]
            ),
            tokens_used=(
                budget_usage["request_bytes"]
                + budget_usage["response_bytes"]
            ),
            cost_limit_microunits=budget_limits["money_microunits"],
            cost_used_microunits=budget_usage["money_microunits"],
            action_request_cost=budget_ceiling["rate_units"],
            action_token_cost=(
                budget_ceiling["request_bytes"]
                + budget_ceiling["response_bytes"]
            ),
            action_cost_microunits=budget_ceiling["money_microunits"],
        )
        return CurrentActionAdmissionMaterial(
            records=records,
            registry=self._registry,
            catalog=catalog,
            parameters=parameters,
            target=target,
            resolver_profile_id=material["resolver_profile_id"],
            resolver_subject=material["resolver_subject"],
            context=ContextBinding.from_dict(material["context"]),
            worker_session=WorkerSession.from_dict(material["worker_session"]),
            credential_lease=CredentialLease.from_dict(material["credential_lease"]),
            health=HealthEvidence.from_dict(material["health"]),
            budget=current_budget,
            evidence_obligations=tuple(
                EvidenceObligation.from_dict(item) for item in material["evidence_obligations"]
            ),
            stop_conditions=StopConditions.from_dict(material["stop_conditions"]),
            restoration_duties=RestorationDuties.from_dict(material["restoration_duties"]),
            resolved_at=material["resolved_at"],
            approved_at=material["approved_at"],
            quorum_expires_at=material["quorum_expires_at"],
            requested_at=material["requested_at"],
            expires_at=material["expires_at"],
            catalog_authority_sha256=bundle["catalog_revision_sha256"],
            authority_revision_sha256=bundle["source_bundle_sha256"],
        )

    def _authorization(
        self,
        connection: sqlite3.Connection,
        *,
        operation: PrincipalOperation,
        role: AuthorizationRole,
        operation_intent_sha256: str,
    ) -> Mapping[str, Any]:
        matches = connection.execute(
            """
            SELECT authorization_json FROM action_authority_grant_submissions
            WHERE operation = ? AND role = ? AND operation_intent_sha256 = ?
            """,
            (operation.value, role.value, operation_intent_sha256),
        ).fetchall()
        if len(matches) != 1:
            raise ActionResolutionError("Exact signed action authorization is absent or ambiguous")
        raw = matches[0]["authorization_json"]
        if type(raw) is not str:
            raise StoreIntegrityError("Stored action authorization type is invalid")
        try:
            authorization = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Stored action authorization is invalid") from exc
        if type(authorization) is not dict or _canonical_json(authorization) != raw:
            raise StoreIntegrityError("Stored action authorization is not canonical")
        return authorization

    def authorize_resolution(
        self,
        connection: sqlite3.Connection,
        resolution: Any,
        operation_intent_sha256: str,
        evaluated_at: str,
    ) -> Mapping[str, Any]:
        del resolution, evaluated_at
        self._require_transaction(connection)
        return self._authorization(
            connection,
            operation=PrincipalOperation.ACTION_RESOLVE,
            role=AuthorizationRole.TYPED_RESOLVER,
            operation_intent_sha256=operation_intent_sha256,
        )

    def authorize_quorum(
        self,
        connection: sqlite3.Connection,
        resolution: Any,
        operation_intents: Mapping[AuthorizationRole, str],
        evaluated_at: str,
    ) -> tuple[Mapping[str, Any], ...]:
        del resolution, evaluated_at
        self._require_transaction(connection)
        return tuple(
            self._authorization(
                connection,
                operation=PrincipalOperation.ACTION_QUORUM_AUTHORIZE,
                role=role,
                operation_intent_sha256=intent,
            )
            for role, intent in operation_intents.items()
        )

    def authorize_admission(
        self,
        connection: sqlite3.Connection,
        resolution: Any,
        quorum: Any,
        request: Any,
        operation_intent_sha256: str,
        evaluated_at: str,
    ) -> Mapping[str, Any]:
        del resolution, quorum, request, evaluated_at
        self._require_transaction(connection)
        return self._authorization(
            connection,
            operation=PrincipalOperation.ACTION_ADMIT,
            role=AuthorizationRole.ADMISSION_CONTROL,
            operation_intent_sha256=operation_intent_sha256,
        )

    def authorize_revocation(
        self,
        connection: sqlite3.Connection,
        stored: StoredActionAdmission,
        reason_code: str,
        operation_intent_sha256: str,
        revoked_at: str,
    ) -> Mapping[str, Any]:
        del stored, reason_code, revoked_at
        self._require_transaction(connection)
        return self._authorization(
            connection,
            operation=PrincipalOperation.ACTION_ADMISSION_REVOKE,
            role=AuthorizationRole.INDEPENDENT_CONTROL,
            operation_intent_sha256=operation_intent_sha256,
        )

    def principal_assertion_for(
        self,
        connection: sqlite3.Connection,
        authorization: Mapping[str, Any],
        operation: str,
        *,
        consumed_at: str,
    ) -> PrincipalAssertion:
        del consumed_at
        self._require_transaction(connection)
        rows = connection.execute(
            """
            SELECT assertion_json, authorization_json
            FROM action_authority_grant_submissions
            WHERE assertion_issuer = ? AND assertion_id = ? AND operation = ?
            """,
            (
                authorization.get("assertion_issuer"),
                authorization.get("assertion_id"),
                operation,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise ActionResolutionError("Signed assertion does not match the exact authorization")
        row = rows[0]
        if (
            type(row["assertion_json"]) is not str
            or type(row["authorization_json"]) is not str
            or _canonical_json(dict(authorization)) != row["authorization_json"]
        ):
            raise StoreIntegrityError("Stored action grant binding is invalid")
        try:
            assertion = PrincipalAssertion.from_dict(json.loads(row["assertion_json"]))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored action assertion is invalid") from exc
        return assertion

    def verify_stored_current(
        self,
        connection: sqlite3.Connection,
        stored: StoredActionAdmission,
        evaluated_at: str,
    ) -> CurrentActionAuthorityState:
        self._require_transaction(connection)
        resolution = stored.resolution.to_dict()
        active = connection.execute(
            "SELECT active_plan_id FROM collaboration_plan_active_heads WHERE mission_id = ?",
            (resolution["mission_id"],),
        ).fetchone()
        bundle = load_current_action_source_bundle(
            connection,
            resolution["mission_id"],
            evaluated_at,
        )
        load_current_action_material_snapshot(
            connection,
            bundle,
            evaluated_at,
        )
        bundle = bundle.to_dict()
        if (
            active is None
            or active["active_plan_id"] != resolution["plan_id"]
            or bundle["plan_id"] != resolution["plan_id"]
            or bundle["workspace_high_water_sha256"]
            != self._workspace_high_water_sha256(connection, stored.receipt.receipt_id)
            or bundle["catalog_revision_sha256"] != stored.authority_state.catalog_authority_sha256
            or bundle["source_bundle_sha256"] != stored.authority_state.authority_revision_sha256
        ):
            raise ActionResolutionError("Action authority material changed or was revoked")
        return CurrentActionAuthorityState(
            review_evidence_sha256=stored.review_evidence_sha256,
            catalog_id=stored.authority_state.catalog_id,
            catalog_sha256=stored.authority_state.catalog_sha256,
            catalog_version=stored.authority_state.catalog_version,
            catalog_authority_sha256=bundle["catalog_revision_sha256"],
            authority_revision_sha256=bundle["source_bundle_sha256"],
        )

    @staticmethod
    def _workspace_high_water_sha256(
        connection: sqlite3.Connection,
        receipt_id: str,
    ) -> str:
        row = connection.execute(
            "SELECT high_water_sha256 FROM action_admission_workspace_high_waters "
            "WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None or type(row["high_water_sha256"]) is not str:
            raise StoreIntegrityError("Action workspace high-water is missing")
        return row["high_water_sha256"]


class MissionStoreActionPrincipalCustody:
    """Authenticate and append one action assertion in a supplied transaction."""

    def __init__(self, store: MissionStore, registry: ExpertRegistry) -> None:
        self._store = store
        self._registry = registry
        self._authenticated = AuthenticatedMissionControlService(store, registry)

    def consume(
        self,
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
        operation: str,
        consumed_at: str,
        *,
        receipt_id: str | None,
        effect_document: Mapping[str, Any] | None = None,
        effect_id: str | None = None,
    ) -> None:
        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError(
                "Action authority must supply a signed principal assertion"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        authorization = dict(authorization)
        parsed_operation = PrincipalOperation(operation)
        if parsed_operation not in {
            PrincipalOperation.ACTION_RESOLVE,
            PrincipalOperation.ACTION_QUORUM_AUTHORIZE,
            PrincipalOperation.ACTION_ADMIT,
            PrincipalOperation.ACTION_ADMISSION_REVOKE,
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            PrincipalOperation.ACTION_EXECUTE,
            PrincipalOperation.ACTION_EXECUTION_RECONCILE,
        }:
            raise PrincipalAuthenticationError("Action operation is invalid")
        if parsed_operation is PrincipalOperation.ACTION_AUTHORITY_PUBLISH:
            intent = {
                "idempotency_key_sha256": authorization["canonical_replay_key_sha256"],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "publication_sha256": authorization["operation_intent_sha256"],
            }
        else:
            intent = {
                "action_intent_sha256": authorization["operation_intent_sha256"],
                "idempotency_key_sha256": authorization["canonical_replay_key_sha256"],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "role": authorization["role"],
            }
        intent_json = canonical_json(intent)
        signed_intent_hash = compute_operation_intent_hash(
            parsed_operation,
            intent,
        )
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)
        if (
            assertion.operation is not parsed_operation
            or assertion.operation_intent_sha256 != signed_intent_hash
            or assertion.issuer != authorization["assertion_issuer"]
            or assertion.assertion_id != authorization["assertion_id"]
            or assertion_hash != authorization["assertion_sha256"]
            or assertion.subject != authorization["principal_subject"]
            or assertion.profile_id != authorization["principal_profile_id"]
            or assertion.scope_grant_sha256 != authorization["scope_grant_sha256"]
        ):
            raise PrincipalAuthenticationError(
                "Signed action assertion differs from the authorization"
            )
        if (
            connection.execute(
                "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                (assertion.issuer, assertion.assertion_id),
            ).fetchone()
            is not None
        ):
            raise StoreConflictError("Action assertion was already consumed")
        (
            identity,
            trust_policies,
            mission,
            scope_grants,
        ) = self._authenticated._verified_mission_state(
            connection,
            authorization["mission_id"],
        )
        consumed_time = parse_timestamp(consumed_at, "action assertion consumed_at")
        current_policy_hash = identity["trust_policy_hash"]
        if current_policy_hash is None:
            raise StoreConflictError("A current trust policy is required")
        verified_policy = trust_policies.get(str(current_policy_hash))
        if verified_policy is None:
            raise StoreIntegrityError("Current trust policy is missing")
        high_water = self._store._trust_policy_high_water_at(
            trust_policies,
            consumed_time,
        )
        if high_water.policy_sha256 != verified_policy.policy_sha256:
            raise PrincipalAuthenticationError(
                "Action assertion clock precedes the current trust policy"
            )
        scope_entry = scope_grants.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Action assertion scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        if (
            parse_timestamp(
                str(scope_row["accepted_at"]),
                "action scope accepted_at",
            )
            > consumed_time
        ):
            raise PrincipalAuthenticationError("Action scope was accepted after assertion use")
        if (
            self._store._effective_scope_grant_revocation(
                connection,
                scope_row,
            )
            is not None
        ):
            raise PrincipalAuthenticationError("Action scope grant is revoked")
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError("Mission has no authenticated scope document hash")
        constraints_hash = sha256_text(canonical_json(mission.mission.to_dict()["constraints"]))
        verified_scope = verify_scope_grant(
            scope_grant,
            verified_policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=authorization["mission_id"],
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            expected_operation=parsed_operation,
            allow_expired_for_safety_reduction=(
                parsed_operation is PrincipalOperation.ACTION_ADMISSION_REVOKE
            ),
            clock=lambda: consumed_time,
        )
        principal = verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=authorization["mission_id"],
            expected_operation=parsed_operation,
            expected_operation_intent_sha256=signed_intent_hash,
            clock=lambda: consumed_time,
        )
        if (
            principal.key_sha256 != authorization["assertion_key_sha256"]
            or principal.policy_sha256 != authorization["trust_policy_sha256"]
            or principal.policy_sha256 != verified_policy.policy_sha256
        ):
            raise PrincipalAuthenticationError(
                "Verified action principal differs from current authorization"
            )
        self._require_role_entitlement(
            connection,
            authorization,
            mission,
            receipt_id=receipt_id,
            checked_at=consumed_at,
            operation=operation,
        )
        effect_payload = authorization if effect_document is None else dict(effect_document)
        effect_identifier = assertion.assertion_id if effect_id is None else effect_id
        effect_value = _action_principal_effect(
            operation=operation,
            effect_id=effect_identifier,
            payload=effect_payload,
            recorded_at=consumed_at,
        )
        effect_json = _canonical_json(effect_value)
        effect_hash = sha256_text(effect_json)
        effects_hash = principal_assertion_effects_hash((effect_hash,))
        ledger = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (authorization["mission_id"],),
        ).fetchone()
        if ledger is None:
            raise StoreIntegrityError("Mission principal ledger is missing")
        if (
            parse_timestamp(
                str(ledger["updated_at"]),
                "mission principal ledger updated_at",
            )
            > consumed_time
        ):
            raise PrincipalAuthenticationError(
                "Action assertion clock precedes the principal ledger"
            )
        use_sequence = int(ledger["assertion_count"]) + 1
        previous_hash = str(ledger["head_hash"])
        entry = self._authenticated._assertion_entry(
            principal=principal,
            assertion=assertion,
            mission_id=authorization["mission_id"],
            use_sequence=use_sequence,
            assertion_hash=assertion_hash,
            operation_intent_json=intent_json,
            signed_intent_hash=signed_intent_hash,
            domain_request_hash=authorization["operation_intent_sha256"],
            idempotency_key_hash=authorization["canonical_replay_key_sha256"],
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
                authorization["mission_id"],
                operation,
                effect_identifier,
                effect_json,
                effect_hash,
                consumed_at,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE mission_principal_ledgers
            SET head_hash = ?, assertion_count = assertion_count + 1,
                effect_count = effect_count + 1, updated_at = ?
            WHERE mission_id = ? AND assertion_count = ? AND head_hash = ?
            """,
            (
                entry_hash,
                consumed_at,
                authorization["mission_id"],
                use_sequence - 1,
                previous_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError("Mission principal ledger changed during action authorization")

    def _require_role_entitlement(
        self,
        connection: sqlite3.Connection,
        authorization: Mapping[str, Any],
        mission: Any,
        *,
        receipt_id: str | None,
        checked_at: str,
        operation: str,
    ) -> None:
        profile_id = authorization["principal_profile_id"]
        try:
            profile = self._registry.profile(profile_id)
        except Exception as exc:
            raise PrincipalAuthenticationError(
                "Action principal has no current registry profile"
            ) from exc
        if profile.status not in {"defined", "qualified"}:
            raise PrincipalAuthenticationError("Action principal registry profile is not current")

        def bound_principal(binding: Mapping[str, Any]) -> sqlite3.Row:
            rows = connection.execute(
                """
                SELECT issuer, subject, principal_profile_id, assertion_id,
                       assertion_hash
                FROM principal_assertion_uses
                WHERE mission_id = ? AND assertion_id = ?
                  AND assertion_hash = ? AND principal_profile_id = ?
                """,
                (
                    authorization["mission_id"],
                    binding.get("assertion_id"),
                    binding.get("assertion_sha256"),
                    binding.get("profile_id"),
                ),
            ).fetchall()
            if len(rows) != 1:
                raise PrincipalAuthenticationError(
                    "Collaboration role binding has no exact authenticated principal"
                )
            return rows[0]

        if operation == ACTION_AUTHORITY_PUBLISH_OPERATION:
            policy_row = connection.execute(
                """
                SELECT policy_json FROM collaboration_mission_policy_commits
                WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1
                """,
                (authorization["mission_id"],),
            ).fetchone()
            if policy_row is None or type(policy_row["policy_json"]) is not str:
                raise PrincipalAuthenticationError(
                    "Authority publication requires current collaboration Control"
                )
            try:
                policy = json.loads(policy_row["policy_json"])
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError("Collaboration authority policy is invalid") from exc
            controls = policy.get("approval_bindings", {}).get("independent_control")
            control_principal = (
                bound_principal(controls) if isinstance(controls, dict) else None
            )
            if (
                canonical_json(policy) != policy_row["policy_json"]
                or not isinstance(controls, dict)
                or policy.get("effective_at") > checked_at
                or policy.get("expires_at") <= checked_at
                or authorization["role"] != "independent_control"
                or profile_id != controls.get("profile_id")
                or control_principal is None
                or authorization["assertion_issuer"] != control_principal["issuer"]
                or authorization["principal_subject"] != control_principal["subject"]
                or profile_id not in mission.control_profile_ids
                or profile.kind is not ProfileKind.SHARED
                or profile.category != "independent control"
            ):
                raise PrincipalAuthenticationError(
                    "Authority publication principal lacks current Control entitlement"
                )
            return
        if receipt_id is None:
            raise StoreIntegrityError("Action receipt identity is required")
        receipt_row = connection.execute(
            "SELECT resolution_json FROM action_admission_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if receipt_row is None or type(receipt_row["resolution_json"]) is not str:
            raise StoreIntegrityError("Action receipt resolution custody is missing")
        try:
            resolution = json.loads(receipt_row["resolution_json"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Action receipt resolution is invalid") from exc
        if canonical_json(resolution) != receipt_row["resolution_json"]:
            raise StoreIntegrityError("Action receipt resolution is not canonical")
        if operation == ACTION_REVOKE_OPERATION:
            policy_row = connection.execute(
                """
                SELECT policy_json FROM collaboration_mission_policy_commits
                WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1
                """,
                (authorization["mission_id"],),
            ).fetchone()
            if policy_row is None or type(policy_row["policy_json"]) is not str:
                raise PrincipalAuthenticationError(
                    "Revocation requires current collaboration Control"
                )
            try:
                policy = json.loads(policy_row["policy_json"])
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError(
                    "Collaboration revocation authority policy is invalid"
                ) from exc
            if not isinstance(policy, dict):
                raise StoreIntegrityError(
                    "Collaboration revocation authority policy is invalid"
                )
            controls = policy.get("approval_bindings", {}).get(
                "independent_control"
            )
            control_principal = (
                bound_principal(controls) if isinstance(controls, dict) else None
            )
            if not (
                canonical_json(policy) == policy_row["policy_json"]
                and isinstance(controls, dict)
                and policy.get("effective_at") <= checked_at
                and policy.get("expires_at") > checked_at
                and authorization["role"] == "independent_control"
                and profile_id == controls.get("profile_id")
                and control_principal is not None
                and authorization["assertion_issuer"] == control_principal["issuer"]
                and authorization["principal_subject"] == control_principal["subject"]
                and profile_id in mission.control_profile_ids
                and profile.kind is ProfileKind.SHARED
                and profile.category == "independent control"
                and profile_id
                not in {
                    resolution["proposal_producer_profile_id"],
                    resolution["resolver_profile_id"],
                }
            ):
                raise PrincipalAuthenticationError(
                    "Revocation principal lacks current Control entitlement"
                )
            return
        action_policy_row = connection.execute(
            """
            SELECT revision.record_json
            FROM action_authority_source_heads AS head
            JOIN action_authority_revisions AS revision
              ON revision.record_kind = head.source_kind
             AND revision.record_id = head.record_id
             AND revision.record_sha256 = head.record_sha256
            WHERE head.mission_id = ?
              AND head.source_kind = 'action_authority_policy_revision'
            ORDER BY head.head_sequence DESC LIMIT 1
            """,
            (authorization["mission_id"],),
        ).fetchone()
        if action_policy_row is None or type(action_policy_row["record_json"]) is not str:
            raise PrincipalAuthenticationError(
                "Action role requires a current repository authority policy"
            )
        try:
            action_policy = ActionAuthorityPolicyRevision.from_dict(
                json.loads(action_policy_row["record_json"])
            ).to_dict()
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Action authority policy is invalid") from exc
        if not (action_policy["effective_at"] <= checked_at < action_policy["expires_at"]):
            raise PrincipalAuthenticationError("Action authority policy is not current")
        active_row = connection.execute(
            """
            SELECT activation.plan_json
            FROM collaboration_plan_active_heads AS head
            JOIN collaboration_plan_activations AS activation
              ON activation.plan_id = head.active_plan_id
            WHERE head.mission_id = ?
            """,
            (authorization["mission_id"],),
        ).fetchone()
        if active_row is None or type(active_row["plan_json"]) is not str:
            raise PrincipalAuthenticationError("Action role requires an active collaboration plan")
        try:
            plan = CollaborationPlan.from_dict(json.loads(active_row["plan_json"]))
        except Exception as exc:
            raise StoreIntegrityError("Active collaboration plan is invalid") from exc
        if plan.plan_id != resolution["plan_id"]:
            raise PrincipalAuthenticationError(
                "Action role is not assigned by the current collaboration plan"
            )
        items = {item.work_item_id: item for item in plan.work_items}
        proposal_item = items.get(resolution["proposal_work_id"])
        if proposal_item is None:
            raise PrincipalAuthenticationError("Action proposal has no current work assignment")

        def current_owner(item: Any) -> str:
            ownership = connection.execute(
                """
                SELECT to_owner_id FROM collaboration_ownership_chain_entries
                WHERE plan_id = ? AND work_item_id = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (plan.plan_id, item.work_item_id),
            ).fetchone()
            return (
                str(item.owner_profile_id) if ownership is None else str(ownership["to_owner_id"])
            )

        role = authorization["role"]
        proposal_owner = current_owner(proposal_item)
        policy_row = connection.execute(
            """
            SELECT policy_json FROM collaboration_mission_policy_commits
            WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1
            """,
            (authorization["mission_id"],),
        ).fetchone()
        if policy_row is None or type(policy_row["policy_json"]) is not str:
            raise PrincipalAuthenticationError(
                "Action role requires a current collaboration authority policy"
            )
        try:
            policy = json.loads(policy_row["policy_json"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Collaboration authority policy is invalid") from exc
        if (
            canonical_json(policy) != policy_row["policy_json"]
            or policy.get("collaboration_plan_id") != plan.plan_id
            or action_policy["plan_id"] != plan.plan_id
            or policy.get("effective_at") > checked_at
            or policy.get("expires_at") <= checked_at
        ):
            raise PrincipalAuthenticationError("Collaboration authority policy is not current")
        approvals = policy.get("approval_bindings")
        if not isinstance(approvals, dict):
            raise StoreIntegrityError("Collaboration authority policy approvals are invalid")
        owner_binding = approvals.get("mission_owner")
        control_binding = approvals.get("independent_control")
        if not isinstance(owner_binding, dict) or not isinstance(control_binding, dict):
            raise StoreIntegrityError("Collaboration authority policy role bindings are invalid")
        owner_principal = bound_principal(owner_binding)
        control_principal = bound_principal(control_binding)
        excluded = {
            proposal_owner,
            resolution["proposal_producer_profile_id"],
            resolution["resolver_profile_id"],
        }
        if role == "mission_owner":
            valid = (
                profile_id == owner_binding.get("profile_id")
                and authorization["assertion_issuer"] == owner_principal["issuer"]
                and authorization["principal_subject"] == owner_principal["subject"]
                and profile_id not in {
                    resolution["proposal_producer_profile_id"],
                    resolution["resolver_profile_id"],
                }
            )
        elif role == "typed_resolver":
            assigned = action_policy["typed_resolver"]
            valid = (
                profile_id == assigned["principal_profile_id"]
                and authorization["principal_subject"] == assigned["principal_subject"]
                and authorization["assertion_issuer"] == assigned["assertion_issuer"]
                and profile_id != proposal_owner
                and profile_id != resolution["proposal_producer_profile_id"]
            )
        elif role == "independent_control":
            valid = (
                profile_id in mission.control_profile_ids
                and profile_id == control_binding.get("profile_id")
                and authorization["assertion_issuer"] == control_principal["issuer"]
                and authorization["principal_subject"] == control_principal["subject"]
                and profile.kind is ProfileKind.SHARED
                and profile.category == "independent control"
                and profile_id not in excluded
            )
        elif role == "admission_control":
            assigned = action_policy["admission_control"]
            valid = (
                profile_id == assigned["principal_profile_id"]
                and authorization["principal_subject"] == assigned["principal_subject"]
                and authorization["assertion_issuer"] == assigned["assertion_issuer"]
                and authorization["principal_subject"].startswith("service:")
                and profile_id not in excluded
            )
        else:
            valid = False
        if not valid:
            raise PrincipalAuthenticationError(
                "Action principal lacks current authoritative role entitlement"
            )

    def verify_stored_current(
        self,
        connection: sqlite3.Connection,
        authorization: Mapping[str, Any],
        operation: str,
        checked_at: str,
        *,
        receipt_id: str | None,
    ) -> None:
        """Revalidate a consumed assertion against current mission authority."""

        authorization = dict(authorization)
        parsed_operation = PrincipalOperation(operation)
        row = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                authorization["mission_id"],
            ),
        ).fetchone()
        if row is None or type(row["assertion_json"]) is not str:
            raise StoreIntegrityError("Stored action principal assertion is missing")
        try:
            raw = json.loads(row["assertion_json"])
            assertion = PrincipalAssertion.from_dict(raw)
        except Exception as exc:
            raise StoreIntegrityError("Stored action principal assertion is invalid") from exc
        assertion_json = canonical_json(assertion.to_dict())
        assertion_hash = sha256_text(assertion_json)
        if parsed_operation is PrincipalOperation.ACTION_AUTHORITY_PUBLISH:
            intent = {
                "idempotency_key_sha256": authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "publication_sha256": authorization["operation_intent_sha256"],
            }
        else:
            intent = {
                "action_intent_sha256": authorization["operation_intent_sha256"],
                "idempotency_key_sha256": authorization[
                    "canonical_replay_key_sha256"
                ],
                "mission_id": authorization["mission_id"],
                "principal_profile_id": authorization["principal_profile_id"],
                "role": authorization["role"],
            }
        signed_intent_hash = compute_operation_intent_hash(parsed_operation, intent)
        if (
            assertion_json != row["assertion_json"]
            or assertion_hash != authorization["assertion_sha256"]
            or assertion.operation is not parsed_operation
            or assertion.operation_intent_sha256 != signed_intent_hash
            or assertion.issuer != authorization["assertion_issuer"]
            or assertion.assertion_id != authorization["assertion_id"]
            or assertion.subject != authorization["principal_subject"]
            or assertion.profile_id != authorization["principal_profile_id"]
            or assertion.scope_grant_sha256 != authorization["scope_grant_sha256"]
            or row["assertion_hash"] != assertion_hash
            or row["operation"] != operation
            or row["signed_intent_hash"] != signed_intent_hash
        ):
            raise PrincipalAuthenticationError("Stored action assertion binding is invalid")
        checked_time = parse_timestamp(checked_at, "action assertion checked_at")
        identity, policies, mission, scopes = self._authenticated._verified_mission_state(
            connection,
            authorization["mission_id"],
        )
        current_policy_hash = identity["trust_policy_hash"]
        if current_policy_hash is None:
            raise StoreConflictError("A current trust policy is required")
        policy = policies.get(str(current_policy_hash))
        if policy is None:
            raise StoreIntegrityError("Current trust policy is missing")
        if (
            self._store._trust_policy_high_water_at(
                policies,
                checked_time,
            ).policy_sha256
            != policy.policy_sha256
        ):
            raise PrincipalAuthenticationError(
                "Action assertion is not valid under current trust authority"
            )
        scope_entry = scopes.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Action assertion scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        if (
            self._store._effective_scope_grant_revocation(
                connection,
                scope_row,
            )
            is not None
        ):
            raise PrincipalAuthenticationError("Action scope grant is revoked")
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError("Mission has no authenticated scope document hash")
        verified_scope = verify_scope_grant(
            scope_grant,
            policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=authorization["mission_id"],
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.mission.to_dict()["constraints"])
            ),
            expected_operation=parsed_operation,
            allow_expired_for_safety_reduction=(
                parsed_operation is PrincipalOperation.ACTION_ADMISSION_REVOKE
            ),
            clock=lambda: checked_time,
        )
        principal = verify_principal_assertion(
            assertion,
            policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=authorization["mission_id"],
            expected_operation=parsed_operation,
            expected_operation_intent_sha256=signed_intent_hash,
            clock=lambda: checked_time,
        )
        if (
            principal.key_sha256 != authorization["assertion_key_sha256"]
            or principal.policy_sha256 != authorization["trust_policy_sha256"]
            or principal.policy_sha256 != policy.policy_sha256
        ):
            raise PrincipalAuthenticationError(
                "Stored action principal differs from current authority"
            )
        self._require_role_entitlement(
            connection,
            authorization,
            mission,
            receipt_id=receipt_id,
            checked_at=checked_at,
            operation=operation,
        )


@dataclass(frozen=True, slots=True)
class _SealedExecutionTransactionTime:
    checked_at: str
    _proof: bytes


@dataclass(frozen=True, slots=True)
class _CommittedTargetHealthDenial:
    boundary: str
    result: TargetHealthGateObservationResult


class MissionStoreAuthenticatedActionAdmissionService(AuthenticatedActionAdmissionService):
    """Commit review revalidation and action admission in one store lock."""

    def __init__(
        self,
        store: MissionStore,
        review_verifier: AuthenticatedExpertReviewClosureVerifierAdapter,
        review_registry: ExpertRegistry,
        *,
        health_gate: MissionStoreTargetHealthGateService,
        clock: Any | None = None,
    ) -> None:
        if type(store) is not MissionStore:
            raise TypeError("store must be a MissionStore")
        if type(review_verifier) is not AuthenticatedExpertReviewClosureVerifierAdapter:
            raise TypeError("review_verifier must be the authenticated Phase194 adapter")
        if review_verifier._custody._store is not store:
            raise TypeError("review verifier and action custody must share one MissionStore")
        if type(health_gate) is not MissionStoreTargetHealthGateService:
            raise TypeError("health_gate must be a MissionStoreTargetHealthGateService")
        if health_gate._store is not store:
            raise TypeError("health gate and action custody must share one MissionStore")
        if health_gate._registry is not review_registry:
            raise TypeError("health gate and action custody must share one registry")
        transaction_clock = clock or store._clock
        if (
            health_gate._clock is not transaction_clock
            or health_gate._custody._trusted_clock is not transaction_clock
        ):
            raise TypeError(
                "action admission and target health custody must share one trusted clock"
            )
        authority = MissionStoreActionAuthority(
            store,
            review_registry,
            review_verifier._custody,
        )
        super().__init__(
            store.path,
            authority,
            review_verifier,
            review_registry,
            clock=transaction_clock,
            busy_timeout_ms=store._busy_timeout_ms,
        )
        self._store = store
        self._transaction_review_verifier = review_verifier
        self._health_gate = health_gate
        self._principal_custody = MissionStoreActionPrincipalCustody(
            store,
            review_registry,
        )
        self._execution_time_key = secrets.token_bytes(32)

    @staticmethod
    def _target_health_binding_from_request(
        request: ActionAdmissionRequest,
    ) -> ExecutionBinding:
        if type(request) is not ActionAdmissionRequest:
            raise TypeError("request must be an ActionAdmissionRequest")
        return build_target_health_execution_binding(
            context=request.context,
            worker_session=request.worker_session,
            credential_lease=request.credential_lease,
            target=request.target,
        )

    @staticmethod
    def _target_health_binding_from_material(
        material: ActionAuthorityMaterialSnapshot,
    ) -> ExecutionBinding:
        if type(material) is not ActionAuthorityMaterialSnapshot:
            raise TypeError("material must be an ActionAuthorityMaterialSnapshot")
        document = material.to_dict()
        target = parse_target_action_descriptor(document["target"]).to_dict()
        return build_target_health_execution_binding(
            context=ContextBinding.from_dict(document["context"]),
            worker_session=WorkerSession.from_dict(document["worker_session"]),
            credential_lease=CredentialLease.from_dict(
                document["credential_lease"]
            ),
            target=TargetBinding(
                target_id=target["target_id"],
                target_sha256=target["target_sha256"],
                authority_sha256=target["authority_snapshot_sha256"],
                tenant_id=target["tenant_id"],
                mission_id=target["mission_id"],
                scope_sha256=target["target_scope_sha256"],
                environment=target["environment"],
            ),
        )

    @staticmethod
    def _target_health_denial(
        boundary: str,
        result: TargetHealthGateObservationResult,
    ) -> _CommittedTargetHealthDenial | None:
        if (
            result.decision.status
            is TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
        ):
            return None
        return _CommittedTargetHealthDenial(boundary=boundary, result=result)

    @staticmethod
    def _raise_committed_target_health_denial(
        denial: _CommittedTargetHealthDenial,
    ) -> None:
        raise ActionResolutionError(
            "Target health gate denied "
            f"{denial.boundary}: "
            f"{denial.result.observation.classification.value}"
        )

    def _observe_target_health_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        binding: ExecutionBinding,
        expected_at: str,
    ) -> TargetHealthGateObservationResult:
        result = self._health_gate.observe_current_in_transaction(
            connection,
            binding,
        )
        if (
            result.decision.status
            is TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
            and result.decision.evaluated_at != expected_at
        ):
            raise StoreConflictError(
                "Target health evaluation time differs from the action transaction"
            )
        return result

    @staticmethod
    def _record_target_health_use(
        connection: sqlite3.Connection,
        *,
        use_kind: ActionTargetHealthGateUseKind,
        consumer_id: str,
        consumer_sha256: str,
        binding: ExecutionBinding,
        result: TargetHealthGateObservationResult,
        used_at: str,
    ) -> ActionTargetHealthGateUse:
        use = ActionTargetHealthGateUse(
            use_kind=use_kind,
            tenant_id=binding.tenant_id,
            mission_id=binding.context_id,
            consumer_id=consumer_id,
            consumer_sha256=consumer_sha256,
            binding_sha256=execution_binding_sha256(binding),
            decision=result.decision,
            transition=result.transition,
            head=result.head,
            used_at=used_at,
        )
        insert_action_target_health_gate_use(connection, use)
        verify_action_target_health_gate_use_store(
            connection,
            mission_id=binding.context_id,
        )
        return use

    def _seal_execution_transaction_time(self) -> _SealedExecutionTransactionTime:
        """Read and seal the one trusted time used by an execution transaction."""

        checked_at = self._format_time(self._clock())
        material = _canonical_json(
            {
                "checked_at": checked_at,
                "domain": "sunderkey.action-execution-transaction-time.v1",
                "service_identity": id(self),
            }
        ).encode("ascii")
        return _SealedExecutionTransactionTime(
            checked_at=checked_at,
            _proof=hmac.new(
                self._execution_time_key,
                material,
                hashlib.sha256,
            ).digest(),
        )

    def publish_authority_sources(
        self,
        assertion: PrincipalAssertion,
        publication: AuthenticatedActionAuthorityPublication,
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
    ) -> AuthenticatedActionAuthorityPublication:
        result = self._publish_authority_sources_with_health_result(
            assertion,
            publication,
            policy=policy,
            catalog=catalog,
            target=target,
            budget=budget,
            safety=safety,
            proposal=proposal,
            source_bundle=source_bundle,
            material=material,
            observations=observations,
        )
        if isinstance(result, _CommittedTargetHealthDenial):
            self._raise_committed_target_health_denial(result)
        return result

    def _publish_authority_sources_with_health_result(
        self,
        assertion: PrincipalAssertion,
        publication: AuthenticatedActionAuthorityPublication,
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
    ) -> AuthenticatedActionAuthorityPublication | _CommittedTargetHealthDenial:
        """Authenticate and atomically publish one complete current source set."""

        if type(assertion) is not PrincipalAssertion:
            raise TypeError("assertion must be a PrincipalAssertion")
        if type(publication) is not AuthenticatedActionAuthorityPublication:
            raise TypeError("publication must be canonical")
        expected_types = (
            (policy, ActionAuthorityPolicyRevision),
            (catalog, AuthoritativeActionCatalogRevision),
            (target, AuthoritativeTargetDescriptorRevision),
            (budget, ActionBudgetPolicyRevision),
            (safety, ActionSafetyPolicyRevision),
            (proposal, AuthenticatedProposalMaterialImport),
            (source_bundle, ExactActionSourceHeadBundle),
            (material, ActionAuthorityMaterialSnapshot),
        )
        if any(type(value) is not expected for value, expected in expected_types):
            raise TypeError("authority publication contains a noncanonical source")
        if (
            type(observations) is not tuple
            or tuple(sorted(item.KIND for item in observations)) != OBSERVATION_KINDS
            or any(type(item) is not ActionAuthorityObservation for item in observations)
        ):
            raise TypeError("authority publication observations are incomplete")
        document = publication.to_dict()
        evaluated_at = self._format_time(self._clock())
        rebuilt_publication = build_authenticated_action_authority_publication(
            policy=policy,
            catalog=catalog,
            target=target,
            budget=budget,
            safety=safety,
            proposal=proposal,
            source_bundle=source_bundle,
            material=material,
            observations=observations,
            idempotency_key_sha256=document["idempotency_key_sha256"],
            published_at=document["published_at"],
        )
        if rebuilt_publication.document_json != publication.document_json:
            raise StoreIntegrityError("Authority publication is not the canonical source set")
        source_documents = tuple(
            value.to_dict()
            for value in (
                policy,
                catalog,
                target,
                budget,
                safety,
                proposal,
                *observations,
                source_bundle,
            )
        )
        supplied = {
            (item["record_kind"], item["record_id"]): item["record_sha256"]
            for item in document["source_records"]
        }
        if catalog.to_dict()["registry_sha256"] != _canonical_sha256(
            self._review_registry.to_dict()
        ):
            raise StoreIntegrityError(
                "Action catalog differs from the current expert registry"
            )
        for value, source_document in zip(
            (
                policy,
                catalog,
                target,
                budget,
                safety,
                proposal,
                *observations,
                source_bundle,
            ),
            source_documents,
            strict=True,
        ):
            if supplied.get((value.KIND, value.record_id)) != value.content_sha256:
                raise StoreIntegrityError("Publication source binding is substituted")
            if any(
                source_document[field] != document[field]
                for field in ("tenant_id", "mission_id", "plan_id")
            ):
                raise StoreIntegrityError("Publication source boundary is inconsistent")
        material_document = material.to_dict()
        if (
            material.material_snapshot_id != document["material_snapshot_id"]
            or material.material_snapshot_sha256 != document["material_snapshot_sha256"]
        ):
            raise StoreIntegrityError("Publication material binding is substituted")
        if assertion.operation is not PrincipalOperation.ACTION_AUTHORITY_PUBLISH:
            raise PrincipalAuthenticationError(
                "Authority publication assertion operation is invalid"
            )
        observation_by_kind = {
            observation.KIND: observation.to_dict() for observation in observations
        }
        workspace_guard: sqlite3.Connection | None = None
        guarded_records: ExpertReviewRecordSet | None = None
        guarded_high_water: dict[str, Any] | None = None
        try:
            with self._store._write_connection() as connection:
                proposal_document = proposal.to_dict()
                guarded_records, _registration = self._authority._review_custody._load_records(
                    connection,
                    proposal_document["review_closure_id"],
                )
                self._verify_review_current(connection, guarded_records)
                reviewed_product = proposal_document["reviewed_product"]
                snapshot_document = guarded_records.snapshot.to_dict()
                matching_products = [
                    item
                    for item in snapshot_document["products"]
                    if item["product_id"] == reviewed_product["product_id"]
                    and item["product_sha256"] == reviewed_product["product_sha256"]
                ]
                if (
                    len(matching_products) != 1
                    or guarded_records.snapshot.snapshot_id
                    != proposal_document["review_snapshot_id"]
                    or guarded_records.snapshot.snapshot_sha256
                    != proposal_document["review_snapshot_sha256"]
                    or guarded_records.closure.closure_id
                    != proposal_document["review_closure_id"]
                    or guarded_records.closure.closure_sha256
                    != proposal_document["review_closure_sha256"]
                    or guarded_records.closure.to_dict()["disposition"] != "accepted"
                    or guarded_records.revocation is not None
                ):
                    raise StoreIntegrityError(
                        "Authority publication reviewed product is not current Phase194 material"
                    )
                workspace_guard, guarded_high_water = (
                    self._transaction_review_verifier.open_local_workspace_guard(
                        connection,
                        guarded_records,
                    )
                )
                published_high_water = observation_by_kind[
                    "workspace_high_water_observation"
                ]["payload"]["high_water"]
                if guarded_high_water != published_high_water:
                    raise StoreConflictError(
                        "Authority publication workspace high-water is stale or substituted"
                    )
                existing = connection.execute(
                    "SELECT * FROM action_authority_publications "
                    "WHERE publication_id = ? OR publication_sha256 = ?",
                    (publication.publication_id, publication.publication_sha256),
                ).fetchall()
                if existing:
                    if (
                        len(existing) != 1
                        or existing[0]["publication_json"] != publication.document_json
                        or existing[0]["assertion_issuer"] != assertion.issuer
                        or existing[0]["assertion_id"] != assertion.assertion_id
                        or existing[0]["operation_intent_sha256"]
                        != assertion.operation_intent_sha256
                    ):
                        raise StoreConflictError(
                            "Authority publication identity has different content"
                        )
                    use = connection.execute(
                        "SELECT * FROM principal_assertion_uses "
                        "WHERE issuer = ? AND assertion_id = ? AND mission_id = ?",
                        (
                            assertion.issuer,
                            assertion.assertion_id,
                            document["mission_id"],
                        ),
                    ).fetchone()
                    assertion_json = canonical_json(assertion.to_dict())
                    if (
                        use is None
                        or use["assertion_json"] != assertion_json
                        or use["assertion_hash"] != sha256_text(assertion_json)
                        or use["operation"] != ACTION_AUTHORITY_PUBLISH_OPERATION
                        or use["domain_request_hash"]
                        != publication.publication_sha256
                        or use["idempotency_key_hash"]
                        != document["idempotency_key_sha256"]
                    ):
                        raise StoreConflictError(
                            "Authority publication replay principal differs"
                        )
                    authorization = {
                        "assertion_issuer": assertion.issuer,
                        "assertion_id": assertion.assertion_id,
                        "assertion_sha256": use["assertion_hash"],
                        "assertion_key_sha256": use["key_hash"],
                        "trust_policy_sha256": use["trust_policy_hash"],
                        "scope_grant_sha256": use["scope_grant_hash"],
                        "operation_intent_sha256": publication.publication_sha256,
                        "canonical_replay_key_sha256": document[
                            "idempotency_key_sha256"
                        ],
                        "mission_id": document["mission_id"],
                        "principal_profile_id": use["principal_profile_id"],
                        "principal_subject": use["subject"],
                        "role": "independent_control",
                    }
                    self._principal_custody.verify_stored_current(
                        connection,
                        authorization,
                        ACTION_AUTHORITY_PUBLISH_OPERATION,
                        evaluated_at,
                        receipt_id=None,
                    )
                    verify_action_authority_repository(
                        connection,
                        mission_id=document["mission_id"],
                        require_current_sources=True,
                    )
                    current_bundle = load_current_action_source_bundle(
                        connection,
                        document["mission_id"],
                        evaluated_at,
                    )
                    if (
                        current_bundle.source_bundle_id
                        != source_bundle.source_bundle_id
                        or current_bundle.source_bundle_sha256
                        != source_bundle.source_bundle_sha256
                    ):
                        raise StoreConflictError(
                            "Authority publication replay is not the current source bundle"
                        )
                    load_current_action_material_snapshot(
                        connection,
                        current_bundle,
                        evaluated_at,
                    )
                    self._transaction_review_verifier.verify_local_workspace_guard(
                        connection,
                        workspace_guard,
                        guarded_records,
                        guarded_high_water,
                    )
                    health_binding = self._target_health_binding_from_material(
                        material
                    )
                    health_result = self._observe_target_health_in_transaction(
                        connection,
                        binding=health_binding,
                        expected_at=evaluated_at,
                    )
                    denial = self._target_health_denial(
                        "authority publication replay",
                        health_result,
                    )
                    if denial is not None:
                        return denial
                    self._record_target_health_use(
                        connection,
                        use_kind=(
                            ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION_REPLAY_FOR_USE
                        ),
                        consumer_id=publication.publication_id,
                        consumer_sha256=publication.publication_sha256,
                        binding=health_binding,
                        result=health_result,
                        used_at=evaluated_at,
                    )
                    return publication
                if document["published_at"] != evaluated_at:
                    raise StoreConflictError(
                        "Authority publication time differs from the service clock"
                    )
                identity, policies, _mission, _scopes = (
                    self._principal_custody._authenticated._verified_mission_state(
                        connection,
                        document["mission_id"],
                    )
                )
                policy_hash = identity["trust_policy_hash"]
                current_policy = policies.get(str(policy_hash))
                if current_policy is None:
                    raise StoreIntegrityError("Current trust policy is absent")
                key = current_policy.policy.key(assertion.key_id)
                authorization = {
                    "assertion_issuer": assertion.issuer,
                    "assertion_id": assertion.assertion_id,
                    "assertion_sha256": sha256_text(canonical_json(assertion.to_dict())),
                    "assertion_key_sha256": key.content_sha256,
                    "trust_policy_sha256": current_policy.policy_sha256,
                    "scope_grant_sha256": assertion.scope_grant_sha256,
                    "operation_intent_sha256": publication.publication_sha256,
                    "canonical_replay_key_sha256": document["idempotency_key_sha256"],
                    "mission_id": document["mission_id"],
                    "principal_profile_id": assertion.profile_id,
                    "principal_subject": assertion.subject,
                    "role": "independent_control",
                }
                health_binding = self._target_health_binding_from_material(material)
                health_result = self._observe_target_health_in_transaction(
                    connection,
                    binding=health_binding,
                    expected_at=evaluated_at,
                )
                denial = self._target_health_denial(
                    "authority publication",
                    health_result,
                )
                if denial is not None:
                    return denial
                self._principal_custody.consume(
                    connection,
                    assertion,
                    authorization,
                    ACTION_AUTHORITY_PUBLISH_OPERATION,
                    document["published_at"],
                    receipt_id=None,
                    effect_document=document,
                    effect_id=publication.publication_id,
                )
                for value, source_document in zip(
                    (policy, catalog, target, budget, safety),
                    source_documents[:5],
                    strict=True,
                ):
                    existing_revision = connection.execute(
                        "SELECT record_json FROM action_authority_revisions "
                        "WHERE (record_kind = ? AND record_id = ?) "
                        "OR (record_kind = ? AND record_sha256 = ?)",
                        (
                            value.KIND,
                            value.record_id,
                            value.KIND,
                            value.content_sha256,
                        ),
                    ).fetchall()
                    if existing_revision:
                        if (
                            len(existing_revision) != 1
                            or existing_revision[0]["record_json"]
                            != value.document_json
                        ):
                            raise StoreConflictError(
                                "Action authority revision identity has different content"
                            )
                        continue
                    connection.execute(
                        """
                        INSERT INTO action_authority_revisions(
                            record_kind, record_id, record_sha256, tenant_id,
                            mission_id, plan_id, revision,
                            previous_revision_sha256, effective_at, expires_at,
                            record_json, committed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            value.KIND,
                            value.record_id,
                            value.content_sha256,
                            source_document["tenant_id"],
                            source_document["mission_id"],
                            source_document["plan_id"],
                            source_document["revision"],
                            source_document["previous_revision_sha256"],
                            source_document["effective_at"],
                            source_document["expires_at"],
                            value.document_json,
                            document["published_at"],
                        ),
                    )
                reviewed_product = proposal_document["reviewed_product"]
                existing_proposal = connection.execute(
                    "SELECT proposal_json FROM action_authority_proposal_imports "
                    "WHERE proposal_import_id = ? OR proposal_import_sha256 = ? "
                    "OR product_id = ? OR product_sha256 = ?",
                    (
                        proposal.proposal_import_id,
                        proposal.proposal_import_sha256,
                        reviewed_product["product_id"],
                        reviewed_product["product_sha256"],
                    ),
                ).fetchall()
                if existing_proposal and (
                    len(existing_proposal) != 1
                    or existing_proposal[0]["proposal_json"] != proposal.document_json
                ):
                    raise StoreConflictError(
                        "Action proposal import identity has different content"
                    )
                if not existing_proposal:
                    connection.execute(
                    """
                    INSERT INTO action_authority_proposal_imports(
                        proposal_import_id, proposal_import_sha256, tenant_id,
                        mission_id, plan_id, product_id, product_sha256,
                        review_snapshot_id, review_snapshot_sha256,
                        review_closure_id, review_closure_sha256,
                        catalog_revision_id, catalog_revision_sha256,
                        target_revision_id, target_revision_sha256,
                        proposal_json, imported_at, committed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                        proposal.proposal_import_id,
                        proposal.proposal_import_sha256,
                        proposal_document["tenant_id"],
                        proposal_document["mission_id"],
                        proposal_document["plan_id"],
                        reviewed_product["product_id"],
                        reviewed_product["product_sha256"],
                        proposal_document["review_snapshot_id"],
                        proposal_document["review_snapshot_sha256"],
                        proposal_document["review_closure_id"],
                        proposal_document["review_closure_sha256"],
                        proposal_document["catalog_binding"]["catalog_revision_id"],
                        proposal_document["catalog_binding"]["catalog_revision_sha256"],
                        proposal_document["target_binding"]["target_revision_id"],
                        proposal_document["target_binding"]["target_revision_sha256"],
                        proposal.document_json,
                        proposal_document["imported_at"],
                        document["published_at"],
                        ),
                    )
                for observation in observations:
                    observation_document = observation.to_dict()
                    existing_observation = connection.execute(
                        "SELECT observation_json FROM action_authority_observations "
                        "WHERE observation_id = ? OR observation_sha256 = ?",
                        (observation.record_id, observation.content_sha256),
                    ).fetchall()
                    if existing_observation:
                        if (
                            len(existing_observation) != 1
                            or existing_observation[0]["observation_json"]
                            != observation.document_json
                        ):
                            raise StoreConflictError(
                                "Action observation identity has different content"
                            )
                        continue
                    connection.execute(
                        """
                        INSERT INTO action_authority_observations(
                            observation_kind, observation_id, observation_sha256,
                            tenant_id, mission_id, plan_id, observation_json,
                            observed_at, valid_until, committed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            observation.KIND,
                            observation.record_id,
                            observation.content_sha256,
                            observation_document["tenant_id"],
                            observation_document["mission_id"],
                            observation_document["plan_id"],
                            observation.document_json,
                            observation_document["observed_at"],
                            observation_document["valid_until"],
                            document["published_at"],
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO action_authority_material_snapshots(
                        material_snapshot_id, material_snapshot_sha256,
                        tenant_id, mission_id, plan_id, proposal_import_id,
                        proposal_import_sha256, credential_lease_sha256,
                        health_observation_sha256, executor_deployment_sha256,
                        monitor_observation_sha256, material_json, observed_at,
                        valid_until, committed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        material.material_snapshot_id,
                        material.material_snapshot_sha256,
                        material_document["tenant_id"],
                        material_document["mission_id"],
                        material_document["plan_id"],
                        material_document["proposal_import_id"],
                        material_document["proposal_import_sha256"],
                        material_document["credential_lease_sha256"],
                        material_document["health_observation_sha256"],
                        material_document["executor_deployment_sha256"],
                        material_document["monitor_observation_sha256"],
                        material.document_json,
                        material_document["observed_at"],
                        material_document["valid_until"],
                        document["published_at"],
                    ),
                )
                budget_document = budget.to_dict()
                account = connection.execute(
                    "SELECT * FROM action_budget_accounts WHERE mission_id = ?",
                    (document["mission_id"],),
                ).fetchone()
                if account is None:
                    opened_at = document["published_at"]
                    account_id = (
                        "ABA-"
                        + _canonical_sha256(
                            {
                                "account": {
                                    "budget_id": budget_document["budget_id"],
                                    "mission_id": document["mission_id"],
                                    "opened_at": opened_at,
                                    "tenant_id": document["tenant_id"],
                                },
                                "domain": BUDGET_ACCOUNT_DOMAIN,
                            }
                        )
                        .removeprefix("sha256:")[:32]
                        .upper()
                    )
                    connection.execute(
                        """
                        INSERT INTO action_budget_accounts(
                            account_id, mission_id, tenant_id, budget_id,
                            budget_revision_id, budget_revision_sha256,
                            limits_json, opened_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            account_id,
                            document["mission_id"],
                            document["tenant_id"],
                            budget_document["budget_id"],
                            budget.budget_revision_id,
                            budget.budget_revision_sha256,
                            canonical_json(budget_document["limits"]),
                            opened_at,
                        ),
                    )
                else:
                    account_id = str(account["account_id"])
                    if (
                        account["tenant_id"] != document["tenant_id"]
                        or account["budget_id"] != budget_document["budget_id"]
                    ):
                        raise StoreConflictError(
                            "Action budget identity cannot rotate within a mission"
                        )
                prior_binding = connection.execute(
                    "SELECT * FROM action_budget_policy_bindings "
                    "WHERE account_id = ? ORDER BY binding_sequence DESC LIMIT 1",
                    (account_id,),
                ).fetchone()
                if (
                    prior_binding is None
                    or prior_binding["budget_revision_id"]
                    != budget.budget_revision_id
                    or prior_binding["budget_revision_sha256"]
                    != budget.budget_revision_sha256
                ):
                    binding_sequence = (
                        1
                        if prior_binding is None
                        else int(prior_binding["binding_sequence"]) + 1
                    )
                    previous_binding_sha256 = (
                        None
                        if prior_binding is None
                        else str(prior_binding["binding_sha256"])
                    )
                    if (
                        prior_binding is not None
                        and str(prior_binding["bound_at"]) >= document["published_at"]
                    ):
                        raise StoreConflictError(
                            "Action budget policy rotation time did not advance"
                        )
                    binding_body = {
                        "account_id": account_id,
                        "binding_sequence": binding_sequence,
                        "budget_revision_id": budget.budget_revision_id,
                        "budget_revision_sha256": budget.budget_revision_sha256,
                        "limits": budget_document["limits"],
                        "previous_binding_sha256": previous_binding_sha256,
                        "bound_at": document["published_at"],
                    }
                    binding_sha256 = _canonical_sha256(
                        {
                            "binding": binding_body,
                            "domain": BUDGET_POLICY_BINDING_DOMAIN,
                        }
                    )
                    connection.execute(
                        """
                        INSERT INTO action_budget_policy_bindings(
                            account_id, binding_sequence, budget_revision_id,
                            budget_revision_sha256, limits_json,
                            previous_binding_sha256, binding_sha256, bound_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            account_id,
                            binding_sequence,
                            budget.budget_revision_id,
                            budget.budget_revision_sha256,
                            canonical_json(budget_document["limits"]),
                            previous_binding_sha256,
                            binding_sha256,
                            document["published_at"],
                        ),
                    )
                else:
                    binding_sequence = int(prior_binding["binding_sequence"])
                    binding_sha256 = str(prior_binding["binding_sha256"])
                if (
                    source_bundle.to_dict()["budget_policy_binding_sequence"]
                    != binding_sequence
                    or source_bundle.to_dict()["budget_policy_binding_sha256"]
                    != binding_sha256
                ):
                    raise StoreConflictError(
                        "Source bundle budget policy head differs from the stable account"
                    )
                latest_budget_event = connection.execute(
                    "SELECT event_sha256 FROM action_budget_account_events "
                    "WHERE account_id = ? ORDER BY event_sequence DESC LIMIT 1",
                    (account_id,),
                ).fetchone()
                empty_budget_head = _canonical_sha256(
                    {
                        "domain": BUDGET_EVENT_DOMAIN,
                        "empty_account_id": account_id,
                    }
                )
                current_budget_head = (
                    empty_budget_head
                    if latest_budget_event is None
                    else str(latest_budget_event["event_sha256"])
                )
                if (
                    source_bundle.to_dict()["budget_ledger_head_sha256"]
                    != current_budget_head
                ):
                    raise StoreConflictError(
                        "Source bundle budget head differs from the stable account"
                    )
                existing_account_head = connection.execute(
                    "SELECT event_count, event_head_sha256, updated_at "
                    "FROM action_budget_account_heads "
                    "WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM action_budget_account_events WHERE account_id = ?",
                    (account_id,),
                ).fetchone()[0]
                if existing_account_head is None:
                    connection.execute(
                        """
                        INSERT INTO action_budget_account_heads(
                            account_id, policy_binding_count, policy_head_sha256,
                            event_count, event_head_sha256, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            account_id,
                            binding_sequence,
                            binding_sha256,
                            event_count,
                            current_budget_head,
                            document["published_at"],
                        ),
                    )
                else:
                    if (
                        existing_account_head["event_count"] != event_count
                        or existing_account_head["event_head_sha256"]
                        != current_budget_head
                        or str(existing_account_head["updated_at"])
                        >= document["published_at"]
                    ):
                        raise StoreIntegrityError(
                            "Action budget event head is inconsistent before rotation"
                        )
                    connection.execute(
                        """
                        UPDATE action_budget_account_heads
                        SET policy_binding_count = ?, policy_head_sha256 = ?, updated_at = ?
                        WHERE account_id = ?
                        """,
                        (
                            binding_sequence,
                            binding_sha256,
                            document["published_at"],
                            account_id,
                        ),
                    )
                bundle_document = source_bundle.to_dict()
                prior_publication = connection.execute(
                    "SELECT published_at FROM action_authority_publications "
                    "WHERE mission_id = ? ORDER BY published_at DESC LIMIT 1",
                    (document["mission_id"],),
                ).fetchone()
                if (
                    prior_publication is not None
                    and str(prior_publication["published_at"])
                    >= document["published_at"]
                ):
                    raise StoreConflictError(
                        "Action authority publication time did not advance"
                    )
                connection.execute(
                    """
                    INSERT INTO action_authority_source_bundles(
                        source_bundle_id, source_bundle_sha256, tenant_id,
                        mission_id, plan_id, bundle_json, observed_at,
                        valid_until, committed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_bundle.source_bundle_id,
                        source_bundle.source_bundle_sha256,
                        bundle_document["tenant_id"],
                        bundle_document["mission_id"],
                        bundle_document["plan_id"],
                        source_bundle.document_json,
                        bundle_document["observed_at"],
                        bundle_document["valid_until"],
                        document["published_at"],
                    ),
                )
                for value in (
                    policy,
                    catalog,
                    target,
                    budget,
                    safety,
                    proposal,
                    *observations,
                    source_bundle,
                ):
                    source_kind = value.KIND
                    previous = connection.execute(
                        "SELECT head_sequence, head_sha256, record_id, record_sha256, "
                        "advanced_at "
                        "FROM action_authority_source_heads "
                        "WHERE mission_id = ? AND source_kind = ? "
                        "ORDER BY head_sequence DESC LIMIT 1",
                        (document["mission_id"], source_kind),
                    ).fetchone()
                    if (
                        previous is not None
                        and previous["record_id"] == value.record_id
                        and previous["record_sha256"] == value.content_sha256
                    ):
                        continue
                    if (
                        previous is not None
                        and str(previous["advanced_at"]) >= document["published_at"]
                    ):
                        raise StoreConflictError(
                            "Action authority source head time did not advance"
                        )
                    sequence = 1 if previous is None else int(previous["head_sequence"]) + 1
                    previous_sha = None if previous is None else str(previous["head_sha256"])
                    head_sha = _head_sha256(
                        mission_id=document["mission_id"],
                        source_kind=source_kind,
                        head_sequence=sequence,
                        record_id=value.record_id,
                        record_sha256=value.content_sha256,
                        previous_head_sha256=previous_sha,
                        advanced_at=document["published_at"],
                    )
                    connection.execute(
                        """
                        INSERT INTO action_authority_source_heads(
                            mission_id, source_kind, head_sequence, record_id,
                            record_sha256, previous_head_sha256, head_sha256,
                            advanced_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            document["mission_id"],
                            source_kind,
                            sequence,
                            value.record_id,
                            value.content_sha256,
                            previous_sha,
                            head_sha,
                            document["published_at"],
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO action_authority_publications(
                        publication_id, publication_sha256, mission_id,
                        source_bundle_id, source_bundle_sha256,
                        material_snapshot_id, material_snapshot_sha256,
                        assertion_issuer, assertion_id,
                        operation_intent_sha256, idempotency_key_sha256,
                        publication_json, published_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        publication.publication_id,
                        publication.publication_sha256,
                        document["mission_id"],
                        source_bundle.source_bundle_id,
                        source_bundle.source_bundle_sha256,
                        material.material_snapshot_id,
                        material.material_snapshot_sha256,
                        assertion.issuer,
                        assertion.assertion_id,
                        assertion.operation_intent_sha256,
                        document["idempotency_key_sha256"],
                        publication.document_json,
                        document["published_at"],
                    ),
                )
                self._record_target_health_use(
                    connection,
                    use_kind=(
                        ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION
                    ),
                    consumer_id=publication.publication_id,
                    consumer_sha256=publication.publication_sha256,
                    binding=health_binding,
                    result=health_result,
                    used_at=evaluated_at,
                )
                verify_action_authority_repository(
                    connection,
                    mission_id=document["mission_id"],
                    require_current_sources=True,
                )
                self._transaction_review_verifier.verify_local_workspace_guard(
                    connection,
                    workspace_guard,
                    guarded_records,
                    guarded_high_water,
                )
                return publication
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authority source publication conflicts") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist authority source publication") from exc
        finally:
            if workspace_guard is not None:
                self._transaction_review_verifier.close_local_workspace_guard(
                    workspace_guard
                )

    def initialize(self) -> None:
        self._store.initialize()
        self._health_gate.initialize()
        with self._store._read_connection() as connection:
            version = self._store._require_schema(connection)
            if version < ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION:
                raise StoreMigrationRequiredError(
                    "MissionStore action admission requires migrate-store"
                )

    def submit_authorization_grant(
        self,
        assertion: PrincipalAssertion,
        authorization: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Stage one signed action authorization for point-of-use consumption.

        Submission does not authorize an action and does not consume the assertion.
        The complete signature, current trust, scope, role, replay, and effect checks
        occur in the admission or revocation transaction that consumes this row.
        """

        if type(assertion) is not PrincipalAssertion:
            raise TypeError("assertion must be a PrincipalAssertion")
        checked = _authorization(authorization, "action authorization grant")
        operation = assertion.operation
        allowed_roles = {
            PrincipalOperation.ACTION_RESOLVE: {
                AuthorizationRole.TYPED_RESOLVER.value,
            },
            PrincipalOperation.ACTION_QUORUM_AUTHORIZE: {
                AuthorizationRole.MISSION_OWNER.value,
                AuthorizationRole.INDEPENDENT_CONTROL.value,
            },
            PrincipalOperation.ACTION_ADMIT: {
                AuthorizationRole.ADMISSION_CONTROL.value,
            },
            PrincipalOperation.ACTION_ADMISSION_REVOKE: {
                AuthorizationRole.INDEPENDENT_CONTROL.value,
            },
        }
        if operation not in allowed_roles or checked["role"] not in allowed_roles[operation]:
            raise PrincipalAuthenticationError(
                "Action authorization role is invalid for the signed operation"
            )
        intent = {
            "action_intent_sha256": checked["operation_intent_sha256"],
            "idempotency_key_sha256": checked["canonical_replay_key_sha256"],
            "mission_id": checked["mission_id"],
            "principal_profile_id": checked["principal_profile_id"],
            "role": checked["role"],
        }
        expected_intent_sha256 = compute_operation_intent_hash(operation, intent)
        assertion_json = canonical_json(assertion.to_dict())
        assertion_sha256 = sha256_text(assertion_json)
        if (
            assertion.operation is not operation
            or assertion.operation_intent_sha256 != expected_intent_sha256
            or assertion.issuer != checked["assertion_issuer"]
            or assertion.assertion_id != checked["assertion_id"]
            or assertion.subject != checked["principal_subject"]
            or assertion.profile_id != checked["principal_profile_id"]
            or assertion.scope_grant_sha256 != checked["scope_grant_sha256"]
            or assertion_sha256 != checked["assertion_sha256"]
        ):
            raise PrincipalAuthenticationError(
                "Signed action assertion differs from the submitted authorization"
            )
        received_at = self._format_time(self._clock())
        authorization_json = canonical_json(checked)
        try:
            with self._store._write_connection() as connection:
                existing = connection.execute(
                    """
                    SELECT * FROM action_authority_grant_submissions
                    WHERE assertion_issuer = ? AND assertion_id = ?
                    """,
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["assertion_sha256"] != assertion_sha256
                        or existing["mission_id"] != checked["mission_id"]
                        or existing["role"] != checked["role"]
                        or existing["operation"] != operation.value
                        or existing["operation_intent_sha256"]
                        != checked["operation_intent_sha256"]
                        or existing["canonical_replay_key_sha256"]
                        != checked["canonical_replay_key_sha256"]
                        or existing["authorization_json"] != authorization_json
                        or existing["assertion_json"] != assertion_json
                    ):
                        raise StoreConflictError(
                            "Action authorization grant identity has different content"
                        )
                    verify_action_authority_repository(
                        connection,
                        mission_id=checked["mission_id"],
                        require_current_sources=(
                            operation
                            is not PrincipalOperation.ACTION_ADMISSION_REVOKE
                        ),
                    )
                    return checked
                connection.execute(
                    """
                    INSERT INTO action_authority_grant_submissions(
                        assertion_issuer, assertion_id, assertion_sha256,
                        mission_id, role, operation, operation_intent_sha256,
                        canonical_replay_key_sha256, authorization_json,
                        assertion_json, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        assertion.issuer,
                        assertion.assertion_id,
                        assertion_sha256,
                        checked["mission_id"],
                        checked["role"],
                        operation.value,
                        checked["operation_intent_sha256"],
                        checked["canonical_replay_key_sha256"],
                        authorization_json,
                        assertion_json,
                        received_at,
                    ),
                )
                verify_action_authority_repository(
                    connection,
                    mission_id=checked["mission_id"],
                    require_current_sources=(
                        operation
                        is not PrincipalOperation.ACTION_ADMISSION_REVOKE
                    ),
                )
                return checked
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Action authorization grant conflicts with existing custody"
            ) from exc

    def _reserve_budget(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
        budget: BudgetBinding,
        reserved_at: str,
    ) -> None:
        account, revision, usage = _current_budget_state(
            connection,
            tenant_id=budget.tenant_id,
            mission_id=budget.mission_id,
            expected_revision_sha256=budget.budget_sha256,
            checked_at=reserved_at,
        )
        resources = dict(revision["per_action_ceiling"])
        limits = revision["limits"]
        expected_budget = BudgetBinding(
            tenant_id=budget.tenant_id,
            mission_id=budget.mission_id,
            budget_sha256=revision["budget_revision_sha256"],
            request_limit=limits["rate_units"],
            requests_used=usage["rate_units"],
            token_limit=limits["request_bytes"] + limits["response_bytes"],
            tokens_used=usage["request_bytes"] + usage["response_bytes"],
            cost_limit_microunits=limits["money_microunits"],
            cost_used_microunits=usage["money_microunits"],
            action_request_cost=resources["rate_units"],
            action_token_cost=resources["request_bytes"]
            + resources["response_bytes"],
            action_cost_microunits=resources["money_microunits"],
        )
        if budget.to_dict() != expected_budget.to_dict():
            raise StoreIntegrityError(
                "Phase165 budget projection differs from the six-axis ledger"
            )
        if any(
            usage[field] + resources[field] > limits[field]
            for field in RESOURCE_FIELDS
        ):
            raise ActionResolutionError(
                "Authoritative six-axis action budget cannot be reserved"
            )
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS "
            "_action_budget_reservation(payload TEXT NOT NULL)"
        )
        connection.execute("DELETE FROM _action_budget_reservation")
        connection.execute(
            "INSERT INTO _action_budget_reservation(payload) VALUES (?)",
            (
                _canonical_json(
                    {
                        "budget_sha256": budget.budget_sha256,
                        "cost_microunits": budget.action_cost_microunits,
                        "mission_id": budget.mission_id,
                        "receipt_id": receipt_id,
                        "request_cost": budget.action_request_cost,
                        "reserved_at": reserved_at,
                        "tenant_id": budget.tenant_id,
                        "token_cost": budget.action_token_cost,
                    }
                ),
            ),
        )
        prior = connection.execute(
            "SELECT event_sequence, event_sha256 "
            "FROM action_budget_account_events WHERE account_id = ? "
            "ORDER BY event_sequence DESC LIMIT 1",
            (account["account_id"],),
        ).fetchone()
        event_sequence = 1 if prior is None else int(prior["event_sequence"]) + 1
        previous_event_sha256 = (
            None if prior is None else str(prior["event_sha256"])
        )
        payload = {
            "account_id": account["account_id"],
            "budget_revision_id": revision["budget_revision_id"],
            "budget_revision_sha256": revision["budget_revision_sha256"],
            "event_sequence": event_sequence,
            "previous_event_sha256": previous_event_sha256,
            "receipt_id": receipt_id,
            "recorded_at": reserved_at,
            "resources": resources,
        }
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS "
            "_action_six_axis_budget_reservation(payload TEXT NOT NULL)"
        )
        connection.execute("DELETE FROM _action_six_axis_budget_reservation")
        connection.execute(
            "INSERT INTO _action_six_axis_budget_reservation(payload) VALUES (?)",
            (canonical_json(payload),),
        )

    def _insert_receipt(
        self,
        connection: sqlite3.Connection,
        custody: Mapping[str, Any],
    ) -> None:
        super()._insert_receipt(connection, custody)
        row = connection.execute(
            "SELECT payload FROM _action_six_axis_budget_reservation"
        ).fetchone()
        if row is None or type(row["payload"]) is not str:
            raise StoreIntegrityError("Six-axis budget reservation custody is missing")
        try:
            event = json.loads(row["payload"])
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Six-axis budget reservation is invalid") from exc
        if canonical_json(event) != row["payload"]:
            raise StoreIntegrityError("Six-axis budget reservation is noncanonical")
        idempotency_key_sha256 = custody["command"]["idempotency_key_sha256"]
        reservation_body = {
            "account_id": event["account_id"],
            "budget_revision_id": event["budget_revision_id"],
            "budget_revision_sha256": event["budget_revision_sha256"],
            "idempotency_key_sha256": idempotency_key_sha256,
            "receipt_id": event["receipt_id"],
            "reserved_at": event["recorded_at"],
            "resources": event["resources"],
        }
        reservation_sha256 = _canonical_sha256(
            {
                "domain": BUDGET_RESERVATION_DOMAIN,
                "reservation": reservation_body,
            }
        )
        reservation_id = (
            "ABR-" + reservation_sha256.removeprefix("sha256:")[:32].upper()
        )
        event_body = {
            "account_id": event["account_id"],
            "budget_revision_id": event["budget_revision_id"],
            "budget_revision_sha256": event["budget_revision_sha256"],
            "claim_id": None,
            "claim_sha256": None,
            "dispatch_id": None,
            "event_kind": "reserve",
            "event_sequence": event["event_sequence"],
            "execution_id": None,
            "execution_intent_sha256": None,
            "idempotency_key_sha256": idempotency_key_sha256,
            "previous_event_sha256": event["previous_event_sha256"],
            "receipt_id": event["receipt_id"],
            "recorded_at": event["recorded_at"],
            "reservation_id": reservation_id,
            "reservation_sha256": reservation_sha256,
            "resources": event["resources"],
        }
        event_sha256 = _canonical_sha256(
            {"domain": BUDGET_EVENT_DOMAIN, "event": event_body}
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
                resources_json,
                previous_event_sha256, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["account_id"],
                event["event_sequence"],
                event_id,
                event_sha256,
                "reserve",
                event["receipt_id"],
                event["budget_revision_id"],
                event["budget_revision_sha256"],
                reservation_id,
                reservation_sha256,
                idempotency_key_sha256,
                None,
                None,
                None,
                None,
                None,
                canonical_json(event["resources"]),
                event["previous_event_sha256"],
                event["recorded_at"],
            ),
        )
        connection.execute(
            """
            INSERT INTO action_budget_receipt_reservations(
                receipt_id, account_id, reservation_id, reservation_sha256,
                reserve_event_id, reserve_event_sha256, budget_revision_id,
                budget_revision_sha256, idempotency_key_sha256,
                resources_json, reserved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["receipt_id"],
                event["account_id"],
                reservation_id,
                reservation_sha256,
                event_id,
                event_sha256,
                event["budget_revision_id"],
                event["budget_revision_sha256"],
                idempotency_key_sha256,
                canonical_json(event["resources"]),
                event["recorded_at"],
            ),
        )
        updated = connection.execute(
            """
            UPDATE action_budget_account_heads
            SET event_count = ?, event_head_sha256 = ?, updated_at = ?
            WHERE account_id = ? AND event_count = ?
              AND event_head_sha256 = ?
            """,
            (
                event["event_sequence"],
                event_sha256,
                event["recorded_at"],
                event["account_id"],
                event["event_sequence"] - 1,
                (
                    _canonical_sha256(
                        {
                            "domain": BUDGET_EVENT_DOMAIN,
                            "empty_account_id": event["account_id"],
                        }
                    )
                    if event["previous_event_sha256"] is None
                    else event["previous_event_sha256"]
                ),
            ),
        )
        if updated.rowcount != 1:
            raise StoreConflictError("Action budget account head changed during reservation")

    def _settle_budget_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        charged_resources: Mapping[str, Any],
        execution_id: str,
        claim_id: str,
        dispatch_id: str,
        recorded_at: str,
    ) -> tuple[str, ...]:
        """Settle one reservation and release its remainder in the caller's transaction."""

        raise StoreIntegrityError(
            "Budget settlement requires durable authenticated dispatch custody"
        )

    def _release_budget_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        execution_id: str | None,
        claim_id: str | None,
        recorded_at: str,
    ) -> tuple[str, ...]:
        """Release an un-dispatched reservation in the caller's transaction."""

        raise StoreIntegrityError(
            "Budget release requires durable authenticated dispatch custody"
        )

    def _append_budget_terminal_events(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        charged_resources: Mapping[str, Any] | None,
        execution_id: str | None,
        claim_id: str | None,
        dispatch_id: str | None,
        recorded_at: str,
        release_only: bool,
        revocation: ActionAdmissionRevocation | None = None,
    ) -> tuple[str, ...]:
        if type(connection) is not sqlite3.Connection or not connection.in_transaction:
            raise StoreIntegrityError(
                "Action budget terminal custody requires the active transaction"
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
        ):
            raise StoreError(
                "Action budget terminal custody requires the owned MissionStore"
            )
        if revocation is None:
            raise StoreIntegrityError(
                "Budget terminal custody requires durable authenticated dispatch custody"
            )
        _identifier(receipt_id, "receipt ID")
        _timestamp(recorded_at, "budget terminal recorded_at")
        if revocation is not None:
            if not release_only or any(
                value is not None for value in (execution_id, claim_id, dispatch_id)
            ):
                raise StoreIntegrityError(
                    "Revocation budget release lineage is invalid"
                )
            lineage = _revocation_budget_release_lineage(revocation)
            execution_id = lineage["execution_id"]
            claim_id = lineage["claim_id"]
        else:
            lineage = None
        for label, value in (
            ("execution_id", execution_id),
            ("claim_id", claim_id),
            ("dispatch_id", dispatch_id),
        ):
            if value is not None:
                _identifier(value, label)
        if not release_only and None in (execution_id, claim_id, dispatch_id):
            raise StoreIntegrityError("Budget settlement requires complete execution lineage")
        if release_only and None in (execution_id, claim_id):
            raise StoreIntegrityError(
                "Budget release requires execution and claim lineage"
            )
        link = connection.execute(
            "SELECT * FROM action_budget_receipt_reservations WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if link is None or type(link["resources_json"]) is not str:
            raise StoreIntegrityError("Action budget reservation is absent")
        consumption = connection.execute(
            "SELECT * FROM action_admission_execution_consumptions "
            "WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if revocation is None:
            if (
                consumption is None
                or consumption["execution_id"] != execution_id
                or consumption["claim_id"] != claim_id
                or str(consumption["consumed_at"]) > recorded_at
            ):
                raise StoreIntegrityError(
                    "Budget terminal lineage differs from execution consumption"
                )
            execution_intent_sha256 = consumption["execution_intent_sha256"]
            claim_sha256 = consumption["claim_sha256"]
        else:
            document = revocation.to_dict()
            if (
                consumption is not None
                or document["receipt_id"] != receipt_id
                or document["revoked_at"] != recorded_at
            ):
                raise StoreIntegrityError(
                    "Budget revocation release differs from revocation custody"
                )
            execution_intent_sha256 = lineage["execution_intent_sha256"]
            claim_sha256 = lineage["claim_sha256"]
        reserved = json.loads(link["resources_json"])
        if canonical_json(reserved) != link["resources_json"]:
            raise StoreIntegrityError("Action budget reservation is noncanonical")
        if release_only:
            event_specs = (("release", reserved),)
        else:
            charged = dict(charged_resources or {})
            if set(charged) != set(RESOURCE_FIELDS) or any(
                type(charged[field]) is not int
                or charged[field] < 0
                or charged[field] > reserved[field]
                for field in RESOURCE_FIELDS
            ):
                raise StoreIntegrityError("Action budget settlement vector is invalid")
            remainder = {
                field: reserved[field] - charged[field] for field in RESOURCE_FIELDS
            }
            event_specs = (
                (("settle", charged), ("release", remainder))
                if any(remainder.values())
                else (("settle", charged),)
            )
        prior_terminal = connection.execute(
            "SELECT event_kind FROM action_budget_account_events "
            "WHERE account_id = ? AND reservation_id = ? AND event_kind != 'reserve'",
            (link["account_id"], link["reservation_id"]),
        ).fetchall()
        if prior_terminal:
            raise StoreConflictError("Action budget reservation is already terminal")
        prior = connection.execute(
            "SELECT event_sequence, event_sha256, recorded_at "
            "FROM action_budget_account_events WHERE account_id = ? "
            "ORDER BY event_sequence DESC LIMIT 1",
            (link["account_id"],),
        ).fetchone()
        if prior is None or str(prior["recorded_at"]) > recorded_at:
            raise StoreConflictError("Action budget terminal chronology regressed")
        account_head = connection.execute(
            "SELECT updated_at FROM action_budget_account_heads WHERE account_id = ?",
            (link["account_id"],),
        ).fetchone()
        if account_head is None or str(account_head["updated_at"]) > recorded_at:
            raise StoreConflictError("Action budget account chronology regressed")
        sequence = int(prior["event_sequence"])
        previous_sha256 = str(prior["event_sha256"])
        event_ids: list[str] = []
        for event_kind, resources in event_specs:
            sequence += 1
            body = {
                "account_id": link["account_id"],
                "budget_revision_id": link["budget_revision_id"],
                "budget_revision_sha256": link["budget_revision_sha256"],
                "claim_id": claim_id,
                "claim_sha256": claim_sha256,
                "dispatch_id": dispatch_id,
                "event_kind": event_kind,
                "event_sequence": sequence,
                "execution_id": execution_id,
                "execution_intent_sha256": execution_intent_sha256,
                "idempotency_key_sha256": link["idempotency_key_sha256"],
                "previous_event_sha256": previous_sha256,
                "receipt_id": receipt_id,
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
                    receipt_id,
                    link["budget_revision_id"],
                    link["budget_revision_sha256"],
                    link["reservation_id"],
                    link["reservation_sha256"],
                    link["idempotency_key_sha256"],
                    execution_id,
                    execution_intent_sha256,
                    claim_id,
                    claim_sha256,
                    dispatch_id,
                    canonical_json(resources),
                    previous_sha256,
                    recorded_at,
                ),
            )
            event_ids.append(event_id)
            previous_sha256 = event_sha256
        updated = connection.execute(
            """
            UPDATE action_budget_account_heads
            SET event_count = ?, event_head_sha256 = ?, updated_at = ?
            WHERE account_id = ? AND event_count = ? AND event_head_sha256 = ?
            """,
            (
                sequence,
                previous_sha256,
                recorded_at,
                link["account_id"],
                int(prior["event_sequence"]),
                prior["event_sha256"],
            ),
        )
        if updated.rowcount != 1:
            raise StoreConflictError("Action budget account head changed during settlement")
        verify_action_authority_repository(
            connection,
            mission_id=connection.execute(
                "SELECT mission_id FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()["mission_id"],
            require_current_sources=False,
        )
        return tuple(event_ids)

    def _verify_review_current(
        self,
        connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
    ) -> ExpertReviewRecordSet:
        sealed = self._transaction_review_verifier.verify_current_in_transaction(
            connection,
            records,
            self._review_registry,
        )
        return _verify_current_expert_review_closure(
            _FixedReviewVerifier(sealed),
            records,
            self._review_registry,
        )

    def admit(
        self,
        command: ActionAdmissionCommand,
    ) -> AuthenticatedActionAdmissionReceipt:
        result = self._admit_with_health_result(command)
        if isinstance(result, _CommittedTargetHealthDenial):
            self._raise_committed_target_health_denial(result)
        return result

    def _admit_with_health_result(
        self,
        command: ActionAdmissionCommand,
    ) -> AuthenticatedActionAdmissionReceipt | _CommittedTargetHealthDenial:
        if type(command) is not ActionAdmissionCommand:
            raise TypeError("command must be an ActionAdmissionCommand")
        evaluated_at = self._format_time(self._clock())
        workspace_guard: sqlite3.Connection | None = None
        guarded_records: ExpertReviewRecordSet | None = None
        workspace_high_water: dict[str, Any] | None = None
        try:
            with self._store._write_connection() as connection:
                existing = connection.execute(
                    """
                    SELECT * FROM action_admission_receipts
                    WHERE tenant_id = ? AND mission_id = ?
                      AND idempotency_key_sha256 = ?
                    """,
                    (
                        command.tenant_id,
                        command.mission_id,
                        command.idempotency_key_sha256,
                    ),
                ).fetchone()
                if existing is not None:
                    if existing["command_sha256"] != command.command_sha256:
                        raise StoreConflictError(
                            "Action admission idempotency key has different intent"
                        )
                    self._require_not_revoked(
                        connection,
                        str(existing["receipt_id"]),
                    )
                    stored = self._stored_from_row(connection, existing)
                    guarded_records = stored.review_records
                    workspace_guard, workspace_high_water = (
                        self._transaction_review_verifier.open_local_workspace_guard(
                            connection,
                            guarded_records,
                        )
                    )
                    self._verify_workspace_high_water(
                        connection,
                        stored.receipt,
                        workspace_high_water,
                    )
                    self._verify_central_receipt(
                        connection,
                        stored,
                        checked_at=evaluated_at,
                    )
                    self._verify_review_current(connection, stored.review_records)
                    current = self._authority.verify_stored_current(
                        connection,
                        stored,
                        evaluated_at,
                    )
                    self._require_same_authority_state(
                        stored.authority_state,
                        current,
                    )
                    self._transaction_review_verifier.verify_local_workspace_guard(
                        connection,
                        workspace_guard,
                        guarded_records,
                        workspace_high_water,
                    )
                    health_binding = self._target_health_binding_from_request(
                        stored.request
                    )
                    health_result = self._observe_target_health_in_transaction(
                        connection,
                        binding=health_binding,
                        expected_at=evaluated_at,
                    )
                    denial = self._target_health_denial(
                        "action admission replay",
                        health_result,
                    )
                    if denial is not None:
                        return denial
                    self._record_target_health_use(
                        connection,
                        use_kind=(
                            ActionTargetHealthGateUseKind.ACTION_ADMISSION_REPLAY_FOR_USE
                        ),
                        consumer_id=stored.receipt.receipt_id,
                        consumer_sha256=stored.receipt.receipt_sha256,
                        binding=health_binding,
                        result=health_result,
                        used_at=evaluated_at,
                    )
                    self._verify_transaction(connection)
                    return stored.receipt

                material = self._authority.load_current_material(
                    connection,
                    command,
                    evaluated_at,
                )
                guarded_records = material.records
                workspace_guard, workspace_high_water = (
                    self._transaction_review_verifier.open_local_workspace_guard(
                        connection,
                        guarded_records,
                    )
                )
                current_bundle = load_current_action_source_bundle(
                    connection,
                    command.mission_id,
                    evaluated_at,
                ).to_dict()
                if (
                    workspace_high_water.get("high_water_sha256")
                    != current_bundle["workspace_high_water_sha256"]
                ):
                    raise ActionResolutionError(
                        "Guarded workspace high-water differs from signed source authority"
                    )
                (
                    resolution,
                    resolver,
                    review_document,
                    review_hash,
                    state,
                ) = self._resolve_current(
                    connection,
                    command,
                    material,
                    evaluated_at,
                )
                quorum = self._authorize_quorum(
                    connection,
                    resolution,
                    resolver,
                    material,
                    evaluated_at,
                )
                request = self._reconstruct_request(
                    resolution,
                    quorum,
                    context=material.context,
                    worker_session=material.worker_session,
                    credential_lease=material.credential_lease,
                    health=material.health,
                    budget=material.budget,
                    evidence_obligations=material.evidence_obligations,
                    stop_conditions=material.stop_conditions,
                    restoration_duties=material.restoration_duties,
                    requested_at=material.requested_at,
                    expires_at=material.expires_at,
                )
                decision = evaluate_action_admission(
                    request,
                    evaluated_at=evaluated_at,
                )
                if decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                    reasons = ",".join(item.value for item in decision.denial_reasons)
                    raise ActionResolutionError(f"Phase 165 action admission denied: {reasons}")
                admission = self._authority.authorize_admission(
                    connection,
                    resolution,
                    quorum,
                    request,
                    admission_authorization_intent_sha256(
                        resolution,
                        quorum,
                        request,
                    ),
                    evaluated_at,
                )
                admission = self._checked_admission_authorization(
                    resolution,
                    resolver,
                    quorum,
                    request,
                    admission,
                    evaluated_at,
                )
                receipt = self._build_receipt(
                    resolution,
                    quorum,
                    request,
                    decision.to_dict(),
                    admission,
                    evaluated_at,
                )
                health_binding = self._target_health_binding_from_request(request)
                health_result = self._observe_target_health_in_transaction(
                    connection,
                    binding=health_binding,
                    expected_at=evaluated_at,
                )
                denial = self._target_health_denial(
                    "action admission",
                    health_result,
                )
                if denial is not None:
                    return denial
                self._reserve_budget(
                    connection,
                    receipt.receipt_id,
                    material.budget,
                    evaluated_at,
                )
                custody = self._custody_document(
                    command,
                    resolution,
                    quorum,
                    request,
                    decision.to_dict(),
                    receipt,
                    resolver,
                    review_document,
                    review_hash,
                    state,
                    evaluated_at,
                )
                self._insert_receipt(connection, custody)
                self._record_target_health_use(
                    connection,
                    use_kind=ActionTargetHealthGateUseKind.ACTION_ADMISSION,
                    consumer_id=receipt.receipt_id,
                    consumer_sha256=receipt.receipt_sha256,
                    binding=health_binding,
                    result=health_result,
                    used_at=evaluated_at,
                )
                self._insert_workspace_high_water(
                    connection,
                    receipt,
                    workspace_high_water,
                    evaluated_at,
                )
                self._consume_central_authorization(
                    connection,
                    receipt,
                    resolver,
                    ACTION_RESOLVE_OPERATION,
                    "action_resolution",
                    evaluated_at,
                )
                for approval in quorum.to_dict()["approvals"]:
                    self._consume_central_authorization(
                        connection,
                        receipt,
                        approval,
                        ACTION_QUORUM_OPERATION,
                        "action_quorum",
                        evaluated_at,
                    )
                self._consume_central_authorization(
                    connection,
                    receipt,
                    admission,
                    ACTION_ADMIT_OPERATION,
                    "action_admission",
                    evaluated_at,
                )
                self._insert_normalized_chain(
                    connection,
                    receipt,
                    resolution,
                    resolver,
                    quorum,
                )
                self._transaction_review_verifier.verify_local_workspace_guard(
                    connection,
                    workspace_guard,
                    guarded_records,
                    workspace_high_water,
                )
                self._verify_transaction(connection)
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Action admission conflicts with global replay or custody"
            ) from exc
        finally:
            if workspace_guard is not None:
                self._transaction_review_verifier.close_local_workspace_guard(workspace_guard)

    def verify_current(
        self,
        receipt_id: str,
        *,
        evaluated_at: str | None = None,
    ) -> CurrentActionAdmission:
        result = self._verify_current_with_health_result(
            receipt_id,
            evaluated_at=evaluated_at,
        )
        if isinstance(result, _CommittedTargetHealthDenial):
            self._raise_committed_target_health_denial(result)
        return result

    def _verify_current_with_health_result(
        self,
        receipt_id: str,
        *,
        evaluated_at: str | None = None,
    ) -> CurrentActionAdmission | _CommittedTargetHealthDenial:
        _identifier(receipt_id, "receipt ID")
        checked_at = self._format_time(self._clock())
        if (
            evaluated_at is not None
            and _timestamp(evaluated_at, "evaluated_at") != checked_at
        ):
            raise ActionResolutionError(
                "Action admission verification time differs from service clock"
            )
        workspace_guard: sqlite3.Connection | None = None
        try:
            with self._store._write_connection() as connection:
                row = connection.execute(
                    "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if row is None:
                    raise ActionResolutionError("Action admission receipt is not in custody")
                self._require_not_revoked(connection, receipt_id)
                stored = self._stored_from_row(connection, row)
                workspace_guard, high_water = (
                    self._transaction_review_verifier.open_local_workspace_guard(
                        connection,
                        stored.review_records,
                    )
                )
                self._verify_workspace_high_water(
                    connection,
                    stored.receipt,
                    high_water,
                )
                self._verify_central_receipt(
                    connection,
                    stored,
                    checked_at=checked_at,
                )
                current_decision = evaluate_action_admission(
                    stored.request,
                    evaluated_at=checked_at,
                )
                if current_decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                    reasons = ",".join(item.value for item in current_decision.denial_reasons)
                    raise ActionResolutionError(
                        f"Phase 165 action admission is no longer current: {reasons}"
                    )
                self._verify_review_current(connection, stored.review_records)
                current = self._authority.verify_stored_current(
                    connection,
                    stored,
                    checked_at,
                )
                self._require_same_authority_state(stored.authority_state, current)
                self._transaction_review_verifier.verify_local_workspace_guard(
                    connection,
                    workspace_guard,
                    stored.review_records,
                    high_water,
                )
                health_binding = self._target_health_binding_from_request(
                    stored.request
                )
                health_result = self._observe_target_health_in_transaction(
                    connection,
                    binding=health_binding,
                    expected_at=checked_at,
                )
                denial = self._target_health_denial(
                    "current action admission verification",
                    health_result,
                )
                if denial is not None:
                    return denial
                self._record_target_health_use(
                    connection,
                    use_kind=(
                        ActionTargetHealthGateUseKind.ACTION_ADMISSION_CURRENT_VERIFICATION
                    ),
                    consumer_id=stored.receipt.receipt_id,
                    consumer_sha256=stored.receipt.receipt_sha256,
                    binding=health_binding,
                    result=health_result,
                    used_at=checked_at,
                )
                self._verify_transaction(connection)
                custody_sha256 = row["custody_sha256"]
                if type(custody_sha256) is not str:
                    raise StoreIntegrityError("Stored custody hash type is invalid")
                proof = hmac.new(
                    self._current_proof_key,
                    _current_proof_material(
                        stored.receipt,
                        checked_at,
                        custody_sha256,
                    ),
                    hashlib.sha256,
                ).digest()
                return CurrentActionAdmission(
                    receipt=stored.receipt,
                    verified_at=checked_at,
                    custody_sha256=custody_sha256,
                    _proof=proof,
                )
        finally:
            if workspace_guard is not None:
                self._transaction_review_verifier.close_local_workspace_guard(workspace_guard)

    def revoke(
        self,
        receipt_id: str,
        *,
        reason_code: str,
        revoked_at: str | None = None,
    ) -> ActionAdmissionRevocation:
        _identifier(receipt_id, "receipt ID")
        _identifier(reason_code, "reason code")
        transaction_at = self._format_time(self._clock())
        requested_revoked_at = (
            None if revoked_at is None else _timestamp(revoked_at, "revoked_at")
        )
        checked_at = transaction_at
        try:
            with self._store._write_connection() as connection:
                row = connection.execute(
                    "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if row is None:
                    raise ActionResolutionError("Action admission receipt is not in custody")
                existing = connection.execute(
                    "SELECT * FROM action_admission_revocations WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if existing is not None:
                    revocation = self._parse_revocation_row(existing)
                    document = revocation.to_dict()
                    if requested_revoked_at is None:
                        checked_at = document["revoked_at"]
                    if (
                        document["reason_code"] != reason_code
                        or (
                            requested_revoked_at is not None
                            and document["revoked_at"] != requested_revoked_at
                        )
                    ):
                        raise StoreConflictError(
                            "Action admission revocation replay has different intent"
                        )
                    stored = self._stored_from_row(connection, row)
                    self._verify_central_receipt(
                        connection,
                        stored,
                    )
                    self._verify_revocation_link(
                        connection,
                        existing,
                        revocation,
                        stored.receipt,
                    )
                    self._verify_transaction(
                        connection,
                        require_current_action_sources=False,
                    )
                    return revocation
                if (
                    requested_revoked_at is not None
                    and requested_revoked_at != transaction_at
                ):
                    raise ActionResolutionError(
                        "Action admission revocation time differs from transaction time"
                    )
                stored = self._stored_from_row(connection, row)
                self._verify_central_receipt(
                    connection,
                    stored,
                )
                if checked_at <= stored.receipt.to_dict()["evaluated_at"]:
                    raise ActionResolutionError("Action admission revocation predates admission")
                intent = revocation_authorization_intent_sha256(
                    stored.receipt,
                    reason_code=reason_code,
                    revoked_at=checked_at,
                )
                authorization = self._authority.authorize_revocation(
                    connection,
                    stored,
                    reason_code,
                    intent,
                    checked_at,
                )
                authorization = self._checked_revocation_authorization(
                    stored,
                    authorization,
                    intent,
                    checked_at,
                )
                body = {
                    "schema_version": 1,
                    "kind": "action_admission_revocation",
                    "receipt_id": stored.receipt.receipt_id,
                    "receipt_sha256": stored.receipt.receipt_sha256,
                    "resolution_id": stored.resolution.resolution_id,
                    "resolution_sha256": stored.resolution.resolution_sha256,
                    "tenant_id": stored.receipt.to_dict()["tenant_id"],
                    "mission_id": stored.receipt.to_dict()["mission_id"],
                    "scope_sha256": stored.receipt.to_dict()["scope_sha256"],
                    "target_sha256": stored.receipt.to_dict()["target_sha256"],
                    "action_sha256": stored.receipt.to_dict()["action_sha256"],
                    "action_tier": stored.receipt.to_dict()["action_tier"],
                    "reason_code": reason_code,
                    "control_authorization": authorization,
                    "revoked_at": checked_at,
                    "identity_assurance": "mission_store_principal_assertion",
                    "effects": dict(NO_EFFECTS),
                }
                revocation = parse_action_admission_revocation(
                    _address_record("action_admission_revocation", body)
                )
                self._consume_central_authorization(
                    connection,
                    stored.receipt,
                    authorization,
                    ACTION_REVOKE_OPERATION,
                    "action_admission_revocation",
                    checked_at,
                )
                connection.execute(
                    """
                    INSERT INTO action_admission_revocations(
                        revocation_id, receipt_id, mission_id,
                        revocation_sha256, revocation_json,
                        assertion_issuer, assertion_id, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        revocation.revocation_id,
                        receipt_id,
                        stored.receipt.to_dict()["mission_id"],
                        revocation.revocation_sha256,
                        _canonical_json(revocation.to_dict()),
                        authorization["assertion_issuer"],
                        authorization["assertion_id"],
                        checked_at,
                    ),
                )
                if connection.execute(
                    "SELECT 1 FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone() is None:
                    self._append_budget_terminal_events(
                        connection,
                        receipt_id=receipt_id,
                        charged_resources=None,
                        execution_id=None,
                        claim_id=None,
                        dispatch_id=None,
                        recorded_at=checked_at,
                        release_only=True,
                        revocation=revocation,
                    )
                self._verify_transaction(
                    connection,
                    require_current_action_sources=False,
                )
                return revocation
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Action admission revocation conflicts with global custody"
            ) from exc

    def _consume_for_execution_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        execution_id: str,
        execution_intent_sha256: str,
        claim_id: str,
        claim_sha256: str,
        consumed_at: str,
        workspace_connection: sqlite3.Connection,
        workspace_high_water: Mapping[str, Any],
        _transaction_time: _SealedExecutionTransactionTime | None = None,
    ) -> ActionAdmissionExecutionConsumption:
        """Reserve one admission inside the caller's durable claim transaction."""

        if type(connection) is not sqlite3.Connection or not connection.in_transaction:
            raise StoreError("An active MissionStore transaction is required")
        _identifier(receipt_id, "receipt ID")
        _identifier(execution_id, "execution ID")
        _sha256(execution_intent_sha256, "execution intent")
        _identifier(claim_id, "claim ID")
        _sha256(claim_sha256, "claim hash")
        if _transaction_time is None:
            checked_at = self._format_time(self._clock())
        else:
            if type(_transaction_time) is not _SealedExecutionTransactionTime:
                raise ActionResolutionError(
                    "Execution transaction time capability is invalid"
                )
            checked_at = _transaction_time.checked_at
            material = _canonical_json(
                {
                    "checked_at": checked_at,
                    "domain": "sunderkey.action-execution-transaction-time.v1",
                    "service_identity": id(self),
                }
            ).encode("ascii")
            expected_time_proof = hmac.new(
                self._execution_time_key,
                material,
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(_transaction_time._proof, expected_time_proof):
                raise ActionResolutionError(
                    "Execution transaction time capability is invalid"
                )
        if _timestamp(consumed_at, "consumed_at") != checked_at:
            raise ActionResolutionError(
                "Execution consumption time differs from service clock"
            )
        if (
            type(workspace_connection) is not sqlite3.Connection
            or not workspace_connection.in_transaction
        ):
            raise StoreError("An active workspace read guard is required")
        mission_main = next(
            (
                item[2]
                for item in connection.execute("PRAGMA database_list").fetchall()
                if item[1] == "main"
            ),
            None,
        )
        workspace_main = next(
            (
                item[2]
                for item in workspace_connection.execute(
                    "PRAGMA database_list"
                ).fetchall()
                if item[1] == "main"
            ),
            None,
        )
        expected_workspace_path = (
            self._transaction_review_verifier._workspace_store.path.resolve()
        )
        if (
            type(mission_main) is not str
            or not mission_main
            or Path(mission_main).resolve() != self._store.path.resolve()
            or type(workspace_main) is not str
            or not workspace_main
            or Path(workspace_main).resolve() != expected_workspace_path
            or str(
                workspace_connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            != "delete"
        ):
            raise StoreError(
                "Execution consumption requires the owned MissionStore and workspace guard"
            )
        row = connection.execute(
            "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            raise ActionResolutionError("Action admission receipt is not in custody")
        if checked_at < _timestamp(str(row["created_at"]), "admission created_at"):
            raise ActionResolutionError("Execution consumption predates admission")
        self._require_not_revoked(connection, receipt_id)
        existing = connection.execute(
            """
            SELECT * FROM action_admission_execution_consumptions
            WHERE receipt_id = ?
            """,
            (receipt_id,),
        ).fetchone()
        consumption_id = (
            "AEC-"
            + _canonical_sha256(
                {
                    "claim_id": claim_id,
                    "claim_sha256": claim_sha256,
                    "domain": "sunderkey.action-admission-execution-consumption.v1",
                    "execution_id": execution_id,
                    "execution_intent_sha256": execution_intent_sha256,
                    "receipt_id": receipt_id,
                    "receipt_sha256": row["receipt_sha256"],
                }
            )
            .removeprefix("sha256:")[:32]
            .upper()
        )
        if existing is not None:
            actual = self._parse_execution_consumption(existing)
            lineage = {
                "claim_id": claim_id,
                "claim_sha256": claim_sha256,
                "execution_id": execution_id,
                "execution_intent_sha256": execution_intent_sha256,
                "receipt_id": receipt_id,
            }
            if any(getattr(actual, field) != value for field, value in lineage.items()):
                raise StoreConflictError(
                    "Action admission was consumed by another execution lineage"
                )
            stored = self._stored_from_row(connection, row)
            self._verify_workspace_high_water(
                connection,
                stored.receipt,
                workspace_high_water,
            )
            self._verify_central_receipt(
                connection,
                stored,
                checked_at=checked_at,
            )
            current_decision = evaluate_action_admission(
                stored.request,
                evaluated_at=checked_at,
            )
            if current_decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                raise ActionResolutionError(
                    "Stored execution consumption has an invalid admission basis"
                )
            current = self._authority.verify_stored_current(
                connection,
                stored,
                checked_at,
            )
            self._require_same_authority_state(stored.authority_state, current)
            self._verify_review_current(connection, stored.review_records)
            self._transaction_review_verifier.verify_local_workspace_guard(
                connection,
                workspace_connection,
                stored.review_records,
                dict(workspace_high_water),
            )
            return actual
        terminal = connection.execute(
            "SELECT 1 FROM action_budget_account_events "
            "WHERE receipt_id = ? AND event_kind != 'reserve' LIMIT 1",
            (receipt_id,),
        ).fetchone()
        if terminal is not None:
            raise StoreConflictError(
                "Action admission budget is already terminal"
            )
        stored = self._stored_from_row(connection, row)
        self._verify_workspace_high_water(
            connection,
            stored.receipt,
            workspace_high_water,
        )
        self._verify_central_receipt(
            connection,
            stored,
            checked_at=checked_at,
        )
        current_decision = evaluate_action_admission(
            stored.request,
            evaluated_at=checked_at,
        )
        if current_decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
            reasons = ",".join(item.value for item in current_decision.denial_reasons)
            raise ActionResolutionError(
                f"Phase 165 action admission is no longer current: {reasons}"
            )
        self._verify_review_current(connection, stored.review_records)
        current = self._authority.verify_stored_current(
            connection,
            stored,
            checked_at,
        )
        self._require_same_authority_state(stored.authority_state, current)
        self._transaction_review_verifier.verify_local_workspace_guard(
            connection,
            workspace_connection,
            stored.review_records,
            dict(workspace_high_water),
        )
        expected = ActionAdmissionExecutionConsumption(
            consumption_id=consumption_id,
            receipt_id=receipt_id,
            receipt_sha256=row["receipt_sha256"],
            custody_sha256=row["custody_sha256"],
            execution_id=execution_id,
            execution_intent_sha256=execution_intent_sha256,
            claim_id=claim_id,
            claim_sha256=claim_sha256,
            consumed_at=checked_at,
        )
        connection.execute(
            """
            INSERT INTO action_admission_execution_consumptions(
                consumption_id, receipt_id, receipt_sha256,
                custody_sha256, execution_id, execution_intent_sha256,
                claim_id, claim_sha256, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(expected.to_dict().values()),
        )
        self._verify_transaction(connection)
        return expected

    @staticmethod
    def _insert_workspace_high_water(
        connection: sqlite3.Connection,
        receipt: AuthenticatedActionAdmissionReceipt,
        high_water: Mapping[str, Any],
        imported_at: str,
    ) -> None:
        high_water = dict(high_water)
        receipt_document = receipt.to_dict()
        if high_water.get("mission_id") != receipt_document["mission_id"]:
            raise ActionResolutionError("Workspace high-water mission differs from admission")
        connection.execute(
            """
            INSERT INTO action_admission_workspace_high_waters(
                high_water_id, high_water_sha256, receipt_id, mission_id,
                mission_store_id, workspace_store_id, workspace_store_path,
                workspace_id, snapshot_id, snapshot_sha256, closure_id,
                closure_sha256, application_id, application_sha256,
                workspace_revision, event_count, event_head_sha256,
                event_head_occurred_at, state, revocation_id,
                revocation_sha256, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                high_water["high_water_id"],
                high_water["high_water_sha256"],
                receipt.receipt_id,
                high_water["mission_id"],
                high_water["mission_store_id"],
                high_water["workspace_store_id"],
                high_water["workspace_store_path"],
                high_water["workspace_id"],
                high_water["snapshot_id"],
                high_water["snapshot_sha256"],
                high_water["closure_id"],
                high_water["closure_sha256"],
                high_water["application_id"],
                high_water["application_sha256"],
                high_water["workspace_revision"],
                high_water["event_count"],
                high_water["event_head_sha256"],
                high_water["event_head_occurred_at"],
                high_water["state"],
                high_water["revocation_id"],
                high_water["revocation_sha256"],
                imported_at,
            ),
        )

    @staticmethod
    def _verify_workspace_high_water(
        connection: sqlite3.Connection,
        receipt: AuthenticatedActionAdmissionReceipt,
        expected: Mapping[str, Any],
    ) -> None:
        row = connection.execute(
            "SELECT * FROM action_admission_workspace_high_waters WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()
        expected = dict(expected)
        if row is None:
            raise StoreIntegrityError("Action workspace high-water custody is missing")
        fields = (
            "high_water_id",
            "high_water_sha256",
            "mission_id",
            "mission_store_id",
            "workspace_store_id",
            "workspace_store_path",
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
        )
        if row["receipt_id"] != receipt.receipt_id or any(
            row[field] != expected[field] for field in fields
        ):
            raise ActionResolutionError("Workspace high-water changed or was substituted")

    @staticmethod
    def _insert_normalized_chain(
        connection: sqlite3.Connection,
        receipt: AuthenticatedActionAdmissionReceipt,
        resolution: Any,
        resolver: Mapping[str, Any],
        quorum: Any,
    ) -> None:
        resolution_doc = resolution.to_dict()
        quorum_doc = quorum.to_dict()
        connection.execute(
            """
            INSERT INTO action_admission_resolutions(
                resolution_id, resolution_sha256, receipt_id, mission_id,
                resolution_json, resolver_assertion_issuer,
                resolver_assertion_id, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution.resolution_id,
                resolution.resolution_sha256,
                receipt.receipt_id,
                resolution_doc["mission_id"],
                _canonical_json(resolution_doc),
                resolver["assertion_issuer"],
                resolver["assertion_id"],
                resolution_doc["resolved_at"],
            ),
        )
        connection.execute(
            """
            INSERT INTO action_admission_quorums(
                quorum_id, quorum_sha256, receipt_id, resolution_id,
                quorum_json, approved_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quorum.quorum_id,
                quorum.quorum_sha256,
                receipt.receipt_id,
                resolution.resolution_id,
                _canonical_json(quorum_doc),
                quorum_doc["approved_at"],
                quorum_doc["expires_at"],
            ),
        )

    def _consume_central_authorization(
        self,
        connection: sqlite3.Connection,
        receipt: AuthenticatedActionAdmissionReceipt,
        authorization: Mapping[str, Any],
        operation: str,
        result_kind: str,
        consumed_at: str,
    ) -> None:
        authorization = dict(authorization)
        mission_id = receipt.to_dict()["mission_id"]
        row = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                mission_id,
            ),
        ).fetchone()
        if row is None:
            assertion = self._authority.principal_assertion_for(
                connection,
                dict(authorization),
                operation,
                consumed_at=consumed_at,
            )
            self._principal_custody.consume(
                connection,
                assertion,
                authorization,
                operation,
                consumed_at,
                receipt_id=receipt.receipt_id,
            )
            row = connection.execute(
                """
                SELECT * FROM principal_assertion_uses
                WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
                """,
                (
                    authorization["assertion_issuer"],
                    authorization["assertion_id"],
                    mission_id,
                ),
            ).fetchone()
        if row is None:
            raise StoreIntegrityError("Signed action assertion was not stored")
        expected = {
            "assertion_hash": authorization["assertion_sha256"],
            "subject": authorization["principal_subject"],
            "principal_profile_id": authorization["principal_profile_id"],
            "key_hash": authorization["assertion_key_sha256"],
            "operation": operation,
            "domain_request_hash": authorization["operation_intent_sha256"],
            "idempotency_key_hash": authorization["canonical_replay_key_sha256"],
            "scope_grant_hash": authorization["scope_grant_sha256"],
            "trust_policy_hash": authorization["trust_policy_sha256"],
        }
        if any(row[field] != value for field, value in expected.items()):
            raise ActionResolutionError(
                "MissionStore assertion use differs from action authorization"
            )
        authorization_json = _canonical_json(authorization)
        effect = connection.execute(
            """
            SELECT * FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
              AND effect_kind = ? AND effect_id = ?
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                mission_id,
                operation,
                authorization["assertion_id"],
            ),
        ).fetchone()
        effect_json = _canonical_json(
            _action_principal_effect(
                operation=operation,
                effect_id=authorization["assertion_id"],
                payload=authorization,
                recorded_at=str(row["consumed_at"]),
            )
        )
        effect_sha = sha256_text(effect_json)
        if (
            effect is None
            or effect["effect_json"] != effect_json
            or effect["effect_hash"] != effect_sha
            or row["effects_hash"] != principal_assertion_effects_hash((effect_sha,))
        ):
            raise ActionResolutionError("Authority did not bind the action authorization effect")
        if operation != ACTION_REVOKE_OPERATION:
            connection.execute(
                """
                INSERT INTO action_admission_assertion_uses(
                    assertion_issuer, assertion_id, mission_id, assertion_sha256,
                    canonical_replay_key_sha256, receipt_id, role, operation,
                    operation_intent_sha256, authorization_json, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization["assertion_issuer"],
                    authorization["assertion_id"],
                    mission_id,
                    authorization["assertion_sha256"],
                    authorization["canonical_replay_key_sha256"],
                    receipt.receipt_id,
                    authorization["role"],
                    operation,
                    authorization["operation_intent_sha256"],
                    authorization_json,
                    row["consumed_at"],
                ),
            )
        connection.execute(
            """
            INSERT INTO action_admission_replay_uses(
                canonical_replay_key_sha256, mission_id, operation,
                operation_intent_sha256, assertion_issuer, assertion_id,
                result_kind, result_id, result_sha256, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authorization["canonical_replay_key_sha256"],
                mission_id,
                operation,
                authorization["operation_intent_sha256"],
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                result_kind,
                authorization["assertion_id"],
                authorization["assertion_sha256"],
                row["consumed_at"],
            ),
        )

    def _verify_central_receipt(
        self,
        connection: sqlite3.Connection,
        stored: StoredActionAdmission,
        *,
        checked_at: str | None = None,
    ) -> None:
        resolution = connection.execute(
            "SELECT * FROM action_admission_resolutions WHERE receipt_id = ?",
            (stored.receipt.receipt_id,),
        ).fetchone()
        quorum = connection.execute(
            "SELECT * FROM action_admission_quorums WHERE receipt_id = ?",
            (stored.receipt.receipt_id,),
        ).fetchone()
        resolution_document = stored.resolution.to_dict()
        quorum_document = stored.quorum.to_dict()
        resolver = stored.resolver_authorization
        if (
            resolution is None
            or quorum is None
            or resolution["resolution_json"] != _canonical_json(resolution_document)
            or resolution["resolution_id"] != stored.resolution.resolution_id
            or resolution["resolution_sha256"] != stored.resolution.resolution_sha256
            or resolution["receipt_id"] != stored.receipt.receipt_id
            or resolution["mission_id"] != resolution_document["mission_id"]
            or resolution["resolver_assertion_issuer"] != resolver["assertion_issuer"]
            or resolution["resolver_assertion_id"] != resolver["assertion_id"]
            or resolution["resolved_at"] != resolution_document["resolved_at"]
            or quorum["quorum_json"] != _canonical_json(quorum_document)
            or quorum["quorum_id"] != stored.quorum.quorum_id
            or quorum["quorum_sha256"] != stored.quorum.quorum_sha256
            or quorum["receipt_id"] != stored.receipt.receipt_id
            or quorum["resolution_id"] != stored.resolution.resolution_id
            or quorum["approved_at"] != quorum_document["approved_at"]
            or quorum["expires_at"] != quorum_document["expires_at"]
        ):
            raise StoreIntegrityError("Normalized action admission chain is inconsistent")
        rows = connection.execute(
            """
            SELECT * FROM action_admission_assertion_uses
            WHERE receipt_id = ? ORDER BY role, assertion_issuer, assertion_id
            """,
            (stored.receipt.receipt_id,),
        ).fetchall()
        expected = [
            (
                stored.resolver_authorization,
                ACTION_RESOLVE_OPERATION,
                "action_resolution",
            ),
            *(
                (item, ACTION_QUORUM_OPERATION, "action_quorum")
                for item in stored.quorum.to_dict()["approvals"]
            ),
            (
                stored.receipt.to_dict()["admission_authorization"],
                ACTION_ADMIT_OPERATION,
                "action_admission",
            ),
        ]
        if len(rows) != len(expected):
            raise StoreIntegrityError("Action authorization link count is invalid")
        by_identity = {
            (item["assertion_issuer"], item["assertion_id"]): (
                item,
                operation,
                result_kind,
            )
            for item, operation, result_kind in expected
        }
        for row in rows:
            expected_link = by_identity.get((row["assertion_issuer"], row["assertion_id"]))
            if expected_link is None:
                raise StoreIntegrityError("Action authorization link is inconsistent")
            authorization, expected_operation, expected_result_kind = expected_link
            if (
                row["authorization_json"] != _canonical_json(authorization)
                or row["mission_id"] != authorization["mission_id"]
                or row["assertion_sha256"] != authorization["assertion_sha256"]
                or row["canonical_replay_key_sha256"]
                != authorization["canonical_replay_key_sha256"]
                or row["receipt_id"] != stored.receipt.receipt_id
                or row["role"] != authorization["role"]
                or row["operation"] != expected_operation
                or row["operation_intent_sha256"] != authorization["operation_intent_sha256"]
            ):
                raise StoreIntegrityError("Action authorization link is inconsistent")
            replay = connection.execute(
                """
                SELECT * FROM action_admission_replay_uses
                WHERE canonical_replay_key_sha256 = ?
                """,
                (row["canonical_replay_key_sha256"],),
            ).fetchone()
            central = connection.execute(
                """
                SELECT * FROM principal_assertion_uses
                WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
                """,
                (row["assertion_issuer"], row["assertion_id"], row["mission_id"]),
            ).fetchone()
            effect = connection.execute(
                """
                SELECT * FROM principal_assertion_effects
                WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
                  AND effect_kind = ? AND effect_id = ?
                """,
                (
                    row["assertion_issuer"],
                    row["assertion_id"],
                    row["mission_id"],
                    row["operation"],
                    row["assertion_id"],
                ),
            ).fetchone()
            try:
                authorization_payload = json.loads(row["authorization_json"])
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError(
                    "Action authorization link is invalid"
                ) from exc
            effect_json = _canonical_json(
                _action_principal_effect(
                    operation=str(row["operation"]),
                    effect_id=str(row["assertion_id"]),
                    payload=authorization_payload,
                    recorded_at=str(row["consumed_at"]),
                )
            )
            effect_sha = sha256_text(effect_json)
            if (
                replay is None
                or central is None
                or effect is None
                or replay["assertion_issuer"] != row["assertion_issuer"]
                or replay["assertion_id"] != row["assertion_id"]
                or replay["operation"] != row["operation"]
                or replay["operation_intent_sha256"] != row["operation_intent_sha256"]
                or replay["mission_id"] != row["mission_id"]
                or replay["result_kind"] != expected_result_kind
                or central["assertion_hash"] != row["assertion_sha256"]
                or central["domain_request_hash"] != row["operation_intent_sha256"]
                or central["idempotency_key_hash"] != row["canonical_replay_key_sha256"]
                or effect["effect_json"] != effect_json
                or effect["effect_hash"] != effect_sha
                or central["effects_hash"] != principal_assertion_effects_hash((effect_sha,))
                or replay["result_id"] != row["assertion_id"]
                or replay["result_sha256"] != row["assertion_sha256"]
                or replay["consumed_at"] != row["consumed_at"]
                or central["consumed_at"] != row["consumed_at"]
                or effect["recorded_at"] != row["consumed_at"]
            ):
                raise StoreIntegrityError(
                    "Central action assertion or replay custody is inconsistent"
                )
            if checked_at is not None:
                self._principal_custody.verify_stored_current(
                    connection,
                    authorization,
                    expected_operation,
                    checked_at,
                    receipt_id=stored.receipt.receipt_id,
                )

    def _verify_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        require_current_action_sources: bool = True,
    ) -> None:
        if type(require_current_action_sources) is not bool:
            raise TypeError("require_current_action_sources must be a bool")
        self._store._foreign_key_check(connection)
        self._store._verify_connection(
            connection,
            self._review_registry,
            schema_version=self._store._require_schema(connection),
            require_current_action_sources=require_current_action_sources,
        )

    @staticmethod
    def _parse_revocation_row(row: sqlite3.Row) -> ActionAdmissionRevocation:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Stored action revocation types are invalid")
        try:
            raw = json.loads(row["revocation_json"])
            revocation = parse_action_admission_revocation(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored action revocation is invalid") from exc
        if (
            _canonical_json(raw) != row["revocation_json"]
            or revocation.revocation_id != row["revocation_id"]
            or revocation.revocation_sha256 != row["revocation_sha256"]
            or revocation.to_dict()["receipt_id"] != row["receipt_id"]
            or revocation.to_dict()["mission_id"] != row["mission_id"]
            or revocation.to_dict()["revoked_at"] != row["revoked_at"]
            or revocation.to_dict()["control_authorization"]["assertion_issuer"]
            != row["assertion_issuer"]
            or revocation.to_dict()["control_authorization"]["assertion_id"] != row["assertion_id"]
        ):
            raise StoreIntegrityError("Stored action revocation binding is invalid")
        return revocation

    @staticmethod
    def _parse_execution_consumption(
        row: sqlite3.Row,
    ) -> ActionAdmissionExecutionConsumption:
        if any(type(row[field]) is not str for field in tuple(row.keys())):
            raise StoreIntegrityError("Execution consumption types are invalid")
        consumption = ActionAdmissionExecutionConsumption(
            **{name: row[name] for name in ActionAdmissionExecutionConsumption.__dataclass_fields__}
        )
        _identifier(consumption.consumption_id, "consumption ID")
        _identifier(consumption.receipt_id, "receipt ID")
        _sha256(consumption.receipt_sha256, "receipt hash")
        _sha256(consumption.custody_sha256, "custody hash")
        _identifier(consumption.execution_id, "execution ID")
        _sha256(consumption.execution_intent_sha256, "execution intent")
        _identifier(consumption.claim_id, "claim ID")
        _sha256(consumption.claim_sha256, "claim hash")
        _timestamp(consumption.consumed_at, "consumed_at")
        expected_id = (
            "AEC-"
            + _canonical_sha256(
                {
                    "domain": "sunderkey.action-admission-execution-consumption.v1",
                    "execution_id": consumption.execution_id,
                    "execution_intent_sha256": consumption.execution_intent_sha256,
                    "claim_id": consumption.claim_id,
                    "claim_sha256": consumption.claim_sha256,
                    "receipt_id": consumption.receipt_id,
                    "receipt_sha256": consumption.receipt_sha256,
                }
            )
            .removeprefix("sha256:")[:32]
            .upper()
        )
        if consumption.consumption_id != expected_id:
            raise StoreIntegrityError("Execution consumption identity is invalid")
        return consumption

    @staticmethod
    def _verify_revocation_link(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        revocation: ActionAdmissionRevocation,
        receipt: AuthenticatedActionAdmissionReceipt,
    ) -> None:
        document = revocation.to_dict()
        authorization = revocation.to_dict()["control_authorization"]
        receipt_document = receipt.to_dict()
        expected_receipt_bindings = {
            "receipt_id": receipt.receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "resolution_id": receipt_document["resolution_id"],
            "resolution_sha256": receipt_document["resolution_sha256"],
            "tenant_id": receipt_document["tenant_id"],
            "mission_id": receipt_document["mission_id"],
            "scope_sha256": receipt_document["scope_sha256"],
            "target_sha256": receipt_document["target_sha256"],
            "action_sha256": receipt_document["action_sha256"],
            "action_tier": receipt_document["action_tier"],
        }
        expected_intent = revocation_authorization_intent_sha256(
            receipt,
            reason_code=document["reason_code"],
            revoked_at=document["revoked_at"],
        )
        historical_control = _historical_collaboration_role_principal(
            connection,
            mission_id=receipt_document["mission_id"],
            plan_id=None,
            role="independent_control",
            effective_at=document["revoked_at"],
        )
        if (
            any(document[field] != value for field, value in expected_receipt_bindings.items())
            or authorization["operation_intent_sha256"] != expected_intent
            or authorization["assertion_issuer"]
            != historical_control["assertion_issuer"]
            or authorization["principal_profile_id"]
            != historical_control["principal_profile_id"]
            or authorization["principal_subject"]
            != historical_control["principal_subject"]
            or row["receipt_id"] != receipt.receipt_id
            or row["mission_id"] != receipt_document["mission_id"]
        ):
            raise StoreIntegrityError(
                "Action revocation differs from its admission receipt"
            )
        replay = connection.execute(
            """
            SELECT * FROM action_admission_replay_uses
            WHERE canonical_replay_key_sha256 = ?
            """,
            (authorization["canonical_replay_key_sha256"],),
        ).fetchone()
        central = connection.execute(
            """
            SELECT * FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
            """,
            (
                row["assertion_issuer"],
                row["assertion_id"],
                row["mission_id"],
            ),
        ).fetchone()
        effect = connection.execute(
            """
            SELECT * FROM principal_assertion_effects
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?
              AND effect_kind = ? AND effect_id = ?
            """,
            (
                row["assertion_issuer"],
                row["assertion_id"],
                row["mission_id"],
                ACTION_REVOKE_OPERATION,
                row["assertion_id"],
            ),
        ).fetchone()
        effect_json = _canonical_json(
            _action_principal_effect(
                operation=ACTION_REVOKE_OPERATION,
                effect_id=authorization["assertion_id"],
                payload=authorization,
                recorded_at=str(row["revoked_at"]),
            )
        )
        effect_sha = sha256_text(effect_json)
        local_use = connection.execute(
            """
            SELECT 1 FROM action_admission_assertion_uses
            WHERE assertion_issuer = ? AND assertion_id = ?
            """,
            (row["assertion_issuer"], row["assertion_id"]),
        ).fetchone()
        if (
            replay is None
            or central is None
            or effect is None
            or local_use is not None
            or replay["operation"] != ACTION_REVOKE_OPERATION
            or replay["assertion_issuer"] != row["assertion_issuer"]
            or replay["assertion_id"] != row["assertion_id"]
            or replay["result_kind"] != "action_admission_revocation"
            or replay["operation_intent_sha256"] != authorization["operation_intent_sha256"]
            or replay["result_id"] != authorization["assertion_id"]
            or replay["result_sha256"] != authorization["assertion_sha256"]
            or replay["consumed_at"] != row["revoked_at"]
            or central["assertion_hash"] != authorization["assertion_sha256"]
            or central["domain_request_hash"] != authorization["operation_intent_sha256"]
            or central["idempotency_key_hash"] != authorization["canonical_replay_key_sha256"]
            or central["consumed_at"] != row["revoked_at"]
            or effect["effect_json"] != effect_json
            or effect["effect_hash"] != effect_sha
            or effect["recorded_at"] != row["revoked_at"]
            or central["effects_hash"] != principal_assertion_effects_hash((effect_sha,))
        ):
            raise StoreIntegrityError("Action revocation replay custody is invalid")


def _verify_historical_admission_roles(
    connection: sqlite3.Connection,
    stored: StoredActionAdmission,
) -> None:
    receipt = stored.receipt.to_dict()
    resolution = stored.resolution.to_dict()
    evaluated_at = receipt["evaluated_at"]
    bundle_rows = connection.execute(
        "SELECT bundle_json FROM action_authority_source_bundles "
        "WHERE source_bundle_sha256 = ?",
        (stored.authority_state.authority_revision_sha256,),
    ).fetchall()
    if len(bundle_rows) != 1 or type(bundle_rows[0]["bundle_json"]) is not str:
        raise StoreIntegrityError("Historical action source bundle is unavailable")
    try:
        bundle = ExactActionSourceHeadBundle.from_dict(
            json.loads(bundle_rows[0]["bundle_json"])
        ).to_dict()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Historical action source bundle is invalid") from exc
    publication_rows = connection.execute(
        """
        SELECT publication_id, publication_sha256, source_bundle_id,
               source_bundle_sha256, material_snapshot_id,
               material_snapshot_sha256, published_at
        FROM action_authority_publications
        WHERE mission_id = ? AND source_bundle_id = ?
          AND source_bundle_sha256 = ?
        """,
        (
            receipt["mission_id"],
            bundle["source_bundle_id"],
            bundle["source_bundle_sha256"],
        ),
    ).fetchall()
    if len(publication_rows) != 1:
        raise StoreIntegrityError("Historical action source publication is unavailable")
    publication = publication_rows[0]
    if any(type(publication[field]) is not str for field in tuple(publication.keys())):
        raise StoreIntegrityError("Historical action source publication type is invalid")
    material_rows = connection.execute(
        """
        SELECT material_json FROM action_authority_material_snapshots
        WHERE material_snapshot_id = ? AND material_snapshot_sha256 = ?
        """,
        (
            publication["material_snapshot_id"],
            publication["material_snapshot_sha256"],
        ),
    ).fetchall()
    if len(material_rows) != 1 or type(material_rows[0]["material_json"]) is not str:
        raise StoreIntegrityError("Historical action material is unavailable")
    try:
        material = ActionAuthorityMaterialSnapshot.from_dict(
            json.loads(material_rows[0]["material_json"])
        ).to_dict()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Historical action material is invalid") from exc
    latest_publication = connection.execute(
        """
        SELECT publication_id, publication_sha256
        FROM action_authority_publications
        WHERE mission_id = ? AND published_at <= ?
        ORDER BY published_at DESC, publication_id DESC LIMIT 1
        """,
        (receipt["mission_id"], evaluated_at),
    ).fetchone()
    evaluated = parse_timestamp(evaluated_at, "historical admission evaluated_at")
    if (
        latest_publication is None
        or latest_publication["publication_id"] != publication["publication_id"]
        or latest_publication["publication_sha256"] != publication["publication_sha256"]
        or parse_timestamp(
            publication["published_at"], "historical action publication published_at"
        )
        > evaluated
        or not (
            parse_timestamp(bundle["observed_at"], "historical bundle observed_at")
            <= evaluated
            < parse_timestamp(bundle["valid_until"], "historical bundle valid_until")
        )
        or not (
            parse_timestamp(material["observed_at"], "historical material observed_at")
            <= evaluated
            < parse_timestamp(material["valid_until"], "historical material valid_until")
        )
    ):
        raise StoreIntegrityError("Historical action source chronology is invalid")
    proposal_rows = connection.execute(
        "SELECT proposal_json FROM action_authority_proposal_imports "
        "WHERE proposal_import_id = ? AND proposal_import_sha256 = ?",
        (bundle["proposal_import_id"], bundle["proposal_import_sha256"]),
    ).fetchall()
    if len(proposal_rows) != 1 or type(proposal_rows[0]["proposal_json"]) is not str:
        raise StoreIntegrityError("Historical action proposal import is unavailable")
    try:
        proposal = AuthenticatedProposalMaterialImport.from_dict(
            json.loads(proposal_rows[0]["proposal_json"])
        ).to_dict()
        catalog = parse_executable_action_catalog(material["catalog"])
        parameters = parse_action_parameter_set(material["parameters"], catalog)
        target = parse_target_action_descriptor(material["target"])
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Historical action material chain is invalid") from exc
    request = stored.request.to_dict()
    quorum = stored.quorum.to_dict()
    catalog_document = catalog.to_dict()
    target_document = target.to_dict()
    snapshot = stored.review_records.snapshot.to_dict()
    closure = stored.review_records.closure.to_dict()
    reviewed_product = proposal["reviewed_product"]
    high_water = connection.execute(
        "SELECT high_water_sha256 FROM action_admission_workspace_high_waters "
        "WHERE receipt_id = ?",
        (stored.receipt.receipt_id,),
    ).fetchone()
    if (
        high_water is None
        or type(high_water["high_water_sha256"]) is not str
        or high_water["high_water_sha256"] != bundle["workspace_high_water_sha256"]
        or material["tenant_id"] != receipt["tenant_id"]
        or material["mission_id"] != receipt["mission_id"]
        or material["plan_id"] != resolution["plan_id"]
        or material["proposal_import_id"] != proposal["proposal_import_id"]
        or material["proposal_import_sha256"] != proposal["proposal_import_sha256"]
        or reviewed_product["product_id"] != resolution["proposal_product_id"]
        or reviewed_product["product_sha256"]
        != resolution["proposal_product_sha256"]
        or proposal["review_snapshot_id"] != resolution["review_snapshot_id"]
        or proposal["review_snapshot_sha256"]
        != resolution["review_snapshot_sha256"]
        or proposal["review_closure_id"] != resolution["review_closure_id"]
        or proposal["review_closure_sha256"]
        != resolution["review_closure_sha256"]
        or snapshot["snapshot_id"] != proposal["review_snapshot_id"]
        or snapshot["snapshot_sha256"] != proposal["review_snapshot_sha256"]
        or closure["closure_id"] != proposal["review_closure_id"]
        or closure["closure_sha256"] != proposal["review_closure_sha256"]
        or catalog.catalog_id != resolution["catalog_id"]
        or catalog.catalog_sha256 != resolution["catalog_sha256"]
        or catalog_document["catalog_version"] != resolution["catalog_version"]
        or stored.authority_state.catalog_id != catalog.catalog_id
        or stored.authority_state.catalog_sha256 != catalog.catalog_sha256
        or stored.authority_state.catalog_version
        != catalog_document["catalog_version"]
        or stored.authority_state.catalog_authority_sha256
        != bundle["catalog_revision_sha256"]
        or stored.authority_state.authority_revision_sha256
        != bundle["source_bundle_sha256"]
        or parameters.parameter_set_id != resolution["parameter_set_id"]
        or parameters.parameter_set_sha256 != resolution["parameter_set_sha256"]
        or target.descriptor_id != resolution["target_descriptor_id"]
        or target.descriptor_sha256 != resolution["target_descriptor_sha256"]
        or target_document["target_sha256"] != resolution["target_sha256"]
        or material["resolver_profile_id"] != resolution["resolver_profile_id"]
        or material["resolver_subject"] != resolution["resolver_subject"]
        or material["resolved_at"] != resolution["resolved_at"]
        or material["approved_at"] != quorum["approved_at"]
        or material["quorum_expires_at"] != quorum["expires_at"]
        or material["requested_at"] != request["requested_at"]
        or material["expires_at"] != request["expires_at"]
        or material["context"] != request["context"]
        or material["worker_session"] != request["worker_session"]
        or material["credential_lease"] != request["credential_lease"]
        or material["health"] != request["health"]
        or material["evidence_obligations"] != request["evidence_obligations"]
        or material["stop_conditions"] != request["stop_conditions"]
        or material["restoration_duties"] != request["restoration_duties"]
    ):
        raise StoreIntegrityError("Historical action material binding is invalid")
    budget_rows = connection.execute(
        "SELECT record_json FROM action_authority_revisions "
        "WHERE record_kind = 'action_budget_policy_revision' "
        "AND record_id = ? AND record_sha256 = ?",
        (bundle["budget_revision_id"], bundle["budget_revision_sha256"]),
    ).fetchall()
    reservation = connection.execute(
        """
        SELECT link.*, event.event_sequence
        FROM action_budget_receipt_reservations AS link
        JOIN action_budget_account_events AS event
          ON event.event_id = link.reserve_event_id
         AND event.event_sha256 = link.reserve_event_sha256
        WHERE link.receipt_id = ?
        """,
        (stored.receipt.receipt_id,),
    ).fetchone()
    if (
        len(budget_rows) != 1
        or type(budget_rows[0]["record_json"]) is not str
        or reservation is None
        or type(reservation["event_sequence"]) is not int
    ):
        raise StoreIntegrityError("Historical action budget source is unavailable")
    try:
        budget_policy = ActionBudgetPolicyRevision.from_dict(
            json.loads(budget_rows[0]["record_json"])
        ).to_dict()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Historical action budget source is invalid") from exc
    usage = {field: 0 for field in RESOURCE_FIELDS}
    for event in connection.execute(
        "SELECT event_kind, resources_json FROM action_budget_account_events "
        "WHERE account_id = ? AND event_sequence < ? ORDER BY event_sequence",
        (reservation["account_id"], reservation["event_sequence"]),
    ).fetchall():
        if type(event["resources_json"]) is not str:
            raise StoreIntegrityError("Historical action budget event type is invalid")
        resources = json.loads(event["resources_json"])
        if set(resources) != set(RESOURCE_FIELDS) or any(
            type(resources[field]) is not int for field in RESOURCE_FIELDS
        ):
            raise StoreIntegrityError("Historical action budget event is invalid")
        if event["event_kind"] == "reserve":
            for field in RESOURCE_FIELDS:
                usage[field] += resources[field]
        elif event["event_kind"] == "release":
            for field in RESOURCE_FIELDS:
                usage[field] -= resources[field]
        elif event["event_kind"] != "settle":
            raise StoreIntegrityError("Historical action budget event kind is invalid")
    limits = budget_policy["limits"]
    ceiling = budget_policy["per_action_ceiling"]
    historical_budget = BudgetBinding(
        tenant_id=receipt["tenant_id"],
        mission_id=receipt["mission_id"],
        budget_sha256=budget_policy["budget_revision_sha256"],
        request_limit=limits["rate_units"],
        requests_used=usage["rate_units"],
        token_limit=limits["request_bytes"] + limits["response_bytes"],
        tokens_used=usage["request_bytes"] + usage["response_bytes"],
        cost_limit_microunits=limits["money_microunits"],
        cost_used_microunits=usage["money_microunits"],
        action_request_cost=ceiling["rate_units"],
        action_token_cost=ceiling["request_bytes"] + ceiling["response_bytes"],
        action_cost_microunits=ceiling["money_microunits"],
    ).to_dict()
    if request["budget"] != historical_budget:
        raise StoreIntegrityError("Historical action budget binding is invalid")
    policy_rows = connection.execute(
        """
        SELECT record_json FROM action_authority_revisions
        WHERE record_kind = 'action_authority_policy_revision'
          AND record_id = ? AND record_sha256 = ?
        """,
        (
            bundle["action_authority_policy_revision_id"],
            bundle["action_authority_policy_revision_sha256"],
        ),
    ).fetchall()
    if len(policy_rows) != 1 or type(policy_rows[0]["record_json"]) is not str:
        raise StoreIntegrityError("Historical action authority policy is unavailable")
    try:
        action_policy = ActionAuthorityPolicyRevision.from_dict(
            json.loads(policy_rows[0]["record_json"])
        ).to_dict()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise StoreIntegrityError("Historical action authority policy is invalid") from exc
    if (
        bundle["tenant_id"] != receipt["tenant_id"]
        or bundle["mission_id"] != receipt["mission_id"]
        or bundle["plan_id"] != resolution["plan_id"]
        or action_policy["tenant_id"] != receipt["tenant_id"]
        or action_policy["mission_id"] != receipt["mission_id"]
        or action_policy["plan_id"] != resolution["plan_id"]
        or not (
            parse_timestamp(
                action_policy["effective_at"],
                "historical action authority policy effective_at",
            )
            <= evaluated
            < parse_timestamp(
                action_policy["expires_at"],
                "historical action authority policy expires_at",
            )
        )
    ):
        raise StoreIntegrityError("Historical action authority policy binding is invalid")

    def require_exact(
        authorization: Mapping[str, Any],
        expected: Mapping[str, Any],
        label: str,
    ) -> None:
        if (
            authorization["assertion_issuer"] != expected["assertion_issuer"]
            or authorization["principal_profile_id"]
            != expected["principal_profile_id"]
            or authorization["principal_subject"] != expected["principal_subject"]
        ):
            raise StoreIntegrityError(
                f"Historical {label} principal assignment is invalid"
            )

    require_exact(
        stored.resolver_authorization,
        action_policy["typed_resolver"],
        "typed resolver",
    )
    require_exact(
        receipt["admission_authorization"],
        action_policy["admission_control"],
        "admission Control",
    )
    for approval in stored.quorum.to_dict()["approvals"]:
        role = approval["role"]
        if role not in {"mission_owner", "independent_control"}:
            raise StoreIntegrityError("Historical action quorum role is invalid")
        expected = _historical_collaboration_role_principal(
            connection,
            mission_id=receipt["mission_id"],
            plan_id=resolution["plan_id"],
            role=role,
            effective_at=evaluated_at,
        )
        require_exact(approval, expected, role.replace("_", " "))


def verify_authenticated_action_admission_store(
    connection: sqlite3.Connection,
    *,
    mission_id: str | None = None,
) -> None:
    """Verify canonical action admission, replay, budget, and central links."""

    where = "" if mission_id is None else " WHERE mission_id = ?"
    parameters: tuple[Any, ...] = () if mission_id is None else (mission_id,)
    rows = connection.execute(
        "SELECT * FROM action_admission_receipts" + where + " ORDER BY receipt_id",
        parameters,
    ).fetchall()
    reader = object.__new__(AuthenticatedActionAdmissionService)
    receipt_ids: set[str] = set()
    receipt_documents: dict[str, dict[str, Any]] = {}
    receipt_records: dict[str, AuthenticatedActionAdmissionReceipt] = {}
    assertion_count = 0
    for row in rows:
        stored = reader._stored_from_row(connection, row)
        receipt_ids.add(stored.receipt.receipt_id)
        receipt_documents[stored.receipt.receipt_id] = stored.receipt.to_dict()
        receipt_records[stored.receipt.receipt_id] = stored.receipt
        high_waters = connection.execute(
            "SELECT * FROM action_admission_workspace_high_waters WHERE receipt_id = ?",
            (stored.receipt.receipt_id,),
        ).fetchall()
        if len(high_waters) != 1:
            raise StoreIntegrityError("Action workspace high-water custody is incomplete")
        high_water = high_waters[0]
        high_water_body = {
            field: high_water[field]
            for field in (
                "application_id",
                "application_sha256",
                "closure_id",
                "closure_sha256",
                "event_count",
                "event_head_occurred_at",
                "event_head_sha256",
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
            )
        }
        high_water_sha256 = _canonical_sha256(
            {
                "domain": "sunderkey.action-workspace-high-water.v1",
                "high_water": high_water_body,
            }
        )
        high_water_id = "AWH-" + high_water_sha256.removeprefix("sha256:")[:32].upper()
        resolution_document = stored.resolution.to_dict()
        snapshot_document = stored.review_records.snapshot.to_dict()
        if (
            high_water["high_water_id"] != high_water_id
            or high_water["high_water_sha256"] != high_water_sha256
            or high_water["mission_id"] != resolution_document["mission_id"]
            or high_water["workspace_id"] != snapshot_document["workspace_id"]
            or high_water["snapshot_id"] != resolution_document["review_snapshot_id"]
            or high_water["snapshot_sha256"] != resolution_document["review_snapshot_sha256"]
            or high_water["closure_id"] != resolution_document["review_closure_id"]
            or high_water["closure_sha256"] != resolution_document["review_closure_sha256"]
            or high_water["state"] != "closure_applied_unrevoked"
            or high_water["revocation_id"] is not None
            or high_water["revocation_sha256"] is not None
            or high_water["imported_at"] != row["created_at"]
        ):
            raise StoreIntegrityError("Action workspace high-water is inconsistent")
        MissionStoreAuthenticatedActionAdmissionService._verify_central_receipt(
            reader,
            connection,
            stored,
        )
        _verify_historical_admission_roles(connection, stored)
        assertion_count += len(stored.quorum.to_dict()["approvals"]) + 2
    revocation_where = "" if mission_id is None else " WHERE mission_id = ?"
    high_water_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM action_admission_workspace_high_waters" + revocation_where,
            parameters,
        ).fetchone()[0]
    )
    if high_water_count != len(rows):
        raise StoreIntegrityError("Action workspace high-water count is inconsistent")
    revocations = connection.execute(
        "SELECT * FROM action_admission_revocations" + revocation_where + " ORDER BY revocation_id",
        parameters,
    ).fetchall()
    for row in revocations:
        if row["receipt_id"] not in receipt_ids and mission_id is not None:
            raise StoreIntegrityError("Action revocation crosses mission custody")
        revocation = MissionStoreAuthenticatedActionAdmissionService._parse_revocation_row(row)
        receipt_document = receipt_documents.get(str(row["receipt_id"]))
        if receipt_document is None or row["revoked_at"] <= receipt_document["evaluated_at"]:
            raise StoreIntegrityError("Action revocation chronology is invalid")
        MissionStoreAuthenticatedActionAdmissionService._verify_revocation_link(
            connection,
            row,
            revocation,
            receipt_records[str(row["receipt_id"])],
        )
    consumption_where = (
        ""
        if mission_id is None
        else (
            " WHERE receipt_id IN ("
            "SELECT receipt_id FROM action_admission_receipts WHERE mission_id = ?)"
        )
    )
    consumptions = connection.execute(
        "SELECT * FROM action_admission_execution_consumptions"
        + consumption_where
        + " ORDER BY consumption_id",
        parameters,
    ).fetchall()
    for row in consumptions:
        consumption = MissionStoreAuthenticatedActionAdmissionService._parse_execution_consumption(
            row
        )
        receipt = connection.execute(
            """
            SELECT receipt_sha256, custody_sha256
            FROM action_admission_receipts WHERE receipt_id = ?
            """,
            (consumption.receipt_id,),
        ).fetchone()
        if (
            receipt is None
            or receipt["receipt_sha256"] != consumption.receipt_sha256
            or receipt["custody_sha256"] != consumption.custody_sha256
        ):
            raise StoreIntegrityError("Execution consumption differs from admission custody")
        receipt_document = receipt_documents.get(consumption.receipt_id)
        revocation = connection.execute(
            "SELECT revoked_at FROM action_admission_revocations WHERE receipt_id = ?",
            (consumption.receipt_id,),
        ).fetchone()
        if (
            receipt_document is None
            or consumption.consumed_at < receipt_document["evaluated_at"]
            or (revocation is not None and consumption.consumed_at >= str(revocation["revoked_at"]))
        ):
            raise StoreIntegrityError("Execution consumption chronology is invalid")
    replay_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM action_admission_replay_uses"
            + where.replace("mission_id", "mission_id"),
            parameters,
        ).fetchone()[0]
    )
    if replay_count != assertion_count + len(revocations):
        raise StoreIntegrityError("Action admission replay count is inconsistent")
    orphan_uses = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM principal_assertion_uses AS use
            WHERE use.operation IN (?, ?, ?, ?)
              AND NOT EXISTS (
                SELECT 1 FROM action_admission_replay_uses AS replay
                WHERE replay.assertion_issuer = use.issuer
                  AND replay.assertion_id = use.assertion_id
                  AND replay.mission_id = use.mission_id
              )
            """
            + (" AND use.mission_id = ?" if mission_id is not None else ""),
            (*sorted(ACTION_OPERATIONS), *parameters),
        ).fetchone()[0]
    )
    if orphan_uses:
        raise StoreIntegrityError("Orphaned central action assertion use exists")


__all__ = [
    "ActionAdmissionExecutionConsumption",
    "ACTION_ADMIT_OPERATION",
    "ACTION_OPERATIONS",
    "ACTION_QUORUM_OPERATION",
    "ACTION_RESOLVE_OPERATION",
    "ACTION_REVOKE_OPERATION",
    "MissionStoreAuthenticatedActionAdmissionService",
    "MissionStoreActionAuthority",
    "MissionStoreActionPrincipalCustody",
    "verify_authenticated_action_admission_store",
]
