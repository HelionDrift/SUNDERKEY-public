"""Durable integrity checks for authenticated expert review custody."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .collaboration import CollaborationPlan
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .expert_review import (
    AuthenticatedExpertReviewReceipt,
    ClosureDisposition,
    ExpertReviewClosureCertificate,
    ExpertReviewClosureRequest,
    ExpertReviewClosureRevocation,
    ExpertReviewReconciliationReport,
    ExpertReviewRecordSet,
    ExpertReviewSnapshot,
    ExpertReviewSubmission,
    ExpertWorkspaceClosureApplication,
    ReconciliationStatus,
    ReviewDecision,
    ReviewerRole,
    build_authenticated_expert_review_receipt,
    build_expert_review_closure_certificate,
    build_expert_review_closure_revocation,
    derive_reviewer_role,
    parse_authenticated_expert_review_receipt,
    parse_expert_review_closure_certificate,
    parse_expert_review_closure_request,
    parse_expert_review_closure_revocation,
    parse_expert_review_snapshot,
    parse_expert_review_submission,
    parse_expert_workspace_closure_application,
    review_set_sha256,
    verify_expert_review_record_set,
)
from .expert_runtime import RuntimePackCatalog
from .expert_workspace import (
    ExpertWorkspaceStoreAdapter,
    ExpertWorkspaceVerificationReport,
    _catalog_document,
)
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    VerifiedPrincipal,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
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
from .validation import DuplicateJsonKeyError, is_ascii_text, loads_json_without_duplicate_keys

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}\Z")
_REGISTRATION_DOMAIN = "sunderkey.authenticated-expert-review-registration.v1"
_REPLAY_DOMAIN = "sunderkey.authenticated-expert-review-replay.v1"
_REQUEST_DOMAIN = "sunderkey.authenticated-expert-review-request.v1"


def _canonical_sha256(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _exact_integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 2**63 - 1:
        raise StoreError(f"{label} is invalid")
    return value


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StoreError("Authenticated expert review clock must return an aware datetime")
    return value.astimezone(UTC)


def _epoch_seconds(value: datetime) -> int:
    result = int(value.timestamp())
    if result < 0:
        raise StoreError("Authenticated expert review time precedes the Unix epoch")
    return result


def _addressed_registration(body: Mapping[str, Any]) -> dict[str, Any]:
    digest = _canonical_sha256({"domain": _REGISTRATION_DOMAIN, "registration": body})
    return {
        **body,
        "registration_id": "ERRG-" + digest.removeprefix("sha256:")[:32].upper(),
        "registration_sha256": digest,
    }


@dataclass(frozen=True, slots=True)
class AuthenticatedExpertReviewSnapshotRegistration:
    """Portable receipt for one authenticated durable review snapshot registration."""

    document_json: str

    @property
    def registration_id(self) -> str:
        return str(self.to_dict()["registration_id"])

    @property
    def registration_sha256(self) -> str:
        return str(self.to_dict()["registration_sha256"])

    @property
    def snapshot_id(self) -> str:
        return str(self.to_dict()["snapshot_id"])

    @property
    def snapshot_sha256(self) -> str:
        return str(self.to_dict()["snapshot_sha256"])

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> AuthenticatedExpertReviewSnapshotRegistration:
        if not isinstance(raw, Mapping):
            raise StoreError("Authenticated review registration must be an object")
        value = dict(raw)
        fields = {
            "schema_version",
            "kind",
            "registration_id",
            "registration_sha256",
            "snapshot_id",
            "snapshot_sha256",
            "mission_id",
            "tenant_id",
            "active_plan_id",
            "active_plan_sha256",
            "active_plan_version",
            "mission_revision",
            "workspace_id",
            "workspace_sha256",
            "workspace_schema_version",
            "workspace_revision",
            "workspace_event_count",
            "workspace_event_head_sha256",
            "runtime_catalog_id",
            "runtime_catalog_version",
            "runtime_catalog_sha256",
            "registry_sha256",
            "target_scope_sha256",
            "authority_snapshot_sha256",
            "evidence_snapshot_sha256",
            "registrar_profile_id",
            "registrar_subject",
            "assertion_issuer",
            "assertion_id",
            "assertion_sha256",
            "assertion_key_sha256",
            "trust_policy_sha256",
            "scope_grant_sha256",
            "operation_intent_sha256",
            "canonical_replay_key_sha256",
            "domain_request_sha256",
            "registered_at",
            "effects",
        }
        if set(value) != fields:
            raise StoreError("Authenticated review registration fields are invalid")
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["kind"] != "authenticated_expert_review_registration"
        ):
            raise StoreError("Authenticated review registration kind is invalid")
        for field_name in (
            "registration_id",
            "snapshot_id",
            "mission_id",
            "tenant_id",
            "active_plan_id",
            "workspace_id",
            "runtime_catalog_id",
            "runtime_catalog_version",
            "registrar_profile_id",
            "registrar_subject",
            "assertion_issuer",
            "assertion_id",
        ):
            _identifier(value[field_name], field_name)
        for field_name in (
            "registration_sha256",
            "snapshot_sha256",
            "active_plan_sha256",
            "workspace_sha256",
            "workspace_event_head_sha256",
            "runtime_catalog_sha256",
            "registry_sha256",
            "target_scope_sha256",
            "authority_snapshot_sha256",
            "evidence_snapshot_sha256",
            "assertion_sha256",
            "assertion_key_sha256",
            "trust_policy_sha256",
            "scope_grant_sha256",
            "operation_intent_sha256",
            "canonical_replay_key_sha256",
            "domain_request_sha256",
        ):
            _digest(value[field_name], field_name)
        for field_name, minimum in (
            ("active_plan_version", 1),
            ("mission_revision", 0),
            ("workspace_schema_version", 1),
            ("workspace_revision", 0),
            ("workspace_event_count", 1),
            ("registered_at", 0),
        ):
            _exact_integer(value[field_name], field_name, minimum)
        if value["registrar_subject"] == value["assertion_issuer"]:
            raise StoreError("Registration assertion issuer and subject must differ")
        expected_effects = {
            "authorization_effect": "none",
            "model_call_performed": False,
            "network_call_performed": False,
            "qualification_effect": "none",
            "target_action_performed": False,
            "tool_effect": "none",
        }
        effects = value["effects"]
        if (
            type(effects) is not dict
            or set(effects) != set(expected_effects)
            or any(
                type(effects[key]) is not type(expected) or effects[key] != expected
                for key, expected in expected_effects.items()
            )
        ):
            raise StoreError("Authenticated review registration effects are invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"registration_id", "registration_sha256"}
        }
        addressed = _addressed_registration(body)
        if (
            value["registration_id"] != addressed["registration_id"]
            or value["registration_sha256"] != addressed["registration_sha256"]
        ):
            raise StoreError("Authenticated review registration identity is invalid")
        return cls(canonical_json(value))


def build_authenticated_expert_review_snapshot_registration(
    *,
    snapshot: ExpertReviewSnapshot,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
    registrar_profile_id: str,
    registrar_subject: str,
    assertion_issuer: str,
    assertion_id: str,
    assertion_sha256: str,
    assertion_key_sha256: str,
    trust_policy_sha256: str,
    scope_grant_sha256: str,
    operation_intent_sha256: str,
    canonical_replay_key_sha256: str,
    domain_request_sha256: str,
    registered_at: int,
) -> AuthenticatedExpertReviewSnapshotRegistration:
    if type(snapshot) is not ExpertReviewSnapshot:
        raise StoreError("A validated expert review snapshot is required")
    document = snapshot.to_dict()
    body = {
        "schema_version": 1,
        "kind": "authenticated_expert_review_registration",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "mission_id": document["mission_id"],
        "tenant_id": document["tenant_id"],
        "active_plan_id": document["plan_id"],
        "active_plan_sha256": active_plan_sha256,
        "active_plan_version": active_plan_version,
        "mission_revision": mission_revision,
        "workspace_id": document["workspace_id"],
        "workspace_sha256": document["workspace_sha256"],
        "workspace_schema_version": document["workspace_schema_version"],
        "workspace_revision": document["workspace_revision"],
        "workspace_event_count": document["event_count"],
        "workspace_event_head_sha256": document["event_head_sha256"],
        "runtime_catalog_id": document["runtime_catalog_id"],
        "runtime_catalog_version": document["runtime_catalog_version"],
        "runtime_catalog_sha256": document["runtime_catalog_sha256"],
        "registry_sha256": document["registry_sha256"],
        "target_scope_sha256": document["target_scope_sha256"],
        "authority_snapshot_sha256": document["authority_snapshot_sha256"],
        "evidence_snapshot_sha256": document["evidence_snapshot_sha256"],
        "registrar_profile_id": registrar_profile_id,
        "registrar_subject": registrar_subject,
        "assertion_issuer": assertion_issuer,
        "assertion_id": assertion_id,
        "assertion_sha256": assertion_sha256,
        "assertion_key_sha256": assertion_key_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "scope_grant_sha256": scope_grant_sha256,
        "operation_intent_sha256": operation_intent_sha256,
        "canonical_replay_key_sha256": canonical_replay_key_sha256,
        "domain_request_sha256": domain_request_sha256,
        "registered_at": registered_at,
        "effects": {
            "authorization_effect": "none",
            "model_call_performed": False,
            "network_call_performed": False,
            "qualification_effect": "none",
            "target_action_performed": False,
            "tool_effect": "none",
        },
    }
    return AuthenticatedExpertReviewSnapshotRegistration.from_dict(_addressed_registration(body))


def expert_review_snapshot_registration_intent(
    snapshot: ExpertReviewSnapshot,
    *,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
    principal_profile_id: str,
) -> dict[str, Any]:
    document = parse_expert_review_snapshot(snapshot.to_dict()).to_dict()
    return {
        "active_plan_id": document["plan_id"],
        "active_plan_sha256": _digest(active_plan_sha256, "active_plan_sha256"),
        "active_plan_version": _exact_integer(active_plan_version, "active_plan_version", 1),
        "mission_id": document["mission_id"],
        "mission_revision": _exact_integer(mission_revision, "mission_revision"),
        "principal_profile_id": _identifier(principal_profile_id, "principal_profile_id"),
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "workspace_event_count": document["event_count"],
        "workspace_event_head_sha256": document["event_head_sha256"],
        "workspace_id": document["workspace_id"],
        "workspace_revision": document["workspace_revision"],
        "workspace_schema_version": document["workspace_schema_version"],
        "workspace_sha256": document["workspace_sha256"],
    }


def expert_work_product_review_intent(
    snapshot: ExpertReviewSnapshot,
    submission: ExpertReviewSubmission,
    *,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
    principal_profile_id: str,
) -> dict[str, Any]:
    snapshot_document = parse_expert_review_snapshot(snapshot.to_dict()).to_dict()
    submission_document = parse_expert_review_submission(submission.to_dict()).to_dict()
    return {
        "active_plan_id": snapshot_document["plan_id"],
        "active_plan_sha256": _digest(active_plan_sha256, "active_plan_sha256"),
        "active_plan_version": _exact_integer(active_plan_version, "active_plan_version", 1),
        "mission_id": snapshot_document["mission_id"],
        "mission_revision": _exact_integer(mission_revision, "mission_revision"),
        "principal_profile_id": _identifier(principal_profile_id, "principal_profile_id"),
        "product_id": submission_document["product_id"],
        "product_sha256": submission_document["product_sha256"],
        "reviewer_role": submission_document["reviewer_role"],
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "submission_id": submission.submission_id,
        "submission_sha256": submission.submission_sha256,
        "work_id": submission_document["work_id"],
    }


def expert_workspace_review_close_intent(
    snapshot: ExpertReviewSnapshot,
    request: ExpertReviewClosureRequest,
    receipts: Sequence[AuthenticatedExpertReviewReceipt],
    *,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
    principal_profile_id: str,
) -> dict[str, Any]:
    snapshot_document = parse_expert_review_snapshot(snapshot.to_dict()).to_dict()
    request_document = parse_expert_review_closure_request(request.to_dict()).to_dict()
    return {
        "active_plan_id": snapshot_document["plan_id"],
        "active_plan_sha256": _digest(active_plan_sha256, "active_plan_sha256"),
        "active_plan_version": _exact_integer(active_plan_version, "active_plan_version", 1),
        "closure_request_id": request.closure_request_id,
        "closure_request_sha256": request.closure_request_sha256,
        "expected_disposition": request_document["expected_disposition"],
        "mission_id": snapshot_document["mission_id"],
        "mission_revision": _exact_integer(mission_revision, "mission_revision"),
        "principal_profile_id": _identifier(principal_profile_id, "principal_profile_id"),
        "review_set_sha256": review_set_sha256(receipts),
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
    }


def expert_workspace_review_revoke_intent(
    closure: ExpertReviewClosureCertificate,
    *,
    active_plan_id: str,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_id: str,
    mission_revision: int,
    principal_profile_id: str,
    reason_code: str,
) -> dict[str, Any]:
    core = {
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "reason_code": _identifier(reason_code, "reason_code"),
    }
    return {
        "active_plan_id": _identifier(active_plan_id, "active_plan_id"),
        "active_plan_sha256": _digest(active_plan_sha256, "active_plan_sha256"),
        "active_plan_version": _exact_integer(active_plan_version, "active_plan_version", 1),
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "mission_id": _identifier(mission_id, "mission_id"),
        "mission_revision": _exact_integer(mission_revision, "mission_revision"),
        "principal_profile_id": _identifier(principal_profile_id, "principal_profile_id"),
        "reason_code": core["reason_code"],
        "revocation_core_sha256": _canonical_sha256(
            {"domain": "sunderkey.expert-review-revocation-core.v1", "core": core}
        ),
    }


def expert_review_canonical_replay_key_sha256(
    assertion: PrincipalAssertion,
    *,
    operation: PrincipalOperation,
    operation_intent_sha256: str,
    domain_request_sha256: str,
) -> str:
    if type(assertion) is not PrincipalAssertion or assertion.operation is not operation:
        raise PrincipalAuthenticationError("Review assertion operation is invalid")
    return _canonical_sha256(
        {
            "assertion_id": assertion.assertion_id,
            "assertion_issuer": assertion.issuer,
            "assertion_sha256": assertion.content_sha256,
            "domain": _REPLAY_DOMAIN,
            "domain_request_sha256": _digest(domain_request_sha256, "domain_request_sha256"),
            "operation": operation.value,
            "operation_intent_sha256": _digest(operation_intent_sha256, "operation_intent_sha256"),
            "schema_version": 1,
        }
    )


def _record_set_proof_sha256(records: ExpertReviewRecordSet) -> str:
    return _canonical_sha256(
        {
            "closure": records.closure.to_dict(),
            "closure_request": records.closure_request.to_dict(),
            "receipts": [item.to_dict() for item in records.receipts],
            "revocation": None if records.revocation is None else records.revocation.to_dict(),
            "snapshot": records.snapshot.to_dict(),
        }
    )


def _proof_material(
    records: ExpertReviewRecordSet,
    mission_store_id: str,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
) -> bytes:
    return canonical_json(
        {
            "active_plan_sha256": active_plan_sha256,
            "active_plan_version": active_plan_version,
            "closure_sha256": records.closure.closure_sha256,
            "mission_revision": mission_revision,
            "mission_store_id": mission_store_id,
            "records_sha256": _record_set_proof_sha256(records),
            "revocation_sha256": (
                None if records.revocation is None else records.revocation.revocation_sha256
            ),
            "snapshot_sha256": records.snapshot.snapshot_sha256,
        }
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class VerifiedExpertReviewClosure:
    """Process-local proof of a fresh durable, nonrevoked expert review closure."""

    records: ExpertReviewRecordSet
    mission_store_id: str
    active_plan_sha256: str
    active_plan_version: int
    mission_revision: int
    _proof: bytes = dataclass_field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class VerifiedExpertReviewRevocation:
    """Process-local proof of a fresh durable closure revocation."""

    records: ExpertReviewRecordSet
    mission_store_id: str
    _proof: bytes = dataclass_field(repr=False, compare=False)


def _revocation_proof_material(
    records: ExpertReviewRecordSet,
    mission_store_id: str,
) -> bytes:
    if records.revocation is None:
        raise StoreIntegrityError("Revocation proof requires a durable revocation")
    return canonical_json(
        {
            "closure_sha256": records.closure.closure_sha256,
            "mission_store_id": mission_store_id,
            "records_sha256": _record_set_proof_sha256(records),
            "revocation_sha256": records.revocation.revocation_sha256,
        }
    ).encode("utf-8")


class SQLiteAuthenticatedExpertReviewCustody:
    """Atomic MissionStore custody for independently reviewed expert work."""

    qualifying = True
    durability = "sqlite_authenticated_atomic_custody"

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if type(registry) is not ExpertRegistry:
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        if not isinstance(workspace_store, ExpertWorkspaceStoreAdapter):
            raise TypeError("workspace_store must implement ExpertWorkspaceStoreAdapter")
        _catalog_document(runtime_catalog)
        self._store = store
        self._registry = registry
        self._workspace_store = workspace_store
        self._runtime_catalog = runtime_catalog
        self.__proof_key = os.urandom(32)
        self.__projection_tokens: dict[bytes, tuple[str, str]] = {}
        self._clock = clock or store._clock
        self._authenticated = AuthenticatedMissionControlService(
            store,
            registry,
            clock=self._clock,
        )

    def _require_trusted_sources(
        self,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> None:
        if workspace_store is not self._workspace_store:
            raise PrincipalAuthenticationError(
                "Workspace adapter is not the custody service authority"
            )
        if runtime_catalog is not self._runtime_catalog:
            raise PrincipalAuthenticationError(
                "Runtime catalog is not the custody service authority"
            )

    def __seal_closure(
        self,
        records: ExpertReviewRecordSet,
        mission_store_id: str,
        active_plan_sha256: str,
        active_plan_version: int,
        mission_revision: int,
    ) -> VerifiedExpertReviewClosure:
        material = _proof_material(
            records,
            mission_store_id,
            active_plan_sha256,
            active_plan_version,
            mission_revision,
        )
        return VerifiedExpertReviewClosure(
            records,
            mission_store_id,
            active_plan_sha256,
            active_plan_version,
            mission_revision,
            hmac.new(self.__proof_key, material, hashlib.sha256).digest(),
        )

    def __seal_revocation(
        self,
        records: ExpertReviewRecordSet,
        mission_store_id: str,
    ) -> VerifiedExpertReviewRevocation:
        material = _revocation_proof_material(records, mission_store_id)
        return VerifiedExpertReviewRevocation(
            records,
            mission_store_id,
            hmac.new(self.__proof_key, material, hashlib.sha256).digest(),
        )

    def validates_closure_proof(self, verified: Any) -> bool:
        """Return whether this custody instance issued the exact closure proof."""

        if type(verified) is not VerifiedExpertReviewClosure or type(verified._proof) is not bytes:
            return False
        expected = hmac.new(
            self.__proof_key,
            _proof_material(
                verified.records,
                verified.mission_store_id,
                verified.active_plan_sha256,
                verified.active_plan_version,
                verified.mission_revision,
            ),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(verified._proof, expected)

    def validates_revocation_proof(self, verified: Any) -> bool:
        """Return whether this custody instance issued the exact revocation proof."""

        if (
            type(verified) is not VerifiedExpertReviewRevocation
            or verified.records.revocation is None
            or type(verified._proof) is not bytes
        ):
            return False
        expected = hmac.new(
            self.__proof_key,
            _revocation_proof_material(verified.records, verified.mission_store_id),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(verified._proof, expected)

    def consume_workspace_projection_authorization(
        self,
        authorization_token: bytes,
        verified: Any,
        operation: str,
    ) -> bool:
        """Consume one token while its issuing MissionStore transaction is active."""

        if type(authorization_token) is not bytes or type(operation) is not str:
            return False
        expected = self.__projection_tokens.pop(authorization_token, None)
        if expected is None:
            return False
        if type(verified) is VerifiedExpertReviewClosure:
            result_id = verified.records.closure.closure_id
            valid = self.validates_closure_proof(verified)
        elif type(verified) is VerifiedExpertReviewRevocation:
            revocation = verified.records.revocation
            result_id = "" if revocation is None else revocation.revocation_id
            valid = self.validates_revocation_proof(verified)
        else:
            return False
        return valid and expected == (operation, result_id)

    def __projection_token(self, operation: str, result_id: str) -> bytes:
        token = os.urandom(32)
        while token in self.__projection_tokens:
            token = os.urandom(32)
        self.__projection_tokens[token] = (operation, result_id)
        return token

    def __discard_projection_token(self, token: bytes) -> None:
        self.__projection_tokens.pop(token, None)

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
        if (
            type(row["plan_json"]) is not str
            or type(row["plan_content_sha256"]) is not str
            or type(row["plan_version"]) is not int
        ):
            raise StoreIntegrityError("Active collaboration plan storage types are invalid")
        try:
            plan = CollaborationPlan.from_dict(loads_json_without_duplicate_keys(row["plan_json"]))
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
        if row is None or type(row["state"]) is not str:
            raise StoreIntegrityError("Mission control state is missing or invalid")
        if row["state"] != "active":
            raise StoreConflictError("Stopped mission cannot change expert review custody")

    def _current_sources(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[sqlite3.Row, dict[str, Any], Any, dict[str, Any], CollaborationPlan, int]:
        identity, policies, mission, scopes = self._authenticated._verified_mission_state(
            connection,
            mission_id,
        )
        self._mission_is_active(connection, mission_id)
        plan, version = self._active_plan(connection, mission_id)
        return identity, policies, mission, scopes, plan, version

    def _verify_principal(
        self,
        connection: sqlite3.Connection,
        *,
        identity: Mapping[str, Any],
        trust_policies: Mapping[str, Any],
        mission: Any,
        scope_grants: Mapping[str, tuple[sqlite3.Row, Any]],
        assertion: PrincipalAssertion,
        operation: PrincipalOperation,
        operation_intent_sha256: str,
        now: datetime,
    ) -> VerifiedPrincipal:
        ledger = connection.execute(
            "SELECT updated_at FROM mission_principal_ledgers WHERE mission_id = ?",
            (assertion.mission_id,),
        ).fetchone()
        if ledger is None or type(ledger["updated_at"]) is not str:
            raise StoreIntegrityError("Mission principal ledger is missing or invalid")
        if parse_timestamp(ledger["updated_at"], "principal ledger time") > now:
            raise PrincipalAuthenticationError("Runtime clock precedes principal ledger")
        current_policy_sha256 = identity["trust_policy_hash"]
        if type(current_policy_sha256) is not str:
            raise StoreConflictError("A current trust policy is required")
        policy = trust_policies.get(current_policy_sha256)
        if policy is None:
            raise StoreIntegrityError("Current trust policy is missing from history")
        if self._store._trust_policy_high_water_at(trust_policies, now).policy_sha256 != (
            policy.policy_sha256
        ):
            raise PrincipalAuthenticationError("Runtime clock precedes the current trust policy")
        scope_entry = scope_grants.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Assertion scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        if type(scope_row["accepted_at"]) is not str:
            raise StoreIntegrityError("Scope grant acceptance time is invalid")
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
            policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=assertion.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            expected_operation=operation,
            clock=lambda: now,
        )
        return verify_principal_assertion(
            assertion,
            policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=assertion.mission_id,
            expected_operation=operation,
            expected_operation_intent_sha256=operation_intent_sha256,
            clock=lambda: now,
        )

    def _workspace_snapshot(
        self,
        workspace_store: ExpertWorkspaceStoreAdapter,
        workspace_id: str,
        runtime_catalog: RuntimePackCatalog,
    ) -> ExpertReviewSnapshot:
        if not isinstance(workspace_store, ExpertWorkspaceStoreAdapter):
            raise TypeError("workspace_store must implement ExpertWorkspaceStoreAdapter")
        _catalog_document(runtime_catalog)
        report = workspace_store.verify_store(
            runtime_catalog,
            expert_registry=self._registry,
        )
        if type(report) is not ExpertWorkspaceVerificationReport or report.status != "valid":
            raise StoreIntegrityError("Expert workspace verification did not succeed")
        snapshot = workspace_store.export_review_snapshot(
            _identifier(workspace_id, "workspace_id"),
            runtime_catalog=runtime_catalog,
            expert_registry=self._registry,
        )
        if type(snapshot) is not ExpertReviewSnapshot:
            raise StoreIntegrityError("Workspace adapter returned an invalid review snapshot")
        return parse_expert_review_snapshot(snapshot.to_dict(), self._registry)

    @staticmethod
    def _domain_request(operation: PrincipalOperation, material: Mapping[str, Any]) -> str:
        return _canonical_sha256(
            {
                "domain": _REQUEST_DOMAIN,
                "operation": operation.value,
                "request": dict(material),
                "schema_version": 1,
            }
        )

    @staticmethod
    def _effect(
        operation: PrincipalOperation,
        result_id: str,
        result_sha256: str,
        replay_sha256: str,
        recorded_at: str,
    ) -> tuple[str, str, str]:
        effect = {
            "effect_id": result_id,
            "effect_kind": operation.value,
            "payload": {
                "canonical_replay_key_sha256": replay_sha256,
                "result_sha256": result_sha256,
            },
            "recorded_at": recorded_at,
            "schema_version": 1,
        }
        effect_json = canonical_json(effect)
        return (
            effect_json,
            sha256_text(effect_json),
            principal_assertion_effects_hash((sha256_text(effect_json),)),
        )

    def _consume(
        self,
        connection: sqlite3.Connection,
        *,
        assertion: PrincipalAssertion,
        principal: VerifiedPrincipal,
        operation_intent: Mapping[str, Any],
        operation_intent_sha256: str,
        domain_request_sha256: str,
        replay_sha256: str,
        result_kind: str,
        result_id: str,
        result_sha256: str,
        consumed_at: str,
    ) -> None:
        effect_json, effect_sha256, effects_sha256 = self._effect(
            assertion.operation,
            result_id,
            result_sha256,
            replay_sha256,
            consumed_at,
        )
        ledger = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (assertion.mission_id,),
        ).fetchone()
        if (
            ledger is None
            or type(ledger["assertion_count"]) is not int
            or type(ledger["effect_count"]) is not int
            or type(ledger["head_hash"]) is not str
        ):
            raise StoreIntegrityError("Mission principal ledger is invalid")
        sequence = ledger["assertion_count"] + 1
        entry = AuthenticatedMissionControlService._assertion_entry(
            principal=principal,
            assertion=assertion,
            mission_id=assertion.mission_id,
            use_sequence=sequence,
            assertion_hash=assertion.content_sha256,
            operation_intent_json=canonical_json(dict(operation_intent)),
            signed_intent_hash=operation_intent_sha256,
            domain_request_hash=domain_request_sha256,
            idempotency_key_hash=replay_sha256,
            consumed_at=consumed_at,
            effects_hash=effects_sha256,
            previous_hash=ledger["head_hash"],
        )
        entry_hash = principal_assertion_entry_hash(entry)
        self._authenticated._insert_assertion_use(
            connection,
            assertion_json=canonical_json(assertion.to_dict()),
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
                assertion.mission_id,
                assertion.operation.value,
                result_id,
                effect_json,
                effect_sha256,
                consumed_at,
            ),
        )
        update = connection.execute(
            """
            UPDATE mission_principal_ledgers
            SET head_hash = ?, assertion_count = assertion_count + 1,
                effect_count = effect_count + 1, updated_at = ?
            WHERE mission_id = ? AND assertion_count = ? AND head_hash = ?
            """,
            (
                entry_hash,
                consumed_at,
                assertion.mission_id,
                sequence - 1,
                ledger["head_hash"],
            ),
        )
        if update.rowcount != 1:
            raise StoreConflictError("Mission principal ledger changed")
        connection.execute(
            """
            INSERT INTO authenticated_expert_review_replay_uses(
                canonical_replay_key_sha256, mission_id, operation,
                domain_request_sha256, assertion_issuer, assertion_id,
                result_kind, result_id, result_sha256, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                replay_sha256,
                assertion.mission_id,
                assertion.operation.value,
                domain_request_sha256,
                assertion.issuer,
                assertion.assertion_id,
                result_kind,
                result_id,
                result_sha256,
                consumed_at,
            ),
        )

    @staticmethod
    def _assertion_is_unused(
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
    ) -> None:
        if (
            connection.execute(
                "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                (assertion.issuer, assertion.assertion_id),
            ).fetchone()
            is not None
        ):
            raise StoreConflictError("Principal assertion was already consumed")

    @staticmethod
    def _require_plan_binding(
        snapshot: ExpertReviewSnapshot,
        plan: CollaborationPlan,
        runtime_catalog: RuntimePackCatalog,
        registry: ExpertRegistry,
        *,
        target_scope_sha256: str | None,
    ) -> None:
        document = snapshot.to_dict()
        catalog_document = _catalog_document(runtime_catalog)
        registry_sha256 = _canonical_sha256(registry.to_dict())
        if (
            document["plan_id"] != plan.plan_id
            or document["mission_id"] != plan.mission_id
            or document["runtime_catalog_sha256"] != runtime_catalog.catalog_sha256
            or document["runtime_catalog_id"] != catalog_document["catalog_id"]
            or document["runtime_catalog_version"] != catalog_document["catalog_version"]
            or document["registry_sha256"] != registry_sha256
            or target_scope_sha256 is None
            or document["target_scope_sha256"] != target_scope_sha256
        ):
            raise StoreConflictError("Review snapshot source binding is stale")

    def register_snapshot(
        self,
        assertion: PrincipalAssertion,
        snapshot: ExpertReviewSnapshot,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> AuthenticatedExpertReviewSnapshotRegistration:
        """Authenticate and atomically register one exact current workspace snapshot."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError("assertion must be canonical")
        if type(snapshot) is not ExpertReviewSnapshot:
            raise StoreError("snapshot must be canonical")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        snapshot = parse_expert_review_snapshot(snapshot.to_dict(), self._registry)
        if assertion.operation is not PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER:
            raise PrincipalAuthenticationError("Snapshot registration assertion is invalid")
        snapshot_document = snapshot.to_dict()
        mission_id = snapshot_document["mission_id"]
        if assertion.mission_id != mission_id:
            raise PrincipalAuthenticationError("Snapshot assertion mission does not match")
        now = _clock_value(self._clock)
        consumed_at = format_timestamp(now)
        try:
            with self._store._write_connection() as connection:
                identity, policies, mission, scopes, plan, plan_version = self._current_sources(
                    connection, mission_id
                )
                self._require_plan_binding(
                    snapshot,
                    plan,
                    runtime_catalog,
                    self._registry,
                    target_scope_sha256=mission.mission.scope_document_hash,
                )
                intent = expert_review_snapshot_registration_intent(
                    snapshot,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    principal_profile_id=assertion.profile_id,
                )
                intent_sha256 = compute_operation_intent_hash(
                    assertion.operation,
                    intent,
                )
                domain_request = self._domain_request(
                    assertion.operation,
                    {
                        "snapshot_id": snapshot.snapshot_id,
                        "snapshot_sha256": snapshot.snapshot_sha256,
                    },
                )
                replay_sha256 = expert_review_canonical_replay_key_sha256(
                    assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                )
                existing = connection.execute(
                    "SELECT * FROM authenticated_expert_review_snapshot_registrations "
                    "WHERE assertion_issuer = ? AND assertion_id = ?",
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing is not None:
                    try:
                        registration = AuthenticatedExpertReviewSnapshotRegistration.from_dict(
                            loads_json_without_duplicate_keys(existing["registration_json"])
                        )
                    except Exception as exc:
                        raise StoreIntegrityError("Stored review registration is invalid") from exc
                    if (
                        existing["snapshot_json"] != snapshot.document_json
                        or existing["assertion_sha256"] != assertion.content_sha256
                        or existing["operation_intent_sha256"] != intent_sha256
                        or existing["canonical_replay_key_sha256"] != replay_sha256
                        or existing["domain_request_sha256"] != domain_request
                    ):
                        raise StoreConflictError(
                            "Snapshot registration assertion replay has different content"
                        )
                    return registration
                self._assertion_is_unused(connection, assertion)
                current_snapshot = self._workspace_snapshot(
                    workspace_store,
                    snapshot_document["workspace_id"],
                    runtime_catalog,
                )
                if current_snapshot != snapshot:
                    raise StoreConflictError("Workspace review snapshot is stale or substituted")
                role = derive_reviewer_role(self._registry, assertion.profile_id)
                if role["reviewer_role"] != ReviewerRole.INDEPENDENT_ASSURANCE.value:
                    raise PrincipalAuthenticationError(
                        "Snapshot registration requires independent Assurance"
                    )
                principal = self._verify_principal(
                    connection,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    assertion=assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    now=now,
                )
                registered_at = _epoch_seconds(now)
                if registered_at < snapshot_document["event_head_occurred_at"]:
                    raise StoreConflictError("Snapshot registration predates the workspace")
                registration = build_authenticated_expert_review_snapshot_registration(
                    snapshot=snapshot,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    registrar_profile_id=assertion.profile_id,
                    registrar_subject=assertion.subject,
                    assertion_issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    assertion_sha256=assertion.content_sha256,
                    assertion_key_sha256=principal.key_sha256,
                    trust_policy_sha256=principal.policy_sha256,
                    scope_grant_sha256=assertion.scope_grant_sha256,
                    operation_intent_sha256=intent_sha256,
                    canonical_replay_key_sha256=replay_sha256,
                    domain_request_sha256=domain_request,
                    registered_at=registered_at,
                )
                self._consume(
                    connection,
                    assertion=assertion,
                    principal=principal,
                    operation_intent=intent,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                    replay_sha256=replay_sha256,
                    result_kind="snapshot_registration",
                    result_id=registration.registration_id,
                    result_sha256=registration.registration_sha256,
                    consumed_at=consumed_at,
                )
                values = registration.to_dict()
                connection.execute(
                    """
                    INSERT INTO authenticated_expert_review_snapshot_registrations(
                        registration_id, registration_sha256, registration_json,
                        snapshot_id, snapshot_sha256, snapshot_json,
                        mission_id, tenant_id, plan_id, active_plan_sha256,
                        active_plan_version, mission_revision, workspace_id,
                        workspace_sha256, workspace_schema_version, workspace_revision,
                        workspace_event_count, workspace_event_head_sha256,
                        runtime_catalog_id, runtime_catalog_version,
                        runtime_catalog_sha256, registry_sha256, target_scope_sha256,
                        authority_snapshot_sha256, evidence_snapshot_sha256,
                        registrar_profile_id, registrar_subject, assertion_issuer,
                        assertion_id, assertion_sha256, assertion_key_sha256,
                        trust_policy_sha256, scope_grant_sha256,
                        operation_intent_sha256, canonical_replay_key_sha256,
                        domain_request_sha256, registered_at, consumed_at
                    ) VALUES (
                        :registration_id, :registration_sha256, :registration_json,
                        :snapshot_id, :snapshot_sha256, :snapshot_json,
                        :mission_id, :tenant_id, :active_plan_id, :active_plan_sha256,
                        :active_plan_version, :mission_revision, :workspace_id,
                        :workspace_sha256, :workspace_schema_version, :workspace_revision,
                        :workspace_event_count, :workspace_event_head_sha256,
                        :runtime_catalog_id, :runtime_catalog_version,
                        :runtime_catalog_sha256, :registry_sha256, :target_scope_sha256,
                        :authority_snapshot_sha256, :evidence_snapshot_sha256,
                        :registrar_profile_id, :registrar_subject, :assertion_issuer,
                        :assertion_id, :assertion_sha256, :assertion_key_sha256,
                        :trust_policy_sha256, :scope_grant_sha256,
                        :operation_intent_sha256, :canonical_replay_key_sha256,
                        :domain_request_sha256, :registered_at, :consumed_at
                    )
                    """,
                    {
                        **values,
                        "registration_json": registration.document_json,
                        "snapshot_json": snapshot.document_json,
                        "consumed_at": consumed_at,
                    },
                )
                for product in snapshot_document["products"]:
                    connection.execute(
                        "INSERT INTO authenticated_expert_review_snapshot_products "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            snapshot.snapshot_id,
                            product["work_id"],
                            product["product_id"],
                            product["product_sha256"],
                            product["product_type"],
                            product["producer_profile_id"],
                            product["command_id"],
                            product["envelope_id"],
                            product["envelope_sha256"],
                            product["attempt_number"],
                            product["fencing_token"],
                            int(product["review_required"]),
                            canonical_json(product["dependency_product_ids"]),
                            canonical_json(product["lineage_product_ids"]),
                            canonical_json(product["disagreement_sha256s"]),
                        ),
                    )
                for slot in snapshot_document["review_slots"]:
                    connection.execute(
                        "INSERT INTO authenticated_expert_review_snapshot_slots "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            snapshot.snapshot_id,
                            slot["work_id"],
                            slot["product_id"],
                            slot["product_sha256"],
                            slot["reviewer_profile_id"],
                            slot["reviewer_role"],
                            slot["profile_sha256"],
                            slot["policy_template_id"],
                            slot["policy_template_sha256"],
                            slot["registry_sha256"],
                            canonical_json(slot["producer_profile_ids_excluded"]),
                        ),
                    )
                verify_authenticated_expert_review_store(connection, mission_id=mission_id)
                return registration
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authenticated snapshot registration conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist authenticated snapshot registration") from exc

    @staticmethod
    def _snapshot_from_registration_row(
        row: sqlite3.Row,
        registry: ExpertRegistry,
    ) -> ExpertReviewSnapshot:
        if type(row["snapshot_json"]) is not str:
            raise StoreIntegrityError("Stored review snapshot is not text")
        try:
            snapshot = parse_expert_review_snapshot(
                loads_json_without_duplicate_keys(row["snapshot_json"]),
                registry,
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored review snapshot is invalid") from exc
        if (
            snapshot.snapshot_id != row["snapshot_id"]
            or snapshot.snapshot_sha256 != row["snapshot_sha256"]
        ):
            raise StoreIntegrityError("Stored review snapshot identity is invalid")
        return snapshot

    def record_review(
        self,
        assertion: PrincipalAssertion,
        submission: ExpertReviewSubmission,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> AuthenticatedExpertReviewReceipt:
        """Authenticate one exact mandatory review slot and commit its receipt."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError("assertion must be canonical")
        if type(submission) is not ExpertReviewSubmission:
            raise StoreError("submission must be canonical")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        submission = parse_expert_review_submission(submission.to_dict())
        if assertion.operation is not PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW:
            raise PrincipalAuthenticationError("Review assertion operation is invalid")
        submission_document = submission.to_dict()
        try:
            with self._store._write_connection() as connection:
                registration_row = connection.execute(
                    "SELECT * FROM authenticated_expert_review_snapshot_registrations "
                    "WHERE snapshot_id = ?",
                    (submission_document["snapshot_id"],),
                ).fetchone()
                if registration_row is None:
                    raise StoreConflictError("Review snapshot is not durably registered")
                snapshot = self._snapshot_from_registration_row(
                    registration_row,
                    self._registry,
                )
                snapshot_document = snapshot.to_dict()
                mission_id = snapshot_document["mission_id"]
                if assertion.mission_id != mission_id:
                    raise PrincipalAuthenticationError("Review assertion mission does not match")
                identity, policies, mission, scopes, plan, plan_version = self._current_sources(
                    connection, mission_id
                )
                self._require_plan_binding(
                    snapshot,
                    plan,
                    runtime_catalog,
                    self._registry,
                    target_scope_sha256=mission.mission.scope_document_hash,
                )
                registration_intent = expert_review_snapshot_registration_intent(
                    snapshot,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    principal_profile_id=registration_row["registrar_profile_id"],
                )
                self._revalidate_assertion_use(
                    connection,
                    domain_row=registration_row,
                    operation=PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                    operation_intent=registration_intent,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    now=_clock_value(self._clock),
                )
                intent = expert_work_product_review_intent(
                    snapshot,
                    submission,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    principal_profile_id=assertion.profile_id,
                )
                intent_sha256 = compute_operation_intent_hash(assertion.operation, intent)
                domain_request = self._domain_request(
                    assertion.operation,
                    {
                        "snapshot_sha256": snapshot.snapshot_sha256,
                        "submission_sha256": submission.submission_sha256,
                    },
                )
                replay_sha256 = expert_review_canonical_replay_key_sha256(
                    assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                )
                existing = connection.execute(
                    "SELECT * FROM authenticated_expert_review_receipts "
                    "WHERE assertion_issuer = ? AND assertion_id = ?",
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing is not None:
                    try:
                        receipt = parse_authenticated_expert_review_receipt(
                            loads_json_without_duplicate_keys(existing["receipt_json"])
                        )
                    except Exception as exc:
                        raise StoreIntegrityError("Stored review receipt is invalid") from exc
                    if (
                        existing["submission_json"] != submission.document_json
                        or existing["assertion_sha256"] != assertion.content_sha256
                        or existing["operation_intent_sha256"] != intent_sha256
                        or existing["canonical_replay_key_sha256"] != replay_sha256
                    ):
                        raise StoreConflictError("Review assertion replay has different content")
                    return receipt
                self._assertion_is_unused(connection, assertion)
                current_snapshot = self._workspace_snapshot(
                    workspace_store,
                    snapshot_document["workspace_id"],
                    runtime_catalog,
                )
                if current_snapshot != snapshot:
                    raise StoreConflictError("Review snapshot is stale or substituted")
                slot = next(
                    (
                        item
                        for item in snapshot_document["review_slots"]
                        if item["work_id"] == submission_document["work_id"]
                        and item["reviewer_profile_id"] == assertion.profile_id
                    ),
                    None,
                )
                role = derive_reviewer_role(self._registry, assertion.profile_id)
                if (
                    slot is None
                    or assertion.profile_id != submission_document["reviewer_profile_id"]
                    or role["reviewer_role"] != submission_document["reviewer_role"]
                    or any(
                        submission_document[key] != slot[key]
                        for key in ("product_id", "product_sha256", "reviewer_role")
                    )
                ):
                    raise PrincipalAuthenticationError("Review authority does not match its slot")
                now = _clock_value(self._clock)
                recorded_at = _epoch_seconds(now)
                if recorded_at < snapshot_document["event_head_occurred_at"]:
                    raise StoreConflictError("Review receipt predates the workspace snapshot")
                principal = self._verify_principal(
                    connection,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    assertion=assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    now=now,
                )
                receipt = build_authenticated_expert_review_receipt(
                    submission,
                    reviewer_subject=assertion.subject,
                    assertion_issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    assertion_sha256=assertion.content_sha256,
                    assertion_key_sha256=principal.key_sha256,
                    trust_policy_sha256=principal.policy_sha256,
                    scope_grant_sha256=assertion.scope_grant_sha256,
                    operation_intent_sha256=intent_sha256,
                    canonical_replay_key_sha256=replay_sha256,
                    recorded_at=recorded_at,
                )
                self._consume(
                    connection,
                    assertion=assertion,
                    principal=principal,
                    operation_intent=intent,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                    replay_sha256=replay_sha256,
                    result_kind="work_product_review",
                    result_id=receipt.receipt_id,
                    result_sha256=receipt.receipt_sha256,
                    consumed_at=format_timestamp(now),
                )
                connection.execute(
                    """
                    INSERT INTO authenticated_expert_review_receipts(
                        receipt_id, receipt_sha256, receipt_json,
                        submission_id, submission_sha256, submission_json,
                        mission_id, snapshot_id, snapshot_sha256, work_id,
                        product_id, product_sha256, reviewer_profile_id,
                        reviewer_role, reviewer_subject, assertion_issuer,
                        assertion_id, assertion_sha256, assertion_key_sha256,
                        trust_policy_sha256, scope_grant_sha256,
                        operation_intent_sha256, canonical_replay_key_sha256,
                        domain_request_sha256, recorded_at, consumed_at
                    ) VALUES (
                        :receipt_id, :receipt_sha256, :receipt_json,
                        :submission_id, :submission_sha256, :submission_json,
                        :mission_id, :snapshot_id, :snapshot_sha256, :work_id,
                        :product_id, :product_sha256, :reviewer_profile_id,
                        :reviewer_role, :reviewer_subject, :assertion_issuer,
                        :assertion_id, :assertion_sha256, :assertion_key_sha256,
                        :trust_policy_sha256, :scope_grant_sha256,
                        :operation_intent_sha256, :canonical_replay_key_sha256,
                        :domain_request_sha256, :recorded_at, :consumed_at
                    )
                    """,
                    {
                        **receipt.to_dict(),
                        "receipt_json": receipt.document_json,
                        "submission_json": submission.document_json,
                        "mission_id": mission_id,
                        "snapshot_id": snapshot.snapshot_id,
                        "snapshot_sha256": snapshot.snapshot_sha256,
                        "work_id": submission_document["work_id"],
                        "product_id": submission_document["product_id"],
                        "product_sha256": submission_document["product_sha256"],
                        "reviewer_profile_id": submission_document["reviewer_profile_id"],
                        "reviewer_role": submission_document["reviewer_role"],
                        "domain_request_sha256": domain_request,
                        "consumed_at": format_timestamp(now),
                    },
                )
                verify_authenticated_expert_review_store(connection, mission_id=mission_id)
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authenticated expert review conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist authenticated expert review") from exc

    @staticmethod
    def _disposition_material(
        receipts: Sequence[AuthenticatedExpertReviewReceipt],
    ) -> tuple[ClosureDisposition, list[str], list[str], list[str]]:
        decisions = {ReviewDecision(item.to_dict()["submission"]["decision"]) for item in receipts}
        if ReviewDecision.REJECTED in decisions:
            disposition = ClosureDisposition.REJECTED
        elif ReviewDecision.REWORK_REQUIRED in decisions:
            disposition = ClosureDisposition.REWORK_REQUIRED
        else:
            disposition = ClosureDisposition.ACCEPTED
        rejected: set[str] = set()
        rework: set[str] = set()
        corrections: set[str] = set()
        for receipt in receipts:
            submission = receipt.to_dict()["submission"]
            if submission["decision"] == ReviewDecision.REJECTED.value:
                rejected.add(submission["work_id"])
            if submission["decision"] == ReviewDecision.REWORK_REQUIRED.value:
                rework.update(submission["affected_work_ids"] or [submission["work_id"]])
                corrections.update(submission["required_correction_ids"])
        return disposition, sorted(rejected), sorted(rework), sorted(corrections)

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row) -> AuthenticatedExpertReviewReceipt:
        if type(row["receipt_json"]) is not str:
            raise StoreIntegrityError("Stored expert review receipt is not text")
        try:
            receipt = parse_authenticated_expert_review_receipt(
                loads_json_without_duplicate_keys(row["receipt_json"])
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored expert review receipt is invalid") from exc
        if (
            receipt.receipt_id != row["receipt_id"]
            or receipt.receipt_sha256 != row["receipt_sha256"]
        ):
            raise StoreIntegrityError("Stored expert review receipt identity is invalid")
        return receipt

    def close_review(
        self,
        assertion: PrincipalAssertion,
        request: ExpertReviewClosureRequest,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> VerifiedExpertReviewClosure:
        """Authenticate a complete quorum and return only a process-local closure proof."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError("assertion must be canonical")
        if type(request) is not ExpertReviewClosureRequest:
            raise StoreError("closure request must be canonical")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        request = parse_expert_review_closure_request(request.to_dict())
        if assertion.operation is not PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE:
            raise PrincipalAuthenticationError("Closure assertion operation is invalid")
        request_document = request.to_dict()
        closure_id: str | None = None
        try:
            with self._store._write_connection() as connection:
                registration_row = connection.execute(
                    "SELECT * FROM authenticated_expert_review_snapshot_registrations "
                    "WHERE snapshot_id = ?",
                    (request_document["snapshot_id"],),
                ).fetchone()
                if registration_row is None:
                    raise StoreConflictError("Closure snapshot is not durably registered")
                snapshot = self._snapshot_from_registration_row(
                    registration_row,
                    self._registry,
                )
                snapshot_document = snapshot.to_dict()
                mission_id = snapshot_document["mission_id"]
                if assertion.mission_id != mission_id:
                    raise PrincipalAuthenticationError("Closure assertion mission does not match")
                receipts: list[AuthenticatedExpertReviewReceipt] = []
                receipt_rows: list[sqlite3.Row] = []
                for binding in request_document["review_receipts"]:
                    row = connection.execute(
                        "SELECT * FROM authenticated_expert_review_receipts WHERE receipt_id = ?",
                        (binding["receipt_id"],),
                    ).fetchone()
                    if row is None:
                        raise StoreConflictError("Closure review receipt is not durable")
                    receipt = self._receipt_from_row(row)
                    if receipt.receipt_sha256 != binding["receipt_sha256"]:
                        raise StoreConflictError("Closure review receipt is substituted")
                    receipts.append(receipt)
                    receipt_rows.append(row)
                receipts_tuple = tuple(sorted(receipts, key=lambda item: item.receipt_id))
                identity, policies, mission, scopes, plan, plan_version = self._current_sources(
                    connection, mission_id
                )
                self._require_plan_binding(
                    snapshot,
                    plan,
                    runtime_catalog,
                    self._registry,
                    target_scope_sha256=mission.mission.scope_document_hash,
                )
                now = _clock_value(self._clock)
                registration_intent = expert_review_snapshot_registration_intent(
                    snapshot,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    principal_profile_id=registration_row["registrar_profile_id"],
                )
                self._revalidate_assertion_use(
                    connection,
                    domain_row=registration_row,
                    operation=PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                    operation_intent=registration_intent,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    now=now,
                )
                for receipt, receipt_row in zip(
                    receipts_tuple,
                    receipt_rows,
                    strict=True,
                ):
                    submission = parse_expert_review_submission(receipt.to_dict()["submission"])
                    receipt_intent = expert_work_product_review_intent(
                        snapshot,
                        submission,
                        active_plan_sha256=plan.content_sha256,
                        active_plan_version=plan_version,
                        mission_revision=mission.revision,
                        principal_profile_id=receipt_row["reviewer_profile_id"],
                    )
                    self._revalidate_assertion_use(
                        connection,
                        domain_row=receipt_row,
                        operation=PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
                        operation_intent=receipt_intent,
                        identity=identity,
                        trust_policies=policies,
                        mission=mission,
                        scope_grants=scopes,
                        now=now,
                    )
                intent = expert_workspace_review_close_intent(
                    snapshot,
                    request,
                    receipts_tuple,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_revision=mission.revision,
                    principal_profile_id=assertion.profile_id,
                )
                intent_sha256 = compute_operation_intent_hash(assertion.operation, intent)
                domain_request = self._domain_request(
                    assertion.operation,
                    {
                        "closure_request_sha256": request.closure_request_sha256,
                        "review_set_sha256": review_set_sha256(receipts_tuple),
                        "snapshot_sha256": snapshot.snapshot_sha256,
                    },
                )
                replay_sha256 = expert_review_canonical_replay_key_sha256(
                    assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                )
                existing = connection.execute(
                    "SELECT * FROM authenticated_expert_review_closures "
                    "WHERE assertion_issuer = ? AND assertion_id = ?",
                    (assertion.issuer, assertion.assertion_id),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["closure_request_json"] != request.document_json
                        or existing["assertion_sha256"] != assertion.content_sha256
                        or existing["operation_intent_sha256"] != intent_sha256
                        or existing["canonical_replay_key_sha256"] != replay_sha256
                    ):
                        raise StoreConflictError("Closure assertion replay has different content")
                    closure_id = str(existing["closure_id"])
                else:
                    self._assertion_is_unused(connection, assertion)
                    current_snapshot = self._workspace_snapshot(
                        workspace_store,
                        snapshot_document["workspace_id"],
                        runtime_catalog,
                    )
                    if current_snapshot != snapshot:
                        raise StoreConflictError("Closure snapshot is stale or substituted")
                    role = derive_reviewer_role(self._registry, assertion.profile_id)
                    if (
                        assertion.profile_id != request_document["closer_profile_id"]
                        or role["reviewer_role"] != ReviewerRole.INDEPENDENT_CONTROL.value
                    ):
                        raise PrincipalAuthenticationError(
                            "Closure requires its assigned independent Control profile"
                        )
                    closed_at = _epoch_seconds(now)
                    if closed_at < request_document["requested_at"]:
                        raise StoreConflictError("Closure certificate predates its request")
                    principal = self._verify_principal(
                        connection,
                        identity=identity,
                        trust_policies=policies,
                        mission=mission,
                        scope_grants=scopes,
                        assertion=assertion,
                        operation=assertion.operation,
                        operation_intent_sha256=intent_sha256,
                        now=now,
                    )
                    disposition, rejected, rework, corrections = self._disposition_material(
                        receipts_tuple
                    )
                    closure = build_expert_review_closure_certificate(
                        request,
                        review_receipt_ids=[item.receipt_id for item in receipts_tuple],
                        review_set_sha256=review_set_sha256(receipts_tuple),
                        disposition=disposition,
                        rejected_work_ids=rejected,
                        rework_work_ids=rework,
                        required_correction_ids=corrections,
                        closer_subject=assertion.subject,
                        closer_profile_id=assertion.profile_id,
                        assertion_issuer=assertion.issuer,
                        assertion_id=assertion.assertion_id,
                        assertion_sha256=assertion.content_sha256,
                        assertion_key_sha256=principal.key_sha256,
                        trust_policy_sha256=principal.policy_sha256,
                        scope_grant_sha256=assertion.scope_grant_sha256,
                        operation_intent_sha256=intent_sha256,
                        canonical_replay_key_sha256=replay_sha256,
                        closed_at=closed_at,
                    )
                    records = verify_expert_review_record_set(
                        ExpertReviewRecordSet(
                            snapshot,
                            receipts_tuple,
                            request,
                            closure,
                        ),
                        self._registry,
                    )
                    self._consume(
                        connection,
                        assertion=assertion,
                        principal=principal,
                        operation_intent=intent,
                        operation_intent_sha256=intent_sha256,
                        domain_request_sha256=domain_request,
                        replay_sha256=replay_sha256,
                        result_kind="workspace_review_close",
                        result_id=closure.closure_id,
                        result_sha256=closure.closure_sha256,
                        consumed_at=format_timestamp(now),
                    )
                    closure_document = closure.to_dict()
                    connection.execute(
                        """
                        INSERT INTO authenticated_expert_review_closures(
                            closure_id, closure_sha256, closure_json,
                            closure_request_id, closure_request_sha256,
                            closure_request_json, mission_id, snapshot_id,
                            snapshot_sha256, review_set_sha256, disposition,
                            rejected_work_ids_json, rework_work_ids_json,
                            required_correction_ids_json, closer_profile_id,
                            closer_subject, assertion_issuer, assertion_id,
                            assertion_sha256, assertion_key_sha256,
                            trust_policy_sha256, scope_grant_sha256,
                            operation_intent_sha256, canonical_replay_key_sha256,
                            domain_request_sha256, closed_at, consumed_at
                        ) VALUES (
                            :closure_id, :closure_sha256, :closure_json,
                            :closure_request_id, :closure_request_sha256,
                            :closure_request_json, :mission_id, :snapshot_id,
                            :snapshot_sha256, :review_set_sha256, :disposition,
                            :rejected_work_ids_json, :rework_work_ids_json,
                            :required_correction_ids_json, :closer_profile_id,
                            :closer_subject, :assertion_issuer, :assertion_id,
                            :assertion_sha256, :assertion_key_sha256,
                            :trust_policy_sha256, :scope_grant_sha256,
                            :operation_intent_sha256, :canonical_replay_key_sha256,
                            :domain_request_sha256, :closed_at, :consumed_at
                        )
                        """,
                        {
                            **closure_document,
                            "closure_json": closure.document_json,
                            "closure_request_json": request.document_json,
                            "mission_id": mission_id,
                            "rejected_work_ids_json": canonical_json(rejected),
                            "rework_work_ids_json": canonical_json(rework),
                            "required_correction_ids_json": canonical_json(corrections),
                            "domain_request_sha256": domain_request,
                            "consumed_at": format_timestamp(now),
                        },
                    )
                    for ordinal, receipt in enumerate(receipts_tuple):
                        connection.execute(
                            "INSERT INTO authenticated_expert_review_closure_receipts "
                            "VALUES (?, ?, ?, ?)",
                            (
                                closure.closure_id,
                                ordinal,
                                receipt.receipt_id,
                                receipt.receipt_sha256,
                            ),
                        )
                    verify_expert_review_record_set(records, self._registry)
                    verify_authenticated_expert_review_store(
                        connection,
                        mission_id=mission_id,
                    )
                    closure_id = closure.closure_id
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authenticated review closure conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist authenticated review closure") from exc
        if closure_id is None:
            raise StoreIntegrityError("Authenticated review closure was not persisted")
        return self.verify_closure(
            closure_id,
            workspace_store=workspace_store,
            runtime_catalog=runtime_catalog,
        )

    def revoke_closure(
        self,
        assertion: PrincipalAssertion,
        closure_id: str,
        *,
        reason_code: str,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> VerifiedExpertReviewRevocation:
        """Authenticate and atomically revoke one exact durable closure."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError("assertion must be canonical")
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        if assertion.operation is not PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE:
            raise PrincipalAuthenticationError("Revocation assertion operation is invalid")
        closure_id = _identifier(closure_id, "closure_id")
        reason_code = _identifier(reason_code, "reason_code")
        try:
            with self._store._write_connection() as connection:
                records, _, _, _, _ = self._reload_records(
                    connection,
                    closure_id,
                    workspace_store=workspace_store,
                    runtime_catalog=runtime_catalog,
                    require_not_revoked=False,
                )
                closure_projection = connection.execute(
                    "SELECT closure_sha256 FROM "
                    "authenticated_expert_review_closure_projections "
                    "WHERE closure_id = ?",
                    (closure_id,),
                ).fetchone()
                if closure_projection is None:
                    raise StoreConflictError("Closure must be projected before it can be revoked")
                if closure_projection["closure_sha256"] != records.closure.closure_sha256:
                    raise StoreIntegrityError("Closure projection custody is inconsistent")
                if records.revocation is not None:
                    row = connection.execute(
                        "SELECT * FROM authenticated_expert_review_revocations "
                        "WHERE closure_id = ?",
                        (closure_id,),
                    ).fetchone()
                    if (
                        row is None
                        or row["assertion_issuer"] != assertion.issuer
                        or row["assertion_id"] != assertion.assertion_id
                        or row["assertion_sha256"] != assertion.content_sha256
                        or row["reason_code"] != reason_code
                    ):
                        raise StoreConflictError("Closure is already revoked")
                    return self.__seal_revocation(
                        records,
                        self._store_id(connection),
                    )
                snapshot_document = records.snapshot.to_dict()
                mission_id = snapshot_document["mission_id"]
                if assertion.mission_id != mission_id:
                    raise PrincipalAuthenticationError(
                        "Revocation assertion mission does not match"
                    )
                identity, policies, mission, scopes, plan, plan_version = self._current_sources(
                    connection, mission_id
                )
                self._require_plan_binding(
                    records.snapshot,
                    plan,
                    runtime_catalog,
                    self._registry,
                    target_scope_sha256=mission.mission.scope_document_hash,
                )
                intent = expert_workspace_review_revoke_intent(
                    records.closure,
                    active_plan_id=plan.plan_id,
                    active_plan_sha256=plan.content_sha256,
                    active_plan_version=plan_version,
                    mission_id=mission_id,
                    mission_revision=mission.revision,
                    principal_profile_id=assertion.profile_id,
                    reason_code=reason_code,
                )
                intent_sha256 = compute_operation_intent_hash(assertion.operation, intent)
                domain_request = self._domain_request(
                    assertion.operation,
                    {
                        "closure_sha256": records.closure.closure_sha256,
                        "reason_code": reason_code,
                        "revocation_core_sha256": intent["revocation_core_sha256"],
                    },
                )
                replay_sha256 = expert_review_canonical_replay_key_sha256(
                    assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                )
                self._assertion_is_unused(connection, assertion)
                role = derive_reviewer_role(self._registry, assertion.profile_id)
                if role["reviewer_role"] != ReviewerRole.INDEPENDENT_CONTROL.value:
                    raise PrincipalAuthenticationError(
                        "Closure revocation requires independent Control"
                    )
                now = _clock_value(self._clock)
                principal = self._verify_principal(
                    connection,
                    identity=identity,
                    trust_policies=policies,
                    mission=mission,
                    scope_grants=scopes,
                    assertion=assertion,
                    operation=assertion.operation,
                    operation_intent_sha256=intent_sha256,
                    now=now,
                )
                revoked_at = _epoch_seconds(now)
                if revoked_at < records.closure.to_dict()["closed_at"]:
                    raise StoreConflictError("Closure revocation predates the closure")
                revocation = build_expert_review_closure_revocation(
                    records.closure,
                    reason_code=reason_code,
                    control_subject=assertion.subject,
                    control_profile_id=assertion.profile_id,
                    assertion_issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    assertion_sha256=assertion.content_sha256,
                    operation_intent_sha256=intent_sha256,
                    canonical_replay_key_sha256=replay_sha256,
                    revoked_at=revoked_at,
                )
                complete_records = verify_expert_review_record_set(
                    ExpertReviewRecordSet(
                        records.snapshot,
                        records.receipts,
                        records.closure_request,
                        records.closure,
                        revocation,
                    ),
                    self._registry,
                )
                self._consume(
                    connection,
                    assertion=assertion,
                    principal=principal,
                    operation_intent=intent,
                    operation_intent_sha256=intent_sha256,
                    domain_request_sha256=domain_request,
                    replay_sha256=replay_sha256,
                    result_kind="workspace_review_revoke",
                    result_id=revocation.revocation_id,
                    result_sha256=revocation.revocation_sha256,
                    consumed_at=format_timestamp(now),
                )
                connection.execute(
                    """
                    INSERT INTO authenticated_expert_review_revocations(
                        revocation_id, revocation_sha256, revocation_json,
                        mission_id, closure_id, closure_sha256, reason_code,
                        revocation_core_sha256, control_profile_id, control_subject,
                        assertion_issuer, assertion_id, assertion_sha256,
                        assertion_key_sha256, trust_policy_sha256,
                        scope_grant_sha256, operation_intent_sha256,
                        canonical_replay_key_sha256, domain_request_sha256,
                        revoked_at, consumed_at
                    ) VALUES (
                        :revocation_id, :revocation_sha256, :revocation_json,
                        :mission_id, :closure_id, :closure_sha256, :reason_code,
                        :revocation_core_sha256, :control_profile_id, :control_subject,
                        :assertion_issuer, :assertion_id, :assertion_sha256,
                        :assertion_key_sha256, :trust_policy_sha256,
                        :scope_grant_sha256, :operation_intent_sha256,
                        :canonical_replay_key_sha256, :domain_request_sha256,
                        :revoked_at, :consumed_at
                    )
                    """,
                    {
                        **revocation.to_dict(),
                        "revocation_json": revocation.document_json,
                        "mission_id": mission_id,
                        "revocation_core_sha256": intent["revocation_core_sha256"],
                        "assertion_key_sha256": principal.key_sha256,
                        "trust_policy_sha256": principal.policy_sha256,
                        "scope_grant_sha256": assertion.scope_grant_sha256,
                        "domain_request_sha256": domain_request,
                        "consumed_at": format_timestamp(now),
                    },
                )
                verify_authenticated_expert_review_store(
                    connection,
                    mission_id=mission_id,
                )
                return self.__seal_revocation(
                    complete_records,
                    self._store_id(connection),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Authenticated review revocation conflicted") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist authenticated review revocation") from exc

    @staticmethod
    def _store_id(connection: sqlite3.Connection) -> str:
        row = connection.execute(
            "SELECT store_id FROM store_identity WHERE singleton_id = 1"
        ).fetchone()
        if row is None or type(row["store_id"]) is not str:
            raise StoreIntegrityError("Mission store identity is missing or invalid")
        return row["store_id"]

    def _load_records(
        self,
        connection: sqlite3.Connection,
        closure_id: str,
    ) -> tuple[ExpertReviewRecordSet, sqlite3.Row]:
        closure_row = connection.execute(
            "SELECT * FROM authenticated_expert_review_closures WHERE closure_id = ?",
            (_identifier(closure_id, "closure_id"),),
        ).fetchone()
        if closure_row is None:
            raise StoreConflictError("Authenticated review closure is absent")
        registration_row = connection.execute(
            "SELECT * FROM authenticated_expert_review_snapshot_registrations "
            "WHERE snapshot_id = ?",
            (closure_row["snapshot_id"],),
        ).fetchone()
        if registration_row is None:
            raise StoreIntegrityError("Closure review snapshot registration is absent")
        try:
            snapshot = self._snapshot_from_registration_row(
                registration_row,
                self._registry,
            )
            request = parse_expert_review_closure_request(
                loads_json_without_duplicate_keys(closure_row["closure_request_json"])
            )
            closure = parse_expert_review_closure_certificate(
                loads_json_without_duplicate_keys(closure_row["closure_json"])
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored expert review closure is invalid") from exc
        links = connection.execute(
            "SELECT * FROM authenticated_expert_review_closure_receipts "
            "WHERE closure_id = ? ORDER BY receipt_ordinal",
            (closure_id,),
        ).fetchall()
        if [row["receipt_ordinal"] for row in links] != list(range(len(links))):
            raise StoreIntegrityError("Stored closure receipt order is invalid")
        receipts: list[AuthenticatedExpertReviewReceipt] = []
        for link in links:
            row = connection.execute(
                "SELECT * FROM authenticated_expert_review_receipts WHERE receipt_id = ?",
                (link["receipt_id"],),
            ).fetchone()
            if row is None:
                raise StoreIntegrityError("Stored closure receipt is absent")
            receipt = self._receipt_from_row(row)
            if receipt.receipt_sha256 != link["receipt_sha256"]:
                raise StoreIntegrityError("Stored closure receipt binding is invalid")
            receipts.append(receipt)
        revocation_row = connection.execute(
            "SELECT * FROM authenticated_expert_review_revocations WHERE closure_id = ?",
            (closure_id,),
        ).fetchone()
        revocation = None
        if revocation_row is not None:
            try:
                revocation = parse_expert_review_closure_revocation(
                    loads_json_without_duplicate_keys(revocation_row["revocation_json"])
                )
            except Exception as exc:
                raise StoreIntegrityError("Stored expert review revocation is invalid") from exc
        try:
            records = verify_expert_review_record_set(
                ExpertReviewRecordSet(
                    snapshot,
                    tuple(receipts),
                    request,
                    closure,
                    revocation,
                ),
                self._registry,
            )
        except StoreError as exc:
            raise StoreIntegrityError("Stored expert review record set is invalid") from exc
        return records, registration_row

    def _revalidate_assertion_use(
        self,
        connection: sqlite3.Connection,
        *,
        domain_row: sqlite3.Row,
        operation: PrincipalOperation,
        operation_intent: Mapping[str, Any],
        identity: Mapping[str, Any],
        trust_policies: Mapping[str, Any],
        mission: Any,
        scope_grants: Mapping[str, tuple[sqlite3.Row, Any]],
        now: datetime,
    ) -> PrincipalAssertion:
        row = connection.execute(
            "SELECT * FROM principal_assertion_uses "
            "WHERE issuer = ? AND assertion_id = ? AND mission_id = ?",
            (
                domain_row["assertion_issuer"],
                domain_row["assertion_id"],
                domain_row["mission_id"],
            ),
        ).fetchone()
        if row is None or type(row["assertion_json"]) is not str:
            raise StoreIntegrityError("Expert review principal assertion use is absent")
        try:
            assertion = PrincipalAssertion.from_dict(
                loads_json_without_duplicate_keys(row["assertion_json"])
            )
        except Exception as exc:
            raise StoreIntegrityError("Stored expert review assertion is invalid") from exc
        intent_json = canonical_json(dict(operation_intent))
        intent_sha256 = compute_operation_intent_hash(operation, dict(operation_intent))
        exact = {
            "issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_hash": assertion.content_sha256,
            "subject": assertion.subject,
            "principal_profile_id": assertion.profile_id,
            "operation": operation.value,
            "operation_intent_json": intent_json,
            "signed_intent_hash": intent_sha256,
            "domain_request_hash": domain_row["domain_request_sha256"],
            "idempotency_key_hash": domain_row["canonical_replay_key_sha256"],
            "scope_grant_hash": assertion.scope_grant_sha256,
            "trust_policy_hash": domain_row["trust_policy_sha256"],
        }
        if any(row[field] != value for field, value in exact.items()):
            raise StoreIntegrityError("Stored expert review assertion use is inconsistent")
        if (
            domain_row["assertion_sha256"] != assertion.content_sha256
            or domain_row["assertion_key_sha256"] != row["key_hash"]
            or domain_row["scope_grant_sha256"] != assertion.scope_grant_sha256
            or domain_row["operation_intent_sha256"] != intent_sha256
            or domain_row["assertion_issuer"] != assertion.issuer
            or domain_row["assertion_id"] != assertion.assertion_id
        ):
            raise StoreIntegrityError("Stored expert review authority binding is invalid")
        identity_fields = next(
            (
                (profile_field, subject_field)
                for profile_field, subject_field in (
                    ("registrar_profile_id", "registrar_subject"),
                    ("reviewer_profile_id", "reviewer_subject"),
                    ("closer_profile_id", "closer_subject"),
                    ("control_profile_id", "control_subject"),
                )
                if profile_field in set(domain_row.keys())
            ),
            None,
        )
        if identity_fields is None:
            raise StoreIntegrityError("Stored expert review authority identity is absent")
        profile_field, subject_field = identity_fields
        if (
            domain_row[profile_field] != assertion.profile_id
            or domain_row[subject_field] != assertion.subject
        ):
            raise StoreIntegrityError("Stored expert review principal identity is inconsistent")
        principal = self._verify_principal(
            connection,
            identity=identity,
            trust_policies=trust_policies,
            mission=mission,
            scope_grants=scope_grants,
            assertion=assertion,
            operation=operation,
            operation_intent_sha256=intent_sha256,
            now=now,
        )
        if (
            principal.key_sha256 != domain_row["assertion_key_sha256"]
            or principal.policy_sha256 != domain_row["trust_policy_sha256"]
        ):
            raise PrincipalAuthenticationError(
                "Current expert review authority differs from durable custody"
            )
        return assertion

    def _reload_records(
        self,
        connection: sqlite3.Connection,
        closure_id: str,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
        require_not_revoked: bool,
    ) -> tuple[ExpertReviewRecordSet, str, CollaborationPlan, int, int]:
        verify_authenticated_expert_review_store(connection)
        records, registration_row = self._load_records(connection, closure_id)
        mission_id = records.snapshot.to_dict()["mission_id"]
        identity, policies, mission, scopes, plan, plan_version = self._current_sources(
            connection,
            mission_id,
        )
        self._require_plan_binding(
            records.snapshot,
            plan,
            runtime_catalog,
            self._registry,
            target_scope_sha256=mission.mission.scope_document_hash,
        )
        if (
            registration_row["active_plan_sha256"] != plan.content_sha256
            or registration_row["active_plan_version"] != plan_version
            or registration_row["mission_revision"] != mission.revision
        ):
            raise StoreConflictError("Expert review source state is no longer current")
        if require_not_revoked and records.revocation is not None:
            raise StoreConflictError("Expert review closure is revoked")
        now = _clock_value(self._clock)
        registration_intent = expert_review_snapshot_registration_intent(
            records.snapshot,
            active_plan_sha256=plan.content_sha256,
            active_plan_version=plan_version,
            mission_revision=mission.revision,
            principal_profile_id=registration_row["registrar_profile_id"],
        )
        registration_assertion = self._revalidate_assertion_use(
            connection,
            domain_row=registration_row,
            operation=PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
            operation_intent=registration_intent,
            identity=identity,
            trust_policies=policies,
            mission=mission,
            scope_grants=scopes,
            now=now,
        )
        if (
            derive_reviewer_role(self._registry, registration_assertion.profile_id)["reviewer_role"]
            != ReviewerRole.INDEPENDENT_ASSURANCE.value
        ):
            raise PrincipalAuthenticationError(
                "Current snapshot registrar is not independent Assurance"
            )
        receipt_rows: dict[str, sqlite3.Row] = {}
        for receipt in records.receipts:
            row = connection.execute(
                "SELECT * FROM authenticated_expert_review_receipts WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()
            if row is None or type(row["submission_json"]) is not str:
                raise StoreIntegrityError("Expert review receipt custody is absent")
            try:
                submission = parse_expert_review_submission(
                    loads_json_without_duplicate_keys(row["submission_json"])
                )
            except Exception as exc:
                raise StoreIntegrityError("Stored review submission is invalid") from exc
            intent = expert_work_product_review_intent(
                records.snapshot,
                submission,
                active_plan_sha256=plan.content_sha256,
                active_plan_version=plan_version,
                mission_revision=mission.revision,
                principal_profile_id=row["reviewer_profile_id"],
            )
            receipt_assertion = self._revalidate_assertion_use(
                connection,
                domain_row=row,
                operation=PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
                operation_intent=intent,
                identity=identity,
                trust_policies=policies,
                mission=mission,
                scope_grants=scopes,
                now=now,
            )
            if (
                derive_reviewer_role(self._registry, receipt_assertion.profile_id)["reviewer_role"]
                != row["reviewer_role"]
            ):
                raise PrincipalAuthenticationError("Current reviewer role differs from custody")
            receipt_rows[receipt.receipt_id] = row
        closure_row = connection.execute(
            "SELECT * FROM authenticated_expert_review_closures WHERE closure_id = ?",
            (closure_id,),
        ).fetchone()
        if closure_row is None:
            raise StoreIntegrityError("Expert review closure custody is absent")
        closure_intent = expert_workspace_review_close_intent(
            records.snapshot,
            records.closure_request,
            records.receipts,
            active_plan_sha256=plan.content_sha256,
            active_plan_version=plan_version,
            mission_revision=mission.revision,
            principal_profile_id=closure_row["closer_profile_id"],
        )
        closure_assertion = self._revalidate_assertion_use(
            connection,
            domain_row=closure_row,
            operation=PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
            operation_intent=closure_intent,
            identity=identity,
            trust_policies=policies,
            mission=mission,
            scope_grants=scopes,
            now=now,
        )
        if (
            derive_reviewer_role(self._registry, closure_assertion.profile_id)["reviewer_role"]
            != ReviewerRole.INDEPENDENT_CONTROL.value
        ):
            raise PrincipalAuthenticationError("Current closer is not independent Control")
        if records.revocation is not None:
            revocation_row = connection.execute(
                "SELECT * FROM authenticated_expert_review_revocations WHERE closure_id = ?",
                (closure_id,),
            ).fetchone()
            if revocation_row is None:
                raise StoreIntegrityError("Expert review revocation custody is absent")
            revocation_intent = expert_workspace_review_revoke_intent(
                records.closure,
                active_plan_id=plan.plan_id,
                active_plan_sha256=plan.content_sha256,
                active_plan_version=plan_version,
                mission_id=mission_id,
                mission_revision=mission.revision,
                principal_profile_id=revocation_row["control_profile_id"],
                reason_code=revocation_row["reason_code"],
            )
            revocation_assertion = self._revalidate_assertion_use(
                connection,
                domain_row=revocation_row,
                operation=PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
                operation_intent=revocation_intent,
                identity=identity,
                trust_policies=policies,
                mission=mission,
                scope_grants=scopes,
                now=now,
            )
            if (
                derive_reviewer_role(self._registry, revocation_assertion.profile_id)[
                    "reviewer_role"
                ]
                != ReviewerRole.INDEPENDENT_CONTROL.value
            ):
                raise PrincipalAuthenticationError(
                    "Current revocation principal is not independent Control"
                )
        reconciliation = workspace_store.reconcile_review_records(
            records,
            expert_registry=self._registry,
        )
        if type(reconciliation) is not ExpertReviewReconciliationReport:
            raise StoreIntegrityError("Workspace reconciliation result is invalid")
        allowed = {
            ReconciliationStatus.CONSISTENT,
            ReconciliationStatus.CLOSURE_PENDING_WORKSPACE_APPLICATION,
        }
        if records.revocation is not None:
            allowed.add(ReconciliationStatus.REVOCATION_PENDING_WORKSPACE_APPLICATION)
        if reconciliation.status not in allowed:
            raise StoreConflictError("Workspace review projection conflicts with custody")
        if reconciliation.status is ReconciliationStatus.CLOSURE_PENDING_WORKSPACE_APPLICATION:
            current_snapshot = self._workspace_snapshot(
                workspace_store,
                records.snapshot.to_dict()["workspace_id"],
                runtime_catalog,
            )
            if current_snapshot != records.snapshot:
                raise StoreConflictError("Workspace review snapshot is stale or substituted")
        return records, self._store_id(connection), plan, plan_version, mission.revision

    def verify_closure(
        self,
        closure_id: str,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> VerifiedExpertReviewClosure:
        """Reload all authority and state before sealing a local closure proof."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        with self._store._read_connection() as connection:
            records, store_id, plan, plan_version, mission_revision = self._reload_records(
                connection,
                closure_id,
                workspace_store=workspace_store,
                runtime_catalog=runtime_catalog,
                require_not_revoked=True,
            )
            return self.__seal_closure(
                records,
                store_id,
                plan.content_sha256,
                plan_version,
                mission_revision,
            )

    def verify_closure_in_transaction(
        self,
        connection: sqlite3.Connection,
        closure_id: str,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> VerifiedExpertReviewClosure:
        """Verify a closure using the caller's MissionStore transaction."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if type(connection) is not sqlite3.Connection or not connection.in_transaction:
            raise StoreError("An active MissionStore transaction is required")
        databases = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [
            Path(str(row[2])).resolve()
            for row in databases
            if str(row[1]) == "main" and str(row[2])
        ]
        if main_paths != [self._store.path]:
            raise StoreError("Transaction does not belong to the custody MissionStore")
        self._store._require_schema(connection)
        records, store_id, plan, plan_version, mission_revision = self._reload_records(
            connection,
            closure_id,
            workspace_store=workspace_store,
            runtime_catalog=runtime_catalog,
            require_not_revoked=True,
        )
        return self.__seal_closure(
            records,
            store_id,
            plan.content_sha256,
            plan_version,
            mission_revision,
        )

    def verify_revocation(
        self,
        closure_id: str,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> VerifiedExpertReviewRevocation:
        """Reload all authority and state before sealing a local revocation proof."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        with self._store._read_connection() as connection:
            records, store_id, _plan, _plan_version, _mission_revision = self._reload_records(
                connection,
                closure_id,
                workspace_store=workspace_store,
                runtime_catalog=runtime_catalog,
                require_not_revoked=False,
            )
            if records.revocation is None:
                raise StoreConflictError("Expert review closure is not revoked")
            return self.__seal_revocation(records, store_id)

    def apply_closure(
        self,
        verified: VerifiedExpertReviewClosure,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> ExpertWorkspaceClosureApplication:
        """Freshly revalidate and project one sealed closure into its workspace."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if not self.validates_closure_proof(verified):
            raise PrincipalAuthenticationError("A valid local closure proof is required")
        with self._store._write_connection() as connection:
            records, store_id, plan, plan_version, mission_revision = self._reload_records(
                connection,
                verified.records.closure.closure_id,
                workspace_store=workspace_store,
                runtime_catalog=runtime_catalog,
                require_not_revoked=True,
            )
            if (
                records != verified.records
                or store_id != verified.mission_store_id
                or plan.content_sha256 != verified.active_plan_sha256
                or plan_version != verified.active_plan_version
                or mission_revision != verified.mission_revision
            ):
                raise PrincipalAuthenticationError("Closure proof is stale or substituted")
            fresh = self.__seal_closure(
                records,
                store_id,
                plan.content_sha256,
                plan_version,
                mission_revision,
            )
            authorization_token = self.__projection_token(
                "closure",
                records.closure.closure_id,
            )
            try:
                result = workspace_store.apply_review_closure(
                    fresh,
                    authority=self,
                    authorization_token=authorization_token,
                    mission_store_id=store_id,
                    runtime_catalog=runtime_catalog,
                    expert_registry=self._registry,
                    applied_at=_epoch_seconds(_clock_value(self._clock)),
                )
            finally:
                self.__discard_projection_token(authorization_token)
            if type(result) is not ExpertWorkspaceClosureApplication:
                raise StoreIntegrityError("Workspace closure projection result is invalid")
            reconciliation = workspace_store.reconcile_review_records(
                records,
                expert_registry=self._registry,
            )
            if (
                type(reconciliation) is not ExpertReviewReconciliationReport
                or reconciliation.status is not ReconciliationStatus.CONSISTENT
                or reconciliation.local_application_id != result.application_id
                or reconciliation.local_revocation_id is not None
            ):
                raise StoreIntegrityError("Workspace closure projection was not durably reconciled")
            document = result.to_dict()
            existing = connection.execute(
                "SELECT * FROM authenticated_expert_review_closure_projections "
                "WHERE closure_id = ?",
                (records.closure.closure_id,),
            ).fetchone()
            values = (
                records.closure.closure_id,
                records.closure.closure_sha256,
                records.snapshot.to_dict()["mission_id"],
                records.snapshot.to_dict()["workspace_id"],
                result.application_id,
                result.application_sha256,
                result.document_json,
                document["applied_at"],
            )
            if existing is None:
                connection.execute(
                    "INSERT INTO authenticated_expert_review_closure_projections "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    values,
                )
            elif tuple(existing) != values:
                raise StoreConflictError("Workspace closure projection custody conflicts")
            verify_authenticated_expert_review_store(
                connection,
                mission_id=records.snapshot.to_dict()["mission_id"],
            )
            return result

    def apply_revocation(
        self,
        verified: VerifiedExpertReviewRevocation,
        *,
        workspace_store: ExpertWorkspaceStoreAdapter,
        runtime_catalog: RuntimePackCatalog,
    ) -> ExpertReviewClosureRevocation:
        """Freshly revalidate and project one sealed revocation into its workspace."""

        self._require_trusted_sources(workspace_store, runtime_catalog)
        if not self.validates_revocation_proof(verified):
            raise PrincipalAuthenticationError("A valid local revocation proof is required")
        with self._store._write_connection() as connection:
            records, store_id, _plan, _plan_version, _mission_revision = self._reload_records(
                connection,
                verified.records.closure.closure_id,
                workspace_store=workspace_store,
                runtime_catalog=runtime_catalog,
                require_not_revoked=False,
            )
            if records != verified.records or store_id != verified.mission_store_id:
                raise PrincipalAuthenticationError("Revocation proof is stale or substituted")
            fresh = self.__seal_revocation(records, store_id)
            projected_at = _epoch_seconds(_clock_value(self._clock))
            revocation = records.revocation
            if revocation is None:
                raise StoreIntegrityError("Revocation proof lost its durable revocation")
            authorization_token = self.__projection_token(
                "revocation",
                revocation.revocation_id,
            )
            try:
                result = workspace_store.apply_review_closure_revocation(
                    fresh,
                    authority=self,
                    authorization_token=authorization_token,
                    runtime_catalog=runtime_catalog,
                    expert_registry=self._registry,
                    applied_at=projected_at,
                )
            finally:
                self.__discard_projection_token(authorization_token)
            if type(result) is not ExpertReviewClosureRevocation:
                raise StoreIntegrityError("Workspace revocation projection result is invalid")
            reconciliation = workspace_store.reconcile_review_records(
                records,
                expert_registry=self._registry,
            )
            if (
                type(reconciliation) is not ExpertReviewReconciliationReport
                or reconciliation.status is not ReconciliationStatus.CONSISTENT
                or reconciliation.local_revocation_id != revocation.revocation_id
            ):
                raise StoreIntegrityError(
                    "Workspace revocation projection was not durably reconciled"
                )
            existing = connection.execute(
                "SELECT * FROM authenticated_expert_review_revocation_projections "
                "WHERE revocation_id = ?",
                (revocation.revocation_id,),
            ).fetchone()
            values = (
                revocation.revocation_id,
                revocation.revocation_sha256,
                records.snapshot.to_dict()["mission_id"],
                records.closure.closure_id,
                records.snapshot.to_dict()["workspace_id"],
                projected_at,
            )
            if existing is None:
                connection.execute(
                    "INSERT INTO authenticated_expert_review_revocation_projections "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    values,
                )
            elif (
                existing["revocation_id"] != values[0]
                or existing["revocation_sha256"] != values[1]
                or existing["mission_id"] != values[2]
                or existing["closure_id"] != values[3]
                or existing["workspace_id"] != values[4]
            ):
                raise StoreConflictError("Workspace revocation projection custody conflicts")
            verify_authenticated_expert_review_store(
                connection,
                mission_id=records.snapshot.to_dict()["mission_id"],
            )
            return result


EXPERT_REVIEW_OPERATIONS = frozenset(
    {
        "sunderkey.expert.review.snapshot.register.v1",
        "sunderkey.expert.work-product.review.v1",
        "sunderkey.expert.workspace.review.close.v1",
        "sunderkey.expert.workspace.review.revoke.v1",
    }
)

_TEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "authenticated_expert_review_replay_uses": (
        "canonical_replay_key_sha256",
        "mission_id",
        "operation",
        "domain_request_sha256",
        "assertion_issuer",
        "assertion_id",
        "result_kind",
        "result_id",
        "result_sha256",
        "consumed_at",
    ),
    "authenticated_expert_review_snapshot_registrations": (
        "registration_id",
        "registration_sha256",
        "registration_json",
        "snapshot_id",
        "snapshot_sha256",
        "snapshot_json",
        "mission_id",
        "tenant_id",
        "plan_id",
        "active_plan_sha256",
        "workspace_id",
        "workspace_sha256",
        "workspace_event_head_sha256",
        "runtime_catalog_id",
        "runtime_catalog_version",
        "runtime_catalog_sha256",
        "registry_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "registrar_profile_id",
        "registrar_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "domain_request_sha256",
        "consumed_at",
    ),
    "authenticated_expert_review_snapshot_products": (
        "snapshot_id",
        "work_id",
        "product_id",
        "product_sha256",
        "product_type",
        "producer_profile_id",
        "command_id",
        "envelope_id",
        "envelope_sha256",
        "dependency_product_ids_json",
        "lineage_product_ids_json",
        "disagreement_sha256s_json",
    ),
    "authenticated_expert_review_snapshot_slots": (
        "snapshot_id",
        "work_id",
        "product_id",
        "product_sha256",
        "reviewer_profile_id",
        "reviewer_role",
        "profile_sha256",
        "policy_template_id",
        "policy_template_sha256",
        "registry_sha256",
        "producer_profile_ids_excluded_json",
    ),
    "authenticated_expert_review_receipts": (
        "receipt_id",
        "receipt_sha256",
        "receipt_json",
        "submission_id",
        "submission_sha256",
        "submission_json",
        "mission_id",
        "snapshot_id",
        "snapshot_sha256",
        "work_id",
        "product_id",
        "product_sha256",
        "reviewer_profile_id",
        "reviewer_role",
        "reviewer_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "domain_request_sha256",
        "consumed_at",
    ),
    "authenticated_expert_review_closures": (
        "closure_id",
        "closure_sha256",
        "closure_json",
        "closure_request_id",
        "closure_request_sha256",
        "closure_request_json",
        "mission_id",
        "snapshot_id",
        "snapshot_sha256",
        "review_set_sha256",
        "disposition",
        "rejected_work_ids_json",
        "rework_work_ids_json",
        "required_correction_ids_json",
        "closer_profile_id",
        "closer_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "domain_request_sha256",
        "consumed_at",
    ),
    "authenticated_expert_review_closure_receipts": (
        "closure_id",
        "receipt_id",
        "receipt_sha256",
    ),
    "authenticated_expert_review_revocations": (
        "revocation_id",
        "revocation_sha256",
        "revocation_json",
        "mission_id",
        "closure_id",
        "closure_sha256",
        "reason_code",
        "revocation_core_sha256",
        "control_profile_id",
        "control_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "domain_request_sha256",
        "consumed_at",
    ),
    "authenticated_expert_review_closure_projections": (
        "closure_id",
        "closure_sha256",
        "mission_id",
        "workspace_id",
        "application_id",
        "application_sha256",
        "application_json",
    ),
    "authenticated_expert_review_revocation_projections": (
        "revocation_id",
        "revocation_sha256",
        "mission_id",
        "closure_id",
        "workspace_id",
    ),
}

_INTEGER_FIELDS: dict[str, tuple[str, ...]] = {
    "authenticated_expert_review_snapshot_registrations": (
        "active_plan_version",
        "mission_revision",
        "workspace_schema_version",
        "workspace_revision",
        "workspace_event_count",
        "registered_at",
    ),
    "authenticated_expert_review_snapshot_products": (
        "attempt_number",
        "fencing_token",
        "review_required",
    ),
    "authenticated_expert_review_receipts": ("recorded_at",),
    "authenticated_expert_review_closures": ("closed_at",),
    "authenticated_expert_review_closure_receipts": ("receipt_ordinal",),
    "authenticated_expert_review_revocations": ("revoked_at",),
    "authenticated_expert_review_closure_projections": ("projected_at",),
    "authenticated_expert_review_revocation_projections": ("projected_at",),
}

_OBJECT_JSON_FIELDS: dict[str, tuple[str, ...]] = {
    "authenticated_expert_review_snapshot_registrations": (
        "registration_json",
        "snapshot_json",
    ),
    "authenticated_expert_review_receipts": ("receipt_json", "submission_json"),
    "authenticated_expert_review_closures": (
        "closure_json",
        "closure_request_json",
    ),
    "authenticated_expert_review_revocations": ("revocation_json",),
    "authenticated_expert_review_closure_projections": ("application_json",),
}

_ARRAY_JSON_FIELDS: dict[str, tuple[str, ...]] = {
    "authenticated_expert_review_snapshot_products": (
        "dependency_product_ids_json",
        "lineage_product_ids_json",
        "disagreement_sha256s_json",
    ),
    "authenticated_expert_review_snapshot_slots": ("producer_profile_ids_excluded_json",),
    "authenticated_expert_review_closures": (
        "rejected_work_ids_json",
        "rework_work_ids_json",
        "required_correction_ids_json",
    ),
}

_DOCUMENT_BINDINGS: dict[str, tuple[str, str, Mapping[str, str]]] = {
    "authenticated_expert_review_snapshot_registrations": (
        "snapshot_json",
        "snapshot",
        {
            "snapshot_id": "snapshot_id",
            "snapshot_sha256": "snapshot_sha256",
            "mission_id": "mission_id",
            "tenant_id": "tenant_id",
            "plan_id": "plan_id",
            "workspace_id": "workspace_id",
            "workspace_sha256": "workspace_sha256",
            "workspace_schema_version": "workspace_schema_version",
            "workspace_revision": "workspace_revision",
            "event_count": "workspace_event_count",
            "event_head_sha256": "workspace_event_head_sha256",
            "runtime_catalog_id": "runtime_catalog_id",
            "runtime_catalog_version": "runtime_catalog_version",
            "runtime_catalog_sha256": "runtime_catalog_sha256",
            "registry_sha256": "registry_sha256",
            "target_scope_sha256": "target_scope_sha256",
            "authority_snapshot_sha256": "authority_snapshot_sha256",
            "evidence_snapshot_sha256": "evidence_snapshot_sha256",
        },
    ),
    "authenticated_expert_review_receipts": (
        "receipt_json",
        "receipt",
        {
            "receipt_id": "receipt_id",
            "receipt_sha256": "receipt_sha256",
            "submission_id": "submission_id",
            "submission_sha256": "submission_sha256",
            "reviewer_subject": "reviewer_subject",
            "assertion_issuer": "assertion_issuer",
            "assertion_id": "assertion_id",
            "assertion_sha256": "assertion_sha256",
            "assertion_key_sha256": "assertion_key_sha256",
            "trust_policy_sha256": "trust_policy_sha256",
            "scope_grant_sha256": "scope_grant_sha256",
            "operation_intent_sha256": "operation_intent_sha256",
            "canonical_replay_key_sha256": "canonical_replay_key_sha256",
            "recorded_at": "recorded_at",
        },
    ),
    "authenticated_expert_review_closures": (
        "closure_json",
        "closure",
        {
            "closure_id": "closure_id",
            "closure_sha256": "closure_sha256",
            "closure_request_id": "closure_request_id",
            "closure_request_sha256": "closure_request_sha256",
            "snapshot_id": "snapshot_id",
            "snapshot_sha256": "snapshot_sha256",
            "review_set_sha256": "review_set_sha256",
            "disposition": "disposition",
            "closer_profile_id": "closer_profile_id",
            "closer_subject": "closer_subject",
            "assertion_issuer": "assertion_issuer",
            "assertion_id": "assertion_id",
            "assertion_sha256": "assertion_sha256",
            "assertion_key_sha256": "assertion_key_sha256",
            "trust_policy_sha256": "trust_policy_sha256",
            "scope_grant_sha256": "scope_grant_sha256",
            "operation_intent_sha256": "operation_intent_sha256",
            "canonical_replay_key_sha256": "canonical_replay_key_sha256",
            "closed_at": "closed_at",
        },
    ),
    "authenticated_expert_review_revocations": (
        "revocation_json",
        "revocation",
        {
            "revocation_id": "revocation_id",
            "revocation_sha256": "revocation_sha256",
            "closure_id": "closure_id",
            "closure_sha256": "closure_sha256",
            "reason_code": "reason_code",
            "control_profile_id": "control_profile_id",
            "control_subject": "control_subject",
            "assertion_issuer": "assertion_issuer",
            "assertion_id": "assertion_id",
            "assertion_sha256": "assertion_sha256",
            "operation_intent_sha256": "operation_intent_sha256",
            "canonical_replay_key_sha256": "canonical_replay_key_sha256",
            "revoked_at": "revoked_at",
        },
    ),
}


def _canonical_stored_json(value: Any, label: str, expected: type[Any]) -> Any:
    if type(value) is not str:
        raise StoreIntegrityError(f"Stored {label} is not text")
    try:
        parsed = loads_json_without_duplicate_keys(value)
        encoded = canonical_json(parsed)
    except (DuplicateJsonKeyError, TypeError, ValueError) as exc:
        raise StoreIntegrityError(f"Stored {label} is not canonical JSON") from exc
    if type(parsed) is not expected or encoded != value:
        raise StoreIntegrityError(f"Stored {label} is not canonical JSON")
    return parsed


def _rows(
    connection: sqlite3.Connection,
    table: str,
    mission_id: str | None,
) -> list[sqlite3.Row]:
    if mission_id is None:
        return connection.execute(f"SELECT * FROM {table}").fetchall()
    if table in {
        "authenticated_expert_review_snapshot_registrations",
        "authenticated_expert_review_receipts",
        "authenticated_expert_review_closures",
        "authenticated_expert_review_revocations",
        "authenticated_expert_review_replay_uses",
        "authenticated_expert_review_closure_projections",
        "authenticated_expert_review_revocation_projections",
    }:
        return connection.execute(
            f"SELECT * FROM {table} WHERE mission_id = ?",
            (mission_id,),
        ).fetchall()
    if table in {
        "authenticated_expert_review_snapshot_products",
        "authenticated_expert_review_snapshot_slots",
    }:
        return connection.execute(
            f"SELECT child.* FROM {table} AS child "
            "JOIN authenticated_expert_review_snapshot_registrations AS source "
            "ON source.snapshot_id = child.snapshot_id WHERE source.mission_id = ?",
            (mission_id,),
        ).fetchall()
    return connection.execute(
        "SELECT child.* FROM authenticated_expert_review_closure_receipts AS child "
        "JOIN authenticated_expert_review_closures AS source "
        "ON source.closure_id = child.closure_id WHERE source.mission_id = ?",
        (mission_id,),
    ).fetchall()


def _verify_row(table: str, row: sqlite3.Row) -> None:
    for field in _TEXT_FIELDS[table]:
        if type(row[field]) is not str or not is_ascii_text(row[field]):
            raise StoreIntegrityError(f"Stored {table}.{field} is not exact text")
        if (field.endswith("_sha256") or field.endswith("_hash")) and _SHA256.fullmatch(
            row[field]
        ) is None:
            raise StoreIntegrityError(f"Stored {table}.{field} is not a digest")
    for field in _INTEGER_FIELDS.get(table, ()):
        if type(row[field]) is not int:
            raise StoreIntegrityError(f"Stored {table}.{field} is not an exact integer")
    documents: dict[str, Any] = {}
    for field in _OBJECT_JSON_FIELDS.get(table, ()):
        documents[field] = _canonical_stored_json(row[field], f"{table}.{field}", dict)
    for field in _ARRAY_JSON_FIELDS.get(table, ()):
        documents[field] = _canonical_stored_json(row[field], f"{table}.{field}", list)
    if table in _DOCUMENT_BINDINGS:
        field, label, bindings = _DOCUMENT_BINDINGS[table]
        document = documents[field]
        if any(document.get(key) != row[column] for key, column in bindings.items()):
            raise StoreIntegrityError(f"Stored expert review {label} binding is invalid")
    try:
        if table == "authenticated_expert_review_snapshot_registrations":
            registration = AuthenticatedExpertReviewSnapshotRegistration.from_dict(
                documents["registration_json"]
            ).to_dict()
            snapshot = parse_expert_review_snapshot(documents["snapshot_json"]).to_dict()
            registration_bindings = {
                "registration_id": "registration_id",
                "registration_sha256": "registration_sha256",
                "snapshot_id": "snapshot_id",
                "snapshot_sha256": "snapshot_sha256",
                "mission_id": "mission_id",
                "tenant_id": "tenant_id",
                "active_plan_id": "plan_id",
                "active_plan_sha256": "active_plan_sha256",
                "active_plan_version": "active_plan_version",
                "mission_revision": "mission_revision",
                "workspace_id": "workspace_id",
                "workspace_sha256": "workspace_sha256",
                "workspace_schema_version": "workspace_schema_version",
                "workspace_revision": "workspace_revision",
                "workspace_event_count": "workspace_event_count",
                "workspace_event_head_sha256": "workspace_event_head_sha256",
                "runtime_catalog_id": "runtime_catalog_id",
                "runtime_catalog_version": "runtime_catalog_version",
                "runtime_catalog_sha256": "runtime_catalog_sha256",
                "registry_sha256": "registry_sha256",
                "target_scope_sha256": "target_scope_sha256",
                "authority_snapshot_sha256": "authority_snapshot_sha256",
                "evidence_snapshot_sha256": "evidence_snapshot_sha256",
                "registrar_profile_id": "registrar_profile_id",
                "registrar_subject": "registrar_subject",
                "assertion_issuer": "assertion_issuer",
                "assertion_id": "assertion_id",
                "assertion_sha256": "assertion_sha256",
                "assertion_key_sha256": "assertion_key_sha256",
                "trust_policy_sha256": "trust_policy_sha256",
                "scope_grant_sha256": "scope_grant_sha256",
                "operation_intent_sha256": "operation_intent_sha256",
                "canonical_replay_key_sha256": "canonical_replay_key_sha256",
                "domain_request_sha256": "domain_request_sha256",
                "registered_at": "registered_at",
            }
            if any(
                registration[key] != row[column] for key, column in registration_bindings.items()
            ):
                raise StoreIntegrityError("Stored review registration binding is invalid")
            if (
                registration["snapshot_id"] != snapshot["snapshot_id"]
                or registration["snapshot_sha256"] != snapshot["snapshot_sha256"]
            ):
                raise StoreIntegrityError("Stored review registration snapshot is invalid")
        elif table == "authenticated_expert_review_receipts":
            receipt = parse_authenticated_expert_review_receipt(documents["receipt_json"]).to_dict()
            submission = parse_expert_review_submission(documents["submission_json"]).to_dict()
            if receipt["submission"] != submission:
                raise StoreIntegrityError("Stored review receipt submission is invalid")
            if any(
                submission[key] != row[column]
                for key, column in {
                    "submission_id": "submission_id",
                    "submission_sha256": "submission_sha256",
                    "snapshot_id": "snapshot_id",
                    "work_id": "work_id",
                    "product_id": "product_id",
                    "product_sha256": "product_sha256",
                    "reviewer_profile_id": "reviewer_profile_id",
                    "reviewer_role": "reviewer_role",
                }.items()
            ):
                raise StoreIntegrityError("Stored review submission binding is invalid")
        elif table == "authenticated_expert_review_closures":
            closure = parse_expert_review_closure_certificate(documents["closure_json"]).to_dict()
            request = parse_expert_review_closure_request(
                documents["closure_request_json"]
            ).to_dict()
            if (
                closure["closure_request_id"] != request["closure_request_id"]
                or closure["closure_request_sha256"] != request["closure_request_sha256"]
            ):
                raise StoreIntegrityError("Stored closure request binding is invalid")
            for document_field, row_field in (
                ("rejected_work_ids", "rejected_work_ids_json"),
                ("rework_work_ids", "rework_work_ids_json"),
                ("required_correction_ids", "required_correction_ids_json"),
            ):
                if closure[document_field] != documents[row_field]:
                    raise StoreIntegrityError("Stored closure disposition material is inconsistent")
        elif table == "authenticated_expert_review_revocations":
            parse_expert_review_closure_revocation(documents["revocation_json"])
        elif table == "authenticated_expert_review_closure_projections":
            application = parse_expert_workspace_closure_application(
                documents["application_json"]
            ).to_dict()
            if any(
                application[key] != row[column]
                for key, column in {
                    "workspace_id": "workspace_id",
                    "closure_id": "closure_id",
                    "closure_sha256": "closure_sha256",
                    "application_id": "application_id",
                    "application_sha256": "application_sha256",
                    "applied_at": "projected_at",
                }.items()
            ):
                raise StoreIntegrityError("Stored closure projection binding is invalid")
    except StoreIntegrityError:
        raise
    except Exception as exc:
        raise StoreIntegrityError(f"Stored {table} document is invalid") from exc
    if "consumed_at" in _TEXT_FIELDS[table]:
        parse_timestamp(row["consumed_at"], f"{table}.consumed_at")
    if (
        table == "authenticated_expert_review_replay_uses"
        and row["operation"] not in EXPERT_REVIEW_OPERATIONS
    ):
        raise StoreIntegrityError("Stored expert review replay operation is invalid")
    if table == "authenticated_expert_review_snapshot_products" and row["review_required"] not in {
        0,
        1,
    }:
        raise StoreIntegrityError("Stored expert review required flag is invalid")


def _orphan_count(connection: sqlite3.Connection, query: str) -> int:
    value = connection.execute(query).fetchone()[0]
    if type(value) is not int:
        raise StoreIntegrityError("Expert review orphan count is not an integer")
    return value


def _verify_normalized_snapshot_links(connection: sqlite3.Connection) -> None:
    registrations = connection.execute(
        "SELECT snapshot_id, snapshot_json FROM authenticated_expert_review_snapshot_registrations"
    ).fetchall()
    for registration in registrations:
        snapshot = parse_expert_review_snapshot(
            _canonical_stored_json(
                registration["snapshot_json"],
                "authenticated_expert_review_snapshot_registrations.snapshot_json",
                dict,
            )
        ).to_dict()
        product_rows = connection.execute(
            "SELECT * FROM authenticated_expert_review_snapshot_products WHERE snapshot_id = ?",
            (registration["snapshot_id"],),
        ).fetchall()
        products = [
            {
                "attempt_number": row["attempt_number"],
                "command_id": row["command_id"],
                "dependency_product_ids": _canonical_stored_json(
                    row["dependency_product_ids_json"],
                    "snapshot product dependencies",
                    list,
                ),
                "disagreement_sha256s": _canonical_stored_json(
                    row["disagreement_sha256s_json"],
                    "snapshot product disagreements",
                    list,
                ),
                "envelope_id": row["envelope_id"],
                "envelope_sha256": row["envelope_sha256"],
                "fencing_token": row["fencing_token"],
                "lineage_product_ids": _canonical_stored_json(
                    row["lineage_product_ids_json"],
                    "snapshot product lineage",
                    list,
                ),
                "producer_profile_id": row["producer_profile_id"],
                "product_id": row["product_id"],
                "product_sha256": row["product_sha256"],
                "product_type": row["product_type"],
                "review_required": bool(row["review_required"]),
                "work_id": row["work_id"],
            }
            for row in product_rows
        ]
        slot_rows = connection.execute(
            "SELECT * FROM authenticated_expert_review_snapshot_slots WHERE snapshot_id = ?",
            (registration["snapshot_id"],),
        ).fetchall()
        slots = [
            {
                "policy_template_id": row["policy_template_id"],
                "policy_template_sha256": row["policy_template_sha256"],
                "producer_profile_ids_excluded": _canonical_stored_json(
                    row["producer_profile_ids_excluded_json"],
                    "snapshot slot producer exclusions",
                    list,
                ),
                "product_id": row["product_id"],
                "product_sha256": row["product_sha256"],
                "profile_sha256": row["profile_sha256"],
                "registry_sha256": row["registry_sha256"],
                "reviewer_profile_id": row["reviewer_profile_id"],
                "reviewer_role": row["reviewer_role"],
                "work_id": row["work_id"],
            }
            for row in slot_rows
        ]
        if sorted(map(canonical_json, products)) != sorted(
            map(canonical_json, snapshot["products"])
        ) or sorted(map(canonical_json, slots)) != sorted(
            map(canonical_json, snapshot["review_slots"])
        ):
            raise StoreIntegrityError(
                "Authenticated expert review normalized snapshot is inconsistent"
            )


def _verify_closure_receipt_links(connection: sqlite3.Connection) -> None:
    closures = connection.execute(
        "SELECT closure_id, closure_json, closure_request_json, review_set_sha256 "
        "FROM authenticated_expert_review_closures"
    ).fetchall()
    for row in closures:
        closure = parse_expert_review_closure_certificate(
            _canonical_stored_json(row["closure_json"], "closure document", dict)
        ).to_dict()
        request = parse_expert_review_closure_request(
            _canonical_stored_json(
                row["closure_request_json"],
                "closure request document",
                dict,
            )
        ).to_dict()
        links = connection.execute(
            "SELECT link.receipt_ordinal, link.receipt_id, link.receipt_sha256, "
            "receipt.receipt_json FROM authenticated_expert_review_closure_receipts AS link "
            "JOIN authenticated_expert_review_receipts AS receipt "
            "ON receipt.receipt_id = link.receipt_id "
            "AND receipt.receipt_sha256 = link.receipt_sha256 "
            "WHERE link.closure_id = ? ORDER BY link.receipt_ordinal",
            (row["closure_id"],),
        ).fetchall()
        if [item["receipt_ordinal"] for item in links] != list(range(len(links))):
            raise StoreIntegrityError("Stored closure receipt order is invalid")
        bindings = [
            {
                "receipt_id": item["receipt_id"],
                "receipt_sha256": item["receipt_sha256"],
            }
            for item in links
        ]
        receipts = tuple(
            parse_authenticated_expert_review_receipt(
                _canonical_stored_json(item["receipt_json"], "review receipt", dict)
            )
            for item in links
        )
        if (
            bindings != request["review_receipts"]
            or [item["receipt_id"] for item in bindings] != closure["review_receipt_ids"]
            or review_set_sha256(receipts) != row["review_set_sha256"]
        ):
            raise StoreIntegrityError(
                "Authenticated expert review closure receipt set is inconsistent"
            )


def _stored_assertion_for_domain(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> PrincipalAssertion:
    use = connection.execute(
        "SELECT assertion_json FROM principal_assertion_uses "
        "WHERE issuer = ? AND assertion_id = ? AND mission_id = ?",
        (row["assertion_issuer"], row["assertion_id"], row["mission_id"]),
    ).fetchone()
    if use is None or type(use["assertion_json"]) is not str:
        raise StoreIntegrityError("Expert review assertion source is absent")
    try:
        return PrincipalAssertion.from_dict(
            loads_json_without_duplicate_keys(use["assertion_json"])
        )
    except Exception as exc:
        raise StoreIntegrityError("Expert review assertion source is invalid") from exc


def _verify_reconstructed_authority(connection: sqlite3.Connection) -> None:
    def verify(
        row: sqlite3.Row,
        operation: PrincipalOperation,
        intent: Mapping[str, Any],
        request_material: Mapping[str, Any],
    ) -> None:
        assertion = _stored_assertion_for_domain(connection, row)
        intent_sha256 = compute_operation_intent_hash(operation, dict(intent))
        domain_request_sha256 = _canonical_sha256(
            {
                "domain": _REQUEST_DOMAIN,
                "operation": operation.value,
                "request": dict(request_material),
                "schema_version": 1,
            }
        )
        try:
            replay_sha256 = expert_review_canonical_replay_key_sha256(
                assertion,
                operation=operation,
                operation_intent_sha256=intent_sha256,
                domain_request_sha256=domain_request_sha256,
            )
        except StoreError as exc:
            raise StoreIntegrityError(
                "Expert review assertion operation source is inconsistent"
            ) from exc
        if (
            row["operation_intent_sha256"] != intent_sha256
            or row["domain_request_sha256"] != domain_request_sha256
            or row["canonical_replay_key_sha256"] != replay_sha256
        ):
            raise StoreIntegrityError(
                "Authenticated expert review authority derivation is inconsistent"
            )

    registrations = connection.execute(
        "SELECT * FROM authenticated_expert_review_snapshot_registrations"
    ).fetchall()
    registration_by_snapshot: dict[str, tuple[sqlite3.Row, ExpertReviewSnapshot]] = {}
    for row in registrations:
        try:
            snapshot = parse_expert_review_snapshot(
                _canonical_stored_json(row["snapshot_json"], "review snapshot", dict)
            )
            intent = expert_review_snapshot_registration_intent(
                snapshot,
                active_plan_sha256=row["active_plan_sha256"],
                active_plan_version=row["active_plan_version"],
                mission_revision=row["mission_revision"],
                principal_profile_id=row["registrar_profile_id"],
            )
            verify(
                row,
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                intent,
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "snapshot_sha256": snapshot.snapshot_sha256,
                },
            )
        except StoreIntegrityError:
            raise
        except Exception as exc:
            raise StoreIntegrityError(
                "Authenticated review registration source cannot be reconstructed"
            ) from exc
        registration_by_snapshot[snapshot.snapshot_id] = (row, snapshot)

    receipts_by_id: dict[str, AuthenticatedExpertReviewReceipt] = {}
    for row in connection.execute("SELECT * FROM authenticated_expert_review_receipts").fetchall():
        source = registration_by_snapshot.get(row["snapshot_id"])
        if source is None:
            raise StoreIntegrityError("Review receipt registration source is absent")
        registration, snapshot = source
        try:
            receipt = parse_authenticated_expert_review_receipt(
                _canonical_stored_json(row["receipt_json"], "review receipt", dict)
            )
            submission = parse_expert_review_submission(
                _canonical_stored_json(row["submission_json"], "review submission", dict)
            )
            intent = expert_work_product_review_intent(
                snapshot,
                submission,
                active_plan_sha256=registration["active_plan_sha256"],
                active_plan_version=registration["active_plan_version"],
                mission_revision=registration["mission_revision"],
                principal_profile_id=row["reviewer_profile_id"],
            )
            verify(
                row,
                PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
                intent,
                {
                    "snapshot_sha256": snapshot.snapshot_sha256,
                    "submission_sha256": submission.submission_sha256,
                },
            )
        except StoreIntegrityError:
            raise
        except Exception as exc:
            raise StoreIntegrityError(
                "Authenticated review receipt source cannot be reconstructed"
            ) from exc
        receipts_by_id[receipt.receipt_id] = receipt

    closure_by_id: dict[
        str,
        tuple[sqlite3.Row, ExpertReviewClosureCertificate, sqlite3.Row],
    ] = {}
    for row in connection.execute("SELECT * FROM authenticated_expert_review_closures").fetchall():
        source = registration_by_snapshot.get(row["snapshot_id"])
        if source is None:
            raise StoreIntegrityError("Review closure registration source is absent")
        registration, snapshot = source
        links = connection.execute(
            "SELECT receipt_id FROM authenticated_expert_review_closure_receipts "
            "WHERE closure_id = ? ORDER BY receipt_ordinal",
            (row["closure_id"],),
        ).fetchall()
        try:
            receipts = tuple(receipts_by_id[item["receipt_id"]] for item in links)
            request = parse_expert_review_closure_request(
                _canonical_stored_json(row["closure_request_json"], "review closure request", dict)
            )
            closure = parse_expert_review_closure_certificate(
                _canonical_stored_json(row["closure_json"], "review closure", dict)
            )
            intent = expert_workspace_review_close_intent(
                snapshot,
                request,
                receipts,
                active_plan_sha256=registration["active_plan_sha256"],
                active_plan_version=registration["active_plan_version"],
                mission_revision=registration["mission_revision"],
                principal_profile_id=row["closer_profile_id"],
            )
            verify(
                row,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
                intent,
                {
                    "closure_request_sha256": request.closure_request_sha256,
                    "review_set_sha256": review_set_sha256(receipts),
                    "snapshot_sha256": snapshot.snapshot_sha256,
                },
            )
        except StoreIntegrityError:
            raise
        except Exception as exc:
            raise StoreIntegrityError(
                "Authenticated review closure source cannot be reconstructed"
            ) from exc
        closure_by_id[closure.closure_id] = (row, closure, registration)

    for row in connection.execute(
        "SELECT * FROM authenticated_expert_review_revocations"
    ).fetchall():
        source = closure_by_id.get(row["closure_id"])
        if source is None:
            raise StoreIntegrityError("Review revocation closure source is absent")
        _closure_row, closure, registration = source
        try:
            snapshot = registration_by_snapshot[registration["snapshot_id"]][1]
            intent = expert_workspace_review_revoke_intent(
                closure,
                active_plan_id=snapshot.to_dict()["plan_id"],
                active_plan_sha256=registration["active_plan_sha256"],
                active_plan_version=registration["active_plan_version"],
                mission_id=row["mission_id"],
                mission_revision=registration["mission_revision"],
                principal_profile_id=row["control_profile_id"],
                reason_code=row["reason_code"],
            )
            if row["revocation_core_sha256"] != intent["revocation_core_sha256"]:
                raise StoreIntegrityError("Review revocation core is inconsistent")
            verify(
                row,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
                intent,
                {
                    "closure_sha256": closure.closure_sha256,
                    "reason_code": row["reason_code"],
                    "revocation_core_sha256": intent["revocation_core_sha256"],
                },
            )
        except StoreIntegrityError:
            raise
        except Exception as exc:
            raise StoreIntegrityError(
                "Authenticated review revocation source cannot be reconstructed"
            ) from exc


def _verify_domain_authority_links(connection: sqlite3.Connection) -> None:
    domain_tables = (
        (
            "authenticated_expert_review_snapshot_registrations",
            PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER.value,
            "registration_id",
            "registration_sha256",
            "registrar_profile_id",
            "registrar_subject",
        ),
        (
            "authenticated_expert_review_receipts",
            PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW.value,
            "receipt_id",
            "receipt_sha256",
            "reviewer_profile_id",
            "reviewer_subject",
        ),
        (
            "authenticated_expert_review_closures",
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE.value,
            "closure_id",
            "closure_sha256",
            "closer_profile_id",
            "closer_subject",
        ),
        (
            "authenticated_expert_review_revocations",
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE.value,
            "revocation_id",
            "revocation_sha256",
            "control_profile_id",
            "control_subject",
        ),
    )
    for table, operation, result_id, result_sha256, profile_id, subject in domain_tables:
        mismatches = _orphan_count(
            connection,
            f"SELECT COUNT(*) FROM {table} AS result "
            "LEFT JOIN authenticated_expert_review_replay_uses AS replay "
            "ON replay.canonical_replay_key_sha256 = result.canonical_replay_key_sha256 "
            "LEFT JOIN principal_assertion_uses AS use "
            "ON use.issuer = result.assertion_issuer "
            "AND use.assertion_id = result.assertion_id "
            "AND use.mission_id = result.mission_id "
            "WHERE replay.canonical_replay_key_sha256 IS NULL OR use.issuer IS NULL "
            f"OR replay.operation != '{operation}' "
            f"OR replay.result_id != result.{result_id} "
            f"OR replay.result_sha256 != result.{result_sha256} "
            "OR replay.domain_request_sha256 != result.domain_request_sha256 "
            "OR replay.assertion_issuer != result.assertion_issuer "
            "OR replay.assertion_id != result.assertion_id "
            "OR replay.mission_id != result.mission_id "
            "OR replay.consumed_at != result.consumed_at "
            "OR use.operation != replay.operation "
            "OR use.assertion_hash != result.assertion_sha256 "
            f"OR use.principal_profile_id != result.{profile_id} "
            f"OR use.subject != result.{subject} "
            "OR use.key_hash != result.assertion_key_sha256 "
            "OR use.trust_policy_hash != result.trust_policy_sha256 "
            "OR use.scope_grant_hash != result.scope_grant_sha256 "
            "OR use.signed_intent_hash != result.operation_intent_sha256 "
            "OR use.domain_request_hash != result.domain_request_sha256 "
            "OR use.idempotency_key_hash != result.canonical_replay_key_sha256 "
            "OR use.consumed_at != result.consumed_at",
        )
        if mismatches:
            raise StoreIntegrityError(
                "Authenticated expert review authority custody is inconsistent"
            )


def _verify_no_orphans(connection: sqlite3.Connection) -> None:
    queries = (
        "SELECT COUNT(*) FROM authenticated_expert_review_replay_uses AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM principal_assertion_uses AS use "
        "WHERE use.issuer = item.assertion_issuer "
        "AND use.assertion_id = item.assertion_id AND use.mission_id = item.mission_id)",
        "SELECT COUNT(*) FROM authenticated_expert_review_snapshot_products AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_snapshot_registrations "
        "AS source WHERE source.snapshot_id = item.snapshot_id)",
        "SELECT COUNT(*) FROM authenticated_expert_review_snapshot_slots AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_snapshot_products "
        "AS source WHERE source.snapshot_id = item.snapshot_id "
        "AND source.work_id = item.work_id AND source.product_id = item.product_id "
        "AND source.product_sha256 = item.product_sha256)",
        "SELECT COUNT(*) FROM authenticated_expert_review_receipts AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_snapshot_registrations "
        "AS registration WHERE registration.mission_id = item.mission_id "
        "AND registration.snapshot_id = item.snapshot_id "
        "AND registration.snapshot_sha256 = item.snapshot_sha256) OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_snapshot_slots AS source "
        "WHERE source.snapshot_id = item.snapshot_id AND source.work_id = item.work_id "
        "AND source.product_id = item.product_id "
        "AND source.product_sha256 = item.product_sha256 "
        "AND source.reviewer_profile_id = item.reviewer_profile_id "
        "AND source.reviewer_role = item.reviewer_role)",
        "SELECT COUNT(*) FROM authenticated_expert_review_closures AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_snapshot_registrations "
        "AS source WHERE source.mission_id = item.mission_id "
        "AND source.snapshot_id = item.snapshot_id "
        "AND source.snapshot_sha256 = item.snapshot_sha256)",
        "SELECT COUNT(*) FROM authenticated_expert_review_closure_receipts AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_closures AS source "
        "WHERE source.closure_id = item.closure_id) OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_receipts AS source "
        "JOIN authenticated_expert_review_closures AS closure "
        "ON closure.closure_id = item.closure_id "
        "WHERE source.receipt_id = item.receipt_id "
        "AND source.receipt_sha256 = item.receipt_sha256 "
        "AND source.snapshot_id = closure.snapshot_id)",
        "SELECT COUNT(*) FROM authenticated_expert_review_revocations AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_closures AS source "
        "WHERE source.mission_id = item.mission_id "
        "AND source.closure_id = item.closure_id "
        "AND source.closure_sha256 = item.closure_sha256)",
        "SELECT COUNT(*) FROM authenticated_expert_review_closure_projections AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_closures AS source "
        "WHERE source.mission_id = item.mission_id "
        "AND source.closure_id = item.closure_id "
        "AND source.closure_sha256 = item.closure_sha256)",
        "SELECT COUNT(*) FROM authenticated_expert_review_revocation_projections AS item "
        "WHERE NOT EXISTS (SELECT 1 FROM authenticated_expert_review_revocations AS source "
        "WHERE source.mission_id = item.mission_id "
        "AND source.closure_id = item.closure_id "
        "AND source.revocation_id = item.revocation_id "
        "AND source.revocation_sha256 = item.revocation_sha256) OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_closure_projections AS closure "
        "WHERE closure.closure_id = item.closure_id "
        "AND closure.workspace_id = item.workspace_id)",
    )
    if any(_orphan_count(connection, query) for query in queries):
        raise StoreIntegrityError("Authenticated expert review custody contains an orphan")


def _verify_replay_links(connection: sqlite3.Connection) -> None:
    mismatches = _orphan_count(
        connection,
        "SELECT COUNT(*) FROM authenticated_expert_review_replay_uses AS replay "
        "LEFT JOIN principal_assertion_uses AS use "
        "ON use.issuer = replay.assertion_issuer "
        "AND use.assertion_id = replay.assertion_id AND use.mission_id = replay.mission_id "
        "LEFT JOIN principal_assertion_effects AS effect "
        "ON effect.issuer = replay.assertion_issuer "
        "AND effect.assertion_id = replay.assertion_id "
        "AND effect.mission_id = replay.mission_id "
        "AND effect.effect_kind = replay.operation AND effect.effect_id = replay.result_id "
        "WHERE use.issuer IS NULL OR effect.issuer IS NULL "
        "OR use.operation != replay.operation "
        "OR use.domain_request_hash != replay.domain_request_sha256 "
        "OR use.idempotency_key_hash != replay.canonical_replay_key_sha256 "
        "OR use.consumed_at != replay.consumed_at "
        "OR json_extract(effect.effect_json, '$.payload.result_sha256') "
        "IS NOT replay.result_sha256 "
        "OR effect.recorded_at != replay.consumed_at",
    )
    if mismatches:
        raise StoreIntegrityError("Authenticated expert review replay custody is inconsistent")
    domain_mismatches = _orphan_count(
        connection,
        "SELECT COUNT(*) FROM authenticated_expert_review_replay_uses AS replay "
        "WHERE (replay.operation = 'sunderkey.expert.review.snapshot.register.v1' "
        "AND (replay.result_kind != 'snapshot_registration' OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_snapshot_registrations AS result "
        "WHERE result.registration_id = replay.result_id "
        "AND result.registration_sha256 = replay.result_sha256 "
        "AND result.canonical_replay_key_sha256 = replay.canonical_replay_key_sha256))) "
        "OR (replay.operation = 'sunderkey.expert.work-product.review.v1' "
        "AND (replay.result_kind != 'work_product_review' OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_receipts AS result "
        "WHERE result.receipt_id = replay.result_id "
        "AND result.receipt_sha256 = replay.result_sha256 "
        "AND result.canonical_replay_key_sha256 = replay.canonical_replay_key_sha256))) "
        "OR (replay.operation = 'sunderkey.expert.workspace.review.close.v1' "
        "AND (replay.result_kind != 'workspace_review_close' OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_closures AS result "
        "WHERE result.closure_id = replay.result_id "
        "AND result.closure_sha256 = replay.result_sha256 "
        "AND result.canonical_replay_key_sha256 = replay.canonical_replay_key_sha256))) "
        "OR (replay.operation = 'sunderkey.expert.workspace.review.revoke.v1' "
        "AND (replay.result_kind != 'workspace_review_revoke' OR NOT EXISTS "
        "(SELECT 1 FROM authenticated_expert_review_revocations AS result "
        "WHERE result.revocation_id = replay.result_id "
        "AND result.revocation_sha256 = replay.result_sha256 "
        "AND result.canonical_replay_key_sha256 = replay.canonical_replay_key_sha256)))",
    )
    if domain_mismatches:
        raise StoreIntegrityError(
            "Authenticated expert review replay result custody is inconsistent"
        )


def _verify_projection_links(connection: sqlite3.Connection) -> None:
    closure_mismatches = _orphan_count(
        connection,
        "SELECT COUNT(*) FROM authenticated_expert_review_closure_projections AS item "
        "JOIN authenticated_expert_review_closures AS closure "
        "ON closure.closure_id = item.closure_id "
        "JOIN store_identity AS identity ON identity.singleton_id = 1 "
        "WHERE json_extract(item.application_json, '$.mission_store_id') "
        "!= identity.store_id "
        "OR json_extract(item.application_json, '$.snapshot_id') != closure.snapshot_id "
        "OR json_extract(item.application_json, '$.snapshot_sha256') "
        "!= closure.snapshot_sha256 "
        "OR json_extract(item.application_json, '$.disposition') != closure.disposition",
    )
    revocation_mismatches = _orphan_count(
        connection,
        "SELECT COUNT(*) FROM authenticated_expert_review_revocation_projections AS item "
        "JOIN authenticated_expert_review_revocations AS revocation "
        "ON revocation.revocation_id = item.revocation_id "
        "WHERE item.projected_at < revocation.revoked_at",
    )
    if closure_mismatches or revocation_mismatches:
        raise StoreIntegrityError(
            "Authenticated expert review workspace projection is inconsistent"
        )


def verify_authenticated_expert_review_store(
    connection: sqlite3.Connection,
    mission_id: str | None = None,
) -> None:
    """Verify exact types, canonical records, relationships, and replay custody."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a SQLite connection")
    if mission_id is not None and (type(mission_id) is not str or not is_ascii_text(mission_id)):
        raise StoreIntegrityError("Expert review mission filter is invalid")
    prior_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    try:
        for table in _TEXT_FIELDS:
            for row in _rows(connection, table, mission_id):
                _verify_row(table, row)
        _verify_normalized_snapshot_links(connection)
        _verify_closure_receipt_links(connection)
        _verify_no_orphans(connection)
        _verify_reconstructed_authority(connection)
        _verify_domain_authority_links(connection)
        _verify_replay_links(connection)
        _verify_projection_links(connection)
    finally:
        connection.row_factory = prior_factory


__all__ = [
    "AuthenticatedExpertReviewSnapshotRegistration",
    "EXPERT_REVIEW_OPERATIONS",
    "SQLiteAuthenticatedExpertReviewCustody",
    "VerifiedExpertReviewClosure",
    "VerifiedExpertReviewRevocation",
    "build_authenticated_expert_review_snapshot_registration",
    "expert_review_canonical_replay_key_sha256",
    "expert_review_snapshot_registration_intent",
    "expert_work_product_review_intent",
    "expert_workspace_review_close_intent",
    "expert_workspace_review_revoke_intent",
    "verify_authenticated_expert_review_store",
]
