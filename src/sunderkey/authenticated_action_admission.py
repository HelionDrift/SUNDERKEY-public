"""Durable authenticated admission for independently resolved actions.

Portable Phase 195 records are evidence and interchange objects. They never
authorize execution. Only this service can persist an admission, and only a
fresh ``CurrentActionAdmission`` returned by ``verify_current`` represents a
point-of-use result. The service owns its authority dependency and supplies the
same locked SQLite connection to every authoritative check.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .action_admission_contracts import (
    ActionAdmissionRequest,
    AdmissionStatus,
    ApprovalBinding,
    ArtifactBinding,
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    EvidenceObligation,
    HealthEvidence,
    RequestedAction,
    RestorationDuties,
    StopConditions,
    TargetBinding,
    TargetEnvironment,
    WorkerSession,
    evaluate_action_admission,
)
from .action_admission_contracts import ActionTier as AdmissionActionTier
from .action_resolution import (
    NO_EFFECTS,
    ActionAdmissionRevocation,
    ActionAuthorizationQuorum,
    ActionParameterSet,
    ActionProposalResolution,
    ActionResolutionError,
    ActionTier,
    AuthenticatedActionAdmissionReceipt,
    AuthorizationRole,
    ExecutableActionCatalog,
    ExpertReviewClosureVerifier,
    TargetActionDescriptor,
    _address_record,
    _assert_authorization_binding,
    _assert_authorization_current_at,
    _authorization,
    _catalog_action,
    _resolved_action_sha256,
    _verify_current_expert_review_closure,
    parse_action_admission_revocation,
    parse_action_authorization_quorum,
    parse_action_parameter_set,
    parse_action_proposal_resolution,
    parse_authenticated_action_admission_receipt,
    parse_executable_action_catalog,
    parse_target_action_descriptor,
)
from .errors import StoreConflictError, StoreError, StoreIntegrityError
from .expert_review import (
    AuthenticatedExpertReviewReceipt,
    ClosureDisposition,
    ExpertReviewClosureCertificate,
    ExpertReviewClosureRequest,
    ExpertReviewClosureRevocation,
    ExpertReviewRecordSet,
    ExpertReviewSnapshot,
)
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry

AUTHORITY_STATE_DOMAIN = "sunderkey.action-admission-authority-state.v1"
COMMAND_DOMAIN = "sunderkey.action-admission-command.v1"
RESOLUTION_INTENT_DOMAIN = "sunderkey.action-resolution-authorization-intent.v1"
QUORUM_INTENT_DOMAIN = "sunderkey.action-quorum-authorization-intent.v1"
ADMISSION_INTENT_DOMAIN = "sunderkey.action-admission-authorization-intent.v1"
REVOCATION_INTENT_DOMAIN = "sunderkey.action-admission-revocation-intent.v1"
CUSTODY_DOMAIN = "sunderkey.authenticated-action-admission-custody.v1"
CURRENT_PROOF_DOMAIN = "sunderkey.current-action-admission-proof.v1"
CUSTODY_APPLICATION_ID = 0x534B4131
CUSTODY_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ActionAdmissionCommand:
    """Caller intent used only to select authoritative typed state."""

    tenant_id: str
    mission_id: str
    proposal_product_id: str
    action_type: str
    action_tier: ActionTier
    idempotency_key_sha256: str

    def __post_init__(self) -> None:
        from .action_resolution import _identifier, _sha256

        for field in ("tenant_id", "mission_id", "proposal_product_id", "action_type"):
            _identifier(getattr(self, field), field)
        object.__setattr__(self, "action_tier", ActionTier(self.action_tier))
        if self.action_tier is ActionTier.R5:
            raise ActionResolutionError("R5 actions are categorically rejected")
        _sha256(self.idempotency_key_sha256, "idempotency key hash")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_tier": self.action_tier.value,
            "action_type": self.action_type,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "mission_id": self.mission_id,
            "proposal_product_id": self.proposal_product_id,
            "tenant_id": self.tenant_id,
        }

    @property
    def command_sha256(self) -> str:
        return _canonical_sha256(
            {"domain": COMMAND_DOMAIN, "command": self.to_dict()}
        )


@dataclass(frozen=True, slots=True)
class CurrentActionAdmissionMaterial:
    """Current typed inputs read by the service-owned authority."""

    records: ExpertReviewRecordSet
    registry: ExpertRegistry
    catalog: ExecutableActionCatalog
    parameters: ActionParameterSet
    target: TargetActionDescriptor
    resolver_profile_id: str
    resolver_subject: str
    context: ContextBinding
    worker_session: WorkerSession
    credential_lease: CredentialLease
    health: HealthEvidence
    budget: BudgetBinding
    evidence_obligations: tuple[EvidenceObligation, ...]
    stop_conditions: StopConditions
    restoration_duties: RestorationDuties
    resolved_at: str
    approved_at: str
    quorum_expires_at: str
    requested_at: str
    expires_at: str
    catalog_authority_sha256: str
    authority_revision_sha256: str


@dataclass(frozen=True, slots=True)
class CurrentActionAuthorityState:
    """Exact current state returned after an authoritative point-of-use check."""

    review_evidence_sha256: str
    catalog_id: str
    catalog_sha256: str
    catalog_version: str
    catalog_authority_sha256: str
    authority_revision_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "authority_revision_sha256": self.authority_revision_sha256,
            "catalog_authority_sha256": self.catalog_authority_sha256,
            "catalog_id": self.catalog_id,
            "catalog_sha256": self.catalog_sha256,
            "catalog_version": self.catalog_version,
            "review_evidence_sha256": self.review_evidence_sha256,
        }

    @property
    def state_sha256(self) -> str:
        return _canonical_sha256(
            {"domain": AUTHORITY_STATE_DOMAIN, "state": self.to_dict()}
        )


@dataclass(frozen=True, slots=True)
class StoredActionAdmission:
    """Immutable custody supplied to the owned authority for current checks."""

    resolution: ActionProposalResolution
    quorum: ActionAuthorizationQuorum
    request: ActionAdmissionRequest
    receipt: AuthenticatedActionAdmissionReceipt
    resolver_authorization: Mapping[str, Any]
    review_records: ExpertReviewRecordSet
    review_evidence_document: Mapping[str, Any]
    review_evidence_sha256: str
    authority_state: CurrentActionAuthorityState


class ActionAdmissionAuthority(Protocol):
    """Trusted adapter owned by one admission service instance.

    Implementations must check MissionStore state, trust policy, assertion
    signatures, scope, replay state, catalog currentness, and revocation using
    the supplied transaction connection. Returning a mapping is an attestation
    by this service-owned dependency, not caller supplied evidence.
    """

    def load_current_material(
        self,
        connection: sqlite3.Connection,
        command: ActionAdmissionCommand,
        evaluated_at: str,
    ) -> CurrentActionAdmissionMaterial: ...

    def authorize_resolution(
        self,
        connection: sqlite3.Connection,
        resolution: ActionProposalResolution,
        operation_intent_sha256: str,
        evaluated_at: str,
    ) -> Mapping[str, Any]: ...

    def authorize_quorum(
        self,
        connection: sqlite3.Connection,
        resolution: ActionProposalResolution,
        operation_intents: Mapping[AuthorizationRole, str],
        evaluated_at: str,
    ) -> Sequence[Mapping[str, Any]]: ...

    def authorize_admission(
        self,
        connection: sqlite3.Connection,
        resolution: ActionProposalResolution,
        quorum: ActionAuthorizationQuorum,
        request: ActionAdmissionRequest,
        operation_intent_sha256: str,
        evaluated_at: str,
    ) -> Mapping[str, Any]: ...

    def verify_stored_current(
        self,
        connection: sqlite3.Connection,
        stored: StoredActionAdmission,
        evaluated_at: str,
    ) -> CurrentActionAuthorityState: ...

    def authorize_revocation(
        self,
        connection: sqlite3.Connection,
        stored: StoredActionAdmission,
        reason_code: str,
        operation_intent_sha256: str,
        revoked_at: str,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True, init=False)
class CurrentActionAdmission:
    """Nonportable proof of a current service-owned verification."""

    receipt: AuthenticatedActionAdmissionReceipt
    verified_at: str
    custody_sha256: str
    _proof: bytes

    def __init__(
        self,
        *,
        receipt: AuthenticatedActionAdmissionReceipt,
        verified_at: str,
        custody_sha256: str,
        _proof: bytes,
    ) -> None:
        if type(_proof) is not bytes or len(_proof) != hashlib.sha256().digest_size:
            raise ActionResolutionError(
                "Current action admission must be issued by its owning service"
            )
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "verified_at", verified_at)
        object.__setattr__(self, "custody_sha256", custody_sha256)
        object.__setattr__(self, "_proof", _proof)


def _review_record_set_document(records: ExpertReviewRecordSet) -> dict[str, Any]:
    return {
        "closure": records.closure.to_dict(),
        "closure_request": records.closure_request.to_dict(),
        "receipts": [item.to_dict() for item in records.receipts],
        "revocation": None if records.revocation is None else records.revocation.to_dict(),
        "snapshot": records.snapshot.to_dict(),
    }


def _review_record_set_from_document(raw: Any) -> ExpertReviewRecordSet:
    if not isinstance(raw, Mapping) or set(raw) != {
        "closure",
        "closure_request",
        "receipts",
        "revocation",
        "snapshot",
    }:
        raise StoreIntegrityError("Stored expert review record set is invalid")
    receipts = raw["receipts"]
    if not isinstance(receipts, list):
        raise StoreIntegrityError("Stored expert review receipts are invalid")
    if not isinstance(raw["snapshot"], Mapping):
        raise StoreIntegrityError("Stored expert review snapshot is invalid")
    if any(not isinstance(item, Mapping) for item in receipts):
        raise StoreIntegrityError("Stored expert review receipt is invalid")
    if not isinstance(raw["closure_request"], Mapping):
        raise StoreIntegrityError("Stored expert review closure request is invalid")
    if not isinstance(raw["closure"], Mapping):
        raise StoreIntegrityError("Stored expert review closure is invalid")
    revocation = raw["revocation"]
    if revocation is not None and not isinstance(revocation, Mapping):
        raise StoreIntegrityError("Stored expert review revocation is invalid")
    return ExpertReviewRecordSet(
        snapshot=ExpertReviewSnapshot(_canonical_json(raw["snapshot"])),
        receipts=tuple(
            AuthenticatedExpertReviewReceipt(_canonical_json(item))
            for item in receipts
        ),
        closure_request=ExpertReviewClosureRequest(
            _canonical_json(raw["closure_request"])
        ),
        closure=ExpertReviewClosureCertificate(_canonical_json(raw["closure"])),
        revocation=(
            None
            if revocation is None
            else ExpertReviewClosureRevocation(_canonical_json(revocation))
        ),
    )


def review_record_set_sha256(records: ExpertReviewRecordSet) -> str:
    """Bind every reviewed record and the explicit revocation state."""

    return _canonical_sha256(
        {
            "domain": "sunderkey.current-expert-review-record-set.v1",
            "records": _review_record_set_document(records),
        }
    )


def resolution_authorization_intent_sha256(
    resolution: ActionProposalResolution,
) -> str:
    return _canonical_sha256(
        {
            "domain": RESOLUTION_INTENT_DOMAIN,
            "resolution": resolution.to_dict(),
            "role": AuthorizationRole.TYPED_RESOLVER.value,
        }
    )


def quorum_authorization_intent_sha256(
    resolution: ActionProposalResolution,
    role: AuthorizationRole,
    *,
    approved_at: str,
    expires_at: str,
) -> str:
    return _canonical_sha256(
        {
            "approved_at": approved_at,
            "domain": QUORUM_INTENT_DOMAIN,
            "expires_at": expires_at,
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "role": role.value,
        }
    )


def admission_authorization_intent_sha256(
    resolution: ActionProposalResolution,
    quorum: ActionAuthorizationQuorum,
    request: ActionAdmissionRequest,
) -> str:
    return _canonical_sha256(
        {
            "domain": ADMISSION_INTENT_DOMAIN,
            "quorum": quorum.to_dict(),
            "request": request.to_dict(),
            "resolution": resolution.to_dict(),
        }
    )


def revocation_authorization_intent_sha256(
    receipt: AuthenticatedActionAdmissionReceipt,
    *,
    reason_code: str,
    revoked_at: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": REVOCATION_INTENT_DOMAIN,
            "reason_code": reason_code,
            "receipt": receipt.to_dict(),
            "revoked_at": revoked_at,
        }
    )


def _current_proof_material(
    receipt: AuthenticatedActionAdmissionReceipt,
    verified_at: str,
    custody_sha256: str,
) -> bytes:
    from .action_resolution import _sha256, _timestamp

    receipt = parse_authenticated_action_admission_receipt(receipt.to_dict())
    _timestamp(verified_at, "verified_at")
    _sha256(custody_sha256, "custody hash")
    return _canonical_json(
        {
            "custody_sha256": custody_sha256,
            "domain": CURRENT_PROOF_DOMAIN,
            "receipt": receipt.to_dict(),
            "verified_at": verified_at,
        }
    ).encode("ascii")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_admission_receipts (
    receipt_id TEXT PRIMARY KEY,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    idempotency_key_sha256 TEXT NOT NULL,
    command_sha256 TEXT NOT NULL,
    resolution_json TEXT NOT NULL,
    quorum_json TEXT NOT NULL,
    request_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    review_evidence_json TEXT NOT NULL,
    review_evidence_sha256 TEXT NOT NULL,
    authority_state_json TEXT NOT NULL,
    authority_state_sha256 TEXT NOT NULL,
    custody_sha256 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE (tenant_id, mission_id, idempotency_key_sha256),
    CHECK (typeof(receipt_id) = 'text'),
    CHECK (typeof(receipt_sha256) = 'text'),
    CHECK (typeof(tenant_id) = 'text'),
    CHECK (typeof(mission_id) = 'text'),
    CHECK (typeof(idempotency_key_sha256) = 'text'),
    CHECK (typeof(command_sha256) = 'text'),
    CHECK (typeof(resolution_json) = 'text'),
    CHECK (typeof(quorum_json) = 'text'),
    CHECK (typeof(request_json) = 'text'),
    CHECK (typeof(decision_json) = 'text'),
    CHECK (typeof(receipt_json) = 'text'),
    CHECK (typeof(review_evidence_json) = 'text'),
    CHECK (typeof(review_evidence_sha256) = 'text'),
    CHECK (typeof(authority_state_json) = 'text'),
    CHECK (typeof(authority_state_sha256) = 'text'),
    CHECK (typeof(custody_sha256) = 'text'),
    CHECK (typeof(created_at) = 'text')
) STRICT;

CREATE TABLE IF NOT EXISTS action_admission_assertion_uses (
    assertion_issuer TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    assertion_sha256 TEXT NOT NULL UNIQUE,
    canonical_replay_key_sha256 TEXT NOT NULL UNIQUE,
    receipt_id TEXT NOT NULL,
    role TEXT NOT NULL,
    authorization_json TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (assertion_issuer, assertion_id),
    FOREIGN KEY (receipt_id) REFERENCES action_admission_receipts(receipt_id),
    CHECK (typeof(assertion_issuer) = 'text'),
    CHECK (typeof(assertion_id) = 'text'),
    CHECK (typeof(assertion_sha256) = 'text'),
    CHECK (typeof(canonical_replay_key_sha256) = 'text'),
    CHECK (typeof(receipt_id) = 'text'),
    CHECK (typeof(role) = 'text'),
    CHECK (typeof(authorization_json) = 'text'),
    CHECK (typeof(consumed_at) = 'text')
) STRICT;

CREATE TABLE IF NOT EXISTS action_admission_budget_reservations (
    receipt_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    budget_sha256 TEXT NOT NULL,
    request_cost INTEGER NOT NULL CHECK (request_cost >= 0),
    token_cost INTEGER NOT NULL CHECK (token_cost >= 0),
    cost_microunits INTEGER NOT NULL CHECK (cost_microunits >= 0),
    reserved_at TEXT NOT NULL,
    FOREIGN KEY (receipt_id) REFERENCES action_admission_receipts(receipt_id),
    CHECK (typeof(receipt_id) = 'text'),
    CHECK (typeof(tenant_id) = 'text'),
    CHECK (typeof(mission_id) = 'text'),
    CHECK (typeof(budget_sha256) = 'text'),
    CHECK (typeof(request_cost) = 'integer'),
    CHECK (typeof(token_cost) = 'integer'),
    CHECK (typeof(cost_microunits) = 'integer'),
    CHECK (typeof(reserved_at) = 'text')
) STRICT;

CREATE TABLE IF NOT EXISTS action_admission_revocations (
    revocation_id TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    revocation_sha256 TEXT NOT NULL UNIQUE,
    revocation_json TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    FOREIGN KEY (receipt_id) REFERENCES action_admission_receipts(receipt_id),
    CHECK (typeof(revocation_id) = 'text'),
    CHECK (typeof(receipt_id) = 'text'),
    CHECK (typeof(revocation_sha256) = 'text'),
    CHECK (typeof(revocation_json) = 'text'),
    CHECK (typeof(revoked_at) = 'text')
) STRICT;

CREATE TRIGGER IF NOT EXISTS action_admission_receipts_no_update
BEFORE UPDATE ON action_admission_receipts BEGIN
    SELECT RAISE(ABORT, 'action admission receipt custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_receipts_no_delete
BEFORE DELETE ON action_admission_receipts BEGIN
    SELECT RAISE(ABORT, 'action admission receipt custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_assertion_uses_no_update
BEFORE UPDATE ON action_admission_assertion_uses BEGIN
    SELECT RAISE(ABORT, 'action admission assertion custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_assertion_uses_no_delete
BEFORE DELETE ON action_admission_assertion_uses BEGIN
    SELECT RAISE(ABORT, 'action admission assertion custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_budget_reservations_no_update
BEFORE UPDATE ON action_admission_budget_reservations BEGIN
    SELECT RAISE(ABORT, 'action admission budget custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_budget_reservations_no_delete
BEFORE DELETE ON action_admission_budget_reservations BEGIN
    SELECT RAISE(ABORT, 'action admission budget custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_revocations_no_update
BEFORE UPDATE ON action_admission_revocations BEGIN
    SELECT RAISE(ABORT, 'action admission revocation custody is immutable');
END;
CREATE TRIGGER IF NOT EXISTS action_admission_revocations_no_delete
BEFORE DELETE ON action_admission_revocations BEGIN
    SELECT RAISE(ABORT, 'action admission revocation custody is immutable');
END;
"""

def _schema_statements() -> tuple[str, ...]:
    statements: list[str] = []
    pending = ""
    for line in _SCHEMA.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statements.append(pending.strip())
            pending = ""
    if pending.strip():
        raise StoreIntegrityError("Action admission custody schema text is incomplete")
    return tuple(statements)


def _schema_objects(connection: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    result: dict[tuple[str, str], str] = {}
    for row in rows:
        row_type, name, sql = row[0], row[1], row[2]
        if type(row_type) is not str or type(name) is not str or type(sql) is not str:
            raise StoreIntegrityError("Action admission custody schema metadata is invalid")
        result[(row_type, name)] = sql
    return result


def _expected_schema_objects() -> dict[tuple[str, str], str]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        return _schema_objects(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA_OBJECTS = _expected_schema_objects()


class AuthenticatedActionAdmissionService:
    """Resolve and admit an action with one owned authority and transaction."""

    def __init__(
        self,
        path: str | Path,
        authority: ActionAdmissionAuthority,
        review_verifier: ExpertReviewClosureVerifier,
        review_registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if not isinstance(busy_timeout_ms, int) or isinstance(busy_timeout_ms, bool):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 120000:
            raise ValueError("busy_timeout_ms must be between 1 and 120000")
        required = (
            "load_current_material",
            "authorize_resolution",
            "authorize_quorum",
            "authorize_admission",
            "verify_stored_current",
            "authorize_revocation",
        )
        if any(not callable(getattr(authority, name, None)) for name in required):
            raise TypeError("authority does not implement the admission authority contract")
        if not callable(getattr(review_verifier, "verify_current", None)):
            raise TypeError("review_verifier does not implement the current review contract")
        if review_registry is None:
            raise TypeError("review_registry is required")
        self._path = Path(path).resolve()
        self._authority = authority
        self._review_verifier = review_verifier
        self._review_registry = review_registry
        self._clock = clock or (lambda: datetime.now(UTC))
        self._busy_timeout_ms = busy_timeout_ms
        self._current_proof_key = secrets.token_bytes(32)

    def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, isolation_level=None)
        try:
            self._configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if type(application_id) is not int or type(user_version) is not int:
                raise StoreIntegrityError("Action admission custody markers are invalid")
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if any(type(name) is not str for name in existing):
                raise StoreIntegrityError("Action admission custody schema names are invalid")
            if application_id == 0 and user_version == 0 and existing:
                raise StoreIntegrityError(
                    "Unmarked action admission custody contains unrelated objects"
                )
            if (application_id, user_version) == (
                CUSTODY_APPLICATION_ID,
                CUSTODY_SCHEMA_VERSION,
            ):
                self._require_schema(connection)
                connection.commit()
                return
            if (application_id, user_version) != (0, 0):
                raise StoreIntegrityError("Action admission custody markers are invalid")
            for statement in _schema_statements():
                connection.execute(statement)
            connection.execute(f"PRAGMA application_id = {CUSTODY_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {CUSTODY_SCHEMA_VERSION}")
            connection.commit()
            self._require_schema(connection)
        except sqlite3.Error as exc:
            connection.rollback()
            raise StoreError("Could not initialize action admission custody") from exc
        finally:
            connection.close()

    @staticmethod
    def _format_time(value: datetime) -> str:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ActionResolutionError("Admission service clock must return an aware datetime")
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _configure(self, connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA recursive_triggers = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")

    def _connect(self) -> sqlite3.Connection:
        if not self._path.is_file():
            raise StoreError("Action admission custody is not initialized")
        connection = sqlite3.connect(
            self._path.as_uri() + "?mode=rw",
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
            uri=True,
        )
        try:
            self._configure(connection)
            self._require_schema(connection)
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        if (
            type(application_id) is not int
            or type(user_version) is not int
            or application_id != CUSTODY_APPLICATION_ID
            or user_version != CUSTODY_SCHEMA_VERSION
        ):
            raise StoreIntegrityError("Action admission custody markers are invalid")
        if _schema_objects(connection) != _EXPECTED_SCHEMA_OBJECTS:
            raise StoreIntegrityError("Action admission custody schema objects are invalid")
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise StoreIntegrityError("Action admission custody foreign keys are invalid")

    def admit(self, command: ActionAdmissionCommand) -> AuthenticatedActionAdmissionReceipt:
        if type(command) is not ActionAdmissionCommand:
            raise TypeError("command must be an ActionAdmissionCommand")
        evaluated_at = self._format_time(self._clock())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT * FROM action_admission_receipts
                WHERE tenant_id = ? AND mission_id = ? AND idempotency_key_sha256 = ?
                """,
                (command.tenant_id, command.mission_id, command.idempotency_key_sha256),
            ).fetchone()
            if existing is not None:
                if existing["command_sha256"] != command.command_sha256:
                    raise StoreConflictError(
                        "Action admission idempotency key is bound to different intent"
                    )
                self._require_not_revoked(connection, str(existing["receipt_id"]))
                stored = self._stored_from_row(connection, existing)
                self._verify_review_current(connection, stored.review_records)
                current = self._authority.verify_stored_current(
                    connection, stored, evaluated_at
                )
                self._require_same_authority_state(stored.authority_state, current)
                connection.commit()
                return stored.receipt

            material = self._authority.load_current_material(
                connection, command, evaluated_at
            )
            (
                resolution,
                resolver,
                review_document,
                review_hash,
                state,
            ) = self._resolve_current(
                connection, command, material, evaluated_at
            )
            quorum = self._authorize_quorum(
                connection, resolution, resolver, material, evaluated_at
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
            decision = evaluate_action_admission(request, evaluated_at=evaluated_at)
            if decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                reasons = ",".join(item.value for item in decision.denial_reasons)
                raise ActionResolutionError(f"Phase 165 action admission denied: {reasons}")
            admission = self._authority.authorize_admission(
                connection,
                resolution,
                quorum,
                request,
                admission_authorization_intent_sha256(resolution, quorum, request),
                evaluated_at,
            )
            admission = self._checked_admission_authorization(
                resolution, resolver, quorum, request, admission, evaluated_at
            )
            receipt = self._build_receipt(
                resolution, quorum, request, decision.to_dict(), admission, evaluated_at
            )
            self._reserve_budget(connection, receipt.receipt_id, material.budget, evaluated_at)
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
            for authorization in (
                resolver,
                *quorum.to_dict()["approvals"],
                admission,
            ):
                self._consume_authorization(
                    connection, receipt.receipt_id, authorization, evaluated_at
                )
            connection.commit()
            return receipt
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError(
                "Action admission conflicts with durable replay or custody state"
            ) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_current(
        self,
        receipt_id: str,
        *,
        evaluated_at: str | None = None,
    ) -> CurrentActionAdmission:
        from .action_resolution import _identifier, _timestamp

        _identifier(receipt_id, "receipt ID")
        checked_at = (
            self._format_time(self._clock())
            if evaluated_at is None
            else _timestamp(evaluated_at, "evaluated_at")
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise ActionResolutionError("Action admission receipt is not in custody")
            self._require_not_revoked(connection, receipt_id)
            stored = self._stored_from_row(connection, row)
            current_decision = evaluate_action_admission(
                stored.request, evaluated_at=checked_at
            )
            if current_decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
                reasons = ",".join(
                    item.value for item in current_decision.denial_reasons
                )
                raise ActionResolutionError(
                    f"Phase 165 action admission is no longer current: {reasons}"
                )
            self._verify_review_current(connection, stored.review_records)
            current = self._authority.verify_stored_current(
                connection, stored, checked_at
            )
            self._require_same_authority_state(stored.authority_state, current)
            connection.commit()
            custody_sha256 = row["custody_sha256"]
            if type(custody_sha256) is not str:
                raise StoreIntegrityError("Stored custody hash type is invalid")
            proof = hmac.new(
                self._current_proof_key,
                _current_proof_material(
                    stored.receipt, checked_at, custody_sha256
                ),
                hashlib.sha256,
            ).digest()
            return CurrentActionAdmission(
                receipt=stored.receipt,
                verified_at=checked_at,
                custody_sha256=custody_sha256,
                _proof=proof,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def require_owned_current_proof(self, proof: CurrentActionAdmission) -> None:
        if type(proof) is not CurrentActionAdmission:
            raise ActionResolutionError("Action admission proof belongs to another service")
        try:
            expected = hmac.new(
                self._current_proof_key,
                _current_proof_material(
                    proof.receipt, proof.verified_at, proof.custody_sha256
                ),
                hashlib.sha256,
            ).digest()
        except (AttributeError, TypeError, ValueError, StoreError) as exc:
            raise ActionResolutionError(
                "Action admission proof is invalid"
            ) from exc
        if type(proof._proof) is not bytes or not hmac.compare_digest(
            proof._proof, expected
        ):
            raise ActionResolutionError("Action admission proof belongs to another service")

    def revoke(
        self,
        receipt_id: str,
        *,
        reason_code: str,
        revoked_at: str | None = None,
    ) -> ActionAdmissionRevocation:
        from .action_resolution import _identifier, _timestamp

        _identifier(receipt_id, "receipt ID")
        _identifier(reason_code, "reason code")
        checked_at = (
            self._format_time(self._clock())
            if revoked_at is None
            else _timestamp(revoked_at, "revoked_at")
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise ActionResolutionError("Action admission receipt is not in custody")
            stored = self._stored_from_row(connection, row)
            self._require_not_revoked(connection, receipt_id)
            if checked_at < stored.receipt.to_dict()["evaluated_at"]:
                raise ActionResolutionError("Action admission revocation predates admission")
            self._verify_review_current(connection, stored.review_records)
            current = self._authority.verify_stored_current(
                connection, stored, checked_at
            )
            self._require_same_authority_state(stored.authority_state, current)
            intent = revocation_authorization_intent_sha256(
                stored.receipt, reason_code=reason_code, revoked_at=checked_at
            )
            authorization = self._authority.authorize_revocation(
                connection, stored, reason_code, intent, checked_at
            )
            authorization = self._checked_revocation_authorization(
                stored, authorization, intent, checked_at
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
            connection.execute(
                """
                INSERT INTO action_admission_revocations(
                    revocation_id, receipt_id, revocation_sha256,
                    revocation_json, revoked_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    revocation.revocation_id,
                    receipt_id,
                    revocation.revocation_sha256,
                    _canonical_json(revocation.to_dict()),
                    checked_at,
                ),
            )
            self._consume_authorization(
                connection, receipt_id, authorization, checked_at
            )
            connection.commit()
            return revocation
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreConflictError("Action admission revocation conflicts") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _resolve_current(
        self,
        connection: sqlite3.Connection,
        command: ActionAdmissionCommand,
        material: CurrentActionAdmissionMaterial,
        evaluated_at: str,
    ) -> tuple[
        ActionProposalResolution,
        dict[str, Any],
        dict[str, Any],
        str,
        CurrentActionAuthorityState,
    ]:
        if type(material) is not CurrentActionAdmissionMaterial:
            raise ActionResolutionError("Authority returned invalid current material")
        if material.registry is not self._review_registry:
            raise ActionResolutionError(
                "Current material registry is not the service review authority"
            )
        verified = self._verify_review_current(connection, material.records)
        if verified.revocation is not None:
            raise ActionResolutionError("Expert review closure is revoked")
        if verified.closure.to_dict()["disposition"] != ClosureDisposition.ACCEPTED.value:
            raise ActionResolutionError("Expert review closure is not accepted")
        catalog = parse_executable_action_catalog(material.catalog.to_dict())
        parameters = parse_action_parameter_set(material.parameters.to_dict(), catalog)
        target = parse_target_action_descriptor(material.target.to_dict())
        snapshot = verified.snapshot.to_dict()
        catalog_doc = catalog.to_dict()
        target_doc = target.to_dict()
        parameter_doc = parameters.to_dict()
        proposal = next(
            (
                item
                for item in snapshot["products"]
                if item["product_id"] == command.proposal_product_id
            ),
            None,
        )
        if proposal is None or proposal["product_type"] != "action_proposal":
            raise ActionResolutionError("Selected reviewed product is not an action proposal")
        if (
            command.tenant_id != snapshot["tenant_id"]
            or command.mission_id != snapshot["mission_id"]
        ):
            raise ActionResolutionError("Command is outside the reviewed mission")
        if parameter_doc["action_type"] != command.action_type:
            raise ActionResolutionError("Parameter set action type is inconsistent")
        if (
            target_doc["tenant_id"] != snapshot["tenant_id"]
            or target_doc["mission_id"] != snapshot["mission_id"]
            or target_doc["target_scope_sha256"] != snapshot["target_scope_sha256"]
            or target_doc["authority_snapshot_sha256"]
            != snapshot["authority_snapshot_sha256"]
        ):
            raise ActionResolutionError("Target descriptor is outside reviewed scope")
        if catalog_doc["registry_sha256"] != snapshot["registry_sha256"]:
            raise ActionResolutionError("Executable catalog registry binding is invalid")
        entry = _catalog_action(catalog, command.action_type)
        if command.action_tier.value not in {"R0", "R1", "R2", "R3", "R4"}:
            raise ActionResolutionError("Action tier is unsupported")
        order = {tier: index for index, tier in enumerate(ActionTier)}
        if order[command.action_tier] > order[ActionTier(entry["maximum_action_tier"])]:
            raise ActionResolutionError("Requested action tier exceeds catalog ceiling")
        if not entry["executor_supported"]:
            raise ActionResolutionError("Action has no qualified executor support")
        if command.action_tier is ActionTier.R4 and not entry["r4_executor_supported"]:
            raise ActionResolutionError("R4 action lacks explicit executor support")
        if target_doc["environment"] not in entry["supported_environments"]:
            raise ActionResolutionError("Target environment is unsupported")
        action_sha = _resolved_action_sha256(
            catalog=catalog,
            entry=entry,
            parameters=parameters,
            target=target,
            action_tier=command.action_tier,
        )
        body = {
            "schema_version": 1,
            "kind": "action_proposal_resolution",
            "tenant_id": snapshot["tenant_id"],
            "mission_id": snapshot["mission_id"],
            "plan_id": snapshot["plan_id"],
            "proposal_work_id": proposal["work_id"],
            "proposal_product_id": proposal["product_id"],
            "proposal_product_sha256": proposal["product_sha256"],
            "proposal_producer_profile_id": proposal["producer_profile_id"],
            "review_snapshot_id": verified.snapshot.snapshot_id,
            "review_snapshot_sha256": verified.snapshot.snapshot_sha256,
            "review_closure_id": verified.closure.closure_id,
            "review_closure_sha256": verified.closure.closure_sha256,
            "catalog_id": catalog.catalog_id,
            "catalog_sha256": catalog.catalog_sha256,
            "catalog_version": catalog_doc["catalog_version"],
            "parameter_set_id": parameters.parameter_set_id,
            "parameter_set_sha256": parameters.parameter_set_sha256,
            "target_descriptor_id": target.descriptor_id,
            "target_descriptor_sha256": target.descriptor_sha256,
            "target_scope_sha256": target_doc["target_scope_sha256"],
            "target_id": target_doc["target_id"],
            "target_sha256": target_doc["target_sha256"],
            "target_authority_sha256": target_doc["authority_snapshot_sha256"],
            "target_environment": target_doc["environment"],
            "action_type": command.action_type,
            "action_tier": command.action_tier.value,
            "action_sha256": action_sha,
            "idempotency_key_sha256": command.idempotency_key_sha256,
            "tool_artifact_ref": entry["tool_artifact_ref"],
            "tool_artifact_sha256": entry["tool_artifact_sha256"],
            "tool_exact_version": entry["tool_exact_version"],
            "resolver_profile_id": material.resolver_profile_id,
            "resolver_subject": material.resolver_subject,
            "resolved_at": material.resolved_at,
            "resolution_status": "typed_resolved_pending_authorization",
            "effects": dict(NO_EFFECTS),
        }
        draft = parse_action_proposal_resolution(
            _address_record("action_proposal_resolution", body)
        )
        authorization = self._authority.authorize_resolution(
            connection,
            draft,
            resolution_authorization_intent_sha256(draft),
            evaluated_at,
        )
        authorization = _authorization(authorization, "resolver authorization")
        self._assert_bound_authorization(
            draft,
            authorization,
            AuthorizationRole.TYPED_RESOLVER,
            resolution_authorization_intent_sha256(draft),
            material.resolved_at,
        )
        if (
            authorization["principal_profile_id"] != material.resolver_profile_id
            or authorization["principal_subject"] != material.resolver_subject
            or authorization["principal_profile_id"] == proposal["producer_profile_id"]
        ):
            raise ActionResolutionError("Typed resolver identity is not authoritative")
        resolution = draft
        review_document = _review_record_set_document(verified)
        review_hash = review_record_set_sha256(verified)
        state = CurrentActionAuthorityState(
            review_evidence_sha256=review_hash,
            catalog_id=catalog.catalog_id,
            catalog_sha256=catalog.catalog_sha256,
            catalog_version=catalog_doc["catalog_version"],
            catalog_authority_sha256=material.catalog_authority_sha256,
            authority_revision_sha256=material.authority_revision_sha256,
        )
        self._validate_authority_state(state)
        return resolution, authorization, review_document, review_hash, state

    def _verify_review_current(
        self,
        connection: sqlite3.Connection,
        records: ExpertReviewRecordSet,
    ) -> ExpertReviewRecordSet:
        del connection
        return _verify_current_expert_review_closure(
            self._review_verifier,
            records,
            self._review_registry,
        )

    @staticmethod
    def _reconstruct_request(
        resolution: ActionProposalResolution,
        quorum: ActionAuthorizationQuorum,
        *,
        context: ContextBinding,
        worker_session: WorkerSession,
        credential_lease: CredentialLease,
        health: HealthEvidence,
        budget: BudgetBinding,
        evidence_obligations: Sequence[EvidenceObligation],
        stop_conditions: StopConditions,
        restoration_duties: RestorationDuties,
        requested_at: str,
        expires_at: str,
    ) -> ActionAdmissionRequest:
        resolution_doc = parse_action_proposal_resolution(
            resolution.to_dict()
        ).to_dict()
        quorum_doc = parse_action_authorization_quorum(quorum.to_dict()).to_dict()
        expected_quorum = {
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "tenant_id": resolution_doc["tenant_id"],
            "mission_id": resolution_doc["mission_id"],
            "scope_sha256": resolution_doc["target_scope_sha256"],
            "target_sha256": resolution_doc["target_sha256"],
            "action_sha256": resolution_doc["action_sha256"],
            "action_tier": resolution_doc["action_tier"],
        }
        if any(quorum_doc[field] != value for field, value in expected_quorum.items()):
            raise ActionResolutionError("Authorization quorum resolution binding is invalid")
        if quorum_doc["approved_at"] < resolution_doc["resolved_at"]:
            raise ActionResolutionError("Authorization quorum predates resolution")
        if (
            context.tenant_id != resolution_doc["tenant_id"]
            or context.mission_id != resolution_doc["mission_id"]
            or context.scope_sha256 != resolution_doc["target_scope_sha256"]
        ):
            raise ActionResolutionError("Authoritative context is outside typed resolution")
        tier = AdmissionActionTier(resolution_doc["action_tier"])
        target = TargetBinding(
            target_id=resolution_doc["target_id"],
            target_sha256=resolution_doc["target_sha256"],
            authority_sha256=resolution_doc["target_authority_sha256"],
            tenant_id=resolution_doc["tenant_id"],
            mission_id=resolution_doc["mission_id"],
            scope_sha256=resolution_doc["target_scope_sha256"],
            environment=TargetEnvironment(resolution_doc["target_environment"]),
        )
        action = RequestedAction(
            action_id=resolution.resolution_id,
            action_type=resolution_doc["action_type"],
            action_tier=tier,
            action_sha256=resolution_doc["action_sha256"],
            target_sha256=resolution_doc["target_sha256"],
            parameters_sha256=resolution_doc["parameter_set_sha256"],
            tool=ArtifactBinding(
                artifact_ref=resolution_doc["tool_artifact_ref"],
                artifact_sha256=resolution_doc["tool_artifact_sha256"],
                exact_version=resolution_doc["tool_exact_version"],
            ),
            idempotency_key_sha256=resolution_doc["idempotency_key_sha256"],
        )
        owner = quorum_doc["approvals"][0]
        approval = ApprovalBinding(
            approval_id=quorum.quorum_id,
            approval_sha256=quorum.quorum_sha256,
            tenant_id=resolution_doc["tenant_id"],
            mission_id=resolution_doc["mission_id"],
            scope_sha256=resolution_doc["target_scope_sha256"],
            target_sha256=resolution_doc["target_sha256"],
            action_sha256=resolution_doc["action_sha256"],
            worker_id=worker_session.worker_id,
            session_id=worker_session.session_id,
            fence_token_sha256=worker_session.fence_token_sha256,
            leader_epoch=worker_session.leader_epoch,
            authorized_tier=tier,
            approver_id=owner["principal_profile_id"],
            decision="approved",
            issued_at=quorum_doc["approved_at"],
            expires_at=quorum_doc["expires_at"],
        )
        request = ActionAdmissionRequest(
            context=context,
            worker_session=worker_session,
            approval=approval,
            credential_lease=credential_lease,
            health=health,
            budget=budget,
            target=target,
            action=action,
            evidence_obligations=tuple(evidence_obligations),
            stop_conditions=stop_conditions,
            restoration_duties=restoration_duties,
            requested_at=requested_at,
            expires_at=expires_at,
        )
        if (
            credential_lease.permitted_action_sha256 != action.action_sha256
            or stop_conditions.action_sha256 != action.action_sha256
            or restoration_duties.action_sha256 != action.action_sha256
            or any(
                item.action_sha256 != action.action_sha256
                for item in evidence_obligations
            )
        ):
            raise ActionResolutionError(
                "Authoritative Phase 165 prerequisites are not bound to action"
            )
        return request

    def _authorize_quorum(
        self,
        connection: sqlite3.Connection,
        resolution: ActionProposalResolution,
        resolver: Mapping[str, Any],
        material: CurrentActionAdmissionMaterial,
        evaluated_at: str,
    ) -> ActionAuthorizationQuorum:
        tier = ActionTier(resolution.to_dict()["action_tier"])
        roles = [AuthorizationRole.MISSION_OWNER]
        if tier in {ActionTier.R3, ActionTier.R4}:
            roles.append(AuthorizationRole.INDEPENDENT_CONTROL)
        intents = {
            role: quorum_authorization_intent_sha256(
                resolution,
                role,
                approved_at=material.approved_at,
                expires_at=material.quorum_expires_at,
            )
            for role in roles
        }
        approvals = list(
            self._authority.authorize_quorum(
                connection, resolution, intents, evaluated_at
            )
        )
        if len(approvals) != len(roles):
            raise ActionResolutionError("Authorization quorum roles are incomplete")
        checked: list[dict[str, Any]] = []
        resolution_doc = resolution.to_dict()
        for role, raw in zip(roles, approvals, strict=True):
            authorization = _authorization(raw, "authorization approval")
            self._assert_bound_authorization(
                resolution,
                authorization,
                role,
                intents[role],
                material.approved_at,
            )
            if authorization["issued_at"] > material.approved_at:
                raise ActionResolutionError("Authorization approval postdates quorum")
            if (
                authorization["principal_profile_id"]
                in {
                    resolution_doc["proposal_producer_profile_id"],
                    resolution_doc["resolver_profile_id"],
                }
                or authorization["principal_subject"] == resolution_doc["resolver_subject"]
            ):
                raise ActionResolutionError("Authorization approver is not independent")
            checked.append(authorization)
        self._require_unique_authorizations((resolver, *checked))
        if material.approved_at < material.resolved_at:
            raise ActionResolutionError("Authorization quorum predates resolution")
        if material.quorum_expires_at > min(item["expires_at"] for item in checked):
            raise ActionResolutionError("Authorization quorum outlives an approval")
        body = {
            "schema_version": 1,
            "kind": "action_authorization_quorum",
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "tenant_id": resolution_doc["tenant_id"],
            "mission_id": resolution_doc["mission_id"],
            "scope_sha256": resolution_doc["target_scope_sha256"],
            "target_sha256": resolution_doc["target_sha256"],
            "action_sha256": resolution_doc["action_sha256"],
            "action_tier": tier.value,
            "approvals": checked,
            "approved_at": material.approved_at,
            "expires_at": material.quorum_expires_at,
            "quorum_status": "approved_for_contract_admission",
            "effects": dict(NO_EFFECTS),
        }
        return parse_action_authorization_quorum(
            _address_record("action_authorization_quorum", body)
        )

    def _checked_admission_authorization(
        self,
        resolution: ActionProposalResolution,
        resolver: Mapping[str, Any],
        quorum: ActionAuthorizationQuorum,
        request: ActionAdmissionRequest,
        raw: Mapping[str, Any],
        evaluated_at: str,
    ) -> dict[str, Any]:
        authorization = _authorization(raw, "admission authorization")
        intent = admission_authorization_intent_sha256(resolution, quorum, request)
        self._assert_bound_authorization(
            resolution,
            authorization,
            AuthorizationRole.ADMISSION_CONTROL,
            intent,
            evaluated_at,
        )
        resolution_doc = resolution.to_dict()
        excluded = [resolver, *quorum.to_dict()["approvals"]]
        if authorization["principal_profile_id"] == resolution_doc["proposal_producer_profile_id"]:
            raise ActionResolutionError("Admission Control is not independent")
        self._require_unique_authorizations((*excluded, authorization))
        return authorization

    def _checked_revocation_authorization(
        self,
        stored: StoredActionAdmission,
        raw: Mapping[str, Any],
        intent: str,
        revoked_at: str,
    ) -> dict[str, Any]:
        authorization = _authorization(raw, "revocation authorization")
        self._assert_bound_authorization(
            stored.resolution,
            authorization,
            AuthorizationRole.INDEPENDENT_CONTROL,
            intent,
            revoked_at,
        )
        receipt_doc = stored.receipt.to_dict()
        admission = receipt_doc["admission_authorization"]
        excluded = [
            stored.resolver_authorization,
            *stored.quorum.to_dict()["approvals"],
            admission,
        ]
        resolution_doc = stored.resolution.to_dict()
        if authorization["principal_profile_id"] in {
            resolution_doc["proposal_producer_profile_id"],
            resolution_doc["resolver_profile_id"],
        } or authorization["principal_subject"] == resolution_doc["resolver_subject"]:
            raise ActionResolutionError("Revocation Control is not independent")
        self._require_unique_authorizations((*excluded, authorization))
        return authorization

    @staticmethod
    def _assert_bound_authorization(
        resolution: ActionProposalResolution,
        authorization: Mapping[str, Any],
        role: AuthorizationRole,
        operation_intent_sha256: str,
        at: str,
    ) -> None:
        document = resolution.to_dict()
        _assert_authorization_binding(
            authorization,
            role=role,
            tenant_id=document["tenant_id"],
            mission_id=document["mission_id"],
            scope_sha256=document["target_scope_sha256"],
            target_sha256=document["target_sha256"],
            action_sha256=document["action_sha256"],
            resolution_sha256=resolution.resolution_sha256,
            action_tier=ActionTier(document["action_tier"]),
        )
        _assert_authorization_current_at(authorization, at, at)
        if authorization["operation_intent_sha256"] != operation_intent_sha256:
            raise ActionResolutionError("Authorization does not bind the exact operation intent")

    @staticmethod
    def _require_unique_authorizations(
        authorizations: Sequence[Mapping[str, Any]],
    ) -> None:
        for field in (
            "principal_profile_id",
            "principal_subject",
            "assertion_sha256",
            "canonical_replay_key_sha256",
        ):
            values = [item[field] for item in authorizations]
            if len(values) != len(set(values)):
                raise ActionResolutionError(f"Authenticated roles reuse {field}")

    def _build_receipt(
        self,
        resolution: ActionProposalResolution,
        quorum: ActionAuthorizationQuorum,
        request: ActionAdmissionRequest,
        decision: Mapping[str, Any],
        authorization: Mapping[str, Any],
        evaluated_at: str,
    ) -> AuthenticatedActionAdmissionReceipt:
        resolution_doc = resolution.to_dict()
        body = {
            "schema_version": 1,
            "kind": "authenticated_action_admission_receipt",
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "quorum_id": quorum.quorum_id,
            "quorum_sha256": quorum.quorum_sha256,
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "decision_id": decision["decision_id"],
            "decision_sha256": decision["decision_sha256"],
            "tenant_id": resolution_doc["tenant_id"],
            "mission_id": resolution_doc["mission_id"],
            "scope_sha256": resolution_doc["target_scope_sha256"],
            "target_sha256": resolution_doc["target_sha256"],
            "action_sha256": resolution_doc["action_sha256"],
            "action_tier": resolution_doc["action_tier"],
            "evaluated_at": evaluated_at,
            "status": "admitted_contract_only",
            "admission_authorization": dict(authorization),
            "identity_assurance": "mission_store_principal_assertion",
            "effects": dict(NO_EFFECTS),
        }
        return parse_authenticated_action_admission_receipt(
            _address_record("authenticated_action_admission_receipt", body)
        )

    @staticmethod
    def _validate_authority_state(state: CurrentActionAuthorityState) -> None:
        from .action_resolution import _identifier, _sha256, _version

        if type(state) is not CurrentActionAuthorityState:
            raise ActionResolutionError("Authority returned invalid current state")
        for field in (
            "review_evidence_sha256",
            "catalog_sha256",
            "catalog_authority_sha256",
            "authority_revision_sha256",
        ):
            _sha256(getattr(state, field), field)
        _identifier(state.catalog_id, "catalog ID")
        _version(state.catalog_version, "catalog version")

    @classmethod
    def _require_same_authority_state(
        cls,
        expected: CurrentActionAuthorityState,
        current: CurrentActionAuthorityState,
    ) -> None:
        cls._validate_authority_state(current)
        if current != expected or current.state_sha256 != expected.state_sha256:
            raise ActionResolutionError("Authoritative action state changed or was revoked")

    def _reserve_budget(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
        budget: BudgetBinding,
        reserved_at: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT COALESCE(SUM(request_cost), 0), COALESCE(SUM(token_cost), 0),
                   COALESCE(SUM(cost_microunits), 0)
            FROM action_admission_budget_reservations
            WHERE tenant_id = ? AND mission_id = ? AND budget_sha256 = ?
            """,
            (budget.tenant_id, budget.mission_id, budget.budget_sha256),
        ).fetchone()
        if row is None or any(type(value) is not int for value in row):
            raise StoreIntegrityError("Stored budget totals have invalid types")
        reserved_requests, reserved_tokens, reserved_cost = row
        if (
            budget.requests_used + reserved_requests + budget.action_request_cost
            > budget.request_limit
            or budget.tokens_used + reserved_tokens + budget.action_token_cost
            > budget.token_limit
            or budget.cost_used_microunits
            + reserved_cost
            + budget.action_cost_microunits
            > budget.cost_limit_microunits
        ):
            raise ActionResolutionError("Authoritative action budget cannot be reserved")
        # The receipt row is inserted before commit, but SQLite immediate foreign
        # keys require it first. Reservation insert is deferred until custody.
        connection.execute(
            "CREATE TEMP TABLE IF NOT EXISTS _action_budget_reservation(payload TEXT NOT NULL)"
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

    def _custody_document(
        self,
        command: ActionAdmissionCommand,
        resolution: ActionProposalResolution,
        quorum: ActionAuthorizationQuorum,
        request: ActionAdmissionRequest,
        decision: Mapping[str, Any],
        receipt: AuthenticatedActionAdmissionReceipt,
        resolver: Mapping[str, Any],
        review_document: Mapping[str, Any],
        review_hash: str,
        state: CurrentActionAuthorityState,
        created_at: str,
    ) -> dict[str, Any]:
        return {
            "authority_state": state.to_dict(),
            "authority_state_sha256": state.state_sha256,
            "command": command.to_dict(),
            "command_sha256": command.command_sha256,
            "created_at": created_at,
            "decision": dict(decision),
            "quorum": quorum.to_dict(),
            "receipt": receipt.to_dict(),
            "request": request.to_dict(),
            "resolution": resolution.to_dict(),
            "resolver_authorization": resolver,
            "review_evidence": dict(review_document),
            "review_evidence_sha256": review_hash,
        }

    def _insert_receipt(
        self,
        connection: sqlite3.Connection,
        custody: Mapping[str, Any],
    ) -> None:
        custody = dict(custody)
        receipt = parse_authenticated_action_admission_receipt(custody["receipt"])
        receipt_doc = receipt.to_dict()
        custody_sha = _canonical_sha256(
            {"domain": CUSTODY_DOMAIN, "custody": dict(custody)}
        )
        state_json = _canonical_json(custody["authority_state"])
        connection.execute(
            """
            INSERT INTO action_admission_receipts(
                receipt_id, receipt_sha256, tenant_id, mission_id,
                idempotency_key_sha256, command_sha256, resolution_json,
                quorum_json, request_json, decision_json, receipt_json,
                review_evidence_json, review_evidence_sha256, authority_state_json,
                authority_state_sha256, custody_sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                receipt.receipt_sha256,
                receipt_doc["tenant_id"],
                receipt_doc["mission_id"],
                custody["command"]["idempotency_key_sha256"],
                custody["command_sha256"],
                _canonical_json(custody["resolution"]),
                _canonical_json(custody["quorum"]),
                _canonical_json(custody["request"]),
                _canonical_json(custody["decision"]),
                _canonical_json(custody["receipt"]),
                _canonical_json(custody["review_evidence"]),
                custody["review_evidence_sha256"],
                state_json,
                custody["authority_state_sha256"],
                custody_sha,
                custody["created_at"],
            ),
        )
        budget_row = connection.execute(
            "SELECT payload FROM _action_budget_reservation"
        ).fetchone()
        if budget_row is None or type(budget_row[0]) is not str:
            raise StoreIntegrityError("Budget reservation custody is missing")
        budget = json.loads(budget_row[0])
        if _canonical_json(budget) != budget_row[0]:
            raise StoreIntegrityError("Budget reservation custody is not canonical")
        connection.execute(
            """
            INSERT INTO action_admission_budget_reservations(
                receipt_id, tenant_id, mission_id, budget_sha256,
                request_cost, token_cost, cost_microunits, reserved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                budget["receipt_id"],
                budget["tenant_id"],
                budget["mission_id"],
                budget["budget_sha256"],
                budget["request_cost"],
                budget["token_cost"],
                budget["cost_microunits"],
                budget["reserved_at"],
            ),
        )

    @staticmethod
    def _consume_authorization(
        connection: sqlite3.Connection,
        receipt_id: str,
        authorization: Mapping[str, Any],
        consumed_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO action_admission_assertion_uses(
                assertion_issuer, assertion_id, assertion_sha256,
                canonical_replay_key_sha256, receipt_id, role,
                authorization_json, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authorization["assertion_issuer"],
                authorization["assertion_id"],
                authorization["assertion_sha256"],
                authorization["canonical_replay_key_sha256"],
                receipt_id,
                authorization["role"],
                _canonical_json(dict(authorization)),
                consumed_at,
            ),
        )

    def _stored_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> StoredActionAdmission:
        try:
            if any(type(row[field]) is not str for field in tuple(row.keys())):
                raise StoreIntegrityError("Stored action admission column type is invalid")
            for field in (
                "resolution_json",
                "quorum_json",
                "request_json",
                "decision_json",
                "receipt_json",
                "review_evidence_json",
                "authority_state_json",
            ):
                decoded = json.loads(row[field])
                if _canonical_json(decoded) != row[field]:
                    raise StoreIntegrityError(f"Stored {field} is not canonical")
            resolution = parse_action_proposal_resolution(json.loads(row["resolution_json"]))
            quorum = parse_action_authorization_quorum(json.loads(row["quorum_json"]))
            request = ActionAdmissionRequest.from_dict(json.loads(row["request_json"]))
            receipt = parse_authenticated_action_admission_receipt(
                json.loads(row["receipt_json"])
            )
            state = CurrentActionAuthorityState(**json.loads(row["authority_state_json"]))
            review_document = json.loads(row["review_evidence_json"])
            review_records = _review_record_set_from_document(review_document)
            self._validate_authority_state(state)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored action admission custody is invalid") from exc
        decision = evaluate_action_admission(
            request, evaluated_at=receipt.to_dict()["evaluated_at"]
        )
        stored_decision = json.loads(row["decision_json"])
        bindings = {
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "quorum_id": quorum.quorum_id,
            "quorum_sha256": quorum.quorum_sha256,
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "decision_id": decision.decision_id,
            "decision_sha256": decision.decision_sha256,
        }
        receipt_doc = receipt.to_dict()
        if (
            decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY
            or stored_decision != decision.to_dict()
            or any(receipt_doc[field] != value for field, value in bindings.items())
        ):
            raise StoreIntegrityError("Stored action admission chain is invalid")
        if row["created_at"] != receipt_doc["evaluated_at"]:
            raise StoreIntegrityError("Stored admission chronology is invalid")
        if row["receipt_sha256"] != receipt.receipt_sha256:
            raise StoreIntegrityError("Stored receipt hash differs from content")
        if row["review_evidence_sha256"] != state.review_evidence_sha256:
            raise StoreIntegrityError("Stored review evidence binding is invalid")
        expected_review_hash = _canonical_sha256(
            {
                "domain": "sunderkey.current-expert-review-record-set.v1",
                "records": review_document,
            }
        )
        if row["review_evidence_sha256"] != expected_review_hash:
            raise StoreIntegrityError("Stored full review evidence hash is invalid")
        if row["authority_state_sha256"] != state.state_sha256:
            raise StoreIntegrityError("Stored authority state hash is invalid")
        resolution_doc = resolution.to_dict()
        if not isinstance(review_document, Mapping) or set(review_document) != {
            "closure",
            "closure_request",
            "receipts",
            "revocation",
            "snapshot",
        }:
            raise StoreIntegrityError("Stored review evidence structure is invalid")
        snapshot = review_document["snapshot"]
        closure = review_document["closure"]
        if (
            not isinstance(snapshot, Mapping)
            or not isinstance(closure, Mapping)
            or review_document["revocation"] is not None
            or snapshot.get("snapshot_id") != resolution_doc["review_snapshot_id"]
            or snapshot.get("snapshot_sha256")
            != resolution_doc["review_snapshot_sha256"]
            or closure.get("closure_id") != resolution_doc["review_closure_id"]
            or closure.get("closure_sha256")
            != resolution_doc["review_closure_sha256"]
        ):
            raise StoreIntegrityError("Stored review evidence chain is invalid")
        if (
            state.catalog_id != resolution_doc["catalog_id"]
            or state.catalog_sha256 != resolution_doc["catalog_sha256"]
            or state.catalog_version != resolution_doc["catalog_version"]
        ):
            raise StoreIntegrityError("Stored catalog authority binding is invalid")
        authorization_rows = connection.execute(
            """
            SELECT *
            FROM action_admission_assertion_uses
            WHERE receipt_id = ?
            ORDER BY role
            """,
            (receipt.receipt_id,),
        ).fetchall()
        try:
            authorizations = [
                _authorization(
                    json.loads(item["authorization_json"]),
                    "stored authorization",
                )
                for item in authorization_rows
            ]
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StoreIntegrityError("Stored authorization custody is invalid") from exc
        resolver_matches = [
            item
            for item in authorizations
            if item["role"] == AuthorizationRole.TYPED_RESOLVER.value
        ]
        if len(authorizations) not in {3, 4} or len(resolver_matches) != 1:
            raise StoreIntegrityError("Stored authorization role custody is incomplete")
        for row_item, authorization in zip(
            authorization_rows, authorizations, strict=True
        ):
            if (
                row_item["role"] != authorization["role"]
                or row_item["assertion_issuer"] != authorization["assertion_issuer"]
                or row_item["assertion_id"] != authorization["assertion_id"]
                or row_item["assertion_sha256"] != authorization["assertion_sha256"]
                or row_item["canonical_replay_key_sha256"]
                != authorization["canonical_replay_key_sha256"]
                or row_item["receipt_id"] != receipt.receipt_id
                or row_item["consumed_at"] != row["created_at"]
                or _canonical_json(authorization) != row_item["authorization_json"]
            ):
                raise StoreIntegrityError("Stored authorization columns are inconsistent")
        resolver = resolver_matches[0]
        self._verify_stored_authorization_invariants(
            resolution, quorum, request, receipt, resolver, authorizations
        )
        command = {
            "action_tier": resolution.to_dict()["action_tier"],
            "action_type": resolution.to_dict()["action_type"],
            "idempotency_key_sha256": resolution.to_dict()["idempotency_key_sha256"],
            "mission_id": resolution.to_dict()["mission_id"],
            "proposal_product_id": resolution.to_dict()["proposal_product_id"],
            "tenant_id": resolution.to_dict()["tenant_id"],
        }
        expected_command_sha = _canonical_sha256(
            {"domain": COMMAND_DOMAIN, "command": command}
        )
        if row["command_sha256"] != expected_command_sha:
            raise StoreIntegrityError("Stored command hash is invalid")
        if (
            row["receipt_id"] != receipt.receipt_id
            or row["tenant_id"] != command["tenant_id"]
            or row["mission_id"] != command["mission_id"]
            or row["idempotency_key_sha256"]
            != command["idempotency_key_sha256"]
        ):
            raise StoreIntegrityError("Stored receipt lookup columns are inconsistent")
        budget_rows = connection.execute(
            """
            SELECT * FROM action_admission_budget_reservations
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchall()
        if len(budget_rows) != 1:
            raise StoreIntegrityError("Stored budget reservation custody is incomplete")
        budget_row = budget_rows[0]
        budget = request.budget
        if (
            any(
                type(budget_row[field]) is not str
                for field in (
                    "receipt_id",
                    "tenant_id",
                    "mission_id",
                    "budget_sha256",
                    "reserved_at",
                )
            )
            or any(
                type(budget_row[field]) is not int
                for field in ("request_cost", "token_cost", "cost_microunits")
            )
            or budget_row["tenant_id"] != budget.tenant_id
            or budget_row["mission_id"] != budget.mission_id
            or budget_row["budget_sha256"] != budget.budget_sha256
            or budget_row["request_cost"] != budget.action_request_cost
            or budget_row["token_cost"] != budget.action_token_cost
            or budget_row["cost_microunits"] != budget.action_cost_microunits
            or budget_row["reserved_at"] != row["created_at"]
        ):
            raise StoreIntegrityError("Stored budget reservation binding is invalid")
        custody = {
            "authority_state": state.to_dict(),
            "authority_state_sha256": state.state_sha256,
            "command": command,
            "command_sha256": expected_command_sha,
            "created_at": row["created_at"],
            "decision": json.loads(row["decision_json"]),
            "quorum": quorum.to_dict(),
            "receipt": receipt.to_dict(),
            "request": request.to_dict(),
            "resolution": resolution.to_dict(),
            "resolver_authorization": resolver,
            "review_evidence": review_document,
            "review_evidence_sha256": row["review_evidence_sha256"],
        }
        expected_custody_sha = _canonical_sha256(
            {"domain": CUSTODY_DOMAIN, "custody": custody}
        )
        if row["custody_sha256"] != expected_custody_sha:
            raise StoreIntegrityError("Stored action admission custody hash is invalid")
        return StoredActionAdmission(
            resolution=resolution,
            quorum=quorum,
            request=request,
            receipt=receipt,
            resolver_authorization=resolver,
            review_records=review_records,
            review_evidence_document=review_document,
            review_evidence_sha256=row["review_evidence_sha256"],
            authority_state=state,
        )

    def _verify_stored_authorization_invariants(
        self,
        resolution: ActionProposalResolution,
        quorum: ActionAuthorizationQuorum,
        request: ActionAdmissionRequest,
        receipt: AuthenticatedActionAdmissionReceipt,
        resolver: Mapping[str, Any],
        authorizations: Sequence[Mapping[str, Any]],
    ) -> None:
        resolution_doc = resolution.to_dict()
        receipt_doc = receipt.to_dict()
        self._assert_bound_authorization(
            resolution,
            resolver,
            AuthorizationRole.TYPED_RESOLVER,
            resolution_authorization_intent_sha256(resolution),
            resolution_doc["resolved_at"],
        )
        if (
            resolver["principal_profile_id"] != resolution_doc["resolver_profile_id"]
            or resolver["principal_subject"] != resolution_doc["resolver_subject"]
        ):
            raise StoreIntegrityError("Stored resolver identity binding is invalid")
        approvals = quorum.to_dict()["approvals"]
        for approval in approvals:
            role = AuthorizationRole(approval["role"])
            self._assert_bound_authorization(
                resolution,
                approval,
                role,
                quorum_authorization_intent_sha256(
                    resolution,
                    role,
                    approved_at=quorum.to_dict()["approved_at"],
                    expires_at=quorum.to_dict()["expires_at"],
                ),
                quorum.to_dict()["approved_at"],
            )
        admission = receipt_doc["admission_authorization"]
        self._assert_bound_authorization(
            resolution,
            admission,
            AuthorizationRole.ADMISSION_CONTROL,
            admission_authorization_intent_sha256(resolution, quorum, request),
            receipt_doc["evaluated_at"],
        )
        expected = [resolver, *approvals, admission]
        if len(authorizations) != len(expected) or {
            item["assertion_sha256"] for item in authorizations
        } != {item["assertion_sha256"] for item in expected}:
            raise StoreIntegrityError("Stored authorization custody differs from receipt chain")
        self._require_unique_authorizations(expected)
        excluded_profiles = {
            resolution_doc["proposal_producer_profile_id"],
            resolution_doc["resolver_profile_id"],
            *(item["principal_profile_id"] for item in approvals),
        }
        excluded_subjects = {
            resolution_doc["resolver_subject"],
            *(item["principal_subject"] for item in approvals),
        }
        if (
            admission["principal_profile_id"] in excluded_profiles
            or admission["principal_subject"] in excluded_subjects
        ):
            raise StoreIntegrityError("Stored Admission Control independence is invalid")

    @staticmethod
    def _require_not_revoked(
        connection: sqlite3.Connection,
        receipt_id: str,
    ) -> None:
        if connection.execute(
            "SELECT 1 FROM action_admission_revocations WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone() is not None:
            raise ActionResolutionError("Action admission receipt is revoked")


__all__ = [
    "ActionAdmissionAuthority",
    "ActionAdmissionCommand",
    "AuthenticatedActionAdmissionService",
    "CurrentActionAdmission",
    "CurrentActionAdmissionMaterial",
    "CurrentActionAuthorityState",
    "StoredActionAdmission",
    "admission_authorization_intent_sha256",
    "quorum_authorization_intent_sha256",
    "resolution_authorization_intent_sha256",
    "review_record_set_sha256",
    "revocation_authorization_intent_sha256",
]
