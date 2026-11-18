"""Atomic metadata custody for authenticated repository-provider reports."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated_collaboration import AuthenticatedCollaborationActivationService
from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
    SunderkeyError,
)
from .events import PROFILE_ID_PATTERN
from .identity import PrincipalAssertion, PrincipalOperation
from .mission_store_target_health_gate import verify_target_health_gate_store
from .provider_evidence_lifecycle import ProviderEvidenceLifecyclePolicy
from .provider_evidence_repository import (
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
    validate_provider_evidence_repository_ingest_receipt,
)
from .provider_evidence_repository_authentication import (
    _bounded_native,
    _capture_wrapper,
    _clock_value,
    _digest,
    _identifier,
    _native_document_json,
    _rebuild,
    _timestamp,
    authenticate_provider_evidence_repository_ingest_receipt,
    provider_evidence_repository_ingest_authentication_effect_payload,
    provider_evidence_repository_ingest_receipt_selection_sha256,
)
from .provider_evidence_repository_authentication import (
    validate_authenticated_provider_evidence_repository_ingest_receipt_document as validate_eri,
)
from .registry import ExpertRegistry
from .store import (
    PROVIDER_EVIDENCE_REPOSITORY_AUTHENTICATION_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
)

_AUTHENTICATION_ID = re.compile(r"ERI-[0-9A-F]{32}")


@dataclass(frozen=True)
class ProviderEvidenceRepositoryPrincipalCommit:
    """Original assertion-use metadata, never reusable current authority."""

    assertion_id: str
    assertion_sha256: str
    ledger_entry_sha256: str

    def to_dict(self) -> dict[str, str]:
        if (
            type(self.assertion_id) is not str
            or re.fullmatch(r"PAS-[0-9A-F]{32}", self.assertion_id) is None
        ):
            raise StoreIntegrityError("Repository assertion custody identity is invalid")
        try:
            _digest(self.assertion_sha256, "assertion_sha256")
            _digest(self.ledger_entry_sha256, "ledger_entry_sha256")
        except PrincipalAuthenticationError as exc:
            raise StoreIntegrityError("Repository assertion custody hash is invalid") from exc
        return {
            "assertion_id": self.assertion_id,
            "assertion_sha256": self.assertion_sha256,
            "ledger_entry_sha256": self.ledger_entry_sha256,
        }


@dataclass(frozen=True)
class AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt:
    """Historical local authentication custody, not accepted object custody."""

    authentication_json: str
    authenticated_at: str
    repository_attestor: ProviderEvidenceRepositoryPrincipalCommit

    @property
    def authentication_id(self) -> str:
        return self.to_dict()["repository_ingest_authentication"]["authentication_id"]

    @property
    def authentication_sha256(self) -> str:
        return self.to_dict()["repository_ingest_authentication"]["authentication_sha256"]

    def to_dict(self) -> dict[str, Any]:
        try:
            document = validate_eri(_native_document_json(self.authentication_json))
            _timestamp(self.authenticated_at, "authenticated_at")
        except SunderkeyError as exc:
            raise StoreIntegrityError("Stored repository authentication is invalid") from exc
        if document["authenticated_at"] != self.authenticated_at:
            raise StoreIntegrityError("Repository authentication time does not reconcile")
        if type(self.repository_attestor) is not ProviderEvidenceRepositoryPrincipalCommit:
            raise StoreIntegrityError("Repository assertion custody family is invalid")
        principal = self.repository_attestor.to_dict()
        if (
            principal["assertion_id"] != document["repository_attestor"]["assertion_id"]
            or principal["assertion_sha256"] != document["repository_attestor"]["assertion_sha256"]
        ):
            raise StoreIntegrityError("Repository assertion custody does not reconcile")
        return {
            "schema_version": 1,
            "repository_ingest_authentication": document,
            "authenticated_at": self.authenticated_at,
            "repository_attestor": principal,
            "metadata_custody_status": "durable_authenticated_repository_report_metadata",
            "evidence_custody_status": "provider_report_only",
            "lifecycle_policy_status": "prepared_policy_bound_not_activated",
            "repository_control_status": "provider_assertions_not_independently_verified",
            "external_effect_status": "authenticated_report_unverified_effect",
            "current_authority_status": "not_verified",
            "runtime_effect": "none",
            "qualification_effect": "none",
        }


class AuthenticatedProviderEvidenceRepositoryService:
    """Publish metadata atomically; replay is live-current, get is historical.

    Positive publication requires an active mission and no recorded paused or
    recovery-pending mission health latch. An absent latch is not healthy proof.
    This service performs no provider operation, observation or source assertion
    reconsumption and does not authorize terminal evidence closeout.
    """

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        repository_principal_subject: str,
        repository_principal_profile_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._expected_subject = repository_principal_subject
        self._expected_profile = repository_principal_profile_id
        self._expected_identity()
        self._policy = AuthenticatedCollaborationMissionPolicyService(store, registry, clock=clock)
        self._store = self._policy._store
        self._activation = self._policy._activation
        self._clock = self._policy._clock
        if not callable(self._clock):
            raise TypeError("clock must be callable")

    def _expected_identity(self) -> tuple[str, str]:
        subject = _identifier(self._expected_subject, "repository_principal_subject")
        profile = _identifier(self._expected_profile, "repository_principal_profile_id")
        if PROFILE_ID_PATTERN.fullmatch(profile) is None:
            raise PrincipalAuthenticationError("Expected repository profile is invalid")
        return subject, profile

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] < (
            PROVIDER_EVIDENCE_REPOSITORY_AUTHENTICATION_SCHEMA_VERSION
        ):
            raise StoreMigrationRequiredError("Repository authentication requires schema39")

    def _inputs(self, request, receipt, lifecycle_policy, assertion):
        expected_subject, expected_profile = self._expected_identity()
        if type(assertion) is not PrincipalAssertion or type(assertion.operation) is not (
            PrincipalOperation
        ):
            raise PrincipalAuthenticationError("Repository assertion family is invalid")
        document = {
            "ingest_request": _capture_wrapper(
                request, ProviderEvidenceRepositoryIngestRequest, "request_id", "request_sha256"
            ),
            "ingest_receipt": _capture_wrapper(
                receipt, ProviderEvidenceRepositoryIngestReceipt, "receipt_id", "receipt_sha256"
            ),
            "lifecycle_policy": _capture_wrapper(
                lifecycle_policy, ProviderEvidenceLifecyclePolicy, "policy_id", "policy_sha256"
            ),
            "repository_assertion": assertion.to_dict(),
            "expected_identity": [expected_subject, expected_profile],
        }
        _bounded_native(document)
        document = json.loads(canonical_json(document))
        request = _rebuild(ProviderEvidenceRepositoryIngestRequest, document["ingest_request"])
        receipt = _rebuild(ProviderEvidenceRepositoryIngestReceipt, document["ingest_receipt"])
        lifecycle_policy = _rebuild(ProviderEvidenceLifecyclePolicy, document["lifecycle_policy"])
        assertion = PrincipalAssertion.from_dict(document["repository_assertion"])
        validate_provider_evidence_repository_ingest_receipt(request, receipt)
        if assertion.subject != expected_subject or assertion.profile_id != expected_profile:
            raise PrincipalAuthenticationError(
                "Repository assertion differs from the expected identity"
            )
        return request, receipt, lifecycle_policy, assertion, expected_subject, expected_profile

    def get(
        self, authentication_id: str
    ) -> AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt:
        """Read original-time verified metadata without present authority checks."""
        return read_provider_evidence_repository_ingest_authentication(
            self._store, self._policy._registry, authentication_id
        )

    def authenticate(
        self,
        request: ProviderEvidenceRepositoryIngestRequest,
        receipt: ProviderEvidenceRepositoryIngestReceipt,
        lifecycle_policy: ProviderEvidenceLifecyclePolicy,
        *,
        repository_assertion: PrincipalAssertion,
    ) -> AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt:
        """Require live admission on both fresh publication and exact replay."""
        request, receipt, lifecycle_policy, assertion, subject, profile = self._inputs(
            request, receipt, lifecycle_policy, repository_assertion
        )
        mission_id = lifecycle_policy.to_dict()["mission"]["mission_id"]
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
        intent = {
            "ingest_receipt_selection_sha256": (
                provider_evidence_repository_ingest_receipt_selection_sha256(receipt)
            ),
            "ingest_request_sha256": request.request_sha256,
            "lifecycle_policy_sha256": lifecycle_policy.policy_sha256,
            "mission_id": mission_id,
            "principal_profile_id": profile,
        }
        material = self._policy._assertion_material(assertion, operation, intent)
        try:
            with self._store._write_connection() as connection:
                self._require_schema(connection)
                identity, trust_policies, mission, scope_grants, ledger = (
                    self._activation._verified_mission_state(connection, mission_id)
                )
                self._store._require_mission_active(connection, mission_id)
                health = verify_target_health_gate_store(connection, mission_id)
                if health.paused_count or health.recovery_pending_count:
                    raise StoreConflictError(
                        "Recorded mission health latch denies repository publication"
                    )
                source, dispatch = self._store._resolve_provider_evidence_repository_ingest_sources(
                    connection, mission=mission, ingest_request=request
                )
                existing_use = self._policy._existing_use(connection, assertion)
                store = self._store
                find = store._provider_evidence_repository_ingest_authentication_row_for_assertion
                existing = find(connection, assertion)
                if existing_use is not None:
                    self._policy._require_exact_replay(
                        existing_use,
                        assertion=assertion,
                        mission_id=mission_id,
                        operation=operation,
                        material=material,
                    )
                    if existing is None:
                        raise StoreIntegrityError(
                            "Repository assertion has no authentication custody"
                        )
                    self._require_exact_authentication(
                        existing, request, receipt, lifecycle_policy, source, dispatch, assertion
                    )
                elif existing is not None:
                    raise StoreIntegrityError("Repository authentication has no assertion use")

                now = _clock_value(self._clock)
                consumed_at = format_timestamp(now)
                self._activation._require_runtime_not_before_state(connection, mission, ledger, now)
                gate_times = connection.execute(
                    "SELECT updated_at FROM target_health_gate_heads WHERE mission_id = ?",
                    (mission_id,),
                ).fetchall()
                if any(
                    parse_timestamp(row["updated_at"], "health.updated_at") > now
                    for row in gate_times
                ):
                    raise PrincipalAuthenticationError(
                        "Runtime clock precedes local mission health state"
                    )
                verified_policy, scope = self._policy._verified_scope(
                    connection,
                    assertion=assertion,
                    operation=operation,
                    mission=mission,
                    identity=identity,
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                    now=now,
                    consumed_time=now,
                )
                authenticated = authenticate_provider_evidence_repository_ingest_receipt(
                    request,
                    receipt,
                    lifecycle_policy,
                    source,
                    dispatch,
                    repository_assertion=assertion,
                    verified_policy=verified_policy,
                    repository_scope=scope,
                    repository_principal_subject=subject,
                    repository_principal_profile_id=profile,
                    expected_audience=identity["audience"],
                    expected_store_id=identity["store_id"],
                    clock=lambda: now,
                )
                if existing_use is not None:
                    # The current-time result is only an eligibility check. Its
                    # timestamp and ERI may differ from immutable original custody.
                    self._activation._verified_mission_state(connection, mission_id)
                    return self._receipt(connection, existing)

                effect = self._policy._effect(
                    authenticated.authentication_id,
                    operation,
                    provider_evidence_repository_ingest_authentication_effect_payload(
                        authenticated
                    ),
                    consumed_at,
                )
                self._policy._record_assertion(
                    connection,
                    principal=authenticated.repository_attestor,
                    assertion=assertion,
                    mission_id=mission_id,
                    operation=operation,
                    material=material,
                    effect=effect,
                    ledger=ledger,
                    consumed_at=consumed_at,
                )
                self._store._insert_provider_evidence_repository_ingest_authentication(
                    connection, authenticated.to_dict()
                )
                self._activation._verified_mission_state(connection, mission_id)
                row = self._store._provider_evidence_repository_ingest_authentication_row(
                    connection, authenticated.authentication_id
                )
                return self._receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Could not publish repository authentication metadata"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not publish repository authentication metadata") from exc

    @staticmethod
    def _require_exact_authentication(row, request, receipt, policy, source, dispatch, assertion):
        try:
            document = validate_eri(_native_document_json(row["authentication_json"]))
        except SunderkeyError as exc:
            raise StoreIntegrityError("Stored repository authentication is invalid") from exc
        incoming = {
            "ingest_request": request.to_dict(),
            "ingest_receipt": receipt.to_dict(),
            "lifecycle_policy": policy.to_dict(),
            "source_report_authentication": source,
            "source_dispatch": dispatch.to_dict(),
        }
        if any(
            canonical_json(document[key]) != canonical_json(value)
            for key, value in incoming.items()
        ) or (
            row["repository_issuer"] != assertion.issuer
            or row["repository_assertion_id"] != assertion.assertion_id
            or document["repository_attestor"]["subject"] != assertion.subject
            or document["repository_attestor"]["profile_id"] != assertion.profile_id
        ):
            raise StoreConflictError(
                "Repository assertion was consumed for different report metadata"
            )

    @staticmethod
    def _receipt(connection, row) -> AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt:
        use = connection.execute(
            """SELECT assertion_hash, entry_hash FROM principal_assertion_uses
            WHERE issuer = ? AND assertion_id = ? AND mission_id = ?""",
            (row["repository_issuer"], row["repository_assertion_id"], row["mission_id"]),
        ).fetchone()
        if use is None:
            raise StoreIntegrityError("Repository assertion custody is missing")
        result = AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt(
            authentication_json=row["authentication_json"],
            authenticated_at=row["authenticated_at"],
            repository_attestor=ProviderEvidenceRepositoryPrincipalCommit(
                assertion_id=row["repository_assertion_id"],
                assertion_sha256=use["assertion_hash"],
                ledger_entry_sha256=use["entry_hash"],
            ),
        )
        result.to_dict()
        return result


def read_provider_evidence_repository_ingest_authentication(
    store: MissionStore,
    registry: ExpertRegistry,
    authentication_id: str,
) -> AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt:
    """Read historical signed metadata without requesting present authority.

    The caller selects the local store and registry, not a repository identity,
    credential or current clock. The original-time signature, source and reciprocal
    custody checks run in one query-only read transaction. Returned metadata is not
    current authority, independently verified provider custody or raw-byte replay.
    """
    if (
        type(authentication_id) is not str
        or _AUTHENTICATION_ID.fullmatch(authentication_id) is None
    ):
        raise StoreError("authentication_id is invalid")
    historical = AuthenticatedCollaborationActivationService(store, registry)
    try:
        with store._read_connection() as connection:
            connection.execute("PRAGMA query_only = ON")
            fence = connection.execute("PRAGMA query_only").fetchone()
            if fence is None or type(fence[0]) is not int or fence[0] != 1:
                raise StoreIntegrityError("Repository historical read requires a query-only fence")
            AuthenticatedProviderEvidenceRepositoryService._require_schema(connection)
            row = store._provider_evidence_repository_ingest_authentication_row(
                connection, authentication_id
            )
            historical._verified_mission_state(connection, row["mission_id"])
            return AuthenticatedProviderEvidenceRepositoryService._receipt(connection, row)
    except sqlite3.Error as exc:
        raise StoreError("Could not read repository authentication") from exc


__all__ = [
    "AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt",
    "AuthenticatedProviderEvidenceRepositoryService",
    "ProviderEvidenceRepositoryPrincipalCommit",
    "read_provider_evidence_repository_ingest_authentication",
]
