"""Offline reference adapters for authorized target-session acquisition.

The provider accepts opaque credential references only. It delegates all
authorization, lease currentness, revocation, and admission checks to the
existing authorized target-session runtime.
"""

from __future__ import annotations

import hmac
import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .assessment_transport_contracts import TargetSessionIntent
from .authorized_target_session_runtime import (
    AtomicLeaseUseStore,
    AuthorizedTargetSessionPolicy,
    CredentialSessionCommand,
    CredentialSessionProviderFailure,
    CredentialSessionResult,
    LeaseRevocationChecker,
    LeaseUseCompletionEvidence,
    LeaseUseReservationEvidence,
    LeaseUseReservationRequest,
    LeaseUseStoreFailure,
    OpaqueLeaseBinding,
    RevocationObservation,
    TargetSessionReceipt,
    TargetSessionRuntimeClock,
    TargetSessionSafetyMonitor,
    execute_authorized_target_session,
    principal_attestation_sha256,
    session_attestation_sha256,
)
from .credential_broker_contracts import CredentialLease
from .execution_control_runtime import (
    AdmissionReceipt,
    ExecutionRequest,
    canonical_sha256,
)
from .signed_scope_compiler import VerifiedAssessmentScope
from .target_adapter_conformance import AdapterStopRequested, AdapterStopState

NO_BUILTIN_IO = True
AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"


class ReferenceTargetSessionAdapterError(ValueError):
    """Raised when injected session evidence fails the reference contract."""


def _digest(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ReferenceTargetSessionAdapterError(f"{label} must be a sha256 digest")
    return value


class SessionTransportStatus(StrEnum):
    ACQUIRED = "acquired"
    OPERATOR_CHALLENGE = "operator_challenge"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class OpaqueSessionTransportResult:
    """Secret-free result from one injected authentication attempt."""

    status: SessionTransportStatus
    expires_at: str | None
    challenge_reference_sha256: str | None = None

    def __post_init__(self) -> None:
        try:
            status = SessionTransportStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ReferenceTargetSessionAdapterError("session status is invalid") from exc
        object.__setattr__(self, "status", status)
        if status is SessionTransportStatus.ACQUIRED:
            if not isinstance(self.expires_at, str):
                raise ReferenceTargetSessionAdapterError("acquired session requires expiry")
            if self.challenge_reference_sha256 is not None:
                raise ReferenceTargetSessionAdapterError(
                    "acquired session cannot claim an operator challenge"
                )
        elif self.expires_at is not None:
            raise ReferenceTargetSessionAdapterError("non-acquired result cannot claim expiry")
        if status is SessionTransportStatus.OPERATOR_CHALLENGE:
            _digest(self.challenge_reference_sha256 or "", "challenge_reference_sha256")
        elif self.challenge_reference_sha256 is not None:
            raise ReferenceTargetSessionAdapterError(
                "challenge reference is allowed only for operator challenge"
            )


class OpaqueSessionTransport(Protocol):
    """Injected provider transport that receives only an opaque command."""

    def acquire(self, command: CredentialSessionCommand) -> OpaqueSessionTransportResult: ...


@dataclass(frozen=True, slots=True)
class OperatorChallengeSuspension:
    """Non-authoritative evidence that operator action is required."""

    intent_sha256: str
    execution_request_sha256: str
    lease_sha256: str
    requested_session_id: str
    challenge_reference_sha256: str
    authority_effect: str = AUTHORITY_EFFECT
    qualification_effect: str = QUALIFICATION_EFFECT

    def __post_init__(self) -> None:
        for value, label in (
            (self.intent_sha256, "intent_sha256"),
            (self.execution_request_sha256, "execution_request_sha256"),
            (self.lease_sha256, "lease_sha256"),
            (self.challenge_reference_sha256, "challenge_reference_sha256"),
        ):
            _digest(value, label)
        if not isinstance(self.requested_session_id, str) or len(self.requested_session_id) < 2:
            raise ReferenceTargetSessionAdapterError("requested_session_id is invalid")
        if self.authority_effect != AUTHORITY_EFFECT:
            raise ReferenceTargetSessionAdapterError("suspension cannot grant authority")
        if self.qualification_effect != QUALIFICATION_EFFECT:
            raise ReferenceTargetSessionAdapterError("suspension cannot grant qualification")


class ReferenceCredentialSessionProvider:
    """One-attempt provider with opaque secret and challenge suspension rules."""

    def __init__(
        self,
        *,
        transport: OpaqueSessionTransport,
        stop_state: AdapterStopState,
        cleanup_obligation_ref: str,
        revocation_obligation_ref: str,
    ) -> None:
        self.transport = transport
        self.stop_state = stop_state
        self.cleanup_obligation_ref = cleanup_obligation_ref
        self.revocation_obligation_ref = revocation_obligation_ref
        self.calls = 0
        self.last_suspension: OperatorChallengeSuspension | None = None

    def acquire(self, command: CredentialSessionCommand) -> CredentialSessionResult:
        if not isinstance(command, CredentialSessionCommand):
            raise CredentialSessionProviderFailure("invalid_command")
        if not command.credential_reference.startswith("credref:"):
            raise CredentialSessionProviderFailure("opaque_reference_required")
        if command.maximum_attempts != 1 or command.retries_allowed is not False:
            raise CredentialSessionProviderFailure("unsafe_attempt_policy")
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise CredentialSessionProviderFailure(exc.code) from exc
        self.calls += 1
        result = self.transport.acquire(command)
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise CredentialSessionProviderFailure(exc.code) from exc
        if not isinstance(result, OpaqueSessionTransportResult):
            raise CredentialSessionProviderFailure("invalid_provider_result")
        if result.status is SessionTransportStatus.OPERATOR_CHALLENGE:
            self.last_suspension = OperatorChallengeSuspension(
                intent_sha256=command.intent_sha256,
                execution_request_sha256=command.execution_request_sha256,
                lease_sha256=command.lease_sha256,
                requested_session_id=command.requested_session_id,
                challenge_reference_sha256=result.challenge_reference_sha256 or "",
            )
            raise CredentialSessionProviderFailure("operator_challenge_required")
        if result.status is SessionTransportStatus.DENIED:
            raise CredentialSessionProviderFailure("authentication_denied")
        expires_at = result.expires_at or ""
        return CredentialSessionResult(
            succeeded=True,
            failure_code=None,
            session_id=command.requested_session_id,
            principal_label=command.principal_label,
            isolated=True,
            expires_at=expires_at,
            authentication_attempts=1,
            session_attestation_sha256=session_attestation_sha256(command, expires_at),
            principal_attestation_sha256=principal_attestation_sha256(command),
            cleanup_obligation_ref=self.cleanup_obligation_ref,
            revocation_obligation_ref=self.revocation_obligation_ref,
            credential_material_returned=False,
        )


class InMemoryLeaseRevocationChecker:
    """Deterministic revocation source for repository-only tests."""

    def __init__(self) -> None:
        self._revoked: set[tuple[str, str]] = set()

    def revoke(self, lease_id: str, lease_sha256: str) -> None:
        _digest(lease_sha256, "lease_sha256")
        self._revoked.add((lease_id, lease_sha256))

    def observe(self, lease_id: str, lease_sha256: str) -> RevocationObservation:
        _digest(lease_sha256, "lease_sha256")
        revoked = (lease_id, lease_sha256) in self._revoked
        return RevocationObservation(
            lease_id=lease_id,
            lease_sha256=lease_sha256,
            revoked=revoked,
            evidence_sha256=canonical_sha256(
                {
                    "lease_id": lease_id,
                    "lease_sha256": lease_sha256,
                    "revoked": revoked,
                    "source": "reference_in_memory_revocation",
                }
            ),
        )


class InMemoryAtomicLeaseUseStore:
    """Exact single-use lease reservation store for deterministic tests."""

    def __init__(self) -> None:
        self._reservations: dict[str, LeaseUseReservationEvidence] = {}
        self._completions: dict[str, LeaseUseCompletionEvidence] = {}
        self._uses: set[tuple[str, str, int]] = set()
        self._one_time_leases: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def reserve(self, request: LeaseUseReservationRequest) -> LeaseUseReservationEvidence:
        if not isinstance(request, LeaseUseReservationRequest):
            raise LeaseUseStoreFailure("invalid_reservation_request")
        key = request.reservation_key_sha256
        use = (request.lease_id, request.lease_sha256, request.lease_use_number)
        lease = (request.lease_id, request.lease_sha256)
        with self._lock:
            if (
                key in self._reservations
                or use in self._uses
                or (
                    request.lease_mode.value == "one_time"
                    and lease in self._one_time_leases
                )
            ):
                raise LeaseUseStoreFailure("lease_use_replayed")
            evidence = LeaseUseReservationEvidence(key)
            self._reservations[key] = evidence
            self._uses.add(use)
            if request.lease_mode.value == "one_time":
                self._one_time_leases.add(lease)
            return evidence

    def complete(
        self,
        reservation: LeaseUseReservationEvidence,
        outcome: str,
        provider_called: bool,
    ) -> LeaseUseCompletionEvidence:
        if not isinstance(reservation, LeaseUseReservationEvidence):
            raise LeaseUseStoreFailure("invalid_reservation")
        with self._lock:
            stored = self._reservations.get(reservation.reservation_key_sha256)
            if stored is None or not hmac.compare_digest(
                stored.reservation_sha256, reservation.reservation_sha256
            ):
                raise LeaseUseStoreFailure("reservation_not_found")
            if reservation.reservation_key_sha256 in self._completions:
                raise LeaseUseStoreFailure("lease_use_already_completed")
            completion = LeaseUseCompletionEvidence(
                reservation_id=reservation.reservation_id,
                reservation_sha256=reservation.reservation_sha256,
                reservation_key_sha256=reservation.reservation_key_sha256,
                outcome=outcome,
                provider_called=provider_called,
            )
            self._completions[reservation.reservation_key_sha256] = completion
            return completion


class ReferenceAuthorizedTargetSessionAdapter:
    """Composition root that delegates admission to the existing runtime."""

    def __init__(
        self,
        *,
        provider: ReferenceCredentialSessionProvider,
        revocation_checker: LeaseRevocationChecker,
        lease_use_store: AtomicLeaseUseStore,
    ) -> None:
        self.provider = provider
        self.revocation_checker = revocation_checker
        self.lease_use_store = lease_use_store

    def acquire(
        self,
        *,
        scope: VerifiedAssessmentScope,
        intent: TargetSessionIntent,
        execution_request: ExecutionRequest,
        admission: AdmissionReceipt,
        policy: AuthorizedTargetSessionPolicy,
        lease: CredentialLease | OpaqueLeaseBinding,
        lease_use_number: int,
        clock: TargetSessionRuntimeClock,
        safety_monitor: TargetSessionSafetyMonitor,
    ) -> TargetSessionReceipt:
        """Run only through the authorized target-session boundary."""

        return execute_authorized_target_session(
            scope=scope,
            intent=intent,
            execution_request=execution_request,
            admission=admission,
            policy=policy,
            lease=lease,
            lease_use_number=lease_use_number,
            clock=clock,
            safety_monitor=safety_monitor,
            revocation_checker=self.revocation_checker,
            lease_use_store=self.lease_use_store,
            provider=self.provider,
        )


__all__ = [
    "AUTHORITY_EFFECT",
    "NO_BUILTIN_IO",
    "QUALIFICATION_EFFECT",
    "InMemoryAtomicLeaseUseStore",
    "InMemoryLeaseRevocationChecker",
    "OpaqueSessionTransport",
    "OpaqueSessionTransportResult",
    "OperatorChallengeSuspension",
    "ReferenceAuthorizedTargetSessionAdapter",
    "ReferenceCredentialSessionProvider",
    "ReferenceTargetSessionAdapterError",
    "SessionTransportStatus",
]
