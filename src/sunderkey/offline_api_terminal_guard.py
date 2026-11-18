"""Opt-in local guard that suppresses unsupported terminal API mutations."""

from __future__ import annotations

from .local_api_service import (
    AccessContext,
    LocalApiService,
    LocalApiServiceError,
    Operation,
    ServiceRequest,
    ServiceResponse,
)

FINDING_TERMINAL_STATUSES = frozenset({"accepted_risk", "false_positive", "remediated", "closed"})
FINDING_STATUSES = frozenset({"discovered", "triaged", "validated"}) | FINDING_TERMINAL_STATUSES
REMEDIATION_STATUSES = frozenset(
    {"guidance_ready", "resubmitted", "retest_pending", "closed", "reopened"}
)


class OfflineApiTerminalGuardError(ValueError):
    """Raised before delegation when an API terminal assertion is blocked."""


def _owned_request(request: ServiceRequest) -> ServiceRequest:
    if type(request) is not ServiceRequest or type(request.access) is not AccessContext:
        raise OfflineApiTerminalGuardError("request must use exact local API types")
    try:
        return ServiceRequest(
            request_id=request.request_id,
            operation=request.operation,
            access=AccessContext(
                tenant_id=request.access.tenant_id,
                context_id=request.access.context_id,
                principal_id=request.access.principal_id,
                session_ref=request.access.session_ref,
            ),
            requested_at=request.requested_at,
            resource_kind=request.resource_kind,
            resource_id=request.resource_id,
            payload=request.payload,
            expected_concurrency_token=request.expected_concurrency_token,
            idempotency_key=request.idempotency_key,
            cursor=request.cursor,
            page_size=request.page_size,
        )
    except (LocalApiServiceError, TypeError, ValueError, RuntimeError) as exc:
        raise OfflineApiTerminalGuardError("request cannot be captured exactly") from exc


def _reject_terminal(request: ServiceRequest) -> None:
    if request.operation is Operation.UPSERT_FINDING:
        payload = request.payload
        if payload is None or type(payload.get("status")) is not str:
            raise OfflineApiTerminalGuardError("finding status is invalid")
        status = payload["status"]
        if status not in FINDING_STATUSES:
            raise OfflineApiTerminalGuardError("finding status is unsupported")
        if status in FINDING_TERMINAL_STATUSES:
            raise OfflineApiTerminalGuardError("terminal finding assertion is blocked")
    elif request.operation is Operation.RECORD_REMEDIATION:
        payload = request.payload
        if payload is None or type(payload.get("closure_status")) is not str:
            raise OfflineApiTerminalGuardError("remediation status is invalid")
        status = payload["closure_status"]
        if status not in REMEDIATION_STATUSES:
            raise OfflineApiTerminalGuardError("remediation status is unsupported")
        if status == "closed":
            raise OfflineApiTerminalGuardError("terminal remediation assertion is blocked")


class OfflineApiTerminalGuard:
    """Delegate only nonterminal requests to an injected local API service."""

    def __init__(self, service: LocalApiService) -> None:
        if type(service) is not LocalApiService:
            raise OfflineApiTerminalGuardError("service must be a LocalApiService")
        self._service = service

    def handle(self, request: ServiceRequest) -> ServiceResponse:
        """Reject terminal status assertions before any service call or effect."""

        owned = _owned_request(request)
        _reject_terminal(owned)
        return self._service.handle(owned)


__all__ = ["OfflineApiTerminalGuard", "OfflineApiTerminalGuardError"]
