"""Durable webhook and enterprise integration delivery worker.

The worker composes the fenced integration outbox with caller-supplied
transports. It contains no HTTP client, socket access, credential resolution,
filesystem discovery, or external service integration.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .api_service_contracts import WebhookEventType, WebhookSubscription
from .enterprise_connector_contracts import (
    ConnectorBinding,
    ConnectorDeliveryObservation,
    ConnectorDeliveryRequest,
    ConnectorKind,
    ConnectorTransportResponse,
    DeliveryDisposition,
    EnterpriseConnectorTransport,
    IntegrationProjection,
    build_connector_delivery_request,
    deliver_with_connector,
)
from .integration_outbox import (
    DeliveryLease,
    DestinationKind,
    DestinationReference,
    IntegrationOutbox,
    IntegrationOutboxError,
    ObservationStatus,
    SignedDeliveryObservation,
    VerifiedIntegrationEvent,
    verify_delivery_observation,
)

SCHEMA_VERSION = 1
NO_BUILTIN_NETWORK = True
DELIVERY_SEMANTIC = "at_least_once"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_REFERENCE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9._~:/+-]{1,255}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class IntegrationDeliveryWorkerError(ValueError):
    """Raised when worker configuration or delivery evidence fails closed."""


class RouteKind(StrEnum):
    WEBHOOK = "webhook"
    ENTERPRISE_CONNECTOR = "enterprise_connector"


class WorkerOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    RETRY_SCHEDULED = "retry_scheduled"
    DEAD_LETTER = "dead_letter"


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise IntegrationDeliveryWorkerError("value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _exact(raw: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise IntegrationDeliveryWorkerError(f"{label} fields are invalid")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise IntegrationDeliveryWorkerError(f"{label} must be a sha256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise IntegrationDeliveryWorkerError(f"{label} is invalid")
    return value


def _reference(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REFERENCE_RE.fullmatch(value) is None:
        raise IntegrationDeliveryWorkerError(f"{label} must be an opaque reference")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise IntegrationDeliveryWorkerError(f"{label} is invalid")
    return value


def _time(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IntegrationDeliveryWorkerError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IntegrationDeliveryWorkerError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise IntegrationDeliveryWorkerError(f"{label} must be canonical UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _public_key_sha256(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkerPolicy:
    """Per-pass claim and request bounds layered over persisted retry policy."""

    lease_seconds: int = 30
    claim_limit: int = 10
    request_ttl_seconds: int = 20

    def __post_init__(self) -> None:
        for value, label, maximum in (
            (self.lease_seconds, "lease_seconds", 3600),
            (self.claim_limit, "claim_limit", 100),
            (self.request_ttl_seconds, "request_ttl_seconds", 3600),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise IntegrationDeliveryWorkerError(f"{label} is invalid")
        if self.request_ttl_seconds >= self.lease_seconds:
            raise IntegrationDeliveryWorkerError("request TTL must be shorter than its lease")


@dataclass(frozen=True, slots=True)
class WebhookDeliveryRequest:
    """Secret-free webhook request passed only to an injected transport."""

    subscription_id: str
    subscription_sha256: str
    tenant_ref: str
    destination_id: str
    destination_sha256: str
    event: IntegrationProjection
    idempotency_key: str
    sequence_number: int
    attempt_number: int
    body_json: str
    created_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    KIND: ClassVar[str] = "webhook_delivery_worker_request"

    def __post_init__(self) -> None:
        _identifier(self.subscription_id, "subscription_id")
        _digest(self.subscription_sha256, "subscription_sha256")
        _reference(self.tenant_ref, "tenant_ref")
        _identifier(self.destination_id, "destination_id")
        _digest(self.destination_sha256, "destination_sha256")
        if not isinstance(self.event, IntegrationProjection):
            raise IntegrationDeliveryWorkerError("event projection is invalid")
        _digest(self.idempotency_key, "idempotency_key")
        for value, label in (
            (self.sequence_number, "sequence_number"),
            (self.attempt_number, "attempt_number"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise IntegrationDeliveryWorkerError(f"{label} is invalid")
        try:
            body = json.loads(self.body_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrationDeliveryWorkerError("body_json is invalid") from exc
        if canonical_json(body) != self.body_json or body != self.event.to_dict():
            raise IntegrationDeliveryWorkerError("body_json does not match event projection")
        _time(self.created_at, "created_at")
        _time(self.expires_at, "expires_at")
        if _instant(self.expires_at) <= _instant(self.created_at):
            raise IntegrationDeliveryWorkerError("request expiry must follow creation")
        request_id, digest = _identity("WDR", self.KIND, self.body())
        if self.request_id and self.request_id != request_id:
            raise IntegrationDeliveryWorkerError("request_id does not match content")
        if self.request_sha256 and self.request_sha256 != digest:
            raise IntegrationDeliveryWorkerError("request_sha256 does not match content")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "request_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "body_json": self.body_json,
            "created_at": self.created_at,
            "destination_id": self.destination_id,
            "destination_sha256": self.destination_sha256,
            "event": self.event.to_dict(),
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
            "sequence_number": self.sequence_number,
            "subscription_id": self.subscription_id,
            "subscription_sha256": self.subscription_sha256,
            "tenant_ref": self.tenant_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> WebhookDeliveryRequest:
        fields = {
            "attempt_number",
            "body_json",
            "created_at",
            "destination_id",
            "destination_sha256",
            "event",
            "expires_at",
            "idempotency_key",
            "kind",
            "request_id",
            "request_sha256",
            "schema_version",
            "sequence_number",
            "subscription_id",
            "subscription_sha256",
            "tenant_ref",
        }
        _exact(raw, fields, cls.KIND)
        if raw["kind"] != cls.KIND or raw["schema_version"] != SCHEMA_VERSION:
            raise IntegrationDeliveryWorkerError("webhook request metadata is invalid")
        candidate = cls(
            subscription_id=raw["subscription_id"],
            subscription_sha256=raw["subscription_sha256"],
            tenant_ref=raw["tenant_ref"],
            destination_id=raw["destination_id"],
            destination_sha256=raw["destination_sha256"],
            event=IntegrationProjection.from_dict(raw["event"]),
            idempotency_key=raw["idempotency_key"],
            sequence_number=raw["sequence_number"],
            attempt_number=raw["attempt_number"],
            body_json=raw["body_json"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            request_id=raw["request_id"],
            request_sha256=raw["request_sha256"],
        )
        if candidate.to_dict() != dict(raw):
            raise IntegrationDeliveryWorkerError("webhook request identity is invalid")
        return candidate


@dataclass(frozen=True, slots=True)
class TransportObservation:
    """Normalized response metadata with no response body."""

    request_id: str
    request_sha256: str
    disposition: DeliveryDisposition | str
    status_code: int
    response_sha256: str
    external_resource_ref: str | None
    retry_after_seconds: int | None
    observed_at: str
    source_observation_id: str | None = None
    source_observation_sha256: str | None = None
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "delivery_worker_transport_observation"

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _digest(self.request_sha256, "request_sha256")
        try:
            disposition = DeliveryDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise IntegrationDeliveryWorkerError("transport disposition is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        ConnectorTransportResponse(
            self.status_code,
            self.response_sha256,
            self.external_resource_ref,
            self.retry_after_seconds,
        )
        _time(self.observed_at, "observed_at")
        if (self.source_observation_id is None) != (self.source_observation_sha256 is None):
            raise IntegrationDeliveryWorkerError("source observation binding is incomplete")
        if self.source_observation_id is not None:
            _identifier(self.source_observation_id, "source_observation_id")
            _digest(self.source_observation_sha256, "source_observation_sha256")
        observation_id, digest = _identity("WTO", self.KIND, self.body())
        if self.observation_id and self.observation_id != observation_id:
            raise IntegrationDeliveryWorkerError("observation_id does not match content")
        if self.observation_sha256 and self.observation_sha256 != digest:
            raise IntegrationDeliveryWorkerError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", observation_id)
        object.__setattr__(self, "observation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "external_resource_ref": self.external_resource_ref,
            "observed_at": self.observed_at,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "retry_after_seconds": self.retry_after_seconds,
            "source_observation_id": self.source_observation_id,
            "source_observation_sha256": self.source_observation_sha256,
            "status_code": self.status_code,
        }


class IntegrationWorkerTransport(EnterpriseConnectorTransport, Protocol):
    """Only runtime boundary allowed to resolve endpoints, keys, or credentials."""

    def send_webhook(
        self,
        *,
        endpoint_ref: str,
        signing_key_ref: str,
        request: WebhookDeliveryRequest,
    ) -> ConnectorTransportResponse: ...

    def acknowledge(
        self,
        *,
        event: VerifiedIntegrationEvent,
        destination: DestinationReference,
        idempotency_key: str,
        attempt_number: int,
        transport_observation: TransportObservation,
    ) -> SignedDeliveryObservation: ...


@dataclass(frozen=True, slots=True)
class WorkerRoute:
    """Runtime binding between one outbox destination and one external route."""

    tenant_ref: str
    destination_id: str
    destination_sha256: str
    route_kind: RouteKind | str
    adapter_id: str
    acknowledgement_signer_key_id: str
    acknowledgement_public_key: Ed25519PublicKey
    connector_binding: ConnectorBinding | None = None
    webhook_subscription: WebhookSubscription | None = None

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref")
        _identifier(self.destination_id, "destination_id")
        _digest(self.destination_sha256, "destination_sha256")
        _identifier(self.adapter_id, "adapter_id")
        _identifier(self.acknowledgement_signer_key_id, "acknowledgement_signer_key_id")
        if not isinstance(self.acknowledgement_public_key, Ed25519PublicKey):
            raise IntegrationDeliveryWorkerError("acknowledgement public key is invalid")
        try:
            kind = RouteKind(self.route_kind)
        except (TypeError, ValueError) as exc:
            raise IntegrationDeliveryWorkerError("route_kind is invalid") from exc
        object.__setattr__(self, "route_kind", kind)
        expected_destination = f"integrationdestination:{self.destination_id}"
        if kind is RouteKind.ENTERPRISE_CONNECTOR:
            if not isinstance(self.connector_binding, ConnectorBinding):
                raise IntegrationDeliveryWorkerError("connector route requires a binding")
            if self.webhook_subscription is not None:
                raise IntegrationDeliveryWorkerError(
                    "connector route cannot include a subscription"
                )
            if (
                self.connector_binding.tenant_ref != self.tenant_ref
                or self.connector_binding.destination_ref != expected_destination
            ):
                raise IntegrationDeliveryWorkerError("connector tenant or destination is rebound")
        else:
            if not isinstance(self.webhook_subscription, WebhookSubscription):
                raise IntegrationDeliveryWorkerError("webhook route requires a subscription")
            if self.connector_binding is not None:
                raise IntegrationDeliveryWorkerError("webhook route cannot include a connector")
            expected_tenant = f"tenantref:{self.webhook_subscription.binding.tenant_id}"
            if self.tenant_ref != expected_tenant:
                raise IntegrationDeliveryWorkerError("webhook tenant is rebound")

    @property
    def acknowledgement_public_key_sha256(self) -> str:
        return _public_key_sha256(self.acknowledgement_public_key)


@dataclass(frozen=True, slots=True)
class WorkerAttemptReceipt:
    """Content-addressed proof of one completed at-least-once attempt."""

    worker_id: str
    tenant_ref: str
    route_kind: RouteKind | str
    outbox_id: str
    sequence_number: int
    fencing_token: int
    attempt_number: int
    max_attempts: int
    lease_expires_at: str
    destination_id: str
    destination_sha256: str
    binding_id: str | None
    binding_sha256: str | None
    request_id: str
    request_sha256: str
    idempotency_key: str
    transport_observation_id: str
    transport_observation_sha256: str
    response_sha256: str
    acknowledgement_id: str
    acknowledgement_sha256: str
    acknowledgement_signer_key_id: str
    acknowledgement_public_key_sha256: str
    disposition: DeliveryDisposition | str
    outcome: WorkerOutcome | str
    outbox_state: str
    next_attempt_at: str
    completed_at: str
    retry_after_seconds: int | None
    remote_receipt_ref: str | None
    error_code: str | None
    receipt_id: str = ""
    receipt_sha256: str = ""
    delivery_semantic: str = DELIVERY_SEMANTIC
    exactly_once_claimed: bool = False
    authorization_effect: str = "none"
    deployment_effect: str = "none"
    qualification_effect: str = "none"

    KIND: ClassVar[str] = "integration_delivery_worker_receipt"

    def __post_init__(self) -> None:
        _identifier(self.worker_id, "worker_id")
        _reference(self.tenant_ref, "tenant_ref")
        try:
            route_kind = RouteKind(self.route_kind)
            disposition = DeliveryDisposition(self.disposition)
            outcome = WorkerOutcome(self.outcome)
        except (TypeError, ValueError) as exc:
            raise IntegrationDeliveryWorkerError("receipt enum value is invalid") from exc
        object.__setattr__(self, "route_kind", route_kind)
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "outcome", outcome)
        for value, label in (
            (self.outbox_id, "outbox_id"),
            (self.destination_id, "destination_id"),
            (self.request_id, "request_id"),
            (self.transport_observation_id, "transport_observation_id"),
            (self.acknowledgement_id, "acknowledgement_id"),
            (self.acknowledgement_signer_key_id, "acknowledgement_signer_key_id"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.destination_sha256, "destination_sha256"),
            (self.request_sha256, "request_sha256"),
            (self.idempotency_key, "idempotency_key"),
            (self.transport_observation_sha256, "transport_observation_sha256"),
            (self.response_sha256, "response_sha256"),
            (self.acknowledgement_sha256, "acknowledgement_sha256"),
            (self.acknowledgement_public_key_sha256, "acknowledgement_public_key_sha256"),
        ):
            _digest(value, label)
        for value, label in (
            (self.sequence_number, "sequence_number"),
            (self.fencing_token, "fencing_token"),
            (self.attempt_number, "attempt_number"),
            (self.max_attempts, "max_attempts"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise IntegrationDeliveryWorkerError(f"{label} is invalid")
        if self.attempt_number > self.max_attempts:
            raise IntegrationDeliveryWorkerError("attempt exceeds persisted attempt budget")
        for value, label in (
            (self.lease_expires_at, "lease_expires_at"),
            (self.next_attempt_at, "next_attempt_at"),
            (self.completed_at, "completed_at"),
        ):
            _time(value, label)
        if (self.binding_id is None) != (self.binding_sha256 is None):
            raise IntegrationDeliveryWorkerError("connector binding evidence is incomplete")
        if route_kind is RouteKind.ENTERPRISE_CONNECTOR:
            if self.binding_id is None or not self.binding_id.startswith("ECB-"):
                raise IntegrationDeliveryWorkerError("connector binding evidence is missing")
            _digest(self.binding_sha256, "binding_sha256")
        elif self.binding_id is not None:
            raise IntegrationDeliveryWorkerError("webhook receipt cannot claim connector binding")
        if self.retry_after_seconds is not None and (
            not isinstance(self.retry_after_seconds, int)
            or isinstance(self.retry_after_seconds, bool)
            or not 1 <= self.retry_after_seconds <= 86_400
        ):
            raise IntegrationDeliveryWorkerError("retry_after_seconds is invalid")
        if self.remote_receipt_ref is not None:
            _reference(self.remote_receipt_ref, "remote_receipt_ref")
        if self.error_code is not None:
            _code(self.error_code, "error_code")
        expected = {
            WorkerOutcome.SUCCEEDED: ("delivered", DeliveryDisposition.SUCCEEDED),
            WorkerOutcome.RETRY_SCHEDULED: ("retry", DeliveryDisposition.RETRYABLE_FAILURE),
        }
        if outcome in expected and (self.outbox_state, disposition) != expected[outcome]:
            raise IntegrationDeliveryWorkerError("receipt outcome does not match outbox state")
        if outcome is WorkerOutcome.DEAD_LETTER and (
            self.outbox_state != "dead_letter" or disposition is DeliveryDisposition.SUCCEEDED
        ):
            raise IntegrationDeliveryWorkerError("dead-letter evidence is inconsistent")
        if outcome is WorkerOutcome.SUCCEEDED and self.error_code is not None:
            raise IntegrationDeliveryWorkerError("successful receipt cannot contain an error")
        if outcome is not WorkerOutcome.SUCCEEDED and self.error_code is None:
            raise IntegrationDeliveryWorkerError("failed receipt requires an error code")
        if (
            self.delivery_semantic != DELIVERY_SEMANTIC
            or self.exactly_once_claimed is not False
            or any(
                effect != "none"
                for effect in (
                    self.authorization_effect,
                    self.deployment_effect,
                    self.qualification_effect,
                )
            )
        ):
            raise IntegrationDeliveryWorkerError("worker receipt makes a prohibited claim")
        receipt_id, digest = _identity("IDW", self.KIND, self.body())
        if self.receipt_id and self.receipt_id != receipt_id:
            raise IntegrationDeliveryWorkerError("receipt_id does not match content")
        if self.receipt_sha256 and self.receipt_sha256 != digest:
            raise IntegrationDeliveryWorkerError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", receipt_id)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "acknowledgement_id": self.acknowledgement_id,
            "acknowledgement_public_key_sha256": self.acknowledgement_public_key_sha256,
            "acknowledgement_sha256": self.acknowledgement_sha256,
            "acknowledgement_signer_key_id": self.acknowledgement_signer_key_id,
            "attempt_number": self.attempt_number,
            "authorization_effect": self.authorization_effect,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "completed_at": self.completed_at,
            "delivery_semantic": self.delivery_semantic,
            "deployment_effect": self.deployment_effect,
            "destination_id": self.destination_id,
            "destination_sha256": self.destination_sha256,
            "disposition": self.disposition.value,
            "error_code": self.error_code,
            "exactly_once_claimed": self.exactly_once_claimed,
            "fencing_token": self.fencing_token,
            "idempotency_key": self.idempotency_key,
            "lease_expires_at": self.lease_expires_at,
            "max_attempts": self.max_attempts,
            "next_attempt_at": self.next_attempt_at,
            "outbox_id": self.outbox_id,
            "outbox_state": self.outbox_state,
            "outcome": self.outcome.value,
            "qualification_effect": self.qualification_effect,
            "remote_receipt_ref": self.remote_receipt_ref,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "retry_after_seconds": self.retry_after_seconds,
            "route_kind": self.route_kind.value,
            "sequence_number": self.sequence_number,
            "tenant_ref": self.tenant_ref,
            "transport_observation_id": self.transport_observation_id,
            "transport_observation_sha256": self.transport_observation_sha256,
            "worker_id": self.worker_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
            **self.body(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> WorkerAttemptReceipt:
        fields = set(cls.__dataclass_fields__) - {"KIND"}  # type: ignore[attr-defined]
        fields.add("schema_version")
        fields.add("kind")
        _exact(raw, fields, cls.KIND)
        if raw["schema_version"] != SCHEMA_VERSION or raw["kind"] != cls.KIND:
            raise IntegrationDeliveryWorkerError("worker receipt metadata is invalid")
        values = {name: raw[name] for name in cls.__dataclass_fields__ if name != "KIND"}  # type: ignore[attr-defined]
        candidate = cls(**values)
        if candidate.to_dict() != dict(raw):
            raise IntegrationDeliveryWorkerError("worker receipt identity is invalid")
        return candidate


_WEBHOOK_EVENT_BY_OUTBOX_EVENT = {
    "assessment.changed": WebhookEventType.STATUS_CHANGED,
    "asset.changed": WebhookEventType.STATUS_CHANGED,
    "finding.changed": WebhookEventType.FINDING_CHANGED,
    "report.changed": WebhookEventType.REPORT_AVAILABLE,
    "retest.changed": WebhookEventType.STATUS_CHANGED,
    "stop_state.changed": WebhookEventType.EMERGENCY_STOP_RECORDED,
}

_DESTINATION_KIND_BY_CONNECTOR_KIND = {
    ConnectorKind.JIRA_CLOUD: DestinationKind.JIRA_TICKET,
    ConnectorKind.MICROSOFT_SENTINEL: DestinationKind.SIEM,
    ConnectorKind.SECURITY_COPILOT: DestinationKind.COLLABORATION,
}


def _projection(lease: DeliveryLease, *, webhook: bool) -> IntegrationProjection:
    event = lease.event.signed.event
    subject_name, subject_value = event.subject_ids[0]
    event_type = (
        _WEBHOOK_EVENT_BY_OUTBOX_EVENT[event.event_type.value].value
        if webhook
        else event.event_type.value
    )
    references = tuple(
        sorted(
            {
                *(item.reference_id for item in event.digest_references),
                *(item.reference_id for item in event.link_references),
            }
        )
    )
    return IntegrationProjection(
        event_id=f"integrationevent:{event.event_id}",
        event_sha256=event.event_sha256,
        event_type=event_type,
        subject_ref=f"{subject_name}ref:{subject_value}",
        state=event.state,
        severity=event.severity.value,
        summary=event.summary,
        artifact_refs=references,
        occurred_at=event.occurred_at,
    )


def _disposition(response: ConnectorTransportResponse) -> DeliveryDisposition:
    if 200 <= response.status_code <= 299:
        return DeliveryDisposition.SUCCEEDED
    if response.status_code in {408, 425, 429} or 500 <= response.status_code <= 599:
        return DeliveryDisposition.RETRYABLE_FAILURE
    return DeliveryDisposition.PERMANENT_FAILURE


def _normalize_connector_observation(
    observation: ConnectorDeliveryObservation,
) -> TransportObservation:
    return TransportObservation(
        request_id=observation.request_id,
        request_sha256=observation.request_sha256,
        disposition=observation.disposition,
        status_code=observation.status_code,
        response_sha256=observation.response_sha256,
        external_resource_ref=observation.external_resource_ref,
        retry_after_seconds=observation.retry_after_seconds,
        observed_at=observation.observed_at,
        source_observation_id=observation.observation_id,
        source_observation_sha256=observation.observation_sha256,
    )


class IntegrationDeliveryWorker:
    """Execute bounded, fenced delivery attempts with no built-in transport."""

    def __init__(
        self,
        *,
        outbox: IntegrationOutbox,
        worker_id: str,
        tenant_ref: str,
        routes: tuple[WorkerRoute, ...],
        event_public_keys: Mapping[str, Ed25519PublicKey],
        transport: IntegrationWorkerTransport,
        policy: WorkerPolicy | None = None,
    ) -> None:
        if not isinstance(outbox, IntegrationOutbox):
            raise IntegrationDeliveryWorkerError("outbox is invalid")
        self.outbox = outbox
        self.worker_id = _identifier(worker_id, "worker_id")
        self.tenant_ref = _reference(tenant_ref, "tenant_ref")
        self.policy = policy or WorkerPolicy()
        if not routes:
            raise IntegrationDeliveryWorkerError("worker requires at least one route")
        if len({route.destination_id for route in routes}) != len(routes):
            raise IntegrationDeliveryWorkerError("worker routes contain duplicate destinations")
        if any(route.tenant_ref != self.tenant_ref for route in routes):
            raise IntegrationDeliveryWorkerError("worker routes cross tenant boundaries")
        for route in routes:
            if (
                route.route_kind is RouteKind.WEBHOOK
                and route.webhook_subscription is not None
                and self.policy.claim_limit > route.webhook_subscription.max_in_flight
            ):
                raise IntegrationDeliveryWorkerError("claim limit exceeds webhook in-flight budget")
        self.routes = {route.destination_id: route for route in routes}
        keys = dict(event_public_keys)
        if not keys:
            raise IntegrationDeliveryWorkerError("worker requires event verification keys")
        for signer_id, key in keys.items():
            _identifier(signer_id, "event signer key id")
            if not isinstance(key, Ed25519PublicKey):
                raise IntegrationDeliveryWorkerError("event public key is invalid")
        self.event_public_keys = keys
        if not callable(getattr(transport, "send", None)):
            raise IntegrationDeliveryWorkerError("transport connector sender is missing")
        if not callable(getattr(transport, "send_webhook", None)):
            raise IntegrationDeliveryWorkerError("transport webhook sender is missing")
        if not callable(getattr(transport, "acknowledge", None)):
            raise IntegrationDeliveryWorkerError("transport acknowledgement method is missing")
        self.transport = transport

    def _event_key(self, signer_key_id: str) -> Ed25519PublicKey:
        try:
            return self.event_public_keys[signer_key_id]
        except KeyError as exc:
            raise IntegrationDeliveryWorkerError("event signer key is not configured") from exc

    def run_once(self, *, observed_at: str) -> tuple[WorkerAttemptReceipt, ...]:
        """Claim a deterministic due batch and complete each acknowledged attempt."""

        _time(observed_at, "observed_at")
        now = _instant(observed_at)
        self._validate_routes_are_active(now)
        leases = self.outbox.claim(
            worker_id=self.worker_id,
            event_public_key_resolver=self._event_key,
            lease_seconds=self.policy.lease_seconds,
            limit=self.policy.claim_limit,
        )
        return tuple(self._deliver(lease, observed_at=observed_at) for lease in leases)

    def _validate_routes_are_active(self, now: datetime) -> None:
        for route in self.routes.values():
            if route.route_kind is RouteKind.ENTERPRISE_CONNECTOR:
                binding = route.connector_binding
                if binding is None:
                    raise IntegrationDeliveryWorkerError("connector binding is missing")
                if not (_instant(binding.enabled_at) <= now < _instant(binding.expires_at)):
                    raise IntegrationDeliveryWorkerError("connector binding is not active")
            else:
                subscription = route.webhook_subscription
                if subscription is None or now < _instant(subscription.created_at):
                    raise IntegrationDeliveryWorkerError("webhook subscription is not active")

    def _deliver(self, lease: DeliveryLease, *, observed_at: str) -> WorkerAttemptReceipt:
        try:
            route = self.routes[lease.destination.destination_id]
        except KeyError as exc:
            raise IntegrationDeliveryWorkerError("claimed destination has no worker route") from exc
        if route.destination_sha256 != lease.destination.destination_sha256:
            raise IntegrationDeliveryWorkerError("claimed destination digest is rebound")
        if route.route_kind is RouteKind.WEBHOOK:
            if lease.destination.kind is not DestinationKind.GENERIC_WEBHOOK:
                raise IntegrationDeliveryWorkerError(
                    "webhook route kind does not match destination"
                )
        else:
            binding = route.connector_binding
            if (
                binding is None
                or lease.destination.kind
                is not _DESTINATION_KIND_BY_CONNECTOR_KIND[binding.connector_kind]
            ):
                raise IntegrationDeliveryWorkerError(
                    "connector route kind does not match destination"
                )
        if _instant(observed_at) < _instant(lease.event.signed.event.occurred_at):
            raise IntegrationDeliveryWorkerError("delivery observation predates event occurrence")
        if _instant(observed_at) >= _instant(lease.lease_expires_at):
            raise IntegrationDeliveryWorkerError("delivery lease expired before dispatch")
        request, transport_observation = self._dispatch(route, lease, observed_at)
        signed = self.transport.acknowledge(
            event=lease.event,
            destination=lease.destination_reference,
            idempotency_key=lease.record.idempotency_key,
            attempt_number=lease.attempt_number,
            transport_observation=transport_observation,
        )
        if not isinstance(signed, SignedDeliveryObservation):
            raise IntegrationDeliveryWorkerError("transport returned an invalid acknowledgement")
        if signed.signer_key_id != route.acknowledgement_signer_key_id:
            raise IntegrationDeliveryWorkerError("acknowledgement signer identity is rebound")
        try:
            verified = verify_delivery_observation(
                signed,
                route.acknowledgement_public_key,
                expected_event=lease.event,
                expected_destination=lease.destination_reference,
                expected_idempotency_key=lease.record.idempotency_key,
                expected_attempt_number=lease.attempt_number,
            )
        except IntegrationOutboxError as exc:
            raise IntegrationDeliveryWorkerError(
                "acknowledgement signature or delivery binding is invalid"
            ) from exc
        self._validate_acknowledgement(route, verified.signed, transport_observation, observed_at)
        updated = self.outbox.complete(lease, verified)
        if updated.state == "delivered":
            outcome = WorkerOutcome.SUCCEEDED
        elif updated.state == "retry":
            outcome = WorkerOutcome.RETRY_SCHEDULED
        elif updated.state == "dead_letter":
            outcome = WorkerOutcome.DEAD_LETTER
        else:
            raise IntegrationDeliveryWorkerError(
                "outbox returned an invalid terminal attempt state"
            )
        observation = verified.signed.observation
        binding = route.connector_binding
        return WorkerAttemptReceipt(
            worker_id=self.worker_id,
            tenant_ref=self.tenant_ref,
            route_kind=route.route_kind,
            outbox_id=updated.outbox_id,
            sequence_number=updated.sequence_number,
            fencing_token=updated.fencing_token,
            attempt_number=updated.attempt_count,
            max_attempts=updated.max_attempts,
            lease_expires_at=lease.lease_expires_at,
            destination_id=updated.destination_id,
            destination_sha256=updated.destination_sha256,
            binding_id=None if binding is None else binding.binding_id,
            binding_sha256=None if binding is None else binding.binding_sha256,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            idempotency_key=updated.idempotency_key,
            transport_observation_id=transport_observation.observation_id,
            transport_observation_sha256=transport_observation.observation_sha256,
            response_sha256=transport_observation.response_sha256,
            acknowledgement_id=observation.observation_id,
            acknowledgement_sha256=observation.observation_sha256,
            acknowledgement_signer_key_id=verified.signed.signer_key_id,
            acknowledgement_public_key_sha256=verified.signed.public_key_sha256,
            disposition=transport_observation.disposition,
            outcome=outcome,
            outbox_state=updated.state,
            next_attempt_at=updated.next_attempt_at,
            completed_at=observed_at,
            retry_after_seconds=transport_observation.retry_after_seconds,
            remote_receipt_ref=observation.remote_receipt_ref,
            error_code=observation.error_code,
        )

    def _dispatch(
        self,
        route: WorkerRoute,
        lease: DeliveryLease,
        observed_at: str,
    ) -> tuple[ConnectorDeliveryRequest | WebhookDeliveryRequest, TransportObservation]:
        now = _instant(observed_at)
        expires = min(
            _instant(lease.lease_expires_at),
            now + timedelta(seconds=self.policy.request_ttl_seconds),
        )
        if route.route_kind is RouteKind.ENTERPRISE_CONNECTOR:
            binding = route.connector_binding
            if binding is None:
                raise IntegrationDeliveryWorkerError("connector binding is missing")
            expires = min(expires, _instant(binding.expires_at))
            if expires <= now:
                raise IntegrationDeliveryWorkerError("connector request would be expired")
            request = build_connector_delivery_request(
                binding,
                _projection(lease, webhook=False),
                idempotency_key="idem:" + lease.record.idempotency_key[7:],
                created_at=observed_at,
                expires_at=_utc(expires),
            )
            connector_observation = deliver_with_connector(
                binding,
                request,
                self.transport,
                observed_at=observed_at,
            )
            return request, _normalize_connector_observation(connector_observation)
        subscription = route.webhook_subscription
        if subscription is None:
            raise IntegrationDeliveryWorkerError("webhook subscription is missing")
        if expires <= now:
            raise IntegrationDeliveryWorkerError("webhook request would be expired")
        projection = _projection(lease, webhook=True)
        if WebhookEventType(projection.event_type) not in subscription.event_filters:
            raise IntegrationDeliveryWorkerError("webhook subscription rejects the event type")
        request = WebhookDeliveryRequest(
            subscription_id=subscription.subscription_id,
            subscription_sha256=subscription.subscription_sha256,
            tenant_ref=self.tenant_ref,
            destination_id=route.destination_id,
            destination_sha256=route.destination_sha256,
            event=projection,
            idempotency_key=lease.record.idempotency_key,
            sequence_number=lease.record.sequence_number,
            attempt_number=lease.attempt_number,
            body_json=canonical_json(projection.to_dict()),
            created_at=observed_at,
            expires_at=_utc(expires),
        )
        response = self.transport.send_webhook(
            endpoint_ref=subscription.endpoint_ref,
            signing_key_ref=subscription.signing_key_ref,
            request=request,
        )
        if not isinstance(response, ConnectorTransportResponse):
            raise IntegrationDeliveryWorkerError("webhook transport returned an invalid response")
        disposition = _disposition(response)
        if disposition is not DeliveryDisposition.SUCCEEDED and response.external_resource_ref:
            raise IntegrationDeliveryWorkerError("failed webhook cannot claim a remote receipt")
        return request, TransportObservation(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            disposition=disposition,
            status_code=response.status_code,
            response_sha256=response.response_sha256,
            external_resource_ref=response.external_resource_ref,
            retry_after_seconds=response.retry_after_seconds,
            observed_at=observed_at,
        )

    @staticmethod
    def _validate_acknowledgement(
        route: WorkerRoute,
        signed: SignedDeliveryObservation,
        transport_observation: TransportObservation,
        observed_at: str,
    ) -> None:
        observation = signed.observation
        expected_status = ObservationStatus(transport_observation.disposition.value)
        if (
            observation.status is not expected_status
            or observation.observed_at != observed_at
            or observation.adapter_id != route.adapter_id
        ):
            raise IntegrationDeliveryWorkerError("acknowledgement outcome binding is invalid")
        if transport_observation.disposition is DeliveryDisposition.SUCCEEDED:
            if observation.remote_receipt_ref != transport_observation.external_resource_ref:
                raise IntegrationDeliveryWorkerError("acknowledgement remote receipt is rebound")
        elif observation.remote_receipt_ref is not None:
            raise IntegrationDeliveryWorkerError("failed acknowledgement claims a remote receipt")


def parse_contract(raw: Mapping[str, Any] | str) -> WebhookDeliveryRequest | WorkerAttemptReceipt:
    document = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(document, Mapping):
        raise IntegrationDeliveryWorkerError("worker contract must be an object")
    if document.get("kind") == WebhookDeliveryRequest.KIND:
        return WebhookDeliveryRequest.from_dict(document)
    if document.get("kind") == WorkerAttemptReceipt.KIND:
        return WorkerAttemptReceipt.from_dict(document)
    raise IntegrationDeliveryWorkerError("worker contract kind is unsupported")


__all__ = [
    "DELIVERY_SEMANTIC",
    "NO_BUILTIN_NETWORK",
    "IntegrationDeliveryWorker",
    "IntegrationDeliveryWorkerError",
    "IntegrationWorkerTransport",
    "RouteKind",
    "TransportObservation",
    "WebhookDeliveryRequest",
    "WorkerAttemptReceipt",
    "WorkerOutcome",
    "WorkerPolicy",
    "WorkerRoute",
    "canonical_json",
    "canonical_sha256",
    "parse_contract",
]
