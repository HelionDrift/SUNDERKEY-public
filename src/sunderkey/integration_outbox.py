"""Signed integration events and a durable, network-free delivery outbox.

This module defines custody and adapter boundaries. It intentionally contains no
network client and grants no authority to change SUNDERKEY runtime state.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = 1
APPLICATION_ID = 0x53494F42
DATABASE_FILENAME = "integration-outbox.sqlite3"
EVENT_DOMAIN = "sunderkey.integration-event.v1"
EVENT_SIGNATURE_DOMAIN = "sunderkey.integration-event-signature.v1"
OBSERVATION_DOMAIN = "sunderkey.integration-delivery-observation.v1"
OBSERVATION_SIGNATURE_DOMAIN = "sunderkey.integration-delivery-observation-signature.v1"

_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_REFERENCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~:/-]{0,255}\Z")
_SUBJECT_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,62}_id\Z")
_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SECRET_TEXT_PATTERN = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie|set-cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
_EXPLOIT_TEXT_PATTERN = re.compile(
    r"(?:<script\b|\bunion\s+select\b|\b(?:powershell|cmd\.exe)\s+-|"
    r"\bcurl\s+https?://|\bwget\s+https?://|\b(?:reverse|bind)\s+shell\b)",
    re.IGNORECASE,
)
_FORBIDDEN_FIELD_PARTS = {
    "authorization",
    "cookie",
    "credential",
    "evidence",
    "exploit",
    "password",
    "payload",
    "private_key",
    "raw",
    "request_body",
    "response_body",
    "secret",
    "token",
}
_TERMINAL_STATES = {"delivered", "dead_letter", "cancelled"}
_VERIFIED_EVENT_MARKER = object()
_VERIFIED_OBSERVATION_MARKER = object()


class IntegrationOutboxError(ValueError):
    """Base error for invalid integration events or outbox operations."""


class IntegrationValidationError(IntegrationOutboxError):
    """Raised when an event, destination, or observation is invalid."""


class IntegrationConflictError(IntegrationOutboxError):
    """Raised when an operation conflicts with durable outbox state."""


class IntegrationIntegrityError(IntegrationOutboxError):
    """Raised when durable custody or stored content is invalid."""


class EventType(StrEnum):
    """The state change families allowed to cross the integration boundary."""

    ASSET = "asset.changed"
    ASSESSMENT = "assessment.changed"
    FINDING = "finding.changed"
    RETEST = "retest.changed"
    REPORT = "report.changed"
    STOP_STATE = "stop_state.changed"


class Severity(StrEnum):
    """Normalized integration severity."""

    NOT_APPLICABLE = "not_applicable"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DestinationKind(StrEnum):
    """Vendor-neutral destination families."""

    GENERIC_WEBHOOK = "generic_webhook"
    JIRA_TICKET = "jira_ticket"
    SIEM = "siem"
    COLLABORATION = "collaboration"


class ObservationStatus(StrEnum):
    """External adapter outcomes understood by the outbox."""

    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise IntegrationValidationError("Value is not canonical JSON") from exc


def _sha256(value: Any) -> str:
    encoded = _canonical_json(value).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _public_key_sha256(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _signature_payload(domain: str, body: Mapping[str, Any]) -> bytes:
    return _canonical_json({"domain": domain, "body": body}).encode("ascii")


def _encode_signature(signature: bytes) -> str:
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise IntegrationValidationError("Signature encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise IntegrationValidationError("Signature encoding is invalid") from exc
    if len(decoded) != 64:
        raise IntegrationValidationError("Ed25519 signature length is invalid")
    if _encode_signature(decoded) != value:
        raise IntegrationValidationError("Signature encoding is not canonical")
    return decoded


def _require_exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown or missing:
        raise IntegrationValidationError(f"{label} fields are invalid")


def _require_text(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 32 for character in value)
    ):
        raise IntegrationValidationError(f"{label} must be safe non-empty ASCII text")
    return value


def _require_identifier(value: Any, label: str) -> str:
    text = _require_text(value, label, 128)
    if not _IDENTIFIER_PATTERN.fullmatch(text) or "://" in text or ".." in text:
        raise IntegrationValidationError(f"{label} is invalid")
    _reject_secret_text(text, label)
    return text


def _require_reference(value: Any, label: str) -> str:
    text = _require_text(value, label, 256)
    if not _REFERENCE_PATTERN.fullmatch(text) or "://" in text or "@" in text:
        raise IntegrationValidationError(f"{label} must be an opaque reference")
    _reject_secret_text(text, label)
    return text


def _require_digest(value: Any, label: str) -> str:
    text = _require_text(value, label, 71)
    if not _SHA256_PATTERN.fullmatch(text):
        raise IntegrationValidationError(f"{label} must be a SHA-256 reference")
    return text


def _require_code(value: Any, label: str) -> str:
    text = _require_text(value, label, 64)
    if not _CODE_PATTERN.fullmatch(text):
        raise IntegrationValidationError(f"{label} is invalid")
    return text


def _require_timestamp(value: Any, label: str) -> str:
    text = _require_text(value, label, 40)
    if not text.endswith("Z"):
        raise IntegrationValidationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise IntegrationValidationError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != text:
        raise IntegrationValidationError(f"{label} must be canonical UTC")
    return text


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise IntegrationValidationError("Clock must return an aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_observation_causality(occurred_at: str, observed_at: str) -> None:
    event_time = datetime.fromisoformat(_require_timestamp(occurred_at, "occurred_at"))
    observation_time = datetime.fromisoformat(_require_timestamp(observed_at, "observed_at"))
    if observation_time < event_time:
        raise IntegrationValidationError("Delivery observation predates event occurrence")


def _reject_secret_text(value: str, label: str) -> None:
    if _SECRET_TEXT_PATTERN.search(value):
        raise IntegrationValidationError(f"{label} contains secret-like material")


def _validate_summary(value: Any) -> str:
    summary = _require_text(value, "summary", 500)
    _reject_secret_text(summary, "summary")
    if _EXPLOIT_TEXT_PATTERN.search(summary):
        raise IntegrationValidationError("summary contains exploit payload material")
    return summary


def _reject_forbidden_fields(value: Any, label: str = "document") -> None:
    if isinstance(value, Mapping):
        for key, member in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_FIELD_PARTS):
                raise IntegrationValidationError(f"{label} contains a forbidden field")
            _reject_forbidden_fields(member, label)
    elif isinstance(value, (list, tuple)):
        for member in value:
            _reject_forbidden_fields(member, label)
    elif isinstance(value, str):
        _reject_secret_text(value, label)


def _none_effects(value: Mapping[str, Any], label: str) -> None:
    for name in (
        "authorization_effect",
        "execution_authority_effect",
        "target_authority_effect",
        "assessment_state_effect",
        "finding_state_effect",
    ):
        if value.get(name) != "none":
            raise IntegrationValidationError(f"{label} cannot grant authority or effects")


@dataclass(frozen=True, slots=True)
class DigestReference:
    """A digest and non-sensitive identifier, never evidence bytes."""

    reference_id: str
    sha256: str
    media_type: str = "application/json"

    def __post_init__(self) -> None:
        _require_reference(self.reference_id, "digest reference id")
        _require_digest(self.sha256, "digest reference sha256")
        media_type = _require_text(self.media_type, "digest media type", 96)
        if not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", media_type):
            raise IntegrationValidationError("digest media type is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "media_type": self.media_type,
            "reference_id": self.reference_id,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DigestReference:
        _require_exact_fields(raw, {"reference_id", "sha256", "media_type"}, "digest reference")
        return cls(str(raw["reference_id"]), str(raw["sha256"]), str(raw["media_type"]))


@dataclass(frozen=True, slots=True)
class OpaqueLinkReference:
    """A relationship to a separately resolved resource, never a URL."""

    relation: str
    reference_id: str

    def __post_init__(self) -> None:
        _require_code(self.relation, "link relation")
        _require_reference(self.reference_id, "link reference")

    def to_dict(self) -> dict[str, str]:
        return {"reference_id": self.reference_id, "relation": self.relation}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> OpaqueLinkReference:
        _require_exact_fields(raw, {"relation", "reference_id"}, "link reference")
        return cls(str(raw["relation"]), str(raw["reference_id"]))


_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "event_sha256",
    "event_type",
    "occurred_at",
    "producer_id",
    "aggregate_id",
    "subject_ids",
    "previous_state",
    "state",
    "severity",
    "digest_references",
    "summary",
    "link_references",
    "partition_key",
    "ordering_key",
    "idempotency_key",
    "authorization_effect",
    "execution_authority_effect",
    "target_authority_effect",
    "assessment_state_effect",
    "finding_state_effect",
}


@dataclass(frozen=True, slots=True)
class IntegrationEvent:
    """Immutable, content-addressed projection of one state change."""

    event_id: str
    event_sha256: str
    event_type: EventType
    occurred_at: str
    producer_id: str
    aggregate_id: str
    subject_ids: tuple[tuple[str, str], ...]
    previous_state: str | None
    state: str
    severity: Severity
    digest_references: tuple[DigestReference, ...]
    summary: str
    link_references: tuple[OpaqueLinkReference, ...]
    partition_key: str
    ordering_key: str
    idempotency_key: str
    schema_version: int = SCHEMA_VERSION
    authorization_effect: str = "none"
    execution_authority_effect: str = "none"
    target_authority_effect: str = "none"
    assessment_state_effect: str = "none"
    finding_state_effect: str = "none"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise IntegrationValidationError("Integration event schema version is invalid")
        if not isinstance(self.event_type, EventType) or not isinstance(self.severity, Severity):
            raise IntegrationValidationError("Event type or severity is invalid")
        _require_text(self.event_id, "event id", 36)
        _require_digest(self.event_sha256, "event sha256")
        _require_timestamp(self.occurred_at, "occurred_at")
        _require_identifier(self.producer_id, "producer id")
        _require_identifier(self.aggregate_id, "aggregate id")
        if not isinstance(self.subject_ids, tuple) or not self.subject_ids:
            raise IntegrationValidationError("subject_ids must be a non-empty tuple")
        if tuple(sorted(self.subject_ids)) != self.subject_ids:
            raise IntegrationValidationError("subject_ids must have deterministic order")
        for key, value in self.subject_ids:
            if not _SUBJECT_KEY_PATTERN.fullmatch(key):
                raise IntegrationValidationError("subject id name is invalid")
            _require_identifier(value, f"subject_ids.{key}")
        if len(dict(self.subject_ids)) != len(self.subject_ids):
            raise IntegrationValidationError("subject_ids contain duplicates")
        if self.previous_state is not None:
            _require_code(self.previous_state, "previous state")
        _require_code(self.state, "state")
        if not isinstance(self.digest_references, tuple) or not all(
            isinstance(item, DigestReference) for item in self.digest_references
        ):
            raise IntegrationValidationError("digest references are invalid")
        if len({item.reference_id for item in self.digest_references}) != len(
            self.digest_references
        ):
            raise IntegrationValidationError("digest references must be unique")
        _validate_summary(self.summary)
        if not isinstance(self.link_references, tuple) or not all(
            isinstance(item, OpaqueLinkReference) for item in self.link_references
        ):
            raise IntegrationValidationError("link references are invalid")
        if len({(item.relation, item.reference_id) for item in self.link_references}) != len(
            self.link_references
        ):
            raise IntegrationValidationError("link references must be unique")
        for value in (self.partition_key, self.ordering_key, self.idempotency_key):
            _require_digest(value, "event deterministic key")
        _none_effects(self.to_dict(), "integration event")

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_id": self.aggregate_id,
            "assessment_state_effect": self.assessment_state_effect,
            "authorization_effect": self.authorization_effect,
            "digest_references": [item.to_dict() for item in self.digest_references],
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "event_type": self.event_type.value,
            "execution_authority_effect": self.execution_authority_effect,
            "finding_state_effect": self.finding_state_effect,
            "idempotency_key": self.idempotency_key,
            "link_references": [item.to_dict() for item in self.link_references],
            "occurred_at": self.occurred_at,
            "ordering_key": self.ordering_key,
            "partition_key": self.partition_key,
            "previous_state": self.previous_state,
            "producer_id": self.producer_id,
            "schema_version": self.schema_version,
            "severity": self.severity.value,
            "state": self.state,
            "subject_ids": dict(self.subject_ids),
            "summary": self.summary,
            "target_authority_effect": self.target_authority_effect,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> IntegrationEvent:
        _require_exact_fields(raw, _EVENT_FIELDS, "integration event")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise IntegrationValidationError("Integration event schema version is invalid")
        subjects_raw = raw.get("subject_ids")
        if not isinstance(subjects_raw, Mapping) or not subjects_raw:
            raise IntegrationValidationError("subject_ids must be a non-empty object")
        subjects: list[tuple[str, str]] = []
        for key, value in sorted(subjects_raw.items()):
            if not isinstance(key, str) or not _SUBJECT_KEY_PATTERN.fullmatch(key):
                raise IntegrationValidationError("subject id name is invalid")
            subjects.append((key, _require_identifier(value, f"subject_ids.{key}")))
        digests_raw = raw.get("digest_references")
        links_raw = raw.get("link_references")
        if not isinstance(digests_raw, list) or not isinstance(links_raw, list):
            raise IntegrationValidationError("Integration references must be arrays")
        previous = raw.get("previous_state")
        if previous is not None:
            previous = _require_code(previous, "previous state")
        try:
            event_type = EventType(raw.get("event_type"))
            severity = Severity(raw.get("severity"))
        except ValueError as exc:
            raise IntegrationValidationError("Event type or severity is invalid") from exc
        event = cls(
            event_id=_require_text(raw.get("event_id"), "event id", 36),
            event_sha256=_require_digest(raw.get("event_sha256"), "event sha256"),
            event_type=event_type,
            occurred_at=_require_timestamp(raw.get("occurred_at"), "occurred_at"),
            producer_id=_require_identifier(raw.get("producer_id"), "producer id"),
            aggregate_id=_require_identifier(raw.get("aggregate_id"), "aggregate id"),
            subject_ids=tuple(subjects),
            previous_state=previous,
            state=_require_code(raw.get("state"), "state"),
            severity=severity,
            digest_references=tuple(DigestReference.from_dict(item) for item in digests_raw),
            summary=_validate_summary(raw.get("summary")),
            link_references=tuple(OpaqueLinkReference.from_dict(item) for item in links_raw),
            partition_key=_require_text(raw.get("partition_key"), "partition key", 71),
            ordering_key=_require_text(raw.get("ordering_key"), "ordering key", 71),
            idempotency_key=_require_text(raw.get("idempotency_key"), "idempotency key", 71),
            authorization_effect=str(raw.get("authorization_effect")),
            execution_authority_effect=str(raw.get("execution_authority_effect")),
            target_authority_effect=str(raw.get("target_authority_effect")),
            assessment_state_effect=str(raw.get("assessment_state_effect")),
            finding_state_effect=str(raw.get("finding_state_effect")),
        )
        _none_effects(raw, "integration event")
        _verify_event_content(event)
        return event


def _event_body(event: IntegrationEvent) -> dict[str, Any]:
    body = event.to_dict()
    for field_name in ("event_id", "event_sha256", "idempotency_key"):
        body.pop(field_name)
    return body


def _verify_event_content(event: IntegrationEvent) -> None:
    raw = event.to_dict()
    _none_effects(raw, "integration event")
    _reject_forbidden_fields(
        {
            "summary_text": raw["summary"],
            "subject_ids": raw["subject_ids"],
            "links": raw["link_references"],
        },
        "integration event",
    )
    expected = _sha256({"domain": EVENT_DOMAIN, "event": _event_body(event)})
    expected_id = "IOE-" + expected.removeprefix("sha256:")[:32].upper()
    expected_key = (
        "sha256:"
        + hashlib.sha256(("integration-idempotency-v1\0" + expected).encode("ascii")).hexdigest()
    )
    if event.event_sha256 != expected or event.event_id != expected_id:
        raise IntegrationValidationError("Integration event content address is invalid")
    if event.idempotency_key != expected_key:
        raise IntegrationValidationError("Integration event idempotency key is invalid")
    for key in (event.partition_key, event.ordering_key):
        _require_digest(key, "event order key")


def create_integration_event(
    *,
    event_type: EventType | str,
    occurred_at: str,
    producer_id: str,
    aggregate_id: str,
    subject_ids: Mapping[str, str],
    previous_state: str | None,
    state: str,
    severity: Severity | str,
    digest_references: Iterable[DigestReference],
    summary: str,
    link_references: Iterable[OpaqueLinkReference] = (),
) -> IntegrationEvent:
    """Create deterministic identity, partition, order, and idempotency keys."""

    try:
        parsed_type = EventType(event_type)
        parsed_severity = Severity(severity)
    except ValueError as exc:
        raise IntegrationValidationError("Event type or severity is invalid") from exc
    occurred_at = _require_timestamp(occurred_at, "occurred_at")
    producer_id = _require_identifier(producer_id, "producer id")
    aggregate_id = _require_identifier(aggregate_id, "aggregate id")
    if not subject_ids:
        raise IntegrationValidationError("subject_ids must not be empty")
    subjects = tuple(sorted((str(key), str(value)) for key, value in subject_ids.items()))
    digests = tuple(digest_references)
    links = tuple(link_references)
    if len({item.reference_id for item in digests}) != len(digests):
        raise IntegrationValidationError("digest references must be unique")
    if len({(item.relation, item.reference_id) for item in links}) != len(links):
        raise IntegrationValidationError("link references must be unique")
    partition_key = _sha256(
        {"aggregate_id": aggregate_id, "event_type": parsed_type.value.split(".")[0]}
    )
    order_material = {
        "aggregate_id": aggregate_id,
        "event_type": parsed_type.value,
        "occurred_at": occurred_at,
        "producer_id": producer_id,
        "state": state,
        "subject_ids": dict(subjects),
    }
    ordering_key = _sha256(order_material)
    provisional = IntegrationEvent(
        event_id="IOE-" + "0" * 32,
        event_sha256="sha256:" + "0" * 64,
        event_type=parsed_type,
        occurred_at=occurred_at,
        producer_id=producer_id,
        aggregate_id=aggregate_id,
        subject_ids=subjects,
        previous_state=previous_state,
        state=state,
        severity=parsed_severity,
        digest_references=digests,
        summary=summary,
        link_references=links,
        partition_key=partition_key,
        ordering_key=ordering_key,
        idempotency_key="sha256:" + "0" * 64,
    )
    raw = provisional.to_dict()
    raw.pop("event_id")
    raw.pop("event_sha256")
    raw.pop("idempotency_key")
    digest = _sha256({"domain": EVENT_DOMAIN, "event": raw})
    idempotency_key = (
        "sha256:"
        + hashlib.sha256(("integration-idempotency-v1\0" + digest).encode("ascii")).hexdigest()
    )
    raw.update(
        {
            "event_id": "IOE-" + digest.removeprefix("sha256:")[:32].upper(),
            "event_sha256": digest,
            "idempotency_key": idempotency_key,
        }
    )
    return IntegrationEvent.from_dict(raw)


@dataclass(frozen=True, slots=True)
class SignedIntegrationEvent:
    """An event signature whose public key is resolved out of band."""

    event: IntegrationEvent
    signer_key_id: str
    public_key_sha256: str
    signature: str
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        _require_identifier(self.signer_key_id, "event signer key id")
        _require_digest(self.public_key_sha256, "event public key sha256")
        _decode_signature(self.signature)
        if self.algorithm != "Ed25519":
            raise IntegrationValidationError("Only Ed25519 event signatures are allowed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "event": self.event.to_dict(),
            "public_key_sha256": self.public_key_sha256,
            "signature": self.signature,
            "signer_key_id": self.signer_key_id,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SignedIntegrationEvent:
        _require_exact_fields(
            raw,
            {"algorithm", "event", "public_key_sha256", "signature", "signer_key_id"},
            "signed integration event",
        )
        event_raw = raw.get("event")
        if not isinstance(event_raw, Mapping):
            raise IntegrationValidationError("Signed integration event body is invalid")
        return cls(
            event=IntegrationEvent.from_dict(event_raw),
            signer_key_id=str(raw.get("signer_key_id")),
            public_key_sha256=str(raw.get("public_key_sha256")),
            signature=str(raw.get("signature")),
            algorithm=str(raw.get("algorithm")),
        )


@dataclass(frozen=True, slots=True)
class VerifiedIntegrationEvent:
    """Capability wrapper issued only after content and signature verification."""

    signed: SignedIntegrationEvent
    _marker: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._marker is not _VERIFIED_EVENT_MARKER:
            raise IntegrationValidationError("Verified event wrappers cannot be forged")


def sign_integration_event(
    event: IntegrationEvent,
    *,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedIntegrationEvent:
    """Sign a validated event without embedding the verification key."""

    _verify_event_content(event)
    signer_key_id = _require_identifier(signer_key_id, "event signer key id")
    public_key_sha256 = _public_key_sha256(private_key.public_key())
    body = {
        "event": event.to_dict(),
        "public_key_sha256": public_key_sha256,
        "signer_key_id": signer_key_id,
    }
    signature = private_key.sign(_signature_payload(EVENT_SIGNATURE_DOMAIN, body))
    return SignedIntegrationEvent(
        event,
        signer_key_id,
        public_key_sha256,
        _encode_signature(signature),
    )


def verify_integration_event(
    signed: SignedIntegrationEvent,
    public_key: Ed25519PublicKey,
) -> VerifiedIntegrationEvent:
    """Verify content identity and Ed25519 signature with an out-of-band key."""

    _verify_event_content(signed.event)
    if signed.public_key_sha256 != _public_key_sha256(public_key):
        raise IntegrationValidationError("Event verification key substitution detected")
    body = {
        "event": signed.event.to_dict(),
        "public_key_sha256": signed.public_key_sha256,
        "signer_key_id": signed.signer_key_id,
    }
    try:
        public_key.verify(
            _decode_signature(signed.signature),
            _signature_payload(EVENT_SIGNATURE_DOMAIN, body),
        )
    except InvalidSignature as exc:
        raise IntegrationValidationError("Integration event signature is invalid") from exc
    return VerifiedIntegrationEvent(signed, _VERIFIED_EVENT_MARKER)


_DESTINATION_ROUTES = {
    DestinationKind.GENERIC_WEBHOOK: {"endpoint_ref"},
    DestinationKind.JIRA_TICKET: {"project_ref", "issue_type_ref"},
    DestinationKind.SIEM: {"stream_ref"},
    DestinationKind.COLLABORATION: {"channel_ref"},
}


@dataclass(frozen=True, slots=True)
class DestinationReference:
    """Opaque reference exposed to an external delivery adapter."""

    destination_id: str
    destination_sha256: str
    kind: DestinationKind

    def __post_init__(self) -> None:
        _require_identifier(self.destination_id, "destination id")
        _require_digest(self.destination_sha256, "destination sha256")
        if not isinstance(self.kind, DestinationKind):
            raise IntegrationValidationError("Destination reference kind is invalid")


@dataclass(frozen=True, slots=True)
class DestinationDescriptor:
    """Strict vendor-neutral route metadata containing no endpoint or credential."""

    destination_id: str
    destination_sha256: str
    kind: DestinationKind
    route: tuple[tuple[str, str], ...]
    authorization_effect: str = "none"
    execution_authority_effect: str = "none"
    target_authority_effect: str = "none"
    assessment_state_effect: str = "none"
    finding_state_effect: str = "none"

    @property
    def reference(self) -> DestinationReference:
        return DestinationReference(self.destination_id, self.destination_sha256, self.kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_state_effect": self.assessment_state_effect,
            "authorization_effect": self.authorization_effect,
            "destination_id": self.destination_id,
            "destination_sha256": self.destination_sha256,
            "execution_authority_effect": self.execution_authority_effect,
            "finding_state_effect": self.finding_state_effect,
            "kind": self.kind.value,
            "route": dict(self.route),
            "target_authority_effect": self.target_authority_effect,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DestinationDescriptor:
        expected = {
            "destination_id",
            "destination_sha256",
            "kind",
            "route",
            "authorization_effect",
            "execution_authority_effect",
            "target_authority_effect",
            "assessment_state_effect",
            "finding_state_effect",
        }
        _require_exact_fields(raw, expected, "destination descriptor")
        try:
            kind = DestinationKind(raw.get("kind"))
        except ValueError as exc:
            raise IntegrationValidationError("Destination kind is invalid") from exc
        route_raw = raw.get("route")
        if not isinstance(route_raw, Mapping) or set(route_raw) != _DESTINATION_ROUTES[kind]:
            raise IntegrationValidationError("Destination route fields are invalid")
        route = tuple(
            sorted(
                (str(key), _require_reference(value, f"destination route {key}"))
                for key, value in route_raw.items()
            )
        )
        descriptor = cls(
            destination_id=_require_identifier(raw.get("destination_id"), "destination id"),
            destination_sha256=_require_digest(raw.get("destination_sha256"), "destination sha256"),
            kind=kind,
            route=route,
            authorization_effect=str(raw.get("authorization_effect")),
            execution_authority_effect=str(raw.get("execution_authority_effect")),
            target_authority_effect=str(raw.get("target_authority_effect")),
            assessment_state_effect=str(raw.get("assessment_state_effect")),
            finding_state_effect=str(raw.get("finding_state_effect")),
        )
        _none_effects(raw, "destination descriptor")
        body = descriptor.to_dict()
        body.pop("destination_sha256")
        if descriptor.destination_sha256 != _sha256(body):
            raise IntegrationValidationError("Destination content address is invalid")
        return descriptor


def create_destination(
    *,
    destination_id: str,
    kind: DestinationKind | str,
    route: Mapping[str, str],
) -> DestinationDescriptor:
    """Create a strict descriptor that contains opaque routing references only."""

    try:
        parsed_kind = DestinationKind(kind)
    except ValueError as exc:
        raise IntegrationValidationError("Destination kind is invalid") from exc
    provisional = {
        "assessment_state_effect": "none",
        "authorization_effect": "none",
        "destination_id": destination_id,
        "execution_authority_effect": "none",
        "finding_state_effect": "none",
        "kind": parsed_kind.value,
        "route": dict(route),
        "target_authority_effect": "none",
    }
    return DestinationDescriptor.from_dict(
        {**provisional, "destination_sha256": _sha256(provisional)}
    )


_OBSERVATION_FIELDS = {
    "schema_version",
    "observation_id",
    "observation_sha256",
    "event_id",
    "event_sha256",
    "event_signer_key_id",
    "event_signer_public_key_sha256",
    "destination_id",
    "destination_sha256",
    "idempotency_key",
    "attempt_number",
    "adapter_id",
    "status",
    "observed_at",
    "remote_receipt_ref",
    "error_code",
    "response_body_stored",
    "authorization_effect",
    "execution_authority_effect",
    "target_authority_effect",
    "assessment_state_effect",
    "finding_state_effect",
}


@dataclass(frozen=True, slots=True)
class DeliveryObservation:
    """Content-addressed adapter observation with no response body."""

    observation_id: str
    observation_sha256: str
    event_id: str
    event_sha256: str
    event_signer_key_id: str
    event_signer_public_key_sha256: str
    destination_id: str
    destination_sha256: str
    idempotency_key: str
    attempt_number: int
    adapter_id: str
    status: ObservationStatus
    observed_at: str
    remote_receipt_ref: str | None
    error_code: str | None
    schema_version: int = SCHEMA_VERSION
    response_body_stored: bool = False
    authorization_effect: str = "none"
    execution_authority_effect: str = "none"
    target_authority_effect: str = "none"
    assessment_state_effect: str = "none"
    finding_state_effect: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "assessment_state_effect": self.assessment_state_effect,
            "attempt_number": self.attempt_number,
            "authorization_effect": self.authorization_effect,
            "destination_id": self.destination_id,
            "destination_sha256": self.destination_sha256,
            "error_code": self.error_code,
            "event_id": self.event_id,
            "event_sha256": self.event_sha256,
            "event_signer_key_id": self.event_signer_key_id,
            "event_signer_public_key_sha256": self.event_signer_public_key_sha256,
            "execution_authority_effect": self.execution_authority_effect,
            "finding_state_effect": self.finding_state_effect,
            "idempotency_key": self.idempotency_key,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "observed_at": self.observed_at,
            "remote_receipt_ref": self.remote_receipt_ref,
            "response_body_stored": self.response_body_stored,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "target_authority_effect": self.target_authority_effect,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> DeliveryObservation:
        _require_exact_fields(raw, _OBSERVATION_FIELDS, "delivery observation")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise IntegrationValidationError("Observation schema version is invalid")
        try:
            status = ObservationStatus(raw.get("status"))
        except ValueError as exc:
            raise IntegrationValidationError("Observation status is invalid") from exc
        receipt = raw.get("remote_receipt_ref")
        error_code = raw.get("error_code")
        if receipt is not None:
            receipt = _require_reference(receipt, "remote receipt reference")
        if error_code is not None:
            error_code = _require_code(error_code, "error code")
        attempt = raw.get("attempt_number")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise IntegrationValidationError("Observation attempt number is invalid")
        observation = cls(
            observation_id=_require_text(raw.get("observation_id"), "observation id", 36),
            observation_sha256=_require_digest(raw.get("observation_sha256"), "observation sha256"),
            event_id=_require_text(raw.get("event_id"), "event id", 36),
            event_sha256=_require_digest(raw.get("event_sha256"), "event sha256"),
            event_signer_key_id=_require_identifier(
                raw.get("event_signer_key_id"), "event signer key id"
            ),
            event_signer_public_key_sha256=_require_digest(
                raw.get("event_signer_public_key_sha256"),
                "event signer public key sha256",
            ),
            destination_id=_require_identifier(raw.get("destination_id"), "destination id"),
            destination_sha256=_require_digest(raw.get("destination_sha256"), "destination sha256"),
            idempotency_key=_require_digest(raw.get("idempotency_key"), "idempotency key"),
            attempt_number=attempt,
            adapter_id=_require_identifier(raw.get("adapter_id"), "adapter id"),
            status=status,
            observed_at=_require_timestamp(raw.get("observed_at"), "observed_at"),
            remote_receipt_ref=receipt,
            error_code=error_code,
            response_body_stored=raw.get("response_body_stored") is True,
            authorization_effect=str(raw.get("authorization_effect")),
            execution_authority_effect=str(raw.get("execution_authority_effect")),
            target_authority_effect=str(raw.get("target_authority_effect")),
            assessment_state_effect=str(raw.get("assessment_state_effect")),
            finding_state_effect=str(raw.get("finding_state_effect")),
        )
        _none_effects(raw, "delivery observation")
        if raw.get("response_body_stored") is not False or observation.response_body_stored:
            raise IntegrationValidationError("Delivery observations cannot store response bodies")
        if status is ObservationStatus.SUCCEEDED and error_code is not None:
            raise IntegrationValidationError("Successful observations cannot have an error code")
        if status is not ObservationStatus.SUCCEEDED and error_code is None:
            raise IntegrationValidationError("Failed observations require an error code")
        body = observation.to_dict()
        body.pop("observation_id")
        body.pop("observation_sha256")
        expected = _sha256({"domain": OBSERVATION_DOMAIN, "observation": body})
        expected_id = "IDO-" + expected.removeprefix("sha256:")[:32].upper()
        if observation.observation_sha256 != expected or observation.observation_id != expected_id:
            raise IntegrationValidationError("Observation content address is invalid")
        return observation


def create_delivery_observation(
    *,
    event: VerifiedIntegrationEvent,
    destination: DestinationReference,
    idempotency_key: str,
    attempt_number: int,
    adapter_id: str,
    status: ObservationStatus | str,
    observed_at: str,
    remote_receipt_ref: str | None = None,
    error_code: str | None = None,
) -> DeliveryObservation:
    """Create an observation bound to an exact event, destination, and attempt."""

    if event._marker is not _VERIFIED_EVENT_MARKER:
        raise IntegrationValidationError("Adapter input event is not verified")
    try:
        parsed_status = ObservationStatus(status)
    except ValueError as exc:
        raise IntegrationValidationError("Observation status is invalid") from exc
    signed = event.signed
    _require_observation_causality(signed.event.occurred_at, observed_at)
    body = {
        "adapter_id": adapter_id,
        "assessment_state_effect": "none",
        "attempt_number": attempt_number,
        "authorization_effect": "none",
        "destination_id": destination.destination_id,
        "destination_sha256": destination.destination_sha256,
        "error_code": error_code,
        "event_id": signed.event.event_id,
        "event_sha256": signed.event.event_sha256,
        "event_signer_key_id": signed.signer_key_id,
        "event_signer_public_key_sha256": signed.public_key_sha256,
        "execution_authority_effect": "none",
        "finding_state_effect": "none",
        "idempotency_key": idempotency_key,
        "observed_at": observed_at,
        "remote_receipt_ref": remote_receipt_ref,
        "response_body_stored": False,
        "schema_version": SCHEMA_VERSION,
        "status": parsed_status.value,
        "target_authority_effect": "none",
    }
    digest = _sha256({"domain": OBSERVATION_DOMAIN, "observation": body})
    return DeliveryObservation.from_dict(
        {
            **body,
            "observation_id": "IDO-" + digest.removeprefix("sha256:")[:32].upper(),
            "observation_sha256": digest,
        }
    )


@dataclass(frozen=True, slots=True)
class SignedDeliveryObservation:
    """External adapter signature over one delivery observation."""

    observation: DeliveryObservation
    signer_key_id: str
    public_key_sha256: str
    signature: str
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        _require_identifier(self.signer_key_id, "observation signer key id")
        _require_digest(self.public_key_sha256, "observation public key sha256")
        _decode_signature(self.signature)
        if self.algorithm != "Ed25519":
            raise IntegrationValidationError("Only Ed25519 observation signatures are allowed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "observation": self.observation.to_dict(),
            "public_key_sha256": self.public_key_sha256,
            "signature": self.signature,
            "signer_key_id": self.signer_key_id,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> SignedDeliveryObservation:
        _require_exact_fields(
            raw,
            {"algorithm", "observation", "public_key_sha256", "signature", "signer_key_id"},
            "signed delivery observation",
        )
        observation_raw = raw.get("observation")
        if not isinstance(observation_raw, Mapping):
            raise IntegrationValidationError("Signed observation body is invalid")
        return cls(
            observation=DeliveryObservation.from_dict(observation_raw),
            signer_key_id=str(raw.get("signer_key_id")),
            public_key_sha256=str(raw.get("public_key_sha256")),
            signature=str(raw.get("signature")),
            algorithm=str(raw.get("algorithm")),
        )


@dataclass(frozen=True, slots=True)
class VerifiedDeliveryObservation:
    """Capability wrapper issued after adapter signature and binding verification."""

    signed: SignedDeliveryObservation
    _marker: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._marker is not _VERIFIED_OBSERVATION_MARKER:
            raise IntegrationValidationError("Verified observation wrappers cannot be forged")


def sign_delivery_observation(
    observation: DeliveryObservation,
    *,
    signer_key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedDeliveryObservation:
    """Sign an adapter observation while preventing event self-acknowledgement."""

    DeliveryObservation.from_dict(observation.to_dict())
    signer_key_id = _require_identifier(signer_key_id, "observation signer key id")
    public_key_sha256 = _public_key_sha256(private_key.public_key())
    if (
        signer_key_id == observation.event_signer_key_id
        or public_key_sha256 == observation.event_signer_public_key_sha256
    ):
        raise IntegrationValidationError("Event signers cannot acknowledge their own events")
    body = {
        "observation": observation.to_dict(),
        "public_key_sha256": public_key_sha256,
        "signer_key_id": signer_key_id,
    }
    signature = private_key.sign(_signature_payload(OBSERVATION_SIGNATURE_DOMAIN, body))
    return SignedDeliveryObservation(
        observation, signer_key_id, public_key_sha256, _encode_signature(signature)
    )


def verify_delivery_observation(
    signed: SignedDeliveryObservation,
    public_key: Ed25519PublicKey,
    *,
    expected_event: VerifiedIntegrationEvent,
    expected_destination: DestinationReference,
    expected_idempotency_key: str,
    expected_attempt_number: int,
) -> VerifiedDeliveryObservation:
    """Verify an adapter signature and all receipt bindings out of band."""

    observation = DeliveryObservation.from_dict(signed.observation.to_dict())
    if (
        signed.signer_key_id == expected_event.signed.signer_key_id
        or signed.public_key_sha256 == expected_event.signed.public_key_sha256
    ):
        raise IntegrationValidationError("Event signers cannot acknowledge their own events")
    if signed.public_key_sha256 != _public_key_sha256(public_key):
        raise IntegrationValidationError("Observation verification key substitution detected")
    expected = (
        expected_event.signed.event.event_id,
        expected_event.signed.event.event_sha256,
        expected_event.signed.signer_key_id,
        expected_event.signed.public_key_sha256,
        expected_destination.destination_id,
        expected_destination.destination_sha256,
        expected_idempotency_key,
        expected_attempt_number,
    )
    actual = (
        observation.event_id,
        observation.event_sha256,
        observation.event_signer_key_id,
        observation.event_signer_public_key_sha256,
        observation.destination_id,
        observation.destination_sha256,
        observation.idempotency_key,
        observation.attempt_number,
    )
    if actual != expected:
        raise IntegrationValidationError("Delivery observation binding substitution detected")
    _require_observation_causality(expected_event.signed.event.occurred_at, observation.observed_at)
    body = {
        "observation": observation.to_dict(),
        "public_key_sha256": signed.public_key_sha256,
        "signer_key_id": signed.signer_key_id,
    }
    try:
        public_key.verify(
            _decode_signature(signed.signature),
            _signature_payload(OBSERVATION_SIGNATURE_DOMAIN, body),
        )
    except InvalidSignature as exc:
        raise IntegrationValidationError("Delivery observation signature is invalid") from exc
    return VerifiedDeliveryObservation(signed, _VERIFIED_OBSERVATION_MARKER)


class ExternalDeliveryAdapter(Protocol):
    """Network implementation boundary supplied outside this module."""

    def deliver(
        self,
        event: VerifiedIntegrationEvent,
        destination: DestinationReference,
    ) -> SignedDeliveryObservation: ...


def deliver_with_adapter(
    adapter: ExternalDeliveryAdapter,
    *,
    event: VerifiedIntegrationEvent,
    destination: DestinationReference,
    idempotency_key: str,
    attempt_number: int,
    observation_public_key: Ed25519PublicKey,
) -> VerifiedDeliveryObservation:
    """Invoke an external adapter and verify its signed observation."""

    if event._marker is not _VERIFIED_EVENT_MARKER:
        raise IntegrationValidationError("Connector accepts only verified signed events")
    signed = adapter.deliver(event, destination)
    if not isinstance(signed, SignedDeliveryObservation):
        raise IntegrationValidationError("Adapter did not return a signed delivery observation")
    return verify_delivery_observation(
        signed,
        observation_public_key,
        expected_event=event,
        expected_destination=destination,
        expected_idempotency_key=idempotency_key,
        expected_attempt_number=attempt_number,
    )


class OutboxAccessController(Protocol):
    """Explicit filesystem custody required for the SQLite store."""

    def protect_directory(self, path: Path) -> None: ...

    def verify_directory(self, path: Path) -> None: ...

    def protect_file(self, path: Path) -> None: ...

    def verify_file(self, path: Path) -> None: ...

    def sync_directory(self, path: Path) -> None: ...


class PosixOwnerOnlyOutboxAccess:
    """Owner-only POSIX access control for a dedicated outbox directory."""

    @staticmethod
    def _require_posix() -> None:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise IntegrationIntegrityError("POSIX outbox access control is unavailable")

    def protect_directory(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o700, follow_symlinks=False)

    def verify_directory(self, path: Path) -> None:
        self._verify(path, directory=True)

    def protect_file(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o600, follow_symlinks=False)

    def verify_file(self, path: Path) -> None:
        self._verify(path, directory=False)

    def sync_directory(self, path: Path) -> None:
        self._require_posix()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _verify(self, path: Path, *, directory: bool) -> None:
        self._require_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise IntegrationIntegrityError("Outbox custody cannot use a symbolic link")
        if directory and not stat.S_ISDIR(metadata.st_mode):
            raise IntegrationIntegrityError("Outbox custody directory is invalid")
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise IntegrationIntegrityError("Outbox custody file is invalid")
        expected_mode = 0o700 if directory else 0o600
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise IntegrationIntegrityError("Outbox custody permissions are not owner-only")
        if metadata.st_uid != os.getuid():
            raise IntegrationIntegrityError("Outbox custody ownership is invalid")


def _require_access_controller(value: Any) -> OutboxAccessController:
    for method in (
        "protect_directory",
        "verify_directory",
        "protect_file",
        "verify_file",
        "sync_directory",
    ):
        if not callable(getattr(value, method, None)):
            raise IntegrationIntegrityError("Outbox access controller is incomplete")
    return value


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded exponential retry policy persisted per outbox entry."""

    max_attempts: int = 5
    base_delay_seconds: int = 5
    max_delay_seconds: int = 300

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 100:
            raise IntegrationValidationError("max_attempts must be from 1 through 100")
        if not 1 <= self.base_delay_seconds <= self.max_delay_seconds <= 86_400:
            raise IntegrationValidationError("Retry delay bounds are invalid")

    def delay_for(self, attempt_number: int) -> int:
        return min(self.max_delay_seconds, self.base_delay_seconds * (2 ** (attempt_number - 1)))


@dataclass(frozen=True, slots=True)
class OutboxRecord:
    """Point-in-time state for one event and destination binding."""

    outbox_id: str
    sequence_number: int
    event_id: str
    event_sha256: str
    destination_id: str
    destination_sha256: str
    idempotency_key: str
    partition_key: str
    ordering_key: str
    state: str
    attempt_count: int
    max_attempts: int
    retry_base_delay_seconds: int
    retry_max_delay_seconds: int
    next_attempt_at: str
    fencing_token: int
    lease_owner: str | None
    lease_expires_at: str | None
    cancellation_reason: str | None


@dataclass(frozen=True, slots=True)
class DeliveryLease:
    """Exclusive attempt capability protected by a monotonically increasing fence."""

    record: OutboxRecord
    worker_id: str
    fencing_token: int
    attempt_number: int
    lease_expires_at: str
    event: VerifiedIntegrationEvent
    destination: DestinationDescriptor

    @property
    def destination_reference(self) -> DestinationReference:
        return self.destination.reference


_SCHEMA = """
CREATE TABLE integration_events (
    event_id TEXT PRIMARY KEY,
    event_sha256 TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE,
    signed_event_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE integration_destinations (
    destination_id TEXT PRIMARY KEY,
    destination_sha256 TEXT NOT NULL UNIQUE,
    descriptor_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE integration_outbox (
    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
    outbox_id TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL REFERENCES integration_events(event_id),
    event_sha256 TEXT NOT NULL,
    destination_id TEXT NOT NULL REFERENCES integration_destinations(destination_id),
    destination_sha256 TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    partition_key TEXT NOT NULL,
    ordering_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'pending', 'leased', 'retry', 'delivered', 'dead_letter', 'cancelled'
    )),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK(max_attempts >= 1),
    retry_base_delay_seconds INTEGER NOT NULL CHECK(retry_base_delay_seconds >= 1),
    retry_max_delay_seconds INTEGER NOT NULL CHECK(
        retry_max_delay_seconds >= retry_base_delay_seconds
    ),
    next_attempt_at TEXT NOT NULL,
    fencing_token INTEGER NOT NULL DEFAULT 0 CHECK(fencing_token >= 0),
    lease_owner TEXT,
    lease_expires_at TEXT,
    cancellation_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    delivered_at TEXT,
    dead_lettered_at TEXT,
    UNIQUE(event_id, destination_id)
) STRICT;

CREATE TABLE integration_delivery_receipts (
    receipt_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id TEXT NOT NULL UNIQUE,
    observation_sha256 TEXT NOT NULL UNIQUE,
    outbox_id TEXT NOT NULL REFERENCES integration_outbox(outbox_id),
    event_id TEXT NOT NULL,
    event_sha256 TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    destination_sha256 TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL,
    signed_observation_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE(outbox_id, attempt_number)
) STRICT;

CREATE INDEX integration_outbox_due
ON integration_outbox(state, next_attempt_at, partition_key, sequence_number);

CREATE TRIGGER integration_events_no_update
BEFORE UPDATE ON integration_events BEGIN
    SELECT RAISE(ABORT, 'integration event custody is immutable');
END;
CREATE TRIGGER integration_events_no_delete
BEFORE DELETE ON integration_events BEGIN
    SELECT RAISE(ABORT, 'integration event custody is append-only');
END;
CREATE TRIGGER integration_destinations_no_update
BEFORE UPDATE ON integration_destinations BEGIN
    SELECT RAISE(ABORT, 'integration destination custody is immutable');
END;
CREATE TRIGGER integration_destinations_no_delete
BEFORE DELETE ON integration_destinations BEGIN
    SELECT RAISE(ABORT, 'integration destination custody is append-only');
END;
CREATE TRIGGER integration_receipts_no_update
BEFORE UPDATE ON integration_delivery_receipts BEGIN
    SELECT RAISE(ABORT, 'integration receipt custody is immutable');
END;
CREATE TRIGGER integration_receipts_no_delete
BEFORE DELETE ON integration_delivery_receipts BEGIN
    SELECT RAISE(ABORT, 'integration receipt custody is append-only');
END;
CREATE TRIGGER integration_outbox_no_delete
BEFORE DELETE ON integration_outbox BEGIN
    SELECT RAISE(ABORT, 'integration outbox custody is append-only');
END;
CREATE TRIGGER integration_outbox_binding_immutable
BEFORE UPDATE ON integration_outbox
WHEN NEW.outbox_id != OLD.outbox_id
  OR NEW.sequence_number != OLD.sequence_number
  OR NEW.event_id != OLD.event_id
  OR NEW.event_sha256 != OLD.event_sha256
  OR NEW.destination_id != OLD.destination_id
  OR NEW.destination_sha256 != OLD.destination_sha256
  OR NEW.idempotency_key != OLD.idempotency_key
  OR NEW.partition_key != OLD.partition_key
  OR NEW.ordering_key != OLD.ordering_key
  OR NEW.max_attempts != OLD.max_attempts
  OR NEW.retry_base_delay_seconds != OLD.retry_base_delay_seconds
  OR NEW.retry_max_delay_seconds != OLD.retry_max_delay_seconds
  OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'integration outbox binding is immutable');
END;
"""


class IntegrationOutbox:
    """SQLite outbox with append-only custody and fenced at-least-once delivery."""

    def __init__(
        self,
        directory: str | Path,
        access_controller: OutboxAccessController,
        *,
        clock: Callable[[], datetime] | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.directory = Path(directory).resolve()
        self.path = self.directory / DATABASE_FILENAME
        self.access = _require_access_controller(access_controller)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.retry_policy = retry_policy or RetryPolicy()

    def initialize(self) -> None:
        """Create or verify a durable store and its explicit filesystem custody."""

        if self.directory.exists() and self.directory.is_symlink():
            raise IntegrationIntegrityError("Outbox directory cannot be a symbolic link")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.access.protect_directory(self.directory)
        self.access.verify_directory(self.directory)
        existed = self.path.exists()
        if existed and self.path.is_symlink():
            raise IntegrationIntegrityError("Outbox database cannot be a symbolic link")
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            if not existed:
                connection.execute("PRAGMA journal_mode = DELETE")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.executescript(_SCHEMA)
                    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            self._verify_database(connection)
        self.access.protect_file(self.path)
        self.access.verify_file(self.path)
        self.access.sync_directory(self.directory)

    def enqueue(
        self,
        event: VerifiedIntegrationEvent,
        destination: DestinationDescriptor,
    ) -> OutboxRecord:
        """Atomically append event custody and its destination work item."""

        return self.enqueue_many(((event, destination),))[0]

    def enqueue_many(
        self,
        entries: Iterable[tuple[VerifiedIntegrationEvent, DestinationDescriptor]],
    ) -> tuple[OutboxRecord, ...]:
        """Atomically enqueue a batch, with no partial custody on conflict."""

        values = tuple(entries)
        if not values:
            raise IntegrationValidationError("Enqueue batch must not be empty")
        now = _utc_text(self.clock())
        with self._transaction() as connection:
            records = [
                self._enqueue_one(connection, event, destination, now)
                for event, destination in values
            ]
        return tuple(records)

    def claim(
        self,
        *,
        worker_id: str,
        event_public_key_resolver: Callable[[str], Ed25519PublicKey],
        lease_seconds: int = 30,
        limit: int = 1,
    ) -> tuple[DeliveryLease, ...]:
        """Claim due work in partition order with a new fencing token."""

        worker_id = _require_identifier(worker_id, "worker id")
        if not 1 <= lease_seconds <= 3600 or not 1 <= limit <= 100:
            raise IntegrationValidationError("Lease bounds are invalid")
        now_value = self.clock()
        now = _utc_text(now_value)
        expires = _utc_text(now_value + timedelta(seconds=lease_seconds))
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE integration_outbox
                   SET state = 'dead_letter', lease_owner = NULL,
                       lease_expires_at = NULL, dead_lettered_at = ?, updated_at = ?
                 WHERE state = 'leased' AND lease_expires_at <= ?
                   AND attempt_count >= max_attempts
                """,
                (now, now, now),
            )
            rows = connection.execute(
                """
                SELECT o.*, e.signed_event_json, d.descriptor_json
                  FROM integration_outbox AS o
                  JOIN integration_events AS e ON e.event_id = o.event_id
                  JOIN integration_destinations AS d
                    ON d.destination_id = o.destination_id
                 WHERE (
                       (o.state IN ('pending', 'retry') AND o.next_attempt_at <= ?)
                    OR (o.state = 'leased' AND o.lease_expires_at <= ?)
                 )
                   AND o.attempt_count < o.max_attempts
                   AND NOT EXISTS (
                       SELECT 1 FROM integration_outbox AS earlier
                        WHERE earlier.partition_key = o.partition_key
                          AND earlier.sequence_number < o.sequence_number
                          AND earlier.state NOT IN ('delivered', 'dead_letter', 'cancelled')
                   )
                 ORDER BY o.sequence_number
                 LIMIT ?
                """,
                (now, now, limit),
            ).fetchall()
            leases: list[DeliveryLease] = []
            for row in rows:
                signed = self._signed_event_from_json(row["signed_event_json"])
                key = event_public_key_resolver(signed.signer_key_id)
                if not isinstance(key, Ed25519PublicKey):
                    raise IntegrationIntegrityError("Event key resolver returned an invalid key")
                verified = verify_integration_event(signed, key)
                destination = self._destination_from_json(row["descriptor_json"])
                if (
                    destination.destination_id != row["destination_id"]
                    or destination.destination_sha256 != row["destination_sha256"]
                ):
                    raise IntegrationIntegrityError("Stored destination binding is invalid")
                token = int(row["fencing_token"]) + 1
                attempt = int(row["attempt_count"]) + 1
                changed = connection.execute(
                    """
                    UPDATE integration_outbox
                       SET state = 'leased', attempt_count = ?, fencing_token = ?,
                           lease_owner = ?, lease_expires_at = ?, updated_at = ?
                     WHERE outbox_id = ? AND fencing_token = ?
                    """,
                    (
                        attempt,
                        token,
                        worker_id,
                        expires,
                        now,
                        row["outbox_id"],
                        row["fencing_token"],
                    ),
                ).rowcount
                if changed != 1:
                    raise IntegrationConflictError("Outbox claim lost its fencing race")
                updated = connection.execute(
                    "SELECT * FROM integration_outbox WHERE outbox_id = ?",
                    (row["outbox_id"],),
                ).fetchone()
                record = self._record(updated)
                leases.append(
                    DeliveryLease(record, worker_id, token, attempt, expires, verified, destination)
                )
        return tuple(leases)

    def complete(
        self,
        lease: DeliveryLease,
        observation: VerifiedDeliveryObservation,
    ) -> OutboxRecord:
        """Record an immutable signed receipt and complete, retry, or dead-letter."""

        if observation._marker is not _VERIFIED_OBSERVATION_MARKER:
            raise IntegrationValidationError("Outbox accepts only verified observations")
        now_value = self.clock()
        now = _utc_text(now_value)
        signed = observation.signed
        observed = signed.observation
        expected = (
            lease.event.signed.event.event_id,
            lease.event.signed.event.event_sha256,
            lease.event.signed.signer_key_id,
            lease.event.signed.public_key_sha256,
            lease.destination.destination_id,
            lease.destination.destination_sha256,
            lease.record.idempotency_key,
            lease.attempt_number,
        )
        actual = (
            observed.event_id,
            observed.event_sha256,
            observed.event_signer_key_id,
            observed.event_signer_public_key_sha256,
            observed.destination_id,
            observed.destination_sha256,
            observed.idempotency_key,
            observed.attempt_number,
        )
        if actual != expected:
            raise IntegrationValidationError("Completion observation binding is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT o.*, e.signed_event_json, d.descriptor_json "
                "FROM integration_outbox AS o "
                "JOIN integration_events AS e ON e.event_id = o.event_id "
                "JOIN integration_destinations AS d ON d.destination_id = o.destination_id "
                "WHERE o.outbox_id = ?",
                (lease.record.outbox_id,),
            ).fetchone()
            if row is None:
                raise IntegrationConflictError("Outbox entry does not exist")
            if row["state"] != "leased":
                raise IntegrationConflictError("Outbox entry is not actively leased")
            if (
                row["lease_owner"] != lease.worker_id
                or row["fencing_token"] != lease.fencing_token
                or row["attempt_count"] != lease.attempt_number
            ):
                raise IntegrationConflictError("Stale lease fencing token cannot complete work")
            if (
                any(
                    getattr(lease.record, name) != row[name]
                    for name in (
                        "event_id",
                        "event_sha256",
                        "destination_id",
                        "destination_sha256",
                        "idempotency_key",
                    )
                )
                or _canonical_json(lease.event.signed.to_dict()) != row["signed_event_json"]
                or _canonical_json(lease.destination.to_dict()) != row["descriptor_json"]
            ):
                raise IntegrationValidationError("Completion lease source binding is invalid")
            try:
                connection.execute(
                    """
                    INSERT INTO integration_delivery_receipts (
                        observation_id, observation_sha256, outbox_id, event_id,
                        event_sha256, destination_id, destination_sha256,
                        attempt_number, status, signed_observation_json, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observed.observation_id,
                        observed.observation_sha256,
                        row["outbox_id"],
                        observed.event_id,
                        observed.event_sha256,
                        observed.destination_id,
                        observed.destination_sha256,
                        observed.attempt_number,
                        observed.status.value,
                        _canonical_json(signed.to_dict()),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise IntegrationConflictError("Delivery observation replay detected") from exc
            if observed.status is ObservationStatus.SUCCEEDED:
                state = "delivered"
                next_attempt = row["next_attempt_at"]
                delivered_at = now
                dead_lettered_at = None
            elif (
                observed.status is ObservationStatus.RETRYABLE_FAILURE
                and row["attempt_count"] < row["max_attempts"]
            ):
                state = "retry"
                next_attempt = _utc_text(
                    now_value
                    + timedelta(
                        seconds=min(
                            row["retry_max_delay_seconds"],
                            row["retry_base_delay_seconds"] * (2 ** (row["attempt_count"] - 1)),
                        )
                    )
                )
                delivered_at = None
                dead_lettered_at = None
            else:
                state = "dead_letter"
                next_attempt = row["next_attempt_at"]
                delivered_at = None
                dead_lettered_at = now
            connection.execute(
                """
                UPDATE integration_outbox
                   SET state = ?, next_attempt_at = ?, lease_owner = NULL,
                       lease_expires_at = NULL, updated_at = ?, delivered_at = ?,
                       dead_lettered_at = ?
                 WHERE outbox_id = ? AND state = 'leased' AND fencing_token = ?
                """,
                (
                    state,
                    next_attempt,
                    now,
                    delivered_at,
                    dead_lettered_at,
                    row["outbox_id"],
                    lease.fencing_token,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM integration_outbox WHERE outbox_id = ?",
                (row["outbox_id"],),
            ).fetchone()
        return self._record(updated)

    def cancel(self, outbox_id: str, *, reason: str) -> OutboxRecord:
        """Cancel undelivered work and revoke any outstanding lease."""

        outbox_id = _require_text(outbox_id, "outbox id", 36)
        reason = _require_code(reason, "cancellation reason")
        now = _utc_text(self.clock())
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM integration_outbox WHERE outbox_id = ?", (outbox_id,)
            ).fetchone()
            if row is None:
                raise IntegrationConflictError("Outbox entry does not exist")
            if row["state"] in _TERMINAL_STATES:
                if row["state"] == "cancelled" and row["cancellation_reason"] == reason:
                    return self._record(row)
                raise IntegrationConflictError("Terminal outbox entry cannot be cancelled")
            connection.execute(
                """
                UPDATE integration_outbox
                   SET state = 'cancelled', cancellation_reason = ?,
                       lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                 WHERE outbox_id = ?
                """,
                (reason, now, outbox_id),
            )
            updated = connection.execute(
                "SELECT * FROM integration_outbox WHERE outbox_id = ?", (outbox_id,)
            ).fetchone()
        return self._record(updated)

    def get(self, outbox_id: str) -> OutboxRecord | None:
        """Read one outbox projection without granting a delivery capability."""

        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM integration_outbox WHERE outbox_id = ?", (outbox_id,)
            ).fetchone()
        return None if row is None else self._record(row)

    def receipt_count(self, outbox_id: str) -> int:
        """Return the number of immutable attempt receipts for one entry."""

        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM integration_delivery_receipts WHERE outbox_id = ?",
                (outbox_id,),
            ).fetchone()
        return int(row[0])

    def _enqueue_one(
        self,
        connection: sqlite3.Connection,
        event: VerifiedIntegrationEvent,
        destination: DestinationDescriptor,
        now: str,
    ) -> OutboxRecord:
        if event._marker is not _VERIFIED_EVENT_MARKER:
            raise IntegrationValidationError("Outbox accepts only verified signed events")
        signed = event.signed
        _verify_event_content(signed.event)
        descriptor = DestinationDescriptor.from_dict(destination.to_dict())
        event_json = _canonical_json(signed.to_dict())
        destination_json = _canonical_json(descriptor.to_dict())
        delivery_key = _sha256(
            {
                "destination_sha256": descriptor.destination_sha256,
                "event_idempotency_key": signed.event.idempotency_key,
            }
        )
        binding = {
            "destination_sha256": descriptor.destination_sha256,
            "event_sha256": signed.event.event_sha256,
            "idempotency_key": delivery_key,
        }
        outbox_id = "OBX-" + _sha256(binding).removeprefix("sha256:")[:32].upper()
        self._insert_or_verify_event(connection, signed, event_json, now)
        self._insert_or_verify_destination(connection, descriptor, destination_json, now)
        existing = connection.execute(
            "SELECT * FROM integration_outbox WHERE outbox_id = ? OR idempotency_key = ?",
            (outbox_id, delivery_key),
        ).fetchone()
        if existing is not None:
            record = self._record(existing)
            if (
                record.outbox_id != outbox_id
                or record.event_sha256 != signed.event.event_sha256
                or record.destination_sha256 != descriptor.destination_sha256
            ):
                raise IntegrationConflictError("Outbox idempotency key is already rebound")
            return record
        try:
            connection.execute(
                """
                INSERT INTO integration_outbox (
                    outbox_id, event_id, event_sha256, destination_id,
                    destination_sha256, idempotency_key, partition_key,
                    ordering_key, state, max_attempts, next_attempt_at,
                    retry_base_delay_seconds, retry_max_delay_seconds,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                """,
                (
                    outbox_id,
                    signed.event.event_id,
                    signed.event.event_sha256,
                    descriptor.destination_id,
                    descriptor.destination_sha256,
                    delivery_key,
                    _sha256(
                        {
                            "destination_sha256": descriptor.destination_sha256,
                            "event_partition_key": signed.event.partition_key,
                        }
                    ),
                    signed.event.ordering_key,
                    self.retry_policy.max_attempts,
                    now,
                    self.retry_policy.base_delay_seconds,
                    self.retry_policy.max_delay_seconds,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IntegrationConflictError("Outbox event or destination binding conflicts") from exc
        row = connection.execute(
            "SELECT * FROM integration_outbox WHERE outbox_id = ?", (outbox_id,)
        ).fetchone()
        return self._record(row)

    def _insert_or_verify_event(
        self,
        connection: sqlite3.Connection,
        signed: SignedIntegrationEvent,
        event_json: str,
        now: str,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM integration_events WHERE event_id = ? OR event_sha256 = ?",
            (signed.event.event_id, signed.event.event_sha256),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO integration_events VALUES (?, ?, ?, ?, ?)",
                (
                    signed.event.event_id,
                    signed.event.event_sha256,
                    signed.event.idempotency_key,
                    event_json,
                    now,
                ),
            )
        elif row["signed_event_json"] != event_json:
            raise IntegrationConflictError("Immutable event custody content differs")

    def _insert_or_verify_destination(
        self,
        connection: sqlite3.Connection,
        destination: DestinationDescriptor,
        destination_json: str,
        now: str,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM integration_destinations WHERE destination_id = ?",
            (destination.destination_id,),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO integration_destinations VALUES (?, ?, ?, ?)",
                (
                    destination.destination_id,
                    destination.destination_sha256,
                    destination_json,
                    now,
                ),
            )
        elif row["descriptor_json"] != destination_json:
            raise IntegrationConflictError("Destination id cannot be substituted")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.access.verify_directory(self.directory)
        self.access.verify_file(self.path)
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            self._verify_database(connection)
            yield connection
        except sqlite3.Error as exc:
            raise IntegrationIntegrityError("SQLite outbox operation failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _verify_database(connection: sqlite3.Connection) -> None:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        if application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
            raise IntegrationIntegrityError("Outbox database identity is invalid")
        if journal_mode.lower() != "delete":
            raise IntegrationIntegrityError("Outbox database journal mode is invalid")

    @staticmethod
    def _record(row: sqlite3.Row) -> OutboxRecord:
        return OutboxRecord(
            outbox_id=str(row["outbox_id"]),
            sequence_number=int(row["sequence_number"]),
            event_id=str(row["event_id"]),
            event_sha256=str(row["event_sha256"]),
            destination_id=str(row["destination_id"]),
            destination_sha256=str(row["destination_sha256"]),
            idempotency_key=str(row["idempotency_key"]),
            partition_key=str(row["partition_key"]),
            ordering_key=str(row["ordering_key"]),
            state=str(row["state"]),
            attempt_count=int(row["attempt_count"]),
            max_attempts=int(row["max_attempts"]),
            retry_base_delay_seconds=int(row["retry_base_delay_seconds"]),
            retry_max_delay_seconds=int(row["retry_max_delay_seconds"]),
            next_attempt_at=str(row["next_attempt_at"]),
            fencing_token=int(row["fencing_token"]),
            lease_owner=None if row["lease_owner"] is None else str(row["lease_owner"]),
            lease_expires_at=(
                None if row["lease_expires_at"] is None else str(row["lease_expires_at"])
            ),
            cancellation_reason=(
                None if row["cancellation_reason"] is None else str(row["cancellation_reason"])
            ),
        )

    @staticmethod
    def _signed_event_from_json(value: str) -> SignedIntegrationEvent:
        try:
            raw = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrationIntegrityError("Stored signed event JSON is invalid") from exc
        if not isinstance(raw, Mapping):
            raise IntegrationIntegrityError("Stored signed event is invalid")
        return SignedIntegrationEvent.from_dict(raw)

    @staticmethod
    def _destination_from_json(value: str) -> DestinationDescriptor:
        try:
            raw = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrationIntegrityError("Stored destination JSON is invalid") from exc
        if not isinstance(raw, Mapping):
            raise IntegrationIntegrityError("Stored destination is invalid")
        return DestinationDescriptor.from_dict(raw)


__all__ = [
    "APPLICATION_ID",
    "DATABASE_FILENAME",
    "DeliveryLease",
    "DeliveryObservation",
    "DestinationDescriptor",
    "DestinationKind",
    "DestinationReference",
    "DigestReference",
    "EventType",
    "ExternalDeliveryAdapter",
    "IntegrationConflictError",
    "IntegrationEvent",
    "IntegrationIntegrityError",
    "IntegrationOutbox",
    "IntegrationOutboxError",
    "IntegrationValidationError",
    "ObservationStatus",
    "OpaqueLinkReference",
    "OutboxAccessController",
    "OutboxRecord",
    "PosixOwnerOnlyOutboxAccess",
    "RetryPolicy",
    "Severity",
    "SignedDeliveryObservation",
    "SignedIntegrationEvent",
    "VerifiedDeliveryObservation",
    "VerifiedIntegrationEvent",
    "create_delivery_observation",
    "create_destination",
    "create_integration_event",
    "deliver_with_adapter",
    "sign_delivery_observation",
    "sign_integration_event",
    "verify_delivery_observation",
    "verify_integration_event",
]
