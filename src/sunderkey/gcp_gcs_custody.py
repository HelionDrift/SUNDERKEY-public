"""Offline, injected-transport GCS mapping for two D012 custody ports.

No network transport is supplied. Provider observations are not authenticated
custody evidence or authority to operate a selected GCP environment.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from typing import Protocol

from .candidate_enrollment_production_custody_contract import (
    LedgerHeadCompareAndSwapReceipt,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadReceipt,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutReceipt,
    LedgerObjectPutRequest,
    LedgerObjectReadReceipt,
    LedgerObjectReadRequest,
    ProviderPolicyRejection,
    RetentionStateReadReceipt,
    RetentionStateReadRequest,
    provider_subject_sha256,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256
from .validation import loads_json_without_duplicate_keys

ENVIRONMENT_CLASS = "reference_simulation_nonqualifying"
MAXIMUM_OBJECT_BYTES = 16 * 1024 * 1024
MAXIMUM_HEAD_BYTES = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_DECIMAL = re.compile(r"[1-9][0-9]{0,18}")


class GCSCustodyError(QualificationError):
    """Unconfirmed or unsupported storage observations, not policy denials."""


class GCSPreconditionFailed(Exception):
    """Injected transport reports an unsuccessful generation precondition."""


class GCSAmbiguousWrite(Exception):
    """Injected transport cannot confirm whether a write was applied."""


def _text(value: object, label: str, pattern: re.Pattern[str]) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise GCSCustodyError(f"{label} is invalid")


def _instant(value: str) -> datetime:
    _text(value, "UTC timestamp", _UTC)
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise GCSCustodyError("UTC timestamp is invalid") from exc


def _generation(value: str, *, zero: bool = False) -> None:
    if zero and type(value) is str and value == "0":
        return
    _text(value, "generation", _DECIMAL)
    if int(value) > 2**63 - 1:
        raise GCSCustodyError("Generation exceeds the supported signed-long range")


def _object_name(value: str) -> None:
    if type(value) is not str or len(value) > 256:
        raise GCSCustodyError("Object name is invalid")
    prefix, separator, identifier = value.partition("/")
    if separator != "/" or prefix not in {"ledger", "heads"}:
        raise GCSCustodyError("Object name is outside the supported mapping")
    _text(identifier, "object identifier", _IDENTIFIER)


@dataclass(frozen=True)
class GCSBucketProfile:
    """Explicit declared profile, also used for injected bucket observations."""

    bucket: str
    namespace_id: str
    failure_domain_id: str
    versioning_enabled: bool
    retention_policy_locked: bool
    retention_period_seconds: int

    def __post_init__(self) -> None:
        _text(self.bucket, "bucket", _BUCKET)
        _text(self.namespace_id, "namespace_id", _IDENTIFIER)
        _text(self.failure_domain_id, "failure_domain_id", _IDENTIFIER)
        if (
            type(self.versioning_enabled) is not bool
            or type(self.retention_policy_locked) is not bool
            or type(self.retention_period_seconds) is not int
            or not 0 <= self.retention_period_seconds <= 3_155_760_000
        ):
            raise GCSCustodyError("Bucket policy scalar types or bounds are invalid")


@dataclass(frozen=True)
class GCSCustodyProfiles:
    """Supported subset: locked ledger bucket and a separate unlocked head."""

    ledger: GCSBucketProfile
    head: GCSBucketProfile

    def __post_init__(self) -> None:
        ledger = _rebuild(self.ledger, GCSBucketProfile)
        head = _rebuild(self.head, GCSBucketProfile)
        if (
            ledger.bucket == head.bucket
            or ledger.namespace_id == head.namespace_id
            or ledger.versioning_enabled
            or head.versioning_enabled
            or not ledger.retention_policy_locked
            or ledger.retention_period_seconds < 1
            or head.retention_policy_locked
            or head.retention_period_seconds != 0
        ):
            raise GCSCustodyError("Unsupported ledger/head bucket profiles")


@dataclass(frozen=True)
class GCSObjectMetadata:
    """Narrow observation of one live object version, not a signed receipt."""

    bucket: str
    object_name: str
    generation: str
    metageneration: str
    size_bytes: int
    retention_until: str | None
    ledger_object: LedgerObjectDescriptor | None
    is_live: bool

    def __post_init__(self) -> None:
        _text(self.bucket, "bucket", _BUCKET)
        _object_name(self.object_name)
        _generation(self.generation)
        _generation(self.metageneration)
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= MAXIMUM_OBJECT_BYTES:
            raise GCSCustodyError("Object size is outside the supported bound")
        if type(self.is_live) is not bool or not self.is_live:
            raise GCSCustodyError("Noncurrent or deleted object observations are unsupported")
        if self.retention_until is not None:
            _instant(self.retention_until)
        if self.ledger_object is not None:
            _rebuild(self.ledger_object, LedgerObjectDescriptor)


@dataclass(frozen=True)
class GCSReadRequest:
    bucket: str
    object_name: str
    generation: str
    metageneration: str

    def __post_init__(self) -> None:
        _text(self.bucket, "bucket", _BUCKET)
        _object_name(self.object_name)
        _generation(self.generation)
        _generation(self.metageneration)


@dataclass(frozen=True)
class GCSObjectRead:
    metadata: GCSObjectMetadata
    payload: bytes

    def __post_init__(self) -> None:
        metadata = _rebuild(self.metadata, GCSObjectMetadata)
        if type(self.payload) is not bytes or len(self.payload) != metadata.size_bytes:
            raise GCSCustodyError("Pinned object bytes do not match observed size")


@dataclass(frozen=True)
class GCSWriteRequest:
    request_id: str
    bucket: str
    object_name: str
    payload: bytes
    if_generation_match: str
    if_metageneration_match: str | None
    ledger_object: LedgerObjectDescriptor | None

    def __post_init__(self) -> None:
        _text(self.request_id, "request_id", _IDENTIFIER)
        _text(self.bucket, "bucket", _BUCKET)
        _object_name(self.object_name)
        _generation(self.if_generation_match, zero=True)
        if type(self.payload) is not bytes or len(self.payload) > MAXIMUM_OBJECT_BYTES:
            raise GCSCustodyError("Write bytes are invalid or exceed the supported bound")
        if self.if_generation_match == "0":
            if self.if_metageneration_match is not None:
                raise GCSCustodyError("Create-only write cannot supply a metageneration")
        else:
            _generation(self.if_metageneration_match)
        if self.ledger_object is not None:
            descriptor = _rebuild(self.ledger_object, LedgerObjectDescriptor)
            if (
                self.if_generation_match != "0"
                or self.object_name != "ledger/" + descriptor.object_id
                or len(self.payload) != descriptor.size_bytes
                or _bytes_digest(self.payload) != descriptor.sha256
            ):
                raise GCSCustodyError("Ledger write binding is invalid")


class GCSCustodyTransport(Protocol):
    """Caller-injected observations and conditional writes, without a default."""

    def read_bucket_profile(self, bucket: str) -> GCSBucketProfile: ...

    def read_object_metadata(self, bucket: str, object_name: str) -> GCSObjectMetadata | None: ...

    def read_object(self, request: GCSReadRequest) -> GCSObjectRead: ...

    def write_object(self, request: GCSWriteRequest) -> GCSObjectMetadata: ...


_SCALAR_TYPES = {
    "request_id": (str,),
    "object_id": (str,),
    "sha256": (str,),
    "size_bytes": (int,),
    "retention_until": (str, type(None)),
    "namespace_id": (str,),
    "failure_domain_id": (str,),
    "expected_sha256": (str,),
    "required_retention_until": (str,),
    "deployment_id": (str,),
    "ledger_sequence": (int,),
    "entry_id": (str,),
    "entry_sha256": (str,),
    "previous_head_sha256": (str, type(None)),
    "expected_head_sha256": (str, type(None)),
    "payload": (bytes,),
    "write_status": (str,),
    "retention_lock_verified": (bool,),
    "digest_verified": (bool,),
    "deletion_protection_verified": (bool,),
    "compare_and_swap_status": (str,),
    "bucket": (str,),
    "versioning_enabled": (bool,),
    "retention_policy_locked": (bool,),
    "retention_period_seconds": (int,),
    "object_name": (str,),
    "generation": (str,),
    "metageneration": (str,),
    "is_live": (bool,),
    "if_generation_match": (str,),
    "if_metageneration_match": (str, type(None)),
}


def _rebuild(value, family):
    """Reconstruct only the fixed port families, including nested descriptors."""

    if type(value) is not family:
        raise GCSCustodyError("Custody value is not the exact expected typed family")
    copied = {}
    for field in fields(family):
        item = getattr(value, field.name)
        if field.name in {"ledger", "head"} and family is GCSCustodyProfiles:
            copied[field.name] = _rebuild(item, GCSBucketProfile)
        elif field.name in {"object", "ledger_object"}:
            if item is None and field.name == "ledger_object":
                copied[field.name] = None
            else:
                copied[field.name] = _rebuild(item, LedgerObjectDescriptor)
        elif field.name in {"head", "proposed_head"}:
            if item is None and family is LedgerHeadReadReceipt:
                copied[field.name] = None
            else:
                copied[field.name] = _rebuild(item, LedgerHeadDescriptor)
        elif field.name == "metadata":
            copied[field.name] = _rebuild(item, GCSObjectMetadata)
        else:
            if type(item) not in _SCALAR_TYPES[field.name]:
                raise GCSCustodyError(f"Non-native custody field: {field.name}")
            if field.name == "payload" and len(item) > MAXIMUM_OBJECT_BYTES:
                raise GCSCustodyError("Custody payload exceeds the supported bound")
            copied[field.name] = item
    try:
        return family(**copied)
    except (TypeError, ValueError) as exc:
        raise GCSCustodyError("Typed custody value does not reconstruct") from exc


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _head_document(head: LedgerHeadDescriptor) -> dict:
    return {field.name: getattr(head, field.name) for field in fields(LedgerHeadDescriptor)}


def _head_digest(head: LedgerHeadDescriptor) -> str:
    return _canonical_sha256(_head_document(head))


def _callback_request_snapshot(request) -> tuple:
    """Capture validated primitive expectations without retaining descriptors."""

    return tuple(
        tuple(getattr(request.ledger_object, item.name) for item in fields(LedgerObjectDescriptor))
        if item.name == "ledger_object" and request.ledger_object is not None
        else getattr(request, item.name)
        for item in fields(type(request))
    )


def _invoke_owned_request_callback(operation, request, family):
    """Reject changed delivery inputs before interpreting any callback outcome."""

    if family not in (GCSReadRequest, GCSWriteRequest):
        raise GCSCustodyError("Unsupported transport request family")
    captured = _rebuild(request, family)
    expected = _callback_request_snapshot(captured)
    delivered = _rebuild(captured, family)
    try:
        return operation(delivered)
    finally:
        try:
            observed = _rebuild(delivered, family)
            unchanged = _callback_request_snapshot(observed) == expected
        except (AttributeError, TypeError, ValueError) as exc:
            raise GCSCustodyError(
                "Transport request changed; outcome is unconfirmed, with no automatic retry"
            ) from exc
        if not unchanged:
            raise GCSCustodyError(
                "Transport request changed; outcome is unconfirmed, with no automatic retry"
            )


class _GCSMapping:
    environment_class = ENVIRONMENT_CLASS

    def __init__(
        self,
        transport: GCSCustodyTransport,
        profiles: GCSCustodyProfiles,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._profiles = _rebuild(profiles, GCSCustodyProfiles)
        if not callable(clock):
            raise GCSCustodyError("An explicit UTC clock is required")
        for operation in (
            "read_bucket_profile",
            "read_object_metadata",
            "read_object",
            "write_object",
        ):
            if not callable(getattr(transport, operation, None)):
                raise GCSCustodyError("Injected transport does not implement its complete port")
        self._transport = transport
        self._clock = clock

    def _profile(self, role: str) -> GCSBucketProfile:
        profiles = _rebuild(self._profiles, GCSCustodyProfiles)
        expected = profiles.ledger if role == "ledger" else profiles.head
        observed = _rebuild(self._transport.read_bucket_profile(expected.bucket), GCSBucketProfile)
        if observed != expected:
            raise GCSCustodyError("Observed bucket policy does not match the explicit profile")
        return expected

    def _now(self) -> datetime:
        value = self._clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise GCSCustodyError("Clock must return a native aware UTC datetime")
        return value

    def _metadata(self, profile: GCSBucketProfile, name: str) -> GCSObjectMetadata | None:
        value = self._transport.read_object_metadata(profile.bucket, name)
        if value is None:
            return None
        metadata = _rebuild(value, GCSObjectMetadata)
        self._coordinates(metadata, profile, name)
        return metadata

    @staticmethod
    def _coordinates(metadata: GCSObjectMetadata, profile: GCSBucketProfile, name: str) -> None:
        if metadata.bucket != profile.bucket or metadata.object_name != name:
            raise GCSCustodyError("Object observation substitutes the bound bucket or name")

    def _pinned_read(self, metadata: GCSObjectMetadata) -> GCSObjectRead:
        request = GCSReadRequest(
            metadata.bucket, metadata.object_name, metadata.generation, metadata.metageneration
        )
        try:
            observed = _rebuild(
                _invoke_owned_request_callback(
                    self._transport.read_object, request, GCSReadRequest
                ),
                GCSObjectRead,
            )
        except GCSPreconditionFailed as exc:
            raise GCSCustodyError("Pinned object snapshot changed during the read") from exc
        if observed.metadata != metadata:
            raise GCSCustodyError("Read substitutes a pinned generation or metadata snapshot")
        return observed

    def _write(self, request: GCSWriteRequest) -> GCSObjectMetadata:
        try:
            return _rebuild(
                _invoke_owned_request_callback(
                    self._transport.write_object, request, GCSWriteRequest
                ),
                GCSObjectMetadata,
            )
        except GCSAmbiguousWrite as exc:
            raise GCSCustodyError("Write outcome is unconfirmed; no automatic retry") from exc


class GCSRetentionLockedLedgerObjectProvider(_GCSMapping):
    """D012 ledger-object port mapped to the supported synthetic GCS profile."""

    def _ledger_read(self, profile: GCSBucketProfile, metadata: GCSObjectMetadata):
        observed = self._pinned_read(metadata)
        descriptor = metadata.ledger_object
        if descriptor is None:
            raise GCSCustodyError("Ledger descriptor is missing")
        if (
            metadata.object_name != "ledger/" + descriptor.object_id
            or descriptor.namespace_id != profile.namespace_id
            or descriptor.failure_domain_id != profile.failure_domain_id
            or descriptor.size_bytes != metadata.size_bytes
            or descriptor.sha256 != _bytes_digest(observed.payload)
            or metadata.retention_until is None
            or _instant(metadata.retention_until) < _instant(descriptor.retention_until)
            or _instant(metadata.retention_until) <= self._now()
        ):
            raise GCSCustodyError("Ledger content, descriptor or active retention is unverified")
        return descriptor, observed.payload

    def put_if_absent(self, request: LedgerObjectPutRequest) -> LedgerObjectPutReceipt:
        request = _rebuild(request, LedgerObjectPutRequest)
        profile = self._profile("ledger")
        descriptor = request.object
        required = _instant(descriptor.retention_until)
        now = self._now()
        if (
            descriptor.namespace_id != profile.namespace_id
            or descriptor.failure_domain_id != profile.failure_domain_id
            or len(request.payload) != descriptor.size_bytes
            or required <= now
            or required - now > timedelta(seconds=profile.retention_period_seconds)
        ):
            raise GCSCustodyError("Ledger request is outside the declared custody profile")
        name = "ledger/" + descriptor.object_id
        write = GCSWriteRequest(
            request.request_id, profile.bucket, name, request.payload, "0", None, descriptor
        )
        status = "created"
        try:
            metadata = self._write(write)
        except GCSPreconditionFailed:
            status = "already_present_same_digest"
            metadata = self._metadata(profile, name)
            if metadata is None:
                raise GCSCustodyError("Create precondition outcome cannot be confirmed") from None
        self._coordinates(metadata, profile, name)
        current, payload = self._ledger_read(profile, metadata)
        if current != descriptor or payload != request.payload:
            if status == "already_present_same_digest":
                raise ProviderPolicyRejection(
                    "immutable_ledger_overwrite",
                    request.request_id,
                    provider_subject_sha256(descriptor),
                )
            raise GCSCustodyError("Write acknowledgement substitutes the requested ledger object")
        self._profile("ledger")
        return _rebuild(
            LedgerObjectPutReceipt(request.request_id, descriptor, status, True),
            LedgerObjectPutReceipt,
        )

    def read_verified(self, request: LedgerObjectReadRequest) -> LedgerObjectReadReceipt:
        request = _rebuild(request, LedgerObjectReadRequest)
        profile = self._profile("ledger")
        metadata = self._metadata(profile, "ledger/" + request.object_id)
        if metadata is None:
            raise GCSCustodyError("Ledger object is unavailable")
        descriptor, payload = self._ledger_read(profile, metadata)
        if descriptor.sha256 != request.expected_sha256:
            raise GCSCustodyError("Ledger read does not match the requested SHA-256")
        self._profile("ledger")
        return _rebuild(
            LedgerObjectReadReceipt(request.request_id, descriptor, payload, True),
            LedgerObjectReadReceipt,
        )

    def read_retention_state(self, request: RetentionStateReadRequest) -> RetentionStateReadReceipt:
        request = _rebuild(request, RetentionStateReadRequest)
        profile = self._profile("ledger")
        metadata = self._metadata(profile, "ledger/" + request.object_id)
        if metadata is None:
            raise GCSCustodyError("Ledger retention object is unavailable")
        descriptor, _ = self._ledger_read(profile, metadata)
        required = _instant(request.required_retention_until)
        if (
            _instant(metadata.retention_until) < required
            or _instant(descriptor.retention_until) < required
        ):
            raise GCSCustodyError("Required retention is not met")
        self._profile("ledger")
        return _rebuild(
            RetentionStateReadReceipt(request.request_id, descriptor, True, True),
            RetentionStateReadReceipt,
        )


class GCSConditionalLedgerHeadProvider(_GCSMapping):
    """D012 logical head sequencing fenced by provider generation tokens."""

    def _head_read(self, profile: GCSBucketProfile, name: str, metadata: GCSObjectMetadata):
        self._coordinates(metadata, profile, name)
        if metadata.ledger_object is not None or metadata.retention_until is not None:
            raise GCSCustodyError("Mutable head unexpectedly has ledger or retention metadata")
        if metadata.size_bytes > MAXIMUM_HEAD_BYTES:
            raise GCSCustodyError("Head exceeds its fixed document bound")
        observed = self._pinned_read(metadata)
        if len(observed.payload) > MAXIMUM_HEAD_BYTES:
            raise GCSCustodyError("Head exceeds its fixed document bound")
        try:
            document = loads_json_without_duplicate_keys(observed.payload.decode("utf-8"))
            expected = {field.name for field in fields(LedgerHeadDescriptor)}
            if type(document) is not dict or set(document) != expected:
                raise GCSCustodyError("Head document fields are invalid")
            head = _rebuild(LedgerHeadDescriptor(**document), LedgerHeadDescriptor)
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise GCSCustodyError("Head document does not reconstruct") from exc
        if name != "heads/" + head.deployment_id or observed.payload != _canonical_json(
            _head_document(head)
        ).encode("utf-8"):
            raise GCSCustodyError("Head bytes or deployment binding are not canonical")
        return head

    def read_head(self, request: LedgerHeadReadRequest) -> LedgerHeadReadReceipt:
        request = _rebuild(request, LedgerHeadReadRequest)
        profile = self._profile("head")
        name = "heads/" + request.deployment_id
        metadata = self._metadata(profile, name)
        head = None if metadata is None else self._head_read(profile, name, metadata)
        self._profile("head")
        return _rebuild(LedgerHeadReadReceipt(request.request_id, head), LedgerHeadReadReceipt)

    def compare_and_swap_head(
        self, request: LedgerHeadCompareAndSwapRequest
    ) -> LedgerHeadCompareAndSwapReceipt:
        request = _rebuild(request, LedgerHeadCompareAndSwapRequest)
        proposed = request.proposed_head
        proposed_payload = _canonical_json(_head_document(proposed)).encode("utf-8")
        if len(proposed_payload) > MAXIMUM_HEAD_BYTES:
            raise GCSCustodyError("Proposed head exceeds its fixed document bound")
        profile = self._profile("head")
        name = "heads/" + proposed.deployment_id
        metadata = self._metadata(profile, name)
        current = None if metadata is None else self._head_read(profile, name, metadata)
        if current == proposed:
            return self._receipt(request, "already_current_same_digest")
        current_digest = None if current is None else _head_digest(current)
        if current_digest != request.expected_head_sha256:
            self._deny(request, "ledger_head_conflict")
        if proposed.ledger_sequence != (1 if current is None else current.ledger_sequence + 1):
            self._deny(request, "ledger_sequence_gap")
        write = GCSWriteRequest(
            request.request_id,
            profile.bucket,
            name,
            proposed_payload,
            "0" if metadata is None else metadata.generation,
            None if metadata is None else metadata.metageneration,
            None,
        )
        try:
            written = self._write(write)
        except GCSPreconditionFailed:
            winner_metadata = self._metadata(profile, name)
            if winner_metadata is None:
                raise GCSCustodyError("Head precondition outcome cannot be confirmed") from None
            winner = self._head_read(profile, name, winner_metadata)
            if winner == proposed:
                return self._receipt(request, "already_current_same_digest")
            if _head_digest(winner) != request.expected_head_sha256:
                self._deny(request, "ledger_head_conflict")
            raise GCSCustodyError("Head precondition outcome is not a confirmed logical conflict")
        if metadata is not None and written.generation == metadata.generation:
            raise GCSCustodyError("CAS acknowledgement did not advance the content generation")
        if self._head_read(profile, name, written) != proposed:
            raise GCSCustodyError("CAS acknowledgement substitutes the proposed head")
        return self._receipt(request, "advanced")

    def _receipt(self, request, status):
        self._profile("head")
        return _rebuild(
            LedgerHeadCompareAndSwapReceipt(request.request_id, request.proposed_head, status),
            LedgerHeadCompareAndSwapReceipt,
        )

    @staticmethod
    def _deny(request, code):
        raise ProviderPolicyRejection(
            code, request.request_id, provider_subject_sha256(request.proposed_head)
        )
