"""Bounded reference-only GCS mapping of the D012 immutable catalog port."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Protocol

from .candidate_enrollment_production_custody_contract import (
    CatalogObjectDescriptor,
    CatalogObjectPutReceipt,
    CatalogObjectPutRequest,
    CatalogObjectReadReceipt,
    CatalogObjectReadRequest,
    ProviderPolicyRejection,
    provider_subject_sha256,
)
from .gcp_gcs_custody import GCSAmbiguousWrite, GCSCustodyError, GCSPreconditionFailed
from .qualification import _canonical_sha256

ENVIRONMENT_CLASS = "reference_simulation_nonqualifying"
MAXIMUM_OBJECT_BYTES = 16 * 1024 * 1024
MAXIMUM_CONFIRMED_OBJECTS = 4096
MAXIMUM_RETENTION_SECONDS = 3_155_760_000
PROFILE_DOMAIN = "sunderkey.gcp-gcs-catalog-simulation-profile.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_TOKEN = re.compile(r"[1-9][0-9]{0,18}")
_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "deployment": "none",
        "enrollment": "none",
        "catalog_publication": "none",
        "network": "none",
        "production_storage_mutation": "none",
        "provider_calls": "none",
        "qualification": "none",
        "provider_selection": "none",
        "runtime": "none",
    }
)


class GCSCatalogError(GCSCustodyError):
    """Unconfirmed catalog observations, not production policy evidence."""


def _text(value: object, label: str, pattern: re.Pattern[str] = _ID) -> None:
    if type(value) is not str or len(value) > 256 or pattern.fullmatch(value) is None:
        raise GCSCatalogError(f"Invalid native {label}")


def _instant(value: str) -> datetime:
    _text(value, "UTC timestamp", _UTC)
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise GCSCatalogError("Invalid UTC timestamp") from exc


def _utc(value: datetime) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise GCSCatalogError("A native aware UTC datetime is required")


def _token(value: str) -> None:
    _text(value, "generation token", _TOKEN)
    if int(value) > 2**63 - 1:
        raise GCSCatalogError("Generation token exceeds the supported range")


def _name(value: str) -> None:
    if type(value) is not str or len(value) > 136 or not value.startswith("catalog/"):
        raise GCSCatalogError("Object name is outside the stable catalog namespace")
    _text(value.removeprefix("catalog/"), "catalog object ID")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class GCSCatalogDomain:
    """Declared coordinates, not verified accounts or failure-domain independence."""

    bucket: str
    namespace_id: str
    failure_domain_id: str
    account_reference: str

    def __post_init__(self) -> None:
        _text(self.bucket, "bucket", _BUCKET)
        for name in ("namespace_id", "failure_domain_id", "account_reference"):
            _text(getattr(self, name), name)


@dataclass(frozen=True)
class GCSCatalogSimulationProfile:
    """One fixed finite use horizon, never a deployment-lifetime retention choice."""

    catalog: GCSCatalogDomain
    ledger: GCSCatalogDomain
    simulation_started_at: str
    simulation_use_until: str
    retention_period_seconds: int
    profile_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        catalog = _owned(self.catalog, GCSCatalogDomain)
        ledger = _owned(self.ledger, GCSCatalogDomain)
        if any(
            getattr(catalog, name) == getattr(ledger, name)
            for name in ("bucket", "namespace_id", "failure_domain_id", "account_reference")
        ):
            raise GCSCatalogError("Catalog and ledger declarations must be distinct")
        started, until = _instant(self.simulation_started_at), _instant(self.simulation_use_until)
        if (
            type(self.retention_period_seconds) is not int
            or not 1 <= self.retention_period_seconds <= MAXIMUM_RETENTION_SECONDS
            or until <= started
            or until - started > timedelta(seconds=self.retention_period_seconds)
        ):
            raise GCSCatalogError("Simulation horizon must fit the explicit bounded retention")
        object.__setattr__(self, "catalog", catalog)
        object.__setattr__(self, "ledger", ledger)
        object.__setattr__(
            self,
            "profile_sha256",
            _canonical_sha256({"domain": PROFILE_DOMAIN, **_profile_body(self)}),
        )

    def to_dict(self) -> dict[str, object]:
        captured = _owned(self, GCSCatalogSimulationProfile)
        return {**_profile_body(captured), "profile_sha256": captured.profile_sha256}


@dataclass(frozen=True)
class GCSCatalogBucketObservation:
    domain: GCSCatalogDomain
    observed_at: datetime
    is_current: bool
    versioning_enabled: bool
    retention_policy_locked: bool
    retention_period_seconds: int
    default_event_based_hold: bool
    object_retention_enabled: bool

    def __post_init__(self) -> None:
        _scalars(self)
        object.__setattr__(self, "domain", _owned(self.domain, GCSCatalogDomain))
        _utc(self.observed_at)
        if not 0 <= self.retention_period_seconds <= MAXIMUM_RETENTION_SECONDS:
            raise GCSCatalogError("Observed retention period is outside the bound")


@dataclass(frozen=True)
class GCSCatalogObjectObservation:
    bucket: str
    object_name: str
    generation: str
    metageneration: str
    descriptor: CatalogObjectDescriptor
    retention_until: str
    observed_at: datetime
    is_current: bool
    temporary_hold: bool
    event_based_hold: bool
    retention_mode: str

    def __post_init__(self) -> None:
        _scalars(self)
        object.__setattr__(self, "descriptor", _owned(self.descriptor, CatalogObjectDescriptor))
        _text(self.bucket, "bucket", _BUCKET)
        _name(self.object_name)
        _token(self.generation)
        _token(self.metageneration)
        _instant(self.retention_until)
        _utc(self.observed_at)
        _text(self.retention_mode, "retention mode")


@dataclass(frozen=True)
class GCSCatalogReadRequest:
    bucket: str
    object_name: str
    generation: str
    metageneration: str
    descriptor: CatalogObjectDescriptor
    observed_at: datetime

    def __post_init__(self) -> None:
        _scalars(self)
        descriptor = _owned(self.descriptor, CatalogObjectDescriptor)
        object.__setattr__(self, "descriptor", descriptor)
        _text(self.bucket, "bucket", _BUCKET)
        _name(self.object_name)
        _token(self.generation)
        _token(self.metageneration)
        _utc(self.observed_at)
        if self.object_name != "catalog/" + descriptor.object_id:
            raise GCSCatalogError("Pinned read substitutes the catalog identity")


@dataclass(frozen=True)
class GCSCatalogObjectRead:
    observation: GCSCatalogObjectObservation
    payload: bytes

    def __post_init__(self) -> None:
        _scalars(self)
        observed = _owned(self.observation, GCSCatalogObjectObservation)
        object.__setattr__(self, "observation", observed)
        if len(self.payload) != observed.descriptor.size_bytes:
            raise GCSCatalogError("Pinned read bytes do not match the observed size")


@dataclass(frozen=True)
class GCSCatalogWriteRequest:
    request_id: str
    bucket: str
    object_name: str
    descriptor: CatalogObjectDescriptor
    payload: bytes
    observed_at: datetime
    if_generation_match: str = "0"
    if_metageneration_match: None = None

    def __post_init__(self) -> None:
        _scalars(self)
        descriptor = _owned(self.descriptor, CatalogObjectDescriptor)
        object.__setattr__(self, "descriptor", descriptor)
        _text(self.request_id, "request ID")
        _text(self.bucket, "bucket", _BUCKET)
        _name(self.object_name)
        _utc(self.observed_at)
        if (
            self.object_name != "catalog/" + descriptor.object_id
            or self.if_generation_match != "0"
            or self.if_metageneration_match is not None
            or len(self.payload) != descriptor.size_bytes
            or _digest(self.payload) != descriptor.sha256
        ):
            raise GCSCatalogError(
                "Catalog write must bind exact bytes and create-only preconditions"
            )


class GCSCatalogTransport(Protocol):
    """Only caller-injected synthetic observations and writes, with no default."""

    environment_class: str

    def read_bucket(self, bucket: str, *, observed_at: datetime) -> GCSCatalogBucketObservation: ...

    def read_object_metadata(
        self, bucket: str, object_name: str, *, observed_at: datetime
    ) -> GCSCatalogObjectObservation | None: ...

    def read_object(self, request: GCSCatalogReadRequest) -> GCSCatalogObjectRead: ...

    def write_object(self, request: GCSCatalogWriteRequest) -> GCSCatalogObjectObservation: ...


_NESTED = {
    "catalog": GCSCatalogDomain,
    "ledger": GCSCatalogDomain,
    "domain": GCSCatalogDomain,
    "descriptor": CatalogObjectDescriptor,
    "object": CatalogObjectDescriptor,
    "observation": GCSCatalogObjectObservation,
}
_INTS = {"retention_period_seconds", "size_bytes"}
_BOOLS = {
    "is_current",
    "versioning_enabled",
    "retention_policy_locked",
    "default_event_based_hold",
    "object_retention_enabled",
    "temporary_hold",
    "event_based_hold",
    "immutable_storage_verified",
    "digest_verified",
}


def _scalars(value: object) -> None:
    for item in fields(type(value)):
        if not item.init or item.name in _NESTED:
            continue
        scalar = getattr(value, item.name)
        expected = (
            int
            if item.name in _INTS
            else bool
            if item.name in _BOOLS
            else datetime
            if item.name == "observed_at"
            else bytes
            if item.name == "payload"
            else type(None)
            if item.name == "if_metageneration_match"
            else str
        )
        if type(scalar) is not expected:
            raise GCSCatalogError(f"Non-native catalog field: {item.name}")
        if expected is str and len(scalar) > 256:
            raise GCSCatalogError("Catalog strings exceed the early bound")
        if item.name in {"request_id", "object_id", "namespace_id", "failure_domain_id"}:
            _text(scalar, item.name)
        if expected is bytes and not 1 <= len(scalar) <= MAXIMUM_OBJECT_BYTES:
            raise GCSCatalogError("Catalog bytes exceed the early bound")
        if item.name == "size_bytes" and not 1 <= scalar <= MAXIMUM_OBJECT_BYTES:
            raise GCSCatalogError("Catalog size exceeds the early bound")


def _owned(value, family):
    if type(value) is not family:
        raise GCSCatalogError("An exact catalog typed family is required")
    try:
        _scalars(value)
        copied = {
            item.name: _owned(getattr(value, item.name), _NESTED[item.name])
            if item.name in _NESTED
            else getattr(value, item.name)
            for item in fields(family)
            if item.init
        }
        if (
            family is CatalogObjectPutRequest
            and len(copied["payload"]) != copied["object"].size_bytes
        ):
            raise GCSCatalogError("Catalog source size does not match its exact bytes")
        result = family(**copied)
        if family is GCSCatalogSimulationProfile and (
            type(value.profile_sha256) is not str or value.profile_sha256 != result.profile_sha256
        ):
            raise GCSCatalogError("Simulation profile no longer matches its fixed source binding")
        return result
    except (AttributeError, TypeError, ValueError) as exc:
        if isinstance(exc, GCSCatalogError):
            raise
        raise GCSCatalogError("Catalog value does not reconstruct") from exc


def _domain_body(domain: GCSCatalogDomain) -> dict[str, str]:
    return {item.name: getattr(domain, item.name) for item in fields(GCSCatalogDomain)}


def _profile_body(profile: GCSCatalogSimulationProfile) -> dict[str, object]:
    return {
        "catalog": _domain_body(profile.catalog),
        "ledger": _domain_body(profile.ledger),
        "simulation_started_at": profile.simulation_started_at,
        "simulation_use_until": profile.simulation_use_until,
        "retention_period_seconds": profile.retention_period_seconds,
        "environment_class": ENVIRONMENT_CLASS,
        "protection_scope": "fixed_finite_reference_simulation_only",
        "identity_assurance": "caller_declared_not_provider_authenticated",
        "effects": dict(_EFFECTS),
    }


def _callback_request_snapshot(request) -> tuple:
    """Retain only validated primitive values, not mutable descriptor objects."""

    values = []
    for item in fields(type(request)):
        value = getattr(request, item.name)
        if item.name == "descriptor":
            value = tuple(getattr(value, field.name) for field in fields(CatalogObjectDescriptor))
        elif item.name == "observed_at":
            value = (
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
                value.fold,
            )
        values.append(value)
    return tuple(values)


def _invoke_owned_request_callback(operation, request, family):
    """Validate delivery ownership before success or error reconciliation."""

    if family not in (GCSCatalogReadRequest, GCSCatalogWriteRequest):
        raise GCSCatalogError("Unsupported catalog transport request family")
    captured = _owned(request, family)
    expected = _callback_request_snapshot(captured)
    delivered = _owned(captured, family)
    try:
        return operation(delivered)
    finally:
        try:
            observed = _owned(delivered, family)
            unchanged = _callback_request_snapshot(observed) == expected
        except (AttributeError, TypeError, ValueError) as exc:
            raise GCSCatalogError(
                "Catalog transport request changed; outcome is unconfirmed, with no automatic retry"
            ) from exc
        if not unchanged:
            raise GCSCatalogError(
                "Catalog transport request changed; outcome is unconfirmed, with no automatic retry"
            )


class GCSImmutableCatalogObjectProvider:
    """D012 catalog behavior within one explicitly bounded synthetic protection window."""

    environment_class = ENVIRONMENT_CLASS

    def __init__(
        self,
        transport: GCSCatalogTransport,
        profile: GCSCatalogSimulationProfile,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._profile = _owned(profile, GCSCatalogSimulationProfile)
        self._profile_sha256 = self._profile.profile_sha256
        if not callable(clock):
            raise GCSCatalogError("An explicit aware UTC clock is required")
        if (
            type(getattr(transport, "environment_class", None)) is not str
            or transport.environment_class != ENVIRONMENT_CLASS
            or any(
                not callable(getattr(transport, name, None))
                for name in ("read_bucket", "read_object_metadata", "read_object", "write_object")
            )
        ):
            raise GCSCatalogError("An explicit complete synthetic catalog transport is required")
        self._transport, self._clock = transport, clock
        self._confirmed: dict[str, GCSCatalogObjectObservation] = {}
        self._active(self._profile)

    def _active(self, profile: GCSCatalogSimulationProfile) -> datetime:
        now = self._clock()
        _utc(now)
        if (
            not _instant(profile.simulation_started_at)
            <= now
            < _instant(profile.simulation_use_until)
        ):
            raise GCSCatalogError("The fixed simulation use horizon is not active")
        return now

    def _current_profile(self, descriptor=None) -> tuple[GCSCatalogSimulationProfile, datetime]:
        profile = _owned(self._profile, GCSCatalogSimulationProfile)
        if type(self._profile_sha256) is not str or profile.profile_sha256 != self._profile_sha256:
            raise GCSCatalogError("The mapping's original simulation profile was substituted")
        if descriptor is not None and (
            descriptor.namespace_id != profile.catalog.namespace_id
            or descriptor.failure_domain_id != profile.catalog.failure_domain_id
        ):
            raise GCSCatalogError("Catalog request is outside the explicit source/profile binding")
        now = self._active(profile)
        if (
            type(getattr(self._transport, "environment_class", None)) is not str
            or self._transport.environment_class != ENVIRONMENT_CLASS
        ):
            raise GCSCatalogError("The transport's simulation boundary changed")
        observed = _owned(
            self._transport.read_bucket(profile.catalog.bucket, observed_at=now),
            GCSCatalogBucketObservation,
        )
        if (
            observed.domain != profile.catalog
            or observed.observed_at != now
            or not observed.is_current
            or observed.versioning_enabled
            or not observed.retention_policy_locked
            or observed.retention_period_seconds != profile.retention_period_seconds
            or observed.default_event_based_hold
            or observed.object_retention_enabled
        ):
            raise GCSCatalogError(
                "Complete current bucket evidence does not match the supported profile"
            )
        self._active(profile)
        return profile, now

    def _capacity(self, object_id: str) -> None:
        if object_id not in self._confirmed and len(self._confirmed) >= MAXIMUM_CONFIRMED_OBJECTS:
            raise GCSCatalogError("The process-local confirmed identity bound is exhausted")

    def _validate_observation(self, observed, profile, name, at):
        observed = _owned(observed, GCSCatalogObjectObservation)
        descriptor = observed.descriptor
        if (
            observed.bucket != profile.catalog.bucket
            or observed.object_name != name
            or name != "catalog/" + descriptor.object_id
            or descriptor.namespace_id != profile.catalog.namespace_id
            or descriptor.failure_domain_id != profile.catalog.failure_domain_id
            or observed.observed_at != at
            or not observed.is_current
            or observed.temporary_hold
            or observed.event_based_hold
            or observed.retention_mode != "bucket_policy"
            or _instant(observed.retention_until) < _instant(profile.simulation_use_until)
        ):
            raise GCSCatalogError("Object identity, mode or fixed-horizon protection is unverified")
        self._active(profile)
        previous = self._confirmed.get(descriptor.object_id)
        if previous is not None:
            previous = _owned(previous, GCSCatalogObjectObservation)
        if previous is not None and any(
            getattr(previous, item.name) != getattr(observed, item.name)
            for item in fields(GCSCatalogObjectObservation)
            if item.name != "observed_at"
        ):
            raise GCSCatalogError("A confirmed catalog version was changed or recreated")
        return observed

    def _metadata(self, profile, name, at):
        raw = self._transport.read_object_metadata(profile.catalog.bucket, name, observed_at=at)
        if raw is None:
            if name.removeprefix("catalog/") in self._confirmed:
                raise GCSCatalogError("A previously confirmed catalog identity disappeared")
            return None
        return self._validate_observation(raw, profile, name, at)

    def _read(self, observed, profile):
        request = GCSCatalogReadRequest(
            observed.bucket,
            observed.object_name,
            observed.generation,
            observed.metageneration,
            observed.descriptor,
            observed.observed_at,
        )
        try:
            result = _owned(
                _invoke_owned_request_callback(
                    self._transport.read_object, request, GCSCatalogReadRequest
                ),
                GCSCatalogObjectRead,
            )
        except GCSPreconditionFailed as exc:
            raise GCSCatalogError("Pinned catalog snapshot changed during confirmation") from exc
        if result.observation != observed or _digest(result.payload) != observed.descriptor.sha256:
            raise GCSCatalogError(
                "Pinned bytes or metadata substitute the confirmed catalog object"
            )
        self._active(profile)
        return result.payload

    def _remember(self, observed):
        self._confirmed[observed.descriptor.object_id] = _owned(
            observed, GCSCatalogObjectObservation
        )

    @staticmethod
    def _deny(request):
        raise ProviderPolicyRejection(
            "immutable_catalog_overwrite",
            request.request_id,
            provider_subject_sha256(request.object),
        )

    def put_sha256_object(self, request: CatalogObjectPutRequest) -> CatalogObjectPutReceipt:
        request = _owned(request, CatalogObjectPutRequest)
        descriptor = request.object
        self._capacity(descriptor.object_id)
        profile, at = self._current_profile(descriptor)
        name = "catalog/" + descriptor.object_id
        observed = self._metadata(profile, name, at)
        status = "already_present_same_digest"
        if observed is None:
            status = "created"
            write = GCSCatalogWriteRequest(
                request.request_id, profile.catalog.bucket, name, descriptor, request.payload, at
            )
            try:
                observed = _invoke_owned_request_callback(
                    self._transport.write_object, write, GCSCatalogWriteRequest
                )
            except GCSAmbiguousWrite as exc:
                raise GCSCatalogError(
                    "Catalog write outcome is unconfirmed; no automatic retry"
                ) from exc
            except GCSPreconditionFailed:
                status = "already_present_same_digest"
                observed = self._metadata(profile, name, at)
                if observed is None:
                    raise GCSCatalogError(
                        "Create precondition outcome cannot be confirmed"
                    ) from None
            observed = self._validate_observation(observed, profile, name, at)
        payload = self._read(observed, profile)
        if observed.descriptor != descriptor or payload != request.payload:
            if status == "already_present_same_digest":
                self._deny(request)
            raise GCSCatalogError("Write acknowledgement substitutes the catalog source")
        self._current_profile()
        self._remember(observed)
        return _owned(
            CatalogObjectPutReceipt(request.request_id, descriptor, status, True),
            CatalogObjectPutReceipt,
        )

    def read_sha256_object(self, request: CatalogObjectReadRequest) -> CatalogObjectReadReceipt:
        request = _owned(request, CatalogObjectReadRequest)
        self._capacity(request.object_id)
        profile, at = self._current_profile()
        observed = self._metadata(profile, "catalog/" + request.object_id, at)
        if observed is None:
            raise GCSCatalogError("The requested catalog identity is unavailable")
        payload = self._read(observed, profile)
        if observed.descriptor.sha256 != request.expected_sha256:
            raise GCSCatalogError("Catalog bytes do not match the requested SHA-256")
        self._current_profile()
        self._remember(observed)
        return _owned(
            CatalogObjectReadReceipt(request.request_id, observed.descriptor, payload, True),
            CatalogObjectReadReceipt,
        )


__all__ = [
    "ENVIRONMENT_CLASS",
    "GCSCatalogError",
    "GCSCatalogDomain",
    "GCSCatalogSimulationProfile",
    "GCSCatalogBucketObservation",
    "GCSCatalogObjectObservation",
    "GCSCatalogReadRequest",
    "GCSCatalogObjectRead",
    "GCSCatalogWriteRequest",
    "GCSCatalogTransport",
    "GCSImmutableCatalogObjectProvider",
    "MAXIMUM_OBJECT_BYTES",
    "MAXIMUM_CONFIRMED_OBJECTS",
]
