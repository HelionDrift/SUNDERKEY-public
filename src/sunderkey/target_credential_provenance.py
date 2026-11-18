"""Pure source-derived target credential provenance, without credential use.

Source reconstruction checks descriptive metadata, not issuance, consent,
mapping-attestation authenticity, current permission, or available lease uses.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .credential_broker_contracts import (
    CredentialDescriptor,
    CredentialLease,
    LeaseMode,
    ProviderAdapter,
)
from .target_authentication_adapter_contracts import (
    AUTHENTICATION_MODE_PROFILES,
    CREDENTIAL_TRANSPORT_RE,
    AuthenticationFactor,
    AuthenticationMode,
    AuthenticationOperation,
    AuthenticationProfileEvidence,
    AuthenticationProtocol,
    ContentAddressBinding,
    CredentialLeaseMode,
    ExecutionEnvironment,
    FlowStage,
    LifecycleObligation,
    PrincipalTopology,
    SessionCarrier,
    TargetAuthenticationContractError,
    TargetAuthenticationProviderBinding,
    TargetCredentialProvenance,
    _digest,
    _timestamp,
    canonical_json,
    parse_target_authentication_provider_binding,
    parse_target_credential_provenance,
    transport_credential_reference_sha256,
)

MAX_DOCUMENT_BYTES = 1_048_576
MAX_DOCUMENT_NODES = 8192
MAX_DOCUMENT_DEPTH = 12
MAX_STRING_BYTES = 512
MAX_NATIVE_INTEGER = (1 << 63) - 1

_WRAPPER_FAMILIES = frozenset(
    {
        ProviderAdapter,
        CredentialDescriptor,
        CredentialLease,
        AuthenticationProfileEvidence,
        ContentAddressBinding,
        TargetAuthenticationProviderBinding,
        TargetCredentialProvenance,
    }
)
_SPECIAL_FIELDS = MappingProxyType(
    {
        (CredentialDescriptor, "adapter"): ProviderAdapter,
        (CredentialLease, "lease_mode"): LeaseMode,
        (AuthenticationProfileEvidence, "mode"): AuthenticationMode,
        (AuthenticationProfileEvidence, "protocol"): AuthenticationProtocol,
        (AuthenticationProfileEvidence, "carrier"): SessionCarrier,
        (AuthenticationProfileEvidence, "topology"): PrincipalTopology,
        (TargetAuthenticationProviderBinding, "execution_environment"): ExecutionEnvironment,
        (TargetCredentialProvenance, "provider_binding"): ContentAddressBinding,
        (TargetCredentialProvenance, "factor"): AuthenticationFactor,
        (TargetCredentialProvenance, "lease_mode"): CredentialLeaseMode,
    }
)
_TUPLE_FIELDS = MappingProxyType(
    {
        (CredentialDescriptor, "allowed_target_refs"): (str, 100),
        (CredentialDescriptor, "allowed_technique_refs"): (str, 100),
        (CredentialDescriptor, "allowed_purpose_refs"): (str, 100),
        (CredentialDescriptor, "allowed_scope_refs"): (str, 100),
        (CredentialDescriptor, "allowed_modes"): (LeaseMode, len(LeaseMode)),
        (CredentialLease, "scope_refs"): (str, 100),
        (AuthenticationProfileEvidence, "factors"): (
            AuthenticationFactor,
            len(AuthenticationFactor),
        ),
        (AuthenticationProfileEvidence, "successful_flow_stages"): (FlowStage, len(FlowStage)),
        (AuthenticationProfileEvidence, "lifecycle_obligations"): (
            LifecycleObligation,
            len(LifecycleObligation),
        ),
        (TargetAuthenticationProviderBinding, "supported_profiles"): (
            AuthenticationProfileEvidence,
            len(AUTHENTICATION_MODE_PROFILES),
        ),
        (TargetAuthenticationProviderBinding, "supported_operations"): (
            AuthenticationOperation,
            len(AuthenticationOperation),
        ),
    }
)
_INTEGER_FIELDS = frozenset(
    {"max_lease_ttl_seconds", "max_uses_per_lease", "max_uses", "lease_use_number"}
)
_NULLABLE_FIELDS = frozenset(
    {(CredentialLease, "session_ref"), (CredentialLease, "renewal_of_lease_sha256")}
)


class TargetCredentialProvenanceSourceError(TargetAuthenticationContractError):
    """Invalid supplied sources or a provenance document that does not replay."""


def _string(value: Any) -> None:
    if type(value) is not str or len(value) > MAX_STRING_BYTES:
        raise TargetCredentialProvenanceSourceError("metadata requires bounded native strings")
    if any(not 32 <= ord(character) <= 126 for character in value):
        raise TargetCredentialProvenanceSourceError("metadata requires printable ASCII strings")


def _integer(value: Any) -> None:
    if type(value) is not int or not -MAX_NATIVE_INTEGER <= value <= MAX_NATIVE_INTEGER:
        raise TargetCredentialProvenanceSourceError("metadata requires bounded native integers")


def _native_document(raw: Any) -> dict[str, Any]:
    """Detach and charge every occurrence before serialization or new hashing."""

    remaining = MAX_DOCUMENT_BYTES
    nodes = 0

    def charge(size: int) -> None:
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise TargetCredentialProvenanceSourceError("metadata exceeds its document byte bound")

    def string(value: str) -> str:
        if len(value) > MAX_STRING_BYTES or len(value) > remaining:
            raise TargetCredentialProvenanceSourceError("metadata string exceeds its byte bound")
        charge(2)
        for character in value:
            if not 32 <= ord(character) <= 126:
                raise TargetCredentialProvenanceSourceError("metadata requires printable ASCII")
            charge(2 if character in {'"', "\\"} else 1)
        return value

    def visit(value: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise TargetCredentialProvenanceSourceError("metadata exceeds its structure bound")
        if type(value) is dict:
            if len(value) > MAX_DOCUMENT_NODES or any(type(key) is not str for key in value):
                raise TargetCredentialProvenanceSourceError("metadata requires bounded native keys")
            charge(2 + len(value) + max(0, len(value) - 1))
            result = {}
            for key, item in value.items():
                string(key)
                result[key] = visit(item, depth + 1)
            return result
        if type(value) is list:
            if len(value) > MAX_DOCUMENT_NODES:
                raise TargetCredentialProvenanceSourceError("metadata array exceeds its bound")
            charge(2 + max(0, len(value) - 1))
            return [visit(item, depth + 1) for item in value]
        if type(value) is str:
            return string(value)
        if type(value) is int:
            _integer(value)
            charge(len(str(value)))
            return value
        if value is None:
            charge(4)
            return None
        raise TargetCredentialProvenanceSourceError("metadata contains a non-native value")

    if type(raw) is not dict:
        raise TargetCredentialProvenanceSourceError("metadata must be a native document")
    return visit(raw, 0)


def _capture_document(value: Any, family: Any) -> dict[str, Any]:
    """Check exact normalized slots before invoking the existing serializer."""

    nodes = 0

    def check(item: Any, expected: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise TargetCredentialProvenanceSourceError(
                "source wrapper exceeds its structure bound"
            )
        if type(item) is not expected:
            raise TargetCredentialProvenanceSourceError("source wrapper has a non-native field")
        if expected in _WRAPPER_FAMILIES:
            for slot in fields(expected):
                try:
                    child = getattr(item, slot.name)
                except AttributeError as exc:
                    raise TargetCredentialProvenanceSourceError(
                        "source wrapper is incomplete"
                    ) from exc
                key = (expected, slot.name)
                if key in _TUPLE_FIELDS:
                    element, maximum = _TUPLE_FIELDS[key]
                    if type(child) is not tuple or len(child) > maximum:
                        raise TargetCredentialProvenanceSourceError(
                            "source wrapper requires a bounded native tuple"
                        )
                    nodes += 1
                    for entry in child:
                        check(entry, element, depth + 2)
                elif key in _NULLABLE_FIELDS and child is None:
                    check(child, type(None), depth + 1)
                else:
                    selected = _SPECIAL_FIELDS.get(
                        key, int if slot.name in _INTEGER_FIELDS else str
                    )
                    check(child, selected, depth + 1)
        elif expected is str:
            _string(item)
        elif expected is int:
            _integer(item)

    check(value, family, 0)
    try:
        return _native_document(value.to_dict())
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, TargetCredentialProvenanceSourceError):
            raise
        raise TargetCredentialProvenanceSourceError("source document capture failed") from exc


def _replay(raw: dict[str, Any], family: Any) -> Any:
    """Reconstruct the unchanged source domain and compare the full document."""

    if family is CredentialDescriptor:
        expected = {slot.name for slot in fields(CredentialDescriptor)}
        if set(raw) != expected:
            raise TargetCredentialProvenanceSourceError("descriptor fields do not reproduce")
        adapter = raw["adapter"]
        if type(adapter) is not dict or set(adapter) != {
            "provider_ref",
            "adapter_ref",
            "adapter_version",
        }:
            raise TargetCredentialProvenanceSourceError(
                "descriptor adapter fields do not reproduce"
            )
        arguments = {slot.name: raw[slot.name] for slot in fields(family) if slot.init}
        arguments["adapter"] = ProviderAdapter(**adapter)
        arguments["allowed_modes"] = tuple(arguments["allowed_modes"])
        result = CredentialDescriptor(**arguments)
    elif family is CredentialLease:
        if set(raw) != {slot.name for slot in fields(CredentialLease)}:
            raise TargetCredentialProvenanceSourceError("lease fields do not reproduce")
        result = CredentialLease(
            **{slot.name: raw[slot.name] for slot in fields(family) if slot.init}
        )
    elif family is TargetAuthenticationProviderBinding:
        result = parse_target_authentication_provider_binding(canonical_json(raw))
    else:
        result = parse_target_credential_provenance(canonical_json(raw))
    if canonical_json(result.to_dict()) != canonical_json(raw):
        raise TargetCredentialProvenanceSourceError("source document does not reproduce exactly")
    return result


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _transport_reference(value: Any) -> None:
    _string(value)
    if CREDENTIAL_TRANSPORT_RE.fullmatch(value) is None:
        raise TargetCredentialProvenanceSourceError(
            "runtime reference must use the credref namespace"
        )


def _declarations(
    factor: Any,
    lease_use_number: Any,
    transport_credential_ref: Any,
    mapping_attestation_sha256: Any,
    created_at: Any,
) -> None:
    if type(factor) is not AuthenticationFactor:
        raise TargetCredentialProvenanceSourceError("factor must be an exact AuthenticationFactor")
    _integer(lease_use_number)
    if not 1 <= lease_use_number <= 100:
        raise TargetCredentialProvenanceSourceError(
            "lease use number is outside its contract bound"
        )
    _transport_reference(transport_credential_ref)
    _string(mapping_attestation_sha256)
    _digest(mapping_attestation_sha256, "mapping_attestation_sha256")
    _string(created_at)
    _timestamp(created_at, "created_at")


def _prepare(
    descriptor: CredentialDescriptor,
    lease: CredentialLease,
    provider: TargetAuthenticationProviderBinding,
    *,
    factor: AuthenticationFactor,
    lease_use_number: int,
    transport_credential_ref: str,
    mapping_attestation_sha256: str,
    created_at: str,
) -> TargetCredentialProvenance:
    for name, actual, expected in (
        ("descriptor", lease.descriptor_sha256, descriptor.descriptor_sha256),
        ("tenant", lease.tenant_ref, descriptor.tenant_ref),
        ("assessment", lease.assessment_ref, descriptor.assessment_ref),
        ("principal", lease.subject_principal_ref, descriptor.subject_principal_ref),
    ):
        if actual != expected:
            raise TargetCredentialProvenanceSourceError(f"lease and descriptor {name} mismatch")
    for name, actual, allowed in (
        ("target", lease.target_ref, descriptor.allowed_target_refs),
        ("technique", lease.technique_ref, descriptor.allowed_technique_refs),
        ("purpose", lease.purpose_ref, descriptor.allowed_purpose_refs),
    ):
        if actual not in allowed:
            raise TargetCredentialProvenanceSourceError(f"lease {name} exceeds the descriptor")
    if not set(lease.scope_refs).issubset(descriptor.allowed_scope_refs):
        raise TargetCredentialProvenanceSourceError("lease scopes exceed the descriptor")
    if lease.lease_mode not in descriptor.allowed_modes:
        raise TargetCredentialProvenanceSourceError("lease mode exceeds the descriptor")
    if lease.max_uses > descriptor.max_uses_per_lease or lease_use_number > lease.max_uses:
        raise TargetCredentialProvenanceSourceError("lease or declared use exceeds source ceilings")
    issued, expires = _instant(lease.issued_at), _instant(lease.expires_at)
    if not _instant(descriptor.created_at) <= issued < expires <= _instant(descriptor.expires_at):
        raise TargetCredentialProvenanceSourceError("lease window exceeds the descriptor")
    if (expires - issued).total_seconds() > descriptor.max_lease_ttl_seconds:
        raise TargetCredentialProvenanceSourceError("lease TTL exceeds the descriptor")
    if not issued <= _instant(created_at) < expires:
        raise TargetCredentialProvenanceSourceError(
            "provenance creation is outside the lease window"
        )
    if not _instant(provider.issued_at) <= _instant(created_at) < _instant(provider.expires_at):
        raise TargetCredentialProvenanceSourceError(
            "provenance creation is outside the provider window"
        )
    if not any(factor in profile.factors for profile in provider.supported_profiles):
        raise TargetCredentialProvenanceSourceError(
            "factor is absent from declared provider profiles"
        )
    mode = (
        CredentialLeaseMode.ONE_TIME
        if lease.lease_mode is LeaseMode.ONE_TIME
        else CredentialLeaseMode.SESSION_BOUND
    )
    return TargetCredentialProvenance(
        provider_binding=ContentAddressBinding(provider.binding_id, provider.binding_sha256),
        principal_ref=lease.subject_principal_ref,
        factor=factor,
        descriptor_id=descriptor.descriptor_id,
        descriptor_sha256=descriptor.descriptor_sha256,
        lease_id=lease.lease_id,
        lease_sha256=lease.lease_sha256,
        lease_mode=mode,
        lease_issued_at=lease.issued_at,
        lease_expires_at=lease.expires_at,
        lease_use_number=lease_use_number,
        source_credential_ref=descriptor.credential_ref,
        transport_credential_ref_sha256=transport_credential_reference_sha256(
            transport_credential_ref
        ),
        mapping_attestation_sha256=mapping_attestation_sha256,
        created_at=created_at,
    )


def prepare_target_credential_provenance(
    *,
    descriptor: CredentialDescriptor,
    lease: CredentialLease,
    provider: TargetAuthenticationProviderBinding,
    factor: AuthenticationFactor,
    lease_use_number: int,
    transport_credential_ref: str,
    mapping_attestation_sha256: str,
    created_at: str,
) -> TargetCredentialProvenance:
    """Derive an unchanged TACP from supplied metadata, without issuing or using a lease."""

    try:
        _declarations(
            factor,
            lease_use_number,
            transport_credential_ref,
            mapping_attestation_sha256,
            created_at,
        )
        descriptor_raw = _capture_document(descriptor, CredentialDescriptor)
        lease_raw = _capture_document(lease, CredentialLease)
        provider_raw = _capture_document(provider, TargetAuthenticationProviderBinding)
        return _prepare(
            _replay(descriptor_raw, CredentialDescriptor),
            _replay(lease_raw, CredentialLease),
            _replay(provider_raw, TargetAuthenticationProviderBinding),
            factor=factor,
            lease_use_number=lease_use_number,
            transport_credential_ref=transport_credential_ref,
            mapping_attestation_sha256=mapping_attestation_sha256,
            created_at=created_at,
        )
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, TargetCredentialProvenanceSourceError):
            raise
        raise TargetCredentialProvenanceSourceError(
            "credential provenance source validation failed"
        ) from exc


def verify_target_credential_provenance_sources(
    *,
    provenance: TargetCredentialProvenance,
    descriptor: CredentialDescriptor,
    lease: CredentialLease,
    provider: TargetAuthenticationProviderBinding,
    transport_credential_ref: str,
) -> TargetCredentialProvenance:
    """Replay historical source metadata and return a detached TACP, not permission."""

    try:
        _transport_reference(transport_credential_ref)
        provenance_raw = _capture_document(provenance, TargetCredentialProvenance)
        descriptor_raw = _capture_document(descriptor, CredentialDescriptor)
        lease_raw = _capture_document(lease, CredentialLease)
        provider_raw = _capture_document(provider, TargetAuthenticationProviderBinding)
        owned = _replay(provenance_raw, TargetCredentialProvenance)
        expected = _prepare(
            _replay(descriptor_raw, CredentialDescriptor),
            _replay(lease_raw, CredentialLease),
            _replay(provider_raw, TargetAuthenticationProviderBinding),
            factor=owned.factor,
            lease_use_number=owned.lease_use_number,
            transport_credential_ref=transport_credential_ref,
            mapping_attestation_sha256=owned.mapping_attestation_sha256,
            created_at=owned.created_at,
        )
        if canonical_json(expected.to_dict()) != canonical_json(provenance_raw):
            raise TargetCredentialProvenanceSourceError(
                "provenance does not match its exact sources"
            )
        return expected
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, TargetCredentialProvenanceSourceError):
            raise
        raise TargetCredentialProvenanceSourceError(
            "credential provenance source replay failed"
        ) from exc


__all__ = [
    "TargetCredentialProvenanceSourceError",
    "prepare_target_credential_provenance",
    "verify_target_credential_provenance_sources",
]
