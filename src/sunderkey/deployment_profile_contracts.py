"""Deterministic deployment profile and restricted worker contracts.

The records in this module describe deployment expectations and evaluate
caller supplied metadata. They do not deploy workers, create signatures,
resolve credentials, access files, contact networks, authorize target action,
or change qualification state.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

SCHEMA_VERSION = 1
MAX_ITEMS = 256
MAX_OFFLINE_SECONDS = 604_800

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "deployment": "none",
        "filesystem_mutation": "none",
        "network": "none",
        "qualification": "none",
        "signature_generation": "none",
        "target_action": "none",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
REFERENCE_RE = re.compile(
    r"(?:profileref|workerref|bundleref|signatureref|trustref|componentref|"
    r"toolref|credentialref|storeref|exportref|manifestref|snapshotref|"
    r"stopref|cleanupref|restorationref|scoperef|assessmentref|tenantref|"
    r"requestref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|"
    r"[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key|cookie|otp)\s*[:=])",
    re.IGNORECASE,
)


class DeploymentProfileError(ValueError):
    """Raised when a deployment profile contract fails closed."""


class DeploymentKind(StrEnum):
    MANAGED_SERVICE = "managed_service"
    CUSTOMER_HOSTED_WORKER = "customer_hosted_worker"
    PRIVATE_CLOUD = "private_cloud"
    RESTRICTED_NETWORK = "restricted_network"
    DISCONNECTED_OPERATION = "disconnected_operation"


class IngressMode(StrEnum):
    MANAGED_CONTROL_PLANE = "managed_control_plane"
    MUTUAL_TLS_CONTROL_PLANE = "mutual_tls_control_plane"
    PRIVATE_CONTROL_PLANE = "private_control_plane"
    CUSTOMER_RELAY = "customer_relay"
    SIGNED_REMOVABLE_MEDIA = "signed_removable_media"


class EgressMode(StrEnum):
    RESTRICTED_ALLOWLIST = "restricted_allowlist"
    CUSTOMER_PROXY = "customer_proxy"
    PRIVATE_ALLOWLIST = "private_allowlist"
    CUSTOMER_RELAY = "customer_relay"
    EVIDENCE_REMOVABLE_MEDIA = "evidence_removable_media"


class CredentialDeliveryMode(StrEnum):
    NONE = "none"
    BROKERED_EPHEMERAL_REFERENCE = "brokered_ephemeral_reference"
    CUSTOMER_INJECTED_REFERENCE = "customer_injected_reference"
    OFFLINE_SEALED_REFERENCE = "offline_sealed_reference"


class UpdateChannel(StrEnum):
    MANAGED_SIGNED_CHANNEL = "managed_signed_channel"
    CUSTOMER_SIGNED_MIRROR = "customer_signed_mirror"
    PRIVATE_SIGNED_MIRROR = "private_signed_mirror"
    RELAYED_SIGNED_BUNDLE = "relayed_signed_bundle"
    OFFLINE_SIGNED_BUNDLE = "offline_signed_bundle"


class Capability(StrEnum):
    PASSIVE_DISCOVERY = "passive_discovery"
    ACTIVE_VALIDATION = "active_validation"
    API_ASSESSMENT = "api_assessment"
    BROWSER_ASSESSMENT = "browser_assessment"
    CLOUD_CONTROL_PLANE = "cloud_control_plane"
    EVIDENCE_COLLECTION = "evidence_collection"
    CLEANUP_VERIFICATION = "cleanup_verification"
    RESTORATION_VERIFICATION = "restoration_verification"


class AdmissionStatus(StrEnum):
    DENIED = "denied"
    CONTRACT_COMPATIBLE_UNVERIFIED = "contract_compatible_unverified"


NETWORK_POLICY = MappingProxyType(
    {
        DeploymentKind.MANAGED_SERVICE: (
            IngressMode.MANAGED_CONTROL_PLANE,
            EgressMode.RESTRICTED_ALLOWLIST,
            UpdateChannel.MANAGED_SIGNED_CHANNEL,
        ),
        DeploymentKind.CUSTOMER_HOSTED_WORKER: (
            IngressMode.MUTUAL_TLS_CONTROL_PLANE,
            EgressMode.CUSTOMER_PROXY,
            UpdateChannel.CUSTOMER_SIGNED_MIRROR,
        ),
        DeploymentKind.PRIVATE_CLOUD: (
            IngressMode.PRIVATE_CONTROL_PLANE,
            EgressMode.PRIVATE_ALLOWLIST,
            UpdateChannel.PRIVATE_SIGNED_MIRROR,
        ),
        DeploymentKind.RESTRICTED_NETWORK: (
            IngressMode.CUSTOMER_RELAY,
            EgressMode.CUSTOMER_RELAY,
            UpdateChannel.RELAYED_SIGNED_BUNDLE,
        ),
        DeploymentKind.DISCONNECTED_OPERATION: (
            IngressMode.SIGNED_REMOVABLE_MEDIA,
            EgressMode.EVIDENCE_REMOVABLE_MEDIA,
            UpdateChannel.OFFLINE_SIGNED_BUNDLE,
        ),
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret screening."""

    _validate_json(value, "value")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DeploymentProfileError("value cannot be serialized") from exc
    if SECRET_RE.search(encoded):
        raise DeploymentProfileError("raw secret or credential material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 12:
        raise DeploymentProfileError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and SECRET_RE.search(value):
            raise DeploymentProfileError(f"{label} contains raw secret material")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DeploymentProfileError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth + 1)
        return
    raise DeploymentProfileError(f"{label} has an unsupported value")


def _exact(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise DeploymentProfileError(f"{label} fields are invalid")
    return raw


def _reference(value: Any, label: str, namespace: str | None = None) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise DeploymentProfileError(f"{label} must be an opaque reference")
    if namespace is not None and not value.startswith(namespace + ":"):
        raise DeploymentProfileError(f"{label} must use the {namespace} namespace")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DeploymentProfileError(f"{label} must be a SHA-256 content address")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise DeploymentProfileError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise DeploymentProfileError(f"{label} must be valid") from exc


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise DeploymentProfileError(f"{label} must be an exact version")
    if value.lower() in {"latest", "stable", "current", "default", "auto"}:
        raise DeploymentProfileError(f"{label} must not be a moving alias")
    return value


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DeploymentProfileError(f"{label} must be between 1 and {maximum}")
    return value


def _bounded_unique(values: Sequence[Any], label: str, *, minimum: int = 1) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes)):
        raise DeploymentProfileError(f"{label} must be a sequence")
    result = tuple(values)
    try:
        unique_count = len(set(result))
    except TypeError as exc:
        raise DeploymentProfileError(f"{label} contains an invalid entry") from exc
    if not minimum <= len(result) <= MAX_ITEMS or len(result) != unique_count:
        raise DeploymentProfileError(f"{label} must be a bounded unique sequence")
    return result


def _enum_tuple(
    values: Sequence[Any], enum_type: type[StrEnum], label: str, *, minimum: int = 1
) -> tuple[Any, ...]:
    try:
        source = _bounded_unique(values, label, minimum=minimum)
        normalized = tuple(sorted((enum_type(item) for item in source), key=str))
    except (TypeError, ValueError) as exc:
        raise DeploymentProfileError(f"{label} contains an unsupported value") from exc
    return normalized


def _reference_tuple(
    values: Sequence[Any], label: str, namespace: str, *, minimum: int = 1
) -> tuple[str, ...]:
    normalized = tuple(
        _reference(item, f"{label} item", namespace)
        for item in _bounded_unique(values, label, minimum=minimum)
    )
    return tuple(sorted(normalized))


def _effects(raw: Any, label: str) -> None:
    if not isinstance(raw, Mapping) or dict(raw) != dict(NO_EFFECTS):
        raise DeploymentProfileError(f"{label} effects are invalid")


def _verify_address(
    raw: Mapping[str, Any], id_field: str, digest_field: str, prefix: str, domain: str
) -> None:
    body = {key: value for key, value in raw.items() if key not in {id_field, digest_field}}
    expected_id, expected_digest = _identity(prefix, domain, body)
    if raw[id_field] != expected_id or raw[digest_field] != expected_digest:
        raise DeploymentProfileError("record content address does not match content")


@dataclass(frozen=True, slots=True)
class VersionPin:
    component_ref: str
    exact_version: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "component_ref",
            _reference(self.component_ref, "component_ref", "componentref"),
        )
        object.__setattr__(self, "exact_version", _version(self.exact_version, "exact_version"))
        _digest(self.artifact_sha256, "artifact_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "component_ref": self.component_ref,
            "exact_version": self.exact_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> VersionPin:
        value = _exact(raw, {"artifact_sha256", "component_ref", "exact_version"}, "version pin")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class TrustRootPin:
    trust_root_ref: str
    public_material_sha256: str
    purposes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "trust_root_ref",
            _reference(self.trust_root_ref, "trust_root_ref", "trustref"),
        )
        _digest(self.public_material_sha256, "public_material_sha256")
        allowed = {"mission_bundle", "revocation_snapshot", "update_bundle", "evidence_export"}
        purposes = tuple(sorted(_bounded_unique(self.purposes, "purposes")))
        if any(not isinstance(item, str) or item not in allowed for item in purposes):
            raise DeploymentProfileError("trust root purpose is invalid")
        object.__setattr__(self, "purposes", purposes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_material_sha256": self.public_material_sha256,
            "purposes": list(self.purposes),
            "trust_root_ref": self.trust_root_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> TrustRootPin:
        value = _exact(
            raw,
            {"public_material_sha256", "purposes", "trust_root_ref"},
            "trust root pin",
        )
        return cls(
            value["trust_root_ref"],
            value["public_material_sha256"],
            tuple(value["purposes"]),
        )


@dataclass(frozen=True, slots=True)
class SignedMissionBundle:
    bundle_ref: str
    bundle_sha256: str
    signature_ref: str
    signing_trust_root_ref: str
    tenant_ref: str
    assessment_ref: str
    scope_ref: str
    scope_sha256: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("bundle_ref", "bundleref"),
            ("signature_ref", "signatureref"),
            ("signing_trust_root_ref", "trustref"),
            ("tenant_ref", "tenantref"),
            ("assessment_ref", "assessmentref"),
            ("scope_ref", "scoperef"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _digest(self.bundle_sha256, "bundle_sha256")
        _digest(self.scope_sha256, "scope_sha256")
        if _timestamp(self.expires_at, "expires_at") <= _timestamp(self.issued_at, "issued_at"):
            raise DeploymentProfileError("mission bundle expiry must follow issue time")

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_ref": self.assessment_ref,
            "bundle_ref": self.bundle_ref,
            "bundle_sha256": self.bundle_sha256,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "signature_ref": self.signature_ref,
            "signing_trust_root_ref": self.signing_trust_root_ref,
            "tenant_ref": self.tenant_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> SignedMissionBundle:
        value = _exact(
            raw,
            {
                "assessment_ref",
                "bundle_ref",
                "bundle_sha256",
                "expires_at",
                "issued_at",
                "scope_ref",
                "scope_sha256",
                "signature_ref",
                "signing_trust_root_ref",
                "tenant_ref",
            },
            "signed mission bundle",
        )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class CredentialConstraints:
    allowed_modes: tuple[CredentialDeliveryMode, ...]
    maximum_lease_seconds: int
    reference_only: bool = True
    prohibit_persistence: bool = True
    require_revocation_check: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_modes",
            _enum_tuple(self.allowed_modes, CredentialDeliveryMode, "allowed_modes"),
        )
        _positive(self.maximum_lease_seconds, "maximum_lease_seconds", 86_400)
        if not all(
            isinstance(value, bool)
            for value in (
                self.reference_only,
                self.prohibit_persistence,
                self.require_revocation_check,
            )
        ):
            raise DeploymentProfileError("credential constraint flags must be boolean")
        if (
            not self.reference_only
            or not self.prohibit_persistence
            or not self.require_revocation_check
        ):
            raise DeploymentProfileError("credential constraints must fail closed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_modes": [item.value for item in self.allowed_modes],
            "maximum_lease_seconds": self.maximum_lease_seconds,
            "prohibit_persistence": self.prohibit_persistence,
            "reference_only": self.reference_only,
            "require_revocation_check": self.require_revocation_check,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> CredentialConstraints:
        value = _exact(
            raw,
            {
                "allowed_modes",
                "maximum_lease_seconds",
                "prohibit_persistence",
                "reference_only",
                "require_revocation_check",
            },
            "credential constraints",
        )
        return cls(
            tuple(value["allowed_modes"]),
            value["maximum_lease_seconds"],
            value["reference_only"],
            value["prohibit_persistence"],
            value["require_revocation_check"],
        )


@dataclass(frozen=True, slots=True)
class EvidenceCustodyPolicy:
    evidence_store_ref: str
    export_manifest_ref: str
    export_trust_root_ref: str
    encrypted_at_rest: bool = True
    export_required: bool = True
    local_deletion_after_verified_export: bool = True

    def __post_init__(self) -> None:
        for name, namespace in (
            ("evidence_store_ref", "storeref"),
            ("export_manifest_ref", "manifestref"),
            ("export_trust_root_ref", "trustref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        flags = (
            self.encrypted_at_rest,
            self.export_required,
            self.local_deletion_after_verified_export,
        )
        if not all(isinstance(value, bool) for value in flags) or not all(flags):
            raise DeploymentProfileError("evidence custody and export requirements are mandatory")

    def to_dict(self) -> dict[str, Any]:
        return {
            "encrypted_at_rest": self.encrypted_at_rest,
            "evidence_store_ref": self.evidence_store_ref,
            "export_manifest_ref": self.export_manifest_ref,
            "export_required": self.export_required,
            "export_trust_root_ref": self.export_trust_root_ref,
            "local_deletion_after_verified_export": self.local_deletion_after_verified_export,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceCustodyPolicy:
        value = _exact(
            raw,
            {
                "encrypted_at_rest",
                "evidence_store_ref",
                "export_manifest_ref",
                "export_required",
                "export_trust_root_ref",
                "local_deletion_after_verified_export",
            },
            "evidence custody policy",
        )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class StopCleanupPolicy:
    stop_contract_ref: str
    cleanup_contract_ref: str
    restoration_contract_ref: str
    maximum_stop_ack_seconds: int
    stop_supported: bool = True
    cleanup_required: bool = True
    restoration_required: bool = True

    def __post_init__(self) -> None:
        for name, namespace in (
            ("stop_contract_ref", "stopref"),
            ("cleanup_contract_ref", "cleanupref"),
            ("restoration_contract_ref", "restorationref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _positive(self.maximum_stop_ack_seconds, "maximum_stop_ack_seconds", 300)
        flags = (self.stop_supported, self.cleanup_required, self.restoration_required)
        if not all(isinstance(value, bool) for value in flags) or not all(flags):
            raise DeploymentProfileError("stop, cleanup, and restoration support are mandatory")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cleanup_contract_ref": self.cleanup_contract_ref,
            "cleanup_required": self.cleanup_required,
            "maximum_stop_ack_seconds": self.maximum_stop_ack_seconds,
            "restoration_contract_ref": self.restoration_contract_ref,
            "restoration_required": self.restoration_required,
            "stop_contract_ref": self.stop_contract_ref,
            "stop_supported": self.stop_supported,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StopCleanupPolicy:
        value = _exact(
            raw,
            {
                "cleanup_contract_ref",
                "cleanup_required",
                "maximum_stop_ack_seconds",
                "restoration_contract_ref",
                "restoration_required",
                "stop_contract_ref",
                "stop_supported",
            },
            "stop cleanup policy",
        )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class DeploymentProfile:
    deployment_kind: DeploymentKind
    worker_ref: str
    ingress_mode: IngressMode
    egress_mode: EgressMode
    update_channel: UpdateChannel
    trust_roots: tuple[TrustRootPin, ...]
    version_pins: tuple[VersionPin, ...]
    supported_capabilities: tuple[Capability, ...]
    tool_allowlist: tuple[str, ...]
    credential_constraints: CredentialConstraints
    custody_policy: EvidenceCustodyPolicy
    stop_cleanup_policy: StopCleanupPolicy
    maximum_clock_skew_seconds: int
    maximum_offline_seconds: int
    profile_id: str = field(init=False)
    profile_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.deployment-profile.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "deployment_kind", DeploymentKind(self.deployment_kind))
        object.__setattr__(self, "ingress_mode", IngressMode(self.ingress_mode))
        object.__setattr__(self, "egress_mode", EgressMode(self.egress_mode))
        object.__setattr__(self, "update_channel", UpdateChannel(self.update_channel))
        object.__setattr__(
            self,
            "worker_ref",
            _reference(self.worker_ref, "worker_ref", "workerref"),
        )
        root_values = _bounded_unique(self.trust_roots, "trust_roots", minimum=2)
        if not all(isinstance(item, TrustRootPin) for item in root_values):
            raise DeploymentProfileError("trust_roots must contain trust root pins")
        roots = tuple(
            sorted(
                root_values,
                key=lambda item: item.trust_root_ref,
            )
        )
        if len({item.trust_root_ref for item in roots}) != len(roots):
            raise DeploymentProfileError("trust root references must be unique")
        purposes = {purpose for root in roots for purpose in root.purposes}
        required_purposes = {
            "mission_bundle",
            "revocation_snapshot",
            "update_bundle",
            "evidence_export",
        }
        if not required_purposes.issubset(purposes):
            raise DeploymentProfileError("required trust root purposes are not pinned")
        object.__setattr__(self, "trust_roots", roots)
        pin_values = _bounded_unique(self.version_pins, "version_pins", minimum=2)
        if not all(isinstance(item, VersionPin) for item in pin_values):
            raise DeploymentProfileError("version_pins must contain version pins")
        pins = tuple(
            sorted(
                pin_values,
                key=lambda item: item.component_ref,
            )
        )
        if len({item.component_ref for item in pins}) != len(pins):
            raise DeploymentProfileError("version pin components must be unique")
        object.__setattr__(self, "version_pins", pins)
        object.__setattr__(
            self,
            "supported_capabilities",
            _enum_tuple(self.supported_capabilities, Capability, "supported_capabilities"),
        )
        object.__setattr__(
            self,
            "tool_allowlist",
            _reference_tuple(self.tool_allowlist, "tool_allowlist", "toolref"),
        )
        if not isinstance(self.credential_constraints, CredentialConstraints):
            raise DeploymentProfileError("credential_constraints are invalid")
        if not isinstance(self.custody_policy, EvidenceCustodyPolicy):
            raise DeploymentProfileError("custody_policy is invalid")
        if not isinstance(self.stop_cleanup_policy, StopCleanupPolicy):
            raise DeploymentProfileError("stop_cleanup_policy is invalid")
        _positive(self.maximum_clock_skew_seconds, "maximum_clock_skew_seconds", 3_600)
        if (
            isinstance(self.maximum_offline_seconds, bool)
            or not isinstance(self.maximum_offline_seconds, int)
            or not 0 <= self.maximum_offline_seconds <= MAX_OFFLINE_SECONDS
        ):
            raise DeploymentProfileError("maximum_offline_seconds is invalid")
        expected = NETWORK_POLICY[self.deployment_kind]
        if (self.ingress_mode, self.egress_mode, self.update_channel) != expected:
            raise DeploymentProfileError("deployment kind contains a forbidden network claim")
        if self.deployment_kind is DeploymentKind.DISCONNECTED_OPERATION:
            if self.maximum_offline_seconds < 1:
                raise DeploymentProfileError(
                    "disconnected operation requires bounded offline validity"
                )
            allowed = {
                CredentialDeliveryMode.NONE,
                CredentialDeliveryMode.OFFLINE_SEALED_REFERENCE,
            }
            if not set(self.credential_constraints.allowed_modes).issubset(allowed):
                raise DeploymentProfileError(
                    "disconnected operation forbids online credential delivery"
                )
        elif self.maximum_offline_seconds != 0:
            raise DeploymentProfileError("connected deployment kinds cannot claim offline validity")
        root_refs = {item.trust_root_ref for item in roots}
        if self.custody_policy.export_trust_root_ref not in root_refs:
            raise DeploymentProfileError("evidence export trust root is not pinned")
        body = self._body()
        identity, digest = _identity("DPC", self.KIND, body)
        object.__setattr__(self, "profile_id", identity)
        object.__setattr__(self, "profile_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "credential_constraints": self.credential_constraints.to_dict(),
            "custody_policy": self.custody_policy.to_dict(),
            "deployment_kind": self.deployment_kind.value,
            "effects": dict(NO_EFFECTS),
            "egress_mode": self.egress_mode.value,
            "ingress_mode": self.ingress_mode.value,
            "kind": self.KIND,
            "maximum_clock_skew_seconds": self.maximum_clock_skew_seconds,
            "maximum_offline_seconds": self.maximum_offline_seconds,
            "schema_version": SCHEMA_VERSION,
            "stop_cleanup_policy": self.stop_cleanup_policy.to_dict(),
            "supported_capabilities": [item.value for item in self.supported_capabilities],
            "tool_allowlist": list(self.tool_allowlist),
            "trust_roots": [item.to_dict() for item in self.trust_roots],
            "update_channel": self.update_channel.value,
            "version_pins": [item.to_dict() for item in self.version_pins],
            "worker_ref": self.worker_ref,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DeploymentProfile:
        fields = {
            "credential_constraints",
            "custody_policy",
            "deployment_kind",
            "effects",
            "egress_mode",
            "ingress_mode",
            "kind",
            "maximum_clock_skew_seconds",
            "maximum_offline_seconds",
            "profile_id",
            "profile_sha256",
            "schema_version",
            "stop_cleanup_policy",
            "supported_capabilities",
            "tool_allowlist",
            "trust_roots",
            "update_channel",
            "version_pins",
            "worker_ref",
        }
        value = _exact(raw, fields, "deployment profile")
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise DeploymentProfileError("deployment profile kind or schema is invalid")
        _effects(value["effects"], "deployment profile")
        _verify_address(value, "profile_id", "profile_sha256", "DPC", cls.KIND)
        instance = cls(
            deployment_kind=value["deployment_kind"],
            worker_ref=value["worker_ref"],
            ingress_mode=value["ingress_mode"],
            egress_mode=value["egress_mode"],
            update_channel=value["update_channel"],
            trust_roots=tuple(TrustRootPin.from_dict(item) for item in value["trust_roots"]),
            version_pins=tuple(VersionPin.from_dict(item) for item in value["version_pins"]),
            supported_capabilities=tuple(value["supported_capabilities"]),
            tool_allowlist=tuple(value["tool_allowlist"]),
            credential_constraints=CredentialConstraints.from_dict(value["credential_constraints"]),
            custody_policy=EvidenceCustodyPolicy.from_dict(value["custody_policy"]),
            stop_cleanup_policy=StopCleanupPolicy.from_dict(value["stop_cleanup_policy"]),
            maximum_clock_skew_seconds=value["maximum_clock_skew_seconds"],
            maximum_offline_seconds=value["maximum_offline_seconds"],
        )
        if instance.to_dict() != dict(value):
            raise DeploymentProfileError("deployment profile is not canonical")
        return instance

    @classmethod
    def from_json(cls, document: str) -> DeploymentProfile:
        try:
            raw = json.loads(document)
        except (TypeError, json.JSONDecodeError) as exc:
            raise DeploymentProfileError("deployment profile JSON is invalid") from exc
        if canonical_json(raw) != document:
            raise DeploymentProfileError("deployment profile JSON is not canonical")
        return cls.from_dict(raw)


@dataclass(frozen=True, slots=True)
class RevocationSnapshot:
    snapshot_ref: str
    snapshot_sha256: str
    signature_ref: str
    signing_trust_root_ref: str
    captured_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("snapshot_ref", "snapshotref"),
            ("signature_ref", "signatureref"),
            ("signing_trust_root_ref", "trustref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _digest(self.snapshot_sha256, "snapshot_sha256")
        if _timestamp(self.expires_at, "expires_at") <= _timestamp(self.captured_at, "captured_at"):
            raise DeploymentProfileError("revocation snapshot expiry must follow capture time")

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "expires_at": self.expires_at,
            "signature_ref": self.signature_ref,
            "signing_trust_root_ref": self.signing_trust_root_ref,
            "snapshot_ref": self.snapshot_ref,
            "snapshot_sha256": self.snapshot_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RevocationSnapshot:
        value = _exact(
            raw,
            {
                "captured_at",
                "expires_at",
                "signature_ref",
                "signing_trust_root_ref",
                "snapshot_ref",
                "snapshot_sha256",
            },
            "revocation snapshot",
        )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class EvidenceExportManifest:
    manifest_ref: str
    manifest_sha256: str
    signature_ref: str
    signing_trust_root_ref: str
    evidence_store_ref: str

    def __post_init__(self) -> None:
        for name, namespace in (
            ("manifest_ref", "manifestref"),
            ("signature_ref", "signatureref"),
            ("signing_trust_root_ref", "trustref"),
            ("evidence_store_ref", "storeref"),
        ):
            object.__setattr__(self, name, _reference(getattr(self, name), name, namespace))
        _digest(self.manifest_sha256, "manifest_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_store_ref": self.evidence_store_ref,
            "manifest_ref": self.manifest_ref,
            "manifest_sha256": self.manifest_sha256,
            "signature_ref": self.signature_ref,
            "signing_trust_root_ref": self.signing_trust_root_ref,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceExportManifest:
        value = _exact(
            raw,
            {
                "evidence_store_ref",
                "manifest_ref",
                "manifest_sha256",
                "signature_ref",
                "signing_trust_root_ref",
            },
            "evidence export manifest",
        )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class DeploymentAdmissionRequest:
    profile_id: str
    profile_sha256: str
    mission_bundle: SignedMissionBundle
    revocation_snapshot: RevocationSnapshot
    evidence_export_manifest: EvidenceExportManifest
    requested_capabilities: tuple[Capability, ...]
    requested_tool_refs: tuple[str, ...]
    credential_mode: CredentialDeliveryMode
    requested_credential_lease_seconds: int
    worker_clock_at: str
    last_online_at: str
    request_id: str = field(init=False)
    request_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.deployment-admission-request.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_id, str)
            or re.fullmatch(r"DPC-[0-9A-F]{32}", self.profile_id) is None
        ):
            raise DeploymentProfileError("profile_id is invalid")
        _digest(self.profile_sha256, "profile_sha256")
        if not isinstance(self.mission_bundle, SignedMissionBundle):
            raise DeploymentProfileError("mission_bundle is invalid")
        if not isinstance(self.revocation_snapshot, RevocationSnapshot):
            raise DeploymentProfileError("revocation_snapshot is invalid")
        if not isinstance(self.evidence_export_manifest, EvidenceExportManifest):
            raise DeploymentProfileError("evidence_export_manifest is invalid")
        object.__setattr__(
            self,
            "requested_capabilities",
            _enum_tuple(self.requested_capabilities, Capability, "requested_capabilities"),
        )
        object.__setattr__(
            self,
            "requested_tool_refs",
            _reference_tuple(self.requested_tool_refs, "requested_tool_refs", "toolref"),
        )
        object.__setattr__(self, "credential_mode", CredentialDeliveryMode(self.credential_mode))
        if self.credential_mode is CredentialDeliveryMode.NONE:
            if self.requested_credential_lease_seconds != 0:
                raise DeploymentProfileError("credential-free request must have a zero lease")
        else:
            _positive(
                self.requested_credential_lease_seconds,
                "requested_credential_lease_seconds",
                86_400,
            )
        _timestamp(self.worker_clock_at, "worker_clock_at")
        _timestamp(self.last_online_at, "last_online_at")
        body = self._body()
        identity, digest = _identity("DAR", self.KIND, body)
        object.__setattr__(self, "request_id", identity)
        object.__setattr__(self, "request_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "credential_mode": self.credential_mode.value,
            "effects": dict(NO_EFFECTS),
            "evidence_export_manifest": self.evidence_export_manifest.to_dict(),
            "kind": self.KIND,
            "last_online_at": self.last_online_at,
            "mission_bundle": self.mission_bundle.to_dict(),
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "requested_capabilities": [item.value for item in self.requested_capabilities],
            "requested_credential_lease_seconds": self.requested_credential_lease_seconds,
            "requested_tool_refs": list(self.requested_tool_refs),
            "revocation_snapshot": self.revocation_snapshot.to_dict(),
            "schema_version": SCHEMA_VERSION,
            "worker_clock_at": self.worker_clock_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DeploymentAdmissionRequest:
        fields = {
            "credential_mode",
            "effects",
            "evidence_export_manifest",
            "kind",
            "last_online_at",
            "mission_bundle",
            "profile_id",
            "profile_sha256",
            "request_id",
            "request_sha256",
            "requested_capabilities",
            "requested_credential_lease_seconds",
            "requested_tool_refs",
            "revocation_snapshot",
            "schema_version",
            "worker_clock_at",
        }
        value = _exact(raw, fields, "deployment admission request")
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise DeploymentProfileError("deployment request kind or schema is invalid")
        _effects(value["effects"], "deployment request")
        _verify_address(value, "request_id", "request_sha256", "DAR", cls.KIND)
        instance = cls(
            profile_id=value["profile_id"],
            profile_sha256=value["profile_sha256"],
            mission_bundle=SignedMissionBundle.from_dict(value["mission_bundle"]),
            revocation_snapshot=RevocationSnapshot.from_dict(value["revocation_snapshot"]),
            evidence_export_manifest=EvidenceExportManifest.from_dict(
                value["evidence_export_manifest"]
            ),
            requested_capabilities=tuple(value["requested_capabilities"]),
            requested_tool_refs=tuple(value["requested_tool_refs"]),
            credential_mode=value["credential_mode"],
            requested_credential_lease_seconds=value["requested_credential_lease_seconds"],
            worker_clock_at=value["worker_clock_at"],
            last_online_at=value["last_online_at"],
        )
        if instance.to_dict() != dict(value):
            raise DeploymentProfileError("deployment admission request is not canonical")
        return instance

    @classmethod
    def from_json(cls, document: str) -> DeploymentAdmissionRequest:
        try:
            raw = json.loads(document)
        except (TypeError, json.JSONDecodeError) as exc:
            raise DeploymentProfileError("deployment request JSON is invalid") from exc
        if canonical_json(raw) != document:
            raise DeploymentProfileError("deployment request JSON is not canonical")
        return cls.from_dict(raw)


@dataclass(frozen=True, slots=True)
class DeploymentAdmissionResult:
    profile_id: str
    profile_sha256: str
    request_id: str
    request_sha256: str
    evaluated_at: str
    status: AdmissionStatus
    blocker_codes: tuple[str, ...]
    result_id: str = field(init=False)
    result_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.deployment-admission-result.v1"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_id, str)
            or re.fullmatch(r"DPC-[0-9A-F]{32}", self.profile_id) is None
        ):
            raise DeploymentProfileError("profile_id is invalid")
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"DAR-[0-9A-F]{32}", self.request_id) is None
        ):
            raise DeploymentProfileError("request_id is invalid")
        _digest(self.profile_sha256, "profile_sha256")
        _digest(self.request_sha256, "request_sha256")
        _timestamp(self.evaluated_at, "evaluated_at")
        object.__setattr__(self, "status", AdmissionStatus(self.status))
        blockers = tuple(sorted(_bounded_unique(self.blocker_codes, "blocker_codes")))
        if any(
            not isinstance(code, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None
            for code in blockers
        ):
            raise DeploymentProfileError("blocker code is invalid")
        if "live_deployment_verification_required" not in blockers:
            raise DeploymentProfileError("live deployment verification blocker is mandatory")
        if self.status is AdmissionStatus.CONTRACT_COMPATIBLE_UNVERIFIED and blockers != (
            "live_deployment_verification_required",
        ):
            raise DeploymentProfileError("compatible result has contradictory blockers")
        if self.status is AdmissionStatus.DENIED and len(blockers) < 2:
            raise DeploymentProfileError("denied result requires a specific blocker")
        object.__setattr__(self, "blocker_codes", blockers)
        body = self._body()
        identity, digest = _identity("DAS", self.KIND, body)
        object.__setattr__(self, "result_id", identity)
        object.__setattr__(self, "result_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "authorization_effect": "none",
            "blocker_codes": list(self.blocker_codes),
            "deployment_effect": "none",
            "effects": dict(NO_EFFECTS),
            "evaluated_at": self.evaluated_at,
            "kind": self.KIND,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "qualification_effect": "none",
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "schema_version": SCHEMA_VERSION,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_id": self.result_id, "result_sha256": self.result_sha256}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> DeploymentAdmissionResult:
        fields = {
            "authorization_effect",
            "blocker_codes",
            "deployment_effect",
            "effects",
            "evaluated_at",
            "kind",
            "profile_id",
            "profile_sha256",
            "qualification_effect",
            "request_id",
            "request_sha256",
            "result_id",
            "result_sha256",
            "schema_version",
            "status",
        }
        value = _exact(raw, fields, "deployment admission result")
        if value["kind"] != cls.KIND or value["schema_version"] != SCHEMA_VERSION:
            raise DeploymentProfileError("deployment result kind or schema is invalid")
        effect_fields = (
            "authorization_effect",
            "deployment_effect",
            "qualification_effect",
        )
        if any(value[name] != "none" for name in effect_fields):
            raise DeploymentProfileError("deployment result effects are invalid")
        _effects(value["effects"], "deployment result")
        _verify_address(value, "result_id", "result_sha256", "DAS", cls.KIND)
        instance = cls(
            profile_id=value["profile_id"],
            profile_sha256=value["profile_sha256"],
            request_id=value["request_id"],
            request_sha256=value["request_sha256"],
            evaluated_at=value["evaluated_at"],
            status=value["status"],
            blocker_codes=tuple(value["blocker_codes"]),
        )
        if instance.to_dict() != dict(value):
            raise DeploymentProfileError("deployment admission result is not canonical")
        return instance

    @classmethod
    def from_json(cls, document: str) -> DeploymentAdmissionResult:
        try:
            raw = json.loads(document)
        except (TypeError, json.JSONDecodeError) as exc:
            raise DeploymentProfileError("deployment result JSON is invalid") from exc
        if canonical_json(raw) != document:
            raise DeploymentProfileError("deployment result JSON is not canonical")
        return cls.from_dict(raw)


def evaluate_deployment_admission(
    profile: DeploymentProfile,
    request: DeploymentAdmissionRequest,
    *,
    evaluated_at: str,
) -> DeploymentAdmissionResult:
    """Evaluate an immutable request without granting deployment authority."""

    if not isinstance(profile, DeploymentProfile) or not isinstance(
        request, DeploymentAdmissionRequest
    ):
        raise DeploymentProfileError("profile and request types are required")
    now = _timestamp(evaluated_at, "evaluated_at")
    blockers: set[str] = {"live_deployment_verification_required"}
    if request.profile_id != profile.profile_id or request.profile_sha256 != profile.profile_sha256:
        blockers.add("profile_binding_mismatch")
    root_map = {item.trust_root_ref: item for item in profile.trust_roots}
    bundle_root = root_map.get(request.mission_bundle.signing_trust_root_ref)
    if bundle_root is None or "mission_bundle" not in bundle_root.purposes:
        blockers.add("mission_bundle_trust_root_unpinned")
    snapshot_root = root_map.get(request.revocation_snapshot.signing_trust_root_ref)
    if snapshot_root is None or "revocation_snapshot" not in snapshot_root.purposes:
        blockers.add("revocation_trust_root_unpinned")
    export_root = root_map.get(request.evidence_export_manifest.signing_trust_root_ref)
    if export_root is None or "evidence_export" not in export_root.purposes:
        blockers.add("evidence_export_trust_root_unpinned")
    if (
        request.evidence_export_manifest.signing_trust_root_ref
        != profile.custody_policy.export_trust_root_ref
    ):
        blockers.add("evidence_export_trust_root_mismatch")
    if request.evidence_export_manifest.manifest_ref != profile.custody_policy.export_manifest_ref:
        blockers.add("evidence_export_manifest_mismatch")
    if (
        request.evidence_export_manifest.evidence_store_ref
        != profile.custody_policy.evidence_store_ref
    ):
        blockers.add("evidence_store_mismatch")
    bundle_issued = _timestamp(request.mission_bundle.issued_at, "mission_bundle.issued_at")
    bundle_expires = _timestamp(request.mission_bundle.expires_at, "mission_bundle.expires_at")
    snapshot_captured = _timestamp(
        request.revocation_snapshot.captured_at,
        "revocation_snapshot.captured_at",
    )
    snapshot_expires = _timestamp(
        request.revocation_snapshot.expires_at,
        "revocation_snapshot.expires_at",
    )
    worker_clock = _timestamp(request.worker_clock_at, "worker_clock_at")
    last_online = _timestamp(request.last_online_at, "last_online_at")
    if now < bundle_issued or now >= bundle_expires:
        blockers.add("mission_bundle_not_current")
    if now < snapshot_captured or now >= snapshot_expires:
        blockers.add("revocation_snapshot_not_current")
    if abs((worker_clock - now).total_seconds()) > profile.maximum_clock_skew_seconds:
        blockers.add("worker_clock_out_of_bounds")
    if last_online > worker_clock:
        blockers.add("last_online_after_worker_clock")
    if profile.deployment_kind is DeploymentKind.DISCONNECTED_OPERATION:
        if (worker_clock - last_online).total_seconds() > profile.maximum_offline_seconds:
            blockers.add("offline_validity_expired")
        if bundle_expires > last_online.replace(microsecond=0) and (
            bundle_expires - last_online
        ).total_seconds() > profile.maximum_offline_seconds:
            blockers.add("mission_bundle_exceeds_offline_window")
        if snapshot_expires > last_online.replace(microsecond=0) and (
            snapshot_expires - last_online
        ).total_seconds() > profile.maximum_offline_seconds:
            blockers.add("revocation_snapshot_exceeds_offline_window")
    if not set(request.requested_capabilities).issubset(profile.supported_capabilities):
        blockers.add("unsupported_capability")
    if not set(request.requested_tool_refs).issubset(profile.tool_allowlist):
        blockers.add("tool_not_allowlisted")
    if request.credential_mode not in profile.credential_constraints.allowed_modes:
        blockers.add("credential_delivery_forbidden")
    if (
        request.requested_credential_lease_seconds
        > profile.credential_constraints.maximum_lease_seconds
    ):
        blockers.add("credential_lease_exceeds_profile")
    status = (
        AdmissionStatus.CONTRACT_COMPATIBLE_UNVERIFIED
        if blockers == {"live_deployment_verification_required"}
        else AdmissionStatus.DENIED
    )
    return DeploymentAdmissionResult(
        profile_id=profile.profile_id,
        profile_sha256=profile.profile_sha256,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        evaluated_at=evaluated_at,
        status=status,
        blocker_codes=tuple(blockers),
    )


def build_standard_profile(deployment_kind: DeploymentKind | str) -> DeploymentProfile:
    """Build a deterministic baseline profile for one supported topology."""

    kind = DeploymentKind(deployment_kind)
    ingress, egress, channel = NETWORK_POLICY[kind]
    disconnected = kind is DeploymentKind.DISCONNECTED_OPERATION
    credential_modes = (
        (CredentialDeliveryMode.NONE, CredentialDeliveryMode.OFFLINE_SEALED_REFERENCE)
        if disconnected
        else (
            CredentialDeliveryMode.NONE,
            CredentialDeliveryMode.BROKERED_EPHEMERAL_REFERENCE,
            CredentialDeliveryMode.CUSTOMER_INJECTED_REFERENCE,
        )
    )
    capabilities = tuple(Capability)
    return DeploymentProfile(
        deployment_kind=kind,
        worker_ref=f"workerref:{kind.value}-baseline",
        ingress_mode=ingress,
        egress_mode=egress,
        update_channel=channel,
        trust_roots=(
            TrustRootPin(
                "trustref:mission-and-revocation-root-v1",
                "sha256:" + "1" * 64,
                ("mission_bundle", "revocation_snapshot"),
            ),
            TrustRootPin(
                "trustref:update-and-export-root-v1",
                "sha256:" + "2" * 64,
                ("update_bundle", "evidence_export"),
            ),
        ),
        version_pins=(
            VersionPin("componentref:worker-runtime", "1.0.0", "sha256:" + "3" * 64),
            VersionPin("componentref:policy-engine", "1.0.0", "sha256:" + "4" * 64),
        ),
        supported_capabilities=capabilities,
        tool_allowlist=("toolref:browser-adapter", "toolref:http-adapter"),
        credential_constraints=CredentialConstraints(credential_modes, 900),
        custody_policy=EvidenceCustodyPolicy(
            "storeref:encrypted-local-evidence",
            "manifestref:required-evidence-export",
            "trustref:update-and-export-root-v1",
        ),
        stop_cleanup_policy=StopCleanupPolicy(
            "stopref:fail-closed-stop-v1",
            "cleanupref:verified-cleanup-v1",
            "restorationref:verified-restoration-v1",
            30,
        ),
        maximum_clock_skew_seconds=120,
        maximum_offline_seconds=86_400 if disconnected else 0,
    )


def standard_deployment_profiles() -> tuple[DeploymentProfile, ...]:
    """Return all five deterministic deployment profiles."""

    return tuple(build_standard_profile(kind) for kind in DeploymentKind)


def parse_contract(
    raw: Any,
) -> DeploymentProfile | DeploymentAdmissionRequest | DeploymentAdmissionResult:
    if not isinstance(raw, Mapping):
        raise DeploymentProfileError("contract must be an object")
    kind = raw.get("kind")
    if kind == DeploymentProfile.KIND:
        return DeploymentProfile.from_dict(raw)
    if kind == DeploymentAdmissionRequest.KIND:
        return DeploymentAdmissionRequest.from_dict(raw)
    if kind == DeploymentAdmissionResult.KIND:
        return DeploymentAdmissionResult.from_dict(raw)
    raise DeploymentProfileError("contract kind is unsupported")


__all__ = [
    "AdmissionStatus",
    "Capability",
    "CredentialConstraints",
    "CredentialDeliveryMode",
    "DeploymentAdmissionRequest",
    "DeploymentAdmissionResult",
    "DeploymentKind",
    "DeploymentProfile",
    "DeploymentProfileError",
    "EgressMode",
    "EvidenceCustodyPolicy",
    "EvidenceExportManifest",
    "IngressMode",
    "NO_EFFECTS",
    "RevocationSnapshot",
    "SignedMissionBundle",
    "StopCleanupPolicy",
    "TrustRootPin",
    "UpdateChannel",
    "VersionPin",
    "build_standard_profile",
    "canonical_json",
    "canonical_sha256",
    "evaluate_deployment_admission",
    "parse_contract",
    "standard_deployment_profiles",
]
