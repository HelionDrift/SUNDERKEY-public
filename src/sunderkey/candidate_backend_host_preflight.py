"""Exact deployment binding and read-only host preflight for containment backends."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from .candidate_adapter_runner import ContainmentBackendAttestation
from .candidate_backend_conformance import ContainmentConformanceSuiteCatalog
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

BINARY_BUNDLE_DOMAIN = "sunderkey.containment-provider-binary-bundle.v1"
CONFIGURATION_BUNDLE_DOMAIN = "sunderkey.containment-provider-configuration-bundle.v1"
DEPLOYMENT_BINDING_DOMAIN = "sunderkey.containment-backend-deployment-binding.v1"
HOST_SNAPSHOT_DOMAIN = "sunderkey.containment-host-snapshot.v1"
PREFLIGHT_REPORT_DOMAIN = "sunderkey.containment-host-preflight-report.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
BINDING_ID_PATTERN = re.compile(r"CBD-[0-9A-F]{32}")
SNAPSHOT_ID_PATTERN = re.compile(r"CHS-[0-9A-F]{32}")
REPORT_ID_PATTERN = re.compile(r"CHR-[0-9A-F]{32}")
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
ARCHITECTURES = {"aarch64", "x86_64"}
MEDIA_TYPES = {"application/json", "application/toml", "text/plain"}
REQUIRED_BINARY_NAMES = {
    "oci_container": ("podman",),
    "microvm": ("firecracker", "jailer"),
}
COMMON_REQUIREMENTS = (
    "linux_host",
    "approved_architecture",
    "binary_bundle_exact",
    "configuration_bundle_exact",
    "service_identity_exact",
    "cgroup_v2",
    "seccomp_enabled",
)
CLASS_REQUIREMENTS = {
    "oci_container": (
        "rootless_provider",
        "user_namespace_enabled",
    ),
    "microvm": (
        "kvm_access",
        "dedicated_jailer_uid_gid",
        "single_tenant_vm",
        "bounded_logging",
        "host_hardening",
    ),
}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label)
    if IDENTIFIER_PATTERN.fullmatch(text) is None:
        raise QualificationError(f"{label} is invalid")
    return text


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _utc(value: Any, label: str) -> str:
    text = _text(value, label)
    if not text.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return text


def _absolute_posix_path(value: Any, label: str) -> str:
    text = _text(value, label)
    if "\\" in text or ":" in text:
        raise QualificationError(f"{label} must be an absolute POSIX path")
    path = PurePosixPath(text)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise QualificationError(f"{label} must be a safe absolute POSIX path")
    return path.as_posix()


def _binary_components(
    raw: Any,
    isolation_class: str,
    *,
    require_paths: bool,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list):
        raise QualificationError("Containment binary components must be a list")
    expected_fields = {"name", "version", "sha256", "source_url", "license_spdx"}
    if require_paths:
        expected_fields.add("path")
    components: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise QualificationError("Containment binary component fields are invalid")
        component = {
            "name": _identifier(item.get("name"), f"binary name {index}"),
            "version": _text(item.get("version"), f"binary version {index}"),
            "sha256": _sha(item.get("sha256"), f"binary hash {index}"),
            "source_url": _text(item.get("source_url"), f"binary source URL {index}"),
            "license_spdx": _text(item.get("license_spdx"), f"binary license {index}"),
        }
        if require_paths:
            component["path"] = _absolute_posix_path(
                item.get("path"), f"binary path {index}"
            )
        components.append(component)
    if tuple(item["name"] for item in components) != REQUIRED_BINARY_NAMES[isolation_class]:
        raise QualificationError("Containment binary component set or order is invalid")
    return tuple(components)


def _configuration_components(raw: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or not raw:
        raise QualificationError("Containment configuration components are incomplete")
    components: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "media_type"}:
            raise QualificationError("Containment configuration component fields are invalid")
        media_type = _text(item.get("media_type"), f"configuration media type {index}")
        if media_type not in MEDIA_TYPES:
            raise QualificationError("Containment configuration media type is not allowed")
        components.append(
            {
                "name": _identifier(item.get("name"), f"configuration name {index}"),
                "sha256": _sha(item.get("sha256"), f"configuration hash {index}"),
                "media_type": media_type,
            }
        )
    if components != sorted(components, key=lambda item: item["name"]):
        raise QualificationError("Containment configuration components must use name order")
    if len({item["name"] for item in components}) != len(components):
        raise QualificationError("Containment configuration component names are duplicated")
    return tuple(components)


def compute_provider_binary_bundle_sha256(
    binary_components: list[dict[str, Any]],
    isolation_class: str,
) -> str:
    components = _binary_components(
        binary_components, isolation_class, require_paths=False
    )
    return _canonical_sha256(
        {
            "domain": BINARY_BUNDLE_DOMAIN,
            "isolation_class": isolation_class,
            "components": components,
        }
    )


def compute_provider_configuration_bundle_sha256(
    configuration_components: list[dict[str, Any]],
) -> str:
    components = _configuration_components(configuration_components)
    return _canonical_sha256(
        {
            "domain": CONFIGURATION_BUNDLE_DOMAIN,
            "components": components,
        }
    )


def _canonical_inputs(
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> None:
    if (
        ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict()) != catalog
        or ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation
    ):
        raise QualificationError("Containment host-preflight inputs are not canonical")


@dataclass(frozen=True)
class ContainmentBackendDeploymentBinding:
    binding_id: str
    binding_sha256: str
    isolation_class: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        catalog: ContainmentConformanceSuiteCatalog,
        attestation: ContainmentBackendAttestation,
    ) -> ContainmentBackendDeploymentBinding:
        expected_fields = {
            "schema_version",
            "binding_id",
            "binding_sha256",
            "suite_catalog_sha256",
            "backend_attestation_sha256",
            "backend_id",
            "isolation_class",
            "implementation_target",
            "host_id",
            "architecture",
            "service_identity_id",
            "binary_components",
            "binary_bundle_sha256",
            "configuration_components",
            "configuration_bundle_sha256",
            "required_checks",
            "status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Containment deployment binding fields are invalid")
        _canonical_inputs(catalog, attestation)
        isolation_class = attestation.isolation_class
        suite = next(
            item for item in catalog.suites if item["isolation_class"] == isolation_class
        )
        binaries = _binary_components(
            raw.get("binary_components"), isolation_class, require_paths=False
        )
        configurations = _configuration_components(raw.get("configuration_components"))
        binary_digest = compute_provider_binary_bundle_sha256(
            list(binaries), isolation_class
        )
        configuration_digest = compute_provider_configuration_bundle_sha256(
            list(configurations)
        )
        required_checks = list(COMMON_REQUIREMENTS + CLASS_REQUIREMENTS[isolation_class])
        if (
            raw.get("schema_version") != 1
            or raw.get("suite_catalog_sha256") != catalog.catalog_sha256
            or raw.get("backend_attestation_sha256") != attestation.attestation_sha256
            or raw.get("backend_id") != attestation.backend_id
            or raw.get("isolation_class") != isolation_class
            or raw.get("implementation_target") != suite["implementation_target"]
            or raw.get("architecture") not in ARCHITECTURES
            or raw.get("binary_bundle_sha256") != binary_digest
            or raw.get("configuration_bundle_sha256") != configuration_digest
            or attestation.executable_sha256 != binary_digest
            or attestation.configuration_sha256 != configuration_digest
            or raw.get("required_checks") != required_checks
            or raw.get("status") != "configured_pending_host_preflight"
            or any(
                raw.get(field) != "none"
                for field in (
                    "qualification_effect",
                    "routing_effect",
                    "deployment_effect",
                    "target_authority_effect",
                )
            )
        ):
            raise QualificationError("Containment deployment binding is invalid")
        _identifier(raw.get("host_id"), "containment host ID")
        _identifier(raw.get("service_identity_id"), "containment service identity ID")
        binding_sha256 = _sha(raw.get("binding_sha256"), "containment binding hash")
        binding_id = _text(raw.get("binding_id"), "containment binding ID")
        if BINDING_ID_PATTERN.fullmatch(binding_id) is None:
            raise QualificationError("Containment binding ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"binding_id", "binding_sha256"}
        }
        expected_sha256 = _canonical_sha256(
            {"domain": DEPLOYMENT_BINDING_DOMAIN, "binding": body}
        )
        expected_id = f"CBD-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if binding_sha256 != expected_sha256 or binding_id != expected_id:
            raise QualificationError("Containment binding identity does not match content")
        return cls(binding_id, binding_sha256, isolation_class, _canonical_json(raw))


def build_containment_backend_deployment_binding(
    *,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    host_id: str,
    architecture: str,
    service_identity_id: str,
    binary_components: list[dict[str, Any]],
    configuration_components: list[dict[str, Any]],
) -> ContainmentBackendDeploymentBinding:
    suite = next(
        item for item in catalog.suites if item["isolation_class"] == attestation.isolation_class
    )
    binary_digest = compute_provider_binary_bundle_sha256(
        binary_components, attestation.isolation_class
    )
    configuration_digest = compute_provider_configuration_bundle_sha256(
        configuration_components
    )
    body = {
        "schema_version": 1,
        "suite_catalog_sha256": catalog.catalog_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "backend_id": attestation.backend_id,
        "isolation_class": attestation.isolation_class,
        "implementation_target": suite["implementation_target"],
        "host_id": host_id,
        "architecture": architecture,
        "service_identity_id": service_identity_id,
        "binary_components": binary_components,
        "binary_bundle_sha256": binary_digest,
        "configuration_components": configuration_components,
        "configuration_bundle_sha256": configuration_digest,
        "required_checks": list(
            COMMON_REQUIREMENTS + CLASS_REQUIREMENTS[attestation.isolation_class]
        ),
        "status": "configured_pending_host_preflight",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": DEPLOYMENT_BINDING_DOMAIN, "binding": body})
    return ContainmentBackendDeploymentBinding.from_dict(
        {
            **body,
            "binding_id": f"CBD-{digest.removeprefix('sha256:')[:32].upper()}",
            "binding_sha256": digest,
        },
        catalog,
        attestation,
    )


@dataclass(frozen=True)
class ContainmentHostSnapshot:
    snapshot_id: str
    snapshot_sha256: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> ContainmentHostSnapshot:
        expected_fields = {
            "schema_version",
            "snapshot_id",
            "snapshot_sha256",
            "host_id",
            "collected_at",
            "collection_method",
            "os_name",
            "architecture",
            "kernel_release",
            "service_identity_id",
            "binary_components",
            "configuration_components",
            "cgroup_version",
            "seccomp_enabled",
            "rootless_provider",
            "user_namespace_enabled",
            "kvm_access",
            "dedicated_jailer_uid_gid",
            "single_tenant_vm",
            "bounded_logging",
            "host_hardening",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Containment host snapshot fields are invalid")
        _identifier(raw.get("host_id"), "snapshot host ID")
        _utc(raw.get("collected_at"), "snapshot collected_at")
        if raw.get("collection_method") != "externally_collected_read_only":
            raise QualificationError("Containment host snapshot collection method is invalid")
        _text(raw.get("os_name"), "snapshot OS name")
        _text(raw.get("architecture"), "snapshot architecture")
        _text(raw.get("kernel_release"), "snapshot kernel release")
        _identifier(raw.get("service_identity_id"), "snapshot service identity ID")
        binary_components = raw.get("binary_components")
        if not isinstance(binary_components, list) or not binary_components:
            raise QualificationError("Snapshot binary components are incomplete")
        for index, item in enumerate(binary_components):
            if not isinstance(item, dict) or set(item) != {
                "name", "version", "sha256", "source_url", "license_spdx", "path"
            }:
                raise QualificationError("Snapshot binary component fields are invalid")
            _identifier(item.get("name"), f"snapshot binary name {index}")
            _text(item.get("version"), f"snapshot binary version {index}")
            _sha(item.get("sha256"), f"snapshot binary hash {index}")
            _text(item.get("source_url"), f"snapshot binary source URL {index}")
            _text(item.get("license_spdx"), f"snapshot binary license {index}")
            _absolute_posix_path(item.get("path"), f"snapshot binary path {index}")
        _configuration_components(raw.get("configuration_components"))
        if raw.get("cgroup_version") not in {"none", "v1", "v2"}:
            raise QualificationError("Snapshot cgroup version is invalid")
        boolean_fields = (
            "seccomp_enabled",
            "rootless_provider",
            "user_namespace_enabled",
            "kvm_access",
            "dedicated_jailer_uid_gid",
            "single_tenant_vm",
            "bounded_logging",
            "host_hardening",
        )
        if any(type(raw.get(field)) is not bool for field in boolean_fields):
            raise QualificationError("Snapshot security controls must be booleans")
        if any(
            raw.get(field) != "none"
            for field in (
                "qualification_effect",
                "routing_effect",
                "deployment_effect",
                "target_authority_effect",
            )
        ):
            raise QualificationError("Containment host snapshot effects are invalid")
        snapshot_sha256 = _sha(raw.get("snapshot_sha256"), "host snapshot hash")
        snapshot_id = _text(raw.get("snapshot_id"), "host snapshot ID")
        if SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id) is None:
            raise QualificationError("Host snapshot ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        expected_sha256 = _canonical_sha256(
            {"domain": HOST_SNAPSHOT_DOMAIN, "snapshot": body}
        )
        expected_id = f"CHS-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if snapshot_sha256 != expected_sha256 or snapshot_id != expected_id:
            raise QualificationError("Host snapshot identity does not match content")
        return cls(snapshot_id, snapshot_sha256, _canonical_json(raw))


def build_containment_host_snapshot(**values: Any) -> ContainmentHostSnapshot:
    body = {
        "schema_version": 1,
        **values,
        "collection_method": "externally_collected_read_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": HOST_SNAPSHOT_DOMAIN, "snapshot": body})
    return ContainmentHostSnapshot.from_dict(
        {
            **body,
            "snapshot_id": f"CHS-{digest.removeprefix('sha256:')[:32].upper()}",
            "snapshot_sha256": digest,
        }
    )


@dataclass(frozen=True)
class ContainmentHostPreflightReport:
    report_id: str
    report_sha256: str
    status: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        binding: ContainmentBackendDeploymentBinding,
        snapshot: ContainmentHostSnapshot,
        catalog: ContainmentConformanceSuiteCatalog,
        attestation: ContainmentBackendAttestation,
    ) -> ContainmentHostPreflightReport:
        expected_fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "binding_id",
            "binding_sha256",
            "snapshot_id",
            "snapshot_sha256",
            "backend_attestation_sha256",
            "isolation_class",
            "check_results",
            "blockers",
            "status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Containment host-preflight report fields are invalid")
        verified_binding = ContainmentBackendDeploymentBinding.from_dict(
            binding.to_dict(), catalog, attestation
        )
        verified_snapshot = ContainmentHostSnapshot.from_dict(snapshot.to_dict())
        if verified_binding != binding or verified_snapshot != snapshot:
            raise QualificationError("Containment host-preflight inputs are not canonical")
        expected_body = _build_host_preflight_body(binding, snapshot, attestation)
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"report_id", "report_sha256"}
        }
        if body != expected_body:
            raise QualificationError("Containment host-preflight report outcome is invalid")
        report_sha256 = _sha(raw.get("report_sha256"), "host-preflight report hash")
        report_id = _text(raw.get("report_id"), "host-preflight report ID")
        if REPORT_ID_PATTERN.fullmatch(report_id) is None:
            raise QualificationError("Containment host-preflight report ID is invalid")
        expected_sha256 = _canonical_sha256(
            {"domain": PREFLIGHT_REPORT_DOMAIN, "report": body}
        )
        expected_id = f"CHR-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if report_sha256 != expected_sha256 or report_id != expected_id:
            raise QualificationError("Host-preflight report identity does not match content")
        return cls(report_id, report_sha256, raw["status"], _canonical_json(raw))


def _build_host_preflight_body(
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    attestation: ContainmentBackendAttestation,
) -> dict[str, Any]:
    binding_raw = binding.to_dict()
    snapshot_raw = snapshot.to_dict()
    expected_binary_components = [
        {key: value for key, value in item.items() if key != "path"}
        for item in snapshot_raw["binary_components"]
    ]
    checks = {
        "linux_host": snapshot_raw["os_name"] == "linux",
        "approved_architecture": snapshot_raw["architecture"] == binding_raw["architecture"],
        "binary_bundle_exact": expected_binary_components == binding_raw["binary_components"],
        "configuration_bundle_exact": snapshot_raw["configuration_components"]
        == binding_raw["configuration_components"],
        "service_identity_exact": snapshot_raw["service_identity_id"]
        == binding_raw["service_identity_id"],
        "cgroup_v2": snapshot_raw["cgroup_version"] == "v2",
        "seccomp_enabled": snapshot_raw["seccomp_enabled"],
        "rootless_provider": snapshot_raw["rootless_provider"],
        "user_namespace_enabled": snapshot_raw["user_namespace_enabled"],
        "kvm_access": snapshot_raw["kvm_access"],
        "dedicated_jailer_uid_gid": snapshot_raw["dedicated_jailer_uid_gid"],
        "single_tenant_vm": snapshot_raw["single_tenant_vm"],
        "bounded_logging": snapshot_raw["bounded_logging"],
        "host_hardening": snapshot_raw["host_hardening"],
    }
    results = [
        {"check_id": check_id, "status": "passed" if checks[check_id] else "failed"}
        for check_id in binding_raw["required_checks"]
    ]
    blockers = [item["check_id"] for item in results if item["status"] == "failed"]
    status = (
        "ready_for_dynamic_conformance_nonqualifying"
        if not blockers
        else "blocked_pending_host_remediation"
    )
    return {
        "schema_version": 1,
        "binding_id": binding.binding_id,
        "binding_sha256": binding.binding_sha256,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "isolation_class": attestation.isolation_class,
        "check_results": results,
        "blockers": blockers,
        "status": status,
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }


def assess_containment_host_preflight(
    *,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> ContainmentHostPreflightReport:
    verified_binding = ContainmentBackendDeploymentBinding.from_dict(
        binding.to_dict(), catalog, attestation
    )
    verified_snapshot = ContainmentHostSnapshot.from_dict(snapshot.to_dict())
    if verified_binding != binding or verified_snapshot != snapshot:
        raise QualificationError("Containment host-preflight inputs are not canonical")
    body = _build_host_preflight_body(binding, snapshot, attestation)
    digest = _canonical_sha256({"domain": PREFLIGHT_REPORT_DOMAIN, "report": body})
    report_id = f"CHR-{digest.removeprefix('sha256:')[:32].upper()}"
    document = {**body, "report_id": report_id, "report_sha256": digest}
    return ContainmentHostPreflightReport.from_dict(
        document,
        binding,
        snapshot,
        catalog,
        attestation,
    )


__all__ = [
    "ContainmentBackendDeploymentBinding",
    "ContainmentHostPreflightReport",
    "ContainmentHostSnapshot",
    "assess_containment_host_preflight",
    "build_containment_backend_deployment_binding",
    "build_containment_host_snapshot",
    "compute_provider_binary_bundle_sha256",
    "compute_provider_configuration_bundle_sha256",
]
