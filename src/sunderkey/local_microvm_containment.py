"""Repository-only Firecracker-style containment specifications and receipts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

from .candidate_adapter_runner import ContainmentExecutionPlan, ContainmentLimits
from .candidate_backend_host_preflight import (
    ContainmentBackendDeploymentBinding,
    ContainmentHostPreflightReport,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

SPEC_DOMAIN = "sunderkey.local-microvm-execution-spec.v1"
OBSERVATION_DOMAIN = "sunderkey.local-microvm-containment-observation.v1"
RECEIPT_DOMAIN = "sunderkey.local-microvm-containment-fixture-receipt.v1"
PLAN_DOMAIN = "sunderkey.adapter-containment-plan.v1"
BINDING_DOMAIN = "sunderkey.containment-backend-deployment-binding.v1"
PREFLIGHT_DOMAIN = "sunderkey.containment-host-preflight-report.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PLAN_ID_PATTERN = re.compile(r"CEP-[0-9A-F]{32}")
BINDING_ID_PATTERN = re.compile(r"CBD-[0-9A-F]{32}")
REPORT_ID_PATTERN = re.compile(r"CHR-[0-9A-F]{32}")
SPEC_ID_PATTERN = re.compile(r"MVS-[0-9A-F]{32}")
OBSERVATION_ID_PATTERN = re.compile(r"MVO-[0-9A-F]{32}")
RECEIPT_ID_PATTERN = re.compile(r"MVR-[0-9A-F]{32}")
BOUNDARY_EFFECTS = {
    "qualification_effect": "none",
    "routing_effect": "none",
    "deployment_effect": "none",
    "target_authority_effect": "none",
}


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _absolute_posix_path(value: Any, label: str) -> str:
    text = _text(value, label)
    if "\\" in text or ":" in text:
        raise QualificationError(f"{label} must be an absolute POSIX path")
    path = PurePosixPath(text)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise QualificationError(f"{label} must be a safe absolute POSIX path")
    return path.as_posix()


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise QualificationError(f"{label} is outside the allowed range")
    return value


def _require_native_document(raw: Any, label: str) -> None:
    pending = [(raw, False)]
    active: set[int] = set()
    verified: set[int] = set()
    while pending:
        value, leaving = pending.pop()
        kind = type(value)
        if value is None or kind is str or kind is bool or kind is int:
            continue
        if kind is not dict and kind is not list:
            raise QualificationError(f"{label} must use native JSON values and integer numbers")
        identity = id(value)
        if leaving:
            active.remove(identity)
            verified.add(identity)
            continue
        if identity in active:
            raise QualificationError(f"{label} must not contain cyclic collections")
        if identity in verified:
            continue
        active.add(identity)
        pending.append((value, True))
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise QualificationError(f"{label} keys must be native strings")
            pending.extend((item, False) for item in value.values())
        else:
            pending.extend((item, False) for item in value)


def _matches_native_projection(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(
            _matches_native_projection(value[key], item) for key, item in expected.items()
        )
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _matches_native_projection(item, reference)
            for item, reference in zip(value, expected, strict=True)
        )
    return value == expected


def _exact_object(raw: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(raw) is not dict or any(type(key) is not str for key in raw) or set(raw) != fields:
        raise QualificationError(f"{label} fields are invalid")
    _require_native_document(raw, label)
    if "schema_version" in fields and (
        type(raw["schema_version"]) is not int or raw["schema_version"] != 1
    ):
        raise QualificationError(f"{label} schema version is invalid")
    return raw


def _effects_are_none(raw: dict[str, Any], label: str) -> None:
    if any(raw.get(field) != value for field, value in BOUNDARY_EFFECTS.items()):
        raise QualificationError(f"{label} operational effects are invalid")


def _validate_content_address(
    raw: dict[str, Any],
    *,
    identifier_field: str,
    digest_field: str,
    identifier_pattern: re.Pattern[str],
    identifier_prefix: str,
    domain: str,
    body_key: str,
    label: str,
) -> None:
    digest = _sha(raw.get(digest_field), f"{label} hash")
    identifier = raw.get(identifier_field)
    if not isinstance(identifier, str) or identifier_pattern.fullmatch(identifier) is None:
        raise QualificationError(f"{label} ID is invalid")
    body = {key: value for key, value in raw.items() if key not in {identifier_field, digest_field}}
    expected = _canonical_sha256({"domain": domain, body_key: body})
    expected_id = f"{identifier_prefix}{expected.removeprefix('sha256:')[:32].upper()}"
    if digest != expected or identifier != expected_id:
        raise QualificationError(f"{label} identity does not match content")


def _verify_plan(plan: ContainmentExecutionPlan) -> dict[str, Any]:
    raw = _exact_object(
        plan.to_dict(),
        {
            "schema_version",
            "adapter_id",
            "adapter_version",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "invocation_sha256",
            "backend_id",
            "backend_attestation_sha256",
            "isolation_class",
            "resource_policy",
            "limits",
            "issued_at",
            "expires_at",
            "execution_mode",
            "result_channel",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
            "plan_id",
            "plan_sha256",
        },
        "Containment plan",
    )
    if (
        raw.get("isolation_class") != "microvm"
        or raw.get("execution_mode") != "external_isolation_required"
        or raw.get("result_channel") != "content_addressed_json_only"
    ):
        raise QualificationError("Local microVM adapter requires a microVM containment plan")
    _effects_are_none(raw, "Containment plan")
    _validate_content_address(
        raw,
        identifier_field="plan_id",
        digest_field="plan_sha256",
        identifier_pattern=PLAN_ID_PATTERN,
        identifier_prefix="CEP-",
        domain=PLAN_DOMAIN,
        body_key="plan",
        label="Containment plan",
    )
    if ContainmentLimits.from_dict(raw.get("limits")) != plan.limits:
        raise QualificationError("Containment plan limits are not canonical")
    if (
        plan.plan_id != raw["plan_id"]
        or plan.plan_sha256 != raw["plan_sha256"]
        or plan.invocation_sha256 != raw["invocation_sha256"]
        or plan.backend_attestation_sha256 != raw["backend_attestation_sha256"]
        or plan.isolation_class != raw["isolation_class"]
    ):
        raise QualificationError("Containment plan object does not match its document")
    return raw


def _verify_binding(binding: ContainmentBackendDeploymentBinding) -> dict[str, Any]:
    raw = _exact_object(
        binding.to_dict(),
        {
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
        },
        "Containment deployment binding",
    )
    if (
        raw.get("isolation_class") != "microvm"
        or raw.get("implementation_target") != "jailed_firecracker"
        or raw.get("status") != "configured_pending_host_preflight"
    ):
        raise QualificationError("Local microVM adapter requires a Firecracker binding")
    _effects_are_none(raw, "Containment deployment binding")
    _validate_content_address(
        raw,
        identifier_field="binding_id",
        digest_field="binding_sha256",
        identifier_pattern=BINDING_ID_PATTERN,
        identifier_prefix="CBD-",
        domain=BINDING_DOMAIN,
        body_key="binding",
        label="Containment deployment binding",
    )
    required = {
        "linux_host",
        "approved_architecture",
        "binary_bundle_exact",
        "configuration_bundle_exact",
        "service_identity_exact",
        "cgroup_v2",
        "seccomp_enabled",
        "kvm_access",
        "dedicated_jailer_uid_gid",
        "single_tenant_vm",
        "bounded_logging",
        "host_hardening",
    }
    if set(raw.get("required_checks", ())) != required:
        raise QualificationError("Firecracker binding checks are incomplete")
    if (
        binding.binding_id != raw["binding_id"]
        or binding.binding_sha256 != raw["binding_sha256"]
        or binding.isolation_class != raw["isolation_class"]
    ):
        raise QualificationError("Containment binding object does not match its document")
    return raw


def _artifact_policy(
    *,
    kernel_path: str,
    kernel_sha256: str,
    rootfs_path: str,
    rootfs_sha256: str,
    overlay_path: str,
    overlay_bytes: int,
) -> dict[str, Any]:
    return {
        "kernel": {
            "path": _absolute_posix_path(kernel_path, "kernel path"),
            "sha256": _sha(kernel_sha256, "kernel hash"),
            "content_pinned": True,
        },
        "base_rootfs": {
            "path": _absolute_posix_path(rootfs_path, "root filesystem path"),
            "sha256": _sha(rootfs_sha256, "root filesystem hash"),
            "content_pinned": True,
            "read_only": True,
        },
        "ephemeral_overlay": {
            "path": _absolute_posix_path(overlay_path, "overlay path"),
            "maximum_bytes": overlay_bytes,
            "ephemeral": True,
            "remove_after_execution": True,
        },
    }


def _jailer_policy(
    *,
    firecracker_path: str,
    jailer_path: str,
    chroot_base_dir: str,
    service_identity_id: str,
    uid: int,
    gid: int,
) -> dict[str, Any]:
    return {
        "firecracker_path": _absolute_posix_path(firecracker_path, "Firecracker executable path"),
        "jailer_path": _absolute_posix_path(jailer_path, "jailer executable path"),
        "chroot_base_dir": _absolute_posix_path(chroot_base_dir, "jailer chroot base"),
        "service_identity_id": _text(service_identity_id, "jailer service identity ID"),
        "uid": _bounded_int(uid, "jailer UID", 1000, 65535),
        "gid": _bounded_int(gid, "jailer GID", 1000, 65535),
        "dedicated_uid_gid_required": True,
        "seccomp_level": 2,
        "new_pid_namespace": True,
        "daemonize": False,
    }


def _resource_limits(limits: ContainmentLimits, vcpu_count: int, log_bytes: int) -> dict[str, Any]:
    return {
        "vcpu_count": _bounded_int(vcpu_count, "microVM vCPU count", 1, 8),
        "cpu_millis": limits.cpu_millis,
        "memory_mib": limits.memory_mib,
        "pid_limit": limits.process_count,
        "output_bytes": limits.output_bytes,
        "log_bytes": _bounded_int(log_bytes, "microVM log limit", 0, limits.output_bytes),
        "timeout_seconds": limits.timeout_seconds,
        "overlay_bytes": limits.workspace_bytes,
    }


def _host_preflight_contract(binding_raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "binding_id": binding_raw["binding_id"],
        "binding_sha256": binding_raw["binding_sha256"],
        "required_report_status": "ready_for_dynamic_conformance_nonqualifying",
        "observed_report_id": None,
        "observed_report_sha256": None,
        "observed_status": "not_observed_fixture",
        "external_preflight_required_before_dispatch": True,
    }


def _lifecycle_policy(timeout_seconds: int) -> dict[str, Any]:
    grace_seconds = min(10, timeout_seconds)
    return {
        "cancellation_required": True,
        "cancellation_mode": "executor_control_channel_fail_closed",
        "deadline_enforced": True,
        "teardown_required": True,
        "teardown_grace_seconds": grace_seconds,
        "teardown_failure_disposition": "failed_closed",
        "residual_effect_observation_required": True,
        "residual_effect_failure_disposition": "failed_closed",
    }


def _jailer_argv(
    *,
    vm_id: str,
    jailer_policy: dict[str, Any],
    resource_limits: dict[str, Any],
) -> list[str]:
    return [
        jailer_policy["jailer_path"],
        "--id",
        vm_id,
        "--exec-file",
        jailer_policy["firecracker_path"],
        "--uid",
        str(jailer_policy["uid"]),
        "--gid",
        str(jailer_policy["gid"]),
        "--chroot-base-dir",
        jailer_policy["chroot_base_dir"],
        "--cgroup-version",
        "2",
        "--resource-limit",
        f"no-file={resource_limits['pid_limit'] + 32}",
    ]


@dataclass(frozen=True)
class LocalMicrovmExecutionSpec:
    spec_id: str
    spec_sha256: str
    plan_id: str
    plan_sha256: str
    limits: ContainmentLimits
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalMicrovmExecutionSpec:
        fields = {
            "schema_version",
            "kind",
            "spec_id",
            "spec_sha256",
            "runtime_kind",
            "runner_interface",
            "plan_id",
            "plan_sha256",
            "invocation_sha256",
            "backend_attestation_sha256",
            "deployment_binding_id",
            "deployment_binding_sha256",
            "isolation_class",
            "vm_id",
            "host_preflight_contract",
            "host_requirements",
            "artifact_policy",
            "jailer_policy",
            "machine_configuration",
            "resource_limits",
            "network_policy",
            "credential_policy",
            "logging_policy",
            "lifecycle_policy",
            "jailer_argv",
            "status",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local microVM execution specification")
        _effects_are_none(value, "Local microVM execution specification")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_microvm_execution_spec"
            or value.get("runtime_kind") != "jailed_firecracker"
            or value.get("runner_interface") != "injected_executor_only"
            or value.get("isolation_class") != "microvm"
            or value.get("status") != "specification_pending_external_host_preflight_nonqualifying"
        ):
            raise QualificationError("Local microVM execution boundary is invalid")
        for field in (
            "plan_sha256",
            "invocation_sha256",
            "backend_attestation_sha256",
            "deployment_binding_sha256",
        ):
            _sha(value.get(field), field)
        plan_id = value.get("plan_id")
        if not isinstance(plan_id, str) or PLAN_ID_PATTERN.fullmatch(plan_id) is None:
            raise QualificationError("Local microVM plan ID is invalid")
        binding_id = value.get("deployment_binding_id")
        if not isinstance(binding_id, str) or BINDING_ID_PATTERN.fullmatch(binding_id) is None:
            raise QualificationError("Local microVM deployment binding ID is invalid")
        vm_id = _text(value.get("vm_id"), "microVM ID")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", vm_id) is None:
            raise QualificationError("Local microVM ID is invalid")

        preflight = _exact_object(
            value.get("host_preflight_contract"),
            {
                "binding_id",
                "binding_sha256",
                "required_report_status",
                "observed_report_id",
                "observed_report_sha256",
                "observed_status",
                "external_preflight_required_before_dispatch",
            },
            "Local microVM host preflight contract",
        )
        if not _matches_native_projection(
            preflight,
            {
                "binding_id": binding_id,
                "binding_sha256": value["deployment_binding_sha256"],
                "required_report_status": "ready_for_dynamic_conformance_nonqualifying",
                "observed_report_id": None,
                "observed_report_sha256": None,
                "observed_status": "not_observed_fixture",
                "external_preflight_required_before_dispatch": True,
            },
        ):
            raise QualificationError("Local microVM host preflight contract is invalid")

        host = _exact_object(
            value.get("host_requirements"),
            {
                "os_name",
                "architecture",
                "kvm_device_path",
                "kvm_access_required",
                "cgroup_version",
                "seccomp_required",
                "dedicated_uid_gid_required",
                "single_tenant_vm_required",
                "bounded_logging_required",
                "host_hardening_required",
            },
            "Local microVM host requirements",
        )
        _absolute_posix_path(host.get("kvm_device_path"), "KVM device path")
        if (
            host.get("os_name") != "linux"
            or type(host.get("architecture")) is not str
            or host.get("architecture") not in {"aarch64", "x86_64"}
            or host.get("kvm_device_path") != "/dev/kvm"
            or host.get("cgroup_version") != "v2"
            or any(
                host.get(field) is not True
                for field in (
                    "kvm_access_required",
                    "seccomp_required",
                    "dedicated_uid_gid_required",
                    "single_tenant_vm_required",
                    "bounded_logging_required",
                    "host_hardening_required",
                )
            )
        ):
            raise QualificationError("Local microVM host requirements are invalid")

        artifacts = _exact_object(
            value.get("artifact_policy"),
            {"kernel", "base_rootfs", "ephemeral_overlay"},
            "Local microVM artifact policy",
        )
        kernel = _exact_object(
            artifacts.get("kernel"), {"path", "sha256", "content_pinned"}, "Kernel pin"
        )
        rootfs = _exact_object(
            artifacts.get("base_rootfs"),
            {"path", "sha256", "content_pinned", "read_only"},
            "Base root filesystem pin",
        )
        overlay = _exact_object(
            artifacts.get("ephemeral_overlay"),
            {"path", "maximum_bytes", "ephemeral", "remove_after_execution"},
            "Ephemeral overlay",
        )
        _absolute_posix_path(kernel.get("path"), "kernel path")
        _sha(kernel.get("sha256"), "kernel hash")
        _absolute_posix_path(rootfs.get("path"), "root filesystem path")
        _sha(rootfs.get("sha256"), "root filesystem hash")
        _absolute_posix_path(overlay.get("path"), "overlay path")
        if (
            kernel.get("content_pinned") is not True
            or rootfs.get("content_pinned") is not True
            or rootfs.get("read_only") is not True
            or overlay.get("ephemeral") is not True
            or overlay.get("remove_after_execution") is not True
        ):
            raise QualificationError("Local microVM filesystem policy is invalid")

        jailer = _exact_object(
            value.get("jailer_policy"),
            {
                "firecracker_path",
                "jailer_path",
                "chroot_base_dir",
                "service_identity_id",
                "uid",
                "gid",
                "dedicated_uid_gid_required",
                "seccomp_level",
                "new_pid_namespace",
                "daemonize",
            },
            "Local microVM jailer policy",
        )
        for field, label in (
            ("firecracker_path", "Firecracker executable path"),
            ("jailer_path", "jailer executable path"),
            ("chroot_base_dir", "jailer chroot base"),
        ):
            _absolute_posix_path(jailer.get(field), label)
        _text(jailer.get("service_identity_id"), "jailer service identity ID")
        _bounded_int(jailer.get("uid"), "jailer UID", 1000, 65535)
        _bounded_int(jailer.get("gid"), "jailer GID", 1000, 65535)
        if (
            jailer.get("dedicated_uid_gid_required") is not True
            or jailer.get("seccomp_level") != 2
            or jailer.get("new_pid_namespace") is not True
            or jailer.get("daemonize") is not False
        ):
            raise QualificationError("Local microVM jailer policy is invalid")

        machine = _exact_object(
            value.get("machine_configuration"),
            {
                "vcpu_count",
                "memory_mib",
                "smt",
                "track_dirty_pages",
                "boot_args",
                "single_tenant",
            },
            "Local microVM machine configuration",
        )
        resources = _exact_object(
            value.get("resource_limits"),
            {
                "vcpu_count",
                "cpu_millis",
                "memory_mib",
                "pid_limit",
                "output_bytes",
                "log_bytes",
                "timeout_seconds",
                "overlay_bytes",
            },
            "Local microVM resource limits",
        )
        limits = ContainmentLimits.from_dict(
            {
                "timeout_seconds": resources.get("timeout_seconds"),
                "memory_mib": resources.get("memory_mib"),
                "cpu_millis": resources.get("cpu_millis"),
                "process_count": resources.get("pid_limit"),
                "output_bytes": resources.get("output_bytes"),
                "workspace_bytes": resources.get("overlay_bytes"),
            }
        )
        vcpu_count = _bounded_int(resources.get("vcpu_count"), "microVM vCPU count", 1, 8)
        log_bytes = _bounded_int(
            resources.get("log_bytes"), "microVM log limit", 0, limits.output_bytes
        )
        if not _matches_native_projection(
            machine,
            {
                "vcpu_count": vcpu_count,
                "memory_mib": limits.memory_mib,
                "smt": False,
                "track_dirty_pages": False,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on",
                "single_tenant": True,
            },
        ) or not _matches_native_projection(overlay.get("maximum_bytes"), limits.workspace_bytes):
            raise QualificationError("Local microVM budgets are inconsistent")

        if not _matches_native_projection(
            value.get("network_policy"),
            {
                "mode": "deny_all",
                "interfaces": [],
                "tap_devices": [],
                "metadata_service": "disabled",
            },
        ):
            raise QualificationError("Local microVM network policy is invalid")
        if not _matches_native_projection(
            value.get("credential_policy"),
            {
                "mode": "deny_all",
                "allowed_references": [],
                "host_environment_forwarding": False,
            },
        ):
            raise QualificationError("Local microVM credential policy is invalid")
        if not _matches_native_projection(
            value.get("logging_policy"),
            {
                "mode": "bounded_capture",
                "maximum_bytes": log_bytes,
                "stdout": "bounded",
                "stderr": "bounded",
                "destination": "content_addressed_receipt_only",
            },
        ):
            raise QualificationError("Local microVM logging policy is invalid")
        if not _matches_native_projection(
            value.get("lifecycle_policy"), _lifecycle_policy(limits.timeout_seconds)
        ):
            raise QualificationError("Local microVM lifecycle policy is invalid")
        expected_argv = _jailer_argv(vm_id=vm_id, jailer_policy=jailer, resource_limits=resources)
        if not _matches_native_projection(value.get("jailer_argv"), expected_argv):
            raise QualificationError("Local microVM jailer arguments are invalid")
        _validate_content_address(
            value,
            identifier_field="spec_id",
            digest_field="spec_sha256",
            identifier_pattern=SPEC_ID_PATTERN,
            identifier_prefix="MVS-",
            domain=SPEC_DOMAIN,
            body_key="specification",
            label="Local microVM specification",
        )
        return cls(
            value["spec_id"],
            value["spec_sha256"],
            plan_id,
            value["plan_sha256"],
            limits,
            _canonical_json(value),
        )


class LocalMicrovmRuntimeAdapter(Protocol):
    """Future external executor interface. This module never calls it."""

    def execute(
        self,
        specification: LocalMicrovmExecutionSpec,
        host_preflight: ContainmentHostPreflightReport,
    ) -> dict[str, Any]:
        """Return an externally captured observation after separate admission."""

    def cancel(self, spec_id: str) -> bool:
        """Request fail-closed cancellation through the external control channel."""

    def teardown(self, spec_id: str) -> bool:
        """Request teardown and residual-effect verification externally."""


def build_local_microvm_execution_spec(
    *,
    plan: ContainmentExecutionPlan,
    binding: ContainmentBackendDeploymentBinding,
    vm_id: str,
    kernel_path: str,
    kernel_sha256: str,
    rootfs_path: str,
    rootfs_sha256: str,
    overlay_path: str,
    firecracker_path: str,
    jailer_path: str,
    chroot_base_dir: str,
    jailer_uid: int,
    jailer_gid: int,
    vcpu_count: int = 1,
    log_bytes: int = 262_144,
) -> LocalMicrovmExecutionSpec:
    """Construct an exact nonexecuting Firecracker-style specification."""

    _verify_plan(plan)
    binding_raw = _verify_binding(binding)
    if plan.backend_attestation_sha256 != binding_raw["backend_attestation_sha256"]:
        raise QualificationError("MicroVM plan and deployment binding attestations differ")
    vm_identifier = _text(vm_id, "microVM ID")
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", vm_identifier) is None:
        raise QualificationError("Local microVM ID is invalid")
    resources = _resource_limits(plan.limits, vcpu_count, log_bytes)
    artifacts = _artifact_policy(
        kernel_path=kernel_path,
        kernel_sha256=kernel_sha256,
        rootfs_path=rootfs_path,
        rootfs_sha256=rootfs_sha256,
        overlay_path=overlay_path,
        overlay_bytes=plan.limits.workspace_bytes,
    )
    jailer = _jailer_policy(
        firecracker_path=firecracker_path,
        jailer_path=jailer_path,
        chroot_base_dir=chroot_base_dir,
        service_identity_id=binding_raw["service_identity_id"],
        uid=jailer_uid,
        gid=jailer_gid,
    )
    body = {
        "schema_version": 1,
        "kind": "local_microvm_execution_spec",
        "runtime_kind": "jailed_firecracker",
        "runner_interface": "injected_executor_only",
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "invocation_sha256": plan.invocation_sha256,
        "backend_attestation_sha256": plan.backend_attestation_sha256,
        "deployment_binding_id": binding.binding_id,
        "deployment_binding_sha256": binding.binding_sha256,
        "isolation_class": "microvm",
        "vm_id": vm_identifier,
        "host_preflight_contract": _host_preflight_contract(binding_raw),
        "host_requirements": {
            "os_name": "linux",
            "architecture": binding_raw["architecture"],
            "kvm_device_path": "/dev/kvm",
            "kvm_access_required": True,
            "cgroup_version": "v2",
            "seccomp_required": True,
            "dedicated_uid_gid_required": True,
            "single_tenant_vm_required": True,
            "bounded_logging_required": True,
            "host_hardening_required": True,
        },
        "artifact_policy": artifacts,
        "jailer_policy": jailer,
        "machine_configuration": {
            "vcpu_count": resources["vcpu_count"],
            "memory_mib": resources["memory_mib"],
            "smt": False,
            "track_dirty_pages": False,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on",
            "single_tenant": True,
        },
        "resource_limits": resources,
        "network_policy": {
            "mode": "deny_all",
            "interfaces": [],
            "tap_devices": [],
            "metadata_service": "disabled",
        },
        "credential_policy": {
            "mode": "deny_all",
            "allowed_references": [],
            "host_environment_forwarding": False,
        },
        "logging_policy": {
            "mode": "bounded_capture",
            "maximum_bytes": resources["log_bytes"],
            "stdout": "bounded",
            "stderr": "bounded",
            "destination": "content_addressed_receipt_only",
        },
        "lifecycle_policy": _lifecycle_policy(plan.limits.timeout_seconds),
        "jailer_argv": _jailer_argv(
            vm_id=vm_identifier, jailer_policy=jailer, resource_limits=resources
        ),
        "status": "specification_pending_external_host_preflight_nonqualifying",
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": SPEC_DOMAIN, "specification": body})
    return LocalMicrovmExecutionSpec.from_dict(
        {
            **body,
            "spec_id": f"MVS-{digest.removeprefix('sha256:')[:32].upper()}",
            "spec_sha256": digest,
        }
    )


def validate_external_host_preflight(
    specification: LocalMicrovmExecutionSpec,
    report: ContainmentHostPreflightReport,
) -> None:
    """Validate a supplied external report without dispatching or changing state."""

    report_raw = _exact_object(
        report.to_dict(),
        {
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
        },
        "Containment host preflight",
    )
    _effects_are_none(report_raw, "Containment host preflight")
    contract = specification.to_dict()["host_preflight_contract"]
    if (
        report_raw.get("binding_id") != contract["binding_id"]
        or report_raw.get("binding_sha256") != contract["binding_sha256"]
        or report_raw.get("status") != contract["required_report_status"]
    ):
        raise QualificationError("External host preflight does not admit this microVM spec")
    body = {
        key: value for key, value in report_raw.items() if key not in {"report_id", "report_sha256"}
    }
    expected = _canonical_sha256({"domain": PREFLIGHT_DOMAIN, "report": body})
    expected_id = f"CHR-{expected.removeprefix('sha256:')[:32].upper()}"
    report_id = report_raw.get("report_id")
    if (
        not isinstance(report_id, str)
        or REPORT_ID_PATTERN.fullmatch(report_id) is None
        or report_raw.get("report_sha256") != expected
        or report_id != expected_id
    ):
        raise QualificationError("External host preflight identity does not match content")


@dataclass(frozen=True)
class LocalMicrovmContainmentObservation:
    observation_id: str
    observation_sha256: str
    observation_kind: str
    outcome: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalMicrovmContainmentObservation:
        fields = {
            "schema_version",
            "kind",
            "observation_id",
            "observation_sha256",
            "spec_id",
            "spec_sha256",
            "observation_kind",
            "outcome",
            "assertions",
            "host_preflight_passed",
            "runtime_execution_performed",
            "external_containment_proven",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local microVM observation")
        _effects_are_none(value, "Local microVM observation")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_microvm_containment_observation"
            or value.get("host_preflight_passed") is not False
            or value.get("runtime_execution_performed") is not False
            or value.get("external_containment_proven") is not False
        ):
            raise QualificationError("Local microVM observation boundary is invalid")
        kinds = {
            "specification_validation": "repository_validated_nonqualifying",
            "runtime_absence": "not_executed",
            "lifecycle_absence": "not_exercised",
            "qualification_boundary": "no_effect",
        }
        observation_kind = value.get("observation_kind")
        if (
            type(observation_kind) is not str
            or type(value.get("outcome")) is not str
            or kinds.get(observation_kind) != value.get("outcome")
        ):
            raise QualificationError("Local microVM observation outcome is invalid")
        assertions = value.get("assertions")
        if (
            type(assertions) is not list
            or not assertions
            or any(type(item) is not str or not item.isascii() for item in assertions)
            or assertions != sorted(set(assertions))
        ):
            raise QualificationError("Local microVM observation assertions are invalid")
        _sha(value.get("spec_sha256"), "local microVM observation specification hash")
        spec_id = value.get("spec_id")
        if type(spec_id) is not str or SPEC_ID_PATTERN.fullmatch(spec_id) is None:
            raise QualificationError("Local microVM observation specification ID is invalid")
        _validate_content_address(
            value,
            identifier_field="observation_id",
            digest_field="observation_sha256",
            identifier_pattern=OBSERVATION_ID_PATTERN,
            identifier_prefix="MVO-",
            domain=OBSERVATION_DOMAIN,
            body_key="observation",
            label="Local microVM observation",
        )
        return cls(
            value["observation_id"],
            value["observation_sha256"],
            observation_kind,
            value["outcome"],
            _canonical_json(value),
        )


def _build_observation(
    specification: LocalMicrovmExecutionSpec,
    observation_kind: str,
    outcome: str,
    assertions: tuple[str, ...],
) -> LocalMicrovmContainmentObservation:
    body = {
        "schema_version": 1,
        "kind": "local_microvm_containment_observation",
        "spec_id": specification.spec_id,
        "spec_sha256": specification.spec_sha256,
        "observation_kind": observation_kind,
        "outcome": outcome,
        "assertions": list(assertions),
        "host_preflight_passed": False,
        "runtime_execution_performed": False,
        "external_containment_proven": False,
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": OBSERVATION_DOMAIN, "observation": body})
    return LocalMicrovmContainmentObservation.from_dict(
        {
            **body,
            "observation_id": f"MVO-{digest.removeprefix('sha256:')[:32].upper()}",
            "observation_sha256": digest,
        }
    )


def _fixture_observations(
    specification: LocalMicrovmExecutionSpec,
) -> tuple[LocalMicrovmContainmentObservation, ...]:
    return (
        _build_observation(
            specification,
            "specification_validation",
            "repository_validated_nonqualifying",
            (
                "bounded_resources_encoded",
                "content_pinned_kernel_and_rootfs_encoded",
                "credentials_denied",
                "deny_all_network_encoded",
                "ephemeral_overlay_encoded",
                "jailer_and_seccomp_encoded",
                "single_tenant_vm_encoded",
            ),
        ),
        _build_observation(
            specification,
            "runtime_absence",
            "not_executed",
            (
                "credentials_not_accessed",
                "firecracker_not_invoked",
                "host_runtime_not_mutated",
                "jailer_not_invoked",
                "kvm_not_opened",
                "network_not_accessed",
            ),
        ),
        _build_observation(
            specification,
            "lifecycle_absence",
            "not_exercised",
            (
                "cancellation_not_requested",
                "residual_effects_not_observed",
                "teardown_not_performed",
            ),
        ),
        _build_observation(
            specification,
            "qualification_boundary",
            "no_effect",
            (
                "external_containment_not_proven",
                "host_preflight_not_passed",
                "qualification_unchanged",
                "target_authority_unchanged",
            ),
        ),
    )


@dataclass(frozen=True)
class LocalMicrovmContainmentFixtureReceipt:
    receipt_id: str
    receipt_sha256: str
    specification: LocalMicrovmExecutionSpec
    observations: tuple[LocalMicrovmContainmentObservation, ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalMicrovmContainmentFixtureReceipt:
        fields = {
            "schema_version",
            "kind",
            "receipt_id",
            "receipt_sha256",
            "specification",
            "observations",
            "status",
            "host_preflight_passed",
            "runtime_execution_performed",
            "external_containment_proven",
            "cancellation_requested",
            "teardown_status",
            "residual_effect_observation_status",
            "residual_effects",
            "output_bytes",
            "log_bytes",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local microVM fixture receipt")
        _effects_are_none(value, "Local microVM fixture receipt")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_microvm_containment_fixture_receipt"
            or value.get("status") != "deterministic_repository_fixture_nonqualifying"
            or value.get("host_preflight_passed") is not False
            or value.get("runtime_execution_performed") is not False
            or value.get("external_containment_proven") is not False
            or value.get("cancellation_requested") is not False
            or value.get("teardown_status") != "not_started"
            or value.get("residual_effect_observation_status") != "not_observed"
            or value.get("residual_effects") != []
            or type(value.get("output_bytes")) is not int
            or value.get("output_bytes") != 0
            or type(value.get("log_bytes")) is not int
            or value.get("log_bytes") != 0
        ):
            raise QualificationError("Local microVM fixture receipt boundary is invalid")
        specification = LocalMicrovmExecutionSpec.from_dict(value.get("specification"))
        observations_raw = value.get("observations")
        if type(observations_raw) is not list:
            raise QualificationError("Local microVM observations must be a list")
        observations = tuple(
            LocalMicrovmContainmentObservation.from_dict(item) for item in observations_raw
        )
        if observations != _fixture_observations(specification):
            raise QualificationError("Local microVM fixture observations are not canonical")
        _validate_content_address(
            value,
            identifier_field="receipt_id",
            digest_field="receipt_sha256",
            identifier_pattern=RECEIPT_ID_PATTERN,
            identifier_prefix="MVR-",
            domain=RECEIPT_DOMAIN,
            body_key="receipt",
            label="Local microVM fixture receipt",
        )
        return cls(
            value["receipt_id"],
            value["receipt_sha256"],
            specification,
            observations,
            _canonical_json(value),
        )


def build_local_microvm_containment_fixture(
    specification: LocalMicrovmExecutionSpec,
) -> LocalMicrovmContainmentFixtureReceipt:
    """Build a deterministic receipt that proves only repository validation."""

    verified = LocalMicrovmExecutionSpec.from_dict(specification.to_dict())
    observations = _fixture_observations(verified)
    body = {
        "schema_version": 1,
        "kind": "local_microvm_containment_fixture_receipt",
        "specification": verified.to_dict(),
        "observations": [item.to_dict() for item in observations],
        "status": "deterministic_repository_fixture_nonqualifying",
        "host_preflight_passed": False,
        "runtime_execution_performed": False,
        "external_containment_proven": False,
        "cancellation_requested": False,
        "teardown_status": "not_started",
        "residual_effect_observation_status": "not_observed",
        "residual_effects": [],
        "output_bytes": 0,
        "log_bytes": 0,
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
    return LocalMicrovmContainmentFixtureReceipt.from_dict(
        {
            **body,
            "receipt_id": f"MVR-{digest.removeprefix('sha256:')[:32].upper()}",
            "receipt_sha256": digest,
        }
    )


__all__ = [
    "LocalMicrovmContainmentFixtureReceipt",
    "LocalMicrovmContainmentObservation",
    "LocalMicrovmExecutionSpec",
    "LocalMicrovmRuntimeAdapter",
    "build_local_microvm_containment_fixture",
    "build_local_microvm_execution_spec",
    "validate_external_host_preflight",
]
