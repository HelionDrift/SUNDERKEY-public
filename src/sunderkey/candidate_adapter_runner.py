"""Fail-closed containment admission and receipt contracts for candidate adapters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .candidate_adapter_sdk import (
    AdapterInvocation,
    AdapterManifest,
    AdapterResult,
    validate_reference_invocation,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

ATTESTATION_DOMAIN = "sunderkey.adapter-containment-attestation.v1"
PLAN_DOMAIN = "sunderkey.adapter-containment-plan.v1"
RECEIPT_DOMAIN = "sunderkey.adapter-containment-receipt.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
BACKEND_ID_PATTERN = re.compile(r"containment\.[a-z0-9]+(?:[.-][a-z0-9]+)*")
PLAN_ID_PATTERN = re.compile(r"CEP-[0-9A-F]{32}")
RECEIPT_ID_PATTERN = re.compile(r"CER-[0-9A-F]{32}")
ISOLATION_RANK = {"oci_container": 1, "microvm": 2}
COMMON_GUARANTEES = {
    "capabilities_dropped",
    "cancellation_enforced",
    "cpu_ceiling_enforced",
    "credential_deny_enforced",
    "deadline_enforced",
    "external_boundary",
    "memory_ceiling_enforced",
    "network_deny_enforced",
    "no_new_privileges",
    "output_ceiling_enforced",
    "process_ceiling_enforced",
    "read_only_rootfs",
    "workspace_ephemeral",
}
OCI_GUARANTEES = COMMON_GUARANTEES | {"rootless", "seccomp", "user_namespace"}
MICROVM_GUARANTEES = COMMON_GUARANTEES | {
    "dedicated_uid_gid",
    "hardware_virtualization",
    "jailer",
    "seccomp",
    "single_tenant_vm",
}


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _utc(value: Any, label: str) -> datetime:
    text = _text(value, label)
    if not text.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return parsed


@dataclass(frozen=True)
class ContainmentLimits:
    timeout_seconds: int = 60
    memory_mib: int = 256
    cpu_millis: int = 1000
    process_count: int = 16
    output_bytes: int = 1_048_576
    workspace_bytes: int = 16_777_216

    def __post_init__(self) -> None:
        values = {
            "timeout_seconds": (self.timeout_seconds, 1, 3600),
            "memory_mib": (self.memory_mib, 64, 4096),
            "cpu_millis": (self.cpu_millis, 100, 60_000),
            "process_count": (self.process_count, 1, 64),
            "output_bytes": (self.output_bytes, 1024, 16_777_216),
            "workspace_bytes": (self.workspace_bytes, 4096, 268_435_456),
        }
        for label, (value, minimum, maximum) in values.items():
            if type(value) is not int or not minimum <= value <= maximum:
                raise QualificationError(f"Containment {label} is outside the allowed range")

    def to_dict(self) -> dict[str, int]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "memory_mib": self.memory_mib,
            "cpu_millis": self.cpu_millis,
            "process_count": self.process_count,
            "output_bytes": self.output_bytes,
            "workspace_bytes": self.workspace_bytes,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ContainmentLimits:
        expected = {
            "timeout_seconds",
            "memory_mib",
            "cpu_millis",
            "process_count",
            "output_bytes",
            "workspace_bytes",
        }
        if (
            type(raw) is not dict
            or any(type(key) is not str for key in raw)
            or set(raw) != expected
        ):
            raise QualificationError("Containment limit fields are invalid")
        return cls(**raw)


@dataclass(frozen=True)
class ContainmentBackendAttestation:
    backend_id: str
    backend_version: str
    isolation_class: str
    executable_sha256: str
    configuration_sha256: str
    source_url: str
    license_spdx: str
    host_os: str
    guarantees: tuple[str, ...]
    attestation_sha256: str
    document_json: str

    @classmethod
    def build(
        cls,
        *,
        backend_id: str,
        backend_version: str,
        isolation_class: str,
        executable_sha256: str,
        configuration_sha256: str,
        source_url: str,
        license_spdx: str,
        host_os: str,
        guarantees: tuple[str, ...],
    ) -> ContainmentBackendAttestation:
        if BACKEND_ID_PATTERN.fullmatch(backend_id) is None:
            raise QualificationError("Containment backend ID is invalid")
        if isolation_class not in ISOLATION_RANK:
            raise QualificationError("Containment isolation class is invalid")
        if host_os != "linux":
            raise QualificationError("Containment backend host must be linux")
        _sha(executable_sha256, "containment executable hash")
        _sha(configuration_sha256, "containment configuration hash")
        for value, label in (
            (backend_version, "containment backend version"),
            (source_url, "containment backend source URL"),
            (license_spdx, "containment backend license"),
        ):
            _text(value, label)
        if tuple(sorted(set(guarantees))) != guarantees:
            raise QualificationError("Containment guarantees must be sorted and unique")
        required = OCI_GUARANTEES if isolation_class == "oci_container" else MICROVM_GUARANTEES
        if not required.issubset(guarantees):
            raise QualificationError("Containment backend guarantees are incomplete")
        body = {
            "backend_id": backend_id,
            "backend_version": backend_version,
            "isolation_class": isolation_class,
            "executable_sha256": executable_sha256,
            "configuration_sha256": configuration_sha256,
            "source_url": source_url,
            "license_spdx": license_spdx,
            "host_os": host_os,
            "guarantees": list(guarantees),
        }
        digest = _canonical_sha256({"domain": ATTESTATION_DOMAIN, "attestation": body})
        return cls(
            backend_id,
            backend_version,
            isolation_class,
            executable_sha256,
            configuration_sha256,
            source_url,
            license_spdx,
            host_os,
            guarantees,
            digest,
            _canonical_json({**body, "attestation_sha256": digest}),
        )

    @classmethod
    def from_dict(cls, raw: Any) -> ContainmentBackendAttestation:
        expected = {
            "backend_id",
            "backend_version",
            "isolation_class",
            "executable_sha256",
            "configuration_sha256",
            "source_url",
            "license_spdx",
            "host_os",
            "guarantees",
            "attestation_sha256",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise QualificationError("Containment attestation fields are invalid")
        guarantees = raw.get("guarantees")
        if not isinstance(guarantees, list):
            raise QualificationError("Containment guarantees must be a list")
        rebuilt = cls.build(
            backend_id=raw.get("backend_id"),
            backend_version=raw.get("backend_version"),
            isolation_class=raw.get("isolation_class"),
            executable_sha256=raw.get("executable_sha256"),
            configuration_sha256=raw.get("configuration_sha256"),
            source_url=raw.get("source_url"),
            license_spdx=raw.get("license_spdx"),
            host_os=raw.get("host_os"),
            guarantees=tuple(guarantees),
        )
        if rebuilt.attestation_sha256 != raw.get("attestation_sha256"):
            raise QualificationError("Containment attestation hash does not match content")
        return rebuilt

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


@dataclass(frozen=True)
class ContainmentExecutionPlan:
    plan_id: str
    plan_sha256: str
    adapter_id: str
    manifest_sha256: str
    invocation_sha256: str
    backend_attestation_sha256: str
    isolation_class: str
    limits: ContainmentLimits
    issued_at: str
    expires_at: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        manifest: AdapterManifest,
        invocation: AdapterInvocation,
        attestation: ContainmentBackendAttestation,
    ) -> ContainmentExecutionPlan:
        if type(raw) is not dict or any(type(key) is not str for key in raw):
            raise QualificationError("Containment plan must be an object")
        if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
            raise QualificationError("Containment plan schema version is invalid")
        limits = ContainmentLimits.from_dict(raw.get("limits"))
        rebuilt = prepare_containment_execution_plan(
            manifest,
            invocation,
            attestation,
            limits,
            issued_at=raw.get("issued_at"),
            expires_at=raw.get("expires_at"),
        )
        expected = rebuilt.to_dict()
        if not _matches_native_json_shape(raw, expected) or _canonical_json(raw) != _canonical_json(
            expected
        ):
            raise QualificationError("Containment plan does not match admitted inputs")
        return rebuilt


def _matches_native_json_shape(value: Any, expected: Any) -> bool:
    """Check native types against the finite reconstructed plan shape."""

    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return (
            all(type(key) is str for key in value)
            and set(value) == set(expected)
            and all(_matches_native_json_shape(value[key], item) for key, item in expected.items())
        )
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _matches_native_json_shape(item, expected_item)
            for item, expected_item in zip(value, expected, strict=True)
        )
    return type(expected) in {str, int, bool, float, type(None)}


def _invocation_body(invocation: AdapterInvocation) -> dict[str, Any]:
    return {
        "invocation_id": invocation.invocation_id,
        "mission_id": invocation.mission_id,
        "authority_ref": invocation.authority_ref,
        "profile_id": invocation.profile_id,
        "vector_id": invocation.vector_id,
        "target_id": invocation.target_id,
        "scope_id": invocation.scope_id,
        "action_tier": invocation.action_tier,
        "environment": invocation.environment,
        "dry_run": invocation.dry_run,
        "credential_refs": list(invocation.credential_refs),
        "input_data": dict(invocation.input_data),
    }


def prepare_containment_execution_plan(
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    limits: ContainmentLimits,
    *,
    issued_at: str,
    expires_at: str,
) -> ContainmentExecutionPlan:
    """Bind one admitted invocation to an independently attested backend."""

    validate_reference_invocation(manifest, invocation)
    issued = _utc(issued_at, "containment plan issued_at")
    expires = _utc(expires_at, "containment plan expires_at")
    if expires <= issued or (expires - issued).total_seconds() > limits.timeout_seconds:
        raise QualificationError("Containment plan validity exceeds its timeout")
    if ISOLATION_RANK[attestation.isolation_class] < ISOLATION_RANK[manifest.required_isolation]:
        raise QualificationError("Containment backend isolation is below the manifest requirement")
    if not manifest.resource_policy.is_deny_all:
        raise QualificationError("Phase 157 containment plans require deny-all resources")
    invocation_sha256 = _canonical_sha256(
        {"domain": "sunderkey.adapter-invocation.v1", "invocation": _invocation_body(invocation)}
    )
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "adapter_version": manifest.adapter_version,
        "profile_id": manifest.profile_id,
        "vector_id": manifest.vector_id,
        "manifest_sha256": manifest.manifest_sha256,
        "invocation_sha256": invocation_sha256,
        "backend_id": attestation.backend_id,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "isolation_class": attestation.isolation_class,
        "resource_policy": manifest.resource_policy.to_dict(),
        "limits": limits.to_dict(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "execution_mode": "external_isolation_required",
        "result_channel": "content_addressed_json_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": PLAN_DOMAIN, "plan": body})
    plan_id = f"CEP-{digest.removeprefix('sha256:')[:32].upper()}"
    document = {**body, "plan_id": plan_id, "plan_sha256": digest}
    return ContainmentExecutionPlan(
        plan_id,
        digest,
        manifest.adapter_id,
        manifest.manifest_sha256,
        invocation_sha256,
        attestation.attestation_sha256,
        attestation.isolation_class,
        limits,
        issued_at,
        expires_at,
        _canonical_json(document),
    )


@dataclass(frozen=True)
class BackendExecutionReport:
    plan_id: str
    backend_attestation_sha256: str
    started_at: str
    finished_at: str
    output_bytes: int
    timed_out: bool
    cancelled: bool
    result: AdapterResult


class ContainmentBackend(Protocol):
    attestation: ContainmentBackendAttestation

    def execute(
        self,
        plan: ContainmentExecutionPlan,
        invocation: AdapterInvocation,
    ) -> BackendExecutionReport:
        """Execute through the externally enforced boundary."""

    def cancel(self, plan_id: str) -> bool:
        """Request cancellation through the externally enforced boundary."""


@dataclass(frozen=True)
class ContainmentExecutionReceipt:
    receipt_id: str
    receipt_sha256: str
    plan_id: str
    result_sha256: str
    run_status: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        plan: ContainmentExecutionPlan,
    ) -> ContainmentExecutionReceipt:
        expected = {
            "schema_version",
            "plan_id",
            "plan_sha256",
            "backend_attestation_sha256",
            "invocation_sha256",
            "result_sha256",
            "result_status",
            "result_disposition",
            "restoration_status",
            "residual_effects",
            "started_at",
            "finished_at",
            "duration_seconds",
            "output_bytes",
            "timed_out",
            "cancelled",
            "run_status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
            "receipt_id",
            "receipt_sha256",
        }
        if (
            type(raw) is not dict
            or any(type(key) is not str for key in raw)
            or set(raw) != expected
        ):
            raise QualificationError("Containment receipt fields are invalid")
        if (
            raw.get("schema_version") != 1
            or raw.get("plan_id") != plan.plan_id
            or raw.get("plan_sha256") != plan.plan_sha256
            or raw.get("backend_attestation_sha256") != plan.backend_attestation_sha256
            or raw.get("invocation_sha256") != plan.invocation_sha256
        ):
            raise QualificationError("Containment receipt plan binding is invalid")
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            if raw.get(field) != "none":
                raise QualificationError("Containment receipt operational effect is invalid")
        _validate_receipt_execution(raw, plan)
        result_sha256 = _sha(raw.get("result_sha256"), "containment result hash")
        receipt_sha256 = _sha(raw.get("receipt_sha256"), "containment receipt hash")
        receipt_id = _text(raw.get("receipt_id"), "containment receipt ID")
        if RECEIPT_ID_PATTERN.fullmatch(receipt_id) is None:
            raise QualificationError("Containment receipt ID is invalid")
        body = {
            key: value for key, value in raw.items() if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
        expected_id = f"CER-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if receipt_sha256 != expected_sha256 or receipt_id != expected_id:
            raise QualificationError("Containment receipt identity does not match content")
        return cls(
            receipt_id,
            receipt_sha256,
            plan.plan_id,
            result_sha256,
            _text(raw.get("run_status"), "containment run status"),
            _canonical_json(raw),
        )


def _validate_receipt_execution(raw: dict[str, Any], plan: ContainmentExecutionPlan) -> None:
    """Replay the producer's execution guarantees without a current-time test."""

    integer_fields = {"schema_version", "duration_seconds", "output_bytes"}
    boolean_fields = {"timed_out", "cancelled"}
    for field, value in raw.items():
        if field in integer_fields:
            if type(value) is not int:
                raise QualificationError(f"Containment receipt {field} must be a native integer")
        elif field in boolean_fields:
            if type(value) is not bool:
                raise QualificationError(f"Containment receipt {field} must be a native boolean")
        elif field != "residual_effects" and type(value) is not str:
            raise QualificationError(f"Containment receipt {field} must be native text")
    if raw["schema_version"] != 1:
        raise QualificationError("Containment receipt schema version is invalid")
    if raw["result_status"] not in {"completed", "abstained", "cancelled", "failed_closed"}:
        raise QualificationError("Containment receipt result status is invalid")
    if raw["result_disposition"] not in {
        "verified_finding",
        "negative_result",
        "hypothesis",
        "abstention",
    }:
        raise QualificationError("Containment receipt result disposition is invalid")
    if raw["restoration_status"] not in {"not_required", "verified", "failed_closed"}:
        raise QualificationError("Containment receipt restoration status is invalid")
    residual_effects = raw["residual_effects"]
    if type(residual_effects) is not list or any(
        type(item) is not str for item in residual_effects
    ):
        raise QualificationError("Containment receipt residual effects must be native text entries")
    for item in residual_effects:
        _text(item, "containment residual effect")
    started = _utc(raw["started_at"], "containment report started_at")
    finished = _utc(raw["finished_at"], "containment report finished_at")
    if finished < started:
        raise QualificationError("Containment backend report times are invalid")
    if started < _utc(plan.issued_at, "containment plan issued_at") or finished > _utc(
        plan.expires_at, "containment plan expires_at"
    ):
        raise QualificationError("Containment backend report exceeded the plan validity window")
    duration = int((finished - started).total_seconds())
    if raw["duration_seconds"] != duration:
        raise QualificationError("Containment receipt duration does not match execution times")
    if duration > plan.limits.timeout_seconds and not raw["timed_out"]:
        raise QualificationError("Containment backend failed to enforce the deadline")
    if not 0 <= raw["output_bytes"] <= plan.limits.output_bytes:
        raise QualificationError("Containment backend output exceeded the plan ceiling")
    if raw["timed_out"] and raw["result_status"] not in {"cancelled", "failed_closed"}:
        raise QualificationError("Timed-out containment result did not fail closed")
    if raw["cancelled"] and raw["result_status"] not in {"cancelled", "failed_closed"}:
        raise QualificationError("Cancelled containment result did not fail closed")
    expected_run_status = "completed_nonqualifying"
    if raw["timed_out"]:
        expected_run_status = "timed_out_fail_closed"
    elif raw["cancelled"]:
        expected_run_status = "cancelled_fail_closed"
    if raw["run_status"] != expected_run_status:
        raise QualificationError("Containment receipt run status contradicts its execution flags")


def execute_contained_adapter(
    backend: ContainmentBackend,
    plan: ContainmentExecutionPlan,
    invocation: AdapterInvocation,
    *,
    observed_at: str,
) -> ContainmentExecutionReceipt:
    """Execute one prepared plan and reject unverifiable backend behavior."""

    now = _utc(observed_at, "containment observed_at")
    if now < _utc(plan.issued_at, "containment plan issued_at"):
        raise QualificationError("Containment plan is not yet valid")
    if now >= _utc(plan.expires_at, "containment plan expires_at"):
        raise QualificationError("Containment plan has expired")
    if backend.attestation.attestation_sha256 != plan.backend_attestation_sha256:
        raise QualificationError("Containment backend attestation does not match the plan")
    invocation_sha256 = _canonical_sha256(
        {"domain": "sunderkey.adapter-invocation.v1", "invocation": _invocation_body(invocation)}
    )
    if invocation_sha256 != plan.invocation_sha256:
        raise QualificationError("Containment invocation does not match the plan")
    report = backend.execute(plan, invocation)
    if report.plan_id != plan.plan_id:
        raise QualificationError("Containment backend report plan does not match")
    if report.backend_attestation_sha256 != plan.backend_attestation_sha256:
        raise QualificationError("Containment backend report attestation does not match")
    started = _utc(report.started_at, "containment report started_at")
    finished = _utc(report.finished_at, "containment report finished_at")
    duration = int((finished - started).total_seconds())
    run_status = "completed_nonqualifying"
    if report.timed_out is True:
        run_status = "timed_out_fail_closed"
    elif report.cancelled is True:
        run_status = "cancelled_fail_closed"
    body = {
        "schema_version": 1,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "backend_attestation_sha256": plan.backend_attestation_sha256,
        "invocation_sha256": plan.invocation_sha256,
        "result_sha256": report.result.result_sha256,
        "result_status": report.result.status,
        "result_disposition": report.result.disposition,
        "restoration_status": report.result.restoration_status,
        "residual_effects": list(report.result.residual_effects),
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "duration_seconds": duration,
        "output_bytes": report.output_bytes,
        "timed_out": report.timed_out,
        "cancelled": report.cancelled,
        "run_status": run_status,
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    _validate_receipt_execution(body, plan)
    digest = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
    receipt_id = f"CER-{digest.removeprefix('sha256:')[:32].upper()}"
    return ContainmentExecutionReceipt(
        receipt_id,
        digest,
        plan.plan_id,
        report.result.result_sha256,
        run_status,
        _canonical_json({**body, "receipt_id": receipt_id, "receipt_sha256": digest}),
    )


def load_containment_backend_attestation(
    source: str | Path,
) -> ContainmentBackendAttestation:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load containment attestation: {source}") from exc
    return ContainmentBackendAttestation.from_dict(raw)


def load_containment_execution_plan(
    source: str | Path,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
) -> ContainmentExecutionPlan:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load containment plan: {source}") from exc
    return ContainmentExecutionPlan.from_dict(raw, manifest, invocation, attestation)


def load_containment_execution_receipt(
    source: str | Path,
    plan: ContainmentExecutionPlan,
) -> ContainmentExecutionReceipt:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load containment receipt: {source}") from exc
    return ContainmentExecutionReceipt.from_dict(raw, plan)


__all__ = [
    "BackendExecutionReport",
    "COMMON_GUARANTEES",
    "ContainmentBackend",
    "ContainmentBackendAttestation",
    "ContainmentExecutionPlan",
    "ContainmentExecutionReceipt",
    "ContainmentLimits",
    "MICROVM_GUARANTEES",
    "OCI_GUARANTEES",
    "execute_contained_adapter",
    "load_containment_backend_attestation",
    "load_containment_execution_plan",
    "load_containment_execution_receipt",
    "prepare_containment_execution_plan",
]
