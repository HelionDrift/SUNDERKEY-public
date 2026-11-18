"""Repository-only rootless OCI containment specifications and fixtures."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .candidate_adapter_runner import (
    ContainmentBackendAttestation,
    ContainmentExecutionPlan,
    ContainmentLimits,
)
from .candidate_adapter_sdk import AdapterInvocation, AdapterManifest
from .candidate_backend_conformance import ContainmentConformanceSuiteCatalog
from .candidate_backend_host_preflight import (
    ContainmentBackendDeploymentBinding,
    ContainmentHostPreflightReport,
    ContainmentHostSnapshot,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

SPEC_DOMAIN = "sunderkey.local-oci-execution-spec.v1"
OBSERVATION_DOMAIN = "sunderkey.local-oci-containment-observation.v1"
FIXTURE_DOMAIN = "sunderkey.local-oci-containment-fixture.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_REFERENCE_PATTERN = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    r"@sha256:[0-9a-f]{64}"
)
SPEC_ID_PATTERN = re.compile(r"OCS-[0-9A-F]{32}")
OBSERVATION_ID_PATTERN = re.compile(r"OCO-[0-9A-F]{32}")
FIXTURE_ID_PATTERN = re.compile(r"OCF-[0-9A-F]{32}")
PLAN_ID_PATTERN = re.compile(r"CEP-[0-9A-F]{32}")
BINDING_ID_PATTERN = re.compile(r"CBD-[0-9A-F]{32}")
PREFLIGHT_ID_PATTERN = re.compile(r"CHR-[0-9A-F]{32}")
ASSERTION_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,95}")
SECCOMP_PROFILE_PATH = "/etc/sunderkey/containment/seccomp-v1.json"
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


def _image_reference(value: Any) -> tuple[str, str]:
    if type(value) is not str or IMAGE_REFERENCE_PATTERN.fullmatch(value) is None:
        raise QualificationError("OCI image reference must be registry qualified and digest pinned")
    return value, value.rsplit("@", 1)[1]


def _security_policy(seccomp_profile_sha256: str) -> dict[str, Any]:
    return {
        "rootless": True,
        "rootfs_read_only": True,
        "capability_drop": ["ALL"],
        "no_new_privileges": True,
        "user_namespace": "auto:size=65536",
        "container_user": "65532:65532",
        "seccomp_profile_path": SECCOMP_PROFILE_PATH,
        "seccomp_profile_sha256": seccomp_profile_sha256,
        "network_mode": "none",
        "credential_mode": "deny_all",
        "host_devices": [],
        "host_bind_mounts": [],
    }


def _workspace_policy(limits: ContainmentLimits) -> dict[str, Any]:
    return {
        "path": "/workspace",
        "storage": "tmpfs",
        "ephemeral": True,
        "executable": False,
        "device_nodes": False,
        "setuid_allowed": False,
        "maximum_bytes": limits.workspace_bytes,
        "cleanup_required": True,
    }


def _cancellation_policy() -> dict[str, Any]:
    return {
        "required": True,
        "signal": "SIGKILL",
        "grace_seconds": 1,
        "fail_closed": True,
    }


def _cleanup_policy() -> dict[str, Any]:
    return {
        "remove_container": True,
        "remove_workspace": True,
        "verify_no_residuals": True,
        "failure_disposition": "failed_closed",
    }


def _observation_policy(limits: ContainmentLimits) -> dict[str, Any]:
    return {
        "format": "content_addressed_json_only",
        "maximum_output_bytes": limits.output_bytes,
        "runtime_stdout": "disabled",
        "runtime_stderr": "bounded_capture",
        "external_verification_required": True,
    }


def _environment() -> list[str]:
    return [
        "HOME=/nonexistent",
        "LANG=C.UTF-8",
        "NETRC=/dev/null",
        "XDG_CONFIG_HOME=/nonexistent",
    ]


def _command_argv(
    *,
    plan_id: str,
    image_reference: str,
    seccomp_profile_path: str,
    limits: ContainmentLimits,
) -> list[str]:
    container_name = f"sunderkey-{plan_id.removeprefix('CEP-')[:24].lower()}"
    cpu_count = f"{limits.cpu_millis / 1000:.3f}"
    return [
        "podman",
        "run",
        "--rm=true",
        "--pull=never",
        "--network=none",
        "--read-only=true",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp_profile_path}",
        "--userns=auto:size=65536",
        "--user=65532:65532",
        "--pid=private",
        "--ipc=private",
        "--cgroupns=private",
        f"--pids-limit={limits.process_count}",
        f"--memory={limits.memory_mib}m",
        f"--memory-swap={limits.memory_mib}m",
        f"--cpus={cpu_count}",
        "--log-driver=none",
        "--stop-timeout=1",
        f"--name={container_name}",
        *[f"--env={item}" for item in _environment()],
        (f"--tmpfs=/workspace:rw,noexec,nosuid,nodev,size={limits.workspace_bytes}"),
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216",
        image_reference,
        "--request=/workspace/request.json",
        "--response=/workspace/response.json",
    ]


@dataclass(frozen=True)
class LocalOciExecutionSpec:
    spec_id: str
    spec_sha256: str
    plan_id: str
    plan_sha256: str
    command_argv: tuple[str, ...]
    limits: ContainmentLimits
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalOciExecutionSpec:
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
            "host_preflight_report_id",
            "host_preflight_report_sha256",
            "isolation_class",
            "image_reference",
            "image_digest",
            "security_policy",
            "environment",
            "workspace_policy",
            "limits",
            "cancellation_policy",
            "cleanup_policy",
            "observation_policy",
            "command_argv",
            "status",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local OCI execution specification")
        _effects_are_none(value, "Local OCI execution specification")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_oci_execution_spec"
            or value.get("runtime_kind") != "rootless_podman"
            or value.get("runner_interface") != "injected_adapter_only"
            or value.get("isolation_class") != "oci_container"
            or value.get("status") != "specification_ready_nonqualifying"
        ):
            raise QualificationError("Local OCI execution specification boundary is invalid")
        for field in (
            "plan_sha256",
            "invocation_sha256",
            "backend_attestation_sha256",
            "deployment_binding_sha256",
            "host_preflight_report_sha256",
            "image_digest",
        ):
            _sha(value.get(field), field)
        for field, pattern in (
            ("plan_id", PLAN_ID_PATTERN),
            ("deployment_binding_id", BINDING_ID_PATTERN),
            ("host_preflight_report_id", PREFLIGHT_ID_PATTERN),
        ):
            identifier = value.get(field)
            if not isinstance(identifier, str) or pattern.fullmatch(identifier) is None:
                raise QualificationError(f"Local OCI {field} is invalid")
        image_reference, image_digest = _image_reference(value.get("image_reference"))
        if value.get("image_digest") != image_digest:
            raise QualificationError("OCI image digest does not match the image reference")
        limits = ContainmentLimits.from_dict(value.get("limits"))
        security = _exact_object(
            value.get("security_policy"),
            {
                "rootless",
                "rootfs_read_only",
                "capability_drop",
                "no_new_privileges",
                "user_namespace",
                "container_user",
                "seccomp_profile_path",
                "seccomp_profile_sha256",
                "network_mode",
                "credential_mode",
                "host_devices",
                "host_bind_mounts",
            },
            "Local OCI security policy",
        )
        seccomp_sha256 = _sha(security.get("seccomp_profile_sha256"), "seccomp profile hash")
        if not _matches_native_projection(security, _security_policy(seccomp_sha256)):
            raise QualificationError("Local OCI security policy is invalid")
        if not _matches_native_projection(value.get("environment"), _environment()):
            raise QualificationError("Local OCI environment allowlist is invalid")
        if not _matches_native_projection(value.get("workspace_policy"), _workspace_policy(limits)):
            raise QualificationError("Local OCI workspace policy is invalid")
        if not _matches_native_projection(value.get("cancellation_policy"), _cancellation_policy()):
            raise QualificationError("Local OCI cancellation policy is invalid")
        if not _matches_native_projection(value.get("cleanup_policy"), _cleanup_policy()):
            raise QualificationError("Local OCI cleanup policy is invalid")
        if not _matches_native_projection(
            value.get("observation_policy"), _observation_policy(limits)
        ):
            raise QualificationError("Local OCI observation policy is invalid")
        argv = _command_argv(
            plan_id=value.get("plan_id"),
            image_reference=image_reference,
            seccomp_profile_path=security["seccomp_profile_path"],
            limits=limits,
        )
        if not _matches_native_projection(value.get("command_argv"), argv):
            raise QualificationError("Local OCI command arguments are invalid")
        spec_sha256 = _sha(value.get("spec_sha256"), "local OCI specification hash")
        spec_id = value.get("spec_id")
        if not isinstance(spec_id, str) or SPEC_ID_PATTERN.fullmatch(spec_id) is None:
            raise QualificationError("Local OCI specification ID is invalid")
        body = {key: item for key, item in value.items() if key not in {"spec_id", "spec_sha256"}}
        expected_sha256 = _canonical_sha256({"domain": SPEC_DOMAIN, "specification": body})
        expected_id = f"OCS-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if spec_sha256 != expected_sha256 or spec_id != expected_id:
            raise QualificationError("Local OCI specification identity does not match content")
        return cls(
            spec_id,
            spec_sha256,
            value["plan_id"],
            value["plan_sha256"],
            tuple(argv),
            limits,
            _canonical_json(value),
        )


class LocalOciRuntimeAdapter(Protocol):
    """Future host adapter interface. This module never calls this protocol."""

    def execute(self, specification: LocalOciExecutionSpec) -> dict[str, Any]:
        """Return an externally captured, content-addressed observation."""

    def cancel(self, spec_id: str) -> bool:
        """Request fail-closed cancellation from an external runtime."""

    def cleanup(self, spec_id: str) -> bool:
        """Request cleanup verification from an external runtime."""


def _validate_source_contracts(
    *,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    plan: ContainmentExecutionPlan,
    catalog: ContainmentConformanceSuiteCatalog,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
) -> None:
    if ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation:
        raise QualificationError("Local OCI attestation is not canonical")
    if (
        ContainmentExecutionPlan.from_dict(plan.to_dict(), manifest, invocation, attestation)
        != plan
    ):
        raise QualificationError("Local OCI plan is not canonical")
    if (
        ContainmentBackendDeploymentBinding.from_dict(binding.to_dict(), catalog, attestation)
        != binding
    ):
        raise QualificationError("Local OCI deployment binding is not canonical")
    if ContainmentHostSnapshot.from_dict(snapshot.to_dict()) != snapshot:
        raise QualificationError("Local OCI host snapshot is not canonical")
    if (
        ContainmentHostPreflightReport.from_dict(
            preflight.to_dict(), binding, snapshot, catalog, attestation
        )
        != preflight
    ):
        raise QualificationError("Local OCI host preflight is not canonical")
    if (
        attestation.isolation_class != "oci_container"
        or plan.isolation_class != "oci_container"
        or binding.isolation_class != "oci_container"
    ):
        raise QualificationError("Local OCI adapter requires OCI containment contracts")
    if preflight.status != "ready_for_dynamic_conformance_nonqualifying":
        raise QualificationError("Local OCI adapter requires a passing host preflight")
    if plan.backend_attestation_sha256 != attestation.attestation_sha256:
        raise QualificationError("Local OCI plan attestation binding is invalid")


def build_local_oci_execution_spec(
    *,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    plan: ContainmentExecutionPlan,
    catalog: ContainmentConformanceSuiteCatalog,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    image_reference: str,
    seccomp_profile_sha256: str,
) -> LocalOciExecutionSpec:
    """Construct an exact nonexecuting rootless Podman specification."""

    _validate_source_contracts(
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        plan=plan,
        catalog=catalog,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
    )
    image, image_digest = _image_reference(image_reference)
    seccomp_digest = _sha(seccomp_profile_sha256, "seccomp profile hash")
    body = {
        "schema_version": 1,
        "kind": "local_oci_execution_spec",
        "runtime_kind": "rootless_podman",
        "runner_interface": "injected_adapter_only",
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "invocation_sha256": plan.invocation_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "deployment_binding_id": binding.binding_id,
        "deployment_binding_sha256": binding.binding_sha256,
        "host_preflight_report_id": preflight.report_id,
        "host_preflight_report_sha256": preflight.report_sha256,
        "isolation_class": "oci_container",
        "image_reference": image,
        "image_digest": image_digest,
        "security_policy": _security_policy(seccomp_digest),
        "environment": _environment(),
        "workspace_policy": _workspace_policy(plan.limits),
        "limits": plan.limits.to_dict(),
        "cancellation_policy": _cancellation_policy(),
        "cleanup_policy": _cleanup_policy(),
        "observation_policy": _observation_policy(plan.limits),
        "command_argv": _command_argv(
            plan_id=plan.plan_id,
            image_reference=image,
            seccomp_profile_path=SECCOMP_PROFILE_PATH,
            limits=plan.limits,
        ),
        "status": "specification_ready_nonqualifying",
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": SPEC_DOMAIN, "specification": body})
    return LocalOciExecutionSpec.from_dict(
        {
            **body,
            "spec_id": f"OCS-{digest.removeprefix('sha256:')[:32].upper()}",
            "spec_sha256": digest,
        }
    )


@dataclass(frozen=True)
class LocalOciContainmentObservation:
    observation_id: str
    observation_sha256: str
    observation_kind: str
    outcome: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalOciContainmentObservation:
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
            "runtime_execution_performed",
            "external_containment_proven",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local OCI observation")
        _effects_are_none(value, "Local OCI observation")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_oci_containment_observation"
            or value.get("runtime_execution_performed") is not False
            or value.get("external_containment_proven") is not False
        ):
            raise QualificationError("Local OCI observation boundary is invalid")
        observation_kind = value.get("observation_kind")
        outcome = value.get("outcome")
        assertions = value.get("assertions")
        expected_outcomes = {
            "specification_validation": "repository_validated_nonqualifying",
            "runtime_absence": "not_executed",
            "qualification_boundary": "no_effect",
        }
        if (
            type(observation_kind) is not str
            or type(outcome) is not str
            or expected_outcomes.get(observation_kind) != outcome
        ):
            raise QualificationError("Local OCI observation outcome is invalid")
        if (
            type(assertions) is not list
            or not assertions
            or any(
                type(item) is not str or ASSERTION_PATTERN.fullmatch(item) is None
                for item in assertions
            )
            or assertions != sorted(set(assertions))
        ):
            raise QualificationError("Local OCI observation assertions are invalid")
        _sha(value.get("spec_sha256"), "local OCI observation specification hash")
        spec_id = value.get("spec_id")
        if not isinstance(spec_id, str) or SPEC_ID_PATTERN.fullmatch(spec_id) is None:
            raise QualificationError("Local OCI observation specification ID is invalid")
        observation_sha256 = _sha(value.get("observation_sha256"), "local OCI observation hash")
        observation_id = value.get("observation_id")
        if (
            not isinstance(observation_id, str)
            or OBSERVATION_ID_PATTERN.fullmatch(observation_id) is None
        ):
            raise QualificationError("Local OCI observation ID is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"observation_id", "observation_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": OBSERVATION_DOMAIN, "observation": body})
        expected_id = f"OCO-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if observation_sha256 != expected_sha256 or observation_id != expected_id:
            raise QualificationError("Local OCI observation identity does not match content")
        return cls(
            observation_id,
            observation_sha256,
            observation_kind,
            outcome,
            _canonical_json(value),
        )


def _build_observation(
    specification: LocalOciExecutionSpec,
    observation_kind: str,
    outcome: str,
    assertions: tuple[str, ...],
) -> LocalOciContainmentObservation:
    body = {
        "schema_version": 1,
        "kind": "local_oci_containment_observation",
        "spec_id": specification.spec_id,
        "spec_sha256": specification.spec_sha256,
        "observation_kind": observation_kind,
        "outcome": outcome,
        "assertions": list(assertions),
        "runtime_execution_performed": False,
        "external_containment_proven": False,
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": OBSERVATION_DOMAIN, "observation": body})
    return LocalOciContainmentObservation.from_dict(
        {
            **body,
            "observation_id": f"OCO-{digest.removeprefix('sha256:')[:32].upper()}",
            "observation_sha256": digest,
        }
    )


def _fixture_observations(
    specification: LocalOciExecutionSpec,
) -> tuple[LocalOciContainmentObservation, ...]:
    return (
        _build_observation(
            specification,
            "specification_validation",
            "repository_validated_nonqualifying",
            (
                "bounded_limits_encoded",
                "credentials_denied",
                "deny_all_network_encoded",
                "ephemeral_workspace_encoded",
                "rootless_controls_encoded",
            ),
        ),
        _build_observation(
            specification,
            "runtime_absence",
            "not_executed",
            (
                "host_runtime_not_mutated",
                "injected_adapter_required",
                "podman_not_invoked",
            ),
        ),
        _build_observation(
            specification,
            "qualification_boundary",
            "no_effect",
            (
                "external_containment_not_proven",
                "qualification_unchanged",
                "target_authority_unchanged",
            ),
        ),
    )


@dataclass(frozen=True)
class LocalOciContainmentFixture:
    fixture_id: str
    fixture_sha256: str
    specification: LocalOciExecutionSpec
    observations: tuple[LocalOciContainmentObservation, ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> LocalOciContainmentFixture:
        fields = {
            "schema_version",
            "kind",
            "fixture_id",
            "fixture_sha256",
            "specification",
            "observations",
            "status",
            "runtime_execution_performed",
            "external_containment_proven",
            *BOUNDARY_EFFECTS,
        }
        value = _exact_object(raw, fields, "Local OCI containment fixture")
        _effects_are_none(value, "Local OCI containment fixture")
        if (
            value.get("schema_version") != 1
            or value.get("kind") != "local_oci_containment_fixture"
            or value.get("status") != "deterministic_repository_fixture_nonqualifying"
            or value.get("runtime_execution_performed") is not False
            or value.get("external_containment_proven") is not False
        ):
            raise QualificationError("Local OCI containment fixture boundary is invalid")
        specification = LocalOciExecutionSpec.from_dict(value.get("specification"))
        observation_values = value.get("observations")
        if type(observation_values) is not list:
            raise QualificationError("Local OCI containment observations must be a list")
        observations = tuple(
            LocalOciContainmentObservation.from_dict(item) for item in observation_values
        )
        if observations != _fixture_observations(specification):
            raise QualificationError("Local OCI containment observations are not canonical")
        fixture_sha256 = _sha(value.get("fixture_sha256"), "local OCI fixture hash")
        fixture_id = value.get("fixture_id")
        if not isinstance(fixture_id, str) or FIXTURE_ID_PATTERN.fullmatch(fixture_id) is None:
            raise QualificationError("Local OCI fixture ID is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"fixture_id", "fixture_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": FIXTURE_DOMAIN, "fixture": body})
        expected_id = f"OCF-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if fixture_sha256 != expected_sha256 or fixture_id != expected_id:
            raise QualificationError("Local OCI fixture identity does not match content")
        return cls(
            fixture_id,
            fixture_sha256,
            specification,
            observations,
            _canonical_json(value),
        )


def build_local_oci_containment_fixture(
    *,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    plan: ContainmentExecutionPlan,
    catalog: ContainmentConformanceSuiteCatalog,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    image_reference: str,
    seccomp_profile_sha256: str,
) -> LocalOciContainmentFixture:
    """Build a deterministic fixture without executing an OCI runtime."""

    specification = build_local_oci_execution_spec(
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        plan=plan,
        catalog=catalog,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        image_reference=image_reference,
        seccomp_profile_sha256=seccomp_profile_sha256,
    )
    observations = _fixture_observations(specification)
    body = {
        "schema_version": 1,
        "kind": "local_oci_containment_fixture",
        "specification": specification.to_dict(),
        "observations": [item.to_dict() for item in observations],
        "status": "deterministic_repository_fixture_nonqualifying",
        "runtime_execution_performed": False,
        "external_containment_proven": False,
        **BOUNDARY_EFFECTS,
    }
    digest = _canonical_sha256({"domain": FIXTURE_DOMAIN, "fixture": body})
    return LocalOciContainmentFixture.from_dict(
        {
            **body,
            "fixture_id": f"OCF-{digest.removeprefix('sha256:')[:32].upper()}",
            "fixture_sha256": digest,
        }
    )


__all__ = [
    "BOUNDARY_EFFECTS",
    "LocalOciContainmentFixture",
    "LocalOciContainmentObservation",
    "LocalOciExecutionSpec",
    "LocalOciRuntimeAdapter",
    "build_local_oci_containment_fixture",
    "build_local_oci_execution_spec",
]
