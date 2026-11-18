"""Content-addressed conformance suites for Phase 157 containment backends."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .candidate_adapter_runner import ContainmentBackendAttestation, ISOLATION_RANK
from .candidate_adapter_sdk import AdapterManifest
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

SUITE_CATALOG_DOMAIN = "sunderkey.containment-conformance-suite-catalog.v1"
OBSERVATION_DOMAIN = "sunderkey.containment-conformance-observation.v1"
REPORT_DOMAIN = "sunderkey.containment-conformance-report.v1"
ADMISSION_DOMAIN = "sunderkey.containment-backend-admission.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REPORT_ID_PATTERN = re.compile(r"BCR-[0-9A-F]{32}")
ADMISSION_ID_PATTERN = re.compile(r"BAR-[0-9A-F]{32}")
COMMON_PROBES = (
    "executable_digest_verified",
    "configuration_digest_verified",
    "external_boundary_verified",
    "deadline_kill_verified",
    "cancellation_kill_verified",
    "cpu_ceiling_verified",
    "memory_ceiling_verified",
    "process_ceiling_verified",
    "output_ceiling_verified",
    "network_deny_verified",
    "credential_deny_verified",
    "read_only_rootfs_verified",
    "workspace_cleanup_verified",
)
OCI_PROBES = COMMON_PROBES + (
    "rootless_verified",
    "user_namespace_verified",
    "seccomp_verified",
    "capabilities_dropped_verified",
    "no_new_privileges_verified",
)
MICROVM_PROBES = COMMON_PROBES + (
    "kvm_verified",
    "jailer_verified",
    "seccomp_verified",
    "dedicated_uid_gid_verified",
    "single_tenant_vm_verified",
    "bounded_logging_verified",
    "host_hardening_verified",
)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


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


def _suite_body(isolation_class: str) -> dict[str, Any]:
    if isolation_class == "oci_container":
        probe_ids = OCI_PROBES
        implementation_target = "rootless_podman"
        source_url = "https://github.com/containers/podman/releases/latest"
    elif isolation_class == "microvm":
        probe_ids = MICROVM_PROBES
        implementation_target = "jailed_firecracker"
        source_url = "https://github.com/firecracker-microvm/firecracker/releases"
    else:
        raise QualificationError("Containment conformance isolation class is invalid")
    return {
        "suite_id": f"sunderkey-containment-{isolation_class}-v1",
        "suite_version": "1.0.0",
        "isolation_class": isolation_class,
        "implementation_target": implementation_target,
        "provider_release_source": source_url,
        "probe_ids": list(probe_ids),
        "required_outcome": "all_probes_passed",
        "evidence_requirement": "one_or_more_content_addressed_artifacts_per_probe",
        "execution_scope": "synthetic_test_backend_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }


@dataclass(frozen=True)
class ContainmentConformanceSuiteCatalog:
    catalog_sha256: str
    suites: tuple[dict[str, Any], ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> ContainmentConformanceSuiteCatalog:
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "suites",
            "limitations",
        }:
            raise QualificationError("Containment conformance suite catalog fields are invalid")
        expected_suites = [_suite_body("oci_container"), _suite_body("microvm")]
        if (
            raw.get("schema_version") != 1
            or raw.get("catalog_id") != "sunderkey-containment-conformance-suites-v1"
            or raw.get("catalog_version") != "1.0.0"
            or raw.get("suites") != expected_suites
        ):
            raise QualificationError("Containment conformance suite catalog is invalid")
        limitations = raw.get("limitations")
        if not isinstance(limitations, list) or len(limitations) < 4:
            raise QualificationError("Containment conformance limitations are incomplete")
        body = {key: value for key, value in raw.items() if key != "catalog_sha256"}
        digest = _canonical_sha256({"domain": SUITE_CATALOG_DOMAIN, "catalog": body})
        if raw.get("catalog_sha256") != digest:
            raise QualificationError("Containment conformance catalog hash does not match content")
        return cls(digest, tuple(expected_suites), _canonical_json(raw))


def build_containment_conformance_suite_catalog() -> ContainmentConformanceSuiteCatalog:
    body = {
        "schema_version": 1,
        "catalog_id": "sunderkey-containment-conformance-suites-v1",
        "catalog_version": "1.0.0",
        "suites": [_suite_body("oci_container"), _suite_body("microvm")],
        "limitations": [
            "A suite definition is not evidence that a backend is installed or conformant.",
            "Conformance has no qualification, routing, deployment, or target-authority effect.",
            "Every observation requires externally collected content-addressed evidence.",
            "Production deployment still requires D014 provider and custodian selection.",
        ],
    }
    digest = _canonical_sha256({"domain": SUITE_CATALOG_DOMAIN, "catalog": body})
    return ContainmentConformanceSuiteCatalog.from_dict(
        {**body, "catalog_sha256": digest}
    )


def load_containment_conformance_suite_catalog(
    source: str | Path,
) -> ContainmentConformanceSuiteCatalog:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(
            f"Could not load containment conformance suites: {source}"
        ) from exc
    return ContainmentConformanceSuiteCatalog.from_dict(raw)


def build_conformance_observation(
    *,
    probe_id: str,
    status: str,
    evidence_sha256: tuple[str, ...],
    measurement: Mapping[str, Any],
) -> dict[str, Any]:
    _text(probe_id, "conformance probe ID")
    if status not in {"passed", "failed", "error"}:
        raise QualificationError("Conformance observation status is invalid")
    if not evidence_sha256 or len(evidence_sha256) != len(set(evidence_sha256)):
        raise QualificationError("Conformance observation evidence is incomplete or duplicated")
    for item in evidence_sha256:
        _sha(item, "conformance evidence hash")
    if not isinstance(measurement, Mapping) or not measurement:
        raise QualificationError("Conformance observation measurement is incomplete")
    try:
        measurement_value = json.loads(_canonical_json(dict(measurement)))
    except (TypeError, ValueError) as exc:
        raise QualificationError("Conformance observation measurement is invalid") from exc
    body = {
        "probe_id": probe_id,
        "status": status,
        "evidence_sha256": list(evidence_sha256),
        "measurement": measurement_value,
    }
    return {
        **body,
        "observation_sha256": _canonical_sha256(
            {"domain": OBSERVATION_DOMAIN, "observation": body}
        ),
    }


@dataclass(frozen=True)
class BackendConformanceReport:
    report_id: str
    report_sha256: str
    backend_attestation_sha256: str
    isolation_class: str
    outcome: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        attestation: ContainmentBackendAttestation,
        catalog: ContainmentConformanceSuiteCatalog,
    ) -> BackendConformanceReport:
        expected_fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "suite_catalog_sha256",
            "suite_id",
            "suite_version",
            "backend_id",
            "backend_attestation_sha256",
            "isolation_class",
            "tested_at",
            "verifier_id",
            "identity_assurance",
            "observations",
            "passed_probe_count",
            "failed_probe_ids",
            "outcome",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Containment conformance report fields are invalid")
        suite = next(
            (
                item
                for item in catalog.suites
                if item["isolation_class"] == attestation.isolation_class
            ),
            None,
        )
        if suite is None:
            raise QualificationError("Containment conformance suite is unavailable")
        if (
            raw.get("schema_version") != 1
            or raw.get("suite_catalog_sha256") != catalog.catalog_sha256
            or raw.get("suite_id") != suite["suite_id"]
            or raw.get("suite_version") != suite["suite_version"]
            or raw.get("backend_id") != attestation.backend_id
            or raw.get("backend_attestation_sha256") != attestation.attestation_sha256
            or raw.get("isolation_class") != attestation.isolation_class
            or raw.get("identity_assurance") != "operator_asserted_unsigned"
            or any(raw.get(field) != "none" for field in (
                "qualification_effect", "routing_effect", "deployment_effect",
                "target_authority_effect",
            ))
        ):
            raise QualificationError("Containment conformance report binding is invalid")
        _utc(raw.get("tested_at"), "conformance tested_at")
        _text(raw.get("verifier_id"), "conformance verifier ID")
        observations = raw.get("observations")
        if not isinstance(observations, list) or len(observations) != len(suite["probe_ids"]):
            raise QualificationError("Containment conformance observations are incomplete")
        parsed: list[dict[str, Any]] = []
        for observation, probe_id in zip(observations, suite["probe_ids"], strict=True):
            if not isinstance(observation, dict) or set(observation) != {
                "probe_id", "status", "evidence_sha256", "measurement",
                "observation_sha256",
            }:
                raise QualificationError("Containment conformance observation fields are invalid")
            if observation.get("probe_id") != probe_id:
                raise QualificationError("Containment conformance observations are unordered")
            rebuilt = build_conformance_observation(
                probe_id=probe_id,
                status=observation.get("status"),
                evidence_sha256=tuple(observation.get("evidence_sha256", [])),
                measurement=observation.get("measurement"),
            )
            if rebuilt != observation:
                raise QualificationError("Containment conformance observation hash is invalid")
            parsed.append(rebuilt)
        failed = [item["probe_id"] for item in parsed if item["status"] != "passed"]
        outcome = "conformant_nonqualifying" if not failed else "nonconforming"
        if (
            raw.get("passed_probe_count") != len(parsed) - len(failed)
            or raw.get("failed_probe_ids") != failed
            or raw.get("outcome") != outcome
        ):
            raise QualificationError("Containment conformance outcome is invalid")
        report_sha256 = _sha(raw.get("report_sha256"), "conformance report hash")
        report_id = _text(raw.get("report_id"), "conformance report ID")
        if REPORT_ID_PATTERN.fullmatch(report_id) is None:
            raise QualificationError("Containment conformance report ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
        expected_id = f"BCR-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if report_sha256 != expected_sha256 or report_id != expected_id:
            raise QualificationError(
                "Containment conformance report identity does not match content"
            )
        return cls(
            report_id,
            report_sha256,
            attestation.attestation_sha256,
            attestation.isolation_class,
            outcome,
            _canonical_json(raw),
        )


def build_backend_conformance_report(
    *,
    attestation: ContainmentBackendAttestation,
    catalog: ContainmentConformanceSuiteCatalog,
    observations: list[dict[str, Any]],
    tested_at: str,
    verifier_id: str,
) -> BackendConformanceReport:
    if (
        ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation
        or ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict()) != catalog
    ):
        raise QualificationError("Conformance inputs are not canonical")
    suite = next(
        item for item in catalog.suites if item["isolation_class"] == attestation.isolation_class
    )
    failed = [
        item.get("probe_id") if isinstance(item, dict) else None
        for item in observations
        if not isinstance(item, dict) or item.get("status") != "passed"
    ]
    body = {
        "schema_version": 1,
        "suite_catalog_sha256": catalog.catalog_sha256,
        "suite_id": suite["suite_id"],
        "suite_version": suite["suite_version"],
        "backend_id": attestation.backend_id,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "isolation_class": attestation.isolation_class,
        "tested_at": tested_at,
        "verifier_id": verifier_id,
        "identity_assurance": "operator_asserted_unsigned",
        "observations": observations,
        "passed_probe_count": len(observations) - len(failed),
        "failed_probe_ids": failed,
        "outcome": "conformant_nonqualifying" if not failed else "nonconforming",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
    return BackendConformanceReport.from_dict(
        {
            **body,
            "report_id": f"BCR-{digest.removeprefix('sha256:')[:32].upper()}",
            "report_sha256": digest,
        },
        attestation,
        catalog,
    )


@dataclass(frozen=True)
class BackendAdmissionReceipt:
    admission_id: str
    admission_sha256: str
    status: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        report: BackendConformanceReport,
        attestation: ContainmentBackendAttestation,
        manifest: AdapterManifest,
        catalog: ContainmentConformanceSuiteCatalog,
    ) -> BackendAdmissionReceipt:
        expected_fields = {
            "schema_version",
            "admission_id",
            "admission_sha256",
            "adapter_id",
            "manifest_sha256",
            "backend_id",
            "backend_attestation_sha256",
            "conformance_report_id",
            "conformance_report_sha256",
            "isolation_class",
            "status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Backend admission receipt fields are invalid")
        if (
            raw.get("schema_version") != 1
            or raw.get("adapter_id") != manifest.adapter_id
            or raw.get("manifest_sha256") != manifest.manifest_sha256
            or raw.get("backend_id") != attestation.backend_id
            or raw.get("backend_attestation_sha256") != attestation.attestation_sha256
            or raw.get("conformance_report_id") != report.report_id
            or raw.get("conformance_report_sha256") != report.report_sha256
            or raw.get("isolation_class") != attestation.isolation_class
            or raw.get("status") != "admitted_for_phase157_synthetic_only"
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
            raise QualificationError("Backend admission receipt binding is invalid")
        verified_report = BackendConformanceReport.from_dict(
            report.to_dict(), attestation, catalog
        )
        verified_catalog = ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict())
        if (
            verified_report != report
            or verified_catalog != catalog
            or report.outcome != "conformant_nonqualifying"
        ):
            raise QualificationError("Backend admission requires a conformant report")
        if (
            ISOLATION_RANK[attestation.isolation_class]
            < ISOLATION_RANK[manifest.required_isolation]
        ):
            raise QualificationError(
                "Backend admission isolation is below the manifest requirement"
            )
        admission_sha256 = _sha(raw.get("admission_sha256"), "backend admission hash")
        admission_id = _text(raw.get("admission_id"), "backend admission ID")
        if ADMISSION_ID_PATTERN.fullmatch(admission_id) is None:
            raise QualificationError("Backend admission ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"admission_id", "admission_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": ADMISSION_DOMAIN, "admission": body})
        expected_id = f"BAR-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if admission_sha256 != expected_sha256 or admission_id != expected_id:
            raise QualificationError("Backend admission identity does not match content")
        return cls(
            admission_id,
            admission_sha256,
            raw["status"],
            _canonical_json(raw),
        )


def admit_conformant_backend_for_manifest(
    report: BackendConformanceReport,
    attestation: ContainmentBackendAttestation,
    manifest: AdapterManifest,
    catalog: ContainmentConformanceSuiteCatalog,
) -> BackendAdmissionReceipt:
    verified_report = BackendConformanceReport.from_dict(
        report.to_dict(), attestation, catalog
    )
    verified_catalog = ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict())
    if (
        verified_report != report
        or verified_catalog != catalog
        or ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation
        or AdapterManifest.from_dict(manifest.to_dict()) != manifest
        or report.backend_attestation_sha256 != attestation.attestation_sha256
        or report.isolation_class != attestation.isolation_class
    ):
        raise QualificationError("Backend conformance report and attestation do not match")
    if report.outcome != "conformant_nonqualifying":
        raise QualificationError("Nonconforming backend cannot be admitted")
    if ISOLATION_RANK[attestation.isolation_class] < ISOLATION_RANK[manifest.required_isolation]:
        raise QualificationError("Conformant backend isolation is below the manifest requirement")
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "manifest_sha256": manifest.manifest_sha256,
        "backend_id": attestation.backend_id,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "conformance_report_id": report.report_id,
        "conformance_report_sha256": report.report_sha256,
        "isolation_class": attestation.isolation_class,
        "status": "admitted_for_phase157_synthetic_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": ADMISSION_DOMAIN, "admission": body})
    admission_id = f"BAR-{digest.removeprefix('sha256:')[:32].upper()}"
    return BackendAdmissionReceipt.from_dict(
        {**body, "admission_id": admission_id, "admission_sha256": digest},
        report,
        attestation,
        manifest,
        catalog,
    )


__all__ = [
    "BackendAdmissionReceipt",
    "BackendConformanceReport",
    "COMMON_PROBES",
    "ContainmentConformanceSuiteCatalog",
    "MICROVM_PROBES",
    "OCI_PROBES",
    "admit_conformant_backend_for_manifest",
    "build_backend_conformance_report",
    "build_conformance_observation",
    "build_containment_conformance_suite_catalog",
    "load_containment_conformance_suite_catalog",
]
