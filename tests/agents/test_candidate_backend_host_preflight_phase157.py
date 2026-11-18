"""Phase 157 containment deployment binding and host-preflight tests."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey.candidate_adapter_runner import (
    MICROVM_GUARANTEES,
    OCI_GUARANTEES,
    ContainmentBackendAttestation,
)
from sunderkey.candidate_backend_conformance import (
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_backend_host_preflight import (
    ContainmentBackendDeploymentBinding,
    ContainmentHostPreflightReport,
    ContainmentHostSnapshot,
    assess_containment_host_preflight,
    build_containment_backend_deployment_binding,
    build_containment_host_snapshot,
    compute_provider_binary_bundle_sha256,
    compute_provider_configuration_bundle_sha256,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64
TWO_SHA = "sha256:" + "2" * 64
THREE_SHA = "sha256:" + "3" * 64


def binaries(isolation_class: str) -> list[dict[str, str]]:
    names = ("podman",) if isolation_class == "oci_container" else ("firecracker", "jailer")
    return [
        {
            "name": name,
            "version": "test-1",
            "sha256": (ZERO_SHA, ONE_SHA)[index],
            "source_url": f"https://example.invalid/{name}",
            "license_spdx": "Apache-2.0",
        }
        for index, name in enumerate(names)
    ]


def configurations() -> list[dict[str, str]]:
    return [
        {
            "name": "containment-policy",
            "sha256": TWO_SHA,
            "media_type": "application/json",
        },
        {
            "name": "runtime-policy",
            "sha256": THREE_SHA,
            "media_type": "application/toml",
        },
    ]


def attestation(isolation_class: str) -> ContainmentBackendAttestation:
    binary_digest = compute_provider_binary_bundle_sha256(
        binaries(isolation_class), isolation_class
    )
    configuration_digest = compute_provider_configuration_bundle_sha256(configurations())
    guarantees = OCI_GUARANTEES if isolation_class == "oci_container" else MICROVM_GUARANTEES
    return ContainmentBackendAttestation.build(
        backend_id=f"containment.preflight.{isolation_class.replace('_', '-')}",
        backend_version="test-1",
        isolation_class=isolation_class,
        executable_sha256=binary_digest,
        configuration_sha256=configuration_digest,
        source_url="https://example.invalid/containment-preflight",
        license_spdx="Apache-2.0",
        host_os="linux",
        guarantees=tuple(sorted(guarantees)),
    )


class CandidateBackendHostPreflightPhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )

    def binding(self, isolation_class: str):
        backend_attestation = attestation(isolation_class)
        binding = build_containment_backend_deployment_binding(
            catalog=self.catalog,
            attestation=backend_attestation,
            host_id=f"host.test.{isolation_class.replace('_', '-')}",
            architecture="x86_64",
            service_identity_id=f"service.test.{isolation_class.replace('_', '-')}",
            binary_components=binaries(isolation_class),
            configuration_components=configurations(),
        )
        return backend_attestation, binding

    def snapshot(self, isolation_class: str, **overrides):
        values = {
            "host_id": f"host.test.{isolation_class.replace('_', '-')}",
            "collected_at": "2026-09-19T20:00:00Z",
            "os_name": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.12.0-test",
            "service_identity_id": f"service.test.{isolation_class.replace('_', '-')}",
            "binary_components": [
                {**item, "path": f"/usr/bin/{item['name']}"}
                for item in binaries(isolation_class)
            ],
            "configuration_components": configurations(),
            "cgroup_version": "v2",
            "seccomp_enabled": True,
            "rootless_provider": isolation_class == "oci_container",
            "user_namespace_enabled": isolation_class == "oci_container",
            "kvm_access": isolation_class == "microvm",
            "dedicated_jailer_uid_gid": isolation_class == "microvm",
            "single_tenant_vm": isolation_class == "microvm",
            "bounded_logging": isolation_class == "microvm",
            "host_hardening": isolation_class == "microvm",
        }
        values.update(overrides)
        return build_containment_host_snapshot(**values)

    def test_oci_host_passes_read_only_preflight_without_operational_effects(self) -> None:
        backend_attestation, binding = self.binding("oci_container")
        snapshot = self.snapshot("oci_container")
        report = assess_containment_host_preflight(
            binding=binding,
            snapshot=snapshot,
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        self.assertEqual(report.status, "ready_for_dynamic_conformance_nonqualifying")
        self.assertEqual(report.to_dict()["blockers"], [])
        self.assertEqual(
            ContainmentHostPreflightReport.from_dict(
                report.to_dict(), binding, snapshot, self.catalog, backend_attestation
            ),
            report,
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(report.to_dict()[field], "none")

    def test_non_linux_or_non_rootless_oci_host_is_blocked(self) -> None:
        backend_attestation, binding = self.binding("oci_container")
        snapshot = self.snapshot(
            "oci_container", os_name="windows", rootless_provider=False
        )
        report = assess_containment_host_preflight(
            binding=binding,
            snapshot=snapshot,
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        self.assertEqual(report.status, "blocked_pending_host_remediation")
        self.assertEqual(report.to_dict()["blockers"], ["linux_host", "rootless_provider"])

    def test_binary_and_configuration_substitution_are_blockers(self) -> None:
        backend_attestation, binding = self.binding("oci_container")
        substituted_binaries = self.snapshot("oci_container").to_dict()["binary_components"]
        substituted_binaries[0]["sha256"] = ONE_SHA
        substituted_configuration = copy.deepcopy(configurations())
        substituted_configuration[0]["sha256"] = ZERO_SHA
        snapshot = self.snapshot(
            "oci_container",
            binary_components=substituted_binaries,
            configuration_components=substituted_configuration,
        )
        report = assess_containment_host_preflight(
            binding=binding,
            snapshot=snapshot,
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        self.assertEqual(
            report.to_dict()["blockers"],
            ["binary_bundle_exact", "configuration_bundle_exact"],
        )

    def test_microvm_requires_exact_firecracker_jailer_and_host_controls(self) -> None:
        backend_attestation, binding = self.binding("microvm")
        snapshot = self.snapshot("microvm")
        report = assess_containment_host_preflight(
            binding=binding,
            snapshot=snapshot,
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        self.assertEqual(report.status, "ready_for_dynamic_conformance_nonqualifying")
        blocked = assess_containment_host_preflight(
            binding=binding,
            snapshot=self.snapshot(
                "microvm",
                kvm_access=False,
                dedicated_jailer_uid_gid=False,
                host_hardening=False,
            ),
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        self.assertEqual(
            blocked.to_dict()["blockers"],
            ["kvm_access", "dedicated_jailer_uid_gid", "host_hardening"],
        )

    def test_binding_rejects_attestation_not_derived_from_exact_bundles(self) -> None:
        wrong_attestation = ContainmentBackendAttestation.build(
            backend_id="containment.preflight.wrong",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/wrong",
            license_spdx="Apache-2.0",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            build_containment_backend_deployment_binding(
                catalog=self.catalog,
                attestation=wrong_attestation,
                host_id="host.test.wrong",
                architecture="x86_64",
                service_identity_id="service.test.wrong",
                binary_components=binaries("oci_container"),
                configuration_components=configurations(),
            )

    def test_binding_snapshot_and_report_tampering_fail_closed(self) -> None:
        backend_attestation, binding = self.binding("oci_container")
        snapshot = self.snapshot("oci_container")
        report = assess_containment_host_preflight(
            binding=binding,
            snapshot=snapshot,
            catalog=self.catalog,
            attestation=backend_attestation,
        )
        binding_raw = binding.to_dict()
        binding_raw["architecture"] = "riscv64"
        binding_body = {
            key: value
            for key, value in binding_raw.items()
            if key not in {"binding_id", "binding_sha256"}
        }
        binding_raw["binding_sha256"] = _canonical_sha256(
            {
                "domain": "sunderkey.containment-backend-deployment-binding.v1",
                "binding": binding_body,
            }
        )
        binding_raw["binding_id"] = (
            "CBD-" + binding_raw["binding_sha256"].removeprefix("sha256:")[:32].upper()
        )
        with self.assertRaisesRegex(QualificationError, "invalid"):
            ContainmentBackendDeploymentBinding.from_dict(
                binding_raw, self.catalog, backend_attestation
            )
        snapshot_raw = snapshot.to_dict()
        snapshot_raw["snapshot_sha256"] = ZERO_SHA
        with self.assertRaisesRegex(QualificationError, "identity"):
            ContainmentHostSnapshot.from_dict(snapshot_raw)
        report_raw = report.to_dict()
        report_raw["status"] = "blocked_pending_host_remediation"
        with self.assertRaisesRegex(QualificationError, "outcome"):
            ContainmentHostPreflightReport.from_dict(
                report_raw, binding, snapshot, self.catalog, backend_attestation
            )

    def test_snapshot_rejects_windows_paths_and_non_boolean_controls(self) -> None:
        binary_components = [
            {**item, "path": "C:/Program Files/Podman/podman.exe"}
            for item in binaries("oci_container")
        ]
        with self.assertRaisesRegex(QualificationError, "POSIX"):
            self.snapshot("oci_container", binary_components=binary_components)
        with self.assertRaisesRegex(QualificationError, "booleans"):
            self.snapshot("oci_container", seccomp_enabled=1)


if __name__ == "__main__":
    unittest.main()
