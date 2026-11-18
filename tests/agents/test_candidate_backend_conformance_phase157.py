"""Phase 157 containment backend conformance contract tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_runner import (
    MICROVM_GUARANTEES,
    OCI_GUARANTEES,
    ContainmentBackendAttestation,
)
from sunderkey.candidate_adapter_sdk import load_candidate_adapter_catalog
from sunderkey.candidate_backend_conformance import (
    MICROVM_PROBES,
    OCI_PROBES,
    BackendAdmissionReceipt,
    BackendConformanceReport,
    admit_conformant_backend_for_manifest,
    build_backend_conformance_report,
    build_conformance_observation,
    build_containment_conformance_suite_catalog,
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64
TWO_SHA = "sha256:" + "2" * 64


def make_attestation(
    isolation_class: str,
    *,
    executable_sha256: str = ZERO_SHA,
) -> ContainmentBackendAttestation:
    guarantees = OCI_GUARANTEES if isolation_class == "oci_container" else MICROVM_GUARANTEES
    return ContainmentBackendAttestation.build(
        backend_id=f"containment.conformance.{isolation_class.replace('_', '-')}",
        backend_version="test-1",
        isolation_class=isolation_class,
        executable_sha256=executable_sha256,
        configuration_sha256=ONE_SHA,
        source_url="https://example.invalid/containment-conformance-backend",
        license_spdx="LicenseRef-Test-Only",
        host_os="linux",
        guarantees=tuple(sorted(guarantees)),
    )


def observations(probe_ids: tuple[str, ...], failed_probe: str | None = None):
    return [
        build_conformance_observation(
            probe_id=probe_id,
            status="failed" if probe_id == failed_probe else "passed",
            evidence_sha256=(TWO_SHA,),
            measurement={"observed": True, "probe": probe_id},
        )
        for probe_id in probe_ids
    ]


class CandidateBackendConformancePhase157Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_containment_conformance_suite_catalog()
        strategy = load_candidate_implementation_strategy(
            REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
        )
        cls.adapters = load_candidate_adapter_catalog(
            REGISTRY_DIR / "candidate-adapters-reference-v1.json",
            strategy,
            load_blueprints(),
            ROOT,
        )

    def report(self, isolation_class: str, failed_probe: str | None = None):
        backend_attestation = make_attestation(isolation_class)
        probe_ids = OCI_PROBES if isolation_class == "oci_container" else MICROVM_PROBES
        report = build_backend_conformance_report(
            attestation=backend_attestation,
            catalog=self.catalog,
            observations=observations(probe_ids, failed_probe),
            tested_at="2026-09-19T18:00:00Z",
            verifier_id="containment-test-verifier",
        )
        return backend_attestation, report

    def test_checked_catalog_matches_builder_and_has_exact_probe_counts(self) -> None:
        checked = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        self.assertEqual(checked, self.catalog)
        self.assertEqual(len(OCI_PROBES), 18)
        self.assertEqual(len(MICROVM_PROBES), 20)
        self.assertEqual(
            [len(suite["probe_ids"]) for suite in checked.suites],
            [18, 20],
        )

    def test_all_passed_observations_are_conformant_but_nonqualifying(self) -> None:
        attestation, report = self.report("oci_container")
        self.assertEqual(report.outcome, "conformant_nonqualifying")
        self.assertEqual(
            BackendConformanceReport.from_dict(report.to_dict(), attestation, self.catalog),
            report,
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(report.to_dict()[field], "none")

    def test_failed_or_error_probe_makes_report_nonconforming(self) -> None:
        for status in ("failed", "error"):
            with self.subTest(status=status):
                attestation = make_attestation("oci_container")
                probe_observations = observations(OCI_PROBES)
                probe_observations[0] = build_conformance_observation(
                    probe_id=OCI_PROBES[0],
                    status=status,
                    evidence_sha256=(TWO_SHA,),
                    measurement={"observed": False, "reason": status},
                )
                report = build_backend_conformance_report(
                    attestation=attestation,
                    catalog=self.catalog,
                    observations=probe_observations,
                    tested_at="2026-09-19T18:00:00Z",
                    verifier_id="containment-test-verifier",
                )
                self.assertEqual(report.outcome, "nonconforming")
                self.assertEqual(report.to_dict()["failed_probe_ids"], [OCI_PROBES[0]])

    def test_missing_reordered_substituted_and_rehashed_observations_are_rejected(self) -> None:
        attestation, report = self.report("oci_container")
        mutations = []
        missing = report.to_dict()
        missing["observations"].pop()
        mutations.append((missing, "incomplete"))
        reordered = report.to_dict()
        reordered["observations"][0], reordered["observations"][1] = (
            reordered["observations"][1],
            reordered["observations"][0],
        )
        mutations.append((reordered, "unordered"))
        substituted = report.to_dict()
        substituted["observations"][0]["probe_id"] = "unreviewed_probe"
        mutations.append((substituted, "unordered"))
        rehashed = report.to_dict()
        rehashed["observations"][0]["observation_sha256"] = ZERO_SHA
        mutations.append((rehashed, "hash is invalid"))
        for document, message in mutations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(QualificationError, message):
                    BackendConformanceReport.from_dict(document, attestation, self.catalog)

    def test_report_is_bound_to_exact_backend_attestation(self) -> None:
        attestation, report = self.report("oci_container")
        substitute = make_attestation("oci_container", executable_sha256=TWO_SHA)
        self.assertNotEqual(attestation.attestation_sha256, substitute.attestation_sha256)
        with self.assertRaisesRegex(QualificationError, "binding"):
            BackendConformanceReport.from_dict(report.to_dict(), substitute, self.catalog)

    def test_oci_conformance_cannot_admit_microvm_manifest(self) -> None:
        attestation, report = self.report("oci_container")
        microvm_manifest = self.adapters.manifests_by_profile_id["AOE-GC-D14-S01"]
        with self.assertRaisesRegex(QualificationError, "below the manifest"):
            admit_conformant_backend_for_manifest(
                report, attestation, microvm_manifest, self.catalog
            )

    def test_matching_manifest_receives_only_synthetic_phase157_admission(self) -> None:
        attestation, report = self.report("oci_container")
        manifest = self.adapters.manifests_by_profile_id["AOE-GB-D06-S09"]
        receipt = admit_conformant_backend_for_manifest(
            report, attestation, manifest, self.catalog
        )
        self.assertEqual(receipt.status, "admitted_for_phase157_synthetic_only")
        self.assertEqual(
            BackendAdmissionReceipt.from_dict(
                receipt.to_dict(), report, attestation, manifest, self.catalog
            ),
            receipt,
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(receipt.to_dict()[field], "none")

    def test_admission_tampering_and_nonconforming_report_are_rejected(self) -> None:
        attestation, report = self.report("oci_container")
        manifest = self.adapters.manifests_by_profile_id["AOE-GB-D06-S09"]
        receipt = admit_conformant_backend_for_manifest(
            report, attestation, manifest, self.catalog
        )
        tampered = copy.deepcopy(receipt.to_dict())
        tampered["manifest_sha256"] = ZERO_SHA
        with self.assertRaisesRegex(QualificationError, "binding"):
            BackendAdmissionReceipt.from_dict(
                tampered, report, attestation, manifest, self.catalog
            )
        _, failed_report = self.report("oci_container", OCI_PROBES[0])
        with self.assertRaisesRegex(QualificationError, "Nonconforming"):
            admit_conformant_backend_for_manifest(
                failed_report, attestation, manifest, self.catalog
            )
        forged_catalog = replace(self.catalog, document_json="{}")
        with self.assertRaisesRegex(QualificationError, "catalog fields"):
            admit_conformant_backend_for_manifest(
                report, attestation, manifest, forged_catalog
            )

    def test_observation_requires_evidence_and_structured_measurement(self) -> None:
        for evidence, measurement, message in (
            ((), {"observed": True}, "evidence"),
            ((TWO_SHA,), {}, "measurement"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(QualificationError, message):
                    build_conformance_observation(
                        probe_id=OCI_PROBES[0],
                        status="passed",
                        evidence_sha256=evidence,
                        measurement=measurement,
                    )

    def test_catalog_file_is_canonical_json(self) -> None:
        document = json.loads(
            (REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(document, self.catalog.to_dict())


if __name__ == "__main__":
    unittest.main()
