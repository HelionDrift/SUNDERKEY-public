"""Phase 157 externally enforced containment admission and receipt tests."""

from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_runner import (
    MICROVM_GUARANTEES,
    OCI_GUARANTEES,
    BackendExecutionReport,
    ContainmentBackendAttestation,
    ContainmentExecutionPlan,
    ContainmentExecutionReceipt,
    ContainmentLimits,
    execute_contained_adapter,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import (
    AdapterInvocation,
    AdapterResult,
    load_candidate_adapter_catalog,
)
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError
from sunderkey.reference_adapters import OfflineReferenceAdapter, build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64


def attestation(isolation_class: str) -> ContainmentBackendAttestation:
    guarantees = OCI_GUARANTEES if isolation_class == "oci_container" else MICROVM_GUARANTEES
    return ContainmentBackendAttestation.build(
        backend_id=f"containment.test.{isolation_class.replace('_', '-')}",
        backend_version="test-1",
        isolation_class=isolation_class,
        executable_sha256=ZERO_SHA,
        configuration_sha256=ONE_SHA,
        source_url="https://example.invalid/containment-test-backend",
        license_spdx="LicenseRef-Test-Only",
        host_os="linux",
        guarantees=tuple(sorted(guarantees)),
    )


def invocation(adapter: OfflineReferenceAdapter) -> AdapterInvocation:
    return AdapterInvocation(
        invocation_id="INV-CONTAINMENT-001",
        mission_id="MISSION-SYNTHETIC-001",
        authority_ref="AUTH-SYNTHETIC-001",
        profile_id=adapter.manifest.profile_id,
        vector_id=adapter.manifest.vector_id,
        target_id="TARGET-SYNTHETIC-001",
        scope_id="SCOPE-SYNTHETIC-001",
        action_tier="R0",
        environment="synthetic",
        dry_run=True,
        credential_refs=(),
        input_data={
            "exchanges": [
                {
                    "evidence_id": "http-1",
                    "subject_id": "user-a",
                    "object_id": "object-b",
                    "expected_permitted": False,
                    "status_code": 200,
                }
            ]
        },
    )


class TestBackend:
    def __init__(
        self,
        adapter: OfflineReferenceAdapter,
        backend_attestation: ContainmentBackendAttestation,
    ) -> None:
        self.adapter = adapter
        self.attestation = backend_attestation
        self.output_bytes = 1024
        self.started_at = "2026-09-19T12:00:01Z"
        self.finished_at = "2026-09-19T12:00:02Z"
        self.timed_out = False
        self.cancelled = False
        self.result_override: AdapterResult | None = None

    def execute(self, plan, request):
        result = self.result_override or self.adapter.execute(request)
        return BackendExecutionReport(
            plan_id=plan.plan_id,
            backend_attestation_sha256=self.attestation.attestation_sha256,
            started_at=self.started_at,
            finished_at=self.finished_at,
            output_bytes=self.output_bytes,
            timed_out=self.timed_out,
            cancelled=self.cancelled,
            result=result,
        )

    def cancel(self, plan_id: str) -> bool:
        return bool(plan_id)


class CandidateAdapterRunnerPhase157Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
        )
        blueprints = load_blueprints()
        catalog = load_candidate_adapter_catalog(
            REGISTRY_DIR / "candidate-adapters-reference-v1.json",
            strategy,
            blueprints,
            ROOT,
        )
        cls.adapters = build_reference_adapters(catalog)

    def make_plan(
        self,
        adapter,
        backend_attestation=None,
        limits=None,
        expires_at="2026-09-19T12:01:00Z",
    ):
        return prepare_containment_execution_plan(
            adapter.manifest,
            invocation(adapter),
            backend_attestation or attestation("oci_container"),
            limits or ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at=expires_at,
        )

    def test_oci_plan_is_content_addressed_and_preserves_no_effects(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        plan = self.make_plan(adapter)
        duplicate = self.make_plan(adapter)
        self.assertEqual(plan.plan_id, duplicate.plan_id)
        self.assertEqual(plan.plan_sha256, duplicate.plan_sha256)
        self.assertEqual(
            plan.to_dict()["resource_policy"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(plan.to_dict()[field], "none")

    def test_microvm_manifest_rejects_oci_backend_and_accepts_microvm(self) -> None:
        adapter = self.adapters["AOE-GC-D14-S01"]
        request = replace(
            invocation(self.adapters["AOE-GB-D06-S09"]),
            profile_id=adapter.manifest.profile_id,
            vector_id=adapter.manifest.vector_id,
            input_data={"statements": []},
        )
        with self.assertRaisesRegex(QualificationError, "below the manifest"):
            prepare_containment_execution_plan(
                adapter.manifest,
                request,
                attestation("oci_container"),
                ContainmentLimits(),
                issued_at="2026-09-19T12:00:00Z",
                expires_at="2026-09-19T12:01:00Z",
            )
        plan = prepare_containment_execution_plan(
            adapter.manifest,
            request,
            attestation("microvm"),
            ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at="2026-09-19T12:01:00Z",
        )
        self.assertEqual(plan.isolation_class, "microvm")

    def test_backend_attestation_requires_complete_external_guarantees(self) -> None:
        with self.assertRaisesRegex(QualificationError, "incomplete"):
            ContainmentBackendAttestation.build(
                backend_id="containment.test.incomplete",
                backend_version="test-1",
                isolation_class="oci_container",
                executable_sha256=ZERO_SHA,
                configuration_sha256=ONE_SHA,
                source_url="https://example.invalid/test",
                license_spdx="LicenseRef-Test-Only",
                host_os="linux",
                guarantees=("external_boundary",),
            )

    def test_valid_backend_report_produces_nonqualifying_receipt(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = TestBackend(adapter, attestation("oci_container"))
        plan = self.make_plan(adapter, backend.attestation)
        receipt = execute_contained_adapter(
            backend,
            plan,
            invocation(adapter),
            observed_at="2026-09-19T12:00:01Z",
        )
        self.assertEqual(receipt.run_status, "completed_nonqualifying")
        self.assertEqual(receipt.to_dict()["qualification_effect"], "none")
        self.assertEqual(receipt.to_dict()["result_disposition"], "verified_finding")
        self.assertEqual(
            ContainmentExecutionReceipt.from_dict(receipt.to_dict(), plan),
            receipt,
        )
        self.assertEqual(
            ContainmentExecutionPlan.from_dict(
                plan.to_dict(), adapter.manifest, invocation(adapter), backend.attestation
            ),
            plan,
        )
        self.assertEqual(
            ContainmentBackendAttestation.from_dict(backend.attestation.to_dict()),
            backend.attestation,
        )

    def test_expired_or_not_yet_valid_plan_never_reaches_backend(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = TestBackend(adapter, attestation("oci_container"))
        plan = self.make_plan(adapter, backend.attestation)
        for observed_at, message in (
            ("2026-09-19T11:59:59Z", "not yet valid"),
            ("2026-09-19T12:01:00Z", "expired"),
        ):
            with self.subTest(observed_at=observed_at):
                with self.assertRaisesRegex(QualificationError, message):
                    execute_contained_adapter(
                        backend, plan, invocation(adapter), observed_at=observed_at
                    )

    def test_output_and_deadline_violations_fail_receipt_validation(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = TestBackend(adapter, attestation("oci_container"))
        plan = self.make_plan(
            adapter,
            backend.attestation,
            ContainmentLimits(timeout_seconds=10, output_bytes=2048),
            expires_at="2026-09-19T12:00:10Z",
        )
        backend.output_bytes = 2049
        with self.assertRaisesRegex(QualificationError, "output exceeded"):
            execute_contained_adapter(
                backend, plan, invocation(adapter), observed_at="2026-09-19T12:00:01Z"
            )
        backend.output_bytes = 100
        backend.finished_at = "2026-09-19T12:00:12Z"
        with self.assertRaisesRegex(QualificationError, "validity window|deadline"):
            execute_contained_adapter(
                backend, plan, invocation(adapter), observed_at="2026-09-19T12:00:01Z"
            )

    def test_timeout_and_cancellation_must_fail_closed(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = TestBackend(adapter, attestation("oci_container"))
        plan = self.make_plan(adapter, backend.attestation)
        backend.timed_out = True
        with self.assertRaisesRegex(QualificationError, "did not fail closed"):
            execute_contained_adapter(
                backend, plan, invocation(adapter), observed_at="2026-09-19T12:00:01Z"
            )
        backend.result_override = AdapterResult.build(
            status="cancelled",
            disposition="abstention",
            observations=(),
            evidence=(),
            restoration_status="failed_closed",
        )
        receipt = execute_contained_adapter(
            backend, plan, invocation(adapter), observed_at="2026-09-19T12:00:01Z"
        )
        self.assertEqual(receipt.run_status, "timed_out_fail_closed")

    def test_invocation_and_serialized_receipt_substitution_fail_closed(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = TestBackend(adapter, attestation("oci_container"))
        request = invocation(adapter)
        plan = self.make_plan(adapter, backend.attestation)
        changed_request = replace(request, target_id="TARGET-SYNTHETIC-OTHER")
        with self.assertRaisesRegex(QualificationError, "invocation does not match"):
            execute_contained_adapter(
                backend, plan, changed_request, observed_at="2026-09-19T12:00:01Z"
            )

        receipt = execute_contained_adapter(
            backend, plan, request, observed_at="2026-09-19T12:00:01Z"
        )
        changed = receipt.to_dict()
        changed["result_sha256"] = ZERO_SHA
        with self.assertRaisesRegex(QualificationError, "identity does not match"):
            ContainmentExecutionReceipt.from_dict(changed, plan)

    def test_attestation_substitution_is_rejected(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        original = attestation("oci_container")
        plan = self.make_plan(adapter, original)
        substituted = ContainmentBackendAttestation.build(
            backend_id="containment.test.substituted",
            backend_version="test-2",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/substituted",
            license_spdx="LicenseRef-Test-Only",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )
        backend = TestBackend(adapter, substituted)
        with self.assertRaisesRegex(QualificationError, "does not match the plan"):
            execute_contained_adapter(
                backend, plan, invocation(adapter), observed_at="2026-09-19T12:00:01Z"
            )


if __name__ == "__main__":
    unittest.main()
