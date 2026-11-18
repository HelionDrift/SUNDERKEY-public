"""Phase 157 host-side candidate execution collection tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_candidate_development_gates import load_adapters
from sunderkey.candidate_adapter_runner import (
    OCI_GUARANTEES,
    BackendExecutionReport,
    ContainmentBackendAttestation,
    ContainmentLimits,
    execute_contained_adapter,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import AdapterInvocation, AdapterResult
from sunderkey.candidate_backend_conformance import (
    OCI_PROBES,
    admit_conformant_backend_for_manifest,
    build_backend_conformance_report,
    build_conformance_observation,
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_backend_host_preflight import (
    assess_containment_host_preflight,
    build_containment_backend_deployment_binding,
    build_containment_host_snapshot,
    compute_provider_binary_bundle_sha256,
    compute_provider_configuration_bundle_sha256,
)
from sunderkey.candidate_execution_collector import (
    MAX_COLLECTION_CONTROL_BYTES,
    CandidateExecutionCollectorPlan,
    _verify_inventory,
    build_candidate_execution_collector_plan,
    publish_signed_candidate_execution_collection,
    verify_published_candidate_execution_collection,
)
from sunderkey.candidate_execution_evidence_import import (
    build_candidate_execution_evidence_challenge,
)
from sunderkey.errors import PrincipalAuthenticationError, QualificationError
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64
TWO_SHA = "sha256:" + "2" * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def binaries() -> list[dict[str, str]]:
    return [
        {
            "name": "podman",
            "version": "test-1",
            "sha256": ZERO_SHA,
            "source_url": "https://example.invalid/podman",
            "license_spdx": "Apache-2.0",
        }
    ]


def configurations() -> list[dict[str, str]]:
    return [
        {
            "name": "containment-policy",
            "sha256": ONE_SHA,
            "media_type": "application/json",
        },
        {
            "name": "runtime-policy",
            "sha256": TWO_SHA,
            "media_type": "application/toml",
        },
    ]


class EvidenceBackend:
    def __init__(self, attestation, result) -> None:
        self.attestation = attestation
        self.result = result

    def execute(self, plan, request):
        del request
        return BackendExecutionReport(
            plan_id=plan.plan_id,
            backend_attestation_sha256=self.attestation.attestation_sha256,
            started_at="2026-09-20T01:00:01Z",
            finished_at="2026-09-20T01:00:02Z",
            output_bytes=1024,
            timed_out=False,
            cancelled=False,
            result=self.result,
        )

    def cancel(self, plan_id: str) -> bool:
        return bool(plan_id)


class CandidateExecutionCollectorPhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        adapter_catalog = load_adapters()
        self.adapter = build_reference_adapters(adapter_catalog)["AOE-GB-D06-S09"]
        self.manifest = self.adapter.manifest
        self.catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.execution-collector.oci",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=compute_provider_binary_bundle_sha256(binaries(), "oci_container"),
            configuration_sha256=compute_provider_configuration_bundle_sha256(configurations()),
            source_url="https://example.invalid/execution-collector",
            license_spdx="Apache-2.0",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )
        observations = [
            build_conformance_observation(
                probe_id=probe_id,
                status="passed",
                evidence_sha256=(f"sha256:{hashlib.sha256(probe_id.encode('ascii')).hexdigest()}",),
                measurement={"observed": True, "probe_id": probe_id},
            )
            for probe_id in OCI_PROBES
        ]
        self.conformance_report = build_backend_conformance_report(
            attestation=self.attestation,
            catalog=self.catalog,
            observations=observations,
            tested_at="2026-09-20T00:55:00Z",
            verifier_id="signed-collector:test",
        )
        self.backend_admission = admit_conformant_backend_for_manifest(
            self.conformance_report,
            self.attestation,
            self.manifest,
            self.catalog,
        )
        self.binding = build_containment_backend_deployment_binding(
            catalog=self.catalog,
            attestation=self.attestation,
            host_id="host.test.execution-collector",
            architecture="x86_64",
            service_identity_id="service.test.execution-collector",
            binary_components=binaries(),
            configuration_components=configurations(),
        )
        self.snapshot = self.build_snapshot()
        self.preflight = assess_containment_host_preflight(
            binding=self.binding,
            snapshot=self.snapshot,
            catalog=self.catalog,
            attestation=self.attestation,
        )
        self.invocation = AdapterInvocation(
            invocation_id="INV-COLLECTOR-001",
            mission_id="MISSION-SYNTHETIC-001",
            authority_ref="AUTH-SYNTHETIC-001",
            profile_id=self.manifest.profile_id,
            vector_id=self.manifest.vector_id,
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
        self.execution_plan = prepare_containment_execution_plan(
            self.manifest,
            self.invocation,
            self.attestation,
            ContainmentLimits(),
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:01:00Z",
        )
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.challenge = build_candidate_execution_evidence_challenge(
            manifest=self.manifest,
            attestation=self.attestation,
            conformance_catalog=self.catalog,
            conformance_report=self.conformance_report,
            backend_admission=self.backend_admission,
            collector_id="collector.test.candidate-execution",
            key_id="key.test.candidate-execution.1",
            public_key_sha256=f"sha256:{hashlib.sha256(self.public_key).hexdigest()}",
            nonce=b64url(bytes(range(32))),
            sequence_number=23,
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:10:00Z",
        )
        self.plan = self.build_plan()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_snapshot(self, **overrides):
        values = {
            "host_id": "host.test.execution-collector",
            "collected_at": "2026-09-20T00:50:00Z",
            "os_name": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.12.0-test",
            "service_identity_id": "service.test.execution-collector",
            "binary_components": [
                {**item, "path": f"/usr/bin/{item['name']}"} for item in binaries()
            ],
            "configuration_components": configurations(),
            "cgroup_version": "v2",
            "seccomp_enabled": True,
            "rootless_provider": True,
            "user_namespace_enabled": True,
            "kvm_access": False,
            "dedicated_jailer_uid_gid": False,
            "single_tenant_vm": False,
            "bounded_logging": False,
            "host_hardening": False,
        }
        values.update(overrides)
        return build_containment_host_snapshot(**values)

    def build_plan(self, **overrides):
        values = self.inputs()
        values.update(overrides)
        return build_candidate_execution_collector_plan(**values)

    def inputs(self):
        return {
            "manifest": self.manifest,
            "invocation": self.invocation,
            "attestation": self.attestation,
            "catalog": self.catalog,
            "conformance_report": self.conformance_report,
            "backend_admission": self.backend_admission,
            "binding": self.binding,
            "snapshot": self.snapshot,
            "preflight": self.preflight,
            "challenge": self.challenge,
            "execution_plan": self.execution_plan,
        }

    def outcome(self, result: AdapterResult | None = None):
        candidate_result = self.adapter.execute(self.invocation) if result is None else result
        receipt = execute_contained_adapter(
            EvidenceBackend(self.attestation, candidate_result),
            self.execution_plan,
            self.invocation,
            observed_at="2026-09-20T01:00:01Z",
        )
        return receipt, candidate_result

    def publish(self, name: str = "collection", result: AdapterResult | None = None, **overrides):
        receipt, candidate_result = self.outcome(result)
        values = {
            "output_directory": self.root / name,
            "plan": self.plan,
            **self.inputs(),
            "receipt": receipt,
            "result": candidate_result,
            "collected_at": "2026-09-20T01:00:04Z",
            "signer": self.private_key.sign,
            "collector_public_key": self.public_key,
        }
        values.update(overrides)
        return publish_signed_candidate_execution_collection(**values)

    def verify(self, directory, **overrides):
        values = {
            "directory": directory,
            "expected_plan": self.plan,
            **self.inputs(),
            "collector_public_key": self.public_key,
            "observed_at": "2026-09-20T01:00:05Z",
        }
        values.update(overrides)
        return verify_published_candidate_execution_collection(**values)

    def test_plan_binds_admission_preflight_challenge_and_execution(self) -> None:
        raw = self.plan.to_dict()
        self.assertEqual(raw["backend_admission_id"], self.backend_admission.admission_id)
        self.assertEqual(raw["snapshot_id"], self.snapshot.snapshot_id)
        self.assertEqual(raw["challenge_id"], self.challenge.challenge_id)
        self.assertEqual(raw["execution_plan_id"], self.execution_plan.plan_id)
        self.assertEqual(raw["publication_contract"]["private_key_storage"], "prohibited")
        self.assertEqual(
            CandidateExecutionCollectorPlan.from_dict(self.plan.to_dict(), **self.inputs()),
            self.plan,
        )

    def test_blocked_host_and_noncanonical_challenge_refuse_planning(self) -> None:
        blocked_snapshot = self.build_snapshot(rootless_provider=False)
        blocked_preflight = assess_containment_host_preflight(
            binding=self.binding,
            snapshot=blocked_snapshot,
            catalog=self.catalog,
            attestation=self.attestation,
        )
        with self.assertRaisesRegex(QualificationError, "passing host preflight"):
            self.build_plan(snapshot=blocked_snapshot, preflight=blocked_preflight)
        changed = self.challenge.to_dict()
        changed["challenge_sha256"] = ZERO_SHA
        forged = replace(
            self.challenge,
            document_json=json.dumps(changed, sort_keys=True, separators=(",", ":")),
        )
        with self.assertRaisesRegex(QualificationError, "identity"):
            self.build_plan(challenge=forged)

    def test_clean_collection_is_atomic_exact_and_import_ready(self) -> None:
        published = self.publish()
        self.assertEqual(published.readiness_status, "published_signed_import_ready")
        self.assertEqual(published.failure_reasons, ())
        self.assertIsNotNone(published.verified_evidence)
        verified = self.verify(published.output_directory)
        self.assertEqual(verified.collection_id, published.collection_id)
        self.assertEqual(verified.packet.packet_sha256, published.packet.packet_sha256)
        self.assertIsNotNone(verified.verified_evidence)
        actual_files = {
            path.relative_to(published.output_directory).as_posix()
            for path in published.output_directory.rglob("*")
            if path.is_file()
        }
        self.assertIn("packet/packet-manifest.json", actual_files)
        self.assertNotIn("private-key.json", actual_files)
        self.assertFalse(any("private" in path for path in actual_files))

    def test_failed_execution_is_preserved_but_never_import_ready(self) -> None:
        failed = AdapterResult.build(
            status="failed_closed",
            disposition="abstention",
            observations=(),
            evidence=(),
            restoration_status="failed_closed",
            residual_effects=(),
        )
        published = self.publish("failed", result=failed)
        self.assertEqual(published.readiness_status, "published_signed_nonconforming")
        self.assertEqual(
            published.failure_reasons,
            ("result_not_completed", "restoration_not_verified"),
        )
        self.assertIsNone(published.verified_evidence)
        verified = self.verify(published.output_directory)
        self.assertEqual(verified.result.status, "failed_closed")
        self.assertIsNone(verified.verified_evidence)

    def test_bad_signature_collision_and_tampering_fail_closed(self) -> None:
        bad_output = self.root / "bad-signature"
        with self.assertRaises(PrincipalAuthenticationError):
            self.publish(
                "bad-signature",
                signer=lambda message: bytes(64),
            )
        self.assertFalse(bad_output.exists())
        published = self.publish()
        with self.assertRaisesRegex(QualificationError, "already exists"):
            self.publish()
        result_path = published.output_directory / "packet" / "adapter-result.json"
        result_path.write_text("{}\n", encoding="ascii")
        with self.assertRaisesRegex(QualificationError, "integrity failed"):
            self.verify(published.output_directory)

    def test_extra_files_wrong_key_and_symlinks_are_rejected(self) -> None:
        published = self.publish()
        extra = published.output_directory / "unexpected.json"
        extra.write_text("{}\n", encoding="ascii")
        with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
            self.verify(published.output_directory)
        extra.unlink()
        unexpected_directory = published.output_directory / "unexpected-directory"
        unexpected_directory.mkdir()
        with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
            self.verify(published.output_directory)
        unexpected_directory.rmdir()
        wrong_public_key = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        with self.assertRaisesRegex(QualificationError, "public key does not match"):
            self.verify(published.output_directory, collector_public_key=wrong_public_key)
        link = published.output_directory / "packet-link.json"
        try:
            os.symlink(
                published.output_directory / "collector-plan.json",
                link,
            )
        except OSError:
            return
        with self.assertRaisesRegex(QualificationError, "cannot contain symlinks"):
            self.verify(published.output_directory)

    def test_control_document_load_rejects_ambiguous_or_oversized_json(self) -> None:
        published = self.publish()
        plan_path = published.output_directory / "collector-plan.json"
        original = plan_path.read_bytes()
        mutations = (
            (original + b" ", "not canonical"),
            (
                original.replace(
                    b'"schema_version":', b'"schema_version":1,"schema_version":', 1
                ),
                "could not be loaded",
            ),
            (b" " * (MAX_COLLECTION_CONTROL_BYTES + 1), "hard limits"),
        )
        for content, error in mutations:
            with self.subTest(error=error, size=len(content)):
                plan_path.write_bytes(content)
                with self.assertRaisesRegex(QualificationError, error):
                    self.verify(published.output_directory)
        plan_path.write_bytes(original)
        self.assertEqual(
            self.verify(published.output_directory).readiness_status,
            "published_signed_import_ready",
        )

    def test_inventory_rejects_unsafe_and_oversized_artifact_records(self) -> None:
        for relative in ("../outside.json", "packet\\..\\outside.json", "packet//bad.json"):
            with self.subTest(path=relative):
                record = {
                    "path": relative,
                    "media_type": "application/json",
                    "byte_size": 3,
                    "sha256": ZERO_SHA,
                }
                with self.assertRaisesRegex(QualificationError, "path is unsafe"):
                    _verify_inventory(self.root, [record])
        oversized = {
            "path": "collector-plan.json",
            "media_type": "application/json",
            "byte_size": MAX_COLLECTION_CONTROL_BYTES + 1,
            "sha256": ZERO_SHA,
        }
        with self.assertRaisesRegex(QualificationError, "artifact is invalid"):
            _verify_inventory(self.root, [oversized])


if __name__ == "__main__":
    unittest.main()
