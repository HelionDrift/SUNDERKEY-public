"""Phase 157 signed candidate execution evidence import tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_candidate_development_gates import load_adapters
from sunderkey.candidate_adapter_evidence import CandidateEvidencePacket
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
from sunderkey.candidate_execution_evidence_import import (
    SignedCandidateExecutionEvidenceSubmission,
    VerifiedCandidateExecutionEvidence,
    build_candidate_execution_evidence_challenge,
    finalize_candidate_execution_evidence_submission,
    prepare_candidate_execution_evidence_submission,
    verify_candidate_execution_evidence_submission,
)
from sunderkey.errors import PrincipalAuthenticationError, QualificationError
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class EvidenceBackend:
    def __init__(self, attestation, result) -> None:
        self.attestation = attestation
        self.result = result

    def execute(self, plan, request):
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


class CandidateExecutionEvidenceImportPhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter_catalog = load_adapters()
        self.adapter = build_reference_adapters(self.adapter_catalog)["AOE-GB-D06-S09"]
        self.manifest = self.adapter.manifest
        self.conformance_catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.execution-evidence.oci",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/execution-evidence-backend",
            license_spdx="LicenseRef-Test-Only",
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
            catalog=self.conformance_catalog,
            observations=observations,
            tested_at="2026-09-20T00:55:00Z",
            verifier_id="signed-collector:test",
        )
        self.backend_admission = admit_conformant_backend_for_manifest(
            self.conformance_report,
            self.attestation,
            self.manifest,
            self.conformance_catalog,
        )
        self.invocation = AdapterInvocation(
            invocation_id="INV-SIGNED-EVIDENCE-001",
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
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.challenge = build_candidate_execution_evidence_challenge(
            manifest=self.manifest,
            attestation=self.attestation,
            conformance_catalog=self.conformance_catalog,
            conformance_report=self.conformance_report,
            backend_admission=self.backend_admission,
            collector_id="collector.test.candidate-execution",
            key_id="key.test.candidate-execution.1",
            public_key_sha256=f"sha256:{hashlib.sha256(self.public_key).hexdigest()}",
            nonce=b64url(bytes(range(32))),
            sequence_number=19,
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:10:00Z",
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_packet(self, result: AdapterResult | None = None, name: str = "packet"):
        candidate_result = self.adapter.execute(self.invocation) if result is None else result
        backend = EvidenceBackend(self.attestation, candidate_result)
        plan = prepare_containment_execution_plan(
            self.manifest,
            self.invocation,
            self.attestation,
            ContainmentLimits(),
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:01:00Z",
        )
        receipt = execute_contained_adapter(
            backend,
            plan,
            self.invocation,
            observed_at="2026-09-20T01:00:01Z",
        )
        packet = CandidateEvidencePacket.build(
            manifest=self.manifest,
            attestation=self.attestation,
            plan=plan,
            receipt=receipt,
            result=candidate_result,
            created_at="2026-09-20T01:00:03Z",
        )
        directory = self.root / name
        packet.publish(directory)
        return packet, directory

    def sign(self, packet):
        unsigned = prepare_candidate_execution_evidence_submission(
            challenge=self.challenge,
            packet=packet,
            collected_at="2026-09-20T01:00:04Z",
        )
        signature = b64url(self.private_key.sign(unsigned.signing_bytes()))
        return finalize_candidate_execution_evidence_submission(
            unsigned,
            signature,
            challenge=self.challenge,
            packet=packet,
        )

    def verify(self, submission, directory, **overrides):
        values = {
            "submission": submission,
            "challenge": self.challenge,
            "manifest": self.manifest,
            "invocation": self.invocation,
            "attestation": self.attestation,
            "conformance_catalog": self.conformance_catalog,
            "conformance_report": self.conformance_report,
            "backend_admission": self.backend_admission,
            "evidence_root": directory,
            "collector_public_key": self.public_key,
            "observed_at": "2026-09-20T01:00:05Z",
        }
        values.update(overrides)
        return verify_candidate_execution_evidence_submission(**values)

    def test_signed_packet_verifies_and_binds_complete_execution_chain(self) -> None:
        packet, directory = self.build_packet()
        submission = self.sign(packet)
        verified = self.verify(submission, directory)
        self.assertEqual(verified.packet.packet_sha256, packet.packet_sha256)
        self.assertEqual(verified.plan.plan_id, packet.manifest["plan_id"])
        self.assertEqual(verified.receipt.receipt_id, packet.manifest["receipt_id"])
        self.assertEqual(verified.result.result_sha256, packet.manifest["result_sha256"])
        self.assertEqual(verified.collector_id, "collector.test.candidate-execution")
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(submission.to_dict()[field], "none")

    def test_signature_key_and_validity_window_are_enforced(self) -> None:
        packet, directory = self.build_packet()
        submission = self.sign(packet)
        changed = submission.to_dict()
        changed["signature"] = b64url(bytes(64))
        tampered = SignedCandidateExecutionEvidenceSubmission.from_dict(
            changed, challenge=self.challenge, packet=packet
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.verify(tampered, directory)
        wrong_key = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        with self.assertRaisesRegex(QualificationError, "public key does not match"):
            self.verify(submission, directory, collector_public_key=wrong_key)
        with self.assertRaisesRegex(QualificationError, "validity window"):
            self.verify(submission, directory, observed_at="2026-09-20T01:10:00Z")

    def test_packet_tampering_and_extra_files_are_rejected(self) -> None:
        packet, directory = self.build_packet()
        submission = self.sign(packet)
        (directory / "unexpected.txt").write_text("extra\n", encoding="ascii")
        with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
            self.verify(submission, directory)
        (directory / "unexpected.txt").unlink()
        empty = directory / "unexpected-directory"
        empty.mkdir()
        with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
            self.verify(submission, directory)
        empty.rmdir()
        (directory / "adapter-result.json").write_text("{}\n", encoding="ascii")
        with self.assertRaisesRegex(QualificationError, "integrity failed"):
            self.verify(submission, directory)

    def test_wrong_invocation_and_admission_are_rejected(self) -> None:
        packet, directory = self.build_packet()
        submission = self.sign(packet)
        wrong_invocation = replace(self.invocation, invocation_id="INV-SUBSTITUTED-001")
        with self.assertRaisesRegex(QualificationError, "does not match admitted inputs"):
            self.verify(submission, directory, invocation=wrong_invocation)
        changed = copy.deepcopy(self.backend_admission.to_dict())
        changed["manifest_sha256"] = ZERO_SHA
        forged = replace(
            self.backend_admission,
            document_json=json.dumps(changed, sort_keys=True, separators=(",", ":")),
        )
        with self.assertRaisesRegex(QualificationError, "binding"):
            self.verify(submission, directory, backend_admission=forged)

    def test_failed_closed_result_cannot_become_verified_evidence(self) -> None:
        failed = AdapterResult.build(
            status="failed_closed",
            disposition="abstention",
            observations=(),
            evidence=(),
            restoration_status="failed_closed",
            residual_effects=(),
        )
        packet, directory = self.build_packet(failed, "failed-packet")
        submission = self.sign(packet)
        with self.assertRaisesRegex(QualificationError, "did not complete cleanly"):
            self.verify(submission, directory)

    def test_verified_wrapper_cannot_be_forged(self) -> None:
        packet, directory = self.build_packet()
        submission = self.sign(packet)
        verified = self.verify(submission, directory)
        with self.assertRaisesRegex(QualificationError, "proof is invalid"):
            VerifiedCandidateExecutionEvidence(
                verified.submission,
                verified.packet,
                verified.plan,
                verified.receipt,
                verified.result,
                verified.challenge_sha256,
                verified.backend_admission_sha256,
                verified.collector_id,
                verified.key_id,
                bytes(32),
            )


if __name__ == "__main__":
    unittest.main()
