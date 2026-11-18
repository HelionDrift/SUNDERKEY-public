"""Phase 158 admission handoff contract tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_candidate_development_gates import load_adapters
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_adapter_evidence import (
    CandidateEvidencePacket,
    load_candidate_development_gate_catalog,
)
from sunderkey.candidate_adapter_runner import (
    OCI_GUARANTEES,
    BackendExecutionReport,
    ContainmentBackendAttestation,
    ContainmentLimits,
    execute_contained_adapter,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import AdapterInvocation
from sunderkey.candidate_backend_conformance import (
    OCI_PROBES,
    admit_conformant_backend_for_manifest,
    build_backend_conformance_report,
    build_conformance_observation,
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_execution_evidence_import import (
    VerifiedCandidateExecutionEvidence,
    build_candidate_execution_evidence_challenge,
    finalize_candidate_execution_evidence_submission,
    prepare_candidate_execution_evidence_submission,
    verify_candidate_execution_evidence_submission,
)
from sunderkey.candidate_phase158_handoff import (
    BLOCKER_DOMAIN,
    HANDOFF_DOMAIN,
    PLAN_ENTRY_DOMAIN,
    Phase158AdmissionHandoff,
    assess_phase158_admission_blockers,
    build_phase158_admission_handoff,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.reference_adapters import build_reference_adapters
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

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
            started_at="2026-09-20T02:00:01Z",
            finished_at="2026-09-20T02:00:02Z",
            output_bytes=1024,
            timed_out=False,
            cancelled=False,
            result=self.result,
        )

    def cancel(self, plan_id: str) -> bool:
        return bool(plan_id)


class CandidatePhase158HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter_catalog = load_adapters()
        cls.adapter = build_reference_adapters(cls.adapter_catalog)["AOE-GB-D06-S09"]
        cls.manifest = cls.adapter.manifest
        cls.development_gates = load_candidate_development_gate_catalog(
            REGISTRY_DIR / "candidate-adapter-development-gates-v1.json",
            cls.adapter_catalog,
        )
        cls.registry = load_registry(REGISTRY_DIR / "army-v2.json")
        cls.capabilities = load_capability_catalog(
            REGISTRY_DIR / "capabilities-army-v2.json", cls.registry
        )
        cls.roadmap = load_army_expansion_roadmap(REGISTRY_DIR / "army-expansion-roadmap-v1.json")
        cls.vectors = load_attack_vector_catalog(
            REGISTRY_DIR / "attack-vectors-v2.json", cls.registry, cls.roadmap
        )
        cls.standard = load_qualification_standard(
            REGISTRY_DIR / "qualification-standard-v2.json",
            cls.registry,
            cls.capabilities,
        )
        cls.qualification_plans = load_qualification_plan_catalog_v2(
            REGISTRY_DIR / "qualification-plans-army-v2.json",
            cls.registry,
            cls.capabilities,
            cls.vectors,
            cls.standard,
        )
        cls.conformance_catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )

    def setUp(self) -> None:
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.phase158-handoff.oci",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/phase158-handoff-backend",
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
            tested_at="2026-09-20T01:55:00Z",
            verifier_id="signed-collector:phase158-test",
        )
        self.backend_admission = admit_conformant_backend_for_manifest(
            self.conformance_report,
            self.attestation,
            self.manifest,
            self.conformance_catalog,
        )
        self.invocation = AdapterInvocation(
            invocation_id="INV-PHASE158-HANDOFF-001",
            mission_id="MISSION-SYNTHETIC-158-001",
            authority_ref="AUTH-SYNTHETIC-158-001",
            profile_id=self.manifest.profile_id,
            vector_id=self.manifest.vector_id,
            target_id="TARGET-SYNTHETIC-158-001",
            scope_id="SCOPE-SYNTHETIC-158-001",
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={
                "exchanges": [
                    {
                        "evidence_id": "http-158-1",
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
            collector_id="collector.test.phase158-handoff",
            key_id="key.test.phase158-handoff.1",
            public_key_sha256=f"sha256:{hashlib.sha256(self.public_key).hexdigest()}",
            nonce=b64url(bytes(range(32))),
            sequence_number=158,
            issued_at="2026-09-20T02:00:00Z",
            expires_at="2026-09-20T02:10:00Z",
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.evidence_root = Path(self.temporary.name) / "packet"
        result = self.adapter.execute(self.invocation)
        plan = prepare_containment_execution_plan(
            self.manifest,
            self.invocation,
            self.attestation,
            ContainmentLimits(),
            issued_at="2026-09-20T02:00:00Z",
            expires_at="2026-09-20T02:01:00Z",
        )
        receipt = execute_contained_adapter(
            EvidenceBackend(self.attestation, result),
            plan,
            self.invocation,
            observed_at="2026-09-20T02:00:01Z",
        )
        packet = CandidateEvidencePacket.build(
            manifest=self.manifest,
            attestation=self.attestation,
            plan=plan,
            receipt=receipt,
            result=result,
            created_at="2026-09-20T02:00:03Z",
        )
        packet.publish(self.evidence_root)
        unsigned = prepare_candidate_execution_evidence_submission(
            challenge=self.challenge,
            packet=packet,
            collected_at="2026-09-20T02:00:04Z",
        )
        submission = finalize_candidate_execution_evidence_submission(
            unsigned,
            b64url(self.private_key.sign(unsigned.signing_bytes())),
            challenge=self.challenge,
            packet=packet,
        )
        self.verified = verify_candidate_execution_evidence_submission(
            submission=submission,
            challenge=self.challenge,
            manifest=self.manifest,
            invocation=self.invocation,
            attestation=self.attestation,
            conformance_catalog=self.conformance_catalog,
            conformance_report=self.conformance_report,
            backend_admission=self.backend_admission,
            evidence_root=self.evidence_root,
            collector_public_key=self.public_key,
            observed_at="2026-09-20T02:00:05Z",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def static_args(self):
        return {
            "manifest": self.manifest,
            "adapter_catalog": self.adapter_catalog,
            "development_gates": self.development_gates,
            "qualification_plans": self.qualification_plans,
            "registry": self.registry,
            "capabilities": self.capabilities,
            "vectors": self.vectors,
            "roadmap": self.roadmap,
            "standard": self.standard,
        }

    def handoff_args(self):
        return {
            **self.static_args(),
            "verified_evidence": self.verified,
            "backend_admission": self.backend_admission,
            "attestation": self.attestation,
            "conformance_catalog": self.conformance_catalog,
            "conformance_report": self.conformance_report,
        }

    def build_handoff(self):
        return build_phase158_admission_handoff(
            **self.handoff_args(), prepared_at="2026-09-20T02:00:06Z"
        )

    @staticmethod
    def rehash_handoff(raw):
        body = {
            key: value for key, value in raw.items() if key not in {"handoff_id", "handoff_sha256"}
        }
        digest = _canonical_sha256({"domain": HANDOFF_DOMAIN, "document": body})
        raw["handoff_sha256"] = digest
        raw["handoff_id"] = f"PAH-{digest.removeprefix('sha256:')[:32].upper()}"

    def test_current_state_has_distinct_deterministic_blocker_assessment(self) -> None:
        first = assess_phase158_admission_blockers(**self.static_args())
        second = assess_phase158_admission_blockers(**self.static_args())
        self.assertEqual(first, second)
        self.assertEqual(first.status, "blocked_pending_external_phase157_evidence")
        self.assertEqual(
            first.blockers,
            (
                "containment_development_gate_blocked",
                "backend_admission_missing",
                "verified_candidate_execution_evidence_missing",
            ),
        )
        document = first.to_dict()
        self.assertNotIn("handoff_id", document)
        self.assertNotIn("prepared_for_phase158_evaluation", document.values())
        body = {
            key: value
            for key, value in document.items()
            if key not in {"assessment_id", "assessment_sha256"}
        }
        self.assertEqual(
            document["assessment_sha256"],
            _canonical_sha256({"domain": BLOCKER_DOMAIN, "document": body}),
        )

    def test_verified_inputs_prepare_exact_nonqualifying_review_handoff(self) -> None:
        handoff = self.build_handoff()
        document = handoff.to_dict()
        self.assertEqual(handoff.status, "prepared_for_phase158_evaluation")
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S09")
        self.assertEqual(document["domain_commander_id"], "AOE-GB-D06-CMD")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(document["manifest_sha256"], self.manifest.manifest_sha256)
        self.assertEqual(
            document["backend_admission_sha256"],
            self.backend_admission.admission_sha256,
        )
        self.assertEqual(
            document["evidence_submission_sha256"],
            self.verified.submission.submission_sha256,
        )
        self.assertEqual(len(document["development_gate_sha256"]), 6)
        self.assertEqual(document["required_scenario_variant_count"], 6)
        self.assertEqual(document["required_gate_count"], 8)
        self.assertEqual(document["minimum_distinct_evaluators"], 2)
        self.assertEqual(
            document["required_review_roles"],
            ["domain_commander", "independent_control", "independent_assurance"],
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(document[field], "none")

    def test_content_tamper_and_plan_substitution_are_rejected(self) -> None:
        handoff = self.build_handoff()
        tampered = handoff.to_dict()
        tampered["result_sha256"] = ZERO_SHA
        with self.assertRaises(QualificationError):
            Phase158AdmissionHandoff.from_dict(tampered, **self.handoff_args())

        substituted = handoff.to_dict()
        substituted["qualification_plan_entry"] = copy.deepcopy(
            substituted["qualification_plan_entry"]
        )
        substituted["qualification_plan_entry"]["evaluation_objective"] = "substituted plan entry"
        substituted["qualification_plan_entry_sha256"] = _canonical_sha256(
            {
                "domain": PLAN_ENTRY_DOMAIN,
                "plan": substituted["qualification_plan_entry"],
            }
        )
        self.rehash_handoff(substituted)
        with self.assertRaisesRegex(QualificationError, "binding"):
            Phase158AdmissionHandoff.from_dict(substituted, **self.handoff_args())

    def test_reviewer_and_manifest_substitution_are_rejected(self) -> None:
        handoff = self.build_handoff()
        for field, value in (
            ("domain_commander_id", "AOE-GA-D01-CMD"),
            ("independent_validator_id", "AOE-HQ-33"),
            ("manifest_sha256", ZERO_SHA),
        ):
            with self.subTest(field=field):
                changed = handoff.to_dict()
                changed[field] = value
                self.rehash_handoff(changed)
                with self.assertRaisesRegex(QualificationError, "binding"):
                    Phase158AdmissionHandoff.from_dict(changed, **self.handoff_args())

    def test_forged_verified_wrapper_and_backend_admission_are_rejected(self) -> None:
        forged_wrapper = object.__new__(VerifiedCandidateExecutionEvidence)
        for field, value in self.verified.__dict__.items():
            object.__setattr__(
                forged_wrapper,
                field,
                bytes(32) if field == "proof" else value,
            )
        with self.assertRaisesRegex(QualificationError, "proof is invalid"):
            build_phase158_admission_handoff(
                **{
                    **self.handoff_args(),
                    "verified_evidence": forged_wrapper,
                },
                prepared_at="2026-09-20T02:00:06Z",
            )
        forged_admission = replace(self.backend_admission, admission_sha256=ZERO_SHA)
        with self.assertRaises(QualificationError):
            build_phase158_admission_handoff(
                **{
                    **self.handoff_args(),
                    "backend_admission": forged_admission,
                },
                prepared_at="2026-09-20T02:00:06Z",
            )

    def test_operational_effect_cannot_be_embedded_in_handoff(self) -> None:
        handoff = self.build_handoff()
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            with self.subTest(field=field):
                changed = handoff.to_dict()
                changed[field] = "granted"
                self.rehash_handoff(changed)
                with self.assertRaisesRegex(QualificationError, "binding"):
                    Phase158AdmissionHandoff.from_dict(changed, **self.handoff_args())


if __name__ == "__main__":
    unittest.main()
