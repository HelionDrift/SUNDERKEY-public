"""Phase 34 signed evidence manifest and reviewer attestation coverage."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_authority_decision import (
    load_qualification_authority_decision_record,
)
from sunderkey.qualification_evaluation import (
    QualificationEvaluationReport,
    QualificationObservationSet,
    evaluate_qualification_observations,
    load_qualification_evaluation_suite,
)
from sunderkey.qualification_evidence import (
    EVIDENCE_MANIFEST_SIGNING_DOMAIN,
    REVIEWER_ATTESTATION_SIGNING_DOMAIN,
    QualificationAttestationConclusion,
    QualificationEvidenceArtifact,
    QualificationEvidenceManifest,
    QualificationReviewerAttestation,
    VerifiedQualificationEvidenceManifest,
    VerifiedQualificationReviewerAttestation,
    compute_qualification_case_evidence_sha256,
    verify_qualification_evidence_manifest,
    verify_qualification_reviewer_attestation,
)
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    verify_qualification_reviewer_credential,
    verify_qualification_trust_policy,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from tests.agents.test_qualification_trust_phase32 import (
    qualification_reviewer_credential_document,
    qualification_trust_policy_document,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    NOW,
    PROFILE_ID,
    REVIEWER_ID,
    ROOT_KEY_ID,
    ROOT_SEED,
    _raw_public_key,
    _signed_credential,
    _signed_policy,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_ID = "candidate-owner-001"
OWNER_SEED = 5
REVIEWER_SEED = 4
REPOSITORY_ID = "qualification-evidence-cas"
CREATED_AT = "2026-02-01T12:00:00Z"
REVIEWED_AT = "2026-02-02T00:00:00Z"


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _encoded_public_key(seed: int) -> str:
    return _encoded(
        _private_key(seed).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def _dummy_signature() -> str:
    return _encoded(bytes(range(64)))


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


class QualificationEvidencePhase34Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(ROOT / "registry" / "army-v1.json")
        cls.catalog = load_capability_catalog(
            ROOT / "registry" / "capabilities-army-v1.json",
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            ROOT / "registry" / "qualification-standard-v1.json",
            cls.registry,
            cls.catalog,
        )
        cls.plans = load_qualification_plan_catalog(
            ROOT / "registry" / "qualification-plans-army-v1.json",
            cls.registry,
            cls.catalog,
            cls.standard,
        )
        cls.suite = load_qualification_evaluation_suite(
            ROOT / "examples" / "qualification" / "passive-osint-suite.json",
            cls.registry,
            cls.catalog,
            cls.standard,
            cls.plans,
        )
        cls.decision = load_qualification_authority_decision_record(
            ROOT / "registry" / "qualification-authority-decision-d008.json"
        )

    def _verified_policy(
        self,
        policy: Any | None = None,
        *,
        clock: datetime = NOW,
    ) -> VerifiedQualificationTrustPolicy:
        value = policy or _signed_policy()
        return verify_qualification_trust_policy(
            value,
            {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
            decision_record=self.decision,
            qualification_standard=self.standard,
            expected_issuer="sunderkey-qualification-authority",
            expected_audience="sunderkey-qualification",
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=1,
            clock=lambda: clock,
        )

    def _verified_credential(
        self,
        policy: Any,
        verified_policy: VerifiedQualificationTrustPolicy,
        *,
        reviewer_id: str = REVIEWER_ID,
        profile_id: str = PROFILE_ID,
        credential: Any | None = None,
        clock: datetime = NOW,
    ) -> VerifiedQualificationReviewerCredential:
        value = credential or _signed_credential(policy)
        return verify_qualification_reviewer_credential(
            value,
            verified_policy,
            expected_reviewer_id=reviewer_id,
            expected_role=QualificationReviewerRole.TECHNICAL_EVALUATOR,
            expected_profile_id=profile_id,
            clock=lambda: clock,
        )

    def _evidence_documents(
        self,
        *,
        owner_id: str = OWNER_ID,
        owner_seed: int = OWNER_SEED,
    ) -> tuple[
        dict[str, Any],
        QualificationObservationSet,
        QualificationEvaluationReport,
    ]:
        observations_raw = {
            "schema_version": 1,
            "observation_set_id": "qualification-observations-authoritative-v1",
            "observation_set_version": "1.0.0",
            "advisory_only": True,
            "suite_id": self.suite.suite_id,
            "suite_version": self.suite.suite_version,
            "suite_sha256": self.suite.canonical_sha256,
            "profile_id": self.suite.profile_id,
            "candidate": self.suite.candidate.to_dict(),
            "observations": [],
        }
        artifacts: list[dict[str, Any]] = []
        cases: list[dict[str, Any]] = []
        for index, suite_case in enumerate(
            sorted(self.suite.cases, key=lambda item: item.case_id),
            start=1,
        ):
            result_sha256 = _digest(f"result:{suite_case.case_id}")
            artifact_documents = [
                {
                    "artifact_id": f"evidence.{index:03d}.reproduction",
                    "case_id": suite_case.case_id,
                    "artifact_type": "reproduction_material",
                    "media_type": "application/json",
                    "size_bytes": 300 + index,
                    "sha256": _digest(f"reproduction:{suite_case.case_id}"),
                },
                {
                    "artifact_id": f"evidence.{index:03d}.result",
                    "case_id": suite_case.case_id,
                    "artifact_type": "candidate_result",
                    "media_type": "application/json",
                    "size_bytes": 100 + index,
                    "sha256": result_sha256,
                },
                {
                    "artifact_id": f"evidence.{index:03d}.supporting",
                    "case_id": suite_case.case_id,
                    "artifact_type": "supporting_evidence",
                    "media_type": "application/json",
                    "size_bytes": 200 + index,
                    "sha256": _digest(f"supporting:{suite_case.case_id}"),
                },
            ]
            artifact_documents.sort(key=lambda item: str(item["artifact_id"]))
            parsed_artifacts = tuple(
                QualificationEvidenceArtifact.from_dict(item, artifact_index)
                for artifact_index, item in enumerate(artifact_documents)
            )
            case_body = {
                "case_id": suite_case.case_id,
                "gate_id": suite_case.gate_id,
                "scenario_sha256": suite_case.scenario_sha256,
                "expected_result_sha256": suite_case.expected_result_sha256,
                "critical_failure_definition_sha256": (
                    suite_case.critical_failure_definition_sha256
                ),
                "outcome": "pass",
                "critical_failure": False,
                "result_sha256": result_sha256,
                "artifact_ids": [
                    artifact.artifact_id for artifact in parsed_artifacts
                ],
            }
            case_evidence_sha256 = compute_qualification_case_evidence_sha256(
                case_body,
                parsed_artifacts,
            )
            cases.append(
                {
                    **case_body,
                    "case_evidence_sha256": case_evidence_sha256,
                }
            )
            artifacts.extend(artifact_documents)
            observations_raw["observations"].append(
                {
                    "case_id": suite_case.case_id,
                    "outcome": "pass",
                    "critical_failure": False,
                    "result_sha256": result_sha256,
                    "evidence_manifest_sha256": case_evidence_sha256,
                }
            )
        artifacts.sort(
            key=lambda item: (str(item["case_id"]), str(item["artifact_id"]))
        )
        cases.sort(key=lambda item: str(item["case_id"]))
        observations_raw["observations"].sort(
            key=lambda item: str(item["case_id"])
        )
        observations = QualificationObservationSet.from_dict(
            observations_raw,
            self.suite,
        )
        report = evaluate_qualification_observations(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
            self.suite,
            observations,
        )
        policy = _signed_policy()
        document = {
            "schema_version": 1,
            "manifest_id": "QEM-33333333333333333333333333333333",
            "manifest_version": 1,
            "policy": {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "sha256": policy.content_sha256,
            },
            "qualification_standard": {
                "id": self.standard.standard_id,
                "version": self.standard.standard_version,
                "sha256": self.standard.canonical_sha256,
            },
            "evaluation_suite": {
                "id": self.suite.suite_id,
                "version": self.suite.suite_version,
                "sha256": self.suite.canonical_sha256,
            },
            "observation_set": {
                "id": observations.observation_set_id,
                "version": observations.observation_set_version,
                "sha256": observations.canonical_sha256,
            },
            "evaluation_report": {
                "id": report.report_id,
                "sha256": report.report_sha256,
            },
            "repository_id": REPOSITORY_ID,
            "profile_id": self.suite.profile_id,
            "candidate": self.suite.candidate.to_dict(),
            "candidate_owner_id": owner_id,
            "created_at": CREATED_AT,
            "artifacts": artifacts,
            "cases": cases,
            "algorithm": "Ed25519",
            "public_key": _encoded_public_key(owner_seed),
            "signature": _dummy_signature(),
        }
        return document, observations, report

    def _signed_manifest(
        self,
        *,
        policy: Any,
        document: dict[str, Any] | None = None,
        observations: QualificationObservationSet | None = None,
        report: QualificationEvaluationReport | None = None,
        owner_seed: int = OWNER_SEED,
    ) -> tuple[
        QualificationEvidenceManifest,
        QualificationObservationSet,
        QualificationEvaluationReport,
    ]:
        raw, generated_observations, generated_report = self._evidence_documents(
            owner_seed=owner_seed
        )
        raw = copy.deepcopy(document or raw)
        raw["policy"] = {
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "sha256": policy.content_sha256,
        }
        unsigned = QualificationEvidenceManifest.from_dict(raw)
        raw["signature"] = _encoded(
            _private_key(owner_seed).sign(unsigned.signing_bytes())
        )
        return (
            QualificationEvidenceManifest.from_dict(raw),
            observations or generated_observations,
            report or generated_report,
        )

    def _verify_manifest(
        self,
        manifest: QualificationEvidenceManifest,
        verified_policy: VerifiedQualificationTrustPolicy,
        observations: QualificationObservationSet,
        report: QualificationEvaluationReport,
        *,
        owner_id: str = OWNER_ID,
        owner_seed: int = OWNER_SEED,
        repository_id: str = REPOSITORY_ID,
        clock: datetime = NOW,
    ) -> VerifiedQualificationEvidenceManifest:
        return verify_qualification_evidence_manifest(
            manifest,
            verified_policy,
            registry=self.registry,
            capability_catalog=self.catalog,
            qualification_standard=self.standard,
            qualification_plans=self.plans,
            evaluation_suite=self.suite,
            observations=observations,
            evaluation_report=report,
            expected_candidate_owner_id=owner_id,
            expected_candidate_owner_public_key=_raw_public_key(owner_seed),
            expected_repository_id=repository_id,
            clock=lambda: clock,
        )

    def _signed_attestation(
        self,
        policy: Any,
        credential: Any,
        manifest: QualificationEvidenceManifest,
        *,
        reviewer_id: str = REVIEWER_ID,
        reviewer_seed: int = REVIEWER_SEED,
        conclusion: str = "supports_qualification",
        reviewed_at: str = REVIEWED_AT,
    ) -> QualificationReviewerAttestation:
        raw = {
            "schema_version": 1,
            "attestation_id": "QRA-44444444444444444444444444444444",
            "policy": {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "sha256": policy.content_sha256,
            },
            "reviewer_credential": {
                "credential_id": credential.credential_id,
                "sha256": credential.content_sha256,
            },
            "evidence_manifest": {
                "id": manifest.manifest_id,
                "sha256": manifest.content_sha256,
            },
            "reviewer_id": reviewer_id,
            "reviewer_role": credential.reviewer_role.value,
            "profile_id": manifest.profile_id,
            "candidate": manifest.candidate.to_dict(),
            "conclusion": conclusion,
            "reason_sha256": _digest("reviewer-reason"),
            "reviewed_at": reviewed_at,
            "algorithm": "Ed25519",
            "signature": _dummy_signature(),
        }
        unsigned = QualificationReviewerAttestation.from_dict(raw)
        raw["signature"] = _encoded(
            _private_key(reviewer_seed).sign(unsigned.signing_bytes())
        )
        return QualificationReviewerAttestation.from_dict(raw)

    def test_signed_manifest_and_attestation_verify(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        credential = _signed_credential(policy)
        verified_credential = self._verified_credential(
            policy,
            verified_policy,
            credential=credential,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
        )
        attestation = self._signed_attestation(policy, credential, manifest)
        verified_attestation = verify_qualification_reviewer_attestation(
            attestation,
            verified_policy,
            verified_credential,
            verified_manifest,
            expected_conclusion=(
                QualificationAttestationConclusion.SUPPORTS_QUALIFICATION
            ),
            clock=lambda: NOW,
        )

        self.assertTrue(
            manifest.signing_bytes().startswith(EVIDENCE_MANIFEST_SIGNING_DOMAIN)
        )
        self.assertTrue(
            attestation.signing_bytes().startswith(
                REVIEWER_ATTESTATION_SIGNING_DOMAIN
            )
        )
        self.assertEqual(verified_manifest.manifest_sha256, manifest.content_sha256)
        self.assertEqual(verified_attestation.reviewer_id, REVIEWER_ID)
        self.assertEqual(
            verified_attestation.conclusion,
            QualificationAttestationConclusion.SUPPORTS_QUALIFICATION,
        )

    def test_manifest_rejects_bad_signature_owner_and_repository(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        raw, observations, report = self._evidence_documents()
        raw["policy"] = {
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "sha256": policy.content_sha256,
        }
        unsigned = QualificationEvidenceManifest.from_dict(raw)
        raw["signature"] = _encoded(
            _private_key(6).sign(unsigned.signing_bytes())
        )
        manifest = QualificationEvidenceManifest.from_dict(raw)
        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
                owner_seed=OWNER_SEED,
            )

        manifest, observations, report = self._signed_manifest(policy=policy)
        with self.assertRaisesRegex(QualificationError, "owner"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
                owner_id="another-owner",
            )
        with self.assertRaisesRegex(QualificationError, "repository"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
                repository_id="another-repository",
            )

    def test_manifest_rejects_stale_policy_and_observations(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        raw, observations, report = self._evidence_documents()
        raw["policy"]["sha256"] = "sha256:" + "0" * 64
        unsigned = QualificationEvidenceManifest.from_dict(raw)
        raw["signature"] = _encoded(
            _private_key(OWNER_SEED).sign(unsigned.signing_bytes())
        )
        manifest = QualificationEvidenceManifest.from_dict(raw)
        with self.assertRaisesRegex(QualificationError, "policy binding"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
            )

        manifest, observations, report = self._signed_manifest(policy=policy)
        stale_raw = observations.to_dict()
        stale_raw["observations"][0]["result_sha256"] = _digest("stale-result")
        stale_observations = QualificationObservationSet.from_dict(
            stale_raw,
            self.suite,
        )
        stale_report = evaluate_qualification_observations(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
            self.suite,
            stale_observations,
        )
        with self.assertRaisesRegex(QualificationError, "observation binding"):
            self._verify_manifest(
                manifest,
                verified_policy,
                stale_observations,
                stale_report,
            )

    def test_manifest_rejects_bad_case_hash_partition_and_result(self) -> None:
        raw, _, _ = self._evidence_documents()
        raw["cases"][0]["case_evidence_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "case_evidence_sha256"):
            QualificationEvidenceManifest.from_dict(raw)

        raw, _, _ = self._evidence_documents()
        raw["cases"][0]["artifact_ids"].append(
            raw["cases"][1]["artifact_ids"][0]
        )
        raw["cases"][0]["artifact_ids"].sort()
        with self.assertRaisesRegex(QualificationError, "another case"):
            QualificationEvidenceManifest.from_dict(raw)

        raw, _, _ = self._evidence_documents()
        result_id = next(
            artifact_id
            for artifact_id in raw["cases"][0]["artifact_ids"]
            if artifact_id.endswith(".result")
        )
        result_artifact = next(
            artifact
            for artifact in raw["artifacts"]
            if artifact["artifact_id"] == result_id
        )
        result_artifact["sha256"] = _digest("different-result")
        with self.assertRaisesRegex(QualificationError, "digest does not match"):
            QualificationEvidenceManifest.from_dict(raw)

    def test_manifest_rejects_future_creation_and_authority_key_reuse(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        raw, observations, report = self._evidence_documents()
        raw["created_at"] = "2026-02-03T00:00:00Z"
        manifest, _, _ = self._signed_manifest(
            policy=policy,
            document=raw,
            observations=observations,
            report=report,
        )
        with self.assertRaisesRegex(QualificationError, "future"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
            )

        raw, observations, report = self._evidence_documents(owner_seed=1)
        manifest, _, _ = self._signed_manifest(
            policy=policy,
            document=raw,
            observations=observations,
            report=report,
            owner_seed=1,
        )
        with self.assertRaisesRegex(QualificationError, "authority key material"):
            self._verify_manifest(
                manifest,
                verified_policy,
                observations,
                report,
                owner_seed=1,
            )

    def test_attestation_rejects_bad_signature_and_conclusion(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        credential = _signed_credential(policy)
        verified_credential = self._verified_credential(
            policy,
            verified_policy,
            credential=credential,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
        )
        attestation = self._signed_attestation(
            policy,
            credential,
            manifest,
            reviewer_seed=6,
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="supports_qualification",
                clock=lambda: NOW,
            )

        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(QualificationError, "conclusion"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="does_not_support_qualification",
                clock=lambda: NOW,
            )

    def test_attestation_rejects_self_review_and_shared_key_material(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        credential = _signed_credential(policy)
        verified_credential = self._verified_credential(
            policy,
            verified_policy,
            credential=credential,
        )
        raw, observations, report = self._evidence_documents(
            owner_id=REVIEWER_ID
        )
        manifest, _, _ = self._signed_manifest(
            policy=policy,
            document=raw,
            observations=observations,
            report=report,
        )
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
            owner_id=REVIEWER_ID,
        )
        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(QualificationError, "own qualification"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="supports_qualification",
                clock=lambda: NOW,
            )

        raw, observations, report = self._evidence_documents(
            owner_seed=REVIEWER_SEED
        )
        manifest, _, _ = self._signed_manifest(
            policy=policy,
            document=raw,
            observations=observations,
            report=report,
            owner_seed=REVIEWER_SEED,
        )
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
            owner_seed=REVIEWER_SEED,
        )
        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(QualificationError, "distinct key material"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="supports_qualification",
                clock=lambda: NOW,
            )

    def test_attestation_rejects_wrong_credential_verification_time(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        credential = _signed_credential(policy)
        different_time = datetime(2026, 2, 3, tzinfo=UTC)
        verified_credential = self._verified_credential(
            policy,
            verified_policy,
            credential=credential,
            clock=different_time,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
        )
        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(QualificationError, "attestation time"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="supports_qualification",
                clock=lambda: different_time,
            )

    def test_attestation_rejects_credential_verified_for_another_profile(
        self,
    ) -> None:
        second_profile = "AOE-GA-D01-S02"
        policy_document = qualification_trust_policy_document()
        policy_document["allowed_profile_ids"] = [PROFILE_ID, second_profile]
        for key in policy_document["keys"]:
            key["allowed_profile_ids"] = [PROFILE_ID, second_profile]
        policy = _signed_policy(policy_document)
        verified_policy = self._verified_policy(policy)
        credential_document = qualification_reviewer_credential_document()
        credential_document["allowed_profile_ids"] = [PROFILE_ID, second_profile]
        credential = _signed_credential(policy, credential_document)
        verified_credential = self._verified_credential(
            policy,
            verified_policy,
            credential=credential,
            profile_id=second_profile,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified_manifest = self._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
        )
        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(QualificationError, "manifest profile"):
            verify_qualification_reviewer_attestation(
                attestation,
                verified_policy,
                verified_credential,
                verified_manifest,
                expected_conclusion="supports_qualification",
                clock=lambda: NOW,
            )

    def test_verified_wrappers_reject_direct_construction(self) -> None:
        policy = _signed_policy()
        manifest, _, _ = self._signed_manifest(policy=policy)
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationEvidenceManifest(
                manifest=manifest,
                manifest_sha256=manifest.content_sha256,
                owner_key_sha256="sha256:" + "0" * 64,
                policy_sha256=policy.content_sha256,
                verified_at=REVIEWED_AT,
                _proof=b"invalid",
            )

        credential = _signed_credential(policy)
        attestation = self._signed_attestation(policy, credential, manifest)
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationReviewerAttestation(
                attestation=attestation,
                attestation_sha256=attestation.content_sha256,
                credential_sha256=credential.content_sha256,
                reviewer_key_sha256="sha256:" + "0" * 64,
                manifest_sha256=manifest.content_sha256,
                policy_sha256=policy.content_sha256,
                verified_at=REVIEWED_AT,
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "qualification_evidence.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(imported & prohibited)


def qualification_evidence_contract_documents() -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    case = QualificationEvidencePhase34Tests()
    case.setUpClass()
    policy = _signed_policy()
    credential = _signed_credential(policy)
    manifest, _, _ = case._signed_manifest(policy=policy)
    attestation = case._signed_attestation(policy, credential, manifest)
    return manifest.to_dict(), attestation.to_dict()


if __name__ == "__main__":
    unittest.main()
