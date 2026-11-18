"""Phase 68 enrollment-bound qualification evidence coverage."""

from __future__ import annotations

import ast
import copy
import unittest
from pathlib import Path

from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_evidence import (
    VerifiedEnrolledQualificationEvidenceManifest,
    verify_enrolled_qualification_evidence_manifest,
)
from sunderkey.candidate_enrollment_verification import (
    verify_candidate_enrollment_catalog,
    verify_candidate_enrollment_signer_authorization,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    verify_qualification_reviewer_credential,
)
from tests.agents.test_candidate_enrollment_phase66 import (
    _public_key_sha256,
    enrollment_catalog_document,
)
from tests.agents.test_candidate_enrollment_verification_phase67 import (
    ASSURANCE_SEED,
    CONTROL_SEED,
    _review_credential_document,
    _signed_authorization,
    _signed_catalog,
)
from tests.agents.test_qualification_evidence_phase34 import (
    NOW,
    OWNER_ID,
    OWNER_SEED,
    REPOSITORY_ID,
    QualificationEvidencePhase34Tests,
    _encoded_public_key,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    ROOT_KEY_ID,
    ROOT_SEED,
    _raw_public_key,
    _signed_credential,
    _signed_policy,
)

ROOT = Path(__file__).resolve().parents[2]


class CandidateEnrollmentEvidencePhase68Tests(QualificationEvidencePhase34Tests):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.d009 = load_candidate_enrollment_decision_record(
            ROOT / "registry" / "candidate-enrollment-decision-d009.json"
        )

    def enrollment_artifacts(self, policy, verified_policy, *, document=None):
        assurance = _signed_credential(
            policy,
            _review_credential_document(
                role=QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                reviewer_id="reviewer-assurance-001",
                credential_id="QRC-44444444444444444444444444444444",
                public_seed=ASSURANCE_SEED,
            ),
        )
        control = _signed_credential(
            policy,
            _review_credential_document(
                role=QualificationReviewerRole.INDEPENDENT_CONTROL,
                reviewer_id="reviewer-control-001",
                credential_id="QRC-55555555555555555555555555555555",
                public_seed=CONTROL_SEED,
            ),
        )
        verified_assurance = verify_qualification_reviewer_credential(
            assurance,
            verified_policy,
            expected_reviewer_id=assurance.reviewer_id,
            expected_role=assurance.reviewer_role,
            expected_profile_id=self.suite.profile_id,
            clock=lambda: NOW,
        )
        verified_control = verify_qualification_reviewer_credential(
            control,
            verified_policy,
            expected_reviewer_id=control.reviewer_id,
            expected_role=control.reviewer_role,
            expected_profile_id=self.suite.profile_id,
            clock=lambda: NOW,
        )
        authorization = _signed_authorization()
        verified_authorization = verify_candidate_enrollment_signer_authorization(
            authorization,
            {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
            d008_decision=self.decision,
            d009_decision=self.d009,
            verified_qualification_policy=verified_policy,
            expected_issuer=authorization.issuer,
            expected_audience=authorization.audience,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_authorization_version=1,
            clock=lambda: NOW,
        )
        raw = copy.deepcopy(document or enrollment_catalog_document())
        raw["enrollments"][0].update(
            {
                "profile_id": self.suite.profile_id,
                "candidate": self.suite.candidate.to_dict(),
                "owner": {
                    "owner_id": OWNER_ID,
                    "key_id": "candidate-owner-evidence-v1",
                    "public_key": _encoded_public_key(OWNER_SEED),
                    "public_key_sha256": _public_key_sha256(OWNER_SEED),
                },
                "repository": {
                    "repository_id": REPOSITORY_ID,
                    "content_address_scheme": "sha256",
                },
            }
        )
        catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=raw,
        )
        verified_catalog = verify_candidate_enrollment_catalog(
            catalog,
            verified_authorization,
            verified_policy,
            (verified_assurance, verified_control),
            d009_decision=self.d009,
            expected_catalog_id=catalog.catalog_id,
            expected_issuer=catalog.issuer,
            expected_audience=catalog.audience,
            minimum_catalog_version=1,
            last_seen_checkpoint=None,
            clock=lambda: NOW,
        )
        return verified_catalog

    def verify_enrolled(self, manifest, policy, catalog, observations, report):
        return verify_enrolled_qualification_evidence_manifest(
            manifest,
            policy,
            catalog,
            registry=self.registry,
            capability_catalog=self.catalog,
            qualification_standard=self.standard,
            qualification_plans=self.plans,
            evaluation_suite=self.suite,
            observations=observations,
            evaluation_report=report,
            clock=lambda: NOW,
        )

    def test_verified_catalog_replaces_manual_owner_and_repository_inputs(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        verified_catalog = self.enrollment_artifacts(policy, verified_policy)
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified = self.verify_enrolled(
            manifest,
            verified_policy,
            verified_catalog,
            observations,
            report,
        )
        self.assertEqual(verified.manifest, manifest)
        self.assertEqual(
            verified.enrollment_sha256,
            verified_catalog.catalog.enrollments[0].content_sha256,
        )
        self.assertEqual(verified.catalog_sha256, verified_catalog.catalog_sha256)

    def test_manifest_self_declarations_cannot_select_owner_or_repository(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        verified_catalog = self.enrollment_artifacts(policy, verified_policy)
        raw, observations, report = self._evidence_documents()
        for field, value in (
            ("candidate_owner_id", "attacker-owner"),
            ("repository_id", "attacker-repository"),
        ):
            changed = copy.deepcopy(raw)
            changed[field] = value
            manifest, _, _ = self._signed_manifest(
                policy=policy,
                document=changed,
                observations=observations,
                report=report,
            )
            with self.subTest(field=field), self.assertRaisesRegex(
                QualificationError,
                "No active non-revoked",
            ):
                self.verify_enrolled(
                    manifest,
                    verified_policy,
                    verified_catalog,
                    observations,
                    report,
                )

    def test_manifest_creation_must_fall_inside_enrollment_window(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        document = enrollment_catalog_document()
        document["enrollments"][0]["not_before"] = "2026-02-01T18:00:00Z"
        verified_catalog = self.enrollment_artifacts(
            policy,
            verified_policy,
            document=document,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        with self.assertRaisesRegex(QualificationError, "predates"):
            self.verify_enrolled(
                manifest,
                verified_policy,
                verified_catalog,
                observations,
                report,
            )

    def test_effective_catalog_revocation_blocks_manifest_acceptance(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        document = enrollment_catalog_document()
        document["revocations"] = [
            {
                "revocation_id": "CRV-11111111111111111111111111111111",
                "revocation_kind": "owner_key",
                "subject_id": "candidate-owner-evidence-v1",
                "effective_at": "2026-02-02T00:00:00Z",
                "recorded_at": "2026-02-01T00:00:00Z",
                "reason_sha256": "sha256:" + "6" * 64,
            }
        ]
        verified_catalog = self.enrollment_artifacts(
            policy,
            verified_policy,
            document=document,
        )
        manifest, observations, report = self._signed_manifest(policy=policy)
        with self.assertRaisesRegex(QualificationError, "No active non-revoked"):
            self.verify_enrolled(
                manifest,
                verified_policy,
                verified_catalog,
                observations,
                report,
            )

    def test_combined_verified_wrapper_cannot_be_forged(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verified_policy(policy)
        verified_catalog = self.enrollment_artifacts(policy, verified_policy)
        manifest, observations, report = self._signed_manifest(policy=policy)
        verified = self.verify_enrolled(
            manifest,
            verified_policy,
            verified_catalog,
            observations,
            report,
        )
        with self.assertRaisesRegex(TypeError, "only by"):
            VerifiedEnrolledQualificationEvidenceManifest(
                verified_manifest=verified.verified_manifest,
                verified_enrollment=verified.verified_enrollment,
                verified_at=verified.verified_at,
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment_evidence.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
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


if __name__ == "__main__":
    unittest.main()
