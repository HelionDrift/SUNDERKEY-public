"""Phase 69 adversarial enrollment rotation, revocation, and migration tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.candidate_enrollment import CandidateEnrollmentEntry
from sunderkey.candidate_enrollment_verification import (
    resolve_candidate_enrollment,
    verify_candidate_enrollment_signer_authorization,
)
from sunderkey.errors import QualificationError
from tests.agents.test_candidate_enrollment_phase66 import (
    _encoded_public_key,
    enrollment_document,
    signer_authorization_document,
)
from tests.agents.test_candidate_enrollment_verification_phase67 import (
    NOW,
    ROOT_KEY_ID,
    ROOT_SEED,
    CandidateEnrollmentVerificationPhase67Tests,
    _signed_authorization,
    _signed_catalog,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    _raw_public_key,
)


class CandidateEnrollmentAdversarialPhase69Tests(
    CandidateEnrollmentVerificationPhase67Tests
):
    def test_enrollment_signer_cannot_reuse_offline_root_material(self) -> None:
        artifacts = self.artifacts()
        document = signer_authorization_document()
        document["keys"][0]["public_key"] = _encoded_public_key(ROOT_SEED)
        authorization = _signed_authorization(document)
        with self.assertRaisesRegex(QualificationError, "reuses qualification"):
            verify_candidate_enrollment_signer_authorization(
                authorization,
                {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
                d008_decision=self.d008,
                d009_decision=self.d009,
                verified_qualification_policy=artifacts[1],
                expected_issuer=authorization.issuer,
                expected_audience=authorization.audience,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_authorization_version=1,
                clock=lambda: NOW,
            )

    def test_owner_rotation_then_revocation_migrates_without_scope_escape(self) -> None:
        artifacts = self.artifacts()
        policy, _, assurance, control, _, _, authorization, _, first_catalog = artifacts
        first_verified = self.verify_catalog(artifacts)
        predecessor = first_catalog.enrollments[0]
        successor_document = enrollment_document(
            enrollment_id="CEE-22222222222222222222222222222222",
            owner_seed=14,
            owner_key_id="candidate-owner-v2",
            predecessor={
                "enrollment_id": predecessor.enrollment_id,
                "sha256": predecessor.content_sha256,
            },
            not_before="2026-02-01T00:00:00Z",
            expires_at="2026-10-01T00:00:00Z",
        )
        successor = CandidateEnrollmentEntry.from_dict(
            successor_document,
            label="successor",
        )
        second_document = first_catalog.to_dict()
        second_document["catalog_version"] = 2
        second_document["previous_catalog_sha256"] = first_catalog.content_sha256
        second_document["enrollments"].append(successor_document)
        second_document["rotations"] = [
            {
                "rotation_id": "CRO-11111111111111111111111111111111",
                "rotation_kind": "owner_key",
                "predecessor": {
                    "enrollment_id": predecessor.enrollment_id,
                    "sha256": predecessor.content_sha256,
                },
                "successor": {
                    "enrollment_id": successor.enrollment_id,
                    "sha256": successor.content_sha256,
                },
                "overlap_not_before": "2026-02-01T00:00:00Z",
                "overlap_expires_at": "2026-06-01T00:00:00Z",
            }
        ]
        second_catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=second_document,
        )
        second_verified = self.verify_catalog(
            artifacts,
            second_catalog,
            last_seen_checkpoint=first_verified.checkpoint,
        )
        resolved_successor = resolve_candidate_enrollment(
            second_verified,
            expected_profile_id=successor.profile_id,
            expected_candidate_id=successor.candidate["candidate_id"],
            expected_candidate_version=successor.candidate["candidate_version"],
            expected_candidate_artifact_sha256=successor.candidate[
                "candidate_artifact_sha256"
            ],
            expected_owner_id=successor.owner["owner_id"],
            expected_owner_public_key=successor.owner["public_key"],
            expected_repository_id=successor.repository["repository_id"],
            clock=lambda: NOW,
        )
        self.assertEqual(resolved_successor.entry.enrollment_id, successor.enrollment_id)

        third_document = copy.deepcopy(second_catalog.to_dict())
        third_document["catalog_version"] = 3
        third_document["previous_catalog_sha256"] = second_catalog.content_sha256
        third_document["revocations"] = [
            {
                "revocation_id": "CRV-11111111111111111111111111111111",
                "revocation_kind": "owner_key",
                "subject_id": predecessor.owner["key_id"],
                "effective_at": "2026-02-02T00:00:00Z",
                "recorded_at": "2026-02-01T00:00:00Z",
                "reason_sha256": "sha256:" + "7" * 64,
            }
        ]
        third_catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=third_document,
        )
        third_verified = self.verify_catalog(
            artifacts,
            third_catalog,
            last_seen_checkpoint=second_verified.checkpoint,
        )
        with self.assertRaisesRegex(QualificationError, "No active non-revoked"):
            resolve_candidate_enrollment(
                third_verified,
                expected_profile_id=predecessor.profile_id,
                expected_candidate_id=predecessor.candidate["candidate_id"],
                expected_candidate_version=predecessor.candidate["candidate_version"],
                expected_candidate_artifact_sha256=predecessor.candidate[
                    "candidate_artifact_sha256"
                ],
                expected_owner_id=predecessor.owner["owner_id"],
                expected_owner_public_key=predecessor.owner["public_key"],
                expected_repository_id=predecessor.repository["repository_id"],
                clock=lambda: NOW,
            )
        self.assertEqual(
            resolve_candidate_enrollment(
                third_verified,
                expected_profile_id=successor.profile_id,
                expected_candidate_id=successor.candidate["candidate_id"],
                expected_candidate_version=successor.candidate["candidate_version"],
                expected_candidate_artifact_sha256=successor.candidate[
                    "candidate_artifact_sha256"
                ],
                expected_owner_id=successor.owner["owner_id"],
                expected_owner_public_key=successor.owner["public_key"],
                expected_repository_id=successor.repository["repository_id"],
                clock=lambda: NOW,
            ).entry.enrollment_id,
            successor.enrollment_id,
        )

    def test_cross_candidate_successor_is_rejected_before_signature_verification(self) -> None:
        artifacts = self.artifacts()
        policy, _, assurance, control, _, _, authorization, _, catalog = artifacts
        predecessor = catalog.enrollments[0]
        successor = enrollment_document(
            enrollment_id="CEE-22222222222222222222222222222222",
            owner_seed=14,
            owner_key_id="candidate-owner-v2",
            predecessor={
                "enrollment_id": predecessor.enrollment_id,
                "sha256": predecessor.content_sha256,
            },
        )
        successor["candidate"]["candidate_version"] = "2.0.0"
        document = catalog.to_dict()
        document["catalog_version"] = 2
        document["previous_catalog_sha256"] = catalog.content_sha256
        document["enrollments"].append(successor)
        with self.assertRaisesRegex(QualificationError, "exact candidate scope"):
            _signed_catalog(
                authorization,
                policy,
                assurance,
                control,
                document=document,
            )


if __name__ == "__main__":
    unittest.main()
