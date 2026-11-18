"""Phase 67 candidate enrollment cryptographic verification coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sunderkey.candidate_enrollment import (
    CandidateEnrollmentCatalog,
    CandidateEnrollmentReleaseReview,
    CandidateEnrollmentSignerAuthorization,
)
from sunderkey.candidate_enrollment_decision import (
    load_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
    VerifiedCandidateEnrollmentCatalog,
    VerifiedCandidateEnrollmentEntry,
    VerifiedCandidateEnrollmentSignerAuthorization,
    resolve_candidate_enrollment,
    verify_candidate_enrollment_catalog,
    verify_candidate_enrollment_signer_authorization,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_decision import (
    load_qualification_authority_decision_record,
)
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    verify_qualification_reviewer_credential,
    verify_qualification_trust_policy,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from tests.agents.test_candidate_enrollment_phase66 import (
    PROFILE_ID,
    _bind_release,
    _encoded_public_key,
    _private_key,
    enrollment_catalog_document,
    signer_authorization_document,
)
from tests.agents.test_qualification_trust_phase32 import (
    qualification_reviewer_credential_document,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    ROOT_KEY_ID,
    ROOT_SEED,
    _encoded,
    _raw_public_key,
    _signed_credential,
    _signed_policy,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 2, 2, tzinfo=UTC)
SIGNER_SEED = 10
ASSURANCE_SEED = 12
CONTROL_SEED = 13


def _signed_authorization(
    document: dict[str, Any] | None = None,
    *,
    signing_seed: int = ROOT_SEED,
) -> CandidateEnrollmentSignerAuthorization:
    raw = copy.deepcopy(document or signer_authorization_document())
    unsigned = CandidateEnrollmentSignerAuthorization.from_dict(raw)
    raw["signature"] = _encoded(
        _private_key(signing_seed).sign(unsigned.signing_bytes())
    )
    return CandidateEnrollmentSignerAuthorization.from_dict(raw)


def _review_credential_document(
    *,
    role: QualificationReviewerRole,
    reviewer_id: str,
    credential_id: str,
    public_seed: int,
) -> dict[str, Any]:
    document = qualification_reviewer_credential_document()
    document.update(
        {
            "credential_id": credential_id,
            "reviewer_id": reviewer_id,
            "reviewer_role": role.value,
            "issued_at": "2026-01-29T00:00:00Z",
            "not_before": "2026-01-29T00:00:00Z",
            "expires_at": "2026-02-05T00:00:00Z",
            "public_key": _encoded_public_key(public_seed),
        }
    )
    return document


def _signed_catalog(
    authorization: CandidateEnrollmentSignerAuthorization,
    policy: Any,
    assurance_credential: Any,
    control_credential: Any,
    *,
    document: dict[str, Any] | None = None,
    signer_seed: int = SIGNER_SEED,
    assurance_seed: int = ASSURANCE_SEED,
    control_seed: int = CONTROL_SEED,
) -> CandidateEnrollmentCatalog:
    raw = copy.deepcopy(document or enrollment_catalog_document())
    raw["authorization"] = {
        "authorization_id": authorization.authorization_id,
        "authorization_version": authorization.authorization_version,
        "sha256": authorization.content_sha256,
    }
    raw["qualification_policy"] = {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": policy.content_sha256,
    }
    credentials = (assurance_credential, control_credential)
    for review, credential in zip(raw["reviews"], credentials, strict=True):
        review["reviewer_id"] = credential.reviewer_id
        review["reviewer_role"] = credential.reviewer_role.value
        review["credential"] = {
            "credential_id": credential.credential_id,
            "sha256": credential.content_sha256,
        }
    _bind_release(raw)
    for review, seed in zip(
        raw["reviews"],
        (assurance_seed, control_seed),
        strict=True,
    ):
        unsigned_review = CandidateEnrollmentReleaseReview.from_dict(
            review,
            label="review",
        )
        review["signature"] = _encoded(
            _private_key(seed).sign(unsigned_review.signing_bytes())
        )
    unsigned_catalog = CandidateEnrollmentCatalog.from_dict(raw)
    raw["signature"] = _encoded(
        _private_key(signer_seed).sign(unsigned_catalog.signing_bytes())
    )
    return CandidateEnrollmentCatalog.from_dict(raw)


class CandidateEnrollmentVerificationPhase67Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        registry = load_registry(ROOT / "registry" / "army-v1.json")
        capabilities = load_capability_catalog(
            ROOT / "registry" / "capabilities-army-v1.json",
            registry,
        )
        cls.standard = load_qualification_standard(
            ROOT / "registry" / "qualification-standard-v1.json",
            registry,
            capabilities,
        )
        cls.d008 = load_qualification_authority_decision_record(
            ROOT / "registry" / "qualification-authority-decision-d008.json"
        )
        cls.d009 = load_candidate_enrollment_decision_record(
            ROOT / "registry" / "candidate-enrollment-decision-d009.json"
        )

    def artifacts(self):
        policy = _signed_policy()
        verified_policy = verify_qualification_trust_policy(
            policy,
            {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
            decision_record=self.d008,
            qualification_standard=self.standard,
            expected_issuer=policy.issuer,
            expected_audience=policy.audience,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=1,
            clock=lambda: NOW,
        )
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
            expected_profile_id=PROFILE_ID,
            clock=lambda: NOW,
        )
        verified_control = verify_qualification_reviewer_credential(
            control,
            verified_policy,
            expected_reviewer_id=control.reviewer_id,
            expected_role=control.reviewer_role,
            expected_profile_id=PROFILE_ID,
            clock=lambda: NOW,
        )
        authorization = _signed_authorization()
        verified_authorization = verify_candidate_enrollment_signer_authorization(
            authorization,
            {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
            d008_decision=self.d008,
            d009_decision=self.d009,
            verified_qualification_policy=verified_policy,
            expected_issuer="sunderkey-qualification-authority",
            expected_audience="sunderkey-candidate-enrollment",
            expected_root_key_id=ROOT_KEY_ID,
            minimum_authorization_version=1,
            clock=lambda: NOW,
        )
        catalog = _signed_catalog(authorization, policy, assurance, control)
        return (
            policy,
            verified_policy,
            assurance,
            control,
            verified_assurance,
            verified_control,
            authorization,
            verified_authorization,
            catalog,
        )

    def verify_catalog(self, artifacts, catalog=None, **overrides):
        (
            _,
            verified_policy,
            _,
            _,
            verified_assurance,
            verified_control,
            _,
            verified_authorization,
            default_catalog,
        ) = artifacts
        arguments = {
            "d009_decision": self.d009,
            "expected_catalog_id": default_catalog.catalog_id,
            "expected_issuer": "sunderkey-qualification-authority",
            "expected_audience": "sunderkey-qualification",
            "minimum_catalog_version": 1,
            "last_seen_checkpoint": None,
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return verify_candidate_enrollment_catalog(
            catalog or default_catalog,
            verified_authorization,
            verified_policy,
            (verified_assurance, verified_control),
            **arguments,
        )

    def test_complete_chain_verifies_and_resolves_exact_enrollment(self) -> None:
        artifacts = self.artifacts()
        verified = self.verify_catalog(artifacts)
        entry = artifacts[-1].enrollments[0]
        resolved = resolve_candidate_enrollment(
            verified,
            expected_profile_id=entry.profile_id,
            expected_candidate_id=entry.candidate["candidate_id"],
            expected_candidate_version=entry.candidate["candidate_version"],
            expected_candidate_artifact_sha256=entry.candidate[
                "candidate_artifact_sha256"
            ],
            expected_owner_id=entry.owner["owner_id"],
            expected_owner_public_key=entry.owner["public_key"],
            expected_repository_id=entry.repository["repository_id"],
            clock=lambda: NOW,
        )
        self.assertEqual(resolved.entry, entry)
        self.assertEqual(verified.checkpoint.catalog_version, 1)

    def test_authorization_rejects_wrong_root_and_signature(self) -> None:
        artifacts = self.artifacts()
        verified_policy = artifacts[1]
        authorization = _signed_authorization(signing_seed=8)
        with self.assertRaisesRegex(QualificationError, "signature"):
            verify_candidate_enrollment_signer_authorization(
                authorization,
                {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
                d008_decision=self.d008,
                d009_decision=self.d009,
                verified_qualification_policy=verified_policy,
                expected_issuer="sunderkey-qualification-authority",
                expected_audience="sunderkey-candidate-enrollment",
                expected_root_key_id=ROOT_KEY_ID,
                minimum_authorization_version=1,
                clock=lambda: NOW,
            )

    def test_catalog_and_review_signatures_fail_closed(self) -> None:
        artifacts = self.artifacts()
        policy, _, assurance, control, _, _, authorization, _, _ = artifacts
        bad_catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            signer_seed=9,
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            self.verify_catalog(artifacts, bad_catalog)

        bad_review = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            assurance_seed=9,
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            self.verify_catalog(artifacts, bad_review)

    def test_owner_cannot_reuse_signer_or_reviewer_key(self) -> None:
        artifacts = self.artifacts()
        policy, _, assurance, control, _, _, authorization, _, _ = artifacts
        document = enrollment_catalog_document()
        document["enrollments"][0]["owner"].update(
            {
                "public_key": authorization.keys[0].public_key,
                "public_key_sha256": (
                    "sha256:"
                    + hashlib.sha256(_raw_public_key(SIGNER_SEED)).hexdigest()
                ),
            }
        )
        catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=document,
        )
        with self.assertRaisesRegex(QualificationError, "reuses authority"):
            self.verify_catalog(artifacts, catalog)

    def test_monotonic_checkpoint_accepts_next_and_rejects_rollback(self) -> None:
        artifacts = self.artifacts()
        first = self.verify_catalog(artifacts)
        policy, _, assurance, control, _, _, authorization, _, catalog = artifacts
        document = catalog.to_dict()
        document["catalog_version"] = 2
        document["previous_catalog_sha256"] = catalog.content_sha256
        next_catalog = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=document,
        )
        second = self.verify_catalog(
            artifacts,
            next_catalog,
            last_seen_checkpoint=first.checkpoint,
        )
        self.assertEqual(second.checkpoint.catalog_version, 2)
        with self.assertRaisesRegex(QualificationError, "not monotonic"):
            self.verify_catalog(
                artifacts,
                catalog,
                last_seen_checkpoint=second.checkpoint,
            )

    def test_replaced_same_version_is_rejected(self) -> None:
        artifacts = self.artifacts()
        first = self.verify_catalog(artifacts)
        policy, _, assurance, control, _, _, authorization, _, catalog = artifacts
        document = catalog.to_dict()
        document["enrollments"][0]["expires_at"] = "2026-07-01T00:00:00Z"
        replacement = _signed_catalog(
            authorization,
            policy,
            assurance,
            control,
            document=document,
        )
        with self.assertRaisesRegex(QualificationError, "was replaced"):
            self.verify_catalog(
                artifacts,
                replacement,
                last_seen_checkpoint=first.checkpoint,
            )

    def test_resolver_rejects_self_declared_owner_or_repository(self) -> None:
        artifacts = self.artifacts()
        verified = self.verify_catalog(artifacts)
        entry = artifacts[-1].enrollments[0]
        base = {
            "expected_profile_id": entry.profile_id,
            "expected_candidate_id": entry.candidate["candidate_id"],
            "expected_candidate_version": entry.candidate["candidate_version"],
            "expected_candidate_artifact_sha256": entry.candidate[
                "candidate_artifact_sha256"
            ],
            "expected_owner_id": entry.owner["owner_id"],
            "expected_owner_public_key": entry.owner["public_key"],
            "expected_repository_id": entry.repository["repository_id"],
            "clock": lambda: NOW,
        }
        for field, value in (
            ("expected_owner_id", "attacker-owner"),
            ("expected_repository_id", "attacker-repository"),
        ):
            arguments = dict(base)
            arguments[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                QualificationError,
                "No active non-revoked",
            ):
                resolve_candidate_enrollment(verified, **arguments)

    def test_verified_wrappers_cannot_be_forged(self) -> None:
        artifacts = self.artifacts()
        authorization = artifacts[6]
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedCandidateEnrollmentSignerAuthorization(
                authorization=authorization,
                authorization_sha256=authorization.content_sha256,
                root_key_sha256="sha256:" + "0" * 64,
                policy_sha256="sha256:" + "1" * 64,
                verified_at="2026-02-02T00:00:00Z",
                _proof=b"invalid",
            )

        verified = self.verify_catalog(artifacts)
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedCandidateEnrollmentCatalog(
                catalog=verified.catalog,
                catalog_sha256=verified.catalog_sha256,
                authorization_sha256=verified.authorization_sha256,
                policy_sha256=verified.policy_sha256,
                reviewer_credential_sha256s=verified.reviewer_credential_sha256s,
                verified_at=verified.verified_at,
                checkpoint=CandidateEnrollmentCatalogCheckpoint(
                    verified.catalog.catalog_id,
                    1,
                    verified.catalog_sha256,
                ),
                _proof=b"invalid",
            )

        entry = verified.catalog.enrollments[0]
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedCandidateEnrollmentEntry(
                entry=entry,
                entry_sha256=entry.content_sha256,
                catalog_sha256=verified.catalog_sha256,
                verified_at=verified.verified_at,
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment_verification.py"
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
