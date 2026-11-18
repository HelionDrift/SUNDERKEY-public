"""Phase 35 signed initial qualification decision coverage."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import QualificationError
from sunderkey.qualification_decisions import (
    QUALIFICATION_DECISION_SIGNING_DOMAIN,
    QualificationDecision,
    QualificationDecisionKind,
    VerifiedQualificationDecision,
    verify_qualification_decision,
)
from sunderkey.qualification_evidence import (
    QualificationReviewerAttestation,
    VerifiedQualificationReviewerAttestation,
    verify_qualification_reviewer_attestation,
)
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    verify_qualification_reviewer_credential,
)
from tests.agents import test_qualification_evidence_phase34 as evidence_phase34
from tests.agents.test_qualification_trust_phase32 import (
    qualification_reviewer_credential_document,
    qualification_trust_policy_document,
)
from tests.agents.test_qualification_trust_verification_phase33 import (
    _signed_credential,
    _signed_policy,
)

ROOT = Path(__file__).resolve().parents[2]
DECISION_NOW = datetime(2026, 2, 4, tzinfo=UTC)
ISSUED_AT = "2026-02-03T00:00:00Z"
VALID_UNTIL = "2026-08-02T00:00:00Z"


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _dummy_signature() -> str:
    return _encoded(bytes(range(64)))


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


class QualificationDecisionsPhase35Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        evidence_phase34.QualificationEvidencePhase34Tests.setUpClass()
        cls.evidence = evidence_phase34.QualificationEvidencePhase34Tests()
        cls.registry = cls.evidence.registry
        cls.catalog = cls.evidence.catalog
        cls.standard = cls.evidence.standard

    def _reviewer_credential(
        self,
        policy: Any,
        *,
        ordinal: int,
        reviewer_id: str,
        role: QualificationReviewerRole,
        reviewer_seed: int,
    ) -> Any:
        document = qualification_reviewer_credential_document()
        document["credential_id"] = f"QRC-{ordinal:032X}"
        document["reviewer_id"] = reviewer_id
        document["reviewer_role"] = role.value
        raw_public_key = _private_key(reviewer_seed).public_key().public_bytes_raw()
        document["public_key"] = _encoded(raw_public_key)
        return _signed_credential(policy, document)

    def _verified_attestations(
        self,
        policy: Any,
        verified_policy: Any,
        manifest: Any,
        verified_manifest: Any,
        *,
        specifications: tuple[
            tuple[str, QualificationReviewerRole, int, str], ...
        ] | None = None,
        reviewed_at: str = "2026-02-02T00:00:00Z",
    ) -> tuple[VerifiedQualificationReviewerAttestation, ...]:
        specs = specifications or (
            (
                "reviewer-technical-001",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "supports_qualification",
            ),
            (
                "reviewer-technical-002",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                6,
                "supports_qualification",
            ),
            (
                "reviewer-control-001",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                7,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-001",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                8,
                "supports_qualification",
            ),
        )
        review_clock = datetime.strptime(
            reviewed_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        results: list[VerifiedQualificationReviewerAttestation] = []
        for ordinal, (reviewer_id, role, reviewer_seed, conclusion) in enumerate(
            specs,
            start=1,
        ):
            credential = self._reviewer_credential(
                policy,
                ordinal=ordinal,
                reviewer_id=reviewer_id,
                role=role,
                reviewer_seed=reviewer_seed,
            )
            verified_credential = verify_qualification_reviewer_credential(
                credential,
                verified_policy,
                expected_reviewer_id=reviewer_id,
                expected_role=role,
                expected_profile_id=evidence_phase34.PROFILE_ID,
                clock=lambda: review_clock,
            )
            raw = {
                "schema_version": 1,
                "attestation_id": f"QRA-{ordinal:032X}",
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
                "reviewer_role": role.value,
                "profile_id": manifest.profile_id,
                "candidate": manifest.candidate.to_dict(),
                "conclusion": conclusion,
                "reason_sha256": _digest(f"review-reason:{ordinal}"),
                "reviewed_at": reviewed_at,
                "algorithm": "Ed25519",
                "signature": _dummy_signature(),
            }
            unsigned = QualificationReviewerAttestation.from_dict(raw)
            raw["signature"] = _encoded(
                _private_key(reviewer_seed).sign(unsigned.signing_bytes())
            )
            attestation = QualificationReviewerAttestation.from_dict(raw)
            results.append(
                verify_qualification_reviewer_attestation(
                    attestation,
                    verified_policy,
                    verified_credential,
                    verified_manifest,
                    expected_conclusion=conclusion,
                    clock=lambda: review_clock,
                )
            )
        return tuple(results)

    def _bundle(
        self,
        *,
        policy: Any | None = None,
        specifications: tuple[
            tuple[str, QualificationReviewerRole, int, str], ...
        ] | None = None,
        reviewed_at: str = "2026-02-02T00:00:00Z",
    ) -> tuple[Any, Any, Any, Any, tuple[Any, ...]]:
        value = policy or _signed_policy()
        verified_policy = self.evidence._verified_policy(value)
        manifest, observations, report = self.evidence._signed_manifest(
            policy=value
        )
        verified_manifest = self.evidence._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
        )
        attestations = self._verified_attestations(
            value,
            verified_policy,
            manifest,
            verified_manifest,
            specifications=specifications,
            reviewed_at=reviewed_at,
        )
        return (
            value,
            verified_policy,
            manifest,
            verified_manifest,
            attestations,
        )

    def _signed_decision(
        self,
        policy: Any,
        manifest: Any,
        attestations: tuple[VerifiedQualificationReviewerAttestation, ...],
        *,
        document: dict[str, Any] | None = None,
        signer_seed: int = 1,
        signer_key_id: str = "qualification-decision-v1",
    ) -> QualificationDecision:
        bindings = [
            {
                "attestation_id": item.attestation.attestation_id,
                "reviewer_id": item.reviewer_id,
                "reviewer_role": item.reviewer_role.value,
                "attestation_sha256": item.attestation_sha256,
                "credential_sha256": item.credential_sha256,
                "reviewer_key_sha256": item.reviewer_key_sha256,
            }
            for item in attestations
        ]
        bindings.sort(
            key=lambda item: (
                str(item["reviewer_role"]),
                str(item["reviewer_id"]),
                str(item["attestation_id"]),
            )
        )
        raw = copy.deepcopy(
            document
            or {
                "schema_version": 1,
                "decision_id": "QKD-55555555555555555555555555555555",
                "decision_version": 1,
                "decision_kind": "initial_approval",
                "policy": {
                    "policy_id": policy.policy_id,
                    "policy_version": policy.policy_version,
                    "sha256": policy.content_sha256,
                },
                "evidence_manifest": {
                    "id": manifest.manifest_id,
                    "sha256": manifest.content_sha256,
                },
                "profile_id": manifest.profile_id,
                "candidate": manifest.candidate.to_dict(),
                "attestations": bindings,
                "decision_status": "approved",
                "registry_effect": "none",
                "issued_at": ISSUED_AT,
                "valid_from": ISSUED_AT,
                "valid_until": VALID_UNTIL,
                "issuer": policy.issuer,
                "signer_key_id": signer_key_id,
                "algorithm": "Ed25519",
                "signature": _dummy_signature(),
            }
        )
        unsigned = QualificationDecision.from_dict(raw)
        raw["signature"] = _encoded(
            _private_key(signer_seed).sign(unsigned.signing_bytes())
        )
        return QualificationDecision.from_dict(raw)

    def _verify(
        self,
        decision: QualificationDecision,
        verified_policy: Any,
        verified_manifest: Any,
        attestations: tuple[VerifiedQualificationReviewerAttestation, ...],
        *,
        clock: datetime = DECISION_NOW,
    ) -> VerifiedQualificationDecision:
        return verify_qualification_decision(
            decision,
            verified_policy,
            verified_manifest,
            attestations,
            registry=self.registry,
            capability_catalog=self.catalog,
            qualification_standard=self.standard,
            clock=lambda: clock,
        )

    def test_complete_initial_approval_verifies_without_registry_effect(self) -> None:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle()
        )
        decision = self._signed_decision(policy, manifest, attestations)
        verified = self._verify(
            decision,
            verified_policy,
            verified_manifest,
            attestations,
        )

        self.assertTrue(
            decision.signing_bytes().startswith(
                QUALIFICATION_DECISION_SIGNING_DOMAIN
            )
        )
        self.assertEqual(decision.decision_kind, QualificationDecisionKind.INITIAL_APPROVAL)
        self.assertEqual(decision.registry_effect, "none")
        self.assertEqual(verified.decision_sha256, decision.content_sha256)
        self.assertEqual(len(verified.reviewer_ids), 4)
        self.assertEqual(len(set(verified.reviewer_key_sha256s)), 4)

    def test_decision_rejects_too_few_evaluators_and_missing_control(self) -> None:
        too_few = (
            (
                "reviewer-technical-001",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "supports_qualification",
            ),
            (
                "reviewer-control-001",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                7,
                "supports_qualification",
            ),
            (
                "reviewer-control-002",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                9,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-001",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                8,
                "supports_qualification",
            ),
        )
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle(specifications=too_few)
        )
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "too few"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

        no_control = (
            (
                "reviewer-technical-001",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "supports_qualification",
            ),
            (
                "reviewer-technical-002",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                6,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-001",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                8,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-002",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                10,
                "supports_qualification",
            ),
        )
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle(specifications=no_control)
        )
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "Control"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

    def test_decision_rejects_negative_attestation_and_duplicate_key(self) -> None:
        negative = (
            (
                "reviewer-technical-001",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "does_not_support_qualification",
            ),
            (
                "reviewer-technical-002",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                6,
                "supports_qualification",
            ),
            (
                "reviewer-control-001",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                7,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-001",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                8,
                "supports_qualification",
            ),
        )
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle(specifications=negative)
        )
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "supporting"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

        duplicate_key = (
            (
                "reviewer-technical-001",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "supports_qualification",
            ),
            (
                "reviewer-technical-002",
                QualificationReviewerRole.TECHNICAL_EVALUATOR,
                4,
                "supports_qualification",
            ),
            (
                "reviewer-control-001",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                7,
                "supports_qualification",
            ),
            (
                "reviewer-assurance-001",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                8,
                "supports_qualification",
            ),
        )
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle(specifications=duplicate_key)
        )
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "must be distinct"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

    def test_decision_rejects_stale_binding_and_bad_signature(self) -> None:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle()
        )
        decision = self._signed_decision(
            policy,
            manifest,
            attestations,
            signer_seed=2,
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

        document = self._signed_decision(
            policy,
            manifest,
            attestations,
        ).to_dict()
        document["evidence_manifest"]["sha256"] = "sha256:" + "0" * 64
        decision = self._signed_decision(
            policy,
            manifest,
            attestations,
            document=document,
        )
        with self.assertRaisesRegex(QualificationError, "evidence binding"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

    def test_decision_rejects_wrong_key_use_and_revoked_signer(self) -> None:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle()
        )
        document = self._signed_decision(
            policy,
            manifest,
            attestations,
        ).to_dict()
        document["signer_key_id"] = "qualification-revocation-v1"
        decision = self._signed_decision(
            policy,
            manifest,
            attestations,
            document=document,
            signer_seed=2,
        )
        with self.assertRaisesRegex(QualificationError, "key use"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

        policy_document = qualification_trust_policy_document()
        policy_document["keys"][0]["state"] = "revoked"
        revoked_policy = _signed_policy(policy_document)
        (
            policy,
            verified_policy,
            manifest,
            verified_manifest,
            attestations,
        ) = self._bundle(policy=revoked_policy)
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "revoked"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

    def test_decision_rejects_excessive_inactive_and_expired_windows(self) -> None:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle()
        )
        document = self._signed_decision(
            policy,
            manifest,
            attestations,
        ).to_dict()
        document["valid_until"] = "2026-08-03T00:00:01Z"
        decision = self._signed_decision(
            policy,
            manifest,
            attestations,
            document=document,
        )
        with self.assertRaisesRegex(QualificationError, "validity window"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "not active yet"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
                clock=datetime(2026, 2, 2, tzinfo=UTC),
            )
        with self.assertRaisesRegex(QualificationError, "expired"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
                clock=datetime(2026, 8, 2, tzinfo=UTC),
            )

    def test_decision_rejects_attestation_after_issuance(self) -> None:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self._bundle(reviewed_at="2026-02-04T00:00:00Z")
        )
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(QualificationError, "predates"):
            self._verify(
                decision,
                verified_policy,
                verified_manifest,
                attestations,
            )

    def test_verified_decision_wrapper_rejects_direct_construction(self) -> None:
        policy, _, manifest, _, attestations = self._bundle()
        decision = self._signed_decision(policy, manifest, attestations)
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationDecision(
                decision=decision,
                decision_sha256=decision.content_sha256,
                policy_sha256=policy.content_sha256,
                manifest_sha256=manifest.content_sha256,
                signer_key_sha256="sha256:" + "0" * 64,
                reviewer_ids=("reviewer-technical-001",),
                reviewer_key_sha256s=("sha256:" + "1" * 64,),
                manifest_created_at="2026-02-01T12:00:00Z",
                reviewer_reviewed_ats=("2026-02-02T00:00:00Z",),
                verified_at="2026-02-04T00:00:00Z",
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "qualification_decisions.py"
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


def qualification_decision_document() -> dict[str, Any]:
    QualificationDecisionsPhase35Tests.setUpClass()
    case = QualificationDecisionsPhase35Tests()
    policy, _, manifest, _, attestations = case._bundle()
    return case._signed_decision(policy, manifest, attestations).to_dict()


if __name__ == "__main__":
    unittest.main()
