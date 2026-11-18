"""Phase 36 signed qualification status lifecycle coverage."""

from __future__ import annotations

import ast
import copy
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sunderkey.errors import QualificationError
from sunderkey.qualification_decisions import VerifiedQualificationDecision
from sunderkey.qualification_lifecycle import (
    QUALIFICATION_STATUS_TRANSITION_SIGNING_DOMAIN,
    QualificationStatus,
    QualificationStatusTransition,
    QualificationStatusTransitionKind,
    VerifiedQualificationStatus,
    qualification_status_from_initial_decision,
    verify_qualification_status_transition,
)
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    verify_qualification_reviewer_credential,
)
from tests.agents import test_qualification_decisions_phase35 as phase35

ROOT = Path(__file__).resolve().parents[2]
INITIAL_CLOCK = datetime(2026, 2, 4, tzinfo=UTC)
SUSPEND_CLOCK = datetime(2026, 2, 5, tzinfo=UTC)
RESTORE_CLOCK = datetime(2026, 2, 9, tzinfo=UTC)


class QualificationLifecyclePhase36Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase35.QualificationDecisionsPhase35Tests.setUpClass()
        cls.decisions = phase35.QualificationDecisionsPhase35Tests()

    def _initial_chain(self) -> tuple[Any, ...]:
        policy, verified_policy, manifest, verified_manifest, attestations = (
            self.decisions._bundle()
        )
        decision = self.decisions._signed_decision(
            policy,
            manifest,
            attestations,
        )
        verified_decision = self.decisions._verify(
            decision,
            verified_policy,
            verified_manifest,
            attestations,
            clock=INITIAL_CLOCK,
        )
        status = qualification_status_from_initial_decision(
            verified_decision,
            clock=lambda: INITIAL_CLOCK,
        )
        control_credential = self._control_credential(
            policy,
            verified_policy,
        )
        return (
            policy,
            verified_policy,
            verified_decision,
            status,
            control_credential,
        )

    def _control_credential(
        self,
        policy: Any,
        verified_policy: Any,
        *,
        reviewer_id: str = "reviewer-control-emergency",
        reviewer_seed: int = 11,
        role: QualificationReviewerRole = QualificationReviewerRole.INDEPENDENT_CONTROL,
    ) -> Any:
        credential = self.decisions._reviewer_credential(
            policy,
            ordinal=32,
            reviewer_id=reviewer_id,
            role=role,
            reviewer_seed=reviewer_seed,
        )
        return verify_qualification_reviewer_credential(
            credential,
            verified_policy,
            expected_reviewer_id=reviewer_id,
            expected_role=role,
            expected_profile_id=self.decisions.evidence.suite.profile_id,
            clock=lambda: SUSPEND_CLOCK,
        )

    def _signed_transition(
        self,
        policy: Any,
        previous_status: VerifiedQualificationStatus,
        *,
        kind: QualificationStatusTransitionKind,
        issued_at: str,
        reason_code: str,
        supporting_decision: VerifiedQualificationDecision | None = None,
        control_credential: Any | None = None,
        document: dict[str, Any] | None = None,
        signer_seed: int | None = None,
        authority_key_id: str | None = None,
        ordinal: int = 1,
    ) -> QualificationStatusTransition:
        resulting_status = {
            QualificationStatusTransitionKind.SUSPEND: "suspended",
            QualificationStatusTransitionKind.REVOKE: "revoked",
            QualificationStatusTransitionKind.RENEW: "active",
            QualificationStatusTransitionKind.REINSTATE: "active",
        }[kind]
        authority_key_id = authority_key_id or (
            "qualification-revocation-v1"
            if kind is QualificationStatusTransitionKind.REVOKE
            else "qualification-decision-v1"
        )
        signer_seed = signer_seed or (
            11
            if kind is QualificationStatusTransitionKind.SUSPEND
            else 2
            if kind is QualificationStatusTransitionKind.REVOKE
            else 1
        )
        raw = copy.deepcopy(
            document
            or {
                "schema_version": 1,
                "transition_id": f"QST-{ordinal:032X}",
                "transition_version": 1,
                "transition_kind": kind.value,
                "policy": {
                    "policy_id": policy.policy_id,
                    "policy_version": policy.policy_version,
                    "sha256": policy.content_sha256,
                },
                "prior_status": previous_status.binding.to_dict(),
                "resulting_status": resulting_status,
                "reason_code": reason_code,
                "reason_evidence_sha256": phase35._digest(
                    f"lifecycle-reason:{ordinal}"
                ),
                "issued_at": issued_at,
                "effective_at": issued_at,
                "signer_id": (
                    control_credential.reviewer_id
                    if control_credential is not None
                    else policy.issuer
                ),
                "registry_effect": "none",
                "algorithm": "Ed25519",
                "signature": phase35._dummy_signature(),
            }
        )
        if document is None:
            if kind is QualificationStatusTransitionKind.SUSPEND:
                if control_credential is None:
                    raise AssertionError("suspension test requires Control credential")
                raw["reviewer_credential"] = {
                    "id": control_credential.credential.credential_id,
                    "sha256": control_credential.credential_sha256,
                }
            else:
                raw["authority_key_id"] = authority_key_id
        if supporting_decision is not None and document is None:
            raw["supporting_decision"] = {
                "id": supporting_decision.decision.decision_id,
                "sha256": supporting_decision.decision_sha256,
            }
        unsigned = QualificationStatusTransition.from_dict(raw)
        raw["signature"] = phase35._encoded(
            phase35._private_key(signer_seed).sign(unsigned.signing_bytes())
        )
        return QualificationStatusTransition.from_dict(raw)

    def _fresh_reviewed_decision(
        self,
        policy: Any,
        verified_policy: Any,
        *,
        manifest_created_at: str = "2026-02-06T00:00:00Z",
        reviewed_at: str = "2026-02-07T00:00:00Z",
        issued_at: str = "2026-02-08T00:00:00Z",
        valid_until: str = "2026-08-07T00:00:00Z",
    ) -> VerifiedQualificationDecision:
        raw, observations, report = self.decisions.evidence._evidence_documents()
        raw["manifest_id"] = "QEM-66666666666666666666666666666666"
        raw["manifest_version"] = 2
        raw["created_at"] = manifest_created_at
        manifest, observations, report = self.decisions.evidence._signed_manifest(
            policy=policy,
            document=raw,
            observations=observations,
            report=report,
        )
        manifest_clock = datetime.strptime(
            manifest_created_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        verified_manifest = self.decisions.evidence._verify_manifest(
            manifest,
            verified_policy,
            observations,
            report,
            clock=manifest_clock,
        )
        attestations = self.decisions._verified_attestations(
            policy,
            verified_policy,
            manifest,
            verified_manifest,
            reviewed_at=reviewed_at,
        )
        decision = self.decisions._signed_decision(
            policy,
            manifest,
            attestations,
        )
        decision_raw = decision.to_dict()
        decision_raw["decision_id"] = "QKD-77777777777777777777777777777777"
        decision_raw["decision_version"] = 2
        decision_raw["issued_at"] = issued_at
        decision_raw["valid_from"] = issued_at
        decision_raw["valid_until"] = valid_until
        decision = self.decisions._signed_decision(
            policy,
            manifest,
            attestations,
            document=decision_raw,
        )
        verify_clock = datetime.strptime(
            issued_at,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
        return self.decisions._verify(
            decision,
            verified_policy,
            verified_manifest,
            attestations,
            clock=verify_clock,
        )

    def test_initial_status_and_emergency_suspension_form_exact_chain(self) -> None:
        policy, verified_policy, verified_decision, status, control = (
            self._initial_chain()
        )
        transition = self._signed_transition(
            policy,
            status,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="evidence_integrity_concern",
            control_credential=control,
        )
        suspended = verify_qualification_status_transition(
            transition,
            status,
            verified_policy,
            clock=lambda: SUSPEND_CLOCK,
            control_credential=control,
        )

        self.assertTrue(
            transition.signing_bytes().startswith(
                QUALIFICATION_STATUS_TRANSITION_SIGNING_DOMAIN
            )
        )
        self.assertEqual(status.binding.sequence, 1)
        self.assertEqual(status.binding.status, QualificationStatus.ACTIVE)
        self.assertEqual(suspended.binding.sequence, 2)
        self.assertEqual(suspended.binding.status, QualificationStatus.SUSPENDED)
        self.assertEqual(
            suspended.binding.current_review_decision["sha256"],
            verified_decision.decision_sha256,
        )
        self.assertEqual(transition.registry_effect, "none")

    def test_transition_signing_authority_is_separated_by_kind(self) -> None:
        policy, verified_policy, _, active, control = self._initial_chain()
        suspension = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="operational_safety",
            control_credential=control,
        )
        with self.assertRaisesRegex(QualificationError, "Control credential"):
            verify_qualification_status_transition(
                suspension,
                active,
                verified_policy,
                clock=lambda: SUSPEND_CLOCK,
            )

        technical = self._control_credential(
            policy,
            verified_policy,
            reviewer_id="reviewer-technical-emergency",
            reviewer_seed=12,
            role=QualificationReviewerRole.TECHNICAL_EVALUATOR,
        )
        unauthorized_suspension = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="operational_safety",
            control_credential=technical,
            signer_seed=12,
        )
        with self.assertRaisesRegex(QualificationError, "not independent Control"):
            verify_qualification_status_transition(
                unauthorized_suspension,
                active,
                verified_policy,
                clock=lambda: SUSPEND_CLOCK,
                control_credential=technical,
            )

        wrong_revocation = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.REVOKE,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="confirmed_key_compromise",
            authority_key_id="qualification-decision-v1",
            signer_seed=1,
        )
        with self.assertRaisesRegex(QualificationError, "key use"):
            verify_qualification_status_transition(
                wrong_revocation,
                active,
                verified_policy,
                clock=lambda: SUSPEND_CLOCK,
            )

    def test_revocation_accepts_active_or_suspended_and_is_terminal(self) -> None:
        policy, verified_policy, _, active, _ = self._initial_chain()
        revoke_active = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.REVOKE,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="confirmed_key_compromise",
        )
        revoked = verify_qualification_status_transition(
            revoke_active,
            active,
            verified_policy,
            clock=lambda: SUSPEND_CLOCK,
        )
        self.assertEqual(revoked.binding.status, QualificationStatus.REVOKED)

        later = self._signed_transition(
            policy,
            revoked,
            kind=QualificationStatusTransitionKind.REVOKE,
            issued_at="2026-02-06T00:00:00Z",
            reason_code="qualification_withdrawn",
            ordinal=2,
        )
        with self.assertRaisesRegex(QualificationError, "terminal"):
            verify_qualification_status_transition(
                later,
                revoked,
                verified_policy,
                clock=lambda: datetime(2026, 2, 6, tzinfo=UTC),
            )

    def test_renewal_requires_fresh_review_and_extends_validity(self) -> None:
        policy, verified_policy, _, active, _ = self._initial_chain()
        supporting = self._fresh_reviewed_decision(policy, verified_policy)
        transition = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.RENEW,
            issued_at="2026-02-09T00:00:00Z",
            reason_code="periodic_review",
            supporting_decision=supporting,
        )
        renewed = verify_qualification_status_transition(
            transition,
            active,
            verified_policy,
            supporting_decision=supporting,
            clock=lambda: RESTORE_CLOCK,
        )

        self.assertEqual(renewed.binding.status, QualificationStatus.ACTIVE)
        self.assertEqual(renewed.binding.sequence, 2)
        self.assertEqual(
            renewed.binding.current_review_decision["sha256"],
            supporting.decision_sha256,
        )
        self.assertEqual(
            renewed.binding.qualification_valid_until,
            supporting.decision.valid_until,
        )

    def test_reinstatement_requires_post_suspension_evidence_and_review(self) -> None:
        policy, verified_policy, _, active, control = self._initial_chain()
        suspension = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="operational_safety",
            control_credential=control,
        )
        suspended = verify_qualification_status_transition(
            suspension,
            active,
            verified_policy,
            clock=lambda: SUSPEND_CLOCK,
            control_credential=control,
        )
        supporting = self._fresh_reviewed_decision(policy, verified_policy)
        reinstatement = self._signed_transition(
            policy,
            suspended,
            kind=QualificationStatusTransitionKind.REINSTATE,
            issued_at="2026-02-09T00:00:00Z",
            reason_code="corrective_review_complete",
            supporting_decision=supporting,
            ordinal=2,
        )
        restored = verify_qualification_status_transition(
            reinstatement,
            suspended,
            verified_policy,
            supporting_decision=supporting,
            clock=lambda: RESTORE_CLOCK,
        )
        self.assertEqual(restored.binding.status, QualificationStatus.ACTIVE)
        self.assertEqual(restored.binding.sequence, 3)

    def test_restorative_transition_rejects_reused_or_stale_review(self) -> None:
        policy, verified_policy, initial, active, _ = self._initial_chain()
        renewal = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.RENEW,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="periodic_review",
            supporting_decision=initial,
        )
        with self.assertRaisesRegex(QualificationError, "fresh"):
            verify_qualification_status_transition(
                renewal,
                active,
                verified_policy,
                supporting_decision=initial,
                clock=lambda: SUSPEND_CLOCK,
            )

        supporting = self._fresh_reviewed_decision(
            policy,
            verified_policy,
            manifest_created_at="2026-02-02T12:00:00Z",
            reviewed_at="2026-02-03T12:00:00Z",
            issued_at="2026-02-04T12:00:00Z",
            valid_until="2026-08-03T12:00:00Z",
        )
        renewal = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.RENEW,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="periodic_review",
            supporting_decision=supporting,
        )
        with self.assertRaisesRegex(QualificationError, "fresh evidence"):
            verify_qualification_status_transition(
                renewal,
                active,
                verified_policy,
                supporting_decision=supporting,
                clock=lambda: SUSPEND_CLOCK,
            )

    def test_transition_rejects_stale_state_matrix_and_bad_signature(self) -> None:
        policy, verified_policy, _, active, control = self._initial_chain()
        supporting = self._fresh_reviewed_decision(policy, verified_policy)
        reinstatement = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.REINSTATE,
            issued_at="2026-02-09T00:00:00Z",
            reason_code="incident_resolved",
            supporting_decision=supporting,
        )
        with self.assertRaisesRegex(QualificationError, "prior status"):
            verify_qualification_status_transition(
                reinstatement,
                active,
                verified_policy,
                supporting_decision=supporting,
                clock=lambda: RESTORE_CLOCK,
            )

        suspension = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="key_compromise_suspected",
            control_credential=control,
        )
        raw = suspension.to_dict()
        raw["reason_evidence_sha256"] = phase35._digest("different-reason")
        tampered = QualificationStatusTransition.from_dict(raw)
        with self.assertRaisesRegex(QualificationError, "signature"):
            verify_qualification_status_transition(
                tampered,
                active,
                verified_policy,
                clock=lambda: SUSPEND_CLOCK,
                control_credential=control,
            )

    def test_transition_rejects_future_effect_and_expired_qualification(self) -> None:
        policy, verified_policy, _, active, control = self._initial_chain()
        future = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-06T00:00:00Z",
            reason_code="operational_safety",
            control_credential=control,
        )
        with self.assertRaisesRegex(QualificationError, "not effective"):
            verify_qualification_status_transition(
                future,
                active,
                verified_policy,
                clock=lambda: SUSPEND_CLOCK,
                control_credential=control,
            )

        expired = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.REVOKE,
            issued_at="2026-08-02T00:00:00Z",
            reason_code="qualification_withdrawn",
        )
        with self.assertRaisesRegex(QualificationError, "expiry"):
            verify_qualification_status_transition(
                expired,
                active,
                verified_policy,
                clock=lambda: datetime(2026, 8, 2, tzinfo=UTC),
            )

    def test_contract_shape_and_verified_wrapper_fail_closed(self) -> None:
        policy, _, _, active, control = self._initial_chain()
        raw = self._signed_transition(
            policy,
            active,
            kind=QualificationStatusTransitionKind.SUSPEND,
            issued_at="2026-02-05T00:00:00Z",
            reason_code="operational_safety",
            control_credential=control,
        ).to_dict()
        raw["supporting_decision"] = {
            "id": "QKD-99999999999999999999999999999999",
            "sha256": phase35._digest("unexpected"),
        }
        with self.assertRaisesRegex(QualificationError, "unsupported"):
            QualificationStatusTransition.from_dict(raw)

        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationStatus(
                binding=active.binding,
                binding_sha256=active.binding_sha256,
                previous_binding_sha256=active.previous_binding_sha256,
                verified_at=active.verified_at,
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "qualification_lifecycle.py"
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


def qualification_status_transition_document() -> dict[str, Any]:
    QualificationLifecyclePhase36Tests.setUpClass()
    case = QualificationLifecyclePhase36Tests()
    policy, _, _, active, control = case._initial_chain()
    return case._signed_transition(
        policy,
        active,
        kind=QualificationStatusTransitionKind.SUSPEND,
        issued_at="2026-02-05T00:00:00Z",
        reason_code="operational_safety",
        control_credential=control,
    ).to_dict()


if __name__ == "__main__":
    unittest.main()
