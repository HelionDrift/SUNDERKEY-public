"""Phase 78 fail-closed candidate enrollment release recovery coverage."""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.candidate_enrollment_release_protocol import (
    execute_candidate_enrollment_controlled_release,
)
from sunderkey.candidate_enrollment_release_recovery import (
    CandidateEnrollmentReleaseRecoveryAssessment,
    assess_candidate_enrollment_release_recovery,
    recover_candidate_enrollment_controlled_release,
)
from sunderkey.errors import QualificationError
from tests.agents import test_candidate_enrollment_release_protocol_phase77

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "registry" / "schemas"


class FailingCommitStore:
    def __init__(self, wrapped) -> None:
        self.wrapped = wrapped

    def load_for_release_initialization(self):
        return self.wrapped.load_for_release_initialization()

    def commit(self, record, intent):
        raise QualificationError("Injected checkpoint commit interruption")


class CandidateEnrollmentReleaseRecoveryPhase78Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase77 = test_candidate_enrollment_release_protocol_phase77
        phase77.CandidateEnrollmentReleaseProtocolPhase77Tests.setUpClass()
        cls.phase77 = phase77
        cls.fixture = phase77.CandidateEnrollmentReleaseProtocolPhase77Tests(
            methodName="test_promotion_failure_leaves_resumable_fail_closed_state"
        )

    def partial_after_checkpoint(self, directory: Path):
        store, ledger, promoter, gate = self.fixture.components(directory)
        with self.assertRaisesRegex(QualificationError, "promotion failed"):
            execute_candidate_enrollment_controlled_release(
                deployment_id="deployment.phase78",
                decision=self.fixture.decision,
                verification_receipt=self.fixture.receipt,
                catalog=self.fixture.catalog,
                verification_gate=gate,
                initialization_approval_bindings=self.fixture.approvals,
                checkpoint_store=store,
                release_ledger=ledger,
                catalog_promoter=self.phase77.RejectingPromoter(),
                clock=self.fixture.clock,
            )
        return store, ledger, promoter, gate

    def recover(self, store, ledger, promoter, gate, assessment):
        return recover_candidate_enrollment_controlled_release(
            deployment_id="deployment.phase78",
            assessment=assessment,
            decision=self.fixture.decision,
            verification_receipt=self.fixture.receipt,
            catalog=self.fixture.catalog,
            verification_gate=gate,
            recovery_approval_bindings=self.fixture.approvals,
            checkpoint_store=store,
            release_ledger=ledger,
            catalog_promoter=promoter,
            clock=self.fixture.clock,
        )

    def test_checkpoint_committed_partial_state_recovers_same_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, promoter, gate = self.partial_after_checkpoint(
                Path(temporary) / "checkpoint-store"
            )
            assessment = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            self.assertEqual(
                assessment.to_dict()["release_state"],
                "checkpoint_committed_promotion_not_recorded",
            )
            recovery = self.recover(store, ledger, promoter, gate, assessment)
            self.assertEqual(
                recovery.to_dict()["recovery_status"], "completed_same_digest"
            )
            self.assertFalse(recovery.to_dict()["readiness"]["ready_for_live_enrollment"])
            self.assertEqual(
                assess_candidate_enrollment_release_recovery(
                    "deployment.phase78", store, ledger
                ).to_dict()["release_state"],
                "release_complete",
            )
            event_types = [
                entry.to_dict()["event_type"]
                for entry in ledger.entries("deployment.phase78")
            ]
            self.assertEqual(
                event_types[-5:],
                [
                    "recovery_intent",
                    "checkpoint_committed",
                    "catalog_promoted",
                    "recovery_completed",
                    "release_completed",
                ],
            )

    def test_intent_only_and_interrupted_recovery_are_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, ledger, promoter, gate = self.fixture.components(directory)
            with self.assertRaisesRegex(QualificationError, "commit interruption"):
                execute_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase78",
                    decision=self.fixture.decision,
                    verification_receipt=self.fixture.receipt,
                    catalog=self.fixture.catalog,
                    verification_gate=gate,
                    initialization_approval_bindings=self.fixture.approvals,
                    checkpoint_store=FailingCommitStore(store),
                    release_ledger=ledger,
                    catalog_promoter=promoter,
                    clock=self.fixture.clock,
                )
            assessment = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            self.assertEqual(
                assessment.to_dict()["release_state"],
                "intent_recorded_checkpoint_not_committed",
            )
            with self.assertRaisesRegex(QualificationError, "commit interruption"):
                recover_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase78",
                    assessment=assessment,
                    decision=self.fixture.decision,
                    verification_receipt=self.fixture.receipt,
                    catalog=self.fixture.catalog,
                    verification_gate=gate,
                    recovery_approval_bindings=self.fixture.approvals,
                    checkpoint_store=FailingCommitStore(store),
                    release_ledger=ledger,
                    catalog_promoter=promoter,
                    clock=self.fixture.clock,
                )
            resumed = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            self.assertEqual(
                resumed.to_dict()["release_state"],
                "recovery_intent_recorded_resume_required",
            )
            receipt = self.recover(store, ledger, promoter, gate, resumed)
            self.assertEqual(receipt.to_dict()["recovery_status"], "completed_same_digest")

    def test_stale_assessment_and_missing_dual_control_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, promoter, gate = self.partial_after_checkpoint(
                Path(temporary) / "checkpoint-store"
            )
            assessment = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            tampered = assessment.to_dict()
            tampered["assessment_sha256"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(QualificationError, "hash"):
                CandidateEnrollmentReleaseRecoveryAssessment.from_dict(tampered)
            with self.assertRaisesRegex(QualificationError, "approval count"):
                recover_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase78",
                    assessment=assessment,
                    decision=self.fixture.decision,
                    verification_receipt=self.fixture.receipt,
                    catalog=self.fixture.catalog,
                    verification_gate=gate,
                    recovery_approval_bindings=self.fixture.approvals[:1],
                    checkpoint_store=store,
                    release_ledger=ledger,
                    catalog_promoter=promoter,
                    clock=self.fixture.clock,
                )
            self.assertEqual(len(ledger.entries("deployment.phase78")), 2)

    def test_corrupt_checkpoint_is_assessed_ambiguous_and_not_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, ledger, promoter, gate = self.partial_after_checkpoint(directory)
            store.current_path.write_text("{", encoding="ascii")
            assessment = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            self.assertEqual(
                assessment.to_dict()["release_state"], "ambiguous_fail_closed"
            )
            with self.assertRaisesRegex(QualificationError, "not eligible"):
                self.recover(store, ledger, promoter, gate, assessment)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_assessment_and_recovery_receipt_match_published_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, promoter, gate = self.partial_after_checkpoint(
                Path(temporary) / "checkpoint-store"
            )
            assessment = assess_candidate_enrollment_release_recovery(
                "deployment.phase78", store, ledger
            )
            recovery = self.recover(store, ledger, promoter, gate, assessment)
        cases = (
            (
                "candidate-enrollment-release-recovery-assessment-v1.schema.json",
                assessment.to_dict(),
            ),
            (
                "candidate-enrollment-release-recovery-receipt-v1.schema.json",
                recovery.to_dict(),
            ),
        )
        for name, document in cases:
            with self.subTest(schema=name):
                schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(document)

    def test_recovery_has_no_network_database_or_subprocess_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment_release_recovery.py"
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


if __name__ == "__main__":
    unittest.main()
