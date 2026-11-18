"""Phase 75 D011 checkpoint and release ledger contract coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_enrollment_release_policy import build_parser, build_policy
from sunderkey.candidate_enrollment_activation_decision import (
    load_candidate_enrollment_activation_decision_record,
)
from sunderkey.candidate_enrollment_release_contract import (
    CandidateEnrollmentCheckpointRecord,
    CandidateEnrollmentReleaseLedgerEntry,
    build_candidate_enrollment_checkpoint_record,
    build_candidate_enrollment_release_ledger_entry,
    load_candidate_enrollment_release_policy,
)
from sunderkey.candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
)
from sunderkey.errors import QualificationError
from tests.agents import test_candidate_enrollment_deployment_verification_phase72

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DECISION_PATH = REGISTRY / "candidate-enrollment-activation-decision-d011.json"
POLICY_PATH = REGISTRY / "candidate-enrollment-release-policy-d011.json"
SCHEMA_DIR = REGISTRY / "schemas"


class CandidateEnrollmentReleaseContractPhase75Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase72 = test_candidate_enrollment_deployment_verification_phase72
        phase72.CandidateEnrollmentDeploymentVerificationPhase72Tests.setUpClass()
        cls.verifier = phase72.CandidateEnrollmentDeploymentVerificationPhase72Tests(
            methodName="test_complete_chain_derives_uncommitted_checkpoint"
        )
        cls.receipt = cls.verifier.verify()
        cls.catalog_checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
            cls.receipt.to_dict()["next_checkpoint"]
        )
        cls.decision = load_candidate_enrollment_activation_decision_record(
            DECISION_PATH
        )
        cls.policy = load_candidate_enrollment_release_policy(POLICY_PATH)
        cls.release_id = "CRL-" + "1" * 32
        cls.approvals = [
            {
                "approval_id": "CRA-" + "A" * 32,
                "sha256": "sha256:" + "a" * 64,
                "role": "deployment_owner",
            },
            {
                "approval_id": "CRA-" + "B" * 32,
                "sha256": "sha256:" + "b" * 64,
                "role": "independent_control",
            },
        ]

    def intent(self) -> CandidateEnrollmentReleaseLedgerEntry:
        return build_candidate_enrollment_release_ledger_entry(
            deployment_id="deployment.phase75",
            ledger_sequence=1,
            previous_entry=None,
            event_type="release_intent",
            release_id=self.release_id,
            decision=self.decision,
            verification_receipt=self.receipt,
            catalog_checkpoint=self.catalog_checkpoint,
            checkpoint_record=None,
            event_artifact=None,
            authority_mode="dual_control_initialization",
            approval_bindings=self.approvals,
            event_time="2026-08-02T20:30:00Z",
        )

    def checkpoint(self) -> CandidateEnrollmentCheckpointRecord:
        return build_candidate_enrollment_checkpoint_record(
            deployment_id="deployment.phase75",
            checkpoint_sequence=1,
            release_id=self.release_id,
            catalog_checkpoint=self.catalog_checkpoint,
            verification_receipt=self.receipt,
            release_intent=self.intent(),
            predecessor_checkpoint=None,
            committed_at="2026-08-02T20:31:00Z",
        )

    def test_checked_policy_matches_deterministic_builder(self) -> None:
        expected = build_policy(build_parser().parse_args([]))
        self.assertEqual(
            POLICY_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.policy.to_dict(), expected)
        self.assertEqual(self.policy.policy_id, "CRP-CB268855D98EC59A1C8D758550848EF5")

    def test_initial_intent_requires_dual_control_and_receipt_binding(self) -> None:
        intent = self.intent().to_dict()
        self.assertEqual(intent["ledger_sequence"], 1)
        self.assertIsNone(intent["previous_entry"])
        self.assertEqual(intent["authority"]["mode"], "dual_control_initialization")
        self.assertEqual(
            {item["role"] for item in intent["authority"]["approval_bindings"]},
            {"deployment_owner", "independent_control"},
        )
        self.assertEqual(
            intent["verification_receipt"]["receipt_id"], self.receipt.receipt_id
        )
        with self.assertRaisesRegex(QualificationError, "approval count"):
            build_candidate_enrollment_release_ledger_entry(
                deployment_id="deployment.phase75",
                ledger_sequence=1,
                previous_entry=None,
                event_type="release_intent",
                release_id=self.release_id,
                decision=self.decision,
                verification_receipt=self.receipt,
                catalog_checkpoint=self.catalog_checkpoint,
                checkpoint_record=None,
                event_artifact=None,
                authority_mode="dual_control_initialization",
                approval_bindings=self.approvals[:1],
                event_time="2026-08-02T20:30:00Z",
            )

    def test_checkpoint_binds_intent_and_precedes_promotion(self) -> None:
        intent = self.intent()
        checkpoint = self.checkpoint()
        committed = build_candidate_enrollment_release_ledger_entry(
            deployment_id="deployment.phase75",
            ledger_sequence=2,
            previous_entry=intent,
            event_type="checkpoint_committed",
            release_id=self.release_id,
            decision=self.decision,
            verification_receipt=self.receipt,
            catalog_checkpoint=self.catalog_checkpoint,
            checkpoint_record=checkpoint,
            event_artifact={
                "artifact_kind": "checkpoint_commit_receipt",
                "artifact_id": "CCR-" + "C" * 32,
                "sha256": "sha256:" + "c" * 64,
            },
            authority_mode="automatic_monotonic_advance",
            approval_bindings=[],
            event_time="2026-08-02T20:32:00Z",
        )
        self.assertEqual(
            committed.to_dict()["checkpoint_record"]["checkpoint_id"],
            checkpoint.checkpoint_id,
        )
        self.assertEqual(
            committed.to_dict()["previous_entry"]["entry_id"], intent.entry_id
        )

    def test_sequence_hash_and_receipt_tampering_fail_closed(self) -> None:
        intent = self.intent().to_dict()
        intent["entry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "hash"):
            CandidateEnrollmentReleaseLedgerEntry.from_dict(intent)
        checkpoint = self.checkpoint().to_dict()
        checkpoint["checkpoint_sequence"] = 2
        with self.assertRaisesRegex(QualificationError, "predecessor"):
            CandidateEnrollmentCheckpointRecord.from_dict(checkpoint)
        mismatch = CandidateEnrollmentCatalogCheckpoint(
            self.catalog_checkpoint.catalog_id,
            self.catalog_checkpoint.catalog_version,
            "sha256:" + "f" * 64,
        )
        with self.assertRaisesRegex(QualificationError, "receipt"):
            build_candidate_enrollment_release_ledger_entry(
                deployment_id="deployment.phase75",
                ledger_sequence=1,
                previous_entry=None,
                event_type="release_intent",
                release_id=self.release_id,
                decision=self.decision,
                verification_receipt=self.receipt,
                catalog_checkpoint=mismatch,
                checkpoint_record=None,
                event_artifact=None,
                authority_mode="dual_control_initialization",
                approval_bindings=self.approvals,
                event_time="2026-08-02T20:30:00Z",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_policy_checkpoint_and_ledger_match_published_schemas(self) -> None:
        cases = (
            (
                "candidate-enrollment-release-policy-v1.schema.json",
                self.policy.to_dict(),
            ),
            (
                "candidate-enrollment-checkpoint-record-v1.schema.json",
                self.checkpoint().to_dict(),
            ),
            (
                "candidate-enrollment-release-ledger-entry-v1.schema.json",
                self.intent().to_dict(),
            ),
        )
        for schema_name, document in cases:
            with self.subTest(schema=schema_name):
                schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(document)

    def test_contract_has_no_network_storage_or_execution_imports(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for relative in (
            "src/sunderkey/candidate_enrollment_release_contract.py",
            "scripts/build_candidate_enrollment_release_policy.py",
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
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
