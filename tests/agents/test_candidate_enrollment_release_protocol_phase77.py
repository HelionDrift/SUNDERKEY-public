"""Phase 77 controlled candidate enrollment release protocol coverage."""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.candidate_enrollment_checkpoint_store import (
    AtomicCandidateEnrollmentCheckpointStore,
)
from sunderkey.candidate_enrollment_release_protocol import (
    InMemoryCandidateEnrollmentCatalogPromoter,
    InMemoryCandidateEnrollmentReleaseLedger,
    execute_candidate_enrollment_controlled_release,
)
from sunderkey.errors import QualificationError
from tests.agents import test_candidate_enrollment_checkpoint_store_phase76

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "registry" / "schemas"


class ExactFixtureVerificationGate:
    def __init__(self, receipt, catalog) -> None:
        self.receipt = receipt
        self.catalog_sha256 = catalog.content_sha256
        self.calls = 0

    def verify(self, receipt, catalog):
        self.calls += 1
        if receipt != self.receipt or catalog.content_sha256 != self.catalog_sha256:
            raise QualificationError("Fixture verification gate rejected release inputs")
        return receipt


class RejectingPromoter:
    def promote(self, **kwargs):
        raise QualificationError("Catalog repository promotion failed")


class CandidateEnrollmentReleaseProtocolPhase77Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase76 = test_candidate_enrollment_checkpoint_store_phase76
        phase76.CandidateEnrollmentCheckpointStorePhase76Tests.setUpClass()
        cls.phase76 = phase76
        cls.fixture = phase76.CandidateEnrollmentCheckpointStorePhase76Tests(
            methodName="test_initial_commit_is_atomic_verified_and_idempotent"
        )
        cls.phase75 = cls.fixture.fixture
        cls.receipt = cls.phase75.receipt
        cls.catalog = cls.phase75.verifier.inputs()[-1]
        cls.decision = cls.phase75.decision
        cls.approvals = cls.phase75.approvals
        cls.clock = staticmethod(
            lambda: datetime(2026, 8, 2, 21, 0, tzinfo=UTC)
        )

    def components(self, directory: Path):
        controller = self.phase76.TestCheckpointAccessController()
        store = AtomicCandidateEnrollmentCheckpointStore(directory, controller)
        store.initialize_directory()
        ledger = InMemoryCandidateEnrollmentReleaseLedger()
        promoter = InMemoryCandidateEnrollmentCatalogPromoter(
            "repository.organization.evidence"
        )
        gate = ExactFixtureVerificationGate(self.receipt, self.catalog)
        return store, ledger, promoter, gate

    def execute(self, directory: Path):
        store, ledger, promoter, gate = self.components(directory)
        completion = execute_candidate_enrollment_controlled_release(
            deployment_id="deployment.phase77",
            decision=self.decision,
            verification_receipt=self.receipt,
            catalog=self.catalog,
            verification_gate=gate,
            initialization_approval_bindings=self.approvals,
            checkpoint_store=store,
            release_ledger=ledger,
            catalog_promoter=promoter,
            clock=self.clock,
        )
        return completion, store, ledger, promoter, gate

    def test_controlled_release_enforces_exact_order_and_stays_not_live(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completion, store, ledger, _, gate = self.execute(
                Path(temporary) / "checkpoint-store"
            )
            entries = ledger.entries("deployment.phase77")
            self.assertEqual(
                [item.to_dict()["event_type"] for item in entries],
                [
                    "release_intent",
                    "checkpoint_committed",
                    "catalog_promoted",
                    "release_completed",
                ],
            )
            self.assertEqual(gate.calls, 1)
            self.assertEqual(
                entries[1].to_dict()["event_artifact"]["artifact_kind"],
                "checkpoint_commit_receipt",
            )
            self.assertEqual(
                entries[2].to_dict()["event_artifact"]["artifact_kind"],
                "catalog_promotion_receipt",
            )
            self.assertEqual(
                store.load_required().checkpoint_id,
                completion.to_dict()["checkpoint_record"]["checkpoint_id"],
            )
            document = completion.to_dict()
            self.assertEqual(document["release_status"], "completed")
            self.assertTrue(document["readiness"]["controlled_catalog_release_complete"])
            self.assertFalse(document["readiness"]["ready_for_live_enrollment"])
            self.assertEqual(document["qualification_effect"], "none")
            self.assertEqual(document["registry_effect"], "none")

    def test_promotion_failure_leaves_resumable_fail_closed_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, _, gate = self.components(
                Path(temporary) / "checkpoint-store"
            )
            with self.assertRaisesRegex(QualificationError, "promotion failed"):
                execute_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase77",
                    decision=self.decision,
                    verification_receipt=self.receipt,
                    catalog=self.catalog,
                    verification_gate=gate,
                    initialization_approval_bindings=self.approvals,
                    checkpoint_store=store,
                    release_ledger=ledger,
                    catalog_promoter=RejectingPromoter(),
                    clock=self.clock,
                )
            self.assertIsNotNone(store.load_required())
            entries = ledger.entries("deployment.phase77")
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[-1].to_dict()["event_type"], "checkpoint_committed")

    def test_verification_failure_prevents_intent_checkpoint_and_promotion(self) -> None:
        class RejectingGate:
            def verify(self, receipt, catalog):
                raise QualificationError("Full Phase 72 reverification failed")

        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, promoter, _ = self.components(
                Path(temporary) / "checkpoint-store"
            )
            with self.assertRaisesRegex(QualificationError, "reverification failed"):
                execute_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase77",
                    decision=self.decision,
                    verification_receipt=self.receipt,
                    catalog=self.catalog,
                    verification_gate=RejectingGate(),
                    initialization_approval_bindings=self.approvals,
                    checkpoint_store=store,
                    release_ledger=ledger,
                    catalog_promoter=promoter,
                    clock=self.clock,
                )
            self.assertIsNone(ledger.tail("deployment.phase77"))
            self.assertIsNone(store.load_for_release_initialization())

    def test_missing_initial_approval_fails_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, ledger, promoter, gate = self.components(
                Path(temporary) / "checkpoint-store"
            )
            with self.assertRaisesRegex(QualificationError, "approval count"):
                execute_candidate_enrollment_controlled_release(
                    deployment_id="deployment.phase77",
                    decision=self.decision,
                    verification_receipt=self.receipt,
                    catalog=self.catalog,
                    verification_gate=gate,
                    initialization_approval_bindings=self.approvals[:1],
                    checkpoint_store=store,
                    release_ledger=ledger,
                    catalog_promoter=promoter,
                    clock=self.clock,
                )
            self.assertIsNone(ledger.tail("deployment.phase77"))
            self.assertIsNone(store.load_for_release_initialization())

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_promotion_and_completion_receipts_match_published_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completion, _, _, promoter, _ = self.execute(
                Path(temporary) / "checkpoint-store"
            )
        completion_schema = json.loads(
            (
                SCHEMA_DIR
                / "candidate-enrollment-release-completion-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(completion_schema).validate(completion.to_dict())
        promotion_schema = json.loads(
            (
                SCHEMA_DIR
                / "candidate-enrollment-catalog-promotion-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        promotion = promoter.receipt(completion.to_dict()["release_id"])
        Draft202012Validator(promotion_schema).validate(promotion.to_dict())

    def test_protocol_has_no_network_database_or_subprocess_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment_release_protocol.py"
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
