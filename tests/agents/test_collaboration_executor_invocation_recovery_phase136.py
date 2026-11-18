"""Phase 136 fail-closed executor invocation recovery coverage."""

from __future__ import annotations

import ast
import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor_invocation_recovery import (
    CollaborationExecutorInvocationRecoveryAssessment,
    CollaborationExecutorInvocationRecoveryService,
)
from sunderkey.errors import CollaborationPlanError, StoreConflictError

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133
from . import (
    test_collaboration_executor_invocation_attempt_store_phase135 as phase135,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorInvocationRecoveryPhase136Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase135.CollaborationExecutorInvocationAttemptStorePhase135Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.service = CollaborationExecutorInvocationRecoveryService(
            self.root.store,
            self.root.registry,
            clock=lambda: self.root.now,
        )

    def test_unresolved_preparation_is_uncertain_and_never_authorizes_retry(self) -> None:
        preparation = self.fixture._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            before = (
                connection.execute("PRAGMA data_version").fetchone()[0],
                connection.execute(
                    """
                    SELECT COUNT(*) FROM executor_dispatch_invocation_preparations
                    """
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT COUNT(*) FROM executor_dispatch_invocation_resolutions
                    """
                ).fetchone()[0],
            )
            assessment = self.service.assess(preparation.attempt_id)
            after = (
                connection.execute("PRAGMA data_version").fetchone()[0],
                connection.execute(
                    """
                    SELECT COUNT(*) FROM executor_dispatch_invocation_preparations
                    """
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT COUNT(*) FROM executor_dispatch_invocation_resolutions
                    """
                ).fetchone()[0],
            )
            self.assertEqual(after, before)
        document = assessment.to_dict()
        self.assertEqual(document["knowledge_state"], "unresolved_after_preparation")
        self.assertEqual(
            document["recovery_disposition"],
            "manual_reconciliation_required",
        )
        self.assertEqual(document["retry_authority"], "not_authorized")
        self.assertEqual(document["external_effect_status"], "outcome_uncertain")
        self.assertEqual(document["runtime_effect"], "none")

    def test_declared_verified_idempotency_still_does_not_authorize_retry(self) -> None:
        preparation = self.fixture.service.prepare(
            self.fixture.fixture.claim_receipt,
            self.fixture.fixture.operation_input,
            adapter_id="adapter.test",
            adapter_version="1.0.0",
            adapter_build_sha256=phase133.ADAPTER_BUILD,
            deployment_binding_sha256=phase133.DEPLOYMENT_BINDING,
            idempotency_status="verified",
            idempotency_key_sha256=phase133.IDEMPOTENCY_KEY,
        )
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        document = self.service.assess(preparation.attempt_id).to_dict()
        self.assertEqual(
            document["invocation_preparation"]["idempotency_status"],
            "verified",
        )
        self.assertEqual(document["retry_authority"], "not_authorized")

    def test_terminal_no_effect_resolution_requires_new_authorization(self) -> None:
        preparation = self.fixture._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        self.fixture.service.resolve(
            preparation.attempt_id,
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
        )
        assessment = self.service.assess(preparation.attempt_id)
        document = assessment.to_dict()
        self.assertEqual(document["knowledge_state"], "terminal_resolution_recorded")
        self.assertEqual(
            document["recovery_disposition"],
            "terminal_retry_disposition_requires_reauthorization",
        )
        self.assertEqual(
            document["retry_authority"],
            "separate_reauthorization_required",
        )
        self.assertEqual(document["external_effect_status"], "not_started")
        changed = assessment.to_dict()
        changed["terminal_resolution"]["attempt_id"] = "EIP-" + "B2" * 16
        with self.assertRaisesRegex(CollaborationPlanError, "resolution is invalid"):
            CollaborationExecutorInvocationRecoveryAssessment.from_dict(changed)

    def test_unknown_attempt_fails_closed(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "preparation is missing"):
            self.service.assess("EIP-" + "A1" * 16)

    def test_assessment_rejects_tampering(self) -> None:
        preparation = self.fixture._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        changed = self.service.assess(preparation.attempt_id).to_dict()
        changed["retry_authority"] = "separate_reauthorization_required"
        with self.assertRaisesRegex(CollaborationPlanError, "boundary"):
            CollaborationExecutorInvocationRecoveryAssessment.from_dict(changed)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_assessment_matches_strict_schema(self) -> None:
        preparation = self.fixture._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        document = self.service.assess(preparation.attempt_id).to_dict()
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-recovery-assessment-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_recovery_has_no_write_network_process_or_adapter_boundary(self) -> None:
        source_path = (
            ROOT / "src/sunderkey/collaboration_executor_invocation_recovery.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "httpx",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("_write_connection", source)
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()
