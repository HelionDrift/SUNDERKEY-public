"""Phase 135 atomic executor invocation attempt custody coverage."""

from __future__ import annotations

import ast
import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor_invocation_attempt_store import (
    CollaborationExecutorInvocationAttemptService,
)
from sunderkey.errors import StoreConflictError

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorInvocationAttemptStorePhase135Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase133.CollaborationExecutorInvocationAttemptPhase133Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.fixture.root
        self.service = CollaborationExecutorInvocationAttemptService(
            self.root.store,
            self.root.registry,
            clock=lambda: self.root.now,
        )

    def _prepare(self, *, adapter_version: str = "1.0.0"):
        return self.service.prepare(
            self.fixture.claim_receipt,
            self.fixture.operation_input,
            adapter_id="adapter.test",
            adapter_version=adapter_version,
            adapter_build_sha256=phase133.ADAPTER_BUILD,
            deployment_binding_sha256=phase133.DEPLOYMENT_BINDING,
            idempotency_status="absent",
            idempotency_key_sha256=None,
        )

    def test_preparation_is_committed_before_invocation_and_readable(self) -> None:
        receipt = self._prepare()
        document = receipt.to_dict()
        self.assertEqual(document["custody_status"], "durable_before_invocation")
        self.assertEqual(
            document["unresolved_recovery_disposition"],
            "treat_as_outcome_uncertain",
        )
        self.assertEqual(document["external_effect_status"], "not_started")
        self.assertEqual(self.service.get_preparation(receipt.attempt_id), receipt)
        self.assertIsNone(self.service.get_resolution(receipt.attempt_id))
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_invocation_preparations"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_exact_preparation_replays_but_changed_material_conflicts(self) -> None:
        first = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        self.assertEqual(self._prepare(), first)
        with self.assertRaisesRegex(StoreConflictError, "another preparation"):
            self._prepare(adapter_version="1.0.1")

    def test_expired_claim_cannot_create_preparation(self) -> None:
        self.root.now = datetime(2026, 7, 30, 10, 8, 40, tzinfo=UTC)
        with self.assertRaisesRegex(StoreConflictError, "expired"):
            self._prepare()
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_invocation_preparations"
                ).fetchone()[0],
                0,
            )

    def test_terminal_resolution_commits_after_claim_expiry_and_replays(self) -> None:
        preparation = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        first = self.service.resolve(
            preparation.attempt_id,
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
        )
        self.assertEqual(
            first.to_dict()["retry_disposition"],
            "retry_allowed_no_external_effect",
        )
        self.assertEqual(self.service.get_resolution(preparation.attempt_id), first)
        self.root.now = datetime(2026, 7, 30, 10, 8, 50, tzinfo=UTC)
        self.assertEqual(
            self.service.resolve(
                preparation.attempt_id,
                outcome="failed_before_invocation",
                failure_code="adapter-not-started",
            ),
            first,
        )
        with self.assertRaisesRegex(StoreConflictError, "another resolution"):
            self.service.resolve(
                preparation.attempt_id,
                outcome="outcome_uncertain",
                failure_code="response-lost",
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_provider_report_resolution_waits_for_full_report_custody(self) -> None:
        preparation = self._prepare()
        with self.assertRaisesRegex(StoreConflictError, "report custody"):
            self.service.resolve(
                preparation.attempt_id,
                outcome="provider_report_received",
                provider_acknowledgement=self.fixture._acknowledgement(),
            )
        self.assertIsNone(self.service.get_resolution(preparation.attempt_id))

    def test_failed_insert_rolls_back_without_partial_custody(self) -> None:
        with patch.object(
            self.service,
            "_insert_preparation",
            side_effect=sqlite3.IntegrityError("injected preparation failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self._prepare()
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_invocation_preparations"
                ).fetchone()[0],
                0,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipts_match_strict_schemas(self) -> None:
        preparation = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        resolution = self.service.resolve(
            preparation.attempt_id,
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
        )
        preparation_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-preparation-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        preparation_schema["properties"]["invocation_preparation"] = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-preparation-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        resolution_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-resolution-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        resolution_schema["properties"]["invocation_resolution"] = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-resolution-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        for schema, document in (
            (preparation_schema, preparation.to_dict()),
            (resolution_schema, resolution.to_dict()),
        ):
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(document)

    def test_writer_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = (
            ROOT
            / "src/sunderkey/collaboration_executor_invocation_attempt_store.py"
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
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()
